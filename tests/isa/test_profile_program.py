from pathlib import Path
import os
import subprocess
import sys

import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.isa.profile_program import build_alu_program, build_f1_records, collect_retirements


ROOT = Path(__file__).resolve().parents[2]


def test_flow_suite_checks_branches_jumps_and_memory_results():
    from myfuzz.isa.profile_program import build_flow_suite_program
    profile = load_component_profile(ROOT / 'configs/cpus/cv32e20/component_profile.json')
    program = build_flow_suite_program(profile, base=0x10000)
    assert {'BEQ', 'BNE', 'JAL', 'JALR', 'SW', 'SB', 'LW', 'LB', 'LBU', 'LHU'} <= {
        i.operation for i in program.instructions}
    assert program.scratch_address == 0x10300
    assert program.scratch_value == 0xffff07ff
    events = [{'kind': 'cpu_retire', 'pc_rdata': i.address, 'pc_wdata': i.next_pc,
               'insn': i.word, 'trap': 0, 'rd_addr': i.rd,
               'rd_wdata': i.expected, 'order': n}
              for n, i in enumerate(program.instructions)]
    assert collect_retirements(program, events)['status'] == 'verified'
    jump = next(e for e, i in zip(events, program.instructions) if i.operation == 'BEQ')
    jump['pc_wdata'] -= 4
    assert collect_retirements(program, events)['status'] == 'mismatch'
    jump['pc_wdata'] += 4
    events.append({'kind': 'cpu_retire', 'pc_rdata': program.skipped_addresses[0]})
    assert collect_retirements(program, events)['status'] == 'mismatch'
    assert collect_retirements(program, events[:-1])['status'] == 'verified'
    events.pop()
    events[1]['order'] = events[0]['order']
    assert collect_retirements(program, events)['status'] == 'mismatch'


def test_m_suite_uses_declared_isa_and_real_retirement_results():
    from types import SimpleNamespace
    from myfuzz.isa.profile_program import build_m_suite_program
    profile = load_component_profile(ROOT / 'configs/cpus/cv32e20/component_profile.json')
    program = build_m_suite_program(profile, base=0x10000)
    assert [i.operation for i in program.instructions] == [
        'ADDI', 'ADDI', 'MUL', 'MULH', 'MULHSU', 'MULHU', 'DIV', 'DIVU',
        'REM', 'REMU', 'DIV', 'REM']
    assert [i.expected for i in program.instructions] == [
        7, 0xfffffffd, 0xffffffeb, 0xffffffff, 6, 6,
        0xfffffffe, 0, 1, 7, 0xffffffff, 7]
    events = [{'kind': 'cpu_retire', 'pc_rdata': i.address, 'insn': i.word,
               'trap': 0, 'rd_addr': i.rd, 'rd_wdata': i.expected, 'order': n}
              for n, i in enumerate(program.instructions)]
    assert collect_retirements(program, events)['status'] == 'verified'
    events[6]['rd_wdata'] ^= 1
    assert collect_retirements(program, events)['status'] == 'mismatch'
    unsupported = SimpleNamespace(cpu=SimpleNamespace(family='riscv', xlen=32, extensions=('i',)))
    with pytest.raises(ValueError, match='M extension'):
        build_m_suite_program(unsupported, base=0x10000)


def test_compressed_suite_covers_supported_operations_and_dependencies():
    from types import SimpleNamespace
    from myfuzz.isa.profile_program import build_c_suite_program
    profile = load_component_profile(ROOT / 'configs/cpus/cv32e20/component_profile.json')
    program = build_c_suite_program(profile, base=0x10000)
    assert [i.operation for i in program.instructions] == [
        'C.LI', 'C.LI', 'C.ADDI', 'C.SUB', 'C.XOR', 'C.OR', 'C.AND',
        'C.SLLI', 'C.SRLI', 'C.SRAI', 'C.ANDI', 'C.MV', 'C.ADD', 'C.LUI']
    assert [i.expected for i in program.instructions] == [7, 3, 8, 5, 6, 7, 3, 12, 6, 3, 1, 3, 4, 4096]
    assert [i.address for i in program.instructions] == list(range(0x10000, 0x1001c, 2))
    events = [{'kind': 'cpu_retire', 'pc_rdata': i.address, 'insn': i.word,
               'trap': 0, 'rd_addr': i.rd, 'rd_wdata': i.expected, 'order': n}
              for n, i in enumerate(program.instructions)]
    assert collect_retirements(program, events)['status'] == 'verified'
    events[-2]['rd_wdata'] ^= 1
    assert collect_retirements(program, events)['status'] == 'mismatch'
    unsupported = SimpleNamespace(cpu=SimpleNamespace(family='riscv', xlen=32, extensions=('i',)))
    with pytest.raises(ValueError, match='C extension'):
        build_c_suite_program(unsupported, base=0x10000)


def test_cold_start_isa_import_and_selection():
    env = dict(os.environ, PYTHONPATH=str(ROOT / 'src'))
    result = subprocess.run([sys.executable, '-c',
        "from myfuzz.isa.profile_program import build_alu_program; "
        "from myfuzz.isa import IsaContract, RiscvInstructionTransducer; "
        "print(RiscvInstructionTransducer(IsaContract(32, ('I',))).repair(0, 0).operation)"],
        cwd=ROOT, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'ADDI'


def test_profile_program_uses_cpu_isa_and_generated_instructions():
    profile = load_component_profile(ROOT / 'configs/cpus/cv32e20/component_profile.json')
    program = build_alu_program(profile, bytes.fromhex('000001800101ff7f'), base=0x10000)
    assert len(program.instructions) == 2
    assert len(program.code) == 12  # two generated words and the parking JAL
    assert program.instructions[0].operation == 'ADDI'
    assert program.instructions[1].operation == 'XORI'
    assert int.from_bytes(program.code[:4], 'little') == program.instructions[0].word


def test_feedback_is_from_retirement_not_fetch_or_planned_result():
    profile = load_component_profile(ROOT / 'configs/cpus/cv32e20/component_profile.json')
    program = build_alu_program(profile, bytes.fromhex('00000180'), base=0x10000)
    instruction = program.instructions[0]
    fetch = {'kind': 'instr_response', 'address': instruction.address, 'rdata': instruction.word}
    assert collect_retirements(program, [fetch])['status'] == 'unobserved'
    partial = {'kind': 'cpu_retire', 'pc_rdata': instruction.address, 'insn': instruction.word, 'order': 3}
    feedback = collect_retirements(program, [partial])
    assert feedback['status'] == 'partial'
    assert feedback['instructions'][0]['result_status'] == 'unobserved'
    retirement = {**partial, 'trap': 0, 'rd_addr': instruction.rd, 'rd_wdata': instruction.expected}
    assert collect_retirements(program, [retirement])['status'] == 'verified'
    retirement['rd_wdata'] ^= 1
    assert collect_retirements(program, [retirement])['status'] == 'mismatch'


def test_program_requires_complete_records_and_rv32i():
    profile = load_component_profile(ROOT / 'configs/cpus/cv32e20/component_profile.json')
    with pytest.raises(ValueError):
        build_alu_program(profile, b'\x00', base=0x10000)


def test_generated_f1_records_are_accepted_by_the_real_public_lowerer():
    from types import SimpleNamespace
    from myfuzz.runtime.flows.memory import (MemoryFlowContext, MemoryFlowKernel,
                                             lower_memory_code)
    profile = load_component_profile(ROOT / 'configs/cpus/cv32e20/component_profile.json')
    entropy = bytes.fromhex('000001800101ff7f0202ab0103030100')
    output = build_f1_records(profile, entropy)
    assert output['entropy_hex'] == entropy.hex()
    assert len(output['records']) == 4
    for index, entry in enumerate(output['records']):
        flow, encoded = entry.split(':')
        assert flow == 'F1'
        raw = bytes.fromhex(encoded)
        word = int.from_bytes(raw, 'little')
        assert 12 <= (word >> 7 & 31) <= 15
        assert (word >> 15 & 31) == 0
        lowered = MemoryFlowKernel().lower(MemoryFlowContext('0' * 64, 'path', 'F1', 'source'),
            {'testcase_id': f'case-{index}', 'path_id': 'path', 'source_id': 'source',
             'raw_records_hex': [encoded]})
        assert lowered.raw_records == (raw,)
        assert lower_memory_code(SimpleNamespace(), raw, flow='F1') == (raw, 'instruction', None)
    assert build_f1_records(profile, entropy) == output
    from myfuzz.runtime.generic_campaign import load_descriptor, select_case_records
    descriptor = load_descriptor(ROOT / 'configs/scenarios/compiled-f1-f6-ibex-gpio-dma-shared/generic_scenario.json', base_dir=ROOT)
    assert select_case_records(descriptor, flow='mixed', records=output['records']) == tuple(
        ('F1', row.split(':')[1]) for row in output['records'])


def test_f1_cli_writes_records_file_and_replay_provenance(tmp_path):
    import json
    output = tmp_path / 'records.json'
    result = subprocess.run([sys.executable, str(ROOT / 'scripts/generate_profile_f1_records.py'),
        '--profile', str(ROOT / 'configs/cpus/cv32e20/component_profile.json'),
        '--entropy-hex', '000001800101ff7f', '--output', str(output)],
        cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    rows = json.loads(output.read_text())
    provenance = json.loads((tmp_path / 'records.json.provenance.json').read_text())
    assert rows == provenance['records']
    assert provenance['entropy_hex'] == '000001800101ff7f'
    assert len(provenance['profile_sha256']) == 64
    assert provenance['retirement'] == 'unknown'


@pytest.mark.parametrize('selector,operation', tuple(enumerate([
    'ADDI', 'XORI', 'ORI', 'ANDI', 'SLTI', 'SLTIU',
    'ADD', 'SUB', 'SLL', 'SLT', 'SLTU', 'XOR', 'SRL', 'SRA', 'OR', 'AND',
    'SLLI', 'SRLI', 'SRAI'])))
def test_all_profile_f1_alu_operations_use_existing_lowerer(selector, operation):
    from types import SimpleNamespace
    from myfuzz.runtime.flows.memory import lower_memory_code
    from myfuzz.scenario.rv32i_sources import instruction_operator_id
    profile = load_component_profile(ROOT / 'configs/cpus/cv32e20/component_profile.json')
    entry = build_f1_records(profile, bytes((selector, 3, 0xff, 0x07)))['records'][0]
    raw = bytes.fromhex(entry.split(':')[1])
    word = int.from_bytes(raw, 'little')
    assert instruction_operator_id(raw) == 'rv32i:' + operation
    assert lower_memory_code(SimpleNamespace(), raw, flow='F1') == (raw, 'instruction', None)
    assert (word >> 7 & 31) == 15 and (word >> 15 & 31) == 0
    if word & 0x7f == 0x33:
        assert (word >> 20 & 31) == 0


def test_optional_f1_register_dependencies_are_replayable_and_safe():
    from types import SimpleNamespace
    from myfuzz.runtime.flows.memory import lower_memory_code
    profile = load_component_profile(ROOT / 'configs/cpus/cv32e20/component_profile.json')
    # ADDI x12,x0,7; ADD x13,x12,x12; XORI x14,x13,3.
    entropy = bytes((0, 0, 7, 0, 6, 0xc1, 0, 0, 1, 0x46, 3, 0))
    generated = build_f1_records(profile, entropy, register_dependencies=True)
    assert generated['register_dependencies'] is True
    assert generated['entropy_hex'] == entropy.hex()
    assert build_f1_records(profile, entropy, register_dependencies=True) == generated
    words = [int.from_bytes(bytes.fromhex(row[3:]), 'little') for row in generated['records']]
    assert [(word >> 7 & 31, word >> 15 & 31) for word in words] == [(12, 0), (13, 12), (14, 13)]
    assert (words[1] >> 20 & 31) == 12
    for word in words:
        lower_memory_code(SimpleNamespace(), word.to_bytes(4, 'little'), flow='F1')
    for reg in range(256):
        for selector in range(19):
            raw = bytes.fromhex(build_f1_records(profile, bytes((selector, reg, 1, 0)),
                                                register_dependencies=True)['records'][0][3:])
            word = int.from_bytes(raw, 'little')
            assert word >> 7 & 31 in (12, 13, 14, 15)
            assert word >> 15 & 31 in (0, 12, 13, 14, 15)
            if word & 0x7f == 0x33:
                assert word >> 20 & 31 in (0, 12, 13, 14, 15)


def test_f1_default_generation_stays_byte_compatible_with_explicit_no_dependencies():
    profile = load_component_profile(ROOT / 'configs/cpus/cv32e20/component_profile.json')
    entropy = bytes.fromhex('00c0010006c1010001460300')
    assert build_f1_records(profile, entropy) == build_f1_records(profile, entropy, register_dependencies=False)


def test_f1_cli_records_register_dependency_mode(tmp_path):
    import json
    output = tmp_path / 'deps.json'
    result = subprocess.run([sys.executable, str(ROOT / 'scripts/generate_profile_f1_records.py'),
        '--profile', str(ROOT / 'configs/cpus/cv32e20/component_profile.json'),
        '--entropy-hex', '0000070006c10000', '--register-dependencies', '--output', str(output)],
        cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    provenance = json.loads((tmp_path / 'deps.json.provenance.json').read_text())
    assert provenance['register_dependencies'] is True
    words = [int.from_bytes(bytes.fromhex(row[3:]), 'little') for row in provenance['records']]
    assert (words[1] >> 15 & 31, words[1] >> 20 & 31) == (12, 12)


def test_profile_ram_records_use_existing_declared_ram_lowerer_and_window():
    from types import SimpleNamespace
    from myfuzz.isa.profile_program import build_ram_dataflow_records
    from myfuzz.runtime.flows.memory import RAM_READ_TOKEN, lower_memory_code
    from myfuzz.runtime.generic_campaign import load_descriptor, select_case_records
    from myfuzz.scenario.rv32i_sources import instruction_operator_id
    profile = load_component_profile(ROOT / 'configs/cpus/cv32e20/component_profile.json')
    entropy = bytes.fromhex('78563412ff000000')
    result = build_ram_dataflow_records(profile, entropy)
    assert result['records'] == ['F3:78563412', 'F1:' + RAM_READ_TOKEN.hex(),
                                 'F3:ff000000', 'F1:' + RAM_READ_TOKEN.hex()]
    assert result['entropy_hex'] == entropy.hex() and result['retirement'] == 'unknown'
    binding = SimpleNamespace(base=0x10000, size=0x1000, readable=True, writable=True)
    runtime = SimpleNamespace(memory_bindings={'F1': binding, 'F3': binding}, result=0x10084)
    write, write_op, write_addr = lower_memory_code(runtime, entropy[:4], flow='F3')
    read, read_op, read_addr = lower_memory_code(runtime, RAM_READ_TOKEN, flow='F1')
    assert (write_op, read_op, write_addr, read_addr) == ('ram_store_word', 'ram_read_word', 0x10080, 0x10080)
    assert instruction_operator_id(write).endswith(':LUI+ADDI+LUI+SW')
    assert instruction_operator_id(read).endswith(':LUI+LW')
    for code in (write, read):
        for index in range(0, len(code), 4):
            word = int.from_bytes(code[index:index + 4], 'little')
            # Generated fragments use only the existing temporary x1/x2;
            # stores have no architectural destination register.
            if word & 0x7f != 0x23:
                assert word >> 7 & 31 in (1, 2)
    descriptor = load_descriptor(ROOT / 'configs/scenarios/compiled-f1-f6-ibex-gpio-dma-shared/generic_scenario.json', base_dir=ROOT)
    assert select_case_records(descriptor, flow='mixed', records=result['records']) == tuple(
        tuple(row.split(':')) for row in result['records'])
    runtime.result = binding.base + binding.size + 8
    with pytest.raises(ValueError, match='outside-declared-ram'):
        lower_memory_code(runtime, entropy[:4], flow='F3')
    runtime.result = 0x10084
    binding.readable = False
    with pytest.raises(ValueError, match='outside-declared-ram'):
        lower_memory_code(runtime, RAM_READ_TOKEN, flow='F1')
    binding.readable = True
    binding.writable = False
    with pytest.raises(ValueError, match='outside-declared-ram'):
        lower_memory_code(runtime, entropy[:4], flow='F3')


def test_profile_ram_generation_rejects_missing_rv32i_and_incomplete_records():
    from types import SimpleNamespace
    from myfuzz.isa.profile_program import build_ram_dataflow_records
    profile = load_component_profile(ROOT / 'configs/cpus/cv32e20/component_profile.json')
    with pytest.raises(ValueError):
        build_ram_dataflow_records(profile, b'\x01')
    with pytest.raises(ValueError, match='RV32I'):
        build_ram_dataflow_records(SimpleNamespace(cpu=SimpleNamespace(
            family='riscv', xlen=64, extensions=('i',))), bytes(4))


def test_profile_ram_cli_writes_real_f3_f1_campaign_records(tmp_path):
    import json
    output = tmp_path / 'ram.json'
    result = subprocess.run([sys.executable, str(ROOT / 'scripts/generate_profile_f1_records.py'),
        '--profile', str(ROOT / 'configs/cpus/cv32e20/component_profile.json'),
        '--entropy-hex', '78563412', '--mode', 'ram', '--output', str(output)],
        cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(output.read_text()) == ['F3:78563412', 'F1:03200000']
    provenance = json.loads((tmp_path / 'ram.json.provenance.json').read_text())
    assert provenance['entropy_hex'] == '78563412'
    assert provenance['ram_address'] == 'resolved-from-declared-runtime-window'


@pytest.mark.parametrize('selector,operation', tuple(enumerate(
    ('MUL', 'MULH', 'MULHSU', 'MULHU', 'DIV', 'DIVU', 'REM', 'REMU'), start=19)))
def test_opt_in_m_instructions_match_cpu_profile_and_safe_registers(selector, operation):
    from myfuzz.isa.constraints import IsaContract, RiscvInstructionProvider
    from myfuzz.scenario.rv32i_sources import validate_instruction_bytes
    profile = load_component_profile(ROOT / 'configs/cpus/cv32e20/component_profile.json')
    entropy = bytes((selector, 0xd2, 0, 0))
    result = build_f1_records(profile, entropy, register_dependencies=True, enable_m=True)
    word = int.from_bytes(bytes.fromhex(result['records'][0][3:]), 'little')
    assert result['runtime_admission'] == 'requires-bound-rv32im-profile'
    assert (word >> 7 & 31, word >> 15 & 31, word >> 20 & 31) == (14, 12, 13)
    assert RiscvInstructionProvider(IsaContract(32, ('I', 'M'))).is_legal_word(word)
    from myfuzz.isa.transducer import RiscvInstructionTransducer
    assert word == RiscvInstructionTransducer(IsaContract(32, ('I', 'M'))).repair_for_operation(
        operation, word).word
    with pytest.raises(ValueError):
        validate_instruction_bytes(word.to_bytes(4, 'little'))
    assert build_f1_records(profile, entropy, register_dependencies=True, enable_m=True) == result


def test_m_opt_in_rejects_i_only_cpu_and_does_not_change_default():
    from types import SimpleNamespace
    profile = load_component_profile(ROOT / 'configs/cpus/cv32e20/component_profile.json')
    entropy = bytes.fromhex('13d20000')
    assert build_f1_records(profile, entropy) == build_f1_records(profile, entropy, enable_m=False)
    i_only = SimpleNamespace(cpu=SimpleNamespace(family='riscv', xlen=32, extensions=('i',)))
    with pytest.raises(ValueError, match='M extension'):
        build_f1_records(i_only, entropy, enable_m=True)


def test_f1_cli_m_opt_in_records_replay_provenance(tmp_path):
    import json
    output = tmp_path / 'm.json'
    result = subprocess.run([sys.executable, str(ROOT / 'scripts/generate_profile_f1_records.py'),
        '--profile', str(ROOT / 'configs/cpus/cv32e20/component_profile.json'),
        '--entropy-hex', '000007000001030013d20000', '--register-dependencies', '--enable-m',
        '--output', str(output)], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    provenance = json.loads((tmp_path / 'm.json.provenance.json').read_text())
    assert provenance['extensions_enabled'] == ['M']
    assert provenance['runtime_admission'] == 'requires-bound-rv32im-profile'
    assert provenance['records'] == json.loads(output.read_text())
