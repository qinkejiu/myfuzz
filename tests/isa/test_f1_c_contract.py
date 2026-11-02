from pathlib import Path
from types import SimpleNamespace

import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.isa.constraints import IsaContract, f1_isa_from_profile
from myfuzz.isa.profile_program import build_f1_records
from myfuzz.runtime.flows.memory import lower_memory_code
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.rv32i_sources import validate_instruction_bytes


ROOT = Path(__file__).resolve().parents[2]
IMC = IsaContract(32, ('I', 'M', 'C'), instruction_alignment=2)


def test_profile_c_pair_generation_and_runtime_admission():
    profile = load_component_profile(ROOT / 'configs/cpus/cv32e20/component_profile.json')
    assert 'C' in f1_isa_from_profile(profile).extensions
    result = build_f1_records(profile, bytes.fromhex('00010102'), enable_c=True)
    assert result['extensions_enabled'] == ['C']
    raw = bytes.fromhex(result['records'][0][3:])
    assert len(raw) == 4
    for offset in (0, 2):
        word = int.from_bytes(raw[offset:offset + 2], 'little')
        assert word & 3 != 3 and 12 <= (word >> 7 & 31) <= 15
    with pytest.raises(ValueError):
        validate_instruction_bytes(raw)
    validate_instruction_bytes(raw, isa=IMC)
    with pytest.raises(ValueError):
        lower_memory_code(SimpleNamespace(instruction_isa=IsaContract(32, ('I',))), raw, flow='F1')
    assert lower_memory_code(SimpleNamespace(instruction_isa=IMC), raw, flow='F1') == (raw, 'instruction', None)
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x1000, 0x1000),),
        initialization_seed=0, max_initialized_bytes=0x1000, instruction_isa=IMC)
    memory.declare_instruction_slots(0x1000)
    assert memory.accept_instructions(0x1000, raw, source_event_id='case').data == raw
    memory.cold_reset()
    assert memory.accept_instructions(0x1000, raw, source_event_id='fresh').data == raw


def test_invalid_or_unsafe_halfword_and_undeclared_c_are_rejected():
    i_only = SimpleNamespace(cpu=SimpleNamespace(family='riscv', xlen=32, extensions=('i',)))
    with pytest.raises(ValueError, match='C extension'):
        build_f1_records(i_only, bytes(4), enable_c=True)
    for raw in (bytes.fromhex('01001300'), bytes.fromhex('01000100'), bytes.fromhex('00000100')):
        with pytest.raises(ValueError):
            validate_instruction_bytes(raw, isa=IMC)


def test_c_pair_uses_public_f1_kernel_and_shared_slot(monkeypatch):
    from myfuzz.runtime.flows.memory import MemoryFlowContext, MemoryFlowKernel
    from myfuzz.runtime.generic_campaign import load_descriptor, select_case_records
    from myfuzz.integration import shared_slot_consumers as shared
    profile = load_component_profile(ROOT / 'configs/cpus/cv32e20/component_profile.json')
    record = build_f1_records(profile, bytes.fromhex('00010102'), enable_c=True)['records'][0]
    raw = bytes.fromhex(record[3:])
    descriptor = load_descriptor(ROOT / 'configs/scenarios/compiled-f1-f6-cv32e20-gpio-dma-shared/generic_scenario.json', base_dir=ROOT)
    assert select_case_records(descriptor, flow='mixed', records=[record]) == (('F1', raw.hex()),)
    case = {'testcase_id': 'case', 'path_id': 'path', 'source_id': 'source', 'raw_records_hex': [raw.hex()]}
    with pytest.raises(ValueError):
        MemoryFlowKernel().lower(MemoryFlowContext('a'*64, 'path', 'F1', 'source'), case)
    assert MemoryFlowKernel().lower(MemoryFlowContext('a'*64, 'path', 'F1', 'source', IMC), case).raw_records == (raw,)
    monkeypatch.setattr(shared, 'instruction_bindings', lambda admission: {})
    inputs = {'compiled': {'paths': [{'flow_id': 'F1', 'status': 'executable'}]}}
    layout = {'scratch_address': 0x2000}
    with pytest.raises(ValueError):
        shared.declare_slot(inputs, layout, {}, flow='F1', raw=raw, slot_index=0)
    declaration = shared.declare_slot(inputs, layout, {}, flow='F1', raw=raw, slot_index=0, instruction_isa=IMC)
    assert bytes.fromhex(declaration['code_hex']).startswith(raw)


def test_compressed_pair_reports_each_actual_retirement_separately():
    from myfuzz.isa.f1_retirement import observe_f1_word_retirements
    raw = bytes.fromhex('05461106')
    def event(address, word, event_id):
        return {'kind': 'cpu_retire', 'schema_version': 'cpu_retire.v2', 'component': 'cpu',
                'source_component': 'cpu', 'execution_id': 'local-execution', 'source_epoch': 0,
                'reset_epoch': 0, 'pc_rdata': address, 'insn': word, 'valid': 1,
                'order': event_id, 'event_id': event_id,
                'observation': {'sampling_edge': 'post_rising', 'physical': {
                    'rvfi_valid': 1, 'rvfi_order': event_id, 'rvfi_pc_rdata': address, 'rvfi_insn': word}}}
    first = event(0x1000, int.from_bytes(raw[:2], 'little'), 11)
    second = event(0x1002, int.from_bytes(raw[2:], 'little'), 12)
    result = observe_f1_word_retirements([first, second], cpu='cpu', execution_id='local-execution',
        epoch=0, address=0x1000, raw=raw, source_event_id=10)
    assert result['status'] == 'observed'
    assert [row['pc'] for row in result['instructions']] == [0x1000, 0x1002]
    partial = observe_f1_word_retirements([first], cpu='cpu', execution_id='local-execution',
        epoch=0, address=0x1000, raw=raw, source_event_id=10)
    assert partial['status'] == 'unknown'
    assert [row['status'] for row in partial['instructions']] == ['observed', 'unknown']


@pytest.mark.parametrize('selector,operation', tuple(enumerate((
    'C.ADDI', 'C.LI', 'C.SUB', 'C.XOR', 'C.OR', 'C.AND', 'C.SLLI',
    'C.SRLI', 'C.SRAI', 'C.ANDI', 'C.MV', 'C.ADD', 'C.LUI'))))
def test_generated_compressed_alu_is_profile_gated_and_uses_safe_registers(selector, operation):
    from myfuzz.isa.transducer import RiscvInstructionTransducer
    profile = load_component_profile(ROOT / 'configs/cpus/cv32e20/component_profile.json')
    result = build_f1_records(profile, bytes((selector, 0x17, selector, 0x17)), enable_c=True)
    raw = bytes.fromhex(result['records'][0][3:])
    word = int.from_bytes(raw[:2], 'little')
    tx = RiscvInstructionTransducer(IsaContract(32, ('I', 'C'), instruction_alignment=2))
    assert tx.repair_for_operation(operation, word).word == word
    validate_instruction_bytes(raw, isa=IMC)
    assert lower_memory_code(SimpleNamespace(instruction_isa=IMC), raw, flow='F1') == (raw, 'instruction', None)
    if operation in ('C.SUB', 'C.XOR', 'C.OR', 'C.AND'):
        assert 12 <= 8 + (word >> 7 & 7) <= 15
        assert 12 <= 8 + (word >> 2 & 7) <= 15
    elif operation in ('C.SRLI', 'C.SRAI', 'C.ANDI'):
        assert 12 <= 8 + (word >> 7 & 7) <= 15
    else:
        assert 12 <= (word >> 7 & 31) <= 15
    if operation in ('C.MV', 'C.ADD'):
        assert 12 <= (word >> 2 & 31) <= 15


def test_compressed_control_and_unsafe_registers_still_rejected():
    # C.JR x12 followed by C.NOP, C.ADDI x10 followed by C.NOP.
    for raw in (bytes.fromhex('02860100'), bytes.fromhex('05050100')):
        with pytest.raises(ValueError):
            validate_instruction_bytes(raw, isa=IMC)
