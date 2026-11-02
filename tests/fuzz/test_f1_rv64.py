"""The declared RV64I F1 mode: real 64-bit programs, reference trace and hash.

No RTL is simulated here.  The pinned facts are the ones the real RV64 run
depends on:

  * the admitted subset decodes and re-encodes exactly (LUI, ADDI, ADD, SUB,
    AND, OR, XOR, ADDIW, ADDW, SLLIW, SRLIW, SRAIW, LD, SD), and everything else
    -- a branch, jump, CSR/system word, compressed parcel, a write to a
    firmware-owned register, a read before the program wrote it, or a memory
    word outside the declared window -- is refused by name;
  * the reference semantics are the RV64 ones: ADDIW/ADDW/SRLIW/SRAIW
    sign-extend a 32-bit result into the 64-bit register, ADD/SUB/AND/OR/XOR and
    LD/SD are 64-bit, and a store retires with rd 0 / wdata 0 (RVFI's own rule);
  * the trace hash is FNV-1a 64 over 8-byte fields and is never the 32-bit
    digest of the RV32 gate;
  * the declared scenario is a 64-bit CPU on the packed AXI4 retirement path with
    no RV32 projection, and its header states ``F1_RV64 1`` while the existing
    RV32 scenario keeps ``F1_RV64 0``.
"""
import json
from pathlib import Path

import pytest

from myfuzz.fuzz.f1_rv64 import (MASK64, Rv64ProgramError, _decode, _encode,
                                 expectation, generate_program, trace_hash64,
                                 validate_rv64_record)
from scripts.run_inprocess_f1f6 import (AXI4_CPU_INPUT_ROLES, AXI4_CPU_OUTPUT_ROLES,
                                        CVA6_RVFI_PROBES_BITS, build_layout,
                                        declared_windows, f1_declared_mode,
                                        render_bindings)

ROOT = Path(__file__).resolve().parents[2]
RV64_CONFIG_PATH = ROOT / 'configs/scenarios/inprocess-cva6-axi4-timer-f1-rv64.json'
RV64_CONFIG = json.loads(RV64_CONFIG_PATH.read_text())
BASE_CONFIG = json.loads(
    (ROOT / 'configs/scenarios/inprocess-cva6-axi4-timer-f1-f2f4.json').read_text())
WINDOWS = declared_windows(RV64_CONFIG)
LAYOUT = build_layout(WINDOWS, 0x10000)
SLOT = LAYOUT['slot']
DATA_BASE = LAYOUT['data_base']
WINDOW = [0xDEADBEEF, 0x11111111] + [0] * 14
PROBE_PORT = 'rt_lh_p_11_6973_0'


def clock(frequency):
    return dict(phase_policy='all_low_then_half_period_toggle',
                clocks=[dict(signal='clk', ratio=1, first_rising_fast_tick=1,
                             half_period_fast_ticks=1, frequency_hz=frequency)])


def cpu_document():
    exports = [dict(physical_port='rvfi_probes_o', direction='output',
                    width=CVA6_RVFI_PROBES_BITS, bit_lo=0,
                    bit_hi=CVA6_RVFI_PROBES_BITS - 1, runtime_name=PROBE_PORT)]
    exports.append(dict(endpoint_id='processor.interrupts', role='machine_external',
                        direction='input', width=1, runtime_name='rt_lh_p_7_0_0'))
    backend = [dict(channel='axi', role=role, name='axi_' + role, direction='output',
                    width=4 if role == 'arid' else 1)
               for role in AXI4_CPU_OUTPUT_ROLES]
    backend += [dict(channel='axi', role=role, name='axi_' + role, direction='input',
                     width=1) for role in AXI4_CPU_INPUT_ROLES]
    return dict(kind='cva6_packed_axi4_cpu', module_name='local_runtime_processor',
                clock_schedule=clock(50000000), physical_exports=exports,
                runtime_ports=[dict(name=PROBE_PORT, direction='output',
                                    width=CVA6_RVFI_PROBES_BITS)],
                backend_ports=backend,
                plan=dict(timing=dict(reset_assert_ticks=12, reset_release_ticks=8)))


def ip_document():
    signals = {role: 'trace_' + role for role in
               ('psel', 'penable', 'pready', 'pwrite', 'paddr', 'pwdata', 'prdata',
                'pslverr')}
    roles = ('req_valid', 'req_ready', 'req_write', 'req_addr', 'req_wdata', 'req_be',
             'rsp_valid', 'rsp_ready', 'rsp_rdata', 'rsp_error')
    return dict(kind='apb3_register_observe',
                module_name='local_runtime_pulp_timer_active',
                clock_schedule=clock(50000000),
                base_protocol_trace=dict(protocol='apb3', signals=signals),
                physical_exports=[dict(physical_port='irq_o', direction='output',
                                       width=4, bit_lo=0, bit_hi=3,
                                       runtime_name='irq_wide')],
                backend_ports=[dict(channel='reg', role=role, name='reg_' + role)
                               for role in roles],
                plan=dict(timing=dict(reset_assert_ticks=2, reset_release_ticks=3)))


def cpu_profile():
    from myfuzz.composition.component_profile import load_component_profile
    return load_component_profile(ROOT / RV64_CONFIG['cpu_profile'])


def header(config=RV64_CONFIG):
    return render_bindings(config, cpu_document(), ip_document(), None, LAYOUT,
                           cpu_profile(), irq=None, dma=None, dma_irq=None,
                           f1_words=4)


# --- the subset ------------------------------------------------------------

def encode(name, **operands):
    return _encode(dict(name=name, **operands))


@pytest.mark.parametrize('instruction', [
    dict(name='LUI', rd=5, imm=0x12345000),
    dict(name='ADDI', rd=5, rs1=5, imm=-3),
    dict(name='ADD', rd=6, rs1=5, rs2=18),
    dict(name='SUB', rd=6, rs1=5, rs2=5),
    dict(name='AND', rd=6, rs1=5, rs2=18),
    dict(name='OR', rd=6, rs1=5, rs2=18),
    dict(name='XOR', rd=6, rs1=5, rs2=18),
    dict(name='ADDIW', rd=6, rs1=5, imm=7),
    dict(name='ADDW', rd=6, rs1=5, rs2=18),
    dict(name='SLLIW', rd=6, rs1=5, shamt=3),
    dict(name='SRLIW', rd=6, rs1=5, shamt=4),
    dict(name='SRAIW', rd=6, rs1=5, shamt=5),
    dict(name='LD', rd=6, rs1=18, imm=8),
    dict(name='SD', rs1=18, rs2=5, imm=16),
])
def test_every_declared_instruction_round_trips(instruction):
    word = _encode(instruction)
    assert _decode(word)['name'] == instruction['name']
    assert validate_rv64_record([encode('LUI', rd=5, imm=0x1000), word],
                                max_words=4) == [encode('LUI', rd=5, imm=0x1000), word]


@pytest.mark.parametrize('words, why', [
    ([0x00000073], 'a CSR/system word'),
    ([0x00800067], 'a jump'),
    ([0x00000463], 'a branch'),
    ([0x00000003], 'a load that is not LD'),
    ([0x0005051b, 0x00028493], 'a write to the reserved x9'),
    ([0x00028413], 'a write to the mailbox pointer x8'),
    ([0x00090c03], 'an unaligned LD offset'),
    ([0x00090e03], 'an LD past the declared window'),
    ([encode('ADD', rd=6, rs1=5, rs2=18)], 'a read before the program wrote x5'),
])
def test_words_outside_the_subset_are_refused(words, why):
    with pytest.raises(Rv64ProgramError):
        validate_rv64_record(words, max_words=4)


def test_the_window_bound_follows_the_declared_data_window():
    words = [encode('LUI', rd=5, imm=0x1000), encode('SD', rs1=18, rs2=5, imm=56)]
    assert validate_rv64_record(words, max_words=4)
    with pytest.raises(Rv64ProgramError):
        validate_rv64_record(words + [encode('LD', rd=6, rs1=18, imm=64)],
                             max_words=4)


# --- 64-bit semantics ------------------------------------------------------

def test_addiw_sign_extends_the_32_bit_result_into_64_bits():
    words = [encode('LUI', rd=5, imm=0x80000000 & 0xFFFFF000),
             encode('ADDIW', rd=6, rs1=5, imm=1)]
    expected = expectation(words, slot=SLOT, data_base=DATA_BASE, window=WINDOW)
    assert expected['trace'][1]['wdata'] == 0xFFFFFFFF80000001
    assert expected['trace'][1]['wdata'] > 0xFFFFFFFF


def test_sraiw_is_the_arithmetic_32_bit_shift_then_sign_extended():
    words = [encode('LUI', rd=5, imm=0x80000000 & 0xFFFFF000),
             encode('SRAIW', rd=6, rs1=5, shamt=4)]
    expected = expectation(words, slot=SLOT, data_base=DATA_BASE, window=WINDOW)
    assert expected['trace'][1]['wdata'] == 0xFFFFFFFFF8000000


def test_srliw_zero_fills_inside_the_32_bit_word():
    words = [encode('LUI', rd=5, imm=0x80000000 & 0xFFFFF000),
             encode('SRLIW', rd=6, rs1=5, shamt=4)]
    expected = expectation(words, slot=SLOT, data_base=DATA_BASE, window=WINDOW)
    assert expected['trace'][1]['wdata'] == 0x0000000008000000


def test_ld_reads_the_full_eight_bytes_of_the_declared_window():
    words = [encode('LD', rd=6, rs1=18, imm=0)]
    expected = expectation(words, slot=SLOT, data_base=DATA_BASE, window=WINDOW)
    # The window's first two words, little-endian: 0xdeadbeef then 0x11111111.
    assert expected['trace'][0]['wdata'] == 0x11111111DEADBEEF


def test_sd_retires_without_a_writeback_and_changes_the_window():
    words = [encode('LUI', rd=5, imm=0x12345000),
             encode('SD', rs1=18, rs2=5, imm=8)]
    expected = expectation(words, slot=SLOT, data_base=DATA_BASE, window=WINDOW)
    store = expected['trace'][1]
    assert (store['rd'], store['wdata']) == (0, 0)
    # The eight bytes land in window words 2 and 3; only word 2 changes, because
    # the stored value's high half is zero and word 3 already was.
    assert expected['window_changed'] == 1
    assert expected['window_after'][2] == 0x12345000
    assert expected['window_after'][3] == 0x0
    assert expected['window_after'][0] == 0xDEADBEEF


def test_add_of_a_window_base_is_a_full_64_bit_value():
    words = [encode('LUI', rd=5, imm=0x0),
             encode('ADD', rd=5, rs1=5, rs2=18)]
    expected = expectation(words, slot=SLOT, data_base=DATA_BASE, window=WINDOW)
    assert expected['last_wdata'] == DATA_BASE
    assert expected['last_pc'] == SLOT + 4


# --- the trace hash --------------------------------------------------------

def test_the_trace_hash_is_64_bit_and_not_the_32_bit_digest():
    words = [encode('LUI', rd=5, imm=0x1000),
             encode('ADDIW', rd=6, rs1=5, imm=1)]
    expected = expectation(words, slot=SLOT, data_base=DATA_BASE, window=WINDOW)
    digest = expected['trace_hash']
    assert digest.startswith('fnv1a64:')
    assert len(digest) == len('fnv1a64:') + 16
    # The four fields are hashed as 8-byte values, so a change in the upper half
    # of the writeback changes the digest (a 32-bit projection would not).
    wide = [encode('LUI', rd=5, imm=0x12345000),
            encode('ADD', rd=6, rs1=5, rs2=18)]
    other = expectation(wide, slot=SLOT, data_base=DATA_BASE, window=WINDOW)
    assert other['trace_hash'] != digest
    assert trace_hash64([dict(pc=SLOT, insn_word=1, rd=0, wdata=0)]) == \
        'fnv1a64:' + format(_fnv64([(SLOT, 1, 0, 0)]), '016x')


def _fnv64(entries):
    digest = 14695981039346656037
    for entry in entries:
        for value in entry:
            for byte in (value & MASK64).to_bytes(8, 'little'):
                digest ^= byte
                digest = (digest * 1099511628211) & MASK64
    return digest


# --- the generator and the scenario declaration ----------------------------

@pytest.mark.parametrize('seed', [64001, 64002, 64003, 64004, 64005])
def test_generated_programs_are_legal_and_deterministic(seed):
    for max_words in (2, 3, 4):
        words = generate_program(seed, max_words=max_words)
        assert len(words) <= max_words
        assert validate_rv64_record(words, max_words=max_words) == words
        first = expectation(words, slot=SLOT, data_base=DATA_BASE, window=WINDOW)
        second = expectation(words, slot=SLOT, data_base=DATA_BASE, window=WINDOW)
        assert first['trace'] == second['trace']
        assert first['trace_hash'] == second['trace_hash']


def test_the_rv64_scenario_is_declared_and_its_header_states_it():
    assert RV64_CONFIG['f1_rv64'] is True
    assert 'f1_rv32_projection' not in RV64_CONFIG
    assert 'f1_trap_program' not in RV64_CONFIG
    assert f1_declared_mode(RV64_CONFIG) == 'rv64'
    assert f1_declared_mode(BASE_CONFIG) is None
    text = header()
    assert '#define F1_RV64 1' in text
    assert '#define F1_TRAP_PROGRAM 0' in text
    assert '#define HAVE_RVFI_TRAP_WITNESS 1' in text
    # The existing RV32 scenario keeps the projection path and states 0 here.
    base = render_bindings(BASE_CONFIG, cpu_document(), ip_document(), None,
                           build_layout(declared_windows(BASE_CONFIG), 0x10000),
                           cpu_profile(), irq=None, dma=None, dma_irq=None,
                           f1_words=4)
    assert '#define F1_RV64 0' in base
    assert '#define F1_TRAP_PROGRAM 0' in base


def test_the_host_hashes_the_64_bit_record_and_never_the_32_bit_digest():
    source = (ROOT / 'scripts/inprocess_obi_apb_f1f4_spike.cpp').read_text()
    assert 'namespace f1_trace64' in source
    assert 'observation.prog_trace_hash64 = f1_trace64::entry(' in source
    # The 32-bit digest is not even printed in a 64-bit build.
    assert '#if !F1_RV64\n        std::cout << " prog_trace_hash "' in source
    assert 'prog_trace_hash64 " << hex64(observation.prog_trace_hash64)' in source
    assert 'prog_last_wdata64 " << hex64(observation.prog_last_wdata64)' in source
