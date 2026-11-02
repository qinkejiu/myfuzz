"""The CVA6 RVFI trap / CSR witness: extra record fields + the declared trap case.

No RTL is simulated and no Verilator model is built here.  What is pinned is
what the real trap run depends on:

  * the wrapper RTL carries the commit lane's own ``cause``/``intr``/``mode``
    with the record, and exposes the scoreboard's registered CSR readback
    (``mcause``/``mepc``/``mtval``/``mtvec``/``mstatus``) rather than inventing
    one;
  * the generated header binds those ports and states
    ``HAVE_RVFI_TRAP_WITNESS 1`` for this CPU, and the host reads the record's
    fields instead of reporting a trap with an unknown cause;
  * the declared trap scenario is an M-mode ECALL (cause 11), its handler lives
    in the firmware image (not in the slot program), and the firmware really
    reads mcause/mepc with CSRRS, stores them, advances mepc past the ECALL and
    returns with MRET;
  * the host's F1 rule for that mode compares the record, the CSR readback and
    the stored words, and the run-log parser accepts the witnessed trap and CSR
    lines it prints (and still accepts the historical "cause unknown" shape).
"""
import json
from pathlib import Path

import pytest

from myfuzz.fuzz.f1_trap_program import (
    ECALL_WORD, ENV_CALL_MMODE, TrapProgramError, expectation, reference_trace,
    trace_hash, trap_declaration, trap_layout, validate_trap_record)
from scripts.run_inprocess_f1f6 import (AXI4_CPU_INPUT_ROLES, AXI4_CPU_OUTPUT_ROLES,
                                        CVA6_RVFI_PROBES_BITS, build_firmware,
                                        build_layout, declared_windows,
                                        f1_declared_mode, parse_event_line,
                                        render_bindings)

ROOT = Path(__file__).resolve().parents[2]
BASE_CONFIG = json.loads(
    (ROOT / 'configs/scenarios/inprocess-cva6-axi4-timer-f1-f2f4.json').read_text())
TRAP_CONFIG_PATH = ROOT / 'configs/scenarios/inprocess-cva6-axi4-timer-f1-trap.json'
TRAP_CONFIG = json.loads(TRAP_CONFIG_PATH.read_text())
WINDOWS = declared_windows(TRAP_CONFIG)
LAYOUT = build_layout(WINDOWS, 0x10000)
TRAP_LAYOUT = trap_layout(LAYOUT)
WRAPPER = ROOT / 'src/myfuzz/local_harness/rtl/cva6_rvfi_top.sv'
HOST_SOURCE = ROOT / 'scripts/inprocess_obi_apb_f1f4_spike.cpp'
PROBE_PORT = 'rt_lh_p_11_6973_0'
SLOT = LAYOUT['slot']


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
    return load_component_profile(ROOT / TRAP_CONFIG['cpu_profile'])


def header(config=TRAP_CONFIG, layout=TRAP_LAYOUT, document=None):
    return render_bindings(config, document if document is not None else cpu_document(),
                           ip_document(), None, layout, cpu_profile(),
                           irq=None, dma=None, dma_irq=None, f1_words=4)


# --- the wrapper RTL -------------------------------------------------------

def test_the_wrapper_emits_the_trap_witness_with_the_record():
    text = WRAPPER.read_text()
    # The record carries the commit lane's own fields, not host-derived ones.
    assert 'logic [63:0] cause;' in text
    assert 'logic [63:0] intr;' in text
    assert 'logic [1:0]  mode;' in text
    assert 'next_queue[next_count].cause    = 64\'(rvfi_instr[lane].cause);' in text
    assert 'next_queue[next_count].intr     = 64\'(rvfi_instr[lane].intr);' in text
    assert 'next_queue[next_count].mode     = 2\'(rvfi_instr[lane].mode);' in text
    for name in ('rvfi_cause', 'rvfi_intr', 'rvfi_mode'):
        assert f'output logic' in text and name in text
    # The CSR readback is the scoreboard's own registered view.
    for csr in ('mcause', 'mepc', 'mtval', 'mtvec', 'mstatus'):
        assert f"assign rvfi_{csr}" in text
        assert f"rvfi_csr.{csr}.rdata" in text
    # The doc comment states the real semantics of the pinned scoreboard's intr
    # word so nobody reads it as a one-bit "this record trapped" flag.
    assert "'b101" in text and "'b11" in text


def test_the_header_binds_the_trap_witness_and_the_csr_readback():
    text = header()
    assert '#define HAVE_RVFI_TRAP_WITNESS 1' in text
    for role in ('cause', 'intr', 'mode'):
        assert f'#define CPU_RVFI_{role.upper()} rvfi_{role}' in text
    for csr in ('mcause', 'mepc', 'mtval', 'mtvec', 'mstatus'):
        assert f'#define CPU_RVFI_CSR_{csr.upper()} rvfi_{csr}' in text
    assert '#define F1_TRAP_PROGRAM 1' in text
    assert f'#define F1_TRAP_CAUSE {ENV_CALL_MMODE}u' in text
    assert '#define F1_TRAP_WORDS 2u' in text
    for key in ('trap_cause', 'trap_epc', 'trap_flag'):
        assert f'#define TRAP_{key.split("_")[1].upper()}_CELL {TRAP_LAYOUT[key]}u' in text
    assert '#define TRAP_SENTINEL 0xffffffffu' in text


def test_a_build_without_the_bundle_states_no_trap_witness():
    document = cpu_document()
    document['physical_exports'] = [row for row in document['physical_exports']
                                    if row.get('physical_port') != 'rvfi_probes_o']
    text = header(document=document)
    assert '#define HAVE_RVFI_TRAP_WITNESS 0' in text
    assert '#define CPU_RVFI_CAUSE' not in text
    assert '#define HAVE_RVFI_ADAPTER 0' in text


# --- the declared trap scenario and its firmware ---------------------------

def test_the_trap_scenario_declares_one_m_mode_ecall():
    declared = trap_declaration(TRAP_CONFIG)
    assert declared == dict(cause=ENV_CALL_MMODE, words=2,
                            cells=dict(cause='trap_cause', epc='trap_epc',
                                       flag='trap_flag'))
    assert TRAP_CONFIG['f1_program_words'] >= declared['words']
    assert 'f1_rv32_projection' not in TRAP_CONFIG
    assert 'f1_rv64' not in TRAP_CONFIG
    assert f1_declared_mode(TRAP_CONFIG) == 'trap'
    assert f1_declared_mode(BASE_CONFIG) is None


@pytest.mark.parametrize('declared', [
    dict(cause=8),                 # an ECALL from U-mode is not this handler
    dict(cause=11, surprise=1),    # an undeclared key
    'an-ecall',                    # not an object
])
def test_a_trap_declaration_outside_the_one_handler_is_refused(declared):
    with pytest.raises(ValueError):
        trap_declaration(dict(f1_trap_program=declared))


def test_the_firmware_image_carries_the_handler_and_installs_the_vector():
    layout = trap_layout(build_layout(WINDOWS, 0x10000))
    firmware = build_firmware(layout, irq=None, dma=None,
                              interrupt_bootstrap=True, f1_words=4,
                              f1_trap=trap_declaration(TRAP_CONFIG))
    images = firmware['images']
    assert layout['trap_handler'] in images
    handler = images[layout['trap_handler']]
    words = [int.from_bytes(handler[4 * index:4 * index + 4], 'little')
             for index in range(len(handler) // 4)]
    # CSRRS x10, mcause, x0 / CSRRS x11, mepc, x0 / ... / CSRRS x0, mepc, x11 /
    # MRET: the handler's own architectural reads and its resume write.
    assert any((word >> 20) & 0xFFF == 0x342 for word in words)
    assert any((word >> 20) & 0xFFF == 0x341 for word in words)
    assert 0x30200073 in words
    # The MPC+4 advance and the two stores are real instructions in the image.
    assert any(word & 0x7F == 0x13 for word in words)
    assert sum(1 for word in words if word & 0x7F == 0x23) == 3
    # The exception entry of the vector jumps to the trap handler, while the
    # machine-external interrupt slot keeps the F5 handler target.
    vector = images[layout['vector']]
    first = int.from_bytes(vector[0:4], 'little')
    assert first & 0x7F == 0x6F
    target = layout['vector'] + ((first >> 31) << 20)
    target |= ((first >> 12) & 0xFF) << 12
    target |= ((first >> 20) & 1) << 11
    target |= ((first >> 21) & 0x3FF) << 1
    assert target == layout['trap_handler']
    mei = int.from_bytes(vector[44:48], 'little')
    mei_target = layout['vector'] + 44 + (((mei >> 31) << 20)
                                          | (((mei >> 12) & 0xFF) << 12)
                                          | (((mei >> 20) & 1) << 11)
                                          | (((mei >> 21) & 0x3FF) << 1))
    assert mei_target == layout['handler']


# --- the record validator and the reference trace --------------------------

def test_the_trap_record_is_the_ecall_then_straight_line_alu():
    words = [ECALL_WORD, 0x00000013]
    assert validate_trap_record(words, slot=SLOT, max_words=4) == words


@pytest.mark.parametrize('words, why', [
    ([0x00000013, ECALL_WORD], 'the ECALL must come first'),
    ([ECALL_WORD, ECALL_WORD], 'a second system word is refused'),
    ([ECALL_WORD, 0x00800067], 'a jump after the ECALL is refused'),
    ([ECALL_WORD, 0x00802023], 'a store after the ECALL is refused'),
    ([ECALL_WORD, 0x0002c503], 'a load after the ECALL is refused'),
    ([ECALL_WORD, 0x00800333], 'reading firmware state is refused'),
    ([ECALL_WORD, 0x00028413], 'writing the mailbox pointer x8 is refused'),
    ([ECALL_WORD, 0x00000493], 'writing the reserved x9 is refused'),
])
def test_a_record_outside_the_declared_trap_program_is_refused(words, why):
    with pytest.raises(TrapProgramError):
        validate_trap_record(words, slot=SLOT, max_words=4)


def test_the_reference_trace_states_the_trap_record_and_the_alu_words():
    words = [ECALL_WORD, 0x00000013]
    reference = reference_trace(words, slot=SLOT)
    assert reference['retired'] == 2
    assert reference['trap_pc'] == SLOT
    assert reference['cause'] == ENV_CALL_MMODE
    assert reference['mode'] == 3
    ecall = reference['trace'][0]
    # RVFI's own rule for a retirement that writes no register.
    assert (ecall['rd'], ecall['wdata']) == (0, 0)
    assert ecall['trap'] is True
    # The same digest the real host printed for this exact record.
    assert trace_hash(reference['trace']) == 'fnv1a32:6907cf11'


def test_the_expectation_names_the_handler_resume_and_the_stored_words():
    expected = expectation([ECALL_WORD, 0x02b00293], slot=SLOT)
    assert expected['stored_cause'] == ENV_CALL_MMODE
    assert expected['stored_epc'] == SLOT
    assert expected['resume_pc'] == SLOT + 4
    assert expected['successor_pc'] == SLOT + 8
    assert expected['intr'] == 0
    assert expected['last_rd'] == 5 and expected['last_wdata'] == 43


# --- the host's own reading of the witness ---------------------------------

def test_the_host_reads_the_record_fields_and_checks_the_stored_words():
    text = HOST_SOURCE.read_text()
    assert 'CPU_RVFI_CAUSE' in text and 'CPU_RVFI_INTR' in text
    assert 'CPU_RVFI_MODE' in text
    assert 'CPU_RVFI_CSR_MCAUSE' in text and 'CPU_RVFI_CSR_MEPC' in text
    # The trap event carries the cause, and the CSR readback has its own event.
    assert 'cause " << hex64(cause)' in text
    assert 'EVENT_STREAM << "csr_trap "' in text
    assert 'EVENT_STREAM << "csr_mepc "' in text
    # The declared mode's F1 rule compares the record, the readback and the
    # handler's stored words; a trap outside that rule still fails the case.
    assert 'observation.trap_cause == uint64_t(F1_TRAP_CAUSE)' in text
    assert 'observation.rvfi_mepc_final == uint64_t(kSlot + 4)' in text
    assert 'observation.trap_stored_epc == kSlot' in text
    assert 'TRAP_CAUSE_CELL' in text and 'TRAP_SENTINEL' in text
    # The sentinel is written before the case, so a stale word cannot pass.
    assert 'memory.write(TRAP_CAUSE_CELL, TRAP_SENTINEL, 15)' in text


def test_the_witnessed_trap_line_and_the_historical_one_both_parse():
    witnessed = parse_event_line(
        'trap 600 pc 0x00012000 insn 0x00000073 cause 0x000000000000000b '
        'intr 0x0000000000000000 mode 3')
    assert witnessed['cause'] == '0x000000000000000b'
    assert witnessed['intr'] == 0 and witnessed['mode'] == 3
    legacy = parse_event_line(
        'trap 12 pc 0x00010000 insn 0x00000073 cause unknown')
    assert legacy['cause'] == 'unknown'
    assert legacy['intr'] is None and legacy['mode'] is None
    csr = parse_event_line(
        'csr_trap 600 mcause 0x000000000000000b mepc 0x0000000000012000 '
        'mtval 0x0000000000000000 mtvec 0x0000000000010201 '
        'mstatus 0x0000000a00001880')
    assert csr['kind'] == 'csr_trap' and csr['mcause'] == 11
    assert csr['mepc'] == 0x12000 and csr['mtvec'] == 0x10201
    later = parse_event_line('csr_mepc 691 mcause 0x000000000000000b '
                             'mepc 0x0000000000012004')
    assert later['kind'] == 'csr_mepc' and later['mepc'] == 0x12004


def test_the_stored_cells_are_outside_every_other_image_region():
    layout = TRAP_LAYOUT
    cells = (layout['trap_cause'], layout['trap_cause'] + layout['trap_block_bytes'])
    assert cells[0] == layout['ram_base'] + 0x3080
    assert layout['mailbox'] + 0x40 <= cells[0]
    assert cells[1] <= layout['data_base']
    assert layout['trap_handler'] < layout['main']
