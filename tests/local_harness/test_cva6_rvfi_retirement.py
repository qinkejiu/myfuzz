"""The packed AXI4 retirement channel: probe bundle -> pinned RVFI scoreboard.

No RTL is simulated and no Verilator model is built here.  Five kinds of facts
are pinned, and each one is a claim the real F1 run depends on:

  * the CPU model really exports the whole 6974-bit RVFI probe bundle, and the
    entry's discovery returns it only when that whole bundle is present -- a
    narrower, missing or renamed export keeps F1 refused by name instead of being
    read as a retirement channel (a fetch beat is not a retirement);
  * the generated header binds the pinned scoreboard as a second model
    (``HAVE_RVFI_ADAPTER``/``RVFI_ADAPTER``), names the probe-bundle port and the
    RVFI record ports, and states the bundle width and its 32-bit word count;
  * the wrapper RTL is the pinned ``cva6_rvfi`` module plus a two-lane-to-one
    retirement queue, with the probe-bundle type declared from the pinned
    ``rvfi_types.svh`` macros and an elaboration error on a width disagreement
    (never a silent reinterpretation of bits);
  * the host carries the probe words across on the AXI4 link's own low phase and
    clocks the scoreboard on the link's single rising edge, and the retirement
    block reads ``cpu_retirement`` -- the CPU model for an OBI/Wishbone build,
    the scoreboard model for the packed AXI4 build;
  * the F1 program gate stays RV32-only.  A 64-bit CPU is admitted only through an
    explicitly declared ``f1_rv32_projection``; the same 64-bit declaration
    without it is still refused, so the projection is a scenario fact and never
    an implicit xlen coercion.
"""
import json
from pathlib import Path

import pytest

from myfuzz.fuzz.f1_program_gate import (f1_gate_flags_from_scenario,
                                         validate_f1_program_record)
from myfuzz.riscv.profile import RiscvProfile
from scripts.run_inprocess_f1f6 import (AXI4_CPU_INPUT_ROLES, AXI4_CPU_OUTPUT_ROLES,
                                        CVA6_RVFI_PROBES_BITS, CVA6_RVFI_PROBES_WORDS,
                                        axi4_rvfi_probe_export, build_layout,
                                        declared_windows, render_bindings)

ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / 'configs/scenarios/inprocess-cva6-axi4-timer-f1-f2f4.json'
CONFIG = json.loads(CONFIG_PATH.read_text())
F2F4_CONFIG = json.loads(
    (ROOT / 'configs/scenarios/inprocess-cva6-axi4-timer-f2f4.json').read_text())
WINDOWS = declared_windows(CONFIG)
LAYOUT = build_layout(WINDOWS, 0x10000)
WRAPPER = ROOT / 'src/myfuzz/local_harness/rtl/cva6_rvfi_top.sv'
HOST_HEADER = ROOT / 'scripts/inprocess_axi4_host.h'
HOST_SOURCE = ROOT / 'scripts/inprocess_obi_apb_f1f4_spike.cpp'
ENTRY = ROOT / 'scripts/run_inprocess_f1f6.py'
ADAPTER_BUILD = ROOT / 'scripts/inprocess_cva6_rvfi_build.py'
CVA6 = ROOT / 'third_party/cva6_upstream_reference'
PROBE_PORT = 'rt_lh_p_11_6973_0'


def clock(frequency):
    return dict(phase_policy='all_low_then_half_period_toggle',
                clocks=[dict(signal='clk', ratio=1, first_rising_fast_tick=1,
                             half_period_fast_ticks=1, frequency_hz=frequency)])


def cpu_document(probe_width=CVA6_RVFI_PROBES_BITS):
    """The CVA6 artifact the entry receives, with the exports the RTL declares."""
    exports = [dict(physical_port='rvfi_probes_o', direction='output',
                    width=probe_width, bit_lo=0, bit_hi=probe_width - 1,
                    runtime_name=PROBE_PORT)]
    exports.append(dict(endpoint_id='processor.interrupts', role='machine_external',
                        direction='input', width=1, runtime_name='rt_lh_p_7_0_0'))
    backend = [dict(channel='axi', role=role, name='axi_' + role, direction='output',
                    width=4 if role == 'arid' else 1)
               for role in AXI4_CPU_OUTPUT_ROLES]
    backend += [dict(channel='axi', role=role, name='axi_' + role, direction='input',
                     width=1)
                for role in AXI4_CPU_INPUT_ROLES]
    return dict(kind='cva6_packed_axi4_cpu', module_name='local_runtime_processor',
                clock_schedule=clock(50000000), physical_exports=exports,
                runtime_ports=[dict(name=PROBE_PORT, direction='output',
                                    width=probe_width)],
                backend_ports=backend,
                plan=dict(timing=dict(reset_assert_ticks=12, reset_release_ticks=8)))


def ip_document():
    signals = {role: 'trace_' + role for role in
               ('psel', 'penable', 'pready', 'pwrite', 'paddr', 'pwdata', 'prdata',
                'pslverr')}
    roles = ('req_valid', 'req_ready', 'req_write', 'req_addr', 'req_wdata', 'req_be',
             'rsp_valid', 'rsp_ready', 'rsp_rdata', 'rsp_error')
    return dict(kind='apb3_register_observe', module_name='local_runtime_pulp_timer_active',
                clock_schedule=clock(50000000),
                base_protocol_trace=dict(protocol='apb3', signals=signals),
                physical_exports=[dict(physical_port='irq_o', direction='output', width=4,
                                       bit_lo=0, bit_hi=3, runtime_name='irq_wide')],
                backend_ports=[dict(channel='reg', role=role, name='reg_' + role)
                               for role in roles],
                plan=dict(timing=dict(reset_assert_ticks=2, reset_release_ticks=3)))


def cpu_profile():
    from myfuzz.composition.component_profile import load_component_profile
    return load_component_profile(ROOT / CONFIG['cpu_profile'])


def header(document=None):
    return render_bindings(CONFIG, document if document is not None else cpu_document(),
                           ip_document(), None, LAYOUT, cpu_profile(),
                           irq=None, dma=None, dma_irq=None, f1_words=4)


# --- discovery -------------------------------------------------------------

def test_the_whole_probe_bundle_is_the_retirement_channel():
    export = axi4_rvfi_probe_export(cpu_document())
    assert export is not None
    assert export['physical_port'] == 'rvfi_probes_o'
    assert export['runtime_name'] == PROBE_PORT
    assert CVA6_RVFI_PROBES_BITS == 6974 and CVA6_RVFI_PROBES_WORDS == 218


@pytest.mark.parametrize('width', [CVA6_RVFI_PROBES_BITS - 1, 1, 64])
def test_a_narrower_bundle_is_not_a_retirement_channel(width):
    assert axi4_rvfi_probe_export(cpu_document(probe_width=width)) is None


def test_a_model_without_the_bundle_has_no_retirement_channel():
    document = cpu_document()
    document['physical_exports'] = [row for row in document['physical_exports']
                                    if row.get('physical_port') != 'rvfi_probes_o']
    assert axi4_rvfi_probe_export(document) is None
    assert axi4_rvfi_probe_export({}) is None


# --- generated header ------------------------------------------------------

def test_the_header_binds_the_pinned_scoreboard_and_its_record_ports():
    text = header()
    assert '#include "Vcva6_rvfi_top.h"' in text
    assert '#define HAVE_RVFI_ADAPTER 1' in text
    assert '#define RVFI_ADAPTER Vcva6_rvfi_top' in text
    assert f'#define CPU_RVFI_PROBES_WIDTH {CVA6_RVFI_PROBES_BITS}' in text
    assert f'#define CPU_RVFI_PROBES_WORDS {CVA6_RVFI_PROBES_WORDS}' in text
    assert f'#define CPU_RVFI_PROBES {PROBE_PORT}' in text
    # The record ports are the adapter model's own, and the host reads them
    # through `cpu_retirement` (rvfi) rather than through the CPU model.
    for role in ('valid', 'order', 'insn', 'pc_rdata', 'trap', 'rd_addr', 'rd_wdata'):
        assert f'#define CPU_RVFI_{role.upper()} rvfi_{role}' in text
    assert '#define HAVE_RVFI_WRITEBACK 1' in text
    # No compressed record is claimed on this path.
    assert '#define HAVE_RVFI_EXPANDED 0' in text


def test_a_header_without_the_bundle_keeps_the_named_refusal_shape():
    document = cpu_document()
    document['physical_exports'] = [row for row in document['physical_exports']
                                    if row.get('physical_port') != 'rvfi_probes_o']
    text = header(document)
    assert '#define HAVE_RVFI_ADAPTER 0' in text
    assert '#define HAVE_RVFI_WRITEBACK 0' in text
    assert 'Vcva6_rvfi_top.h' not in text
    assert '#define CPU_RVFI_VALID' not in text
    assert '#define RVFI_ADAPTER' not in text
    # The AXI4 bus bindings the F2-F4 evidence needs are still rendered.
    assert '#define CPU_AXI_ARVALID' in text
    assert '#define AXI4_ADAPTER Vaxi4_processor_memory_adapter' in text


# --- the wrapper RTL -------------------------------------------------------

def test_the_wrapper_is_the_pinned_scoreboard_plus_one_retirement_lane():
    text = WRAPPER.read_text()
    # The pinned scoreboard is instantiated, not re-implemented.
    assert 'cva6_rvfi #(' in text and 'i_cva6_rvfi' in text
    assert '`RVFI_PROBES_INSTR_T(CVA6Cfg)' in text
    assert '`RVFI_PROBES_CSR_T(CVA6Cfg)' in text
    assert '`RVFI_INSTR_T(CVA6Cfg)' in text
    # The record word comes from the scoreboard's own issue/commit scoreboard.
    scoreboard = (CVA6 / 'core/cva6_rvfi.sv').read_text()
    assert 'rvfi_instr_o[i].insn  <= mem_q[commit_pointer[i]].instr;' in scoreboard
    # A width disagreement is an elaboration error, never a truncation.
    assert '$error(' in text and 'PROBES_BITS != PROBES_WIDTH' in text
    # The one-record-per-clock face the host's F1 block reads.
    for port in ('output logic                    rvfi_valid',
                 'output logic [63:0]             rvfi_order',
                 'output logic [31:0]             rvfi_insn',
                 'output logic [63:0]             rvfi_pc_rdata',
                 'output logic                    rvfi_trap',
                 'output logic [4:0]              rvfi_rd_addr',
                 'output logic [63:0]             rvfi_rd_wdata'):
        assert port in text
    # Two commit lanes are queued, and a lost record is stated, never hidden.
    assert 'retire_dropped' in text and 'QUEUE_DEPTH' in text


def test_the_scoreboard_is_outside_the_pinned_core_closure():
    filelist = (CVA6 / 'core/Flist.cva6').read_text()
    assert 'cva6_rvfi.sv' not in filelist
    assert 'cva6_rvfi_probes.sv' in filelist
    build = ADAPTER_BUILD.read_text()
    assert "RVFI_OUTSIDE_CORE_CLOSURE = ('core/cva6_rvfi.sv',)" in build
    # The packages it compiles are byte-compared with the model's own inputs.
    assert "verified_against" in build and "generated_model_inputs" in build


# --- the host path ---------------------------------------------------------

def test_the_host_clocks_the_scoreboard_on_the_link_edge_from_the_probe_port():
    header_text = HOST_HEADER.read_text()
    assert 'struct ProbeAdapter' in header_text
    assert 'attach_probe_adapter' in header_text
    assert 'probe_.drive(probe_.context, probe_.source, probe_.words);' in header_text
    assert 'if (probe_.clock != nullptr) probe_.clock(probe_.context, true);' in header_text
    source = HOST_SOURCE.read_text()
    # The retirement block is gated by the adapter, and reads one name either way.
    assert '#if !CPU_BUS_AHB && (!CPU_BUS_AXI4 || HAVE_RVFI_ADAPTER)' in source
    assert '#define cpu_retirement rvfi' in source
    assert 'cpu_retirement.CPU_RVFI_VALID' in source
    # The probe words are copied from the CPU model's exported bundle and the
    # adapter's own probe-width output is checked against the binding.
    assert 'cpu.CPU_RVFI_PROBES.data(), CPU_RVFI_PROBES_WORDS' in source
    assert 'rvfi.rvfi_probes_width_o' in source
    assert 'rvfi.retire_dropped' in source


def test_the_entry_builds_the_scoreboard_from_the_models_own_pinned_inputs():
    text = ENTRY.read_text()
    assert 'from scripts.inprocess_cva6_rvfi_build import build_cva6_rvfi_adapter' in text
    assert "pinned_root=build_directory / 'inputs'" in text
    assert 'axi4_rvfi_probe_export(cpu.runtime_document)' in text


# --- the declared RV32 projection -----------------------------------------

def test_the_projection_is_a_declared_scenario_fact():
    assert CONFIG.get('f1_rv32_projection') is True
    assert CONFIG['f1_program_words'] == 4
    # The F2-F4 twin declares no projection: it has no F1 channel at all.
    assert 'f1_rv32_projection' not in F2F4_CONFIG
    assert 'f1_program_words' not in F2F4_CONFIG


def test_a_64_bit_cpu_without_the_projection_is_still_refused():
    from myfuzz.isa.constraints import IsaContract
    rv64 = IsaContract(64, ('I', 'M'), instruction_alignment=4)
    flags = f1_gate_flags_from_scenario(dict(f1_program_words=4))
    with pytest.raises(ValueError, match='RV32-only'):
        validate_f1_program_record({'flow': 'F1', 'fields': (0x2ab00693, 0x29d1f0b7)},
                                   isa=rv64, window_bytes=64, flags=flags)


def test_the_projection_admits_the_rv32im_subset_and_nothing_wider():
    projected = RiscvProfile(32, frozenset(('I', 'M')), 4, 32, 0)
    flags = f1_gate_flags_from_scenario(dict(f1_program_words=4))
    validate_f1_program_record({'flow': 'F1', 'fields': (0x2ab00693, 0x29d1f0b7)},
                               isa=projected, window_bytes=64, flags=flags)
    # The projected subset declares no C extension, so a compressed record is
    # refused outright instead of being executed under an RV32IM name.
    with pytest.raises(ValueError, match='C extension'):
        validate_f1_program_record(
            {'flow': 'F1', 'fields': (0x00004501,)}, isa=projected, window_bytes=64,
            flags=f1_gate_flags_from_scenario(
                dict(f1_program_words=4, f1_allow_compressed=True)))
    # A 16-bit parcel is not a 32-bit record word.
    with pytest.raises(ValueError):
        validate_f1_program_record({'flow': 'F1', 'fields': (0x00004501,)},
                                   isa=projected, window_bytes=64, flags=flags)
