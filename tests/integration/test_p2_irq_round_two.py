"""p2 IRQ round two: the declarations, refusals and saved evidence of the round.

Pure Python: no model is built and no Verilator runs.  Every assertion is a fact
that is either read out of a shipped profile/declaration, or re-derived from the
saved `runs/p2-irq-20261103/` evidence.  The point is that a profile edit which
would invalidate the round's report fails here instead of silently rotting.

See `docs/reports/p2-irq-round-two-20261103.md` and
`runs/p2-irq-20261103/README.md`.
"""
import json
from pathlib import Path

import pytest

from scripts.run_inprocess_f1f6 import (
    F5_TARGET_PROTOCOLS, F5_TARGET_PROTOCOL_REFUSAL, IRQ_NMI_REFUSAL_PREFIX,
    IRQ_PLIC_REFUSAL_PREFIX, IRQ_CPU_PARTIAL_VECTOR_PREFIX,
    IRQ_CPU_VECTOR_REFUSAL_PREFIX, IRQ_WRITE_ONE_CLEAR_REFUSAL_PREFIX,
    advanced_irq_refusals, f5_protocol_check)

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / 'runs/p2-irq-20261103'
W1C_SCENARIO = ROOT / 'configs/scenarios/inprocess-obi-tlul-gpio-w1c-f5.json'
W1C_BEHAVIOR = ROOT / 'configs/behaviors/opentitan_gpio_w1c_f5.json'
WB_SCENARIO = ROOT / 'configs/scenarios/inprocess-obi-wb-uart-f5-refused.json'
AXIL_SCENARIO = ROOT / 'configs/scenarios/inprocess-obi-axi4lite-axiluart-f5-refused.json'
UART_BEHAVIOR = ROOT / 'configs/behaviors/zipcpu_uart_fifo_level_f5.json'


def _load(path):
    return json.loads(Path(path).read_text())


def _registers(profile_path):
    return {row['offset']: row
            for row in (_load(profile_path).get('address') or {}).get('registers') or ()}


# --------------------------------------------------------------------------
# Requirement 5: the write-one-to-clear declaration that really ran
# --------------------------------------------------------------------------

def test_w1c_scenario_selects_the_gpio_profile_and_declares_its_behavior():
    scenario = _load(W1C_SCENARIO)
    assert scenario['schema_version'] == 'inprocess_f1f6_config.v1'
    (target,) = scenario['targets']
    assert target['profile'] == 'configs/peripherals/opentitan_gpio_local/component_profile.json'
    assert target['behavior'] == 'configs/behaviors/opentitan_gpio_w1c_f5.json'
    assert Path(ROOT / target['behavior']).is_file()
    # No dir-resolved pad word: the interrupt is raised through the register
    # interface, so a pad model is neither declared nor required.
    assert target['pins'] is None
    roles = {row['role'] for row in target['fixed_inputs']}
    assert roles == {'in', 'strap_en'}


def test_w1c_status_word_is_the_declared_write_one_clears_register():
    behavior = _load(W1C_BEHAVIOR)
    registers = _registers(W1C_SCENARIO and
                           ROOT / _load(W1C_SCENARIO)['targets'][0]['profile'])
    (status_offset,) = behavior['status_offsets']
    status = registers[status_offset]
    assert status['name'] == 'INTR_STATE'
    assert status['access'] == 'rw'
    assert status['side_effect'] == 'write_one_clears'
    # The read is not the clear here; the write is.
    assert status['side_effect'] != 'read_clears'


def test_w1c_triggers_enable_before_test_and_every_trigger_is_writable():
    behavior = _load(W1C_BEHAVIOR)
    registers = _registers(ROOT / _load(W1C_SCENARIO)['targets'][0]['profile'])
    names = [registers[offset]['name'] for offset, _value in behavior['trigger_writes']]
    assert names == ['INTR_ENABLE', 'INTR_TEST'], names
    for offset, _value in behavior['trigger_writes']:
        row = registers[offset]
        assert row['width'] == 32
        assert row['access'] in ('rw', 'wo')
    # The values really arm one event: enable the vector bit, then force it.
    assert [value for _offset, value in behavior['trigger_writes']] == [1, 1]


def test_w1c_clear_writes_the_status_word_itself_with_the_cause_bit():
    behavior = _load(W1C_BEHAVIOR)
    registers = _registers(ROOT / _load(W1C_SCENARIO)['targets'][0]['profile'])
    (clear_offset, clear_value), = behavior['clear_writes']
    assert clear_offset == behavior['status_offsets'][0]
    assert registers[clear_offset]['side_effect'] == 'write_one_clears'
    # A W1C clear writes 1 to the observed cause bit, so the declared word is
    # exactly the declared cause mask.
    assert behavior['status_cause_bits'] == [0]
    assert clear_value == 1 << behavior['status_cause_bits'][0]


def test_w1c_source_port_is_the_rtl_output_the_profile_declares():
    behavior = _load(W1C_BEHAVIOR)
    profile = _load(ROOT / _load(W1C_SCENARIO)['targets'][0]['profile'])
    endpoint_ids = {endpoint['endpoint_id'] for endpoint in profile['endpoints']}
    sources = [source for source in profile['interrupts']
               if source['endpoint_id'] in endpoint_ids
               and (source.get('bit') or 0) == behavior['source_bit_offset']]
    assert sources, 'the profile declares no interrupt on the declared bit'
    assert behavior['source_port'] == 'intr_gpio_o'


def test_advanced_refusals_lift_the_w1c_refusal_for_this_target_only():
    cpu = _load(ROOT / 'configs/cpus/ibex_rvfi_local/component_profile.json')
    gpio = _load(ROOT / 'configs/peripherals/opentitan_gpio_local/component_profile.json')
    with_w1c = advanced_irq_refusals(cpu, [gpio])
    assert with_w1c['write_one_clear'] is None
    # A target set with no declared W1C interrupt status keeps the refusal, so
    # the lift above is a fact about the declared target, not about the code.
    timer = _load(ROOT / 'configs/peripherals/pulp_timer_irq/component_profile.json')
    without = advanced_irq_refusals(cpu, [timer])
    assert without['write_one_clear'] == (
        IRQ_WRITE_ONE_CLEAR_REFUSAL_PREFIX +
        'no-composed-target-register-declares-write_one_clears')


# --------------------------------------------------------------------------
# Requirement 1: the Wishbone / AXI4-Lite asks and the protocol gate
# --------------------------------------------------------------------------

def test_wb_and_axil_asks_differ_only_in_the_target_protocol():
    wb = _load(WB_SCENARIO)
    axil = _load(AXIL_SCENARIO)
    assert wb['targets'][0]['behavior'] == axil['targets'][0]['behavior']
    assert wb['targets'][0]['profile'] == 'configs/peripherals/zipcpu_uart/component_profile.json'
    assert axil['targets'][0]['profile'] == 'configs/peripherals/zipcpu_axiluart/component_profile.json'
    # Same RTL, same declaration: the only difference is the bus in front of it,
    # which is exactly why the identical device-layer refusal is meaningful.
    assert _load(UART_BEHAVIOR)['clear_writes'] == []
    assert wb['cpu_profile'] == axil['cpu_profile']


def test_uart_f5_declaration_is_a_level_source_with_no_honest_clear():
    behavior = _load(UART_BEHAVIOR)
    registers = _registers(ROOT / 'configs/peripherals/zipcpu_uart/component_profile.json')
    (status_offset,) = behavior['status_offsets']
    assert registers[status_offset]['name'] == 'FIFO_STATUS'
    assert registers[status_offset]['side_effect'] != 'read_clears'
    assert behavior['clear_writes'] == []
    profile = _load(ROOT / 'configs/peripherals/zipcpu_uart/component_profile.json')
    declared = [row for row in profile['interrupts']
                if row['role'] and row.get('trigger') == 'level']
    assert declared, 'the wbuart profile is expected to declare level interrupts'
    assert all(row['polarity'] == 'active_high' for row in declared)
    # Every one of the four is a FIFO level; none is a latched event.
    assert {row['role'] for row in declared} == {'rx', 'rxfifo', 'tx', 'txfifo'}


def test_f5_target_protocols_are_unchanged_and_still_refuse_the_two_asked():
    assert F5_TARGET_PROTOCOLS == ('apb3', 'tl-ul')
    for protocol in ('wishbone', 'axi4-lite'):
        with pytest.raises(ValueError) as error:
            f5_protocol_check(protocol, 'target', {'link': True})
        assert str(error.value) == F5_TARGET_PROTOCOL_REFUSAL + protocol + ':target'
    # A target that declares no F5 facts is never gated; the refusal belongs to a
    # declaration that would otherwise be accepted.
    assert f5_protocol_check('wishbone', 'target', None) is None


# --------------------------------------------------------------------------
# Requirement 2/3/4: the refusals still stand, with the same words
# --------------------------------------------------------------------------

def test_ibex_keeps_the_nmi_refusal_at_the_port_action_constant():
    cpu = _load(ROOT / 'configs/cpus/ibex_rvfi_local/component_profile.json')
    refusals = advanced_irq_refusals(cpu)
    assert refusals['nmi'] == (IRQ_NMI_REFUSAL_PREFIX +
                               'ibex_rvfi_local:irq_nm_i=constant-0')


def test_cv32e20_nmi_is_held_by_the_same_constant_action():
    cpu = _load(ROOT / 'configs/cpus/cv32e20/component_profile.json')
    refusals = advanced_irq_refusals(cpu)
    assert refusals['nmi'].startswith(IRQ_NMI_REFUSAL_PREFIX + 'cv32e20:irq_nm_i')
    # The observation face the round relies on is declared by the profile.
    observed = {row['port'] for row in cpu.get('port_actions') or ()
                if row.get('action') == 'observe'}
    assert 'rvfi_ext_nmi' in observed


def test_cva6_has_no_nmi_port_and_a_partial_two_bit_vector():
    cpu = _load(ROOT / 'configs/cpus/cva6/component_profile.json')
    refusals = advanced_irq_refusals(cpu)
    assert refusals['nmi'] == (IRQ_NMI_REFUSAL_PREFIX + 'cva6:no-declared-nmi-port')
    assert refusals['cpu_vector'].startswith(IRQ_CPU_PARTIAL_VECTOR_PREFIX + 'cva6:')
    (held,) = refusals['cpu_vector_entry']['held_bits']
    assert held == {'port': 'irq_i', 'bit': 1, 'value': 0}
    assert refusals['cpu_vector_entry']['aliases'] == ['irq_i']
    # Bit 0 is the machine-external entry the host really drives.
    assert refusals['cpu_vector_entry']['role'] == 'machine_external'


def test_ibex_one_bit_entry_is_not_called_a_vector():
    cpu = _load(ROOT / 'configs/cpus/ibex_rvfi_local/component_profile.json')
    refusals = advanced_irq_refusals(cpu)
    assert refusals['cpu_vector'] == (
        IRQ_CPU_VECTOR_REFUSAL_PREFIX + 'ibex_rvfi_local:one-external-input:'
        'irq_external_i-width-1')
    assert refusals['cpu_vector_entry']['held_bits'] == []


def test_plic_refusal_names_the_rtl_that_exists_and_both_missing_composition_facts():
    cpu = _load(ROOT / 'configs/cpus/ibex_rvfi_local/component_profile.json')
    refusals = advanced_irq_refusals(cpu)
    assert refusals['plic'] == (IRQ_PLIC_REFUSAL_PREFIX + 'ibex_rvfi_local:'
                                'no-declared-interrupt-controller-endpoint')
    rtl = refusals['plic_rtl']
    assert rtl['rtl'].startswith('third_party/soc-opentitan/')
    assert rtl['rtl'].endswith('rv_plic.sv:63-89')
    assert rtl['composed_by_profile'] is False
    assert rtl['cpu_target_port'] is False


def test_rv_plic_claim_and_complete_are_mmxo_accesses_not_a_cpu_port():
    """The standing assumption the report corrects, checked against the RTL.

    `rv_plic` is a TL-UL device whose claim/complete are a read/write of the
    target's CC register, so no CPU-side claim/complete port is what is missing.
    """
    rtl = (ROOT / 'third_party/soc-opentitan/hw/top_earlgrey/ip_autogen/rv_plic/'
           'rtl/rv_plic.sv').read_text()
    assert 'input  tlul_pkg::tl_h2d_t tl_i,' in rtl
    assert 'output tlul_pkg::tl_d2h_t tl_o,' in rtl
    assert 'assign claim_re[0]    = reg2hw.cc0.re;' in rtl
    assert 'assign complete_we[0] = reg2hw.cc0.qe;' in rtl
    assert 'input  [NumSrc-1:0] intr_src_i,' in rtl
    assert 'output [NumTarget-1:0] irq_o,' in rtl
    pkg = (ROOT / 'third_party/soc-opentitan/hw/top_earlgrey/ip_autogen/rv_plic/'
           'rtl/rv_plic_reg_pkg.sv').read_text()
    assert 'parameter int NumSrc = 184;' in pkg
    assert 'parameter int NumTarget = 1;' in pkg


def test_ibex_nmi_cause_encoding_is_the_one_the_report_cites():
    pkg = (ROOT / 'third_party/rfuzz/upstream/ibex/rtl/ibex_pkg.sv').read_text()
    assert "localparam exc_cause_t ExcCauseIrqNm =" in pkg
    assert "localparam exc_cause_t ExcCauseIrqNm =\n    '{irq_ext: 1'b1, irq_int: 1'b0, lower_cause: 5'd31};" in pkg


def test_ibex_wrapper_that_the_cpu_uses_really_carries_irq_nm_i():
    wrapper = (ROOT / 'src/myfuzz/composition/rtl/soc_ibex_rvfi_local.sv').read_text()
    assert 'input logic irq_nm_i,' in wrapper
    assert '.irq_nm_i(irq_nm_i),' in wrapper


def test_cv32e20_wrapper_ties_the_nmi_and_the_external_line():
    wrapper = (ROOT / 'configs/cpus/cv32e20/cv32e20_real_wrapper.sv').read_text()
    assert ".irq_nm_i(1'b0)" in wrapper
    assert ".irq_external_i(1'b0)" in wrapper


def test_wbuart_interrupt_outputs_are_all_combinational_fifo_levels():
    rtl = (ROOT / 'third_party/soc-zipcpu-wbuart/rtl/wbuart.v').read_text()
    for line in ('assign\to_uart_rxfifo_int = rxf_status[1];',
                 'assign\to_uart_rx_int = rxf_status[0];',
                 'assign\to_uart_tx_int = txf_status[0];',
                 'assign\to_uart_txfifo_int = txf_status[1];'):
        assert line in rtl, line
    # The break path that could otherwise be driven from software is tied off.
    assert 'assign\trx_break = 1\'b0;' in rtl


# --------------------------------------------------------------------------
# The saved evidence is the evidence the report quotes
# --------------------------------------------------------------------------

@pytest.mark.parametrize('name, cases', [
    ('w1c-gpio', 3), ('readclear-gpio', 4), ('cva6-multibit', 3)])
def test_saved_batch_case_counts_match_its_summary(name, cases):
    run_dir = EVIDENCE / name
    summary = _load(run_dir / 'summary.json')
    assert summary['status'] == 'observations_passed'
    assert len(summary['cases']) == cases
    logged = [line for line in (run_dir / 'run.log').read_text().splitlines()
              if line.startswith('case ')]
    assert len(logged) == cases


def test_saved_w1c_case_shows_a_clear_write_and_a_level_that_fell():
    line = next(line for line in (EVIDENCE / 'w1c-gpio/run.log').read_text().splitlines()
                if line.startswith('case 0 '))
    assert 'flow F5' in line
    assert 'observations_passed' in line
    for token in ('irq_edges 1', 'irq_takes 1', 'irq_level_final 0x00000000',
                  'level_stuck 0', 'isr_read_value 0x00000001',
                  'last_clear_offset 0x00000000', 'last_clear_data 0x00000001',
                  'clear_writes 1', 'target_protocol tl-ul'):
        assert token in line, token


def test_saved_readclear_case_shows_no_write_at_all():
    line = next(line for line in (EVIDENCE / 'readclear-gpio/run.log').read_text().splitlines()
                if line.startswith('case 2 '))
    for token in ('clear_writes 0', 'isr_read_clears 1', 'isr_read_addr 0x40000024',
                  'irq_level_final 0x00000000', 'level_stuck 0', 'irq_takes 1'):
        assert token in line, token


def test_saved_cva6_batch_states_bit0_driven_and_bit1_held():
    summary = _load(EVIDENCE / 'cva6-multibit/summary.json')
    text = json.dumps(summary)
    assert 'driven_bit0_machine_external' in text
    assert 'mcause_readback' in text
    advanced = summary['irq_advanced']
    assert advanced['cpu_vector'].startswith(IRQ_CPU_PARTIAL_VECTOR_PREFIX + 'cva6:')
    assert advanced['cpu_vector_entry']['held_bits'] == [
        {'port': 'irq_i', 'bit': 1, 'value': 0}]


def test_evidence_shapes_are_the_ones_the_readme_documents():
    for name in ('README.md', 'run.sh', 'campaign.log', 'irq-advanced.json'):
        assert (EVIDENCE / name).is_file(), name
    script = (EVIDENCE / 'run.sh').read_text()
    for scenario in ('inprocess-obi-tlul-gpio-w1c-f5.json',
                     'inprocess-obi-apb-gpio-multibit-f5-pins.json',
                     'inprocess-cva6-axi4-timer-f5.json',
                     'inprocess-obi-wb-uart-f5-refused.json',
                     'inprocess-obi-axi4lite-axiluart-f5-refused.json'):
        assert scenario in script, scenario
        assert (ROOT / 'configs/scenarios' / scenario).is_file(), scenario
    facts = _load(EVIDENCE / 'irq-advanced.json')
    assert facts['ibex_plus_pulp_gpio']['write_one_clear'] is None
    assert facts['cva6_plus_pulp_timer']['write_one_clear'] == (
        IRQ_WRITE_ONE_CLEAR_REFUSAL_PREFIX +
        'no-composed-target-register-declares-write_one_clears')
