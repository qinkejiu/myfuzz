"""P0-1: the IRQ and DMA declaration fields, their host wires, and refusals.

These tests are pure declarations: no model is built and no run is claimed.
They pin

* the five F5 facts a target declares and the exact host link fields
  ``irq_declaration`` returns from them (port, bit, trigger/polarity, status
  word, cause bits, clear write),
* the minimal timer declaration this increment adds
  (``configs/behaviors/opentitan_rv_timer_f5.json``) and its cross-check against
  the pinned OpenTitan rv_timer profile,
* the record arity the declaration derives (F5 carries one trigger word per
  declared trigger; F6 one input word per DMA block word), and
* the named refusals: a malformed or incomplete IRQ declaration, an F5 target
  protocol with no real F5 run, and a DMA route to a non-APB3 target.

The DMA half states the fields the unified entry consumes: the profile's
control/source/destination/length word offsets, the behavior's block words and
busy/err/status facts, the plan's start word / length value / master byte
enable, and the route's direction, address mode and evidence kind.
"""
from pathlib import Path

import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.inprocess_behavior import dma_behavior, source_behavior

from scripts.run_inprocess_f1f6 import (
    DMA_HOST_CAPABILITY, DMA_ROUTE_ADDRESS_MODES, DMA_ROUTE_DIRECTIONS,
    DMA_ROUTE_EVIDENCE_KINDS, DMA_ROUTE_PROTOCOL_REFUSAL, F5_TARGET_PROTOCOLS,
    F5_TARGET_PROTOCOL_REFUSAL, dma_route_protocol_check, f5_declaration,
    f5_protocol_check, flow_arity, irq_declaration, parse_run_log, register_kind,
)

ROOT = Path(__file__).resolve().parents[2]
TIMER_PROFILE = ROOT / 'configs/peripherals/opentitan_rv_timer_local/component_profile.json'
TIMER_BEHAVIOR = 'configs/behaviors/opentitan_rv_timer_f5.json'
ZIPDMA_BEHAVIOR = 'configs/behaviors/zipdma_f6.json'
#: The timer's window in the F5 scenario.  The declaration cross-check uses the
#: profile's own size/alignment, so this is the one scenario fact the test states.
TIMER_WINDOW = {'base': 0x40004000, 'size': 4096}

SOURCE_KEYS = ('source_port', 'source_bit_offset', 'pulse_width_ticks',
               'trigger_writes', 'status_offsets', 'status_cause_bits',
               'clear_writes')


def timer_profile():
    return load_component_profile(str(TIMER_PROFILE))


def timer_facts():
    return source_behavior({'source_behavior': TIMER_BEHAVIOR}, base_dir=ROOT)


def timer_config(**overrides):
    """The declared timer facts merged with the profile-compatible window."""
    config = {'source_behavior': TIMER_BEHAVIOR, 'target_window': dict(TIMER_WINDOW)}
    facts = timer_facts()
    for key in SOURCE_KEYS:
        if key in facts:
            config[key] = facts[key]
    config.update(overrides)
    return config


# --- 1. the required IRQ fields and the host link they map to --------------

def test_the_minimal_timer_declaration_maps_to_the_host_irq_link():
    """One declared source -> one host link with every field the wiring reads."""
    facts = timer_facts()
    assert facts['source_port'] == 'intr_timer_expired_hart0_timer0_o'
    assert facts['source_bit_offset'] == 0
    assert facts['trigger_writes'] == [[4, 1], [280, 0], [284, 0], [256, 1]]
    assert facts['status_offsets'] == [260]
    assert facts['status_cause_bits'] == [0]
    assert facts['clear_writes'] == [[280, 0xFFFFFF00]]

    link = irq_declaration(timer_config(), timer_profile())
    # The physical output the host samples and delivers to the CPU's declared
    # external interrupt input; the bit inside that output.
    assert (link['port'], link['bit']) == ('intr_timer_expired_hart0_timer0_o', 0)
    # The device's own trigger kind: a level held by INTR_STATE0/INTR_ENABLE0.
    assert (link['trigger'], link['polarity'], link['pulse_ticks']) == (
        'level', 'active_high', 0)
    # The word the ISR loads, and what the profile says that word is.
    assert link['status_offset'] == 260
    assert link['status_kind'] == 'status'
    assert link['status_read_clears'] is False
    # The one declared cause bit, and the RTL compare-update clear the ISR writes
    # after it has read the status word.
    assert (link['cause_declared'], link['cause_bits'], link['cause_mask']) == (
        True, [0], 1)
    assert link['clear'] == {'offset': 280, 'value': 0xFFFFFF00}
    assert link['trigger_offsets'] == [4, 280, 284, 256]

    irq, refusal = f5_declaration(timer_config(), timer_profile(), 'tl-ul')
    assert refusal is None
    assert irq['trigger_offsets'] == link['trigger_offsets']
    assert irq['cause_mask'] == 1
    assert flow_arity(irq, None)['F5'] == 4


def test_the_register_word_kind_recognises_the_opentitan_status_name():
    assert register_kind('INTR_STATE0') == 'status'
    assert register_kind('INTR_ENABLE0') == 'undeclared'
    assert register_kind('TIMER_V_LOWER0') == 'undeclared'
    assert register_kind('COMPARE_LOWER0_0') == 'compare'


# --- 2. the declaration fields a scenario cannot omit ----------------------

def test_an_incomplete_irq_declaration_is_refused_by_name():
    # No trigger sequence: the four declared facts are not all present.
    missing_trigger = timer_config()
    del missing_trigger['trigger_writes']
    irq, refusal = f5_declaration(missing_trigger, timer_profile(), 'tl-ul')
    assert irq is None
    assert refusal == 'unsupported-f5:target-irq-semantics:tl-ul:trigger_writes'
    # A level source without a clear is an interrupt storm, not a pass.
    with pytest.raises(ValueError) as error:
        irq_declaration(timer_config(clear_writes=[]), timer_profile())
    assert 'a level IRQ source needs a declared clear write' in str(error.value)
    # A status offset the profile does not declare as a readable word.
    with pytest.raises(ValueError) as error:
        irq_declaration(timer_config(status_offsets=[0x120]), timer_profile())
    assert 'declared status register is not a readable word' in str(error.value)
    # A source port the profile does not export on that interrupt endpoint.
    with pytest.raises(ValueError) as error:
        irq_declaration(timer_config(source_port='irq_o'), timer_profile())
    assert 'target declares no single IRQ output' in str(error.value)


def test_f5_is_admitted_for_the_protocols_with_a_real_run_only():
    assert F5_TARGET_PROTOCOLS == ('apb3', 'tl-ul')
    assert f5_protocol_check('apb3', 'timer', {}) is None
    assert f5_protocol_check('tl-ul', 'tlultimer', {}) is None
    for protocol, name in (('wishbone', 'wbuart'), ('axi4-lite', 'axiluart')):
        with pytest.raises(ValueError) as error:
            f5_protocol_check(protocol, name, {})
        assert str(error.value) == (
            F5_TARGET_PROTOCOL_REFUSAL + protocol + ':' + name)
        # A target that declares no F5 facts keeps its own refusal.
        assert f5_protocol_check(protocol, name, None) is None


# --- 3. the DMA declaration fields and the route protocol gate -------------

def test_the_dma_behavior_states_the_control_status_facts():
    facts = dma_behavior({'dma_behavior': ZIPDMA_BEHAVIOR}, base_dir=ROOT)
    assert facts['block_words'] == 4
    assert (facts['busy_bit'], facts['err_bit']) == (31, 30)
    assert facts['status_kind'] == 'status'
    assert facts['status_bits_declared'] is True
    assert facts['declaration_path'] == ZIPDMA_BEHAVIOR
    # The host's F6 input shape follows the declared block, not a host constant.
    assert flow_arity(None, {'block_words': facts['block_words']})['F6'] == 4
    assert 'F6' not in flow_arity(None, None)


def test_the_route_shape_fields_are_the_ones_the_host_presents():
    assert DMA_ROUTE_DIRECTIONS == ('write', 'read')
    assert DMA_ROUTE_ADDRESS_MODES == ('fixed', 'aperture')
    assert DMA_ROUTE_EVIDENCE_KINDS == ('fifo_level', 'register_readback')
    # The host executes at most eight block words and one outstanding route beat;
    # a plan outside those is refused from this capability map.
    assert DMA_HOST_CAPABILITY['host-block-words-cap'] == 8
    assert DMA_HOST_CAPABILITY['host-full-word-master-sel'] == 15
    assert DMA_HOST_CAPABILITY['host-response-delay-absent'] == 8
    assert DMA_HOST_CAPABILITY['host-error-injection-absent'] is None


def test_a_dma_route_is_admitted_on_the_routed_targets_own_protocol():
    """Every protocol with a real beat adapter is admitted; a wire without one is not.

    A route is one master beat on the target's generic request port, so the
    admitted set is a property of the generated adapters, not of APB3: APB3 keeps
    the historical path and TL-UL, Wishbone and AXI4-Lite are executed through
    their own bridges.  A protocol outside that set keeps the named refusal.
    """
    for protocol, name in (('apb3', 'timer'), ('wishbone', 'wbuart'),
                           ('tl-ul', 'tlultimer'), ('axi4-lite', 'axiluart')):
        assert dma_route_protocol_check(protocol, name) is None
    with pytest.raises(ValueError) as error:
        dma_route_protocol_check('ahb-lite', 'ahbsha')
    assert str(error.value) == (
        DMA_ROUTE_PROTOCOL_REFUSAL + 'ahb-lite:ahbsha')


# --- 4. the real run this declaration produced -----------------------------

def test_the_real_tlul_timer_run_states_the_irq_take_and_clear():
    """The saved case line, not the declaration, is the evidence."""
    run = ROOT / 'runs/p0-1-ip/batch2/all-six/run.log'
    arity = flow_arity({'trigger_offsets': [4, 280, 284, 256]},
                       {'block_words': 4})
    log = parse_run_log(run.read_text(), flows=arity)
    assert log['summary']['status'] == 'observations_passed'
    assert len(log['cases']) == 9
    f5 = next(case for case in log['cases'] if case['flow'] == 'F5')
    assert f5['status'] == 'observations_passed'
    assert f5['irq_edges'] == 1 and f5['irq_takes'] == 1
    assert f5['wait_timeout'] == 0 and f5['isr_flag'] == 1
    assert f5['isr_cause'] == 1
    assert f5['isr_read_addr'] == 0x40004104
    assert f5['isr_read_register_kind'] == 'status'
    assert f5['clear_writes'] == 1
    assert f5['last_clear_offset'] == 0x118
    assert f5['last_clear_data'] == 0xFFFFFF00
    assert f5['irq_level_final'] == 0 and f5['level_stuck'] == 0
    f6 = next(case for case in log['cases'] if case['flow'] == 'F6')
    assert (f6['dma_reads'], f6['dma_writes']) == (4, 4)
    assert f6['irq_takes'] == 1
