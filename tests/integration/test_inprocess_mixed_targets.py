"""Mixed APB3 + AXI4-Lite target builds: the pure-Python half, no RTL.

The unified in-process entry can now route one CPU to an APB3 register target and
an AXI4-Lite register target in the same session.  Every target states its own
protocol from its own artifact, the generated header states those facts per
target, and each case line states the protocol of the target it was routed to.

These tests cover the declaration axis, the generated trait text, the case-line
and summary words a mixed build prints, and the homogeneous paths that must keep
their historical keys and names.  The case and summary lines are the exact lines
a real run printed (``runs/round3-mixed-targets/fixed/run.log``), so the parser
is exercised on the host's own output rather than on a hand-written shape.  No
model is built and no run is claimed here.
"""
import json
from pathlib import Path

import pytest

from myfuzz.composition.multi_target import declared_targets, target_windows

from scripts.run_inprocess_f1f6 import (
    AXI_CASE_COUNTER_KEYS, AXI_CASE_OBSERVATION_KEYS, CASE_COUNTER_KEYS,
    CASE_OBSERVATION_KEYS, MIXED_TARGET_PROTOCOL, SUPPORTED_TARGET_PROTOCOLS,
    _generated_target_traits,
    _target_protocol_mismatch, build_layout, case_counter_keys, case_document,
    case_observation_keys, case_target_protocol, correspondence,
    dma_route_protocol_check, f5_protocol_check, flow_arity,
    parse_case_line, parse_record, parse_run_log, parse_summary_line,
    target_protocol_axis, target_view,
)

ROOT = Path(__file__).resolve().parents[2]
MIXED_SCENARIO = ROOT / 'configs/scenarios/inprocess-obi-apb-axi4lite-mixed-timer-axiluart-f1f4.json'
MIXED_CONFIG = json.loads(MIXED_SCENARIO.read_text())


def mixed_windows():
    """The mixed scenario's address view, with each target's own protocol.

    The entry adds ``target_count`` and ``target_protocols`` to the composition
    layer's view; the same two keys are added here so a case line is checked
    against the declaration it was produced under.
    """
    windows = target_windows(MIXED_CONFIG)
    windows['target_count'] = len(windows['ip_targets'])
    windows['target_protocols'] = ['apb3', 'axi4-lite']
    return windows


WINDOWS = mixed_windows()
LAYOUT = build_layout(WINDOWS, 0x10080, irq_base=WINDOWS['ip_base'])
ARITY = flow_arity(None, None)
#: The flow tags the saved case lines carry.  Parsing a line is independent of
#: whether this build can serve the flow, so the F5 case of the mixed run is
#: readable here even though no IRQ declaration is passed to ``flow_arity``.
CASE_FLOWS = dict(ARITY, F5=3)


def record(text, arity=None):
    """One record, routed through the mixed declaration's own window table."""
    return parse_record(text, windows=WINDOWS, arity=ARITY if arity is None else arity,
                        label='APB3+AXI4-Lite')


def case_of(line):
    return parse_case_line(line, flows=CASE_FLOWS)


# --- the declaration axis -------------------------------------------------


def test_the_mixed_scenario_declares_both_protocols():
    """One scenario, two targets, two protocols: the axis is a fact, not a choice."""
    targets = declared_targets(MIXED_CONFIG)
    assert [row['name'] for row in targets] == ['timer', 'axiluart']
    protocols = []
    for row in targets:
        profile = json.loads((ROOT / row['profile']).read_text())
        protocols.append([tuple(endpoint['protocol']) for endpoint in profile['endpoints']
                          if endpoint.get('function') == 'mmio_slave'][0])
    assert protocols == [('apb', '3'), ('axi4-lite', '1')]
    assert target_protocol_axis({'apb3', 'axi4-lite'}) == (MIXED_TARGET_PROTOCOL, True)
    # The two windows are disjoint from each other and from the RAM image.
    windows = WINDOWS
    assert windows['ip_targets'][0]['base'] + windows['ip_targets'][0]['size'] \
        <= windows['ip_targets'][1]['base']
    ram = (windows['ram_base'], windows['ram_base'] + windows['ram_size'])
    for row in windows['ip_targets']:
        assert row['base'] >= ram[1] or row['base'] + row['size'] <= ram[0]


def test_one_protocol_keeps_the_homogeneous_axis():
    assert target_protocol_axis({'apb3'}) == ('apb3', False)
    assert target_protocol_axis({'axi4-lite'}) == ('axi4-lite', False)
    # A two-target declaration of one protocol is still a homogeneous build.
    assert target_protocol_axis({'apb3', 'apb3'}) == ('apb3', False)


def test_every_supported_subset_of_two_or_more_is_admitted():
    """Any subset of 2..4 supported protocols shares one build.

    The increment generalizes the axis: the per-target traits select the trace
    sample and the completion criterion, so a pair, a triple or the full set is a
    mixed build.  The historical exact pair keeps its own axis word.
    """
    for declared in ({'apb3', 'axi4-lite'}, {'apb3', 'wishbone'}, {'apb3', 'tl-ul'},
                     {'wishbone', 'tl-ul'}, {'axi4-lite', 'tl-ul'},
                     {'apb3', 'axi4-lite', 'tl-ul'},
                     {'apb3', 'wishbone', 'tl-ul'},
                     set(SUPPORTED_TARGET_PROTOCOLS)):
        assert target_protocol_axis(declared) == (MIXED_TARGET_PROTOCOL, True), declared


def test_a_protocol_outside_the_supported_set_keeps_the_named_refusal():
    # The set is the five admitted protocols (apb3, axi4-lite, wishbone, tl-ul,
    # ahb-lite); a word that is not one of them is still refused by name and the
    # refusal lists everything the caller asked for.
    assert set(SUPPORTED_TARGET_PROTOCOLS) == {'apb3', 'axi4-lite', 'wishbone',
                                               'tl-ul', 'ahb-lite'}
    with pytest.raises(ValueError) as error:
        target_protocol_axis({'apb3', 'ahb5'})
    assert str(error.value) == 'unsupported-targets:mixed-protocol:ahb5,apb3'
    with pytest.raises(ValueError) as error:
        target_protocol_axis({'ahb5', 'wishbone', 'tl-ul'})
    assert str(error.value) == 'unsupported-targets:mixed-protocol:ahb5,tl-ul,wishbone'


def test_an_empty_protocol_set_is_refused():
    with pytest.raises(ValueError) as error:
        target_protocol_axis(set())
    assert str(error.value) == 'unsupported-targets:none'


# --- the generated per-target traits --------------------------------------

REQUEST_ROLES = ('IP_REQ_VALID', 'IP_REQ_WRITE', 'IP_REQ_ADDR', 'IP_REQ_WDATA',
                 'IP_REQ_BE', 'IP_REQ_READY', 'IP_RSP_READY', 'IP_RSP_VALID',
                 'IP_RSP_RDATA', 'IP_RSP_ERROR')
APB_TRACE_FIELDS = ('PSEL', 'PENABLE', 'PREADY', 'PWRITE', 'PADDR', 'PWDATA', 'PRDATA')
AXI_TRACE_FIELDS = ('AWVALID', 'AWREADY', 'AWADDR', 'AWPROT', 'WVALID', 'WREADY',
                    'WDATA', 'WSTRB', 'BVALID', 'BREADY', 'BRESP', 'ARVALID',
                    'ARREADY', 'ARADDR', 'ARPROT', 'RVALID', 'RREADY', 'RDATA', 'RRESP')


def trait_text(targets, protocol='mixed'):
    """Render the generated traits for fabricated target rows and protocol fields."""
    fields = []
    for row in targets:
        item = {role: 'req_' + role.lower() for role in REQUEST_ROLES}
        item['IP_REQ_READY'] = 'req_ready'
        traces = (APB_TRACE_FIELDS if row['protocol'] == 'apb3' else AXI_TRACE_FIELDS)
        for name in traces:
            item['IP_TRACE_' + name] = 'trace_' + name.lower()
        if row['protocol'] == 'apb3' and row.get('pslverr'):
            item['IP_TRACE_PSLVERR'] = 'trace_pslverr'
        fields.append(item)
    observed = {row['index']: None for row in targets}
    return '\n'.join(_generated_target_traits(targets, fields, [[] for _ in targets],
                                              observed, protocol, lambda value: value))


def trait_block(rows):
    return [
        dict(index=index, protocol=protocol, window=dict(base=base, size=size),
             reset_assert=2, reset_release=3, irq=None, pslverr=pslverr)
        for index, (protocol, base, size, pslverr) in enumerate(rows)]


def test_generated_traits_state_each_targets_own_protocol():
    text = trait_text(trait_block([('apb3', 0x40001000, 4096, True),
                                   ('axi4-lite', 0x40002000, 16, False)]))
    assert 'template <> struct IpTarget<0> {' in text
    assert 'template <> struct IpTarget<1> {' in text
    first, second = text.split('template <> struct IpTarget<1> {')
    assert 'static constexpr bool apb = true;' in first
    assert 'static constexpr bool axi4lite = false;' in first
    assert 'static constexpr const char *protocol = "apb3";' in first
    assert 'static constexpr const char *name = TARGET_NAME_0;' in first
    assert 'static constexpr const char *bridge = TARGET_BRIDGE_0;' in first
    assert 'static constexpr const char *bus_channel = TARGET_BUS_CHANNEL_0;' in first
    assert 'static constexpr bool apb = false;' in second
    assert 'static constexpr bool axi4lite = true;' in second
    assert 'static constexpr const char *protocol = "axi4-lite";' in second
    assert 'static constexpr const char *name = TARGET_NAME_1;' in second
    assert 'static constexpr const char *bridge = TARGET_BRIDGE_1;' in second


def test_each_target_only_exposes_its_own_protocols_taps():
    text = trait_text(trait_block([('apb3', 0x40001000, 4096, True),
                                   ('axi4-lite', 0x40002000, 16, False)]))
    first, second = text.split('template <> struct IpTarget<1> {')
    assert 'static bool apb_sel(' in first
    assert 'static bool apb_error(' in first
    assert 'static bool axi_awvalid(' not in first
    assert 'static bool apb_sel(' not in second
    assert 'static bool axi_awvalid(' in second
    assert 'static unsigned axi_wstrb(' in second


def test_pslverr_sampling_is_stated_per_target():
    """A target whose trace has no pslverr states that it has none.

    The build-wide ``HAVE_APB_PSLVERR`` is the OR of every target, so the host
    guards each call with the target's own constant instead of assuming the
    first target's trace.
    """
    text = trait_text(trait_block([('apb3', 0x40001000, 4096, True),
                                   ('apb3', 0x40002000, 4096, False)]))
    first, second = text.split('template <> struct IpTarget<1> {')
    assert 'static constexpr bool apb_error_sampled = true;' in first
    assert 'static bool apb_error(' in first
    assert 'static constexpr bool apb_error_sampled = false;' in second
    assert 'static bool apb_error(' not in second


def test_a_homogeneous_two_target_build_stays_one_protocol():
    """Two APB3 targets keep the historical single-protocol header shape."""
    text = trait_text(trait_block([('apb3', 0x40001000, 4096, True),
                                   ('apb3', 0x40002000, 4096, False)]), protocol='apb3')
    assert 'static constexpr bool axi4lite = false;' in text
    assert 'static bool axi_awvalid(' not in text
    assert 'static bool apb_sel(' in text


# --- the mixed case and summary lines the host really printed ---------------


#: The timer F5 case of the same mixed run: the real IRQ, the three trigger
#: writes and the ISR's declared status read.
MIXED_F5_TIMER = (
    'case 2 observations_passed flow F5 record F5:00000001:00000000:ffffffff ticks 146 '
    'seconds 0.000188394 i_fetches 61 d_reads 9 d_writes 8 target_reads 1 target_writes 3 '
    'target_index 0 target0_reads 1 target0_writes 3 target0_ready 1 target0_last_offset '
    '0x00000000 target0_last_data 0x00000010 target0_irq_high_ticks 1 target1_reads 0 '
    'target1_writes 0 target1_ready 0 target1_last_offset 0x00000000 target1_last_data '
    '0x00000000 target1_irq_high_ticks 0 retires 47 rvfi_writebacks 25 '
    'rvfi_order_monotonic 1 traps 0 bus_errors 0 target_transfers 4 axi_aw 0 axi_w 0 '
    'axi_b 0 axi_ar 0 axi_r 0 target_error unknown target_protocol apb3 trigger_writes 3 '
    'target_read_offset 0x00000000 target_read_data 0x00000010 target_last_write_offset '
    '0x00000000 target_last_write_data 0xffffffff irq_edges 1 irq_high_ticks 1 '
    'device_high_ticks 1 delivered_high_ticks 16 irq_takes 1 wait_timeout 0 isr_result '
    '0x00000010 isr_flag 1 isr_read_addr 0x40001000 isr_read_value 0x00000010 '
    'isr_read_register_kind count trigger_writes_declared 3 trigger_writes_observed 3 '
    'clear_writes 0 last_trigger_offset 0x00000000 last_trigger_data 0xffffffff '
    'last_clear_offset 0x00000000 last_clear_data 0x00000000 isr_cause unknown irq_link 0 '
    'irq_link_edges 1 irq_level_final 0x00000000 level_stuck 0 '
)

MIXED_F2_APB3 = (
    'case 0 observations_passed flow F2 record F2:40001000 ticks 110 seconds 0.000155794 '
    'i_fetches 49 d_reads 2 d_writes 15 target_reads 1 target_writes 0 target_index 0 '
    'target0_reads 1 target0_writes 0 target0_ready 1 target0_last_offset 0x00000000 '
    'target0_last_data 0x00000000 target0_irq_high_ticks 0 target1_reads 0 target1_writes '
    '0 target1_ready 0 target1_last_offset 0x00000000 target1_last_data 0x00000000 '
    'target1_irq_high_ticks 0 retires 41 rvfi_writebacks 20 rvfi_order_monotonic 1 traps '
    '0 bus_errors 0 target_transfers 1 axi_aw 0 axi_w 0 axi_b 0 axi_ar 0 axi_r 0 '
    'target_error unknown target_protocol apb3 read_addr 0x40001000 read_value 0x00000000 '
    'echo_value 0x00000000 read_from target target_rdata 0x00000000 target_offset '
    '0x00000000 target_ready 1 irq_edges 0 irq_takes 0 '
)

MIXED_F2_AXIL = (
    'case 3 observations_passed flow F2 record F2:40002004 ticks 39 seconds 3.9966e-05 '
    'i_fetches 16 d_reads 2 d_writes 2 target_reads 1 target_writes 0 target_index 1 '
    'target0_reads 0 target0_writes 0 target0_ready 0 target0_last_offset 0x00000000 '
    'target0_last_data 0x00000000 target0_irq_high_ticks 0 target1_reads 1 target1_writes '
    '0 target1_ready 1 target1_last_offset 0x00000004 target1_last_data 0x403f4000 '
    'target1_irq_high_ticks 0 retires 11 rvfi_writebacks 5 rvfi_order_monotonic 1 traps 0 '
    'bus_errors 0 target_transfers 1 axi_aw 0 axi_w 0 axi_b 0 axi_ar 1 axi_r 1 '
    'target_error unknown target_resp 0 target_protocol axi4-lite read_addr 0x40002004 '
    'read_value 0x403f4000 echo_value 0x403f4000 read_from target target_rdata 0x403f4000 '
    'target_offset 0x00000004 target_ready 1 irq_edges 0 irq_takes 0 '
)

MIXED_F3_RAM = (
    'case 5 observations_passed flow F3 record F3:00014004:0badf00d ticks 36 seconds '
    '3.676e-05 i_fetches 17 d_reads 3 d_writes 2 target_reads 0 target_writes 0 '
    'target_index -1 target0_reads 0 target0_writes 0 target0_ready 0 target0_last_offset '
    '0x00000000 target0_last_data 0x00000000 target0_irq_high_ticks 0 target1_reads 0 '
    'target1_writes 0 target1_ready 0 target1_last_offset 0x00000000 target1_last_data '
    '0x00000000 target1_irq_high_ticks 0 retires 13 rvfi_writebacks 6 '
    'rvfi_order_monotonic 1 traps 0 bus_errors 0 target_transfers 0 axi_aw 0 axi_w 0 '
    'axi_b 0 axi_ar 0 axi_r 0 target_error unknown target_protocol none write_addr '
    '0x00014004 write_value 0x0badf00d write_be 15 ram_before 0x11111111 ram_after '
    '0x0badf00d irq_edges 0 irq_takes 0 '
)

MIXED_SUMMARY = (
    'summary observations_passed cases 6 ticks 445 instruction_fetches 193 ram_reads 23 '
    'ram_writes 37 target_transfers 8 target_reads 3 target_writes 5 ip_count 2 '
    'target_index_scope selected_or_-1 ip_windows '
    'target0=0x40001000:4096,target1=0x40002000:16 target_protocols apb3,axi4-lite '
    'target0_protocol apb3 target0_bridge apb3_mmio_bridge target0_fixed_inputs 0 '
    'target1_protocol axi4-lite target1_bridge axi4_lite_mmio_bridge target1_fixed_inputs '
    '2 target0_reads_total 2 target0_writes_total 4 target0_irq_high_ticks 1 '
    'target0_irq_delivered_ticks 16 target0_irq delivered target0_f5 yes '
    'target1_reads_total 1 target1_writes_total 1 target1_irq_high_ticks 0 '
    'target1_irq_delivered_ticks 0 target1_irq none target1_f5 no axi_aw 1 axi_w 1 axi_b '
    '1 axi_ar 1 axi_r 1 target_wstrb_full 1 target_resp_okay 2 target_resp_non_okay 0 '
    'target_error unknown irq_high_ticks 1 device_high_ticks 1 delivered_high_ticks 16 '
    'irq_edges 1 irq_takes 1 wait_timeouts 0 level_stuck 0 device_resets 0 recovery_scope '
    'devices_only_cpu_and_ram_retained irq_delivery observed irq_sources 1 '
    'irq_target_links 1 irq_link_edges 1 dma not_present instruction_fetch_evidence '
    'observed retirement_evidence observed ifetch_events 193 ifetch_evidence observed '
    'retirements 152 rvfi_writebacks 71 rvfi_order_monotonic 1 rvfi_writeback_evidence '
    'observed traps 0 trap_evidence observed expanded_insn_events 0 '
    'expanded_insn_evidence missing target_errors 0 bus_error unknown bus_error_axi '
    'unknown bus_error_apb observed bus_error_obi_i unknown bus_error_obi_d unknown '
    'irq_cause unknown irq_cause_bits none_declared failures 0 runtime_seconds '
    '0.001780064 '
)


def test_a_mixed_apb3_case_states_its_protocol_and_neutral_fields():
    case = case_of(MIXED_F2_APB3)
    assert case['flow'] == 'F2'
    assert case['status'] == 'observations_passed'
    assert case['target_index'] == 0
    assert case['target_protocol'] == 'apb3'
    # The neutral group a mixed build prints instead of one protocol's spelling.
    assert case['target_reads'] == 1 and case['target_writes'] == 0
    assert case['target_transfers'] == 1
    assert 'apb_reads' not in case and 'apb_rdata' not in case
    assert case['target_rdata'] == 0 and case['target_offset'] == 0
    assert case['read_from'] == 'target'
    # The AXI4-Lite target did not move.
    assert case['target1_reads'] == 0 and case['target1_writes'] == 0
    assert (case['axi_aw'], case['axi_w'], case['axi_b'], case['axi_ar'],
            case['axi_r']) == (0, 0, 0, 0, 0)
    view = target_view(case)
    assert view['target_reads'] == 1 and view['target_ready'] == 1


def test_a_mixed_axilite_case_carries_its_channels():
    case = case_of(MIXED_F2_AXIL)
    assert case['target_index'] == 1
    assert case['target_protocol'] == 'axi4-lite'
    assert (case['axi_ar'], case['axi_r']) == (1, 1)
    assert (case['axi_aw'], case['axi_w'], case['axi_b']) == (0, 0, 0)
    assert case['target_offset'] == 4 and case['target_rdata'] == 0x403F4000
    assert case['target_resp'] == 0
    assert case['target0_reads'] == 0 and case['target0_writes'] == 0


def test_a_mixed_ram_case_states_no_protocol():
    case = case_of(MIXED_F3_RAM)
    assert case['target_index'] == -1
    assert case['target_protocol'] == 'none'
    assert case['target_reads'] == 0 and case['target_writes'] == 0
    assert case['target0_reads'] == 0 and case['target1_reads'] == 0


def test_the_protocol_word_is_checked_against_the_declaration():
    case = case_of(MIXED_F2_APB3)
    assert case_target_protocol(case, WINDOWS, 'mixed') == 'apb3'
    assert _target_protocol_mismatch(case, WINDOWS, 'mixed') is None
    wrong = dict(case, target_protocol='axi4-lite')
    mismatch = _target_protocol_mismatch(wrong, WINDOWS, 'mixed')
    assert mismatch == ('case target_protocol axi4-lite differs from the declared '
                        'target protocol apb3')
    # ``none`` is only honest for a case that named no target.
    named = dict(case, target_protocol='none')
    assert _target_protocol_mismatch(named, WINDOWS, 'mixed') == \
        'case target_protocol none on a case that named a target'
    ram = case_of(MIXED_F3_RAM)
    assert _target_protocol_mismatch(ram, WINDOWS, 'mixed') is None
    # A legacy (one-target) case line carries no such word at all.
    assert _target_protocol_mismatch(dict(case, target_protocol=None), WINDOWS,
                                     'mixed') is None


def test_the_mixed_summary_states_each_targets_protocol():
    summary = parse_summary_line(MIXED_SUMMARY)
    assert summary['status'] == 'observations_passed'
    assert summary['ip_count'] == 2
    assert summary['target_protocols'] == 'apb3,axi4-lite'
    assert summary['target0_protocol'] == 'apb3'
    assert summary['target0_bridge'] == 'apb3_mmio_bridge'
    assert summary['target0_fixed_inputs'] == 0
    assert summary['target1_protocol'] == 'axi4-lite'
    assert summary['target1_bridge'] == 'axi4_lite_mmio_bridge'
    assert summary['target1_fixed_inputs'] == 2
    # The per-target counters are the evidence that the other target did not move.
    assert summary['target0_reads_total'] == 2
    assert summary['target0_writes_total'] == 4
    assert summary['target1_reads_total'] == 1
    assert summary['target1_writes_total'] == 1
    # The five AXI4-Lite channels, and the APB3 error channel beside them.
    assert (summary['axi_aw'], summary['axi_w'], summary['axi_b'],
            summary['axi_ar'], summary['axi_r']) == (1, 1, 1, 1, 1)
    assert summary['bus_error_axi'] == 'unknown'
    assert summary['bus_error_apb'] == 'observed'
    assert summary['dma'] == 'not_present'


def test_a_mixed_log_parses_as_one_run():
    log = '\n'.join([MIXED_F2_APB3, MIXED_F2_AXIL, MIXED_F3_RAM, MIXED_SUMMARY])
    parsed = parse_run_log(log, flows=ARITY)
    assert len(parsed['cases']) == 3
    assert [case['target_protocol'] for case in parsed['cases']] == [
        'apb3', 'axi4-lite', 'none']
    assert parsed['summary']['target_protocols'] == 'apb3,axi4-lite'


def test_the_mixed_case_document_reads_the_neutral_fields():
    case = case_of(MIXED_F2_AXIL)
    document = case_document(record('F2:40002004'), case, protocol=MIXED_TARGET_PROTOCOL)
    assert document['target_protocol'] == 'axi4-lite'
    assert document['target_index'] == 1
    observation = document['observation']
    assert observation['read_from'] == 'target'
    assert observation['target_rdata'] == 0x403F4000
    assert observation['target_offset'] == 4
    assert observation['target_ready'] == 1
    assert observation['axi_ar'] == 1 and observation['axi_r'] == 1


def test_the_mixed_f5_document_reads_the_neutral_target_fields():
    """The F5 case's transfer words follow the selected (APB3) target.

    A mixed build prints ``target_read_offset``/``target_last_write_*`` for the F5
    status read and trigger writes, so the document reads those neutral names
    rather than the historical ``apb_*`` spellings a one-protocol APB3 build
    prints.
    """
    case = case_of(MIXED_F5_TIMER)
    document = case_document(record('F5:00000001:00000000:ffffffff', arity=CASE_FLOWS),
                             case, protocol=MIXED_TARGET_PROTOCOL)
    observation = document['observation']
    assert document['target_protocol'] == 'apb3'
    assert document['target_index'] == 0
    assert observation['trigger_writes_observed'] == 3
    assert observation['target_read_offset'] == 0
    assert observation['target_read_data'] == 0x00000010
    assert observation['target_last_write_offset'] == 0
    assert observation['target_last_write_data'] == 0xFFFFFFFF
    assert observation['isr_result'] == 0x00000010
    assert observation['isr_flag'] == 1
    assert observation['irq_edges'] == 1 and observation['irq_takes'] == 1
    assert observation['wait_timeout'] == 0


def test_correspondence_accepts_the_real_mixed_case_lines():
    """The real F2/F3 lines of both targets match the input they were handed."""
    apb = case_of(MIXED_F2_APB3)
    axil = case_of(MIXED_F2_AXIL)
    ram = case_of(MIXED_F3_RAM)
    common = dict(layout=LAYOUT, windows=WINDOWS, irq=None, dma=None,
                  protocol=MIXED_TARGET_PROTOCOL, irq_base=WINDOWS['ip_base'])
    assert correspondence(record('F2:40001000'), apb, **common) is None
    assert correspondence(record('F2:40002004'), axil, **common) is None
    assert correspondence(record('F3:00014004:0badf00d'), ram, **common) is None
    # The same line credited to the other target's protocol is refused.
    swapped = dict(apb, target_protocol='axi4-lite')
    assert correspondence(record('F2:40001000'), swapped, **common) == (
        'case target_protocol axi4-lite differs from the declared target protocol apb3')


# --- the homogeneous path that must not change -----------------------------

def test_the_apb3_case_keys_are_unchanged():
    assert case_observation_keys('F4', 'apb3') == CASE_OBSERVATION_KEYS['F4']
    assert case_observation_keys('F4', 'apb3') == (
        'mmio_addr', 'mmio_value', 'apb_offset', 'apb_pwdata', 'apb_pready')
    assert case_counter_keys('apb3') == CASE_COUNTER_KEYS
    assert 'apb_reads' in case_counter_keys('apb3')
    assert 'target_reads' not in case_counter_keys('apb3')
    assert 'axi_aw' not in case_counter_keys('apb3')


def test_the_axilite_case_keys_are_unchanged():
    assert case_observation_keys('F4', 'axi4-lite') == AXI_CASE_OBSERVATION_KEYS['F4']
    assert case_counter_keys('axi4-lite') == AXI_CASE_COUNTER_KEYS
    assert 'target_reads' in case_counter_keys('axi4-lite')
    assert 'apb_reads' not in case_counter_keys('axi4-lite')


def test_a_mixed_build_uses_the_neutral_group_for_every_flow():
    for flow in ('F1', 'F2', 'F3', 'F4', 'F5'):
        assert case_observation_keys(flow, MIXED_TARGET_PROTOCOL) == \
            case_observation_keys(flow, 'axi4-lite')
    assert case_counter_keys(MIXED_TARGET_PROTOCOL) == AXI_CASE_COUNTER_KEYS
    assert case_counter_keys('apb3', bus='ahb') != AXI_CASE_COUNTER_KEYS


def test_a_legacy_case_line_keeps_the_build_protocol():
    """A one-target case carries no ``target_index`` and no protocol word."""
    case = {'flow': 'F4', 'target_offset': 8}
    assert case_target_protocol(case, {'ip_base': 0x40001000, 'ip_size': 4096}) == 'apb3'
    assert _target_protocol_mismatch(case, {'ip_base': 0x40001000, 'ip_size': 4096},
                                     'apb3') is None


# --- the two named refusals this increment keeps ---------------------------

#: An F5 declaration shape, as ``f5_declaration`` returns it.  Only its presence
#: matters to the protocol gate: a target that declares one under AXI4-Lite is
#: refused before any model is built.
F5_FACTS = dict(port='irq_o', bit=0, trigger='pulse', polarity='active_high',
                pulse_ticks=16, status_offset=0, trigger_offsets=[4, 8, 0],
                status_kind='count', cause_declared=False, cause_bits=[],
                cause_mask=0, clear=None)


def test_an_axilite_target_declaring_f5_is_refused_by_name():
    """AXI4-Lite has no F5 run; the admitted set is stated by its own name."""
    assert f5_protocol_check('apb3', 'timer', dict(F5_FACTS)) is None
    # A target with no F5 facts keeps its own, longer-standing refusal.
    assert f5_protocol_check('axi4-lite', 'axiluart', None) is None
    with pytest.raises(ValueError) as error:
        f5_protocol_check('axi4-lite', 'axiluart', dict(F5_FACTS))
    assert str(error.value) == (
        'unsupported-f5:target-protocol-not-run:axi4-lite:axiluart')


def test_a_dma_route_is_admitted_on_an_axilite_target():
    """The routed beat completes on the target's own AXI4-Lite B/R response.

    The APB3 route is unchanged and every protocol with a generated beat adapter
    is admitted; the named refusal applies to a wire without one.
    """
    assert dma_route_protocol_check('apb3', 'timer') is None
    assert dma_route_protocol_check('axi4-lite', 'axiluart') is None
    with pytest.raises(ValueError) as error:
        dma_route_protocol_check('ahb-lite', 'ahbsha')
    assert str(error.value) == (
        'unsupported-dma-route:target-protocol-not-admitted:ahb-lite:ahbsha')
