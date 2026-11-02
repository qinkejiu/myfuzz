"""Mixed target-protocol builds: any subset of 2..5 supported protocols.

The increment generalizes the mixed axis from the one historical exact pair
(APB3 + AXI4-Lite) to any subset of 2..5 supported target protocols.  Every
target states its own protocol from its own artifact; the generated header states
that protocol per target, the host samples that target's own trace and completion
criterion, and each case line names the protocol of the target it was routed to.

The declaration axis, the generated per-target traits and the case/summary words
are the only things asserted here.  The case and summary lines are the exact lines
the real runs in ``runs/p1-mixed-protocols/`` printed - an APB3 + TL-UL session, an
APB3 + Wishbone-classic session and a three-protocol APB3 + AXI4-Lite + TL-UL
session - so the parser is exercised on the host's own output rather than on a
hand-written shape.  No model is built and no run is claimed here.
"""
import json
from pathlib import Path

import pytest

from myfuzz.composition.multi_target import declared_targets, target_windows

from scripts.run_inprocess_f1f6 import (
    AXI_CASE_COUNTER_KEYS, AXI_CASE_OBSERVATION_KEYS, MIXED_TARGET_PROTOCOL,
    SUPPORTED_TARGET_PROTOCOLS, TARGET_LABELS, TARGET_TRANSFER_CRITERIA,
    TLUL_CASE_COUNTER_KEYS, TLUL_CASE_OBSERVATION_KEYS, WB_CASE_COUNTER_KEYS,
    WB_CASE_OBSERVATION_KEYS, _generated_target_traits, build_layout,
    case_counter_keys, case_document, case_observation_keys, correspondence,
    f5_protocol_check, flow_arity, mixed_case_counter_keys,
    mixed_case_observation_keys, mixed_target_bridge, mixed_target_criterion,
    ordered_target_protocols, parse_case_line, parse_record, parse_run_log,
    profile_protocol, render_bindings, target_protocol_axis, target_protocol_label,
)

ROOT = Path(__file__).resolve().parents[2]
RUNS = ROOT / 'runs/p1-mixed-protocols'

APB3_TLUL_SCENARIO = (
    ROOT / 'configs/scenarios/inprocess-obi-apb-tlul-mixed-timer-rvtimer-f1f4.json')
APB3_WB_SCENARIO = (
    ROOT / 'configs/scenarios/inprocess-obi-apb-wb-mixed-timer-uart-f1f4.json')
THREE_SCENARIO = (
    ROOT / 'configs/scenarios/inprocess-obi-apb-axi4lite-tlul-mixed-three-protocol-f1f4.json')
APB3_WB_TLUL_SCENARIO = (
    ROOT / 'configs/scenarios/inprocess-obi-apb-wb-tlul-mixed-timer-uart-rvtimer-f1f4.json')

ARITY = flow_arity(None, None)
#: The flow tags the saved case lines carry.  Parsing a line is independent of
#: whether a build serves the flow, so an F5 case is readable here even though no
#: IRQ declaration is passed to ``flow_arity``.
CASE_FLOWS = dict(ARITY, F5=3)

#: One saved session: its scenario, the records the command really ran and the
#: protocols the declaration names.  The record lists are the exact ``--records``
#: strings of ``runs/p1-mixed-protocols/run-all.sh``.
SESSIONS = {
    'apb3-tlul': dict(
        scenario=APB3_TLUL_SCENARIO, protocols=('apb3', 'tl-ul'),
        records=['F2:40001000', 'F4:40001008:0fffffff',
                 'F5:00000001:00000000:ffffffff', 'F2:40003004',
                 'F4:40003004:00000001', 'F2:40003004', 'F4:40003118:00000100',
                 'F3:00014004:0badf00d']),
    'apb3-wb': dict(
        scenario=APB3_WB_SCENARIO, protocols=('apb3', 'wishbone'),
        records=['F2:40001000', 'F4:40001008:0fffffff',
                 'F5:00000001:00000000:ffffffff', 'F2:40002004',
                 'F4:40002000:0000005a', 'F2:40002000', 'F4:4000200c:00000041',
                 'F3:00014004:0badf00d']),
    'three-protocol': dict(
        scenario=THREE_SCENARIO, protocols=('apb3', 'axi4-lite', 'tl-ul'),
        records=['F2:40001000', 'F4:40001008:0fffffff',
                 'F5:00000001:00000000:ffffffff', 'F2:40002004',
                 'F4:4000200c:00005a5a', 'F2:40003004', 'F4:40003004:00000001',
                 'F3:00014004:0badf00d']),
    'apb3-wb-tlul': dict(
        scenario=APB3_WB_TLUL_SCENARIO, protocols=('apb3', 'wishbone', 'tl-ul'),
        records=['F2:40001000', 'F4:40001008:0fffffff',
                 'F5:00000001:00000000:ffffffff', 'F2:40002004',
                 'F4:40002000:0000005a', 'F2:40003004', 'F4:40003118:00000100',
                 'F3:00014004:0badf00d']),
}


def config_of(name):
    return json.loads(SESSIONS[name]['scenario'].read_text())


def declared_protocols(config):
    """Each declared target's protocol, from its own profile's MMIO endpoint."""
    return [profile_protocol(json.loads((ROOT / row['profile']).read_text()))
            for row in declared_targets(config)]


def windows_of(name):
    """The address view of one session, with each target's own protocol."""
    config = config_of(name)
    windows = target_windows(config)
    windows['target_count'] = len(windows['ip_targets'])
    windows['target_protocols'] = declared_protocols(config)
    return windows


def saved(name):
    """The parsed case and summary lines of one saved run."""
    return parse_run_log((RUNS / name / 'run.log').read_text(), flows=CASE_FLOWS)


def session_documents(name):
    """One case document per saved case, projected with the session's own set."""
    entry = SESSIONS[name]
    windows = windows_of(name)
    layout = build_layout(windows, 0x10080, irq_base=windows['ip_base'])
    parsed = saved(name)
    assert len(parsed['cases']) == len(entry['records'])
    documents = []
    for text, case in zip(entry['records'], parsed['cases']):
        record = parse_record(text, windows=windows, arity=CASE_FLOWS,
                              label='mixed')
        documents.append(case_document(
            record, case, protocol=MIXED_TARGET_PROTOCOL,
            protocols=entry['protocols']))
    return windows, layout, documents, parsed


# --- the declaration axis -------------------------------------------------


def test_the_new_scenarios_declare_the_protocols_they_name():
    assert declared_protocols(config_of('apb3-tlul')) == ['apb3', 'tl-ul']
    assert declared_protocols(config_of('apb3-wb')) == ['apb3', 'wishbone']
    assert declared_protocols(config_of('three-protocol')) == [
        'apb3', 'axi4-lite', 'tl-ul']
    assert declared_protocols(config_of('apb3-wb-tlul')) == [
        'apb3', 'wishbone', 'tl-ul']
    for name in SESSIONS:
        assert target_protocol_axis(set(SESSIONS[name]['protocols'])) == (
            MIXED_TARGET_PROTOCOL, True)


def test_every_supported_pair_and_triple_is_a_mixed_build():
    pairs = [('apb3', 'axi4-lite'), ('apb3', 'wishbone'), ('apb3', 'tl-ul'),
             ('axi4-lite', 'wishbone'), ('axi4-lite', 'tl-ul'),
             ('wishbone', 'tl-ul'),
             # The AHB-Lite target added later mixes like any other protocol.
             ('apb3', 'ahb-lite'), ('tl-ul', 'ahb-lite')]
    for pair in pairs:
        assert target_protocol_axis(set(pair)) == (MIXED_TARGET_PROTOCOL, True)
    for triple in [('apb3', 'axi4-lite', 'tl-ul'),
                   ('apb3', 'wishbone', 'tl-ul'),
                   ('axi4-lite', 'wishbone', 'tl-ul'),
                   ('apb3', 'ahb-lite', 'tl-ul'),
                   ('wishbone', 'ahb-lite', 'axi4-lite')]:
        assert target_protocol_axis(set(triple)) == (MIXED_TARGET_PROTOCOL, True)
    # Four and five declared protocols are one build too.
    assert target_protocol_axis({'apb3', 'axi4-lite', 'wishbone', 'tl-ul'}) == (
        MIXED_TARGET_PROTOCOL, True)
    assert target_protocol_axis({'apb3', 'axi4-lite', 'wishbone', 'tl-ul',
                                 'ahb-lite'}) == (MIXED_TARGET_PROTOCOL, True)
    assert target_protocol_axis(set(SUPPORTED_TARGET_PROTOCOLS)) == (
        MIXED_TARGET_PROTOCOL, True)


def test_the_declared_protocols_are_ordered_canonically():
    # The build-wide words (bridge, criterion) must not depend on set iteration.
    assert ordered_target_protocols({'tl-ul', 'apb3', 'wishbone'}) == [
        'apb3', 'wishbone', 'tl-ul']
    assert ordered_target_protocols({'tl-ul', 'axi4-lite'}) == [
        'axi4-lite', 'tl-ul']


def test_a_protocol_outside_the_supported_set_is_refused_by_name():
    with pytest.raises(ValueError) as error:
        target_protocol_axis({'apb3', 'ahb5'})
    assert str(error.value) == 'unsupported-targets:mixed-protocol:ahb5,apb3'
    with pytest.raises(ValueError) as error:
        target_protocol_axis({'apb4', 'tl-ul', 'wishbone'})
    assert str(error.value) == 'unsupported-targets:mixed-protocol:apb4,tl-ul,wishbone'
    with pytest.raises(ValueError) as error:
        target_protocol_axis(set())
    assert str(error.value) == 'unsupported-targets:none'


def test_mixed_pin_models_are_refused_by_name():
    """A pin model is a one-target feature, whatever protocols are mixed.

    ``render_bindings`` refuses a multi-target declaration that states pads before
    it reads any artifact, so this is the entry's own gate rather than a claim.
    """
    def row(index, name, base, pins):
        return dict(index=index, name=name, protocol='apb3',
                    artifact={'plan': {'timing': {'reset_assert_ticks': 2,
                                                  'reset_release_ticks': 3}}},
                    window={'base': base, 'size': 4096}, irq=None, pins=pins)
    rows = [row(0, 'timer', 0x40001000, dict(endpoint_id='gpio.pins', width=4)),
            row(1, 'other', 0x40002000, None)]
    with pytest.raises(ValueError) as error:
        render_bindings({}, None, None, None, {}, {}, irq=None, dma=None,
                        dma_irq=None, targets=rows)
    assert str(error.value) == 'unsupported-pins:multiple-targets'
    bare = [row(0, 'a', 0x40001000, None), row(1, 'b', 0x40002000, None)]
    with pytest.raises(ValueError) as error:
        render_bindings({}, None, None, None, {}, {}, irq=None, dma=None,
                        dma_irq=None, targets=bare,
                        pins=dict(endpoint_id='gpio.pins', width=4))
    assert str(error.value) == 'unsupported-pins:multiple-targets'


def test_f5_stays_refused_on_a_protocol_with_no_f5_run():
    declared = {'links': [dict(index=0, target_index=0)]}
    assert f5_protocol_check('apb3', 'timer', declared) is None
    assert f5_protocol_check('tl-ul', 'tlultimer', declared) is None
    with pytest.raises(ValueError) as error:
        f5_protocol_check('wishbone', 'wbuart', declared)
    assert str(error.value) == (
        'unsupported-f5:target-protocol-not-run:wishbone:wbuart')
    with pytest.raises(ValueError) as error:
        f5_protocol_check('axi4-lite', 'axiluart', declared)
    assert str(error.value) == (
        'unsupported-f5:target-protocol-not-run:axi4-lite:axiluart')


# --- the build-wide words a mixed declaration renders ----------------------


def test_the_historical_pair_keeps_its_exact_build_words():
    assert mixed_target_bridge({'apb3', 'axi4-lite'}) == (
        'mixed:apb3_mmio_bridge+axi4_lite_mmio_bridge')
    assert mixed_target_criterion({'apb3', 'axi4-lite'}) == (
        'per_target: apb3=sel_enable_ready; axi4-lite=aw_w_b or ar_r')
    assert target_protocol_label(MIXED_TARGET_PROTOCOL, {'apb3', 'axi4-lite'}) == (
        TARGET_LABELS[MIXED_TARGET_PROTOCOL])


def test_each_mixed_protocol_contributes_its_own_bridge():
    assert mixed_target_bridge({'apb3', 'wishbone'}) == (
        'mixed:apb3_mmio_bridge+beat_to_wishbone')
    assert mixed_target_bridge({'apb3', 'tl-ul'}) == (
        'mixed:apb3_mmio_bridge+beat_to_tlul')
    assert mixed_target_bridge({'apb3', 'axi4-lite', 'tl-ul'}) == (
        'mixed:apb3_mmio_bridge+axi4_lite_mmio_bridge+beat_to_tlul')
    assert target_protocol_label(MIXED_TARGET_PROTOCOL, {'apb3', 'wishbone'}) == (
        'APB+Wishbone')
    assert target_protocol_label(MIXED_TARGET_PROTOCOL,
                                 {'apb3', 'axi4-lite', 'tl-ul'}) == (
        'APB+AXI4-Lite+TL-UL')


def test_each_mixed_protocol_contributes_its_own_criterion():
    word = mixed_target_criterion({'apb3', 'wishbone', 'tl-ul'})
    assert word == ('per_target: apb3=' + TARGET_TRANSFER_CRITERIA['apb3'] +
                    '; wishbone=' + TARGET_TRANSFER_CRITERIA['wishbone'] +
                    '; tl-ul=' + TARGET_TRANSFER_CRITERIA['tl-ul'])


# --- the case-line projection ---------------------------------------------


def test_the_historical_pair_projects_exactly_its_axi_tables():
    """The generalized projection must not grow the historical pair's documents."""
    pair = {'apb3', 'axi4-lite'}
    for flow in ('F1', 'F2', 'F3', 'F4', 'F5', 'F6'):
        assert mixed_case_observation_keys(flow, pair) == (
            AXI_CASE_OBSERVATION_KEYS[flow]), flow
    assert mixed_case_counter_keys(pair) == AXI_CASE_COUNTER_KEYS
    for flow in ('F2', 'F4'):
        assert case_observation_keys(flow, MIXED_TARGET_PROTOCOL) == (
            AXI_CASE_OBSERVATION_KEYS[flow])
    assert case_counter_keys(MIXED_TARGET_PROTOCOL) == AXI_CASE_COUNTER_KEYS
    assert case_counter_keys(MIXED_TARGET_PROTOCOL,
                             protocols=('apb3', 'axi4-lite')) == (
        AXI_CASE_COUNTER_KEYS)


def test_a_wishbone_mixed_projection_is_the_wishbone_table_plus_the_neutral_group():
    pair = ('apb3', 'wishbone')
    for flow in ('F2', 'F4', 'F5'):
        assert mixed_case_observation_keys(flow, pair) == (
            WB_CASE_OBSERVATION_KEYS[flow]), flow
    assert mixed_case_counter_keys(pair) == WB_CASE_COUNTER_KEYS


def test_a_tlul_mixed_projection_is_the_tlul_table_plus_the_neutral_group():
    pair = ('apb3', 'tl-ul')
    for flow in ('F2', 'F4', 'F5'):
        assert mixed_case_observation_keys(flow, pair) == (
            TLUL_CASE_OBSERVATION_KEYS[flow]), flow
    assert mixed_case_counter_keys(pair) == TLUL_CASE_COUNTER_KEYS


def test_a_three_protocol_projection_covers_every_declared_protocol():
    triple = ('apb3', 'axi4-lite', 'tl-ul')
    for flow in ('F2', 'F4'):
        keys = mixed_case_observation_keys(flow, triple)
        for name in ('target_resp', 'target_offset', 'target_ready'):
            assert name in keys
        for name in TLUL_CASE_OBSERVATION_KEYS[flow]:
            assert name in keys
    counters = mixed_case_counter_keys(triple)
    for name in ('axi_aw', 'axi_r', 'tlul_a_handshakes', 'tlul_errors',
                 'target_error'):
        assert name in counters
    # The adaptive counters of a protocol the build does not declare are absent.
    assert 'wb_acks' not in counters


# --- the generated per-target traits --------------------------------------

REQUEST_ROLES = ('IP_REQ_VALID', 'IP_REQ_WRITE', 'IP_REQ_ADDR', 'IP_REQ_WDATA',
                 'IP_REQ_BE', 'IP_REQ_READY', 'IP_RSP_READY', 'IP_RSP_VALID',
                 'IP_RSP_RDATA', 'IP_RSP_ERROR')
TRACE_FIELDS = {
    'apb3': ('PSEL', 'PENABLE', 'PREADY', 'PWRITE', 'PADDR', 'PWDATA', 'PRDATA'),
    'axi4-lite': ('AWVALID', 'AWREADY', 'AWADDR', 'AWPROT', 'WVALID', 'WREADY',
                  'WDATA', 'WSTRB', 'BVALID', 'BREADY', 'BRESP', 'ARVALID',
                  'ARREADY', 'ARADDR', 'ARPROT', 'RVALID', 'RREADY', 'RDATA',
                  'RRESP'),
    'wishbone': ('CYC', 'STB', 'ACK', 'WE', 'ADR', 'DAT_W', 'DAT_R', 'SEL',
                 'STALL'),
    'tl-ul': ('A_VALID', 'A_READY', 'A_OPCODE', 'A_ADDRESS', 'A_MASK', 'A_DATA',
              'D_VALID', 'D_READY', 'D_DATA', 'D_ERROR'),
}


def mixed_trait_text(protocols):
    """Render the generated traits for one fabricated target per protocol."""
    targets, fields = [], []
    for index, protocol in enumerate(protocols):
        targets.append(dict(index=index, protocol=protocol,
                            window=dict(base=0x40001000 + 0x1000 * index, size=4096),
                            reset_assert=2, reset_release=3, irq=None))
        item = {role: 'req_' + role.lower() for role in REQUEST_ROLES}
        for name in TRACE_FIELDS[protocol]:
            item['IP_TRACE_' + name] = 'trace_' + name.lower()
        fields.append(item)
    observed = {row['index']: None for row in targets}
    return '\n'.join(_generated_target_traits(
        targets, fields, [[] for _ in targets], observed, None, lambda value: value))


def trait_block(text, index):
    """The text of one trait specialization, up to the next one."""
    marker = 'template <> struct IpTarget<%d> {' % index
    assert marker in text
    block = text.split(marker, 1)[1]
    following = 'template <> struct IpTarget<%d> {' % (index + 1)
    return block.split(following, 1)[0] if following in block else block


def test_generated_traits_state_each_protocols_own_macros_and_taps():
    text = mixed_trait_text(['apb3', 'wishbone', 'tl-ul'])
    first, second, third = (trait_block(text, 0), trait_block(text, 1),
                            trait_block(text, 2))
    # Each target states its own protocol through the per-target macros.
    assert 'static constexpr const char *protocol = "apb3";' in first
    assert 'static constexpr bool apb = true;' in first
    assert 'static constexpr bool wishbone = false;' in first
    assert 'static constexpr const char *bridge = TARGET_BRIDGE_0;' in first
    assert 'static constexpr const char *protocol = "wishbone";' in second
    assert 'static constexpr bool wishbone = true;' in second
    assert 'static constexpr bool apb = false;' in second
    assert 'static constexpr const char *bridge = TARGET_BRIDGE_1;' in second
    assert 'static constexpr const char *protocol = "tl-ul";' in third
    assert 'static constexpr bool tlul = true;' in third
    assert 'static constexpr bool wishbone = false;' in third
    assert 'static constexpr const char *bridge = TARGET_BRIDGE_2;' in third
    # And only its own protocol's taps.
    assert 'static bool apb_sel(' in first
    assert 'static bool wb_cyc(' not in first
    assert 'static bool tlul_a_valid(' not in first
    assert 'static bool wb_cyc(' in second
    assert 'static uint32_t wb_adr(' in second
    assert 'static uint32_t wb_dat_r(' in second
    assert 'static constexpr bool wb_stall_sampled = true;' in second
    assert 'static bool apb_sel(' not in second
    assert 'static bool tlul_a_valid(' in third
    assert 'static uint32_t tlul_d_data(' in third
    assert 'static bool wb_cyc(' not in third
    assert 'static bool apb_sel(' not in third


def test_a_wishbone_trait_without_a_stall_pin_states_that_it_has_none():
    targets = [dict(index=0, protocol='wishbone',
                    window=dict(base=0x40001000, size=16), reset_assert=2,
                    reset_release=3, irq=None)]
    item = {role: 'req_' + role.lower() for role in REQUEST_ROLES}
    for name in ('CYC', 'STB', 'ACK', 'WE', 'ADR', 'DAT_W', 'DAT_R', 'SEL'):
        item['IP_TRACE_' + name] = 'trace_' + name.lower()
    text = '\n'.join(_generated_target_traits(
        targets, [item], [[]], {0: None}, None, lambda value: value))
    assert 'static constexpr bool wb_stall_sampled = false;' in text
    assert 'static bool wb_stall(' not in text


# --- the saved mixed sessions ---------------------------------------------


def test_the_saved_sessions_route_every_case_to_its_own_protocol():
    for name, entry in SESSIONS.items():
        windows, layout, documents, parsed = session_documents(name)
        assert windows['target_protocols'] == list(entry['protocols'])
        for document in documents:
            assert document['status'] == 'observations_passed'
            # A mixed build always states the routed target's protocol word;
            # a RAM-only case states none.
            assert 'target_protocol' in document
            stated = document['target_protocol']
            if document['observation'].get('write_addr') is not None:
                continue  # F3 carries no target
            index = document['target_index']
            assert stated == entry['protocols'][index], (name, document['index'])
        assert parsed['summary']['status'] == 'observations_passed'
        assert parsed['summary']['cases'] == len(entry['records'])


def test_every_routed_case_leaves_the_other_targets_at_zero():
    """Each case line carries per-target counters, and only one target moved.

    The counters are read from the parsed case line (the host prints them for a
    multi-target build); the projected document keeps the routed target's own
    transfer facts.
    """
    for name in SESSIONS:
        windows, layout, documents, parsed = session_documents(name)
        count = windows['target_count']
        assert parsed['summary']['ip_count'] == count
        for case, document in zip(parsed['cases'], documents):
            routed = case.get('target_index', -1)
            moved = 0
            for index in range(count):
                reads = case['target%d_reads' % index]
                writes = case['target%d_writes' % index]
                if reads or writes:
                    assert index == routed, (name, document['index'], index)
                    moved += 1
            assert moved == (1 if routed >= 0 else 0), (name, document['index'])


def test_the_saved_apb3_tlul_run_samples_both_traces():
    windows, layout, documents, parsed = session_documents('apb3-tlul')
    apb3_cases = [row for row in documents if row.get('target_index') == 0]
    tlul_cases = [row for row in documents if row.get('target_index') == 1]
    assert len(apb3_cases) == 3 and len(tlul_cases) == 4
    f5_rows = [row for row in apb3_cases if row['flow'] == 'F5']
    assert len(f5_rows) == 1
    for row in apb3_cases:
        observation = row['observation']
        assert row['target_protocol'] == 'apb3'
        # Every TL-UL counter of an APB3-routed case is zero, and the TL-UL
        # trace keys are absent from that line.
        assert observation['tlul_a_handshakes'] == 0
        assert observation['tlul_d_handshakes'] == 0
        assert observation['tlul_errors'] == 0
        if row['flow'] in ('F2', 'F4'):
            assert observation['target_reads'] + observation['target_writes'] >= 1
            assert observation['target_ready'] == 1
            # The TL-UL trace keys are not on an APB3-routed line at all.
            assert observation['tlul_a_address'] == 'unknown'
        if row['flow'] == 'F5':
            # The one F5 target is still the APB3 timer: its own trigger/status
            # words carried the interrupt, not the TL-UL target's registers.
            assert observation['trigger_writes'] == 3
            assert observation['isr_read_addr'] == 0x40001000
    for row in tlul_cases:
        observation = row['observation']
        assert row['target_protocol'] == 'tl-ul'
        assert observation['tlul_a_handshakes'] == 1
        assert observation['tlul_d_handshakes'] == 1
        assert observation['tlul_d_error'] == 0
        assert observation['target_ready'] == 1
        # The sampled A channel carries the routed offset and the D channel the
        # word the CPU committed.
        assert observation['tlul_a_address'] == observation['target_offset']
        if row['flow'] == 'F2':
            assert observation['tlul_a_opcode'] == 4
            assert observation['tlul_d_data'] == observation['target_rdata']
        else:
            assert observation['tlul_a_opcode'] in (0, 1)
            assert observation['tlul_a_data'] == observation['target_wdata']
    summary = parsed['summary']
    assert summary['target_protocols'] == 'apb3,tl-ul'
    assert summary['target0_protocol'] == 'apb3'
    assert summary['target0_bridge'] == 'apb3_mmio_bridge'
    assert summary['target1_protocol'] == 'tl-ul'
    assert summary['target1_bridge'] == 'beat_to_tlul'
    assert summary['tlul_a_handshakes'] == 4
    assert summary['tlul_d_handshakes'] == 4
    assert summary['tlul_errors'] == 0
    assert summary['target_error'] == 'unknown'
    assert summary['bus_error_tlul'] == 'unknown'


def test_the_saved_apb3_wishbone_run_samples_the_classic_handshake():
    windows, layout, documents, parsed = session_documents('apb3-wb')
    wb_cases = [row for row in documents if row.get('target_index') == 1]
    apb3_cases = [row for row in documents if row.get('target_index') == 0]
    assert len(wb_cases) == 4 and len(apb3_cases) == 3
    for row in wb_cases:
        observation = row['observation']
        assert row['target_protocol'] == 'wishbone'
        assert observation['wb_acks'] == 1
        assert observation['wb_stb_pulses'] == 1
        assert observation['wb_cyc'] == 1
        assert observation['wb_ack'] == 1
        assert observation['wb_stb'] == 0
        assert observation['wb_sel'] == 15
        assert observation['wb_adr'] == observation['target_offset'] // 4
        if observation['wb_we']:
            assert observation['wb_dat_w'] == observation['target_wdata']
        else:
            assert observation['wb_dat_r'] == observation['target_rdata']
    for row in apb3_cases:
        observation = row['observation']
        assert row['target_protocol'] == 'apb3'
        assert observation['wb_acks'] == 0
        if row['flow'] in ('F2', 'F4'):
            assert observation['wb_cyc'] == 'unknown'
        if row['flow'] == 'F5':
            assert observation['trigger_writes'] == 3
            assert observation['isr_read_addr'] == 0x40001000
    summary = parsed['summary']
    assert summary['target_protocols'] == 'apb3,wishbone'
    assert summary['target0_bridge'] == 'apb3_mmio_bridge'
    assert summary['target1_protocol'] == 'wishbone'
    assert summary['target1_bridge'] == 'beat_to_wishbone'
    assert summary['wb_acks'] == 4
    assert summary['wb_stb_pulses'] == 4
    assert summary['target_error'] == 'unknown'
    assert summary['bus_error_wb'] == 'unknown'


def test_the_saved_three_protocol_run_states_three_protocols_and_bridges():
    windows, layout, documents, parsed = session_documents('three-protocol')
    by_protocol = {}
    for row in documents:
        if row.get('target_index', -1) < 0:
            continue
        by_protocol.setdefault(row['target_protocol'], []).append(row)
    assert set(by_protocol) == {'apb3', 'axi4-lite', 'tl-ul'}
    assert {name: len(rows) for name, rows in by_protocol.items()} == {
        'apb3': 3, 'axi4-lite': 2, 'tl-ul': 2}
    # Each protocol's own counters are only non-zero on its own cases.
    for row in by_protocol['axi4-lite']:
        observation = row['observation']
        assert (observation['axi_aw'], observation['axi_ar']) in ((0, 1), (1, 0))
        assert observation['tlul_a_handshakes'] == 0
    for row in by_protocol['tl-ul']:
        observation = row['observation']
        assert observation['tlul_a_handshakes'] == 1
        assert observation['axi_aw'] == 0 and observation['axi_ar'] == 0
    summary = parsed['summary']
    assert summary['ip_count'] == 3
    assert summary['target_protocols'] == 'apb3,axi4-lite,tl-ul'
    assert summary['target0_protocol'] == 'apb3'
    assert summary['target0_bridge'] == 'apb3_mmio_bridge'
    assert summary['target1_protocol'] == 'axi4-lite'
    assert summary['target1_bridge'] == 'axi4_lite_mmio_bridge'
    assert summary['target2_protocol'] == 'tl-ul'
    assert summary['target2_bridge'] == 'beat_to_tlul'
    for index in range(3):
        assert summary['target%d_reads_total' % index] >= 1
        assert summary['target%d_writes_total' % index] >= 1


def test_the_saved_no_axi_three_protocol_run_prints_no_axi_counter_group():
    """A three-protocol build without an AXI4-Lite target prints no axi_* group.

    The neutral counter words are printed by the Wishbone group (the first
    declared protocol group that has them), the TL-UL group prints its own
    ``tlul_error`` word, and the summary names only the channels the build has.
    """
    windows, layout, documents, parsed = session_documents('apb3-wb-tlul')
    raw = (RUNS / 'apb3-wb-tlul' / 'run.log').read_text()
    assert 'axi_aw' not in raw and 'axi_error' not in raw
    for document in documents:
        observation = document['observation']
        assert 'axi_aw' not in observation
        assert 'wb_acks' in observation
        assert 'tlul_a_handshakes' in observation
        if document.get('target_index', -1) == 1:
            assert observation['wb_acks'] == 1
        if document.get('target_index', -1) == 2:
            assert observation['tlul_a_handshakes'] == 1
    summary = parsed['summary']
    assert summary['target_protocols'] == 'apb3,wishbone,tl-ul'
    assert summary['ip_count'] == 3
    assert 'target_error' in summary and 'tlul_error' in summary
    assert 'axi_error' not in summary
    assert summary['bus_error_wb'] == 'unknown'
    assert summary['bus_error_tlul'] == 'unknown'
    assert summary['bus_error_apb'] == 'observed'


def test_the_saved_mixed_case_lines_satisfy_the_entrys_own_correspondence():
    """The parser reads the saved lines and the correspondence check passes.

    The live run already applied this check (every case is
    ``observations_passed``); re-running it here ties the saved text to the
    declarations the sessions really built, so a hand-edited line cannot pass.
    """
    for name, entry in SESSIONS.items():
        windows, layout, documents, parsed = session_documents(name)
        for (text, case, document) in zip(entry['records'], parsed['cases'],
                                          documents):
            record = parse_record(text, windows=windows, arity=CASE_FLOWS,
                              label='mixed')
            if record['flow'] == 'F5':
                # F5 needs the declared IRQ link table; the case document above
                # already states the routed target and its protocol.
                continue
            mismatch = correspondence(
                record, case, layout=layout, windows=windows, irq=None, dma=None,
                protocol=MIXED_TARGET_PROTOCOL, pins=None, registers=None,
                bus='obi', irq_base=layout['irq_base'], f5_target_index=None)
            assert mismatch is None, (name, document['index'], mismatch)
