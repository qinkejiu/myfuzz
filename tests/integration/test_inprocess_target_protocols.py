"""Wishbone and TL-UL register targets in the unified in-process entry (pure Python).

The unified entry and its C++ host now drive real Wishbone-classic and TL-UL
register targets in a homogeneous build, beside the APB3 and AXI4-Lite targets
they already drove.  These tests cover the declaration axis, the request the
generic target is built from, the generated per-target traits, the case and
summary words the two protocols print, and the named refusals this increment
keeps.  The case/summary text is the exact text the real runs in
``runs/round3-target-protocols/`` printed, so the parser is exercised on the
host's own output.  No model is built and no run is claimed here.
"""
import json
from pathlib import Path

import pytest

from myfuzz.composition.multi_target import target_windows

from scripts.run_inprocess_f1f6 import (
    AHB_TARGET_KIND, CASE_COUNTER_KEYS, MIXED_TARGET_PROTOCOL,
    PROTOCOL_TRACE_ROLES, SUPPORTED_TARGET_PROTOCOLS, TARGET_LABELS, TARGET_PROTOCOLS,
    TLUL_CASE_COUNTER_KEYS, TLUL_CASE_OBSERVATION_KEYS, WB_CASE_COUNTER_KEYS,
    WB_CASE_OBSERVATION_KEYS, WB_TRACE_ROLES, TLUL_TRACE_ROLES,
    _generated_target_traits, _target_protocol_mismatch, build_layout,
    case_counter_keys, case_document, case_observation_keys, case_target_protocol,
    correspondence, dma_route_protocol_check, f5_protocol_check, flow_arity,
    generic_target_request_from_profile, parse_case_line, parse_record, parse_run_log,
    parse_summary_line, profile_protocol, target_protocol, target_protocol_axis,
    target_view,
)

ROOT = Path(__file__).resolve().parents[2]
WB_SCENARIO = ROOT / 'configs/scenarios/inprocess-obi-wb-uart-f1f4.json'
TLUL_SCENARIO = ROOT / 'configs/scenarios/inprocess-obi-tlul-timer-f1f4.json'
WB_CONFIG = json.loads(WB_SCENARIO.read_text())
TLUL_CONFIG = json.loads(TLUL_SCENARIO.read_text())
WB_PROFILE = 'configs/peripherals/zipcpu_uart/component_profile.json'
TLUL_PROFILE = 'configs/peripherals/opentitan_rv_timer_local/component_profile.json'
AHB_PROFILE = 'configs/peripherals/caliptra_sha256/component_profile.json'
ARITY = flow_arity(None, None)


def windows_of(config, protocol):
    windows = target_windows(config)
    windows['target_count'] = len(windows['ip_targets'])
    windows['target_protocols'] = [protocol]
    return windows


WB_WINDOWS = windows_of(WB_CONFIG, 'wishbone')
TLUL_WINDOWS = windows_of(TLUL_CONFIG, 'tl-ul')
WB_LAYOUT = build_layout(WB_WINDOWS, 0x10080)
TLUL_LAYOUT = build_layout(TLUL_WINDOWS, 0x10080)


def case_of(line):
    return parse_case_line(line, flows=ARITY)


def record_of(text, windows):
    return parse_record(text, windows=windows, arity=ARITY,
                        label='Wishbone' if windows is WB_WINDOWS else 'TL-UL')


# --- the declaration axis -------------------------------------------------

def test_the_two_generic_register_kinds_map_to_their_protocol():
    assert TARGET_PROTOCOLS['wishbone_register_observe'] == 'wishbone'
    assert TARGET_PROTOCOLS['tlul_register_observe'] == 'tl-ul'
    assert TARGET_PROTOCOLS['apb3_register_observe'] == 'apb3'
    assert TARGET_PROTOCOLS['axi4lite_register_observe'] == 'axi4-lite'
    assert {'wishbone', 'tl-ul'} <= set(SUPPORTED_TARGET_PROTOCOLS)
    assert TARGET_LABELS['wishbone'] == 'Wishbone'
    assert TARGET_LABELS['tl-ul'] == 'TL-UL'


def test_the_new_protocols_are_admitted_in_a_mixed_build():
    assert target_protocol_axis({'wishbone'}) == ('wishbone', False)
    assert target_protocol_axis({'tl-ul'}) == ('tl-ul', False)
    # The two protocols with a run behind them keep the historical mixed axis.
    assert target_protocol_axis({'apb3', 'axi4-lite'}) == (MIXED_TARGET_PROTOCOL, True)
    # This increment admits every supported subset of 2..4 protocols: each
    # target's own trait selects its adapter, trace sample and completion
    # criterion, so a new protocol is no longer a homogeneous-only declaration.
    assert target_protocol_axis({'apb3', 'wishbone'}) == (MIXED_TARGET_PROTOCOL, True)
    assert target_protocol_axis({'tl-ul', 'wishbone'}) == (MIXED_TARGET_PROTOCOL, True)
    assert target_protocol_axis({'apb3', 'tl-ul'}) == (MIXED_TARGET_PROTOCOL, True)
    assert target_protocol_axis({'apb3', 'axi4-lite', 'tl-ul'}) == (
        MIXED_TARGET_PROTOCOL, True)
    # The AHB-Lite target of this increment is part of the supported set, so it
    # mixes like any other; a protocol outside the set is still refused by name.
    assert target_protocol_axis({'apb3', 'ahb-lite'}) == (MIXED_TARGET_PROTOCOL, True)
    with pytest.raises(ValueError) as error:
        target_protocol_axis({'apb3', 'ahb5'})
    assert str(error.value) == 'unsupported-targets:mixed-protocol:ahb5,apb3'


def test_the_profile_protocol_maps_the_two_real_profiles():
    assert profile_protocol(json.loads((ROOT / WB_PROFILE).read_text())) == 'wishbone'
    assert profile_protocol(json.loads((ROOT / TLUL_PROFILE).read_text())) == 'tl-ul'
    # The pinned AHB-Lite target states its own protocol from its own endpoint.
    assert profile_protocol(json.loads((ROOT / AHB_PROFILE).read_text())) == 'ahb-lite'


def test_the_ahb_lite_target_kind_is_admitted_and_its_trace_is_checked():
    artifact = dict(kind=AHB_TARGET_KIND,
                    plan=dict(profile_path=AHB_PROFILE),
                    base_protocol_trace=dict(protocol='ahb-lite', signals={}))
    assert target_protocol(artifact) == 'ahb-lite'
    # A trace that contradicts the kind keeps the named refusal.
    mismatch = dict(artifact, base_protocol_trace=dict(protocol='wishbone', signals={}))
    with pytest.raises(ValueError) as error:
        target_protocol(mismatch)
    assert str(error.value) == ('unsupported-target-trace:ahb_lite_register_observe:'
                                'wishbone')
    # And a kind with no adapter at all keeps its own word.
    with pytest.raises(ValueError) as error:
        target_protocol(dict(kind='tlul_gpio', plan={},
                             base_protocol_trace=dict(protocol='tl-ul', signals={})))
    assert str(error.value) == 'unsupported-target-kind:tlul_gpio'


def test_each_protocol_states_the_trace_roles_a_case_samples():
    assert WB_TRACE_ROLES == ('cyc', 'stb', 'ack', 'we', 'adr', 'dat_w', 'dat_r', 'sel')
    assert TLUL_TRACE_ROLES == ('a_valid', 'a_ready', 'a_opcode', 'a_address',
                                'a_mask', 'a_data', 'd_valid', 'd_ready', 'd_data',
                                'd_error')
    assert PROTOCOL_TRACE_ROLES['wishbone'] == WB_TRACE_ROLES
    assert PROTOCOL_TRACE_ROLES['tl-ul'] == TLUL_TRACE_ROLES


# --- the request the generic target is built from -------------------------

def request_config(profile, fixed=()):
    return dict(source_profile=profile, active_id='generic', source_tuning={},
                source_timing=dict(reset_assert_ticks=2, reset_release_ticks=2,
                                   max_wait_cycles=16),
                source_fixed_inputs=[dict(endpoint_id=endpoint, role=role, value=value)
                                     for endpoint, role, value in fixed])


def test_the_wishbone_request_pins_its_own_template_and_constants():
    request = generic_target_request_from_profile(
        request_config(WB_PROFILE, fixed=(('uart.pins', 'rx', 1),
                                          ('uart.pins', 'cts_n', 0))),
        json.loads((ROOT / WB_PROFILE).read_text()), 'wishbone')
    assert request['schema_version'] == 'local_harness.v2'
    assert request['tuning']['endpoint_policies'] == [dict(
        endpoint_id='uart.bus', template_id='target.wishbone', template_version='1',
        variant_id='word-addressed-registered-ack', max_outstanding=1)]
    assert request['tuning']['fixed_inputs'] == [
        dict(endpoint_id='uart.pins', role='cts_n', value=0),
        dict(endpoint_id='uart.pins', role='rx', value=1)]


def test_the_tlul_request_pins_the_integrity_variant_and_no_constants():
    request = generic_target_request_from_profile(
        request_config(TLUL_PROFILE),
        json.loads((ROOT / TLUL_PROFILE).read_text()), 'tl-ul')
    assert request['tuning']['endpoint_policies'] == [dict(
        endpoint_id='opentitan_rv_timer.mmio', template_id='target.tl-ul',
        template_version='1', variant_id='user-integrity', max_outstanding=1)]
    assert request['tuning']['fixed_inputs'] == []


def test_an_addressless_wishbone_target_is_refused_before_any_rtl():
    """The ziptimer variant has no ``adr`` port, so no case could state it."""
    profile = 'configs/peripherals/zipcpu_timer/component_profile.json'
    with pytest.raises(ValueError) as error:
        generic_target_request_from_profile(
            request_config(profile), json.loads((ROOT / profile).read_text()),
            'wishbone')
    assert str(error.value) == ('unsupported-target-trace:wishbone:addressless:'
                                + profile)


# --- the generated per-target traits --------------------------------------

WB_TRACE_FIELDS = ('CYC', 'STB', 'ACK', 'WE', 'ADR', 'DAT_W', 'DAT_R', 'SEL', 'STALL')
TLUL_TRACE_FIELDS = ('A_VALID', 'A_READY', 'A_OPCODE', 'A_ADDRESS', 'A_MASK',
                     'A_DATA', 'D_VALID', 'D_READY', 'D_DATA', 'D_ERROR')
REQUEST_ROLES = ('IP_REQ_VALID', 'IP_REQ_WRITE', 'IP_REQ_ADDR', 'IP_REQ_WDATA',
                 'IP_REQ_BE', 'IP_REQ_READY', 'IP_RSP_READY', 'IP_RSP_VALID',
                 'IP_RSP_RDATA', 'IP_RSP_ERROR')


def trait_text(rows):
    fields = []
    for protocol in rows:
        item = {role: 'req_' + role.lower() for role in REQUEST_ROLES}
        item['IP_REQ_READY'] = 'req_ready'
        names = {'wishbone': WB_TRACE_FIELDS, 'tl-ul': TLUL_TRACE_FIELDS,
                 'apb3': ('PSEL', 'PENABLE', 'PREADY', 'PWRITE', 'PADDR',
                          'PWDATA', 'PRDATA')}[protocol]
        for name in names:
            item['IP_TRACE_' + name] = 'trace_' + name.lower()
        fields.append(item)
    targets = [dict(index=index, protocol=protocol,
                    window=dict(base=0x40001000 + 0x1000 * index, size=4096),
                    reset_assert=2, reset_release=3, irq=None)
               for index, protocol in enumerate(rows)]
    observed = {row['index']: None for row in targets}
    return '\n'.join(_generated_target_traits(
        targets, fields, [[] for _ in targets], observed, None, lambda value: value))


def test_a_wishbone_target_state_its_own_protocol_and_handshake():
    text = trait_text(['wishbone', 'tl-ul'])
    first, second = text.split('template <> struct IpTarget<1> {')
    assert 'static constexpr bool wishbone = true;' in first
    assert 'static constexpr bool tlul = false;' in first
    assert 'static constexpr const char *protocol = "wishbone";' in first
    assert 'static bool wb_ack(' in first and 'static uint32_t wb_adr(' in first
    assert 'static bool tlul_a_valid(' not in first
    assert 'static bool apb_sel(' not in first
    assert 'static constexpr bool wishbone = false;' in second
    assert 'static constexpr bool tlul = true;' in second
    assert 'static constexpr const char *protocol = "tl-ul";' in second
    assert 'static unsigned tlul_a_opcode(' in second
    assert 'static bool wb_ack(' not in second


# --- the case lines the real runs printed ---------------------------------

WB_CASE0 = (
    'case 0 observations_passed flow F2 record F2:40001004 ticks 87 seconds '
    '0.000118013 i_fetches 41 d_reads 2 d_writes 7 target_reads 1 target_writes 0 '
    'retires 33 rvfi_writebacks 20 rvfi_order_monotonic 1 traps 0 bus_errors 0 '
    'target_transfers 1 wb_acks 1 wb_stb_pulses 1 wb_stalls 0 target_error unknown '
    'target_protocol wishbone read_addr 0x40001004 read_value 0x403f4000 '
    'echo_value 0x403f4000 read_from target target_rdata 0x403f4000 target_offset '
    '0x00000004 target_ready 1 wb_cyc 1 wb_stb 0 wb_ack 1 wb_we 0 wb_adr 1 '
    'wb_dat_w 0x00000000 wb_dat_r 0x403f4000 wb_sel 15 irq_edges 0 irq_takes 0')
WB_CASE1 = (
    'case 1 observations_passed flow F4 record F4:40001000:0000005a ticks 45 seconds '
    '4.54e-05 i_fetches 19 d_reads 3 d_writes 1 target_reads 0 target_writes 1 '
    'retires 15 rvfi_writebacks 7 rvfi_order_monotonic 1 traps 0 bus_errors 0 '
    'target_transfers 1 wb_acks 1 wb_stb_pulses 1 wb_stalls 0 target_error unknown '
    'target_protocol wishbone mmio_addr 0x40001000 mmio_value 0x0000005a '
    'target_offset 0x00000000 target_wdata 0x0000005a target_ready 1 wb_cyc 1 '
    'wb_stb 0 wb_ack 1 wb_we 1 wb_adr 0 wb_dat_w 0x0000005a wb_dat_r 0x0000005a '
    'wb_sel 15 irq_edges 0 irq_takes 0')
TLUL_CASE0 = (
    'case 0 observations_passed flow F2 record F2:40003004 ticks 86 seconds '
    '0.000117879 i_fetches 41 d_reads 2 d_writes 7 target_reads 1 target_writes 0 '
    'retires 33 rvfi_writebacks 20 rvfi_order_monotonic 1 traps 0 bus_errors 0 '
    'target_transfers 1 tlul_a_handshakes 1 tlul_d_handshakes 1 tlul_errors 0 '
    'target_error unknown target_protocol tl-ul read_addr 0x40003004 read_value '
    '0x00000000 echo_value 0x00000000 read_from target target_rdata 0x00000000 '
    'target_offset 0x00000004 target_ready 1 tlul_a_valid 1 tlul_a_ready 1 '
    'tlul_a_opcode 4 tlul_a_address 0x00000004 tlul_a_mask 15 tlul_a_data '
    '0x00000000 tlul_d_valid 1 tlul_d_ready 1 tlul_d_data 0x00000000 tlul_d_error '
    '0 irq_edges 0 irq_takes 0')
TLUL_CASE1 = (
    'case 1 observations_passed flow F4 record F4:40003004:00000001 ticks 44 seconds '
    '4.5738e-05 i_fetches 19 d_reads 3 d_writes 1 target_reads 0 target_writes 1 '
    'retires 15 rvfi_writebacks 7 rvfi_order_monotonic 1 traps 0 bus_errors 0 '
    'target_transfers 1 tlul_a_handshakes 1 tlul_d_handshakes 1 tlul_errors 0 '
    'target_error unknown target_protocol tl-ul mmio_addr 0x40003004 mmio_value '
    '0x00000001 target_offset 0x00000004 target_wdata 0x00000001 target_ready 1 '
    'tlul_a_valid 1 tlul_a_ready 1 tlul_a_opcode 0 tlul_a_address 0x00000004 '
    'tlul_a_mask 15 tlul_a_data 0x00000001 tlul_d_valid 1 tlul_d_ready 1 '
    'tlul_d_data 0xffffffff tlul_d_error 0 irq_edges 0 irq_takes 0')
WB_SUMMARY = (
    'summary observations_passed cases 5 ticks 246 instruction_fetches 111 ram_reads '
    '13 ram_writes 13 target_transfers 4 target_reads 2 target_writes 2 '
    'target_protocols wishbone target0_protocol wishbone target0_bridge '
    'beat_to_wishbone target0_fixed_inputs 2 wb_acks 4 wb_stb_pulses 4 wb_stalls 0 '
    'target_error unknown ip_irq_high_ticks 0 irq_delivery unknown dma not_present '
    'instruction_fetch_evidence observed retirement_evidence observed ifetch_events '
    '111 ifetch_evidence observed retirements 87 rvfi_writebacks 45 '
    'rvfi_order_monotonic 1 rvfi_writeback_evidence observed traps 0 '
    'trap_evidence observed expanded_insn_events 0 expanded_insn_evidence missing '
    'target_errors 0 failures 0 runtime_seconds 0.001646343')
TLUL_SUMMARY = (
    'summary observations_passed cases 6 ticks 277 instruction_fetches 126 ram_reads '
    '15 ram_writes 15 target_transfers 5 target_reads 3 target_writes 2 '
    'target_protocols tl-ul target0_protocol tl-ul target0_bridge beat_to_tlul '
    'target0_fixed_inputs 0 tlul_a_handshakes 5 tlul_d_handshakes 5 tlul_errors 0 '
    'target_error unknown ip_irq_high_ticks 0 irq_delivery unknown dma not_present '
    'instruction_fetch_evidence observed retirement_evidence observed ifetch_events '
    '126 ifetch_evidence observed retirements 98 rvfi_writebacks 50 '
    'rvfi_order_monotonic 1 rvfi_writeback_evidence observed traps 0 '
    'trap_evidence observed expanded_insn_events 0 expanded_insn_evidence missing '
    'target_errors 0 failures 0 runtime_seconds 0.001712606')


def test_the_wishbone_case_line_states_its_protocol_and_handshake():
    case = case_of(WB_CASE0)
    assert case['target_protocol'] == 'wishbone'
    assert case['read_from'] == 'target'
    assert (case['wb_cyc'], case['wb_stb'], case['wb_ack'], case['wb_we']) == (1, 0, 1, 0)
    assert case['wb_adr'] == 1 and case['target_offset'] == 4
    assert case['wb_dat_r'] == 0x403F4000 and case['target_rdata'] == 0x403F4000
    assert case['wb_sel'] == 15
    assert case['wb_acks'] == 1 and case['wb_stb_pulses'] == 1
    # The neutral document reads the same facts under the neutral names.
    document = case_document(record_of('F2:40001004', WB_WINDOWS), case,
                             protocol='wishbone', bus='obi')
    assert document['target']['target_reads'] == 1
    assert document['observation']['wb_ack'] == 1
    assert document['observation']['target_rdata'] == 0x403F4000
    assert document['target_protocol'] == 'wishbone'


def test_the_tlul_case_line_states_its_two_channels():
    case = case_of(TLUL_CASE0)
    assert case['target_protocol'] == 'tl-ul'
    assert (case['tlul_a_valid'], case['tlul_a_ready']) == (1, 1)
    assert case['tlul_a_opcode'] == 4 and case['tlul_a_mask'] == 15
    assert case['tlul_a_address'] == 4 and case['tlul_d_data'] == 0
    assert (case['tlul_d_valid'], case['tlul_d_ready'], case['tlul_d_error']) == (1, 1, 0)
    assert case['tlul_a_handshakes'] == 1 and case['tlul_d_handshakes'] == 1
    document = case_document(record_of('F2:40003004', TLUL_WINDOWS), case,
                             protocol='tl-ul', bus='obi')
    assert document['observation']['tlul_a_opcode'] == 4
    assert document['target_protocol'] == 'tl-ul'


def test_each_protocol_keeps_its_own_case_key_set():
    assert case_observation_keys('F4', 'wishbone') == WB_CASE_OBSERVATION_KEYS['F4']
    assert 'wb_adr' in case_observation_keys('F2', 'wishbone')
    assert 'tlul_a_opcode' not in case_observation_keys('F2', 'wishbone')
    assert case_counter_keys('wishbone') == WB_CASE_COUNTER_KEYS
    assert 'wb_stb_pulses' in case_counter_keys('wishbone')
    assert 'apb_reads' not in case_counter_keys('wishbone')
    assert 'tlul_a_opcode' in case_observation_keys('F4', 'tl-ul')
    assert case_counter_keys('tl-ul') == TLUL_CASE_COUNTER_KEYS
    # The historical tables are untouched.
    assert case_observation_keys('F4', 'apb3') != WB_CASE_OBSERVATION_KEYS['F4']
    assert case_counter_keys('apb3') == CASE_COUNTER_KEYS


def test_the_summary_states_each_targets_protocol_and_bridge():
    wishbone = parse_summary_line(WB_SUMMARY)
    assert wishbone['target_protocols'] == 'wishbone'
    assert wishbone['target0_protocol'] == 'wishbone'
    assert wishbone['target0_bridge'] == 'beat_to_wishbone'
    assert wishbone['target0_fixed_inputs'] == 2
    assert (wishbone['wb_acks'], wishbone['wb_stb_pulses']) == (4, 4)
    assert wishbone['target_transfers'] == 4
    tlul = parse_summary_line(TLUL_SUMMARY)
    assert tlul['target_protocols'] == 'tl-ul'
    assert tlul['target0_bridge'] == 'beat_to_tlul'
    assert tlul['tlul_a_handshakes'] == 5 and tlul['tlul_d_handshakes'] == 5
    assert tlul['tlul_errors'] == 0


# --- the entry credits a case only to the trace it sampled ----------------

def test_correspondence_accepts_the_real_wishbone_case_lines():
    common = dict(layout=WB_LAYOUT, windows=WB_WINDOWS, irq=None, dma=None,
                  protocol='wishbone', irq_base=WB_WINDOWS['ip_base'])
    read = case_of(WB_CASE0)
    assert correspondence(record_of('F2:40001004', WB_WINDOWS), read, **common) is None
    write = case_of(WB_CASE1)
    assert correspondence(record_of('F4:40001000:0000005a', WB_WINDOWS), write,
                          **common) is None


def test_correspondence_accepts_the_real_tlul_case_lines():
    common = dict(layout=TLUL_LAYOUT, windows=TLUL_WINDOWS, irq=None, dma=None,
                  protocol='tl-ul', irq_base=TLUL_WINDOWS['ip_base'])
    read = case_of(TLUL_CASE0)
    assert correspondence(record_of('F2:40003004', TLUL_WINDOWS), read, **common) is None
    write = case_of(TLUL_CASE1)
    assert correspondence(record_of('F4:40003004:00000001', TLUL_WINDOWS), write,
                          **common) is None


def test_a_wishbone_case_with_a_different_handshake_is_refused():
    common = dict(layout=WB_LAYOUT, windows=WB_WINDOWS, irq=None, dma=None,
                  protocol='wishbone', irq_base=WB_WINDOWS['ip_base'])
    read = dict(case_of(WB_CASE0), wb_we=1)
    assert correspondence(record_of('F2:40001004', WB_WINDOWS), read, **common) == (
        'F2 Wishbone read presented the write pin')
    read = dict(case_of(WB_CASE0), wb_dat_r=0)
    assert correspondence(record_of('F2:40001004', WB_WINDOWS), read, **common) == (
        'F2 Wishbone dat_r differs from the word the CPU committed')
    read = dict(case_of(WB_CASE0), wb_adr=2)
    assert correspondence(record_of('F2:40001004', WB_WINDOWS), read, **common) == (
        'F2 Wishbone adr differs from the read address')
    write = dict(case_of(WB_CASE1), wb_sel=7)
    assert correspondence(record_of('F4:40001000:0000005a', WB_WINDOWS), write,
                          **common) == 'F4 Wishbone write strobes are not the full word'
    write = dict(case_of(WB_CASE1), wb_stb_pulses=2)
    assert correspondence(record_of('F4:40001000:0000005a', WB_WINDOWS), write,
                          **common) == (
        'F4 Wishbone write did not present exactly one stb request phase')


def test_a_tlul_case_with_a_different_channel_is_refused():
    common = dict(layout=TLUL_LAYOUT, windows=TLUL_WINDOWS, irq=None, dma=None,
                  protocol='tl-ul', irq_base=TLUL_WINDOWS['ip_base'])
    read = dict(case_of(TLUL_CASE0), tlul_d_error=1)
    assert correspondence(record_of('F2:40003004', TLUL_WINDOWS), read, **common) == (
        'F2 TL-UL read was answered with d_error')
    read = dict(case_of(TLUL_CASE0), tlul_d_data=7)
    assert correspondence(record_of('F2:40003004', TLUL_WINDOWS), read, **common) == (
        'F2 TL-UL d_data differs from the word the CPU committed')
    write = dict(case_of(TLUL_CASE1), tlul_a_mask=3)
    assert correspondence(record_of('F4:40003004:00000001', TLUL_WINDOWS), write,
                          **common) == 'F4 TL-UL a_mask is not the full word'
    write = dict(case_of(TLUL_CASE1), tlul_a_data=7)
    assert correspondence(record_of('F4:40003004:00000001', TLUL_WINDOWS), write,
                          **common) == 'F4 TL-UL a_data differs from the written value'


def test_the_protocol_word_is_checked_against_the_declaration():
    case = dict(case_of(WB_CASE0), target_protocol='apb3')
    assert _target_protocol_mismatch(case, WB_WINDOWS, 'wishbone') == (
        'case target_protocol apb3 differs from the declared target protocol wishbone')
    assert case_target_protocol(case_of(WB_CASE0), WB_WINDOWS, 'wishbone') == 'wishbone'


# --- the named refusals this increment keeps ------------------------------

F5_FACTS = dict(port='o_int', bit=0, trigger='pulse', polarity='active_high',
                pulse_ticks=16, status_offset=0, trigger_offsets=[0, 4],
                status_kind='count', cause_declared=False, cause_bits=[],
                cause_mask=0, clear=None)


def test_an_f5_declaration_on_an_unrun_protocol_is_refused_by_name():
    """TL-UL is admitted after the rv_timer run; a protocol with no F5 run is not."""
    # The TL-UL rv_timer is the first non-APB3 F5 target (runs/p0-1-ip/): the
    # handler's stores and loads go through the target's own protocol adapter,
    # so the gate admits it and the target's own declaration decides the rest.
    assert f5_protocol_check('tl-ul', 'tlultimer', dict(F5_FACTS)) is None
    with pytest.raises(ValueError) as error:
        f5_protocol_check('wishbone', 'wbuart', dict(F5_FACTS))
    assert str(error.value) == (
        'unsupported-f5:target-protocol-not-run:wishbone:wbuart')
    # A target that declares no F5 facts keeps its own, longer-standing refusal.
    assert f5_protocol_check('wishbone', 'wbuart', None) is None


def test_a_dma_route_is_admitted_on_a_wishbone_or_tlul_target():
    """The routed beat rides the target's own adapter, so both wires are admitted.

    A TL-UL or Wishbone target has a real beat adapter and a real passive trace,
    and the host presents the routed beat on exactly that port; APB3 is no longer
    the only executable route protocol.  The named refusal still exists for a
    protocol with no such adapter (runs/p1-dma-route states the refusals).
    """
    assert dma_route_protocol_check('wishbone', 'wbuart') is None
    assert dma_route_protocol_check('tl-ul', 'tlultimer') is None
    with pytest.raises(ValueError) as error:
        dma_route_protocol_check('ahb-lite', 'ahbsha')
    assert str(error.value) == (
        'unsupported-dma-route:target-protocol-not-admitted:ahb-lite:ahbsha')


def test_the_real_run_logs_parse_as_one_batch_each():
    wishbone = parse_run_log((ROOT / 'runs/round3-target-protocols/wb-fixed/run.log'
                              ).read_text(), flows=ARITY)
    assert wishbone['summary']['status'] == 'observations_passed'
    assert [case['status'] for case in wishbone['cases']] == [
        'observations_passed'] * 5
    assert {case['target_protocol'] for case in wishbone['cases']
            if 'target_protocol' in case} == {'wishbone', 'none'}
    tlul = parse_run_log((ROOT / 'runs/round3-target-protocols/tlul-fixed/run.log'
                          ).read_text(), flows=ARITY)
    assert tlul['summary']['status'] == 'observations_passed'
    assert [case['status'] for case in tlul['cases']] == ['observations_passed'] * 6
    assert {case['target_protocol'] for case in tlul['cases']
            if 'target_protocol' in case} == {'tl-ul', 'none'}
