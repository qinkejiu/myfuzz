"""AHB-Lite MMIO target adapter in the unified in-process entry (pure Python).

The unified entry and its C++ host now drive a real AHB-Lite *target* beside the
APB3, AXI4-Lite, Wishbone and TL-UL targets they already drove.  The adapter is
derived from the declaration, not from a component name: the profile's own
``mmio_slave`` endpoint protocol selects the pinned ``target.ahb-lite/1``
full-word template, the generated model binds the target kernel to its own
``ahb_lite_mmio_target`` manager, and the host samples the slave port's own two
phases from the artifact's ten role taps.

These tests cover the declaration axis, the request the target is built from,
the generated per-target traits, the case-line keys and criterion words, the
named refusals that stay refusals (F5 without a declared IRQ contract, a routed
DMA beat on a protocol the route admission does not list), and the two host
facts that make the case line honest: both AHB phases are sampled, and no
CPU x IP branch exists on either side.

Nothing here builds a Verilator model or claims a run.  The real runs are in
``runs/p2-ahb-target-20261103/``; the parser tests below read that evidence when
it is present so the host's own text is what is parsed.
"""
import json
import os
import re
from pathlib import Path

import pytest

from scripts.run_inprocess_f1f6 import (
    AHB_TARGET_CASE_COUNTER_KEYS, AHB_TARGET_CASE_TRACE_KEYS, AHB_TARGET_KIND,
    AHB_TRACE_ROLES, CASE_COUNTER_KEYS, DMA_ROUTE_PROTOCOL_REFUSAL, DMA_ROUTE_PROTOCOLS,
    F5_TARGET_PROTOCOL_REFUSAL, F5_TARGET_PROTOCOLS, MIXED_TARGET_PROTOCOL,
    MIXED_TARGET_PROTOCOL_MAX, PROFILE_PROTOCOLS, PROTOCOL_TRACE_ROLES,
    SUPPORTED_TARGET_PROTOCOLS, TARGET_BRIDGES, TARGET_ERROR_RESPONSES, TARGET_LABELS,
    TARGET_PROTOCOLS, TARGET_TRANSFER_CRITERIA, _generated_target_traits,
    ahb_target_request_from_profile, case_counter_keys, case_observation_keys,
    dma_route_protocol_check, f5_declaration, f5_protocol_check, flow_arity,
    mixed_case_counter_keys, mixed_case_observation_keys, mixed_target_bridge,
    mixed_target_criterion, ordered_target_protocols, parse_run_log,
    profile_protocol, target_protocol, target_protocol_axis,
)

ROOT = Path(__file__).resolve().parents[2]
AHB_PROFILE = 'configs/peripherals/caliptra_sha256/component_profile.json'
AHB_SCENARIO = ROOT / 'configs/scenarios/inprocess-obi-ahb-sha256-f1f4.json'
MIXED_SCENARIO = (ROOT / 'configs/scenarios/'
                  'inprocess-obi-apb3-ahb-tlul-three-protocol-f1f4.json')
EVIDENCE = ROOT / 'runs/p2-ahb-target-20261103'
ARITY = flow_arity(None, None)
HOST = ROOT / 'scripts/inprocess_obi_apb_f1f4_spike.cpp'
RTL = ROOT / 'src/myfuzz/protocols/rtl/ahb_lite_mmio_target.sv'


def ahb_profile():
    return json.loads((ROOT / AHB_PROFILE).read_text())


# --- the declaration axis -------------------------------------------------

def test_ahb_lite_is_a_supported_target_protocol():
    assert 'ahb-lite' in SUPPORTED_TARGET_PROTOCOLS
    # The supported set is still the only source of a protocol word, and the
    # mixed bound follows it, so 2..5 declared protocols are one build.
    assert MIXED_TARGET_PROTOCOL_MAX == len(SUPPORTED_TARGET_PROTOCOLS) == 5
    assert TARGET_PROTOCOLS[AHB_TARGET_KIND] == 'ahb-lite'
    assert PROFILE_PROTOCOLS[('ahb-lite', '1')] == 'ahb-lite'
    assert TARGET_BRIDGES['ahb-lite'] == 'ahb_lite_mmio_target'
    assert TARGET_LABELS['ahb-lite'] == 'AHB-Lite'


def test_the_ahb_trace_roles_are_the_ten_declared_slave_pins():
    assert AHB_TRACE_ROLES == ('hsel', 'htrans', 'haddr', 'hwrite', 'hsize',
                               'hwdata', 'hreadyin', 'hreadyout', 'hrdata', 'hresp')
    assert PROTOCOL_TRACE_ROLES['ahb-lite'] == AHB_TRACE_ROLES


def test_the_profile_protocol_and_the_artifact_kind_agree():
    assert profile_protocol(ahb_profile()) == 'ahb-lite'
    artifact = dict(kind=AHB_TARGET_KIND,
                    plan=dict(profile_path=AHB_PROFILE),
                    base_protocol_trace=dict(protocol='ahb-lite', signals={}))
    assert target_protocol(artifact) == 'ahb-lite'


def test_a_contradicting_trace_is_still_refused_by_name():
    # The adapter is selected by the artifact's own kind, and a trace that does
    # not state that protocol is refused instead of being driven through the
    # other criterion.
    artefact = dict(kind=AHB_TARGET_KIND, plan=dict(profile_path=AHB_PROFILE),
                    base_protocol_trace=dict(protocol='apb3', signals={}))
    with pytest.raises(ValueError) as error:
        target_protocol(artefact)
    assert str(error.value) == ('unsupported-target-trace:ahb_lite_register_observe:'
                                'apb3')


def test_a_mixed_build_may_declare_the_ahb_target_with_any_other_protocol():
    assert target_protocol_axis({'ahb-lite'}) == ('ahb-lite', False)
    assert target_protocol_axis({'apb3', 'ahb-lite'}) == (MIXED_TARGET_PROTOCOL, True)
    assert target_protocol_axis({'ahb-lite', 'tl-ul'}) == (MIXED_TARGET_PROTOCOL, True)
    assert target_protocol_axis({'apb3', 'wishbone', 'ahb-lite'}) == (
        MIXED_TARGET_PROTOCOL, True)
    assert target_protocol_axis(set(SUPPORTED_TARGET_PROTOCOLS)) == (
        MIXED_TARGET_PROTOCOL, True)
    # A protocol outside the supported set keeps the historical refusal.
    with pytest.raises(ValueError) as error:
        target_protocol_axis({'apb3', 'ahb5'})
    assert str(error.value) == 'unsupported-targets:mixed-protocol:ahb5,apb3'


def test_the_canonical_order_keeps_every_existing_build_word_and_puts_ahb_last():
    # The AHB target was added at the end of SUPPORTED_TARGET_PROTOCOLS, so every
    # word a build that existed before this increment printed is unchanged.
    assert ordered_target_protocols({'apb3', 'axi4-lite'}) == ['apb3', 'axi4-lite']
    assert ordered_target_protocols({'ahb-lite', 'apb3', 'tl-ul'}) == [
        'apb3', 'tl-ul', 'ahb-lite']
    assert mixed_target_bridge({'apb3', 'ahb-lite'}) == (
        'mixed:apb3_mmio_bridge+ahb_lite_mmio_target')


# --- the request the target is built from ---------------------------------

def request_config(profile):
    return dict(source_profile=profile, active_id='sha', source_tuning={},
                source_timing=dict(reset_assert_ticks=2, reset_release_ticks=3,
                                   max_wait_cycles=16),
                source_fixed_inputs=[])


def test_the_ahb_request_pins_its_own_template_and_no_constants():
    request = ahb_target_request_from_profile(request_config(AHB_PROFILE),
                                             ahb_profile())
    assert request['schema_version'] == 'local_harness.v2'
    assert request['profile_path'] == AHB_PROFILE
    assert request['tuning']['endpoint_policies'] == [dict(
        endpoint_id='sha256.bus', template_id='target.ahb-lite', template_version='1',
        variant_id='full-word-single', max_outstanding=1)]
    assert request['tuning']['fixed_inputs'] == []
    assert request['reset_assert_ticks'] == 2


def test_a_profile_without_an_ahb_slave_is_refused_before_any_rtl():
    profile = 'configs/peripherals/opentitan_rv_timer_local/component_profile.json'
    with pytest.raises(ValueError) as error:
        ahb_target_request_from_profile(
            request_config(profile), json.loads((ROOT / profile).read_text()))
    assert str(error.value) == ('unsupported: source_profile requires exactly one '
                                'AHB-Lite MMIO slave endpoint')


# --- the generated per-target traits --------------------------------------

AHB_TRACE_FIELDS = ('HSEL', 'HTRANS', 'HADDR', 'HWRITE', 'HSIZE', 'HWDATA',
                    'HREADYIN', 'HREADYOUT', 'HRDATA', 'HRESP')
REQUEST_ROLES = ('IP_REQ_VALID', 'IP_REQ_WRITE', 'IP_REQ_ADDR', 'IP_REQ_WDATA',
                 'IP_REQ_BE', 'IP_REQ_READY', 'IP_RSP_READY', 'IP_RSP_VALID',
                 'IP_RSP_RDATA', 'IP_RSP_ERROR')


def trait_text(rows):
    fields = []
    for protocol in rows:
        item = {role: 'req_' + role.lower() for role in REQUEST_ROLES}
        names = {'ahb-lite': AHB_TRACE_FIELDS,
                 'apb3': ('PSEL', 'PENABLE', 'PREADY', 'PWRITE', 'PADDR',
                          'PWDATA', 'PRDATA')}[protocol]
        for name in names:
            item['IP_TRACE_' + name] = 'trace_' + name.lower()
        fields.append(item)
    targets = [dict(index=index, protocol=protocol,
                    window=dict(base=0x40000000 + 0x1000 * index, size=4096),
                    reset_assert=2, reset_release=3, irq=None)
               for index, protocol in enumerate(rows)]
    observed = {row['index']: None for row in targets}
    return '\n'.join(_generated_target_traits(
        targets, fields, [[] for _ in targets], observed, None, lambda value: value))


def test_a_generated_ahb_target_trait_states_its_own_protocol_and_phases():
    text = trait_text(['apb3', 'ahb-lite'])
    first, second = text.split('template <> struct IpTarget<1> {')
    # The APB3 target is untouched: same protocol word, its own accessors, and
    # no AHB accessor leaked into it.
    assert 'static constexpr bool apb = true;' in first
    assert 'static constexpr bool ahb = false;' in first
    assert 'static bool apb_sel(' in first
    assert 'static bool ahb_hsel(' not in first
    # The AHB-Lite target carries its own protocol and both phase faces.
    assert 'static constexpr bool apb = false;' in second
    assert 'static constexpr bool ahb = true;' in second
    assert 'static constexpr const char *protocol = "ahb-lite";' in second
    for role in ('hsel', 'htrans', 'haddr', 'hwrite', 'hsize', 'hwdata',
                 'hreadyin', 'hreadyout', 'hrdata', 'hresp'):
        assert 'static ' in second and 'ahb_%s(' % role in second
    assert 'static bool apb_sel(' not in second


# --- the case line and the criterion word ---------------------------------

def test_the_ahb_case_line_states_both_phases_and_its_own_error_word():
    counters = case_counter_keys('ahb-lite')
    assert counters == AHB_TARGET_CASE_COUNTER_KEYS
    for key in ('ahb_address_phases', 'ahb_data_phases', 'ahb_error',
                'target_reads', 'target_writes', 'target_transfers'):
        assert key in counters
    # The historical APB3 spellings never appear on an AHB case line.
    assert 'apb_reads' not in counters and 'apb_writes' not in counters
    for flow in ('F2', 'F4'):
        keys = case_observation_keys(flow, 'ahb-lite')
        for key in AHB_TARGET_CASE_TRACE_KEYS:
            assert key in keys
    # The completion criterion is the two phases, not one handshake.
    assert TARGET_TRANSFER_CRITERIA['ahb-lite'] == (
        'hsel_and_htrans_address_phase_then_hreadyout_data_phase')
    assert 'mixed' not in TARGET_ERROR_RESPONSES['ahb-lite']
    assert TARGET_ERROR_RESPONSES['ahb-lite'].startswith('unknown:')


def test_a_mixed_build_adds_the_ahb_keys_only_when_ahb_is_declared():
    apb = set(mixed_case_observation_keys('F2', {'apb3'}))
    ahb = set(mixed_case_observation_keys('F2', {'apb3', 'ahb-lite'}))
    assert 'ahb_haddr' not in apb and 'ahb_haddr' in ahb
    counts = mixed_case_counter_keys({'apb3'})
    assert 'ahb_address_phases' not in counts
    counts = mixed_case_counter_keys({'apb3', 'ahb-lite'})
    assert 'ahb_address_phases' in counts and 'ahb_data_phases' in counts
    assert 'ahb_error' in counts
    assert mixed_target_criterion({'apb3', 'ahb-lite'}).endswith(
        'ahb-lite=hsel_and_htrans_address_phase_then_hreadyout_data_phase')


# --- what stays refused ---------------------------------------------------

def test_f5_is_refused_by_name_because_the_profile_grants_no_irq_contract():
    # The pinned profile states that error/notification outputs are passive
    # observations and grants no IRQ trigger/capture contract; the declaration
    # carries none of the four F5 facts and the refusal names them.
    irq, refusal = f5_declaration({}, None, 'ahb-lite')
    assert irq is None
    assert refusal == ('unsupported-f5:target-irq-semantics:ahb-lite:'
                       'source_port,source_bit_offset,trigger_writes,status_offsets')
    assert 'ahb-lite' not in F5_TARGET_PROTOCOLS


def test_a_declared_f5_on_an_untested_protocol_keeps_its_own_refusal():
    # Even a declaration that carried the four facts would not be given an F5
    # path this increment never ran: the protocol gate names it.
    with pytest.raises(ValueError) as error:
        f5_protocol_check('ahb-lite', 'sha', dict(port='error_intr'))
    assert str(error.value) == (F5_TARGET_PROTOCOL_REFUSAL + 'ahb-lite:sha')


def test_a_routed_dma_beat_on_the_ahb_target_is_refused_by_name():
    # The route admission lists the protocols whose artifact binds the generic
    # beat port; ahb-lite is not in it, so the declaration is refused instead of
    # being driven through another protocol's completion.
    assert 'ahb-lite' not in DMA_ROUTE_PROTOCOLS
    with pytest.raises(ValueError) as error:
        dma_route_protocol_check('ahb-lite', 'sha')
    assert str(error.value) == (DMA_ROUTE_PROTOCOL_REFUSAL + 'ahb-lite:sha')


# --- the host and the adapter RTL ----------------------------------------

def test_the_host_samples_both_phases_from_the_targets_own_pins():
    text = HOST.read_text()
    assert '#if TARGET_HAS_AHB' in text
    block = text.split('#if TARGET_HAS_AHB', 1)[1].split('#endif  // TARGET_HAS_AHB')[0]
    # The sample is the routed target's own trait, selected per target, and the
    # two phases are counted where the target completes them.
    assert 'if constexpr (!myfuzz_ip::IpTarget<index>::ahb)' in block
    assert 'myfuzz_ip::IpTarget<index>::ahb_hsel(model)' in block
    assert 'myfuzz_ip::IpTarget<index>::ahb_haddr(model)' in block
    assert 'myfuzz_ip::IpTarget<index>::ahb_hreadyin(model)' in block
    assert 'myfuzz_ip::IpTarget<index>::ahb_hreadyout(model)' in block
    assert 'myfuzz_ip::IpTarget<index>::ahb_hrdata(model)' in block
    assert '++observation.ahb_address_phases;' in block
    assert '++observation.ahb_data_phases;' in block
    # Both flows require one accepted address phase and one completed data phase.
    assert text.count('observation.ahb_address_phases == 1') == 2
    assert text.count('observation.ahb_data_phases == 1') == 2
    # The error contract is unknown, never a clean bus, and the sampled HRESP pin
    # is printed as the pin it is.
    assert 'ahb_error unknown' in text
    assert '" ahb_hresp "' in text
    # No CPU x IP branch and no device name in the code: the target is selected
    # by its protocol trait.  Comments may cite the pinned RTL as the source of a
    # fact, so only non-comment lines are checked.
    code = '\n'.join(line.split('//')[0] if '"' not in line.split('//')[0] else line
                      for line in text.splitlines())
    assert not re.search(r'sha256|caliptra', code, re.IGNORECASE)


def test_the_host_prints_the_ahb_group_only_for_the_routed_ahb_target():
    text = HOST.read_text()
    group = text.split('#if TARGET_HAS_AHB', 2)[2]
    assert 'ip_is_ahb(observation.target_index)' in group
    assert 'ahb_haddr' in group and 'ahb_hresp' in group


def test_the_adapter_rtl_drives_a_real_two_phase_ahb_manager():
    text = RTL.read_text()
    # The adapter state machine: address phase accepted on HREADYOUT, then a
    # separate data phase, and the response only in RESPONSE.
    assert 'typedef enum logic [1:0] {IDLE, ADDRESS, DATA, RESPONSE} state_t;' in text
    assert 'assign hsel = rst_ni && state_q == ADDRESS;' in text
    assert 'assign htrans = hsel ? 2\'b10 : 2\'b00;' in text
    assert 'assign hsize = 3\'b010;' in text
    assert 'assign hreadyin = hreadyout;' in text
    assert 'rsp_rdata_o <= hrdata;' in text and 'rsp_error_o <= hresp;' in text


# --- the declaration and profile the real runs used -----------------------

def test_the_declared_scenarios_route_to_the_ahb_target():
    from myfuzz.composition.multi_target import declared_targets
    single = declared_targets(json.loads(AHB_SCENARIO.read_text()))
    assert len(single) == 1 and single[0]['profile'] == AHB_PROFILE
    mixed = declared_targets(json.loads(MIXED_SCENARIO.read_text()))
    assert [row['name'] for row in mixed] == ['timer', 'sha', 'tlultimer']
    protocols = [profile_protocol(json.loads((ROOT / row['profile']).read_text()))
                 for row in mixed]
    assert protocols == ['apb3', 'ahb-lite', 'tl-ul']


@pytest.mark.skipif(not (EVIDENCE / 'mixed-three-protocol/run.log').is_file(),
                    reason='the real AHB evidence package is not present')
def test_the_real_mixed_session_parses_and_names_each_routed_protocol():
    document = parse_run_log(
        (EVIDENCE / 'mixed-three-protocol/run.log').read_text(), flows=ARITY)
    assert document['summary']['status'] == 'observations_passed'
    assert document['summary']['target_protocols'] == 'apb3,ahb-lite,tl-ul'
    assert [case['status'] for case in document['cases']] == [
        'observations_passed'] * len(document['cases'])
    routed = [case.get('target_protocol') for case in document['cases']]
    assert routed == ['apb3', 'apb3', 'ahb-lite', 'ahb-lite', 'ahb-lite',
                      'tl-ul', 'tl-ul', 'tl-ul', 'none']
    ahb_cases = [case for case in document['cases']
                 if case.get('target_protocol') == 'ahb-lite']
    assert [case['flow'] for case in ahb_cases] == ['F2', 'F4', 'F2']
    for case in ahb_cases:
        assert case['ahb_address_phases'] == 1 and case['ahb_data_phases'] == 1
        assert case['ahb_htrans'] == 2 and case['ahb_hsize'] == 2
        assert case['target_error'] == 'unknown' and case['ahb_error'] == 'unknown'
    # A case routed to another target did not sample this slave's pins.
    for case in document['cases']:
        if case.get('target_protocol') != 'ahb-lite':
            assert case['ahb_address_phases'] == 0
            assert case['ahb_data_phases'] == 0


@pytest.mark.skipif(not (EVIDENCE / 'known-answer/run.log').is_file(),
                    reason='the real AHB known-answer evidence is not present')
def test_the_real_known_answer_run_read_back_the_pinned_digest():
    import hashlib
    document = parse_run_log(
        (EVIDENCE / 'known-answer/run.log').read_text(), flows=ARITY)
    cases = document['cases']
    assert document['summary']['status'] == 'observations_passed'
    assert len(cases) == 67
    values = [case.get('read_value') for case in cases]
    assert values[0] == 0x61327368 and values[1] == 0x35362d32
    assert values[2] == 0x3830312e
    # STATUS is ready at reset, not ready while the block is being hashed, and
    # READY|VALID once the pinned core finished.
    assert values[20] == 0 and values[22] == 3
    assert values[34] == 0  # BLOCK is write-only, as the profile says
    first = b''.join(values[26 + index].to_bytes(4, 'big') for index in range(8))
    second = b''.join(values[58 + index].to_bytes(4, 'big') for index in range(8))
    assert first == hashlib.sha256(b'abc').digest()
    assert second == hashlib.sha256(b'abd').digest()
    assert first != second
    for case in (cases[index] for index in range(26, 34)):
        assert case['target_protocol'] == 'ahb-lite'
        assert case['ahb_address_phases'] == 1 and case['ahb_data_phases'] == 1
