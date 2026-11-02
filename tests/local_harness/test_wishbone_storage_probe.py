"""Closed Wishbone storage probe documents: shape, digest and refusals.

No elaboration, process or native run: every fact here is generated from the
reviewed source row and the pinned profile.
"""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.local_harness import (
    load_local_harness_request, plan_local_harness, render_local_harness,
    render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.tuning import load_local_harness_tuning
from myfuzz.local_harness.wishbone_storage_probe_contract import (
    AUTHORITY_FLAGS, ROLES, SCHEMA_VERSION, SCOPE, SAMPLE_GROUP,
    generate_wishbone_storage_probe, validate_wishbone_storage_probe_sample,
    wishbone_probe_widths, wishbone_storage_probe_digest,
    wishbone_storage_probe_selection)
from myfuzz.local_harness.wishbone_storage_probe_verification import (
    verified_wishbone_storage_observation)
from myfuzz.local_harness.wishbone_storage_source_contract import (
    select_wishbone_storage_source_contract)

ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'configs/peripherals/zipcpu_uart_storage/component_profile.json'
CONTRACT = 'zipcpu-wbuart.setup.storage.v1'
SELECTOR = dict(endpoint_id='uart.bus', contract_id=CONTRACT, register='SETUP')
WIRES = {role: 'wb_' + role for role in ROLES}


def request(*, selector=SELECTOR, profile=PROFILE, endpoint='uart.bus',
            variant='word-addressed-registered-ack'):
    return load_local_harness_request(dict(
        schema_version='local_harness.v2', profile_path=profile,
        instance_id='uart_setup', reset_assert_ticks=2, reset_release_ticks=2,
        max_wait_cycles=16, tuning={
            'endpoint_policies': [dict(endpoint_id=endpoint,
                template_id='target.wishbone', template_version='1',
                variant_id=variant, max_outstanding=1)],
            'wishbone_storage_observations': [dict(selector)],
            'fixed_inputs': [
                dict(endpoint_id='uart.pins', role='rx', value=1),
                dict(endpoint_id='uart.pins', role='cts_n', value=0)]}))


def plan(*, selector=SELECTOR):
    return plan_local_harness(request(selector=selector), base_dir=ROOT)


def artifact(*, selector=SELECTOR):
    value = plan(selector=selector)
    top = render_local_runtime(
        value, render_local_harness(value),
        verify_local_source_lock(value.profile, base_dir=ROOT), base_dir=ROOT)
    return value, top


def unselected_plan():
    document = request()
    document = load_local_harness_request(dict(
        schema_version='local_harness.v2', profile_path=PROFILE,
        instance_id='uart_setup', reset_assert_ticks=2,
        reset_release_ticks=2, max_wait_cycles=16, tuning={
            'endpoint_policies': document.tuning.document()['endpoint_policies'],
            'fixed_inputs': [
                dict(endpoint_id='uart.pins', role='rx', value=1),
                dict(endpoint_id='uart.pins', role='cts_n', value=0)]}))
    return plan_local_harness(document, base_dir=ROOT)


def fake_plan(base, records):
    return SimpleNamespace(
        profile=base.profile, binding=base.binding,
        request=SimpleNamespace(tuning=SimpleNamespace(records=tuple(records))))


def record(row):
    return SimpleNamespace(
        kind='wishbone_storage_observations', document=lambda: dict(row))


def test_optional_selector_roundtrip_and_absent_generation():
    tuned = plan()
    assert wishbone_storage_probe_selection(tuned) == SELECTOR
    probe = generate_wishbone_storage_probe(tuned, WIRES, base_dir=ROOT)
    assert probe is not None
    plain = unselected_plan()
    assert wishbone_storage_probe_selection(plain) is None
    assert generate_wishbone_storage_probe(plain, WIRES, base_dir=ROOT) is None


def test_registered_probe_shape_ports_and_digest():
    value = plan()
    probe = generate_wishbone_storage_probe(value, WIRES, base_dir=ROOT)
    contract = select_wishbone_storage_source_contract(
        value.profile, base_dir=ROOT,
        selection={'contract_id': CONTRACT, 'register': 'SETUP'})
    assert probe['schema_version'] == SCHEMA_VERSION
    assert probe['scope'] == SCOPE
    assert probe['sample_group'] == SAMPLE_GROUP
    assert probe['protocol'] == ['wishbone', 'classic']
    assert probe['address_units'] == 'word'
    assert probe['selection'] == SELECTOR
    assert probe['source_contract'] == contract
    widths = wishbone_probe_widths(contract)
    assert [row['name'] for row in probe['ports']] == [
        'storage_value', 'storage_reset'] + ['storage_' + role for role in ROLES]
    assert [row['width'] for row in probe['ports']] == [
        widths[row['name']] for row in probe['ports']]
    assert widths == {
        'storage_value': 32, 'storage_reset': 1, 'storage_cyc': 1,
        'storage_stb': 1, 'storage_we': 1, 'storage_adr': 2,
        'storage_sel': 4, 'storage_dat_w': 32, 'storage_ack': 1,
        'storage_dat_r': 32, 'storage_stall': 1}
    by_name = {row['name']: row for row in probe['ports']}
    assert by_name['storage_value'] == dict(
        name='storage_value', direction='output', width=32, role='value',
        expression="{1'b0, u_component.u_dut.uart_setup}")
    assert by_name['storage_reset']['expression'] == 'reset'
    assert all(row['direction'] == 'output' for row in probe['ports'])
    for role in ROLES:
        assert by_name['storage_' + role]['role'] == role
        assert by_name['storage_' + role]['expression'] == WIRES[role]
    assert all(probe[flag] is False for flag in AUTHORITY_FLAGS)
    assert probe['digest'] == wishbone_storage_probe_digest(probe)
    payload = {key: deepcopy(value) for key, value in probe.items()
               if key != 'digest'}
    canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'),
                           allow_nan=False)
    assert probe['digest'] == hashlib.sha256(canonical.encode()).hexdigest()
    payload['source_contract']['decode']['mask'] = 0x1
    assert probe['digest'] != wishbone_storage_probe_digest(payload)


def test_wire_map_accepts_exact_width_pairs_and_refuses_others():
    value = plan()
    pairs = {role: ('wb_' + role, wishbone_probe_widths(
        select_wishbone_storage_source_contract(
            value.profile, base_dir=ROOT,
            selection={'contract_id': CONTRACT, 'register': 'SETUP'}))[
                'storage_' + role]) for role in ROLES}
    probe = generate_wishbone_storage_probe(value, pairs, base_dir=ROOT)
    assert [row['expression'] for row in probe['ports'][2:]] == [
        pairs[role][0] for role in ROLES]
    widened = dict(pairs)
    widened['adr'] = ('wb_adr', 32)
    with pytest.raises(ValueError, match='wire-width'):
        generate_wishbone_storage_probe(value, widened, base_dir=ROOT)
    for broken in (
            {role: WIRES[role] for role in ROLES if role != 'stall'},
            dict(WIRES, err='wb_err'),
            dict(WIRES, adr=''),
            dict(WIRES, sel=True),
            dict(WIRES, cyc=(7, 1))):
        with pytest.raises(ValueError):
            generate_wishbone_storage_probe(value, broken, base_dir=ROOT)


def test_sample_validator_shape_only():
    probe = generate_wishbone_storage_probe(plan(), WIRES, base_dir=ROOT)
    ports = probe['ports']
    good = {'storage_' + role: 0 for role in
            ('value', 'reset', 'cyc', 'stb', 'we', 'ack', 'stall')}
    good.update(storage_adr=0, storage_sel=15, storage_dat_w=0x55,
                storage_dat_r=0x55)
    assert validate_wishbone_storage_probe_sample(
        {'storage_probes': good}, ports) == good
    for broken in (
            {}, {'storage_probes': {}},
            {'storage_probes': dict(good, storage_value=True)},
            {'storage_probes': dict(good, storage_value=1 << 32)},
            {'storage_probes': dict(good, storage_adr=4)},
            {'storage_probes': dict(good, extra=0)},
            {'storage_probes': {k: v for k, v in good.items()
                                if k != 'storage_stall'}}):
        with pytest.raises(ValueError):
            validate_wishbone_storage_probe_sample(broken, ports)


@pytest.mark.parametrize('override', [
    dict(endpoint_id='foreign.bus'), dict(contract_id='unknown'),
    dict(register='RXREG'), dict(register='FIFO_STATUS'),
    dict(register='TXREG'), dict(register='COUNT')])
def test_unknown_or_foreign_selection_refused_before_generation(override):
    with pytest.raises(ValueError):
        # Planning may refuse an endpoint id first; generation must never emit
        # a port set for an unregistered contract or register.
        generate_wishbone_storage_probe(
            plan(selector={**SELECTOR, **override}), WIRES, base_dir=ROOT)


@pytest.mark.parametrize('row', [
    dict(SELECTOR, expression='fabricated'),
    {'endpoint_id': 'uart.bus', 'contract_id': CONTRACT},
    {'endpoint_id': 'uart.bus', 'contract_id': CONTRACT, 'register': 'SETUP',
     'evidence_ref': 'caller'},
    {'endpoint_id': 7, 'contract_id': CONTRACT, 'register': 'SETUP'}])
def test_malformed_selection_row_refused(row):
    base = unselected_plan()
    broken = fake_plan(base, [record(row)])
    with pytest.raises(ValueError):
        wishbone_storage_probe_selection(broken)
    with pytest.raises(ValueError):
        generate_wishbone_storage_probe(broken, WIRES, base_dir=ROOT)


def test_duplicate_selection_rows_refused():
    base = unselected_plan()
    twin = record(dict(SELECTOR))
    with pytest.raises(ValueError, match='selection-unsupported'):
        wishbone_storage_probe_selection(fake_plan(base, [twin, record(
            dict(SELECTOR, endpoint_id='uart.pins'))]))


def test_non_wishbone_endpoint_refused():
    timer = load_component_profile(
        ROOT / 'configs/peripherals/pulp_timer/component_profile.json')
    document = load_local_harness_request(dict(
        schema_version='local_harness.v2',
        profile_path='configs/peripherals/pulp_timer/component_profile.json',
        instance_id='timer', reset_assert_ticks=2, reset_release_ticks=2,
        max_wait_cycles=16, tuning={'endpoint_policies': [dict(
            endpoint_id='timer.bus', template_id='target.apb3',
            template_version='1', variant_id='full-word',
            max_outstanding=1)]}))
    base = plan_local_harness(document, base_dir=ROOT)
    apb = fake_plan(base, [record(dict(endpoint_id='timer.bus',
        contract_id='pulp-apb-timer.ctrl0.source.v1', register='TIMER0_CTRL'))])
    with pytest.raises(ValueError, match='endpoint-unsupported'):
        wishbone_storage_probe_selection(apb)
    wrong_id = fake_plan(base, [record(dict(SELECTOR))])
    with pytest.raises(ValueError, match='endpoint-unsupported'):
        wishbone_storage_probe_selection(wrong_id)
    assert timer.source.top_module == 'apb_timer'


def test_renderer_emits_probe_bytes_and_pins():
    _, top = artifact()
    document = top.runtime_document
    probe = document['storage_observation']
    assert document['kind'] == 'wishbone_register_observe'
    assert probe['schema_version'] == SCHEMA_VERSION
    assert document['storage_probe_ports'] == probe['ports']
    assert all(probe[flag] is False for flag in AUTHORITY_FLAGS)
    for row in probe['ports']:
        assert f"assign {row['name']} = {row['expression']};" in top.runtime_sv
        assert dict(name=row['name'], direction='output', width=row['width']) \
            in document['runtime_ports']
    trace = document['base_protocol_trace']
    assert trace['protocol'] == 'wishbone'
    assert trace['endpoint_id'] == 'uart.bus'
    assert set(trace['signals']) == set(ROLES)
    assert trace['signal_widths'] == {
        role: wishbone_probe_widths(probe['source_contract'])[
            'storage_' + role] for role in ROLES}
    assert verified_wishbone_storage_observation(
        probe, top, base_dir=ROOT) is None
    pins = {row['path'] for row in document['selected_template']['executor'][
        'binding']['implementation_sources']}
    assert 'src/myfuzz/local_harness/wishbone_storage_source_contract.py' in pins
    assert 'src/myfuzz/local_harness/wishbone_storage_probe_contract.py' in pins


def tampered_artifact(probe, top, mutate):
    document = deepcopy(top.runtime_document)
    observation = deepcopy(probe)
    mutate(observation, document)
    observation['digest'] = wishbone_storage_probe_digest(observation)
    document['storage_observation'] = observation
    document['storage_probe_ports'] = observation.get('ports')
    return observation, replace(top, runtime_document=document)


@pytest.mark.parametrize('mutation', (
    'value_expression', 'port_width', 'flag', 'evidence', 'selection_register',
    'selection_endpoint', 'contract_mask', 'contract_register', 'trace_protocol',
    'trace_role', 'trace_width', 'artifact_kind'))
def test_probe_or_trace_tamper_refused(mutation):
    _, top = artifact()
    probe = top.runtime_document['storage_observation']

    def mutate(observation, document):
        if mutation == 'value_expression':
            observation['ports'][0]['expression'] = '1\'b0'
        elif mutation == 'port_width':
            observation['ports'][1]['width'] = 2
        elif mutation == 'flag':
            observation['native_verified'] = True
        elif mutation == 'evidence':
            observation['hierarchy_evidence'] = {'reference': 'caller'}
        elif mutation == 'selection_register':
            observation['selection']['register'] = 'RXREG'
        elif mutation == 'selection_endpoint':
            observation['selection']['endpoint_id'] = 'other.bus'
        elif mutation == 'contract_mask':
            observation['source_contract']['decode']['mask'] = 0x1
        elif mutation == 'contract_register':
            observation['source_contract']['register']['name'] = 'SETUP2'
        elif mutation == 'trace_protocol':
            document['base_protocol_trace']['protocol'] = 'apb3'
        elif mutation == 'trace_role':
            document['base_protocol_trace']['signals']['err'] = 'trace_err'
        elif mutation == 'trace_width':
            document['base_protocol_trace']['signal_widths']['adr'] = 32
        else:
            document['kind'] = 'apb3_register_observe'

    observation, mutated = tampered_artifact(probe, top, mutate)
    with pytest.raises(ValueError):
        verified_wishbone_storage_observation(
            observation, mutated, base_dir=ROOT)


def test_probe_digest_port_or_contract_tamper_caught_by_digest():
    _, top = artifact()
    probe = top.runtime_document['storage_observation']
    for mutation in ('port', 'contract', 'outer'):
        observation = deepcopy(probe)
        if mutation == 'port':
            observation['ports'][0]['expression'] = '1\'b0'
        elif mutation == 'contract':
            observation['source_contract']['decode']['value'] = 1
        else:
            observation['digest'] = '0' * 64
        with pytest.raises(ValueError, match='digest-mismatch'):
            verified_wishbone_storage_observation(
                {**observation}, replace(top, runtime_document={
                    **top.runtime_document,
                    'storage_observation': observation,
                    'storage_probe_ports': observation['ports']}),
                base_dir=ROOT)


def test_probe_from_a_foreign_artifact_refused():
    _, uart = artifact()
    probe = uart.runtime_document['storage_observation']
    document = load_local_harness_request(dict(
        schema_version='local_harness.v2',
        profile_path='configs/peripherals/zipcpu_timer/component_profile.json',
        instance_id='timer', reset_assert_ticks=2, reset_release_ticks=2,
        max_wait_cycles=16, tuning={'endpoint_policies': [dict(
            endpoint_id='timer.bus', template_id='target.wishbone',
            template_version='1', variant_id='addressless-select-ignored',
            max_outstanding=1)]}))
    value = plan_local_harness(document, base_dir=ROOT)
    timer = render_local_runtime(
        value, render_local_harness(value),
        verify_local_source_lock(value.profile, base_dir=ROOT), base_dir=ROOT)
    with pytest.raises(ValueError):
        verified_wishbone_storage_observation(probe, timer, base_dir=ROOT)
    forged = replace(uart, runtime_document={**uart.runtime_document,
                                             'kind': 'apb3_register_observe'})
    with pytest.raises(ValueError, match='artifact-required'):
        verified_wishbone_storage_observation(probe, forged, base_dir=ROOT)
    with pytest.raises(ValueError, match='artifact-required'):
        verified_wishbone_storage_observation(probe, {}, base_dir=ROOT)
