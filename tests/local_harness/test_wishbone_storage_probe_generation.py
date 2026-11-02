"""Pure Wishbone storage probe generation; no native build or live authority."""
import hashlib
import json
import sys
from pathlib import Path

import pytest

from myfuzz.local_harness import (
    load_local_harness_request,
    plan_local_harness,
    render_local_harness,
    render_local_runtime,
    verify_local_source_lock,
)

ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'configs/peripherals/zipcpu_uart_storage/component_profile.json'
SELECTOR = dict(endpoint_id='uart.bus',
                contract_id='zipcpu-wbuart.setup.storage.v1', register='SETUP')
POLICY = dict(endpoint_id='uart.bus', template_id='target.wishbone',
              template_version='1', variant_id='word-addressed-registered-ack',
              max_outstanding=1)
FIXED = [dict(endpoint_id='uart.pins', role='rx', value=1),
         dict(endpoint_id='uart.pins', role='cts_n', value=0)]
PORT_ORDER = ['storage_value', 'storage_reset', 'storage_cyc', 'storage_stb',
              'storage_we', 'storage_adr', 'storage_sel', 'storage_dat_w',
              'storage_ack', 'storage_dat_r', 'storage_stall']
PORT_WIDTHS = dict(storage_value=32, storage_reset=1, storage_cyc=1,
                   storage_stb=1, storage_we=1, storage_adr=2, storage_sel=4,
                   storage_dat_w=32, storage_ack=1, storage_dat_r=32,
                   storage_stall=1)


def request(*, storage=None, tuning=None):
    base = {'endpoint_policies': [dict(POLICY)],
            'fixed_inputs': [dict(row) for row in FIXED]}
    if storage is not None:
        base['wishbone_storage_observations'] = storage
    if tuning is not None:
        base.update(tuning)
    return load_local_harness_request(dict(
        schema_version='local_harness.v2', profile_path=PROFILE,
        instance_id='peripheral', reset_assert_ticks=2, reset_release_ticks=3,
        max_wait_cycles=16, tuning=base))


def artifact(req):
    plan = plan_local_harness(req, base_dir=ROOT)
    return render_local_runtime(
        plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)


@pytest.fixture(scope='module')
def storage_artifact():
    return artifact(request(storage=[dict(SELECTOR)]))


@pytest.fixture(scope='module')
def plain_artifact():
    return artifact(request())


def test_tuning_kind_roundtrip_and_optional_absence():
    from myfuzz.local_harness.tuning import load_local_harness_tuning
    selected = load_local_harness_tuning(
        {'wishbone_storage_observations': [dict(SELECTOR)]})
    assert selected.document()['wishbone_storage_observations'] == [SELECTOR]
    assert 'wishbone_storage_observations' not in load_local_harness_tuning({}).document()


def test_scenario_request_selects_the_reviewed_setup_row():
    scenario = (ROOT / 'configs/scenarios/compiled-f4-obi-wb-uart-setup/requests'
                / 'peripheral.json')
    result = artifact(load_local_harness_request(
        json.loads(scenario.read_text())))
    document = result.runtime_document
    assert document['kind'] == 'wishbone_register_observe'
    assert document['storage_observation']['selection'] == SELECTOR
    assert {row['path'] for row in
            document['selected_template']['executor']['binding']['implementation_sources']
            } >= {'src/myfuzz/local_harness/wishbone_storage_probe_contract.py'}


def test_not_opted_in_has_no_storage_observation(plain_artifact):
    document = plain_artifact.runtime_document
    assert document['kind'] == 'wishbone_register_observe'
    assert 'storage_observation' not in document
    assert 'storage_probe_ports' not in document
    assert not any(row['name'].startswith('storage_')
                   for row in document['runtime_ports'])
    assert 'assign storage_value' not in plain_artifact.runtime_sv
    pins = {row['path'] for row in
            document['selected_template']['executor']['binding']['implementation_sources']}
    assert 'src/myfuzz/local_harness/wishbone_storage_probe_contract.py' not in pins


def test_unused_feature_never_imports_the_probe_contract(monkeypatch, plain_artifact):
    # A missing sibling probe module may only affect an opted-in render.
    monkeypatch.setitem(
        sys.modules, 'myfuzz.local_harness.wishbone_storage_probe_contract', None)
    result = artifact(request())
    assert result.runtime_document['kind'] == 'wishbone_register_observe'
    assert 'storage_observation' not in result.runtime_document


def test_missing_probe_contract_is_a_clear_error_when_requested(monkeypatch):
    monkeypatch.setitem(
        sys.modules, 'myfuzz.local_harness.wishbone_storage_probe_contract', None)
    with pytest.raises(ValueError,
                       match='wishbone-storage-probe-contract-unavailable'):
        artifact(request(storage=[dict(SELECTOR)]))


def test_opted_in_probe_document_and_ports(storage_artifact):
    document = storage_artifact.runtime_document
    assert document['kind'] == 'wishbone_register_observe'
    probe = document['storage_observation']
    assert probe['schema_version'] == 'wishbone_storage_probe.v1'
    assert probe['scope'] == 'generated_expression_source_mapped'
    assert probe['sample_group'] == 'storage_probes'
    assert probe['selection'] == SELECTOR
    assert probe['source_contract']['contract_id'] == SELECTOR['contract_id']
    assert probe['source_contract']['register']['name'] == 'SETUP'
    assert [row['name'] for row in probe['ports']] == PORT_ORDER
    assert {row['name']: row['width'] for row in probe['ports']} == PORT_WIDTHS
    assert probe['ports'][0]['expression'] == \
        "{1'b0, u_component.u_dut.uart_setup}"
    assert probe['ports'][1]['expression'] == 'reset'
    # A renderer-only document never claims hierarchy, native or version
    # authority for the Wishbone row.
    assert all(probe[key] is False for key in (
        'authority', 'hierarchy_verified', 'native_verified',
        'reset_authority', 'source_authority', 'version_authority'))
    body = {key: value for key, value in probe.items() if key != 'digest'}
    assert probe['digest'] == hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(',', ':'),
        allow_nan=False).encode()).hexdigest()
    assert document['storage_probe_ports'] == probe['ports']
    runtime_ports = {row['name']: row for row in document['runtime_ports']}
    assert set(PORT_ORDER) <= set(runtime_ports)
    assert all(runtime_ports[row['name']] ==
               dict(name=row['name'], direction='output', width=row['width'])
               for row in probe['ports'])
    for row in probe['ports']:
        assert storage_artifact.runtime_sv.count(
            f"assign {row['name']} = {row['expression']};") == 1
        assert f"output logic [{row['width']-1}:0] {row['name']}" in \
            storage_artifact.runtime_sv
    # The Wishbone probe is not the APB probe and adds no APB-shaped role.
    assert 'storage_paddr' not in runtime_ports
    assert 'storage_psel' not in runtime_ports
    assert 'apb_storage_probe.v1' not in json.dumps(document)
    trace = document['base_protocol_trace']
    assert trace['protocol'] == 'wishbone'
    assert trace['endpoint_id'] == 'uart.bus'
    assert document['base_event_schema_version'] == 'ip_base_event.v1'
    pins = {row['path'] for row in
            document['selected_template']['executor']['binding']['implementation_sources']}
    assert 'src/myfuzz/local_harness/wishbone_storage_source_contract.py' in pins
    assert 'src/myfuzz/local_harness/wishbone_storage_probe_contract.py' in pins
    assert 'src/myfuzz/local_harness/apb_storage_source_contract.py' not in pins


def test_probe_ports_validate_a_storage_sample(storage_artifact):
    from myfuzz.local_harness.wishbone_storage_probe_contract import (
        validate_wishbone_storage_probe_sample)
    ports = storage_artifact.runtime_document['storage_probe_ports']
    zeros = {'storage_probes': {row['name']: 0 for row in ports}}
    assert validate_wishbone_storage_probe_sample(zeros, ports) == zeros['storage_probes']
    for sample in ({}, {'storage_probes': {}},
                   {'storage_probes': {**zeros['storage_probes'],
                                       'storage_value': True}},
                   {'storage_probes': {**zeros['storage_probes'],
                                       'storage_value': 1 << 32}}):
        with pytest.raises(ValueError):
            validate_wishbone_storage_probe_sample(sample, ports)


def test_probe_digest_tracks_the_embedded_source_contract():
    first = artifact(request(storage=[dict(SELECTOR)]))
    second = artifact(request(storage=[dict(SELECTOR)]))
    assert first.runtime_document['storage_observation']['digest'] == \
        second.runtime_document['storage_observation']['digest']
    changed = json.loads(json.dumps(
        first.runtime_document['storage_observation']))
    changed['source_contract']['decode']['mask'] = 0x1c
    body = {key: value for key, value in changed.items() if key != 'digest'}
    assert changed['digest'] != hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(',', ':'),
        allow_nan=False).encode()).hexdigest()


def test_duplicate_selection_refused_by_tuning():
    with pytest.raises(ValueError):
        request(storage=[dict(SELECTOR), dict(SELECTOR, register='FIFO_STATUS')])


def test_foreign_endpoint_refused():
    record = dict(SELECTOR, endpoint_id='timer.bus')
    with pytest.raises(ValueError,
                       match='wishbone-storage-probe-endpoint-unsupported'):
        artifact(request(storage=[record]))


@pytest.mark.parametrize('override', (
    dict(register='FIFO_STATUS'),
    dict(contract_id='zipcpu-wbuart.fifo.storage.v1'),
    dict(contract_id='unknown.contract.v1'),
))
def test_unknown_register_or_contract_refused_before_generation(override):
    # The closed source row is selected while the probe is generated, so an
    # unknown register/contract can never reach runtime output ports.
    with pytest.raises(ValueError):
        artifact(request(storage=[dict(SELECTOR, **override)]))


def test_apb_storage_tuning_is_not_accepted():
    selector = dict(endpoint_id='uart.bus',
                    contract_id='pulp-apb-timer.ctrl0.source.v1',
                    register='TIMER0_CTRL')
    with pytest.raises(ValueError, match='wishbone-register-unsupported-tuning'):
        artifact(request(tuning={'apb_storage_observations': [selector]}))


def test_apb_request_does_not_accept_wishbone_storage_tuning():
    # The APB policy keeps its own closed tuning set; Wishbone storage is not
    # an APB capability.
    req = load_local_harness_request(dict(
        schema_version='local_harness.v2',
        profile_path='configs/peripherals/pulp_timer/component_profile.json',
        instance_id='timer', reset_assert_ticks=2, reset_release_ticks=2,
        max_wait_cycles=16,
        tuning={'endpoint_policies': [dict(
                    endpoint_id='timer.bus', template_id='target.apb3',
                    template_version='1', variant_id='full-word',
                    max_outstanding=1)],
                'wishbone_storage_observations': [dict(SELECTOR)]}))
    with pytest.raises(ValueError, match='apb3-register-unsupported-tuning'):
        plan_local_harness(req, base_dir=ROOT)
