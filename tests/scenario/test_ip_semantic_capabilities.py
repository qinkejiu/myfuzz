from pathlib import Path

import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.test_capability import load_ip_test_capability
from myfuzz.composition.ip_test_levels import RuntimeCapabilitySnapshot, assess_ip_test_level
from tests.scenario.test_ip_semantic_evidence import consumer, configuration
from tests.scenario.test_gpio_consumption_versions import access
from tests.scenario.test_gpio_register_evidence import read

ROOT = Path(__file__).resolve().parents[2]


def contract(*, width=2, provider='gpio_sync_consumption', version='1', operation='completion'):
    profile = load_component_profile(ROOT/'configs/peripherals/pulp_gpio_causal_local/component_profile.json')
    document = dict(schema_version='ip_test_capability.v2', component_id=profile.component_id,
        profile_fingerprint=profile.profile_fingerprint,
        endpoint_capabilities=[], register_semantics=[dict(register='PADOUT', field='pins',
            lsb=0, width=width, access='rw', read_mask=(1 << width)-1,
            write_mask=(1 << width)-1, reset_value=None, side_effect='none',
            evidence_ref='native:gpio_probe_out')],
        observation_mappings=[dict(mapping_id='sample', endpoint_id='gpio.pins', role='in_sync',
            observation_kind='port_sample', evidence_ref='native:gpio_probe_padin_latch')],
        feature_contract=dict(provider_id=provider, provider_version=version,
            operations=[dict(endpoint_id='gpio.pins', operation=operation,
                required_observation_mappings=['sample'], evidence_ref='manifest:checked')]))
    sidecar = load_ip_test_capability(document, profile=profile)
    runtime = RuntimeCapabilitySnapshot.from_mapping(profile,
        supported_protocols=[('apb', '3')], sidecar=sidecar,
        endpoint_operations={'gpio.bus': [('request', None), ('accept', None), ('response', None),
            ('register_read', 'PADOUT.pins'), ('register_write', 'PADOUT.pins')],
            'gpio.pins': [operation]}, observation_mappings=['sample'])
    return profile, sidecar, runtime


def bind(c, *, field='PADOUT.pins', operation='register_read', width=2):
    profile, sidecar, runtime = contract(width=width)
    c.bind_semantic_capabilities('gpio', profile=profile, sidecar=sidecar,
        runtime_support=runtime, bindings={'out': ('gpio.bus', operation, field)}, base_dir=ROOT)
    return profile, sidecar, runtime


def test_exact_field_observation_produces_existing_verified_snapshot():
    c = consumer()
    profile, sidecar, runtime = bind(c)
    c.ingest([access(), read()])
    snapshot = c.semantic_capability_snapshot('gpio')
    assert snapshot.profile_fingerprint == profile.profile_fingerprint
    assert snapshot.sidecar_fingerprint == sidecar.sidecar_fingerprint
    assert len(snapshot.operations) == 1
    assert snapshot.operations[0].scope == 'PADOUT.pins'
    assessment = assess_ip_test_level(profile, sidecar=sidecar, runtime_support=runtime,
                                     verification=snapshot)
    row = next(r for r in assessment.support_matrix if r.operation == 'register_read')
    assert row.verified
    assert assessment.verified_level is None  # Other required L1 operations remain unverified.


def test_binding_changes_identity_and_freezes_only_before_ingest():
    c = consumer()
    before = c.semantic_evidence_report()['configuration_sha256']
    bind(c)
    assert c.semantic_evidence_report()['configuration_sha256'] != before
    with pytest.raises(ValueError):
        bind(c)
    c = consumer()
    c.ingest([access()])
    with pytest.raises(ValueError):
        bind(c)


def test_runtime_preflight_metadata_participates_in_identity():
    from dataclasses import replace
    c1, c2 = consumer(), consumer()
    profile, sidecar, runtime = contract()
    other = replace(runtime, supported_protocols=runtime.supported_protocols + (('wishbone', 'classic'),))
    for c, preflight in ((c1, runtime), (c2, other)):
        c.bind_semantic_capabilities('gpio', profile=profile, sidecar=sidecar,
            runtime_support=preflight, bindings={'out': ('gpio.bus', 'register_read', 'PADOUT.pins')},
            base_dir=ROOT)
    assert c1.semantic_evidence_report()['configuration_sha256'] != c2.semantic_evidence_report()['configuration_sha256']


@pytest.mark.parametrize('kwargs', [dict(field='PADOUT.wrong'), dict(width=1),
    dict(operation='register_write', width=1), dict(operation='completion')])
def test_wrong_field_slice_or_operation_cannot_bind(kwargs):
    c = consumer()
    with pytest.raises(ValueError):
        bind(c, **kwargs)


def test_missing_raw_versions_and_reset_cannot_create_snapshot_claims():
    c = consumer()
    bind(c)
    assert c.semantic_capability_snapshot('gpio').operations == ()
    c.ingest([access(), read()])
    assert len(c.semantic_capability_snapshot('gpio').operations) == 1
    c.ingest([dict(event_id=3, kind='gpio_reset', component='gpio', reset_epoch=1)])
    assert c.semantic_capability_snapshot('gpio').operations == ()


@pytest.mark.parametrize('offset,old,new', [(16, 0, 3), (20, 3, 0)])
def test_set_clear_only_does_not_certify_direct_register_write(offset, old, new):
    c = consumer()
    bind(c, operation='register_write')
    c.ingest([access(offset=offset, value=3, old=old, new=new), read(value=new)])
    assert c.semantic_evidence_report()['counts']['register_version'] == 1
    assert c.semantic_capability_snapshot('gpio').operations == ()


def test_actual_direct_write_can_certify_write_field():
    c = consumer()
    bind(c, operation='register_write')
    c.ingest([access(value=3, new=3), read(value=3)])
    assert c.semantic_capability_snapshot('gpio').operations[0].operation == 'register_write'


def test_set_writer_still_certifies_actual_direct_read():
    c = consumer()
    bind(c)
    c.ingest([access(offset=16, value=3, new=3), read(value=3)])
    assert c.semantic_capability_snapshot('gpio').operations[0].operation == 'register_read'


def test_journal_conflict_keeps_history_but_removes_capability_claims():
    c = consumer()
    bind(c)
    c.ingest([access(), read()])
    c.ingest([dict(event_id=2, kind='changed')])
    assert c.semantic_evidence_report()['counts']['register_version'] == 1
    assert c.semantic_capability_snapshot('gpio').operations == ()


def test_internal_consumption_is_not_declared_completion_or_external_sample():
    from tests.scenario.test_gpio_sync_evidence import rows
    config = configuration()
    config['completion'] = dict(level='L3', provider='gpio_sync_consumption.v1',
        parameters=dict(component='gpio', bit_lo=0, width=1))
    c = consumer(config)
    profile, sidecar, runtime = contract()
    c.bind_semantic_capabilities('gpio', profile=profile, sidecar=sidecar,
        runtime_support=runtime, bindings={'completion': ('gpio.pins', 'completion')}, base_dir=ROOT)
    c.ingest(rows()[:2])
    assert c.semantic_evidence_report()['counts']['functional_consumption'] == 1
    assert c.semantic_capability_snapshot('gpio').operations == ()
    assert c.semantic_evidence_report()['capability_bindings']['gpio']['gaps']['completion'] == 'evidence-scope-does-not-cover-declared-operation'


def test_wrong_profile_source_identity_is_rejected():
    from dataclasses import replace
    c = consumer()
    p, s, r = contract()
    p = replace(p, description='different profile identity')
    with pytest.raises(ValueError):
        c.bind_semantic_capabilities('gpio', profile=p, sidecar=s, runtime_support=r,
            bindings={'out': ('gpio.bus', 'register_read', 'PADOUT.pins')}, base_dir=ROOT)
