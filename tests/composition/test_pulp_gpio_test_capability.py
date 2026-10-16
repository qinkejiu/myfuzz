"""Pinned GPIO data declarations; no executor or DUT verification claims."""
import hashlib
import json
from pathlib import Path

import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.test_capability import load_ip_test_capability, plan_register_operation
from myfuzz.composition.ip_test_levels import assess_ip_test_level

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / 'configs/peripherals/pulp_gpio/component_profile.json'
SIDECAR = PROFILE.with_name('test_capability.json')
SOURCE = ROOT / 'third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv'


def loaded():
    profile = load_component_profile(PROFILE)
    return profile, load_ip_test_capability(SIDECAR, profile=profile)


def test_real_sidecar_loads_exact_fields_and_masks():
    profile, sidecar = loaded()
    assert sidecar.profile_fingerprint == profile.profile_fingerprint
    assert sidecar.feature_contract is None
    assert [(f.register, f.field, f.lsb, f.width, f.read_mask, f.write_mask, f.reset_value)
            for f in sidecar.register_semantics[:4]] == [
        ('PADDIR', 'value', 0, 32, 0xffffffff, 0xffffffff, 0),
        ('PADOUT', 'value', 0, 32, 0xffffffff, 0xffffffff, 0),
        ('PADOUTSET', 'bits', 0, 32, 0, 0xffffffff, None),
        ('PADOUTCLR', 'bits', 0, 32, 0, 0xffffffff, None)]
    assert sidecar.endpoint_capabilities[0].endpoint_id == 'gpio.bus'
    assert sidecar.endpoint_capabilities[0].operations == ('request', 'accept', 'response', 'read', 'write', 'wait', 'error')


@pytest.mark.parametrize('register,field,offset,effect', (
    ('PADDIR', 'value', 0, 'none'), ('PADOUT', 'value', 12, 'none'),
    ('PADOUTSET', 'bits', 16, 'write_one_sets'), ('PADOUTCLR', 'bits', 20, 'write_one_clears')))
def test_register_plans_preserve_full_word_masks(register, field, offset, effect):
    profile, sidecar = loaded()
    if effect != 'none':
        with pytest.raises(ValueError, match='side-effect-requires-explicit'):
            plan_register_operation(profile, sidecar, register=register, field=field,
                                    operation='register_write', value=1)
    plan = plan_register_operation(profile, sidecar, register=register, field=field,
        operation='register_write', value=0x80000001, allow_side_effect=effect != 'none')
    assert (plan.offset, plan.bus_mask, plan.bus_value, plan.side_effect) == (
        offset, 0xffffffff, 0x80000001, effect)


@pytest.mark.parametrize('register', ('PADOUTSET', 'PADOUTCLR'))
def test_write_only_aliases_refuse_read_plans(register):
    profile, sidecar = loaded()
    with pytest.raises(ValueError, match='field-not-readable'):
        plan_register_operation(profile, sidecar, register=register, field='bits',
                                operation='register_read', allow_side_effect=True)


@pytest.mark.parametrize('value', (-1, 1 << 32, True))
def test_values_must_be_unsigned_exact_32_bit(value):
    profile, sidecar = loaded()
    with pytest.raises(ValueError, match='value-outside-width'):
        plan_register_operation(profile, sidecar, register='PADOUT', field='value',
                                operation='register_write', value=value)


def test_narrowed_declared_mask_refuses_unselected_write_value():
    profile, _ = loaded()
    document = json.loads(SIDECAR.read_text())
    document['register_semantics'][1]['write_mask'] = 255
    sidecar = load_ip_test_capability(document, profile=profile)
    with pytest.raises(ValueError, match='value-exceeds-write-mask'):
        plan_register_operation(profile, sidecar, register='PADOUT', field='value',
                                operation='register_write', value=256)


@pytest.mark.parametrize('mutation', ('revision', 'description', 'offset'))
def test_profile_drift_cannot_reuse_sidecar(mutation):
    document = json.loads(PROFILE.read_text())
    if mutation == 'revision':
        document['source']['revision'] = 'sha256:' + '0' * 64
    elif mutation == 'description':
        document['description'] += ' drift'
    else:
        document['address']['registers'][0]['offset'] = 56
    with pytest.raises(ValueError, match='test-capability-profile-mismatch'):
        load_ip_test_capability(SIDECAR, profile=load_component_profile(document))


def test_source_evidence_refs_pin_actual_sha_revision_and_line_ranges():
    profile, sidecar = loaded()
    digest = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    assert digest == '1e271914da4d25c87acd12121dde60a6ed955033870fd7a6730b2c9bafcbcaef'
    refs = [f.evidence_ref for f in sidecar.register_semantics]
    refs += [row.evidence_ref for row in sidecar.observation_mappings]
    for ref in refs:
        assert f'@{profile.source.revision.removeprefix("git:")}:' in ref
        assert ref.endswith(';sha256=' + digest)
        assert 'third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv' in ref
    assert [f.evidence_ref.split(':')[-1].split(';')[0] for f in sidecar.register_semantics[:4]] == [
        '215,277-280,530-538,781', '216,287-290,570-578,780',
        '297-302,216', '311-316,216']
    assert [(o.endpoint_id, o.role, o.observation_kind, o.bit_range)
            for o in sidecar.observation_mappings] == [
        ('gpio.pins', 'dir', 'port_sample', (0, 31)),
        ('gpio.pins', 'out', 'port_sample', (0, 31))]


def test_declarations_never_grant_effective_verified_or_l3_levels():
    profile, sidecar = loaded()
    assessment = assess_ip_test_level(profile, sidecar=sidecar)
    assert assessment.declared_level == 'L2'
    assert assessment.effective_level is None
    assert assessment.verified_level is None
    assert sidecar.feature_contract is None
    default = assess_ip_test_level(profile)
    assert default.declared_level == 'L1'
    assert default.effective_level is None and default.verified_level is None


def test_actual_v3_alias_relations_match_pinned_rtl_and_full_register_fields():
    profile, sidecar = loaded()
    assert sidecar.schema_version == 'ip_test_capability.v3'
    assert [(row.source_register, row.source_field, row.destination_register,
             row.destination_field, row.operation, row.bus_width)
            for row in sidecar.register_aliases] == [
        ('PADOUTSET', 'bits', 'PADOUT', 'value', 'set_bits', 32),
        ('PADOUTCLR', 'bits', 'PADOUT', 'value', 'clear_bits', 32)]
    digest = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    fields = {(row.register, row.field): row for row in sidecar.register_semantics}
    for row in sidecar.register_aliases:
        assert row.endpoint_id == 'gpio.bus'
        assert row.evidence_ref == fields[(row.source_register, row.source_field)].evidence_ref
        assert row.evidence_ref.endswith(';sha256=' + digest)
        assert '@' + profile.source.revision.removeprefix('git:') + ':' in row.evidence_ref
    lines = SOURCE.read_text().splitlines()
    assert 'r_gpio_out[i] | PWDATA[i]' in '\n'.join(lines[296:302])
    assert 'r_gpio_out[i] & ~PWDATA[i]' in '\n'.join(lines[310:316])
    assert 'r_gpio_out' in '\n'.join(lines[569:578])
