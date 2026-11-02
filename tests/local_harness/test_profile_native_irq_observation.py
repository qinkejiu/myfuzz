"""Profile IRQ observation uses physical cause signals, not RVFI intr."""
from dataclasses import replace
from pathlib import Path

import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.local_harness.native_irq_receipt_contract import (
    native_irq_receipt_contract_for_profile, native_irq_decision_probes,
    native_irq_notification_observed, native_irq_serial_observable,
)

ROOT = Path(__file__).resolve().parents[2]


def profile():
    p = load_component_profile(ROOT / 'configs/cpus/cv32e20_profile_only/component_profile.json')
    description = dict(schema_version='profile_native_irq_observation.v1',
        input_port='irq_external_i', masked_port='external_irq_masked_o',
        taken_port='external_irq_taken_o', source_semantics='machine_external_cause_only',
        source_files={'rtl/cve2_controller.sv':
            '5f5a05d177ed7e500b28c77e4e708fe4e4af73d00fc659c9648a95bed235b865'})
    return replace(p, evidence={**p.evidence, 'native_irq_observation': description})


def test_declared_irq_decision_never_infers_source_from_rvfi_intr():
    contract = native_irq_receipt_contract_for_profile(profile())
    assert native_irq_decision_probes(contract) == {'irq_masked_pre': 1, 'irq_taken_pre': 1}
    assert not native_irq_serial_observable(contract)
    assert not native_irq_notification_observed(contract, {'rvfi_valid': 1, 'rvfi_intr': 1})
    assert contract['generic_irq_entry_origin'] == 'unknown'
    assert contract['retirement_authority'] == 'pc_insn_order_only'


@pytest.mark.parametrize('change', [
    {'taken_port': 'rvfi_intr'}, {'masked_port': 'rvfi_valid'},
    {'taken_port': 'external_irq_masked_o'}, {'source_semantics': 'any_interrupt'},
    {'source_files': {}}, {'taken_port': 'a; assign hacked=1'},
])
def test_invalid_profile_irq_description_is_refused(change):
    p = profile()
    doc = dict(p.evidence['native_irq_observation']); doc.update(change)
    p = replace(p, evidence={**p.evidence, 'native_irq_observation': doc})
    with pytest.raises(ValueError):
        native_irq_receipt_contract_for_profile(p)


def test_decision_wiring_uses_unique_physical_outputs():
    from myfuzz.local_harness.profile_native_irq import profile_irq_probe_outputs
    contract = native_irq_receipt_contract_for_profile(profile())
    rows = [dict(physical_port=name, runtime_name='rt_'+name, direction='output',
                 width=1, disposition='observe') for name in
            ('external_irq_masked_o', 'external_irq_taken_o')]
    assert profile_irq_probe_outputs(contract, rows) == {
        'irq_masked_pre':'rt_external_irq_masked_o', 'irq_taken_pre':'rt_external_irq_taken_o'}
    for invalid in (rows[:1], rows + [rows[0]],
                    [rows[0], {**rows[1], 'direction':'input'}],
                    [rows[0], {**rows[1], 'width':2}]):
        with pytest.raises(ValueError, match='decision-port'):
            profile_irq_probe_outputs(contract, invalid)


def test_source_description_requires_actual_matching_locked_bytes():
    from myfuzz.local_harness.profile_native_irq import verify_profile_irq_source
    p = profile()
    assert verify_profile_irq_source(p, base_dir=ROOT)['source_status'] == 'source_verified'
    doc = dict(p.evidence['native_irq_observation'])
    doc['source_files'] = {'rtl/cve2_controller.sv':'0'*64}
    p = replace(p, evidence={**p.evidence, 'native_irq_observation':doc})
    with pytest.raises(ValueError, match='source-mismatch'):
        verify_profile_irq_source(p, base_dir=ROOT)


def test_actual_artifact_observation_requires_real_wiring_and_limited_rvfi(monkeypatch):
    import hashlib
    from types import SimpleNamespace
    from myfuzz.local_harness import profile_native_irq
    from myfuzz.local_harness.runtime_artifact import LocalRuntimeArtifact
    p = profile(); verification = {'actual':'source-check'}
    monkeypatch.setattr(profile_native_irq, 'verify_profile_irq_source', lambda *a, **k: verification)
    exports = [dict(physical_port=name, runtime_name='rt_'+name, direction='output',
                    width=width, disposition='observe') for name,width in (
        ('external_irq_masked_o',1), ('external_irq_taken_o',1),
        ('rvfi_valid',1), ('rvfi_order',64), ('rvfi_insn',32), ('rvfi_pc_rdata',32))]
    exports += [dict(physical_port=name,runtime_name='probe_'+name,direction='output',width=1)
                for name in ('irq_masked_pre','irq_taken_pre')]
    exports.append(dict(physical_port='irq_external_i',runtime_name='rt_irq_external_i',
        direction='input',width=1,endpoint_id=p.cpu.irq_entry_endpoint,role=p.cpu.irq_entry_role))
    sv=('assign probe_irq_masked_pre = rt_external_irq_masked_o;\n'
        'assign probe_irq_taken_pre = rt_external_irq_taken_o;')
    doc=dict(kind='obi_cpu', source_verification=verification,physical_exports=exports,
             runtime_sv_sha256=hashlib.sha256(sv.encode()).hexdigest())
    a=LocalRuntimeArtifact(SimpleNamespace(profile=p),None,verification,sv,'',doc)
    assert profile_native_irq.verify_profile_irq_artifact(a,base_dir=ROOT)=='rt_irq_external_i'
    for changed in (exports+[dict(physical_port='rvfi_intr',direction='output',width=1,disposition='observe')],
                    [r for r in exports if r['physical_port']!='external_irq_taken_o']):
        with pytest.raises(ValueError, match='profile-native-IRQ'):
            profile_native_irq.verify_profile_irq_artifact(replace(a,runtime_document={**doc,'physical_exports':changed}),base_dir=ROOT)
