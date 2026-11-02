"""F6 source selection uses the real profile and never invents a runtime link."""
from pathlib import Path
from dataclasses import replace
import pytest
from myfuzz.composition.component_profile import load_component_profile
from myfuzz.scenario.f6_dma_source_provider import select_f6_dma_source_provider, f6_dma_static_bindings

ROOT=Path(__file__).resolve().parents[2]

@pytest.mark.parametrize('name,unit,trigger,offsets', [
    ('zipcpu_wbdmac','words','pulse',{'control':0,'length':4,'source':8,'destination':12}),
    ('zipdma_smoke','bytes','level',{'control':0,'length':12,'source':4,'destination':8})])
def test_source_verified_provider_has_real_endpoints_and_irq(name,unit,trigger,offsets):
    profile=load_component_profile(ROOT/'configs/peripherals'/name/'component_profile.json')
    provider=select_f6_dma_source_provider(profile,base_dir=ROOT)
    assert provider.csr['offsets']==offsets
    assert provider.behavior['length_unit']==unit
    assert provider.irq_trigger==trigger and provider.irq_port=='o_interrupt'
    assert provider.master_endpoint_id=='dma.memory' and provider.control_endpoint_id=='dma.control'
    if trigger=='level':
        assert provider.behavior['irq_clear']==dict(method='write',offset=0,value=0x80000000,byte_enable=15)
    else:
        master,control=f6_dma_static_bindings(provider,profile,base_dir=ROOT)
        assert master['endpoint_id']==provider.master_endpoint_id
        assert master['template_binding']['variant_id']=='dma-full-word-no-select'
        assert control['variant_id']=='dma-full-word-no-select'


def test_profile_irq_drift_is_refused():
    profile=load_component_profile(ROOT/'configs/peripherals/zipdma_smoke/component_profile.json')
    changed=replace(profile,interrupts=(replace(profile.interrupts[0],trigger='pulse',pulse_width_cycles=1),))
    with pytest.raises(ValueError):select_f6_dma_source_provider(changed,base_dir=ROOT)


def test_profile_declares_f6_semantics_without_a_top_module_dispatch():
    profile=load_component_profile(ROOT/'configs/peripherals/zipdma_smoke/component_profile.json')
    known=select_f6_dma_source_provider(profile,base_dir=ROOT)
    declaration=dict(schema_version='f6_dma_behavior.v1',csr=known.csr,
        behavior=known.behavior,irq_trigger='level')
    profile=replace(profile,evidence={**profile.evidence,'f6_dma':declaration})
    provider=select_f6_dma_source_provider(profile,base_dir=ROOT)
    assert provider.source['schema_version']=='declared_f6_dma_source_contract.v1'
    assert provider.source['semantics_origin']=='component_profile_declared'
    assert provider.source['source_verification']['schema_version']=='zipdma_selected_profile_contract.v1'
    assert provider.csr==known.csr and provider.behavior==known.behavior
    assert provider.irq_trigger=='level'


def test_known_source_rejects_conflicting_declared_semantics():
    profile=load_component_profile(ROOT/'configs/peripherals/zipdma_smoke/component_profile.json')
    known=select_f6_dma_source_provider(profile,base_dir=ROOT)
    csr={**known.csr,'start_word':1}
    profile=replace(profile,evidence={**profile.evidence,'f6_dma':dict(
        schema_version='f6_dma_behavior.v1',csr=csr,behavior=known.behavior,irq_trigger='level')})
    with pytest.raises(ValueError,match='f6-dma-declaration-source-drift'):
        select_f6_dma_source_provider(profile,base_dir=ROOT)


def test_generic_profile_uses_source_lock_and_declared_irq(monkeypatch):
    profile=load_component_profile(ROOT/'configs/peripherals/zipdma_smoke/component_profile.json')
    known=select_f6_dma_source_provider(profile,base_dir=ROOT)
    profile=replace(profile,source_document={**profile.source_document,'top_module':'another_dma'},
        evidence={**profile.evidence,'f6_dma':dict(schema_version='f6_dma_behavior.v1',
            csr=known.csr,behavior=known.behavior,irq_trigger='level')})
    verified={'schema_version':'local_source_lock_verification.v1','source_status':'source_verified',
              'elaboration_status':'elaboration_verified'}
    monkeypatch.setattr('myfuzz.local_harness.source_lock.verify_local_source_lock',lambda *a,**kw:verified)
    provider=select_f6_dma_source_provider(profile,base_dir=ROOT)
    assert provider.source['source_verification']==verified
    assert provider.source['semantics_origin']=='component_profile_declared'
    assert provider.csr==known.csr and provider.irq_trigger=='level'
    from myfuzz.integration.f6_dma_behavior import f6_dma_irq_trigger
    assert f6_dma_irq_trigger(provider.source)=='level'


def test_declared_register_offsets_must_belong_to_profile(monkeypatch):
    profile=load_component_profile(ROOT/'configs/peripherals/zipdma_smoke/component_profile.json')
    known=select_f6_dma_source_provider(profile,base_dir=ROOT)
    csr={**known.csr,'offsets':{**known.csr['offsets'],'length':16}}
    profile=replace(profile,source_document={**profile.source_document,'top_module':'another_dma'},
        evidence={**profile.evidence,'f6_dma':dict(schema_version='f6_dma_behavior.v1',
            csr=csr,behavior=known.behavior,irq_trigger='level')})
    monkeypatch.setattr('myfuzz.local_harness.source_lock.verify_local_source_lock',lambda *a,**kw:{'schema_version':'local_source_lock_verification.v1'})
    with pytest.raises(ValueError,match='f6-dma-declared-csr-invalid'):
        select_f6_dma_source_provider(profile,base_dir=ROOT)


def test_declared_wide_control_window_and_irq_clear_offsets(monkeypatch):
    """Synthetic profile checks declarations only, not wide RTL execution."""
    profile=load_component_profile(ROOT/'configs/peripherals/zipdma_smoke/component_profile.json')
    known=select_f6_dma_source_provider(profile,base_dir=ROOT)
    offsets={name:offset+16 for name,offset in known.csr['offsets'].items()}
    csr={**known.csr,'offsets':offsets}
    behavior={**known.behavior,'irq_clear':{**known.behavior['irq_clear'],'offset':16}}
    address=replace(profile.address,window_size=32,
        registers=tuple(replace(reg,offset=reg.offset+16) for reg in profile.address.registers))
    profile=replace(profile,address=address,
        capabilities={**profile.capabilities,'address_width':4},
        source_document={**profile.source_document,'top_module':'synthetic_wide_dma'},
        evidence={**profile.evidence,'f6_dma':dict(schema_version='f6_dma_behavior.v1',
            csr=csr,behavior=behavior,irq_trigger='level')})
    monkeypatch.setattr('myfuzz.local_harness.source_lock.verify_local_source_lock',
        lambda *a,**kw:{'schema_version':'local_source_lock_verification.v1'})
    provider=select_f6_dma_source_provider(profile,base_dir=ROOT)
    assert provider.source['control_size']==32
    assert provider.csr['offsets']==offsets
    assert provider.behavior['irq_clear']['offset']==16
    bad=replace(profile,address=replace(address,window_size=28))
    with pytest.raises(ValueError,match='f6-dma-declared-csr-invalid'):
        select_f6_dma_source_provider(bad,base_dir=ROOT)


def test_declared_write_only_configuration_and_writable_irq_clear(monkeypatch):
    profile=load_component_profile(ROOT/'configs/peripherals/zipdma_smoke/component_profile.json')
    known=select_f6_dma_source_provider(profile,base_dir=ROOT)
    declaration=dict(schema_version='f6_dma_behavior.v1',csr=known.csr,
        behavior=known.behavior,irq_trigger='level')
    registers=tuple(replace(r,access='wo') if r.offset != known.csr['offsets']['control'] else r
        for r in profile.address.registers)
    profile=replace(profile,source_document={**profile.source_document,'top_module':'synthetic_dma'},
        address=replace(profile.address,registers=registers),
        evidence={**profile.evidence,'f6_dma':declaration})
    monkeypatch.setattr('myfuzz.local_harness.source_lock.verify_local_source_lock',
        lambda *a,**kw:{'schema_version':'local_source_lock_verification.v1'})
    assert select_f6_dma_source_provider(profile,base_dir=ROOT).csr==known.csr
    control=known.csr['offsets']['control']
    unreadable=replace(profile,address=replace(profile.address,registers=tuple(
        replace(r,access='wo') if r.offset==control else r for r in registers)))
    with pytest.raises(ValueError,match='f6-dma-declared-csr-invalid'):
        select_f6_dma_source_provider(unreadable,base_dir=ROOT)
    clear={**known.behavior['irq_clear'],'offset':16}
    bad=replace(profile,address=replace(profile.address,window_size=32),
        evidence={**profile.evidence,'f6_dma':{**declaration,
            'behavior':{**known.behavior,'irq_clear':clear}}})
    with pytest.raises(ValueError,match='f6-dma-declared-csr-invalid'):
        select_f6_dma_source_provider(bad,base_dir=ROOT)
