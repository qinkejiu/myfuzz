"""Real generated CPU boot inputs and source-backed predictions; no RTL run."""
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import pytest

ROOT=Path(__file__).resolve().parents[2]

@pytest.mark.parametrize('cpu,count,first',[('ibex_rvfi_local',32,0x10080),('cv32e20',32,0x10000),('cv32e20_rv32e',16,0x10000)])
def test_actual_cpu_artifact_selects_boot_and_legal_firmware_registers(cpu,count,first):
    from myfuzz.scenario.ibex_pulp_dual_source import _artifact
    from myfuzz.composition.component_profile import elaboration_mode_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from myfuzz.integration.shared_irq_firmware import expected_boot_fetch,irq_firmware_register_count,build_irq_firmware
    with elaboration_mode_scope('direct'),execution_validation_scope():
        artifact=_artifact(f'configs/cpus/{cpu}/component_profile.json','cpu')
        runtime=SimpleNamespace(artifacts={'cpu':artifact},cpu_id='cpu',base_dir=ROOT)
        assert expected_boot_fetch(runtime)==first
        assert irq_firmware_register_count(artifact.plan.profile)==count
        fw=build_irq_firmware(image_start=0x10000,image_end=0x40000,first_fetch=first,
            gpio_base=0x40001000,pin=8,register_count=count)
        assert fw['first_fetch']==first
        artifact.runtime_document['boot_contract']['configured_boot_base']^=4
        with pytest.raises(ValueError,match='boot-contract'):
            expected_boot_fetch(runtime)


def test_base_isa_and_rv32e_parameter_must_agree():
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.integration.shared_irq_firmware import irq_firmware_register_count
    p=load_component_profile(ROOT/'configs/cpus/cv32e20_rv32e/component_profile.json')
    with pytest.raises(ValueError,match='parameter-mismatch'):
        irq_firmware_register_count(replace(p,cpu=replace(p.cpu,extensions=('i',))))
    with pytest.raises(ValueError,match='unambiguous'):
        irq_firmware_register_count(replace(p,cpu=replace(p.cpu,extensions=('e','i'))))


def test_boot_strategy_rejects_changed_source_even_after_source_verification(tmp_path,monkeypatch):
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.integration.cpu_boot_contract import source_backed_boot_fetch
    from myfuzz.local_harness import source_lock
    p=load_component_profile(ROOT/'configs/cpus/cv32e20/component_profile.json')
    path=tmp_path/'third_party/cv32e20_upstream_reference/rtl/cve2_if_stage.sv'
    path.parent.mkdir(parents=True);path.write_bytes((ROOT/path.relative_to(tmp_path)).read_bytes()+b'\n// changed\n')
    monkeypatch.setattr(source_lock,'verify_local_source_lock',lambda *args,**kwargs:{})
    with pytest.raises(ValueError,match='strategy changed'):
        source_backed_boot_fetch(p,base_dir=tmp_path,configured_boot_base=0x10000)


def test_boot_profile_contract_uses_declared_locked_source():
    from hashlib import sha256
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.integration.cpu_boot_contract import source_backed_boot_fetch
    p=load_component_profile(ROOT/'configs/cpus/cv32e20/component_profile.json')
    source='rtl/cve2_core.sv'
    digest=sha256((ROOT/p.source.source_root/source).read_bytes()).hexdigest()
    contract={'source_file':source,'source_sha256':digest,'base_mask':0xffffffe0,'fixed_bits':8}
    p=replace(p,evidence={**p.evidence,'boot_fetch':contract})
    assert source_backed_boot_fetch(p,base_dir=ROOT,configured_boot_base=0x1001c)==0x10008


def test_loaded_profile_boot_contract_does_not_require_strategy_registration(monkeypatch):
    import json
    from hashlib import sha256
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.integration import cpu_boot_contract
    doc=json.loads((ROOT/'configs/cpus/cv32e20/component_profile.json').read_text())
    source='rtl/cve2_if_stage.sv'
    digest=sha256((ROOT/doc['source']['root']/source).read_bytes()).hexdigest()
    doc.setdefault('evidence',{})['boot_fetch']={
        'source_file':source,'source_sha256':digest,'base_mask':0xfffffffc,'fixed_bits':0}
    p=load_component_profile(doc)
    monkeypatch.setattr(cpu_boot_contract,'_BOOT_STRATEGIES',())
    assert cpu_boot_contract.source_backed_boot_fetch(p,base_dir=ROOT,
        configured_boot_base=0x1001c)==0x1001c


@pytest.mark.parametrize('change',[
    {'source_file':'rtl/not_declared.sv'}, {'source_sha256':'0'*64},
    {'base_mask':0xfffffff0,'fixed_bits':16}, {'fixed_bits':3},
])
def test_boot_profile_contract_rejects_invalid_declaration(change):
    from hashlib import sha256
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.integration.cpu_boot_contract import source_backed_boot_fetch
    p=load_component_profile(ROOT/'configs/cpus/cv32e20/component_profile.json')
    source='rtl/cve2_core.sv'
    contract={'source_file':source,'source_sha256':sha256((ROOT/p.source.source_root/source).read_bytes()).hexdigest(),
              'base_mask':0xffffffe0,'fixed_bits':8}
    contract.update(change)
    p=replace(p,evidence={**p.evidence,'boot_fetch':contract})
    with pytest.raises(ValueError,match='boot'):
        source_backed_boot_fetch(p,base_dir=ROOT,configured_boot_base=0x1001c)
