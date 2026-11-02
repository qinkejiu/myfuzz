import json
from pathlib import Path
from types import SimpleNamespace

from myfuzz.integration.declared_irq_consumption import admit_declared_irq_consumption, build_declared_irq_firmware
from myfuzz.composition.component_profile import load_component_profile
from scripts.run_inprocess_irq import build_case, request_from_profile, cpu_request_from_config, apply_irq_behavior
from scripts.run_declared_irq_f5 import case_program, f5_fields
from scripts import inprocess_build


def test_one_click_builds_existing_f5_firmware_without_a_prior_prefix():
    root=Path(__file__).resolve().parents[2]
    config=json.loads((root/'configs/scenarios/declared-irq-f5-pulp-timer-single/config.json').read_text())
    admission=admit_declared_irq_consumption(config,base_dir=root)
    assert admission['status']=='admitted'
    cpu=load_component_profile(root/config['cpu_profile'])
    target=load_component_profile(root/'configs/peripherals/pulp_timer_irq/component_profile.json')
    options,prefix=build_case(config,cpu,target,boot=0x10080)
    assert options['active_id']=='pulp_timer_active' and options['idle_id'] is None
    assert options['trigger_writes']==((4,0),(8,0),(0,0xffffffff))
    assert prefix['firmware']['first_fetch']==0x10080
    assert prefix['firmware']['status_offsets']==[0]
    assert prefix['program']['images'][str(prefix['firmware']['dynamic_start'])].endswith('6f000000')
    fields=f5_fields(config,admission)
    baseline=build_declared_irq_firmware(image_start=fields['image_start'],image_end=fields['image_end'],
        first_fetch=0x10080,target_base=fields['target_base'],status_offsets=fields['status_offsets'],
        result_address=fields['result_address'],clear_writes=fields['clear_writes'])
    assert prefix['firmware']==baseline
    assert prefix['program']==case_program(baseline,options,fields)


def test_one_click_rejects_undeclared_register_or_irq():
    import pytest
    root=Path(__file__).resolve().parents[2]
    config=json.loads((root/'configs/scenarios/declared-irq-f5-pulp-timer-single/config.json').read_text())
    cpu=load_component_profile(root/config['cpu_profile'])
    target=load_component_profile(root/'configs/peripherals/pulp_timer_irq/component_profile.json')
    with pytest.raises(ValueError,match='register'):
        build_case(dict(config,status_offsets=[12]),cpu,target,boot=0x10080)
    with pytest.raises(ValueError,match='IRQ'):
        build_case(dict(config,source_bit_offset=7),cpu,target,boot=0x10080)


def test_same_timer_description_accepts_cv32e20_profile():
    root=Path(__file__).resolve().parents[2]
    config=json.loads((root/'configs/scenarios/inprocess-irq-cv32e20-pulp-timer-profile.json').read_text())
    cpu=load_component_profile(root/config['cpu_profile'])
    target=load_component_profile(root/config['source_profile'])
    options,prefix=build_case(config,cpu,target,boot=0x10000)
    assert options['trigger_writes']==((4,0),(8,0),(0,0xffffffff))
    assert prefix['firmware']['first_fetch']==0x10000
    assert prefix['firmware']['status_offsets']==[0]


def test_shared_builder_links_two_verified_model_archives_and_runs_once(tmp_path,monkeypatch):
    artifacts=[SimpleNamespace(runtime_document={'module_name':'local_runtime_cpu'}),
               SimpleNamespace(runtime_document={'module_name':'local_runtime_target'})]
    for artifact in artifacts:
        obj=tmp_path/artifact.runtime_document['module_name']/'obj'
        obj.mkdir(parents=True)
        (obj/('V'+artifact.runtime_document['module_name']+'__ALL.a')).write_bytes(b'model')
    class Built:
        def __init__(self,artifact): self.artifact=artifact
        def validate_current(self,artifact,**kwargs):
            assert artifact is self.artifact
            return tmp_path/artifact.runtime_document['module_name']/'harness'
        def observation_document(self): return {'outcome':'cache_hit'}
    monkeypatch.setattr(inprocess_build,'build_local_harness_with_receipt',lambda artifact,**kw:Built(artifact))
    (tmp_path/'main.cpp').write_text('int main() {}\n')
    (tmp_path/'cxx').write_bytes(b'test compiler')
    (tmp_path/'include').mkdir()
    monkeypatch.setattr(inprocess_build,'_toolchain',lambda:{'cxx':{'path':str(tmp_path/'cxx')},
                                                            'verilator':{'runtime_root':str(tmp_path)}})
    calls=[]
    def run(command,**kwargs):
        calls.append(command)
        if len(calls)==1:
            Path(command[-1]).write_bytes(b'test executable')
        return SimpleNamespace(returncode=0,stdout='observed',stderr='')
    monkeypatch.setattr(inprocess_build.subprocess,'run',run)
    result=inprocess_build.build_link_run(artifacts,tmp_path/'main.cpp',tmp_path,tmp_path/'cache',
                                          ['firmware.txt','50'],root=tmp_path)
    assert result['status']=='observations_passed' and len(result['archives'])==2
    assert len(calls)==2 and calls[1][-2:]==['firmware.txt','50']
    assert (tmp_path/'run.log').read_text()=='observed'


def test_source_profile_requires_explicit_timing_and_declared_apb_endpoint():
    root=Path(__file__).resolve().parents[2]
    name='configs/peripherals/pulp_timer_irq/component_profile.json'
    profile=json.loads((root/name).read_text())
    config=dict(source_profile=name,active_id='timer',
                source_timing=dict(reset_assert_ticks=2,reset_release_ticks=3,max_wait_cycles=16))
    request=request_from_profile(config,profile)
    assert request['profile_path']==name
    assert request['tuning']['endpoint_policies'][0]['endpoint_id']=='timer.bus'
    assert request['reset_assert_ticks']==2
    config.pop('source_timing')
    import pytest
    with pytest.raises(ValueError,match='source_timing'):
        request_from_profile(config,profile)


def test_cpu_profile_requires_explicit_reset_and_wait_timing():
    import pytest
    config=dict(cpu_profile='configs/cpus/ibex_rvfi_local/component_profile.json',
                cpu_timing=dict(reset_assert_ticks=8,reset_release_ticks=8,max_wait_cycles=16))
    request=cpu_request_from_config(config)
    assert request['profile_path']==config['cpu_profile']
    assert request['reset_assert_ticks']==8 and request['reset_release_ticks']==8
    with pytest.raises(ValueError,match='cpu_timing'):
        cpu_request_from_config(dict(cpu_profile=config['cpu_profile']))


def test_ip_owned_irq_behavior_and_fixed_inputs_reuse_same_cpu():
    root=Path(__file__).resolve().parents[2]
    behavior=json.loads((root/'configs/peripherals/pulp_spi_irq/irq_behavior.json').read_text())
    config=dict(single_source=True,cpu_profile='configs/cpus/ibex_rvfi_local/component_profile.json',
        source_profile='configs/peripherals/pulp_spi/component_profile.json',active_id='spi_active',
        active_base=0x40001000,image_start=0x10000,image_end=0x30000,result_address=0x10c40,
        source_timing=dict(reset_assert_ticks=2,reset_release_ticks=3,max_wait_cycles=16),
        source_tuning=dict(fixed_inputs=[dict(endpoint_id='spi.pins',role='sdi0',value=0)]))
    resolved=apply_irq_behavior(config,behavior,root=root)
    assert resolved['source_port']=='events_o' and resolved['status_offsets']==[40]
    cpu=load_component_profile(root/config['cpu_profile'])
    target=load_component_profile(root/config['source_profile'])
    options,prefix=build_case(resolved,cpu,target,boot=0x10080,behavior=behavior)
    assert options['trigger_writes']==((36,0x80000000),)
    assert prefix['firmware']['status_offsets']==[40]
    raw=json.loads((root/config['source_profile']).read_text())
    request=request_from_profile(resolved,raw)
    assert request['tuning']['fixed_inputs']==config['source_tuning']['fixed_inputs']
    import pytest
    with pytest.raises(ValueError,match='profile'):
        apply_irq_behavior(dict(config,source_profile='configs/peripherals/pulp_timer_irq/component_profile.json'),behavior,root=root)
