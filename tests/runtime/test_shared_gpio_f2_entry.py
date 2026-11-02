from pathlib import Path
from types import SimpleNamespace

from myfuzz.runtime.generic_campaign import load_descriptor,select_case_records
from myfuzz.runtime.flows.mixed import MixedStorageFlowBackend

ROOT=Path(__file__).resolve().parents[2]
CONFIG=ROOT/'configs/scenarios/compiled-f1-f5-ibex-gpio-shared'


def test_explicit_f2_descriptor_keeps_no_f2_default_unchanged():
    old=load_descriptor(CONFIG/'generic_scenario.json',base_dir=ROOT)
    explicit=load_descriptor(CONFIG/'generic_scenario_f2.json',base_dir=ROOT)
    assert 'F2' not in old.flow_ids
    assert explicit.records('F2')==['08100040']
    assert select_case_records(explicit,flow='mixed',records=['F2:08100040'])==( ('F2','08100040'), )


def test_backend_preserves_explicit_f2_runtime_capability():
    runtime=SimpleNamespace(_mixed_flows=True,_memory_flows=True,_f2_flows=True,_f5_preparation=object())
    assert MixedStorageFlowBackend(runtime=runtime).flows==frozenset(('F1','F2','F3','F4','F5'))


def test_explicit_gpio_f2_uses_padin_actual_read_version(tmp_path,monkeypatch):
    from myfuzz.runtime.preparation import create_preparation
    from myfuzz.local_harness.session import GeneratedLocalSession
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    from unittest.mock import patch
    import myfuzz.integration.compiled_f4 as f4
    import myfuzz.integration.compiled_f2 as f2
    import myfuzz.integration.compiled_f2_consumer as consumer
    context=create_preparation(base_dir=ROOT,compose_path=CONFIG/'compose.json',
        capability_paths=(ROOT/'configs/scenarios/compiled-f4-obi-apb-ibex/test_capability.json',),
        supplement_path=CONFIG/'execution_supplement.json',generated_dir=tmp_path/'generated',
        flow_ids=('F1','F2','F3','F4','F5'))
    try:
        monkeypatch.setattr(GeneratedLocalSession,'prepare_local',lambda self:None)
        monkeypatch.setattr(GeneratedLocalSession,'configure_built_executable_receipt',lambda self:None)
        monkeypatch.setattr(GeneratedLocalSession,'validate_built_executable_receipt',lambda self:{})
        monkeypatch.setattr(f4,'validate_built_receipts',lambda *a:None)
        monkeypatch.setattr(f2,'validate_built_receipts',lambda *a:None)
        monkeypatch.setattr(f4,'build_storage_producer',lambda binding,artifact,base_dir,cache_dir,max_cases:
            (GeneratedPulpGpioSession(artifact,base_dir=base_dir,cache_dir=cache_dir),SimpleNamespace()))
        import subprocess
        actual_popen=subprocess.Popen
        def no_native(command,*args,**kwargs):
            if command[0]=='git':return actual_popen(command,*args,**kwargs)
            raise AssertionError('native forbidden: '+str(command))
        with patch('subprocess.Popen',side_effect=no_native):
            runtime=f4.CompiledF4Runtime(artifacts=context.artifacts,compiled_inputs=context.compiled_inputs(),
                base_dir=ROOT,cache_dir=tmp_path/'cache',defer_begin=True,mixed_flows=True,
                memory_flows=True,f5_preparation=context)
        assert runtime._f2_flows is True
        assert runtime.register_name=='GPIOEN' and runtime.register_f2=='PADIN'
        runtime.cursor=runtime.start;runtime._stable=lambda:None
        before={'schema_version':'compiled_GPIO_F2_version.v1','register':'PADIN','reset_epoch':0,
            'value':0,'field_version':88,'write_count':0}
        actual={**before,'value':256,'field_version':0}
        after={**actual,'field_version':2}
        captures=[]
        def capture(authority,*,register,reset_epoch):
            captures.append(register)
            return SimpleNamespace(document=lambda:before)
        monkeypatch.setattr(consumer,'capture_f2_read_version',capture)
        tx=dict(execution_id='e',testcase_id='t',source_component='processor',source_epoch=0,channel_id='data',source_sequence=1)
        observed=dict(version_before=actual,version_witness=after,joins=[{'source_transaction':tx,'write':False}],
            actual_read={'schema_version':'gpio_PADIN_native_read_receipt.v1','value':256,'field_version':0})
        exact={'data_hops':[{'native_APB_event':11,'native_acceptance_event':12,'native_response_event':13,
                'source_transaction':tx}],'edges':[],'ram_write_hop':{'memory_write_event':14}}
        def submit(case):
            runtime._checked=(observed,after,exact)
            return SimpleNamespace(status='running',violations=())
        runtime.session.submit_case=submit
        certificate=runtime.submit(bytes.fromhex('08100040'),flow='F2')
        assert captures==['PADIN']
        assert certificate['version_before']['field_version']==0
        assert certificate['version_before']['value']==256
        assert certificate['prerequisite']['subject']['register']=='PADIN'
        assert certificate['prerequisite']['evidence_ref'].endswith(':PADIN:0')
        assert certificate['native_read']==observed['actual_read']
    finally:
        context.close()
