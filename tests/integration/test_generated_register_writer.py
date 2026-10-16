import copy
from dataclasses import replace
import json
import os
from types import SimpleNamespace
from pathlib import Path
import pytest
from myfuzz.integration.generated_register_writer import declare_writer,writer_case,check_writer_observation
from myfuzz.integration.cv32e40p_pulp_online import make_cv32e40p_pulp_online_runtime
from tests.integration.test_generated_dual_runtime_loaded_real import _loaded
from myfuzz.local_harness.generated_execution_admission import require_runtime_projection, GeneratedExecutionRefused


def declaration(inputs,value):
    source=next(s for p in inputs['compiled']['paths'] if p['flow_id']=='F4'
                for s in p['sources'] if s['kind']=='cpu_mmio_stream')
    return declare_writer(inputs['request'],inputs['compiled'],source_id=source['source_id'],value=value)


def test_exact_writer_encoding_and_refusal(tmp_path):
    _,inputs=_loaded(tmp_path)
    a=declaration(inputs,0x55); b=declaration(inputs,0xaa)
    assert a['candidate']['access']['address']==0x40001004
    assert a['candidate']['access']['register']=='GPIOEN'
    assert a['code_hex']!=b['code_hex']
    assert a['runtime_admitted'] is False
    assert a['unsupported_flows']==['F1','F2','F3']
    tampered=copy.deepcopy(a);tampered['code_hex']='13000000'
    with pytest.raises(ValueError,match='generated-writer-declaration-mismatch'):
        writer_case(SimpleNamespace(),tampered,request=inputs['request'],compiled=inputs['compiled'])
    with pytest.raises(ValueError,match='register-candidate-value-invalid'):declaration(inputs,True)
    changed=dict(inputs,compiled=copy.deepcopy(inputs['compiled']));changed['compiled']['paths'][3]['sources'][1]['register_access']['address']+=8
    with pytest.raises(ValueError,match='register-candidate-compiled-document-mismatch'):declaration(changed,0x55)


@pytest.mark.skipif(os.environ.get('MYFUZZ_GENERATED_RUNTIME_REAL')!='1',reason='isolated real RTL gate')
def test_real_generated_GPIOEN_writer_and_fresh_replay(tmp_path):
    artifacts,inputs=_loaded(tmp_path,physical_observations=True)
    evidence=Path(os.environ.get('MYFUZZ_WRITER_EVIDENCE',str(tmp_path/'evidence')))
    evidence.mkdir(parents=True,exist_ok=True)
    cache=Path(os.environ.get('MYFUZZ_GENERATED_RUNTIME_CACHE',str(tmp_path/'cache')))
    summaries=[]
    for value in (0x55,0xaa):
        runtime=make_cv32e40p_pulp_online_runtime(cache_dir=cache,run_id=f'generated-writer-{value}',
            generated_artifacts=artifacts,generated_execution_scope='loaded_artifacts',checker=lambda r:(),
            observation_modes={'cpu':False,'gpio_a':True,'gpio_b':True})
        try:
            d=declaration(inputs,value)
            tampered=copy.deepcopy(d);tampered['candidate']['access']['address']+=8
            with pytest.raises(ValueError,match='generated-writer-declaration-mismatch'):
                writer_case(runtime,tampered,request=inputs['request'],compiled=inputs['compiled'])
            case=writer_case(runtime,d,request=inputs['request'],compiled=inputs['compiled'])
            receipt=runtime.session.submit_case(case)
            observed=check_writer_observation(d,receipt,target_artifact=artifacts['gpio_a'])
            assert observed['register_version_authenticated'] is False
            assert observed['runtime_admitted'] is False
            missing_physical=replace(receipt,events=tuple(e for e in receipt.events
                if e.get('event_id')!=observed['joins'][0]['native_APB_event']))
            with pytest.raises(ValueError,match='generated-writer-native-APB-transfer-mismatch'):
                check_writer_observation(d,missing_physical,target_artifact=artifacts['gpio_a'])
            with pytest.raises(GeneratedExecutionRefused):
                require_runtime_projection(artifacts=artifacts,compiled_inputs=inputs)
            other=declaration(inputs,value^0xff)
            with pytest.raises(ValueError,match='generated-writer-actual-write-mismatch'):
                check_writer_observation(other,receipt,target_artifact=artifacts['gpio_a'])
            reference=runtime.session.finish()
            replay=runtime.replay(reference,checker=lambda r:())
            assert replay.matches,replay
            identities={n:s.identity_document() for n,s in runtime.session.runner.sessions.items()}
            summary=dict(declaration=d,observation=observed,fresh_matches=replay.matches,
                fresh_scope=replay.verification_scope,identities=identities)
            summaries.append(summary)
            (evidence/f'{value}-events.json').write_text(json.dumps(list(reference.events),indent=2))
            (evidence/f'{value}-plan.json').write_bytes(runtime.session.encode_plan())
        finally:
            if not runtime.session._finished:runtime.session.finish()
    (evidence/'summary.json').write_text(json.dumps(summaries,indent=2))


@pytest.mark.parametrize("modes", [True, {}, {'cpu': False},
    {'cpu': False, 'gpio_a': True, 'gpio_b': 'native'},
    {'cpu': False, 'gpio_a': True, 'gpio_b': True, 'unknown': False}])
def test_observation_modes_refuse_unknown_instances_and_modes(modes):
    from myfuzz.scenario.cv32e40p_pulp_dual_source import make_cv32e40p_pulp_dual_source_factory
    with pytest.raises(ValueError, match='observation_modes'):
        make_cv32e40p_pulp_dual_source_factory(Path('/unused'), observation_modes=modes)


def test_loaded_mixed_observation_modes_are_explicit(tmp_path):
    from myfuzz.local_harness.generated_execution_admission import select_factory_artifacts
    from myfuzz.scenario.cv32e40p_pulp_dual_source import CV32E40P_CPU_PROFILE
    from myfuzz.scenario.ibex_pulp_dual_source import dual_source_wiring, ROOT
    artifacts, _ = _loaded(tmp_path, physical_observations=True)
    wiring = dual_source_wiring(cpu_profile=CV32E40P_CPU_PROFILE)
    expected = {'cpu': (wiring.cpu_profile, 'obi_cpu'),
                'gpio_a': (wiring.gpio_profile, 'apb_gpio'),
                'gpio_b': (wiring.gpio_profile, 'apb_gpio')}
    modes = {'cpu': False, 'gpio_a': True, 'gpio_b': True}
    selected = select_factory_artifacts(artifacts, expected=expected, base_dir=ROOT,
                                        observation_modes=modes)
    assert all(selected[name] is artifact for name, artifact in artifacts.items())
    with pytest.raises(GeneratedExecutionRefused, match='observation-mode-mismatch'):
        select_factory_artifacts(artifacts, expected=expected, base_dir=ROOT)
    for bad in ({}, dict(modes, unknown=False), dict(modes, gpio_a='native')):
        with pytest.raises(GeneratedExecutionRefused, match='observation-mode-invalid'):
            select_factory_artifacts(artifacts, expected=expected, base_dir=ROOT,
                                     observation_modes=bad)
