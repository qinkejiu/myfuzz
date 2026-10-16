"""D2 objects execute a declared runtime; unimplemented D3 semantics stay refused."""
import json
import os
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

from myfuzz.local_harness.auto_harness_test import (load_composition,build_path_compile_request,
    load_session_inputs,runtime_family,assess_runtime_execution)
from myfuzz.local_harness.generated_execution_admission import GeneratedExecutionRefused,require_runtime_projection
from myfuzz.local_harness.harness_set import load_compose,generate_harness_set
from myfuzz.scenario.compiled_paths import load_path_compile_request,compile_paths
from myfuzz.integration.cv32e40p_pulp_online import make_cv32e40p_pulp_online_runtime
from myfuzz.scenario import ibex_pulp_dual_source as shared

ROOT=Path(__file__).resolve().parents[2]


def _loaded(directory):
    compose_dir=directory/'compose'
    shutil.copytree(ROOT/'configs/scenarios/cv32e40p-pulp-dual-gpio',compose_dir)
    for p in (compose_dir/'requests').glob('*.json'):
        d=json.loads(p.read_text());d.update(reset_assert_ticks=2,reset_release_ticks=3)
        p.write_text(json.dumps(d))
    compose=load_compose(compose_dir/'compose.json',base_dir=ROOT)
    generated=directory/'generated'
    generate_harness_set(compose,base_dir=ROOT,compose_base=compose_dir,output_root=generated)
    composition=load_composition(compose_dir/'compose.json',base_dir=ROOT)
    doc,_=build_path_compile_request(composition,wiring_path=generated/'wiring_contract.json')
    request=load_path_compile_request(doc,base_dir=ROOT)
    compiled=compile_paths(request)
    artifacts,inputs=load_session_inputs(generated_root=generated,base_dir=ROOT,
        family=runtime_family('cv32e40p-pulp-dual-source'),request=request,compiled=compiled)
    return artifacts,inputs


def test_dual_d3_missing_bound_producers_refuses_before_any_factory_start(tmp_path):
    artifacts,inputs=_loaded(tmp_path)
    assert all(a.plan.request.reset_assert_ticks==2 for a in artifacts.values())
    with patch('subprocess.Popen',side_effect=AssertionError('no runtime')):
        with pytest.raises(GeneratedExecutionRefused,match='compiled-runtime-input-refused') as error:
            require_runtime_projection(artifacts=artifacts,compiled_inputs=inputs)
    codes={r['code'] for r in error.value.detail['refusals']}
    assert 'ownership-bound-producer-not-admitted' in codes
    assert 'ownership-source-uncompiled' in codes


@pytest.mark.skipif(os.environ.get('MYFUZZ_GENERATED_RUNTIME_REAL')!='1',
    reason='set MYFUZZ_GENERATED_RUNTIME_REAL=1 for real loaded CV32E40P + dual GPIO')
def test_loaded_artifacts_drive_one_persistent_runtime_and_fresh_replay(tmp_path):
    artifacts,inputs=_loaded(tmp_path)
    evidence_dir=Path(os.environ.get('MYFUZZ_GENERATED_RUNTIME_EVIDENCE',str(tmp_path/'evidence')))
    evidence_dir.mkdir(parents=True,exist_ok=True)
    (evidence_dir/'compiled-paths.json').write_text(json.dumps(inputs['compiled'],indent=2))
    cache=Path(os.environ.get('MYFUZZ_GENERATED_RUNTIME_CACHE',str(tmp_path/'cache')))
    # The production factory must consume the exact loaded objects. Any default
    # regeneration is a failure, including factory() during fresh replay.
    with patch.object(shared,'_artifact',side_effect=AssertionError('D2 objects must be consumed')):
        runtime=make_cv32e40p_pulp_online_runtime(cache_dir=cache,run_id='loaded-cv32e40p',
            generated_artifacts=artifacts,generated_execution_scope='loaded_artifacts')
        runner=runtime.session.runner
        assert all(runner.sessions[name].artifact is value for name,value in artifacts.items())
        processes={name:session.process.pid for name,session in runner.sessions.items()}
        receipts=[];raws=[]
        try:
            for index in range(8):
                wanted='instruction' if index%2==0 else 'source'
                for salt in range(256):
                    raw=bytes((salt,index,index%2,4 if wanted=='instruction' else index//2%2,1,0,0,0))
                    case=runtime.decoder.decode(raw)
                    source=next(s for s in runtime.decoder.sources if s.source_id in case.source.action_id)
                    if source.kind==wanted:break
                else:raise AssertionError('could not select declared source')
                receipt=runtime.session.submit_case(case)
                runtime.decoder.commit(case)
                receipts.append(dict(case_id=receipt.case_id,status=receipt.status,
                    violations=list(receipt.violations),source_kind=wanted))
                raws.append(raw.hex())
                assert not receipt.violations
                assert {name:session.process.pid for name,session in runner.sessions.items()}==processes
            reference=runtime.session.finish()
            plan=runtime.session.encode_plan()
            replay=runtime.replay(reference)
            assert replay.matches,replay
            events=list(reference.events)
            assert any(e.get('kind')=='mmio_delivery' and e.get('device_id')=='gpio_a' and e.get('offset')==12 and e.get('write') for e in events)
            assert any(e.get('kind')=='source_injection' and e.get('component')=='gpio_b' for e in events)
            assert all(r.get('kind')!='reset_barrier' for r in events)
            projection=assess_runtime_execution(family=runtime_family('cv32e40p-pulp-dual-source'),
                artifacts=artifacts,compiled_inputs=inputs,producer_events=events)
            (evidence_dir/'execution-projection.json').write_text(json.dumps(projection,indent=2))
            assert projection['capability_executable']==4
            assert projection['execution_supported']==0
            f1=next(p for p in projection['paths'] if p['flow_id']=='F1')
            assert f1['status']=='unsupported'
            assert any(r['code']=='authenticated-retirement-observation-missing' for r in f1['refusals'])
            f4=next(p for p in projection['paths'] if p['flow_id']=='F4')
            target=f4['register_targets'][0]
            assert target['address']==0x40001004
            assert target['register_access']['access_alignment']==4
            assert target['register_access']['window_alignment']==4096
            assert any(r['code']=='compiled-register-writer-checker-binding-missing' for r in f4['refusals'])
            assert not any(r['code']=='compiled-register-address-alignment-unresolved' for r in f4['refusals'])
            assert target['diagnostic_matching_deliveries']
            assert all(e['provenance']['observed_case'] is None for e in target['diagnostic_matching_deliveries'])
            assert target['candidate_source_certified'] is False
            assert any(r['code']=='compiled-register-outside-runtime-candidate-windows' for r in f4['refusals'])
            (evidence_dir/'summary.json').write_text(json.dumps(dict(
                scope='D2_loaded_artifacts_fixed_declared_runtime_only',d3_runtime_admitted=False,
                artifact_digests={n:a.runtime_document['artifact_digest'] for n,a in artifacts.items()},
                requests={n:a.plan.request.document() for n,a in artifacts.items()},
                source_inputs=raws,receipts=receipts,fresh_matches=replay.matches,
                fresh_scope=replay.verification_scope,event_count=len(events),
                final_ticks={n:s.local_ticks for n,s in runner.sessions.items()},
                build_identities={n:s.identity_document()['build_identity'] for n,s in runner.sessions.items()}),indent=2))
            (evidence_dir/'plan.json').write_bytes(plan)
            (evidence_dir/'events.json').write_text(json.dumps(events,indent=2))
        finally:
            if not runtime.session._finished:runtime.session.finish()
