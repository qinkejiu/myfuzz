"""Actual Caliptra profile/constructor with saved ABI facts; no new frontend."""
import copy
import gzip
import json
from pathlib import Path
import subprocess
import pytest

ROOT=Path(__file__).resolve().parents[2]


@pytest.fixture
def target(monkeypatch,tmp_path):
 from myfuzz.composition.component_profile import PhysicalFacts,load_component_profile
 from myfuzz.composition.source_crawler import ElaboratedPortFact
 from myfuzz.local_harness import plan as planning,runtime_renderer,session,build
 from myfuzz.local_harness import load_local_harness_request,render_local_harness,verify_local_source_lock
 from myfuzz.local_harness.driver_renderer import render_local_driver
 from myfuzz.local_harness.ahb_lite_register_session import GeneratedAhbLiteRegisterSession
 path='configs/peripherals/caliptra_sha256/component_profile.json';profile=load_component_profile(ROOT/path)
 raw=gzip.decompress((ROOT/'docs/reports/evidence/ahb-register-identity-20261017/old-caliptra-target-artifact.json.gz').read_bytes())
 saved=json.loads(raw)
 rows=sorted({(r['port'],r['direction'],r['port_width']) for r in saved['plan']['ports']})
 ports=tuple(ElaboratedPortFact(name=n,direction=d,width=w,signed=False,source_file=profile.source.files[-1],line=1,column=1) for n,d,w in rows)
 facts=PhysicalFacts(top_module=profile.source.top_module,ports=ports,content_hash='saved_abi_software_fixture_not_new_elaboration',revision=profile.source.revision,files=profile.source.files,include_roots=profile.source.include_roots)
 monkeypatch.setattr(planning,'elaborate_profile',lambda *a,**kw:facts)
 monkeypatch.setattr(runtime_renderer,'elaborate_profile',lambda *a,**kw:facts)
 actual_popen=subprocess.Popen
 def guard(argv,*a,**kw):
  if Path(argv[0]).name!='git':raise AssertionError('no frontend/model/build '+str(argv))
  return actual_popen(argv,*a,**kw)
 monkeypatch.setattr(subprocess,'Popen',guard)
 identity=lambda artifact,**kw:dict(software_fixture=True,artifact_digest=artifact.runtime_document['artifact_digest'])
 monkeypatch.setattr(build,'local_build_identity',identity);monkeypatch.setattr(session,'local_build_identity',identity)
 request=load_local_harness_request(dict(schema_version='local_harness.v2',profile_path=path,instance_id='sha',reset_assert_ticks=8,reset_release_ticks=8,max_wait_cycles=16,tuning={'endpoint_policies':[dict(endpoint_id='sha256.bus',template_id='target.ahb-lite',template_version='1',variant_id='full-word-single',max_outstanding=1)]}))
 plan=planning.plan_local_harness(request,base_dir=ROOT)
 artifact=render_local_driver(runtime_renderer.render_local_runtime(plan,render_local_harness(plan),verify_local_source_lock(profile,base_dir=ROOT),base_dir=ROOT),base_dir=ROOT)
 return artifact,GeneratedAhbLiteRegisterSession(artifact,base_dir=ROOT,cache_dir=tmp_path,setup_writes=((0x80,0x61626380),),probe_offsets=(0x18,))


def test_actual_target_factory_identity_and_json_roundtrip(target):
 from myfuzz.scenario.contracts import _verify_generated_session,_generated_session_class_kind
 artifact,session=target;identity=session.identity_document()
 assert _generated_session_class_kind('myfuzz.local_harness.ahb_lite_register_session.GeneratedAhbLiteRegisterSession')=='ahb_lite_register_observe'
 assert _verify_generated_session(identity)==artifact
 assert _verify_generated_session(json.loads(json.dumps(identity)))==artifact
 assert 'apb3_register_service_schema_version' not in identity
 assert identity['ahb_lite_register_service_schema_version']=='generated_ahb_lite_register_observe.v1'


@pytest.mark.parametrize('mutate',[
 lambda d:d.update(unknown=True),
 lambda d:d.pop('ahb_lite_register_service_schema_version'),
 lambda d:d.update(ahb_lite_register_service_schema_version='generated_apb3_register_observe.v1'),
 lambda d:d.update(apb3_register_service_schema_version='generated_apb3_register_observe.v1'),
 lambda d:d.update(dynamic_input_initial_policy='expected'),
 lambda d:d.update(bound_input_initial_policy='expected'),
 lambda d:d.update(setup_writes=[[True,1]]),
 lambda d:d.update(setup_writes=[[4,True]]),
 lambda d:d.update(setup_writes=[[4096,1]]),
 lambda d:d.update(setup_writes=[[2,1]]),
 lambda d:d.update(setup_writes=[[4,1<<32]]),
 lambda d:d.update(setup_writes=[[4,1]]*17),
 lambda d:d.update(probe_offsets=[True]),
 lambda d:d.update(probe_offsets=[2]),
 lambda d:d.update(probe_offsets=[4096]),
 lambda d:d.update(probe_offsets=[4]*17),
 lambda d:d['build_identity'].update(software_fixture=1),
 lambda d:d['runtime_artifact']['base_protocol_trace'].update(max_wait_cycles=True),
])
def test_strict_target_identity_mutations(target,mutate):
 from myfuzz.scenario.contracts import _verify_generated_session
 _,session=target;identity=session.identity_document();mutate(identity)
 with pytest.raises(ValueError):_verify_generated_session(identity)


def test_bare_identity_downgrade_and_protocol_key_swap_refuse(target):
 from myfuzz.scenario.contracts import _verify_generated_session
 _,session=target;identity=session.identity_document()
 bare={k:v for k,v in identity.items() if k in ('schema_version','runtime_artifact','build_identity','command_timeout_seconds')}
 with pytest.raises(ValueError):_verify_generated_session(bare)
 identity['apb3_register_service_schema_version']=identity.pop('ahb_lite_register_service_schema_version')
 with pytest.raises(ValueError):_verify_generated_session(identity)


def test_actual_runner_manifest_registers_target_class_with_host_closure(target,monkeypatch):
 import hashlib
 from myfuzz.local_harness import build,session as base_session
 from myfuzz.scenario.runner import ScenarioRunner
 from myfuzz.scenario.ownership import compile_ownership
 from myfuzz.scenario.contracts import ScenarioManifest,ResourceBudget
 artifact,session=target
 def source_identity(artifact,**kw):
  paths=build._discover_host_sources()
  return dict(software_fixture=True,artifact_digest=artifact.runtime_document['artifact_digest'],
   inputs=[dict(path=p,sha256=hashlib.sha256((ROOT/p).read_bytes()).hexdigest()) for p in sorted(paths)])
 monkeypatch.setattr(build,'local_build_identity',source_identity)
 monkeypatch.setattr(base_session,'local_build_identity',source_identity)
 runner=ScenarioRunner(sessions={'sha':session},ownership=compile_ownership((),()),bindings=())
 identity=runner.identity_document();doc=artifact.runtime_document
 timing=dict(schema_version='generated_local_reset.v1',artifact_digest=doc['artifact_digest'],driver_sha256=doc['cpp_sha256'],hold_cycles=8,release_cycles=8)
 manifest=ScenarioManifest.from_runner_identity(identity,scenario_id='software_ahb_target_identity',schedule_order=('sha',),scheduler_policy_id='stable-local-v1',budget=ResourceBudget(),reset_timings={'sha':timing})
 assert manifest.to_document()['runner_identity']['sessions']['sha']['type']=='myfuzz.local_harness.ahb_lite_register_session.GeneratedAhbLiteRegisterSession'
 assert any(r['path']=='src/myfuzz/local_harness/ahb_lite_register_session.py' for r in identity['host_sources']['files'])
