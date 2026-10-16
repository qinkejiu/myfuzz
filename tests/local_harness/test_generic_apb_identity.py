"""Pure generic identity controls; substituted ports/build are not native evidence."""
import copy
import json
from pathlib import Path
import subprocess
import tarfile
import pytest

ROOT=Path(__file__).resolve().parents[2]


@pytest.fixture(params=('timer','gpio'))
def generated(request,monkeypatch,tmp_path):
 from myfuzz.composition.component_profile import PhysicalFacts,load_component_profile
 from myfuzz.composition.source_crawler import ElaboratedPortFact
 from myfuzz.local_harness import plan as planning,runtime_renderer,session,build
 from myfuzz.local_harness import load_local_harness_request,render_local_harness,verify_local_source_lock
 from myfuzz.local_harness.driver_renderer import render_local_driver
 from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
 kind=request.param
 path=f'configs/peripherals/pulp_{kind}/component_profile.json'
 profile=load_component_profile(ROOT/path)
 if kind=='timer':
  rows=[(name,'input',width) for name,width in [('HCLK',1),('HRESETn',1),('PADDR',12),('PWDATA',32),('PWRITE',1),('PSEL',1),('PENABLE',1)]]
  rows += [(name,'output',width) for name,width in [('PRDATA',32),('PREADY',1),('PSLVERR',1),('irq_o',4)]]
 else:
  archive=ROOT/'docs/reports/evidence/compiled-f4-cv32-current-20261017/evidence.tar.gz'
  with tarfile.open(archive) as t:
   saved=json.load(t.extractfile('outputs/cv32/generated/peripheral/artifact.json'))
  rows=sorted({(r['port'],r['direction'],r['port_width']) for r in saved['plan']['ports']})
 ports=tuple(ElaboratedPortFact(name=n,direction=d,width=w,signed=False,source_file=profile.source.files[0],line=1,column=1) for n,d,w in rows)
 facts=PhysicalFacts(top_module=profile.source.top_module,ports=ports,content_hash='software_port_fixture_not_elaboration',revision=profile.source.revision,files=profile.source.files,include_roots=profile.source.include_roots)
 monkeypatch.setattr(planning,'elaborate_profile',lambda *a,**kw:facts)
 monkeypatch.setattr(runtime_renderer,'elaborate_profile',lambda *a,**kw:facts)
 original=subprocess.Popen
 def guard(argv,*a,**kw):
  if Path(argv[0]).name!='git':raise AssertionError('external model/compiler/elaboration forbidden '+str(argv))
  return original(argv,*a,**kw)
 monkeypatch.setattr(subprocess,'Popen',guard)
 identity=lambda artifact,**kw:dict(software_fixture=True,artifact_digest=artifact.runtime_document['artifact_digest'])
 monkeypatch.setattr(build,'local_build_identity',identity)
 monkeypatch.setattr(session,'local_build_identity',identity)
 tuning={'endpoint_policies':[dict(endpoint_id=kind+'.bus',template_id='target.apb3',template_version='1',variant_id='full-word',max_outstanding=1)]}
 if kind=='gpio':tuning['fixed_inputs']=[dict(endpoint_id='gpio.pins',role='in',value=0)]
 req=load_local_harness_request(dict(schema_version='local_harness.v2',profile_path=path,instance_id='unrelated_instance',reset_assert_ticks=2,reset_release_ticks=2,max_wait_cycles=16,tuning=tuning))
 plan=planning.plan_local_harness(req,base_dir=ROOT)
 artifact=render_local_driver(runtime_renderer.render_local_runtime(plan,render_local_harness(plan),verify_local_source_lock(profile,base_dir=ROOT),base_dir=ROOT),base_dir=ROOT)
 target=GeneratedApb3RegisterSession(artifact,base_dir=ROOT,cache_dir=tmp_path,setup_writes=((4,0x55),),probe_offsets=(4,))
 return artifact,target


def test_actual_generic_service_identity_reconstructs(generated):
 from myfuzz.scenario.contracts import _verify_generated_session,_generated_session_class_kind
 artifact,target=generated
 assert _generated_session_class_kind('myfuzz.local_harness.apb3_register_session.GeneratedApb3RegisterSession')=='apb3_register_observe'
 identity=target.identity_document()
 assert _verify_generated_session(identity)==artifact
 assert _verify_generated_session(json.loads(json.dumps(identity)))==artifact
 assert identity['setup_writes']==[[4,0x55]] and identity['probe_offsets']==[4]


@pytest.mark.parametrize('mutate',[
 lambda d:d.update(unknown=True),
 lambda d:d.pop('apb3_register_service_schema_version'),
 lambda d:d.update(apb3_register_service_schema_version='other'),
 lambda d:d.update(dynamic_input_initial_policy='expected_data'),
 lambda d:d.update(bound_input_initial_policy='fabricated'),
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
def test_generic_identity_refuses_mutations(generated,mutate):
 from myfuzz.scenario.contracts import _verify_generated_session
 artifact,target=generated;identity=target.identity_document();mutate(identity)
 with pytest.raises(ValueError):_verify_generated_session(identity)


def test_generic_identity_cannot_downgrade_to_bare_session(generated):
 from myfuzz.scenario.contracts import _verify_generated_session
 _,target=generated;identity=target.identity_document()
 identity={k:v for k,v in identity.items() if k in ('schema_version','runtime_artifact','build_identity','command_timeout_seconds')}
 with pytest.raises(ValueError):_verify_generated_session(identity)
