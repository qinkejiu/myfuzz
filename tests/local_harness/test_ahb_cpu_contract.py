"""Pure generation with saved elaborated ports, no fresh elaboration/build.

Only elaboration and build-tool identity are replaced. Real profile binding,
source lock, runtime/driver rendering, constructor and reconstruction run.
"""
import copy
import json
from pathlib import Path
import subprocess
import pytest

ROOT=Path(__file__).resolve().parents[2]


@pytest.fixture
def generated(monkeypatch,tmp_path,request):
 timings=getattr(request,'param',(8,8))
 from myfuzz.composition.component_profile import PhysicalFacts,load_component_profile
 from myfuzz.composition.source_crawler import ElaboratedPortFact
 from myfuzz.local_harness import plan as planning, runtime_renderer,session,build
 from myfuzz.composition import source_elaboration
 from myfuzz.local_harness import load_local_harness_request,render_local_harness,verify_local_source_lock
 from myfuzz.local_harness.driver_renderer import render_local_driver
 profile=load_component_profile(ROOT/'configs/cpus/cvw/component_profile.json')
 saved=json.loads((ROOT/'configs/cpus/cvw/evidence/llen32-20261017/elaborated_ports.json').read_text())
 ports=tuple(ElaboratedPortFact(name=r['name'],direction=r['direction'],width=r['width'],signed=r['signed'],source_file=r['source']['file'],line=r['source']['line'],column=r['source']['column']) for r in saved['ports'])
 facts=PhysicalFacts(top_module=profile.source.top_module,ports=ports,content_hash='saved_ports_software_fixture',revision=profile.source.revision,files=profile.source.files,include_roots=profile.source.include_roots)
 def saved_frontend(**kw):
  out=kw['output_dir'];out.mkdir(parents=True)
  (out/'manifest.json').write_bytes((ROOT/'configs/cpus/cvw/evidence/llen32-20261017/manifest.json').read_bytes())
 monkeypatch.setattr(source_elaboration,'run_verilator_elaboration',saved_frontend)
 monkeypatch.setattr(planning,'elaborate_profile',lambda *a,**kw:facts)
 monkeypatch.setattr(runtime_renderer,'elaborate_profile',lambda *a,**kw:facts)
 actual_popen=subprocess.Popen
 def guard(argv,*a,**kw):
  if Path(argv[0]).name!='git':raise AssertionError('no external model/compiler/elaboration '+str(argv))
  return actual_popen(argv,*a,**kw)
 monkeypatch.setattr(subprocess,'Popen',guard)
 identity=lambda artifact,**kw:dict(software_fixture=True,artifact_digest=artifact.runtime_document['artifact_digest'])
 monkeypatch.setattr(build,'local_build_identity',identity)
 monkeypatch.setattr(session,'local_build_identity',identity)
 request=load_local_harness_request(dict(schema_version='local_harness.v1',profile_path='configs/cpus/cvw/component_profile.json',instance_id='cpu',reset_assert_ticks=timings[0],reset_release_ticks=timings[1],max_wait_cycles=16))
 plan=planning.plan_local_harness(request,base_dir=ROOT)
 top=runtime_renderer.render_local_runtime(plan,render_local_harness(plan),verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT)
 artifact=render_local_driver(top,base_dir=ROOT)
 from myfuzz.local_harness.ahb_lite_session import GeneratedAhbMemorySession
 from myfuzz.scenario.memory import PersistentMemory,MemoryRegion
 memory=PersistentMemory(regions=(MemoryRegion('ram',0xc0000000,4096),),initialization_seed=0,max_initialized_bytes=4096)
 cpu=GeneratedAhbMemorySession(artifact,base_dir=ROOT,cache_dir=tmp_path,memory=memory)
 return artifact,cpu


def test_real_constructor_identity_reconstruction_and_factory(generated):
 from myfuzz.scenario.contracts import _verify_generated_session,_generated_session_class_kind
 artifact,cpu=generated
 assert _generated_session_class_kind('myfuzz.local_harness.ahb_lite_session.GeneratedAhbMemorySession')=='ahb_lite_cpu'
 assert _verify_generated_session(cpu.identity_document())==artifact
 assert len(artifact.runtime_document['protocol_tap_ports'])==13
 assert 'protocol_taps' in artifact.cpp_text


@pytest.mark.parametrize('mutate',[
 lambda d:d.update(unknown=True),
 lambda d:d.update(memory_policy='other'),
 lambda d:d.update(source_component='other'),
 lambda d:d.update(ahb_lite_service_schema_version='other'),
 lambda d:d['ahb_observation_contract']['budgets'].update(max_edges=1),
 lambda d:d['runtime_artifact']['boot_contract'].update(configured_boot_base=0),
 lambda d:d['build_identity'].update(artifact_digest='other'),
 lambda d:d['runtime_artifact']['protocol_tap_ports'][0].update(source_wire='guessed'),
 lambda d:next(r for r in d['runtime_artifact']['protocol_tap_ports'] if r['role']=='hready').update(width=True),
 lambda d:d['build_identity'].update(software_fixture=1),
])
def test_strict_identity_mutations(generated,mutate):
 from myfuzz.scenario.contracts import _verify_generated_session
 artifact,cpu=generated;identity=copy.deepcopy(cpu.identity_document());mutate(identity)
 with pytest.raises(ValueError):_verify_generated_session(identity)


def test_runner_imports_stream_once(generated):
 from myfuzz.scenario.runner import ScenarioRunner
 from myfuzz.scenario.ownership import compile_ownership
 from myfuzz.scenario.ahb_cpu_events import SHAPE
 artifact,cpu=generated
 cpu._ahb_observer.begin_scope(execution_id='issued',testcase_id='case',reset_epoch=0)
 row=dict.fromkeys(SHAPE,0);row.update(hready=1,hsel=1,htrans=2)
 cpu._ahb_observer.observe(dict(local_tick=1,pre=row,post=row))
 runner=ScenarioRunner(sessions={'cpu':cpu},ownership=compile_ownership((),()),bindings=())
 runner._append_external_events('cpu',0);first=list(runner._events)
 runner._append_external_events('cpu',0)
 assert list(runner._events)==first
 assert [e['kind'] for e in first]==[e['kind'] for e in cpu.runtime_events]
 assert all(e['authority']=='observation_only' for e in first)


def test_runner_journal_drain_keeps_global_raw_refs(generated):
 from myfuzz.scenario.runner import ScenarioRunner
 from myfuzz.scenario.ownership import compile_ownership
 from myfuzz.scenario.event_journal import EventJournal
 from myfuzz.scenario.ahb_cpu_events import SHAPE
 artifact,cpu=generated;observer=cpu._ahb_observer
 observer.begin_scope(execution_id='issued',testcase_id='case',reset_epoch=0)
 row=dict.fromkeys(SHAPE,0)|dict(hready=1,hsel=1,htrans=2)
 observer.observe(dict(local_tick=1,pre=row,post=row))
 original=list(cpu.runtime_events)
 runner=ScenarioRunner(sessions={'cpu':cpu},ownership=compile_ownership((),()),bindings=())
 runner._events._records=EventJournal(chunk_size=2)
 runner._append_external_events('cpu',0)
 assert cpu.runtime_events==[]
 row=dict.fromkeys(SHAPE,0)|dict(hready=1,hrdata=42)
 observer.observe(dict(local_tick=2,pre=row,post=row))
 runner._append_external_events('cpu',0);n=len(runner._events)
 runner._append_external_events('cpu',0);assert len(runner._events)==n
 raw=[e for e in runner._events if e['kind']=='ahb_raw']
 complete=[e for e in runner._events if e['kind']=='ahb_complete'][0]
 assert complete['completion_ref']['raw_event']>complete['address_ref']['raw_event']
 assert complete['raw_event_refs']==[raw[0]['observer_record_index'],raw[1]['observer_record_index']]
