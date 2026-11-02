def test_entry_has_no_family_fallback():
    from myfuzz.local_harness.auto_harness_test import COMPILED_EXECUTORS
    row=COMPILED_EXECUTORS['compiled-f6-rfuzz']
    assert row['flow']=='F6' and row['family_fallback'] is False
    assert row['entry']=='myfuzz.integration.compiled_f6_rfuzz:run_compiled_f6_rfuzz_session'

def test_wrapper_signature_matches_f2():
    import inspect
    from myfuzz.integration.compiled_f2_rfuzz import run_compiled_f2_rfuzz_session
    from myfuzz.integration.compiled_f6_rfuzz import run_compiled_f6_rfuzz_session
    assert inspect.signature(run_compiled_f2_rfuzz_session)==inspect.signature(run_compiled_f6_rfuzz_session)

def test_marker_has_explicit_cli_and_api_carrier():
    import argparse, inspect, importlib.util
    from pathlib import Path
    from myfuzz.local_harness.auto_harness_test import run_auto_harness_test
    assert inspect.signature(run_auto_harness_test).parameters['f6_execution'].default is None
    spec=importlib.util.spec_from_file_location('f6_cli',Path('scripts/auto_harness_test.py'))
    cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
    parser=argparse.ArgumentParser();cli.configure_parser(parser)
    action=next(a for a in parser._actions if '--f6-execution' in a.option_strings)
    assert action.type is Path and action.default is None

def test_irq_delivery_has_explicit_api_carrier():
    import inspect
    from myfuzz.local_harness.auto_harness_test import run_auto_harness_test
    assert inspect.signature(run_auto_harness_test).parameters['f6_deliveries'].default is None

import json
from copy import deepcopy
import pytest
from tests.integration.test_compiled_f6_contract import ROOT, source_inputs, _saved_source_facts

@pytest.fixture(scope='module')
def driver_declarations(tmp_path_factory):
    root=tmp_path_factory.mktemp('f6-driver-declarations')
    request,compiled,artifacts=source_inputs()
    def write(name,value):
        path=root/name;path.write_text(json.dumps(value,default=lambda v:dict(v)));return path
    cpu=write('cpu.json',artifacts['cpu'].plan.request.document())
    dma=write('dma.json',artifacts['dma'].plan.request.document())
    # This sidecar is the exact source-backed declaration consumed by Task1.
    capability=write('test_capability.json',dict(request.devices[0].capability.source_document))
    wiring=request.wiring.document
    from myfuzz.local_harness.dma_artifact_endpoint_links import _artifact_link
    binding=_artifact_link(artifacts['dma'])['template_binding']
    template={k:binding[k] for k in ('template_id','template_version','variant_id')}
    compose=write('compose.json',dict(schema_version='harness_compose.v2',
        cpu=dict(instance_id='cpu',request=str(cpu),data_endpoint='processor.data'),
        devices=[dict(device_id='dma',instance_id='dma',request=str(dma),bus_endpoint='dma.control',
            base=0x40000000,size=16,template=dict(template_id='target.wishbone-pipelined',template_version='1',variant_id='dma-full-word-no-select'))],memory=wiring['resources'],
        dma_master_routes=wiring['dma_master_routes'],dma_master_route_bindings=[dict(route_id=r['route_id'],
            initiator_template=template) for r in wiring['dma_master_routes']['routes']]))
    marker=write('f6_execution.json',request.document['f6_execution'])
    deliveries=write('f6_deliveries.json',wiring['deliveries'])
    return dict(cpu=ROOT/'configs/cpus/ibex_rvfi_local/component_profile.json',
        ips=[ROOT/'configs/peripherals/zipcpu_wbdmac/component_profile.json'],compose=compose,
        ip_capabilities=[capability],f6_execution=marker,f6_deliveries=deliveries,
        base_dir=ROOT,executor='compiled-f6-rfuzz',skip_session=True,rounds_per_case=4096)

@pytest.mark.parametrize('mode',['valid','no_marker','extra_marker','no_delivery','wrong_delivery'])
def test_source_backed_driver_explicit_carriers_refuse_before_constructor(driver_declarations,tmp_path,monkeypatch,mode):
    from myfuzz.local_harness import auto_harness_test as driver
    # Source elaboration facts are the pinned source-backed software fixture;
    # no native builder, client, session, verifier or inventory is replaced.
    monkeypatch.setattr('myfuzz.local_harness.plan.elaborate_profile',_saved_source_facts)
    monkeypatch.setattr('myfuzz.local_harness.runtime_renderer.elaborate_profile',_saved_source_facts)
    monkeypatch.setattr(driver,'run_compiled_f6_session',lambda **kw:pytest.fail('constructor reached'))
    args=dict(driver_declarations,output=tmp_path/'run')
    if mode=='no_marker':args.pop('f6_execution')
    if mode=='no_delivery':args.pop('f6_deliveries')
    if mode=='extra_marker':
        marker=json.loads(args['f6_execution'].read_text());marker['hidden']=True
        path=tmp_path/'bad-marker.json';path.write_text(json.dumps(marker));args['f6_execution']=path
    if mode=='wrong_delivery':
        rows=json.loads(args['f6_deliveries'].read_text());rows[0]['producer_signal']='wrong'
        path=tmp_path/'bad-deliveries.json';path.write_text(json.dumps(rows));args['f6_deliveries']=path
    summary=driver.run_auto_harness_test(**args)
    if mode=='valid':
        assert summary['status']=='complete',summary['refusals']
        projection=json.loads((args['output']/'execution_projection.v1.json').read_text())
        assert projection['execution_supported']==1
        loaded=json.loads((args['output']/'path_compile_request.json').read_text())
        assert loaded['f6_execution']==json.loads(args['f6_execution'].read_text())
        assert loaded['deliveries']==json.loads(args['f6_deliveries'].read_text())
    else:assert summary['status']=='refused'

def test_wbdmac_declares_source_grounded_native_interrupt_form():
    from myfuzz.local_harness.declaration_review import review_profiles
    profile=ROOT/'configs/peripherals/zipcpu_wbdmac/component_profile.json'
    document=json.loads(profile.read_text())
    assert document['interrupts'][0]['trigger']=='pulse'
    result=review_profiles([profile],base_dir=ROOT)
    assert result['status']=='ok',result

@pytest.mark.parametrize('field',['polarity','trigger','role','endpoint_id','clear','hold'])
def test_wbdmac_d1_missing_irq_fields_refuses(tmp_path,field):
    from myfuzz.local_harness.declaration_review import review_profiles
    document=json.loads((ROOT/'configs/peripherals/zipcpu_wbdmac/component_profile.json').read_text())
    document['interrupts'][0].pop(field)
    path=tmp_path/'bad-profile.json';path.write_text(json.dumps(document))
    with pytest.raises(ValueError):
        # The closed profile loader itself may refuse incomplete records.
        from myfuzz.composition.component_profile import load_component_profile
        profile=load_component_profile(path)
        from myfuzz.local_harness.declaration_review import review_interrupts
        if review_interrupts(profile,base_dir=ROOT)['status']!='ok':raise ValueError('incomplete form')

from tests.integration.test_compiled_f6_build_join import admitted

@pytest.mark.parametrize('late_swap',[None,'raw','typed','fresh','build','capability','marker','delivery','expected_error'])
def test_real_driver_uses_exact_loaded_objects_and_independent_missing_inventory(
        driver_declarations,admitted,tmp_path,monkeypatch,late_swap):
    from contextlib import nullcontext
    from hashlib import sha256
    from types import SimpleNamespace
    from myfuzz.local_harness import auto_harness_test as driver
    from myfuzz.integration import compiled_f6_saved_outputs as saved
    from myfuzz.scenario.f6_assertion_evidence import build_f6_assertion_material
    from myfuzz.scenario.f6_execution_binding import CompiledF6ExecutionBinding
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.integration.compiled_f6_build_join import build_compiled_f6_build_join
    from myfuzz.integration.compiled_f4 import _artifact_execution_identity
    canonical=lambda v:json.dumps(v,sort_keys=True,separators=(',', ':'),ensure_ascii=False).encode()
    digest=lambda v:sha256(canonical(v)).hexdigest()
    monkeypatch.setattr('myfuzz.local_harness.plan.elaborate_profile',_saved_source_facts)
    monkeypatch.setattr('myfuzz.local_harness.runtime_renderer.elaborate_profile',_saved_source_facts)
    monkeypatch.setattr(driver,'_heavy_worker_lock',lambda _:nullcontext())
    args=dict(driver_declarations,output=tmp_path/'run',skip_session=False,max_tests=1)
    client=tmp_path/'client';client.write_bytes(b'');cache=tmp_path/'cache';cache.mkdir()
    args.update(client_binary=client,cache_dir=cache)
    # Keep declared inputs local because mutation cases intentionally alter bytes.
    for name in ('f6_execution','f6_deliveries'):
        local=tmp_path/(name+'.json');local.write_bytes(args[name].read_bytes());args[name]=local
    seen={};loader=driver.load_compiled_session_inputs
    def capture(**kwargs):
        artifacts,inputs=loader(**kwargs)
        assert inputs['request'] is kwargs['request'] and inputs['compiled'] is kwargs['compiled']
        seen.update(artifacts=artifacts,inputs=inputs);return artifacts,inputs
    monkeypatch.setattr(driver,'load_compiled_session_inputs',capture)
    def session(**kwargs):
        assert kwargs['artifacts'] is seen['artifacts'] and kwargs['compiled_inputs'] is seen['inputs']
        assert kwargs['rounds_per_case']==4096
        admission=admit_compiled_f6_runtime_path(artifacts=kwargs['artifacts'],compiled_inputs=kwargs['compiled_inputs'],base_dir=ROOT)
        binding=deepcopy(admitted['execution_binding'])
        binding.update(run_id=kwargs['run_id'],runtime_path_admission=admission,
            runtime_path_admission_sha256=admission['admission_sha256'],request_sha256=admission['request_sha256'],
            compiled_document_sha256=admission['compiled_document_sha256'],selected_path_sha256=admission['selected_path_sha256'],
            execution_contract_sha256=admission['execution_contract_sha256'],sparse_program_manifest=admission['sparse_program_manifest'],
            artifact_identities={c:_artifact_execution_identity(a) for c,a in kwargs['artifacts'].items()},
            ownership_sha256=digest(kwargs['compiled_inputs']['ownership'].document()))
        binding['binding_sha256']=digest({k:v for k,v in binding.items() if k!='binding_sha256'})
        binding=CompiledF6ExecutionBinding(binding).document()
        joined=build_compiled_f6_build_join(artifacts=kwargs['artifacts'],execution_binding=binding,
            original=admitted['original'],fresh=admitted['fresh'])
        class BoundaryRuntime:
            pass
        runtime=BoundaryRuntime();runtime.__dict__.update(artifacts=kwargs['artifacts'],execution_binding=binding,
            compiled_document_sha256=binding['compiled_document_sha256'],binding_sha256=binding['binding_sha256'],
            execution_binding_sha256=binding['binding_sha256'],path=admission['logical_path'],run_id=kwargs['run_id'],
            admitted_attempts=({'case_id':kwargs['run_id']+':case:0'},))
        # The genuine inventory builder reports missing observations for this
        # synthetic admitted case. No evidence collector or verifier is patched.
        material=build_f6_assertion_material(runtime)
        material['assertion_evidence']=dict(execution_binding=binding,path_id=binding['path_id'],run_id=kwargs['run_id'],
            cases=material['assertion_evidence']['cases'])
        seen['material']=material
        manifest={'source_backed_software_boundary':True}
        runtime.session=SimpleNamespace(manifest_document=manifest)
        plan=dict(completed=True,scope='full',execution_binding=binding,rounds_per_case=kwargs['rounds_per_case'],
            artifact_digests=joined['artifact_digests'],original_build=admitted['original'],records=[])
        replay=dict(matches=True,first_difference=None,verification_scope='full',actual_prefix=deepcopy(plan),actual_events=[],
            execution_audit=admitted['fresh']['execution_audit'],fresh_build=admitted['fresh'])
        outcome=dict(runtime=runtime,plan=plan,replay=replay,build_join=joined,assertion_material=material,
            verification={'matches':True,'first_difference':None,'verification_scope':'full'},
            live=SimpleNamespace(client_returncode=0,tests=1,completed_feedback_exchanges=1,statuses={},effective_search_seconds=0.01),
            join=dict(schema_version='compiled_F6_receipt_join.v1',path_id=binding['path_id'],source_id='cpu.f6.word0',rows=1,status='ok'),
            transport_files={},saved_output_hashes={},completed=True,scope='full')
        directory=kwargs['session_dir'];directory.mkdir()
        for name,value in [('online_session_manifest.json',manifest),('report.json',{'tests':1,'execution_status':'complete'})]:
            (directory/name).write_bytes(canonical(value))
        for name in ('seed.bin','receipts.jsonl','online_plan.json','online_final_trace.json'):(directory/name).write_bytes(b'{}')
        outcome['transport_files']={str(p):sha256(p.read_bytes()).hexdigest() for p in directory.iterdir() if p.name!='report.json'}
        documents=saved.expected_f6_documents(outcome)
        if late_swap=='expected_error':
            plan.update(completed=False,scope='failed_prefix_full',status='expected_error')
            replay['actual_prefix'].update(completed=False,scope='failed_prefix_full',status='expected_error')
            replay['verification_scope']='failed_prefix_full'
            outcome['verification']['verification_scope']='failed_prefix_full'
            outcome.update(completed=False,scope='failed_prefix_full',expected_error=True)
            documents=saved.expected_f6_failed_prefix_documents(outcome)
        for name,value in documents.items():saved.write_pinned_json(kwargs['output_dir']/name,value,outcome['saved_output_hashes'])
        return outcome
    monkeypatch.setattr(driver,'run_compiled_f6_session',session)
    writer=saved.write_pinned_json
    def write(path,value,pins):
        result=writer(path,value,pins)
        if late_swap=='capability' and path.name=='capability-report.json':path.write_bytes(path.read_bytes()+b' ')
        return result
    monkeypatch.setattr(saved,'write_pinned_json',write)
    def bundle(*,session_dir,bundle_dir):
        if late_swap in ('raw','typed','fresh','build'):
            path={'raw':session_dir/'seed.bin','typed':args['output']/'compiled_assertion_results.v1.json',
                'fresh':args['output']/'compiled_f6_fresh_events.json','build':args['output']/'compiled_f6_build_join.v1.json'}[late_swap]
            path.write_bytes(path.read_bytes()+b' ')
        if late_swap=='marker':args['f6_execution'].write_bytes(args['f6_execution'].read_bytes()+b' ')
        if late_swap=='delivery':args['f6_deliveries'].write_bytes(args['f6_deliveries'].read_bytes()+b' ')
        bundle_dir.mkdir();(bundle_dir/'bundle-manifest.json').write_text('{}');return {}
    monkeypatch.setattr(driver,'write_authenticated_bundle',bundle)
    report=driver.build_capability_report
    def checked_report(*a,**kw):
        assert kw['assertion_results'] is seen['material']['assertions']
        assert kw['assertion_evidence'] is seen['material']['assertion_evidence']
        actual=report(*a,**kw)
        baseline=report(*a,**{k:v for k,v in kw.items() if k not in ('assertion_results','assertion_evidence')})
        assert [p['tiers'] for p in actual['paths']]==[p['tiers'] for p in baseline['paths']]
        return actual
    monkeypatch.setattr(driver,'build_capability_report',checked_report)
    summary=driver.run_auto_harness_test(**args)
    assert 'material' in seen,summary['refusals']
    assert len(seen['material']['assertions']['cases'][0]['assertions'])==5
    assert summary['status']==('refused' if late_swap else 'complete'),summary['refusals']
    if late_swap=='expected_error':
        assert summary['stages']['session']['scope']=='failed_prefix_full'
        assert summary['fresh_replay']['verification_scope']=='failed_prefix_full'
        assert summary['executor']['detail']['completed'] is False
        assert summary['executor']['detail']['useful_search_benefit_claimed'] is False

def test_f6_file_entry_is_explicit_and_rounds_forward_without_rewrite(monkeypatch):
    from myfuzz.integration.compiled_execution_files import _FLOW_BY_EXECUTOR
    assert _FLOW_BY_EXECUTOR['compiled_f6_cpu_dma']=='F6'
    from myfuzz.local_harness import auto_harness_test as driver
    from myfuzz.integration import compiled_f6_rfuzz
    seen={}
    monkeypatch.setattr(compiled_f6_rfuzz,'run_compiled_f6_rfuzz_session',lambda **kw:seen.update(kw))
    artifacts={};inputs={}
    driver.run_compiled_f6_session(artifacts=artifacts,compiled_inputs=inputs,base_dir=ROOT,cache_dir=ROOT,
        run_id='r',session_dir=ROOT,output_dir=ROOT,client_binary=ROOT,budget_seconds=1,max_tests=1,
        search_seed=1,max_runs_per_batch=1,rounds_per_case=137)
    assert seen['rounds_per_case']==137 and seen['artifacts'] is artifacts and seen['compiled_inputs'] is inputs

from tests.integration.test_compiled_f6_saved_outputs import saved_outcome

@pytest.mark.parametrize('change',[None,'missing_pair','missing_binding','wrong_binding','cross_run','compiled_scope','extra_case'])
def test_f6_typed_report_requires_independent_pair_and_exact_binding_scope(saved_outcome,change):
    from myfuzz.scenario.capability_report import build_capability_report,CapabilityReportRefused
    outcome,harness,_=saved_outcome
    _,compiled,_=source_inputs()
    material=deepcopy(outcome['assertion_material'])
    if change=='missing_pair':material.pop('assertion_evidence')
    elif change=='missing_binding':material['assertion_evidence']['execution_binding']=None
    elif change=='wrong_binding':material['assertion_evidence']['execution_binding']['schema_version']='compiled_F2_execution_binding.v1'
    elif change=='cross_run':material['assertion_evidence']['run_id']='borrowed-run'
    elif change=='compiled_scope':material['assertions']['compiled_document_sha256']='0'*64
    elif change=='extra_case':material['assertions']['cases'].append({'case_id':'fabricated','assertions':[]})
    kwargs=dict(assertion_results=material['assertions'],assertion_evidence=material.get('assertion_evidence'))
    if change:
        with pytest.raises(CapabilityReportRefused):build_capability_report(compiled,**kwargs)
    else:
        report=build_capability_report(compiled,**kwargs)
        baseline=build_capability_report(compiled)
        assert [row['tiers'] for row in report['paths']]==[row['tiers'] for row in baseline['paths']]


def test_ordinary_capability_report_still_refuses_route_bearing_harness():
    from myfuzz.scenario.capability_report import _validate_harness_set,CapabilityReportRefused
    with pytest.raises(CapabilityReportRefused) as caught:
        _validate_harness_set({'schema_version':'harness_set.v2','wiring':{'schema_version':'wiring_contract.v2'}})
    assert caught.value.code=='capability-report-route-intent-unsupported'

@pytest.mark.parametrize('failure',['transfer_before_return','finish_hash_read'])
def test_f6_auto_driver_releases_provider_on_helper_or_final_pin_error(driver_declarations,tmp_path,monkeypatch,failure):
    from myfuzz.local_harness import auto_harness_test as driver
    from myfuzz.local_harness import generated_artifact_admission as admission
    monkeypatch.setattr('myfuzz.local_harness.plan.elaborate_profile',_saved_source_facts)
    monkeypatch.setattr('myfuzz.local_harness.runtime_renderer.elaborate_profile',_saved_source_facts)
    monkeypatch.setattr(driver,'run_compiled_f6_session',lambda **kw:pytest.fail('native constructor reached'))
    seen={};loader=admission.load_generated_artifacts
    def capture(**kwargs):
        loaded=loader(**kwargs);seen['artifacts']=loaded
        if failure=='transfer_before_return':
            path=kwargs['generated_root']/'wiring_contract.json'
            wire=json.loads(path.read_bytes());wire['windows'][0]['size']+=4;path.write_text(json.dumps(wire))
        return loaded
    monkeypatch.setattr(admission,'load_generated_artifacts',capture)
    digest=driver._sha256_file
    def pin_read(path):
        if failure=='finish_hash_read' and 'artifacts' in seen and path.name=='dma_endpoint_links.v1.json':
            seen['io_refused']=True;raise OSError('synthetic final pin read failure')
        return digest(path)
    monkeypatch.setattr(driver,'_sha256_file',pin_read)
    try:summary=driver.run_auto_harness_test(**dict(driver_declarations,output=tmp_path/'output'))
    except OSError:
        assert failure=='finish_hash_read'
    else:
        assert summary['status']=='refused' if failure=='transfer_before_return' else summary['status']=='complete'
    assert 'artifacts' in seen
    if failure=='finish_hash_read':assert seen.get('io_refused') is True
    with pytest.raises(admission.GeneratedArtifactRefused,match='same-call-provider-required'):
        admission.validated_f6_provider_credentials(seen['artifacts'])

@pytest.mark.parametrize('entry',['file','live'])
@pytest.mark.parametrize('outcome',['return','raise'])
def test_f6_owner_wrapper_preserves_result_or_primary_and_releases_once(monkeypatch,entry,outcome):
    """Wrapper control flow only: the owned execution boundary is synthetic."""
    from myfuzz.local_harness import generated_artifact_admission as admission
    from myfuzz.integration import compiled_execution_files as files,compiled_f6_rfuzz_session as live
    artifacts={};released=[];sentinel={'report':'same object'};primary=RuntimeError('original execution failure')
    primary.add_note('original note')
    monkeypatch.setattr(admission,'release_f6_provider_credentials',lambda actual:released.append(actual))
    def owned(**kwargs):
        assert kwargs['artifacts'] is artifacts
        if outcome=='raise':raise primary
        return sentinel
    if entry=='file':
        monkeypatch.setattr(files,'_run_f6_file_route_owned',owned)
        call=lambda:files._run_f6_file_route(output=ROOT,marker=ROOT,report={},artifacts=artifacts,inputs={},
            base=ROOT,cache_dir=ROOT,run_id='test',rounds=4096,max_cases=1,replay_count=1,records=[],
            lock_path=ROOT,check_sources=lambda:None)
    else:
        monkeypatch.setattr(live,'_run_f6_live_and_fresh_owned',owned)
        call=lambda:live.run_f6_live_and_fresh(artifacts=artifacts,compiled_inputs={},base_dir=ROOT,cache_dir=ROOT,
            run_id='test',session_dir=ROOT,output_dir=ROOT,client_binary=ROOT,budget_seconds=1,max_tests=1,
            search_seed=1,max_runs_per_batch=1,rounds_per_case=4096)
    if outcome=='raise':
        with pytest.raises(RuntimeError) as caught:call()
        assert caught.value is primary and primary.__notes__==['original note']
    else:assert call() is sentinel
    assert len(released)==1 and released[0] is artifacts
