"""Saved synthetic source-backed evidence verifies consistency, never native authority."""
from copy import deepcopy
from dataclasses import asdict
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import tarfile
import io
import sys
from types import SimpleNamespace
from unittest.mock import patch
import pytest

ROOT=Path(__file__).resolve().parents[2]


def module():
    path=ROOT/'scripts/verify_compiled_f2_rfuzz.py'
    assert path.is_file(),'F2 saved-evidence auditor missing'
    spec=importlib.util.spec_from_file_location('f2_saved_auditor',path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',', ':'),allow_nan=False).encode()
def digest(value):return sha256(canonical(value)).hexdigest()
def save(path,value):path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(canonical(value)+b'\n')


def save_source_origins(inv, sources):
    origins = {name:dict(is_symlink=(ROOT/name).is_symlink(),
        link_target=str((ROOT/name).readlink()) if (ROOT/name).is_symlink() else None,
        resolved_path=str((ROOT/name).resolve()),content_sha256=expected)
        for name, expected in sources.items()}
    for phase in ('before','after'):
        save(inv/('source-origins-'+phase+'.json'), origins)
        save(inv/('unavailable-symlinks-'+phase+'.json'), {})


@pytest.fixture(scope='module')
def saved_master(tmp_path_factory):
    from tests.integration.test_compiled_f4_storage_producer import timer_loaded
    from tests.integration.test_compiled_f2_rfuzz_feedback import observed
    from tests.integration.test_compiled_f2_read_response import _journal
    from myfuzz.integration.compiled_f2 import CompiledF2Runtime,CompiledF2ExecutionBinding
    from myfuzz.integration.compiled_f2_build_join import build_compiled_f2_build_join
    from myfuzz.integration.compiled_f2_feedback import f2_observation_targets
    from myfuzz.scenario.compiled_f2_decoder import CompiledF2Decoder
    from tests.integration.test_compiled_f4_built_wiring import fake_preparation
    from myfuzz.scenario.session_runtime import ScenarioSession,_trace_semantic_sha256
    from myfuzz.integration.compiled_f4 import normalized_semantic_sha256
    from myfuzz.scenario.replay import ScenarioTrace
    from myfuzz.integration.scenario_rfuzz_live import _write_online_run_identity,_canonical_json
    attempt=tmp_path_factory.mktemp('saved-f2-audit');out=attempt/'run';out.mkdir()
    generated=timer_loaded(out);artifacts,inputs=generated
    runtime,_,certificate=observed(generated)
    binding=runtime.execution_binding.document();receipts={}
    for name,artifact in artifacts.items():
        identity=dict(schema_version='local_harness_build_identity.v1',artifact_digest=artifact.runtime_document['artifact_digest'],inputs=[],toolchain={})
        identity['build_digest']=digest(identity)
        receipts[name]=dict(schema_version='local_harness_built_receipt.v1',artifact_digest=identity['artifact_digest'],build_digest=identity['build_digest'],build_identity=identity,binary_sha256=digest(name))
    binding.update(built_executable_receipts=receipts,built_executable_receipts_sha256=digest(receipts))
    runtime.execution_binding=CompiledF2ExecutionBinding.build(binding);binding=runtime.execution_binding.document()
    dec=CompiledF2Decoder.from_request(request=inputs['request'],compiled=inputs['compiled'],run_id='synthetic',schedule=('processor','peripheral'),rounds=32,result_address=0x3fffc)
    wire=runtime.path['execution_contract']['address'].to_bytes(4,'little')+bytes(4)
    candidate=dec.decode_candidate(wire,cursor=0x10000,case_index=0)
    certificate.update(execution_binding_sha256=runtime.execution_binding.digest,runtime_path_id=candidate.case.path_id,runtime_path_admission_sha256=dec.runtime_path_admission.digest,runtime_admitted=True)
    runtime.records=[dict(raw=candidate.candidate_bytes.hex(),value=candidate.address,source_values={candidate.source_id:candidate.address},certificate=certificate)]
    runs=[]
    for offset in (100,200):
        rows={name:dict(component=name,role='cpu' if name=='processor' else 'bound_target',pid=offset+i,execution_nonce=f'{offset}-{name}',artifact_digest=r['artifact_digest'],build_digest=r['build_digest'],binary_sha256=r['binary_sha256'],built_receipt_sha256=digest(r),observed_executable_sha256=r['binary_sha256'],ready_artifact_digest=r['artifact_digest']) for i,(name,r) in enumerate(receipts.items())}
        runs.append(dict(receipts=deepcopy(receipts),preparation_observations={name:{'outcome':'synthetic'} for name in receipts},execution_audit=dict(identities=rows,exits={name:dict(returncode=0,reaped=True) for name in receipts},closed=True)))
    build=build_compiled_f2_build_join(artifacts=artifacts,execution_binding=runtime.execution_binding,compiled_document_sha256=runtime.compiled_digest,runtime_path_id=candidate.case.path_id,logical_path_id=runtime.path['path_id'],original=runs[0],fresh=runs[1])
    captured=[]
    class BeforeNative(Exception):pass
    def stop(session):captured.append(deepcopy(session.runtime_path_document));raise BeforeNative()
    with fake_preparation(),patch.object(ScenarioSession,'begin',stop),pytest.raises(BeforeNative):
        CompiledF2Runtime(artifacts=artifacts,compiled_inputs=inputs,base_dir=ROOT,cache_dir=attempt/'synthetic-cache',rounds_per_case=32,max_cases=2)
    source=asdict(candidate.case.source);source['kind']='bound_instruction'
    online=dict(schema_version=24,runtime_paths=captured[0],instruction_image_bindings=[dec.runtime_path_admission.instruction_binding.document()],instruction_slots=[['processor',0x10000,(0x3fffc-0x10000)//4]],cases=[dict(case_id=candidate.case.case_id,direction=candidate.case.direction,path_id=candidate.case.path_id,source=source)])
    manifest=dict(runtime_paths=captured[0],instruction_image_bindings=online['instruction_image_bindings'],runner=dict(sessions={name:dict(identity=dict(runtime_artifact=artifacts[name].runtime_document,built_executable_receipt=r,build_identity=r['build_identity'])) for name,r in receipts.items()}),checker=dict(config=dict(execution_binding=binding,execution_binding_sha256=binding['binding_sha256'])))
    events=_journal(generated)['events'];ticks={'processor':100,'peripheral':100}
    semantic=normalized_semantic_sha256('complete',events,ticks)
    prefix=dict(schema_version='compiled_F2_prefix.v1',run_id='synthetic',compiled_sha256=runtime.compiled_digest,rounds_per_case=32,max_cases=2,records=runtime.records,execution_binding=binding,execution_binding_sha256=binding['binding_sha256'],artifact_digests=build['artifact_digests'],assertions=runtime.assertion_results(),online_plan=online,semantic_hash=semantic)
    replay=dict(matches=True,first_difference=None,verification_scope='full',scope='synthetic_saved_fixture_only',expected_semantic_hash=semantic,actual_semantic_hash=semantic,original_execution_audit=runs[0]['execution_audit'],execution_audit=runs[1]['execution_audit'])
    row=dict(run_id='synthetic',buffer_id=1,slot=0,raw_sha256=sha256(wire).hexdigest(),genome_sha256=sha256(wire[:4]).hexdigest(),flow_id='F2',path_id=runtime.path['path_id'],source_id=candidate.source_id,status='certified',coverage_hex='01'*6,online_raw_records_hex=[wire.hex()],online_source=dict(schema_version='compiled_F2_sequence.v1',path_id=candidate.path_id,source_id=candidate.source_id,candidates=[candidate.document()],candidate_count=1),candidate_count=1,wire_cycle_count=1)
    session=out/'session';session.mkdir();save(session/'online_plan.json',online);save(session/'decoder_manifest.json',dec.document());save(session/'targets.json',[asdict(target) for target in f2_observation_targets(runtime.path)])
    (session/'rfuzz.toml').write_text('# synthetic saved fixture\n');(session/'seed.bin').write_bytes(wire)
    (session/'receipts.jsonl').write_bytes(canonical(row)+b'\n')
    trace=ScenarioTrace(sha256((session/'online_plan.json').read_bytes()).hexdigest(),'complete',events,ticks,_trace_semantic_sha256('complete',events,ticks),sha256(_canonical_json(manifest)).hexdigest())
    save(session/'online_final_trace.json',asdict(trace))
    identity=_write_online_run_identity(session,session_manifest=manifest,plan_bytes=(session/'online_plan.json').read_bytes(),trace=trace,client_binary=Path('/usr/bin/true'),run_config={'synthetic_saved_fixture_only':True},frozen_inputs={'collector':None,'source_files':[],'client':{'binary_sha256':sha256(b'synthetic-client').hexdigest(),'synthetic_saved_fixture_only':True}})
    save(session/'report.json',dict(client_returncode=0,tests=1,statuses={'certified':1},online_run_identity_sha256=identity))
    join=dict(schema_version='compiled_F2_receipt_join.v1',status='ok',run_id='synthetic',path_id=candidate.path_id,source_id=candidate.source_id,compiled_sha256=runtime.compiled_digest,execution_binding_sha256=binding['binding_sha256'],receipts_sha256=sha256((session/'receipts.jsonl').read_bytes()).hexdigest(),rows=1,case_count=1,raw_record_count=1,candidate_bytes=4,wire_record_bytes=8,rejected_tests=0,cases=[dict(case_id=candidate.case.case_id,source_id=candidate.source_id,instruction_source_id=candidate.case.source.source_id,runtime_path_id=candidate.case.path_id,raw8_sha256=sha256(wire).hexdigest(),projected4_sha256=sha256(wire[:4]).hexdigest())])
    documents={'path_compile_request.json':dict(inputs['request'].document),'compiled_paths.v1.json':inputs['compiled'],'compiled_f2_prefix.json':prefix,'compiled_f2_fresh_prefix.json':deepcopy(prefix),'compiled_f2_replay.json':replay,'compiled_f2_fresh_events.json':events,'compiled_f2_fresh_execution_audit.json':replay['execution_audit'],'compiled_f2_fresh_verification.json':dict(matches=True,first_difference=None,verification_scope='full',actual_semantic_hash=semantic,expected_semantic_hash=semantic),'compiled_f2_build_join.v1.json':build,'compiled_f2_receipt_join.v1.json':join,'compiled_assertion_results.v1.json':runtime.assertion_results(),'compiled_assertion_evidence.v1.json':dict(execution_binding=binding,path_id=candidate.path_id,run_id='synthetic',cases=runtime.assertion_case_evidence()),'run-summary.json':dict(exit_code=0,refusals=[],executor={'requested':'compiled-f2-rfuzz','name':'compiled-f2-rfuzz'})}
    for name,value in documents.items():save(out/name,value)
    save(out/'generated/harness_set.json',dict(components=[dict(instance_id=name,artifact_digest=value) for name,value in build['artifact_digests'].items()]))
    inv=attempt/'invocation';inv.mkdir()
    source_files=list((ROOT/'configs').rglob('*.json'))+list((ROOT/'src/myfuzz').rglob('*.py'))+[ROOT/'scripts/verify_compiled_f2_rfuzz.py']
    sources={str(p.relative_to(ROOT)):sha256(p.read_bytes()).hexdigest() for p in source_files if p.is_file()}
    save(inv/'source-before.json',sources);save(inv/'source-after.json',sources)
    save_source_origins(inv, sources)
    with tarfile.open(inv/'executed-inputs.tar.gz','w:gz') as archive:
        for name in sources:archive.add(ROOT/name,arcname=name,recursive=False)
    save(inv/'command.json',dict(cwd=str(ROOT),argv=['python3','scripts/auto_harness_test.py','--executor','compiled-f2-rfuzz'],expected_exit_code=0,executables={'python':{'path':str(Path(sys.executable).resolve()),'sha256':sha256(Path(sys.executable).read_bytes()).hexdigest()},'rfuzz_client':{'path':'synthetic-not-launched','sha256':sha256(b'synthetic-client').hexdigest()}}))
    save(inv/'process.json',dict(pid=99999999,pgid=99999999))
    pins={str(p.relative_to(attempt)):sha256(p.read_bytes()).hexdigest() for p in attempt.rglob('*') if p.is_file() and not p.is_relative_to(inv)}
    save(inv/'output-initial.json',pins);save(inv/'output-final.json',pins)
    save(inv/'terminal.json',dict(pid=99999999,reaped=True,exit_code=0,expected_exit_code=0,exit_matches_expectation=True,timed_out=False,inputs_unchanged=True,source_origins_unchanged=True,unavailable_symlinks_unchanged=True,outputs_unchanged=True,archive_sha256=sha256((inv/'executed-inputs.tar.gz').read_bytes()).hexdigest(),synthetic_saved_fixture_only=True))
    return out


@pytest.fixture
def saved_run(saved_master):
    attempt=saved_master.parent
    original={p:p.read_bytes() for p in attempt.rglob('*') if p.is_file()}
    yield saved_master
    for path in attempt.rglob('*'):
        if path.is_symlink() or path.is_file() and path not in original:path.unlink()
    for path,raw in original.items():
        if path.is_symlink():path.unlink()
        path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)


def test_saved_source_backed_bundle_consistency_without_native_authority(saved_run):
    result=module().verify_saved_f2_run(saved_run,base_dir=ROOT)
    assert result['status']=='ok' and result['case_count']==1
    assert result['native_authority_issued'] is False


@pytest.mark.parametrize('name',['session/receipts.jsonl','compiled_assertion_results.v1.json','compiled_assertion_evidence.v1.json','compiled_f2_prefix.json','compiled_f2_fresh_prefix.json','compiled_f2_fresh_events.json','compiled_f2_fresh_execution_audit.json','compiled_f2_build_join.v1.json','compiled_f2_receipt_join.v1.json','session/online_session_manifest.json'])
@pytest.mark.parametrize('change',['semantic','format','missing'])
def test_external_byte_pins_refuse_substitution(saved_run,name,change):
    path=saved_run/name
    if change=='missing':path.unlink()
    elif change=='format':path.write_bytes(path.read_bytes()+b'\n')
    else:path.write_bytes(b'{}\n')
    with pytest.raises(ValueError):module().verify_saved_f2_run(saved_run,base_dir=ROOT)


@pytest.mark.parametrize('change',['marker','timeout','unreaped','exit','source-map','source-archive','traversal','symlink'])
def test_external_supervisor_and_path_refusals(saved_run,change):
    inv=saved_run.parent/'invocation'
    if change=='marker':(saved_run/'.incomplete').write_text('controlled')
    elif change=='source-archive':(inv/'executed-inputs.tar.gz').write_bytes(b'bad')
    elif change=='source-map':save(inv/'source-after.json',{})
    elif change=='traversal':save(inv/'output-final.json',{'../escape':'0'*64})
    elif change=='symlink':
        path=saved_run/'compiled_f2_prefix.json';path.unlink();path.symlink_to(saved_run/'compiled_f2_fresh_prefix.json')
    else:
        doc=json.loads((inv/'terminal.json').read_bytes());doc[{'timeout':'timed_out','unreaped':'reaped','exit':'exit_code'}[change]]={'timeout':True,'unreaped':False,'exit':2}[change];save(inv/'terminal.json',doc)
    with pytest.raises(ValueError):module().verify_saved_f2_run(saved_run,base_dir=ROOT)


def test_auditor_is_installed():
    assert callable(module().verify_saved_f2_run)


def test_coherent_process_binary_rehash_still_joins_built_receipt(saved_run):
    """Controlled supervisor-pin replacement exercises inner saved associations."""
    build_path=saved_run/'compiled_f2_build_join.v1.json';replay_path=saved_run/'compiled_f2_replay.json'
    build=json.loads(build_path.read_bytes());replay=json.loads(replay_path.read_bytes())
    component=next(iter(build['built_executable_receipts']))
    build['original']['execution_audit']['identities'][component]['binary_sha256']='0'*64
    replay['original_execution_audit']['identities'][component]['binary_sha256']='0'*64
    save(build_path,build);save(replay_path,replay)
    inv=saved_run.parent/'invocation'
    pins=json.loads((inv/'output-initial.json').read_bytes())
    for path in (build_path,replay_path):pins[str(path.relative_to(saved_run.parent))]=sha256(path.read_bytes()).hexdigest()
    save(inv/'output-initial.json',pins);save(inv/'output-final.json',pins)
    with pytest.raises(ValueError,match='binary|receipt|process'):
        module().verify_saved_f2_run(saved_run,base_dir=ROOT)


def test_external_client_binary_pin_must_match_saved_identity(saved_run):
    inv=saved_run.parent/'invocation';path=inv/'command.json'
    command=json.loads(path.read_bytes());command['executables']={'rfuzz_client':{'path':'controlled-client','sha256':'0'*64}}
    save(path,command)
    with pytest.raises(ValueError,match='client'):
        module().verify_saved_f2_run(saved_run,base_dir=ROOT)


def repin_saved_material(out):
    """Controlled ledger/identity rewrite tests inner semantic validation only."""
    from myfuzz.integration.scenario_rfuzz_live import _canonical_json
    session=out/'session';path=session/'online_run_identity.json';envelope=json.loads(path.read_bytes())
    for name in envelope['identity']['artifacts']:
        envelope['identity']['artifacts'][name]=sha256((session/name).read_bytes()).hexdigest()
    targets=json.loads((session/'targets.json').read_bytes())
    envelope['identity']['feedback']['targets_sha256']=sha256(_canonical_json(targets)).hexdigest()
    envelope['sha256']=sha256(_canonical_json(envelope['identity'])).hexdigest();save(path,envelope)
    report=json.loads((session/'report.json').read_bytes());report['online_run_identity_sha256']=envelope['sha256'];save(session/'report.json',report)
    inv=out.parent/'invocation';pins={str(p.relative_to(out.parent)):sha256(p.read_bytes()).hexdigest() for p in out.parent.rglob('*') if p.is_file() and not p.is_relative_to(inv)}
    save(inv/'output-initial.json',pins);save(inv/'output-final.json',pins)


@pytest.mark.parametrize('change',['certified','refused','targets'])
def test_independent_feedback_join_rejects_coherent_repin(saved_run,change):
    path=saved_run/'session/receipts.jsonl';row=json.loads(path.read_bytes());rows=[row]
    if change=='certified':row['coverage_hex']='ff'*6
    elif change=='targets':save(saved_run/'session/targets.json',[])
    else:
        refused=deepcopy(row);refused.update(slot=1,status='input_invalid',raw_sha256=sha256(bytes(8)).hexdigest(),genome_sha256=None,online_raw_records_hex=[bytes(8).hex()],coverage_hex='01'+'00'*5,candidate_count=0,rejection=dict(code='candidate-address-range',pointer='/records/address',detail={'reason':'address-range'}))
        refused['online_source']['candidates']=[];refused['online_source']['candidate_count']=0;rows.append(refused)
        report=json.loads((saved_run/'session/report.json').read_bytes());report['tests']=2;report['statuses']['input_invalid']=1;save(saved_run/'session/report.json',report)
    path.write_bytes(b''.join(canonical(r)+b'\n' for r in rows))
    join=json.loads((saved_run/'compiled_f2_receipt_join.v1.json').read_bytes());join.update(rows=len(rows),raw_record_count=len(rows),rejected_tests=len(rows)-1,receipts_sha256=sha256(path.read_bytes()).hexdigest());save(saved_run/'compiled_f2_receipt_join.v1.json',join)
    repin_saved_material(saved_run)
    with pytest.raises(ValueError,match='coverage|feedback|target'):
        module().verify_saved_f2_run(saved_run,base_dir=ROOT)


@pytest.mark.parametrize('change',['missing','changed'])
def test_auditor_source_attribution_requires_actual_frozen_code(saved_run,change):
    inv=saved_run.parent/'invocation';sources=json.loads((inv/'source-before.json').read_bytes())
    name='scripts/verify_compiled_f2_rfuzz.py'
    if change=='missing':sources.pop(name)
    modified=(ROOT/name).read_bytes()+b'\n# controlled archived previous-source substitution\n'
    if change=='changed':sources[name]=sha256(modified).hexdigest()
    with tarfile.open(inv/'executed-inputs.tar.gz','w:gz') as archive:
        for key in sources:
            raw=modified if key==name and change=='changed' else (ROOT/key).read_bytes()
            info=tarfile.TarInfo(key);info.size=len(raw);archive.addfile(info,io.BytesIO(raw))
    save(inv/'source-before.json',sources);save(inv/'source-after.json',sources)
    save_source_origins(inv, sources)
    terminal=json.loads((inv/'terminal.json').read_bytes());terminal['archive_sha256']=sha256((inv/'executed-inputs.tar.gz').read_bytes()).hexdigest();save(inv/'terminal.json',terminal)
    with pytest.raises(ValueError,match='source|auditor'):
        module().verify_saved_f2_run(saved_run,base_dir=ROOT)


def test_missing_external_client_pin_is_not_a_reduced_audit(saved_run):
    inv=saved_run.parent/'invocation';path=inv/'command.json';command=json.loads(path.read_bytes())
    command['executables'].pop('rfuzz_client');save(path,command)
    with pytest.raises(ValueError,match='client'):module().verify_saved_f2_run(saved_run,base_dir=ROOT)


def test_refusal_auditor_has_separate_closed_entry():
    assert callable(getattr(module(),'verify_saved_f2_refusal',None)), 'Expected-refusal audit API is absent'


@pytest.mark.parametrize('control', ('wrong-registration','incompatible-shape'))
def test_expected_refusal_has_closed_separate_audit(saved_run, control):
    """Synthetic supervisor, actual frozen constructor-guard/source declarations."""
    import shutil
    mod = module(); out = saved_run; inv = out.parent/'invocation'
    declarations = json.loads((ROOT/mod.DECLARATIONS).read_bytes())
    selected = declarations['expected_refusals'][control]
    proof = selected['preconstruction_proof']
    guard = json.loads((ROOT/proof['receipt']).read_bytes())
    # Remove completed-execution files: a refused run cannot carry them.
    for path in out.iterdir():
        if path.is_dir():shutil.rmtree(path)
        else:path.unlink()
    save(out/'run-summary.json', dict(exit_code=1, status='refused', refusals=guard['actual_refusals']))
    (out/'.incomplete').write_bytes(b'controlled refusal\n')
    sources = json.loads((inv/'source-before.json').read_bytes())
    guard_sources = json.loads((ROOT/proof['source_before']).read_bytes())
    sources.update(guard_sources)
    for name in (mod.DECLARATIONS, proof['receipt'], proof['source_before'], proof['source_after']):
        sources[name] = sha256((ROOT/name).read_bytes()).hexdigest()
    for name in (ROOT/'.superpowers/sdd/compiled-f2-rfuzz-entry-20261023/gates/inputs').rglob('*.json'):
        sources[str(name.relative_to(ROOT))] = sha256(name.read_bytes()).hexdigest()
    save(inv/'source-before.json',sources);save(inv/'source-after.json',sources)
    save_source_origins(inv, sources)
    with tarfile.open(inv/'executed-inputs.tar.gz','w:gz') as archive:
        for name in sources:
            raw = (ROOT/name).read_bytes()
            info=tarfile.TarInfo(name);info.size=len(raw);archive.addfile(info,io.BytesIO(raw))
    command=json.loads((inv/'command.json').read_bytes())
    command.update(expected_exit_code=1, argv=['python3','scripts/auto_harness_test.py',
        '--executor','compiled-f2-rfuzz','--compose',selected['fixture'],'--ip',selected['profile']])
    save(inv/'command.json',command)
    terminal=json.loads((inv/'terminal.json').read_bytes())
    terminal.update(exit_code=1,expected_exit_code=1,archive_sha256=sha256((inv/'executed-inputs.tar.gz').read_bytes()).hexdigest())
    save(inv/'terminal.json',terminal)
    def repin():
        pins={str(path.relative_to(out.parent)):sha256(path.read_bytes()).hexdigest()
            for path in out.parent.rglob('*') if path.is_file() and not path.is_relative_to(inv)}
        save(inv/'output-initial.json',pins);save(inv/'output-final.json',pins)
    repin()
    result=mod.verify_saved_f2_refusal(out,control=control,base_dir=ROOT)
    assert result['status']=='ok' and result['refusal']['constructor_called'] is False
    assert result['native_authority_issued'] is False
    with pytest.raises(ValueError):mod.verify_saved_f2_run(out,base_dir=ROOT)
    summary=json.loads((out/'run-summary.json').read_bytes());summary['refusals'][0]['code']='unrelated'
    save(out/'run-summary.json',summary);repin()
    with pytest.raises(ValueError,match='refusal-exact-code'):
        mod.verify_saved_f2_refusal(out,control=control,base_dir=ROOT)


@pytest.mark.parametrize('explicit_invocation', (False, True))
def test_audit_relative_paths_have_same_checks_as_absolute(saved_run, explicit_invocation):
    import os
    relative = Path(os.path.relpath(saved_run, Path.cwd()))
    arguments = {'base_dir': ROOT}
    if explicit_invocation:
        arguments['invocation'] = Path(os.path.relpath(saved_run.parent/'invocation', Path.cwd()))
    result=module().verify_saved_f2_run(relative, **arguments)
    assert result['status']=='ok' and result['case_count']==1
    assert result['native_authority_issued'] is False


def test_origin_and_unavailable_link_maps_must_match(saved_run):
    inv=saved_run.parent/'invocation'
    origins=json.loads((inv/'source-origins-after.json').read_bytes())
    key=next(iter(origins));origins[key]['resolved_path'] += '.different-origin'
    save(inv/'source-origins-after.json',origins)
    with pytest.raises(ValueError,match='origin'):
        module().verify_saved_f2_run(saved_run,base_dir=ROOT)


def test_unavailable_link_state_drift_is_not_an_input_byte_map_match(saved_run):
    inv=saved_run.parent/'invocation'
    save(inv/'unavailable-symlinks-after.json', {'third_party/unavailable.sv':dict(
        is_symlink=True,link_target='missing.sv',resolved_path=str(ROOT/'missing.sv'),
        content_sha256=None,unavailable_reason='target_missing',declared_source_file=False)})
    with pytest.raises(ValueError,match='unavailable'):
        module().verify_saved_f2_run(saved_run,base_dir=ROOT)
