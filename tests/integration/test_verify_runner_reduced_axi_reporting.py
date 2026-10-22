"""Software controls only; no generated binary is built or launched."""
import copy
import json
from pathlib import Path
import pytest
from scripts.verify_runner_reduced_axi_reporting import archive_files, verify_archive, compare_runs
from tests.scenario.test_runner_reduced_axi_stream import runtime, session_factory, runner


def recording(factory):
    r = runner(factory); r.begin_test('same-case'); r.step('alias-0'); r.finalize()
    config = r.identity_document()['reduced_axi_observation_streams'][0]
    return dict(events=json.loads(json.dumps(list(r.events))), config=config,
        runtime=r.sessions['alias-0']._artifact_document,
        report=r.reduced_axi_observation_reports()['alias-0'],
        execution=r.sessions['alias-0']._execution)


def test_archive_members_are_exact_and_external_manifest_required(tmp_path):
    source=tmp_path/'source'; source.write_bytes(b'original\x00bytes')
    archive=tmp_path/'archive'
    manifest=archive_files([source], archive)
    verify_archive(archive, manifest)
    member=archive/manifest['members'][0]['member']
    member.write_bytes(b'changed')
    with pytest.raises(ValueError): verify_archive(archive, manifest)


def test_archive_refuses_symlinks_and_escaping_members(tmp_path):
    source=tmp_path/'source'; source.write_text('bytes')
    link=tmp_path/'link';link.symlink_to(source)
    with pytest.raises(ValueError):archive_files([link],tmp_path/'archive')
    manifest=archive_files([source],tmp_path/'good')
    manifest['members'][0]['member']='../source'
    with pytest.raises(ValueError):verify_archive(tmp_path/'good',manifest)


def test_complete_originals_compare_and_tamper_is_rejected(session_factory):
    a=recording(session_factory); b=copy.deepcopy(a)
    result=compare_runs(a,b,require_distinct=False)
    assert result['equal'] and result['first_view']==result['fresh_view']
    broken=copy.deepcopy(b)
    next(e for e in broken['events'] if e.get('kind')=='reduced_axi_raw')['local_tick']=88
    with pytest.raises(ValueError):compare_runs(a,broken,require_distinct=False)
    broken=copy.deepcopy(b);broken['events'].pop()
    with pytest.raises(ValueError):compare_runs(a,broken,require_distinct=False)


def test_nonce_change_rehashes_every_dependency_without_dropping_rows(session_factory):
    from scripts.verify_runner_reduced_axi_reporting import normalized, EXECUTION
    a=recording(session_factory)
    view,_=normalized(a)
    b=copy.deepcopy(a); b['events']=view['events'];b['report']=view['report']
    b['config']['binding']=view['binding'];b['execution']=EXECUTION
    assert a['execution']!=b['execution']
    result=compare_runs(a,b,require_distinct=False)
    assert len(result['first_view']['events'])==len(a['events'])
    assert result['first_view_sha256']==result['fresh_view_sha256']
    assert result['first_rehash_audit'][1]['original']!=result['first_rehash_audit'][1]['rebuilt']


def test_independent_software_runner_prefix_is_exact(session_factory):
    a=recording(session_factory);b=recording(session_factory)
    assert compare_runs(a,b,require_distinct=False)['equal']


@pytest.mark.parametrize('mutation',['sidecar','seal','wire','type','extra_identity'])
def test_comparator_preserves_every_commitment_and_undeclared_field(session_factory,mutation):
    a=recording(session_factory);b=copy.deepcopy(a)
    if mutation=='sidecar':
        next(e for e in b['events'] if e.get('kind')=='reduced_axi_journal_binding')['observation_sha256']='0'*64
    elif mutation=='seal':
        next(e['operation'] for e in b['events'] if e.get('kind')=='reduced_axi_source_operation' and e['operation']['kind']=='seal')['payload']['prior_operation_chain_sha256']='0'*64
    elif mutation=='wire':
        next(e['operation'] for e in b['events'] if e.get('kind')=='reduced_axi_source_operation' and e['operation']['kind']=='receipt')['payload']['wire_reply']='RESULT bogus\n'
    elif mutation=='type':
        next(e for e in b['events'] if e.get('kind')=='reduced_axi_raw')['raw_sample']['local_tick']=True
    else:
        # An unrelated identity-shaped string is retained exactly; no recursive
        # substring replacement or blanket identity/hash removal is permitted.
        b['events'][0]['unrelated_execution_string']=a['execution']
    with pytest.raises(ValueError):compare_runs(a,b,require_distinct=False)


@pytest.mark.parametrize('fmt',['jsonl','zlib'])
def test_durable_external_trust_checked_before_consumer(session_factory,tmp_path,monkeypatch,fmt):
    import hashlib
    import scripts.verify_runner_reduced_axi_reporting as verifier
    from myfuzz.scenario.replay import ScenarioTrace
    from myfuzz.integration.scenario_rfuzz_live import _write_online_trace_jsonl,_write_online_trace_zlib
    a=recording(session_factory);a['local_ticks']={'alias-0':1}
    trace=ScenarioTrace('0'*64,'complete',a['events'],a['local_ticks'],'','1'*64)
    trust=dict(semantic_sha256=verifier.semantic_digest(a['events'],a['local_ticks'],'complete'))
    for name,writer in [('jsonl',_write_online_trace_jsonl),('zlib',_write_online_trace_zlib)]:
        directory=tmp_path/name;directory.mkdir();writer(directory,trace)
        path=directory/('online_events.'+name)
        trust[name+'_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(verifier,'verify_native_join',lambda run:{'scope':'software_only'})
    assert verifier.verify_durable(tmp_path,a,trust)['reports']['jsonl']==a['report']
    path=tmp_path/fmt/('online_events.'+fmt);path.write_bytes(path.read_bytes()+b'tamper')
    with pytest.raises(ValueError,match='external raw file hash mismatch'):
        verifier.verify_durable(tmp_path,a,trust)


def test_every_software_receipt_must_join_exact_passive_wire(session_factory,monkeypatch):
    import scripts.verify_runner_reduced_axi_reporting as verifier
    a=recording(session_factory)
    expected=session_factory()._expected_ready();a['expected_ready']=list(expected)
    a['wire']=[dict(direction='native',text=f'READY local_driver.v1 {expected[0]} {expected[1]:x} {expected[2]:x}\n')]
    a['samples']=[]
    for row in a['events']:
        if row.get('kind')=='reduced_axi_source_operation' and row['operation']['kind']=='receipt':
            p=row['operation']['payload']
            a['wire'].extend([dict(direction='host',text=p['wire_command']),dict(direction='native',text=p['wire_reply'])])
            a['samples'].extend(copy.deepcopy(p['receipt']['payload']['samples']))
    monkeypatch.setattr(verifier,'verify_physical',lambda samples:dict(scope='software_only',count=len(samples)))
    assert verifier.verify_native_join(a)['count']==1
    a['wire'][1]['text']=a['wire'][1]['text'].replace('CMD ','CMD  ',1)
    with pytest.raises(ValueError,match='actual/admitted command sequence mismatch'):verifier.verify_native_join(a)


def test_memory_wrapper_digest_is_rebuilt_from_complete_preimage(session_factory):
    import hashlib
    from dataclasses import asdict
    from myfuzz.scenario.ledger import TransactionKey
    import scripts.verify_runner_reduced_axi_reporting as verifier
    a=recording(session_factory)
    key=TransactionKey(a['execution'],'same-case','cpu',0,'data',1)
    cells=[['ram',0,53,[0,1],'store',str(key)]]
    encoded=b''.join(json.dumps(row,ensure_ascii=False,separators=(',',':')).encode()+b'\n' for row in cells)
    a.update(memory_preimages={'alias-0':cells},transaction_key_preimages=[dict(text=str(key),fields=asdict(key))],
        identity={'stable':'configuration'},final_state={'memories':{'alias-0':{'cells_sha256':hashlib.sha256(encoded).hexdigest()}},
        'reduced_axi_observations':{'alias-0':a['report']},'uncertain_transactions':[]})
    view,_=verifier.normalized(a)
    assert view['final_state']['memories']['alias-0']['cells_sha256']!=a['final_state']['memories']['alias-0']['cells_sha256']
    a['memory_preimages']['alias-0'][0][2]=54
    with pytest.raises(ValueError,match='original memory digest mismatch'):verifier.normalized(a)


def memory_recording(factory,nonce):
    """Real session/service/Runner mechanics with software wire transport only."""
    from scripts.verify_runner_reduced_axi_reporting import capture_transaction_preimages
    from myfuzz.scenario.memory_service import MemoryService
    from myfuzz.scenario.ledger import TransactionLedger
    r=runner(factory);cpu=r.sessions['alias-0'];cpu.starts=int(nonce,16)-1
    from myfuzz.scenario.memory import PersistentMemory,MemoryRegion
    from tests.local_harness.test_vexii_generated_cpu import PROGRAM,BOOT
    cpu.memory=PersistentMemory(regions=(MemoryRegion('ram',BOOT,0x100000),),initialization_seed=0,max_initialized_bytes=65536)
    cpu.memory.preload(BOOT,b''.join(word.to_bytes(4,'little') for word in PROGRAM))
    cpu.service=MemoryService(cpu.memory,TransactionLedger(),commit_stream_capacity=4)
    initial_memory_preimages={'alias-0':[[mid,offset,cell.value,cell.version,cell.writer_kind,cell.writer_event_id]
        for (mid,offset),cell in sorted(cpu.memory._bytes.items())]}
    r.enable_event_journal(chunk_size=2);r.begin_test('same-case')
    signals=[dict(i_arvalid=1,i_araddr=BOOT,i_arsize=2,i_arid=1),
        dict(i_rready=1,d_awvalid=1,d_awaddr=BOOT+0x100,d_awsize=2,d_awid=1,
             d_wvalid=1,d_wdata=53,d_wstrb=15,d_wlast=1),
        dict(d_bready=1,d_arvalid=1,d_araddr=BOOT+0x100,d_arsize=2,d_arid=1),
        dict(d_rready=1,i_arvalid=1,i_araddr=BOOT+0x40,i_arsize=2,i_arid=1),
        dict(i_rready=1,d_awvalid=1,d_awaddr=BOOT+0x104,d_awsize=2,d_awid=1,
             d_wvalid=1,d_wdata=54,d_wstrb=15,d_wlast=1),dict(d_bready=1)]
    for index,signal in enumerate(signals):
        cpu.signals=signal;r.step('alias-0')
        if index in (1,4):
            # Actual immutable service callback DTOs, imported by ordinary
            # service.events drain; this fixture grants no commit authority.
            issued=cpu.service.drain_commit_events()
            cpu.service.events.extend(issued)
            cpu.service.ack_commit_events(tuple(row['commit_id'] for row in issued))
    r.finalize()
    config=r.identity_document()['reduced_axi_observation_streams'][0]
    return json.loads(json.dumps(dict(events=list(r.events),config=config,
        runtime=cpu._artifact_document,report=r.reduced_axi_observation_reports()['alias-0'],
        execution=cpu._execution,identity={'stable':'software-fixture'},local_ticks=dict(r.local_ticks),
        final_state=r.final_state_document(),
        memory_preimages={'alias-0':[[mid,offset,cell.value,cell.version,cell.writer_kind,cell.writer_event_id]
            for (mid,offset),cell in sorted(cpu.memory._bytes.items())]},
        transaction_key_preimages=capture_transaction_preimages(cpu.service),initial_memory_preimages=initial_memory_preimages)))


def test_actual_memory_service_first_fresh_complete_global_journal(session_factory):
    a=memory_recording(session_factory,'1'*32);b=memory_recording(session_factory,'2'*32)
    kinds={e.get('kind') for e in a['events']}
    assert {'memory_initialization','memory_read','memory_write','memory_write_commit','state_dependency'}<=kinds
    result=compare_runs(a,b,require_distinct=False)
    assert result['equal']
    assert len(result['first_view']['events'])==len(a['events'])


@pytest.mark.parametrize('mutation',['missing','extra','changed','primitive'])
def test_original_final_report_map_cannot_be_erased(session_factory,mutation):
    import scripts.verify_runner_reduced_axi_reporting as verifier
    a=memory_recording(session_factory,'1'*32)
    reports=a['final_state']['reduced_axi_observations']
    if mutation=='missing':reports.clear()
    elif mutation=='extra':reports['forged-alias']=copy.deepcopy(a['report'])
    elif mutation=='changed':reports['alias-0']['pending']['i']['read']=True
    else:a['final_state']['reduced_axi_observations']=[]
    with pytest.raises(ValueError,match='original final-state report map'):verifier.normalized(a)


def test_build_snapshot_required_members_cannot_be_omitted_or_changed(tmp_path):
    import scripts.verify_runner_reduced_axi_reporting as verifier
    import hashlib
    snapshots={'src/myfuzz/local_harness/rtl/local_driver_v1.h':b'header1',
        'src/myfuzz/scenario/rtl/local_command_replay.h':b'header2',
        'configs/soc/sources.lock.json':b'lock', 'adapter/reduced.sv':b'adapter',
        'generated/driver.cpp':b'generated'}
    for name,data in snapshots.items():
        if not name.startswith('generated/'):
            path=tmp_path/'repo'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
    identity=dict(inputs=[dict(path=name,sha256=hashlib.sha256(data).hexdigest()) for name,data in sorted(snapshots.items())])
    archive=tmp_path/'snapshot'
    manifest=verifier.archive_build_snapshot(identity,snapshots,archive,tmp_path/'repo')
    verifier.verify_build_snapshot(archive,manifest,originals=True,identity=identity)
    broken=copy.deepcopy(manifest);broken['members'].pop()
    with pytest.raises(ValueError):verifier.verify_build_snapshot(archive,broken,identity=identity)
    path=archive/'configs/soc/sources.lock.json';path.write_bytes(b'changed')
    with pytest.raises(ValueError):verifier.verify_build_snapshot(archive,manifest,identity=identity)


@pytest.mark.parametrize('mutation',['foreign_transaction','foreign_writer','commit_digest','nested_fullkey','nested_cell','state_edge','address'])
def test_actual_memory_original_tamper_refuses_before_normalizing(session_factory,mutation):
    import scripts.verify_runner_reduced_axi_reporting as verifier
    run=memory_recording(session_factory,'1'*32)
    if mutation=='foreign_transaction':
        next(e for e in run['events'] if e.get('kind')=='memory_read')['transaction']['execution_id']='3'*32
    elif mutation=='foreign_writer':
        from myfuzz.scenario.ledger import TransactionKey
        read=next(e for e in run['events'] if e.get('kind')=='memory_read' and any(v.startswith('TransactionKey(') for v in e['writer_event_ids']))
        read['writer_event_ids'][0]=str(TransactionKey('3'*32,'same-case','cpu',0,'data',1))
    elif mutation=='commit_digest':
        next(e for e in run['events'] if e.get('kind')=='memory_write_commit')['commit_id']='0'*64
    elif mutation=='nested_fullkey':
        next(e for e in run['events'] if e.get('kind')=='memory_write_commit')['commit_document']['fullkey']['execution_id']='3'*32
    elif mutation=='nested_cell':
        next(e for e in run['events'] if e.get('kind')=='memory_write_commit')['commit_document']['enabled_byte_cells'][0]['value']^=1
    elif mutation=='state_edge':
        next(e for e in run['events'] if e.get('kind')=='state_dependency')['target']='forged'
    else:
        next(e for e in run['events'] if e.get('kind')=='memory_read')['address']+=4
    with pytest.raises(ValueError):verifier.normalized(run)


def test_actual_declared_build_capture_includes_every_header_lock_adapter(runtime,tmp_path):
    import scripts.verify_runner_reduced_axi_reporting as verifier
    from myfuzz.local_harness.build import _prepare
    from tests.local_harness.test_vexii_generated_cpu import ROOT
    identity,snapshots=_prepare(runtime,ROOT)  # Metadata/source capture; never compiles or launches RTL.
    required={'configs/soc/sources.lock.json','src/myfuzz/local_harness/rtl/local_driver_v1.h',
        'src/myfuzz/scenario/rtl/local_command_replay.h'}
    required.update(row['path'] for row in runtime.runtime_document['adapter_sources'])
    required.update(row['path'] for row in runtime.runtime_document.get('protocol_sources',[]))
    assert required<=set(snapshots)
    manifest=verifier.archive_build_snapshot(identity,snapshots,tmp_path/'archive',ROOT)
    assert {r['path'] for r in manifest['members']}==set(snapshots)
    verifier.verify_build_snapshot(tmp_path/'archive',manifest,originals=True,identity=identity)
    for name in required:
        broken=copy.deepcopy(manifest);broken['members']=[r for r in broken['members'] if r['path']!=name]
        with pytest.raises(ValueError):verifier.verify_build_snapshot(tmp_path/'archive',broken,identity=identity)


@pytest.mark.parametrize('mutation',['source_changed','escaping_path','extra_file','member_symlink'])
def test_build_snapshot_source_and_member_paths_are_audited(tmp_path,mutation):
    import hashlib
    import scripts.verify_runner_reduced_axi_reporting as verifier
    root=tmp_path/'repo';root.mkdir();(root/'header.h').write_bytes(b'header')
    identity={'inputs':[dict(path='header.h',sha256=hashlib.sha256(b'header').hexdigest())]}
    directory=tmp_path/'archive'
    manifest=verifier.archive_build_snapshot(identity,{'header.h':b'header'},directory,root)
    if mutation=='source_changed':(root/'header.h').write_bytes(b'changed')
    elif mutation=='escaping_path':manifest['members'][0]['path']='../header.h'
    elif mutation=='extra_file':(directory/'extra').write_bytes(b'extra')
    else:
        (directory/'header.h').unlink();(directory/'header.h').symlink_to(root/'header.h')
    with pytest.raises(ValueError):verifier.verify_build_snapshot(directory,manifest,originals=True)


@pytest.mark.parametrize('mutation',['unused_key','edge_parent','final_cell','local_ticks'])
def test_complete_original_memory_inventory_and_global_joins_refuse_tamper(session_factory,mutation):
    from myfuzz.scenario.ledger import TransactionKey
    import scripts.verify_runner_reduced_axi_reporting as verifier
    run=memory_recording(session_factory,'1'*32)
    if mutation=='unused_key':
        item=copy.deepcopy(run['transaction_key_preimages'][0]);item['fields']['source_sequence']=1000
        item['text']=str(TransactionKey(**item['fields']));item['receipt']['transaction_id']=item['text']
        run['transaction_key_preimages'].append(item)
    elif mutation=='edge_parent':next(e for e in run['events'] if e.get('kind')=='state_dependency')['producer_event_id']=1
    elif mutation=='final_cell':run['memory_preimages']['alias-0'][-1][2]^=1
    else:run['final_state']['local_ticks']['alias-0']+=1
    with pytest.raises(ValueError):verifier.normalized(run)


def test_actual_cache_input_bytes_are_archived_and_bound_to_prebuild(tmp_path):
    import hashlib
    import scripts.verify_runner_reduced_axi_reporting as verifier
    root=tmp_path/'repo';root.mkdir();(root/'header.h').write_bytes(b'header')
    snapshots={'header.h':b'header','generated/driver.cpp':b'generated'}
    identity={'inputs':[dict(path=k,sha256=hashlib.sha256(v).hexdigest()) for k,v in sorted(snapshots.items())]}
    prebuild=verifier.archive_build_snapshot(identity,snapshots,tmp_path/'prebuild',root)
    cache=tmp_path/'cache';cache.mkdir();binary=cache/'harness';binary.write_bytes(b'software inert file, never launched');binary.chmod(0o755)
    for name,data in snapshots.items():
        p=cache/'inputs'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
    (cache/'manifest.json').write_text(json.dumps(dict(identity=identity,binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())))
    archived=verifier.archive_validated_cache(binary,prebuild,tmp_path/'archive',tmp_path/'prebuild')
    result=verifier.verify_validated_cache_archive(tmp_path/'archive',archived,prebuild,tmp_path/'prebuild',originals=True)
    assert result['input_count']==2
    # The actual materialized cache bytes, copied archive bytes and original
    # source snapshot each have independent coverage and byte checks.
    (tmp_path/'archive/inputs/header.h').unlink()
    with pytest.raises(ValueError):verifier.verify_validated_cache_archive(tmp_path/'archive',archived,prebuild,tmp_path/'prebuild')
