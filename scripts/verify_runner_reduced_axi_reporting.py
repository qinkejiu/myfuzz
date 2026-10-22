#!/usr/bin/env python3
"""Scoped Task5 original replay, archive audit, and dependency-order comparison.

Only declared scope/wire identity paths change. The full global journal is retained.
Original validation precedes normalization; a normalized journal is replayed again.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import myfuzz.local_harness  # establish existing package initialization order
from myfuzz.scenario.reduced_axi_journal import ReducedAxiJournalConsumer

ENVELOPE={'event_id','producer_event_id','component'}
OBS={'reduced_axi_raw','reduced_axi_accept','reduced_axi_complete',
     'reduced_axi_write_join','reduced_axi_reset','reduced_axi_violation'}
EXECUTION='f'*32
RULES={'schema':'reduced_axi_comparison.v1', 'native_execution_paths':[
    'operation.payload.scope.execution_id','operation.payload.receipt.execution',
    'operation.payload.wire_command.token[1]','operation.payload.wire_reply.token[1]',
    'operation.observations[].scope.execution_id','operation.observations[].next_scope.execution_id',
    'original.scope.execution_id','original.next_scope.execution_id'],
    'binding_paths':['session_id','observer_stream_id'],
    'rehash':['binding_digest','content_digest','seal.prior_operation_chain_sha256',
              'sidecar.observation_sha256'],
    'memory_paths':{
        'memory_initialization':['transaction.execution_id','writer_event_id'],
        'memory_read':['transaction.execution_id','writer_event_ids[]'],
        'memory_write':['transaction.execution_id'],
        'memory_write_commit':['transaction.execution_id','commit_document.fullkey.execution_id','commit_document.enabled_byte_cells[].writer_event_id','commit_document.commit_id from exact complete preimage','commit_id equal nested commitment'],
        'memory_read_issuance':['fullkey.execution_id','writer_event_ids[]'],
        'state_dependency':['source','target; original full edge sequence reprojected via StateDependencyTracker'],
        'transaction_key_preimages':['fields.execution_id','text from exact TransactionKey fields','receipt.transaction_id','receipt.writer_event_ids[]','receipt.commit_document.fullkey.execution_id','receipt.commit_document.enabled_byte_cells[].writer_event_id','receipt.commit_document.commit_id']},
    'wrapper_paths':['final_state.reduced_axi_observations via rebuilt report','transaction_key_preimages[].fields.execution_id','memory_preimages[][][5] via exact validated TransactionKey text','final_state.memories.*.cells_sha256 from complete memory preimages','final_state.uncertain_transactions[] via exact validated TransactionKey text'],
    'preserved':'all global rows, event IDs, local references, ticks, pin payloads, wire payloadhex'}


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def digest(value):return hashlib.sha256(canonical(value)).hexdigest()


def require(condition, reason):
    if not condition:raise ValueError(reason)


def archive_files(paths, directory):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=False)
    members=[]
    for n,path in enumerate(sorted(set(map(Path,paths)),key=str)):
        require(not path.is_symlink() and path.is_file(),'archive source is not regular')
        data=path.read_bytes(); name=f'{n:06d}-{path.name}'
        (directory/name).write_bytes(data)
        members.append(dict(source=str(path.absolute()),member=name,size=len(data),sha256=hashlib.sha256(data).hexdigest()))
    return dict(schema_version='task5_selected_byte_archive.v1',members=members,
        scope='selected declared inputs and imported Python closure; not complete toolchain closure')


def verify_archive(directory, manifest, *, originals=False):
    directory=Path(directory); seen=set()
    for row in manifest['members']:
        name=row['member'];require(type(name) is str and Path(name).name==name and name not in ('.','..'),'unsafe member')
        require(name not in seen,'duplicate member');seen.add(name)
        path=directory/name
        require(not path.is_symlink() and path.is_file(),'archive member missing or symlink')
        data=path.read_bytes()
        require(len(data)==row['size'] and hashlib.sha256(data).hexdigest()==row['sha256'],'archive member mismatch')
        if originals:
            source=Path(row['source']);require(not source.is_symlink(),'source symlink drift')
            require(source.read_bytes()==data,'postrun source drift')
    require(set(p.name for p in directory.iterdir())==seen,'unexpected archive member')
    return dict(member_count=len(seen),manifest_sha256=digest(manifest))


def safe_relative(name):
    require(type(name) is str and bool(name),'build input path type')
    path=Path(name)
    require(not path.is_absolute() and '..' not in path.parts and '.' not in path.parts and path.as_posix()==name,'unsafe build input path')
    return path


def build_input_map(identity):
    rows=identity['inputs'];require(type(rows) is list and bool(rows),'build input manifest shape')
    result={}
    for row in rows:
        require(type(row) is dict and set(row)=={'path','sha256'},'build input identity row shape')
        safe_relative(row['path'])
        require(row['path'] not in result and re.fullmatch('[0-9a-f]{64}',row['sha256']) is not None,'duplicate/invalid build input identity')
        result[row['path']]=row['sha256']
    if 'build_digest' in identity:
        from myfuzz.local_harness.renderer import _sha
        require(identity['build_digest']==_sha({k:v for k,v in identity.items() if k!='build_digest'}),'build identity digest mismatch')
    return result


def checked_member(base,name):
    base=Path(base).absolute();path=base/safe_relative(name)
    require(path.resolve().is_relative_to(base.resolve()),'build member escapes root')
    cursor=path
    while cursor!=base:
        require(not cursor.is_symlink(),'build member symlink');cursor=cursor.parent
    return path


def archive_build_snapshot(identity,snapshots,directory,source_root):
    """Archive every exact build._prepare capture byte before compile/cache use."""
    expected=build_input_map(identity)
    require(set(snapshots)==set(expected),'declared build snapshot coverage mismatch')
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=False)
    source_root=Path(source_root).absolute();members=[]
    require(sum(len(raw) for raw in snapshots.values())<=1024**3,'1GiB declared build input budget')
    for name in sorted(expected):
        raw=snapshots[name]
        require(type(raw) is bytes and hashlib.sha256(raw).hexdigest()==expected[name],'declared build snapshot digest mismatch')
        generated=name.startswith('generated/')
        if not generated:
            source=checked_member(source_root,name)
            require(source.is_file() and source.read_bytes()==raw,'prebuild source snapshot mismatch')
        path=checked_member(directory,name);path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
        members.append(dict(path=name,size=len(raw),sha256=expected[name],generated=generated))
    return dict(schema_version='task5_exact_declared_build_snapshot.v1',identity=deepcopy(identity),
        source_root=str(source_root),members=members,
        scope='exact build._prepare capture map including generated inputs; compiler/linker/OS toolchain closure excluded')


def verify_build_snapshot(directory,manifest, *, originals=False,identity=None):
    require(manifest['schema_version']=='task5_exact_declared_build_snapshot.v1','build snapshot schema')
    expected=build_input_map(manifest['identity'])
    if identity is not None:require(canonical(identity)==canonical(manifest['identity']),'actual/prebuild build identity mismatch')
    seen=set();directory=Path(directory)
    for member in manifest['members']:
        require(type(member) is dict and set(member)=={'path','size','sha256','generated'},'build snapshot member shape')
        name=member['path'];require(name in expected and name not in seen,'undeclared/duplicate build snapshot member');seen.add(name)
        require(member['generated'] is name.startswith('generated/'),'build snapshot generated marker mismatch')
        path=checked_member(directory,name);require(path.is_file(),'declared build input missing')
        data=path.read_bytes()
        require(len(data)==member['size'] and member['sha256']==expected[name]==hashlib.sha256(data).hexdigest(),'declared build input bytes mismatch')
        if originals and not member['generated']:
            source=checked_member(manifest['source_root'],name)
            require(source.is_file() and source.read_bytes()==data,'postrun declared build source changed')
    require(seen==set(expected),'declared build snapshot missing member')
    actual={p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file() or p.is_symlink()}
    require(actual==seen,'declared build snapshot tree mismatch')
    return dict(member_count=len(seen),identity_sha256=digest(manifest['identity']),manifest_sha256=digest(manifest))


def freeze_declared_build(artifact,source_root,directory):
    from myfuzz.local_harness.build import _prepare
    identity,snapshots=_prepare(artifact,source_root)
    manifest=archive_build_snapshot(identity,snapshots,directory,source_root)
    verify_build_snapshot(directory,manifest,originals=True,identity=identity)
    return manifest


def archive_validated_cache(binary,prebuild,directory,prebuild_directory):
    from myfuzz.local_harness.build import _validate_cache
    binary=Path(binary);identity=prebuild['identity'];cache=binary.parent
    require(_validate_cache(cache,identity)==binary,'actual validated binary mismatch')
    if 'build_digest' in identity:require(cache.name==identity['build_digest'],'actual cache directory identity mismatch')
    require({p.relative_to(cache/'inputs').as_posix() for p in (cache/'inputs').rglob('*') if p.is_file() or p.is_symlink()}==set(build_input_map(identity)),'actual cache input tree mismatch')
    snapshots={name:checked_member(cache/'inputs',name).read_bytes() for name in build_input_map(identity)}
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=False)
    # Here inputs are copied from the actual validated compiler/cache tree, not
    # reconstructed from repository hashes or from the earlier prebuild archive.
    inputs=archive_build_snapshot(identity,snapshots,directory/'inputs',prebuild['source_root'])
    artifacts=archive_files([binary,cache/'manifest.json'],directory/'artifacts')
    result=dict(schema_version='task5_validated_cache_archive.v1',inputs=inputs,artifacts=artifacts)
    verify_validated_cache_archive(directory,result,prebuild,prebuild_directory,originals=True)
    return result


def verify_validated_cache_archive(directory,manifest,prebuild,prebuild_directory, *, originals=False):
    require(manifest['schema_version']=='task5_validated_cache_archive.v1','validated cache archive schema')
    directory=Path(directory)
    verify_build_snapshot(prebuild_directory,prebuild,originals=originals)
    verify_build_snapshot(directory/'inputs',manifest['inputs'],originals=originals,identity=prebuild['identity'])
    for member in prebuild['members']:
        name=member['path']
        require(checked_member(directory/'inputs',name).read_bytes()==checked_member(prebuild_directory,name).read_bytes(),'actual/prebuild input byte mismatch')
    verify_archive(directory/'artifacts',manifest['artifacts'],originals=originals)
    members=manifest['artifacts']['members']
    binary=next((m for m in members if Path(m['source']).name=='harness'),None)
    build=next((m for m in members if Path(m['source']).name=='manifest.json'),None)
    require(len(members)==2 and binary is not None and build is not None,'validated cache artifacts coverage')
    actual=json.loads((directory/'artifacts'/build['member']).read_bytes())
    require(canonical(actual['identity'])==canonical(prebuild['identity']) and actual['binary_sha256']==binary['sha256'],'actual cache manifest bytes mismatch')
    return dict(input_count=len(prebuild['members']),binary_sha256=binary['sha256'],cache_manifest_sha256=build['sha256'])


def replay(run, events=None, binding=None):
    config=run['config']; consumer=ReducedAxiJournalConsumer(binding or config['binding'],
        runner_component=config['runner_component'],runtime_document=run['runtime'],limits=config['consumer_limits'])
    for row in run['events'] if events is None else events:consumer.consume(row)
    report=consumer.finalize()
    require(report['status']=='complete',f'original/rebuilt replay refused: {report}')
    return report


def validate_original(run):
    require(re.fullmatch('[0-9a-f]{32}',run['execution']) is not None,'invalid launch execution')
    report=replay(run)
    require(canonical(report)==canonical(run['report']),'live/durable report mismatch')
    operations=[e['operation'] for e in run['events'] if e.get('kind')=='reduced_axi_source_operation']
    scopes=[o['payload']['scope']['execution_id'] for o in operations if o['kind']=='begin_scope']
    require(scopes==[run['execution']],'launch/scope mismatch')
    require(operations[-1]['kind']=='seal','missing terminal seal')
    if 'final_state' in run:
        from myfuzz.scenario.observation_stream import _validate_json
        final=run['final_state'];require(type(final) is dict,'original final-state report map: final-state type')
        reports=final.get('reduced_axi_observations');_validate_json(reports)
        require(type(reports) is dict and canonical(reports)==canonical({run['config']['runner_component']:report}),'original final-state report map mismatch')
        if 'local_ticks' in final or 'local_ticks' in run:
            require(type(run.get('local_ticks')) is dict and set(run['local_ticks'])=={run['config']['runner_component']}
                and canonical(final.get('local_ticks'))==canonical(run['local_ticks']),'original final-state local ticks mismatch')
    memory_context(run)
    return report


def capture_transaction_preimages(service):
    """Detached actual completed ledger receipts, never invented journal facts."""
    from dataclasses import asdict
    from myfuzz.scenario.memory import ReadSnapshot
    from myfuzz.scenario.memory_service import WriteReceipt
    rows=[]
    for key,entry in service.ledger._entries.items():
        require(entry.status=='complete','incomplete actual memory ledger')
        receipt=entry.receipt
        if type(receipt) is ReadSnapshot:
            document=dict(kind='read',transaction_id=receipt.transaction_id,
                memory_id=receipt.memory_id,generation=receipt.generation,byte_offset=receipt.byte_offset,
                data_hex=receipt.data.hex(),value=receipt.value,versions=[list(v) for v in receipt.versions],
                writer_event_ids=list(receipt.writer_event_ids),writer_kinds=list(receipt.writer_kinds),
                materialized_offsets=list(receipt.materialized_offsets))
        else:
            require(type(receipt) is WriteReceipt,'unsupported actual memory receipt')
            document=dict(kind='write',commit_document=receipt.commit_document())
        rows.append(dict(text=str(key),fields=asdict(key),payload_sha256=entry.payload_digest,receipt=document))
    return rows


def memory_context(run):
    """Validate exact original service/commit/dependency DTOs before any mapping."""
    from dataclasses import asdict
    from myfuzz.scenario.ledger import TransactionKey,TransactionLedger
    from myfuzz.scenario.observation_stream import _validate_json
    from myfuzz.scenario.state_dependency import StateDependencyTracker
    fields_set=set(TransactionKey.__dataclass_fields__)
    operations=[e['operation'] for e in run['events'] if e.get('kind')=='reduced_axi_source_operation']
    scope=next(o['payload']['scope'] for o in operations if o['kind']=='begin_scope')
    entries={};by_fields={};replacements={}
    for item in run.get('transaction_key_preimages',[]):
        require(type(item) is dict and set(item) in ({'text','fields'},{'text','fields','payload_sha256','receipt'}),'transaction key preimage shape')
        fields=item['fields'];_validate_json(fields)
        require(type(fields) is dict and set(fields)==fields_set,'transaction key fields shape')
        require(all(type(fields[k]) is str and fields[k] for k in ('execution_id','testcase_id','source_component','channel_id'))
            and fields['channel_id'] in ('instr','data')
            and all(type(fields[k]) is int and 0<=fields[k]<2**64 for k in ('source_epoch','source_sequence')),'transaction key primitive types')
        key=TransactionKey(**fields)
        require(str(key)==item['text'] and item['text'] not in entries,'transaction key preimage mismatch')
        require(fields['execution_id']==run['execution'] and fields['source_component']==run['config']['binding']['source_component']
            and fields['testcase_id']==scope['testcase_id'] and fields['source_epoch']==scope['reset_epoch'],'transaction key scope mismatch')
        entries[item['text']]=item;by_fields[canonical(fields)]=item
        mapped=dict(fields,execution_id=EXECUTION);replacements[item['text']]=str(TransactionKey(**mapped))
    def transaction(fields):
        _validate_json(fields)
        require(type(fields) is dict and set(fields)==fields_set and canonical(fields) in by_fields,'foreign or altered transaction key')
        return by_fields[canonical(fields)]
    def writer(text):
        require(type(text) is str and bool(text),'writer reference type')
        require(not text.startswith('TransactionKey(') or text in entries,'foreign writer transaction key')
    def commit_document(document,item):
        require(type(document) is dict and document.get('schema_version')=='memory_write_commit_receipt.v1','commit schema')
        require(transaction(document['fullkey']) is item,'commit fullkey mismatch')
        require(document['commit_id']==digest({k:v for k,v in document.items() if k!='commit_id'}),'original commit digest mismatch')
        if 'receipt' in item:
            require(item['receipt']['kind']=='write' and canonical(document)==canonical(item['receipt']['commit_document']),'commit callback preimage mismatch')
            require(document['payload_sha256']==item['payload_sha256'],'commit payload digest mismatch')
        for cell in document['enabled_byte_cells']:
            writer(cell['writer_event_id']);require(cell['writer_event_id']==item['text'],'commit cell writer mismatch')
    # First validate all captured commit preimages, even if commit streaming was disabled.
    for item in entries.values():
        if item.get('receipt',{}).get('kind')=='write':commit_document(item['receipt']['commit_document'],item)
        elif 'receipt' in item:
            receipt=item['receipt'];require(receipt['kind']=='read' and receipt['transaction_id']==item['text'],'read callback preimage mismatch')
            for text in receipt['writer_event_ids']:writer(text)
    tracker=StateDependencyTracker();expected_edges=[];actual_edges=[];seen_memory=set();read_rows={}
    memory_events=any(e.get('kind') in ('memory_read','memory_write') for e in run['events'])
    cells={};alias=run['config']['runner_component']
    if memory_events:
        initial=run.get('initial_memory_preimages')
        require(type(initial) is dict and set(initial)=={alias},'initial memory preimages missing')
        for cell in initial[alias]:
            require(type(cell) is list and len(cell)==6 and (cell[0],cell[1]) not in cells,'initial memory cell shape/duplicate')
            require(cell[4]=='INITIAL_IMAGE' and cell[5]=='initial-image','unsupported initial memory cell origin')
            cells[(cell[0],cell[1])]=deepcopy(cell)
    commit_count=0

    for event in run['events']:
        kind=event.get('kind')
        if kind in ('memory_initialization','memory_read','memory_write','memory_write_commit'):
            require(event.get('component')==run['config']['runner_component'],'foreign memory component')
            item=transaction(event['transaction']);require('receipt' in item,'memory callback preimage missing')
            receipt=item['receipt']
            if kind=='memory_initialization':
                require(receipt['kind']=='read','initialization callback kind')
                lane=event['byte_offset']-receipt['byte_offset']
                require(event['byte_offset'] in receipt['materialized_offsets'] and 0<=lane<len(receipt['versions']),'initialization callback offset')
                require(event['memory_id']==receipt['memory_id'] and event['generation']==receipt['generation']
                    and event['value']==bytes.fromhex(receipt['data_hex'])[lane]
                    and canonical(event['version'])==canonical(receipt['versions'][lane])
                    and event['writer_event_id']==receipt['writer_event_ids'][lane],'initialization callback mismatch')
                writer(event['writer_event_id'])
                require(event['writer_event_id']==f"init:{event['memory_id']}:{event['byte_offset']}",'initialization writer origin')
                coordinate=(event['memory_id'],event['byte_offset'])
                require(coordinate not in cells,'initialization overwrites existing byte')
                cells[coordinate]=[event['memory_id'],event['byte_offset'],event['value'],event['version'],'FIRST_READ',event['writer_event_id']]
            elif kind=='memory_read':
                require(receipt['kind']=='read','read callback kind')
                for name in ('memory_id','generation','byte_offset','value','data_hex','versions','writer_event_ids'):
                    require(canonical(event[name])==canonical(receipt[name]),'read callback mismatch:'+name)
                if 'writer_kinds' in event:require(event['writer_kinds']==receipt['writer_kinds'],'read writer kinds mismatch')
                payload=dict(op='read',address=event['address'],width_bytes=event['width_bytes'])
                require(event['width_bytes']==len(bytes.fromhex(event['data_hex'])) and TransactionLedger._digest(payload)==item['payload_sha256'],'read payload mismatch')
                for text in event['writer_event_ids']:writer(text)
                for lane,value in enumerate(bytes.fromhex(event['data_hex'])):
                    actual=cells.get((event['memory_id'],event['byte_offset']+lane))
                    require(actual is not None and canonical(actual[2:])==canonical([value,event['versions'][lane],receipt['writer_kinds'][lane],event['writer_event_ids'][lane]]),'read byte/version/writer has no original prior memory origin')
                require(item['text'] not in read_rows,'duplicate memory read');read_rows[item['text']]=event
            elif kind=='memory_write':
                require(receipt['kind']=='write','write callback kind');document=receipt['commit_document']
                payload=dict(op='write',address=event['address'],value=event['value'],width_bytes=event['width_bytes'],byte_enable=event['byte_enable'])
                require(TransactionLedger._digest(payload)==item['payload_sha256'],'write payload mismatch')
                for name in ('memory_id','generation','byte_offset','width_bytes','byte_enable','version'):
                    require(canonical(event[name])==canonical(document[name]),'write callback mismatch:'+name)
                expected_cells=[]
                for lane in range(event['width_bytes']):
                    if event['byte_enable']>>lane&1:
                        cell=[event['memory_id'],event['byte_offset']+lane,(event['value']>>(lane*8))&255,event['version'],'STORE',item['text']]
                        cells[(cell[0],cell[1])]=cell
                        expected_cells.append(dict(byte_offset=cell[1],value=cell[2],version=cell[3],writer_kind=cell[4],writer_event_id=cell[5]))
                require(canonical(document['enabled_byte_cells'])==canonical(expected_cells),'write enabled-cell preimage mismatch')
            else:
                commit_document(event['commit_document'],item)
                require(event.get('schema_version')=='memory_write_commit.v1' and event['commit_id']==event['commit_document']['commit_id'],'commit envelope mismatch')
                commit_count+=1
                require(type(event['service_commit_sequence']) is int and event['service_commit_sequence']==commit_count,'commit sequence mismatch')
            if kind in ('memory_read','memory_write'):
                require(item['text'] not in seen_memory,'duplicate memory service transaction');seen_memory.add(item['text'])
                before=len(tracker.edges);tracker.ingest([event])
                expected_edges.extend([dict(asdict(edge),kind='state_dependency',edge_kind=edge.kind,event_id=event['event_id']+n,producer_event_id=event['event_id']) for n,edge in enumerate(tracker.edges[before:],1)])
        elif kind=='state_dependency':
            actual_edges.append(event)
            writer(event['source']);writer(event['target'])
        elif kind=='memory_read_issuance':
            require(event.get('schema_version')=='memory_read_authority.v1' and event.get('status')=='accepted','read issuance schema')
            item=transaction(event['fullkey']);source=read_rows.get(item['text'])
            require(source is not None,'read issuance has no original read')
            for name in ('address','width_bytes','memory_id','generation','byte_offset','value','data_hex','versions','writer_event_ids'):
                require(canonical(event[name])==canonical(source[name]),'read issuance mismatch:'+name)
            for text in event['writer_event_ids']:writer(text)
    # StateEdge.kind became edge_kind in the actual global journal.
    require(canonical(actual_edges)==canonical(expected_edges),'state dependency projection mismatch')
    if memory_events:
        require(seen_memory==set(entries),'ledger/service transaction inventory mismatch')
        require(type(run.get('memory_preimages')) is dict and set(run['memory_preimages'])=={alias},'final memory preimage coverage')
        require(canonical([cells[k] for k in sorted(cells)])==canonical(run['memory_preimages'][alias]),'final memory byte/version/writer origin mismatch')
    return entries,replacements


def verify_dependency_projection(events):
    from dataclasses import asdict
    from myfuzz.scenario.state_dependency import StateDependencyTracker
    tracker=StateDependencyTracker();expected=[];actual=[]
    for row in events:
        if row.get('kind') in ('memory_read','memory_write'):
            before=len(tracker.edges);tracker.ingest([row])
            expected.extend(dict(asdict(edge),kind='state_dependency',edge_kind=edge.kind,
                event_id=row['event_id']+n,producer_event_id=row['event_id']) for n,edge in enumerate(tracker.edges[before:],1))
        elif row.get('kind')=='state_dependency':actual.append(row)
    require(canonical(actual)==canonical(expected),'normalized state dependency projection mismatch')


def map_commit(document,replacements):
    document['fullkey']['execution_id']=EXECUTION
    for cell in document['enabled_byte_cells']:
        cell['writer_event_id']=replacements.get(cell['writer_event_id'],cell['writer_event_id'])
    document['commit_id']=digest({k:v for k,v in document.items() if k!='commit_id'})


def map_memory_event(row,replacements):
    kind=row.get('kind')
    if kind in ('memory_initialization','memory_read','memory_write','memory_write_commit'):
        row['transaction']['execution_id']=EXECUTION
        if kind=='memory_initialization':row['writer_event_id']=replacements.get(row['writer_event_id'],row['writer_event_id'])
        elif kind=='memory_read':row['writer_event_ids']=[replacements.get(v,v) for v in row['writer_event_ids']]
        elif kind=='memory_write_commit':
            map_commit(row['commit_document'],replacements);row['commit_id']=row['commit_document']['commit_id']
    elif kind=='memory_read_issuance':
        row['fullkey']['execution_id']=EXECUTION
        row['writer_event_ids']=[replacements.get(v,v) for v in row['writer_event_ids']]
    elif kind=='state_dependency':
        for name in ('source','target'):row[name]=replacements.get(row[name],row[name])


def normalized(run):
    """Return consumer-valid full journal and complete derived report."""
    validate_original(run)
    events=deepcopy(run['events']);binding=deepcopy(run['config']['binding'])
    binding['session_id']='runner-session-1';binding['observer_stream_id']='runner-stream-1'
    old=run['execution']; chain=digest(binding);audit=[]
    entries,replacements=memory_context(run)
    def scope(s):
        if s is not None:
            require(s['execution_id']==old,'unknown scope execution');s['execution_id']=EXECUTION
    def observation(row):
        scope(row['scope'])
        if 'next_scope' in row:scope(row['next_scope'])
    originals={}
    for row in events:
        kind=row.get('kind')
        if kind=='reduced_axi_stream_binding':row['binding']=deepcopy(binding)
        elif kind=='reduced_axi_source_operation':
            op=row['operation'];p=op['payload'];scope(p['scope'])
            if op['kind']=='receipt':
                require(p['receipt']['execution']==old,'unknown receipt execution')
                p['receipt']['execution']=EXECUTION
                for field in ('wire_command','wire_reply'):
                    wire=p[field];tokens=wire[:-1].split(' ')
                    require(wire.endswith('\n') and tokens[1]==old,'wire scope mismatch')
                    tokens[1]=EXECUTION;p[field]=' '.join(tokens)+'\n'
            for observation_row in op['observations']:observation(observation_row)
            if op['kind']=='seal':p['prior_operation_chain_sha256']=chain
            before=op['content_digest'];op['binding_digest']=digest(binding)
            op['content_digest']=digest({k:v for k,v in op.items() if k!='content_digest'})
            audit.append(dict(event_id=row['event_id'],original=before,rebuilt=op['content_digest'],preimage_sha256=op['content_digest']))
            chain=hashlib.sha256((chain+':'+op['content_digest']).encode('ascii')).hexdigest()
        elif kind in OBS:
            observation(row); originals[row['event_id']]={k:v for k,v in row.items() if k not in ENVELOPE}
        elif kind=='reduced_axi_journal_binding':row['observation_sha256']=digest(originals[row['observation_event_id']])
        else:map_memory_event(row,replacements)
    verify_dependency_projection(events)
    report=replay(run,events,binding)
    view=dict(binding=binding,events=events,report=report)
    if 'final_state' in run:
        keys=deepcopy(run['transaction_key_preimages'])
        for item in keys:
            item['fields']['execution_id']=EXECUTION;item['text']=replacements[item['text']]
            if item.get('receipt',{}).get('kind')=='write':map_commit(item['receipt']['commit_document'],replacements)
            elif 'receipt' in item:
                item['receipt']['transaction_id']=item['text']
                item['receipt']['writer_event_ids']=[replacements.get(v,v) for v in item['receipt']['writer_event_ids']]
        final=deepcopy(run['final_state']);memory=deepcopy(run['memory_preimages'])
        def memory_hash(rows):
            return hashlib.sha256(b''.join(json.dumps(row,ensure_ascii=False,separators=(',',':')).encode('utf8')+b'\n' for row in rows)).hexdigest()
        require(set(memory)==set(final['memories']),'memory preimage coverage')
        for alias,rows in memory.items():
            require(memory_hash(rows)==final['memories'][alias]['cells_sha256'],'original memory digest mismatch')
            for row in rows:
                if row[5] in replacements:row[5]=replacements[row[5]]
            final['memories'][alias]['cells_sha256']=memory_hash(rows)
        final['reduced_axi_observations']={run['config']['runner_component']:report}
        for key in final['uncertain_transactions']:require(key in replacements,'unknown uncertain transaction key')
        final['uncertain_transactions']=[replacements[key] for key in final['uncertain_transactions']]
        if 'initial_memory_preimages' in run:view['initial_memory_preimages']=deepcopy(run['initial_memory_preimages'])
        view.update(final_state=final,memory_preimages=memory,transaction_key_preimages=keys,identity=deepcopy(run['identity']))
    return view,audit


def compare_runs(first,fresh, *, require_distinct=True):
    if require_distinct:
        require(first['execution']!=fresh['execution'],'native execution reused')
        for run in (first,fresh):
            require(all(k in run for k in ('final_state','memory_preimages','transaction_key_preimages','identity','initial_memory_preimages')),'native comparison wrapper preimages missing')
            proc=run['process'];require(proc['execution']==run['execution'],'process execution mismatch');require(type(proc['pid']) is int and proc['pid']>0 and proc['reaped'] and type(proc['returncode']) is int,'process not reaped')
        require(first['process']['pid']!=fresh['process']['pid'],'native PID reused')
    for key in ('runner_component','stream_ordinal','source_limits','consumer_limits'):
        require(first['config'][key]==fresh['config'][key],f'stable config mismatch: {key}')
    require(first['runtime']==fresh['runtime'],'runtime differs')
    a,aa=normalized(first);b,ba=normalized(fresh)
    require(canonical(a)==canonical(b),'full normalized prefix differs')
    return dict(equal=True,rules=RULES,rules_sha256=digest(RULES),
        bijection=dict(native_executions=[[first['execution'],fresh['execution'],EXECUTION]],
            sessions=[[first['config']['binding']['session_id'],fresh['config']['binding']['session_id'],'runner-session-1']],
            streams=[[first['config']['binding']['observer_stream_id'],fresh['config']['binding']['observer_stream_id'],'runner-stream-1']]),
        first_original_sha256=digest(first),fresh_original_sha256=digest(fresh),
        first_view=a,fresh_view=b,first_view_sha256=digest(a),fresh_view_sha256=digest(b),
        first_rehash_audit=aa,fresh_rehash_audit=ba)


def verify_physical(samples):
    pre=[s['pre']['backend'] for s in samples]
    require(0<len(pre)<=500,'measured sample bound')
    require([r['d_awaddr'] for r in pre if r['d_awvalid'] and r['d_awready']]==[0x80000100,0x80000104],'physical AW')
    require([(r['d_wdata'],r['d_wstrb'],r['d_wlast']) for r in pre if r['d_wvalid'] and r['d_wready']]==[(53,15,1),(54,15,1)],'physical W')
    require([(r['d_araddr'],r['d_arsize']) for r in pre if r['d_arvalid'] and r['d_arready']]==[(0x80000100,2)],'physical data AR')
    require([(r['d_rdata'],r['d_rlast'],r['d_rresp']) for r in pre if r['d_rvalid'] and r['d_rready']]==[(53,1,0)],'physical data R')
    require(sum(bool(r['i_arvalid'] and r['i_arready']) for r in pre)>=8,'physical fetch count')
    require([r['d_bresp'] for r in pre if r['d_bvalid'] and r['d_bready']]==[0,0],'physical B responses')
    return dict(measured_samples=len(pre),physical_stores=[53,54],physical_data_reads=[53],physical_b_responses=2,
        authority='observation_only',runtime_accepted=False,semantic_accepted=False)


def semantic_digest(events,local_ticks,status):
    # Same documented durable trace grammar, independent of writer metadata.
    def utf8(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf8')
    return hashlib.sha256(b'{"events":['+b','.join(utf8(e) for e in events)+b'],"local_ticks":'+utf8(local_ticks)+b',"status":'+utf8(status)+b'}').hexdigest()


def verify_native_join(run):
    """Join every admitted measured operation to actual passive I/O capture."""
    validate_original(run)
    operations=[e['operation'] for e in run['events'] if e.get('kind')=='reduced_axi_source_operation']
    receipts=[o['payload'] for o in operations if o['kind']=='receipt']
    wire=run['wire']; commands=[x['text'] for x in wire if x['direction']=='host' and x['text'].startswith('CMD ')]
    replies=[x['text'] for x in wire if x['direction']=='native' and x['text'].startswith(('RESULT ','ERROR '))]
    require(commands==[p['wire_command'] for p in receipts],'actual/admitted command sequence mismatch')
    require(replies==[p['wire_reply'] for p in receipts],'actual/admitted reply sequence mismatch')
    samples=[s for p in receipts for s in p['receipt']['payload']['samples']]
    require(samples==run['samples'],'measured sample mismatch')
    raw=[e['raw_sample'] for e in run['events'] if e.get('kind')=='reduced_axi_raw']
    require(raw==samples,'sample/raw original mismatch')
    from myfuzz.local_harness.wire import parse_driver_ready,parse_driver_ack
    ready=[x['text'] for x in wire if x['direction']=='native' and x['text'].startswith('READY ')]
    require(len(ready)==1,'startup READY missing/duplicate')
    tokens=ready[0].strip().split(' ')
    require(len(tokens)==5,'READY grammar')
    # The exact READY digest/reset bytes were checked by the actual startup parser.
    # Recheck against archived explicit expected_ready obtained before launch.
    expected=run['expected_ready']
    runtime=run['runtime'];reset=runtime['driver_reset']
    require(expected==[runtime['artifact_digest'],reset['reset_assert_ticks'],reset['reset_release_ticks'],runtime['kind']],'READY/runtime binding mismatch')
    parse_driver_ready(ready[0].strip(),digest=expected[0],assert_ticks=expected[1],release_ticks=expected[2])
    sent=[x['text'] for x in wire if x['direction']=='host' and x['text'].startswith('ACK ')]
    acked=[x['text'] for x in wire if x['direction']=='native' and x['text'].startswith('ACKED ')]
    require(len(sent)==len(acked)==max(0,(len(receipts)-1)//16),'ACK capture mismatch')
    for command,reply in zip(sent,acked):
        ct=command[:-1].split(' ');require(command.endswith('\n') and len(ct)==3 and ct[1]==run['execution'],'ACK grammar')
        seq=int(ct[2],16);require(1<=seq<=len(receipts),'ACK sequence')
        parse_driver_ack(reply.strip(),execution=run['execution'],sequence=seq,current_tick=receipts[seq-1]['receipt']['tick_after'])
    require(len(wire)==len(commands)+len(replies)+len(ready)+len(sent)+len(acked),'unclassified wire traffic')
    expected_wire=[dict(direction='native',text=ready[0])]
    ack_index=0
    for index,payload in enumerate(receipts):
        if index and index%16==0:
            expected_wire.extend([dict(direction='host',text=sent[ack_index]),dict(direction='native',text=acked[ack_index])]);ack_index+=1
        expected_wire.extend([dict(direction='host',text=payload['wire_command']),dict(direction='native',text=payload['wire_reply'])])
    require(wire==expected_wire,'wire command/reply/ACK chronology mismatch')
    return verify_physical(samples)


def verify_durable(directory,run,trust):
    """Trust must be supplied by the supervising process/external audit, not metadata."""
    from myfuzz.scenario.event_journal import JsonlEventView,ZlibChunkEventView
    directory=Path(directory)
    expected=semantic_digest(run['events'],run['local_ticks'],'complete')
    require(trust['semantic_sha256']==expected,'external semantic hash mismatch')
    reports={}
    for name,cls in [('jsonl',JsonlEventView),('zlib',ZlibChunkEventView)]:
        path=directory/name/('online_events.'+name)
        data=path.read_bytes();require(hashlib.sha256(data).hexdigest()==trust[name+'_sha256'],'external raw file hash mismatch')
        view=cls(path,len(run['events']))
        # Verify raw semantic commitment before feeding ANY row to consumer.
        rows=list(view)
        require(semantic_digest(rows,run['local_ticks'],'complete')==expected,'durable semantic mismatch')
        if name=='zlib':view.verify_trace_semantic(status='complete',local_ticks=run['local_ticks'],expected_sha256=expected)
        require(rows==run['events'],'durable global journal differs')
        reports[name]=replay(run,rows)
        require(reports[name]==run['report'],'durable/live report differs')
    return dict(semantic_sha256=expected,reports=reports,physical=verify_native_join(run))


def verify_inventory(base,inventory):
    base=Path(base).resolve();seen=set()
    require('raw' in inventory['scopes'] and 'declared-input-bytes' in inventory['scopes'],'inventory missing required scopes')
    for row in inventory['members']:
        relative=Path(row['path'])
        require(not relative.is_absolute() and '..' not in relative.parts,'unsafe inventory path')
        require(str(relative) not in seen,'duplicate inventory path');seen.add(str(relative))
        path=base/relative
        require(path.resolve().is_relative_to(base) and not path.is_symlink() and path.is_file(),'inventory member not regular')
        data=path.read_bytes()
        require(len(data)==row['size'] and hashlib.sha256(data).hexdigest()==row['sha256'],'inventory member mismatch')
    require(inventory['sha256']==digest(inventory['members']),'inventory commitment mismatch')
    actual=set()
    for scope in inventory['scopes']:
        relative=Path(scope)
        require(not relative.is_absolute() and '..' not in relative.parts,'unsafe inventory scope')
        entry=base/relative
        actual.update(str(p.relative_to(base)) for p in (entry.rglob('*') if entry.is_dir() else [entry]) if p.is_file())
    require(actual==seen,'raw inventory coverage mismatch')
    return dict(member_count=len(seen),inventory_sha256=digest(inventory))


def main():
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--attempt',type=Path,required=True)
    parser.add_argument('--trust',type=Path,required=True)
    parser.add_argument('--trust-sha256',required=True,help='trusted external SHA256 of trust file bytes')
    parser.add_argument('--inventory',type=Path,required=True)
    parser.add_argument('--inventory-sha256',required=True,help='trusted external SHA256 of inventory file bytes')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    def trusted(path,expected):
        data=path.read_bytes();require(hashlib.sha256(data).hexdigest()==expected,'external trust bytes mismatch')
        return json.loads(data)
    trust=trusted(args.trust,args.trust_sha256)
    inventory=trusted(args.inventory,args.inventory_sha256)
    audit=dict(inventory=verify_inventory(args.attempt,inventory),runs={})
    runs={}
    for name in ('first','fresh'):
        directory=args.attempt/'raw'/name
        data=(directory/'run.json').read_bytes()
        require(hashlib.sha256(data).hexdigest()==trust[name]['run_json_sha256'],'external run bytes mismatch')
        runs[name]=json.loads(data)
        audit['runs'][name]=verify_durable(directory,runs[name],trust[name])
        manifest=json.loads((directory/'build-manifest.json').read_text())
        prebuild=json.loads((args.attempt/'raw/prebuild-input-manifest.json').read_text())
        verify_build_snapshot(args.attempt/'raw/prebuild-inputs',prebuild)
        verify_validated_cache_archive(directory/'build-bytes',manifest,prebuild,args.attempt/'raw/prebuild-inputs')
    raw=args.attempt/'raw'
    for folder,file in [('rendered-bytes','rendered-manifest.json'),('python-closure','python-closure-manifest.json')]:
        verify_archive(raw/folder,json.loads((raw/file).read_text()))
    freeze=json.loads((args.attempt/'prelaunch-freeze.json').read_text())
    # Archived directory relocation is supported without rewriting original manifest.
    verify_archive(args.attempt/'declared-input-bytes',freeze['manifest'])
    comparison=compare_runs(runs['first'],runs['fresh'])
    require(comparison==json.loads((raw/'comparison.json').read_text()),'saved comparison mismatch')
    audit.update(comparison=comparison,authority='observation_only',runtime_accepted=False,semantic_accepted=False)
    require(not args.output.exists(),'audit output already exists')
    args.output.write_text(json.dumps(audit,sort_keys=True,indent=2)+'\n')


if __name__=='__main__':main()
