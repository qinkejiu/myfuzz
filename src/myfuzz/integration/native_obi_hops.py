"""Exact F2 instruction, OBI and dependent RAM joins. No authority issuance."""
from copy import deepcopy
from myfuzz.scenario.ledger import TransactionKey


class F2ObservationMissing(ValueError):
    """A required F2 observation was unavailable, rather than contradictory."""


def _native_steps(events, component, error_prefix):
    for event in events:
        if event.get('kind') == 'reset_barrier':
            yield event, None
            continue
        if event.get('component')!=component or 'outputs' not in event or 'local_tick' not in event:
            continue
        samples=event['outputs'].get('driver_samples')
        if samples is None:continue
        if len(samples)!=1 or samples[0]['local_tick']!=event['local_tick']:
            raise ValueError(error_prefix+'-native-CPU-sample-shape')
        yield event,samples[0]['pre']['protocol_taps']


def collect_native_obi_beats(events,*,cpu,traces,error_policy,error_prefix="compiled-F2",transaction_channel="instr"):
    """Reconstruct one outstanding physical beat per channel."""
    pending={'instr':None,'data':None};sequence={'instr':0,'data':0};completed={}
    for step,taps in _native_steps(events,cpu,error_prefix):
        if taps is None:
            pending={'instr':None,'data':None};sequence={'instr':0,'data':0};completed={}
            continue
        for channel,signals in traces.items():
            def pin(role):return taps.get(signals.get(role))
            # OBI has no response backpressure at this physical CPU boundary.
            if pin('rvalid')==1:
                if error_policy['native_error_observation'] and (type(pin('error')) is not int or pin('error')!=0):
                    raise ValueError(error_prefix+'-native-CPU-response-error')
                accepted=pending[channel]
                if accepted is None:raise ValueError(error_prefix+'-native-response-unowned')
                key=(channel,accepted['sequence'])
                completed[key]=dict(accepted, response_event=step['event_id'],rdata=pin('rdata'),error=pin('error') if error_policy['native_error_observation'] else None)
                pending[channel]=None
            if pin('req')==1 and pin('gnt')==1:
                if pending[channel] is not None:raise ValueError(error_prefix+'-native-outstanding-overlap')
                sequence[channel]+=1
                pending[channel]=dict(sequence=sequence[channel],acceptance_event=step['event_id'],
                    address=pin('addr'),write=pin('we') if channel=='data' else 0,
                    value=pin('wdata'),byte_enable=pin('be'))
    return completed


def verify_instruction_fetches(*,events,cpu,address,code,source_event_id,source,route_transaction,instruction_snapshots,completed,image,functional_offsets=tuple(range(0,28,4)),error_prefix="compiled-F2",transaction_channel="instr"):
    """Join seven generated functional words to immutable memory and OBI."""
    from myfuzz.scenario.edge_provenance import _transaction_key
    instruction_hops=[]
    # The seven functional instructions must all be consumed from this image.
    # Four trailing NOPs merely separate contiguous candidates.
    for offset in functional_offsets:
        rows=[e for e in events if e.get('kind')=='memory_read' and e.get('component')==cpu
              and e.get('address')==address+offset and e.get('transaction',{}).get('channel_id')==transaction_channel
              and isinstance(e.get('writer_event_ids'),(list,tuple))
              and tuple(e['writer_event_ids'])==(source_event_id,)*4
              and e.get('data_hex')==code[offset:offset+4].hex()]
        if not rows:
            # A read at this address with different bytes/writers is observed
            # contradictory evidence, not an unavailable fetch.
            error=ValueError if any(e.get('kind')=='memory_read' and
                e.get('component')==cpu and e.get('address')==address+offset
                for e in events) else F2ObservationMissing
            raise error(error_prefix+'-instruction-version-hop-missing')
        if len(rows)!=1:raise ValueError(error_prefix+'-instruction-version-hop-missing')
        read=rows[0];transaction=read['transaction']
        snapshot=instruction_snapshots[offset//4]
        if (read['data_hex']!=snapshot.data.hex() or read['byte_offset']!=snapshot.byte_offset
                or [list(v) for v in read['versions']]!=[list(v) for v in snapshot.versions]
                or tuple(read['writer_event_ids'])!=snapshot.writer_event_ids
                or snapshot.writer_kinds!=('INSTRUCTION_SOURCE',)*4):
            raise ValueError(error_prefix+'-instruction-authoritative-version-mismatch')
        if (_transaction_key(transaction) is None or any(transaction[k]!=route_transaction[k]
                for k in ('execution_id','testcase_id','source_component','source_epoch'))):
            raise ValueError(error_prefix+'-instruction-transaction-mismatch')
        beat=completed.get(('instr',transaction['source_sequence']))
        if beat is None:
            raise F2ObservationMissing(error_prefix+'-native-instruction-consumption-missing')
        if (read.get('memory_id')!=image['port'] or read.get('generation')!=source['generation']
                or read.get('width_bytes')!=4 or len(read.get('versions',[]))!=4
                or any(type(v) not in (list,tuple) or len(v)!=2
                       or any(type(n) is not int or n<0 for n in v)
                       or v[0]!=source['generation'] or v[1]<1 for v in read['versions'])
                or any(v!=read['versions'][0] for v in read['versions'])
                or beat['address']!=address+offset
                or beat['rdata']!=int.from_bytes(code[offset:offset+4],'little')
                or not beat['acceptance_event']<=read['producer_event_id']<beat['response_event']):
            raise ValueError(error_prefix+'-native-instruction-consumption-missing')
        instruction_hops.append(dict(beat,source_event=source['event_id'],
            memory_read_event=read['event_id'],versions=read['versions']))
    return instruction_hops


def verify_dependent_ram_store(*,declaration,data_hops,image,by_id,ram_event_id,cpu,completed,instruction_hops,result_snapshot,native_field='native_obi',xor_constant=0x5a5,store_instruction_index=6,transaction_channel='data',consecutive_sequence=True):
    """Authenticate the later XOR dependent store and installed RAM snapshot."""
    from myfuzz.scenario.edge_provenance import _transaction_key
    result_address=declaration.get('result_address')
    candidate=declaration.get('candidate')
    value=data_hops[0]['value'] ^ xor_constant
    if declaration.get('xor_constant',0) != xor_constant:
        raise ValueError('compiled-F2-dependent-XOR-mismatch')
    memory_range=image.get('range')
    if (not isinstance(memory_range,(list,tuple)) or len(memory_range)!=2
            or any(type(bound) is not int for bound in memory_range)
            or not 0<=memory_range[0]<=memory_range[1]<1<<32
            or type(result_address) is not int or result_address< memory_range[0]
            or result_address+3>memory_range[1] or result_address%4
            or type(value) is not int or not 0<=value<=0xffffffff
            or type(ram_event_id) is not int):
        raise ValueError('compiled-F2-result-RAM-hop-missing')
    ram_event=by_id.get(ram_event_id)
    if ram_event is None:raise F2ObservationMissing('compiled-F2-result-RAM-hop-missing')
    if (not isinstance(ram_event,dict) or ram_event.get('kind')!='memory_write'
            or ram_event.get('component')!=cpu
            or ram_event.get('memory_id')!=image.get('port')
            or ram_event.get('address')!=result_address
            or ram_event.get('value')!=value
            or ram_event.get('byte_enable')!=15
            or ram_event.get('width_bytes')!=4
            or type(ram_event.get('generation')) is not int
            or ram_event['generation']<0
            or type(ram_event.get('byte_offset')) is not int
            or ram_event['byte_offset']!=result_address-memory_range[0]):
        raise ValueError('compiled-F2-result-RAM-hop-missing')
    version=ram_event.get('version')
    if (not isinstance(version,(list,tuple)) or len(version)!=2
            or any(type(item) is not int or item<0 for item in version)
            or version[0]!=ram_event['generation'] or version[1]<1):
        raise ValueError('compiled-F2-result-RAM-version-mismatch')
    transaction=ram_event.get('transaction')
    if _transaction_key(transaction) is None:
        raise ValueError('compiled-F2-result-RAM-transaction-mismatch')
    read_transaction=data_hops[0]['source_transaction']
    if (transaction.get('channel_id')!=transaction_channel
            or transaction.get('source_component')!=cpu
            or transaction.get('source_epoch')!=0
            or any(transaction.get(key)!=read_transaction.get(key)
                   for key in ('execution_id','testcase_id','source_component',
                               'source_epoch'))
            or (transaction.get('source_sequence') !=read_transaction.get('source_sequence',-1)+1
                if consecutive_sequence else transaction.get('source_sequence',-1)<=read_transaction.get('source_sequence',-1))):
        raise ValueError('compiled-F2-result-RAM-transaction-mismatch')
    ram_beat=completed.get(('data',transaction['source_sequence']))
    read_beat=data_hops[0][native_field]
    if ram_beat is None:raise F2ObservationMissing('compiled-F2-result-RAM-native-hop-missing')
    if any(hop['response_event']>=ram_beat['acceptance_event']
           for hop in instruction_hops):
        raise ValueError('compiled-F2-instruction-store-order')
    if (ram_beat['write']!=1
            or ram_beat['address']!=result_address or ram_beat['value']!=value
            or ram_beat['byte_enable']!=15
            or ram_event.get('producer_event_id')!=ram_beat['acceptance_event']
            or ram_beat['acceptance_event']<=read_beat['response_event']
            or instruction_hops[store_instruction_index]['response_event']>=ram_beat['acceptance_event']
            or not ram_beat['acceptance_event']<ram_event_id<ram_beat['response_event']):
        raise ValueError('compiled-F2-result-RAM-native-hop-missing')
    if result_snapshot is None:
        raise F2ObservationMissing('compiled-F2-result-RAM-authoritative-snapshot-mismatch')
    if (result_snapshot.data != value.to_bytes(4,'little')
            or tuple(result_snapshot.versions)!=(tuple(version),)*4
            or result_snapshot.writer_event_ids!=(str(TransactionKey(**transaction)),)*4
            or result_snapshot.writer_kinds!=('STORE',)*4):
        raise ValueError('compiled-F2-result-RAM-authoritative-snapshot-mismatch')
    ram_write_hop=dict(memory_write_event=ram_event_id,
        producer_event_id=ram_event['producer_event_id'],
        memory_id=ram_event['memory_id'],generation=ram_event['generation'],
        byte_offset=ram_event['byte_offset'],width_bytes=ram_event['width_bytes'],
        address=ram_event['address'],value=ram_event['value'],
        byte_enable=ram_event['byte_enable'],version=list(version),
        transaction=deepcopy(transaction),
        native_acceptance_event=ram_beat['acceptance_event'],
        native_response_event=ram_beat['response_event'],**{native_field:dict(ram_beat)})
    return ram_write_hop


def check_f2_exact_hops(*, events, declaration, image, stream, traces, address, source_event_id, joins, declared_edges, instruction_snapshots, ram_event_id, error_policy=None, proof_scope=None, result_snapshot=None):
    """Consume the narrow F2 chain: image byte versions, native OBI and APB.

    A consumed fetch is not instruction retirement. F2 declares consumption;
    no retirement or unrelated fixed-topology ChainCertificates claim is made.
    The native ABI permits exactly one outstanding beat per channel, so each
    response consumes the exact outstanding acceptance, never an adjacent row.
    """
    if not joins:raise F2ObservationMissing('compiled-F2-exactly-one-read-required')
    if len(joins)!=1:
        raise ValueError('compiled-F2-exactly-one-read-required')
    if error_policy is None:error_policy=dict(mode='native_error_role',native_error_observation=True)
    if (error_policy.get('mode'),error_policy.get('native_error_observation')) not in {
            ('native_error_role',True),('fail_stop_no_error_pin',False)}:
        raise ValueError('compiled-F2-error-policy-invalid')
    if not error_policy['native_error_observation'] and any('error' in row for row in traces.values()):
        raise ValueError('compiled-F2-error-policy-trace-contradiction')
    cpu=image['component'];access=stream['register_access'];code=bytes.fromhex(declaration['code_hex'])
    by_id={e['event_id']:e for e in events}
    if len(by_id)!=len(events):raise ValueError('compiled-F2-duplicate-event-identity')
    sources=[e for e in events if e.get('kind')=='instruction_source' and e.get('component')==cpu
             and e.get('source_event_id')==source_event_id and e.get('address')==address
             and e.get('data_hex')==code.hex()]
    if not sources:
        error=ValueError if any(e.get('kind')=='instruction_source' and
            e.get('component')==cpu and e.get('address')==address for e in events
            ) else F2ObservationMissing
        raise error('compiled-F2-instruction-source-missing')
    if len(sources)!=1:raise ValueError('compiled-F2-instruction-source-missing')
    from myfuzz.scenario.edge_provenance import _transaction_key
    route_transaction=by_id[joins[0]['delivery_event']]['source_transaction']
    if _transaction_key(route_transaction) is None:raise ValueError('compiled-F2-transaction-malformed')
    source=sources[0]
    completed=collect_native_obi_beats(events,cpu=cpu,traces=traces,error_policy=error_policy)
    instruction_hops=verify_instruction_fetches(events=events,cpu=cpu,address=address,code=code,
        source_event_id=source_event_id,source=source,route_transaction=route_transaction,
        instruction_snapshots=instruction_snapshots,completed=completed,image=image)
    # This bounded straight-line program consumes functional words in address
    # order. Prefetch remains allowed: a response and the next acceptance may
    # share a physical sample, and fetches can run ahead of data accesses.
    if any(left['acceptance_event']>=right['acceptance_event'] or
            left['response_event']>=right['response_event'] or
            left['sequence']>=right['sequence']
            for left,right in zip(instruction_hops,instruction_hops[1:])):
        raise ValueError('compiled-F2-functional-fetch-order')
    data_hops=[]
    for join in joins:
        delivery=by_id[join['delivery_event']];accept=by_id[join['acceptance_event']]
        transaction=delivery['source_transaction'];beat=completed.get(('data',transaction['source_sequence']))
        if beat is None:raise F2ObservationMissing('compiled-F2-native-data-route-hop-missing')
        if (_transaction_key(transaction) is None
                or any(transaction[k]!=route_transaction[k] for k in ('execution_id','testcase_id','source_component','source_epoch'))
                or transaction.get('source_component')!=cpu or transaction.get('source_epoch')!=0
                or transaction.get('channel_id')!='data' or accept.get('component')!=cpu
                or accept.get('device_id')!=access['device_id']
                or delivery.get('device_id')!=access['device_id']
                or delivery.get('offset')!=access['register_offset']
                or beat['acceptance_event']!=accept['producer_event_id']
                or beat['address']!=access['address'] or beat['write']!=int(delivery['write'])
                or delivery['write'] is not False
                or beat['rdata']!=join['value'] or beat['byte_enable']!=15
                or not accept['event_id']<delivery['event_id']<beat['response_event']):
            raise ValueError('compiled-F2-native-data-route-hop-missing')
        data_hops.append(dict(join,native_acceptance_event=beat['acceptance_event'],
            native_response_event=beat['response_event'],native_obi=dict(beat)))
    if len(data_hops)!=1 or instruction_hops[2]['response_event']>=data_hops[0]['native_acceptance_event']:
        raise ValueError('compiled-F2-instruction-data-order')
    ram_write_hop=verify_dependent_ram_store(declaration=declaration,data_hops=data_hops,
        image=image,by_id=by_id,ram_event_id=ram_event_id,cpu=cpu,completed=completed,
        instruction_hops=instruction_hops,result_snapshot=result_snapshot)
    if len(declared_edges)!=3 or [e.get('relation') for e in declared_edges]!=['persistent_state','mmio_route','mmio_route']:
        raise ValueError('compiled-F2-declared-edge-shape')
    edge_hops=[instruction_hops,
        [dict(data_hops[0],role='read_request',consumer_event=data_hops[0]['native_APB_event'])],
        [dict(data_hops[0],role='read_return',producer_event=data_hops[0]['native_APB_event'],
            consumer_event=data_hops[0]['native_response_event'])]]
    return dict(schema_version='compiled_F2_exact_hops.v2',
        proof_scope=(proof_scope or
            'selected_F2_image_consumption_native_OBI_route_native_APB_live_register_version_result_RAM'),
        cpu_error_policy=deepcopy(error_policy),
        instruction_hops=instruction_hops,data_hops=data_hops,
        ram_write_hop=ram_write_hop,
        edges=[dict(edge,status='certified',hops=hops) for edge,hops in zip(declared_edges,edge_hops)])

