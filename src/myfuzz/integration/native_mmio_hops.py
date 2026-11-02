"""Consume normalized real CPU beats without relabeling their bus protocol."""
from copy import deepcopy
from .native_obi_hops import verify_instruction_fetches,verify_dependent_ram_store


def _unified_request_channel(cpu_adapter):
    """Whether this CPU adapter's session numbers one request channel.

    ``unified`` is the declared channel model of the adapter's session, not a
    protocol name test: the AHB and AXI4-Lite memory sessions number both
    instruction fetches and data beats on one request channel (transaction
    channel id ``memory``), so their beats are keyed ('data', sequence) and a
    later RAM store only has to follow the read, not follow it immediately.
    The OBI and classic Wishbone rows keep their own ``instr``/``data`` channels
    and sequence counters.  A caller that hands in the declared model wins; an
    adapter-shaped object that predates the declaration is read by its protocol
    row, which is the same mapping the declaration encodes.
    """
    declared=getattr(cpu_adapter,'channel_model',None)
    if declared is None:
        declared=('unified' if cpu_adapter.protocol in ('ahb-lite','axi4-lite')
                  else 'split')
    if declared not in ('unified','split'):
        raise ValueError('MMIO-native-channel-model')
    return declared=='unified'


def check_native_mmio_hops(*,events,declaration,image,stream,address,source_event_id,joins,
        instruction_snapshots,ram_event_id,result_snapshot,cpu_adapter,flow):
    from ..scenario.edge_provenance import _transaction_key
    unified=_unified_request_channel(cpu_adapter)
    traces=getattr(cpu_adapter,'traces',None)
    read_transfer=(traces.get('read_transfer') if isinstance(traces,dict) else None)
    data_channel='memory' if unified else 'data'
    cpu=image['component'];access=stream['register_access'];by_id={e['event_id']:e for e in events}
    if len(by_id)!=len(events):raise ValueError('MMIO-duplicate-native-event')
    sources=[e for e in events if e.get('kind')=='instruction_source' and e.get('component')==cpu
        and e.get('source_event_id')==source_event_id and e.get('address')==address and e.get('data_hex')==declaration['code_hex']]
    if len(sources)!=1:raise ValueError('MMIO-native-instruction-source')
    if len(joins)!=(2 if flow=='F4' else 1):raise ValueError('MMIO-route-joins')
    completed=cpu_adapter.completed_beats(events,cpu)
    transaction=by_id[joins[0]['delivery_event']]['source_transaction']
    instructions=verify_instruction_fetches(events=events,cpu=cpu,address=address,
        code=bytes.fromhex(declaration['code_hex']),source_event_id=source_event_id,source=sources[0],
        route_transaction=transaction,instruction_snapshots=instruction_snapshots,completed=completed,image=image,
        functional_offsets=tuple(range(0,32 if flow=='F4' else 28,4)),error_prefix='MMIO-native',
        transaction_channel='memory' if unified else 'instr')
    if any(a['response_event']>=b['response_event'] for a,b in zip(instructions,instructions[1:])):
        raise ValueError('MMIO-native-functional-fetch-order')
    data=[]
    for join in joins:
        delivery=by_id[join['delivery_event']];accepted=by_id[join['acceptance_event']]
        key=delivery['source_transaction'];beat=completed.get(('data',key['source_sequence']))
        if (_transaction_key(key) is None or any(key[k]!=transaction[k] for k in ('execution_id','testcase_id','source_component','source_epoch'))
                or key['source_component']!=cpu or key['source_epoch']!=0 or key['channel_id']!=data_channel
                or accepted.get('source_transaction')!=key or accepted.get('component')!=cpu
                or accepted.get('device_id')!=access['device_id'] or delivery.get('device_id')!=access['device_id']
                or delivery.get('offset')!=access['register_offset'] or beat is None
                or beat['acceptance_event']!=accepted['producer_event_id'] or beat['address']!=access['address']
                or beat['write']!=int(delivery['write']) or delivery.get('byte_enable')!=15
                or (delivery['write'] and (beat['value']!=join['value'] or beat['byte_enable']!=15))
                or (not delivery['write'] and beat['rdata']!=join['value'])
                or not accepted['event_id']<delivery['event_id']<beat['response_event']):
            raise ValueError('MMIO-native-CPU-data-route')
        data.append(dict(join,native_acceptance_event=beat['acceptance_event'],native_response_event=beat['response_event'],
            native_cpu=deepcopy(beat)))
    load_index=5 if flow=='F4' else 2
    if instructions[load_index]['response_event']>=data[-1]['native_acceptance_event']:
        raise ValueError('MMIO-native-load-fetch-order')
    if flow=='F4' and instructions[4]['response_event']>=data[0]['native_acceptance_event']:
        raise ValueError('MMIO-native-store-fetch-order')
    ram=verify_dependent_ram_store(declaration=declaration,data_hops=[data[-1]],image=image,by_id=by_id,
        ram_event_id=ram_event_id,cpu=cpu,completed=completed,instruction_hops=instructions,result_snapshot=result_snapshot,
        native_field='native_cpu',xor_constant=0 if flow=='F4' else 0x5a5,store_instruction_index=7 if flow=='F4' else 6,
        transaction_channel=data_channel,consecutive_sequence=not unified)
    return dict(schema_version='native_CPU_MMIO_hops.v1',native_protocol=cpu_adapter.protocol,
        proof_scope='actual_CPU_native_MMIO_return_dependent_RAM_no_internal_version',
        instruction_hops=instructions,data_hops=data,ram_write_hop=ram,
        instruction_retirement='unknown',internal_storage_version='unknown',
        # Only a row that declares its read data granularity records it here, so
        # every other protocol's evidence stays byte-identical.
        **({'read_transfer':deepcopy(read_transfer)}
           if read_transfer is not None else {}))
