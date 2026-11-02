"""Pure F2 CPU-load -> IP-read-response -> dependent RAM path controls.

These controls consume the registered Timer D3 row and the assembled exact-hop
checker only.  They execute no native process and grant no native authority:
the positive case uses one synthetic journal whose beats, delivery and
dependent store match the declared F2 shape, and every negative case mutates
exactly one declared fact.  The real native gate is frozen and run separately.
"""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from myfuzz.scenario.f2_read_contract import build_f2_read_contract
from tests.integration.test_compiled_f4_storage_producer import ROOT, timer_loaded


@pytest.fixture(scope='module')
def generated(tmp_path_factory):
    return timer_loaded(tmp_path_factory.mktemp('f2-read-response'))


def f2_row(inputs):
    return next(path for path in inputs['compiled']['paths']
                if path['flow_id'] == 'F2' and path['status'] == 'executable')


def f2_parts(generated):
    """The admitted F2 row plus the exact-hop inputs derived from source."""
    from myfuzz.integration.compiled_f2 import _f2_edges, admit_f2
    from myfuzz.integration.generated_register_reader import declare_reader
    artifacts, inputs = generated
    row = admit_f2(artifacts=artifacts, compiled_inputs=inputs, base_dir=ROOT)
    image = next(source for source in row['sources']
                 if source['kind'] == 'instruction_image')
    stream = next(source for source in row['sources']
                  if source['kind'] == 'cpu_load_stream')
    access = stream['register_access']
    result = image['range'][1] - 3
    cursor = image['range'][0]
    declaration = declare_reader(inputs['request'], inputs['compiled'],
                                 source_id=stream['source_id'],
                                 address=access['address'], result_address=result)
    edges = _f2_edges(inputs['compiled'], image, access)
    return dict(row=row, image=image, stream=stream, access=access,
                declaration=declaration, edges=edges, result=result, cursor=cursor)


# --------------------------------------------------------------- positive path


def test_positive_selected_f2_path_is_cpu_to_ip_to_cpu(generated):
    parts = f2_parts(generated)
    access, image, edges = parts['access'], parts['image'], parts['edges']
    cpu, device = access['source_component'], access['target_component']
    assert [edge['relation'] for edge in edges] == [
        'persistent_state', 'mmio_route', 'mmio_route']
    assert [edge['role'] for edge in edges] == [
        'read_request', 'read_request', 'read_return']
    # The request leg is CPU -> IP; the return leg is IP -> CPU.  Neither MMIO
    # leg is a fabricated CPU -> CPU edge.
    assert [(edge['source_component'], edge['target_component'])
            for edge in edges] == [(cpu, cpu), (cpu, device), (device, cpu)]
    assert all(not (edge['source_component'] == edge['target_component'] == cpu
                    and edge['relation'] == 'mmio_route') for edge in edges)
    contract = parts['row']['execution_contract']
    assert contract['version_selector'] == dict(
        kind='ip_register_version', component=device,
        register=access['register'], epoch_policy='current_live_epoch')
    assert contract['response_mask'] == 0xffffffff
    assert contract['consumption_mode'] == 'native_read_then_dependent_ram_store'
    # An IP register is not a RAM resource: the resolved prerequisite is an IP
    # register version selector, never a RAM byte version with an IP name.
    prerequisite = parts['row']['prerequisites']
    assert prerequisite == [dict(kind='ip_register_version',
        basis='F2 requires the current live IP register version before reading',
        subject=dict(component=device, register=access['register']))]
    assert 'memory_id' not in prerequisite[0]['subject']
    # The only fuzzable value is the read-owned address; PRDATA stays bound.
    assert sorted(source['kind'] for source in parts['row']['sources']) == [
        'cpu_load_stream', 'instruction_image']
    assert parts['row']['bound_inputs'] == [dict(
        input_id=f'{device}.{access["target_endpoint"]}.read_response',
        origin='bound', kind='ip_read_response', component=device,
        endpoint_id=access['target_endpoint'],
        basis=parts['row']['bound_inputs'][0]['basis'])]
    code = bytes.fromhex(parts['declaration']['code_hex'])
    assert parts['declaration']['functional_offsets'] == {
        'load': 8, 'xor': 12, 'store': 24}
    assert parts['declaration']['xor_constant'] == 0x5a5
    assert len(code) == 44 and parts['declaration']['result_address'] == parts['result']


def _transaction(sequence, channel, cpu):
    return dict(execution_id='synthetic-exec', testcase_id='synthetic-case',
                source_component=cpu, source_epoch=0, channel_id=channel,
                source_sequence=sequence)


def _step(event_id, pins, component):
    return dict(event_id=event_id, component=component, local_tick=event_id,
                outputs={'driver_samples': [dict(local_tick=event_id,
                    pre={'protocol_taps': pins})]})


def _journal(generated):
    """One synthetic exact-hop journal matching the declared F2 read shape."""
    parts = f2_parts(generated)
    artifacts, inputs = generated
    from myfuzz.integration.compiled_f2 import _cpu_policy
    cpu = parts['access']['source_component']
    device = parts['access']['target_component']
    from myfuzz.integration.compiled_f4 import _cpu_traces
    traces = _cpu_traces(artifacts[cpu], parts['image'], parts['stream'])
    policy = _cpu_policy(artifacts[cpu], parts['image'], parts['stream'])
    code = bytes.fromhex(parts['declaration']['code_hex'])
    value = 0x0000002a
    result_value = value ^ parts['declaration']['xor_constant']
    source_event_id = 9001
    generation = 7
    instruction_snapshots = []
    events = []
    next_id = 1

    def add(event):
        nonlocal next_id
        event['event_id'] = next_id
        events.append(event)
        next_id += 1
        return event

    add(dict(kind='instruction_source', component=cpu,
             source_event_id=source_event_id, address=parts['cursor'],
             generation=generation, data_hex=code.hex()))
    instr_signals = traces['instr']
    data_signals = traces['data']
    route = _transaction(1, 'data', cpu)
    # Seven functional words: each native OBI fetch consumes one immutable
    # memory read whose byte versions name the instruction source.
    for sequence, offset in enumerate(range(0, 28, 4), start=1):
        word = code[offset:offset + 4]
        request = add(_step(next_id, {instr_signals['req']: 1,
            instr_signals['gnt']: 1,
            instr_signals['addr']: parts['cursor'] + offset}, component=cpu))
        read = add(dict(kind='memory_read', component=cpu,
            address=parts['cursor'] + offset, memory_id=parts['image']['port'],
            generation=generation, byte_offset=0, width_bytes=4,
            data_hex=word.hex(), versions=[[generation, 1]] * 4,
            writer_event_ids=(source_event_id,) * 4,
            producer_event_id=request['event_id'],
            transaction=_transaction(sequence, 'instr', cpu)))
        add(_step(next_id, {instr_signals['rvalid']: 1,
            instr_signals['rdata']: int.from_bytes(word, 'little'),
            instr_signals['error']: 0}, component=cpu))
        instruction_snapshots.append(SimpleNamespace(
            data=word, byte_offset=0, versions=[[generation, 1]] * 4,
            writer_event_ids=(source_event_id,) * 4,
            writer_kinds=('INSTRUCTION_SOURCE',) * 4))
    # The CPU read request: acceptance, Router delivery, native OBI response.
    read_request = add(_step(next_id, {data_signals['req']: 1,
        data_signals['gnt']: 1, data_signals['addr']: parts['access']['address'],
        data_signals['we']: 0, data_signals['be']: 15}, component=cpu))
    acceptance = add(dict(kind='mmio_acceptance', component=cpu,
        device_id=device, address=parts['access']['address'], write=False,
        source_transaction=deepcopy(route),
        producer_event_id=read_request['event_id']))
    delivery = add(dict(kind='mmio_delivery', component=cpu, device_id=device,
        address=parts['access']['address'],
        offset=parts['access']['register_offset'], write=False,
        read_value=value, source_transaction=deepcopy(route),
        producer_event_id=read_request['event_id']))
    read_response = add(_step(next_id, {data_signals['rvalid']: 1,
        data_signals['rdata']: value, data_signals['error']: 0}, component=cpu))
    # The dependent store of `PRDATA XOR 0x5a5` into the declared result word.
    store_request = add(_step(next_id, {data_signals['req']: 1,
        data_signals['gnt']: 1, data_signals['addr']: parts['result'],
        data_signals['we']: 1, data_signals['be']: 15,
        data_signals['wdata']: result_value}, component=cpu))
    store_transaction = _transaction(route['source_sequence'] + 1, 'data', cpu)
    ram_event = add(dict(kind='memory_write', component=cpu,
        memory_id=parts['image']['port'], address=parts['result'],
        generation=generation,
        byte_offset=parts['result'] - parts['image']['range'][0],
        width_bytes=4, value=result_value, byte_enable=15,
        version=[generation, 1], producer_event_id=store_request['event_id'],
        transaction=deepcopy(store_transaction)))
    store_response = add(_step(next_id, {data_signals['rvalid']: 1,
        data_signals['rdata']: 0, data_signals['error']: 0}, component=cpu))
    from myfuzz.scenario.ledger import TransactionKey
    result_snapshot = SimpleNamespace(
        data=result_value.to_bytes(4, 'little'),
        versions=(tuple(ram_event['version']),) * 4,
        writer_event_ids=(str(TransactionKey(**store_transaction)),) * 4,
        writer_kinds=('STORE',) * 4)
    join = dict(delivery_event=delivery['event_id'],
                acceptance_event=acceptance['event_id'], value=value,
                write=False, native_APB_event=read_request['event_id'],
                source_transaction=deepcopy(route))
    context = dict(parts=parts, traces=traces, policy=policy, events=events,
                   declaration=parts['declaration'],
                   instruction_snapshots=instruction_snapshots,
                   join=join, ram_event_id=ram_event['event_id'],
                   result_snapshot=result_snapshot, value=value,
                   result_value=result_value, delivery=delivery,
                   read_response=read_response, store_request=store_request,
                   store_response=store_response,
                   ram_event=ram_event, route=route)
    return context


def _check(context):
    from myfuzz.integration.native_obi_hops import check_f2_exact_hops
    parts = context['parts']
    return check_f2_exact_hops(events=context['events'],
        declaration=context['declaration'], image=parts['image'],
        stream=parts['stream'], traces=context['traces'],
        address=parts['cursor'], source_event_id=9001,
        joins=[context['join']], declared_edges=parts['edges'],
        instruction_snapshots=context['instruction_snapshots'],
        ram_event_id=context['ram_event_id'],
        error_policy=context['policy'],
        result_snapshot=context['result_snapshot'])


def test_synthetic_full_read_chain_certifies_exact_hops(generated):
    context = _journal(generated)
    observed = _check(context)
    assert observed['schema_version'] == 'compiled_F2_exact_hops.v2'
    assert [edge['role'] for edge in observed['edges']] == [
        'read_request', 'read_request', 'read_return']
    assert len(observed['instruction_hops']) == 7
    assert observed['data_hops'][0]['write'] is False
    assert observed['data_hops'][0]['native_obi']['rdata'] == context['value']
    hop = observed['ram_write_hop']
    assert hop['value'] == context['result_value']
    assert hop['address'] == context['parts']['result']
    assert hop['transaction'] == context['ram_event']['transaction']
    assert all(edge['status'] == 'certified' for edge in observed['edges'])


def _reindex_journal(context):
    """Rebind event references and native fetch sequences after coherent edits."""
    events = context['events']
    identities = {event['event_id']: index for index, event in enumerate(events, 1)}
    references = ('event_id', 'producer_event_id', 'delivery_event',
                  'acceptance_event', 'native_APB_event')
    for event in [*events, context['join']]:
        for key in references:
            if key in event:
                event[key] = identities[event[key]]
        if 'local_tick' in event:
            event['local_tick'] = event['event_id']
            event['outputs']['driver_samples'][0]['local_tick'] = event['event_id']
    sequence = 0
    for event in events:
        if event.get('kind') == 'memory_read':
            sequence += 1
            event['transaction']['source_sequence'] = sequence
    context['ram_event_id'] = context['ram_event']['event_id']


def test_coherent_late_xor_fetch_cannot_certify_dependent_store(generated):
    context = _journal(generated)
    # Move a complete native XOR fetch after the store, and rebind both event
    # references and source sequences. Each word still has its correct bytes,
    # source writer, snapshot and actual native acceptance/response beat.
    xor_fetch = context['events'][10:13]
    del context['events'][10:13]
    context['events'].extend(xor_fetch)
    _reindex_journal(context)
    with pytest.raises(ValueError, match='functional-fetch-order|instruction-store-order'):
        _check(context)


def test_coherent_out_of_order_functional_fetch_refuses(generated):
    context = _journal(generated)
    context['events'][10:16] = context['events'][13:16] + context['events'][10:13]
    _reindex_journal(context)
    with pytest.raises(ValueError, match='functional-fetch-order'):
        _check(context)


def test_native_fetch_response_and_next_acceptance_may_share_sample(generated):
    context = _journal(generated)
    previous_response = context['events'][3]
    next_request = context['events'][4]
    signals = context['traces']['instr']
    previous_response['outputs']['driver_samples'][0]['pre']['protocol_taps'].update(
        next_request['outputs']['driver_samples'][0]['pre']['protocol_taps'])
    assert previous_response['outputs']['driver_samples'][0]['pre']['protocol_taps'][signals['rvalid']] == 1
    context['events'][5]['producer_event_id'] = previous_response['event_id']
    context['events'].remove(next_request)
    _reindex_journal(context)
    assert len(_check(context)['instruction_hops']) == 7


def test_observed_wrong_instruction_source_is_contradictory(generated):
    from myfuzz.integration.native_obi_hops import F2ObservationMissing
    context = _journal(generated)
    context['events'][0]['data_hex'] = '00' * len(bytes.fromhex(context['events'][0]['data_hex']))
    with pytest.raises(ValueError) as caught:
        _check(context)
    assert not isinstance(caught.value, F2ObservationMissing)


def test_unavailable_native_read_response_is_missing(generated):
    from myfuzz.integration.native_obi_hops import F2ObservationMissing
    context = _journal(generated)
    for key in ('read_response', 'store_request', 'ram_event', 'store_response'):
        context['events'].remove(context[key])
    with pytest.raises(F2ObservationMissing, match='native-data-route-hop-missing'):
        _check(context)


# ----------------------------------------------------------- missing responses


def test_missing_ip_read_response_refuses(generated):
    context = _journal(generated)
    # Drop the CPU read response and its dependent store; the response channel
    # stays outstanding and never becomes an accepted native beat.
    for key in ('read_response', 'store_request', 'ram_event', 'store_response'):
        context['events'].remove(context[key])
    with pytest.raises(ValueError, match='native-data-route-hop-missing'):
        _check(context)


def test_missing_join_refuses(generated):
    from myfuzz.integration.native_obi_hops import check_f2_exact_hops
    context = _journal(generated)
    parts = context['parts']
    with pytest.raises(ValueError, match='exactly-one-read'):
        check_f2_exact_hops(events=context['events'],
            declaration=context['declaration'], image=parts['image'],
            stream=parts['stream'], traces=context['traces'],
            address=parts['cursor'], source_event_id=9001, joins=[],
            declared_edges=parts['edges'],
            instruction_snapshots=context['instruction_snapshots'],
            ram_event_id=context['ram_event_id'],
            error_policy=context['policy'],
            result_snapshot=context['result_snapshot'])


def test_wrong_read_response_data_refuses(generated):
    context = _journal(generated)
    # Deliver a different PRDATA than the value the joins claim.
    context['read_response']['outputs']['driver_samples'][0]['pre'][
        'protocol_taps'][context['traces']['data']['rdata']] ^= 1
    with pytest.raises(ValueError, match='native-data-route-hop-missing'):
        _check(context)


def test_borrowed_read_response_refuses(generated):
    context = _journal(generated)
    # The delivery names another device: the IP response is not borrowed from
    # a differently routed transaction.
    context['delivery']['device_id'] = 'other_peripheral'
    with pytest.raises(ValueError, match='native-data-route-hop-missing'):
        _check(context)


def test_missing_dependent_store_refuses(generated):
    context = _journal(generated)
    context['events'].remove(context['ram_event'])
    with pytest.raises(ValueError, match='result-RAM-hop-missing'):
        _check(context)


def test_wrong_dependent_store_value_refuses(generated):
    context = _journal(generated)
    context['ram_event']['value'] ^= 1
    with pytest.raises(ValueError, match='result-RAM-hop-missing'):
        _check(context)


# ------------------------------------------------------- admission negatives


def test_wrong_register_refuses(generated):
    from myfuzz.integration.compiled_f2_layout import compile_f2_candidate_layout
    artifacts, inputs = generated
    row = deepcopy(f2_row(inputs))
    load = next(source for source in row['sources']
                if source['kind'] == 'cpu_load_stream')
    load['register'] = 'SPI0_CTRL'
    row['execution_contract'] = build_f2_read_contract(row)
    with pytest.raises(ValueError, match='register-access'):
        compile_f2_candidate_layout(row)


def test_ram_version_masquerade_refuses_before_native(generated):
    from myfuzz.integration.compiled_f2 import admit_f2
    artifacts, inputs = generated
    row = deepcopy(f2_row(inputs))
    register = next(source for source in row['sources']
                    if source['kind'] == 'cpu_load_stream')['register']
    row['prerequisites'] = [dict(kind='ram_byte_version',
        basis='legacy RAM-shaped F2 prerequisite',
        subject=dict(memory_id=register))]
    compiled = deepcopy(inputs['compiled'])
    target = next(path for path in compiled['paths']
                  if path['flow_id'] == 'F2' and path['status'] == 'executable')
    target.clear(); target.update(row)
    # The strict whole-document recompile is the first guard; it refuses the
    # RAM-shaped F2 version before any constructor or native tick.
    with pytest.raises(ValueError, match='compiled-runtime-input-refused'):
        admit_f2(artifacts=artifacts,
                 compiled_inputs={**inputs, 'compiled': compiled}, base_dir=ROOT)


def test_cpu_to_cpu_mmio_edge_refuses(generated):
    from myfuzz.integration.compiled_f2 import _f2_edges
    artifacts, inputs = generated
    row = f2_row(inputs)
    image = next(source for source in row['sources']
                 if source['kind'] == 'instruction_image')
    access = next(source for source in row['sources']
                  if source['kind'] == 'cpu_load_stream')['register_access']
    compiled = deepcopy(inputs['compiled'])
    for node in compiled['runtime_path_contract']['nodes']:
        if node['node_id'] == 'F2.read_response':
            node['component'] = access['source_component']
    with pytest.raises(ValueError, match='CPU-to-CPU-route-unsupported'):
        _f2_edges(compiled, image, access)


def test_missing_response_edge_refuses(generated):
    from myfuzz.integration.compiled_f2 import _f2_edges
    artifacts, inputs = generated
    row = f2_row(inputs)
    image = next(source for source in row['sources']
                 if source['kind'] == 'instruction_image')
    access = next(source for source in row['sources']
                  if source['kind'] == 'cpu_load_stream')['register_access']
    compiled = deepcopy(inputs['compiled'])
    graph = compiled['runtime_dependency_graph']
    graph['rules'] = [rule for rule in graph['rules']
                      if rule['target'] != 'F2.data_read_consumed']
    compiled['runtime_path_contract']['edges'] = [
        edge for edge in compiled['runtime_path_contract']['edges']
        if edge['rule_index'] != 3]
    with pytest.raises(ValueError, match='declared-edge-shape-unsupported'):
        _f2_edges(compiled, image, access)


def test_unsupported_flows_and_shapes_refuse(generated):
    artifacts, inputs = generated
    f4 = next(path for path in inputs['compiled']['paths']
              if path['flow_id'] == 'F4')
    with pytest.raises(ValueError, match='executable-F2-required'):
        build_f2_read_contract(f4)
    row = deepcopy(f2_row(inputs))
    load = next(source for source in row['sources']
                if source['kind'] == 'cpu_load_stream')
    load['register_access']['operation'] = 'write'
    with pytest.raises(ValueError, match='read-operation'):
        build_f2_read_contract(row)
    row = deepcopy(f2_row(inputs))
    access = next(source for source in row['sources']
                  if source['kind'] == 'cpu_load_stream')['register_access']
    access['value_mask'] = 0x000000ff
    row['execution_contract'] = build_f2_read_contract(row)
    from myfuzz.integration.compiled_f2_layout import compile_f2_candidate_layout
    # A response bit mask is not the address-selector width. Protocol MMIO
    # admits this declared mask without granting the old storage producer.
    layout=compile_f2_candidate_layout(row)
    assert layout.byte_length==4
    assert layout.classify(row['execution_contract']['address'].to_bytes(4,'little')).accepted
    access['value_mask']=0x100000000
    row['execution_contract']=build_f2_read_contract(row)
    with pytest.raises(ValueError, match='register-word-shape'):
        compile_f2_candidate_layout(row)
