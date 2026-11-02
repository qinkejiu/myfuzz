"""Pure synthetic archived Runner records; no native acceptance is claimed."""
from copy import deepcopy
import importlib
import importlib.util
import json

import pytest

from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
from tests.integration.test_compiled_f6_firmware import contract, candidate


def projector():
    name = 'myfuzz.integration.compiled_f6_saved_semantics'
    assert importlib.util.find_spec(name) is not None, 'saved CPU configuration projector is missing'
    return importlib.import_module(name).project_saved_cpu_configuration


def test_saved_configuration_uses_declared_control_window():
    from myfuzz.integration.compiled_f6_saved_semantics import _saved_dma_configuration_values
    c = contract()
    behavior = dict(length_unit='words', irq_clear=dict(method='write', offset=16, value=1, byte_enable=15))
    assert _saved_dma_configuration_values(c['program_contract'], c['dma']['csr'], behavior, 32)[2] == 4
    with pytest.raises(ValueError):
        _saved_dma_configuration_values(c['program_contract'], c['dma']['csr'], behavior, 16)


@pytest.fixture
def archive():
    c = contract()
    c['cpu'] = dict(instance_id='processor_alpha')
    c['dma']['instance_id'] = 'mover_beta'
    c['control'].update(device_id='control_window', size=16,
                        configuration_order=c['dma']['csr']['configuration_order'])
    p = c['program_contract']
    cand = candidate()
    prefix = build_f6_firmware(c).prefix(cand, case_index=0)
    attempt = dict(case_id='run:case:0', case_index=0, raw8_hex=cand.raw.hex(),
                   prefix_hex=prefix.hex(), operands=[], configuration=[], deliveries=[])
    events, local = [], {}
    scope = dict(case_id=attempt['case_id'], case_index=0)

    def add(component, kind=None, **fields):
        row = dict(component=component, event_id=len(events)+1,
                   provenance=dict(observed_case=deepcopy(scope)), **fields)
        if kind is not None:
            row['kind'] = kind
        events.append(row)
        observer_id = len(events)+1000
        local[component, observer_id] = dict(deepcopy(row),
            event_id=observer_id, runner_event_id=row['event_id'])
        return observer_id

    sample_tick = 0

    def samples(tick, backend, step_outputs=None):
        nonlocal sample_tick
        assert tick > sample_tick
        while sample_tick < tick:
            sample_tick += 1
            pre = dict(i_req_valid=0, i_req_ready=1, d_req_valid=0, d_req_ready=1)
            if sample_tick == tick:
                pre.update(backend)
            outputs = dict(instr_rsp_consumed=0, instr_rsp_source_epoch=0,
                instr_rsp_source_sequence=0, instr_rsp_rdata=0, data_rsp_consumed=0,
                data_rsp_source_epoch=0, data_rsp_source_sequence=0, data_rsp_rdata=0)
            if sample_tick == tick and step_outputs:
                outputs.update(step_outputs)
            add('processor_alpha', local_tick=sample_tick, inputs={}, outputs=outputs)
            producer = events[-1]['event_id']
            for phase in ('pre', 'post'):
                add('processor_alpha', 'local_tick_sample', producer_event_id=producer,
                    local_tick=sample_tick, phase=phase, outputs=dict(backend=deepcopy(pre)))

    def transaction(channel, sequence):
        return dict(execution_id='local-execution', testcase_id='native-testcase',
            source_component='processor_alpha', source_epoch=0,
            channel_id=channel, source_sequence=sequence)

    def consume(row, channel, sequence):
        write = int(channel == 'data')
        tag = 'd' if write else 'i'
        consumed = (dict(data_rsp_consumed=1, data_rsp_source_epoch=0,
            data_rsp_source_sequence=sequence, data_rsp_rdata=row['rdata'])
            if write else dict(instr_rsp_consumed=1, instr_rsp_source_epoch=0,
                instr_rsp_source_sequence=sequence, instr_rsp_rdata=row['rdata']))
        samples(row['response_tick'], {tag+'_rsp_valid':1, tag+'_rsp_ready':1,
            tag+'_rsp_rdata':row['rdata'], tag+'_rsp_error':0}, consumed)

    def response(channel, sequence, tick, address, value, *, deferred=False):
        write = int(channel == 'data')
        key = transaction(channel, sequence)
        row = dict(transaction=key, address=address, raw_address=address,
            aligned_address=address, write=write, be=15, wdata=value if write else 0,
            acceptance_tick=tick, response_tick=tick+1, error=0,
            rdata=0 if write else value)
        tag = 'd' if write else 'i'
        samples(tick, {tag+'_req_valid':1, tag+'_req_ready':1,
            tag+'_req_write':write, tag+'_req_addr':address,
            tag+'_req_be':15, tag+'_req_wdata':row['wdata']})
        if not deferred:
            consume(row, channel, sequence)
        return row

    add('processor_alpha', 'cpu_native_startup', local_tick=0, tick=0,
        reset_epoch=0, source_epoch=0, execution_id='local-execution',
        source_component='processor_alpha', physical_reset=True)
    for i, offset in enumerate(p['operand_instruction_offsets']):
        data = prefix[offset:offset+4]
        row = response('instr', i+1, 10+4*i, p['slot_base']+offset,
                       int.from_bytes(data, 'little'))
        row['snapshot'] = dict(value=row['rdata'], data_hex=data.hex(),
            writer_kinds=['INSTRUCTION_SOURCE']*4)
        attempt['operands'].append(add('processor_alpha', 'instr_response', **row))
        # Four native source stores precede configuration. Their handshakes
        # consume data-channel sequence numbers even though this projection
        # does not evaluate source-RAM memory effects.
        response('data', i+1, 12+4*i, p['source_address']+4*i, cand.words[i])
    for i, (name, value) in enumerate(zip(c['control']['configuration_order'],
            [p['source_address'], p['destination_address'], 4, 0x0fed0004])):
        offset = c['dma']['csr']['offsets'][name]
        address = c['control']['base']+offset
        row = response('data', 5+i, 40+4*i, address, value, deferred=True)
        accepted = {k:v for k,v in row.items() if k not in ('rdata','error','response_tick')}
        attempt['configuration'].append(add('processor_alpha', 'data_accept', **accepted))
        routing = dict(source_transaction=row['transaction'], device_id=c['control']['device_id'],
            source_sequence=5+i, address=address, offset=offset, beat_bytes=4,
            write=True, byte_enable=15, write_value=value)
        add('processor_alpha', 'mmio_acceptance', acceptance_order=i+1, **routing)
        ticks = [100+4*i, 101+4*i, 102+4*i]
        add('mover_beta', local_tick=ticks[0]-1, inputs={}, outputs={})
        target_producer = events[-1]['event_id']
        for j, tick in enumerate(ticks):
            pre = dict(swb_cyc=int(j<2), swb_stb=int(j==0), swb_we=int(j<2),
                swb_adr=offset//4 if j<2 else 0, swb_dat_w=value if j<2 else 0,
                swb_ack=int(j==1), swb_stall=0, swb_dat_r=0)
            add('mover_beta', 'dma_edge', tick=tick, payload=dict(pre_backend=pre))
        context = dict(source_transaction=row['transaction'], device_id=c['control']['device_id'],
            window_base=c['control']['base'], window_size=16, address=address,
            offset=offset, write=True, value=value, be=15)
        receipt = dict(source_transaction=row['transaction'], address=address, offset=offset,
            write=True, value=value, byte_enable=15, edge_ticks=ticks, delivery_context=context)
        attempt['deliveries'].append(add('processor_alpha', 'mmio_delivery', **routing,
            read_value=None, delivery_order=i+1, target_delivery_order=i+1,
            dma_control_receipt=receipt, producer_event_id=target_producer))
        consume(row, 'data', 5+i)
        add('processor_alpha', 'data_response', **row)
    archive = dict(attempt=attempt, contract=c, events=events, local_by_id=local)
    normalize_cpu_drains(archive)
    return archive


def rows(archive, kind):
    return [r for r in archive['events'] if r.get('kind') == kind]


def refresh(archive):
    """Reauthenticate mutations as archived facts, not forged Observer copies."""
    for key, row in list(archive['local_by_id'].items()):
        actual = next((r for r in archive['events'] if r['event_id']==row['runner_event_id']), None)
        if actual is None:
            del archive['local_by_id'][key]
        else:
            archive['local_by_id'][key] = dict(deepcopy(actual), event_id=key[1],
                runner_event_id=actual['event_id'])


def renumber(archive):
    mapping = {r['event_id']:i for i,r in enumerate(archive['events'], 1)}
    for row in archive['events']:
        row['event_id'] = mapping[row['event_id']]
        if 'producer_event_id' in row:
            row['producer_event_id'] = mapping[row['producer_event_id']]
    for row in archive['local_by_id'].values():
        row['runner_event_id'] = mapping[row['runner_event_id']]
    refresh(archive)


def normalize_cpu_drains(archive):
    """Model Runner's producer -> external streams -> PRE/POST drain order."""
    pending = {}
    moved = set()
    for row in list(archive['events']):
        if row.get('kind') not in ('data_accept','data_response','instr_response'):
            continue
        tick = row['acceptance_tick'] if row['kind']=='data_accept' else row['response_tick']
        producer = next(r for r in archive['events'] if 'kind' not in r and r.get('local_tick')==tick)
        ordered = pending.setdefault(producer['event_id'], [])
        if row['kind']=='data_accept':
            routed = next(r for r in rows(archive, 'mmio_acceptance')
                          if r['source_transaction']==row['transaction'])
            routed['producer_event_id'] = producer['event_id']
            ordered.append(routed)
            moved.add(routed['event_id'])
        row['producer_event_id'] = producer['event_id']
        ordered.append(row)
        moved.add(row['event_id'])
    normalized = []
    for row in archive['events']:
        if row['event_id'] not in moved:
            normalized.append(row)
            normalized.extend(pending.get(row['event_id'], []))
    archive['events'] = normalized
    renumber(archive)


def test_complete_four_write_configuration_is_independently_derived(archive):
    before = deepcopy(archive)
    result = projector()(**archive)
    assert result['kind'] == 'dma.cpu_configuration'
    assert result['outcome'] == 'passed', (result['details']['issues'],
        result['details']['component_evidence']['word_transfer']['details']['issues'],
        [row['issues'] for row in result['details']['edges']])
    assert result['details']['operands'] == archive['attempt']['operands']
    assert result['details']['configuration_transactions'] == [
        row['transaction'] for row in rows(archive, 'data_accept')]
    assert archive == before


def test_selected_configuration_checks_native_swb_sel(archive):
    archive['contract']['dma']['master_endpoint_link']={'template_binding':{'variant_id':'dma-selected'}}
    requests=[r for r in rows(archive,'dma_edge') if r['payload']['pre_backend']['swb_stb']==1]
    for request in requests:request['payload']['pre_backend']['swb_sel']=15
    refresh(archive)
    assert projector()(**archive)['outcome']=='passed'
    requests[0]['payload']['pre_backend']['swb_sel']=3
    refresh(archive)
    assert projector()(**archive)['outcome']=='failed'


def test_configuration_accepts_held_strobe_only_after_stall_clears(archive):
    edges=rows(archive,'dma_edge')[:3]
    first=edges[0]['payload']['pre_backend']
    first['swb_stall']=1
    second=edges[1]['payload']['pre_backend']
    second['swb_stb']=1
    second['swb_stall']=0
    second['swb_ack']=0
    final=edges[2]['payload']['pre_backend']
    final.update(swb_cyc=1,swb_stb=0,swb_we=1,swb_adr=first['swb_adr'],
        swb_dat_w=first['swb_dat_w'],swb_ack=1)
    idle=deepcopy(edges[2]);idle['event_id']=max(r['event_id'] for r in archive['events'])+1
    idle['tick']=103
    idle['payload']['pre_backend'].update(swb_cyc=0,swb_stb=0,swb_we=0,
        swb_adr=0,swb_dat_w=0,swb_ack=0)
    archive['events'].append(idle)
    rows(archive,'mmio_delivery')[0]['dma_control_receipt']['edge_ticks'].append(103)
    refresh(archive)
    assert projector()(**archive)['outcome']=='passed'
    first['swb_dat_w'] ^= 1
    refresh(archive)
    assert projector()(**archive)['outcome']=='failed'


def test_declared_dma_sel_mode_comes_from_endpoint_binding():
    from myfuzz.integration.compiled_f6_saved_semantics import _selected_dma, _EvidenceIssue
    source={'schema_version':'declared_f6_dma_source_contract.v1'}
    dma={'source_contract':source,'master_endpoint_link':{'template_binding':{'variant_id':'dma-selected'}}}
    assert _selected_dma({'dma':dma}) is True
    dma['master_endpoint_link']['template_binding']['variant_id']='dma-full-word-no-select'
    assert _selected_dma({'dma':dma}) is False
    dma['master_endpoint_link']['template_binding']['variant_id']='unrecognized'
    with pytest.raises(_EvidenceIssue,match='DMA master endpoint variant'):
        _selected_dma({'dma':dma})
    del dma['master_endpoint_link']
    with pytest.raises(_EvidenceIssue,match='declared DMA master endpoint binding'):
        _selected_dma({'dma':dma})


@pytest.mark.parametrize('control,master',[(True,False),(False,True)])
def test_saved_dma_select_modes_are_independent(control,master):
    from myfuzz.integration.compiled_f6_saved_semantics import _selected_dma
    variant=lambda value:'dma-selected' if value else 'dma-full-word-no-select'
    contract={'dma':{'source_contract':{'schema_version':'declared_f6_dma_source_contract.v1'},
        'master_endpoint_link':{'template_binding':{'variant_id':variant(master)}},
        'selected_template':{'control':{'variant_id':variant(control)}}}}
    assert _selected_dma(contract)==master
    assert _selected_dma(contract,side='control')==control


@pytest.mark.parametrize('kind,field,value', [
    ('data_accept','wdata',7), ('data_response','wdata',7),
    ('data_response','be',1), ('data_response','error',1),
    ('mmio_acceptance','write_value',7), ('mmio_delivery','write_value',7),
    ('mmio_delivery','device_id','other'), ('mmio_delivery','delivery_order',4),
])
def test_observed_configuration_contradiction_fails(archive, kind, field, value):
    rows(archive, kind)[0][field] = value
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'failed'


def test_response_transaction_mismatch_is_failed_not_missing(archive):
    rows(archive, 'data_response')[0]['transaction']['testcase_id'] = 'foreign'
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'failed'


def test_duplicate_same_domain_response_is_failed(archive):
    duplicate = deepcopy(rows(archive, 'data_response')[0])
    duplicate['event_id'] = len(archive['events'])+1
    archive['events'].append(duplicate)
    assert projector()(**archive)['outcome'] == 'failed'


def test_missing_instruction_snapshot_is_missing(archive):
    del rows(archive, 'instr_response')[0]['snapshot']
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'missing'


def test_conflicting_control_request_outside_claimed_ticks_is_failed(archive):
    duplicate = deepcopy(rows(archive, 'dma_edge')[0])
    duplicate.update(event_id=len(archive['events'])+1, tick=999)
    duplicate['payload']['pre_backend']['swb_dat_w'] = 7
    archive['events'].append(duplicate)
    assert projector()(**archive)['outcome'] == 'failed'


@pytest.mark.parametrize('kind', ['data_accept','data_response','mmio_acceptance','dma_edge','local_tick_sample'])
def test_missing_required_archived_observations_are_missing(archive, kind):
    archive['events'] = [r for r in archive['events'] if r.get('kind') != kind]
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'missing'


def test_claimed_outcome_and_semantic_details_do_not_change_projection(archive):
    expected = projector()(**archive)
    archive['attempt'].update(outcome='failed', observation_status='failed',
        case_material={'evidence_inventory': {'forged': {'outcome':'passed'}}},
        details={'configuration_transactions':[]})
    assert projector()(**archive) == expected


def test_partial_missing_operand_does_not_hide_wrong_control_value(archive):
    archive['attempt']['operands'] = []
    rows(archive, 'data_accept')[0]['wdata'] = 7
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'failed'


def test_snapshot_contradiction_is_failed(archive):
    rows(archive, 'instr_response')[0]['snapshot']['data_hex'] = '00000000'
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'failed'


def test_observer_projection_cannot_replace_runner_facts(archive):
    key = ('processor_alpha', archive['attempt']['configuration'][0])
    archive['local_by_id'][key]['wdata'] = 7
    assert projector()(**archive)['outcome'] == 'failed'


def test_cross_case_selected_delivery_is_failed(archive):
    rows(archive, 'mmio_delivery')[0]['provenance']['observed_case']['case_id'] = 'foreign'
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'failed'


def test_native_cpu_handshake_contradiction_is_failed(archive):
    sample = next(r for r in rows(archive, 'local_tick_sample')
        if r['local_tick']==41 and r['phase']=='pre')
    sample['outputs']['backend']['d_rsp_ready'] = 0
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'failed'


def test_receipt_without_native_ack_is_missing(archive):
    for row in rows(archive, 'dma_edge'):
        row['payload']['pre_backend']['swb_ack'] = 0
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'missing'


def test_noncanonical_prefix_is_failed(archive):
    archive['attempt']['prefix_hex'] = '00'*128
    assert projector()(**archive)['outcome'] == 'failed'


def test_later_control_status_read_is_not_an_extra_configuration_write(archive):
    # An actual complete attempt reads CONTROL in its ISR after configuring it.
    for kind in ('data_accept','data_response','mmio_acceptance','mmio_delivery'):
        row = deepcopy(rows(archive, kind)[-1])
        row['event_id'] = len(archive['events'])+1
        row['write'] = 0 if kind.startswith('data_') else False
        field = 'transaction' if kind.startswith('data_') else 'source_transaction'
        row[field]['source_sequence'] += 100
        row['acceptance_tick'] = 200
        archive['events'].append(row)
    edge = deepcopy(rows(archive, 'dma_edge')[-3])
    edge.update(event_id=len(archive['events'])+1, tick=200)
    edge['payload']['pre_backend']['swb_we'] = 0
    archive['events'].append(edge)
    assert projector()(**archive)['outcome'] == 'passed'


def test_missing_cpu_acceptance_does_not_hide_control_receipt_contradiction(archive):
    archive['events'] = [r for r in archive['events'] if r.get('kind') != 'data_accept']
    rows(archive, 'mmio_delivery')[0]['dma_control_receipt']['value'] = 7
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'failed'


def test_out_of_order_full_transaction_sequence_is_failed(archive):
    # Keep every linked copy consistent; chronology must still reject it.
    for row in archive['events']:
        for field in ('transaction','source_transaction'):
            key = row.get(field)
            if key and key['channel_id']=='data' and key['source_sequence']==5:
                key['source_sequence'] = 99
        if row.get('source_sequence') == 5:
            row['source_sequence'] = 99
        receipt = row.get('dma_control_receipt')
        if receipt and receipt['source_transaction']['source_sequence'] == 5:
            receipt['source_transaction']['source_sequence'] = 99
            receipt['delivery_context']['source_transaction']['source_sequence'] = 99
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'failed'


@pytest.mark.parametrize('same_key', [True, False])
def test_read_shaped_same_key_or_same_tick_response_is_still_a_conflict(archive, same_key):
    row = deepcopy(rows(archive, 'data_response')[0])
    row.update(event_id=len(archive['events'])+1, write=0)
    if not same_key:
        row['transaction']['source_sequence'] += 100
    archive['events'].append(row)
    assert projector()(**archive)['outcome'] == 'failed'


def test_missing_all_cpu_edges_does_not_hide_wrong_native_control_request(archive):
    archive['events'] = [r for r in archive['events'] if r['component'] != 'processor_alpha']
    rows(archive, 'dma_edge')[0]['payload']['pre_backend']['swb_dat_w'] = 7
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'failed'


@pytest.mark.parametrize('kind', ['data_response','dma_edge'])
def test_invalid_operation_in_configuration_address_domain_is_not_filtered(archive, kind):
    row = deepcopy(rows(archive, kind)[0])
    row['event_id'] = len(archive['events'])+1
    if kind == 'data_response':
        row.update(write=2, acceptance_tick=999)
        row['transaction']['source_sequence'] += 100
    else:
        row['tick'] = 999
        row['payload']['pre_backend']['swb_we'] = 2
    archive['events'].append(row)
    assert projector()(**archive)['outcome'] == 'failed'


def forge_sequences(archive, channel):
    archive['events'] = json.loads(json.dumps(archive['events']))
    def change(value):
        if isinstance(value, dict):
            if value.get('channel_id') == channel and 'source_sequence' in value:
                value['source_sequence'] += 100
            if channel == 'data' and 'source_transaction' in value and 'source_sequence' in value:
                value['source_sequence'] += 100
            for child in value.values():
                change(child)
        elif isinstance(value, list):
            for child in value:
                change(child)
    change(archive['events'])
    refresh(archive)


@pytest.mark.parametrize('channel', ['instr', 'data'])
def test_consistently_forged_channel_sequence_cannot_override_native_ordinal(archive, channel):
    # Every linked transaction agrees; only the actual PRE handshake count
    # distinguishes these forged sequence numbers from the producer's keys.
    forge_sequences(archive, channel)
    assert projector()(**archive)['outcome'] == 'failed'


def test_absent_cpu_sequence_reset_anchor_is_missing(archive):
    archive['events'] = [r for r in archive['events']
                         if r.get('kind') not in ('cpu_native_startup', 'cpu_reset')]
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'missing'


@pytest.mark.parametrize('mutation', ['none', 'wrong_producer', 'wrong_scope',
                                      'wrong_driver_sample', 'wrong_startup_receipt'])
def test_native_startup_may_drain_inside_first_step(mutation, archive):
    cpu = archive['contract']['cpu']['instance_id']
    anchor = rows(archive, 'cpu_native_startup')[0]
    pre = next(r for r in rows(archive, 'local_tick_sample')
               if r['local_tick'] == 1 and r['phase'] == 'pre')
    post = next(r for r in rows(archive, 'local_tick_sample')
                if r['local_tick'] == 1 and r['phase'] == 'post')
    producer = next(r for r in archive['events'] if r['event_id'] == pre['producer_event_id'])
    anchor.update(producer_event_id=producer['event_id'], schema_version='cpu_native_startup.v1',
        phase='startup_ready', receipt_id={'execution': 'local-driver:'+cpu+':1', 'sequence': 0},
        command_scope={'component': cpu, 'reset_epoch': 0, 'command_sequence': 0})
    for sample in (pre, post): sample['f6_obi_scope'] = ['a'*32, 1, 0, 1]
    producer['outputs']['driver_samples'] = [dict(local_tick=1,
        pre=deepcopy(pre['outputs']), post=deepcopy(post['outputs']))]
    archive['events'].remove(anchor)
    archive['events'].insert(archive['events'].index(producer)+1, anchor)
    renumber(archive)
    if mutation == 'wrong_producer': anchor['producer_event_id'] += 10000
    elif mutation == 'wrong_scope': post['f6_obi_scope'][1] = 2
    elif mutation == 'wrong_driver_sample': producer['outputs']['driver_samples'][0]['pre'] = {}
    elif mutation == 'wrong_startup_receipt': anchor['receipt_id']['sequence'] = 1
    refresh(archive)
    result = projector()(**archive)
    assert result['outcome'] == ('passed' if mutation == 'none' else 'failed'), result['details']['issues']


def test_missing_response_does_not_hide_wrong_acceptance_sequence(archive):
    archive['events'] = [r for r in archive['events'] if r.get('kind') != 'data_response']
    forge_sequences(archive, 'data')
    assert projector()(**archive)['outcome'] == 'failed'


def test_sequence_history_gap_before_selected_handshakes_is_missing(archive):
    archive['events'] = [r for r in archive['events']
        if not (r.get('kind') == 'local_tick_sample' and r.get('local_tick') == 5)]
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'missing'


def test_sequence_count_includes_previous_logical_case_handshakes(archive):
    for row in rows(archive, 'local_tick_sample'):
        if row['local_tick'] in (12,13,16,17,20,21,24,25):
            row['provenance']['observed_case'] = dict(case_id='previous:logical:case', case_index=99)
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'passed'


def test_latest_native_reset_restarts_both_channel_ordinals(archive):
    old = next(r for r in rows(archive, 'local_tick_sample')
               if r['local_tick'] == 5 and r['phase'] == 'pre')
    old['outputs']['backend'].update(i_req_valid=1, d_req_valid=1)
    reset = deepcopy(rows(archive, 'cpu_native_startup')[0])
    reset.update(kind='cpu_reset', event_id=len(archive['events'])+1,
                 local_tick=9, tick=9, reset_epoch=1, source_epoch=1)
    first_after_reset = next(i for i,r in enumerate(archive['events'])
        if 'kind' not in r and r.get('local_tick') == 10)
    archive['events'].insert(first_after_reset, reset)
    def epoch(value):
        if isinstance(value, dict):
            if 'channel_id' in value:
                value['source_epoch'] = 1
            for child in value.values():
                epoch(child)
        elif isinstance(value, list):
            for child in value:
                epoch(child)
    epoch(archive['events'])
    for row in archive['events']:
        if 'kind' not in row and row.get('local_tick', 0) > 9:
            row['outputs']['data_rsp_source_epoch'] = 1
            row['outputs']['instr_rsp_source_epoch'] = 1
    renumber(archive)
    assert projector()(**archive)['outcome'] == 'passed'


def test_same_value_write_response_cannot_borrow_other_transaction_consume_tick(archive):
    first, second = rows(archive, 'data_response')[:2]
    assert first['rdata'] == second['rdata'] == 0
    first['response_tick'] = second['response_tick']
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'failed'


@pytest.mark.parametrize('field,value', [('data_rsp_consumed',0),
    ('data_rsp_source_epoch',9), ('data_rsp_source_sequence',999), ('data_rsp_rdata',7)])
def test_cpu_data_response_binds_runner_producer_identity(archive, field, value):
    producer = next(r for r in archive['events'] if 'kind' not in r and r.get('local_tick') == 41)
    producer['outputs'][field] = value
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'failed'


def test_instruction_response_requires_runner_producer_consumption(archive):
    producer = next(r for r in archive['events'] if 'kind' not in r and r.get('local_tick') == 11)
    producer['outputs']['instr_rsp_consumed'] = 0
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'failed'


@pytest.mark.parametrize('remove_accept', [False, True])
def test_missing_response_does_not_hide_native_configuration_request_contradiction(archive, remove_accept):
    missing = ('data_accept','data_response') if remove_accept else ('data_response',)
    archive['events'] = [r for r in archive['events'] if r.get('kind') not in missing]
    pre = next(r for r in rows(archive, 'local_tick_sample')
        if r['phase'] == 'pre' and r['local_tick'] == 40)
    pre['outputs']['backend']['d_req_wdata'] = 7
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'failed'


@pytest.mark.parametrize('contradictory', [False, True])
def test_extra_ack_in_claimed_control_callback_is_failed(archive, contradictory):
    request, ack, idle = rows(archive, 'dma_edge')[:3]
    idle['payload']['pre_backend'] = deepcopy(ack['payload']['pre_backend'])
    if contradictory:
        idle['payload']['pre_backend']['swb_dat_w'] = 7
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'failed'


def test_control_callback_cannot_omit_post_ack_idle_from_receipt(archive):
    rows(archive, 'mmio_delivery')[0]['dma_control_receipt']['edge_ticks'].pop()
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'failed'


def test_control_callback_cannot_replace_final_idle_with_active_cycle(archive):
    rows(archive, 'dma_edge')[2]['payload']['pre_backend']['swb_cyc'] = 1
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'failed'


def test_late_archived_reset_cannot_retroactively_anchor_sequence_history(archive):
    reset = deepcopy(rows(archive, 'cpu_native_startup')[0])
    reset.update(kind='cpu_reset', event_id=len(archive['events'])+1, local_tick=9, tick=9)
    archive['events'].append(reset)
    assert projector()(**archive)['outcome'] == 'failed'


def test_fixture_uses_normalized_runner_cpu_drain_order(archive):
    for row in rows(archive, 'instr_response')+rows(archive, 'data_response')+rows(archive, 'data_accept'):
        tick = row['acceptance_tick'] if row['kind']=='data_accept' else row['response_tick']
        producer = next(r for r in archive['events'] if 'kind' not in r and r.get('local_tick')==tick)
        pre = next(r for r in rows(archive, 'local_tick_sample')
                   if r['local_tick']==tick and r['phase']=='pre')
        assert producer['event_id'] < row['event_id'] < pre['event_id']
        if row['kind']=='data_accept':
            routed = next(r for r in rows(archive, 'mmio_acceptance')
                          if r['source_transaction']==row['transaction'])
            assert producer['event_id'] < routed['event_id'] < row['event_id']
        if row['kind']=='data_response':
            delivered = next(r for r in rows(archive, 'mmio_delivery')
                             if r['source_transaction']==row['transaction'])
            assert delivered['event_id'] < producer['event_id']


@pytest.mark.parametrize('kind', ['instr_response','data_accept','data_response','mmio_acceptance','mmio_delivery'])
def test_semantic_event_producer_cannot_be_borrowed_from_another_step(archive, kind):
    first, second = rows(archive, kind)[:2]
    first['producer_event_id'] = second['producer_event_id']
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'failed'


@pytest.mark.parametrize('normalized_link', [False, True])
def test_equal_instruction_response_cannot_borrow_later_consume_tick(archive, normalized_link):
    first = rows(archive, 'instr_response')[0]
    donor = deepcopy(first)
    donor.update(event_id=len(archive['events'])+1, acceptance_tick=26, response_tick=27,
                 address=first['address']+512, raw_address=first['address']+512,
                 aligned_address=first['address']+512)
    donor['transaction']['source_sequence'] = 5
    archive['events'].append(donor)
    for row in rows(archive, 'local_tick_sample'):
        if row['local_tick']==26:
            row['outputs']['backend'].update(i_req_valid=1, i_req_ready=1, i_req_write=0,
                i_req_addr=donor['address'], i_req_be=15, i_req_wdata=0)
        if row['local_tick']==27:
            row['outputs']['backend'].update(i_rsp_valid=1, i_rsp_ready=1,
                i_rsp_rdata=first['rdata'], i_rsp_error=0)
    producer = next(r for r in archive['events'] if 'kind' not in r and r.get('local_tick')==27)
    producer['outputs'].update(instr_rsp_consumed=1, instr_rsp_source_epoch=0,
                              instr_rsp_source_sequence=5, instr_rsp_rdata=first['rdata'])
    normalize_cpu_drains(archive)
    first['response_tick'] = 27
    if normalized_link:
        # Move the forged row and its producer link into the donor step's
        # normalized drain order; stale metadata cannot explain rejection.
        normalize_cpu_drains(archive)
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'failed'


def test_control_delivery_cannot_borrow_an_earlier_dma_trigger_step(archive):
    first, second = rows(archive, 'mmio_delivery')[:2]
    second['producer_event_id'] = first['producer_event_id']
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'failed'


def test_dma_edge_journal_drain_may_follow_router_delivery(archive):
    edges = rows(archive, 'dma_edge')
    archive['events'] = [r for r in archive['events'] if r.get('kind') != 'dma_edge']+edges
    renumber(archive)
    assert projector()(**archive)['outcome'] == 'passed'


@pytest.mark.parametrize('field,value', [('instr_rsp_source_epoch',9),
    ('instr_rsp_source_sequence',999), ('instr_rsp_rdata',7)])
def test_instruction_response_matches_exact_producer_transaction(archive, field, value):
    producer = next(r for r in archive['events'] if 'kind' not in r and r.get('local_tick')==11)
    producer['outputs'][field] = value
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'failed'


@pytest.mark.parametrize('field', ['instr_rsp_source_epoch','instr_rsp_source_sequence','instr_rsp_rdata'])
def test_instruction_response_without_producer_identity_is_missing(archive, field):
    producer = next(r for r in archive['events'] if 'kind' not in r and r.get('local_tick')==11)
    del producer['outputs'][field]
    refresh(archive)
    assert projector()(**archive)['outcome'] == 'missing'


def test_router_acceptance_must_precede_cpu_acceptance_in_same_step(archive):
    accepted = rows(archive, 'data_accept')[0]
    routed = rows(archive, 'mmio_acceptance')[0]
    i = archive['events'].index(accepted)
    j = archive['events'].index(routed)
    archive['events'][i], archive['events'][j] = archive['events'][j], archive['events'][i]
    renumber(archive)
    assert projector()(**archive)['outcome'] == 'failed'


def word_projector():
    name = 'myfuzz.integration.compiled_f6_saved_semantics'
    assert importlib.util.find_spec(name) is not None, 'saved word-transfer projector is missing'
    function = getattr(importlib.import_module(name), 'project_saved_word_transfer', None)
    assert callable(function), 'saved word-transfer projector is missing'
    return function


def edge_projector():
    function = getattr(importlib.import_module(
        'myfuzz.integration.compiled_f6_saved_semantics'),
        'project_saved_cross_component_edges', None)
    assert callable(function), 'saved declared-edge projector is missing'
    def project(**archive):
        artifact = archive.pop('_cpu_artifact')
        return function(**archive, cpu_artifact=artifact)
    return project


def f6_acceptance_anchor(acceptance):
    return dict(schema_version='compiled_F6_instruction_acceptance_anchor.v1',
        **deepcopy(acceptance))


def _word_route_binding(contract):
    from hashlib import sha256
    from myfuzz.scenario.runtime_path_contract import DmaMasterRouteContract

    p = contract['program_contract']
    cpu, dma = contract['cpu']['instance_id'], contract['dma']['instance_id']
    resource = contract['memory']['resource']
    target_identity = 'b' * 64
    routes = []
    intents = []
    bindings = []
    for index, operation in enumerate(('read', 'write')):
        route_id = 'copy.' + operation
        intent = dict(route_id=route_id, initiator_instance=dma,
            initiator_endpoint_id='dma.memory',
            target=dict(kind='persistent_memory', component_instance=cpu,
                resource_id=resource['resource_id']),
            base=resource['base'], size=resource['size'], operation=operation,
            permissions=[operation], byte_enable=15, readable_offsets=[],
            writable_offsets=[], accepted_write_values=dict(kind='values', values=[]))
        intents.append(intent)
        bindings.append(dict(route_id=route_id,
            initiator=contract['master_routes']['physical_endpoint_link']['template_binding'],
            target=dict(kind='persistent_memory', owner_profile_fingerprint='profile',
                resource_sha256='c' * 64)))
        route = DmaMasterRouteContract(rule_index=index * 2,
            prerequisite_index=0, source_node_id='dma.' + operation,
            target_node_id='ram.' + operation, initiator_component=dma,
            endpoint_id='dma.memory', endpoint_identity_sha256='a' * 64,
            target_kind='persistent_memory', target_component=cpu,
            target_id=resource['resource_id'], base=resource['base'],
            size=resource['size'], operation=operation,
            permissions=(operation,), byte_enable=15, readable_offsets=(),
            writable_offsets=(), accepted_write_values=(),
            target_identity_sha256=target_identity)
        routes.append(route.document())
    contract['master_routes'].update(intents=dict(schema_version='dma_master_route_intent.v1',
        routes=intents), bindings=bindings)
    contract['memory']['resource']['resource_id'] = resource['resource_id']
    contract['dma']['master_endpoint_link'] = contract['master_routes']['physical_endpoint_link']
    runtime_path = dict(selected_dma_routes=deepcopy(routes))
    body = dict(schema_version='compiled_F6_execution_binding.v1',
        run_id='synthetic-run', path_id=contract['path_id'], flow_id='F6',
        runtime_path_admission=runtime_path, dma_routes=deepcopy(routes),
        memory=dict(identity_sha256=target_identity))
    body['binding_sha256'] = sha256(json.dumps(body, sort_keys=True,
        separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
    return body


def _word_commit_doc(key, *, address, value, memory_id, memory_base, version):
    from hashlib import sha256
    from myfuzz.scenario.ledger import TransactionKey
    writer_event_id = str(TransactionKey(**key)) if type(key) is dict else str(key)
    payload = dict(op='write', address=address, value=value,
        width_bytes=4, byte_enable=15)
    payload_hash = sha256(json.dumps(payload, sort_keys=True,
        separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
    offset = address - memory_base
    document = dict(schema_version='memory_write_commit_receipt.v1',
        fullkey=deepcopy(key), memory_kind='modeled_host_persistent_memory',
        memory_id=memory_id, generation=0, byte_offset=offset,
        width_bytes=4, byte_enable=15, version=list(version),
        payload_sha256=payload_hash, commit_status='complete',
        performed_effect=True,
        enabled_byte_cells=[dict(byte_offset=offset+lane,
            value=(value >> (8*lane)) & 255, version=list(version),
            writer_kind='STORE', writer_event_id=writer_event_id) for lane in range(4)])
    unsigned = json.dumps(document, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode()
    document['commit_id'] = sha256(unsigned).hexdigest()
    return document


@pytest.fixture
def word_transfer_archive(archive):
    """Raw synthetic Runner facts for an offline four-word DMA projection."""
    from copy import deepcopy
    from myfuzz.scenario.ledger import TransactionKey

    result = deepcopy(archive)
    attempt, contract = result['attempt'], result['contract']
    cpu, dma = contract['cpu']['instance_id'], contract['dma']['instance_id']
    p = contract['program_contract']
    raw = bytes.fromhex(attempt['raw8_hex'])
    values = [(int.from_bytes(raw, 'little') >> (11*i)) & 0x7ff for i in range(4)]
    assert values == [1, 2, 3, 4]
    attempt.update(sources=[], source_commits=[], reads=[None]*4,
        read_snapshots=[None]*4, read_responses=[None]*4, writes=[None]*4,
        word_commits=[None]*4, write_responses=[None]*4,
        expected_error=False, status_kind='passed')
    contract['path_id'] = 'F6:synthetic.word-transfer'
    contract['memory'] = dict(resource=dict(resource_id='shared_ram',
        component_instance=cpu, base=0x10000, size=0x20000,
        read=True, write=True, execute=True, initialization_policy='preload'))
    contract['master_routes'] = dict(physical_endpoint_link=dict(
        endpoint_id='dma.memory', template_binding=dict(
            template_id='master.wishbone-pipelined', template_version='1',
            variant_id='dma-full-word-no-select', contract_sha256='d'*64,
            profile_endpoint_sha256='e'*64, selection_sha256='f'*64)))
    result['binding'] = _word_route_binding(contract)
    memory = contract['memory']['resource']
    scope = dict(case_id=attempt['case_id'], case_index=attempt['case_index'])

    def new_event(row, owner, *, observer=False):
        row = deepcopy(row)
        row.update(component=owner, event_id=len(result['events'])+1,
            provenance=dict(observed_case=deepcopy(scope)))
        result['events'].append(row)
        if not observer:
            return row['event_id']
        observer_id = max((value['event_id'] for value in result['local_by_id'].values()),
            default=1000) + 1
        local = dict(deepcopy(row), event_id=observer_id,
            runner_event_id=row['event_id'])
        result['local_by_id'][owner, observer_id] = local
        return observer_id

    def insert_cpu_drain(row, tick):
        producer = next(event for event in result['events']
            if event.get('component') == cpu and 'kind' not in event
            and event.get('local_tick') == tick)
        row = deepcopy(row)
        row.update(component=cpu, event_id=max(e['event_id'] for e in result['events'])
            + 100000 + len(insertions) + 1,
            provenance=dict(observed_case=deepcopy(scope)))
        row['producer_event_id'] = producer['event_id']
        insertions.append((producer['event_id'], row))

    insertions = []
    for index, value in enumerate(values):
        transaction = dict(execution_id='local-execution', testcase_id='native-testcase',
            source_component=cpu, source_epoch=0, channel_id='data',
            source_sequence=index+1)
        address = p['source_address'] + 4*index
        accepted_tick = 12 + 4*index
        response_tick = accepted_tick + 1
        producer = next(event for event in result['events']
            if event.get('component') == cpu and 'kind' not in event
            and event.get('local_tick') == accepted_tick)
        accept = dict(kind='data_accept', transaction=transaction,
            address=address, raw_address=address, aligned_address=address,
            write=1, be=15, wdata=value, acceptance_tick=accepted_tick)
        insert_cpu_drain(accept, accepted_tick)
        response = dict(kind='data_response', transaction=transaction,
            address=address, raw_address=address, aligned_address=address,
            write=1, be=15, wdata=value, acceptance_tick=accepted_tick,
            response_tick=response_tick, error=0, rdata=0)
        insert_cpu_drain(response, response_tick)
        source_key = TransactionKey(**transaction)
        version = [0, index+1]
        commit = _word_commit_doc(transaction, address=address, value=value,
            memory_id=memory['resource_id'], memory_base=memory['base'], version=version)
        source = dict(kind='memory_write', transaction=transaction,
            address=address, width_bytes=4, memory_id=memory['resource_id'],
            generation=0, byte_offset=address-memory['base'], value=value,
            byte_enable=15, version=version)
        result['attempt']['sources'].append(new_event(source, cpu, observer=True))
        commit_event = dict(kind='memory_write_commit', schema_version='memory_write_commit.v1',
            service_commit_sequence=index+1, transaction=transaction,
            commit_id=commit['commit_id'], commit_document=commit)
        attempt['source_commits'].append(new_event(commit_event, cpu, observer=True))

    for producer_id, row in sorted(insertions, key=lambda item:item[0], reverse=True):
        position = next(i for i, event in enumerate(result['events'])
            if event['event_id'] == producer_id)
        result['events'].insert(position+1, row)
    renumber(result)
    # Rebuild the source rows' Observer links after Runner IDs were shifted.
    refresh(result)

    route_rows = {row['operation']: row
        for row in result['binding']['dma_routes']}
    dma_execution, dma_testcase, dma_epoch = 'dma-execution', 'dma-case-0', 0
    dma_sequence = 0
    next_tick = 100
    for operation in ('read', 'write'):
        for index, value in enumerate(values):
            dma_sequence += 1
            write = operation == 'write'
            address = (p['destination_address'] if write else p['source_address']) + 4*index
            transaction = dict(execution_id=dma_execution, testcase_id=dma_testcase,
                source_component=dma, source_epoch=dma_epoch, channel_id='dma-memory',
                source_sequence=dma_sequence)
            pre = dict(mwb_cyc=1, mwb_stb=1, mwb_we=int(write),
                mwb_adr=address >> 2, mwb_dat_w=value if write else 0,
                mwb_stall=0, mwb_ack=0, mwb_err=0, mwb_dat_r=0)
            accepted = dict(transaction=transaction, address=address,
                word_address=address >> 2, write=write,
                value=value if write else 0, byte_enable=15)
            accept_row = dict(kind='dma_edge', tick=next_tick,
                payload=dict(pre_backend=pre), accepted=accepted)
            attempt_group = 'writes' if write else 'reads'
            ref_index = index
            ref = new_event(accept_row, dma, observer=True)
            attempt[attempt_group][ref_index] = ref
            source_key = dict(execution_id='local-execution', testcase_id='native-testcase',
                source_component=cpu, source_epoch=0, channel_id='data',
                source_sequence=index+1)
            if not write:
                source_commit = next(row for row in result['events']
                    if row.get('kind') == 'memory_write_commit'
                    and row.get('component') == cpu
                    and row.get('transaction') == source_key)
                version = deepcopy(source_commit['commit_document']['version'])
                snapshot = dict(kind='memory_read', transaction=transaction,
                    address=address, width_bytes=4, memory_id=memory['resource_id'],
                    generation=0, byte_offset=address-memory['base'], value=value,
                    data_hex=value.to_bytes(4, 'little').hex(), versions=[version]*4,
                    writer_event_ids=[str(TransactionKey(**source_key))]*4,
                    writer_kinds=['STORE']*4)
                attempt['read_snapshots'][index] = new_event(snapshot, dma, observer=True)
            else:
                version = [0, 5+index]
                doc = _word_commit_doc(transaction, address=address, value=value,
                    memory_id=memory['resource_id'], memory_base=memory['base'], version=version)
                commit_event = dict(kind='memory_write_commit',
                    schema_version='memory_write_commit.v1',
                    service_commit_sequence=index+1, transaction=transaction,
                    commit_id=doc['commit_id'], commit_document=doc)
                attempt['word_commits'][index] = new_event(commit_event, dma, observer=True)
            next_tick += 1
            response_pre = dict(mwb_cyc=0, mwb_stb=0, mwb_we=0, mwb_adr=0,
                mwb_dat_w=0, mwb_stall=0, mwb_ack=1, mwb_err=0,
                mwb_dat_r=value if not write else 0)
            response = dict(transaction=transaction, rdata=value if not write else 0,
                error=0, delay=0)
            response_row = dict(kind='dma_edge', tick=next_tick,
                payload=dict(pre_backend=response_pre), response=response)
            attempt['read_responses' if not write else 'write_responses'][index] = \
                new_event(response_row, dma, observer=True)
            next_tick += 1

    return result


def test_four_word_archive_joins_runner_facts_to_bound_routes(word_transfer_archive):
    before = deepcopy(word_transfer_archive)
    result = word_projector()(**word_transfer_archive)
    assert result['kind'] == 'dma.word_transfer_join'
    assert result['outcome'] == 'passed'
    assert [row['value'] for row in result['details']['words']] == [1, 2, 3, 4]
    assert [row['candidate_source_slice_hex'] for row in result['details']['words']] == [
        word_transfer_archive['local_by_id']['processor_alpha', ref]['snapshot']['data_hex']
        for ref in word_transfer_archive['attempt']['operands']]
    assert len(result['details']['operands']) == 4
    assert len(result['details']['raw_references']) >= 36
    assert word_transfer_archive == before


@pytest.mark.parametrize('mutation', [
    'observer', 'foreign_case', 'source_value', 'snapshot_writer',
    'snapshot_version', 'snapshot_bytes', 'accept_pre', 'response_pre',
    'destination_cell', 'destination_hash', 'wrong_route', 'same_accept_response',
    'duplicate_accept', 'reverse_words', 'operand_fetch', 'operand_snapshot',
    'source_pre',
])
def test_word_transfer_archive_rejects_adversarial_raw_mutations(word_transfer_archive, mutation):
    archive = word_transfer_archive
    if mutation == 'observer':
        ref = archive['attempt']['reads'][0]
        archive['local_by_id'][('mover_beta', ref)]['accepted']['address'] += 4
    elif mutation == 'foreign_case':
        rows(archive, 'memory_read')[0]['provenance']['observed_case']['case_id'] = 'other'
        refresh(archive)
    elif mutation == 'source_value':
        next(row for row in rows(archive, 'memory_write')
            if row['component'] == 'processor_alpha'
            and row['address'] == archive['contract']['program_contract']['source_address'])['value'] ^= 1
        refresh(archive)
    elif mutation in ('snapshot_writer', 'snapshot_version', 'snapshot_bytes'):
        row = rows(archive, 'memory_read')[0]
        field, value = {'snapshot_writer': ('writer_event_ids', ['foreign']*4),
            'snapshot_version': ('versions', [[0, 999]]*4),
            'snapshot_bytes': ('data_hex', '00000000')}[mutation]
        row[field] = value
        refresh(archive)
    elif mutation == 'accept_pre':
        next(row for row in rows(archive, 'dma_edge')
            if type(row.get('accepted')) is dict)['payload']['pre_backend']['mwb_adr'] += 1
        refresh(archive)
    elif mutation == 'response_pre':
        ref = archive['attempt']['read_responses'][0]
        observer = archive['local_by_id'][('mover_beta', ref)]
        next(row for row in archive['events']
            if row['event_id'] == observer['runner_event_id'])['payload']['pre_backend']['mwb_ack'] = 0
        refresh(archive)
    elif mutation in ('destination_cell', 'destination_hash'):
        observer = archive['local_by_id'][('mover_beta', archive['attempt']['word_commits'][0])]
        row = next(event for event in archive['events']
            if event['event_id'] == observer['runner_event_id'])
        if mutation == 'destination_cell':
            row['commit_document']['enabled_byte_cells'][0]['value'] ^= 1
        else:
            row['commit_document']['commit_id'] = '0' * 64
        refresh(archive)
    elif mutation == 'wrong_route':
        from dataclasses import replace
        from hashlib import sha256
        from myfuzz.scenario.runtime_path_contract import DmaMasterRouteContract
        route_doc = archive['binding']['dma_routes'][0]
        changed = replace(DmaMasterRouteContract.from_document(route_doc),
            base=route_doc['base']+4).document()
        archive['binding']['dma_routes'][0] = changed
        archive['binding']['runtime_path_admission']['selected_dma_routes'][0] = changed
        body = {key: value for key, value in archive['binding'].items()
            if key != 'binding_sha256'}
        archive['binding']['binding_sha256'] = sha256(json.dumps(body,
            sort_keys=True, separators=(',', ':'), ensure_ascii=False,
            allow_nan=False).encode()).hexdigest()
    elif mutation == 'same_accept_response':
        archive['attempt']['read_responses'][0] = archive['attempt']['reads'][0]
    elif mutation == 'duplicate_accept':
        duplicate = deepcopy(next(row for row in rows(archive, 'dma_edge')
            if type(row.get('accepted')) is dict))
        duplicate['event_id'] = len(archive['events'])+1
        archive['events'].append(duplicate)
    elif mutation == 'reverse_words':
        archive['attempt']['reads'][0], archive['attempt']['reads'][1] = \
            archive['attempt']['reads'][1], archive['attempt']['reads'][0]
    elif mutation in ('operand_fetch', 'operand_snapshot'):
        ref = archive['attempt']['operands'][0]
        observer = archive['local_by_id'][('processor_alpha', ref)]
        row = next(event for event in archive['events']
            if event['event_id'] == observer['runner_event_id'])
        if mutation == 'operand_fetch':
            row['rdata'] ^= 1
        else:
            row['snapshot']['data_hex'] = '00000000'
        refresh(archive)
    elif mutation == 'source_pre':
        tick = rows(archive, 'data_accept')[0]['acceptance_tick']
        sample = next(row for row in rows(archive, 'local_tick_sample')
            if row.get('component') == 'processor_alpha'
            and row.get('local_tick') == tick and row.get('phase') == 'pre')
        sample['outputs']['backend']['d_req_wdata'] ^= 1
    assert word_projector()(**archive)['outcome'] == 'failed'


@pytest.mark.parametrize('mutation', [
    'source_store', 'operand_fetch', 'dma_accept', 'read_snapshot',
    'destination_commit',
])
def test_missing_attempt_reference_does_not_hide_contradictory_raw_word_fact(
        word_transfer_archive, mutation):
    archive = word_transfer_archive
    if mutation == 'source_store':
        archive['attempt']['sources'][0] = None
        source_address = archive['contract']['program_contract']['source_address']
        source = next(row for row in rows(archive, 'memory_write')
            if row.get('component') == 'processor_alpha'
            and row.get('address') == source_address)
        source['value'] = 0
    elif mutation == 'dma_accept':
        archive['attempt']['reads'][0] = None
        accepted = next(row for row in rows(archive, 'dma_edge')
            if type(row.get('accepted')) is dict
            and row['accepted']['transaction']['source_sequence'] == 1)
        accepted['accepted']['address'] += 4
        accepted['accepted']['word_address'] = accepted['accepted']['address'] >> 2
        accepted['payload']['pre_backend']['mwb_adr'] = accepted['accepted']['word_address']
    elif mutation == 'operand_fetch':
        archive['attempt']['operands'][0] = None
        offset = archive['contract']['program_contract']['operand_instruction_offsets'][0]
        address = (archive['contract']['program_contract']['slot_base']
            + archive['contract']['program_contract']['slot_bytes']
                * archive['attempt']['case_index'] + offset)
        response = next(row for row in rows(archive, 'instr_response')
            if row.get('component') == 'processor_alpha' and row.get('address') == address)
        response['rdata'] ^= 1
    elif mutation == 'read_snapshot':
        archive['attempt']['reads'][0] = None
        snapshot = next(row for row in rows(archive, 'memory_read')
            if row.get('component') == 'mover_beta')
        snapshot['value'] ^= 1
        snapshot['data_hex'] = snapshot['value'].to_bytes(4, 'little').hex()
    else:
        archive['attempt']['writes'][0] = None
        commit = next(row for row in rows(archive, 'memory_write_commit')
            if row.get('component') == 'mover_beta')
        commit['commit_document']['enabled_byte_cells'][0]['value'] ^= 1
    refresh(archive)

    result = word_projector()(**archive)

    assert result['outcome'] == 'failed', result['details']['issues']


def test_missing_dma_response_is_missing_unless_another_fact_contradicts(word_transfer_archive):
    archive = word_transfer_archive
    contradictory = deepcopy(archive)
    ref = archive['attempt']['read_responses'][0]
    archive['events'] = [row for row in archive['events']
        if row.get('event_id') != archive['local_by_id'][('mover_beta', ref)]['runner_event_id']]
    del archive['local_by_id'][('mover_beta', ref)]
    assert word_projector()(**archive)['outcome'] == 'missing'

    contradictory_ref = contradictory['attempt']['read_responses'][0]
    contradictory['events'] = [row for row in contradictory['events']
        if row.get('event_id') != contradictory['local_by_id'][
            ('mover_beta', contradictory_ref)]['runner_event_id']]
    del contradictory['local_by_id'][('mover_beta', contradictory_ref)]
    rows(contradictory, 'memory_read')[0]['writer_event_ids'] = ['foreign']*4
    refresh(contradictory)
    assert word_projector()(**contradictory)['outcome'] == 'failed'


def test_selected_word_transfer_checks_native_mwb_sel(word_transfer_archive):
    archive=word_transfer_archive
    archive['contract']['dma']['master_endpoint_link']={'template_binding':{'variant_id':'dma-selected'}}
    requests=[r for r in rows(archive,'dma_edge') if r.get('accepted')]
    for request in requests:request['payload']['pre_backend']['mwb_sel']=15
    refresh(archive)
    assert word_projector()(**archive)['outcome']=='passed'
    requests[0]['payload']['pre_backend']['mwb_sel']=3
    refresh(archive)
    assert word_projector()(**archive)['outcome']=='failed'

@pytest.mark.parametrize('malformed_receipt', [False, True])
@pytest.mark.parametrize('mutate_prior_snapshot', [False, True])
@pytest.mark.parametrize('drop_error_response_selector', [False, True])
@pytest.mark.parametrize('drop_error_accept_selector', [False, True])
@pytest.mark.parametrize('foreign_prior_snapshot', [False, True])
def test_expected_error_never_passes_and_reports_prior_effects(
        word_transfer_archive, malformed_receipt, mutate_prior_snapshot,
        drop_error_response_selector, drop_error_accept_selector,
        foreign_prior_snapshot):
    archive = word_transfer_archive
    # Preserve only read word zero, then select a sealed ERR for read word one.
    accepted = [row for row in rows(archive, 'dma_edge')
        if type(row.get('accepted')) is dict]
    selected = accepted[1]
    selected_key = deepcopy(selected['accepted']['transaction'])
    selected_snapshot_ref = archive['attempt']['read_snapshots'][1]
    selected_success_response_ref = archive['attempt']['read_responses'][1]
    selected['environment_error_receipt'] = dict(
        schema_version='f6_dma_environment_error_receipt.v1',
        owner='mover_beta', source_transaction=selected_key, error=1,
        target_effect=False, timing='before_target_effect', op='master_environment_error',
        address=selected['accepted']['address'], write=False, value=0,
        byte_enable=15, reason='declared_f6_response_fault',
        selector=dict(case_index=0, operation='read', word_index=1),
        execution_binding_sha256=archive['binding']['binding_sha256'])
    if malformed_receipt:
        selected['environment_error_receipt']['target_effect'] = True
    selected['accepted']['transaction']['source_sequence'] = 2
    # Drop word one snapshot and all words after the selected error. Rebuild its ERR row.
    archive['attempt']['reads'] = [archive['attempt']['reads'][0], archive['attempt']['reads'][1], None, None]
    archive['attempt']['read_snapshots'] = [archive['attempt']['read_snapshots'][0], None, None, None]
    archive['attempt']['read_responses'] = [archive['attempt']['read_responses'][0], None, None, None]
    archive['attempt']['writes'] = [None]*4
    archive['attempt']['word_commits'] = [None]*4
    archive['attempt']['write_responses'] = [None]*4
    archive['attempt']['expected_error'] = True
    archive['attempt']['status_kind'] = 'expected_error'
    selected_snapshot = archive['local_by_id'].pop(('mover_beta', selected_snapshot_ref))
    selected_snapshot_runner_id = selected_snapshot['runner_event_id']
    archive['events'] = [row for row in archive['events']
        if row.get('event_id') != selected_snapshot_runner_id
        and not (row.get('component') == 'mover_beta'
            and row.get('kind') == 'memory_read'
            and row.get('transaction') == selected_key)]
    for ref in archive['attempt']['read_snapshots'][2:]:
        if ref is not None:
            snapshot_row = archive['local_by_id'].pop(('mover_beta', ref))
            snapshot_runner_id = snapshot_row['runner_event_id']
            archive['events'] = [row for row in archive['events']
                if row.get('event_id') != snapshot_runner_id]
    # The selected accepted row is terminal in the DMA stream; no later acceptance may survive.
    selected_id = selected['event_id']
    archive['events'] = [row for row in archive['events'] if not (
        row.get('component') == 'mover_beta' and row.get('kind') == 'dma_edge'
        and row.get('event_id') > selected_id)]
    # Replace the old successful word-one response with the native ERR response.
    success_response = archive['local_by_id'][('mover_beta', selected_success_response_ref)]
    response_runner_id = success_response['runner_event_id']
    archive['events'] = [row for row in archive['events'] if row.get('event_id') != response_runner_id]
    archive['local_by_id'].pop(('mover_beta', selected_success_response_ref))
    err_row = dict(kind='dma_edge', tick=selected['tick']+1,
        payload=dict(pre_backend=dict(mwb_ack=0, mwb_err=1, mwb_dat_r=0)),
        response=dict(transaction=selected_key, rdata=0, error=1, delay=0),
        component='mover_beta', provenance=deepcopy(selected['provenance']))
    err_row['event_id'] = max(row['event_id'] for row in archive['events'])+1
    archive['events'].append(err_row)
    observer_id = max(row['event_id'] for row in archive['local_by_id'].values())+1
    archive['local_by_id']['mover_beta', observer_id] = dict(deepcopy(err_row),
        event_id=observer_id, runner_event_id=err_row['event_id'])
    archive['attempt']['read_responses'][1] = observer_id
    if drop_error_response_selector:
        archive['attempt']['read_responses'][1] = None
    if drop_error_accept_selector:
        archive['attempt']['reads'][1] = None
    if mutate_prior_snapshot:
        archive['attempt']['read_snapshots'][0] = None
        prior_transaction = accepted[0]['accepted']['transaction']
        prior_snapshot = next(row for row in rows(archive, 'memory_read')
            if row.get('component') == 'mover_beta'
            and row.get('transaction') == prior_transaction)
        if foreign_prior_snapshot:
            prior_snapshot['provenance']['observed_case']['case_id'] = 'other-case'
        else:
            prior_snapshot['value'] ^= 1
            prior_snapshot['data_hex'] = prior_snapshot['value'].to_bytes(4, 'little').hex()
    remaining_runner_ids = {row['event_id'] for row in archive['events']}
    archive['local_by_id'] = {key: row for key, row in archive['local_by_id'].items()
        if row.get('runner_event_id') in remaining_runner_ids}
    renumber(archive)
    refresh(archive)
    error_ref = archive['attempt']['read_responses'][1]
    if error_ref is not None:
        error_runner_id = archive['local_by_id']['mover_beta', error_ref]['runner_event_id']
        archive['local_by_id'] = {key: row for key, row in archive['local_by_id'].items()
            if row.get('runner_event_id') != error_runner_id
            or key == ('mover_beta', error_ref)}
    result = word_projector()(**archive)
    assert result['outcome'] == 'failed', result['details']['issues']
    if mutate_prior_snapshot and foreign_prior_snapshot:
        foreign_snapshot_ids = {row['event_id'] for row in rows(archive, 'memory_read')
            if row.get('component') == 'mover_beta'
            and row.get('provenance', {}).get('observed_case', {}).get('case_id') == 'other-case'}
        case_snapshot_ids = {row['event_id'] for row in rows(archive, 'memory_read')
            if row.get('component') == 'mover_beta'
            and row.get('provenance', {}).get('observed_case', {}).get('case_id') == 'run:case:0'}
        partial_ids = set(result['details']['partial_effects']['read_snapshot_event_ids'])
        assert not (partial_ids & foreign_snapshot_ids)
        assert partial_ids == case_snapshot_ids
    else:
        assert result['details']['partial_effects']['read_snapshot_event_ids']
    assert result['details']['partial_effects']['error_response']
    assert not result['details']['words']
    if mutate_prior_snapshot:
        expected_reason = ('cross-case Runner evidence' if foreign_prior_snapshot
            else 'snapshot owner/address/data')
        assert any(expected_reason in issue['reason']
            for issue in result['details']['issues'])


def _write_error_archive(word_transfer_archive):
    archive = word_transfer_archive
    attempt = archive['attempt']
    dma = archive['contract']['dma']['instance_id']
    accepted = [row for row in rows(archive, 'dma_edge')
        if type(row.get('accepted')) is dict]
    selected = accepted[5]
    transaction = deepcopy(selected['accepted']['transaction'])
    raw = bytes.fromhex(attempt['raw8_hex'])
    words = [(int.from_bytes(raw, 'little') >> (11*index)) & 0x7ff
        for index in range(4)]
    attempt['expected_error'] = True
    attempt['status_kind'] = 'expected_error'
    old_commits = list(attempt['word_commits'])
    old_responses = list(attempt['write_responses'])
    attempt['writes'] = [attempt['writes'][0], attempt['writes'][1], None, None]
    attempt['word_commits'] = [old_commits[0], None, None, None]
    attempt['write_responses'] = [old_responses[0], None, None, None]
    selected['environment_error_receipt'] = dict(
        schema_version='f6_dma_environment_error_receipt.v1', owner=dma,
        source_transaction=transaction, error=1, target_effect=False,
        timing='before_target_effect', op='master_environment_error',
        address=selected['accepted']['address'], write=True, value=words[1],
        byte_enable=15, reason='declared_f6_response_fault',
        selector=dict(case_index=attempt['case_index'], operation='write',
            word_index=1), execution_binding_sha256=archive['binding']['binding_sha256'])
    selected_id = selected['event_id']
    removed_runner_ids = set()
    for ref in old_commits[1:]:
        observer = archive['local_by_id'].pop((dma, ref))
        removed_runner_ids.add(observer['runner_event_id'])
    for ref in old_responses[1:]:
        observer = archive['local_by_id'].pop((dma, ref))
        removed_runner_ids.add(observer['runner_event_id'])
    archive['events'] = [row for row in archive['events']
        if row.get('event_id') not in removed_runner_ids
        and not (row.get('component') == dma and row.get('kind') == 'dma_edge'
            and row.get('event_id') > selected_id)
        and not (row.get('component') == dma and row.get('kind') == 'memory_write_commit'
            and type(row.get('transaction')) is dict
            and row['transaction'].get('source_sequence', 0) >= 6)]
    error_row = dict(kind='dma_edge', tick=selected['tick']+1,
        payload=dict(pre_backend=dict(mwb_ack=0, mwb_err=1, mwb_dat_r=0)),
        response=dict(transaction=transaction, rdata=0, error=1, delay=0),
        component=dma, provenance=deepcopy(selected['provenance']))
    error_row['event_id'] = max(row['event_id'] for row in archive['events'])+1
    archive['events'].append(error_row)
    observer_id = max(row['event_id'] for row in archive['local_by_id'].values())+1
    archive['local_by_id'][dma, observer_id] = dict(deepcopy(error_row),
        event_id=observer_id, runner_event_id=error_row['event_id'])
    attempt['write_responses'][1] = observer_id
    remaining_runner_ids = {row['event_id'] for row in archive['events']}
    archive['local_by_id'] = {key: row for key, row in archive['local_by_id'].items()
        if row.get('runner_event_id') in remaining_runner_ids}
    renumber(archive)
    refresh(archive)
    return archive


@pytest.mark.parametrize('foreign_prior_commit', [False, True])
def test_expected_error_checks_raw_prior_commit_without_attempt_selector(
        word_transfer_archive, foreign_prior_commit):
    archive = _write_error_archive(word_transfer_archive)
    archive['attempt']['word_commits'][0] = None
    dma = archive['contract']['dma']['instance_id']
    prior_transaction = next(row['accepted']['transaction']
        for row in rows(archive, 'dma_edge')
        if type(row.get('accepted')) is dict
        and row['accepted']['transaction']['source_sequence'] == 5)
    prior_commit = next(row for row in rows(archive, 'memory_write_commit')
        if row.get('component') == dma
        and row.get('transaction') == prior_transaction)
    if foreign_prior_commit:
        prior_commit['provenance']['observed_case']['case_id'] = 'other-case'
    else:
        prior_commit['commit_document']['enabled_byte_cells'][0]['value'] ^= 1
    refresh(archive)

    result = word_projector()(**archive)

    assert result['outcome'] == 'failed'
    expected_reason = ('cross-case Runner evidence' if foreign_prior_commit
        else 'write commit hash/payload digest')
    assert any(expected_reason in issue['reason']
        for issue in result['details']['issues'])
    if foreign_prior_commit:
        assert not result['details']['partial_effects']['destination_commit_event_ids']
    else:
        assert result['details']['partial_effects']['destination_commit_event_ids']


def test_expected_error_without_raw_accepted_row_still_preserves_prior_effects(
        word_transfer_archive):
    archive = _write_error_archive(word_transfer_archive)
    attempt = archive['attempt']
    dma = archive['contract']['dma']['instance_id']
    selected_ref = attempt['writes'][1]
    selected_observer = archive['local_by_id'].pop((dma, selected_ref))
    selected_runner_id = selected_observer['runner_event_id']
    archive['events'] = [row for row in archive['events']
        if row.get('event_id') != selected_runner_id]
    attempt['writes'][1] = None
    renumber(archive)
    refresh(archive)

    result = word_projector()(**archive)

    assert result['outcome'] == 'failed'
    assert result['details']['partial_effects']['read_snapshot_event_ids']
    assert result['details']['partial_effects']['destination_commit_event_ids']
    assert any('selected native ERR has no referenced accepted beat'
        in issue['reason'] for issue in result['details']['issues'])


def test_expected_error_without_raw_err_response_preserves_observed_dma_prefix(
        word_transfer_archive):
    archive = _write_error_archive(word_transfer_archive)
    attempt = archive['attempt']
    dma = archive['contract']['dma']['instance_id']
    selected_ref = attempt['write_responses'][1]
    observer = archive['local_by_id'].pop((dma, selected_ref))
    runner_id = observer['runner_event_id']
    archive['events'] = [row for row in archive['events']
        if row['event_id'] != runner_id]
    attempt['write_responses'][1] = None
    renumber(archive)
    refresh(archive)

    result = word_projector()(**archive)

    dma = archive['contract']['dma']['instance_id']
    expected_snapshots = {row['event_id'] for row in rows(archive, 'memory_read')
        if row.get('component') == dma}
    expected_commits = {row['event_id'] for row in rows(archive, 'memory_write_commit')
        if row.get('component') == dma}
    partial = result['details']['partial_effects']
    assert result['outcome'] == 'missing', result['details']['issues']
    assert set(partial['read_snapshot_event_ids']) == expected_snapshots
    assert set(partial['destination_commit_event_ids']) == expected_commits
    assert {row['source_sequence'] for row in partial['accepted_transactions']} == set(range(1, 7))
    assert partial.get('error_response') is None
    assert any('no scoped native ERR response' in issue['reason']
        for issue in result['details']['issues'])


def test_expected_error_with_malformed_err_key_still_preserves_prior_effects(
        word_transfer_archive):
    archive = _write_error_archive(word_transfer_archive)
    dma = archive['contract']['dma']['instance_id']
    selected_ref = archive['attempt']['write_responses'][1]
    selected_observer = archive['local_by_id'][dma, selected_ref]
    selected = next(row for row in archive['events']
        if row['event_id'] == selected_observer['runner_event_id'])
    selected['response']['transaction']['source_sequence'] = 'invalid'
    refresh(archive)

    result = word_projector()(**archive)

    assert result['outcome'] == 'failed'
    assert result['details']['partial_effects']['read_snapshot_event_ids']
    assert result['details']['partial_effects']['destination_commit_event_ids']
    assert any('transaction owner/channel/field types' in issue['reason']
        for issue in result['details']['issues'])


@pytest.mark.parametrize('corrupt_snapshot', [False, True])
def test_missing_prior_acceptance_does_not_hide_case_scoped_effect(
        word_transfer_archive, corrupt_snapshot):
    archive = _write_error_archive(word_transfer_archive)
    attempt = archive['attempt']
    dma = archive['contract']['dma']['instance_id']
    error_ref = attempt['write_responses'][1]
    error_observer = archive['local_by_id'].pop((dma, error_ref))
    error_runner_id = error_observer['runner_event_id']
    accepted_ref = attempt['reads'][0]
    accepted_observer = archive['local_by_id'].pop((dma, accepted_ref))
    accepted_runner_id = accepted_observer['runner_event_id']
    archive['events'] = [row for row in archive['events']
        if row['event_id'] not in (error_runner_id, accepted_runner_id)]
    attempt['write_responses'][1] = None
    attempt['reads'][0] = None
    snapshot = next(row for row in rows(archive, 'memory_read')
        if row.get('component') == dma
        and row.get('transaction', {}).get('source_sequence') == 1)
    if corrupt_snapshot:
        snapshot['value'] ^= 1
        snapshot['data_hex'] = snapshot['value'].to_bytes(4, 'little').hex()
    renumber(archive)
    refresh(archive)
    expected_snapshot_id = next(row['event_id'] for row in rows(archive, 'memory_read')
        if row.get('component') == dma
        and row.get('transaction', {}).get('source_sequence') == 1)

    result = word_projector()(**archive)

    assert expected_snapshot_id in result['details']['partial_effects']['read_snapshot_event_ids']
    assert result['details']['partial_effects']['destination_commit_event_ids']
    if corrupt_snapshot:
        assert result['outcome'] == 'failed'
        assert any('snapshot owner/address/data' in issue['reason']
            for issue in result['details']['issues'])
    else:
        assert result['outcome'] == 'missing'


@pytest.mark.parametrize('transaction_shape', ['missing', 'malformed'])
def test_case_scoped_effect_id_survives_unjoinable_transaction(
        word_transfer_archive, transaction_shape):
    archive = _write_error_archive(word_transfer_archive)
    dma = archive['contract']['dma']['instance_id']
    error_ref = archive['attempt']['write_responses'][1]
    error_observer = archive['local_by_id'].pop((dma, error_ref))
    error_runner_id = error_observer['runner_event_id']
    archive['events'] = [row for row in archive['events']
        if row['event_id'] != error_runner_id]
    archive['attempt']['write_responses'][1] = None
    snapshot = next(row for row in rows(archive, 'memory_read')
        if row.get('component') == dma
        and row.get('transaction', {}).get('source_sequence') == 1)
    if transaction_shape == 'missing':
        snapshot.pop('transaction')
    else:
        snapshot['transaction']['source_sequence'] = 'invalid'
    renumber(archive)
    refresh(archive)
    snapshot_id = next(row['event_id'] for row in rows(archive, 'memory_read')
        if row.get('component') == dma
        and (row.get('transaction') is None
            or row.get('transaction', {}).get('source_sequence') == 'invalid'))

    result = word_projector()(**archive)

    assert snapshot_id in result['details']['partial_effects']['read_snapshot_event_ids']
    assert result['outcome'] == 'failed'
    assert any('transaction' in issue['reason']
        for issue in result['details']['issues'])


@pytest.mark.parametrize('mutation', ['duplicate_effect', 'effect_after_response'])
def test_unaccepted_effect_still_checks_raw_cardinality_and_response_order(
        word_transfer_archive, mutation):
    archive = _write_error_archive(word_transfer_archive)
    attempt = archive['attempt']
    dma = archive['contract']['dma']['instance_id']
    accepted_ref = attempt['reads'][0]
    accepted_observer = archive['local_by_id'].pop((dma, accepted_ref))
    accepted_runner_id = accepted_observer['runner_event_id']
    archive['events'] = [row for row in archive['events']
        if row['event_id'] != accepted_runner_id]
    attempt['reads'][0] = None
    snapshot = next(row for row in rows(archive, 'memory_read')
        if row.get('component') == dma
        and row.get('transaction', {}).get('source_sequence') == 1)
    transaction = snapshot['transaction']
    response = next(row for row in rows(archive, 'dma_edge')
        if type(row.get('response')) is dict
        and row['response'].get('transaction') == transaction)
    if mutation == 'duplicate_effect':
        duplicate = deepcopy(snapshot)
        duplicate['event_id'] = max(row['event_id'] for row in archive['events'])+1
        archive['events'].append(duplicate)
    else:
        archive['events'].remove(snapshot)
        archive['events'].insert(archive['events'].index(response)+1, snapshot)
    renumber(archive)

    result = word_projector()(**archive)

    assert snapshot['event_id'] in result['details']['partial_effects']['read_snapshot_event_ids']
    assert result['outcome'] == 'failed'
    expected = ('duplicate raw DMA effect' if mutation == 'duplicate_effect'
        else 'raw DMA effect/response chronology')
    assert any(expected in issue['reason'] for issue in result['details']['issues'])


def test_raw_effect_conflicting_with_no_effect_receipt_is_not_excused(
        word_transfer_archive):
    archive = _write_error_archive(word_transfer_archive)
    attempt = archive['attempt']
    dma = archive['contract']['dma']['instance_id']
    accepted_ref = attempt['reads'][0]
    accepted_observer = archive['local_by_id'][dma, accepted_ref]
    accepted_runner_id = accepted_observer['runner_event_id']
    accepted_row = next(row for row in archive['events']
        if row['event_id'] == accepted_runner_id)
    transaction = deepcopy(accepted_row['accepted']['transaction'])
    receipt = deepcopy(next(row['environment_error_receipt']
        for row in archive['events'] if type(row.get('environment_error_receipt')) is dict))
    receipt.update(source_transaction=transaction,
        address=accepted_row['accepted']['address'],
        write=False, value=0, selector=dict(case_index=attempt['case_index'],
            operation='read', word_index=0))
    accepted_row['environment_error_receipt'] = receipt

    response_ref = attempt['read_responses'][0]
    response_observer = archive['local_by_id'].pop((dma, response_ref))
    response_runner_id = response_observer['runner_event_id']
    archive['events'] = [row for row in archive['events']
        if row['event_id'] != response_runner_id]
    attempt['read_responses'][0] = None
    renumber(archive)
    refresh(archive)

    result = word_projector()(**archive)

    reasons = [issue['reason'] for issue in result['details']['issues']]
    assert result['outcome'] == 'failed'
    assert any('no-effect receipt' in reason for reason in reasons)
    assert any('no matching response' in reason for reason in reasons)
    assert result['details']['partial_effects']['read_snapshot_event_ids']


def test_success_duplicate_raw_response_retains_partial_effect_inventory(
        word_transfer_archive):
    archive = word_transfer_archive
    response = next(row for row in rows(archive, 'dma_edge')
        if type(row.get('response')) is dict
        and row['response']['transaction']['source_sequence'] == 1)
    duplicate = deepcopy(response)
    duplicate['event_id'] = max(row['event_id'] for row in archive['events'])+1
    archive['events'].append(duplicate)

    result = word_projector()(**archive)

    assert result['outcome'] == 'failed'
    assert result['details']['partial_effects']['read_snapshot_event_ids']
    assert result['details']['partial_effects']['destination_commit_event_ids']
    assert any('duplicate DMA read response transaction' in issue['reason']
        for issue in result['details']['issues'])


def test_surviving_source_commit_fallback_is_kept_in_partial_inventory(
        word_transfer_archive):
    archive = word_transfer_archive
    attempt = archive['attempt']
    source_address = archive['contract']['program_contract']['source_address']
    attempt['sources'][0] = None
    source_rows = [row for row in archive['events']
        if row.get('component') == 'processor_alpha'
        and row.get('kind') == 'memory_write' and row.get('address') == source_address]
    assert len(source_rows) == 1
    source_runner_id = source_rows[0]['event_id']
    archive['events'] = [row for row in archive['events']
        if row['event_id'] != source_runner_id]
    archive['local_by_id'] = {key: row for key, row in archive['local_by_id'].items()
        if row.get('runner_event_id') != source_runner_id}
    renumber(archive)
    refresh(archive)
    commit = next(row for row in archive['events']
        if row.get('component') == 'processor_alpha'
        and row.get('kind') == 'memory_write_commit'
        and row['commit_document']['byte_offset'] == source_address
            - archive['contract']['memory']['resource']['base'])

    result = word_projector()(**archive)

    assert result['outcome'] == 'missing'
    assert commit['event_id'] in result['details']['partial_effects']['source_commit_event_ids']


def irq_projector():
    return importlib.import_module(
        'myfuzz.integration.compiled_f6_saved_semantics').project_saved_irq_isr


def _irq_archive(archive, *, error=False, control_offset=0):
    from hashlib import sha256
    from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract
    from myfuzz.scenario.ledger import TransactionKey

    archive = _write_error_archive(archive) if error else archive
    c, a, b = archive['contract'], archive['attempt'], archive['binding']
    if control_offset:
        offsets=c['dma']['csr']['offsets']
        offsets['control'],offsets['length']=control_offset,offsets['control']
    cpu, dma, p = c['cpu']['instance_id'], c['dma']['instance_id'], c['program_contract']
    provider = ibex_irq_receipt_contract()
    c['cpu']['native_irq_provider'] = provider
    c['irq'] = dict(delivery_id='irq.route', producer_instance=dma,
        producer_endpoint_id='dma.irq',
        producer_port='o_interrupt', consumer_instance=cpu,
        consumer_endpoint_id='processor.interrupts',
        consumer_port=provider['input_port'], delivery_policy='IrqPulseDelivery',
        target_local_ticks=16, clear_policy='fixed_expiry',
        native_take_provider=provider, isr_return_schema='native_f6_isr_return.v1')
    b.pop('binding_sha256')
    b['binding_sha256'] = sha256(json.dumps(b, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()
    for row in archive['events']:
        if 'environment_error_receipt' in row:
            row['environment_error_receipt']['execution_binding_sha256'] = b['binding_sha256']
    scope = dict(case_id=a['case_id'], case_index=a['case_index'])
    fw = build_f6_firmware(c)
    if control_offset:
        a['prefix_hex']=fw.prefix(candidate(),case_index=a['case_index']).hex()
    native_execution = 'a'*32
    dispatch=fw.document().get('irq_dispatch')
    dispatch_path=(dispatch['stages']['dma_dispatch_path']+[dispatch['stages']['dma']['address']]
        if dispatch is not None else [p['isr_address']])
    dispatch_ticks={202+i:pc for i,pc in enumerate(dispatch_path)}

    def add(owner, kind=None, **fields):
        row = dict(component=owner, event_id=max(r['event_id'] for r in archive['events'])+1,
            provenance=dict(observed_case=deepcopy(scope)), **fields)
        if kind is not None:
            row['kind'] = kind
        archive['events'].append(row)
        ref = max(r['event_id'] for r in archive['local_by_id'].values())+1
        archive['local_by_id'][owner, ref] = dict(deepcopy(row), event_id=ref,
            runner_event_id=row['event_id'])
        return ref, row

    _, edge = add(dma, 'dma_edge', tick=150, reset_epoch=0,
        payload=dict(observations=dict(physical=dict(o_interrupt=1))))
    edge_ref = next(key[1] for key, row in archive['local_by_id'].items()
        if row['runner_event_id'] == edge['event_id'])
    source_key = [dma, 0, 'o_interrupt', 150]
    a['irq_output'], _ = add(dma, 'source_start', source_output_key=source_key,
        producer_event_id=edge_ref, source_event_id=edge_ref)
    a['irq_delivery'], _ = add(cpu, 'binding_delivery', source_event_id=a['irq_output'],
        source_output_key=source_key, delivery_id=c['irq']['delivery_id'],
        target_component=cpu, target_epoch=0, start_local_tick=200, end_local_tick=216)
    group=None
    if dispatch is not None:
        from dataclasses import asdict
        from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup,IrqDeliveryMember
        declaration=p['gpio_irq'];gpio=declaration['component']
        group=IrqDeliveryGroup(declaration['group_id'],cpu,provider['input_port'],(
            IrqDeliveryMember(dma,'irq',pulse_width_ticks=16),IrqDeliveryMember(gpio,'interrupt',pulse_width_ticks=4)))
        topology=dict(components=[cpu,dma,gpio],bindings=[asdict(row) for row in group.member_bindings()],
            ownership_inputs=[dict(component=cpu,port=provider['input_port'],owners=[dict(component_id=cpu,
                port=provider['input_port'],bit_offset=0,width=1,kind='bound',producer_ref=group.owner_ref)])],
            irq_delivery_groups=[group.document()],routers=[],resources=[])
        b['runtime_topology']=topology
        b['topology_binding']=dict(b.get('topology_binding',{}),topology_sha256=sha256(json.dumps(topology,
            sort_keys=True,separators=(',',':')).encode()).hexdigest())
        b.pop('binding_sha256');b['binding_sha256']=sha256(json.dumps(b,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        _,dma_sample=add(dma,'local_tick_sample',local_tick=150,reset_epoch=0,phase='post',
            outputs=dict(irq=1,physical=dict(o_interrupt=1)))
        _,gpio_sample=add(gpio,'local_tick_sample',local_tick=1,reset_epoch=0,phase='post',
            outputs=dict(interrupt=0,physical=dict(gpio_irq_wire=0)))
        add(dma,'pulse_start',source=[dma,'irq'],target=[cpu,provider['input_port']],
            start_cpu_tick=200,end_cpu_tick_exclusive=216,source_event_id=1)
    samples = {}
    for tick in range(200, 251):
        rid = dict(execution=native_execution, sequence=tick)
        command_scope = dict(component=cpu, reset_epoch=0, command_sequence=tick)
        _, producer = add(cpu, local_tick=tick, inputs=dict(irq=int(tick<216)), outputs={})
        physical = dict(rvfi_valid=0, rvfi_intr=0, rvfi_trap=0, rvfi_mode=3,
            rvfi_ext_debug_mode=0, rvfi_ext_debug_req=0, rvfi_halt=0,
            irq_decision_serial=7 if tick==201 else 0,
            irq_retirement_serial=7 if tick==202 else 0,
            probe_irq_masked_pre=0, probe_irq_taken_pre=int(tick==201),
            irq_external_i=int(tick<216))
        if tick in dispatch_ticks or tick in (240, 242):
            pc = (dispatch_ticks[tick] if tick in dispatch_ticks else
                fw.document()['isr']['mret_addresses'][int(error)] if tick==240
                else p['slot_base']+128)
            data = next(data[pc-base:pc-base+4] for base, data in fw.initial_images.items()
                if base <= pc < base+len(data))
            physical.update(rvfi_valid=1, rvfi_intr=int(tick==202),
                rvfi_order=(tick-201 if tick in dispatch_ticks else len(dispatch_path)+(1 if tick==240 else 2)), rvfi_pc_rdata=pc,
                rvfi_pc_wdata=0xdeadbeec, rvfi_insn=int.from_bytes(data,'little'))
        phases = {}
        for phase in ('pre','post'):
            _, row = add(cpu, 'local_tick_sample', producer_event_id=producer['event_id'],
                local_tick=tick, phase=phase,
                outputs=dict(backend=dict(i_req_valid=0,i_req_ready=1,
                    d_req_valid=0,d_req_ready=1), physical=deepcopy(physical)))
            phases[phase] = row
        samples[tick] = producer, phases
        if tick <=250:
            context = (dict(binding_delivery_event_id=a['irq_delivery'],
                source_output_key=source_key, target_component=cpu, target_epoch=0,
                expected_input=1) if tick<216 else None)
            fields = dict(local_tick=tick, reset_epoch=0, command_scope=command_scope,
                receipt_id=rid,receipt_ticks=dict(tick_before=tick-1,tick_after=tick,
                    new_ticks=1,local_tick_base=0),
                expected_input=int(tick<216), actual_pre_input=int(tick<216),
                actual_post_input=int(tick<216), input_context=context,
                observation_contract=provider)
            if context:
                fields.update(binding_delivery_event_id=a['irq_delivery'], source_output_key=source_key)
            add(cpu, 'cpu_external_irq_sample', **fields)
            if tick==201:
                a['irq'], take = add(cpu, 'cpu_external_irq_taken', **fields,
                    take_key=[cpu,0,1], irq_masked_pre=0, irq_taken_pre=1,
                    irq_serial_observation=dict(decision=dict(status='observed',value=7)))
    sequence = 8

    def response(address, value, tick, *, write=False, instr=False):
        nonlocal sequence
        sequence += 1
        key = dict(execution_id='local-execution', testcase_id='native-testcase',
            source_component=cpu, source_epoch=0, channel_id='instr' if instr else 'data',
            source_sequence=sequence)
        fields = dict(transaction=key, address=address, raw_address=address,
            aligned_address=address, write=int(write), be=15, wdata=value if write else 0,
            acceptance_tick=tick, response_tick=tick+1, error=0, rdata=0 if write else value)
        tag = 'i' if instr else 'd'
        for phase in ('pre','post'):
            samples[tick][1][phase]['outputs']['backend'].update({tag+'_req_valid':1,
                tag+'_req_ready':1,tag+'_req_addr':address,tag+'_req_write':int(write),
                tag+'_req_be':15,tag+'_req_wdata':value if write else 0})
            samples[tick+1][1][phase]['outputs']['backend'].update({tag+'_rsp_valid':1,
                tag+'_rsp_ready':1,tag+'_rsp_rdata':0 if write else value,tag+'_rsp_error':0})
        add(cpu, 'data_accept' if not instr else 'instr_accept',
            producer_event_id=samples[tick][0]['event_id'], **{k:v for k,v in fields.items()
                if k not in ('response_tick','error','rdata')})
        rsp_tag = 'instr' if instr else 'data'
        samples[tick+1][0]['outputs'].update({rsp_tag+'_rsp_consumed':1,
            rsp_tag+'_rsp_source_epoch':0,rsp_tag+'_rsp_source_sequence':sequence,
            rsp_tag+'_rsp_rdata':0 if write else value})
        ref, row = add(cpu, 'instr_response' if instr else 'data_response',
            producer_event_id=samples[tick+1][0]['event_id'], **fields)
        if write:
            doc = _word_commit_doc(key,address=address,value=value,memory_id='shared_ram',
                memory_base=c['memory']['resource']['base'],version=[0,sequence+10])
            add(cpu,'memory_write_commit',transaction=key,commit_id=doc['commit_id'],
                commit_document=doc)
            return add(cpu,'memory_write',transaction=key,address=address,value=value,
                width_bytes=4,byte_enable=15,memory_id='shared_ram',generation=0,
                byte_offset=address-c['memory']['resource']['base'],version=doc['version'])[0]
        return ref

    status = c['dma']['csr']['status_error_mask'] if error else 0
    status_address=c['control']['base']+control_offset
    a['status'] = response(status_address,status,203)
    status_row = archive['local_by_id'][cpu,a['status']]
    _, control_producer = add(dma,local_tick=159,inputs={},outputs={})
    for tick in (160,161,162):
        add(dma,'dma_edge',tick=tick,payload=dict(pre_backend=dict(swb_cyc=int(tick<162),
            swb_stb=int(tick==160),swb_we=0,swb_adr=control_offset//4,swb_dat_w=0,
            swb_ack=int(tick==161),swb_stall=0,swb_dat_r=status if tick==161 else 0)))
    control_context=dict(source_transaction=deepcopy(status_row['transaction']),
        device_id=c['control']['device_id'],window_base=c['control']['base'],window_size=16,
        address=status_address,offset=control_offset,write=False,value=0,be=15)
    control_receipt=dict(source_transaction=deepcopy(status_row['transaction']),
        address=status_address,offset=control_offset,write=False,value=0,byte_enable=15,
        read_value=status,edge_ticks=[160,161,162],delivery_context=control_context)
    add(cpu,'mmio_delivery',source_transaction=status_row['transaction'], address=status_address,
        write=False,read_value=status,device_id=c['control']['device_id'],
        producer_event_id=control_producer['event_id'],dma_control_receipt=control_receipt)
    result_base = p['result_base']+24*a['case_index']
    a['status_store'] = response(result_base,status,205,write=True)
    a['readbacks'], a['results'] = [], []
    if not error:
        for i in range(4):
            ref = response(p['destination_address']+4*i,i+1,207+4*i)
            read = next(r for r in archive['events']
                if r['event_id']==archive['local_by_id'][cpu,ref]['runner_event_id'])
            commit = archive['local_by_id'][dma,a['word_commits'][i]]['commit_document']
            read['snapshot'] = dict(versions=[commit['version']]*4,
                writer_event_ids=[str(TransactionKey(**commit['fullkey']))]*4,
                writer_kinds=['STORE']*4)
            a['readbacks'].append(ref)
            a['results'].append(response(result_base+4+4*i,i+1,209+4*i,write=True))
    a['terminal'] = response(result_base+20,2 if error else 1,237,write=True)
    pc = p['slot_base']+128
    insn = int.from_bytes(fw.initial_images[pc][:4],'little')
    ref = response(pc,insn,240,instr=True)
    response_row = archive['local_by_id'][cpu,ref]
    a['return'], return_row = add(cpu,'native_f6_isr_return.v1',schema_version='native_f6_isr_return.v1',
        execution=native_execution, reset_epoch=0,native_testcase_id='native-testcase',
        case_id=a['case_id'],case_index=a['case_index'],execution_binding_sha256=b['binding_sha256'],
        irq_take_key=take['take_key'],take_receipt_id=take['receipt_id'],
        handler_entry_receipt_id=dict(execution=native_execution,sequence=202),
        handler_entry_rvfi_order=1,handler_entry_pc_rdata=p['isr_address'],
        return_receipt_id=dict(execution=native_execution,sequence=240),local_tick=240,
        rvfi_order=len(dispatch_path)+1,instruction=0x30200073,pc_rdata=fw.document()['isr']['mret_addresses'][int(error)],
        pc_wdata=0xdeadbeec,successor_receipt_id=dict(execution=native_execution,sequence=242),
        successor_rvfi_order=len(dispatch_path)+2,successor_local_tick=242,successor_pc_rdata=pc,
        successor_instruction=insn,successor_instruction_response={k:v for k,v in response_row.items()
            if k not in ('event_id','runner_event_id','provenance','producer_event_id')},
        successor_instruction_response_receipt_id=dict(execution=native_execution,sequence=241),
        return_target=pc)
    if dispatch is not None:
        return_row.update(dispatcher_stage_sha256=dispatch['identity_sha256'],
            dma_stage_address=dispatch['stages']['dma']['address'],
            dispatcher_retirements=[dict(pc=address,
                instruction=int.from_bytes(fw.initial_images[p['isr_address']][address-p['isr_address']:address-p['isr_address']+4],'little'),
                rvfi_order=i+1,receipt_id=dict(execution=native_execution,sequence=202+i))
                for i,address in enumerate(dispatch_path)])
    next_pc = pc if error else p['slot_base']+256
    a['next_fetch'], _ = add(cpu,'native_fetch_boundary',address=next_pc,
        execution=native_execution,reset_epoch=0,native_testcase_id='native-testcase',
        local_tick=245,transaction=dict(execution_id='local-execution',testcase_id='native-testcase',
            source_component=cpu,source_epoch=0,channel_id='instr',source_sequence=sequence+1))
    samples[245][1]['pre']['outputs']['backend'].update(i_req_valid=1,i_req_ready=1,i_req_addr=next_pc,i_req_write=0,i_req_be=15,i_req_wdata=0)
    if group is not None:
        def source_ref(raw,wire):
            return dict(event_id=raw['event_id'],component=raw['component'],reset_epoch=0,
                local_tick=raw['local_tick'],phase='post',runtime_name=wire)
        for tick in range(200,217):
            sample=next(r for r in archive['events'] if r.get('kind')=='cpu_external_irq_sample'
                and r.get('component')==cpu and r.get('local_tick')==tick)
            sample['producer_event_id']=samples[tick][0]['event_id']
            active=tick<216
            fields=dict(group_id=group.group_id,group_sha256=group.identity_sha256,
                target_component=cpu,target_port=group.target_port,target_epoch=0,cpu_tick=tick,value=int(active),
                native_sample_event_id=sample['event_id'],cpu_step_event_id=sample['producer_event_id'],
                receipt_id=sample['receipt_id'],members=[dict(source_id=group.members[0].source_id,mode='pulse',
                    value=int(active),native_source=source_ref(dma_sample,'o_interrupt')),
                    dict(source_id=group.members[1].source_id,mode='pulse',value=0,native_source=source_ref(gpio_sample,'gpio_irq_wire'))],
                active_sources=[group.members[0].source_id] if active else [],
                unique_source=group.members[0].source_id if active else None,
                attribution_status='unique' if active else 'unknown')
            if tick==201:
                take['sample_event_id']=sample['event_id']
                fields.update(native_take_event_id=take['event_id'],take_key=take['take_key'])
            add(cpu,'irq_group_delivery',**fields)
    refresh(archive)
    return archive


@pytest.fixture
def irq_archive(word_transfer_archive):
    return _irq_archive(word_transfer_archive)


def test_saved_irq_success_is_derived_from_runner_chain(irq_archive):
    before = deepcopy(irq_archive)
    result = irq_projector()(**irq_archive)
    assert result['kind'] == 'dma.irq_isr_completion'
    assert result['outcome'] == 'passed', result['details']['issues']
    assert result['details']['return_target'] == irq_archive['contract']['program_contract']['slot_base']+128
    assert irq_archive == before


def test_saved_irq_status_uses_declared_nonzero_control_offset(word_transfer_archive):
    archive=_irq_archive(word_transfer_archive,control_offset=4)
    result=irq_projector()(**archive)
    assert result['outcome']=='passed', result['details']['issues']
    status=next(row for row in archive['events'] if row.get('kind')=='mmio_delivery'
        and row.get('address')==archive['contract']['control']['base']+4 and row.get('write') is False)
    status['dma_control_receipt']['offset']=0
    refresh(archive)
    assert irq_projector()(**archive)['outcome']=='failed'


def _runner_normalized_irq_archive(archive):
    """Model run5's raw scope versus the Runner's normalized receipt IDs.

    The remaining chain is the existing software fixture; no live/native grant
    is made. Raw f6_obi_scope retains wire nonce/sequence/epoch/tick on each
    physical PRE/POST sample, as in the saved real Ibex execution.
    """
    archive = deepcopy(archive)
    cpu = archive['contract']['cpu']['instance_id']
    returned = rows(archive, 'native_f6_isr_return.v1')[0]
    # Serialization detaches these documents in the real saved artifact.
    returned['take_receipt_id'] = deepcopy(returned['take_receipt_id'])
    nonce = returned['execution']
    raw_samples = {}
    for row in archive['events']:
        if row.get('component') != cpu:
            continue
        if row.get('kind') in ('cpu_external_irq_sample', 'cpu_external_irq_taken'):
            row['receipt_id']['execution'] = f'local-driver:{cpu}:1'
        if row.get('kind') == 'local_tick_sample':
            tick = row['local_tick']
            row['f6_obi_scope'] = [nonce, tick, row.get('reset_epoch', 0), tick]
            raw_samples.setdefault(tick, {})[row['phase']] = row
    for tick, phases in raw_samples.items():
        if set(phases) != {'pre', 'post'}:
            continue
        producer = next(row for row in archive['events']
                        if row['event_id'] == phases['pre']['producer_event_id'])
        producer['outputs']['driver_samples'] = [{
            'local_tick': tick, 'pre': deepcopy(phases['pre']['outputs']),
            'post': deepcopy(phases['post']['outputs'])}]
    for row in archive['events']:
        if (row.get('component') == cpu
                and row.get('kind') in ('cpu_external_irq_sample', 'cpu_external_irq_taken')):
            phases = raw_samples[row['local_tick']]
            row['producer_event_id'] = phases['pre']['producer_event_id']
    take = rows(archive, 'cpu_external_irq_taken')[0]
    take['sample_ref'] = {'command_scope': deepcopy(take['command_scope']),
                          'local_tick': take['local_tick']}
    sample = next(row for row in rows(archive, 'cpu_external_irq_sample')
                  if row['local_tick'] == take['local_tick'])
    take['sample_event_id'] = sample['event_id']
    refresh(archive)
    return archive


def test_saved_irq_normalized_receipt_joins_raw_pre_post_scope(irq_archive):
    archive = _runner_normalized_irq_archive(irq_archive)
    result = irq_projector()(**archive)
    assert result['outcome'] == 'passed', result['details']['issues']


@pytest.mark.parametrize('mutation', ['none', 'wrong_transaction', 'duplicate_transaction'])
def test_saved_irq_successor_response_uses_full_transaction(irq_archive, mutation):
    archive = _observer_only_irq_rows(_runner_normalized_irq_archive(irq_archive))
    a = archive['attempt']; cpu = archive['contract']['cpu']['instance_id']
    returned = archive['local_by_id'][cpu, a['return']]
    target = returned['successor_instruction_response']
    original = next(row for row in archive['events'] if row.get('kind') == 'instr_response'
        and row.get('transaction') == target['transaction'])
    earlier = deepcopy(original); earlier['event_id'] = max(r['event_id'] for r in archive['events'])+1
    earlier['transaction']['source_sequence'] += 1000
    earlier['response_tick'] -= 1
    archive['events'].append(earlier)
    if mutation == 'wrong_transaction': target['transaction']['source_sequence'] += 2000
    elif mutation == 'duplicate_transaction': earlier['transaction'] = deepcopy(original['transaction'])
    result = irq_projector()(**archive)
    expected = {'none': 'passed', 'wrong_transaction': 'missing',
                'duplicate_transaction': 'failed'}[mutation]
    assert result['outcome'] == expected, result['details']['issues']


@pytest.mark.parametrize('mutation', ['none', 'missing_samples', 'pre_ack',
                                      'pre_irq', 'post_irq', 'wrong_tick'])
def test_saved_irq_final_response_can_share_proven_native_edge(irq_archive, mutation):
    archive = deepcopy(irq_archive); a = archive['attempt']; dma = archive['contract']['dma']['instance_id']
    final_ref = a['write_responses'][-1]
    final = archive['local_by_id'][dma, final_ref]
    edge = next(row for row in archive['events'] if row['event_id'] == final['runner_event_id'])
    tick = edge['tick']; old_key = [dma, 0, 'o_interrupt', 150]
    new_key = [dma, 0, 'o_interrupt', tick]
    def replace_key(value):
        if type(value) is dict:
            for key, item in value.items():
                if item == old_key: value[key] = deepcopy(new_key)
                else: replace_key(item)
        elif type(value) is list:
            for item in value: replace_key(item)
    for section in ('attempt', 'events', 'local_by_id'): replace_key(archive[section])
    output = archive['local_by_id'][dma, a['irq_output']]
    source = next(row for row in archive['events'] if row['event_id'] == output['runner_event_id'])
    source.update(source_output_key=new_key, producer_event_id=final_ref, source_event_id=final_ref)
    pre = {'backend': deepcopy(edge['payload']['pre_backend']), 'physical': {'o_interrupt': 0}}
    post = {'backend': {}, 'physical': {'o_interrupt': 1}}
    edge.update(reset_epoch=0, native_local_tick=tick)
    edge['payload'].update(observations=deepcopy(post),
        samples=[{'local_tick': tick, 'pre': pre, 'post': post}])
    if mutation == 'missing_samples': edge['payload'].pop('samples')
    elif mutation == 'pre_ack': pre['backend']['mwb_ack'] = 0
    elif mutation == 'pre_irq': pre['physical']['o_interrupt'] = 1
    elif mutation == 'post_irq': post['physical']['o_interrupt'] = 0
    elif mutation == 'wrong_tick': edge['payload']['samples'][0]['local_tick'] += 1
    refresh(archive)
    result = irq_projector()(**archive)
    assert result['outcome'] == ('passed' if mutation == 'none' else 'failed'), result['details']['issues']


@pytest.mark.parametrize('mutation', ['missing_pre_scope', 'wrong_owner',
                                       'wrong_nonce', 'wrong_sequence', 'wrong_tick',
                                       'wrong_alias', 'wrong_producer', 'wrong_sample',
                                       'boolean_epoch'])
def test_saved_irq_scope_cannot_map_missing_or_foreign_raw_evidence(irq_archive, mutation):
    archive = _runner_normalized_irq_archive(irq_archive)
    cpu = archive['contract']['cpu']['instance_id']
    tick = rows(archive, 'cpu_external_irq_taken')[0]['local_tick']
    raw = next(row for row in rows(archive, 'local_tick_sample')
               if row['component'] == cpu and row['local_tick'] == tick
               and row['phase'] == 'pre')
    if mutation == 'missing_pre_scope':
        del raw['f6_obi_scope']
    elif mutation == 'wrong_owner':
        raw['component'] = 'foreign-cpu'
    elif mutation == 'wrong_nonce':
        raw['f6_obi_scope'][0] = 'f' * 32
    elif mutation == 'wrong_sequence':
        raw['f6_obi_scope'][1] += 1
    elif mutation == 'wrong_tick':
        raw['f6_obi_scope'][3] += 1
    elif mutation == 'wrong_alias':
        rows(archive, 'cpu_external_irq_taken')[0]['receipt_id']['execution'] = 'local-driver:foreign:1'
    elif mutation == 'wrong_producer':
        rows(archive, 'cpu_external_irq_taken')[0]['producer_event_id'] += 1
    elif mutation == 'wrong_sample':
        rows(archive, 'cpu_external_irq_taken')[0]['sample_event_id'] += 1
    else:
        raw['f6_obi_scope'][2] = False
    # Update the Observer copy so this tests the raw join, not copy mismatch.
    refresh(archive)
    result = irq_projector()(**archive)
    assert result['outcome'] == ('missing' if mutation in ('missing_pre_scope', 'wrong_owner') else 'failed')


def test_saved_irq_expected_error_rebuilds_error_branch(word_transfer_archive):
    archive = _irq_archive(word_transfer_archive,error=True)
    archive['attempt']['expected_error'] = False
    archive['attempt']['status_kind'] = 'passed'
    result = irq_projector()(**archive)
    assert result['outcome'] == 'failed'
    assert result['details'].get('error_completion',{}).get('terminal_marker') == 2, result['details']['issues']
    assert result['details']['partial_effects']['destination_commit_event_ids']


@pytest.mark.parametrize('kind,field,value', [
    ('binding_delivery','end_local_tick',215),
    ('cpu_external_irq_taken','irq_taken_pre',0),
    ('cpu_external_irq_taken','source_output_key',['other',0,'irq',150]),
    ('native_f6_isr_return.v1','successor_rvfi_order',4),
    ('native_f6_isr_return.v1','pc_rdata',0),
    ('native_fetch_boundary','address',0),
])
def test_saved_irq_rejects_contradictory_chain(irq_archive,kind,field,value):
    rows(irq_archive,kind)[0][field] = value
    refresh(irq_archive)
    assert irq_projector()(**irq_archive)['outcome'] == 'failed'


@pytest.mark.parametrize('mutation', ['missing_expiry','duplicate_expiry','wrong_expiry',
    'foreign_take','missing_take_provenance','duplicate_return','bad_status',
    'wrong_readback','wrong_result','bad_snapshot','tampered_transaction',
    'wrong_entry_serial','intervening_trap','successor_response_error','wrong_first_successor',
    'missing_status_selector','missing_return','observer_forgery'])
def test_saved_irq_fault_regressions(irq_archive,mutation):
    archive = irq_archive
    sample = next(r for r in rows(archive,'cpu_external_irq_sample') if r['local_tick']==216)
    expected = 'failed'
    if mutation=='missing_expiry':
        archive['events'].remove(sample)
        expected='missing'
    elif mutation=='duplicate_expiry':
        duplicate=deepcopy(sample);duplicate['event_id']=max(r['event_id'] for r in archive['events'])+1
        archive['events'].append(duplicate)
    elif mutation=='wrong_expiry': sample['actual_post_input']=1
    elif mutation=='foreign_take': rows(archive,'cpu_external_irq_taken')[0]['provenance']['observed_case']['case_id']='foreign'
    elif mutation=='missing_take_provenance': rows(archive,'cpu_external_irq_taken')[0].pop('provenance');expected='missing'
    elif mutation=='duplicate_return':
        duplicate=deepcopy(rows(archive,'native_f6_isr_return.v1')[0]);duplicate['event_id']=max(r['event_id'] for r in archive['events'])+1
        archive['events'].append(duplicate)
    elif mutation=='bad_status':
        ref=archive['attempt']['status'];rid=archive['local_by_id']['processor_alpha',ref]['runner_event_id']
        next(r for r in archive['events'] if r['event_id']==rid)['rdata']=0x40000000
    elif mutation in ('wrong_readback','bad_snapshot'):
        ref=archive['attempt']['readbacks'][0];rid=archive['local_by_id']['processor_alpha',ref]['runner_event_id']
        row=next(r for r in archive['events'] if r['event_id']==rid)
        if mutation=='wrong_readback':row['rdata']=99
        else:row['snapshot']['versions']=[[0,999]]*4
    elif mutation=='wrong_result':
        ref=archive['attempt']['results'][0];rid=archive['local_by_id']['processor_alpha',ref]['runner_event_id']
        next(r for r in archive['events'] if r['event_id']==rid)['value']=99
    elif mutation=='tampered_transaction': rows(archive,'native_fetch_boundary')[0]['transaction']['source_epoch']=1
    elif mutation in ('wrong_entry_serial','intervening_trap','wrong_first_successor'):
        tick=202 if mutation=='wrong_entry_serial' else 230 if mutation=='intervening_trap' else 241
        row=next(r for r in rows(archive,'local_tick_sample') if r['local_tick']==tick and r['phase']=='post')
        physical=row['outputs']['physical']
        if mutation=='wrong_entry_serial':physical['irq_retirement_serial']=8
        else:physical.update(rvfi_valid=1,rvfi_trap=int(mutation=='intervening_trap'),rvfi_order=3,rvfi_pc_rdata=0,rvfi_insn=0)
    elif mutation=='successor_response_error':
        row=next(r for r in rows(archive,'instr_response') if r['address']==archive['contract']['program_contract']['slot_base']+128)
        row['error']=1
    elif mutation=='missing_status_selector':archive['attempt']['status']=None;expected='missing'
    elif mutation=='missing_return':archive['events'].remove(rows(archive,'native_f6_isr_return.v1')[0]);expected='missing'
    elif mutation=='observer_forgery':
        archive['local_by_id']['processor_alpha',archive['attempt']['return']]['pc_rdata']=0
    if mutation!='observer_forgery':refresh(archive)
    result=irq_projector()(**archive)
    assert result['outcome']==expected, result['details']['issues']
    foreign_ids={r['event_id'] for r in archive['events'] if r.get('provenance',{}).get('observed_case',{}).get('case_id')=='foreign'}
    assert not foreign_ids.intersection(r['runner_event_id'] for r in result['details']['raw_references'])


@pytest.mark.parametrize('mutation', ['missing_selector_bad_status','missing_selector_bad_result',
    'missing_native_acceptance','duplicate_status_response','duplicate_result_effect',
    'status_native_mismatch','status_wrong_transaction','result_response_wrong_identity',
    'wrong_response_producer','wrong_command_receipt','missing_continuity_receipt',
    'foreign_continuity_receipt','wrong_take_serial','missing_native_post','bad_expiry_context',
    'wrong_status_control_ack','missing_status_control_ack','wrong_status_control_receipt',
    'wrong_mret_pc_wdata_claim','bad_boundary_be','duplicate_boundary_key'])
def test_saved_irq_additional_independent_raw_regressions(irq_archive,mutation):
    archive=irq_archive
    a=archive['attempt'];cpu=archive['contract']['cpu']['instance_id']
    def selected(section,index=None):
        ref=a[section] if index is None else a[section][index]
        return next(r for r in archive['events']
            if r['event_id']==archive['local_by_id'][cpu,ref]['runner_event_id'])
    expected='failed'
    if mutation=='missing_selector_bad_status':
        selected('status')['rdata']=99;a['status']=None
    elif mutation=='missing_selector_bad_result':
        selected('results',0)['value']=99;a['results'][0]=None
    elif mutation=='missing_native_acceptance':
        status=selected('status')
        archive['events']=[r for r in archive['events'] if not
            (r.get('kind')=='data_accept' and r.get('transaction')==status['transaction'])]
        expected='missing'
    elif mutation in ('duplicate_status_response','duplicate_result_effect','duplicate_boundary_key'):
        row=selected('status' if mutation=='duplicate_status_response' else 'results' if mutation=='duplicate_result_effect' else 'next_fetch',
            0 if mutation=='duplicate_result_effect' else None)
        duplicate=deepcopy(row);duplicate['event_id']=max(r['event_id'] for r in archive['events'])+1
        archive['events'].append(duplicate)
    elif mutation=='status_native_mismatch':
        next(r for r in rows(archive,'local_tick_sample') if r['local_tick']==204 and r['phase']=='pre')['outputs']['backend']['d_rsp_rdata']=99
    elif mutation=='status_wrong_transaction':selected('status')['transaction']['source_sequence']=999
    elif mutation=='result_response_wrong_identity':
        key=selected('results',0)['transaction']
        row=next(r for r in rows(archive,'data_response') if r.get('transaction')==key)
        producer=next(r for r in archive['events'] if r['event_id']==row['producer_event_id'])
        producer['outputs']['data_rsp_source_sequence']=999
    elif mutation=='wrong_response_producer':selected('status')['producer_event_id']=2
    elif mutation=='wrong_command_receipt':
        next(r for r in rows(archive,'cpu_external_irq_sample') if r['local_tick']==230)['receipt_id']['sequence']=999
    elif mutation in ('missing_continuity_receipt','foreign_continuity_receipt'):
        row=next(r for r in rows(archive,'cpu_external_irq_sample') if r['local_tick']==230)
        if mutation=='missing_continuity_receipt':archive['events'].remove(row);expected='missing'
        else:row['receipt_id']['execution']='b'*32
    elif mutation=='wrong_take_serial':rows(archive,'cpu_external_irq_taken')[0]['irq_serial_observation']['decision']['value']=9
    elif mutation=='missing_native_post':
        archive['events'].remove(next(r for r in rows(archive,'local_tick_sample') if r['local_tick']==230 and r['phase']=='post'));expected='missing'
    elif mutation=='bad_expiry_context':
        next(r for r in rows(archive,'cpu_external_irq_sample') if r['local_tick']==216)['input_context']={'expected_input':1}
    elif mutation in ('wrong_status_control_ack','missing_status_control_ack'):
        row=next(r for r in rows(archive,'dma_edge') if r.get('tick')==161)
        if mutation=='wrong_status_control_ack':row['payload']['pre_backend']['swb_dat_r']=99
        else:archive['events'].remove(row);expected='missing'
    elif mutation=='wrong_status_control_receipt':
        row=next(r for r in rows(archive,'mmio_delivery') if r.get('write') is False)
        row['dma_control_receipt']['source_transaction']['source_sequence']=999
    elif mutation=='wrong_mret_pc_wdata_claim':
        selected('return')['pc_wdata']=123
    elif mutation=='bad_boundary_be':
        next(r for r in rows(archive,'local_tick_sample') if r['local_tick']==245 and r['phase']=='pre')['outputs']['backend']['i_req_be']=0
    refresh(archive)
    result=irq_projector()(**archive)
    assert result['outcome']==expected,result['details']['issues']


def test_saved_irq_pc_wdata_is_only_an_observation(irq_archive):
    archive=irq_archive
    row=rows(archive,'native_f6_isr_return.v1')[0]
    row['pc_wdata']=0
    for sample in rows(archive,'local_tick_sample'):
        if sample['local_tick']==240:sample['outputs']['physical']['rvfi_pc_wdata']=0
    refresh(archive)
    result=irq_projector()(**archive)
    assert result['outcome']=='passed',result['details']['issues']
    assert result['details']['return_target']!=0
    assert result['details']['pc_wdata']==0


@pytest.mark.parametrize('mutation',['missing_boundary','bad_error_terminal','raw_success_readback'])
def test_saved_error_completion_requires_closed_error_chain(word_transfer_archive,mutation):
    archive=_irq_archive(word_transfer_archive,error=True)
    if mutation=='missing_boundary':
        archive['events'].remove(rows(archive,'native_fetch_boundary')[0])
    elif mutation=='bad_error_terminal':
        ref=archive['attempt']['terminal'];rid=archive['local_by_id']['processor_alpha',ref]['runner_event_id']
        next(r for r in archive['events'] if r['event_id']==rid)['value']=1
    else:
        duplicate=deepcopy(next(r for r in rows(archive,'data_response') if r.get('write')==0))
        duplicate.update(event_id=max(r['event_id'] for r in archive['events'])+1,
            address=archive['contract']['program_contract']['destination_address'])
        archive['events'].append(duplicate)
    refresh(archive)
    result=irq_projector()(**archive)
    assert result['outcome'] in ('failed','missing')
    assert 'error_completion' not in result['details']


@pytest.mark.parametrize('mutation',['duplicate_observer_link','missing_selector_bad_boundary',
    'missing_accept_bad_commit','missing_receipt_later_trap','missing_input_later_wrong_input'])
def test_saved_irq_missing_evidence_cannot_hide_independent_contradiction(irq_archive,mutation):
    archive=irq_archive;a=archive['attempt'];cpu='processor_alpha'
    if mutation=='duplicate_observer_link':
        original=archive['local_by_id'][cpu,a['return']]
        archive['local_by_id'][cpu,99999]=dict(deepcopy(original),event_id=99999)
    elif mutation=='missing_selector_bad_boundary':
        rows(archive,'native_fetch_boundary')[0]['address']=0;a['next_fetch']=None
    elif mutation=='missing_accept_bad_commit':
        key=archive['local_by_id'][cpu,a['results'][0]]['transaction']
        archive['events']=[r for r in archive['events'] if not
            (r.get('kind')=='data_accept' and r.get('transaction')==key)]
        next(r for r in rows(archive,'memory_write_commit') if r.get('transaction')==key)['commit_document']['enabled_byte_cells'][0]['value']^=1
    elif mutation=='missing_receipt_later_trap':
        archive['events'].remove(next(r for r in rows(archive,'cpu_external_irq_sample') if r['local_tick']==220))
        row=next(r for r in rows(archive,'local_tick_sample') if r['local_tick']==230 and r['phase']=='post')
        row['outputs']['physical'].update(rvfi_valid=1,rvfi_trap=1,rvfi_order=2)
    else:
        archive['events'].remove(next(r for r in rows(archive,'cpu_external_irq_sample') if r['local_tick']==205))
        next(r for r in rows(archive,'cpu_external_irq_sample') if r['local_tick']==210)['actual_post_input']=0
    refresh(archive)
    result=irq_projector()(**archive)
    assert result['outcome']=='failed',result['details']['issues']


def _observer_only_irq_rows(archive):
    """Match production: these four summaries never enter the Runner journal."""
    a=archive['attempt'];c=archive['contract'];cpu=c['cpu']['instance_id'];dma=c['dma']['instance_id']
    archive['dma_irq_runtime_name']=c['irq']['producer_port']
    for section,owner in (('irq_output',dma),('irq_delivery',cpu),('return',cpu),('next_fetch',cpu)):
        row=archive['local_by_id'][owner,a[section]]
        rid=row.pop('runner_event_id')
        archive['events']=[event for event in archive['events'] if event['event_id']!=rid]
        row.pop('provenance',None)
        if section=='irq_output':row.update(source=[dma,'irq'],target=[cpu,'irq'])
        if section=='return':
            from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_serial_observation
            row.pop('kind',None)
            def serial(tick,sampling):
                physical=next(event['outputs']['physical'] for event in rows(archive,'local_tick_sample')
                    if event['local_tick']==tick and event['phase']=='post')
                return ibex_irq_serial_observation(sampling=sampling,
                    decision_phase='pre' if sampling=='pre_post_rising' else 'post',retirement_phase='post',
                    decision_value=physical['irq_decision_serial'],
                    retirement_value=physical['irq_retirement_serial'])
            row.update(take_irq_serial_observation=deepcopy(
                archive['local_by_id'][cpu,a['irq']]['irq_serial_observation']),
                handler_entry_irq_serial_observation=serial(202,'post_rising'),
                irq_serial_observation=serial(240,'post_rising'),
                successor_irq_serial_observation=serial(242,'post_rising'),
                return_receipt_ticks=dict(tick_before=239,tick_after=240,new_ticks=1,local_tick_base=0),
                phase='post',isr_sha256=build_f6_firmware(c).document()['isr']['sha256'],
                return_target_source='first_subsequent_valid_RVFI_pc_rdata_with_instruction_response',
                return_target_authority='inferred_architectural_successor_after_MRET')
        if section=='next_fetch':
            row['boundary']='error_current_island' if a.get('expected_error') else 'next_prefix_or_park'
            row['transaction']['source_sequence']=sum(1 for event in rows(archive,'local_tick_sample')
                if event.get('phase')=='pre' and event.get('component')==cpu
                and event.get('local_tick',0)<=row['local_tick']
                and event.get('outputs',{}).get('backend',{}).get('i_req_valid')==1
                and event.get('outputs',{}).get('backend',{}).get('i_req_ready')==1)
    return archive


@pytest.mark.parametrize('error',[False,True])
def test_saved_irq_projects_production_observer_only_summaries(word_transfer_archive,error):
    archive=_observer_only_irq_rows(_irq_archive(word_transfer_archive,error=error))
    result=irq_projector()(**archive)
    assert result['outcome']==('failed' if error else 'passed'),result['details']['issues']
    if error:assert result['details'].get('error_completion'),result['details']['issues']
    assert result['details']['return_target']==archive['contract']['program_contract']['slot_base']+128
    assert not {'source_start','binding_delivery','native_f6_isr_return.v1','native_fetch_boundary'}.intersection(
        row.get('kind') for row in archive['events'])


@pytest.mark.parametrize('mutation',['source_key','source_owner','source_producer','delivery_window',
    'delivery_key','return_target','return_scope','return_order','boundary_key','boundary_tick',
    'duplicate_source','duplicate_return','missing_retirement_sample','foreign_source'])
def test_saved_irq_observer_only_summaries_have_no_semantic_authority(irq_archive,mutation):
    archive=_observer_only_irq_rows(irq_archive);a=archive['attempt'];cpu='processor_alpha';dma='mover_beta'
    source=archive['local_by_id'][dma,a['irq_output']]
    delivery=archive['local_by_id'][cpu,a['irq_delivery']]
    returned=archive['local_by_id'][cpu,a['return']]
    boundary=archive['local_by_id'][cpu,a['next_fetch']]
    expected='failed'
    if mutation=='source_key':source['source_output_key'][3]=999
    elif mutation=='source_owner':source['source']=['foreign','irq']
    elif mutation=='source_producer':source['producer_event_id']=None
    elif mutation=='delivery_window':delivery['start_local_tick']+=1;delivery['end_local_tick']+=1
    elif mutation=='delivery_key':delivery['source_output_key']=['foreign',0,'o_interrupt',150]
    elif mutation=='return_target':returned['return_target']=0
    elif mutation=='return_scope':returned['execution']='b'*32
    elif mutation=='return_order':returned['successor_rvfi_order']+=1
    elif mutation=='boundary_key':boundary['transaction']['source_sequence']+=1
    elif mutation=='boundary_tick':boundary['local_tick']=246
    elif mutation in ('duplicate_source','duplicate_return'):
        row=source if mutation=='duplicate_source' else returned
        archive['local_by_id'][row['component'],99999]=dict(deepcopy(row),event_id=99999)
    elif mutation=='missing_retirement_sample':
        archive['events'].remove(next(r for r in rows(archive,'local_tick_sample') if r['local_tick']==240 and r['phase']=='post'))
        expected='missing'
    elif mutation=='foreign_source':
        raw_ref=source['producer_event_id'];rid=archive['local_by_id'][dma,raw_ref]['runner_event_id']
        raw=next(r for r in archive['events'] if r['event_id']==rid)
        raw['provenance']['observed_case']['case_id']='foreign'
        archive['local_by_id'][dma,raw_ref]=dict(deepcopy(raw),event_id=raw_ref,runner_event_id=rid)
    result=irq_projector()(**archive)
    assert result['outcome']==expected,result['details']['issues']


@pytest.mark.parametrize('field,value',[
    ('isr_sha256','0'*64),('phase','pre'),
    ('return_target_source','pc_wdata'),('return_target_authority','direct_mepc'),
    ('return_receipt_ticks',dict(tick_before=239,tick_after=241,new_ticks=2,local_tick_base=0)),
    ('handler_entry_irq_serial_observation',{}),('irq_serial_observation',{}),
    ('successor_irq_serial_observation',{}),('take_irq_serial_observation',{})])
def test_saved_irq_derived_return_fields_are_rebuilt(irq_archive,field,value):
    archive=_observer_only_irq_rows(irq_archive)
    archive['local_by_id']['processor_alpha',archive['attempt']['return']][field]=value
    result=irq_projector()(**archive)
    assert result['outcome']=='failed',result['details']['issues']


def test_saved_irq_uses_source_admitted_wrapper_runtime_alias(irq_archive):
    archive=_observer_only_irq_rows(irq_archive)
    archive['dma_irq_runtime_name']='wrapper_dma_irq'
    source=archive['local_by_id']['mover_beta',archive['attempt']['irq_output']]
    ref=source['producer_event_id']
    observer=archive['local_by_id']['mover_beta',ref]
    raw=next(r for r in archive['events'] if r['event_id']==observer['runner_event_id'])
    physical=raw['payload']['observations']['physical']
    physical['wrapper_dma_irq']=physical.pop('o_interrupt')
    archive['local_by_id']['mover_beta',ref]=dict(deepcopy(raw),
        event_id=ref,runner_event_id=raw['event_id'])
    result=irq_projector()(**archive)
    assert result['outcome']=='passed',result['details']['issues']
    assert source['source_output_key'][2]=='o_interrupt'


def test_saved_irq_production_requires_admitted_runtime_name(irq_archive):
    archive=_observer_only_irq_rows(irq_archive)
    archive.pop('dma_irq_runtime_name',None)
    result=irq_projector()(**archive)
    assert result['outcome']=='missing',result['details']['issues']


@pytest.fixture(scope='module')
def irq_cpu_artifact():
    """Render the real Ibex RVFI profile without compiling or running RTL."""
    from pathlib import Path
    from myfuzz.local_harness import (load_local_harness_request,
        plan_local_harness, render_local_driver, render_local_harness,
        render_local_runtime, verify_local_source_lock)
    root = Path(__file__).resolve().parents[2]
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path='configs/cpus/ibex_rvfi_local/component_profile.json',
        instance_id='processor_alpha', reset_assert_ticks=12,
        reset_release_ticks=8, max_wait_cycles=32))
    plan = plan_local_harness(request, base_dir=root)
    return render_local_driver(render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=root), base_dir=root), base_dir=root)


def _physical_alias_irq_archive(archive, artifact):
    from myfuzz.integration.compiled_f4 import _artifact_execution_identity
    archive = _runner_normalized_irq_archive(archive)
    exports = artifact.runtime_document['physical_exports']
    aliases = {row['physical_port']: row['runtime_name'] for row in exports}
    for row in rows(archive, 'local_tick_sample'):
        if row.get('component') != archive['contract']['cpu']['instance_id']:
            continue
        physical = row['outputs'].get('physical', {})
        for logical in list(physical):
            if logical in aliases:
                physical[aliases[logical]] = physical.pop(logical)
    for row in rows(archive, 'local_tick_sample'):
        if row.get('component') != archive['contract']['cpu']['instance_id']:
            continue
        producer = next(event for event in archive['events']
                        if event['event_id'] == row['producer_event_id'])
        for sample in producer['outputs'].get('driver_samples', []):
            if sample['local_tick'] == row['local_tick']:
                sample[row['phase']] = deepcopy(row['outputs'])
    refresh(archive)
    _bind_irq_cpu_artifact(archive, artifact)
    return archive


def _bind_irq_cpu_artifact(archive, artifact):
    from myfuzz.integration.compiled_f4 import _artifact_execution_identity
    cpu = archive['contract']['cpu']['instance_id']
    old = archive['binding']['binding_sha256']
    archive['binding']['artifact_identities'] = {cpu: _artifact_execution_identity(artifact)}
    archive['binding']['cpu'] = dict(instance_id=cpu,
        profile_fingerprint=artifact.plan.profile.profile_fingerprint,
        runtime_artifact_sha256=_edge_digest(artifact.runtime_document))
    archive['binding']['binding_sha256'] = _edge_digest({k: v for k, v in
        archive['binding'].items() if k != 'binding_sha256'})
    new = archive['binding']['binding_sha256']
    def rewrite(value):
        if type(value) is dict:
            for key, item in value.items():
                if item == old:
                    value[key] = new
                else:
                    rewrite(item)
        elif type(value) is list:
            for item in value:
                rewrite(item)
    for key in ('attempt', 'events', 'local_by_id'):
        rewrite(archive[key])


def test_saved_irq_uses_bound_cpu_physical_exports(irq_archive, irq_cpu_artifact):
    archive = _physical_alias_irq_archive(irq_archive, irq_cpu_artifact)
    original = deepcopy(archive['events'])
    result = irq_projector()(**archive, cpu_artifact=irq_cpu_artifact)
    assert result['outcome'] == 'passed', result['details']['issues']
    assert archive['events'] == original


@pytest.mark.parametrize('port,value,tick', [
    ('irq_external_i', True, 200), ('rvfi_valid', True, 202),
    ('irq_decision_serial', 1 << 64, 201), ('rvfi_pc_rdata', -1, 202),
    ('probe_irq_taken_pre', True, 201), ('probe_irq_masked_pre', False, 201)])
def test_saved_irq_rejects_non_integer_or_out_of_width_physical_values(
        irq_archive, irq_cpu_artifact, port, value, tick):
    archive = _physical_alias_irq_archive(irq_archive, irq_cpu_artifact)
    exports = irq_cpu_artifact.runtime_document['physical_exports']
    name = next((row['runtime_name'] for row in exports
                 if row['physical_port'] == port), port)
    cpu = archive['contract']['cpu']['instance_id']
    for row in rows(archive, 'local_tick_sample'):
        if row.get('component') != cpu or row.get('local_tick') != tick:
            continue
        row['outputs']['physical'][name] = value
        producer = next(event for event in archive['events']
                        if event['event_id'] == row['producer_event_id'])
        for sample in producer['outputs']['driver_samples']:
            if sample['local_tick'] == tick:
                sample[row['phase']] = deepcopy(row['outputs'])
    refresh(archive)
    result = irq_projector()(**archive, cpu_artifact=irq_cpu_artifact)
    assert result['outcome'] == 'failed', result['details']['issues']
    assert any('physical value' in issue['reason'] for issue in result['details']['issues'])


def test_saved_irq_aliased_physical_without_artifact_is_missing(irq_archive, irq_cpu_artifact):
    archive = _physical_alias_irq_archive(irq_archive, irq_cpu_artifact)
    result = irq_projector()(**archive)
    assert result['outcome'] == 'missing', result['details']['issues']


@pytest.mark.parametrize('mutation', ['missing', 'duplicate', 'direction', 'width',
                                      'alias_collision', 'irq_endpoint', 'foreign_identity'])
def test_saved_irq_rejects_untrusted_cpu_physical_mapping(irq_archive, irq_cpu_artifact, mutation):
    from dataclasses import replace
    archive = _physical_alias_irq_archive(irq_archive, irq_cpu_artifact)
    runtime = deepcopy(irq_cpu_artifact.runtime_document)
    exports = runtime['physical_exports']
    row = next(row for row in exports if row['physical_port'] == 'rvfi_valid')
    if mutation == 'missing': exports.remove(row)
    elif mutation == 'duplicate': exports.append(deepcopy(row))
    elif mutation == 'direction': row['direction'] = 'input'
    elif mutation == 'width': row['width'] = 2
    elif mutation == 'alias_collision':
        row['runtime_name'] = next(r['runtime_name'] for r in exports
                                   if r['physical_port'] == 'rvfi_intr')
    elif mutation == 'irq_endpoint':
        next(r for r in exports if r['physical_port'] == 'irq_external_i')['endpoint_id'] = 'foreign'
    else:
        archive['binding']['artifact_identities']['processor_alpha']['instance_id'] = 'foreign'
    artifact = replace(irq_cpu_artifact, runtime_document=runtime)
    if mutation != 'foreign_identity': _bind_irq_cpu_artifact(archive, artifact)
    result = irq_projector()(**archive, cpu_artifact=artifact)
    assert result['outcome'] in ('missing', 'failed'), result['details']


@pytest.mark.parametrize('mutation',['wrong_alias','empty_alias','wrong_endpoint','wrong_logical_port'])
def test_saved_irq_runtime_alias_cannot_replace_contract_identity(irq_archive,mutation):
    archive=_observer_only_irq_rows(irq_archive)
    if mutation=='wrong_alias':archive['dma_irq_runtime_name']='absent_wrapper_signal'
    elif mutation=='empty_alias':archive['dma_irq_runtime_name']=''
    elif mutation=='wrong_endpoint':archive['contract']['irq']['producer_endpoint_id']=''
    else:archive['contract']['irq']['producer_port']='another_logical_irq'
    result=irq_projector()(**archive)
    assert result['outcome'] in ('failed','missing'),result['details']['issues']


def _edge_digest(document):
    from hashlib import sha256
    return sha256(json.dumps(document, sort_keys=True,
        separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def _refresh_edge_binding(archive):
    binding = archive['binding']
    path = binding['runtime_path_admission']
    path['admission_sha256'] = _edge_digest({k:v for k,v in path.items()
        if k != 'admission_sha256'})
    binding['binding_sha256'] = _edge_digest({k:v for k,v in binding.items()
        if k != 'binding_sha256'})


def _rebind_edge_cpu_artifact(archive, runtime_document):
    from dataclasses import replace
    from myfuzz.integration.compiled_f4 import _artifact_execution_identity
    from myfuzz.local_harness.renderer import _sha

    artifact = archive['_cpu_artifact']
    runtime_document = deepcopy(runtime_document)
    runtime_document.pop('artifact_digest', None)
    runtime_document['artifact_digest'] = _sha(runtime_document)
    artifact = replace(artifact, runtime_document=runtime_document)
    archive['_cpu_artifact'] = artifact
    cpu = archive['contract']['cpu']['instance_id']
    archive['binding']['artifact_identities'][cpu] = \
        _artifact_execution_identity(artifact)
    archive['binding']['cpu']['runtime_artifact_sha256'] = _edge_digest(
        artifact.runtime_document)
    _refresh_edge_binding(archive)
    return artifact


@pytest.fixture(scope='module')
def cpu_obi_artifact():
    """Render a real pinned OBI artifact without building or running RTL."""
    from pathlib import Path
    from myfuzz.local_harness import (load_local_harness_request,
        plan_local_harness, render_local_driver, render_local_harness,
        render_local_runtime, verify_local_source_lock)

    root = Path(__file__).resolve().parents[2]
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path='configs/cpus/ibex_obi_local/component_profile.json',
        instance_id='processor_alpha', reset_assert_ticks=12,
        reset_release_ticks=8, max_wait_cycles=32))
    plan = plan_local_harness(request, base_dir=root)
    structural = render_local_harness(plan)
    source = verify_local_source_lock(plan.profile, base_dir=root)
    return render_local_driver(render_local_runtime(plan, structural, source,
        base_dir=root), base_dir=root)


@pytest.fixture
def edge_archive(word_transfer_archive, cpu_obi_artifact):
    """Production-shaped declarations and original archived source facts."""
    from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
    from myfuzz.scenario.runtime_path_contract import (DmaMasterRouteContract,
        RuntimeNode, RuntimeEdgeContract, RuntimePathContract, PreparedRuntimePathContract)
    from myfuzz.scenario.source_provenance import SourceAdmission

    archive = deepcopy(word_transfer_archive)
    c, b, a = archive['contract'], archive['binding'], archive['attempt']
    cpu, dma, resource = c['cpu']['instance_id'], c['dma']['instance_id'], c['memory']['resource']
    from myfuzz.integration.compiled_f4 import _artifact_execution_identity
    from hashlib import sha256
    artifact_identity = _artifact_execution_identity(cpu_obi_artifact)
    runtime_digest = sha256(json.dumps(cpu_obi_artifact.runtime_document,
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    traces = cpu_obi_artifact.runtime_document['base_protocol_traces']['traces']
    endpoints = {endpoint.function: endpoint.endpoint_id
        for endpoint in cpu_obi_artifact.plan.binding.endpoints}
    c['cpu'].update(profile_fingerprint=cpu_obi_artifact.plan.profile.profile_fingerprint,
        artifact_kind='obi_cpu',
        instruction_endpoint_id=endpoints['instruction_memory_master'],
        data_endpoint_id=endpoints['data_memory_master'],
        source_verification_sha256=artifact_identity['source_verification_sha256'])
    b['artifact_identities'] = {cpu: artifact_identity}
    b['cpu'] = dict(instance_id=cpu,
        profile_fingerprint=cpu_obi_artifact.plan.profile.profile_fingerprint,
        runtime_artifact_sha256=runtime_digest)
    archive['_cpu_artifact'] = cpu_obi_artifact
    p = c['program_contract']
    c['memory']['source']=dict(base=p['source_address'],size=16)
    source_id = c['instruction_source_id'] = p['instruction_source_id']
    nodes = ['F6.runtime_ram_source_words', 'F6.runtime_dma_read_words',
        'F6.runtime_dma_write_words', 'F6.runtime_ram_destination_words',
        source_id, 'F6.runtime_online_instruction_prefixes']
    graph = DependencyGraph(sources=(
        FuzzableSource(nodes[0], cpu, resource['resource_id'], 0, 128,
            ('CPU_TO_IP',), kind='memory_image', image_address=p['source_address']),
        FuzzableSource(source_id, cpu, resource['resource_id'], 0, resource['size']*8,
            ('CPU_TO_IP',), kind='memory_image')),
        rules=tuple(DependencyRule(nodes[target], (nodes[source],), kind)
            for source,target,kind in ((0,1,'DMA_MASTER_TRANSFER'),(1,2,'EVENT_ORDER'),
                (2,3,'DMA_MASTER_TRANSFER'),(4,5,'PERSISTENT_STATE_RULE'))))
    routes = []
    for doc in b['dma_routes']:
        doc = deepcopy(doc)
        index = doc['rule_index']
        doc.update(source_node_id=nodes[index], target_node_id=nodes[index+1])
        doc.pop('identity_sha256')
        for key in ('permissions','readable_offsets','writable_offsets'):
            doc[key] = tuple(doc[key])
        doc['accepted_write_values'] = ()
        routes.append(DmaMasterRouteContract(**doc))
    runtime_contract = RuntimePathContract(_edge_digest(graph.edge_document()),
        tuple(RuntimeNode(node, dma if index in (1,2) else cpu,
            'logical' if index in (1,2,5) else 'state') for index,node in enumerate(nodes)),
        (RuntimeEdgeContract(0,0,'dma_master_route'),RuntimeEdgeContract(1,0,'causal_order'),
         RuntimeEdgeContract(2,0,'dma_master_route'),RuntimeEdgeContract(3,0,'persistent_state',
             resource_component=cpu, resource_id=resource['resource_id'])), tuple(routes))
    selections = tuple(('CPU_TO_IP', graph.edge_paths_to(nodes[target],
        direction='CPU_TO_IP', max_depth=3, max_paths=2)[0]) for target in (3,5))
    prepared = PreparedRuntimePathContract(graph, runtime_contract, selections)
    b['dma_routes'] = [route.document() for route in routes]
    b['runtime_path_admission'] = dict(schema_version='compiled_F6_runtime_path_admission.v1',
        runtime_graph=graph.edge_document(), runtime_contract=runtime_contract.document(),
        prepared_runtime_paths=prepared.document(), runtime_path_ids=list(prepared.path_ids),
        execution_contract=deepcopy(c), execution_contract_sha256=_edge_digest(c),
        selected_dma_routes=deepcopy(b['dma_routes']))
    _refresh_edge_binding(archive)
    action = source_id + ':'+str(a['case_index'])
    slot = p['slot_base']+p['slot_bytes']*a['case_index']
    source = dict(action_id=action, component=cpu, address=slot,
        data_hex=a['prefix_hex'], source_id=source_id, kind='instruction')
    admission = SourceAdmission.create(case_id=a['case_id'], case_index=a['case_index'],
        source_id=source_id, path_id=prepared.path_ids[1], direction='CPU_TO_IP',
        component=cpu, action_id=action, role='fuzz_source', input_kind='instruction',
        input_sha256=_edge_digest(source)).document()
    scope = dict(observed_case=dict(case_id=a['case_id'], case_index=a['case_index']))
    # ScenarioRunner registers admissions without a component/provenance
    # envelope. F6 drains the instruction service event on the first CPU step.
    original = dict(event_id=900001, kind='source_admission', admission=admission)
    first_step = next(row for row in archive['events']
        if row.get('component')==cpu and 'kind' not in row)
    service = dict(event_id=900002, component=cpu, kind='instruction_source',
        producer_event_id=first_step['event_id'], address=source['address'], data_hex=a['prefix_hex'],
        source_event_id=action, generation=0, provenance=deepcopy(scope))
    archive['events'].insert(archive['events'].index(first_step)+1, service)
    archive['events'].insert(0, original)
    renumber(archive)
    for row in rows(archive,'instr_response'):
        offset = row['address']-source['address']
        row['snapshot'].update(memory_id=resource['resource_id'], generation=0,
            byte_offset=slot-resource['base']+offset, versions=[[0,1]]*4,
            writer_event_ids=[action]*4)
    refresh(archive)
    return archive


def _saved_fetch_archive(archive, *, count=32, refetch=False, sequence_start=1,
        scope_sequence_start=1000, min_tick=0):
    """Attach a complete Task9-shaped detached OBI receipt set to one case."""
    from myfuzz.scenario.ledger import TransactionKey

    archive = deepcopy(archive)
    events, local = archive['events'], archive['local_by_id']
    attempt, contract = archive['attempt'], archive['contract']
    cpu = contract['cpu']['instance_id']
    removed = {row['event_id'] for row in events if row.get('kind') == 'instr_response'}
    events[:] = [row for row in events if row.get('kind') != 'instr_response']
    for key, row in list(local.items()):
        if row.get('runner_event_id') in removed:
            del local[key]
    attempt['operands'] = []
    # The base graph fixture had four operand-only handshakes. The receipt
    # fixture replaces them with a complete 32-word stream, so remove those
    # old native instruction handshakes while preserving all data-channel facts.
    old_response_ticks = set()
    for row in events:
        if row.get('component') == cpu and row.get('kind') == 'local_tick_sample':
            backend = row.get('outputs', {}).get('backend', {})
            if row.get('phase') == 'pre' and backend.get('i_req_valid') == 1:
                backend.update(i_req_valid=0, i_req_ready=1, i_req_write=0,
                    i_req_addr=0, i_req_be=0, i_req_wdata=0)
                old_response_ticks.add(row.get('local_tick') + 1)
            if type(backend) is dict:
                for name, value in dict(i_req_valid=0, i_req_ready=1, i_req_write=0,
                        i_req_addr=0, i_req_be=0, i_req_wdata=0,
                        i_rsp_valid=0, i_rsp_ready=1, i_rsp_rdata=0, i_rsp_error=0,
                        d_req_valid=0, d_req_ready=1, d_req_write=0,
                        d_req_addr=0, d_req_be=0, d_req_wdata=0,
                        d_rsp_valid=0, d_rsp_ready=1, d_rsp_rdata=0, d_rsp_error=0).items():
                    backend.setdefault(name, value)
    for row in events:
        if row.get('component') == cpu and 'kind' not in row:
            if row.get('local_tick') in old_response_ticks:
                row['outputs'].update(instr_rsp_consumed=0,
                    instr_rsp_source_epoch=0, instr_rsp_source_sequence=0,
                    instr_rsp_rdata=0)
    refresh(archive)
    program, memory = contract['program_contract'], contract['memory']['resource']
    source_id = contract['instruction_source_id']
    action = source_id + ':' + str(attempt['case_index'])
    slot = program['slot_base'] + program['slot_bytes']*attempt['case_index']
    prefix = bytes.fromhex(attempt['prefix_hex'])
    source = dict(action_id=action, component=cpu, address=slot,
        data_hex=prefix.hex(), source_id=source_id)
    source_document = dict(source, kind='instruction')
    admission_row = rows(archive, 'source_admission')[0]
    service = rows(archive, 'instruction_source')[0]
    service['producer_event_id'] = admission_row['event_id']
    refresh(archive)
    service_observer_id=max(ref for component,ref in local)+1
    local[cpu,service_observer_id]=dict(deepcopy(service),
        event_id=service_observer_id,runner_event_id=service['event_id'])
    admission = deepcopy(admission_row['admission'])
    acceptance = dict(memory_id=memory['resource_id'], address=slot,
        byte_offset=slot-memory['base'], generation=0, data_hex=prefix.hex(),
        source_event_id=action, versions=[[0, 1]]*len(prefix),
        writer_event_ids=[action]*len(prefix),
        writer_kinds=['INSTRUCTION_SOURCE']*len(prefix))
    service['f6_acceptance_anchor'] = f6_acceptance_anchor(acceptance)
    refresh(archive)
    run_id = attempt['case_id'].split(':case:', 1)[0]
    binding_sha = archive['binding']['binding_sha256']
    execution_token = 'a'*32

    def add(component, kind, **fields):
        event_id = max(row['event_id'] for row in events) + 1
        row = dict(event_id=event_id, component=component,
            provenance=dict(observed_case=dict(case_id=attempt['case_id'],
                case_index=attempt['case_index'])), **fields)
        if kind is not None:
            row['kind'] = kind
        events.append(row)
        observer_id = 200000 + event_id
        local[component, observer_id] = dict(deepcopy(row), event_id=observer_id,
            runner_event_id=event_id)
        return row

    def add_step(tick, sequence, phase_rows, outputs):
        outputs = deepcopy(outputs)
        driver_samples = outputs.get('driver_samples')
        if type(driver_samples) is list:
            for sample_row in driver_samples:
                # Task9 driver samples carry the child-relative local tick;
                # Runner producer rows carry the absolute tick after _tick_base.
                sample_row['local_tick'] = tick - 1
        producer = add(cpu, None, local_tick=tick, inputs={}, outputs=outputs)
        produced = producer['event_id']
        ids = {}
        for phase, sample in phase_rows.items():
            ids[phase] = add(cpu, 'local_tick_sample', producer_event_id=produced,
                local_tick=tick, phase=phase, f6_obi_scope=[execution_token, sequence, 0, tick],
                outputs=deepcopy(sample))['event_id']
        return produced, ids

    def sample(backend, taps):
        return dict(backend=deepcopy(backend), protocol_taps=deepcopy(taps))

    traces = archive['_cpu_artifact'].runtime_document['base_protocol_traces']['traces']
    instruction_signals = next(trace['signals'] for trace in traces
        if trace['endpoint_id'] == contract['cpu']['instruction_endpoint_id'])
    data_signals = next(trace['signals'] for trace in traces
        if trace['endpoint_id'] == contract['cpu']['data_endpoint_id'])

    def tap_values(**values):
        taps = {name: 0 for name in (*instruction_signals.values(),
            *data_signals.values())}
        roles = dict(req='req', addr='addr', gnt='gnt', rvalid='rvalid',
            rdata='rdata', error='error')
        taps.update({instruction_signals[roles[name]]: value
            for name, value in values.items()})
        return taps

    total = count + int(refetch)
    receipts = []
    base_tick = max(max(row['local_tick'] for row in events
        if row.get('component') == cpu and row.get('kind') == 'local_tick_sample') + 1,
        min_tick)
    for index in range(total):
        word = index if index < count else 0
        address = slot + 4*word
        data = prefix[4*word:4*word+4]
        value = int.from_bytes(data, 'little')
        sequence = sequence_start + index
        key = TransactionKey('local-execution', 'native-testcase', cpu, 0,
            'instr', sequence)
        key_doc = dict(execution_id=key.execution_id, testcase_id=key.testcase_id,
            source_component=key.source_component, source_epoch=key.source_epoch,
            channel_id=key.channel_id, source_sequence=key.source_sequence)
        request_tick, backend_tick, response_tick = (base_tick+3*index,
            base_tick+3*index+1, base_tick+3*index+2)
        request_scope = (execution_token, scope_sequence_start+3*index, 0, request_tick)
        backend_scope = (execution_token, scope_sequence_start+3*index+1, 0, backend_tick)
        response_scope = (execution_token, scope_sequence_start+3*index+2, 0, response_tick)
        request_backend = dict(i_req_valid=1, i_req_ready=1, i_req_write=0,
            i_req_addr=address, i_req_be=15, i_req_wdata=0,
            i_rsp_valid=0, i_rsp_ready=1, i_rsp_rdata=0, i_rsp_error=0)
        request_backend.update(d_req_valid=0, d_req_ready=1, d_req_write=0,
            d_req_addr=0, d_req_be=0, d_req_wdata=0,
            d_rsp_valid=0, d_rsp_ready=1, d_rsp_rdata=0, d_rsp_error=0)
        request_pre = sample(request_backend, tap_values(req=1, addr=address,
            gnt=1, rvalid=0, rdata=0, error=0))
        idle_backend = dict(i_req_valid=0, i_req_ready=1, i_req_write=0,
            i_req_addr=0, i_req_be=0, i_req_wdata=0,
            i_rsp_valid=0, i_rsp_ready=1, i_rsp_rdata=0, i_rsp_error=0,
            d_req_valid=0, d_req_ready=1, d_req_write=0, d_req_addr=0,
            d_req_be=0, d_req_wdata=0, d_rsp_valid=0, d_rsp_ready=1,
            d_rsp_rdata=0, d_rsp_error=0)
        request_post = sample(idle_backend, tap_values(req=0, addr=0,
            gnt=0, rvalid=0, rdata=0, error=0))
        request_producer, request_ids = add_step(request_tick,
            request_scope[1], {'pre':request_pre, 'post':request_post},
            dict(instr_req_accepted=1, instr_addr=address,
                driver_samples=[dict(pre=request_pre, post=request_post)]))

        response_backend = dict(i_req_valid=0, i_req_ready=1, i_req_write=0,
            i_req_addr=0, i_req_be=0, i_req_wdata=0, i_rsp_valid=1,
            i_rsp_ready=1, i_rsp_rdata=value, i_rsp_error=0,
            d_req_valid=0, d_req_ready=1, d_req_write=0, d_req_addr=0,
            d_req_be=0, d_req_wdata=0, d_rsp_valid=0, d_rsp_ready=1,
            d_rsp_rdata=0, d_rsp_error=0)
        backend_pre = sample(response_backend, tap_values(req=0, addr=0,
            gnt=0, rvalid=0, rdata=0, error=0))
        backend_post = sample(response_backend, tap_values(req=0, addr=0,
            gnt=0, rvalid=1, rdata=value, error=0))
        snapshot = dict(transaction_id=str(key), memory_id=memory['resource_id'],
            generation=0, byte_offset=slot-memory['base']+4*word,
            data_hex=data.hex(), versions=[[0,1]]*4, writer_event_ids=[action]*4,
            materialized_offsets=[], writer_kinds=['INSTRUCTION_SOURCE']*4)
        memory_read = add(cpu, 'memory_read', transaction=key_doc, address=address,
            width_bytes=4, memory_id=memory['resource_id'], generation=0,
            byte_offset=snapshot['byte_offset'], value=value, data_hex=data.hex(),
            versions=[[0,1]]*4, writer_event_ids=[action]*4,
            writer_kinds=['INSTRUCTION_SOURCE']*4, producer_event_id=request_producer)
        backend_outputs = dict(instr_rsp_consumed=1, instr_rsp_source_epoch=0,
                instr_rsp_source_sequence=sequence, instr_rsp_rdata=value,
                driver_samples=[dict(local_tick=backend_tick-1,
                    pre=backend_pre, post=backend_post)])
        backend_producer = add(cpu, None, local_tick=backend_tick, inputs={},
            outputs=backend_outputs)['event_id']
        instr = add(cpu, 'instr_response', transaction=key_doc, address=address,
            raw_address=address, aligned_address=address, write=0, be=15, wdata=0,
            acceptance_tick=request_tick, response_tick=backend_tick, error=0,
            rdata=value, snapshot=dict(snapshot, value=value),
            response_boundary='obi_adapter_backend_acceptance',
            producer_event_id=backend_producer)
        backend_ids = {
            'pre': add(cpu, 'local_tick_sample', producer_event_id=backend_producer,
                local_tick=backend_tick, phase='pre', f6_obi_scope=list(backend_scope),
                outputs=backend_pre)['event_id'],
            'post': add(cpu, 'local_tick_sample', producer_event_id=backend_producer,
                local_tick=backend_tick, phase='post', f6_obi_scope=list(backend_scope),
                outputs=backend_post)['event_id']}
        assert memory_read['event_id'] < instr['event_id'] < backend_ids['pre']

        native_pre = sample(idle_backend, tap_values(req=0, addr=0,
            gnt=0, rvalid=1, rdata=value, error=0))
        native_post = sample(idle_backend, tap_values(req=0, addr=0,
            gnt=0, rvalid=0, rdata=value, error=0))
        response_producer, response_ids = add_step(response_tick,
            response_scope[1], {'pre':native_pre, 'post':native_post},
            dict(instr_rsp_consumed=0, instr_rsp_source_epoch=0,
                instr_rsp_source_sequence=0, instr_rsp_rdata=0,
                driver_samples=[dict(pre=native_pre, post=native_post)]))
        event_id = max(row['event_id'] for row in events) + 1
        receipt = dict(schema_version='compiled_F6_instruction_fetch_completion.v1',
            proof_scope='native_obi_instruction_fetch_completed',
            grants_source_authority=False, key=key_doc, snapshot=snapshot,
            acceptance=deepcopy(acceptance), source=deepcopy(source), admission=admission,
            run_id=run_id, execution_binding_sha256=binding_sha,
            case_id=attempt['case_id'], case_index=attempt['case_index'],
            execution=execution_token, testcase_id='native-testcase', reset_epoch=0,
            address=address, acceptance_tick=request_tick, snapshot_tick=request_tick,
            response_tick=response_tick, request_scope=list(request_scope),
            response_scope=list(response_scope), request_pre=request_pre,
            response_pre=native_pre, response_post=native_post,
            backend_response_tick=backend_tick, backend_response_scope=list(backend_scope),
            backend_response_pre=backend_pre, backend_response_post=backend_post,
            kind='compiled_F6_instruction_fetch_completion', component=cpu,
            provenance=dict(observed_case=dict(case_id=attempt['case_id'],
                case_index=attempt['case_index'])),
            event_id=event_id, producer_event_id=response_ids['pre'],
            admission_event_id=admission_row['event_id'],
            service_event_id=service['event_id'], instr_response_event_id=instr['event_id'],
            memory_read_event_id=memory_read['event_id'],
            request_pre_event_id=request_ids['pre'], request_producer_event_id=request_producer,
            backend_response_pre_event_id=backend_ids['pre'],
            backend_response_producer_event_id=backend_producer,
            backend_response_post_event_id=backend_ids['post'],
            response_pre_event_id=response_ids['pre'],
            response_producer_event_id=response_producer,
            response_post_event_id=response_ids['post'])
        events.append(receipt)
        observer_id = 200000 + event_id
        local[cpu, observer_id] = dict(deepcopy(receipt), event_id=observer_id,
            runner_event_id=event_id)
        receipts.append((receipt, observer_id, dict(memory_read=memory_read,
            instr_response=instr, request_producer=request_producer,
            request_pre=request_ids['pre'], request_post=request_ids['post'],
            backend_producer=backend_producer, backend_pre=backend_ids['pre'],
            backend_post=backend_ids['post'], response_producer=response_producer,
            response_pre=response_ids['pre'], response_post=response_ids['post'])))
    required_operands = []
    for offset in program['operand_instruction_offsets']:
        address = slot + offset
        response = next(item[2]['instr_response'] for item in receipts
            if item[2]['instr_response']['address'] == address)
        observer_id = next(ref for (component, ref), observer in local.items()
            if component == cpu and observer.get('runner_event_id') == response['event_id'])
        required_operands.append(observer_id)
    attempt['operands'] = required_operands
    return archive


def _append_other_case_fetches(archive, base_archive):
    """Merge a second independently synthesized case without cross-linking it."""
    from myfuzz.integration.compiled_f6_layout import F6Candidate

    other=deepcopy(base_archive)
    attempt,contract=other['attempt'],other['contract']
    raw=bytes.fromhex(attempt['raw8_hex'])
    packed=int.from_bytes(raw,'little')
    cand=F6Candidate(raw,tuple((packed>>(11*i))&2047 for i in range(4)))
    attempt['case_id']='run:case:1'
    attempt['case_index']=1
    attempt['prefix_hex']=build_f6_firmware(contract).prefix(cand,case_index=1).hex()
    second=edge_archive.__wrapped__(other, archive['_cpu_artifact'])
    last_tick=max(row.get('local_tick',0) for row in archive['events']
        if row.get('component')==contract['cpu']['instance_id'])
    second=_saved_fetch_archive(second,sequence_start=33,
        scope_sequence_start=2000,min_tick=last_tick+1)
    second_case=dict(case_id=attempt['case_id'],case_index=attempt['case_index'])
    selected=[row for row in second['events']
        if row.get('kind')=='source_admission'
            and row.get('admission',{}).get('case_id')==attempt['case_id']
        or type(row.get('provenance')) is dict
            and row['provenance'].get('observed_case')==second_case
            and row.get('component')==contract['cpu']['instance_id']]
    first_id=max(row['event_id'] for row in archive['events'])
    mapping={row['event_id']:first_id+index
        for index,row in enumerate(selected,1)}
    mapped=[]
    receipt_refs=('admission_event_id','service_event_id','memory_read_event_id',
        'instr_response_event_id','request_pre_event_id','request_producer_event_id',
        'backend_response_pre_event_id','backend_response_producer_event_id',
        'backend_response_post_event_id','response_pre_event_id',
        'response_producer_event_id','response_post_event_id')
    for row in selected:
        item=deepcopy(row)
        old_id=item['event_id']
        item['event_id']=mapping[old_id]
        if type(item.get('producer_event_id')) is int:
            item['producer_event_id']=mapping[item['producer_event_id']]
        if item.get('kind')=='compiled_F6_instruction_fetch_completion':
            for field in receipt_refs:
                item[field]=mapping[item[field]]
        mapped.append(item)
    archive['events'].extend(mapped)
    cpu=contract['cpu']['instance_id']
    for row in mapped:
        if row.get('kind')=='source_admission':
            continue
        observer_id=300000+row['event_id']
        archive['local_by_id'][cpu,observer_id]=dict(deepcopy(row),
            event_id=observer_id,runner_event_id=row['event_id'])


def test_saved_declared_edges_project_dma_hops_and_keep_unarchived_acceptance_missing(edge_archive):
    before = deepcopy(edge_archive)
    result = edge_projector()(**edge_archive)
    assert result['kind'] == 'cross_component.declared_edge_hops'
    assert result['outcome'] == 'missing', (result['details']['issues'],
        result['details']['component_evidence']['word_transfer']['details']['issues'],
        [row['issues'] for row in result['details']['edges']])
    edges = result['details']['edges']
    assert [(row['rule_index'],row['prerequisite_index']) for row in edges] == [(i,0) for i in range(4)]
    assert [row['outcome'] for row in edges] == ['passed','passed','passed','missing']
    assert all(row['runner_event_ids'] for row in edges)
    assert rows(edge_archive,'source_admission')[0]['event_id'] in edges[3]['runner_event_ids']
    assert result['details']['component_evidence']['word_transfer']['outcome'] == 'passed'
    assert edge_archive == before


def test_saved_instruction_edge_projects_complete_native_receipt_coverage(edge_archive):
    archive = _saved_fetch_archive(edge_archive)
    result = edge_projector()(**archive)
    edge = result['details']['edges'][3]
    assert edge['outcome'] == 'passed', (result['outcome'], edge['issues'])
    assert result['outcome'] == 'passed', (result['details']['issues'],
        result['details']['component_evidence']['word_transfer']['details']['issues'],
        [row['issues'] for row in result['details']['edges']])
    assert len(edge['evidence']) == 32
    assert {row['address'] for row in edge['evidence']} == {
        archive['contract']['program_contract']['slot_base'] + offset
        for offset in range(0, 128, 4)}
    assert len({json.dumps(row['key'], sort_keys=True) for row in edge['evidence']}) == 32
    assert len(archive['_cpu_artifact'].runtime_document['protocol_tap_ports']) == 15
    acceptance = rows(archive, 'compiled_F6_instruction_fetch_completion')[0]['acceptance']
    service = rows(archive, 'instruction_source')[0]
    assert service['f6_acceptance_anchor'] == f6_acceptance_anchor(acceptance)
    assert all(len(receipt['request_pre']['protocol_taps']) == 15
        for receipt in rows(archive, 'compiled_F6_instruction_fetch_completion'))
    assert all(set(row)=={'address','key','completion_event_id','root_refs'}
        and set(row['root_refs'])=={'admission','service','memory_read','instr_response',
            'request_pre','request_producer','backend_response_pre',
            'backend_response_producer','backend_response_post','response_pre',
            'response_producer','response_post'} for row in edge['evidence'])
    assert all(set(ref) == {'component', 'event_id', 'kind'}
        for ref in result['details']['raw_references'])


def test_saved_instruction_edge_rejects_uniform_version_chain_without_source_anchor(
        edge_archive):
    archive = _saved_fetch_archive(edge_archive)
    runner = {row['event_id']: row for row in archive['events']}
    for receipt in rows(archive, 'compiled_F6_instruction_fetch_completion'):
        changed = [[0, 7]] * len(receipt['acceptance']['versions'])
        receipt['acceptance']['versions'] = deepcopy(changed)
        receipt['snapshot']['versions'] = [[0, 7]] * 4
        runner[receipt['memory_read_event_id']]['versions'] = [[0, 7]] * 4
        runner[receipt['instr_response_event_id']]['snapshot']['versions'] = [[0, 7]] * 4
    refresh(archive)

    result = edge_projector()(**archive)
    edge = result['details']['edges'][3]
    assert edge['outcome'] == 'failed', edge['issues']
    assert any('acceptance anchor' in issue['reason'] for issue in edge['issues'])


def test_saved_instruction_edge_without_source_acceptance_anchor_stays_missing(
        edge_archive):
    archive = _saved_fetch_archive(edge_archive)
    rows(archive, 'instruction_source')[0].pop('f6_acceptance_anchor')
    refresh(archive)

    result = edge_projector()(**archive)
    assert result['details']['edges'][3]['outcome'] == 'missing'


def test_saved_instruction_edge_allows_refetch_only_with_new_full_transaction_key(edge_archive):
    archive = _saved_fetch_archive(edge_archive, refetch=True)
    result = edge_projector()(**archive)
    edge = result['details']['edges'][3]
    assert edge['outcome'] == 'passed', (result['outcome'], edge['issues'])
    assert len(edge['evidence']) == 33
    same_address = [row for row in edge['evidence']
        if row['address'] == archive['contract']['program_contract']['slot_base']]
    assert len(same_address) == 2
    assert same_address[0]['key'] != same_address[1]['key']


def test_saved_instruction_projection_ignores_a_complete_other_case(edge_archive):
    archive=_saved_fetch_archive(edge_archive)
    _append_other_case_fetches(archive,edge_archive)
    assert len([row for row in rows(archive,'compiled_F6_instruction_fetch_completion')
        if row.get('case_id')=='run:case:1'])==32
    result=edge_projector()(**archive)
    edge=result['details']['edges'][3]
    assert edge['outcome']=='passed', (result['outcome'],edge['issues'])
    assert result['outcome']=='passed', result['details']['issues']
    assert len(edge['evidence'])==32
    assert all(item['key']['source_sequence']<=32 for item in edge['evidence'])


def _strip_completion_linked_provenance(archive):
    receipts=rows(archive,'compiled_F6_instruction_fetch_completion')
    linked={receipt['event_id'] for receipt in receipts}
    for receipt in receipts:
        linked.update(receipt[field] for field in (
            'admission_event_id','service_event_id','memory_read_event_id',
            'instr_response_event_id','request_pre_event_id','request_producer_event_id',
            'backend_response_pre_event_id','backend_response_producer_event_id',
            'backend_response_post_event_id','response_pre_event_id',
            'response_producer_event_id','response_post_event_id'))
    cpu=archive['contract']['cpu']['instance_id']
    for ref in archive['attempt'].get('configuration',[]):
        observed=archive['local_by_id'].get((cpu,ref))
        if type(observed) is dict and type(observed.get('runner_event_id')) is int:
            linked.add(observed['runner_event_id'])
    for row in archive['events']:
        if row.get('event_id') in linked:
            row.pop('provenance',None)
    refresh(archive)
    return linked


def _tuple_arrays(value):
    if type(value) is dict:
        return {key:_tuple_arrays(item) for key,item in value.items()}
    if type(value) in (list,tuple):
        return tuple(_tuple_arrays(item) for item in value)
    return value


def _task9_in_memory_tuple_archive(archive):
    for row in archive['events']:
        for key,value in list(row.items()):
            row[key]=_tuple_arrays(value)
    refresh(archive)
    return archive


def test_saved_instruction_edge_accepts_typed_receipt_roots_without_generic_provenance(edge_archive):
    archive=_saved_fetch_archive(edge_archive)
    linked=_strip_completion_linked_provenance(archive)
    assert all('provenance' not in row for row in archive['events']
        if row.get('event_id') in linked)
    result=edge_projector()(**archive)
    edge=result['details']['edges'][3]
    assert edge['outcome']=='passed', (result['outcome'],edge['issues'])
    assert len(edge['evidence'])==32
    expected=_receipt_runner_closure(archive)
    raw_ids={row['event_id'] for row in result['details']['raw_evidence']}
    assert expected <= set(edge['runner_event_ids'])
    assert expected <= raw_ids


def _receipt_runner_closure(archive):
    root_fields=('admission_event_id','service_event_id','memory_read_event_id',
        'instr_response_event_id','request_pre_event_id','request_producer_event_id',
        'backend_response_pre_event_id','backend_response_producer_event_id',
        'backend_response_post_event_id','response_pre_event_id',
        'response_producer_event_id','response_post_event_id')
    runner={row.get('event_id'):row for row in archive['events']
        if type(row.get('event_id')) is int}
    result=set()
    for receipt in rows(archive,'compiled_F6_instruction_fetch_completion'):
        for event_id in (receipt.get('event_id'),*(receipt.get(field) for field in root_fields)):
            if type(event_id) is int and event_id>0:
                row=runner.get(event_id)
                if type(row) is dict and row.get('event_id')==event_id:
                    result.add(event_id)
    return result


def _swap_runner_event_ids(archive, first, second):
    mapping={first:second,second:first}
    for row in archive['events']:
        for field,value in list(row.items()):
            if (field=='event_id' or field.endswith('_event_id')) and type(value) is int:
                row[field]=mapping.get(value,value)
    for row in archive['local_by_id'].values():
        value=row.get('runner_event_id')
        if type(value) is int:
            row['runner_event_id']=mapping.get(value,value)
    refresh(archive)


@pytest.mark.parametrize('field,value', [('case_id','foreign:case:0'),('case_index',99)])
def test_saved_instruction_edge_still_rejects_typed_receipt_scope_drift_without_provenance(
        edge_archive,field,value):
    archive=_saved_fetch_archive(edge_archive)
    _strip_completion_linked_provenance(archive)
    rows(archive,'compiled_F6_instruction_fetch_completion')[0][field]=value
    refresh(archive)
    result=edge_projector()(**archive)
    assert result['details']['edges'][3]['outcome']=='failed',result['details']['edges'][3]['issues']


def test_saved_instruction_edge_accepts_tuple_native_command_scopes(edge_archive):
    archive=_saved_fetch_archive(edge_archive)
    for receipt in rows(archive,'compiled_F6_instruction_fetch_completion'):
        for field in ('request_scope','backend_response_scope','response_scope'):
            receipt[field]=tuple(receipt[field])
    refresh(archive)
    result=edge_projector()(**archive)
    assert result['details']['edges'][3]['outcome']=='passed',result['details']['edges'][3]['issues']


def test_saved_instruction_edge_projects_task9_in_memory_tuple_archives(edge_archive):
    archive=_saved_fetch_archive(edge_archive)
    _strip_completion_linked_provenance(archive)
    _task9_in_memory_tuple_archive(archive)
    receipt=rows(archive,'compiled_F6_instruction_fetch_completion')[0]
    assert type(receipt['acceptance']['versions']) is tuple
    assert type(receipt['acceptance']['versions'][0]) is tuple
    result=edge_projector()(**archive)
    edge=result['details']['edges'][3]
    assert edge['outcome']=='passed',edge['issues']
    assert len(edge['evidence'])==32


def test_saved_instruction_edge_rejects_coherent_per_byte_versions_with_exact_snapshots(edge_archive):
    archive=_saved_fetch_archive(edge_archive)
    _strip_completion_linked_provenance(archive)
    _task9_in_memory_tuple_archive(archive)
    slot=archive['contract']['program_contract']['slot_base']
    action=archive['contract']['instruction_source_id']+':0'
    acceptance_versions=tuple((0,index+1) for index in range(128))
    writer_ids=(action,)*128
    writer_kinds=('INSTRUCTION_SOURCE',)*128
    runner={row['event_id']:row for row in archive['events']}
    for receipt in rows(archive,'compiled_F6_instruction_fetch_completion'):
        offset=receipt['address']-slot
        receipt['acceptance']['versions']=acceptance_versions
        receipt['acceptance']['writer_event_ids']=writer_ids
        receipt['acceptance']['writer_kinds']=writer_kinds
        receipt['snapshot']['versions']=acceptance_versions[offset:offset+4]
        receipt['snapshot']['writer_event_ids']=writer_ids[offset:offset+4]
        receipt['snapshot']['writer_kinds']=writer_kinds[offset:offset+4]
        memory_read=runner[receipt['memory_read_event_id']]
        memory_read['versions']=acceptance_versions[offset:offset+4]
        memory_read['writer_event_ids']=writer_ids[offset:offset+4]
        memory_read['writer_kinds']=writer_kinds[offset:offset+4]
        response=runner[receipt['instr_response_event_id']]
        response['snapshot']['versions']=acceptance_versions[offset:offset+4]
        response['snapshot']['writer_event_ids']=writer_ids[offset:offset+4]
        response['snapshot']['writer_kinds']=writer_kinds[offset:offset+4]
    refresh(archive)
    result=edge_projector()(**archive)
    edge=result['details']['edges'][3]
    assert edge['outcome']=='failed',edge['issues']
    assert any('instruction acceptance full byte-version chain' in issue['reason']
        for issue in edge['issues'])


@pytest.mark.parametrize(('producer_field','output_field','value'), [
    ('request_producer_event_id','instr_req_accepted',True),
    ('backend_response_producer_event_id','instr_rsp_consumed',True),
    ('backend_response_producer_event_id','instr_rsp_source_sequence',True),
])
def test_saved_instruction_edge_rejects_bool_as_integer_step_output(
        edge_archive,producer_field,output_field,value):
    archive=_saved_fetch_archive(edge_archive)
    _strip_completion_linked_provenance(archive)
    receipt=rows(archive,'compiled_F6_instruction_fetch_completion')[0]
    runner={row['event_id']:row for row in archive['events']}
    producer=runner[receipt[producer_field]]
    producer['outputs'][output_field]=value
    refresh(archive)
    result=edge_projector()(**archive)
    edge=result['details']['edges'][3]
    assert edge['outcome']=='failed',edge['issues']


def test_saved_instruction_edge_rejects_nonappend_order_runner_event_ids(edge_archive):
    archive=_saved_fetch_archive(edge_archive)
    receipt=rows(archive,'compiled_F6_instruction_fetch_completion')[0]
    _swap_runner_event_ids(archive,receipt['request_pre_event_id'],
        receipt['memory_read_event_id'])
    receipt=rows(archive,'compiled_F6_instruction_fetch_completion')[0]
    assert receipt['request_pre_event_id']>receipt['memory_read_event_id']
    assert any(row['event_id'] != index+1
        for index,row in enumerate(archive['events']))
    result=edge_projector()(**archive)
    edge=result['details']['edges'][3]
    assert edge['outcome']=='failed',edge['issues']
    assert any('Runner event append order' in issue['reason'] for issue in edge['issues'])


def test_saved_word_transfer_uses_unicode_execution_binding_canonicalization(edge_archive):
    archive=edge_archive
    archive['binding']['audit_note']='F6 实测绑定'
    _refresh_edge_binding(archive)
    result=edge_projector()(**archive)
    word=result['details']['component_evidence']['word_transfer']
    assert word['outcome']=='passed',word['details']['issues']


def test_saved_instruction_edge_joins_config_scope_without_case_provenance(edge_archive):
    archive=_saved_fetch_archive(edge_archive)
    _strip_completion_linked_provenance(archive)
    cpu=archive['contract']['cpu']['instance_id']
    ref=archive['attempt']['configuration'][0]
    observed=archive['local_by_id'][cpu,ref]
    accepted=next(row for row in archive['events']
        if row['event_id']==observed['runner_event_id'])
    accepted['transaction']['testcase_id']='foreign-testcase'
    refresh(archive)
    result=edge_projector()(**archive)
    assert result['details']['edges'][3]['outcome']=='failed',result['details']['edges'][3]['issues']


def test_saved_instruction_edge_uses_receipt_scope_when_no_config_transaction_refs(edge_archive):
    archive=_saved_fetch_archive(edge_archive)
    archive['attempt']['configuration']=[]
    result=edge_projector()(**archive)
    assert result['details']['edges'][3]['outcome']=='passed',result['details']['edges'][3]['issues']


def test_saved_instruction_edge_retains_available_diagnostic_roots_when_one_is_missing(edge_archive):
    archive=_saved_fetch_archive(edge_archive)
    _strip_completion_linked_provenance(archive)
    receipt=rows(archive,'compiled_F6_instruction_fetch_completion')[0]
    missing=receipt['backend_response_producer_event_id']
    archive['events']=[row for row in archive['events'] if row['event_id']!=missing]
    refresh(archive)
    result=edge_projector()(**archive)
    edge=result['details']['edges'][3]
    assert edge['outcome']=='failed',edge['issues']
    expected=_receipt_runner_closure(archive)
    raw_ids={row['event_id'] for row in result['details']['raw_evidence']}
    assert expected <= set(edge['runner_event_ids'])
    assert expected <= raw_ids
    assert missing not in raw_ids


def test_saved_instruction_edge_rejects_duplicate_completion_key(edge_archive):
    archive = _saved_fetch_archive(edge_archive, refetch=True)
    receipts = rows(archive, 'compiled_F6_instruction_fetch_completion')
    receipts[-1]['key'] = deepcopy(receipts[0]['key'])
    refresh(archive)
    result = edge_projector()(**archive)
    assert result['details']['edges'][3]['outcome'] == 'failed'


def test_saved_instruction_edge_requires_receipts_for_every_prefix_word(edge_archive):
    archive = _saved_fetch_archive(edge_archive, count=31)
    result = edge_projector()(**archive)
    edge = result['details']['edges'][3]
    assert edge['outcome'] == 'missing'
    assert len(edge['evidence']) == 31
    assert result['outcome'] == 'missing'


def test_saved_instruction_edge_reports_unreceipted_prefix_response_as_missing(edge_archive):
    archive=_saved_fetch_archive(edge_archive)
    receipt=rows(archive,'compiled_F6_instruction_fetch_completion')[-1]
    archive['events'].remove(receipt)
    for key,row in list(archive['local_by_id'].items()):
        if row.get('runner_event_id')==receipt['event_id']:
            del archive['local_by_id'][key]
    result=edge_projector()(**archive)
    assert result['details']['edges'][3]['outcome']=='missing'


@pytest.mark.parametrize('mutation', ['acceptance_versions','snapshot_writer',
    'native_pre','cross_case','fresh_binding','wrong_slot','dangling_root',
    'bool_case_index','request_epoch_bool'])
def test_saved_instruction_receipt_chain_rejects_archived_contradictions(edge_archive, mutation):
    archive = _saved_fetch_archive(edge_archive)
    receipt = rows(archive, 'compiled_F6_instruction_fetch_completion')[0]
    if mutation == 'acceptance_versions':
        receipt['acceptance']['versions'][0] = [0, 99]
    elif mutation == 'snapshot_writer':
        receipt['snapshot']['writer_event_ids'][0] = 'foreign-action'
    elif mutation == 'native_pre':
        pre = next(row for row in rows(archive, 'local_tick_sample')
            if row['event_id'] == receipt['response_pre_event_id'])
        pre['outputs']['protocol_taps']['trace_obi_i_rdata'] ^= 1
    elif mutation == 'cross_case':
        receipt['case_id'] = 'foreign:case:0'
    elif mutation == 'fresh_binding':
        receipt['execution_binding_sha256'] = '0'*64
    elif mutation == 'wrong_slot':
        receipt['address'] += archive['contract']['program_contract']['slot_bytes']
    elif mutation == 'bool_case_index':
        receipt['case_index'] = False
    elif mutation == 'request_epoch_bool':
        receipt['request_scope'][2] = False
    else:
        receipt['response_post_event_id'] = max(row['event_id'] for row in archive['events']) + 7
    refresh(archive)
    result = edge_projector()(**archive)
    edge=result['details']['edges'][3]
    assert edge['outcome'] == 'failed', edge['issues']
    expected=_receipt_runner_closure(archive)
    raw_ids={row['event_id'] for row in result['details']['raw_evidence']}
    assert expected <= set(edge['runner_event_ids'])
    assert expected <= raw_ids


def test_saved_instruction_edge_rejects_boolean_request_scope_tick(edge_archive):
    archive=_saved_fetch_archive(edge_archive)
    receipt=rows(archive,'compiled_F6_instruction_fetch_completion')[0]
    receipt['acceptance_tick']=1
    receipt['snapshot_tick']=1
    receipt['request_scope'][3]=True
    runner={row['event_id']:row for row in archive['events']}
    request_pre=runner[receipt['request_pre_event_id']]
    request_pre['local_tick']=1
    request_pre['f6_obi_scope'][3]=1
    request_producer=runner[receipt['request_producer_event_id']]
    request_producer['local_tick']=1
    refresh(archive)
    result=edge_projector()(**archive)
    edge=result['details']['edges'][3]
    assert edge['outcome']=='failed',edge['issues']


@pytest.mark.parametrize('mutation', ['missing','extra','non_int'])
def test_saved_instruction_edge_requires_exact_integer_request_tap_inventory(edge_archive,mutation):
    archive=_saved_fetch_archive(edge_archive)
    receipt=rows(archive,'compiled_F6_instruction_fetch_completion')[0]
    taps=receipt['request_pre']['protocol_taps']
    if mutation=='missing':
        taps.pop('trace_obi_i_error')
    elif mutation=='extra':
        taps['trace_obi_extra']=0
    else:
        taps['trace_obi_i_req']=True
    runner={row['event_id']:row for row in archive['events']}
    request_pre=runner[receipt['request_pre_event_id']]
    request_pre['outputs']=deepcopy(receipt['request_pre'])
    request_producer=runner[receipt['request_producer_event_id']]
    request_producer['outputs']['driver_samples'][0]['pre']=deepcopy(receipt['request_pre'])
    refresh(archive)
    result=edge_projector()(**archive)
    assert result['details']['edges'][3]['outcome']=='failed',result['details']['edges'][3]['issues']


@pytest.mark.parametrize(('phase', 'mutation'), [
    ('request_post', 'missing'),
    ('backend_response_pre', 'extra'),
    ('backend_response_post', 'non_int'),
    ('response_pre', 'missing'),
    ('response_post', 'extra'),
])
def test_saved_instruction_edge_checks_artifact_taps_on_each_response_sample(
        edge_archive, phase, mutation):
    archive = _saved_fetch_archive(edge_archive)
    receipt = rows(archive, 'compiled_F6_instruction_fetch_completion')[0]
    runner = {row['event_id']: row for row in archive['events']}
    phase_root = {
        'request_post': ('request_producer_event_id', 'post', None),
        'backend_response_pre': ('backend_response_producer_event_id', 'pre',
            'backend_response_pre_event_id'),
        'backend_response_post': ('backend_response_producer_event_id', 'post',
            'backend_response_post_event_id'),
        'response_pre': ('response_producer_event_id', 'pre', 'response_pre_event_id'),
        'response_post': ('response_producer_event_id', 'post', 'response_post_event_id'),
    }
    producer_field, sample_phase, sample_field = phase_root[phase]
    producer = runner[receipt[producer_field]]
    sample = producer['outputs']['driver_samples'][0][sample_phase]
    taps = sample['protocol_taps']
    if mutation == 'missing':
        taps.pop(next(iter(taps)))
    elif mutation == 'extra':
        taps['trace_obi_unbound_extra'] = 0
    else:
        taps[next(iter(taps))] = True
    if sample_field is not None:
        row = runner[receipt[sample_field]]
        row['outputs'] = deepcopy(sample)
        receipt[phase] = deepcopy(sample)
    else:
        # The request POST is nested in the real step producer rather than a
        # separate receipt root. Keep its archived local sample synchronized.
        row = next(row for row in archive['events']
            if row.get('kind') == 'local_tick_sample'
            and row.get('producer_event_id') == producer['event_id']
            and row.get('phase') == 'post')
        row['outputs'] = deepcopy(sample)
    refresh(archive)
    result = edge_projector()(**archive)
    edge = result['details']['edges'][3]
    assert edge['outcome'] == 'failed', edge['issues']
    assert any('physical tap inventory' in issue['reason'] for issue in edge['issues'])


def test_saved_instruction_edge_rejects_wrong_native_request_driver_local_tick(
        edge_archive):
    archive = _saved_fetch_archive(edge_archive)
    receipt = rows(archive, 'compiled_F6_instruction_fetch_completion')[0]
    producer = next(row for row in archive['events']
        if row['event_id'] == receipt['request_producer_event_id'])
    producer['outputs']['driver_samples'][0]['local_tick'] = True
    refresh(archive)
    result = edge_projector()(**archive)
    edge = result['details']['edges'][3]
    assert edge['outcome'] == 'failed', edge['issues']
    assert any('request step sample inventory mismatch' in issue['reason']
        for issue in edge['issues'])


@pytest.mark.parametrize('mutation', ['contract_endpoint', 'binding_identity',
    'runtime_digest'])
def test_saved_instruction_edge_binds_taps_to_cpu_artifact_identity(
        edge_archive, mutation):
    archive = _saved_fetch_archive(edge_archive)
    cpu = archive['contract']['cpu']['instance_id']
    if mutation == 'contract_endpoint':
        archive['contract']['cpu']['instruction_endpoint_id'] = 'unbound_instruction'
        path = archive['binding']['runtime_path_admission']
        path['execution_contract'] = deepcopy(archive['contract'])
        path['execution_contract_sha256'] = _edge_digest(archive['contract'])
    elif mutation == 'binding_identity':
        archive['binding']['artifact_identities'][cpu]['artifact_digest'] = '0' * 64
    else:
        archive['binding']['cpu']['runtime_artifact_sha256'] = '0' * 64
    _refresh_edge_binding(archive)
    result = edge_projector()(**archive)
    edge = result['details']['edges'][3]
    assert edge['outcome'] == 'failed', edge['issues']
    assert any('CPU OBI artifact' in issue['reason'] for issue in edge['issues'])


@pytest.mark.parametrize('mutation', ['missing', 'extra', 'non_int_port',
    'non_int_trace_width', 'non_str_port_name', 'non_str_port_direction',
    'non_str_port_role', 'non_str_port_endpoint', 'non_str_port_source_wire',
    'non_str_trace_signal'])
def test_saved_instruction_edge_requires_artifact_authenticated_tap_inventory(
        edge_archive, mutation):
    archive = _saved_fetch_archive(edge_archive)
    artifact = archive['_cpu_artifact']
    runtime = deepcopy(artifact.runtime_document)
    if mutation == 'missing':
        runtime['protocol_tap_ports'].pop()
    elif mutation == 'extra':
        runtime['protocol_tap_ports'].append(dict(
            name='trace_obi_extra', direction='output', width=1,
            role='extra', endpoint_id='instruction', source_wire='link_extra'))
    elif mutation == 'non_int_port':
        runtime['protocol_tap_ports'][0]['width'] = True
    elif mutation.startswith('non_str_port_'):
        field = mutation.removeprefix('non_str_port_')
        field = {'direction':'direction', 'role':'role', 'endpoint':'endpoint_id',
            'source_wire':'source_wire', 'name':'name'}[field]
        runtime['protocol_tap_ports'][0][field] = True
    else:
        instruction = next(trace for trace in
            runtime['base_protocol_traces']['traces']
            if trace['endpoint_id'] ==
                archive['contract']['cpu']['instruction_endpoint_id'])
        if mutation == 'non_int_trace_width':
            instruction['signal_widths']['req'] = True
        else:
            instruction['signals']['req'] = True
    _rebind_edge_cpu_artifact(archive, runtime)
    result = edge_projector()(**archive)
    assert result['details']['edges'][3]['outcome'] == 'failed'
    assert any('artifact' in row['reason'] or 'OBI' in row['reason']
        for row in result['details']['edges'][3]['issues'])


def test_saved_instruction_edge_rejects_driver_local_tick_base_drift_within_epoch(
        edge_archive):
    archive = _saved_fetch_archive(edge_archive)
    receipts = rows(archive, 'compiled_F6_instruction_fetch_completion')
    runner = {row['event_id']:row for row in archive['events']}
    producer = runner[receipts[1]['request_producer_event_id']]
    producer['outputs']['driver_samples'][0]['local_tick'] += 1
    refresh(archive)
    result = edge_projector()(**archive)
    edge = result['details']['edges'][3]
    assert edge['outcome'] == 'failed', edge['issues']
    assert any('tick base' in issue['reason'] for issue in edge['issues'])


@pytest.mark.parametrize('edge,kind', [(0,'memory_read'),(1,'dma_edge'),
    (2,'memory_write_commit'),(3,'instruction_source')])
@pytest.mark.parametrize('mutation', ['missing','duplicate','foreign','corrupt'])
def test_saved_declared_edge_raw_evidence_cannot_be_replaced_by_labels(edge_archive, edge, kind, mutation):
    archive = edge_archive
    candidates = rows(archive,kind)
    if edge == 1:
        candidates = [r for r in candidates if r.get('response') is not None]
    if edge == 2:
        candidates = [r for r in candidates if r['component']=='mover_beta']
    selected = candidates[0]
    if mutation == 'missing':
        archive['events'].remove(selected)
    elif mutation == 'duplicate':
        duplicate = deepcopy(selected)
        duplicate['event_id'] = max(r['event_id'] for r in archive['events'])+1
        archive['events'].append(duplicate)
    elif mutation == 'foreign':
        selected['provenance']['observed_case']['case_id'] = 'foreign'
    elif edge == 0:
        selected['writer_event_ids'][0] = 'unrelated-source'
    elif edge == 1:
        selected['response']['transaction']['testcase_id'] = 'foreign'
    elif edge == 2:
        selected['commit_document']['generation'] = 7
    else:
        selected['source_event_id'] = 'foreign-action'
    refresh(archive)
    archive['attempt'].update(outcome='passed',details={'edges':[{'outcome':'passed'}]*4})
    result = edge_projector()(**archive)
    assert result['outcome'] == ('missing' if mutation=='missing' else 'failed'), result['details']['issues']
    assert result['details']['edges'][edge]['outcome'] != 'passed'
    assert result['details']['edges'][edge]['runner_event_ids']


@pytest.mark.parametrize('field', ['versions','writer_event_ids','writer_kinds','generation','byte_offset','data_hex'])
def test_saved_instruction_edge_checks_exact_byte_acceptance(edge_archive, field):
    row = rows(edge_archive,'instr_response')[0]['snapshot']
    row[field] = ([['wrong']] if isinstance(row[field],list) else
        '00000000' if field=='data_hex' else 99)
    edge_archive['attempt']['reads'] = []
    refresh(edge_archive)
    result = edge_projector()(**edge_archive)
    assert result['outcome'] == 'failed'
    assert result['details']['edges'][3]['outcome'] == 'failed'


@pytest.mark.parametrize('mutation', ['duplicate_edge','wrong_graph_hash','wrong_path',
    'wrong_source','route_key','ram_source_span'])
def test_saved_declared_edges_reject_declaration_drift(edge_archive, mutation):
    path = edge_archive['binding']['runtime_path_admission']
    if mutation=='duplicate_edge':
        path['runtime_contract']['edges'].append(deepcopy(path['runtime_contract']['edges'][0]))
    elif mutation=='wrong_graph_hash':
        path['runtime_contract']['graph_sha256']='0'*64
    elif mutation=='wrong_path':
        path['runtime_path_ids'][1]='foreign'
    elif mutation=='wrong_source':
        path['runtime_graph']['rules'][3]['prerequisites']=['foreign']
    elif mutation=='route_key':
        path['selected_dma_routes'][0]['rule_index']=1
    else:
        source_id='F6.runtime_ram_source_words'
        for graph in (path['runtime_graph'],path['prepared_runtime_paths']['graph']):
            row=next(item for item in graph['sources'] if item['source_id']==source_id)
            row['width']+=8
        graph_sha=_edge_digest(path['runtime_graph'])
        path['runtime_contract']['graph_sha256']=graph_sha
        path['prepared_runtime_paths']['contract']['graph_sha256']=graph_sha
    _refresh_edge_binding(edge_archive)
    result = edge_projector()(**edge_archive)
    assert result['outcome']=='failed'
    assert not any(row['outcome']=='passed' for row in result['details']['edges'])


def test_saved_dma_edge_outcomes_keep_unrelated_effect_gaps_separate(edge_archive):
    archive=edge_archive
    destination=next(row for row in rows(archive,'memory_write_commit')
        if row.get('component')=='mover_beta'
        and row.get('transaction',{}).get('source_sequence')==5)
    archive['events'].remove(destination)
    refresh(archive)
    result=edge_projector()(**archive)
    edges=result['details']['edges']
    assert result['outcome']=='missing'
    assert [row['outcome'] for row in edges]==['passed','passed','missing','missing']


def test_saved_word_contradiction_precedes_missing_runtime_declaration(edge_archive):
    archive=edge_archive
    archive['binding'].pop('runtime_path_admission')
    archive['binding']['binding_sha256']=_edge_digest({
        key:value for key,value in archive['binding'].items()
        if key!='binding_sha256'})
    archive['attempt']['raw8_hex']='ff'*8
    result=edge_projector()(**archive)
    assert result['details']['component_evidence']['word_transfer']['outcome']=='failed'
    assert result['outcome']=='failed'


def test_saved_instruction_missing_reference_does_not_hide_snapshot_contradiction(edge_archive):
    edge_archive['attempt']['operands'] = []
    rows(edge_archive,'instr_response')[0]['snapshot']['writer_event_ids'][0] = 'foreign'
    refresh(edge_archive)
    result = edge_projector()(**edge_archive)
    assert result['outcome']=='failed'
    assert result['details']['edges'][3]['outcome']=='failed'


def test_saved_instruction_without_original_acceptance_stays_missing(edge_archive):
    result = edge_projector()(**edge_archive)
    assert result['outcome']=='missing'
    assert result['details']['edges'][3]['outcome']=='missing'
    assert len(result['details']['edges'][3]['evidence'])==4


def test_saved_instruction_without_acceptance_still_rejects_bad_byte_version(edge_archive):
    rows(edge_archive,'instr_response')[0]['snapshot']['versions'] = [[-1,0]]*4
    refresh(edge_archive)
    assert edge_projector()(**edge_archive)['outcome']=='failed'


def test_saved_declared_edges_ignore_saved_status_labels(edge_archive):
    expected = edge_projector()(**edge_archive)
    edge_archive['attempt'].update(outcome='failed',status_kind='failed',
        observation_status='failed', details={'edges':[]})
    assert edge_projector()(**edge_archive)==expected


@pytest.mark.parametrize('mutation', ['provenance','admission','refs'])
def test_saved_declared_edges_malformed_evidence_returns_closed_failure(edge_archive,mutation):
    if mutation=='provenance':
        rows(edge_archive,'instruction_source')[0]['provenance']=[]
    elif mutation=='admission':
        rows(edge_archive,'source_admission')[0]['admission']=[]
    else:
        edge_archive['attempt']['reads']=True
    result = edge_projector()(**edge_archive)
    assert result['outcome']=='failed'
    assert set(result)=={'kind','outcome','details'}
    assert {'raw_evidence','raw_references'} <= set(result['details'])


def test_saved_instruction_cross_testcase_refs_never_get_success(edge_archive):
    for row in rows(edge_archive,'instr_response'):
        row['transaction']['testcase_id'] = 'foreign'
    refresh(edge_archive)
    result = edge_projector()(**edge_archive)
    assert result['details']['edges'][3]['outcome']=='failed'


def test_saved_instruction_generation_conflict_precedes_absent_acceptance(edge_archive):
    snapshot = rows(edge_archive,'instr_response')[0]['snapshot']
    snapshot.update(generation=9, versions=[[9,1]]*4)
    refresh(edge_archive)
    assert edge_projector()(**edge_archive)['details']['edges'][3]['outcome']=='failed'


def test_saved_instruction_extra_observer_reference_fails(edge_archive):
    edge_archive['attempt']['operands'].append(edge_archive['attempt']['operands'][0])
    assert edge_projector()(**edge_archive)['details']['edges'][3]['outcome']=='failed'


def test_saved_dma_read_accepts_nonzero_ignored_write_data(word_transfer_archive):
    archive = word_transfer_archive
    row = next(row for row in rows(archive, 'dma_edge')
        if row.get('accepted', {}).get('transaction', {}).get('source_sequence') == 3)
    row['accepted']['value'] = 1
    row['payload']['pre_backend']['mwb_dat_w'] = 1
    refresh(archive)
    result = word_projector()(**archive)
    assert result['outcome'] == 'passed', result['details']['issues']


@pytest.mark.parametrize('forged', [False, True])
def test_saved_word_route_accepts_only_declared_runtime_endpoint_alias(word_transfer_archive, forged):
    from dataclasses import replace
    from myfuzz.scenario.runtime_path_contract import DmaMasterRouteContract

    archive = word_transfer_archive
    binding = archive['binding']
    path = binding['runtime_path_admission']
    physical = archive['contract']['master_routes']['physical_endpoint_link']
    physical['link_id'] = 'mwb'
    intents = archive['contract']['master_routes']['intents']['routes']
    links = []
    for index, route_doc in enumerate(binding['dma_routes']):
        route = DmaMasterRouteContract.from_document(route_doc)
        changed = replace(route, endpoint_id=route.operation + '_master').document()
        binding['dma_routes'][index] = changed
        path['selected_dma_routes'][index] = deepcopy(changed)
        links.append(dict(route_id=intents[index]['route_id'],
            runtime_route_sha256=changed['identity_sha256'],
            rule_index=changed['rule_index'], prerequisite_index=changed['prerequisite_index'],
            endpoint_link=dict(static_endpoint_id=physical['endpoint_id'],
                artifact_endpoint_id=physical['endpoint_id'],
                artifact_link_id='mwb', artifact_link_provider_id='wishbone-dma-single-master.v1',
                mode='explicit_alias',
                runtime_endpoint_id=changed['endpoint_id'], operation=route.operation,
                template_binding=deepcopy(physical['template_binding']))))
    if forged:
        links[0]['endpoint_link']['runtime_endpoint_id'] = 'foreign_master'
    path['route_links'] = links
    binding['binding_sha256'] = _edge_digest({k: v for k, v in binding.items()
        if k != 'binding_sha256'})
    result = word_projector()(**archive)
    reasons = [issue['reason'] for issue in result['details']['issues']]
    if forged:
        assert 'runtime route endpoint binding mismatch' in reasons
    else:
        assert 'bound route differs from contract intent/endpoint/resource' not in reasons
        assert 'runtime route endpoint binding mismatch' not in reasons


@pytest.mark.parametrize('mutation', ['same_step', 'different_step', 'wrong_tick',
    'wrong_key', 'wrong_writer', 'wrong_version', 'after_response'])
def test_saved_read_snapshot_can_precede_accept_only_with_same_dma_step(
        word_transfer_archive, mutation):
    archive = word_transfer_archive
    attempt = archive['attempt']
    dma = archive['contract']['dma']['instance_id']
    accepted_local = archive['local_by_id'][dma, attempt['reads'][0]]
    snapshot_local = archive['local_by_id'][dma, attempt['read_snapshots'][0]]
    accepted = next(row for row in archive['events']
        if row['event_id'] == accepted_local['runner_event_id'])
    snapshot = next(row for row in archive['events']
        if row['event_id'] == snapshot_local['runner_event_id'])
    response_local = archive['local_by_id'][dma, attempt['read_responses'][0]]
    response = next(row for row in archive['events']
        if row['event_id'] == response_local['runner_event_id'])
    producer = dict(event_id=max(row['event_id'] for row in archive['events']) + 1,
        component=dma, local_tick=accepted['tick'], inputs={}, outputs={})
    archive['events'].insert(archive['events'].index(accepted), producer)
    accepted['producer_event_id'] = producer['event_id']
    snapshot['producer_event_id'] = producer['event_id']
    archive['events'].remove(snapshot)
    if mutation == 'after_response':
        archive['events'].insert(archive['events'].index(response) + 1, snapshot)
    else:
        archive['events'].insert(archive['events'].index(accepted), snapshot)
    if mutation == 'different_step':
        other = dict(event_id=producer['event_id'] + 1, component=dma,
            local_tick=accepted['tick'] - 1, inputs={}, outputs={})
        archive['events'].insert(archive['events'].index(producer), other)
        snapshot['producer_event_id'] = other['event_id']
    elif mutation == 'wrong_tick':
        producer['local_tick'] -= 1
    elif mutation == 'wrong_key':
        snapshot['transaction']['source_sequence'] = 99
    elif mutation == 'wrong_writer':
        snapshot['writer_event_ids'][0] = 'other-cpu-write'
    elif mutation == 'wrong_version':
        snapshot['versions'][0] = [0, 999]
    renumber(archive)
    refresh(archive)
    result = word_projector()(**archive)
    if mutation == 'same_step':
        assert result['outcome'] == 'passed', result['details']['issues']
    else:
        assert result['outcome'] == 'failed', result['details']['issues']


@pytest.mark.parametrize('mutation', ['same_step', 'different_step', 'wrong_tick',
    'wrong_key', 'wrong_writer', 'wrong_version', 'after_response'])
def test_saved_dma_commit_can_precede_accept_only_with_same_dma_step(
        word_transfer_archive, mutation):
    archive = word_transfer_archive
    attempt = archive['attempt']
    dma = archive['contract']['dma']['instance_id']
    def selected(section):
        local = archive['local_by_id'][dma, attempt[section][0]]
        return next(row for row in archive['events'] if row['event_id'] == local['runner_event_id'])
    accepted, commit, response = (selected(name) for name in
        ('writes', 'word_commits', 'write_responses'))
    producer = dict(event_id=max(row['event_id'] for row in archive['events']) + 1,
        component=dma, local_tick=accepted['tick'], inputs={}, outputs={})
    archive['events'].insert(archive['events'].index(accepted), producer)
    accepted['producer_event_id'] = commit['producer_event_id'] = producer['event_id']
    archive['events'].remove(commit)
    if mutation == 'after_response':
        archive['events'].insert(archive['events'].index(response) + 1, commit)
    else:
        archive['events'].insert(archive['events'].index(accepted), commit)
    if mutation == 'different_step':
        other = dict(event_id=producer['event_id'] + 1, component=dma,
            local_tick=accepted['tick'] - 1, inputs={}, outputs={})
        archive['events'].insert(archive['events'].index(producer), other)
        commit['producer_event_id'] = other['event_id']
    elif mutation == 'wrong_tick':
        producer['local_tick'] -= 1
    elif mutation == 'wrong_key':
        commit['transaction']['source_sequence'] = 99
    elif mutation == 'wrong_writer':
        commit['commit_document']['enabled_byte_cells'][0]['writer_event_id'] = 'foreign'
    elif mutation == 'wrong_version':
        commit['commit_document']['enabled_byte_cells'][0]['version'] = [0, 999]
    renumber(archive)
    refresh(archive)
    result = word_projector()(**archive)
    if mutation == 'same_step':
        assert result['outcome'] == 'passed', result['details']['issues']
    else:
        assert result['outcome'] == 'failed', result['details']['issues']


def _shared_instruction_response_request_edge(archive):
    """Model one native OBI edge that consumes one response and grants the next request."""
    receipts = [r for r in archive['events']
        if r.get('kind') == 'compiled_F6_instruction_fetch_completion']
    first, second = receipts[:2]
    by_id = {r['event_id']: r for r in archive['events']}
    pre = by_id[first['response_pre_event_id']]
    producer = by_id[first['response_producer_event_id']]
    sample = deepcopy(pre['outputs'])
    request_sample = second['request_pre']
    for name in ('i_req_valid', 'i_req_ready', 'i_req_write', 'i_req_addr',
                 'i_req_be', 'i_req_wdata'):
        sample['backend'][name] = request_sample['backend'][name]
    traces = archive['_cpu_artifact'].runtime_document['base_protocol_traces']['traces']
    signals = next(row['signals'] for row in traces
        if row['endpoint_id'] == archive['contract']['cpu']['instruction_endpoint_id'])
    for role in ('req', 'gnt', 'addr'):
        sample['protocol_taps'][signals[role]] = request_sample['protocol_taps'][signals[role]]
    pre['outputs'] = deepcopy(sample)
    producer['outputs']['driver_samples'][0]['pre'] = deepcopy(sample)
    producer['outputs']['instr_req_accepted'] = 1
    producer['outputs']['instr_addr'] = second['address']
    first['response_pre'] = deepcopy(sample)
    second['request_pre'] = deepcopy(sample)
    second['request_scope'] = deepcopy(first['response_scope'])
    second['acceptance_tick'] = first['response_tick']
    second['request_pre_event_id'] = first['response_pre_event_id']
    second['request_producer_event_id'] = first['response_producer_event_id']
    by_id[second['memory_read_event_id']]['producer_event_id'] = first['response_producer_event_id']
    by_id[second['instr_response_event_id']]['acceptance_tick'] = first['response_tick']
    refresh(archive)
    return first, second, pre, producer


@pytest.mark.parametrize('mutation', ['same_edge', 'wrong_key', 'wrong_version', 'wrong_scope', 'wrong_pre'])
def test_saved_instruction_response_and_next_request_share_only_same_edge(edge_archive, mutation):
    archive = _saved_fetch_archive(edge_archive)
    first, second, pre, producer = _shared_instruction_response_request_edge(archive)
    by_id = {row['event_id']: row for row in archive['events']}
    if mutation == 'wrong_key':
        by_id[second['memory_read_event_id']]['transaction']['source_sequence'] = 999
    elif mutation == 'wrong_version':
        by_id[second['memory_read_event_id']]['versions'][0] = [0, 999]
    elif mutation == 'wrong_scope':
        second['request_scope'][1] += 1
    elif mutation == 'wrong_pre':
        pre['outputs']['backend']['i_req_addr'] += 4
    refresh(archive)
    result = edge_projector()(**archive)
    edge = result['details']['edges'][3]
    if mutation == 'same_edge':
        assert edge['outcome'] == 'passed', edge['issues']
    else:
        assert edge['outcome'] == 'failed', edge['issues']


def _first_slot_handover_archive(word_transfer_archive, cpu_obi_artifact):
    from myfuzz.integration.compiled_f6_layout import F6Candidate
    base = deepcopy(word_transfer_archive)
    attempt = base['attempt']
    raw = bytes.fromhex(attempt['raw8_hex'])
    packed = int.from_bytes(raw, 'little')
    candidate = F6Candidate(raw, tuple((packed >> (11*i)) & 2047 for i in range(4)))
    attempt.update(case_id='run:case:1', case_index=1)
    attempt['prefix_hex'] = build_f6_firmware(base['contract']).prefix(candidate, case_index=1).hex()
    archive = _saved_fetch_archive(edge_archive.__wrapped__(base, cpu_obi_artifact))
    archive['binding']['run_id'] = 'run'
    _refresh_edge_binding(archive)
    # Completion declarations pin the binding digest.
    for row in rows(archive, 'compiled_F6_instruction_fetch_completion'):
        row['execution_binding_sha256'] = archive['binding']['binding_sha256']
    receipt = rows(archive, 'compiled_F6_instruction_fetch_completion')[0]
    by_id = {row['event_id']: row for row in archive['events']}
    request_ids = [receipt[name] for name in ('request_pre_event_id', 'request_producer_event_id')]
    attempt = archive['attempt']
    attempt['_runner_event_start'] = max(request_ids)
    attempt['configuration'] = []
    for event_id in request_ids:
        by_id[event_id]['provenance'] = {'observed_case': {'case_id': 'run:case:0', 'case_index': 0}}
    refresh(archive)
    return archive, receipt, by_id


@pytest.mark.parametrize('mutation', ['valid', 'wrong_previous_index', 'wrong_previous_id',
    'nonfirst_address', 'post_cursor', 'boolean_cursor', 'response_root',
    'false_previous_index', 'null_provenance', 'invalid_provenance'])
def test_saved_first_slot_request_handover_is_exact(word_transfer_archive, cpu_obi_artifact, mutation):
    archive, receipt, by_id = _first_slot_handover_archive(word_transfer_archive, cpu_obi_artifact)
    request = by_id[receipt['request_pre_event_id']]
    if mutation == 'wrong_previous_index':
        request['provenance']['observed_case']['case_index'] = -1
    elif mutation == 'wrong_previous_id':
        request['provenance']['observed_case']['case_id'] = 'foreign:case:0'
    elif mutation == 'nonfirst_address':
        second = rows(archive, 'compiled_F6_instruction_fetch_completion')[1]
        for field in ('request_pre_event_id', 'request_producer_event_id'):
            by_id[second[field]]['provenance'] = deepcopy(request['provenance'])
        archive['attempt']['_runner_event_start'] = max(second['request_pre_event_id'], second['request_producer_event_id'])
    elif mutation == 'post_cursor':
        archive['attempt']['_runner_event_start'] = min(receipt['request_pre_event_id'], receipt['request_producer_event_id']) - 1
    elif mutation == 'boolean_cursor':
        archive['attempt']['_runner_event_start'] = True
    elif mutation == 'response_root':
        by_id[receipt['response_pre_event_id']]['provenance'] = deepcopy(request['provenance'])
    elif mutation == 'false_previous_index':
        request['provenance']['observed_case']['case_index'] = False
    elif mutation == 'null_provenance':
        request['provenance'] = None
    elif mutation == 'invalid_provenance':
        request['provenance'] = []
    refresh(archive)
    edge = edge_projector()(**archive)['details']['edges'][3]
    assert edge['outcome'] == ('passed' if mutation == 'valid' else 'failed'), edge['issues']


def test_saved_shared_irq_rebuilds_actual_DMA_dispatch(word_transfer_archive):
    from tests.integration.test_shared_irq_dispatcher import declaration
    word_transfer_archive['contract']['program_contract']['gpio_irq']=declaration()
    archive=_irq_archive(word_transfer_archive)
    result=irq_projector()(**archive)
    assert result['outcome']=='passed',result['details']['issues']


@pytest.mark.parametrize('mutation',['stage_hash','child_address','saved_path','raw_path'])
def test_saved_shared_irq_rejects_diverted_or_relabelled_dispatch(word_transfer_archive,mutation):
    from tests.integration.test_shared_irq_dispatcher import declaration
    word_transfer_archive['contract']['program_contract']['gpio_irq']=declaration()
    archive=_irq_archive(word_transfer_archive)
    returned=rows(archive,'native_f6_isr_return.v1')[0]
    if mutation=='stage_hash':returned['dispatcher_stage_sha256']='0'*64
    elif mutation=='child_address':returned['dma_stage_address']+=4
    elif mutation=='saved_path':returned['dispatcher_retirements'].pop(1)
    else:
        for row in archive['events']:
            if row.get('kind')=='local_tick_sample' and row.get('local_tick')==203:
                row['outputs']['physical']['rvfi_pc_rdata']=declaration()['gpio_handler_address']
    refresh(archive)
    result=irq_projector()(**archive)
    assert result['outcome']=='failed',result['details']['issues']


@pytest.mark.parametrize('mutation',['joint','take','sample_epoch','member_remint'])
def test_saved_shared_irq_requires_bound_unique_DMA_OR_facts(word_transfer_archive,mutation):
    from tests.integration.test_shared_irq_dispatcher import declaration
    word_transfer_archive['contract']['program_contract']['gpio_irq']=declaration()
    archive=_irq_archive(word_transfer_archive)
    frame=next(r for r in archive['events'] if r.get('kind')=='irq_group_delivery' and r['cpu_tick']==201)
    if mutation=='joint':
        frame['members'][1]['value']=1
        frame['active_sources'].append(frame['members'][1]['source_id'])
        frame.update(unique_source=None,attribution_status='joint')
    elif mutation=='take':frame['native_take_event_id']+=1
    elif mutation=='sample_epoch':frame['members'][1]['native_source']['reset_epoch']=1
    else:
        import hashlib
        topology=archive['binding']['runtime_topology']
        topology['irq_delivery_groups'][0]['members'][1]['pulse_width_ticks']=8
        archive['binding']['topology_binding']['topology_sha256']=hashlib.sha256(
            json.dumps(topology,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    refresh(archive)
    result=irq_projector()(**archive)
    assert result['outcome']=='failed',result['details']['issues']
