"""L1 binding certification must resolve measured raw evidence, not annotations."""
from copy import deepcopy

import pytest

from myfuzz.scenario.edge_provenance import EdgeProvenanceConsumer, EdgeEndpoints
from myfuzz.scenario.ip_base_events import IpBaseEventNormalizer
from myfuzz.scenario.runtime_path_contract import RuntimeNode, RuntimeEdgeContract, RuntimePathContract

KEY = (0, 0)


def configurations():
    def export(direction, port, runtime, role):
        return dict(endpoint_id='bus', role=role, physical_port=port,
                    runtime_name=runtime, direction=direction, bit_lo=3,
                    bit_hi=10, width=8, encoding='integer')
    return {
        'a': dict(component_id='opaque_a', instance_id='a0',
                  endpoint_clock_domains={'bus': 'clock_a'},
                  physical_exports=[export('output', 'out', 'tap_out', 'result')]),
        'b': dict(component_id='opaque_b', instance_id='b0',
                  endpoint_clock_domains={'bus': 'clock_b'},
                  physical_exports=[export('input', 'native_pin', 'tap_pin', 'pin')],
                  bound_physical_inputs=[dict(endpoint_id='bus', role='pin',
                     input_name='bus.pin', runtime_name='tap_pin', width=8,
                     producer_ref='a.out')]),
    }


def journal():
    config = configurations()
    source = IpBaseEventNormalizer(**config['a'])
    target = IpBaseEventNormalizer(**config['b'])
    raw_source = dict(event_id=2, kind='local_tick_sample', component='a',
                      local_tick=1, phase='post', reset_epoch=0,
                      observation_schema_version='ip_raw_observation.v1',
                      outputs={'physical': {'tap_out': 0x5a}})
    transport = dict(event_id=3, kind='dataflow_delivery', producer_event_id=2,
                     source=['a', 'out'], target=['b', 'bus.pin'], value=0x5a,
                     source_bit_offset=0, target_bit_offset=0, width=8,
                     target_value=0x5a,
                     edge_candidates=[{'rule_index': 0, 'prerequisite_index': 0}])
    identity = dict(component='b', component_id='opaque_b', instance_id='b0',
                    input_name='bus.pin', endpoint_id='bus', role='pin',
                    physical_port='native_pin', runtime_name='tap_pin',
                    width=8, reset_epoch=0)
    projected = source.project_binding_delivery(event_id=2,
        dataflow_delivery_event_id=3, source_component='a', source_port='out',
        source_tick=1, source_phase='post', source_epoch=0, source_value=0x5a,
        source_bit_offset=0, target=identity, target_value=0x5a,
        target_bit_offset=0, width=8)
    target.register_binding_delivery(event_id=4, source_component='a', source_port='out',
        target_port='bus.pin', target_epoch=0, target_value=0x5a, width=8)
    raw_target = dict(event_id=5, kind='local_tick_sample', component='b',
        local_tick=7, phase='pre', reset_epoch=0,
        observation_schema_version='ip_raw_observation.v1',
        outputs={'physical': {'tap_pin': 0x5a}})
    sample = next(row for row in target.consume_local_tick(raw_target, reset_epoch=0)
                  if row['event_type'] == 'input_sample')
    return [dict(event_id=1, kind='begin'), raw_source, transport,
            dict(projected, event_id=4, kind='binding_delivery'), raw_target,
            dict(sample, event_id=6, kind='input_sample')]


def make_consumer(config=None):
    nodes = (RuntimeNode('a.out', 'a', 'physical', 'out', 0, 8),
             RuntimeNode('b.pin', 'b', 'physical', 'bus.pin', 0, 8))
    contract = RuntimePathContract('a' * 64, nodes,
                                  (RuntimeEdgeContract(*KEY, 'direct_binding'),))
    consumer = EdgeProvenanceConsumer(contract, endpoints={KEY: EdgeEndpoints(*nodes)})
    configure = getattr(consumer, 'configure_base_events', None)
    if configure is not None:
        configure(config or configurations())
    return consumer


def consume(rows, config=None, chunked=False):
    consumer = make_consumer(config)
    if chunked:
        for row in rows:
            consumer.ingest([row])
    else:
        consumer.ingest(rows)
    return consumer.report()['edges'][0]


@pytest.mark.parametrize('chunked', [False, True])
def test_exact_raw_binding_chain_certifies_without_functional_plugin(chunked):
    row = consume(journal(), chunked=chunked)
    assert row['status'] == 'certified'
    assert [hop['event_id'] for hop in row['hops']] == [2, 3, 6]
    assert row['hops'][-1]['delivery_event_id'] == 3
    assert row['hops'][-1]['value'] == 0x5a


@pytest.mark.parametrize('position,path,value', [
    (5, ('raw_event_refs',), [2]),
    (5, ('binding_delivery_event_id',), 3),
    (5, ('payload', 'binding_delivery_event_id'), 3),
    (5, ('payload', 'value'), 0x59),
    (5, ('reset_epoch',), 1),
    (5, ('instance_id',), 'other'),
    (5, ('physical_port',), 'other'),
    (5, ('payload', 'phase'), 'post'),
    (4, ('outputs', 'physical', 'tap_pin'), 0x59),
    (4, ('reset_epoch',), 1),
    (4, ('phase',), 'post'),
    (1, ('outputs', 'physical', 'tap_out'), 0x59),
    (1, ('reset_epoch',), 1),
    (2, ('source',), ['other', 'out']),
    (2, ('width',), 7),
    (2, ('producer_event_id',), 1),
    (3, ('payload', 'target_component_id'), 'other'),
    (3, ('payload', 'source_value'), 0x59),
    (3, ('payload', 'target_reset_epoch'), 1),
])
def test_forged_or_mismatched_evidence_never_certifies(position, path, value):
    rows = journal()
    obj = rows[position]
    for part in path[:-1]:
        obj = obj[part]
    obj[path[-1]] = value
    assert consume(rows)['status'] != 'certified'


def test_missing_raw_epoch_does_not_upgrade_legacy_evidence():
    rows = journal()
    del rows[4]['reset_epoch']
    assert consume(rows)['status'] != 'certified'


def test_source_case_and_target_case_do_not_need_to_match():
    rows = journal()
    rows[1]['case_id'] = 'old_case'
    rows[4]['case_id'] = 'new_case'
    assert consume(rows)['status'] == 'certified'


def test_consistently_forged_target_value_is_not_a_source_delivery():
    rows = journal()
    rows[2]['target_value'] = 0x59
    rows[3]['payload']['target_value'] = 0x59
    rows[4]['outputs']['physical']['tap_pin'] = 0x59
    rows[5]['payload']['value'] = 0x59
    assert consume(rows)['status'] != 'certified'


@pytest.mark.parametrize('kind', ['reset_barrier', 'overwrite', 'same_value_delivery'])
def test_intervening_reset_or_delivery_cannot_revive_old_binding(kind):
    rows = journal()
    inserted = dict(event_id=5, kind='reset_barrier') if kind == 'reset_barrier' else dict(
        rows[2], event_id=5, value=0x59 if kind == 'overwrite' else 0x5a)
    rows.insert(4, inserted)
    rows[5]['event_id'] = 6
    rows[6]['event_id'] = 7
    rows[6]['raw_event_refs'] = [6]
    assert consume(rows)['status'] != 'certified'


@pytest.mark.parametrize('field,value', [('source', None), ('source', 7), ('target', None)])
def test_malformed_transport_endpoint_fails_closed(field, value):
    rows = journal()
    rows[2][field] = value
    assert consume(rows)['status'] != 'certified'


def test_reset_after_raw_receipt_cannot_issue_an_active_certificate():
    rows = journal()
    rows.insert(5, dict(event_id=6, kind='reset_barrier'))
    rows[-1]['event_id'] = 7
    assert consume(rows)['status'] != 'certified'


def test_missing_required_projection_field_is_not_authenticated():
    rows = journal()
    del rows[-1]['transaction_key']
    assert consume(rows)['status'] != 'certified'


def test_caller_mutation_cannot_rewrite_retained_raw_receipt():
    rows = journal()
    rows[1]['outputs']['physical']['tap_out'] = 0x59
    proof = make_consumer()
    proof.ingest(rows[:5])
    rows[1]['outputs']['physical']['tap_out'] = 0x5a
    proof.ingest(rows[5:])
    assert proof.report()['edges'][0]['status'] != 'certified'


def test_conflicting_repeated_raw_id_prevents_new_certification():
    rows = journal()
    proof = make_consumer()
    proof.ingest(rows[:5])
    conflict = deepcopy(rows[1])
    conflict['outputs']['physical']['tap_out'] = 0x59
    proof.ingest([conflict])
    proof.ingest(rows[5:])
    assert proof.report()['edges'][0]['status'] != 'certified'


def test_missing_journal_row_cannot_be_assumed_irrelevant():
    rows = journal()
    rows[-1]['event_id'] = 7
    assert consume(rows)['status'] != 'certified'


def test_frozen_contracts_survive_caller_changes_and_cannot_be_reconfigured():
    config = configurations()
    proof = make_consumer(config)
    config['b']['physical_exports'][0]['runtime_name'] = 'forged'
    proof.ingest(journal())
    assert proof.report()['edges'][0]['status'] == 'certified'
    with pytest.raises(ValueError, match='configured once'):
        proof.configure_base_events(config)


def test_identical_duplicate_is_rejected_but_does_not_rewrite_evidence():
    rows = journal()
    proof = make_consumer()
    proof.ingest(rows[:5])
    proof.ingest([deepcopy(rows[4])])
    proof.ingest(rows[5:])
    assert proof.report()['edges'][0]['status'] == 'certified'
    assert proof.events_rejected == 1


def test_expired_raw_evidence_never_becomes_a_new_certified_witness():
    rows = journal()
    proof = make_consumer()
    proof.max_event_gap = 2
    proof.ingest(rows)
    assert proof.report()['edges'][0]['status'] != 'certified'
