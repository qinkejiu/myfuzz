from copy import deepcopy

import pytest

from myfuzz.scenario.dependency_candidates import (
    CandidateSignal, CandidateRelation, DependencyCandidateConsumer)
from myfuzz.scenario.ip_base_coverage import IpBaseCoverageConsumer
from myfuzz.scenario.ip_base_events import IpBaseEventNormalizer


def signal(node, *, instance=None, direction='output'):
    return CandidateSignal(node_id=node, component_id='opaque', instance_id=instance or node,
                           endpoint_id='pins', role='bit', physical_port='pin',
                           direction=direction, bit_lo=2, width=1)


def event(node, event_id, *, value=1, epoch=0, **changes):
    row = dict(schema_version='ip_base_event.v1', event_type='port_sample',
               event_id=event_id, local_event_id=f'{node}:{event_id}',
               component_id='opaque', instance_id=node, endpoint_id='pins',
               role='bit', direction='input' if node == 'b' else 'output',
               physical_port='pin', bit_lo=2, tick=event_id, reset_epoch=epoch,
               raw_event_refs=[event_id - 1], payload={'value': value, 'width': 1})
    row.update(changes)
    return row


def consumer(**kwargs):
    return DependencyCandidateConsumer(
        signals=(signal('a'), signal('b', direction='input')),
        relations=(CandidateRelation('pair', 'a', 'b', 'direct_binding'),),
        coverage_features=('response:pins:ok',),
        base_coverage=IpBaseCoverageConsumer(component_id='opaque', instance_id='b',
                                            endpoint_protocols={'pins': 'apb3'}), **kwargs)


def test_actual_value_and_receipt_correlation_remains_candidate_and_raw_unchanged():
    c = consumer()
    rows = [event('a', 2), event('b', 4)]
    before = deepcopy(rows)
    candidates = c.consume(rows, start_cursor=0)
    assert len(candidates) == 1
    row = candidates[0]
    assert row.evidence_type == 'candidate' and row.scope == 'event_correlation'
    assert row.evidence_refs == ('base:a:2', 'base:b:4')
    assert row.epochs == (('a', 0), ('b', 0))
    assert rows == before
    doc = c.snapshot()
    assert doc['proof_scope'] == 'exploration_suggestions_only'
    assert doc['feature_counts'] == {'pair:value_match': 1}
    assert doc['candidate_records'] == [row.document()]
    assert c.consume(rows, start_cursor=0) == ()
    assert c.snapshot() == doc


def test_production_base_normalizer_records_feed_discovery_without_plugins():
    journal = []
    for instance, direction in (('a', 'output'), ('b', 'input')):
        normalizer = IpBaseEventNormalizer(component_id='opaque', instance_id=instance,
            endpoint_clock_domains={'pins': 'clk'}, physical_exports=(
                dict(endpoint_id='pins', role='bit', physical_port='pin', runtime_name='rt_pin',
                     direction=direction, bit_lo=2, bit_hi=2, width=1),))
        raw = dict(kind='local_tick_sample', event_id=len(journal) + 1,
                   component=instance, local_tick=1, phase='pre',
                   outputs={'physical': {'rt_pin': 1}})
        journal.append(raw)
        for row in normalizer.consume_local_tick(raw, reset_epoch=0):
            journal.append({**row, 'event_id': len(journal) + 1, 'kind': row['event_type']})
    before = deepcopy(journal)
    candidates = consumer().consume(journal, start_cursor=0)
    assert len(candidates) == 1 and candidates[0].evidence_type == 'candidate'
    assert journal == before


def test_time_order_and_coverage_context_never_grant_proof_or_change_topology():
    c = consumer()
    c.consume([event('a', 2)], start_cursor=0)
    produced = c.consume([event('b', 3, event_type='transaction_response', payload={'error': False}),
                          event('b', 4, value=0)], start_cursor=1)
    assert len(produced) == 2
    assert {r.rule_id for r in produced} == {
        'receipt_window', 'coverage_context:response:pins:ok'}
    assert all(r.evidence_type == 'candidate' for r in produced)
    coverage_row = next(r for r in produced if r.rule_id.startswith('coverage_context'))
    assert 'journal:1' in coverage_row.evidence_refs
    assert not hasattr(c, 'runner') and not hasattr(c, 'satisfies_prerequisite')
    assert c.snapshot()['feature_capacity'] == 3


def test_multi_instance_coverage_context_keeps_feature_and_raw_reference_identity():
    bases = tuple(IpBaseCoverageConsumer(component_id='opaque', instance_id=instance,
        endpoint_protocols={'pins': 'apb3'}) for instance in ('a', 'b'))
    features = ('["opaque","a","response:pins:ok"]', '["opaque","b","response:pins:ok"]')
    c = DependencyCandidateConsumer(signals=(signal('a'), signal('b', direction='input')),
        relations=(CandidateRelation('pair', 'a', 'b', 'direct_binding'),),
        coverage_features=features, base_coverage=bases)
    rows = [event('a', 2),
        event('b', 3, event_type='transaction_response', payload={'error': False}), event('b', 4)]
    produced = c.consume(rows, start_cursor=0)
    contextual = [row for row in produced if row.rule_id.startswith('coverage_context:')]
    assert len(contextual) == 1
    assert contextual[0].rule_id == 'coverage_context:' + features[1]
    assert 'journal:1' in contextual[0].evidence_refs
    assert all(base.cursor == c.cursor == 3 for base in bases)
    assert c.consume(rows, start_cursor=0) == ()


def test_duplicate_coverage_instance_is_refused():
    bases = tuple(IpBaseCoverageConsumer(component_id='opaque', instance_id='b',
        endpoint_protocols={'pins': 'apb3'}) for _ in range(2))
    with pytest.raises(ValueError, match='coverage'):
        DependencyCandidateConsumer(signals=(signal('a'), signal('b', direction='input')),
            relations=(CandidateRelation('pair', 'a', 'b', 'direct_binding'),), base_coverage=bases)


@pytest.mark.parametrize('changes', (
    {'role': 'different'}, {'bit_lo': 0}, {'direction': 'output'},
    {'component_id': 'other'}, {'reset_epoch': True}, {'raw_event_refs': []},
    {'reset_epoch': 1 << 64}, {'local_event_id': 'a' * 1024},
    {'local_event_id': 'a:2'},
    {'raw_event_refs': [True]}, {'payload': {'value': 2, 'width': 1}},
    {'payload': {'value': True, 'width': 1}}, {'event_type': 'completion'},
))
def test_missing_or_wrong_actual_slice_does_not_suggest(changes):
    c = consumer()
    c.consume([event('a', 2)], start_cursor=0)
    assert c.consume([event('b', 4, **changes)], start_cursor=1) == ()
    assert c.snapshot()['candidate_records'] == []


def test_epoch_change_expiry_and_eviction_do_not_recreate_novelty():
    c = consumer(max_event_gap=1)
    assert c.consume([event('a', 2), {}, event('b', 4)], start_cursor=0) == ()
    c.consume([event('a', 6), event('b', 8)], start_cursor=3)
    assert c.snapshot()['feature_counts'] == {'pair:value_match': 1}
    # Reset of the source invalidates its pending observed value. A later
    # target sample cannot correlate against the source's old epoch.
    c.consume([dict(event('a', 10, epoch=1), event_type='reset_observation'),
               event('b', 12)], start_cursor=5)
    c.consume([event('a', 14, epoch=1), event('b', 16)], start_cursor=7)
    assert c.snapshot()['feature_counts'] == {'pair:value_match': 1}
    assert len(c.snapshot()['candidate_records']) == 1


def test_capacity_and_saturated_counts_preserve_finite_session_feature_set():
    signals = tuple(signal(n) for n in ('a', 'c')) + (signal('b', direction='input'),)
    c = DependencyCandidateConsumer(signals=signals,
        relations=(CandidateRelation('ab', 'a', 'b', 'direct_binding'),
                   CandidateRelation('cb', 'c', 'b', 'direct_binding')),
        max_pending=1, max_records=1, counter_cap=2)
    c.consume([event('a', 2), event('c', 4), event('b', 6)], start_cursor=0)
    assert c.snapshot()['feature_counts'] == {'cb:value_match': 1}
    assert c.snapshot()['diagnostics']['pending_eviction'] == 1
    for i in range(4):
        c.consume([event('a', 10 + 4 * i), event('b', 12 + 4 * i)], start_cursor=c.cursor)
    doc = c.snapshot()
    assert len(doc['candidate_records']) == 1
    assert len(doc['feature_counts']) <= doc['feature_capacity'] == 4
    assert doc['pending_count'] <= 1 and doc['diagnostics']['record_limit'] <= 2
    doc['candidate_records'].clear()
    assert len(c.snapshot()['candidate_records']) == 1


def test_future_cursor_and_undeclared_coverage_features_fail_closed():
    c = consumer()
    before = c.snapshot()
    with pytest.raises(ValueError, match='cursor'):
        c.consume([], start_cursor=1)
    with pytest.raises(ValueError, match='coverage'):
        c.consume([], start_cursor=0, new_base_features=('unknown',))
    assert c.snapshot() == before


def test_caller_cannot_invent_a_known_base_coverage_change():
    c = consumer()
    c.consume([event('a', 2)], start_cursor=0)
    with pytest.raises(ValueError, match='coverage'):
        c.consume([event('b', 4)], start_cursor=1, new_base_features=('response:pins:ok',))


@pytest.mark.parametrize('changes', ({'reset_epoch': 1 << 64}, {'raw_event_refs': []},
                                    {'raw_event_refs': [True]}, {'local_event_id': ''},
                                    {'event_id': True}, {'tick': True}))
def test_malformed_protocol_row_cannot_seed_coverage_context(changes):
    c = consumer()
    malformed = event('b', 3, event_type='transaction_response', payload={'error': False})
    malformed.update(changes)
    produced = c.consume([event('a', 2), malformed, event('b', 4)], start_cursor=0)
    assert len(produced) == 1
    assert produced[0].rule_id == 'value_match'
    assert c.snapshot()['coverage_pending_count'] == 0


@pytest.mark.parametrize('payload', ({'value': 1, 'width': 1},
                                    {'value': 1, 'previous_value': 1, 'width': 1}))
def test_invalid_transition_cannot_produce_candidate_or_update_epoch(payload):
    c = consumer()
    c.consume([event('a', 2)], start_cursor=0)
    assert c.consume([event('b', 3, epoch=99, event_type='signal_change', payload=payload)],
                     start_cursor=1) == ()
    assert len(c.consume([event('b', 4)], start_cursor=2)) == 1


def test_stale_protocol_epoch_cannot_seed_coverage_context():
    c = consumer()
    c.consume([event('b', 2, epoch=1), event('a', 3, epoch=1)], start_cursor=0)
    response = event('b', 4, epoch=0, event_type='transaction_response', payload={'error': False})
    produced = c.consume([response, event('b', 6, epoch=1)], start_cursor=2)
    assert len(produced) == 1 and produced[0].rule_id == 'value_match'
    assert c.snapshot()['coverage_pending_count'] == 0


def test_wrong_component_cannot_reset_pending_by_claiming_an_instance():
    c = consumer()
    c.consume([event('a', 2)], start_cursor=0)
    c.consume([event('a', 3, epoch=99, component_id='other', event_type='reset_observation')],
              start_cursor=1)
    assert len(c.consume([event('b', 4)], start_cursor=2)) == 1


@pytest.mark.parametrize('changes', ({'event_type': 'magic'},
                                    {'payload': {'value': 2, 'width': 1}},
                                    {'bit_lo': 0}, {'reset_epoch': True}))
def test_invalid_observation_cannot_advance_epoch_or_drop_source(changes):
    c = consumer()
    c.consume([event('a', 2)], start_cursor=0)
    c.consume([event('a', 3, epoch=1, **changes)], start_cursor=1)
    assert len(c.consume([event('b', 4)], start_cursor=2)) == 1
    assert 'reset_invalidated' not in c.snapshot()['diagnostics']


def test_coverage_context_expires_and_does_not_reappear_when_counter_increases():
    c = consumer(max_event_gap=1)
    response = event('b', 2, event_type='transaction_response', payload={'error': False})
    c.consume([response, {}, event('a', 4), event('b', 6)], start_cursor=0)
    assert c.snapshot()['feature_counts'] == {'pair:value_match': 1}
    c.consume([dict(response, event_id=8), event('a', 10), event('b', 12)], start_cursor=4)
    assert c.snapshot()['feature_counts'] == {'pair:value_match': 1}


def test_invalid_coverage_configuration_is_rejected_before_consumption():
    for features in (('missing',), ('f' * 1024,)):
        with pytest.raises(ValueError):
            DependencyCandidateConsumer(signals=(signal('a'), signal('b', direction='input')),
                relations=(CandidateRelation('pair', 'a', 'b', 'direct_binding'),),
                coverage_features=features,
                base_coverage=IpBaseCoverageConsumer(component_id='opaque', instance_id='b',
                                                    endpoint_protocols={'pins': 'apb3'}))


@pytest.mark.parametrize('kwargs', ({'max_pending': True}, {'max_event_gap': 0},
                                   {'max_records': 0}, {'counter_cap': False}))
def test_invalid_resource_bounds_rejected(kwargs):
    with pytest.raises(ValueError):
        consumer(**kwargs)


def test_explicit_subslice_uses_actual_vector_offset_and_keeps_raw_references():
    from dataclasses import replace
    source = replace(signal('a'), bit_lo=10, width=2,
                     observation_bit_lo=8, observation_width=8)
    target = replace(signal('b', direction='input'), bit_lo=3, width=2,
                     observation_bit_lo=0, observation_width=8)
    c = DependencyCandidateConsumer(signals=(source, target),
        relations=(CandidateRelation('slice', 'a', 'b', 'direct_binding'),))
    rows = [event('a', 2, bit_lo=8, value=0b11101100, payload={'value': 0b11101100, 'width': 8}),
            event('b', 4, bit_lo=0, payload={'value': 0b00011000, 'width': 8})]
    before = deepcopy(rows)
    produced = c.consume(rows, start_cursor=0)
    assert len(produced) == 1 and produced[0].rule_id == 'value_match'
    assert produced[0].evidence_refs == ('base:a:2', 'base:b:4')
    assert rows == before


@pytest.mark.parametrize('changes', (
    {'observation_bit_lo': 0}, {'observation_width': 1},
    {'observation_bit_lo': True, 'observation_width': 8},
    {'observation_bit_lo': 3, 'observation_width': 1},
    {'observation_bit_lo': 0, 'observation_width': True},
    {'observation_bit_lo': 65535, 'observation_width': 2},
))
def test_explicit_subslice_requires_complete_exact_containing_envelope(changes):
    from dataclasses import replace
    with pytest.raises(ValueError, match='signal'):
        replace(signal('a'), **changes)


def test_subslice_does_not_accept_wrong_vector_envelope_or_unrelated_bit_change():
    from dataclasses import replace
    source = replace(signal('a'), observation_bit_lo=0, observation_width=8)
    target = signal('b', direction='input')
    c = DependencyCandidateConsumer(signals=(source, target),
        relations=(CandidateRelation('slice', 'a', 'b', 'direct_binding'),))
    assert c.consume([event('a', 2, bit_lo=0, payload={'width': 16, 'value': 4}),
                      event('b', 4)], start_cursor=0) == ()
    # Change of bit 7 leaves the requested bit 2 unchanged; no source receipt.
    assert c.consume([event('a', 6, event_type='signal_change', bit_lo=0,
                          payload={'width': 8, 'value': 128, 'previous_value': 0}),
                      event('b', 8, value=0)], start_cursor=2) == ()
    assert c.snapshot()['pending_count'] == 0


def test_explicit_signal_aliases_share_receipt_without_same_event_correlation():
    from dataclasses import replace
    a = signal('a')
    alias = replace(a, node_id='a_alias')
    b = signal('b', direction='input')
    relations = (CandidateRelation('one', 'a', 'b', 'direct_binding'),
                 CandidateRelation('two', 'a_alias', 'b', 'direct_binding'),
                 CandidateRelation('same_receipt', 'a', 'a_alias', 'causal_order'))
    with pytest.raises(ValueError, match='configuration'):
        DependencyCandidateConsumer(signals=(a, alias, b), relations=relations)
    c = DependencyCandidateConsumer(signals=(a, alias, b), relations=relations,
                                    allow_signal_aliases=True)
    assert c.consume([event('a', 2)], start_cursor=0) == ()
    produced = c.consume([event('b', 4)], start_cursor=1)
    assert {r.source for r in produced} == {'a', 'a_alias'}
    assert all(r.evidence_refs == ('base:a:2', 'base:b:4') for r in produced)
    assert 'same_receipt:value_match' not in c.snapshot()['feature_counts']


@pytest.mark.parametrize('value', (1, 'true', None))
def test_signal_alias_opt_in_is_exact_bool(value):
    with pytest.raises(ValueError, match='alias'):
        consumer(allow_signal_aliases=value)
