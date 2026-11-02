"""Pure tests for the typed fresh-replay normalizer (S4)."""
import pytest

from myfuzz.scenario.replay_normalize import (
    EXECUTION_ROLES, GPIO_DMA_EXECUTION_ROLES, FIELD_RULES,
    FORBIDDEN_REWRITE_SCOPES, IDENTITY_FIELD_NAMES, NORMALIZER_RULES,
    RETAINED_FIELDS, PrefixDivergence, assert_prefix_equal,
    declared_identity_mappings, first_difference, first_difference_normalized,
    first_replay_difference, first_gpio_dma_replay_difference,
    normalize_execution_identities, normalize_gpio_dma_execution_identities,
    normalized_digest)

IDS = {'cpu': 'a' * 32, 'dma': 'b' * 32, 'uart': 'c' * 32, 'runner': 'd' * 32}
FRESH = {'cpu': '1' * 32, 'dma': '2' * 32, 'uart': '3' * 32, 'runner': '4' * 32}


def _ledger(value):
    return "TransactionKey(execution_id='%s', testcase_id='case', source_sequence=7)" % value


def _state_edge(source, target):
    # Real journal state-dependency endpoints are TransactionKey reprs, so the
    # typed rule rewrites their leading execution token and retains the suffix.
    return {'kind': 'state_dependency', 'event_id': 9,
            'producer_event_id': 8, 'edge_kind': 'persist',
            'memory_id': 'ram', 'generation': 1, 'byte_offset': 0,
            'version': 1, 'source': _ledger(source), 'target': _ledger(target)}


def test_declared_rule_table_is_complete_and_disjoint_from_retained_fields():
    assert set(FIELD_RULES) == {field for rule in NORMALIZER_RULES
                                if rule.scope == 'field' for field in rule.fields}
    assert {rule.name for rule in NORMALIZER_RULES} == {
        'execution_value', 'execution_id_value', 'state_edge_endpoint',
        'ledger_writer', 'ledger_writers', 'ledger_pending_before',
        'ledger_pending_after', 'ledger_uncertain', 'provenance_unknown_writers'}
    overlap = set(RETAINED_FIELDS) & set(FIELD_RULES)
    # Writer references are retained except for their leading execution token.
    assert overlap <= {'writer_event_id', 'writer_event_ids'}
    assert all(FIELD_RULES[field].action == 'transaction_execution_prefix'
               for field in overlap)
    for scope in FORBIDDEN_REWRITE_SCOPES:
        assert all(rule.scope != scope for rule in NORMALIZER_RULES)
    # One value-level rule per declared rewrite field: no catch-all regex pass.
    for field, rule in FIELD_RULES.items():
        assert rule.action in ('execution_identity',
                               'transaction_execution_prefix')
        assert field in rule.fields


def test_execution_fields_are_rewritten_only_for_issued_uuids():
    record = {'execution': IDS['cpu'], 'execution_id': IDS['dma'],
              'nested': {'execution_id': IDS['uart']}}
    normalized = normalize_execution_identities(record, IDS)
    assert normalized == {'execution': 'execution:cpu',
                          'execution_id': 'execution:dma',
                          'nested': {'execution_id': 'execution:uart'}}
    unknown = {'execution': 'e' * 32, 'execution_id': 'not-a-uuid'}
    assert normalize_execution_identities(unknown, IDS) == unknown


def test_state_dependency_endpoints_are_rewritten_only_on_a_journal_root_edge():
    edge = _state_edge(IDS['dma'], IDS['cpu'])
    normalized = normalize_execution_identities([edge], IDS)
    assert normalized[0]['source'].startswith(
        "TransactionKey(execution_id='execution:dma', ")
    assert normalized[0]['target'].startswith(
        "TransactionKey(execution_id='execution:cpu', ")
    assert normalized[0]['source'].endswith(
        "testcase_id='case', source_sequence=7)")
    # The same field names and values inside a payload are not an edge.
    nested = {'kind': 'memory_write', 'payload': _state_edge(IDS['dma'], IDS['cpu'])}
    assert normalize_execution_identities([nested], IDS) == [nested]
    # A root record missing the canonical edge fields is not an edge either.
    partial = _state_edge(IDS['dma'], IDS['cpu'])
    partial.pop('generation')
    assert normalize_execution_identities([partial], IDS) == [partial]


def test_ledger_transaction_prefix_is_rewritten_and_suffix_retained():
    record = {'kind': 'memory_write',
              'writer_event_id': _ledger(IDS['uart']),
              'writer_event_ids': [_ledger(IDS['runner'])],
              'pending_before_finalize': [_ledger(IDS['dma'])],
              'pending_after_finalize': [_ledger(IDS['cpu'])],
              'uncertain_transactions': 'not-a-transaction-key'}
    normalized = normalize_execution_identities(record, IDS)
    assert normalized['writer_event_id'].startswith(
        "TransactionKey(execution_id='execution:uart', ")
    assert normalized['writer_event_ids'][0].startswith(
        "TransactionKey(execution_id='execution:runner', ")
    assert normalized['pending_before_finalize'][0].startswith(
        "TransactionKey(execution_id='execution:dma', ")
    assert normalized['pending_after_finalize'][0].startswith(
        "TransactionKey(execution_id='execution:cpu', ")
    # A non-TransactionKey string is never partially rewritten.
    assert normalized['uncertain_transactions'] == 'not-a-transaction-key'
    # A UUID embedded mid-string is not a leading execution token.
    embedded = {'kind': 'memory_write',
                'writer_event_id': 'prefix ' + _ledger(IDS['uart'])}
    assert normalize_execution_identities([embedded], IDS) == [embedded]


def test_provenance_unknown_writer_list_rewrites_only_the_execution_token():
    record = {'kind': 'memory_read', 'provenance': {
        'unknown_writer_ids': [_ledger(IDS['dma']), _ledger(IDS['uart'])],
        'resource': {'writer_event_ids': [_ledger(IDS['runner'])]}}}
    normalized = normalize_execution_identities([record], IDS)
    unknown = normalized[0]['provenance']['unknown_writer_ids']
    assert unknown[0].startswith("TransactionKey(execution_id='execution:dma', ")
    assert unknown[1].startswith("TransactionKey(execution_id='execution:uart', ")
    assert unknown[0].endswith("testcase_id='case', source_sequence=7)")
    # Non-transaction strings and payload bytes survive a fresh comparison.
    payload = {'kind': 'memory_read', 'provenance': {
        'unknown_writer_ids': ['initial-image', 'payload-' + IDS['dma']]}}
    normalized_payload = normalize_execution_identities([payload], IDS)
    assert normalized_payload[0]['provenance']['unknown_writer_ids'] == [
        'initial-image', 'payload-' + IDS['dma']]


@pytest.mark.parametrize('field', RETAINED_FIELDS)
def test_retained_fields_are_never_rewritten(field):
    record = {field: 'value-' + IDS['cpu'], 'execution_id': IDS['cpu']}
    normalized = normalize_execution_identities(record, IDS)
    assert normalized[field] == 'value-' + IDS['cpu']
    assert normalized['execution_id'] == 'execution:cpu'


def test_whole_json_replacement_is_not_a_normalizer_rule():
    # A whole-JSON str.replace of the old execution UUID would also rewrite this
    # payload byte string.  The typed normalizer must leave it intact, so a
    # fresh run that actually differs there is detected instead of washed.
    reference = [{'kind': 'memory_write', 'value': 'payload-' + IDS['cpu'],
                  'tick': 3}]
    actual = [{'kind': 'memory_write', 'value': 'payload-' + FRESH['cpu'],
               'tick': 3}]
    washed_reference = repr(reference).replace(IDS['cpu'], 'EXEC')
    assert washed_reference == repr(actual).replace(FRESH['cpu'], 'EXEC')
    assert normalize_execution_identities(reference, IDS)[0]['value'] == (
        'payload-' + IDS['cpu'])
    difference = first_replay_difference(reference, actual,
        reference_execution_ids=IDS, actual_execution_ids=FRESH)
    assert difference is not None
    assert difference['path'] == [0, 'value']


def test_tampered_tick_byte_and_irq_are_the_first_difference():
    reference = [{'kind': 'uart_tick_observation', 'local_tick': 7},
                 {'kind': 'uart_rdata_access', 'read_value': 0x5A},
                 {'kind': 'dma_edge', 'native_local_tick': 11,
                  'payload': {'observations': {'physical': {'irq': 1}}}}]
    tick = [dict(reference[0], local_tick=8), reference[1], reference[2]]
    assert first_difference(reference, tick, IDS)['path'] == [0, 'local_tick']
    byte = [reference[0], dict(reference[1], read_value=0x5B), reference[2]]
    assert first_difference(reference, byte, IDS)['path'] == [1, 'read_value']
    irq = [reference[0], reference[1],
           {'kind': 'dma_edge', 'native_local_tick': 11,
            'payload': {'observations': {'physical': {'irq': 0}}}}]
    assert first_difference(reference, irq, IDS)['path'] == [
        2, 'payload', 'observations', 'physical', 'irq']


def test_fresh_runs_compare_equal_when_only_execution_identity_differs():
    reference = [{'kind': 'source_injection', 'action_id': 'a',
                  'execution_id': IDS['cpu']},
                 _state_edge(IDS['dma'], IDS['uart']),
                 {'kind': 'memory_write', 'writer_event_id': _ledger(IDS['dma'])}]
    actual = [{'kind': 'source_injection', 'action_id': 'a',
               'execution_id': FRESH['cpu']},
              _state_edge(FRESH['dma'], FRESH['uart']),
              {'kind': 'memory_write', 'writer_event_id': _ledger(FRESH['dma'])}]
    assert first_replay_difference(reference, actual,
        reference_execution_ids=IDS, actual_execution_ids=FRESH) is None
    assert normalized_digest(reference, IDS) == normalized_digest(actual, FRESH)
    # One shared mapping cannot compare two fresh runs: the actual UUIDs are
    # unknown to the reference mapping, so the shared-mapping helper diverges.
    assert first_difference(reference, actual, IDS) is not None
    with pytest.raises(PrefixDivergence):
        assert_prefix_equal(reference, actual, IDS)


def test_first_difference_reports_missing_and_extra_fields_stably():
    left = [{'kind': 'a', 'value': 1}]
    right = [{'kind': 'a', 'value': 1, 'extra': 2}]
    assert first_difference_normalized(left, right)['path'] == [0, 'extra']
    assert first_difference_normalized(right, left)['path'] == [0, 'extra']
    assert first_difference_normalized(left, [])['reason'] == 'length'


def test_execution_ids_must_be_the_four_distinct_native_uuids():
    assert set(EXECUTION_ROLES) == {'cpu', 'dma', 'uart', 'runner'}
    with pytest.raises(ValueError):
        normalize_execution_identities({}, {**IDS, 'cpu': IDS['dma']})
    with pytest.raises(ValueError):
        normalize_execution_identities({}, {'cpu': IDS['cpu']})
    with pytest.raises(ValueError):
        first_replay_difference([], [], reference_execution_ids=IDS,
            actual_execution_ids={'cpu': 'not-hex'})


def test_gpio_dma_normalizer_uses_only_cpu_dma_gpio_and_runner_ids():
    reference_ids = {'cpu': 'a' * 32, 'dma': 'b' * 32,
        'gpio': 'c' * 32, 'runner': 'd' * 32}
    actual_ids = {'cpu': '1' * 32, 'dma': '2' * 32,
        'gpio': '3' * 32, 'runner': '4' * 32}
    reference = [{'kind': 'gpio_apb_access', 'execution_id': reference_ids['gpio'],
        'value': 'payload-' + reference_ids['gpio'],
        'writer_event_id': _ledger(reference_ids['dma'])}]
    actual = [{'kind': 'gpio_apb_access', 'execution_id': actual_ids['gpio'],
        'value': 'payload-' + actual_ids['gpio'],
        'writer_event_id': _ledger(actual_ids['dma'])}]

    assert set(GPIO_DMA_EXECUTION_ROLES) == {'cpu', 'dma', 'gpio', 'runner'}
    assert normalize_gpio_dma_execution_identities(reference,
        reference_ids)[0]['execution_id'] == 'execution:gpio'
    assert first_gpio_dma_replay_difference(reference, actual,
        reference_execution_ids=reference_ids,
        actual_execution_ids=actual_ids)['path'] == [0, 'value']
    reference[0]['value'] = 'same-payload'
    actual[0]['value'] = 'same-payload'
    assert first_gpio_dma_replay_difference(reference, actual,
        reference_execution_ids=reference_ids,
        actual_execution_ids=actual_ids) is None
    edge_reference = {'events': [_state_edge(reference_ids['dma'],
        reference_ids['gpio'])]}
    edge_actual = {'events': [_state_edge(actual_ids['dma'],
        actual_ids['gpio'])]}
    assert first_gpio_dma_replay_difference(edge_reference, edge_actual,
        reference_execution_ids=reference_ids,
        actual_execution_ids=actual_ids) is None
    with pytest.raises(ValueError, match='exactly'):
        normalize_gpio_dma_execution_identities([], IDS)


def test_prefix_divergence_carries_the_first_difference_record():
    with pytest.raises(PrefixDivergence) as caught:
        assert_prefix_equal([{'tick': 1}], [{'tick': 2}], IDS)
    assert caught.value.difference['path'] == [0, 'tick']
    assert caught.value.difference['reference'] == 1
    assert caught.value.difference['actual'] == 2


def _observed(nonce, *, data=0xA5, address=0x400, tick=3, kind='full_axi_accept'):
    return {'kind': kind, 'local_tick': tick,
            'scope': {'execution_id': nonce, 'testcase_id': 'case',
                      'reset_epoch': 0, 'source_component': 'cva6'},
            'payload': {'data': data, 'address': address}}


def test_declared_identity_field_set_comes_from_the_rule_table():
    assert IDENTITY_FIELD_NAMES == ('execution', 'execution_id')
    assert set(IDENTITY_FIELD_NAMES) <= set(FIELD_RULES)


def test_only_the_run_nonce_differs_so_the_mapping_matches():
    # A fresh native process mints a new execution nonce; everything measured
    # (scope metadata, payload data/address, tick, event order) is identical.
    reference = [_observed(IDS['cpu']), _observed(IDS['cpu'], tick=4)]
    actual = [_observed(FRESH['cpu']), _observed(FRESH['cpu'], tick=4)]
    normalization = declared_identity_mappings(reference, actual)
    assert normalization.applied
    assert normalization.fields == ('execution_id',)
    assert normalization.report() == {
        'schema_version': 'typed_replay_normalizer.v1', 'applied': True,
        'fields': ['execution_id'],
        'mapping': 'per_side_own_values_in_first_appearance_order',
        'rewrites': {'reference': 1, 'actual': 1}}
    assert normalization.normalize_reference(reference) == \
        normalization.normalize_actual(actual)
    # Each side is rewritten with its own value, never with one shared mapping:
    # the reference mapping knows nothing about the fresh run's nonce.
    assert normalization.normalize_reference(actual) == actual
    assert normalization.normalize_actual(reference) == reference
    # Retained fields survive verbatim on both sides.
    left = normalization.normalize_reference(reference)
    assert left[0]['payload'] == reference[0]['payload']
    assert left[0]['scope']['testcase_id'] == 'case'


@pytest.mark.parametrize('drift', [
    {'data': 0xA6},            # payload byte
    {'address': 0x404},        # address
    {'tick': 4},               # tick
    {'kind': 'full_axi_accept_extra'},  # event kind
])
def test_undeclared_drift_still_differs_after_the_nonce_is_normalized(drift):
    reference = [_observed(IDS['cpu'])]
    actual = [_observed(FRESH['cpu'], **drift)]
    normalization = declared_identity_mappings(reference, actual)
    assert normalization.fields == ('execution_id',)
    assert normalization.normalize_reference(reference) != \
        normalization.normalize_actual(actual)
    assert first_difference_normalized(
        normalization.normalize_reference(reference),
        normalization.normalize_actual(actual)) is not None


def test_reordered_events_still_differ_after_the_nonce_is_normalized():
    reference = [_observed(IDS['cpu'], tick=3), _observed(IDS['cpu'], tick=4)]
    actual = [_observed(FRESH['cpu'], tick=4), _observed(FRESH['cpu'], tick=3)]
    normalization = declared_identity_mappings(reference, actual)
    difference = first_difference_normalized(
        normalization.normalize_reference(reference),
        normalization.normalize_actual(actual))
    assert difference['path'] == [0, 'local_tick']


def test_a_nonce_shape_disagreement_is_never_paired():
    # Two distinct nonces on one side and one on the other: no positional
    # pairing is invented, so the difference is reported instead of hidden.
    reference = [_observed(IDS['cpu']), _observed(IDS['dma'], tick=4)]
    actual = [_observed(FRESH['cpu']), _observed(FRESH['cpu'], tick=4)]
    normalization = declared_identity_mappings(reference, actual)
    assert not normalization.applied
    assert normalization.fields == ()
    assert normalization.report()['applied'] is False
    assert normalization.normalize_reference(reference) == reference
    assert normalization.normalize_actual(actual) == actual
    assert normalization.normalize_reference(reference) != \
        normalization.normalize_actual(actual)


def test_evidence_without_a_declared_identity_field_is_unchanged():
    # No declared field is present: the mapping is empty and the caller's
    # comparison degenerates to the previous byte-for-byte one.
    reference = [{'kind': 'memory_write', 'value': 0x11, 'local_tick': 2}]
    actual = [{'kind': 'memory_write', 'value': 0x11, 'local_tick': 2}]
    normalization = declared_identity_mappings(reference, actual)
    assert not normalization.applied
    assert normalization.normalize_reference(reference) == reference
    assert normalization.normalize_actual(actual) == actual
    drifted = [{'kind': 'memory_write', 'value': 0x12, 'local_tick': 2}]
    drifted_normalization = declared_identity_mappings(reference, drifted)
    assert not drifted_normalization.applied
    assert (drifted_normalization.normalize_reference(reference)
            != drifted_normalization.normalize_actual(drifted))


def test_the_nonce_mapping_does_not_touch_a_payload_that_embeds_the_nonce():
    # A whole-JSON replacement would rewrite this payload; the declared walker
    # only rewrites the value stored under the declared field name.
    reference = [{'kind': 'memory_write', 'scope': {'execution_id': IDS['cpu']},
                  'value': 'payload-' + IDS['cpu']}]
    actual = [{'kind': 'memory_write', 'scope': {'execution_id': FRESH['cpu']},
               'value': 'payload-' + FRESH['cpu']}]
    normalization = declared_identity_mappings(reference, actual)
    assert normalization.normalize_reference(reference)[0]['value'] == (
        'payload-' + IDS['cpu'])
    assert normalization.normalize_reference(reference) != \
        normalization.normalize_actual(actual)
