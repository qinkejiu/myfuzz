"""Fresh process scopes in real state-dependency references are structural."""
from copy import deepcopy

from myfuzz.integration.dma_uart_rx_runtime import _normalize


def identities(offset=1):
    return {name: f'{offset + index:032x}'
            for index, name in enumerate(('cpu', 'dma', 'uart', 'runner'))}


def transaction(execution, sequence=2):
    return (f"TransactionKey(execution_id='{execution}', "
            "testcase_id='continuous-dma-uart-rx', source_component='dma', "
            f"source_epoch=0, channel_id='dma-memory', source_sequence={sequence})")


def edge(execution):
    return dict(kind='state_dependency', event_id=4823, producer_event_id=4822,
                edge_kind='RAW', memory_id='ram', generation=0,
                byte_offset=77824, version=[0, 1], source=transaction(execution),
                target="TransactionKey(execution_id='local-execution', source_sequence=12)")


def test_fresh_state_dependency_source_scope_is_structural():
    original, fresh = identities(), identities(20)
    assert _normalize([edge(original['dma'])], original) == _normalize([edge(fresh['dma'])], fresh)


def test_state_edge_transaction_suffix_and_data_stay_significant():
    ids = identities()
    baseline = edge(ids['dma'])
    normalized = _normalize([baseline], ids)
    for key, replacement in (('source', transaction(ids['dma'], 3)),
                             ('byte_offset', 77828), ('version', [0, 2]),
                             ('target', transaction(ids['cpu'], 99))):
        changed = deepcopy(baseline); changed[key] = replacement
        assert _normalize([changed], ids) != normalized


def test_nested_or_non_edge_source_strings_are_not_rewritten():
    ids = identities()
    original = edge(ids['dma'])
    records = [dict(kind='custom_payload', source=original['source'], nested=original),
               dict(kind='state_dependency', source=original['source'])]
    assert _normalize(records, ids) == records
    assert _normalize(original, ids) == original


def test_unknown_execution_token_is_not_rewritten():
    ids = identities()
    unknown = edge('f' * 32)
    assert _normalize([unknown], ids) == [unknown]
