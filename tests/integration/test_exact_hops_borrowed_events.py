"""The runtime copies compact proofs, never exposes borrowed journal fields."""
from types import SimpleNamespace
from unittest.mock import Mock, patch
from myfuzz.integration.compiled_f4 import CompiledF4Runtime
from myfuzz.scenario.runner import ScenarioRunner


def test_f2_runtime_detaches_checker_proof_from_borrowed_events():
    runner = object.__new__(ScenarioRunner)
    runner._events = [{'event_id': 1, 'versions': [[0, 1]]}]
    runner.events_since = Mock(side_effect=AssertionError('public whole-history copy'))
    runner.sessions = {'cpu': SimpleNamespace(memory=SimpleNamespace(read=Mock(return_value=object())))}
    runtime = SimpleNamespace(authority=SimpleNamespace(issue=Mock(return_value=object())), register_f2='PADIN',
        artifacts={'gpio': object()}, target_id='gpio', cpu_id='cpu', runner=runner, cursor=0,
        result=32, records=[], image_f2={'source_id': 'source'}, stream_f2={}, traces_f2={},
        declared_edges_f2=[], error_policy_f2={})
    before = SimpleNamespace(document=lambda: {'reset_epoch': 0})

    def exact(**kwargs):
        assert kwargs['events'][0] is runner._events[0]
        return {'instruction_hops': [{'versions': kwargs['events'][0]['versions']}]}

    with patch('myfuzz.integration.compiled_f2_consumer.check_f2_read_observation',
               return_value=({'joins': [], 'RAM_event': 1}, object())), \
         patch('myfuzz.integration.native_obi_hops.check_f2_exact_hops', side_effect=exact):
        _, _, proof = CompiledF4Runtime._check_chain_f2(runtime, object(), {}, before, [])
    proof['instruction_hops'][0]['versions'][0][1] = 999
    assert runner._events[0]['versions'] == [[0, 1]]


def test_f4_runtime_detaches_checker_proof_from_borrowed_events():
    from myfuzz.integration.compiled_f4 import ROW_GENERIC_APB_STORAGE
    runner = object.__new__(ScenarioRunner)
    runner._events = [{'event_id': 1, 'versions': [[0, 1]]}]
    runner.events_since = Mock(side_effect=AssertionError('public whole-history copy'))
    runner.sessions = {'cpu': SimpleNamespace(memory=SimpleNamespace(read=Mock(return_value=object())))}
    runtime = SimpleNamespace(row=ROW_GENERIC_APB_STORAGE, _issue_register_version=Mock(return_value=object()),
        authority=object(), register_name='DATA', artifacts={'ip': object()}, target_id='ip', cpu_id='cpu',
        runner=runner, cursor=0, records=[], image={'source_id': 'source'}, stream={}, traces={},
        declared_edges=[], error_policy={})

    def exact(**kwargs):
        assert kwargs['events'][0] is runner._events[0]
        return {'instruction_hops': [{'versions': kwargs['events'][0]['versions']}],
                'edges': [], 'data_hops': [],
                'ram_write_hop': {'memory_write_event': 1, 'transaction': {}, 'address': 32, 'value': 0}}

    with patch('myfuzz.integration.compiled_f4.check_storage_observation',
               return_value=({'joins': [], 'RAM_event': 1}, {'tick': 1}, object())), \
         patch('myfuzz.integration.compiled_f4.check_f4_exact_hops', side_effect=exact):
        observed, _, _ = CompiledF4Runtime._check_chain(runtime,
            SimpleNamespace(violations=()), {}, {'reset_epoch': 0}, [])
    observed['exact_hops']['instruction_hops'][0]['versions'][0][1] = 999
    assert runner._events[0]['versions'] == [[0, 1]]


def test_exact_borrowing_rejects_replaced_reader():
    import pytest
    from myfuzz.integration.compiled_f4 import _borrow_exact_events
    runner = object.__new__(ScenarioRunner)
    runner._events = []
    runner._event_refs_since = lambda *a, **kw: ()
    with pytest.raises(ValueError, match='reader-drift'):
        _borrow_exact_events(runner)
    del runner._event_refs_since
    with patch.object(ScenarioRunner, '_event_refs_since', lambda *a, **kw: ()):
        with pytest.raises(ValueError, match='reader-drift'):
            _borrow_exact_events(runner)
