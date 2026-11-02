"""Live adapters preserve their actual case and feedback order."""
from types import SimpleNamespace
import pytest
from myfuzz.search import storage
from myfuzz.search.case_adapter import CaseAdapter, CaseContext
from myfuzz.search.gpio_case_adapter import GpioCaseAdapter


def test_storage_adapter_preserves_lower_journal_submit_feedback_order(monkeypatch):
    calls = []
    decision = SimpleNamespace(id='decision')
    record = {'flow_id': 'F4'}
    runtime = object()
    engine = SimpleNamespace(submit=lambda row: calls.append(('submit', row)) or record)
    credit = SimpleNamespace(observe=lambda *args: calls.append(('settle', args)) or {'status':'pending'})
    monkeypatch.setattr(storage, 'read_current', lambda r: calls.append(('state', r)) or 'live')
    monkeypatch.setattr(storage, 'lower_storage', lambda *args: calls.append(('lower', args)) or {'raw':'55'})
    adapter = storage.StorageCaseAdapter(runtime, engine, 'catalog', 'contexts', 'encoders', credit)
    assert isinstance(adapter, CaseAdapter)
    context = CaseContext('case', on_prepared=lambda row: calls.append(('journal',row)))
    before = adapter.current_state()
    actual = adapter.execute(decision, context)
    after = adapter.current_state()
    feedback = adapter.settle(decision, context, actual, after, {'frontier': ()}, 7)
    assert before == after == 'live'
    assert feedback == {'status':'pending'}
    assert [call[0] for call in calls] == ['state', 'lower', 'journal', 'submit', 'state', 'settle']
    assert calls[-1][1] == ('decision', 'F4', 'live', {'frontier': ()}, 7)


@pytest.mark.parametrize('mode', ['original', 'fresh'])
def test_gpio_adapter_forwards_real_context_and_feedback(mode):
    calls = []
    decision = SimpleNamespace(id='decision')
    assembly = SimpleNamespace(field_state=lambda: calls.append(('state',)) or {'version':1},
        submit=lambda decision, **kwargs: calls.append(('submit', decision, kwargs)) or 'receipt')
    credit = SimpleNamespace(observe=lambda *args: calls.append(('settle', args)) or 'feedback')
    adapter = GpioCaseAdapter(assembly, credit)
    assert isinstance(adapter, CaseAdapter)
    context = CaseContext('gpio-1', deadline_ns=42 if mode == 'original' else None,
                          replay_advance_count=3 if mode == 'fresh' else None)
    assert adapter.current_state() == {'version':1}
    result = adapter.execute(decision, context)
    report = {'relations':['certified']}
    assert adapter.settle(decision, context, result, {'version':1}, report, 17) == 'feedback'
    assert calls[1] == ('submit', decision, {'case_id':'gpio-1', **({'deadline_ns':42} if mode == 'original' else {'replay_advance_count':3})})
    assert calls[2] == ('settle', (decision, 'gpio-1', {'version':1}, report, 17))


def test_storage_prepared_failure_never_submits(monkeypatch):
    submitted = []
    adapter = storage.StorageCaseAdapter(None, SimpleNamespace(submit=lambda row: submitted.append(row)),
                                         None, None, None, None)
    monkeypatch.setattr(storage, 'lower_storage', lambda *args: {'raw':'55'})
    def reject(case):
        raise ValueError('replay mismatch')
    with pytest.raises(ValueError, match='replay mismatch'):
        adapter.execute(object(), CaseContext('case', on_prepared=reject))
    assert submitted == []


def test_gpio_budget_exception_remains_visible():
    def expired(*args, **kwargs):
        raise TimeoutError('R1 search budget expired before admission')
    adapter = GpioCaseAdapter(SimpleNamespace(submit=expired), None)
    with pytest.raises(TimeoutError, match='before admission'):
        adapter.execute(object(), CaseContext('gpio-1', deadline_ns=42))
