"""Independent adapter consumes actual Runner providers, without candidates."""
from types import SimpleNamespace

import pytest

from myfuzz.integration.classified_feedback import OnlineClassifiedFeedback
from tests.scenario.test_classified_feedback import memory, transact
from tests.scenario.test_irq_dependency_runner import wired, configure
from tests.scenario.test_irq_dependency_evidence import events


def fixture(kind):
    if kind == 'memory':
        runner, cpu = memory()
        produce = lambda: transact(runner, cpu)
        count = 4
    else:
        runner = wired()
        configure(runner)
        def produce():
            for row in events(): runner._events.append(row)
        count = 3
    executor = SimpleNamespace(online_decoder=object(),
        session=SimpleNamespace(runner=runner), classified_feedback=True,
        _candidate_exploration=None)
    return runner, OnlineClassifiedFeedback(executor), produce, count


@pytest.mark.parametrize('kind', ['memory', 'irq'])
def test_actual_verified_records_are_classified_with_candidate_disabled(kind):
    runner, adapter, produce, count = fixture(kind)
    adapter.prepare_case()
    produce()
    result = adapter.observe_case()
    verified = result['verified_dependency']
    assert verified['counts'] == {'new': count, 'total': count}
    assert all(record['evidence_type'] == 'verified' for record in verified['new_records'])
    if kind == 'irq':
        assert {record['scope'] for record in verified['new_records']} == {
            'irq_delivery', 'irq_acceptance', 'cpu_retirement'}
    assert result['candidate_novelty']['status'] == 'disabled'
    assert result['candidate_novelty']['candidate_energy'] == 0
    assert result['functional_coverage']['status'] == 'unknown'
    assert result['base_coverage']['status'] == 'unknown'
    assert verified['grants_prerequisites'] is False
    adapter.prepare_case()
    assert adapter.observe_case()['verified_dependency']['new_records'] == []
    assert adapter.state()['evidence']['counts']['verified'] == count


@pytest.mark.parametrize('kind', ['memory', 'irq'])
def test_bootstrap_certificates_do_not_receive_case_credit(kind):
    _, adapter, produce, _ = fixture(kind)
    produce()
    adapter.prepare_case()
    verified = adapter.observe_case()['verified_dependency']
    assert verified['new_records'] == []
    assert verified['counts'] == {'new': 0, 'total': 0}


@pytest.mark.parametrize('kind', ['memory', 'irq'])
def test_reset_retains_history_without_recrediting_old_certificates(kind):
    runner, adapter, produce, count = fixture(kind)
    adapter.prepare_case()
    produce()
    assert adapter.observe_case()['verified_dependency']['counts']['new'] == count
    runner._events.append({'event_id': len(runner.events) + 1, 'kind': 'reset_barrier'})
    adapter.prepare_case()
    result = adapter.observe_case()['verified_dependency']
    assert result['counts'] == {'new': 0, 'total': count}
    assert result['new_records'] == []
    assert adapter.state()['evidence']['counts']['verified'] == count
