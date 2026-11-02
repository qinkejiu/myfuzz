"""Installed RAM authority feedback stays historical and outside rewards."""
import pytest

from myfuzz.search.record_feedback import RecordConsumptionFeedback
from tests.scenario.test_classified_feedback import memory, transact


def test_installed_memory_consumption_is_observed_without_live_or_reward_claims():
    runner, cpu = memory()
    feedback = RecordConsumptionFeedback(runner)
    feedback.prepare_case()
    transact(runner, cpu)
    result = feedback.observe_case(case_id='case-a', flow='F3')
    assert len(result['new_historical_records']) == 4
    assert len(result['new_semantic_features']) == 4
    assert result['state_observation'] == 'unknown'
    assert result['reward_eligible'] is False
    assert result['cross_testcase'] == 'unknown'
    assert result['memory_kind'] == 'modeled_host_persistent_memory'
    assert result['source_origin'] == 'unknown'
    assert result['policy_features'] == {}
    assert feedback.snapshot()['case_count'] == 1


def test_write_alone_and_empty_success_do_not_infer_consumption():
    runner, cpu = memory()
    feedback = RecordConsumptionFeedback(runner)
    feedback.prepare_case()
    cpu._serve('data', 1, 0x20000, 90, 15)
    runner._append_external_events('cpu', 1)
    result = feedback.observe_case(case_id='writer', flow='F3')
    assert result['new_historical_records'] == []
    feedback.prepare_case()
    result = feedback.observe_case(case_id='submitted', flow='F1')
    assert result['new_semantic_features'] == []


def test_new_event_ids_and_payload_do_not_create_semantic_novelty():
    runner, cpu = memory()
    feedback = RecordConsumptionFeedback(runner)
    feedback.prepare_case()
    transact(runner, cpu)
    first = feedback.observe_case(case_id='first', flow='F3')
    feedback.prepare_case()
    transact(runner, cpu)
    second = feedback.observe_case(case_id='second', flow='F3')
    assert len(second['new_historical_records']) == 4
    assert second['new_semantic_features'] == []
    assert feedback.snapshot()['semantic_feature_count'] == len(first['new_semantic_features'])


def test_bootstrap_history_and_document_replacement_never_receive_credit():
    runner, cpu = memory()
    transact(runner, cpu)
    feedback = RecordConsumptionFeedback(runner)
    feedback.prepare_case()
    assert feedback.observe_case(case_id='empty', flow='F1')['new_historical_records'] == []
    runner._memory_dependency_consumer = None
    with pytest.raises(ValueError, match='configuration-changed'):
        feedback.prepare_case()


def test_missing_memory_provider_stays_unknown():
    from tests.scenario.test_memory_dependency_runner import wired
    runner, _ = wired()
    feedback = RecordConsumptionFeedback(runner)
    feedback.prepare_case()
    result = feedback.observe_case(case_id='case', flow='F3')
    assert result['provider_status'] == 'not_configured'
    assert result['consumption_observation'] == 'unknown'
    assert result['new_semantic_features'] == []


def test_campaign_queries_feedback_around_actual_submit_and_exports_report():
    from myfuzz.runtime.campaign import run_directed_campaign
    from myfuzz.runtime.flows.storage import StorageFlowBackend
    from tests.runtime.test_persistent_engine import _world, FakePersistentRuntime, raw_of
    from tests.runtime.test_storage_kernel import FakeScenarioSession, directed_case, directed_sequence
    bound, runner, _, _ = _world()
    runtime = FakePersistentRuntime(runner, FakeScenarioSession())
    calls = []
    class Feedback:
        def prepare_case(self):
            calls.append(('prepare', runtime.submit_calls))
        def observe_case(self, *, case_id, flow):
            calls.append(('observe', runtime.submit_calls, case_id, flow))
            return {'state_observation': 'unknown', 'reward_eligible': False}
        def snapshot(self):
            return {'case_count': 1}
    sequence = directed_sequence(directed_case('a', records=(raw_of(1),)),
                                plan_sha256=bound.plan_sha256)
    report = run_directed_campaign(bound_plan=bound,
        backend=StorageFlowBackend(runtime=runtime, flow_id='F4'),
        sequence=sequence, case_feedback=Feedback())
    assert calls == [('prepare', 0), ('observe', 1, 'a', 'F4')]
    assert report['record_consumption_feedback']['cases'][0]['reward_eligible'] is False
    assert report['record_consumption_feedback']['state'] == {'case_count': 1}


def test_f5_can_audit_actual_memory_certificates_without_irq_or_policy_credit():
    runner, cpu = memory()
    feedback = RecordConsumptionFeedback(runner)
    feedback.prepare_case()
    transact(runner, cpu)
    result = feedback.observe_case(case_id='shared-f5', flow='F5')
    assert result['flow_id'] == 'F5'
    assert len(result['new_historical_records']) == 4
    assert all(row['scope'] == 'memory_byte_version' for row in result['new_historical_records'])
    assert result['consumption_observation'] == 'historical_observed'
    assert result['irq_consumption'] == 'unknown'
    assert result['reward_eligible'] is False and result['policy_features'] == {}
    assert result['state_observation'] == result['cross_testcase'] == 'unknown'


def test_f5_without_memory_provider_stays_unknown_and_requires_prepare():
    from tests.scenario.test_memory_dependency_runner import wired
    runner, _ = wired()
    feedback = RecordConsumptionFeedback(runner)
    with pytest.raises(ValueError, match='prepared'):
        feedback.observe_case(case_id='unprepared', flow='F5')
    feedback.prepare_case()
    result = feedback.observe_case(case_id='shared-f5', flow='F5')
    assert result['provider_status'] == 'not_configured'
    assert result['consumption_observation'] == result['irq_consumption'] == 'unknown'
    assert result['new_historical_records'] == result['new_semantic_features'] == []
    assert result['reward_eligible'] is False and result['policy_features'] == {}


def test_f5_actual_irq_certificates_cannot_become_memory_or_irq_consumption_credit():
    from tests.scenario.test_irq_dependency_runner import wired, configure
    from tests.scenario.test_irq_dependency_evidence import events
    runner = wired()
    configure(runner)
    feedback = RecordConsumptionFeedback(runner)
    feedback.prepare_case()
    for event in events(): runner._events.append(event)
    result = feedback.observe_case(case_id='shared-f5', flow='F5')
    assert result['provider_status'] == 'not_configured'
    assert result['consumption_observation'] == result['irq_consumption'] == 'unknown'
    assert result['new_historical_records'] == result['new_semantic_features'] == []
    assert result['reward_eligible'] is False and result['policy_features'] == {}
