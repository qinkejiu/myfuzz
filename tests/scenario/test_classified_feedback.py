"""Actual Runner providers; pure software callbacks and IRQ receipts."""
from copy import deepcopy
import pytest
from myfuzz.scenario.classified_feedback import ClassifiedEvidenceFeedback
from tests.scenario.test_memory_dependency_runner import wired
from tests.scenario.test_irq_dependency_runner import wired as irq_wired, configure
from tests.scenario.test_irq_dependency_evidence import events


def memory():
    runner, cpu = wired()
    runner.configure_memory_dependency_evidence(runtime_contract_sha256='a'*64)
    return runner, cpu


def transact(runner, cpu):
    cpu._serve('data', 1, 0x20000, 90, 15)
    runner._append_external_events('cpu', 1)
    cpu._serve('data', 0, 0x20000, 0, 15)
    runner._append_external_events('cpu', 1)


def test_actual_memory_new_records_are_detached_and_deduplicated():
    runner, cpu = memory(); feedback = ClassifiedEvidenceFeedback(runner)
    feedback.prepare_case(); transact(runner, cpu)
    result = feedback.observe_case()
    verified = result['verified_dependency']
    assert len(verified['new_records']) == 4
    assert verified['counts'] == {'new': 4, 'total': 4}
    assert verified['grants_prerequisites'] is False
    assert result['functional_coverage']['status'] == 'unknown'
    assert result['functional_coverage']['new_features'] == []
    result['verified_dependency']['new_records'].clear()
    assert feedback.observe_case()['verified_dependency']['counts'] == {'new': 0, 'total': 4}
    assert feedback.snapshot()['counts']['verified'] == 4
    assert feedback.snapshot()['functional_coverage']['status'] == 'unknown'


def test_prepare_consumes_history_without_credit_and_eviction_cannot_revive():
    runner, cpu = memory(); transact(runner, cpu)
    feedback = ClassifiedEvidenceFeedback(runner); feedback.prepare_case()
    assert feedback.observe_case()['verified_dependency']['counts'] == {'new': 0, 'total': 0}
    provider = runner._memory_dependency_consumer
    records = deepcopy(provider._ledger._records['verified'])
    provider._ledger._records['verified'].clear()
    feedback.prepare_case()
    provider._ledger._records['verified'].update(records)
    assert feedback.observe_case()['verified_dependency']['new_records'] == []


def test_irq_scopes_are_preserved():
    runner = irq_wired(); configure(runner)
    feedback = ClassifiedEvidenceFeedback(runner); feedback.prepare_case()
    for row in events(): runner._events.append(row)
    records = feedback.observe_case()['verified_dependency']['new_records']
    assert {r['scope'] for r in records} == {'irq_delivery', 'irq_acceptance', 'cpu_retirement'}
    assert all(r['evidence_type'] == 'verified' for r in records)


@pytest.mark.parametrize('bad', [True, 0, 65537, 1.0])
def test_strict_capacity(bad):
    with pytest.raises(ValueError): ClassifiedEvidenceFeedback(memory()[0], max_records=bad)


def test_capacity_exhaustion_is_atomic_and_does_not_evict():
    runner, cpu = memory(); feedback = ClassifiedEvidenceFeedback(runner, max_records=3)
    feedback.prepare_case(); transact(runner, cpu)
    before = feedback.snapshot()
    with pytest.raises(ValueError, match='capacity'): feedback.observe_case()
    assert feedback.snapshot() == before


@pytest.mark.parametrize('bad', ['replacement', 'config_bool', 'record_hash', 'record_epoch_bool', 'candidate_in_verified'])
def test_provider_and_document_drift_rejected(bad):
    runner, cpu = memory(); feedback = ClassifiedEvidenceFeedback(runner)
    feedback.prepare_case(); transact(runner, cpu)
    provider = runner._memory_dependency_consumer
    if bad == 'replacement': runner._memory_dependency_consumer = deepcopy(provider)
    elif bad == 'config_bool': runner._memory_dependency_configuration['max_records'] = True
    else:
        record = next(iter(provider._ledger._records['verified'].values()))
        if bad == 'record_hash': object.__setattr__(record, 'rule_id', '')
        elif bad == 'record_epoch_bool': object.__setattr__(record, 'epochs', (('cpu', True),))
        else: object.__setattr__(record, 'evidence_type', 'candidate')
    with pytest.raises(ValueError): feedback.observe_case()


def test_saved_reports_and_legacy_targets_cannot_supply_proof():
    runner, _ = memory()
    runner.memory_dependency_evidence_report = lambda: {'ledger': {'records': {'verified': [{'fake': True}]}}}
    feedback = ClassifiedEvidenceFeedback(runner)
    assert feedback.observe_case()['verified_dependency']['new_records'] == []
    state = feedback.snapshot(); state['configuration'].clear()
    assert feedback.snapshot()['configuration']


def test_absent_providers_are_explicit_and_late_installation_rejected():
    from tests.scenario.test_uart_native_irq_runner import fixture
    runner = fixture()[0]
    feedback = ClassifiedEvidenceFeedback(runner)
    result = feedback.observe_case()
    assert result['verified_dependency']['provider_statuses'] == dict(memory='not_configured', irq='not_configured')
    runner._irq_dependency_configuration = {'max_records': True}
    with pytest.raises(ValueError): feedback.validate()


def test_boolean_configuration_cannot_alias_provider_integer_bound():
    runner, _ = wired()
    runner.configure_memory_dependency_evidence(runtime_contract_sha256='a'*64, max_records=1)
    runner._memory_dependency_configuration['max_records'] = True
    with pytest.raises(ValueError): ClassifiedEvidenceFeedback(runner).validate()


@pytest.mark.parametrize('kind', ['memory', 'irq'])
@pytest.mark.parametrize('tamper', ['append', 'replace'])
def test_rehashed_ledger_record_requires_actual_certificate_projection(kind, tamper):
    from dataclasses import replace
    if kind == 'memory':
        runner, cpu = memory(); transact(runner, cpu)
        provider = runner._memory_dependency_consumer
    else:
        runner = irq_wired(); configure(runner)
        for row in events(): runner._events.append(row)
        provider = runner._irq_dependency_consumer
    feedback = ClassifiedEvidenceFeedback(runner)
    original = next(iter(provider._ledger._records['verified'].values()))
    forged = replace(original, source='forged.saved.source', declaration_ref=None)
    if tamper == 'replace': provider._ledger._records['verified'].pop(original.evidence_id)
    provider._ledger.append(forged)
    with pytest.raises(ValueError, match='certificate'): feedback.observe_case()


@pytest.mark.parametrize('kind', ['memory', 'irq'])
def test_same_certificate_id_cannot_hide_changed_projection_facts(kind):
    if kind == 'memory':
        runner, cpu = memory(); transact(runner, cpu)
        provider = runner._memory_dependency_consumer
        field = 'generation'
    else:
        runner = irq_wired(); configure(runner)
        for row in events(): runner._events.append(row)
        provider = runner._irq_dependency_consumer
        field = 'source_epoch'
    feedback = ClassifiedEvidenceFeedback(runner)
    provider._certificates[0][field] += 1
    with pytest.raises(ValueError, match='certificate'): feedback.observe_case()
