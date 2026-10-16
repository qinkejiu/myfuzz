"""Runner journal integration of native IRQ scopes; no fresh RTL claim."""
import pytest
from tests.scenario.test_uart_native_irq_runner import fixture
from tests.scenario.test_uart_operand_use import scenario
from tests.scenario.test_irq_dependency_evidence import events


def wired():
    runner, _, _ = fixture()
    stream, _ = scenario()
    runner.configure_provenance(stream.index)
    return runner


def configure(runner, **bounds):
    runner.configure_irq_dependency_evidence(source_component='uart', target_component='cpu',
        runtime_contract_sha256='a' * 64, **bounds)


@pytest.mark.parametrize('journal', [False, True])
def test_complete_journal_consumes_native_scopes_once(journal):
    runner = wired()
    if journal:
        runner.enable_event_journal(chunk_size=2)
    configure(runner)
    for row in events():
        runner._events.append(row)
    report = runner.irq_dependency_evidence_report()
    assert report['counts'] == dict(irq_delivery=1, irq_acceptance=1, cpu_retirement=1)
    assert report['journal_integrity'] is True and report['grants_prerequisites'] is False
    report['certificates'].clear()
    assert len(runner.irq_dependency_evidence_report()['certificates']) == 3


def test_default_off_and_configuration_in_identity():
    runner = wired()
    assert runner.irq_dependency_evidence_report()['status'] == 'not_configured'
    assert 'irq_dependency_evidence' not in runner.identity_document()
    configure(runner, max_records=8, max_pending=16, max_event_gap=32)
    identity = runner.identity_document()['irq_dependency_evidence']
    assert identity['source_component'] == 'uart' and identity['target_component'] == 'cpu'
    assert identity['max_pending'] == 16 and identity['runtime_contract_sha256'] == 'a' * 64
    identity.clear()
    assert runner.identity_document()['irq_dependency_evidence']
    with pytest.raises(ValueError, match='startup'):
        configure(runner)


@pytest.mark.parametrize('bad', ['no_provenance', 'source', 'target', 'binding'])
def test_requires_installed_native_provider_and_exact_binding(bad):
    runner = wired() if bad != 'no_provenance' else fixture()[0]
    if bad == 'source': runner.sessions['uart'].uart_fifo_observation_enabled = False
    if bad == 'target': runner.sessions['cpu'].native_irq_receipts_enabled = False
    if bad == 'binding': runner.bindings = ()
    with pytest.raises(ValueError):
        configure(runner)
    assert runner.irq_dependency_evidence_report()['status'] == 'not_configured'


def test_unchecked_barrier_is_seen_and_old_pending_take_cannot_retire():
    runner = wired(); configure(runner)
    rows = events()
    for row in rows[:4]: runner._events.append(row)
    runner._events.append_unchecked({'event_id': 5, 'kind': 'reset_barrier'})
    runner._events.append({**rows[4], 'event_id': 6})
    runner._events.append({**rows[5], 'event_id': 7})
    report = runner.irq_dependency_evidence_report()
    assert report['counts'] == dict(irq_delivery=1, irq_acceptance=0, cpu_retirement=0)
    assert report['journal_integrity'] is True


def test_gap_is_not_hidden_by_unrelated_runner_events():
    runner = wired(); configure(runner)
    runner._events.append({'event_id': 2, 'kind': 'fixture_step'})
    assert runner.irq_dependency_evidence_report()['journal_integrity'] is False


def test_runner_routes_actual_native_resource_and_prepares_cpu_sample_reference():
    from copy import deepcopy
    runner = wired(); configure(runner)
    rows = events()
    for row in rows[:2]:
        runner._events.append(deepcopy(row))
        runner._append_native_irq(row)
    sample_id = len(runner.events) + 1
    runner._events.append({'event_id': sample_id, 'kind': 'local_tick_sample',
        'component': 'uart', 'local_tick': 1, 'phase': 'post',
        'outputs': {'uart_rx_watermark': 1}})
    runner._route_observed_outputs('uart', {'uart_rx_watermark': 1}, sample_id, 1, 'post')
    context = runner._native_irq_input_context('cpu', 1)
    assert context is not None
    measured, accepted, retired = deepcopy(rows[3:])
    measured['input_context'] = context
    measured['binding_delivery_event_id'] = context['binding_delivery_event_id']
    measured['source_output_key'] = context['source_output_key']
    runner.sessions['cpu'].cpu_events = [measured, accepted, retired]
    runner._append_external_events('cpu', sample_id)
    report = runner.irq_dependency_evidence_report()
    assert report['counts'] == dict(irq_delivery=1, irq_acceptance=1, cpu_retirement=1)
    assert report['journal_integrity'] is True


@pytest.mark.parametrize('first', ['memory', 'irq'])
def test_ram_and_irq_consumers_share_full_journal_without_stealing_scopes(first):
    from tests.scenario.test_memory_dependency_runner import wired as memory_wired
    runner, cpu = memory_wired()
    cpu._native_irq_receipts = True
    stream, _ = scenario()
    runner.configure_provenance(stream.index)
    def memory(): runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64)
    if first == 'memory': memory(); configure(runner)
    else: configure(runner); memory()
    cpu._serve('data', 1, 0x20000, 90, 15)
    runner._append_external_events('cpu', 1)
    cpu._serve('data', 0, 0x20000, 0, 15)
    runner._append_external_events('cpu', 1)
    for row in events(start=len(runner.events) + 1): runner._events.append(row)
    assert runner.memory_dependency_evidence_report()['counts']['verified'] == 4
    assert runner.irq_dependency_evidence_report()['counts'] == dict(
        irq_delivery=1, irq_acceptance=1, cpu_retirement=1)
    assert runner.memory_dependency_evidence_report()['journal_integrity'] is True
    assert runner.irq_dependency_evidence_report()['journal_integrity'] is True
