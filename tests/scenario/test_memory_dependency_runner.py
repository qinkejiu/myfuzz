"""Actual Runner callback distribution; software fixtures, no RTL claim."""
from pathlib import Path
from types import SimpleNamespace
import pytest

from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from tests.local_harness.test_cpu_session import Target
from tests.scenario.test_uart_native_irq_runner import fixture


def wired():
    runner, _, _ = fixture()
    artifact = SimpleNamespace(
        plan=SimpleNamespace(request=SimpleNamespace(instance_id='cpu')),
        runtime_document={'kind': 'obi_cpu', 'backend_ports': [], 'physical_exports': []})
    cpu = GeneratedCve2Session(artifact, base_dir=Path('.'), cache_dir=Path('/tmp/unused'),
        memory=PersistentMemory(regions=(MemoryRegion('ram', 0x20000, 4096),),
            initialization_seed=5, max_initialized_bytes=4096),
        router=DataflowRouter((DeviceWindow('dummy', 0x40000000, 0x1000, Target()),)),
        memory_commit_receipts=True, memory_readback_receipts=True)
    cpu._case_id = 'cpu-stream'
    cpu.identity_document = lambda: {'fixture': 'actual_memory_callbacks.v1'}
    runner.sessions['cpu'] = cpu
    return runner, cpu


@pytest.mark.parametrize('journal', [False, True])
def test_actual_cpu_callbacks_feed_history_once_and_release_pending(journal):
    runner, cpu = wired()
    if journal:
        runner.enable_event_journal(chunk_size=2)
    runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64)
    runner._events.append({'event_id': 1, 'kind': 'fixture_step'})
    cpu._serve('data', 1, 0x20000, 0x11223344, 15)
    runner._append_external_events('cpu', 1)
    cpu._serve('data', 0, 0x20000, 0, 15)
    runner._append_external_events('cpu', 1)
    report = runner.memory_dependency_evidence_report()
    assert report['counts']['verified'] == 4
    assert report['journal_integrity'] is True
    assert report['grants_prerequisites'] is False
    assert runner._memory_commit_authority.pending_count == 0
    assert runner._memory_read_authority.pending_count == 0
    before = tuple(runner.events)
    runner._append_external_events('cpu', 1)
    assert tuple(runner.events) == before
    assert not any('token' in name for event in runner.events for name in event)


def test_legacy_readback_consumer_receives_same_actual_proof_independently():
    runner, cpu = wired()
    runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64)
    received = []
    def consume(event, *, commit_token=None, read_token=None):
        if commit_token is not None:
            received.append(runner._memory_commit_authority.resolve(commit_token))
        if read_token is not None:
            received.append(runner._memory_read_authority.resolve(read_token))
        return ()
    runner._uart_memory_readback_join = SimpleNamespace(consume=consume)
    cpu._serve('data', 1, 0x20000, 90, 15)
    runner._append_external_events('cpu', 1)
    cpu._serve('data', 0, 0x20000, 0, 15)
    runner._append_external_events('cpu', 1)
    assert len(received) == 2 and all(received)
    assert runner.memory_dependency_evidence_report()['counts']['verified'] == 4
    assert runner._memory_read_authority.pending_count == 0


def test_configuration_is_opt_in_startup_once_and_identity_bound():
    runner, _, _ = fixture()
    assert runner.memory_dependency_evidence_report()['status'] == 'not_configured'
    assert 'memory_dependency_evidence' not in runner.identity_document()
    runner, _ = wired()
    runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64,
        max_records=8, max_writer_versions=32, max_event_gap=64)
    identity = runner.identity_document()['memory_dependency_evidence']
    assert identity['runtime_contract_sha256'] == 'a' * 64
    assert identity['max_records'] == 8 and identity['components'] == ['cpu']
    identity.clear()
    assert runner.identity_document()['memory_dependency_evidence']
    with pytest.raises(ValueError, match='startup'):
        runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64)
    with pytest.raises(ValueError, match='compiled runtime edge index'):
        runner.configure_provenance(None)


def test_incompatible_provenance_commit_services_reject_before_partial_install():
    from tests.scenario.test_memory_dependency_evidence import fixture as evidence_fixture
    from tests.scenario.test_uart_operand_use import scenario
    runner, cpu = wired()
    runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64)
    cpu._native_irq_receipts = True
    runner.sessions['uart'].service = evidence_fixture()[0]
    stream, _ = scenario()
    with pytest.raises(ValueError, match='commit services differ'):
        runner.configure_provenance(stream.index)
    assert not runner.provenance_enabled
    assert runner._uart_consumption_tracker is None


def test_configuration_rejects_missing_actual_stream_and_late_start():
    runner, _ = wired()
    runner.sessions['cpu'].memory_readback_receipts_enabled = False
    with pytest.raises(ValueError):
        runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64)
    runner, _ = wired()
    runner._events.append({'event_id': 1, 'kind': 'fixture_step'})
    with pytest.raises(ValueError, match='startup'):
        runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64)


def test_unchecked_events_also_preserve_contiguous_history():
    runner, cpu = wired()
    runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64)
    runner._events.append_unchecked({'event_id': 1, 'kind': 'capacity_barrier'})
    cpu._serve('data', 1, 0x20000, 90, 15)
    runner._append_external_events('cpu', 1)
    cpu._serve('data', 0, 0x20000, 0, 15)
    runner._append_external_events('cpu', 1)
    assert runner.memory_dependency_evidence_report()['counts']['verified'] == 4


@pytest.mark.parametrize('conflict', ['reserved_name', 'full_registry'])
def test_failed_registration_does_not_partially_install_shared_authorities(conflict):
    from myfuzz.scenario.memory_commit_authority import MemoryCommitAuthority
    from myfuzz.scenario.memory_read_authority import MemoryReadAuthority
    runner, cpu = wired()
    cpu.service.include_writer_kinds = True
    commits = MemoryCommitAuthority(services={'cpu': cpu.service})
    reads = MemoryReadAuthority(services={'cpu': cpu.service})
    if conflict == 'reserved_name':
        reads.register_consumer('dependency_evidence')
    else:
        for i in range(15):
            reads.register_consumer(f'consumer-{i}')
    runner._memory_commit_authority = commits
    runner._memory_read_authority = reads
    before = set(commits._consumers), set(reads._consumers)
    with pytest.raises(ValueError):
        runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64)
    assert (commits._consumers, reads._consumers) == before
    assert cpu.memory_read_authority is None
    assert runner.memory_dependency_evidence_report()['status'] == 'not_configured'


def test_existing_real_uart_store_join_keeps_default_commit_proof():
    from tests.scenario.test_uart_store_memory_runner import wired as legacy_wired
    from dataclasses import asdict
    from myfuzz.scenario.ledger import TransactionKey
    stream, _, service, receipt, runner = legacy_wired()
    runner.sessions['cpu'].memory_readback_receipts_enabled = True
    original = runner._memory_commit_authority
    runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64)
    assert runner._memory_commit_authority is original
    runner._append_external_events('cpu', 1)
    for event in stream.events:
        runner._append_uart_store_memory_join(event)
    assert any(e.get('kind') == 'uart_store_memory_match' and e.get('status') == 'accepted'
               for e in runner.events)
    read_key = TransactionKey(**{**asdict(receipt.transaction_id),
                                'source_sequence': receipt.transaction_id.source_sequence + 1})
    runner._memory_read_authority.read('cpu', service, read_key, 0x20000, width_bytes=4)
    runner._append_external_events('cpu', 1)
    assert runner.memory_dependency_evidence_report()['counts']['verified'] == 4
    assert original.pending_count == runner._memory_read_authority.pending_count == 0


def test_legacy_ram_join_still_stages_actual_receipt_before_ack():
    from tests.scenario.test_uart_ram_commit_runner import wired_fixture, feed_raw
    stream, _, service, _, _, runner = wired_fixture()
    runner.sessions['cpu'].memory_readback_receipts_enabled = True
    runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64)
    runner._append_external_events('cpu', 1)
    feed_raw(runner, stream)
    assert any(e.get('kind') == 'uart_ram_commit_join' and e.get('status') == 'accepted'
               for e in runner.events)
    assert service.pending_commit_count == 0


def test_saved_commit_document_never_obtains_live_runner_token():
    runner, cpu = wired()
    runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64)
    cpu._serve('data', 1, 0x20000, 90, 15)
    saved = cpu.service.drain_commit_events()[0]
    cpu.service.ack_commit_events((saved['commit_id'],))
    cpu.service.events.append(saved)
    runner._append_external_events('cpu', 1)
    cpu._serve('data', 0, 0x20000, 0, 15)
    runner._append_external_events('cpu', 1)
    assert runner.memory_dependency_evidence_report()['counts']['verified'] == 0
    assert runner.memory_dependency_evidence_report()['journal_integrity'] is False


def test_startup_does_not_replace_a_separately_installed_read_authority():
    from myfuzz.scenario.memory_read_authority import MemoryReadAuthority
    runner, cpu = wired()
    cpu.service.include_writer_kinds = True
    installed = MemoryReadAuthority(services={'cpu': cpu.service})
    cpu.memory_read_authority = installed
    cpu._serve('data', 0, 0x20000, 0, 15)
    with pytest.raises(ValueError, match='installed'):
        runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64)
    assert cpu.memory_read_authority is installed and installed.pending_count == 1


def test_other_pending_view_never_causes_runner_to_relog_read_issuance():
    from myfuzz.scenario.memory_commit_authority import MemoryCommitAuthority
    from myfuzz.scenario.memory_read_authority import MemoryReadAuthority
    runner, cpu = wired()
    cpu.service.include_writer_kinds = True
    commits = MemoryCommitAuthority(services={'cpu': cpu.service})
    reads = MemoryReadAuthority(services={'cpu': cpu.service})
    for authority in (commits, reads):
        authority.register_consumer('other')
    runner._memory_commit_authority = commits
    runner._memory_read_authority = reads
    runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64)
    cpu._serve('data', 1, 0x20000, 90, 15)
    runner._append_external_events('cpu', 1)
    cpu._serve('data', 0, 0x20000, 0, 15)
    runner._append_external_events('cpu', 1)
    assert commits.pending_count == reads.pending_count == 1
    before = tuple(runner.events)
    runner._append_external_events('cpu', 1)
    assert tuple(runner.events) == before
    assert runner.memory_dependency_evidence_report()['journal_integrity'] is True
    token, _ = reads.drain()[0]
    assert reads.resolve(token, consumer='other') and reads.pending_count == 0
    assert commits.resolve(next(iter(commits._pending)), consumer='other')


def test_normal_provenance_startup_reuses_real_readback_authorities():
    from tests.scenario.test_uart_operand_use import scenario
    stream, _ = scenario()
    runner, cpu = wired()
    cpu._native_irq_receipts = True
    runner.configure_provenance(stream.index)
    commits, reads = runner._memory_commit_authority, runner._memory_read_authority
    assert runner._uart_memory_readback_join is not None
    runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64)
    assert runner._memory_commit_authority is commits and runner._memory_read_authority is reads
    cpu._serve('data', 1, 0x20000, 90, 15)
    runner._append_external_events('cpu', 1)
    cpu._serve('data', 0, 0x20000, 0, 15)
    runner._append_external_events('cpu', 1)
    assert runner.memory_dependency_evidence_report()['counts']['verified'] == 4
    assert commits.pending_count == reads.pending_count == 0
