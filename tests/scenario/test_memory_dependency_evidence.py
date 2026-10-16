"""Actual host callback tokens retain byte scope; no RTL or CPU origin claim."""
import pytest

from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.memory_commit_authority import MemoryCommitAuthority
from myfuzz.scenario.memory_read_authority import MemoryReadAuthority


def fixture(*, regions=None, **bounds):
    from myfuzz.scenario.memory_dependency_evidence import MemoryDependencyEvidenceConsumer
    memory = PersistentMemory(regions=regions or (MemoryRegion('ram', 0x20000, 4096),),
                              initialization_seed=7, max_initialized_bytes=4096)
    service = MemoryService(memory, TransactionLedger(), include_writer_kinds=True,
                            commit_stream_capacity=16)
    commits = MemoryCommitAuthority(services={'cpu': service})
    reads = MemoryReadAuthority(services={'cpu': service})
    consumer = MemoryDependencyEvidenceConsumer(memory_commit_authority=commits,
        memory_read_authority=reads, runtime_contract_sha256='a' * 64, **bounds)
    return service, commits, reads, consumer


def key(sequence):
    return TransactionKey('execution', 'case', 'cpu', 0, 'data', sequence)


def write(f, sequence=1, *, event_id=1, value=0x11223344, mask=15):
    service, authority, _, consumer = f
    receipt = service.write(key(sequence), 0x20000, value, width_bytes=4, byte_enable=mask)
    token = authority.stage('cpu', service, service.ledger, key(sequence), receipt)
    event, = service.drain_commit_events()
    service.ack_commit_events((event['commit_id'],))
    logged = {**event, 'event_id': event_id, 'component': 'cpu'}
    consumer.consume(logged, commit_token=token)
    return logged


def read(f, sequence=2, *, event_id=2, changes=None, use_token=True):
    service, _, authority, consumer = f
    authority.read('cpu', service, key(sequence), 0x20000, width_bytes=4)
    (token, document), = authority.drain()
    event = {**document, 'event_id': event_id, 'component': 'cpu',
             'kind': 'memory_read_issuance', 'status': 'accepted'}
    event.update(changes or {})
    consumer.consume(event, read_token=token if use_token else None)
    return event


def test_actual_writer_and_snapshot_prove_four_exact_bytes_only():
    f = fixture()
    write(f); read(f)
    report = f[-1].report()
    assert report['counts']['verified'] == 4
    assert report['proof_scope'] == 'historical_host_memory_byte_versions_only'
    rows = report['ledger']['records']['verified']
    assert {r['scope'] for r in rows} == {'memory_byte_version'}
    assert {r['validity'] for r in rows} == {'historical'}
    for cert in report['certificates']:
        assert cert['write_event_id'] == 1 and cert['read_event_id'] == 2
        assert cert['writer_event_id'] == str(key(1))
        assert cert['byte_version'] == [0, 1]
        assert cert['source_origin'] == 'unknown'
    assert report['grants_prerequisites'] is False


def test_partial_write_certifies_enabled_lanes_and_retains_missing_lane_gaps():
    f = fixture()
    write(f, mask=5); read(f)
    report = f[-1].report()
    assert {r['byte_offset'] for r in report['certificates']} == {0, 2}
    assert report['status'] == 'incomplete'


@pytest.mark.parametrize('field,value', [
    ('writer_event_ids', ['fake'] * 4), ('versions', [[0, 2]] * 4),
    ('value', 0), ('generation', True), ('status', 'unknown'),
])
def test_tampered_snapshot_consumes_token_but_never_certifies(field, value):
    f = fixture()
    write(f); read(f, changes={field: value})
    assert f[-1].report()['counts']['verified'] == 0
    assert f[-1].report()['journal_integrity'] is False
    assert f[2].pending_count == 0


def test_accepted_label_and_snapshot_without_actual_token_are_not_authority():
    f = fixture()
    write(f); read(f, use_token=False)
    assert f[-1].report()['counts']['verified'] == 0


def test_same_value_new_write_preserves_distinct_writer_versions():
    f = fixture()
    write(f); read(f)
    write(f, 3, event_id=3); read(f, 4, event_id=4)
    assert {tuple(c['byte_version']) for c in f[-1].report()['certificates']} == {(0, 1), (0, 2)}
    assert f[-1].report()['counts']['verified'] == 8


def test_conflicting_journal_id_preserves_history_and_stops_future_proof():
    f = fixture()
    event = write(f); read(f)
    f[-1].consume({**event, 'annotation': 'changed'})
    write(f, 3, event_id=3); read(f, 4, event_id=4)
    assert f[-1].report()['counts']['verified'] == 4
    assert f[-1].report()['journal_integrity'] is False
    assert f[2].pending_count == 0


def test_writer_eviction_or_expiry_never_uses_same_value_as_proof():
    for bounds in ({'max_writer_versions': 1}, {'max_event_gap': 1}):
        f = fixture(**bounds)
        write(f)
        f[-1].consume({'event_id': 2, 'kind': 'annotation'})
        read(f, event_id=3)
        assert f[-1].report()['counts']['verified'] <= 1
        assert f[-1].report()['status'] == 'incomplete'


def test_reports_are_detached_and_record_capacity_does_not_silently_evict():
    f = fixture(max_records=2)
    write(f); read(f)
    report = f[-1].report()
    assert report['counts']['verified'] == 2
    assert report['status'] == 'incomplete'
    report['certificates'].clear()
    assert len(f[-1].report()['certificates']) == 2


def test_existing_edge_ingest_accepts_private_callback_tokens_separately():
    from myfuzz.scenario.edge_provenance import EdgeProvenanceConsumer
    from myfuzz.scenario.runtime_path_contract import RuntimePathContract
    f = fixture()
    service, commits, reads, _ = f
    edge = EdgeProvenanceConsumer(RuntimePathContract('a' * 64, (), ()))
    configure = getattr(edge, 'configure_memory_events', None)
    assert configure is not None
    configure(memory_commit_authority=commits, memory_read_authority=reads)
    receipt = service.write(key(1), 0x20000, 0x5a, width_bytes=4, byte_enable=1)
    token = commits.stage('cpu', service, service.ledger, key(1), receipt)
    event, = service.drain_commit_events()
    edge.ingest([{**event, 'event_id': 1, 'component': 'cpu'}], memory_commit_token=token)
    reads.read('cpu', service, key(2), 0x20000, width_bytes=4)
    (token, document), = reads.drain()
    edge.ingest([{**document, 'event_id': 2, 'component': 'cpu',
                 'kind': 'memory_read_issuance', 'status': 'accepted'}], memory_read_token=token)
    assert edge.memory_evidence_report()['counts']['verified'] == 1
    with pytest.raises(ValueError):
        configure(memory_commit_authority=commits, memory_read_authority=reads)


def test_edge_memory_configuration_is_startup_only_and_opt_in():
    from myfuzz.scenario.edge_provenance import EdgeProvenanceConsumer
    from myfuzz.scenario.runtime_path_contract import RuntimePathContract
    f = fixture()
    edge = EdgeProvenanceConsumer(RuntimePathContract('a' * 64, (), ()))
    report = getattr(edge, 'memory_evidence_report', None)
    assert report is not None and report()['status'] == 'not_configured'
    edge.ingest([None])
    with pytest.raises(ValueError):
        edge.configure_memory_events(memory_commit_authority=f[1], memory_read_authority=f[2])


def test_partial_overwrite_read_keeps_each_lanes_actual_writer():
    f = fixture()
    write(f)
    write(f, 2, event_id=2, mask=1, value=0x44)
    read(f, 3, event_id=3)
    certs = {c['byte_offset']: c for c in f[-1].report()['certificates']}
    assert certs[0]['write_event_id'] == 2 and certs[0]['byte_version'] == [0, 2]
    assert {certs[lane]['write_event_id'] for lane in (1, 2, 3)} == {1}
    assert f[-1].report()['status'] == 'verified'


def test_cold_memory_generation_does_not_match_retained_previous_writer():
    f = fixture()
    write(f)
    f[0].memory.cold_reset()
    read(f)
    assert f[-1].report()['counts']['verified'] == 0
    assert f[-1].report()['status'] == 'incomplete'


def test_identical_journal_repeat_is_idempotent_without_reissuing_tokens():
    f = fixture()
    event = write(f)
    f[-1].consume(event)
    event = read(f)
    f[-1].consume(event)
    assert f[-1].report()['counts']['verified'] == 4
    assert f[-1].report()['journal_integrity'] is True


def test_gap_or_expired_journal_identity_permanently_blocks_later_proof():
    for changed in ({'event_id': 3, 'kind': 'other'}, {'event_id': 0, 'kind': 'other'}):
        f = fixture(max_event_gap=1)
        write(f)
        f[-1].consume(changed)
        read(f, event_id=4)
        assert f[-1].report()['counts']['verified'] == 0
        assert f[-1].report()['journal_integrity'] is False
        assert f[2].pending_count == 0


def test_same_value_read_without_observed_commit_is_not_a_writer_proof():
    f = fixture()
    f[0].write(key(1), 0x20000, 0x11223344, width_bytes=4, byte_enable=15)
    read(f, event_id=1)
    assert f[-1].report()['counts']['verified'] == 0
    assert f[-1].report()['status'] == 'incomplete'


@pytest.mark.parametrize('bounds', [dict(max_records=True), dict(max_event_gap=0),
    dict(max_writer_versions=65537), dict(runtime_contract_sha256='invalid')])
def test_invalid_configuration_is_rejected(bounds):
    from myfuzz.scenario.memory_dependency_evidence import MemoryDependencyEvidenceConsumer
    f = fixture()
    configuration = dict(memory_commit_authority=f[1], memory_read_authority=f[2],
                         runtime_contract_sha256='a' * 64)
    configuration.update(bounds)
    with pytest.raises(ValueError):
        MemoryDependencyEvidenceConsumer(**configuration)


def test_different_installed_read_and_write_services_cannot_be_joined():
    from myfuzz.scenario.memory_dependency_evidence import MemoryDependencyEvidenceConsumer
    left, right = fixture(), fixture()
    with pytest.raises(ValueError):
        MemoryDependencyEvidenceConsumer(memory_commit_authority=left[1],
            memory_read_authority=right[2], runtime_contract_sha256='a' * 64)


def test_edge_token_batch_rejected_before_consuming_private_authority():
    from myfuzz.scenario.edge_provenance import EdgeProvenanceConsumer
    from myfuzz.scenario.runtime_path_contract import RuntimePathContract
    f = fixture()
    service, commits, reads, _ = f
    edge = EdgeProvenanceConsumer(RuntimePathContract('a' * 64, (), ()))
    edge.configure_memory_events(memory_commit_authority=commits, memory_read_authority=reads)
    receipt = service.write(key(1), 0x20000, 0x5a, width_bytes=4, byte_enable=1)
    token = commits.stage('cpu', service, service.ledger, key(1), receipt)
    event, = service.drain_commit_events()
    events = [{**event, 'event_id': 1, 'component': 'cpu'}, {'event_id': 2, 'kind': 'other'}]
    with pytest.raises(ValueError): edge.ingest(events, memory_commit_token=token)
    assert commits.pending_count == 1
    edge.ingest(events[:1], memory_commit_token=token)
    assert commits.pending_count == 0


@pytest.mark.parametrize('role', ['writer', 'reader'])
def test_actual_authority_cannot_enroll_unbounded_transaction_details(role):
    from dataclasses import replace
    f = fixture()
    service, commits, reads, consumer = f
    oversized = replace(key(1), execution_id='x' * 10000)
    if role == 'writer':
        receipt = service.write(oversized, 0x20000, 0x5a, width_bytes=4, byte_enable=1)
        token = commits.stage('cpu', service, service.ledger, oversized, receipt)
        event, = service.drain_commit_events()
        consumer.consume({**event, 'event_id': 1, 'component': 'cpu'}, commit_token=token)
        assert consumer.report()['retained_writer_versions'] == 0
    else:
        write(f)
        reads.read('cpu', service, oversized, 0x20000, width_bytes=4)
        (token, doc), = reads.drain()
        consumer.consume({**doc, 'event_id': 2, 'component': 'cpu',
                          'kind': 'memory_read_issuance', 'status': 'accepted'}, read_token=token)
    assert consumer.report()['counts']['verified'] == 0
    assert consumer.report()['journal_integrity'] is False


def test_multiple_installed_regions_do_not_consume_history_record_capacity():
    f = fixture(regions=(MemoryRegion('ram', 0x20000, 4096),
                         MemoryRegion('second', 0x30000, 4096)), max_records=1)
    write(f); read(f)
    report = f[-1].report()
    assert len(report['ledger']['records']['declared']) == 2
    assert report['counts']['verified'] == 1
    assert report['status'] == 'incomplete'
