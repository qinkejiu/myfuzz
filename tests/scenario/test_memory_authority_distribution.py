"""One actual callback, bounded independent consumers, no reissued effects."""
import pytest
from tests.scenario.test_memory_commit_authority import setup, write, stage, key as write_key
from tests.scenario.test_memory_read_authority import fixture, key


@pytest.fixture(params=['write', 'read'])
def issuance(request):
    if request.param == 'write':
        service, authority = setup(max_pending=1)
        issue = lambda: stage(authority, service, write(service))
    else:
        service, authority = fixture(capacity=1)
        def issue():
            authority.read('cpu', service, key(), 0x20000, width_bytes=4)
            return authority.drain()[0][0]
    return service, authority, issue


@pytest.mark.parametrize('first', ['default', 'dependency_evidence'])
def test_actual_callback_distributed_once_per_registered_consumer(issuance, first):
    service, authority, issue = issuance
    authority.register_consumer('dependency_evidence')
    token = issue()
    events = len(service.events)
    proof = authority.resolve(token, consumer=first)
    assert proof and authority.pending_count == 1
    assert authority.resolve(token, consumer=first) is None
    assert authority.resolve(token, consumer='unregistered') is None
    other = 'default' if first != 'default' else 'dependency_evidence'
    proof.clear()
    assert authority.resolve(token, consumer=other)
    assert authority.pending_count == 0 and len(service.events) == events


def test_registration_frozen_after_actual_issuance(issuance):
    _, authority, issue = issuance
    token = issue()
    authority.resolve(token)
    with pytest.raises(ValueError, match='startup'):
        authority.register_consumer('late')


def test_consumer_registration_bounded_and_unique(issuance):
    _, authority, _ = issuance
    for bad in ('', ' ', 'x' * 65, None, [], 'default'):
        with pytest.raises(ValueError):
            authority.register_consumer(bad)
    for i in range(15):
        authority.register_consumer(f'consumer-{i}')
    with pytest.raises(ValueError, match='capacity'):
        authority.register_consumer('overflow')


def test_degradation_consumes_each_view_without_exporting_proof(issuance):
    _, authority, issue = issuance
    authority.register_consumer('dependency_evidence')
    token = issue()
    authority._bad = True
    assert authority.resolve(token) is None and authority.pending_count == 1
    assert authority.resolve(token, consumer='dependency_evidence') is None
    assert authority.pending_count == 0


def test_memory_history_uses_its_view_without_stealing_legacy_proof():
    from myfuzz.scenario.memory_read_authority import MemoryReadAuthority
    from myfuzz.scenario.memory_dependency_evidence import MemoryDependencyEvidenceConsumer
    service, commits = setup()
    service.include_writer_kinds = True
    reads = MemoryReadAuthority(services={'cpu': service})
    for authority in (commits, reads):
        authority.register_consumer('dependency_evidence')
    consumer = MemoryDependencyEvidenceConsumer(memory_commit_authority=commits,
        memory_read_authority=reads, runtime_contract_sha256='a' * 64,
        authority_consumer='dependency_evidence')
    receipt = write(service)
    issued = service.drain_commit_events()[0]
    token = stage(commits, service, receipt)
    consumer.consume({**issued, 'event_id': 1, 'component': 'cpu'}, commit_token=token)
    assert commits.resolve(token)
    reads.read('cpu', service, write_key(2), 0x20000, width_bytes=4)
    token, issued = reads.drain()[0]
    consumer.consume({**issued, 'event_id': 2, 'component': 'cpu',
                      'kind': 'memory_read_issuance', 'status': 'accepted'}, read_token=token)
    assert reads.resolve(token)
    assert consumer.report()['counts']['verified'] == 4


def test_history_rejects_unregistered_consumer_before_issuance():
    from myfuzz.scenario.memory_read_authority import MemoryReadAuthority
    from myfuzz.scenario.memory_dependency_evidence import MemoryDependencyEvidenceConsumer
    service, commits = setup()
    service.include_writer_kinds = True
    reads = MemoryReadAuthority(services={'cpu': service})
    with pytest.raises(ValueError, match='consumer'):
        MemoryDependencyEvidenceConsumer(memory_commit_authority=commits,
            memory_read_authority=reads, runtime_contract_sha256='a' * 64,
            authority_consumer='unregistered')
