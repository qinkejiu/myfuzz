"""RED integration contracts for live host RAM readback opt-in."""
from pathlib import Path
from types import SimpleNamespace

from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_read_authority import MemoryReadAuthority
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from tests.local_harness.test_cpu_session import Target
from tests.scenario.test_uart_native_irq_runner import fixture as runner_fixture
from tests.scenario.test_uart_store_memory_runner import wired as store_runner_fixture
from copy import deepcopy
from myfuzz.scenario.ibex_uart_online import make_ibex_uart_online_bootstrap
from myfuzz.scenario.ibex_pulp_dual_source import _artifact, RVFI_CPU_PROFILE
from myfuzz.scenario.uart_irq_entry import controlled_uart_bootstrap_configuration
from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract


ROOT = Path(__file__).resolve().parents[2]


def test_readback_bootstrap_loads_result_before_current_irq_stores():
    image = make_ibex_uart_online_bootstrap(memory_readback=True).template.initial_images[1]
    words = [int.from_bytes(bytes.fromhex(image.data_hex)[offset:offset + 4], 'little')
             for offset in range(0, len(bytes.fromhex(image.data_hex)), 4)]
    result_load = 0x0002a303  # lw x6, 0(x5)
    uart_read = 0x0180a183  # lw x3, 0x18(x1)
    result_store = 0x0032a023  # sw x3, 0(x5)
    assert words.index(result_load) < words.index(uart_read) < words.index(result_store)
    legacy = make_ibex_uart_online_bootstrap().template.initial_images[1]
    assert result_load not in [int.from_bytes(bytes.fromhex(legacy.data_hex)[offset:offset + 4], 'little')
                               for offset in range(0, len(bytes.fromhex(legacy.data_hex)), 4)]
    configuration = controlled_uart_bootstrap_configuration(
        make_ibex_uart_online_bootstrap(memory_readback=True), component='cpu',
        runtime_artifact=_artifact(RVFI_CPU_PROFILE, 'cpu').runtime_document,
        observation_contract=ibex_irq_receipt_contract())
    assert configuration['state_load_pc'] == 0x1022c
    assert configuration['rdata_load_pc'] == 0x10230
    assert configuration['mret_pc'] == 0x10240


def service():
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x20000, 4096),),
                              initialization_seed=5, max_initialized_bytes=4096)
    return MemoryService(memory, TransactionLedger(), include_writer_kinds=True)


def key(sequence=1):
    return TransactionKey('execution', 'cpu-stream', 'cpu', 0, 'data', sequence)


def test_opted_in_cpu_ram_read_issues_before_data_response():
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x20000, 4096),),
                              initialization_seed=5, max_initialized_bytes=4096)
    artifact = SimpleNamespace(
        plan=SimpleNamespace(request=SimpleNamespace(instance_id='cpu')),
        runtime_document={'kind': 'obi_cpu', 'backend_ports': [], 'physical_exports': []})
    cpu = GeneratedCve2Session(artifact, base_dir=ROOT, cache_dir=ROOT / 'unused',
                               memory=memory, router=DataflowRouter((
                                   DeviceWindow('dummy', 0x40000000, 0x1000, Target()),)),
                               memory_readback_receipts=True)
    cpu._case_id = 'cpu-stream'
    cpu.service.include_writer_kinds = True
    authority = MemoryReadAuthority(services={'cpu': cpu.service})
    cpu.memory_read_authority = authority

    value, error, sequence = cpu._serve('data', 0, 0x20000, 0, 15)

    assert error == 0 and sequence == 1
    assert authority.pending_count == 1
    token, issued = authority.drain()[0]
    assert issued['fullkey']['source_sequence'] == sequence
    assert issued['value'] == value
    assert not [event for event in cpu.cpu_events if event.get('kind') == 'data_response']
    assert authority.resolve(token) == issued


def test_runner_delivers_live_read_token_to_join_before_consumption():
    runner, _, _ = runner_fixture()
    installed = service()
    authority = MemoryReadAuthority(services={'cpu': installed})
    snapshot = authority.read('cpu', installed, key(), 0x20000, width_bytes=4)
    runner.sessions['cpu'].service = installed
    runner.sessions['cpu'].cpu_events = []
    runner._memory_read_authority = authority
    received = []

    def consume(event, *, read_token=None, commit_token=None):
        if event.get('kind') == 'memory_read_issuance':
            assert type(read_token) is int
            assert authority.pending_count == 1
            received.append(authority.resolve(read_token))
        return ()

    runner._uart_memory_readback_join = SimpleNamespace(consume=consume)
    runner._append_external_events('cpu', 1)
    assert len(received) == 1
    assert received[0]['value'] == snapshot.value
    assert authority.pending_count == 0
    assert len([event for event in runner.events
                if event.get('kind') == 'memory_read_issuance']) == 1


def test_runner_stamps_readback_proof_with_current_observation_case():
    runner, _, _ = runner_fixture()
    runner._provenance = SimpleNamespace(observed_case=None, decorate=lambda record: record)
    runner.set_observation_case('later-uart-case', 3)
    runner._uart_memory_readback_join = SimpleNamespace(consume=lambda event, **kwargs: (
        {'kind': 'uart_memory_readback', 'status': 'accepted',
         'load_observed_case': None},))
    runner._append_uart_store_memory_join({'kind': 'cpu_retire', 'event_id': 17})
    proof = runner.events[-1]
    assert proof['load_observed_case'] == {'case_id': 'later-uart-case', 'case_index': 3}


def test_detached_read_issuance_after_token_use_cannot_promote():
    runner, _, _ = runner_fixture()
    installed = service()
    authority = MemoryReadAuthority(services={'cpu': installed})
    authority.read('cpu', installed, key(), 0x20000, width_bytes=4)
    token, issued = authority.drain()[0]
    authority.resolve(token)
    installed.events.append(dict(issued, kind='memory_read_issuance', status='accepted'))
    runner.sessions['cpu'].service = installed
    runner.sessions['cpu'].cpu_events = []
    runner._memory_read_authority = authority
    tokens = []
    def consume(event, *, read_token=None, commit_token=None):
        if event.get('kind') == 'memory_read_issuance':
            tokens.append(read_token)
        return ()
    runner._uart_memory_readback_join = SimpleNamespace(
        consume=consume)
    runner._append_external_events('cpu', 1)
    assert all(token is None for token in tokens)


def test_readback_optin_off_preserves_legacy_store_stream_shape():
    runner, _, _ = runner_fixture()
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x20000, 4096),),
                              initialization_seed=5, max_initialized_bytes=4096)
    installed = MemoryService(memory, TransactionLedger())
    installed.write(key(), 0x20000, 0x5a, width_bytes=4, byte_enable=15)
    runner.sessions['cpu'].service = installed
    runner.sessions['cpu'].cpu_events = []
    runner._append_external_events('cpu', 1)
    assert len([event for event in runner.events if event.get('kind') == 'memory_write']) == 1
    assert not [event for event in runner.events
                if event.get('kind') in ('memory_write_commit', 'memory_read_issuance')]
    assert installed.pending_commit_count == 0


def test_readback_optin_off_keeps_existing_uart_store_certificate():
    stream, _, service, receipt, runner = store_runner_fixture()
    assert getattr(runner, '_uart_memory_readback_join', None) is None
    runner._append_external_events('cpu', 1)
    for raw in stream.events:
        runner._append_uart_store_memory_join(deepcopy(raw))
    store_proofs = [event for event in runner.events
                    if event.get('kind') == 'uart_store_memory_match'
                    and event.get('status') == 'accepted']
    assert len(store_proofs) == 1
    assert store_proofs[0]['commit_id'] == receipt.commit_document()['commit_id']
