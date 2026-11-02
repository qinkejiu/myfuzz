"""The Vexii AXI4 wrapper session and the F1/F3 memory-flow receipt streams.

Synthetic wire only: the real session code (``GeneratedVexiiAxiMmioSession`` on
``GeneratedReducedAxiCpuSession``), the real observer, service, ledger and
authorities run unchanged; only ``command``/``begin_case`` are replaced by a
one-tick driver receipt, exactly like ``tests/integration/test_cpu_axi4.py``.
No RTL is built and no process is started.
"""
from pathlib import Path

import pytest

from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_read_authority import MemoryReadAuthority
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.router import DataflowRouter
from tests.integration.test_cpu_axi4 import (BOOT, Wire, session_artifact,
                                             wrapper_class)

ROOT = Path(__file__).resolve().parents[2]
SCENARIO = ROOT / 'configs/scenarios/compiled-f1-f4-axi4-apb-i2c-vexii'


def make_session(tmp_path, *, router=None, **options):
    memory = PersistentMemory(regions=(MemoryRegion('ram', BOOT, 0x10000),),
                              initialization_seed=0, max_initialized_bytes=0x10000)
    session = wrapper_class()(session_artifact(), base_dir=tmp_path,
                              cache_dir=tmp_path, memory=memory,
                              router=router, **options)
    return session, memory


def identity_without_build(session, monkeypatch):
    """Only the wrapper's own keys: the inherited one needs a real artifact."""
    from myfuzz.local_harness.session import GeneratedLocalSession
    monkeypatch.setattr(GeneratedLocalSession, 'identity_document',
                        lambda self: {'stubbed_inherited_identity': True})
    return session.identity_document()


# ---------------------------------------------------------------------------
# unchanged default: F2/F4 only, no receipt streams at all
# ---------------------------------------------------------------------------

def test_without_the_options_nothing_about_the_session_changes(tmp_path, monkeypatch):
    session, _ = make_session(tmp_path)
    assert type(session.service) is MemoryService
    assert session.service.commit_stream_enabled is False
    assert session.service.include_writer_kinds is False
    assert session.memory_commit_receipts_enabled is False
    assert session.memory_readback_receipts_enabled is False
    assert session.memory_flows_enabled is False
    assert session.memory_read_authority is None
    # The Runner's tick-stream branch must not be reachable at all.
    assert not hasattr(session, 'drain_tick_samples')
    document = identity_without_build(session, monkeypatch)
    for name in ('memory_commit_stream', 'memory_read_issuance',
                 'cpu_physical_tick_stream'):
        assert name not in document
    service = document['online_instruction_service']
    assert service['supported_flows'] == ['F2', 'F4']
    assert set(service['refused_flows']) == {'F1', 'F3'}
    # A data read still goes through the plain service, no authority needed.
    wire = Wire(session, monkeypatch)
    session.begin_case('case')
    wire.plan = {'d_arvalid': 1, 'd_araddr': BOOT + 0x40, 'd_arsize': 2}
    assert session.step_local({})['d_ar_accepted'] == 1
    assert session.service.events[-1]['kind'] == 'memory_read'
    assert session.memory_read_authority is None
    assert session.service.commit_stream_enabled is False


# ---------------------------------------------------------------------------
# F3: a real LSU store is a drainable, authentic commit
# ---------------------------------------------------------------------------

def test_a_data_write_is_a_real_drainable_memory_commit(tmp_path, monkeypatch):
    session, memory = make_session(tmp_path, memory_commit_receipts=True,
                                   memory_readback_receipts=True)
    assert type(session.service) is MemoryService
    assert session.service.commit_stream_enabled is True
    assert session.service.include_writer_kinds is True
    wire = Wire(session, monkeypatch)
    session.begin_case('case')
    address = BOOT + 0x100
    wire.plan = {'d_awvalid': 1, 'd_awaddr': address, 'd_awsize': 2,
                 'd_wvalid': 1, 'd_wdata': 0x1122_3344, 'd_wstrb': 0xf,
                 'd_wlast': 1}
    outputs = session.step_local({})
    assert outputs['d_aw_accepted'] == 1 and outputs['d_w_accepted'] == 1
    # The store really landed in the persistent host memory.
    assert memory.read(address, 4, transaction_id='probe').value == 0x1122_3344
    assert [event['kind'] for event in session.service.events].count(
        'memory_write') == 1
    commits = session.service.drain_commit_events()
    assert len(commits) == 1
    event = commits[0]
    assert event['schema_version'] == 'memory_write_commit.v1'
    assert event['kind'] == 'memory_write_commit'
    assert event['transaction']['channel_id'] == 'data'
    document = event['commit_document']
    assert document['memory_kind'] == 'modeled_host_persistent_memory'
    assert document['byte_offset'] == 0x100 and document['byte_enable'] == 0xf
    cells = document['enabled_byte_cells']
    assert [cell['value'] for cell in cells] == [0x44, 0x33, 0x22, 0x11]
    assert [cell['byte_offset'] for cell in cells] == [0x100, 0x101, 0x102, 0x103]
    assert {cell['writer_kind'] for cell in cells} == {'STORE'}
    # Draining is a detached prefix; release is an exact acknowledged prefix.
    assert session.service.pending_commit_count == 1
    session.service.ack_commit_events((event['commit_id'],))
    assert session.service.pending_commit_count == 0
    assert session.service.drain_commit_events() == ()


def test_the_commit_stream_is_bounded_and_refuses_an_unacked_flood(tmp_path):
    from myfuzz.scenario.ledger import TransactionKey
    session, _ = make_session(tmp_path, memory_commit_receipts=True)
    for index in range(256):
        key = TransactionKey('a' * 32, 'case', 'cpu', 0, 'data', index + 1)
        session.service.write(key, BOOT + 0x100 + index * 4, index,
                              width_bytes=4, byte_enable=15)
    assert session.service.pending_commit_count == 256
    with pytest.raises(RuntimeError, match='capacity exceeded'):
        session.service.write(TransactionKey('a' * 32, 'case', 'cpu', 0, 'data',
                                             257),
                              BOOT + 0x500, 0x5a, width_bytes=4, byte_enable=15)


# ---------------------------------------------------------------------------
# F1: a real LSU read is an authenticated issuance, never a fetch
# ---------------------------------------------------------------------------

def test_a_data_read_uses_the_installed_readback_authority(tmp_path, monkeypatch):
    session, memory = make_session(tmp_path, memory_commit_receipts=True,
                                   memory_readback_receipts=True)
    authority = MemoryReadAuthority(services={'cpu': session.service})
    session.memory_read_authority = authority
    memory.preload(BOOT + 0x200, bytes.fromhex('78563412'))
    wire = Wire(session, monkeypatch)
    session.begin_case('case')
    wire.plan = {'d_arvalid': 1, 'd_araddr': BOOT + 0x200, 'd_arsize': 2}
    assert session.step_local({})['d_ar_accepted'] == 1
    assert authority.pending_count == 1
    wire.plan = {'d_rvalid': 1, 'd_rid': 0, 'd_rdata': 0x1234_5678,
                 'd_rlast': 1, 'd_rresp': 0}
    assert session.step_local({})['d_r_consumed'] == 1
    ((_, record),) = authority.drain()
    assert record['schema_version'] == 'memory_read_authority.v1'
    assert record['proof_scope'] == 'installed_host_memory_read_snapshot'
    assert record['address'] == BOOT + 0x200 and record['value'] == 0x1234_5678
    assert record['data_hex'] == '78563412'
    assert record['fullkey']['channel_id'] == 'data'
    assert len(record['writer_kinds']) == 4
    # A fetch never is an issuance: the instruction face keeps its own path.
    issued_before = len(authority.drain())
    wire.plan = {'i_arvalid': 1, 'i_araddr': BOOT, 'i_arsize': 2}
    assert session.step_local({})['i_ar_accepted'] == 1
    assert len(authority.drain()) == issued_before


def test_a_data_read_without_the_installed_authority_fails_closed(tmp_path,
                                                                 monkeypatch):
    session, _ = make_session(tmp_path, memory_readback_receipts=True)
    wire = Wire(session, monkeypatch)
    session.begin_case('case')
    wire.plan = {'d_arvalid': 1, 'd_araddr': BOOT + 0x40, 'd_arsize': 2}
    with pytest.raises(RuntimeError, match='readback authority is not installed'):
        session.step_local({})


def test_routed_mmio_reads_keep_the_router_path_under_the_same_option(tmp_path,
                                                                    monkeypatch):
    from myfuzz.scenario.router import DeviceWindow
    from types import SimpleNamespace
    router = DataflowRouter((DeviceWindow('peripheral', 0x4000_1000, 0x1000,
                                          SimpleNamespace()),))
    session, _ = make_session(tmp_path, router=router,
                              memory_commit_receipts=True,
                              memory_readback_receipts=True)
    authority = MemoryReadAuthority(services={'cpu': session.service})
    session.memory_read_authority = authority
    wire = Wire(session, monkeypatch)
    session.begin_case('case')
    wire.plan = {'d_arvalid': 1, 'd_araddr': 0x4000_1000, 'd_arsize': 2}
    assert session.step_local({})['d_ar_accepted'] == 1
    # The routed read is the router's, not a host-RAM issuance.
    assert len(router.acceptances) == 1
    assert authority.pending_count == 0


# ---------------------------------------------------------------------------
# the opt-in physical tick stream
# ---------------------------------------------------------------------------

def test_the_physical_tick_stream_is_opt_in_and_keeps_measured_pre_post(
        tmp_path, monkeypatch):
    session, _ = make_session(tmp_path, physical_tick_samples=True)
    assert callable(session.drain_tick_samples)
    wire = Wire(session, monkeypatch)
    session.begin_case('case')
    wire.plan = {'i_arvalid': 1, 'i_araddr': BOOT, 'i_arsize': 2}
    session.step_local({})
    samples = session.drain_tick_samples()
    assert len(samples) == 1
    sample = samples[0]
    assert sample['local_tick'] == 1
    assert set(sample['pre']['backend']) == set(sample['post']['backend'])
    assert sample['pre']['backend']['i_arvalid'] == 1
    assert session.drain_tick_samples() == []
    assert len(session._last_drained_physical_tick_samples) == 1


def test_memory_flow_runs_key_beats_in_the_process_free_scope(tmp_path):
    """Commit/readback evidence digests must be reproducible in a fresh run."""
    session, _ = make_session(tmp_path, memory_commit_receipts=True,
                              memory_readback_receipts=True)
    session._execution, session._case_id = 'a' * 32, 'case'
    key = session._key('d')
    assert key.execution_id == 'local-execution'
    assert key.channel_id == 'data' and key.source_sequence == 1
    assert session.transaction_execution_id == 'local-execution'
    # Without the options the shared session's own nonce-keyed plan is kept.
    plain, _ = make_session(tmp_path)
    plain._execution, plain._case_id = 'b' * 32, 'case'
    legacy = plain._key('i')
    assert legacy.execution_id == 'b' * 32 and legacy.channel_id == 'instr'
    assert plain.transaction_execution_id == 'b' * 32


# ---------------------------------------------------------------------------
# identity, and the runner's real wiring
# ---------------------------------------------------------------------------

def test_the_identity_declares_each_enabled_stream_exactly(tmp_path, monkeypatch):
    session, _ = make_session(tmp_path, memory_commit_receipts=True,
                              memory_readback_receipts=True,
                              physical_tick_samples=True)
    document = identity_without_build(session, monkeypatch)
    assert document['memory_commit_stream'] == {
        'schema_version': 'memory_write_commit_stream.v1', 'capacity': 256}
    assert document['memory_read_issuance'] == {
        'schema_version': 'memory_read_authority.v1', 'capacity': 256}
    assert document['cpu_physical_tick_stream'] == {
        'schema_version': 'cpu_physical_tick_stream.v1', 'capacity': 256,
        'sampling': 'pre_post'}
    assert document['online_instruction_service']['supported_flows'] == [
        'F1', 'F2', 'F3', 'F4']
    assert document['online_instruction_service']['refused_flows'] == {}


def test_half_the_options_still_refuse_f1_f3_by_name(tmp_path, monkeypatch):
    for options in ({'memory_commit_receipts': True},
                    {'memory_readback_receipts': True}):
        session, _ = make_session(tmp_path, **options)
        document = identity_without_build(session, monkeypatch)
        service = document['online_instruction_service']
        assert service['supported_flows'] == ['F2', 'F4']
        assert set(service['refused_flows']) == {'F1', 'F3'}


def runner_session_artifact():
    """The same wired shape, with the artifact digest the Runner re-derives.

    A live ``ScenarioRunner`` admits the session's reduced-AXI observation
    stream, which re-hashes the artifact document minus its digest; the plain
    synthetic artifact has no such digest, so this fixture supplies the real
    self-consistent one (still no RTL, no build).
    """
    from types import SimpleNamespace
    from myfuzz.local_harness.renderer import _sha
    document = dict(kind='reduced_dual_axi_cpu',
                    backend_ports=session_artifact().runtime_document['backend_ports'],
                    physical_exports=[])
    document['artifact_digest'] = _sha(document)
    return SimpleNamespace(runtime_document=document,
                           plan=session_artifact().plan)


def test_the_runner_installs_the_live_read_authority_and_commit_journal(
        tmp_path, monkeypatch):
    from myfuzz.scenario.ibex_pulp_dual_source import install_host_ram_commit_journal
    from myfuzz.scenario.ledger import TransactionKey
    from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
    from myfuzz.scenario.ownership import compile_ownership
    from myfuzz.scenario.runner import ScenarioRunner
    memory = PersistentMemory(regions=(MemoryRegion('ram', BOOT, 0x10000),),
                              initialization_seed=0, max_initialized_bytes=0x10000)
    session = wrapper_class()(runner_session_artifact(), base_dir=tmp_path,
                              cache_dir=tmp_path, memory=memory, router=None,
                              memory_commit_receipts=True,
                              memory_readback_receipts=True)
    runner = ScenarioRunner(sessions={'cpu': session},
                            ownership=compile_ownership((), ()), bindings=())
    journal = install_host_ram_commit_journal(runner, component='cpu',
                                              service=session.service)
    runner.configure_memory_dependency_evidence(runtime_contract_sha256='a' * 64)
    assert session.memory_read_authority is runner._memory_read_authority
    assert runner._memory_read_authority._installed['cpu'][0] is session.service
    assert journal is runner._uart_ram_commit_join
    # The session now serves its data reads through that very authority.
    session._execution, session._case_id = 'a' * 32, 'case'
    served = []
    key = TransactionKey('a' * 32, 'case', 'cpu', 0, 'data', 1)
    assert session.queue_mmio(key, 'd', BOOT + 0x40, False, 0, 15,
                              served.append) is True
    assert served and served[0][1] == 0
    assert runner._memory_read_authority.pending_count == 1
    # A store through the same service yields a commit the journal authenticates.
    write = TransactionKey('a' * 32, 'case', 'cpu', 0, 'data', 2)
    receipt = session.service.write(write, BOOT + 0x40, 0x5a, width_bytes=4,
                                    byte_enable=15)
    assert journal.stage_commit('cpu', session.service, session.service.ledger,
                                write, receipt) is True


# ---------------------------------------------------------------------------
# the shipped F1-F4 descriptor (configuration only, no RTL)
# ---------------------------------------------------------------------------

def test_the_memory_flow_descriptor_declares_f1_to_f4_for_compiled_mmio():
    from myfuzz.runtime.generic_campaign import load_descriptor
    descriptor = load_descriptor(SCENARIO / 'generic_scenario.json', base_dir=ROOT)
    assert descriptor.flow_ids == ('F1', 'F2', 'F3', 'F4')
    assert set(descriptor.executors.values()) == {'compiled_mmio'}
    assert descriptor.executors == {flow: 'compiled_mmio'
                                   for flow in ('F1', 'F2', 'F3', 'F4')}
    assert descriptor.f1_records == ('03200000',)
    assert descriptor.f3_records == ('55000000',)
    assert descriptor.f4_records and descriptor.f2_records
    for member in (descriptor.compose, descriptor.supplement,
                   descriptor.capability):
        assert member.is_relative_to(descriptor.root) and member.is_file()
    # The ordered smoke starts with a store so the F1 read has a real writer.
    import json
    sequence = json.loads((SCENARIO / 'acceptance_sequence.json').read_text())
    assert sequence == ['F3:55000000', 'F1:03200000', 'F4:55000000',
                        'F2:00000040', 'F4:aa000000', 'F2:00000040']


def test_the_memory_flow_descriptor_selects_its_cases_before_any_rtl():
    from myfuzz.runtime.generic_campaign import load_descriptor, select_case_records
    descriptor = load_descriptor(SCENARIO / 'generic_scenario.json', base_dir=ROOT)
    cases = select_case_records(
        descriptor, flow='mixed',
        records=['F3:55000000', 'F1:03200000', 'F4:55000000',
                 'F2:00000040', 'F4:aa000000', 'F2:00000040'])
    assert [flow for flow, _ in cases] == ['F3', 'F1', 'F4', 'F2', 'F4', 'F2']
    assert cases[0] == ('F3', '55000000') and cases[1] == ('F1', '03200000')
