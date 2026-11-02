"""Synthetic-wire tests for the packed single-port CVA6 F2/F4 row."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))

from myfuzz.integration.cva6_axi_mmio import (INSTRUCTION_HOP_REFUSAL,
    cva6_axi_mmio_traces, cva6_mmio_cpu_adapter, replay_cva6_axi)
from myfuzz.integration.cpu_axi4 import AXI4_KIND_GAPS, SESSION_WRAPPERS
from myfuzz.local_harness.cva6_axi4_fields import CVA6_AXI_SHAPE
from myfuzz.local_harness.cva6_axi_mmio_session import (
    INSTRUCTION_HOP_REFUSAL as SESSION_REFUSAL,
    GeneratedCva6AxiMmioSession)


class _Profile:
    capabilities = {'address_width': 64, 'data_width': 64, 'id_width': 4,
                    'user_width': 64, 'byte_enable': True,
                    'error_response': True, 'bursts': False,
                    'max_outstanding': 1}
    profile_fingerprint = 'sha256:test'


class _Plan:
    profile = _Profile()

    class request:
        instance_id = 'processor'


class _Artifact:
    def __init__(self, rows=None, kind='cva6_packed_axi4_cpu'):
        self.plan = _Plan()
        self.runtime_document = {
            'kind': kind,
            'backend_ports': rows if rows is not None else default_rows(),
            'boot_contract': {'configured_boot_base': 65536},
        }


def default_rows():
    return [{'name': 'axi_' + role, 'role': role, 'channel': 'axi',
             'direction': direction, 'width': width}
            for role, (direction, width) in CVA6_AXI_SHAPE.items()]


def sample(event_id, tick, **roles):
    backend = {name: 0 for name in
               ('axi_' + role for role in CVA6_AXI_SHAPE)}
    for key, value in roles.items():
        backend['axi_' + key] = value
    return {'event_id': event_id, 'component': 'processor', 'local_tick': tick,
            'outputs': {'driver_samples': [
                {'local_tick': tick, 'pre': {'backend': backend}}]}}


def test_traces_map_every_packed_role():
    traces = cva6_axi_mmio_traces(_Artifact())
    assert traces['schema_version'] == 'cva6_packed_axi4_native_traces.v1'
    assert traces['channels'] == {'memory': 'axi'}
    assert sorted(traces['memory']) == sorted(CVA6_AXI_SHAPE)
    assert traces['memory']['araddr'] == 'axi_araddr'
    # The row declares the address-ID fetch identity it could re-read from the
    # pinned RTL, so the data-only refusal is *not* what it carries.
    assert 'instruction_hop_refusal' not in traces
    assert traces['instruction_id_map'] == {'arid': 0, 'rid': 0,
                                            'granule_bytes': 8, 'rsize': 3}
    assert traces['observation']['instruction_channel'] is None
    identity = traces['observation']['instruction_identity']
    assert identity['instruction_id_map'] == traces['instruction_id_map']
    assert 'wt_axi_adapter.sv:159' in identity['scope']


def test_traces_refuse_a_missing_or_reshaped_role():
    rows = [row for row in default_rows() if row['name'] != 'axi_aruser']
    with pytest.raises(ValueError):
        cva6_axi_mmio_traces(_Artifact(rows))
    rows = default_rows()
    next(row for row in rows if row['name'] == 'axi_wstrb')['width'] = 4
    with pytest.raises(ValueError):
        cva6_axi_mmio_traces(_Artifact(rows))


def test_traces_refuse_another_kind():
    with pytest.raises(ValueError):
        cva6_axi_mmio_traces(_Artifact(kind='reduced_dual_axi_cpu'))


def test_replay_numbers_one_channel_and_the_real_widths():
    traces = cva6_axi_mmio_traces(_Artifact())
    events = [
        sample(10, 1, arvalid=1, arready=1, araddr=0x10000, arsize=3, arid=0),
        sample(11, 2, rvalid=1, rready=1, rid=0, rdata=0x0000001300000013,
               rlast=1),
        sample(12, 3, arvalid=1, arready=1, araddr=0x40000000, arsize=2, arid=0),
        sample(13, 4, rvalid=1, rready=1, rid=0, rdata=0x55, rlast=1),
        sample(14, 5, awvalid=1, awready=1, awaddr=0x100ff8, awsize=2, awid=1,
               wvalid=1, wready=1, wdata=0x0000000000001234, wstrb=0x0f,
               wlast=1),
        sample(15, 6, bvalid=1, bready=1, bid=1),
    ]
    completed, reads = replay_cva6_axi(events, 'processor', traces)
    assert [address for _, address in reads] == [0x10000, 0x40000000]
    assert sorted(completed) == [('data', 1), ('data', 2), ('data', 3)]
    fetch = completed[('data', 1)]
    assert (fetch['write'], fetch['address'], fetch['rdata']) == (
        0, 0x10000, 0x0000001300000013)
    read = completed[('data', 2)]
    assert (read['rdata'], read['byte_enable']) == (0x55, 0)
    write = completed[('data', 3)]
    assert (write['write'], write['address'], write['value']) == (
        1, 0x100ff8, 0x1234)
    assert write['byte_enable'] == 0x0f
    assert write['acceptance_event'] == 14 and write['response_event'] == 15


def test_replay_uses_the_addressed_lane_of_a_wide_beat():
    traces = cva6_axi_mmio_traces(_Artifact())
    events = [
        sample(20, 1, awvalid=1, awready=1, awaddr=0x100ffc, awsize=2, awid=1,
               wvalid=1, wready=1, wdata=0x1234567800000000, wstrb=0xf0,
               wlast=1),
        sample(21, 2, bvalid=1, bready=1, bid=1),
    ]
    completed, _ = replay_cva6_axi(events, 'processor', traces)
    write = completed[('data', 1)]
    assert (write['address'], write['value'], write['byte_enable']) == (
        0x100ffc, 0x12345678, 0x0f)


def test_replay_refuses_a_non_okay_response():
    traces = cva6_axi_mmio_traces(_Artifact())
    events = [
        sample(30, 1, arvalid=1, arready=1, araddr=0x10000, arsize=3, arid=0),
        sample(31, 2, rvalid=1, rready=1, rid=0, rdata=0, rlast=1, rresp=2),
    ]
    with pytest.raises(ValueError):
        replay_cva6_axi(events, 'processor', traces)


def test_adapter_declares_the_data_only_scope():
    adapter = cva6_mmio_cpu_adapter(_Artifact(), {}, {})
    assert adapter.protocol == 'axi4'
    assert adapter.channel_model == 'unified'
    assert adapter.instruction_granule == 8
    assert adapter.session_type is GeneratedCva6AxiMmioSession
    assert adapter.traces['instruction_id_map']['arid'] == 0
    assert adapter.memory_receipts_on_unified is True
    assert adapter.policy['native_error_pins']['memory']['read'] == 'axi_rresp'


def test_session_and_gaps_declare_the_refusal_and_the_flows():
    assert SESSION_WRAPPERS['cva6_packed_axi4_cpu'].endswith(
        'GeneratedCva6AxiMmioSession')
    gaps = ' '.join(AXI4_KIND_GAPS['cva6_packed_axi4_cpu'])
    assert 'wt_axi_adapter.sv' in gaps and 'cva6_icache_axi_wrapper.sv' in gaps
    identity = GeneratedCva6AxiMmioSession.identity_document
    assert callable(identity)
    assert hasattr(GeneratedCva6AxiMmioSession, 'waiting_instruction_address')
    assert hasattr(GeneratedCva6AxiMmioSession, 'parked_instruction_address')
    assert callable(GeneratedCva6AxiMmioSession.declare_instruction_slots)
    assert callable(GeneratedCva6AxiMmioSession.accept_instructions)
    assert SESSION_REFUSAL == INSTRUCTION_HOP_REFUSAL


def test_session_implements_two_memory_flow_options_and_refuses_the_third():
    assert set(GeneratedCva6AxiMmioSession.MEMORY_FLOW_OPTIONS) == {
        'memory_commit_receipts', 'memory_readback_receipts',
        'physical_tick_samples'}
    parameters = GeneratedCva6AxiMmioSession.__init__.__code__.co_varnames
    # The two receipt streams are named keywords (opt-in, default off); the
    # physical tick stream is not implemented and stays a named refusal.
    assert 'router' in parameters and 'memory' in parameters
    assert 'memory_commit_receipts' in parameters
    assert 'memory_readback_receipts' in parameters
    assert 'physical_tick_samples' not in parameters
    source = Path(GeneratedCva6AxiMmioSession.__init__.__code__.co_filename)
    assert 'does not implement this memory-flow option' in source.read_text()
    assert 'memory_flows_enabled' in source.read_text()
