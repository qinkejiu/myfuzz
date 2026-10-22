"""Pure tests: DMA master UART FIFO pops can become accepted authority (S4).

The synthetic tick/access rows below have the measured shape of the pinned
OpenTitan FIFO probes; they prove the *joins*, not any RTL fact.  A real gate is
separate and opt-in.
"""
import hashlib
import json

import pytest

from myfuzz.local_harness.wishbone_dma_session import MasterTargetWindow
from myfuzz.scenario.dma_runtime_paths import (SOURCE_NODE,
    compile_dma_runtime_paths, compile_dma_source_provenance, source_input_sha256)
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import (InputField, InputOwner, compile_ownership)
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding
from myfuzz.scenario.ledger import TransactionLedger
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.source_provenance import AdmissionRegistry, SourceAdmission
from myfuzz.scenario.uart_consumption import UartConsumptionTracker

UART_BASE = 0x50000000
UART_SIZE = 0x1000
DMA_BASE = 0x3000
BYTE = 0


class _UartFake:
    def identity_document(self):
        return {'component': 'uart', 'fake': True}

    def read_register(self, offset):
        return 0

    def write_register(self, offset, value, *, be=15):
        return None

    def master_target_access(self, key, *, address, offset, write, value, be,
                             delivery_context):
        return {'rdata': 0, 'target_uart_access': {
            'kind': 'uart_rdata_access', 'status': 'observed',
            'read_value': 0, 'access_id': 'uart-access:uart:0:1'}}


class _SessionFake:
    def __init__(self, *, memory=None, router=None):
        self.memory = memory
        self.router = router
        self.routed_register_access_enabled = True

    def identity_document(self):
        return {'component': 'fake-session'}

    def dma_route_endpoint_identity_document(self):
        return {'schema_version': 'fake_dma_route_endpoint.v1',
                'source_component': 'dma', 'fake': True}

    def configure_dma_route_validator(self, callback):
        self._dma_route_validator = callback


class _RunnerFake:
    def __init__(self):
        memory = PersistentMemory(regions=(MemoryRegion('ram', 0x10000, 0x20000),),
            initialization_seed=17, max_initialized_bytes=0x20000)
        self.uart = _UartFake()
        self.cpu = _SessionFake(memory=memory)
        self.dma = _SessionFake()
        self.dma.memory_service = MemoryService(memory, TransactionLedger())
        self.dma.source_component = 'dma'
        self.sessions = {'cpu': self.cpu, 'dma': self.dma, 'uart': self.uart}
        self.cpu.router = DataflowRouter((
            DeviceWindow('dma', DMA_BASE, 16, self.dma),
            DeviceWindow('uart', UART_BASE, UART_SIZE, self.uart)))
        self.dma.master_targets = (MasterTargetWindow('uart', UART_BASE,
            UART_SIZE, self.uart, (0x1C,), range(256),
            readable_offsets=(0x18,)),)
        self.ownership = compile_ownership(
            (InputField('cpu', 'irq', 1), InputField('uart', 'uart_rx_byte', 8)),
            (InputOwner('cpu', 'irq', 0, 1, 'bound', 'dma.irq'),
             InputOwner('uart', 'uart_rx_byte', 0, 8, 'source',
                        'external-serial-byte')))
        self.bindings = (Binding('dma', 'irq', 'cpu', 'irq', 1),)
        self._provenance = None

    @property
    def provenance_enabled(self):
        return self._provenance is not None

    def configure_provenance(self, edge_index):
        self._provenance = edge_index

    def register_source_admission(self, admission):
        pass


def tick(n, pre=None, post=None):
    from myfuzz.local_harness.opentitan_uart_fifo_contract import (
        UART_FIFO_PROBES, uart_fifo_observation_contract)
    p = dict(sync_intq=1, rx_sync=1, rx_in=1, rx_enable=1, idle=1, bit_cnt=0,
             tick_baud=0, sreg=0, rx_valid=0, rx_data=0, frame_err=0,
             parity_err=0, nco=1, rxnf_enable=0, sys_loopback=0,
             line_loopback=0, parity_en=0, parity_odd=0, fifo_wvalid=0,
             fifo_wready=1, fifo_rvalid=0, fifo_rdata_re=0, fifo_data=0,
             fifo_head=0, fifo_depth=0, fifo_wptr=0, fifo_rptr=0,
             fifo_under_rst=0, fifo_clear=0, fifo_incr_wptr=0,
             fifo_incr_rptr=0)
    p = dict({k: 0 for k in UART_FIFO_PROBES}, **p)
    a = dict(p, **(pre or {}))
    b = dict(a, **(post or {}))
    if a['rx_enable'] and a['idle'] and not a['rx_in'] and b['idle'] == 0:
        if not post or 'baud_div' not in post:
            b['baud_div'] = 8
        if not post or 'tick_baud' not in post:
            b['tick_baud'] = 0
    return dict(kind='uart_tick_observation', component='uart', reset_epoch=0,
        local_tick=n, event_id=f't{n}',
        command_scope=dict(component='uart', reset_epoch=0, command_sequence=1),
        observation_contract=uart_fifo_observation_contract(),
        receipt_id={'execution': 'process', 'sequence': 1},
        pre={'probe_uart_' + k: v for k, v in a.items()},
        post={'probe_uart_' + k: v for k, v in b.items()})


def _source_admission(provenance, action='a', value=BYTE, source_id=None):
    return SourceAdmission.create(case_id='A', case_index=0,
        source_id=source_id or provenance.source_id,
        path_id=provenance.paths.path_id, direction='IP_TO_CPU',
        component='uart', action_id=action, role='fuzz_source',
        input_kind='source_event',
        input_sha256=source_input_sha256(action, 'uart', value))


def _tracker(*, edge_index=True, register=True, source_id=None):
    runner = _RunnerFake()
    provenance = compile_dma_source_provenance(runner)
    admission = _source_admission(provenance, source_id=source_id)
    registry = AdmissionRegistry()
    if register:
        registry.register(admission)
    tracker = UartConsumptionTracker(admission_registry=registry,
        ownership=runner.ownership,
        edge_index=runner._provenance if edge_index else None)
    return tracker, provenance, admission


def _run_validated_frame(tracker, admission):
    """Play the measured 8N1 drive/push sequence for the admitted byte."""
    refs = []
    q0 = q1 = 1
    idle, count, shift = 1, 0, 0
    for n in range(43):
        slot = n // 4
        value = 0 if slot < 9 else 1
        ref = dict(frame_id='f', action_id='a',
                   admission_id=admission.admission_id, bit_index=min(slot, 9),
                   bit_value=value, drive_tick=n,
                   receipt_id={'execution': 'process', 'sequence': 1})
        if n < 40:
            refs.append(ref)
        start = bool(idle and not q1)
        sample = bool(not idle and n in range(4, 41, 4))
        newshift = (q1 << 10) | (shift >> 1) if sample else shift
        postcount = 10 if start else count - 1 if sample else count
        postidle = 0 if start else int(count == 1) if sample else idle
        event = tick(n, dict(sync_input=value, sync_intq=q0, rx_sync=q1,
            rx_in=q1, idle=idle, bit_cnt=count, tick_baud=int(sample),
            sreg=shift, rx_valid=int(n == 41), fifo_wvalid=int(n == 41),
            fifo_incr_wptr=int(n == 41), fifo_depth=int(n > 41),
            fifo_wptr=int(n > 41), fifo_rvalid=int(n > 41)),
            dict(sync_intq=value, rx_sync=q0, idle=postidle,
                 bit_cnt=postcount, sreg=0 if start else newshift,
                 rx_valid=int(sample and count == 1),
                 fifo_depth=int(n >= 41), fifo_wptr=int(n >= 41),
                 fifo_rvalid=int(n >= 41)))
        if n < 40:
            event.update(physical_rx_ref=ref, physical_rx_value=value)
        tracker.consume(event)
        q0, q1 = value, q0
        idle, count, shift = postidle, postcount, 0 if start else newshift
    validation = dict(kind='uart_frame_validation', component='uart',
        reset_epoch=0, local_tick=42, event_id='validation',
        command_scope=dict(component='uart', reset_epoch=0, command_sequence=1),
        frame_id='f', action_id='a', admission_id=admission.admission_id,
        waveform_matched=True, source_drive_refs=refs)
    return tracker.consume(validation)


def _read_event(*, mode, tamper=None, edge_index=True):
    if mode == 'dma_master':
        key = dict(execution_id='b' * 32, testcase_id='A',
            source_component='dma', source_epoch=0, channel_id='dma-memory',
            source_sequence=1)
    else:
        key = dict(execution_id='a' * 32, testcase_id='A',
            source_component='cpu', source_epoch=0, channel_id='data',
            source_sequence=1)
    window_base = 0x50000000
    address = window_base + 0x18
    window_size = 0x1000
    value = 0
    if tamper == 'channel_data':
        key = dict(key, channel_id='data')
    delivery = dict(source_transaction=key, device_id='uart', address=address,
        offset=24, write=False, value=value, be=15, window_base=window_base,
        window_size=window_size)
    # A wrong declared window is a mismatch between the measured access context
    # and the DMA session's delivery evidence; both are real journal fields.
    if tamper == 'window_base':
        delivery['window_base'] = 0x50001000
    if tamper == 'window_size':
        delivery['window_size'] = 0x800
    context = dict(access_id='access', source_transaction=key, raw_offset=24,
        write=False, byte_enable=1 if tamper == 'be' else 15, address=address,
        window_base=window_base, window_size=window_size,
        route_context_mode=mode, delivery_context=delivery)
    return key, context, delivery


def _drive_read(tracker, *, mode, tamper=None):
    key, context, delivery = _read_event(mode=mode, tamper=tamper)
    req = tick(43, dict(fifo_depth=1, fifo_wptr=1, fifo_rvalid=1,
        fifo_rdata_re=1, fifo_incr_rptr=1, a_accept=1, tl_a_valid=1,
        tl_a_ready=1, tl_a_opcode=4, tl_a_address=24, tl_a_mask=15,
        tl_a_source=7, reg_re=1, reg_rdata_re=1, reg_addr=24),
        dict(fifo_depth=0, fifo_rptr=1, fifo_rvalid=0, captured_source=7))
    req['access'] = context
    tracker.consume(req)
    rsp = tick(44, dict(fifo_wptr=1, fifo_rptr=1, d_accept=1, tl_d_valid=1,
        tl_d_ready=1, tl_d_source=7, tl_d_opcode=1, captured_source=7))
    rsp['access'] = context
    tracker.consume(rsp)
    access = dict(kind='uart_rdata_access', component='uart', reset_epoch=0,
        local_tick=44, event_id='access-final',
        command_scope=req['command_scope'], **context, request_tick=43,
        response_tick=44, read_value=0, error=0,
        actual_request_event_id=req['event_id'],
        actual_response_event_id=rsp['event_id'],
        read_capture=dict(pre=req['pre'], post=req['post'],
            actual_receipt_ref=dict(command_scope=req['command_scope'],
                                    local_tick=43)),
        response_capture=dict(pre=rsp['pre'], post=rsp['post'],
            actual_receipt_ref=dict(command_scope=rsp['command_scope'],
                                    local_tick=44)))
    return tracker.consume(access)


def _accepted(reports, scope):
    return [row for row in reports if row.get('kind') == 'uart_consumption_match'
            and row.get('status') == 'accepted' and row.get('proof_scope') == scope]


def test_router_cpu_pop_is_still_accepted():
    tracker, provenance, admission = _tracker()
    validation = _run_validated_frame(tracker, admission)
    assert _accepted(validation, 'uart_fifo_retention')
    reports = _drive_read(tracker, mode='router')
    proof = _accepted(reports, 'uart_fifo_read_consumption')
    assert len(proof) == 1
    assert proof[0]['route_context_mode'] == 'router'
    assert proof[0]['path_id'] == provenance.paths.path_id
    assert proof[0]['graph_path_certified'] is True


def test_dma_master_pop_is_accepted_with_the_dma_channel_identity():
    tracker, provenance, admission = _tracker()
    validation = _run_validated_frame(tracker, admission)
    assert len(_accepted(validation, 'uart_fifo_retention')) == 1
    reports = _drive_read(tracker, mode='dma_master')
    proof = _accepted(reports, 'uart_fifo_read_consumption')
    assert len(proof) == 1
    proof = proof[0]
    assert proof['route_context_mode'] == 'dma_master'
    assert proof['source_transaction']['channel_id'] == 'dma-memory'
    assert proof['source_transaction']['source_component'] == 'dma'
    assert proof['path_id'] == provenance.paths.path_id
    assert proof['graph_path_certified'] is True
    assert proof['window_base'] == 0x50000000
    assert proof['window_size'] == 0x1000
    route_match = proof['dma_master_route_match']
    assert route_match['route_sha256'] == \
        provenance.edge_index.dma_master_routes_for_path(provenance.paths.path_id)[0].route_sha256
    assert route_match['edge_key'] == (3, 0)


@pytest.mark.parametrize('tamper, reason', [
    ('channel_data', 'unproven_uart_routed_access'),
    ('window_base', 'unproven_uart_dma_master_window'),
    ('window_size', 'unproven_uart_dma_master_window'),
    ('be', 'unproven_uart_routed_access')])
def test_dma_master_pop_refuses_wrong_channel_window_or_strobe(tamper, reason):
    tracker, provenance, admission = _tracker()
    _run_validated_frame(tracker, admission)
    reports = _drive_read(tracker, mode='dma_master', tamper=tamper)
    assert not _accepted(reports, 'uart_fifo_read_consumption')
    assert any(row.get('status') == 'incomplete' and row.get('reason') == reason
               for row in reports)


def test_missing_admission_keeps_the_dma_pop_unproven():
    tracker, provenance, admission = _tracker(register=False)
    validation = _run_validated_frame(tracker, admission)
    assert not _accepted(validation, 'uart_fifo_retention')
    assert any(row.get('reason') == 'unproven_uart_source_authority'
               for row in validation)
    reports = _drive_read(tracker, mode='dma_master')
    assert not _accepted(reports, 'uart_fifo_read_consumption')


def test_missing_edge_index_keeps_the_source_unproven():
    tracker, provenance, admission = _tracker(edge_index=False)
    validation = _run_validated_frame(tracker, admission)
    assert not _accepted(validation, 'uart_fifo_retention')
    assert any(row.get('reason') == 'unproven_uart_source_authority'
               for row in validation)


def test_producer_ref_masquerading_as_source_id_is_unproven():
    tracker, provenance, admission = _tracker(
        source_id='external-serial-byte')
    validation = _run_validated_frame(tracker, admission)
    assert not _accepted(validation, 'uart_fifo_retention')
    assert any(row.get('reason') == 'unproven_uart_source_authority'
               for row in validation)


def test_tampered_waveform_is_unproven():
    tracker, provenance, admission = _tracker()
    validation = _run_validated_frame(tracker, admission)
    # Replay a validation whose measured drive refs differ from the sampler.
    tampered = dict(validation[0])
    original = _run_validated_frame
    assert any(row.get('status') == 'accepted' for row in validation)
    # A second validation for the same frame with dropped refs is refused.
    again = tracker.consume(dict(kind='uart_frame_validation', component='uart',
        reset_epoch=0, local_tick=42, event_id='validation-2',
        command_scope=dict(component='uart', reset_epoch=0, command_sequence=1),
        frame_id='f', action_id='a', admission_id=admission.admission_id,
        waveform_matched=False, source_drive_refs=[]))
    assert not any(row.get('status') == 'accepted' for row in again)
