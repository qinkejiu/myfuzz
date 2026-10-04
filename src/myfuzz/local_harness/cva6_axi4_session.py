"""One-edge, single-port 64-bit AXI4 memory service for the pinned CVA6 top."""
from __future__ import annotations

import copy
from collections.abc import Mapping
from pathlib import Path

from myfuzz.scenario.contracts import ProtocolEnvironmentError
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from .cva6_axi4_fields import CVA6_AXI_STEP_PORTS, CVA6_AXI_WIDTHS
from .runtime_artifact import LocalRuntimeArtifact
from .session import GeneratedLocalSession


def _beat_address(start: int, index: int, size: int, burst: int, length: int) -> int:
    stride = 1 << size
    if burst == 0:
        return start
    if burst == 1:
        return start + index * stride
    if burst == 2:
        span = stride * length
        if length not in (2, 4, 8, 16) or start % stride:
            raise ProtocolEnvironmentError('unsupported CVA6 AXI4 wrap burst')
        base = start & ~(span - 1)
        return base + (start + index * stride - base) % span
    raise ProtocolEnvironmentError('reserved CVA6 AXI4 burst type')


def _check_address(row: Mapping[str, int], channel: str) -> None:
    start = row[channel + 'addr']
    size = row[channel + 'size']
    length = row[channel + 'len'] + 1
    burst = row[channel + 'burst']
    if size > 3 or start % (1 << size) or length > 256:
        raise ProtocolEnvironmentError('unsupported CVA6 AXI4 size or alignment')
    if row[channel + 'lock']:
        raise ProtocolEnvironmentError('CVA6 AXI4 exclusive access is unsupported')
    if channel == 'aw' and row['awatop']:
        raise ProtocolEnvironmentError('CVA6 AXI4 atomic operation is unsupported')
    for index in range(length):
        address = _beat_address(start, index, size, burst, length)
        if address > 0xffffffffffffffff or (address >> 12) != (start >> 12):
            raise ProtocolEnvironmentError('CVA6 AXI4 burst crosses 4K boundary')


def _check_write_strobe(address: int, size: int, strobe: int) -> None:
    lane = address & 7
    allowed = ((1 << (1 << size)) - 1) << lane
    if strobe & ~allowed:
        raise ProtocolEnvironmentError('CVA6 AXI4 WSTRB exceeds addressed lanes')


class GeneratedCva6Axi4Session(GeneratedLocalSession):
    """Serve only actual accepted CVA6 AXI4 transactions from persistent RAM."""

    artifact_kind = 'cva6_packed_axi4_cpu'
    max_transaction_events_per_step = 5
    max_local_ticks_per_step = 1
    max_mmio_target_accesses_per_step = 0

    def __init__(self, artifact: LocalRuntimeArtifact, *, base_dir: Path,
                 cache_dir: Path, memory: PersistentMemory,
                 command_timeout_seconds: float = 10.0):
        if artifact.runtime_document.get('kind') != self.artifact_kind:
            raise ValueError('generated CVA6 session requires packed AXI4 artifact')
        if not isinstance(memory, PersistentMemory):
            raise ValueError('generated CVA6 session requires persistent memory')
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir,
                         command_timeout_seconds=command_timeout_seconds)
        self.memory = memory
        self.service = MemoryService(memory, TransactionLedger())
        self.source_component = artifact.plan.request.instance_id
        self.read_beats = 0
        self.write_beats = 0
        self.read_bursts = 0
        self.write_bursts = 0
        self.last_samples: tuple[dict, ...] = ()
        self._clear()

    def _clear(self) -> None:
        self._state = {'read': None, 'write': None, 'wbeats': [], 'b': None}
        self._memory_sequence = 0
        self._quiescing = False
        self.last_samples = ()

    def identity_document(self) -> dict[str, object]:
        return {**super().identity_document(),
                'cpu_service_schema_version': 'generated_cva6_axi4_cpu_service.v1',
                'source_component': self.source_component}

    def begin_case(self, testcase_id: str) -> None:
        super().begin_case(testcase_id)
        self._clear()

    @property
    def pending_responses(self) -> int:
        state = self._state
        return (int(state['read'] is not None) + int(state['write'] is not None)
                + int(state['b'] is not None) + len(state['wbeats']))

    def begin_quiesce(self) -> None:
        self._quiescing = True

    def reset_local(self) -> dict[str, object]:
        cancelled = self.pending_responses
        self._clear()
        super().reset_local()
        return {'cancelled_responses': cancelled, 'cancelled_target_requests': ()}

    def _key(self) -> TransactionKey:
        if not self._case_id:
            raise RuntimeError('generated CVA6 testcase is not running')
        self._memory_sequence += 1
        return TransactionKey('local-execution', self._case_id,
                              self.source_component, self.reset_epoch,
                              'memory', self._memory_sequence)

    def _ready_inputs(self, irq_external: int) -> dict[str, int]:
        state = self._state
        values = {name: 0 for name in CVA6_AXI_STEP_PORTS}
        values['irq_external'] = irq_external
        values['axi_awready'] = int(not self._quiescing and state['write'] is None
                                    and state['b'] is None)
        values['axi_wready'] = int(not self._quiescing and len(state['wbeats']) < 256
                                   and state['b'] is None)
        values['axi_arready'] = int(not self._quiescing and state['read'] is None)
        if state['b'] is not None:
            values['axi_bvalid'] = 1
            values['axi_bid'] = state['b']
        read = state['read']
        if read is not None:
            if read['data'] is None:
                address = _beat_address(read['addr'], read['index'], read['size'],
                                        read['burst'], read['length'])
                snapshot = self.service.read(self._key(), address & ~7,
                                             width_bytes=8)
                read['data'] = snapshot.value
            values['axi_rvalid'] = 1
            values['axi_rid'] = read['id']
            values['axi_rdata'] = read['data']
            values['axi_rlast'] = int(read['index'] == read['length'] - 1)
        return values

    def _commit_writes(self) -> None:
        state = self._state
        write = state['write']
        if write is None or not state['wbeats']:
            return
        wdata, wstrb, last = state['wbeats'].pop(0)
        expected_last = write['index'] == write['length'] - 1
        if bool(last) != expected_last:
            raise ProtocolEnvironmentError('CVA6 AXI4 WLAST disagrees with AWLEN')
        address = _beat_address(write['addr'], write['index'], write['size'],
                                write['burst'], write['length'])
        _check_write_strobe(address, write['size'], wstrb)
        self.service.write(self._key(), address & ~7, wdata,
                           width_bytes=8, byte_enable=wstrb)
        self.write_beats += 1
        write['index'] += 1
        if expected_last:
            if state['wbeats']:
                raise ProtocolEnvironmentError('CVA6 AXI4 extra W beat after WLAST')
            state['b'] = write['id']
            state['write'] = None
            self.write_bursts += 1

    def step_local(self, inputs: Mapping[str, int]) -> Mapping[str, object]:
        if (not isinstance(inputs, Mapping) or set(inputs) - {'irq_external'}
                or type(inputs.get('irq_external', 0)) is not int
                or inputs.get('irq_external', 0) not in (0, 1)):
            raise ValueError('generated CVA6 accepts only a one-bit external IRQ input')
        values = self._ready_inputs(inputs.get('irq_external', 0))
        receipt = self.command('STEP_CVA6_AXI4',
                               tuple(values[name] for name in CVA6_AXI_STEP_PORTS))
        if receipt.status == 'error':
            message = f'{receipt.error_code}: {receipt.error_detail}'
            if receipt.error_code == 'protocol_environment':
                raise ProtocolEnvironmentError(message)
            raise RuntimeError(message)
        payload = receipt.payload
        if (receipt.new_ticks != 1 or not isinstance(payload, dict)
                or payload.get('kind') != self.artifact_kind
                or not isinstance(payload.get('samples'), list)
                or len(payload['samples']) != 1):
            raise ProtocolEnvironmentError('generated CVA6 receipt is not one measured tick')
        pre = payload.get('pre_backend')
        expected = {'axi_' + role for role in CVA6_AXI_WIDTHS}
        if (not isinstance(pre, dict) or set(pre) != expected
                or any(type(value) is not int or not 0 <= value < 1 << CVA6_AXI_WIDTHS[name[4:]]
                       for name, value in pre.items())
                or any(pre[name] != value for name, value in values.items() if name != 'irq_external')
                or payload['samples'][0].get('pre', {}).get('backend') != pre):
            raise ProtocolEnvironmentError('invalid generated CVA6 backend observation')
        self.last_samples = tuple(copy.deepcopy(payload['samples']))
        row = {name[4:]: value for name, value in pre.items()}
        def handshake(channel: str) -> bool:
            return bool(row[channel + 'valid'] and row[channel + 'ready'])
        aw, w, b, ar, r = (handshake(channel)
                           for channel in ('aw', 'w', 'b', 'ar', 'r'))
        state = self._state
        if b:
            if state['b'] is None or row['bid'] != state['b'] or row['bresp'] != 0:
                raise ProtocolEnvironmentError('CVA6 AXI4 B response mismatch')
            state['b'] = None
        if r:
            read = state['read']
            if (read is None or row['rid'] != read['id'] or row['rresp'] != 0
                    or row['rlast'] != int(read['index'] == read['length'] - 1)):
                raise ProtocolEnvironmentError('CVA6 AXI4 R response mismatch')
            self.read_beats += 1
            read['index'] += 1
            read['data'] = None
            if read['index'] == read['length']:
                state['read'] = None
                self.read_bursts += 1
        if aw:
            if state['write'] is not None:
                raise ProtocolEnvironmentError('CVA6 AXI4 multiple outstanding AW')
            _check_address(row, 'aw')
            state['write'] = dict(addr=row['awaddr'], size=row['awsize'],
                                  burst=row['awburst'], length=row['awlen'] + 1,
                                  id=row['awid'], index=0)
        if w:
            state['wbeats'].append((row['wdata'], row['wstrb'], row['wlast']))
        if ar:
            if state['read'] is not None:
                raise ProtocolEnvironmentError('CVA6 AXI4 multiple outstanding AR')
            _check_address(row, 'ar')
            state['read'] = dict(addr=row['araddr'], size=row['arsize'],
                                 burst=row['arburst'], length=row['arlen'] + 1,
                                 id=row['arid'], index=0, data=None)
        self._commit_writes()
        self.memory.advance_step()
        return {'aw_accepted': int(aw), 'w_accepted': int(w),
                'b_consumed': int(b), 'ar_accepted': int(ar),
                'r_consumed': int(r),
                'araddr': row['araddr'] if ar else 0,
                'awaddr': row['awaddr'] if aw else 0,
                'driver_samples': copy.deepcopy(self.last_samples),
                'physical_observations': copy.deepcopy(payload['observations']['physical'])}
