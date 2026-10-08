"""One-edge, single-port 64-bit AXI4 memory service for the pinned CVA6 top."""
from __future__ import annotations

import copy
from collections.abc import Mapping
from pathlib import Path

from myfuzz.scenario.contracts import ProtocolEnvironmentError
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.router import DataflowRouter
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
    """Serve actual CVA6 AXI4 requests from persistent RAM and real MMIO RTL."""

    artifact_kind = 'cva6_packed_axi4_cpu'
    max_transaction_events_per_step = 5
    max_local_ticks_per_step = 1
    max_mmio_target_accesses_per_step = 0

    def __init__(self, artifact: LocalRuntimeArtifact, *, base_dir: Path,
                 cache_dir: Path, memory: PersistentMemory,
                 router: DataflowRouter | None = None,
                 defer_mmio: bool = False,
                 command_timeout_seconds: float = 10.0):
        if artifact.runtime_document.get('kind') != self.artifact_kind:
            raise ValueError('generated CVA6 session requires packed AXI4 artifact')
        if not isinstance(memory, PersistentMemory):
            raise ValueError('generated CVA6 session requires persistent memory')
        if router is not None and not isinstance(router, DataflowRouter):
            raise ValueError('generated CVA6 router must be a DataflowRouter')
        if type(defer_mmio) is not bool or (defer_mmio and router is None):
            raise ValueError('deferred CVA6 MMIO requires a router')
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir,
                         command_timeout_seconds=command_timeout_seconds)
        self.memory = memory
        self.router = router
        self.defer_mmio = defer_mmio
        self.max_mmio_target_accesses_per_step = 0 if defer_mmio else 1
        self.service = MemoryService(memory, TransactionLedger())
        self.mmio_ledger = TransactionLedger()
        self.source_component = artifact.plan.request.instance_id
        self._mmio_sequence = 0
        self._queued_mmio = 0
        self._queued_mmio_write = False
        self.mmio_read_count = 0
        self.mmio_write_count = 0
        self.read_beats = 0
        self.write_beats = 0
        self.read_bursts = 0
        self.write_bursts = 0
        self.last_samples: tuple[dict, ...] = ()
        self._clear()

    def _clear(self) -> None:
        self._state = {'read': None, 'write': None, 'wbeats': [], 'b': None}
        self._memory_sequence = 0
        self._mmio_sequence = 0
        self._queued_mmio = 0
        self._queued_mmio_write = False
        self._quiescing = False
        self.last_samples = ()

    def identity_document(self) -> dict[str, object]:
        return {**super().identity_document(),
                'cpu_service_schema_version': 'generated_cva6_axi4_cpu_service.v3',
                'source_component': self.source_component,
                'defer_mmio': self.defer_mmio}

    def begin_case(self, testcase_id: str) -> None:
        super().begin_case(testcase_id)
        self._clear()

    @property
    def pending_responses(self) -> int:
        state = self._state
        queued_reads_already_counted = int(
            state['read'] is not None and state['read'].get('mmio', False)
            and state['read']['data'] is None)
        return (int(state['read'] is not None) + int(state['write'] is not None)
                + int(state['b'] is not None) + len(state['wbeats'])
                + max(0, self._queued_mmio - queued_reads_already_counted))

    def begin_quiesce(self) -> None:
        self._quiescing = True

    def reset_local(self) -> dict[str, object]:
        cancelled = self.pending_responses
        uncertain = (self.mmio_ledger.uncertain_keys
                     if self.router is not None else ())
        if uncertain:
            raise RuntimeError('cannot reset generated CVA6 after an uncertain MMIO target effect: '
                               + ', '.join(str(key) for key in uncertain))
        targets = (self.router.cancel_for_ledger(self.mmio_ledger)
                   if self.router is not None else ())
        if self._queued_mmio != len(targets):
            raise RuntimeError('generated CVA6 MMIO queue accounting mismatch at reset')
        self._clear()
        super().reset_local()
        return {'cancelled_responses': cancelled,
                'cancelled_target_requests': tuple(str(key) for key in targets)}

    def _key(self) -> TransactionKey:
        if not self._case_id:
            raise RuntimeError('generated CVA6 testcase is not running')
        self._memory_sequence += 1
        return TransactionKey('local-execution', self._case_id,
                              self.source_component, self.reset_epoch,
                              'memory', self._memory_sequence)

    def _mmio_key(self) -> TransactionKey:
        if not self._case_id:
            raise RuntimeError('generated CVA6 testcase is not running')
        self._mmio_sequence += 1
        return TransactionKey('local-execution', self._case_id,
                              self.source_component, self.reset_epoch,
                              'mmio', self._mmio_sequence)

    def _is_mmio_burst(self, row: Mapping[str, int], channel: str) -> bool:
        if self.router is None:
            return False
        start = row[channel + 'addr']
        size = row[channel + 'size']
        burst = row[channel + 'burst']
        length = row[channel + 'len'] + 1
        addresses = tuple(_beat_address(start, index, size, burst, length)
                          for index in range(length))
        mapped = tuple(self.router.owns(address) for address in addresses)
        if not any(mapped):
            return False
        if not all(mapped) or length != 1 or size != 2:
            raise ProtocolEnvironmentError(
                'CVA6 AXI4 MMIO supports one aligned 32-bit beat')
        if start % 4:
            raise ProtocolEnvironmentError('CVA6 AXI4 MMIO address is not word aligned')
        return True

    def _route_mmio(self, *, address: int, write: bool, data: int,
                    byte_enable: int, callback) -> None:
        if self.router is None:
            raise ProtocolEnvironmentError('CVA6 AXI4 request targets undeclared MMIO')
        key = self._mmio_key()
        if self.defer_mmio:
            self._queued_mmio += 1
            if write:
                self._queued_mmio_write = True

            def completed(response: tuple[int, int]) -> None:
                self._queued_mmio -= 1
                if write:
                    self._queued_mmio_write = False
                    self.mmio_write_count += 1
                else:
                    self.mmio_read_count += 1
                callback(response)

            try:
                fresh = self.router.enqueue(self.mmio_ledger, key,
                    address=address, write=write, wdata=data,
                    be=byte_enable, beat_bytes=8, callback=completed)
            except BaseException:
                self._queued_mmio -= 1
                if write:
                    self._queued_mmio_write = False
                raise
            if not fresh:
                self._queued_mmio -= 1
                if write:
                    self._queued_mmio_write = False
                raise RuntimeError('duplicate generated CVA6 MMIO acceptance')
            return
        response = self.router.transact(self.mmio_ledger, key,
            address=address, write=write, wdata=data, be=byte_enable,
            beat_bytes=8)
        if write:
            self.mmio_write_count += 1
        else:
            self.mmio_read_count += 1
        callback(response)

    def _ready_inputs(self, irq_external: int, irq_timer: int) -> dict[str, int]:
        state = self._state
        values = {name: 0 for name in CVA6_AXI_STEP_PORTS}
        values['irq_external'] = irq_external
        values['irq_timer'] = irq_timer
        values['axi_awready'] = int(not self._quiescing and state['write'] is None
                                    and state['b'] is None and not self._queued_mmio_write)
        values['axi_wready'] = int(not self._quiescing and len(state['wbeats']) < 256
                                   and state['b'] is None and not self._queued_mmio_write)
        values['axi_arready'] = int(not self._quiescing and state['read'] is None)
        if state['b'] is not None:
            values['axi_bvalid'] = 1
            values['axi_bid'] = state['b']
        read = state['read']
        if read is not None:
            if read['data'] is None and not read.get('mmio', False):
                address = _beat_address(read['addr'], read['index'], read['size'],
                                        read['burst'], read['length'])
                snapshot = self.service.read(self._key(), address & ~7,
                                             width_bytes=8)
                read['data'] = snapshot.value
            if read['data'] is not None:
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
        self.write_beats += 1
        write['index'] += 1
        if expected_last:
            if state['wbeats']:
                raise ProtocolEnvironmentError('CVA6 AXI4 extra W beat after WLAST')
            state['write'] = None
            self.write_bursts += 1
        if self.router is not None and self.router.owns(address):
            if not expected_last or write['index'] != 1 or write['size'] != 2:
                raise ProtocolEnvironmentError(
                    'CVA6 AXI4 MMIO supports one aligned 32-bit beat')
            if not wstrb:
                raise ProtocolEnvironmentError('CVA6 AXI4 MMIO write has no enabled bytes')
            response_id = write['id']

            def complete_mmio_write(_response: tuple[int, int]) -> None:
                state['b'] = response_id

            self._route_mmio(address=address, write=True, data=wdata,
                             byte_enable=wstrb,
                             callback=complete_mmio_write)
        else:
            self.service.write(self._key(), address & ~7, wdata,
                               width_bytes=8, byte_enable=wstrb)
            if expected_last:
                state['b'] = write['id']

    def step_local(self, inputs: Mapping[str, int]) -> Mapping[str, object]:
        if (not isinstance(inputs, Mapping) or set(inputs) - {'irq_external', 'irq_timer'}
                or any(type(inputs.get(name, 0)) is not int
                       or inputs.get(name, 0) not in (0, 1)
                       for name in ('irq_external', 'irq_timer'))):
            raise ValueError('generated CVA6 accepts only one-bit external and timer IRQ inputs')
        values = self._ready_inputs(inputs.get('irq_external', 0),
                                    inputs.get('irq_timer', 0))
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
                or any(pre[name] != value for name, value in values.items()
                       if name not in ('irq_external', 'irq_timer'))
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
            self._is_mmio_burst(row, 'aw')
            state['write'] = dict(addr=row['awaddr'], size=row['awsize'],
                                  burst=row['awburst'], length=row['awlen'] + 1,
                                  id=row['awid'], index=0)
        if w:
            state['wbeats'].append((row['wdata'], row['wstrb'], row['wlast']))
        if ar:
            if state['read'] is not None:
                raise ProtocolEnvironmentError('CVA6 AXI4 multiple outstanding AR')
            _check_address(row, 'ar')
            mmio = self._is_mmio_burst(row, 'ar')
            state['read'] = dict(addr=row['araddr'], size=row['arsize'],
                                 burst=row['arburst'], length=row['arlen'] + 1,
                                 id=row['arid'], index=0, data=None, mmio=mmio)
            if mmio:
                address = row['araddr']
                response_id = row['arid']

                def complete_mmio_read(response: tuple[int, int]) -> None:
                    current = self._state['read']
                    if current is None or current['id'] != response_id:
                        raise ProtocolEnvironmentError(
                            'CVA6 AXI4 MMIO read response lost its source request')
                    current['data'] = response[0]

                self._route_mmio(address=address, write=False, data=0,
                                 byte_enable=0xff,
                                 callback=complete_mmio_read)
        self._commit_writes()
        self.memory.advance_step()
        return {'aw_accepted': int(aw), 'w_accepted': int(w),
                'b_consumed': int(b), 'ar_accepted': int(ar),
                'r_consumed': int(r),
                'araddr': row['araddr'] if ar else 0,
                'awaddr': row['awaddr'] if aw else 0,
                'driver_samples': copy.deepcopy(self.last_samples),
                'physical_observations': copy.deepcopy(payload['observations']['physical'])}
