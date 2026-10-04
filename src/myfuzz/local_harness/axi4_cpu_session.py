"""Cycle-accurate local RAM service for the pinned ZipCPU full AXI4 masters."""
from __future__ import annotations

import copy
from collections.abc import Mapping
from pathlib import Path

from myfuzz.scenario.contracts import ProtocolEnvironmentError
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from .axi4_fields import AXI_INPUT_FIELDS, AXI_STEP_PORTS, AXI_WIDTHS
from .runtime_artifact import LocalRuntimeArtifact
from .session import GeneratedLocalSession


def _address(start: int, index: int, size: int, burst: int, length: int) -> int:
    step = 1 << size
    if burst == 0:
        return start
    if burst == 1:
        return start + index * step
    if burst == 2:
        span = step * length
        if length not in (2, 4, 8, 16) or start % step:
            raise ProtocolEnvironmentError('invalid AXI4 wrap burst')
        base = start & ~(span - 1)
        return base + (start + index * step - base) % span
    raise ProtocolEnvironmentError('reserved AXI4 burst type')


def _check_address(row: Mapping[str, int], channel: str) -> None:
    start, size, length, burst = (row[channel + name] for name in ('addr', 'size', 'len', 'burst'))
    if size > 2 or start % (1 << size) or length > 255:
        raise ProtocolEnvironmentError('invalid AXI4 transfer size or alignment')
    if row[channel + 'lock']:
        raise ProtocolEnvironmentError('AXI4 exclusive access is unsupported')
    for index in range(length + 1):
        addr = _address(start, index, size, burst, length + 1)
        if addr > 0xffffffff or (addr >> 12) != (start >> 12):
            raise ProtocolEnvironmentError('AXI4 burst crosses address boundary')


class GeneratedAxi4CpuSession(GeneratedLocalSession):
    """Advance both AXI4 masters one measured edge while serving versioned RAM."""

    max_transaction_events_per_step = 4
    max_local_ticks_per_step = 1
    max_mmio_target_accesses_per_step = 0

    def __init__(self, artifact: LocalRuntimeArtifact, *, base_dir: Path,
                 cache_dir: Path, memory: PersistentMemory,
                 command_timeout_seconds: float = 10.0):
        if artifact.runtime_document.get('kind') != 'axi4_cpu':
            raise ValueError('generated AXI4 CPU requires full AXI4 artifact')
        if not isinstance(memory, PersistentMemory):
            raise ValueError('generated AXI4 CPU requires persistent memory')
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir,
                         command_timeout_seconds=command_timeout_seconds)
        self.memory = memory
        self.service = MemoryService(memory, TransactionLedger())
        self.source_component = artifact.plan.request.instance_id
        self._state = {}
        self._sequences = {'i': 0, 'd': 0}
        self._quiescing = False
        self.read_beats = 0
        self.write_beats = 0
        self.read_bursts = 0
        self.write_bursts = 0
        self.max_read_burst_length = 0
        self.last_samples: tuple[dict, ...] = ()
        self._clear()

    def _clear(self) -> None:
        self._state = {p: {'read': None, 'write': None, 'wbeats': [], 'b': None}
                       for p in ('i', 'd')}
        self._sequences = {'i': 0, 'd': 0}
        self.last_samples = ()
        self._quiescing = False

    def identity_document(self) -> dict[str, object]:
        return {**super().identity_document(),
                'cpu_service_schema_version': 'generated_axi4_cpu_service.v1',
                'source_component': self.source_component}

    def begin_case(self, testcase_id: str) -> None:
        super().begin_case(testcase_id)
        self._clear()

    @property
    def pending_responses(self) -> int:
        return sum(int(s['read'] is not None) + int(s['write'] is not None)
                   + int(s['b'] is not None) + len(s['wbeats']) for s in self._state.values())

    def begin_quiesce(self) -> None:
        self._quiescing = True

    def reset_local(self) -> dict[str, object]:
        cancelled = self.pending_responses
        self._clear()
        super().reset_local()
        return {'cancelled_responses': cancelled, 'cancelled_target_requests': ()}

    def _key(self, prefix: str) -> TransactionKey:
        if not self._case_id:
            raise RuntimeError('generated CPU testcase is not running')
        self._sequences[prefix] += 1
        return TransactionKey('local-execution', self._case_id, self.source_component,
                              self.reset_epoch, 'instr' if prefix == 'i' else 'data',
                              self._sequences[prefix])

    def _ready_inputs(self) -> dict[str, int]:
        values = {name: 0 for name in AXI_STEP_PORTS}
        for prefix, state in self._state.items():
            values[prefix + '_awready'] = int(not self._quiescing and state['write'] is None and state['b'] is None)
            values[prefix + '_wready'] = int(not self._quiescing and len(state['wbeats']) < 256 and state['b'] is None)
            values[prefix + '_arready'] = int(not self._quiescing and state['read'] is None)
            if state['b'] is not None:
                values[prefix + '_bvalid'] = 1
                values[prefix + '_bid'] = state['b']
            read = state['read']
            if read is not None:
                if read['data'] is None:
                    address = _address(read['addr'], read['index'], read['size'],
                                       read['burst'], read['length'])
                    snapshot = self.service.read(self._key(prefix), address & ~3, width_bytes=4)
                    read['data'] = snapshot.value
                values[prefix + '_rvalid'] = 1
                values[prefix + '_rid'] = read['id']
                values[prefix + '_rdata'] = read['data']
                values[prefix + '_rlast'] = int(read['index'] == read['length'] - 1)
        return values

    def _commit_writes(self, prefix: str) -> None:
        state = self._state[prefix]
        write = state['write']
        if write is None:
            return
        if state['wbeats'] and write['index'] < write['length']:
            wdata, wstrb, last = state['wbeats'].pop(0)
            expected_last = write['index'] == write['length'] - 1
            if bool(last) != expected_last:
                raise ProtocolEnvironmentError('AXI4 WLAST disagrees with AWLEN')
            address = _address(write['addr'], write['index'], write['size'],
                               write['burst'], write['length'])
            self.service.write(self._key(prefix), address & ~3, wdata,
                               width_bytes=4, byte_enable=wstrb)
            self.write_beats += 1
            write['index'] += 1
            if expected_last:
                if state['wbeats']:
                    raise ProtocolEnvironmentError('AXI4 write data exceeds AWLEN')
                state['b'] = write['id']
                state['write'] = None
                self.write_bursts += 1

    def step_local(self, inputs: Mapping[str, int]) -> Mapping[str, object]:
        if not isinstance(inputs, Mapping) or inputs:
            raise ValueError('generated AXI4 CPU has no external input')
        values = self._ready_inputs()
        receipt = self.command('STEP_AXI4', tuple(values[name] for name in AXI_STEP_PORTS))
        if receipt.status == 'error':
            message = f'{receipt.error_code}: {receipt.error_detail}'
            if receipt.error_code == 'protocol_environment':
                raise ProtocolEnvironmentError(message)
            raise RuntimeError(message)
        payload = receipt.payload
        if (receipt.new_ticks != 1 or not isinstance(payload, dict)
                or payload.get('kind') != 'axi4_cpu'
                or not isinstance(payload.get('samples'), list)
                or len(payload['samples']) != 1):
            raise ProtocolEnvironmentError('generated AXI4 receipt is not one measured tick')
        pre = payload.get('pre_backend')
        expected = {p + '_' + role for p in ('i', 'd') for role in AXI_WIDTHS}
        if (not isinstance(pre, dict) or set(pre) != expected
                or any(type(value) is not int or not 0 <= value < 1 << AXI_WIDTHS[name[2:]]
                       for name, value in pre.items())
                or any(pre[name] != value for name, value in values.items())
                or payload['samples'][0].get('pre', {}).get('backend') != pre):
            raise ProtocolEnvironmentError('invalid generated AXI4 backend observation')
        self.last_samples = tuple(copy.deepcopy(payload['samples']))
        observations = {}
        for prefix in ('i', 'd'):
            state = self._state[prefix]
            row = {name[2:]: value for name, value in pre.items() if name.startswith(prefix + '_')}
            def handshake(channel: str) -> bool:
                return bool(row[channel + 'valid'] and row[channel + 'ready'])
            aw, w, b, ar, r = (handshake(channel) for channel in ('aw', 'w', 'b', 'ar', 'r'))
            if b:
                if state['b'] is None or row['bid'] != state['b'] or row['bresp'] != 0:
                    raise ProtocolEnvironmentError('AXI4 write response ID or status mismatch')
                state['b'] = None
            if r:
                read = state['read']
                if (read is None or row['rid'] != read['id'] or row['rresp'] != 0
                        or row['rlast'] != int(read['index'] == read['length'] - 1)):
                    raise ProtocolEnvironmentError('AXI4 read response ID, status, or last mismatch')
                self.read_beats += 1
                read['index'] += 1
                read['data'] = None
                if read['index'] == read['length']:
                    state['read'] = None
                    self.read_bursts += 1
            if aw:
                if state['write'] is not None:
                    raise ProtocolEnvironmentError('AXI4 multiple outstanding writes')
                _check_address(row, 'aw')
                state['write'] = dict(addr=row['awaddr'], size=row['awsize'],
                                      burst=row['awburst'], length=row['awlen'] + 1,
                                      id=row['awid'], index=0)
            if w:
                state['wbeats'].append((row['wdata'], row['wstrb'], row['wlast']))
            if ar:
                if state['read'] is not None:
                    raise ProtocolEnvironmentError('AXI4 multiple outstanding reads')
                _check_address(row, 'ar')
                state['read'] = dict(addr=row['araddr'], size=row['arsize'],
                                     burst=row['arburst'], length=row['arlen'] + 1,
                                     id=row['arid'], index=0, data=None)
                self.max_read_burst_length = max(self.max_read_burst_length,
                                                 row['arlen'] + 1)
            self._commit_writes(prefix)
            observations[prefix + '_aw_accepted'] = int(aw)
            observations[prefix + '_w_accepted'] = int(w)
            observations[prefix + '_b_consumed'] = int(b)
            observations[prefix + '_ar_accepted'] = int(ar)
            observations[prefix + '_r_consumed'] = int(r)
            observations[prefix + '_arlen'] = row['arlen'] if ar else 0
            observations[prefix + '_awlen'] = row['awlen'] if aw else 0
        self.memory.advance_step()
        return {**observations, 'driver_samples': copy.deepcopy(self.last_samples),
                'physical_observations': copy.deepcopy(payload['observations']['physical'])}
