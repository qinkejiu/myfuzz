"""One-edge RAM service for admitted reduced single-beat dual AXI masters."""
from __future__ import annotations
import copy
from collections.abc import Mapping
from pathlib import Path

from myfuzz.scenario.contracts import ProtocolEnvironmentError
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from .runtime_artifact import LocalRuntimeArtifact
from .session import GeneratedLocalSession
from .vexii_axi_fields import SHAPES, STEP_PORTS


class GeneratedReducedAxiCpuSession(GeneratedLocalSession):
    """Separate fetch reads and LSU channels; no MMIO or interrupt delivery."""
    artifact_kind = 'reduced_dual_axi_cpu'
    max_transaction_events_per_step = 5
    max_local_ticks_per_step = 1
    max_mmio_target_accesses_per_step = 0

    def __init__(self, artifact: LocalRuntimeArtifact, *, base_dir: Path,
                 cache_dir: Path, memory: PersistentMemory,
                 command_timeout_seconds: float = 10.0):
        if artifact.runtime_document.get('kind') != self.artifact_kind:
            raise ValueError('reduced AXI session requires admitted reduced dual AXI artifact')
        if not isinstance(memory, PersistentMemory):
            raise ValueError('reduced AXI session requires persistent memory')
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir,
                         command_timeout_seconds=command_timeout_seconds)
        self.memory = memory
        self.service = MemoryService(memory, TransactionLedger())
        self.source_component = artifact.plan.request.instance_id
        self.read_beats = self.write_beats = self.write_responses = 0
        self._clear()

    def _clear(self):
        self._state = {p: {'read': None, 'aw': None, 'w': None, 'b': None}
                       for p in SHAPES}
        self._sequences = {'i': 0, 'd': 0}
        self._quiescing = False
        self.last_samples = ()

    def identity_document(self):
        return {**super().identity_document(),
                'cpu_service_schema_version': 'generated_reduced_dual_axi_ram.v1',
                'source_component': self.source_component}

    def begin_case(self, testcase_id):
        super().begin_case(testcase_id)
        self._clear()

    @property
    def pending_responses(self):
        return sum(sum(value is not None for value in state.values())
                   for state in self._state.values())

    def begin_quiesce(self):
        self._quiescing = True

    def reset_local(self):
        cancelled = self.pending_responses
        self._clear()
        super().reset_local()
        return {'cancelled_responses': cancelled, 'cancelled_target_requests': ()}

    def _key(self, prefix):
        if not self._case_id:
            raise RuntimeError('reduced AXI testcase is not running')
        self._sequences[prefix] += 1
        return TransactionKey('local-execution', self._case_id, self.source_component,
                              self.reset_epoch, 'instr' if prefix == 'i' else 'data',
                              self._sequences[prefix])

    @staticmethod
    def _address(row, channel):
        address, size = row[channel+'addr'], row[channel+'size']
        if size > 2 or address % (1 << size):
            raise ProtocolEnvironmentError('reduced AXI unsupported size or alignment')
        return address, size

    def _ready_inputs(self):
        values = {name: 0 for name in STEP_PORTS}
        for prefix, state in self._state.items():
            values[prefix+'_arready'] = int(not self._quiescing and state['read'] is None)
            if prefix == 'd':
                values['d_awready'] = int((not self._quiescing or state['w'] is not None) and state['aw'] is None and state['b'] is None)
                values['d_wready'] = int((not self._quiescing or state['aw'] is not None) and state['w'] is None and state['b'] is None)
                if state['b'] is not None:
                    values['d_bvalid'], values['d_bid'] = 1, state['b']
            read = state['read']
            if read is not None:
                values.update({prefix+'_rvalid': 1, prefix+'_rid': read['id'],
                               prefix+'_rdata': read['data'], prefix+'_rlast': 1})
        return values

    def step_local(self, inputs: Mapping[str, int]):
        if not isinstance(inputs, Mapping) or inputs:
            raise ValueError('reduced AXI RAM session accepts no external inputs')
        values = self._ready_inputs()
        receipt = self.command('STEP_REDUCED_AXI', tuple(values[name] for name in STEP_PORTS))
        if receipt.status == 'error':
            raise ProtocolEnvironmentError(f'{receipt.error_code}: {receipt.error_detail}')
        payload = receipt.payload
        if (receipt.new_ticks != 1 or not isinstance(payload, dict)
                or payload.get('kind') != self.artifact_kind
                or not isinstance(payload.get('samples'), list) or len(payload['samples']) != 1):
            raise ProtocolEnvironmentError('reduced AXI receipt is not one measured edge')
        pre = payload.get('pre_backend')
        expected = {p+'_'+role: width for p, shape in SHAPES.items()
                    for role, (_, width) in shape.items()}
        if (not isinstance(pre, dict) or set(pre) != set(expected)
                or any(type(pre[name]) is not int or not 0 <= pre[name] < 1 << width
                       for name, width in expected.items())
                or any(pre[name] != value for name, value in values.items())
                or payload['samples'][0].get('pre', {}).get('backend') != pre):
            raise ProtocolEnvironmentError('invalid reduced AXI physical observation')
        self.last_samples = tuple(copy.deepcopy(payload['samples']))
        observed = {}
        for prefix, shape in SHAPES.items():
            row = {role: pre[prefix+'_'+role] for role in shape}
            state = self._state[prefix]
            def handshake(channel):
                return bool(row.get(channel+'valid', 0) and row.get(channel+'ready', 0))
            ar, r, aw, w, b = (handshake(c) for c in ('ar', 'r', 'aw', 'w', 'b'))
            if r:
                read = state['read']
                if (read is None or row['rid'] != read['id'] or row['rdata'] != read['data']
                        or row['rresp'] != 0 or row['rlast'] != 1):
                    raise ProtocolEnvironmentError('reduced AXI unmatched R response')
                state['read'] = None
                self.read_beats += 1
            if b:
                if state['b'] is None or row['bid'] != state['b'] or row['bresp'] != 0:
                    raise ProtocolEnvironmentError('reduced AXI unmatched B response')
                state['b'] = None
                self.write_responses += 1
            if ar:
                if state['read'] is not None:
                    raise ProtocolEnvironmentError('reduced AXI multiple outstanding AR')
                address, _ = self._address(row, 'ar')
                snapshot = self.service.read(self._key(prefix), address & ~3, width_bytes=4)
                state['read'] = {'id': row['arid'], 'data': snapshot.value}
            if aw:
                if state['aw'] is not None:
                    raise ProtocolEnvironmentError('reduced AXI multiple outstanding AW')
                address, size = self._address(row, 'aw')
                state['aw'] = {'address': address, 'size': size, 'id': row['awid']}
            if w:
                if state['w'] is not None or row['wlast'] != 1:
                    raise ProtocolEnvironmentError('reduced AXI extra W beat or missing WLAST')
                state['w'] = (row['wdata'], row['wstrb'])
            if state['aw'] is not None and state['w'] is not None:
                address, size = state['aw']['address'], state['aw']['size']
                data, strobe = state['w']
                allowed = ((1 << (1 << size))-1) << (address & 3)
                if strobe & ~allowed:
                    raise ProtocolEnvironmentError('reduced AXI strobe exceeds addressed lanes')
                self.service.write(self._key(prefix), address & ~3, data,
                                   width_bytes=4, byte_enable=strobe)
                state['b'] = state['aw']['id']
                state['aw'] = state['w'] = None
                self.write_beats += 1
            for name, accepted in [('ar', ar), ('r', r), ('aw', aw), ('w', w), ('b', b)]:
                observed[prefix+'_'+name+('_consumed' if name in ('r', 'b') else '_accepted')] = int(accepted)
        self.memory.advance_step()
        return {**observed, 'driver_samples': copy.deepcopy(self.last_samples),
                'physical_observations': copy.deepcopy(payload['observations']['physical'])}
