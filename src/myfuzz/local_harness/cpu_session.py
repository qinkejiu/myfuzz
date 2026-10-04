"""Persistent host memory/router service for measured generated OBI CPU beats."""
from __future__ import annotations

import copy
import re
from collections.abc import Mapping
from pathlib import Path

from myfuzz.scenario.contracts import ProtocolEnvironmentError
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.router import DataflowRouter
from .runtime_artifact import LocalRuntimeArtifact
from .session import GeneratedLocalSession


_CONTROL_NAMES = ('i_req_ready', 'i_rsp_valid', 'i_rsp_rdata', 'i_rsp_error',
                  'd_req_ready', 'd_rsp_valid', 'd_rsp_rdata', 'd_rsp_error')
_BACKEND_LIMITS = {
    prefix + '_' + role: (0xffffffff if role in ('req_addr', 'req_wdata', 'rsp_rdata')
                         else 15 if role == 'req_be' else 1)
    for prefix in ('i', 'd')
    for role in ('req_valid', 'req_ready', 'req_write', 'req_addr', 'req_wdata',
                 'req_be', 'rsp_valid', 'rsp_ready', 'rsp_rdata', 'rsp_error')
}


class GeneratedCve2Session(GeneratedLocalSession):
    """Advance real OBI CPU RTL once; service each accepted request exactly once.

    The artifact selects physical signals and boot behavior. No instruction,
    IRQ masking or retirement behavior is inferred by the host memory service.
    Deferred MMIO executes only through a registered target's scheduler step.
    """

    artifact_kind = 'obi_cpu'
    max_transaction_events_per_step = 2
    max_local_ticks_per_step = 1

    def __init__(self, artifact: LocalRuntimeArtifact, *, base_dir: Path,
                 cache_dir: Path, memory: PersistentMemory,
                 router: DataflowRouter, defer_mmio: bool = True,
                 command_timeout_seconds: float = 10.0):
        if artifact.runtime_document.get('kind') != 'obi_cpu':
            raise ValueError('generated CPU requires an OBI CPU artifact')
        if not isinstance(memory, PersistentMemory) or not isinstance(router, DataflowRouter):
            raise ValueError('generated CPU requires persistent memory and router')
        if type(defer_mmio) is not bool:
            raise ValueError('defer_mmio must be boolean')
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir,
                         command_timeout_seconds=command_timeout_seconds)
        self.memory = memory
        self.router = router
        self.defer_mmio = defer_mmio
        self.max_mmio_target_accesses_per_step = 0 if defer_mmio else 1
        self.service = MemoryService(memory, TransactionLedger())
        self.source_component = artifact.plan.request.instance_id
        self._pending_instr: tuple[int, int, int] | None = None
        self._pending_data: tuple[int, int, int] | None = None
        self._queued_mmio = False
        self._sequences = {'instr': 0, 'data': 0}
        self._quiescing = False
        self.memory_write_count = 0
        self.mmio_write_count = 0
        self.mmio_read_count = 0
        self.last_samples: tuple[dict, ...] = ()

    def identity_document(self) -> dict[str, object]:
        return {**super().identity_document(),
                'cpu_service_schema_version': 'generated_obi_cpu_service.v1',
                'source_component': self.source_component,
                'defer_mmio': self.defer_mmio}

    def begin_case(self, testcase_id: str) -> None:
        super().begin_case(testcase_id)
        self._pending_instr = None
        self._pending_data = None
        self._queued_mmio = False
        self._sequences = {'instr': 0, 'data': 0}
        self._quiescing = False
        self.last_samples = ()

    def _key(self, channel: str) -> TransactionKey:
        if not self._case_id:
            raise RuntimeError('generated CPU testcase is not running')
        self._sequences[channel] += 1
        return TransactionKey('local-execution', self._case_id, self.source_component,
                              self.reset_epoch, channel, self._sequences[channel])

    @property
    def pending_responses(self) -> int:
        return (int(self._pending_instr is not None) + int(self._pending_data is not None)
                + int(self._queued_mmio))

    def begin_quiesce(self) -> None:
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError('generated CPU process is not running')
        self._quiescing = True

    def reset_local(self) -> dict[str, object]:
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError('generated CPU process is not running')
        cancelled = self.pending_responses
        targets = self.router.cancel_for_ledger(self.service.ledger)
        if self._queued_mmio and len(targets) != 1:
            raise RuntimeError('queued generated MMIO request was not cancelled')
        self._pending_instr = None
        self._pending_data = None
        self._queued_mmio = False
        self._sequences = {'instr': 0, 'data': 0}
        self._quiescing = False
        self.last_samples = ()
        super().reset_local()
        return {'cancelled_responses': cancelled,
                'cancelled_target_requests': tuple(str(key) for key in targets)}

    def _serve(self, channel: str, write: int, address: int,
               wdata: int, be: int) -> tuple[int, int, int] | None:
        key = self._key(channel)
        if channel == 'instr' and write:
            raise ProtocolEnvironmentError('instruction port accepted a write')
        if self.router.owns(address):
            if channel == 'instr':
                raise ProtocolEnvironmentError('instruction fetch reached MMIO')
            if self.defer_mmio:
                def completed(response: tuple[int, int]) -> None:
                    self._pending_data = (response[0], response[1], key.source_sequence)
                    self._queued_mmio = False
                    if write:
                        self.mmio_write_count += 1
                    else:
                        self.mmio_read_count += 1
                fresh = self.router.enqueue(self.service.ledger, key, address=address,
                    write=bool(write), wdata=wdata, be=be, beat_bytes=4, callback=completed)
                if not fresh:
                    raise RuntimeError('duplicate generated CPU MMIO acceptance')
                self._queued_mmio = True
                return None
            response = self.router.transact(self.service.ledger, key, address=address,
                write=bool(write), wdata=wdata, be=be, beat_bytes=4)
            if write:
                self.mmio_write_count += 1
            else:
                self.mmio_read_count += 1
            return response[0], response[1], key.source_sequence
        if write:
            self.service.write(key, address, wdata, width_bytes=4, byte_enable=be)
            self.memory_write_count += 1
            return 0, 0, key.source_sequence
        snapshot = self.service.read(key, address, width_bytes=4)
        return snapshot.value, 0, key.source_sequence

    @staticmethod
    def _validate_pre(receipt, values: tuple[int, ...]) -> dict[str, int]:
        if receipt.status == 'error':
            message = f'{receipt.error_code}: {receipt.error_detail}'
            if receipt.error_code == 'protocol_environment':
                raise ProtocolEnvironmentError(message)
            raise RuntimeError(message)
        payload = receipt.payload
        if (receipt.new_ticks != 1 or not isinstance(payload, dict)
                or payload.get('kind') != 'obi_cpu'
                or not isinstance(payload.get('samples'), list) or len(payload['samples']) != 1):
            raise ProtocolEnvironmentError('generated CPU receipt is not one measured tick')
        pre = payload.get('pre_backend')
        if (not isinstance(pre, dict) or set(pre) != set(_BACKEND_LIMITS)
                or any(type(value) is not int or not 0 <= value <= _BACKEND_LIMITS[name]
                       for name, value in pre.items())):
            raise ProtocolEnvironmentError('invalid generated CPU backend fields')
        sample = payload['samples'][0]
        if (sample.get('pre', {}).get('backend') != pre
                or any(pre[name] != value for name, value in zip(_CONTROL_NAMES, values[1:]))):
            raise ProtocolEnvironmentError('generated CPU handshake observation differs from command')
        return pre

    def _physical_outputs(self, payload: dict) -> dict[str, int]:
        """Decode admitted physical output spans, preserving their raw bit offsets."""
        physical = payload['observations']['physical']
        result = {}
        for row in self._artifact_document['physical_exports']:
            if row['direction'] != 'output':
                continue
            width = row['width']
            value = physical.get(row['runtime_name'])
            if width > 64:
                if (type(value) is not str or len(value) != row['hex_digits']
                        or re.fullmatch(r'[0-9a-f]+', value) is None):
                    raise ProtocolEnvironmentError('invalid wide physical CPU observation')
                value = int(value, 16)
            if type(value) is not int or not 0 <= value < 1 << width:
                raise ProtocolEnvironmentError('invalid physical CPU observation width')
            name = row['physical_port']
            result[name] = result.get(name, 0) | value << row['bit_lo']
        return result

    def step_local(self, inputs: Mapping[str, int]) -> Mapping[str, object]:
        if not isinstance(inputs, Mapping) or set(inputs) - {'irq'}:
            raise ValueError('undeclared generated CPU input')
        irq = inputs.get('irq', 0)
        if type(irq) is not int or irq not in (0, 1):
            raise ValueError('generated CPU external IRQ must be zero or one')
        ipending, dpending = self._pending_instr, self._pending_data
        values = (irq, int(ipending is None and not self._quiescing), int(ipending is not None),
                  ipending[0] if ipending else 0, ipending[1] if ipending else 0,
                  int(dpending is None and not self._queued_mmio and not self._quiescing),
                  int(dpending is not None), dpending[0] if dpending else 0,
                  dpending[1] if dpending else 0)
        receipt = self.command('STEP_CPU', values)
        pre = self._validate_pre(receipt, values)
        physical_outputs = self._physical_outputs(receipt.payload)
        self.last_samples = tuple(copy.deepcopy(receipt.payload['samples']))
        iconsumed = int(bool(pre['i_rsp_valid'] and pre['i_rsp_ready']))
        dconsumed = int(bool(pre['d_rsp_valid'] and pre['d_rsp_ready']))
        if iconsumed:
            if ipending is None:
                raise ProtocolEnvironmentError('instruction response without source request')
            self._pending_instr = None
        if dconsumed:
            if dpending is None:
                raise ProtocolEnvironmentError('data response without source request')
            self._pending_data = None
        iaccepted = int(bool(pre['i_req_valid'] and pre['i_req_ready']))
        daccepted = int(bool(pre['d_req_valid'] and pre['d_req_ready']))
        if iaccepted:
            self._pending_instr = self._serve('instr', pre['i_req_write'], pre['i_req_addr'],
                                              pre['i_req_wdata'], pre['i_req_be'])
        if daccepted:
            self._pending_data = self._serve('data', pre['d_req_write'], pre['d_req_addr'],
                                             pre['d_req_wdata'], pre['d_req_be'])
        self.memory.advance_step()
        return {**physical_outputs, 'instr_req_valid': pre['i_req_valid'], 'instr_req_accepted': iaccepted,
                'instr_addr': pre['i_req_addr'], 'instr_rsp_consumed': iconsumed,
                'data_req_valid': pre['d_req_valid'], 'data_req_accepted': daccepted,
                'data_write': pre['d_req_write'], 'data_addr': pre['d_req_addr'],
                'data_wdata': pre['d_req_wdata'], 'data_be': pre['d_req_be'],
                'data_rsp_consumed': dconsumed,
                'data_rsp_rdata': dpending[0] if dconsumed else 0,
                'data_rsp_source_epoch': self.reset_epoch if dconsumed else 0,
                'data_rsp_source_sequence': dpending[2] if dconsumed else 0,
                'driver_samples': copy.deepcopy(self.last_samples),
                'physical_observations': copy.deepcopy(receipt.payload['observations']['physical'])}
