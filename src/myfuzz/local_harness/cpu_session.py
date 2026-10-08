"""Persistent host memory/router service for measured generated OBI CPU beats."""
from __future__ import annotations

import copy
import json
from dataclasses import asdict
import re
from collections.abc import Mapping
from pathlib import Path

from myfuzz.scenario.contracts import ProtocolEnvironmentError
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import InstructionNotReady, PersistentMemory
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
                 command_timeout_seconds: float = 10.0,
                 native_irq_receipts: bool = False,
                 memory_commit_receipts: bool = False,
                 memory_readback_receipts: bool = False):
        if type(native_irq_receipts) is not bool:
            raise ValueError('native_irq_receipts must be boolean')
        if type(memory_commit_receipts) is not bool:
            raise ValueError('memory_commit_receipts must be boolean')
        if type(memory_readback_receipts) is not bool:
            raise ValueError('memory_readback_receipts must be boolean')
        if native_irq_receipts:
            from .ibex_irq_receipt_contract import verify_ibex_irq_receipt_artifact
            irq_runtime_name = verify_ibex_irq_receipt_artifact(artifact, base_dir=base_dir)
        else:
            irq_runtime_name = None
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
        self.service = MemoryService(memory, TransactionLedger(),
            commit_stream_capacity=256 if memory_commit_receipts else None)
        self.memory_commit_receipts_enabled = memory_commit_receipts
        self.memory_readback_receipts_enabled = memory_readback_receipts
        self.memory_read_authority = None
        self.source_component = artifact.plan.request.instance_id
        self._pending_instr: tuple[int, int, int] | None = None
        self._waiting_instr: tuple[TransactionKey, int] | None = None
        self._pending_data: tuple[int, int, int] | None = None
        self._queued_mmio = False
        self._sequences = {'instr': 0, 'data': 0}
        self._quiescing = False
        self.memory_write_count = 0
        self.mmio_write_count = 0
        self.mmio_read_count = 0
        self.last_samples: tuple[dict, ...] = ()
        self.cpu_events: list[dict] = []
        self._started_cpu = False
        self._resetting_cpu = False
        self._request_evidence: dict[str, dict] = {}
        self._last_retire_order: tuple[int, int] | None = None
        self._native_irq_receipts = native_irq_receipts
        self._irq_runtime_name = irq_runtime_name
        self._next_irq_input_context = None
        self._active_irq_input_context = None
        self._native_irq_last_receipt = None
        self._native_irq_take_sequence = 0
        self._rvfi_enabled = getattr(getattr(artifact.plan, 'profile', None),
                                     'component_id', None) == 'ibex_rvfi_local'

    def identity_document(self) -> dict[str, object]:
        observation = ({'cpu_observation_schema_version': 'ibex_rvfi_observation.v1',
                        'cpu_retirement_sampling_edge': 'post_rising'}
                       if self._rvfi_enabled else {})
        if self.native_irq_receipts_enabled:
            from .ibex_irq_receipt_contract import ibex_irq_receipt_contract
            observation['cpu_native_irq_receipt_contract'] = ibex_irq_receipt_contract()
        if self.memory_commit_receipts_enabled:
            observation['memory_commit_stream'] = {
                'schema_version': 'memory_write_commit_stream.v1', 'capacity': 256}
        if self.memory_readback_receipts_enabled:
            observation['memory_read_issuance'] = {
                'schema_version': 'memory_read_authority.v1', 'capacity': 256}
        return {**super().identity_document(), **observation,
                'cpu_service_schema_version': 'generated_obi_cpu_service.v1',
                'source_component': self.source_component,
                'defer_mmio': self.defer_mmio}

    def begin_case(self, testcase_id: str) -> None:
        self._clear_native_irq_receipts()
        super().begin_case(testcase_id)
        if self.native_irq_receipts_enabled and not self._started_cpu:
            self._cpu_event('cpu_native_startup', schema_version='cpu_native_startup.v1',
                **self._native_reset_fields())
        if self._rvfi_enabled and self._started_cpu and not self._resetting_cpu:
            self.reset_epoch += 1
            self._cpu_event('cpu_reset', reason='fresh_process',
                **(self._native_reset_fields() if self.native_irq_receipts_enabled else {}))
        self._started_cpu = True
        self._request_evidence.clear()
        self._pending_instr = None
        self._waiting_instr = None
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
        return (int(self._pending_instr is not None or self._waiting_instr is not None) + int(self._pending_data is not None)
                + int(self._queued_mmio))

    @property
    def waiting_instruction_address(self) -> int | None:
        """Accepted fetch address waiting for an online instruction source."""
        return self._waiting_instr[1] if self._waiting_instr is not None else None

    def declare_instruction_slots(self, address: int, count: int = 1) -> None:
        self.memory.declare_instruction_slots(address, count)

    def accept_instructions(self, address: int, data: bytes, *, source_event_id: str) -> None:
        self.service.accept_instructions(address, data, source_event_id=source_event_id)
        self._resume_instruction()

    def _resume_instruction(self) -> None:
        if self._waiting_instr is None:
            return
        key, address = self._waiting_instr
        try:
            snapshot = self.service.read(key, address, width_bytes=4)
        except InstructionNotReady:
            return
        self._freeze_snapshot('instr', snapshot)
        self._pending_instr = (snapshot.value, 0, key.source_sequence)
        self._waiting_instr = None

    def begin_quiesce(self) -> None:
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError('generated CPU process is not running')
        self._quiescing = True

    def reset_local(self) -> dict[str, object]:
        self._clear_native_irq_receipts()
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError('generated CPU process is not running')
        cancelled = self.pending_responses
        targets = self.router.cancel_for_ledger(self.service.ledger)
        if self._queued_mmio and len(targets) != 1:
            raise RuntimeError('queued generated MMIO request was not cancelled')
        self._pending_instr = None
        self._waiting_instr = None
        self._pending_data = None
        self._queued_mmio = False
        self._sequences = {'instr': 0, 'data': 0}
        self._quiescing = False
        self.last_samples = ()
        self._request_evidence.clear()
        self._resetting_cpu = True
        try:
            reset_outcome = super().reset_local()
        finally:
            self._resetting_cpu = False
        self._cpu_event('cpu_reset', cancelled_responses=cancelled,
            **({**self._native_reset_fields(), 'reset_service_outcome':copy.deepcopy(reset_outcome)}
               if self.native_irq_receipts_enabled else {}))
        return {'cancelled_responses': cancelled,
                'cancelled_target_requests': tuple(str(key) for key in targets)}

    def _serve(self, channel: str, write: int, address: int,
               wdata: int, be: int) -> tuple[int, int, int] | None:
        key = self._key(channel)
        self._request_evidence[channel] = dict(transaction=asdict(key),
            raw_address=address, aligned_address=address & ~3, address=address,
            write=write, be=be, wdata=wdata, acceptance_tick=self.local_ticks)
        if channel == 'data':
            self._cpu_event('data_accept', **self._request_evidence[channel])
        if channel == 'instr' and write:
            raise ProtocolEnvironmentError('instruction port accepted a write')
        # The OBI CPU ports expose byte addresses while this 32-bit service
        # returns/stores a complete beat and relies on the CPU RTL to select
        # the requested byte lane. Keep the observed request address intact in
        # step_local's sample, but address backing memory and MMIO by the beat.
        beat_address = address & ~3
        if self.router.owns(beat_address):
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
                fresh = self.router.enqueue(self.service.ledger, key, address=beat_address,
                    write=bool(write), wdata=wdata, be=be, beat_bytes=4, callback=completed)
                if not fresh:
                    raise RuntimeError('duplicate generated CPU MMIO acceptance')
                self._queued_mmio = True
                return None
            response = self.router.transact(self.service.ledger, key, address=beat_address,
                write=bool(write), wdata=wdata, be=be, beat_bytes=4)
            if write:
                self.mmio_write_count += 1
            else:
                self.mmio_read_count += 1
            return response[0], response[1], key.source_sequence
        if write:
            self.service.write(key, beat_address, wdata, width_bytes=4, byte_enable=be)
            self.memory_write_count += 1
            return 0, 0, key.source_sequence
        try:
            if channel == 'data' and self.memory_readback_receipts_enabled:
                if self.memory_read_authority is None:
                    raise RuntimeError('memory readback authority is not installed')
                snapshot = self.memory_read_authority.read(
                    self.source_component, self.service, key, beat_address,
                    width_bytes=4)
            else:
                snapshot = self.service.read(key, beat_address, width_bytes=4)
        except InstructionNotReady:
            if channel != 'instr':
                raise ProtocolEnvironmentError('data request reached an unfilled instruction slot')
            self._waiting_instr = (key, beat_address)
            return None
        self._freeze_snapshot(channel, snapshot)
        return snapshot.value, 0, key.source_sequence

    def _cpu_event(self, kind: str, **fields) -> None:
        if self._rvfi_enabled:
            self.cpu_events.append(copy.deepcopy(dict(kind=kind, component=self.source_component,
                source_component=self.source_component, execution_id='local-execution',
                reset_epoch=self.reset_epoch, source_epoch=self.reset_epoch,
                tick=self.local_ticks, **fields)))

    def _freeze_snapshot(self, channel: str, snapshot) -> None:
        frozen = asdict(snapshot)
        frozen.pop('data')
        self._request_evidence[channel]['snapshot'] = {
            **frozen, 'value': snapshot.value, 'data_hex': snapshot.data.hex()}

    def _native_reset_fields(self):
        digest, asserted, released, _ = self._expected_ready()
        from .ibex_irq_receipt_contract import ibex_irq_receipt_contract
        return {'physical_reset':True, 'local_tick':self.local_ticks,
                'phase':'startup_ready',
                'command_scope':{'component':self.source_component,'reset_epoch':self.reset_epoch,'command_sequence':0},
                'receipt_id':{'execution':self._execution,'sequence':0},
                'observation_contract':ibex_irq_receipt_contract(),
                'artifact_digest':digest,
                'boot_base':self._artifact_document['boot_contract']['configured_boot_base'],
                'reset_outcome':{'schema_version':'native_cpu_reset_outcome.v1',
                    'assert_ticks':asserted, 'release_ticks':released,
                    'artifact_digest':digest,
                    'boot_base':self._artifact_document['boot_contract']['configured_boot_base'],
                    'source':'startup_ready'}}

    def _serial_observation(self, decision_physical: dict, retirement_physical: dict, *,
                            sampling: str, decision_phase: str,
                            retirement_phase: str) -> dict:
        """Versioned serial sideband measurement; a missing export stays unobservable.

        The session never invents a token: an artifact without the passive serial
        exports records None plus an explicit unobservable status, and a present
        but invalid physical value fails closed.
        """
        from .ibex_irq_receipt_contract import (IBEX_IRQ_SERIAL_DECISION_PORT,
            IBEX_IRQ_SERIAL_RETIREMENT_PORT, ibex_irq_serial_observation)
        try:
            return ibex_irq_serial_observation(sampling=sampling,
                decision_phase=decision_phase, retirement_phase=retirement_phase,
                decision_value=decision_physical.get(IBEX_IRQ_SERIAL_DECISION_PORT),
                retirement_value=retirement_physical.get(IBEX_IRQ_SERIAL_RETIREMENT_PORT))
        except ValueError as error:
            raise ProtocolEnvironmentError('invalid physical IRQ serial observation') from error

    def _native_retirement_receipt(self, receipt, physical):
        from .wire import DriverReceipt
        from .ibex_irq_receipt_contract import ibex_irq_receipt_contract
        identity = (self.reset_epoch, getattr(receipt,'execution',None),
                    getattr(receipt,'sequence',None), getattr(receipt,'tick_after',None))
        if (type(receipt) is not DriverReceipt or receipt.status != 'result'
                or type(receipt.execution) is not str or receipt.execution != self._execution
                or type(receipt.sequence) is not int or receipt.sequence != self._sequence
                or type(receipt.tick_after) is not int or type(receipt.tick_before) is not int
                or type(receipt.new_ticks) is not int or receipt.new_ticks != 1
                or receipt.tick_after != receipt.tick_before + 1
                or identity != self._native_irq_last_receipt
                or self._tick_base + receipt.tick_after != self.local_ticks):
            raise ProtocolEnvironmentError('native retirement parsed receipt mismatch')
        sample=receipt.payload['samples'][0]
        post=self._physical_outputs({'observations':sample['post']})
        rvfi={name:value for name,value in physical.items() if name.startswith('rvfi_')}
        actual={name:value for name,value in post.items() if name.startswith('rvfi_')}
        if (len(rvfi)!=44 or type(sample.get('local_tick')) is not int
                or sample['local_tick']!=receipt.tick_after
                or json.dumps(rvfi,sort_keys=True,allow_nan=False)!=json.dumps(actual,sort_keys=True,allow_nan=False)):
            raise ProtocolEnvironmentError('native retirement requires complete actual POST RVFI')
        scope={'component':self.source_component,'reset_epoch':self.reset_epoch,
               'command_sequence':receipt.sequence}
        return {'schema_version':'cpu_retire.v2','phase':'post','local_tick':self.local_ticks,
            'command_scope':scope,'receipt_id':{'execution':receipt.execution,'sequence':receipt.sequence},
            'receipt_ticks':{'tick_before':receipt.tick_before,'tick_after':receipt.tick_after,
                'new_ticks':receipt.new_ticks,'local_tick_base':self._tick_base},
            'actual_post_ref':{'command_scope':copy.deepcopy(scope),'local_tick':self.local_ticks,'phase':'post'},
            'observation_contract':ibex_irq_receipt_contract()}

    def _retire(self, physical: dict[str, int], receipt=None) -> None:
        measured=(self._native_retirement_receipt(receipt,physical)
                  if self.native_irq_receipts_enabled else {})
        if not self._rvfi_enabled or not physical.get('rvfi_valid'):
            return
        identity = (self.reset_epoch, physical['rvfi_order'])
        if self._last_retire_order is not None and self._last_retire_order[0] == self.reset_epoch:
            if identity[1] == self._last_retire_order[1]:
                return
            if identity[1] < self._last_retire_order[1]:
                raise ProtocolEnvironmentError('Ibex RVFI retirement order regressed in one epoch')
        self._last_retire_order = identity
        fields = {name.removeprefix('rvfi_'): value for name, value in physical.items()
                  if name.startswith('rvfi_')}
        self._cpu_event('cpu_retire', **fields, **measured,
                        irq_serial_observation=self._serial_observation(
                            physical, physical, sampling='post_rising',
                            decision_phase='post', retirement_phase='post'),
                        observation={'sampling_edge': 'post_rising', 'physical':
                                     {name: value for name, value in physical.items()
                                      if name.startswith('rvfi_')}})

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

    @property
    def native_irq_receipts_enabled(self) -> bool:
        return self._native_irq_receipts

    def _clear_native_irq_receipts(self):
        self._next_irq_input_context = None
        self._active_irq_input_context = None
        self._native_irq_last_receipt = None
        self._native_irq_take_sequence = 0

    def set_next_irq_input_context(self, context: dict | None) -> None:
        # Context is a detached planned reference. Actual input is always read
        # independently from the complete parsed CPU receipt.
        self._next_irq_input_context = None
        if context is None:
            return
        if not self.native_irq_receipts_enabled:
            raise ValueError('native IRQ receipts are disabled')
        keys = {'schema_version', 'binding_delivery_event_id', 'expected_input',
                'source_output_key', 'target_component', 'target_epoch'}
        if type(context) is not dict or set(context) != keys:
            raise ValueError('invalid native IRQ input context')
        key = context['source_output_key']
        if (type(context['schema_version']) is not str or context['schema_version'] != 'native_irq_input_context.v1'
                or type(context['binding_delivery_event_id']) is not int
                or not 0 < context['binding_delivery_event_id'] < 1 << 64
                or type(context['expected_input']) is not int or context['expected_input'] not in (0, 1)
                or type(context['target_component']) is not str or context['target_component'] != self.source_component
                or type(context['target_epoch']) is not int or context['target_epoch'] != self.reset_epoch
                or type(key) is not list or len(key) != 4
                or any(type(key[index]) is not str or not key[index].strip()
                       or key[index].strip() != key[index] or len(key[index]) > 128 for index in (0, 2))
                or type(key[1]) is not int or not 0 <= key[1] < 1 << 64
                or type(key[3]) is not int or not 0 <= key[3] < 1 << 64):
            raise ValueError('invalid native IRQ input context')
        self._next_irq_input_context = copy.deepcopy(context)

    def step_local(self, inputs: Mapping[str, int]) -> Mapping[str, object]:
        self._active_irq_input_context = self._next_irq_input_context
        self._next_irq_input_context = None
        try:
            return self._step_local(inputs)
        finally:
            self._next_irq_input_context = None
            self._active_irq_input_context = None

    def _native_irq_facts(self, receipt, values):
        from .wire import DriverReceipt
        from .ibex_irq_receipt_contract import ibex_irq_receipt_contract
        if (type(receipt) is not DriverReceipt or receipt.status != 'result'
                or type(receipt.execution) is not str or re.fullmatch(r'[0-9a-f]{32}', receipt.execution) is None
                or receipt.execution != self._execution
                or type(receipt.sequence) is not int or not 0 < receipt.sequence < 1 << 64
                or receipt.sequence != self._sequence
                or any(type(value) is not int for value in (receipt.tick_before, receipt.tick_after, receipt.new_ticks))
                or not 0 <= receipt.tick_before < receipt.tick_after < 1 << 64
                or receipt.tick_after != receipt.tick_before + 1 or receipt.new_ticks != 1):
            raise ProtocolEnvironmentError('invalid parsed native IRQ command receipt')
        sample = receipt.payload['samples'][0]
        if type(sample.get('local_tick')) is not int or sample['local_tick'] != receipt.tick_after:
            raise ProtocolEnvironmentError('native IRQ sample tick differs from parsed receipt')
        identity = (self.reset_epoch, receipt.execution, receipt.sequence, receipt.tick_after)
        previous = self._native_irq_last_receipt
        if previous is not None and (previous[:2] != identity[:2]
                or identity[2] <= previous[2] or identity[3] <= previous[3]):
            raise ProtocolEnvironmentError('native IRQ receipt reused or regressed')
        physical = []
        for phase in ('pre', 'post'):
            fields = sample.get(phase, {}).get('physical', {})
            actual = fields.get(self._irq_runtime_name)
            if type(actual) is not int or actual not in (0, 1) or actual != values[0]:
                raise ProtocolEnvironmentError('native IRQ actual physical input differs from command')
            physical.append(fields)
        context = self._active_irq_input_context
        if context is not None and (context['target_epoch'] != self.reset_epoch
                or context['expected_input'] != values[0]):
            raise ProtocolEnvironmentError('native IRQ planned context differs from actual command')
        decisions = {name: physical[0].get('probe_' + name)
                     for name in ('irq_masked_pre', 'irq_taken_pre')}
        if any(type(value) is not int or value not in (0, 1) for value in decisions.values()):
            raise ProtocolEnvironmentError('invalid native IRQ actual decision')
        decoded = [self._physical_outputs({'observations': sample[phase]}) for phase in ('pre', 'post')]
        names = tuple(ibex_irq_receipt_contract()['notification_widths'])
        before, after = ({name: decoded[index][name] for name in names} for index in (0, 1))
        tick = self._tick_base + receipt.tick_after
        if tick != self.local_ticks:
            raise ProtocolEnvironmentError('native IRQ parsed lifetime tick mismatch')
        scope = dict(component=self.source_component, reset_epoch=self.reset_epoch,
                     command_sequence=receipt.sequence)
        common = dict(local_tick=tick, phase='pre_post_rising', command_scope=scope,
            receipt_id={'execution':receipt.execution, 'sequence':receipt.sequence},
            receipt_ticks={'tick_before':receipt.tick_before,'tick_after':receipt.tick_after,
                'new_ticks':receipt.new_ticks,'local_tick_base':self._tick_base},
            expected_input=values[0], actual_pre_input=physical[0][self._irq_runtime_name],
            actual_post_input=physical[1][self._irq_runtime_name],
            input_context=copy.deepcopy(context), observation_contract=ibex_irq_receipt_contract(),
            notification_pre=before, notification_post=after,
            # The decision token is a combinational pre-edge observation; the
            # retirement token is read from the same edge's post sample.
            irq_serial_observation=self._serial_observation(
                decoded[0], decoded[1], sampling='pre_post_rising',
                decision_phase='pre', retirement_phase='post'),
            actual_post_ref={'command_scope':copy.deepcopy(scope),'local_tick':tick,'phase':'post'}, **decisions)
        if context is not None:
            common.update(binding_delivery_event_id=context['binding_delivery_event_id'],
                          source_output_key=copy.deepcopy(context['source_output_key']))
        records = [('cpu_external_irq_sample', common)]
        if decisions['irq_taken_pre'] == 1:
            records.append(('cpu_external_irq_taken', {**common,
                'sample_ref': {'command_scope':copy.deepcopy(scope), 'local_tick':tick},
                'take_key':[self.source_component,self.reset_epoch,self._native_irq_take_sequence+1]}))
        if after['rvfi_ext_irq_valid'] == 1:
            records.append(('cpu_irq_notification', {**common, 'phase':'post', **after}))
        return identity, records

    def _step_local(self, inputs: Mapping[str, int]) -> Mapping[str, object]:

        if not isinstance(inputs, Mapping) or set(inputs) - {'irq'}:
            raise ValueError('undeclared generated CPU input')
        irq = inputs.get('irq', 0)
        if type(irq) is not int or irq not in (0, 1):
            raise ValueError('generated CPU external IRQ must be zero or one')
        self._resume_instruction()
        ipending, dpending = self._pending_instr, self._pending_data
        values = (irq, int(ipending is None and self._waiting_instr is None and not self._quiescing), int(ipending is not None),
                  ipending[0] if ipending else 0, ipending[1] if ipending else 0,
                  int(dpending is None and not self._queued_mmio and not self._quiescing),
                  int(dpending is not None), dpending[0] if dpending else 0,
                  dpending[1] if dpending else 0)
        receipt = self.command('STEP_CPU', values)
        pre = self._validate_pre(receipt, values)
        native = self._native_irq_facts(receipt, values) if self.native_irq_receipts_enabled else None
        physical_outputs = self._physical_outputs(receipt.payload)
        self.last_samples = tuple(copy.deepcopy(receipt.payload['samples']))
        # IRQ acceptance is a combinational decision *before* the edge being
        # advanced.  The final physical snapshot is after that edge and may
        # already have cleared the pulse, so consume the driver's pre sample.
        if getattr(getattr(self.artifact.plan, 'profile', None), 'component_id', None) in ('ibex_obi_local', 'ibex_rvfi_local'):
            pre_physical = self.last_samples[0].get('pre', {}).get('physical', {})
            for name in ('irq_masked_pre', 'irq_taken_pre'):
                observed = pre_physical.get('probe_' + name)
                if type(observed) is not int or observed not in (0, 1):
                    raise ProtocolEnvironmentError('invalid Ibex pre-edge IRQ probe: ' + name)
                physical_outputs[name] = observed
        iconsumed = int(bool(pre['i_rsp_valid'] and pre['i_rsp_ready']))
        dconsumed = int(bool(pre['d_rsp_valid'] and pre['d_rsp_ready']))
        if iconsumed:
            if ipending is None:
                raise ProtocolEnvironmentError('instruction response without source request')
            self._cpu_event('instr_response', **self._request_evidence.pop('instr'),
                            rdata=ipending[0], error=ipending[1], response_tick=self.local_ticks)
            self._pending_instr = None
        if dconsumed:
            if dpending is None:
                raise ProtocolEnvironmentError('data response without source request')
            self._cpu_event('data_response', **self._request_evidence.pop('data'),
                            rdata=dpending[0], error=dpending[1], response_tick=self.local_ticks)
            self._pending_data = None
        iaccepted = int(bool(pre['i_req_valid'] and pre['i_req_ready']))
        daccepted = int(bool(pre['d_req_valid'] and pre['d_req_ready']))
        if iaccepted:
            self._pending_instr = self._serve('instr', pre['i_req_write'], pre['i_req_addr'],
                                              pre['i_req_wdata'], pre['i_req_be'])
        if daccepted:
            self._pending_data = self._serve('data', pre['d_req_write'], pre['d_req_addr'],
                                             pre['d_req_wdata'], pre['d_req_be'])
        if native is not None:
            self._native_irq_last_receipt = native[0]
            for kind, fields in native[1]:
                if kind == 'cpu_external_irq_taken':
                    self._native_irq_take_sequence += 1
                self._cpu_event(kind, schema_version=kind + '.v1', **fields)
        if self._rvfi_enabled:
            self._retire(self._physical_outputs({'observations': self.last_samples[0]['post']}),receipt=receipt)
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
