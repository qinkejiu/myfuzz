"""Persistent memory service for the pinned PicoRV32 classic Wishbone master.

The service serves every fetch from persistent memory and additionally
supports declared online instruction slots, exactly like the OBI CPU
session: a fetch of a declared but unmaterialised slot is accepted once,
answered only after a bound source materialises the word, and the response
is the session's own measured value.  ``wb_dat_w`` is don't-care on a
classic Wishbone read, so a read transaction never carries a write payload.
"""
from __future__ import annotations

import copy
import re
from collections.abc import Mapping
from pathlib import Path

from myfuzz.scenario.contracts import ProtocolEnvironmentError
from myfuzz.scenario.memory import InstructionNotReady
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.router import DataflowRouter
from .runtime_artifact import LocalRuntimeArtifact
from .session import GeneratedLocalSession


_LIMITS = {'wb_cyc': 1, 'wb_stb': 1, 'wb_we': 1, 'wb_adr': 0xffffffff,
           'wb_dat_w': 0xffffffff, 'wb_sel': 15, 'wb_ack': 1,
           'wb_dat_r': 0xffffffff}


class GeneratedWishboneCpuSession(GeneratedLocalSession):
    """Acknowledge each observed Wishbone request once after servicing it."""

    artifact_kind = 'wishbone_cpu'
    max_transaction_events_per_step = 1
    max_local_ticks_per_step = 1

    def __init__(self, artifact: LocalRuntimeArtifact, *, base_dir: Path,
                 cache_dir: Path, memory: PersistentMemory, router: DataflowRouter,
                 defer_mmio: bool = True, command_timeout_seconds: float = 10.0,
                 memory_commit_receipts: bool = False,
                 memory_readback_receipts: bool = False,
                 physical_tick_samples: bool = False,
                 custom_irq_observations: bool = False):
        if artifact.runtime_document.get('kind') != 'wishbone_cpu':
            raise ValueError('generated Wishbone CPU requires a Wishbone artifact')
        if not isinstance(memory, PersistentMemory) or not isinstance(router, DataflowRouter):
            raise ValueError('generated Wishbone CPU requires persistent memory and router')
        if type(defer_mmio) is not bool:
            raise ValueError('defer_mmio must be boolean')
        if any(type(flag) is not bool for flag in
               (memory_commit_receipts, memory_readback_receipts, physical_tick_samples, custom_irq_observations)):
            raise ValueError('CPU evidence options must be boolean')
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir,
                         command_timeout_seconds=command_timeout_seconds)
        from .cpu_session import rvfi_observation_contract
        self._rvfi_contract = rvfi_observation_contract(artifact)
        self._last_retire_order = None
        self.cpu_events = []
        self._custom_irq_contract = None
        if custom_irq_observations:
            from .profile_custom_irq import verify_custom_irq_artifact
            self._custom_irq_contract = verify_custom_irq_artifact(artifact, base_dir=base_dir)
        self.memory = memory
        self.router = router
        self.defer_mmio = defer_mmio
        self.max_mmio_target_accesses_per_step = 0 if defer_mmio else 1
        self.service = MemoryService(memory, TransactionLedger(),
            include_writer_kinds=memory_readback_receipts,
            commit_stream_capacity=256 if memory_commit_receipts else None)
        self.memory_commit_receipts_enabled = memory_commit_receipts
        self.memory_readback_receipts_enabled = memory_readback_receipts
        self.memory_read_authority = None
        self._physical_tick_samples_enabled = physical_tick_samples
        self._physical_tick_samples = []
        self._last_drained_physical_tick_samples = ()
        self.source_component = artifact.plan.request.instance_id
        self._pending: tuple[int, int, str] | None = None
        self._queued_mmio = False
        # Online instruction source: one accepted fetch waits for its word.
        self._online_instruction_slots = False
        self._waiting_fetch: tuple[TransactionKey, int] | None = None
        self._source_sequences = {'instr': 0, 'data': 0}
        self._quiescing = False
        self.memory_write_count = 0
        self.mmio_write_count = 0
        self.mmio_read_count = 0
        self.last_samples: tuple[dict, ...] = ()
        cpu = artifact.plan.profile.cpu
        self._irq_runtime_name = next((row['runtime_name']
            for row in self._artifact_document['physical_exports']
            if row['direction'] == 'input' and row['width'] == 32
            and cpu.irq_entry_endpoint is not None
            and row['endpoint_id'] == cpu.irq_entry_endpoint
            and row['role'] == cpu.irq_entry_role), None)

    def identity_document(self) -> dict[str, object]:
        observation = {}
        if self._custom_irq_contract is not None:
            observation['cpu_custom_irq_observation'] = {'schema_version':'custom_irq_observation.v1'}
        if self._rvfi_contract is not None:
            observation['cpu_observation_schema_version'] = self._rvfi_contract['schema_version']
            observation['cpu_retirement_sampling_edge'] = 'post_rising'
        if self.memory_commit_receipts_enabled:
            observation['memory_commit_stream'] = {'schema_version':'memory_write_commit_stream.v1','capacity':256}
        if self.memory_readback_receipts_enabled:
            observation['memory_read_issuance'] = {'schema_version':'memory_read_authority.v1','capacity':256}
        if self._physical_tick_samples_enabled:
            observation['cpu_physical_tick_stream'] = {
                'schema_version':'cpu_physical_tick_stream.v1','capacity':256,'sampling':'pre_post'}
        return {**super().identity_document(), **observation,
                'cpu_service_schema_version': 'generated_wishbone_cpu_service.v1',
                'source_component': self.source_component, 'defer_mmio': self.defer_mmio}

    def begin_case(self, testcase_id: str) -> None:
        super().begin_case(testcase_id)
        self._pending = None
        self._queued_mmio = False
        self._waiting_fetch = None
        self._source_sequences = {'instr': 0, 'data': 0}
        self._quiescing = False
        self.last_samples = ()
        self._physical_tick_samples.clear()
        self._last_drained_physical_tick_samples = ()
        self._last_retire_order = None

    @property
    def pending_responses(self) -> int:
        return int(self._pending is not None or self._queued_mmio
                   or self._waiting_fetch is not None)

    @property
    def waiting_instruction_address(self) -> int | None:
        """Accepted fetch address waiting for its online instruction source."""
        return None if self._waiting_fetch is None else self._waiting_fetch[1]

    def declare_instruction_slots(self, address: int, count: int = 1) -> None:
        """Reserve instruction slots that a bound source materialises later.

        Declaration must happen before the process starts; the physical
        instruction-identity observation is required because the accepted
        fetch channel is derived from that measured signal.
        """
        if self.process is not None or self._case_id is not None:
            raise RuntimeError(
                'native instruction slots require pre-start declaration')
        marker = self._artifact_document.get('instruction_identity_observation')
        if not marker:
            raise ValueError(
                'native online instructions require physical instruction identity')
        self.memory.declare_instruction_slots(address, count)
        self._online_instruction_slots = True

    def accept_instructions(self, address: int, data: bytes, *,
                            source_event_id: str):
        """Materialise one declared slot from a bound instruction source."""
        if not self._online_instruction_slots:
            raise ValueError('native instruction slots were not declared')
        return self.service.accept_instructions(address, data,
            source_event_id=source_event_id)

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
        self._pending = None
        self._queued_mmio = False
        self._waiting_fetch = None
        self._source_sequences = {'instr': 0, 'data': 0}
        self._quiescing = False
        self.last_samples = ()
        self._physical_tick_samples.clear()
        self._last_drained_physical_tick_samples = ()
        super().reset_local()
        return {'cancelled_responses': cancelled,
                'cancelled_target_requests': tuple(str(key) for key in targets)}

    def _physical(self, values: dict) -> dict[str, int]:
        raw = values['physical']
        decoded: dict[str, int] = {}
        for row in self._artifact_document['physical_exports']:
            if row['direction'] != 'output':
                continue
            value = raw.get(row['runtime_name'])
            width = row['width']
            if width > 64:
                if (type(value) is not str or len(value) != row['hex_digits']
                        or re.fullmatch(r'[0-9a-f]+', value) is None):
                    raise ProtocolEnvironmentError('invalid wide physical CPU observation')
                value = int(value, 16)
            if type(value) is not int or not 0 <= value < 1 << width:
                raise ProtocolEnvironmentError('invalid physical CPU observation width')
            name = row['physical_port']
            decoded[name] = decoded.get(name, 0) | value << row['bit_lo']
        return decoded

    def _observe_rvfi_retirement(self, physical):
        """Record only a valid, complete post-edge native RVFI observation."""
        if self._rvfi_contract is None or not physical.get('rvfi_valid'):
            return
        names = self._rvfi_contract['fields']
        if any(name not in physical or type(physical[name]) is not int
               or not 0 <= physical[name] < (1 << width) for name, width in names.items()):
            raise ProtocolEnvironmentError('incomplete declared POST RVFI observation')
        identity = (self.reset_epoch, physical['rvfi_order'])
        if self._last_retire_order is not None and self._last_retire_order[0] == self.reset_epoch:
            if identity[1] == self._last_retire_order[1]:
                return
            if identity[1] < self._last_retire_order[1]:
                raise ProtocolEnvironmentError('RVFI retirement order regressed in one epoch')
        self._last_retire_order = identity
        self.cpu_events.append(dict(kind='cpu_retire', component=self.source_component,
            source_component=self.source_component, execution_id='local-execution',
            reset_epoch=self.reset_epoch, source_epoch=self.reset_epoch, tick=self.local_ticks,
            **{name.removeprefix('rvfi_'):physical[name] for name in names},
            observation={'sampling_edge':'post_rising', 'physical':
                         {name:physical[name] for name in names}}))

    def _serve(self, *, instruction: bool, write: int, address: int,
               wdata: int, sel: int) -> None:
        if instruction and write:
            raise ProtocolEnvironmentError('Wishbone instruction fetch wrote memory')
        if not write:
            # ``wb_dat_w`` is don't-care on a classic Wishbone read: the pinned
            # PicoRV32 keeps driving the previous store data while ``we == 0``.
            # A routed read transaction therefore carries no write payload; the
            # measured level still appears in the beat sample.
            wdata = 0
        if not self._case_id:
            raise RuntimeError('generated CPU testcase is not running')
        channel = 'instr' if instruction else 'data'
        self._source_sequences[channel] += 1
        key = TransactionKey('local-execution', self._case_id, self.source_component,
                             self.reset_epoch, channel, self._source_sequences[channel])
        if self.router.owns(address):
            if instruction:
                raise ProtocolEnvironmentError('instruction fetch reached MMIO')
            if self.defer_mmio:
                def completed(response: tuple[int, int]) -> None:
                    self._pending = (response[0], key.source_sequence, channel)
                    self._queued_mmio = False
                    if write:
                        self.mmio_write_count += 1
                    else:
                        self.mmio_read_count += 1
                if not self.router.enqueue(self.service.ledger, key, address=address,
                    write=bool(write), wdata=wdata, be=sel if write else 15,
                    beat_bytes=4, callback=completed):
                    raise RuntimeError('duplicate generated CPU MMIO acceptance')
                self._queued_mmio = True
                return
            response = self.router.transact(self.service.ledger, key, address=address,
                write=bool(write), wdata=wdata, be=sel if write else 15, beat_bytes=4)
            if write:
                self.mmio_write_count += 1
            else:
                self.mmio_read_count += 1
            self._pending = (response[0], key.source_sequence, channel)
        elif write:
            self.service.write(key, address, wdata, width_bytes=4, byte_enable=sel)
            self.memory_write_count += 1
            self._pending = (0, key.source_sequence, channel)
        else:
            # PicoRV32 drives sel=0 for reads; the data bus still returns a full word.
            try:
                if not instruction and self.memory_readback_receipts_enabled:
                    if self.memory_read_authority is None:
                        raise RuntimeError('memory readback authority is not installed')
                    snapshot = self.memory_read_authority.read(self.source_component,
                        self.service, key, address, width_bytes=4)
                else:
                    snapshot = self.service.read(key, address, width_bytes=4)
            except InstructionNotReady:
                if not instruction:
                    raise ProtocolEnvironmentError(
                        'data request reached an unfilled instruction slot')
                # The fetch is accepted once and answered when the bound source
                # materialises the word.  No response is produced this tick.
                self._waiting_fetch = (key, address)
                return
            self._pending = (snapshot.value, key.source_sequence, channel)

    def step_local(self, inputs: Mapping[str, int]) -> Mapping[str, object]:
        if self._physical_tick_samples_enabled and len(self._physical_tick_samples) >= 256:
            raise RuntimeError('CPU physical tick stream capacity exceeded')
        # While a fetch waits for its word no further request may be accepted:
        # the base acceptance predicate is held off for exactly this step.
        quiescing = self._quiescing
        if self._waiting_fetch is not None:
            self._quiescing = True
        try:
            outputs = self._step_measured(inputs)
        finally:
            self._quiescing = quiescing
        self._resume_waiting_fetch()
        return outputs

    def drain_tick_samples(self) -> list[dict]:
        """Drain actual parsed Wishbone PRE/POST samples, preserving epoch ticks."""
        samples = self._physical_tick_samples
        self._physical_tick_samples = []
        if samples:
            self._last_drained_physical_tick_samples = tuple(copy.deepcopy(samples))
        return samples

    def _resume_waiting_fetch(self) -> None:
        waiting = self._waiting_fetch
        if waiting is None:
            return
        key, address = waiting
        if self.memory.instruction_slot_unmaterialized(address):
            return
        snapshot = self.service.read(key, address, width_bytes=4)
        self._waiting_fetch = None
        self._pending = (snapshot.value, key.source_sequence, 'instr')

    def _step_measured(self, inputs: Mapping[str, int]) -> Mapping[str, object]:
        allowed = {'irq'} if self._irq_runtime_name is not None else set()
        if not isinstance(inputs, Mapping) or set(inputs) - allowed:
            raise ValueError('undeclared generated Wishbone CPU input')
        irq = inputs.get('irq', 0)
        if type(irq) is not int or not 0 <= irq <= 0xffffffff:
            raise ValueError('invalid generated Wishbone CPU IRQ width')
        pending = self._pending
        ack = int(pending is not None)
        rdata = pending[0] if pending else 0
        receipt = (self.command('STEP_WISHBONE_IRQ', (ack, rdata, irq))
                   if self._irq_runtime_name is not None
                   else self.command('STEP_WISHBONE', (ack, rdata)))
        if receipt.status == 'error':
            message = f'{receipt.error_code}: {receipt.error_detail}'
            if receipt.error_code == 'protocol_environment':
                raise ProtocolEnvironmentError(message)
            raise RuntimeError(message)
        payload = receipt.payload
        if (receipt.new_ticks != 1 or not isinstance(payload, dict)
                or payload.get('kind') != 'wishbone_cpu'
                or not isinstance(payload.get('samples'), list)
                or len(payload['samples']) != 1):
            raise ProtocolEnvironmentError('generated Wishbone receipt is not one measured tick')
        pre = payload.get('pre_backend')
        if (not isinstance(pre, dict) or set(pre) != set(_LIMITS)
                or any(type(value) is not int or not 0 <= value <= _LIMITS[name]
                       for name, value in pre.items())
                or pre['wb_ack'] != ack or pre['wb_dat_r'] != rdata
                or payload['samples'][0].get('pre', {}).get('backend') != pre):
            raise ProtocolEnvironmentError('invalid generated Wishbone backend observation')
        pre_observation = payload['samples'][0]['pre']
        if (self._irq_runtime_name is not None
                and pre_observation.get('physical', {}).get(self._irq_runtime_name) != irq):
            raise ProtocolEnvironmentError('generated Wishbone IRQ observation mismatch')
        self._physical(pre_observation)
        marker = self._artifact_document['instruction_identity_observation']
        instruction = pre_observation['physical'].get(marker)
        if type(instruction) is not int or instruction not in (0, 1):
            raise ProtocolEnvironmentError('invalid Wishbone instruction observation')
        self.last_samples = tuple(copy.deepcopy(payload['samples']))
        if self._rvfi_contract is not None:
            self._observe_rvfi_retirement(self._physical(self.last_samples[0]['post']))
        custom_irq = {}
        if self._custom_irq_contract is not None:
            from .profile_custom_irq import observe_custom_irq
            sample = {**self.last_samples[0],
                      'local_tick': self._tick_base + self.last_samples[0]['local_tick']}
            custom_irq['custom_irq_observation'] = observe_custom_irq(self._custom_irq_contract, sample, irq)
        if self._physical_tick_samples_enabled:
            self._physical_tick_samples.extend(
                {**copy.deepcopy(sample), 'local_tick': self._tick_base + sample['local_tick']}
                for sample in self.last_samples)
        request = bool(pre['wb_cyc'] and pre['wb_stb'])
        consumed = int(bool(request and ack))
        if ack and not request:
            raise ProtocolEnvironmentError('Wishbone response without active request')
        if consumed:
            self._pending = None
        accepted = int(bool(request and pending is None and not self._queued_mmio and not self._quiescing))
        if accepted:
            self._serve(instruction=bool(instruction), write=pre['wb_we'],
                address=pre['wb_adr'], wdata=pre['wb_dat_w'], sel=pre['wb_sel'])
        self.memory.advance_step()
        channel = pending[2] if consumed else ('instr' if instruction else 'data')
        return {**custom_irq, **self._physical(payload['observations']),
                'instr_req_valid': int(request and channel == 'instr'),
                'instr_req_accepted': int(accepted and channel == 'instr'),
                'instr_addr': pre['wb_adr'] if channel == 'instr' else 0,
                'instr_rsp_consumed': int(consumed and channel == 'instr'),
                'data_req_valid': int(request and channel == 'data'),
                'data_req_accepted': int(accepted and channel == 'data'),
                'data_write': pre['wb_we'] if channel == 'data' else 0,
                'data_addr': pre['wb_adr'] if channel == 'data' else 0,
                'data_wdata': pre['wb_dat_w'] if channel == 'data' else 0,
                'data_be': pre['wb_sel'] if channel == 'data' else 0,
                'data_rsp_consumed': int(consumed and channel == 'data'),
                'data_rsp_rdata': rdata if consumed and channel == 'data' else 0,
                'data_rsp_source_epoch': self.reset_epoch if consumed and channel == 'data' else 0,
                'data_rsp_source_sequence': pending[1] if consumed and channel == 'data' else 0,
                'driver_samples': copy.deepcopy(self.last_samples),
                'physical_observations': copy.deepcopy(payload['observations']['physical'])}
