"""Admission from retained live authority and current installed host RAM only.

Historical read certificates stay historical. Saved receipt ingestion cannot
enroll or restore an active byte. Queries inspect one cell without a read effect.
"""
from .memory_dependency_evidence import MemoryDependencyEvidenceConsumer
from .source_actions import (CrossCaseEffectTracker, EffectWitness, SourceActionGate,
                             InstructionSlotReservationGate, SourceAction,
                             TerminationObservation, DynamicPrerequisiteBinder,
                             TrustedRamByteDeclaration, BoundWitness, DynamicEffectBinding,
                             DynamicBindingRefused, ram_commit_evidence_ref)
from types import SimpleNamespace
from dataclasses import replace


class LiveMemoryEffectTracker(CrossCaseEffectTracker):
    def __init__(self, *, consumer, max_slots=512):
        if type(consumer) is not MemoryDependencyEvidenceConsumer:
            raise ValueError('actual installed memory evidence consumer required')
        super().__init__(max_effects=consumer._bounds['max_writer_versions'],
                         max_age_events=consumer._bounds['max_event_gap'], max_slots=max_slots)
        self._consumer = consumer
        self._commit_authority = consumer._commit_authority
        self._read_authority = consumer._read_authority
        self._authority_registries = (
            (self._commit_authority, dict(self._commit_authority._installed)),
            (self._read_authority, dict(self._read_authority._installed)))
        self._installed = dict(consumer._commit_authority._installed)
        memories = {}
        for _, _, memory, ids in self._installed.values():
            for memory_id in ids:
                if memory_id in memories and memories[memory_id] is not memory:
                    raise ValueError('ambiguous persistent memory id across actual services')
                memories[memory_id] = memory
        self._memories = memories
        self._reset_floor = 0
        self._slot_policy = None

    def ingest(self, events, *, case_id=None):
        """Receipt observation supplies no authority and cannot restore witnesses."""
        return ()

    def register_instruction_slot(self, component, address, reservation_ref, *, event_id, count=1):
        created = super().register_instruction_slot(component, address, reservation_ref,
                                                     event_id=event_id, count=count)
        installed = self._installed.get(component)
        if installed is None:
            return created
        # Only newly created reservations acquire the current physical generation.
        # Idempotent registration cannot renew a retained old reservation.
        bound = tuple(replace(witness, version=(installed[2].generation, 0), witness_id='')
                      for witness in created)
        for witness in bound:
            words = self._slots.get(component)
            if words is not None and witness.subject['address'] in words:
                words[witness.subject['address']] = witness
        return bound

    def consume_event(self, event):
        self._cursor = max(self._cursor, self._consumer._last_id)
        if not self._consumer._integrity:
            self._degraded = True
        if event.get('kind') in ('reset_barrier', 'cpu_reset', 'uart_reset'):
            self.reset(event_id=self._cursor)

    def reset(self, *, event_id, reason='reset_barrier'):
        # A reset can invalidate retained proof but never heal uncertainty.
        if type(event_id) is not int or event_id < 0:
            raise ValueError('invalid live memory reset event')
        self._reset_floor = max(self._reset_floor, event_id)
        self._cursor = max(self._cursor, event_id)
        self._epoch += 1
        self._retire_floor = max(self._retire_floor, event_id)
        self._slots.clear()

    def _authority_available(self):
        if (self._consumer._commit_authority is not self._commit_authority
                or self._consumer._read_authority is not self._read_authority
                or self._commit_authority.degraded or self._read_authority.degraded):
            self._degraded = True
        for authority, expected in self._authority_registries:
            installed = authority._installed
            if (type(installed) is not dict or set(installed) != set(expected)
                    or any(type(installed[c]) is not tuple
                           or len(installed[c]) != len(row)
                           or any(actual is not pinned
                                  for actual, pinned in zip(installed[c][:3], row[:3]))
                           or installed[c][3:] != row[3:]
                           for c, row in expected.items())):
                self._degraded = True
        return not self._degraded

    def _live_witnesses(self, memory_id, byte_offset):
        self._authority_available()
        if self._degraded or not self._consumer._integrity:
            return ()
        for service, ledger, memory, _ in self._installed.values():
            if service.ledger is not ledger or service.memory is not memory:
                self._degraded = True
                return ()
        memory = self._memories.get(memory_id)
        cell = memory.inspect_byte(memory_id, byte_offset) if memory is not None else None
        if cell is None or cell.writer_kind != 'STORE':
            return ()
        rows = []
        for identity, writer in self._consumer._writers.items():
            _, region, generation, offset, version, writer_id = identity
            if (region == memory_id and offset == byte_offset and generation == memory.generation
                    and version == cell.version and writer_id == cell.writer_event_id
                    and writer['value'] == cell.value and writer['event_id'] > self._reset_floor
                    and self._cursor - writer['event_id'] <= self.max_age_events):
                rows.append(EffectWitness('ram_byte_version',
                    {'memory_id': region, 'generation': generation, 'byte_offset': offset},
                    ram_commit_evidence_ref(writer['commit_id']), writer['event_id'],
                    version, cell.value, writer['fullkey']['testcase_id']))
        return tuple(sorted(rows, key=lambda w: (w.event_id, w.subject['generation'],
                                                w.evidence_ref), reverse=True))

    def _match(self, prerequisite):
        if prerequisite.kind == 'instruction_slot_unmaterialized' and self._slot_policy is not None:
            if not self._authority_available() or not self._consumer._integrity:
                self._degraded = True
                return None, 'uncertain_live_instruction_slot'
            component, address = prerequisite.subject['component'], prerequisite.subject['address']
            policy = self._slot_policy
            installed = self._installed.get(component)
            if (installed is None or component != policy.component
                    or not policy.first_address <= address < policy.last_address):
                return None, 'undeclared_live_instruction_slot'
            service, ledger, memory, _ = installed
            if service.ledger is not ledger or service.memory is not memory:
                self._degraded = True
                return None, 'changed_installed_instruction_memory'
            reservation = self._slots.get(component, {}).get(address)
            if reservation is None or reservation.version != (memory.generation, 0):
                return None, 'no_current_generation_instruction_reservation'
            if not memory.instruction_slot_unmaterialized(address):
                return None, 'materialized_or_undeclared_instruction_slot'
            return super()._match(prerequisite)
        if prerequisite.kind != 'ram_byte_version':
            return None, 'unsupported_live_memory_prerequisite'
        for witness in self._live_witnesses(prerequisite.subject['memory_id'],
                                             prerequisite.subject['byte_offset']):
            if witness.subject == prerequisite.subject and witness.evidence_ref == prerequisite.evidence_ref:
                return witness, 'satisfied'
        return None, 'no_retained_live_memory_byte'

    def retained_ram_witnesses(self, memory_id, byte_offset):
        if type(memory_id) is not str or not memory_id or type(byte_offset) is not int or byte_offset < 0:
            raise ValueError('invalid RAM witness query')
        return self._live_witnesses(memory_id, byte_offset)

    def document(self):
        self._authority_available()
        return dict(schema_version='live_memory_effect_tracker.v1',
            proof_scope='current_installed_host_memory_bytes', cursor=self._cursor,
            epoch=self._epoch, reset_floor=self._reset_floor,
            degraded=self._degraded or not self._consumer._integrity,
            retained_authority_writer_versions=len(self._consumer._writers),
            max_writer_versions=self.max_effects, max_event_gap=self.max_age_events,
            receipt_ingestion_grants=False)


class LiveMemoryDynamicPrerequisiteBinder(DynamicPrerequisiteBinder):
    """Bind unchanged payloads using only actual retained current STORE cells.

    STORE is a host memory writer kind; it grants no instruction retirement or
    upstream source origin. Receipt labels cannot enroll writer provenance.
    """

    def __init__(self, tracker, declaration, *, max_provenance=None, **kwargs):
        if (type(tracker) is not LiveMemoryEffectTracker
                or type(declaration) is not TrustedRamByteDeclaration
                or declaration.writer_kinds != ('STORE',)
                or len(declaration.byte_offsets) > 256):
            raise ValueError('bounded actual memory STORE declaration required')
        memory = tracker._memories.get(declaration.memory_id)
        if memory is None:
            raise ValueError('declaration requires actual installed memory')
        region = next(region for region in memory._regions if region.memory_id == declaration.memory_id)
        for offset in declaration.byte_offsets:
            if offset >= region.size:
                raise ValueError('binding declaration outside actual memory region')
            memory.inspect_byte(declaration.memory_id, offset)
        if max_provenance is not None and (type(max_provenance) is not int
                or not 1 <= max_provenance <= 65536):
            raise ValueError('invalid live binding provenance capacity')
        super().__init__(tracker, declaration, max_provenance=max_provenance, **kwargs)

    def observe(self, receipt):
        """Saved or actual receipt projections are never enrollment authority."""
        return ()

    def _record_provenance(self, events):
        return None

    def _refresh_live_provenance(self, memory_id, byte_offset):
        if not self.declaration.allows(memory_id, byte_offset):
            return
        for witness in self.tracker.retained_ram_witnesses(memory_id, byte_offset):
            key = (memory_id, byte_offset, witness.evidence_ref, witness.event_id)
            self._provenance[key] = 'STORE'
            self._provenance.move_to_end(key)
            while len(self._provenance) > self.max_provenance:
                self._provenance.popitem(last=False)
                self._counters['provenance_evictions'] += 1

    def _select(self, memory_id, byte_offset, effective, require_value):
        self._refresh_live_provenance(memory_id, byte_offset)
        return super()._select(memory_id, byte_offset, effective, require_value)

    def _verify(self, claim, action):
        document = (claim.document()['bound_witness'] if isinstance(claim, DynamicEffectBinding)
                    else claim.document() if isinstance(claim, BoundWitness) else claim)
        if document is not None:
            proof = BoundWitness.from_document(document)
            self._refresh_live_provenance(proof.memory_id, proof.byte_offset)
        verified = super()._verify(claim, action)
        live = self.tracker.retained_ram_witnesses(verified.memory_id, verified.byte_offset)
        if not any(w.evidence_ref == verified.evidence_ref and w.event_id == verified.event_id
                   and w.version == verified.version for w in live):
            raise DynamicBindingRefused('unretained_evidence', 'claim version differs from actual current writer')
        consumer_action = claim.action if isinstance(claim, DynamicEffectBinding) and action is None else action
        if consumer_action is not None and verified.action_id != consumer_action.action_id:
            raise DynamicBindingRefused('action_mismatch', 'claim action identity differs from consumer action')
        return verified


class PersistentMemoryPrerequisiteGate(SourceActionGate):
    def __init__(self, *, consumer, max_actions=256, instruction_slot_policy=None):
        if type(max_actions) is not int or not 1 <= max_actions <= 65536:
            raise ValueError('invalid persistent prerequisite action capacity')
        words = 512
        if instruction_slot_policy is not None:
            p = instruction_slot_policy
            if (type(p) is not dict or set(p) != {'component', 'first_address', 'last_address', 'reservation_ref_prefix'}
                    or type(p['component']) is not str or p['component'] not in consumer._commit_authority._installed
                    or type(p['first_address']) is not int or type(p['last_address']) is not int
                    or not 0 <= p['first_address'] < p['last_address'] < 1 << 64
                    or p['first_address'] % 4 or p['last_address'] % 4
                    or type(p['reservation_ref_prefix']) is not str
                    or not 0 < len(p['reservation_ref_prefix']) <= 256):
                raise ValueError('invalid installed instruction slot policy')
            words = (p['last_address'] - p['first_address']) // 4
            if words > 65536:
                raise ValueError('instruction slot capacity exceeded')
            memory = consumer._commit_authority._installed[p['component']][2]
            first = memory.resolve_span(p['first_address'], 4)
            last = memory.resolve_span(p['last_address'] - 4, 4)
            if (first[:2] != last[:2]
                    or last[2] != first[2] + p['last_address'] - p['first_address'] - 4):
                raise ValueError('instruction slot policy crosses actual memory span')
        super().__init__(tracker=LiveMemoryEffectTracker(consumer=consumer, max_slots=words), enforce=True)
        self.max_actions = max_actions
        self._support_instructions = {}
        self._registration_declarations = {}
        self._slot_policy = (InstructionSlotReservationGate(gate=self, **instruction_slot_policy)
                             if instruction_slot_policy is not None else None)
        self.tracker._slot_policy = self._slot_policy

    def register(self, action):
        if getattr(action, 'action_id', None) not in self._actions and len(self._actions) >= self.max_actions:
            raise ValueError('persistent prerequisite action capacity exceeded')
        bound = self._slot_policy._bind(action) if self._slot_policy is not None else action
        registered = super().register(bound)
        if self._slot_policy is not None:
            self._slot_policy._reserve(registered)
        self._registration_declarations[registered.action_id] = action
        return registered

    def replay_case_declaration(self, case):
        action_id = case.source.action_id
        action = self._resolve(action_id)
        original = self._registration_declarations[action_id]
        binding_reader = getattr(self, 'dynamic_binding_for_action', None)
        return dict(schema_version='persistent_memory_case_admission.v1',
                    source_action=original.document(), admitted_action=action.document(),
                    support_actions=[self._resolve(fragment.action_id).document()
                                     for fragment in case.support_instructions],
                    dynamic_binding=binding_reader(action_id) if binding_reader is not None else None)

    def validate_replay_case_declaration(self, case, declaration):
        """Validate saved input structure without enrolling any authority."""
        if (type(declaration) is not dict or set(declaration) != {
                'schema_version', 'source_action', 'admitted_action', 'support_actions', 'dynamic_binding'}
                or declaration['schema_version'] != 'persistent_memory_case_admission.v1'
                or type(declaration['support_actions']) is not list
                or len(declaration['support_actions']) != len(case.support_instructions)
                or len(case.support_instructions) > self.max_actions):
            raise ValueError('invalid saved persistent memory case declaration')
        action = SourceAction.from_document(declaration['source_action'])
        if action.ownership != 'fuzzable' or action.action_id != case.source.action_id:
            raise ValueError('saved primary action disagrees with case')
        self._assert_case_input(action, case.source)
        SourceAction.from_document(declaration['admitted_action'])
        for expected in declaration['support_actions']:
            SourceAction.from_document(expected)
        if declaration['dynamic_binding'] is not None:
            DynamicEffectBinding.from_document(declaration['dynamic_binding'])
        return action

    def register_replay_case(self, case, declaration):
        """Recompute saved decisions using current actual authority before commands."""
        import json
        action = self.validate_replay_case_declaration(case, declaration)
        self.register(action)
        for fragment in case.support_instructions:
            self.register_support_instruction(fragment, flow_id=action.flow_id,
                                              local_step_budget=action.local_step_budget)
        actual = self.replay_case_declaration(case)
        canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'))
        if canonical(actual) != canonical(declaration):
            raise ValueError('saved admission differs from actual recomputed decision')
        return self.require_case(case)

    @property
    def instruction_slot_policy(self):
        return self._slot_policy.declaration() if self._slot_policy is not None else None

    def register_support_instruction(self, fragment, *, flow_id, local_step_budget):
        from .session_runtime import OnlineInstruction
        if (type(fragment) is not OnlineInstruction or self._slot_policy is None
                or fragment.component != self._slot_policy.component
                or fragment.data != b'\x13\x00\x00\x00' * (len(fragment.data) // 4)):
            raise ValueError('declared fixed NOP support fragment required')
        if fragment.action_id not in self._actions and len(self._actions) >= self.max_actions:
            raise ValueError('persistent prerequisite action capacity exceeded')
        # Reuse exact window/word binding, then remove all mutable payload.
        template = SourceAction(action_id=fragment.action_id, kind='instruction',
            component=fragment.component, source_id='fixed_instruction_support', ownership='fuzzable',
            flow_id=flow_id, payload=dict(address=fragment.address, words_hex=fragment.data_hex),
            termination_observation=TerminationObservation('incomplete', '', flow_id),
            local_step_budget=local_step_budget)
        action = replace(self._slot_policy._bind(template), ownership='fixed', payload={}, action_sha256='')
        previous = self._support_instructions.get(fragment.action_id)
        if previous is not None and previous != fragment:
            raise ValueError('conflicting fixed support instruction')
        registered = super().register(action)
        self._slot_policy._reserve(registered)
        self._support_instructions[fragment.action_id] = fragment
        return registered

    def require_case(self, case):
        self._check_fixed_support(getattr(case, 'source', None))
        action = super().require_case(case)
        support = getattr(case, 'support_instructions', ())
        if type(support) is not tuple or len(support) > self.max_actions:
            raise ValueError('bounded support instruction tuple required')
        for instruction in support:
            self._check_fixed_support(instruction)
            super().require_case(SimpleNamespace(source=instruction))
        return action

    def _check_fixed_support(self, instruction):
        expected = self._support_instructions.get(getattr(instruction, 'action_id', None))
        if expected is not None and instruction != expected:
            raise ValueError('case differs from registered fixed support instruction')
