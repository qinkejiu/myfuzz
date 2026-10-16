"""Current prerequisite qualification beside immutable historical reports.

Only the installed native memory tracker supplies active qualification today.
Other scopes remain unknown. Detached answers are observations, not tokens;
there is no document loader, receipt enrollment or cached positive answer.
"""
from copy import deepcopy

from .source_actions import Prerequisite, PREREQUISITE_KINDS


class DependencyWitnessLifecycle:
    def __init__(self):
        self._gate = None
        self._tracker = None
        self._consumer = None
        self._kinds = ()
        self._degraded = False

    def bind_memory(self, gate):
        from .live_memory_prerequisites import (
            LiveMemoryEffectTracker, PersistentMemoryPrerequisiteGate,
        )
        if (self._gate is not None
                or not isinstance(gate, PersistentMemoryPrerequisiteGate)
                or type(gate.tracker) is not LiveMemoryEffectTracker):
            raise ValueError('installed native memory lifecycle provider required once')
        tracker = gate.tracker
        consumer = tracker._consumer
        kinds = ('ram_byte_version',) + (
            ('instruction_slot_unmaterialized',) if gate.instruction_slot_policy is not None else ())
        self._gate, self._tracker, self._consumer, self._kinds = gate, tracker, consumer, kinds

    def _memory_status(self, runner):
        if self._gate is None:
            return 'unknown', None
        if (runner.persistent_memory_prerequisite_gate is not self._gate
                or self._gate.tracker is not self._tracker
                or self._tracker._consumer is not self._consumer
                or runner._memory_dependency_consumer is not self._consumer):
            self._degraded = True
            self._tracker._degraded = True
        # A replaced consumer may not even implement the native interface.
        # Do not dereference it after detecting the identity conflict.
        if self._degraded:
            return 'incomplete', None
        state = self._tracker.document()
        if self._degraded or state['degraded']:
            self._degraded = True
            self._tracker._degraded = True
            return 'incomplete', state
        return 'available', state

    def qualify(self, runner, prerequisite):
        if type(prerequisite) is not Prerequisite:
            raise ValueError('typed prerequisite required; saved evidence grants no authority')
        # Revalidate even frozen values at this boundary, including their digest.
        prerequisite = Prerequisite.from_document(prerequisite.document())
        status, _ = self._memory_status(runner)
        supported = prerequisite.kind in self._kinds
        witness = None
        scope = None
        if not supported:
            status, reason = 'unknown', 'missing_active_provider'
        else:
            scope = ('current_installed_host_memory_bytes' if prerequisite.kind == 'ram_byte_version'
                     else 'current_declared_unmaterialized_instruction_slot')
            if status == 'incomplete':
                reason = 'active_provider_integrity_failed'
            else:
                witness, reason = self._tracker._match(prerequisite)
                if self._memory_status(runner)[0] == 'incomplete':
                    status, reason, witness = 'incomplete', 'active_provider_integrity_failed', None
                else:
                    status = 'satisfied' if witness is not None else 'unsatisfied'
        return deepcopy(dict(schema_version='active_prerequisite_status.v1',
            prerequisite_id=prerequisite.prerequisite_id, status=status,
            satisfied=status == 'satisfied', reason=reason, proof_scope=scope,
            provider='installed_memory_authority.v1' if supported else None,
            witness=witness.document() if witness is not None else None))

    def report(self, runner):
        status, state = self._memory_status(runner)
        history = {}
        for name, report in (
                ('memory', self._consumer.report() if self._consumer is not None
                 else runner.memory_dependency_evidence_report()),
                ('irq', runner.irq_dependency_evidence_report())):
            history[name] = dict(status=report.get('status', 'configured'),
                proof_scope=report.get('proof_scope'), counts=report.get('counts', {}),
                grants_prerequisites=False)
        return deepcopy(dict(schema_version='dependency_witness_lifecycle.v1',
            proof_scope='runtime_qualification_separate_from_history',
            history_grants_prerequisites=False, history=history,
            active=dict(status=status, supported_kinds=list(self._kinds),
                unknown_kinds=[kind for kind in PREREQUISITE_KINDS if kind not in self._kinds],
                provider='installed_memory_authority.v1' if self._gate is not None else None,
                state=state, qualification='recomputed_per_query',
                counts=None, counts_reason='query_subject_required')))
