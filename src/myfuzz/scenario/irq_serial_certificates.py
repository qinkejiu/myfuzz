"""Bounded, incremental exact joins of the passive Ibex IRQ serial sidebands.

The pinned RVFI wrapper exports two passive 64-bit tokens:
``irq_decision_serial`` (set while an external Machine-mode IRQ owns the PC
decision, 0 otherwise) and ``irq_retirement_serial`` (the token presented on
``rvfi_valid && rvfi_intr``, 0 otherwise). Zero means that no external source has
a provable lineage, so a zero token never certifies anything.

This consumer joins one decision observation to one retirement observation only
when all of the following hold:

* both tokens were physically observed (status ``observed``) and are nonzero;
* the two observations carry the same ``execution_id`` and ``reset_epoch``;
* the decision event precedes the retirement event and their event-id distance
  stays within ``max_event_gap``;
* the retirement is a real interrupt retirement (``valid == 1``, ``intr == 1``);
* the decision still owns a live, corroborated take identity:
  - native receipts must present an exact ``take_key`` ``[component, epoch,
    sequence]`` whose component/epoch match the decision scope and whose
    sequence is strictly new inside that scope; and
  - a ``source_trigger`` reference must be corroborated by the journal's own
    ``cpu_irq_input``/``cpu_irq_taken`` pair with a field-by-field equal
    reference, so a mismatched ``trigger_id`` or referenced event refuses.
  Any mismatch refuses the join.

``proof_scope`` is ``exact_nonzero_irq_serial_token_equality``: one exact
hardware source token hop. It is explicitly *not* event adjacency, not
instruction/operand origin, and not a complete propagation chain. Certificates
here must never be promoted to a full source-identity chain.

State is bounded by ``max_pending`` (pending decisions, take identities,
corroborating references and recorded rejections) and by ``max_event_gap``
(expiry). Evicted, expired or reset observations are dropped for good: no later
event can restore their credit. Only a strictly later measured reset barrier
lifts a scope that conflicting or malformed evidence barred.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from collections.abc import Iterable, Mapping

from myfuzz.local_harness.ibex_irq_receipt_contract import (
    IBEX_IRQ_SERIAL_DECISION_PORT, IBEX_IRQ_SERIAL_OBSERVATION_SCHEMA,
    IBEX_IRQ_SERIAL_RETIREMENT_PORT, IBEX_IRQ_SERIAL_WIDTH_BITS,
    IBEX_IRQ_SERIAL_ZERO_SEMANTICS)


CERTIFICATE_SCHEMA = 'irq_serial_certificate.v1'
REJECTION_SCHEMA = 'irq_serial_rejection.v1'
PROOF_SCOPE = 'exact_nonzero_irq_serial_token_equality'
CERTIFICATE_SCOPE = 'external_irq_decision_serial_to_rvfi_retirement_serial'
NOT_PROOF_OF = ('event_adjacency', 'instruction_origin', 'operand_or_fifo_taint',
                'complete_propagation_chain', 'handler_entry_or_isr_effect')
_TAKE_IDENTITY_SCHEMA = 'irq_serial_take_identity.v1'

_RESET_KINDS = ('reset_barrier', 'gpio_reset_resource', 'cpu_reset')
_NATIVE_DECISION_KINDS = ('cpu_external_irq_sample', 'cpu_external_irq_taken')
_PIN8_KINDS = ('cpu_irq_input', 'cpu_irq_taken')
_DECISION_KINDS = _NATIVE_DECISION_KINDS + _PIN8_KINDS
_TAKE_KINDS = ('cpu_external_irq_taken', 'cpu_irq_taken')
_OBSERVATION_FIELDS = frozenset(('schema_version', 'sampling', 'width_bits',
                                 'zero_semantics', 'decision', 'retirement'))
_ROLE_FIELDS = frozenset(('physical_port', 'phase', 'value', 'status'))
_ROLE_PORTS = {'decision': IBEX_IRQ_SERIAL_DECISION_PORT,
               'retirement': IBEX_IRQ_SERIAL_RETIREMENT_PORT}
_SAMPLING = ('pre_post_rising', 'post_rising')
_PHASES = ('pre', 'post')
_TRIGGER_FIELDS = ('trigger_id', 'trigger_event_id', 'observation_event_id',
                   'sample_event_id')
_CONFLICT = object()


class _Malformed(Exception):
    """A present serial observation or identity that cannot be trusted."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _uint(value) -> bool:
    return type(value) is int and 0 <= value < 1 << IBEX_IRQ_SERIAL_WIDTH_BITS


def _text(value) -> bool:
    return type(value) is str and bool(value.strip())


def _take_key(value):
    """Native receipt take identity ``[component, reset_epoch, sequence]``."""
    if (type(value) is not list or len(value) != 3 or not _text(value[0])
            or type(value[1]) is not int or value[1] < 0
            or type(value[2]) is not int or value[2] < 1):
        return None
    return [value[0], value[1], value[2]]


def _source_trigger(value):
    """Pin8-style exact trigger reference of one observed CPU interrupt."""
    if not isinstance(value, Mapping) or set(value) != set(_TRIGGER_FIELDS):
        return None
    if _text(value['trigger_id']) is False:
        return None
    if any(type(value[name]) is not int or value[name] < 1
           for name in _TRIGGER_FIELDS[1:]):
        return None
    return {name: value[name] for name in _TRIGGER_FIELDS}


def _role(document, name):
    port = _ROLE_PORTS[name]
    if (not isinstance(document, Mapping) or set(document) != _ROLE_FIELDS
            or document.get('physical_port') != port
            or document.get('phase') not in _PHASES
            or document.get('status') not in ('observed', 'unobservable')):
        raise _Malformed('malformed_irq_serial_observation')
    value, status = document['value'], document['status']
    if status == 'observed':
        if not _uint(value):
            raise _Malformed('malformed_irq_serial_value')
    elif value is not None:
        raise _Malformed('malformed_irq_serial_value')
    return {'physical_port': port, 'phase': document['phase'], 'value': value,
            'status': status}


def _serial_roles(event):
    """Parse the versioned observation document; None means 'not recorded'."""
    if 'irq_serial_observation' not in event:
        return None
    document = event['irq_serial_observation']
    if (not isinstance(document, Mapping) or set(document) != _OBSERVATION_FIELDS
            or document.get('schema_version') != IBEX_IRQ_SERIAL_OBSERVATION_SCHEMA
            or document.get('sampling') not in _SAMPLING
            or document.get('width_bits') != IBEX_IRQ_SERIAL_WIDTH_BITS
            or document.get('zero_semantics') != IBEX_IRQ_SERIAL_ZERO_SEMANTICS):
        raise _Malformed('malformed_irq_serial_observation')
    return {'schema_version': document['schema_version'],
            'sampling': document['sampling'],
            'decision': _role(document['decision'], 'decision'),
            'retirement': _role(document['retirement'], 'retirement')}


def _scope(event):
    """Exact CPU observation scope, or None when it is absent or inconsistent."""
    execution = event.get('execution_id')
    epoch = event.get('reset_epoch')
    component = event.get('source_component', event.get('component'))
    if not _text(execution) or type(epoch) is not int or epoch < 0 or not _text(component):
        return None
    if 'source_epoch' in event and event['source_epoch'] != epoch:
        return None
    if 'source_component' in event and event['source_component'] != component:
        return None
    if 'component' in event and event['component'] != component:
        return None
    return (execution, epoch, component)


def _merge_identity(left, right):
    """Union two identity conventions; conflicting duplicates stay unresolved."""
    if left is None:
        return right
    if right is None:
        return left
    merged = dict(left)
    for name, value in right.items():
        if name in merged and merged[name] != value:
            return _CONFLICT
        merged[name] = value
    return merged


class IrqSerialCertificates:
    """Consume one contiguous journal prefix; certify exact serial joins only."""

    def __init__(self, *, max_pending: int = 128, max_event_gap: int = 4096):
        if type(max_pending) is not int or max_pending < 1:
            raise ValueError('max_pending must be a positive integer')
        if type(max_event_gap) is not int or max_event_gap < 1:
            raise ValueError('max_event_gap must be a positive integer')
        self.max_pending = max_pending
        self.max_event_gap = max_event_gap
        self._last_event_id = 0
        self._decisions: OrderedDict = OrderedDict()
        self._take_keys: OrderedDict = OrderedDict()
        self._triggers: OrderedDict = OrderedDict()
        self._barred: OrderedDict = OrderedDict()
        self._rejections: deque = deque(maxlen=max_pending)

    @property
    def pending_count(self) -> int:
        return len(self._decisions)

    def state_counts(self) -> dict:
        """Bounded sizes of every retained cache, for capacity evidence."""
        return {'pending_decisions': len(self._decisions),
                'take_identities': len(self._take_keys),
                'trigger_references': len(self._triggers),
                'rejections': len(self._rejections)}

    def rejections(self) -> tuple:
        """Detached bounded records of refused or incomplete observations."""
        return tuple(dict(record) for record in self._rejections)

    def ingest(self, events: Iterable[Mapping]) -> tuple[dict, ...]:
        result = []
        for event in events:
            if (not isinstance(event, Mapping)
                    or type(event.get('event_id')) is not int
                    or event['event_id'] != self._last_event_id + 1):
                raise ValueError('certificate journal must be contiguous')
            self._last_event_id = event['event_id']
            self._expire(event['event_id'])
            kind = event.get('kind')
            if kind in _RESET_KINDS:
                self._clear()
                continue
            try:
                roles = _serial_roles(event)
            except _Malformed as error:
                scope = _scope(event)
                if scope is not None:
                    self._bar(scope, event['event_id'])
                self._record(event, 'rejected', error.reason)
                continue
            if kind in _PIN8_KINDS:
                self._trigger_reference(event)
            if kind in _DECISION_KINDS:
                self._decision(event, roles)
            elif kind == 'cpu_retire':
                certificate = self._retirement(event, roles)
                if certificate is not None:
                    result.append(certificate)
        return tuple(result)

    def _record(self, event: Mapping, status: str, reason: str, *,
                decision_serial=None, retirement_serial=None) -> None:
        self._rejections.append({
            'schema_version': REJECTION_SCHEMA, 'status': status, 'reason': reason,
            'event_id': event.get('event_id') if type(event.get('event_id')) is int else None,
            'producer_event_id': (event.get('producer_event_id')
                                  if type(event.get('producer_event_id')) is int else None),
            'kind': event.get('kind') if type(event.get('kind')) is str else None,
            'component': event.get('source_component', event.get('component'))
                         if _text(event.get('source_component', event.get('component'))) else None,
            'execution_id': event.get('execution_id') if _text(event.get('execution_id')) else None,
            'reset_epoch': (event.get('reset_epoch')
                            if type(event.get('reset_epoch')) is int
                            and event['reset_epoch'] >= 0 else None),
            'decision_serial': decision_serial, 'retirement_serial': retirement_serial})

    def _bar(self, scope, event_id: int) -> None:
        if scope not in self._barred:
            while len(self._barred) >= self.max_pending:
                self._barred.popitem(last=False)
        self._barred[scope] = event_id
        for key in [key for key in self._decisions if key[:3] == scope]:
            del self._decisions[key]

    def _clear(self) -> None:
        self._decisions.clear()
        self._take_keys.clear()
        self._triggers.clear()
        self._barred.clear()

    def _expire(self, event_id: int) -> None:
        for key, state in tuple(self._decisions.items()):
            if event_id - state['born'] > self.max_event_gap:
                del self._decisions[key]
                self._record(state['event'], 'incomplete', 'decision_serial_expired',
                             decision_serial=state['decision_serial'])
        for trigger_id, state in tuple(self._triggers.items()):
            if event_id - state['born'] > self.max_event_gap:
                del self._triggers[trigger_id]

    def _limit_decisions(self) -> None:
        while len(self._decisions) > self.max_pending:
            key, state = self._decisions.popitem(last=False)
            self._record(state['event'], 'incomplete', 'pending_capacity_exceeded',
                         decision_serial=state['decision_serial'])

    def _decision(self, event: Mapping, roles) -> None:
        scope = _scope(event)
        serial = roles['decision']['value'] if roles is not None else None
        if scope is None:
            if roles is not None and roles['decision']['status'] == 'observed' \
                    and roles['decision']['value'] != 0:
                self._record(event, 'incomplete', 'missing_cpu_event_scope',
                             decision_serial=serial)
            return
        if scope in self._barred:
            self._record(event, 'incomplete',
                         'scope_barred_after_observed_evidence_conflict',
                         decision_serial=serial)
            return
        if roles is None:
            if event.get('kind') in _NATIVE_DECISION_KINDS:
                self._record(event, 'incomplete', 'missing_irq_serial_observation')
            return
        role = roles['decision']
        if role['status'] != 'observed':
            if event.get('kind') in _TAKE_KINDS or event.get('irq_taken_pre') == 1:
                self._record(event, 'incomplete', 'unobservable_decision_serial')
            return
        if role['value'] == 0:
            if event.get('kind') in _TAKE_KINDS or event.get('irq_taken_pre') == 1:
                self._record(event, 'incomplete', 'zero_decision_serial')
            return
        value = role['value']
        identity, reason = self._identity(event, scope)
        if reason is not None:
            self._record(event, 'rejected', reason, decision_serial=value)
            return
        key = (scope[0], scope[1], scope[2], value)
        existing = self._decisions.get(key)
        if existing is not None:
            if existing['producer_event_id'] != event.get('producer_event_id'):
                del self._decisions[key]
                self._record(event, 'rejected', 'duplicate_decision_serial',
                             decision_serial=value)
                return
            merged = _merge_identity(existing['identity'], identity)
            if merged is _CONFLICT:
                del self._decisions[key]
                self._record(event, 'rejected', 'decision_identity_conflict',
                             decision_serial=value)
                return
            existing['identity'] = merged
            if identity is not None:
                existing['identity_event_id'] = event['event_id']
            return
        self._decisions[key] = {
            'born': event['event_id'],
            'producer_event_id': event.get('producer_event_id'),
            'decision_serial': value, 'scope': scope, 'sampling': roles['sampling'],
            'phase': role['phase'], 'identity': identity,
            'identity_event_id': event['event_id'] if identity is not None else None,
            'event': dict(event)}
        self._limit_decisions()

    def _identity(self, event: Mapping, scope):
        """Exact take identity; (None, None) means 'not claimed yet'."""
        identity = {}
        if 'take_key' in event:
            key = _take_key(event['take_key'])
            if key is None:
                return None, 'malformed_take_key'
            if key[0] != scope[2] or key[1] != scope[1]:
                return None, 'take_key_scope_mismatch'
            marker = (scope[2], scope[1])
            previous = self._take_keys.get(marker)
            if previous is not None and key[2] <= previous:
                return None, 'take_key_reused_or_regressed'
            self._take_keys[marker] = key[2]
            while len(self._take_keys) > self.max_pending:
                self._take_keys.popitem(last=False)
            identity['take_key'] = key
        if 'source_trigger' in event:
            reference = _source_trigger(event['source_trigger'])
            if reference is None:
                return None, 'malformed_source_trigger'
            identity['source_trigger'] = reference
        if not identity:
            return None, None
        return identity, None

    def _trigger_reference(self, event: Mapping) -> None:
        reference = _source_trigger(event.get('source_trigger'))
        if reference is None:
            return
        trigger_id = reference['trigger_id']
        state = self._triggers.get(trigger_id)
        if state is not None and state['reference'] != reference:
            del self._triggers[trigger_id]
            self._record(event, 'rejected', 'trigger_identity_mismatch')
            return
        if state is None:
            state = {'reference': reference, 'input_event_id': None,
                     'taken_event_id': None, 'born': event['event_id']}
            self._triggers[trigger_id] = state
            while len(self._triggers) > self.max_pending:
                self._triggers.popitem(last=False)
        slot = 'input_event_id' if event.get('kind') == 'cpu_irq_input' else 'taken_event_id'
        if state[slot] is None:
            state[slot] = event['event_id']

    def _corroborated(self, reference, event_id: int) -> bool:
        """The journal's own cpu_irq_input/cpu_irq_taken pair must be identical."""
        state = self._triggers.get(reference['trigger_id'])
        if state is None or state['reference'] != reference:
            return False
        return (state['input_event_id'] is not None
                and state['taken_event_id'] is not None
                and state['input_event_id'] < state['taken_event_id'] <= event_id)

    def _retirement(self, event: Mapping, roles):
        scope = _scope(event)
        if scope is None:
            return None
        if scope in self._barred:
            self._record(event, 'incomplete',
                         'scope_barred_after_observed_evidence_conflict')
            return None
        if roles is None:
            if event.get('intr') == 1:
                self._record(event, 'incomplete', 'missing_irq_serial_observation')
            return None
        role = roles['retirement']
        if role['status'] != 'observed':
            if event.get('intr') == 1:
                self._record(event, 'incomplete', 'unobservable_retirement_serial')
            return None
        if type(event.get('valid')) is not int or event['valid'] != 1:
            self._record(event, 'incomplete', 'retirement_not_valid')
            return None
        if type(event.get('intr')) is not int or event['intr'] != 1:
            self._record(event, 'incomplete', 'retirement_not_interrupt')
            return None
        value = role['value']
        if value == 0:
            self._record(event, 'incomplete', 'zero_retirement_serial')
            return None
        key = (scope[0], scope[1], scope[2], value)
        state = self._decisions.get(key)
        if state is None:
            self._record(event, 'incomplete', 'unmatched_retirement_serial',
                         retirement_serial=value)
            return None
        gap = event['event_id'] - state['born']
        if gap <= 0 or gap > self.max_event_gap:
            del self._decisions[key]
            self._record(event, 'incomplete', 'unmatched_retirement_serial',
                         retirement_serial=value)
            return None
        identity = state['identity']
        if identity is None:
            self._record(event, 'incomplete', 'missing_decision_take_identity',
                         retirement_serial=value)
            return None
        reference = identity.get('source_trigger')
        if reference is not None and not self._corroborated(reference,
                                                            state['identity_event_id']):
            self._record(event, 'incomplete', 'take_identity_uncorroborated',
                         retirement_serial=value)
            return None
        del self._decisions[key]
        return self._certificate(event, state, roles, gap)

    def _certificate(self, event: Mapping, state, roles, gap: int) -> dict:
        identity = state['identity']
        event_ids = []
        for event_id in (state['born'], state['identity_event_id'], event['event_id']):
            if event_id is not None and event_id not in event_ids:
                event_ids.append(event_id)
        return {
            'schema_version': CERTIFICATE_SCHEMA,
            'kind': 'irq_serial_certificate',
            'status': 'certified',
            'scope': CERTIFICATE_SCOPE,
            'proof_scope': PROOF_SCOPE,
            'not_proof_of': list(NOT_PROOF_OF),
            'hops': 1,
            'execution_id': state['scope'][0],
            'reset_epoch': state['scope'][1],
            'component': state['scope'][2],
            'decision_serial': state['decision_serial'],
            'retirement_serial': roles['retirement']['value'],
            'decision_event_id': state['born'],
            'decision_producer_event_id': state['producer_event_id'],
            'decision_phase': state['phase'],
            'decision_sampling': state['sampling'],
            'take_identity': {name: value for name, value in identity.items()},
            'take_identity_schema_version': _TAKE_IDENTITY_SCHEMA,
            'take_identity_event_id': state['identity_event_id'],
            'retirement_event_id': event['event_id'],
            'retirement_producer_event_id': (event.get('producer_event_id')
                                             if type(event.get('producer_event_id')) is int
                                             else None),
            'retirement_phase': roles['retirement']['phase'],
            'retirement_sampling': roles['sampling'],
            'retirement_order': (event.get('order') if type(event.get('order')) is int
                                 else None),
            'event_gap': gap,
            'event_ids': event_ids,
            'irq_serial_observation_schema': IBEX_IRQ_SERIAL_OBSERVATION_SCHEMA,
            'zero_semantics': IBEX_IRQ_SERIAL_ZERO_SEMANTICS}
