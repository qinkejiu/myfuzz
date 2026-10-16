"""Optional GPIO register-version evidence from authenticated native probes.

This adapter recomputes resources with the existing factual tracker. Journal
annotations and protocol accept events grant no register or functional proof.
Certificates describe historical write/read associations, never prerequisites.
"""
from collections import OrderedDict
from copy import deepcopy
import hashlib
import json
import re

from .dependency_evidence import DependencyEvidence, DependencyEvidenceLedger
from .gpio_consumption import GpioConsumptionTracker, _REGS, is_authenticated_gpio_tick
from .retirement_delivery import _key
from myfuzz.local_harness.pulp_gpio_probe_contract import (
    PULP_GPIO_PROBES, pulp_gpio_observation_contract)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def _uint(value):
    return type(value) is int and 0 <= value < 1 << 64


def _text(value):
    return type(value) is str and 0 < len(value) <= 512 and value.strip() == value


def validate_capability_binding(parameters, *, profile, sidecar, key, base_dir):
    """Known native layout, source pins and exact field access only."""
    from myfuzz.local_harness.pulp_gpio_probe_contract import verify_pulp_gpio_source_contract
    verify_pulp_gpio_source_contract(profile, base_dir=base_dir)
    layouts = {'dir': ('PADDIR', 0), 'gpioen': ('GPIOEN', 4),
        'out': ('PADOUT', 12), 'inten': ('INTEN', 24),
        'inttype': ('INTTYPE_HIGH', 32) if parameters['bit_lo'] >= 32 else ('INTTYPE_LOW', 28)}
    layout = layouts.get(parameters['register'])
    if layout is None or sidecar is None or key[1] not in ('register_read', 'register_write'):
        raise ValueError('native-register-capability-scope-unsupported')
    register, offset = layout
    field = next((f for f in sidecar.register_semantics
                  if f'{f.register}.{f.field}' == key[2]), None)
    base = next((r for r in profile.address.registers if r.name == register), None)
    mask = (1 << parameters['width'])-1
    if (field is None or base is None or field.register != register
            or base.offset != offset or base.width != 32 or base.side_effect != 'none'
            or field.lsb != parameters['bit_lo'] % 32 or field.width != parameters['width']
            or (field.read_mask if key[1] == 'register_read' else field.write_mask) != mask):
        raise ValueError('native-register-capability-field-mismatch')


class GpioRegisterEvidenceConsumer:
    """One explicit register slice; bounded, optional and independent of L1.

    All local edges must be observed. A matching ACCESS then tick pair shares
    an edge; every other repeated edge or skipped edge is a certainty barrier.
    Reset discards resource associations but cannot heal a damaged journal.
    """

    def __init__(self, *, component, register, bit_lo, width,
                 runtime_contract_sha256, max_records=4096, max_event_gap=4096,
                 max_accesses=256):
        if (not _text(component) or type(register) is not str or register not in _REGS
                or type(bit_lo) is not int or bit_lo < 0
                or type(width) is not int or not 1 <= width <= 32
                or bit_lo + width > _REGS[register]
                or bit_lo // 32 != (bit_lo + width - 1) // 32
                or type(runtime_contract_sha256) is not str
                or re.fullmatch('[0-9a-f]{64}', runtime_contract_sha256) is None
                or any(type(v) is not int or not 1 <= v <= 65536
                       for v in (max_records, max_event_gap, max_accesses))):
            raise ValueError('gpio-register-evidence-configuration-invalid')
        self._component, self._register = component, register
        self._bit_lo, self._width = bit_lo, width
        self._runtime_hash = runtime_contract_sha256
        self._max_records, self._max_gap, self._max_accesses = (
            max_records, max_event_gap, max_accesses)
        contract = dict(component=component, register=register, bit_lo=bit_lo,
                        width=width, observation_contract=pulp_gpio_observation_contract())
        self._contract_hash = hashlib.sha256(_canonical(contract)).hexdigest()
        self._source = f'{component}:{register}[{bit_lo}:{width}]:write'
        self._target = f'{component}:{register}[{bit_lo}:{width}]:read'
        self._ledger = DependencyEvidenceLedger(max_records_per_type=max_records)
        self._declaration = DependencyEvidence('declared', 'persistent_state',
            self._source, self._target, 'declared_topology',
            ('observation_contract:' + self._contract_hash,
             'runtime_contract:' + self._runtime_hash), 'gpio_register_version', '1', ())
        self._ledger.append(self._declaration)
        self._tracker = GpioConsumptionTracker(max_components=1,
                                              max_completed_accesses=max_accesses)
        self._last_id = 0
        self._digests = OrderedDict()
        self._integrity = True
        self._incomplete = False
        self._register_status = 'unknown'
        self._epoch = None
        self._last_edge = None
        self._native_reset_pending_barrier = False
        self._awaiting_native_reset = False
        self._access_count = 0
        self._writers = {}
        self._transactions = set()
        self._certificates = []
        self._reason = 'missing_actual_write_read_versions'

    def _fail(self, reason):
        self._incomplete = True
        self._register_status = 'incomplete'
        self._writers.clear()
        self._clear_additional_resources()
        self._reason = reason

    def _clear_additional_resources(self):
        """Optional factual providers clear their resource view at barriers."""

    def consume(self, event):
        """Read one complete journal record without changing it or driving RTL."""
        try:
            if type(event) is not dict or type(event.get('event_id')) is not int:
                raise ValueError('malformed journal')
            digest = hashlib.sha256(_canonical(event)).hexdigest()
        except (ValueError, TypeError, OverflowError, RecursionError):
            self._integrity = False
            self._fail('malformed_journal_record')
            return
        event_id = event['event_id']
        if event_id <= self._last_id:
            if self._digests.get(event_id) != digest:
                self._integrity = False
                self._fail('conflicting_or_expired_journal_identity')
            return
        if event_id != self._last_id + 1:
            self._integrity = False
            self._fail('journal_gap')
        self._last_id = event_id
        self._digests[event_id] = digest
        while len(self._digests) > self._max_gap:
            self._digests.popitem(last=False)
        if not self._integrity:
            return
        kind = event.get('kind')
        if kind == 'reset_barrier':
            # The Runner barrier is global and carries no component. A native
            # reset may be drained before or after it; one reset acknowledges
            # at most one barrier, before any subsequent native observation.
            self._awaiting_native_reset = not self._native_reset_pending_barrier
            self._native_reset_pending_barrier = False
            self._last_edge = None
            self._writers.clear()
            self._clear_additional_resources()
            self._transactions.clear()
            self._access_count = 0
            self._tracker = GpioConsumptionTracker(max_components=1,
                max_completed_accesses=self._max_accesses)
            if self._awaiting_native_reset or self._incomplete:
                self._fail('reset_barrier_without_current_native_reset')
            else:
                self._register_status = 'unknown'
                self._reason = 'reset_barrier_discarded_native_resources'
            return
        if event.get('component') != self._component:
            return
        if kind == 'gpio_reset':
            epoch = event.get('reset_epoch')
            if not _uint(epoch) or self._epoch is not None and epoch <= self._epoch:
                self._fail('reset_epoch_did_not_advance')
                return
            self._epoch = epoch
            self._native_reset_pending_barrier = not self._awaiting_native_reset
            self._awaiting_native_reset = False
            self._last_edge = None
            self._writers.clear()
            self._clear_additional_resources()
            self._transactions.clear()
            self._access_count = 0
            self._incomplete = False
            self._register_status = 'unknown'
            self._reason = 'reset_discarded_register_versions'
            self._tracker = GpioConsumptionTracker(max_components=1,
                max_completed_accesses=self._max_accesses)
            return
        if kind == 'gpio_access_terminal':
            self._fail('uncertain_actual_target_access')
            return
        if kind not in ('gpio_apb_access', 'gpio_tick_observation') or self._incomplete:
            return
        self._native_reset_pending_barrier = False
        # Validate measured physical transitions, not the optional derived fields.
        raw = {key: deepcopy(event[key]) for key in (
            'kind', 'component', 'reset_epoch', 'source_epoch', 'local_tick',
            'event_id', 'observation_contract', 'status', 'phase', 'access_id',
            'raw_offset', 'decoded_offset', 'write', 'wdata', 'read_rdata',
            'source_transaction', 'command_scope', 'target_response') if key in event}
        for phase in ('pre', 'post'):
            state = event.get(phase)
            raw[phase] = ({key: state[key] for key in
                ['gpio_in'] + ['gpio_probe_' + name for name in PULP_GPIO_PROBES]
                if key in state} if type(state) is dict else None)
        if kind == 'gpio_tick_observation':
            for key in ('source_transaction', 'access_id', 'target_response',
                        'raw_offset', 'decoded_offset', 'write', 'wdata', 'read_rdata'):
                raw.pop(key, None)
        elif type(raw.get('target_response')) is dict:
            raw['target_response'] = {key: raw['target_response'][key]
                for key in ('rdata', 'error') if key in raw['target_response']}
        raw['kind'] = 'gpio_tick_observation'
        if (not is_authenticated_gpio_tick(raw) or raw['local_tick'] == 0
                or _canonical(raw['observation_contract']) !=
                   _canonical(pulp_gpio_observation_contract())):
            self._fail('invalid_authenticated_probe_observation')
            return
        epoch = raw['reset_epoch']
        if self._epoch is None:
            self._epoch = epoch
        if epoch != self._epoch:
            self._fail('epoch_without_reset')
            return
        scope = raw.get('command_scope')
        if scope is not None and (type(scope) is not dict or set(scope) != {
                'component', 'reset_epoch', 'command_sequence'}
                or scope['component'] != self._component
                or not _uint(scope['reset_epoch']) or scope['reset_epoch'] != epoch
                or not _uint(scope['command_sequence']) or scope['command_sequence'] == 0):
            self._fail('malformed_command_scope')
            return
        paired = False
        if self._last_edge is not None:
            previous = self._last_edge
            paired = (kind == 'gpio_tick_observation'
                      and previous['kind'] == 'gpio_apb_access'
                      and raw['local_tick'] == previous['local_tick']
                      and _canonical(raw['pre']) == _canonical(previous['pre'])
                      and _canonical(raw['post']) == _canonical(previous['post'])
                      and _canonical(raw.get('command_scope')) ==
                          _canonical(previous.get('command_scope')))
            if not paired and (raw['local_tick'] != previous['local_tick'] + 1
                    or any(raw['pre']['gpio_probe_' + name] !=
                           previous['post']['gpio_probe_' + name] for name in _REGS)):
                self._fail('missing_or_conflicting_local_edge')
                return
        if (kind == 'gpio_tick_observation' and not paired
                and raw['pre']['gpio_probe_psel'] == 1
                and raw['pre']['gpio_probe_penable'] == 1
                and (raw['pre']['gpio_probe_pready'] == 1
                     or raw['pre']['gpio_probe_write'] == 1)):
            # Native register write gating can precede protocol completion.
            # Even a same-value write without ready replaces the version.
            self._fail('missing_actual_access_for_native_bus_edge')
            return
        if kind == 'gpio_apb_access':
            transaction = raw.get('source_transaction')
            key = _key(transaction)
            if (key is None or any(
                    not _text(value) if type(value) is str else not _uint(value)
                    for value in transaction.values())
                    or not _text(raw.get('access_id'))):
                self._fail('malformed_or_unbounded_access_identity')
                return
            if key in self._transactions:
                self._fail('conflicting_transaction_identity')
                return
            self._access_count += 1
            if self._access_count > self._max_accesses:
                self._fail('access_capacity_exceeded')
                return
            self._transactions.add(key)
        # Keep only the fields needed for next-edge and paired-observation checks.
        self._last_edge = {key: deepcopy(raw.get(key)) for key in
            ('kind', 'local_tick', 'pre', 'post', 'command_scope')}
        self._last_edge['kind'] = kind
        raw['kind'] = kind
        records = self._tracker.consume(raw)
        if any(r.get('kind') == 'gpio_consumption_match' and
               r.get('status') in ('rejected', 'ambiguous', 'incomplete') for r in records):
            self._fail('native_tracker_rejected_evidence')
            return
        self._process_records(records, raw, event_id)

    def _process_records(self, records, raw, event_id):
        for r in records:
            if r.get('status') != 'observed' or r.get('register') != self._register:
                continue
            if r['kind'] == 'gpio_register_commit':
                for resource in r['bit_resources'][self._bit_lo:self._bit_lo + self._width]:
                    if resource['observation_event_id'] == event_id:
                        self._writers[resource['bit']] = dict(resource=deepcopy(resource),
                            transaction=deepcopy(r['fullkey']), access={name: deepcopy(r[name])
                                for name in ('raw_offset', 'decoded_offset', 'operation',
                                             'write_value', 'pre_value', 'post_value', 'access_id')})
            elif r['kind'] == 'gpio_register_read':
                # A 64-bit register is read as one actual 32-bit APB bank.
                bank = 32 if raw['decoded_offset'] == 32 else 0
                if self._bit_lo // 32 != bank // 32:
                    continue
                self._read(r, event_id, raw)

    def _read(self, record, event_id, raw):
        resources = record['bit_resources'][self._bit_lo:self._bit_lo + self._width]
        writers = []
        for resource in resources:
            writer = self._writers.get(resource['bit'])
            if (writer is None or writer['resource'] != resource
                    or not 0 < event_id - resource['observation_event_id'] <= self._max_gap):
                self._reason = 'missing_or_expired_exact_register_writer'
                self._register_status = 'incomplete'
                return
            writers.append(writer)
        if len(writers) != self._width or len(self._certificates) >= self._max_records:
            self._reason = 'record_capacity_exceeded'
            self._register_status = 'incomplete'
            return
        writer_ids = sorted({w['resource']['observation_event_id'] for w in writers})
        evidence = DependencyEvidence('verified', 'persistent_state', self._source,
            self._target, 'register_version', tuple(
                ['journal:' + str(v) for v in writer_ids + [event_id]] +
                ['observation_contract:' + self._contract_hash,
                 'runtime_contract:' + self._runtime_hash]),
            'gpio_register_version', '1', ((self._component, self._epoch),),
            declaration_ref=self._declaration.evidence_id, validity='historical')
        if not self._ledger.append(evidence):
            return
        self._certificates.append(dict(evidence_id=evidence.evidence_id,
            proof_scope='register_version', component=self._component,
            reset_epoch=self._epoch, register=self._register,
            bit_lo=self._bit_lo, width=self._width, writer_event_ids=writer_ids,
            read_event_id=event_id, bit_resources=deepcopy(resources),
            write_accesses=[deepcopy(next(w['access'] for w in writers
                if w['resource']['observation_event_id'] == v)) for v in writer_ids],
            read_access=dict(raw_offset=raw['raw_offset'], decoded_offset=raw['decoded_offset'],
                access_id=record['access_id'], read_value=record['read_value']),
            write_transactions=[deepcopy(next(w['transaction'] for w in writers
                if w['resource']['observation_event_id'] == v)) for v in writer_ids],
            read_transaction=deepcopy(record['fullkey'])))
        self._reason = 'actual_write_read_versions'
        self._register_status = 'verified'

    def report(self):
        return deepcopy(dict(schema_version='gpio_register_evidence_report.v1',
            proof_scope='register_version_only', journal_integrity=self._integrity,
            awaiting_native_reset=self._awaiting_native_reset,
            register_status=self._register_status,
            functional_status='unknown', reason=self._reason,
            counts=dict(verified=len(self._certificates)),
            bounds=dict(max_records=self._max_records, max_event_gap=self._max_gap,
                        max_accesses=self._max_accesses),
            certificates=self._certificates, ledger=self._ledger.document()))
