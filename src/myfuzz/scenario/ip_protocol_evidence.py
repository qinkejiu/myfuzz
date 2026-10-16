"""Bounded protocol proof from raw receipts and authenticated base projections.

This consumer reuses the protocol normalizer and Checker. Certificates describe
completed boundary transactions as historical evidence, never prerequisites,
register effects, CPU origins, or internal functional success.
"""
from collections import OrderedDict, deque
from collections.abc import Mapping
from copy import deepcopy
import hashlib

from .dependency_evidence import DependencyEvidence, DependencyEvidenceLedger, _canonical, _digest, _text
from .ip_binding_evidence import _same_projection
from .ip_protocol_checker import IpProtocolChecker
from .ip_protocol_events import IpProtocolEventNormalizer


_PROOF_EVENTS = frozenset(('transaction_request', 'transaction_accept', 'transaction_response'))
_DIAGNOSTICS = frozenset(('journal_integrity', 'raw_invalid', 'stale_epoch',
    'non_increasing_tick', 'projection_mismatch', 'missing_projection',
    'checker_violation', 'pending_eviction', 'evidence_expired', 'record_limit',
    'native_state_limit', 'incomplete_chain', 'reset'))


class IpProtocolEvidenceConsumer:
    def __init__(self, configurations, *, runtime_contract_sha256,
                 max_pending=1024, max_event_gap=4096, max_records=4096,
                 counter_cap=65535):
        if not _digest(runtime_contract_sha256):
            raise ValueError('protocol-evidence-runtime-contract-invalid')
        for value in (max_pending, max_event_gap, max_records, counter_cap):
            if type(value) is not int or not 1 <= value <= 65536:
                raise ValueError('protocol-evidence-bound-invalid')
        if not isinstance(configurations, Mapping) or not 1 <= len(configurations) <= 1024:
            raise ValueError('protocol-evidence-contracts-required')
        self.max_pending, self.max_event_gap = max_pending, max_event_gap
        self.max_records, self.counter_cap = max_records, counter_cap
        self._runtime_contract = runtime_contract_sha256
        self._configurations, self._states, self._identities = {}, {}, {}
        for alias, row in configurations.items():
            if (not _text(alias) or not isinstance(row, Mapping)
                    or set(row) != {'component_id', 'instance_id', 'protocol_trace'}
                    or not _text(row['component_id']) or not _text(row['instance_id'])):
                raise ValueError('protocol-evidence-component-contract-invalid')
            trace = row['protocol_trace']
            if (not isinstance(trace, Mapping) or not _text(trace.get('endpoint_id'))
                    or not _text(trace.get('clock_domain'))
                    or len(alias + ':' + trace['endpoint_id'] + ':response') > 1024
                    or not isinstance(trace.get('signals'), Mapping)
                    or len(trace['signals']) > 64
                    or any(not _text(k) or not _text(v) for k, v in trace['signals'].items())
                    or not isinstance(trace.get('signal_widths'), Mapping)
                    or len(trace['signal_widths']) > 64
                    or any(type(v) is not int or not 1 <= v <= 65536
                           for v in trace['signal_widths'].values())
                    or type(trace.get('max_wait_cycles')) is not int
                    or not 1 <= trace['max_wait_cycles'] <= 65536):
                raise ValueError('protocol-evidence-trace-bound-invalid')
            saved = deepcopy(dict(row))
            normalizer, checker = IpProtocolEventNormalizer(**saved), IpProtocolChecker(**saved)
            identity = (saved['component_id'], saved['instance_id'], trace['endpoint_id'])
            if identity in self._identities:
                raise ValueError('protocol-evidence-duplicate-identity')
            self._identities[identity] = alias
            self._configurations[alias] = saved
            self._states[alias] = dict(normalizer=normalizer, checker=checker,
                epoch=None, last_pre_tick=0, poisoned=False, expected=deque())
        self._contract_sha256 = hashlib.sha256(_canonical(self._configurations)).hexdigest()
        self._ledger = DependencyEvidenceLedger(max_records_per_type=max(max_records, len(configurations)))
        self._declaration_refs = {}
        for alias, cfg in self._configurations.items():
            endpoint = cfg['protocol_trace']['endpoint_id']
            declaration = DependencyEvidence('declared', 'protocol_transaction',
                alias + ':' + endpoint + ':request', alias + ':' + endpoint + ':response',
                'declared_topology', ('protocol_contract:' + self._contract_sha256,
                                     'runtime_contract:' + self._runtime_contract),
                'ip_protocol_trace', '1', ())
            self._ledger.append(declaration)
            self._declaration_refs[alias] = declaration.evidence_id
        self._pending, self._digests = OrderedDict(), OrderedDict()
        self._certificates = []
        self._diagnostics = {}
        self._last_id = 0
        self._integrity = True

    def _diagnose(self, reason):
        assert reason in _DIAGNOSTICS
        self._diagnostics[reason] = min(self.counter_cap, self._diagnostics.get(reason, 0) + 1)

    def _clear_alias(self, alias):
        for key in tuple(self._pending):
            if key[0] == alias:
                del self._pending[key]
        self._states[alias]['expected'].clear()

    def _poison(self, alias, reason):
        self._diagnose(reason)
        self._clear_alias(alias)
        state = self._states[alias]
        state['poisoned'] = True
        # Bound native state as well as evidence state while disabled.
        state['normalizer'] = IpProtocolEventNormalizer(**self._configurations[alias])
        state['checker'] = IpProtocolChecker(**self._configurations[alias])

    def consume(self, event):
        """Consume the same ordered journal passed to the runtime edge consumer."""
        if not isinstance(event, Mapping):
            self._integrity = False
            self._diagnose('journal_integrity')
            return
        event_id = event.get('event_id')
        try:
            digest = hashlib.sha256(_canonical(dict(event))).hexdigest()
        except (ValueError, TypeError):
            self._integrity = False
            self._diagnose('journal_integrity')
            return
        if type(event_id) is not int or event_id < 1:
            self._integrity = False
            self._diagnose('journal_integrity')
            return
        if event_id <= self._last_id:
            if self._digests.get(event_id) != digest:
                self._integrity = False
                self._diagnose('journal_integrity')
            return
        if event_id != self._last_id + 1:
            self._integrity = False
            self._diagnose('journal_integrity')
        self._last_id = event_id
        self._digests[event_id] = digest
        while len(self._digests) > self.max_event_gap:
            self._digests.popitem(last=False)
        for key in tuple(self._pending):
            if event_id - key[1] > self.max_event_gap:
                del self._pending[key]
                self._diagnose('evidence_expired')
        if not self._integrity:
            self._pending.clear()
            for state in self._states.values():
                state['expected'].clear()
            return
        if event.get('kind') == 'reset_barrier':
            self._diagnose('reset')
            for alias in self._states:
                self._clear_alias(alias)
                state = self._states[alias]
                state['normalizer'] = IpProtocolEventNormalizer(**self._configurations[alias])
                state['checker'] = IpProtocolChecker(**self._configurations[alias])
            return
        if event.get('kind') == 'local_tick_sample':
            alias = event.get('component')
            if isinstance(alias, str) and alias in self._states:
                self._raw(alias, event)
            return
        if (event.get('schema_version') == 'ip_base_event.v1'
                and event.get('event_type') in _PROOF_EVENTS):
            identity = tuple(event.get(name) for name in ('component_id', 'instance_id', 'endpoint_id'))
            if any(type(v) is not str for v in identity):
                return
            alias = self._identities.get(identity)
            if alias is not None:
                self._projection(alias, event)

    def _raw(self, alias, raw):
        state = self._states[alias]
        epoch, tick = raw.get('reset_epoch'), raw.get('local_tick')
        if (raw.get('observation_schema_version') != 'ip_raw_observation.v1'
                or type(epoch) is not int or not 0 <= epoch < 1 << 64
                or type(tick) is not int or tick < 1
                or raw.get('phase') not in ('pre', 'post')):
            self._poison(alias, 'raw_invalid')
            return
        provenance = raw.get('provenance', {})
        if not isinstance(provenance, Mapping):
            self._poison(alias, 'raw_invalid')
            return
        case = provenance.get('observed_case')
        if case is not None and (
                not isinstance(case, Mapping) or set(case) != {'case_id', 'case_index'}
                or case['case_id'] is not None and not _text(case['case_id'])
                or case['case_index'] is not None and (
                    type(case['case_index']) is not int or not 0 <= case['case_index'] < 1 << 64)):
            self._poison(alias, 'raw_invalid')
            return
        # Retain only the bounded declared tap, header and validated case.
        # Raw journal digests still cover the original complete receipt.
        outputs = raw.get('outputs')
        backend = outputs.get('backend') if isinstance(outputs, Mapping) else None
        signals = self._configurations[alias]['protocol_trace']['signals']
        raw = {name: raw.get(name) for name in (
            'event_id', 'kind', 'component', 'local_tick', 'phase',
            'reset_epoch', 'observation_schema_version')}
        raw['outputs'] = {'backend': ({name: backend.get(name) for name in signals.values()}
                                      if isinstance(backend, Mapping) else None)}
        raw['provenance'] = {'observed_case': deepcopy(case)}
        if state['epoch'] is not None and epoch < state['epoch']:
            self._poison(alias, 'stale_epoch')
            return
        if epoch != state['epoch']:
            self._clear_alias(alias)
            state.update(epoch=epoch, last_pre_tick=0, poisoned=False)
        if state['poisoned'] or raw['phase'] == 'post':
            return
        if tick <= state['last_pre_tick']:
            self._poison(alias, 'non_increasing_tick')
            return
        state['last_pre_tick'] = tick
        if state['expected']:
            self._poison(alias, 'missing_projection')
            return
        try:
            findings = state['checker'].consume_local_tick(raw, reset_epoch=epoch)
            if findings:
                self._poison(alias, 'checker_violation')
                return
            projected = state['normalizer'].consume_local_tick(raw, reset_epoch=epoch)
        except (ValueError, TypeError):
            self._poison(alias, 'raw_invalid')
            return
        for native in (state['normalizer'], state['checker']):
            size = sum(len(getattr(native, name, ())) for name in
                       ('_tl_outstanding', '_tl_quarantined', '_wb_outstanding'))
            if size > self.max_pending:
                self._poison(alias, 'native_state_limit')
                return
        for row in projected:
            if row['event_type'] in ('transaction_cancel', 'transaction_timeout', 'transaction_duplicate'):
                for ref in row['related_request_event_refs']:
                    self._pending.pop((alias, ref), None)
            if row['event_type'] in _PROOF_EVENTS:
                state['expected'].append((row, raw))

    def _projection(self, alias, event):
        state = self._states[alias]
        if state['poisoned']:
            return
        if not state['expected']:
            self._poison(alias, 'projection_mismatch')
            return
        expected, raw = state['expected'][0]
        if event.get('kind') != expected['event_type'] or not _same_projection(event, expected):
            self._poison(alias, 'projection_mismatch')
            return
        state['expected'].popleft()
        kind = expected['event_type']
        refs = expected['related_request_event_refs']
        request_raw_id = raw['event_id'] if kind == 'transaction_request' else (refs[0] if len(refs) == 1 else None)
        if request_raw_id is None:
            self._diagnose('incomplete_chain')
            return
        key = (alias, request_raw_id)
        if kind == 'transaction_request':
            self._pending[key] = dict(request_event_id=event['event_id'],
                request_raw_event_id=request_raw_id, epoch=expected['reset_epoch'],
                transaction_key=deepcopy(expected['transaction_key']),
                identity_gap=expected['identity_gap'], accept_event_id=None,
                request_case=deepcopy(raw.get('provenance', {}).get('observed_case')))
            while len(self._pending) > self.max_pending:
                self._pending.popitem(last=False)
                self._diagnose('pending_eviction')
            return
        pending = self._pending.get(key)
        if (pending is None or pending['epoch'] != expected['reset_epoch']
                or pending['transaction_key'] != expected['transaction_key']):
            self._diagnose('incomplete_chain')
            return
        if kind == 'transaction_accept':
            if pending['accept_event_id'] is not None:
                self._pending.pop(key)
                self._diagnose('incomplete_chain')
                return
            pending.update(accept_event_id=event['event_id'], accept_raw_event_id=raw['event_id'])
            return
        self._pending.pop(key)
        if pending['accept_event_id'] is None:
            self._diagnose('incomplete_chain')
            return
        if len(self._certificates) >= self.max_records:
            self._diagnose('record_limit')
            return
        cfg = self._configurations[alias]
        protocol = cfg['protocol_trace']['protocol']
        payload = expected['payload']
        # Each protocol reports its own failure field: TL-UL and Wishbone carry
        # an explicit error signal, APB3 carries PSLVERR as ``error``, and a
        # real AXI4-Lite slave answers with a two-bit response code per channel.
        # AXI4-Lite has no such thing as a generic ``error`` key, so reading one
        # raised KeyError on a perfectly valid transaction.
        error = (bool(payload['signals']['d_error']) if protocol == 'tl-ul'
                 else bool(payload['err']) if protocol == 'wishbone'
                 else bool(payload.get('bresp', payload.get('rresp', 0)))
                 if protocol == 'axi4-lite' else payload['error'])
        references = tuple(dict.fromkeys([
            'base:' + str(pending['request_event_id']),
            'base:' + str(pending['accept_event_id']), 'base:' + str(event['event_id']),
            'raw:' + str(request_raw_id), 'raw:' + str(pending['accept_raw_event_id']),
            'raw:' + str(raw['event_id']), 'protocol_contract:' + self._contract_sha256,
            'runtime_contract:' + self._runtime_contract]))
        endpoint = cfg['protocol_trace']['endpoint_id']
        evidence = DependencyEvidence('verified', 'protocol_transaction',
            alias + ':' + endpoint + ':request', alias + ':' + endpoint + ':response',
            'protocol_accept_response', references, 'ip_protocol_evidence', '1',
            ((alias, pending['epoch']),), declaration_ref=self._declaration_refs[alias],
            validity='historical')
        self._ledger.append(evidence)
        self._certificates.append(dict(evidence=evidence.document(),
            request_event_id=pending['request_event_id'], accept_event_id=pending['accept_event_id'],
            response_event_id=event['event_id'], request_raw_event_id=request_raw_id,
            accept_raw_event_id=pending['accept_raw_event_id'], response_raw_event_id=raw['event_id'],
            transaction_key=pending['transaction_key'], identity_gap=pending['identity_gap'],
            request_case=pending['request_case'],
            response_case=deepcopy(raw.get('provenance', {}).get('observed_case')),
            outcome='error' if error else 'ok'))

    def report(self):
        return deepcopy(dict(schema_version='ip_protocol_evidence_report.v1',
            proof_scope='protocol_boundary_only', runtime_contract_sha256=self._runtime_contract,
            observation_contract_sha256=self._contract_sha256,
            journal_integrity=self._integrity, last_event_id=self._last_id,
            certificates=self._certificates,
            evidence_ledger=self._ledger.document(),
            counts=dict(verified=len(self._certificates), pending=len(self._pending)),
            diagnostics=self._diagnostics,
            bounds=dict(max_pending=self.max_pending, max_event_gap=self.max_event_gap,
                        max_records=self.max_records, counter_cap=self.counter_cap)))
