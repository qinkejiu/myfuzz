"""Receipt/lifecycle issuance for the reduced single beat protocol.

Session.admit_observation_stream returns the actual ObservationStreamSource.
Consumers MUST inspect source.state before using tokens; poisoned lookup is
only diagnostic. Tokens remain FIFO ACKable. seal_observation_stream is an
explicit terminal recording checkpoint and never closes a protocol scope.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
from weakref import WeakKeyDictionary, ref
from myfuzz.scenario.observation_stream import ObservationStreamSource
from myfuzz.local_harness.vexii_axi_fields import STEP_PORTS, SHAPES

DEFAULT_LIMITS = dict(max_operations=100000, max_pending_operations=1024,
                      max_pending_bytes=8388608, max_operation_bytes=1048576)


_ADMITTED_EXPORTS = WeakKeyDictionary()


def observation_export_for(session, *, diagnostic=False):
    """Read admission from stable ownership, never from a replaceable attribute."""
    export = _ADMITTED_EXPORTS.get(session)
    if export is not None and not diagnostic:
        export.verify_integrity()
    elif export is None and getattr(session, '_observation_export', None) is not None:
        raise RuntimeError('unadmitted observation export ownership')
    return export


def register_observation_export(session, export):
    if session in _ADMITTED_EXPORTS:
        raise ValueError('observation export ownership already admitted')
    export._owner = ref(session)
    _ADMITTED_EXPORTS[session] = export



class ReducedAxiStreamExport:
    """Private producer coordinator; no buffer exists until explicit admission.

    One reserved failure slot retains the last failed issue, independently of
    normal queue limits. Its input is bounded by the existing wire parser and
    observer's maximum eleven records per edge. No subsequent transport runs.
    """
    def __init__(self, observer, *, session_id, observer_stream_id,
                 artifact_digest, source_component, **limits):
        if source_component != observer.component_id:
            raise ValueError('observer/source component mismatch')
        self.limits = {**DEFAULT_LIMITS, **limits}
        self.source = ObservationStreamSource(binding={
            'schema_version':'observation_stream_binding.v1',
            'session_id':session_id, 'observer_stream_id':observer_stream_id,
            'source_component':source_component, 'artifact_digest':artifact_digest,
            'observer_contract':deepcopy(observer.contract)}, **self.limits)
        self.observer = observer
        self.failure_evidence = None
        self.max_terminal_bytes = 16 * 1024 * 1024
        self.outcome = None
        self.session_failed = False
        self._span = None
        self._record_index = 0
        self._seen_scopes = set()
        self._capture_failure = None
        self._owner = None
        self._admitted_source = self.source
        self._admitted_observer = observer
        self._binding = self.source.identity_document()
        self._contract = deepcopy(observer.contract)
        self._contract_fingerprint = self._canonical(observer.contract)
        self._binding_fingerprint = self._canonical(self._binding)
        self._operation_chain = hashlib.sha256(self._binding_fingerprint).hexdigest()
        self._operation_count = self._issued_record_count = 0
        self._kind_counts = {kind:0 for kind in ('begin_scope', 'end_scope', 'receipt', 'seal')}
        self._component = source_component
        self._admitted_limits_fingerprint = self._canonical(self.limits)
        self._listener = self._capture
        observer._emit_listener = self._listener

    @staticmethod
    def _canonical(value):
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=True, allow_nan=False).encode('ascii')

    def verify_integrity(self):
        owner = None if self._owner is None else self._owner()
        observer = self._admitted_observer
        try:
            intact = (self.source is self._admitted_source
                and self.observer is observer
                and observer._emit_listener is self._listener
                and observer.component_id == self._component
                and self._canonical(observer.contract) == self._contract_fingerprint
                and self._canonical(self._admitted_source.identity_document()) == self._binding_fingerprint
                and self._canonical(self.limits) == self._admitted_limits_fingerprint
                and (self._span is not None or observer._record_count == self._record_index)
                and (self._owner is None or (owner is not None
                    and getattr(owner, '_observation_export', None) is self
                    and owner._axi_observer is observer
                    and owner.source_component == self._component
                    and owner._artifact_document['artifact_digest'] == self._binding['artifact_digest'])))
        except (AttributeError, KeyError, TypeError, ValueError, RecursionError):
            intact = False
        if not intact:
            self._admitted_source.poison('admitted observation ownership/binding integrity drift')
            raise RuntimeError('admitted observation ownership/binding integrity drift')

    def require_active(self):
        self.verify_integrity()
        if self.source.state != 'active':
            raise RuntimeError('reduced AXI observation source is '+self.source.state)

    def require_transport(self):
        self.require_active()
        if self.session_failed or self.outcome is not None:
            raise RuntimeError('reduced AXI session observation failed')

    def _capture(self, event, ordinal):
        try:
            self.verify_integrity()
            if self._span is None:
                raise RuntimeError('observation outside source operation')
            if ordinal != self._record_index + 1:
                raise ValueError('reduced AXI issued record ordinal mismatch')
            if event['kind']=='reduced_axi_raw' and event['raw_event_ref'] != ordinal:
                raise ValueError('reduced AXI raw reference ordinal mismatch')
            self._span.append(deepcopy(event))
            self._record_index = ordinal
        except Exception as error:
            self._capture_failure = {'detail':str(error)[:512],
                                     'ordinal':ordinal, 'observation':deepcopy(event)}
            self._admitted_source.poison('observation capture integrity failure')
            raise

    def _retain_failure(self, kind, payload, span):
        evidence = {'kind':kind, 'payload':payload, 'observations':span,
                    'capture_failure':self._capture_failure}
        digest, size = hashlib.sha256(), 0
        encoder = json.JSONEncoder(sort_keys=True, separators=(',', ':'),
                                   ensure_ascii=True, allow_nan=False)
        for chunk in encoder.iterencode(evidence):
            encoded = chunk.encode('ascii')
            size += len(encoded)
            digest.update(encoded)
        self.failure_evidence = (deepcopy(evidence) if size <= self.max_terminal_bytes
            else {'kind':kind, 'failure':'terminal evidence byte bound exceeded',
                  'sha256':digest.hexdigest(), 'bytes':size})
        # The failed observation is now owned solely by the bounded terminal slot.
        self._capture_failure = None

    def operation(self, kind, payload, action):
        self.require_active()
        self._span = []
        failure = None
        try:
            result = action()
        except Exception as error:
            failure = error
            payload['failure'] = {'type':type(error).__name__, 'detail':str(error)[:512]}
        span, self._span = self._span, None
        payload = {'authority':'observation_only', 'runtime_accepted':False,
                   'semantic_accepted':False, **payload}
        try:
            self.verify_integrity()
            token = self.source.issue(kind, payload, span)
            issued = self.source.lookup(token)
            self._operation_count += 1
            self._issued_record_count += issued['record_count']
            self._kind_counts[kind] += 1
            self._operation_chain = hashlib.sha256(
                (self._operation_chain + ':' + issued['content_digest']).encode('ascii')).hexdigest()
        except Exception:
            self._retain_failure(kind, payload, span)
            self._admitted_source.poison('source emission or capture integrity failure')
            if failure is not None:
                raise failure
            raise
        if failure is not None:
            violation = span[-1] if span else {}
            intact_protocol_failure = (kind == 'receipt' and self.observer._failed
                and violation.get('kind') == 'reduced_axi_violation'
                and isinstance(failure, ValueError)
                and str(failure) == 'reduced_axi_' + violation.get('reason', '')
                and bool(violation.get('raw_event_refs'))
                and any(row.get('kind') == 'reduced_axi_raw'
                    and row.get('raw_event_ref') == violation['raw_event_refs'][0]
                    for row in span))
            if intact_protocol_failure:
                self.outcome = 'observed_protocol_failure'
            else:
                self._admitted_source.poison('producer operation failure')
            raise failure
        return result

    def begin(self, scope, *, prepare=None, requested_testcase_id=None):
        payload = {'scope':deepcopy(scope), 'requested_testcase_id':requested_testcase_id}
        def action():
            actual = scope if prepare is None else prepare()
            payload['scope'] = deepcopy(actual)
            key = tuple(sorted(actual.items()))
            if key in self._seen_scopes:
                raise ValueError('reduced_axi_scope_reuse')
            self.observer.begin_scope(**actual)
            self._seen_scopes.add(key)
        return self.operation('begin_scope', payload, action)

    def end(self, service_pending=None):
        return self.operation('end_scope', {'scope':deepcopy(self.observer.scope),
             'pending':deepcopy(self.observer.pending),
             'service_pending':None if service_pending is None else {
                 p:{slot:value is not None for slot,value in slots.items()}
                 for p,slots in service_pending.items()}}, self.observer.end_scope)

    def receipt(self, receipt, *, operation, fields, wire_command, wire_reply,
                cumulative_after, tick_base, artifact_kind):
        witness = dict(operation=operation, command_fields=list(fields),
            wire_command=wire_command, wire_reply=wire_reply,
            receipt=deepcopy(asdict(receipt)), cumulative_after=cumulative_after,
            tick_base=tick_base, scope=deepcopy(self.observer.scope))
        def action():
            if receipt.status == 'error':
                raise ValueError(f'{receipt.error_code}: {receipt.error_detail}')
            payload = receipt.payload
            if (receipt.new_ticks != 1 or receipt.tick_after != receipt.tick_before+1
                    or cumulative_after != tick_base+receipt.tick_after
                    or not isinstance(payload, dict) or payload.get('kind') != artifact_kind
                    or not isinstance(payload.get('samples'), list)
                    or len(payload['samples']) != 1
                    or payload['samples'][0].get('local_tick') != receipt.tick_after):
                raise ValueError('reduced AXI receipt is not one measured edge')
            pre = payload.get('pre_backend')
            expected = {p+'_'+r:w for p,shape in SHAPES.items() for r,(_,w) in shape.items()}
            driven = fields[-len(STEP_PORTS):]
            if (not isinstance(pre, dict) or set(pre) != set(expected)
                    or any(type(pre[n]) is not int or not 0 <= pre[n] < 1 << w for n,w in expected.items())
                    or any(pre[n] != v for n,v in zip(STEP_PORTS, driven))
                    or payload['samples'][0].get('pre', {}).get('backend') != pre):
                raise ValueError('invalid reduced AXI physical observation')
            self.observer.observe(deepcopy(payload['samples'][0]))
        return self.operation('receipt', witness, action)

    def seal(self):
        return self.operation('seal', {'recording_integrity':'complete',
            'prior_operation_count':self._operation_count,
            'prior_record_count':self._issued_record_count,
            'prior_kind_counts':deepcopy(self._kind_counts),
            'prior_operation_chain_sha256':self._operation_chain,
            'scope':deepcopy(self.observer.scope),
            'outcome':self.outcome,
            'pending':deepcopy(self.observer.pending)}, lambda: None)
