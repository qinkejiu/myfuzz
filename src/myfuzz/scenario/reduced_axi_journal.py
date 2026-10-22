"""Bounded consistency replay of a complete reduced AXI observation journal.

Hashes inside a journal are consistency commitments, not external authentication.
Offline authentication additionally requires a trusted external journal manifest.
No result here grants functional, memory, retirement or feedback authority.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
import math

from myfuzz.local_harness.renderer import _sha as artifact_sha
from myfuzz.local_harness.vexii_axi_fields import SHAPES, STEP_PORTS, STEP_MAXIMA
from myfuzz.local_harness.wire import parse_driver_receipt, _clock_trace_identity
from myfuzz.scenario.observation_stream import ObservationStreamSource
from myfuzz.scenario.reduced_axi_events import ReducedAxiObserver
from myfuzz.scenario.reduced_axi_stream_source import DEFAULT_LIMITS as SOURCE_LIMITS

DEFAULT_LIMITS = dict(max_streams=1, max_scopes=1024, max_raw_mappings=100000,
    max_pending=8, max_expected_records=11, max_retained_records=1024,
    max_input_bytes=8388608, max_total_input_bytes=1073741824,
    max_events=1000000, max_event_gap=10000)
_AUTHORITY = dict(authority='observation_only', runtime_accepted=False, semantic_accepted=False)
_ENVELOPE = {'event_id', 'producer_event_id', 'component'}
_BINDING_KIND = 'reduced_axi_stream_binding'
_OPERATION_KIND = 'reduced_axi_source_operation'
_SIDECAR_KIND = 'reduced_axi_journal_binding'
_OBSERVATION_KINDS = {'reduced_axi_raw', 'reduced_axi_accept', 'reduced_axi_complete',
    'reduced_axi_write_join', 'reduced_axi_reset', 'reduced_axi_violation'}
_OPERATION_KEYS = {'schema_version','binding_digest','operation_index','kind','payload',
    'observations','first_record_index','record_count','content_digest'}


def _require(condition, reason):
    if not condition:
        raise ValueError(reason)


def _integer(value, minimum=1):
    return type(value) is int and value >= minimum


def _strict(value, depth=0):
    _require(depth <= 32, 'json_depth_limit')
    if value is None or type(value) in (str, int, bool):
        return
    if type(value) is float:
        _require(math.isfinite(value), 'invalid_json')
        return
    _require(type(value) in (dict, list), 'invalid_json')
    if type(value) is dict:
        _require(all(type(key) is str for key in value), 'invalid_json')
        values = value.values()
    else:
        values = value
    for item in values:
        _strict(item, depth+1)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _equal(a, b):
    return _canonical(a) == _canonical(b)


def _bounded_size(value, limit):
    """Count before retaining/encoding a complete second copy."""
    _strict(value)
    size = 0
    for chunk in json.JSONEncoder(sort_keys=True, separators=(',', ':'),
            ensure_ascii=True, allow_nan=False).iterencode(value):
        size += len(chunk)
        _require(size <= limit, 'input_bytes_limit')
    return size


def _original(event):
    return {key:value for key,value in event.items() if key not in _ENVELOPE}


def _roles(record):
    """Fixed v1 role paths; no recursive discovery of claimed reference fields."""
    kind = record.get('kind')
    _require(kind in _OBSERVATION_KINDS, 'unknown_observation_kind')
    roles = []
    allowed = {'raw_event_ref'} if kind == 'reduced_axi_raw' else {'raw_event_refs'}
    if kind == 'reduced_axi_complete': allowed.add('request_refs')
    if kind == 'reduced_axi_reset': allowed = {'pending_request_refs'}
    for field in ('raw_event_ref','raw_event_refs','request_refs','pending_request_refs'):
        _require(field not in record or field in allowed, 'unexpected_reference_role')
    if kind == 'reduced_axi_raw':
        roles.append(('raw_event_ref', [record['raw_event_ref']]))
    elif kind == 'reduced_axi_reset':
        pending = record['pending_request_refs']
        _require(type(pending) is dict and set(pending) == set(SHAPES), 'reset_context_shape')
        for endpoint in SHAPES:
            slots = pending[endpoint]
            _require(type(slots) is dict and set(slots) == {'read','aw','w','write'}, 'reset_context_shape')
            for slot in ('read','aw','w','write'):
                context = slots[slot]
                if context is None: continue
                keys = {'strobe','refs','tick'} if slot == 'w' else {'id','address','size','refs','tick'}
                _require(type(context) is dict and set(context) == keys, 'reset_context_shape')
                roles.append((f'pending_request_refs.{endpoint}.{slot}.refs', context['refs']))
    else:
        roles.append(('raw_event_refs', record['raw_event_refs']))
        if kind == 'reduced_axi_complete': roles.append(('request_refs', record['request_refs']))
    for role, refs in roles:
        _require(type(refs) is list and 1 <= len(refs) <= 2
                 and all(_integer(ref) for ref in refs), 'reference_shape')
    return roles


def build_reduced_axi_journal_sidecar(observation_event, *, stream_binding_event_id,
        operation_event_id, record_index, raw_mappings):
    """Pure mapping after Runner assigns IDs; caller owns a bounded lifetime map.

    ``raw_mappings[local_ref] = {'event_id': original_raw_id, 'scope': full_scope}``.
    Add a raw to that map only AFTER building/committing its own sidecar. This
    helper never mutates any input and does not authenticate source issuance.
    """
    _strict(observation_event)
    event_id = observation_event['event_id']
    _require(all(_integer(n) for n in (event_id, stream_binding_event_id,
        operation_event_id, record_index)), 'journal_index_type')
    _require(stream_binding_event_id < operation_event_id < event_id, 'journal_order')
    record = _original(observation_event)
    resolved = []
    for role, refs in _roles(record):
        ids = []
        for ref in refs:
            if role == 'raw_event_ref':
                _require(ref == record_index and ref not in raw_mappings, 'duplicate_raw_definition')
                target = event_id
            else:
                mapping = raw_mappings.get(ref)
                _require(type(mapping) is dict, 'missing_raw_reference')
                target = mapping['event_id']
                _require(_integer(target) and target < event_id, 'forward_raw_reference')
                _require(_equal(mapping['scope'], record['scope']), 'wrong_scope_reference')
            ids.append(target)
        resolved.append(dict(role=role, local_refs=list(refs), event_ids=ids))
    return dict(kind=_SIDECAR_KIND, schema_version='reduced_axi_journal_binding.v1',
        component=observation_event['component'], stream_binding_event_id=stream_binding_event_id,
        operation_event_id=operation_event_id, observation_event_id=event_id,
        record_index=record_index, observation_sha256=_digest(record),
        resolved_refs=resolved, **_AUTHORITY)


class ReducedAxiJournalConsumer:
    """One explicitly bound stream, following unfiltered consecutive global IDs.

    consume returns None without copying report history. Integrity errors permanently poison
    the consumer and are represented by a stable first reason. Constructor errors
    raise ValueError. finalize takes no detached seal or cursor state.
    """
    def __init__(self, binding, *, runner_component, runtime_document, limits=None):
        limits = {} if limits is None else limits
        _require(type(limits) is dict and not (set(limits)-set(DEFAULT_LIMITS)), 'invalid_limits')
        self.limits = {**DEFAULT_LIMITS, **limits}
        _require(all(_integer(n) for n in self.limits.values()), 'invalid_limits')
        _require(type(runner_component) is str and bool(runner_component), 'invalid_runner_component')
        _bounded_size(binding, self.limits['max_input_bytes'])
        _bounded_size(runtime_document, self.limits['max_input_bytes'])
        ObservationStreamSource(binding=binding)  # exact six fields / JSON types
        _require(type(runtime_document) is dict, 'runtime_document_invalid')
        unsigned = {k:v for k,v in runtime_document.items() if k != 'artifact_digest'}
        _require(runtime_document.get('artifact_digest') == artifact_sha(unsigned)
            and binding['artifact_digest'] == runtime_document['artifact_digest'], 'runtime_digest_mismatch')
        kind = runtime_document.get('kind')
        _require(kind in ('reduced_dual_axi_cpu','reduced_dual_axi_irq_cpu'), 'runtime_kind_unsupported')
        _clock_trace_identity(runtime_document.get('clock_schedule'))
        contract = binding['observer_contract']
        try:
            budgets = contract['budgets']
            self.observer = ReducedAxiObserver(component_id=binding['source_component'],
                max_edges=budgets['max_edges'], max_bytes=budgets['max_raw_bytes'], max_scopes=budgets['max_scopes'])
        except (KeyError, TypeError) as error:
            raise ValueError('observer_contract_mismatch') from error
        _require(_equal(contract, self.observer.contract), 'observer_contract_mismatch')
        self.binding = deepcopy(binding)
        self.runner_component = runner_component
        self.runtime = deepcopy(runtime_document)
        self._binding_digest = _digest(binding)
        self._binding_id = None
        self._source_limits = None
        self._cursor = self._gap = self._input_bytes = 0
        self._operations = self._records = self._receipts = 0
        self._kind_counts = dict.fromkeys(('begin_scope','end_scope','receipt','seal'),0)
        self._chain = self._binding_digest
        self._expected = []
        self._expected_index = 0
        self._operation_id = None
        self._awaiting_sidecar = None
        self._raw = {}
        self._scopes = set()
        self._native = {}
        self._cumulative = 0
        self._sealed = self._finalized = False
        self._reason = None
        self._outcome = None
        self._producer_outcome = None
        self._boundaries = []
        self._protocol_failure = None
        self._orders = {}

    def _poison(self, reason):
        if self._reason is None:
            self._reason = reason
        self._expected.clear()
        self._awaiting_sidecar = None
        self.observer.events.clear()

    def consume(self, event):
        if self._reason is not None: return None
        try:
            _require(not self._finalized, 'consume_after_finalize')
            size = _bounded_size(event, self.limits['max_input_bytes'])
            _require(self._input_bytes + size <= self.limits['max_total_input_bytes'], 'total_input_bytes_limit')
            _require(type(event) is dict and _integer(event.get('event_id')), 'journal_index_type')
            _require(event['event_id'] == self._cursor+1, 'journal_id_discontinuity')
            _require(self._cursor < self.limits['max_events'], 'events_limit')
            self._cursor += 1
            self._input_bytes += size
            kind = event.get('kind')
            if event.get('component') == self.runner_component and (
                    event.get('schema_version') == 'reduced_axi_observation.v1'
                    or type(kind) is str and kind.startswith('reduced_axi_')):
                _require(kind in _OBSERVATION_KINDS | {_BINDING_KIND,_OPERATION_KIND,_SIDECAR_KIND},
                    'unknown_stream_record_kind')
            own = (event.get('component') == self.runner_component
                and kind in _OBSERVATION_KINDS | {_BINDING_KIND,_OPERATION_KIND,_SIDECAR_KIND})
            if not own:
                self._gap += 1
                _require(self._gap <= self.limits['max_event_gap'], 'event_gap_limit')
                return None
            self._gap = 0
            _require(_integer(event.get('producer_event_id')), 'producer_index_type')
            _require(event['producer_event_id'] < event['event_id'], 'producer_event_not_prior')
            if kind == _BINDING_KIND: self._consume_binding(event)
            else:
                _require(self._binding_id is not None, 'missing_stream_binding')
                if kind == _OPERATION_KIND: self._consume_operation(event)
                elif kind == _SIDECAR_KIND: self._consume_sidecar(event)
                else: self._consume_original(event)
        except (ValueError, KeyError, TypeError, IndexError, OverflowError, RecursionError) as error:
            reason = str(error) if isinstance(error, ValueError) else 'malformed_record'
            self._poison(reason[:128])
        return None

    def _consume_binding(self, event):
        _require(self._binding_id is None, 'duplicate_stream_binding')
        _require(set(event) == _ENVELOPE | {'kind','schema_version','binding','limits'}, 'binding_row_shape')
        _require(event['schema_version'] == 'reduced_axi_stream_binding.v1'
            and _equal(event['binding'], self.binding), 'stream_binding_mismatch')
        limits = event['limits']
        _require(type(limits) is dict and set(limits) == set(SOURCE_LIMITS)
            and all(_integer(n) for n in limits.values()), 'source_limits_invalid')
        self._source_limits = deepcopy(limits)
        self._binding_id = event['event_id']

    def _span_done(self):
        _require(self._awaiting_sidecar is None, 'missing_sidecar')
        _require(not self._expected, 'missing_observation')

    def _consume_operation(self, event):
        self._span_done()
        _require(not self._sealed, 'operation_after_seal')
        _require(set(event) == _ENVELOPE | {'kind','schema_version','stream_binding_event_id','operation'}, 'operation_row_shape')
        _require(event['schema_version'] == 'reduced_axi_source_operation.v1'
            and type(event['stream_binding_event_id']) is int
            and event['stream_binding_event_id'] == self._binding_id, 'operation_binding_mismatch')
        op = event['operation']
        _require(type(op) is dict and set(op) == _OPERATION_KEYS, 'operation_shape')
        _require(op['schema_version'] == 'observation_stream_operation.v1'
            and op['binding_digest'] == self._binding_digest, 'operation_binding_mismatch')
        _require(_integer(op['operation_index']) and op['operation_index'] == self._operations+1, 'operation_index_mismatch')
        _require(_integer(op['first_record_index']) and op['first_record_index'] == self._records+1, 'record_index_mismatch')
        _require(type(op['observations']) is list and _integer(op['record_count'],0)
            and op['record_count'] == len(op['observations']), 'operation_span_mismatch')
        _require(op['content_digest'] == _digest({k:v for k,v in op.items() if k != 'content_digest'}), 'operation_digest_mismatch')
        _require(self._operations < self._source_limits['max_operations'], 'source_operations_limit')
        _require(len(_canonical(op)) <= self._source_limits['max_operation_bytes'], 'source_operation_bytes_limit')
        _require(len(_canonical(op)) <= self._source_limits['max_pending_bytes'], 'source_pending_bytes_limit')
        _require(op['record_count'] <= self.limits['max_expected_records'], 'expected_records_limit')
        kind, payload = op['kind'], op['payload']
        _require(kind in self._kind_counts and type(payload) is dict, 'operation_kind_invalid')
        _require(all(k in payload and _equal(payload[k],v) for k,v in _AUTHORITY.items()), 'operation_authority_mismatch')
        self._replay(kind, payload)
        _require(_equal(self.observer.events, op['observations']), 'projection_mismatch')
        _require(sum(sum(slots.values()) for slots in self.observer.pending.values()) <= self.limits['max_pending'], 'pending_limit')
        self._expected = deepcopy(self.observer.events)
        self.observer.events.clear()
        self._expected_index = op['first_record_index']
        self._operation_id = event['event_id']
        self._operations += 1
        self._records += op['record_count']
        self._kind_counts[kind] += 1
        self._chain = hashlib.sha256((self._chain+':'+op['content_digest']).encode('ascii')).hexdigest()

    def _replay(self, kind, payload):
        if kind == 'begin_scope':
            _require(self._outcome is None, 'lifecycle_after_protocol_failure')
            _require(set(payload) == set(_AUTHORITY) | {'scope','requested_testcase_id'}, 'lifecycle_payload_shape')
            scope = payload['scope']
            _require(type(scope) is dict and set(scope) == {'execution_id','testcase_id','reset_epoch'}, 'lifecycle_scope_shape')
            _require(payload['requested_testcase_id'] is None or (
                type(payload['requested_testcase_id']) is str
                and payload['requested_testcase_id'] == scope['testcase_id']), 'requested_testcase_mismatch')
            scope_key = _canonical(scope)
            _require(scope_key not in self._scopes, 'scope_reuse')
            _require(len(self._scopes) < self.limits['max_scopes'], 'scopes_limit')
            self.observer.begin_scope(**scope)
            self._scopes.add(scope_key)
            self._orders.clear()
        elif kind == 'end_scope':
            _require(set(payload) == set(_AUTHORITY) | {'scope','pending','service_pending'}, 'lifecycle_payload_shape')
            _require(_equal(payload['scope'],self.observer.scope)
                and _equal(payload['pending'],self.observer.pending), 'lifecycle_scope_mismatch')
            service = payload['service_pending']
            if service is not None:
                _require(type(service) is dict and set(service) == set(SHAPES), 'service_pending_shape')
                for slots in service.values():
                    _require(type(slots) is dict and set(slots) == {'read','aw','w','b'}
                        and all(type(v) is bool for v in slots.values()), 'service_pending_shape')
            self.observer.end_scope()
            self._orders.clear()
        elif kind == 'receipt':
            _require(self._outcome is None, 'receipt_after_protocol_failure')
            self._replay_receipt(payload)
        else:
            _require(set(payload) == set(_AUTHORITY) | {'recording_integrity','prior_operation_count',
                'prior_record_count','prior_kind_counts','prior_operation_chain_sha256','scope','outcome','pending'}, 'seal_payload_shape')
            declared_outcome = payload['outcome']
            _require((self._outcome is None and declared_outcome in (None,'observed_session_failure'))
                or self._outcome == 'observed_protocol_failure' and declared_outcome == self._outcome,
                'seal_outcome_mismatch')
            expected = dict(recording_integrity='complete', prior_operation_count=self._operations,
                prior_record_count=self._records, prior_kind_counts=self._kind_counts,
                prior_operation_chain_sha256=self._chain, scope=self.observer.scope,
                outcome=declared_outcome, pending=self.observer.pending, **_AUTHORITY)
            _require(_equal(payload, expected), 'seal_prefix_mismatch')
            self._producer_outcome = declared_outcome
            self._sealed = True

    def _replay_receipt(self, payload):
        keys = set(_AUTHORITY) | {'operation','command_fields','wire_command','wire_reply','receipt',
            'cumulative_after','tick_base','scope'}
        _require(set(payload) in (keys,keys | {'failure'}), 'receipt_payload_shape')
        _require(self.observer.scope is not None and _equal(payload['scope'], self.observer.scope), 'receipt_scope_mismatch')
        scope = self.observer.scope
        execution = scope['execution_id']
        state = self._native.get(execution)
        if state is None:
            state = dict(sequence=0,tick=0,base=self._cumulative)
            self._native[execution] = state
        irq = self.runtime['kind'] == 'reduced_dual_axi_irq_cpu'
        operation = 'STEP_REDUCED_AXI_IRQ' if irq else 'STEP_REDUCED_AXI'
        fields = payload['command_fields']
        maxima = (1,)+STEP_MAXIMA if irq else STEP_MAXIMA
        _require(payload['operation'] == operation and type(fields) is list
            and len(fields) == len(maxima) and all(type(v) is int and 0 <= v <= m
                for v,m in zip(fields,maxima)), 'command_fields_invalid')
        sequence = state['sequence']+1
        command = f'CMD {execution} {sequence:x} {operation} ' + ' '.join(f'{v:x}' for v in fields) + '\n'
        _require(payload['wire_command'] == command, 'wire_command_mismatch')
        wire = payload['wire_reply']
        _require(type(wire) is str and wire.endswith('\n') and not wire.endswith('\n\n'), 'wire_reply_shape')
        receipt = parse_driver_receipt(wire[:-1],execution=execution,sequence=sequence,
            current_tick=state['tick'],kind=self.runtime['kind'],clock_schedule=self.runtime.get('clock_schedule'))
        _require(_equal(asdict(receipt),payload['receipt']), 'wire_receipt_mismatch')
        _require(receipt.status == 'result' and receipt.new_ticks == 1
            and receipt.tick_after == receipt.tick_before+1, 'receipt_not_measured_edge')
        _require(type(payload['tick_base']) is int and payload['tick_base'] == state['base']
            and type(payload['cumulative_after']) is int
            and payload['cumulative_after'] == state['base']+receipt.tick_after == self._cumulative+1,
            'cumulative_tick_mismatch')
        sample = receipt.payload['samples'][0]
        pre = receipt.payload['pre_backend']
        expected = {p+'_'+r:w for p,s in SHAPES.items() for r,(_,w) in s.items()}
        _require(type(pre) is dict and set(pre) == set(expected)
            and all(type(pre[n]) is int and 0 <= pre[n] < 1 << w for n,w in expected.items())
            and all(pre[n] == v for n,v in zip(STEP_PORTS,fields[-len(STEP_PORTS):]))
            and _equal(sample['pre']['backend'],pre), 'physical_sample_mismatch')
        failure = None
        try:
            self.observer.observe(deepcopy(sample))
        except ValueError as error:
            failure = {'type':type(error).__name__,'detail':str(error)[:512]}
            _require(bool(self.observer.events) and self.observer.events[-1]['kind'] == 'reduced_axi_violation'
                and str(error) == 'reduced_axi_'+self.observer.events[-1]['reason'], 'replay_failure')
            self._outcome = 'observed_protocol_failure'
        _require(_equal(payload.get('failure'),failure), 'receipt_failure_mismatch')
        _require(sum(row['kind']=='reduced_axi_raw' for row in self.observer.events) == 1, 'receipt_raw_count_mismatch')
        state.update(sequence=sequence,tick=receipt.tick_after)
        self._cumulative = payload['cumulative_after']
        self._receipts += 1

    def _consume_original(self, event):
        _require(self._awaiting_sidecar is None, 'missing_sidecar')
        _require(bool(self._expected), 'unexpected_observation')
        record = _original(event)
        _require(_equal(record,self._expected[0]), 'original_observation_mismatch')
        _require(record['component_id'] == self.binding['source_component'], 'source_component_mismatch')
        sidecar = build_reduced_axi_journal_sidecar(event,stream_binding_event_id=self._binding_id,
            operation_event_id=self._operation_id,record_index=self._expected_index,raw_mappings=self._raw)
        self._awaiting_sidecar = (sidecar,deepcopy(record))

    def _consume_sidecar(self, event):
        _require(self._awaiting_sidecar is not None, 'unexpected_sidecar')
        expected, record = self._awaiting_sidecar
        _require(_equal({k:v for k,v in event.items() if k not in {'event_id','producer_event_id'}}, expected), 'sidecar_mismatch')
        if record['kind'] == 'reduced_axi_raw':
            _require(len(self._raw) < self.limits['max_raw_mappings'], 'raw_mappings_limit')
            self._raw[record['raw_event_ref']] = dict(event_id=expected['observation_event_id'],scope=deepcopy(record['scope']))
        elif record['kind'] == 'reduced_axi_write_join':
            self._orders[record['endpoint_id']] = record['aw_w_order']
        elif record['kind'] == 'reduced_axi_violation':
            self._protocol_failure = dict(reason=record['reason'],
                observation_event_id=expected['observation_event_id'],
                raw_event_refs=deepcopy(record['raw_event_refs']),
                raw_event_ids=deepcopy(expected['resolved_refs'][0]['event_ids']),
                scope=deepcopy(record['scope']), local_tick=record['local_tick'], **_AUTHORITY)
        elif record['kind'] == 'reduced_axi_complete':
            _require(len(self._boundaries) < self.limits['max_retained_records'], 'retained_records_limit')
            roles = {r['role']:r['event_ids'] for r in expected['resolved_refs']}
            status = record['payload'][record['channel']+'resp']
            self._boundaries.append(dict(observation_event_id=expected['observation_event_id'],
                endpoint_id=record['endpoint_id'],channel=record['channel'],scope=deepcopy(record['scope']),
                request_event_ids=roles['request_refs'],response_event_ids=roles['raw_event_refs'],
                request_raw_refs=deepcopy(record['request_refs']), response_raw_refs=deepcopy(record['raw_event_refs']),
                native_id=record['payload'][record['channel']+'id'],local_tick=record['local_tick'],
                payload=deepcopy(record['payload']),
                response_status=status,outcome='okay' if status == 0 else 'error',
                aw_w_order=self._orders.pop(record['endpoint_id'],None) if record['channel']=='b' else None,
                **_AUTHORITY))
        self._expected.pop(0)
        self._expected_index += 1
        self._awaiting_sidecar = None

    def operation_ready(self, operation_index):
        """Cheap ACK prerequisite for exactly the most recently consumed operation.

        True means its complete original/sidecar span matched replay. The caller
        must also verify actual source ownership/state and durable append success.
        """
        _require(_integer(operation_index), 'journal_index_type')
        return (self._reason is None and self._operations == operation_index
            and not self._expected and self._awaiting_sidecar is None)

    def report(self):
        complete = self._reason is None and self._sealed and not self._expected and self._awaiting_sidecar is None
        return dict(schema_version='reduced_axi_journal_report.v1',
            status='failed' if self._reason else 'complete' if complete else 'prefix',
            reason=self._reason, recording_integrity='complete' if complete else 'unverified',
            outcome=self._outcome or self._producer_outcome, protocol_outcome=self._outcome,
            producer_declared_outcome=self._producer_outcome,
            journal_event_id=self._cursor, operation_count=self._operations,
            observation_count=self._records, receipt_count=self._receipts, raw_mapping_count=len(self._raw),
            pending=deepcopy(self.observer.pending), boundary_observations=deepcopy(self._boundaries),
            protocol_failure=deepcopy(self._protocol_failure),
            external_authentication='trusted_external_journal_manifest_required', **_AUTHORITY)

    def finalize(self):
        if not self._finalized:
            if self._reason is None:
                try:
                    self._span_done()
                    _require(self._binding_id is not None, 'missing_stream_binding')
                    _require(self._sealed, 'missing_seal')
                except ValueError as error:
                    self._poison(str(error))
            self._finalized = True
        return self.report()
