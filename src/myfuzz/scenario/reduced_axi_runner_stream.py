"""Bounded live import of admitted reduced AXI issuance into Runner journals.

ACK commits to the temporary Runner journal, not an fsync of exported artifacts.
An append can commit before raising; any import error permanently forbids retries.
"""
from copy import deepcopy
import json

from .reduced_axi_journal import (ReducedAxiJournalConsumer,
    build_reduced_axi_journal_sidecar)
from .reduced_axi_stream_source import observation_export_for
from .observation_stream import _validate_json


def canonical(value):
    _validate_json(value)
    return json.dumps(value,sort_keys=True,separators=(',',':'),
                      ensure_ascii=True,allow_nan=False).encode('ascii')


class _EncodedSize:
    """A precomputed encoded JSON length, never an evidence value."""
    def __init__(self, byte_count):
        self.byte_count = byte_count


def _encoded_size(value):
    if isinstance(value, _EncodedSize):
        return value.byte_count
    if isinstance(value, dict):
        return (2 + sum(len(canonical(key))+1+_encoded_size(item)
                        for key,item in value.items()) + max(0,len(value)-1))
    if isinstance(value, list):
        return 2 + sum(_encoded_size(item) for item in value) + max(0,len(value)-1)
    return len(canonical(value))


class ReducedAxiRunnerStreams:
    def __init__(self, runner, *, limits=None):
        self.runner = runner
        self.streams = {}
        self.closed = False
        limits={} if limits is None else deepcopy(dict(limits))
        if (set(limits)-set(runner.sessions) or any(type(v) is not dict
                or set(v)-{'source','consumer'} for v in limits.values())):
            raise ValueError('invalid reduced AXI stream limits')
        seen = set()
        for ordinal,(alias,session) in enumerate(sorted(runner.sessions.items()),1):
            runtime = getattr(session,'_artifact_document',None)
            admit = getattr(session,'admit_observation_stream',None)
            if (not isinstance(runtime,dict) or runtime.get('kind') not in
                    ('reduced_dual_axi_cpu','reduced_dual_axi_irq_cpu')
                    or not callable(admit)):
                continue
            if id(session) in seen:
                raise ValueError('duplicate reduced AXI session alias')
            seen.add(id(session))
            source = admit(session_id=f'runner-session-{ordinal}',
                           observer_stream_id=f'runner-stream-{ordinal}',
                           **limits.get(alias,{}).get('source',{}))
            export = observation_export_for(session)
            if export is None or source is not export.source:
                raise ValueError('reduced AXI source ownership unavailable')
            if any(s['source'] is source for s in self.streams.values()):
                raise ValueError('duplicate reduced AXI source alias')
            binding = source.identity_document()
            consumer = ReducedAxiJournalConsumer(binding,runner_component=alias,
                                                 runtime_document=runtime,
                limits=limits.get(alias,{}).get('consumer'))
            self.streams[alias] = dict(session=session,source=source,export=export,
                runtime=deepcopy(runtime),binding=binding,limits=deepcopy(export.limits),
                consumer=consumer,binding_id=None,raw={},failure=None,stage='admission',
                operation_index=None,start_id=None,last_id=None,last_completed=None,importing=False)

    def source_operation_fit(self, alias, kind, *, testcase_id=None):
        """Source ASCII bounds from supported producer DTOs, before effects.

        These are shape/encoding bounds, not issued operations. Malformed wire
        input outside the pinned generated ABI may instead occupy the producer's
        bounded failure slot; it cannot be authenticated as a supported receipt.
        """
        s = self.streams[alias]
        session, export = s['session'], s['export']
        observer = export.observer
        authority = dict(authority='observation_only', runtime_accepted=False,
                         semantic_accepted=False)
        # Generated UUIDs have 32 lowercase hex characters. Case/epoch lengths
        # are known before process startup, including source ASCII escaping.
        case = testcase_id if testcase_id is not None else (
            session._case_id or getattr(self.runner, 'testcase_id', None))
        if case is None:
            raise ValueError('source envelope fit requires testcase identity')
        native_scope = dict(execution_id='f'*32, testcase_id=case,
                            reset_epoch=session.reset_epoch + (kind == 'reset'))
        full_scope = dict(native_scope, source_component=s['binding']['source_component'])
        scope = observer.scope if observer.scope is not None else full_scope
        # The export truncates failure.detail to 512 Unicode code points;
        # source ensure_ascii uses at most 12 bytes per point. Class names below
        # are actual supported producer/transport exceptions, not attacker-owned
        # arbitrary Python callback types. Unsupported corruption stays terminal.
        from .protocol_io import LocalCommandDeadlineExceeded
        from .contracts import ProtocolEnvironmentError
        failure_types = (ValueError, RuntimeError, OSError, TimeoutError,
            UnicodeError, FileNotFoundError, PermissionError, BrokenPipeError,
            EOFError, BlockingIOError, LocalCommandDeadlineExceeded,
            ProtocolEnvironmentError)
        failure = dict(type=max((t.__name__ for t in failure_types),
                                key=lambda name: len(canonical(name))),
                       detail=_EncodedSize(2 + 12*512))

        def envelope(operation_kind, payload, observations, record_count,
                     *, offset=1, record_offset=0, failed=True):
            if failed:
                payload = dict(payload, failure=failure)
            return _encoded_size(dict(
                schema_version='observation_stream_operation.v1',
                binding_digest='0'*64,
                operation_index=export._operation_count + offset,
                kind=operation_kind, payload=dict(authority, **payload),
                observations=observations,
                first_record_index=observer._record_count + record_offset + 1,
                record_count=record_count, content_digest='0'*64))

        def begin(*, offset=1, record_offset=0):
            return envelope('begin_scope', dict(scope=native_scope,
                requested_testcase_id=case), [], 0, offset=offset,
                record_offset=record_offset)

        if kind == 'begin_scope':
            return dict(operation_bytes=[begin()], sample_bytes=0)
        if kind in ('end_scope', 'reset'):
            old_scope = observer.scope
            service_pending = {p:{slot:value is not None for slot,value in slots.items()}
                               for p,slots in session._state.items()}
            observations = []
            if old_scope is not None:
                observations.append(dict(schema_version='reduced_axi_observation.v1',
                    kind='reduced_axi_reset', component_id=observer.component_id,
                    scope=old_scope, cancelled=observer.pending,
                    pending_request_refs=observer._state, next_scope=None, **authority))
            end = envelope('end_scope', dict(scope=old_scope, pending=observer.pending,
                service_pending=service_pending), observations, len(observations))
            sizes = [end]
            if kind == 'reset':
                sizes.append(begin(offset=2, record_offset=len(observations)))
            return dict(operation_bytes=sizes, sample_bytes=0)
        if kind == 'seal':
            payload = dict(recording_integrity='complete',
                prior_operation_count=export._operation_count,
                prior_record_count=export._issued_record_count,
                prior_kind_counts=export._kind_counts,
                prior_operation_chain_sha256='0'*64, scope=observer.scope,
                outcome=export.outcome, pending=observer.pending)
            return dict(operation_bytes=[envelope('seal', payload, [], 0, failed=False)],
                        sample_bytes=0)
        if kind != 'receipt':
            raise ValueError('unsupported source envelope fit kind')

        from myfuzz.local_harness.vexii_axi_fields import SHAPES, STEP_MAXIMA, IRQ_STEP_MAXIMA
        from myfuzz.local_harness.wire import _clock_trace_identity, _clock_edges_through
        runtime = s['runtime']
        limits = runtime['driver_limits']
        if limits['max_samples_per_command'] != 1:
            raise ValueError('source envelope fit requires single-edge producer')
        backend = {p+'_'+role:(1 << width)-1
            for p,shape in SHAPES.items() for role,(_,width) in shape.items()}
        declared_backend = {row['name']:(1 << row['width'])-1
                            for row in runtime['backend_ports']}
        if declared_backend != backend:
            raise ValueError('source envelope fit backend ABI mismatch')
        physical = {row['runtime_name']:('f'*row['hex_digits'] if row['width']>64
                    else (1 << row['width'])-1) for row in runtime['physical_exports']}
        # For this ABI the renderer emits backend and physical snapshots only.
        # Snapshot aliases/storage/native taps belong to other admitted ABIs.
        snapshot = dict(backend=backend, physical=physical)
        if any(not key.isascii() for key in list(backend)+list(physical)):
            raise ValueError('source envelope fit requires generated ASCII signal names')
        before = session.local_ticks - session._tick_base
        after, sequence = before + 1, session._sequence + 1
        if not 0 <= before < (1 << 64)-1 or not 0 < sequence < (1 << 64):
            raise ValueError('source envelope fit native counter overflow')
        sample = dict(local_tick=after, pre=snapshot, post=snapshot)
        clock_identity = _clock_trace_identity(runtime.get('clock_schedule'))
        if clock_identity is not None and len(clock_identity[0]) > 1:
            rows, startup = clock_identity
            sample['clock_edges'] = {row['domain']:
                _clock_edges_through(row, startup+after)-_clock_edges_through(row,startup)
                for row in rows}
        # Exactly the observer's spaced ensure_ascii serialization, independent
        # of the source cap and its compact encoding.
        sample_bytes = len(json.dumps(sample,sort_keys=True,allow_nan=False).encode())
        payload = dict(schema_version='local_driver_result.v1', kind=runtime['kind'],
            samples=[sample], observations=snapshot, pre_backend=backend,
            rdata=(1 << 32)-1, error=1)
        payload_bytes = _encoded_size(payload)
        result_wire_bytes = (len('RESULT ')+32+1+len(f'{sequence:x}')+1
            +len(f'{before:x}')+1+len(f'{after:x}')+1+2*payload_bytes+1)
        reservation = limits['reply_reservation_bytes']
        if result_wire_bytes > reservation:
            raise ValueError('source envelope fit exceeds generated reply reservation')
        # Reservation also covers finite generated ERROR replies and an earlier
        # generated reply retained on transport failure. ASCII strings add two
        # JSON quotes and one extra byte for the terminal newline escape.
        wire_reply = _EncodedSize(reservation+3)
        receipt = dict(status='result', execution='f'*32, sequence=sequence,
            tick_before=before, tick_after=after, new_ticks=1, payload=payload,
            error_code=None, error_detail=None)
        # In ERROR, both error tokens together fit the generated wire bound;
        # reserve their total plus their two pairs of JSON quotes, not two
        # copies of the entire payload. Numeric fields may span wire uint64.
        error_receipt = dict(status='error', execution='f'*32, sequence=(1 << 64)-1,
            tick_before=(1 << 64)-1, tick_after=(1 << 64)-1,
            new_ticks=(1 << 64)-1, payload=None,
            error_code=_EncodedSize(reservation+2), error_detail='')
        receipt_bytes = max(_encoded_size(receipt), _encoded_size(error_receipt), 4)
        irq = runtime['kind'] == 'reduced_dual_axi_irq_cpu'
        fields = list(IRQ_STEP_MAXIMA if irq else STEP_MAXIMA)
        operation = 'STEP_REDUCED_AXI_IRQ' if irq else 'STEP_REDUCED_AXI'
        command = (f'CMD {"f"*32} {sequence:x} {operation} '
                   +' '.join(f'{value:x}' for value in fields)+'\n')
        ref = observer._record_count + 1
        # Enumerate the actual _emit DTOs. One raw plus at most ten nonraw rows
        # follows the admitted max_events_per_edge=11 contract. No reset is
        # generated by a receipt. Each row's payload is the whole endpoint map.
        common = dict(schema_version='reduced_axi_observation.v1',
            component_id=observer.component_id, scope=_EncodedSize(_encoded_size(scope)), **authority)
        raw = dict(common,kind='reduced_axi_raw',raw_event_ref=ref,raw_sample=sample)
        derived = []
        for endpoint,shape in SHAPES.items():
            row = {role:(1 << width)-1 for role,(_,width) in shape.items()}
            for channel in ('ar','aw','w'):
                if channel+'valid' in shape:
                    derived.append(dict(common,kind='reduced_axi_accept', endpoint_id=endpoint,
                        channel=channel,local_tick=after,payload=row,raw_event_refs=[ref]))
            for channel in ('r','b'):
                if channel+'valid' in shape:
                    derived.append(dict(common,kind='reduced_axi_complete',endpoint_id=endpoint,
                        channel=channel,local_tick=after,payload=row,raw_event_refs=[ref],
                        request_refs=[ref,ref]))
        for order in ('same_edge','aw_before_w','w_before_aw'):
            derived.append(dict(common,kind='reduced_axi_write_join',endpoint_id='d',
                local_tick=after,aw_w_order=order,raw_event_refs=[ref,ref],
                native_id=max((1 << shape.get('awid',('',1))[1])-1 for shape in SHAPES.values())))
        for reason in ('shape','budget','tick','hold','orphan_r','orphan_b','response_id',
                       'last','exclusive_response_unsupported','outstanding_budget','size_alignment','strobe_lanes'):
            derived.append(dict(common,kind='reduced_axi_violation',reason=reason,
                raw_event_refs=[ref],pending={p:{slot:False for slot in slots}
                    for p,slots in observer.pending.items()},local_tick=after))
        maximum_derived = max(_encoded_size(row) for row in derived)
        maximum_records = observer.contract['budgets']['max_events_per_edge']
        span_bytes = (2+_encoded_size(raw)+(maximum_records-1)*maximum_derived
                      +(maximum_records-1))
        witness = dict(operation=operation,command_fields=fields,wire_command=command,
            wire_reply=wire_reply,receipt=_EncodedSize(receipt_bytes),
            cumulative_after=session.local_ticks+1,tick_base=session._tick_base,scope=scope)
        required = envelope('receipt', witness, _EncodedSize(span_bytes), maximum_records)
        return dict(operation_bytes=[required], sample_bytes=sample_bytes)

    def configuration(self):
        return [dict(runner_component=alias,stream_ordinal=n,
            binding=deepcopy(s['binding']),source_limits=deepcopy(s['limits']),
            consumer_limits=deepcopy(s['consumer'].limits),
            import_commit='temporary_runner_journal',
            checkpoint='drain_seal_drain_before_teardown',
            global_consumer_input='durable_json_projection_strict_issued_originals',
            source_envelope_admission='reduced_axi_source_envelope_fit.v1',
            max_journal_record_bytes=self.record_bound(alias),
            max_report_growth_bytes=self.growth_bound(alias))
            for n,(alias,s) in enumerate(self.streams.items(),1)]

    def record_bound(self,alias):
        # Source canonical ASCII is an upper bound for UTF-8 JSON payloads;
        # Runner envelope, binding/contract and provenance are reserved separately.
        s=self.streams[alias]
        return (s['limits']['max_operation_bytes']+len(canonical(s['binding']))
                +len(canonical(alias))+65536)

    def growth_bound(self,alias):
        # At most eleven original records can add report witnesses. Every new
        # boundary/failure witness copies a subset of one complete/violation
        # original (including its scope) plus fixed reference lists/IDs. Reserve
        # one entire maximum row per original, plus pending/counter/failure slots.
        # This deliberately exceeds the ABI's four possible completions per edge.
        return 13*self.record_bound(alias)

    def consume(self,event):
        # Runner uses tuples in unrelated scheduler outputs and reset markers.
        # Validate the same JSON representation durable writers preserve; issued
        # observations are strict JSON already and are not rewritten.
        if not self.streams or self.closed:return
        try:
            document=json.loads(json.dumps(event,ensure_ascii=False,allow_nan=False))
            for alias,s in self.streams.items():
                consumer=s['consumer']
                consumer.consume(document)
                if not s['importing']:
                    refused=(not consumer.operation_ready(s['last_completed'])
                        if s['last_completed'] is not None
                        else consumer.report()['reason'] is not None)
                    if refused:
                        s['stage']='global_consume'
                        self.fail(alias,ValueError('global journal consumer refused'))
        except BaseException as error:
            for alias in self.streams:self.fail(alias,error)
            raise

    def verify(self,alias):
        s=self.streams[alias]
        if s['failure'] is not None:raise RuntimeError('reduced AXI stream import poisoned')
        if self.closed:raise RuntimeError('reduced AXI stream import finalized')
        if self.runner.sessions.get(alias) is not s['session']:
            raise RuntimeError('reduced AXI session ownership drift')
        export=observation_export_for(s['session'])
        if (export is not s['export'] or export.source is not s['source']
                or s['source'].state not in ('active','sealed')
                or canonical(s['session']._artifact_document)!=canonical(s['runtime'])
                or s['session'].runtime_events is not export.observer.events):
            raise RuntimeError('reduced AXI source ownership drift')
        return s

    def fail(self,alias,error):
        s=self.streams[alias]
        if s['failure'] is None:
            s['failure']=dict(stage=s['stage'],operation_index=s['operation_index'],
                first_event_id=s['start_id'],committed_through_event_id=len(self.runner._events),
                error_type=type(error).__name__,detail=str(error)[:256],
                evidence_missing=True)
            s['source'].poison('Runner import failure')
            self.runner._status='failed'
            if self.runner.failure_status is None:
                self.runner.failure_status='environment_error'
        # No diagnostic append here: failure slots remain small even if storage
        # itself failed. finalize still reaps every session.

    def preflight(self,alias,*,operations=1,records=11,overhead=1,issued=False,kind='receipt'):
        if alias not in self.streams:return
        s=self.streams[alias]
        if not issued:
            s['stage']='preflight_'+kind
            s['operation_index']=None
            s['start_id']=None
        try:
            self.verify(alias)
            if s['last_completed'] is not None and not s['consumer'].operation_ready(s['last_completed']):
                raise ValueError('reduced AXI global journal consumer refused')
            if not issued:
                fit = self.source_operation_fit(alias, kind)
                required = fit['operation_bytes']
                if any(size>s['limits']['max_operation_bytes'] for size in required):
                    raise ValueError('reduced AXI source envelope byte fit refused: required='
                                     +str(max(required))+' configured='
                                     +str(s['limits']['max_operation_bytes']))
                source=s['source']
                configured=s['limits']
                if (s['export']._operation_count+operations>configured['max_operations']
                        or len(source.pending())+operations>configured['max_pending_operations']
                        or source._pending_bytes+sum(required)>configured['max_pending_bytes']):
                    raise ValueError('reduced AXI source capacity preflight refused')
                if kind=='receipt' and len(s['raw'])+operations>s['consumer'].limits['max_raw_mappings']:
                    raise ValueError('reduced AXI raw map capacity preflight refused')
            count=operations+2*records+overhead+(s['binding_id'] is None)
            bound=self.record_bound(alias)
            for other in self.streams.values():
                consumer=other['consumer'];limits=consumer.limits
                if (consumer._cursor+count>limits['max_events']
                        or bound>limits['max_input_bytes']
                        or consumer._input_bytes+count*bound>limits['max_total_input_bytes']
                        or (other is not s and consumer._gap+count>limits['max_event_gap'])):
                    raise ValueError('reduced AXI global consumer capacity preflight refused')
            if not issued:
                consumer=s['consumer'];observer=s['export'].observer
                limits=consumer.limits
                if kind in ('begin_scope','reset') and (
                        len(consumer._scopes)+1>limits['max_scopes']
                        or observer._scopes+1>observer.max_scopes):
                    raise ValueError('reduced AXI scope capacity preflight refused')
                if kind=='receipt' and (
                        len(consumer._boundaries)+4>limits['max_retained_records']
                        or limits['max_pending']<8 or limits['max_expected_records']<11
                        or observer._edges+1>observer.max_edges
                        or observer._bytes+fit['sample_bytes']>observer.max_bytes):
                    raise ValueError('reduced AXI observer/report capacity preflight refused')
            budget=self.runner._resource_budget
            if budget is None:return
            if len(self.runner._events)+count>budget.max_semantic_records-1:
                self.runner._exhaust_budget('max_semantic_records','before_reduced_axi_operation')
            bound=self.record_bound(alias)
            meter=self.runner._evidence_projected_bytes
            if meter is not None:
                if self.runner._evidence_record_bound is not None and bound>self.runner._evidence_record_bound:
                    raise ValueError('reduced AXI evidence record reservation insufficient')
                # Each observation is included in the envelope AND original.
                # Reserve sidecars, copied report/map state, scheduler and
                # configured secondary evidence copies before any transport.
                copies=2+max(self.runner._evidence_copy_counts.values(),default=0)
                total=count*bound*copies+self.growth_bound(alias)*operations
                if meter+total>budget.max_evidence_bytes-budget.evidence_termination_reserve_bytes:
                    self.runner._exhaust_budget('max_evidence_bytes','before_reduced_axi_operation')
        except BaseException as error:
            self.fail(alias,error)
            raise

    def bind(self,alias):
        try:
            self._bind(alias)
        except BaseException as error:
            self.fail(alias,error)
            raise

    def _bind(self,alias):
        s=self.verify(alias)
        if s['binding_id'] is not None:return
        s['stage']='binding'
        if not self.runner._events:
            self.put(s,dict(kind='observation_stream_control',component=alias))
        parent=len(self.runner._events)
        row=dict(kind='reduced_axi_stream_binding',schema_version='reduced_axi_stream_binding.v1',
            component=alias,producer_event_id=parent,binding=s['binding'],limits=s['limits'])
        s['binding_id']=self.put(s,row)['event_id']

    def put(self,s,row):
        row=deepcopy(row);row['event_id']=len(self.runner._events)+1
        self.runner._events.append(row)
        # Return the actual decorated committed row, not a guessed source ID.
        result=self.runner._events[row['event_id']-1]
        if row.get('kind','').startswith('reduced_axi_') and canonical(result)!=canonical(row):
            raise ValueError('committed reduced AXI row changed during append')
        s['last_id']=result['event_id']
        return result

    def drain(self,alias,parent):
        if alias not in self.streams:return
        s=self.streams[alias]
        try:
            self.verify(alias)
            self.bind(alias)
            for token in s['source'].pending():
                s['stage']='export';s['start_id']=len(self.runner._events)+1
                s['operation_index']=None
                operation=s['source'].lookup(token)
                s['operation_index']=operation['operation_index']
                observations=operation['observations']
                self.preflight(alias,records=len(observations),overhead=0,issued=True)
                mutable=s['session'].runtime_events
                if canonical(mutable[:len(observations)])!=canonical(observations):
                    raise ValueError('mutable reduced AXI observation prefix mismatch')
                s['stage']='operation'
                s['importing']=True
                op=self.put(s,dict(kind='reduced_axi_source_operation',
                    schema_version='reduced_axi_source_operation.v1',component=alias,
                    producer_event_id=max(1,parent),stream_binding_event_id=s['binding_id'],
                    operation=operation))
                for index,row in enumerate(observations,operation['first_record_index']):
                    s['stage']='original'
                    original=self.put(s,dict(row,component=alias,producer_event_id=op['event_id']))
                    s['stage']='sidecar'
                    side=build_reduced_axi_journal_sidecar(original,
                        stream_binding_event_id=s['binding_id'],operation_event_id=op['event_id'],
                        record_index=index,raw_mappings=s['raw'])
                    self.put(s,dict(side,producer_event_id=original['event_id']))
                    if row['kind']=='reduced_axi_raw':
                        if len(s['raw'])>=s['consumer'].limits['max_raw_mappings']:
                            raise ValueError('reduced AXI raw map capacity')
                        s['raw'][row['raw_event_ref']]=dict(event_id=original['event_id'],scope=deepcopy(row['scope']))
                s['stage']='verify'
                self.verify(alias)
                if canonical(mutable[:len(observations)])!=canonical(observations):
                    raise ValueError('mutable reduced AXI observation prefix changed during import')
                if not s['consumer'].operation_ready(operation['operation_index']):
                    raise ValueError('reduced AXI operation not verified: '+str(s['consumer'].report()['reason']))
                s['stage']='ack'
                s['source'].ack(token)
                s['last_completed']=operation['operation_index']
                # No clearing until the successful FIFO ACK, even for post-effect errors.
                del mutable[:len(observations)]
                s['importing']=False
            if s['session'].runtime_events:
                raise ValueError('unissued reduced AXI observations')
        except BaseException as error:
            s['importing']=False
            self.fail(alias,error)
            raise

    def cleanup_targets(self, alias=None):
        # Session replacement is an integrity failure, but must not lose the
        # process belonging to the originally admitted source.
        targets=[]
        seen=set()
        candidates=list(self.runner.sessions.items())+[
            (name,s['session']) for name,s in self.streams.items()]
        for name,session in candidates:
            if (alias is None or name==alias) and id(session) not in seen:
                targets.append((name,session));seen.add(id(session))
        return targets

    def checkpoint(self):
        errors=[]
        for alias,s in self.streams.items():
            try:
                self.drain(alias,len(self.runner._events))
                if s['source'].state=='active':
                    self.preflight(alias,records=0,overhead=0,kind='seal')
                    s['stage']='seal';s['session'].seal_observation_stream()
                self.drain(alias,len(self.runner._events))
            except BaseException as error:
                self.fail(alias,error);errors.append(error)
        return errors

    def finalize(self):
        if self.closed:return
        for s in self.streams.values():s['consumer'].finalize()
        self.closed=True

    def reports(self):
        reports={}
        for alias,s in self.streams.items():
            report=s['consumer'].report()
            if s['failure'] is not None:
                report.update(status='failed',reason='runner_import_failure',recording_integrity='unverified',
                              import_failure=deepcopy(s['failure']))
            reports[alias]=report
        return reports
