"""Bounded associations of actual ordinary commands; never semantic authority."""
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
from types import CodeType, FunctionType

from myfuzz.local_harness.ordinary_apb_access_receipts import (
    OrdinaryApbAccessReceipts, _json, _uint, validate_ordinary_apb_target_receipt)
from .ledger import TransactionKey, TransactionLedger
from .memory import PersistentMemory
from .router import DataflowRouter
from .ip_protocol_events import IpProtocolEventNormalizer


def _strip(row):
    return {k:v for k,v in row.items() if k not in ('event_id','producer_event_id','component','kind')}


class OrdinaryApbAccessEvidence:
    def __init__(self, runner, *, max_records=256):
        from .runner import ScenarioRunner
        from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
        from myfuzz.local_harness.cpu_session import GeneratedCve2Session
        if (type(runner) is not ScenarioRunner or runner._status!='created' or runner._events
                or type(max_records) is not int or not 1<=max_records<=65536):
            raise ValueError('ordinary-evidence-fresh-actual-runner-required')
        self.runner=runner;self.max_records=max_records;self._limit=max_records
        self._targets={};self._bindings=[];self._pending={};self._records=[]
        self._completed_access_json=()
        self._raw={};self._closed_raw=set();self._acceptances={};self._deliveries={};self._seen={}
        self._status='complete';self._reason=None
        self._confirmation_method=DataflowRouter.ordinary_delivery_confirmation
        self._router_methods=(DataflowRouter._prepare,DataflowRouter._window,DataflowRouter._access,DataflowRouter.enqueue,DataflowRouter.drain_one)
        self._cpu_serve_method=GeneratedCve2Session._serve
        self._cpu_completed_code=next(c for c in self._cpu_serve_method.__code__.co_consts
            if type(c) is CodeType and c.co_name=='completed')
        for name,target in runner.sessions.items():
            helper=getattr(target,'_ordinary_apb_receipts',None)
            if helper is None:continue
            if type(target) is not GeneratedPulpGpioSession or type(helper) is not OrdinaryApbAccessReceipts:
                raise ValueError('ordinary-evidence-actual-native-target-required')
            helper.validate()
            normalizer=runner._ip_protocol_event_normalizer(name,target)
            checker=runner._ip_protocol_checker(name,target)
            if normalizer is None or checker is None:raise ValueError('ordinary-evidence-native-projectors-required')
            self._targets[name]=(target,helper,normalizer,checker)
        for source,cpu in runner.sessions.items():
            if type(cpu) is not GeneratedCve2Session:continue
            router=cpu.router
            if type(router) is not DataflowRouter or type(cpu.service.ledger) is not TransactionLedger:
                raise ValueError('ordinary-evidence-actual-cpu-service-required')
            if cpu.service.memory is not cpu.memory or type(cpu.memory) is not PersistentMemory:
                raise ValueError('ordinary-evidence-memory-binding')
            for window in router.windows:
                if window.device_id in self._targets:
                    if window.target is not self._targets[window.device_id][0]:raise ValueError('ordinary-evidence-window-target')
                    self._bindings.append((source,cpu,router,window,cpu.service,cpu.service.ledger,cpu.memory,
                                           router._ordinary_delivery_confirmations))
        if not self._targets or any(not any(b[3].target is t[0] for b in self._bindings) for t in self._targets.values()):
            raise ValueError('ordinary-evidence-actual-routed-target-required')
        self._sources={str(Path(__file__).resolve()):None}
        from myfuzz.local_harness import ordinary_apb_access_receipts, gpio_session, cpu_session
        from . import router as router_module, ip_protocol_events, ip_protocol_checker, ledger as ledger_module, memory as memory_module
        for module in (ordinary_apb_access_receipts,gpio_session,cpu_session,router_module,ledger_module,memory_module,ip_protocol_events,ip_protocol_checker):
            self._sources[str(Path(module.__file__).resolve())]=None
        self._sources={p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in self._sources}
        self._helper_registry_pins={name:(t[1]._records,t[1]._sample_digests,t[1]._execution_pins,t[1]._keys) for name,t in self._targets.items()}
        self._helper_methods=(OrdinaryApbAccessReceipts.lookup,OrdinaryApbAccessReceipts.sample_digest,OrdinaryApbAccessReceipts.validate)
        self._router_windows={id(b[2]):tuple(b[2].windows) for b in self._bindings}
        self._ledger_registry_pins={id(b[5]):b[5]._entries for b in self._bindings}
        self._memory_identity_method=PersistentMemory.identity_document
        self._memory_pins={}
        for binding in self._bindings:
            memory=binding[6]
            if id(memory) in self._memory_pins:continue
            if 'identity_document' in vars(memory) or type(memory._instruction_slots) is not set:
                raise ValueError('ordinary-evidence-memory-declaration-required')
            identity=self._memory_identity_method(memory)
            metadata={key:value for key,value in identity.items() if key!='instruction_slots'}
            if (_json(metadata)!=self._memory_metadata(memory)
                    or _json(identity.get('instruction_slots'))!=_json(sorted(memory._instruction_slots))):
                raise ValueError('ordinary-evidence-memory-declaration-mismatch')
            self._memory_pins[id(memory)]=(memory._regions,frozenset(memory._instruction_slots),deepcopy(identity),_json(metadata))
        self._configuration=self._config()
        self._configuration_sha256=hashlib.sha256(_json(self._configuration).encode()).hexdigest()
        self._validation_configuration_json=_json(self._config(include_memory_slots=False))
        self._projector_pins={name:_json({'normalizer':{k:v for k,v in vars(t[2]).items() if k in ('_signals','_widths','component_id','instance_id','protocol','endpoint_id','clock_domain','max_wait_cycles')},
            'checker':{k:v for k,v in vars(t[3]).items() if k in ('_signals','_widths','component_id','instance_id','protocol','endpoint_id','clock_domain','max_wait_cycles')}}) for name,t in self._targets.items()}

    @staticmethod
    def _memory_metadata(memory):
        return _json(dict(regions=[asdict(region) for region in memory._regions],
            initialization_seed=memory.initialization_seed,initialization_algorithm='memory-init-v1',
            max_initialized_bytes=memory.max_initialized_bytes))

    def _config(self, *, include_memory_slots=True):
        return dict(schema_version='ordinary_apb_access_evidence_configuration.v1',max_records=self._limit,
            targets={n:t[1].configuration() for n,t in sorted(self._targets.items())},
            bindings=[dict(source_component=b[0],target_instance=b[3].device_id,window_base=b[3].base,
                window_size=b[3].size,memory={key:value for key,value in self._memory_pins[id(b[6])][2].items()
                    if include_memory_slots or key!='instruction_slots'}) for b in self._bindings],
            source_files=dict(self._sources),proof_scope='actual_command_protocol_boundary_association_only',
            grants_verified=False,grants_storage=False,grants_functional=False)

    def configuration(self):return deepcopy(self._configuration)

    @property
    def configuration_sha256(self):return self._configuration_sha256

    def _fail(self, reason):
        self._status='incomplete'
        if self._reason is None:self._reason=reason

    def validate(self, *, allow_incomplete=False):
        if type(allow_incomplete) is not bool:
            raise ValueError('ordinary-evidence-allow-incomplete-boolean-required')
        try:
            if PersistentMemory.identity_document is not self._memory_identity_method:
                raise ValueError('memory-identity-method-drift')
            from myfuzz.local_harness.cpu_session import GeneratedCve2Session
            if GeneratedCve2Session._serve is not self._cpu_serve_method:raise ValueError('cpu-serve-method-drift')
            if self.max_records!=self._limit or type(self.max_records) is not int:raise ValueError('capacity-drift')
            if DataflowRouter.ordinary_delivery_confirmation is not self._confirmation_method:raise ValueError('confirmation-method-drift')
            if (DataflowRouter._prepare,DataflowRouter._window,DataflowRouter._access,DataflowRouter.enqueue,DataflowRouter.drain_one)!=self._router_methods:
                raise ValueError('router-method-drift')
            if (OrdinaryApbAccessReceipts.lookup,OrdinaryApbAccessReceipts.sample_digest,OrdinaryApbAccessReceipts.validate)!=self._helper_methods:
                raise ValueError('target-method-drift')
            for p,digest in self._sources.items():
                if hashlib.sha256(Path(p).read_bytes()).hexdigest()!=digest:raise ValueError('source-drift')
            for name,(target,helper,normalizer,checker) in self._targets.items():
                if (self.runner.sessions.get(name) is not target or target._ordinary_apb_receipts is not helper
                        or self.runner._ip_protocol_event_normalizers.get(name) is not normalizer
                        or self.runner._ip_protocol_checkers.get(name) is not checker):raise ValueError('target-projector-drift')
                if any(actual is not pinned for actual,pinned in zip((helper._records,helper._sample_digests,helper._execution_pins,helper._keys),self._helper_registry_pins[name])):
                    raise ValueError('target-private-registry-drift')
                if any(name in vars(helper) for name in ('lookup','sample_digest','validate')):
                    raise ValueError('target-instance-method-drift')
                self._helper_methods[2](helper)
                pin=_json({'normalizer':{k:v for k,v in vars(normalizer).items() if k in ('_signals','_widths','component_id','instance_id','protocol','endpoint_id','clock_domain','max_wait_cycles')},
                    'checker':{k:v for k,v in vars(checker).items() if k in ('_signals','_widths','component_id','instance_id','protocol','endpoint_id','clock_domain','max_wait_cycles')}})
                if pin!=self._projector_pins[name]:raise ValueError('projector-configuration-drift')
            for source,cpu,router,window,service,ledger,memory,registry in self._bindings:
                regions,slots,_,metadata=self._memory_pins[id(memory)]
                if (memory._regions is not regions or type(memory._instruction_slots) is not set
                        or memory._instruction_slots!=slots or 'identity_document' in vars(memory)
                        or self._memory_metadata(memory)!=metadata):
                    raise ValueError('memory-configuration-drift')
                if any(name in vars(router) for name in ('_prepare','_window','_access','enqueue','drain_one','ordinary_delivery_confirmation')):
                    raise ValueError('router-instance-method-drift')
                if (self.runner.sessions.get(source) is not cpu or cpu.router is not router or cpu.service is not service
                        or service.ledger is not ledger or ledger._entries is not self._ledger_registry_pins[id(ledger)] or cpu.memory is not memory or service.memory is not memory
                        or not any(w is window for w in router.windows)
                        or router._ordinary_delivery_confirmations is not registry
                        or len(router.windows)!=len(self._router_windows[id(router)])
                        or any(a is not b for a,b in zip(router.windows,self._router_windows[id(router)]))):raise ValueError('actual-binding-drift')
            if _json(self._config(include_memory_slots=False))!=self._validation_configuration_json:
                raise ValueError('configuration-drift')
            if self._status=='incomplete' and not allow_incomplete:raise ValueError('ordinary-evidence-permanently-incomplete')
        except BaseException:
            self._fail('actual_configuration_drift');raise

    def _binding(self,router,target):
        rows=[b for b in self._bindings if b[2] is router and b[3].target is target]
        if len(rows)!=1:raise ValueError('ordinary-evidence-ambiguous-binding')
        return rows[0]

    def _cpu_callback(self, binding, queued):
        cpu=binding[1];key=queued[1];payload=queued[2];callback=queued[-1]
        if (type(callback) is not FunctionType or callback.__code__ is not self._cpu_completed_code
                or callback.__closure__ is None or '_serve' in vars(cpu)):
            raise ValueError('ordinary-evidence-actual-cpu-completion-required')
        closure=dict(zip(callback.__code__.co_freevars,(cell.cell_contents for cell in callback.__closure__)))
        write=closure.get('write')
        if (set(closure)!={'self','key','write'} or closure['self'] is not cpu or closure['key'] is not key
                or type(write) not in (int,bool) or write not in (0,1) or bool(write) is not queued[7]
                or key.channel_id!='data' or key.execution_id!='local-execution'
                or type(cpu._sequences.get('data')) is not int or cpu._sequences['data']!=key.source_sequence
                or cpu._queued_mmio is not True or cpu._pending_data is not None):
            raise ValueError('ordinary-evidence-cpu-completion-context-mismatch')
        evidence=cpu._request_evidence.get('data')
        if (type(evidence) is not dict or set(evidence)!={'transaction','raw_address','aligned_address','address',
                'write','be','wdata','acceptance_tick'} or _json(evidence['transaction'])!=_json(asdict(key))
                or type(evidence['raw_address']) is not int or evidence['raw_address']!=evidence['address']
                or evidence['raw_address'] & ~3 != payload['address'] or evidence['aligned_address']!=payload['address']
                or type(evidence['write']) not in (int,bool) or evidence['write'] not in (0,1)
                or bool(evidence['write']) is not queued[7] or _json(evidence['write'])!=_json(write) or evidence['be']!=payload['be']
                or type(evidence['be']) is not int or type(evidence['wdata']) is not int
                or evidence['wdata']!=payload['wdata'] or not _uint(evidence['acceptance_tick'])
                or evidence['acceptance_tick']>cpu.local_ticks):
            raise ValueError('ordinary-evidence-actual-cpu-request-mismatch')
        return callback,deepcopy(evidence),(cpu.mmio_read_count,cpu.mmio_write_count)

    def preflight_access(self,router,target):
        if not any(t[0] is target for t in self._targets.values()):return
        self.validate();binding=self._binding(router,target)
        queued=next((q for q in router._queued if q[3] is binding[3]),None)
        if queued is None:raise ValueError('ordinary-evidence-actual-queued-access-required')
        ledger,key,payload=queued[:3]
        try:
            if (type(payload) is not dict or set(payload)!={'device_id','address','write','wdata','be','beat_bytes'}
                    or not _uint(payload['address'],(1<<32)-1) or not _uint(payload['wdata'],(1<<32)-1)
                    or type(payload['write']) is not bool or type(payload['beat_bytes']) is not int
                    or payload['beat_bytes']!=4 or type(payload['be']) is not int or payload['be']!=15):
                raise ValueError('unsupported-ordinary-queued-payload')
            decoded=self._router_methods[0](router,address=payload['address'],write=payload['write'],
                wdata=payload['wdata'],be=payload['be'],beat_bytes=payload['beat_bytes'])
            if (decoded[0] is not binding[3] or queued[3] is not decoded[0]
                    or _json(list(queued[4:8]))!=_json([decoded[1],decoded[2],decoded[3],payload['write']])
                    or _json(decoded[5])!=_json(payload)):
                raise ValueError('ordinary-queued-decode-mismatch')
        except (ValueError,KeyError,TypeError):
            self._fail('actual_queued_decode_mismatch');raise ValueError('ordinary-evidence-queued-decode-mismatch')
        if (ledger is not binding[5] or type(key) is not TransactionKey or key.source_component!=binding[0]
                or key.source_epoch!=binding[1].reset_epoch or key.testcase_id!=binding[1]._case_id):raise ValueError('ordinary-evidence-source-ledger-mismatch')
        token=_json(asdict(key))
        try:callback,request_evidence,counts=self._cpu_callback(binding,queued)
        except ValueError:
            self._fail('invalid_actual_cpu_completion');raise
        if token in self._pending:
            pending=self._pending[token]
            if (pending['callback'] is not callback or _json(request_evidence)!=_json(pending['request_evidence'])
                    or counts!=pending['cpu_counts'] or pending['binding'] is not binding or _json(payload)!=_json(pending['payload'])
                    or ledger._digest(payload)!=pending['digest'] or target.reset_epoch!=pending['epoch']
                    or binding[6].generation!=pending['generation']):
                self._fail('preflight_context_drift');raise ValueError('ordinary-evidence-preflight-context-drift')
            entry=ledger._entries.get(key)
            if entry is None or entry.status!='target_pending' or entry.payload_digest!=pending['digest']:
                self._fail('preflight_ledger_drift');raise ValueError('ordinary-evidence-preflight-ledger-drift')
            return
        if len(self._records)+len(self._pending)>=self._limit:raise ValueError('ordinary-evidence-capacity')
        entry=ledger._entries.get(key)
        if entry is None or entry.status!='target_pending' or entry.payload_digest!=ledger._digest(payload):
            raise ValueError('ordinary-evidence-actual-acceptance-required')
        self._pending[token]=dict(binding=binding,key=key,payload=deepcopy(payload),digest=entry.payload_digest,
            callback=callback,request_evidence=request_evidence,cpu_counts=counts,
            generation=binding[6].generation,epoch=target.reset_epoch,context=dict(source_transaction=asdict(key),
                device_id=binding[3].device_id,window_base=binding[3].base,window_size=binding[3].size,
                address=payload['address'],offset=queued[6],write=queued[7],value=queued[5],be=queued[4]),receipt=None,receipt_id=None,
            raw={},base=[],expected=[],normalizer=IpProtocolEventNormalizer(component_id=target.artifact.plan.profile.component_id,
            instance_id=binding[3].device_id,protocol_trace=target.artifact.runtime_document['base_protocol_trace']),error=None)

    def observe_event(self,record):
        if type(record) is not dict or type(record.get('event_id')) is not int or self.runner._event_ref_by_id(record['event_id']) is not record:
            self._fail('foreign_journal_record');raise ValueError('ordinary-evidence-actual-journal-reference-required')
        kind=record.get('kind')
        if kind not in ('mmio_acceptance','mmio_delivery','ordinary_apb_target_receipt','ordinary_apb_delivery_terminal',
                        'local_tick_sample','transaction_request','transaction_accept','transaction_response','protocol_violation'):return
        relevant=(record.get('device_id') in self._targets or record.get('target_instance') in self._targets
            or 'ordinary_apb_access_ref' in record or any(ref in self._raw or ref in self._closed_raw for ref in record.get('raw_event_refs',())))
        if not relevant:return
        event_id=record['event_id'];canonical=_json(record)
        if event_id in self._seen:
            if self._seen[event_id]!=canonical:self._fail('journal_record_conflict')
            return
        if len(self._seen)>=self._limit*(2*65536+8):self._fail('journal_index_capacity');raise ValueError('ordinary-evidence-index-capacity')
        self._seen[event_id]=canonical
        try:self._consume(record)
        except (ValueError,KeyError,TypeError) as error:
            self._fail('invalid_actual_association')
            for p in self._pending.values():p['error']=str(error)
            raise ValueError('ordinary-evidence-invalid-association') from error

    def _consume(self,row):
        kind=row['kind']
        if kind in ('mmio_acceptance','mmio_delivery'):
            token=_json(row['source_transaction']);index=self._acceptances if kind=='mmio_acceptance' else self._deliveries
            if token not in index and len(index)>=self._limit:raise ValueError('ordinary-evidence-index-capacity')
            if token in index:raise ValueError('ordinary-evidence-duplicate-delivery')
            index[token]=row['event_id'];return
        if kind=='ordinary_apb_target_receipt':
            receipt=_strip(row);validate_ordinary_apb_target_receipt(receipt)
            token=_json(receipt['source_transaction']);p=self._pending.get(token)
            if p is None:raise ValueError('ordinary-evidence-unpreflighted-target')
            target=p['binding'][3].target;helper=self._targets[receipt['target_instance']][1]
            if (_json(receipt['delivery_context'])!=_json(p['context']) or receipt['target_reset_epoch']!=p['epoch']):
                raise ValueError('ordinary-evidence-receipt-context-mismatch')
            if _json(self._helper_methods[0](helper,receipt['access_id']))!=_json(receipt):raise ValueError('ordinary-evidence-foreign-target-receipt')
            if p['receipt'] is not None:raise ValueError('ordinary-evidence-duplicate-target-receipt')
            p['receipt']=deepcopy(receipt);p['receipt_id']=row['event_id'];return
        if kind=='ordinary_apb_delivery_terminal':
            p=self._pending.get(_json(row['source_transaction']))
            if p is not None:p['error']=row['status']
            self._fail('actual_delivery_terminal');return
        if kind=='local_tick_sample':
            tag=row.get('ordinary_apb_access_ref')
            if tag is None:return
            if type(tag) is not dict or set(tag)!={'access_id','command_scope'}:raise ValueError('ordinary-evidence-invalid-tag')
            target,helper,_,_=self._targets[row['component']]
            receipt=self._helper_methods[0](helper,tag['access_id']);p=self._pending.get(_json(receipt['source_transaction']))
            if p is None or _json(tag['command_scope'])!=_json(receipt['command_scope']):raise ValueError('ordinary-evidence-foreign-command')
            tick=row['local_tick'];phase=row['phase']
            if (not _uint(tick) or row.get('reset_epoch')!=p['epoch'] or type(row.get('reset_epoch')) is not int
                    or hashlib.sha256(_json(row['outputs']).encode()).hexdigest()!=self._helper_methods[1](helper,tag['access_id'],tick,phase)):
                raise ValueError('ordinary-evidence-raw-content-mismatch')
            coordinate=(tick,phase)
            if coordinate in p['raw']:raise ValueError('ordinary-evidence-duplicate-raw')
            p['raw'][coordinate]=row['event_id'];self._raw[row['event_id']]=p
            p['expected'].extend(p['normalizer'].consume_local_tick(row,reset_epoch=p['epoch']));return
        refs=row.get('raw_event_refs',[])
        pending={id(self._raw[ref]):self._raw[ref] for ref in refs if ref in self._raw}
        if len(pending)!=1 or any(ref not in self._raw for ref in refs):raise ValueError('ordinary-evidence-foreign-protocol-ref')
        p=next(iter(pending.values()))
        if kind=='protocol_violation':p['error']='protocol_violation';self._fail('protocol_violation');return
        expected=next((e for e in p['expected'] if e['event_type']==kind and e['raw_event_refs']==refs),None)
        if expected is None or _json(_strip(row))!=_json(expected):raise ValueError('ordinary-evidence-protocol-projection-mismatch')
        if any(k==kind for k,_ in p['base']):raise ValueError('ordinary-evidence-duplicate-boundary')
        p['base'].append((kind,row['event_id']))

    def finalize_pending(self,router,target,*,failure=None):
        if not any(t[0] is target for t in self._targets.values()):return ()
        rows=[]
        for token,p in tuple(self._pending.items()):
            if p['binding'][2] is not router or p['binding'][3].target is not target:continue
            receipt=p['receipt'];reason=p['error'] or failure;status='incomplete'
            try:
                if reason is not None:raise ValueError(reason)
                self.validate()
                if receipt is None:raise ValueError('missing_target_receipt')
                expected={(tick,phase) for tick in receipt['sample_ticks'] for phase in ('pre','post')}
                if set(p['raw'])!=expected:raise ValueError('missing_raw_span')
                if [k for k,_ in p['base']]!=['transaction_request','transaction_accept','transaction_response']:raise ValueError('missing_protocol_boundary')
                if target.reset_epoch!=p['epoch'] or p['binding'][6].generation!=p['generation']:raise ValueError('generation_or_epoch_changed')
                acceptance_id=self._acceptances.get(token);delivery_id=self._deliveries.get(token)
                if acceptance_id is None:raise ValueError('missing_actual_acceptance')
                if delivery_id is None:raise ValueError('missing_actual_queued_delivery')
                acceptance=_strip(self.runner._event_ref_by_id(acceptance_id))
                context=receipt['delivery_context']
                expected_acceptance=dict(source_transaction=asdict(p['key']),device_id=p['binding'][3].device_id,
                    source_sequence=p['key'].source_sequence,acceptance_order=acceptance.get('acceptance_order'),
                    address=p['payload']['address'],offset=context['offset'],beat_bytes=p['payload']['beat_bytes'],
                    write=context['write'],byte_enable=context['be'],write_value=context['value'] if context['write'] else None)
                if (not _uint(acceptance.get('acceptance_order')) or acceptance['acceptance_order']==0
                        or _json(acceptance)!=_json(expected_acceptance)):
                    raise ValueError('acceptance_payload_mismatch')
                entry=p['binding'][5]._entries.get(p['key'])
                if entry is None or entry.status!='complete' or entry.payload_digest!=p['digest']:raise ValueError('ledger_state_mismatch')
                status='target_observed'
                if delivery_id is not None:
                    delivery=self.runner._event_ref_by_id(delivery_id)
                    confirmation=self._confirmation_method(router,p['key'])
                    if _json(_strip(delivery))!=_json(confirmation):raise ValueError('callback_confirmation_mismatch')
                    if confirmation.get('source_delivery_confirmed') is not True or confirmation.get('target_access_id')!=receipt['access_id']:
                        raise ValueError('callback_confirmation_mismatch')
                    cpu=p['binding'][1]
                    expected_response=(0 if receipt['delivery_context']['write'] else receipt['rdata'],0,p['key'].source_sequence)
                    counts=p['cpu_counts'];write=receipt['delivery_context']['write']
                    expected_counts=(counts[0]+int(not write),counts[1]+int(write))
                    if (type(cpu._pending_data) is not tuple or len(cpu._pending_data)!=3
                            or any(type(value) is not int for value in cpu._pending_data)
                            or cpu._pending_data!=expected_response or cpu._queued_mmio is not False
                            or (cpu.mmio_read_count,cpu.mmio_write_count)!=expected_counts
                            or any(type(value) is not int for value in (cpu.mmio_read_count,cpu.mmio_write_count))
                            or _json(cpu._request_evidence.get('data'))!=_json(p['request_evidence'])
                            or cpu._case_id!=p['key'].testcase_id or cpu.reset_epoch!=p['key'].source_epoch
                            or cpu._sequences.get('data')!=p['key'].source_sequence):
                        raise ValueError('actual_cpu_response_handoff_mismatch')
                    status='cpu_delivery_confirmed' 
            except (ValueError,KeyError,TypeError) as error:
                reason=str(error);status='incomplete';self._fail(reason)
            row=dict(schema_version='ordinary_apb_access_association.v1',access_id=receipt['access_id'] if receipt else None,
                target_instance=p['binding'][3].device_id,endpoint_id=receipt['endpoint_id'] if receipt else None,
                source_transaction=asdict(p['key']),target_reset_epoch=p['epoch'],memory_generation=p['generation'],
                target_receipt_event_id=p['receipt_id'],acceptance_event_id=self._acceptances.get(token),
                delivery_event_id=self._deliveries.get(token),raw_event_refs=sorted(p['raw'].values()),
                base_event_refs=[ref for _,ref in p['base']],status=status,reason=reason,
                proof_scope='actual_command_protocol_boundary_association_only',grants_verified=False,grants_storage=False,grants_functional=False)
            if status=='cpu_delivery_confirmed':
                helper=self._targets[receipt['target_instance']][1]
                samples=[dict(local_tick=tick,phase=phase,sha256=self._helper_methods[1](helper,receipt['access_id'],tick,phase))
                    for tick,phase in sorted(p['raw'])]
                completed=dict(schema_version='ordinary_apb_completed_access.v1',
                    ordinal=len(self._completed_access_json)+1,association=row,receipt=receipt,
                    acceptance=acceptance,delivery=confirmation,cpu_response=expected_response,
                    request_evidence=p['request_evidence'],
                    command_samples_sha256=hashlib.sha256(_json(samples).encode()).hexdigest(),
                    grants_verified=False,grants_storage=False,grants_functional=False)
                self._completed_access_json+=(_json(completed),)
            self._records.append(row);rows.append(deepcopy(row));del self._pending[token]
            for ref in p['raw'].values():
                self._raw.pop(ref,None);self._closed_raw.add(ref)
        return tuple(rows)

    def completed_accesses(self):
        """Detached actual handoffs for code-owned observers, never restored data.

        Only successful finalize creates a seal. A terminal failed prefix may
        expose earlier handoffs, while every actual configuration guard remains.
        """
        self.validate(allow_incomplete=True)
        return tuple(json.loads(raw) for raw in self._completed_access_json)

    def snapshot(self):
        return deepcopy(dict(schema_version='ordinary_apb_access_evidence_state.v1',configuration=self._configuration,
            configuration_sha256=self._configuration_sha256,status=self._status,
            reason=self._reason,counts=dict(records=len(self._records),pending=len(self._pending),
                cpu_delivery_confirmed=sum(r['status']=='cpu_delivery_confirmed' for r in self._records)),records=self._records))
