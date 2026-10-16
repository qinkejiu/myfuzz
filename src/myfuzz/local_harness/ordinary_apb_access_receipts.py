"""Bounded ordinary target command observations, never register authority."""
from dataclasses import asdict
from copy import deepcopy
import json
import hashlib

from .wire import DriverReceipt
from . import native_physical_observation

CONTEXT_KEYS = {'source_transaction','device_id','window_base','window_size','address','offset','write','value','be'}
RECEIPT_KEYS = {'schema_version','access_id','target_instance','endpoint_id','target_reset_epoch',
    'source_transaction','delivery_context','command_scope','driver_receipt','sample_ticks','status',
    'rdata','error','proof_scope','grants_verified','grants_storage','grants_functional'}


def _json(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)


def _uint(value,maximum=(1<<64)-1):
    return type(value) is int and 0 <= value <= maximum


def _text(value):
    return type(value) is str and 0 < len(value) <= 256 and value.strip()==value


def _key_document(value):
    from myfuzz.scenario.ledger import TransactionKey
    if type(value) is not TransactionKey:
        raise ValueError('ordinary-access-actual-transaction-key-required')
    row=asdict(value)
    if (any(not _text(row[name]) for name in ('execution_id','testcase_id','source_component','channel_id'))
            or any(not _uint(row[name]) for name in ('source_epoch','source_sequence'))):
        raise ValueError('ordinary-access-transaction-key-invalid')
    return row


def _validate_context(context, transaction):
    if type(context) is not dict or set(context)!=CONTEXT_KEYS:
        raise ValueError('ordinary-access-closed-context-required')
    source=context['source_transaction']
    if (type(source) is not dict or set(source)!=set(transaction)
            or any(not _text(source[name]) for name in ('execution_id','testcase_id','source_component','channel_id'))
            or any(not _uint(source[name]) for name in ('source_epoch','source_sequence'))
            or _json(source) != _json(transaction) or not _text(context['device_id'])):
        raise ValueError('ordinary-access-source-context-mismatch')
    if (any(not _uint(context[name],(1<<32)-1) for name in ('window_base','address','offset','value'))
            or type(context['window_size']) is not int or context['window_size'] <= 0
            or context['window_base']+context['window_size'] > 1<<32
            or context['address'] != context['window_base']+context['offset']
            or context['address']%4 or context['offset']+4 > context['window_size']
            or type(context['write']) is not bool or type(context['be']) is not int or context['be']!=15):
        raise ValueError('ordinary-access-invalid-context')


def validate_ordinary_apb_target_receipt(document, *, source_transaction=None, delivery_context=None):
    """Validate comparison data. Authority additionally requires the live registry."""
    if type(document) is not dict or set(document)!=RECEIPT_KEYS:
        raise ValueError('ordinary-access-closed-receipt-required')
    if (document['schema_version']!='ordinary_apb_target_receipt.v1'
            or document['proof_scope']!='actual_target_command_observation_only'
            or document['status']!='target_observed'
            or any(document[name] is not False for name in ('grants_verified','grants_storage','grants_functional'))
            or not _uint(document['rdata'],(1<<32)-1) or type(document['error']) is not int or document['error']!=0
            or not _uint(document['target_reset_epoch'])
            or any(not _text(document[name]) for name in ('access_id','target_instance','endpoint_id'))):
        raise ValueError('ordinary-access-invalid-receipt')
    transaction=document['source_transaction']
    if type(transaction) is not dict or set(transaction)!={'execution_id','testcase_id','source_component','source_epoch','channel_id','source_sequence'}:
        raise ValueError('ordinary-access-invalid-source-key')
    from myfuzz.scenario.ledger import TransactionKey
    if _key_document(TransactionKey(**transaction)) != transaction:
        raise ValueError('ordinary-access-invalid-source-key')
    _validate_context(document['delivery_context'],transaction)
    scope=document['command_scope']; driver=document['driver_receipt']; ticks=document['sample_ticks']
    if (type(scope) is not dict or set(scope)!={'component','reset_epoch','command_sequence'}
            or scope['component']!=document['target_instance'] or scope['reset_epoch']!=document['target_reset_epoch']
            or not _uint(scope['reset_epoch'])
            or not _uint(scope['command_sequence']) or scope['command_sequence']==0
            or type(driver) is not dict or set(driver)!={'execution_scope','process_scope','sequence','tick_before','tick_after','new_ticks'}
            or driver['execution_scope']!='parsed_driver_execution' or not _text(driver['process_scope'])
            or any(not _uint(driver[name]) for name in ('sequence','tick_before','tick_after','new_ticks'))
            or driver['sequence']!=scope['command_sequence']
            or not 1 <= driver['new_ticks'] <= 65536
            or driver['tick_after']-driver['tick_before']!=driver['new_ticks']
            or type(ticks) is not list or any(not _uint(t) for t in ticks)
            or ticks!=list(range(driver['tick_before']+1,driver['tick_after']+1))
            or document['target_instance']!=document['delivery_context']['device_id']):
        raise ValueError('ordinary-access-invalid-command-span')
    if source_transaction is not None:
        if type(source_transaction) is dict:
            if set(source_transaction)!=set(transaction): raise ValueError('ordinary-access-source-mismatch')
            expected=_key_document(TransactionKey(**source_transaction))
        else:
            expected=_key_document(source_transaction)
        if _json(transaction)!=_json(expected): raise ValueError('ordinary-access-source-mismatch')
    if delivery_context is not None:
        _validate_context(delivery_context,transaction)
        if _json(document['delivery_context'])!=_json(delivery_context):
            raise ValueError('ordinary-access-delivery-context-mismatch')
    return deepcopy(document)


class OrdinaryApbAccessReceipts:
    def __init__(self,session,*,max_records=256):
        if type(max_records) is not int or not 1<=max_records<=65536:
            raise ValueError('ordinary-access-invalid-capacity')
        if session._case_id is not None or session.process is not None or session._sequence or session._samples:
            raise ValueError('ordinary-access-configure-before-begin-required')
        if session.routed_register_access_enabled:
            raise ValueError('ordinary-access-causal-mode-not-supported')
        if native_physical_observation.verify_native_physical_observation(session.artifact) is not True:
            raise ValueError('ordinary-access-native-observation-required')
        trace=session.artifact.runtime_document.get('base_protocol_trace')
        if type(trace) is not dict or trace.get('protocol')!='apb3':
            raise ValueError('ordinary-access-native-apb-trace-required')
        self.session=session; self._session=session; self.artifact=session.artifact; self.max_records=max_records
        self.instance=session.artifact.plan.request.instance_id
        self.endpoint=trace['endpoint_id'];self.window_size=session.artifact.plan.profile.address.window_size
        self._configuration=_json(self._static())
        self._records={};self._keys={};self._terminal={};self._execution_pins={};self._sample_digests={}
        self._process_scopes={};self._commands=set();self._access_counter=0
        self.events=[];self._uncertain=False;self._active=False

    def _static(self):
        from myfuzz.composition.component_profile import bind_profile
        artifact=self.session.artifact
        if bind_profile(artifact.plan.profile,artifact.plan.facts)!=artifact.plan.binding:
            raise ValueError('ordinary-access-binding-drift')
        return dict(runtime=artifact.runtime_document,plan=artifact.plan.document(),
            binding=asdict(artifact.plan.binding),profile_fingerprint=artifact.plan.profile.profile_fingerprint,
            runtime_sv=artifact.runtime_sv,driver=artifact.cpp_text,
            configuration=dict(instance=self.instance,endpoint=self.endpoint,window_size=self.window_size,max_records=self.max_records))

    def configuration(self):
        self.validate()
        return dict(schema_version='ordinary_apb_access_receipts.v1',artifact_kind='apb_gpio',
            target_instance=self.instance,endpoint_id=self.endpoint,max_records=self.max_records,
            max_pending_samples=65536,native_trace_sha256=hashlib.sha256(_json(
                self.artifact.runtime_document['base_protocol_trace']).encode()).hexdigest(),
            proof_scope='actual_target_command_observation_only',grants_verified=False,
            grants_storage=False,grants_functional=False)

    def validate(self):
        if self.session is not self._session or type(self.max_records) is not int:
            raise ValueError('ordinary-access-configuration-drift')
        self.session._check_artifact_stable()
        if native_physical_observation.verify_native_physical_observation(self.session.artifact) is not True:
            raise ValueError('ordinary-access-native-observation-required')
        if self.session.artifact is not self.artifact or _json(self._static())!=self._configuration:
            raise ValueError('ordinary-access-artifact-drift')

    def lookup(self,access_id):
        self.validate()
        record=self._records.get(access_id)
        if (record is None or record['target_reset_epoch']!=self.session.reset_epoch
                or self._execution_pins.get(access_id)!=self.session._execution):
            raise ValueError('ordinary-access-unknown-or-stale-receipt')
        return deepcopy(record)

    def sample_digest(self, access_id, local_tick, phase):
        self.lookup(access_id)
        if not _uint(local_tick) or type(phase) is not str or phase not in ('pre','post'):
            raise ValueError('ordinary-access-invalid-sample-coordinate')
        digest=self._sample_digests.get((access_id,local_tick,phase))
        if digest is None: raise ValueError('ordinary-access-sample-not-recorded')
        return digest

    def _check_protocol_boundary(self,samples,context,rdata,epoch):
        from myfuzz.scenario.ip_protocol_events import IpProtocolEventNormalizer
        from myfuzz.scenario.ip_protocol_checker import IpProtocolChecker
        trace=self.session.artifact.runtime_document['base_protocol_trace']
        args=dict(component_id=self.session.artifact.plan.profile.component_id,
            instance_id=self.instance,protocol_trace=trace)
        normalizer=IpProtocolEventNormalizer(**args);checker=IpProtocolChecker(**args)
        events=[]
        for index,sample in enumerate(samples,1):
            for phase in ('pre','post'):
                state=sample.get(phase)
                backend=state.get('backend') if type(state) is dict else None
                if type(backend) is not dict:
                    raise ValueError('ordinary-access-native-backend-required')
                for role,name in trace['signals'].items():
                    if not _uint(backend.get(name),(1<<trace['signal_widths'][role])-1):
                        raise ValueError('ordinary-access-native-signal-invalid')
            signals={role:sample['pre']['backend'][name] for role,name in trace['signals'].items()}
            if signals['psel'] and (signals['paddr']!=context['offset']
                    or signals['pwrite']!=int(context['write'])
                    or context['write'] and signals['pwdata']!=context['value']):
                raise ValueError('ordinary-access-command-signals-mismatch')
            raw=dict(kind='local_tick_sample',event_id=index,local_tick=sample['local_tick'],
                phase='pre',outputs=sample['pre'])
            if checker.consume_local_tick(raw,reset_epoch=epoch):
                raise ValueError('ordinary-access-protocol-violation')
            events.extend(normalizer.consume_local_tick(raw,reset_epoch=epoch))
        boundaries=[e for e in events if e['event_type'] in ('transaction_request','transaction_accept','transaction_response')]
        if [e['event_type'] for e in boundaries]!=['transaction_request','transaction_accept','transaction_response']:
            raise ValueError('ordinary-access-incomplete-or-duplicate-boundary')
        response=boundaries[-1]['payload']
        if response['error'] or not context['write'] and response['rdata']!=rdata:
            raise ValueError('ordinary-access-native-response-mismatch')

    def execute(self,key,context):
        self.validate(); transaction=_key_document(key);_validate_context(context,transaction)
        if context['device_id']!=self.instance or context['window_size']!=self.window_size:
            raise ValueError('ordinary-access-target-context-mismatch')
        if self._uncertain or self._active or self.session._case_id is None:
            raise ValueError('ordinary-access-inactive-or-uncertain')
        identity=_json(transaction)
        if identity in self._keys:
            record=self.lookup(self._keys[identity])
            if record['delivery_context']!=context:
                self._uncertain=True
                raise ValueError('ordinary-access-conflicting-transaction')
            return dict(rdata=record['rdata'],target_access_id=record['access_id'],target_access_receipt=record)
        if (len(self._keys)>=self.max_records or len(self.session._samples)+self.session.max_local_ticks_per_register_access>65536):
            raise ValueError('ordinary-access-capacity-exceeded')
        epoch=self.session.reset_epoch;sequence=self.session._sequence+1;before=self.session.local_ticks
        execution=self.session._execution;tick_base=self.session._tick_base
        command_identity=(execution,epoch,sequence)
        if command_identity in self._commands:
            self._uncertain=True
            raise ValueError('ordinary-access-duplicate-physical-command')
        self._access_counter+=1
        access_id=f'ordinary-apb:{self.instance}:{self._access_counter}'
        process_ordinal=self._process_scopes.setdefault(execution,len(self._process_scopes)+1)
        self._active=True
        try:
            reply=self.session.command('ACCESS_GPIO',(self.session._gpio_in,int(context['write']),context['offset'],context['value'] if context['write'] else 0,15))
            if (type(reply) is not DriverReceipt or reply.status!='result' or reply.execution!=execution
                    or any(not _uint(getattr(reply,name)) for name in ('sequence','tick_before','tick_after','new_ticks'))
                    or reply.sequence!=sequence or self.session._sequence!=sequence
                    or self.session._execution!=execution or self.session.reset_epoch!=epoch
                    or self.session._tick_base!=tick_base
                    or reply.tick_before+tick_base!=before or reply.tick_after+tick_base!=self.session.local_ticks
                    or not 1<=reply.new_ticks<=self.session.max_local_ticks_per_register_access
                    or reply.new_ticks!=reply.tick_after-reply.tick_before
                    or type(reply.payload) is not dict):
                raise ValueError('ordinary-access-parsed-receipt-mismatch')
            samples=reply.payload.get('samples')
            if (type(samples) is not list or len(samples)!=reply.new_ticks
                    or any(type(s) is not dict or not _uint(s.get('local_tick')) for s in samples)
                    or [s.get('local_tick') for s in samples]!=list(range(reply.tick_before+1,reply.tick_after+1))):
                raise ValueError('ordinary-access-sample-span-mismatch')
            self._check_protocol_boundary(samples,context,reply.payload.get('rdata'),epoch)
            scope=dict(component=self.instance,reset_epoch=epoch,command_sequence=sequence)
            record=dict(schema_version='ordinary_apb_target_receipt.v1',access_id=access_id,
                target_instance=self.instance,endpoint_id=self.endpoint,target_reset_epoch=epoch,
                source_transaction=transaction,delivery_context=deepcopy(context),command_scope=scope,
                driver_receipt=dict(execution_scope='parsed_driver_execution',process_scope=f'local-driver:{self.instance}:{process_ordinal}',
                    sequence=sequence,tick_before=before,tick_after=self.session.local_ticks,new_ticks=reply.new_ticks),
                sample_ticks=list(range(before+1,self.session.local_ticks+1)),status='target_observed',
                rdata=reply.payload.get('rdata'),error=reply.payload.get('error'),
                proof_scope='actual_target_command_observation_only',grants_verified=False,grants_storage=False,grants_functional=False)
            validate_ordinary_apb_target_receipt(record)
            values=self.session._take(reply)
            if values['rdata']!=record['rdata']: raise ValueError('ordinary-access-response-mismatch')
            queued=list(self.session._samples)[-len(samples):]
            expected=[{**deepcopy(sample),'local_tick':tick_base+sample['local_tick']} for sample in samples]
            if (_json(queued)!=_json(expected) or self.session._tick_base!=tick_base
                    or [s['local_tick'] for s in queued]!=record['sample_ticks']):
                raise ValueError('ordinary-access-queued-sample-mismatch')
            for sample in queued:
                sample['ordinary_apb_access_ref']=deepcopy(dict(access_id=access_id,command_scope=scope))
            self.validate()
            self._records[access_id]=deepcopy(record);self._keys[identity]=access_id;self._execution_pins[access_id]=execution
            self._sample_digests.update({(access_id,tick_base+sample['local_tick'],phase):
                hashlib.sha256(_json(sample[phase]).encode()).hexdigest()
                for sample in samples for phase in ('pre','post')})
            self._commands.add(command_identity)
            self.events.append(deepcopy(record))
            return dict(rdata=record['rdata'],target_access_id=access_id,target_access_receipt=deepcopy(record))
        except BaseException as error:
            self._uncertain=True
            self.events.append(dict(schema_version='ordinary_apb_delivery_terminal.v1',access_id=access_id,
                source_transaction=transaction,target_reset_epoch=epoch,status='uncertain_target_effect',error_type=type(error).__name__))
            raise
        finally:
            self._active=False

    def delivery_failed(self,key,access_id):
        record=self.lookup(access_id)
        if record['source_transaction']!=_key_document(key):
            raise ValueError('ordinary-access-failed-delivery-identity')
        if access_id not in self._terminal:
            terminal=dict(schema_version='ordinary_apb_delivery_terminal.v1',access_id=access_id,
                source_transaction=record['source_transaction'],target_reset_epoch=record['target_reset_epoch'],
                status='uncertain_source_response')
            self._terminal[access_id]=terminal;self.events.append(deepcopy(terminal))
        self._uncertain=True
