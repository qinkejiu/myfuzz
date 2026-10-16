"""Native-only current-value witnesses. Pure reducers and JSON are not authority."""
from copy import deepcopy
from dataclasses import asdict
import sys
from pathlib import Path
import hashlib
import json
_GETFRAME=sys._getframe
from types import MappingProxyType
from weakref import WeakKeyDictionary

_WIDTHS = MappingProxyType(dict(value=32, reset=1, paddr=12, psel=1, penable=1,
               pwrite=1, pwdata=32, prdata=32, pready=1, pslverr=1))


def reduce_storage_samples(samples, *, previous=None, first_tick=1, max_samples=65536):
    """Isolated source-equation calculation; cannot create or consume tokens."""
    if (type(samples) is not list or not samples or type(max_samples) is not int
            or not 1 <= max_samples <= 65536 or not 1 <= len(samples) <= max_samples or type(first_tick) is not int or first_tick < 1):
        raise ValueError('storage-sample-capacity-or-shape')
    if previous is not None and (type(previous) is not dict or set(previous)-{'tick','value','reset_waveform_observed','sequence'} or any(type(previous.get(k)) is not int for k in ('tick','value')) or type(previous.get('reset_waveform_observed')) is not bool):raise ValueError('storage-previous-shape')
    state=deepcopy(previous);writes=[]
    names={'storage_'+role for role in _WIDTHS}
    for index,sample in enumerate(samples):
        if (type(sample) is not dict or not {'local_tick','pre','post'}<=set(sample)
                or any(type(sample[phase]) is not dict or 'storage_probes' not in sample[phase] for phase in ('pre','post'))):raise ValueError('storage-raw-sample-shape')
        tick=sample['local_tick']
        expected=first_tick if state is None else state['tick']+1
        if type(tick) is not int or tick!=expected:raise ValueError('storage-tick-discontinuity')
        pre=sample['pre']['storage_probes'];post=sample['post']['storage_probes']
        for group in (pre,post):
            if type(group) is not dict or set(group)!=names:raise ValueError('storage-probe-shape')
            if any(type(group['storage_'+role]) is not int or not 0<=group['storage_'+role]<(1<<width) for role,width in _WIDTHS.items()):raise ValueError('storage-probe-width')
            if group['storage_pready']!=1 or group['storage_pslverr']!=0:raise ValueError('storage-physical-error')
        old,new=pre['storage_value'],post['storage_value']
        if state is not None and old!=state['value']:raise ValueError('storage-value-discontinuity')
        reset=pre['storage_reset']
        if reset!=post['storage_reset']:raise ValueError('storage-reset-phase-uncertain')
        write=all(pre['storage_'+role]==1 for role in ('psel','penable','pwrite')) and (pre['storage_paddr']&0x1c)==4
        expected_value=0 if reset else pre['storage_pwdata'] if write else old
        if (reset and old!=0) or new!=expected_value:raise ValueError('storage-source-equation')
        if write and not reset:
            writes.append(dict(tick=tick,raw_address=pre['storage_paddr'],before=old,after=new,sample_index=index,phase='pre'))
        state=dict(tick=tick,value=new,reset_waveform_observed=bool(reset or state and state['reset_waveform_observed']))
    return state,writes

def validate_routed_context(context, *, operation, fields, sequence, execution, epoch, window):
    """Typed correlation only, never proof of a Router/ledger source producer."""
    if context is None:return None
    keys={'source_transaction','device_id','window_base','window_size','address','offset','write','value','be',
          'execution','reset_epoch','command_sequence','schema_version','source_authenticated'}
    if type(context) is not dict or set(context)!=keys:raise ValueError('storage-context-shape')
    key=context['source_transaction']
    if (type(key) is not dict or set(key)!={'execution_id','testcase_id','source_component','source_epoch','channel_id','source_sequence'}
            or any(type(key[k]) is not str or not key[k] for k in ('execution_id','testcase_id','source_component','channel_id'))
            or any(type(key[k]) is not int or key[k]<0 for k in ('source_epoch','source_sequence'))):raise ValueError('storage-context-transaction-types')
    if (operation!='ACCESS_APB3_REG' or type(fields) is not tuple or len(fields)!=4
            or any(type(v) is not int for v in fields)
            or any(type(context[k]) is not int for k in ('window_base','window_size','address','offset','value','be','reset_epoch','command_sequence'))
            or type(context['device_id']) is not str or not context['device_id']
            or type(context['write']) is not bool or context['write']!=bool(fields[0])
            or fields[0] not in (0,1) or fields[3]!=15
            or context['offset']!=fields[1] or context['value']!=fields[2] or context['be']!=fields[3]
            or not 0<=context['window_base']<1<<32 or context['window_size']!=window
            or not 0<=context['offset']<window or context['offset']%4
            or context['address']!=context['window_base']+context['offset']
            or context['window_base']+window>1<<32
            or context['execution']!=execution or type(context['execution']) is not str
            or context['reset_epoch']!=epoch or context['command_sequence']!=sequence
            or context['schema_version']!='apb_storage_routed_context.v1' or context['source_authenticated'] is not False):raise ValueError('storage-context-command-mismatch')
    return deepcopy(context)


_ROUTED_VALIDATOR=(validate_routed_context,validate_routed_context.__code__)

_AUTHORITIES=WeakKeyDictionary();_LIVE=WeakKeyDictionary();_TOKENS=WeakKeyDictionary()
_REGISTRIES=(_AUTHORITIES,_LIVE,_TOKENS)
_REDUCER=(reduce_storage_samples,reduce_storage_samples.__code__)


class ApbStorageRegisterVersionAuthority:
    def __init__(self,target,*,max_samples=65536,max_writes=4096,max_tokens=16):
        from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
        from myfuzz.local_harness.session import _NATIVE_RESET_CHECK_PRODUCERS
        if (type(target) is not GeneratedApb3RegisterSession or target.process is not None
                or target._case_id is not None or target._execution or target.reset_epoch or target in _AUTHORITIES
                or any(type(v) is not int or v!=0 for v in (target._sequence,target.local_ticks,target._tick_base))
                or target._storage_active_context is not None or target._storage_last_access is not None
                or any(type(v) is not int or not 1<=v<=65536 for v in (max_samples,max_writes,max_tokens))):
            raise ValueError('storage-version-fresh-exact-producer-required')
        _NATIVE_RESET_CHECK_PRODUCERS[0](target)
        if target._native_reset_observation is None:target.configure_native_reset_observation()
        self.target=target;self.artifact=target.artifact
        _AUTHORITIES[target]=self;_TOKENS[self]={}
        _LIVE[self]=dict(bad=False,state=None,scope=None,pending=None,writes=[],samples=0,
                         limits=(max_samples,max_writes,max_tokens))

    def _validate(self,*,native=False):
        from myfuzz.local_harness.session import _NATIVE_RESET_CHECK_PRODUCERS,_NATIVE_RESET_NATIVE_ELIGIBLE
        if (type(self) is not _TYPE
                or any(a is not b for a,b in zip((_AUTHORITIES,_LIVE,_TOKENS),_REGISTRIES))
                or _AUTHORITIES.get(self.target) is not self or self not in _LIVE
                or _LIVE[self]['bad'] or self.target.artifact is not self.artifact
                or any(type(value) is not int or value<0 for value in (self.target.reset_epoch,self.target._sequence,self.target.local_ticks,self.target._tick_base))
                or any(name in vars(self) or getattr(_TYPE,name) is not method or method.__code__ is not code for name,(method,code) in _METHODS.items())
                or validate_routed_context is not _ROUTED_VALIDATOR[0] or validate_routed_context.__code__ is not _ROUTED_VALIDATOR[1]
                or reduce_storage_samples is not _REDUCER[0] or reduce_storage_samples.__code__ is not _REDUCER[1]):
            raise ValueError('storage-version-authority-drift-or-revoked')
        _NATIVE_RESET_CHECK_PRODUCERS[0](self.target)
        self.target._native_reset_observation.validate()
        if native:
            eligible,digest=_NATIVE_RESET_NATIVE_ELIGIBLE[0](self.target)
            if eligible is not True:raise ValueError('storage-version-actual-native-build-required')
            return digest

    def _frame(self,target,name,receipt=None):
        from myfuzz.local_harness import session
        if sys._getframe is not _GETFRAME:self._revoke();raise ValueError('storage-version-frame-reader-drift')
        frame=_GETFRAME(2)
        method,code=session._NATIVE_RESET_SESSION_FUNCTIONS[name]
        if (frame.f_code is not code or frame.f_globals is not vars(session)
                or frame.f_locals.get('self') is not target or target is not self.target
                or receipt is not None and frame.f_locals.get('receipt') is not receipt):
            self._revoke();raise ValueError('storage-version-actual-producer-frame-required')

    def _revoke(self):
        if self in _TOKENS:_TOKENS[self].clear()
        if self in _LIVE:_LIVE[self]['bad']=True

    def _actual_begin(self,target,operation,fields):
        from myfuzz.local_harness.session import _NATIVE_RESET_CHECK_PRODUCERS, _STORAGE_VERSION_LOOKUP_PINS, _NATIVE_RESET_OWNER_GUARD_PIN
        _NATIVE_RESET_OWNER_GUARD_PIN[0](self.target)
        _NATIVE_RESET_CHECK_PRODUCERS[0](self.target)
        if _STORAGE_VERSION_LOOKUP_PINS['_storage_version_authority'][0](self.target) is not self:
            raise ValueError('storage-version-independent-entry-origin-required')
        self._frame(target,'_command_impl')
        _TOKENS[self].clear()
        try:
            build_digest=self._validate(native=True)
            live=_LIVE[self]
            if live.get('build_digest',build_digest)!=build_digest:raise ValueError('storage-version-build-drift')
            live['build_digest']=build_digest
            scope=(target.process,target._execution,target.reset_epoch)
            if (live['pending'] is not None or live['scope'] is not None and live['scope']!=scope
                    or live['state'] is None and target._sequence!=0):raise ValueError('storage-version-history-unavailable')
            live['scope']=scope
            context=_ROUTED_VALIDATOR[0](target._storage_active_context,operation=operation,fields=fields,sequence=target._sequence+1,execution=target._execution,epoch=target.reset_epoch,window=target._window)
            live['pending']=(operation,fields,target._sequence+1,target.local_ticks,context)
        except BaseException:self._revoke();raise

    def _actual_command(self,target,operation,fields,receipt):
        from myfuzz.local_harness.session import _NATIVE_RESET_CHECK_PRODUCERS, _STORAGE_VERSION_LOOKUP_PINS, _NATIVE_RESET_OWNER_GUARD_PIN
        _NATIVE_RESET_OWNER_GUARD_PIN[0](self.target)
        _NATIVE_RESET_CHECK_PRODUCERS[0](self.target)
        if _STORAGE_VERSION_LOOKUP_PINS['_storage_version_authority'][0](self.target) is not self:
            raise ValueError('storage-version-independent-entry-origin-required')
        self._frame(target,'_command_impl',receipt)
        try:
            self._validate(native=True);live=_LIVE[self];pending=live['pending']
            if (pending is None or live['scope']!=(target.process,target._execution,target.reset_epoch)
                    or json.dumps(target._storage_active_context,sort_keys=True,allow_nan=False)!=json.dumps(pending[4],sort_keys=True,allow_nan=False)
                    or pending[:3]!=(operation,fields,receipt.sequence)
                    or receipt.status!='result' or receipt.payload is None or receipt.payload['error']!=0
                    or receipt.execution!=target._execution or receipt.tick_before+target._tick_base!=pending[3]
                    or receipt.tick_after-receipt.tick_before!=len(receipt.payload['samples'])):raise ValueError('storage-version-receipt-mismatch')
            rows=deepcopy(receipt.payload['samples'])
            for row in rows:row['local_tick']+=target._tick_base
            remaining=live['limits'][0]-live['samples']
            state,writes=_REDUCER[0](rows,previous=live['state'],first_tick=pending[3]+1,max_samples=remaining)
            accepted=[r['pre']['storage_probes'] for r in rows if all(r['pre']['storage_probes']['storage_'+k]==1 for k in ('psel','penable','pready'))]
            if operation=='ACCESS_APB3_REG':
                if (len(accepted)!=1 or accepted[0]['storage_paddr']!=fields[1] or accepted[0]['storage_pwrite']!=fields[0]
                        or fields[0] and accepted[0]['storage_pwdata']!=fields[2]
                        or not fields[0] and accepted[0]['storage_prdata']!=receipt.payload['rdata']):raise ValueError('storage-version-command-physical-join')
            elif operation!='STEP_APB3_REG' or accepted:raise ValueError('storage-version-untracked-physical-access')
            if len(live['writes'])+len(writes)>live['limits'][1]:raise ValueError('storage-version-write-capacity')
            for write in writes:
                write.update(command_sequence=receipt.sequence,context=deepcopy(pending[4]),
                    raw_reference=dict(execution=receipt.execution,sequence=receipt.sequence,sample_index=write['sample_index'],phase='pre'))
            live['writes'].extend(writes);live['samples']+=len(rows);live['state']=state
            state['sequence']=receipt.sequence;live['pending']=None
        except BaseException:self._revoke();raise

    def issue(self,*,register='TIMER0_CTRL',reset_epoch):
        from myfuzz.local_harness.session import _NATIVE_RESET_CHECK_PRODUCERS, _STORAGE_VERSION_LOOKUP_PINS, _NATIVE_RESET_OWNER_GUARD_PIN
        _NATIVE_RESET_OWNER_GUARD_PIN[0](self.target)
        _NATIVE_RESET_CHECK_PRODUCERS[0](self.target)
        if _STORAGE_VERSION_LOOKUP_PINS['_storage_version_authority'][0](self.target) is not self:
            raise ValueError('storage-version-independent-entry-origin-required')
        try:
            self._validate(native=True);t=self.target;live=_LIVE[self];state=live['state']
            if (register!='TIMER0_CTRL' or type(reset_epoch) is not int or reset_epoch!=t.reset_epoch
                    or state is None or live['pending'] is not None or live['scope']!=(t.process,t._execution,t.reset_epoch)
                    or t.process is None or t.process.poll() is not None or state['sequence']!=t._sequence):raise ValueError('storage-version-current-state-unavailable')
            if len(_TOKENS[self])>=live['limits'][2]:raise ValueError('storage-version-token-capacity')
            doc=t._artifact_document;probe=doc['storage_observation']
            token=object();_TOKENS[self][token]=dict(register=register,value=state['value'],local_tick=state['tick'],
                write_history_sha256=hashlib.sha256(json.dumps(live['writes'],sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest(),
                field_version=len(live['writes']),write_count=len(live['writes']),version_basis='all_measured_CTRL_alias_writes_since_first_command',
                reset_epoch=reset_epoch,command_sequence=state['sequence'],pid=t.process.pid,execution=t._execution,
                build_identity_sha256=live['build_digest'],producer_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                artifact_digest=doc['artifact_digest'],source_contract_digest=probe['source_contract']['digest'],probe_digest=probe['digest'],
                reset_waveform_observed=state['reset_waveform_observed'],grants_reset_prerequisite=False,
                history_scope='complete_commands_since_first_measured_state_not_unobserved_startup',routed_context_authenticated=False)
            return token
        except BaseException:self._revoke();raise

    def consume(self,token):
        from myfuzz.local_harness.session import _NATIVE_RESET_CHECK_PRODUCERS, _STORAGE_VERSION_LOOKUP_PINS, _NATIVE_RESET_OWNER_GUARD_PIN
        _NATIVE_RESET_OWNER_GUARD_PIN[0](self.target)
        _NATIVE_RESET_CHECK_PRODUCERS[0](self.target)
        if _STORAGE_VERSION_LOOKUP_PINS['_storage_version_authority'][0](self.target) is not self:
            raise ValueError('storage-version-independent-entry-origin-required')
        try:
            self._validate(native=True);t=self.target;live=_LIVE[self];state=live['state']
            if (state is None or live['pending'] is not None or live['scope']!=(t.process,t._execution,t.reset_epoch)
                    or t.process is None or t.process.poll() is not None or state['sequence']!=t._sequence):raise ValueError('storage-version-stale-scope')
            witness=_TOKENS[self].pop(token,None)
            if witness is None:raise ValueError('storage-version-token-invalid')
            return deepcopy(witness)
        except BaseException:self._revoke();raise

    def writes(self):
        from myfuzz.local_harness.session import _NATIVE_RESET_CHECK_PRODUCERS, _STORAGE_VERSION_LOOKUP_PINS, _NATIVE_RESET_OWNER_GUARD_PIN
        _NATIVE_RESET_OWNER_GUARD_PIN[0](self.target)
        _NATIVE_RESET_CHECK_PRODUCERS[0](self.target)
        if _STORAGE_VERSION_LOOKUP_PINS['_storage_version_authority'][0](self.target) is not self:
            raise ValueError('storage-version-independent-entry-origin-required')
        self._validate();return deepcopy(_LIVE[self]['writes'])

_TYPE=ApbStorageRegisterVersionAuthority
_METHODS=MappingProxyType({name:(method,method.__code__) for name,method in vars(_TYPE).items() if hasattr(method,'__code__')})
