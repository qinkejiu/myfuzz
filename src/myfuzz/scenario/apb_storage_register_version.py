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
_STARTUP_HELPER_MODULE=None
_STARTUP_HELPER_FUNCTIONS=None

_STARTUP_OPERATION='READ_APB_STORAGE_STARTUP'
_STARTUP_PHASES=('not_started','awaiting_first_command','done')
_STARTUP_KEYS=frozenset({'contract','ports','page_count','next_page','pages','records',
    'bytes','complete','handoff','handoff_facts','last_post','last_raw','reset_observed'})

_WIDTHS = MappingProxyType(dict(value=32, reset=1, paddr=12, psel=1, penable=1,
               pwrite=1, pwdata=32, prdata=32, pready=1, pslverr=1))


def validate_storage_startup_receipt(receipt, *, execution, sequence, contract,
                                     ports, expected_page):
    """Pure documentary page check; never an issuance or authority API."""
    if (receipt is None or type(execution) is not str or not execution
            or type(sequence) is not int or sequence < 1
            or type(expected_page) is not int or expected_page < 0):
        raise ValueError('storage-startup-receipt-types')
    if (receipt.status!='result' or receipt.execution!=execution
            or receipt.sequence!=sequence or receipt.tick_before!=0
            or receipt.tick_after!=0 or receipt.new_ticks!=0
            or receipt.payload is None):
        raise ValueError('storage-startup-receipt-identity')
    payload=receipt.payload
    if (not isinstance(payload,dict) or set(payload)!={'schema_version','kind',
            'samples','observations','pre_backend','rdata','error'}
            or payload.get('kind')!='apb3_register_observe'
            or payload.get('samples')!=[] or payload.get('rdata')!=0
            or payload.get('error')!=0 or not isinstance(payload.get('pre_backend'),dict)
            or not isinstance(payload.get('observations'),dict)
            or set(payload['observations'])!={'storage_startup'}):
        raise ValueError('storage-startup-receipt-payload')
    page=payload['observations']['storage_startup']
    from myfuzz.local_harness.apb_storage_startup import validate_startup_page
    records=validate_startup_page(page,contract,expected_page=expected_page,ports=ports)
    return deepcopy(page),records


_STARTUP_LOCAL_FUNCTIONS=MappingProxyType({name:(value,value.__code__) for name,value in (
    ('validate_storage_startup_receipt',validate_storage_startup_receipt),)})
_STARTUP_HELPER_NAMES=('validate_startup_handoff','validate_startup_page','contract_from_document')


def _startup_helper():
    global _STARTUP_HELPER_MODULE
    module=_STARTUP_HELPER_MODULE
    if module is None:
        from myfuzz.local_harness import apb_storage_startup as module
        _STARTUP_HELPER_MODULE=module
    return _STARTUP_HELPER_MODULE


def _startup_helper_functions():
    global _STARTUP_HELPER_FUNCTIONS
    module=_startup_helper()
    if _STARTUP_HELPER_FUNCTIONS is None:
        _STARTUP_HELPER_FUNCTIONS=MappingProxyType({name:(getattr(module,name),
            getattr(module,name).__code__) for name in _STARTUP_HELPER_NAMES})
    return _STARTUP_HELPER_FUNCTIONS


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)


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

def validate_storage_scope(state, scope, *, process, execution, epoch, tick_base, sequence, tick, allow_initial=False):
    """Pure consistency guard, not native eligibility or an issuance API."""
    if (type(allow_initial) is not bool or process is None or type(execution) is not str or not execution
            or any(type(value) is not int or value<0 for value in (epoch,tick_base,sequence,tick))):
        raise ValueError('storage-version-scope-types')
    current=(process,execution,epoch,tick_base)
    if state is None:
        if not allow_initial or scope is not None or sequence!=0 or tick!=tick_base:
            raise ValueError('storage-version-history-unavailable')
    elif (type(scope) is not tuple or len(scope)!=4 or scope[0] is not process
            or scope!=current or state['sequence']!=sequence or state['tick']!=tick):
        raise ValueError('storage-version-current-scope-drift')


_SCOPE_VALIDATOR=(validate_storage_scope,validate_storage_scope.__code__)

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
                         limits=(max_samples,max_writes,max_tokens),startup=None,
                         last_wire_sequence=0)

    def _validate(self,*,native=False):
        from myfuzz.local_harness.session import _NATIVE_RESET_CHECK_PRODUCERS,_NATIVE_RESET_NATIVE_ELIGIBLE
        if (type(self) is not _TYPE
                or any(a is not b for a,b in zip((_AUTHORITIES,_LIVE,_TOKENS),_REGISTRIES))
                or _AUTHORITIES.get(self.target) is not self or self not in _LIVE
                or _LIVE[self]['bad'] or self.target.artifact is not self.artifact
                or any(type(value) is not int or value<0 for value in (self.target.reset_epoch,self.target._sequence,self.target.local_ticks,self.target._tick_base))
                or any(name in vars(self) or getattr(_TYPE,name) is not method or method.__code__ is not code for name,(method,code) in _METHODS.items())
                or validate_storage_scope is not _SCOPE_VALIDATOR[0] or validate_storage_scope.__code__ is not _SCOPE_VALIDATOR[1]
                or validate_routed_context is not _ROUTED_VALIDATOR[0] or validate_routed_context.__code__ is not _ROUTED_VALIDATOR[1]
                or reduce_storage_samples is not _REDUCER[0] or reduce_storage_samples.__code__ is not _REDUCER[1]
                or any(globals().get(name) is not value or value.__code__ is not code
                       for name,(value,code) in _STARTUP_LOCAL_FUNCTIONS.items())
                or any(getattr(_startup_helper(),name) is not value or value.__code__ is not code
                       for name,(value,code) in _startup_helper_functions().items())):
            raise ValueError('storage-version-authority-drift-or-revoked')
        _NATIVE_RESET_CHECK_PRODUCERS[0](self.target)
        self.target._native_reset_observation.validate()
        self._check_startup(_LIVE[self])
        if native:
            eligible,digest=_NATIVE_RESET_NATIVE_ELIGIBLE[0](self.target)
            if eligible is not True:raise ValueError('storage-version-actual-native-build-required')
            return digest

    def _startup_required(self):
        document=self.target._artifact_document
        return (document.get('kind')=='apb3_register_observe'
            and ('storage_startup_selection' in document
                 or 'storage_startup_capture' in document))

    def _startup_contract(self):
        document=self.target._artifact_document
        if (document.get('kind')!='apb3_register_observe'
                or 'storage_startup_selection' not in document
                or 'storage_startup_capture' not in document):
            raise ValueError('storage-startup-document-required')
        contract=_startup_helper_functions()['contract_from_document'][0](document)
        ports=deepcopy(document.get('storage_probe_ports'))
        if type(ports) is not list:raise ValueError('storage-startup-ports-required')
        return contract,ports

    def _check_startup(self,live):
        startup=live.get('startup')
        required=self._startup_required()
        if startup is None:
            if required and live['state'] is not None:
                raise ValueError('storage-startup-initial-pages-required')
            return
        if type(startup) is not dict or set(startup)!=_STARTUP_KEYS:
            raise ValueError('storage-startup-state-drift')
        if (type(live.get('last_wire_sequence')) is not int
                or live['last_wire_sequence']<0):
            raise ValueError('storage-startup-wire-sequence-drift')
        contract,ports=self._startup_contract()
        if (_canonical(startup['contract'])!=_canonical(contract)
                or _canonical(startup['ports'])!=_canonical(ports)
                or startup['page_count']!=contract['page_count']):
            raise ValueError('storage-startup-contract-drift')
        if (type(startup['next_page']) is not int
                or not 0<=startup['next_page']<=startup['page_count']
                or type(startup['pages']) is not list
                or len(startup['pages'])!=startup['next_page']
                or startup['complete'] is not (startup['next_page']==startup['page_count'])
                or startup['handoff'] not in _STARTUP_PHASES
                or type(startup['reset_observed']) is not bool
                or type(startup['records']) is not int
                or not 0<=startup['records']<=contract['total_ticks']
                or type(startup['bytes']) is not int
                or not 0<=startup['bytes']<=contract['receipt_storage_bound_bytes']
                or startup['handoff']=='done' and live['state'] is None):
            raise ValueError('storage-startup-state-drift')
        if live['pending'] is not None and live['pending'][5]=='startup_page':
            if startup['handoff'] not in ('not_started','awaiting_first_command'):
                raise ValueError('storage-startup-handoff-state')
        post=startup['last_post']
        if post is not None:
            names={'storage_'+role for role in _WIDTHS}
            if (type(post) is not dict or set(post)!=names
                    or any(type(post[name]) is not int or not 0<=post[name]<1<<_WIDTHS[name[8:]]
                           for name in names)):
                raise ValueError('storage-startup-last-post-drift')
            if startup['next_page']==0:raise ValueError('storage-startup-last-post-drift')

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
            self._validate()
            live=_LIVE[self]
            if live['pending'] is not None:raise ValueError('storage-version-pending-command')
            if live['last_wire_sequence']!=target._sequence:
                raise ValueError('storage-version-wire-sequence-drift')
            scope=(target.process,target._execution,target.reset_epoch,target._tick_base)
            startup=None;context=None;kind='command'
            if operation==_STARTUP_OPERATION:
                if not self._startup_required():
                    raise ValueError('storage-startup-document-required')
                startup,need_scope=self._plan_startup_page(target,fields,live,scope)
                kind='startup_page'
            else:
                if self._startup_required():
                    if live['startup'] is None or live['startup']['complete'] is not True:
                        raise ValueError('storage-startup-initial-pages-required')
                startup,context,need_scope=self._plan_ordinary_command(
                    target,operation,fields,live,scope)
            if need_scope:
                _SCOPE_VALIDATOR[0](live['state'] if kind!='startup_page' else None,
                    live['scope'] if kind!='startup_page' else None,
                    process=target.process,execution=target._execution,
                    epoch=target.reset_epoch,tick_base=target._tick_base,
                    sequence=target._sequence,tick=target.local_ticks,allow_initial=True)
            build_digest=self._validate(native=True)
            live=_LIVE[self]
            if live.get('build_digest',build_digest)!=build_digest:raise ValueError('storage-version-build-drift')
            live['build_digest']=build_digest
            live['scope']=scope
            if startup is not None:live['startup']=startup
            live['pending']=(operation,fields,target._sequence+1,target.local_ticks,context,kind)
        except BaseException:self._revoke();raise

    def _plan_startup_page(self,target,fields,live,scope):
        startup=live.get('startup')
        if startup is None:
            contract,ports=self._startup_contract()
            host_contract=getattr(target,'_storage_startup_contract',None)
            if _canonical(host_contract)!=_canonical(contract):
                raise ValueError('storage-startup-host-contract-mismatch')
            startup=dict(contract=contract,ports=ports,page_count=contract['page_count'],
                next_page=0,pages=[],records=0,bytes=0,complete=False,
                handoff='not_started',handoff_facts=None,last_post=None,last_raw=None,
                reset_observed=False)
        else:
            startup=deepcopy(startup)
        if startup['complete']:raise ValueError('storage-startup-pages-complete')
        if (type(fields) is not tuple or len(fields)!=1 or type(fields[0]) is not int
                or not 0<=fields[0]<startup['page_count']):
            raise ValueError('storage-startup-page-order')
        page=fields[0]
        if page!=startup['next_page'] or target._sequence!=page:
            raise ValueError('storage-startup-page-order')
        if target.local_ticks!=target._tick_base:
            raise ValueError('storage-startup-command-tick')
        if target._storage_active_context is not None:
            raise ValueError('storage-startup-routed-context')
        if page==0:
            if (live['scope'] is not None or live['state'] is not None
                    or live['last_wire_sequence']!=0):
                raise ValueError('storage-startup-initial-history')
            return startup,True
        if (live['scope']!=scope or live['state'] is not None
                or live['last_wire_sequence']!=target._sequence):
            raise ValueError('storage-startup-scope-drift')
        return startup,False

    def _plan_ordinary_command(self,target,operation,fields,live,scope):
        startup=deepcopy(live['startup']) if live.get('startup') is not None else None
        if self._startup_required():
            if startup is None or startup['complete'] is not True:
                raise ValueError('storage-startup-initial-pages-required')
            if live['state'] is None:
                if startup['handoff']!='awaiting_first_command':
                    raise ValueError('storage-startup-handoff-state')
                if target._sequence!=startup['page_count']:
                    raise ValueError('storage-startup-page-sequence')
                if target.local_ticks!=target._tick_base:
                    raise ValueError('storage-startup-command-tick')
                if live['scope']!=scope:
                    raise ValueError('storage-startup-scope-drift')
                need_scope=False
            else:
                need_scope=True
        else:
            need_scope=True
        context=_ROUTED_VALIDATOR[0](target._storage_active_context,operation=operation,
            fields=fields,sequence=target._sequence+1,execution=target._execution,
            epoch=target.reset_epoch,window=target._window)
        return startup,context,need_scope

    def _actual_command(self,target,operation,fields,receipt):
        from myfuzz.local_harness.session import _NATIVE_RESET_CHECK_PRODUCERS, _STORAGE_VERSION_LOOKUP_PINS, _NATIVE_RESET_OWNER_GUARD_PIN
        _NATIVE_RESET_OWNER_GUARD_PIN[0](self.target)
        _NATIVE_RESET_CHECK_PRODUCERS[0](self.target)
        if _STORAGE_VERSION_LOOKUP_PINS['_storage_version_authority'][0](self.target) is not self:
            raise ValueError('storage-version-independent-entry-origin-required')
        self._frame(target,'_command_impl',receipt)
        try:
            self._validate(native=True);live=_LIVE[self];pending=live['pending']
            if (pending is None
                    or live['scope']!=(target.process,target._execution,target.reset_epoch,target._tick_base)
                    or target._sequence!=pending[2]-1
                    or live['last_wire_sequence']!=target._sequence
                    or pending[:3]!=(operation,fields,receipt.sequence)
                    or receipt.execution!=target._execution
                    or receipt.sequence!=pending[2]):
                raise ValueError('storage-version-receipt-mismatch')
            if pending[5]=='startup_page':
                if (receipt.tick_before!=0 or receipt.tick_after!=0
                        or target.local_ticks!=pending[3]):
                    raise ValueError('storage-startup-command-tick')
                self._complete_startup_page(target,receipt,pending,live)
            else:
                if (json.dumps(target._storage_active_context,sort_keys=True,allow_nan=False)!=json.dumps(pending[4],sort_keys=True,allow_nan=False)
                        or receipt.status!='result' or receipt.payload is None or receipt.payload['error']!=0
                        or receipt.tick_before+target._tick_base!=pending[3]
                        or receipt.tick_after-receipt.tick_before!=len(receipt.payload['samples'])):
                    raise ValueError('storage-version-receipt-mismatch')
                self._complete_ordinary_command(target,operation,fields,receipt,pending,live)
            live['last_wire_sequence']=receipt.sequence
            live['pending']=None
        except BaseException:self._revoke();raise

    def _complete_startup_page(self,target,receipt,pending,live):
        startup=live.get('startup')
        if (startup is None or type(startup) is not dict or set(startup)!=_STARTUP_KEYS
                or pending[4] is not None or pending[0]!=_STARTUP_OPERATION):
            raise ValueError('storage-startup-page-state')
        if startup['complete']:raise ValueError('storage-startup-pages-complete')
        page_index=pending[1][0]
        if page_index!=startup['next_page']:
            raise ValueError('storage-startup-page-order')
        page,records=_STARTUP_LOCAL_FUNCTIONS['validate_storage_startup_receipt'][0](
            receipt,execution=target._execution,sequence=pending[2],
            contract=startup['contract'],ports=startup['ports'],
            expected_page=page_index)
        if len(records)!=min(32,startup['contract']['total_ticks']-page_index*32):
            raise ValueError('storage-startup-page-count')
        page_text=_canonical(page)
        receipt_text=_canonical(asdict(receipt))
        consumed=len(page_text.encode())+len(receipt_text.encode())
        if startup['bytes']+consumed>startup['contract']['receipt_storage_bound_bytes']:
            raise ValueError('storage-startup-budget')
        startup=deepcopy(startup)
        startup['pages'].append(dict(page=deepcopy(page),receipt=deepcopy(asdict(receipt)),
            page_sha256=hashlib.sha256(page_text.encode()).hexdigest()))
        startup['next_page']+=1
        startup['records']+=len(records)
        startup['bytes']+=consumed
        if any(record['reset_pre']==1 or record['reset_post']==1 for record in records):
            startup['reset_observed']=True
        last=records[-1]
        startup['last_post']=deepcopy(last['sample']['post']['storage_probes'])
        startup['last_raw']=dict(namespace='startup',page_index=page_index,
            command_sequence=receipt.sequence,startup_edge_index=last['startup_edge_index'],
            sample_phase='post',execution=target._execution,target_epoch=target.reset_epoch,
            pid=None if target.process is None else target.process.pid)
        if startup['next_page']==startup['page_count']:
            startup['complete']=True
            startup['handoff']='awaiting_first_command'
        live['startup']=startup

    def _complete_ordinary_command(self,target,operation,fields,receipt,pending,live):
        startup=live.get('startup')
        rows=deepcopy(receipt.payload['samples'])
        for row in rows:row['local_tick']+=target._tick_base
        if startup is not None and startup['complete'] is True and startup['handoff']=='awaiting_first_command':
            if (live['state'] is not None or live['scope']!=(target.process,target._execution,target.reset_epoch,target._tick_base)
                    or pending[3]!=target._tick_base or receipt.tick_before!=0 or not rows):
                raise ValueError('storage-startup-handoff-shape')
            first_pre=rows[0].get('pre',{}).get('storage_probes')
            facts=_startup_helper_functions()['validate_startup_handoff'][0](
                startup['last_post'],first_pre,operation=operation,fields=fields,
                reset_observed=startup['reset_observed'])
            startup=deepcopy(startup)
            startup['handoff_facts']=dict(schema_version='apb_storage_startup_handoff.v1',
                facts=facts,last_startup=deepcopy(startup['last_raw']),
                first_command_sequence=receipt.sequence,first_command_tick=receipt.tick_before,
                readback_not_storage=True,grants_reset_prerequisite=False)
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
        live['writes'].extend(writes);live['samples']+=len(rows);state['sequence']=receipt.sequence
        live['state']=state
        if startup is not None:
            if startup['handoff']=='awaiting_first_command':startup['handoff']='done'
            live['startup']=startup

    def issue(self,*,register='TIMER0_CTRL',reset_epoch):
        from myfuzz.local_harness.session import _NATIVE_RESET_CHECK_PRODUCERS, _STORAGE_VERSION_LOOKUP_PINS, _NATIVE_RESET_OWNER_GUARD_PIN
        _NATIVE_RESET_OWNER_GUARD_PIN[0](self.target)
        _NATIVE_RESET_CHECK_PRODUCERS[0](self.target)
        if _STORAGE_VERSION_LOOKUP_PINS['_storage_version_authority'][0](self.target) is not self:
            raise ValueError('storage-version-independent-entry-origin-required')
        try:
            self._validate(native=True);t=self.target;live=_LIVE[self];state=live['state']
            if (self._startup_required() and (live['startup'] is None
                    or live['startup']['complete'] is not True
                    or live['startup']['handoff']!='done')):
                raise ValueError('storage-startup-handoff-incomplete')
            _SCOPE_VALIDATOR[0](state,live['scope'],process=t.process,execution=t._execution,epoch=t.reset_epoch,
                tick_base=t._tick_base,sequence=t._sequence,tick=t.local_ticks)
            if (register!='TIMER0_CTRL' or type(reset_epoch) is not int or reset_epoch!=t.reset_epoch
                    or state is None or live['pending'] is not None or live['scope']!=(t.process,t._execution,t.reset_epoch,t._tick_base)
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
            if (self._startup_required() and (live['startup'] is None
                    or live['startup']['complete'] is not True
                    or live['startup']['handoff']!='done')):
                raise ValueError('storage-startup-handoff-incomplete')
            _SCOPE_VALIDATOR[0](state,live['scope'],process=t.process,execution=t._execution,epoch=t.reset_epoch,
                tick_base=t._tick_base,sequence=t._sequence,tick=t.local_ticks)
            if (state is None or live['pending'] is not None or live['scope']!=(t.process,t._execution,t.reset_epoch,t._tick_base)
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
