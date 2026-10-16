"""Runner-owned private native lifecycle/command facts; exports grant no authority."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import inspect
from weakref import WeakKeyDictionary
from types import MappingProxyType
from myfuzz.local_harness.native_reset_observation import NativeResetObservation, NativeResetPrivateState, _json
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from .memory import PersistentMemory
from .memory_service import MemoryService
from .ledger import TransactionLedger
from .router import DataflowRouter

_CACHE = WeakKeyDictionary()
_CPU_STATES = WeakKeyDictionary()
_ATTEMPTS = WeakKeyDictionary()
_QUALIFICATIONS = WeakKeyDictionary()
_CONTENTS = WeakKeyDictionary()
_MODULE = sys.modules[__name__]


def _natural(value):return type(value) is int and value>=0


def _revision(records,attempts,journal_length):
    """Content-derived revision of everything the committed-prefix re-derivation reads.

    Folded in are, for every committed fact, its target, fact ordinal, journal event id, kind,
    canonical fact document and the exact expected decorated event text; plus every retained
    failed-attempt row; plus the live journal length.  Those are precisely the inputs the
    committed-prefix reconstruction consumes, and every one of them is committed, private,
    unexported state.

    The value is used **only** as a change indicator.  It is content-derived rather than a count: an
    in-place mutation of an already-cached fact record -- its document, its event id, its expected
    text -- or an appended journal event changes it even where no counter of its own moves.  A
    mismatch always re-enters the reconstruction; a match can only ever skip work whose committed
    inputs are provably identical, which the previous reconstruction established.  It replaces no
    guard, and it does not gate the live journal tie, which still runs on every call.
    """
    digest=hashlib.sha256()
    digest.update(str(journal_length).encode());digest.update(b'\x00')
    for name,token,ordinal,kind,encoded,event_id,expected in records:
        digest.update(name.encode());digest.update(b'\x00')
        digest.update(str(ordinal).encode());digest.update(b'\x00')
        digest.update(str(event_id).encode());digest.update(b'\x00')
        digest.update(kind.encode());digest.update(b'\x00')
        digest.update(encoded.encode());digest.update(b'\x00')
        digest.update(expected.encode());digest.update(b'\x00')
    for name,token,ordinal,kind,encoded,event_id,expected,present in attempts:
        digest.update(name.encode());digest.update(b'\x00')
        digest.update(str(ordinal).encode());digest.update(b'\x00')
        digest.update(str(event_id).encode());digest.update(b'\x00')
        digest.update(kind.encode());digest.update(b'\x00')
        digest.update(encoded.encode());digest.update(b'\x00')
        digest.update(expected.encode());digest.update(b'\x00')
        digest.update(b'1' if present else b'0')
    return digest.hexdigest()


class NativeResetEvidence:
    def __init__(self, runner, *, max_records=256, max_commands=4096):
        from .runner import ScenarioRunner
        if (type(runner) is not ScenarioRunner or runner._status!='created' or runner._events
                or any(type(n) is not int or not 1<=n<=65536 for n in (max_records,max_commands))):
            raise ValueError('native reset evidence requires fresh actual Runner')
        self.runner=runner;self._limits=(max_records,max_commands)
        self._targets={};self._bindings=[];self._status='complete';self._reason=None
        self._cursor={};self._chain={};self._state={};self._commands={};self._lifecycle={}
        self._intervals={};self._cache=();self._barrier=None;self._begun=False
        self._semantic_pin=None
        self._consumption_failed=False
        self._attempts=()
        self._native_qualifications=()
        self._provenance=runner._provenance
        for name,target in runner.sessions.items():
            observer=getattr(target,'_native_reset_observation',None)
            if type(target) is GeneratedPulpGpioSession:
                if type(observer) is not NativeResetObservation:raise ValueError('all native targets require actual reset observers')
                observer.validate()
                cfg=observer.configuration()
                if observer._issuer is not None or cfg['target_instance']!=name or cfg['max_commands']>max_commands:
                    raise ValueError('native reset observer issuer or command capacity mismatch')
                self._targets[name]=(target,observer,_json(cfg))
                self._cursor[name]=0;self._chain[name]='0'*64;self._commands[name]={};self._intervals[name]=()
        for name,cpu in runner.sessions.items():
            if type(cpu) is not GeneratedCve2Session:continue
            router=cpu.router;service=cpu.service;memory=cpu.memory
            if (type(router) is not DataflowRouter or type(service) is not MemoryService
                    or type(service.ledger) is not TransactionLedger or type(memory) is not PersistentMemory
                    or service.memory is not memory):raise ValueError('native reset actual CPU memory/router binding required')
            for window in router.windows:
                if window.device_id in self._targets:
                    if window.target is not self._targets[window.device_id][0]:raise ValueError('native reset foreign window target')
                    self._bindings.append((name,cpu,router,window,service,service.ledger,memory,
                        tuple(router.windows),service.ledger._entries,router._ordinary_delivery_confirmations))
        if not self._targets or any(not any(b[3].device_id==n for b in self._bindings) for n in self._targets):
            raise ValueError('native reset actual routed targets required')
        self._sessions=runner.sessions;self._session_pins=dict(runner.sessions)
        self._event_log=runner._events
        self._ordinary=runner._ordinary_apb_access_evidence
        self._authority=runner._memory_commit_authority
        from . import runner as runner_module
        accessor,code=runner_module._NATIVE_RESET_RUNNER_TABLE_ACCESSOR
        if runner_module._native_reset_runner_method_table is not accessor or accessor.__code__ is not code:
            raise ValueError('native reset Runner method table drift')
        table=accessor()
        self._runner_method_table=table
        self._runner_table_accessor=(accessor,code)
        self._runner_methods={}
        for name,(method,code) in table.items():
            bound=method.__get__(runner,ScenarioRunner)
            if (getattr(ScenarioRunner,name) is not method or method.__code__ is not code
                    or getattr(runner,name)!=bound):
                raise ValueError('native reset Runner method drift:'+name)
            self._runner_methods[name]=(method,code,bound)
        modules=[_MODULE,runner_module]
        for name in ('myfuzz.local_harness.native_reset_observation','myfuzz.local_harness.session',
            'myfuzz.local_harness.gpio_session','myfuzz.local_harness.cpu_session','myfuzz.local_harness.build',
            'myfuzz.scenario.router','myfuzz.scenario.ledger','myfuzz.scenario.memory','myfuzz.scenario.memory_service',
            'myfuzz.scenario.memory_commit_authority'):
            modules.append(sys.modules[name])
        self._sources={str(Path(m.__file__).resolve()):hashlib.sha256(Path(m.__file__).read_bytes()).hexdigest() for m in modules}
        self._configuration=dict(schema_version='native_reset_evidence_configuration.v1',capacity_scope='per_target',
            target_count=len(self._targets),max_records=max_records,max_commands=max_commands,
            targets={n:dict(observer=json.loads(t[2]),fact_storage_bound=2*t[1]._limits[0]+2*t[1]._limits[1]+1)
                     for n,t in self._targets.items()},source_files=dict(self._sources),
            proof_scope='actual_private_lifecycle_command_and_runner_domain_binding',grants_storage=False,
            grants_version_dependency=False,grants_prerequisites=False,grants_functional=False)
        self._config_json=_json(self._configuration)
        _CACHE[self]=()
        _CPU_STATES[self]={}
        _ATTEMPTS[self]=()
        _QUALIFICATIONS[self]=()
        _CONTENTS[self]=None
        self._registries=(_CACHE,_CPU_STATES,_ATTEMPTS,_QUALIFICATIONS,_CONTENTS)
        self._method_table=_METHODS
        self._target_pins=tuple(self._targets.items())
        self._binding_pins=tuple(self._bindings)
        self._helper_pins=tuple((name,f,f.__code__) for name,f in (("_json",_json),("_natural",_natural)))
        self._read_pin=(Path.read_bytes,Path.read_bytes.__code__)
        self._hash_pin=hashlib.sha256
        self._dispatch_pins={n:(getattr(runner_module,n),getattr(runner_module,n).__code__)
                             for n in ('guard_native_reset_evidence','guard_register_program_verifier')}
        self._dispatch_module=runner_module

    def _attach(self):
        if self.runner._native_reset_evidence is not self:raise ValueError('native reset actual install binding required')
        # All target/static preflight above completed before any irreversible issuer registration.
        try:
            for target,observer,_ in self._targets.values():observer._register_private_issuer(self,runner=self.runner)
            for name,(_,observer,_) in self._targets.items():self._state[name]=observer._private_state(issuer=self)
            self.validate()
        except BaseException:
            self._fail('failed_install');self.runner._native_reset_evidence_failed_install=True
            raise

    def _fail(self, reason):
        if self._status=='complete':self._status='incomplete';self._reason=str(reason)

    def validate(self, *, allow_incomplete=False):
        try:
            return self._validate(allow_incomplete=allow_incomplete)
        except BaseException:
            self._fail('validation_or_source_drift')
            raise

    def _validate(self, *, allow_incomplete=False):
        from .runner import ScenarioRunner
        if type(allow_incomplete) is not bool:raise ValueError('native reset invalid export policy')
        if (type(self) is not _TYPE or sys.modules.get(__name__) is not _MODULE or _MODULE.NativeResetEvidence is not _TYPE
                or self.runner._native_reset_evidence is not self or type(self.runner) is not ScenarioRunner
                or self.runner.sessions is not self._sessions or self.runner._events is not self._event_log
                or self.runner._ordinary_apb_access_evidence is not self._ordinary
                or self.runner._memory_commit_authority is not self._authority
                or self.runner._provenance is not self._provenance
                or any(actual is not pinned for actual,pinned in zip((_CACHE,_CPU_STATES,_ATTEMPTS,_QUALIFICATIONS,_CONTENTS),self._registries))
                or self._attempts is not _ATTEMPTS.get(self)
                or self._native_qualifications is not _QUALIFICATIONS.get(self)
                or (_CONTENTS.get(self) is not None and type(_CONTENTS.get(self)) is not tuple)
                or self._method_table is not _METHODS
                or tuple(self._targets.items())!=self._target_pins
                or tuple(self._bindings)!=self._binding_pins
                or self._limits!=(self._configuration['max_records'],self._configuration['max_commands'])
                or any(globals()[name] is not f or f.__code__ is not code for name,f,code in self._helper_pins)
                or self._cache is not _CACHE.get(self) or _json(self._configuration)!=self._config_json):
            raise ValueError('native reset consumer ownership drift')
        accessor,accessor_code=self._runner_table_accessor
        if (self._dispatch_module._native_reset_runner_method_table is not accessor
                or accessor.__code__ is not accessor_code
                or accessor() is not self._runner_method_table):
            raise ValueError('native reset Runner method table drift')
        for name,(method,code,bound) in self._runner_methods.items():
            if getattr(ScenarioRunner,name) is not method or method.__code__ is not code or getattr(self.runner,name)!=bound:
                raise ValueError('native reset Runner method drift:'+name)
        for name,(method,code) in _METHODS.items():
            if name in vars(self) or getattr(_TYPE,name) is not method or method.__code__ is not code:
                raise ValueError('native reset consumer method drift:'+name)
        if any(self.runner.sessions.get(n) is not t for n,t in self._session_pins.items()):
            raise ValueError('native reset session map drift')
        if (Path.read_bytes is not self._read_pin[0] or Path.read_bytes.__code__ is not self._read_pin[1]
                or hashlib.sha256 is not self._hash_pin):raise ValueError("native reset source reader drift")
        for name,(function,code) in self._dispatch_pins.items():
            if getattr(self._dispatch_module,name) is not function or function.__code__ is not code:
                raise ValueError("native reset fixed Runner guard drift")
        for path,digest in self._sources.items():
            if hashlib.sha256(Path(path).read_bytes()).hexdigest()!=digest:raise ValueError('native reset source drift')
        for name,(target,observer,config) in self._targets.items():
            if target._native_reset_observation is not observer or observer._owner is not target or type(observer) is not NativeResetObservation:
                raise ValueError('native reset observer binding drift')
            observer.validate(allow_incomplete=allow_incomplete)
            if _json(observer.configuration())!=config:raise ValueError('native reset observer config drift')
            state=observer._private_state(issuer=self)
            if (type(state) is not NativeResetPrivateState or not all(_natural(v) for v in
                    (state.fact_cursor,state.command_cursor,state.lifecycle_count,state.logical_process,state.target_epoch))
                    or state.fact_cursor<self._cursor[name]):raise ValueError('native reset private cursor drift')
            old=self._state.get(name)
            if old is not None and (state.issuer_token is not old.issuer_token or state.registry_token is not old.registry_token):
                raise ValueError('native reset private registry drift')
            if state.status=='incomplete':self._fail('target_incomplete:'+name)
            life=self._lifecycle.get(name)
            if life is not None and life['native_eligible']:
                if not self._native_build_qualified(name,life):
                    raise ValueError('native reset current native build qualification drift')
        for source,cpu,router,window,service,ledger,memory,windows,entries,confirmations in self._bindings:
            if not all(_natural(v) for v in (cpu.reset_epoch,memory.generation,self.runner.command_epoch)):
                raise ValueError("native reset invalid independent domain")
            if (cpu.router is not router or cpu.service is not service or cpu.memory is not memory
                    or service.memory is not memory or service.ledger is not ledger or ledger._entries is not entries
                    or tuple(router.windows)!=windows or not any(w is window for w in router.windows)
                    or window.target is not self._targets[window.device_id][0]
                    or router._ordinary_delivery_confirmations is not confirmations):raise ValueError('native reset CPU route/memory drift')
        # Independent actual CPU execution bindings remain private; logical ordinals alone export.
        cpu_states=_CPU_STATES[self]
        for source,cpu,*_ in self._bindings:
            process=cpu._process;execution=cpu._execution;old=cpu_states.get(source)
            if old is None:
                if process is not None:cpu_states[source]=(cpu,process,execution,1,cpu.reset_epoch)
                continue
            if not _natural(cpu.reset_epoch) or not _natural(self.runner.command_epoch):
                raise ValueError("native reset invalid CPU/Runner domain")
            owner,previous,nonce,ordinal,epoch=old
            if cpu is not owner:raise ValueError('native reset CPU process owner drift')
            if process is previous and execution==nonce:
                if cpu.reset_epoch!=epoch:raise ValueError('native reset CPU process epoch drift')
                continue
            if process is None and previous.poll() is not None and execution==nonce:
                continue  # Closed process remains pinned historical comparison evidence.
            if (self._barrier is not None and previous.poll() is not None and process is not None
                    and process is not previous and execution!=nonce and cpu.reset_epoch==epoch+1):
                cpu_states[source]=(cpu,process,execution,ordinal+1,cpu.reset_epoch)
            else:raise ValueError('native reset CPU process/execution drift')
        if self._ordinary is not None:
            self._ordinary.validate(allow_incomplete=allow_incomplete)
            if self._ordinary._status=="incomplete":self._fail("ordinary_callback_or_delivery_incomplete")
        # The committed-prefix reconstruction below is re-derived only when its committed inputs
        # actually changed.  `_revision` folds those inputs themselves -- for every cached fact the
        # target, ordinal, journal event id, kind, canonical fact document and exact expected
        # decorated event text, plus the retained failed-attempt rows and the journal length -- so
        # the indicator is content-derived, not a count: mutating an already-cached record in place
        # changes it even though no counter moves, and so does an appended event.  A match is
        # therefore only ever a skip of reconstruction whose committed inputs are provably
        # identical, and the stored projections are still compared against the live ones below.
        # The live journal tie is never gated by this value.
        registries=_CONTENTS.get(self)
        if registries is None:
            revision=None
        elif type(registries) is not tuple or len(registries)!=6 or _CONTENTS.get(self) is not registries:
            raise ValueError('native reset consumer ownership drift')
        else:
            revision=registries[0]
            if type(revision) is not str or len(revision)!=64:
                raise ValueError('native reset committed index drift')
        if registries is None or _revision(self._cache,self._attempts,len(self.runner._events))!=revision:
            cursors={n:0 for n in self._targets};chains={n:'0'*64 for n in self._targets}
            commands={n:{} for n in self._targets};lifecycles={}
            for n,token,o,k,d,e,expected in self._cache:
                if o!=cursors[n]+1:raise ValueError('native reset committed prefix discontinuity')
                cursors[n]=o;chains[n]=hashlib.sha256((chains[n]+k+d).encode()).hexdigest()
                if k.startswith('command_'):
                    document=json.loads(d);commands[n][document['command_ordinal']]=document
                if k=='lifecycle':lifecycles[n]=json.loads(d)
            if (_json(self._cursor)!=_json(cursors) or self._chain!=chains or _json(self._commands)!=_json(commands)
                    or _json(self._lifecycle)!=_json(lifecycles)):raise ValueError('native reset private committed index drift')
            _CONTENTS[self]=(_revision(self._cache,self._attempts,len(self.runner._events)),dict(cursors),dict(chains),
                             {n:dict(rows) for n,rows in commands.items()},dict(lifecycles),self._attempts)
        elif (_json(self._cursor)!=_json(registries[1]) or self._chain!=registries[2]
                or _json(self._commands)!=_json(registries[3]) or _json(self._lifecycle)!=_json(registries[4])):
            # The committed inputs are provably unchanged, so the stored projections must still be
            # exact; a divergence here is an in-place mutation of the live indices themselves.
            raise ValueError('native reset private committed index drift')
        # Journal ties are never gated by the revision: a live record mutated in place must still be
        # caught even when every committed input is byte-identical to the previous call.
        for name,token,ordinal,kind,encoded,event_id,expected,present in self._attempts:
            actual=self.runner._event_ref_by_id(event_id)
            if present and (actual is None or _json(actual)!=expected):
                raise ValueError("native reset failed attempt journal drift")
        for name,token,ordinal,kind,encoded,event_id,expected in self._cache:
            actual=self.runner._event_ref_by_id(event_id)
            if actual is None or _json(actual)!=expected:raise ValueError('native reset actual journal ref drift')
        if not allow_incomplete and self._status!='complete':raise ValueError('native reset evidence incomplete:'+str(self._reason))

    def _native_build_qualified(self,name,life):
        # One native build qualification per (target, committed lifecycle ordinal, recorded build
        # digest). Both key elements are committed lifecycle facts and can only change by
        # committing a new lifecycle for that target, so a stale, poisoned or mismatched entry is
        # never inherited across a lifecycle change and the boundary check still refuses on drift.
        # The memo is private object-owned state: never exported, never settable by a caller and
        # never restorable from a saved document.
        ordinal=life['lifecycle_ordinal'];recorded=life['build_inputs_sha256']
        if type(ordinal) is not int or ordinal<1 or type(recorded) is not str or len(recorded)!=64:
            raise ValueError('native reset invalid committed lifecycle qualification key')
        key=(name,ordinal,recorded)
        if key in self._native_qualifications:return True
        from myfuzz.local_harness.session import _NATIVE_RESET_NATIVE_ELIGIBLE
        eligible,digest=_NATIVE_RESET_NATIVE_ELIGIBLE[0](self._targets[name][0])
        remaining=tuple(entry for entry in self._native_qualifications if entry[0]!=name)
        if type(eligible) is not bool or not eligible or type(digest) is not str or digest!=recorded:
            self._native_qualifications=remaining;_QUALIFICATIONS[self]=remaining
            return False
        self._native_qualifications=(*remaining,key);_QUALIFICATIONS[self]=self._native_qualifications
        return True

    def configuration(self):
        self.validate(allow_incomplete=True);return json.loads(self._config_json)

    def _domains(self,name):
        b=next(b for b in self._bindings if b[3].device_id==name)
        source,cpu,_,_,service,_,memory,*_=b
        return dict(cpu_component=source,cpu_source_epoch=cpu.reset_epoch,
            cpu_logical_process=_CPU_STATES[self].get(source,(None,None,None,0,None))[3],
            runner_command_epoch=self.runner.command_epoch,
            memory_generation=memory.generation,memory_ids=list(memory.memory_ids))

    def _preflight_command(self, *, new_operation=False):
        self.validate()
        if type(new_operation) is not bool:raise ValueError('native reset invalid admission policy')
        if self._barrier is None and self._begun:
            for name,(target,_,_) in self._targets.items():
                previous=self._lifecycle.get(name)
                if previous is not None and target.reset_epoch!=previous['target_epoch']:
                    self._fail('unrecorded_target_reset');raise ValueError('native reset target epoch changed outside actual barrier')
        if new_operation and self.runner._register_reset_default_verifier is not None:
            self.runner._register_reset_default_verifier._preflight_command(new_operation=True)

    def _drain(self):
        self.validate(allow_incomplete=True)
        if self._consumption_failed:return
        attempt=None
        try:
            for name,(_,observer,_) in self._targets.items():
                tokens,next_cursor=observer._private_facts_since(self._cursor[name],issuer=self)
                if type(tokens) is not tuple or not _natural(next_cursor) or next_cursor!=self._cursor[name]+len(tokens):
                    raise ValueError('native reset discontinuous fact cursor')
                bound=self._configuration['targets'][name]['fact_storage_bound']
                if next_cursor>bound:raise ValueError('native reset fact storage bound exceeded')
                for token in tokens:
                    self.runner._ensure_semantic_capacity('native_reset_private_fact')
                    fact=observer._resolve_fact(token,issuer=self);ordinal=fact['fact_ordinal']
                    if ordinal!=self._cursor[name]+1:raise ValueError('native reset fact ordinal gap')
                    kind=fact['kind'];doc=fact['document'];encoded=_json(doc)
                    if kind not in ('lifecycle','process_close','command_pending','command_parsed','command_failed','failure'):
                        raise ValueError('native reset unknown private fact')
                    if kind=='lifecycle' and doc.get('kind')=='explicit_reset' and self._barrier is None:
                        self._fail('explicit_target_reset_outside_global_barrier:'+name)
                    if kind.startswith('command_'):
                        command=doc['command_ordinal'];previous=self._commands[name].get(command)
                        if not _natural(command) or command<1 or command>self._limits[1]:raise ValueError('native reset command ordinal')
                        if kind=='command_pending':
                            if previous is not None or command!=len(self._commands[name])+1:raise ValueError('native reset duplicate pending command')
                        elif previous is None or previous['status']!='pending' or any(doc[k]!=previous[k] for k in
                            ('logical_process','target_epoch','command_sequence','operation','fields')):
                            raise ValueError('native reset command completion without exact reservation')
                    event=dict(kind='native_reset_private_fact',schema_version='native_reset_private_fact.v1',
                        event_id=len(self.runner._events)+1,target_instance=name,fact_kind=kind,fact_ordinal=ordinal,
                        document=deepcopy(doc),grants_storage=False,grants_version_dependency=False,
                        grants_prerequisites=False,grants_functional=False)
                    expected=_json(self.runner._decorate_provenance(deepcopy(event)))
                    attempt=(name,token,ordinal,kind,encoded,event["event_id"],expected)
                    self.runner._events.append(event)
                    actual=self.runner._event_ref_by_id(event['event_id'])
                    if actual is None or _json(actual)!=expected:
                        raise ValueError('native reset journal append content mismatch')
                    observer.validate(allow_incomplete=True)
                    entry=(name,token,ordinal,kind,encoded,event['event_id'],expected)
                    self._cache=(*self._cache,entry);_CACHE[self]=self._cache
                    self._chain[name]=hashlib.sha256((self._chain[name]+kind+encoded).encode()).hexdigest()
                    self._cursor[name]=ordinal
                    attempt=None
                    if kind.startswith('command_'):self._commands[name][doc['command_ordinal']]=deepcopy(doc)
                    if kind=='lifecycle':
                        # Committing a lifecycle never lets a previous qualification survive.
                        self._lifecycle[name]=deepcopy(doc)
                        self._native_qualifications=tuple(entry for entry in self._native_qualifications if entry[0]!=name)
                        _QUALIFICATIONS[self]=self._native_qualifications
                    if kind in ('command_failed','failure'):self._fail('provider_failure:'+name)
                state=observer._private_state(issuer=self)
                if state.fact_cursor!=next_cursor or state.chain_sha256!=self._chain[name]:raise ValueError('native reset chain or cursor drift')
                self._state[name]=state
            self.validate(allow_incomplete=True)
        except BaseException:
            if attempt is not None:
                present=self.runner._event_ref_by_id(attempt[5]) is not None
                self._attempts=(*self._attempts,(*attempt,present));_ATTEMPTS[self]=self._attempts
            self._consumption_failed=True
            self._fail('fact_consumption_or_append_failed');raise

    def _require_runner_hook(self,name):
        method,code,_=self._runner_methods[name]
        frame=inspect.currentframe().f_back.f_back
        if frame.f_code is not code or frame.f_locals.get("self") is not self.runner:
            raise ValueError("native reset requires actual Runner lifecycle hook")

    def _reserve_capacity(self,new_facts=0):
        self.validate()
        if not _natural(new_facts):raise ValueError("native reset invalid fact reservation")
        pending=sum(obs._private_state(issuer=self).fact_cursor-self._cursor[name]
                    for name,(_,obs,_) in self._targets.items())
        budget=self.runner._resource_budget
        if budget is not None and len(self.runner._events)+pending+new_facts>=budget.max_semantic_records-1:
            self.runner._exhaust_budget("max_semantic_records","before_native_reset_fact_effect")

    def _before_reset(self,policy):
        self._require_runner_hook("reset_all")
        self._reserve_capacity(2*len(self._targets)+1)
        self._preflight_command();self._drain()
        if self._barrier is not None:raise ValueError('native reset overlapping global reset')
        for name,(_,observer,_) in self._targets.items():
            if len(self._intervals[name])>=self._limits[0] or observer._private_state(issuer=self).lifecycle_count>=observer._limits[0]:
                raise ValueError('native reset interval/lifecycle capacity exceeded')
            if any(c['status']=='pending' for c in self._commands[name].values()):raise ValueError('native reset pending command at barrier')
        self._barrier=(policy,self.runner.command_epoch,{n:self._domains(n) for n in self._targets},
            {n:dict(self._lifecycle.get(n,{})) for n in self._targets})

    def _after_barrier(self,event_id):
        try:
            self._require_runner_hook("reset_all")
            self._drain()
            event=self.runner._event_ref_by_id(event_id)
            if self._barrier is None or event is None or event.get('kind')!='reset_barrier':raise ValueError('native reset actual global barrier required')
            policy,epoch,domains,previous=self._barrier
            if event['policy']!=policy or self.runner.command_epoch!=epoch+1:raise ValueError('native reset global barrier epoch mismatch')
            for name in self._targets:
                life=self._lifecycle[name];new=self._domains(name);old=previous[name]
                if (life['kind']!='explicit_reset' or life['target_epoch']!=old.get('target_epoch',-1)+1
                        or life['logical_process']!=old.get('logical_process',-1)+1 or not life['process_exit_confirmed']
                        or new['cpu_source_epoch']!=domains[name]['cpu_source_epoch']+1
                        or new['cpu_logical_process']!=domains[name]['cpu_logical_process']+1
                        or new['memory_generation']!=domains[name]['memory_generation']+int(policy=='cold_all')):
                    raise ValueError('native reset independent domain transition mismatch')
                self._add_interval(name,event_id,new)
            self._barrier=None;self.validate()
        except BaseException:
            self._fail("post_lifecycle_binding_failed")
            self.runner._status="failed"
            self.runner.failure_status="environment_error"
            raise

    def _after_begin(self):
        try:
            self._require_runner_hook("begin_test")
            self._drain();self._begun=True
            for name in self._targets:self._add_interval(name,None,self._domains(name))
        except BaseException:
            self._fail("post_lifecycle_binding_failed")
            self.runner._status="failed"
            self.runner.failure_status="environment_error"
            raise

    def _add_interval(self,name,barrier_id,domains):
        life=self._lifecycle[name]
        if len(self._intervals[name])>=self._limits[0]:raise ValueError('native reset interval capacity exceeded')
        record=dict(schema_version='native_reset_interval.v1',target_instance=name,target_epoch=life['target_epoch'],
            logical_process=life['logical_process'],reset_barrier_event_id=barrier_id,native_eligible=life['native_eligible'],
            lifecycle=deepcopy(life),**domains,grants_storage=False,grants_version_dependency=False,
            grants_prerequisites=False,grants_functional=False)
        self._intervals[name]=(*self._intervals[name],_json(record))

    def _operation_failed(self,reason):
        self._fail(reason)
        try:self._drain()
        except BaseException:pass

    def completed_intervals(self):
        self.validate();self._drain()
        result=[]
        for name,rows in self._intervals.items():
            for encoded in rows:
                row=json.loads(encoded)
                commands=[deepcopy(c) for c in self._commands[name].values() if c['logical_process']==row['logical_process']]
                if row['native_eligible'] and all(c['status']=='parsed_complete' for c in commands):
                    row['commands']=commands;result.append(row)
        return tuple(result)

    def snapshot(self):
        self.validate(allow_incomplete=True);self._drain()
        return dict(schema_version='native_reset_evidence_state.v1',configuration=json.loads(self._config_json),
            status=self._status,reason=self._reason,intervals=[json.loads(r) for rows in self._intervals.values() for r in rows],
            facts=[dict(target_instance=n,fact_ordinal=o,kind=k,document=json.loads(d),event_id=e)
                   for n,token,o,k,d,e,expected in self._cache],
            failed_attempts=[dict(target_instance=n,fact_ordinal=o,kind=k,document=json.loads(d),
                actual_event_id=e if present else None,committed=False)
                for n,token,o,k,d,e,expected,present in self._attempts],
            counts=dict(facts=len(self._cache),commands=sum(len(c) for c in self._commands.values()),
                        intervals=sum(len(r) for r in self._intervals.values())))

_TYPE=NativeResetEvidence
_METHODS=MappingProxyType({n:(m,m.__code__) for n,m in vars(_TYPE).items() if callable(m) and hasattr(m,'__code__')})

# These references are captured when this code-owned module loads, never at installation.
_IMPORT_REGISTRIES=(_CACHE,_CPU_STATES,_ATTEMPTS,_QUALIFICATIONS,_CONTENTS)
_IMPORT_HELPERS=MappingProxyType({name:(function,function.__code__) for name,function in
                               (('_json',_json),('_natural',_natural))})
_IMPORT_READER=(Path.read_bytes,Path.read_bytes.__code__)
_IMPORT_HASH=hashlib.sha256

def _check_import_time_baselines(_registries=_IMPORT_REGISTRIES,_helpers=_IMPORT_HELPERS,
                                 _reader=_IMPORT_READER,_hash=_IMPORT_HASH,
                                 _methods=_METHODS,_type=_TYPE,_module=_MODULE,
                                 _frame=(inspect.currentframe,inspect.currentframe.__code__,sys._getframe,inspect.sys)):
    if (_METHODS is not _methods or _TYPE is not _type or NativeResetEvidence is not _type
            or _MODULE is not _module or sys.modules.get(__name__) is not _module
            or inspect.currentframe is not _frame[0] or inspect.currentframe.__code__ is not _frame[1]
            or sys._getframe is not _frame[2] or inspect.sys is not _frame[3]
            or any(actual is not pinned for actual,pinned in zip((_CACHE,_CPU_STATES,_ATTEMPTS,_QUALIFICATIONS,_CONTENTS),_registries))
            or _IMPORT_REGISTRIES is not _registries or _IMPORT_HELPERS is not _helpers
            or _IMPORT_READER is not _reader or _IMPORT_HASH is not _hash
            or Path.read_bytes is not _reader[0] or Path.read_bytes.__code__ is not _reader[1]
            or hashlib.sha256 is not _hash
            or any(globals()[name] is not function or function.__code__ is not code
                   for name,(function,code) in _helpers.items())):
        raise ValueError('native reset consumer ownership drift: import-time implementation baseline')

_IMPORT_CHECK=(_check_import_time_baselines,_check_import_time_baselines.__code__)


def _seal_import_baseline_guard():
    # A closure retains the original table/defaults independently of mutable module aliases.
    table=_IMPORT_CHECK
    checker,code=table
    defaults=checker.__defaults__
    methods=_METHODS
    cls=_TYPE
    from myfuzz.local_harness import session as producer_module
    producer_table=producer_module._NATIVE_RESET_CHECK_PRODUCERS
    producer,producer_code=producer_table
    def guard():
        if (producer_module._NATIVE_RESET_CHECK_PRODUCERS is not producer_table
                or producer_module._native_reset_check_producers is not producer
                or producer.__code__ is not producer_code):
            raise ValueError('native reset Task1 producer baseline drift')
        if (_IMPORT_BASELINE_GUARD is not guard or _IMPORT_CHECK is not table or _check_import_time_baselines is not checker
                or checker.__code__ is not code or checker.__defaults__ is not defaults
                or _METHODS is not methods or _TYPE is not cls or NativeResetEvidence is not cls):
            raise ValueError('native reset consumer ownership drift: sealed import baseline')
        for name,(method,expected_code) in methods.items():
            if getattr(cls,name) is not method or method.__code__ is not expected_code:
                raise ValueError('native reset consumer method drift:'+name)
        checker(*defaults)
    return guard

def _bind_sealed_import_entries():
    # Both entry points retain a lexical reference; rebinding any module alias cannot bypass it.
    global _METHODS
    original_init=NativeResetEvidence.__init__
    original_validate=NativeResetEvidence._validate
    init_code=original_init.__code__
    validate_code=original_validate.__code__
    guard=None
    def initialize(self,runner,*,max_records=256,max_commands=4096):
        guard()
        if original_init.__code__ is not init_code:
            raise ValueError('native reset original initializer code drift')
        return original_init(self,runner,max_records=max_records,max_commands=max_commands)
    def validate(self,*,allow_incomplete=False):
        guard()
        if original_validate.__code__ is not validate_code:
            raise ValueError('native reset original validator code drift')
        return original_validate(self,allow_incomplete=allow_incomplete)
    NativeResetEvidence.__init__=initialize
    NativeResetEvidence._validate=validate
    _METHODS=MappingProxyType({n:(m,m.__code__) for n,m in vars(_TYPE).items()
                              if callable(m) and hasattr(m,'__code__')})
    # Finish the import-time baseline after the guarded entries have their final identities.
    defaults=list(_check_import_time_baselines.__defaults__)
    defaults[4]=_METHODS
    _check_import_time_baselines.__defaults__=tuple(defaults)
    guard=_seal_import_baseline_guard()
    return guard

_IMPORT_BASELINE_GUARD=_bind_sealed_import_entries()

# Publish the original completed module exactly once to Runner's independent closure anchor.
from .runner import _register_native_reset_import_anchor
_register_native_reset_import_anchor(_MODULE,_TYPE,_METHODS,_IMPORT_BASELINE_GUARD)
