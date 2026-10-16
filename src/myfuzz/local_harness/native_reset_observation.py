"""Actual generated lifecycle/command mechanics; READY is not a reset waveform.

Private issuer tokens authenticate live facts. Public JSON is comparison only.
"""
from dataclasses import asdict, dataclass
from types import MappingProxyType
import hashlib
import json
from pathlib import Path


def _json(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True)


def _uint(value):
    return type(value) is int and value >= 0


@dataclass(frozen=True)
class NativeResetPrivateState:
    issuer_token: object
    registry_token: object
    fact_cursor: int
    command_cursor: int
    lifecycle_count: int
    logical_process: int
    target_epoch: int
    process: object
    execution: str
    chain_sha256: str
    status: str
    reason: str | None


class NativeResetObservation:
    def __init__(self, owner, *, max_lifecycles=256, max_commands=4096):
        from .gpio_session import GeneratedPulpGpioSession
        from .session import _NATIVE_RESET_CHECK_PRODUCERS
        if (type(owner) is not GeneratedPulpGpioSession or owner._process is not None
                or owner._case_id is not None or owner._execution or owner.reset_epoch
                or owner._native_reset_observation is not None
                or type(max_lifecycles) is not int or not 1<=max_lifecycles<=65536
                or type(max_commands) is not int or not 1<=max_commands<=65536):
            raise ValueError('native reset observation requires fresh actual GPIO')
        _NATIVE_RESET_CHECK_PRODUCERS[0](owner)
        self._owner=owner
        self._limits=(max_lifecycles,max_commands)
        self._artifact=owner.artifact
        self._artifact_json=_json(owner._artifact_document)
        self._binary_binding=None if owner._binary is None else self._binary(owner._binary)
        self._status='complete';self._reason=None
        self._lifecycles=[];self._commands=[];self._facts=[];self._processes={}
        self._registry_pins=(self._lifecycles,self._commands,self._facts,self._processes)
        self._token_index={};self._token_index_pin=self._token_index
        self._chain_sha256='0'*64
        self._sealed_facts=();self._sealed_processes=();self._closed_processes=set()
        self._closed_processes_pin=self._closed_processes;self._sealed_closed=frozenset()
        self._pending_process=None
        self._registry_token_pin=None;self._issuer_token_pin=None
        self._consumed_sealed=frozenset()
        self._registry_token=object();self._issuer=None;self._issuer_pin=None;self._issuer_token=None;self._consumed=set()
        self._registry_token_pin=self._registry_token
        self._consumed_pin=self._consumed
        self._logical_process=0;self._pending=None;self._close_pending=None
        self._sources={str(Path(module.__file__).resolve()):hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
            for module in __import__('sys').modules.values() if module is not None
            and getattr(module,'__name__','') in ('myfuzz.local_harness.session','myfuzz.local_harness.gpio_session',
                'myfuzz.local_harness.native_reset_observation','myfuzz.local_harness.build','myfuzz.local_harness.wire')}
        self._configuration=dict(schema_version='native_reset_observation_configuration.v1',
            target_instance=owner._artifact_document['plan']['instance_id'],max_lifecycles=max_lifecycles,max_commands=max_commands,
            source_files=self._sources,artifact_sha256=hashlib.sha256(self._artifact_json.encode()).hexdigest(),
            proof_scope='actual_generated_driver_lifecycle_and_complete_command_coverage',
            grants_storage=False,grants_version_dependency=False,grants_prerequisites=False,grants_functional=False)

    @staticmethod
    def _binary(path):
        path=Path(path).resolve()
        return (path,hashlib.sha256(path.read_bytes()).hexdigest())

    def validate(self, *, allow_incomplete=False):
        try:
            return self._validate_impl(allow_incomplete=allow_incomplete)
        except BaseException:
            if self._status != 'incomplete':
                self._status='incomplete';self._reason='validation_drift_or_failure'
            raise

    def _validate_impl(self, *, allow_incomplete=False):
        from .session import _NATIVE_RESET_CHECK_PRODUCERS
        if type(allow_incomplete) is not bool:raise ValueError('invalid native reset export policy')
        if (self._owner._native_reset_observation is not self or self._owner.artifact is not self._artifact
                or _json(self._owner._artifact_document)!=self._artifact_json
                or any(actual is not pinned for actual,pinned in zip(
                    (self._lifecycles,self._commands,self._facts,self._processes),self._registry_pins))):
            self._fail('owner_or_registry_drift');raise ValueError('native reset owner or registry drift')
        _NATIVE_RESET_CHECK_PRODUCERS[0](self._owner)
        if (tuple(self._facts)!=self._sealed_facts or tuple(self._processes.items())!=self._sealed_processes
                or self._registry_token is not self._registry_token_pin
                or self._issuer_token is not self._issuer_token_pin
                or self._consumed is not self._consumed_pin or frozenset(self._consumed)!=self._consumed_sealed
                or self._issuer is not self._issuer_pin or self._token_index is not self._token_index_pin
                or self._closed_processes is not self._closed_processes_pin
                or frozenset(self._closed_processes)!=self._sealed_closed):
            raise ValueError('native reset sealed provenance drift')
        for process,execution,epoch in self._processes.values():
            if process not in self._closed_processes and process is not self._owner._process:
                raise ValueError('native reset unclosed process binding detached')
        if self._owner._process is not None and self._pending_process is None:
            expected=self._processes.get(self._logical_process)
            if expected is None or expected != (self._owner._process,self._owner._execution,self._owner.reset_epoch):
                raise ValueError('native reset current process binding drift')
            if self._owner._process.poll() is not None:
                self._fail('process_not_running')
        if any(hashlib.sha256(Path(path).read_bytes()).hexdigest()!=digest for path,digest in self._sources.items()):
            self._fail('source_drift');raise ValueError('native reset source drift')
        if self._binary_binding is not None and self._binary(self._owner._binary)!=self._binary_binding:
            self._fail('binary_drift');raise ValueError('native reset binary drift')
        if not allow_incomplete and self._status=='incomplete':raise ValueError('native reset observation incomplete:'+str(self._reason))

    def configuration(self):
        self.validate(allow_incomplete=True)
        return json.loads(_json(self._configuration))

    def lifecycles(self):
        self.validate(allow_incomplete=True);return tuple(json.loads(row) for row in self._lifecycles)

    def commands(self):
        self.validate(allow_incomplete=True);return tuple(json.loads(row) for row in self._commands)

    def snapshot(self):
        self.validate(allow_incomplete=True)
        return dict(schema_version='native_reset_observation_state.v1',configuration=self.configuration(),
            status=self._status,reason=self._reason,lifecycles=list(self.lifecycles()),commands=list(self.commands()),
            counts=dict(lifecycles=len(self._lifecycles),commands=len(self._commands),facts=len(self._facts),pending=int(self._pending is not None)))

    def _fact(self, kind, document, *, process=None, execution=None):
        from .session import _NATIVE_RESET_CHECK_PRODUCERS
        try:
            _NATIVE_RESET_CHECK_PRODUCERS[0](self._owner)
        except BaseException:
            self._status='incomplete';self._reason='producer_or_binding_drift'
            raise
        _actual_fact_origin(self)
        token=object()
        self._facts.append((token,kind,_json(document),process,execution))
        self._sealed_facts=tuple(self._facts)
        self._token_index[token]=(len(self._facts),self._facts[-1])
        self._chain_sha256=hashlib.sha256((self._chain_sha256+kind+self._facts[-1][2]).encode()).hexdigest()
        return token

    def _fail(self, reason):
        if self._status!='incomplete':
            self._status='incomplete';self._reason=reason
            self._fact('failure',dict(reason=reason,logical_process=self._logical_process))

    def _before_begin(self, owner):
        self.validate()
        if owner is not self._owner or len(self._lifecycles)>=self._limits[0]:
            raise ValueError('native reset lifecycle capacity exceeded')
        if self._pending is not None:self._fail('pending_command_at_begin');raise ValueError('native reset pending command')
        self._binary_binding=None if owner._binary is None else self._binary(owner._binary)

    def _before_reset(self, owner):
        self.validate()
        if owner is not self._owner or len(self._lifecycles)>=self._limits[0]:
            raise ValueError('native reset lifecycle capacity exceeded')
        if self._pending is not None:
            self._fail('pending_command_at_reset')
            raise ValueError('native reset pending command')

    def _prepared(self, owner):
        _actual_producer_frame(owner, 'prepare_local')
        if owner is not self._owner:raise ValueError('native reset foreign prepare')
        self._binary_binding=self._binary(owner._binary)

    def _launched(self, owner):
        _actual_producer_frame(owner, 'begin_case')
        self._pending_process=(owner._process,owner._execution,owner.reset_epoch,self._logical_process+1)
        self._processes[self._logical_process+1]=(owner._process,owner._execution,owner.reset_epoch)
        self._sealed_processes=tuple(self._processes.items())

    def _ready(self, owner, ready):
        _actual_producer_frame(owner, 'begin_case')
        self.validate()
        if self._pending_process != (owner._process,owner._execution,owner.reset_epoch,self._logical_process+1):
            self._fail('foreign_startup_process');raise ValueError('native reset startup binding mismatch')
        if owner is not self._owner or owner._process is None:raise ValueError('native reset foreign READY')
        self._logical_process+=1
        process=owner._process;execution=owner._execution
        self._processes[self._logical_process]=(process,execution,owner.reset_epoch)
        close=self._close_pending
        explicit=close is not None and owner.reset_epoch==close['target_epoch']+1
        case_begin=close is not None and owner.reset_epoch==close['target_epoch']
        if close is not None and not explicit and not case_begin:self._fail('reset_epoch_mismatch');raise ValueError('native reset epoch mismatch')
        from .session import _NATIVE_RESET_NATIVE_ELIGIBLE
        eligible,build_digest=_NATIVE_RESET_NATIVE_ELIGIBLE[0](owner)
        row=dict(schema_version='native_reset_lifecycle.v1',lifecycle_ordinal=len(self._lifecycles)+1,
            kind='explicit_reset' if explicit else 'case_begin' if case_begin else 'initial_begin',logical_process=self._logical_process,
            target_instance=self._configuration['target_instance'],target_epoch=owner.reset_epoch,
            previous_target_epoch=close['target_epoch'] if explicit else None,
            driver_identity=list(owner._expected_ready()),source_binding_sha256=hashlib.sha256(_json(self._sources).encode()).hexdigest(),
            build_inputs_sha256=build_digest,binary_sha256=self._binary_binding[1],native_eligible=eligible,
            reset_assert_ticks=ready.assert_ticks,reset_release_ticks=ready.release_ticks,
            process_exit_confirmed=bool(explicit and close['process_exit_confirmed']),ready_confirmed=True,
            first_command_sequence=1,proof_scope='source_bound_reset_execution_completion_not_raw_waveform',
            grants_storage=False,grants_version_dependency=False,grants_prerequisites=False,grants_functional=False)
        self._lifecycles.append(_json(row));self._fact('lifecycle',row,process=process,execution=execution)
        self._close_pending=None;self._pending_process=None

    def _begin_actual_command(self, owner, operation, fields):
        self.validate()
        _actual_producer_frame(owner, '_command_impl')
        if (owner is not self._owner or self._pending is not None
                or self._logical_process not in self._processes
                or self._processes[self._logical_process] != (owner._process,owner._execution,owner.reset_epoch)):
            raise ValueError('native reset foreign or pending command')
        if len(self._commands)>=self._limits[1]:raise ValueError('native reset command capacity exceeded')
        token=object()
        row=dict(schema_version='native_reset_command.v1',command_ordinal=len(self._commands)+1,
            logical_process=self._logical_process,target_epoch=owner.reset_epoch,command_sequence=owner._sequence+1,
            operation=operation,fields=list(fields),parsed_receipt_projection=None,status='pending',reason=None,
            coverage_cursor=len(self._commands)+1)
        self._pending=(token,row,owner._process,owner._execution,owner._tick_base,owner.local_ticks)
        self._commands.append(_json(row));self._fact('command_pending',row,process=owner._process,execution=owner._execution)
        return token

    def _complete_actual_command(self, owner, attempt, receipt):
        try:
            _actual_producer_frame(owner, '_command_impl')
        except BaseException:
            self._fail('foreign_command_completion');raise
        pending=self._pending
        if (owner is not self._owner or pending is None or attempt is not pending[0]
                or owner._process is not pending[2] or receipt.execution!=pending[3]
                or receipt.sequence!=pending[1]['command_sequence'] or owner.reset_epoch!=pending[1]['target_epoch']
                or owner._tick_base != pending[4] or owner.local_ticks != pending[5]
                or receipt.tick_before != pending[5]-pending[4]):
            self._fail('foreign_or_duplicate_completion');raise ValueError('native reset command completion mismatch')
        row=dict(pending[1]);projection=asdict(receipt);projection.pop('execution')
        row.update(status='parsed_complete',parsed_receipt_projection=projection)
        self._commands[-1]=_json(row);self._fact('command_parsed',row,process=pending[2],execution=pending[3]);self._pending=None
        if receipt.status!='result' or receipt.payload is None or receipt.payload.get('error'):
            self._fail('parsed_driver_error')
        self.validate(allow_incomplete=True)

    def _fail_actual_command(self, owner, attempt, reason):
        if owner is not self._owner:raise ValueError('native reset foreign command failure')
        if self._pending is not None and attempt is self._pending[0]:
            row=dict(self._pending[1]);row.update(status='failed',reason=reason)
            self._commands[-1]=_json(row);self._fact('command_failed',row,process=self._pending[2],execution=self._pending[3]);self._pending=None
        self._fail(reason)

    def _consumer_failed(self, owner, reason):
        if owner is not self._owner:raise ValueError('native reset foreign consumer failure')
        self._fail(reason)

    def _closed(self, owner, process, *, aborted=False):
        _actual_producer_frame(owner, '_abort' if aborted else 'end_case')
        if owner is not self._owner:raise ValueError('native reset foreign process close')
        known=next(((ordinal,binding) for ordinal,binding in self._processes.items()
            if binding[0] is process and binding[1]==owner._execution),None)
        if known is None:
            self._fail('unknown_process_close');raise ValueError('native reset unknown closing process')
        if aborted:
            self._fail_actual_command(owner,self._pending[0] if self._pending else None,'transport_aborted')
        try:
            confirmed=process.poll() is not None
        except BaseException:
            confirmed=False
            self._fail('process_exit_unconfirmed')
        row=dict(logical_process=known[0],target_epoch=known[1][2],process_exit_confirmed=confirmed,aborted=aborted)
        self._fact('process_close',row,process=process,execution=owner._execution)
        self._closed_processes.add(process)
        self._sealed_closed=frozenset(self._closed_processes)
        self._pending_process=None
        self._close_pending=row
        if not confirmed:self._fail('process_exit_unconfirmed')

    def _register_private_issuer(self, issuer, *, runner):
        if getattr(issuer, 'runner', None) is not runner:
            raise ValueError('native reset foreign issuer')
        try:
            from myfuzz.scenario.native_reset_evidence import NativeResetEvidence
        except ImportError as error:
            raise ValueError('native reset issuer implementation unavailable') from error
        from myfuzz.scenario.runner import ScenarioRunner
        self.validate()
        if (type(issuer) is not NativeResetEvidence or type(runner) is not ScenarioRunner
                or issuer.runner is not runner or runner.sessions.get(self._configuration['target_instance']) is not self._owner
                or self._issuer is not None):raise ValueError('native reset issuer must be actual installed evidence')
        self._issuer=issuer;self._issuer_pin=issuer;self._issuer_token=object();self._issuer_token_pin=self._issuer_token

    def _issuer_guard(self, issuer):
        _check_observer_methods(self)
        self.validate(allow_incomplete=True)
        if issuer is not self._issuer or self._issuer is None or getattr(issuer.runner,'_native_reset_evidence',None) is not issuer:
            raise ValueError('native reset foreign issuer')

    def _private_state(self, *, issuer):
        self._issuer_guard(issuer)
        binding=self._processes.get(self._logical_process)
        return NativeResetPrivateState(self._issuer_token,self._registry_token,len(self._facts),
            len(self._commands),len(self._lifecycles),self._logical_process,self._owner.reset_epoch,
            binding[0] if binding else None,binding[1] if binding else '',self._chain_sha256,self._status,self._reason)

    def _private_facts_since(self, cursor, *, issuer):
        self._issuer_guard(issuer)
        if not _uint(cursor) or cursor>len(self._facts):raise ValueError('native reset invalid cursor')
        return tuple(row[0] for row in self._facts[cursor:]),len(self._facts)

    def _resolve_fact(self, token, *, issuer):
        self._issuer_guard(issuer)
        if type(token) is not object:raise ValueError('native reset foreign token')
        indexed=self._token_index.get(token)
        if indexed is None:raise ValueError('native reset foreign token')
        fact_ordinal,found=indexed
        if (not _uint(fact_ordinal) or not 1<=fact_ordinal<=len(self._sealed_facts)
                or self._sealed_facts[fact_ordinal-1] is not found or found[0] is not token
                or token in self._consumed):raise ValueError('native reset foreign or consumed token')
        if found[3] is not None:
            row=json.loads(found[2]);logical_process=row.get('logical_process')
            binding=self._processes.get(logical_process)
            if binding is None or binding[0] is not found[3] or binding[1]!=found[4]:
                self._fail('fact_original_process_mismatch');raise ValueError('native reset original fact process drift')
        self._consumed.add(token);self._consumed_sealed=frozenset(self._consumed)
        return dict(kind=found[1],document=json.loads(found[2]),fact_ordinal=fact_ordinal)


def _actual_producer_frame(owner, name):
    import sys
    from . import session
    frame=sys._getframe(2)
    method,code=session._NATIVE_RESET_SESSION_FUNCTIONS[name]
    if frame.f_code is not code or frame.f_globals is not vars(session) or frame.f_locals.get('self') is not owner:
        raise ValueError('native reset attempt must originate in actual producer')

def _actual_fact_origin(observer):
    import sys
    frame=sys._getframe(2)
    allowed=('_ready','_begin_actual_command','_complete_actual_command','_fail_actual_command','_closed','_fail')
    if frame.f_globals is not globals() or frame.f_locals.get('self') is not observer or not any(
            frame.f_code is _OBSERVER_METHODS[name][1] for name in allowed):
        observer._status='incomplete';observer._reason='foreign_fact_producer'
        raise ValueError('native reset fact must originate in actual producer')

_OBSERVER_CLASS=NativeResetObservation
_OBSERVER_METHODS=MappingProxyType({name:(method,method.__code__) for name,method in vars(NativeResetObservation).items()
    if callable(method) and hasattr(method,'__code__')})
_OBSERVER_METHODS_PIN=_OBSERVER_METHODS

def _check_observer_methods(observer):
    if _OBSERVER_METHODS is not _OBSERVER_METHODS_PIN:
        raise ValueError('native reset observer pin table drift')
    if NativeResetObservation is not _OBSERVER_CLASS or type(observer) is not _OBSERVER_CLASS:
        raise ValueError('native reset observer type drift')
    for name,(method,code) in _OBSERVER_METHODS.items():
        if getattr(NativeResetObservation,name) is not method or method.__code__ is not code or name in vars(observer):
            raise ValueError('native reset observer method drift:'+name)
