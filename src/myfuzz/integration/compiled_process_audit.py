"""Shared executable receipt and process diagnostics for compiled runtimes.

This module validates associations and retains partial diagnostics; it never
issues native storage/source authority or grants permission to launch a model.

Launch epochs
-------------
A compiled runtime pins the launch identity of every session it built.  A
measured whole-scenario reset (``ScenarioRunner.reset_all``) ends and relaunches
every actual RTL process, so the *same* session legitimately has a second launch
row afterwards.  ``bind_reset_epoch_launch`` is the one declared place that binds
such a relaunch to the measured barrier that produced it: the accepted row is
the row at index ``reset_epoch`` (exactly one launch per epoch, oldest first),
its execution identity must be one that no earlier launch used, and the barrier
must still be in the runner's own journal.  Everything else keeps refusing:
an unbound relaunch (any launch count other than one), an identity reuse, a
second launch without a new barrier, and the receipt identities themselves.
"""
from copy import deepcopy
from functools import wraps
import json
from .compiled_build_join import validate_built_receipts, built_receipt_sha256

#: The one declared relaunch rule.  ``launch_index`` is ``reset_epoch`` because
#: epoch 0 launched once and every barrier relaunches every session exactly once.
EPOCH_LAUNCH_SCHEMA = 'compiled_epoch_launch.v1'
RESET_POLICIES = ('warm_all', 'cold_all')


def _semantic_canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')


def diagnostic_build_snapshot(runtime, *, closed=None, previous=None, error=None):
    """Capture diagnostics without allowing export refusal to erase earlier facts."""
    try:
        snapshot = (runtime.build_audit_snapshot() if closed is None
                    else runtime.build_audit_snapshot(closed=closed))
        if type(snapshot) is not dict:
            raise ValueError('compiled-F4 build snapshot must be a document')
    except BaseException as export_error:
        snapshot = deepcopy(previous if previous is not None
                            else getattr(runtime, '_build_audit_previous', {}))
        snapshot.setdefault('unavailable', {})['snapshot'] = dict(
            error_type=type(export_error).__name__, error=str(export_error))
        if error is not None:
            error.add_note('compiled-F4 build snapshot export: ' + repr(export_error))
    if error is not None and snapshot.get('unavailable'):
        error.add_note('compiled-F4 build diagnostics unavailable: ' + repr(snapshot['unavailable']))
    runtime._build_audit_previous = deepcopy(snapshot)
    return deepcopy(snapshot)


def capture_build_construction(function):
    """Keep partial lifecycle evidence when __init__ cannot return an owner."""
    @wraps(function)
    def construct(self, *args, **kwargs):
        self._build_audit_sink = kwargs.get('build_audit_sink')
        self._build_sessions = {}
        self._build_audit_previous = {}
        self._native_processes = {}
        self._process_identities = {}
        self._epoch_launch = None
        try:
            return function(self, *args, **kwargs)
        except BaseException as error:
            for local in self._build_sessions.values():
                try:
                    local.end_case()
                except BaseException as cleanup:
                    error.add_note('compiled-F4 startup cleanup: ' + repr(cleanup))
            if self._build_audit_sink is not None:
                try:
                    self._build_audit_sink(diagnostic_build_snapshot(
                        self, closed=True, error=error))
                except BaseException as audit_error:
                    error.add_note('compiled-F4 partial build audit: ' + repr(audit_error))
            raise
    return construct



def _measured_reset_barrier(runner, *, event_id, policy, prefix):
    """Read the one measured barrier a relaunch claims, from the runner's journal."""
    read = getattr(runner, '_event_ref_by_id', None)
    if not callable(read):
        raise ValueError(prefix + '-built-process-launch-missing')
    barrier = read(event_id)
    if (type(barrier) is not dict or barrier.get('kind') != 'reset_barrier'
            or barrier.get('policy') != policy
            or barrier.get('event_id') != event_id):
        raise ValueError(prefix + '-built-process-launch-missing')
    return {'event_id': barrier['event_id'], 'policy': barrier['policy']}


def bind_reset_epoch_launch(runtime, *, reset_epoch, barrier_event_id, policy):
    """Bind ONE measured reset barrier to the relaunch it produced.

    After this call the audit accepts the launch row at index ``reset_epoch`` and
    keeps refusing every other row: a launch without a binding (any session with
    more than one launch row), an identity an earlier launch already used, a
    second barrier that was not re-declared, and a barrier that is not in the
    runner's measured journal.
    """
    from myfuzz.scenario.runner import ScenarioRunner
    prefix = getattr(runtime, '_audit_error_prefix', 'compiled-runtime')
    if (type(reset_epoch) is not int or reset_epoch < 1
            or type(barrier_event_id) is not int or barrier_event_id < 1
            or policy not in RESET_POLICIES):
        raise ValueError(prefix + '-built-process-launch-missing')
    runner = getattr(runtime, 'runner', None)
    sessions = getattr(runtime, '_build_sessions', None)
    if (type(runner) is not ScenarioRunner or type(sessions) is not dict or not sessions
            or set(sessions) != set(getattr(runner, 'sessions', {}))
            or any(runner.sessions[name] is not local for name, local in sessions.items())):
        raise ValueError(prefix + '-built-process-launch-missing')
    previous = getattr(runtime, '_epoch_launch', None)
    if (previous is not None
            and previous.get('reset_epoch') + 1 != reset_epoch):
        raise ValueError(prefix + '-built-process-identity-changed')
    barrier = _measured_reset_barrier(runner, event_id=barrier_event_id,
                                     policy=policy, prefix=prefix)
    processes = {name: local.process for name, local in sessions.items()}
    if any(process is None or getattr(process, 'poll', None) is None
           or process.poll() is not None for process in processes.values()):
        raise ValueError(prefix + '-native-process-not-live')
    binding = dict(schema_version=EPOCH_LAUNCH_SCHEMA, reset_epoch=reset_epoch,
                   previous_epoch=reset_epoch - 1, launch_index=reset_epoch,
                   barrier_event_id=barrier['event_id'], policy=barrier['policy'])
    previous_processes = runtime._native_processes
    previous_identities = runtime._process_identities
    runtime._epoch_launch = binding
    try:
        # The relaunched processes replace the pinned map, and the audit's own
        # identity document is re-derived from them under the same rule.
        runtime._native_processes = processes
        identities = runtime._validated_build_process_identities()
        runtime._process_identities = identities
        binding['identities'] = deepcopy(identities)
        result = deepcopy(binding)
    except BaseException:
        runtime._epoch_launch = previous
        runtime._native_processes = previous_processes
        runtime._process_identities = previous_identities
        raise
    return result


class BuiltProcessAudit:
    """Receipt/launch joins shared without inheriting a flow executor."""
    _audit_error_prefix = 'compiled-runtime'
    _audit_schema = 'compiled_execution_audit.v1'

    def _validated_built_receipts(self):
        receipts = {name:local.validate_built_executable_receipt()
                    for name,local in sorted(self._build_sessions.items())}
        validate_built_receipts(self.artifacts, receipts)
        if _semantic_canonical(receipts) != _semantic_canonical(self._built_receipts):
            raise ValueError(self._audit_error_prefix+'-built-receipt-identity-changed')
        return receipts


    def _accepted_launch(self, local, launches):
        """The single admitted launch row, or the declared epoch-bound relaunch."""
        binding = getattr(self, '_epoch_launch', None)
        if binding is None:
            if len(launches) != 1:
                raise ValueError(self._audit_error_prefix + '-built-process-launch-missing')
            return launches[0]
        self._validated_epoch_launch(local, launches, binding)
        return launches[binding['launch_index']]


    def _validated_epoch_launch(self, local, launches, binding):
        """One launch per measured epoch; never a reused or unbound identity."""
        prefix = self._audit_error_prefix
        epoch = binding['reset_epoch']
        _measured_reset_barrier(self.runner, event_id=binding['barrier_event_id'],
                                policy=binding['policy'], prefix=prefix)
        if local.reset_epoch != epoch or len(launches) != epoch + 1:
            raise ValueError(prefix + '-built-process-launch-missing')
        index = binding['launch_index']
        row, prior = launches[index], launches[:index]
        nonces = [earlier.get('execution_nonce') for earlier in prior]
        if (any(type(nonce) is not str or not nonce for nonce in nonces)
                or len(set(nonces)) != len(nonces)
                or row.get('execution_nonce') != local._execution
                or row.get('execution_nonce') in nonces):
            raise ValueError(prefix + '-built-process-identity-mismatch')


    def _validated_build_process_identities(self):
        receipts = self._validated_built_receipts()
        identities = {}
        for name, local in self._build_sessions.items():
            launches = local.built_executable_launch_observations()
            row = self._accepted_launch(local, launches)
            receipt = receipts[name]
            expected = dict(artifact_digest=receipt['artifact_digest'],
                build_digest=receipt['build_digest'], binary_sha256=receipt['binary_sha256'],
                built_receipt_sha256=built_receipt_sha256(receipt),
                observed_executable_sha256=receipt['binary_sha256'],
                ready_artifact_digest=receipt['artifact_digest'])
            process = self._native_processes[name]
            if (any(row.get(key) != value for key,value in expected.items())
                    or row.get('pid') != process.pid
                    or row.get('execution_nonce') != local._execution):
                raise ValueError(self._audit_error_prefix+'-built-process-identity-mismatch')
            identities[name] = dict(component=name,
                role='cpu' if name == self.cpu_id else 'bound_target',
                pid=row['pid'],execution_nonce=row['execution_nonce'],**expected)
        return identities


    def build_audit_snapshot(self, *, closed=None):
        """Export retained observations; unavailable material never grants authority."""
        previous = deepcopy(getattr(self, '_build_audit_previous', {}))
        receipts = previous.get('receipts', {})
        observations = previous.get('preparation_observations', {})
        audit = previous.get('execution_audit', {})
        identities = audit.get('identities', {})
        exits = audit.get('exits', {})
        failures = previous.get('unavailable', {})
        for name, local in self._build_sessions.items():
            def unavailable(label, error):
                failures.setdefault(name, {})[label] = dict(
                    error_type=type(error).__name__, error=str(error))
            for target, label, accessor in (
                    (receipts, 'receipt', 'built_executable_receipt_document'),
                    (observations, 'preparation', 'build_preparation_observation_document')):
                try:
                    target[name] = getattr(local, accessor)()
                except BaseException as error:
                    unavailable(label, error)
            try:
                launches = local.built_executable_launch_observations()
            except BaseException as error:
                unavailable('launches', error)
                try:
                    launches = local._built_executable_launch_diagnostics()
                except BaseException as diagnostic_error:
                    unavailable('launch_diagnostics', diagnostic_error)
                    launches = ()
            try:
                if launches:
                    row = launches[-1]
                    identities[name] = dict(row, component=name,
                        role='cpu' if name == getattr(self,'cpu_id',None) else 'bound_target')
                    exits[name] = dict(returncode=row.get('returncode'),reaped=row.get('reaped',False))
            except BaseException as error:
                unavailable('launch_document', error)
        snapshot = dict(receipts=receipts,preparation_observations=observations,
            execution_audit=dict(identities=identities,exits=exits,
                closed=bool(getattr(self,'finished',False) if closed is None else closed)),
            unavailable=failures)
        self._build_audit_previous = deepcopy(snapshot)
        return deepcopy(snapshot)


    def execution_audit(self):
        identities = self._validated_build_process_identities()
        if identities != self._process_identities:
            raise ValueError(self._audit_error_prefix+'-built-process-identity-changed')
        codes={name:proc.poll() for name,proc in self._native_processes.items()}
        return dict(schema_version=self._audit_schema,
            identities=deepcopy(self._process_identities),
            exits={name:dict(returncode=code,reaped=code is not None)
                   for name,code in codes.items()},closed=self.finished)

