"""Epoch-bound relaunch acceptance in the compiled build/process audit.

A real ``ScenarioRunner`` performs a real ``reset_all`` and really appends the
second launch row of each session; the sessions are the smallest doubles that
expose the built-session launch API.  Nothing here is an RTL run or a native
fetch.  The point of the gates is that a *new* launch identity is admitted only
when it is bound to a measured barrier, and that every pre-existing refusal
survives.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from types import SimpleNamespace

import pytest

from myfuzz.integration.compiled_build_join import built_receipt_sha256
from myfuzz.integration.compiled_process_audit import (
    EPOCH_LAUNCH_SCHEMA, BuiltProcessAudit, bind_reset_epoch_launch)
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner

LAUNCH_MISSING = 'compiled-F6-built-process-launch-missing'
IDENTITY_MISMATCH = 'compiled-F6-built-process-identity-mismatch'
IDENTITY_CHANGED = 'compiled-F6-built-process-identity-changed'
RECEIPT_CHANGED = 'compiled-F6-built-receipt-identity-changed'
NOT_LIVE = 'compiled-F6-native-process-not-live'


class _Process:
    _next = 4100

    def __init__(self, returncode=None):
        _Process._next += 1
        self.pid = _Process._next
        self.returncode = returncode

    def poll(self):
        return self.returncode


def _digest(label):
    return sha256(label.encode()).hexdigest()


def _artifact(name):
    return SimpleNamespace(runtime_document=dict(artifact_digest=_digest(name + 'a')),
                           plan=SimpleNamespace(
                               request=SimpleNamespace(instance_id=name)))


def _receipt(artifact):
    identity = dict(schema_version='local_harness_build_identity.v1',
                    artifact_digest=artifact.runtime_document['artifact_digest'],
                    profile_sha256=_digest('p'), facts_sha256=_digest('f'))
    identity['build_digest'] = built_receipt_sha256(identity)
    return dict(schema_version='local_harness_built_receipt.v1',
                artifact_digest=identity['artifact_digest'],
                build_digest=identity['build_digest'],
                build_identity=identity, binary_sha256=_digest('b'))


class _BuiltSession:
    """One built session: a pinned receipt, launch rows, epoch and live process."""

    def __init__(self, name, memory):
        self.name = name
        self.memory = memory
        self.artifact = _artifact(name)
        self.receipt = _receipt(self.artifact)
        self.reset_epoch = 0
        self.process = _Process()
        self.begins = 0
        self._execution = name + ':exec:0'
        # the first launch row is appended by ScenarioRunner.begin_test()
        self._launches = []

    def _append_launch(self):
        self._launches.append(dict(
            pid=self.process.pid, execution_nonce=self._execution,
            built_receipt_sha256=built_receipt_sha256(self.receipt),
            artifact_digest=self.receipt['artifact_digest'],
            build_digest=self.receipt['build_digest'],
            binary_sha256=self.receipt['binary_sha256'],
            observed_executable_sha256=self.receipt['binary_sha256'],
            ready_artifact_digest=self.receipt['artifact_digest'],
            failure_stage=None, returncode=None, reaped=False, aborted=False))

    def validate_built_executable_receipt(self):
        return deepcopy(self.receipt)

    def built_executable_launch_observations(self):
        return deepcopy(tuple(self._launches))

    def begin_case(self, testcase_id):
        self.begins += 1
        self._execution = self.name + ':exec:' + str(self.begins)
        self.process = _Process()
        self._append_launch()

    def end_case(self):
        pass

    def reset_local(self):
        self.reset_epoch += 1
        self.end_case()
        self.begin_case(self.name + ':reset:' + str(self.reset_epoch))
        return {'cancelled_responses': 0, 'cancelled_target_requests': ()}

    def step_local(self, inputs):
        return {'observed': {}}


class _Audited(BuiltProcessAudit):
    """The audit mixin over real sessions; not a flow executor."""

    _audit_error_prefix = 'compiled-F6'

    def __init__(self, runner, *, cpu_id='cpu', sessions=None):
        self.runner = runner
        self.cpu_id = cpu_id
        self._build_sessions = dict(runner.sessions if sessions is None else sessions)
        self.artifacts = {name: local.artifact
                          for name, local in self._build_sessions.items()}
        self._built_receipts = {name: local.validate_built_executable_receipt()
                                for name, local in self._build_sessions.items()}
        self._native_processes = {name: local.process
                                  for name, local in self._build_sessions.items()}
        self._epoch_launch = None
        self.finished = False
        self._process_identities = self._validated_build_process_identities()


def _runtime():
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x1000),),
                              initialization_seed=11, max_initialized_bytes=0x1000)
    sessions = {'cpu': _BuiltSession('cpu', memory),
                'peripheral': _BuiltSession('peripheral', memory)}
    runner = ScenarioRunner(sessions=sessions, ownership=compile_ownership(
        (InputField('cpu', 'pin', 1),),
        (InputOwner('cpu', 'pin', 0, 1, 'source', 'external'),)), bindings=())
    runner.begin_test('epoch-launch-audit')
    return _Audited(runner), runner, sessions


def _barrier(runner):
    barriers = [event for event in runner.events if event.get('kind') == 'reset_barrier']
    return barriers[-1]['event_id']


# --------------------------------------------------------------------------- #
# Before any barrier: exactly one launch, exactly as before
# --------------------------------------------------------------------------- #

def test_the_first_epoch_still_admits_exactly_one_launch_per_session():
    runtime, runner, sessions = _runtime()
    assert set(runtime._process_identities) == {'cpu', 'peripheral'}
    assert runtime.execution_audit()['identities'] == runtime._process_identities
    sessions['cpu'].begin_case('unmeasured-second-launch')
    with pytest.raises(ValueError) as raised:
        runtime._validated_build_process_identities()
    assert str(raised.value) == LAUNCH_MISSING
    runner.finalize()


def test_a_relaunch_cannot_be_bound_without_a_measured_reset_barrier():
    runtime, runner, sessions = _runtime()
    sessions['cpu'].begin_case('unmeasured-second-launch')
    sessions['peripheral'].begin_case('unmeasured-second-launch')
    for kwargs in ({'barrier_event_id': runner.event_count + 7},
                   {'barrier_event_id': 0},
                   {'policy': 'cold_all'},
                   {'reset_epoch': 0},
                   {'reset_epoch': 2}):
        declared = dict(reset_epoch=1, barrier_event_id=1, policy='warm_all')
        declared.update(kwargs)
        with pytest.raises(ValueError) as raised:
            bind_reset_epoch_launch(runtime, **declared)
        assert str(raised.value) == LAUNCH_MISSING
    assert runtime._epoch_launch is None
    with pytest.raises(ValueError) as raised:
        runtime._validated_build_process_identities()
    assert str(raised.value) == LAUNCH_MISSING
    runner.finalize()


def test_a_barrier_of_another_policy_never_binds_the_relaunch():
    runtime, runner, sessions = _runtime()
    runner.reset_all('warm_all')
    with pytest.raises(ValueError) as raised:
        bind_reset_epoch_launch(runtime, reset_epoch=1,
                                barrier_event_id=_barrier(runner), policy='cold_all')
    assert str(raised.value) == LAUNCH_MISSING
    runner.finalize()


def test_an_audit_bound_to_sessions_it_does_not_own_is_refused():
    runtime, runner, sessions = _runtime()
    foreign = {'cpu': _BuiltSession('cpu', sessions['cpu'].memory),
               'peripheral': sessions['peripheral']}
    runner.reset_all('warm_all')
    with pytest.raises(ValueError) as raised:
        bind_reset_epoch_launch(_Audited(runner, sessions=foreign), reset_epoch=1,
                                barrier_event_id=_barrier(runner), policy='warm_all')
    assert str(raised.value) == LAUNCH_MISSING
    with pytest.raises(ValueError) as not_a_runner:
        bind_reset_epoch_launch(SimpleNamespace(_audit_error_prefix='compiled-F6',
                                               runner=object(), _build_sessions={}),
                                reset_epoch=1, barrier_event_id=1, policy='warm_all')
    assert str(not_a_runner.value) == LAUNCH_MISSING
    runner.finalize()


# --------------------------------------------------------------------------- #
# After a measured barrier: the new identity is admitted, bound to the epoch
# --------------------------------------------------------------------------- #

def test_a_measured_barrier_admits_the_relaunch_it_produced():
    runtime, runner, sessions = _runtime()
    first = {name: local.process.pid for name, local in sessions.items()}
    first_nonce = {name: local._execution for name, local in sessions.items()}
    runner.reset_all('warm_all')
    with pytest.raises(ValueError) as unbound:
        runtime._validated_build_process_identities()
    assert str(unbound.value) == LAUNCH_MISSING

    binding = bind_reset_epoch_launch(runtime, reset_epoch=1,
                                      barrier_event_id=_barrier(runner),
                                      policy='warm_all')
    assert binding['schema_version'] == EPOCH_LAUNCH_SCHEMA
    assert binding['reset_epoch'] == 1 and binding['launch_index'] == 1
    assert binding['previous_epoch'] == 0
    assert binding['barrier_event_id'] == _barrier(runner)
    assert set(binding['identities']) == {'cpu', 'peripheral'}
    identities = runtime._validated_build_process_identities()
    assert identities == runtime._process_identities == binding['identities']
    for name, row in identities.items():
        assert row['pid'] == sessions[name].process.pid != first[name]
        assert row['execution_nonce'] == sessions[name]._execution != first_nonce[name]
        assert runtime._native_processes[name] is sessions[name].process
    # the relaunch is admissible exactly once: a third launch is not an epoch
    sessions['cpu'].begin_case('unmeasured-third-launch')
    with pytest.raises(ValueError) as raised:
        runtime._validated_build_process_identities()
    assert str(raised.value) == LAUNCH_MISSING
    runner.finalize()


def test_failed_relaunch_validation_preserves_old_process_and_epoch_pins():
    runtime, runner, sessions = _runtime()
    old_processes = runtime._native_processes
    old_identities = runtime._process_identities
    old_epoch = runtime._epoch_launch
    runner.reset_all('warm_all')
    launch = sessions['cpu']._launches[-1]
    valid_nonce = launch['execution_nonce']
    launch['execution_nonce'] = sessions['cpu']._launches[0]['execution_nonce']
    with pytest.raises(ValueError, match=IDENTITY_MISMATCH):
        bind_reset_epoch_launch(runtime, reset_epoch=1,
                                barrier_event_id=_barrier(runner), policy='warm_all')
    assert runtime._native_processes is old_processes
    assert runtime._process_identities is old_identities
    assert runtime._epoch_launch is old_epoch
    launch['execution_nonce'] = valid_nonce
    result = bind_reset_epoch_launch(runtime, reset_epoch=1,
                                     barrier_event_id=_barrier(runner), policy='warm_all')
    assert result['identities'] == runtime._process_identities
    assert runtime._native_processes['cpu'] is sessions['cpu'].process
    runner.finalize()


def test_the_binding_document_is_detached_from_the_pinned_pin():
    runtime, runner, sessions = _runtime()
    runner.reset_all('warm_all')
    binding = bind_reset_epoch_launch(runtime, reset_epoch=1,
                                      barrier_event_id=_barrier(runner),
                                      policy='warm_all')
    binding['identities']['cpu']['pid'] = 1
    binding['reset_epoch'] = 9
    assert runtime._epoch_launch['reset_epoch'] == 1
    assert runtime._validated_build_process_identities()['cpu']['pid'] \
        == sessions['cpu'].process.pid
    runner.finalize()


def test_a_second_barrier_needs_its_own_binding_and_is_never_rebound():
    runtime, runner, sessions = _runtime()
    runner.reset_all('warm_all')
    bind_reset_epoch_launch(runtime, reset_epoch=1, barrier_event_id=_barrier(runner),
                            policy='warm_all')
    runner.reset_all('cold_all')
    # the epoch-1 binding cannot cover the second relaunch
    with pytest.raises(ValueError) as raised:
        runtime._validated_build_process_identities()
    assert str(raised.value) == LAUNCH_MISSING
    # and the epoch it already accepted cannot be claimed again
    with pytest.raises(ValueError) as rebound:
        bind_reset_epoch_launch(runtime, reset_epoch=1,
                                barrier_event_id=_barrier(runner), policy='cold_all')
    assert str(rebound.value) == IDENTITY_CHANGED
    # a fresh epoch is a fresh, measured relaunch
    binding = bind_reset_epoch_launch(runtime, reset_epoch=2,
                                      barrier_event_id=_barrier(runner),
                                      policy='cold_all')
    assert binding['launch_index'] == 2
    assert runtime._validated_build_process_identities() == binding['identities']
    runner.finalize()


# --------------------------------------------------------------------------- #
# Every original refusal survives
# --------------------------------------------------------------------------- #

def test_a_reused_execution_identity_is_refused_after_the_barrier():
    runtime, runner, sessions = _runtime()
    reused = {name: local._execution for name, local in sessions.items()}
    runner.reset_all('warm_all')
    bind_reset_epoch_launch(runtime, reset_epoch=1, barrier_event_id=_barrier(runner),
                            policy='warm_all')
    sessions['peripheral']._execution = reused['peripheral']   # an identity, reused
    with pytest.raises(ValueError) as raised:
        runtime._validated_build_process_identities()
    assert str(raised.value) == IDENTITY_MISMATCH
    runner.finalize()


def test_a_launch_row_that_repeats_an_earlier_nonce_is_refused():
    runtime, runner, sessions = _runtime()
    runner.reset_all('warm_all')
    bind_reset_epoch_launch(runtime, reset_epoch=1, barrier_event_id=_barrier(runner),
                            policy='warm_all')
    local = sessions['cpu']
    local._launches[1]['execution_nonce'] = local._launches[0]['execution_nonce']
    with pytest.raises(ValueError) as raised:
        runtime._validated_build_process_identities()
    assert str(raised.value) == IDENTITY_MISMATCH
    runner.finalize()


def test_the_built_receipt_identity_still_refuses_after_the_barrier():
    runtime, runner, sessions = _runtime()
    runner.reset_all('warm_all')
    bind_reset_epoch_launch(runtime, reset_epoch=1, barrier_event_id=_barrier(runner),
                            policy='warm_all')
    sessions['cpu'].receipt['binary_sha256'] = _digest('c')
    with pytest.raises(ValueError) as raised:
        runtime._validated_build_process_identities()
    assert str(raised.value) == RECEIPT_CHANGED
    runner.finalize()


def test_a_dead_relaunched_process_is_never_bound():
    runtime, runner, sessions = _runtime()
    runner.reset_all('warm_all')
    sessions['peripheral'].process.returncode = 0
    with pytest.raises(ValueError) as raised:
        bind_reset_epoch_launch(runtime, reset_epoch=1,
                                barrier_event_id=_barrier(runner), policy='warm_all')
    assert str(raised.value) == NOT_LIVE
    assert runtime._epoch_launch is None
    runner.finalize()


def test_a_real_event_that_is_not_the_barrier_never_binds_the_relaunch():
    runtime, runner, sessions = _runtime()
    runner.reset_all('warm_all')
    with pytest.raises(ValueError) as raised:
        bind_reset_epoch_launch(runtime, reset_epoch=1,
                                barrier_event_id=_barrier(runner) - 1,
                                policy='warm_all')
    assert str(raised.value) == LAUNCH_MISSING
    assert runtime._epoch_launch is None
    runner.finalize()
