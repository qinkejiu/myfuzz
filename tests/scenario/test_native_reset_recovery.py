"""Executable gates for the declared, epoch-scoped reset recovery.

These are software gates only: a real ``ScenarioRunner`` performs a real
``reset_all`` over real ``PersistentMemory``, and the provider/authority/carrier
objects are the smallest doubles that expose the same declared method shapes as
the live ones (``current_state()``, ``issue(register=..., reset_epoch=...)`` /
``consume(token)``, ``submit(record, flow=...)``).  The authority double keeps
the real ``GpioRegisterVersionAuthority`` rule that its live state is keyed by
``(process, reset_epoch)``, so it cannot issue for a new epoch until a new
actual command re-armed it - that rule is what makes the re-install meaningful.

Nothing here is a native run and nothing here stands in for one.
"""
from __future__ import annotations

import inspect
import json

import pytest

from myfuzz.runtime.contracts import REFUSAL_CODES
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.native_reset_recovery import (
    CODE_DRIFT, CODE_UNDECLARED, CODE_UNSUPPORTED, CONTINUATION_VERIFIED,
    REINSTALLED, SCHEMA_VERSION, UNAVAILABLE, UNDECLARED, ResetRecoveryRefused,
    declare_reset_recovery)
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner

F6_RECORD = bytes.fromhex('0110c00008000000')
CARRIER_CODE = 'compiled-F6-built-process-identity-changed'


# --------------------------------------------------------------------------- #
# Doubles: the declared method shapes, not a new runtime
# --------------------------------------------------------------------------- #

class _Process:
    _next = 7000

    def __init__(self):
        _Process._next += 1
        self.pid = _Process._next

    def poll(self):
        return None


class _Session:
    """One persistent session: epoch, execution identity and a live process."""

    def __init__(self, memory, name):
        self.memory = memory
        self.name = name
        self.reset_epoch = 0
        self._execution = name + ':exec:0'
        self.process = _Process()
        self.local_ticks = 0
        self.begins = 0
        self.on_command = None

    def begin_case(self, testcase_id):
        self.begins += 1
        self._execution = self.name + ':exec:' + str(self.begins)
        self.process = _Process()

    def step_local(self, inputs):
        self.local_ticks += 1
        return {'observed': {'epoch': self.reset_epoch}}

    def reset_local(self):
        self.reset_epoch += 1
        self._execution = self.name + ':reset:' + str(self.reset_epoch)
        self.process = _Process()
        return {'cancelled_responses': 0}

    def end_case(self):
        pass

    def command(self, operation, fields):
        """One declared re-arm command; the real session sends it to the RTL."""
        if operation != 'ACCESS_GPIO' or not isinstance(fields, tuple):
            raise ValueError('declared re-arm command required')
        if self.on_command is not None:
            self.on_command(self)
        return _Receipt(operation)


class _Receipt:
    def __init__(self, operation):
        self.status = 'result'
        self.operation = operation
        self.sequence = 1


class _Authority:
    """Epoch- and process-scoped live state, exactly like the real authority."""

    def __init__(self, session):
        self.session = session
        self._state = None
        self._tokens = {}
        self.fence_epochs = True
        self.restamp = False

    def arm(self):
        self._state = {'identity': (self.session.process, self.session.reset_epoch),
                       'reset_epoch': self.session.reset_epoch, 'value': 0}

    def issue(self, *, register='GPIOEN', reset_epoch):
        state = self._state
        if (register != 'GPIOEN' or type(reset_epoch) is not int or state is None
                or state['identity'] != (self.session.process, self.session.reset_epoch)
                or reset_epoch != self.session.reset_epoch):
            raise ValueError('register-version-current-state-unavailable')
        token = object()
        self._tokens[token] = {'register': register, 'reset_epoch': reset_epoch,
                               'value': state['value']}
        return token

    def consume(self, token):
        if self.fence_epochs:
            state = self._state
            if (state is None
                    or state['identity'] != (self.session.process, self.session.reset_epoch)):
                self._tokens.clear()
                raise ValueError('register-version-current-state-unavailable')
        witness = self._tokens.pop(token, None)
        if witness is None:
            raise ValueError('register-version-token-invalid-or-revoked')
        witness = dict(witness)
        if self.restamp:
            witness['reset_epoch'] = self.session.reset_epoch
        return witness


class _Provider:
    def __init__(self, name, session):
        self.name = name
        self.session = session
        self.reason = 'shared_pin_process_identity_changed'
        self.epoch = 0
        self.status = 'observed'

    def arm(self):
        self.epoch = self.session.reset_epoch
        self.status = 'observed'
        self.reason = None

    def current_state(self):
        return {'status': self.status, 'reset_epoch': self.epoch,
                'reason': self.reason, 'name': self.name}


class _Carrier:
    def __init__(self, outcome='refuse'):
        self.outcome = outcome
        self.calls = []

    def submit(self, record, *, flow='F6'):
        self.calls.append((record, flow))
        if self.outcome == 'refuse':
            raise ValueError(CARRIER_CODE)
        if self.outcome == 'incomplete':
            return {'status': 'failed'}
        return {'status': 'passed'}


# --------------------------------------------------------------------------- #
# A real runner and a real measured reset
# --------------------------------------------------------------------------- #

def _runner():
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x1000),),
                              initialization_seed=7, max_initialized_bytes=0x1000)
    memory.preload(0x100, b'\x11\x22\x33\x44')
    sessions = {'cpu': _Session(memory, 'cpu'),
                'peripheral': _Session(memory, 'peripheral')}
    ownership = compile_ownership(
        (InputField('cpu', 'pin', 1),),
        (InputOwner('cpu', 'pin', 0, 1, 'source', 'external'),))
    runner = ScenarioRunner(sessions=sessions, ownership=ownership, bindings=())
    runner.begin_test('reset-recovery')
    return runner, sessions, memory


def _declared(policy='warm_all', *, authority=True, providers=True, carrier=True,
              rearm=False, runner=None, sessions=None):
    runner, sessions, memory = _runner()
    session = sessions['peripheral']
    auth = _Authority(session)
    auth.arm()
    provider = _Provider('padin', session)
    provider.arm()
    kwargs = dict(policy=policy, sources=dict(sessions),
                  providers={'padin': provider} if providers else {},
                  authority=auth if authority else None,
                  carrier=_Carrier() if carrier else None)
    if rearm:
        kwargs['rearm'] = {'session': 'peripheral', 'operation': 'ACCESS_GPIO',
                           'fields': (0,)}
        session.on_command = lambda target: (auth.arm(), provider.arm())
    recovery = declare_reset_recovery(runner, **kwargs)
    return recovery, runner, sessions, auth, provider


# --------------------------------------------------------------------------- #
# (a) the re-install really happens and is bound to the new epoch
# --------------------------------------------------------------------------- #

def test_reinstall_binds_every_declared_binding_to_the_new_epoch():
    recovery, runner, sessions, authority, provider = _declared(rearm=True)
    pre = recovery.credit(component='cpu', epoch=0, token=1, identity=('cpu', 0, 1))
    assert pre['lineage'] is True
    assert recovery.capture_authority_token() is True
    declared_pid = sessions['cpu'].process.pid
    reset = runner.reset_all('warm_all')
    document = recovery.observe()

    assert document['schema_version'] == SCHEMA_VERSION
    assert document['status'] == REINSTALLED
    assert document['policy'] == 'warm_all'
    assert document['epoch'] == {'before': {'cpu': 0, 'peripheral': 0}, 'after': 1,
                                 'advanced': True}
    assert document['command_epoch'] == {'before': 0, 'after': 1}
    assert document['barrier']['policy'] == 'warm_all'
    barrier_events = [event for event in runner.events
                      if event.get('kind') == 'reset_barrier']
    assert document['barrier']['event_id'] == barrier_events[-1]['event_id']
    assert document['memory_generations'] == {'before': {'ram': 0}, 'after': {'ram': 0}}

    by_name = {row['name']: row for row in document['sources']}
    assert set(by_name) == {'cpu', 'peripheral'}
    for name, row in by_name.items():
        assert row['status'] == REINSTALLED
        assert row['reset_epoch'] == 1
        assert row['execution'] == name + ':reset:1'
        assert row['pid'] != declared_pid
        assert len(row['binding_sha256']) == 64

    assert document['providers'] == [{'name': 'padin', 'status': REINSTALLED,
                                      'reset_epoch': 1, 'source': 'current_state'}]
    assert document['authority']['status'] == REINSTALLED
    assert document['authority']['reset_epoch'] == 1
    assert document['authority']['rearm'] == 'complete'
    # the captured pre-reset token is refused, or consumable only while it still
    # carries its old epoch - it can never become new-epoch credit
    assert document['lineage']['authority_token_refused'] is False
    assert document['lineage']['authority_token_stale_epoch'] == 0
    assert document['lineage']['old_epoch_fenced'] is True
    assert reset.policy == 'warm_all'
    json.dumps(document)  # the document is exportable as it stands
    runner.finalize()


def test_reinstall_requires_a_declared_rearm_before_the_authority_returns():
    recovery, runner, sessions, authority, provider = _declared(rearm=False)
    runner.reset_all('warm_all')
    document = recovery.observe()
    assert document['status'] == UNAVAILABLE
    assert document['authority'] == {'status': UNAVAILABLE,
                                     'reset_epoch': None, 'rearm': UNDECLARED,
                                     'pre_reset_token_refused': None,
                                     'reason': 'register-version-current-state-unavailable'}
    # the sources were still re-installed; the authority needs a new actual
    # command, and a provider nobody re-armed still reports the old epoch
    assert all(row['status'] == REINSTALLED for row in document['sources'])
    assert document['providers'][0]['status'] == UNAVAILABLE
    assert document['providers'][0]['reason'] == 'stale-reset-epoch'
    runner.finalize()


def test_a_provider_that_still_reports_the_old_epoch_is_not_reinstalled():
    recovery, runner, sessions, authority, provider = _declared(rearm=False)
    runner.reset_all('warm_all')
    provider.status = 'unknown'
    provider.epoch = 0
    provider.reason = 'shared_RAM_unavailable:shared_RAM_live_process_required'
    document = recovery.observe()
    assert document['status'] == UNAVAILABLE
    assert document['providers'][0]['status'] == UNAVAILABLE
    assert document['providers'][0]['reason'] == (
        'shared_RAM_unavailable:shared_RAM_live_process_required')
    assert document['providers'][0]['provider_epoch'] == 0
    runner.finalize()


def test_cold_reset_must_advance_the_declared_memory_generation():
    recovery, runner, sessions, authority, provider = _declared(policy='cold_all', rearm=True)
    runner.reset_all('cold_all')
    document = recovery.observe()
    assert document['status'] == REINSTALLED
    assert document['memory_generations'] == {'before': {'ram': 0}, 'after': {'ram': 1}}
    runner.finalize()


def test_a_warm_barrier_under_a_cold_declaration_is_refused():
    recovery, runner, sessions, authority, provider = _declared(policy='cold_all', rearm=True)
    runner.reset_all('warm_all')
    with pytest.raises(ResetRecoveryRefused) as raised:
        recovery.observe()
    assert raised.value.code == CODE_DRIFT
    assert raised.value.pointer == '/barrier/policy'
    runner.finalize()


def test_a_memory_generation_that_does_not_match_the_declared_policy_is_refused():
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x1000),),
                              initialization_seed=7, max_initialized_bytes=0x1000)
    sessions = {'cpu': _Session(memory, 'cpu')}
    runner = ScenarioRunner(sessions=sessions,
                            ownership=compile_ownership(
                                (InputField('cpu', 'pin', 1),),
                                (InputOwner('cpu', 'pin', 0, 1, 'source', 'external'),)),
                            bindings=())
    runner.begin_test('reset-recovery-memory')
    recovery = declare_reset_recovery(runner, policy='warm_all', sources=dict(sessions),
                                      authority=_Authority(sessions['cpu']))
    runner.reset_all('warm_all')
    memory.cold_reset()                  # a generation the warm declaration denies
    with pytest.raises(ResetRecoveryRefused) as raised:
        recovery.observe()
    assert raised.value.code == CODE_DRIFT
    assert raised.value.pointer == '/memory_generations/ram'
    runner.finalize()


# --------------------------------------------------------------------------- #
# (b) pre-reset lineage and credit cannot be reused after the barrier
# --------------------------------------------------------------------------- #

def test_old_epoch_credit_is_refused_after_the_barrier():
    recovery, runner, sessions, authority, provider = _declared(rearm=True)
    recovery.credit(component='cpu', epoch=0, token=1, identity=('cpu', 0, 1))
    runner.reset_all('warm_all')
    recovery.observe()
    with pytest.raises(ResetRecoveryRefused) as raised:
        recovery.credit(component='cpu', epoch=0, token=1, identity=('cpu', 0, 1))
    assert raised.value.code == CODE_DRIFT
    assert raised.value.code in REFUSAL_CODES
    assert raised.value.pointer == '/credit/epoch'
    runner.finalize()


def test_a_pre_reset_identity_cannot_be_credited_in_the_new_epoch():
    recovery, runner, sessions, authority, provider = _declared(rearm=True)
    recovery.credit(component='cpu', epoch=0, token=1, identity=('cpu', 0, 1))
    runner.reset_all('warm_all')
    recovery.observe()
    with pytest.raises(ResetRecoveryRefused) as raised:
        recovery.credit(component='cpu', epoch=1, token=1, identity=('cpu', 0, 1))
    assert raised.value.code == CODE_DRIFT
    assert raised.value.pointer == '/credit/identity'
    runner.finalize()


def test_a_pre_reset_token_re_stamped_with_the_new_epoch_is_refused():
    recovery, runner, sessions, authority, provider = _declared(rearm=True)
    assert recovery.capture_authority_token() is True
    authority.fence_epochs = False        # a broken authority never invalidates
    authority.restamp = True              # ... and re-labels old tokens as new
    runner.reset_all('warm_all')
    with pytest.raises(ResetRecoveryRefused) as raised:
        recovery.observe()
    assert raised.value.code == CODE_DRIFT
    assert raised.value.pointer == '/authority/token'
    runner.finalize()


# --------------------------------------------------------------------------- #
# (c) a same-value/same-token new-epoch event is not lineage
# --------------------------------------------------------------------------- #

def test_the_same_numeric_token_in_the_new_epoch_is_not_lineage():
    recovery, runner, sessions, authority, provider = _declared(rearm=True)
    pre = recovery.credit(component='cpu', epoch=0, token=1, identity=('cpu', 0, 1))
    runner.reset_all('warm_all')
    recovery.observe()
    post = recovery.credit(component='cpu', epoch=1, token=1, identity=('cpu', 1, 1))
    assert pre['lineage'] is True and pre['token_reuse_across_epoch'] is False
    assert post['lineage'] is False
    assert post['epoch_scoped'] is True
    assert post['token_reuse_across_epoch'] is True
    assert pre['reset_epoch'] != post['reset_epoch']
    document = recovery.document()
    assert document['lineage']['token_reuse_across_epoch'] == [
        {'component': 'cpu', 'reset_epoch': 1, 'token': 1, 'lineage': False}]
    assert document['lineage']['pre_reset_tokens'] == [
        {'component': 'cpu', 'reset_epoch': 0, 'token': 1}]
    runner.finalize()


def test_a_distinct_new_epoch_token_is_still_not_lineage():
    recovery, runner, sessions, authority, provider = _declared(rearm=True)
    recovery.credit(component='cpu', epoch=0, token=1)
    runner.reset_all('warm_all')
    recovery.observe()
    post = recovery.credit(component='cpu', epoch=1, token=2)
    assert post['lineage'] is False and post['token_reuse_across_epoch'] is False
    runner.finalize()


def test_an_opaque_new_epoch_token_stays_out_of_the_document():
    recovery, runner, sessions, authority, provider = _declared(rearm=True)
    recovery.credit(component='cpu', epoch=0, token=object())
    runner.reset_all('warm_all')
    recovery.observe()
    post = recovery.credit(component='cpu', epoch=1, token=object())
    assert post['token'] == 'opaque'
    json.dumps(recovery.document())
    runner.finalize()


# --------------------------------------------------------------------------- #
# (d) the refusal path when the re-install is undeclared or impossible
# --------------------------------------------------------------------------- #

def test_undeclared_bindings_are_refused_with_a_typed_code():
    runner, sessions, memory = _runner()
    with pytest.raises(ResetRecoveryRefused) as raised:
        declare_reset_recovery(runner, policy='warm_all', sources={})
    assert raised.value.code == CODE_UNDECLARED
    assert raised.value.pointer == '/sources'
    with pytest.raises(ResetRecoveryRefused) as raised:
        declare_reset_recovery(runner, policy='warm_all', sources=dict(sessions))
    assert raised.value.code == CODE_UNDECLARED
    assert raised.value.pointer == '/bindings'
    assert CODE_UNDECLARED in REFUSAL_CODES
    runner.finalize()


def test_a_provider_without_the_declared_state_reader_is_refused():
    runner, sessions, memory = _runner()
    with pytest.raises(ResetRecoveryRefused) as raised:
        declare_reset_recovery(runner, policy='warm_all', sources=dict(sessions),
                               providers={'bad': object()})
    assert raised.value.code == CODE_UNDECLARED
    assert raised.value.pointer == '/providers/bad'
    runner.finalize()


def test_a_carrier_without_submit_is_refused_at_declaration():
    runner, sessions, memory = _runner()
    with pytest.raises(ResetRecoveryRefused) as raised:
        declare_reset_recovery(runner, policy='warm_all', sources=dict(sessions),
                               authority=_Authority(sessions['cpu']),
                               carrier=object())
    assert raised.value.code == CODE_UNDECLARED
    assert raised.value.pointer == '/carrier'
    runner.finalize()


def test_slot_continuation_without_a_declared_carrier_is_refused():
    recovery, runner, sessions, authority, provider = _declared(carrier=False, rearm=True)
    runner.reset_all('warm_all')
    recovery.observe()
    with pytest.raises(ResetRecoveryRefused) as raised:
        recovery.continue_slot(F6_RECORD, flow='F6')
    assert raised.value.code == CODE_UNDECLARED
    assert raised.value.pointer == '/slot_continuation'
    document = recovery.document()
    assert document['slot_continuation']['status'] == UNDECLARED
    runner.finalize()


def test_a_carrier_refusal_is_typed_and_explicitly_unavailable():
    recovery, runner, sessions, authority, provider = _declared(rearm=True)
    runner.reset_all('warm_all')
    recovery.observe()
    carrier = recovery._carrier
    with pytest.raises(ResetRecoveryRefused) as raised:
        recovery.continue_slot(F6_RECORD, flow='F6')
    assert raised.value.code == CODE_UNSUPPORTED
    assert raised.value.code in REFUSAL_CODES
    assert raised.value.detail['carrier_code'] == CARRIER_CODE
    assert carrier.calls == [(F6_RECORD, 'F6')]
    continuation = recovery.document()['slot_continuation']
    assert continuation == {'status': UNAVAILABLE, 'carrier': '_Carrier',
                            'operation': 'submit:F6', 'code': CARRIER_CODE}
    json.dumps(recovery.document())
    runner.finalize()


def test_a_non_passing_carrier_document_is_never_a_continuation():
    recovery, runner, sessions, authority, provider = _declared(rearm=True)
    recovery._carrier = _Carrier('incomplete')
    runner.reset_all('warm_all')
    recovery.observe()
    with pytest.raises(ResetRecoveryRefused) as raised:
        recovery.continue_slot(F6_RECORD, flow='F6')
    assert raised.value.code == CODE_UNSUPPORTED
    assert recovery.document()['slot_continuation']['status'] == UNAVAILABLE
    runner.finalize()


def test_a_passing_carrier_document_is_bound_to_the_new_epoch():
    recovery, runner, sessions, authority, provider = _declared(rearm=True)
    recovery._carrier = _Carrier('pass')
    runner.reset_all('warm_all')
    recovery.observe()
    continuation = recovery.continue_slot(F6_RECORD, flow='F6')
    assert continuation == {'status': CONTINUATION_VERIFIED, 'carrier': '_Carrier',
                            'reset_epoch': 1, 'flow': 'F6', 'carrier_status': 'passed'}
    assert recovery.document()['slot_continuation']['status'] == CONTINUATION_VERIFIED
    runner.finalize()


def test_observing_before_any_measured_barrier_is_refused():
    recovery, runner, sessions, authority, provider = _declared(rearm=True)
    with pytest.raises(ResetRecoveryRefused) as raised:
        recovery.observe()
    assert raised.value.code == CODE_UNDECLARED
    assert raised.value.pointer == '/barrier'
    runner.finalize()


def test_a_barrier_with_the_wrong_policy_is_refused():
    recovery, runner, sessions, authority, provider = _declared(policy='cold_all', rearm=True)
    runner.reset_all('warm_all')
    with pytest.raises(ResetRecoveryRefused) as raised:
        recovery.observe()
    assert raised.value.code == CODE_DRIFT
    assert raised.value.pointer == '/barrier/policy'
    runner.finalize()


def test_two_measured_barriers_are_refused():
    recovery, runner, sessions, authority, provider = _declared(rearm=True)
    runner.reset_all('warm_all')
    runner.reset_all('warm_all')
    with pytest.raises(ResetRecoveryRefused) as raised:
        recovery.observe()
    assert raised.value.code == CODE_DRIFT
    assert raised.value.pointer == '/barrier'
    runner.finalize()


def test_a_declaration_that_does_not_cover_the_live_sessions_is_refused():
    runner, sessions, memory = _runner()
    with pytest.raises(ValueError) as raised:
        declare_reset_recovery(runner, policy='warm_all',
                               sources={'cpu': object()},
                               authority=_Authority(sessions['cpu']))
    assert 'declared runner session' in str(raised.value)
    runner.finalize()


# --------------------------------------------------------------------------- #
# The declaration must keep the real shapes it calls
# --------------------------------------------------------------------------- #

def test_the_real_authority_exposes_the_epoch_scoped_calls_the_recovery_makes():
    from myfuzz.scenario.gpio_register_version import GpioRegisterVersionAuthority
    issue = inspect.signature(GpioRegisterVersionAuthority.issue)
    assert issue.parameters['register'].kind is inspect.Parameter.KEYWORD_ONLY
    assert issue.parameters['reset_epoch'].kind is inspect.Parameter.KEYWORD_ONLY
    consume = inspect.signature(GpioRegisterVersionAuthority.consume)
    assert list(consume.parameters) == ['self', 'token']
    handles = [name for name in ('current_state', 'observe_case')]
    from myfuzz.search.shared_slot_ram import _Installation as RamInstallation
    from myfuzz.search.shared_slot_pin_read import _Installation as PinInstallation
    for installation in (RamInstallation, PinInstallation):
        for name in handles:
            assert callable(getattr(installation, name, None))


def test_the_recovery_document_grants_no_authority():
    recovery, runner, sessions, authority, provider = _declared(rearm=True)
    runner.reset_all('warm_all')
    document = recovery.observe()
    assert document['grants_storage'] is False
    assert document['grants_version_dependency'] is False
    assert document['grants_functional'] is False
    assert document['grants_reward'] is False
    runner.finalize()


def test_a_second_observation_is_a_programming_error():
    recovery, runner, sessions, authority, provider = _declared(rearm=True)
    runner.reset_all('warm_all')
    recovery.observe()
    with pytest.raises(ValueError) as raised:
        recovery.observe()
    assert 'already observed' in str(raised.value)
    runner.finalize()
