"""The declared continuation chain in software: barrier -> epoch+1 -> entry ->
relaunch -> providers/authority -> one slot.

The carrier here is a declared double of the compiled runtime: it exposes the
real build/launch audit (``BuiltProcessAudit``) and the real ``submit(record,
flow=...)`` contract, and it refuses a post-reset submit until a relaunch is
bound to the measured barrier - which is exactly what the compiled carrier does
today.  It is not an RTL run: the slot "execution" is a passing document of the
declared shape, so the chain is proven, not native-verified.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from types import SimpleNamespace

import pytest

from myfuzz.integration.compiled_build_join import built_receipt_sha256
from myfuzz.integration.compiled_process_audit import BuiltProcessAudit
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.native_reset_recovery import (
    CODE_DRIFT, CODE_UNDECLARED, REINSTALLED, UNAVAILABLE, ResetRecoveryRefused,
    declare_reset_recovery)
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from scripts.run_reset_recovery_native import classify_outcome
from tests.scenario.test_native_reset_recovery import _Authority, _Provider, _Session

F6_RECORD = bytes.fromhex('0110c00008000000')
STALE_CARRIER_CODE = 'compiled-F6-built-process-identity-changed'


def _digest(label):
    return sha256(label.encode()).hexdigest()


def _artifact(name):
    return SimpleNamespace(runtime_document=dict(artifact_digest=_digest(name + ':artifact')),
                           plan=SimpleNamespace(request=SimpleNamespace(instance_id=name)))


def _receipt(artifact):
    identity = dict(schema_version='local_harness_build_identity.v1',
                    artifact_digest=artifact.runtime_document['artifact_digest'],
                    profile_sha256=_digest('profile'), facts_sha256=_digest('facts'))
    identity['build_digest'] = built_receipt_sha256(identity)
    return dict(schema_version='local_harness_built_receipt.v1',
                artifact_digest=identity['artifact_digest'],
                build_digest=identity['build_digest'],
                build_identity=identity, binary_sha256=_digest('binary'))


class _LiveProcess:
    """A process whose liveness the test can really end."""

    _next = 8100

    def __init__(self, returncode=None):
        _LiveProcess._next += 1
        self.pid = _LiveProcess._next
        self.returncode = returncode

    def poll(self):
        return self.returncode


class _AuditedSession(_Session):
    """A persistent session that is also a built session with launch rows."""

    def __init__(self, memory, name):
        super().__init__(memory, name)
        self.artifact = _artifact(name)
        self.receipt = _receipt(self.artifact)
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
        super().begin_case(testcase_id)
        self.process = _LiveProcess()
        self._append_launch()

    def reset_local(self):
        """The real reset: end the actual child, advance the epoch, relaunch it."""
        self.end_case()
        self.reset_epoch += 1
        self.begin_case(self.name + ':reset:' + str(self.reset_epoch))
        return {'cancelled_responses': 0, 'cancelled_target_requests': ()}


class _EpochCarrier(BuiltProcessAudit):
    """Declared double of the compiled carrier: audit pins + one slot submit."""

    _audit_error_prefix = 'compiled-F6'

    def __init__(self, runner, *, next_slot, slot_count, cpu_id='cpu'):
        self.runner = runner
        self.cpu_id = cpu_id
        self._build_sessions = dict(runner.sessions)
        self.artifacts = {name: local.artifact
                          for name, local in self._build_sessions.items()}
        self._built_receipts = {name: local.validate_built_executable_receipt()
                                for name, local in self._build_sessions.items()}
        self._native_processes = {name: local.process
                                  for name, local in self._build_sessions.items()}
        self._epoch_launch = None
        self.finished = False
        self._process_identities = self._validated_build_process_identities()
        self.next_slot = next_slot
        self.slot_count = slot_count
        self.submissions = []
        self.epoch_program = None

    def submit(self, record, *, flow='F6'):
        """The real carrier's precondition: a relaunch bound to this epoch."""
        if self._epoch_launch is None:
            raise ValueError(STALE_CARRIER_CODE)
        if flow != 'F6' or record != F6_RECORD:
            raise ValueError('compiled-F6-unsupported-flow')
        if not 0 <= self.next_slot < self.slot_count:
            raise ValueError('shared-F4-F6-slot-budget')
        self.submissions.append(dict(record=record.hex(), flow=flow,
                                     slot_index=self.next_slot,
                                     reset_epoch=self._epoch_launch['reset_epoch']))
        return {'status': 'passed', 'case_id': 'continuation',
                'slot_index': self.next_slot,
                'reset_epoch': self._epoch_launch['reset_epoch'],
                'epoch_program': self.epoch_program}


def contract(slot_count=4):
    """The F6 execution contract the per-epoch program is rendered from."""
    return dict(program_contract=dict(schema_version='compiled_F6_program.v1',
        boot_address=0x10080, isr_address=0x1022c, park_address=0x10400,
        slot_base=0x11000, slot_count=slot_count, source_address=0x22804,
        destination_address=0x23808, result_base=0x2480c,
        slot_bytes=256, online_prefix_bytes=128, result_stride=24,
        operand_instruction_offsets=[40, 48, 56, 64],
        initial_image=[], initial_image_sha256=None, instruction_source_id='cpu.image'),
        control=dict(base=0x40000800), dma=dict(csr=dict(
            offsets=dict(control=0, length=4, source=8, destination=12),
            configuration_order=['source', 'destination', 'length', 'control'],
            start_key=0xfed, start_word=0x0fed0004, length_words=4, block_words=4,
            increment_source=True, increment_destination=True,
            source_destination_units='byte_address_shift_right_2',
            master_address_units='word', master_byte_enable=15, status_error_mask=0x40000000)))


def _chain(*, next_slot=2, slot_count=4, rearm=True):
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x1000),),
                              initialization_seed=5, max_initialized_bytes=0x1000)
    sessions = {'cpu': _AuditedSession(memory, 'cpu'),
                'peripheral': _AuditedSession(memory, 'peripheral')}
    runner = ScenarioRunner(sessions=sessions, ownership=compile_ownership(
        (InputField('cpu', 'pin', 1),),
        (InputOwner('cpu', 'pin', 0, 1, 'source', 'external'),)), bindings=())
    runner.begin_test('reset-continuation')
    session = sessions['peripheral']
    authority = _Authority(session)
    authority.arm()
    provider = _Provider('RAM', session)
    provider.arm()
    carrier = _EpochCarrier(runner, next_slot=next_slot, slot_count=slot_count)
    kwargs = dict(policy='warm_all', sources=dict(sessions),
                  providers={'RAM': provider}, authority=authority,
                  carrier=carrier, register='GPIOEN')
    if rearm:
        kwargs['rearm'] = {'session': 'peripheral', 'operation': 'ACCESS_GPIO',
                           'fields': (0,)}
        session.on_command = lambda target: (authority.arm(), provider.arm())
    recovery = declare_reset_recovery(runner, **kwargs)
    return recovery, runner, sessions, authority, provider, carrier


class _ResetAwareProvider:
    def __init__(self, carrier, session, *, fail=False):
        self.carrier=carrier;self.session=session;self.fail=fail;self.calls=[]
    def rebind_after_reset(self, *, barrier_event_id):
        assert self.carrier._native_processes['peripheral'] is self.session.process
        self.calls.append(barrier_event_id)
        if self.fail:raise ValueError('test-rebind-failed')
    def current_state(self):
        return {'status':'unknown','reason':'no-post-reset-sample'}


def test_rebound_provider_is_not_claimed_observed_without_new_evidence():
    recovery,runner,sessions,authority,_,carrier=_chain(rearm=False)
    provider=_ResetAwareProvider(carrier,sessions['peripheral'])
    recovery._providers={'RAM':provider}
    runner.reset_all('warm_all')
    document=recovery.observe()
    assert provider.calls==[document['barrier']['event_id']]
    assert document['providers'][0]['binding_status']=='reinstalled'
    assert document['providers'][0]['status']=='unavailable'
    assert document['providers'][0]['reason']=='no-post-reset-sample'
    runner.finalize()


def test_provider_rebind_failure_and_unauthenticated_relaunch_are_reported():
    recovery,runner,sessions,authority,_,carrier=_chain(rearm=False)
    provider=_ResetAwareProvider(carrier,sessions['peripheral'],fail=True)
    recovery._providers={'RAM':provider}
    runner.reset_all('warm_all')
    doc=recovery.observe()
    assert doc['providers'][0]['binding_status']=='unavailable'
    assert doc['providers'][0]['reason']=='test-rebind-failed'
    runner.finalize()
    recovery,runner,sessions,authority,_,carrier=_chain(rearm=False)
    provider=_ResetAwareProvider(carrier,sessions['peripheral'])
    recovery._providers={'RAM':provider}
    runner.reset_all('warm_all')
    sessions['peripheral'].process.returncode=0
    doc=recovery.observe()
    assert provider.calls==[]
    assert doc['providers'][0]['binding_status']=='unavailable'
    assert doc['providers'][0]['reason']=='relaunch-not-reinstalled'
    runner.finalize()


def test_one_provider_failure_does_not_hide_another_new_epoch_observation():
    recovery,runner,sessions,authority,_,carrier=_chain(rearm=False)
    failed=_ResetAwareProvider(carrier,sessions['peripheral'],fail=True)
    live=_ResetAwareProvider(carrier,sessions['peripheral'])
    live.current_state=lambda:{'status':'observed','reset_epoch':1}
    recovery._providers={'RAM':failed,'PIN':live}
    runner.reset_all('warm_all')
    doc=recovery.observe()
    assert doc['providers'][0]['binding_status']=='unavailable'
    assert doc['providers'][1]=={'name':'PIN','status':'reinstalled',
        'reset_epoch':1,'source':'current_state','binding_status':'reinstalled'}
    assert len(live.calls)==1
    runner.finalize()


# --------------------------------------------------------------------------- #
# The full declared chain
# --------------------------------------------------------------------------- #

def test_the_declared_chain_completes_one_slot_execution_in_the_new_epoch():
    recovery, runner, sessions, authority, provider, carrier = _chain()
    recovery.declare_epoch_program(contract=contract(), next_slot=2)
    first = {name: local.process.pid for name, local in sessions.items()}
    reset = runner.reset_all('warm_all')
    document = recovery.observe()

    assert reset.policy == 'warm_all'
    assert document['status'] == REINSTALLED
    assert document['epoch'] == {'before': {'cpu': 0, 'peripheral': 0}, 'after': 1,
                                 'advanced': True}
    # 1. the new epoch renders the same islands with an entry at the next slot
    program = document['program']
    assert program['status'] == REINSTALLED
    assert program['entry']['reset_epoch'] == 1
    assert program['entry']['slot'] == 2
    assert program['entry']['entry_address'] == 0x11000 + 256*2
    assert program['image_changed'] is True
    assert program['manifest_sha256'] != program['previous_manifest_sha256']
    assert program['contract_image_sha256'] == program['manifest_sha256']
    # 2. the relaunch the barrier produced is accepted, bound to this epoch
    relaunch = document['relaunch']
    assert relaunch['status'] == REINSTALLED
    assert relaunch['reset_epoch'] == 1 and relaunch['launch_index'] == 1
    assert relaunch['barrier_event_id'] == document['barrier']['event_id']
    for name, row in relaunch['identities'].items():
        assert row['pid'] == sessions[name].process.pid != first[name]
    # 3. the providers and the authority are re-installed for the new epoch
    assert document['providers'] == [{'name': 'RAM', 'status': REINSTALLED,
                                      'reset_epoch': 1, 'source': 'current_state'}]
    assert document['authority']['status'] == REINSTALLED
    # 4. one slot case really completes in the new epoch, on that entry
    carrier.epoch_program = {'manifest_sha256': program['manifest_sha256'],
                             'entry': program['entry']}
    continuation = recovery.continue_slot(F6_RECORD, flow='F6')
    assert continuation['status'] == 'verified'
    assert continuation['reset_epoch'] == 1
    assert continuation['program']['entry']['slot'] == 2
    assert continuation['program']['manifest_sha256'] == program['manifest_sha256']
    assert carrier.submissions == [{'record': F6_RECORD.hex(), 'flow': 'F6',
                                    'slot_index': 2, 'reset_epoch': 1}]
    assert recovery.document()['slot_continuation'] == continuation
    assert classify_outcome(recovery.document(), continuation) == (
        'verified', 'one more slot case executed in the new epoch')
    runner.finalize()


def test_a_continuation_without_a_declared_epoch_entry_is_never_a_pass():
    recovery, runner, sessions, authority, provider, carrier = _chain()
    # no declare_epoch_program(): the carrier still accepts the relaunch, so the
    # only thing missing is the declared entry - and that must not be a pass.
    runner.reset_all('warm_all')
    document = recovery.observe()
    assert document['program'] == {'status': 'undeclared',
                                   'reason': 'no per-epoch program was declared'}
    continuation = recovery.continue_slot(F6_RECORD, flow='F6')
    assert 'program' not in continuation
    outcome, detail = classify_outcome(document, continuation)
    assert outcome == 'mismatch' and 'program entry' in detail
    runner.finalize()


def test_the_declared_next_slot_is_the_one_the_ledger_would_use():
    recovery, runner, sessions, authority, provider, carrier = _chain(next_slot=3,
                                                                     slot_count=4)
    recovery.declare_epoch_program(contract=contract(), next_slot=3)
    runner.reset_all('warm_all')
    document = recovery.observe()
    assert document['program']['entry']['entry_address'] == 0x11000 + 256*3
    carrier.epoch_program = {'manifest_sha256': document['program']['manifest_sha256'],
                             'entry': document['program']['entry']}
    continuation = recovery.continue_slot(F6_RECORD, flow='F6')
    assert continuation['program']['entry']['slot'] == carrier.submissions[0]['slot_index'] == 3
    runner.finalize()


def test_declared_program_is_not_claimed_as_executed_without_carrier_receipt():
    recovery, runner, sessions, authority, provider, carrier = _chain()
    recovery.declare_epoch_program(contract=contract(), next_slot=2)
    runner.reset_all('warm_all')
    recovery.observe()
    with pytest.raises(ResetRecoveryRefused):
        recovery.continue_slot(F6_RECORD, flow='F6')
    assert recovery.document()['slot_continuation']['status'] == 'unavailable'
    runner.finalize()


@pytest.mark.parametrize('matching',[True,False])
def test_actual_f6_carrier_requires_live_recomputed_epoch_evidence(monkeypatch,matching):
    from myfuzz.integration import compiled_f6
    recovery,runner,sessions,authority,_,carrier=_chain()
    recovery.declare_epoch_program(contract=contract(),next_slot=2)
    runner.reset_all('warm_all');doc=recovery.observe()
    epoch=doc['program']
    proof=dict(manifest_sha256=epoch['manifest_sha256'],entry=epoch['entry'],
               evidence=dict(image_event_id=2,boot_read_event_id=3,
                             boot_response_event_id=4,boot_retirement_event_id=5,
                             slot_fetch_event_id=6))
    result=dict(status='passed',epoch_program=proof)
    runtime=object.__new__(compiled_f6.CompiledF6Runtime)
    monkeypatch.setattr(compiled_f6.CompiledF6Runtime,'submit',lambda *a,**kw:result)
    monkeypatch.setattr(compiled_f6,'_f6_epoch_execution_receipt',
        lambda carrier,result:proof if matching else None)
    recovery._carrier=runtime
    recovery._carrier_rebind_row={'status':REINSTALLED}
    if matching:
        assert recovery.continue_slot(F6_RECORD,flow='F6')['program']==proof
    else:
        with pytest.raises(ResetRecoveryRefused):
            recovery.continue_slot(F6_RECORD,flow='F6')
        assert recovery.document()['slot_continuation']['status']==UNAVAILABLE
    runner.finalize()


# --------------------------------------------------------------------------- #
# Refusals along the chain
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize('next_slot,slot_count', [(0, 4), (4, 4), (-1, 4), (1, 1)])
def test_a_next_slot_the_epoch_could_not_enter_is_refused_at_declaration(
        next_slot, slot_count):
    recovery, runner, sessions, authority, provider, carrier = _chain(
        next_slot=next_slot, slot_count=slot_count)
    with pytest.raises(ResetRecoveryRefused) as raised:
        recovery.declare_epoch_program(contract=contract(slot_count), next_slot=next_slot)
    assert raised.value.code == CODE_UNDECLARED
    assert raised.value.pointer == '/program/next_slot'
    runner.reset_all('warm_all')
    document = recovery.observe()
    assert document['program']['status'] == 'undeclared'
    runner.finalize()


def test_a_program_declared_after_the_barrier_is_refused():
    recovery, runner, sessions, authority, provider, carrier = _chain()
    runner.reset_all('warm_all')
    recovery.observe()
    with pytest.raises(ValueError, match='before the barrier'):
        recovery.declare_epoch_program(contract=contract(), next_slot=2)
    runner.finalize()


def test_a_program_declared_twice_is_refused():
    recovery, runner, sessions, authority, provider, carrier = _chain()
    recovery.declare_epoch_program(contract=contract(), next_slot=2)
    with pytest.raises(ValueError, match='already declared'):
        recovery.declare_epoch_program(contract=contract(), next_slot=2)
    runner.finalize()


def test_a_contract_whose_pin_does_not_describe_the_program_is_refused():
    recovery, runner, sessions, authority, provider, carrier = _chain()
    pinned = contract()
    pinned['program_contract']['initial_image_sha256'] = '0'*64
    with pytest.raises(ValueError, match='initial-image-drift'):
        recovery.declare_epoch_program(contract=pinned, next_slot=2)
    runner.finalize()


def test_a_relaunch_the_audit_cannot_authenticate_leaves_the_chain_unavailable():
    recovery, runner, sessions, authority, provider, carrier = _chain()
    recovery.declare_epoch_program(contract=contract(), next_slot=2)
    runner.reset_all('warm_all')
    sessions['peripheral'].process.returncode = 0     # the relaunch died at once
    document = recovery.observe()
    assert document['relaunch'] == {
        'status': UNAVAILABLE, 'reason': 'compiled-F6-native-process-not-live',
        'barrier_event_id': document['barrier']['event_id']}
    assert document['status'] == UNAVAILABLE
    with pytest.raises(ResetRecoveryRefused) as raised:
        recovery.continue_slot(F6_RECORD, flow='F6')
    assert raised.value.code == 'generic-semantic-unsupported'
    continuation = recovery.document()['slot_continuation']
    assert continuation['status'] == 'unavailable'
    assert continuation['code'] == STALE_CARRIER_CODE
    outcome, detail = classify_outcome(recovery.document(), continuation)
    assert outcome == 'unavailable'      # the declared blocker, never a pass
    assert STALE_CARRIER_CODE in detail
    runner.finalize()


def test_a_carrier_without_the_compiled_audit_declares_nothing_it_cannot_do():
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x1000),),
                              initialization_seed=5, max_initialized_bytes=0x1000)
    sessions = {'cpu': _Session(memory, 'cpu')}
    runner = ScenarioRunner(sessions=sessions, ownership=compile_ownership(
        (InputField('cpu', 'pin', 1),),
        (InputOwner('cpu', 'pin', 0, 1, 'source', 'external'),)), bindings=())
    runner.begin_test('reset-continuation-plain-carrier')

    class _Plain:
        def submit(self, record, *, flow='F6'):
            raise ValueError(STALE_CARRIER_CODE)

    recovery = declare_reset_recovery(runner, policy='warm_all',
                                      sources=dict(sessions), authority=_Authority(
                                          sessions['cpu']), carrier=_Plain())
    assert recovery.document()['relaunch'] == {
        'status': 'undeclared', 'reason': 'the carrier has no compiled launch audit'}
    runner.reset_all('warm_all')
    document = recovery.observe()
    assert document['relaunch']['status'] == 'undeclared'
    assert document['program']['status'] == 'undeclared'
    with pytest.raises(ResetRecoveryRefused) as raised:
        recovery.continue_slot(F6_RECORD, flow='F6')
    assert raised.value.code == 'generic-semantic-unsupported'
    assert recovery.document()['slot_continuation'] == {
        'status': 'unavailable', 'carrier': '_Plain', 'operation': 'submit:F6',
        'code': STALE_CARRIER_CODE}
    runner.finalize()
