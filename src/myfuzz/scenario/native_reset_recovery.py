"""Declared, epoch-scoped reset recovery for one persistent native session.

A measured reset (``ScenarioRunner.reset_all``) is not an epoch counter bump: it
ends every actual RTL process, relaunches it, advances every session's
``reset_epoch``, advances the runner's command epoch and applies a warm/cold
memory policy.  A persistent session that means to keep going after that barrier
must re-establish, **for the new epoch**, the three binding kinds it declared
before the barrier:

``provider``
    the objects that issued pre-reset credit (an installed observation provider
    with ``current_state()``);
``authority``
    the live storage/register version authority that issues epoch-scoped tokens
    (``issue(register=..., reset_epoch=...)`` / ``consume(token)``);
``sources``
    the declared live sessions (the persistent RTL instances).

This module does exactly that and nothing else:

* the declaration is captured before the barrier and is authenticated against
  the live runner (session identity, reset epoch, process, execution, command
  epoch, memory generations);
* after the barrier it re-installs each declared binding *bound to the new
  epoch*, and it records per binding whether the re-install really happened or
  why it could not (a provider that still reports the old epoch, an authority
  that needs a new actual command first, a memory policy that did not apply);
* it fences the old epoch: an old-epoch credit is refused, an old identity is
  refused, and the same numeric token observed in the new epoch is reported as
  a new-epoch observation (``lineage: false``), never as lineage;
* slot continuation is *not* implied.  The declared carrier is asked once, and
  its own refusal is surfaced as a typed refusal plus the explicit
  ``unavailable`` status - never converted into a pass.

Two optional declarations make the continuation *attempt* real rather than
assumed, and both are off unless declared:

``program``
    ``{'contract': <F6 execution contract>, 'next_slot': <int>}``.  After the
    barrier the recovery renders that epoch's program (same island layout, same
    slot payloads, boot entry at the declared next slot;
    ``myfuzz.integration.compiled_f6_firmware.render_epoch_program``) and records
    the entry rule, the new manifest digest and the fact that the image really
    changed.  The declared next slot can never be slot 0: that window's
    instruction bytes are already materialized with a pre-reset case payload, so
    re-entering it would replay a pre-reset case instead of continuing.
``relaunch``
    implied by the declared carrier when it is a compiled runtime: the recovery
    asks ``myfuzz.integration.compiled_process_audit.bind_reset_epoch_launch`` to
    bind the relaunch the barrier produced, and records the accepted launch index
    and identity or the audit's own refusal code.

Every refusal reuses the closed generic refusal vocabulary
(``myfuzz.runtime.contracts.REFUSAL_CODES``): ``generic-evidence-missing`` when
a re-install was not declared, ``generic-binding-drift`` when the live state did
not make the declared transition, and ``generic-semantic-unsupported`` when the
declared carrier cannot continue slot execution in the new epoch.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json

from myfuzz.runtime.contracts import GenericRuntimeRefused, REFUSAL_CODES

SCHEMA_VERSION = 'native_reset_recovery.v1'
CREDIT_SCHEMA_VERSION = 'native_reset_credit.v1'
POLICIES = ('warm_all', 'cold_all')

#: Status vocabulary: a binding is either really re-installed, explicitly
#: unavailable (with the refusing party's own reason), or not declared at all.
REINSTALLED = 'reinstalled'
UNAVAILABLE = 'unavailable'
UNDECLARED = 'undeclared'
CONTINUATION_VERIFIED = 'verified'

CODE_UNDECLARED = 'generic-evidence-missing'
CODE_DRIFT = 'generic-binding-drift'
CODE_UNSUPPORTED = 'generic-semantic-unsupported'
if not {CODE_UNDECLARED, CODE_DRIFT, CODE_UNSUPPORTED} <= REFUSAL_CODES:
    raise ValueError('reset recovery refusal vocabulary drift')

#: Read states a provider may report after a successful re-install.
_PROVIDER_LIVE_STATES = ('observed', 'verified', 'complete')


class ResetRecoveryRefused(GenericRuntimeRefused):
    """A declared binding could not be re-established for the new reset epoch."""

    def __init__(self, code, pointer='', detail=None):
        super().__init__(code, pointer, detail)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False)


def _digest(value):
    return sha256(_canonical(value).encode()).hexdigest()


def _uint(value):
    return type(value) is int and value >= 0


def _document_value(value):
    """A JSON-safe rendering of one credential (an opaque value stays private)."""
    try:
        json.dumps(value)
    except (TypeError, ValueError):
        return 'opaque'
    return value


def _scope_document(scope):
    component, epoch, token = scope
    return {'component': component, 'reset_epoch': epoch,
            'token': _document_value(token)}


def declare_reset_recovery(runner, *, policy, sources, providers=None, authority=None,
                           carrier=None, register='GPIOEN', rearm=None, program=None):
    """Declare, before the barrier, the bindings a reset must re-install."""
    return ResetRecovery(runner, policy=policy, sources=sources, providers=providers,
                         authority=authority, carrier=carrier, register=register,
                         rearm=rearm, program=program)


class ResetRecovery:
    """One declared recovery for one measured reset of one persistent session."""

    def __init__(self, runner, *, policy, sources, providers=None, authority=None,
                 carrier=None, register='GPIOEN', rearm=None, program=None):
        from .runner import ScenarioRunner
        if type(runner) is not ScenarioRunner or runner._status != 'running':
            raise ValueError('reset recovery requires one running actual runner')
        if policy not in POLICIES:
            raise ValueError('reset recovery requires the measured warm_all/cold_all policy')
        if type(register) is not str or not register.strip():
            raise ValueError('reset recovery requires the declared authority register name')
        if not isinstance(sources, dict) or not sources:
            raise ResetRecoveryRefused(CODE_UNDECLARED, '/sources',
                                       {'declared': 'no source session was declared'})
        if providers is None:
            declared = {}
        elif not isinstance(providers, dict):
            raise ValueError('reset recovery providers must be a mapping')
        else:
            declared = dict(providers)
        if authority is None and not declared:
            raise ResetRecoveryRefused(CODE_UNDECLARED, '/bindings',
                                       {'declared': 'no provider and no authority declared'})
        for name, provider in declared.items():
            if type(name) is not str or not name:
                raise ValueError('reset recovery provider name invalid')
            if not callable(getattr(provider, 'current_state', None)):
                raise ResetRecoveryRefused(CODE_UNDECLARED, '/providers/' + name,
                                           {'declared': 'provider has no current_state()'})
        if authority is not None and not callable(getattr(authority, 'issue', None)):
            raise ResetRecoveryRefused(CODE_UNDECLARED, '/authority',
                                       {'declared': 'authority has no epoch-scoped issue()'})
        if carrier is not None and not callable(getattr(carrier, 'submit', None)):
            raise ResetRecoveryRefused(CODE_UNDECLARED, '/carrier',
                                       {'declared': 'carrier has no submit()'})
        self._rearm = self._declare_rearm(rearm, sources)
        self._program = self._declare_program(program)
        for name, session in sources.items():
            if type(name) is not str or not name or runner.sessions.get(name) is not session:
                raise ValueError('reset recovery source must be the declared runner session:' + str(name))
            if not _uint(getattr(session, 'reset_epoch', None)):
                raise ValueError('reset recovery source has no reset epoch:' + name)
        self._runner = runner
        self._policy = policy
        self._register = register
        self._sources = dict(sources)
        self._providers = declared
        self._authority = authority
        self._carrier = carrier
        self._cursor = runner.event_count
        self._declared_epoch = {name: session.reset_epoch for name, session in sources.items()}
        self._declared_process = {name: getattr(session, 'process', None) for name, session in sources.items()}
        self._declared_execution = {name: getattr(session, '_execution', None) for name, session in sources.items()}
        self._declared_command_epoch = runner.command_epoch
        self._declared_generations = self._generations()
        self._pre_epoch = sorted(set(self._declared_epoch.values()))
        self._pre_scopes = []
        self._pre_token_keys = set()
        self._pre_identity_keys = []
        self._seen_scopes = set()
        self._seen_identity_keys = set()
        self._pre_authority_token = None
        self._rearm_row = None
        self._observed = None
        self._epoch_program = None
        self._program_manifest = self._declared_manifest()
        self._continuation = {'status': UNDECLARED, 'reason': 'no slot continuation was attempted'}
        self._authority_row = ({'status': 'declared', 'reset_epoch': None}
                               if authority is not None
                               else {'status': UNDECLARED,
                                     'reason': 'no authority declared'})
        self._provider_rows = [{'name': name, 'status': UNDECLARED,
                                'reason': 'not re-installed yet'} for name in declared]
        self._program_row = ({'status': UNDECLARED,
                              'reason': 'no per-epoch program was declared'}
                             if self._program is None else
                             {'status': 'declared',
                              'next_slot': self._program['next_slot'],
                              'previous_manifest_sha256': self._program_manifest})
        self._carrier_rebind_row = {'status': UNDECLARED, 'reason': 'not attempted'}
        self._relaunch_row = ({'status': UNDECLARED,
                               'reason': 'the carrier has no compiled launch audit'}
                              if not isinstance(getattr(carrier, '_build_sessions', None), dict)
                              else {'status': 'declared', 'reason': 'not bound yet'})

    # ------------------------------------------------------------------ #
    # declaration
    # ------------------------------------------------------------------ #

    @staticmethod
    def _declare_rearm(rearm, sources):
        """One declared re-arm command, or nothing (no speculative retries)."""
        if rearm is None:
            return None
        if not isinstance(rearm, dict) or set(rearm) != {'session', 'operation', 'fields'}:
            raise ValueError('reset recovery re-arm declaration keys')
        name, operation, fields = rearm['session'], rearm['operation'], rearm['fields']
        if name not in sources or not callable(getattr(sources[name], 'command', None)):
            raise ValueError('reset recovery re-arm requires a declared source session command')
        if type(operation) is not str or not operation.strip():
            raise ValueError('reset recovery re-arm operation')
        if type(fields) is not tuple or any(not _uint(value) for value in fields):
            raise ValueError('reset recovery re-arm fields')
        return {'session': name, 'operation': operation, 'fields': tuple(fields)}

    def _generations(self):
        generations = {}
        for session in self._sources.values():
            memory = getattr(session, 'memory', None)
            if memory is None:
                continue
            for memory_id in memory.memory_ids:
                generations[memory_id] = memory.generation
        return generations

    @staticmethod
    def _declare_program(program):
        """One declared per-epoch program; the renderer owns the entry rule."""
        if program is None:
            return None
        if not isinstance(program, dict) or set(program) != {'contract', 'next_slot'}:
            raise ValueError('reset recovery program declaration keys')
        contract, next_slot = program['contract'], program['next_slot']
        if (not isinstance(contract, dict)
                or not isinstance(contract.get('program_contract'), dict)):
            raise ValueError('reset recovery program requires the F6 execution contract')
        slot_count = contract['program_contract'].get('slot_count')
        if type(slot_count) is not int or type(next_slot) is not int:
            raise ValueError('reset recovery program slot declarations')
        if not 1 <= next_slot < slot_count:
            # The renderer's declared rule: a later epoch never enters slot 0,
            # whose instruction window already holds a pre-reset case payload.
            raise ResetRecoveryRefused(CODE_UNDECLARED, '/program/next_slot', {
                'declared': 'a later epoch resumes at an unused slot', 'actual': next_slot,
                'slot_count': slot_count})
        return {'contract': deepcopy(contract), 'next_slot': next_slot}

    def _declared_manifest(self):
        """The pre-reset program's manifest, captured before the barrier."""
        if self._program is None:
            return None
        from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
        return build_f6_firmware(self._program['contract']).manifest_sha256

    def _declared_source(self, component):
        if component not in self._sources:
            raise ValueError('reset recovery credit names an undeclared source:' + str(component))
        return self._declared_epoch[component]

    def declare_epoch_program(self, *, contract, next_slot):
        """Declare, still before the barrier, the slot the new epoch resumes at."""
        if self._observed is not None:
            raise ValueError('reset recovery program must be declared before the barrier')
        if self._program is not None:
            raise ValueError('reset recovery program was already declared')
        program = self._declare_program({'contract': contract, 'next_slot': next_slot})
        self._program = program
        self._program_manifest = self._declared_manifest()
        self._program_row = {'status': 'declared', 'next_slot': program['next_slot'],
                             'previous_manifest_sha256': self._program_manifest}
        return dict(self._program_row)

    def reset_with_declared_program(self):
        """Reset the carrier session and install the declared next-slot boot image."""
        from .genome import MemoryImage
        from myfuzz.integration.compiled_f6_firmware import render_epoch_program
        session = getattr(self._carrier, 'session', None)
        if (self._observed is not None or self._program is None
                or session is None or session.runner is not self._runner
                or len(self._pre_epoch) != 1):
            raise ValueError('reset recovery requires a declared program and active carrier session')
        rendered = render_epoch_program(self._program['contract'],
            reset_epoch=self._pre_epoch[0] + 1, slot=self._program['next_slot'])
        address = self._program['contract']['program_contract']['boot_address']
        images = [image for image in session.template.initial_images if image.address == address]
        if len(images) != 1:
            raise ValueError('reset recovery requires the declared boot image')
        original = images[0]
        boot = rendered['program'].initial_images[address]
        image = MemoryImage(original.image_id, original.component, address, boot.hex())
        return session.reset(self._policy, image=image)

    def capture_authority_token(self):
        """Capture one real pre-reset authority token (the lineage negative control)."""
        if self._observed is not None:
            raise ValueError('reset recovery authority token must be captured before the barrier')
        if self._authority is None:
            return False
        epoch = self._declared_epoch[sorted(self._declared_epoch)[0]]
        try:
            self._pre_authority_token = self._authority.issue(register=self._register,
                                                              reset_epoch=epoch)
        except ValueError:
            self._pre_authority_token = None
            return False
        return True

    # ------------------------------------------------------------------ #
    # the measured barrier and the re-install
    # ------------------------------------------------------------------ #

    def observe(self, *, barrier_event_id=None):
        """Re-install every declared binding for the new epoch (once)."""
        if self._observed is not None:
            raise ValueError('reset recovery already observed the barrier')
        barrier = self._measured_barrier(barrier_event_id)
        new_epoch = self._new_epoch()
        if self._runner.command_epoch != self._declared_command_epoch + 1:
            raise ResetRecoveryRefused(CODE_DRIFT, '/command_epoch', {
                'declared': self._declared_command_epoch,
                'actual': self._runner.command_epoch})
        self._check_memory_policy()
        sources = [self._reinstall_source(name) for name in self._sources]
        self._rearm_row = None if self._rearm is None else self._run_rearm()
        self._program_row = self._render_epoch_program(new_epoch)
        self._relaunch_row = self._accept_relaunch(new_epoch, barrier)
        self._carrier_rebind_row = self._rebind_carrier(new_epoch, barrier)
        self._provider_rows = [self._reinstall_provider(name, provider,
                                                          barrier=barrier, relaunch=self._relaunch_row)
                               for name, provider in self._providers.items()]
        self._authority_row = self._reinstall_authority(new_epoch)
        reinstalled = (all(row['status'] == REINSTALLED for row in sources)
                       and all(row.get('binding_status', row['status']) == REINSTALLED
                               for row in self._provider_rows)
                       and self._authority_row['status'] == REINSTALLED
                       and all(row['status'] in (REINSTALLED, UNDECLARED)
                               for row in (self._program_row, self._relaunch_row,
                                           self._carrier_rebind_row)))
        self._observed = {
            'schema_version': SCHEMA_VERSION,
            'status': REINSTALLED if reinstalled else UNAVAILABLE,
            'policy': self._policy,
            'register': self._register,
            'barrier': barrier,
            'epoch': {'before': dict(self._declared_epoch), 'after': new_epoch,
                      'advanced': True},
            'command_epoch': {'before': self._declared_command_epoch,
                              'after': self._runner.command_epoch},
            'sources': sources,
            'program': dict(self._program_row),
            'relaunch': dict(self._relaunch_row),
            'carrier_rebind': dict(self._carrier_rebind_row),
            'providers': self._provider_rows,
            'authority': self._authority_row,
            'memory_generations': {'before': dict(self._declared_generations),
                                   'after': self._generations()},
            'lineage': {'old_epoch_fenced': True,
                        'pre_reset_tokens': [_scope_document(scope)
                                             for scope in self._pre_scopes],
                        'pre_reset_identities': [
                            {'component': component, 'identity': identity}
                            for component, identity in self._pre_identity_keys],
                        'authority_token_refused': self._authority_row.get(
                            'pre_reset_token_refused'),
                        'authority_token_stale_epoch': self._authority_row.get(
                            'pre_reset_token_stale_epoch'),
                        'token_reuse_across_epoch': [],
                        'join_semantics': (
                            'a credit is lineage only when its component, epoch and '
                            'identity all match a pre-barrier observation; the same '
                            'numeric token in the new epoch is a new scope')},
            'slot_continuation': dict(self._continuation),
            'grants_storage': False,
            'grants_version_dependency': False,
            'grants_functional': False,
            'grants_reward': False,
        }
        return self.document()

    def _measured_barrier(self, barrier_event_id):
        events = list(self._runner.events_since(self._cursor))
        barriers = [event for event in events if event.get('kind') == 'reset_barrier']
        if not barriers:
            raise ResetRecoveryRefused(CODE_UNDECLARED, '/barrier',
                                       {'declared': 'no measured reset barrier was recorded'})
        if len(barriers) != 1:
            raise ResetRecoveryRefused(CODE_DRIFT, '/barrier',
                                       {'measured': len(barriers)})
        barrier = barriers[0]
        if barrier.get('policy') != self._policy:
            raise ResetRecoveryRefused(CODE_DRIFT, '/barrier/policy', {
                'declared': self._policy, 'measured': barrier.get('policy')})
        if barrier_event_id is not None and barrier.get('event_id') != barrier_event_id:
            raise ResetRecoveryRefused(CODE_DRIFT, '/barrier/event_id', {
                'declared': barrier_event_id, 'measured': barrier.get('event_id')})
        generations = barrier.get('memory_generations')
        if not isinstance(generations, dict) or not generations:
            raise ResetRecoveryRefused(CODE_DRIFT, '/barrier/memory_generations',
                                       {'measured': 'no memory generation'})
        return {'event_id': barrier['event_id'], 'policy': barrier['policy'],
                'memory_generations': dict(generations),
                'cancelled_responses': dict(barrier.get('cancelled_responses') or {})}

    def _new_epoch(self):
        for name, session in self._sources.items():
            epoch = session.reset_epoch
            if epoch != self._declared_epoch[name] + 1:
                raise ResetRecoveryRefused(CODE_DRIFT, '/sources/' + name + '/reset_epoch', {
                    'declared': self._declared_epoch[name], 'actual': epoch})
        epochs = {session.reset_epoch for session in self._sources.values()}
        if len(epochs) != 1:
            raise ResetRecoveryRefused(CODE_DRIFT, '/sources', {'epochs': sorted(epochs)})
        expected = sorted(self._pre_epoch)
        if len(expected) != 1:
            raise ResetRecoveryRefused(CODE_DRIFT, '/sources', {
                'declared': 'every declared source must share one reset epoch'})
        return epochs.pop()

    def _check_memory_policy(self):
        """The declared warm/cold policy must be the one the barrier applied."""
        current = self._generations()
        if set(current) != set(self._declared_generations):
            raise ResetRecoveryRefused(CODE_DRIFT, '/memory_generations', {
                'declared': sorted(self._declared_generations),
                'actual': sorted(current)})
        delta = 1 if self._policy == 'cold_all' else 0
        for memory_id, generation in current.items():
            expected = self._declared_generations[memory_id] + delta
            if generation != expected:
                raise ResetRecoveryRefused(CODE_DRIFT, '/memory_generations/' + memory_id, {
                    'policy': self._policy, 'declared': expected, 'actual': generation})

    def _reinstall_source(self, name):
        session = self._sources[name]
        process = getattr(session, 'process', None)
        declared_process = self._declared_process[name]
        if declared_process is not None:
            if process is None or process is declared_process:
                raise ResetRecoveryRefused(CODE_DRIFT, '/sources/' + name + '/process', {
                    'declared': 'the reset must relaunch the actual RTL process'})
        execution = getattr(session, '_execution', None)
        if (self._declared_execution[name] is not None
                and execution == self._declared_execution[name]):
            raise ResetRecoveryRefused(CODE_DRIFT, '/sources/' + name + '/execution', {
                'declared': 'the reset must issue a fresh execution identity'})
        try:
            pid = None if process is None else process.pid
        except AttributeError:
            pid = None
        row = {'name': name, 'status': REINSTALLED, 'reset_epoch': session.reset_epoch,
               'execution': execution, 'pid': pid}
        row['binding_sha256'] = _digest({key: row[key] for key in
                                         ('name', 'reset_epoch', 'execution', 'pid')})
        return row

    def _render_epoch_program(self, new_epoch):
        """Render this epoch's program entry; the declared rule owns the address."""
        if self._program is None:
            return {'status': UNDECLARED, 'reason': 'no per-epoch program was declared'}
        from myfuzz.integration.compiled_f6_firmware import render_epoch_program
        try:
            rendered = render_epoch_program(self._program['contract'],
                                            reset_epoch=new_epoch,
                                            slot=self._program['next_slot'])
        except ValueError as error:
            return {'status': UNAVAILABLE, 'reason': str(error)}
        manifest = rendered['program'].manifest_sha256
        self._epoch_program = rendered
        return {'status': REINSTALLED, 'reset_epoch': new_epoch,
                'slot': self._program['next_slot'],
                'entry': rendered['entry'],
                'observation': 'rendered_only',
                'manifest_sha256': manifest,
                'previous_manifest_sha256': self._program_manifest,
                'image_changed': manifest != self._program_manifest,
                'contract_image_sha256': rendered['contract']['program_contract'][
                    'initial_image_sha256']}

    def _accept_relaunch(self, new_epoch, barrier):
        """Bind the relaunch this measured barrier produced, or record its refusal."""
        carrier = self._carrier
        if carrier is None or not isinstance(getattr(carrier, '_build_sessions', None), dict):
            return {'status': UNDECLARED,
                    'reason': 'the declared carrier has no compiled launch audit'}
        from myfuzz.integration.compiled_process_audit import bind_reset_epoch_launch
        try:
            binding = bind_reset_epoch_launch(
                carrier, reset_epoch=new_epoch,
                barrier_event_id=barrier['event_id'], policy=self._policy)
        except ValueError as error:
            return {'status': UNAVAILABLE, 'reason': str(error),
                    'barrier_event_id': barrier['event_id']}
        return {'status': REINSTALLED, 'reset_epoch': new_epoch,
                'barrier_event_id': binding['barrier_event_id'],
                'launch_index': binding['launch_index'],
                'identities': {name: {'pid': row['pid'],
                                      'execution_nonce': row['execution_nonce']}
                               for name, row in sorted(binding['identities'].items())}}

    def _rebind_carrier(self, new_epoch, barrier):
        """Bind the carrier only after the session installed the declared boot image."""
        carrier=self._carrier
        rebind=getattr(carrier,'rebind_reset_epoch',None)
        if not callable(rebind) or self._program is None:
            return {'status': UNDECLARED, 'reason': 'no declared epoch carrier'}
        if self._relaunch_row['status'] != REINSTALLED or self._epoch_program is None:
            return {'status': UNAVAILABLE, 'reason': 'program-or-relaunch-unavailable'}
        session=getattr(carrier,'session',None)
        from .session_runtime import ScenarioSession
        if type(session) is not ScenarioSession or session.runner is not self._runner:
            return {'status': UNAVAILABLE, 'reason': 'reset-session-required'}
        address=self._program['contract']['program_contract']['boot_address']
        expected=self._epoch_program['program'].initial_images[address]
        operations=session._reset_operations
        image=operations[-1].get('image') if operations else None
        events=[row for row in self._runner.events_since(barrier['event_id'])
                if row.get('kind')=='reset_image' and row.get('reset_event_id')==barrier['event_id']
                and row.get('address')==address and row.get('component')==carrier.cpu_id]
        if (not isinstance(image,dict) or image.get('address')!=address
                or image.get('component')!=carrier.cpu_id or image.get('data_hex')!=expected.hex()
                or len(events)!=1 or events[0].get('data_hex')!=expected.hex()):
            return {'status': UNAVAILABLE, 'reason': 'epoch-image-not-installed'}
        memory=getattr(self._runner.sessions[carrier.cpu_id],'memory',None)
        if memory is None or len(expected)%4:
            return {'status': UNAVAILABLE, 'reason': 'epoch-image-not-installed'}
        for offset in range(0,len(expected),4):
            try:
                snapshot=memory.read(address+offset,4,transaction_id='reset-recovery-image-check')
            except (ValueError,RuntimeError):
                return {'status': UNAVAILABLE, 'reason': 'epoch-image-not-installed'}
            if (snapshot.data!=expected[offset:offset+4]
                    or snapshot.writer_kinds!=('RESET_IMAGE',)*4
                    or snapshot.writer_event_ids!=(f"reset-image:{events[0]['event_id']}",)*4):
                return {'status': UNAVAILABLE, 'reason': 'epoch-image-not-installed'}
        try:
            result=rebind(reset_policy=self._policy,barrier_event_id=barrier['event_id'],
                          expected_epoch=new_epoch,next_slot=self._program['next_slot'])
        except (ValueError,RuntimeError) as error:
            return {'status': UNAVAILABLE, 'reason': str(error)}
        if (not isinstance(result,dict) or result.get('entry')!=self._epoch_program['entry']
                or result.get('manifest_sha256')!=self._epoch_program['program'].manifest_sha256
                or result.get('image_event_id')!=events[0]['event_id']):
            return {'status': UNAVAILABLE, 'reason': 'carrier-rebind-receipt-mismatch'}
        return {'status': REINSTALLED, 'reset_epoch': new_epoch,
                'barrier_event_id':barrier['event_id'], 'image_event_id':events[0]['event_id'],
                'entry':dict(result['entry']), 'manifest_sha256':result['manifest_sha256'],
                'execution':'unverified'}

    def _reinstall_provider(self, name, provider, *, barrier, relaunch):
        rebind=getattr(provider, 'rebind_after_reset', None)
        binding_status=None
        if callable(rebind):
            if relaunch['status'] != REINSTALLED:
                return {'name': name, 'status': UNAVAILABLE, 'binding_status': UNAVAILABLE,
                        'reason': 'relaunch-not-reinstalled', 'source': 'rebind_after_reset'}
            if self._carrier_rebind_row['status'] == UNAVAILABLE:
                return {'name': name, 'status': UNAVAILABLE, 'binding_status': UNAVAILABLE,
                        'reason': 'carrier-rebind-unavailable', 'source': 'rebind_after_reset'}
            try:
                rebind(barrier_event_id=barrier['event_id'])
            except (ValueError, RuntimeError) as error:
                return {'name': name, 'status': UNAVAILABLE, 'binding_status': UNAVAILABLE,
                        'reason': str(error), 'source': 'rebind_after_reset'}
            binding_status=REINSTALLED
        try:
            state = provider.current_state()
        except ValueError as error:
            row={'name': name, 'status': UNAVAILABLE, 'reason': str(error),
                 'source': 'current_state'}
            if binding_status is not None: row['binding_status']=binding_status
            return row
        if not isinstance(state, dict):
            row={'name': name, 'status': UNAVAILABLE, 'reason': 'provider-state-missing',
                 'source': 'current_state'}
            if binding_status is not None: row['binding_status']=binding_status
            return row
        epoch = state.get('reset_epoch')
        status = state.get('status')
        if status in _PROVIDER_LIVE_STATES and epoch in {session.reset_epoch
                                                         for session in self._sources.values()}:
            row={'name': name, 'status': REINSTALLED, 'reset_epoch': epoch,
                 'source': 'current_state'}
            if binding_status is not None: row['binding_status']=binding_status
            return row
        reason = state.get('reason')
        if reason is None:
            reason = 'stale-reset-epoch' if epoch is not None else (status or 'not-live')
        row={'name': name, 'status': UNAVAILABLE, 'reason': reason,
             'provider_epoch': epoch, 'source': 'current_state'}
        if binding_status is not None: row['binding_status']=binding_status
        return row

    def _reinstall_authority(self, new_epoch):
        authority = self._authority
        if authority is None:
            return {'status': UNDECLARED, 'reason': 'no authority declared'}
        row = {'status': UNAVAILABLE, 'reset_epoch': None,
               'rearm': UNDECLARED if self._rearm_row is None else self._rearm_row['status'],
               'pre_reset_token_refused': None}
        if self._pre_authority_token is not None:
            # A pre-reset credential may be refused outright, or it may still be
            # consumable while *carrying its old epoch*; either way it can never
            # be credited in the new epoch. What is refused here is the one real
            # violation: an old token silently re-stamped with the new epoch.
            try:
                witness = authority.consume(self._pre_authority_token)
            except ValueError:
                row['pre_reset_token_refused'] = True
            else:
                epoch = witness.get('reset_epoch') if isinstance(witness, dict) else None
                if epoch == new_epoch:
                    raise ResetRecoveryRefused(CODE_DRIFT, '/authority/token', {
                        'declared': 'a pre-reset authority token cannot be re-stamped '
                                    'with the new epoch'})
                row['pre_reset_token_refused'] = False
                row['pre_reset_token_stale_epoch'] = epoch
            finally:
                self._pre_authority_token = None
        failure = self._authority_issue(authority, new_epoch, row)
        if failure is None:
            return row
        if self._rearm_row is not None and self._rearm_row['status'] != 'complete':
            return dict(row, reason=self._rearm_row.get('reason') or failure)
        return dict(row, reason=failure)

    def _authority_issue(self, authority, new_epoch, row):
        """Issue and consume one epoch-scoped authority token; refusal text or None."""
        try:
            token = authority.issue(register=self._register, reset_epoch=new_epoch)
            witness = authority.consume(token)
        except ValueError as error:
            return str(error)
        if not isinstance(witness, dict) or witness.get('reset_epoch') != new_epoch:
            raise ResetRecoveryRefused(CODE_DRIFT, '/authority/witness', {
                'declared': new_epoch,
                'actual': (witness or {}).get('reset_epoch')
                if isinstance(witness, dict) else None})
        row.update(status=REINSTALLED, reset_epoch=new_epoch,
                   token_scope={'register': witness.get('register', self._register),
                                'reset_epoch': new_epoch})
        return None

    def _run_rearm(self):
        session = self._sources[self._rearm['session']]
        try:
            receipt = session.command(self._rearm['operation'], self._rearm['fields'])
        except (ValueError, RuntimeError, OSError) as error:
            return {'status': UNAVAILABLE, 'reason': type(error).__name__ + ': ' + str(error)}
        status = getattr(receipt, 'status', None)
        if status != 'result':
            return {'status': UNAVAILABLE, 'reason': 're-arm-receipt:' + str(status)}
        return {'status': 'complete', 'operation': self._rearm['operation'],
                'command_sequence': getattr(receipt, 'sequence', None)}

    # ------------------------------------------------------------------ #
    # epoch-scoped credit and lineage
    # ------------------------------------------------------------------ #

    @staticmethod
    def _identity_key(component, identity):
        try:
            return (component, _canonical(identity))
        except (TypeError, ValueError):
            return (component, repr(identity))

    def credit(self, *, component, epoch, token, identity=None):
        """Return one epoch-scoped credit row, or refuse old-epoch lineage.

        Before the barrier a credit is ordinary pre-reset lineage.  After it, an
        old-epoch credit is refused, an identity that a pre-reset observation
        already used is refused, and the same numeric token in the new epoch is
        a *new* observation: ``lineage`` is false and the reuse is recorded.
        """
        if type(component) is not str or not component:
            raise ValueError('reset recovery credit component')
        declared = self._declared_source(component)
        if not _uint(epoch):
            raise ValueError('reset recovery credit epoch')
        if token is None:
            raise ValueError('reset recovery credit token')
        scope = (component, epoch, token)
        identity_key = (None if identity is None
                        else self._identity_key(component, identity))
        if self._observed is None:
            if epoch != declared:
                raise ResetRecoveryRefused(CODE_DRIFT, '/credit/epoch', {
                    'declared': declared, 'actual': epoch})
            self._pre_scopes.append(scope)
            self._pre_token_keys.add((component, token))
            self._seen_scopes.add(scope)
            if identity_key is not None:
                self._pre_identity_keys.append(identity_key)
                self._seen_identity_keys.add(identity_key)
            return {'schema_version': CREDIT_SCHEMA_VERSION, 'component': component,
                    'reset_epoch': epoch, 'token': _document_value(token),
                    'identity': None if identity is None else _document_value(identity),
                    'lineage': True, 'epoch_scoped': True,
                    'token_reuse_across_epoch': False}
        new_epoch = self._observed['epoch']['after']
        if epoch != new_epoch:
            raise ResetRecoveryRefused(CODE_DRIFT, '/credit/epoch', {
                'declared': new_epoch, 'actual': epoch,
                'measured_barrier': self._observed['barrier']['event_id']})
        if identity_key is not None and identity_key in self._pre_identity_keys:
            raise ResetRecoveryRefused(CODE_DRIFT, '/credit/identity', {
                'declared': 'a pre-reset identity cannot be credited in the new epoch'})
        reuse = (component, token) in self._pre_token_keys
        self._seen_scopes.add(scope)
        if identity_key is not None:
            self._seen_identity_keys.add(identity_key)
        if reuse:
            self._observed['lineage']['token_reuse_across_epoch'].append(
                dict(_scope_document(scope), lineage=False))
        return {'schema_version': CREDIT_SCHEMA_VERSION, 'component': component,
                'reset_epoch': epoch, 'token': _document_value(token),
                'identity': None if identity is None else _document_value(identity),
                'lineage': False, 'epoch_scoped': True,
                'token_reuse_across_epoch': bool(reuse)}

    # ------------------------------------------------------------------ #
    # slot continuation
    # ------------------------------------------------------------------ #

    def continue_slot(self, record, *, flow):
        """Ask the declared carrier to execute one more slot case in the new epoch."""
        if self._observed is None:
            raise ValueError('reset recovery must observe the barrier before continuing')
        if self._carrier is None:
            self._continuation = {'status': UNDECLARED,
                                  'reason': 'no slot carrier was declared before the barrier'}
            raise ResetRecoveryRefused(CODE_UNDECLARED, '/slot_continuation',
                                       {'declared': 'no slot carrier'})
        if type(record) is not bytes or not record:
            raise ValueError('reset recovery continuation record must be bytes')
        if (self._program is not None and callable(getattr(self._carrier,'rebind_reset_epoch',None))
                and self._carrier_rebind_row['status']!=REINSTALLED):
            self._continuation={'status':UNAVAILABLE,'carrier':type(self._carrier).__name__,
                'operation':'submit:'+str(flow),'code':'carrier-reset-rebind-unavailable'}
            self._observed['slot_continuation']=dict(self._continuation)
            raise ResetRecoveryRefused(CODE_UNSUPPORTED,'/slot_continuation',
                {'carrier_code':'carrier-reset-rebind-unavailable'})
        new_epoch = self._observed['epoch']['after']
        carrier = type(self._carrier).__name__
        try:
            result = self._carrier.submit(record, flow=flow)
        except ValueError as error:
            self._continuation = {'status': UNAVAILABLE, 'carrier': carrier,
                                  'operation': 'submit:' + str(flow),
                                  'code': str(error)}
            self._observed['slot_continuation'] = dict(self._continuation)
            raise ResetRecoveryRefused(CODE_UNSUPPORTED, '/slot_continuation', {
                'carrier': carrier, 'flow': str(flow),
                'carrier_code': str(error)}) from error
        status = result.get('status') if isinstance(result, dict) else None
        if status not in ('passed', 'certified'):
            self._continuation = {'status': UNAVAILABLE, 'carrier': carrier,
                                  'operation': 'submit:' + str(flow),
                                  'code': 'carrier-document-not-passing:' + str(status)}
            self._observed['slot_continuation'] = dict(self._continuation)
            raise ResetRecoveryRefused(CODE_UNSUPPORTED, '/slot_continuation', {
                'carrier': carrier, 'carrier_status': status})
        if self._epoch_program is not None:
            expected_program = {
                'manifest_sha256': self._epoch_program['program'].manifest_sha256,
                'entry': dict(self._epoch_program['entry'])}
            claimed=result.get('epoch_program')
            from myfuzz.integration.compiled_f6 import CompiledF6Runtime, _f6_epoch_execution_receipt
            if type(self._carrier) is CompiledF6Runtime:
                live=_f6_epoch_execution_receipt(self._carrier,result)
                valid=(isinstance(claimed,dict) and claimed==live
                       and all(claimed.get(key)==value for key,value in expected_program.items())
                       and isinstance(claimed.get('evidence'),dict))
            else:
                valid=claimed==expected_program
            if not valid:
                self._continuation = {'status': UNAVAILABLE, 'carrier': carrier,
                    'operation': 'submit:' + str(flow),
                    'code': 'carrier-epoch-program-unverified'}
                self._observed['slot_continuation'] = dict(self._continuation)
                raise ResetRecoveryRefused(CODE_UNSUPPORTED, '/slot_continuation', {
                    'carrier': carrier, 'carrier_code': 'carrier-epoch-program-unverified'})
        self._continuation = {'status': CONTINUATION_VERIFIED, 'carrier': carrier,
                              'reset_epoch': new_epoch, 'flow': str(flow),
                              'carrier_status': status}
        if self._epoch_program is not None:
            # A verified continuation names the epoch program it ran on.
            self._continuation['program'] = deepcopy(claimed)
        self._observed['slot_continuation'] = dict(self._continuation)
        return deepcopy(self._continuation)

    # ------------------------------------------------------------------ #
    # documents
    # ------------------------------------------------------------------ #

    @property
    def status(self):
        return None if self._observed is None else self._observed['status']

    def document(self):
        """The whole recovery state; a barrier that has not been re-installed yet
        is reported as such instead of as a pass."""
        if self._observed is None:
            return {'schema_version': SCHEMA_VERSION, 'status': 'declared',
                    'policy': self._policy, 'register': self._register,
                    'epoch': {'before': dict(self._declared_epoch), 'after': None,
                              'advanced': False},
                    'sources': [], 'providers': list(self._provider_rows),
                    'program': dict(self._program_row),
                    'relaunch': dict(self._relaunch_row),
                    'authority': dict(self._authority_row),
                    'slot_continuation': dict(self._continuation),
                    'lineage': {'old_epoch_fenced': False,
                                'pre_reset_tokens': [_scope_document(scope)
                                                     for scope in self._pre_scopes],
                                'pre_reset_identities': [
                                    {'component': component, 'identity': identity}
                                    for component, identity in self._pre_identity_keys],
                                'authority_token_refused': None,
                                'token_reuse_across_epoch': []},
                    'grants_storage': False, 'grants_version_dependency': False,
                    'grants_functional': False, 'grants_reward': False}
        document = deepcopy(self._observed)
        document['slot_continuation'] = dict(self._continuation)
        return document
