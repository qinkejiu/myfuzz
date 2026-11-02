"""Pure gates for ``scripts/run_reset_recovery_native.py``; no RTL, no native run.

The measured outcome documents below are shaped exactly like the ones the runner
writes (``recovery.json``, ``slot_continuation.json``, ``result.json``), so the
outcome rule is exercised on the documents the frozen window will really
produce.  The native run itself stays with the lead; nothing here stands in for
it.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.run_reset_recovery_native import (
    CARRIER_BLOCKERS, CONTINUATION_FLOW, CONTINUATION_RECORD, DEFAULT_CACHE,
    DEFAULT_DESCRIPTOR, LAYERS, RESULT_SCHEMA, SUMMARY_SCHEMA,
    ResetRecoverySelector, build_summary, classify_outcome, main, refusal_summary,
    scope_fields)

ROOT = Path(__file__).resolve().parents[2]


def _document(**changes):
    document = {
        'schema_version': 'native_reset_recovery.v1',
        'status': 'reinstalled',
        'policy': 'warm_all',
        'epoch': {'before': {'cpu': 0, 'dma': 0, 'peripheral': 0},
                  'after': 1, 'advanced': True},
        'barrier': {'event_id': 1738, 'policy': 'warm_all',
                    'memory_generations': {'shared_ram': 0}},
        'sources': [{'name': name, 'status': 'reinstalled', 'reset_epoch': 1,
                     'execution': name + ':reset:1', 'pid': 9000,
                     'binding_sha256': 'a' * 64}
                    for name in ('cpu', 'dma', 'peripheral')],
        'providers': [{'name': 'RAM', 'status': 'unavailable',
                       'reason': 'shared_RAM_unavailable:shared_RAM_live_process_required',
                       'source': 'current_state'},
                      {'name': 'PIN', 'status': 'unavailable',
                       'reason': 'shared_pin_process_identity_changed',
                       'source': 'current_state'}],
        'authority': {'status': 'unavailable', 'reset_epoch': None,
                      'rearm': 'undeclared',
                      'reason': 'register-version-current-state-unavailable'},
        'lineage': {'old_epoch_fenced': True, 'pre_reset_tokens': [],
                    'pre_reset_identities': [], 'authority_token_refused': None,
                    'token_reuse_across_epoch': []},
        'slot_continuation': {'status': 'unavailable', 'carrier': 'CompiledF6Runtime',
                              'operation': 'submit:F6',
                              'code': 'compiled-F6-built-process-identity-changed'},
    }
    document.update(changes)
    return document


ENTRY = {'schema_version': 'compiled_F6_entry.v1', 'policy': 'declared_resume_slot',
         'declared': True, 'reset_epoch': 1, 'slot': 2, 'slot_count': 8,
         'entry_address': 0x11600, 'slot_base': 0x11000, 'slot_bytes': 256,
         'boot_address': 0x10080,
         'rule': 'boot_jal_target = slot_base + slot_bytes*slot'}


def _continuation(status, code=None, epoch=None, program=True):
    document = {'status': status}
    if code is not None:
        document['code'] = code
    if epoch is not None:
        document['reset_epoch'] = epoch
    if program:
        document['program'] = {'manifest_sha256': 'b' * 64, 'entry': dict(ENTRY)}
    return document


# --------------------------------------------------------------------------- #
# The declared outcome rule
# --------------------------------------------------------------------------- #

def test_the_declared_carrier_blocker_is_the_unavailable_outcome():
    outcome, detail = classify_outcome(
        _document(), _continuation('unavailable',
                                   code='compiled-F6-built-process-identity-changed'))
    assert outcome == 'unavailable'
    assert 'compiled-F6-built-process-identity-changed' in detail


@pytest.mark.parametrize('code', CARRIER_BLOCKERS)
def test_every_declared_blocker_is_accepted(code):
    assert classify_outcome(_document(), _continuation('unavailable', code=code))[0] \
        == 'unavailable'


def test_an_undeclared_carrier_code_is_a_mismatch():
    outcome, detail = classify_outcome(
        _document(), _continuation('unavailable', code='compiled-F6-whatever'))
    assert outcome == 'mismatch'
    assert 'undeclared' in detail


def test_a_verified_continuation_requires_a_reinstalled_binding_and_new_epoch():
    document = _document(status='reinstalled')
    assert classify_outcome(
        document, _continuation('verified', epoch=1))[0] == 'verified'
    assert classify_outcome(
        document, _continuation('verified', epoch=0))[0] == 'mismatch'
    assert classify_outcome(
        _document(status='unavailable'),
        _continuation('verified', epoch=1))[0] == 'mismatch'
    # a continuation that names no declared epoch entry re-entered the old one
    outcome, detail = classify_outcome(
        document, _continuation('verified', epoch=1, program=False))
    assert outcome == 'mismatch' and 'program entry' in detail


def test_an_undeclared_or_missing_continuation_is_a_mismatch():
    assert classify_outcome(_document(), {'status': 'undeclared'})[0] == 'mismatch'
    assert classify_outcome(_document(), None)[0] == 'mismatch'
    assert classify_outcome(None, _continuation('unavailable', code=CARRIER_BLOCKERS[0]))[0] \
        == 'mismatch'


# --------------------------------------------------------------------------- #
# The declared blocker codes must still be the real carrier codes
# --------------------------------------------------------------------------- #

def test_the_declared_blockers_are_the_compiled_carrier_codes():
    carrier = (ROOT / 'src/myfuzz/integration/compiled_f6.py').read_text(encoding='utf-8')
    slots = (ROOT / 'src/myfuzz/integration/shared_f6_slots.py').read_text(encoding='utf-8')
    audit = (ROOT / 'src/myfuzz/integration/compiled_process_audit.py').read_text(encoding='utf-8')
    assert "'compiled-F6-built-process-identity-changed'" in carrier
    for code in ('-built-process-launch-missing', '-built-process-identity-mismatch',
                 '-built-receipt-identity-changed'):
        assert code in audit
    # the unbound relaunch is still refused by the one-launch rule ...
    assert 'len(launches) != 1' in audit
    # ... and a bound relaunch is accepted only one launch per measured epoch
    assert 'len(launches) != epoch + 1' in audit
    assert "EPOCH_LAUNCH_SCHEMA = 'compiled_epoch_launch.v1'" in audit
    assert "'compiled-F6-native-process-not-live'" in carrier
    assert "'compiled-F6-runtime-not-live'" in carrier
    assert "require(state['scope'] == scope, 'CPU-scope-drift')" in slots
    assert "'f6-case-native-identity-drift'" in carrier
    # the process/epoch pins the refusal is about, in the real carrier
    assert 'self._process_identities = self._validated_build_process_identities()' in carrier
    assert 'self._f6_original_cpu_reset_epoch = cpu.reset_epoch' in carrier
    assert "state['scope'] = scope" in slots


def test_the_continuation_is_one_declared_eight_byte_f6_record():
    assert CONTINUATION_FLOW == 'F6'
    assert len(bytes.fromhex(CONTINUATION_RECORD)) == 8
    assert CONTINUATION_RECORD == '0110c00008000000'


# --------------------------------------------------------------------------- #
# Reuse of the proven native plumbing (no second plan, no second probe)
# --------------------------------------------------------------------------- #

def test_the_selector_reuses_the_proven_diagnostic_plan_and_probe():
    from scripts.run_shared_consumption_diagnostic import (
        DirectedConsumptionSelector, PLANS, ResetProbeComplete)
    assert issubclass(ResetRecoverySelector, DirectedConsumptionSelector)
    assert set(PLANS) >= {'reset-ram', 'reset-pin'}
    # the inherited probe is the only code that performs the measured reset
    assert '_reset_probe' in vars(ResetRecoverySelector)
    assert issubclass(ResetRecoverySelector, object)
    assert ResetProbeComplete.__name__ == 'ResetProbeComplete'


def test_the_defaults_are_the_declared_descriptor_and_cache():
    assert DEFAULT_DESCRIPTOR == ('configs/scenarios/compiled-f1-f6-ibex-gpio-dma-'
                                 'shared/generic_scenario.json')
    assert DEFAULT_CACHE == 'runs/config-driven-20261028/cache'
    assert (ROOT / DEFAULT_DESCRIPTOR).is_file()
    assert (ROOT / DEFAULT_CACHE).is_dir()


def test_the_declared_layers_are_the_six_the_run_reports():
    # one layer per measured step of the declared chain: barrier -> epoch+1 ->
    # new program entry -> relaunch accepted -> providers/authority -> slot run
    assert LAYERS == ('reset_barrier', 'recovery_reinstall', 'no_old_epoch_credit',
                      'epoch_program_entry', 'relaunch_accepted', 'slot_continuation')


# --------------------------------------------------------------------------- #
# Summary documents keep their explicit non-authority
# --------------------------------------------------------------------------- #

def test_the_summary_is_a_terminal_probe_without_authority():
    result = {'schema_version': RESULT_SCHEMA, 'status': 'unavailable',
              'layers': {'reset_barrier': True, 'recovery_reinstall': False,
                         'no_old_epoch_credit': True, 'slot_continuation': 'unavailable'}}
    summary = build_summary(
        result, scenario='reset-ram', policy='warm_all', descriptor=DEFAULT_DESCRIPTOR,
        cache=DEFAULT_CACHE, rounds=1024, expect='unavailable', outcome='unavailable',
        detail='the declared carrier blocker was reproduced', semantic_sha256='b' * 64)
    assert summary['schema_version'] == SUMMARY_SCHEMA
    assert summary['native'] is True
    assert summary['native_authority'] is False
    assert summary['grants_F5'] is False
    assert summary['grants_F6'] is False
    assert summary['reward_eligible'] is False
    assert summary['isr_mmio'] == 'unknown'
    assert summary['terminal_probe']['normal_campaign_completion'] is False
    assert summary['declared_layers'] == list(LAYERS)
    json.dumps(summary)


def test_a_refusal_summary_is_never_a_pass():
    summary = refusal_summary(code='case-execution-failed', detail='x',
                              stage='native-execution', scenario='reset-ram',
                              policy='warm_all')
    assert summary['status'] == 'refused'
    assert summary['native_authority'] is False
    assert summary['terminal_probe']['normal_campaign_completion'] is False
    json.dumps(summary)


def test_scope_fields_grant_nothing():
    fields = scope_fields()
    assert all(value is False for key, value in fields.items()
               if key.startswith(('native', 'grants', 'reward')))
    assert fields['isr_mmio'] == 'unknown'


# --------------------------------------------------------------------------- #
# CLI refusals write nothing and start nothing
# --------------------------------------------------------------------------- #

def test_an_existing_output_dir_is_refused(tmp_path, capsys):
    output = tmp_path / 'existing'
    output.mkdir()
    (output / 'keep.txt').write_text('keep')
    assert main(['--native', '--output', str(output)]) == 2
    assert sorted(path.name for path in output.iterdir()) == ['keep.txt']
    printed = json.loads(capsys.readouterr().out)
    assert printed['code'] == 'output-exists'


def test_a_missing_descriptor_is_refused(tmp_path, capsys):
    output = tmp_path / 'new'
    assert main(['--native', '--output', str(output),
                 '--descriptor', 'configs/scenarios/does-not-exist.json']) == 2
    assert not output.exists()
    printed = json.loads(capsys.readouterr().out)
    assert printed['code'] == 'descriptor-missing'


def test_an_unbounded_round_budget_is_refused(tmp_path, capsys):
    output = tmp_path / 'new'
    assert main(['--native', '--output', str(output), '--rounds', '0']) == 2
    assert not output.exists()
    printed = json.loads(capsys.readouterr().out)
    assert printed['code'] == 'invalid-rounds'


def test_the_native_flag_is_required():
    from scripts.run_reset_recovery_native import main as runner_main
    with pytest.raises(SystemExit):
        runner_main(['--output', 'unused'])


# --------------------------------------------------------------------------- #
# The selector's declaration and post-barrier recovery, with the native
# processes replaced by declared doubles (the carrier code stays the real one)
# --------------------------------------------------------------------------- #

def _recovery_fixture(tmp_path):
    from types import SimpleNamespace

    from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
    from myfuzz.scenario.native_reset_recovery import REINSTALLED
    from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
    from myfuzz.scenario.runner import ScenarioRunner

    class Process:
        _next = 9000

        def __init__(self):
            Process._next += 1
            self.pid = Process._next

        def poll(self):
            return None

    class Session:
        def __init__(self, memory, name):
            self.memory = memory
            self.name = name
            self.reset_epoch = 0
            self._execution = name + ':exec:0'
            self.process = Process()
            self.local_ticks = 0
            self.begins = 0
            self.on_command = None

        def begin_case(self, testcase_id):
            self.begins += 1
            self._execution = self.name + ':exec:' + str(self.begins)
            self.process = Process()

        def step_local(self, inputs):
            self.local_ticks += 1
            return {}

        def reset_local(self):
            self.reset_epoch += 1
            self._execution = self.name + ':reset:' + str(self.reset_epoch)
            self.process = Process()
            return {'cancelled_responses': 0}

        def end_case(self):
            pass

        def command(self, operation, fields):
            if self.on_command is not None:
                self.on_command(self)
            return SimpleNamespace(status='result', sequence=1)

    memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x1000),),
                              initialization_seed=7, max_initialized_bytes=0x1000)
    sessions = {'cpu': Session(memory, 'cpu'), 'peripheral': Session(memory, 'peripheral')}
    runner = ScenarioRunner(sessions=sessions, ownership=compile_ownership(
        (InputField('cpu', 'pin', 1),),
        (InputOwner('cpu', 'pin', 0, 1, 'source', 'external'),)), bindings=())
    runner.begin_test('reset-recovery-script')

    class Authority:
        def __init__(self):
            self.state = None
            self.tokens = {}

        def arm(self):
            session = sessions['peripheral']
            self.state = {'identity': (session.process, session.reset_epoch),
                          'reset_epoch': session.reset_epoch}

        def issue(self, *, register='GPIOEN', reset_epoch):
            session = sessions['peripheral']
            if (self.state is None or self.state['identity']
                    != (session.process, session.reset_epoch)
                    or reset_epoch != session.reset_epoch):
                raise ValueError('register-version-current-state-unavailable')
            token = object()
            self.tokens[token] = {'register': register, 'reset_epoch': reset_epoch}
            return token

        def consume(self, token):
            # the real authority clears its issuance on an identity change
            session = sessions['peripheral']
            if (self.state is None
                    or self.state['identity'] != (session.process, session.reset_epoch)):
                self.tokens.clear()
                raise ValueError('register-version-current-state-unavailable')
            witness = self.tokens.pop(token, None)
            if witness is None:
                raise ValueError('register-version-token-invalid-or-revoked')
            return dict(witness)

    class Provider:
        def __init__(self, name, reason):
            self.name = name
            self.reason = reason

        def current_state(self):
            return {'name': self.name, 'status': 'unknown',
                    'reason': self.reason, 'reset_epoch': 0}

    class Carrier:
        def submit(self, record, *, flow='F6'):
            raise ValueError(CARRIER_BLOCKERS[0])

    authority = Authority()
    authority.arm()
    carrier = Carrier()
    shell = SimpleNamespace(
        runner=runner,
        runtime_path_admission={'shared_flow_paths': {'F5': {'pin': {
            'component': 'peripheral', 'bit_offset': 8, 'width': 1}}}},
        assembly=SimpleNamespace(companion_authorities={'peripheral': authority}),
        submit=carrier.submit)
    selector = ResetRecoverySelector(
        'reset-ram', output=tmp_path / 'consumption-diagnostic.json',
        reset_policy='warm_all', recovery_dir=tmp_path)
    selector._runtime = shell
    selector._handle = Provider(
        'RAM', 'shared_RAM_unavailable:shared_RAM_live_process_required')
    selector._pin_handle = Provider('PIN', 'shared_pin_process_identity_changed')
    return selector, runner, sessions, authority, REINSTALLED


def test_the_selector_declares_every_persistent_session_before_the_barrier(tmp_path):
    selector, runner, sessions, authority, _ = _recovery_fixture(tmp_path)
    assert selector.recovery is None
    selector._declare_recovery()
    document = selector.recovery.document()
    assert document['status'] == 'declared'
    assert document['epoch']['before'] == {'cpu': 0, 'peripheral': 0}
    assert set(document['epoch']['before']) == set(runner.sessions)
    assert [row['name'] for row in document['providers']] == ['RAM', 'PIN']
    assert document['policy'] == 'warm_all'
    assert document['register'] == 'GPIOEN'
    runner.finalize()


def test_the_post_barrier_recovery_writes_its_artifacts_and_stays_unavailable(tmp_path):
    selector, runner, sessions, authority, reinstalled = _recovery_fixture(tmp_path)
    selector._declare_recovery()
    selector.pre_reset_authority_token_captured = \
        selector.recovery.capture_authority_token()
    assert selector.pre_reset_authority_token_captured is True
    runner.reset_all('warm_all')
    selector.reset_report = {'policy': 'warm_all', 'terminal_probe': True}
    selector._recover_after_barrier()

    for name in ('recovery.json', 'slot_continuation.json', 'result.json'):
        assert (tmp_path / name).is_file(), name
    result = json.loads((tmp_path / 'result.json').read_text())
    assert result['schema_version'] == RESULT_SCHEMA
    assert result['status'] == 'unavailable'
    assert result['epoch'] == {'before': {'cpu': 0, 'peripheral': 0}, 'after': 1,
                               'advanced': True}
    assert result['barrier']['policy'] == 'warm_all'
    assert result['layers']['reset_barrier'] is True
    assert result['layers']['no_old_epoch_credit'] is True
    assert result['layers']['slot_continuation'] == 'unavailable'
    assert all(row['status'] == reinstalled for row in result['sources'])
    assert result['providers'][0]['reason'] == (
        'shared_RAM_unavailable:shared_RAM_live_process_required')
    assert result['providers'][1]['reason'] == 'shared_pin_process_identity_changed'
    assert result['slot_continuation']['code'] == CARRIER_BLOCKERS[0]
    assert result['pre_reset_authority_token_captured'] is True
    # the pre-reset token is dead: nothing from the old epoch can be re-credited
    assert result['recovery']['lineage']['authority_token_refused'] is True
    assert result['lineage']['authority_token_refused'] is True
    continuation = json.loads((tmp_path / 'slot_continuation.json').read_text())
    assert continuation['status'] == 'unavailable'
    assert continuation['code'] == CARRIER_BLOCKERS[0]
    runner.finalize()


def test_a_typed_recovery_refusal_is_written_with_its_own_code(tmp_path, monkeypatch, capsys):
    import myfuzz.runtime.generic_campaign as campaign
    import scripts.run_reset_recovery_native as runner_module
    from myfuzz.scenario.native_reset_recovery import CODE_UNDECLARED, ResetRecoveryRefused

    class FakeSelector:
        def __init__(self, *args, **kwargs):
            self.plan = ('F3:55000000',)
            self.recovery_document = None
            self.outcome = None
            self.outcome_detail = None

    def fake_run_descriptor(*args, **kwargs):
        raise ResetRecoveryRefused(CODE_UNDECLARED, '/barrier',
                                   {'declared': 'no measured reset barrier was recorded'})

    monkeypatch.setattr(runner_module, 'ResetRecoverySelector', FakeSelector)
    monkeypatch.setattr(campaign, 'run_descriptor', fake_run_descriptor)
    output = tmp_path / 'new'
    assert runner_module.main(['--native', '--output', str(output)]) == 2
    summary = json.loads((output / 'summary.json').read_text())
    assert summary['status'] == 'refused'
    assert summary['refusal']['code'] == CODE_UNDECLARED
    assert summary['refusal']['stage'] == 'reset-recovery'
    printed = json.loads(capsys.readouterr().out)
    assert printed['code'] == CODE_UNDECLARED
    assert printed['pointer'] == '/barrier'


def test_verified_ram_recovery_requires_fresh_certified_write_read():
    document = _document(status='reinstalled')
    continuation = _continuation('verified', epoch=1)
    assert classify_outcome(document, continuation, ram_recovery={'status':'unknown'})[0] == 'mismatch'
    assert classify_outcome(document, continuation, ram_recovery={'status':'verified'})[0] == 'verified'


def test_ram_recovery_uses_new_f3_and_f1_and_fences_old_case(monkeypatch):
    from types import SimpleNamespace
    from scripts.run_reset_recovery_native import _verify_ram_after_reset
    import myfuzz.integration.shared_f6_slots as slots
    rows = []
    def submit(raw, *, flow):
        case_id = 'new-' + flow
        rows.append({'case_id':case_id, 'flow':flow, 'status':'passed'})
        return {'status':'certified'}
    class Provider:
        def current_state(self):
            if not rows: return {'status':'unknown'}
            return {'status':'observed', 'reset_epoch':1, 'writer_attributed':True,
                    'writer_case_ids':['new-F3']*4}
        def observe_case(self, case):
            if case == 'old': return {'status':'unknown', 'relations':[]}
            return {'status':'verified', 'relations':[{'status':'verified',
                'read_case_id':'new-F1', 'writer_case_ids':['new-F3']*4}]}
    monkeypatch.setattr(slots, 'flow_records', lambda runtime: rows)
    report = _verify_ram_after_reset(SimpleNamespace(submit=submit), Provider(), 'old', 1)
    assert report['status']=='verified'
    assert [row['flow'] for row in rows] == ['F3','F1']
    class BadProvider(Provider):
        def observe_case(self, case): return {'status':'verified', 'relations':[{}]}
    rows.clear()
    assert _verify_ram_after_reset(SimpleNamespace(submit=submit), BadProvider(), 'old', 1)['status']=='unavailable'
    assert not rows
