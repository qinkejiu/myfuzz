#!/usr/bin/env python3
"""Reset recovery on the persistent shared F1-F6 slot session (native).

The existing ``scripts/run_shared_consumption_diagnostic.py`` proves one thing
about a real reset inside the compiled shared slot session: after
``reset_all('warm_all'|'cold_all')`` the old RAM/PIN providers refuse and the
probe is **terminal**.  It deliberately does not re-install the provider for the
new epoch, and it does not continue slot execution.

This runner does the missing half.  It reuses that script's descriptor, cache,
selector's directed native plan and its real reset probe unchanged, then:

1. declares the epoch-scoped recovery *before* the barrier
   (``myfuzz.scenario.native_reset_recovery``): the provider handles, the live
   storage/register authority and every persistent source session;
2. lets the directed plan finish, performs the real ``runner.reset_all`` through
   the inherited probe, and observes the measured ``reset_barrier``;
3. re-installs each declared binding **bound to the new reset epoch** and records
   per binding whether it really happened or why not;
4. attempts exactly one slot continuation in the new epoch through the declared
   carrier (the compiled shared-slot runtime), and records the carrier's own
   answer.  A carrier refusal is surfaced as a typed refusal
   (``generic-semantic-unsupported`` if it is a declared blocker) plus the
   explicit ``unavailable`` status - never converted into a pass.

Exit status: **0** only when the measured outcome equals ``--expect`` (default
``unavailable``: the declared blocker is reproduced exactly); **2** on any
mismatch, undeclared binding, unexpected carrier code or execution failure.  A
``verified`` outcome is possible only after ``--expect verified`` and only when
the carrier really executed one more slot case in the new epoch.

Nothing here is a campaign: one descriptor, one directed plan, one measured
reset, one continuation attempt.  No new adapter, no RTL build difference, no
native authority.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]

from scripts.run_shared_consumption_diagnostic import (  # noqa: E402
    DirectedConsumptionSelector, ResetProbeComplete)
from myfuzz.scenario.native_reset_recovery import (  # noqa: E402
    REINSTALLED, ResetRecoveryRefused, declare_reset_recovery)

SUMMARY_SCHEMA = 'reset_recovery_native_summary.v1'
RESULT_SCHEMA = 'reset_recovery_native_result.v1'
DEFAULT_DESCRIPTOR = 'configs/scenarios/compiled-f1-f6-ibex-gpio-dma-shared/generic_scenario.json'
DEFAULT_CACHE = 'runs/config-driven-20261028/cache'
SCENARIOS = ('reset-ram', 'reset-pin')
POLICIES = ('warm_all', 'cold_all')
EXPECTATIONS = ('unavailable', 'verified')
CONTINUATION_FLOW = 'F6'
#: The same canonical eight-byte F6 record the shared-slot tests and the
#: consumption catalog already use for this descriptor.
CONTINUATION_RECORD = '0110c00008000000'
#: The carrier's own refusals that mean "this runtime cannot continue a slot
#: execution after a reset".  Each string is raised by the compiled carrier at
#: ``CompiledF6Runtime._verify_live_owner`` (the launch/epoch identity pins taken
#: in ``_begin_once``) or by the shared slot ledger's one-shot CPU scope; a code
#: outside this set is a mismatch, not the documented blocker, so an unrelated
#: failure can never be reported as the known one.
CARRIER_BLOCKERS = (
    # the post-reset relaunch is the second launch of the same session, while
    # the carrier admits exactly one launch per session (compiled_process_audit)
    'compiled-F6-built-process-launch-missing',
    'compiled-F6-built-process-identity-changed',
    'compiled-F6-built-process-identity-mismatch',
    'compiled-F6-built-receipt-identity-changed',
    'compiled-F6-native-process-not-live',
    'compiled-F6-runtime-not-live',
    # only reached if the identity pins above were bypassed
    'shared-F4-F6-CPU-scope-drift',
    'f6-case-native-identity-drift',
    # raised by the prepared owner rebind (`runs/reset-continuation-20261030/
    # owner-reset-rebind.patch`) when the admitted contract image is not this
    # epoch's image: the entry is declared, not executed, and no slot runs.
    'compiled-F6-epoch-program-unbound',
)
LAYERS = ('reset_barrier', 'recovery_reinstall', 'no_old_epoch_credit',
          'epoch_program_entry', 'relaunch_accepted', 'slot_continuation')


class ResetRecoveryMismatch(RuntimeError):
    """The measured outcome is not the declared expectation."""

    def __init__(self, code, detail):
        super().__init__(code + ': ' + detail)
        self.code = code
        self.detail = detail


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


# --------------------------------------------------------------------------- #
# Pure outcome rules (software-testable, no runtime)
# --------------------------------------------------------------------------- #

def classify_outcome(document, continuation, *, ram_recovery=None):
    """``verified``|``unavailable``|``mismatch`` from the measured documents."""
    if not isinstance(document, dict):
        return 'mismatch', 'no recovery document'
    status = document.get('status')
    if not isinstance(continuation, dict):
        return 'mismatch', 'no continuation document'
    kind = continuation.get('status')
    if kind == 'verified':
        if status != 'reinstalled':
            return 'mismatch', ('the carrier continued without a re-installed binding: '
                                + str(status))
        if continuation.get('reset_epoch') != (document.get('epoch') or {}).get('after'):
            return 'mismatch', 'the continuation is not bound to the new epoch'
        entry = (continuation.get('program') or {}).get('entry')
        if not isinstance(entry, dict) or entry.get('reset_epoch') != continuation['reset_epoch']:
            # Without the declared per-epoch entry the CPU re-entered the slot the
            # pre-reset epoch already used, which is a replay, not a continuation.
            return 'mismatch', ('the continuation names no declared epoch program entry')
        if ram_recovery is not None and ram_recovery.get('status') != 'verified':
            return 'mismatch', 'new epoch RAM write/read evidence unavailable'
        return 'verified', 'one more slot case executed in the new epoch'
    if kind == 'unavailable':
        code = continuation.get('code')
        if code not in CARRIER_BLOCKERS:
            return 'mismatch', 'the carrier refused with an undeclared code: ' + str(code)
        return 'unavailable', 'the declared carrier blocker was reproduced: ' + str(code)
    return 'mismatch', 'the continuation was not declared or never attempted'


def _verify_ram_after_reset(runtime, provider, old_case_id, epoch):
    """Run real F3/F1 slots; accept only the provider's observed relation."""
    from myfuzz.integration.shared_f6_slots import flow_records
    report = {'status': 'unavailable'}
    try:
        before = provider.current_state()
        old_read = provider.observe_case(old_case_id)
        if before.get('writer_attributed') or old_read.get('relations'):
            return dict(report, reason='old RAM credit survived reset')
        write = runtime.submit(bytes.fromhex('55000000'), flow='F3')
        rows = flow_records(runtime)
        if write.get('status') not in ('passed', 'certified') or not rows or rows[-1]['flow'] != 'F3':
            return dict(report, reason='new F3 did not pass')
        writer = rows[-1]['case_id']
        current = provider.current_state()
        if (current.get('status') != 'observed' or current.get('reset_epoch') != epoch
                or current.get('writer_attributed') is not True
                or current.get('writer_case_ids') != [writer]*4):
            return dict(report, reason='new F3 current version unavailable', current=current)
        read = runtime.submit(bytes.fromhex('03200000'), flow='F1')
        rows = flow_records(runtime)
        if read.get('status') not in ('passed', 'certified') or not rows or rows[-1]['flow'] != 'F1':
            return dict(report, reason='new F1 did not pass', current=current)
        reader = rows[-1]['case_id']
        relation = provider.observe_case(reader)
        matches = relation.get('relations', [])
        if (relation.get('status') != 'verified' or len(matches) != 1
                or matches[0].get('status') != 'verified'
                or matches[0].get('writer_case_ids') != [writer]*4
                or matches[0].get('read_case_id') != reader):
            return dict(report, reason='new F1 relation unavailable', current=current, relation=relation)
        return {'status':'verified', 'reset_epoch':epoch, 'old_case_id':old_case_id,
                'old_relation':old_read, 'current':current, 'relation':relation,
                'writer_case_id':writer, 'reader_case_id':reader}
    except (ValueError, RuntimeError, TypeError, KeyError, AttributeError) as error:
        return dict(report, reason=str(error))


def scope_fields():
    return {'native_authority': False, 'grants_F5': False, 'grants_F6': False,
            'grants_storage': False, 'reward_eligible': False,
            'isr_mmio': 'unknown', 'irq_consumption': 'unknown'}


def build_summary(result, *, scenario, policy, descriptor, cache, rounds, expect,
                  outcome, detail, semantic_sha256):
    layers = dict(result.get('layers') or {})
    return {
        'schema_version': SUMMARY_SCHEMA,
        'status': outcome,
        'detail': detail,
        'expectation': expect,
        'case': scenario,
        'scope': 'measured-reset-recovery-on-the-persistent-shared-slot-session',
        'native': True,
        'descriptor': str(descriptor),
        'cache': str(cache),
        'rounds_per_case': rounds,
        'reset_policy': policy,
        'semantic_sha256': semantic_sha256,
        'layers': layers,
        'declared_layers': list(LAYERS),
        'result': result,
        'terminal_probe': {'schema_version': 'reset_recovery_terminal_probe.v1',
                           'terminal': True, 'kind': 'reset-recovery',
                           'normal_campaign_completion': False},
        **scope_fields(),
        'limitations': [
            'One directed plan on one descriptor and one CPU/DMA/GPIO triple.',
            'The recovery re-installs provider/authority/source bindings; it does '
            'not grant storage version, ISR/MMIO or F5/F6 authority.',
            'A carrier refusal is reproduced as evidence, not as a pass: the '
            'compiled shared-slot runtime pins its original launch identities.',
            'Native authority remains with the frozen-window acceptance process.',
        ],
    }


def refusal_summary(*, code, detail, stage, scenario, policy, native=True):
    return {'schema_version': SUMMARY_SCHEMA, 'status': 'refused', 'case': scenario,
            'scope': 'reset-recovery-refusal', 'native': native,
            'reset_policy': policy,
            'refusal': {'code': code, 'reason': detail, 'stage': stage},
            'terminal_probe': {'schema_version': 'reset_recovery_terminal_probe.v1',
                               'terminal': True, 'kind': 'reset-recovery',
                               'normal_campaign_completion': False},
            **scope_fields(),
            'limitations': ['A refusal is never a pass: no verified status was written.']}


# --------------------------------------------------------------------------- #
# The selector: the same directed plan, plus one declared recovery
# --------------------------------------------------------------------------- #

class ResetRecoverySelector(DirectedConsumptionSelector):
    """The directed consumption plan, plus ONE declared epoch-scoped recovery."""

    def __init__(self, name, *, output, reset_policy, recovery_dir,
                 continuation=CONTINUATION_RECORD):
        super().__init__(name, output=output, reset_policy=reset_policy)
        self.recovery_dir = Path(recovery_dir)
        self.continuation = continuation
        self.recovery = None
        self.recovery_document = None
        self.continuation_document = None
        self.continuation_refusal = None
        self.program_declaration = None
        self.outcome = None
        self.outcome_detail = None
        self.pre_reset_authority_token_captured = False
        self.ram_recovery = None

    # The runner only becomes 'running' inside runtime.begin(), which happens
    # after attach_runtime(); the declaration is captured at the first case and
    # is therefore still strictly before the barrier.
    def choose(self):
        if self.recovery is None:
            self._declare_recovery()
        return super().choose()

    def _declare_recovery(self):
        runtime = self._runtime
        paths = runtime.runtime_path_admission['shared_flow_paths']
        target_id = paths['F5']['pin']['component']
        self.recovery = declare_reset_recovery(
            runtime.runner, policy=self.reset_policy,
            sources=dict(runtime.runner.sessions),
            providers={'RAM': self._handle, 'PIN': self._pin_handle},
            authority=runtime.assembly.companion_authorities[target_id],
            carrier=runtime, register='GPIOEN')

    def _declare_epoch_program(self):
        """Declare the slot this epoch resumes at; still before the barrier."""
        from myfuzz.integration.shared_f6_slots import flow_records
        runtime = self._runtime
        try:
            self.program_declaration = {'status': 'reinstalled',
                **self.recovery.declare_epoch_program(
                    contract=runtime.contract, next_slot=len(flow_records(runtime)))}
        except (ValueError, ResetRecoveryRefused) as error:
            # The barrier is still measured; the declaration refusal is recorded
            # as the reason this epoch's program entry has no legal address.
            self.program_declaration = {
                'status': 'unavailable', 'reason': str(error),
                'next_slot': len(flow_records(runtime)),
                'slot_count': runtime.contract['program_contract']['slot_count']}

    def _reset_probe(self):
        # One real pre-reset authority token is the lineage negative control: it
        # may be refused after the barrier, or be consumable only while it still
        # carries its old epoch, but it can never become new-epoch credit.
        try:
            self.pre_reset_authority_token_captured = (
                self.recovery.capture_authority_token())
        except ValueError:
            self.pre_reset_authority_token_captured = False
        self._declare_epoch_program()
        try:
            super()._reset_probe()
        except ResetProbeComplete:
            self._recover_after_barrier()
            raise

    def _apply_reset(self):
        return self.recovery.reset_with_declared_program()

    def _recover_after_barrier(self):
        document = self.recovery.observe()
        save(self.recovery_dir / 'recovery.json', document)
        try:
            self.continuation_document = self.recovery.continue_slot(
                bytes.fromhex(self.continuation), flow=CONTINUATION_FLOW)
        except ResetRecoveryRefused as error:
            self.continuation_refusal = {'code': error.code, 'pointer': error.pointer,
                                         'detail': error.detail}
        if self.name == 'reset-ram' and self.continuation_document is not None:
            self.ram_recovery = _verify_ram_after_reset(
                self._runtime, self._handle, self.steps[-1]['case_id'],
                document['epoch']['after'])
        document = self.recovery.document()
        self.recovery_document = document
        save(self.recovery_dir / 'recovery.json', document)
        save(self.recovery_dir / 'slot_continuation.json',
             document['slot_continuation'])
        self.outcome, self.outcome_detail = classify_outcome(
            document, document['slot_continuation'], ram_recovery=self.ram_recovery)
        save(self.recovery_dir / 'result.json', self.result())

    def result(self):
        document = self.recovery.document() if self.recovery is not None else {}
        return {
            'schema_version': RESULT_SCHEMA,
            'status': self.outcome,
            'detail': self.outcome_detail,
            'case': self.name,
            'reset_policy': self.reset_policy,
            'plan': list(self.plan),
            'continuation_record': self.continuation,
            'continuation_flow': CONTINUATION_FLOW,
            'recovery': document,
            'epoch': document.get('epoch'),
            'barrier': document.get('barrier'),
            'sources': document.get('sources'),
            'program': document.get('program'),
            'relaunch': document.get('relaunch'),
            'program_declaration': self.program_declaration,
            'providers': document.get('providers'),
            'authority': document.get('authority'),
            'lineage': document.get('lineage'),
            'slot_continuation': document.get('slot_continuation'),
            'ram_recovery': self.ram_recovery,
            'continuation_refusal': self.continuation_refusal,
            'pre_reset_authority_token_captured': self.pre_reset_authority_token_captured,
            'provider_invalidation': self.reset_report,
            'process_identity': {
                name: {'pid': getattr(local.process, 'pid', None),
                       'execution': getattr(local, '_execution', None),
                       'reset_epoch': local.reset_epoch}
                for name, local in self._runtime.runner.sessions.items()},
            'layers': {
                'reset_barrier': bool(document.get('barrier')),
                'recovery_reinstall': document.get('status') == REINSTALLED,
                'no_old_epoch_credit': bool(
                    (document.get('lineage') or {}).get('old_epoch_fenced')),
                'epoch_program_entry': (document.get('program') or {}).get('status'),
                'relaunch_accepted': (document.get('relaunch') or {}).get('status'),
                'slot_continuation': (document.get('slot_continuation') or {}).get('status'),
            },
        }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true', required=True)
    parser.add_argument('--scenario', choices=SCENARIOS, default='reset-ram')
    parser.add_argument('--reset-policy', choices=POLICIES, default='warm_all')
    parser.add_argument('--descriptor', default=DEFAULT_DESCRIPTOR)
    parser.add_argument('--cache', type=Path, default=ROOT / DEFAULT_CACHE)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rounds', type=int, default=1024)
    parser.add_argument('--expect', choices=EXPECTATIONS, default='unavailable')
    args = parser.parse_args(argv)

    if args.output.exists():
        print(json.dumps({'status': 'refused', 'code': 'output-exists',
                          'reason': 'reset recovery output must not exist'},
                         sort_keys=True))
        return 2
    if not 1 <= args.rounds <= 65536:
        print(json.dumps({'status': 'refused', 'code': 'invalid-rounds',
                          'reason': 'bounded positive rounds required'}, sort_keys=True))
        return 2
    descriptor_path = Path(args.descriptor)
    if not descriptor_path.is_absolute():
        descriptor_path = ROOT / descriptor_path
    if not descriptor_path.is_file():
        print(json.dumps({'status': 'refused', 'code': 'descriptor-missing',
                          'reason': str(descriptor_path)}, sort_keys=True))
        return 2

    args.output.mkdir(parents=True)
    summary_path = args.output / 'summary.json'
    try:
        from myfuzz.runtime.generic_campaign import load_descriptor, run_descriptor
        selector = ResetRecoverySelector(
            args.scenario, output=args.output / 'original' / 'consumption-diagnostic.json',
            reset_policy=args.reset_policy, recovery_dir=args.output)
        descriptor = load_descriptor(descriptor_path, base_dir=ROOT)
        try:
            run_descriptor(descriptor, flow='mixed', mode='original',
                           case_root=args.output, base_dir=ROOT, cache_dir=args.cache,
                           sequence=list(selector.plan), record_selector=selector,
                           selected_count=len(selector.plan), execution_case_capacity=8,
                           rounds=args.rounds, execution_mode='acceptance')
        except ResetProbeComplete:
            pass
        if selector.recovery_document is None or selector.outcome is None:
            raise ResetRecoveryMismatch(
                'recovery-not-observed',
                'the measured reset barrier and its re-install were not observed')
        result = selector.result()
        digest = sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
        summary = build_summary(
            result, scenario=args.scenario, policy=args.reset_policy,
            descriptor=descriptor_path, cache=args.cache, rounds=args.rounds,
            expect=args.expect, outcome=selector.outcome,
            detail=selector.outcome_detail, semantic_sha256=digest)
        save(summary_path, summary)
    except ResetRecoveryMismatch as error:
        save(summary_path, refusal_summary(code=error.code, detail=error.detail,
                                           stage='reset-recovery', scenario=args.scenario,
                                           policy=args.reset_policy))
        print(json.dumps({'status': 'mismatch', 'code': error.code,
                          'reason': error.detail, 'output': str(args.output)},
                         sort_keys=True))
        return 2
    except ResetRecoveryRefused as error:
        save(summary_path, refusal_summary(
            code=error.code, detail=(str(error) + ' ' + json.dumps(error.detail,
                                                                    sort_keys=True)),
            stage='reset-recovery', scenario=args.scenario, policy=args.reset_policy))
        print(json.dumps({'status': 'refused', 'code': error.code,
                          'pointer': error.pointer, 'output': str(args.output)},
                         sort_keys=True))
        return 2
    except (OSError, ValueError, KeyError, TypeError) as error:
        save(summary_path, refusal_summary(code='case-execution-failed', detail=str(error),
                                           stage='native-execution',
                                           scenario=args.scenario,
                                           policy=args.reset_policy))
        print(json.dumps({'status': 'refused', 'code': 'case-execution-failed',
                          'reason': str(error), 'output': str(args.output)},
                         sort_keys=True))
        return 2
    except Exception as error:  # a real native failure is never a pass either
        detail = type(error).__name__ + ': ' + str(error)
        save(summary_path, refusal_summary(code='native-execution-failed', detail=detail,
                                           stage='native-execution',
                                           scenario=args.scenario,
                                           policy=args.reset_policy))
        print(json.dumps({'status': 'refused', 'code': 'native-execution-failed',
                          'reason': detail, 'output': str(args.output)},
                         sort_keys=True))
        return 2
    if selector.outcome != args.expect:
        code = 'outcome-not-the-declared-expectation'
        save(summary_path, build_summary(
            result, scenario=args.scenario, policy=args.reset_policy,
            descriptor=descriptor_path, cache=args.cache, rounds=args.rounds,
            expect=args.expect, outcome='mismatch',
            detail=code + ': measured ' + str(selector.outcome),
            semantic_sha256=summary['semantic_sha256']))
        print(json.dumps({'status': 'mismatch', 'code': code,
                          'measured': selector.outcome, 'expected': args.expect,
                          'output': str(args.output)}, sort_keys=True))
        return 2
    print(json.dumps({'status': selector.outcome,
                      'code': (result.get('slot_continuation') or {}).get('code'),
                      'epochs_advanced': (result.get('epoch') or {}).get('advanced'),
                      'layers': (result.get('layers') or {}),
                      'output': str(args.output)}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
