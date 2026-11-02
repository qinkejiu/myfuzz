"""Bounded component integration probe, not a search/coverage experiment."""
import argparse
from dataclasses import asdict, is_dataclass
import json
from pathlib import Path
import signal
import time
import traceback

from .actions import Decision
from .r1_session import create_r1_session


def _default(value):
    if is_dataclass(value):
        return asdict(value)
    raise TypeError(type(value).__name__)


def _capture_and_close(assembly, save, primary_error):
    error = primary_error
    try:
        save('events.json', assembly.runner.events_since(0))
        save('registers.json', assembly.registers.snapshot())
    except BaseException as exc:
        error = error or exc
        raise
    finally:
        assembly.close(error)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--cache', required=True, type=Path)
    parser.add_argument('--timeout-seconds', type=int, default=180)
    parser.add_argument('--fresh-from', type=Path,
                        help='independently reconstruct and compare a passed directed probe')
    parser.add_argument('--with-pin', action='store_true',
                        help='include typed pin low/high and verify native GPIOEN-to-IRQ consumption')
    args = parser.parse_args()
    if not 1 <= args.timeout_seconds <= 600:
        parser.error('timeout-seconds must be within 1..600')
    args.output.mkdir(parents=True, exist_ok=False)
    def save(name, document):
        (args.output / name).write_text(json.dumps(document, default=_default,
            ensure_ascii=False, indent=2, allow_nan=False) + '\n')
    started, assembly, error = time.monotonic(), None, None
    results, processes = [], {}
    def timed_out(signum, frame):
        raise TimeoutError('bounded R1 component probe expired')
    signal.signal(signal.SIGALRM, timed_out)
    signal.signal(signal.SIGTERM, timed_out)
    signal.alarm(args.timeout_seconds)
    try:
        assembly = create_r1_session(cache_dir=args.cache, advance_rounds=96)
        if args.with_pin:
            from .gpio_actions import validate_pin_session
            validate_pin_session(assembly.session)
        save('catalog.json', assembly.space.document())
        save('configuration.json', assembly.registers.configuration())
        assembly.begin()
        print('bootstrap-ready', flush=True)
        processes = {name: session.process for name, session in assembly.runner.sessions.items()}
        sequence = [('gpioen:write', 256)]
        if args.with_pin:
            sequence.extend((('pin8:event', 0), ('pin8:event', 1)))
        sequence.append(('gpioen:read', assembly.space.result_address))
        for index, (action, value) in enumerate(sequence):
            decision = Decision(index, 'r1:gpioen', 'directed:probe', action, value,
                                'component-integration', index)
            result = assembly.submit(decision, case_id=f'r1-component-{index}')
            results.append(dict(decision=decision.document(), result=result,
                field=assembly.field_state(), relations=assembly.observer.report(),
                irq=assembly.observer.irq_report()))
            save('steps.json', results)
            print(json.dumps(dict(step=index, action=action, runner=assembly.runner._status,
                field=results[-1]['field']['status'],
                relation=results[-1]['relations']['status'])), flush=True)
        report = assembly.observer.report()
        if (assembly.runner._status != 'running' or not report['reward_eligible']
                or results[-1]['field']['status'] != 'observed'):
            raise RuntimeError('probe lacks a running exact cross-case write/read relation')
        if args.with_pin and not assembly.observer.irq_report()['reward_eligible']:
            raise RuntimeError('probe lacks exact cross-case GPIOEN-to-native-IRQ consumption')
        plan = assembly.session.encode_plan()
        (args.output / 'plan.json').write_bytes(plan)
        launches = assembly.runner.sessions['gpio_b'].built_executable_launch_observations()
        save('live-launches.json', launches)
        if args.fresh_from is not None:
            original = args.fresh_from
            previous = json.loads((original / 'summary.json').read_text())
            old_steps = json.loads((original / 'steps.json').read_text())
            old_launches = json.loads((original / 'live-launches.json').read_text())
            checks = dict(original_passed=previous['status'] == 'passed',
                plan_identical=(original / 'plan.json').read_bytes() == plan,
                decisions_identical=[r['decision'] for r in old_steps] == [r['decision'] for r in results],
                observations_identical=[[r['field'], r['relations'], r.get('irq')] for r in old_steps]
                    == json.loads(json.dumps([[r['field'], r['relations'], r.get('irq')] for r in results])),
                distinct_gpio_execution=(len(launches) == len(old_launches) == 1
                    and launches[0]['execution_nonce'] != old_launches[0]['execution_nonce']))
            save('fresh-comparison.json', checks)
            if not all(checks.values()):
                raise RuntimeError('independent directed reconstruction differs')
    except BaseException as exc:
        error = exc
        save('failure.json', dict(error=repr(exc), traceback=traceback.format_exc()))
    finally:
        signal.alarm(0)
        if assembly is not None:
            processes.update({name: session.process for name, session in assembly.runner.sessions.items()
                              if session.process is not None})
            try:
                _capture_and_close(assembly, save, error)
            except BaseException as exc:
                error = error or exc
        save('summary.json', dict(status='failed' if error else 'passed',
            scope='directed_component_probe_only', wall_seconds=time.monotonic()-started,
            mixed_pin_requested=args.with_pin,
            mixed_pin_supported=bool(assembly is not None and assembly.registers.external_sources),
            independent_reconstruction=args.fresh_from is not None,
            completed_steps=len(results), search_benefit_proven=False,
            irq_consumption_proven=bool(not error and args.with_pin),
            irq_scope='GPIOEN-to-native-GPIO-IRQ only; no CPU delivery or ISR proof',
            processes={name: dict(reaped=p.poll() is not None, exit_code=p.poll())
                       for name, p in processes.items() if p is not None}))
    if error is not None:
        raise error


if __name__ == '__main__':
    from myfuzz.local_harness.build import host_source_discovery_scope
    with host_source_discovery_scope(reuse_nested=True):
        main()
