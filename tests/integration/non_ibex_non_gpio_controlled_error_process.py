#!/usr/bin/env python3
"""One isolated OS process for the CV32E40P + OpenTitan UART negative case.

The caller (``test_non_ibex_non_gpio_controlled_error_real.py``) invokes this
driver once per phase so that the normal run, the fault run, both fresh RTL
replays and the checker recheck are genuinely separate processes:

* ``run``    - execute the real RTL scenario once and publish a full evidence
  bundle.  ``--group control`` uses the unmodified sibling factory;
  ``--group fault`` wraps the UART target session with the one-shot RDATA
  response perturbation.
* ``replay`` - load a saved bundle, build fresh RTL sessions, compare the
  complete trace with the saved one, and re-run the independent checker on the
  replay trace.
* ``check``  - read already-saved trace JSON files only (no RTL, no harness)
  and run a fresh ``IbexUartOnlineChecker`` on each one.

Every invocation writes exactly one observation JSON file.  No command rewrites
the saved evidence tree or any file under ``third_party/``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from myfuzz.scenario.ibex_uart_online_checker import IbexUartOnlineChecker
from myfuzz.scenario.session_runtime import OnlineCaseReceipt, _checker_identity

SCHEMA = 'p6_non_ibex_non_gpio_process_observation.v1'
EXPECTED_VIOLATION = 'uart_rxdata_source_mismatch'
SOURCE_BYTE = 0x5a
INJECTED_BYTE = SOURCE_BYTE ^ 1
RDATA_OFFSET = 0x18
CPU_PROFILE = 'configs/cpus/cv32e40p/component_profile.json'
UART_PROFILE = 'configs/peripherals/opentitan_uart_local/component_profile.json'
UART_DEVICE = 'uart'
GENOME_ID = 'cv32e40p-opentitan-uart-rx-watermark-irq'
_STARTED_UNIX_NS = time.time_ns()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, document: dict) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True,
                               ensure_ascii=False) + '\n', encoding='utf-8')


def _process(role: str, group: str) -> dict:
    return {
        'role': role,
        'group': group,
        'pid': os.getpid(),
        'parent_pid': os.getppid(),
        'argv': list(sys.argv),
        'cwd': os.getcwd(),
        'python': sys.executable,
        'python_version': sys.version.split()[0],
        'started_unix_ns': _STARTED_UNIX_NS,
        'finished_unix_ns': time.time_ns(),
        'environment': {
            'MYFUZZ_SCENARIO_REAL': os.environ.get('MYFUZZ_SCENARIO_REAL'),
            'MYFUZZ_CONTROLLED_ERROR_OUTPUT':
                os.environ.get('MYFUZZ_CONTROLLED_ERROR_OUTPUT'),
            'PYTHONPATH': os.environ.get('PYTHONPATH'),
        },
    }


def _common(role: str, group: str) -> dict:
    return {
        'schema_version': SCHEMA,
        'role': role,
        'group': group,
        'expected_violation': EXPECTED_VIOLATION,
        'checker': _checker_identity(IbexUartOnlineChecker()),
        'chain': {
            'cpu_profile': CPU_PROFILE,
            'target_profile': UART_PROFILE,
            'target_device_id': UART_DEVICE,
            'genome_testcase_id': GENOME_ID,
        },
        'process': _process(role, group),
    }


def _load_case_helpers():
    """Import the real-chain helpers only in modes that execute RTL."""
    from tests.integration.test_scenario_cv32e40p_opentitan_uart_irq_real import (
        RESULT, _artifact, _genome, _make_factory)
    from tests.integration.test_cv32e40p_opentitan_uart_controlled_error_real import (
        RdataResponseFault, _findings, _make_injecting_factory,
        _violation_evidence)
    return {
        'RESULT': RESULT,
        '_artifact': _artifact,
        '_genome': _genome,
        '_make_factory': _make_factory,
        'RdataResponseFault': RdataResponseFault,
        '_findings': _findings,
        '_make_injecting_factory': _make_injecting_factory,
        '_violation_evidence': _violation_evidence,
    }


def _factory(helpers, group: str, cpu_artifact, uart_artifact, cache_dir,
             faults: list):
    if group == 'control':
        return helpers['_make_factory'](cpu_artifact, uart_artifact, cache_dir)
    return helpers['_make_injecting_factory'](
        cpu_artifact, uart_artifact, cache_dir, faults)


def _case_observation(helpers, trace, *, group: str, label: str,
                      instances, faults: list) -> dict:
    findings = helpers['_findings'](trace, label)
    evidence = helpers['_violation_evidence'](trace, findings)
    memory = instances[0].sessions['cpu'].memory.read(
        helpers['RESULT'], 4, transaction_id=f'{label}-rdata')
    return {
        'status': trace.status,
        'event_count': len(trace.events),
        'local_ticks': dict(trace.local_ticks),
        'semantic_sha256': trace.semantic_sha256,
        'manifest_sha256': trace.manifest_sha256,
        'findings': list(findings),
        'evidence': evidence,
        'persistent_ram_rdata': memory.value,
        'fault_document': (faults[0].document
                           if group == 'fault' and faults else None),
    }


def run(args: argparse.Namespace) -> None:
    helpers = _load_case_helpers()
    bundle = Path(args.bundle)
    if bundle.exists():
        raise SystemExit(f'bundle must be new: {bundle}')
    cpu_artifact = helpers['_artifact'](CPU_PROFILE, 'cpu')
    uart_artifact = helpers['_artifact'](UART_PROFILE, UART_DEVICE)
    genome = helpers['_genome']()
    faults: list = []
    factory, instances = _factory(helpers, args.group, cpu_artifact,
                                  uart_artifact, Path(args.cache), faults)
    trace = save_bundle(genome, factory, bundle)
    document = _common('run', args.group)
    document.update(_case_observation(
        helpers, trace, group=args.group,
        label=f'non-ibex-non-gpio-{args.group}-run',
        instances=instances, faults=faults))
    document.update({
        'bundle': str(bundle.resolve()),
        'bundle_trace_json_sha256': _sha256(bundle / 'trace.json'),
        'bundle_index_sha256': _sha256(bundle / 'bundle_index.json'),
    })
    if args.group == 'fault':
        if document['fault_document'] is None:
            raise SystemExit('the controlled RDATA perturbation never fired')
        if document['fault_document']['real_rtl_rdata'] != SOURCE_BYTE:
            raise SystemExit('the controlled perturbation did not witness 0x5a')
        if document['fault_document']['delivered_rdata'] != INJECTED_BYTE:
            raise SystemExit('the controlled perturbation did not deliver 0x5b')
        if document['findings'] != [EXPECTED_VIOLATION]:
            raise SystemExit('the fault group was not caught as expected')
    elif document['findings']:
        raise SystemExit('the control group was not silent')
    _write_json(Path(args.observation), document)


def save_bundle(genome, factory, bundle: Path):
    from myfuzz.scenario.evidence import save_evidence_bundle
    return save_evidence_bundle(genome, factory, bundle)


def replay(args: argparse.Namespace) -> None:
    helpers = _load_case_helpers()
    bundle = Path(args.bundle)
    cpu_artifact = helpers['_artifact'](CPU_PROFILE, 'cpu')
    uart_artifact = helpers['_artifact'](UART_PROFILE, UART_DEVICE)
    faults: list = []
    factory, instances = _factory(helpers, args.group, cpu_artifact,
                                  uart_artifact, Path(args.cache), faults)
    from myfuzz.scenario.evidence import replay_evidence_bundle
    comparison = replay_evidence_bundle(bundle, factory)
    trace = comparison.actual_trace
    observation = _case_observation(
        helpers, trace, group=args.group,
        label=f'non-ibex-non-gpio-{args.group}-fresh-replay',
        instances=instances, faults=faults)
    trace_path = Path(args.trace_out)
    _write_json(trace_path, {
        'schema_version': 'p6_non_ibex_non_gpio_replay_trace.v1',
        'status': trace.status,
        'events': trace.events,
        'local_ticks': dict(trace.local_ticks),
        'semantic_sha256': trace.semantic_sha256,
        'manifest_sha256': trace.manifest_sha256,
    })
    document = _common('replay', args.group)
    document.update(observation)
    document.update({
        'source_bundle': str(bundle.resolve()),
        'source_bundle_trace_json_sha256': _sha256(bundle / 'trace.json'),
        'replay': {
            'matches': comparison.matches,
            'first_difference': comparison.first_difference,
            'verification_scope': comparison.verification_scope,
            'difference_context': comparison.difference_context,
            'expected_event': comparison.expected_event,
            'actual_event': comparison.actual_event,
        },
        'replay_trace': str(trace_path.resolve()),
        'replay_trace_json_sha256': _sha256(trace_path),
    })
    if not comparison.matches:
        raise SystemExit('fresh RTL replay did not match the saved trace')
    if args.group == 'fault':
        if document['fault_document'] is None:
            raise SystemExit('the controlled RDATA perturbation never fired '
                             'during replay')
        if document['findings'] != [EXPECTED_VIOLATION]:
            raise SystemExit('the fresh replay did not reproduce the violation')
    elif document['findings']:
        raise SystemExit('the control fresh replay was not silent')
    _write_json(Path(args.observation), document)


def check(args: argparse.Namespace) -> None:
    results: dict[str, dict] = {}
    for item in args.trace:
        if '=' not in item:
            raise SystemExit(f'--trace must be LABEL=PATH: {item}')
        label, raw_path = item.split('=', 1)
        path = Path(raw_path)
        document = json.loads(path.read_text(encoding='utf-8'))
        events = tuple(document['events'])
        local_ticks = dict(document['local_ticks'])
        receipt = OnlineCaseReceipt(label, 0, len(events), events, {},
                                    local_ticks, document['status'])
        findings = IbexUartOnlineChecker()(receipt)
        results[label] = {
            'findings': list(findings),
            'status': document['status'],
            'event_count': len(events),
            'local_ticks': local_ticks,
            'manifest_sha256': document.get('manifest_sha256'),
            'trace_json_sha256': _sha256(path),
            'path': str(path.resolve()),
        }
    document = _common('check', args.group)
    document['results'] = results
    _write_json(Path(args.observation), document)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='role', required=True)

    run_parser = sub.add_parser('run')
    run_parser.add_argument('--group', choices=('control', 'fault'),
                            required=True)
    run_parser.add_argument('--bundle', required=True)
    run_parser.add_argument('--cache', required=True)
    run_parser.add_argument('--observation', required=True)

    replay_parser = sub.add_parser('replay')
    replay_parser.add_argument('--group', choices=('control', 'fault'),
                               required=True)
    replay_parser.add_argument('--bundle', required=True)
    replay_parser.add_argument('--cache', required=True)
    replay_parser.add_argument('--trace-out', required=True)
    replay_parser.add_argument('--observation', required=True)

    check_parser = sub.add_parser('check')
    check_parser.add_argument('--group', choices=('control', 'fault'),
                              required=True)
    check_parser.add_argument('--trace', action='append', default=[],
                              required=True)
    check_parser.add_argument('--observation', required=True)

    args = parser.parse_args(argv)
    if args.role == 'run':
        run(args)
    elif args.role == 'replay':
        replay(args)
    else:
        check(args)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
