#!/usr/bin/env python3
"""Run the fixed-instance VexiiRiscv CPU + PULP GPIO IRQ row and preserve evidence.

Two complete rows are produced by two independent child processes. Each child
renders and builds its own artifacts (from the shared identity-keyed cache),
starts its own native CPU and GPIO processes, and writes one full evidence
document. The parent compares the two documents and writes the compressed
evidence plus a recomputable summary.

The row itself is implemented in
``myfuzz.scenario.vexii_pulp_gpio_fixed``; this script is only orchestration and
evidence publication, not a second scenario framework.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

BASE = Path(__file__).resolve().parents[1]
SRC = BASE / 'src'
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

EVIDENCE_SCHEMA = 'vexi_pulp_gpio_irq_fixed_evidence.v1'


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json_bytes(document: object) -> bytes:
    return (json.dumps(document, sort_keys=True, indent=1, ensure_ascii=False) + '\n').encode()


def _gzip(raw: bytes) -> bytes:
    # mtime=0 keeps the compressed evidence stable for identical content.
    return gzip.compress(raw, compresslevel=9, mtime=0)


def _implementation_identity() -> dict[str, object]:
    from myfuzz.scenario import vexii_pulp_gpio_fixed

    def file_row(path: Path) -> dict[str, str]:
        return {'path': str(path.relative_to(BASE)), 'sha256': _sha256(path.read_bytes())}

    return {
        'schema_version': 'vexi_pulp_gpio_irq_implementation.v1',
        'scenario_module': file_row(Path(vexii_pulp_gpio_fixed.__file__).resolve()),
        'gate_script': file_row(Path(__file__).resolve()),
        'derived_profile': file_row(BASE / 'configs/cpus/vexiiriscv_irq/component_profile.json'),
        'derived_contract': file_row(BASE / 'src/myfuzz/local_harness/vexii_irq_contract.py'),
        'driver_header': file_row(BASE / 'src/myfuzz/local_harness/rtl/local_driver_v1.h'),
    }


def _child(arguments: argparse.Namespace) -> int:
    from myfuzz.scenario.vexii_pulp_gpio_fixed import (DEFAULT_CASES,
        VexiiPulpGpioIrqFixedChain, validate_cases)

    cases = validate_cases(tuple(arguments.cases)) if arguments.cases else DEFAULT_CASES
    started = time.time()
    chain = VexiiPulpGpioIrqFixedChain(base_dir=Path(arguments.base_dir),
                                       cache_dir=Path(arguments.cache),
                                       cases=cases)
    document = chain.run(arguments.testcase)
    document['implementation'] = _implementation_identity()
    document['measurement'] = {
        'schema_version': 'vexi_pulp_gpio_irq_measurement.v1',
        'wall_seconds': round(time.time() - started, 3),
        'child_pid': os.getpid(),
        'python': sys.version.split()[0],
        'cases': list(cases),
    }
    raw = _json_bytes(document)
    Path(arguments.single_run).write_bytes(raw)
    print(json.dumps({'status': document['status'], 'bytes': len(raw),
                      'wall_seconds': document['measurement']['wall_seconds'],
                      'cpu_ticks': document['counts']['cpu_ticks'],
                      'gpio_ticks': document['counts']['gpio_ticks'],
                      'cases': len(cases)}, sort_keys=True))
    return 0 if document['status'] == 'verified' else 1


def _spawn(arguments: argparse.Namespace, output: Path, label: str) -> tuple[Path, subprocess.CompletedProcess, float]:
    target = output / f'{label}.json'
    command = [sys.executable, str(Path(__file__).resolve()), '--single-run', str(target),
               '--testcase', f'vexii-gpio-irq-{label}', '--cache', str(Path(arguments.cache))]
    if arguments.cases:
        command += ['--cases', *[str(value) for value in arguments.cases]]
    environment = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
                   'PYTHONPATH': str(SRC), 'LC_ALL': 'C'}
    started = time.time()
    completed = subprocess.run(command, cwd=str(Path(arguments.base_dir)),
                               env=environment, capture_output=True, text=True,
                               timeout=arguments.timeout)
    return target, completed, time.time() - started


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--output', default=str(BASE / 'docs/reports/evidence/vexi-irq-fixed-20261018'))
    parser.add_argument('--base-dir', default=str(BASE))
    parser.add_argument('--cache', default=str(Path(os.environ.get(
        'MYFUZZ_VEXII_IRQ_CACHE', Path.home() / '.cache/myfuzz/vexi-irq'))))
    parser.add_argument('--cases', type=int, nargs='*', default=None,
                        help='explicit case values; defaults to the row defaults')
    parser.add_argument('--timeout', type=float, default=1800.0)
    parser.add_argument('--single-run', default=None, help=argparse.SUPPRESS)
    parser.add_argument('--testcase', default='vexii-gpio-irq-row', help=argparse.SUPPRESS)
    arguments = parser.parse_args(argv)
    if arguments.single_run:
        return _child(arguments)

    from myfuzz.scenario.vexii_pulp_gpio_fixed import compare_fresh_runs

    output = Path(arguments.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    results = {}
    logs = {}
    for label in ('first', 'fresh'):
        target, completed, wall = _spawn(arguments, output, label)
        logs[label] = {'exit_code': completed.returncode, 'stdout': completed.stdout[-4000:],
                       'stderr': completed.stderr[-4000:], 'wall_seconds': round(wall, 3)}
        if completed.returncode != 0 or not target.is_file():
            summary = {'schema_version': EVIDENCE_SCHEMA, 'status': 'failed',
                       'reason': f'{label} child run failed', 'logs': logs}
            (output / 'summary.json').write_bytes(_json_bytes(summary))
            print(json.dumps(summary, sort_keys=True))
            return 1
        results[label] = json.loads(target.read_bytes())
    replay = compare_fresh_runs(results['first'], results['fresh'])
    artifacts = {}
    for label in ('first', 'fresh'):
        source = output / f'{label}.json'
        raw = source.read_bytes()
        compressed = _gzip(raw)
        (output / f'{label}.json.gz').write_bytes(compressed)
        artifacts[label] = {'json_sha256': _sha256(raw), 'json_bytes': len(raw),
                            'gzip_sha256': _sha256(compressed),
                            'gzip_bytes': len(compressed)}
        # Keep the repository evidence to the compressed documents; the
        # summary pins their uncompressed hashes so the gzip can be verified.
        source.unlink()
    summary = {
        'schema_version': EVIDENCE_SCHEMA,
        'status': ('verified' if replay['matches'] else 'failed'),
        'command': [sys.executable, str(Path(__file__).resolve()), '--output', str(output)]
                   + (['--cases'] + [str(value) for value in arguments.cases]
                      if arguments.cases else []),
        'repository_head': _head(arguments.base_dir),
        'cases': results['first']['program']['cases'],
        'program': {key: value for key, value in results['first']['program'].items()
                    if key not in ('cases',)},
        'counts': {'first': results['first']['counts'], 'fresh': results['fresh']['counts']},
        'execution': replay['first_execution'],
        'fresh_execution': replay['fresh_execution'],
        'implementation': results['first'].get('implementation'),
        'replay': replay,
        'artifacts': artifacts,
        'children': logs,
        'row_checks': {'first': results['first']['checks'], 'fresh': results['fresh']['checks']},
        'boundaries': [
            'Two real native processes per row: one pinned generated VexiiRiscv CPU '
            'and one pinned PULP apb_gpio target.',
            'Each case is one CPU -> APB register write -> GPIO real interrupt pulse '
            '-> host level wire -> real core trap at the program mtvec -> ISR real '
            'APB reads/PADOUTCLR write -> mret -> main RAM check.',
            'The host converts the GPIO transition pulse to the level the core '
            'requires and drops it after the actual PADOUTCLR delivery; it injects '
            'no trap, cause or vector.',
            'The GPIO input is a declared loopback of its real gpio_out output, not '
            'a CPU pin.',
            'The program image is fixed per row and case data comes from a preloaded '
            'RAM table; this is not the P6 campaign framework (no online genome '
            'mutation, coverage feedback, arbitrary program-image replay or '
            'cross-case arbitrary harness reuse).',
        ],
    }
    raw = _json_bytes(summary)
    (output / 'summary.json').write_bytes(raw)
    print(json.dumps({'schema_version': EVIDENCE_SCHEMA, 'status': summary['status'],
                      'replay_matches': replay['matches'],
                      'first_execution': replay['first_execution'],
                      'fresh_execution': replay['fresh_execution'],
                      'cpu_ticks': summary['counts']['first']['cpu_ticks'],
                      'cases': len(summary['cases']),
                      'artifacts': artifacts}, sort_keys=True))
    return 0 if summary['status'] == 'verified' else 1


def _head(base_dir: str) -> str | None:
    try:
        completed = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=base_dir,
                                   capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    value = completed.stdout.strip()
    return value if completed.returncode == 0 and len(value) == 40 else None


if __name__ == '__main__':
    sys.exit(main())
