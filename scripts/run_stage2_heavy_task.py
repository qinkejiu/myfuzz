#!/usr/bin/env python3
"""Run one serialized stage-2 build, search, or replay with a durable receipt.

The command is an argv array after ``--``. ``{run_dir}`` and ``{cache_dir}``
may be used in individual arguments. Every heavy stage-2 task should enter here
so memory admission, one-worker locking, JVM heap checks, cleanup, and the
resource receipt use the same policy.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT/'src'
if SRC.as_posix() not in sys.path:
    sys.path.insert(0, SRC.as_posix())

from myfuzz.experiments.resource_policy import (  # noqa: E402
    ResourceProfileError, run_budgeted_process)

DEFAULT_CACHE = ROOT/'.superpowers'/'cache'/'local-harness'
LOCK_PATH = ROOT/'.superpowers'/'sdd'/'stage2-heavy-worker.lock'
RECEIPT_NAME = 'stage2_heavy_task_receipt.json'


def _dump(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False)


def _write(path: Path, value: str) -> None:
    path.write_text(value, encoding='utf-8')


def _arguments(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', required=True, type=Path,
                        help='new directory receiving command logs and the resource receipt')
    parser.add_argument('--cache-dir', type=Path, default=DEFAULT_CACHE,
                        help='shared identity-keyed local harness cache')
    parser.add_argument('command', nargs=argparse.REMAINDER,
                        help='heavy command argv after --; supports {run_dir}/{cache_dir}')
    args = parser.parse_args(argv)
    if args.command and args.command[0] == '--':
        args.command = args.command[1:]
    return args


def main(argv: list[str] | None = None) -> int:
    args = _arguments(argv)
    output_dir = args.output_dir.absolute()
    cache_dir = args.cache_dir.absolute()
    if output_dir.exists() or output_dir.is_symlink():
        print('stage2-heavy-task-error: output directory must be new', file=sys.stderr)
        return 1
    command = [token.replace('{run_dir}', str(output_dir.resolve()))
               .replace('{cache_dir}', str(cache_dir.resolve()))
               for token in args.command]
    base = {'schema_version': 'stage2_heavy_task_receipt.v1',
            'started_at': datetime.now(timezone.utc).isoformat(),
            'run_dir': str(output_dir.resolve()), 'build_cache': str(cache_dir.resolve()),
            'command': command, 'workers': 1, 'dut_finding': False}
    try:
        if not command or any(not isinstance(token, str) or not token for token in command):
            raise ResourceProfileError('command must be a non-empty argument array')
        output_dir.mkdir(parents=True, exist_ok=False)
    except (OSError, ResourceProfileError) as exc:
        print(f'stage2-heavy-task-error: {exc}', file=sys.stderr)
        return 1

    result = None
    error = None
    try:
        result = run_budgeted_process(
            command, lock_path=LOCK_PATH)
        (output_dir/'stdout.log').write_text(result.stdout, encoding='utf-8')
        (output_dir/'stderr.log').write_text(result.stderr, encoding='utf-8')
        status = result.resource_receipt['status']
    except ResourceProfileError as exc:
        error = str(exc)
        resource = getattr(exc, 'resource_receipt', {
            'schema_version': 'heavy_process_resource_receipt.v1',
            'status': 'startup_refused', 'dut_finding': False, 'workers': 1,
            'peak_tree_rss_bytes': None, 'elapsed_seconds': None})
        (output_dir/'stdout.log').write_text('', encoding='utf-8')
        (output_dir/'stderr.log').write_text(error+'\n', encoding='utf-8')
        status = resource.get('status', 'startup_refused')
    else:
        resource = result.resource_receipt
    if result is not None:
        resource = result.resource_receipt
    stdout_path = output_dir/'stdout.log'
    stderr_path = output_dir/'stderr.log'
    document = {
        **base, 'status': status,
        'command_exit_code': None if result is None else result.returncode,
        'error': error,
        'resource': resource,
        'stdout_sha256': hashlib.sha256(stdout_path.read_bytes()).hexdigest(),
        'stderr_sha256': hashlib.sha256(stderr_path.read_bytes()).hexdigest(),
    }
    _write(output_dir/RECEIPT_NAME, _dump(document)+'\n')
    if result is None:
        print(f'stage2-heavy-task-error: {error}', file=sys.stderr)
        return 1
    print(_dump(document))
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
