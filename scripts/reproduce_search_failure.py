#!/usr/bin/env python3
"""Explicitly reproduce an authenticated failed search prefix in a fresh worker."""
import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'src'))
from myfuzz.search.failure_replay import run_worker


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--specimen', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=float, default=300)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.worker:
        result = run_worker(args.specimen, args.output)
    else:
        import math
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            parser.error('--timeout must be positive and finite')
        if args.output.exists() or args.output.is_symlink():
            parser.error('--output must be new')
        args.output.mkdir(parents=True)
        from scripts.run_search_comparison import execute
        execution = execute([sys.executable, str(Path(__file__).resolve()), '--worker',
            '--specimen', str(args.specimen.resolve()), '--output', str((args.output/'worker').resolve())],
            args.output, args.timeout, dict(os.environ))
        path = args.output/'worker/failure-replay.json'
        if execution['timed_out'] or execution['returncode'] != 0 or not path.is_file():
            result = {'status':'replay-error','accepted':False,'dut_bug':False,
                'reason':'worker-timed-out' if execution['timed_out'] else 'worker-failed', 'execution':execution}
        else:
            result = json.loads(path.read_text())
            result['execution'] = execution
        (args.output/'failure-replay.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))
    return 0 if args.worker or result['status'] == 'reproduced' else 1


if __name__ == '__main__':
    raise SystemExit(main())
