#!/usr/bin/env python3
"""Replay one recorded independent component on an instrumented harness."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from myfuzz.local_harness.coverage import (measure_cached_harness,coverage_budget,validate_wire_budget,requested_coverage_overrides)


def select_recorded_session(document, component: str, build_digest: str, *, max_commands=512,
                            max_input_bytes=64*1024*1024,max_output_bytes=64*1024*1024,max_wall_seconds=60):
    coverage_budget(max_commands=max_commands,max_input_bytes=max_input_bytes,max_output_bytes=max_output_bytes,max_wall_seconds=max_wall_seconds)
    if (not isinstance(document, dict)
            or document.get('schema_version') != 'local_command_trace.v1'
            or not isinstance(document.get('sessions'), dict)):
        raise ValueError('invalid-local-command-trace')
    row = document['sessions'].get(component)
    if not isinstance(row, dict) or row.get('complete') is not True:
        raise ValueError('incomplete-local-command-trace')
    identity, records = row.get('identity'), row.get('records')
    if (not isinstance(identity, dict) or identity.get('build_digest') != build_digest
            or not isinstance(records, list) or not 1 <= len(records) <= max_commands):
        raise ValueError('local-command-identity-mismatch')
    nonce = identity.get('execution_nonce')
    binary = identity.get('binary_sha256')
    if (not isinstance(nonce, str) or not re.fullmatch(r'[0-9a-f]{32}', nonce)
            or not isinstance(binary, str) or not re.fullmatch(r'[0-9a-f]{64}', binary)):
        raise ValueError('local-command-identity-mismatch')
    commands, replies = [], []
    for index, record in enumerate(records, 1):
        if not isinstance(record, dict):
            raise ValueError('invalid-local-command-record')
        command, reply = record.get('command'), record.get('reply')
        if (type(record.get('sequence')) is not int or record['sequence'] != index
                or type(record.get('reset_epoch')) is not int or record['reset_epoch'] != 0
                or not isinstance(command, str) or not isinstance(reply, str)
                or not command.isascii() or len(command)>4096
                or not command.startswith(f'CMD {nonce} {index:x} ')
                or not reply.startswith(f'RESULT {nonce} {index:x} ')):
            raise ValueError('invalid-local-command-record')
        commands.append(command)
        replies.append(reply)
    validate_wire_budget(commands,max_input_bytes=max_input_bytes,expected_replies=replies,max_output_bytes=max_output_bytes)
    return commands, replies, binary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trace', type=Path, required=True)
    parser.add_argument('--component', required=True)
    parser.add_argument('--cache', type=Path, required=True,
                        help='original content-addressed component cache directory')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--max-commands',type=int,default=512)
    parser.add_argument('--max-input-bytes',type=int,default=64*1024*1024)
    parser.add_argument('--max-output-bytes',type=int,default=64*1024*1024)
    parser.add_argument('--max-wall-seconds',type=float,default=60)
    parser.add_argument('--build-jobs',type=int,default=None,
                        help='optional compile-schedule cap (1-64); does not change the instrumentation')
    args = parser.parse_args(argv)
    try:
        options=requested_coverage_overrides(coverage_budget(max_commands=args.max_commands,
            max_input_bytes=args.max_input_bytes,max_output_bytes=args.max_output_bytes,max_wall_seconds=args.max_wall_seconds))
        cache = args.cache.resolve()
        document = json.loads(args.trace.read_text(encoding='utf-8'))
        commands, replies, binary = select_recorded_session(document, args.component, cache.name,**options)
        if sha256((cache / 'harness').read_bytes()).hexdigest() != binary:
            raise ValueError('recorded-binary-mismatch')
        result = measure_cached_harness(cache, args.output, commands,
                                        expected_replies=replies,max_build_jobs=args.build_jobs,
                                        **options)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({'status': 'refused', 'reason': str(error)}))
        return 2
    print(json.dumps({'status': 'measured', 'component': args.component,
                      'output': str(args.output), 'coverage_kind': result['coverage_kind'],
                      'source_selection': result['source_selection'],
                      'replay': result['replay']}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
