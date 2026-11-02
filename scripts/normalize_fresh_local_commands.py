#!/usr/bin/env python3
"""Reviewed converter: raw saved command list -> ``local_command_trace.v1``.

A declared-IRQ F5 run saves the *fresh* invocation commands in the raw
per-component list form (``fresh/fresh/local_commands.json``): a JSON array of
session rows, one per component.  The offline replay tooling
(:func:`scripts.measure_local_coverage.select_recorded_session`) only accepts the
aggregated ``local_command_trace.v1`` document, so this script is the single,
explicit bridge between the two layouts.

What it does, and what it deliberately does not do:

* it validates every row it is given (component, completeness, identity digests,
  sequential records, command/reply nonce prefixes) and refuses the whole input
  on the first structural defect -- it never repairs, drops or truncates;
* it wraps the rows **verbatim** under ``sessions`` (sorted by component) and
  stamps ``schema_version = local_command_trace.v1``; no record, nonce, tick or
  payload is rewritten, reordered or synthesised;
* it writes a deterministic document (sorted keys, trailing newline) plus a
  provenance sidecar recording the input SHA256, the output SHA256, the
  converter's own SHA256 and the per-component record counts, so the converted
  artifact is auditable and reproducible;
* it refuses an input that is already a ``local_command_trace.v1`` document and
  an input whose component rows are not unique.

Exit codes: 0 converted, 2 refused (with ``{"status": "refused", "reason": ...}``).
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]

CONVERTER = 'scripts/normalize_fresh_local_commands.py'
CONVERTER_VERSION = 1
TRACE_SCHEMA = 'local_command_trace.v1'
PROVENANCE_SCHEMA = 'local_command_trace_normalization.v1'
# Candidate raw names, checked in this order in the given directory and then in
# its sorted immediate subdirectories.
RAW_NAMES = ('fresh_local_commands.json', 'local_commands.json',
             'local-commands.json', 'raw_local_commands.json')
MAX_RECORDS = 65536
_MAX_COMMAND_BYTES = 4096
_HEX32 = re.compile(r'[0-9a-f]{32}')
_HEX64 = re.compile(r'[0-9a-f]{64}')


class Refused(ValueError):
    """The input cannot be converted without inventing or dropping evidence."""


def _digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def _relative(path):
    path = Path(path)
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _is_digest(value, pattern):
    return type(value) is str and pattern.fullmatch(value) is not None


def find_raw_commands(path):
    """Resolve a raw per-component list from a file or a saved run-side root."""
    path = Path(path)
    if path.is_file():
        return path
    if not path.is_dir():
        raise Refused('input-missing')
    candidates = [path / name for name in RAW_NAMES]
    candidates.extend(sorted(child / name for child in path.iterdir()
                             if child.is_dir() for name in RAW_NAMES))
    found = [candidate for candidate in candidates if candidate.is_file()]
    if not found:
        raise Refused('raw-command-list-missing')
    for candidate in found:
        try:
            document = json.loads(candidate.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            continue
        if isinstance(document, list):
            return candidate
    raise Refused('raw-command-list-not-a-list')


def _check_record(record, index, nonce, component, *, where):
    if not isinstance(record, dict):
        raise Refused(f'{where}-record-not-an-object')
    tick = record.get('tick_after')
    command, reply = record.get('command'), record.get('reply')
    if (type(record.get('sequence')) is not int or record['sequence'] != index
            or type(record.get('reset_epoch')) is not int or record['reset_epoch'] != 0
            or type(tick) is not int
            or not isinstance(command, str) or not isinstance(reply, str)
            or not command.isascii() or len(command) > _MAX_COMMAND_BYTES
            or not command.startswith(f'CMD {nonce} {index:x} ')
            or not reply.startswith(f'RESULT {nonce} {index:x} ')):
        raise Refused(f'{where}-record-invalid:{component}:{index}')


def validate_raw_sessions(document):
    """Validate the raw per-component list and return ``{component: row}``."""
    if not isinstance(document, list) or not document:
        raise Refused('raw-command-list-empty')
    if len(document) > 1024:
        raise Refused('raw-command-list-too-many-sessions')
    sessions = {}
    for row in document:
        if not isinstance(row, dict):
            raise Refused('session-row-not-an-object')
        component = row.get('component')
        if not isinstance(component, str) or not component or component == '.' \
                or component == '..' or any(part in ('', '.', '..')
                                            for part in component.split('/')):
            raise Refused('session-component-invalid')
        if component in sessions:
            raise Refused('session-component-duplicate:' + component)
        if row.get('complete') is not True:
            raise Refused('session-incomplete:' + component)
        identity = row.get('identity')
        if not isinstance(identity, dict):
            raise Refused('session-identity-missing:' + component)
        if identity.get('component', component) != component:
            raise Refused('session-identity-component-mismatch:' + component)
        nonce = identity.get('execution_nonce')
        if not _is_digest(nonce, _HEX32):
            raise Refused('session-nonce-invalid:' + component)
        if not _is_digest(identity.get('binary_sha256'), _HEX64):
            raise Refused('session-binary-invalid:' + component)
        if not _is_digest(identity.get('build_digest'), _HEX64):
            raise Refused('session-build-digest-invalid:' + component)
        records = row.get('records')
        if not isinstance(records, list) or not records:
            raise Refused('session-records-empty:' + component)
        if len(records) > MAX_RECORDS:
            raise Refused('session-records-too-many:' + component)
        for index, record in enumerate(records, 1):
            _check_record(record, index, nonce, component, where='session')
        sessions[component] = row
    return sessions


def normalize(input_path, output_path, provenance_path):
    """Convert one raw list into ``local_command_trace.v1`` plus provenance."""
    input_path = Path(input_path)
    output_path = Path(output_path)
    provenance_path = Path(provenance_path)
    if output_path.resolve() == input_path.resolve():
        raise Refused('output-equals-input')
    if provenance_path.resolve() in (input_path.resolve(), output_path.resolve()):
        raise Refused('provenance-path-collision')
    try:
        document = json.loads(input_path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        raise Refused('raw-command-list-unreadable:' + type(error).__name__) from None
    if isinstance(document, dict):
        if document.get('schema_version') == TRACE_SCHEMA:
            raise Refused('already-normalized')
        raise Refused('raw-command-list-not-a-list')
    sessions = validate_raw_sessions(document)
    trace = {'schema_version': TRACE_SCHEMA,
             'sessions': {name: sessions[name] for name in sorted(sessions)}}
    text = json.dumps(trace, indent=2, sort_keys=True) + '\n'
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text, encoding='utf-8')
    converter_sha = _digest(ROOT / CONVERTER)
    output_sha = sha256(text.encode('utf-8')).hexdigest()
    provenance = {
        'schema_version': PROVENANCE_SCHEMA,
        'converter': CONVERTER,
        'converter_version': CONVERTER_VERSION,
        'converter_sha256': converter_sha,
        'input': {'path': _relative(input_path), 'sha256': _digest(input_path)},
        'output': {'path': _relative(output_path), 'sha256': output_sha},
        'trace_schema': TRACE_SCHEMA,
        'normalization': ('raw per-component session rows wrapped verbatim under '
                          'sessions, sorted by component; no record, nonce, tick or '
                          'reply payload is rewritten, reordered or synthesised'),
        'review': ('reviewed converter: validation is all-or-nothing and the output is '
                   'deterministic; the freshness of the input is not authenticated by '
                   'this script'),
        'components': {
            name: {
                'records': len(sessions[name]['records']),
                'execution_nonce': sessions[name]['identity']['execution_nonce'],
                'build_digest': sessions[name]['identity']['build_digest'],
                'binary_sha256': sessions[name]['identity']['binary_sha256'],
                'artifact_digest': sessions[name]['identity'].get('artifact_digest'),
                'local_ticks': sessions[name]['records'][-1]['tick_after'],
            } for name in sorted(sessions)},
    }
    provenance_path.parent.mkdir(parents=True, exist_ok=True)
    provenance_path.write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return provenance


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True,
                        help='raw per-component command list, or a saved run-side root')
    parser.add_argument('--output', type=Path, required=True,
                        help='local_command_trace.v1 document to write')
    parser.add_argument('--provenance', type=Path, default=None,
                        help='provenance sidecar (default: <output>.provenance.json)')
    args = parser.parse_args(argv)
    provenance_path = (args.provenance if args.provenance is not None
                       else args.output.with_name(args.output.name + '.provenance.json'))
    try:
        source = find_raw_commands(args.input)
        provenance = normalize(source, args.output, provenance_path)
    except (Refused, OSError, ValueError) as error:
        print(json.dumps({'status': 'refused', 'reason': str(error)}, sort_keys=True))
        return 2
    print(json.dumps({
        'status': 'converted',
        'input': provenance['input']['path'],
        'input_sha256': provenance['input']['sha256'],
        'output': provenance['output']['path'],
        'output_sha256': provenance['output']['sha256'],
        'components': sorted(provenance['components']),
        'records': {name: row['records']
                    for name, row in provenance['components'].items()},
        'provenance': _relative(provenance_path),
    }, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
