#!/usr/bin/env python3
"""Independently audit saved compiled-F6 output without launching native code."""
from copy import deepcopy
from dataclasses import asdict
from hashlib import sha256
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / 'src') not in sys.path:
    sys.path.insert(0, str(ROOT / 'src'))

DECLARATION_SCHEMA = 'compiled_F6_saved_declaration.v1'
GUARD_SCHEMA = 'compiled_F6_preconstruction_guard.v1'
F6_OUTPUT_DOCUMENTS = (
    'compiled_f6_prefix.json', 'compiled_f6_replay.json',
    'compiled_f6_fresh_prefix.json', 'compiled_f6_fresh_events.json',
    'compiled_f6_fresh_execution_audit.json',
    'compiled_f6_fresh_verification.json',
    'compiled_f6_build_join.v1.json', 'compiled_f6_receipt_join.v1.json',
    'compiled_assertion_results.v1.json',
    'compiled_assertion_evidence.v1.json',
)


def require(condition, code):
    if not condition:
        raise ValueError('compiled-F6-saved-audit-' + code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def digest(value):
    return sha256(canonical(value)).hexdigest()


def file_hash(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def equal(left, right, code):
    require(canonical(left) == canonical(right), code)


def safe_name(name):
    require(type(name) is str and bool(name) and '\\' not in name,
            'unsafe-relative-path')
    parsed = PurePosixPath(name)
    require(not parsed.is_absolute() and '..' not in parsed.parts
            and str(parsed) == name, 'unsafe-relative-path')
    return parsed


def _no_symlink_path(path):
    path = Path(path)
    current = Path(path.anchor) if path.is_absolute() else Path('.')
    for part in path.parts[1:] if path.is_absolute() else path.parts:
        current = current / part
        require(not current.is_symlink(), 'symlink:' + str(current))
    return path


def safe_file(base, name):
    parsed = safe_name(name)
    path = Path(base)
    for part in parsed.parts:
        path = path / part
        require(not path.is_symlink(), 'symlink:' + name)
    require(path.is_file() and path.resolve().is_relative_to(Path(base).resolve()),
            'missing-or-outside-file:' + name)
    return path


def _reject_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key: ' + str(key))
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError('non-finite JSON constant: ' + value)


def read_json(path, *, pretty=False):
    raw = Path(path).read_bytes()
    value = json.loads(raw, object_pairs_hook=_reject_duplicate_pairs,
                       parse_constant=_reject_constant)
    if pretty:
        expected = (json.dumps(value, sort_keys=True, indent=2,
                               ensure_ascii=False, allow_nan=False)
                    + '\n').encode('utf-8')
        require(raw == expected, 'json-format:' + str(path))
    return value


def read_properties(instance, names):
    """Read the actual named properties, without inspecting private storage."""
    if (type(names) not in (tuple, list) or any(type(name) is not str or not name
            for name in names) or len(set(names)) != len(names)):
        raise ValueError('property names must be unique nonempty strings')
    return {name: getattr(instance, name) for name in names}


def attempt_all(labelled_actions, *, primary=None):
    """Run every cleanup/export action while retaining the first exception."""
    if type(labelled_actions) not in (tuple, list):
        raise TypeError('labelled actions must be an ordered sequence')
    first = primary
    results = []
    for row in labelled_actions:
        if (type(row) not in (tuple, list) or len(row) != 2
                or type(row[0]) is not str or not row[0]
                or not callable(row[1])):
            raise TypeError('each action requires a label and callable')
        label, action = row
        try:
            results.append(action())
        except BaseException as error:
            if first is None:
                first = error
            elif error is not first:
                first.add_note(label + ': ' + repr(error))
                for note in getattr(error, '__notes__', ()):
                    first.add_note(label + ' note: ' + note)
    if first is not None:
        raise first
    return tuple(results)


def _closed(value, keys, code):
    require(type(value) is dict and set(value) == set(keys), code)
    return value


def _hex_sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _declaration(invocation):
    invocation = _no_symlink_path(Path(invocation))
    require(invocation.is_dir(), 'invocation-directory')
    path = safe_file(invocation, 'declaration.json')
    document = read_json(path, pretty=True)
    common = {'schema_version', 'outcome', 'output_path', 'invocation_path',
              'expected_exit_code', 'command_sha256'}
    outcome = document.get('outcome') if type(document) is dict else None
    keys = set(common)
    if outcome == 'expected_error':
        keys.add('fault_selector')
    elif outcome == 'refusal':
        keys.add('refusal')
    elif outcome != 'completed':
        raise ValueError('compiled-F6-saved-audit-declaration-outcome')
    _closed(document, keys, 'declaration-fields')
    require(document['schema_version'] == DECLARATION_SCHEMA,
            'declaration-schema')
    require(document['output_path'] == 'run'
            and document['invocation_path'] == 'invocation',
            'declaration-paths')
    safe_name(document['output_path'])
    safe_name(document['invocation_path'])
    expected_exit = 1 if outcome == 'refusal' else 0
    require(type(document['expected_exit_code']) is int
            and document['expected_exit_code'] == expected_exit,
            'declaration-expected-exit')
    require(_hex_sha(document['command_sha256']), 'declaration-command-sha256')
    if outcome == 'expected_error':
        selector = _closed(document['fault_selector'],
            {'case_index', 'operation', 'word_index'},
            'fault-selector-fields')
        require(type(selector['case_index']) is int
                and 0 <= selector['case_index'] < 16
                and selector['operation'] in ('read', 'write')
                and type(selector['word_index']) is int
                and selector['word_index'] in (1, 2),
                'fault-selector-values')
    if outcome == 'refusal':
        refusal = _closed(document['refusal'],
            {'stage', 'code', 'pointer', 'proof_path', 'proof_sha256'},
            'refusal-fields')
        require(type(refusal['stage']) is str and bool(refusal['stage'])
                and type(refusal['code']) is str and bool(refusal['code'])
                and type(refusal['pointer']) is str
                and (not refusal['pointer'] or refusal['pointer'].startswith('/'))
                and _hex_sha(refusal['proof_sha256']), 'refusal-values')
        safe_name(refusal['proof_path'])
    return document


def _map(value, label):
    require(type(value) is dict and bool(value), label + '-empty')
    for name, checksum in value.items():
        safe_name(name)
        require(_hex_sha(checksum), label + '-digest')
    return value


def _verify_origins(invocation, sources, terminal):
    before = read_json(safe_file(invocation, 'source-origins-before.json'), pretty=True)
    after = read_json(safe_file(invocation, 'source-origins-after.json'), pretty=True)
    equal(before, after, 'source-origin-drift')
    require(type(before) is dict and set(before) == set(sources),
            'source-origin-bijection')
    require(terminal.get('source_origins_unchanged') is True,
            'source-origin-supervisor-state')
    for name, row in before.items():
        require(type(row) is dict and type(row.get('is_symlink')) is bool
                and type(row.get('resolved_path')) is str
                and Path(row['resolved_path']).is_absolute()
                and row.get('content_sha256') == sources[name],
                'source-origin-record')
        require(type(row.get('link_target')) is str and bool(row['link_target'])
                if row['is_symlink'] else row.get('link_target') is None,
                'source-origin-link')
        current = ROOT.joinpath(*safe_name(name).parts)
        parts = safe_name(name).parts
        parent = ROOT
        for part in parts[:-1]:
            parent = parent / part
            require(not parent.is_symlink(), 'current-source-parent-symlink:' + name)
        require(current.is_symlink() is row['is_symlink']
                and current.is_file()
                and current.resolve(strict=True).as_posix() == row['resolved_path']
                and (os.readlink(current) if current.is_symlink() else None)
                    == row['link_target']
                and file_hash(current) == sources[name],
                'current-source-origin-or-bytes:' + name)
    unavailable_before = read_json(
        safe_file(invocation, 'unavailable-symlinks-before.json'), pretty=True)
    unavailable_after = read_json(
        safe_file(invocation, 'unavailable-symlinks-after.json'), pretty=True)
    equal(unavailable_before, unavailable_after, 'unavailable-link-drift')
    require(type(unavailable_before) is dict
            and not set(unavailable_before) & set(sources)
            and terminal.get('unavailable_symlinks_unchanged') is True,
            'unavailable-link-map')
    for name, row in unavailable_before.items():
        safe_name(name)
        require(type(row) is dict and row.get('is_symlink') is True
                and type(row.get('link_target')) is str and bool(row['link_target'])
                and type(row.get('resolved_path')) is str
                and Path(row['resolved_path']).is_absolute()
                and row.get('content_sha256') is None
                and row.get('unavailable_reason') == 'target_missing'
                and row.get('declared_source_file') is False,
                'unavailable-link-record')
        current = ROOT.joinpath(*safe_name(name).parts)
        parent = ROOT
        for part in safe_name(name).parts[:-1]:
            parent = parent / part
            require(not parent.is_symlink(),
                    'current-unavailable-link-parent-symlink:' + name)
        require(current.is_symlink() and not current.exists()
                and os.readlink(current) == row['link_target']
                and current.resolve(strict=False).as_posix() == row['resolved_path'],
                'current-unavailable-link-drift:' + name)


def _verify_external(output, invocation, declaration):
    output = _no_symlink_path(output)
    invocation = _no_symlink_path(invocation)
    require(output.is_dir() and invocation.is_dir(), 'attempt-roots')
    output = output.resolve(strict=True)
    invocation = invocation.resolve(strict=True)
    attempt_root = invocation.parent.resolve()
    require(invocation.resolve() == (attempt_root / declaration['invocation_path']).resolve()
            and output.resolve() == (attempt_root / declaration['output_path']).resolve(),
            'invocation-output-path-binding')
    incomplete = output / '.incomplete'
    if declaration['outcome'] in ('refusal', 'expected_error'):
        require(not incomplete.is_symlink() and incomplete.is_file(),
                'incomplete-marker-required')
        marker = read_json(incomplete, pretty=True)
        require(marker.get('status') == 'started'
                and marker.get('output') == str(output),
                'incomplete-marker-content')
    else:
        require(not incomplete.exists() and not incomplete.is_symlink(),
                'stale-incomplete-marker')

    terminal = read_json(safe_file(invocation, 'terminal.json'), pretty=True)
    process = read_json(safe_file(invocation, 'process.json'), pretty=True)
    _closed(process, {'pid', 'pgid', 'start_new_session', 'command_sha256'},
            'process-fields')
    expected_exit = declaration['expected_exit_code']
    require(type(terminal.get('returncode')) is int
            and terminal['returncode'] == expected_exit
            and type(terminal.get('expected_exit_code')) is int
            and terminal['expected_exit_code'] == expected_exit
            and terminal.get('exit_matches_expectation') is True
            and terminal.get('reaped') is True
            and terminal.get('timed_out') is False
            and terminal.get('inputs_unchanged') is True
            and terminal.get('output_map_unchanged') is True
            and terminal.get('supervisor_error') is None,
            'supervisor-terminal')
    require(type(terminal.get('pid')) is int and terminal['pid'] > 0
            and terminal.get('pgid') == terminal['pid']
            and process.get('pid') == terminal['pid']
            and process.get('pgid') == terminal['pid']
            and process.get('start_new_session') is True
            and process.get('command_sha256') == declaration['command_sha256'],
            'supervisor-process')
    samples_available = terminal.get('rss_samples_available')
    peak_rss = terminal.get('peak_process_group_rss_bytes')
    require(type(samples_available) is bool
            and ((samples_available and type(peak_rss) is int and peak_rss >= 0)
                 or (not samples_available and peak_rss is None)),
            'process-accounting')
    terminal_output = terminal.get('output_path')
    terminal_invocation = terminal.get('invocation_path')
    require(terminal_output == declaration['output_path']
            and terminal_invocation == declaration['invocation_path'],
            'terminal-path-binding')

    sources = _map(read_json(safe_file(invocation, 'source-before.json'), pretty=True),
                   'source-map')
    equal(sources, read_json(safe_file(invocation, 'source-after.json'), pretty=True),
          'source-drift')
    require(terminal.get('source_map_unchanged') is True
            and terminal.get('inputs_unchanged') is True,
            'source-map-supervisor-state')
    _verify_origins(invocation, sources, terminal)
    archive = safe_file(invocation, 'executed-inputs.tar.gz')
    require(file_hash(archive) == terminal.get('archive_sha256'), 'archive-hash')
    archived = {}
    try:
        with tarfile.open(archive, 'r:gz') as stream:
            for member in stream:
                safe_name(member.name)
                require(member.isfile() and member.name not in archived,
                        'archive-member')
                material = stream.extractfile(member)
                require(material is not None, 'archive-member')
                archived[member.name] = sha256(material.read()).hexdigest()
    except (tarfile.TarError, EOFError, OSError) as error:
        raise ValueError('compiled-F6-saved-audit-archive-invalid') from error
    equal(archived, sources, 'archive-source-map')

    output_initial = _map(read_json(safe_file(invocation, 'output-initial.json'), pretty=True),
                          'output-map')
    output_final = _map(read_json(safe_file(invocation, 'output-final.json'), pretty=True),
                        'output-map')
    equal(output_initial, output_final, 'output-drift')
    actual = {}
    for path in attempt_root.rglob('*'):
        require(not path.is_symlink(), 'attempt-output-symlink')
        if path.is_file() and not path.is_relative_to(invocation):
            actual[path.relative_to(attempt_root).as_posix()] = file_hash(path)
    equal(actual, output_initial, 'external-output-bytes')

    command_path = safe_file(invocation, 'command.json')
    command_bytes = command_path.read_bytes()
    require(sha256(command_bytes).hexdigest() == declaration['command_sha256'],
            'command-declaration-hash')
    command = read_json(command_path, pretty=True)
    command_keys = {'argv', 'cwd', 'environment_overrides',
        'expected_exit_code', 'timeout_seconds', 'executable_pins',
        'child_kind', 'command_kind', 'selected_nodes', 'selected_modules',
        'gate_mode', 'lock_owner', 'shared_lock', 'output_path',
        'invocation_path', 'freeze_manifest_sha256', 'started_at'}
    _closed(command, command_keys, 'command-fields')
    argv = command.get('argv')
    require(type(argv) is list and all(type(part) is str for part in argv)
            and type(command.get('expected_exit_code')) is int
            and command['expected_exit_code'] == expected_exit,
            'command-record')
    require(terminal.get('command_sha256') == declaration['command_sha256'],
            'terminal-command-hash')
    require(terminal.get('executable_pins') == command.get('executable_pins'),
            'terminal-executable-pins')
    pins = command.get('executable_pins')
    require(type(pins) is dict and 'python' in pins
            and 'rfuzz_client' in pins
            and type(pins.get('python')) is dict
            and set(pins['python']) == {'path', 'sha256', 'size_bytes'},
            'executable-pin-map')
    for label, pin in pins.items():
        require(type(label) is str and bool(label) and type(pin) is dict,
                'executable-pin-row')
        if set(pin) == {'path', 'sha256', 'size_bytes'}:
            require(type(pin['path']) is str and Path(pin['path']).is_absolute()
                    and _hex_sha(pin['sha256'])
                    and type(pin['size_bytes']) is int and pin['size_bytes'] >= 0,
                    'executable-pin-values')
            executable_path = _no_symlink_path(Path(pin['path']))
            require(executable_path.is_file()
                    and file_hash(executable_path) == pin['sha256']
                    and executable_path.stat().st_size == pin['size_bytes'],
                    'executable-pin-current-bytes:' + label)
        else:
            _closed(pin, {'path', 'sha256', 'size_bytes', 'unavailable'},
                    'unavailable-executable-pin-fields')
            require(type(pin['path']) is str and Path(pin['path']).is_absolute()
                    and pin['sha256'] is None and pin['size_bytes'] is None
                    and pin['unavailable'] == 'not_found'
                    and not Path(pin['path']).exists()
                    and not Path(pin['path']).is_symlink(),
                    'unavailable-executable-pin')
    require(command.get('output_path') == declaration['output_path']
            and command.get('invocation_path') == declaration['invocation_path'],
            'command-path-binding')
    command_kind = command.get('command_kind')
    require(command.get('child_kind') == command_kind
            and command_kind in ('auto_harness_cli', 'pytest_native_case'),
            'command-kind-tag')
    cwd = Path(command.get('cwd'))
    require(cwd.is_absolute() and cwd.resolve() == ROOT.resolve(),
            'command-cwd')
    nodes = command.get('selected_nodes')
    modules = command.get('selected_modules')
    require(type(nodes) is list and all(type(node) is str for node in nodes)
            and type(modules) is list
            and all(type(module) is str for module in modules),
            'command-selection-shape')
    overrides = command.get('environment_overrides')
    require(type(overrides) is dict
            and all(type(key) is str and type(value) is str
                    for key, value in overrides.items()),
            'command-environment-shape')
    require(type(command.get('gate_mode')) is str
            and type(command.get('lock_owner')) is str
            and type(command.get('shared_lock')) is str
            and Path(command['shared_lock']).is_absolute()
            and type(command.get('freeze_manifest_sha256')) is str
            and _hex_sha(command.get('freeze_manifest_sha256'))
            and type(command.get('started_at')) is str
            and bool(command['started_at']), 'command-provenance-fields')
    if command_kind == 'auto_harness_cli':
        require(declaration['outcome'] in ('completed', 'refusal')
                and nodes == [] and modules == [], 'cli-command-outcome-selection')
        expected_mode = ('f6-positive' if declaration['outcome'] == 'completed'
            and command['gate_mode'] == 'f6-positive' else
            'f6-renamed' if declaration['outcome'] == 'completed'
            and command['gate_mode'] == 'f6-renamed' else
            'f6-unsupported-irq' if declaration['outcome'] == 'refusal'
            and command['gate_mode'] == 'f6-unsupported-irq' else
            'f6-wrong-route' if declaration['outcome'] == 'refusal'
            and command['gate_mode'] == 'f6-wrong-route' else None)
        require(expected_mode is not None, 'cli-command-gate-mode')
        require(argv.count('--output') == 1, 'command-output-argument')
        out_arg = Path(argv[argv.index('--output') + 1])
        if not out_arg.is_absolute():
            out_arg = cwd / out_arg
        require(out_arg.resolve() == output, 'command-output-path')
        require(len(argv) >= 3 and argv[1] == 'scripts/auto_harness_test.py'
                and argv[2:4] == ['--executor', 'compiled-f6-rfuzz'],
                'cli-command-executable')
        require(argv.count('--executor') == 1
                and overrides == _expected_cli_environment(
                    declaration['outcome']),
                'cli-command-environment')
    elif command_kind == 'pytest_native_case':
        require(type(nodes) is list and len(nodes) == 1
                and type(nodes[0]) is str and '::' in nodes[0]
                and modules == [] and declaration['outcome'] == 'expected_error'
                and nodes[0] in argv and argv[-1] == nodes[0],
                'native-case-node-binding')
        require(command['gate_mode'] in ('f6-controlled-err-read',
                    'f6-controlled-err-write'), 'native-case-gate-mode')
        expected_op = 'read' if command['gate_mode'].endswith('read') else 'write'
        require(declaration['fault_selector']['operation'] == expected_op,
                'native-case-selector-mode')
        require(argv[:4] == [argv[0], '-m', 'pytest', '-q']
                and argv[4] == '-ra' and len(argv) == 7
                and argv[5] == '--junitxml=' + (attempt_root / 'pytest-results.xml').relative_to(ROOT).as_posix(),
                'native-case-pytest-argv')
        require(type(argv[0]) is str and Path(argv[0]).is_absolute(),
                'native-case-python')
        expected_env = {
            'PYTHONPATH': 'src:.',
            'MYFUZZ_RUN_NATIVE_F6': '1',
            'MYFUZZ_COMPILED_F6_NATIVE_EVIDENCE':
                (attempt_root / 'native-controls').relative_to(ROOT).as_posix(),
            'MYFUZZ_COMPILED_F6_NATIVE_CACHE':
                '.superpowers/cache/compiled-f6-20261024',
            'MYFUZZ_COMPILED_F6_NATIVE_OUTPUT':
                (attempt_root / 'run').relative_to(ROOT).as_posix(),
        }
        require(overrides == expected_env, 'native-case-environment')
    else:
        raise ValueError('compiled-F6-saved-audit-command-kind')
    require(Path(argv[0]).is_absolute()
            and Path(argv[0]).resolve() == Path(pins['python']['path']).resolve(),
            'command-python-pin')
    return sources, output_initial, command, terminal, process


def _verify_auditor_sources(sources, binding):
    """Pin the full Python package used by the auditor and F6 re-projection."""
    require(ROOT.resolve() == Path(__file__).resolve().parents[1],
            'auditor-root')
    closure = {path.relative_to(ROOT).as_posix(): file_hash(path)
               for path in sorted((ROOT / 'src/myfuzz').rglob('*.py'))}
    require('scripts/verify_compiled_f6.py' in sources
            and sources['scripts/verify_compiled_f6.py'] == file_hash(__file__),
            'auditor-source-attribution')
    require(all(sources.get(name) == checksum
                for name, checksum in closure.items()), 'f6-source-drift')
    require(binding.get('executor_source_closure_sha256') == digest(closure),
            'binding-source-closure')


def _audit_refusal(output, invocation, declaration, sources):
    refusal = declaration['refusal']
    command = _command_for_invocation(invocation)
    expected_control = {'f6-unsupported-irq': 'f6-unsupported-irq-form',
                        'f6-wrong-route': 'f6-wrong-route'}.get(
                            command.get('gate_mode'))
    require(command.get('command_kind') == 'auto_harness_cli'
            and expected_control is not None,
            'refusal-command-selection')
    proof_path = safe_file(ROOT, refusal['proof_path'])
    proof_raw = proof_path.read_bytes()
    require(sha256(proof_raw).hexdigest() == refusal['proof_sha256'],
            'refusal-proof-bytes')
    require(sources.get(refusal['proof_path']) == refusal['proof_sha256'],
            'refusal-proof-frozen-input')
    proof = read_json(proof_path, pretty=True)
    keys = {'schema_version', 'control_id', 'fixture_path', 'fixture_sha256',
            'guard_sources', 'guard_sources_sha256', 'guard_mode',
            'constructor_called', 'native_process_count', 'status',
            'stage', 'code', 'pointer'}
    _closed(proof, keys, 'refusal-proof-fields')
    require(proof['control_id'] == expected_control
            and proof['schema_version'] == GUARD_SCHEMA
            and proof['guard_mode'] == 'runtime_constructor_sentinel'
            and proof['constructor_called'] is False
            and proof['native_process_count'] == 0
            and type(proof['native_process_count']) is int
            and proof['status'] == 'refused', 'refusal-proof-status')
    guard_sources = _map(proof['guard_sources'], 'guard-source-map')
    require(proof['guard_sources_sha256'] == digest(guard_sources),
            'guard-source-map-digest')
    require(all(sources.get(name) == checksum
                for name, checksum in guard_sources.items()),
            'guard-source-map-join')
    safe_name(proof['fixture_path'])
    require(_hex_sha(proof['fixture_sha256'])
            and sources.get(proof['fixture_path']) == proof['fixture_sha256'],
            'refusal-fixture-pin')
    require((proof['stage'], proof['code'], proof['pointer']) ==
            (refusal['stage'], refusal['code'], refusal['pointer']),
            'refusal-proof-declaration-join')

    marker = read_json(output / '.incomplete', pretty=True)
    require(marker.get('status') == 'started'
            and marker.get('output') == str(output.resolve()),
            'refusal-marker-content')
    summary_path = safe_file(output, 'run-summary.json')
    summary = read_json(summary_path, pretty=True)
    require(summary.get('status') == 'refused'
            and summary.get('exit_code') == 1
            and summary.get('output') == str(output.resolve()),
            'refusal-run-summary')
    refusals = summary.get('refusals')
    matching = [row for row in refusals if type(row) is dict and
                (row.get('stage'), row.get('code'), row.get('pointer')) ==
                (refusal['stage'], refusal['code'], refusal['pointer'])]
    require(type(refusals) is list and len(refusals) == 1
            and len(matching) == 1, 'refusal-run-summary-join')
    require(not (output / 'session').exists()
            and not (output / 'bundle').exists(), 'refusal-session-created')
    stages = summary.get('stages')
    require(type(stages) is dict
            and stages.get(refusal['stage'], {}).get('status') == 'refused'
            and stages.get('session', {}).get('status') == 'absent'
            and stages.get('fresh_verification', {}).get('status') == 'absent',
            'refusal-stage-scope')
    execution_names = {name for name in F6_OUTPUT_DOCUMENTS}
    require(not any((output / name).exists() for name in execution_names),
            'refusal-fabricated-execution-output')
    for path in output.rglob('*'):
        if path.is_file():
            require(path.name not in {'receipts.jsonl', 'online_plan.json',
                'online_final_trace.json', 'compiled_f6_prefix.json',
                'compiled_f6_replay.json', 'fresh-verification.json',
                'compiled_f6_partial_events.json',
                'compiled_f6_partial_prefix.json'},
                'refusal-fabricated-session-material')
    return dict(status='ok', outcome='refusal', scope='preconstruction_only',
                refusal=dict(stage=refusal['stage'], code=refusal['code'],
                             pointer=refusal['pointer']),
                native_authority_issued=False)


def _verify_prefix_trace(prefix):
    """Recompute saved F6 trace identity from its selected event field."""
    require(type(prefix) is dict, 'prefix-trace-shape')
    require(prefix.get('trace_status') == 'complete', 'prefix-trace-status')
    require(prefix.get('trace_events_source') == 'actual_events'
            and prefix.get('trace_events') is None,
            'prefix-trace-event-source')
    events = prefix.get('actual_events')
    ticks = prefix.get('trace_local_ticks')
    require(type(events) is list and bool(events)
            and all(type(row) is dict for row in events)
            and all(type(row.get('event_id')) is int
                and row['event_id'] == index
                for index, row in enumerate(events, start=1)),
            'prefix-trace-events')
    execution_audit = prefix.get('original_execution_audit')
    identities = (execution_audit.get('identities')
        if type(execution_audit) is dict else None)
    require(type(identities) is dict and bool(identities)
            and all(type(component) is str and component
                for component in identities), 'prefix-trace-components')
    require(type(ticks) is dict and set(ticks) == set(identities)
            and all(type(value) is int and value >= 0
                for value in ticks.values()),
            'prefix-trace-ticks')
    semantic_sha256 = prefix.get('semantic_hash')
    require(type(semantic_sha256) is str and len(semantic_sha256) == 64
            and all(ch in '0123456789abcdef' for ch in semantic_sha256),
            'prefix-trace-semantic-shape')
    from myfuzz.scenario.session_runtime import _trace_semantic_sha256
    require(semantic_sha256 == _trace_semantic_sha256(
        prefix['trace_status'], events, ticks), 'prefix-trace-semantic-hash')
    online_plan = prefix.get('online_plan')
    genome_sha256 = prefix.get('trace_genome_sha256')
    require(type(online_plan) is dict and type(genome_sha256) is str
            and len(genome_sha256) == 64
            and all(ch in '0123456789abcdef' for ch in genome_sha256)
            and genome_sha256 == sha256(canonical(online_plan)).hexdigest(),
            'prefix-trace-genome-hash')
    manifest_sha256 = prefix.get('trace_manifest_sha256')
    require(type(manifest_sha256) is str and len(manifest_sha256) == 64
            and all(ch in '0123456789abcdef' for ch in manifest_sha256),
            'prefix-trace-manifest-shape')


def _verify_prefix_online_trace(prefix, trace):
    """Join the independently parsed session trace to the saved prefix."""
    from myfuzz.scenario.replay import ScenarioTrace
    require(isinstance(trace, ScenarioTrace), 'online-trace-type')
    for prefix_field, trace_field in (
            ('actual_events', 'events'), ('trace_status', 'status'),
            ('trace_local_ticks', 'local_ticks'),
            ('semantic_hash', 'semantic_sha256'),
            ('trace_genome_sha256', 'genome_sha256'),
            ('trace_manifest_sha256', 'manifest_sha256')):
        equal(prefix.get(prefix_field), getattr(trace, trace_field),
              'prefix-online-trace-' + prefix_field)


def _verify_f6_case_joins(prefix, contract, local_by_id, owners, events):
    """Bind each case's Observer references to its one IRQ and fetch edge."""
    cpu_id = contract['cpu']['instance_id']
    dma_id = contract['dma']['instance_id']
    program = contract['program_contract']
    attempts = prefix['attempts']
    if owners is None:
        owners = {}
        for attempt in attempts:
            case = attempt.get('case_material')
            inventory = case.get('evidence_inventory') if type(case) is dict else None
            require(type(inventory) is dict, 'raw-case-inventory')
            for item in inventory.values():
                details = item.get('details') if type(item) is dict else None
                rows = details.get('raw_evidence') if type(details) is dict else None
                require(type(rows) is list, 'raw-case-evidence-list')
                for row in rows:
                    if row.get('kind') == 'local_tick_sample':
                        continue  # Direct Runner IDs are a separate namespace.
                    owners.setdefault((row.get('component'), row.get('event_id')),
                                      set()).add(attempt.get('case_id'))
    claimed = {kind: set() for kind in (
        'source_start', 'binding_delivery', 'native_f6_isr_return.v1',
        'native_fetch_boundary')}
    for attempt in attempts:
        case_id, case_index = attempt.get('case_id'), attempt.get('case_index')
        require(type(case_id) is str and bool(case_id)
                and type(case_index) is int and case_index >= 0,
                'raw-case-identity')

        def referenced(field, component, kind):
            event_id = attempt.get(field)
            key = (component, event_id)
            require(type(event_id) is int and event_id > 0
                    and owners.get(key) == {case_id}
                    and key in local_by_id,
                    'raw-case-reference:' + field)
            row = local_by_id[key]
            require(row.get('kind', row.get('schema_version')) == kind,
                    'raw-case-kind:' + field)
            return row

        source = referenced('irq_output', dma_id, 'source_start')
        delivery = referenced('irq_delivery', cpu_id, 'binding_delivery')
        take = referenced('irq', cpu_id, 'cpu_external_irq_taken')
        returned = referenced('return', cpu_id, 'native_f6_isr_return.v1')
        for kind, row in (('source_start', source),
                          ('binding_delivery', delivery),
                          ('native_f6_isr_return.v1', returned)):
            key = (row['component'], row['event_id'])
            require(key not in claimed[kind], 'raw-case-derived-owner:' + kind)
            claimed[kind].add(key)
        boundary_claim = attempt.get('next_fetch')
        boundary_event_id = (boundary_claim.get('event_id')
            if type(boundary_claim) is dict else boundary_claim)
        require(type(boundary_event_id) is int and boundary_event_id > 0,
                'raw-case-boundary-claim')
        boundary_key = (cpu_id, boundary_event_id)
        require(owners.get(boundary_key) == {case_id}
                and boundary_key in local_by_id
                and boundary_key not in claimed['native_fetch_boundary'],
                'raw-case-boundary-owner')
        claimed['native_fetch_boundary'].add(boundary_key)
        boundary = local_by_id[boundary_key]
        if type(boundary_claim) is dict:
            equal(boundary_claim, boundary, 'raw-case-boundary-copy')
        else:
            require(boundary_claim == boundary.get('event_id'),
                    'raw-case-boundary-id-join')
        require(boundary.get('kind') == 'native_fetch_boundary',
                'raw-case-boundary-kind')

        source_key = source.get('source_output_key')
        start, end = delivery.get('start_local_tick'), delivery.get('end_local_tick')
        require(delivery.get('source_event_id') == source['event_id']
                and delivery.get('source_output_key') == source_key
                and type(source_key) is list and len(source_key) == 4
                and source_key[0] == dma_id
                and type(source_key[1]) is int
                and type(delivery.get('target_epoch')) is int
                and type(take.get('reset_epoch')) is int
                and delivery['target_epoch'] == take['reset_epoch']
                and type(start) is int and type(end) is int
                and start <= take.get('local_tick', -1) < end
                and take.get('binding_delivery_event_id') == delivery['event_id']
                and take.get('source_output_key') == source_key,
                'raw-case-irq-delivery-take')
        pulse = [row for row in events
            if type(row) is dict and row.get('component') == cpu_id
            and row.get('kind') == 'cpu_external_irq_sample'
            and row.get('binding_delivery_event_id') == delivery['event_id']
            and row.get('source_output_key') == source_key
            and row.get('reset_epoch') == delivery['target_epoch']
            and type(row.get('local_tick')) is int
            and start <= row['local_tick'] < end]
        require(end == start + 16 and len(pulse) == 16
                and {row['local_tick'] for row in pulse} == set(range(start, end))
                and take.get('sample_event_id') in
                    {row.get('event_id') for row in pulse}
                and any(row.get('event_id') == take['sample_event_id']
                    and row.get('local_tick') == take['local_tick']
                    for row in pulse),
                'raw-case-take-pulse-sample')
        require(returned.get('case_id') == case_id
                and returned.get('case_index') == case_index
                and returned.get('irq_take_key') == take.get('take_key')
                and returned.get('reset_epoch') == delivery['target_epoch']
                and returned.get('take_receipt_id', {}).get('sequence') ==
                    take.get('receipt_id', {}).get('sequence'),
                'raw-case-return-take')

        error = attempt.get('status_kind') == 'expected_error'
        slot = program['slot_base'] + 256 * case_index
        expected_address = (slot + 128 if error else
            program['slot_base'] + 256 * (case_index + 1)
            if case_index + 1 < program['slot_count'] else
            program['park_address'])
        transaction = boundary.get('transaction')
        require(boundary.get('address') == expected_address
                and boundary.get('boundary') ==
                    ('error_current_island' if error else 'next_prefix_or_park')
                and boundary.get('execution') == returned.get('execution')
                and boundary.get('reset_epoch') == returned.get('reset_epoch')
                and boundary.get('native_testcase_id') ==
                    returned.get('native_testcase_id')
                and type(transaction) is dict
                and transaction.get('testcase_id') ==
                    returned.get('native_testcase_id')
                and transaction.get('source_component') == cpu_id
                and transaction.get('source_epoch') == returned.get('reset_epoch')
                and type(boundary.get('local_tick')) is int
                and type(returned.get('successor_local_tick')) is int
                and boundary['local_tick'] > returned['successor_local_tick'],
                'raw-case-fetch-boundary')
    for kind, keys in claimed.items():
        actual = {key for key, row in local_by_id.items()
            if row.get('kind', row.get('schema_version')) == kind}
        require(actual == keys, 'raw-case-derived-bijection:' + kind)


def _verify_f6_expectation_attempt_refs(attempts, cpu_id, dma_id):
    """Require each passed expectation to cite its own attempt references."""
    configuration = (
        ('operands', cpu_id, 'instr_response'),
        ('configuration', cpu_id, 'data_accept'),
        ('deliveries', cpu_id, 'mmio_delivery'))
    words = (
        ('sources', cpu_id, 'memory_write'),
        ('source_commits', cpu_id, 'memory_write_commit'),
        ('reads', dma_id, 'dma_edge'),
        ('read_snapshots', dma_id, 'memory_read'),
        ('read_responses', dma_id, 'dma_edge'),
        ('writes', dma_id, 'dma_edge'),
        ('word_commits', dma_id, 'memory_write_commit'),
        ('write_responses', dma_id, 'dma_edge'))
    irq = (
        ('irq_output', dma_id, 'source_start'),
        ('irq_delivery', cpu_id, 'binding_delivery'),
        ('irq', cpu_id, 'cpu_external_irq_taken'),
        ('return', cpu_id, 'native_f6_isr_return.v1'),
        ('status', cpu_id, 'data_response'),
        ('status_store', cpu_id, 'memory_write'),
        ('terminal', cpu_id, 'memory_write'),
        ('next_fetch', cpu_id, 'native_fetch_boundary'),
        ('readbacks', cpu_id, 'data_response'),
        ('results', cpu_id, 'memory_write'),
        ('word_commits', dma_id, 'memory_write_commit'))
    groups = {
        'dma.cpu_configuration': configuration,
        'dma.word_transfer_join': words,
        'dma.irq_isr_completion': irq,
    }
    scalar = {'irq_output', 'irq_delivery', 'irq', 'return', 'status',
              'status_store', 'terminal', 'next_fetch'}
    for attempt in attempts:
        case = attempt.get('case_material')
        inventory = case.get('evidence_inventory') if type(case) is dict else None
        require(type(inventory) is dict, 'typed-attempt-ref-inventory')
        for item in inventory.values():
            if item.get('outcome') != 'passed':
                continue
            expected = groups.get(item.get('kind'))
            if expected is None:
                continue
            details = item.get('details')
            refs = details.get('raw_references') if type(details) is dict else None
            require(type(refs) is list, 'typed-attempt-raw-references')
            present = {(row.get('component'), row.get('event_id'), row.get('kind'))
                for row in refs if type(row) is dict}
            for field, component, kind in expected:
                value = attempt.get(field)
                if field == 'next_fetch' and type(value) is dict:
                    value = value.get('event_id')
                values = [value] if field in scalar else value
                require(type(values) is list and len(values) ==
                    (1 if field in scalar else 4)
                    and all(type(event_id) is int and event_id > 0
                        and (component, event_id, kind) in present
                        for event_id in values),
                    'typed-attempt-own-ref:' + item['kind'] + ':' + field)


def _verify_f6_raw_evidence_trace(prefix, contract, binding, artifacts=None,
                                 firmware_document=None):
    """Join every saved F6 raw observation to the authoritative Runner trace.

    Observer event IDs are a local projection namespace. Projected rows carry
    their Runner ID explicitly; direct local tick rows retain the Runner ID.
    The small set of F6-created rows is accepted only after its source fields
    are rederived from those Runner events.
    """
    attempts = prefix.get('attempts')
    events = prefix.get('actual_events')
    require(type(attempts) is list and bool(attempts)
            and type(events) is list and bool(events),
            'raw-trace-inventory-shape')
    runner_by_id = {}
    for expected_id, row in enumerate(events, start=1):
        require(type(row) is dict and type(row.get('event_id')) is int
                and row['event_id'] == expected_id,
                'raw-trace-runner-event-identity')
        runner_by_id[expected_id] = row

    cpu_id = contract['cpu']['instance_id']
    dma_id = contract['dma']['instance_id']
    irq_contract = contract['irq']
    local_by_id = {}
    runner_link_by_local_id = {}
    local_id_by_runner_link = {}
    observer_component_by_id = {}
    for attempt in attempts:
        case_material = attempt.get('case_material')
        inventory = (case_material.get('evidence_inventory')
                    if type(case_material) is dict else None)
        require(type(inventory) is dict and bool(inventory),
                'raw-trace-case-inventory')
        for item in inventory.values():
            details = item.get('details') if type(item) is dict else None
            raw_rows = (details.get('raw_evidence')
                        if type(details) is dict else None)
            require(type(raw_rows) is list, 'raw-trace-evidence-list')
            for row in raw_rows:
                require(type(row) is dict
                        and type(row.get('event_id')) is int
                        and row['event_id'] > 0
                        and type(row.get('component')) is str
                        and bool(row['component']),
                        'raw-trace-local-event-identity')
                if row.get('kind') == 'local_tick_sample':
                    require('runner_event_id' not in row,
                            'raw-trace-direct-tick-link')
                    runner_row = runner_by_id.get(row['event_id'])
                    require(type(runner_row) is dict,
                            'raw-trace-direct-tick-missing')
                    equal(row, runner_row, 'raw-trace-direct-tick-mismatch')
                    continue
                key = (row['component'], row['event_id'])
                previous_component = observer_component_by_id.setdefault(
                    row['event_id'], row['component'])
                require(previous_component == row['component'],
                        'raw-trace-observer-id-unique')
                if key in local_by_id:
                    equal(local_by_id[key], row,
                          'raw-trace-duplicate-local-event')
                    continue
                local_by_id[key] = row
                runner_id = row.get('runner_event_id')
                if runner_id is not None:
                    require(row.get('kind') != 'local_tick_sample'
                            and type(runner_id) is int and runner_id > 0,
                            'raw-trace-runner-link-shape')
                    runner_row = runner_by_id.get(runner_id)
                    require(type(runner_row) is dict,
                            'raw-trace-runner-link-missing')
                    projected = deepcopy(row)
                    projected.pop('runner_event_id')
                    projected['event_id'] = runner_id
                    equal(projected, runner_row,
                          'raw-trace-runner-projection-mismatch')
                    previous_local_id = local_id_by_runner_link.setdefault(
                        runner_id, key)
                    require(previous_local_id == key,
                            'raw-trace-runner-link-not-bijective')
                    runner_link_by_local_id[key] = runner_id
                else:
                    require(row.get('kind') is not None
                            or row.get('schema_version') is not None,
                            'raw-trace-derived-kind-missing')

    def local(component, event_id, code):
        require(type(event_id) is int and event_id > 0
                and (component, event_id) in local_by_id, code)
        return local_by_id[(component, event_id)]

    def source_runtime_name():
        if type(artifacts) is not dict:
            return None
        artifact = artifacts.get(dma_id)
        runtime = getattr(artifact, 'runtime_document', None)
        exports = runtime.get('physical_exports') if type(runtime) is dict else None
        rows = [row for row in exports if type(row) is dict
            and row.get('physical_port') == irq_contract['producer_port']
            and row.get('endpoint_id') == irq_contract['producer_endpoint_id']
            and row.get('direction') == 'output' and row.get('role') == 'irq'
            and row.get('width') == 1 and row.get('disposition') == 'functional'] \
            if type(exports) in (tuple, list) else []
        require(len(rows) == 1 and type(rows[0].get('runtime_name')) is str
                and bool(rows[0]['runtime_name']),
                'raw-trace-irq-export-identity')
        return rows[0]['runtime_name']

    derived_rows = [row for row in local_by_id.values()
        if row.get('runner_event_id') is None
        and row.get('kind') != 'local_tick_sample']
    for row in derived_rows:
        kind = row.get('kind', row.get('schema_version'))
        component = row['component']
        if kind == 'source_start':
            require(component == dma_id
                    and set(row) == {'component', 'event_id', 'kind',
                        'source_output_key', 'source', 'target',
                        'producer_event_id', 'source_event_id'},
                    'raw-trace-source-start-shape')
            producer_id = row.get('producer_event_id')
            require(row.get('source_event_id') == producer_id,
                    'raw-trace-source-start-reference')
            producer = local(dma_id, producer_id,
                             'raw-trace-source-start-producer-missing')
            physical_name = source_runtime_name()
            payload = producer.get('payload')
            observations = payload.get('observations') if type(payload) is dict else None
            physical = observations.get('physical') if type(observations) is dict else None
            tick, epoch = producer.get('tick'), producer.get('reset_epoch')
            require(producer.get('kind') == 'dma_edge'
                    and (dma_id, producer_id) in runner_link_by_local_id
                    and physical_name is not None and type(physical) is dict
                    and type(physical.get(physical_name)) is int
                    and physical[physical_name] == 1
                    and type(tick) is int and tick > 0
                    and type(epoch) is int and epoch >= 0,
                    'raw-trace-source-start-runner-origin')
            equal(row, dict(component=dma_id, event_id=row['event_id'],
                kind='source_start', source_output_key=[dma_id, epoch,
                    irq_contract['producer_port'], tick],
                source=[dma_id, 'irq'], target=[cpu_id, 'irq'],
                producer_event_id=producer_id, source_event_id=producer_id),
                'raw-trace-source-start-reprojection')
        elif kind == 'binding_delivery':
            require(component == cpu_id
                    and set(row) == {'component', 'event_id', 'kind',
                        'source_event_id', 'source_output_key', 'delivery_id',
                        'target_component', 'target_epoch', 'start_local_tick',
                        'end_local_tick'},
                    'raw-trace-delivery-shape')
            source = local(dma_id, row.get('source_event_id'),
                           'raw-trace-delivery-source-missing')
            start, end = row.get('start_local_tick'), row.get('end_local_tick')
            require(source.get('kind') == 'source_start'
                    and row.get('source_output_key') ==
                        source.get('source_output_key')
                    and row.get('delivery_id') == irq_contract['delivery_id']
                    and row.get('target_component') == cpu_id
                    and type(row.get('target_epoch')) is int
                    and type(start) is int and start >= 1
                    and type(end) is int and end == start + 16,
                    'raw-trace-delivery-source-scope')
            pulse_rows = [event for event in events
                if event.get('component') == cpu_id
                and event.get('kind') == 'cpu_external_irq_sample'
                and event.get('binding_delivery_event_id') == row['event_id']]
            require(len(pulse_rows) == 16
                    and [event.get('local_tick') for event in pulse_rows] ==
                        list(range(start, end)),
                    'raw-trace-delivery-sample-span')
            for event in pulse_rows:
                context = event.get('input_context')
                require(type(event.get('expected_input')) is int
                        and event['expected_input'] == 1
                        and event.get('reset_epoch') == row['target_epoch']
                        and type(event.get('actual_pre_input')) is int
                        and event['actual_pre_input'] == 1
                        and type(event.get('actual_post_input')) is int
                        and event['actual_post_input'] == 1
                        and event.get('source_output_key') ==
                            row['source_output_key']
                        and type(context) is dict
                        and context.get('binding_delivery_event_id') ==
                            row['event_id']
                        and context.get('source_output_key') ==
                            row['source_output_key'],
                        'raw-trace-delivery-sample-join')
            expiry = [event for event in events
                if event.get('component') == cpu_id
                and event.get('kind') == 'cpu_external_irq_sample'
                and event.get('local_tick') == end
                and event.get('reset_epoch') == row['target_epoch']]
            require(len(expiry) == 1
                    and type(expiry[0].get('expected_input')) is int
                    and expiry[0]['expected_input'] == 0
                    and type(expiry[0].get('actual_pre_input')) is int
                    and expiry[0]['actual_pre_input'] == 0
                    and type(expiry[0].get('actual_post_input')) is int
                    and expiry[0]['actual_post_input'] == 0,
                    'raw-trace-delivery-expiry-sample')
        elif kind == 'native_fetch_boundary':
            transaction = row.get('transaction')
            audit = prefix.get('original_execution_audit')
            identities = audit.get('identities') if type(audit) is dict else None
            cpu_identity = (identities.get(cpu_id)
                if type(identities) is dict else None)
            execution_nonce = (cpu_identity.get('execution_nonce')
                if type(cpu_identity) is dict else None)
            require(component == cpu_id
                    and set(row) == {'address', 'execution', 'reset_epoch',
                        'native_testcase_id', 'transaction', 'local_tick',
                        'boundary', 'component', 'event_id', 'kind'}
                    and type(transaction) is dict
                    and set(transaction) == {'execution_id', 'testcase_id',
                        'source_component', 'source_epoch', 'channel_id',
                        'source_sequence'}
                    and transaction.get('execution_id') == 'local-execution'
                    and type(transaction.get('testcase_id')) is str
                    and bool(transaction['testcase_id'])
                    and transaction.get('source_component') == cpu_id
                    and transaction.get('channel_id') == 'instr'
                    and type(transaction.get('source_epoch')) is int
                    and type(transaction.get('source_sequence')) is int
                    and transaction['source_sequence'] > 0
                    and type(row.get('local_tick')) is int
                    and type(row.get('reset_epoch')) is int
                    and row['reset_epoch'] == transaction['source_epoch']
                    and type(execution_nonce) is str
                    and row.get('execution') == execution_nonce
                    and row.get('native_testcase_id') ==
                        transaction.get('testcase_id')
                    and type(row.get('execution')) is str
                    and bool(row['execution'])
                    and type(row.get('address')) is int
                    and row.get('boundary') in
                        ('error_current_island', 'next_prefix_or_park'),
                    'raw-trace-fetch-boundary-shape')
            samples = [event for event in events
                if event.get('component') == cpu_id
                and event.get('kind') == 'local_tick_sample'
                and event.get('local_tick') == row['local_tick']
                and event.get('phase') == 'pre']
            require(len(samples) == 1, 'raw-trace-fetch-boundary-sample')
            sample = samples[0]
            backend = sample.get('outputs', {}).get('backend', {})
            require(type(backend) is dict
                    and backend.get('i_req_valid') == 1
                    and backend.get('i_req_ready') == 1
                    and backend.get('i_req_addr') == row['address'],
                    'raw-trace-fetch-boundary-handshake')
            sample_event_id = sample.get('event_id')
            reset_rows = [event for event in events
                if event.get('component') == cpu_id
                and event.get('kind') == 'cpu_reset'
                and event.get('reset_epoch') == transaction['source_epoch']
                and type(event.get('event_id')) is int
                and type(sample_event_id) is int
                and event['event_id'] < sample_event_id]
            if reset_rows:
                sequence_start_event_id = max(
                    event['event_id'] for event in reset_rows)
            else:
                require(transaction['source_epoch'] == 0,
                        'raw-trace-fetch-boundary-reset-anchor')
                sequence_start_event_id = 0
            accepted_instruction_handshakes = 0
            for event in events:
                if (event.get('component') != cpu_id
                        or event.get('kind') != 'local_tick_sample'
                        or event.get('phase') != 'pre'
                        or type(event.get('event_id')) is not int
                        or not sequence_start_event_id < event['event_id']
                        <= sample_event_id):
                    continue
                outputs = event.get('outputs')
                event_backend = (outputs.get('backend')
                    if type(outputs) is dict else None)
                require(type(event_backend) is dict
                        and type(event_backend.get('i_req_valid')) is int
                        and type(event_backend.get('i_req_ready')) is int
                        and event_backend['i_req_valid'] in (0, 1)
                        and event_backend['i_req_ready'] in (0, 1),
                        'raw-trace-fetch-boundary-sequence-sample')
                if (event_backend['i_req_valid'] == 1
                        and event_backend['i_req_ready'] == 1):
                    accepted_instruction_handshakes += 1
            require(accepted_instruction_handshakes ==
                    transaction['source_sequence'],
                    'raw-trace-fetch-boundary-sequence')
        elif kind == 'native_f6_isr_return.v1':
            _verify_f6_isr_return_trace_row(row, prefix, contract, binding,
                runner_by_id, firmware_document)
        else:
            require(False, 'raw-trace-unrecognized-derived-event:' + str(kind))

    return local_by_id


def _verify_f6_isr_return_trace_row(row, prefix, contract, binding,
                                    runner_by_id, firmware_document):
    """Reproject the derived ISR-return row from its Runner receipt sources."""
    cpu_id = contract['cpu']['instance_id']
    attempts = [attempt for attempt in prefix['attempts']
        if attempt.get('case_id') == row.get('case_id')]
    require(len(attempts) == 1 and row.get('component') == cpu_id,
            'raw-trace-isr-return-case')
    attempt = attempts[0]
    expected_fields = {'schema_version', 'component', 'event_id', 'execution',
        'reset_epoch', 'case_id', 'case_index', 'native_testcase_id',
        'irq_take_key', 'take_receipt_id', 'take_irq_serial_observation',
        'handler_entry_receipt_id', 'handler_entry_rvfi_order',
        'handler_entry_pc_rdata', 'handler_entry_irq_serial_observation',
        'return_receipt_id', 'return_receipt_ticks', 'local_tick', 'phase',
        'rvfi_order', 'instruction', 'pc_rdata', 'pc_wdata',
        'irq_serial_observation', 'isr_sha256',
        'execution_binding_sha256', 'successor_receipt_id',
        'successor_rvfi_order', 'successor_local_tick',
        'successor_pc_rdata', 'successor_instruction',
        'successor_irq_serial_observation', 'successor_instruction_response',
        'successor_instruction_response_receipt_id', 'return_target',
        'return_target_source', 'return_target_authority'}
    require(set(row) == expected_fields
            and row.get('schema_version') == 'native_f6_isr_return.v1'
            and row.get('case_index') == attempt.get('case_index')
            and row.get('execution_binding_sha256') ==
                binding.get('binding_sha256')
            and type(firmware_document) is dict,
            'raw-trace-isr-return-shape')
    events = [event for event in runner_by_id.values()
        if event.get('component') == cpu_id]
    audit = prefix.get('original_execution_audit')
    identities = audit.get('identities') if type(audit) is dict else None
    cpu_identity = identities.get(cpu_id) if type(identities) is dict else None
    execution_nonce = (cpu_identity.get('execution_nonce')
        if type(cpu_identity) is dict else None)
    require(type(execution_nonce) is str and bool(execution_nonce)
            and row.get('execution') == execution_nonce,
            'raw-trace-isr-execution-identity')

    def one(predicate, code):
        matches = [event for event in events if predicate(event)]
        require(len(matches) == 1, code)
        return matches[0]

    take_receipt = row.get('take_receipt_id')
    require(type(take_receipt) is dict
            and set(take_receipt) == {'execution', 'sequence'}
            and take_receipt.get('execution') == execution_nonce
            and type(take_receipt.get('sequence')) is int
            and take_receipt['sequence'] > 0,
            'raw-trace-isr-take-receipt-shape')
    take = one(lambda event: event.get('kind') == 'cpu_external_irq_taken'
        and event.get('take_key') == row.get('irq_take_key')
        and type(event.get('receipt_id')) is dict
        and event['receipt_id'].get('sequence') == take_receipt['sequence'],
        'raw-trace-isr-take')
    take_sample = runner_by_id.get(take.get('sample_event_id'))
    require(row.get('take_irq_serial_observation') ==
                take.get('irq_serial_observation')
            and (take.get('testcase_id') is None or
                 row.get('native_testcase_id') == take.get('testcase_id'))
            and row.get('reset_epoch') == take.get('reset_epoch')
            and type(row.get('irq_take_key')) is list
            and row['irq_take_key'] == take.get('take_key')
            and type(take_sample) is dict
            and take_sample.get('kind') == 'cpu_external_irq_sample'
            and take_sample.get('component') == cpu_id
            and take_sample.get('receipt_id') == take.get('receipt_id')
            and take_sample.get('local_tick') == take.get('local_tick')
            and take_sample.get('reset_epoch') == take.get('reset_epoch'),
            'raw-trace-isr-take-join')
    if take.get('testcase_id') is None:
        # Run7's Runner take is scoped by a parsed command, not a testcase
        # field. Bind that alias back to the audited execution nonce through
        # both physical phases and the original producer's driver samples.
        tick = take.get('local_tick')
        seq = take_receipt['sequence']; epoch = row['reset_epoch']
        scope = dict(component=cpu_id, reset_epoch=epoch, command_sequence=seq)
        receipt = take.get('receipt_id', {})
        alias = receipt.get('execution', '')
        alias_prefix = 'local-driver:' + cpu_id + ':'
        ordinal = alias[len(alias_prefix):] if type(alias) is str and alias.startswith(alias_prefix) else ''
        observed_case = dict(case_id=row['case_id'], case_index=row['case_index'])
        require(type(tick) is int and tick > 0 and ordinal.isascii()
                and ordinal.isdigit() and ordinal[0:1] not in ('', '0')
                and take.get('command_scope') == take_sample.get('command_scope')
                == scope and take.get('sample_ref') ==
                    dict(command_scope=scope, local_tick=tick)
                and take.get('receipt_ticks') == take_sample.get('receipt_ticks')
                and all(event.get('provenance', {}).get('observed_case') == observed_case
                    for event in (take, take_sample)),
                'raw-trace-isr-take-command-scope')
        pre = one(lambda event: event.get('kind') == 'local_tick_sample'
            and event.get('local_tick') == tick and event.get('phase') == 'pre',
            'raw-trace-isr-take-pre')
        post = one(lambda event: event.get('kind') == 'local_tick_sample'
            and event.get('local_tick') == tick and event.get('phase') == 'post',
            'raw-trace-isr-take-post')
        producer = runner_by_id.get(take.get('producer_event_id'))
        ticks = take.get('receipt_ticks'); expected_raw = [execution_nonce, seq, epoch, tick]
        require(type(producer) is dict and producer.get('component') == cpu_id
                and producer.get('local_tick') == tick and type(ticks) is dict
                and all(type(ticks.get(k)) is int for k in
                    ('tick_before', 'tick_after', 'new_ticks', 'local_tick_base'))
                and ticks['new_ticks'] == 1 and ticks['tick_after'] == ticks['tick_before'] + 1
                and ticks['tick_after'] + ticks['local_tick_base'] == tick
                and take_sample.get('producer_event_id') == producer['event_id']
                and all(part.get('producer_event_id') == producer['event_id']
                    and part.get('f6_obi_scope') == expected_raw
                    and part.get('provenance', {}).get('observed_case') == observed_case
                    for part in (pre, post))
                and producer.get('provenance', {}).get('observed_case') == observed_case
                and producer.get('outputs', {}).get('driver_samples') == [dict(
                    local_tick=ticks['tick_after'], pre=pre.get('outputs'), post=post.get('outputs'))],
                'raw-trace-isr-take-native-scope')

    def retirement(receipt_id, code):
        require(type(receipt_id) is dict
                and set(receipt_id) == {'execution', 'sequence'}
                and receipt_id.get('execution') == execution_nonce
                and type(receipt_id.get('sequence')) is int
                and receipt_id['sequence'] > 0,
                'raw-trace-isr-retirement-receipt-shape')
        event = one(lambda event: event.get('kind') == 'cpu_retire'
            and type(event.get('receipt_id')) is dict
            and event['receipt_id'].get('sequence') == receipt_id['sequence']
            and event.get('reset_epoch') == row.get('reset_epoch'), code)
        retire_tick = event.get('local_tick')
        sample = one(lambda sample_event: sample_event.get('kind') ==
            'cpu_external_irq_sample'
            and type(sample_event.get('receipt_id')) is dict
            and sample_event['receipt_id'].get('sequence') == receipt_id['sequence']
            and sample_event.get('local_tick') == retire_tick,
            code + '-receipt-sample')
        require(sample.get('reset_epoch') == event.get('reset_epoch')
                and sample.get('local_tick') == event.get('local_tick')
                and sample.get('receipt_ticks') == event.get('receipt_ticks')
                and sample.get('receipt_id') == event.get('receipt_id'),
                code + '-receipt-sample-join')
        return event

    handler = retirement(row.get('handler_entry_receipt_id'),
                         'raw-trace-isr-handler-retirement')
    returned = retirement(row.get('return_receipt_id'),
                          'raw-trace-isr-return-retirement')
    successor = retirement(row.get('successor_receipt_id'),
                           'raw-trace-isr-successor-retirement')
    require(take_sample.get('receipt_id', {}).get('execution') ==
                handler.get('receipt_id', {}).get('execution') ==
                returned.get('receipt_id', {}).get('execution') ==
                successor.get('receipt_id', {}).get('execution'),
            'raw-trace-isr-normalized-execution-scope')

    def compare_retirement(receipt_id, event, *, handler_entry=False,
                           successor_entry=False):
        require(event.get('reset_epoch') == row.get('reset_epoch')
                and event.get('phase') == 'post'
                and event.get('receipt_id', {}).get('sequence') ==
                    receipt_id.get('sequence'),
                'raw-trace-isr-retirement-scope')
        if handler_entry:
            require(event.get('order') == row['handler_entry_rvfi_order']
                    and event.get('pc_rdata') == row['handler_entry_pc_rdata']
                    and event.get('irq_serial_observation') ==
                        row['handler_entry_irq_serial_observation']
                    and event.get('intr') == 1,
                    'raw-trace-isr-handler-join')
        elif successor_entry:
            require(event.get('order') == row['successor_rvfi_order']
                    and event.get('local_tick') == row['successor_local_tick']
                    and event.get('pc_rdata') == row['successor_pc_rdata']
                    and event.get('insn') == row['successor_instruction']
                    and event.get('irq_serial_observation') ==
                        row['successor_irq_serial_observation']
                    and event.get('intr') == 0,
                    'raw-trace-isr-successor-join')
        else:
            require(event.get('order') == row['rvfi_order']
                    and event.get('local_tick') == row['local_tick']
                    and event.get('insn') == row['instruction']
                    and event.get('pc_rdata') == row['pc_rdata']
                    and event.get('pc_wdata') == row['pc_wdata']
                    and event.get('irq_serial_observation') ==
                        row['irq_serial_observation'],
                    'raw-trace-isr-return-join')
        require(event.get('receipt_id', {}).get('sequence') ==
                    receipt_id.get('sequence'),
                'raw-trace-isr-retirement-receipt')

    compare_retirement(row['handler_entry_receipt_id'], handler,
                       handler_entry=True)
    compare_retirement(row['return_receipt_id'], returned)
    compare_retirement(row['successor_receipt_id'], successor,
                       successor_entry=True)
    require(handler.get('order') < returned.get('order')
            and returned.get('order', 0) + 1 == successor.get('order')
            and handler.get('local_tick') < returned.get('local_tick')
            and returned.get('local_tick') < successor.get('local_tick')
            and returned.get('insn') == 0x30200073
            and returned.get('intr') == 0,
            'raw-trace-isr-retirement-order')
    isr = firmware_document.get('isr')
    require(type(isr) is dict
            and handler.get('pc_rdata') == isr.get('address')
            and returned.get('pc_rdata') in isr.get('mret_addresses', [])
            and row.get('isr_sha256') == isr.get('sha256'),
            'raw-trace-isr-firmware-join')
    return_ticks = row.get('return_receipt_ticks')
    require(type(return_ticks) is dict
            and set(return_ticks) == {'tick_before', 'tick_after',
                'new_ticks', 'local_tick_base'}
            and returned.get('receipt_ticks') == return_ticks
            and returned.get('receipt_id', {}).get('sequence') ==
                row.get('return_receipt_id', {}).get('sequence')
            and row.get('return_target') == row.get('successor_pc_rdata')
            and row.get('successor_instruction_response_receipt_id', {}).get(
                'sequence', 0) <= row.get('successor_receipt_id', {}).get(
                    'sequence', -1)
            and row.get('return_target_source') ==
                'first_subsequent_valid_RVFI_pc_rdata_with_instruction_response'
            and row.get('return_target_authority') ==
                'inferred_architectural_successor_after_MRET',
            'raw-trace-isr-return-successor-identity')
    response_receipt = row.get('successor_instruction_response_receipt_id')
    require(type(response_receipt) is dict
            and set(response_receipt) == {'execution', 'sequence'}
            and response_receipt.get('execution') == execution_nonce
            and type(response_receipt.get('sequence')) is int
            and response_receipt['sequence'] > 0,
            'raw-trace-isr-successor-response-receipt')
    response_samples = [event for event in events
        if event.get('kind') == 'cpu_external_irq_sample'
        and type(event.get('receipt_id')) is dict
        and event['receipt_id'].get('sequence') == response_receipt['sequence']]
    response_doc = row.get('successor_instruction_response')
    require(type(response_doc) is dict,
            'raw-trace-isr-successor-response-shape')
    transaction = response_doc.get('transaction')
    require(type(transaction) is dict
            and transaction.get('testcase_id') == row.get('native_testcase_id')
            and transaction.get('source_component') == cpu_id
            and transaction.get('source_epoch') == row.get('reset_epoch')
            and transaction.get('channel_id') == 'instr'
            and transaction.get('execution_id') == 'local-execution'
            and type(transaction.get('source_sequence')) is int
            and transaction['source_sequence'] > 0,
            'raw-trace-isr-successor-response-transaction')
    response = one(lambda event: event.get('kind') == 'instr_response'
        and event.get('transaction') == response_doc.get('transaction')
        and event.get('response_tick') == response_doc.get('response_tick'),
        'raw-trace-isr-successor-response')
    require(len(response_samples) == 1
            and response_samples[0].get('local_tick') ==
                response_doc.get('response_tick')
            and response_samples[0].get('reset_epoch') == row.get('reset_epoch')
            and response_samples[0].get('receipt_id', {}).get('execution') ==
                successor.get('receipt_id', {}).get('execution')
            and response.get('component') == cpu_id,
            'raw-trace-isr-successor-response-tick')
    projected_response = deepcopy(response)
    for key in ('event_id', 'producer_event_id', 'provenance'):
        projected_response.pop(key, None)
    equal(response_doc, projected_response,
          'raw-trace-isr-successor-response-join')


def _audit_attempt(output, invocation, declaration, sources):
    """Rebuild F6 D3/D4 and audit the saved original/fresh execution material."""
    # Read all ten mandatory documents before accepting any claimed mode. This
    # makes partial failure exports ineligible for a completed/error verdict.
    docs = {name: read_json(safe_file(output, name), pretty=True)
            for name in F6_OUTPUT_DOCUMENTS}
    prefix = docs['compiled_f6_prefix.json']
    replay = docs['compiled_f6_replay.json']
    fresh_prefix = docs['compiled_f6_fresh_prefix.json']
    fresh_events = docs['compiled_f6_fresh_events.json']
    fresh_audit = docs['compiled_f6_fresh_execution_audit.json']
    fresh_verification = docs['compiled_f6_fresh_verification.json']
    build_join = docs['compiled_f6_build_join.v1.json']
    receipt_join = docs['compiled_f6_receipt_join.v1.json']
    typed_results = docs['compiled_assertion_results.v1.json']
    typed_evidence = docs['compiled_assertion_evidence.v1.json']

    summary = read_json(safe_file(output, 'run-summary.json'), pretty=True)
    expected_error = declaration['outcome'] == 'expected_error'
    if expected_error:
        expected_refusal = {'stage': 'session',
            'code': 'compiled-f6-expected-error-prefix', 'pointer': '/session'}
        refusal_rows = summary.get('refusals')
        require(summary.get('status') == 'refused'
                and summary.get('exit_code') == 1
                and summary.get('output') == str(output.resolve())
                and type(refusal_rows) is list and len(refusal_rows) == 1
                and type(refusal_rows[0]) is dict
                and all(refusal_rows[0].get(key) == value
                        for key, value in expected_refusal.items())
                and summary.get('absences') == [], 'expected-error-run-summary')
        session_stage = summary.get('stages', {}).get('session', {})
        require(session_stage.get('status') == 'refused'
                and session_stage.get('scope') == 'failed_prefix_full'
                and session_stage.get('completed') is False,
                'expected-error-session-stage')
        executor_stage = summary.get('executor', {})
        require(executor_stage.get('status') == 'refused'
                and executor_stage.get('code') ==
                    'compiled-f6-expected-error-prefix',
                'expected-error-executor-stage')
        require((output / '.incomplete').is_file(),
                'expected-error-incomplete-marker')
    else:
        require(summary.get('status') == 'complete'
                and summary.get('exit_code') == 0
                and summary.get('output') == str(output.resolve())
                and summary.get('refusals') == []
                and summary.get('absences') == []
                and not (output / '.incomplete').exists(),
                'attempt-run-summary')
    stages = summary.get('stages')
    require(type(stages) is dict
            and stages.get('session', {}).get('status') ==
                ('refused' if expected_error else 'ok')
            and stages.get('fresh_verification', {}).get('status') == 'ok'
            and stages.get('capability_report', {}).get('status') == 'ok',
            'attempt-stage-completion')
    require(summary.get('executor', {}).get('name') == 'compiled-f6-rfuzz'
            and summary.get('executor', {}).get('family_fallback') is False,
            'attempt-executor')

    outcome = declaration['outcome']
    if outcome == 'completed':
        expected_status, expected_scope, expected_completed = 'complete', 'full', True
    elif outcome == 'expected_error':
        expected_status, expected_scope, expected_completed = (
            'expected_error', 'failed_prefix_full', False)
    else:
        raise ValueError('compiled-F6-saved-audit-attempt-outcome')
    require(type(prefix) is dict
            and prefix.get('schema_version') == 'compiled_F6_prefix.v1'
            and prefix.get('status') == expected_status
            and prefix.get('scope') == expected_scope
            and prefix.get('completed') is expected_completed
            and type(prefix.get('records')) is list and bool(prefix['records'])
            and type(prefix.get('attempts')) is list
            and len(prefix['records']) == len(prefix['attempts'])
            and prefix.get('error') is None
            and prefix.get('trace_status') == 'complete'
            and prefix.get('unavailable') == {}, 'attempt-prefix-scope')
    _verify_prefix_trace(prefix)

    # Recompile the exact D3 request, then reconstruct D2 and the runtime path
    # from its source-backed files. This is pure admission; no native session or
    # build command is started by the saved auditor.
    request_document = read_json(safe_file(output, 'path_compile_request.json'),
                                 pretty=True)
    compiled_document = read_json(safe_file(output, 'compiled_paths.v1.json'),
                                  pretty=True)
    from myfuzz.scenario.compiled_paths import (
        load_path_compile_request, compile_paths, compiled_document_sha256)
    request = load_path_compile_request(request_document, base_dir=ROOT)
    rebuilt_compiled = compile_paths(request)
    equal(rebuilt_compiled, compiled_document, 'd3-recompile')
    executable = [row for row in rebuilt_compiled.get('paths', ())
                  if row.get('flow_id') == 'F6' and row.get('status') == 'executable']
    require(len(executable) == 1, 'one-executable-f6-path')
    path = executable[0]
    contract = path.get('execution_contract')
    require(type(contract) is dict
            and contract.get('schema_version') ==
                'compiled_F6_cpu_dma_contract.v1', 'f6-contract-required')
    from myfuzz.integration.compiled_f6_layout import compile_f6_candidate_layout
    from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
    layout = compile_f6_candidate_layout(path)
    firmware = build_f6_firmware(contract)
    compiled_sha = compiled_document_sha256(rebuilt_compiled)
    binding_document = prefix.get('execution_binding')
    from myfuzz.scenario.f6_execution_binding import CompiledF6ExecutionBinding
    binding = CompiledF6ExecutionBinding(binding_document).document()
    _verify_auditor_sources(sources, binding)
    require(prefix.get('compiled_document_sha256') == compiled_sha
            and prefix.get('binding_sha256') == binding['binding_sha256']
            and prefix.get('execution_binding_sha256') == binding['binding_sha256']
            and binding.get('compiled_document_sha256') == compiled_sha
            and binding.get('request_sha256') == digest(request.document)
            and binding.get('execution_contract_sha256') == digest(contract)
            and binding.get('path_id') == path.get('path_id')
            and binding.get('run_id') == prefix.get('run_id')
            and binding.get('program_sha256') == digest(firmware.document()),
            'execution-binding-d3-program-join')
    require(prefix.get('run_id') == summary.get('label')
            and prefix.get('runtime_path_admission') == binding.get('runtime_path_admission'),
            'prefix-binding-identity')

    generated = output / 'generated'
    require(generated.is_dir() and not generated.is_symlink(),
            'generated-artifacts-required')
    temporary = tempfile.TemporaryDirectory(prefix='compiled-f6-saved-audit-')
    artifacts = None
    try:
        temp_root = Path(temporary.name)
        temp_generated = temp_root / 'generated'
        shutil.copytree(generated, temp_generated, symlinks=False)
        from myfuzz.local_harness.auto_harness_test import load_compiled_session_inputs
        artifacts, compiled_inputs = load_compiled_session_inputs(
            generated_root=temp_generated, base_dir=ROOT, request=request,
            compiled=rebuilt_compiled, flow='F6')
        saved_ownership = read_json(safe_file(output, 'compiled_ownership.v1.json'),
                                    pretty=True)
        equal(saved_ownership, read_json(temp_root / 'compiled_ownership.v1.json'),
              'compiled-ownership-source-rebuild')
        from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
        runtime_admission = admit_compiled_f6_runtime_path(
            artifacts=artifacts, compiled_inputs=compiled_inputs, base_dir=ROOT)
        equal(binding.get('runtime_path_admission'), runtime_admission,
              'runtime-path-recompile')
        require(prefix.get('runtime_path_admission') == runtime_admission
                and binding.get('runtime_path_admission_sha256') ==
                    runtime_admission.get('admission_sha256')
                and binding.get('selected_path_sha256') ==
                    digest(runtime_admission['logical_path']),
                'runtime-path-binding')
        artifact_digests = {name: artifact.runtime_document['artifact_digest']
                            for name, artifact in sorted(artifacts.items())}
        equal(prefix.get('artifact_digests'), artifact_digests,
              'prefix-artifact-digests')
        require(binding.get('artifact_identities') == {
            name: __import__('myfuzz.integration.compiled_f4', fromlist=['_artifact_execution_identity'])
                ._artifact_execution_identity(artifact)
            for name, artifact in sorted(artifacts.items())},
            'binding-artifact-identities')

        _audit_f6_prefix_records(prefix, fresh_prefix, layout, firmware,
            runtime_admission, binding, declaration)
        _audit_f6_receipts(output, prefix, receipt_join, layout, firmware,
            runtime_admission, declaration)
        _audit_f6_fresh(prefix, replay, fresh_prefix, fresh_events, fresh_audit,
            fresh_verification, expected_scope, expected_completed)
        raw_event_index = _audit_f6_typed(prefix, fresh_prefix,
            typed_results, typed_evidence, binding, expected_completed,
            contract, artifacts, firmware.document())

        session_dir = output / 'session'
        require(session_dir.is_dir() and not session_dir.is_symlink(),
                'session-directory-required')
        manifest = read_json(safe_file(session_dir, 'online_session_manifest.json'))
        trace_document = read_json(safe_file(session_dir, 'online_final_trace.json'))
        from myfuzz.scenario.replay import ScenarioTrace
        trace = ScenarioTrace(**trace_document)
        _verify_prefix_online_trace(prefix, trace)
        from myfuzz.integration.scenario_rfuzz_live import _verify_online_run_identity
        identity = _verify_online_run_identity(session_dir,
            plan_path=safe_file(session_dir, 'online_plan.json'),
            trace_path=safe_file(session_dir, 'online_final_trace.json'), trace=trace)
        require(type(identity) is dict, 'online-run-identity-required')
        if expected_error:
            _audit_f6_expected_error(prefix, contract,
                                     firmware.document(), binding,
                                     declaration['fault_selector'],
                                     raw_event_index)
        _audit_client_pin(_command_for_invocation(invocation), identity, sources)
        from myfuzz.integration.compiled_build_join import verify_compiled_build_material
        verify_compiled_build_material(build_join, flow='F6',
            harness_set=read_json(safe_file(generated, 'harness_set.json'), pretty=True),
            manifest=manifest, prefix=prefix, replay=replay)
        from myfuzz.integration.compiled_f6_build_join import verify_compiled_f6_build_join
        verify_compiled_f6_build_join(build_join, artifacts=artifacts,
            execution_binding=binding, original=prefix.get('original_build'),
            fresh=fresh_prefix.get('original_build'))

        # The D4 report is rebuilt from saved D2/D3/session/fresh/typed docs.
        from myfuzz.scenario.capability_report import build_capability_report
        expected_report = build_capability_report(
            output / 'compiled_paths.v1.json',
            harness_set=generated / 'harness_set.json', session=session_dir,
            fresh_verification=output / 'fresh-verification.json',
            label=summary['label'], base_dir=ROOT,
            assertion_results=typed_results,
            assertion_evidence=typed_evidence)
        equal(expected_report, read_json(safe_file(output, 'capability-report.json'),
                                        pretty=True), 'capability-report-rebuild')
    finally:
        if artifacts is not None:
            from myfuzz.local_harness.generated_artifact_admission import release_f6_provider_credentials
            release_f6_provider_credentials(artifacts)
        temporary.cleanup()

    return dict(status='ok', outcome=outcome, scope=expected_scope,
                case_count=len(prefix['records']),
                native_authority_issued=False)


def _command_for_invocation(invocation):
    return read_json(safe_file(invocation, 'command.json'), pretty=True)


def _expected_cli_environment(outcome):
    require(outcome in ('completed', 'refusal'),
            'cli-command-outcome-selection')
    return {
        'PYTHONPATH': 'src:.',
        'MYFUZZ_SCENARIO_RFUZZ_LIVE': '1',
        'MYFUZZ_RUN_NATIVE_F6': '1' if outcome == 'completed' else '0',
    }


def _expected_error_dma_testcase_id(prefix, case_index, dma_component,
        raw_event_index):
    """Rebuild the selected DMA scope from the native start and saved transitions."""
    run_id = prefix.get('run_id')
    attempts = prefix.get('attempts')
    require(type(run_id) is str and bool(run_id)
            and type(attempts) is list
            and type(case_index) is int
            and 0 <= case_index < len(attempts)
            and type(raw_event_index) is dict,
            'expected-error-dma-scope-shape')
    expected_scope = run_id + ':native'
    for next_index in range(1, case_index + 1):
        previous_attempt = attempts[next_index - 1]
        require(type(previous_attempt) is dict
                and previous_attempt.get('case_id') ==
                    f'{run_id}:case:{next_index - 1}'
                and previous_attempt.get('case_index') == next_index - 1
                and previous_attempt.get('status_kind') == 'passed'
                and previous_attempt.get('expected_error') is False
                and previous_attempt.get('feedback') == [1] * 5,
                'expected-error-dma-scope-previous-case')

        for field in ('reads', 'writes'):
            references = previous_attempt.get(field)
            require(type(references) is list and len(references) == 4
                    and all(type(event_id) is int and event_id > 0
                        for event_id in references),
                    'expected-error-dma-scope-previous-references:' + field)
            for event_id in references:
                row = raw_event_index.get((dma_component, event_id))
                accepted = row.get('accepted') if type(row) is dict else None
                transaction = (accepted.get('transaction')
                    if type(accepted) is dict else None)
                require(type(row) is dict
                        and row.get('component') == dma_component
                        and row.get('kind') == 'dma_edge'
                        and type(transaction) is dict
                        and transaction.get('testcase_id') == expected_scope,
                        'expected-error-dma-scope-previous-transaction')

        expected_next_scope = f'{run_id}:dma:{next_index}'
        expected_transition = dict(previous_case_id=expected_scope,
            testcase_id=expected_next_scope,
            case_id=f'{run_id}:case:{next_index}', case_index=next_index)
        equal(previous_attempt.get('scope_transition'), expected_transition,
              'expected-error-dma-scope-transition')
        expected_scope = expected_next_scope
    return expected_scope


def _audit_f6_expected_error(prefix, contract, firmware, binding,
        selector, raw_event_index=None):
    """Join the sealed selector to the actual accepted/ERR native beat and ISR."""
    require(type(selector) is dict,
            'expected-error-trace-shape')
    attempts = prefix.get('attempts')
    records = prefix.get('records')
    require(type(attempts) is list and bool(attempts)
            and type(records) is list and len(records) == len(attempts),
            'expected-error-attempt-inventory')
    case_index = selector['case_index']
    require(type(case_index) is int and case_index == len(attempts) - 1,
            'expected-error-terminal-case')
    attempt = attempts[case_index]
    program = contract['program_contract']
    operation = selector['operation']
    word_index = selector['word_index']
    require(operation in ('read', 'write') and word_index in (1, 2),
            'expected-error-middle-beat')
    component = contract['dma']['instance_id']
    cpu_component = contract['cpu']['instance_id']

    case_material = attempt.get('case_material')
    inventory = (case_material.get('evidence_inventory')
                 if type(case_material) is dict else None)
    require(type(inventory) is dict and bool(inventory),
            'expected-error-raw-inventory')
    by_id = (raw_event_index if type(raw_event_index) is dict else
        _verify_f6_raw_evidence_trace(prefix, contract, binding))
    expected_dma_testcase_id = _expected_error_dma_testcase_id(
        prefix, case_index, component, by_id)

    def referenced(name, component, index=None):
        values = attempt.get(name)
        if index is not None:
            require(type(values) is list and len(values) == 4,
                    'expected-error-reference-array:' + name)
            event_id = values[index]
        else:
            event_id = values
        require(type(event_id) is int and (component, event_id) in by_id,
                'expected-error-reference-missing:' + name)
        return by_id[(component, event_id)]

    accepted_field = 'reads' if operation == 'read' else 'writes'
    response_field = ('read_responses' if operation == 'read'
                      else 'write_responses')
    accepted_event = referenced(accepted_field, component, word_index)
    response_event = referenced(response_field, component, word_index)
    accepted = accepted_event.get('accepted')
    transaction = accepted.get('transaction') if type(accepted) is dict else None
    transaction_fields = {'execution_id', 'testcase_id', 'source_component',
                          'source_epoch', 'channel_id', 'source_sequence'}
    _closed(transaction, transaction_fields, 'expected-error-transaction-fields')
    expected_sequence = (word_index + 1 if operation == 'read'
                         else 4 + word_index + 1)
    expected_address = (program['source_address'] if operation == 'read'
                        else program['destination_address']) + 4 * word_index
    require(accepted_event.get('component') == component
            and accepted_event.get('kind') == 'dma_edge'
            and accepted.get('address') == expected_address
            and accepted.get('write') is (operation == 'write')
            and transaction['source_component'] == component
            and transaction['channel_id'] == 'dma-memory'
            and transaction['source_sequence'] == expected_sequence
            and type(transaction['execution_id']) is str
            and bool(transaction['execution_id'])
            and transaction['testcase_id'] == expected_dma_testcase_id
            and type(transaction['source_epoch']) is int
            and transaction['source_epoch'] >= 0,
            'expected-error-native-accepted-transaction')
    response = response_event.get('response')
    require(response_event.get('component') == component
            and response_event.get('kind') == 'dma_edge'
            and type(response) is dict
            and response.get('transaction') == transaction
            and type(response.get('error')) is int
            and response.get('error') == 1
            and type(response_event.get('tick')) is int
            and type(accepted_event.get('tick')) is int
            and response_event['tick'] > accepted_event['tick'],
            'expected-error-native-err-response')
    receipt = accepted_event.get('environment_error_receipt')
    require(type(receipt) is dict
            and receipt.get('schema_version') ==
                'f6_dma_environment_error_receipt.v1'
            and receipt.get('owner') == component
            and receipt.get('source_transaction') == transaction
            and type(receipt.get('error')) is int
            and receipt.get('error') == 1
            and receipt.get('target_effect') is False
            and receipt.get('timing') == 'before_target_effect'
            and receipt.get('reason') == 'declared_f6_response_fault'
            and receipt.get('address') == expected_address
            and receipt.get('write') is (operation == 'write')
            and receipt.get('byte_enable') == 15
            and receipt.get('selector') == {
                'case_index': case_index, 'operation': operation,
                'word_index': word_index}
            and receipt.get('execution_binding_sha256') ==
                binding.get('binding_sha256'),
            'expected-error-native-fault-receipt')
    if operation == 'write':
        expected_value = attempt.get('words', [])[word_index]
        require(receipt.get('value') == expected_value,
                'expected-error-write-value')
    require(attempt.get('status_kind') == 'expected_error'
            and attempt.get('expected_error') is True
            and attempt.get('feedback') == [0] * 5,
            'expected-error-attempt-status')

    # The selected request is terminal for this DMA case. Every preceding
    # accepted beat has a successful response and its actual read snapshot or
    # destination commit; the selected beat has no target-side effect.
    case_dma = []
    for row in by_id.values():
        body = row.get('accepted')
        key = body.get('transaction') if type(body) is dict else None
        if (row.get('component') == component and row.get('kind') == 'dma_edge'
                and type(key) is dict
                and key.get('execution_id') == transaction['execution_id']
                and key.get('testcase_id') == transaction['testcase_id']):
            case_dma.append((key.get('source_sequence'), row, body))
    case_dma.sort(key=lambda item: item[0] if type(item[0]) is int else -1)
    require([item[0] for item in case_dma] == list(range(1, expected_sequence + 1))
            and case_dma[-1][1] is accepted_event,
            'expected-error-no-postselection-dma-beat')
    for sequence, row, body in case_dma[:-1]:
        key = body['transaction']
        matches = [candidate for candidate in by_id.values()
            if candidate.get('component') == component
            and candidate.get('kind') == 'dma_edge'
            and type(candidate.get('response')) is dict
            and candidate['response'].get('transaction') == key]
        require(len(matches) == 1 and matches[0]['response'].get('error') == 0,
                'expected-error-prior-success-response')
        if body.get('write') is True:
            effects = [candidate for candidate in by_id.values()
                if candidate.get('kind') == 'memory_write_commit'
                and candidate.get('transaction') == key]
        else:
            effects = [candidate for candidate in by_id.values()
                if candidate.get('kind') == 'memory_read'
                and candidate.get('transaction') == key]
        require(len(effects) == 1, 'expected-error-prior-target-effect')
    if operation == 'write':
        require(attempt.get('word_commits', [None] * 4)[word_index] is None
                and not any(row.get('kind') == 'memory_write_commit'
                    and row.get('transaction') == transaction for row in by_id.values()),
                'expected-error-selected-write-no-commit')
    else:
        require(attempt.get('read_snapshots', [None] * 4)[word_index] is None
                and not any(row.get('kind') == 'memory_read'
                    and row.get('transaction') == transaction for row in by_id.values()),
                'expected-error-selected-read-no-snapshot')

    case_material = attempt.get('case_material')
    observations = case_material.get('observations') if type(case_material) is dict else None
    irq = observations.get('dma.irq_isr_completion') if type(observations) is dict else None
    refs = irq.get('evidence_refs') if type(irq) is dict else None
    require(type(refs) is list and len(refs) == 1
            and type(inventory) is dict and type(inventory.get(refs[0])) is dict
            and inventory[refs[0]].get('kind') == 'dma.irq_isr_completion'
            and inventory[refs[0]].get('outcome') == 'failed'
            and irq.get('status') == 'failed',
            'expected-error-irq-evidence')
    details = inventory[refs[0]].get('details')
    completion = details.get('error_completion') if type(details) is dict else None
    require(type(completion) is dict
            and completion.get('terminal_marker') == 2
            and type(completion.get('actual_status_word')) is int
            and completion['actual_status_word'] &
                contract['dma']['csr']['status_error_mask']
            and completion.get('next_address') ==
                program['slot_base'] + 256 * case_index + 128,
            'expected-error-isr-branch')
    status_event = referenced('status', cpu_component)
    require(status_event.get('component') == cpu_component
            and status_event.get('kind') == 'data_response'
            and status_event.get('address') == contract['control']['base']
            and status_event.get('rdata') == completion.get('actual_status_word')
            and status_event.get('transaction') ==
                completion.get('status_transaction'),
            'expected-error-status-transaction')
    returned = referenced('return', cpu_component)
    boundary_claim = attempt.get('next_fetch')
    boundary_event_id = (boundary_claim.get('event_id')
        if type(boundary_claim) is dict else boundary_claim)
    require(type(boundary_event_id) is int and boundary_event_id > 0
            and (cpu_component, boundary_event_id) in by_id,
            'expected-error-boundary-reference')
    boundary = by_id[(cpu_component, boundary_event_id)]
    if type(boundary_claim) is dict:
        equal(boundary_claim, boundary, 'expected-error-boundary-source-join')
    else:
        require(boundary_claim == boundary.get('event_id'),
                'expected-error-boundary-id-join')
    terminal = referenced('terminal', cpu_component)
    irq_event = referenced('irq', cpu_component)
    require(returned.get('component') == cpu_component
            and returned.get('kind', returned.get('schema_version')) ==
                'native_f6_isr_return.v1'
            and returned.get('case_id') == attempt.get('case_id')
            and returned.get('case_index') == case_index
            and returned.get('execution_binding_sha256') ==
                binding.get('binding_sha256')
            and completion.get('mret_pc') == returned.get('pc_rdata')
            and returned.get('pc_rdata') ==
                firmware['isr']['mret_addresses'][1]
            and completion.get('return_receipt_id') ==
                returned.get('return_receipt_id'),
            'expected-error-mret-return')
    expected_boundary = program['slot_base'] + 256 * case_index + 128
    require(boundary.get('component') == cpu_component
            and boundary.get('kind') == 'native_fetch_boundary'
            and boundary.get('address') == expected_boundary
            and boundary.get('boundary') == 'error_current_island'
            and boundary.get('execution') == returned.get('execution')
            and boundary.get('native_testcase_id') == returned.get('native_testcase_id')
            and boundary.get('reset_epoch') == returned.get('reset_epoch')
            and completion.get('next_fetch') == boundary.get('event_id')
            and completion.get('successor_receipt_id') ==
                returned.get('successor_receipt_id'),
            'expected-error-current-island-boundary')
    take_key = irq_event.get('take_key')
    require(irq_event.get('component') == cpu_component
            and irq_event.get('kind') == 'cpu_external_irq_taken'
            and take_key == completion.get('irq_take_key')
            and type(take_key) is list and len(take_key) == 3
            and take_key[0] == cpu_component
            and take_key[1] == returned.get('reset_epoch')
            and type(take_key[2]) is int and take_key[2] > 0
            and irq_event.get('actual_pre_input') == 1
            and irq_event.get('actual_post_input') == 1
            and irq_event.get('irq_masked_pre') == 0
            and irq_event.get('irq_taken_pre') == 1,
            'expected-error-native-irq-take')
    terminal_address = program['result_base'] + 24 * case_index + 20
    require(terminal.get('component') == cpu_component
            and terminal.get('kind') == 'memory_write'
            and terminal.get('address') == terminal_address
            and terminal.get('value') == 2,
            'expected-error-terminal-store')


def _audit_client_pin(command, identity, sources):
    pins = command.get('executable_pins')
    require(type(pins) is dict and type(pins.get('rfuzz_client')) is dict,
            'client-executable-pin')
    client = pins['rfuzz_client']
    require(type(client.get('path')) is str and Path(client['path']).is_absolute()
            and _hex_sha(client.get('sha256')), 'client-executable-pin-shape')
    client_path = _no_symlink_path(Path(client['path']))
    require(client_path.is_file() and file_hash(client_path) == client['sha256'],
            'client-executable-current-bytes')
    online_client = identity.get('toolchain', {}).get('client', {})
    require(online_client.get('binary_sha256') == client['sha256'],
            'client-session-identity')
    argv = command.get('argv', [])
    if '--client-binary' in argv:
        require(argv.count('--client-binary') == 1, 'client-command-argument')
        selected = Path(argv[argv.index('--client-binary') + 1])
        cwd = Path(command.get('cwd', ROOT))
        if not selected.is_absolute():
            selected = cwd / selected
        require(selected.resolve() == client_path.resolve(), 'client-command-pin')
    relative = None
    try:
        relative = client_path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        pass
    if relative is not None and relative in sources:
        require(sources[relative] == client['sha256'], 'client-frozen-source-pin')


def _audit_f6_prefix_records(prefix, fresh_prefix, layout, firmware,
        runtime_admission, binding, declaration):
    records = prefix['records']
    attempts = prefix['attempts']
    require(type(records) is list and len(records) == len(attempts)
            and bool(records), 'case-prefix-shape')
    run_id = prefix['run_id']
    p = firmware.document()['program_contract']
    if declaration['outcome'] == 'completed':
        require(all(row.get('status_kind') == 'passed' for row in attempts)
                and all(row.get('status') == 'passed' for row in records)
                and prefix.get('feedback') == [1] * 5,
                'completed-case-status-feedback')
    else:
        require(all(row.get('status_kind') == 'passed' for row in attempts[:-1])
                and attempts[-1].get('status_kind') == 'expected_error'
                and all(row.get('status') == 'passed' for row in records[:-1])
                and records[-1].get('status') == 'expected_error'
                and prefix.get('feedback') == [0] * 5,
                'expected-error-prefix-status-feedback')
        selector = declaration['fault_selector']
        require(selector['case_index'] == len(records) - 1,
                'fault-selector-terminal-case')
    path = runtime_admission['logical_path']
    source_ids = [row['source_id'] for row in path['sources']]
    require(len(source_ids) == 4 and len(set(source_ids)) == 4,
            'f6-source-operand-set')
    for index, (record, attempt) in enumerate(zip(records, attempts)):
        case_id = f'{run_id}:case:{index}'
        require(record.get('case_index') == attempt.get('case_index') == index
                and record.get('case_id') == attempt.get('case_id') == case_id
                and record.get('raw8_hex') == attempt.get('raw8_hex')
                and record.get('words') == attempt.get('words')
                and record.get('instruction_address') == attempt.get('instruction_address')
                and record.get('prefix_hex') == attempt.get('prefix_hex')
                and record.get('feedback') == attempt.get('feedback'),
                'case-record-attempt-join')
        raw_hex = record.get('raw8_hex')
        prefix_hex = record.get('prefix_hex')
        require(type(raw_hex) is str and len(raw_hex) == 16
                and type(prefix_hex) is str and len(prefix_hex) == 256,
                'case-raw-prefix-shape')
        raw = bytes.fromhex(raw_hex)
        candidate = layout.decode(raw)
        expected_prefix = firmware.prefix(candidate, case_index=index)
        slot = p['slot_base'] + p['slot_bytes'] * index
        require(raw.hex() == raw_hex and record.get('words') == list(candidate.words)
                and record.get('instruction_address') == slot
                and bytes.fromhex(prefix_hex) == expected_prefix,
                'case-raw44-program-join')
        require(attempt.get('result', {}).get('case_id') == case_id
                and attempt['result'].get('case_index') == index
                and attempt['result'].get('raw8_hex') == raw_hex
                and attempt['result'].get('words') == list(candidate.words)
                and attempt['result'].get('prefix_hex') == prefix_hex
                and attempt['result'].get('feedback') == attempt.get('feedback'),
                'case-result-join')
        if attempt.get('status_kind') == 'passed':
            require(attempt.get('expected_error') is False
                    and attempt.get('feedback') == [1] * 5,
                    'passed-case-feedback')
        else:
            require(declaration['outcome'] == 'expected_error'
                    and index == len(records) - 1
                    and attempt.get('expected_error') is True
                    and attempt.get('feedback') == [0] * 5,
                    'failed-case-feedback')
    require(type(fresh_prefix) is dict
            and fresh_prefix.get('run_id') == run_id
            and fresh_prefix.get('records') == records
            and fresh_prefix.get('attempts') == attempts,
            'fresh-case-identity')


def _audit_f6_receipts(output, prefix, receipt_join, layout, firmware,
        runtime_admission, declaration):
    raw = safe_file(output / 'session', 'receipts.jsonl').read_bytes()
    require(raw.endswith(b'\n'), 'receipt-lines-terminal-newline')
    rows = []
    for line in raw.splitlines():
        require(bool(line), 'receipt-empty-line')
        row = json.loads(line, object_pairs_hook=_reject_duplicate_pairs,
                         parse_constant=_reject_constant)
        require(type(row) is dict, 'receipt-row-shape')
        rows.append(row)
    require(bool(rows), 'receipt-rows-required')
    records = prefix['records']
    p = firmware.document()['program_contract']
    source_ids = [row['source_id'] for row in runtime_admission['logical_path']['sources']]
    cases = []
    seen_slots = set()
    raw_count = 0
    rejected = 0
    case_index = 0
    for row in rows:
        require(row.get('run_id') == prefix['run_id']
                and row.get('flow_id') == 'F6'
                and row.get('path_id') == runtime_admission['logical_path']['path_id']
                and row.get('source_id') == source_ids[0],
                'receipt-run-path-source')
        slot_key = (row.get('buffer_id'), row.get('slot'))
        require(all(type(value) is int and value >= 0 for value in slot_key)
                and slot_key not in seen_slots, 'receipt-slot-identity')
        seen_slots.add(slot_key)
        hex_records = row.get('online_raw_records_hex')
        require(type(hex_records) is list and all(type(value) is str for value in hex_records),
                'receipt-raw-record-list')
        wire = tuple(bytes.fromhex(value) for value in hex_records)
        require(all(len(value) == 8 for value in wire)
                and sha256(b''.join(wire)).hexdigest() == row.get('raw_sha256'),
                'receipt-raw-record-hash')
        raw_count += len(wire)
        online_source = row.get('online_source')
        require(type(online_source) is dict
                and online_source.get('schema_version') == 'compiled_F6_sequence.v1'
                and online_source.get('source_ids') == source_ids,
                'receipt-decoder-source')
        projected = online_source.get('candidates')
        require(type(projected) is list, 'receipt-decoded-candidates')
        if row.get('status') == 'input_invalid':
            require(row.get('coverage_hex') == bytes(5).hex()
                    and row.get('case_id') is None and projected == []
                    and row.get('candidate_disposition') == 'rejected',
                    'receipt-preflight-refusal')
            if len(wire) != 1:
                require(row.get('rejection', {}).get('code') == 'record-count',
                        'receipt-record-count-refusal')
            else:
                try:
                    layout.decode(wire[0])
                except ValueError:
                    pass
                else:
                    raise ValueError('compiled-F6-saved-audit-receipt-invalid-was-legal')
                require(row.get('rejection', {}).get('code') == 'candidate',
                        'receipt-invalid-candidate-refusal')
            rejected += 1
            continue
        require(len(wire) == 1 and len(projected) == 1,
                'receipt-one-candidate')
        candidate = layout.decode(wire[0])
        record = records[case_index]
        case_id = f'{prefix["run_id"]}:case:{case_index}'
        prefix_bytes = firmware.prefix(candidate, case_index=case_index)
        candidate_doc = dict(schema_version='compiled_F6_candidate.v1',
            raw8_hex=candidate.raw.hex(), words=list(candidate.words),
            case_id=case_id, case_index=case_index,
            instruction_address=p['slot_base'] + 256 * case_index,
            prefix_hex=prefix_bytes.hex(),
            path_id=runtime_admission['logical_path']['path_id'],
            source_ids=source_ids)
        equal(projected[0], candidate_doc, 'receipt-candidate-decoder')
        require(record.get('case_id') == case_id
                and record.get('raw8_hex') == candidate.raw.hex()
                and record.get('words') == list(candidate.words)
                and record.get('prefix_hex') == prefix_bytes.hex()
                and row.get('case_id') == case_id,
                'receipt-case-program-crosswalk')
        status = row.get('status')
        expected_error = declaration['outcome'] == 'expected_error' and case_index == len(records)-1
        if expected_error:
            require(status == 'execution_failed'
                    and row.get('coverage_hex') == bytes(5).hex(),
                    'receipt-expected-error-zero-feedback')
        else:
            require(status == 'certified'
                    and row.get('coverage_hex') == bytes([1] * 5).hex(),
                    'receipt-success-feedback')
        require(row.get('candidate_disposition') == 'admitted'
                and row.get('wire_cycle_count') == 1
                and row.get('candidate_count') == 1,
                'receipt-admission-counts')
        cases.append(dict(case_id=case_id, raw8_hex=candidate.raw.hex(),
            words=list(candidate.words), prefix_hex=prefix_bytes.hex(),
            source_ids=source_ids,
            instruction_address=p['slot_base'] + 256 * case_index))
        case_index += 1
    require(case_index == len(records), 'receipt-case-count')
    scope = 'full' if declaration['outcome'] == 'completed' else 'failed_prefix_full'
    expected_join = dict(schema_version='compiled_F6_receipt_join.v1', status='ok',
        scope=scope, run_id=prefix['run_id'],
        path_id=runtime_admission['logical_path']['path_id'], source_id=source_ids[0],
        source_ids=source_ids,
        execution_binding_sha256=prefix['execution_binding_sha256'],
        receipts_sha256=sha256(raw).hexdigest(), rows=len(rows),
        case_count=len(cases), raw_record_count=raw_count,
        rejected_tests=rejected, wire_record_bytes=8, candidate_bytes=8,
        cases=cases)
    equal(receipt_join, expected_join, 'receipt-join-reprojection')


def _audit_f6_fresh(prefix, replay, fresh_prefix, fresh_events, fresh_audit,
        verification, scope, completed):
    require(type(replay) is dict and replay.get('matches') is True
            and replay.get('first_difference') is None
            and replay.get('verification_scope') == scope
            and type(replay.get('actual_event_count')) is int
            and replay.get('actual_event_count') == len(fresh_events)
            and type(fresh_events) is list and bool(fresh_events),
            'fresh-replay-summary')
    from myfuzz.integration.compiled_f6 import _normalized_f6_prefix
    equal(_normalized_f6_prefix(prefix), _normalized_f6_prefix(fresh_prefix),
          'fresh-prefix-reprojection')
    require(fresh_prefix.get('actual_events') == fresh_events,
            'fresh-events-prefix-join')
    require(type(fresh_audit) is dict and fresh_audit.get('closed') is True
            and replay.get('execution_audit') == fresh_audit
            and fresh_prefix.get('original_execution_audit') == fresh_audit
            and replay.get('original_execution_audit') ==
                prefix.get('original_execution_audit')
            and type(prefix.get('original_execution_audit')) is dict
            and prefix['original_execution_audit'].get('closed') is True,
            'fresh-execution-audit-join')
    require(type(prefix.get('original_build')) is dict
            and type(fresh_prefix.get('original_build')) is dict
            and replay.get('actual_event_count') == len(fresh_prefix['actual_events']),
            'fresh-build-event-material')
    expected = dict(schema_version='fresh_verification.v1', matches=True,
        first_difference=None, verification_scope=scope, completed=completed,
        expected_semantic_hash=prefix.get('semantic_hash'),
        actual_semantic_hash=fresh_prefix.get('semantic_hash'),
        record_count=len(prefix['records']), event_count=len(fresh_events),
        replay_entry='myfuzz.integration.compiled_f6_rfuzz:run_compiled_f6_rfuzz_session')
    equal(verification, expected, 'fresh-verification-reprojection')


def _audit_f6_typed(prefix, fresh_prefix, typed_results, typed_evidence,
        binding, completed, contract, artifacts, firmware_document):
    from myfuzz.scenario.f6_execution_contract import EXPECTATION_IDS
    from myfuzz.scenario.f6_assertion_evidence import (
        validate_f6_assertion_evidence, f6_case_feedback)
    material = prefix.get('assertion_material')
    require(type(material) is dict
            and type(material.get('assertions')) is dict
            and type(material.get('assertion_evidence')) is dict,
            'typed-prefix-material')
    core = material['assertion_evidence']
    require(core.get('schema_version') == 'compiled_F6_assertion_evidence.v1'
            and core.get('cases') == [attempt.get('case_material')
                for attempt in prefix['attempts']],
            'typed-attempt-inventory')
    _verify_f6_expectation_attempt_refs(prefix['attempts'],
        contract['cpu']['instance_id'], contract['dma']['instance_id'])
    raw_event_index = _verify_f6_raw_evidence_trace(prefix, contract,
        binding, artifacts, firmware_document)
    _verify_f6_case_joins(prefix, contract, raw_event_index, None,
                          prefix['actual_events'])
    _reproject_f6_cpu_configuration(prefix, raw_event_index, contract)
    _reproject_f6_word_transfer(prefix, raw_event_index, contract, binding)
    _reproject_f6_irq_isr(prefix, raw_event_index, contract, binding,
                          artifacts=artifacts)
    _reproject_f6_cross_component_edges(prefix, raw_event_index, contract,
                                        binding, artifacts=artifacts)
    assertion_scope = _f6_assertion_binding_scope(binding)
    rebuilt = validate_f6_assertion_evidence(material,
        execution_binding=assertion_scope, case_inventory=core['cases'])
    equal(material['assertions'], rebuilt['assertions'],
          'typed-assertion-results-rebuild')
    expected_outer = dict(execution_binding=binding,
        path_id=binding['path_id'], run_id=binding['run_id'], cases=core['cases'])
    equal(typed_evidence, expected_outer, 'typed-evidence-binding')
    equal(typed_results, material['assertions'], 'typed-results-prefix-join')
    fresh_material = fresh_prefix.get('assertion_material')
    require(type(fresh_material) is dict
            and type(fresh_material.get('assertion_evidence')) is dict,
            'fresh-typed-material')
    require([case.get('case_id') for case in fresh_material['assertion_evidence'].get('cases', [])]
            == [case.get('case_id') for case in core['cases']],
            'fresh-typed-case-bijection')
    fresh_raw_event_index = _verify_f6_raw_evidence_trace(fresh_prefix, contract,
        binding, artifacts, firmware_document)
    _verify_f6_case_joins(fresh_prefix, contract, fresh_raw_event_index, None,
                          fresh_prefix['actual_events'])
    _reproject_f6_cpu_configuration(fresh_prefix, fresh_raw_event_index,
                                    contract)
    _reproject_f6_word_transfer(fresh_prefix, fresh_raw_event_index,
                                contract, binding)
    _reproject_f6_irq_isr(fresh_prefix, fresh_raw_event_index, contract,
                          binding, artifacts=artifacts)
    _reproject_f6_cross_component_edges(fresh_prefix, fresh_raw_event_index,
                                        contract, binding, artifacts=artifacts)
    if completed:
        require(all(row.get('status') == 'passed' for case in typed_results.get('cases', [])
                    for row in case.get('assertions', [])),
                'typed-completed-all-expectations')
    else:
        require(any(row.get('status') != 'passed'
                    for case in typed_results.get('cases', [])
                    for row in case.get('assertions', [])),
                'typed-error-has-observed-failure')
    material_for_feedback = dict(assertions=typed_results,
        assertion_evidence=core)
    for index, attempt in enumerate(prefix['attempts']):
        expected_feedback = list(f6_case_feedback(material_for_feedback,
            case_ids=(attempt['case_id'],)))
        require(attempt.get('feedback') == expected_feedback,
                'typed-case-feedback-reprojection')
        if index < len(prefix['attempts']) - 1 or completed:
            require(expected_feedback == [1] * len(EXPECTATION_IDS),
                    'typed-passed-feedback')
        else:
            require(expected_feedback == [0] * len(EXPECTATION_IDS),
                    'typed-failed-feedback-zero')
    return raw_event_index


def _reproject_f6_cpu_configuration(prefix, local_by_id, contract):
    """Rebuild saved CPU-configuration outcomes from this prefix's raw rows."""
    from myfuzz.integration.compiled_f6_saved_semantics import (
        project_saved_cpu_configuration)

    attempts = prefix.get('attempts')
    events = prefix.get('actual_events')
    material = prefix.get('assertion_material')
    evidence = (material.get('assertion_evidence')
                if type(material) is dict else None)
    cases = evidence.get('cases') if type(evidence) is dict else None
    require(type(attempts) is list and type(events) is list
            and type(local_by_id) is dict and type(cases) is list
            and len(attempts) == len(cases),
            'saved-cpu-configuration-projection-inventory')
    for attempt, case in zip(attempts, cases):
        require(type(attempt) is dict and type(case) is dict
                and attempt.get('case_id') == case.get('case_id')
                and attempt.get('case_material') == case,
                'saved-cpu-configuration-case-join')
        inventory = case.get('evidence_inventory')
        require(type(inventory) is dict,
                'saved-cpu-configuration-evidence-inventory')
        rows = [row for row in inventory.values()
            if type(row) is dict and row.get('kind') == 'dma.cpu_configuration']
        require(len(rows) == 1,
                'saved-cpu-configuration-evidence-cardinality')
        saved = rows[0]
        outcome = saved.get('outcome')
        require(outcome in ('passed', 'failed', 'missing'),
                'saved-cpu-configuration-outcome-shape')
        projection = project_saved_cpu_configuration(attempt=attempt,
            contract=contract, events=events, local_by_id=local_by_id)
        require(type(projection) is dict
                and projection.get('kind') == 'dma.cpu_configuration'
                and projection.get('outcome') in ('passed', 'failed', 'missing'),
                'saved-cpu-configuration-projection-shape')
        require(projection['outcome'] == outcome,
                'saved-cpu-configuration-semantic-reprojection')
        observations = case.get('observations')
        observation = (observations.get('dma.cpu_configuration')
                       if type(observations) is dict else None)
        require(type(observation) is dict
                and observation.get('status') == projection['outcome'],
                'saved-cpu-configuration-observation-reprojection')


def _reproject_f6_word_transfer(prefix, local_by_id, contract, binding):
    """Rebuild saved four-word transfer outcomes from this prefix's raw rows."""
    from myfuzz.integration.compiled_f6_saved_semantics import (
        project_saved_word_transfer)

    attempts = prefix.get('attempts')
    events = prefix.get('actual_events')
    material = prefix.get('assertion_material')
    evidence = (material.get('assertion_evidence')
                if type(material) is dict else None)
    cases = evidence.get('cases') if type(evidence) is dict else None
    require(type(attempts) is list and type(events) is list
            and type(local_by_id) is dict and type(cases) is list
            and len(attempts) == len(cases),
            'saved-word-transfer-projection-inventory')
    for attempt, case in zip(attempts, cases):
        require(type(attempt) is dict and type(case) is dict
                and attempt.get('case_id') == case.get('case_id')
                and attempt.get('case_material') == case,
                'saved-word-transfer-case-join')
        inventory = case.get('evidence_inventory')
        require(type(inventory) is dict,
                'saved-word-transfer-evidence-inventory')
        rows = [row for row in inventory.values()
            if type(row) is dict and row.get('kind') == 'dma.word_transfer_join']
        require(len(rows) == 1,
                'saved-word-transfer-evidence-cardinality')
        saved = rows[0]
        outcome = saved.get('outcome')
        require(outcome in ('passed', 'failed', 'missing'),
                'saved-word-transfer-outcome-shape')
        projection = project_saved_word_transfer(attempt=attempt,
            contract=contract, binding=binding, events=events,
            local_by_id=local_by_id)
        require(type(projection) is dict
                and projection.get('kind') == 'dma.word_transfer_join'
                and projection.get('outcome') in ('passed', 'failed', 'missing'),
                'saved-word-transfer-projection-shape')
        require(projection['outcome'] == outcome,
                'saved-word-transfer-semantic-reprojection')
        observations = case.get('observations')
        observation = (observations.get('dma.word_transfer_join')
                       if type(observations) is dict else None)
        require(type(observation) is dict
                and observation.get('status') == projection['outcome'],
                'saved-word-transfer-observation-reprojection')


def _reproject_f6_irq_isr(prefix, local_by_id, contract, binding, *,
                          artifacts=None):
    """Rebuild saved IRQ/ISR outcomes from this prefix's raw Runner rows."""
    from myfuzz.integration.compiled_f6_saved_semantics import (
        project_saved_irq_isr)

    expectation = 'dma.irq_isr_completion'
    attempts = prefix.get('attempts')
    events = prefix.get('actual_events')
    material = prefix.get('assertion_material')
    evidence = (material.get('assertion_evidence')
                if type(material) is dict else None)
    cases = evidence.get('cases') if type(evidence) is dict else None
    require(type(attempts) is list and type(events) is list
            and type(local_by_id) is dict and type(cases) is list
            and len(attempts) == len(cases),
            'saved-irq-isr-projection-inventory')
    for attempt, case in zip(attempts, cases):
        require(type(attempt) is dict and type(case) is dict
                and attempt.get('case_id') == case.get('case_id')
                and attempt.get('case_material') == case,
                'saved-irq-isr-case-join')
        inventory = case.get('evidence_inventory')
        require(type(inventory) is dict,
                'saved-irq-isr-evidence-inventory')
        rows = [(reference, row) for reference, row in inventory.items()
            if type(row) is dict and row.get('kind') == expectation]
        require(len(rows) == 1,
                'saved-irq-isr-evidence-cardinality')
        reference, saved = rows[0]
        outcome = saved.get('outcome')
        require(outcome in ('passed', 'failed', 'missing'),
                'saved-irq-isr-outcome-shape')
        expected_scope = dict(_f6_assertion_binding_scope(binding),
                              case_id=case['case_id'],
                              expectation_id=expectation)
        require(saved.get('scope') == expected_scope,
                'saved-irq-isr-evidence-scope')
        projection = project_saved_irq_isr(attempt=attempt,
            contract=contract, binding=binding, events=events,
            local_by_id=local_by_id,
            cpu_artifact=(artifacts.get(contract['cpu']['instance_id'])
                if type(artifacts) is dict else None),
            dma_irq_runtime_name=_f6_dma_irq_runtime_name(artifacts, contract))
        require(type(projection) is dict
                and projection.get('kind') == expectation
                and projection.get('outcome') in ('passed', 'failed', 'missing'),
                'saved-irq-isr-projection-shape')
        require(projection['outcome'] == outcome,
                'saved-irq-isr-semantic-reprojection')
        observations = case.get('observations')
        observation = (observations.get(expectation)
                       if type(observations) is dict else None)
        require(type(observation) is dict
                and observation.get('status') == projection['outcome']
                and reference in observation.get('evidence_refs', []),
                'saved-irq-isr-observation-reprojection')


def _reproject_f6_cross_component_edges(prefix, local_by_id, contract, binding,
                                         *, artifacts=None):
    """Rebuild cross-component edge evidence from each saved Runner archive.

    The cross expectation has its own declared-edge refs. It is intentionally
    not validated as a union of the CPU, word-transfer, and IRQ expectation
    refs: those are separate observations with separate evidence inventories.
    """
    from myfuzz.integration.compiled_f6_saved_semantics import (
        project_saved_cpu_configuration, project_saved_word_transfer,
        project_saved_irq_isr, project_saved_cross_component_edges)

    expectation = 'cross_component.declared_edge_hops'
    attempts = prefix.get('attempts')
    events = prefix.get('actual_events')
    material = prefix.get('assertion_material')
    evidence = (material.get('assertion_evidence')
                if type(material) is dict else None)
    cases = evidence.get('cases') if type(evidence) is dict else None
    require(type(attempts) is list and type(events) is list
            and type(local_by_id) is dict and type(cases) is list
            and len(attempts) == len(cases),
            'saved-cross-edge-projection-inventory')

    def projection_status(row, kind, label):
        require(type(row) is dict and row.get('kind') == kind
                and row.get('outcome') in ('passed', 'failed', 'missing'),
                'saved-cross-edge-'+label+'-projection-shape')
        return row['outcome']

    def reduce_outcomes(outcomes):
        return ('failed' if 'failed' in outcomes else
                'missing' if 'missing' in outcomes else 'passed')

    for attempt, case in zip(attempts, cases):
        require(type(attempt) is dict and type(case) is dict
                and attempt.get('case_id') == case.get('case_id')
                and attempt.get('case_material') == case,
                'saved-cross-edge-case-join')
        inventory = case.get('evidence_inventory')
        observations = case.get('observations')
        require(type(inventory) is dict and type(observations) is dict,
                'saved-cross-edge-case-evidence')
        rows = [(reference, row) for reference, row in inventory.items()
            if type(row) is dict and row.get('kind') == expectation]
        observation = observations.get(expectation)
        require(type(observation) is dict
                and observation.get('status') in ('passed', 'failed', 'missing')
                and type(observation.get('evidence_refs')) is list,
                'saved-cross-edge-observation-shape')

        # Missing with no inventory row is representable by the shared typed
        # evidence schema. Keep that state only for legacy/minimal test
        # material that has no execution path to project. A production F6
        # binding always carries runtime_path_admission and is reprojected.
        has_projection_context = (type(binding) is dict
            and type(binding.get('runtime_path_admission')) is dict
            and binding['runtime_path_admission'].get('schema_version') ==
                'compiled_F6_runtime_path_admission.v1')
        if not rows and not has_projection_context:
            require(observation['status'] == 'missing'
                    and observation['evidence_refs'] == [],
                    'saved-cross-edge-unprojected-claim')
            continue
        require(len(rows) == 1,
                'saved-cross-edge-evidence-cardinality')

        cpu_id = contract['cpu']['instance_id']
        cpu_artifact = None
        if has_projection_context:
            require(type(artifacts) is dict and cpu_id in artifacts,
                'saved-cross-edge-bound-cpu-artifact')
            cpu_artifact = artifacts[cpu_id]

        configuration = project_saved_cpu_configuration(attempt=attempt,
            contract=contract, events=events, local_by_id=local_by_id)
        words = project_saved_word_transfer(attempt=attempt,
            contract=contract, binding=binding, events=events,
            local_by_id=local_by_id)
        irq = project_saved_irq_isr(attempt=attempt, contract=contract,
            binding=binding, events=events, local_by_id=local_by_id,
            cpu_artifact=(artifacts.get(cpu_id) if type(artifacts) is dict else None),
            dma_irq_runtime_name=_f6_dma_irq_runtime_name(artifacts, contract))
        declared = project_saved_cross_component_edges(attempt=attempt,
            contract=contract, binding=binding, events=events,
            local_by_id=local_by_id, cpu_artifact=cpu_artifact)
        component_outcomes = {
            'configuration': projection_status(configuration,
                'dma.cpu_configuration', 'configuration'),
            'words': projection_status(words, 'dma.word_transfer_join', 'words'),
            'irq': projection_status(irq, 'dma.irq_isr_completion', 'irq'),
        }
        declared_outcome = projection_status(declared, expectation, 'declared')
        declared_details = declared.get('details')
        require(type(declared_details) is dict
                and type(declared_details.get('edges')) is list
                and len(declared_details['edges']) == 4
                and [(row.get('rule_index'), row.get('prerequisite_index'))
                    for row in declared_details['edges']]
                    == [(index, 0) for index in range(4)],
                'saved-cross-edge-declared-edge-inventory')
        expected_outcome = reduce_outcomes(
            list(component_outcomes.values()) + [declared_outcome])

        reference, saved = rows[0]
        expected_scope = dict(_f6_assertion_binding_scope(binding),
            case_id=case['case_id'], expectation_id=expectation)
        require(saved.get('scope') == expected_scope,
                'saved-cross-edge-evidence-scope')
        require(saved.get('outcome') == expected_outcome,
                'saved-cross-edge-semantic-reprojection')
        require(observation['status'] == expected_outcome
                and reference in observation['evidence_refs'],
                'saved-cross-edge-observation-reprojection')

        details = saved.get('details')
        require(type(details) is dict
                and details.get('declared_edge_projection') == declared_details
                and details.get('edges') == declared_details.get('edges'),
                'saved-cross-edge-declared-projection-reprojection')
        saved_components = details.get('component_evidence')
        require(type(saved_components) is dict
                and set(saved_components) == set(component_outcomes)
                and all(type(saved_components[name]) is dict
                    and saved_components[name].get('status') == status
                    for name, status in component_outcomes.items()),
                'saved-cross-edge-component-outcome-reprojection')

        # Every independently selected graph-edge Observer ref must also be
        # present in this cross expectation's own raw refs and raw evidence.
        # Resolve it back to its Runner row here; the generic trace auditor
        # then authenticates the full Observer-to-Runner projection.
        raw_references = details.get('raw_references')
        raw_evidence = details.get('raw_evidence')
        require(type(raw_references) is list and type(raw_evidence) is list,
                'saved-cross-edge-raw-inventory-shape')
        require(all(type(row) is dict
                and set(row) == {'component', 'event_id', 'kind'}
                for row in raw_references),
                'saved-cross-edge-reference-row-shape')
        saved_reference_ids = {(row.get('component'), row.get('event_id'),
            row.get('kind')) for row in raw_references}
        saved_evidence_ids = {(row.get('component'), row.get('event_id'),
            row.get('kind', row.get('schema_version')))
            for row in raw_evidence if type(row) is dict}
        expected_reference_ids = set()
        projected_details = declared_details
        for edge_reference in projected_details.get('raw_references', []):
            require(type(edge_reference) is dict,
                    'saved-cross-edge-projected-reference-shape')
            component = edge_reference.get('component')
            local_id = edge_reference.get('event_id')
            kind = edge_reference.get('kind')
            require(type(component) is str and type(local_id) is int
                    and local_id > 0 and type(kind) is str,
                    'saved-cross-edge-projected-reference-identity')
            key = (component, local_id)
            local_row = local_by_id.get(key)
            require(type(local_row) is dict
                    and local_row.get('component') == component
                    and local_row.get('event_id') == local_id
                    and local_row.get('kind', local_row.get('schema_version')) == kind,
                    'saved-cross-edge-projected-observer-reference')
            runner_id = local_row.get('runner_event_id')
            require(type(runner_id) is int and runner_id > 0,
                    'saved-cross-edge-projected-runner-link')
            if 'runner_event_id' in edge_reference:
                require(edge_reference['runner_event_id'] == runner_id,
                        'saved-cross-edge-projected-runner-reference')
            require((component, local_id, kind) in saved_reference_ids
                    and (component, local_id, kind) in saved_evidence_ids,
                    'saved-cross-edge-reference-closure')
            expected_reference_ids.add((component, local_id, kind))

        # The original instruction service row is represented by one exact
        # Observer projection. Source-admission remains nested in the declared
        # projection and is independently reconstructed from actual_events.
        instruction_rows = [row for row in projected_details.get('raw_evidence', [])
            if type(row) is dict and row.get('kind') == 'instruction_source']
        require(len(instruction_rows) <= 1,
                'saved-cross-edge-instruction-source-cardinality')
        instruction_refs = [row for row in raw_references
            if type(row) is dict and row.get('kind') == 'instruction_source']
        if instruction_rows:
            runner_row = instruction_rows[0]
            runner_id = runner_row.get('event_id')
            component = runner_row.get('component', contract['cpu']['instance_id'])
            local_rows = [row for (owner, _event_id), row in local_by_id.items()
                if owner == component and type(row) is dict
                and row.get('kind', row.get('schema_version')) == 'instruction_source'
                and row.get('runner_event_id') == runner_id]
            require(len(local_rows) == 1,
                    'saved-cross-edge-instruction-source-observer')
            local_row = local_rows[0]
            local_id = local_row.get('event_id')
            expected_reference = (component, local_id, 'instruction_source')
            require(len(instruction_refs) == 1
                    and (instruction_refs[0].get('component'),
                        instruction_refs[0].get('event_id'),
                        instruction_refs[0].get('kind')) == expected_reference
                    and expected_reference in saved_evidence_ids,
                    'saved-cross-edge-instruction-source-reference')
            expected_reference_ids.add(expected_reference)
        else:
            require(not instruction_refs,
                    'saved-cross-edge-unselected-instruction-source-reference')
        require(len(raw_references) == len(saved_reference_ids)
                and saved_reference_ids == expected_reference_ids,
                'saved-cross-edge-exact-reference-inventory')
        require(len(raw_evidence) == len(saved_evidence_ids)
                and saved_evidence_ids == expected_reference_ids,
                'saved-cross-edge-exact-raw-evidence-inventory')


def _f6_assertion_binding_scope(binding):
    """Project the closed execution binding into the six assertion scope keys."""
    from myfuzz.scenario.f6_assertion_evidence import _SCOPE_KEYS, _binding_scope

    if type(binding) is dict and set(_SCOPE_KEYS) <= set(binding):
        return _binding_scope(binding)
    require(type(binding) is dict
            and binding.get('schema_version') ==
                'compiled_F6_execution_binding.v1'
            and type(binding.get('runtime_path_admission')) is dict
            and type(binding['runtime_path_admission'].get('logical_path')) is dict,
            'assertion-scope-execution-binding-shape')
    logical_path = binding['runtime_path_admission']['logical_path']
    scope = dict(compiled_document_sha256=binding.get('compiled_document_sha256'),
        binding_sha256=binding.get('binding_sha256'),
        path_sha256=sha256(canonical(logical_path)).hexdigest(),
        execution_binding_sha256=binding.get('binding_sha256'),
        path_id=binding.get('path_id'), run_id=binding.get('run_id'))
    return _binding_scope(scope)


def _f6_dma_irq_runtime_name(artifacts, contract):
    """Resolve the source-admitted DMA IRQ physical sample key."""
    irq = contract.get('irq') if type(contract) is dict else None
    if artifacts is None or artifacts == {}:
        # Standalone synthetic auditor tests have no admitted artifact map.
        return irq.get('producer_port') if type(irq) is dict else None
    require(type(irq) is dict, 'saved-irq-runtime-export-contract')
    port = irq.get('producer_port')
    dma_id = contract['dma']['instance_id']
    require(type(artifacts) is dict and dma_id in artifacts,
            'saved-irq-runtime-export-artifact')
    artifact = artifacts[dma_id]
    runtime = getattr(artifact, 'runtime_document', None)
    exports = runtime.get('physical_exports') if type(runtime) is dict else None
    rows = [row for row in exports if type(row) is dict
        and row.get('physical_port') == port
        and row.get('endpoint_id') == irq.get('producer_endpoint_id')
        and row.get('direction') == 'output' and row.get('role') == 'irq'
        and row.get('width') == 1 and row.get('disposition') == 'functional'] \
        if type(exports) in (list, tuple) else []
    require(len(rows) == 1 and type(rows[0].get('runtime_name')) is str
            and bool(rows[0]['runtime_name']),
            'saved-irq-runtime-export-identity')
    return rows[0]['runtime_name']


def verify_saved_f6(output, *, invocation):
    """Verify one frozen F6 attempt; the outcome comes only from its declaration."""
    output = Path(output)
    invocation = Path(invocation)
    declaration = _declaration(invocation)
    sources, _outputs, _command, _terminal, _process = _verify_external(
        output, invocation, declaration)
    if declaration['outcome'] == 'refusal':
        return _audit_refusal(output, invocation, declaration, sources)
    return _audit_attempt(output, invocation, declaration, sources)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--invocation', required=True)
    arguments = parser.parse_args(argv)
    result = verify_saved_f6(Path(arguments.output),
                             invocation=Path(arguments.invocation))
    print(json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False,
                     allow_nan=False))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, TypeError, ValueError, KeyError, IndexError,
            json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
