#!/usr/bin/env python3
"""Line/block DUT coverage plus a comparability document for a saved prefix.

The measurement reuses the existing offline coverage tooling instead of
inventing a metric:

* :func:`scripts.compare_local_harness_coverage.load_run` re-verifies a saved
  measurement (file hashes, original cache identity, instrumentation, replay
  protocol/ticks) and decodes every Verilator line/block point, including the
  zeros;
* :func:`scripts.measure_local_coverage.select_recorded_session` validates the
  saved component command prefix and binds it to the measured build digest;
* the saved ``commands.txt``/``replies.txt`` must still equal that prefix.

Nothing is built, replayed or simulated here: the numbers describe an existing
saved replay.  When any input is missing or does not match, the result is
``unavailable`` with the exact reason and *no* coverage number -- a missing
measurement is never reported as zero and never reported as a pass.

Two comparability modes exist and neither invents a second number:

* ``own-original-fresh-prefix`` compares a run's *own* saved ``original`` and
  ``fresh`` prefixes (same config, identical recorded commands/replies/local
  ticks modulo the execution nonce, both exit 0).  It says the recorded prefix
  is reproducible on a separate invocation; it does *not* compare coverage,
  because only the original prefix was instrumented.
* the existing baseline mode compares point identities of two saved
  measurements and keeps seed/budget/fairness unknown.

Either comparability document is deliberately weak, and one pair of replays is
not evidence of tool superiority.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'src'))

SCHEMA = 'directed_new_path_coverage.v1'
CONTRACT_SCHEMA = 'coverage_comparison_contract.v1'
CONTRACT_ID = 'dut-line-block/offline-recorded-prefix.v1'
BUDGET_RECORD_SCHEMA = 'offline_replay_budget.v1'
_CONTRACT_RULES = (
    'same DUT: identical declared structural-build source files '
    '(dut.source_files_sha256) for the same component',
    'same point set: identical saved point map (dut.point_set_sha256) and canonical '
    'denominator (dut.denominator_sha256)',
    'same workload: identical recorded command sequence, execution nonce normalised '
    '(workload.commands_sha256), same command count and local ticks',
    'same budget: identical replay_budget and executed command count; a search budget '
    'is not represented by an offline replay and stays unknown',
    'same explicit coverage mode: offline recorded-prefix replay on both sides '
    '(online and fixed-time coverage are false)',
    'both sides instrumented: a prefix without its own instrumented replay has no '
    'covered/total and is never compared',
)
_CONTRACT_LIMITATIONS = (
    'A contract match says the two numbers describe the same DUT points, workload '
    'and replay budget in the same offline mode.',
    'It does not establish equal search budgets, seeds, process independence or '
    'statistical superiority.',
    'Recorded replies are observations; they are compared as a condition but they '
    'are not the workload identity.',
)
_REQUIRED_MEASUREMENT_FILES = ('coverage.json', 'coverage.dat', 'commands.txt',
                               'replies.txt', 'obj/harness',
                               'inputs/generated/driver.cpp',
                               'inputs/generated/artifact.json')
# ``local-command-trace.json`` is the aggregated trace; ``local_commands.json``
# is sometimes the same document and sometimes the raw per-component list.
_TRACE_NAMES = ('local-command-trace.json', 'local-commands.json', 'local_commands.json')


def _unavailable(reason, *, missing=(), inputs=None, searched=()):
    return {
        'schema_version': SCHEMA,
        'status': 'unavailable',
        'reason': reason,
        'missing_inputs': list(missing),
        'searched_inputs': list(searched),
        'inputs': inputs or {},
        'coverage': None,
        'comparability': None,
        'online': False,
        'fixed_time_coverage': False,
        'coverage_auc_available': False,
        'native_authority': False,
        'limitations': ['Unavailable evidence never substitutes for a measured number.',
                        'No build, replay or DUT simulation was performed by this script.'],
    }


def _trace_candidates(directory):
    """Yield saved trace candidates, the directory itself first."""
    directory = Path(directory)
    roots = [directory]
    if directory.is_dir():
        roots.extend(sorted(path for path in directory.iterdir() if path.is_dir()))
    for base in roots:
        for name in _TRACE_NAMES:
            candidate = base / name
            if candidate.is_file():
                yield candidate


def resolve_trace(run):
    """Accept the saved run directory or the trace path itself.

    A run directory can hold both the aggregated trace document and the raw
    per-component list; the first candidate that parses to a JSON object or
    array is returned.  Shape errors are reported later, by :func:`load_trace`,
    so that an existing but malformed trace still yields an exact reason.
    """
    path = Path(run)
    if path.is_file():
        return path
    for candidate in _trace_candidates(path):
        try:
            document = json.loads(candidate.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            continue
        if isinstance(document, (dict, list)):
            return candidate
    return None


def load_trace(path):
    """Normalize a trace document: ``local_command_trace.v1`` or a row list.

    The raw per-component list is the same row shape as ``sessions``; wrapping
    it keeps a single verifier for both layouts instead of a second parser.
    """
    document = json.loads(Path(path).read_text(encoding='utf-8'))
    if isinstance(document, dict):
        return document
    if not isinstance(document, list) or not document:
        raise ValueError('invalid-local-command-trace:document-shape')
    sessions = {}
    for row in document:
        if not isinstance(row, dict):
            raise ValueError('invalid-local-command-trace:session-row')
        component = row.get('component')
        if not isinstance(component, str) or not component or component in sessions:
            raise ValueError('invalid-local-command-trace:session-component')
        sessions[component] = row
    return {'schema_version': 'local_command_trace.v1', 'sessions': sessions}


def _missing_measurement_files(directory):
    return [name for name in _REQUIRED_MEASUREMENT_FILES
            if not (Path(directory) / name).is_file()]


def _file_breakdown(points):
    files = {}
    for identity, count in points.items():
        relative = json.loads(identity).get('f')
        row = files.setdefault(relative, {'total': 0, 'covered': 0})
        row['total'] += 1
        row['covered'] += 1 if count > 0 else 0
    return {name: row for name, row in sorted(files.items())}


def _kind_breakdown(points):
    """Split Verilator point kinds without renaming them (line, branch, ...)."""
    kinds = {}
    for identity, count in points.items():
        kind = json.loads(identity).get('t')
        kind = kind if isinstance(kind, str) and kind else 'unknown'
        row = kinds.setdefault(kind, {'total': 0, 'covered': 0})
        row['total'] += 1
        row['covered'] += 1 if count > 0 else 0
    return {name: row for name, row in sorted(kinds.items())}


def _point_identities_digest(points):
    """SHA256 of a canonical point-identity set.

    The identities were already normalised against ``inputs/`` by the verified
    loader, so the digest does not depend on the absolute build directory.
    """
    canonical = json.dumps(sorted(points), separators=(',', ':'), ensure_ascii=True)
    return sha256(canonical.encode('ascii')).hexdigest()


def _tool_identity(cache):
    """The pinned Verilator identity from the verified cache manifest.

    Only the version and the executable hash are published: the absolute host
    path would make the document host-specific without adding evidence, and the
    manifest identity is already bound to ``build_digest``.
    """
    manifest = json.loads((Path(cache) / 'manifest.json').read_text(encoding='utf-8'))
    verilator = manifest.get('identity', {}).get('toolchain', {}).get('verilator')
    if not isinstance(verilator, dict):
        raise ValueError('tool-identity-missing')
    version = verilator.get('version')
    executable = verilator.get('executable_sha256')
    if not isinstance(version, str) or not version:
        raise ValueError('tool-identity-version-missing')
    if not _is_digest(executable, 64):
        raise ValueError('tool-identity-executable-invalid')
    return {'name': 'verilator', 'version': version,
            'executable_sha256': executable, 'identity_source': 'cache-manifest'}


def _budget_record(meta, measured, *, cache):
    """Explicit offline replay budget: what was bounded, how much was executed.

    ``search_budget`` stays explicitly unknown: an offline replay has no
    fuzzing/search budget and none is inferred here.
    """
    wall = meta.get('replay_seconds')
    wall_seconds = None
    if isinstance(wall, dict):
        wall_seconds = {key: wall[key] for key in ('plain', 'instrumented')
                        if key in wall}
    return {
        'schema_version': BUDGET_RECORD_SCHEMA,
        'mode': 'offline',
        'commands': measured['commands']['count'],
        'executed_commands': meta['replay']['result_count'],
        'local_ticks': measured['commands']['local_ticks'],
        'wall_seconds': wall_seconds,
        'tool_version': _tool_identity(cache),
        'build_digest': measured['build_digest'],
        'binary_sha256': measured['binary_sha256'],
        'replay_bounds': meta['replay_budget'],
        'recorded_replies': meta['replay'].get('result_count'),
        'same_budget_rule': ('identical replay_bounds and identical recorded command '
                             'sequence; wall seconds are recorded but are not a budget'),
        'search_budget': 'unknown',
    }


def _coverage_document(component, measured, *, trace_path, measurement, cache,
                       extended=False):
    points = measured['dut_points']
    if not points:
        raise ValueError('empty-dut-point-universe')
    canonical = json.dumps(sorted(points), separators=(',', ':'), ensure_ascii=True)
    files = _file_breakdown(points)
    kinds = _kind_breakdown(points)
    meta = json.loads((Path(measurement) / 'coverage.json').read_text(encoding='utf-8'))
    reply_lines = len((Path(measurement) / 'replies.txt').read_text(
        encoding='utf-8').splitlines())
    document = {
        'status': 'available',
        'attestation': 'recorded-prefix-replay.v1',
        'metric': f"verilator-line-block:{component}:dut",
        'coverage_kind': measured['coverage_kind'],
        'component': component,
        'total': len(points),
        'covered': sum(1 for count in points.values() if count > 0),
        'denominator_sha256': sha256(canonical.encode('ascii')).hexdigest(),
        'point_set_sha256': meta.get('coverage_points_sha256'),
        'coverage_data_sha256': meta['coverage_data_sha256'],
        'source_selection': meta.get('source_selection'),
        'files': files,
        'by_kind': kinds,
        'online': False,
        'fixed_time_coverage': False,
        'coverage_auc_available': False,
        'scope': 'offline full executed component prefix including startup/reset and any budget overrun',
        'includes_startup_reset': True,
        'includes_budget_overrun': True,
        'original_build_digest': measured['build_digest'],
        'original_binary_sha256': measured['binary_sha256'],
        'commands': measured['commands'],
        'local_ticks': measured['commands']['local_ticks'],
        'reply_lines': reply_lines,
        'reply_results': meta['replay']['result_count'],
        'trace': str(trace_path),
        'trace_sha256': sha256(Path(trace_path).read_bytes()).hexdigest(),
        'measurement': str(measurement),
        'original_cache': str(cache),
        'limitations': ['Offline saved-prefix coverage is not online or fixed-time-point coverage.',
                        'Saved-file consistency does not authenticate the original execution.',
                        'Verilator point kinds are reported as saved; the line/block metric is not source-branch coverage.',
                        'Line/block coverage of one generated component is not an SoC metric.'],
    }
    if extended:
        # Additive keys only: the default document keeps its exact old shape so
        # the recorded reports still reproduce byte-identically.
        document['point_universe_sha256'] = _point_identities_digest(measured['points'])
        # The canonical DUT point identity set, named explicitly for a cross-tool
        # comparison: the saved point_map_sha256 above embeds this build dir.
        document['point_set_normalized_sha256'] = document['denominator_sha256']
        document['budget_record'] = _budget_record(meta, measured, cache=cache)
    return document


def _focus_view(coverage, focus):
    if type(focus) is not str or not focus:
        return None
    selected = {name: row for name, row in coverage['files'].items() if focus in name}
    return {'focus': focus, 'files': selected,
            'total': sum(row['total'] for row in selected.values()),
            'covered': sum(row['covered'] for row in selected.values())}


def _unavailable_contract(component, reason, *, missing=()):
    """A contract that cannot be fixed never becomes a comparison."""
    return {
        'schema_version': CONTRACT_SCHEMA,
        'contract': CONTRACT_ID,
        'status': 'unavailable',
        'component': component,
        'reason': reason,
        'missing_inputs': list(missing),
        'dut': None,
        'workload': None,
        'budget': None,
        'mode': None,
        'rules': list(_CONTRACT_RULES),
        'limitations': list(_CONTRACT_LIMITATIONS),
    }


def _normalized_wire_lines(lines):
    """Replace the execution nonce token so two invocations are comparable."""
    if not isinstance(lines, list) or not lines:
        raise ValueError('empty-workload')
    nonce = lines[0].split(' ')[1]
    if not _is_digest(nonce, 32):
        raise ValueError('workload-nonce-invalid')
    normalized = []
    for line in lines:
        parts = line.split(' ')
        if len(parts) > 1 and parts[1] == nonce:
            parts[1] = '{NONCE}'
        normalized.append(' '.join(parts))
    return normalized


def _digest_lines(lines):
    return sha256(('\n'.join(lines) + '\n').encode('ascii')).hexdigest()


def _workload_document(commands, replies, coverage):
    commands_normalized = _normalized_wire_lines(commands)
    replies_normalized = _normalized_wire_lines(replies)
    return {
        'identity': 'recorded-command-sequence.v1',
        'commands': len(commands),
        'commands_sha256': _digest_lines(commands_normalized),
        'replies_sha256': _digest_lines(replies_normalized),
        'local_ticks': coverage['local_ticks'],
        'reset_epochs': 0,
        'includes_startup_reset': True,
        'scope': 'every command accepted by the recorded session, in order',
    }


def _dut_sources_document(measurement, sources):
    rows = []
    for name in sources:
        path = Path(measurement) / 'inputs' / name
        if not path.is_file():
            raise ValueError('dut-source-missing:' + name)
        rows.append({'path': name, 'sha256': sha256(path.read_bytes()).hexdigest()})
    canonical = json.dumps(rows, sort_keys=True, separators=(',', ':'))
    return rows, sha256(canonical.encode('ascii')).hexdigest()


def _comparison_contract(component, coverage, measured, commands, replies, *,
                         measurement, trace_path, cache=None, extended=False):
    """State exactly what an equal-contract comparison would require."""
    if coverage.get('point_set_sha256') is None:
        return _unavailable_contract(component, 'missing-point-set',
                                     missing=['coverage-points.json'])
    saved = json.loads((Path(measurement) / 'coverage.json').read_text(encoding='utf-8'))
    source_rows, source_digest = _dut_sources_document(measurement,
                                                       measured['dut_sources'])
    dut = {
        'component': component,
        'source_file_count': len(source_rows),
        'source_files_sha256': source_digest,
        'point_set_sha256': coverage['point_set_sha256'],
        'denominator_sha256': coverage['denominator_sha256'],
        'total_points': coverage['total'],
        'covered_points': coverage['covered'],
        'scope': ('points in declared structural-build DUT source files; '
                  'all retained hierarchy instances'),
    }
    budget = {
        'replay': saved['replay_budget'],
        'executed_commands': len(commands),
        'search_budget': 'unknown',
        'same_budget_rule': ('identical replay_budget keys and identical '
                             'recorded command sequence'),
    }
    if extended:
        # Additive keys only, opt-in: the saved point-map hash embeds the build
        # directory, so the normalised whole-harness point identity set is what
        # makes two instrumented builds of the same inputs comparable.
        dut['point_universe_sha256'] = _point_identities_digest(measured['points'])
        # The canonical DUT point identity set is build-directory independent;
        # naming it explicitly is what lets an external tool know which
        # identity its `point_set_sha256` must reproduce.
        dut['point_set_normalized_sha256'] = coverage['denominator_sha256']
        record = _budget_record(saved, measured, cache=cache) if cache is not None \
            else None
        budget.update({
            'commands': len(commands),
            'local_ticks': measured['commands']['local_ticks'],
            'wall_seconds': (record or {}).get('wall_seconds'),
            'tool_version': (record or {}).get('tool_version'),
            'build_digest': measured['build_digest'],
        })
    return {
        'schema_version': CONTRACT_SCHEMA,
        'contract': CONTRACT_ID,
        'status': 'available',
        'component': component,
        'metric': coverage['metric'],
        'coverage_kind': coverage['coverage_kind'],
        'dut': dut,
        'workload': _workload_document(commands, replies, coverage),
        'budget': budget,
        'mode': {
            'coverage': 'offline',
            'online': False,
            'fixed_time_coverage': False,
            'instrumented': True,
            'attestation': coverage['attestation'],
        },
        'measurement': {
            'coverage_data_sha256': coverage['coverage_data_sha256'],
            'point_set_sha256': coverage['point_set_sha256'],
            'trace': str(trace_path),
            'trace_sha256': coverage['trace_sha256'],
        },
        'rules': list(_CONTRACT_RULES),
        'limitations': list(_CONTRACT_LIMITATIONS),
    }


_CONTRACT_CONDITIONS = {
    'same_component': 'component-mismatch',
    'same_metric': 'metric-mismatch',
    'same_dut_sources': 'dut-source-set-mismatch',
    'same_point_set': 'point-set-mismatch',
    'same_denominator': 'denominator-mismatch',
    'same_workload': 'workload-mismatch',
    'same_command_count': 'workload-length-mismatch',
    'same_local_ticks': 'workload-tick-mismatch',
    'same_replies': 'replies-mismatch',
    'same_replay_budget': 'budget-mismatch',
    'same_coverage_mode': 'coverage-mode-mismatch',
    'both_instrumented': 'non-instrumented-prefix',
}


def _point_set_identity(left, right):
    """Decide which point-set identity to compare.

    The saved point-map hash (``point_set_sha256``) embeds the absolute build
    directory, so two instrumented builds of the same pinned inputs never carry
    the same saved hash.  When both contracts publish the normalised
    whole-harness point identity set (extended contract), that set -- together
    with the canonical DUT denominator -- is the point-set identity.  Documents
    without the extended field keep the old byte-for-byte behaviour.
    """
    normalized = {}
    for side, contract in (('left', left), ('right', right)):
        dut = contract.get('dut') if isinstance(contract, dict) else None
        value = dut.get('point_universe_sha256') if isinstance(dut, dict) else None
        if _is_digest(value, 64):
            normalized[side] = value
    if len(normalized) != 2:
        # Old documents (and any mixed pair) compare the saved point-map hash,
        # exactly as before.
        return {'basis': 'saved-point-map',
                'matches': left['dut']['point_set_sha256']
                == right['dut']['point_set_sha256'],
                'identity': None}
    saved = {}
    for side, contract in (('left', left), ('right', right)):
        saved[side] = contract['dut'].get('point_set_sha256')
    return {
        'basis': 'normalized-point-identities',
        'matches': normalized['left'] == normalized['right'],
        'identity': {
            'basis': 'normalized-point-identities',
            'rule': ('SHA256 of the sorted normalised point identities of the '
                     'whole generated harness; the absolute build directory is '
                     'not part of the identity'),
            'left': normalized['left'],
            'right': normalized['right'],
            'saved_point_map_sha256': {'left': saved['left'], 'right': saved['right'],
                                       'note': ('saved point maps embed their own '
                                                'build directory and are recorded, '
                                                'not required to be byte-equal')},
        },
    }


def compare_under_contract(left, right):
    """Compare two contracts only when every identity condition is fixed.

    A covered/total is compared only when both sides are instrumented offline
    measurements with the same DUT source set, point set, workload and replay
    budget.  Anything else yields ``not_comparable``/``unavailable`` and no
    number.  Equality is not a superiority claim.
    """
    document = {
        'schema_version': 'coverage_contract_comparison.v1',
        'contract': CONTRACT_ID,
        'status': 'unavailable',
        'reasons': [],
        'conditions': {},
        'comparison': None,
        'limitations': list(_CONTRACT_LIMITATIONS),
    }
    if not isinstance(left, dict) or not isinstance(right, dict):
        document['reasons'].append('missing-contract')
        return document
    unavailable = [side for side, value in (('left', left), ('right', right))
                   if value.get('status') != 'available']
    if unavailable:
        document['reasons'].extend('contract-unavailable:' + side
                                   for side in unavailable)
        return document
    try:
        point_set = _point_set_identity(left, right)
        conditions = {
            'same_component': left['component'] == right['component'],
            'same_metric': left['metric'] == right['metric'],
            'same_dut_sources': (left['dut']['source_files_sha256']
                                 == right['dut']['source_files_sha256']),
            'same_point_set': point_set['matches'],
            'same_denominator': (left['dut']['denominator_sha256']
                                 == right['dut']['denominator_sha256']),
            'same_workload': (left['workload']['commands_sha256']
                              == right['workload']['commands_sha256']),
            'same_command_count': (left['workload']['commands']
                                   == right['workload']['commands']),
            'same_local_ticks': (left['workload']['local_ticks']
                                 == right['workload']['local_ticks']),
            'same_replies': (left['workload']['replies_sha256']
                             == right['workload']['replies_sha256']),
            'same_replay_budget': (left['budget']['replay']
                                   == right['budget']['replay']),
            'same_coverage_mode': (left['mode']['coverage'] == 'offline'
                                   and right['mode']['coverage'] == 'offline'
                                   and left['mode']['online'] is False
                                   and right['mode']['online'] is False),
            'both_instrumented': (left['mode']['instrumented'] is True
                                  and right['mode']['instrumented'] is True),
        }
    except (KeyError, TypeError):
        document['reasons'].append('contract-shape-invalid')
        return document
    document['conditions'] = conditions
    if point_set['basis'] == 'normalized-point-identities':
        document['point_set_identity'] = point_set['identity']
    document['reasons'] = [reason for name, reason in _CONTRACT_CONDITIONS.items()
                           if conditions[name] is not True]
    if document['reasons']:
        document['status'] = 'not_comparable'
        return document
    document['status'] = 'comparable_contract'
    document['comparison'] = {
        'metric': left['metric'],
        'total_points': left['dut']['total_points'],
        'left': {'covered': left['dut']['covered_points'],
                 'total': left['dut']['total_points']},
        'right': {'covered': right['dut']['covered_points'],
                  'total': right['dut']['total_points']},
        'hit_delta': (right['dut']['covered_points']
                      - left['dut']['covered_points']),
        'note': ('Equal contract only: same DUT points, workload and replay budget '
                 'in the same offline mode; not a superiority claim.'),
    }
    return document


class PrefixEvidenceError(ValueError):
    """A saved prefix cannot be resolved into comparable evidence."""


_OWN_PREFIX_UNKNOWN = ('seed', 'time_budget', 'execution_budget',
                       'process_independence', 'fairness')
_OWN_PREFIX_BOOLEANS = ('same_config', 'same_admission', 'same_artifacts', 'same_case',
                        'same_group', 'same_build_digest', 'same_binary',
                        'same_command_count', 'same_commands', 'same_replies',
                        'same_local_ticks', 'both_exit_zero', 'matches_measured_prefix')
_OWN_PREFIX_REASONS = {
    'same_config': 'prefix-config-mismatch',
    'same_admission': 'prefix-admission-mismatch',
    'same_artifacts': 'prefix-artifact-mismatch',
    'same_case': 'prefix-case-mismatch',
    'same_group': 'prefix-group-mismatch',
    'same_build_digest': 'prefix-build-digest-mismatch',
    'same_binary': 'prefix-binary-mismatch',
    'same_command_count': 'prefix-command-count-mismatch',
    'same_commands': 'prefix-commands-mismatch',
    'same_replies': 'prefix-replies-mismatch',
    'same_local_ticks': 'prefix-local-ticks-mismatch',
    'both_exit_zero': 'prefix-exit-nonzero',
    'matches_measured_prefix': 'original-prefix-measurement-mismatch',
}


def _is_digest(value, length):
    return type(value) is str and len(value) == length and \
        all(character in '0123456789abcdef' for character in value)


def _read_side_json(root, name, *, side):
    path = Path(root) / name
    try:
        document = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        raise PrefixEvidenceError(f'{side}-{name}-unreadable') from None
    if not isinstance(document, dict):
        raise PrefixEvidenceError(f'{side}-{name}-not-an-object')
    return document


def _side_processes(evidence, component, *, side):
    processes = evidence['summary'].get('processes')
    if not isinstance(processes, list) or not processes:
        raise PrefixEvidenceError(f'{side}-summary-processes-missing')
    exits, pids = {}, {}
    for row in processes:
        if not isinstance(row, dict) or not isinstance(row.get('component'), str):
            raise PrefixEvidenceError(f'{side}-summary-process-invalid')
        if type(row.get('exit_code')) is not int:
            raise PrefixEvidenceError(f'{side}-summary-exit-code-invalid')
        if row['component'] in exits:
            raise PrefixEvidenceError(f'{side}-summary-component-duplicate')
        exits[row['component']] = row['exit_code']
        pids[row['component']] = row.get('pid')
    if component not in exits:
        raise PrefixEvidenceError(f'{side}-summary-component-missing:' + component)
    return {'exit_codes': exits, 'pids': pids}


def _side_records(session, *, side):
    """Strip the execution nonce so two invocations can be compared honestly."""
    identity = session['identity']
    nonce = identity.get('execution_nonce')
    if not _is_digest(nonce, 32):
        raise PrefixEvidenceError(f'{side}-identity-nonce-invalid')
    if not _is_digest(identity.get('binary_sha256'), 64):
        raise PrefixEvidenceError(f'{side}-identity-binary-invalid')
    if not _is_digest(identity.get('build_digest'), 64):
        raise PrefixEvidenceError(f'{side}-identity-build-invalid')
    records = session.get('records')
    if not isinstance(records, list) or not records:
        raise PrefixEvidenceError(f'{side}-prefix-empty')
    commands, replies, ticks = [], [], []
    for index, record in enumerate(records, 1):
        if not isinstance(record, dict):
            raise PrefixEvidenceError(f'{side}-prefix-record-invalid')
        command, reply = record.get('command'), record.get('reply')
        tick = record.get('tick_after')
        if (type(record.get('sequence')) is not int or record['sequence'] != index
                or type(record.get('reset_epoch')) is not int or record['reset_epoch'] != 0
                or type(tick) is not int
                or not isinstance(command, str) or not isinstance(reply, str)
                or not command.startswith(f'CMD {nonce} {index:x} ')
                or not reply.startswith(f'RESULT {nonce} {index:x} ')):
            raise PrefixEvidenceError(f'{side}-prefix-record-invalid')
        commands.append(command.replace(nonce, '{NONCE}', 1))
        replies.append(reply.replace(nonce, '{NONCE}', 1))
        ticks.append(tick)
    return {'commands': commands, 'replies': replies, 'ticks': ticks, 'nonce': nonce}


def _prefix_side(root, *, side):
    root = Path(root)
    if not root.is_dir():
        raise PrefixEvidenceError(f'{side}-prefix-missing')
    prefix = _read_side_json(root, 'prefix.json', side=side)
    summary = _read_side_json(root, 'summary.json', side=side)
    config = (_read_side_json(root, 'config.json', side=side)
              if (root / 'config.json').is_file() else None)
    trace_path = resolve_trace(root)
    if trace_path is None:
        raise PrefixEvidenceError(f'{side}-prefix-trace-missing')
    try:
        trace = load_trace(trace_path)
    except (OSError, ValueError) as error:
        raise PrefixEvidenceError(f'{side}-prefix-trace-invalid:' + str(error)) from None
    sessions = trace.get('sessions')
    if not isinstance(sessions, dict):
        raise PrefixEvidenceError(f'{side}-prefix-trace-sessions-missing')
    return {'root': root, 'prefix': prefix, 'summary': summary, 'config': config,
            'trace_path': trace_path, 'sessions': sessions}


def _side_session(evidence, component, *, side):
    session = evidence['sessions'].get(component)
    if not isinstance(session, dict):
        raise PrefixEvidenceError(f'{side}-prefix-component-missing:' + component)
    if session.get('complete') is not True:
        raise PrefixEvidenceError(f'{side}-prefix-component-incomplete:' + component)
    if not isinstance(session.get('identity'), dict):
        raise PrefixEvidenceError(f'{side}-prefix-identity-missing')
    return session


def own_prefix_comparability(original_prefix, fresh_prefix, *, component, expected=None,
                             conflicting=False):
    """Compare one run's own saved ``original`` and ``fresh`` prefixes.

    The document states recorded command/reply/tick identity on the same build
    (modulo the execution nonce) and whether both invocations exited 0.  It
    never compares coverage: only the original prefix was instrumented, so the
    fresh prefix has no ``covered``/``total`` and none is derived.

    ``expected`` (``build_digest``, ``binary_sha256``, ``commands``,
    ``local_ticks``) binds the original side to an already verified
    measurement.  ``conflicting`` flags a caller that also passed a foreign
    baseline; the pair is then reported unavailable instead of mixing scopes.
    """
    conditions = {name: 'unknown' for name in _OWN_PREFIX_UNKNOWN}
    conditions.update({name: False for name in _OWN_PREFIX_BOOLEANS})
    document = {
        'schema_version': 'local_harness_coverage_comparison.v1',
        'status': 'unavailable',
        'mode': 'own-original-fresh-prefix',
        'scope': ('recorded command/reply/tick identity of this run\'s own original and '
                  'fresh prefixes; only the original prefix carries coverage'),
        'reasons': [],
        'comparison': None,
        'coverage_comparison_available': False,
        'coverage_comparison_reason': 'fresh-prefix-not-instrumented',
        'conditions': conditions,
        'prefixes': None,
        'limitations': [
            'Equal commands, replies and local ticks across two invocations do not turn the fresh prefix into a coverage measurement.',
            'The fresh prefix was not instrumented, so no second covered/total exists to compare.',
            'Seed, time budget, execution budget and fairness remain unknown.',
            'Saved-file agreement does not authenticate either original process.',
            'A reproducible prefix is not evidence of tool superiority.',
        ],
    }
    reasons = document['reasons']
    if conflicting:
        reasons.append('conflicting-comparability-inputs')
    if original_prefix is None or fresh_prefix is None:
        reasons.append('missing-original-prefix' if original_prefix is None
                       else 'missing-fresh-prefix')
        return document
    if not isinstance(component, str) or not component:
        reasons.append('missing-component')
        return document
    try:
        original = _prefix_side(original_prefix, side='original')
        fresh = _prefix_side(fresh_prefix, side='fresh')
        for side, evidence in (('original', original), ('fresh', fresh)):
            evidence['session'] = _side_session(evidence, component, side=side)
            evidence['records'] = _side_records(evidence['session'], side=side)
            evidence['processes'] = _side_processes(evidence, component, side=side)
    except PrefixEvidenceError as error:
        reasons.append(str(error))
        return document
    original_prefix_doc, fresh_prefix_doc = original['prefix'], fresh['prefix']
    conditions['same_config'] = (
        _is_digest(original_prefix_doc.get('config_sha256'), 64)
        and original_prefix_doc.get('config_sha256') == fresh_prefix_doc.get('config_sha256')
        and (original['config'] is None or fresh['config'] is None
             or original['config'] == fresh['config']))
    conditions['same_admission'] = (
        _is_digest(original_prefix_doc.get('admission_sha256'), 64)
        and original_prefix_doc.get('admission_sha256') == fresh_prefix_doc.get('admission_sha256'))
    conditions['same_artifacts'] = (
        isinstance(original_prefix_doc.get('artifacts'), dict)
        and original_prefix_doc['artifacts'] == fresh_prefix_doc.get('artifacts'))
    conditions['same_case'] = (
        isinstance(original_prefix_doc.get('case'), dict)
        and original_prefix_doc['case'] == fresh_prefix_doc.get('case'))
    conditions['same_group'] = (
        isinstance(original_prefix_doc.get('group'), dict)
        and original_prefix_doc['group'] == fresh_prefix_doc.get('group'))
    original_identity = original['session']['identity']
    fresh_identity = fresh['session']['identity']
    conditions['same_build_digest'] = (
        original_identity.get('build_digest') == fresh_identity.get('build_digest'))
    conditions['same_binary'] = (
        original_identity.get('binary_sha256') == fresh_identity.get('binary_sha256'))
    original_records, fresh_records = original['records'], fresh['records']
    conditions['same_command_count'] = (len(original_records['commands'])
                                        == len(fresh_records['commands']))
    conditions['same_commands'] = original_records['commands'] == fresh_records['commands']
    conditions['same_replies'] = original_records['replies'] == fresh_records['replies']
    conditions['same_local_ticks'] = original_records['ticks'] == fresh_records['ticks']
    conditions['both_exit_zero'] = (
        all(code == 0 for code in original['processes']['exit_codes'].values())
        and all(code == 0 for code in fresh['processes']['exit_codes'].values()))
    if expected is None:
        conditions['matches_measured_prefix'] = 'unknown'
    else:
        conditions['matches_measured_prefix'] = (
            original_identity.get('build_digest') == expected.get('build_digest')
            and original_identity.get('binary_sha256') == expected.get('binary_sha256')
            and len(original_records['commands']) == expected.get('commands')
            and original_records['ticks'][-1] == expected.get('local_ticks'))
    for condition, reason in _OWN_PREFIX_REASONS.items():
        if conditions[condition] is False:
            reasons.append(reason)
    if (original_records['nonce'] != fresh_records['nonce']
            and original['processes']['pids'] != fresh['processes']['pids']):
        conditions['process_independence'] = 'separate-invocations'
    if not reasons:
        document['status'] = 'comparable_prefix'
    document['prefixes'] = {
        'component': component,
        'build_digest': original_identity.get('build_digest'),
        'binary_sha256': original_identity.get('binary_sha256'),
        'commands': len(original_records['commands']),
        'local_ticks': original_records['ticks'][-1],
        'config_sha256': original_prefix_doc.get('config_sha256'),
        'admission_sha256': original_prefix_doc.get('admission_sha256'),
        'original': _side_document(original),
        'fresh': _side_document(fresh),
    }
    return document


def _side_document(evidence):
    session = evidence['session']
    return {
        'root': str(evidence['root']),
        'trace': str(evidence['trace_path']),
        'trace_sha256': sha256(Path(evidence['trace_path']).read_bytes()).hexdigest(),
        'execution_nonce': session['identity'].get('execution_nonce'),
        'summary_status': evidence['summary'].get('status'),
        'summary_mode': evidence['summary'].get('mode'),
        'commands': len(evidence['records']['commands']),
        'local_ticks': evidence['records']['ticks'][-1],
        'process_exit_codes': evidence['processes']['exit_codes'],
        'process_pids': evidence['processes']['pids'],
    }


def _comparability(*, current, baseline_measurement, baseline_run, cache,
                   current_measurement, component=None, original_prefix=None,
                   fresh_prefix=None, expected=None):
    if original_prefix is not None or fresh_prefix is not None:
        return own_prefix_comparability(original_prefix, fresh_prefix,
                                        component=component, expected=expected,
                                        conflicting=baseline_measurement is not None
                                        or baseline_run is not None)
    from scripts.compare_local_harness_coverage import compare_runs, load_run
    from scripts.measure_local_coverage import select_recorded_session

    document = {
        'schema_version': 'local_harness_coverage_comparison.v1',
        'status': 'not_comparable',
        'mode': 'foreign-baseline',
        'reasons': [],
        'comparison': None,
        'conditions': {'seed': 'unknown', 'time_budget': 'unknown',
                       'execution_budget': 'unknown', 'process_independence': 'unknown',
                       'fairness': 'unknown'},
        'limitations': ['Point-identity agreement does not establish equal budgets or seeds.',
                        'A single pair of saved replays does not establish tool superiority.',
                        'Line/block coverage is not a source-branch or SoC metric.'],
    }
    if baseline_measurement is None:
        document['reasons'].append('no-baseline-measurement')
        return document
    missing = _missing_measurement_files(baseline_measurement)
    if missing:
        document['reasons'].append('baseline-measurement-incomplete:' + ','.join(missing))
        return document
    baseline = load_run(baseline_measurement, cache=cache)
    if baseline_run is not None:
        baseline_trace = resolve_trace(baseline_run)
        if baseline_trace is None:
            document['reasons'].append('missing-baseline-trace')
            return document
        try:
            trace = load_trace(baseline_trace)
        except (OSError, ValueError) as error:
            document['reasons'].append('baseline-trace-invalid:' + str(error))
            return document
        components = [name for name, row in trace.get('sessions', {}).items()
                      if isinstance(row, dict)
                      and isinstance(row.get('identity'), dict)
                      and row['identity'].get('build_digest') == baseline['build_digest']]
        if len(components) != 1:
            document['reasons'].append('baseline-component-session-unresolved')
            return document
        commands, replies, _ = select_recorded_session(trace, components[0],
                                                       baseline['build_digest'])
        if ((Path(baseline_measurement) / 'commands.txt').read_text(encoding='ascii')
                != '\n'.join([*commands, 'END', '']) or [
                line for line in (Path(baseline_measurement) / 'replies.txt').read_text(
                    encoding='utf8').splitlines() if line.startswith('RESULT ')] != replies):
            document['reasons'].append('baseline-measurement-trace-mismatch')
            return document
    compared = compare_runs(current, baseline)
    document['status'] = compared['status']
    document['reasons'] = list(compared['reasons'])
    document['comparison'] = {'coverage': compared['coverage'],
                              'dut_coverage': compared['dut_coverage'],
                              'dut_scope': compared['dut_scope'],
                              'conditions': compared['conditions']}
    document['measurements'] = {'current': str(current_measurement),
                                'baseline': str(baseline_measurement)}
    return document


def measure(run, *, measurement, cache, component=None, focus=None,
            baseline_measurement=None, baseline_run=None,
            original_prefix=None, fresh_prefix=None, contract=False,
            extended_identity=False):
    """Return the coverage and comparability document, or an explicit unavailable.

    ``original_prefix``/``fresh_prefix`` select the run's own prefix pair for
    comparability; without them the legacy foreign-baseline mode is used.
    ``contract`` additionally publishes the fixed comparison contract; the
    default document shape (and therefore the existing reports) is unchanged.
    ``extended_identity`` adds the explicit offline replay-budget record and the
    normalised whole-harness point-set digest (additive keys only); it is
    off by default so the recorded reports still reproduce byte-identically.
    """
    from scripts.compare_local_harness_coverage import load_run
    from scripts.measure_local_coverage import select_recorded_session

    inputs = {'run': str(run), 'measurement': str(measurement), 'cache': str(cache),
              'component': component,
              'baseline_measurement': str(baseline_measurement) if baseline_measurement else None,
              'baseline_run': str(baseline_run) if baseline_run else None,
              'original_prefix': str(original_prefix) if original_prefix else None,
              'fresh_prefix': str(fresh_prefix) if fresh_prefix else None}
    trace_path = resolve_trace(run)
    if trace_path is None:
        return _unavailable('missing-local-command-trace', missing=['local_commands.json'],
                            searched=_TRACE_NAMES, inputs=inputs)
    try:
        trace = load_trace(trace_path)
    except (OSError, ValueError) as error:
        return _unavailable('invalid-local-command-trace:' + str(error), inputs=inputs)
    missing = _missing_measurement_files(measurement)
    if missing:
        return _unavailable('incomplete-saved-measurement', missing=missing, inputs=inputs)
    cache = Path(cache)
    if not (cache / 'manifest.json').is_file():
        return _unavailable('missing-original-cache', missing=['manifest.json'], inputs=inputs)
    try:
        measured = load_run(Path(measurement), cache=cache)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        return _unavailable('saved-measurement-unverified:' + str(error), inputs=inputs)
    if measured.get('cache_verified') is not True:
        return _unavailable('original-cache-unverified', inputs=inputs)
    if component is None:
        candidates = [name for name, row in trace.get('sessions', {}).items()
                      if isinstance(row, dict) and row.get('complete') is True
                      and isinstance(row.get('identity'), dict)
                      and row['identity'].get('build_digest') == measured['build_digest']]
        if len(candidates) != 1:
            return _unavailable('component-session-unresolved', inputs=inputs)
        component = candidates[0]
    try:
        commands, replies, binary = select_recorded_session(trace, component,
                                                            measured['build_digest'])
    except (OSError, ValueError, KeyError, TypeError) as error:
        return _unavailable('recorded-prefix-unverified:' + str(error), inputs=inputs)
    measurement_dir = Path(measurement)
    if binary != measured['binary_sha256']:
        return _unavailable('component-or-binary-mismatch', inputs=inputs)
    if (measurement_dir / 'commands.txt').read_text(encoding='ascii') != \
            '\n'.join([*commands, 'END', '']):
        return _unavailable('measurement-command-trace-mismatch', inputs=inputs)
    saved = [line for line in (measurement_dir / 'replies.txt').read_text(
        encoding='utf8').splitlines() if line.startswith('RESULT ')]
    if saved != replies:
        return _unavailable('measurement-reply-trace-mismatch', inputs=inputs)
    coverage = _coverage_document(component, measured, trace_path=trace_path,
                                  measurement=measurement_dir, cache=cache,
                                  extended=extended_identity)
    focus_view = _focus_view(coverage, focus)
    expected = {'build_digest': measured['build_digest'],
                'binary_sha256': measured['binary_sha256'],
                'commands': measured['commands']['count'],
                'local_ticks': measured['commands']['local_ticks']}
    own_mode = original_prefix is not None or fresh_prefix is not None
    try:
        comparability = _comparability(current=measured,
                                       baseline_measurement=(Path(baseline_measurement)
                                                             if baseline_measurement else None),
                                       baseline_run=baseline_run, cache=cache,
                                       current_measurement=measurement_dir,
                                       component=component, expected=expected,
                                       original_prefix=(Path(original_prefix)
                                                         if original_prefix else None),
                                       fresh_prefix=(Path(fresh_prefix)
                                                     if fresh_prefix else None))
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        comparability = {'schema_version': 'local_harness_coverage_comparison.v1',
                         'status': 'unavailable' if own_mode else 'not_comparable',
                         'mode': 'own-original-fresh-prefix' if own_mode else 'foreign-baseline',
                         'reasons': [('own-prefix-unverified:' if own_mode
                                      else 'baseline-unverified:') + str(error)],
                         'comparison': None,
                         'coverage_comparison_available': False,
                         'conditions': {'seed': 'unknown', 'time_budget': 'unknown',
                                        'execution_budget': 'unknown',
                                        'process_independence': 'unknown',
                                        'fairness': 'unknown'},
                         'limitations': ['A missing comparability block never becomes a number.']}
    result = {
        'schema_version': SCHEMA,
        'status': 'available',
        'scope': 'saved offline component prefix replay',
        'native_authority': False,
        'online': False,
        'fixed_time_coverage': False,
        'inputs': inputs,
        'coverage': coverage,
        'focus': focus_view,
        'comparability': comparability,
        'limitations': ['This document describes a saved replay, not a new native run.',
                        'Comparability keeps seed, budget, process independence and fairness unknown.',
                        'A fresh prefix without its own instrumented measurement is not coverage.'],
    }
    if contract:
        try:
            result['comparison_contract'] = _comparison_contract(
                component, coverage, measured, commands, replies,
                measurement=measurement_dir, trace_path=trace_path, cache=cache,
                extended=extended_identity)
        except (OSError, ValueError, KeyError, TypeError) as error:
            result['comparison_contract'] = _unavailable_contract(
                component, 'contract-unverified:' + str(error))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True,
                        help='saved run directory (or its local_commands.json)')
    parser.add_argument('--measurement', type=Path, required=True,
                        help='saved offline coverage measurement directory')
    parser.add_argument('--cache', type=Path, required=True,
                        help='original content-addressed component cache')
    parser.add_argument('--output', type=Path, default=None)
    parser.add_argument('--component', default=None)
    parser.add_argument('--focus', default=None,
                        help='optional source-file substring for a focused breakdown')
    parser.add_argument('--baseline-measurement', type=Path, default=None)
    parser.add_argument('--baseline-run', type=Path, default=None)
    parser.add_argument('--original-prefix', type=Path, default=None,
                        help='this run\'s saved original prefix root (prefix.json, summary.json, trace)')
    parser.add_argument('--fresh-prefix', type=Path, default=None,
                        help='this run\'s saved fresh prefix root; compared with --original-prefix')
    parser.add_argument('--contract', action='store_true',
                        help='also publish the fixed offline comparison contract')
    parser.add_argument('--extended-identity', action='store_true',
                        help=('add the explicit replay-budget record and the normalised '
                              'whole-harness point-set digest (additive keys only; off by '
                              'default so recorded reports stay byte-identical)'))
    args = parser.parse_args(argv)
    try:
        document = measure(args.run, measurement=args.measurement, cache=args.cache,
                           component=args.component, focus=args.focus,
                           baseline_measurement=args.baseline_measurement,
                           baseline_run=args.baseline_run,
                           original_prefix=args.original_prefix,
                           fresh_prefix=args.fresh_prefix, contract=args.contract,
                           extended_identity=args.extended_identity)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        document = _unavailable('measurement-error:' + str(error))
    text = json.dumps(document, indent=2, sort_keys=True) + '\n'
    if args.output is not None:
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / 'summary.json').write_text(text, encoding='utf-8')
        if document['status'] == 'available':
            (args.output / 'coverage.json').write_text(
                json.dumps(document['coverage'], indent=2, sort_keys=True) + '\n',
                encoding='utf-8')
            (args.output / 'comparability.json').write_text(
                json.dumps(document['comparability'], indent=2, sort_keys=True) + '\n',
                encoding='utf-8')
            if args.contract:
                (args.output / 'contract.json').write_text(
                    json.dumps(document['comparison_contract'], indent=2,
                               sort_keys=True) + '\n', encoding='utf-8')
    if document['status'] != 'available':
        print(json.dumps({'status': 'unavailable', 'reason': document['reason'],
                          'missing_inputs': document['missing_inputs']}, sort_keys=True))
        return 1
    printed = {'status': 'available', 'component': document['coverage']['component'],
               'covered': document['coverage']['covered'],
               'total': document['coverage']['total'],
               'local_ticks': document['coverage']['local_ticks'],
               'metric': document['coverage']['metric'],
               'comparability': document['comparability']['status']}
    if args.contract:
        printed['contract'] = document['comparison_contract']['status']
    if args.extended_identity:
        printed['extended_identity'] = True
        printed['point_universe_sha256'] = document['coverage'].get('point_universe_sha256')
    print(json.dumps(printed, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
