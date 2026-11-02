#!/usr/bin/env python3
"""Check an external tool's coverage measurement against our fixed contract.

We cannot run another fuzzing tool in this environment, so this script delivers
the *representation and verification* side of a same-budget comparison:

* it resolves **one of our** already measured scopes through the same verified
  loader as ``scripts/measure_new_path_coverage.py`` (never a hand-copied
  number), builds its extended contract and remembers the exact identity a
  second tool must reproduce;
* it accepts the other tool's measurement document in the documented strict
  schema :data:`EXTERNAL_SCHEMA` (``external_coverage_measurement.v1``),
  validates every required field (types, digest formats, enums, no unknown
  keys) and compares each identity field against ours;
* it prints/writes ``comparable`` or ``not_comparable`` with an exact per-field
  reason (``dut-source-set-mismatch``, ``point-set-mismatch``,
  ``workload-mismatch``, ``budget-missing``, ``non-instrumented-measurement``,
  ``coverage-mode-mismatch``, ...).

It never generates, fetches or implies a measurement: the document is supplied
by the caller.  It performs **no network access** of any kind (only stdlib file
I/O and SHA256), and nothing is built or replayed.  ``--self-test`` exercises the
validator with synthetic documents derived from a real measured scope: one
matching document that must be ``comparable`` and a set of mismatches that must
each be rejected for the named reason.

Schema of the external document
-------------------------------
``schema_version``          const ``external_coverage_measurement.v1``
``tool``                    ``{name, version, identity}`` non-empty strings
``dut``                     ``{component, source_files_sha256, source_file_count,
                            point_set_sha256, denominator_sha256, total_points}``
``workload``                ``{identity: recorded-command-sequence.v1, commands,
                            commands_sha256, local_ticks[, replies_sha256]}``
``budget``                  ``{replay: {max_commands, max_input_bytes,
                            max_output_bytes, max_wall_seconds}, executed_commands}``
``mode``                    ``{coverage: offline|online|fixed_time, online,
                            fixed_time_coverage, instrumented}``
``result``                  ``{covered, total}``
``artifacts``               ``{coverage_data_sha256: <64 hex>, ...}`` (at least one)
``reproduction``            non-empty string (the exact command that produced it)

Digests are lowercase SHA256 hex (``^[0-9a-f]{64}$``); integers are JSON
integers; ``additionalProperties`` is ``false`` at every level.  ``point_set_sha256``
is the *normalised* DUT point-identity digest (see
``dut.point_set_normalized_sha256`` in our extended contract); the raw saved
point-map hash of our own measurement embeds its build directory and is
recorded as our ``dut.point_set_sha256`` for provenance only.
"""
from __future__ import annotations

import argparse
import copy
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'src'))

from scripts.measure_new_path_coverage import (CONTRACT_ID, _is_digest, measure)
from scripts.report_declared_f5_coverage import (_relative, _run_summary,
                                                 _scope_component)
from scripts.report_coverage_comparison_contract import (DEFAULT_CPU_MEASUREMENT,
                                                         DEFAULT_RUNS)

SCHEMA = 'external_coverage_contract_check.v1'
EXTERNAL_SCHEMA_VERSION = 'external_coverage_measurement.v1'
WORKLOAD_IDENTITY = 'recorded-command-sequence.v1'
_HEX = '^[0-9a-f]{64}$'
_DIGEST = {'type': 'string', 'pattern': _HEX}
_COUNT = {'type': 'integer', 'minimum': 0}
_POSITIVE = {'type': 'integer', 'minimum': 1}
_STRING = {'type': 'string', 'minLength': 1}

EXTERNAL_SCHEMA = {
    '$schema': 'https://json-schema.org/draft/2020-12/schema',
    'title': EXTERNAL_SCHEMA_VERSION,
    'description': ('A second tool\'s offline line/block measurement of one of our '
                    'measured DUT scopes, for comparison under '
                    'dut-line-block/offline-recorded-prefix.v1.'),
    'type': 'object',
    'additionalProperties': False,
    'required': ['schema_version', 'tool', 'dut', 'workload', 'budget', 'mode',
                 'result', 'artifacts', 'reproduction'],
    'properties': {
        'schema_version': {'const': EXTERNAL_SCHEMA_VERSION},
        'tool': {
            'type': 'object', 'additionalProperties': False,
            'required': ['name', 'version', 'identity'],
            'properties': {'name': _STRING, 'version': _STRING, 'identity': _STRING},
        },
        'dut': {
            'type': 'object', 'additionalProperties': False,
            'required': ['component', 'source_files_sha256', 'source_file_count',
                         'point_set_sha256', 'denominator_sha256', 'total_points'],
            'properties': {
                'component': _STRING,
                'source_files_sha256': _DIGEST,
                'source_file_count': _POSITIVE,
                'point_set_sha256': _DIGEST,
                'denominator_sha256': _DIGEST,
                'total_points': _POSITIVE,
            },
        },
        'workload': {
            'type': 'object', 'additionalProperties': False,
            'required': ['identity', 'commands', 'commands_sha256', 'local_ticks'],
            'properties': {
                'identity': {'const': WORKLOAD_IDENTITY},
                'commands': _POSITIVE,
                'commands_sha256': _DIGEST,
                'replies_sha256': _DIGEST,
                'local_ticks': _COUNT,
            },
        },
        'budget': {
            'type': 'object', 'additionalProperties': False,
            'required': ['replay', 'executed_commands'],
            'properties': {
                'replay': {
                    'type': 'object', 'additionalProperties': False,
                    'required': ['max_commands', 'max_input_bytes',
                                 'max_output_bytes', 'max_wall_seconds'],
                    'properties': {
                        'max_commands': _POSITIVE,
                        'max_input_bytes': _POSITIVE,
                        'max_output_bytes': _POSITIVE,
                        'max_wall_seconds': {'type': 'number', 'exclusiveMinimum': 0},
                    },
                },
                'executed_commands': _COUNT,
            },
        },
        'mode': {
            'type': 'object', 'additionalProperties': False,
            'required': ['coverage', 'online', 'fixed_time_coverage', 'instrumented'],
            'properties': {
                'coverage': {'enum': ['offline', 'online', 'fixed_time']},
                'online': {'type': 'boolean'},
                'fixed_time_coverage': {'type': 'boolean'},
                'instrumented': {'type': 'boolean'},
            },
        },
        'result': {
            'type': 'object', 'additionalProperties': False,
            'required': ['covered', 'total'],
            'properties': {'covered': _COUNT, 'total': _POSITIVE},
        },
        'artifacts': {
            'type': 'object', 'additionalProperties': _DIGEST, 'minProperties': 1,
            'required': ['coverage_data_sha256'],
        },
        'reproduction': _STRING,
    },
}

# Canonical reason per field for structural (shape) failures.
_STRUCTURAL_REASONS = {
    'schema_version': 'unsupported-schema',
    'tool': 'tool-missing',
    'tool.name': 'tool-name-missing',
    'tool.version': 'tool-version-missing',
    'tool.identity': 'tool-identity-missing',
    'dut': 'dut-missing',
    'dut.component': 'dut-component-missing',
    'dut.source_files_sha256': 'dut-source-set-missing',
    'dut.source_file_count': 'dut-source-file-count-missing',
    'dut.point_set_sha256': 'dut-point-set-missing',
    'dut.denominator_sha256': 'dut-denominator-missing',
    'dut.total_points': 'dut-total-points-missing',
    'workload': 'workload-missing',
    'workload.identity': 'workload-identity-unsupported',
    'workload.commands': 'workload-commands-missing',
    'workload.commands_sha256': 'workload-command-sha-missing',
    'workload.local_ticks': 'workload-ticks-missing',
    'budget': 'budget-missing',
    'budget.replay': 'budget-replay-missing',
    'budget.executed_commands': 'budget-executed-commands-missing',
    'mode': 'mode-missing',
    'mode.coverage': 'mode-coverage-invalid',
    'mode.online': 'mode-online-flag-missing',
    'mode.fixed_time_coverage': 'mode-fixed-time-flag-missing',
    'mode.instrumented': 'mode-instrumented-flag-missing',
    'result': 'result-missing',
    'result.covered': 'result-covered-missing',
    'result.total': 'result-total-missing',
    'artifacts': 'artifacts-missing',
    'reproduction': 'reproduction-missing',
}

LIMITATIONS = [
    'A comparable verdict says the two numbers describe the same DUT points, workload and replay budget in the same offline mode.',
    'It does not establish equal search budgets, seeds, process independence or tool superiority.',
    'This script never produces a measurement: the external document is caller-supplied.',
    'The raw saved point-map hash of one side embeds its own build directory; the normalised point-identity digest is the compared identity.',
    'No network access is performed and no external measurement is claimed to exist.',
]


class ExternalCheckError(ValueError):
    """Our own scope cannot be resolved into an extended contract."""


def _sha256(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def _get(document, path):
    value = document
    for part in path.split('.'):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _structural_errors(document):
    """Validate the strict schema, returning ``[{'field', 'reason'}]``."""
    if not isinstance(document, dict):
        return [{'field': '-', 'reason': 'not-an-object'}]
    errors = []

    def fail(path, reason=None):
        errors.append({'field': path,
                       'reason': reason or _STRUCTURAL_REASONS.get(
                           path, 'invalid-document:' + path)})

    allowed = set(EXTERNAL_SCHEMA['required'])
    for key in document:
        if key not in allowed:
            fail(key, 'unknown-field:' + key)
    for path in EXTERNAL_SCHEMA['required']:
        if path not in document:
            fail(path)
    if errors:
        return errors
    if document.get('schema_version') != EXTERNAL_SCHEMA_VERSION:
        fail('schema_version')
    for section in ('tool', 'dut', 'workload', 'budget', 'mode', 'result'):
        if not isinstance(document[section], dict):
            fail(section, 'invalid-type:' + section)
    if errors:
        return errors
    for section in ('tool', 'dut', 'workload', 'budget', 'mode', 'result'):
        unknown = set(document[section]) - set(
            EXTERNAL_SCHEMA['properties'][section]['required'])
        optional = set(EXTERNAL_SCHEMA['properties'][section]['properties'])
        for key in sorted(unknown - optional):
            fail(f'{section}.{key}', 'unknown-field:' + f'{section}.{key}')
    for path in _STRUCTURAL_REASONS:
        if '.' not in path:
            continue
        section, leaf = path.split('.', 1)
        if leaf not in document.get(section, {}):
            fail(path)
    if errors:
        return errors

    def digest(path):
        value = _get(document, path)
        if not _is_digest(value, 64):
            fail(path, 'invalid-digest:' + path)

    def integer(path, minimum):
        value = _get(document, path)
        if type(value) is not int or value < minimum:
            fail(path, 'invalid-integer:' + path)

    digest('dut.source_files_sha256')
    digest('dut.point_set_sha256')
    digest('dut.denominator_sha256')
    digest('workload.commands_sha256')
    if 'replies_sha256' in document['workload']:
        digest('workload.replies_sha256')
    integer('dut.source_file_count', 1)
    integer('dut.total_points', 1)
    integer('workload.commands', 1)
    integer('workload.local_ticks', 0)
    integer('budget.executed_commands', 0)
    integer('result.covered', 0)
    integer('result.total', 1)
    if not isinstance(document['budget'].get('replay'), dict):
        fail('budget.replay', 'invalid-type:budget.replay')
    else:
        replay = document['budget']['replay']
        if set(replay) != {'max_commands', 'max_input_bytes', 'max_output_bytes',
                           'max_wall_seconds'}:
            fail('budget.replay', 'invalid-replay-budget-keys')
        else:
            for key in ('max_commands', 'max_input_bytes', 'max_output_bytes'):
                if type(replay[key]) is not int or replay[key] < 1:
                    fail('budget.replay', 'invalid-replay-budget-value:' + key)
            wall = replay['max_wall_seconds']
            if type(wall) not in (int, float) or not wall > 0:
                fail('budget.replay', 'invalid-replay-budget-value:max_wall_seconds')
    if not isinstance(document['artifacts'], dict) or not document['artifacts']:
        fail('artifacts', 'artifacts-empty')
    else:
        if 'coverage_data_sha256' not in document['artifacts']:
            fail('artifacts', 'artifact-missing:coverage_data_sha256')
        for name in sorted(document['artifacts']):
            if not _is_digest(document['artifacts'][name], 64):
                fail('artifacts', 'invalid-artifact-digest:' + name)
    for name in ('name', 'version', 'identity'):
        if not isinstance(document['tool'].get(name), str) or not document['tool'][name]:
            fail('tool.' + name, 'invalid-type:tool.' + name)
    if document['mode'].get('coverage') not in ('offline', 'online', 'fixed_time'):
        fail('mode.coverage')
    for name in ('online', 'fixed_time_coverage', 'instrumented'):
        if type(document['mode'].get(name)) is not bool:
            fail('mode.' + name, 'invalid-type:mode.' + name)
    if document['workload'].get('identity') != WORKLOAD_IDENTITY:
        fail('workload.identity')
    if not isinstance(document['reproduction'], str) or not document['reproduction']:
        fail('reproduction', 'invalid-type:reproduction')
    return errors


def _condition_table(ours, external):
    """Per-field comparison rows; each row carries its own exact reason."""
    extension = ours['dut'].get('point_set_normalized_sha256')
    if not _is_digest(extension, 64):
        raise ExternalCheckError('our-contract-missing-normalized-point-set')
    rows = [
        ('dut.component', ours['dut']['component'],
         _get(external, 'dut.component'), 'component-mismatch'),
        ('dut.source_files_sha256', ours['dut']['source_files_sha256'],
         _get(external, 'dut.source_files_sha256'), 'dut-source-set-mismatch'),
        ('dut.point_set_sha256', extension,
         _get(external, 'dut.point_set_sha256'), 'point-set-mismatch'),
        ('dut.denominator_sha256', ours['dut']['denominator_sha256'],
         _get(external, 'dut.denominator_sha256'), 'denominator-mismatch'),
        ('dut.total_points', ours['dut']['total_points'],
         _get(external, 'dut.total_points'), 'denominator-size-mismatch'),
        ('workload.identity', ours['workload']['identity'],
         _get(external, 'workload.identity'), 'workload-identity-unsupported'),
        ('workload.commands_sha256', ours['workload']['commands_sha256'],
         _get(external, 'workload.commands_sha256'), 'workload-mismatch'),
        ('workload.commands', ours['workload']['commands'],
         _get(external, 'workload.commands'), 'workload-length-mismatch'),
        ('workload.local_ticks', ours['workload']['local_ticks'],
         _get(external, 'workload.local_ticks'), 'workload-tick-mismatch'),
        ('budget.replay', ours['budget']['replay'],
         _get(external, 'budget.replay'), 'budget-mismatch'),
        ('budget.executed_commands', ours['budget']['executed_commands'],
         _get(external, 'budget.executed_commands'), 'budget-mismatch'),
        ('mode.coverage', 'offline', _get(external, 'mode.coverage'),
         'coverage-mode-mismatch'),
        ('mode.online', False, _get(external, 'mode.online'),
         'online-mode-not-comparable'),
        ('mode.fixed_time_coverage', False, _get(external, 'mode.fixed_time_coverage'),
         'fixed-time-mode-not-comparable'),
        ('mode.instrumented', True, _get(external, 'mode.instrumented'),
         'non-instrumented-measurement'),
        ('result.total', ours['dut']['total_points'],
         _get(external, 'result.total'), 'denominator-size-mismatch'),
    ]
    if 'replies_sha256' in external.get('workload', {}):
        rows.append(('workload.replies_sha256', ours['workload']['replies_sha256'],
                     external['workload']['replies_sha256'], 'replies-mismatch'))
    table = []
    for field, our_value, external_value, reason in rows:
        matches = our_value == external_value
        table.append({'field': field, 'ours': our_value,
                      'external': external_value, 'matches': matches,
                      'reason': None if matches else reason})
    covered = external['result']['covered']
    total = external['result']['total']
    if covered > total:
        table.append({'field': 'result.covered', 'ours': total, 'external': covered,
                      'matches': False, 'reason': 'covered-exceeds-total'})
    else:
        table.append({'field': 'result.covered',
                      'ours': ours['dut']['covered_points'], 'external': covered,
                      'matches': True, 'reason': None})
    return table


def _provenance(document):
    """Fields recorded for audit only; they never make a document comparable."""
    return {
        'tool': document['tool'],
        'artifacts': document['artifacts'],
        'reproduction': document['reproduction'],
        'declared_source_file_count': document['dut']['source_file_count'],
    }


def check_document(ours, external, *, ours_name=None):
    """Validate one external document against one of our extended contracts."""
    document = {
        'schema_version': SCHEMA,
        'contract': CONTRACT_ID,
        'external_schema': EXTERNAL_SCHEMA_VERSION,
        'status': 'not_comparable',
        'structural': False,
        'reasons': [],
        'fields': [],
        'provenance': None,
        'comparison': None,
        'ours': _ours_summary(ours, name=ours_name),
        'network_used': False,
        'limitations': list(LIMITATIONS),
    }
    structural = _structural_errors(external)
    if structural:
        document['structural'] = True
        document['structural_errors'] = structural
        document['reasons'] = [row['reason'] for row in structural]
        return document
    table = _condition_table(ours, external)
    document['fields'] = table
    document['provenance'] = _provenance(external)
    document['reasons'] = [row['reason'] for row in table if row['reason']]
    if document['reasons']:
        return document
    document['status'] = 'comparable'
    document['comparison'] = {
        'metric': ours['metric'],
        'total_points': ours['dut']['total_points'],
        'ours': {'covered': ours['dut']['covered_points'],
                 'total': ours['dut']['total_points']},
        'external': {'covered': external['result']['covered'],
                     'total': external['result']['total']},
        'hit_delta': external['result']['covered'] - ours['dut']['covered_points'],
        'note': ('Equal contract only: same DUT points, workload and replay budget '
                 'in the same offline mode; not a superiority claim.'),
    }
    return document


def _ours_summary(contract, *, name=None):
    return {
        'scope': name,
        'component': contract['component'],
        'metric': contract['metric'],
        'covered_points': contract['dut']['covered_points'],
        'total_points': contract['dut']['total_points'],
        'source_files_sha256': contract['dut']['source_files_sha256'],
        'point_set_normalized_sha256': contract['dut'].get('point_set_normalized_sha256'),
        'denominator_sha256': contract['dut']['denominator_sha256'],
        'saved_point_map_sha256': contract['dut']['point_set_sha256'],
        'workload': {key: contract['workload'][key] for key in (
            'identity', 'commands', 'commands_sha256', 'replies_sha256',
            'local_ticks')},
        'budget': contract['budget'],
        'mode': contract['mode'],
    }


def _scope_entries(runs_root, cpu_measurement):
    """Discover the measured scopes without trusting hand-written numbers."""
    entries = {}
    runs_root, cpu_measurement = Path(runs_root), Path(cpu_measurement)
    if runs_root.is_dir():
        for run_root in sorted(path for path in runs_root.iterdir() if path.is_dir()):
            original, fresh = run_root / 'original', run_root / 'fresh'
            if not (original / 'summary.json').is_file():
                continue
            summary, processes = _run_summary(original)
            for scope in sorted(path for path in run_root.glob('coverage-*')
                                if path.is_dir()):
                component = _scope_component(scope, processes, summary.get('target'))
                row = processes.get(component)
                if row is None or not isinstance(row.get('binary_path'), str):
                    continue
                entries[f'{run_root.name}/{scope.name}'] = {
                    'run': original, 'measurement': scope, 'component': component,
                    'cache': Path(row['binary_path']).parent,
                    'fresh': fresh}
    if cpu_measurement.is_dir():
        wb = runs_root / 'wb-timer' if runs_root.is_dir() else None
        if wb is not None and (wb / 'original/summary.json').is_file():
            summary, processes = _run_summary(wb / 'original')
            row = processes.get('cpu')
            if row is not None:
                entries['wb-timer/coverage-cpu'] = {
                    'run': wb / 'original', 'measurement': cpu_measurement,
                    'component': 'cpu', 'cache': Path(row['binary_path']).parent,
                    'fresh': wb / 'fresh'}
    return entries


def resolve_ours(*, scope=None, measurement=None, component=None, cache=None,
                 run=None, runs_root=DEFAULT_RUNS, cpu_measurement=DEFAULT_CPU_MEASUREMENT):
    """Build our extended contract for a preset scope or explicit paths."""
    if scope is not None:
        entries = _scope_entries(Path(runs_root), Path(cpu_measurement))
        if scope not in entries:
            raise ExternalCheckError('unknown-scope:' + scope)
        entry = entries[scope]
        measurement, component = entry['measurement'], entry['component']
        cache, run = entry['cache'], entry['run']
    else:
        if measurement is None or component is None or cache is None or run is None:
            raise ExternalCheckError('incomplete-our-scope')
    document = measure(run, measurement=measurement, cache=cache, component=component,
                       contract=True, extended_identity=True)
    if document.get('status') != 'available':
        raise ExternalCheckError('our-scope-unavailable:' + str(document.get('reason')))
    contract = document.get('comparison_contract')
    if not isinstance(contract, dict) or contract.get('status') != 'available':
        raise ExternalCheckError('our-contract-unavailable')
    return {'name': scope or str(measurement), 'contract': contract,
            'coverage': document['coverage'], 'measurement': str(measurement),
            'component': component}


def matching_document(contract, *, tool=None):
    """A synthetic document that reproduces our contract identity exactly."""
    dut, workload, budget = contract['dut'], contract['workload'], contract['budget']
    normalized = dut.get('point_set_normalized_sha256')
    if not _is_digest(normalized, 64):
        raise ExternalCheckError('our-contract-missing-normalized-point-set')
    return {
        'schema_version': EXTERNAL_SCHEMA_VERSION,
        'tool': tool or {'name': 'synthetic-self-test', 'version': '0.0.0',
                         'identity': 'sha256:' + '0' * 64},
        'dut': {
            'component': dut['component'],
            'source_files_sha256': dut['source_files_sha256'],
            'source_file_count': dut['source_file_count'],
            'point_set_sha256': normalized,
            'denominator_sha256': dut['denominator_sha256'],
            'total_points': dut['total_points'],
        },
        'workload': {
            'identity': workload['identity'],
            'commands': workload['commands'],
            'commands_sha256': workload['commands_sha256'],
            'replies_sha256': workload['replies_sha256'],
            'local_ticks': workload['local_ticks'],
        },
        'budget': {'replay': copy.deepcopy(budget['replay']),
                   'executed_commands': budget['executed_commands']},
        'mode': {'coverage': 'offline', 'online': False,
                 'fixed_time_coverage': False, 'instrumented': True},
        'result': {'covered': dut['covered_points'], 'total': dut['total_points']},
        'artifacts': {'coverage_data_sha256': '1' * 64,
                      'commands_sha256': workload['commands_sha256']},
        'reproduction': ('synthetic self-test document derived from '
                         f'{dut["component"]}; it is not a real measurement'),
    }


def _mutations(document):
    """Named mismatch cases; each must be rejected for its named reason."""
    def changed(**paths):
        result = copy.deepcopy(document)
        for path, value in paths.items():
            target = result
            parts = path.split('__')
            for part in parts[:-1]:
                target = target[part]
            target[parts[-1]] = value
        return result

    def removed(path):
        result = copy.deepcopy(document)
        target = result
        parts = path.split('__')
        for part in parts[:-1]:
            target = target[part]
        target.pop(parts[-1])
        return result

    return [
        ('matching', copy.deepcopy(document), None, 'comparable'),
        ('different-dut-source-set',
         changed(dut__source_files_sha256='2' * 64),
         'dut-source-set-mismatch', 'not_comparable'),
        ('different-point-set', changed(dut__point_set_sha256='3' * 64),
         'point-set-mismatch', 'not_comparable'),
        ('different-denominator', changed(dut__denominator_sha256='4' * 64),
         'denominator-mismatch', 'not_comparable'),
        ('different-total-points', changed(dut__total_points=1),
         'denominator-size-mismatch', 'not_comparable'),
        ('different-workload-sha', changed(workload__commands_sha256='5' * 64),
         'workload-mismatch', 'not_comparable'),
        ('different-command-count', changed(workload__commands=1),
         'workload-length-mismatch', 'not_comparable'),
        ('different-local-ticks', changed(workload__local_ticks=0),
         'workload-tick-mismatch', 'not_comparable'),
        ('different-replies', changed(workload__replies_sha256='6' * 64),
         'replies-mismatch', 'not_comparable'),
        ('missing-budget', removed('budget'), 'budget-missing', 'not_comparable'),
        ('different-budget', changed(budget__replay__max_commands=1),
         'budget-mismatch', 'not_comparable'),
        ('non-instrumented', changed(mode__instrumented=False),
         'non-instrumented-measurement', 'not_comparable'),
        ('online-mode', changed(mode__coverage='online', mode__online=True),
         'coverage-mode-mismatch', 'not_comparable'),
        ('fixed-time-mode',
         changed(mode__coverage='fixed_time', mode__fixed_time_coverage=True),
         'coverage-mode-mismatch', 'not_comparable'),
        ('missing-tool-identity', removed('tool__identity'),
         'tool-identity-missing', 'not_comparable'),
        ('missing-artifacts', removed('artifacts'), 'artifacts-missing',
         'not_comparable'),
        ('covered-exceeds-total',
         changed(result__covered=document['result']['total'] + 1),
         'covered-exceeds-total', 'not_comparable'),
        ('unknown-field', dict(document, unexpected_extra=1),
         'unknown-field:unexpected_extra', 'not_comparable'),
        ('wrong-schema-version', changed(schema_version='external_coverage_measurement.v0'),
         'unsupported-schema', 'not_comparable'),
    ]


def self_test(ours):
    """Run every synthetic case against one real extended contract."""
    base = matching_document(ours['contract'])
    cases = []
    for name, document, expected_reason, expected_status in _mutations(base):
        result = check_document(ours['contract'], document, ours_name=ours['name'])
        observed = result['status']
        reasons = list(result['reasons'])
        if expected_reason is not None and expected_reason not in reasons:
            reasons.append('missing-expected-reason:' + expected_reason)
        if expected_status == 'comparable' and result['comparison'] is None:
            reasons.append('missing-comparison')
        ok = observed == expected_status and not [
            reason for reason in reasons
            if reason == 'missing-expected-reason:' + expected_reason
            or reason == 'missing-comparison']
        cases.append({'case': name, 'expected_status': expected_status,
                      'observed_status': observed,
                      'expected_reason': expected_reason,
                      'reasons': result['reasons'], 'ok': ok})
    return {
        'schema_version': 'external_coverage_contract_self_test.v1',
        'scope': ours['name'],
        'cases': cases,
        'comparable': sum(1 for case in cases if case['observed_status'] == 'comparable'),
        'not_comparable': sum(1 for case in cases
                              if case['observed_status'] == 'not_comparable'),
        'checked': len(cases),
        'ok': all(case['ok'] for case in cases),
        'note': ('Every document here is synthetic and derived from a real measured '
                 'scope; no external tool measurement exists.'),
    }


def print_schema():
    return json.dumps(EXTERNAL_SCHEMA, indent=2, sort_keys=True) + '\n'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', default=None,
                        help='one of our measured scopes, e.g. wb-timer/coverage-target')
    parser.add_argument('--runs-root', type=Path, default=ROOT / DEFAULT_RUNS)
    parser.add_argument('--cpu-measurement', type=Path,
                        default=ROOT / DEFAULT_CPU_MEASUREMENT)
    parser.add_argument('--our-measurement', type=Path, default=None)
    parser.add_argument('--our-component', default=None)
    parser.add_argument('--our-cache', type=Path, default=None)
    parser.add_argument('--our-run', type=Path, default=None)
    parser.add_argument('--external', type=Path, default=None,
                        help='the other tool\'s external_coverage_measurement.v1 document')
    parser.add_argument('--output', type=Path, default=None)
    parser.add_argument('--self-test', action='store_true',
                        help='run the synthetic self-tests and exit 0 only if all pass')
    parser.add_argument('--print-schema', action='store_true',
                        help='print the strict external document schema and exit')
    args = parser.parse_args(argv)
    if args.print_schema:
        sys.stdout.write(print_schema())
        return 0
    try:
        ours = resolve_ours(scope=args.scope, measurement=args.our_measurement,
                            component=args.our_component, cache=args.our_cache,
                            run=args.our_run, runs_root=args.runs_root,
                            cpu_measurement=args.cpu_measurement)
    except (ExternalCheckError, OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({'status': 'refused', 'reason': str(error)}, sort_keys=True))
        return 2
    if args.self_test:
        report = self_test(ours)
        text = json.dumps(report, indent=2, sort_keys=True) + '\n'
        if args.output is not None:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(text, encoding='utf-8')
        else:
            sys.stdout.write(text)
        print(json.dumps({'status': 'self-test', 'ok': report['ok'],
                          'checked': report['checked'],
                          'comparable': report['comparable'],
                          'not_comparable': report['not_comparable']}, sort_keys=True))
        return 0 if report['ok'] else 1
    if args.external is None:
        print(json.dumps({'status': 'refused', 'reason': 'missing-external-document'},
                         sort_keys=True))
        return 2
    try:
        external = json.loads(args.external.read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        print(json.dumps({'status': 'refused',
                          'reason': 'external-document-unreadable:' + type(error).__name__},
                         sort_keys=True))
        return 2
    result = check_document(ours['contract'], external, ours_name=ours['name'])
    result['external'] = {'document': _relative(args.external),
                          'sha256': _sha256(args.external),
                          'supplied_by': 'caller',
                          'measurement_present': True}
    text = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding='utf-8')
    else:
        sys.stdout.write(text)
    print(json.dumps({'status': result['status'],
                      'reasons': result['reasons'],
                      'scope': ours['name']}, sort_keys=True))
    return 0 if result['status'] == 'comparable' else 1


if __name__ == '__main__':
    raise SystemExit(main())
