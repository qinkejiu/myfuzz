"""The external same-budget comparison harness: representation and verification.

We cannot run another fuzzing tool here, so the deliverable is the validator: a
strict schema for the other tool's measurement document plus a per-field check
against one of our measured scopes.  These tests pin the contract the harness
exists for -- a document that matches the measured identity is ``comparable``,
and every mismatch is rejected for its exact named reason -- and they pin the
two honesty properties: the harness never needs the network, and no test or
report may claim that an external measurement exists.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'src'))

from scripts.check_external_coverage_contract import (EXTERNAL_SCHEMA,
                                                      EXTERNAL_SCHEMA_VERSION,
                                                      ExternalCheckError,
                                                      _mutations,
                                                      check_document,
                                                      matching_document,
                                                      print_schema,
                                                      resolve_ours,
                                                      self_test)
from scripts.report_fresh_prefix_and_external_contract import (DEFAULT_RUNS,
                                                              build_report)

SCRIPT = ROOT / 'scripts/check_external_coverage_contract.py'
SCOPE = 'wb-timer/coverage-target'


@pytest.fixture(scope='module')
def ours():
    if not (ROOT / DEFAULT_RUNS).is_dir():
        pytest.skip('declared-IRQ F5 saved runs unavailable')
    try:
        return resolve_ours(scope=SCOPE)
    except ExternalCheckError as error:
        pytest.skip(str(error))


# --- schema ----------------------------------------------------------------

def test_schema_is_strict_and_documents_every_required_field():
    schema = EXTERNAL_SCHEMA
    assert schema['type'] == 'object'
    assert schema['additionalProperties'] is False
    assert set(schema['required']) == {
        'schema_version', 'tool', 'dut', 'workload', 'budget', 'mode', 'result',
        'artifacts', 'reproduction'}
    assert schema['properties']['schema_version']['const'] == EXTERNAL_SCHEMA_VERSION
    assert schema['properties']['mode']['properties']['coverage']['enum'] == [
        'offline', 'online', 'fixed_time']
    for section in ('tool', 'dut', 'workload', 'budget', 'mode', 'result',
                    'artifacts'):
        assert schema['properties'][section]['type'] == 'object'
        if section != 'artifacts':
            assert schema['properties'][section]['additionalProperties'] is False
    assert schema['properties']['dut']['required'] == [
        'component', 'source_files_sha256', 'source_file_count',
        'point_set_sha256', 'denominator_sha256', 'total_points']
    assert schema['properties']['workload']['required'] == [
        'identity', 'commands', 'commands_sha256', 'local_ticks']
    assert schema['properties']['budget']['required'] == [
        'replay', 'executed_commands']
    assert schema['properties']['result']['required'] == ['covered', 'total']
    assert schema['properties']['artifacts']['required'] == ['coverage_data_sha256']
    assert json.loads(print_schema()) == schema


def test_ours_is_a_verified_measured_scope(ours):
    assert ours['name'] == SCOPE
    contract = ours['contract']
    assert contract['status'] == 'available'
    assert contract['dut']['covered_points'] == 37
    assert contract['dut']['total_points'] == 39
    assert contract['dut']['point_set_normalized_sha256'] == \
        contract['dut']['denominator_sha256']
    assert contract['mode'] == {'coverage': 'offline', 'online': False,
                                'fixed_time_coverage': False,
                                'instrumented': True,
                                'attestation': 'recorded-prefix-replay.v1'}


# --- per-field verdicts ----------------------------------------------------

def test_matching_synthetic_document_is_comparable(ours):
    document = matching_document(ours['contract'])
    result = check_document(ours['contract'], document, ours_name=SCOPE)
    assert result['status'] == 'comparable'
    assert result['reasons'] == [] and result['structural'] is False
    assert result['network_used'] is False
    assert result['comparison']['total_points'] == 39
    assert result['comparison']['ours'] == {'covered': 37, 'total': 39}
    assert result['comparison']['hit_delta'] == 0
    assert all(row['matches'] for row in result['fields'])
    assert result['provenance']['tool']['name'] == 'synthetic-self-test'


@pytest.mark.parametrize('case, reason', [
    ('different-point-set', 'point-set-mismatch'),
    ('different-denominator', 'denominator-mismatch'),
    ('different-total-points', 'denominator-size-mismatch'),
    ('different-dut-source-set', 'dut-source-set-mismatch'),
    ('different-workload-sha', 'workload-mismatch'),
    ('different-command-count', 'workload-length-mismatch'),
    ('different-local-ticks', 'workload-tick-mismatch'),
    ('different-replies', 'replies-mismatch'),
    ('missing-budget', 'budget-missing'),
    ('different-budget', 'budget-mismatch'),
    ('non-instrumented', 'non-instrumented-measurement'),
    ('online-mode', 'coverage-mode-mismatch'),
    ('fixed-time-mode', 'coverage-mode-mismatch'),
    ('missing-tool-identity', 'tool-identity-missing'),
    ('missing-artifacts', 'artifacts-missing'),
    ('covered-exceeds-total', 'covered-exceeds-total'),
    ('unknown-field', 'unknown-field:unexpected_extra'),
    ('wrong-schema-version', 'unsupported-schema'),
])
def test_every_mismatch_is_rejected_for_its_named_reason(ours, case, reason):
    base = matching_document(ours['contract'])
    by_name = {name: document for name, document, _, _ in _mutations(base)}
    result = check_document(ours['contract'], by_name[case], ours_name=SCOPE)
    assert result['status'] == 'not_comparable'
    assert reason in result['reasons'], result['reasons']
    assert result['comparison'] is None


def test_missing_budget_is_a_structural_rejection(ours):
    document = matching_document(ours['contract'])
    document.pop('budget')
    result = check_document(ours['contract'], document)
    assert result['status'] == 'not_comparable'
    assert result['structural'] is True
    assert result['reasons'] == ['budget-missing']
    assert result['fields'] == []


def test_instrumented_vs_not_and_online_vs_offline_are_distinct_reasons(ours):
    base = matching_document(ours['contract'])
    by_name = {name: document for name, document, _, _ in _mutations(base)}
    not_instrumented = check_document(ours['contract'], by_name['non-instrumented'])
    assert not_instrumented['reasons'] == ['non-instrumented-measurement']
    online = check_document(ours['contract'], by_name['online-mode'])
    assert 'coverage-mode-mismatch' in online['reasons']
    assert 'online-mode-not-comparable' in online['reasons']


def test_covered_count_without_a_denominator_is_rejected(ours):
    document = matching_document(ours['contract'])
    document['result']['total'] = 1
    result = check_document(ours['contract'], document)
    assert result['status'] == 'not_comparable'
    assert 'denominator-size-mismatch' in result['reasons']


def test_self_test_runs_every_synthetic_case(ours):
    report = self_test(ours)
    assert report['ok'] is True
    assert report['checked'] == 19
    assert report['comparable'] == 1
    assert report['not_comparable'] == 18
    names = {case['case'] for case in report['cases']}
    assert 'matching' in names and 'missing-budget' in names
    assert 'no external tool measurement exists' in report['note']
    assert all(case['ok'] for case in report['cases'])


# --- honesty properties ----------------------------------------------------

def test_harness_performs_no_network_access():
    text = SCRIPT.read_text(encoding='utf-8')
    for forbidden in ('import socket', 'import urllib', 'import http',
                      'from urllib', 'from http', 'requests.', 'urlopen'):
        assert forbidden not in text
    assert 'network_used' not in text or "'network_used': False" in text


def test_self_test_note_never_claims_a_measurement(ours):
    report = self_test(ours)
    payload = json.dumps(report).lower()
    assert 'synthetic' in payload
    assert 'not a real measurement' in payload or 'no external' in payload


def test_report_keeps_the_external_comparison_unavailable():
    if not (ROOT / DEFAULT_RUNS).is_dir():
        pytest.skip('declared-IRQ F5 saved runs unavailable')
    report = build_report()
    external = report['external_contract']
    assert external['status'] == 'unavailable'
    assert external['reason'] == 'no-external-tool-measurement'
    assert external['network_required'] is False
    assert external['self_tests']['ok'] is True
    assert external['self_tests']['checked'] == 76
    assert 'no external covered/total is published' in external['claim']


# --- CLI -------------------------------------------------------------------

def test_cli_self_test_succeeds_and_reports_counts():
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), '--scope', SCOPE, '--self-test'],
        cwd=str(ROOT), capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    printed = json.loads(completed.stdout.strip().splitlines()[-1])
    assert printed['status'] == 'self-test'
    assert printed['ok'] is True
    assert printed['checked'] == 19
    assert printed['comparable'] == 1
    assert printed['not_comparable'] == 18


def test_cli_checks_a_matching_document_as_comparable(ours, tmp_path):
    document = matching_document(ours['contract'])
    external = tmp_path / 'external.json'
    external.write_text(json.dumps(document), encoding='utf-8')
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), '--scope', SCOPE, '--external', str(external),
         '--output', str(tmp_path / 'check.json')],
        cwd=str(ROOT), capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    printed = json.loads(completed.stdout.strip().splitlines()[-1])
    assert printed['status'] == 'comparable'
    written = json.loads((tmp_path / 'check.json').read_text(encoding='utf-8'))
    assert written['status'] == 'comparable'
    assert written['external']['supplied_by'] == 'caller'
    assert written['external']['measurement_present'] is True
    assert len(written['external']['sha256']) == 64


def test_cli_rejects_a_mismatching_document_with_reasons(ours, tmp_path):
    base = matching_document(ours['contract'])
    by_name = {name: document for name, document, _, _ in _mutations(base)}
    external = tmp_path / 'external.json'
    external.write_text(json.dumps(by_name['different-point-set']), encoding='utf-8')
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), '--scope', SCOPE, '--external', str(external),
         '--output', str(tmp_path / 'check.json')],
        cwd=str(ROOT), capture_output=True, text=True)
    assert completed.returncode == 1
    printed = json.loads(completed.stdout.strip().splitlines()[-1])
    assert printed['status'] == 'not_comparable'
    assert 'point-set-mismatch' in printed['reasons']
    written = json.loads((tmp_path / 'check.json').read_text(encoding='utf-8'))
    assert written['status'] == 'not_comparable'
    rows = {row['field']: row for row in written['fields']}
    assert rows['dut.point_set_sha256']['matches'] is False
    assert rows['dut.point_set_sha256']['reason'] == 'point-set-mismatch'
    assert written['comparison'] is None


def test_explicit_measurement_path_resolves_the_fresh_side(tmp_path):
    from scripts.report_fresh_prefix_and_external_contract import DEFAULT_FRESH
    fresh = ROOT / DEFAULT_FRESH
    measurement = fresh / 'wb-timer' / 'coverage-target'
    trace = fresh / 'wb-timer' / 'normalized-local-command-trace.json'
    if not (measurement / 'coverage.json').is_file() or not trace.is_file():
        pytest.skip('fresh instrumented measurement unavailable')
    original, processes = None, None
    summary = json.loads((ROOT / DEFAULT_RUNS / 'wb-timer' / 'original'
                          / 'summary.json').read_text(encoding='utf-8'))
    caches = {row['component']: Path(row['binary_path']).parent
              for row in summary['processes']}
    explicit = resolve_ours(measurement=measurement, component='wb_timer_active',
                            cache=caches['wb_timer_active'], run=trace)
    assert explicit['contract']['status'] == 'available'
    document = matching_document(explicit['contract'])
    result = check_document(explicit['contract'], document, ours_name='fresh-side')
    assert result['status'] == 'comparable'
    assert result['comparison']['ours'] == {'covered': 37, 'total': 39}


def test_cli_refuses_without_an_external_document():
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), '--scope', SCOPE],
        cwd=str(ROOT), capture_output=True, text=True)
    assert completed.returncode == 2
    printed = json.loads(completed.stdout.strip().splitlines()[-1])
    assert printed['status'] == 'refused'
    assert printed['reason'] == 'missing-external-document'


def test_cli_prints_the_schema():
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), '--print-schema'],
        cwd=str(ROOT), capture_output=True, text=True)
    assert completed.returncode == 0
    assert json.loads(completed.stdout) == EXTERNAL_SCHEMA


def test_cli_refuses_an_unknown_scope():
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), '--scope', 'nope/coverage-target',
         '--self-test'],
        cwd=str(ROOT), capture_output=True, text=True)
    assert completed.returncode == 2
    printed = json.loads(completed.stdout.strip().splitlines()[-1])
    assert printed['reason'] == 'unknown-scope:nope/coverage-target'
