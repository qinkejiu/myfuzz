"""P7-D: the graded capability report, and the evidence each tier needs.

The report's whole point is that a tier is claimed **only** with the artifact and
the fact that establish it.  These tests pin that property rather than the
report's shape:

* one test walks all six tiers of the authoritative ladder and asserts each one
  is awarded at exactly the moment its own evidence arrives -- and not before;
* one test asserts, per adjacent pair, that the lower tier never implies the
  upper one (``Generated`` does not give ``RTL operational``, a run existing does
  not give ``Cross-component accepted``, coverage numbers do not give
  ``Bug confirmed``);
* one test asserts a tier whose evidence is absent is reported as *grade not
  claimed* with a reason, and is distinguishable from P7-C's ``unsupported``;
* one test feeds the report a **real** ``compiled_paths.v1`` produced by the real
  :func:`myfuzz.scenario.compiled_paths.compile_paths` over a real P7-B harness
  set, and proves the report consumes it without re-deriving anything;
* one test asserts every ``unsupported`` path's named reasons pass through
  verbatim, including a sentinel reason the report could not have invented.

The composition is the repository's own pinned Ibex + PULP GPIO pair, generated
by the real P7-B entry point and compiled by the real P7-C compiler.  The saved
session evidence used by the cheap tests is a *constructed* session directory
(``report.json`` + ``receipts.jsonl``) whose field names are copied from a real
recorded session; the one test that uses a really recorded session says so and
skips when this checkout does not carry it.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from myfuzz.local_harness.harness_set import generate_harness_set, load_compose
from myfuzz.scenario.capability_report import (
    CAPABILITY_REPORT_SCHEMA, CAPABILITY_TIERS, DISPOSITION_NOT_CLAIMED,
    FINDING_CALIBRATION, FINDING_INJECTED, FINDING_NATURAL, STATUS_GRADED,
    STATUS_SKIPPED_UNAVAILABLE, TIER_BUG_CONFIRMED, TIER_CATALOG,
    TIER_COVERAGE_GUIDED_SEARCHED, TIER_CROSS_COMPONENT_ACCEPTED, TIER_GENERATED,
    TIER_RTL_OPERATIONAL, UNAVAILABLE_SCHEMA, CapabilityReportRefused,
    build_capability_report)
from myfuzz.scenario.compiled_paths import (STATUS_EXECUTABLE, STATUS_UNSUPPORTED,
                                            compile_paths,
                                            load_path_compile_request)
from myfuzz.scenario.p5_arm_metrics import CHECKLIST_METRIC_GROUPS, GROUP_SPECS

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts' / 'report_capability.py'

CPU_PROFILE = 'configs/cpus/ibex_obi_local/component_profile.json'
GPIO_PROFILE = 'configs/peripherals/pulp_gpio/component_profile.json'
GPIO_CAPABILITY = 'configs/peripherals/pulp_gpio/test_capability.json'

ROM = {'resource_id': 'rom0', 'component_instance': 'cpu', 'base': 65536,
       'size': 32768, 'read': True, 'write': False, 'execute': True,
       'initialization_policy': 'preload'}
RAM = {'resource_id': 'ram0', 'component_instance': 'cpu', 'base': 2147483648,
       'size': 65536, 'read': True, 'write': True, 'execute': False,
       'initialization_policy': 'preload'}

#: A really recorded scenario online session.  It is not tracked by git (``runs/``
#: is a local artifact tree), so the test that uses it skips when it is absent.
REAL_SESSION = ROOT / 'runs' / 'current-dataflow-p5-chain-acceptance-20261007-online'

#: A consumption feature id: ``kind:producer:consumer`` with two distinct
#: components (interaction_feedback.v1 stages carry exactly that shape).
CROSS_FEATURE = 'bound_delivered:cpu:gpio'
#: An ordering-only feature id: interaction_feedback.py:472 builds
#: ``observed_path:<kind>:<components>`` from ``observed_paths``, which the plan
#: (line 90) says is *not* a causal hit.
ORDERING_FEATURE = 'observed_path:write_bound_then_read:cpu:gpio:cpu'


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True), encoding='utf-8')
    return path


# ---------------------------------------------------------------------------
# real P7-B -> P7-C inputs
# ---------------------------------------------------------------------------

@pytest.fixture(scope='module')
def chain(tmp_path_factory):
    """A real harness set and the real compilation of it.

    ``generate_harness_set`` renders both harnesses and verifies both source
    locks; ``compile_paths`` is handed the ``wiring_contract.v1`` the generator
    wrote.  Nothing is mocked.
    """
    directory = tmp_path_factory.mktemp('p7d-chain')
    write_json(directory / 'requests/cpu.json', {
        'schema_version': 'local_harness.v1', 'profile_path': CPU_PROFILE,
        'instance_id': 'cpu', 'reset_assert_ticks': 2, 'reset_release_ticks': 2,
        'max_wait_cycles': 16})
    write_json(directory / 'requests/gpio.json', {
        'schema_version': 'local_harness.v1', 'profile_path': GPIO_PROFILE,
        'instance_id': 'gpio', 'reset_assert_ticks': 2, 'reset_release_ticks': 2,
        'max_wait_cycles': 16})
    compose_path = write_json(directory / 'compose.json', {
        'schema_version': 'harness_compose.v1',
        'cpu': {'instance_id': 'cpu', 'request': 'requests/cpu.json',
                'data_endpoint': 'processor.data'},
        'devices': [{'device_id': 'gpio', 'instance_id': 'gpio',
                     'request': 'requests/gpio.json',
                     'bus_endpoint': 'gpio.bus',
                     'base': 0x40000000, 'size': 0x1000}],
        'memory': [ROM, RAM]})
    compose = load_compose(compose_path, base_dir=ROOT)
    harness_set = generate_harness_set(compose, base_dir=ROOT,
                                       compose_base=directory,
                                       output_root=directory / 'generated')
    request = write_json(directory / 'request.json', {
        'schema_version': 'path_compile_request.v1',
        'cpu': {'instance_id': 'cpu', 'profile': CPU_PROFILE,
                'data_endpoint': 'processor.data',
                'instruction_endpoint': 'processor.instruction'},
        'devices': [{'device_id': 'gpio', 'instance_id': 'gpio',
                     'profile': GPIO_PROFILE,
                     'test_capability': GPIO_CAPABILITY}],
        'wiring': {'source': str(directory / 'generated' / 'wiring_contract.json')}})
    compiled = compile_paths(load_path_compile_request(request, base_dir=ROOT))
    return {
        'directory': directory,
        'harness_set': harness_set,
        'harness_set_path': directory / 'generated' / 'harness_set.json',
        'compiled': compiled,
        'compiled_path': write_json(directory / 'compiled_paths.v1.json', compiled),
    }


# ---------------------------------------------------------------------------
# session / findings / replay documents
# ---------------------------------------------------------------------------

def receipt(case_id, flow_id, *, ticks=None, coverage='00000000', features=(),
            hint=None, deltas=None, status='complete',
            disposition_reason='rtl_case_committed', direction='CPU_TO_IP'):
    """One ``receipts.jsonl`` row, with the field names a real run writes."""
    ticks = {'cpu': 32, 'gpio': 32} if ticks is None else dict(ticks)
    return {
        'applied_hint_sequence': hint,
        'candidate_disposition': 'admitted',
        'candidate_disposition_reason': disposition_reason,
        'case_id': case_id,
        'coverage_hex': coverage,
        'direction': direction,
        'flow_id': flow_id,
        'interaction_feature_deltas': dict(deltas or {}),
        'interaction_new_features': list(features),
        'local_ticks': ticks,
        'path_id': hashlib.sha256(case_id.encode()).hexdigest(),
        'source_id': 'cpu.online_instruction',
        'status': status,
        'target_id': f'{flow_id.lower()}.target',
        'total_local_ticks': sum(ticks.values()),
        'violations': [],
    }


def write_session(directory, rows, *, report=None):
    """Write a session directory the shipped p5 reader can analyze."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'receipts.jsonl').write_text(
        ''.join(json.dumps(row, sort_keys=True) + '\n' for row in rows),
        encoding='utf-8')
    statuses = {}
    for row in rows:
        statuses[row['status']] = statuses.get(row['status'], 0) + 1
    document = {
        'client_returncode': 0,
        'clock_model': 'independent_local_ticks_and_causal_order',
        'completed_feedback_exchanges': 2,
        'effective_search_seconds': 1.0,
        'elapsed_seconds': 1.5,
        'execution_mode': 'online_cases',
        'execution_status': 'complete',
        'mutation_hint_schema': 'scenario_mutation_hint.v1',
        'mutation_hint_updates': 3,
        'record_semantics': 'mutation_decisions_not_dut_cycles',
        'session_status': 'complete',
        'statuses': statuses,
        'tests': len(rows),
        'total_local_ticks_semantics': 'sum_of_independent_local_ticks_cost_only',
    }
    document.update(report or {})
    write_json(directory / 'report.json', document)
    return directory


def findings_document(rows):
    return {'schema_version': 'capability_checker_findings.v1', 'findings': rows}


def fresh_verification(*, matches=True, first_difference=None, scope='full'):
    return {'matches': matches, 'first_difference': first_difference,
            'difference_context': None, 'verification_scope': scope,
            'event_count': 12, 'semantic_sha256': 'ab' * 32}


@pytest.fixture(scope='module')
def evidence(chain, tmp_path_factory):
    """The session / findings / replay documents the tier tests combine.

    Cheap by design: the constructed session directories carry the field names a
    real recorded session writes, and the one test that uses the real recorded
    session is separate and skips when the checkout does not have it.
    """
    base = tmp_path_factory.mktemp('p7d-evidence')
    documents = {
        'session_rtl': write_session(
            base / 'session-rtl',
            [receipt('case-rtl-0', 'F4', coverage='00000000')],
            report={'mutation_hint_updates': 0, 'completed_feedback_exchanges': 0}),
        'session_ordering': write_session(
            base / 'session-ordering',
            [receipt('case-ordering-0', 'F4', features=[ORDERING_FEATURE])],
            report={'mutation_hint_updates': 0}),
        'session_cross': write_session(
            base / 'session-cross',
            [receipt('case-cross-0', 'F4', features=[CROSS_FEATURE])],
            report={'mutation_hint_updates': 0}),
        'session_coverage': write_session(
            base / 'session-coverage',
            [receipt('case-coverage-0', 'F4', coverage='00000001',
                     features=[CROSS_FEATURE], hint=7)],
            report={'mutation_hint_updates': 3}),
        'session_native': write_session(
            base / 'session-native',
            [receipt('case-native-0', 'F4', coverage='00000001',
                     disposition_reason='rejected')],
            report={'mutation_hint_updates': 3}),
    }
    documents['findings_natural'] = write_json(base / 'findings-natural.json',
                                               findings_document([
        {'finding_id': 'finding-natural-1', 'flow_id': 'F4',
         'classification': FINDING_NATURAL, 'component': 'cpu',
         'assertion_class': 'cross_component_provenance_and_order',
         'expectation_id': 'cross_component.chain_certificate_hops',
         'outcome': 'violated', 'detail': 'a real cross-component hop was lost'}]))
    documents['findings_injected'] = write_json(base / 'findings-injected.json',
                                                findings_document([
        {'finding_id': 'finding-injected-1', 'flow_id': 'F4',
         'classification': FINDING_INJECTED, 'component': 'cpu',
         'outcome': 'violated', 'detail': 'controlled fault injection'}]))
    documents['findings_calibration'] = write_json(
        base / 'findings-calibration.json', findings_document([
            {'finding_id': 'finding-calibration-1', 'flow_id': 'F4',
             'classification': FINDING_CALIBRATION, 'component': 'cpu',
             'outcome': 'violated', 'detail': 'checker calibration'}]))
    documents['fresh_full'] = write_json(base / 'fresh-verification.json',
                                         fresh_verification())
    documents['fresh_partial'] = write_json(
        base / 'fresh-verification-partial.json',
        fresh_verification(scope='bounded_prefix'))
    return documents


# ---------------------------------------------------------------------------
# small readers
# ---------------------------------------------------------------------------

def grade(chain, **kwargs):
    kwargs.setdefault('base_dir', ROOT)
    return build_capability_report(chain['compiled_path'], **kwargs)


def path_record(report, flow_id):
    rows = [row for row in report['paths'] if row['flow_id'] == flow_id]
    assert len(rows) == 1, f'{flow_id} has {len(rows)} records'
    return rows[0]


def component_record(report, instance_id):
    rows = [row for row in report['components']
            if row['instance_id'] == instance_id]
    assert len(rows) == 1, f'{instance_id} has {len(rows)} records'
    return rows[0]


def tier_row(subject, tier):
    rows = [row for row in subject['tiers'] if row['tier'] == tier]
    assert len(rows) == 1, f'{subject["subject"]} has no single {tier} row'
    return rows[0]


def assert_awarded(subject, expected):
    assert subject['awarded'] == list(expected), (
        f'{subject["subject"]} {subject.get("flow_id") or subject.get("instance_id")} '
        f'awarded {subject["awarded"]}, expected {list(expected)}: '
        + json.dumps([row for row in subject['tiers'] if not row['claimed']],
                     ensure_ascii=False)[:800])


# ---------------------------------------------------------------------------
# the six-tier walk and the no-implication pairs
# ---------------------------------------------------------------------------

def test_six_tiers_are_awarded_only_from_their_own_evidence(chain, evidence):
    """Each tier arrives exactly when its own artifact does -- and not before."""
    session = evidence['session_rtl']
    stages = [
        # (extra inputs, expected awarded tiers, the tier that must still be
        #  missing and a fragment its reason has to name)
        ({}, [TIER_CATALOG], TIER_GENERATED, 'harness_set'),
        ({'harness_set': chain['harness_set_path']},
         [TIER_CATALOG, TIER_GENERATED], TIER_RTL_OPERATIONAL, 'session'),
        ({'harness_set': chain['harness_set_path'], 'session': session},
         [TIER_CATALOG, TIER_GENERATED, TIER_RTL_OPERATIONAL],
         TIER_CROSS_COMPONENT_ACCEPTED, 'interaction'),
        ({'harness_set': chain['harness_set_path'],
          'session': evidence['session_cross']},
         [TIER_CATALOG, TIER_GENERATED, TIER_RTL_OPERATIONAL,
          TIER_CROSS_COMPONENT_ACCEPTED],
         TIER_COVERAGE_GUIDED_SEARCHED, 'coverage'),
        ({'harness_set': chain['harness_set_path'],
          'session': evidence['session_coverage']},
         [TIER_CATALOG, TIER_GENERATED, TIER_RTL_OPERATIONAL,
          TIER_CROSS_COMPONENT_ACCEPTED, TIER_COVERAGE_GUIDED_SEARCHED],
         TIER_BUG_CONFIRMED, 'finding'),
        ({'harness_set': chain['harness_set_path'],
          'session': evidence['session_coverage'],
          'checker_findings': evidence['findings_natural'],
          'fresh_verification': evidence['fresh_full']},
         list(CAPABILITY_TIERS), None, None),
    ]
    assert tuple(CAPABILITY_TIERS) == (
        'Catalog', 'Generated', 'RTL operational', 'Cross-component accepted',
        'Coverage-guided searched', 'Bug confirmed')

    for index, (extra, expected, missing, fragment) in enumerate(stages):
        report = grade(chain, **extra)
        for subject in (path_record(report, 'F4'), component_record(report, 'cpu')):
            assert_awarded(subject, expected)
            assert subject['highest_claimed'] == expected[-1]
            if missing is not None:
                row = tier_row(subject, missing)
                assert row['claimed'] is False, (index, subject['subject'], missing)
                assert row['disposition'] == DISPOSITION_NOT_CLAIMED
                assert fragment in row['reason'], (index, missing, row['reason'])
            # every awarded tier carries its own artifact+fact evidence
            for tier in expected:
                row = tier_row(subject, tier)
                assert row['claimed'] is True
                assert row['disposition'] == 'awarded'
                assert row['evidence'], (index, tier)
                for entry in row['evidence']:
                    assert entry['supports'] == tier
                    assert isinstance(entry['artifact'], str) and entry['artifact']
                    assert isinstance(entry['fact'], str) and entry['fact']


def test_no_implication_between_each_adjacent_pair(chain, evidence):
    """No tier may be reached by sitting next to the one below it."""
    harness = chain['harness_set_path']
    session = evidence['session_rtl']
    states = [
        ({}, TIER_CATALOG, TIER_GENERATED, 'harness_set'),
        ({'harness_set': harness}, TIER_GENERATED, TIER_RTL_OPERATIONAL,
         'session'),
        ({'harness_set': harness, 'session': session},
         TIER_RTL_OPERATIONAL, TIER_CROSS_COMPONENT_ACCEPTED, 'interaction'),
        ({'harness_set': harness, 'session': evidence['session_cross']},
         TIER_CROSS_COMPONENT_ACCEPTED, TIER_COVERAGE_GUIDED_SEARCHED,
         'coverage'),
    ]
    for extra, lower, upper, fragment in states:
        report = grade(chain, **extra)
        subject = path_record(report, 'F4')
        assert tier_row(subject, lower)['claimed'] is True, (lower, extra)
        row = tier_row(subject, upper)
        assert row['claimed'] is False, (
            f'{lower} implied {upper}: {json.dumps(row, ensure_ascii=False)[:400]}')
        assert row['disposition'] == DISPOSITION_NOT_CLAIMED
        assert fragment in row['reason'], (upper, row['reason'])

    # Coverage numbers plus a matching fresh replay still do not confirm a bug.
    report = grade(chain, harness_set=harness, session=evidence['session_coverage'],
                   fresh_verification=evidence['fresh_full'])
    subject = path_record(report, 'F4')
    assert tier_row(subject, TIER_COVERAGE_GUIDED_SEARCHED)['claimed'] is True
    row = tier_row(subject, TIER_BUG_CONFIRMED)
    assert row['claimed'] is False
    assert 'finding' in row['reason']
    # And an ordering-only observation is not cross-component propagation.
    report = grade(chain, harness_set=harness,
                   session=evidence['session_ordering'])
    subject = path_record(report, 'F4')
    assert tier_row(subject, TIER_RTL_OPERATIONAL)['claimed'] is True
    row = tier_row(subject, TIER_CROSS_COMPONENT_ACCEPTED)
    assert row['claimed'] is False
    assert ORDERING_FEATURE in row['reason'] or 'ordering' in row['reason']


def test_a_generated_harness_set_alone_never_yields_rtl_operational(chain):
    """A ``generated`` harness set is generation evidence and nothing more."""
    report = grade(chain, harness_set=chain['harness_set_path'])
    for subject in (path_record(report, 'F4'), component_record(report, 'cpu')):
        assert_awarded(subject, [TIER_CATALOG, TIER_GENERATED])
        row = tier_row(subject, TIER_RTL_OPERATIONAL)
        assert row['claimed'] is False
        assert 'no saved online session' in row['reason']
        assert 'transaction' in row['reason']


def test_a_run_alone_never_yields_cross_component_acceptance(chain, evidence):
    """Real local transactions are not a cross-component propagation claim."""
    report = grade(chain, harness_set=chain['harness_set_path'],
                   session=evidence['session_rtl'])
    subject = path_record(report, 'F4')
    assert tier_row(subject, TIER_RTL_OPERATIONAL)['claimed'] is True
    row = tier_row(subject, TIER_CROSS_COMPONENT_ACCEPTED)
    assert row['claimed'] is False
    assert 'interaction' in row['reason']

    # A receipt that is not an admitted, committed RTL case is not even that.
    report = grade(chain, harness_set=chain['harness_set_path'],
                   session=evidence['session_native'])
    row = tier_row(path_record(report, 'F4'), TIER_RTL_OPERATIONAL)
    assert row['claimed'] is False
    assert 'rtl_case_committed' in row['reason'] or 'committed' in row['reason']


def test_coverage_numbers_alone_never_confirm_a_bug(chain, evidence):
    """Coverage plus a matching replay is still not a confirmed defect."""
    report = grade(chain, harness_set=chain['harness_set_path'],
                   session=evidence['session_coverage'],
                   fresh_verification=evidence['fresh_full'])
    subject = path_record(report, 'F4')
    assert tier_row(subject, TIER_COVERAGE_GUIDED_SEARCHED)['claimed'] is True
    row = tier_row(subject, TIER_BUG_CONFIRMED)
    assert row['claimed'] is False
    assert 'natural' in row['reason']

    for key, fragment in (('findings_injected', 'injected'),
                          ('findings_calibration', 'calibration')):
        report = grade(chain, harness_set=chain['harness_set_path'],
                       session=evidence['session_coverage'],
                       checker_findings=evidence[key],
                       fresh_verification=evidence['fresh_full'])
        row = tier_row(path_record(report, 'F4'), TIER_BUG_CONFIRMED)
        assert row['claimed'] is False, key
        assert fragment in row['reason'], (key, row['reason'])

    # A natural finding without the full fresh replay does not either.
    report = grade(chain, harness_set=chain['harness_set_path'],
                   session=evidence['session_coverage'],
                   checker_findings=evidence['findings_natural'])
    row = tier_row(path_record(report, 'F4'), TIER_BUG_CONFIRMED)
    assert row['claimed'] is False
    assert 'fresh' in row['reason'] or 'replay' in row['reason']

    report = grade(chain, harness_set=chain['harness_set_path'],
                   session=evidence['session_coverage'],
                   checker_findings=evidence['findings_natural'],
                   fresh_verification=evidence['fresh_partial'])
    row = tier_row(path_record(report, 'F4'), TIER_BUG_CONFIRMED)
    assert row['claimed'] is False
    assert 'full' in row['reason'] or 'scope' in row['reason']


# ---------------------------------------------------------------------------
# "grade not claimed" versus "unsupported"
# ---------------------------------------------------------------------------

def test_missing_evidence_is_grade_not_claimed_not_unsupported(chain):
    """Nothing here proves it is exactly as reportable as it cannot be done."""
    report = grade(chain)

    executable = path_record(report, 'F4')
    assert executable['compiled_status'] == STATUS_EXECUTABLE
    assert executable['unsupported'] is None
    for tier in CAPABILITY_TIERS[1:]:
        row = tier_row(executable, tier)
        assert row['claimed'] is False
        assert row['disposition'] == DISPOSITION_NOT_CLAIMED
        assert 'unsupported' not in row['reason'].lower(), row['reason']
        assert 'evidence' not in row

    unsupported = path_record(report, 'F5')
    assert unsupported['compiled_status'] == STATUS_UNSUPPORTED
    assert unsupported['unsupported']['code'] == 'interrupt-delivery-missing'
    assert unsupported['unsupported'] == next(
        row['reason'] for row in chain['compiled']['paths']
        if row['flow_id'] == 'F5')
    # The compiled status is reported as a status; the tier rows still say
    # "grade not claimed", because a tier is not a status.
    assert unsupported['status'] == STATUS_GRADED
    for row in unsupported['tiers']:
        assert row['disposition'] in ('awarded', DISPOSITION_NOT_CLAIMED)
        assert row['disposition'] != STATUS_UNSUPPORTED

    # The report separates the two lists: unsupported reasons come from P7-C,
    # not-claimed reasons are this report's own missing facts.
    assert {row['flow_id'] for row in report['unsupported_reasons']} == {'F5', 'F6'}
    assert all(row['code'] and row['pointer'] and row['missing']
               for row in report['unsupported_reasons'])
    unsupported_flows = {row['flow_id'] for row in report['unsupported_reasons']}
    for record in report['paths']:
        if record['compiled_status'] == STATUS_EXECUTABLE:
            assert record['flow_id'] not in unsupported_flows


def test_a_document_without_identity_grades_paths_and_names_the_gap():
    """A gap is named, never silently dropped: no identity means no components."""
    document = {'schema_version': 'compiled_paths.v1', 'paths': [
        {'path_id': 'F1:x', 'flow_id': 'F1', 'flow_name': 'instruction_stream',
         'status': STATUS_EXECUTABLE, 'reason': {'code': None, 'pointer': None,
                                                 'detail': None, 'missing': []},
         'definition': {'authority': 'plan:77'}, 'runtime_path_identity': None}],
        'counts': {'executable': 1, 'unsupported': 0, 'total': 1}}
    report = build_capability_report(document, base_dir=ROOT)
    assert report['components'] == []
    assert report['counts']['components'] == 0
    assert_awarded(report['paths'][0], [TIER_CATALOG])
    limits = {row['quantity']: row['reason'] for row in report['limits']}
    assert 'identity' in limits and 'no component subject is graded' in limits['identity']
    for flow_id in ('F2', 'F3', 'F4', 'F5', 'F6'):
        assert f'paths.{flow_id}' in limits, flow_id


def test_every_tier_row_is_well_formed(chain, evidence):
    """Claimed means evidence; not claimed means a reason; never both."""
    reports = [
        grade(chain),
        grade(chain, harness_set=chain['harness_set_path'],
              session=evidence['session_coverage']),
    ]
    for report in reports:
        for subject in [*report['paths'], *report['components']]:
            assert [row['tier'] for row in subject['tiers']] == list(CAPABILITY_TIERS)
            awarded = []
            for row in subject['tiers']:
                if row['claimed']:
                    awarded.append(row['tier'])
                    assert row['disposition'] == 'awarded'
                    assert row['evidence']
                    assert 'reason' not in row
                    for entry in row['evidence']:
                        assert set(entry) == {'artifact', 'fact', 'supports'}
                        assert entry['supports'] == row['tier']
                        assert entry['artifact'] and entry['fact']
                else:
                    assert row['disposition'] == DISPOSITION_NOT_CLAIMED
                    assert isinstance(row['reason'], str) and row['reason']
                    assert 'evidence' not in row
            assert subject['awarded'] == awarded
            assert subject['highest_claimed'] == (awarded[-1] if awarded else None)
            assert subject['not_claimed'] == [
                tier for tier in CAPABILITY_TIERS if tier not in awarded]
            assert 'generated' not in subject['not_claimed']


# ---------------------------------------------------------------------------
# the real compiled_paths.v1, consumed as given
# ---------------------------------------------------------------------------

def test_real_compiled_paths_are_consumed_without_re_derivation(chain):
    """The report reports what P7-C states, including a sentinel it cannot derive."""
    compiled = chain['compiled']
    report = grade(chain)

    assert report['inputs']['compiled_paths']['counts'] == compiled['counts']
    assert report['counts']['compiled_paths'] == compiled['counts']
    for row in compiled['paths']:
        record = path_record(report, row['flow_id'])
        assert record['compiled']['path_id'] == row['path_id']
        assert record['compiled']['status'] == row['status']
        assert record['compiled']['reason'] == row['reason']
        assert record['compiled']['runtime_path_identity'] == (
            row['runtime_path_identity'])
    assert [row['flow_id'] for row in report['paths']] == [
        row['flow_id'] for row in compiled['paths']]

    # A perturbation the report has no way to compute must survive unchanged;
    # a re-deriving report would turn this F1 back into executable.
    perturbed = copy.deepcopy(compiled)
    sentinel = {
        'code': 'sentinel-not-derived',
        'pointer': '/sentinel',
        'detail': {'requires': '声明缺失 → 无法编译', 'nested': [1, 2, {'x': None}]},
        'missing': [{'code': 'sentinel-not-derived', 'pointer': '/sentinel',
                     'detail': {'requires': '声明缺失 → 无法编译'}}],
    }
    perturbed['paths'][0]['status'] = STATUS_UNSUPPORTED
    perturbed['paths'][0]['reason'] = sentinel
    perturbed['paths'][0]['runtime_path_identity'] = None
    report = build_capability_report(perturbed, base_dir=ROOT)

    record = path_record(report, 'F1')
    assert record['compiled_status'] == STATUS_UNSUPPORTED
    assert record['compiled']['reason'] == sentinel
    assert record['unsupported'] == sentinel
    assert_awarded(record, [TIER_CATALOG])
    assert 'sentinel-not-derived' in tier_row(
        record, TIER_GENERATED)['reason']
    assert 'sentinel-not-derived' in json.dumps(report['unsupported_reasons'],
                                                ensure_ascii=False)

    # Deterministic: the same inputs grade to the same document.
    assert grade(chain) == grade(chain)


def test_unsupported_reasons_pass_through_verbatim(chain):
    """Every named reason is carried as P7-C wrote it, in its own words."""
    compiled = chain['compiled']
    report = grade(chain)

    expected = [row for row in compiled['paths']
                if row['status'] == STATUS_UNSUPPORTED]
    assert expected
    rows = {row['flow_id']: row for row in report['unsupported_reasons']}
    for path in expected:
        carried = rows[path['flow_id']]
        assert carried['code'] == path['reason']['code']
        assert carried['pointer'] == path['reason']['pointer']
        assert carried['missing'] == path['reason']['missing']
        assert carried['detail'] == path['reason']['detail']
        record = path_record(report, path['flow_id'])
        assert record['compiled']['reason'] == path['reason']

    missing_total = sum(len(path['reason']['missing']) for path in expected)
    assert sum(len(row['missing']) for row in report['unsupported_reasons']) == (
        missing_total)

    # A reason with a pointer into a document this report never reads survives.
    perturbed = copy.deepcopy(compiled)
    sentinel = {'code': 'not-json-clean', 'pointer': '/devices/0/profile/interrupts',
                'detail': {'requires': '声明IRQ极性<missing>', 'observed': None},
                'missing': [{'code': 'not-json-clean',
                             'pointer': '/devices/0/profile/interrupts',
                             'detail': {'requires': '声明IRQ极性<missing>'}}]}
    perturbed['paths'][4]['reason'] = sentinel
    report = build_capability_report(perturbed, base_dir=ROOT)
    assert json.dumps(report, ensure_ascii=False, sort_keys=True).count(
        '声明IRQ极性<missing>') >= 3
    assert path_record(report, 'F5')['compiled']['reason'] == sentinel


# ---------------------------------------------------------------------------
# per-path and per-component grades are separate
# ---------------------------------------------------------------------------

def test_per_component_and_per_path_grades_are_separate(chain, evidence):
    """A component can be Generated while the path it would serve is unsupported."""
    report = grade(chain, harness_set=chain['harness_set_path'],
                   session=evidence['session_rtl'])

    gpio = component_record(report, 'gpio')
    assert_awarded(gpio, [TIER_CATALOG, TIER_GENERATED, TIER_RTL_OPERATIONAL])
    f5 = path_record(report, 'F5')
    assert f5['unsupported']['code'] == 'interrupt-delivery-missing'
    assert_awarded(f5, [TIER_CATALOG])
    row = tier_row(f5, TIER_RTL_OPERATIONAL)
    assert row['claimed'] is False
    assert 'interrupt-delivery-missing' in row['reason']
    # Even a real run that did execute an F5 case cannot lift an unsupported
    # compiled path: P7-C states this composition cannot walk it.
    assert report['counts']['executable'] == 4
    assert report['counts']['unsupported'] == 2
    assert report['counts']['components'] == 2


# ---------------------------------------------------------------------------
# build cost and throughput are mandatory sections
# ---------------------------------------------------------------------------

def test_build_cost_and_throughput_are_mandatory_named_absences(chain, evidence):
    """No session means a named absence, never a zero that reads as a result."""
    report = grade(chain, harness_set=chain['harness_set_path'])

    throughput = report['throughput']
    assert throughput['status'] == 'not_measured'
    assert throughput['absences']
    assert any('no saved online session' in row['reason']
               for row in throughput['absences'])
    for group in ('effective_cases_per_second', 'certified_chains_per_second'):
        rows = throughput['groups'][group]
        assert [row['leaf'] for row in rows] == [
            leaf for leaf, _ in GROUP_SPECS[group]]
        for row in rows:
            assert row['value'] is None, row
            assert row['source']
            assert row['reason']
    assert throughput['p5_arm_metrics']['checklist_metric_groups'] == list(
        CHECKLIST_METRIC_GROUPS)

    build_cost = report['build_cost']
    assert build_cost['status'] == 'declared'
    assert [row['instance_id'] for row in build_cost['components']] == [
        'cpu', 'gpio']
    for row in build_cost['components']:
        assert row['artifact_digest']
        assert row['built'] is False
        assert row['binary'] is None
    assert any('binary=null' in row['reason'] for row in build_cost['absences'])
    assert 'generat' in build_cost['not_a_substitute_for']


def test_throughput_reuses_the_shipped_p5_grouping(chain, evidence):
    """The measured values are the shipped reader's values, leaf for leaf."""
    from myfuzz.scenario.p5_arm_metrics import analyze_arm

    session = evidence['session_coverage']
    report = grade(chain, harness_set=chain['harness_set_path'], session=session)
    arm = analyze_arm(session)

    assert report['session']['arm_kind'] == arm['arm_kind']
    assert report['session']['run_id'] == arm['run_id']
    assert report['throughput']['status'] == 'measured'
    groups = [
        ('effective_cases_per_second',
         report['throughput']['groups']['effective_cases_per_second']),
        ('certified_chains_per_second',
         report['throughput']['groups']['certified_chains_per_second']),
        ('one_time_compile_init', report['build_cost']['group']),
    ]
    for group, group_rows in groups:
        rows = {row['leaf']: row for row in group_rows}
        assert list(rows) == [leaf for leaf, _ in GROUP_SPECS[group]]
        for leaf, entry in arm['metrics'][group].items():
            assert rows[leaf]['value'] == entry['value'], (group, leaf)
            assert rows[leaf]['source'] == entry['source'], (group, leaf)
            assert rows[leaf]['reason'] == entry['reason'], (group, leaf)
    assert report['throughput']['groups']['effective_cases_per_second'][0][
        'value'] == arm['metrics']['effective_cases_per_second'][
            'effective_cases_per_second']['value']
    assert report['session']['metrics'] == arm['metrics']
    assert report['session']['limits'] == arm['limits']


# ---------------------------------------------------------------------------
# honesty markers, skipped_unavailable, refusals, CLI
# ---------------------------------------------------------------------------

def test_report_carries_the_honesty_markers(chain, evidence):
    report = grade(chain, harness_set=chain['harness_set_path'],
                   session=evidence['session_coverage'])
    assert report['schema_version'] == CAPABILITY_REPORT_SCHEMA
    assert report['generated'] is False
    assert report['not_claimed']
    assert any('generat' in row and 'performance' in row
               for row in report['not_claimed'])
    assert report['tier_vocabulary']['order'] == list(CAPABILITY_TIERS)
    assert report['tier_vocabulary']['non_tiers'] == [STATUS_SKIPPED_UNAVAILABLE]
    assert STATUS_SKIPPED_UNAVAILABLE not in CAPABILITY_TIERS
    for subject in [*report['paths'], *report['components']]:
        assert subject['not_claimed']


def test_skipped_unavailable_is_a_status_not_a_tier(chain):
    """An explicitly unavailable component is recorded, not graded and not silent."""
    assert STATUS_SKIPPED_UNAVAILABLE not in CAPABILITY_TIERS
    unavailable = {
        'schema_version': UNAVAILABLE_SCHEMA,
        'components': [{'instance_id': 'gpio', 'code': 'local-source-missing',
                        'missing': ['third_party/pulp_gpio', 'riscv toolchain'],
                        'detail': 'no pinned checkout on this host'}]}
    report = grade(chain, unavailable=unavailable)

    gpio = component_record(report, 'gpio')
    assert gpio['status'] == STATUS_SKIPPED_UNAVAILABLE
    assert gpio['skipped'] == unavailable['components'][0]
    # The status is a status: the tier ladder is still exactly the six tiers,
    # and only Catalog ("it is in the registry") survives an unavailability.
    assert gpio['awarded'] == [TIER_CATALOG]
    for row in gpio['tiers']:
        assert row['tier'] in CAPABILITY_TIERS
        if row['tier'] == TIER_CATALOG:
            continue
        assert row['claimed'] is False
        assert 'local-source-missing' in row['reason']
        assert 'third_party/pulp_gpio' in row['reason']
    assert [row['instance_id'] for row in report['skipped_unavailable']] == ['gpio']
    assert 'gpio' not in {row['instance_id'] for row in report['unsupported_reasons']}
    assert component_record(report, 'cpu')['status'] == STATUS_GRADED
    assert report['counts']['skipped_unavailable'] == 1


@pytest.mark.parametrize('mutate,code,pointer', [
    (lambda document: document.update(schema_version='not_compiled_paths.v1'),
     'unsupported-compiled-paths-schema', '/schema_version'),
    (lambda document: document.pop('paths'), 'compiled-paths-paths-missing',
     '/paths'),
    (lambda document: document['paths'][0].update(status='maybe'),
     'compiled-paths-status-unknown', '/paths/0/status'),
    (lambda document: document['paths'].append(copy.deepcopy(document['paths'][0])),
     'compiled-paths-flow-duplicate', '/paths/6/flow_id'),
])
def test_compiled_paths_refusals(chain, mutate, code, pointer):
    document = copy.deepcopy(chain['compiled'])
    mutate(document)
    with pytest.raises(CapabilityReportRefused) as raised:
        build_capability_report(document, base_dir=ROOT)
    assert raised.value.code == code
    assert raised.value.pointer == pointer


def test_input_refusals(chain, tmp_path, evidence):
    cases = []

    def add(**kwargs):
        cases.append(kwargs)

    add(compiled_paths=tmp_path / 'absent.json')
    add(compiled_paths=chain['compiled_path'],
        harness_set={'schema_version': 'harness_set.v2'})
    add(compiled_paths=chain['compiled_path'],
        session=tmp_path / 'absent-session')
    empty = tmp_path / 'empty-session'
    empty.mkdir()
    add(compiled_paths=chain['compiled_path'], session=empty)
    add(compiled_paths=chain['compiled_path'],
        fresh_verification={'first_difference': None})
    add(compiled_paths=chain['compiled_path'],
        fresh_verification={'matches': 'yes', 'first_difference': None})
    add(compiled_paths=chain['compiled_path'],
        checker_findings={'findings': [{'finding_id': 'f', 'flow_id': 'F4',
                                        'classification': 'probably-a-bug'}]})
    add(compiled_paths=chain['compiled_path'],
        checker_findings={'findings': [{'finding_id': 'f', 'flow_id': 'F9',
                                        'classification': FINDING_NATURAL}]})
    add(compiled_paths=chain['compiled_path'],
        unavailable={'schema_version': 'capability_unavailable.v2',
                     'components': []})
    add(compiled_paths=chain['compiled_path'],
        unavailable={'schema_version': UNAVAILABLE_SCHEMA,
                     'components': [{'instance_id': 'nobody',
                                     'code': 'local-source-missing',
                                     'missing': ['x']}]})
    add(compiled_paths=chain['compiled_path'],
        unavailable={'schema_version': UNAVAILABLE_SCHEMA,
                     'components': [{'instance_id': 'gpio',
                                     'code': 'local-source-missing'}]})

    expected = ['compiled-paths-unreadable', 'unsupported-harness-set-schema',
                'session-directory-missing', 'session-evidence-missing',
                'fresh-verification-matches-missing',
                'fresh-verification-matches-invalid',
                'checker-findings-classification-unknown',
                'checker-findings-flow-unknown', 'unsupported-unavailable-schema',
                'unavailable-component-undeclared',
                'unavailable-missing-undeclared']
    seen = []
    for kwargs, code in zip(cases, expected):
        with pytest.raises(CapabilityReportRefused) as raised:
            build_capability_report(base_dir=ROOT, **kwargs)
        assert raised.value.code == code, (code, raised.value.code)
        assert raised.value.pointer, code
        seen.append(raised.value.code)
    assert seen == expected
    # A malformed document is a refusal too, and it says where.
    bad = tmp_path / 'bad.json'
    bad.write_text('{not json', encoding='utf-8')
    with pytest.raises(CapabilityReportRefused) as raised:
        build_capability_report(bad, base_dir=ROOT)
    assert raised.value.code == 'compiled-paths-not-json'
    assert raised.value.pointer == '/compiled_paths'


def test_cli_writes_one_json_line_and_refuses_with_code_and_pointer(
        chain, evidence, tmp_path):
    output = tmp_path / 'capability-report.json'
    environment = {**os.environ, 'PYTHONPATH': str(ROOT / 'src')}
    arguments = [
        sys.executable, str(SCRIPT),
        '--compiled-paths', str(chain['compiled_path']),
        '--harness-set', str(chain['harness_set_path']),
        '--session', str(evidence['session_coverage']),
        '--checker-findings', str(evidence['findings_natural']),
        '--fresh-verification', str(evidence['fresh_full']),
        '--output', str(output)]
    result = subprocess.run(arguments, cwd=ROOT, capture_output=True, text=True,
                            env=environment)
    assert result.returncode == 0, result.stderr[-2000:]
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 1, result.stdout
    summary = json.loads(lines[0])
    assert summary['status'] == 'graded'
    assert summary['output'] == str(output)
    assert summary['schema_version'] == CAPABILITY_REPORT_SCHEMA
    written = json.loads(output.read_text(encoding='utf-8'))
    assert written['schema_version'] == CAPABILITY_REPORT_SCHEMA
    expected = build_capability_report(
        chain['compiled_path'], harness_set=chain['harness_set_path'],
        session=evidence['session_coverage'],
        checker_findings=evidence['findings_natural'],
        fresh_verification=evidence['fresh_full'], base_dir=ROOT)
    assert written == expected

    refused = subprocess.run(
        [sys.executable, str(SCRIPT), '--compiled-paths', str(tmp_path / 'no.json'),
         '--output', str(tmp_path / 'never.json')],
        cwd=ROOT, capture_output=True, text=True, env=environment)
    assert refused.returncode != 0
    payload = json.loads([line for line in refused.stdout.splitlines()
                          if line.strip()][-1])
    assert payload['status'] == 'refused'
    assert payload['code'] == 'compiled-paths-unreadable'
    assert payload['pointer'] == '/compiled_paths'
    assert not (tmp_path / 'never.json').exists()


@pytest.mark.skipif(
    not REAL_SESSION.is_dir(),
    reason=f'no really recorded session in this checkout: {REAL_SESSION}')
def test_a_really_recorded_session_is_consumed(chain):
    """A real saved run grades the real compilation, and refuses to over-attribute."""
    report = build_capability_report(
        chain['compiled_path'], harness_set=chain['harness_set_path'],
        session=REAL_SESSION, base_dir=ROOT)

    assert report['session']['arm_kind'] == 'scenario_online_cases'
    assert report['session']['report']['tests'] == 24
    certified = report['session']['metrics']['certified_chains_per_second'][
        'certified_chains']
    assert isinstance(certified['value'], int) and certified['value'] > 0, certified

    # F4 really ran in that session and is executable in this compilation.
    f4 = path_record(report, 'F4')
    assert TIER_RTL_OPERATIONAL in f4['awarded']
    # F5 really ran there too, but this compilation says it cannot be walked:
    # P7-C's status wins over the saved run.
    f5 = path_record(report, 'F5')
    assert f5['compiled_status'] == STATUS_UNSUPPORTED
    assert_awarded(f5, [TIER_CATALOG])

    cpu = component_record(report, 'cpu')
    assert TIER_RTL_OPERATIONAL in cpu['awarded']

    # The saved session's own instance ids are cpu/gpio_a/gpio_b; this
    # composition declares cpu/gpio, so the cross-component features it recorded
    # name instances this composition does not declare and must not be claimed.
    row = tier_row(f4, TIER_CROSS_COMPONENT_ACCEPTED)
    assert row['claimed'] is False
    assert 'gpio' in row['reason'], row['reason']
