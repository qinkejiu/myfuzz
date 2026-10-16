"""P7-D: one graded capability report for a compiled composition.

The plan's P7-D deliverable (D4) is the *graded report*: one place that states,
per flow path and per component, which of the six capability tiers is really
established, which is not, and what is missing -- plus the build cost and the
sustained useful throughput, because "generation succeeded" is explicitly not a
substitute for fuzzable-performance evidence (implementation plan §7).

The tier ladder is the authoritative one, in order, from the generated-harness
design (``docs/superpowers/specs/2026-10-04-generated-local-harness-five-
protocol-design.md:92``)::

    Catalog -> Generated -> RTL operational -> Cross-component accepted
            -> Coverage-guided searched -> Bug confirmed

**One tier never implies the next**, and this module enforces that by giving each
tier its own evidence gate rather than by documenting the rule:

======================  ====================================================
tier                    the artifact and the fact that establish it here
======================  ====================================================
``Catalog``             the component is named by a trusted registry document
                        (``compiled_paths.v1`` ``identity`` / ``harness_set.v1``
                        ``components``) with its profile or artifact identity
``Generated``           ``harness_set.v1`` carries this component, an
                        ``artifact_digest`` and an admitted template identity
``RTL operational``     a saved session's ``receipts.jsonl`` records an admitted
                        RTL case (``candidate_disposition_reason=
                        rtl_case_committed``) with real local ticks for this
                        component / for this path's flow
``Cross-component       a receipt's ``interaction_new_features`` names a
accepted``              consumed/delivered edge between two distinct instances
                        this composition declares
``Coverage-guided       a receipt records a nonzero ``coverage_hex`` for this
searched``              flow/component **and** a feedback-steering fact
                        (``report.json:mutation_hint_updates`` > 0 or a receipt's
                        ``applied_hint_sequence``) shows the search used it
``Bug confirmed``       a checker finding that *declares itself natural* (not
                        fault-injection/calibration) names this subject **and** a
                        fresh-verification document confirms a full-prefix match
                        with no first difference
======================  ====================================================

Two distinctions are load-bearing and are never blurred:

* ``unsupported`` is a **P7-C status**: the thing cannot be done and P7-C names
  why (``reason.code`` / ``reason.pointer`` / ``reason.missing``, carried here
  verbatim, including for a perturbed document this module could not have
  computed itself).
* *grade not claimed* is this report's own disposition: the tier might well be
  true, but nothing supplied here proves it.  A tier with missing evidence is
  reported as ``grade_not_claimed`` with a reason -- never as ``unsupported``,
  and never omitted.

``skipped_unavailable`` is likewise a *status* (a component declared locally
unavailable with its missing source/toolchain conditions), not a tier; it is
never inferred from missing evidence, only read from an explicit
``capability_unavailable.v1`` declaration.

Nothing here generates, builds, runs or replays anything.  The document always
carries ``generated: false``, a ``not_claimed`` list and per-subject tier records
whose awarded entries each carry ``{"artifact", "fact", "supports"}``.

Reused rather than re-implemented: :mod:`myfuzz.scenario.compiled_paths` for the
path identities, statuses, reasons and flow vocabulary (P7-C is never
re-derived); :mod:`myfuzz.local_harness.harness_set` for the harness-set schema
and its own ``generated`` tier claim; and
:mod:`myfuzz.scenario.p5_arm_metrics` for the build-cost and throughput
grouping, so this report states no second throughput vocabulary.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
from pathlib import Path

from myfuzz.local_harness.harness_set import (
    GENERATED_TIER, HARNESS_SET_SCHEMA_VERSION)
from myfuzz.scenario.compiled_paths import (
    COMPILED_PATHS_SCHEMA, FLOW_IDS, STATUS_EXECUTABLE, STATUS_UNSUPPORTED)
from myfuzz.scenario.p5_arm_metrics import (
    CHECKLIST_METRIC_GROUPS, GROUP_SPECS, P5ArmMetricsInputError,
    SCHEMA_VERSION as P5_ARM_METRICS_SCHEMA, analyze_arm)

# ---------------------------------------------------------------------------
# vocabulary
# ---------------------------------------------------------------------------

CAPABILITY_REPORT_SCHEMA = 'capability_report.v1'
#: The declaration that a component could not be executed locally.
UNAVAILABLE_SCHEMA = 'capability_unavailable.v1'

#: The six capability tiers, in the authoritative order.  ``skipped_unavailable``
#: is deliberately absent: it is a status, not a tier.
TIER_CATALOG = 'Catalog'
TIER_GENERATED = 'Generated'
TIER_RTL_OPERATIONAL = 'RTL operational'
TIER_CROSS_COMPONENT_ACCEPTED = 'Cross-component accepted'
TIER_COVERAGE_GUIDED_SEARCHED = 'Coverage-guided searched'
TIER_BUG_CONFIRMED = 'Bug confirmed'
CAPABILITY_TIERS = (
    TIER_CATALOG, TIER_GENERATED, TIER_RTL_OPERATIONAL,
    TIER_CROSS_COMPONENT_ACCEPTED, TIER_COVERAGE_GUIDED_SEARCHED,
    TIER_BUG_CONFIRMED)

TIER_AUTHORITY = ('docs/superpowers/specs/2026-10-04-generated-local-harness-'
                  'five-protocol-design.md:92')
EVIDENCE_RULE = ('a tier is awarded only with an `evidence` entry naming the '
                 'artifact and the fact in it that establish the tier; one tier '
                 'never implies the next')

#: Per-tier disposition vocabulary.  A tier is either awarded with evidence or
#: reported as *grade not claimed* with a reason; there is no third value, and
#: neither value is ``unsupported``.
DISPOSITION_AWARDED = 'awarded'
DISPOSITION_NOT_CLAIMED = 'grade_not_claimed'

#: A subject is either graded or explicitly declared unavailable locally.
STATUS_GRADED = 'graded'
STATUS_SKIPPED_UNAVAILABLE = 'skipped_unavailable'
SUBJECT_STATUSES = (STATUS_GRADED, STATUS_SKIPPED_UNAVAILABLE)

#: Checker-finding classifications.  Plan line 92 requires controlled fault
#: injection to be counted separately from natural RTL defects, so a finding that
#: does not *declare* one of these never supports ``Bug confirmed``.
FINDING_NATURAL = 'natural'
FINDING_INJECTED = 'injected'
FINDING_CALIBRATION = 'calibration'
FINDING_CLASSIFICATIONS = (FINDING_NATURAL, FINDING_INJECTED, FINDING_CALIBRATION)

#: Feature-id prefixes that record an *ordering* observation rather than a
#: consumed/delivered edge.  ``interaction_feedback.py`` builds
#: ``observed_path:<kind>:<components>`` from ``observed_paths``, and plan line
#: 90 forbids inferring a causal hit from two components merely appearing in
#: order.
ORDERING_ONLY_FEATURE_PREFIXES = ('observed_path:',)

#: The p5 groups this report reuses for its mandatory cost/throughput sections.
BUILD_COST_GROUP = 'one_time_compile_init'
THROUGHPUT_GROUPS = ('effective_cases_per_second', 'certified_chains_per_second')

#: Mandatory statements the report always carries.
GENERATION_IS_NOT_PERFORMANCE = (
    'generation success is not fuzzable-performance evidence; the build_cost and '
    'throughput sections state what was measured and what is a named absence '
    '(P7 implementation plan §7)')


class CapabilityReportRefused(ValueError):
    """An input is unusable, contradictory or not the declared document.

    ``code`` is a stable machine-readable reason and ``pointer`` names where the
    offending declaration is; no report is produced.
    """

    def __init__(self, code: str, pointer: str = '', detail=None):
        self.code = code
        self.pointer = pointer
        self.detail = detail
        super().__init__(f'{code} at {pointer or "/"}')


def _refuse(code: str, pointer: str = '', detail=None):
    raise CapabilityReportRefused(code, pointer, detail)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _digest(value: object) -> str:
    return 'sha256:' + hashlib.sha256(_canonical(value)).hexdigest()


def _evidence(artifact: str, fact: str, tier: str) -> dict:
    return {'artifact': artifact, 'fact': fact, 'supports': tier}


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


# ---------------------------------------------------------------------------
# input loading
# ---------------------------------------------------------------------------

def _load_document(value: object, *, base_dir: Path, code: str, pointer: str):
    """``(document, path)`` for an in-memory document or a JSON file path."""
    if isinstance(value, Mapping):
        return dict(value), None
    if isinstance(value, (str, Path)):
        path = Path(value)
        if not path.is_absolute():
            path = base_dir / path
        try:
            text = path.read_text(encoding='utf-8')
        except (OSError, UnicodeError) as error:
            _refuse(f'{code}-unreadable', pointer, {'path': str(value),
                                                    'error': str(error)})
        try:
            document = json.loads(text)
        except json.JSONDecodeError as error:
            _refuse(f'{code}-not-json', pointer,
                    {'path': str(value), 'error': error.msg})
        if not isinstance(document, dict):
            _refuse(f'{code}-object-required', pointer, {'path': str(value)})
        return document, path
    _refuse(f'{code}-unreadable', pointer, {'value': type(value).__name__})


def _described(document: Mapping, path: Path | None, *, default: str) -> dict:
    name = path.name if path is not None else (document.get('schema_version')
                                               or default)
    return {'artifact': name,
            'source': 'file' if path is not None else 'document',
            'path': str(path) if path is not None else None,
            'sha256': _digest(document)}


def _validate_compiled_paths(document: Mapping):
    """``(rows, counts)``; every status/reason is taken exactly as stated."""
    if document.get('schema_version') != COMPILED_PATHS_SCHEMA:
        _refuse('unsupported-compiled-paths-schema', '/schema_version',
                {'expected': COMPILED_PATHS_SCHEMA,
                 'observed': document.get('schema_version')})
    paths = document.get('paths')
    if not isinstance(paths, list) or not paths:
        _refuse('compiled-paths-paths-missing', '/paths')
    rows: list[Mapping] = []
    seen: set[str] = set()
    for index, row in enumerate(paths):
        pointer = f'/paths/{index}'
        if not isinstance(row, Mapping):
            _refuse('compiled-paths-path-not-object', pointer)
        flow_id = row.get('flow_id')
        if not _text(flow_id):
            _refuse('compiled-paths-flow-missing', pointer + '/flow_id')
        if flow_id in seen:
            _refuse('compiled-paths-flow-duplicate', pointer + '/flow_id',
                    {'flow_id': flow_id})
        seen.add(flow_id)
        status = row.get('status')
        if status not in (STATUS_EXECUTABLE, STATUS_UNSUPPORTED):
            _refuse('compiled-paths-status-unknown', pointer + '/status',
                    {'observed': status,
                     'allowed': [STATUS_EXECUTABLE, STATUS_UNSUPPORTED]})
        reason = row.get('reason')
        if not isinstance(reason, Mapping):
            _refuse('compiled-paths-reason-missing', pointer + '/reason')
        if status == STATUS_UNSUPPORTED and not _text(reason.get('code')):
            _refuse('compiled-paths-unsupported-reason-missing',
                    pointer + '/reason/code',
                    {'rule': 'an unsupported path must name its reason (P7-C)'})
        rows.append(row)
    counts = document.get('counts')
    if counts is not None and not isinstance(counts, Mapping):
        _refuse('compiled-paths-counts-invalid', '/counts')
    return rows, counts


def _validate_harness_set(document: Mapping) -> list:
    if document.get('schema_version') != HARNESS_SET_SCHEMA_VERSION:
        _refuse('unsupported-harness-set-schema', '/schema_version',
                {'expected': HARNESS_SET_SCHEMA_VERSION,
                 'observed': document.get('schema_version')})
    if document.get('tier') != GENERATED_TIER:
        _refuse('harness-set-tier-not-generated', '/tier',
                {'expected': GENERATED_TIER, 'observed': document.get('tier')})
    components = document.get('components')
    if not isinstance(components, list):
        _refuse('harness-set-components-missing', '/components')
    rows = []
    for index, row in enumerate(components):
        if not isinstance(row, Mapping):
            _refuse('harness-set-component-not-object', f'/components/{index}')
        if not _text(row.get('instance_id')):
            _refuse('harness-set-component-instance-missing',
                    f'/components/{index}/instance_id')
        rows.append(row)
    return rows


def _validate_fresh_verification(document: Mapping) -> dict:
    if 'matches' not in document:
        _refuse('fresh-verification-matches-missing', '/fresh_verification',
                {'requires': 'the fresh replay conclusion (`matches`)'})
    if type(document['matches']) is not bool:
        _refuse('fresh-verification-matches-invalid', '/fresh_verification/matches',
                {'observed': document['matches']})
    if 'first_difference' not in document:
        _refuse('fresh-verification-first-difference-missing',
                '/fresh_verification',
                {'requires': 'the replay comparison conclusion '
                             '(`first_difference`, null when the prefix matched)'})
    scope = document.get('verification_scope')
    if scope is not None and not _text(scope):
        _refuse('fresh-verification-scope-invalid',
                '/fresh_verification/verification_scope', {'observed': scope})
    return dict(document)


def _validate_checker_findings(value: object) -> tuple[dict, list]:
    if isinstance(value, Mapping):
        document = dict(value)
        rows = document.get('findings')
        if rows is None:
            _refuse('checker-findings-shape', '/checker_findings',
                    {'requires': 'a `findings` list'})
    elif isinstance(value, list):
        document = {'findings': list(value)}
        rows = document['findings']
    else:
        _refuse('checker-findings-shape', '/checker_findings',
                {'value': type(value).__name__})
    if not isinstance(rows, list):
        _refuse('checker-findings-shape', '/checker_findings/findings')
    checked = []
    for index, row in enumerate(rows):
        pointer = f'/checker_findings/findings/{index}'
        if not isinstance(row, Mapping):
            _refuse('checker-findings-row-not-object', pointer)
        classification = row.get('classification')
        if classification is not None:
            if classification not in FINDING_CLASSIFICATIONS:
                _refuse('checker-findings-classification-unknown',
                        pointer + '/classification',
                        {'observed': classification,
                         'allowed': list(FINDING_CLASSIFICATIONS)})
        flow_id = row.get('flow_id')
        if flow_id is not None and flow_id not in FLOW_IDS:
            _refuse('checker-findings-flow-unknown', pointer + '/flow_id',
                    {'observed': flow_id, 'allowed': list(FLOW_IDS)})
        checked.append(dict(row))
    return document, checked


#: Closed vocabulary of a declared local unavailability.
_UNAVAILABLE_FIELDS = {'instance_id', 'code', 'missing', 'detail', 'pointer'}


def _validate_unavailable(document: Mapping) -> list:
    if document.get('schema_version') != UNAVAILABLE_SCHEMA:
        _refuse('unsupported-unavailable-schema', '/schema_version',
                {'expected': UNAVAILABLE_SCHEMA,
                 'observed': document.get('schema_version')})
    components = document.get('components')
    if not isinstance(components, list) or not components:
        _refuse('unavailable-components-missing', '/unavailable/components')
    rows = []
    for index, row in enumerate(components):
        pointer = f'/unavailable/components/{index}'
        if not isinstance(row, Mapping):
            _refuse('unavailable-component-not-object', pointer)
        unknown = sorted(set(row) - _UNAVAILABLE_FIELDS)
        if unknown:
            _refuse('unavailable-field-unknown', pointer, {'unknown': unknown})
        if not _text(row.get('instance_id')):
            _refuse('unavailable-instance-missing', pointer + '/instance_id')
        if not _text(row.get('code')):
            _refuse('unavailable-code-missing', pointer + '/code')
        missing = row.get('missing')
        if (not isinstance(missing, list) or not missing
                or not all(_text(item) for item in missing)):
            _refuse('unavailable-missing-undeclared', pointer + '/missing',
                    {'observed': missing,
                     'requires': 'the missing source/toolchain conditions; an '
                                 'unavailability with nothing missing is not '
                                 'honest'})
        rows.append(dict(row))
    return rows


# ---------------------------------------------------------------------------
# session evidence
# ---------------------------------------------------------------------------

def _coverage_bits(coverage_hex: object) -> int | None:
    if not _text(coverage_hex):
        return None
    try:
        return bin(int(str(coverage_hex), 16)).count('1')
    except ValueError:
        return None


def _feature_instances(token: object, instances: Sequence[str]) -> tuple[str, ...]:
    """The declared instance ids a feature id names, in order, deduplicated."""
    if not _text(token):
        return ()
    named: list[str] = []
    for part in str(token).split(':'):
        if part in instances and part not in named:
            named.append(part)
    return tuple(named)


def _cross_component_tokens(tokens: Sequence[str],
                            instances: Sequence[str]) -> list[dict]:
    """Feature ids that record a delivered/consumed edge between two instances.

    A token qualifies when it names at least two distinct instances this
    composition declares and is not an ordering-only ``observed_path`` token.
    Component ids are used only as the declared identity vocabulary; no token
    kind is inferred from a name.
    """
    rows = []
    for token in tokens:
        if any(str(token).startswith(prefix)
               for prefix in ORDERING_ONLY_FEATURE_PREFIXES):
            continue
        named = _feature_instances(token, instances)
        if len(named) >= 2:
            rows.append({'token': token, 'instances': list(named)})
    return rows


def _index_receipts(path: Path, *, sample_limit: int = 3) -> dict:
    """Stream ``receipts.jsonl`` for the per-path / per-component facts.

    The shipped :func:`myfuzz.scenario.p5_arm_metrics.analyze_arm` reports
    session-level groups; attributing a fact to one flow or one component needs
    the receipts' own ``flow_id`` / ``local_ticks`` fields.  This pass stores
    counters and bounded samples only -- it computes no rate, so the report keeps
    exactly one throughput vocabulary (the shipped p5 grouping).
    """
    index: dict = {
        'available': False,
        'artifact': path.name,
        'rows': 0,
        'unreadable_rows': 0,
        'unreadable_samples': [],
        'status_counts': {},
        'disposition_reasons': {},
        'flows': {},
        'components': {},
        'features': {},
        'violations': {'cases': 0, 'total': 0, 'samples': []},
        'cases_with_applied_hint': 0,
        'cases_with_feature_deltas': 0,
    }
    if not path.is_file():
        return index
    index['available'] = True
    index['sha256'] = _digest_of_file(path)
    with path.open('r', encoding='utf-8') as stream:
        for line in stream:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                index['unreadable_rows'] += 1
                if len(index['unreadable_samples']) < sample_limit:
                    index['unreadable_samples'].append(line[:120])
                continue
            if not isinstance(row, Mapping):
                index['unreadable_rows'] += 1
                continue
            index['rows'] += 1
            status = row.get('status')
            index['status_counts'][status] = index['status_counts'].get(
                status, 0) + 1
            disposition = row.get('candidate_disposition_reason')
            index['disposition_reasons'][disposition] = (
                index['disposition_reasons'].get(disposition, 0) + 1)
            committed = disposition == 'rtl_case_committed'
            case_id = row.get('case_id')
            coverage = _coverage_bits(row.get('coverage_hex'))
            flow_id = row.get('flow_id')
            directions = row.get('direction')
            ticks = row.get('local_ticks')
            ticks = dict(ticks) if isinstance(ticks, Mapping) else {}
            total_ticks = row.get('total_local_ticks')
            if type(total_ticks) is not int:
                total_ticks = sum(value for value in ticks.values()
                                  if type(value) is int)
            features = row.get('interaction_new_features')
            features = [item for item in features if _text(item)] \
                if isinstance(features, list) else []
            deltas = row.get('interaction_feature_deltas')
            if isinstance(deltas, Mapping) and deltas:
                index['cases_with_feature_deltas'] += 1
            applied = row.get('applied_hint_sequence')
            if applied is not None:
                index['cases_with_applied_hint'] += 1
            violations = row.get('violations')
            if isinstance(violations, list) and violations:
                index['violations']['cases'] += 1
                index['violations']['total'] += len(violations)
                if len(index['violations']['samples']) < sample_limit:
                    index['violations']['samples'].append(
                        {'case_id': case_id, 'violations': violations[:3]})

            if _text(flow_id):
                stats = index['flows'].setdefault(str(flow_id), {
                    'cases': 0, 'complete': 0, 'rtl_committed': 0,
                    'ticks_sum': 0, 'coverage_cases': 0, 'coverage_bits_max': 0,
                    'cases_with_hint': 0, 'cases_with_features': 0,
                    'directions': {}, 'target_ids': {}, 'features': {},
                    'coverage_sample': None, 'features_sample': None,
                    'path_ids': [], 'sample_case_ids': []})
                stats['cases'] += 1
                stats['ticks_sum'] += total_ticks if type(total_ticks) is int else 0
                if status == 'complete':
                    stats['complete'] += 1
                if committed:
                    stats['rtl_committed'] += 1
                if applied is not None:
                    stats['cases_with_hint'] += 1
                if features:
                    stats['cases_with_features'] += 1
                    for token in features:
                        stats['features'][token] = stats['features'].get(
                            token, 0) + 1
                    if stats['features_sample'] is None:
                        stats['features_sample'] = {'case_id': case_id,
                                                    'tokens': features}
                if coverage:
                    stats['coverage_cases'] += 1
                    stats['coverage_bits_max'] = max(stats['coverage_bits_max'],
                                                     coverage)
                    if stats['coverage_sample'] is None:
                        stats['coverage_sample'] = {
                            'case_id': case_id, 'coverage_hex': row.get('coverage_hex'),
                            'coverage_bits': coverage}
                if _text(directions):
                    stats['directions'][str(directions)] = stats['directions'].get(
                        str(directions), 0) + 1
                target = row.get('target_id')
                if _text(target):
                    stats['target_ids'][str(target)] = stats['target_ids'].get(
                        str(target), 0) + 1
                path_id = row.get('path_id')
                if _text(path_id) and path_id not in stats['path_ids'] \
                        and len(stats['path_ids']) < 4:
                    stats['path_ids'].append(path_id)
                if len(stats['sample_case_ids']) < sample_limit:
                    stats['sample_case_ids'].append(case_id)

            for instance_id, value in ticks.items():
                if not _text(instance_id) or type(value) is not int:
                    continue
                stats = index['components'].setdefault(str(instance_id), {
                    'cases': 0, 'ticks_sum': 0, 'rtl_committed_cases': 0,
                    'coverage_cases': 0, 'coverage_sample': None,
                    'rtl_sample': None})
                stats['cases'] += 1
                stats['ticks_sum'] += value
                if value > 0 and committed:
                    stats['rtl_committed_cases'] += 1
                    if stats['rtl_sample'] is None:
                        stats['rtl_sample'] = {
                            'case_id': case_id, 'flow_id': flow_id,
                            'ticks': value, 'total_local_ticks': total_ticks}
                if value > 0 and coverage:
                    stats['coverage_cases'] += 1
                    if stats['coverage_sample'] is None:
                        stats['coverage_sample'] = {
                            'case_id': case_id, 'flow_id': flow_id,
                            'coverage_hex': row.get('coverage_hex'),
                            'ticks': value}

            for token in features:
                entry = index['features'].setdefault(token, {
                    'cases': 0, 'first_case_id': case_id, 'flows': []})
                entry['cases'] += 1
                if _text(flow_id) and flow_id not in entry['flows'] \
                        and len(entry['flows']) < 4:
                    entry['flows'].append(flow_id)
    return index


def _digest_of_file(path: Path) -> str | None:
    try:
        return 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


#: Report facts this module reads straight out of ``report.json``.
_REPORT_FACTS = ('execution_mode', 'execution_status', 'session_status', 'tests',
                 'statuses', 'effective_search_seconds', 'elapsed_seconds',
                 'mutation_hint_updates', 'completed_feedback_exchanges',
                 'runtime_path_status', 'record_semantics',
                 'total_local_ticks_semantics', 'clock_model')


def _load_session(value: object, *, base_dir: Path, instances: Sequence[str],
                  cpu_instance: str | None) -> dict:
    if not isinstance(value, (str, Path)):
        _refuse('session-directory-required', '/session',
                {'value': type(value).__name__})
    directory = Path(value)
    if not directory.is_absolute():
        directory = base_dir / directory
    if directory.is_file():
        _refuse('session-directory-required', '/session',
                {'path': str(value), 'requires': 'the session output directory'})
    if not directory.is_dir():
        _refuse('session-directory-missing', '/session', {'path': str(value)})
    report_path = directory / 'report.json'
    receipts_path = directory / 'receipts.jsonl'
    if not report_path.is_file() and not receipts_path.is_file():
        _refuse('session-evidence-missing', '/session',
                {'path': str(value),
                 'requires': 'report.json (the relevant report document) and/or '
                             'receipts.jsonl'})

    session: dict = {
        'supplied': True,
        'directory': str(value),
        'arm_kind': None,
        'arm_kind_source': None,
        'arm_kind_reason': None,
        'run_id': None,
        'analysis_performed': False,
        'metrics_available': False,
        'metrics_reason': None,
        'metrics': None,
        'limits': [],
        'report': {'available': False, 'artifact': report_path.name},
        'identity': None,
        'receipts': _index_receipts(receipts_path),
        'certified_chains': None,
    }

    document = None
    if report_path.is_file():
        document, _ = _load_document(report_path, base_dir=base_dir,
                                     code='session-report',
                                     pointer='/session/report.json')
        facts = {name: document.get(name) for name in _REPORT_FACTS
                 if name in document}
        session['report'] = {'available': True, 'artifact': report_path.name,
                             'sha256': _digest(document), **facts}

    try:
        arm = analyze_arm(directory)
    except (P5ArmMetricsInputError, ValueError) as error:
        session['metrics_reason'] = (
            f'the shipped p5 reader could not aggregate this directory: {error}')
        session['limits'].append({'quantity': 'p5_arm_metrics.v1',
                                  'reason': session['metrics_reason']})
    else:
        session.update({
            'arm_kind': arm.get('arm_kind'),
            'arm_kind_source': arm.get('arm_kind_source'),
            'arm_kind_reason': arm.get('arm_kind_reason'),
            'run_id': arm.get('run_id'),
            'analysis_performed': arm.get('analysis_performed'),
            'metrics_available': True,
            'metrics': arm.get('metrics'),
            'limits': [dict(row) for row in arm.get('limits') or ()],
        })
        certified = (arm.get('metrics') or {}).get(
            'certified_chains_per_second', {}).get('certified_chains', {})
        session['certified_chains'] = certified.get('value')

    identity_path = directory / 'online_run_identity.json'
    if identity_path.is_file():
        identity, _ = _load_document(identity_path, base_dir=base_dir,
                                     code='session-identity',
                                     pointer='/session/online_run_identity.json')
        session['identity'] = {'artifact': identity_path.name,
                               'sha256': _digest(identity),
                               'schema_version': identity.get('schema_version')}

    observed = sorted(session['receipts']['components'])
    session['linkage'] = {
        'declared_instances': list(instances),
        'observed_instances': observed,
        'observed_declared_instances': [name for name in observed
                                        if name in set(instances)],
        'cpu_instance': cpu_instance,
        'cpu_observed': bool(cpu_instance) and any(
            name == cpu_instance and row['ticks_sum'] > 0
            for name, row in session['receipts']['components'].items()),
    }
    return session


def _empty_session(reason: str) -> dict:
    return {
        'supplied': False,
        'reason': reason,
        'metrics_available': False,
        'metrics': None,
        'limits': [],
        'report': {'available': False, 'artifact': 'report.json'},
        'identity': None,
        'linkage': {'declared_instances': [], 'observed_instances': [],
                    'observed_declared_instances': [], 'cpu_instance': None,
                    'cpu_observed': False},
        'receipts': {'available': False, 'artifact': 'receipts.jsonl', 'rows': 0,
                     'flows': {}, 'components': {}, 'features': {},
                     'status_counts': {}, 'cases_with_applied_hint': 0},
        'certified_chains': None,
    }


def _session_descriptor(session: Mapping) -> dict:
    """The compact ``inputs.session`` entry; the evidence is under `session`."""
    if not session.get('supplied'):
        return {'supplied': False, 'reason': session.get('reason')}
    return {
        'supplied': True,
        'directory': session.get('directory'),
        'arm_kind': session.get('arm_kind'),
        'arm_kind_source': session.get('arm_kind_source'),
        'run_id': session.get('run_id'),
        'analysis_performed': session.get('analysis_performed'),
        'metrics_available': session.get('metrics_available'),
        'metrics_reason': session.get('metrics_reason'),
        'report_sha256': (session.get('report') or {}).get('sha256'),
        'receipts_available': bool(
            (session.get('receipts') or {}).get('available')),
        'full_evidence': 'capability_report.v1:session',
    }


# ---------------------------------------------------------------------------
# per-tier evidence gates
# ---------------------------------------------------------------------------

def _p5_leaf(session: Mapping, group: str, leaf: str):
    metrics = session.get('metrics')
    if not isinstance(metrics, Mapping):
        return None
    entry = (metrics.get(group) or {}).get(leaf)
    return entry if isinstance(entry, Mapping) else None


def _steering_facts(session: Mapping) -> list[dict]:
    """The facts that show the search consumed coverage feedback."""
    facts = []
    updates = (session.get('report') or {}).get('mutation_hint_updates')
    if type(updates) is int and updates > 0:
        facts.append(_evidence('report.json', f'mutation_hint_updates={updates}',
                               TIER_COVERAGE_GUIDED_SEARCHED))
    exchanges = (session.get('report') or {}).get('completed_feedback_exchanges')
    if type(exchanges) is int and exchanges > 0:
        facts.append(_evidence('report.json',
                               f'completed_feedback_exchanges={exchanges}',
                               TIER_COVERAGE_GUIDED_SEARCHED))
    hints = (session.get('receipts') or {}).get('cases_with_applied_hint')
    if type(hints) is int and hints > 0:
        facts.append(_evidence('receipts.jsonl',
                               f'applied_hint_sequence present in {hints} case(s)',
                               TIER_COVERAGE_GUIDED_SEARCHED))
    return facts


def _coverage_confirmation(session: Mapping) -> dict | None:
    entry = _p5_leaf(session, 'coverage_novelty', 'first_seen_target_bits')
    value = None if entry is None else entry.get('value')
    if type(value) is int and value > 0:
        return _evidence('p5_arm_metrics.v1:coverage_novelty',
                         f'first_seen_target_bits={value} '
                         f'(source: {entry.get("source")})',
                         TIER_COVERAGE_GUIDED_SEARCHED)
    return None


def _session_absent_reason(session: Mapping) -> str:
    if not session.get('supplied'):
        return ('no saved online session was supplied, so no real local '
                'transaction is recorded here')
    return ('the supplied session directory carries no receipts.jsonl, so no '
            'per-case receipt records a real local transaction')


def _rtl_gate(session: Mapping, *, flow_id: str | None = None,
              instance_id: str | None = None):
    """Real local transaction evidence for one path's flow or one component."""
    if not session.get('supplied') or not session['receipts'].get('available'):
        return None, _session_absent_reason(session)
    if flow_id is not None:
        linkage = session.get('linkage') or {}
        if not linkage.get('cpu_observed'):
            observed = ', '.join(linkage.get('observed_instances') or ()) or 'none'
            return None, (
                f"the session's receipts record local ticks for {observed}, not for "
                f"this composition's declared CPU instance "
                f"{linkage.get('cpu_instance')!r}; a run of a different harness "
                "instance set is not this path's real local transaction")
        stats = (session['receipts']['flows'] or {}).get(flow_id)
        if not stats or not stats.get('rtl_committed'):
            cases = 0 if not stats else stats['cases']
            return None, (
                f"the session's receipts record {cases} case(s) for flow {flow_id} "
                "but none with candidate_disposition_reason=rtl_case_committed, so "
                "no real RTL case is recorded for this path")
        sample = stats.get('sample_case_ids') or [None]
        return [
            _evidence('receipts.jsonl',
                      f'flow_id={flow_id}; case_id={sample[0]}; '
                      f'candidate_disposition_reason=rtl_case_committed; '
                      f'total_local_ticks={stats["ticks_sum"]} over '
                      f'{stats["rtl_committed"]} committed case(s)',
                      TIER_RTL_OPERATIONAL),
        ], None

    stats = (session['receipts']['components'] or {}).get(instance_id)
    if not stats or not stats.get('rtl_committed_cases'):
        observed = ', '.join(sorted(session['receipts']['components'])) or 'none'
        return None, (
            f"the session's receipts record local ticks for {observed}, so "
            f"instance_id={instance_id} is not among them with an admitted "
            "candidate_disposition_reason=rtl_case_committed case; a different "
            "harness instance is not this component's real local transaction")
    sample = stats.get('rtl_sample') or {}
    evidence = [
        _evidence('receipts.jsonl',
                  f'local_ticks.{instance_id} (sum)={stats["ticks_sum"]} over '
                  f'{stats["cases"]} case(s); '
                  f'candidate_disposition_reason=rtl_case_committed in '
                  f'{stats["rtl_committed_cases"]} case(s)',
                  TIER_RTL_OPERATIONAL),
    ]
    if sample:
        evidence.append(_evidence(
            'receipts.jsonl',
            f'case_id={sample.get("case_id")} flow_id={sample.get("flow_id")} '
            f'local_ticks.{instance_id}={sample.get("ticks")}',
            TIER_RTL_OPERATIONAL))
    return evidence, None


def _cross_gate(session: Mapping, instances: Sequence[str], *,
                flow_id: str | None = None, instance_id: str | None = None):
    """A consumed/delivered edge between two declared instances, per receipt."""
    if not session.get('supplied') or not session['receipts'].get('available'):
        return None, _session_absent_reason(session)
    if flow_id is not None:
        stats = (session['receipts']['flows'] or {}).get(flow_id) or {}
        tokens = sorted(stats.get('features') or ())
        candidates = _cross_component_tokens(tokens, instances)
        subject = f'flow {flow_id}'
    else:
        tokens = sorted(session['receipts'].get('features') or ())
        candidates = [row for row in _cross_component_tokens(tokens, instances)
                      if instance_id in row['instances']]
        subject = f'instance_id={instance_id}'
    if not candidates:
        seen = ', '.join(tokens) if tokens else 'none'
        return None, (
            f'the session records interaction features for {subject} ({seen}), but '
            'none is a consumed/delivered edge naming two instances this '
            f'composition declares (declared: {", ".join(instances)}); an '
            'ordering-only observation is not a causal hit (plan line 90)')
    evidence = []
    for row in candidates[:2]:
        entry = (session['receipts'].get('features') or {}).get(row['token']) or {}
        evidence.append(_evidence(
            'receipts.jsonl',
            f'interaction_new_features=["{row["token"]}"] in '
            f'{subject} case_id={entry.get("first_case_id")}; declares instances '
            f'{", ".join(row["instances"])}, all declared by this composition',
            TIER_CROSS_COMPONENT_ACCEPTED))
    return evidence, None


def _coverage_gate(session: Mapping, *, flow_id: str | None = None,
                   instance_id: str | None = None):
    if not session.get('supplied') or not session['receipts'].get('available'):
        return None, _session_absent_reason(session)
    if flow_id is not None:
        stats = (session['receipts']['flows'] or {}).get(flow_id)
        sample = (stats or {}).get('coverage_sample')
        if not sample:
            return None, (
                f"the session's receipts for flow {flow_id} record no case with a "
                'nonzero coverage_hex, so this path is not shown to be searched '
                'by coverage')
        subject = f'flow {flow_id}'
        tick_fact = f'local_ticks.{sample.get("case_id")!r} (case total)'
        ticks = 0
    else:
        stats = (session['receipts']['components'] or {}).get(instance_id)
        sample = (stats or {}).get('coverage_sample')
        if not sample:
            return None, (
                f"the session's receipts record no case with a nonzero coverage_hex "
                f'in which instance_id={instance_id} really ran local ticks, so '
                'this component is not shown to be searched by coverage')
        subject = f'instance_id={instance_id}'
        tick_fact = f'local_ticks.{instance_id}'
        ticks = sample.get('ticks')
    steering = _steering_facts(session)
    if not steering:
        confirmation = _coverage_confirmation(session)
        detail = ('' if confirmation is None else
                  '; the shipped grouping confirms coverage was recorded')
        return None, (
            f'coverage was recorded for {subject}{detail}, but no '
            'feedback-steering fact is present (report.json:mutation_hint_updates '
            '> 0, report.json:completed_feedback_exchanges > 0, or a receipt '
            'applied_hint_sequence), so the search is not shown to be '
            'coverage-guided')
    evidence = [_evidence(
        'receipts.jsonl',
        f'coverage_hex={sample.get("coverage_hex")} in case_id='
        f'{sample.get("case_id")} for {subject}; {tick_fact}={ticks}',
        TIER_COVERAGE_GUIDED_SEARCHED)]
    confirmation = _coverage_confirmation(session)
    if confirmation is not None:
        evidence.append(confirmation)
    evidence.extend(steering[:1])
    return evidence, None


def _bug_gate(findings: Sequence[Mapping], fresh: Mapping | None, *,
              flow_id: str | None = None, instance_id: str | None = None):
    """A declared-natural finding for this subject, confirmed by a full replay."""
    natural = [row for row in findings
               if row.get('classification') == FINDING_NATURAL
               and _finding_names(row, flow_id=flow_id, instance_id=instance_id)]
    other = sorted({str(row.get('classification')) for row in findings
                    if row.get('classification') in (FINDING_INJECTED,
                                                     FINDING_CALIBRATION)})
    if not natural:
        if other:
            reason = (f'the checker findings declare only {", ".join(other)} '
                      'finding(s), which calibrate the checker and are counted '
                      'separately from natural RTL defects (plan line 92)')
        elif not findings:
            reason = ('no checker finding was supplied that declares itself a '
                      f'natural RTL defect for this subject, so the defect is '
                      'not confirmed here')
        else:
            reason = ('the supplied checker findings carry no finding with '
                      f'classification={FINDING_NATURAL} naming this subject; an '
                      'unclassified or differently classified finding is never '
                      'counted as a natural defect')
        return None, reason
    if fresh is None:
        return None, ('no fresh-verification document was supplied, so the finding '
                      'has no fresh replay conclusion and the bug is not confirmed '
                      'as replayable')
    if not fresh.get('matches') or fresh.get('first_difference') is not None:
        return None, (
            'the fresh replay does not confirm the prefix (matches='
            f'{fresh.get("matches")!r}, first_difference='
            f'{fresh.get("first_difference")!r}), so the finding is not confirmed')
    scope = fresh.get('verification_scope')
    if scope != 'full':
        return None, (
            f'the fresh replay declares verification_scope={scope!r}, not the '
            'complete prefix (`full`), so the finding is not confirmed as '
            'replayable')
    evidence = [
        _evidence('checker findings',
                  f'finding_id={natural[0].get("finding_id")!r}; '
                  f'classification={FINDING_NATURAL}; '
                  f'flow_id={natural[0].get("flow_id")!r}; '
                  f'component={natural[0].get("component")!r}',
                  TIER_BUG_CONFIRMED),
        _evidence('fresh-verification.json',
                  f'matches={fresh.get("matches")!r}; first_difference='
                  f'{fresh.get("first_difference")!r}; verification_scope='
                  f'{fresh.get("verification_scope")!r}',
                  TIER_BUG_CONFIRMED),
    ]
    return evidence, None


def _finding_names(row: Mapping, *, flow_id: str | None = None,
                   instance_id: str | None = None) -> bool:
    named_paths = {value for value in (row.get('flow_id'), row.get('path_id'))
                   if _text(value)}
    named_instances = {value for value in (row.get('component'),
                                           row.get('instance_id'),
                                           row.get('components'))
                       if _text(value) or isinstance(value, list)}
    if flow_id is not None:
        return flow_id in named_paths
    if instance_id is not None:
        if instance_id in named_instances:
            return True
        for value in named_instances:
            if isinstance(value, str) and instance_id in value.split(','):
                return True
        return False
    return False


# ---------------------------------------------------------------------------
# subject grading
# ---------------------------------------------------------------------------

class _Context:
    def __init__(self, *, compiled_artifact, harness_artifact, harness_supplied,
                 compiled_identity, harness_rows, session, findings, fresh,
                 unavailable, instances, cpu_instance):
        self.compiled_artifact = compiled_artifact
        self.harness_artifact = harness_artifact
        self.harness_supplied = harness_supplied
        self.compiled_identity = compiled_identity
        self.harness_rows = harness_rows
        self.session = session
        self.findings = findings
        self.fresh = fresh
        self.unavailable = unavailable
        self.instances = instances
        self.cpu_instance = cpu_instance

    def harness_row(self, instance_id):
        return next((row for index, row in enumerate(self.harness_rows)
                     if row.get('instance_id') == instance_id), None)

    def harness_pointer(self, instance_id):
        for index, row in enumerate(self.harness_rows):
            if row.get('instance_id') == instance_id:
                return f'components[{index}]'
        return None

    def harness_ready(self, instance_id) -> bool:
        """Whether this component's harness is established as generated."""
        row = self.harness_row(instance_id)
        if row is None:
            return False
        template = row.get('template')
        return bool(_text(row.get('artifact_digest'))
                    and isinstance(template, Mapping)
                    and _text(template.get('template_id')))


def _tier(tier: str, evidence, reason: str | None) -> dict:
    if evidence:
        if reason is not None:
            raise AssertionError(f'{tier}: awarded with a reason')
        return {'tier': tier, 'claimed': True,
                'disposition': DISPOSITION_AWARDED,
                'evidence': list(evidence)}
    if not _text(reason):
        raise AssertionError(f'{tier}: not claimed without a reason')
    return {'tier': tier, 'claimed': False,
            'disposition': DISPOSITION_NOT_CLAIMED, 'reason': reason}


def _subject(surface: str, *, tiers: list, extra: dict) -> dict:
    awarded = [row['tier'] for row in tiers if row['claimed']]
    return {
        'subject': surface,
        **extra,
        'tiers': tiers,
        'awarded': awarded,
        'highest_claimed': awarded[-1] if awarded else None,
        'not_claimed': [tier for tier in CAPABILITY_TIERS if tier not in awarded],
    }


def _path_participants(row: Mapping) -> list[str]:
    """The declared component instances this path's own hops use, in order.

    Read only from the compiled path's own declared ends (its target, its
    fuzzable sources, its bound inputs and its endpoints); ``compiled_paths.v1``
    is authoritative for them, so nothing is inferred from a component id.
    """
    names: list[str] = []

    def add(value):
        if _text(value) and value not in names:
            names.append(str(value))

    target = row.get('target')
    if isinstance(target, Mapping):
        add(target.get('component'))
    for item in row.get('sources') or ():
        if isinstance(item, Mapping):
            add(item.get('component'))
    for item in row.get('bound_inputs') or ():
        if isinstance(item, Mapping):
            add(item.get('component'))
    for item in row.get('endpoints') or ():
        if isinstance(item, Mapping):
            add(item.get('instance_id'))
    return names


def _grade_path(row: Mapping, index: int, ctx: _Context) -> dict:
    flow_id = row['flow_id']
    status = row['status']
    reason = dict(row['reason'])
    pointer = f'paths[{index}]'
    code = reason.get('code')
    compiled_reason = (f'{code} at {reason.get("pointer")}'
                       if code else 'no reason: the path is executable')
    unsupported_reason = (f'the compiled path is unsupported ({compiled_reason}); '
                          'P7-C states this composition cannot walk it, so no '
                          'runtime path exists for it')

    catalog = [_evidence(
        ctx.compiled_artifact,
        f'{pointer}/flow_id={flow_id}; definition.authority='
        f'{(row.get("definition") or {}).get("authority")}',
        TIER_CATALOG)]

    participants = _path_participants(row)
    if status == STATUS_UNSUPPORTED:
        generated = (None, unsupported_reason)
        higher = (None, f'the compiled path is unsupported ({compiled_reason}); '
                        'no tier above Catalog is claimed for a path this '
                        'composition cannot walk')
    else:
        identity = row.get('runtime_path_identity')
        built = {name: ctx.harness_row(name) for name in participants}
        missing = sorted(name for name, harness in built.items()
                         if not ctx.harness_ready(name))
        if not isinstance(identity, Mapping) or not _text(identity.get('path_id')):
            generated = (None, (
                f'{pointer}/status={STATUS_EXECUTABLE} but the document carries no '
                'runtime_path_identity for it, so P7-C compiled no runtime hop '
                'this report could call generated'))
        elif not participants:
            generated = (None, (
                f'{pointer} names no participating component instance, so no '
                'harness generation can be attributed to this path'))
        elif not ctx.harness_supplied:
            generated = (None, (
                'no harness_set.v1 was supplied, so nothing here establishes that '
                f"the harnesses for this path's components "
                f"({', '.join(participants)}) were generated"))
        elif missing:
            generated = (None, (
                f'harness_set.v1 carries no generated harness for '
                f'{", ".join(missing)}, which this path\'s declared hops use; the '
                'path is compiled but its harnesses are not established as '
                'generated'))
        else:
            evidence = [_evidence(
                ctx.compiled_artifact,
                f'{pointer}/status={STATUS_EXECUTABLE}; '
                f'{pointer}/runtime_path_identity.path_id='
                f'{identity.get("path_id")}',
                TIER_GENERATED)]
            for name in participants:
                harness_pointer = ctx.harness_pointer(name)
                evidence.append(_evidence(
                    ctx.harness_artifact,
                    f'{harness_pointer}/instance_id={name}; artifact_digest='
                    f'{built[name].get("artifact_digest")}',
                    TIER_GENERATED))
            generated = (evidence, None)
        higher = None

    rtl = _rtl_gate(ctx.session, flow_id=flow_id) if higher is None else higher
    cross = (_cross_gate(ctx.session, ctx.instances, flow_id=flow_id)
             if higher is None else higher)
    coverage = (_coverage_gate(ctx.session, flow_id=flow_id)
                if higher is None else higher)
    bug = (_bug_gate(ctx.findings, ctx.fresh, flow_id=flow_id)
           if higher is None else higher)

    tiers = [
        _tier(TIER_CATALOG, catalog, None),
        _tier(TIER_GENERATED, *generated),
        _tier(TIER_RTL_OPERATIONAL, *rtl),
        _tier(TIER_CROSS_COMPONENT_ACCEPTED, *cross),
        _tier(TIER_COVERAGE_GUIDED_SEARCHED, *coverage),
        _tier(TIER_BUG_CONFIRMED, *bug),
    ]
    findings_here = [dict(item) for item in ctx.findings
                     if item.get('flow_id') == flow_id
                     or item.get('path_id') == row.get('path_id')]
    return _subject('path', tiers=tiers, extra={
        'path_id': row.get('path_id'),
        'flow_id': flow_id,
        'flow_name': row.get('flow_name'),
        'compiled_status': status,
        'status': STATUS_GRADED,
        'unsupported': dict(reason) if status == STATUS_UNSUPPORTED else None,
        'compiled': {
            'artifact': ctx.compiled_artifact,
            'pointer': pointer,
            'path_id': row.get('path_id'),
            'flow_id': flow_id,
            'status': status,
            'reason': dict(reason),
            'target': row.get('target'),
            'direction': row.get('direction'),
            'sources': [dict(item) for item in (row.get('sources') or ())],
            'bound_inputs': [dict(item) for item in (row.get('bound_inputs') or ())],
            'prerequisites': [dict(item) for item in (row.get('prerequisites') or ())],
            'termination_observation': row.get('termination_observation'),
            'assertions': [dict(item) for item in (row.get('assertions') or ())],
            'runtime_path_identity': row.get('runtime_path_identity'),
            'constraints': {
                'declared_in': f'{ctx.compiled_artifact}:{pointer}/constraints',
                'policy_hash': (row.get('constraints') or {}).get('policy_hash'),
                'layout_hash': (row.get('constraints') or {}).get('layout_hash'),
                'rule_ids': list((row.get('constraints') or {}).get('rule_ids') or ()),
            },
            'not_claimed': list(row.get('not_claimed') or ()),
        },
        'assertion_results': findings_here,
    })


def _grade_component(identity: Mapping, pointer: str | None, ctx: _Context) -> dict:
    instance_id = identity['instance_id']
    role = identity.get('role')
    declared = bool(pointer)
    skipped = next((row for row in ctx.unavailable
                    if row['instance_id'] == instance_id), None)

    catalog = []
    if declared:
        catalog.append(_evidence(
            ctx.compiled_artifact,
            f'identity.{pointer}.instance_id={instance_id}; component_id='
            f'{identity.get("component_id")}; profile_fingerprint='
            f'{identity.get("profile_fingerprint")}',
            TIER_CATALOG))
    harness_pointer = ctx.harness_pointer(instance_id)
    row = ctx.harness_row(instance_id)
    if harness_pointer is not None and row is not None:
        catalog.append(_evidence(
            ctx.harness_artifact,
            f'{harness_pointer}/instance_id={instance_id}; kind={row.get("kind")}; '
            f'artifact_digest={row.get("artifact_digest")}',
            TIER_CATALOG))
    catalog_reason = (None if catalog else
                      'no supplied registry document names this component, so it '
                      'is not even in the catalog here')

    if row is not None and harness_pointer is not None:
        digest = row.get('artifact_digest')
        template = row.get('template') if isinstance(row.get('template'),
                                                     Mapping) else {}
        if not _text(digest):
            generated = (None, (
                f'{harness_pointer} carries no artifact_digest, so the harness '
                'identity that establishes generation is missing'))
        elif not _text(template.get('template_id')):
            generated = (None, (
                f'{harness_pointer} carries no admitted template identity, so the '
                'generated tier is not established by this document'))
        else:
            generated = ([
                _evidence(ctx.harness_artifact,
                          f'{harness_pointer}/artifact_digest={digest}',
                          TIER_GENERATED),
                _evidence(ctx.harness_artifact,
                          f'{harness_pointer}/template.template_id='
                          f'{template.get("template_id")}; variant_id='
                          f'{template.get("variant_id")}',
                          TIER_GENERATED),
            ], None)
    else:
        supplied = ctx.harness_supplied
        reason = (f'no harness_set.v1 was supplied, so nothing here establishes '
                  f'that a harness was generated for {instance_id}'
                  if not supplied else
                  f'harness_set.v1 carries no component with '
                  f'instance_id={instance_id}, so its generated tier is not '
                  'claimed for this component')
        generated = (None, reason)

    if skipped is not None:
        reason = (f'the component is declared locally unavailable '
                  f'({skipped["code"]}); missing: '
                  f'{"; ".join(skipped["missing"])}')
        tiers = [_tier(TIER_CATALOG, catalog, catalog_reason),
                 _tier(TIER_GENERATED, None, reason),
                 _tier(TIER_RTL_OPERATIONAL, None, reason),
                 _tier(TIER_CROSS_COMPONENT_ACCEPTED, None, reason),
                 _tier(TIER_COVERAGE_GUIDED_SEARCHED, None, reason),
                 _tier(TIER_BUG_CONFIRMED, None, reason)]
        return _subject('component', tiers=tiers, extra={
            'instance_id': instance_id,
            'component_id': identity.get('component_id'),
            'role': role,
            'kind': identity.get('kind'),
            'status': STATUS_SKIPPED_UNAVAILABLE,
            'skipped': dict(skipped),
            'harness': dict(row) if row is not None else None,
        })

    tiers = [
        _tier(TIER_CATALOG, catalog, catalog_reason),
        _tier(TIER_GENERATED, *generated),
        _tier(TIER_RTL_OPERATIONAL, *_rtl_gate(ctx.session,
                                               instance_id=instance_id)),
        _tier(TIER_CROSS_COMPONENT_ACCEPTED,
              *_cross_gate(ctx.session, ctx.instances, instance_id=instance_id)),
        _tier(TIER_COVERAGE_GUIDED_SEARCHED,
              *_coverage_gate(ctx.session, instance_id=instance_id)),
        _tier(TIER_BUG_CONFIRMED,
              *_bug_gate(ctx.findings, ctx.fresh, instance_id=instance_id)),
    ]
    return _subject('component', tiers=tiers, extra={
        'instance_id': instance_id,
        'component_id': identity.get('component_id'),
        'role': role,
        'kind': identity.get('kind'),
        'profile_fingerprint': identity.get('profile_fingerprint'),
        'sidecar_fingerprint': identity.get('sidecar_fingerprint'),
        'declared_by_compiled_paths': declared,
        'status': STATUS_GRADED,
        'skipped': None,
        'harness': ({'pointer': harness_pointer,
                     'instance_id': row.get('instance_id'),
                     'role': row.get('role'),
                     'kind': row.get('kind'),
                     'artifact_digest': row.get('artifact_digest'),
                     'binary': row.get('binary'),
                     'template': row.get('template')}
                    if row is not None else None),
    })


def _component_identities(compiled: Mapping, harness_rows: Sequence[Mapping]):
    identity = compiled.get('identity')
    identity = identity if isinstance(identity, Mapping) else {}
    rows: list[dict] = []
    cpu = identity.get('cpu')
    if isinstance(cpu, Mapping):
        if not _text(cpu.get('instance_id')):
            _refuse('compiled-paths-identity-instance-missing',
                    '/identity/cpu/instance_id')
        rows.append({**dict(cpu), 'role': 'cpu', 'pointer': 'cpu'})
    for index, item in enumerate(identity.get('devices') or ()):
        if not isinstance(item, Mapping) or not _text(item.get('instance_id')):
            _refuse('compiled-paths-identity-instance-missing',
                    f'/identity/devices/{index}/instance_id')
        rows.append({**dict(item), 'role': 'device',
                     'pointer': f'devices[{index}]'})
    known = {row['instance_id'] for row in rows}
    for row in harness_rows:
        if row['instance_id'] in known:
            continue
        rows.append({'instance_id': row['instance_id'], 'component_id': None,
                     'kind': row.get('kind'), 'role': row.get('role'),
                     'pointer': None})
        known.add(row['instance_id'])
    return rows


# ---------------------------------------------------------------------------
# mandatory cost / throughput sections
# ---------------------------------------------------------------------------

def _p5_rows(session: Mapping, group: str, absence_reason: str) -> list[dict]:
    rows = []
    for leaf, source in GROUP_SPECS[group]:
        entry = _p5_leaf(session, group, leaf)
        if entry is None:
            rows.append({'group': group, 'leaf': leaf, 'value': None,
                         'source': source, 'reason': absence_reason})
        else:
            rows.append({'group': group, 'leaf': leaf, 'value': entry.get('value'),
                         'source': entry.get('source'),
                         'reason': entry.get('reason')})
    return rows


def _build_cost(session: Mapping, harness_rows: Sequence[Mapping]) -> dict:
    measured = any(row['value'] is not None
                   for row in _p5_rows(session, BUILD_COST_GROUP, ''))
    if measured:
        status = 'measured'
    elif harness_rows:
        # The artifacts and their build identities are declared; the cost itself
        # was not measured by anything supplied here.
        status = 'declared'
    else:
        status = 'not_measured'
    absence = ('no saved online session was supplied, so no build or '
               'initialization cost was measured; this is an absence, not a '
               'measured 0')
    components = []
    for row in harness_rows:
        binary = row.get('binary')
        components.append({
            'instance_id': row.get('instance_id'),
            'role': row.get('role'),
            'kind': row.get('kind'),
            'artifact_digest': row.get('artifact_digest'),
            'binary': binary,
            'built': binary is not None,
            'template_id': (row.get('template') or {}).get('template_id')
            if isinstance(row.get('template'), Mapping) else None,
        })
    absences = []
    if not session.get('supplied'):
        absences.append({'quantity': BUILD_COST_GROUP, 'reason': absence})
    for row in components:
        if not row['built']:
            absences.append({
                'quantity': f'build.{row["instance_id"]}',
                'reason': (f'harness_set.v1 records binary=null for '
                           f'{row["instance_id"]}, so the harness was generated '
                           'without a build cache; generation success is not a '
                           'build measurement')})
    return {
        'status': status,
        'group': _p5_rows(session, BUILD_COST_GROUP, absence),
        'p5_arm_metrics': {'module': 'myfuzz.scenario.p5_arm_metrics',
                           'schema_version': P5_ARM_METRICS_SCHEMA,
                           'group': BUILD_COST_GROUP},
        'components': components,
        'absences': absences,
        'not_a_substitute_for': GENERATION_IS_NOT_PERFORMANCE,
    }


def _throughput(session: Mapping) -> dict:
    absence = ('no saved online session was supplied, so no useful throughput '
               'was measured; the leaves below are named absences, not zeros')
    groups = {group: _p5_rows(session, group, absence)
              for group in THROUGHPUT_GROUPS}
    effective = None
    if session.get('metrics_available'):
        entry = _p5_leaf(session, 'effective_cases_per_second',
                         'effective_cases_per_second')
        effective = None if entry is None else entry.get('value')
    status = 'measured' if isinstance(effective, (int, float)) else 'not_measured'
    absences = []
    if not session.get('supplied'):
        absences.append({'quantity': 'throughput', 'reason': absence})
    elif not session.get('metrics_available'):
        absences.append({'quantity': 'throughput',
                         'reason': session.get('metrics_reason')
                         or 'the p5 grouping is unavailable for this session'})
    else:
        for group, rows in groups.items():
            for row in rows:
                if row['value'] is None:
                    absences.append({
                        'quantity': f'{group}.{row["leaf"]}',
                        'reason': row['reason'] or absence})
    return {
        'status': status,
        'groups': groups,
        'p5_arm_metrics': {'module': 'myfuzz.scenario.p5_arm_metrics',
                           'schema_version': P5_ARM_METRICS_SCHEMA,
                           'checklist_metric_groups': list(CHECKLIST_METRIC_GROUPS)},
        'absences': absences,
        'not_a_substitute_for': GENERATION_IS_NOT_PERFORMANCE,
    }


# ---------------------------------------------------------------------------
# public entry point
# ---------------------------------------------------------------------------

def build_capability_report(compiled_paths, *, harness_set=None, session=None,
                            fresh_verification=None, checker_findings=None,
                            unavailable=None, label=None, base_dir='.') -> dict:
    """Grade one composition's paths and components from the supplied evidence.

    ``compiled_paths`` is required and is authoritative for path identity,
    status and reasons.  Everything else is optional evidence: a
    ``harness_set.v1`` document (or path), a saved online session directory, a
    fresh-verification document, checker findings and an explicit
    ``capability_unavailable.v1`` declaration.  Missing evidence never lowers a
    status and never raises: it is reported as *grade not claimed* with a reason.
    An unusable input raises :class:`CapabilityReportRefused` with ``code`` and
    ``pointer`` instead of producing a partly-graded document.
    """
    base = Path(base_dir)

    compiled, compiled_path = _load_document(
        compiled_paths, base_dir=base, code='compiled-paths',
        pointer='/compiled_paths')
    compiled_rows, compiled_counts = _validate_compiled_paths(compiled)
    compiled_desc = _described(compiled, compiled_path,
                               default=COMPILED_PATHS_SCHEMA)
    compiled_desc['counts'] = (dict(compiled_counts)
                               if isinstance(compiled_counts, Mapping) else None)

    limits: list[dict] = []
    harness_rows: list[Mapping] = []
    harness_desc: dict = {'supplied': False,
                          'reason': ('no harness_set.v1 was supplied, so the '
                                     'Generated tier is not claimed for any '
                                     'component')}
    if harness_set is not None:
        document, path = _load_document(harness_set, base_dir=base,
                                        code='harness-set',
                                        pointer='/harness_set')
        harness_rows = _validate_harness_set(document)
        harness_desc = {'supplied': True,
                        **_described(document, path,
                                     default=HARNESS_SET_SCHEMA_VERSION),
                        'tier': document.get('tier'),
                        'not_claimed': list(document.get('not_claimed') or ())}

    fresh = None
    fresh_desc: dict = {'supplied': False,
                        'reason': ('no fresh-verification document was supplied, '
                                   'so no finding is confirmed as replayable')}
    if fresh_verification is not None:
        document, path = _load_document(fresh_verification, base_dir=base,
                                        code='fresh-verification',
                                        pointer='/fresh_verification')
        fresh = _validate_fresh_verification(document)
        fresh_desc = {'supplied': True,
                      **_described(document, path,
                                   default='fresh-verification.json'),
                      'matches': fresh.get('matches'),
                      'first_difference': fresh.get('first_difference'),
                      'verification_scope': fresh.get('verification_scope'),
                      'full_prefix_confirmed': bool(
                          fresh.get('matches')
                          and fresh.get('first_difference') is None
                          and fresh.get('verification_scope') == 'full')}

    findings: list[Mapping] = []
    findings_desc: dict = {'supplied': False,
                           'reason': ('no checker findings were supplied, so no '
                                      'finding is reported and no bug is '
                                      'confirmed')}
    if checker_findings is not None:
        document, path = _load_document(checker_findings, base_dir=base,
                                       code='checker-findings',
                                       pointer='/checker_findings')
        document, findings = _validate_checker_findings(document)
        classifications: dict = {}
        for row in findings:
            key = row.get('classification') or 'undeclared'
            classifications[key] = classifications.get(key, 0) + 1
        findings_desc = {
            'supplied': True,
            **_described(document, path, default='checker findings'),
            'findings_total': len(findings),
            'classifications': classifications,
            'natural': [dict(row) for row in findings
                        if row.get('classification') == FINDING_NATURAL],
            'injected': [dict(row) for row in findings
                         if row.get('classification') == FINDING_INJECTED],
            'calibration': [dict(row) for row in findings
                            if row.get('classification') == FINDING_CALIBRATION],
            'undeclared': [dict(row) for row in findings
                           if row.get('classification') is None],
        }

    unavailable_rows: list[Mapping] = []
    unavailable_desc: dict = {'supplied': False,
                              'reason': ('no local unavailability was declared, '
                                         'so no component is reported as '
                                         'skipped_unavailable')}
    if unavailable is not None:
        document, path = _load_document(unavailable, base_dir=base,
                                       code='unavailable',
                                       pointer='/unavailable')
        unavailable_rows = _validate_unavailable(document)
        unavailable_desc = {'supplied': True,
                            **_described(document, path,
                                         default=UNAVAILABLE_SCHEMA),
                            'components': [dict(row) for row in unavailable_rows]}

    identities = _component_identities(compiled, harness_rows)
    if not identities:
        limits.append({
            'quantity': 'identity',
            'reason': (f'{compiled_desc["artifact"]} carries no component '
                       'identity block and no harness_set.v1 component names '
                       'one, so no component subject is graded here; the paths '
                       'are still graded as the document states them')})
    instances = [row['instance_id'] for row in identities]
    cpu_instance = next((row['instance_id'] for row in identities
                         if row.get('role') == 'cpu'), None)
    declared = set(instances)
    for index, row in enumerate(unavailable_rows):
        if row['instance_id'] not in declared:
            _refuse('unavailable-component-undeclared',
                    f'/unavailable/components/{index}/instance_id',
                    {'instance_id': row['instance_id'],
                     'declared_instances': sorted(declared)})

    if session is None:
        session_evidence = _empty_session(
            'no saved online session directory was supplied, so no real-run '
            'evidence exists in this report')
    else:
        session_evidence = _load_session(session, base_dir=base,
                                         instances=instances,
                                         cpu_instance=cpu_instance)
        if (session_evidence['receipts'].get('available')
                and session_evidence['linkage']['observed_instances']
                and not session_evidence['linkage'][
                    'observed_declared_instances']):
            limits.append({
                'quantity': 'session linkage',
                'reason': ('the session observed only '
                           f'{session_evidence["linkage"]["observed_instances"]}, '
                           'none of which this composition declares; no '
                           'session-derived tier can be attributed')})

    ctx = _Context(compiled_artifact=compiled_desc['artifact'],
                   harness_artifact=(harness_desc.get('artifact')
                                     if harness_desc.get('supplied') else None),
                   harness_supplied=bool(harness_desc.get('supplied')),
                   compiled_identity=compiled.get('identity'),
                   harness_rows=harness_rows,
                   session=session_evidence,
                   findings=findings,
                   fresh=fresh,
                   unavailable=unavailable_rows,
                   instances=instances,
                   cpu_instance=cpu_instance)

    paths = [_grade_path(row, index, ctx)
             for index, row in enumerate(compiled_rows)]
    components = [_grade_component(row, row.get('pointer'), ctx)
                  for row in identities]

    compiled_flows = {row['flow_id'] for row in compiled_rows}
    for flow_id in FLOW_IDS:
        if flow_id not in compiled_flows:
            limits.append({
                'quantity': f'paths.{flow_id}',
                'reason': (f'{compiled_desc["artifact"]} carries no record for '
                           f'{flow_id}; this report does not invent one')})
    if isinstance(compiled_counts, Mapping):
        observed = {
            'executable': sum(1 for row in compiled_rows
                              if row['status'] == STATUS_EXECUTABLE),
            'unsupported': sum(1 for row in compiled_rows
                               if row['status'] == STATUS_UNSUPPORTED),
            'total': len(compiled_rows)}
        for key, value in observed.items():
            if key in compiled_counts and compiled_counts[key] != value:
                limits.append({
                    'quantity': f'counts.{key}',
                    'reason': (f'{compiled_desc["artifact"]} declares '
                               f'counts.{key}={compiled_counts[key]} but its own '
                               f'path records state {value}')})
    for row in harness_rows:
        if row['instance_id'] not in {item['instance_id']
                                      for item in identities}:
            limits.append({
                'quantity': f'harness_set.components.{row["instance_id"]}',
                'reason': ('harness_set.v1 declares a component the compiled '
                           'paths do not; it is graded with harness evidence '
                           'only')})
    unavailable_names = {row['instance_id'] for row in unavailable_rows}
    for row in harness_rows:
        if row['instance_id'] in unavailable_names:
            limits.append({
                'quantity': f'unavailable.{row["instance_id"]}',
                'reason': ('the component is declared locally unavailable and '
                           'also carries a generated harness in harness_set.v1; '
                           'the unavailability declaration wins and no tier is '
                           'claimed')})
    if fresh_desc.get('supplied') and not fresh_desc.get('full_prefix_confirmed'):
        limits.append({
            'quantity': 'fresh_replay',
            'reason': ('the fresh replay does not confirm the complete prefix '
                       f'(matches={fresh_desc.get("matches")!r}, '
                       f'first_difference={fresh_desc.get("first_difference")!r}, '
                       f'verification_scope='
                       f'{fresh_desc.get("verification_scope")!r})')})
    if session_evidence['receipts'].get('unreadable_rows'):
        limits.append({
            'quantity': 'receipts.jsonl',
            'reason': (f'{session_evidence["receipts"]["unreadable_rows"]} line(s) '
                       'could not be decoded and are excluded from every count')})

    unsupported_reasons = []
    for record in paths:
        if record['unsupported'] is None:
            continue
        carried = record['unsupported']
        unsupported_reasons.append({
            'subject': 'path',
            'instance_id': None,
            'path_id': record['path_id'],
            'flow_id': record['flow_id'],
            'code': carried.get('code'),
            'pointer': carried.get('pointer'),
            'detail': carried.get('detail'),
            'missing': [dict(item) for item in carried.get('missing') or ()],
            'assertion_results': record['assertion_results'],
        })

    skipped = [record['skipped'] for record in components
               if record['status'] == STATUS_SKIPPED_UNAVAILABLE]
    assertion_results = []
    for record in paths:
        for row in record['assertion_results']:
            assertion_results.append({
                'flow_id': record['flow_id'], 'path_id': record['path_id'],
                'finding_id': row.get('finding_id'),
                'expectation_id': row.get('expectation_id'),
                'assertion_class': row.get('assertion_class'),
                'classification': row.get('classification'),
                'outcome': row.get('outcome', row.get('status')),
                'detail': row.get('detail')})

    tier_awards = {tier: sum(1 for subject in [*paths, *components]
                             for row in subject['tiers']
                             if row['tier'] == tier and row['claimed'])
                   for tier in CAPABILITY_TIERS}

    not_claimed = [
        ('this report generates, builds, runs and replays nothing; every grade is '
         'read from the supplied artifacts, so capability_report.v1 is an '
         'aggregation and not a run'),
        ('a tier is claimed only when its own `evidence` entry names the artifact '
         'and the fact that establish it; a tier without such evidence is listed '
         'per subject as grade_not_claimed and is not claimed here'),
        ('grade_not_claimed is not `unsupported`: `unsupported` is a P7-C compiled '
         'status with a named reason and is carried verbatim in '
         '`unsupported_reasons`'),
        GENERATION_IS_NOT_PERFORMANCE,
        ('coverage records and certified chains are not by themselves a confirmed '
         'defect, and an ordering-only observation is not a causal hit'),
    ]
    if not harness_desc.get('supplied'):
        not_claimed.append('no harness_set.v1 was supplied, so no component '
                          'reaches the Generated tier here')
    if not session_evidence.get('supplied'):
        not_claimed.append('no saved online session was supplied, so no RTL '
                           'operational, Cross-component accepted, Coverage-guided '
                           'searched or Bug confirmed tier is claimed from a run')
    if not fresh_desc.get('supplied') or not fresh_desc.get(
            'full_prefix_confirmed'):
        not_claimed.append('no full-prefix fresh replay is confirmed, so no '
                           'finding is claimed as replayable')
    if any(record['status'] == STATUS_SKIPPED_UNAVAILABLE for record in components):
        not_claimed.append('a component declared locally unavailable is reported '
                           'with status skipped_unavailable and its missing '
                           'conditions; that status is not a tier')

    return {
        'schema_version': CAPABILITY_REPORT_SCHEMA,
        'generated': False,
        'label': label,
        'tier_vocabulary': {
            'order': list(CAPABILITY_TIERS),
            'non_tiers': [STATUS_SKIPPED_UNAVAILABLE],
            'authority': TIER_AUTHORITY,
            'evidence_rule': EVIDENCE_RULE,
            'no_implication': ('one tier never implies the next; each tier has its '
                              'own evidence gate and the adjacent tiers are '
                              'checked separately'),
            'statuses': list(SUBJECT_STATUSES),
        },
        'inputs': {
            'compiled_paths': compiled_desc,
            'harness_set': harness_desc,
            'fresh_verification': fresh_desc,
            'checker_findings': findings_desc,
            'unavailable': unavailable_desc,
            # A descriptor only: the full session evidence lives under the
            # top-level `session` key and is not serialized twice.
            'session': _session_descriptor(session_evidence),
        },
        'identity': {
            'cpu': next((row for row in identities if row.get('role') == 'cpu'),
                        None),
            'devices': [row for row in identities if row.get('role') != 'cpu'],
            'components': [{'instance_id': row['instance_id'],
                            'component_id': row.get('component_id'),
                            'role': row.get('role'),
                            'kind': row.get('kind'),
                            'declared_by_compiled_paths': bool(row.get('pointer'))}
                           for row in identities],
            'session_run_id': session_evidence.get('run_id'),
        },
        'paths': paths,
        'components': components,
        'skipped_unavailable': skipped,
        'unsupported_reasons': unsupported_reasons,
        'session': session_evidence,
        'build_cost': _build_cost(session_evidence, harness_rows),
        'throughput': _throughput(session_evidence),
        'fresh_replay': fresh_desc,
        'checker_findings': findings_desc,
        'assertion_results': assertion_results,
        'counts': {
            'compiled_paths': (dict(compiled_counts)
                               if isinstance(compiled_counts, Mapping) else None),
            'paths': len(paths),
            'executable': sum(1 for row in paths
                              if row['compiled_status'] == STATUS_EXECUTABLE),
            'unsupported': sum(1 for row in paths
                               if row['compiled_status'] == STATUS_UNSUPPORTED),
            'components': len(components),
            'graded': sum(1 for row in components
                          if row['status'] == STATUS_GRADED),
            'skipped_unavailable': len(skipped),
            'tier_awards': tier_awards,
        },
        'limits': [*limits, *session_evidence.get('limits', [])],
        'not_claimed': not_claimed,
    }


__all__ = [
    'BUILD_COST_GROUP', 'CAPABILITY_REPORT_SCHEMA', 'CAPABILITY_TIERS',
    'DISPOSITION_AWARDED', 'DISPOSITION_NOT_CLAIMED', 'EVIDENCE_RULE',
    'FINDING_CALIBRATION', 'FINDING_CLASSIFICATIONS', 'FINDING_INJECTED',
    'FINDING_NATURAL', 'ORDERING_ONLY_FEATURE_PREFIXES', 'STATUS_GRADED',
    'STATUS_SKIPPED_UNAVAILABLE', 'SUBJECT_STATUSES', 'THROUGHPUT_GROUPS',
    'TIER_AUTHORITY', 'TIER_BUG_CONFIRMED', 'TIER_CATALOG',
    'TIER_COVERAGE_GUIDED_SEARCHED', 'TIER_CROSS_COMPONENT_ACCEPTED',
    'TIER_GENERATED', 'TIER_RTL_OPERATIONAL', 'UNAVAILABLE_SCHEMA',
    'CapabilityReportRefused', 'build_capability_report',
]
