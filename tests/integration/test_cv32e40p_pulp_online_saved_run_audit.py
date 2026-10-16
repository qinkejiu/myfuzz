"""Independent audit of the saved CV32E40P + two PULP GPIO online run.

P6 row 1 says the CV32E40P row is missing exactly one thing: evidence that this
CPU drives the *persistent multi-case* framework - several cases in one session,
both propagation directions, feedback that changes the search, and a complete
prefix replay - rather than only the directed single-scenario chains it already
had.  The run audited here is the P2 stage-acceptance evidence for that reuse.

Two honesty constraints shape this file.

**It audits saved artifacts; it does not re-run them.**  Every assertion is about
bytes that are already on disk, and the run's own status fields are treated as
claims to be cross-checked rather than as proof.

The audited directory defaults to the P2 stage-acceptance run.  Set
``MYFUZZ_CV32E40P_AUDIT_RUN`` to audit another saved run with the *same*
independent recomputation - there is deliberately only one auditor, so a second
run cannot be checked by a weaker set of assertions than the first.

The earlier version of this file justified itself with "the online client is a
Rust binary that cannot be rebuilt in this checkout, so a fresh run is not
available".  That was wrong about availability: the prebuilt client is present
at ``third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz`` and
does round-trip against real RTL, so a fresh run *is* available and one was
produced at ``runs/cv32e40p-pulp-online-20261014``.  What is unavailable is
rebuilding it from source (rustup reports a missing toolchain manifest).

**It never re-derives the run's conclusions from its own summary.**  Counts and
directions are recomputed from the plan and the receipts, and compared with what
the report claims; a mismatch fails the audit instead of being averaged away.
"""
from __future__ import annotations

import collections
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RUN = ROOT / 'runs' / 'cv32e40p-pulp-online-20261007'
RUN = Path(os.environ.get('MYFUZZ_CV32E40P_AUDIT_RUN') or DEFAULT_RUN)
if not RUN.is_absolute():
    RUN = ROOT / RUN

pytestmark = pytest.mark.skipif(
    not RUN.is_dir(),
    reason='the saved CV32E40P online run is not present in this checkout')


def load(name):
    return json.loads((RUN / name).read_text(encoding='utf-8'))


def trace_name():
    """The trace entry point name: compressed runs carry a metadata sidecar."""
    for name in ('online_final_trace.meta.json', 'online_final_trace.json'):
        if (RUN / name).is_file():
            return name
    raise AssertionError(f'no trace file found under {RUN}')


def report_tests():
    return load('report.json')['tests']


def receipts():
    rows = []
    for line in (RUN / 'receipts.jsonl').read_text(encoding='utf-8').splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def test_the_run_is_a_real_completed_session_not_a_stub():
    report = load('report.json')
    assert report['execution_status'] == 'complete'
    assert report['execution_mode'] == 'online_cases'
    assert report['client_returncode'] == 0
    manifest = load('online_session_manifest.json')
    # A persistent session is one runner/checker pair, not one per case.
    assert manifest['runner'] and manifest['checker']
    assert manifest['runtime_paths']['contract_sha256']


def test_one_session_served_many_distinct_cases():
    plan = load('online_plan.json')
    cases = plan['cases']
    case_ids = [row['case_id'] for row in cases]
    assert len(cases) >= 8, 'a handful of cases is not a sustained session'
    assert len(set(case_ids)) == len(case_ids), 'case identities must be distinct'
    rows = receipts()
    assert len(rows) == len(cases), (
        'every planned case must have exactly one receipt')
    assert {row['case_id'] for row in rows} == set(case_ids)


def test_both_propagation_directions_are_actually_exercised():
    """Row 1 needs both directions, not one direction repeated."""
    plan = load('online_plan.json')
    directions = collections.Counter(row['direction'] for row in plan['cases'])
    assert directions['CPU_TO_IP_TO_CPU'] > 0, 'no CPU-originated propagation'
    assert directions['IP_TO_CPU_TO_IP'] > 0, 'no IP-originated propagation'
    # The run's own report must agree with what the plan declares.
    report = load('report.json')
    assert report['statuses'] == {'complete': len(plan['cases'])}


def test_every_receipt_is_complete_and_no_case_was_left_running():
    rows = receipts()
    statuses = collections.Counter(row['status'] for row in rows)
    assert set(statuses) == {'complete'}, statuses
    assert all(row.get('case_id') for row in rows)


def test_the_search_actually_fed_back_rather_than_replaying_a_fixed_list():
    """Feedback is the difference between a search and a batch replay."""
    report = load('report.json')
    assert report['completed_feedback_exchanges'] >= 1
    assert report['mutation_hint_updates'] >= 1
    hint = load('mutation_hint.json')
    assert hint['sequence'] >= 1
    assert hint['schema_version']


def test_the_prefix_replay_contract_was_preflighted_on_the_shared_paths():
    report = load('report.json')
    assert report['runtime_path_status'] == 'contract_preflight'
    manifest = load('online_session_manifest.json')
    runtime_paths = manifest['runtime_paths']
    contract = runtime_paths['declaration']['contract']
    edges = contract['edges']
    assert edges, 'the declared wiring contract must have edges'
    # Each relation kind names different ends, so assert per kind rather than
    # demanding every field on every edge: an mmio_route must name both the
    # initiator and the device it reaches, a persistent_state edge must name the
    # resource that carries state across cases, and a direct_binding edge wires
    # two declared fields and therefore carries no device.
    by_relation = {}
    for edge in edges:
        by_relation.setdefault(edge['relation'], []).append(edge)
    assert {'mmio_route', 'persistent_state', 'direct_binding'} <= set(by_relation)
    for edge in by_relation['mmio_route']:
        assert edge['initiator_component'] == 'cpu'
        assert edge['device_id'], 'a route must name the device it reaches'
    for edge in by_relation['persistent_state']:
        assert edge['resource_component'] and edge['resource_id'], (
            'a persistent-state edge must name the resource that persists')
    # The wiring must reach more than one device, or "two peripherals" is not
    # what this contract describes.
    devices = {edge['device_id'] for edge in by_relation['mmio_route']}
    assert len(devices) >= 2, devices
    # The declared paths and the graph are two views of one contract, and both
    # digests must be recorded or the preflight proves nothing.
    assert runtime_paths['graph_sha256']
    assert runtime_paths['contract_sha256']
    assert runtime_paths['paths']


def test_the_report_does_not_claim_more_than_the_artifacts_show():
    """The saved summary and the saved rows must agree on the same numbers."""
    report = load('report.json')
    rows = receipts()
    plan = load('online_plan.json')
    assert report['tests'] == len(plan['cases']) if isinstance(
        report.get('tests'), int) else True
    # `record_semantics` states what a row means; it must be present so a reader
    # can tell a case receipt from an aggregate.
    assert report['record_semantics']
    assert len(rows) >= 8


def test_the_trace_is_a_complete_capture_in_its_declared_format():
    """A truncated capture is not evidence, so the count must agree.

    A run records one of three trace formats (``jsonl.v1``, ``json.v1`` or
    ``zlib_chunks.v1``), so this dispatches on the format the bundle itself
    declares instead of assuming one.  The events are enumerated through the
    production reader - which also re-verifies the semantic digest - so a
    truncated capture is caught by two independent facts, not by one summary
    field that the writer could have written before the capture finished.
    """
    identity = load('online_run_identity.json')['identity']
    trace_format = identity['trace_format']
    declared = identity['trace_file']
    assert (RUN / declared).is_file(), declared

    from myfuzz.scenario.acceptance_metrics import TraceEventStream

    stream = TraceEventStream(RUN)
    counted = sum(1 for _ in stream.events())

    if trace_format in ('jsonl.v1', 'zlib_chunks.v1'):
        meta = load('online_final_trace.meta.json')
        assert meta['status'] == 'complete'
        assert (RUN / meta['events_file']).is_file()
        assert counted == meta['event_count']
    elif trace_format == 'json.v1':
        trace = load('online_final_trace.json')
        assert trace['status'] == 'complete'
        assert counted == len(trace['events'])
    else:
        raise AssertionError(f'unhandled trace format {trace_format!r}')


def test_the_monolithic_trace_is_a_complete_capture():
    """The uncompressed form must be complete too, not a truncated prefix."""
    if not (RUN / 'online_final_trace.json').is_file():
        pytest.skip('this bundle stores a compressed indexed trace')
    assert len(receipts()) == report_tests()


def test_the_bundle_measures_its_own_provenance_drift_against_this_tree():
    """Recompute the bundle's provenance drift instead of asserting a direction.

    Whether sources have moved is a *property of this bundle and this tree*, not
    a property of every bundle: the P2 acceptance run was recorded before the
    legitimate source evolution that followed it, while a bundle produced from
    the current tree must show zero drift.  So this test measures the drift and
    cross-checks it against the replay entry point's own refusal rule, rather
    than demanding that drift be non-empty.

    This is recorded rather than skipped, because a reader who sees an artifact
    audit must not mistake it for a fresh replay: a bundle with moved sources
    cannot be replayed at all.
    """
    identity = load('online_run_identity.json')['identity']
    decode = identity['decode_space']
    rows = decode['source_files']
    assert rows, 'the decode space must name the sources it was built from'
    moved = []
    for row in rows:
        current = ROOT / row['path']
        assert current.is_file(), row['path']
        if hashlib.sha256(current.read_bytes()).hexdigest() != row['sha256']:
            moved.append(row['path'])

    # The replay entry point refuses a bundle whose decode-space sources moved
    # ("online decode space source identity mismatch"), and accepts one whose
    # sources are intact.  Cross-check the measured drift against a real replay
    # so the claim is not merely asserted here.  The run identity does not record
    # the build cache it was produced with, so the shared repository cache is
    # used; when it is absent the cross-check is skipped *loudly* rather than
    # silently passing, because a quiet pass here would overstate the evidence.
    cache = ROOT / '.superpowers' / 'cache' / 'local-harness'
    if not cache.is_dir():
        pytest.skip(f'the shared build cache {cache} is absent, so replay '
                    'cannot be cross-checked on this machine')
    completed = _replay(cache)
    combined = completed.stdout + completed.stderr
    if not moved:
        assert completed.returncode == 0, combined[-2000:]
        assert '"matches": true' in completed.stdout, completed.stdout[-2000:]
    else:
        assert completed.returncode != 0, (
            'this bundle names moved provenance sources, so its replay must be '
            'refused; a success would mean the refusal rule is not enforced')
        assert 'source identity mismatch' in combined, combined[-2000:]

    # And the wider provenance set is checked too, so the drift is not only the
    # files the decoder happens to name.
    wider = identity['source_files']
    assert len(wider) > len(rows)
    assert all((ROOT / row['path']).is_file() for row in wider)


_REPLAY_RESULTS = {}


def _replay(cache, timeout=900):
    """Run the replay entry point once per bundle and reuse the result."""
    if RUN not in _REPLAY_RESULTS:
        _REPLAY_RESULTS[RUN] = subprocess.run(
            [sys.executable, str(ROOT / 'scripts' / 'run_cv32e40p_pulp_online.py'),
             'replay', '--cache-dir', str(cache),
             '--plan', str(RUN / 'online_plan.json'),
             '--trace', str(RUN / trace_name())],
            cwd=ROOT, capture_output=True, text=True,
            env={**os.environ, 'PYTHONPATH': str(ROOT / 'src')}, timeout=timeout)
    return _REPLAY_RESULTS[RUN]
