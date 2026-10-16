"""Independent audit of a saved CVA6 + two OpenTitan GPIO scenario campaign.

P6 row 2 (``docs/superpowers/plans/2026-10-13-p6-per-protocol-row-checklist.md``
line 120) records exactly one missing item for the complete-AXI4/CVA6 row:
the row's already-accepted local protocol evidence, two-way MMIO/IRQ paths and
real ISRs are all *directed* scenarios, and what is missing is a **continuous
multi-case session** - ``多例持续会话＋反馈驱动变异＋完整前缀 replay``.
``myfuzz.integration.scenario_campaign.run_scenario_campaign`` is the framework
that is supposed to supply it, and ``myfuzz.integration.cva6_scenario_campaign.
Cva6TwoGpioBoundProvider`` is its CVA6 provider.

Two honesty constraints shape this file.

**It audits saved bytes; it does not re-run the campaign.**  Every count in
``campaign_report.json`` is treated as a claim to be cross-checked, never as
proof: the receipts, chain checks, mutation selections and corpus entries on
disk are recomputed here with the same rules the gate uses and compared against
what the report claims.  A mismatch fails the audit instead of being averaged
away.

**It deliberately does not re-run the RTL.**  A campaign cell is only evidence
of a *real* run because its receipts carry positive per-component local ticks
for the three real RTL instances and a single manifest identity; that is
asserted directly from the saved receipts.

The audited directory defaults to the run recorded below.  Set
``MYFUZZ_CVA6_CAMPAIGN_RUN`` to audit another saved campaign with the *same*
independent recomputation - there is deliberately only one auditor, so a second
campaign cannot be checked by a weaker set of assertions than the first.
"""
from __future__ import annotations

import collections
import hashlib
import json
import os
from pathlib import Path

import pytest

from myfuzz.integration.scenario_campaign import (
    MINIMUM_G4_SECONDS,
    ReplayEvidence,
    SearchEvidence,
    _gate_failures,
    campaign_matrix,
    CampaignConfig,
)

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RUN = (ROOT / 'runs' / 'scenario' /
               'campaign-cva6-g4-18cell-p6-row2-20261014-v2')
RUN = Path(os.environ.get('MYFUZZ_CVA6_CAMPAIGN_RUN') or DEFAULT_RUN)
if not RUN.is_absolute():
    RUN = ROOT / RUN

# The two sides row 2 asks to be driven *both* from the CPU and from the IP.
CPU_SIDE_SOURCES = {'cpu.program', 'cpu.isr'}
IP_SIDE_SOURCES = {'b.pin8', 'b.pin9'}
BOUND_STRATEGIES = {'dependency_guided', 'uniform_source'}
REAL_RTL_COMPONENTS = {'cpu', 'gpio_a', 'gpio_b'}

pytestmark = pytest.mark.skipif(
    not RUN.is_dir(),
    reason='the saved CVA6 campaign bundle is not present in this checkout')


def report():
    return json.loads((RUN / 'campaign_report.json').read_text(encoding='utf-8'))


def cell_dir(cell_id):
    return RUN / cell_id


def _jsonl(path):
    if not path.is_file():
        return []
    return [json.loads(line) for line in
            path.read_text(encoding='utf-8').splitlines() if line.strip()]


def receipts(cell_id):
    return _jsonl(cell_dir(cell_id) / 'live' / 'receipts.jsonl')


def chain_checks(cell_id):
    return _jsonl(cell_dir(cell_id) / 'chain_checks.jsonl')


def live_report(cell_id):
    return json.loads((cell_dir(cell_id) / 'live' / 'report.json')
                      .read_text(encoding='utf-8'))


def corpus_entries(cell_id):
    return sorted((cell_dir(cell_id) / 'live' / 'corpus').glob('entry_*.json'))


def bound_cells(document):
    return [cell for cell in document['cells']
            if cell['strategy'] in BOUND_STRATEGIES]


def test_report_claims_a_complete_eighteen_cell_campaign_for_new_inputs():
    document = report()
    assert document['schema_version'] == 'scenario_campaign.v1'
    assert document['gate'] == 'G4'
    assert document['required_cells'] == 18
    cells = document['cells']
    assert len(cells) == 18, 'G4 is an 18-cell matrix, not a subset'
    matrix = campaign_matrix(CampaignConfig(RUN / 'inputs/bound/cva6_cpu_two_gpio_campaign_seed.json',
                                            RUN / 'inputs/independent/cva6_two_gpio_campaign_baseline.json'))
    assert [cell.cell_id for cell in matrix] == [cell['cell_id'] for cell in cells]
    assert document['gate_status'] == 'complete'
    assert all(cell['status'] == 'complete' for cell in cells)
    assert all(cell['gate_failures'] == [] for cell in cells)
    assert all(cell['error'] is None for cell in cells)
    # The campaign must be reproducible from frozen inputs, not from a tree
    # that changed while it ran.
    assert document['campaign_source_identity_stable'] is True
    assert document['campaign_source_identity'] == document['campaign_source_identity_end']
    assert document['campaign_input_stability']['originals_stable'] is True
    assert document['campaign_input_stability']['snapshots_stable'] is True
    assert document['campaign_inputs']['bound']['closure_status'] == 'provider_declared'
    assert document['campaign_inputs']['independent']['closure_status'] == 'provider_declared'


def test_every_cell_saved_real_rtl_receipts_that_recompute_its_counts():
    document = report()
    for cell in document['cells']:
        cell_id = cell['cell_id']
        saved = receipts(cell_id)
        assert saved, f'{cell_id}: no saved receipts'
        search = cell['search']
        assert search is not None, cell_id

        # Multi-case continuous session: many cases in one session, all of them
        # executed through the real RTL instances.
        assert search['testcases'] == len(saved) == live_report(cell_id)['tests']
        assert search['testcases'] > 9, cell_id

        cycles = collections.Counter()
        statuses = collections.Counter()
        manifests = set()
        for receipt in saved:
            statuses[receipt['status']] += 1
            manifests.add(receipt['manifest_sha256'])
            ticks = receipt['local_ticks']
            assert set(ticks) == REAL_RTL_COMPONENTS, (cell_id, sorted(ticks))
            assert all(type(value) is int and value > 0 for value in ticks.values()), \
                (cell_id, ticks)
            assert receipt['total_local_ticks'] == sum(ticks.values())
            for component, value in ticks.items():
                cycles[component] += value
        assert len(manifests) == 1, f'{cell_id}: mixed manifest identity'
        assert dict(cycles) == dict(search['local_cycles']), cell_id
        assert dict(statuses) == dict(search['failures']), cell_id
        assert search['valid_testcases'] == sum(
            count for status, count in statuses.items()
            if status in ('complete', 'dut_violation'))
        assert cell['valid_rate'] == search['valid_testcases'] / search['testcases']
        # The gate counts these two classes as unresolved execution failures;
        # a cell that reached "complete" cannot contain them.
        assert not statuses.get('environment_error') and not statuses.get('uncertain_effect')
        assert search['status'] == 'ok'
        assert search['seed_status'] == 'supported'
        assert search['effective_search_seconds'] >= max(MINIMUM_G4_SECONDS,
                                                         cell['requested_seconds'])
        assert search['effective_search_seconds'] <= cell['cost']['search_wall_seconds'] + 0.05


def test_the_two_sides_are_both_really_driven_in_every_bound_cell():
    """Row 2 item 4: 逐例双侧源 - CPU side *and* IP side, both really selected."""
    document = report()
    recomputed = {}
    for cell in bound_cells(document):
        cell_id = cell['cell_id']
        uses = collections.Counter()
        for receipt in receipts(cell_id):
            for source in receipt['applied_sources']:
                uses[source] += 1
        assert dict(uses) == cell['search']['applied_source_uses'], cell_id
        recomputed.setdefault(f"{cell['strategy']}__{cell['direction']}", []).append(uses)

    groups = sorted(recomputed)
    assert groups == [f'{strategy}__{direction}'
                      for strategy in ('dependency_guided', 'uniform_source')
                      for direction in ('CPU_TO_IP_TO_CPU', 'IP_TO_CPU_TO_IP')]
    for group, per_seed in recomputed.items():
        declared = set().union(*(set(uses) for uses in per_seed))
        expected = CPU_SIDE_SOURCES if group.endswith('CPU_TO_IP_TO_CPU') else IP_SIDE_SOURCES
        assert declared == expected, group
        assert len(declared) == 2, group
        coverage = document['actual_source_coverage'][group]
        assert coverage['measured'] is True
        assert coverage['declared'] == sorted(declared)
        assert coverage['executed'] == sorted(declared)
        # Stronger than the gate: every seed must exercise every declared
        # source, so a single direction cannot be carried by one seed.
        for uses in per_seed:
            assert set(uses) == declared, (group, dict(uses))
            assert all(count > 0 for count in uses.values()), (group, dict(uses))


def test_feedback_really_changed_the_search_after_the_seed():
    """Row 2 item 5: 交互反馈 - search decisions follow observed RTL results."""
    document = report()
    for cell in bound_cells(document):
        cell_id = cell['cell_id']
        selections = _jsonl(cell_dir(cell_id) / 'mutation_selections.jsonl')
        live = live_report(cell_id)
        assert live['mutation_hint_updates'] == len(selections) >= 2, cell_id
        assert live['completed_feedback_exchanges'] >= 1, cell_id
        assert [item['sequence'] for item in selections] == \
            list(range(1, len(selections) + 1)), cell_id
        assert {item['run_id'] for item in selections} == {cell_id}
        # The later hints must carry feedback from completed batches: a hint
        # that never saw a completed batch is not feedback-driven.
        assert any(item['latest_completed_batch'] for item in selections[1:]), cell_id
        seen = [item['max_completed_buffer_id'] for item in selections
                if item['max_completed_buffer_id'] is not None]
        assert seen and max(seen) >= 1, cell_id

        saved = receipts(cell_id)
        seed_buffer = saved[0]['buffer_id']
        batches = {receipt['buffer_id'] for receipt in saved[1:]
                   if receipt['buffer_id'] != seed_buffer
                   and receipt['genome_sha256'] is not None
                   and receipt['total_local_ticks'] > 0
                   and receipt['applied_sources']}
        assert len(batches) == cell['search']['post_seed_mutation_batches'] >= 2, cell_id


def test_post_seed_diversity_and_completed_chains_recompute_from_artifacts():
    """Row 2 item 6: 断言 - an independently assessed closed chain, post-seed."""
    document = report()
    for cell in bound_cells(document):
        cell_id = cell['cell_id']
        saved = receipts(cell_id)
        checks = chain_checks(cell_id)
        search = cell['search']
        assert len(checks) == len(saved), cell_id

        seed_hash = saved[0]['effective_genome_sha256']
        variants = {receipt['effective_genome_sha256'] for receipt in saved[1:]
                    if receipt['status'] in ('complete', 'dut_violation')
                    and receipt['total_local_ticks'] > 0
                    and receipt['effective_genome_sha256']
                    and receipt['effective_genome_sha256'] != seed_hash}
        assert len(variants) == search['post_seed_effective_genotypes'] >= 2, cell_id

        complete = {check['genome_sha256'] for check in checks
                    if check['assessment'] and check['assessment'].get('complete')}
        assert len(complete) == search['completed_chains'] > 0, cell_id
        post_seed = sum(receipt['genome_sha256'] in complete for receipt in saved[1:]
                        if receipt['status'] in ('complete', 'dut_violation')
                        and receipt['total_local_ticks'] > 0
                        and receipt['effective_genome_sha256'] in variants)
        assert post_seed == search['post_seed_completed_chains'] >= 1, cell_id
        # A completed assessment is two ordered real RTL rounds, not a claim.
        for check in checks:
            if check['assessment'] and check['assessment'].get('complete'):
                assert check['assessment']['rounds'] == 2, cell_id


def test_replay_covers_the_whole_saved_corpus_including_failures():
    """Row 2 item 7: 完整前缀 fresh replay."""
    document = report()
    for cell in document['cells']:
        cell_id = cell['cell_id']
        entries = corpus_entries(cell_id)
        replay = cell['replay']
        assert replay is not None, cell_id
        assert replay['error'] is None, (cell_id, replay['error'])
        assert len(entries) == cell['search']['saved_corpus_entries'] >= 1, cell_id
        assert replay['total_entries'] == len(entries), cell_id
        assert replay['matched_entries'] == replay['total_entries'], cell_id
        assert replay['matched_failure_entries'] == replay['failure_entries'], cell_id
        failure_dir = cell_dir(cell_id) / 'live' / 'failures'
        saved_failures = sorted(failure_dir.glob('*.json')) if failure_dir.is_dir() else []
        assert replay['failure_entries'] == len(saved_failures), cell_id


def test_every_cell_is_this_rows_cpu_and_ip_and_not_another_rows():
    """Artifact-derived row identity: the campaign cannot be relabelled.

    Every bound cell's saved runner manifest must name the pinned CVA6 source
    closure as the CPU session and the real OpenTitan GPIO as both IP targets.
    A Wishbone/OBI manifest cannot produce these bytes, so these cells are
    row 2's evidence and may not be offered for rows 3/4/5.
    """
    document = report()
    for cell in document['cells']:
        cell_id = cell['cell_id']
        manifest = json.loads((cell_dir(cell_id) / 'live' /
                               'runner_manifest.json').read_text(encoding='utf-8'))
        sessions = manifest['sessions']
        assert set(sessions) == REAL_RTL_COMPONENTS, cell_id
        assert sessions['cpu']['type'] == \
            'myfuzz.scenario.cva6_session.Cva6CpuSession', cell_id
        cpu_files = [item['path'] for item in
                     sessions['cpu']['identity']['sources']['files']]
        assert sum('third_party/cva6_upstream_reference/' in path
                   for path in cpu_files) >= 200, cell_id
        assert not any('wishbone' in path.lower() for path in cpu_files), cell_id
        for gpio in ('gpio_a', 'gpio_b'):
            identity = sessions[gpio]['identity']
            ip_files = [item['path'] for item in identity['sources']['files']]
            assert sum('opentitan' in path.lower() for path in ip_files) >= 40, \
                (cell_id, gpio)
            # A real pinned upstream revision built by Verilator - not a host
            # register model standing in for the IP.  (Both arms use the real
            # OpenTitan GPIO RTL; the independent arm subclasses the session
            # only to apply its own local window configuration, so the class
            # name is not the identity - the source closure and revision are.)
            assert identity['revision'].startswith('git:'), (cell_id, gpio)
            assert identity['toolchain']['verilator']['available'] is True, \
                (cell_id, gpio)
        if cell['strategy'] in BOUND_STRATEGIES:
            # The closed chain needs a real CPU->IP MMIO window and a real
            # IP->CPU IRQ binding; both are declared in the saved manifest.
            windows = {window['device_id']: window
                       for window in manifest['windows']['cpu']}
            assert windows['gpio_a']['base'] == 0x40001000, cell_id
            assert windows['gpio_b']['base'] == 0x40000000, cell_id
            assert manifest['bindings'] == [
                {'source_component': 'gpio_a', 'source_port': 'gpio_out',
                 'source_bit_offset': 0, 'target_component': 'gpio_b',
                 'target_port': 'gpio_in', 'target_bit_offset': 0, 'width': 8},
                {'source_component': 'gpio_b', 'source_port': 'irq',
                 'source_bit_offset': 0, 'target_component': 'cpu',
                 'target_port': 'irq', 'target_bit_offset': 0, 'width': 1},
            ], cell_id
            owners = manifest['ownership']['owners']
            irq = [owner for owner in owners
                   if owner['component_id'] == 'cpu' and owner['port'] == 'irq'
                   and owner['bit_offset'] == 0]
            # The Scheduler may never synthesize this IRQ: it is bound to a
            # real GPIO B RTL output.
            assert irq and irq[0]['kind'] == 'bound' \
                and irq[0]['producer_ref'] == 'gpio_b.irq', cell_id
            external = [owner for owner in owners
                        if owner['component_id'] == 'gpio_b'
                        and owner['port'] == 'gpio_in']
            assert [(owner['bit_offset'], owner['width'], owner['kind'])
                    for owner in external] == [(0, 8, 'bound'), (8, 24, 'source')], \
                cell_id
        else:
            # The independent arm is an explicitly declared diagnostic: no
            # cross-component binding, no causal chain, CPU IRQ constant zero.
            assert manifest['bindings'] == [], cell_id
            assert all(owner['kind'] != 'bound'
                       for owner in manifest['ownership']['owners']), cell_id
            assert all('OpenTitanGpioSession' not in window['target_type']
                       for window in manifest['windows']['cpu']), cell_id


def test_the_run_really_is_on_the_current_source_and_input_identity():
    """The checklist refuses evidence produced on a drifted source identity.

    Recomputed here from the same eleven campaign sources, the host source set
    and the two frozen manifests the campaign hashed, so a later edit to the
    campaign transport (or to an input) turns this red instead of leaving a
    stale bundle standing in as row 2's evidence.  Point
    ``MYFUZZ_CVA6_CAMPAIGN_RUN`` at a fresh campaign to clear it.
    """
    from myfuzz.integration.scenario_campaign import _campaign_source_identity

    document = report()
    config = CampaignConfig(
        Path(document['campaign_inputs']['bound']['original_manifest']),
        Path(document['campaign_inputs']['independent']['original_manifest']))
    now = _campaign_source_identity(config)
    assert document['campaign_source_identity_end'] == now
    for name, digest in now.items():
        assert document['campaign_source_identity'].get(name) == digest, name


def test_execution_identity_envelopes_bind_every_cell_to_its_frozen_inputs():
    """The provider sets ``requires_execution_identity``; a cell without a
    validated envelope is not a run this audit may trust."""
    document = report()
    for cell in document['cells']:
        cell_id = cell['cell_id']
        envelope_path = cell_dir(cell_id) / 'live' / 'run_identity.json'
        assert envelope_path.is_file(), cell_id
        envelope = json.loads(envelope_path.read_text(encoding='utf-8'))
        assert envelope['schema_version'] == \
            'scenario_fresh_run_identity_envelope.v1', cell_id
        body = envelope['identity']
        assert body['schema_version'] == 'scenario_fresh_run_identity.v1'
        assert body['run_config']['run_id'] == cell_id
        recomputed = hashlib.sha256(json.dumps(
            body, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
            allow_nan=False).encode()).hexdigest()
        assert recomputed == envelope['sha256'], cell_id
        assert live_report(cell_id)['run_identity_sha256'] == envelope['sha256'], cell_id
        assert live_report(cell_id)['execution_status'] == 'complete', cell_id
        # The envelope names exactly the artifacts that are on disk today.
        live = cell_dir(cell_id) / 'live'
        present = {path.relative_to(live).as_posix() for path in live.rglob('*')
                   if path.is_file() and path.name != 'run_identity.json'}
        for name, digest in body['artifacts'].items():
            assert (live / name).is_file(), (cell_id, name)
            assert hashlib.sha256((live / name).read_bytes()).hexdigest() == digest, \
                (cell_id, name)
        assert set(body['artifacts']).issubset(present)


def test_the_saved_gate_would_still_reject_these_cells_if_they_lost_evidence():
    """The saved statuses are production gate verdicts, not decoration.

    This re-runs the real gate function on each cell's *saved* evidence: a
    complete cell must come back clean, and every bound cell must lose its
    completeness the moment the multi-case / feedback / chain evidence is
    removed.  Without this, "status: complete" could be a hand-written field.
    """
    from dataclasses import replace

    document = report()
    for cell in document['cells']:
        search = SearchEvidence(**cell['search'])
        replay = ReplayEvidence(**cell['replay'])
        cell_key = type('Cell', (), {
            'strategy': cell['strategy'], 'direction': cell['direction'],
            'requested_seconds': cell['requested_seconds']})()
        wall = cell['cost']['search_wall_seconds']
        assert _gate_failures(cell_key, search, replay, wall) == [], cell['cell_id']
        if cell['strategy'] in BOUND_STRATEGIES:
            for broken in (
                    replace(search, testcases=9),
                    replace(search, post_seed_mutation_batches=1),
                    replace(search, post_seed_effective_genotypes=1),
                    replace(search, post_seed_completed_chains=0),
                    replace(search, completed_chains=0),
                    replace(search, effective_search_seconds=59.0)):
                assert _gate_failures(cell_key, broken, replay, wall), \
                    (cell['cell_id'], broken)
