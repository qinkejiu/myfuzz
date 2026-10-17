"""Independent audit of a saved PicoRV32 native x PULP APB3 GPIO campaign.

P6 row 5 (``docs/superpowers/plans/2026-10-13-p6-per-protocol-row-checklist.md``)
recorded the native CPU's local RAM/ROM acceptance and a directed CPU<->GPIO
chain, and listed what was still missing: a continuous multi-case session with
both sides' sources, interaction feedback, assertions, prefix replay and the
queued ``defer_mmio`` form.
``myfuzz.integration.scenario_campaign.run_scenario_campaign`` supplies the
first four and
``myfuzz.integration.picorv32_native_scenario_campaign.PicoNativeGpioBoundProvider``
is the row-5 provider.

Three honesty constraints shape this file.

**It audits saved bytes; it does not re-run the campaign.**  Every count in
``campaign_report.json`` is treated as a claim to be cross-checked against the
receipts, chain checks, mutation selections and corpus entries on disk,
recomputed with the same rules the gate uses.  A mismatch fails the audit
instead of being averaged away.

**It audits the row's own identity from the artifacts.**  Each cell's saved
runner manifest must name the pinned PicoRV32 native CPU source closure and the
pinned PULP APB3 ``apb_gpio`` device, and the chain checks must carry the queued
delivery evidence (a delivery executed on the device's own step, not on the
accepting CPU step).  No other protocol's fixture produces these bytes, so these
cells are row 5's evidence and may not be offered for another row.

**It fails if the tree moved.**  The saved campaign records the framework
source identity; this audit recomputes it *and* recomputes the identity of the
provider, the fixture, the four frozen inputs and the Rust client against the
values saved beside the run, so an edit to any of them turns this red instead of
leaving a stale bundle standing in as row 5's evidence.

The audited directory defaults to the run recorded in its
``CAMPAIGN_EVIDENCE.md``.  Set ``MYFUZZ_PICO_NATIVE_CAMPAIGN_RUN`` to audit
another saved campaign with the *same* independent recomputation -- there is
deliberately only one auditor, so a second campaign cannot be checked by a
weaker set of assertions than the first.
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
    CampaignConfig,
    ReplayEvidence,
    SearchEvidence,
    _campaign_source_identity,
    _gate_failures,
    _validated_replay,
    campaign_matrix,
)

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RUN = (ROOT / 'runs' / 'scenario' /
               'campaign-pico-native-g4-18cell-p6-row5-20261017-v1')
RUN = Path(os.environ.get('MYFUZZ_PICO_NATIVE_CAMPAIGN_RUN') or DEFAULT_RUN)
if not RUN.is_absolute():
    RUN = ROOT / RUN
IDENTITY_FILE = RUN / 'pico_native_campaign_source_identity.json'

#: The two sides row 5 asks to be driven: both are declared in *both*
#: directions by this fixture, unlike a per-direction source split.
CPU_SIDE_SOURCES = {'cpu.padout_byte'}
IP_SIDE_SOURCES = {'gpio0.pin_byte'}
BOTH_SIDE_SOURCES = CPU_SIDE_SOURCES | IP_SIDE_SOURCES
BOUND_STRATEGIES = {'dependency_guided', 'uniform_source'}
REAL_RTL_COMPONENTS = {'cpu', 'gpio0'}
CPU_SESSION_TYPE = ('myfuzz.scenario.picorv32_native_cpu_example.'
                    'DeferredNativeMemorySession')
GPIO_SESSION_TYPE = ('myfuzz.local_harness.gpio_session.'
                     'GeneratedPulpGpioSession')
CPU_REVISION = 'git:ef203c2b0a3fb793280f5114941416c425c5b461'
IP_REVISION = 'git:f82caeb7f7d89427f05e9af5ed31e0675efe0d83'
GPIO_BASE = 0x40000000
GPIO_WINDOW = 0x1000
PADIN = 0x08
PADOUT = 0x0C
RESULT_ADDRESS = 0x100
RESULT2_ADDRESS = 0x104

pytestmark = pytest.mark.skipif(
    not RUN.is_dir(),
    reason='the saved PicoRV32 native campaign bundle is not present in this checkout')


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


def runner_manifest(cell_id):
    return json.loads((cell_dir(cell_id) / 'live' / 'runner_manifest.json')
                      .read_text(encoding='utf-8'))


def corpus_entries(cell_id):
    return sorted((cell_dir(cell_id) / 'live' / 'corpus').glob('entry_*.json'))


def bound_cells(document):
    return [cell for cell in document['cells']
            if cell['strategy'] in BOUND_STRATEGIES]


def test_the_report_is_a_real_eighteen_cell_matrix_with_recomputed_verdicts():
    document = report()
    assert document['schema_version'] == 'scenario_campaign.v1'
    assert document['gate'] == 'G4'
    assert document['required_cells'] == 18
    cells = document['cells']
    assert len(cells) == 18, 'G4 is an 18-cell matrix, not a subset'
    matrix = campaign_matrix(CampaignConfig(
        RUN / 'inputs/bound/pico_native_gpio_campaign_seed.json',
        RUN / 'inputs/independent/pico_native_gpio_campaign_baseline.json'))
    assert [cell.cell_id for cell in matrix] == [cell['cell_id'] for cell in cells]
    for cell in cells:
        cell_key = type('Cell', (), {
            'strategy': cell['strategy'], 'direction': cell['direction'],
            'requested_seconds': cell['requested_seconds']})()
        recomputed = _gate_failures(
            cell_key, SearchEvidence(**cell['search']) if cell['search'] else None,
            ReplayEvidence(**cell['replay']) if cell['replay'] else None,
            cell['cost']['search_wall_seconds'])
        assert cell['gate_failures'] == recomputed, cell['cell_id']
        if cell['error'] is not None:
            assert cell['status'] == 'error', cell['cell_id']
        else:
            assert cell['status'] == ('complete' if not recomputed else 'incomplete'), \
                (cell['cell_id'], cell['status'], recomputed)
    assert document['gate_status'] == (
        'complete' if all(cell['status'] == 'complete' for cell in cells)
        else 'incomplete')
    if document['gate_status'] == 'complete':
        assert all(cell['gate_failures'] == [] for cell in cells)
        assert all(cell['error'] is None for cell in cells)
    assert document['campaign_source_identity_stable'] is True
    assert document['campaign_source_identity'] == document['campaign_source_identity_end']
    assert document['campaign_input_stability']['originals_stable'] is True
    assert document['campaign_input_stability']['snapshots_stable'] is True
    assert document['campaign_inputs']['bound']['closure_status'] == 'provider_declared'
    assert document['campaign_inputs']['independent']['closure_status'] == 'provider_declared'
    for role, expected in (('bound', {'pico_native_gpio_campaign_seed.json',
                                      'pico_native_gpio_reverse_seed.json'}),
                           ('independent', {'pico_native_gpio_campaign_baseline.json',
                                           'pico_native_gpio_campaign_seed.json',
                                           'pico_native_gpio_independent_ip_seed.json'})):
        saved = {row['relative_path']
                 for row in document['campaign_inputs'][role]['files']}
        assert saved == expected, (role, sorted(saved))


def test_every_cell_saved_real_rtl_receipts_that_recompute_its_counts():
    document = report()
    for cell in document['cells']:
        cell_id = cell['cell_id']
        saved = receipts(cell_id)
        assert saved, f'{cell_id}: no saved receipts'
        search = cell['search']
        assert search is not None, cell_id

        # Multi-case continuous session: many cases, all of them executed
        # through both real RTL instances.
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
        assert not statuses.get('environment_error') and not statuses.get('uncertain_effect')
        assert search['status'] == 'ok'
        assert search['seed_status'] == 'supported'
        assert search['effective_search_seconds'] >= max(MINIMUM_G4_SECONDS,
                                                         cell['requested_seconds'])
        assert search['effective_search_seconds'] <= cell['cost']['search_wall_seconds'] + 0.05
        # The fixture's own pinned step budget is what the cell actually ran.
        assert all(receipt['local_ticks']['cpu'] <= 700 for receipt in saved), cell_id


def test_both_sides_are_declared_and_really_driven_in_every_bound_cell():
    """Row 5: CPU side *and* IP side sources, both really selected and consumed."""
    document = report()
    recomputed = {}
    selection_uses = {}
    for cell in bound_cells(document):
        cell_id = cell['cell_id']
        uses = collections.Counter()
        for receipt in receipts(cell_id):
            for source in receipt['applied_sources']:
                uses[source] += 1
        selection_uses.setdefault(
            f"{cell['strategy']}__{cell['direction']}", []).append(uses)
        consumed = collections.Counter()
        for receipt in receipts(cell_id):
            for source in receipt['applied_source_ids']:
                consumed[source] += 1
        reported = cell['search']['applied_source_uses']
        assert set(reported) == BOTH_SIDE_SOURCES, cell_id
        for source in BOTH_SIDE_SOURCES:
            assert reported[source] == consumed.get(source, 0), (cell_id, source)
        recomputed.setdefault(f"{cell['strategy']}__{cell['direction']}",
                              []).append(consumed)

    for group, per_seed in selection_uses.items():
        declared = set().union(*(set(uses) for uses in per_seed))
        assert declared == BOTH_SIDE_SOURCES, group
        executed = {source for source in declared
                    if any(uses.get(source, 0) > 0 for uses in per_seed)}
        assert executed == declared, (group, {source: [uses.get(source, 0)
                                                       for uses in per_seed]
                                             for source in sorted(declared)})

    groups = sorted(recomputed)
    assert groups == [f'{strategy}__{direction}'
                      for strategy in ('dependency_guided', 'uniform_source')
                      for direction in ('CPU_TO_IP_TO_CPU', 'IP_TO_CPU_TO_IP')]
    for group, per_seed in recomputed.items():
        declared = set().union(*(set(uses) for uses in per_seed))
        assert declared == BOTH_SIDE_SOURCES, group
        executed = {source for source in declared
                    if any(uses.get(source, 0) > 0 for uses in per_seed)}
        coverage = document['actual_source_coverage'][group]
        assert coverage['measured'] is True
        assert coverage['declared'] == sorted(declared)
        assert coverage['executed'] == sorted(executed), (group, coverage)


def test_feedback_really_changed_the_search_after_the_seed():
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


def test_post_seed_diversity_and_queued_two_round_chains_recompute():
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

        # A credited assessment is two ordered real RTL rounds whose committed
        # values are the joint functions of the two observed source bytes, and
        # every device beat was queued and executed on the device's own step.
        for check in checks:
            assessment = check['assessment']
            if not assessment or not assessment.get('complete'):
                continue
            assert assessment['rounds'] == 2, cell_id
            assert assessment['findings'] == [], cell_id
            padout = assessment['padout_byte']
            pin = assessment['pin_byte']
            assert assessment['joint_value'] == padout ^ pin, cell_id
            assert assessment['second_commit'] == (padout ^ pin) + pin, cell_id
            assert assessment['queued_device_deliveries'] >= 6, cell_id


def test_replay_covers_the_whole_saved_corpus_including_failures():
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
        saved_failures = sorted(failure_dir.glob('*.json')) \
            if failure_dir.is_dir() else []
        assert replay['failure_entries'] == len(saved_failures), cell_id
        _validated_replay(ReplayEvidence(**replay))


def test_every_cell_is_this_rows_cpu_and_ip_and_not_another_rows():
    document = report()
    for cell in document['cells']:
        cell_id = cell['cell_id']
        manifest = runner_manifest(cell_id)
        sessions = manifest['sessions']
        assert set(sessions) == REAL_RTL_COMPONENTS, cell_id

        cpu = sessions['cpu']
        assert cpu['type'] == CPU_SESSION_TYPE, cell_id
        cpu_artifact = cpu['identity']['runtime_artifact']
        assert cpu_artifact['kind'] == 'native_memory_cpu', cell_id
        assert cpu_artifact['plan']['source_revision'] == CPU_REVISION, cell_id
        assert cpu_artifact['plan']['source_files'] == ['picorv32.v'], cell_id
        assert cpu_artifact['plan']['top'] == 'picorv32', cell_id
        cpu_inputs = [row['path'] for row in
                      cpu['identity']['build_identity']['inputs']]
        assert 'third_party/picorv32_upstream_reference/picorv32.v' in cpu_inputs, cell_id
        verilator = cpu['identity']['build_identity']['toolchain']['verilator']
        assert verilator['version'].startswith('Verilator'), cell_id
        assert verilator['path'] and verilator['backend_sha256'], cell_id

        ip = sessions['gpio0']
        assert ip['type'] == GPIO_SESSION_TYPE, cell_id
        ip_artifact = ip['identity']['runtime_artifact']
        assert ip_artifact['kind'] == 'apb_gpio', cell_id
        assert ip_artifact['plan']['source_revision'] == IP_REVISION, cell_id
        assert ip_artifact['plan']['top'] == 'apb_gpio', cell_id
        assert ip_artifact['plan']['source_files'] == ['rtl/apb_gpio.sv'], cell_id
        assert ip['identity']['build_identity']['toolchain']['verilator'][
            'version'].startswith('Verilator'), cell_id

        # The CPU's only declared device window is the pinned PULP GPIO.
        windows = manifest['windows']['cpu']
        if cell['strategy'] in BOUND_STRATEGIES:
            assert [(window['device_id'], window['base'], window['size'])
                    for window in windows] == [('gpio0', GPIO_BASE, GPIO_WINDOW)], cell_id
            assert windows[0]['target_component'] == 'gpio0', cell_id
            assert windows[0]['target_type'] == GPIO_SESSION_TYPE, cell_id
        else:
            # The independent arm answers the CPU from a declared local shadow
            # and must not reach the real IP RTL at all.
            assert [(window['device_id'], window['base'])
                    for window in windows] == [('gpio0_local', GPIO_BASE)], cell_id
            assert windows[0]['target_component'] == '', cell_id
            assert 'GeneratedPulpGpioSession' not in windows[0]['target_type'], cell_id
        assert manifest['bindings'] == [], cell_id
        owners = manifest['ownership']['owners']
        assert [(owner['component_id'], owner['port'], owner['bit_offset'],
                 owner['width'], owner['kind'], owner['producer_ref'])
                for owner in owners] == [
            ('gpio0', 'gpio_in', 0, 8, 'source', 'external_gpio_pins'),
            ('gpio0', 'gpio_in', 8, 24, 'fixed', 'constant_zero')], cell_id
        assert [row['component_id'] for row in manifest['ownership']['fields']] == \
            ['gpio0']


def test_the_run_really_is_on_the_current_source_and_input_identity():
    """The checklist refuses evidence produced on a drifted source identity."""
    document = report()
    config = CampaignConfig(
        Path(document['campaign_inputs']['bound']['original_manifest']),
        Path(document['campaign_inputs']['independent']['original_manifest']))
    now = _campaign_source_identity(config)
    assert document['campaign_source_identity_end'] == now
    for name, digest in now.items():
        assert document['campaign_source_identity'].get(name) == digest, name

    # The provider, the fixture, the frozen inputs and the Rust client are not
    # part of the framework's list, so their recorded bytes are re-checked here.
    assert IDENTITY_FILE.is_file(), 'the run must record the provider identity'
    recorded = json.loads(IDENTITY_FILE.read_text(encoding='utf-8'))
    assert recorded['schema_version'] == 'pico_native_campaign_source_identity.v1'
    assert recorded['campaign_run_identity_sha256'] == \
        document['campaign_run_identity_sha256']
    for relative, expected in sorted(recorded['sources'].items()):
        path = ROOT / relative
        assert path.is_file(), relative
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, relative

    # Every pinned build input of both harnesses - the RTL, the profiles, the
    # closures and the local wrappers - must still be the byte the run built.
    # Paths under ``generated/`` are materialized into the build directory and
    # are not repository files; each harness generates its own.
    pinned = {(row['path'], row['sha256'])
              for cell in document['cells']
              for record in runner_manifest(cell['cell_id'])['sessions'].values()
              for row in record['identity']['build_identity']['inputs']}
    assert len(pinned) >= 250, len(pinned)
    for relative, digest in sorted(pinned):
        if relative.startswith('generated/'):
            continue
        path = ROOT / relative
        assert path.is_file(), relative
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, relative


def test_execution_identity_envelopes_bind_every_cell_to_its_frozen_inputs():
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
        live = cell_dir(cell_id) / 'live'
        for name, digest in body['artifacts'].items():
            assert (live / name).is_file(), (cell_id, name)
