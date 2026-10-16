"""Independent audit of a saved PicoRV32 AXI4-Lite x ZipCPU AXI4-Lite campaign.

P6 row 3 (``docs/superpowers/plans/2026-10-13-p6-per-protocol-row-checklist.md``)
records two gaps for the AXI4-Lite row.  The first - a real AXI4-Lite CPU
adapter driving a real AXI4-Lite IP target - is closed by
``tests/integration/test_axil_cpu_generic_ip_chain_real.py``; the second is a
**continuous multi-case session** with feedback-driven mutation and full-prefix
replay.  ``myfuzz.integration.scenario_campaign.run_scenario_campaign`` is the
framework that supplies it and
``myfuzz.integration.axil_scenario_campaign.AxilUartCpuBoundProvider`` is its
AXI4-Lite provider.

Three honesty constraints shape this file.

**It audits saved bytes; it does not re-run the campaign.**  Every count in
``campaign_report.json`` is treated as a claim to be cross-checked against the
receipts, chain checks, mutation selections and corpus entries on disk,
recomputed with the same rules the gate uses.  A mismatch fails the audit
instead of being averaged away.

**It audits the row's own identity from the artifacts.**  Each cell's saved
runner manifest must name the pinned PicoRV32 AXI4-Lite CPU source closure and
the pinned ZipCPU ``axiluart`` AXI4-Lite slave, with the declared 8N1 peer's
frame source.  No other protocol's manifest can produce these bytes, so these
cells are row 3's evidence and may not be offered for another row.

**It fails if the tree moved.**  The saved campaign records the framework
source identity; this audit recomputes it *and* recomputes the identity of the
provider, the fixture, the four frozen inputs and the Rust client against the
values saved beside the run, so an edit to any of them turns this red instead
of leaving a stale bundle standing in as row 3's evidence.

The audited directory defaults to the run recorded in its
``CAMPAIGN_EVIDENCE.md``.  Set ``MYFUZZ_AXIL_CAMPAIGN_RUN`` to audit another
saved campaign with the *same* independent recomputation - there is
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
    _validated_search,
    campaign_matrix,
)

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RUN = (ROOT / 'runs' / 'scenario' /
               'campaign-axil-g4-18cell-p6-row3-20261015-v6')
RUN = Path(os.environ.get('MYFUZZ_AXIL_CAMPAIGN_RUN') or DEFAULT_RUN)
if not RUN.is_absolute():
    RUN = ROOT / RUN
#: Paths whose bytes must still be the bytes that produced this bundle.  The
#: framework files are also covered by the campaign's own source identity; the
#: provider, the fixture, the frozen inputs and the client are recorded beside
#: the run because the campaign framework does not know about them.
IDENTITY_FILE = RUN / 'axil_campaign_source_identity.json'

#: The two sides row 3 asks to be driven: both are declared in *both*
#: directions by this fixture, unlike a per-direction source split.
CPU_SIDE_SOURCES = {'cpu.tx_byte'}
IP_SIDE_SOURCES = {'uart0.rx_frame'}
BOTH_SIDE_SOURCES = CPU_SIDE_SOURCES | IP_SIDE_SOURCES
BOUND_STRATEGIES = {'dependency_guided', 'uniform_source'}
REAL_RTL_COMPONENTS = {'cpu', 'uart0'}
CPU_SESSION_TYPE = ('myfuzz.local_harness.axi_lite_session.'
                    'GeneratedAxiLiteMemorySession')
IP_SESSION_TYPE = ('myfuzz.scenario.axil_uart_cpu_example.AxilUartPeerSession')
CPU_REVISION = 'git:ef203c2b0a3fb793280f5114941416c425c5b461'
IP_REVISION = 'git:f43a6b83c3a70fb2ac0696a45c5545b233fb860b'

pytestmark = pytest.mark.skipif(
    not RUN.is_dir(),
    reason='the saved AXI4-Lite campaign bundle is not present in this checkout')


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
    """The saved status of every cell is the gate's verdict, not decoration.

    A campaign that is honestly ``incomplete`` is as auditable as a complete
    one: what may never happen is a cell whose saved status disagrees with the
    verdict the production gate returns for its own saved evidence.
    """
    document = report()
    assert document['schema_version'] == 'scenario_campaign.v1'
    assert document['gate'] == 'G4'
    assert document['required_cells'] == 18
    cells = document['cells']
    assert len(cells) == 18, 'G4 is an 18-cell matrix, not a subset'
    matrix = campaign_matrix(CampaignConfig(
        RUN / 'inputs/bound/axil_picorv32_uart_campaign_seed.json',
        RUN / 'inputs/independent/axil_picorv32_uart_campaign_baseline.json'))
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
    # The provider declares the reverse-direction and independent seed files too.
    for role, expected in (('bound', {'axil_picorv32_uart_campaign_seed.json',
                                      'axil_picorv32_uart_reverse_seed.json'}),
                           ('independent', {'axil_picorv32_uart_campaign_baseline.json',
                                           'axil_picorv32_uart_campaign_seed.json',
                                           'axil_picorv32_uart_independent_ip_seed.json'})):
        saved = {row['relative_path'] for row in document['campaign_inputs'][role]['files']}
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
        # The fixture's own program budget is what the cell actually ran.
        assert all(receipt['local_ticks']['cpu'] <= 900 for receipt in saved), cell_id


def test_both_sides_are_declared_and_really_driven_in_every_bound_cell():
    """Row 3 item 4: 逐例双侧源 - CPU side *and* IP side, both really selected.

    Two different accountings are recomputed here, because this row exposes a
    difference between them:

    * ``receipts[].applied_sources`` is what the decoder really selected from
      each raw RFuzz record, so it is what proves both sides were driven;
    * ``search.applied_source_uses`` is the executor's *trace-proven
      consumption* count (``_hint_source_uses``), which the gate's per-direction
      source coverage uses.  ``myfuzz.integration.scenario_rfuzz.
      _consumed_source_ids`` credits a ``memory_image`` source only through a
      ``memory_read`` whose channel is ``instr`` or ``unified``, and the
      generated AXI4-Lite CPU session labels its one unified port ``memory``
      (``src/myfuzz/local_harness/native_session.py``), so the CPU-side source
      is selected and effective but never *consumed* in that accounting.  That
      is a framework/session labelling mismatch, reported as such; the audit
      recomputes the gate's own numbers instead of quietly accepting them.
    """
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
        # The report's consumption counts are the executor's own accounting of
        # trace-proven consumption; recompute them from the receipts.
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

    # Every declared source was really selected from the raw records somewhere
    # in each three-seed group, and no seed was carried by a source the decoder
    # never chose.
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
        # The report's executed set must be exactly the gate's own computation
        # over the saved consumption counts, whatever those turn out to be.
        assert coverage['executed'] == sorted(executed), (group, coverage)


def test_feedback_really_changed_the_search_after_the_seed():
    """Row 3 item 5: 交互反馈 - search decisions follow observed RTL results."""
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


def test_post_seed_diversity_and_completed_chains_recompute_from_artifacts():
    """Row 3 item 6: 断言 - an independently assessed closed chain, post-seed."""
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

        # A credited assessment is one ordered real RTL round whose committed
        # value is the joint function of the two observed source bytes, not a
        # hand-written flag.
        for check in checks:
            assessment = check['assessment']
            if not assessment or not assessment.get('complete'):
                continue
            assert assessment['rounds'] == 1, cell_id
            assert assessment['findings'] == [], cell_id
            assert type(assessment['cpu_tx_byte']) is int
            assert type(assessment['rx_frame_byte']) is int
            assert assessment['committed_value'] == (
                assessment['cpu_tx_byte'] ^ assessment['rx_frame_byte']), cell_id


def test_replay_covers_the_whole_saved_corpus_including_failures():
    """Row 3 item 7: 完整前缀 fresh replay."""
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
    """Artifact-derived row identity: the campaign cannot be relabelled."""
    document = report()
    for cell in document['cells']:
        cell_id = cell['cell_id']
        manifest = runner_manifest(cell_id)
        sessions = manifest['sessions']
        assert set(sessions) == REAL_RTL_COMPONENTS, cell_id

        cpu = sessions['cpu']
        assert cpu['type'] == CPU_SESSION_TYPE, cell_id
        cpu_artifact = cpu['identity']['runtime_artifact']
        assert cpu_artifact['kind'] == 'axi4_lite_cpu', cell_id
        assert cpu_artifact['plan']['source_revision'] == CPU_REVISION, cell_id
        assert cpu_artifact['plan']['source_files'] == ['picorv32.v'], cell_id
        assert cpu_artifact['plan']['top'] == 'picorv32_axi', cell_id
        cpu_inputs = [row['path'] for row in
                      cpu['identity']['build_identity']['inputs']]
        assert 'third_party/picorv32_upstream_reference/picorv32.v' in cpu_inputs, cell_id
        # The protocol identity of the CPU side is its adapter, not the shape of
        # a host-closure file list: the generated harness imports every protocol
        # template it can render, so a 'wishbone' filename proves nothing.
        assert [row['path'] for row in cpu_artifact['adapter_sources']] == \
            ['src/myfuzz/protocols/rtl/axi4_lite_processor_memory_adapter.sv'], cell_id
        assert cpu_artifact['adapted_endpoint_ids'] == ['processor.memory'], cell_id
        verilator = cpu['identity']['build_identity']['toolchain']['verilator']
        assert verilator['version'].startswith('Verilator'), cell_id
        assert verilator['path'] and verilator['backend_sha256'], cell_id

        ip = sessions['uart0']
        assert ip['type'] == IP_SESSION_TYPE, cell_id
        ip_artifact = ip['identity']['runtime_artifact']
        assert ip_artifact['kind'] == 'axi4lite_register_observe', cell_id
        assert ip_artifact['functional_scope'] == 'axi4lite_register_uart_8n1_peer', cell_id
        assert ip_artifact['plan']['source_revision'] == IP_REVISION, cell_id
        assert ip_artifact['plan']['top'] == 'axiluart', cell_id
        assert set(ip_artifact['plan']['source_files']) == {
            'rtl/axiluart.v', 'rtl/ufifo.v', 'rtl/rxuart.v', 'rtl/txuart.v',
            'rtl/skidbuffer.v'}, cell_id
        peer = ip_artifact['serial_peer']
        assert peer['format'] == '8N1' and peer['source_id'] == 'serial_rx_frame', cell_id
        assert peer['rx_port'] == 'uart.pins.rx', cell_id
        assert peer['clocks_per_bit'] == 16 and peer['idle_bits'] == 20, cell_id
        ip_inputs = [row['path'] for row in
                     ip['identity']['build_identity']['inputs']]
        assert 'third_party/soc-zipcpu-wbuart/rtl/axiluart.v' in ip_inputs, cell_id
        assert ip['identity']['build_identity']['toolchain']['verilator'][
            'version'].startswith('Verilator'), cell_id

        # The CPU's only declared device window is the pinned AXI4-Lite UART.
        windows = manifest['windows']['cpu']
        if cell['strategy'] in BOUND_STRATEGIES:
            assert [(window['device_id'], window['base'], window['size'])
                    for window in windows] == [('uart0', 0x40000, 0x1000)], cell_id
            assert windows[0]['target_component'] == 'uart0', cell_id
            assert windows[0]['target_type'] == IP_SESSION_TYPE, cell_id
        else:
            # The independent arm answers the CPU from a declared local shadow
            # and must not reach the real IP RTL at all.
            assert [(window['device_id'], window['base'])
                    for window in windows] == [('uart0_local', 0x40000)], cell_id
            assert windows[0]['target_component'] == '', cell_id
            assert 'AxilUartPeerSession' not in windows[0]['target_type'], cell_id
        assert manifest['bindings'] == [], cell_id
        owners = manifest['ownership']['owners']
        assert [(owner['component_id'], owner['port'], owner['bit_offset'],
                 owner['width'], owner['kind'], owner['producer_ref'])
                for owner in owners] == [('uart0', 'uart_rx_byte', 0, 8,
                                          'source', 'serial_rx_frame')], cell_id
        assert [row['component_id'] for row in manifest['ownership']['fields']] == ['uart0']


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
    assert recorded['schema_version'] == 'axil_campaign_source_identity.v1'
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
            assert hashlib.sha256((live / name).read_bytes()).hexdigest() == digest, \
                (cell_id, name)


def test_the_saved_gate_would_still_reject_these_cells_if_they_lost_evidence():
    """The saved statuses are production gate verdicts, not decoration.

    Each saved cell's failure set is recomputed first (so an honestly
    ``incomplete`` cell is audited as strictly as a complete one), and then
    every bound cell must lose *more* than it already lost the moment its
    multi-case, feedback, chain or replay evidence is removed.
    """
    from dataclasses import replace

    document = report()
    for cell in document['cells']:
        if cell['search'] is None or cell['replay'] is None:
            # A cell that never produced evidence has nothing to lose; its
            # saved status is recomputed in the matrix test above.
            continue
        search = SearchEvidence(**cell['search'])
        replay = ReplayEvidence(**cell['replay'])
        cell_key = type('Cell', (), {
            'strategy': cell['strategy'], 'direction': cell['direction'],
            'requested_seconds': cell['requested_seconds']})()
        wall = cell['cost']['search_wall_seconds']
        saved = set(_gate_failures(cell_key, search, replay, wall))
        assert saved == set(cell['gate_failures']), cell['cell_id']
        if cell['strategy'] in BOUND_STRATEGIES:
            for broken in (
                    replace(search, testcases=9),
                    replace(search, post_seed_mutation_batches=1),
                    replace(search, post_seed_effective_genotypes=1),
                    replace(search, post_seed_completed_chains=0),
                    replace(search, completed_chains=0),
                    replace(search, effective_search_seconds=59.0),
                    replace(search, seed_status='unverified')):
                assert set(_gate_failures(cell_key, broken, replay, wall)) > saved, \
                    (cell['cell_id'], broken)
            # A corpus replay that no longer covers the corpus must lose more
            # than the cell already lost.
            assert set(_gate_failures(cell_key, search,
                                      replace(replay, matched_entries=0),
                                      wall)) > saved, cell['cell_id']
        else:
            # The independent arm cannot claim a bound causal chain at all:
            # the provider's evidence is refused, not merely gated.
            with pytest.raises(ValueError):
                _validated_search(cell_key, replace(search, completed_chains=1))
            assert search.completed_chains == 0, cell['cell_id']
