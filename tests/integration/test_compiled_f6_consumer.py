"""Marked synthetic native receipts; these tests grant no native acceptance."""
from copy import deepcopy
from copy import copy
from dataclasses import replace
from hashlib import sha256
import importlib
import importlib.util
import json
from types import SimpleNamespace

import pytest

from tests.integration.f6_compiled_support import consumer_case, inputs, make_case


def make_live_f6_fetch_attempt(tmp_path, monkeypatch, *, fetch_offsets=range(0, 128, 4)):
    """Create original Task9 OBI receipts inside the actual compiled F6 owner."""
    from tests.integration.test_compiled_f6_contract import source_inputs
    from tests.scenario.test_f6_instruction_fetch_receipt import make_live
    from myfuzz.scenario.batch import BatchAdvance
    from myfuzz.scenario.session_runtime import BoundOnlineInstruction, OnlineCase

    runtime = make_live(source_inputs(), tmp_path, monkeypatch)
    raw8 = sum(value << (11 * index)
        for index, value in enumerate((11, 12, 13, 14))).to_bytes(8, 'little')
    candidate = runtime.preflight(raw8)
    program = runtime.contract['program_contract']
    slot = program['slot_base']
    source_id = runtime.contract['instruction_source_id']
    case_id = runtime.run_id + ':case:0'
    source_action = source_id + ':0'
    prefix = runtime.program.prefix(candidate, case_index=0)
    online = OnlineCase(case_id, 'CPU_TO_IP',
        runtime.runtime_path_admission['runtime_path_ids'][1],
        BoundOnlineInstruction(source_action, runtime.cpu_id, slot,
            prefix.hex(), source_id),
        (BatchAdvance((runtime.cpu_id,)),))
    attempt_start = runtime.runner.event_count

    # Keep the first request waiting on its originally empty slot, as in the
    # real F6 admission path. The source admission resumes that same key.
    from tests.scenario.test_f6_instruction_fetch_receipt import request, step
    request(runtime, 0)
    runtime.session.submit_case(online)
    step(runtime, i_rsp_ready=1)
    step(runtime)
    skipped_waiting_request = False
    for offset in fetch_offsets:
        if offset == 0 and not skipped_waiting_request:
            # The first zero offset is the pre-admission waiting request above.
            skipped_waiting_request = True
            continue
        request(runtime, offset)
        step(runtime, i_rsp_ready=1)
        step(runtime)
    runtime._drain_observer_view()

    attempt = dict(case_id=case_id, case_index=0, raw8_hex=raw8.hex(),
        prefix_hex=prefix.hex(), _runner_event_start=attempt_start)
    for name in ('operands', 'sources', 'source_commits', 'configuration',
            'deliveries', 'reads', 'read_snapshots', 'read_responses', 'writes',
            'word_commits', 'write_responses', 'readbacks', 'results'):
        attempt[name] = []
    for name in ('status', 'status_store', 'terminal', 'irq', 'irq_output',
            'irq_delivery', 'return', 'next_fetch'):
        attempt[name] = None
    runtime.attempts.append(attempt)
    return runtime, attempt


def api(name='myfuzz.integration.compiled_f6_consumer'):
    assert importlib.util.find_spec(name) is not None, 'Task5 actual F6 consumer is missing'
    return importlib.import_module(name)


def runner_backed_mmio_delivery(runtime, attempt, index=0):
    from myfuzz.scenario.runner import ScenarioRunner

    row = next(row for row in runtime.observer_view
        if row.get('event_id') == attempt['deliveries'][index])
    row['runner_event_id'] = 1
    row['provenance'] = dict(schema_version='event_source_provenance.v1',
        observed_case=dict(case_id=attempt['case_id'],
            case_index=attempt['case_index']), origin_admission_ids=[],
        origin_status='unknown', unknown_writer_ids=[],
        invalid_origin_references=0, proof_scope='observation_only',
        edge_candidates=[], resource=None)
    source = deepcopy(row)
    source['event_id'] = 1
    source.pop('runner_event_id')
    runtime.runner = object.__new__(ScenarioRunner)
    runtime.runner.sessions = {'cpu': runtime.cpu}
    runtime.runner._events = [source]
    attempt['_runner_event_start'] = 0
    return row


def install_synthetic_dma_checker_report(runtime, attempt, journal, *,
        orphan_master_ack=False):
    """Run the production report assembler over a synthetic Runner journal."""
    from myfuzz.local_harness.renderer import _sha
    from myfuzz.integration.compiled_f6 import (
        _assemble_f6_protocol_checker_case_report)
    from myfuzz.scenario.ip_protocol_checker import WishboneDmaProtocolChecker
    from myfuzz.scenario.runner import ScenarioRunner

    trace_set = runtime.dma.artifact.runtime_document['protocol_checker_trace_set']
    start = attempt['_runner_event_start']
    names = {name for trace in trace_set['traces']
        for name in trace['signals'].values()}
    backend = {name: 0 for name in names}
    for tick in (1, 2):
        event_id = len(journal) + 1
        sample_backend = dict(backend)
        if orphan_master_ack and tick == 1:
            sample_backend.update(mwb_cyc=1, mwb_ack=1)
        journal.append(dict(event_id=event_id, producer_event_id=1,
            kind='local_tick_sample', component=runtime.dma.source_component,
            local_tick=tick, phase='pre', reset_epoch=0,
            observation_schema_version='ip_raw_observation.v1',
            outputs={'backend': sample_backend}))
    artifact = runtime.dma.artifact
    identity = dict(component_id=artifact.plan.profile.component_id,
        instance_id=artifact.plan.request.instance_id,
        artifact_digest=artifact.runtime_document['artifact_digest'],
        profile_fingerprint=artifact.plan.profile.profile_fingerprint,
        source_verification_sha256=_sha(artifact.source_verification),
        runtime_artifact_sha256=_sha(artifact.runtime_document))
    checker = WishboneDmaProtocolChecker(
        component_id=identity['component_id'], instance_id=identity['instance_id'],
        trace_set=trace_set, artifact_identity=identity)
    checker_snapshot = checker.snapshot()
    for row in list(journal[start:]):
        if (row.get('kind') == 'local_tick_sample'
                and row.get('component') == runtime.dma.source_component
                and row.get('phase') == 'pre'):
            findings = checker.consume_local_tick(row,
                reset_epoch=row['reset_epoch'])
            for finding in findings:
                journal.append({**deepcopy(finding),
                    'event_id': len(journal) + 1,
                    'kind': finding['event_type']})
    runner = object.__new__(ScenarioRunner)
    runner.sessions = {'cpu': runtime.cpu, 'dma': runtime.dma}
    runner._events = journal
    runner._ip_protocol_checkers = {
        runtime.dma.source_component: checker}
    runtime.runner = runner
    runtime.protocol_checker_case_report = \
        _assemble_f6_protocol_checker_case_report(runner,
            runtime.dma.source_component, checker_snapshot=checker_snapshot,
            attempt=attempt, run_id=runtime.run_id,
            execution_binding_sha256=runtime.execution_binding_sha256)


def test_four_words_join_actual_source_versions_routes_effects_and_responses(consumer_case):
    runtime, attempt = consumer_case
    material = api().capture_f6_case(runtime, attempt)
    statuses = {key: row['status'] for key, row in material['observations'].items()}
    assert statuses == {
        'protocol_checker.receipt_violations':'passed',
        'cross_component.declared_edge_hops':'missing',
        'dma.cpu_configuration':'passed',
        'dma.word_transfer_join':'passed',
        'dma.irq_isr_completion':'passed'}
    assert api().f6_case_feedback(material, case_ids=(attempt['case_id'],)) == bytes(5)
    joins = material['evidence_inventory'][material['observations']['dma.word_transfer_join']['evidence_refs'][0]]['details']['words']
    assert len(joins) == 4
    assert len({str(w['read_transaction']) for w in joins}) == 4
    assert len({str(w['write_transaction']) for w in joins}) == 4


@pytest.mark.parametrize('schema',['wishbone_dma_selected_edge.v1','wishbone_dma_selected_edge.v2'])
def test_selected_dma_master_select_must_match_real_pre_sample(consumer_case,monkeypatch,schema):
    runtime,attempt=consumer_case
    monkeypatch.setitem(runtime.dma.artifact.runtime_document,'dma_edge_contract',
        {'schema_version':schema})
    observer=next(r for r in runtime.observer_view if r.get('event_id')==attempt['reads'][0])
    observer['payload']['pre_backend']['mwb_sel']=15
    monkeypatch.setattr(api()._Case,'live_dma',lambda self,row:None)
    case=api()._Case(runtime,attempt)
    address=runtime.contract['program_contract']['source_address']
    case.dma_beat('reads',0,write=False,address=address,value=0)
    observer['payload']['pre_backend']['mwb_sel']=3
    with pytest.raises(ValueError,match='SEL'):
        case.dma_beat('reads',0,write=False,address=address,value=0)


def test_runnerless_fixture_cannot_certify_declared_runtime_edges(consumer_case):
    runtime, attempt = consumer_case
    material = api().capture_f6_case(runtime, attempt)
    observation = material['observations']['cross_component.declared_edge_hops']
    details = material['evidence_inventory'][observation['evidence_refs'][0]]['details']
    edges = details['edges']
    assert [(row['rule_index'], row['prerequisite_index']) for row in edges] == [
        (0, 0), (1, 0), (2, 0), (3, 0)]
    assert [row['relation'] for row in edges] == [
        'dma_master_route', 'causal_order', 'dma_master_route', 'persistent_state']
    assert all(row['outcome'] == 'missing' for row in edges)
    assert all(not row['runner_event_ids'] for row in edges)
    source_edge = edges[3]
    assert source_edge['source_node_id'] == runtime.contract['instruction_source_id']
    assert 'Runner raw event archive unavailable' in source_edge['issues'][0]['reason']
    assert observation['status'] == 'missing'
    assert api().f6_case_feedback(material, case_ids=(attempt['case_id'],)) == bytes(5)


def test_instruction_source_summary_cannot_replace_runner_acceptance_witness(consumer_case):
    runtime, attempt = consumer_case
    source = next(row for row in runtime.observer_view
        if row.get('component') == runtime.cpu.source_component
        and row.get('kind') == 'instruction_source')
    source['data_hex'] = '00' * 128
    material = api().capture_f6_case(runtime, attempt)
    observation = material['observations']['cross_component.declared_edge_hops']
    details = material['evidence_inventory'][observation['evidence_refs'][0]]['details']
    edge = details['edges'][3]
    assert edge['outcome'] == 'missing'
    assert observation['status'] in ('missing','failed')
    assert api().f6_case_feedback(material, case_ids=(attempt['case_id'],)) == bytes(5)


def test_runner_delivery_provenance_is_authenticated_before_callback_projection(consumer_case):
    from myfuzz.integration.compiled_f6_consumer import _Case

    runtime, attempt = consumer_case
    row = runner_backed_mmio_delivery(runtime, attempt)
    _Case(runtime, attempt).independent_delivery(row)


def test_control_delivery_accepts_authenticated_runner_provenance(consumer_case):
    from myfuzz.integration.compiled_f6_consumer import _Case, _Missing
    from myfuzz.scenario.ledger import TransactionKey

    runtime, attempt = consumer_case
    row = runner_backed_mmio_delivery(runtime, attempt)
    case = _Case(runtime, attempt)
    case.owner_events = lambda *args, **kwargs: []
    key = TransactionKey(**row['source_transaction'])
    response = next(event for event in runtime.observer_view
        if event.get('kind') == 'data_response'
        and event.get('transaction') == row['source_transaction'])
    with pytest.raises(_Missing, match='native DMA control edge unavailable'):
        case.control_delivery(row, key=key, address=row['address'], write=True,
            value=row['write_value'], response=response)


def test_synthetic_delivery_keeps_provenance_in_strict_callback_comparison(consumer_case):
    from myfuzz.integration.compiled_f6_consumer import _Case, _Contradiction

    runtime, attempt = consumer_case
    row = next(row for row in runtime.observer_view
        if row.get('event_id') == attempt['deliveries'][0])
    row['provenance'] = {'forged': True}
    with pytest.raises(_Contradiction,
            match='present router delivery contradicts original completed callback'):
        _Case(runtime, attempt).independent_delivery(row)


@pytest.mark.parametrize('method', ['independent', 'control'])
@pytest.mark.parametrize('field', ['producer_event_id', 'runner_event_id'])
def test_synthetic_delivery_rejects_unowned_runner_identity_fields(
        consumer_case,method,field):
    from myfuzz.integration.compiled_f6_consumer import _Case, _Contradiction
    from myfuzz.scenario.ledger import TransactionKey

    runtime, attempt = consumer_case
    row = next(row for row in runtime.observer_view
        if row.get('event_id') == attempt['deliveries'][0])
    row[field] = 1
    case = _Case(runtime, attempt)
    with pytest.raises(_Contradiction):
        if method == 'independent':
            case.independent_delivery(row)
        else:
            key = TransactionKey(**row['source_transaction'])
            response = next(event for event in runtime.observer_view
                if event.get('kind') == 'data_response'
                and event.get('transaction') == row['source_transaction'])
            case.control_delivery(row, key=key, address=row['address'],
                write=True, value=row['write_value'], response=response)


def test_task5_joins_complete_cpu_tick_journal_after_session_samples_are_drained(
        consumer_case):
    runtime, attempt = consumer_case
    physical_samples = deepcopy(runtime.cpu._physical_tick_samples)
    assert physical_samples

    # Project existing observations into the Runner journal with explicit
    # contiguous identities, then append the CPU tick samples being tested.
    journal = []
    for runner_event_id, row in enumerate(runtime.observer_view, start=1):
        if row.get('kind') == 'memory_read':
            resource_names = ('memory_id', 'generation', 'byte_offset',
                'address', 'width_bytes', 'byte_enable', 'transaction',
                'version', 'versions', 'writer_event_id',
                'writer_event_ids', 'writer_kinds')
            resource = {name: list(row[name]) if type(row.get(name)) is tuple
                else row[name] for name in resource_names if name in row}
            row['producer_event_id'] = runner_event_id - 1
            row['provenance'] = dict(schema_version='event_source_provenance.v1',
                observed_case=dict(case_id=attempt['case_id'],
                    case_index=attempt['case_index']),
                origin_admission_ids=[], origin_status='unknown',
                unknown_writer_ids=list(dict.fromkeys(row['writer_event_ids'])),
                invalid_origin_references=0,
                proof_scope='memory_writer_snapshot', edge_candidates=[],
                resource=resource)
        elif row.get('component') == 'dma' and row.get('kind') == 'dma_edge':
            row['provenance'] = dict(schema_version='event_source_provenance.v1',
                observed_case=dict(case_id=attempt['case_id'],
                    case_index=attempt['case_index']), origin_admission_ids=[],
                origin_status='unknown', unknown_writer_ids=[],
                invalid_origin_references=0, proof_scope='observation_only',
                edge_candidates=[], resource=None)
        source = deepcopy(row)
        source['event_id'] = runner_event_id
        row['runner_event_id'] = runner_event_id
        journal.append(source)
    attempt['_runner_event_start'] = len(journal)
    for sample in physical_samples:
        producer_event_id = len(journal) + 1
        journal.append(dict(event_id=producer_event_id, component='cpu',
            local_tick=sample['local_tick'], inputs={}, outputs={}))
        for phase in ('pre', 'post'):
            journal.append(dict(event_id=len(journal) + 1,
                producer_event_id=producer_event_id,
                kind='local_tick_sample', component='cpu',
                local_tick=sample['local_tick'], phase=phase,
                outputs=deepcopy(sample[phase])))
    install_synthetic_dma_checker_report(runtime, attempt, journal)
    from myfuzz.scenario.runner import ScenarioRunner
    runtime.runner = object.__new__(ScenarioRunner)
    runtime.runner.sessions = {'cpu': runtime.cpu, 'dma': runtime.dma}
    runtime.runner._events = journal
    runtime.cpu.drain_tick_samples()
    runtime.cpu.drain_tick_samples()  # Runner's following DMA drain is empty.
    assert runtime.cpu._physical_tick_samples == []

    material = api().capture_f6_case(runtime, attempt)
    statuses = {key: row['status']
        for key, row in material['observations'].items()}
    assert statuses['protocol_checker.receipt_violations'] == 'passed'
    assert statuses['cross_component.declared_edge_hops'] == 'failed'
    assert all(statuses[key] == 'passed' for key in (
        'dma.cpu_configuration','dma.word_transfer_join','dma.irq_isr_completion'))
    word_join = material['evidence_inventory'][
        material['observations']['dma.word_transfer_join']['evidence_refs'][0]]['details']
    evidence = word_join['raw_evidence']
    cpu_samples = [row for row in evidence
        if row.get('kind') == 'local_tick_sample'
        and row.get('component') == 'cpu']
    assert cpu_samples
    assert all(reference.get('source') == 'runner'
        for reference in word_join['raw_references']
        if reference.get('kind') == 'local_tick_sample')

    assert attempt['_runner_event_start'] > 0
    runtime.protocol_checker_case_report['runner_event_start'] -= 1
    attempt['case_id'] += ':report-start-shifted'
    runtime.admitted_attempts = (deepcopy(attempt),)
    runtime.protocol_checker_case_report['case_id'] = attempt['case_id']
    altered = api().capture_f6_case(runtime, attempt)
    assert altered['observations'][
        'protocol_checker.receipt_violations']['status'] == 'failed'


def test_runner_backed_f6_without_dual_endpoint_checker_report_is_missing(
        consumer_case):
    from myfuzz.scenario.runner import ScenarioRunner

    runtime, attempt = consumer_case
    runtime.runner = object.__new__(ScenarioRunner)
    runtime.runner.sessions = {'cpu': runtime.cpu, 'dma': runtime.dma}
    runtime.runner._events = []
    attempt['_runner_event_start'] = 0
    runtime.protocol_checker_case_report = None

    material = api().capture_f6_case(runtime, attempt)

    assert material['observations'][
        'protocol_checker.receipt_violations']['status'] == 'missing'


def test_compiled_runtime_cannot_downgrade_missing_checker_to_synthetic_mode(
        consumer_case):
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime

    runtime, attempt = consumer_case
    production_runtime = CompiledF6Runtime.__new__(CompiledF6Runtime)
    production_runtime.__dict__.update(runtime.__dict__)
    production_runtime.attempts = [attempt]
    production_runtime.runner = None
    production_runtime.protocol_checker_case_report = None

    consumer = api()
    assert consumer._requires_runner_backed_protocol_report(production_runtime)
    assert not consumer._requires_runner_backed_protocol_report(runtime)
    material = consumer.capture_f6_case(production_runtime, attempt)
    assert material['observations'][
        'protocol_checker.receipt_violations']['status'] == 'missing'


def test_live_report_assembler_joins_finding_to_runner_violation_and_consumer(
        consumer_case):
    runtime, attempt = consumer_case
    journal = []
    attempt['_runner_event_start'] = 0

    install_synthetic_dma_checker_report(runtime, attempt, journal,
        orphan_master_ack=True)

    report = runtime.protocol_checker_case_report
    assert report['status'] == 'violation'
    assert len(report['findings']) == 1
    assert report['findings'][0]['payload']['violation_code'] == \
        'wishbone_response_without_request'
    assert report['runner_violation_event_ids'] == [3]
    material = api().capture_f6_case(runtime, attempt)
    assert material['observations'][
        'protocol_checker.receipt_violations']['status'] == 'failed'


def test_runner_violation_cannot_be_hidden_by_tampering_live_checker_report(
        consumer_case):
    runtime, attempt = consumer_case
    journal = []
    attempt['_runner_event_start'] = 0

    install_synthetic_dma_checker_report(runtime, attempt, journal,
        orphan_master_ack=True)
    runtime.protocol_checker_case_report.update(
        findings=[], runner_violation_event_ids=[], status='clean')

    material = api().capture_f6_case(runtime, attempt)
    assert material['observations'][
        'protocol_checker.receipt_violations']['status'] == 'failed'


def test_consumer_rejects_live_checker_sample_id_scope_tampering(consumer_case):
    runtime, attempt = consumer_case
    journal = []
    attempt['_runner_event_start'] = 0

    install_synthetic_dma_checker_report(runtime, attempt, journal)
    runtime.protocol_checker_case_report['endpoints'][0][
        'sample_event_ids'].pop()

    material = api().capture_f6_case(runtime, attempt)
    assert material['observations'][
        'protocol_checker.receipt_violations']['status'] == 'failed'


def test_task5_rejects_cpu_samples_from_a_runner_that_does_not_own_the_cpu(
        consumer_case):
    runtime, attempt = consumer_case
    journal = []
    for sample in deepcopy(runtime.cpu._physical_tick_samples):
        producer_event_id = len(journal) + 1
        journal.append(dict(event_id=producer_event_id, kind='step',
            component='cpu'))
        for phase in ('pre', 'post'):
            journal.append(dict(event_id=len(journal) + 1,
                producer_event_id=producer_event_id,
                kind='local_tick_sample', component='cpu',
                local_tick=sample['local_tick'], phase=phase,
                outputs=deepcopy(sample[phase])))
    runtime.runner = SimpleNamespace(sessions={'cpu': object()},
        event_count=len(journal),
        events_since=lambda index: tuple(deepcopy(journal[index:])))
    runtime.cpu.drain_tick_samples()

    with pytest.raises(ValueError, match='Runner CPU source identity mismatch'):
        api().capture_f6_case(runtime, attempt)


def test_task5_runner_samples_require_a_case_event_cursor(consumer_case):
    runtime, attempt = consumer_case
    journal = []
    for sample in deepcopy(runtime.cpu._physical_tick_samples):
        producer_event_id = len(journal) + 1
        journal.append(dict(event_id=producer_event_id, component='cpu',
            local_tick=sample['local_tick'], inputs={}, outputs={}))
        for phase in ('pre', 'post'):
            journal.append(dict(event_id=len(journal) + 1,
                producer_event_id=producer_event_id,
                kind='local_tick_sample', component='cpu',
                local_tick=sample['local_tick'], phase=phase,
                outputs=deepcopy(sample[phase])))
    from myfuzz.scenario.runner import ScenarioRunner
    runtime.runner = object.__new__(ScenarioRunner)
    runtime.runner.sessions = {'cpu': runtime.cpu, 'dma': runtime.dma}
    runtime.runner._events = journal
    attempt.pop('_runner_event_start', None)
    runtime.cpu.drain_tick_samples()

    with pytest.raises(ValueError, match='Runner case event start is invalid'):
        api().capture_f6_case(runtime, attempt)


def test_task5_runner_sample_must_join_its_same_tick_cpu_step(consumer_case):
    runtime, attempt = consumer_case
    physical_samples = deepcopy(runtime.cpu._physical_tick_samples)
    first = physical_samples[0]
    journal = [dict(event_id=1, component='cpu',
        local_tick=first['local_tick'] + 1000, inputs={}, outputs={})]
    attempt['_runner_event_start'] = len(journal)
    for index, sample in enumerate(physical_samples):
        producer_event_id = len(journal) + 1
        journal.append(dict(event_id=producer_event_id, component='cpu',
            local_tick=sample['local_tick'], inputs={}, outputs={}))
        if index == 0:
            producer_event_id = 1  # A previous, wrong-tick CPU step.
        for phase in ('pre', 'post'):
            journal.append(dict(event_id=len(journal) + 1,
                producer_event_id=producer_event_id,
                kind='local_tick_sample', component='cpu',
                local_tick=sample['local_tick'], phase=phase,
                outputs=deepcopy(sample[phase])))
    from myfuzz.scenario.runner import ScenarioRunner
    runtime.runner = object.__new__(ScenarioRunner)
    runtime.runner.sessions = {'cpu': runtime.cpu, 'dma': runtime.dma}
    runtime.runner._events = journal
    runtime.cpu.drain_tick_samples()

    with pytest.raises(ValueError, match='Runner CPU sample producer mismatch'):
        api().capture_f6_case(runtime, attempt)


def test_missing_word_never_credits_other_words(consumer_case):
    runtime, attempt = consumer_case
    runtime.observer_view = [e for e in runtime.observer_view
                             if e.get('event_id') != attempt['word_commits'][2]]
    material = api().capture_f6_case(runtime, attempt)
    assert material['observations']['dma.word_transfer_join']['status'] == 'missing'
    assert api().f6_case_feedback(material, case_ids=(attempt['case_id'],)) == bytes(5)


def test_filtered_owner_lookup_rejects_corrupt_out_of_scope_dma_projection(
        consumer_case):
    runtime, attempt = consumer_case
    row = deepcopy(next(event for event in runtime.observer_view
        if event.get('component') == 'dma' and event.get('kind') == 'dma_edge'))
    row['event_id'] = max(event['event_id'] for event in runtime.observer_view) + 1
    row['tick'] = 1_000_000
    runtime.observer_view.append(row)

    material = api().capture_f6_case(runtime, attempt)

    assert material['observations']['dma.cpu_configuration']['status'] == 'failed'


@pytest.mark.parametrize('section,index,field,value,eid', [
    *[('configuration', i, 'wdata', 7, 'dma.cpu_configuration') for i in range(4)],
    *[('sources', i, 'byte_enable', 7, 'dma.word_transfer_join') for i in range(4)],
    *[('reads', i, 'value', 77, 'dma.word_transfer_join') for i in range(4)],
    *[('writes', i, 'byte_enable', 7, 'dma.word_transfer_join') for i in range(4)],
    ('irq', 0, 'take_key', ['other', 0, 1], 'dma.irq_isr_completion'),
    ('return', 0, 'return_target', 0, 'dma.irq_isr_completion'),
    ('next_fetch', 0, 'address', 0, 'dma.irq_isr_completion'),
    ('terminal', 0, 'value', 2, 'dma.irq_isr_completion'),
])
def test_contradictory_raw_edges_fail(consumer_case, section, index, field, value, eid):
    runtime, attempt = consumer_case
    ref = attempt[section][index] if type(attempt[section]) is list else attempt[section]
    row = next(e for e in runtime.observer_view if e['event_id'] == ref)
    if section in ('reads', 'writes'):
        row['accepted'][field] = value
    else:
        row[field] = value
    assert api().capture_f6_case(runtime, attempt)['observations'][eid]['status'] == 'failed'


@pytest.mark.parametrize('mode', ['snapshot_version', 'snapshot_writer', 'snapshot_key',
    'snapshot_owner', 'unarmed_snapshot', 'saved_json', 'route', 'route_key',
    'read_response', 'write_response', 'commit_version', 'commit_key', 'commit_cells',
    'word_order', 'operand', 'prefix', 'delivery', 'status', 'readback', 'result',
    'irq_delivery', 'irq_output', 'duplicate_commit', 'duplicate_read_response'])
def test_no_borrowed_or_reconstructed_edge_passes(consumer_case, mode):
    runtime, attempt = consumer_case
    runtime.corrupt(mode, attempt)
    material = api().capture_f6_case(runtime, attempt)
    assert any(r['status'] == 'failed' for r in material['observations'].values())
    assert api().f6_case_feedback(material, case_ids=(attempt['case_id'],)) == bytes(5)


@pytest.mark.parametrize('section', ['operands', 'sources', 'configuration', 'reads',
    'writes', 'read_responses', 'write_responses', 'irq', 'return', 'next_fetch',
    'terminal', 'status', 'readbacks', 'results', 'irq_delivery', 'irq_output'])
def test_missing_or_contradictory_edge_never_passes_and_vector_zero(consumer_case, section):
    runtime, attempt = consumer_case
    ref = attempt[section][0] if type(attempt[section]) is list else attempt[section]
    runtime.observer_view = [e for e in runtime.observer_view if e['event_id'] != ref]
    material = api().capture_f6_case(runtime, attempt)
    assert any(r['status'] in ('missing', 'failed')
        for r in material['observations'].values())
    assert api().f6_case_feedback(material, case_ids=(attempt['case_id'],)) == bytes(5)


@pytest.mark.parametrize('operation,index', [('read', 2), ('write', 2)])
def test_expected_err_retains_partial_effects_without_success_certificate(inputs, tmp_path, monkeypatch, operation, index):
    api()
    from tests.integration.f6_compiled_support import make_case
    runtime, attempt = make_case(inputs, tmp_path, monkeypatch, fault=(operation,index))
    assert runtime.policy.state == 'expected_response_fault_pending'
    assert len(runtime.actual_read_results()) == (index if operation == 'read' else 4)
    assert len(runtime.dma.memory_service.drain_commit_events()) == (0 if operation == 'read' else index)
    material = api().capture_f6_case(runtime, attempt)
    assert material['observations']['dma.word_transfer_join']['status'] == 'failed'
    irq=material['observations']['dma.irq_isr_completion']
    assert irq['status']=='failed'
    assert material['evidence_inventory'][irq['evidence_refs'][0]]['details']['error_completion']['terminal_marker']==2
    assert api().f6_case_feedback(material, case_ids=(attempt['case_id'],)) == bytes(5)
    assert runtime.dma._pending is None
    assert any('environment_error_receipt' in e for e in runtime.dma.events)


def test_checker_and_host_exceptions_propagate(consumer_case):
    runtime, attempt = consumer_case
    def broken():
        raise RuntimeError('checker implementation bug')
    runtime.checker_findings = broken
    with pytest.raises(RuntimeError, match='checker implementation bug'):
        api().capture_f6_case(runtime, attempt)


def test_policy_closes_typed_scope_order_and_expected_error(inputs):
    mod = api('myfuzz.scenario.f6_ram_dma_policy')
    from tests.integration.f6_compiled_support import source_versions
    from myfuzz.scenario.ledger import TransactionKey
    policy = mod.F6RamDmaPolicy(inputs[0]['execution_contract'])
    contract = inputs[0]['execution_contract']; source = contract['program_contract']['source_address']
    policy.begin_case('native', 'stream')
    policy.begin_transfer(case_id='c0', source_versions=source_versions(contract))
    key = TransactionKey('native', 'stream', 'dma', 0, 'dma-memory', 1)
    with pytest.raises(ValueError):
        policy.accepted(key, address=source+4, write=False, value=0, byte_enable=15, target=None)
    policy.accepted(key, address=source, write=False, value=0, byte_enable=15, target=None)
    with pytest.raises(ValueError):
        policy.completed(replace(key, source_epoch=1), rdata=11, error=0)
    with pytest.raises(ValueError):
        policy.completed(key, rdata=11, error=True)
    with pytest.raises(ValueError):
        policy.completed(key, rdata=12, error=0)
    policy.completed(key, rdata=11, error=0)
    with pytest.raises(ValueError):
        policy.accepted(key, address=source+4, write=False, value=0, byte_enable=15, target=None)


@pytest.mark.parametrize('mode', ['unarmed', 'wrong_key_identity', 'wrong_owner', 'copied_snapshot',
    'copied_handle', 'duplicate_delivery', 'override_read', 'direct_arm',
    'response_receipt', 'epoch', 'testcase', 'execution', 'ledger_entry', 'callback_event', 'bool_key'])
def test_issued_snapshot_bridge_requires_original_callback_and_handle(consumer_case, mode):
    runtime, _ = consumer_case
    with pytest.raises((ValueError, RuntimeError)):
        runtime.probe_bridge(mode)


@pytest.mark.parametrize('contradictory_word',[0,3])
def test_missing_word_cannot_hide_later_contradiction(consumer_case,contradictory_word):
    runtime,attempt=consumer_case
    runtime.observer_view=[e for e in runtime.observer_view if e['event_id']!=attempt['word_commits'][0]]
    row=next(e for e in runtime.observer_view if e['event_id']==attempt['read_responses'][contradictory_word])
    row['response']['rdata']+=1
    assert api().capture_f6_case(runtime,attempt)['observations']['dma.word_transfer_join']['status']=='failed'


def test_error_material_preserves_prior_issued_reads_and_commits(inputs,tmp_path,monkeypatch):
    from tests.integration.f6_compiled_support import make_case
    runtime,attempt=make_case(inputs,tmp_path,monkeypatch,fault=('write',2))
    material=api().capture_f6_case(runtime,attempt)
    ref=material['observations']['dma.word_transfer_join']['evidence_refs'][0]
    details=material['evidence_inventory'][ref]['details']
    assert len(details['partial_effects']['issued_read_transactions'])==4
    assert len(details['partial_effects']['destination_commit_ids'])==2
    assert 'words' not in details


def test_success_status_preserves_actual_nonerror_bits(inputs,tmp_path,monkeypatch):
    from tests.integration.f6_compiled_support import make_case
    runtime,attempt=make_case(inputs,tmp_path,monkeypatch,status_word=0x1234)
    material=api().capture_f6_case(runtime,attempt)
    assert material['observations']['dma.irq_isr_completion']['status']=='passed'
    ref=material['observations']['dma.irq_isr_completion']['evidence_refs'][0]
    assert material['evidence_inventory'][ref]['details']['actual_status_word']==0x1234


def test_copied_cpu_cannot_borrow_original_isr_issuer(consumer_case):
    runtime,attempt=consumer_case
    runtime.cpu=copy(runtime.cpu)
    material=api().capture_f6_case(runtime,attempt)
    assert material['observations']['dma.irq_isr_completion']['status']=='failed'


def test_native_read_response_with_dropped_cycle_never_closes(inputs,tmp_path,monkeypatch):
    from tests.integration.f6_compiled_support import make_case
    with pytest.raises(ValueError,match='CYC'):
        make_case(inputs,tmp_path,monkeypatch,response_cycle=False)


@pytest.mark.parametrize('mode,expected',[('early_drop','failed'),('context','failed'),
    ('expiry_high','failed'),('expiry_missing','missing')])
def test_irq_delivery_requires_actual_full_interval_and_expiry(consumer_case,mode,expected):
    runtime,attempt=consumer_case
    delivery=next(e for e in runtime.observer_view if e['event_id']==attempt['irq_delivery'])
    tick=delivery['end_local_tick'] if mode.startswith('expiry') else delivery['start_local_tick']+2
    sample=next(e for e in runtime.observer_view if e.get('kind')=='cpu_external_irq_sample' and e['local_tick']==tick)
    if mode=='expiry_missing':runtime.observer_view.remove(sample)
    elif mode=='context':sample['source_output_key']=['other',0,'o_interrupt',1]
    else:
        sample['actual_pre_input']=sample['actual_post_input']=int(mode=='expiry_high')
    result=api().capture_f6_case(runtime,attempt)
    assert result['observations']['dma.irq_isr_completion']['status']==expected


def test_irq_source_cannot_borrow_a_nonpulse_native_edge(consumer_case):
    runtime,attempt=consumer_case
    output=next(e for e in runtime.observer_view if e['event_id']==attempt['irq_output'])
    native=next(e for e in runtime.observer_view if e['event_id']==attempt['read_responses'][0])
    native['payload']['observations']['physical'][runtime.dma._irq_runtime_name]=1
    output['producer_event_id']=native['event_id']
    assert api().capture_f6_case(runtime,attempt)['observations']['dma.irq_isr_completion']['status']=='failed'


@pytest.mark.parametrize('field', ['tick', 'epoch'])
def test_irq_source_key_must_match_original_dma_edge_scope(consumer_case, field):
    runtime,attempt=consumer_case
    output=next(e for e in runtime.observer_view if e['event_id']==attempt['irq_output'])
    delivery=next(e for e in runtime.observer_view if e['event_id']==attempt['irq_delivery'])
    key=list(output['source_output_key'])
    key[3 if field=='tick' else 1] += 1
    output['source_output_key']=list(key)
    delivery['source_output_key']=list(key)

    material=api().capture_f6_case(runtime,attempt)
    assert material['observations']['dma.irq_isr_completion']['status']=='failed'


def test_irq_cannot_precede_final_native_write_response(consumer_case):
    runtime,attempt=consumer_case
    output=next(e for e in runtime.observer_view if e['event_id']==attempt['irq_output'])
    # Mark an earlier ORIGINAL synthetic native edge as a pulse as well as its
    # copied journal row. Matching source values alone cannot certify completion.
    early=next(e for e in runtime.observer_view if e['event_id']==attempt['read_responses'][0])
    irq_runtime_name=runtime.dma._irq_runtime_name
    early['payload']['observations']['physical'][irq_runtime_name]=1
    next(e for e in runtime.dma.events if e['tick']==early['tick'])['payload']['observations']['physical'][irq_runtime_name]=1
    output['producer_event_id']=early['event_id']
    assert api().capture_f6_case(runtime,attempt)['observations']['dma.irq_isr_completion']['status']=='failed'


def test_success_branch_cannot_use_original_error_site_mret(inputs,tmp_path,monkeypatch):
    from tests.integration.f6_compiled_support import make_case
    runtime,attempt=make_case(inputs,tmp_path,monkeypatch,mret_site=1)
    row=api().capture_f6_case(runtime,attempt)['observations']['dma.irq_isr_completion']
    assert row['status']=='failed' and 'MRET branch' in row['reason']


def test_expected_err_cannot_use_original_success_site_mret(inputs,tmp_path,monkeypatch):
    from tests.integration.f6_compiled_support import make_case
    runtime,attempt=make_case(inputs,tmp_path,monkeypatch,fault=('write',2),mret_site=0)
    row=api().capture_f6_case(runtime,attempt)['observations']['dma.irq_isr_completion']
    assert row['status']=='failed' and 'MRET branch' in row['reason']


def test_expected_err_records_authenticated_error_site_and_current_island(inputs,tmp_path,monkeypatch):
    from tests.integration.f6_compiled_support import make_case
    from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
    runtime,attempt=make_case(inputs,tmp_path,monkeypatch,fault=('write',2))
    material=api().capture_f6_case(runtime,attempt)
    row=material['observations']['dma.irq_isr_completion']
    assert row['status']=='failed'
    details=material['evidence_inventory'][row['evidence_refs'][0]]['details']['error_completion']
    assert details['mret_pc']==build_f6_firmware(runtime.contract).document()['isr']['mret_addresses'][1]
    assert details['terminal_marker']==2
    assert details['next_address']==runtime.contract['program_contract']['slot_base']+128


def test_missing_commit_never_hides_present_native_err_response(consumer_case):
    runtime,attempt=consumer_case
    runtime.observer_view=[e for e in runtime.observer_view if e['event_id']!=attempt['word_commits'][0]]
    response=next(e for e in runtime.observer_view if e['event_id']==attempt['write_responses'][0])
    response['response']['error']=1
    material=api().capture_f6_case(runtime,attempt)
    observation=material['observations']['dma.word_transfer_join']
    assert observation['status']=='failed'
    details=material['evidence_inventory'][observation['evidence_refs'][0]]['details']
    edges={e['edge_id']:e for e in details['word_evidence'][0]['edges']}
    assert edges['write_commit']['status']=='missing'
    assert edges['write_response']['status']=='failed'
    assert edges['write_response']['raw_rows'][0]['event_id']==attempt['write_responses'][0]
    assert edges['write_response']['raw_rows'][0]['response']['error']==1
    assert api().f6_case_feedback(material,case_ids=(attempt['case_id'],))==bytes(5)


@pytest.mark.parametrize('missing,contradictory,field,value,edge_id',[
    ('source_commits','write_responses','error',1,'write_response'),
    ('reads','word_commits','version',[0,999],'write_commit'),
    ('read_snapshots','writes','byte_enable',7,'write_accept'),
    ('read_responses','source_commits','version',[0,999],'source_commit'),
])
def test_independent_word_edges_are_collected_despite_missing_dependencies(consumer_case,missing,contradictory,field,value,edge_id):
    runtime,attempt=consumer_case
    runtime.observer_view=[e for e in runtime.observer_view if e['event_id']!=attempt[missing][0]]
    row=next(e for e in runtime.observer_view if e['event_id']==attempt[contradictory][0])
    payload=(row['response'] if contradictory.endswith('responses') else
             row['commit_document'] if 'commits' in contradictory else row['accepted'])
    payload[field]=value
    material=api().capture_f6_case(runtime,attempt)
    observation=material['observations']['dma.word_transfer_join']
    assert observation['status']=='failed'
    details=material['evidence_inventory'][observation['evidence_refs'][0]]['details']
    edges={e['edge_id']:e for e in details['word_evidence'][0]['edges']}
    assert edges[edge_id]['status']=='failed'
    assert edges[edge_id]['raw_rows'][0]['event_id']==attempt[contradictory][0]
    assert len(edges)==8


def test_word_inventory_retains_supporting_cpu_response_with_missing_commit(consumer_case):
    runtime,attempt=consumer_case
    source=next(e for e in runtime.observer_view if e['event_id']==attempt['sources'][0])
    response=next(e for e in runtime.observer_view if e.get('kind')=='data_response'
                  and e.get('transaction')==source['transaction'])
    response['error']=1
    runtime.observer_view=[e for e in runtime.observer_view if e['event_id']!=attempt['source_commits'][0]]
    material=api().capture_f6_case(runtime,attempt)
    observation=material['observations']['dma.word_transfer_join']
    assert observation['status']=='failed'
    details=material['evidence_inventory'][observation['evidence_refs'][0]]['details']
    saved=next(e for e in details['raw_evidence'] if e['event_id']==response['event_id'])
    assert saved['error']==1


@pytest.mark.parametrize('missing,failed,expected,component_statuses',[
    ('operands','word','failed',('missing','failed','passed')),
    ('read_snapshots','irq','failed',('passed','missing','failed')),
    ('operands','irq','failed',('missing','passed','failed')),
    ('operands',None,'missing',('missing','passed','passed')),
    (None,'word','failed',('passed','failed','passed')),
])
def test_cross_component_collects_all_outcomes_before_precedence(consumer_case,missing,failed,expected,component_statuses):
    runtime,attempt=consumer_case
    if missing:
        runtime.observer_view=[e for e in runtime.observer_view if e['event_id']!=attempt[missing][0]]
    if failed=='word':
        next(e for e in runtime.observer_view if e['event_id']==attempt['write_responses'][0])['response']['error']=1
    elif failed=='irq':
        next(e for e in runtime.observer_view if e['event_id']==attempt['irq'])['take_key']=['wrong',0,1]
    material=api().capture_f6_case(runtime,attempt)
    cross=material['observations']['cross_component.declared_edge_hops']
    assert cross['status']==expected
    details=material['evidence_inventory'][cross['evidence_refs'][0]]['details']
    components=details['component_evidence']
    assert set(components)=={'configuration','words','irq'}
    assert tuple(components[name]['status'] for name in ('configuration','words','irq'))==component_statuses
    # Component references remain with their component evidence. This synthetic
    # fixture has no Runner archive, so the graph-owned raw evidence is empty.
    word_refs=components['words']['raw_references']
    irq_refs=components['irq']['raw_references']
    assert dict(component='dma',event_id=attempt['write_responses'][0],
        kind='dma_edge') in word_refs
    assert dict(component='cpu',event_id=attempt['irq'],
        kind='cpu_external_irq_taken') in irq_refs
    assert details['raw_evidence']==[]
    assert api().f6_case_feedback(material,case_ids=(attempt['case_id'],))==bytes(5)


def test_conflicting_projection_stays_in_its_dma_control_domain(consumer_case):
    runtime, attempt = consumer_case
    delivery = next(row for row in runtime.observer_view
        if row.get('event_id') == attempt['deliveries'][0])
    receipt = delivery['dma_control_receipt']
    edge = next(row for row in runtime.observer_view
        if row.get('component') == 'dma' and row.get('kind') == 'dma_edge'
        and row.get('tick') in receipt['edge_ticks']
        and row.get('payload', {}).get('pre_backend', {}).get('swb_stb') == 1)
    edge['tick'] += 1000

    material = api().capture_f6_case(runtime, attempt)
    assert material['observations']['dma.cpu_configuration']['status'] == 'failed'
    assert material['observations']['dma.word_transfer_join']['status'] == 'passed'
    assert material['observations']['dma.irq_isr_completion']['status'] == 'passed'


def test_other_same_address_control_claim_requires_distinct_complete_cpu_transaction():
    from myfuzz.scenario.ledger import TransactionKey
    module=api();key=TransactionKey('local-execution','case','cpu',0,'data',2)
    old=TransactionKey('local-execution','case','cpu',0,'data',1)
    tx=vars(key);address=0x40000000
    receipt=dict(source_transaction=tx,address=address,offset=0,write=True,
        value=0x80000000,byte_enable=15,edge_ticks=[201,202,203])
    delivery=dict(component='cpu',kind='mmio_delivery',event_id=21,source_transaction=tx,
        device_id='dma',address=address,write=True,byte_enable=15,write_value=0x80000000,
        dma_control_receipt=receipt,provenance={'observed_case':{'case_id':'current','case_index':0}})
    accept=dict(component='cpu',kind='mmio_acceptance',source_transaction=tx,
        device_id='dma',address=address,write=True,byte_enable=15,write_value=0x80000000)
    cpu_accept=dict(component='cpu',kind='data_accept',transaction=tx,address=address,
        write=1,wdata=0x80000000,be=15)
    response=dict(component='cpu',kind='data_response',transaction=tx,address=address,
        write=1,wdata=0x80000000,be=15,error=0)
    for row in (cpu_accept,response):row['provenance']=deepcopy(delivery['provenance'])
    class Fake:
        cpu_id='cpu';contract={'control':{'device_id':'dma','base':address}}
        index={('cpu',21):[delivery]}
        cpu=SimpleNamespace(router=SimpleNamespace(deliveries=[{k:v for k,v in delivery.items()
            if k not in ('component','kind','event_id')}]))
        def live_cpu(self,row):pass
        def _mmio_delivery_projection(self,row):return module._raw(row)
        def owner_event_in_current_case(self,row,actual):
            return actual.get('provenance',{}).get('observed_case')=={'case_id':'current','case_index':0}
        def unique(self,owner,kind,transaction):
            return {'mmio_acceptance':accept,'data_accept':cpu_accept,'data_response':response}[kind]
    fake=Fake()
    assert module._Case._other_control_ticks(fake,old,address,True)=={201,202,203}
    delivery['provenance']['observed_case']['case_id']='previous'
    assert module._Case._other_control_ticks(fake,old,address,True)==set()
    delivery['provenance']['observed_case']['case_id']='current'
    receipt['source_transaction']=vars(old)
    assert module._Case._other_control_ticks(fake,old,address,True)==set()


@pytest.mark.parametrize('index', range(4))
def test_control_read_projection_cannot_contaminate_csr_write_scope(consumer_case,index):
    runtime, attempt = consumer_case
    delivery = next(row for row in runtime.observer_view
        if row.get('event_id') == attempt['deliveries'][index])
    word_address = delivery['dma_control_receipt']['offset'] // 4
    original = next(row for row in runtime.observer_view
        if row.get('component') == 'dma' and row.get('kind') == 'dma_edge'
        and row.get('payload', {}).get('pre_backend', {}).get('swb_stb') == 1)
    read_projection = deepcopy(original)
    read_projection['event_id'] = max(row['event_id']
        for row in runtime.observer_view) + 1
    read_projection['tick'] = 10000 + index
    pre = read_projection['payload']['pre_backend']
    pre.update(swb_adr=word_address, swb_we=0)
    runtime.observer_view.append(read_projection)

    if index == 3:
        from myfuzz.integration.compiled_f6_consumer import _Case
        _Case(runtime, attempt).configuration()
        runtime.observer_view.remove(read_projection)
        material = api().capture_f6_case(runtime, attempt)
        assert material['observations']['dma.irq_isr_completion']['status'] == 'passed'
    else:
        material = api().capture_f6_case(runtime, attempt)
        assert material['observations']['dma.cpu_configuration']['status'] == 'passed'
        assert material['observations']['dma.word_transfer_join']['status'] == 'passed'
        assert material['observations']['dma.irq_isr_completion']['status'] == 'passed'


@pytest.mark.parametrize('index', range(4))
def test_same_case_extra_control_write_is_not_filtered_by_payload(consumer_case,index):
    runtime, attempt = consumer_case
    delivery = next(row for row in runtime.observer_view
        if row.get('event_id') == attempt['deliveries'][index])
    receipt = delivery['dma_control_receipt']
    original = next(row for row in runtime.dma.events
        if row.get('tick') in receipt['edge_ticks']
        and row.get('payload', {}).get('pre_backend', {}).get('swb_stb') == 1)
    extra = deepcopy(original)
    extra['tick'] = max(event['tick'] for event in runtime.dma.events) + 100 + index
    pre = extra['payload']['pre_backend']
    pre['swb_adr'] = receipt['offset'] // 4
    pre['swb_we'] = 1
    pre['swb_dat_w'] = receipt['value'] + 1
    runtime.dma.events.append(extra)
    projection = deepcopy(extra)
    projection.update(component='dma', event_id=max(row['event_id']
        for row in runtime.observer_view) + 1)
    runtime.observer_view.append(projection)

    material = api().capture_f6_case(runtime, attempt)
    assert material['observations']['dma.cpu_configuration']['status'] == 'failed'
    assert material['observations']['dma.word_transfer_join']['status'] == 'passed'
    assert material['observations']['dma.irq_isr_completion']['status'] == 'passed'


def test_runner_control_edge_scope_excludes_authenticated_other_case(consumer_case):
    from myfuzz.integration.compiled_f6_consumer import _Case
    from myfuzz.scenario.runner import ScenarioRunner

    runtime, attempt = consumer_case
    current_case = dict(case_id=attempt['case_id'],
        case_index=attempt['case_index'])
    other_case = dict(case_id='prior-case', case_index=attempt['case_index'] - 1)
    projections = []
    journal = []
    for event_id, (tick, observed_case) in enumerate(
            ((10, current_case), (20, other_case)), start=1):
        source = dict(event_id=event_id, kind='dma_edge', component='dma',
            tick=tick, payload=dict(pre_backend=dict(swb_stb=1, swb_adr=2,
                swb_we=1, swb_dat_w=0x1234)),
            provenance=dict(schema_version='event_source_provenance.v1',
                observed_case=observed_case))
        projection = deepcopy(source)
        projection['runner_event_id'] = event_id
        projections.append(projection)
        journal.append(source)
    runtime.observer_view = projections
    runtime.runner = object.__new__(ScenarioRunner)
    runtime.runner.sessions = {'cpu': runtime.cpu, 'dma': runtime.dma}
    runtime.runner._events = journal
    attempt['_runner_event_start'] = 0
    case = _Case(runtime, attempt)

    rows = case.owner_events('dma', 'dma_edge',
        predicate=lambda row: row.get('tick') == 10,
        domain_predicate=lambda row: row.get('payload', {}).get(
            'pre_backend', {}).get('swb_stb') == 1
            and row.get('payload', {}).get('pre_backend', {}).get('swb_adr') == 2
            and row.get('payload', {}).get('pre_backend', {}).get('swb_we') == 1,
        domain_scope_predicate=case.owner_event_in_current_case,
        reject_domain_extras=True)
    assert [row['tick'] for row in rows] == [10]


def test_cross_component_preserves_order_counts_and_host_exception(consumer_case,monkeypatch):
    runtime,attempt=consumer_case;module=api();calls=[]
    for name in ('configuration','words','irq_completion'):
        original=getattr(module._Case,name)
        def observed(self,_name=name,_original=original):
            calls.append(_name);return _original(self)
        monkeypatch.setattr(module._Case,name,observed)
    module.capture_f6_case(runtime,attempt)
    assert calls==['configuration','words','irq_completion']*2
    calls.clear()
    def host_failure(self):
        calls.append('configuration');raise RuntimeError('cross checker bug')
    monkeypatch.setattr(module._Case,'configuration',host_failure)
    with pytest.raises(RuntimeError,match='cross checker bug'):
        module.capture_f6_case(runtime,attempt)
    assert calls==['configuration']


@pytest.mark.parametrize('missing,bad,field,value,expectation',[
    ('operands','configuration','wdata',7,'dma.cpu_configuration'),
    ('configuration','deliveries','write_value',7,'dma.cpu_configuration'),
    ('irq_output','terminal','value',2,'dma.irq_isr_completion'),
    ('irq_output','irq','take_key',['wrong',0,1],'dma.irq_isr_completion'),
    ('irq_output','irq_delivery','target_epoch',1,'dma.irq_isr_completion'),
    ('input_sample','terminal','value',2,'dma.irq_isr_completion'),
])
def test_expectation_leaf_collection_preserves_later_contradictions(consumer_case,missing,bad,field,value,expectation):
    runtime,attempt=consumer_case
    if missing=='input_sample':
        delivery=next(e for e in runtime.observer_view if e['event_id']==attempt['irq_delivery'])
        removed=next(e['event_id'] for e in runtime.observer_view if e.get('kind')=='cpu_external_irq_sample'
                     and e['local_tick']==delivery['start_local_tick']+1)
    else:
        reference=attempt[missing];removed=reference[0] if isinstance(reference,list) else reference
    runtime.observer_view=[e for e in runtime.observer_view if e['event_id']!=removed]
    reference=attempt[bad];reference=reference[-1] if isinstance(reference,list) else reference
    row=next(e for e in runtime.observer_view if e['event_id']==reference);row[field]=value
    material=api().capture_f6_case(runtime,attempt);observation=material['observations'][expectation]
    assert observation['status']=='failed'
    details=material['evidence_inventory'][observation['evidence_refs'][0]]['details']
    assert any(e['event_id']==reference for e in details['raw_evidence'])
    assert material['observations']['cross_component.declared_edge_hops']['status']=='failed'
    assert api().f6_case_feedback(material,case_ids=(attempt['case_id'],))==bytes(5)


@pytest.mark.parametrize('missing_output',[False,True])
@pytest.mark.parametrize('mode',['early_drop','context','expiry_high','epoch','owner','tick'])
def test_source_authentic_irq_sample_predicate_is_independent(consumer_case,missing_output,mode):
    runtime,attempt=consumer_case
    delivery=next(e for e in runtime.observer_view if e['event_id']==attempt['irq_delivery'])
    tick=delivery['end_local_tick'] if mode=='expiry_high' else delivery['start_local_tick']+2
    sample=next(e for e in runtime.observer_view if e.get('kind')=='cpu_external_irq_sample' and e['local_tick']==tick)
    original=next(e for e in runtime.cpu.cpu_events if e.get('kind')=='cpu_external_irq_sample' and e['local_tick']==tick)
    # This models contradictory values emitted by the authenticated producer,
    # rather than relying on copied-journal authentication to detect a change.
    for row in (sample,original):
        if mode=='context':row['source_output_key']=['wrong',0,'o_interrupt',1]
        elif mode=='epoch':row['reset_epoch']=runtime.cpu.reset_epoch+1
        elif mode=='owner':row['component']='wrong_cpu'
        elif mode=='tick':row['local_tick']=delivery['end_local_tick']+2
        else:row['actual_pre_input']=row['actual_post_input']=int(mode=='expiry_high')
    if missing_output:
        runtime.observer_view=[e for e in runtime.observer_view if e['event_id']!=attempt['irq_output']]
    material=api().capture_f6_case(runtime,attempt);observation=material['observations']['dma.irq_isr_completion']
    assert observation['status']=='failed'
    details=material['evidence_inventory'][observation['evidence_refs'][0]]['details']
    edge=next(e for group in details['independent_edges'] for e in group['edges']
              if e['edge_id'].startswith('input_sample.') and e['raw_rows']
              and e['raw_rows'][0]['event_id']==sample['event_id'])
    assert edge['status']=='failed' and edge['checks']
    assert edge['raw_rows'][0]['event_id']==sample['event_id']
    assert material['observations']['cross_component.declared_edge_hops']['status']=='failed'
    assert api().f6_case_feedback(material,case_ids=(attempt['case_id'],))==bytes(5)


@pytest.mark.parametrize('start',[-16,1<<64])
def test_present_invalid_irq_window_is_failed_without_output(consumer_case,start):
    runtime,attempt=consumer_case
    runtime.observer_view=[e for e in runtime.observer_view if e['event_id']!=attempt['irq_output']]
    delivery=next(e for e in runtime.observer_view if e['event_id']==attempt['irq_delivery'])
    delivery['start_local_tick']=start;delivery['end_local_tick']=start+16
    material=api().capture_f6_case(runtime,attempt)
    assert material['observations']['dma.irq_isr_completion']['status']=='failed'


@pytest.mark.parametrize('missing_output',[False,True])
@pytest.mark.parametrize('duplicate_source',[False,True])
def test_duplicate_irq_samples_are_independent_ambiguity(consumer_case,missing_output,duplicate_source):
    runtime,attempt=consumer_case
    delivery=next(e for e in runtime.observer_view if e['event_id']==attempt['irq_delivery'])
    tick=delivery['start_local_tick']+2
    sample=next(e for e in runtime.observer_view if e.get('kind')=='cpu_external_irq_sample' and e['local_tick']==tick)
    duplicate=deepcopy(sample);duplicate['event_id']=max(e['event_id'] for e in runtime.observer_view)+1
    runtime.observer_view.append(duplicate)
    if duplicate_source:
        original=next(e for e in runtime.cpu.cpu_events if e.get('kind')=='cpu_external_irq_sample' and e['local_tick']==tick)
        runtime.cpu.cpu_events.append(deepcopy(original))
    if missing_output:runtime.observer_view=[e for e in runtime.observer_view if e['event_id']!=attempt['irq_output']]
    material=api().capture_f6_case(runtime,attempt);observation=material['observations']['dma.irq_isr_completion']
    assert observation['status']=='failed'
    details=material['evidence_inventory'][observation['evidence_refs'][0]]['details']
    edges=[e for group in details['independent_edges'] for e in group['edges']
           if e['edge_id'].startswith('input_sample.') and e['raw_rows'] and e['raw_rows'][0]['local_tick']==tick]
    assert len(edges)==2 and all(e['status']=='failed' and e['checks'] for e in edges)
    assert {e['raw_rows'][0]['event_id'] for e in edges}=={sample['event_id'],duplicate['event_id']}


def test_unrelated_cpu_sample_is_not_an_irq_contradiction(consumer_case):
    runtime,attempt=consumer_case
    sample=deepcopy(next(e for e in runtime.observer_view if e.get('kind')=='cpu_external_irq_sample'
                        and e.get('source_output_key') is not None))
    sample.update(event_id=max(e['event_id'] for e in runtime.observer_view)+1,
        component='other_cpu',source_component='other_cpu',binding_delivery_event_id=99999,
        source_output_key=['other_dma',0,'o_interrupt',1],expected_input=0,actual_pre_input=0,actual_post_input=0)
    sample['receipt_id']['execution']='f'*32
    sample['input_context'].update(target_component='other_cpu',binding_delivery_event_id=99999,
        source_output_key=['other_dma',0,'o_interrupt',1],expected_input=0)
    runtime.observer_view.append(sample)
    material=api().capture_f6_case(runtime,attempt)
    assert material['observations']['cross_component.declared_edge_hops']['status']=='missing'
    assert material['observations']['dma.irq_isr_completion']['status']=='passed'
    observation=material['observations']['dma.irq_isr_completion']
    raw=material['evidence_inventory'][observation['evidence_refs'][0]]['details']['raw_evidence']
    assert all(row['event_id']!=sample['event_id'] for row in raw)


def test_runner_normalized_irq_receipt_requires_pinned_cpu_ownership(consumer_case):
    from myfuzz.scenario.runner import ScenarioRunner

    runtime, attempt = consumer_case
    case = api()._Case(runtime, attempt)
    delivery = next(row for row in runtime.observer_view
        if row.get('event_id') == attempt['irq_delivery'])
    tick = delivery['start_local_tick'] + 2
    sample = deepcopy(next(row for row in runtime.observer_view
        if row.get('kind') == 'cpu_external_irq_sample'
        and row.get('local_tick') == tick))
    nonce = sample['receipt_id']['execution']
    normalized = 'local-driver:cpu:7'
    runner_event_id = 1
    sample['runner_event_id'] = runner_event_id
    sample['receipt_id']['execution'] = normalized
    source = deepcopy(sample)
    source['event_id'] = runner_event_id
    source.pop('runner_event_id')
    runtime.runner = object.__new__(ScenarioRunner)
    runtime.runner.sessions = {'cpu': runtime.cpu}
    runtime.runner._source_transport_scopes = {'cpu': {nonce: normalized}}
    runtime.runner._events = [source]

    case.independent_irq_input(sample, delivery)


def test_runner_rejects_irq_receipt_normalization_for_another_nonce(consumer_case):
    from myfuzz.scenario.runner import ScenarioRunner

    runtime, attempt = consumer_case
    case = api()._Case(runtime, attempt)
    delivery = next(row for row in runtime.observer_view
        if row.get('event_id') == attempt['irq_delivery'])
    tick = delivery['start_local_tick'] + 2
    sample = deepcopy(next(row for row in runtime.observer_view
        if row.get('kind') == 'cpu_external_irq_sample'
        and row.get('local_tick') == tick))
    runner_event_id = 1
    sample['runner_event_id'] = runner_event_id
    sample['receipt_id']['execution'] = 'local-driver:cpu:7'
    source = deepcopy(sample)
    source['event_id'] = runner_event_id
    source.pop('runner_event_id')
    runtime.runner = object.__new__(ScenarioRunner)
    runtime.runner.sessions = {'cpu': runtime.cpu}
    runtime.runner._source_transport_scopes = {'cpu': {
        runtime.cpu._execution: 'local-driver:cpu:8'}}
    runtime.runner._events = [source]

    with pytest.raises(ValueError, match='native scope/tick'):
        case.independent_irq_input(sample, delivery)


@pytest.mark.parametrize('receipt_execution', ['missing', None])
def test_runner_rejects_absent_normalized_cpu_receipt_scope(consumer_case,
        receipt_execution):
    from myfuzz.scenario.runner import ScenarioRunner

    runtime, attempt = consumer_case
    case = api()._Case(runtime, attempt)
    delivery = next(row for row in runtime.observer_view
        if row.get('event_id') == attempt['irq_delivery'])
    tick = delivery['start_local_tick'] + 2
    sample = deepcopy(next(row for row in runtime.observer_view
        if row.get('kind') == 'cpu_external_irq_sample'
        and row.get('local_tick') == tick))
    if receipt_execution == 'missing':
        sample['receipt_id'].pop('execution')
    else:
        sample['receipt_id']['execution'] = None
    sample['runner_event_id'] = 1
    source = deepcopy(sample)
    source['event_id'] = 1
    source.pop('runner_event_id')
    runtime.runner = object.__new__(ScenarioRunner)
    runtime.runner.sessions = {'cpu': runtime.cpu}
    runtime.runner._source_transport_scopes = {'cpu': {}}
    runtime.runner._events = [source]
    attempt['_runner_event_start'] = 0

    with pytest.raises(ValueError, match='native scope/tick'):
        case.independent_irq_input(sample, delivery)


@pytest.mark.parametrize('missing_output',[False,True])
@pytest.mark.parametrize('same_source',[True,False])
def test_source_key_alone_keeps_relevant_outside_sample(consumer_case,missing_output,same_source):
    runtime,attempt=consumer_case
    delivery=next(e for e in runtime.observer_view if e['event_id']==attempt['irq_delivery'])
    sample=deepcopy(next(e for e in runtime.observer_view if e.get('kind')=='cpu_external_irq_sample'
                        and e['local_tick']==delivery['start_local_tick']+2))
    original=deepcopy(next(e for e in runtime.cpu.cpu_events if e.get('kind')=='cpu_external_irq_sample'
                          and e['local_tick']==delivery['start_local_tick']+2))
    sample['event_id']=max(e['event_id'] for e in runtime.observer_view)+1
    for row in (sample,original):
        row['local_tick']=delivery['end_local_tick']+2;row['binding_delivery_event_id']=99999
        row['input_context']['binding_delivery_event_id']=99999
        if not same_source:
            row['source_output_key']=['other_dma',0,'o_interrupt',1]
            row['input_context']['source_output_key']=['other_dma',0,'o_interrupt',1]
    runtime.observer_view.append(sample);runtime.cpu.cpu_events.append(original)
    if missing_output:runtime.observer_view=[e for e in runtime.observer_view if e['event_id']!=attempt['irq_output']]
    material=api().capture_f6_case(runtime,attempt);observation=material['observations']['dma.irq_isr_completion']
    assert observation['status']==('failed' if same_source else 'missing' if missing_output else 'passed')
    details=material['evidence_inventory'][observation['evidence_refs'][0]]['details']
    assert any(row['event_id']==sample['event_id'] for row in details['raw_evidence']) is same_source
    if same_source:
        edge=next(e for group in details['independent_edges'] for e in group['edges']
                  if e['raw_rows'] and e['raw_rows'][0]['event_id']==sample['event_id'])
        assert edge['status']=='failed' and edge['checks']


@pytest.mark.parametrize('missing_output',[False,True])
@pytest.mark.parametrize('field,value',[('start_local_tick','bad'),('end_local_tick','bad')])
def test_malformed_irq_window_is_typed_failure(consumer_case,missing_output,field,value):
    runtime,attempt=consumer_case
    delivery=next(e for e in runtime.observer_view if e['event_id']==attempt['irq_delivery']);delivery[field]=value
    if missing_output:runtime.observer_view=[e for e in runtime.observer_view if e['event_id']!=attempt['irq_output']]
    material=api().capture_f6_case(runtime,attempt)
    assert material['observations']['dma.irq_isr_completion']['status']=='failed'
    assert material['observations']['cross_component.declared_edge_hops']['status']=='failed'
    assert api().f6_case_feedback(material,case_ids=(attempt['case_id'],))==bytes(5)


def test_live_edge3_requires_original_source_bound_completion_for_all_32_words(
        tmp_path, monkeypatch):
    runtime, attempt = make_live_f6_fetch_attempt(tmp_path, monkeypatch)
    completions = [row for row in runtime.runner._events
        if row.get('kind') == 'compiled_F6_instruction_fetch_completion']
    assert any(row['request_pre_event_id'] > row['memory_read_event_id']
        for row in completions)
    material = api().capture_f6_case(runtime, attempt)
    observation = material['observations']['cross_component.declared_edge_hops']
    details = material['evidence_inventory'][observation['evidence_refs'][0]]['details']
    edge = details['edges'][3]
    assert edge['outcome'] == 'passed', edge['issues']
    assert len(edge['evidence']) == 32
    assert {row['address'] for row in edge['evidence']} == {
        runtime.contract['program_contract']['slot_base'] + offset
        for offset in range(0, 128, 4)}
    assert len({json.dumps(row['key'], sort_keys=True) for row in edge['evidence']}) == 32
    assert all(type(row['completion_event_id']) is int and row['root_refs']
        for row in edge['evidence'])
    root_fields = {'admission', 'service', 'memory_read', 'instr_response',
        'request_pre', 'request_producer', 'backend_response_pre',
        'backend_response_producer', 'backend_response_post', 'response_pre',
        'response_producer', 'response_post'}
    assert all(set(row['root_refs']) == root_fields
        and all(type(value) is int for value in row['root_refs'].values())
        for row in edge['evidence'])
    references = details['raw_references']
    assert all(set(reference) == {'component', 'event_id', 'kind'}
        for reference in references)
    completion_observer_ids = {row['event_id'] for row in runtime.observer_view
        if row.get('kind') == 'compiled_F6_instruction_fetch_completion'}
    assert completion_observer_ids <= {reference['event_id']
        for reference in references
        if reference['kind'] == 'compiled_F6_instruction_fetch_completion'}


def _capture_live_edge3(runtime, attempt):
    material = api().capture_f6_case(runtime, attempt)
    observation = material['observations']['cross_component.declared_edge_hops']
    details = material['evidence_inventory'][observation['evidence_refs'][0]]['details']
    return material, observation, details['edges'][3]


def test_live_edge3_partial_prefix_is_missing_and_retains_31_original_receipts(
        tmp_path, monkeypatch):
    runtime, attempt = make_live_f6_fetch_attempt(tmp_path, monkeypatch,
        fetch_offsets=range(0, 124, 4))

    _material, _observation, edge = _capture_live_edge3(runtime, attempt)

    assert edge['outcome'] == 'missing'
    assert len(edge['evidence']) == 31


def test_live_edge3_allows_refetch_only_with_a_distinct_complete_transaction_key(
        tmp_path, monkeypatch):
    runtime, attempt = make_live_f6_fetch_attempt(tmp_path, monkeypatch,
        fetch_offsets=(*range(0, 128, 4), 0))

    _material, _observation, edge = _capture_live_edge3(runtime, attempt)

    assert edge['outcome'] == 'passed'
    assert len(edge['evidence']) == 33
    assert len({row['address'] for row in edge['evidence']}) == 32
    keys = [json.dumps(row['key'], sort_keys=True) for row in edge['evidence']]
    assert len(set(keys)) == 33
    zero_address = runtime.contract['program_contract']['slot_base']
    zero_keys = {json.dumps(row['key'], sort_keys=True) for row in edge['evidence']
        if row['address'] == zero_address}
    assert len(zero_keys) == 2
    assert edge['issues'] == []


@pytest.mark.parametrize('tamper', [
    'completion', 'request_pre_root', 'fresh_scope', 'path_scope'])
def test_live_edge3_rejects_tampered_completion_and_runner_roots(
        tmp_path, monkeypatch, tamper):
    runtime, attempt = make_live_f6_fetch_attempt(tmp_path, monkeypatch)
    completion = next(row for row in runtime.runner._events
        if row.get('kind') == 'compiled_F6_instruction_fetch_completion')
    if tamper == 'completion':
        completion['snapshot']['data_hex'] = 'deadc0de'
    elif tamper == 'request_pre_root':
        root = runtime.runner._events[completion['request_pre_event_id'] - 1]
        root['outputs']['backend']['i_req_addr'] += 4
    elif tamper == 'path_scope':
        completion['admission']['path_id'] = 'foreign-runtime-path'
    else:
        completion['run_id'] = runtime.run_id + '-fresh'

    _material, observation, edge = _capture_live_edge3(runtime, attempt)

    assert edge['outcome'] == 'failed'
    assert observation['status'] == 'failed'


def test_live_edge3_rejects_mutated_original_issuer_receipt(tmp_path, monkeypatch):
    from myfuzz.scenario.f6_instruction_fetch_receipt import \
        f6_instruction_fetch_receipts

    runtime, attempt = make_live_f6_fetch_attempt(tmp_path, monkeypatch)
    receipt = f6_instruction_fetch_receipts(runtime.cpu)[0]
    object.__setattr__(receipt, 'address', receipt.address + 4)

    _material, observation, edge = _capture_live_edge3(runtime, attempt)

    assert edge['outcome'] == 'failed'
    assert observation['status'] == 'failed'


def test_live_edge3_rejects_foreign_case_slot_scope(tmp_path, monkeypatch):
    runtime, attempt = make_live_f6_fetch_attempt(tmp_path, monkeypatch)
    candidate = runtime.preflight(bytes.fromhex(attempt['raw8_hex']))
    attempt['case_id'] = runtime.run_id + ':case:1'
    attempt['case_index'] = 1
    attempt['prefix_hex'] = runtime.program.prefix(candidate,
        case_index=1).hex()

    _material, observation, edge = _capture_live_edge3(runtime, attempt)

    assert edge['outcome'] in ('failed', 'missing')
    assert observation['status'] in ('failed', 'missing')
    assert edge['outcome'] != 'passed'


def test_irq_join_accepts_runner_normalized_take_receipt(tmp_path, monkeypatch):
    """Runner scope mapping joins the take to the original ISR issuer receipt."""
    from myfuzz.scenario.runner import ScenarioRunner

    runtime, attempt = make_case(inputs.__wrapped__(), tmp_path, monkeypatch)
    consumer = object.__new__(api()._Case)
    consumer.runtime, consumer.attempt, consumer.contract = runtime, attempt, runtime.contract
    consumer.cpu, consumer.dma = runtime.cpu, runtime.dma
    consumer.cpu_id, consumer.dma_id = runtime.cpu.source_component, runtime.dma.source_component
    runner = object.__new__(ScenarioRunner)
    runner.sessions = {consumer.cpu_id: runtime.cpu}
    runner._source_transport_scopes = {consumer.cpu_id: {
        runtime.cpu._execution: 'local-driver:cpu:1'}}
    runtime.runner = runner
    selected = {section: deepcopy(next(row for row in runtime.observer_view
        if row.get('event_id') == attempt[section]))
        for section in ('irq_output', 'irq_delivery', 'irq', 'return')}
    selected['irq']['receipt_id']['execution'] = 'local-driver:cpu:1'
    class StatusReached(Exception):
        pass
    def select(section, *_args):
        if section == 'status':
            raise StatusReached()
        return selected[section]
    consumer.event = select
    consumer.independent_irq_delivery = lambda _row: None
    consumer.live_cpu = lambda _row: None
    with pytest.raises(StatusReached):
        consumer.irq_completion_join()


@pytest.mark.parametrize('mutation', ['owner', 'mapping', 'sequence', 'raw_execution'])
def test_irq_join_rejects_unbound_runner_receipt_identity(tmp_path, monkeypatch, mutation):
    from myfuzz.scenario.runner import ScenarioRunner

    runtime, attempt = make_case(inputs.__wrapped__(), tmp_path, monkeypatch)
    consumer = object.__new__(api()._Case)
    consumer.runtime, consumer.attempt, consumer.contract = runtime, attempt, runtime.contract
    consumer.cpu, consumer.dma = runtime.cpu, runtime.dma
    consumer.cpu_id, consumer.dma_id = runtime.cpu.source_component, runtime.dma.source_component
    runner = object.__new__(ScenarioRunner)
    runner.sessions = {consumer.cpu_id: runtime.cpu}
    runner._source_transport_scopes = {consumer.cpu_id: {
        runtime.cpu._execution: 'local-driver:cpu:1'}}
    runtime.runner = runner
    selected = {section: deepcopy(next(row for row in runtime.observer_view
        if row.get('event_id') == attempt[section]))
        for section in ('irq_output', 'irq_delivery', 'irq', 'return')}
    selected['irq']['receipt_id']['execution'] = 'local-driver:cpu:1'
    if mutation == 'owner':
        runner.sessions[consumer.cpu_id] = object()
    elif mutation == 'mapping':
        runner._source_transport_scopes[consumer.cpu_id][runtime.cpu._execution] = 'other'
    elif mutation == 'sequence':
        selected['irq']['receipt_id']['sequence'] += 1
    else:
        selected['irq']['receipt_id']['execution'] = 'unrelated'
    consumer.event = lambda section, *_args: selected[section]
    consumer.independent_irq_delivery = lambda _row: None
    consumer.live_cpu = lambda _row: None
    with pytest.raises(api()._Contradiction, match='MRET/take case/key/receipt mismatch'):
        consumer.irq_completion_join()


def test_remember_retains_a_detached_row_in_the_published_json_value_domain():
    """The retained row is detached and stays in the saved-evidence JSON domain."""
    from myfuzz.integration import compiled_f6_consumer as consumer
    case = object.__new__(consumer._Case)
    case.raw_evidence = []
    case.seen_raw = set()
    row = {'event_id': 7, 'component': 'cpu', 'kind': 'local_tick_sample',
           'local_tick': 11, 'version': (3, 1),
           'outputs': {'driver_samples': [{'local_tick': 11, 'pre': {'protocol_taps': {'a': 1}}}]},
           'provenance': {'observed_case': {'case_id': 'c', 'case_index': 0},
                          'origin_admission_ids': ['id-1'], 'resource': None}}
    case.remember([row, row])
    assert len(case.raw_evidence) == 1
    retained = case.raw_evidence[0]
    assert retained == json.loads(consumer._json(row))
    assert retained is not row and retained['outputs'] is not row['outputs']
    assert row['version'] == (3, 1) and retained['version'] == [3, 1]
    row['outputs']['driver_samples'][0]['pre']['protocol_taps']['a'] = 2
    row['version'] = (9, 9)
    assert retained['outputs']['driver_samples'][0]['pre']['protocol_taps'] == {'a': 1}
    assert retained['version'] == [3, 1]
