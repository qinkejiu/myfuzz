"""F1/F3 must reach the same generic plan from real declarations.

The first control is software-only: no CPU process, native trace or RAM write is
claimed by compiling the scenario.
"""
from pathlib import Path
from copy import deepcopy
from types import SimpleNamespace

import pytest

from myfuzz.runtime.preparation import create_preparation
from tests.runtime.test_plan_compiler import compile_from_context


ROOT = Path(__file__).resolve().parents[2]
TIMER = ROOT / 'configs/scenarios/compiled-f4-obi-apb-timer'


@pytest.mark.parametrize('flows', [('F1', 'F2', 'F3', 'F4')])
def test_real_declared_f1_f3_paths_compile_in_one_generic_plan(tmp_path, flows):
    context = create_preparation(
        base_dir=ROOT, compose_path=TIMER / 'compose.json',
        capability_paths=(TIMER / 'test_capability.json',),
        supplement_path=TIMER / 'execution_supplement.json',
        generated_dir=tmp_path / 'generated', flow_ids=flows)
    try:
        result = compile_from_context(context)
        paths = {row['flow_id']: row for row in result.plan.document()['paths']}
        assert set(paths) == set(flows)
        for flow, kind in (('F1', 'instruction_image'), ('F3', 'cpu_store_stream')):
            sources = [row for row in paths[flow]['sources'] if row['kind'] == kind]
            assert len(sources) == 1 and sources[0]['origin'] == 'fuzzable'
    finally:
        context.close()


def test_f1_f3_memory_paths_bind_the_actual_compiled_graph(tmp_path):
    from tests.integration.test_compiled_f4_storage_producer import timer_loaded
    from myfuzz.runtime.flows.memory import prepare_memory_paths

    _artifacts, inputs = timer_loaded(tmp_path)
    prepared, bindings = prepare_memory_paths(
        request=inputs['request'], compiled=inputs['compiled'])
    assert {binding.logical_source_id for binding in bindings} == {'ram.image'}
    assert {binding.source_id for binding in bindings} == {
        'F1.program_image', 'F3.program_image'}
    assert len(prepared.runtime_paths) == 2
    altered = deepcopy(inputs['compiled'])
    f3 = next(row for row in altered['paths'] if row['flow_id'] == 'F3')
    next(row for row in f3['sources'] if row['kind'] == 'cpu_store_stream')['range'][0] += 4
    with pytest.raises(ValueError):
        prepare_memory_paths(request=inputs['request'], compiled=altered)


@pytest.mark.parametrize('flow,source,record', [
    ('F1', 'ram.image', '13000000'), ('F3', 'ram.store_stream', '78563412')])
def test_memory_kernel_keeps_declared_case_identity(flow, source, record):
    from myfuzz.runtime.flows.memory import MemoryFlowKernel
    path = {'path_id': flow + ':ram.image', 'flow_id': flow,
            'sources': [{'source_id': source, 'kind': (
                'instruction_image' if flow == 'F1' else 'cpu_store_stream'),
                'origin': 'fuzzable'}]}
    bound = SimpleNamespace(plan=SimpleNamespace(document=lambda: {'paths': [path]}),
                            plan_sha256='a' * 64)
    kernel = MemoryFlowKernel()
    context = kernel.prepare(bound, path['path_id'])
    case = {'testcase_id': 'case-1', 'path_id': path['path_id'],
            'source_id': source, 'raw_records_hex': [record]}
    lowered = kernel.lower(context, case)
    assert (lowered.flow_id, lowered.source_id, lowered.raw_records) == (
        flow, source, (bytes.fromhex(record),))
    with pytest.raises(ValueError):
        kernel.lower(context, {**case, 'source_id': 'foreign'})


def test_f1_rejects_an_unbounded_store_before_execution():
    from myfuzz.runtime.flows.memory import MemoryFlowKernel
    path = {'path_id': 'F1:ram.image', 'flow_id': 'F1', 'sources': [
        {'source_id': 'ram.image', 'kind': 'instruction_image', 'origin': 'fuzzable'}]}
    bound = SimpleNamespace(plan=SimpleNamespace(document=lambda: {'paths': [path]}),
                            plan_sha256='a' * 64)
    kernel = MemoryFlowKernel()
    context = kernel.prepare(bound, path['path_id'])
    case = {'testcase_id': 'unsafe', 'path_id': path['path_id'],
            'source_id': 'ram.image', 'raw_records_hex': ['23202000']}
    with pytest.raises(ValueError):
        kernel.lower(context, case)


def test_memory_submission_uses_one_existing_session_and_reports_missing_evidence():
    from myfuzz.runtime.flows.memory import submit_memory_case
    binding = SimpleNamespace(source_id='F1.program_image', path_id='runtime-f1')
    cases = []
    # A bound session declares the batch template it was opened with; the live
    # transaction scope is read from it, so the fake carries the same contract.
    session = SimpleNamespace(
        template=SimpleNamespace(testcase_id='unit-case'),
        submit_case=lambda case, **options: (
            cases.append(case) or SimpleNamespace(status='running', violations=(), events=(),
                                                  local_ticks_after={'processor': 0})))
    runtime = SimpleNamespace(_stable=lambda: None, finished=False, records=[],
        max_cases=4, cursor=0x10000, result=0x1fffc, rounds=1,
        cpu_id='processor',
        runner=SimpleNamespace(sessions={'processor': SimpleNamespace(
            waiting_instruction_address=None, reset_epoch=0)}),
        session=session, run_id='unit', memory_bindings={'F1': binding})
    result = submit_memory_case(runtime, b'\x13\x00\x00\x00', flow='F1')
    assert cases[0].path_id == 'runtime-f1'
    assert cases[0].source.source_id == 'F1.program_image'
    assert result['retirement'] == 'unknown'
    assert result['status'] == 'submitted'
    assert result['instruction_boundary_park']['reason'] == 'no_instruction_fetch_park'
    assert runtime.session is session


def test_existing_generic_mixed_entry_selects_f1_and_f3_in_order():
    from myfuzz.runtime.generic_campaign import load_descriptor, select_case_records
    descriptor = load_descriptor(TIMER / 'generic_scenario.json', base_dir=ROOT)
    cases = select_case_records(descriptor, flow='mixed', records=[
        'F1:13000000', 'F3:78563412', 'F4:55000000', 'F2:04100040'])
    assert tuple(flow for flow, _raw in cases) == ('F1', 'F3', 'F4', 'F2')


def _f3_observation_fixture():
    """Synthetic OBI observations; these are not a native execution claim."""
    from types import SimpleNamespace
    signals = {role: role for role in ('req', 'gnt', 'addr', 'rvalid', 'rdata',
                                      'error', 'we', 'wdata', 'be')}
    tx = {'execution_id': 'run', 'testcase_id': 'session',
          'source_component': 'cpu', 'source_epoch': 0,
          'channel_id': 'data', 'source_sequence': 1}
    case = {'case_id': 'case-3', 'case_index': 1}
    def tick(event_id, taps):
        return {'event_id': event_id, 'component': 'cpu', 'local_tick': event_id,
                'outputs': {'driver_samples': [{'local_tick': event_id,
                    'pre': {'protocol_taps': taps}}]}}
    accept = tick(1, {'req': 1, 'gnt': 1, 'addr': 0x1080, 'rvalid': 0,
                      'we': 1, 'wdata': 0x12345678, 'be': 15})
    write = {'event_id': 2, 'kind': 'memory_write', 'component': 'cpu',
             'producer_event_id': 1, 'address': 0x1080, 'value': 0x12345678,
             'width_bytes': 4, 'byte_enable': 15, 'memory_id': 'ram',
             'byte_offset': 128, 'generation': 0, 'version': [0, 1],
             'transaction': tx, 'provenance': {'observed_case': case}}
    response = tick(3, {'req': 0, 'gnt': 0, 'rvalid': 1, 'rdata': 0, 'error': 0})
    return dict(events=[accept, write, response],
        receipt=SimpleNamespace(case_id='case-3', event_start=0, event_end=3),
        cpu='cpu', address=0x1080, value=0x12345678, memory_id='ram',
        memory_base=0x1000, memory_generation=0, traces={'data': signals},
        error_policy={'native_error_observation': True},
        transaction_scope={'execution_id': 'run', 'testcase_id': 'session',
                           'source_component': 'cpu', 'source_epoch': 0})


def test_f3_observes_a_matching_case_scoped_cpu_beat_and_ram_write():
    from myfuzz.runtime.flows.memory import _observe_f3_write
    observed = _observe_f3_write(**_f3_observation_fixture())
    assert observed['memory_write_event'] == 2
    assert observed['acceptance_event'] == 1
    assert observed['response_event'] == 3


@pytest.mark.parametrize('change', ['missing_response', 'wrong_case', 'wrong_transaction', 'wrong_execution',
                                    'wrong_producer', 'wrong_value', 'partial_write', 'wrong_generation'])
def test_f3_does_not_promote_unjoined_or_incomplete_observations(change):
    from myfuzz.runtime.flows.memory import _observe_f3_write
    args = _f3_observation_fixture()
    events = args['events']
    if change == 'missing_response': events.pop()
    if change == 'wrong_case': events[1]['provenance']['observed_case']['case_id'] = 'other'
    if change == 'wrong_transaction': events[1]['transaction']['source_sequence'] = 2
    if change == 'wrong_execution': events[1]['transaction']['execution_id'] = 'foreign'
    if change == 'wrong_producer': events[1]['producer_event_id'] = 3
    if change == 'wrong_value': events[1]['value'] = 0
    if change == 'partial_write': events[1]['byte_enable'] = 3
    if change == 'wrong_generation': events[1]['generation'] = 1; events[1]['version'] = [1, 1]
    assert _observe_f3_write(**args) is None


def test_campaign_marks_success_without_effect_evidence_as_submitted():
    from unittest.mock import patch
    from tests.runtime.test_persistent_engine import _world, _engine, CASES
    bound, _runner, path, runtime = _world()
    engine = _engine(bound, path, runtime)
    engine.start()
    with patch.object(type(engine.kernel), 'capture', return_value=()):
        record = engine.submit(CASES[0])
    assert record['status'] == 'submitted'
    assert record['evidence'] == []
    engine.finish()
