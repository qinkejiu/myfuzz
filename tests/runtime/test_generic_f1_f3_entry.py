"""F1/F3 entry must bind the real compiled sources before starting RTL.

These are software-only tests. A path marked executable by compiled_paths is
not evidence of a fetch, retired instruction, or CPU-authenticated RAM store.
"""
from copy import deepcopy

import pytest

from myfuzz.runtime.generic_campaign import (
    GenericScenarioRefused, case_sequence_for_plan,
)
from tests.scenario.test_compiled_paths import SOC_RENDER_REQUEST, compile_document


@pytest.fixture
def real_compiled_paths():
    document = compile_document(SOC_RENDER_REQUEST)
    rows = {row['flow_id']: row for row in document['paths']}
    assert rows['F1']['status'] == rows['F3']['status'] == 'executable'
    image = [s for s in rows['F1']['sources'] if s['kind'] == 'instruction_image']
    stores = [s for s in rows['F3']['sources'] if s['kind'] == 'cpu_store_stream']
    assert len(image) == len(stores) == 1
    assert image[0]['origin'] == stores[0]['origin'] == 'fuzzable'
    assert image[0]['range'] and stores[0]['range']
    return document


def test_generic_case_sequence_selects_actual_f1_image_and_f3_store_sources(real_compiled_paths):
    rows = {row['flow_id']: row for row in real_compiled_paths['paths']}
    image = next(s for s in rows['F1']['sources'] if s['kind'] == 'instruction_image')
    store = next(s for s in rows['F3']['sources'] if s['kind'] == 'cpu_store_stream')
    sequence = case_sequence_for_plan(
        scenario_id='compiled-memory', plan_document=real_compiled_paths,
        plan_sha256='a' * 64,
        cases=(('F1', '13000000'), ('F3', '00000000'), ('F1', '13000000')))
    assert [(row['path_id'], row['source_id'], row['raw_records_hex'])
            for row in sequence['cases']] == [
        (rows['F1']['path_id'], image['source_id'], ['13000000']),
        (rows['F3']['path_id'], store['source_id'], ['00000000']),
        (rows['F1']['path_id'], image['source_id'], ['13000000'])]


@pytest.mark.parametrize('flow,kind', [('F1', 'instruction_image'),
                                       ('F3', 'cpu_store_stream')])
def test_missing_compiled_source_cannot_be_replaced_by_a_different_kind(real_compiled_paths, flow, kind):
    document = deepcopy(real_compiled_paths)
    path = next(row for row in document['paths'] if row['flow_id'] == flow)
    path['sources'] = [source for source in path['sources'] if source['kind'] != kind]
    # This unrelated stream must not become the source for either flow.
    path['sources'].append({'kind': 'cpu_load_stream', 'origin': 'fuzzable',
                            'source_id': 'unrelated-load'})
    with pytest.raises(GenericScenarioRefused):
        case_sequence_for_plan(scenario_id='invalid', plan_document=document,
                               plan_sha256='a' * 64, cases=((flow, '00000000'),))


@pytest.mark.parametrize('flow,kind', [('F1', 'instruction_image'),
                                       ('F3', 'cpu_store_stream')])
def test_ambiguous_compiled_source_is_refused(real_compiled_paths, flow, kind):
    document = deepcopy(real_compiled_paths)
    path = next(row for row in document['paths'] if row['flow_id'] == flow)
    source = next(source for source in path['sources'] if source['kind'] == kind)
    extra = deepcopy(source)
    extra['source_id'] += '.duplicate'
    path['sources'].append(extra)
    with pytest.raises(GenericScenarioRefused):
        case_sequence_for_plan(scenario_id='ambiguous', plan_document=document,
                               plan_sha256='a' * 64, cases=((flow, '00000000'),))


def test_summary_reads_process_identity_and_exit_from_closed_execution_audit():
    from myfuzz.runtime.generic_campaign import summarize_execution_identities

    audit = {'identities': {'cpu': {'pid': 101}, 'device': {'pid': 202}},
             'exits': {'cpu': {'returncode': 0, 'reaped': True},
                       'device': {'returncode': 3, 'reaped': True}}}
    assert summarize_execution_identities(audit) == {
        'cpu': {'pid': 101, 'returncode': 0, 'reaped': True},
        'device': {'pid': 202, 'returncode': 3, 'reaped': True}}


def test_summary_does_not_invent_missing_process_or_exit_evidence():
    from myfuzz.runtime.generic_campaign import summarize_execution_identities

    audit = {'identities': {'cpu': {'pid': 101}, 'device': {'pid': None}},
             'exits': {'device': {'returncode': None, 'reaped': False}}}
    assert summarize_execution_identities(audit) == {
        'cpu': {'pid': 101, 'returncode': None, 'reaped': None},
        'device': {'pid': None, 'returncode': None, 'reaped': False}}


def test_persistent_campaign_passes_declared_case_identity_to_an_opted_in_channel():
    """An instruction channel needs the bound path/source, not just raw bytes.

    F4 here exercises the existing real campaign engine and storage kernel with
    the repository's software harness stand-in; it makes no RTL claim. The
    missing handoff is needed before an F1/F3 session channel can validate that
    a decoded instruction belongs to the directed plan's source and testcase.
    """
    from myfuzz.runtime.flows.storage import StorageFlowChannel
    from tests.runtime.test_persistent_engine import _engine, _world
    from tests.runtime.test_storage_kernel import directed_case

    bound, _, path, runtime = _world()

    class CaseAwareChannel(StorageFlowChannel):
        accepts_lowered_case = True

        def __init__(self, runtime):
            super().__init__(runtime, flow_id='F4')
            self.received = []

        def submit_lowered(self, lowered, raw_index):
            self.received.append((lowered.testcase_id, lowered.path_id,
                                  lowered.source_id, lowered.flow_id,
                                  raw_index, lowered.raw_records[raw_index]))
            return super().submit(lowered.raw_records[raw_index])

    channel = CaseAwareChannel(runtime)
    engine = _engine(bound, path, runtime, channel=channel)
    engine.prepare()
    engine.start()
    case = directed_case('selected-case', path_id=path['path_id'],
                         source_id='timer0.TIMER0_CTRL.CTRL.value',
                         records=('44332211',))
    try:
        engine.submit(case)
        assert channel.received == [('selected-case', path['path_id'],
                                    'timer0.TIMER0_CTRL.CTRL.value', 'F4',
                                    0, bytes.fromhex('44332211'))]
    finally:
        engine.finish()


def test_incomplete_case_aware_channel_is_refused_before_session_start():
    from myfuzz.runtime.contracts import GenericRuntimeRefused
    from myfuzz.runtime.flows.storage import StorageFlowChannel
    from tests.runtime.test_persistent_engine import _engine, _world

    bound, runner, path, runtime = _world()
    channel = StorageFlowChannel(runtime, flow_id='F4')
    channel.accepts_lowered_case = True
    with pytest.raises(GenericRuntimeRefused) as error:
        _engine(bound, path, runtime, channel=channel)
    assert error.value.code == 'generic-contract-type'
    assert runner.began == 0


