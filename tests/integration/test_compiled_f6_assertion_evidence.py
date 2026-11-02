"""Five-row, separately scoped documentary results do not issue live authority."""
from copy import deepcopy
import importlib
import importlib.util

import pytest

from tests.integration.f6_compiled_support import consumer_case, inputs


def api():
    name = 'myfuzz.scenario.f6_assertion_evidence'
    assert importlib.util.find_spec(name) is not None, 'Task5 five typed assertions are missing'
    return importlib.import_module(name)


def material(runtime, attempt):
    from myfuzz.integration.compiled_f6_consumer import capture_f6_case
    capture_f6_case(runtime, attempt)
    return api().build_f6_assertion_material(runtime)


def test_exact_five_rows_and_independent_inventory(consumer_case):
    runtime, attempt = consumer_case
    result = material(runtime, attempt)
    expected = runtime.contract['expectation_ids']
    assert [a['expectation_id'] for a in result['assertions']['cases'][0]['assertions']] == expected
    original = deepcopy(result)
    result['assertions']['cases'][0]['assertions'][0]['status'] = 'failed'
    assert runtime.case_inventory == original['assertion_evidence']['cases']
    assert api().validate_f6_assertion_evidence(original,
        execution_binding=runtime.evidence_binding(), case_inventory=runtime.case_inventory) == original


@pytest.mark.parametrize('mode', ['missing_row', 'extra_row', 'duplicate_row', 'case',
    'run', 'path', 'compiled', 'binding', 'execution_binding', 'borrowed_reference',
    'missing_inventory', 'contradiction', 'duplicate_reference', 'coherent_rehash', 'extra_case'])
def test_saved_evidence_requires_exact_five_rows_and_frozen_external_inventory(consumer_case, mode):
    runtime, attempt = consumer_case
    result = material(runtime, attempt)
    rows = result['assertions']['cases'][0]['assertions']
    if mode == 'missing_row':rows.pop()
    elif mode == 'extra_row':rows.append(dict(rows[0], expectation_id='unknown'))
    elif mode == 'duplicate_row':rows[-1] = deepcopy(rows[0])
    elif mode == 'case':result['assertions']['cases'][0]['case_id'] = 'borrowed'
    elif mode in ('run', 'path', 'compiled', 'binding', 'execution_binding'):
        key = dict(run='run_id', path='path_sha256', compiled='compiled_document_sha256',
            binding='binding_sha256', execution_binding='execution_binding_sha256')[mode]
        result['assertion_evidence'][key] = 'other'
    elif mode == 'borrowed_reference':rows[0]['evidence_refs'] = rows[1]['evidence_refs'][:]
    elif mode == 'duplicate_reference':rows[0]['evidence_refs'] *= 2
    elif mode == 'missing_inventory':result['assertion_evidence']['cases'][0]['evidence_inventory'].clear()
    elif mode == 'contradiction':
        next(iter(result['assertion_evidence']['cases'][0]['evidence_inventory'].values()))['outcome'] = 'failed'
    elif mode == 'coherent_rehash':
        case = result['assertion_evidence']['cases'][0]
        row = next(iter(case['evidence_inventory'].values())); row['details'] = {'forged': True}
    elif mode == 'extra_case':result['assertions']['cases'].append(deepcopy(result['assertions']['cases'][0]))
    with pytest.raises(ValueError):
        api().validate_f6_assertion_evidence(result, execution_binding=runtime.evidence_binding(),
            case_inventory=runtime.case_inventory)


def test_missing_admitted_case_is_retained_with_all_five_missing_rows(consumer_case):
    runtime, attempt = consumer_case
    result = api().build_f6_assertion_material(runtime)
    assert [r['status'] for r in result['assertions']['cases'][0]['assertions']] == ['missing']*5
    assert api().f6_case_feedback(result, case_ids=(attempt['case_id'],)) == bytes(5)


def test_contradiction_cannot_be_hidden_by_missing_observation(consumer_case):
    runtime, attempt = consumer_case
    result = material(runtime, attempt)
    case = result['assertion_evidence']['cases'][0]
    case['observations'].pop(runtime.contract['expectation_ids'][0])
    next(iter(case['evidence_inventory'].values()))['outcome'] = 'failed'
    with pytest.raises(ValueError):
        api().validate_f6_assertion_evidence(result, execution_binding=runtime.evidence_binding(), case_inventory=runtime.case_inventory)


def test_feedback_conjoins_all_cases_and_never_credits_partial_vector(consumer_case):
    runtime, attempt = consumer_case
    result = material(runtime, attempt)
    # The runnerless fixture cannot certify the declared cross-component hops,
    # so no feedback vector is eligible even when all component projections pass.
    assert api().f6_case_feedback(result, case_ids=(attempt['case_id'],)) == bytes(5)
    assert api().f6_case_feedback(result, case_ids=(attempt['case_id'], 'missing')) == bytes(5)
    result['assertions']['cases'][0]['assertions'][3]['status'] = 'missing'
    assert api().f6_case_feedback(result, case_ids=(attempt['case_id'],)) == bytes(5)


def test_original_inventory_cannot_be_overwritten_after_capture(consumer_case):
    runtime,attempt=consumer_case
    result=material(runtime,attempt)
    runtime.observer_view=[]
    from myfuzz.integration.compiled_f6_consumer import capture_f6_case
    with pytest.raises(ValueError,match='immutable'):
        capture_f6_case(runtime,attempt)
    assert runtime.case_inventory==result['assertion_evidence']['cases']


def test_passed_non_protocol_expectation_requires_raw_rows_and_references(consumer_case):
    runtime, attempt = consumer_case
    result = material(runtime, attempt)
    case = result['assertion_evidence']['cases'][0]
    item = next(row for row in case['evidence_inventory'].values()
        if row['kind'] != 'protocol_checker.receipt_violations'
        and row['outcome'] == 'passed')
    item['details']['raw_evidence'] = []
    item['details']['raw_references'] = []
    with pytest.raises(ValueError, match='raw evidence'):
        api().validate_f6_assertion_evidence(result,
            execution_binding=runtime.evidence_binding(),
            case_inventory=result['assertion_evidence']['cases'])


def test_passed_raw_references_must_close_to_raw_rows(consumer_case):
    runtime, attempt = consumer_case
    result = material(runtime, attempt)
    case = result['assertion_evidence']['cases'][0]
    item = next(row for row in case['evidence_inventory'].values()
        if row['kind'] != 'protocol_checker.receipt_violations'
        and row['outcome'] == 'passed')
    item['details']['raw_references'] = [
        {'component': 'unrelated', 'event_id': 987654, 'kind': 'memory_write'}]
    with pytest.raises(ValueError, match='raw evidence reference'):
        api().validate_f6_assertion_evidence(result,
            execution_binding=runtime.evidence_binding(),
            case_inventory=result['assertion_evidence']['cases'])
