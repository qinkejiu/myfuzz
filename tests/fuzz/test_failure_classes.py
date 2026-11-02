"""Pure-Python tests for the case failure classification and recovery semantics.

The classifier must keep four things apart that the fuzz loop previously mixed:
a random input that never triggered the device (expected), a bounded wait that
expired, a protocol/bus error, and a device/execution anomaly.  No RTL is needed
for these tests: the inputs are the exact case-line dictionaries the executor's
parser produces.
"""
import pytest

from scripts.run_inprocess_f1f6 import (EXPECTED_FAILURE_CLASSES, FAILURE_CLASSES,
                                       FAILURE_SEVERITY, classify_case,
                                       classify_host_failure, recovery_declaration)


def case(flow='F5', status='failed', **fields):
    base = dict(index=0, flow=flow, status=status, record=flow + ':0')
    base.update(fields)
    return base


def check(case_dict):
    verdict = classify_case(case_dict)
    assert verdict['failure_class'] in FAILURE_CLASSES
    assert verdict['severity'] == FAILURE_SEVERITY[verdict['failure_class']]
    assert verdict['expected'] == (verdict['failure_class'] in EXPECTED_FAILURE_CLASSES)
    assert verdict['detail']
    return verdict


def test_a_passing_case_is_not_a_failure():
    verdict = check(case('F1', status='observations_passed'))
    assert verdict['failure_class'] == 'passed'
    assert verdict['severity'] == 'none'


def test_a_random_f5_that_never_triggered_is_expected_not_a_defect():
    verdict = check(case('F5', wait_timeout=1, irq_edges=0, irq_takes=0))
    assert verdict['failure_class'] == 'not_triggered'
    assert verdict['expected'] is True
    assert verdict['severity'] == 'expected'
    assert 'never asserted' in verdict['detail']


def test_an_asserted_irq_the_cpu_did_not_take_is_a_wait_limit():
    verdict = check(case('F5', wait_timeout=1, irq_edges=1, irq_takes=0))
    assert verdict['failure_class'] == 'wait_budget_exceeded'
    assert verdict['severity'] == 'limit'
    assert verdict['expected'] is False


def test_an_irq_the_handler_did_not_finish_is_a_wait_limit():
    verdict = check(case('F5', wait_timeout=1, irq_edges=1, irq_takes=1,
                         isr_flag=0))
    assert verdict['failure_class'] == 'wait_budget_exceeded'


def test_a_handler_that_ran_but_did_not_set_the_flag_is_an_anomaly():
    verdict = check(case('F5', irq_edges=1, irq_takes=1, isr_flag=0))
    assert verdict['failure_class'] == 'device_anomaly'
    assert verdict['severity'] == 'anomaly'


def test_a_handler_that_stored_the_wrong_status_is_an_anomaly():
    verdict = check(case('F5', irq_edges=1, irq_takes=1, isr_flag=1,
                         apb_read_data=7, isr_result=8))
    assert verdict['failure_class'] == 'device_anomaly'


def test_more_than_one_irq_in_one_case_is_state_contamination():
    verdict = check(case('F5', irq_edges=2, irq_takes=2, isr_flag=1))
    assert verdict['failure_class'] == 'state_contamination'
    verdict = check(case('F6', irq_edges=2, irq_takes=2, isr_flag=1,
                         busy_after=0, err_after=0))
    assert verdict['failure_class'] == 'state_contamination'


def test_a_dma_that_still_reports_busy_after_completion_is_an_anomaly():
    verdict = check(case('F6', irq_edges=1, irq_takes=1, isr_flag=1,
                         busy_after=1, err_after=0))
    assert verdict['failure_class'] == 'device_anomaly'


def test_a_dma_handler_that_stored_the_wrong_control_word_is_an_anomaly():
    verdict = check(case('F6', irq_edges=1, irq_takes=1, isr_flag=1,
                         busy_after=0, err_after=0, ctl_status=3, isr_result=4))
    assert verdict['failure_class'] == 'device_anomaly'


def test_an_interrupt_taken_during_a_non_irq_flow_is_state_contamination():
    verdict = check(case('F2', irq_takes=1))
    assert verdict['failure_class'] == 'state_contamination'
    assert 'previous case' in verdict['detail']


def test_a_target_read_inside_a_store_only_case_is_state_contamination():
    verdict = check(case('F4', target_reads=1))
    assert verdict['failure_class'] == 'state_contamination'
    assert 'store-only' in verdict['detail']
    # APB3 prints the same counter as apb_reads.
    apb = check(case('F4', apb_reads=1))
    assert apb['failure_class'] == 'state_contamination'


def test_a_trap_is_an_execution_exception():
    verdict = check(case('F1', traps=1))
    assert verdict['failure_class'] == 'execution_exception'


def test_a_program_that_did_not_retire_every_word_is_an_execution_anomaly():
    verdict = check(case('F1', prog_words=4, prog_retires=3, prog_pc_ordered=1,
                         prog_insns_match=1))
    assert verdict['failure_class'] == 'execution_anomaly'
    assert check(case('F1', prog_words=4, prog_retires=4,
                      prog_pc_ordered=0)).get('failure_class') == 'execution_anomaly'


def test_a_cpu_that_does_not_commit_the_read_is_an_execution_anomaly():
    verdict = check(case('F2', read_value=1, echo_value=2))
    assert verdict['failure_class'] == 'execution_anomaly'


def test_a_target_read_that_differs_from_the_cpu_response_is_a_device_anomaly():
    verdict = check(case('F2', read_value=1, echo_value=1, apb_rdata=2))
    assert verdict['failure_class'] == 'device_anomaly'


def test_a_ram_store_that_did_not_commit_is_a_device_anomaly():
    verdict = check(case('F3', ram_after=0, write_value=5))
    assert verdict['failure_class'] == 'device_anomaly'


def test_a_bus_error_is_a_protocol_error_and_not_a_device_anomaly():
    assert check(case('F4', bus_errors=1))['failure_class'] == 'protocol_error'
    assert check(case('F4', target_resp=2))['failure_class'] == 'protocol_error'


@pytest.mark.parametrize('text,kind', [
    ('case exceeded its tick budget', 'wait_budget_exceeded'),
    ('CPU data access outside RAM and the declared target windows', 'protocol_error'),
    ('target answered without a completed request', 'protocol_error'),
    ('AXI4-Lite write did not complete AW, W and B exactly once', 'protocol_error'),
    ('could not generate a legal F5 input', 'host_abort'),
])
def test_the_last_host_line_is_classified(text, kind):
    assert classify_host_failure(text)['kind'] == kind
    assert classify_host_failure(text)['message'] == text


def test_the_recovery_scope_is_device_only_and_states_what_is_retained():
    config = {'source_timing': {'reset_assert_ticks': 2},
              'dma_timing': {'reset_assert_ticks': 8}}
    irq = {'port': 'irq'}
    dma = {'control_offset': 0}
    doc = recovery_declaration(config, irq=irq, dma=dma, pins=None, bus='obi')
    assert doc['cpu_reset'] is False and doc['ram_reset'] is False
    assert doc['scope'].startswith('ip and dma reset only')
    assert doc['ip_reset_assert_ticks'] == 2
    assert doc['dma_reset_assert_ticks'] == 8
    assert any('CPU program counter' in item for item in doc['retained'])
    assert any('device configuration' in item for item in doc['consequences'])
    assert doc['pad_model'] is None
    no_dma = recovery_declaration(config, irq=irq, dma=None, pins=None, bus='obi')
    assert no_dma['dma_reset_assert_ticks'] is None
    assert no_dma['cpu_reset'] is False


def test_the_recovery_pad_model_is_reported_only_for_a_pin_target():
    config = {'source_timing': {'reset_assert_ticks': 2}}
    doc = recovery_declaration(config, irq={'port': 'interrupt'}, dma=None,
                               pins={'padin_offset': 8, 'width': 32}, bus='obi')
    assert 'resampled' in doc['pad_model']


def test_classification_rejects_a_non_case_dict():
    with pytest.raises(ValueError):
        classify_case([])
    with pytest.raises(ValueError):
        classify_case({'flow': 'F9', 'status': 'failed'})
