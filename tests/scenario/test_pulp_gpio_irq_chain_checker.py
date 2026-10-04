"""PULP GPIO checker reports incomplete paths separately from RTL violations."""
from __future__ import annotations

import unittest
from copy import deepcopy

from myfuzz.scenario import checker


def _events():
    return (
        {'event_id': 1, 'kind': 'mmio_delivery', 'component': 'cpu',
         'device_id': 'gpio_b', 'offset': 4, 'write': True, 'write_value': 0xff},
        {'event_id': 2, 'kind': 'mmio_delivery', 'component': 'cpu',
         'device_id': 'gpio_b', 'offset': 0x18, 'write': True, 'write_value': 1},
        {'event_id': 3, 'kind': 'mmio_delivery', 'component': 'cpu',
         'device_id': 'gpio_b', 'offset': 0x1c, 'write': True, 'write_value': 1},
        {'event_id': 4, 'kind': 'mmio_delivery', 'component': 'cpu',
         'device_id': 'gpio_a', 'offset': 0x0c, 'write': True,
         'write_value': 3, 'byte_enable': 15},
        {'event_id': 5, 'component': 'gpio_a', 'local_tick': 5,
         'outputs': {'gpio_out': 3}},
        {'event_id': 6, 'kind': 'dataflow_delivery',
         'source': ('gpio_a', 'gpio_out'), 'target': ('gpio_b', 'gpio_in'),
         'value': 3, 'producer_event_id': 5},
        {'event_id': 7, 'component': 'gpio_b', 'inputs': {'gpio_in': 3},
         'outputs': {'irq': 1}},
        {'event_id': 8, 'kind': 'source_start', 'source': ('gpio_b', 'irq'),
         'target': ('cpu', 'irq')},
        {'event_id': 9, 'kind': 'pulse_start', 'source': ('gpio_b', 'irq'),
         'target': ('cpu', 'irq'), 'start_cpu_tick': 4, 'end_cpu_tick_exclusive': 8},
        {'event_id': 10, 'component': 'cpu', 'inputs': {'irq': 1},
         'outputs': {'instr_req_accepted': 0}},
        {'event_id': 11, 'component': 'cpu', 'inputs': {'irq': 1},
         'outputs': {'instr_req_accepted': 1, 'instr_addr': 0x1012c}},
        {'event_id': 12, 'kind': 'mmio_delivery', 'component': 'cpu',
         'device_id': 'gpio_b', 'offset': 8, 'write': False,
         'read_value': 3, 'source_transaction': {'source_epoch': 0,
                                                'source_sequence': 7}},
        {'event_id': 13, 'component': 'cpu',
         'outputs': {'data_rsp_consumed': 1, 'data_rsp_rdata': 3,
                     'data_rsp_source_epoch': 0,
                     'data_rsp_source_sequence': 7}},
        {'event_id': 14, 'kind': 'memory_write', 'component': 'cpu',
         'address': 0x20000, 'value': 3, 'byte_enable': 15},
        {'event_id': 15, 'kind': 'mmio_delivery', 'component': 'cpu',
         'device_id': 'gpio_b', 'offset': 0x24, 'write': False,
         'read_value': 1},
        {'event_id': 16, 'kind': 'memory_write', 'component': 'cpu',
         'address': 0x20004, 'value': 1, 'byte_enable': 15},
    )


def _configured_events():
    events = deepcopy(list(_events()))
    for event in events:
        if event['event_id'] >= 4:
            event['event_id'] += 1
        if event.get('producer_event_id', 0) >= 4:
            event['producer_event_id'] += 1
    events.insert(3, {'event_id': 4, 'kind': 'mmio_delivery',
                      'component': 'cpu', 'device_id': 'gpio_a',
                      'offset': 0, 'write': True, 'write_value': 0xff,
                      'byte_enable': 15})
    events[4]['source_transaction'] = {
        'execution_id': 'fixture', 'testcase_id': 'fixture',
        'source_component': 'cpu', 'source_epoch': 0,
        'channel_id': 'data', 'source_sequence': 4}
    events[12]['source_transaction'].update({
        'execution_id': 'fixture', 'testcase_id': 'fixture',
        'source_component': 'cpu', 'channel_id': 'data'})
    events[14]['transaction'] = {
        'execution_id': 'fixture', 'testcase_id': 'fixture',
        'source_component': 'cpu', 'source_epoch': 0,
        'channel_id': 'data', 'source_sequence': 8}
    return events


class PulpGpioIrqCheckerTests(unittest.TestCase):
    def test_complete_real_chain_shape(self):
        report = checker.check_pulp_gpio_irq_chain(_configured_events(), expected_value=3)
        self.assertTrue(report['complete'], report)
        self.assertEqual([], report['dut_violations'])
        self.assertEqual([], report['path_incomplete'])

    def test_missing_isr_is_incomplete_not_dut_bug(self):
        report = checker.check_pulp_gpio_irq_chain(_configured_events()[:11], expected_value=3)
        self.assertFalse(report['complete'])
        self.assertTrue(report['path_incomplete'])
        self.assertEqual([], report['dut_violations'])

    def test_corrupted_observed_output_is_a_violation(self):
        events = _configured_events()
        events[5] = {'event_id': 6, 'component': 'gpio_a', 'local_tick': 5,
                     'outputs': {'gpio_out': 0}}
        for event in events[6:]:
            event['event_id'] += 4
        events[6:6] = ({'event_id': 7 + index, 'component': 'gpio_a',
                        'local_tick': 6 + index, 'outputs': {'gpio_out': 0}}
                       for index in range(4))
        report = checker.check_pulp_gpio_irq_chain(events, expected_value=3)
        self.assertIn('gpio_a_output_mismatch', report['dut_violations'])

    def test_missing_a_pad_direction_is_incomplete(self):
        events = [event for event in _configured_events()
                  if not (event.get('device_id') == 'gpio_a'
                          and event.get('offset') == 0)]
        report = checker.check_pulp_gpio_irq_chain(events, expected_value=3)
        self.assertIn('gpio_a_direction_missing', report['path_incomplete'])
        self.assertEqual([], report['dut_violations'])

    def test_bound_cpu_response_value_mismatch_is_violation(self):
        events = _configured_events()
        events[13]['outputs']['data_rsp_rdata'] = 2
        report = checker.check_pulp_gpio_irq_chain(events, expected_value=3)
        self.assertIn('cpu_padin_response_mismatch', report['dut_violations'])

    def test_cpu_ram_store_value_mismatch_is_violation(self):
        events = _configured_events()
        events[14]['value'] = 2
        report = checker.check_pulp_gpio_irq_chain(events, expected_value=3)
        self.assertIn('cpu_padin_store_mismatch', report['dut_violations'])

    def test_repeated_a_padout_transaction_is_integrity_failure(self):
        events = _configured_events()
        duplicate = deepcopy(events[4])
        duplicate['event_id'] = events[-1]['event_id'] + 1
        events.append(duplicate)
        report = checker.check_pulp_gpio_irq_chain(events, expected_value=3)
        self.assertIn('gpio_a_padout_transaction_reused', report['path_incomplete'])

    def test_unrelated_ram_store_does_not_count_as_cpu_result(self):
        events = _configured_events()
        unrelated = deepcopy(events[14])
        unrelated['value'] = 2
        unrelated['transaction']['testcase_id'] = 'other-testcase'
        unrelated['event_id'] = events[14]['event_id']
        for event in events[14:]:
            event['event_id'] += 1
        events.insert(14, unrelated)
        report = checker.check_pulp_gpio_irq_chain(events, expected_value=3)
        self.assertTrue(report['complete'], report)

    def test_unidentified_response_is_incomplete_not_data_mismatch(self):
        events = _configured_events()
        events[12]['source_transaction'].pop('source_sequence')
        events[13]['outputs']['data_rsp_rdata'] = 2
        report = checker.check_pulp_gpio_irq_chain(events, expected_value=3)
        self.assertIn('gpio_b_padin_transaction_missing', report['path_incomplete'])
        self.assertNotIn('cpu_padin_response_mismatch', report['dut_violations'])


if __name__ == '__main__':
    unittest.main()
