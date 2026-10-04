"""External B pin source must reach CPU response and A output in order."""
from __future__ import annotations

import unittest

from myfuzz.scenario import checker


def _stream():
    return [
        {'event_id': 1, 'kind': 'mmio_delivery', 'component': 'cpu',
         'device_id': 'gpio_b', 'offset': 4, 'write': True, 'write_value': 0xff00},
        {'event_id': 2, 'kind': 'mmio_delivery', 'component': 'cpu',
         'device_id': 'gpio_b', 'offset': 0x18, 'write': True, 'write_value': 0x100},
        {'event_id': 3, 'kind': 'mmio_delivery', 'component': 'cpu',
         'device_id': 'gpio_b', 'offset': 0x1c, 'write': True, 'write_value': 0x10000},
        {'event_id': 4, 'kind': 'mmio_delivery', 'component': 'cpu',
         'device_id': 'gpio_a', 'offset': 0, 'write': True, 'write_value': 0xff},
        {'event_id': 5, 'kind': 'source_injection', 'component': 'gpio_b',
         'port': 'gpio_in', 'value': 0x49, 'bit_offset': 8, 'width': 8},
        {'event_id': 6, 'component': 'gpio_b', 'inputs': {'gpio_in': 0x4900},
         'outputs': {'irq': 1}},
        {'event_id': 7, 'kind': 'source_start',
         'source': ('gpio_b', 'irq'), 'target': ('cpu', 'irq')},
        {'event_id': 8, 'kind': 'pulse_start',
         'source': ('gpio_b', 'irq'), 'target': ('cpu', 'irq')},
        {'event_id': 9, 'component': 'cpu', 'inputs': {'irq': 1},
         'outputs': {'instr_req_accepted': 0}},
        {'event_id': 10, 'component': 'cpu', 'inputs': {'irq': 1},
         'outputs': {'instr_req_accepted': 1, 'instr_addr': 0x1012c}},
        {'event_id': 11, 'kind': 'mmio_delivery', 'component': 'cpu',
         'device_id': 'gpio_b', 'offset': 8, 'write': False,
         'read_value': 0x4900,
         'source_transaction': {'source_epoch': 0, 'source_sequence': 5}},
        {'event_id': 12, 'component': 'cpu', 'outputs': {
            'data_rsp_consumed': 1, 'data_rsp_rdata': 0x4900,
            'data_rsp_source_epoch': 0, 'data_rsp_source_sequence': 5}},
        {'event_id': 13, 'kind': 'memory_write', 'component': 'cpu',
         'address': 0x20000, 'value': 0x49, 'byte_enable': 15},
        {'event_id': 14, 'kind': 'mmio_delivery', 'component': 'cpu',
         'device_id': 'gpio_a', 'offset': 0x0c, 'write': True,
         'write_value': 0x49, 'byte_enable': 15},
        {'event_id': 15, 'component': 'gpio_a', 'local_tick': 5,
         'outputs': {'gpio_out': 0x49}},
    ]


class PulpGpioReverseCheckerTests(unittest.TestCase):
    def test_complete_reverse_chain(self):
        report = checker.check_pulp_gpio_reverse_irq_chain(_stream(),
                                                             external_byte=0x49)
        self.assertTrue(report['complete'], report)

    def test_missing_cpu_path_is_not_dut_violation(self):
        report = checker.check_pulp_gpio_reverse_irq_chain(_stream()[:9],
                                                             external_byte=0x49)
        self.assertFalse(report['complete'])
        self.assertTrue(report['path_incomplete'])
        self.assertEqual([], report['dut_violations'])

    def test_wrong_real_padin_response_is_violation(self):
        stream = _stream()
        stream[10]['read_value'] = 0x0900
        report = checker.check_pulp_gpio_reverse_irq_chain(stream,
                                                             external_byte=0x49)
        self.assertIn('gpio_b_padin_read_mismatch', report['dut_violations'])


if __name__ == '__main__':
    unittest.main()
