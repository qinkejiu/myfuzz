"""Independent observations for the Ibex → PULP SPI → Ibex data path."""
from __future__ import annotations

from copy import deepcopy
import unittest

from myfuzz.scenario.checker import check_pulp_spi_rx_chain


def _trace():
    tx = lambda sequence: dict(execution_id='x', testcase_id='case',
        source_component='cpu', source_epoch=0, channel_id='data',
        source_sequence=sequence)
    return [
        dict(event_id=1, kind='mmio_delivery', component='cpu', device_id='spi',
             offset=4, write=True, byte_enable=15, write_value=1,
             source_transaction=tx(1)),
        dict(event_id=2, kind='mmio_delivery', component='cpu', device_id='spi',
             offset=0x10, write=True, byte_enable=15, write_value=0x00200000,
             source_transaction=tx(2)),
        dict(event_id=3, kind='mmio_delivery', component='cpu', device_id='spi',
             offset=0, write=True, byte_enable=15, write_value=0x101,
             source_transaction=tx(3)),
        dict(event_id=4, component='spi', local_tick=154,
             outputs={'events_o': 2, 'spi_sample_count': 32}),
        dict(event_id=5, kind='mmio_delivery', component='cpu', device_id='spi',
             offset=0x20, write=False, read_value=0xa5c396f0,
             byte_enable=15, source_transaction=tx(4)),
        dict(event_id=6, component='cpu', outputs={
            'data_rsp_consumed': 1, 'data_rsp_source_epoch': 0,
            'data_rsp_source_sequence': 4, 'data_rsp_rdata': 0xa5c396f0}),
        dict(event_id=7, kind='memory_write', component='cpu',
             address=0x20000, value=0xa5c396f0, byte_enable=15,
             transaction=tx(5)),
    ]


class PulpSpiRxCheckerTests(unittest.TestCase):
    def test_accepts_observed_transfer_and_cpu_store(self):
        result = check_pulp_spi_rx_chain(_trace(), expected_word=0xa5c396f0)
        self.assertTrue(result['complete'], result)
        self.assertEqual(7, result['endpoint_event_id'])

    def test_reports_wrong_real_rxfifo_data_as_violation(self):
        events = _trace()
        events[4]['read_value'] ^= 1
        result = check_pulp_spi_rx_chain(events, expected_word=0xa5c396f0)
        self.assertIn('spi_rxfifo_data_mismatch', result['dut_violations'])

    def test_missing_real_transfer_is_incomplete_not_dut_violation(self):
        events = [event for event in _trace() if event['event_id'] != 4]
        result = check_pulp_spi_rx_chain(events, expected_word=0xa5c396f0)
        self.assertFalse(result['complete'])
        self.assertIn('spi_eot_missing', result['path_incomplete'])
        self.assertNotIn('spi_rxfifo_data_mismatch', result['dut_violations'])

    def test_cpu_response_cannot_overwrite_spi_read_data(self):
        events = deepcopy(_trace())
        events[5]['outputs']['data_rsp_rdata'] ^= 1
        result = check_pulp_spi_rx_chain(events, expected_word=0xa5c396f0)
        self.assertIn('cpu_spi_response_mismatch', result['dut_violations'])


if __name__ == '__main__':
    unittest.main()
