"""A witnessed UART read must expose a copied CPU response fault."""

from __future__ import annotations

import unittest

from myfuzz.scenario.ibex_uart_online_checker import IbexUartOnlineChecker
from myfuzz.scenario.session_runtime import OnlineCaseReceipt, _checker_identity


def receipt(case_id, events):
    return OnlineCaseReceipt(case_id, 0, len(events), tuple(events), {}, {}, "running")


def read_events():
    return (
        {"event_id": 1, "kind": "source_injection", "component": "uart",
         "port": "uart_rx_byte", "bit_offset": 0, "width": 8, "value": 0x5a},
        {"event_id": 2, "kind": "mmio_delivery", "device_id": "uart",
         "offset": 0x18, "write": False, "read_value": 0x5a,
         "source_transaction": {"source_epoch": 0, "source_sequence": 5}},
        {"event_id": 3, "component": "cpu", "kind": None,
         "outputs": {"data_rsp_consumed": 1, "data_rsp_source_epoch": 0,
                     "data_rsp_source_sequence": 5, "data_rsp_rdata": 0x5a}},
    )


class ControlledUartReadFaultTest(unittest.TestCase):
    def test_matched_read_fault_is_found_without_changing_raw_events(self):
        from myfuzz.scenario.p5_controlled_uart_fault import ControlledUartReadFaultChecker

        events = read_events()
        self.assertEqual(IbexUartOnlineChecker()(receipt("case", events)), ())
        checker = ControlledUartReadFaultChecker()
        self.assertEqual(checker(receipt("case", events)),
                         ("cpu_uart_rxdata_response_mismatch",))
        self.assertEqual(events[2]["outputs"]["data_rsp_rdata"], 0x5a)
        self.assertEqual(checker.fault["read_event_id"], 2)
        self.assertEqual(checker.fault["cpu_response_event_id"], 3)
        self.assertEqual(checker.fault["original_rdata"], 0x5a)
        self.assertEqual(checker.fault["checker_input_rdata"], 0x5b)

    def test_without_matching_read_no_fault_is_injected(self):
        from myfuzz.scenario.p5_controlled_uart_fault import ControlledUartReadFaultChecker

        events = (read_events()[0], read_events()[2])
        checker = ControlledUartReadFaultChecker()
        self.assertEqual(checker(receipt("case", events)), ())
        self.assertIsNone(checker.fault)

    def test_config_identity_is_stable_after_fault(self):
        from myfuzz.scenario.p5_controlled_uart_fault import ControlledUartReadFaultChecker

        checker = ControlledUartReadFaultChecker()
        before = _checker_identity(checker)
        checker(receipt("case", read_events()))
        self.assertEqual(before, _checker_identity(ControlledUartReadFaultChecker()))
        self.assertEqual(before["config"]["fault_mode"],
                         "checker_input_cpu_uart_rxdata_xor1.v1")


if __name__ == "__main__":
    unittest.main()
