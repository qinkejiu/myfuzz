"""Pure construction and observed-result checks for the UART online pilot."""

import unittest

from myfuzz.scenario.ibex_uart_online import (
    make_ibex_uart_online_bootstrap, make_ibex_uart_online_decoder,
    uart_online_advances, UART_RX_READY_TICKS, UART_ISR_CPU_TICKS)
from myfuzz.scenario.ibex_uart_online_checker import IbexUartOnlineChecker
from myfuzz.scenario.session_runtime import OnlineCaseReceipt
from myfuzz.scenario.rv32i_sources import mutate_mmio_access


def _receipt(case_id, events):
    return OnlineCaseReceipt(case_id, 0, events[-1]["event_id"], tuple(events),
                             {"cpu": 0, "uart": 0},
                             {"cpu": 0, "uart": 0}, "running")


class IbexUartOnlinePilotTests(unittest.TestCase):
    def test_bootstrap_and_decoder_declare_both_upstream_sources(self):
        bootstrap = make_ibex_uart_online_bootstrap()
        decoder = make_ibex_uart_online_decoder(bootstrap=bootstrap)
        self.assertEqual(("uart", "cpu"), bootstrap.template.schedule_order)
        self.assertEqual({"instruction", "source"},
                         {source.kind for source in decoder.sources})
        self.assertEqual(("CPU_TO_IP", "IP_TO_CPU"),
                         tuple(source.direction for source in decoder.sources))
        self.assertEqual(96, len(decoder.advances))
        self.assertEqual(96, len(uart_online_advances("cpu")))
        self.assertEqual(UART_RX_READY_TICKS + UART_ISR_CPU_TICKS,
                         len(uart_online_advances("rx")))
        self.assertEqual(UART_RX_READY_TICKS + UART_ISR_CPU_TICKS,
                         len(uart_online_advances("warmup")))
        self.assertEqual(0x4000001c, decoder.windows[0].base)
        self.assertFalse(bootstrap.template.actions)

    def test_cpu_txdata_mutation_uses_one_legal_fuzzer_byte(self):
        decoder = make_ibex_uart_online_decoder(
            bootstrap=make_ibex_uart_online_bootstrap())
        case = decoder.decode(bytes((1, 0, 0, 3, 0xa6, 0xff, 0xff, 0xff)))
        words = [int.from_bytes(case.source.data[index:index + 4], "little")
                 for index in range(0, len(case.source.data), 4)]
        self.assertEqual(4, len(words))
        self.assertEqual(0xa6, (words[0] & 0xfffff000)
                         + ((words[1] >> 20) & 0xfff))
        self.assertEqual(0x4000001c, (words[2] & 0xfffff000)
                         + (((words[3] >> 25) << 5) | ((words[3] >> 7) & 31)))
        decoder.commit(case)

    def test_uart_wdata_byte_store_requires_explicit_opt_in(self):
        bootstrap = make_ibex_uart_online_bootstrap()
        default = make_ibex_uart_online_decoder(bootstrap=bootstrap)
        opted = make_ibex_uart_online_decoder(
            bootstrap=bootstrap, uart_wdata_byte_store=True)
        raw = bytes((1, 0, 0, 3, 0xa6, 0xff, 0xff, 0xff))
        default_case = default.decode(raw)
        opted_case = opted.decode(raw)
        default_word = int.from_bytes(default_case.source.data[-4:], 'little')
        opted_word = int.from_bytes(opted_case.source.data[-4:], 'little')
        self.assertEqual(2, (default_word >> 12) & 7)  # SW
        self.assertEqual(0, (opted_word >> 12) & 7)    # SB
        self.assertEqual((1,), opted.windows[0].write_widths)
        self.assertEqual(('SB',), opted.allowed_mmio_operations)

    def test_uart_byte_store_window_selects_only_wdata_lane_zero(self):
        decoder = make_ibex_uart_online_decoder(
            bootstrap=make_ibex_uart_online_bootstrap(),
            uart_wdata_byte_store=True)
        self.assertEqual(1, decoder.windows[0].size)
        for selector in range(16):
            fragment = mutate_mmio_access(
                'SB', bytes((selector, selector, 0, 0)),
                windows=decoder.windows, base_register=1, data_register=2)
            self.assertEqual(0x4000001c, fragment[0].immediate << 12
                             | (fragment[1].immediate & 0xfff))

    def test_uart_rx_schedule_advances_peer_before_cpu_handler(self):
        decoder = make_ibex_uart_online_decoder(
            bootstrap=make_ibex_uart_online_bootstrap())
        # Path selection now mixes the whole input entropy, including the
        # source byte. This value selects the declared IP-to-CPU path.
        case = decoder.decode(bytes((0, 1, 1, 0, 0x5a, 0, 0, 0)))
        self.assertEqual("IP_TO_CPU", case.direction)
        self.assertTrue(all(advance.schedule == ("uart",)
                            for advance in case.advances[:UART_RX_READY_TICKS]))
        self.assertTrue(all(advance.schedule == ("uart", "cpu")
                            for advance in case.advances[UART_RX_READY_TICKS:]))
        self.assertLessEqual(sum(len(advance.schedule)
                                 for advance in case.advances),
                             decoder.max_steps)
        self.assertEqual("ibex_uart_local_schedule.v1",
                         decoder.document()["uart_local_schedule"]["schema_version"])

    def test_checker_keeps_rx_fifo_order_across_cases(self):
        checker = IbexUartOnlineChecker()
        first = _receipt("one", [{"event_id": 1, "kind": "source_injection",
                                  "component": "uart", "port": "uart_rx_byte",
                                  "bit_offset": 0, "width": 8, "value": 0x5a}])
        self.assertEqual((), checker(first))
        second = _receipt("two", [
            {"event_id": 2, "kind": "mmio_delivery", "device_id": "uart",
             "offset": 0x18, "write": False, "read_value": 0x5a,
             "source_transaction": {"source_epoch": 0, "source_sequence": 1}},
            {"event_id": 3, "kind": None, "component": "cpu",
             "outputs": {"data_rsp_consumed": 1, "data_rsp_source_epoch": 0,
                         "data_rsp_source_sequence": 1, "data_rsp_rdata": 0x5a}}])
        self.assertEqual((), checker(second))
        self.assertEqual((), checker(second))

    def test_checker_reports_real_uart_read_and_cpu_response_mismatch(self):
        checker = IbexUartOnlineChecker()
        events = [
            {"event_id": 1, "kind": "source_injection", "component": "uart",
             "port": "uart_rx_byte", "bit_offset": 0, "width": 8,
             "value": 0xa6},
            {"event_id": 2, "kind": "mmio_delivery", "device_id": "uart",
             "offset": 0x18, "write": False, "read_value": 0x5a,
             "source_transaction": {"source_epoch": 0, "source_sequence": 1}},
            {"event_id": 3, "kind": None, "component": "cpu",
             "outputs": {"data_rsp_consumed": 1, "data_rsp_source_epoch": 0,
                         "data_rsp_source_sequence": 1, "data_rsp_rdata": 0}}]
        self.assertEqual(("uart_rxdata_source_mismatch",
                          "cpu_uart_rxdata_response_mismatch"),
                         checker(_receipt("case", events)))


if __name__ == "__main__":
    unittest.main()
