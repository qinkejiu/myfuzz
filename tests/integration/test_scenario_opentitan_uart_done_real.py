"""Pinned OpenTitan UART provides a real IRQ before its real TX_DONE event."""

import os
import unittest
from unittest.mock import patch

from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.gpio_session import OpenTitanGpioSession
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.protocol_io import LocalCommandDeadlineExceeded
from myfuzz.scenario.runner import Binding, ScenarioBudgetExhausted, ScenarioRunner


def _three_device_runner():
    from myfuzz.scenario.uart_session import OpenTitanUartSession

    gpio_a, gpio_b = OpenTitanGpioSession(), OpenTitanGpioSession()
    uart = OpenTitanUartSession()
    ownership = compile_ownership(
        (InputField("gpio_a", "gpio_in", 32),
         InputField("gpio_b", "gpio_in", 32),
         InputField("uart", "uart_rx", 1)),
        (InputOwner("gpio_a", "gpio_in", 0, 32, "source", "external_a"),
         InputOwner("gpio_b", "gpio_in", 0, 1, "bound", "gpio_a.gpio_out"),
         InputOwner("gpio_b", "gpio_in", 1, 31, "fixed", "constant_zero"),
         InputOwner("uart", "uart_rx", 0, 1, "source", "external_uart_rx")))
    runner = ScenarioRunner(
        sessions={"gpio_a": gpio_a, "gpio_b": gpio_b, "uart": uart},
        ownership=ownership,
        bindings=(Binding("gpio_a", "gpio_out", "gpio_b", "gpio_in", 1),))
    return gpio_a, gpio_b, uart, runner


def _start_bound_gpio_and_uart_tx(gpio_a, gpio_b, uart, runner):
    gpio_b.write_register(0x04, 1)
    gpio_b.write_register(0x2c, 1)
    gpio_a.write_register(0x14, 1)
    uart.write_register(0x10, (0x2000 << 16) | 1)
    uart.write_register(0x1c, 0xa5)
    uart.write_register(0x04, 0b100)
    runner.step("gpio_a")


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealOpenTitanUartDoneTests(unittest.TestCase):
    def test_quiesce_keeps_two_real_devices_pending_after_bound_delivery(self):
        gpio_a, gpio_b, uart, runner = _three_device_runner()
        runner.begin_test("gpio-bound-and-uart-pending")
        try:
            _start_bound_gpio_and_uart_tx(gpio_a, gpio_b, uart, runner)
            self.assertEqual(1, uart.pending_events)
            self.assertEqual(("gpio_b",), runner.final_state_document()[
                "pending_dataflow_targets"])
            outcome = runner.quiesce(2)
            self.assertEqual("incomplete", outcome.status)
            self.assertEqual(2, outcome.steps)
            self.assertGreater(gpio_b.pending_events, 0)
            self.assertEqual(1, uart.pending_events)
            ending = [event for event in runner.events
                      if event.get("kind") == "quiesce_end"][-1]
            self.assertGreater(ending["pending_events"]["gpio_b"], 0)
            self.assertEqual(1, ending["pending_events"]["uart"])
            self.assertEqual((), ending["pending_dataflow_targets"])
            self.assertTrue(any(event.get("component") == "gpio_b"
                                and event.get("inputs", {}).get("gpio_in") & 1
                                for event in runner.events))
            self.assertFalse(any(event.get("component") == "uart"
                                 and event.get("outputs", {}).get("tx_done") == 1
                                 for event in runner.events))
        finally:
            runner.finalize()

    def test_lost_real_gpio_reply_during_two_device_quiesce_is_uncertain(self):
        gpio_a, gpio_b, uart, runner = _three_device_runner()
        runner.begin_test("gpio-reply-lost-uart-pending")
        try:
            _start_bound_gpio_and_uart_tx(gpio_a, gpio_b, uart, runner)
            observed_replies = []
            real_readline = gpio_b._line_reader.readline

            def consume_accepted_reply(stream):
                observed_replies.append(real_readline(stream))
                return ""

            with patch.object(gpio_b._line_reader, "readline",
                              side_effect=consume_accepted_reply):
                with self.assertRaisesRegex(RuntimeError, "lost_reply"):
                    runner.quiesce(2)
            self.assertEqual(1, len(observed_replies))
            self.assertTrue(observed_replies[0].startswith(
                "RESULT " + gpio_b._wire_execution + " "))
            self.assertEqual("uncertain_effect", runner.failure_status)
            self.assertEqual(1, uart.pending_events)
            self.assertEqual(("gpio_b",), runner.final_state_document()[
                "pending_dataflow_targets"])
            self.assertTrue(any(event.get("kind") == "harness_failure"
                                and event.get("component") == "gpio_b"
                                for event in runner.events))
            self.assertTrue(any(event.get("kind") == "quiesce_failure"
                                for event in runner.events))
            self.assertFalse(any(event.get("component") == "uart"
                                 and event.get("outputs", {}).get("tx_done") == 1
                                 for event in runner.events))
            with self.assertRaisesRegex(RuntimeError, "scenario is not running"):
                runner.reset_all("warm_all")
            self.assertEqual(1, uart.pending_events)
        finally:
            runner.finalize()

    def test_scheduler_budget_cuts_two_real_pending_devices_before_uart_step(self):
        gpio_a, gpio_b, uart, runner = _three_device_runner()
        runner.set_resource_budget(ResourceBudget(max_scheduler_steps=32))
        runner.begin_test("gpio-and-uart-budget-cut")
        try:
            _start_bound_gpio_and_uart_tx(gpio_a, gpio_b, uart, runner)
            self.assertEqual(6, runner.local_ticks["gpio_a"])
            self.assertEqual(31, sum(runner.local_ticks.values()))
            with self.assertRaises(ScenarioBudgetExhausted):
                runner.quiesce(2)
            self.assertEqual("budget_exhausted", runner.failure_status)
            self.assertEqual("max_scheduler_steps", runner.events[-1]["limit"])
            self.assertEqual("before_step", runner.events[-1]["phase"])
            self.assertGreater(gpio_b.pending_events, 0)
            self.assertEqual(1, uart.pending_events)
            self.assertEqual(15, runner.local_ticks["uart"])
            self.assertFalse(any(event.get("component") == "uart"
                                 and "outputs" in event for event in runner.events))
        finally:
            runner.finalize()

    def test_real_gpio_reply_timeout_preserves_other_pending_uart(self):
        gpio_a, gpio_b, uart, runner = _three_device_runner()
        runner.set_resource_budget(ResourceBudget(max_wall_time_ms=500))
        runner.begin_test("gpio-reply-timeout-uart-pending")
        original_stdout = None
        blocked_write_fd = None
        try:
            _start_bound_gpio_and_uart_tx(gpio_a, gpio_b, uart, runner)
            original_stdout = gpio_b._process.stdout
            blocked_read_fd, blocked_write_fd = os.pipe()
            gpio_b._process.stdout = os.fdopen(
                blocked_read_fd, "r", encoding="ascii", buffering=1)
            with self.assertRaises(LocalCommandDeadlineExceeded):
                runner.quiesce(2)
            self.assertEqual("budget_exhausted", runner.failure_status)
            self.assertEqual("max_wall_time_ms", runner.events[-1]["limit"])
            self.assertEqual("inflight_step", runner.events[-1]["phase"])
            self.assertTrue(runner.events[-1]["effect_may_have_occurred"])
            self.assertTrue(any(event.get("kind") == "harness_failure"
                                and event.get("component") == "gpio_b"
                                and event.get("error_type") ==
                                "LocalCommandDeadlineExceeded"
                                for event in runner.events))
            self.assertEqual({"gpio_b": gpio_b.pending_events,
                              "uart": 1}, runner.final_state_document()[
                                  "pending_events"])
            self.assertEqual(1, uart.pending_events)
        finally:
            runner.finalize()
            if blocked_write_fd is not None:
                os.close(blocked_write_fd)
            if original_stdout is not None:
                original_stdout.close()

    def test_local_cycle_budget_truncates_real_pending_uart_quiesce(self):
        from myfuzz.scenario.uart_session import OpenTitanUartSession

        uart = OpenTitanUartSession()
        ownership = compile_ownership(
            (InputField("uart", "uart_rx", 1),),
            (InputOwner("uart", "uart_rx", 0, 1, "source",
                        "external_uart_rx"),))
        runner = ScenarioRunner(sessions={"uart": uart}, ownership=ownership,
                                bindings=())
        runner.set_resource_budget(ResourceBudget(max_local_cycles_per_component=17))
        runner.begin_test("uart-budgeted-quiesce")
        try:
            uart.write_register(0x10, (0x2000 << 16) | 1)
            uart.write_register(0x1c, 0xa5)
            uart.write_register(0x04, 0b100)
            self.assertEqual(15, uart.local_ticks)
            with self.assertRaises(ScenarioBudgetExhausted):
                runner.quiesce(1500)
            self.assertEqual("budget_exhausted", runner.failure_status)
            self.assertEqual("max_local_cycles_per_component",
                             runner.events[-1]["limit"])
            self.assertEqual("before_step", runner.events[-1]["phase"])
            self.assertEqual(1, uart.pending_events)
            self.assertEqual(17, runner.local_ticks["uart"])
        finally:
            runner.finalize()

    def test_short_quiesce_keeps_real_pending_tx_and_finalize_is_idempotent(self):
        from myfuzz.scenario.uart_session import OpenTitanUartSession

        uart = OpenTitanUartSession()
        ownership = compile_ownership(
            (InputField("uart", "uart_rx", 1),),
            (InputOwner("uart", "uart_rx", 0, 1, "source",
                        "external_uart_rx"),))
        runner = ScenarioRunner(sessions={"uart": uart}, ownership=ownership,
                                bindings=())
        runner.begin_test("uart-short-quiesce")
        try:
            uart.write_register(0x10, (0x2000 << 16) | 1)
            uart.write_register(0x1c, 0xa5)
            uart.write_register(0x04, 0b100)
            self.assertEqual(1, uart.pending_events)
            outcome = runner.quiesce(2)
            self.assertEqual("incomplete", outcome.status)
            self.assertEqual(2, outcome.steps)
            self.assertEqual(1, uart.pending_events)
            self.assertEqual({"uart": 1}, runner.final_state_document()[
                "pending_events"])
            ending = [event for event in runner.events
                      if event.get("kind") == "quiesce_end"]
            self.assertEqual(1, len(ending))
            self.assertEqual({"uart": 1}, ending[0]["pending_events"])
            self.assertFalse(any(event.get("component") == "uart"
                                 and event.get("outputs", {}).get("tx_done") == 1
                                 for event in runner.events))
        finally:
            runner.finalize()
        events_after_first = runner.events
        runner.finalize()
        self.assertEqual(events_after_first, runner.events)
        self.assertIsNone(uart._process)

    def test_warm_reset_cancels_real_inflight_tx_event(self):
        from myfuzz.scenario.uart_session import OpenTitanUartSession

        uart = OpenTitanUartSession()
        ownership = compile_ownership(
            (InputField("uart", "uart_rx", 1),),
            (InputOwner("uart", "uart_rx", 0, 1, "source",
                        "external_uart_rx"),))
        runner = ScenarioRunner(sessions={"uart": uart}, ownership=ownership,
                                bindings=())
        runner.begin_test("uart-reset-inflight")
        try:
            uart.write_register(0x10, (0x2000 << 16) | 1)
            uart.write_register(0x1c, 0xa5)
            runner.step("uart")
            self.assertEqual(1, uart.pending_events)
            runner.reset_all("warm_all")
            barrier = next(e for e in runner.events
                           if e.get("kind") == "reset_barrier")
            self.assertEqual({"uart": 1}, barrier["pending_events_before_reset"])
            self.assertEqual({}, barrier["pending_events_after_reset"])
            self.assertEqual(0, uart.pending_events)
            observed = runner.step("uart")
            self.assertEqual(1, observed["tx_idle"])
            self.assertEqual(0, observed["tx_done"])
            self.assertEqual(0, observed["irq"])
        finally:
            runner.finalize()

    def test_quiesce_ticks_real_uart_until_transmit_is_idle(self):
        from myfuzz.scenario.uart_session import OpenTitanUartSession

        uart = OpenTitanUartSession()
        ownership = compile_ownership(
            (InputField("uart", "uart_rx", 1),),
            (InputOwner("uart", "uart_rx", 0, 1, "source",
                        "external_uart_rx"),))
        runner = ScenarioRunner(sessions={"uart": uart}, ownership=ownership,
                                bindings=())
        runner.begin_test("uart-quiesce-tx")
        try:
            uart.write_register(0x10, (0x2000 << 16) | 1)
            uart.write_register(0x1c, 0xa5)
            uart.write_register(0x04, 0b100)
            self.assertEqual(1, uart.pending_events)
            outcome = runner.quiesce(1500)
            self.assertEqual("drained", outcome.status)
            self.assertGreater(outcome.steps, 1000)
            self.assertEqual(0, uart.pending_events)
            self.assertTrue(any(event.get("component") == "uart"
                                and event.get("outputs", {}).get("tx_done") == 1
                                for event in runner.events))
        finally:
            runner.finalize()

    def test_transmit_irq_can_precede_real_tx_done(self):
        from myfuzz.scenario.uart_session import OpenTitanUartSession

        uart = OpenTitanUartSession()
        uart.begin_case("uart-early-irq")
        try:
            # Slow enough for the FIFO watermark to precede actual TX_DONE.
            uart.write_register(0x10, (0x2000 << 16) | 1)
            uart.write_register(0x1c, 0xa5)
            uart.write_register(0x04, 0b101)
            self.assertGreater(uart.pending_events, 0)
            early_irq = False
            done = False
            for _ in range(1500):
                observed = uart.step_local({"uart_rx": 1})
                self.assertIn("tx_idle", observed)
                if observed["irq"] and not observed["tx_done"]:
                    early_irq = True
                if observed["tx_done"]:
                    done = True
                    break
            self.assertTrue(early_irq, "real UART did not expose IRQ before DONE")
            self.assertTrue(done, "real UART did not complete the transmit")
            self.assertEqual(0, uart.pending_events)
            self.assertEqual(0b100, uart.read_register(0x00) & 0b100)
            uart.write_register(0x00, 0b100)
            self.assertEqual(0, uart.read_register(0x00) & 0b100)
        finally:
            uart.end_case()


if __name__ == "__main__":
    unittest.main()
