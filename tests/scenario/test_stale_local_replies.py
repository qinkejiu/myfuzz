"""Late process replies cannot bind to a new local execution."""

from __future__ import annotations

from io import StringIO
from types import SimpleNamespace
import unittest

from myfuzz.scenario.gpio_session import OpenTitanGpioSession
from myfuzz.scenario.ibex_session import IbexCpuSession
from myfuzz.scenario.cva6_session import Cva6CpuSession
from myfuzz.scenario.uart_session import OpenTitanUartSession


class ReplyStream:
    def __init__(self, *lines):
        self.lines = list(lines)
        self.reads = 0

    def readline(self):
        self.reads += 1
        return self.lines.pop(0) if self.lines else ""


class MemoryClock:
    def advance_step(self):
        pass


def prepared_session(kind, lines):
    stream = ReplyStream(*lines)
    process = SimpleNamespace(poll=lambda: None, stdin=StringIO(), stdout=stream)
    if kind == "gpio":
        session = OpenTitanGpioSession()
        session._tick_base = 0
    elif kind == "uart":
        session = OpenTitanUartSession()
    elif kind == "ibex":
        session = object.__new__(IbexCpuSession)
        session._pending_instr = None
        session._pending_data = None
        session._quiescing = False
        session.memory = MemoryClock()
        session.local_ticks = 0
        session.reset_epoch = 0
    else:
        session = object.__new__(Cva6CpuSession)
        session._pending = None
        session._quiescing = False
        session.memory = MemoryClock()
        session.local_ticks = 0
    session._process = process
    session._wire_execution = "current"
    session._command_sequence = 0
    return session, stream


def result_line(kind, execution="current", sequence="1"):
    if kind == "gpio":
        return f"RESULT {execution} {sequence} 33 0 0 0 0 1\n"
    if kind == "uart":
        return f"RESULT {execution} {sequence} 1 0 0 0 1 0 0 1\n"
    if kind == "ibex":
        return (f"RESULT {execution} {sequence} "
                + " ".join(["0"] * 14) + f" {sequence}\n")
    return (f"RESULT {execution} {sequence} "
            + " ".join(["0"] * 6) + f" {sequence}\n")


class StaleLocalReplyTests(unittest.TestCase):
    def _step(self, kind, session):
        if kind == "gpio":
            return session._command()
        if kind == "uart":
            return session.step_local({"uart_rx": 1})
        return session.step_local({"irq": 0})

    def test_old_reply_is_skipped_then_current_reply_applies_once(self):
        for kind in ("gpio", "uart", "ibex", "cva6"):
            with self.subTest(kind=kind):
                session, stream = prepared_session(
                    kind, (result_line(kind, "old"), result_line(kind)))
                output = self._step(kind, session)
                self.assertEqual(2, stream.reads)
                self.assertEqual(1, session.local_ticks)
                self.assertEqual(1, session._command_sequence)
                if kind == "gpio":
                    self.assertEqual(0x33, output["gpio_out"])

    def test_eof_after_stale_reply_is_classified_as_lost_reply(self):
        for kind in ("gpio", "uart", "ibex", "cva6"):
            with self.subTest(kind=kind):
                session, _stream = prepared_session(kind, (result_line(kind, "old"),))
                with self.assertRaisesRegex(RuntimeError, "lost_reply"):
                    self._step(kind, session)
                self.assertEqual(0, session.local_ticks)

    def test_stale_reply_budget_is_bounded(self):
        for kind in ("gpio", "uart", "ibex", "cva6"):
            with self.subTest(kind=kind):
                session, stream = prepared_session(
                    kind, tuple(result_line(kind, "old") for _ in range(9))
                    + (result_line(kind),))
                with self.assertRaisesRegex(RuntimeError, "stale_execution"):
                    self._step(kind, session)
                self.assertEqual(9, stream.reads)
                self.assertEqual(0, session.local_ticks)

    def test_eight_stale_replies_still_allow_current_result(self):
        for kind in ("gpio", "uart", "ibex", "cva6"):
            with self.subTest(kind=kind):
                session, stream = prepared_session(
                    kind, tuple(result_line(kind, "old") for _ in range(8))
                    + (result_line(kind),))
                self._step(kind, session)
                self.assertEqual(9, stream.reads)
                self.assertEqual(1, session.local_ticks)


if __name__ == "__main__":
    unittest.main()
