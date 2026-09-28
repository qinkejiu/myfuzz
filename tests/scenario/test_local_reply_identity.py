"""A delayed reply from an old local execution must not satisfy a new command."""

import io
import unittest

from myfuzz.scenario.gpio_session import OpenTitanGpioSession
from myfuzz.scenario.ibex_session import IbexCpuSession
from myfuzz.scenario.cva6_session import Cva6CpuSession


class _FakeProcess:
    def __init__(self, reply):
        self.stdin = io.StringIO()
        self.stdout = io.StringIO(reply + "\n")

    def poll(self):
        return None


class LocalReplyIdentityTests(unittest.TestCase):
    def test_previous_execution_reply_then_eof_loses_current_reply(self):
        session = OpenTitanGpioSession()
        session._wire_execution = "new-execution"
        # The old wire format had only a sequence. It cannot satisfy the new
        # execution; with no later current reply, stdout EOF means reply loss.
        session._process = _FakeProcess("RESULT 1 0 0 0 0 0 1")
        with self.assertRaisesRegex(RuntimeError, "lost_reply"):
            session.step_local({"gpio_in": 0})
        self.assertEqual(0, session.local_ticks)

    def test_cpu_sessions_report_lost_reply_after_old_result_then_eof(self):
        for session_type in (IbexCpuSession, Cva6CpuSession):
            with self.subTest(session_type=session_type.__name__):
                session = object.__new__(session_type)
                session._wire_execution = "new-execution"
                session._command_sequence = 0
                session._quiescing = False
                session._process = _FakeProcess("RESULT old-execution 1")
                if session_type is IbexCpuSession:
                    session._pending_instr = None
                    session._pending_data = None
                else:
                    session._pending = None
                with self.assertRaisesRegex(RuntimeError, "lost_reply"):
                    session.step_local({"irq": 0})

    def test_explicit_target_error_is_not_reported_as_stale_execution(self):
        session = OpenTitanGpioSession()
        session._wire_execution = "new-execution"
        session._process = _FakeProcess("ERROR invalid command")
        with self.assertRaisesRegex(RuntimeError, "process error: ERROR invalid command"):
            session.step_local({"gpio_in": 0})


if __name__ == "__main__":
    unittest.main()
