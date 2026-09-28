"""A blocked child stdin must not stall a local RTL command or cleanup."""

import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from myfuzz.scenario.cva6_session import Cva6CpuSession
from myfuzz.scenario.gpio_session import OpenTitanGpioSession
from myfuzz.scenario.ibex_session import IbexCpuSession
from myfuzz.scenario.protocol_io import LocalCommandDeadlineExceeded, command_deadline
from myfuzz.scenario.uart_session import OpenTitanUartSession


def _fill_child_stdin(stream):
    descriptor = stream.fileno()
    os.set_blocking(descriptor, False)
    try:
        while True:
            try:
                os.write(descriptor, b"x" * 4096)
            except BlockingIOError:
                break
    finally:
        os.set_blocking(descriptor, True)


class LocalCommandWriteDeadlineTests(unittest.TestCase):
    def _sessions(self):
        return (
            ("gpio_session", lambda: OpenTitanGpioSession(), "READY",
             lambda session: session.step_local({"gpio_in": 0})),
            ("uart_session", lambda: OpenTitanUartSession(), "READY",
             lambda session: session.step_local({"uart_rx": 1})),
            ("ibex_session", lambda: IbexCpuSession(memory=object(), router=object()),
             "READY 3", lambda session: session.step_local({"irq": 0})),
            ("cva6_session", lambda: Cva6CpuSession(memory=object()),
             "READY", lambda session: session.step_local({"irq": 0})),
        )

    def _run_until_complete(self, session, action):
        errors = []

        def work():
            try:
                action()
            except BaseException as exc:
                errors.append(exc)

        started = time.monotonic()
        worker = threading.Thread(target=work, daemon=True)
        worker.start()
        worker.join(0.35)
        elapsed = time.monotonic() - started
        if worker.is_alive():
            session._process.kill()
            worker.join(0.5)
        return elapsed, worker.is_alive(), errors

    def test_full_pipe_command_obeys_enclosing_deadline_for_all_real_sessions(self):
        with tempfile.TemporaryDirectory() as directory:
            for module, constructor, ready, step in self._sessions():
                with self.subTest(module=module):
                    executable = Path(directory) / f"silent-{module}"
                    executable.write_text(
                        f"#!/bin/sh\nprintf '{ready}\\n'\nexec sleep 2\n")
                    executable.chmod(0o755)
                    with patch(f"myfuzz.scenario.{module}._binary",
                               return_value=executable):
                        session = constructor()
                        session.begin_case("full-pipe")
                        try:
                            _fill_child_stdin(session._process.stdin)

                            def action():
                                with command_deadline(time.monotonic() + 0.03):
                                    step(session)

                            elapsed, alive, errors = self._run_until_complete(
                                session, action)
                            self.assertFalse(alive)
                            self.assertLess(elapsed, 0.3)
                            self.assertEqual(1, len(errors))
                            self.assertIsInstance(errors[0],
                                                  LocalCommandDeadlineExceeded)
                        finally:
                            session.end_case()

    def test_full_pipe_end_is_bounded_and_reaps_all_real_sessions(self):
        with tempfile.TemporaryDirectory() as directory, patch(
                "myfuzz.scenario.protocol_io.DEFAULT_END_TIMEOUT_SECONDS", 0.03):
            for module, constructor, ready, _ in self._sessions():
                with self.subTest(module=module):
                    executable = Path(directory) / f"silent-end-{module}"
                    executable.write_text(
                        f"#!/bin/sh\nprintf '{ready}\\n'\nexec sleep 2\n")
                    executable.chmod(0o755)
                    with patch(f"myfuzz.scenario.{module}._binary",
                               return_value=executable):
                        session = constructor()
                        session.begin_case("full-pipe-end")
                        process = session._process
                        _fill_child_stdin(process.stdin)
                        elapsed, alive, errors = self._run_until_complete(
                            session, session.end_case)
                        self.assertFalse(alive)
                        self.assertFalse(errors)
                        self.assertLess(elapsed, 0.3)
                        self.assertIsNotNone(process.poll())
                        self.assertIsNone(session._process)


if __name__ == "__main__":
    unittest.main()
