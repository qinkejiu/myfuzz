"""A local harness startup failure still leaves a replayable semantic prefix."""

from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from myfuzz.scenario.evidence import save_evidence_bundle
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.replay import replay_scenario
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.gpio_session import OpenTitanGpioSession
from myfuzz.scenario.uart_session import OpenTitanUartSession
from myfuzz.scenario.ibex_session import IbexCpuSession
from myfuzz.scenario.cva6_session import Cva6CpuSession
from myfuzz.scenario.protocol_io import LocalCommandDeadlineExceeded


class FailingBeginSession:
    def __init__(self):
        self.closes = 0

    def identity_document(self):
        return {"kind": "deterministic_begin_failure"}

    def begin_case(self, testcase_id):
        raise RuntimeError("local process failed before READY")

    def end_case(self):
        self.closes += 1


class StartedSession:
    def __init__(self):
        self.closes = 0

    def begin_case(self, testcase_id):
        pass

    def end_case(self):
        self.closes += 1


class BeginFailureEvidenceTests(unittest.TestCase):
    def test_all_real_session_ready_reads_are_bounded(self):
        constructors = (
            ("gpio_session", OpenTitanGpioSession),
            ("uart_session", OpenTitanUartSession),
            ("ibex_session", lambda: IbexCpuSession(memory=object(), router=object())),
            ("cva6_session", lambda: Cva6CpuSession(memory=object())),
        )
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "silent-ready"
            executable.write_text("#!/bin/sh\nexec sleep 2\n")
            executable.chmod(0o755)
            for module, constructor in constructors:
                with self.subTest(module=module), patch(
                    f"myfuzz.scenario.{module}._binary", return_value=executable
                ), patch("myfuzz.scenario.protocol_io.DEFAULT_READY_TIMEOUT_SECONDS", 0.03):
                    session = constructor()
                    started = time.monotonic()
                    with self.assertRaises(LocalCommandDeadlineExceeded):
                        session.begin_case("silent-ready")
                    self.assertIsNone(session._process)
                    self.assertLess(time.monotonic() - started, 1)

    def test_gpio_ready_silence_has_bounded_replayable_begin_failure(self):
        ownership = compile_ownership(
            (InputField("gpio", "gpio_in", 32),),
            (InputOwner("gpio", "gpio_in", 0, 32, "source", "external"),))

        def factory():
            return ScenarioRunner(sessions={"gpio": OpenTitanGpioSession()},
                                  ownership=ownership, bindings=())

        genome = ScenarioGenome(testcase_id="gpio-silent-ready",
                                direction="IP_TO_IP", path_id="gpio-start",
                                schedule_order=("gpio",), max_steps=1, actions=())
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "silent-ready"
            executable.write_text("#!/bin/sh\nexec sleep 2\n")
            executable.chmod(0o755)
            bundle = Path(directory) / "bundle"
            started = time.monotonic()
            with patch("myfuzz.scenario.gpio_session._binary",
                       return_value=executable), patch(
                       "myfuzz.scenario.protocol_io.DEFAULT_READY_TIMEOUT_SECONDS",
                       0.03):
                trace = save_evidence_bundle(genome, factory, bundle)
                self.assertEqual("environment_error", trace.status)
                self.assertEqual("begin_failure", trace.events[-1]["kind"])
                self.assertEqual("LocalCommandDeadlineExceeded",
                                 trace.events[-1]["error_type"])
                self.assertTrue(replay_scenario(genome, factory, trace).matches)
            self.assertLess(time.monotonic() - started, 1)

    def test_real_gpio_session_binary_start_failure_is_replayable(self):
        ownership = compile_ownership(
            (InputField("gpio", "gpio_in", 32),),
            (InputOwner("gpio", "gpio_in", 0, 32, "source", "external"),))

        def factory():
            return ScenarioRunner(sessions={"gpio": OpenTitanGpioSession()},
                                  ownership=ownership, bindings=())

        genome = ScenarioGenome(testcase_id="gpio-spawn-failure",
                                direction="IP_TO_IP", path_id="gpio-start",
                                schedule_order=("gpio",), max_steps=1, actions=())
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "bundle"
            absent_binary = Path(directory) / "missing-local-gpio"
            with patch("myfuzz.scenario.gpio_session._binary",
                       return_value=absent_binary):
                trace = save_evidence_bundle(genome, factory, bundle)
                self.assertEqual("environment_error", trace.status)
                self.assertEqual(0, trace.local_ticks["gpio"])
                self.assertEqual("begin_failure", trace.events[-1]["kind"])
                self.assertEqual("FileNotFoundError", trace.events[-1]["error_type"])
                self.assertTrue(replay_scenario(genome, factory, trace).matches)

    def test_real_gpio_session_bad_ready_is_replayable(self):
        ownership = compile_ownership(
            (InputField("gpio", "gpio_in", 32),),
            (InputOwner("gpio", "gpio_in", 0, 32, "source", "external"),))

        def factory():
            return ScenarioRunner(sessions={"gpio": OpenTitanGpioSession()},
                                  ownership=ownership, bindings=())

        genome = ScenarioGenome(testcase_id="gpio-bad-ready",
                                direction="IP_TO_IP", path_id="gpio-start",
                                schedule_order=("gpio",), max_steps=1, actions=())
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "bad-ready"
            executable.write_text("#!/bin/sh\nprintf 'BROKEN\\n'\n")
            executable.chmod(0o755)
            bundle = Path(directory) / "bundle"
            with patch("myfuzz.scenario.gpio_session._binary",
                       return_value=executable):
                trace = save_evidence_bundle(genome, factory, bundle)
                self.assertEqual("environment_error", trace.status)
                self.assertEqual(0, trace.local_ticks["gpio"])
                self.assertEqual("begin_failure", trace.events[-1]["kind"])
                self.assertEqual("RuntimeError", trace.events[-1]["error_type"])
                self.assertTrue(replay_scenario(genome, factory, trace).matches)

    def test_begin_failure_is_saved_and_replayed_without_rtl_step(self):
        ownership = compile_ownership(
            (InputField("gpio", "pin", 1),),
            (InputOwner("gpio", "pin", 0, 1, "source", "external"),))

        def factory():
            return ScenarioRunner(sessions={"gpio": FailingBeginSession()},
                                  ownership=ownership, bindings=())

        genome = ScenarioGenome(testcase_id="begin-failure", direction="IP_TO_IP",
                                path_id="local-start", schedule_order=("gpio",),
                                max_steps=1, actions=())
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "bundle"
            trace = save_evidence_bundle(genome, factory, bundle)
            self.assertEqual("environment_error", trace.status)
            self.assertEqual(0, trace.local_ticks["gpio"])
            self.assertEqual("begin_failure", trace.events[-1]["kind"])
            self.assertEqual("gpio", trace.events[-1]["failed_component"])
            self.assertEqual("RuntimeError", trace.events[-1]["error_type"])
            self.assertTrue((bundle / "bundle_index.json").is_file())
            self.assertTrue(replay_scenario(genome, factory, trace).matches)

    def test_all_attempted_harnesses_close_once_after_partial_begin(self):
        started = StartedSession()
        failed = FailingBeginSession()
        ownership = compile_ownership(
            (InputField("a", "pin", 1), InputField("b", "pin", 1)),
            (InputOwner("a", "pin", 0, 1, "source", "external_a"),
             InputOwner("b", "pin", 0, 1, "source", "external_b")))
        runner = ScenarioRunner(sessions={"a": started, "b": failed},
                                ownership=ownership, bindings=())
        with self.assertRaisesRegex(RuntimeError, "local process failed"):
            runner.begin_test("partial")
        runner.finalize()
        self.assertEqual(1, started.closes)
        self.assertEqual(1, failed.closes)


if __name__ == "__main__":
    unittest.main()
