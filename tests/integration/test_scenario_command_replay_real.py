"""Local RTL process commands are idempotent under reply retransmission."""

from __future__ import annotations

import os
import subprocess
import unittest
from unittest.mock import patch

from myfuzz.scenario.gpio_session import _binary as gpio_binary
from myfuzz.scenario.gpio_session import OpenTitanGpioSession
from myfuzz.scenario.ibex_session import _binary as ibex_binary
from myfuzz.scenario.ibex_session import IbexCpuSession
from myfuzz.scenario.cva6_session import _binary as cva6_binary
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.replay import record_scenario, replay_scenario
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealCommandReplayTests(unittest.TestCase):
    def test_crashed_ibex_tick_is_uncertain_in_complete_scenario(self):
        ownership = compile_ownership(
            (InputField("cpu", "irq", 2), InputField("gpio", "gpio_in", 32)),
            (InputOwner("cpu", "irq", 0, 2, "fixed", "constant_zero"),
             InputOwner("gpio", "gpio_in", 0, 32, "source", "external")))
        genome = ScenarioGenome(
            testcase_id="ibex-crash", direction="CPU_TO_IP", path_id="cpu-gpio",
            schedule_order=("cpu", "gpio"), max_steps=2, actions=())

        def factory():
            gpio = OpenTitanGpioSession()
            memory = PersistentMemory(
                regions=(MemoryRegion("ram", 0, 0x20000),),
                initialization_seed=13, max_initialized_bytes=0x20000)
            router = DataflowRouter((DeviceWindow("gpio", 0x40000000,
                                                  0x1000, gpio),))
            cpu = IbexCpuSession(memory=memory, router=router)
            return ScenarioRunner(sessions={"cpu": cpu, "gpio": gpio},
                                  ownership=ownership, bindings=())

        with patch.dict(os.environ, {"MYFUZZ_TEST_CRASH_AFTER_CPU_TICK": "1"}):
            trace = record_scenario(genome, factory)
            self.assertEqual("uncertain_effect", trace.status)
            self.assertTrue(any(event.get("component") == "cpu"
                                and event.get("kind") == "harness_failure"
                                for event in trace.events))
            self.assertTrue(replay_scenario(genome, factory, trace).matches)

    def test_cpu_process_crash_after_real_tick_loses_reply(self):
        environment = dict(os.environ)
        environment["MYFUZZ_TEST_CRASH_AFTER_CPU_TICK"] = "1"
        for binary, ready, fields in (
                (ibex_binary, "READY 3", "0 1 0 0 0 1 0 0 0"),
                (cva6_binary, "READY", "0 1 0 0 0")):
            with self.subTest(binary=binary.__name__):
                proc = subprocess.Popen((str(binary()),), stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL,
                                        text=True, bufsize=1, env=environment)
                try:
                    self.assertEqual(ready, proc.stdout.readline().strip())
                    proc.stdin.write(f"CMD execution-crash 1 {fields}\n")
                    proc.stdin.flush()
                    self.assertEqual("", proc.stdout.readline())
                    self.assertEqual(87, proc.wait(timeout=3))
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait(timeout=3)
                    proc.stdin.close()
                    proc.stdout.close()

    def test_crashed_gpio_write_is_uncertain_in_complete_scenario(self):
        class WriteThenCrashSession(OpenTitanGpioSession):
            def step_local(self, inputs):
                self.write_register(0x14, 5)
                return {"gpio_out": 0}

        ownership = compile_ownership(
            (InputField("gpio", "gpio_in", 32),),
            (InputOwner("gpio", "gpio_in", 0, 32, "source", "external"),))
        genome = ScenarioGenome(
            testcase_id="real-crash", direction="IP_TO_CPU", path_id="gpio-irq",
            schedule_order=("gpio",), max_steps=2, actions=())

        def factory():
            return ScenarioRunner(sessions={"gpio": WriteThenCrashSession()},
                                  ownership=ownership, bindings=())

        with patch.dict(os.environ, {"MYFUZZ_TEST_CRASH_AFTER_GPIO_WRITE": "1"}):
            trace = record_scenario(genome, factory)
            self.assertEqual("uncertain_effect", trace.status)
            self.assertTrue(any(event["kind"] == "harness_failure"
                                for event in trace.events))
            self.assertTrue(replay_scenario(genome, factory, trace).matches)

    def _probe_cpu(self, binary, ready, fields):
        proc = subprocess.Popen((str(binary()),), stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, bufsize=1)
        self.assertEqual(ready, proc.stdout.readline().strip())

        def send(line):
            proc.stdin.write(line + "\n")
            proc.stdin.flush()
            return proc.stdout.readline().strip()

        try:
            command = f"CMD execution-a 1 {fields}"
            first = send(command)
            self.assertTrue(first.startswith("RESULT execution-a 1 "), first)
            self.assertEqual(first, send(command))
            second = send(f"CMD execution-a 2 {fields}")
            self.assertEqual(int(first.split()[-1], 16) + 1,
                             int(second.split()[-1], 16))
            changed = " ".join(("1", *fields.split()[1:]))
            self.assertIn("identity_conflict", send(
                f"CMD execution-a 1 {changed}"))
            self.assertIn("stale_execution", send(
                f"CMD execution-b 3 {fields}"))
            self.assertIn("out_of_order_command", send(
                f"CMD execution-a 4 {fields}"))
        finally:
            if proc.poll() is None:
                proc.stdin.write("END\n")
                proc.stdin.flush()
            proc.wait(timeout=3)
            proc.stdin.close()
            proc.stdout.close()

    def test_ibex_step_retry_does_not_advance_two_cycles(self):
        self._probe_cpu(ibex_binary, "READY 3", "0 1 0 0 0 1 0 0 0")

    def test_cva6_step_retry_does_not_advance_two_cycles(self):
        self._probe_cpu(cva6_binary, "READY", "0 1 0 0 0")

    def test_gpio_command_retry_returns_cached_observation_without_tick(self):
        proc = subprocess.Popen((str(gpio_binary()),), stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, bufsize=1)
        self.assertEqual("READY", proc.stdout.readline().strip())

        def send(line):
            proc.stdin.write(line + "\n")
            proc.stdin.flush()
            return proc.stdout.readline().strip()

        try:
            command = "CMD execution-a 1 0 1 1 40000014 5 f 1"
            first = send(command)
            self.assertTrue(first.startswith("RESULT execution-a 1 "), first)
            self.assertEqual(first, send(command))
            self.assertIn("identity_conflict", send(
                "CMD execution-a 1 1 0 0 0 0 f 1"))
            second = send("CMD execution-a 2 0 0 0 0 0 f 1")
            self.assertEqual(int(first.split()[-1], 16) + 1,
                             int(second.split()[-1], 16))
            self.assertIn("out_of_order_command", send(
                "CMD execution-a 4 0 0 0 0 0 f 1"))
            self.assertIn("stale_execution", send(
                "CMD execution-b 3 0 0 0 0 0 f 1"))
        finally:
            if proc.poll() is None:
                proc.stdin.write("END\n")
                proc.stdin.flush()
            proc.wait(timeout=3)
            proc.stdin.close()
            proc.stdout.close()

    def test_gpio_crash_after_real_write_has_no_completion_receipt(self):
        environment = dict(os.environ)
        environment["MYFUZZ_TEST_CRASH_AFTER_GPIO_WRITE"] = "1"
        proc = subprocess.Popen((str(gpio_binary()),), stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, bufsize=1, env=environment)
        try:
            self.assertEqual("READY", proc.stdout.readline().strip())
            proc.stdin.write("CMD execution-crash 1 0 1 1 40000014 5 f 1\n")
            proc.stdin.flush()
            self.assertEqual("", proc.stdout.readline())
            self.assertEqual(86, proc.wait(timeout=3))
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=3)
            proc.stdin.close()
            proc.stdout.close()


if __name__ == "__main__":
    unittest.main()
