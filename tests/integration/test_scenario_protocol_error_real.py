"""ABS-01: a malformed local TL-UL response is a driver error."""

import os
from unittest.mock import patch
import unittest

from myfuzz.integration.rfuzz_wire import InputBatch
from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
from myfuzz.integration.scenario_rfuzz import _trace_protocol_environment_error
from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.genome import Action, ScenarioGenome, Trigger
from myfuzz.scenario.gpio_session import OpenTitanGpioSession
from myfuzz.scenario.replay import record_scenario
from myfuzz.scenario.rfuzz_decoder import DecoderTemplate, GenomeRecordDecoder


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealProtocolEnvironmentTests(unittest.TestCase):
    def test_corrupted_tlul_d_source_is_attributed_to_driver(self):
        from myfuzz.integration.scenario_rfuzz import ProtocolEnvironmentError

        with patch.dict(os.environ, {"MYFUZZ_TEST_BAD_TL_D_SOURCE": "1"}):
            gpio = OpenTitanGpioSession()
            gpio.begin_case("bad-tlul-d")
            try:
                with self.assertRaises(ProtocolEnvironmentError):
                    gpio.write_register(0x04, 1)
            finally:
                gpio.end_case()

    def test_real_driver_fault_trace_is_environment_error_not_dut_bug(self):
        from tests.integration.test_scenario_reset_quiesce_real import _case

        genome = ScenarioGenome(
            testcase_id="bad-tlul-trace", direction="CPU_TO_IP_TO_CPU",
            path_id="cpu-gpio-bad-driver", schedule_order=("cpu", "gpio"),
            max_steps=100, actions=())
        with patch.dict(os.environ, {"MYFUZZ_TEST_BAD_TL_D_SOURCE": "1"}):
            trace = record_scenario(genome, lambda: _case(preload=True)[-1])
        self.assertEqual("uncertain_effect", trace.status)
        self.assertTrue(_trace_protocol_environment_error(trace))
        failures = [event for event in trace.events
                    if event.get("kind") == "harness_failure"]
        self.assertEqual("ProtocolEnvironmentError",
                         failures[-1]["error_type"])

    def test_unsolicited_real_cpu_response_is_attributed_to_driver(self):
        from tests.integration.test_scenario_reset_quiesce_real import _case

        genome = ScenarioGenome(
            testcase_id="bad-cpu-response", direction="CPU_TO_IP_TO_CPU",
            path_id="cpu-unsolicited-rvalid", schedule_order=("cpu", "gpio"),
            max_steps=10, actions=())
        with patch.dict(os.environ, {"MYFUZZ_TEST_BAD_CPU_RESPONSE": "1"}):
            trace = record_scenario(genome, lambda: _case(preload=True)[-1])
        self.assertEqual("uncertain_effect", trace.status)
        self.assertTrue(_trace_protocol_environment_error(trace))
        failures = [event for event in trace.events
                    if event.get("kind") == "harness_failure"]
        self.assertEqual("ProtocolEnvironmentError",
                         failures[-1]["error_type"])
        self.assertGreaterEqual(trace.local_ticks["cpu"], 1)

    def test_real_protocol_faults_do_not_enter_rfuzz_dut_bug_corpus(self):
        from tests.integration.test_scenario_reset_quiesce_real import _case

        for variable in ("MYFUZZ_TEST_BAD_TL_D_SOURCE",
                         "MYFUZZ_TEST_BAD_CPU_RESPONSE"):
            with self.subTest(variable=variable):
                factory = lambda: _case(preload=True)[-1]
                fixture = factory()
                graph = DependencyGraph(
                    sources=(FuzzableSource("gpio.pin", "gpio", "gpio_in", 0, 1,
                                            ("CPU_TO_IP_TO_CPU",)),),
                    rules=(DependencyRule("gpio.irq", ("gpio.pin",),
                                          "DATA_BINDING"),))
                genome = ScenarioGenome(
                    testcase_id="real-protocol-fault", direction="CPU_TO_IP_TO_CPU",
                    path_id="cpu-gpio-driver-fault", schedule_order=("cpu", "gpio"),
                    max_steps=100,
                    actions=(Action("pin", "gpio", "gpio_in", 0,
                                    "CPU_TO_IP_TO_CPU", Trigger("START"), width=1),))
                decoder = GenomeRecordDecoder(
                    graph=graph, ownership=fixture.ownership,
                    templates=(DecoderTemplate("gpio.irq", genome),))
                checker_calls = []
                executor = ScenarioRfuzzExecutor(
                    run_id="real-protocol-fault", decoder=decoder, factory=factory,
                    targets=(CoverageTarget("gpio.irq", "gpio", "irq", 1, 1),),
                    checker=lambda trace: checker_calls.append(trace) or
                    ("invented_dut_bug",), allow_legacy_search=True)
                with patch.dict(os.environ, {variable: "1"}):
                    executor.execute_batch(InputBatch(1, 8, ((bytes(8),),)))
                receipt = executor.receipts[0]
                self.assertEqual("environment_error", receipt.status)
                self.assertEqual((), receipt.violations)
                self.assertEqual([], checker_calls)


if __name__ == "__main__":
    unittest.main()
