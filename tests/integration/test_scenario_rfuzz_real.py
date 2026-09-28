"""RFuzz records drive an actual persistent Ibex/GPIO scenario executor."""

from __future__ import annotations

from dataclasses import replace
import os
import unittest

from myfuzz.integration.rfuzz_wire import InputBatch
from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.rfuzz_decoder import DecoderTemplate, GenomeRecordDecoder

from tests.integration.test_scenario_ip_cpu_ip_genome import IpCpuIpGenomeTests


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class ScenarioRfuzzRealTests(unittest.TestCase):
    def test_rfuzz_test_record_changes_real_ip_cpu_ip_chain(self):
        _, _, _, runner, baseline = IpCpuIpGenomeTests._case()
        seed_actions = list(baseline.actions)
        seed_actions[2] = replace(seed_actions[2], value=0x100)
        seed = replace(baseline, testcase_id="rfuzz-seed",
                       actions=tuple(seed_actions))
        graph = DependencyGraph(
            sources=(FuzzableSource("b.pin9", "gpio_b", "gpio_in", 9, 1,
                                    ("IP_TO_CPU_TO_IP",)),),
            rules=(DependencyRule("a.output.0x300", ("b.pin9",),
                                  "DATA_BINDING"),))
        decoder = GenomeRecordDecoder(
            graph=graph, ownership=runner.ownership,
            templates=(DecoderTemplate("a.output.0x300", seed),))
        executor = ScenarioRfuzzExecutor(
            run_id="real-ibex-gpio", decoder=decoder,
            factory=lambda: IpCpuIpGenomeTests._case()[3],
            targets=(CoverageTarget("a.output.0x300", "gpio_a", "gpio_out",
                                    0x300, 0x300),), allow_legacy_search=True)
        batch = InputBatch(7, 8, ((bytes(8),),
                                  (bytes((0, 0, 0, 0, 0, 1, 0, 0)),)))
        self.assertEqual((b"\x00", b"\x01"), executor.execute_batch(batch))
        self.assertEqual(("complete", "complete"),
                         tuple(r.status for r in executor.receipts))
        self.assertTrue(all(r.total_local_ticks > 1000
                            for r in executor.receipts))
        self.assertNotEqual(executor.receipts[0].genome_sha256,
                            executor.receipts[1].genome_sha256)


if __name__ == "__main__":
    unittest.main()
