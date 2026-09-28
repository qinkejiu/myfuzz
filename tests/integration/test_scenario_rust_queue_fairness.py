"""A scenario corpus child must be scheduled after its parent's first stage."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from myfuzz.integration.scenario_campaign import IbexTwoGpioBoundProvider
from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
from myfuzz.integration.scenario_rfuzz_live import run_scenario_rfuzz_live


ROOT = Path(__file__).resolve().parents[2]


class ScenarioRustQueueFairnessTests(unittest.TestCase):
    def test_discovered_child_gets_queue_visit_after_parent_stage(self):
        provider = IbexTwoGpioBoundProvider()
        if not provider.client_binary.is_file():
            self.skipTest("local pinned RFuzz release binary is unavailable")
        factory, decoder, targets, _ = provider._fixture(
            "IP_TO_CPU_TO_IP",
            ROOT / "configs/scenario/ibex_two_gpio_closed_two_rounds.json")
        executor = ScenarioRfuzzExecutor(
            run_id="scenario-queue-fairness-real",
            decoder=decoder, factory=factory, targets=targets)
        original_hint = executor.mutation_hint
        executor.mutation_hint = lambda: {**original_hint(), "energy": 8}
        with tempfile.TemporaryDirectory(prefix="scenario-queue-fairness-") as name:
            output = Path(name) / "live"
            result = run_scenario_rfuzz_live(
                executor=executor, client_binary=provider.client_binary,
                output_dir=output, duration_seconds=5.0,
                search_seed=20260928, max_runs_per_batch=1)
            entries = tuple((output / "corpus").glob("entry_*.json"))
            log = (output / "client.log").read_text(
                encoding="utf-8", errors="replace")
        self.assertGreaterEqual(len(entries), 2, "fixture must discover a child")
        self.assertIn("1. Queue Entry", log)
        self.assertEqual(0, result.client_returncode,
                         "Rust must drain feedback without an orphan")


if __name__ == "__main__":
    unittest.main()
