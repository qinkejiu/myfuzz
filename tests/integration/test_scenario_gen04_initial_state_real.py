"""GEN-04: changed CPU program restarts three real local RTL instances."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from myfuzz.scenario.examples import make_ibex_two_gpio_runner
from myfuzz.scenario.genome import GenomeCodec
from myfuzz.scenario.ledger import TransactionKey
from myfuzz.scenario.replay import record_scenario


ROOT = Path(__file__).resolve().parents[2]
CONFIGS = ROOT / "configs/scenario"


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class Gen04RealInitialStateTests(unittest.TestCase):
    def test_program_variant_restarts_ibex_and_two_gpio_from_initial_state(self):
        baseline = GenomeCodec.decode((
            CONFIGS / "ibex_two_gpio_closed_two_rounds.json").read_bytes())
        variant = GenomeCodec.decode((
            CONFIGS / "ibex_two_gpio_closed_two_rounds_variant.json").read_bytes())
        self.assertNotEqual(baseline.initial_images, variant.initial_images)
        self.assertEqual(baseline.actions, variant.actions)
        self.assertEqual(baseline.schedule_order, variant.schedule_order)

        runners = []
        before = []

        def factory():
            runner = make_ibex_two_gpio_runner()
            memory = runner.sessions["cpu"].memory
            before.append((memory.generation, memory.initialized_bytes,
                           memory.state_summary()["cells_sha256"]))
            runners.append(runner)
            return runner

        traces = [record_scenario(genome, factory)
                  for genome in (baseline, variant, baseline)]
        self.assertEqual(["complete"] * 3, [trace.status for trace in traces])
        self.assertEqual(3, len({id(runner) for runner in runners}))
        self.assertEqual(3, len({id(runner.sessions["cpu"].memory)
                                 for runner in runners}))
        self.assertEqual([(0, 0)] * 3, [(generation, initialized)
                                        for generation, initialized, _ in before])
        self.assertEqual(1, len({digest for _, _, digest in before}))

        for trace, runner, expected in zip(traces, runners, (1, 3, 1), strict=True):
            with self.subTest(expected=expected):
                first_a_mmio = next(event for event in trace.events
                                    if event.get("kind") == "mmio_delivery"
                                    and event.get("device_id") == "gpio_a"
                                    and event.get("offset") == 0x14
                                    and event.get("write"))
                self.assertEqual(expected, first_a_mmio["write_value"])
                writes = [event for event in trace.events
                          if event.get("kind") == "memory_write"
                          and event.get("component") == "cpu"
                          and event.get("address") == 0x200]
                self.assertGreaterEqual(len(writes), 2)
                self.assertEqual(expected, writes[0]["value"])
                self.assertEqual(expected, writes[-1]["value"])
                memory = runner.sessions["cpu"].memory
                self.assertEqual(0, memory.generation)
                snapshot = memory.read(0x200, 4,
                                       transaction_id=f"inspect-{expected}")
                self.assertEqual(expected, snapshot.value)
                self.assertEqual((str(TransactionKey(**writes[-1]["transaction"])),) * 4,
                                 snapshot.writer_event_ids)

        self.assertEqual(traces[0].semantic_sha256,
                         traces[2].semantic_sha256)
        self.assertNotEqual(traces[0].semantic_sha256,
                            traces[1].semantic_sha256)
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "old-final-state.json"
            checkpoint.write_text(json.dumps(runners[0].final_state_document()),
                                  encoding="utf-8")
            environment = dict(os.environ)
            environment["PYTHONPATH"] = f"{ROOT / 'src'}:{ROOT}"
            replay = subprocess.run(
                (sys.executable, str(ROOT / "scripts/replay_scenario.py"),
                 "--evidence", str(Path(directory) / "unused-bundle"),
                 "--factory", "myfuzz.scenario.examples:make_ibex_two_gpio_runner",
                 "--resume", str(checkpoint)),
                cwd=ROOT, env=environment, capture_output=True, text=True,
                timeout=30)
            self.assertEqual(2, replay.returncode)
            self.assertIn("unsupported_checkpoint_resume", replay.stderr)


if __name__ == "__main__":
    unittest.main()
