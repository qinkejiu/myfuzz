"""RUN-05: a later real testcase matches a fresh Python process."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from myfuzz.scenario.examples import make_ibex_two_gpio_runner
from myfuzz.scenario.genome import GenomeCodec
from myfuzz.scenario.ip_cpu_ip_example import make_external_gpio_ibex_gpio_runner
from myfuzz.scenario.replay import record_scenario


ROOT = Path(__file__).resolve().parents[2]
CASES = {
    "cpu": (
        "ibex_two_gpio_closed_two_rounds.json",
        "ibex_two_gpio_closed_two_rounds_variant.json",
        make_ibex_two_gpio_runner,
    ),
    "external": (
        "external_gpio_ibex_gpio_closed_two_rounds_variant.json",
        "external_gpio_ibex_gpio_closed_two_rounds.json",
        make_external_gpio_ibex_gpio_runner,
    ),
}


def _run_case(direction: str, *, first: bool) -> dict:
    before, second, factory = CASES[direction]
    name = before if first else second
    genome = GenomeCodec.decode((ROOT / "configs/scenario" / name).read_bytes())
    runners = []

    def capture_factory():
        runner = factory()
        runners.append(runner)
        return runner

    trace = record_scenario(genome, capture_factory)
    events = trace.events
    gpio_a = [event["outputs"]["gpio_out"] for event in events
              if event.get("component") == "gpio_a"
              and "gpio_out" in event.get("outputs", {})]
    gpio_b = [event["outputs"]["gpio_out"] for event in events
              if event.get("component") == "gpio_b"
              and "gpio_out" in event.get("outputs", {})]
    initializations = [
        [event["memory_id"], event["byte_offset"], event["value"],
         event["generation"], event["version"], event["writer_event_id"]]
        for event in events if event.get("kind") == "memory_initialization"
    ]
    writes = [event["value"] for event in events
              if event.get("kind") == "memory_write"
              and event.get("address") == 0x200]
    memory = runners[0].final_state_document()["memories"]["cpu"]
    return {
        "status": trace.status,
        "semantic_sha256": trace.semantic_sha256,
        "local_ticks": trace.local_ticks,
        "first_gpio_a": gpio_a[0],
        "last_gpio_a": gpio_a[-1],
        "first_gpio_b": gpio_b[0],
        "last_gpio_b": gpio_b[-1],
        "initializations": initializations,
        "ram_writes": writes,
        "memory": memory,
    }


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class FreshProcessCaseIsolationTests(unittest.TestCase):
    def test_second_case_matches_fresh_process_in_both_directions(self):
        for direction in CASES:
            with self.subTest(direction=direction):
                first = _run_case(direction, first=True)
                after_first = _run_case(direction, first=False)
                child = subprocess.run(
                    [sys.executable, str(Path(__file__).resolve()),
                     "--emit-second", direction],
                    cwd=ROOT, env=os.environ.copy(), capture_output=True,
                    text=True, timeout=180, check=True)
                fresh = json.loads(child.stdout)

                self.assertEqual("complete", first["status"])
                self.assertEqual("complete", after_first["status"])
                self.assertTrue(first["ram_writes"])
                self.assertTrue(after_first["ram_writes"])
                self.assertNotEqual(first["ram_writes"],
                                    after_first["ram_writes"])
                self.assertNotEqual(first["last_gpio_a"],
                                    after_first["last_gpio_a"])
                self.assertEqual(0, after_first["first_gpio_a"])
                self.assertEqual(0, after_first["first_gpio_b"])
                self.assertTrue(after_first["initializations"])
                self.assertTrue(all(row[3] == 0 and row[4][0] == 0
                                    for row in after_first["initializations"]))
                self.assertEqual(0, after_first["memory"]["generation"])
                normalized = json.loads(json.dumps(after_first))
                for key in normalized:
                    self.assertEqual(normalized[key], fresh[key], key)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--emit-second":
        print(json.dumps(_run_case(sys.argv[2], first=False), sort_keys=True))
    else:
        unittest.main()
