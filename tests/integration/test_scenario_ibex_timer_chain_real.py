"""Two real RV Timer expiries traverse Ibex IRQ and persistent RAM."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import GenomeCodec
from myfuzz.scenario.replay import record_scenario
from myfuzz.scenario.runner import ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
GENOME_PATH = ROOT / "configs/scenario/ibex_timer_two_rounds.json"


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealIbexTimerChainTests(unittest.TestCase):
    def test_two_expiries_are_handled_by_cpu_and_replay_from_fresh_processes(self):
        from myfuzz.scenario.ibex_timer_example import make_ibex_timer_runner

        genome = GenomeCodec.decode(GENOME_PATH.read_bytes())
        self.assertEqual((), genome.actions)
        self.assertEqual(("cpu", "timer"), genome.schedule_order)
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "bundle"
            runners = []

            def factory():
                runner = make_ibex_timer_runner()
                runners.append(runner)
                return runner

            trace = save_evidence_bundle(genome, factory, bundle)
            self.assertEqual("complete", trace.status)
            events = trace.events
            self.assertFalse(any(e.get("kind") == "source_injection" for e in events))
            self.assertFalse(any(e.get("kind") == "reset_barrier" for e in events))
            writes = [e for e in events if e.get("kind") == "mmio_delivery"
                      and e.get("device_id") == "timer" and e.get("write")]
            offsets = [e["offset"] for e in writes]
            for required in (0x10c, 0x118, 0x11c, 0x100, 0x4):
                self.assertIn(required, offsets)
            compares = [e for e in writes if e["offset"] == 0x118]
            self.assertEqual(3, len(compares))
            self.assertLess(compares[0]["write_value"], compares[1]["write_value"])
            self.assertLess(compares[1]["write_value"], compares[2]["write_value"])
            self.assertEqual(0, [e["write_value"] for e in writes
                                 if e["offset"] == 0x4][-1])
            irq = [e for e in events if e.get("kind") == "dataflow_delivery"
                   and e.get("source") == ("timer", "irq")
                   and e.get("target") == ("cpu", "irq")
                   and e.get("value") == 1]
            self.assertGreaterEqual(len(irq), 2)
            taken = [e for e in events if e.get("component") == "cpu"
                     and e.get("outputs", {}).get("irq_taken_pre") == 1]
            self.assertEqual(2, len(taken))
            reads = [e for e in events if e.get("kind") == "mmio_delivery"
                     and e.get("device_id") == "timer" and not e.get("write")
                     and e.get("offset") == 0x110]
            pending_reads = [e for e in events if e.get("kind") == "mmio_delivery"
                             and e.get("device_id") == "timer" and not e.get("write")
                             and e.get("offset") == 0x104]
            ram = [e for e in events if e.get("kind") == "memory_write"
                   and e.get("component") == "cpu"
                   and e.get("address") in (0x200, 0x204)]
            self.assertEqual([0x200, 0x204], [e["address"] for e in ram])
            self.assertEqual(2, len(reads))
            self.assertEqual([1, 1], [e["read_value"] & 1
                                      for e in pending_reads])
            self.assertEqual([e["read_value"] for e in reads],
                             [e["value"] for e in ram])
            self.assertLess(ram[0]["value"], ram[1]["value"])
            for pending, read, write, compare in zip(
                    pending_reads, reads, ram, compares[1:]):
                self.assertLess(pending["event_id"], read["event_id"])
                self.assertTrue(any(irq_event["event_id"] < read["event_id"]
                                    and irq_event["event_id"] < write["event_id"]
                                    for irq_event in irq))
                self.assertLess(read["event_id"], write["event_id"])
                self.assertLess(write["event_id"], compare["event_id"])
            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay)
            self.assertIsNot(runners[0], runners[1])
            self.assertIsNot(runners[0].sessions["timer"],
                             runners[1].sessions["timer"])

    def test_cut_timer_irq_prevents_cpu_receipt(self):
        from myfuzz.scenario.ibex_timer_example import make_ibex_timer_runner

        genome = GenomeCodec.decode(GENOME_PATH.read_bytes())

        def cut_factory():
            connected = make_ibex_timer_runner()
            return ScenarioRunner(sessions=connected.sessions,
                                  ownership=connected.ownership, bindings=())

        trace = record_scenario(genome, cut_factory)
        self.assertEqual("complete", trace.status)
        self.assertTrue(any(e.get("component") == "timer"
                            and e.get("outputs", {}).get("irq") == 1
                            for e in trace.events))
        self.assertFalse(any(e.get("kind") == "memory_write"
                             and e.get("address") in (0x200, 0x204)
                             for e in trace.events))


if __name__ == "__main__":
    unittest.main()
