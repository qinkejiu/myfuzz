"""Auditable source mutations and an isolated downstream real RTL control."""

from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.scenario import checker
from myfuzz.scenario.edge_experiments import make_fixed_b_input_runner
from myfuzz.scenario.evidence import save_evidence_bundle
from myfuzz.scenario.examples import make_ibex_two_gpio_runner
from myfuzz.scenario.genome import GenomeCodec
from myfuzz.scenario.ip_cpu_ip_example import make_external_gpio_ibex_gpio_runner


ROOT = Path(__file__).resolve().parents[2]
CONFIGS = ROOT / "configs/scenario"


def _genome(name):
    return GenomeCodec.decode((CONFIGS / name).read_bytes())


def _events(events, kind, **fields):
    return [event for event in events if event.get("kind") == kind
            and all(event.get(key) == value for key, value in fields.items())]


def _ram_writes(events):
    return [event["value"] for event in _events(
        events, "memory_write", component="cpu", address=0x200)]


def _delivered(events, source, target, value):
    return any(tuple(event.get("source", ())) == source
               and tuple(event.get("target", ())) == target
               and event.get("value") == value
               for event in _events(events, "dataflow_delivery"))


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class UpstreamProvenanceRealTests(unittest.TestCase):
    def test_e2e04_cpu_program_is_the_only_changed_root(self):
        baseline = _genome("ibex_two_gpio_closed_two_rounds.json")
        variant = _genome("ibex_two_gpio_closed_two_rounds_variant.json")

        # Testcase ID labels the run; it is not a DUT input. All other scenario
        # fields except the three copies of one program immediate must match.
        self.assertEqual(replace(baseline, testcase_id=variant.testcase_id,
                                 initial_images=variant.initial_images), variant)
        differences = {}
        for original, changed in zip(baseline.initial_images,
                                     variant.initial_images, strict=True):
            self.assertEqual((original.image_id, original.component,
                              original.address),
                             (changed.image_id, changed.component,
                              changed.address))
            differences[original.image_id] = [
                (index, old, new)
                for index, (old, new) in enumerate(zip(
                    bytes.fromhex(original.data_hex),
                    bytes.fromhex(changed.data_hex), strict=True))
                if old != new]
        self.assertEqual({"cpu.main": [(10, 0x10, 0x30)],
                          "cpu.isr": [(14, 0x10, 0x30)],
                          "cpu.isr.vector": [(14, 0x10, 0x30)]}, differences)

        with tempfile.TemporaryDirectory() as directory:
            for index, (genome, value) in enumerate(((baseline, 1), (variant, 3))):
                with self.subTest(value=value):
                    bundle = Path(directory) / f"cpu-source-{index}"
                    trace = save_evidence_bundle(
                        genome, make_ibex_two_gpio_runner, bundle,
                        closed_chain_expected_value=value)
                    final_state = json.loads((bundle / "final_state.json").read_text())
                    report = checker.check_cpu_gpio_closed_chain(
                        trace.events, final_state,
                        expected_value=value, min_rounds=2)
                    self.assertEqual("complete", trace.status)
                    self.assertTrue(report["complete"], report["findings"])
                    self.assertEqual(2, report["rounds"])
                    self.assertTrue(_delivered(
                        trace.events, ("gpio_a", "gpio_out"),
                        ("gpio_b", "gpio_in"), value))
                    self.assertTrue(_delivered(
                        trace.events, ("gpio_b", "irq"),
                        ("cpu", "irq"), 1))
                    self.assertTrue(any(event.get("component") == "gpio_a"
                                        and event.get("outputs", {}).get("gpio_out")
                                        == value for event in trace.events))
                    self.assertGreaterEqual(_ram_writes(trace.events).count(value), 2)
                    self.assertNotIn(3 if value == 1 else 1,
                                     _ram_writes(trace.events))

    def test_e2e04_external_gpio_is_the_only_changed_root(self):
        baseline = _genome("external_gpio_ibex_gpio_closed_two_rounds.json")
        variant = _genome(
            "external_gpio_ibex_gpio_closed_two_rounds_variant.json")
        self.assertEqual(replace(baseline, testcase_id=variant.testcase_id,
                                 actions=variant.actions), variant)
        self.assertEqual(3, len(baseline.actions))
        for original, changed in zip(baseline.actions, variant.actions,
                                     strict=True):
            self.assertEqual(replace(original, value=changed.value), changed)
        self.assertEqual([(action.action_id, action.value) for action in baseline.actions],
                         [("first-rise", 0x100), ("second-low", 0),
                          ("second-rise", 0x300)])
        self.assertEqual([(action.action_id, action.value) for action in variant.actions],
                         [("first-rise", 0x100), ("second-low", 0),
                          ("second-rise", 0x100)])

        with tempfile.TemporaryDirectory() as directory:
            for index, (genome, values) in enumerate(
                    ((baseline, (0x100, 0x300)),
                     (variant, (0x100, 0x100)))):
                with self.subTest(values=values):
                    bundle = Path(directory) / f"external-source-{index}"
                    trace = save_evidence_bundle(
                        genome, make_external_gpio_ibex_gpio_runner, bundle,
                        reverse_chain_expected_values=values)
                    final_state = json.loads((bundle / "final_state.json").read_text())
                    report = checker.check_gpio_cpu_gpio_closed_chain(
                        trace.events, final_state, expected_values=values)
                    self.assertEqual("complete", trace.status)
                    self.assertTrue(report["complete"], report["findings"])
                    self.assertEqual(2, report["rounds"])
                    self.assertEqual([("first-rise", 0x100), ("second-low", 0),
                                      ("second-rise", values[1])],
                                     [(event["action_id"], event["value"])
                                      for event in _events(trace.events,
                                                           "source_injection")])
                    self.assertTrue(_delivered(
                        trace.events, ("gpio_b", "irq"), ("cpu", "irq"), 1))
                    self.assertEqual(list(values), _ram_writes(trace.events))
                    for value in values:
                        self.assertTrue(any(
                            event.get("component") == "gpio_a"
                            and event.get("outputs", {}).get("gpio_out") == value
                            for event in trace.events))

    def test_e2e06_isolated_b_uses_value_recorded_from_real_a_output(self):
        baseline = _genome("ibex_two_gpio_closed_two_rounds.json")
        variant = _genome("ibex_two_gpio_closed_two_rounds_variant.json")
        with tempfile.TemporaryDirectory() as directory:
            recorded = save_evidence_bundle(
                baseline, make_ibex_two_gpio_runner,
                Path(directory) / "recorded-a-to-b",
                closed_chain_expected_value=1)
            self.assertEqual("complete", recorded.status)
            recorded_values = {
                event["value"] for event in _events(
                    recorded.events, "dataflow_delivery")
                if tuple(event.get("source", ())) == ("gpio_a", "gpio_out")
                and tuple(event.get("target", ())) == ("gpio_b", "gpio_in")}
            self.assertIn(1, recorded_values)
            self.assertTrue(any(event.get("component") == "gpio_a"
                                and event.get("outputs", {}).get("gpio_out") == 1
                                for event in recorded.events))

            for index, (source_genome, fixed_name, a_value) in enumerate((
                    (baseline, "ibex_two_gpio_fixed_b_one.json", 1),
                    (variant, "ibex_two_gpio_fixed_b_three.json", 3))):
                with self.subTest(a_value=a_value):
                    isolated = _genome(fixed_name)
                    self.assertEqual(source_genome.initial_images,
                                     isolated.initial_images)
                    self.assertEqual("isolated_replay.cpu-a-b-fixed-b",
                                     isolated.path_id)
                    self.assertEqual(1, len(isolated.actions))
                    self.assertEqual("fixed-b-rise",
                                     isolated.actions[0].action_id)
                    self.assertEqual(1, isolated.actions[0].value)
                    self.assertIn(isolated.actions[0].value, recorded_values)
                    trace = save_evidence_bundle(
                        isolated, make_fixed_b_input_runner,
                        Path(directory) / f"isolated-{index}")
                    self.assertEqual("complete", trace.status)
                    self.assertEqual([1], [event["value"] for event in
                                           _events(trace.events, "source_injection",
                                                   action_id="fixed-b-rise")])
                    self.assertFalse(any(
                        tuple(event.get("source", ())) ==
                        ("gpio_a", "gpio_out") and
                        tuple(event.get("target", ())) ==
                        ("gpio_b", "gpio_in")
                        for event in _events(trace.events, "dataflow_delivery")))
                    self.assertTrue(any(event.get("component") == "gpio_a"
                                        and event.get("outputs", {}).get("gpio_out")
                                        == a_value for event in trace.events))
                    self.assertEqual({1}, set(_ram_writes(trace.events)))
                    self.assertTrue(_ram_writes(trace.events))


if __name__ == "__main__":
    unittest.main()
