"""Replay reruns fresh sessions and compares every observed semantic event."""

from dataclasses import replace
import unittest

from myfuzz.scenario.genome import Action, ScenarioGenome, Trigger
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.replay import _difference_context, record_scenario, replay_scenario
from myfuzz.scenario.runner import ScenarioRunner


class _Session:
    def __init__(self, output_offset=0, source_identity="source-a"):
        self.output_offset = output_offset
        self.source_identity = source_identity
        self.begins = 0

    def identity_document(self):
        return {"source_identity": self.source_identity}

    def begin_case(self, testcase_id):
        self.begins += 1

    def step_local(self, inputs):
        return {"out": inputs.get("pin", 0) + self.output_offset}

    def end_case(self):
        pass


class ReplayTests(unittest.TestCase):
    def test_difference_context_retains_transaction_and_writer_identity(self):
        expected = {"event_id": 9, "component": "cpu", "local_tick": 20,
                    "transaction": {"source_sequence": 3},
                    "memory_id": "ram", "generation": 1,
                    "byte_offset": 4, "writer_event_ids": ("store:2",)}
        actual = dict(expected, writer_event_ids=("store:5",))
        context = _difference_context(expected, actual, 8)
        self.assertEqual(3, context["transaction"]["source_sequence"])
        self.assertEqual(("store:5",), context["writer_event_id"])
        self.assertEqual(20, context["local_tick"])
        self.assertEqual(("store:2",), context["expected"]["writer_event_ids"])

    def setUp(self):
        self.genome = ScenarioGenome(
            testcase_id="replay", direction="IP_TO_IP", path_id="gpio",
            schedule_order=("gpio",), max_steps=4,
            actions=(Action("edge", "gpio", "pin", 1, "IP_TO_IP",
                            Trigger("START")),))
        self.instances = []

    def factory(self, *, offset=0, source_identity="source-a",
                producer="external"):
        session = _Session(offset, source_identity)
        self.instances.append(session)
        ownership = compile_ownership(
            (InputField("gpio", "pin", 1),),
            (InputOwner("gpio", "pin", 0, 1, "source", producer),))
        return ScenarioRunner(sessions={"gpio": session}, ownership=ownership,
                              bindings=())

    def test_replay_from_fresh_session_matches_full_trace(self):
        reference = record_scenario(self.genome, self.factory)
        compared = replay_scenario(self.genome, self.factory, reference)
        self.assertTrue(compared.matches)
        self.assertIsNone(compared.first_difference)
        self.assertEqual(2, len(self.instances))
        self.assertTrue(all(instance.begins == 1 for instance in self.instances))

    def test_first_different_real_output_is_reported(self):
        reference = record_scenario(self.genome, self.factory)
        compared = replay_scenario(self.genome, lambda: self.factory(offset=1),
                                   reference)
        self.assertFalse(compared.matches)
        self.assertEqual(1, compared.first_difference)
        self.assertNotEqual(compared.expected_event, compared.actual_event)
        self.assertEqual("gpio", compared.difference_context["component"])
        self.assertEqual(1, compared.difference_context["local_tick"])
        self.assertEqual(2, compared.difference_context["event_id"])

    def test_replay_rejects_binding_change_before_rtl_start(self):
        reference = record_scenario(self.genome, self.factory)
        with self.assertRaisesRegex(ValueError, "manifest identity"):
            replay_scenario(self.genome,
                            lambda: self.factory(producer="different-root"),
                            reference)
        self.assertEqual(0, self.instances[-1].begins)

    def test_replay_rejects_harness_source_change_before_rtl_start(self):
        reference = record_scenario(self.genome, self.factory)
        with self.assertRaisesRegex(ValueError, "manifest identity"):
            replay_scenario(self.genome,
                            lambda: self.factory(source_identity="source-b"),
                            reference)
        self.assertEqual(0, self.instances[-1].begins)

    def test_replay_rejects_reference_without_manifest_identity(self):
        reference = record_scenario(self.genome, self.factory)
        with self.assertRaisesRegex(ValueError, "manifest identity missing"):
            replay_scenario(self.genome, self.factory,
                            replace(reference, manifest_sha256=""))
        self.assertEqual(1, len(self.instances))


if __name__ == "__main__":
    unittest.main()
