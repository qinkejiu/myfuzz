"""DEP-03: observed edges, absent outputs, and reset epoch boundaries."""

import unittest
from dataclasses import asdict

from myfuzz.scenario.genome import Action, ResetAction, ScenarioGenome, Trigger
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.scheduler import DependencyScheduler
from myfuzz.scenario.interaction_feedback import InteractionFeedback


class _Levels:
    def __init__(self, levels):
        self.levels = iter(levels)

    def begin_case(self, testcase_id):
        pass

    def step_local(self, inputs):
        return {"irq": next(self.levels)}

    def reset_local(self):
        return {}

    def end_case(self):
        pass


class _Sink:
    def begin_case(self, testcase_id):
        pass

    def step_local(self, inputs):
        return {"seen": inputs.get("pin", 0)}

    def reset_local(self):
        return {}

    def end_case(self):
        pass


def _run(levels, actions, *, reset_actions=(), max_steps=None):
    ownership = compile_ownership(
        (InputField("sink", "pin", 2),),
        (InputOwner("sink", "pin", 0, 2, "source", "external"),))
    runner = ScenarioRunner(
        sessions={"pulse": _Levels(levels), "sink": _Sink()},
        ownership=ownership, bindings=())
    genome = ScenarioGenome(
        testcase_id="dep03-cursor", direction="IP_TO_IP", path_id="irq-done",
        schedule_order=("pulse", "sink"),
        max_steps=max_steps or 2 * len(levels), actions=actions,
        encoding_version=3 if reset_actions else 2,
        reset_actions=reset_actions)
    result = DependencyScheduler().run(runner, genome)
    return result, runner.events, runner.command_epoch


class Dep03ConsumptionCursorTests(unittest.TestCase):
    def test_trusted_journal_lookup_survives_spill_and_public_lookup_is_detached(self):
        runner = ScenarioRunner(
            sessions={"pulse": _Levels((1, 0, 1))},
            ownership=compile_ownership((), ()), bindings=())
        runner.enable_event_journal(chunk_size=2)
        runner.begin_test("trusted-event-lookup")
        try:
            for _ in range(3):
                runner.step("pulse")
            self.assertEqual(3, runner.event_count)
            borrowed = runner._event_ref_by_id(1)
            self.assertIs(borrowed, runner._events[0])
            self.assertIsNone(runner._event_ref_by_id(0))
            self.assertIsNone(runner._event_ref_by_id(4))
            public = runner.event_by_id(1)
            self.assertIsNot(public, borrowed)
            public["outputs"]["irq"] = 99
            self.assertEqual(1, runner._event_ref_by_id(1)["outputs"]["irq"])

            feedback = InteractionFeedback(event_lookup=runner._event_ref_by_id)
            feedback.ingest(runner.events_since(0))
            self.assertEqual(3, feedback.summary()["event_count"])
            with self.assertRaisesRegex(ValueError, "different evidence"):
                feedback.ingest([{"event_id": 1, "kind": "wrong"}])
        finally:
            runner.finalize()

    def test_event_window_is_bounded_read_only_and_deep_copied(self):
        runner = ScenarioRunner(
            sessions={"pulse": _Levels((1,))},
            ownership=compile_ownership((), ()), bindings=())
        runner.begin_test("event-window")
        try:
            self.assertEqual(0, runner.event_count)
            runner.step("pulse")
            self.assertEqual(1, runner.event_count)
            self.assertEqual((), runner.events_since(1))
            observed = runner.events_since(0)
            self.assertEqual((1,), tuple(event["event_id"] for event in observed))
            observed[0]["outputs"]["irq"] = 0
            self.assertEqual(1, runner.events_since(0)[0]["outputs"]["irq"])
            self.assertEqual(1, runner.event_count)
            for invalid in (-1, 2, True, 0.5):
                with self.subTest(index=invalid):
                    with self.assertRaises(ValueError):
                        runner.events_since(invalid)
            with self.assertRaises(AttributeError):
                runner.event_count = 0
        finally:
            runner.finalize()

    def test_two_rising_edges_fire_distinct_occurrences_and_held_high_does_not(self):
        actions = (
            Action("first", "sink", "pin", 1, "IP_TO_IP",
                   Trigger("AFTER_OUTPUT", "pulse", "irq", 1, 1, 1), width=2),
            Action("second", "sink", "pin", 2, "IP_TO_IP",
                   Trigger("AFTER_OUTPUT", "pulse", "irq", 1, 1, 2), width=2))
        result, events, _ = _run((0, 1, 1, 0, 1, 0), actions)
        self.assertEqual("complete", result.status)
        self.assertEqual(("first", "second"), result.fired_actions)
        observed = [event for event in events
                    if event.get("component") == "pulse" and "outputs" in event]
        self.assertEqual((0, 1, 1, 0, 1, 0),
                         tuple(event["outputs"]["irq"] for event in observed))
        injected = [event for event in events
                    if event.get("kind") == "source_injection"]
        self.assertEqual(("first", "second"),
                         tuple(event["action_id"] for event in injected))
        self.assertLess(observed[1]["event_id"], injected[0]["event_id"])
        self.assertLess(observed[4]["event_id"], injected[1]["event_id"])
        self.assertLess(observed[2]["event_id"], injected[1]["event_id"])
        self.assertEqual(observed[1]["event_id"],
                         result.consumption_cursors["first"].event_id)
        self.assertEqual(observed[4]["event_id"],
                         result.consumption_cursors["second"].event_id)
        self.assertEqual((1, 2), tuple(result.consumption_cursors[name].occurrence
                                       for name in ("first", "second")))

        held, held_events, _ = _run((1, 1, 1, 1), actions[1:])
        self.assertEqual("path_incomplete", held.status)
        self.assertEqual(("second",), held.pending_actions)
        self.assertFalse(any(event.get("kind") == "source_injection"
                             for event in held_events))
        self.assertEqual({}, held.consumption_cursors)

    def test_unobserved_done_does_not_create_a_guard_event(self):
        action = Action("after-done", "sink", "pin", 1, "IP_TO_IP",
                        Trigger("AFTER_OUTPUT", "pulse", "done", 1, 1))
        result, events, _ = _run((0, 1, 0), (action,))
        self.assertEqual("path_incomplete", result.status)
        self.assertEqual(("after-done",), result.pending_actions)
        self.assertFalse(any("done" in event.get("outputs", {}) for event in events))
        self.assertFalse(any(event.get("kind") == "source_injection"
                             for event in events))
        self.assertEqual({}, result.consumption_cursors)

    def test_reset_starts_new_edge_identity_but_keeps_event_order(self):
        second = Action("second-epoch-rise", "sink", "pin", 2, "IP_TO_IP",
                        Trigger("AFTER_OUTPUT", "pulse", "irq", 1, 1, 2),
                        width=2)
        reset = ResetAction("epoch-boundary", "warm_all",
                            Trigger("AFTER_OUTPUT", "pulse", "irq", 1, 1))
        result, events, epoch = _run((1, 1, 1), (second,),
                                     reset_actions=(reset,))
        self.assertEqual("complete", result.status)
        self.assertEqual(("epoch-boundary",), result.fired_resets)
        self.assertEqual(("second-epoch-rise",), result.fired_actions)
        self.assertEqual(1, epoch)
        rises = [event for event in events
                 if event.get("component") == "pulse"
                 and event.get("outputs", {}).get("irq") == 1]
        barrier = next(event for event in events
                       if event.get("kind") == "reset_barrier")
        injection = next(event for event in events
                         if event.get("kind") == "source_injection")
        self.assertLess(rises[0]["event_id"], barrier["event_id"])
        self.assertLess(barrier["event_id"], rises[1]["event_id"])
        self.assertLess(rises[1]["event_id"], injection["event_id"])
        self.assertEqual((rises[0]["event_id"], 0, 1),
                         (result.consumption_cursors["epoch-boundary"].event_id,
                          result.consumption_cursors["epoch-boundary"].epoch,
                          result.consumption_cursors["epoch-boundary"].occurrence))
        self.assertEqual((rises[1]["event_id"], 1, 2),
                         (result.consumption_cursors["second-epoch-rise"].event_id,
                          result.consumption_cursors["second-epoch-rise"].epoch,
                          result.consumption_cursors["second-epoch-rise"].occurrence))

    def test_result_exposes_consumed_event_cursor_with_epoch_identity(self):
        action = Action("first", "sink", "pin", 1, "IP_TO_IP",
                        Trigger("AFTER_OUTPUT", "pulse", "irq", 1, 1))
        result, _, _ = _run((0, 1), (action,))
        self.assertEqual(1, result.consumption_cursors["first"].occurrence)
        self.assertEqual(0, result.consumption_cursors["first"].epoch)
        self.assertGreater(result.consumption_cursors["first"].event_id, 0)
        self.assertEqual(("pulse", "irq"),
                         (result.consumption_cursors["first"].source_component,
                          result.consumption_cursors["first"].source_port))
        with self.assertRaises(TypeError):
            result.consumption_cursors["first"] = result.consumption_cursors["first"]
        self.assertEqual(result.consumption_cursors["first"].event_id,
                         asdict(result)["consumption_cursor_records"][0][1]["event_id"])

    def test_delayed_action_keeps_pre_reset_source_identity(self):
        action = Action("delayed", "sink", "pin", 1, "IP_TO_IP",
                        Trigger("AFTER_OUTPUT", "pulse", "irq", 1, 1),
                        delay_component="sink", delay_ticks=2)
        reset = ResetAction("reset", "warm_all", Trigger("START"),
                            delay_component="pulse", delay_ticks=1)
        result, events, epoch = _run((1, 0, 0), (action,),
                                     reset_actions=(reset,))
        self.assertEqual("complete", result.status)
        self.assertEqual(1, epoch)
        source = next(event for event in events
                      if event.get("component") == "pulse" and
                      event.get("outputs", {}).get("irq") == 1)
        barrier = next(event for event in events
                       if event.get("kind") == "reset_barrier")
        injection = next(event for event in events
                         if event.get("kind") == "source_injection")
        self.assertLess(source["event_id"], barrier["event_id"])
        self.assertLess(barrier["event_id"], injection["event_id"])
        self.assertEqual((source["event_id"], 0, 1),
                         (result.consumption_cursors["delayed"].event_id,
                          result.consumption_cursors["delayed"].epoch,
                          result.consumption_cursors["delayed"].occurrence))

    def test_start_actions_have_no_fabricated_source_event(self):
        start = Action("start", "sink", "pin", 1, "IP_TO_IP", Trigger("START"))
        reset = ResetAction("start-reset", "warm_all", Trigger("START"))
        result, events, epoch = _run((0,), (start,), reset_actions=(reset,))
        self.assertEqual("complete", result.status)
        self.assertEqual(1, epoch)
        self.assertEqual({"start", "start-reset"},
                         set(result.consumption_cursors))
        for cursor in result.consumption_cursors.values():
            self.assertIsNone(cursor.event_id)
            self.assertEqual(0, cursor.epoch)
            self.assertEqual(0, cursor.occurrence)
            self.assertEqual("START", cursor.kind)
        self.assertFalse(any(event.get("component") == "pulse" and
                             event.get("outputs", {}).get("irq") == 1
                             for event in events))


if __name__ == "__main__":
    unittest.main()
