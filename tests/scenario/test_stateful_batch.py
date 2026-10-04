"""Tests for reset-free online scenario batch recording and replay."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import unittest
from unittest.mock import patch

from myfuzz.scenario.batch import (
    BatchAdvance,
    BatchSourceEvent,
    MAX_BATCH_SOURCE_WIDTH_BITS,
    ScenarioBatchCodec,
    ScenarioBatchPlan,
    ScenarioBatchRecorder,
)
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.protocol_io import BoundedLineReader, read_local_reply
from myfuzz.scenario.replay import record_scenario_batch, replay_scenario_batch
from myfuzz.scenario.runner import Binding, ScenarioRunner


class RecordingSession:
    def __init__(self, *, output_name: str = "value"):
        self.output_name = output_name
        self.extra_outputs = {}
        self.begins = 0
        self.ends = 0
        self.steps = []
        self.resets = 0

    def begin_case(self, testcase_id):
        self.begins += 1

    def step_local(self, inputs):
        snapshot = dict(inputs)
        self.steps.append(snapshot)
        return {self.output_name: snapshot.get("source", 0), **self.extra_outputs}

    def end_case(self):
        self.ends += 1


class DeadlineBoundarySession(RecordingSession):
    """Exercise partial local effects before STEP or END reply deadlines."""

    max_local_ticks_per_step = 1

    def __init__(self, *, block_step: bool = False,
                 delayed_end_reply: bool = False, end_delay_s: float = 0):
        super().__init__()
        self.block_step = block_step
        self.delayed_end_reply = delayed_end_reply
        self.end_delay_s = end_delay_s
        self.local_ticks = 0
        self._samples = []
        self._read_fd = None
        self._write_fd = None
        self._line_reader = BoundedLineReader()
        self._stream = None

    def begin_case(self, testcase_id):
        super().begin_case(testcase_id)
        self._read_fd, self._write_fd = os.pipe()
        self._line_reader.reset()
        self._stream = os.fdopen(self._read_fd, "r", encoding="ascii",
                                 buffering=1)

    def step_local(self, inputs):
        self.local_ticks += 1
        if self.block_step:
            self._samples.append({
                "local_tick": self.local_ticks,
                "pre": {"irq": 0},
                "post": {"irq": 0},
            })
            read_local_reply(self, self._stream)
        self.steps.append(dict(inputs))
        return {"value": inputs.get("source", 0)}

    def drain_tick_samples(self):
        samples, self._samples = self._samples, []
        return samples

    def end_case(self):
        self.ends += 1
        if self.end_delay_s:
            # Model process cleanup that reaches its deadline, kills/reaps the
            # child, and returns without surfacing the lower-level timeout.
            time.sleep(self.end_delay_s)
        if self.delayed_end_reply:
            if self._write_fd is None or self._stream is None:
                raise RuntimeError("session pipe was not started")
            reply_fd = os.dup(self._write_fd)

            def release_reply():
                try:
                    time.sleep(0.05)
                    os.write(reply_fd, b"END\n")
                except OSError:
                    pass
                finally:
                    os.close(reply_fd)

            threading.Thread(target=release_reply, daemon=True).start()
            try:
                read_local_reply(self, self._stream)
            finally:
                self._close_pipe()
            return
        self._close_pipe()

    def _close_pipe(self):
        if self._write_fd is not None:
            try:
                os.close(self._write_fd)
            except OSError:
                pass
            self._write_fd = None
        if self._stream is not None:
            try:
                self._stream.close()
            except OSError:
                pass
            self._stream = None


def template(*, max_steps: int = 8) -> ScenarioGenome:
    return ScenarioGenome(
        testcase_id="online-batch", direction="CPU_TO_IP", path_id="unit-path",
        schedule_order=("cpu", "gpio"), max_steps=max_steps, actions=())


def make_factory(runners=None):
    if runners is None:
        runners = []

    def factory():
        cpu = RecordingSession()
        gpio = RecordingSession()
        ownership = compile_ownership(
            (InputField("cpu", "source", 8), InputField("cpu", "irq", 1),
             InputField("gpio", "source", 8), InputField("gpio", "irq_out", 1)),
            (InputOwner("cpu", "source", 0, 8, "source", "program"),
             InputOwner("cpu", "irq", 0, 1, "bound", "gpio.irq_out"),
             InputOwner("gpio", "source", 0, 8, "source", "external"),
             InputOwner("gpio", "irq_out", 0, 1, "fixed", "constant_zero")))
        runner = ScenarioRunner(
            sessions={"cpu": cpu, "gpio": gpio}, ownership=ownership,
            bindings=(Binding("gpio", "irq_out", "cpu", "irq", 1),))
        runners.append(runner)
        return runner

    return factory, runners


class ScenarioBatchCodecTests(unittest.TestCase):
    def setUp(self):
        self.plan = ScenarioBatchPlan(
            template(),
            (BatchSourceEvent("gpio-high", "gpio", "source", 0x49),
             BatchAdvance(("gpio", "cpu")),
             BatchSourceEvent("gpio-low", "gpio", "source", 0)))

    def test_encode_decode_round_trip_is_immutable_and_canonical(self):
        encoded = ScenarioBatchCodec.encode(self.plan)
        self.assertIsInstance(encoded, bytes)
        self.assertEqual(self.plan, ScenarioBatchCodec.decode(encoded))
        self.assertEqual(encoded, ScenarioBatchCodec.encode(
            ScenarioBatchCodec.decode(encoded)))

    def test_decode_rejects_unknown_or_missing_fields(self):
        document = json.loads(ScenarioBatchCodec.encode(self.plan))
        document["unexpected"] = 1
        with self.assertRaisesRegex(ValueError, "unknown or missing"):
            ScenarioBatchCodec.decode(json.dumps(document).encode())
        document.pop("unexpected")
        document["commands"][0].pop("port")
        with self.assertRaisesRegex(ValueError, "unknown or missing"):
            ScenarioBatchCodec.decode(json.dumps(document).encode())

    def test_decode_rejects_duplicate_json_object_keys(self):
        raw = (b'{"commands":[],"schema_version":1,"schema_version":1,'
               b'"template":{}}')
        with self.assertRaisesRegex(ValueError, "invalid batch plan JSON"):
            ScenarioBatchCodec.decode(raw)

    def test_decode_rejects_width_far_above_supported_limit(self):
        document = json.loads(ScenarioBatchCodec.encode(self.plan))
        document["commands"][0]["width"] = 1 << 63
        document["commands"][0]["value"] = 1
        raw = json.dumps(document, separators=(",", ":")).encode()
        with self.assertRaisesRegex(ValueError, "width exceeds maximum"):
            ScenarioBatchCodec.decode(raw)

    def test_source_event_width_limit_is_inclusive_and_bounded(self):
        BatchSourceEvent("max-width", "gpio", "source", 0,
                         width=MAX_BATCH_SOURCE_WIDTH_BITS)
        with self.assertRaisesRegex(ValueError, "width exceeds maximum"):
            BatchSourceEvent("over-width", "gpio", "source", 0,
                             width=MAX_BATCH_SOURCE_WIDTH_BITS + 1)

    def test_plan_rejects_duplicate_action_ids_invalid_width_and_bad_schedule(self):
        duplicate = (BatchSourceEvent("same", "gpio", "source", 1),
                     BatchSourceEvent("same", "gpio", "source", 2))
        with self.assertRaisesRegex(ValueError, "unique"):
            ScenarioBatchPlan(template(), duplicate)
        with self.assertRaisesRegex(ValueError, "width"):
            BatchSourceEvent("bad-width", "gpio", "source", 1, width=0)
        with self.assertRaisesRegex(ValueError, "schedule"):
            BatchAdvance(())
        with self.assertRaisesRegex(ValueError, "unknown component"):
            ScenarioBatchPlan(template(), (BatchAdvance(("missing",)),))

    def test_decode_rejects_duplicate_ids_invalid_width_and_malformed_schedules(self):
        document = json.loads(ScenarioBatchCodec.encode(self.plan))
        document["commands"].append(dict(document["commands"][0]))
        with self.assertRaisesRegex(ValueError, "unique"):
            ScenarioBatchCodec.decode(json.dumps(document).encode())
        document["commands"].pop()
        document["commands"][0]["width"] = 0
        with self.assertRaisesRegex(ValueError, "width"):
            ScenarioBatchCodec.decode(json.dumps(document).encode())
        document = json.loads(ScenarioBatchCodec.encode(self.plan))
        document["commands"][1]["schedule"] = []
        with self.assertRaisesRegex(ValueError, "schedule"):
            ScenarioBatchCodec.decode(json.dumps(document).encode())

    def test_template_rejects_preencoded_actions_resets_or_quiesce(self):
        from myfuzz.scenario.genome import Action, ResetAction, Trigger
        from dataclasses import replace

        action = Action("one", "gpio", "source", 1, "CPU_TO_IP", Trigger("START"))
        with self.assertRaisesRegex(ValueError, "actions"):
            ScenarioBatchPlan(template().__class__(
                testcase_id="x", direction="CPU_TO_IP", path_id="x",
                schedule_order=("cpu", "gpio"), max_steps=8, actions=(action,)), ())
        reset_template = replace(
            template(), encoding_version=3,
            reset_actions=(ResetAction("reset", "cold_all", Trigger("START")),))
        with self.assertRaisesRegex(ValueError, "resets"):
            ScenarioBatchPlan(reset_template, ())
        quiesce_template = replace(template(), encoding_version=3, quiesce_steps=1)
        with self.assertRaisesRegex(ValueError, "quiesce"):
            ScenarioBatchPlan(quiesce_template, ())


class ScenarioBatchRecorderTests(unittest.TestCase):
    def test_one_begin_one_finish_and_later_input_after_advance(self):
        factory, runners = make_factory()
        runner = factory()
        recorder = ScenarioBatchRecorder(template(), runner)
        recorder.begin()
        recorder.submit_source_event(BatchSourceEvent(
            "program", "cpu", "source", 0x35))
        outputs = recorder.advance(("cpu",))
        recorder.submit_source_event(BatchSourceEvent(
            "external", "gpio", "source", 0x49))
        recorder.advance(("gpio", "cpu"))
        trace = recorder.finish()

        self.assertEqual("complete", trace.status)
        self.assertEqual(1, runner.sessions["cpu"].begins)
        self.assertEqual(1, runner.sessions["gpio"].begins)
        self.assertEqual(1, runner.sessions["cpu"].ends)
        self.assertEqual(1, runner.sessions["gpio"].ends)
        self.assertEqual(0, runner.sessions["cpu"].resets)
        self.assertEqual(0, runner.sessions["gpio"].resets)
        self.assertEqual(({"value": 0x35},), outputs)
        self.assertEqual(0x35, runner.sessions["cpu"].steps[0]["source"])
        self.assertEqual(0x49, runner.sessions["gpio"].steps[0]["source"])
        self.assertEqual(4, len(recorder.plan.commands))
        self.assertEqual(("program", "external"), tuple(
            command.action_id for command in recorder.plan.commands
            if isinstance(command, BatchSourceEvent)))

    def test_source_action_identity_cannot_be_reused(self):
        runner = make_factory()[0]()
        recorder = ScenarioBatchRecorder(template(), runner)
        recorder.begin()
        event = BatchSourceEvent("same", "cpu", "source", 1)
        recorder.submit_source_event(event)
        with self.assertRaisesRegex(ValueError, "unique"):
            recorder.submit_source_event(event)
        recorder.finish()
        self.assertEqual(1, sum(e.get("kind") == "source_injection"
                                for e in runner.events))

    def test_bound_input_cannot_be_admitted(self):
        runner = make_factory()[0]()
        recorder = ScenarioBatchRecorder(template(), runner)
        recorder.begin()
        with self.assertRaisesRegex(ValueError, "bound"):
            recorder.submit_source_event(BatchSourceEvent(
                "irq", "cpu", "irq", 1))
        recorder.finish()
        self.assertFalse(any(e.get("kind") == "source_injection"
                             and e.get("port") == "irq" for e in runner.events))

    def test_advance_enforces_max_steps_atomically(self):
        runner = make_factory()[0]()
        recorder = ScenarioBatchRecorder(template(max_steps=2), runner)
        recorder.begin()
        with self.assertRaisesRegex(ValueError, "max_steps"):
            recorder.advance(("cpu", "gpio", "cpu"))
        self.assertEqual({"cpu": 0, "gpio": 0}, runner.local_ticks)
        self.assertEqual((), recorder.commands)
        recorder.finish()

    def test_implicit_ownership_width_is_capped_before_source_validation(self):
        runner = make_factory()[0]()
        runner.ownership.field_width = lambda *_: MAX_BATCH_SOURCE_WIDTH_BITS + 1
        runner.ownership.mutation_source = lambda *args, **kwargs: self.fail(
            "oversized ownership width reached source validation")
        recorder = ScenarioBatchRecorder(template(), runner)
        recorder.begin()
        with self.assertRaisesRegex(ValueError, "selected source width exceeds maximum"):
            recorder.submit_source_event(BatchSourceEvent(
                "oversized-field", "cpu", "source", 0))
        self.assertFalse(any(event.get("kind") == "source_injection"
                             for event in runner.events))
        recorder.finish()

    def test_actual_semantic_budget_failure_records_attempt_and_replays(self):
        from myfuzz.scenario.contracts import ResourceBudget

        def budget_factory():
            runner = make_factory()[0]()
            runner.set_resource_budget(ResourceBudget(max_semantic_records=1))
            return runner

        source = BatchSourceEvent("budget-rejected", "cpu", "source", 0x35)
        plan = ScenarioBatchPlan(template(), (source,))
        trace = record_scenario_batch(plan, budget_factory)
        self.assertEqual("budget_exhausted", trace.status)
        self.assertEqual(hashlib.sha256(ScenarioBatchCodec.encode(plan)).hexdigest(),
                         trace.genome_sha256)
        self.assertFalse(any(item.get("kind") == "source_injection"
                             for item in trace.events))
        self.assertTrue(any(item.get("kind") == "budget_exhausted"
                            and item.get("phase") == "before_source_injection"
                            for item in trace.events))
        replay = replay_scenario_batch(plan, budget_factory, trace)
        self.assertTrue(replay.matches, replay.difference_context)

    def test_recorder_rejects_duplicate_lifecycle_calls(self):
        runner = make_factory()[0]()
        recorder = ScenarioBatchRecorder(template(), runner)
        recorder.begin()
        with self.assertRaisesRegex(RuntimeError, "once"):
            recorder.begin()
        recorder.finish()
        with self.assertRaisesRegex(RuntimeError, "once"):
            recorder.finish()

    def test_bound_data_is_not_overwritten_when_other_source_is_mutated(self):
        runner = make_factory()[0]()
        recorder = ScenarioBatchRecorder(template(), runner)
        recorder.begin()
        # An actual GPIO IRQ output is routed by the existing runner as a
        # bound CPU input. The recorder has no API that accepts that CPU field.
        runner.sessions["gpio"].extra_outputs = {"irq_out": 1}
        recorder.submit_source_event(BatchSourceEvent(
            "gpio-external", "gpio", "source", 0xA5))
        recorder.advance(("gpio", "cpu"))
        self.assertEqual(1, runner.sessions["cpu"].steps[0]["irq"])
        recorder.finish()


class ScenarioBatchReplayTests(unittest.TestCase):
    def test_inflight_step_replay_preserves_partial_ticks_and_failure_events(self):
        from myfuzz.scenario.contracts import ResourceBudget

        runners = []

        def budget_factory():
            cpu = DeadlineBoundarySession(block_step=True)
            gpio = RecordingSession()
            ownership = compile_ownership(
                (InputField("cpu", "source", 8), InputField("cpu", "irq", 1),
                 InputField("gpio", "source", 8), InputField("gpio", "irq_out", 1)),
                (InputOwner("cpu", "source", 0, 8, "source", "program"),
                 InputOwner("cpu", "irq", 0, 1, "bound", "gpio.irq_out"),
                 InputOwner("gpio", "source", 0, 8, "source", "external"),
                 InputOwner("gpio", "irq_out", 0, 1, "fixed", "constant_zero")))
            runner = ScenarioRunner(
                sessions={"cpu": cpu, "gpio": gpio}, ownership=ownership,
                bindings=(Binding("gpio", "irq_out", "cpu", "irq", 1),))
            runner.set_resource_budget(ResourceBudget(max_wall_time_ms=25))
            runners.append(runner)
            return runner

        plan = ScenarioBatchPlan(template(), (BatchAdvance(("cpu",)),))
        reference = record_scenario_batch(plan, budget_factory)
        kinds = [event["kind"] for event in reference.events]
        self.assertEqual("budget_exhausted", reference.status)
        self.assertEqual(["harness_failure", "local_tick_sample",
                          "local_tick_sample", "budget_exhausted"], kinds)
        self.assertEqual(1, reference.local_ticks["cpu"])

        replay = replay_scenario_batch(plan, budget_factory, reference)
        self.assertTrue(replay.matches, replay.difference_context)

    def test_inflight_finalize_replay_preserves_cleanup_deadline_evidence(self):
        from myfuzz.scenario.contracts import ResourceBudget

        runners = []

        def budget_factory():
            cpu = RecordingSession()
            gpio = DeadlineBoundarySession(delayed_end_reply=True)
            ownership = compile_ownership(
                (InputField("cpu", "source", 8), InputField("cpu", "irq", 1),
                 InputField("gpio", "source", 8), InputField("gpio", "irq_out", 1)),
                (InputOwner("cpu", "source", 0, 8, "source", "program"),
                 InputOwner("cpu", "irq", 0, 1, "bound", "gpio.irq_out"),
                 InputOwner("gpio", "source", 0, 8, "source", "external"),
                 InputOwner("gpio", "irq_out", 0, 1, "fixed", "constant_zero")))
            runner = ScenarioRunner(
                sessions={"cpu": cpu, "gpio": gpio}, ownership=ownership,
                bindings=(Binding("gpio", "irq_out", "cpu", "irq", 1),))
            runner.set_resource_budget(ResourceBudget(max_wall_time_ms=25))
            runners.append(runner)
            return runner

        plan = ScenarioBatchPlan(template(), (BatchAdvance(("cpu",)),))
        reference = record_scenario_batch(plan, budget_factory)
        marker = reference.events[-1]
        self.assertEqual("budget_exhausted", reference.status)
        self.assertEqual("inflight_finalize", marker["phase"])
        self.assertEqual([{"component": "gpio",
                           "error_type": "LocalCommandDeadlineExceeded"}],
                         marker["cleanup_errors"])

        replay = replay_scenario_batch(plan, budget_factory, reference)
        self.assertTrue(replay.matches, replay.difference_context)

    def test_inflight_finalize_replay_mismatches_if_cleanup_finishes_early(self):
        from myfuzz.scenario.contracts import ResourceBudget

        factory_calls = 0

        def budget_factory():
            nonlocal factory_calls
            factory_calls += 1
            cpu = RecordingSession()
            # The original cleanup crosses its wall deadline but behaves like
            # end_local_process: it handles the low-level timeout internally.
            gpio = DeadlineBoundarySession(end_delay_s=(0.05
                                                        if factory_calls == 1
                                                        else 0))
            ownership = compile_ownership(
                (InputField("cpu", "source", 8), InputField("cpu", "irq", 1),
                 InputField("gpio", "source", 8), InputField("gpio", "irq_out", 1)),
                (InputOwner("cpu", "source", 0, 8, "source", "program"),
                 InputOwner("cpu", "irq", 0, 1, "bound", "gpio.irq_out"),
                 InputOwner("gpio", "source", 0, 8, "source", "external"),
                 InputOwner("gpio", "irq_out", 0, 1, "fixed", "constant_zero")))
            runner = ScenarioRunner(
                sessions={"cpu": cpu, "gpio": gpio}, ownership=ownership,
                bindings=(Binding("gpio", "irq_out", "cpu", "irq", 1),))
            runner.set_resource_budget(ResourceBudget(max_wall_time_ms=25))
            return runner

        plan = ScenarioBatchPlan(template(), (BatchAdvance(("cpu",)),))
        reference = record_scenario_batch(plan, budget_factory)
        marker = reference.events[-1]
        self.assertEqual("budget_exhausted", reference.status)
        self.assertEqual("inflight_finalize", marker["phase"])
        self.assertNotIn("cleanup_errors", marker)

        replay = replay_scenario_batch(plan, budget_factory, reference)
        self.assertFalse(replay.matches, replay.difference_context)

    def test_batch_replay_rejects_finalize_wall_cut_without_timeout_window(self):
        from dataclasses import replace
        from myfuzz.scenario.contracts import ResourceBudget

        factory_calls = 0

        def budget_factory():
            nonlocal factory_calls
            factory_calls += 1
            cpu = RecordingSession()
            gpio = DeadlineBoundarySession(end_delay_s=(0.05
                                                        if factory_calls == 1
                                                        else 0))
            ownership = compile_ownership(
                (InputField("cpu", "source", 8), InputField("cpu", "irq", 1),
                 InputField("gpio", "source", 8), InputField("gpio", "irq_out", 1)),
                (InputOwner("cpu", "source", 0, 8, "source", "program"),
                 InputOwner("cpu", "irq", 0, 1, "bound", "gpio.irq_out"),
                 InputOwner("gpio", "source", 0, 8, "source", "external"),
                 InputOwner("gpio", "irq_out", 0, 1, "fixed", "constant_zero")))
            runner = ScenarioRunner(
                sessions={"cpu": cpu, "gpio": gpio}, ownership=ownership,
                bindings=(Binding("gpio", "irq_out", "cpu", "irq", 1),))
            runner.set_resource_budget(ResourceBudget(max_wall_time_ms=25))
            return runner

        plan = ScenarioBatchPlan(template(), (BatchAdvance(("cpu",)),))
        trace = record_scenario_batch(plan, budget_factory)
        self.assertEqual("inflight_finalize", trace.events[-1]["phase"])
        marker = dict(trace.events[-1])
        marker.pop("finalize_timeout_us", None)
        events = (*trace.events[:-1], marker)
        incomplete = replace(trace, events=events)
        with self.assertRaisesRegex(ValueError, "finalize wall-time marker"):
            replay_scenario_batch(plan, budget_factory, incomplete)

    def test_runner_rejects_unbounded_inflight_finalize_replay_cut(self):
        from myfuzz.scenario.contracts import ResourceBudget

        runner = make_factory()[0]()
        runner.set_resource_budget(ResourceBudget(max_wall_time_ms=25))
        with self.assertRaisesRegex(ValueError, "finalize_timeout_us is required"):
            runner.set_replay_wall_cut(
                0, "inflight_finalize", prefix_event_count=0)

    def test_batch_replay_restores_a_wall_cut_before_source_admission(self):
        from myfuzz.scenario.contracts import ResourceBudget
        from myfuzz.scenario.runner import ScenarioBudgetExhausted

        def budget_factory():
            runner = make_factory()[0]()
            runner.set_resource_budget(ResourceBudget(max_wall_time_ms=60_000))
            return runner

        source = BatchSourceEvent("wall-cut", "cpu", "source", 0x35)
        plan = ScenarioBatchPlan(template(), (source,))
        runner = budget_factory()
        recorder = ScenarioBatchRecorder(template(), runner)
        now = [100.0]
        with patch("myfuzz.scenario.runner.time.monotonic",
                   side_effect=lambda: now[0]):
            recorder.begin()
            now[0] = 200.0
            with self.assertRaises(ScenarioBudgetExhausted):
                recorder.submit_source_event(source)
            reference = recorder.finish()

        self.assertEqual("budget_exhausted", reference.status)
        marker = next(event for event in reference.events
                      if event.get("kind") == "budget_exhausted")
        self.assertEqual("before_source_injection", marker["phase"])
        self.assertEqual((source,), recorder.plan.commands)
        replay = replay_scenario_batch(recorder.plan, budget_factory, reference)
        self.assertTrue(replay.matches, replay.difference_context)

    def test_batch_replays_same_full_trace_in_fresh_runtime(self):
        plan = ScenarioBatchPlan(
            template(),
            (BatchSourceEvent("program", "cpu", "source", 0x35),
             BatchAdvance(("cpu", "gpio")),
             BatchSourceEvent("external", "gpio", "source", 0x49),
             BatchAdvance(("gpio", "cpu", "cpu"))))
        factory, runners = make_factory()
        reference = record_scenario_batch(plan, factory)
        replay = replay_scenario_batch(plan, factory, reference)
        self.assertTrue(replay.matches, replay.difference_context)
        self.assertEqual(2, len(runners))
        self.assertIsNot(runners[0], runners[1])
        self.assertEqual(1, runners[0].sessions["cpu"].begins)
        self.assertEqual(1, runners[1].sessions["cpu"].begins)
        self.assertEqual(reference.events, replay.actual_trace.events)
        self.assertEqual(reference.local_ticks, replay.actual_trace.local_ticks)

    def test_replay_rejects_a_different_command_plan_identity(self):
        factory, _ = make_factory()
        original = ScenarioBatchPlan(
            template(), (BatchAdvance(("cpu",)),))
        changed = ScenarioBatchPlan(
            template(), (BatchAdvance(("gpio",)),))
        trace = record_scenario_batch(original, factory)
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            replay_scenario_batch(changed, factory, trace)

    def test_replay_identity_preserves_advance_call_boundaries(self):
        factory, runners = make_factory()
        grouped = ScenarioBatchPlan(
            template(), (BatchAdvance(("cpu", "gpio")),))
        split = ScenarioBatchPlan(
            template(), (BatchAdvance(("cpu",)), BatchAdvance(("gpio",))))
        trace = record_scenario_batch(grouped, factory)
        # These plans flatten to the same local step order but represent
        # different online calls and therefore have different replay identity.
        self.assertEqual(2, sum(len(command.schedule) for command in grouped.commands
                                if isinstance(command, BatchAdvance)))
        self.assertEqual(2, sum(len(command.schedule) for command in split.commands
                                if isinstance(command, BatchAdvance)))
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            replay_scenario_batch(split, factory, trace)
        self.assertEqual(1, len(runners))


if __name__ == "__main__":
    unittest.main()
