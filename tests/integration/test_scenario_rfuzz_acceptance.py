"""FUZ-04 and abstract-boundary acceptance probes for scenario RFuzz."""

from __future__ import annotations

import hashlib
import json
import unittest
from unittest.mock import patch

from myfuzz.integration.rfuzz_wire import InputBatch
from myfuzz.integration.scenario_rfuzz import (
    ProtocolEnvironmentError, ScenarioRfuzzExecutor, _trace_wall_cut,
)
from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.genome import Action, MemoryImage, ScenarioGenome, Trigger
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.rfuzz_decoder import DecoderTemplate, GenomeRecordDecoder
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.replay import ScenarioTrace


class LocalSession:
    def __init__(self, error=None, error_type=ProtocolEnvironmentError):
        self.error = error
        self.error_type = error_type
        self.steps = 0

    def begin_case(self, testcase_id):
        self.steps = 0

    def step_local(self, inputs):
        self.steps += 1
        if self.error:
            raise self.error_type(self.error)
        return {"observed": inputs.get("pin", 0)}

    def end_case(self):
        pass


def executor_for(error=None, checker=None, error_type=ProtocolEnvironmentError):
    ownership = compile_ownership(
        (InputField("local", "pin", 1),),
        (InputOwner("local", "pin", 0, 1, "source", "external_pin"),))
    graph = DependencyGraph(
        sources=(FuzzableSource("local.pin", "local", "pin", 0, 1,
                                ("IP_TO_IP",)),),
        rules=(DependencyRule("local.observed", ("local.pin",),
                              "DATA_BINDING"),))
    genome = ScenarioGenome(
        testcase_id="identity-seed", direction="IP_TO_IP", path_id="local",
        schedule_order=("local",), max_steps=3,
        actions=(Action("drive", "local", "pin", 0, "IP_TO_IP",
                        Trigger("START"), width=1),))
    decoder = GenomeRecordDecoder(
        graph=graph, ownership=ownership,
        templates=(DecoderTemplate("local.observed", genome),))
    return ScenarioRfuzzExecutor(
        run_id="acceptance-run", decoder=decoder,
        factory=lambda: ScenarioRunner(
            sessions={"local": LocalSession(error, error_type)}, ownership=ownership,
            bindings=()),
        targets=(CoverageTarget("local.observed", "local", "observed", 1, 1),),
        checker=checker, allow_legacy_search=True)


class ScenarioRfuzzAcceptanceTests(unittest.TestCase):
    def test_finalize_wall_cut_kept_when_prior_status_is_uncertain(self):
        prefix = {"event_id": 1, "kind": "harness_failure", "component": "cpu"}
        marker = {"event_id": 2, "kind": "budget_exhausted",
                  "limit": "max_wall_time_ms", "phase": "inflight_finalize",
                  "effect_may_have_occurred": True,
                  "status_before_finalize": "uncertain_effect",
                  "prefix_event_count": 1, "prefix_local_ticks": {"cpu": 1},
                  "local_ticks": {"cpu": 1}, "finalize_timeout_us": 1200}
        trace = ScenarioTrace("genome", "uncertain_effect", (prefix, marker),
                              {"cpu": 1}, "semantic")
        cut = _trace_wall_cut(trace)
        self.assertIsNotNone(cut)
        encoded = json.dumps((prefix,), sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(hashlib.sha256(encoded).hexdigest(),
                         cut["semantic_prefix_sha256"])

    def test_selected_gpio_source_requires_matching_injection_and_later_step(self):
        executor = executor_for()
        selected = bytes((0, 0, 0, 0, 0, 1, 0, 0))
        traces = (
            ({"event_id": 1, "component": "local", "inputs": {"pin": 1}},),
            ({"event_id": 1, "kind": "source_injection", "action_id": "other",
              "component": "local", "port": "pin", "bit_offset": 0,
              "width": 1, "value": 1, "direction": "IP_TO_IP",
              "source_ref": "external_pin"},
             {"event_id": 2, "component": "local", "inputs": {"pin": 1}}),
            ({"event_id": 1, "kind": "source_injection", "action_id": "drive",
              "component": "local", "port": "pin", "bit_offset": 0,
              "width": 1, "value": 1, "direction": "IP_TO_IP",
              "source_ref": "external_pin"},
             {"event_id": 2, "component": "local", "inputs": {"pin": 1}}),
        )
        with patch("myfuzz.integration.scenario_rfuzz.record_scenario",
                   side_effect=(ScenarioTrace("genome", "budget_exhausted", events,
                                              {"local": 1}, "semantic")
                                for events in traces)):
            for index in range(3):
                executor.execute_batch(InputBatch(index + 1, 8, ((selected,),)))
        self.assertEqual(("local.pin",), executor.receipts[0].applied_sources)
        self.assertEqual(((), (), ("local.pin",)),
                         tuple(r.applied_source_ids for r in executor.receipts))
        self.assertEqual({"local.pin": 1}, executor.applied_source_uses)

    def test_selected_cpu_image_requires_read_of_mutated_initial_byte(self):
        graph = DependencyGraph(
            sources=(FuzzableSource("cpu.program", "cpu", "main", 8, 1,
                                    ("CPU_TO_IP",), kind="memory_image"),),
            rules=(DependencyRule("cpu.fetch", ("cpu.program",),
                                  "DATA_BINDING"),))
        ownership = compile_ownership((), ())
        genome = ScenarioGenome(
            testcase_id="seed", direction="CPU_TO_IP", path_id="cpu",
            schedule_order=("cpu",), max_steps=2, actions=(),
            initial_images=(MemoryImage("main", "cpu", 0x1000, "0000"),))
        decoder = GenomeRecordDecoder(
            graph=graph, ownership=ownership,
            templates=(DecoderTemplate("cpu.fetch", genome),))
        executor = ScenarioRfuzzExecutor(
            run_id="image-use", decoder=decoder, factory=lambda: None,
            targets=(CoverageTarget("cpu.fetch", "cpu", "fetch", 1, 1),),
            allow_legacy_search=True)
        selected = bytes((0, 0, 0, 0, 0, 1, 0, 0))
        image_event = {"event_id": 1, "kind": "initial_image", "image_id": "main",
                       "component": "cpu", "address": 0x1000, "data_hex": "0001"}
        reads = (
            (image_event, {"event_id": 2, "kind": "memory_read", "component": "cpu",
                           "address": 0x1000, "width_bytes": 1, "data_hex": "00",
                           "transaction": {"channel_id": "instr"},
                           "writer_event_ids": ("initial-image",)}),
            (image_event, {"event_id": 2, "kind": "memory_read", "component": "cpu",
                           "address": 0x1001, "width_bytes": 1, "data_hex": "01",
                           "transaction": {"channel_id": "instr"},
                           "writer_event_ids": ("real-write",)}),
            (image_event, {"event_id": 2, "kind": "memory_read", "component": "cpu",
                           "address": 0x1001, "width_bytes": 1, "data_hex": "01",
                           "transaction": {"channel_id": "data"},
                           "writer_event_ids": ("initial-image",)}),
            (image_event, {"event_id": 2, "kind": "memory_read", "component": "cpu",
                           "address": 0x1001, "width_bytes": 1, "data_hex": "01",
                           "transaction": {"channel_id": "instr"},
                           "writer_event_ids": ("initial-image",)}),
        )
        with patch("myfuzz.integration.scenario_rfuzz.record_scenario",
                   side_effect=(ScenarioTrace("genome", "complete", events,
                                              {"cpu": 1}, "semantic")
                                for events in reads)):
            for index in range(4):
                executor.execute_batch(InputBatch(index + 1, 8, ((selected,),)))
        self.assertEqual(((), (), (), ("cpu.program",)),
                         tuple(r.applied_source_ids for r in executor.receipts))
        self.assertEqual({"cpu.program": 1}, executor.applied_source_uses)

    def test_two_selected_bit_flips_cancel_before_source_is_used(self):
        executor = executor_for()
        selected = bytes((0, 0, 0, 0, 0, 1, 0, 0))
        events = (
            {"event_id": 1, "kind": "source_injection", "action_id": "drive",
             "component": "local", "port": "pin", "bit_offset": 0,
             "width": 1, "value": 0, "direction": "IP_TO_IP",
             "source_ref": "external_pin"},
            {"event_id": 2, "component": "local", "inputs": {"pin": 0}},
        )
        with patch("myfuzz.integration.scenario_rfuzz.record_scenario",
                   return_value=ScenarioTrace("genome", "complete", events,
                                              {"local": 1}, "semantic")):
            executor.execute_batch(InputBatch(1, 8, ((selected, selected),)))
        self.assertEqual(("local.pin",), executor.receipts[0].applied_sources)
        self.assertEqual((), executor.receipts[0].applied_source_ids)
        self.assertEqual({"local.pin": 0}, executor.applied_source_uses)

    def test_two_selected_image_bit_flips_cancel_before_instruction_read(self):
        graph = DependencyGraph(
            sources=(FuzzableSource("cpu.program", "cpu", "main", 0, 1,
                                    ("CPU_TO_IP",), kind="memory_image"),),
            rules=(DependencyRule("cpu.fetch", ("cpu.program",),
                                  "DATA_BINDING"),))
        genome = ScenarioGenome(
            testcase_id="seed", direction="CPU_TO_IP", path_id="cpu",
            schedule_order=("cpu",), max_steps=2, actions=(),
            initial_images=(MemoryImage("main", "cpu", 0x1000, "00"),))
        decoder = GenomeRecordDecoder(
            graph=graph, ownership=compile_ownership((), ()),
            templates=(DecoderTemplate("cpu.fetch", genome),))
        executor = ScenarioRfuzzExecutor(
            run_id="image-cancel", decoder=decoder, factory=lambda: None,
            targets=(CoverageTarget("cpu.fetch", "cpu", "fetch", 1, 1),),
            allow_legacy_search=True)
        events = (
            {"event_id": 1, "kind": "initial_image", "image_id": "main",
             "component": "cpu", "address": 0x1000, "data_hex": "00"},
            {"event_id": 2, "kind": "memory_read", "component": "cpu",
             "address": 0x1000, "width_bytes": 1, "data_hex": "00",
             "transaction": {"channel_id": "instr"},
             "writer_event_ids": ("initial-image",)},
        )
        selected = bytes((0, 0, 0, 0, 0, 1, 0, 0))
        with patch("myfuzz.integration.scenario_rfuzz.record_scenario",
                   return_value=ScenarioTrace("genome", "complete", events,
                                              {"cpu": 1}, "semantic")):
            executor.execute_batch(InputBatch(1, 8, ((selected, selected),)))
        self.assertEqual(("cpu.program",), executor.receipts[0].applied_sources)
        self.assertEqual((), executor.receipts[0].applied_source_ids)
        self.assertEqual({"cpu.program": 0}, executor.applied_source_uses)

    def test_receipts_count_only_mutated_source_not_unconsumed_hints(self):
        ownership = compile_ownership(
            (InputField("local", "pin", 2),),
            (InputOwner("local", "pin", 0, 1, "source", "pin0"),
             InputOwner("local", "pin", 1, 1, "source", "pin1")))
        graph = DependencyGraph(
            sources=(FuzzableSource("pin0", "local", "pin", 0, 1,
                                    ("IP_TO_IP",)),
                     FuzzableSource("pin1", "local", "pin", 1, 1,
                                    ("IP_TO_IP",))),
            rules=(DependencyRule("local.observed", ("pin0", "pin1"),
                                  "DATA_BINDING"),))
        genome = ScenarioGenome(
            testcase_id="seed", direction="IP_TO_IP", path_id="local",
            schedule_order=("local",), max_steps=3,
            actions=(Action("drive0", "local", "pin", 0, "IP_TO_IP",
                            Trigger("START"), width=1),
                     Action("drive1", "local", "pin", 0, "IP_TO_IP",
                            Trigger("START"), bit_offset=1, width=1)))
        decoder = GenomeRecordDecoder(
            graph=graph, ownership=ownership,
            templates=(DecoderTemplate("local.observed", genome),))
        executor = ScenarioRfuzzExecutor(
            run_id="source-evidence", decoder=decoder,
            factory=lambda: ScenarioRunner(
                sessions={"local": LocalSession()}, ownership=ownership,
                bindings=()),
            targets=(CoverageTarget("local.observed", "local", "observed", 2, 2),),
            allow_legacy_search=True)
        hints = []
        for sequence, source in enumerate((0, 1, 0), 1):
            hint = {"sequence": sequence, "template": 0, "path": 0,
                    "source": source}
            executor.note_published_hint(hint)
            hints.append(hint)
        self.assertEqual({"pin0": 0, "pin1": 0}, executor.applied_source_uses)
        seed = bytes(8)
        source1 = bytes((0, 0, 1, 0, 0, 1, 0, 0))
        executor.execute_batch(InputBatch(1, 8, ((seed,), (source1,))))
        self.assertEqual((), executor.receipts[0].applied_sources)
        self.assertEqual(("pin1",), executor.receipts[1].applied_sources)
        self.assertEqual(2, executor.receipts[1].applied_hint_sequence)
        self.assertEqual({"pin0": 0, "pin1": 1}, executor.applied_source_uses)
        executor.execute_batch(InputBatch(1, 8, ((seed,), (source1,))))
        self.assertEqual({"pin0": 0, "pin1": 1}, executor.applied_source_uses)
        source0 = bytes((0, 0, 0, 0, 0, 1, 0, 0))
        executor.execute_batch(InputBatch(2, 8, ((source0,),)))
        self.assertEqual(("pin0",), executor.receipts[2].applied_sources)
        self.assertIsNone(executor.receipts[2].applied_hint_sequence)
        zero_delay = bytes((0, 0, 1, 0, 0, 2, 0, 0))
        executor.execute_batch(InputBatch(3, 8, ((zero_delay,),)))
        self.assertEqual((), executor.receipts[3].applied_sources)

    def test_batch_repeated_genome_uses_distinct_slot_identity_and_idempotent_retry(self):
        executor = executor_for()
        zero = bytes(8)
        one = bytes((0, 0, 0, 0, 0, 1, 0, 0))
        batch = InputBatch(40, 8, ((zero,), (zero,), (one,)))
        self.assertEqual((b"\x00", b"\x00", b"\x01"),
                         executor.execute_batch(batch))
        self.assertEqual(3, len(executor.receipts))
        self.assertEqual({(40, 0), (40, 1), (40, 2)},
                         {(r.buffer_id, r.slot) for r in executor.receipts})
        self.assertEqual(executor.receipts[0].genome_sha256,
                         executor.receipts[1].genome_sha256)
        hint = executor.mutation_hint()
        self.assertEqual("cumulative_run_feedback", hint["feedback_scope"])
        self.assertEqual([(40, 0), (40, 1), (40, 2)],
                         [(item["buffer_id"], item["slot"])
                          for item in hint["latest_completed_batch"]])
        self.assertTrue(all(item["run_id"] == "acceptance-run"
                            and item["raw_sha256"]
                            and item["genome_sha256"]
                            and item["path_id"] == "local.observed:local.pin"
                            for item in hint["latest_completed_batch"]))
        self.assertEqual((b"\x00", b"\x00", b"\x01"),
                         executor.execute_batch(batch))
        self.assertEqual(3, len(executor.receipts))
        with self.assertRaisesRegex(ValueError, "slot identity reused"):
            executor.execute_batch(InputBatch(40, 8, ((one,), (zero,), (one,))))

    def test_raw_differences_without_genome_effect_share_effective_hash(self):
        executor = executor_for()
        seed = bytes(8)
        no_effect_delay = bytes((0, 0, 0, 0, 0, 2, 0, 0))
        executor.execute_batch(InputBatch(41, 8, ((seed,), (no_effect_delay,))))
        first, second = executor.receipts
        self.assertNotEqual(first.raw_sha256, second.raw_sha256)
        self.assertNotEqual(first.genome_sha256, second.genome_sha256)
        self.assertEqual(first.effective_genome_sha256,
                         second.effective_genome_sha256)

    def test_out_of_order_buffers_preserve_coverage_and_source_identity(self):
        executor = executor_for()
        zero = bytes(8)
        one = bytes((0, 0, 0, 0, 0, 1, 0, 0))
        self.assertEqual((b"\x01",),
                         executor.execute_batch(InputBatch(52, 8, ((one,),))))
        self.assertEqual((b"\x00",),
                         executor.execute_batch(InputBatch(51, 8, ((zero,),))))
        self.assertEqual([(52, 0, "01"), (51, 0, "00")],
                         [(r.buffer_id, r.slot, r.coverage_hex)
                          for r in executor.receipts])
        hint = executor.mutation_hint()
        self.assertEqual(52, hint["max_completed_buffer_id"])
        self.assertEqual([51], [item["buffer_id"]
                                for item in hint["latest_completed_batch"]])

    def test_illegal_local_protocol_is_environment_error_without_dut_bug(self):
        for description in ("illegal TL-UL A/D handshake",
                            "CPU response without accepted request"):
            with self.subTest(description=description):
                called = []
                executor = executor_for(error=description,
                                        checker=lambda trace: called.append(trace) or
                                        ("fake_dut_bug",))
                self.assertEqual((b"\x00",), executor.execute_batch(
                    InputBatch(7, 8, ((bytes(8),),))))
                receipt = executor.receipts[0]
                self.assertEqual("environment_error", receipt.status)
                self.assertEqual((), receipt.violations)
                self.assertEqual([], called)

    def test_untyped_harness_failure_stays_uncertain(self):
        executor = executor_for(error="unknown step failure", error_type=RuntimeError)
        executor.execute_batch(InputBatch(8, 8, ((bytes(8),),)))
        self.assertEqual("uncertain_effect", executor.receipts[0].status)


if __name__ == "__main__":
    unittest.main()
