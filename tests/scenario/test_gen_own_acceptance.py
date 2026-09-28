"""Acceptance checks spanning mutation, ownership, and persistent execution."""

import hashlib
import json
import unittest

from myfuzz.integration.rfuzz_wire import InputBatch
from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.genome import Action, GenomeCodec, MemoryImage, ScenarioGenome, Trigger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.mutation import choose_mutation, mutate_genome
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.replay import record_scenario
from myfuzz.scenario.rfuzz_decoder import DecoderTemplate, GenomeRecordDecoder
from myfuzz.scenario.runner import Binding, ScenarioRunner
from myfuzz.scenario.scheduler import DependencyScheduler


class _SourceSession:
    def begin_case(self, testcase_id):
        pass

    def step_local(self, inputs):
        return {"out": inputs.get("pin", 0)}

    def end_case(self):
        pass


class _TargetSession:
    def __init__(self):
        self.samples = []

    def begin_case(self, testcase_id):
        pass

    def step_local(self, inputs):
        self.samples.append(inputs.get("pin", 0))
        return {}

    def end_case(self):
        pass


class _MemorySession:
    def __init__(self):
        self.memory = PersistentMemory(
            regions=(MemoryRegion("ram", 0x1000, 0x100),),
            initialization_seed=5, max_initialized_bytes=0x100)
        self.observed = []
        self.steps = 0

    def begin_case(self, testcase_id):
        pass

    def step_local(self, inputs):
        self.steps += 1
        if self.steps == 2:
            self.memory.write(0x1000, 0x55, width_bytes=1, byte_enable=1,
                              writer_event_id="store-1")
        snapshot = self.memory.read(0x1000, 1,
                                    transaction_id=f"read-{self.steps}")
        self.observed.append(snapshot)
        return {"value": snapshot.value}

    def end_case(self):
        pass


class _DecodedSession:
    def __init__(self):
        self.memory = PersistentMemory(
            regions=(MemoryRegion("ram", 0x1000, 0x100),),
            initialization_seed=5, max_initialized_bytes=0x100)

    def begin_case(self, testcase_id):
        pass

    def step_local(self, inputs):
        image = self.memory.read(0x1000, 1, transaction_id="decode-read")
        return {"out": inputs.get("pin", 0), "image_byte": image.value}

    def end_case(self):
        pass


class _ProgramStoreSession:
    def __init__(self):
        self.memory = PersistentMemory(
            regions=(MemoryRegion("ram", 0x1000, 0x100),),
            initialization_seed=5, max_initialized_bytes=0x100)
        self.loaded_program = None
        self.stored_snapshots = []

    def begin_case(self, testcase_id):
        pass

    def step_local(self, inputs):
        if self.loaded_program is None:
            self.loaded_program = self.memory.read(
                0x1000, 1, transaction_id="fetch-program").value
            self.memory.write(0x1001, self.loaded_program, width_bytes=1,
                              byte_enable=1, writer_event_id="program-store")
        snapshot = self.memory.read(
            0x1001, 1, transaction_id=f"load-data-{len(self.stored_snapshots)}")
        self.stored_snapshots.append(snapshot)
        return {"stored_value": snapshot.value}

    def end_case(self):
        pass


class _ObservedStoreSession:
    def __init__(self):
        self.memory = PersistentMemory(
            regions=(MemoryRegion("ram", 0x1000, 0x100),),
            initialization_seed=5, max_initialized_bytes=0x100)
        self.before_store = None
        self.frozen_response = None
        self.steps = 0

    def begin_case(self, testcase_id):
        pass

    def step_local(self, inputs):
        self.steps += 1
        if self.frozen_response is None:
            self.before_store = self.memory.read(
                0x1000, 1, transaction_id="before-store")
            self.memory.write(0x1000, 0x55, width_bytes=1, byte_enable=1,
                              writer_event_id="fixture-store")
            self.frozen_response = self.memory.read(
                0x1000, 1, transaction_id="frozen-response")
        elif self.steps == 2:
            self.memory.write(0x1000, 0x66, width_bytes=1, byte_enable=1,
                              writer_event_id="later-fixture-store")
        return {"out": inputs.get("pin", 0),
                "response": self.frozen_response.value,
                "program_before": self.before_store.value}

    def end_case(self):
        pass


class GenomeOwnershipAcceptanceTests(unittest.TestCase):
    def test_overlapping_memory_image_sources_cannot_mutate_same_bit(self):
        genome = ScenarioGenome(
            "image-owner", "CPU_TO_IP", "ip.effect", ("cpu",), 2, (),
            initial_images=(MemoryImage("cpu.main", "cpu", 0x1000, "11"),))
        graph = DependencyGraph(
            sources=(FuzzableSource("declared", "cpu", "cpu.main", 0, 8,
                                    ("CPU_TO_IP",), kind="memory_image"),
                     FuzzableSource("alias", "cpu", "cpu.main", 0, 1,
                                    ("CPU_TO_IP",), kind="memory_image")),
            rules=(DependencyRule("ip.effect", ("declared",),
                                  "PERSISTENT_STATE_RULE"),))
        plan = choose_mutation(graph, {"ip.effect": 1}, direction="CPU_TO_IP")
        with self.assertRaisesRegex(ValueError, "overlap|multiple|owner"):
            mutate_genome(genome, plan, graph, compile_ownership((), ()),
                          bit_index=0)

    def test_disjoint_memory_image_sources_keep_separate_bit_ownership(self):
        genome = ScenarioGenome(
            "image-owner", "CPU_TO_IP", "ip.effect", ("cpu",), 2, (),
            initial_images=(MemoryImage("cpu.main", "cpu", 0x1000, "11"),))
        graph = DependencyGraph(
            sources=(FuzzableSource("low", "cpu", "cpu.main", 0, 1,
                                    ("CPU_TO_IP",), kind="memory_image"),
                     FuzzableSource("upper", "cpu", "cpu.main", 1, 7,
                                    ("CPU_TO_IP",), kind="memory_image")),
            rules=(DependencyRule("ip.effect", ("low",),
                                  "PERSISTENT_STATE_RULE"),))
        plan = choose_mutation(graph, {"ip.effect": 1}, direction="CPU_TO_IP")
        changed = mutate_genome(genome, plan, graph,
                                compile_ownership((), ()), bit_index=0)
        self.assertEqual("10", changed.initial_images[0].data_hex)

    def test_memory_image_source_must_match_component_and_image_id(self):
        genome = ScenarioGenome(
            "image-owner", "CPU_TO_IP", "ip.effect", ("cpu", "other"), 2, (),
            initial_images=(MemoryImage("cpu.main", "cpu", 0x1000, "11"),))
        for component, image_id in (("other", "cpu.main"),
                                    ("cpu", "other.image")):
            with self.subTest(component=component, image_id=image_id):
                graph = DependencyGraph(
                    sources=(FuzzableSource("claim", component, image_id, 0, 1,
                                            ("CPU_TO_IP",), kind="memory_image"),),
                    rules=(DependencyRule("ip.effect", ("claim",),
                                          "PERSISTENT_STATE_RULE"),))
                plan = choose_mutation(graph, {"ip.effect": 1},
                                       direction="CPU_TO_IP")
                with self.assertRaisesRegex(ValueError, "no image"):
                    mutate_genome(genome, plan, graph,
                                  compile_ownership((), ()), bit_index=0)

    def test_mutation_operator_cannot_target_observed_bound_output_or_response(self):
        ownership = compile_ownership(
            (InputField("a", "pin", 1), InputField("b", "pin", 1)),
            (InputOwner("a", "pin", 0, 1, "source", "external"),
             InputOwner("b", "pin", 0, 1, "bound", "a.out")))
        source_session = _ObservedStoreSession()
        target_session = _TargetSession()
        runner = ScenarioRunner(
            sessions={"a": source_session, "b": target_session},
            ownership=ownership,
            bindings=(Binding("a", "out", "b", "pin", 1),))
        genome = ScenarioGenome(
            "observed", "IP_TO_CPU", "a.out", ("a", "b"), 4,
            (Action("external", "a", "pin", 1, "IP_TO_CPU",
                    Trigger("START"), width=1),),
            initial_images=(MemoryImage("program", "a", 0x1000, "11"),))
        result = DependencyScheduler().run(runner, genome)
        self.assertEqual("complete", result.status)
        self.assertEqual([1, 1], target_session.samples)
        self.assertEqual(0x55, source_session.frozen_response.value)
        self.assertEqual(("fixture-store",),
                         source_session.frozen_response.writer_event_ids)
        observed_events = runner.events
        output_events = [event for event in observed_events
                         if event.get("component") == "a" and "outputs" in event]
        self.assertEqual([(1, 0x55), (1, 0x55)],
                         [(event["outputs"]["out"],
                           event["outputs"]["response"])
                          for event in output_events])

        for component, port, expected_error in (
                ("b", "pin", "bound"),
                ("a", "out", "undeclared input"),
                ("a", "response", "undeclared input")):
            with self.subTest(component=component, port=port):
                graph = DependencyGraph(
                    sources=(FuzzableSource("attempt", component, port, 0, 1,
                                            ("IP_TO_CPU",)),),
                    rules=(DependencyRule("observed", ("attempt",),
                                          "DATA_BINDING"),))
                forged = ScenarioGenome(
                    "attempt", "IP_TO_CPU", "observed", ("a", "b"), 2,
                    (Action("write-observed", component, port, 0, "IP_TO_CPU",
                            Trigger("START"), width=1),))
                plan = choose_mutation(graph, {"observed": 1},
                                       direction="IP_TO_CPU")
                with self.assertRaisesRegex(ValueError, expected_error):
                    mutate_genome(forged, plan, graph, ownership, bit_index=0)

        image_graph = DependencyGraph(
            sources=(FuzzableSource("initial.program", "a", "program", 0, 8,
                                    ("IP_TO_CPU",), kind="memory_image"),),
            rules=(DependencyRule("a.out", ("initial.program",),
                                  "PERSISTENT_STATE_RULE"),))
        image_plan = choose_mutation(image_graph, {"a.out": 1},
                                     direction="IP_TO_CPU")
        changed = mutate_genome(genome, image_plan, image_graph, ownership,
                                bit_index=0)
        self.assertEqual("10", changed.initial_images[0].data_hex)
        self.assertEqual("11", genome.initial_images[0].data_hex)
        self.assertEqual(0x11, source_session.before_store.value)
        self.assertEqual(0x55, source_session.frozen_response.value)
        current = source_session.memory.read(0x1000, 1, transaction_id="after-mutation")
        self.assertEqual((0x66, ("later-fixture-store",)),
                         (current.value, current.writer_event_ids))
        self.assertEqual(observed_events, runner.events)

        new_source = _ObservedStoreSession()
        new_runner = ScenarioRunner(
            sessions={"a": new_source, "b": _TargetSession()},
            ownership=ownership,
            bindings=(Binding("a", "out", "b", "pin", 1),))
        self.assertEqual("complete", DependencyScheduler().run(new_runner,
                                                                 changed).status)
        self.assertEqual((0x10, 0x55),
                         (new_source.before_store.value,
                          new_source.frozen_response.value))

    def test_same_rfuzz_raw_and_manifest_ignore_prior_corpus_and_feedback(self):
        graph = DependencyGraph(
            sources=(FuzzableSource("cpu.pin", "cpu", "pin", 0, 1,
                                    ("CPU_TO_IP",)),
                     FuzzableSource("cpu.program", "cpu", "program", 0, 8,
                                    ("CPU_TO_IP",), kind="memory_image")),
            rules=(DependencyRule("hit", ("cpu.pin", "cpu.program"),
                                  "PERSISTENT_STATE_RULE"),
                   DependencyRule("not_yet", ("cpu.pin",),
                                  "DATA_BINDING")))
        ownership = compile_ownership(
            (InputField("cpu", "pin", 1),),
            (InputOwner("cpu", "pin", 0, 1, "source", "external"),))
        seed = ScenarioGenome(
            "seed", "CPU_TO_IP", "hit", ("cpu",), 2,
            (Action("pin", "cpu", "pin", 0, "CPU_TO_IP",
                    Trigger("START"), width=1),),
            initial_images=(MemoryImage("program", "cpu", 0x1000, "11"),))
        decoder = GenomeRecordDecoder(
            graph=graph, ownership=ownership,
            templates=(DecoderTemplate("hit", seed),
                       DecoderTemplate("not_yet", seed)))
        manifest = json.loads(json.dumps(decoder.document()))
        reconstructed = GenomeRecordDecoder.from_document(manifest)
        raw = (bytes(8),
               bytes((0, 0, 0, 0, 0, 1, 0, 0)),
               bytes((0, 0, 1, 0, 0, 1, 0, 0)))
        alternate = (bytes((1, 0, 0, 0, 0, 0, 0, 0)),)
        first = reconstructed.decode(raw)
        self.assertEqual("10", first.initial_images[0].data_hex)
        self.assertEqual(1, first.actions[0].value)

        def factory():
            return ScenarioRunner(sessions={"cpu": _DecodedSession()},
                                  ownership=ownership, bindings=())

        targets = (CoverageTarget("hit", "cpu", "out", 1, 1),
                   CoverageTarget("not_yet", "cpu", "never", 1, 1))
        fresh = ScenarioRfuzzExecutor(
            run_id="fresh", decoder=decoder, factory=factory,
            targets=targets, allow_legacy_search=True)
        before_hint = fresh.mutation_hint()
        fresh.execute_batch(InputBatch(2, 8, (raw,)))
        after_hint = fresh.mutation_hint()
        self.assertEqual("hit", before_hint["target_id"])
        self.assertEqual("not_yet", after_hint["target_id"])
        self.assertEqual("10", reconstructed.decode(raw).initial_images[0].data_hex)

        historical = ScenarioRfuzzExecutor(
            run_id="history", decoder=GenomeRecordDecoder(
                graph=graph, ownership=ownership,
                templates=(DecoderTemplate("hit", seed),
                           DecoderTemplate("not_yet", seed))),
            factory=factory, targets=targets, allow_legacy_search=True)
        historical.execute_batch(InputBatch(1, 8, (alternate,)))
        historical.mutation_hint()
        historical.execute_batch(InputBatch(2, 8, (raw,)))
        after_history = historical.decoder.decode(raw)
        self.assertEqual(GenomeCodec.encode(first), GenomeCodec.encode(after_history))
        self.assertEqual((1, 2), (len(fresh.receipts), len(historical.receipts)))
        self.assertEqual(("complete", "complete"),
                         (fresh.receipts[-1].status,
                          historical.receipts[-1].status))
        self.assertTrue(fresh.receipts[-1].genome_sha256)
        self.assertTrue(fresh.receipts[-1].semantic_sha256)
        self.assertTrue(historical.receipts[-1].genome_sha256)
        self.assertTrue(historical.receipts[-1].semantic_sha256)
        self.assertEqual(fresh.receipts[-1].genome_sha256,
                         historical.receipts[-1].genome_sha256)
        self.assertEqual(fresh.receipts[-1].semantic_sha256,
                         historical.receipts[-1].semantic_sha256)

    def test_both_directions_keep_same_binding_and_sustain_legal_root_value(self):
        ownership = compile_ownership(
            (InputField("a", "pin", 1), InputField("b", "pin", 2)),
            (InputOwner("a", "pin", 0, 1, "source", "cpu_program"),
             InputOwner("b", "pin", 0, 1, "bound", "a.out"),
             InputOwner("b", "pin", 1, 1, "source", "external_pin")))
        binding = Binding("a", "out", "b", "pin", 1)
        graph = DependencyGraph(
            sources=(FuzzableSource("cpu.root", "a", "pin", 0, 1,
                                    ("CPU_TO_IP",)),
                     FuzzableSource("external.root", "b", "pin", 1, 1,
                                    ("IP_TO_CPU",))),
            rules=(DependencyRule("b.observed", ("cpu.root",), "DATA_BINDING"),
                   DependencyRule("cpu.observed", ("external.root",),
                                  "DATA_BINDING")))
        cases = (
            ("CPU_TO_IP", "b.observed", Action("cpu-root", "a", "pin", 0,
                                                "CPU_TO_IP", Trigger("START"),
                                                width=1), (1, 1, 1)),
            ("IP_TO_CPU", "cpu.observed", Action("external-root", "b", "pin", 0,
                                                  "IP_TO_CPU", Trigger("START"),
                                                  bit_offset=1, width=1), (2, 2, 2)),
        )
        identities = []
        for direction, target, action, expected_samples in cases:
            with self.subTest(direction=direction):
                genome = ScenarioGenome("case", direction, target, ("a", "b"),
                                        6, (action,))
                plan = choose_mutation(graph, {target: 1}, direction=direction)
                changed = mutate_genome(genome, plan, graph, ownership,
                                        bit_index=0)
                self.assertEqual(1, changed.actions[0].value)
                self.assertEqual(0, genome.actions[0].value)
                target_session = _TargetSession()
                runner = ScenarioRunner(sessions={"a": _SourceSession(),
                                                  "b": target_session},
                                        ownership=ownership, bindings=(binding,))
                identity = runner.identity_document()
                binding_material = {key: identity[key]
                                    for key in ("ownership", "bindings")}
                identities.append(hashlib.sha256(json.dumps(
                    binding_material, sort_keys=True,
                    separators=(",", ":")).encode()).hexdigest())
                result = DependencyScheduler().run(runner, changed)
                self.assertEqual("complete", result.status)
                self.assertEqual(expected_samples, tuple(target_session.samples))
                self.assertEqual(1, sum(event.get("kind") == "source_injection"
                                        for event in runner.events))
                injections = [event for event in runner.events
                              if event.get("kind") == "source_injection"]
                self.assertEqual("a" if direction == "CPU_TO_IP" else "b",
                                 injections[0]["component"])
                observed_delivery = [event for event in runner.events
                                     if event.get("kind") == "dataflow_delivery"]
                self.assertEqual(("a", "out"), observed_delivery[-1]["source"])
                self.assertEqual(("b", "pin"), observed_delivery[-1]["target"])
                self.assertEqual(1 if direction == "CPU_TO_IP" else 0,
                                 observed_delivery[-1]["value"])
                self.assertEqual(expected_samples[0] & 1,
                                 observed_delivery[-1]["value"])
        self.assertEqual(identities[0], identities[1])

    def test_mutated_initial_image_reexecutes_from_initial_state_after_store(self):
        graph = DependencyGraph(
            sources=(FuzzableSource("initial.program", "cpu", "program", 0, 8,
                                    ("CPU_TO_IP",), kind="memory_image"),),
            rules=(DependencyRule("ip.output", ("initial.program",),
                                  "PERSISTENT_STATE_RULE"),))
        genome = ScenarioGenome(
            "new-case", "CPU_TO_IP", "ip.output", ("cpu",), 3, (),
            initial_images=(MemoryImage("program", "cpu", 0x1000, "11"),))
        plan = choose_mutation(graph, {"ip.output": 1}, direction="CPU_TO_IP")
        changed = mutate_genome(genome, plan, graph,
                                compile_ownership((), ()), bit_index=0)
        self.assertEqual("10", changed.initial_images[0].data_hex)
        self.assertEqual("11", genome.initial_images[0].data_hex)
        sessions = []

        def factory():
            session = _MemorySession()
            sessions.append(session)
            return ScenarioRunner(sessions={"cpu": session},
                                  ownership=compile_ownership((), ()), bindings=())

        original_trace = record_scenario(genome, factory)
        changed_trace = record_scenario(changed, factory)
        repeated_trace = record_scenario(genome, factory)
        self.assertEqual(["complete"] * 3,
                         [original_trace.status, changed_trace.status,
                          repeated_trace.status])
        self.assertEqual([[0x11, 0x55, 0x55], [0x10, 0x55, 0x55],
                          [0x11, 0x55, 0x55]],
                         [[snapshot.value for snapshot in session.observed]
                          for session in sessions])
        self.assertEqual([0, 0, 0],
                         [session.memory.generation for session in sessions])
        self.assertEqual(original_trace.semantic_sha256,
                         repeated_trace.semantic_sha256)
        self.assertNotEqual(original_trace.semantic_sha256,
                            changed_trace.semantic_sha256)
        self.assertEqual([("store-1",)] * 3,
                         [session.observed[-1].writer_event_ids
                          for session in sessions])

    def test_mutated_early_store_program_reexecutes_from_initial_state(self):
        graph = DependencyGraph(
            sources=(FuzzableSource("cpu.program", "cpu", "program", 0, 8,
                                    ("CPU_TO_IP",), kind="memory_image"),),
            rules=(DependencyRule("data.loaded", ("cpu.program",),
                                  "PERSISTENT_STATE_RULE"),))
        genome = ScenarioGenome(
            "program-case", "CPU_TO_IP", "data.loaded", ("cpu",), 2, (),
            initial_images=(MemoryImage("program", "cpu", 0x1000, "11"),))
        plan = choose_mutation(graph, {"data.loaded": 1}, direction="CPU_TO_IP")
        changed = mutate_genome(genome, plan, graph,
                                compile_ownership((), ()), bit_index=0)
        sessions = []

        def factory():
            session = _ProgramStoreSession()
            sessions.append(session)
            return ScenarioRunner(sessions={"cpu": session},
                                  ownership=compile_ownership((), ()), bindings=())

        original = record_scenario(genome, factory)
        mutant = record_scenario(changed, factory)
        repeated = record_scenario(genome, factory)
        self.assertEqual(["complete"] * 3,
                         [original.status, mutant.status, repeated.status])
        self.assertEqual([0x11, 0x10, 0x11],
                         [session.loaded_program for session in sessions])
        self.assertEqual([[0x11, 0x11], [0x10, 0x10], [0x11, 0x11]],
                         [[snapshot.value for snapshot in session.stored_snapshots]
                          for session in sessions])
        self.assertEqual([("program-store",)] * 3,
                         [session.stored_snapshots[-1].writer_event_ids
                          for session in sessions])
        self.assertEqual([0, 0, 0],
                         [session.memory.generation for session in sessions])
        self.assertEqual(original.semantic_sha256, repeated.semantic_sha256)
        self.assertNotEqual(original.semantic_sha256, mutant.semantic_sha256)

    def test_mutation_operator_rejects_bound_bank_and_accepts_free_bank(self):
        ownership = compile_ownership(
            (InputField("a", "pin", 1), InputField("b", "pin", 2)),
            (InputOwner("a", "pin", 0, 1, "source", "external_a"),
             InputOwner("b", "pin", 0, 1, "bound", "a.out"),
             InputOwner("b", "pin", 1, 1, "source", "external_b")))
        for bit_offset, expected in ((0, "bound"), (1, None)):
            with self.subTest(bit_offset=bit_offset):
                graph = DependencyGraph(
                    sources=(FuzzableSource("candidate", "b", "pin", bit_offset, 1,
                                            ("IP_TO_CPU",)),),
                    rules=(DependencyRule("target", ("candidate",),
                                          "DATA_BINDING"),))
                genome = ScenarioGenome(
                    "case", "IP_TO_CPU", "target", ("a", "b"), 2,
                    (Action("attempt", "b", "pin", 0, "IP_TO_CPU",
                            Trigger("START"), bit_offset=bit_offset, width=1),))
                plan = choose_mutation(graph, {"target": 1},
                                       direction="IP_TO_CPU")
                if expected:
                    with self.assertRaisesRegex(ValueError, expected):
                        mutate_genome(genome, plan, graph, ownership, bit_index=0)
                else:
                    changed = mutate_genome(genome, plan, graph, ownership,
                                            bit_index=0)
                    self.assertEqual(1, changed.actions[0].value)


if __name__ == "__main__":
    unittest.main()
