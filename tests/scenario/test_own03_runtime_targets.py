"""OWN-03: existing Genome mutation cannot rewrite observed runtime facts."""

import unittest

from myfuzz.scenario.dependency import (DependencyGraph, DependencyRule,
                                        FuzzableSource)
from myfuzz.scenario.genome import Action, MemoryImage, ScenarioGenome, Trigger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.mutation import (MutationTarget, choose_mutation,
                                      mutate_genome)
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner


class _ObservedStoreSession:
    def __init__(self):
        self.memory = PersistentMemory(
            regions=(MemoryRegion("ram", 0x1000, 0x100),),
            initialization_seed=7, max_initialized_bytes=0x100)
        self.frozen_response = None

    def begin_case(self, testcase_id):
        pass

    def step_local(self, inputs):
        if self.frozen_response is None:
            self.memory.write(0x1000, 0x55, width_bytes=1, byte_enable=1,
                              writer_event_id="first-store")
            self.frozen_response = self.memory.read(
                0x1000, 1, transaction_id="frozen-response")
        return {"out": inputs.get("pin", 0),
                "response": self.frozen_response.value}

    def end_case(self):
        pass


class Own03RuntimeTargetsTests(unittest.TestCase):
    def test_explicit_runtime_targets_are_rejected_before_execution(self):
        session = _ObservedStoreSession()
        ownership = compile_ownership(
            (InputField("device", "pin", 1),),
            (InputOwner("device", "pin", 0, 1, "source", "external"),))
        runner = ScenarioRunner(sessions={"device": session}, ownership=ownership,
                                bindings=())
        genome = ScenarioGenome(
            "material", "IP_TO_IP", "observed", ("device",), 1,
            (Action("pin-action", "device", "pin", 1, "IP_TO_IP",
                    Trigger("START"), width=1),),
            initial_images=(MemoryImage("boot", "device", 0x1000, "11"),))
        graph = DependencyGraph(
            sources=(FuzzableSource("pin-source", "device", "pin", 0, 1,
                                    ("IP_TO_IP",)),),
            rules=(DependencyRule("observed", ("pin-source",),
                                  "DATA_BINDING"),))
        plan = choose_mutation(graph, {"observed": 1}, direction="IP_TO_IP")
        runner.preload_image(genome.initial_images[0])
        runner.begin_test("material")
        try:
            runner.inject_source("device", "pin", 1, direction="IP_TO_IP")
            runner.step("device")
            frozen = session.frozen_response
            history = runner.events
            original = session.memory.read(0x1000, 1, transaction_id="before")
            for kind, identifier in (
                ("committed_ram", "ram:0x1000"),
                ("read_snapshot", frozen.transaction_id),
                ("real_response", "device:response"),
                ("ip_output", "device:out"),
            ):
                with self.subTest(target_kind=kind):
                    with self.assertRaisesRegex(ValueError,
                                                "runtime mutation target is immutable"):
                        mutate_genome(genome, plan, graph, ownership,
                                      bit_index=0,
                                      target=MutationTarget(kind, identifier))
                    self.assertEqual(genome.actions[0].value, 1)
                    self.assertEqual(history, runner.events)
                    self.assertIs(frozen, session.frozen_response)
                    current = session.memory.read(0x1000, 1,
                                                  transaction_id="after-refusal")
                    self.assertEqual((original.value, original.writer_event_ids),
                                     (current.value, current.writer_event_ids))
        finally:
            runner.finalize()

    def test_explicit_genome_targets_preserve_legal_source_mutation(self):
        ownership = compile_ownership(
            (InputField("device", "pin", 1),),
            (InputOwner("device", "pin", 0, 1, "source", "external"),))
        genome = ScenarioGenome(
            "material", "IP_TO_IP", "observed", ("device",), 1,
            (Action("pin-action", "device", "pin", 1, "IP_TO_IP",
                    Trigger("START"), width=1),),
            initial_images=(MemoryImage("boot", "device", 0x1000, "11"),))
        action_graph = DependencyGraph(
            sources=(FuzzableSource("pin-source", "device", "pin", 0, 1,
                                    ("IP_TO_IP",)),),
            rules=(DependencyRule("observed", ("pin-source",),
                                  "DATA_BINDING"),))
        action_plan = choose_mutation(action_graph, {"observed": 1},
                                      direction="IP_TO_IP")
        changed_action = mutate_genome(
            genome, action_plan, action_graph, ownership, bit_index=0,
            target=MutationTarget("genome_action", "pin-action"))
        self.assertEqual(changed_action.actions[0].value, 0)
        self.assertEqual(genome.actions[0].value, 1)
        image_graph = DependencyGraph(
            sources=(FuzzableSource("image-source", "device", "boot", 0, 8,
                                    ("IP_TO_IP",), kind="memory_image"),),
            rules=(DependencyRule("observed", ("image-source",),
                                  "PERSISTENT_STATE_RULE"),))
        image_plan = choose_mutation(image_graph, {"observed": 1},
                                     direction="IP_TO_IP")
        changed_image = mutate_genome(
            genome, image_plan, image_graph, ownership, bit_index=0,
            target=MutationTarget("initial_image", "boot"))
        self.assertEqual(changed_image.initial_images[0].data_hex, "10")
        self.assertEqual(genome.initial_images[0].data_hex, "11")
        new_session = _ObservedStoreSession()
        new_runner = ScenarioRunner(sessions={"device": new_session},
                                    ownership=ownership, bindings=())
        new_runner.preload_image(changed_image.initial_images[0])
        new_runner.begin_test("new-material")
        try:
            self.assertEqual(0x10, new_session.memory.read(
                0x1000, 1, transaction_id="new-testcase-initial").value)
        finally:
            new_runner.finalize()
        with self.assertRaisesRegex(ValueError, "mutation target does not match"):
            mutate_genome(genome, action_plan, action_graph, ownership,
                          bit_index=0,
                          target=MutationTarget("initial_image", "boot"))

    def test_runtime_ram_snapshot_response_and_output_are_not_mutation_inputs(self):
        session = _ObservedStoreSession()
        ownership = compile_ownership(
            (InputField("device", "pin", 1),),
            (InputOwner("device", "pin", 0, 1, "source", "external"),))
        runner = ScenarioRunner(sessions={"device": session}, ownership=ownership,
                                bindings=())
        session.memory.preload(0x1000, b"\x11")
        runner.begin_test("runtime-facts")
        try:
            runner.inject_source("device", "pin", 1, direction="IP_TO_IP")
            self.assertEqual({"out": 1, "response": 0x55},
                             runner.step("device"))
            frozen = session.frozen_response
            history = runner.events
            committed = session.memory.read(
                0x1000, 1, transaction_id="after-first-store")
            self.assertEqual((0x55, ("first-store",)),
                             (committed.value, committed.writer_event_ids))

            for port in ("ram", "snapshot", "response", "out"):
                with self.subTest(runtime_target=port):
                    source = FuzzableSource(
                        "attempt", "device", port, 0, 1, ("IP_TO_IP",))
                    graph = DependencyGraph(
                        sources=(source,),
                        rules=(DependencyRule("observed", ("attempt",),
                                              "DATA_BINDING"),))
                    genome = ScenarioGenome(
                        "forged", "IP_TO_IP", "observed", ("device",), 1,
                        (Action("rewrite-runtime", "device", port, 1,
                                "IP_TO_IP", Trigger("START"), width=1),))
                    plan = choose_mutation(graph, {"observed": 1},
                                           direction="IP_TO_IP")
                    with self.assertRaisesRegex(ValueError,
                                                "undeclared input field"):
                        mutate_genome(genome, plan, graph, ownership,
                                      bit_index=0)
                    self.assertEqual(history, runner.events)
                    self.assertIs(frozen, session.frozen_response)
                    current = session.memory.read(
                        0x1000, 1, transaction_id="after-refusal")
                    self.assertEqual((0x55, ("first-store",)),
                                     (current.value, current.writer_event_ids))

            for image_id in ("committed-ram", "frozen-snapshot"):
                with self.subTest(runtime_image=image_id):
                    source = FuzzableSource(
                        "attempt", "device", image_id, 0, 1,
                        ("IP_TO_IP",), kind="memory_image")
                    graph = DependencyGraph(
                        sources=(source,),
                        rules=(DependencyRule("observed", ("attempt",),
                                              "PERSISTENT_STATE_RULE"),))
                    genome = ScenarioGenome(
                        "forged", "IP_TO_IP", "observed", ("device",),
                        1, ())
                    plan = choose_mutation(graph, {"observed": 1},
                                           direction="IP_TO_IP")
                    with self.assertRaisesRegex(ValueError,
                                                "no image for selected upstream source"):
                        mutate_genome(genome, plan, graph, ownership,
                                      bit_index=0)
                    current = session.memory.read(
                        0x1000, 1, transaction_id="after-image-refusal")
                    self.assertEqual((0x55, ("first-store",)),
                                     (current.value, current.writer_event_ids))
                    self.assertIs(frozen, session.frozen_response)
                    self.assertEqual((0x55, ("first-store",)),
                                     (frozen.value, frozen.writer_event_ids))
                    self.assertEqual(history, runner.events)
        finally:
            runner.finalize()

    def test_runtime_target_kind_cannot_be_a_graph_mutation_source(self):
        for kind in ("committed_ram", "read_snapshot", "response", "output"):
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(ValueError,
                                            "only fuzzable source nodes"):
                    FuzzableSource("attempt", "device", "runtime", 0, 1,
                                   ("IP_TO_IP",), kind=kind)

    def test_initial_image_mutation_is_new_material_and_later_store_changes_only_current_ram(self):
        session = _ObservedStoreSession()
        ownership = compile_ownership(
            (InputField("device", "pin", 1),),
            (InputOwner("device", "pin", 0, 1, "source", "external"),))
        runner = ScenarioRunner(sessions={"device": session}, ownership=ownership,
                                bindings=())
        genome = ScenarioGenome(
            "material", "IP_TO_IP", "observed", ("device",), 1, (),
            initial_images=(MemoryImage("boot", "device", 0x1000, "11"),))
        graph = DependencyGraph(
            sources=(FuzzableSource("initial.boot", "device", "boot", 0,
                                    8, ("IP_TO_IP",), kind="memory_image"),),
            rules=(DependencyRule("observed", ("initial.boot",),
                                  "PERSISTENT_STATE_RULE"),))
        runner.preload_image(genome.initial_images[0])
        runner.begin_test("material")
        try:
            runner.step("device")
            frozen = session.frozen_response
            history = runner.events
            changed = mutate_genome(
                genome, choose_mutation(graph, {"observed": 1},
                                        direction="IP_TO_IP"), graph, ownership,
                bit_index=0)
            self.assertEqual("10", changed.initial_images[0].data_hex)
            self.assertEqual("11", genome.initial_images[0].data_hex)
            self.assertEqual(history, runner.events)
            self.assertEqual(0x55, frozen.value)
            self.assertEqual(0x55, session.memory.read(
                0x1000, 1, transaction_id="before-later-store").value)

            session.memory.write(0x1000, 0x66, width_bytes=1, byte_enable=1,
                                 writer_event_id="later-store")
            current = session.memory.read(
                0x1000, 1, transaction_id="after-later-store")
            self.assertEqual((0x66, ("later-store",)),
                             (current.value, current.writer_event_ids))
            self.assertEqual((0x55, ("first-store",)),
                             (frozen.value, frozen.writer_event_ids))
            self.assertEqual(history, runner.events)
        finally:
            runner.finalize()


if __name__ == "__main__":
    unittest.main()
