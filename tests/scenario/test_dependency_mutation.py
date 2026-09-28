"""An uncovered target selects upstream source actions, not bound inputs."""

import unittest

from myfuzz.scenario.dependency import (DependencyGraph, DependencyPath,
                                        DependencyRule, FuzzableSource)
from myfuzz.scenario.genome import Action, MemoryImage, ScenarioGenome, Trigger
from myfuzz.scenario.mutation import MutationPlan, choose_mutation, mutate_genome
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership


class DependencyMutationTests(unittest.TestCase):
    def setUp(self):
        self.graph = DependencyGraph(
            sources=(FuzzableSource("gpio.pin", "gpio", "gpio_in", 0, 8,
                                    ("IP_TO_CPU",)),
                     FuzzableSource("cpu.program", "cpu", "program", 0, 32,
                                    ("CPU_TO_IP",)),
                     FuzzableSource("spi.miso", "spi", "miso", 0, 8,
                                    ("CPU_TO_IP",))),
            rules=(DependencyRule("gpio.irq", ("gpio.pin",), "DATA_BINDING"),
                   DependencyRule("cpu.irq", ("gpio.irq",), "EVENT_ORDER"),
                   DependencyRule("spi.transfer", ("cpu.program", "spi.miso"),
                                  "PERSISTENT_STATE_RULE")))

    def test_reverse_search_finds_real_upstream_source(self):
        paths = self.graph.paths_to("cpu.irq", direction="IP_TO_CPU")
        self.assertEqual(("gpio.pin",), paths[0].source_ids)
        self.assertEqual((), self.graph.paths_to("cpu.irq", direction="CPU_TO_IP"))

    def test_and_rule_preserves_config_and_external_data_sources(self):
        paths = self.graph.paths_to("spi.transfer", direction="CPU_TO_IP")
        self.assertEqual(("cpu.program", "spi.miso"), paths[0].source_ids)
        plan = choose_mutation(self.graph, {"spi.transfer": 1},
                               direction="CPU_TO_IP",
                               source_weights={"spi.miso": 10,
                                               "cpu.program": 1})
        self.assertEqual("spi.miso", plan.focus_source)
        self.assertEqual(("cpu.program", "spi.miso"), plan.path.source_ids)

    def test_feedback_target_selects_gpio_pin_and_mutates_only_it(self):
        genome = ScenarioGenome(
            testcase_id="seed", direction="IP_TO_CPU", path_id="gpio-irq",
            schedule_order=("gpio",), max_steps=8,
            actions=(Action("edge", "gpio", "gpio_in", 0, "IP_TO_CPU",
                            Trigger("START"), width=8),))
        ownership = compile_ownership(
            (InputField("gpio", "gpio_in", 8), InputField("cpu", "irq", 1)),
            (InputOwner("gpio", "gpio_in", 0, 8, "source", "gpio.pin"),
             InputOwner("cpu", "irq", 0, 1, "bound", "gpio.irq")))
        plan = choose_mutation(self.graph, {"cpu.irq": 10, "spi.transfer": 1},
                               direction="IP_TO_CPU")
        self.assertEqual("gpio.pin", plan.focus_source)
        changed = mutate_genome(genome, plan, self.graph, ownership,
                                bit_index=0)
        self.assertEqual(1, changed.actions[0].value)
        self.assertEqual(genome.actions[0].trigger, changed.actions[0].trigger)
        self.assertEqual(genome.max_steps, changed.max_steps)
        self.assertEqual(0, genome.actions[0].value)

    def test_mutation_can_select_one_causal_action_occurrence(self):
        genome = ScenarioGenome(
            testcase_id="two-events", direction="IP_TO_CPU", path_id="gpio-irq",
            schedule_order=("gpio",), max_steps=8,
            actions=(Action("first", "gpio", "gpio_in", 0, "IP_TO_CPU",
                            Trigger("START"), width=8),
                     Action("second", "gpio", "gpio_in", 0, "IP_TO_CPU",
                            Trigger("START"), width=8)))
        ownership = compile_ownership(
            (InputField("gpio", "gpio_in", 8),),
            (InputOwner("gpio", "gpio_in", 0, 8, "source", "gpio.pin"),))
        plan = choose_mutation(self.graph, {"cpu.irq": 10},
                               direction="IP_TO_CPU")
        changed = mutate_genome(genome, plan, self.graph, ownership,
                                bit_index=0, action_id="second")
        self.assertEqual((0, 1), tuple(a.value for a in changed.actions))

    def test_bound_source_cannot_be_used_as_mutation_target(self):
        with self.assertRaisesRegex(ValueError, "source"):
            DependencyGraph(
                sources=(FuzzableSource("cpu.irq", "cpu", "irq", 0, 1,
                                        ("IP_TO_CPU",), kind="bound"),), rules=())

    def test_cpu_program_image_is_mutated_as_upstream_source(self):
        graph = DependencyGraph(
            sources=(FuzzableSource("cpu.program", "cpu", "cpu.main", 0, 32,
                                    ("CPU_TO_IP",), kind="memory_image"),),
            rules=(DependencyRule("gpio.config", ("cpu.program",),
                                  "PERSISTENT_STATE_RULE"),))
        genome = ScenarioGenome(
            testcase_id="cpu-mmio", direction="CPU_TO_IP", path_id="cpu-gpio",
            schedule_order=("cpu",), max_steps=5, actions=(),
            initial_images=(MemoryImage("cpu.main", "cpu", 0x10080,
                                        "13011000"),))
        plan = choose_mutation(graph, {"gpio.config": 4}, direction="CPU_TO_IP")
        changed = mutate_genome(genome, plan, graph, self._ownership(),
                                bit_index=20)
        self.assertEqual("13010000", changed.initial_images[0].data_hex)
        self.assertEqual("13011000", genome.initial_images[0].data_hex)

    def test_forged_path_or_wrong_direction_cannot_mutate_a_source(self):
        graph = DependencyGraph(
            sources=(FuzzableSource("gpio.pin", "gpio", "pin", 0, 1,
                                    ("CPU_TO_IP",)),),
            rules=(DependencyRule("ip.out", ("gpio.pin",), "DATA_BINDING"),))
        ownership = compile_ownership(
            (InputField("gpio", "pin", 1),),
            (InputOwner("gpio", "pin", 0, 1, "source", "gpio.pin"),))
        genome = ScenarioGenome(
            testcase_id="direction", direction="IP_TO_CPU", path_id="ip.out",
            schedule_order=("gpio",), max_steps=2,
            actions=(Action("pin", "gpio", "pin", 0, "IP_TO_CPU",
                            Trigger("START"), width=1),))
        wrong_direction = MutationPlan(
            "IP_TO_CPU", "ip.out", DependencyPath("ip.out", ("gpio.pin",)),
            "gpio.pin")
        with self.assertRaisesRegex(ValueError, "path"):
            mutate_genome(genome, wrong_direction, graph, ownership, bit_index=0)
        allowed_genome = ScenarioGenome(
            testcase_id="direction", direction="CPU_TO_IP", path_id="ip.out",
            schedule_order=("gpio",), max_steps=2,
            actions=(Action("pin", "gpio", "pin", 0, "CPU_TO_IP",
                            Trigger("START"), width=1),))
        forged_target = MutationPlan(
            "CPU_TO_IP", "other", DependencyPath("ip.out", ("gpio.pin",)),
            "gpio.pin")
        with self.assertRaisesRegex(ValueError, "path"):
            mutate_genome(allowed_genome, forged_target, graph, ownership,
                          bit_index=0)

    def test_overlapping_graph_sources_cannot_claim_one_action_bit(self):
        graph = DependencyGraph(
            sources=(FuzzableSource("first", "gpio", "pin", 0, 1,
                                    ("IP_TO_CPU",)),
                     FuzzableSource("alias", "gpio", "pin", 0, 1,
                                    ("CPU_TO_IP",))),
            rules=(DependencyRule("target", ("first",), "DATA_BINDING"),))
        ownership = compile_ownership(
            (InputField("gpio", "pin", 1),),
            (InputOwner("gpio", "pin", 0, 1, "source", "external"),))
        genome = ScenarioGenome("case", "IP_TO_CPU", "target", ("gpio",), 2,
                                (Action("pin", "gpio", "pin", 0,
                                        "IP_TO_CPU", Trigger("START"), width=1),))
        plan = choose_mutation(graph, {"target": 1}, direction="IP_TO_CPU")
        with self.assertRaisesRegex(ValueError, "overlap|multiple|owner"):
            mutate_genome(genome, plan, graph, ownership, bit_index=0)

    def test_action_with_other_direction_is_not_mutated(self):
        graph = DependencyGraph(
            sources=(FuzzableSource("root", "gpio", "pin", 0, 1,
                                    ("IP_TO_CPU",)),),
            rules=(DependencyRule("target", ("root",), "DATA_BINDING"),))
        ownership = compile_ownership(
            (InputField("gpio", "pin", 1),),
            (InputOwner("gpio", "pin", 0, 1, "source", "external"),))
        genome = ScenarioGenome("case", "IP_TO_CPU", "target", ("gpio",), 2,
                                (Action("pin", "gpio", "pin", 0,
                                        "CPU_TO_IP", Trigger("START"), width=1),))
        plan = choose_mutation(graph, {"target": 1}, direction="IP_TO_CPU")
        with self.assertRaisesRegex(ValueError, "direction|matching action"):
            mutate_genome(genome, plan, graph, ownership, bit_index=0)

    def test_source_claim_cannot_extend_past_declared_input(self):
        graph = DependencyGraph(
            sources=(FuzzableSource("root", "gpio", "pin", 0, 2,
                                    ("IP_TO_CPU",)),),
            rules=(DependencyRule("target", ("root",), "DATA_BINDING"),))
        ownership = compile_ownership(
            (InputField("gpio", "pin", 1),),
            (InputOwner("gpio", "pin", 0, 1, "source", "external"),))
        genome = ScenarioGenome("case", "IP_TO_CPU", "target", ("gpio",), 2,
                                (Action("pin", "gpio", "pin", 0,
                                        "IP_TO_CPU", Trigger("START"), width=1),))
        plan = choose_mutation(graph, {"target": 1}, direction="IP_TO_CPU")
        with self.assertRaisesRegex(ValueError, "range|field"):
            mutate_genome(genome, plan, graph, ownership, bit_index=0)

    def test_image_source_claim_cannot_extend_past_initial_image(self):
        graph = DependencyGraph(
            sources=(FuzzableSource("program", "cpu", "boot", 0, 16,
                                    ("CPU_TO_IP",), kind="memory_image"),),
            rules=(DependencyRule("target", ("program",),
                                  "PERSISTENT_STATE_RULE"),))
        genome = ScenarioGenome(
            "case", "CPU_TO_IP", "target", ("cpu",), 2, (),
            initial_images=(MemoryImage("boot", "cpu", 0x1000, "11"),))
        plan = choose_mutation(graph, {"target": 1}, direction="CPU_TO_IP")
        with self.assertRaisesRegex(ValueError, "outside memory image"):
            mutate_genome(genome, plan, graph, self._ownership(), bit_index=0)

    @staticmethod
    def _ownership():
        return compile_ownership((), ())


if __name__ == "__main__":
    unittest.main()
