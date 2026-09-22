"""Step 4A: interrupt source numbering, controller capacity and the three paths."""
from __future__ import annotations

import unittest
from dataclasses import replace

from myfuzz.composition.component_profile import (
    bind_profile,
    elaborate_profile,
    load_component_profile,
)
from myfuzz.composition.soc_interrupt_plan import (
    CONTROLLER_RTL_SOURCE,
    CONTROLLER_VERIFIED_SOURCES,
    InterruptPlanError,
    InterruptSourceRequest,
    build_interrupt_plan,
    interrupt_plan_document,
    register_map,
)

from .soc_generation_fixture import EXAMPLE, ROOT


def _binding(name: str):
    profile = load_component_profile(EXAMPLE / "profiles" / f"{name}.json")
    return profile, bind_profile(profile, elaborate_profile(profile, base_dir=ROOT))


class _PlanFixture:
    def __init__(self) -> None:
        self.cpu_profile, self.cpu_binding = _binding("novacore")
        self.uart_profile, self.uart_binding = _binding("novauart")
        self.gpio_profile, self.gpio_binding = _binding("novagpio")
        self.bindings = {"cpu0": self.cpu_binding, "uart0": self.uart_binding,
                         "gpio0": self.gpio_binding}

    def sources(self, order=("uart0", "gpio0"), *, bit=None):
        result = []
        for instance_id in order:
            profile = self.uart_profile if instance_id == "uart0" else self.gpio_profile
            binding = self.uart_binding if instance_id == "uart0" else self.gpio_binding
            for source in profile.interrupts:
                result.append((InterruptSourceRequest(
                    instance_id=instance_id,
                    component_id=binding.component_id,
                    endpoint_id=source.endpoint_id,
                    role=source.role,
                    declared_source_id=source.source_id,
                    bit=source.bit if bit is None else bit,
                ), source))
        return result

    def build(self, sources=None, **overrides):
        arguments = {
            "sources": self.sources() if sources is None else sources,
            "bindings": self.bindings,
            "cpu_instance_id": "cpu0",
            "cpu_binding": self.cpu_binding,
            "cpu_profile": self.cpu_profile,
            "address_width": 32,
        }
        arguments.update(overrides)
        return build_interrupt_plan(**arguments)


class NumberingTests(unittest.TestCase):
    def test_source_ids_follow_stable_instance_ids_not_input_order(self) -> None:
        fixture = _PlanFixture()
        forward = fixture.build(fixture.sources(("uart0", "gpio0")))
        backward = fixture.build(fixture.sources(("gpio0", "uart0")))
        self.assertEqual(2, forward.num_sources)
        self.assertEqual([(item.instance_id, item.source_id) for item in forward.sources],
                         [(item.instance_id, item.source_id) for item in backward.sources])
        self.assertEqual(["gpio0", "uart0"], [item.instance_id for item in forward.sources])
        self.assertEqual([1, 2], [item.source_id for item in forward.sources])
        self.assertEqual([0, 1], [item.source_id - 1 for item in forward.sources])

    def test_two_instances_of_one_component_do_not_share_a_source(self) -> None:
        fixture = _PlanFixture()
        fixture.bindings["uart1"] = fixture.uart_binding
        sources = []
        for instance_id in ("uart0", "uart1"):
            for source in fixture.uart_profile.interrupts:
                sources.append((InterruptSourceRequest(
                    instance_id=instance_id, component_id="novauart",
                    endpoint_id=source.endpoint_id, role=source.role), source))
        plan = fixture.build(sources)
        self.assertEqual(["uart0", "uart1"], [item.instance_id for item in plan.sources])
        self.assertEqual([1, 2], [item.source_id for item in plan.sources])

    def test_duplicate_physical_source_is_rejected(self) -> None:
        fixture = _PlanFixture()
        sources = fixture.sources(("uart0",))
        with self.assertRaises(InterruptPlanError) as error:
            fixture.build(sources + sources)
        self.assertIn("duplicate-physical-interrupt-source", str(error.exception))

    def test_capacity_beyond_the_verified_limit_is_rejected(self) -> None:
        fixture = _PlanFixture()
        sources = []
        for index in range(CONTROLLER_VERIFIED_SOURCES + 1):
            instance_id = f"src{index:03d}"
            fixture.bindings[instance_id] = fixture.uart_binding
            source = fixture.uart_profile.interrupts[0]
            sources.append((InterruptSourceRequest(
                instance_id=instance_id, component_id="novauart",
                endpoint_id=source.endpoint_id, role=source.role), source))
        with self.assertRaises(InterruptPlanError) as error:
            fixture.build(sources)
        self.assertIn("capacity-exceeded", str(error.exception))

    def test_multi_bit_vector_without_a_declared_bit_is_rejected(self) -> None:
        """The generator never ORs several outputs just to make one source."""
        fixture = _PlanFixture()
        source = fixture.gpio_profile.interrupts[0]
        widened = replace(source, bit=None, source_id="pin_event_vector")
        # Only the resolved interface is widened: the point is that the plan
        # refuses to invent bit mappings for a real multi-bit vector.
        wide_binding = replace(fixture.gpio_binding, endpoints=tuple(
            replace(item, fields=tuple(
                replace(field, width=4, raw_lo=0, raw_hi=3)
                if field.role == source.role else field
                for field in item.fields)) if item.endpoint_id == source.endpoint_id else item
            for item in fixture.gpio_binding.endpoints))
        fixture.bindings["gpio0"] = wide_binding
        with self.assertRaises(InterruptPlanError) as error:
            fixture.build([(InterruptSourceRequest(
                instance_id="gpio0", component_id="novagpio",
                endpoint_id=source.endpoint_id, role=source.role), widened)])
        self.assertIn("bit-ambiguous", str(error.exception))

    def test_active_low_source_records_the_inversion(self) -> None:
        fixture = _PlanFixture()
        source = replace(fixture.uart_profile.interrupts[0], polarity="active_low")
        plan = fixture.build([(InterruptSourceRequest(
            instance_id="uart0", component_id="novauart",
            endpoint_id=source.endpoint_id, role=source.role), source)])
        document = interrupt_plan_document(plan, window_base=0x40000000)
        self.assertTrue(document["sources"][0]["polarity_inversion"])
        path = document["paths"]["source_to_controller"][0]
        self.assertTrue(path["inversion"])

    def test_non_level_trigger_is_rejected(self) -> None:
        fixture = _PlanFixture()
        source = replace(fixture.uart_profile.interrupts[0], trigger="edge")
        with self.assertRaises(InterruptPlanError) as error:
            fixture.build([(InterruptSourceRequest(
                instance_id="uart0", component_id="novauart",
                endpoint_id=source.endpoint_id, role=source.role), source)])
        self.assertIn("unsupported-interrupt-trigger", str(error.exception))

    def test_no_sources_means_no_controller_and_a_disabled_entry(self) -> None:
        fixture = _PlanFixture()
        plan = fixture.build([])
        self.assertFalse(plan.present)
        document = interrupt_plan_document(plan)
        self.assertFalse(document["controller"]["present"])
        self.assertTrue(document["gaps"])
        self.assertIn("disabled", document["cpu_entry"]["semantics"])


class RegisterMapTests(unittest.TestCase):
    def test_window_size_is_the_smallest_power_of_two_covering_the_bitmaps(self) -> None:
        fixture = _PlanFixture()
        plan = fixture.build()
        self.assertEqual(1, plan.bitmap_words)
        self.assertEqual(0x40, plan.window_size)
        self.assertEqual(0x40, plan.window_alignment)
        offsets = {item["name"]: item["offset"] for item in plan.register_map}
        self.assertEqual(0x00, offsets["CLAIM"])
        self.assertEqual(0x04, offsets["COMPLETE"])
        self.assertEqual(0x08, offsets["IN_SERVICE"])
        self.assertEqual(0x0c, offsets["SOURCE_COUNT"])
        self.assertEqual(0x20, offsets["PENDING0"])
        self.assertEqual(0x24, offsets["ENABLE0"])

    def test_two_bitmap_words_for_more_than_31_sources(self) -> None:
        registers = {item["name"]: item["offset"] for item in register_map(40)}
        self.assertEqual(0x20, registers["PENDING0"])
        self.assertEqual(0x24, registers["PENDING1"])
        self.assertEqual(0x28, registers["ENABLE0"])
        self.assertEqual(0x2c, registers["ENABLE1"])

    def test_controller_source_is_the_versioned_rtl(self) -> None:
        self.assertEqual("src/myfuzz/protocols/rtl/soc_irq_controller.sv", CONTROLLER_RTL_SOURCE)
        self.assertTrue(CONTROLLER_RTL_SOURCE.endswith(".sv"))

    def test_window_misalignment_is_rejected(self) -> None:
        fixture = _PlanFixture()
        plan = fixture.build()
        with self.assertRaises(InterruptPlanError) as error:
            interrupt_plan_document(plan, window_base=0x40000008)
        self.assertIn("misaligned", str(error.exception))

    def test_three_paths_are_recorded(self) -> None:
        fixture = _PlanFixture()
        plan = fixture.build()
        document = interrupt_plan_document(plan, window_base=0x40003000)
        self.assertEqual(2, len(document["paths"]["source_to_controller"]))
        self.assertEqual(1, len(document["paths"]["controller_to_cpu"]))
        self.assertEqual(1, len(document["paths"]["cpu_to_mmio"]))
        self.assertEqual("none", document["service_contract"]["environment_control_entry"])
        self.assertEqual(0x40003000, document["controller"]["window"]["base"])


if __name__ == "__main__":
    unittest.main()
