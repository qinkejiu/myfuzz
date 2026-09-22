"""Steps 4 and 5: the unified plan, address allocation, adapters and raw layout."""
from __future__ import annotations

import json
import unittest

from myfuzz.composition.component_profile import (
    ComponentProfileError,
    load_component_profile,
    load_composition_request,
)
from myfuzz.composition.soc_composition import (
    CompositionError,
    build_composition,
    composition_document,
    composition_summary,
)
from myfuzz.composition.soc_profile_renderer import render_composition, source_list

from .soc_generation_fixture import ROOT, example_plan, example_profiles


def _request_with(**changes):
    document = json.loads((ROOT / "examples/soc_generation/request.json").read_text())
    document.update(changes)
    return load_composition_request(document, profiles=example_profiles())


class PlanTests(unittest.TestCase):
    def test_plan_is_validated_and_records_every_window(self) -> None:
        plan = example_plan()
        windows = {item["target_id"]: (item["base"], item["size"])
                   for item in plan.plan["address_map"]["windows"]}
        self.assertEqual((0x40000000, 0x1000), windows["gpio0_win"])
        self.assertEqual((0x40001000, 0x1000), windows["uart1_win"])
        self.assertEqual((0x40002000, 0x1000), windows["uart0_win"])
        self.assertEqual((0x40003000, 0x40), windows["irq_controller0_win"])
        self.assertEqual((0x00010000, 0x8000), windows["rom0_win"])
        self.assertEqual((0x80000000, 0x10000), windows["ram0_win"])

    def test_a_user_fixed_address_is_kept_exactly(self) -> None:
        plan = example_plan()
        self.assertEqual(1073745920, plan.instance("uart1").window_base)
        self.assertEqual(0x40001000,
                         next(item["base"] for item in plan.plan["address_map"]["windows"]
                              if item["target_id"] == "uart1_win"))

    def test_a_fixed_address_that_overlaps_is_rejected(self) -> None:
        document = json.loads((ROOT / "examples/soc_generation/request.json").read_text())
        document["peripherals"][2]["address"] = 0x80000000
        request = load_composition_request(document, profiles=example_profiles())
        with self.assertRaises(CompositionError) as error:
            build_composition(request, base_dir=ROOT)
        self.assertIn("fixed-address-overlap", str(error.exception))

    def test_a_misaligned_fixed_address_is_rejected(self) -> None:
        document = json.loads((ROOT / "examples/soc_generation/request.json").read_text())
        document["peripherals"][2]["address"] = 0x40001008
        request = load_composition_request(document, profiles=example_profiles())
        with self.assertRaises(CompositionError) as error:
            build_composition(request, base_dir=ROOT)
        self.assertIn("fixed-address-misaligned", str(error.exception))

    def test_auto_allocation_order_is_stable_and_independent_of_request_order(self) -> None:
        document = json.loads((ROOT / "examples/soc_generation/request.json").read_text())
        reversed_document = json.loads(json.dumps(document))
        reversed_document["peripherals"] = list(reversed(document["peripherals"]))
        reversed_document["peripherals"][1]["address"] = None
        first = build_composition(
            load_composition_request(document, profiles=example_profiles()), base_dir=ROOT)
        second = build_composition(
            load_composition_request(reversed_document, profiles=example_profiles()),
            base_dir=ROOT)
        self.assertEqual(
            sorted((item["target_id"], item["base"])
                   for item in first.plan["address_map"]["windows"]),
            sorted((item["target_id"], item["base"])
                   for item in second.plan["address_map"]["windows"]))

    def test_two_instances_of_one_profile_get_separate_windows(self) -> None:
        plan = example_plan()
        uart0 = plan.instance("uart0")
        uart1 = plan.instance("uart1")
        self.assertEqual(uart0.component_id, uart1.component_id)
        self.assertNotEqual(uart0.window_base, uart1.window_base)
        self.assertIs(uart0.binding, uart1.binding)

    def test_the_peripheral_adapter_is_resolved_from_protocol_capabilities(self) -> None:
        plan = example_plan()
        for target in plan.target_records:
            if "instance_id" not in target:
                continue
            adapter = target["resolved_adapter"]
            self.assertEqual("beat_to_apb", adapter["rtl_module"])
            self.assertEqual("beat-initiator-to-peripheral-target", adapter["direction"])
            self.assertEqual("synchronous", adapter["reset"]["synchrony"])
            self.assertEqual("active_high", adapter["reset"]["polarity"])

    def test_an_address_narrowing_records_its_window_proof(self) -> None:
        plan = example_plan()
        target = next(item for item in plan.target_records
                      if item.get("instance_id") == "gpio0")
        binding = target["resolved_adapter"]["role_widths"]["paddr"]
        self.assertEqual("narrow_address", binding["mode"])
        self.assertEqual(32, binding["width"])
        self.assertEqual(12, binding["component_width"])
        self.assertIn("multiple of 2**12", binding["proof"])

    def test_an_unprovable_address_narrowing_is_rejected(self) -> None:
        """A window that does not fit the port would alias register offsets."""
        from myfuzz.composition.soc_composition import _bind_role_widths

        plan = example_plan()
        target = next(item for item in plan.target_records
                      if item.get("instance_id") == "gpio0")
        instance = plan.instance("gpio0")
        from myfuzz.composition.soc_composition import _protocol_address_roles
        with self.assertRaises(CompositionError) as error:
            _bind_role_widths(instance, target["resolved_adapter"], base_dir=ROOT,
                              window_base=0x40000010, window_size=0x1000,
                              address_roles=_protocol_address_roles(("apb", "4")))
        self.assertIn("address-narrowing-unproven", str(error.exception))

    def test_missing_capability_is_reported_with_the_instance(self) -> None:
        document = json.loads((ROOT / "examples/soc_generation/profiles/novagpio.json").read_text())
        del document["capabilities"]["partial_write"]
        profile = load_component_profile(document)
        profiles = dict(example_profiles())
        profiles["examples/soc_generation/profiles/novagpio.json"] = profile
        request = load_composition_request(
            ROOT / "examples/soc_generation/request.json", profiles=profiles)
        with self.assertRaises(CompositionError) as error:
            build_composition(request, base_dir=ROOT)
        self.assertIn("partial_write", str(error.exception))


class ProcessorExecutionTests(unittest.TestCase):
    def test_the_cpu_adapter_chain_comes_from_the_declared_protocol(self) -> None:
        plan = example_plan()
        self.assertEqual("obi_processor_memory_adapter", plan.cpu_adapter["module"])
        routes = plan.plan["processor_execution"]["routes"]
        self.assertEqual(1, len(routes))
        self.assertEqual("memory_master", routes[0]["function"])
        self.assertEqual(["processor-memory-beat", "1"], routes[0]["target_protocol"])
        self.assertEqual(1, routes[0]["backend_contract"]["capabilities"]["max_outstanding"])
        self.assertEqual({"READ_ONLY": 0, "HAS_BE": 1, "HAS_ERROR": 1},
                         {key: value for key, value in routes[0]["parameters"].items()
                          if key in ("READ_ONLY", "HAS_BE", "HAS_ERROR")})

    def test_a_unified_endpoint_is_not_split_into_two_interfaces(self) -> None:
        plan = example_plan()
        kinds = [item["kind"] for item in plan.plan["fabric"]["sources"]]
        self.assertEqual(["cpu_unified"], kinds)
        self.assertEqual(1, plan.plan["fabric"]["rtl"]["parameters"]["NUM_SOURCES"])

    def test_the_execution_identity_changes_with_the_port_mapping(self) -> None:
        from dataclasses import replace

        profile = example_profiles()["novacore"]
        endpoint = profile.endpoint("core.bus")
        swapped = replace(profile, endpoints=tuple(
            replace(item, fields=tuple(
                replace(field, aliases=("obi_addr_o",)) if field.role == "req"
                else replace(field, aliases=("obi_req_o",)) if field.role == "addr"
                else field for field in endpoint.fields))
            if item.endpoint_id == "core.bus" else item for item in profile.endpoints))
        profiles = dict(example_profiles())
        profiles["examples/soc_generation/profiles/novacore.json"] = swapped
        request = load_composition_request(
            ROOT / "examples/soc_generation/request.json", profiles=profiles)
        with self.assertRaises((CompositionError, ComponentProfileError)) as error:
            build_composition(request, base_dir=ROOT)
        self.assertTrue(any(token in str(error.exception)
                            for token in ("direction-conflict", "binding-", "protocol-width")),
                        str(error.exception))


class RawLayoutTests(unittest.TestCase):
    def test_special_inputs_get_stable_offsets_and_a_layout_identity(self) -> None:
        plan = example_plan()
        layout = plan.raw_layout
        self.assertEqual(7, layout["raw_width"])
        fields = {item["field_id"]: item for item in layout["fields"]}
        self.assertEqual({"cpu0::event_i:event_i", "gpio0::pin_mode_i:pin_mode_i"},
                         set(fields))
        self.assertEqual((0, 3), (fields["cpu0::event_i:event_i"]["raw_lo"],
                                  fields["cpu0::event_i:event_i"]["raw_hi"]))
        self.assertEqual((4, 6), (fields["gpio0::pin_mode_i:pin_mode_i"]["raw_lo"],
                                  fields["gpio0::pin_mode_i:pin_mode_i"]["raw_hi"]))
        for item in fields.values():
            self.assertEqual("input", item["binding"]["direction"])
            self.assertTrue(item["constraint"].get("randomizable"))
        self.assertTrue(layout["layout_hash"])
        self.assertEqual({"cpu0__event_i": "cycle_value",
                          "gpio0__pin_mode_i": "cycle_value"},
                         layout["drive_strategies"])

    def test_external_pins_are_not_in_the_random_layout(self) -> None:
        plan = example_plan()
        owners = {item["field_id"].split("::")[0] for item in plan.raw_layout["fields"]}
        self.assertNotIn("uart0", owners)
        self.assertNotIn("uart1", owners)

    def test_layout_identity_changes_when_the_profile_changes_the_input(self) -> None:
        document = json.loads((ROOT / "examples/soc_generation/profiles/novagpio.json").read_text())
        document["port_actions"][0]["bits"] = [0, 1]
        profiles = dict(example_profiles())
        profiles["examples/soc_generation/profiles/novagpio.json"] = \
            load_component_profile(document)
        request = load_composition_request(
            ROOT / "examples/soc_generation/request.json", profiles=profiles)
        with self.assertRaises((CompositionError, ComponentProfileError)):
            build_composition(request, base_dir=ROOT)


class RenderTests(unittest.TestCase):
    def test_render_is_deterministic_and_instance_qualified(self) -> None:
        plan = example_plan()
        first = render_composition(plan)
        second = render_composition(plan)
        self.assertEqual(first, second)
        top = first["myfuzz_soc_top.sv"]
        for name in ("cpu0__event_i", "gpio0__pin_mode_i", "uart0__uart_rx_i",
                     "uart1__uart_tx_o", "cpu0__status_o", "cpu0__trap_o"):
            self.assertIn(name, top)
        self.assertIn("u_uart0_adapter", top)
        self.assertIn("u_uart1_adapter", top)
        self.assertIn("soc_irq_controller", top)

    def test_source_list_covers_every_instantiated_thing(self) -> None:
        records = source_list(example_plan())
        paths = {item["path"] for item in records}
        for required in ("src/myfuzz/protocols/rtl/soc_arbiter.sv",
                         "src/myfuzz/protocols/rtl/soc_router.sv",
                         "src/myfuzz/protocols/rtl/soc_irq_controller.sv",
                         "src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv",
                         "src/myfuzz/protocols/rtl/beat_to_apb.sv",
                         "src/myfuzz/integration/rtl/riscv_boot_memory.sv",
                         "examples/soc_generation/rtl/novacore.sv",
                         "examples/soc_generation/rtl/novauart.sv",
                         "examples/soc_generation/rtl/novagpio.sv"):
            self.assertIn(required, paths)
        roles = {item["role"] for item in records}
        self.assertIn("interrupt_controller", roles)
        self.assertIn("soc_fabric", roles)

    def test_render_parameters_come_from_the_plan(self) -> None:
        plan = example_plan()
        top = render_composition(plan)["myfuzz_soc_top.sv"]
        parameters = plan.plan["fabric"]["rtl"]["parameters"]
        self.assertIn(f"localparam integer NUM_TARGETS = {parameters['NUM_TARGETS']};", top)
        self.assertIn(f"localparam integer NUM_SOURCES = {parameters['NUM_SOURCES']};", top)
        self.assertIn(f"localparam integer ADDRESS_WIDTH = {parameters['ADDRESS_WIDTH']};", top)
        self.assertIn("riscv_boot_memory_32 #(.BASE_ADDR(65536), .BYTES(32768),",
                      top)
        self.assertIn(".LOAD_IMAGE(1)", top)

    def test_composition_document_and_summary_are_self_consistent(self) -> None:
        plan = example_plan()
        document = composition_document(plan)
        self.assertEqual(plan.plan_hash, document["plan_hash"])
        self.assertEqual({"cpu0", "gpio0", "uart0", "uart1"},
                         {item["instance_id"] for item in document["instances"]})
        dispositions = document["dispositions"]
        self.assertEqual("soc_port_dispositions.v1", dispositions["schema_version"])
        self.assertEqual(len(document["soc_plan"]["address_map"]["windows"]),
                         len(document["soc_plan"]["target_capabilities"]))
        summary = composition_summary(plan)
        self.assertEqual(7, summary["raw_width"])
        self.assertEqual(3, summary["interrupt_sources"])


if __name__ == "__main__":
    unittest.main()
