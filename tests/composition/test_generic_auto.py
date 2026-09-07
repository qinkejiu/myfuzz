from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from myfuzz.composition import (
    GenericCompositionRequest,
    load_interface_description,
    plan_generic_composition,
    source_tree_hash,
)
from myfuzz.components.catalog import ComponentCatalog
from myfuzz.components.model import PeripheralProfile
from myfuzz.protocols.catalog import ProtocolCatalog
from myfuzz.protocols.model import FieldSpec, ProtocolPlugin


def synthetic_description(root: Path, module: str, names: tuple[str, str, str, str]):
    clock, reset, stimulus, observation = names
    source = root / "source" / "rtl" / f"{module}.sv"
    source.parent.mkdir(parents=True)
    source.write_text(
        f"""module {module}(
  input logic {clock},
  input logic {reset},
  input logic [7:0] {stimulus},
  output logic [15:0] {observation}
);
  assign {observation} = {{{{8{{{stimulus}[7]}}}}, {stimulus}}};
endmodule
""",
        encoding="utf-8",
    )
    return load_interface_description(
        {
            "schema_version": "interface_description.v1",
            "source": {
                "root": "source",
                "revision": source_tree_hash(root / "source", (source,)),
                "top_module": module,
                "files": [f"rtl/{module}.sv"],
            },
            "endpoints": [
                {
                    "endpoint_id": "cpu.control",
                    "function": "control",
                    "module": module,
                    "fields": [
                        {"role": "clock", "aliases": [clock]},
                        {"role": "reset", "aliases": [reset]},
                        {"role": "stimulus", "aliases": [stimulus]},
                        {"role": "observation", "aliases": [observation]},
                    ],
                }
            ],
        }
    )


class GenericAutoCompositionTests(unittest.TestCase):
    def test_component_binding_is_source_verified_and_records_generic_topology(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source" / "rtl" / "bus_cpu.sv"
            source.parent.mkdir(parents=True)
            source.write_text(
                """module bus_cpu(
 output logic [15:0] addr, output logic valid, input logic ready,
 output logic [31:0] wdata, input logic [31:0] rdata, input logic irq
); endmodule
""",
                encoding="utf-8",
            )
            (root / "device.sv").write_text(
                """module device(
 input logic [15:0] addr, input logic valid, output logic ready,
 input logic [31:0] wdata, output logic [31:0] rdata, output logic irq
); assign ready = valid; assign rdata = wdata; assign irq = valid; endmodule
""",
                encoding="utf-8",
            )
            description = self._opaque_description(root, source)
            protocol = self._opaque_protocol()
            catalog = ComponentCatalog((PeripheralProfile(
                "device", "device", (("opaque", "1"),), 0x100, 0x100, True,
                (), "implemented", ("device.sv",), True, {},
            ),))

            plan = plan_generic_composition(
                GenericCompositionRequest(description, ("device",), (("opaque", "1"),)),
                base_dir=root, component_catalog=catalog, protocol_catalog=protocol,
            )

            self.assertTrue(plan.complete)
            self.assertEqual(plan.components[0]["module_name"], "device")
            self.assertEqual(plan.components[0]["selected_endpoint"], "cpu.mmio")
            self.assertEqual(plan.components[0]["target_binding"]["module"], "device")
            self.assertTrue(any(match["accepted"] for match in plan.matches))
            self.assertEqual(plan.ir["instances"][0]["module_name"], "device")
            self.assertEqual(plan.ir["adapters"][0]["protocol"], ("opaque", "1"))
            self.assertEqual(plan.ir["address_regions"][0]["base"], 0)
            self.assertEqual(plan.ir["irq_routes"][0]["component_id"], "device0")

    def test_component_without_source_proven_ports_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source" / "rtl" / "bus_cpu.sv"
            source.parent.mkdir(parents=True)
            source.write_text(
                """module bus_cpu(
 output logic [15:0] addr, output logic valid, input logic ready,
 output logic [31:0] wdata, input logic [31:0] rdata, input logic irq
); endmodule
""",
                encoding="utf-8",
            )
            (root / "device.sv").write_text("module device; endmodule\n", encoding="utf-8")
            catalog = ComponentCatalog((PeripheralProfile(
                "device", "device", (("opaque", "1"),), 0x100, 0x100, False,
                (), "implemented", ("device.sv",), True, {},
            ),))
            with self.assertRaisesRegex(ValueError, "target-binding.*required-field"):
                plan_generic_composition(
                    GenericCompositionRequest(self._opaque_description(root, source), ("device",), (("opaque", "1"),)),
                    base_dir=root, component_catalog=catalog, protocol_catalog=self._opaque_protocol(),
                )

    def test_address_width_uses_apb_field_ids_and_width_expressions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cpu = root / "source" / "rtl" / "apb_cpu.sv"
            cpu.parent.mkdir(parents=True)
            cpu.write_text(
                """module apb_cpu(
 output logic [23:0] paddr, output logic [2:0] pprot, output logic psel,
 output logic penable, output logic pwrite, output logic [31:0] pwdata,
 output logic [3:0] pstrb, input logic pready, input logic [31:0] prdata,
 input logic pslverr
); endmodule
""",
                encoding="utf-8",
            )
            (root / "apb_device.sv").write_text(
                """module apb_device(
 input logic [23:0] paddr, input logic [2:0] pprot, input logic psel,
 input logic penable, input logic pwrite, input logic [31:0] pwdata,
 input logic [3:0] pstrb, output logic pready, output logic [31:0] prdata,
 output logic pslverr
); assign pready = psel; assign prdata = pwdata; assign pslverr = 1'b0; endmodule
""",
                encoding="utf-8",
            )
            description = load_interface_description({
                "schema_version": "interface_description.v1",
                "source": {"root": "source", "revision": source_tree_hash(root / "source", (cpu,)),
                           "top_module": "apb_cpu", "files": ["rtl/apb_cpu.sv"]},
                "endpoints": [{"endpoint_id": "cpu.apb", "function": "memory_master", "module": "apb_cpu",
                               "protocol": ["apb", "4"], "fields": [
                                   {"role": name, "aliases": [name]}
                                   for name in ("paddr", "pprot", "psel", "penable", "pwrite", "pwdata", "pstrb", "pready", "prdata", "pslverr")
                               ]}],
            })
            catalog = ComponentCatalog((PeripheralProfile(
                "apb_device", "apb_device", (("apb", "4"),), 0x100, 0x100, False,
                (), "implemented", ("apb_device.sv",), True, {},
            ),))
            plan = plan_generic_composition(
                GenericCompositionRequest(description, ("apb_device",), (("apb", "4"),)),
                base_dir=root, component_catalog=catalog,
            )
            self.assertEqual(plan.ir["target"]["address_width"], 24)

    def test_ambiguous_initiator_binding_fails_closed_with_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source" / "rtl" / "ambiguous.sv"
            source.parent.mkdir(parents=True)
            source.write_text(
                """module ambiguous(
 output logic [15:0] a_addr, output logic a_valid, input logic a_ready, output logic [31:0] a_wdata, input logic [31:0] a_rdata,
 output logic [15:0] b_addr, output logic b_valid, input logic b_ready, output logic [31:0] b_wdata, input logic [31:0] b_rdata
); endmodule
""", encoding="utf-8")
            (root / "device.sv").write_text(
                """module device(input logic [15:0] addr, input logic valid, output logic ready, input logic [31:0] wdata, output logic [31:0] rdata); assign ready=valid; assign rdata=wdata; endmodule
""", encoding="utf-8")
            description = load_interface_description({
                "schema_version": "interface_description.v1", "source": {"root": "source", "revision": source_tree_hash(root / "source", (source,)), "top_module": "ambiguous", "files": ["rtl/ambiguous.sv"]},
                "endpoints": [
                    {"endpoint_id": f"cpu.{name}", "function": "memory_master", "module": "ambiguous", "protocol": ["opaque", "1"], "fields": [{"role": role, "aliases": [f"{name}_{role}"]} for role in ("addr", "valid", "ready", "wdata", "rdata")]}
                    for name in ("a", "b")
                ],
            })
            catalog = ComponentCatalog((PeripheralProfile("device", "device", (("opaque", "1"),), 0x100, 0x100, False, (), "implemented", ("device.sv",), True, {}),))
            with self.assertRaisesRegex(ValueError, "ambiguous-source-endpoint:cpu.a,cpu.b"):
                plan_generic_composition(GenericCompositionRequest(description, ("device",)), base_dir=root, component_catalog=catalog, protocol_catalog=self._opaque_protocol())

    def test_multiple_protocols_require_preference_and_honor_its_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source" / "rtl" / "dual_protocol_cpu.sv"
            source.parent.mkdir(parents=True)
            source.write_text(
                "module dual_protocol_cpu("
                "output logic [15:0] a_addr, output logic a_valid, input logic a_ready, output logic [31:0] a_wdata, input logic [31:0] a_rdata, "
                "output logic [15:0] b_addr, output logic b_valid, input logic b_ready, output logic [31:0] b_wdata, input logic [31:0] b_rdata"
                "); endmodule\n", encoding="utf-8"
            )
            (root / "device.sv").write_text(
                "module device(input logic [15:0] addr, input logic valid, output logic ready, "
                "input logic [31:0] wdata, output logic [31:0] rdata); assign ready=valid; assign rdata=wdata; endmodule\n",
                encoding="utf-8",
            )
            fields = tuple(
                FieldSpec(name, direction, width, True, 0)
                for name, direction, width in (("addr", "host_to_device", "address_width"), ("valid", "host_to_device", "1"),
                                                ("ready", "device_to_host", "1"), ("wdata", "host_to_device", "data_width"),
                                                ("rdata", "device_to_host", "data_width"))
            )
            protocols = ProtocolCatalog((ProtocolPlugin("opaque", "1", fields, ()), ProtocolPlugin("opaque", "2", fields, ())))
            description = load_interface_description({
                "schema_version": "interface_description.v1",
                "source": {"root": "source", "revision": source_tree_hash(root / "source", (source,)),
                           "top_module": "dual_protocol_cpu", "files": ["rtl/dual_protocol_cpu.sv"]},
                "endpoints": [
                    {"endpoint_id": f"cpu.{prefix}", "function": "memory_master", "module": "dual_protocol_cpu",
                     "protocol": ["opaque", version], "fields": [{"role": role, "aliases": [f"{prefix}_{role}"]}
                     for role in ("addr", "valid", "ready", "wdata", "rdata")]}
                    for prefix, version in (("a", "1"), ("b", "2"))
                ],
            })
            catalog = ComponentCatalog((PeripheralProfile(
                "device", "device", (("opaque", "1"), ("opaque", "2")), 0x100, 0x100, False,
                (), "implemented", ("device.sv",), True, {},
            ),))
            with self.assertRaisesRegex(ValueError, "ambiguous-protocol:opaque@1,opaque@2"):
                plan_generic_composition(GenericCompositionRequest(description, ("device",)), base_dir=root,
                                         component_catalog=catalog, protocol_catalog=protocols)
            plan = plan_generic_composition(GenericCompositionRequest(
                description, ("device",), (("opaque", "2"), ("opaque", "1")),
            ), base_dir=root, component_catalog=catalog, protocol_catalog=protocols)
            self.assertEqual(plan.components[0]["protocol"]["version"], "2")
            self.assertEqual(plan.components[0]["selected_endpoint"], "cpu.b")

    @staticmethod
    def _opaque_protocol() -> ProtocolCatalog:
        return ProtocolCatalog((ProtocolPlugin("opaque", "1", (
            FieldSpec("addr", "host_to_device", "address_width", True, 0),
            FieldSpec("valid", "host_to_device", "1", True, 0),
            FieldSpec("ready", "device_to_host", "1", True, 0),
            FieldSpec("wdata", "host_to_device", "data_width", True, 0),
            FieldSpec("rdata", "device_to_host", "data_width", True, 0),
            FieldSpec("irq", "device_to_host", "1", False, 0),
        ), ()),))

    @staticmethod
    def _opaque_description(root: Path, source: Path):
        return load_interface_description({
            "schema_version": "interface_description.v1",
            "source": {"root": "source", "revision": source_tree_hash(root / "source", (source,)),
                       "top_module": "bus_cpu", "files": ["rtl/bus_cpu.sv"]},
            "endpoints": [{"endpoint_id": "cpu.mmio", "function": "memory_master", "module": "bus_cpu",
                           "protocol": ["opaque", "1"], "fields": [
                               {"role": name, "aliases": [name]}
                               for name in ("addr", "valid", "ready", "wdata", "rdata", "irq")
                           ]}],
        })

    def test_source_renamed_synthetic_cpus_plan_without_cpu_branch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = synthetic_description(root / "first", "alpha_tile", ("alpha_clk", "alpha_rst", "alpha_fuzz", "alpha_seen"))
            second = synthetic_description(root / "second", "beta_tile", ("beta_clk", "beta_rst", "beta_fuzz", "beta_seen"))

            first_plan = plan_generic_composition(GenericCompositionRequest(first, ()), base_dir=root / "first")
            second_plan = plan_generic_composition(GenericCompositionRequest(second, ()), base_dir=root / "second")

            self.assertTrue(first_plan.complete)
            self.assertTrue(second_plan.complete)
            self.assertEqual(first_plan.layout.raw_width, second_plan.layout.raw_width)
            self.assertNotEqual(first_plan.interface_annotation_hash, second_plan.interface_annotation_hash)
            self.assertEqual(first_plan.annotations["endpoints"][0]["module"], "alpha_tile")
            self.assertEqual(second_plan.annotations["endpoints"][0]["module"], "beta_tile")

    def test_missing_required_annotation_fails_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            description = synthetic_description(root, "missing_tile", ("clk", "rst", "fuzz", "seen"))
            broken = load_interface_description(
                {
                    "schema_version": "interface_description.v1",
                    "source": {
                        "root": "source",
                        "revision": description.source.revision,
                        "top_module": "missing_tile",
                        "files": ["rtl/missing_tile.sv"],
                    },
                    "endpoints": [{
                        "endpoint_id": "cpu.control", "function": "control", "module": "missing_tile",
                        "fields": [{"role": "stimulus", "aliases": ["does_not_exist"]}],
                    }],
                }
            )
            output = root / "out"
            with self.assertRaisesRegex(ValueError, "field-unresolved"):
                plan_generic_composition(GenericCompositionRequest(broken, ()), base_dir=root)
            self.assertFalse(output.exists())

    def test_catalog_component_uses_protocol_matching_and_declared_alignment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source" / "rtl" / "bus_cpu.sv"
            source.parent.mkdir(parents=True)
            source.write_text(
                """module bus_cpu(
 output logic [15:0] opaque_addr, output logic opaque_valid,
 input logic opaque_ready, output logic [31:0] opaque_wdata,
 input logic [31:0] opaque_rdata
); endmodule
""",
                encoding="utf-8",
            )
            (root / "device.sv").write_text(
                "module device(input logic [15:0] addr, input logic valid, output logic ready, "
                "input logic [31:0] wdata, output logic [31:0] rdata); "
                "assign ready=valid; assign rdata=wdata; endmodule\n", encoding="utf-8"
            )
            description = load_interface_description({
                "schema_version": "interface_description.v1",
                "source": {"root": "source", "revision": source_tree_hash(root / "source", (source,)),
                           "top_module": "bus_cpu", "files": ["rtl/bus_cpu.sv"]},
                "endpoints": [{"endpoint_id": "cpu.mmio", "function": "memory_master", "module": "bus_cpu",
                    "protocol": ["opaque", "1"], "fields": [
                        {"role": "addr", "aliases": ["opaque_addr"]},
                        {"role": "valid", "aliases": ["opaque_valid"]},
                        {"role": "ready", "aliases": ["opaque_ready"]},
                        {"role": "wdata", "aliases": ["opaque_wdata"]},
                        {"role": "rdata", "aliases": ["opaque_rdata"]},
                    ]}],
            })
            protocol = ProtocolCatalog((ProtocolPlugin("opaque", "1", (
                FieldSpec("addr", "host_to_device", "address_width", True, 0),
                FieldSpec("valid", "host_to_device", "1", True, 0),
                FieldSpec("ready", "device_to_host", "1", True, 0),
                FieldSpec("wdata", "host_to_device", "data_width", True, 0),
                FieldSpec("rdata", "device_to_host", "data_width", True, 0),
            ), ()),))
            catalog = ComponentCatalog((PeripheralProfile(
                "device", "device", (("opaque", "1"),), 0x100, 0x100, False,
                (), "implemented", ("device.sv",), True, {},
            ),))

            plan = plan_generic_composition(
                GenericCompositionRequest(description, ("device",), (("opaque", "1"),)),
                base_dir=root,
                component_catalog=catalog,
                protocol_catalog=protocol,
            )

            self.assertEqual(plan.components[0]["base"], 0)
            self.assertEqual(plan.components[0]["size"], 0x100)
            self.assertTrue(any(match["accepted"] for match in plan.matches))

            irq_catalog = ComponentCatalog((PeripheralProfile(
                "irq_device", "device", (("opaque", "1"),), 0x100, 0x100, True,
                (), "implemented", ("device.sv",), True, {},
            ),))
            with self.assertRaisesRegex(ValueError, "irq-endpoint-unavailable"):
                plan_generic_composition(
                    GenericCompositionRequest(description, ("irq_device",), (("opaque", "1"),)),
                    base_dir=root,
                    component_catalog=irq_catalog,
                    protocol_catalog=protocol,
                )


if __name__ == "__main__":
    unittest.main()
