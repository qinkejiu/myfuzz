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
            (root / "device.sv").write_text("module device; endmodule\n", encoding="utf-8")
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
