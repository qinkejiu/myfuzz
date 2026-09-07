from __future__ import annotations

import json
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from myfuzz.composition import (
    GenericCompositionRequest,
    load_interface_description,
    plan_generic_composition,
    source_tree_hash,
    write_generic_composition,
)
from myfuzz.composition import protocol_composer
from myfuzz.composition.ir import canonical_ir_hash
from tests.composition.test_generic_auto import GenericAutoCompositionTests, synthetic_description


class GenericCompositionIntegrationTests(unittest.TestCase):
    def test_writer_rejects_existing_output_file_without_mutating_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            description = synthetic_description(root, "published_file_cpu", ("clk", "rst", "fuzz", "seen"))
            plan = plan_generic_composition(GenericCompositionRequest(description, ()), base_dir=root)
            output = root / "out"
            output.write_bytes(b"existing file must survive")

            with self.assertRaisesRegex(ValueError, "existing output is not a directory"):
                write_generic_composition(plan, output, base_dir=root)

            self.assertTrue(output.is_file())
            self.assertEqual(output.read_bytes(), b"existing file must survive")

    def test_writer_rejects_ir_forgery_even_when_hash_is_updated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            description = synthetic_description(root, "forged_ir_cpu", ("clk", "rst", "fuzz", "seen"))
            plan = plan_generic_composition(GenericCompositionRequest(description, ()), base_dir=root)
            forged = dict(plan.ir)
            forged["target"] = {"top_module": "forged_top"}
            object.__setattr__(plan, "ir", forged)
            object.__setattr__(plan, "composition_ir_hash", canonical_ir_hash(forged))

            with self.assertRaisesRegex(ValueError, "plan reconstruction mismatch"):
                write_generic_composition(plan, root / "out", base_dir=root)

    def test_writer_rejects_component_source_bytes_changed_after_planning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, component_source = self._bounded_component_plan(root, "component_pin_cpu")
            component_source.write_text(
                component_source.read_text(encoding="utf-8") + "// changed after planning\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "plan reconstruction mismatch"):
                write_generic_composition(plan, root / "out", base_dir=root)
            self.assertFalse((root / "out").exists())

    def test_writer_renders_stateful_bounded_adapter_with_real_control_nets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cpu = root / "source" / "rtl" / "bounded_cpu.sv"
            cpu.parent.mkdir(parents=True)
            cpu.write_text(
                "module bounded_cpu(input logic clk, input logic rst, output logic [15:0] addr, "
                "output logic valid, input logic ready, output logic [31:0] wdata, input logic [31:0] rdata, "
                "input logic error, input logic irq, output logic monitor); "
                "always_ff @(posedge clk or negedge rst) if (!rst) monitor <= 1'b0; else monitor <= valid; endmodule\n",
                encoding="utf-8",
            )
            (root / "bounded_device.sv").write_text(
                "module bounded_device(input logic clock, input logic reset, input logic [15:0] addr, "
                "input logic valid, output logic ready, input logic [31:0] wdata, output logic [31:0] rdata, "
                "output logic error, output logic irq); logic state; "
                "always_ff @(posedge clock or negedge reset) if (!reset) state <= 1'b0; else state <= valid; "
                "assign ready = valid; assign rdata = wdata; assign error = 1'b0; assign irq = valid; endmodule\n",
                encoding="utf-8",
            )
            from myfuzz.components.catalog import ComponentCatalog
            from myfuzz.components.model import PeripheralProfile
            from myfuzz.protocols.catalog import ProtocolCatalog
            from myfuzz.protocols.model import ChannelRelationSpec, FieldSpec, ProjectionActionSpec, ProtocolPlugin
            protocol = ProtocolCatalog((ProtocolPlugin("bounded", "1", (
                FieldSpec("addr", "host_to_device", "address_width", True, 0),
                FieldSpec("valid", "host_to_device", "1", True, 0),
                FieldSpec("ready", "device_to_host", "1", True, 0),
                FieldSpec("wdata", "host_to_device", "data_width", True, 0),
                FieldSpec("rdata", "device_to_host", "data_width", True, 0),
                FieldSpec("error", "device_to_host", "1", True, 0),
                FieldSpec("irq", "device_to_host", "1", False, 0),
            ), (), (ProjectionActionSpec(1, ("valid",), "gate", "protocol_legality", 16),), (),
               (ChannelRelationSpec(1, "request_response_handshake", ("valid", "ready", "rdata")),),
               (("max_outstanding", 1), ("bursts", False), ("ids", False))),))
            description = load_interface_description({
                "schema_version": "interface_description.v1",
                "source": {"root": "source", "revision": source_tree_hash(root / "source", (cpu,)),
                           "top_module": "bounded_cpu", "files": ["rtl/bounded_cpu.sv"]},
                "endpoints": [{"endpoint_id": "cpu.mmio", "function": "memory_master", "module": "bounded_cpu",
                               "protocol": ["bounded", "1"], "fields": [
                                   {"role": role, "aliases": [port]} for role, port in (
                                       ("clock", "clk"), ("reset", "rst"), ("monitor", "monitor"),
                                       ("addr", "addr"), ("valid", "valid"), ("ready", "ready"),
                                       ("wdata", "wdata"), ("rdata", "rdata"), ("error", "error"), ("irq", "irq"),
                                   )
                               ]}],
            })
            catalog = ComponentCatalog((PeripheralProfile(
                "bounded", "bounded_device", (("bounded", "1"),), 0x100, 0x100,
                True, (), "implemented", ("bounded_device.sv",), True, {},
            ),))
            plan = plan_generic_composition(
                GenericCompositionRequest(description, ("bounded",), (("bounded", "1"),)),
                base_dir=root, component_catalog=catalog, protocol_catalog=protocol,
            )
            write_generic_composition(plan, root / "out", base_dir=root)
            top = (root / "out" / "generic_composition_top.sv").read_text(encoding="utf-8")
            self.assertIn("typedef enum logic", top)
            self.assertIn("wait_cycles", top)
            self.assertIn("timeout_error", top)
            self.assertIn("MAX_WAIT_CYCLES", top)
            self.assertIn(".clock(p_", top)
            self.assertIn(".reset(p_", top)
            self.assertNotIn(" || ", top)

    def test_writer_rejects_base_and_source_overlap_before_any_publish(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            description = synthetic_description(root, "sealed_boundary_cpu", ("clk", "rst", "fuzz", "seen"))
            plan = plan_generic_composition(GenericCompositionRequest(description, ()), base_dir=root)
            protected = (root, root / "source", root / "source" / "rtl" / "sealed_boundary_cpu.sv")
            original_replace = protocol_composer.os.replace

            def reject_publish(source, destination):
                if Path(destination) in protected and ".generic-" in Path(source).name:
                    raise AssertionError("writer attempted publication into protected source")
                return original_replace(source, destination)

            for output in protected:
                with self.subTest(output=output), patch.object(
                    protocol_composer.os, "replace", side_effect=reject_publish
                ):
                    with self.assertRaisesRegex(ValueError, "base_dir itself|overlaps source"):
                        write_generic_composition(plan, output, base_dir=root)
            self.assertTrue((root / "source" / "rtl" / "sealed_boundary_cpu.sv").is_file())

    def test_writer_rejects_stale_source_evidence_and_mutated_ir(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            description = synthetic_description(root, "stale_cpu", ("clk", "rst", "fuzz", "seen"))
            plan = plan_generic_composition(GenericCompositionRequest(description, ()), base_dir=root)
            source = root / "source" / "rtl" / "stale_cpu.sv"
            source.write_text(source.read_text(encoding="utf-8") + "// stale plan\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "stale source evidence"):
                write_generic_composition(plan, root / "out", base_dir=root)

            fresh = plan_generic_composition(
                GenericCompositionRequest(
                    load_interface_description({
                        "schema_version": "interface_description.v1",
                        "source": {"root": "source", "revision": source_tree_hash(root / "source", (source,)),
                                   "top_module": "stale_cpu", "files": ["rtl/stale_cpu.sv"]},
                        "endpoints": [{"endpoint_id": "cpu.control", "function": "control", "module": "stale_cpu",
                                       "fields": [{"role": role, "aliases": [port]} for role, port in
                                                  (("clock", "clk"), ("reset", "rst"), ("stimulus", "fuzz"), ("observation", "seen"))]}],
                    }),
                    (),
                ),
                base_dir=root,
            )
            changed_ir = dict(fresh.ir)
            changed_ir["instances"] = [{"instance_id": "forged"}]
            object.__setattr__(fresh, "ir", changed_ir)
            with self.assertRaisesRegex(ValueError, "plan reconstruction mismatch"):
                write_generic_composition(fresh, root / "out", base_dir=root)

    def test_writer_renders_source_verified_component_adapter_and_routes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source" / "rtl" / "bus_cpu.sv"
            source.parent.mkdir(parents=True)
            source.write_text("module bus_cpu(output logic [15:0] addr, output logic valid, input logic ready, output logic [31:0] wdata, input logic [31:0] rdata, input logic irq); endmodule\n", encoding="utf-8")
            (root / "device.sv").write_text("module device(input logic [15:0] addr, input logic valid, output logic ready, input logic [31:0] wdata, output logic [31:0] rdata, output logic irq); assign ready=valid; assign rdata=wdata; assign irq=valid; endmodule\n", encoding="utf-8")
            from myfuzz.components.catalog import ComponentCatalog
            from myfuzz.components.model import PeripheralProfile
            catalog = ComponentCatalog((PeripheralProfile("device", "device", (("opaque", "1"),), 0x100, 0x100, True, (), "implemented", ("device.sv",), True, {}),))
            with self.assertRaisesRegex(ValueError, "target-binding:control:clock"):
                plan_generic_composition(
                    GenericCompositionRequest(GenericAutoCompositionTests._opaque_description(root, source), ("device",), (("opaque", "1"),)),
                    base_dir=root, component_catalog=catalog, protocol_catalog=GenericAutoCompositionTests._opaque_protocol(),
                )

    def test_writer_uses_relative_stable_sources_and_rejects_external_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            description = synthetic_description(root, "portable_cpu", ("clk", "rst", "fuzz", "seen"))
            include_root = root / "source" / "includes"
            include_root.mkdir()
            header = include_root / "portable_defs.svh"
            header.write_text("`define PORTABLE_VALUE 1\n", encoding="utf-8")
            description = replace(
                description,
                source=replace(description.source, include_roots=("includes",)),
            )
            plan = plan_generic_composition(GenericCompositionRequest(description, ()), base_dir=root)
            first, second = root / "one", root / "two"
            write_generic_composition(plan, first, base_dir=root)
            write_generic_composition(plan, second, base_dir=root)
            self.assertEqual((first / "sources.f").read_bytes(), (second / "sources.f").read_bytes())
            self.assertEqual(
                (first / "sources.f").read_text(encoding="utf-8"),
                "+incdir+../source/includes\n../source/rtl/portable_cpu.sv\ngeneric_composition_top.sv\n",
            )
            with self.assertRaisesRegex(ValueError, "outside base_dir"):
                write_generic_composition(plan, root.parent / "external", base_dir=root)
            header.write_text("`define PORTABLE_VALUE 2\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "plan reconstruction mismatch"):
                write_generic_composition(plan, root / "three", base_dir=root)

    def test_writer_restores_entire_existing_output_when_publish_replacement_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            description = synthetic_description(root, "transaction_cpu", ("clk", "rst", "fuzz", "seen"))
            output = root / "out"
            original = plan_generic_composition(GenericCompositionRequest(description, (), seed=7), base_dir=root)
            replacement = plan_generic_composition(GenericCompositionRequest(description, (), seed=8), base_dir=root)
            write_generic_composition(original, output, base_dir=root)
            before = {path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()}
            original_replace = protocol_composer.os.replace

            def fail_stage_publish(source, destination):
                if Path(source).name.startswith(".out.generic-") and Path(destination) == output:
                    raise OSError("injected publish failure")
                return original_replace(source, destination)

            with patch.object(protocol_composer.os, "replace", side_effect=fail_stage_publish):
                with self.assertRaisesRegex(OSError, "injected publish failure"):
                    write_generic_composition(replacement, output, base_dir=root)
            self.assertEqual(before, {path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()})
    def test_writer_publishes_deterministic_ir_layout_top_and_source_list(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            description = synthetic_description(root, "opaque_cpu", ("x_clock", "x_reset", "x_input", "x_output"))
            plan = plan_generic_composition(GenericCompositionRequest(description, ()), base_dir=root)
            first_dir, second_dir = root / "one", root / "two"

            first = write_generic_composition(plan, first_dir, base_dir=root)
            second = write_generic_composition(plan, second_dir, base_dir=root)

            self.assertTrue(first["complete"])
            self.assertEqual(first["composition_ir_hash"], second["composition_ir_hash"])
            self.assertEqual(first["layout_hash"], second["layout_hash"])
            self.assertEqual(first["interface_annotation_hash"], second["interface_annotation_hash"])
            self.assertEqual(Path(first["top_path"]), first_dir / "generic_composition_top.sv")
            self.assertEqual(Path(first["source_list_path"]), first_dir / "sources.f")
            self.assertTrue((first_dir / "composition_ir.json").is_file())
            self.assertTrue((first_dir / "input_layout.json").is_file())
            self.assertEqual(
                (first_dir / "composition_ir.json").read_bytes(),
                (second_dir / "composition_ir.json").read_bytes(),
            )
            top = (first_dir / "generic_composition_top.sv").read_text(encoding="utf-8")
            self.assertIn("module generic_composition_top", top)
            self.assertIn("opaque_cpu", top)
            self.assertNotIn("ibex", top.lower())
            self.assertEqual((first_dir / "sources.f").read_text(encoding="utf-8"), "../source/rtl/opaque_cpu.sv\ngeneric_composition_top.sv\n")
            self.assertEqual(json.loads((first_dir / "composition_ir.json").read_text())["composition_kind"], "generic_composition")

    def test_writer_does_not_replace_existing_artifacts_after_source_disappears(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            description = synthetic_description(root, "sealed_cpu", ("clk", "rst", "fuzz", "seen"))
            plan = plan_generic_composition(GenericCompositionRequest(description, ()), base_dir=root)
            output = root / "out"
            write_generic_composition(plan, output, base_dir=root)
            before = {
                path.name: path.read_bytes()
                for path in output.iterdir()
                if path.is_file()
            }
            (root / "source" / "rtl" / "sealed_cpu.sv").unlink()

            with self.assertRaisesRegex(ValueError, "stale source evidence"):
                write_generic_composition(plan, output, base_dir=root)

            self.assertEqual(
                before,
                {path.name: path.read_bytes() for path in output.iterdir() if path.is_file()},
            )

    def test_cli_interface_description_mode_uses_base_dir(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            description = synthetic_description(root, "cli_cpu", ("clk", "rst", "fuzz", "seen"))
            document = {
                "schema_version": "interface_description.v1",
                "source": {"root": description.source.source_root, "revision": description.source.revision,
                           "top_module": description.source.top_module, "files": list(description.source.files)},
                "endpoints": [{"endpoint_id": endpoint.endpoint_id, "function": endpoint.function,
                               "module": endpoint.module,
                               "fields": [{"role": field.role, "aliases": list(field.aliases)} for field in endpoint.fields]}
                              for endpoint in description.endpoints],
            }
            (root / "interface.json").write_text(json.dumps(document), encoding="utf-8")
            script = Path(__file__).resolve().parents[2] / "scripts" / "generate_composition.py"
            result = subprocess.run(
                ["python3", script, "--interface-description", "interface.json", "--base-dir", root, "--out-dir", "out"],
                check=False, capture_output=True, text=True,
                env={"PYTHONPATH": str(Path(__file__).resolve().parents[2] / "src")},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads(result.stdout)
            self.assertTrue(summary["complete"])
            self.assertTrue((root / "out" / "generic_composition_top.sv").is_file())

    def test_cli_generic_options_are_forwarded_to_the_request(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            description = synthetic_description(root, "cli_options_cpu", ("clk", "rst", "fuzz", "seen"))
            document = {
                "schema_version": "interface_description.v1",
                "source": {"root": description.source.source_root, "revision": description.source.revision,
                           "top_module": description.source.top_module, "files": list(description.source.files)},
                "endpoints": [{"endpoint_id": endpoint.endpoint_id, "function": endpoint.function,
                               "module": endpoint.module,
                               "fields": [{"role": field.role, "aliases": list(field.aliases)} for field in endpoint.fields]}
                              for endpoint in description.endpoints],
            }
            (root / "interface.json").write_text(json.dumps(document), encoding="utf-8")
            script = Path(__file__).resolve().parents[2] / "scripts" / "generate_composition.py"
            spec = importlib.util.spec_from_file_location("generic_composition_cli", script)
            assert spec is not None and spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            observed = []
            summary = {"schema_version": "composition_ir.v1", "interface_annotation_hash": "a",
                       "composition_ir_hash": "b", "layout_hash": "c", "top_path": "top",
                       "source_list_path": "sources", "complete": True}
            with patch.object(module, "plan_generic_composition", side_effect=lambda request, **_: observed.append(request) or object()), \
                 patch.object(module, "write_generic_composition", return_value=summary), \
                 patch.object(sys, "argv", [str(script), "--interface-description", "interface.json", "--base-dir", str(root),
                                              "--out-dir", "out", "--component-type", "ram", "--component-type", "gpio",
                                              "--protocol-preference", "obi@1", "--protocol-preference", "apb@4",
                                              "--isa-xlen", "64", "--isa-extension", "I", "--isa-extension", "M", "--seed", "23"]):
                self.assertEqual(module.main(), 0)
            self.assertEqual(observed[0].component_types, ("ram", "gpio"))
            self.assertEqual(observed[0].protocol_preferences, (("obi", "1"), ("apb", "4")))
            self.assertEqual(observed[0].isa.xlen, 64)
            self.assertEqual(observed[0].isa.extensions, ("I", "M"))
            self.assertEqual(observed[0].seed, 23)

    def test_cli_rejects_explicit_generic_default_seed_in_protocol_mode(self) -> None:
        script = Path(__file__).resolve().parents[2] / "scripts" / "generate_composition.py"
        spec = importlib.util.spec_from_file_location("generic_composition_cli_seed", script)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with patch.object(sys, "argv", [str(script), "--protocol-manifest", "plan.json", "--out-dir", "out", "--seed", "7"]):
            with self.assertRaises(SystemExit) as raised:
                module.parse_args()
        self.assertEqual(raised.exception.code, 2)

    @staticmethod
    def _bounded_component_plan(root: Path, module: str):
        cpu = root / "source" / "rtl" / f"{module}.sv"
        cpu.parent.mkdir(parents=True)
        cpu.write_text(
            f"module {module}(input logic clk, input logic rst, output logic [15:0] addr, output logic valid, "
            "input logic ready, output logic [31:0] wdata, input logic [31:0] rdata, input logic error, output logic monitor); "
            "always_ff @(posedge clk or negedge rst) if (!rst) monitor <= 1'b0; else monitor <= valid; endmodule\n",
            encoding="utf-8",
        )
        component = root / "bounded_device.sv"
        component.write_text(
            "module bounded_device(input logic clock, input logic reset, input logic [15:0] addr, input logic valid, "
            "output logic ready, input logic [31:0] wdata, output logic [31:0] rdata, output logic error); "
            "logic state; always_ff @(posedge clock or negedge reset) if (!reset) state <= 1'b0; else state <= valid; "
            "assign ready = valid; assign rdata = wdata; assign error = 1'b0; endmodule\n",
            encoding="utf-8",
        )
        from myfuzz.components.catalog import ComponentCatalog
        from myfuzz.components.model import PeripheralProfile
        from myfuzz.protocols.catalog import ProtocolCatalog
        from myfuzz.protocols.model import ChannelRelationSpec, FieldSpec, ProjectionActionSpec, ProtocolPlugin
        protocol = ProtocolCatalog((ProtocolPlugin("bounded", "1", (
            FieldSpec("addr", "host_to_device", "address_width", True, 0),
            FieldSpec("valid", "host_to_device", "1", True, 0),
            FieldSpec("ready", "device_to_host", "1", True, 0),
            FieldSpec("wdata", "host_to_device", "data_width", True, 0),
            FieldSpec("rdata", "device_to_host", "data_width", True, 0),
            FieldSpec("error", "device_to_host", "1", True, 0),
        ), (), (ProjectionActionSpec(1, ("valid",), "gate", "protocol_legality", 16),), (),
           (ChannelRelationSpec(1, "request_response_handshake", ("valid", "ready", "rdata")),),
           (("max_outstanding", 1), ("bursts", False), ("ids", False))),))
        description = load_interface_description({
            "schema_version": "interface_description.v1",
            "source": {"root": "source", "revision": source_tree_hash(root / "source", (cpu,)),
                       "top_module": module, "files": [f"rtl/{module}.sv"]},
            "endpoints": [{"endpoint_id": "cpu.mmio", "function": "memory_master", "module": module,
                           "protocol": ["bounded", "1"], "fields": [
                               {"role": role, "aliases": [port]} for role, port in (
                                   ("clock", "clk"), ("reset", "rst"), ("monitor", "monitor"), ("addr", "addr"), ("valid", "valid"),
                                   ("ready", "ready"), ("wdata", "wdata"), ("rdata", "rdata"), ("error", "error"),
                               )
                           ]}],
        })
        catalog = ComponentCatalog((PeripheralProfile(
            "bounded", "bounded_device", (("bounded", "1"),), 0x100, 0x100,
            False, (), "implemented", ("bounded_device.sv",), True, {},
        ),))
        return (
            plan_generic_composition(
                GenericCompositionRequest(description, ("bounded",), (("bounded", "1"),)),
                base_dir=root, component_catalog=catalog, protocol_catalog=protocol,
            ),
            component,
        )


if __name__ == "__main__":
    unittest.main()
