from __future__ import annotations

import json
import io
import os
import shutil
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from dataclasses import replace
from pathlib import Path
from unittest.mock import ANY, patch

from myfuzz.composition import (
    GenericCompositionRequest,
    load_interface_description,
    plan_generic_composition,
    source_tree_hash,
    write_generic_composition,
)
from myfuzz.composition import protocol_composer
from myfuzz.composition.auto import _generic_source_evidence_hash
from myfuzz.composition.ids import canonical_id
from myfuzz.composition.ir import canonical_ir_hash
from tests.composition.test_generic_auto import GenericAutoCompositionTests, synthetic_description


class GenericCompositionIntegrationTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("verilator"), "verilator is not installed")
    def test_locator_and_filelist_include_precedence_agrees_with_compilation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            (source / "declared").mkdir(parents=True)
            (source / "listed").mkdir()
            header = source / "declared/width.svh"
            other = source / "listed/width.svh"
            header.write_text("`define PAYLOAD_WIDTH 8\n")
            other.write_text("`define PAYLOAD_WIDTH 16\n")
            hdl = source / "top.sv"
            hdl.write_text('`include "width.svh"\nmodule top(input logic [`PAYLOAD_WIDTH-1:0] value, output logic [`PAYLOAD_WIDTH-1:0] seen); assign seen=value; endmodule\n')
            filelist = source / "files.f"
            filelist.write_text("+incdir+listed\ntop.sv\n")
            description = load_interface_description({
                "schema_version": "interface_description.v1",
                "source": {"root": "source", "revision": source_tree_hash(source, (hdl, filelist, header, other)),
                           "top_module": "top", "filelist": "files.f", "include_roots": ["declared"],
                           "elaboration": {"frontend": "verilator-json"}},
                "endpoints": [{"endpoint_id": "control", "function": "control", "module": "top",
                               "fields": [{"role": "value", "aliases": ["value"]}, {"role": "seen", "aliases": ["seen"]}]}],
            })
            plan = plan_generic_composition(GenericCompositionRequest(description, ()), base_dir=root)
            assert {field.width for endpoint in plan.capabilities for field in endpoint.fields} == {8}
            write_generic_composition(plan, root / "out", base_dir=root)
            source_list = (root / "out/sources.f").read_text()
            assert source_list.index("declared") < source_list.index("listed")

    @unittest.skipUnless(shutil.which("verilator"), "verilator is not installed")
    def test_source_only_packed_containers_compile_and_require_complete_inputs(self) -> None:
        fields = [
            {"role": "lo", "port": "req", "direction": "input", "width": 8, "signed": False,
             "member_path": ["lo"], "raw_lo": 0, "raw_hi": 7, "container_width": 16},
            {"role": "hi", "port": "req", "direction": "input", "width": 8, "signed": False,
             "member_path": ["hi"], "raw_lo": 8, "raw_hi": 15, "container_width": 16},
            {"role": "value", "port": "rsp", "direction": "output", "width": 8, "signed": False,
             "member_path": ["value"], "raw_lo": 0, "raw_hi": 7, "container_width": 16},
        ]
        plan = SimpleNamespace(annotations={"endpoints": [{"endpoint_id": "packed", "fields": fields}]},
                               interface_description=SimpleNamespace(source=SimpleNamespace(top_module="packed_dut", elaboration=SimpleNamespace(parameters=(("WIDTH", "16"),)))))
        rendered = protocol_composer._render_generic_source_only_top(plan)
        self.assertEqual(1, rendered.count(".req("))
        self.assertEqual(1, rendered.count(".rsp("))
        self.assertIn("#(\n        .WIDTH(16)", rendered)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "dut.sv").write_text("typedef struct packed {logic [7:0] hi; logic [7:0] lo;} req_t; typedef struct packed {logic [7:0] pad; logic [7:0] value;} rsp_t; module packed_dut #(parameter WIDTH=16) (input req_t req, output rsp_t rsp); assign rsp='{default:'0}; endmodule\n", encoding="utf-8")
            (root / "top.sv").write_text(rendered, encoding="utf-8")
            result = subprocess.run(("nice", "-n15", "verilator", "--lint-only", "--top-module", "generic_composition_top", "dut.sv", "top.sv"), cwd=root, env={**os.environ, "JOBS": "1"}, capture_output=True, text=True, timeout=20, check=False)
            self.assertEqual(0, result.returncode, result.stderr)
        incomplete = SimpleNamespace(annotations={"endpoints": [{"endpoint_id": "packed", "fields": fields[:1]}]}, interface_description=plan.interface_description)
        with self.assertRaisesRegex(ValueError, "not fully covered"):
            protocol_composer._render_generic_source_only_top(incomplete)

    def test_complete_range_check_is_constant_in_container_width(self) -> None:
        self.assertTrue(protocol_composer._complete_ranges([(0, 8_388_607), (8_388_608, 16_777_215)], 16_777_216))
        self.assertFalse(protocol_composer._complete_ranges([(0, 8_388_607), (8_388_609, 16_777_215)], 16_777_216))

    @unittest.skipUnless(shutil.which("verilator"), "verilator is not installed")
    def test_connected_packed_plan_is_rebuilt_published_and_compiles(self) -> None:
        from myfuzz.components.catalog import ComponentCatalog
        from myfuzz.components.model import PeripheralProfile
        from myfuzz.protocols.catalog import ProtocolCatalog
        from myfuzz.protocols.model import (
            ChannelRelationSpec,
            FieldSpec,
            ProjectionActionSpec,
            ProtocolPlugin,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "source"
            source_root.mkdir()
            cpu = source_root / "packed_connected.sv"
            cpu.write_text(
                "`ifndef PACKED_FEATURE\npacked_feature_define_is_required\n`endif\n"
                "module packed_connected #(parameter integer W=8) (\n"
                " input logic clk, input logic rst,\n"
                " output struct packed {logic [W-1:0] addr; logic valid; logic [31:0] wdata;} req,\n"
                " input struct packed {logic ready; logic [31:0] rdata; logic error; logic irq;} rsp,\n"
                " output logic monitor);\n"
                " always_ff @(posedge clk or negedge rst) if (!rst) monitor <= 1'b0; else monitor <= req.valid;\n"
                "endmodule\n",
                encoding="utf-8",
            )
            device = root / "packed_device.sv"
            device.write_text(
                "module packed_device(input logic clock, input logic reset, input logic [15:0] addr, "
                "input logic valid, output logic ready, input logic [31:0] wdata, output logic [31:0] rdata, "
                "output logic error, output logic irq); "
                "always_ff @(posedge clock or negedge reset) if (!reset) rdata <= '0; else if (valid) rdata <= wdata; "
                "assign ready=valid; assign error=1'b0; assign irq=valid; endmodule\n",
                encoding="utf-8",
            )
            protocol = ProtocolCatalog((ProtocolPlugin(
                "packed-bounded", "1", (
                    FieldSpec("addr", "host_to_device", "address_width", True, 0),
                    FieldSpec("valid", "host_to_device", "1", True, 0),
                    FieldSpec("ready", "device_to_host", "1", True, 0),
                    FieldSpec("wdata", "host_to_device", "data_width", True, 0),
                    FieldSpec("rdata", "device_to_host", "data_width", True, 0),
                    FieldSpec("error", "device_to_host", "1", True, 0),
                    FieldSpec("irq", "device_to_host", "1", False, 0),
                ), (), (ProjectionActionSpec(1, ("valid",), "gate", "protocol_legality", 16),), (),
                (ChannelRelationSpec(1, "request_response_handshake", ("valid", "ready", "rdata")),),
                (("max_outstanding", 1), ("bursts", False), ("ids", False),
                 ("single_beat_only", True), ("ordering", "in_order_single_id"),
                 ("completion", "ack_or_err"), ("max_wait_cycles", 16)),
            ),))
            catalog = ComponentCatalog((PeripheralProfile(
                "packed-device", "packed_device", (("packed-bounded", "1"),),
                0x100, 0x100, True, (), "implemented", ("packed_device.sv",), True, {},
            ),))
            physical = {
                "addr": ("req", ("addr",)), "valid": ("req", ("valid",)),
                "wdata": ("req", ("wdata",)), "ready": ("rsp", ("ready",)),
                "rdata": ("rsp", ("rdata",)), "error": ("rsp", ("error",)),
                "irq": ("rsp", ("irq",)),
            }
            description = load_interface_description({
                "schema_version": "interface_description.v1",
                "source": {
                    "root": "source", "revision": source_tree_hash(source_root, (cpu,)),
                    "top_module": "packed_connected", "files": ["packed_connected.sv"],
                    "elaboration": {"frontend": "verilator-json",
                                    "defines": [{"name": "PACKED_FEATURE", "value": "1"}],
                                    "parameters": [{"name": "W", "value": "16"}]},
                },
                "endpoints": [{
                    "endpoint_id": "cpu.mmio", "function": "memory_master",
                    "module": "packed_connected", "protocol": ["packed-bounded", "1"],
                    "fields": [
                        {"role": "clock", "aliases": ["clk"]},
                        {"role": "reset", "aliases": ["rst"]},
                        {"role": "monitor", "aliases": ["monitor"]},
                        *({"role": role, "physical": {"port": port, "member_path": list(path)}}
                          for role, (port, path) in physical.items()),
                    ],
                }],
            })
            plan = plan_generic_composition(
                GenericCompositionRequest(description, ("packed-device",), (("packed-bounded", "1"),)),
                base_dir=root, component_catalog=catalog, protocol_catalog=protocol,
            )
            self.assertEqual(16, next(
                field.width for endpoint in plan.capabilities for field in endpoint.fields
                if field.role == "addr"
            ))
            output = root / "out"
            write_generic_composition(plan, output, base_dir=root)
            rendered = (output / "generic_composition_top.sv").read_text(encoding="utf-8")
            self.assertIn("#(\n        .W(16)", rendered)
            self.assertEqual(1, rendered.count(".req("))
            self.assertEqual(1, rendered.count(".rsp("))
            for role in ("ready", "rdata", "error", "irq"):
                field = next(
                    item for endpoint in plan.capabilities for item in endpoint.fields
                    if item.role == role
                )
                self.assertIn(f"[{field.raw_hi}:{field.raw_lo}]", rendered)
            strict = subprocess.run(
                ("nice", "-n15", "verilator", "--lint-only", "--sv", "--top-module",
                 "generic_composition_top", "-Wno-DECLFILENAME", "-Wno-UNUSEDSIGNAL",
                 "-Wno-UNDRIVEN", "-Wno-UNSIGNED", "-f", "sources.f"),
                cwd=output, env={**os.environ, "JOBS": "1"}, capture_output=True,
                text=True, timeout=20, check=False,
            )
            self.assertEqual(0, strict.returncode, strict.stderr)

    def test_stage_publish_error_leaves_no_output_or_hidden_transaction_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            description = synthetic_description(root, "stage_failure_cpu", ("clk", "rst", "fuzz", "seen"))
            plan = plan_generic_composition(GenericCompositionRequest(description, ()), base_dir=root)
            output = root / "out"

            with patch.object(protocol_composer.os, "replace", side_effect=OSError("injected stage publish failure")), \
                 patch.object(protocol_composer.os, "rename", side_effect=OSError("rename must not run")), \
                 patch.object(protocol_composer.shutil, "rmtree", side_effect=OSError("rmtree must not run")):
                with self.assertRaisesRegex(OSError, "injected stage publish failure"):
                    write_generic_composition(plan, output, base_dir=root)

            self.assertFalse(output.exists())
            self.assertFalse(any(path.name.startswith(".out.") for path in root.iterdir()))

    def test_writer_rejects_existing_output_directory_before_any_rollback_risk(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            description = synthetic_description(root, "published_directory_cpu", ("clk", "rst", "fuzz", "seen"))
            plan = plan_generic_composition(GenericCompositionRequest(description, ()), base_dir=root)
            output = root / "out"
            output.mkdir()
            (output / "old.txt").write_bytes(b"old output must survive")
            before = {path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()}

            with patch.object(protocol_composer.os, "replace", side_effect=OSError("replace must not run")), \
                 patch.object(protocol_composer.os, "rename", side_effect=OSError("rename must not run")), \
                 patch.object(protocol_composer.shutil, "rmtree", side_effect=OSError("rmtree must not run")):
                with self.assertRaisesRegex(ValueError, "existing output"):
                    write_generic_composition(plan, output, base_dir=root)

            self.assertTrue(output.is_dir())
            self.assertEqual(before, {path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()})
            self.assertFalse(any(path.name.startswith(".out.") for path in root.iterdir()))

    def test_filelist_expansion_emits_hdl_and_filelist_include_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            hdl = source / "rtl" / "filelist_cpu.sv"
            include = source / "zdir"
            second_include = source / "adir"
            hdl.parent.mkdir(parents=True)
            include.mkdir()
            second_include.mkdir()
            hdl.write_text(
                "module filelist_cpu(input logic clk, input logic rst, input logic [7:0] fuzz, output logic [15:0] seen); "
                "assign seen = `FILELIST_VALUE ? {fuzz, fuzz} : '0; endmodule\n", encoding="utf-8"
            )
            filelist = source / "sources.f"
            filelist.write_text("+incdir+zdir+adir\n+define+FILELIST_VALUE=1\nrtl/filelist_cpu.sv\n", encoding="utf-8")
            description = load_interface_description({
                "schema_version": "interface_description.v1",
                "source": {"root": "source", "revision": source_tree_hash(source, (filelist, hdl)),
                           "top_module": "filelist_cpu", "filelist": "sources.f"},
                "endpoints": [{"endpoint_id": "cpu.control", "function": "control", "module": "filelist_cpu",
                               "fields": [{"role": role, "aliases": [port]} for role, port in
                                          (("clock", "clk"), ("reset", "rst"), ("stimulus", "fuzz"), ("observation", "seen"))]}],
            })
            plan = plan_generic_composition(GenericCompositionRequest(description, ()), base_dir=root)
            self.assertEqual(plan.source_files, ("source/rtl/filelist_cpu.sv",))
            self.assertEqual(
                plan.ir["source_list"]["include_root_ids"],
                (
                    canonical_id("generic-include-root", "source/zdir"),
                    canonical_id("generic-include-root", "source/adir"),
                ),
            )
            output = root / "out"
            write_generic_composition(plan, output, base_dir=root)

            self.assertEqual(
                (output / "sources.f").read_text(encoding="utf-8"),
                "+incdir+../source/zdir\n+incdir+../source/adir\n+define+FILELIST_VALUE=1\n../source/rtl/filelist_cpu.sv\ngeneric_composition_top.sv\n",
            )

            before = plan.source_evidence_hash
            filelist.write_text("+incdir+zdir+adir\n+define+FILELIST_VALUE=0\nrtl/filelist_cpu.sv\n", encoding="utf-8")
            self.assertNotEqual(
                before,
                _generic_source_evidence_hash(root, plan.source_files, description.source),
            )

    def test_timeout_uses_minimum_of_projection_and_capability_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, _ = self._bounded_component_plan(root, "short_timeout_cpu", projection_cycles=2, max_wait_cycles=5)
            write_generic_composition(plan, root / "out", base_dir=root)
            adapter = plan.ir["adapters"][0]
            self.assertEqual(adapter["max_wait_cycles"], 2)
            top = (root / "out" / "generic_composition_top.sv").read_text(encoding="utf-8")
            self.assertIn("localparam int unsigned MAX_WAIT_CYCLES = 2;", top)

    def test_writer_lints_an_explicit_locator_include_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            hdl = source / "rtl" / "explicit_include_cpu.sv"
            include = source / "includes"
            hdl.parent.mkdir(parents=True)
            include.mkdir()
            (include / "defs.svh").write_text("`define EXPLICIT_INCLUDE_VALUE 1\n", encoding="utf-8")
            hdl.write_text(
                "`include \"defs.svh\"\n"
                "module explicit_include_cpu(input logic clk, input logic rst, input logic [7:0] fuzz, output logic [15:0] seen); "
                "assign seen = `EXPLICIT_INCLUDE_VALUE ? {fuzz, fuzz} : '0; endmodule\n",
                encoding="utf-8",
            )
            description = load_interface_description({
                "schema_version": "interface_description.v1",
                "source": {"root": "source", "revision": source_tree_hash(source, (hdl,)),
                           "top_module": "explicit_include_cpu", "files": ["rtl/explicit_include_cpu.sv"],
                           "include_roots": ["includes"]},
                "endpoints": [{"endpoint_id": "cpu.control", "function": "control", "module": "explicit_include_cpu",
                               "fields": [{"role": role, "aliases": [port]} for role, port in
                                          (("clock", "clk"), ("reset", "rst"), ("stimulus", "fuzz"), ("observation", "seen"))]}],
            })

            plan = plan_generic_composition(GenericCompositionRequest(description, ()), base_dir=root)
            write_generic_composition(plan, root / "out", base_dir=root)

            self.assertIn("+incdir+../source/includes", (root / "out" / "sources.f").read_text(encoding="utf-8"))

    def test_writer_rejects_existing_output_file_without_mutating_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            description = synthetic_description(root, "published_file_cpu", ("clk", "rst", "fuzz", "seen"))
            plan = plan_generic_composition(GenericCompositionRequest(description, ()), base_dir=root)
            output = root / "out"
            output.write_bytes(b"existing file must survive")

            with self.assertRaisesRegex(ValueError, "existing output"):
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
               (("max_outstanding", 1), ("bursts", False), ("ids", False), ("single_beat_only", True),
                ("ordering", "in_order_single_id"), ("completion", "ack_or_err"), ("max_wait_cycles", 16))),))
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
            with patch.object(protocol_composer.os, "replace", side_effect=OSError("replace must not run")), \
                 patch.object(protocol_composer.os, "rename", side_effect=OSError("rename must not run")), \
                 patch.object(protocol_composer.shutil, "rmtree", side_effect=OSError("rmtree must not run")):
                with self.assertRaisesRegex(ValueError, "existing output"):
                    write_generic_composition(replacement, output, base_dir=root)
            self.assertEqual(before, {path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()})
            self.assertFalse(any(path.name.startswith(".out.") for path in root.iterdir()))
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

    def test_cli_constrained_mode_compiles_contract_and_reports_artifact_paths(self) -> None:
        script = Path(__file__).resolve().parents[2] / "scripts" / "generate_composition.py"
        spec = importlib.util.spec_from_file_location("generic_composition_cli_constrained", script)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interface = root / "interface.json"
            interface.write_text("{}", encoding="utf-8")
            args = SimpleNamespace(
                config=None, frontend=None, top_k=None, protocol_manifest=None,
                interface_description=Path("interface.json"), base_dir=root,
                out_dir=Path("out"), component_type=[], protocol_preference=[],
                isa_xlen=32, isa_extension=["I", "M"], seed=None, root=None,
                frontend_library=None, constrained=True, max_wait_cycles=23,
                memory_capacity_entries=17, allow_error=False,
            )
            fake_plan = SimpleNamespace(processor_execution=object())
            execution = {"routes": [{"function": "processor_memory_master", "widths": {"address": 32, "data": 32}}]}
            contract = object()
            summary = {
                "schema_version": "composition_ir.v1", "interface_annotation_hash": "a",
                "composition_ir_hash": "b", "layout_hash": "c", "top_path": "top",
                "source_list_path": "sources", "complete": True,
            }
            with (
                patch.object(module, "parse_args", return_value=args),
                patch.object(
                    module, "load_interface_description",
                    return_value=synthetic_description(root, "cli_constrained_cpu", ("clk", "rst", "fuzz", "seen")),
                ),
                patch.object(module, "plan_generic_composition", return_value=fake_plan),
                patch.object(module, "processor_execution_document", return_value=execution, create=True),
                patch.object(module, "compile_contract_transducer", return_value=contract, create=True) as compile_contract,
                patch.object(module, "write_generic_composition", return_value=summary) as write,
                patch.object(sys, "stdout", new=io.StringIO()) as stdout,
            ):
                self.assertEqual(module.main(), 0)
            compile_contract.assert_called_once_with(
                isa=ANY, protocol=("processor-memory-beat", "1"),
                address_width=32, data_width=32,
                memory_domains={"instruction_memory_master": "main", "data_memory_master": "main"},
                max_wait_cycles=23, allow_error=False, memory_capacity_entries=17,
            )
            write.assert_called_once()
            self.assertIs(write.call_args.kwargs["contract_transducer"], contract)
            emitted = json.loads(stdout.getvalue())
            self.assertEqual(emitted["processor_execution_path"], str(root / "out/processor_execution.v1.json"))
            self.assertEqual(emitted["contract_transducer_path"], str(root / "out/contract_transducer.json"))

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
    def _bounded_component_plan(root: Path, module: str, *, projection_cycles: int = 16, max_wait_cycles: int = 16):
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
        ), (), (ProjectionActionSpec(1, ("valid",), "gate", "protocol_legality", projection_cycles),), (),
           (ChannelRelationSpec(1, "request_response_handshake", ("valid", "ready", "rdata")),),
           (("max_outstanding", 1), ("bursts", False), ("ids", False), ("single_beat_only", True),
            ("ordering", "in_order_single_id"), ("completion", "ack_or_err"), ("max_wait_cycles", max_wait_cycles))),))
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
