from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from myfuzz.composition import (
    GenericCompositionRequest,
    load_interface_description,
    plan_generic_composition,
    source_tree_hash,
    write_generic_composition,
)
from myfuzz.composition.processor_adapters import resolve_processor_adapter
from myfuzz.composition.processor_boundary import ProcessorMemoryBinding
from myfuzz.composition.endpoint_capabilities import EndpointFieldFact, SourceReference
from myfuzz.composition.ids import canonical_id
from myfuzz.components.catalog import ComponentCatalog
from myfuzz.components.model import PeripheralProfile
from myfuzz.protocols.catalog import load_protocol_catalog
from myfuzz.protocols.widths import compile_width_expression


ROOT = Path(__file__).resolve().parents[2]
PROTOCOLS = (("obi", "1"), ("axi4", "1"), ("tl-ul", "1"))


def _fixture(root: Path, protocol: tuple[str, str], ordinal: int, *, with_ram: bool = False):
    catalog = load_protocol_catalog(ROOT / "src/myfuzz/protocols/plugins")
    plugin = catalog.require(*protocol)
    parameters = {"address_width": 32, "data_width": 32, "id_width": 4,
                  "source_width": 4, "sink_width": 1, "user_width": 3}
    fields = [
        EndpointFieldFact(
            spec.field_id,
            f"p_{ordinal}_{spec.field_id}",
            "output" if spec.direction == "host_to_device" else "input",
            compile_width_expression(spec.width_expression, parameters),
            False,
            SourceReference("rtl/renamed.sv", 1, 1),
            ("compiler",),
        )
        for spec in plugin.fields
    ]
    protocol_roles = {field.role for field in fields}
    extensions = []
    if protocol == ("obi", "1"):
        extensions.append(EndpointFieldFact(
            "error", f"p_{ordinal}_error", "input", 1, False,
            SourceReference("rtl/renamed.sv", 1, 1), ("compiler",),
        ))
        fields.extend(extensions)
    provisional = ProcessorMemoryBinding(
        f"execution.route.{ordinal}", "processor_memory_master", protocol,
        tuple(fields), tuple(extensions),
    )
    adapter = resolve_processor_adapter(provisional)
    for policy in adapter.extension_policies:
        if policy.role in protocol_roles or any(field.role == policy.role for field in extensions):
            continue
        width = policy.width
        if width is None and policy.width_of is not None:
            width = next(field.width for field in fields if field.role == policy.width_of) // policy.width_divisor
        if width is None and policy.width_group == "user":
            width = 3
        assert width is not None
        field = EndpointFieldFact(
            policy.role, f"p_{ordinal}_{policy.role}", policy.direction, width,
            False, SourceReference("rtl/renamed.sv", 1, 1), ("compiler",),
        )
        extensions.append(field)
        fields.append(field)

    module = f"renamed_execution_source_{ordinal}"
    source_root = root / "source"
    source = source_root / "rtl" / "renamed.sv"
    source.parent.mkdir(parents=True)
    inputs = [field for field in fields if field.direction == "input"]
    outputs = [field for field in fields if field.direction == "output"]
    packed_width = sum(field.width for field in inputs)
    members = " ".join(
        f"logic{' [' + str(field.width - 1) + ':0]' if field.width > 1 else ''} {field.role};"
        for field in inputs
    )
    ports = ["input logic clock_pin", "input logic reset_pin"]
    ports.append(f"input struct packed {{{members}}} packed_response")
    ports.extend(
        f"output logic{' [' + str(field.width - 1) + ':0]' if field.width > 1 else ''} {field.port}"
        for field in outputs
    )
    sequential = outputs[0]
    assignments = " ".join(
        f"assign {field.port} = '0;" for field in outputs[1:]
    )
    source.write_text(
        f"module {module}({', '.join(ports)}); "
        f"always_ff @(posedge clock_pin or negedge reset_pin) if (!reset_pin) {sequential.port} <= '0; else {sequential.port} <= '0; "
        f"{assignments} endmodule\n",
        encoding="utf-8",
    )
    adapter_source = root / adapter.rtl_source
    adapter_source.parent.mkdir(parents=True, exist_ok=True)
    adapter_source.write_bytes((ROOT / adapter.rtl_source).read_bytes())

    endpoint_fields = []
    for field in fields:
        if field.direction == "input":
            endpoint_fields.append({
                "role": field.role,
                "physical": {"port": "packed_response", "member_path": [field.role]},
            })
        else:
            endpoint_fields.append({"role": field.role, "aliases": [field.port]})
    description = load_interface_description({
        "schema_version": "interface_description.v1",
        "source": {
            "root": "source", "revision": source_tree_hash(source_root, (source,)),
            "top_module": module, "files": ["rtl/renamed.sv"],
            "elaboration": {"frontend": "verilator-json"},
        },
        "endpoints": [
            {"endpoint_id": f"timing.clock.{ordinal}", "function": "clock", "module": module,
             "fields": [{"role": "clock", "aliases": ["clock_pin"]}]},
            {"endpoint_id": f"timing.reset.{ordinal}", "function": "reset", "module": module,
             "fields": [{"role": "reset", "aliases": ["reset_pin"]}]},
            {"endpoint_id": f"execution.route.{ordinal}", "function": "processor_memory_master",
             "module": module, "protocol": list(protocol), "fields": endpoint_fields},
        ],
    })
    component_types = ()
    component_catalog = None
    if with_ram:
        ram = root / "semantic_ram.sv"
        ram.write_text(
            "module semantic_storage(input logic clock, input logic reset, "
            "input logic req_valid, output logic req_ready, input logic write, "
            "input logic [31:0] addr, input logic [31:0] wdata, input logic [3:0] be, "
            "output logic rsp_valid, input logic rsp_ready, output logic [31:0] rdata, "
            "output logic error); logic pending; always_ff @(posedge clock or negedge reset) "
            "if (!reset) pending <= 0; else if (req_valid && req_ready) pending <= 1; "
            "else if (rsp_valid && rsp_ready) pending <= 0; assign req_ready=!pending; "
            "assign rsp_valid=pending; assign rdata=addr ^ wdata; assign error=0; endmodule\n",
            encoding="utf-8",
        )
        component_types = ("storage",)
        component_catalog = ComponentCatalog((PeripheralProfile(
            "storage", "semantic_storage", (("processor-memory-beat", "1"),),
            4, 0x1000, False, (), "implemented", ("semantic_ram.sv",), True, {},
        ),))
    return plan_generic_composition(
        GenericCompositionRequest(description, component_types), base_dir=root,
        component_catalog=component_catalog, protocol_catalog=catalog,
    ), module, adapter.rtl_module, packed_width


class ProcessorAutoWiringIntegrationTests(unittest.TestCase):
    def test_processor_backend_instantiates_semantic_memory_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, _, _, _ = _fixture(root, ("obi", "1"), 9, with_ram=True)
            output = root / "published"
            write_generic_composition(plan, output, base_dir=root)
            top = (output / "generic_composition_top.sv").read_text(encoding="utf-8")
            self.assertIn("semantic_storage ", top)
            self.assertIn(".req_valid(", top)
            self.assertIn(".rsp_ready(", top)
            self.assertNotIn("assign rsp_error_o = 1'b1;", top)

    def test_renamed_protocol_fixtures_publish_complete_wiring_and_compile(self) -> None:
        for ordinal, protocol in enumerate(PROTOCOLS):
            with self.subTest(protocol=protocol), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                plan, module, adapter_module, packed_width = _fixture(root, protocol, ordinal)
                output = root / "published"
                write_generic_composition(plan, output, base_dir=root)

                top = (output / "generic_composition_top.sv").read_text(encoding="utf-8")
                execution = json.loads((output / "processor_execution.v1.json").read_text(encoding="utf-8"))
                backend = json.loads((output / "processor_backend.v1.json").read_text(encoding="utf-8"))
                self.assertIn(f"{module} ", top)
                self.assertIn(f"{adapter_module} #(", top)
                self.assertEqual(1, top.count(".packed_response("))
                self.assertEqual(1, top.count(f"logic [{packed_width - 1}:0] source_"))
                for connection in execution["routes"][0]["field_connections"]:
                    physical = connection["physical"]
                    if "part_select" in physical:
                        signal = f"source_{canonical_id('generic-render-source-port', physical['container_port']):016x}"
                        self.assertEqual(1, top.count(signal + physical["part_select"]))
                self.assertEqual("direct", backend["routing"]["mode"])
                self.assertEqual(backend["backend_hash"], execution["backend_route"]["backend_hash"])
                self.assertTrue(execution["source_hashes"])
                self.assertIn("generic_composition_top.sv", {
                    record["path"] for record in execution["source_hashes"]
                })
                for record in execution["source_hashes"]:
                    path = (
                        output / record["path"]
                        if record["path"] == "generic_composition_top.sv"
                        else root / record["path"]
                    )
                    self.assertEqual("sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(), record["content_hash"])
                self.assertIn("backend_cancel_valid", top)
                self.assertIn("backend_cancel_ready", top)
                self.assertNotIn("cancel_ready_i()", top)

                commands = []
                if shutil.which("iverilog"):
                    commands.append(("iverilog", "-g2012", "-s", "generic_composition_top", "-f", "sources.f"))
                if shutil.which("verilator"):
                    commands.append(("verilator", "--lint-only", "--sv", "-Wno-fatal",
                                     "--top-module", "generic_composition_top", "-f", "sources.f"))
                for command in commands:
                    result = subprocess.run(
                        command, cwd=output, env={**os.environ, "JOBS": "1"},
                        capture_output=True, text=True, timeout=30, check=False,
                    )
                    self.assertEqual(0, result.returncode, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
