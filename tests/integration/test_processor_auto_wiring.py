from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from myfuzz.composition import (
    GenericCompositionRequest,
    load_interface_description,
    plan_generic_composition,
    source_tree_hash,
    write_generic_composition,
)
from myfuzz.composition.processor_backend import build_processor_backend
from myfuzz.composition.protocol_composer import (
    _render_processor_backend_module,
    _render_processor_top,
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


def _fixture(
    root: Path, protocol: tuple[str, str], ordinal: int, *, with_ram: bool = False,
    synchronous_reset: bool = False, flush_contract: bool = True,
):
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
        f"always_ff @(posedge clock_pin{' ' if synchronous_reset else ' or negedge reset_pin'}) if (!reset_pin) {sequential.port} <= '0; else {sequential.port} <= '0; "
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
             "module": module, "protocol": list(protocol), "clock": "clock_pin",
             "reset": "reset_pin", "fields": endpoint_fields},
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
            protocol_features={
                ("processor-memory-beat", "1"): ("reset_flush",)
            } if flush_contract else {},
        ),))
    return plan_generic_composition(
        GenericCompositionRequest(description, component_types), base_dir=root,
        component_catalog=component_catalog, protocol_catalog=catalog,
    ), module, adapter.rtl_module, packed_width


def _split_fixture(root: Path):
    catalog = load_protocol_catalog(ROOT / "src/myfuzz/protocols/plugins")
    source_root = root / "source"
    source = source_root / "rtl" / "renamed_split.sv"
    source.parent.mkdir(parents=True)
    source.write_text(
        "module renamed_split(input logic clock_pin, input logic reset_pin, "
        "output logic i_request, input logic i_grant, output logic [31:0] i_address, "
        "input logic i_response, input logic [31:0] i_read_data, input logic i_fault, "
        "output logic d_request, input logic d_grant, output logic [31:0] d_address, "
        "output logic d_write, output logic [31:0] d_write_data, output logic [3:0] d_bytes, "
        "input logic d_response, input logic [31:0] d_read_data, input logic d_fault, "
        "output logic completion_flag); "
        "typedef enum logic [2:0] {START_I, WAIT_I, START_D, WAIT_D, FINISHED} state_t; "
        "state_t state; assign i_address=0; "
        "assign d_address=4; assign d_write=0; "
        "assign d_write_data=0; assign d_bytes=4'hf; assign completion_flag=state==FINISHED; "
        "always_ff @(posedge clock_pin or negedge reset_pin) if (!reset_pin) begin "
        "state<=START_I; i_request<=0; d_request<=0; end else begin "
        "i_request<=state==START_I; d_request<=state==START_D; "
        "case(state) START_I:if(i_request&&i_grant)state<=WAIT_I; WAIT_I:if(i_response)state<=START_D; "
        "START_D:if(d_request&&d_grant)state<=WAIT_D; WAIT_D:if(d_response)state<=FINISHED; default:state<=state; endcase end endmodule\n",
        encoding="utf-8",
    )
    adapter_source = root / "src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv"
    adapter_source.parent.mkdir(parents=True)
    adapter_source.write_bytes((ROOT / "src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv").read_bytes())
    arbiter_source = root / "src/myfuzz/protocols/rtl/processor_memory_arbiter.sv"
    arbiter_source.write_bytes((ROOT / "src/myfuzz/protocols/rtl/processor_memory_arbiter.sv").read_bytes())
    target = root / "semantic_split_target.sv"
    target.write_text(
        "module semantic_split_target(input logic clock, input logic reset, input logic req_valid, "
        "output logic req_ready, input logic write, input logic [31:0] addr, input logic [31:0] wdata, "
        "input logic [3:0] be, output logic rsp_valid, input logic rsp_ready, output logic [31:0] rdata, "
        "output logic error); logic pending; logic [31:0] saved; assign req_ready=!pending; "
        "assign rsp_valid=pending && saved==4; assign rdata=32'h12345678; assign error=0; "
        "always_ff @(posedge clock or negedge reset) if(!reset) begin pending<=0; saved<=0; end "
        "else if(req_valid&&req_ready) begin pending<=1; saved<=addr; end "
        "else if(rsp_valid&&rsp_ready) pending<=0; endmodule\n",
        encoding="utf-8",
    )
    endpoints = [
        {"endpoint_id": "timing.clock", "function": "clock", "module": "renamed_split",
         "fields": [{"role": "clock", "aliases": ["clock_pin"]}]},
        {"endpoint_id": "timing.reset", "function": "reset", "module": "renamed_split",
         "fields": [{"role": "reset", "aliases": ["reset_pin"]}]},
        {"endpoint_id": "route.instruction", "function": "instruction_memory_master",
         "module": "renamed_split", "protocol": ["obi", "1"],
         "clock": "clock_pin", "reset": "reset_pin", "fields": [
             {"role": role, "aliases": [port]} for role, port in (
                 ("req", "i_request"), ("gnt", "i_grant"), ("addr", "i_address"),
                 ("rvalid", "i_response"), ("rdata", "i_read_data"), ("error", "i_fault"))]},
        {"endpoint_id": "route.data", "function": "data_memory_master",
         "module": "renamed_split", "protocol": ["obi", "1"],
         "clock": "clock_pin", "reset": "reset_pin", "fields": [
             {"role": role, "aliases": [port]} for role, port in (
                 ("req", "d_request"), ("gnt", "d_grant"), ("addr", "d_address"),
                 ("we", "d_write"), ("wdata", "d_write_data"), ("be", "d_bytes"),
                 ("rvalid", "d_response"), ("rdata", "d_read_data"), ("error", "d_fault"))]},
        {"endpoint_id": "status", "function": "observation", "module": "renamed_split",
         "fields": [{"role": "done", "aliases": ["completion_flag"]}]},
    ]
    description = load_interface_description({
        "schema_version": "interface_description.v1",
        "source": {"root": "source", "revision": source_tree_hash(source_root, (source,)),
                   "top_module": "renamed_split", "files": ["rtl/renamed_split.sv"],
                   "elaboration": {"frontend": "verilator-json"}},
        "endpoints": endpoints,
    })
    profile = PeripheralProfile(
        "split_storage", "semantic_split_target", (("processor-memory-beat", "1"),),
        4, 0x1000, False, (), "implemented", ("semantic_split_target.sv",), True, {},
        protocol_features={("processor-memory-beat", "1"): ("reset_flush",)},
    )
    plan = plan_generic_composition(
        GenericCompositionRequest(description, ("split_storage",)), base_dir=root,
        component_catalog=ComponentCatalog((profile,)), protocol_catalog=catalog,
    )
    return plan


def _run_iverilog(output: Path, testbench: str) -> str:
    compiler = shutil.which("iverilog")
    runtime = shutil.which("vvp")
    if compiler is None or runtime is None:
        raise unittest.SkipTest("Icarus Verilog and vvp are not installed")
    (output / "tb.sv").write_text(testbench, encoding="utf-8")
    compile_result = subprocess.run(
        (compiler, "-g2012", "-s", "tb", "-o", "simulation", "-f", "sources.f", "tb.sv"),
        cwd=output, capture_output=True, text=True, timeout=30, check=False,
    )
    if compile_result.returncode:
        raise AssertionError(compile_result.stdout + compile_result.stderr)
    result = subprocess.run(
        (runtime, "simulation"), cwd=output, capture_output=True, text=True,
        timeout=30, check=False,
    )
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    return result.stdout


class ProcessorAutoWiringIntegrationTests(unittest.TestCase):
    def test_direct_backend_flushes_an_accepted_nonresponding_target_before_reuse(self) -> None:
        module = _render_processor_backend_module(32, 32, 4, "asynchronous")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            (output / "backend.sv").write_text(module, encoding="utf-8")
            (output / "sources.f").write_text("backend.sv\n", encoding="utf-8")
            stdout = _run_iverilog(output, """
module tb;
  logic clk=0, rst_n=0, req_valid=0, req_ready, rsp_valid, rsp_ready=1;
  logic target_ready=1, target_rsp=0, target_rsp_ready, target_flush;
  logic [31:0] addr=0, target_addr, rdata; logic error;
  always #1 clk=~clk;
  myfuzz_processor_memory_backend dut(
    .clk_i(clk),.rst_ni(rst_n),.req_valid_i(req_valid),.req_ready_o(req_ready),
    .req_write_i(1'b0),.req_addr_i(addr),.req_wdata_i('0),.req_be_i('1),.req_mapped_i(1'b1),
    .rsp_valid_o(rsp_valid),.rsp_ready_i(rsp_ready),.rsp_rdata_o(rdata),.rsp_error_o(error),
    .cancel_valid_i(1'b0),.cancel_ready_o(),.target_flush_o(target_flush),
    .target_req_valid_o(),.target_req_ready_i(target_ready),.target_write_o(),
    .target_addr_o(target_addr),.target_wdata_o(),.target_be_o(),.target_rsp_valid_i(target_rsp),
    .target_rsp_ready_o(target_rsp_ready),.target_rdata_i(32'h55),.target_error_i(1'b0));
  initial begin
    repeat(2) @(negedge clk); rst_n=1; req_valid=1; @(negedge clk); req_valid=0;
    wait(rsp_valid && error); @(negedge clk); wait(target_flush); @(negedge clk);
    addr=4; req_valid=1; wait(req_ready); @(posedge clk); @(negedge clk);
    req_valid=0; target_rsp=1;
    wait(rsp_valid && !error); $display("PASS direct recovery"); $finish;
  end
  initial begin repeat(80) @(posedge clk); $fatal(1,"timeout"); end
endmodule
""")
            self.assertIn("PASS direct recovery", stdout)

    def test_direct_target_without_explicit_flush_contract_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(
            ValueError, "recovery-contract"
        ):
            _fixture(Path(temporary), ("obi", "1"), 3, with_ram=True, flush_contract=False)

    def test_synchronous_cpu_reset_is_rejected_by_asynchronous_fixed_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(
            ValueError, "adapter-reset-synchrony"
        ):
            _fixture(Path(temporary), ("obi", "1"), 4, synchronous_reset=True)

    def test_split_renamed_fixture_compiles_and_recovers_after_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = _split_fixture(root)
            output = root / "published"
            write_generic_composition(plan, output, base_dir=root)
            top = (output / "generic_composition_top.sv").read_text(encoding="utf-8")
            self.assertEqual(2, top.count("obi_processor_memory_adapter #("))
            self.assertIn("processor_memory_arbiter #(", top)
            self.assertIn(".cancel_valid_o(backend_cancel_valid)", top)
            commands = []
            if shutil.which("iverilog"):
                commands.append(("iverilog", "-g2012", "-s", "generic_composition_top", "-f", "sources.f"))
            if shutil.which("verilator"):
                commands.append(("verilator", "--lint-only", "--sv", "-Wno-fatal",
                                 "--top-module", "generic_composition_top", "-f", "sources.f"))
            if not commands:
                raise unittest.SkipTest("Icarus Verilog and Verilator are not installed")
            for command in commands:
                result = subprocess.run(command, cwd=output, capture_output=True, text=True, timeout=30, check=False)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            clk = f"p_{canonical_id('generic-top-port', 'timing.clock:clock:clock_pin'):016x}"
            rst = f"p_{canonical_id('generic-top-port', 'timing.reset:reset:reset_pin'):016x}"
            done = f"p_{canonical_id('generic-top-port', 'status:done:completion_flag'):016x}"
            stdout = _run_iverilog(output, f"""
module tb; logic clk=0,rst=0; wire done; always #1 clk=~clk;
generic_composition_top dut(.{clk}(clk),.{rst}(rst),.{done}(done));
initial begin repeat(2) @(posedge clk); rst=1; wait(done); $display("PASS split recovery"); $finish; end
initial begin repeat(160) @(posedge clk); $fatal(1,"timeout"); end endmodule
""")
            self.assertIn("PASS split recovery", stdout)

    def test_split_routing_evidence_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = _split_fixture(root)
            backend = build_processor_backend(plan.processor_execution, plan.ir["address_regions"])
            malformed = replace(backend, routing={**backend.routing, "rtl_module": "wrong_arbiter"})
            with self.assertRaisesRegex(ValueError, "routing evidence"):
                _render_processor_top(plan, malformed)

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
                if not commands:
                    raise unittest.SkipTest("Icarus Verilog and Verilator are not installed")
                for command in commands:
                    result = subprocess.run(
                        command, cwd=output, env={**os.environ, "JOBS": "1"},
                        capture_output=True, text=True, timeout=30, check=False,
                    )
                    self.assertEqual(0, result.returncode, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
