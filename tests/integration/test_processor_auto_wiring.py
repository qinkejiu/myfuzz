from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
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
    cross_file_types: bool = False, binary_collateral: bool = False,
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
    source_files = ["rtl/renamed.sv"]
    closure = [source]
    if cross_file_types:
        (source_root / "include").mkdir()
        header = source_root / "include/response.svh"
        package = source_root / "types.sv"
        member_declarations = members.split(";")
        header.write_text(";".join(member_declarations[:-2]) + ";\n", encoding="utf-8")
        package.write_text(
            "package response_types; typedef struct packed {\n"
            '`include "response.svh"\n'
            + member_declarations[-2] + ";\n} response_t; endpackage\n", encoding="utf-8",
        )
        source.write_text(source.read_text().replace(
            f"struct packed {{{members}}}", "response_types::response_t"
        ), encoding="utf-8")
        source_files.insert(0, "types.sv")
        closure.extend((header, package))
        if binary_collateral:
            collateral = source_root / "include/reference.bin"
            collateral.write_bytes(b"\x89\xff\x00reference")
            closure.append(collateral)
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
            "root": "source", "revision": source_tree_hash(source_root, closure),
            "top_module": module, "files": source_files,
            **({"include_roots": ["include"]} if cross_file_types else {}),
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
        "output logic completion_flag, output logic instruction_errors_ok, "
        "output logic [3:0] i_completion_count, output logic [3:0] d_completion_count, "
        "output logic [7:0] completion_order, output logic [15:0] data_history); "
        "logic i_active, d_active; assign i_address=0; "
        "assign d_address=4; assign d_write=0; assign d_write_data=0; assign d_bytes=4'hf; "
        "assign i_request=(i_completion_count<4)&&!i_active; "
        "assign d_request=(d_completion_count<4)&&!d_active; "
        "assign completion_flag=(i_completion_count==4)&&(d_completion_count==4); "
        "always_ff @(posedge clock_pin or negedge reset_pin) if (!reset_pin) begin "
        "i_active<=0; d_active<=0; i_completion_count<=0; d_completion_count<=0; "
        "completion_order<=0; data_history<=0; instruction_errors_ok<=1; end else begin "
        "if(i_request&&i_grant)i_active<=1; if(d_request&&d_grant)d_active<=1; "
        "if(i_response)begin i_active<=0; i_completion_count<=i_completion_count+1; "
        "completion_order<={completion_order[6:0],1'b0}; if(!i_fault)instruction_errors_ok<=0; end "
        "if(d_response)begin d_active<=0; d_completion_count<=d_completion_count+1; "
        "completion_order<={completion_order[6:0],1'b1}; "
        "data_history<={data_history[11:0],d_read_data[3:0]}; end end endmodule\n",
        encoding="utf-8",
    )
    adapter_source = root / "src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv"
    adapter_source.parent.mkdir(parents=True)
    adapter_source.write_bytes((ROOT / "src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv").read_bytes())
    arbiter_source = root / "src/myfuzz/protocols/rtl/processor_memory_arbiter.sv"
    arbiter_source.write_bytes((ROOT / "src/myfuzz/protocols/rtl/processor_memory_arbiter.sv").read_bytes())
    timeout_target = root / "semantic_timeout_target.sv"
    timeout_target.write_text(
        "module semantic_timeout_target(input logic clock, input logic reset, input logic req_valid, "
        "output logic req_ready, input logic write, input logic [31:0] addr, input logic [31:0] wdata, "
        "input logic [3:0] be, output logic rsp_valid, input logic rsp_ready, output logic [31:0] rdata, "
        "output logic error); logic pending; assign req_ready=!pending; assign rsp_valid=0; "
        "assign rdata=0; assign error=0; always_ff @(posedge clock or negedge reset) "
        "if(!reset)pending<=0;else if(req_valid&&req_ready)pending<=1; endmodule\n",
        encoding="utf-8",
    )
    stateful_target = root / "semantic_stateful_target.sv"
    stateful_target.write_text(
        "module semantic_stateful_target(input logic clock, input logic reset, input logic req_valid, "
        "output logic req_ready, input logic write, input logic [31:0] addr, input logic [31:0] wdata, "
        "input logic [3:0] be, output logic rsp_valid, input logic rsp_ready, output logic [31:0] rdata, "
        "output logic error); logic pending; logic [31:0] state; assign req_ready=!pending; "
        "assign rsp_valid=pending; assign rdata=state; assign error=0; "
        "always_ff @(posedge clock or negedge reset) if(!reset)begin pending<=0;state<=0;end "
        "else begin if(req_valid&&req_ready)pending<=1; if(rsp_valid&&rsp_ready)begin "
        "pending<=0;state<=state+1;end end endmodule\n",
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
         "fields": [
             {"role": "done", "aliases": ["completion_flag"]},
             {"role": "instruction_errors_ok", "aliases": ["instruction_errors_ok"]},
             {"role": "instruction_completions", "aliases": ["i_completion_count"]},
             {"role": "data_completions", "aliases": ["d_completion_count"]},
             {"role": "completion_order", "aliases": ["completion_order"]},
             {"role": "data_history", "aliases": ["data_history"]},
         ]},
    ]
    description = load_interface_description({
        "schema_version": "interface_description.v1",
        "source": {"root": "source", "revision": source_tree_hash(source_root, (source,)),
                   "top_module": "renamed_split", "files": ["rtl/renamed_split.sv"],
                   "elaboration": {"frontend": "verilator-json"}},
        "endpoints": endpoints,
    })
    profiles = (
        PeripheralProfile(
            "timeout_storage", "semantic_timeout_target", (("processor-memory-beat", "1"),),
            4, 4, False, (), "implemented", ("semantic_timeout_target.sv",), True, {},
            protocol_features={("processor-memory-beat", "1"): ("reset_flush",)},
        ),
        PeripheralProfile(
            "stateful_storage", "semantic_stateful_target", (("processor-memory-beat", "1"),),
            4, 4, False, (), "implemented", ("semantic_stateful_target.sv",), True, {},
            protocol_features={("processor-memory-beat", "1"): ("reset_flush",)},
        ),
    )
    plan = plan_generic_composition(
        GenericCompositionRequest(description, ("timeout_storage", "stateful_storage")), base_dir=root,
        component_catalog=ComponentCatalog(profiles), protocol_catalog=catalog,
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
    def test_binary_include_collateral_keeps_provenance_without_compiling_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, _, _, _ = _fixture(root, ("obi", "1"), 19,
                                    cross_file_types=True, binary_collateral=True)
            assert "source/include/reference.bin" not in plan.source_files
            write_generic_composition(plan, root / "out", base_dir=root)
            assert "reference.bin" not in (root / "out/sources.f").read_text()

    def test_header_change_during_lint_rejects_publication(self) -> None:
        from myfuzz.composition import protocol_composer

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, _, _, _ = _fixture(root, ("obi", "1"), 18, cross_file_types=True)
            header = root / "source/include/response.svh"
            validate = protocol_composer._validate_generic_top

            def changed_header(*args, **kwargs):
                validate(*args, **kwargs)
                header.write_text(header.read_text() + "// changed during lint\n")

            with patch.object(protocol_composer, "_validate_generic_top", side_effect=changed_header):
                with self.assertRaisesRegex(ValueError, "source.*changed"):
                    write_generic_composition(plan, root / "out", base_dir=root)
            assert not (root / "out").exists()

    def test_highest_address_region_renders_and_decodes_in_both_backend_modes(self) -> None:
        from myfuzz.composition.contract_transducer import compile_contract_transducer
        from myfuzz.isa import IsaContract

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = _split_fixture(root)
            regions = [dict(item) for item in plan.ir["address_regions"]]
            regions[-1].update(base=0xFFFFFFFC, size=4, end=1 << 32)
            backend = build_processor_backend(plan.processor_execution, regions)
            contract = compile_contract_transducer(
                isa=IsaContract(32, ("I",)), protocol=("processor-memory-beat", "1"),
                address_width=32, data_width=32,
                memory_domains={"instruction_memory_master": "main", "data_memory_master": "main"},
            )
            for constrained in (False, True):
                with self.subTest(constrained=constrained):
                    rendered = _render_processor_top(plan, backend, contract_transducer=contract if constrained else None)
                    if constrained:
                        assert "assign backend_mapped = 1'b1" in rendered
                        continue
                    # Compile and evaluate every generated mapping/target-select
                    # expression that decodes the region at the address ceiling.
                    expressions = re.findall(r"assign \w+ = ([^;]*32'hfffffffc[^;]*);", rendered)
                    assert len(expressions) == 4  # two routes, shared backend, target
                    bench = ["module tb; reg [31:0] addr;"]
                    for index, expr in enumerate(expressions):
                        expr = re.sub(r"\b(?:r_[0-9a-f]+_addr|backend_addr|backend_target_addr)\b", "addr", expr)
                        bench.append(f"wire mapped_{index} = {expr};")
                    bench.append("initial begin")
                    for address, expected in ((0xFFFFFFFB, 0), (0xFFFFFFFC, 1), (0xFFFFFFFF, 1)):
                        bench.append(f"addr=32'h{address:x}; #1;")
                        for index in range(len(expressions)):
                            bench.append(f'if (mapped_{index} !== 1\'b{expected}) $fatal(1, "bad ceiling decode");')
                    bench.append('$display("CEILING_PASS"); $finish; end endmodule')
                    (root / "sources.f").write_text("")
                    assert "CEILING_PASS" in _run_iverilog(root, "\n".join(bench))

    def test_packed_package_and_header_members_keep_complete_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, _, _, _ = _fixture(root, ("obi", "1"), 17, cross_file_types=True)
            fields = [field for endpoint in plan.capabilities for field in endpoint.fields]
            assert {"types.sv", "include/response.svh"} <= {
                field.source.file for field in fields if field.member_path
            }
            assert "source/response.svh" not in plan.source_files
            assert plan.source_files[:2] == ("source/types.sv", "source/rtl/renamed.sv")
            ids = set(plan.ir["source_file_ids"])
            for endpoint in plan.ir["capabilities"]:
                for field in endpoint["fields"]:
                    assert field["source"]["file_id"] in ids
            write_generic_composition(plan, root / "out", base_dir=root)
            source_list = (root / "out/sources.f").read_text()
            assert "response.svh" not in source_list
            assert source_list.index("types.sv") < source_list.index("rtl/renamed.sv")

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

    def test_synchronous_cpu_reset_matches_fixed_adapter_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, _, _, _ = _fixture(root, ("obi", "1"), 4, synchronous_reset=True)
            self.assertEqual(
                {"polarity": "active_low", "synchrony": "synchronous"},
                plan.processor_execution.routes[0].reset_contract,
            )
            output = root / "published"
            write_generic_composition(plan, output, base_dir=root)
            top = (output / "generic_composition_top.sv").read_text(encoding="utf-8")
            self.assertNotIn("processor_adapter_reset_sync_q", top)

    def test_asynchronous_cpu_reset_derives_synchronous_fixed_adapter_reset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, _, _, _ = _fixture(root, ("obi", "1"), 5)
            output = root / "published"
            write_generic_composition(plan, output, base_dir=root)
            top = (output / "generic_composition_top.sv").read_text(encoding="utf-8")
            self.assertEqual(
                {"polarity": "active_low", "synchrony": "synchronous"},
                plan.processor_execution.routes[0].reset_contract,
            )
            self.assertIn("logic [1:0] processor_adapter_reset_sync_q;", top)
            self.assertIn(".rst_ni(processor_adapter_reset_n)", top)

    def test_tampered_fixed_adapter_reset_fact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, _, _, _ = _fixture(root, ("obi", "1"), 6)
            route = replace(
                plan.processor_execution.routes[0],
                reset_contract={"polarity": "active_low", "synchrony": "asynchronous"},
            )
            execution = replace(plan.processor_execution, routes=(route,))
            malformed = replace(plan, processor_execution=execution)
            backend = build_processor_backend(execution, plan.ir["address_regions"])
            with self.assertRaisesRegex(ValueError, "adapter reset contract"):
                _render_processor_top(malformed, backend)

    def test_split_multitarget_contention_is_fair_and_flush_is_target_local(self) -> None:
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
            errors_ok = f"p_{canonical_id('generic-top-port', 'status:instruction_errors_ok:instruction_errors_ok'):016x}"
            i_count = f"p_{canonical_id('generic-top-port', 'status:instruction_completions:i_completion_count'):016x}"
            d_count = f"p_{canonical_id('generic-top-port', 'status:data_completions:d_completion_count'):016x}"
            order = f"p_{canonical_id('generic-top-port', 'status:completion_order:completion_order'):016x}"
            data_history = f"p_{canonical_id('generic-top-port', 'status:data_history:data_history'):016x}"
            stateful_tag = f"c_{canonical_id('processor-backend-component', 'stateful_storage0'):016x}"
            stdout = _run_iverilog(output, f"""
module tb; logic clk=0,rst=0; wire done,errors_ok; wire [3:0] i_count,d_count;
wire [7:0] order; wire [15:0] data_history;
integer cancel_events=0,flush_events=0,unselected_reset_cycles=0;
logic armed=0,cancel_q=0;
always #1 clk=~clk;
generic_composition_top dut(.{clk}(clk),.{rst}(rst),.{done}(done),.{errors_ok}(errors_ok),
  .{i_count}(i_count),.{d_count}(d_count),.{order}(order),.{data_history}(data_history));
always @(posedge clk) begin
  cancel_q <= dut.backend_cancel_valid;
  if(armed && dut.backend_cancel_valid && !cancel_q) cancel_events <= cancel_events+1;
  if(armed && dut.backend_target_flush) flush_events <= flush_events+1;
  if(armed && !dut.{stateful_tag}_flush_reset) unselected_reset_cycles <= unselected_reset_cycles+1;
end
initial begin repeat(2) @(negedge clk); rst=1; wait(!dut.backend_cancel_valid); armed=1;
  wait(done); repeat(2) @(posedge clk);
  if(!errors_ok) $fatal(1,"instruction timeout did not return errors");
  if(unselected_reset_cycles!=0) $fatal(1,"unselected reset cycles %0d",unselected_reset_cycles);
  if(data_history!=16'h0123) $fatal(1,"unselected target history %h",data_history);
  if(i_count!=4 || d_count!=4) $fatal(1,"missing completions");
  if(order!=8'b10101010) $fatal(1,"unfair completion order %b",order);
  if(cancel_events!=4) $fatal(1,"timeout cancellation count %0d",cancel_events);
  if(flush_events!=4) $fatal(1,"target flush count %0d",flush_events);
  $display("PASS split fairness cancel=%0d flush=%0d",cancel_events,flush_events); $finish; end
initial begin repeat(400) @(posedge clk); $fatal(1,"timeout"); end endmodule
""")
            self.assertIn("PASS split fairness cancel=4 flush=4", stdout)

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
                self.assertEqual(
                    {"polarity": "active_low", "synchrony": "synchronous"},
                    execution["routes"][0]["reset_contract"],
                )
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
