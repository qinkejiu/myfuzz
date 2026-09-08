"""Task 13 contracts for bounded, fact-driven real RISC-V execution."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from myfuzz.components.catalog import ComponentCatalog
from myfuzz.components.model import PeripheralProfile
from myfuzz.composition import (
    GenericCompositionRequest,
    build_processor_backend,
    load_interface_description,
    plan_generic_composition,
    write_generic_composition,
)
from myfuzz.composition.ids import canonical_id
from myfuzz.composition.source_crawler import SourceCrawler
from myfuzz.protocols.catalog import load_protocol_catalog
from myfuzz.integration.riscv_execution import (
    ExecutionEvent,
    RiscvExecutionError,
    RiscvExecutionFacts,
    RiscvExecutionProvenance,
    build_minimal_boot_image,
    build_protocol_blocker,
    build_run_manifest,
    verify_execution_events,
    verify_repository_pins,
)


class RiscvExecutionTests(unittest.TestCase):
    @staticmethod
    def top_port(endpoint: str, role: str, port: str) -> str:
        return f"p_{canonical_id('generic-top-port', f'{endpoint}:{role}:{port}'):016x}"

    @staticmethod
    def ibex_plan(root: Path):
        description = load_interface_description(
            root / "configs/cpus/ibex/official_core_interface_description.json"
        )
        memory = PeripheralProfile(
            "boot-memory", "riscv_boot_memory_32", (("processor-memory-beat", "1"),),
            4, 4096, False, (), "implemented",
            ("src/myfuzz/integration/rtl/riscv_boot_memory.sv",), True, {},
            protocol_features={("processor-memory-beat", "1"): ("reset_flush",)},
        )
        return plan_generic_composition(
            GenericCompositionRequest(description, ("boot-memory",)),
            base_dir=root,
            component_catalog=ComponentCatalog((memory,)),
            protocol_catalog=load_protocol_catalog(root / "src/myfuzz/protocols/plugins"),
        )

    @staticmethod
    def cva6_plan(root: Path):
        description = load_interface_description(
            root / "configs/cpus/cva6/official_core_interface_description.json"
        )
        memory = PeripheralProfile(
            "boot-memory", "riscv_boot_memory_64", (("processor-memory-beat", "1"),),
            8, 4096, False, (), "implemented",
            ("src/myfuzz/integration/rtl/riscv_boot_memory.sv",), True, {},
            protocol_features={("processor-memory-beat", "1"): ("reset_flush",)},
        )
        return plan_generic_composition(
            GenericCompositionRequest(description, ("boot-memory",)),
            base_dir=root,
            component_catalog=ComponentCatalog((memory,)),
            protocol_catalog=load_protocol_catalog(root / "src/myfuzz/protocols/plugins"),
        )

    def facts(self, **changes: object) -> RiscvExecutionFacts:
        values: dict[str, object] = {
            "isa": "rv32imc",
            "xlen": 32,
            "reset_vector": 0x80,
            "pass_address": 0x400,
            "pass_value": 0x600DCAFE,
            "protocol": ("obi", "1"),
            "max_cycles": 400,
        }
        values.update(changes)
        if "provenance" not in changes:
            values["provenance"] = RiscvExecutionProvenance(
                source_identity="fixture-source",
                source_hash="sha256:" + "1" * 64,
                profile_identity="fixture-profile",
                profile_hash="sha256:" + "2" * 64,
                interface_identity="fixture-interface",
                interface_hash="sha256:" + "3" * 64,
                isa=values["isa"],
                xlen=values["xlen"],
                reset_vector=values["reset_vector"],
            )
        return RiscvExecutionFacts(**values)

    def test_builds_minimal_boot_from_isa_xlen_and_reset_facts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = build_minimal_boot_image(self.facts(), Path(temporary))

            self.assertEqual("rv32imc", result.isa)
            self.assertEqual(32, result.xlen)
            self.assertEqual(0x80, result.reset_vector)
            self.assertEqual(0x80, result.load_base)
            self.assertGreater(result.binary_size, 0)
            self.assertTrue(result.elf_hash.startswith("sha256:"))
            self.assertTrue(result.binary_hash.startswith("sha256:"))
            self.assertNotEqual(result.binary_hash, result.memory_hex_hash)
            self.assertEqual("@00000080", result.memory_hex_path.read_text().splitlines()[0])
            self.assertTrue(result.elf_path.is_file())
            self.assertTrue(result.binary_path.is_file())
            self.assertTrue(result.memory_hex_path.is_file())

    def test_rejects_incomplete_execution_and_records_complete_manifest(self) -> None:
        facts = self.facts()
        with tempfile.TemporaryDirectory() as temporary:
            boot = build_minimal_boot_image(facts, Path(temporary))
            complete = ExecutionEvent(
                reset_released=True,
                successful_fetches=3,
                progress_events=2,
                backend_completions=3,
                pass_observed=True,
                cycles=31,
                exit_reason="pass",
                first_fetch_address=facts.reset_vector,
                first_fetch_data=boot.first_fetch_data,
                illegal_or_trap_records=0,
            )
            verify_execution_events(complete, facts, boot)
            for field in (
                "reset_released", "successful_fetches", "progress_events",
                "backend_completions", "pass_observed",
            ):
                broken = complete.__dict__ | {field: False if isinstance(getattr(complete, field), bool) else 0}
                with self.subTest(field=field), self.assertRaisesRegex(RiscvExecutionError, field):
                    verify_execution_events(ExecutionEvent(**broken), facts, boot)

            for field, value, error in (
                ("first_fetch_address", facts.reset_vector + 4, "first_fetch_address"),
                ("first_fetch_data", boot.first_fetch_data ^ 1, "first_fetch_data"),
                ("illegal_or_trap_records", 1, "illegal_or_trap_records"),
            ):
                broken = complete.__dict__ | {field: value}
                with self.subTest(field=field), self.assertRaisesRegex(RiscvExecutionError, error):
                    verify_execution_events(ExecutionEvent(**broken), facts, boot)

            manifest = build_run_manifest(
                facts=facts,
                event=complete,
                boot_image=boot,
                revisions={"root": "git:" + "1" * 40},
                nested_pins={"dep": "git:" + "2" * 40},
                tools={"compiler": "clang 18", "simulator": "verilator 5"},
                elaboration={"frontend": "verilator-json", "warning_policy": "fatal"},
                hashes={
                    "composition": "sha256:" + "4" * 64,
                    "layout": "sha256:" + "5" * 64,
                    "source": facts.provenance.source_hash,
                    "binary": boot.binary_hash,
                    "config": "sha256:" + "6" * 64,
                    "profile": facts.provenance.profile_hash,
                    "interface": facts.provenance.interface_hash,
                },
                peak_rss_bytes=1024,
                warning_summary={"warning_count": 0, "error_count": 0, "classes": {}},
                log_summary={"compile": "pass", "simulate": "pass"},
            )
            self.assertEqual("riscv_execution.v1", manifest["schema_version"])
            self.assertEqual(
                {"load_base": 0x80, "reset_vector": 0x80,
                 "address_encoding": "verilog-readmemh-address-directive",
                 "first_fetch_address": 0x80,
                 "first_fetch_data": boot.first_fetch_data},
                manifest["image"],
            )
            self.assertEqual(
                {"source_identity": "fixture-source", "profile_identity": "fixture-profile",
                 "interface_identity": "fixture-interface"},
                {f"{key}_identity": manifest["provenance"][key]["identity"]
                 for key in ("source", "profile", "interface")},
            )
            self.assertTrue(manifest["manifest_hash"].startswith("sha256:"))
            self.assertEqual(31, manifest["metrics"]["cycles"])

    def test_rejects_provenance_mismatch_in_build_and_manifest(self) -> None:
        facts = self.facts()
        with self.assertRaisesRegex(RiscvExecutionError, "provenance:isa-mismatch"):
            RiscvExecutionFacts(
                isa=facts.isa, xlen=facts.xlen, reset_vector=facts.reset_vector,
                pass_address=facts.pass_address, pass_value=facts.pass_value,
                protocol=facts.protocol, max_cycles=facts.max_cycles,
                provenance=RiscvExecutionProvenance(
                    source_identity="fixture-source", source_hash="sha256:" + "1" * 64,
                    profile_identity="fixture-profile", profile_hash="sha256:" + "2" * 64,
                    interface_identity="fixture-interface", interface_hash="sha256:" + "3" * 64,
                    isa="rv64imafdc", xlen=64, reset_vector=facts.reset_vector,
                ),
            )

        with tempfile.TemporaryDirectory() as temporary:
            boot = build_minimal_boot_image(facts, Path(temporary))
            event = ExecutionEvent(
                reset_released=True, successful_fetches=1, progress_events=1,
                backend_completions=1, pass_observed=True, cycles=1,
                exit_reason="pass", first_fetch_address=facts.reset_vector,
                first_fetch_data=boot.first_fetch_data, illegal_or_trap_records=0,
            )
            hashes = {
                "composition": "sha256:" + "4" * 64,
                "layout": "sha256:" + "5" * 64,
                "source": facts.provenance.source_hash,
                "binary": boot.binary_hash,
                "config": "sha256:" + "6" * 64,
                "profile": "sha256:" + "9" * 64,
                "interface": facts.provenance.interface_hash,
            }
            with self.assertRaisesRegex(RiscvExecutionError, "profile-hash:mismatch"):
                build_run_manifest(
                    facts=facts, event=event, boot_image=boot,
                    revisions={"root": "git:" + "1" * 40}, nested_pins={},
                    tools={"compiler": "clang 18"}, elaboration={}, hashes=hashes,
                    peak_rss_bytes=1024, warning_summary={}, log_summary={},
                )

    def test_verifies_exact_repository_pins_and_reports_generic_protocol_gap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            metadata = root / "pins.json"
            metadata.write_text(json.dumps({"root": "git:" + "a" * 40}), encoding="utf-8")
            self.assertEqual(
                {"root": "git:" + "a" * 40},
                verify_repository_pins(metadata, {"root": "git:" + "a" * 40}),
            )
            with self.assertRaisesRegex(RiscvExecutionError, "pin-mismatch"):
                verify_repository_pins(metadata, {"root": "git:" + "b" * 40})

        blocker = build_protocol_blocker(
            protocol=("tilelink", "1"),
            available_protocols=(("obi", "1"), ("axi4", "1"), ("tl-ul", "1")),
            missing_dependencies=("generated-rtl", "source-closure"),
        )
        self.assertEqual("BLOCKED", blocker["status"])
        self.assertEqual("protocol-capability:tilelink@1", blocker["reason"])
        self.assertEqual("generic-protocol-work-item", blocker["work_item"]["kind"])
        self.assertNotIn("boom", json.dumps(blocker).lower())

    def test_boom_blocker_manifest_is_source_backed_and_generic(self) -> None:
        root = Path(__file__).resolve().parents[2]
        document = json.loads(
            (root / "third_party/docs/task-13/boom-blocker/manifest.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("task13_boom_blocker.v1", document["schema_version"])
        self.assertEqual("BLOCKED", document["status"])
        self.assertEqual(
            "git:58ef2720eae13be26b3008c02b5a74ce29c61c44",
            document["revisions"]["boom"]["revision"],
        )
        self.assertEqual(
            "git:4180463d52bc0a6b4c004530601ccdabebf0ab7d",
            document["revisions"]["chipyard"]["revision"],
        )
        self.assertGreaterEqual(len(document["source_facts"]), 3)
        for fact in document["source_facts"]:
            self.assertTrue(fact["path"])
            self.assertGreater(fact["line"], 0)
            self.assertTrue(fact["observation"])
            self.assertRegex(fact["sha256"], r"^[0-9a-f]{64}$")
        self.assertFalse(document["execution"]["attempted"])
        self.assertFalse(document["tool_availability"]["java"]["available"])
        self.assertFalse(document["tool_availability"]["sbt"]["available"])
        self.assertEqual("generic-protocol-work-item", document["work_item"]["kind"])
        self.assertEqual(["tilelink", "1"], document["work_item"]["protocol"])
        self.assertIn("B/C/E", " ".join(document["work_item"]["requirements"]))

    @unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"), "Icarus is required")
    def test_boot_memory_executes_reads_writes_and_completions(self) -> None:
        root = Path(__file__).resolve().parents[2]
        rtl = root / "src/myfuzz/integration/rtl/riscv_boot_memory.sv"
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            image = output / "image.hex"
            image.write_text("13\n57\n9b\ndf\n00\n00\n00\n00\n", encoding="ascii")
            bench = output / "tb.sv"
            bench.write_text(
                """module tb;
logic clk=0, reset=0, flush=0, valid=0, write=0, ready, rsp_valid, rsp_ready=1, error;
logic [31:0] addr=0, wdata=0, rdata; logic [3:0] be=0;
always #1 clk=~clk;
riscv_boot_memory_32 dut(.clock(clk),.reset(reset),.flush(flush),
 .req_valid(valid),.req_ready(ready),.write(write),.addr(addr),
 .wdata(wdata),.be(be),.rsp_valid(rsp_valid),.rsp_ready(rsp_ready),
 .rdata(rdata),.error(error));
task request(input wr, input [31:0] a, input [31:0] d, input [3:0] mask);
begin @(negedge clk); valid=1; write=wr; addr=a; wdata=d; be=mask;
  while(!ready) @(negedge clk); @(negedge clk); valid=0;
  while(!rsp_valid) @(negedge clk); if(error) $fatal(1,"memory error");
end endtask
initial begin repeat(2) @(negedge clk); reset=1;
 request(0,0,0,0); if(rdata!==32'hdf9b5713) $fatal(1,"boot read %h",rdata);
 request(1,4,32'h600dcafe,4'hf); request(0,4,0,0);
 if(rdata!==32'h600dcafe) $fatal(1,"write readback %h",rdata);
 $display("PASS boot memory"); $finish; end
initial begin repeat(100) @(posedge clk); $fatal(1,"timeout"); end
endmodule
""",
                encoding="ascii",
            )
            compile_result = subprocess.run(
                ("iverilog", "-g2012", "-s", "tb", "-o", "sim", str(rtl), str(bench)),
                cwd=output, capture_output=True, text=True, timeout=20, check=False,
            )
            self.assertEqual(0, compile_result.returncode, compile_result.stdout + compile_result.stderr)
            result = subprocess.run(
                ("vvp", "sim", f"+riscv_boot_image={image}"), cwd=output,
                capture_output=True, text=True, timeout=20, check=False,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn("PASS boot memory", result.stdout)

    @unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"), "Icarus is required")
    def test_64_bit_boot_memory_preserves_byte_lanes(self) -> None:
        root = Path(__file__).resolve().parents[2]
        rtl = root / "src/myfuzz/integration/rtl/riscv_boot_memory.sv"
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            image = output / "image.hex"
            image.write_text("08\n07\n06\n05\n04\n03\n02\n01\n", encoding="ascii")
            bench = output / "tb64.sv"
            bench.write_text(
                """module tb;
logic clk=0, reset=0, valid=0, ready, rsp_valid, rsp_ready=1, error;
logic [63:0] wdata=0, rdata; logic [63:0] addr=0; logic [7:0] be=0; logic write=0;
always #1 clk=~clk;
riscv_boot_memory_64 dut(.clock(clk),.reset(reset),.flush(1'b0),.req_valid(valid),
 .req_ready(ready),.write(write),.addr(addr),.wdata(wdata),.be(be),
 .rsp_valid(rsp_valid),.rsp_ready(rsp_ready),.rdata(rdata),.error(error));
initial begin repeat(2) @(negedge clk); reset=1; @(negedge clk); valid=1;
 while(!ready) @(negedge clk); @(negedge clk); valid=0;
 while(!rsp_valid) @(negedge clk);
 if(error || rdata!==64'h0102030405060708) $fatal(1,"read %h",rdata);
 $display("PASS boot memory 64"); $finish; end
initial begin repeat(50) @(posedge clk); $fatal(1,"timeout"); end
endmodule
""",
                encoding="ascii",
            )
            compiled = subprocess.run(
                ("iverilog", "-g2012", "-s", "tb", "-o", "sim", str(rtl), str(bench)),
                cwd=output, capture_output=True, text=True, timeout=20, check=False,
            )
            self.assertEqual(0, compiled.returncode, compiled.stdout + compiled.stderr)
            result = subprocess.run(
                ("vvp", "sim", f"+riscv_boot_image={image}"), cwd=output,
                capture_output=True, text=True, timeout=20, check=False,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn("PASS boot memory 64", result.stdout)

    def test_official_split_obi_processor_plans_generated_arbiter_backend(self) -> None:
        root = Path(__file__).resolve().parents[2]
        plan = self.ibex_plan(root)
        assert plan.processor_execution is not None
        self.assertEqual(2, len(plan.processor_execution.routes))
        self.assertEqual(
            {("obi", "1")},
            {route.source_protocol for route in plan.processor_execution.routes},
        )
        backend = build_processor_backend(
            plan.processor_execution, plan.ir["address_regions"]
        )
        self.assertEqual("round_robin", backend.routing["mode"])
        self.assertIn(
            "src/myfuzz/protocols/rtl/processor_memory_arbiter.sv", backend.rtl_sources
        )

    @unittest.skipUnless(shutil.which("verilator"), "Verilator is required")
    def test_ibex_executes_boot_through_generated_split_obi_path(self) -> None:
        root = Path(__file__).resolve().parents[2]
        facts = self.facts()
        with tempfile.TemporaryDirectory(prefix="task13-ibex-", dir=root / "runs") as temporary:
            work = Path(temporary)
            boot = build_minimal_boot_image(facts, work / "boot")
            first_word = int.from_bytes(boot.binary_path.read_bytes()[:4], "little")
            plan = self.ibex_plan(root)
            output = work / "composition"
            write_generic_composition(plan, output, base_dir=root)
            port = self.top_port
            bench = output / "task13_tb.sv"
            bench.write_text(f"""module tb;
logic clock=0, reset_n=0; integer cycles=0, fetches=0, progress=0, completions=0;
logic [31:0] last_fetch=0; integer illegal_or_trap_records=0;
logic reset_released=0, pass_seen=0, first_fetch_checked=0;
always #1 clock=~clock;
generic_composition_top dut(
 .{port('processor.clock','clock','clk_i')}(clock),
 .{port('processor.reset','reset','rst_ni')}(reset_n),
 .{port('processor.boot','boot_address','boot_addr_i')}(32'h{facts.reset_vector:08x}),
 .{port('processor.boot','hart_id','hart_id_i')}(32'h0),
 .{port('processor.interrupts','software_interrupt','irq_software_i')}(1'b0),
 .{port('processor.interrupts','timer_interrupt','irq_timer_i')}(1'b0),
 .{port('processor.interrupts','external_interrupt','irq_external_i')}(1'b0),
 .{port('processor.interrupts','fast_interrupt','irq_fast_i')}(15'h0),
 .{port('processor.debug','request','debug_req_i')}(1'b0),
 .{port('processor.execution_controls','fetch_enable','fetch_enable_i')}(4'b0101),
 .{port('processor.execution_controls','scan_reset','scan_rst_ni')}(1'b1),
 .{port('processor.execution_controls','test_enable','test_en_i')}(1'b0),
 .{port('processor.execution_controls','counter_enable_writable','mcounteren_writable_i')}(4'b0101),
 .{port('processor.execution_controls','cheriot_enable','cheriot_enable_i')}(4'b1010),
 .{port('processor.execution_controls','trvk_heap_base','trvk_heap_base_addr_i')}('0),
 .{port('processor.execution_controls','instruction_integrity','instr_rdata_intg_i')}('0),
 .{port('processor.execution_controls','data_integrity','data_rdata_intg_i')}('0),
 .{port('processor.execution_controls','data_tag','data_tag_i')}('0),
 .{port('processor.execution_controls','trvk_grant','trvk_revbm_gnt_i')}('0),
 .{port('processor.execution_controls','trvk_response_valid','trvk_revbm_rvalid_i')}('0),
 .{port('processor.execution_controls','trvk_read_data','trvk_revbm_rdata_i')}('0),
 .{port('processor.execution_controls','trvk_read_integrity','trvk_revbm_rdata_intg_i')}('0),
 .{port('processor.execution_controls','trvk_error','trvk_revbm_err_i')}('0),
 .{port('processor.execution_controls','nonmaskable_interrupt','irq_nm_i')}('0),
 .{port('processor.execution_controls','scramble_key_valid','scramble_key_valid_i')}('0),
 .{port('processor.execution_controls','scramble_key','scramble_key_i')}('0),
 .{port('processor.execution_controls','scramble_nonce','scramble_nonce_i')}('0)
);
always @(posedge clock) if(reset_n) begin
 cycles <= cycles + 1; reset_released <= 1;
 if(dut.backend_target_req_valid && dut.backend_target_req_ready) begin
   if(!dut.backend_target_write) begin
     fetches <= fetches + 1;
     if(dut.backend_target_addr != last_fetch) begin progress <= progress + 1; last_fetch <= dut.backend_target_addr; end
   end
   if(dut.backend_target_write && dut.backend_target_addr == 32'h{facts.pass_address:08x} &&
      dut.backend_target_wdata[31:0] == 32'h{facts.pass_value:08x}) pass_seen <= 1;
 end
 if(dut.backend_target_rsp_valid && dut.backend_target_rsp_ready) begin
   completions <= completions + 1;
   if(!first_fetch_checked) begin
     if(dut.backend_target_addr != 32'h{facts.reset_vector:08x} ||
        dut.backend_target_rdata[31:0] != 32'h{first_word:08x})
       $fatal(1,"initial fetch mismatch addr=%h data=%h",dut.backend_target_addr,dut.backend_target_rdata);
     first_fetch_checked <= 1;
     $display("BOOT_FETCH addr=%h data=%h",dut.backend_target_addr,dut.backend_target_rdata[31:0]);
   end
 end
 if(pass_seen && completions > 0 && first_fetch_checked) begin
   $display("EXEC reset=%0d fetches=%0d progress=%0d completions=%0d pass=1 cycles=%0d illegal_or_trap_records=%0d exit=pass", reset_released,fetches,progress,completions,cycles,illegal_or_trap_records);
   $finish;
 end
 if(cycles >= {facts.max_cycles}) begin
   $display("EXEC reset=%0d fetches=%0d progress=%0d completions=%0d pass=%0d cycles=%0d exit=timeout", reset_released,fetches,progress,completions,pass_seen,cycles);
   $fatal(1,"execution timeout");
 end
end
initial begin repeat(5) @(negedge clock); reset_n=1; end
endmodule
""", encoding="ascii")
            compile_result = subprocess.run(
                ("nice", "-n15", "verilator", "--binary", "--timing", "--top-module", "tb",
                 "-Wno-fatal", "-Wno-PINMISSING", "-Wno-WIDTH", "-Wno-UNOPTFLAT",
                 "-j", "1", "--Mdir", "obj_dir", "-f", "sources.f", bench.name),
                cwd=output, env={**os.environ, "JOBS": "1"}, capture_output=True,
                text=True, timeout=120, check=False,
            )
            self.assertEqual(0, compile_result.returncode, compile_result.stdout + compile_result.stderr)
            result = subprocess.run(
                (str(output / "obj_dir/Vtb"), f"+riscv_boot_image={boot.memory_hex_path}"),
                cwd=output, capture_output=True, text=True, timeout=30, check=False,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertNotIn("Illegal instruction", result.stdout + result.stderr)
            self.assertRegex(result.stdout, rf"BOOT_FETCH addr=0*{facts.reset_vector:x} data={first_word:08x}")
            self.assertRegex(result.stdout, r"EXEC reset=1 fetches=[1-9]\d* progress=[1-9]\d* completions=[1-9]\d* pass=1 cycles=\d+ illegal_or_trap_records=0 exit=pass")

    def test_cva6_packed_axi_wiring_matches_compiler_evidence_and_warnings(self) -> None:
        root = Path(__file__).resolve().parents[2]
        description = load_interface_description(
            root / "configs/cpus/cva6/official_core_interface_description.json"
        )
        snapshot = SourceCrawler().crawl(description.source, base_dir=root)
        assert snapshot.elaboration_evidence is not None
        elaboration = json.loads(snapshot.elaboration_evidence)
        self.assertEqual("recorded-nonfatal", description.source.elaboration.warning_policy)
        self.assertEqual(464, elaboration["warning_summary"]["warning_count"])

        plan = self.cva6_plan(root)
        assert plan.processor_execution is not None
        self.assertEqual(1, len(plan.processor_execution.routes))
        route = plan.processor_execution.routes[0]
        self.assertEqual(("axi4", "1"), route.source_protocol)
        packed = [
            connection["physical"] for connection in route.field_connections
            if "part_select" in connection["physical"]
        ]
        self.assertEqual(45, len(packed))
        self.assertEqual({"noc_req_o", "noc_resp_i"}, {item["container_port"] for item in packed})
        for item in packed:
            self.assertEqual(f"[{item['raw_hi']}:{item['raw_lo']}]", item["part_select"])


if __name__ == "__main__":
    unittest.main()
