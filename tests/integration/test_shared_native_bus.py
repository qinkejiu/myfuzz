"""Source-backed shared native fabrics, exercised by real Icarus without waves."""
from dataclasses import replace
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tests.integration.test_native_protocol_composition import native_plan
from myfuzz.composition import GenericCompositionRequest, plan_generic_composition, write_generic_composition
from myfuzz.composition.auto import AutoCompositionError
from myfuzz.components.catalog import ComponentCatalog
from myfuzz.composition.protocol_composer import _generic_routes, _generic_port_records
from myfuzz.composition.ids import canonical_id
from myfuzz.composition.shared_native_bus import validate_groups
from myfuzz.integration.campaign import CampaignOptions, run_supervised_command


def shared_plan(root, key, registers=False, full_range=False):
    single = native_plan(root, key)
    profile = single.component_catalog.require("device")
    profiles = []
    for name in ("amber", "birch", "cobalt"):
        text = (root / "target.sv").read_text().replace("module device(", "module " + name + "(")
        if registers:
            apb = key[0] == "apb"
            outputs = ("pready", "pslverr", "prdata") if apb else ("ack", "err", "dat_r")
            for field in outputs:
                text = text.replace(f"assign {field} = '0;", "")
            active = "psel && penable" if apb else "cyc && stb"
            addr, data, write = ("paddr", "pwdata", "pwrite") if apb else ("adr", "dat_w", "we")
            # Responses deliberately remain asserted while inactive: only the
            # fabric may prevent these unrelated responses reaching the host.
            response = ("assign pready = done; assign pslverr = bad; assign prdata = value;" if apb else
                        "assign ack = done && !bad; assign err = done && bad; assign dat_r = value;")
            body = f"""
logic [31:0] value; integer writes; integer waits;
wire done = {addr}[7:0] != 8'hf0 && ({addr}[7:0] != 8'h10 || waits >= 3);
wire bad = {addr}[7:0] == 8'he0;
{response}
always @(posedge clock or negedge reset) begin
 if (!reset) begin value <= 0; writes <= 0; waits <= 0; end
 else if ({active}) begin
   waits <= waits + 1;
   if (done && !bad && {write}) begin value <= {data}; writes <= writes + 1; end
 end else waits <= 0;
end
"""
            text = text.replace("endmodule", body + "endmodule")
        (root / (name + ".sv")).write_text(text)
        size = (32768 if name == "cobalt" else 16384) if full_range else 256
        profiles.append(replace(profile, component_type=name, module_name=name, source_paths=(name + ".sv",), default_size=size))
    return plan_generic_composition(
        GenericCompositionRequest(single.interface_description, tuple(p.component_type for p in profiles), (key,)),
        base_dir=root, component_catalog=ComponentCatalog(tuple(profiles)), protocol_catalog=single.protocol_catalog)


class SharedNativeBusTests(unittest.TestCase):
    def test_three_targets_one_source(self):
        for key in (("apb", "3"), ("apb", "4"), ("wishbone", "classic")):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                try:
                    plan = shared_plan(root, key)
                except AutoCompositionError as error:
                    self.fail(str(error))
                self.assertEqual([c["selected_endpoint"] for c in plan.components], ["bus"] * 3)
                write_generic_composition(plan, root / "out", base_dir=root)

    def test_shared_axi_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(AutoCompositionError, "single-target-source"):
                shared_plan(Path(tmp), ("axi4-lite", "1"))

    def test_multiple_compatible_masters_still_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = shared_plan(root, ("apb", "3"))
            desc = plan.interface_description
            desc = replace(desc, endpoints=(*desc.endpoints, replace(desc.endpoints[0], endpoint_id="other_bus")))
            with self.assertRaisesRegex(AutoCompositionError, "ambiguous-source-endpoint"):
                plan_generic_composition(replace(plan.request, interface_description=desc), base_dir=root,
                    component_catalog=plan.component_catalog, protocol_catalog=plan.protocol_catalog)

    def test_source_backed_target_reset_and_width_mismatch(self):
        for mutation in ("reset", "width", "direction"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                plan = shared_plan(root, ("apb", "3"))
                path = root / "birch.sv"
                text = path.read_text()
                if mutation == "reset":
                    text = text.replace("negedge reset", "posedge reset").replace("!reset", "reset")
                elif mutation == "width":
                    text = text.replace("[15:0] paddr", "[14:0] paddr")
                else:
                    text = text.replace("input logic [15:0] paddr", "output logic [15:0] paddr")
                path.write_text(text)
                with self.assertRaises(AutoCompositionError):
                    plan_generic_composition(plan.request, base_dir=root, component_catalog=plan.component_catalog,
                                             protocol_catalog=plan.protocol_catalog)

    def test_group_mismatch_and_shared_reset_rejected(self):
        for key in (("apb", "3"), ("wishbone", "classic")):
            with tempfile.TemporaryDirectory() as tmp:
                routes = _generic_routes(shared_plan(Path(tmp), key))
                for changed in (
                    {"contract": {**routes[1]["contract"], "mode": "native_axi4_lite"}},
                    {"control": {**routes[1]["control"], "reset": {"source_port": "other", "target_port": "reset"}}},
                    {"control": {**routes[1]["control"], "reset_semantics": {"polarity": "active_high", "synchrony": "asynchronous"}}},
                    {"fields": ({**routes[1]["fields"][0], "width": 99}, *routes[1]["fields"][1:])},
                ):
                    with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, "mismatch/reset"):
                        validate_groups((routes[0], {**routes[1], **changed}, routes[2]))

    @unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"), "Icarus required")
    def test_real_icarus_shared_transactions(self):
        for key in (("apb", "3"), ("apb", "4"), ("wishbone", "classic")):
            for full_range in (False, True):
                with self.subTest(key=key, full_range=full_range), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    plan = shared_plan(root, key, registers=True, full_range=full_range)
                    write_generic_composition(plan, root / "out", base_dir=root)
                    route = _generic_routes(plan)[0]
                    apb = key[0] == "apb"
                    source_instance = f"u_{canonical_id('generic-source-instance', 'renamed_initiator'):016x}"
                    decl, force = [], []
                    for f in route["fields"]:
                        name = f["field_id"]
                        path = f"dut.{source_instance}.wire_{name}"
                        if f["direction"] == "input":
                            decl.append(f"reg [{f['width']-1}:0] s_{name}=0;")
                            force.append(f"force {path} = s_{name};")
                        else:
                            decl.append(f"wire [{f['width']-1}:0] r_{name} = {path};")
                    ports = {r["source_port"]: r["opaque_port"] for r in _generic_port_records(plan)}
                    ready = "r_pready" if apb else "(r_ack || r_err)"
                    error = "r_pslverr" if apb else "r_err"
                    read = "r_prdata" if apb else "r_dat_r"
                    start = ("s_paddr=a; s_pwdata=d; s_pwrite=w; s_psel=1; s_penable=0; tick(); s_penable=1; tick();" if apb else
                             "s_adr=a; s_dat_w=d; s_we=w; s_cyc=1; s_stb=1; tick();")
                    drop = "s_penable=0;" if apb else "s_stb=0; tick();"
                    # APB leaves PSEL high across different regions; WB leaves
                    # CYC high and drops STB between Classic transfers.
                    b1, b2 = (16384, 32768) if full_range else (256, 512)
                    fabric_name = f"myfuzz_shared_{canonical_id('shared-native-endpoint', 'bus'):016x}"
                    fabric = f"dut.u_{canonical_id('generic-component-instance', fabric_name):016x}"
                    guards = []
                    for i in range(3):
                        select = "psel" if apb else "cyc"
                        guards.append(f"if (!{fabric}.hit_{i} && {fabric}.t{i}_{select}) $fatal(1,\"inactive target request\");")
                    counts = f"""
if ({fabric}.target_0.writes != 2 || {fabric}.target_1.writes != 1 ||
    {fabric}.target_2.writes != {2 if full_range else 1}) $fatal(1,"cross-target or duplicate write");
"""
                    test = f"""
transfer(0,1,32'h11,0,0); transfer({b1},1,32'h22,0,0); transfer({b2},1,32'h33,0,0);
transfer(0,0,0,0,32'h11); transfer({b1},0,0,0,32'h22); transfer({b2},0,0,0,32'h33);
transfer({b1}+16,0,0,0,32'h22);
transfer({b2}+224,1,32'h99,1,0);
transfer({b2},0,0,0,32'h33);
transfer(240,1,32'h99,1,0);
transfer({b1},0,0,0,32'h22);
"""
                    if full_range:
                        test += "transfer(65535,1,32'h44,0,0); transfer(65535,0,0,0,32'h44);\n"
                    else:
                        test += "transfer(65535,1,32'h44,1,0); transfer(768,0,0,1,0);\n"
                    if apb:
                        test += f"""
// Setup abort and setup timeout must release every target without writes.
s_paddr=0; s_psel=1; s_penable=0; tick(); s_psel=0; tick();
if (r_pready) $fatal(1,"setup abort response");
s_psel=1; tick(); repeat(20) tick();
if ({fabric}.t0_psel || {fabric}.t1_psel || {fabric}.t2_psel) $fatal(1,"setup timeout select");
s_psel=0; tick(); transfer({b1},0,0,0,32'h22);
"""
                    abort = ("s_psel=0; s_penable=0;" if apb else "s_cyc=0; s_stb=0;")
                    corrupt = (f"s_paddr={b2}; s_pwdata=32'hdead;" if apb else f"s_adr={b2}; s_dat_w=32'hdead;")
                    test += f"""
// The latched selection and payload must survive live source changes.
begin_request(16,1,32'h55); {corrupt}
finish_request(0,0,0); transfer(0,0,0,0,32'h55);
transfer({b2},0,0,0,{'32\'h44' if full_range else '32\'h33'});
// Abort a stalled transaction and reissue to another region.
begin_request(240,1,32'hbad); {abort} tick();
if ({ready}) $fatal(1,"abort response");
transfer({b1},0,0,0,32'h22);
{counts}
begin_request(240,1,32'hbad); reset=0; tick(); {abort} tick(); reset=1; tick();
transfer(0,0,0,0,0); transfer({b1},0,0,0,0); transfer({b2},0,0,0,0);
$display("PASS shared {key[0]} {key[1]} full_range={full_range}"); $finish;
"""
                    bench = "\n".join(["module tb; reg clock=0,reset=0;", *decl,
                        f"generic_composition_top dut(.{ports['clk']}(clock), .{ports['rst']}(reset));",
                        "task tick; begin #5; clock=1; #5; clock=0; " + " ".join(guards) + " end endtask",
                        f"task begin_request(input [15:0] a,input w,input [31:0] d); begin {start} end endtask",
                        f"""task finish_request(input expected_error,input check_data,input [31:0] expected_data);
integer n; begin n=0;
while (!{ready} && n<40) begin tick(); n=n+1; end
if (!{ready} || {error} !== expected_error) $fatal(1,"completion/error n=%0d",n);
if (!expected_error && check_data && {read} !== expected_data) $fatal(1,"read isolation got=%h expected=%h",{read},expected_data);
tick(); {drop}
end endtask
task transfer(input [15:0] a,input w,input [31:0] d,input e,input [31:0] expected);
begin begin_request(a,w,d); finish_request(e,!w,expected); end endtask
initial begin
""", *force, "tick(); reset=1; tick();", test, "end endmodule"])
                    (root / "tb.sv").write_text(bench)
                    compiled = subprocess.run(["iverilog", "-g2012", "-s", "tb", "-o", str(root / "sim"),
                        *(str(root / p) for p in plan.source_files), str(root / "out/generic_composition_top.sv"), str(root / "tb.sv")], capture_output=True, text=True, timeout=20)
                    self.assertEqual(compiled.returncode, 0, compiled.stderr)
                    result = run_supervised_command(CampaignOptions(
                        command=("nice", "-n15", "vvp", "-l", str(root / "simulation.log"), str(root / "sim")),
                        output_dir=root / "runtime", duration_seconds=20, checkpoint_seconds=1))
                    self.assertEqual(result["returncode"], 0, result)
                    self.assertEqual(result["status"], "completed", result)
                    self.assertFalse(result["soft_limit_exceeded"], result)
                    self.assertIn("PASS shared", (root / "simulation.log").read_text())
