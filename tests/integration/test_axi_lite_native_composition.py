"""Generic AXI4-Lite routing: source-backed publication and clocked RTL evidence."""
from dataclasses import replace
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tests.integration.test_native_protocol_composition import native_plan, catalog_for
from myfuzz.composition import plan_generic_composition, write_generic_composition
from myfuzz.components.catalog import ComponentCatalog
from myfuzz.composition.auto import _generic_adapter_contract, AutoCompositionError
from myfuzz.composition.ids import canonical_id
from myfuzz.composition.protocol_composer import _generic_routes, _render_generic_adapter, _render_generic_top
from myfuzz.protocols.catalog import ProtocolCatalog


KEY = ("axi4-lite", "1")


class AxiLiteNativeCompositionTests(unittest.TestCase):
    def test_generated_top_with_last_page_region(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = native_plan(Path(tmp), KEY)
            region = {**plan.ir["address_regions"][0], "base": 0xff00, "size": 0x100, "end": 0x10000}
            plan = replace(plan, ir={**plan.ir, "address_regions": [region]})
            text = _render_generic_top(plan)
            self.assertIn("ADDRESS_BASE = 16'hff00", text)
            self.assertIn("ADDRESS_SIZE = 17'h100", text)

    def test_source_backed_publication_at_address_space_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = native_plan(root, KEY)
            profile = replace(original.component_catalog.require("device"), default_size=0x10000)
            plan = plan_generic_composition(original.request, base_dir=root,
                component_catalog=ComponentCatalog((profile,)), protocol_catalog=original.protocol_catalog)
            self.assertEqual(plan.ir["address_regions"][0]["end"], 0x10000)
            write_generic_composition(plan, root / "out", base_dir=root)
            if shutil.which("iverilog"):
                result = subprocess.run(["iverilog", "-g2012", "-s", "generic_composition_top", "-o", str(root / "compiled"), str(root / "source/source.sv"), str(root / "target.sv"), str(root / "out/generic_composition_top.sv")], capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_source_backed_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = native_plan(root, KEY)
            self.assertEqual(plan.ir["adapters"][0]["contract"]["mode"], "native_axi4_lite")
            write_generic_composition(plan, root / "out", base_dir=root)
            if shutil.which("iverilog"):
                result = subprocess.run(["iverilog", "-g2012", "-s", "generic_composition_top", "-o", str(root / "compiled"), str(root / "source/source.sv"), str(root / "target.sv"), str(root / "out/generic_composition_top.sv")], capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_contract_bounds_and_malformed_metadata(self):
        plugin = catalog_for(KEY).require(*KEY)
        self.assertEqual(_generic_adapter_contract(KEY, ProtocolCatalog((plugin,)))["max_wait_cycles"], 16)
        for bound in (1, 7):
            bounded = replace(plugin, temporal_rules=(replace(plugin.temporal_rules[0], max_cycles=bound), *plugin.temporal_rules[1:]))
            self.assertEqual(_generic_adapter_contract(KEY, ProtocolCatalog((bounded,)))["max_wait_cycles"], bound)
        bad_plugins = [
            replace(plugin, fields=plugin.fields[:-1]),
            replace(plugin, fields=plugin.fields + (replace(plugin.fields[0], field_id="awid"),)),
            replace(plugin, fields=(replace(plugin.fields[0], width_expression="8"), *plugin.fields[1:])),
            replace(plugin, channel_relations=(replace(plugin.channel_relations[0], kind="burst"), *plugin.channel_relations[1:])),
        ]
        for key, value in (("bursts", True), ("ids", True), ("max_outstanding", 2), ("max_wait_cycles", 0), ("max_wait_cycles", True), ("cdc", True)):
            limits = dict(plugin.capability_limits)
            limits[key] = value
            bad_plugins.append(replace(plugin, capability_limits=tuple(limits.items())))
        for index, bad in enumerate(bad_plugins):
            with self.subTest(case=index), self.assertRaises(AutoCompositionError):
                _generic_adapter_contract(KEY, ProtocolCatalog((bad,)))

    def test_rejects_unsupported_temporal_and_projection_shapes(self):
        plugin = catalog_for(KEY).require(*KEY)
        for index, bad in enumerate((
            replace(plugin, temporal_rules=()),
            replace(plugin, temporal_rules=(replace(plugin.temporal_rules[0], kind="burst"), *plugin.temporal_rules[1:])),
            replace(plugin, temporal_rules=(replace(plugin.temporal_rules[0], consequent_field_id="wready"), *plugin.temporal_rules[1:])),
            replace(plugin, projection_actions=()),
            replace(plugin, projection_actions=(replace(plugin.projection_actions[0], field_ids=("awaddr",)), *plugin.projection_actions[1:])),
            replace(plugin, projection_actions=(*plugin.projection_actions, replace(plugin.projection_actions[1], kind="unknown"))),
        )):
            with self.subTest(case=index), self.assertRaises(AutoCompositionError):
                _generic_adapter_contract(KEY, ProtocolCatalog((bad,)))

    def test_rejects_malformed_physical_shapes(self):
        with tempfile.TemporaryDirectory() as tmp:
            route = _generic_routes(native_plan(Path(tmp), KEY))[0]
            for name, change in (("awvalid", {"width": 2}), ("awaddr", {"signed": True}), ("araddr", {"width": 15}), ("wstrb", {"width": 2}), ("rdata", {"width": 16}), ("bresp", {"width": 1}), ("arprot", {"width": 2}), ("wdata", {"direction": "output"})):
                bad = {**route, "fields": [dict(f) for f in route["fields"]]}
                next(f for f in bad["fields"] if f["field_id"] == name).update(change)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    _render_generic_adapter(bad)

    def simulate(self, stimulus, bound=16, *, reset_semantics=None, data_width=32, base=0x100):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            route = _generic_routes(native_plan(root, KEY))[0]
            route["base"] = base
            if reset_semantics is not None:
                route["control"]["reset_semantics"] = reset_semantics
            if data_width != 32:
                for field in route["fields"]:
                    if field["field_id"] in {"wdata", "rdata"}:
                        field["width"] = data_width
                    elif field["field_id"] == "wstrb":
                        field["width"] = data_width // 8
            route["max_wait_cycles"] = route["contract"]["max_wait_cycles"] = bound
            tag = f"{canonical_id('generic-render-route', str(route['component_id'])):016x}"
            declarations, connections = [], [".clock(clock)", ".reset(reset)", ".component_select(1'b1)"]
            for f in route["fields"]:
                name = f["field_id"]
                hashed = f"f_{canonical_id('generic-render-field', name):016x}"
                for prefix in (("source", "target") if f["direction"] == "input" else ("target", "response")):
                    driven = prefix == "source" or (prefix == "target" and f["direction"] == "output")
                    declarations.append(f"logic [{f['width']-1}:0] {prefix}_{name}" + (" = 0;" if driven else ";"))
                    connections.append(f".{prefix}_{hashed}({prefix}_{name})")
            bench = "module tb; logic clock=0, reset=0; integer cycles; " + "\n".join(declarations) + f"\nmyfuzz_generic_adapter_{tag} dut(" + ",".join(connections) + ");\n" + """
task tick; begin #5; clock=1; #5; clock=0; end endtask
task reset_route; begin reset=0; tick(); reset=1; tick(); end endtask
task consume_b; begin source_bready=1; tick(); source_bready=0; tick(); end endtask
task consume_r; begin source_rready=1; tick(); source_rready=0; tick(); end endtask
initial begin reset_route();
""" + stimulus + '\n$display("PASS"); $finish; end\ninitial begin #10000; $fatal(1,"watchdog"); end endmodule\n'
            if reset_semantics and reset_semantics["polarity"] == "active_high":
                bench = bench.replace("reset=0", "reset=ACTIVE").replace("reset=1", "reset=0").replace("reset=ACTIVE", "reset=1")
            (root / "sim.sv").write_text(_render_generic_adapter(route) + bench)
            compiled = subprocess.run(["iverilog", "-g2012", "-s", "tb", "-o", str(root / "sim"), str(root / "sim.sv")], capture_output=True, text=True, timeout=20)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run(["vvp", str(root / "sim")], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("PASS", result.stdout)

    @unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"), "Icarus required")
    def test_independent_channels_addresses_and_backpressure(self):
        self.simulate("""
// AW first: reserve the route; AR must not steal a partially captured write.
source_awaddr=16'h104; source_awprot=3; source_araddr=16'h999;
source_awvalid=1; tick(); source_awvalid=0;
source_arvalid=1; #1;
if (response_arready || response_awready) $fatal(1,"outstanding AW");
repeat(2) tick(); source_arvalid=0;
source_wdata=32'h12345678; source_wstrb=5; source_wvalid=1; tick(); source_wvalid=0;
tick(); source_awaddr=0; source_wdata=0;
repeat(3) begin
if (!target_awvalid || !target_wvalid || target_awaddr!=4 || target_awprot!=3 || target_wdata!=32'h12345678 || target_wstrb!=5) $fatal(1,"write payload hold");
tick(); end
target_wready=1; tick(); target_wready=0;
if (target_wvalid || !target_awvalid) $fatal(1,"independent target handshake");
target_awready=1; tick(); target_awready=0;
target_bresp=2; target_bvalid=1; tick(); target_bvalid=0; target_bresp=0;
repeat(20) begin
if (!response_bvalid || response_bresp!=2 || response_awready || response_wready || response_arready) $fatal(1,"B backpressure");
tick(); end
consume_b();
// W first; unrelated ARADDR must not affect AW decoding.
source_wdata=32'hcafefeed; source_wstrb=15; source_wvalid=1; tick(); source_wvalid=0;
source_arvalid=1; #1; if(response_arready) $fatal(1,"W reserves route"); source_arvalid=0;
source_awaddr=16'h108; source_awvalid=1; tick(); source_awvalid=0; tick();
if(target_awaddr!=8 || target_wdata!=32'hcafefeed) $fatal(1,"W first");
target_awready=1; target_wready=1; tick(); target_awready=0; target_wready=0;
target_bvalid=1; tick(); target_bvalid=0; consume_b();
// AR is independent of AW; read request/response are both held when stalled.
source_awaddr=16'h999; source_araddr=16'h10c; source_arprot=6; source_arvalid=1; tick(); source_arvalid=0;
source_araddr=0;
repeat(3) begin
if(!target_arvalid || target_araddr!=12 || target_arprot!=6) $fatal(1,"AR hold/address"); tick(); end
target_arready=1; tick(); target_arready=0;
target_rdata=32'h89abcdef; target_rresp=2; target_rvalid=1; tick(); target_rvalid=0; target_rdata=0; target_rresp=0;
repeat(20) begin
if(!response_rvalid || response_rdata!=32'h89abcdef || response_rresp!=2 || response_awready || response_wready || response_arready) $fatal(1,"R backpressure"); tick(); end
consume_r(); if(!response_arready) $fatal(1,"read completion");
""")

    @unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"), "Icarus required")
    def test_completion_at_deadline_and_simultaneous_arbitration(self):
        self.simulate("""
source_awaddr=16'h100; source_araddr=16'h104;
source_awvalid=1; source_wvalid=1; source_arvalid=1; #1;
if(response_arready || !response_awready || !response_wready) $fatal(1,"arbitration");
tick(); source_awvalid=0; source_wvalid=0; tick();
target_awready=1; tick(); target_awready=0;
if(!target_wvalid || target_awvalid) $fatal(1,"AW before W target");
target_wready=1; tick(); target_wready=0;
tick(); target_bvalid=1; target_bresp=0; tick(); target_bvalid=0;
if(!response_bvalid || response_bresp!=0) $fatal(1,"B deadline completion");
source_bready=1; tick(); source_bready=0; tick(); source_arvalid=0;
if(!target_arvalid || target_araddr!=4) $fatal(1,"pending AR after write");
target_arready=1; tick(); target_arready=0; tick(); tick();
target_rvalid=1; target_rresp=0; target_rdata=32'h1234; tick(); target_rvalid=0;
if(!response_rvalid || response_rresp!=0 || response_rdata!=32'h1234) $fatal(1,"R deadline completion");
consume_r(); if(!response_arready) $fatal(1,"deadline must not poison");
""", bound=4)

    @unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"), "Icarus required")
    def test_partial_timeout_preserves_payload_then_handshakes_in_quarantine(self):
        self.simulate("""
source_awaddr=16'h108; source_awprot=5; source_wdata=32'hfeed; source_wstrb=3;
source_awvalid=1; source_wvalid=1; tick(); source_awvalid=0; source_wvalid=0; tick();
target_wready=1; tick(); target_wready=0; tick();
if(!response_bvalid || response_bresp!=2 || !target_awvalid || target_wvalid) $fatal(1,"partial timeout");
consume_b(); source_awaddr=16'h180; source_awprot=0; source_wdata=0;
repeat(5) begin
if(!target_awvalid || target_awaddr!=8 || target_awprot!=5 || target_wdata!=32'hfeed || target_wstrb!=3) $fatal(1,"quarantined payload"); tick(); end
target_awready=1; tick(); target_awready=0;
if(target_awvalid) $fatal(1,"quarantine handshake");
target_bvalid=1; tick(); target_bvalid=0;
if(response_bvalid || response_awready) $fatal(1,"late completion");
reset_route();
source_araddr=16'h104; source_arvalid=1; tick(); source_arvalid=0;
target_arready=1; tick(); target_arready=0;
target_rvalid=1; target_rdata=32'habcd; tick(); target_rvalid=0;
if(!response_rvalid || response_rresp!=0 || response_rdata!=32'habcd) $fatal(1,"post-reset transaction");
consume_r();
""", bound=2)

    @unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"), "Icarus required")
    def test_reset_variants_64bit_data_and_top_of_address_space(self):
        for polarity in ("active_low", "active_high"):
            for synchrony in ("synchronous", "asynchronous"):
                with self.subTest(polarity=polarity, synchrony=synchrony):
                    self.simulate("""
source_awaddr=16'hffff; source_wdata=64'h0123456789abcdef; source_wstrb=8'h81;
source_awvalid=1; source_wvalid=1; tick(); source_awvalid=0; source_wvalid=0; tick();
if(!target_awvalid || target_awaddr!=255 || target_wdata!=64'h0123456789abcdef || target_wstrb!=8'h81) $fatal(1,"64bit/full region");
reset_route();
if(target_awvalid || target_wvalid || response_bvalid || !response_arready) $fatal(1,"reset pending write");
source_araddr=16'hff00; source_arvalid=1; tick(); source_arvalid=0;
if(target_araddr!=0 || !target_arvalid) $fatal(1,"lower boundary");
target_arready=1; tick(); target_arready=0; target_rvalid=1; target_rdata=64'hfedcba9876543210; tick(); target_rvalid=0;
if(!response_rvalid || response_rdata!=64'hfedcba9876543210) $fatal(1,"64bit read");
reset_route(); if(response_rvalid || !response_arready) $fatal(1,"reset response");
""", reset_semantics={"polarity": polarity, "synchrony": synchrony}, data_width=64, base=0xff00)

    @unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"), "Icarus required")
    def test_invalid_addresses_have_no_target_transaction(self):
        self.simulate("""
source_awaddr=16'h200; source_araddr=16'h100; source_awvalid=1; source_wvalid=1;
tick(); source_awvalid=0; source_wvalid=0; tick();
repeat(20) begin
if(target_awvalid || target_wvalid || target_arvalid || !response_bvalid || response_bresp!=3) $fatal(1,"invalid AW"); tick(); end
consume_b();
source_awaddr=16'h100; source_araddr=16'hff; source_arvalid=1; tick(); source_arvalid=0; tick();
repeat(20) begin
if(target_awvalid || target_wvalid || target_arvalid || !response_rvalid || response_rresp!=3 || response_rdata!=0) $fatal(1,"invalid AR"); tick(); end
consume_r(); if(!response_arready) $fatal(1,"invalid is not quarantine");
""")

    @unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"), "Icarus required")
    def test_timeout_quarantine_and_reset(self):
        for read in (False, True):
            for bound in (1, 4):
                for accept in (False, True):
                    with self.subTest(read=read, bound=bound, accept=accept):
                        start = "source_araddr=16'h104; source_arvalid=1; tick(); source_arvalid=0;" if read else "source_awaddr=16'h108; source_wdata=32'h1234; source_awvalid=1; source_wvalid=1; tick(); source_awvalid=0; source_wvalid=0; tick();"
                        valid, resp, ready = ("rvalid", "rresp", "rready") if read else ("bvalid", "bresp", "bready")
                        pending = "target_arvalid" if read else "(target_awvalid || target_wvalid)"
                        self.simulate(("target_arready=1; target_awready=1; target_wready=1;" if accept else "") + start + f"""
cycles=0;
while(!response_{valid} && cycles<8) begin tick(); cycles=cycles+1; end
if(cycles!={bound} || response_{resp}!=2) $fatal(1,"timeout bound %0d", cycles);
repeat(3) begin if(!response_{valid} || response_{resp}!=2) $fatal(1,"timeout response hold"); tick(); end
source_{ready}=1; tick(); source_{ready}=0;
source_awvalid=1; source_wvalid=1; source_arvalid=1;
target_bvalid=1; target_rvalid=1; target_rdata=32'hbad;
repeat(8) begin
if(response_awready || response_wready || response_arready || response_bvalid || response_rvalid) $fatal(1,"quarantine late response");
if({pending} != {0 if accept else 1}) $fatal(1,"pending VALID dropped"); tick(); end
source_awvalid=0; source_wvalid=0; source_arvalid=0; target_bvalid=0; target_rvalid=0;
reset_route();
if(target_awvalid || target_wvalid || target_arvalid || !response_arready) $fatal(1,"reset quarantine");
""", bound=bound)
