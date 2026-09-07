"""Source-backed native routes, including real clocked wait/timeout simulation."""
from dataclasses import replace
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from myfuzz.composition import GenericCompositionRequest, load_interface_description, plan_generic_composition, source_tree_hash, write_generic_composition
from myfuzz.composition.auto import _generic_adapter_contract, AutoCompositionError
from myfuzz.composition.protocol_composer import _generic_routes, _render_generic_adapter
from myfuzz.composition.ids import canonical_id
from myfuzz.components.catalog import ComponentCatalog
from myfuzz.components.model import PeripheralProfile
from myfuzz.protocols.catalog import _builtin_catalog as builtin_protocol_catalog, ProtocolCatalog


def catalog_for(key):
    plugin = builtin_protocol_catalog().require(*key)
    return ProtocolCatalog((plugin,))


def native_plan(root, key):
    catalog = catalog_for(key)
    plugin = catalog.require(*key)
    # Classic endpoints have no pipelined STALL pin; the catalog may advertise
    # an optional declaration for other consumers, with stall_supported=False.
    plugin = replace(plugin, fields=tuple(f for f in plugin.fields if f.field_id != "stall"))
    widths = {f.field_id: int(eval(f.width_expression, {"__builtins__": {}}, {"address_width": 16, "data_width": 32})) for f in plugin.fields}
    source = root / "source"
    source.mkdir()
    def declaration(f, host):
        output = (f.direction == "host_to_device") == host
        return f"{'output' if output else 'input'} logic [{widths[f.field_id]-1}:0] {'wire_' if host else ''}{f.field_id}"
    cpu = source / "source.sv"
    cpu.write_text("module renamed_initiator(input logic clk, input logic rst, output logic monitor, " + ", ".join(declaration(f, True) for f in plugin.fields) + "); always_ff @(posedge clk or negedge rst) if (!rst) monitor <= 0; else monitor <= 1; " + " ".join(f"assign wire_{f.field_id} = '0;" for f in plugin.fields if f.direction == "host_to_device") + " endmodule")
    target = root / "target.sv"
    target.write_text("module device(input logic clock, input logic reset, " + ", ".join(declaration(f, False) for f in plugin.fields) + "); logic marker; always_ff @(posedge clock or negedge reset) if (!reset) marker <= 0; else marker <= 1; " + " ".join(f"assign {f.field_id} = '0;" for f in plugin.fields if f.direction == "device_to_host") + " endmodule")
    description = load_interface_description({"schema_version": "interface_description.v1", "source": {"root": "source", "revision": source_tree_hash(source, (cpu,)), "top_module": "renamed_initiator", "files": ["source.sv"]}, "endpoints": [{"endpoint_id": "bus", "function": "memory_master", "module": "renamed_initiator", "protocol": list(key), "fields": [{"role": role, "aliases": [port]} for role, port in [("clock", "clk"), ("reset", "rst"), ("monitor", "monitor"), *((f.field_id, "wire_" + f.field_id) for f in plugin.fields)]]}]})
    components = ComponentCatalog((PeripheralProfile("device", "device", (key,), 256, 256, False, (), "implemented", ("target.sv",), True, {}),))
    return plan_generic_composition(GenericCompositionRequest(description, ("device",), (key,)), base_dir=root, component_catalog=components, protocol_catalog=catalog)


class NativeProtocolCompositionTests(unittest.TestCase):
    def test_cpu_metadata_is_hashed_without_changing_legacy_document(self):
        from myfuzz.isa.model import CpuProfile
        from myfuzz.composition.auto import _cpu_document
        from myfuzz.composition.auto import content_hash as canonical_ir_hash
        cpu = CpuProfile("test", "test", (32,), ("I",), (), (), "reference-only", (), False)
        legacy = _cpu_document(cpu)
        self.assertNotIn("interface_description", legacy)
        self.assertNotIn("source_locator", legacy)
        annotated = replace(cpu, interface_description="cpu/interface.json", source_locator={"files": ("cpu.sv",), "revision": "test"})
        doc = _cpu_document(annotated)
        self.assertEqual(doc["source_locator"]["files"], ["cpu.sv"])
        self.assertNotEqual(canonical_ir_hash(legacy), canonical_ir_hash(doc))
        self.assertNotEqual(canonical_ir_hash(doc), canonical_ir_hash(_cpu_document(replace(annotated, interface_description="other.json"))))
        self.assertNotEqual(canonical_ir_hash(doc), canonical_ir_hash(_cpu_document(replace(annotated, source_locator={"files": ["other.sv"]}))))

    def test_native_top_publication(self):
        for key in (("apb", "3"), ("apb", "4"), ("wishbone", "classic")):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                plan = native_plan(root, key)
                write_generic_composition(plan, root / "out", base_dir=root)
                self.assertIn("native_", plan.ir["adapters"][0]["contract"]["mode"])
                self.assertTrue((root / "out" / "generic_composition_top.sv").is_file())

    def test_rejects_unknown_channels_and_pipelined_features(self):
        for key in (("apb", "3"), ("wishbone", "classic")):
            plugin = catalog_for(key).require(*key)
            for bad in (replace(plugin, fields=plugin.fields + (replace(plugin.fields[0], field_id="unknown"),)),
                        replace(plugin, capability_limits=plugin.capability_limits + (("coherence", True),)),
                        replace(plugin, channel_relations=(replace(plugin.channel_relations[0], kind="unknown"),))):
                with self.assertRaises(AutoCompositionError):
                    _generic_adapter_contract(key, ProtocolCatalog((bad,)))
        with self.assertRaises(AutoCompositionError):
            _generic_adapter_contract(("axi4", "1"), builtin_protocol_catalog())
        wb = catalog_for(("wishbone", "classic")).require("wishbone", "classic")
        pipelined = replace(wb, capability_limits=tuple((k, True if k == "stall_supported" else v) for k, v in wb.capability_limits))
        with self.assertRaises(AutoCompositionError):
            _generic_adapter_contract(("wishbone", "classic"), ProtocolCatalog((pipelined,)))

    def test_native_bound_respects_strictest_temporal_rule(self):
        for key in (("apb", "3"), ("apb", "4"), ("wishbone", "classic")):
            plugin = catalog_for(key).require(*key)
            plugin = replace(plugin, temporal_rules=(replace(plugin.temporal_rules[0], max_cycles=1), *plugin.temporal_rules[1:]))
            self.assertEqual(_generic_adapter_contract(key, ProtocolCatalog((plugin,)))["max_wait_cycles"], 1)

    @unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"), "Icarus required")
    def test_native_wait_error_timeout_and_abort(self):
        for key in (("apb", "3"), ("apb", "4"), ("wishbone", "classic")):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                route = _generic_routes(native_plan(root, key))[0]
                tag = f"{canonical_id('generic-render-route', str(route['component_id'])):016x}"
                declarations, connections = [], [".clock(clock)", ".reset(reset)", ".component_select(selected)"]
                for f in route["fields"]:
                    name = f["field_id"]
                    hashed = f"f_{canonical_id('generic-render-field', name):016x}"
                    for prefix in (("source", "target") if f["direction"] == "input" else ("target", "response")):
                        driven = prefix == "source" or (prefix == "target" and f["direction"] == "output")
                        declarations.append(f"logic [{f['width']-1}:0] {prefix}_{name}" + (" = 0;" if driven else ";"))
                        connections.append(f".{prefix}_{hashed}({prefix}_{name})")
                if key[0] == "apb":
                    stimulus = """source_paddr = 16'h104; source_pwdata = 32'h12345678; source_pwrite = 1;
source_psel = 1; source_penable = 0; tick();
if (!target_psel || target_penable || target_paddr != 4) $fatal(1,"APB setup");
source_penable = 1; tick();
if (!target_psel || !target_penable) $fatal(1,"APB access");
repeat (3) begin if(response_pready) $fatal(1,"early ready"); tick(); end
target_prdata = 32'habcdef01; target_pready = 1; #1;
if (!response_pready || response_prdata != 32'habcdef01) $fatal(1,"APB response");
tick(); source_penable = 0; target_pready = 0; tick(); source_penable = 1; tick();
target_pslverr = 1; target_pready = 1; #1;
if (!response_pslverr || !response_pready) $fatal(1,"APB error");
tick(); source_penable = 0; target_pready = 0; target_pslverr = 0; tick(); source_penable = 1; tick();
repeat (20) begin if (response_pready && response_pslverr) seen = 1; tick(); end
if (!seen || target_psel) $fatal(1,"APB timeout");
source_psel = 0; source_penable = 0; tick();
source_psel = 1; tick(); source_psel = 0; tick();
if (target_psel || response_pready) $fatal(1,"APB abort");
"""
                else:
                    stimulus = """source_adr = 16'h104; source_dat_w = 32'h12345678; source_cyc = 1; source_stb = 1; tick();
if (!target_cyc || !target_stb || target_adr != 4) $fatal(1,"WB request");
repeat(3) begin if (response_ack || response_err) $fatal(1,"WB early response"); tick(); end
target_dat_r = 32'habcdef01; target_ack = 1; #1;
if (!response_ack || response_err || response_dat_r != 32'habcdef01) $fatal(1,"WB ack");
tick(); source_cyc = 0; source_stb = 0; target_ack = 0; tick();
source_cyc = 1; source_stb = 1; tick(); target_err = 1; #1;
if (!response_err || response_ack) $fatal(1,"WB err");
tick(); source_cyc = 0; source_stb = 0; target_err = 0; tick();
source_cyc = 1; source_stb = 1; tick();
repeat(20) begin if (response_err && !response_ack) seen = 1; tick(); end
if (!seen || target_cyc || target_stb) $fatal(1,"WB timeout");
source_cyc = 0; source_stb = 0; tick(); source_cyc = 1; source_stb = 1; tick(); source_cyc = 0; #1;
if(target_cyc || response_ack || response_err) $fatal(1,"WB abort"); tick();
"""
                bench = "module tb; logic clock=0, reset=0, selected=1; integer seen=0; " + "\n".join(declarations) + f"\nmyfuzz_generic_adapter_{tag} #(.ADDRESS_BASE(16'h100)) dut(" + ",".join(connections) + ");\n task tick; begin #5; clock=1; #5; clock=0; end endtask\ninitial begin tick(); reset=1; tick();\n" + stimulus + '\n$display("PASS"); $finish; end endmodule\n'
                (root / "sim.sv").write_text(_render_generic_adapter(route) + bench)
                compiled = subprocess.run(["iverilog", "-g2012", "-s", "tb", "-o", str(root / "sim"), str(root / "sim.sv")], capture_output=True, text=True, timeout=20)
                self.assertEqual(compiled.returncode, 0, compiled.stderr)
                result = subprocess.run(["vvp", str(root / "sim")], capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("PASS", result.stdout)
