"""Execute the generated processor request path with a source-backed RTL initiator."""

from __future__ import annotations

from dataclasses import dataclass
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from myfuzz.components.catalog import ComponentCatalog
from myfuzz.components.model import PeripheralProfile
from myfuzz.composition import (
    GenericCompositionRequest,
    load_interface_description,
    plan_generic_composition,
    source_tree_hash,
    write_generic_composition,
)
from myfuzz.composition.ids import canonical_id
from myfuzz.composition.processor_adapters import ProcessorAdapterDefinition
from myfuzz.protocols.catalog import load_protocol_catalog
from myfuzz.integration import rfuzz_simulator


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/fixtures/rtl/generic_processor"
PROTOCOLS = (("obi", "1"), ("axi4", "1"), ("tl-ul", "1"))
WIDTHS = {
    "address_width": 32,
    "data_width": 32,
    "id_width": 4,
    "source_width": 1,
    "sink_width": 1,
    "user_width": 3,
}


@dataclass(frozen=True)
class RunMetrics:
    accepted: int
    completions: int
    readback: int
    errors: int
    cycles: int
    exit_reason: str


def _adapter_for(protocol: tuple[str, str]) -> ProcessorAdapterDefinition:
    # Resolve through the public behavior table without coupling the fixture to
    # any processor, module, or endpoint identity.
    from myfuzz.composition import processor_adapters

    return processor_adapters._ADAPTERS[protocol]


def _physical_port(protocol: tuple[str, str], role: str, direction: str) -> str:
    prefix = {"obi": "obi", "axi4": "axi", "tl-ul": "tl"}[protocol[0]]
    return f"{prefix}_{role}_{'o' if direction == 'output' else 'i'}"


def _endpoint_fields(protocol: tuple[str, str], catalog) -> tuple[list[dict[str, object]], set[str]]:
    plugin = catalog.require(*protocol)
    adapter = _adapter_for(protocol)
    fields: list[tuple[str, str]] = [
        (field.field_id, "output" if field.direction == "host_to_device" else "input")
        for field in plugin.fields
    ]
    roles = {role for role, _ in fields}
    for policy in adapter.extension_policies:
        if policy.role not in roles:
            fields.append((policy.role, policy.direction))
            roles.add(policy.role)
    return ([
        {"role": role, "aliases": [_physical_port(protocol, role, direction)]}
        for role, direction in fields
    ], { _physical_port(protocol, role, direction) for role, direction in fields if direction == "input" })


def _make_plan(root: Path, protocol: tuple[str, str]):
    source_root = root / "source"
    source_root.mkdir()
    processor = source_root / "generic_processor_fixture.sv"
    ram = root / "generic_processor_ram.sv"
    shutil.copyfile(FIXTURE / processor.name, processor)
    shutil.copyfile(FIXTURE / ram.name, ram)

    catalog = load_protocol_catalog(ROOT / "src/myfuzz/protocols/plugins")
    adapter = _adapter_for(protocol)
    adapter_source = root / adapter.rtl_source
    adapter_source.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / adapter.rtl_source, adapter_source)
    memory_fields, response_ports = _endpoint_fields(protocol, catalog)
    description = load_interface_description({
        "schema_version": "interface_description.v1",
        "source": {
            "root": "source",
            "revision": source_tree_hash(source_root, (processor,)),
            "top_module": "generic_processor_fixture",
            "files": [processor.name],
            "elaboration": {"frontend": "verilator-json"},
        },
        "endpoints": [
            {"endpoint_id": "fixture.clock", "function": "clock",
             "module": "generic_processor_fixture",
             "fields": [{"role": "clock", "aliases": ["clk_i"]}]},
            {"endpoint_id": "fixture.reset", "function": "reset",
             "module": "generic_processor_fixture",
             "fields": [{"role": "reset", "aliases": ["rst_ni"]}]},
            {"endpoint_id": "fixture.request", "function": "processor_memory_master",
             "module": "generic_processor_fixture", "protocol": list(protocol),
             "clock": "clk_i", "reset": "rst_ni", "fields": memory_fields},
            {"endpoint_id": "fixture.status", "function": "observation",
             "module": "generic_processor_fixture", "fields": [
                 {"role": "random_input", "aliases": ["random_i"]},
                 {"role": "done", "aliases": ["done_o"]},
                 {"role": "accepted", "aliases": ["accepted_o"]},
                 {"role": "completions", "aliases": ["completions_o"]},
                 {"role": "readback", "aliases": ["readback_o"]},
                 {"role": "errors", "aliases": ["errors_o"]},
                 {"role": "cycles", "aliases": ["cycles_o"]},
             ]},
        ],
    })
    components = ComponentCatalog((PeripheralProfile(
        "fixture-memory", "generic_processor_ram", (("processor-memory-beat", "1"),),
        4, 0x100, False, (), "implemented", (ram.name,), True, {},
        protocol_features={("processor-memory-beat", "1"): ("reset_flush",)},
    ),))
    plan = plan_generic_composition(
        GenericCompositionRequest(description, ("fixture-memory",)),
        base_dir=root, component_catalog=components, protocol_catalog=catalog,
    )
    return plan, response_ports


def _top_port(endpoint: str, role: str, port: str) -> str:
    return f"p_{canonical_id('generic-top-port', f'{endpoint}:{role}:{port}'):016x}"


def _compile_and_simulate(output: Path) -> RunMetrics:
    ports = {
        "clock": _top_port("fixture.clock", "clock", "clk_i"),
        "reset": _top_port("fixture.reset", "reset", "rst_ni"),
        "random": _top_port("fixture.status", "random_input", "random_i"),
        "done": _top_port("fixture.status", "done", "done_o"),
        "source_accepted": _top_port("fixture.status", "accepted", "accepted_o"),
        "source_completions": _top_port("fixture.status", "completions", "completions_o"),
        "readback": _top_port("fixture.status", "readback", "readback_o"),
        "source_errors": _top_port("fixture.status", "errors", "errors_o"),
        "source_cycles": _top_port("fixture.status", "cycles", "cycles_o"),
    }
    connections = ",".join(f".{port}({name})" for name, port in ports.items())
    bench = f"""
module tb;
  logic clock=0, reset=0; logic [7:0] random=0;
  wire done; wire [7:0] source_accepted, source_completions, source_errors;
  wire [31:0] readback; wire [15:0] source_cycles;
  integer accepted=0, completions=0, errors=0, cycles=0;
  always #1 clock=~clock;
  generic_composition_top dut({connections});
  task fail_metrics(input [8*40-1:0] reason);
    begin
      $display("METRICS accepted=%0d completions=%0d readback=%08x errors=%0d cycles=%0d exit=%0s", accepted, completions, readback, errors + source_errors, source_cycles, reason);
      $fatal(1,"processor fixture integrity failure: %0s", reason);
    end
  endtask
  always @(posedge clock) if (reset) begin
    cycles <= cycles + 1;
    random <= random + 8'h5b;
    if (dut.backend_target_req_valid && dut.backend_target_req_ready)
      accepted <= accepted + 1;
    if (dut.backend_target_rsp_valid && dut.backend_target_rsp_ready) begin
      completions <= completions + 1;
      if (dut.backend_target_error) errors <= errors + 1;
    end
  end
  initial begin
    repeat(3) @(negedge clock); reset=1;
    while (!done && cycles < 160) @(negedge clock);
    if (!done) begin
      $display("METRICS accepted=%0d completions=%0d readback=%08x errors=%0d cycles=%0d exit=timeout", accepted, completions, readback, errors + source_errors, cycles);
      $fatal(1,"processor fixture stalled");
    end
    repeat(2) @(posedge clock);
    if (accepted != 4) fail_metrics("backend_accepted_count");
    if (completions != 4) fail_metrics("backend_completion_count");
    if (source_accepted != 4) fail_metrics("source_accepted_count");
    if (source_completions != 4) fail_metrics("source_completion_count");
    if (errors != 0) fail_metrics("backend_error");
    if (source_errors != 0) fail_metrics("source_error");
    if (readback != 32'haabb3344) fail_metrics("readback_corrupt");
    $display("METRICS accepted=%0d completions=%0d readback=%08x errors=%0d cycles=%0d exit=done", accepted, completions, readback, errors + source_errors, source_cycles);
    $finish;
  end
endmodule
"""
    (output / "connected_tb.sv").write_text(bench, encoding="utf-8")
    compile_result = subprocess.run(
        ("iverilog", "-g2012", "-s", "tb", "-o", "connected_sim", "-f", "sources.f", "connected_tb.sv"),
        cwd=output, capture_output=True, text=True, timeout=30, check=False,
    )
    if compile_result.returncode:
        raise AssertionError("compile failed:\n" + compile_result.stdout + compile_result.stderr)
    simulate_result = subprocess.run(
        ("vvp", "connected_sim"), cwd=output, capture_output=True, text=True,
        timeout=30, check=False,
    )
    if simulate_result.returncode:
        raise AssertionError("simulate failed:\n" + simulate_result.stdout + simulate_result.stderr)
    match = re.search(
        r"METRICS accepted=(\d+) completions=(\d+) readback=([0-9a-fA-F]+) "
        r"errors=(\d+) cycles=(\d+) exit=([a-z_]+)", simulate_result.stdout,
    )
    if match is None:
        raise AssertionError("missing simulator metrics:\n" + simulate_result.stdout)
    return RunMetrics(
        int(match.group(1)), int(match.group(2)), int(match.group(3), 16),
        int(match.group(4)), int(match.group(5)), match.group(6),
    )


@unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp") and shutil.which("verilator"),
                     "Icarus and Verilator are required")
class ConnectedProcessorFixtureTests(unittest.TestCase):
    def test_generated_complete_request_path_executes_for_each_processor_protocol(self) -> None:
        for protocol in PROTOCOLS:
            with self.subTest(protocol=protocol), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                plan, response_ports = _make_plan(root, protocol)

                # RFuzz may project the unrelated random input, but every
                # adapter-driven source response must remain internally owned.
                runtime_ports, _, _, _, layout, _ = rfuzz_simulator._runtime_boundary(plan, root)
                self.assertEqual([field.port for field in layout.fields], ["random_i"])
                self.assertTrue(response_ports.isdisjoint(runtime_ports))

                output = root / "published"
                write_generic_composition(plan, output, base_dir=root)
                metrics = _compile_and_simulate(output)
                self.assertEqual(metrics.accepted, 4)
                self.assertEqual(metrics.completions, 4)
                self.assertEqual(metrics.readback, 0xAABB3344)
                self.assertEqual(metrics.errors, 0)
                self.assertLess(metrics.cycles, 160)
                self.assertEqual(metrics.exit_reason, "done")


if __name__ == "__main__":
    unittest.main()
