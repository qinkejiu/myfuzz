"""Reproducible, sequential RTL campaigns for generated native compositions.

The bundled traffic source is a synthetic bus exerciser, not a RISC-V CPU.
Register-bank peripherals are validation fixtures, not production IP profiles.
"""
from itertools import combinations
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import time

from myfuzz.composition import GenericCompositionRequest, load_interface_description, plan_generic_composition, source_tree_hash, write_generic_composition
from myfuzz.composition.protocol_composer import _generic_port_records, _generic_routes
from myfuzz.components.catalog import ComponentCatalog
from myfuzz.components.model import PeripheralProfile
from myfuzz.protocols.catalog import load_protocol_catalog
from .campaign import CampaignOptions, CampaignLimits, run_supervised_command

DEMO_PROTOCOLS = {"apb3_register": ("apb", "3"), "apb4_register": ("apb", "4"), "wishbone_register": ("wishbone", "classic")}


def select_combinations(seed: int, count: int = 3) -> tuple[tuple[str, ...], ...]:
    if type(seed) is not int or seed < 0 or type(count) is not int or not 1 <= count <= 4:
        raise ValueError("nonnegative seed and count in [1,4] required")
    pool = [item for size in (2, 3) for item in combinations(DEMO_PROTOCOLS, size)]
    return tuple(random.Random(seed).sample(pool, count))


def prepare_demo(root: Path, selected: tuple[str, ...]):
    """Materialize pinned local fixture RTL, then use the production planner."""
    root.mkdir(parents=True, exist_ok=False)
    if len(set(selected)) != len(selected) or not selected or any(item not in DEMO_PROTOCOLS for item in selected):
        raise ValueError("invalid demo combination")
    source_root = root / "source"
    source_root.mkdir()
    catalog = load_protocol_catalog(Path(__file__).parents[1] / "protocols/plugins")
    ports = ["input logic clk", "input logic rst", "input logic [31:0] stimulus", "output logic [31:0] transaction_count", "output logic [31:0] failure_count"]
    blocks, endpoints, profiles = [], [], []
    for index, name in enumerate(selected):
        key = DEMO_PROTOCOLS[name]
        plugin = catalog.require(*key)
        fields = tuple(f for f in plugin.fields if f.field_id != "stall")
        def width(f):
            return {"1": 1, "3": 3, "address_width": 16, "data_width": 32, "data_width / 8": 4}[f.width_expression]
        for field in fields:
            direction = "output" if field.direction == "host_to_device" else "input"
            ports.append(f"{direction} logic [{width(field)-1}:0] b{index}_{field.field_id}")
        prefix = f"b{index}_"
        apb = key[0] == "apb"
        addr, data, rdata, write, ready, error = (("paddr", "pwdata", "prdata", "pwrite", "pready", "pslverr") if apb else ("adr", "dat_w", "dat_r", "we", "ack", "err"))
        active = 2 if apb else 1
        assignments = [f"assign {prefix}{addr} = 16'h{index * 256:04x};", f"assign {prefix}{data} = value_{index};", f"assign {prefix}{write} = writing_{index};"]
        if apb:
            assignments += [f"assign {prefix}psel = state_{index} == 1 || state_{index} == 2;", f"assign {prefix}penable = state_{index} == 2;"]
            if key[1] == "4":
                assignments += [f"assign {prefix}pstrb = 4'hf;", f"assign {prefix}pprot = 0;"]
        else:
            assignments += [f"assign {prefix}cyc = state_{index} == 1;", f"assign {prefix}stb = state_{index} == 1;", f"assign {prefix}sel = 4'hf;"]
        blocks.append(f"""
logic [1:0] state_{index}; logic writing_{index};
logic [31:0] value_{index}, done_{index}, bad_{index};
{' '.join(assignments)}
always_ff @(posedge clk or negedge rst) begin
 if (!rst) begin state_{index} <= 0; writing_{index} <= 1; value_{index} <= 0; done_{index} <= 0; bad_{index} <= 0; end
 else case (state_{index})
 0: begin if(writing_{index}) value_{index} <= stimulus; state_{index} <= 1; end
 {('1: state_' + str(index) + ' <= 2;') if apb else ''}
 {active}: if ({prefix}{ready} || {prefix}{error}) begin
   done_{index} <= done_{index} + 1;
   if ({prefix}{error} || (!writing_{index} && {prefix}{rdata} != value_{index})) bad_{index} <= bad_{index} + 1;
   writing_{index} <= !writing_{index}; state_{index} <= 3;
 end
 3: state_{index} <= 0;
 default: state_{index} <= 0;
 endcase
end
""")
        hints = [{"role": "clock", "aliases": ["clk"]}, {"role": "reset", "aliases": ["rst"]}]
        hints += [{"role": f.field_id, "aliases": [prefix + f.field_id]} for f in fields]
        endpoints.append({"endpoint_id": name, "function": "memory_master", "module": "traffic_source", "protocol": list(key), "fields": hints})
        target_ports = ["input logic clock", "input logic reset"]
        for f in fields:
            direction = "input" if f.direction == "host_to_device" else "output"
            target_ports.append(f"{direction} logic [{width(f)-1}:0] {f.field_id}")
        transfer = "psel && penable" if apb else "cyc && stb"
        target = f"""module {name}({', '.join(target_ports)});
logic [31:0] stored; logic [2:0] waiting;
assign {ready} = ({transfer}) && waiting >= 2;
assign {error} = 0;
assign {rdata} = stored;
always_ff @(posedge clock or negedge reset) begin
 if(!reset) begin stored <= 0; waiting <= 0; end
 else begin
  if(!({transfer})) waiting <= 0;
  else if(waiting < 2) waiting <= waiting + 1;
  if(({transfer}) && {ready} && {write}) stored <= {data};
 end
end
endmodule
"""
        (root / f"{name}.sv").write_text(target)
        profiles.append(PeripheralProfile(name, name, (key,), 256, 256, False, (), "implemented", (f"{name}.sv",), True, {}))
    blocks += ["assign transaction_count = " + " + ".join(f"done_{i}" for i in range(len(selected))) + ";", "assign failure_count = " + " + ".join(f"bad_{i}" for i in range(len(selected))) + ";"]
    source = source_root / "traffic.sv"
    source.write_text("module traffic_source(" + ",\n".join(ports) + ");\n" + "\n".join(blocks) + "\nendmodule\n")
    endpoints.append({"endpoint_id": "control", "function": "control", "module": "traffic_source", "fields": [{"role": r, "aliases": [p]} for r, p in (("stimulus", "stimulus"), ("transaction_count", "transaction_count"), ("failure_count", "failure_count"))]})
    document = {"schema_version": "interface_description.v1", "source": {"root": "source", "top_module": "traffic_source", "files": ["traffic.sv"], "revision": source_tree_hash(source_root, (source,))}, "endpoints": endpoints}
    (root / "interface.json").write_text(json.dumps(document, indent=2))
    plan = plan_generic_composition(GenericCompositionRequest(load_interface_description(document), selected), base_dir=root, component_catalog=ComponentCatalog(tuple(profiles)), protocol_catalog=catalog)
    artifact = write_generic_composition(plan, root / "generated", base_dir=root)
    internal = frozenset(f["source_port"] for a in _generic_routes(plan) for f in a["fields"])
    mapping = {r["source_port"]: r["opaque_port"] for r in _generic_port_records(plan, internal_ports=internal)}
    connections = ",".join(f".{opaque}({name})" for name, opaque in mapping.items())
    bench = f"""module campaign_tb;
logic clk=0, rst=0; logic [31:0] stimulus=1;
wire [31:0] transaction_count, failure_count;
integer seed, unused, i;
generic_composition_top dut({connections});
task tick; begin #5; clk=1; #5; clk=0; end endtask
initial begin
 seed=1; unused=$value$plusargs("seed=%d",seed); stimulus=seed;
 tick(); tick(); rst=1;
 for(i=0;i<4096;i=i+1) begin
  stimulus = stimulus ^ (stimulus << 13); stimulus = stimulus ^ (stimulus >> 17); stimulus = stimulus ^ (stimulus << 5);
  tick();
 end
 $display("RESULT %0d %0d",transaction_count,failure_count);
 if(failure_count != 0 || transaction_count < 100) $fatal(1,"scoreboard/progress failure");
 $finish;
end
endmodule
"""
    (root / "campaign_tb.sv").write_text(bench)
    executable = root / "simulation.vvp"
    command = ["iverilog", "-g2012", "-s", "campaign_tb", "-o", str(executable), *(str(root / p) for p in plan.source_files), artifact["top_path"], str(root / "campaign_tb.sv")]
    compiled = subprocess.run(command, capture_output=True, text=True, timeout=60)
    (root / "build.log").write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        raise RuntimeError("RTL compilation failed: " + compiled.stderr[-2000:])
    return plan, executable


def worker(executable: Path, seed: int):
    """Fresh seed per real 4096-cycle simulation, supervised as one process group."""
    rng = random.Random(seed)
    while True:
        batch_seed = rng.randrange(1, 2**31)
        result = subprocess.run(["vvp", str(executable), f"+seed={batch_seed}"], capture_output=True, text=True, timeout=15)
        lines = [line.split() for line in result.stdout.splitlines() if line.startswith("RESULT ")]
        if result.returncode or len(lines) != 1 or len(lines[0]) != 3:
            print(json.dumps({"transactions": 0, "error": 1}), flush=True)
            raise RuntimeError(f"RTL seed {batch_seed} failed: {result.stdout[-2000:]} {result.stderr[-2000:]}")
        transactions, failures = map(int, lines[0][1:])
        if failures or transactions < 100:
            raise RuntimeError(f"scoreboard failure at seed {batch_seed}")
        print(json.dumps({"transactions": transactions, "component": executable.parent.name, "error": 0}), flush=True)
        time.sleep(0.05)


def run_demo_campaign(output: Path, *, seed: int, seconds: int = 300, count: int = 3):
    if type(seconds) is not int or seconds <= 0:
        raise ValueError("positive simulation duration required")
    selected = select_combinations(seed, count)
    if output.exists():
        raise ValueError("campaign output must be new")
    output.mkdir(parents=True)
    metadata = {"schema_version": "generic_rtl_campaign.v1", "seed": seed, "seconds_per_combination": seconds,
                "selected": selected, "execution_kind": "synthetic_bus_source_and_register_bank_RTL", "riscv_cpu_execution": False,
                "rfuzz_execution": False, "workers": 1, "waveforms": False, "results": []}
    report = output / "campaign.json"
    def persist():
        report.write_text(json.dumps(metadata, indent=2))
    persist()
    missing = [tool for tool in ("iverilog", "vvp") if shutil.which(tool) is None]
    if missing:
        metadata.update(status="dependency-unavailable", missing=missing)
        persist()
        return metadata
    for index, selection in enumerate(selected):
        case = output / f"combination_{index+1}"
        plan, executable = prepare_demo(case, selection)
        # Check a real batch before allocating the 300-second campaign budget.
        check = subprocess.run(["vvp", str(executable), f"+seed={seed % (2**31-1) or 1}"], capture_output=True, text=True, timeout=15)
        (case / "preflight.log").write_text(check.stdout + check.stderr)
        if check.returncode or "RESULT " not in check.stdout:
            raise RuntimeError(f"RTL preflight failed: {case}")
        result = run_supervised_command(CampaignOptions(
            command=(sys.executable, "-m", "myfuzz.integration.generic_rtl_campaign", "worker", str(executable), str(seed + index)),
            output_dir=case / "runtime", duration_seconds=seconds, seed=seed + index, checkpoint_seconds=10,
            limits=CampaignLimits(max_restarts=0), env={"PYTHONPATH": str(Path(__file__).resolve().parents[2]), "JOBS": "1"},
            composition_hash=plan.composition_ir_hash,
        ))
        result_document = dict(result)
        (case / "runtime/result.json").write_text(json.dumps(result_document, indent=2))
        successful = (result.get("status") == "timed-out" and result.get("duration_seconds", 0) >= seconds
                      and result.get("transactions", 0) > 0 and result.get("errors", 1) == 0
                      and result.get("invalid_metric_lines", 1) == 0 and not result.get("soft_limit_exceeded"))
        metadata["results"].append({"combination": selection, "passed": successful,
                                    "result": {k: v for k, v in result_document.items() if k != "metrics"}})
        persist()
        if not successful:
            metadata["status"] = "failed"
            persist()
            return metadata
    metadata["status"] = "finished"
    persist()
    return metadata


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "worker":
        worker(Path(sys.argv[2]), int(sys.argv[3]))
    else:
        raise SystemExit("Use scripts/run_generic_rtl_campaign.py")
