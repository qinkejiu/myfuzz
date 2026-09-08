"""Data-driven real CPU campaigns, retained builds, and independent replay."""
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import random

from myfuzz.components.catalog import ComponentCatalog
from myfuzz.components.model import PeripheralProfile, ParameterSpec
from myfuzz.composition import GenericCompositionRequest, load_interface_description, plan_generic_composition
from myfuzz.contracts import canonical_bytes
from myfuzz.isa.constraints import IsaContract
from myfuzz.protocols.catalog import load_protocol_catalog
from .riscv_execution import RiscvExecutionFacts, RiscvExecutionProvenance, build_minimal_boot_image
from .rfuzz_simulator import RtlSimulator, build_simulator
from .rfuzz_live import run_live, replay_corpus


def digest(value):
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def publish(path, value):
    path.write_bytes(canonical_bytes(value))


def build_candidate(root, output, config, personality):
    root, output = Path(root).resolve(), Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    document = json.loads((root / config["interface"]).read_text())
    for endpoint in document["endpoints"]:
        for field in endpoint["fields"]:
            if f"{endpoint['endpoint_id']}:{field['role']}" in config["randomizable_fields"]:
                field["randomizable"] = True
    description = load_interface_description(document)
    memory = PeripheralProfile(
        "boot-memory", config["memory_module"], (("processor-memory-beat", "1"),),
        4096, 4096, False, (), "implemented",
        ("src/myfuzz/integration/rtl/riscv_boot_memory.sv",), True, {},
        protocol_features={("processor-memory-beat", "1"): ("reset_flush",)},
    )
    peripheral = PeripheralProfile(
        personality["name"], personality["module"], (("processor-memory-beat", "1"),),
        4096, 4096, False, (), "implemented", (personality["source"],), True, {},
        protocol_features={("processor-memory-beat", "1"): ("reset_flush",)},
        parameters={"MODE": ParameterSpec("MODE", "integer", personality["mode"])},
    )
    isa = IsaContract(**{**config["isa_contract"], "extensions": tuple(config["isa_contract"]["extensions"])})
    plan = plan_generic_composition(
        GenericCompositionRequest(description, (memory.component_type, peripheral.component_type),
                                  isa=isa, seed=config.get("composition_seed", 0)),
        base_dir=root, component_catalog=ComponentCatalog((memory, peripheral)),
        protocol_catalog=load_protocol_catalog(root / "src/myfuzz/protocols/plugins"),
    )
    regions = plan.ir["address_regions"]
    memory_component = next(c for c in plan.components if c["module_name"] == config["memory_module"])
    boot_region = next(r for r in regions if r["component_id"] == memory_component["component_id"])
    if boot_region["base"] != 0:
        raise ValueError("boot memory must cover the declared reset vector at address zero")
    peripheral_region = next(r for r in regions if r["component_id"] != memory_component["component_id"])
    provenance = RiscvExecutionProvenance(
        source_identity=description.source.source_root,
        source_hash="sha256:" + plan.source_evidence_hash.removeprefix("sha256:"),
        profile_identity=config["id"], profile_hash=digest(config),
        interface_identity=config["interface"], interface_hash=digest(document),
        isa=config["isa"], xlen=isa.xlen, reset_vector=config["reset_vector"],
    )
    facts = RiscvExecutionFacts(
        isa=config["isa"], xlen=isa.xlen, reset_vector=config["reset_vector"],
        pass_address=peripheral_region["base"], pass_value=0x600DCAFE,
        protocol=tuple(config["protocol"]), max_cycles=config["probe_cycles"], provenance=provenance,
    )
    boot = build_minimal_boot_image(facts, output / "boot")
    monitor = {"reset_vector": facts.reset_vector, "first_fetch_data": boot.first_fetch_data,
               "pass_address": facts.pass_address, "pass_value": facts.pass_value}
    randomizable = frozenset(config["randomizable_fields"])
    coverage_inputs = tuple(
        (field.port, bit)
        for field in plan.layout.fields
        if field.field_id in randomizable
        for bit in range(field.width)
    )
    if not coverage_inputs:
        raise ValueError("campaign requires explicitly randomizable RTL input observations")
    artifact = build_simulator(
        plan, output / "sim", base_dir=root, coverage_ports=(),
        coverage_inputs=coverage_inputs,
        coverage_signals=(("backend_target_req_valid", 0), ("backend_target_rsp_valid", 0)),
        randomized_controls=("interrupt",), control_defaults=config["control_defaults"],
        simulator_args=(f"+riscv_boot_image={boot.memory_hex_path}",),
        simulator="verilator", isolate_tests=False, execution_monitor=monitor,
    )
    records = (artifact.transport.pack(0),) * config["probe_cycles"]
    with RtlSimulator(artifact) as simulator:
        first = simulator.run_test(records)
        execution = dict(simulator.last_execution)
        second = simulator.run_test(records)
        if first != second or execution != simulator.last_execution:
            raise ValueError("real CPU probe replay mismatch")
    if not (execution["first_fetch_matched"] and execution["progress_events"] > 1
            and execution["completions"] > 0 and execution["pass_completions"] > 0
            and execution["errors"] == 0):
        raise ValueError(f"real CPU/peripheral execution acceptance failed: {execution}")
    proof = {"status": "passed", "cpu_config": config, "peripheral": personality,
             "facts": asdict(facts), "execution": execution,
             "composition_hash": plan.composition_ir_hash, "layout_hash": artifact.layout.layout_hash,
             "boot_sha256": boot.binary_hash, "coverage": list(first),
             "progress_kind": "distinct successful memory-read addresses",
             "pass_kind": "successful peripheral write completion",
             "replay": "equal in two independent simulator processes"}
    publish(output / "execution.json", proof)
    publish(output / "interface.json", document)
    return artifact, proof


def run_campaigns(root, output, config_path, client, *, seconds=300, seed=20260908, count=3):
    if type(seconds) is not int or seconds < 300:
        raise ValueError("acceptance campaigns require at least 300 seconds")
    root, output = Path(root).resolve(), Path(output).resolve()
    config = json.loads(Path(config_path).read_text())
    pool = config["peripherals"]
    if count != 3 or len(pool) < count:
        raise ValueError("three distinct real combinations required")
    selection = random.Random(seed).sample(pool, count)
    output.mkdir(parents=True, exist_ok=False)
    manifest = {"schema_version": "real_cpu_campaigns.v1", "status": "running", "seed": seed,
                "selection_algorithm": "python random.Random(seed).sample(pool, 3)",
                "pool": pool, "selected": selection, "seconds_per_campaign": seconds, "runs": []}
    publish(output / "manifest.json", manifest)
    try:
        for index, personality in enumerate(selection):
            work = output / f"campaign-{index+1}"
            work.mkdir()
            artifact, proof = build_candidate(root, work / "build", config, personality)
            result = run_live(artifact, client, work / "live", duration_seconds=seconds,
                              seed_cycles=config["probe_cycles"])
            if (result["duration_seconds"] < seconds or result["corpus_entries"] < 2
                    or result.get("execution_totals", {}).get("pass_completions", 0) < 1):
                raise ValueError("campaign lacks duration, new corpus, or peripheral progress")
            rebuilt, replay_proof = build_candidate(root, work / "rebuild", config, personality)
            replay = replay_corpus(rebuilt, work / "live/corpus")
            original = result["corpus_manifest"]["replays"]
            for fresh, saved in zip(replay["replays"], original, strict=True):
                for key in ("input_sha256", "layout_hash", "constraint_hash",
                            "physical_controls_sha256", "simulator_inputs_sha256"):
                    if fresh[key] != saved[key]:
                        raise ValueError(f"rebuild identity changed: {key}")
            publish(work / "rebuild_replay.json", replay)
            manifest["runs"].append({"peripheral": personality["name"], "status": "passed",
                "duration_seconds": result["duration_seconds"], "tests": result["tests"],
                "corpus_entries": result["corpus_entries"], "execution": result["execution_totals"],
                "peak_rss_bytes": result["peak_rss_bytes"], "remaining_segments": result["remaining_segments"],
                "rebuild_replays": replay["entries"], "path": str(work)})
            publish(output / "manifest.json", manifest)
        manifest["status"] = "passed"
    except BaseException as error:
        manifest.update(status="failed", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        publish(output / "manifest.json", manifest)
    return manifest
