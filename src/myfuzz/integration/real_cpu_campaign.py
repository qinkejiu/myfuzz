"""Data-driven real CPU campaigns, retained builds, and independent replay."""
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import random

from myfuzz.components.catalog import ComponentCatalog
from myfuzz.components.model import PeripheralProfile, ParameterSpec
from myfuzz.composition import GenericCompositionRequest, load_interface_description, plan_generic_composition
from myfuzz.composition.contract_transducer import compile_contract_transducer
from myfuzz.composition.cycle_input import TestHeader
from myfuzz.contracts import canonical_bytes
from myfuzz.isa.constraints import IsaContract
from myfuzz.protocols.catalog import load_protocol_catalog
from .riscv_execution import RiscvExecutionProvenance
from .rfuzz_simulator import RtlSimulator, build_simulator
from .rfuzz_live import run_live, replay_corpus


def digest(value):
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def publish(path, value):
    path.write_bytes(canonical_bytes(value))


def build_candidate(root, output, config, personality):
    root, output = Path(root).resolve(), Path(output).resolve()
    if config.get("input_mode") != "contract_transducer":
        raise ValueError("real CPU candidates require input_mode=contract_transducer")
    output.mkdir(parents=True, exist_ok=False)
    document = json.loads((root / config["interface"]).read_text())
    for endpoint in document["endpoints"]:
        for field in endpoint["fields"]:
            if f"{endpoint['endpoint_id']}:{field['role']}" in config["randomizable_fields"]:
                field["randomizable"] = True
    description = load_interface_description(document)
    peripheral = PeripheralProfile(
        personality["name"], personality["module"], (("processor-memory-beat", "1"),),
        4096, 4096, False, (), "implemented", (personality["source"],), True, {},
        protocol_features={("processor-memory-beat", "1"): ("reset_flush",)},
        parameters={"MODE": ParameterSpec("MODE", "integer", personality["mode"])},
    )
    isa = IsaContract(**{**config["isa_contract"], "extensions": tuple(config["isa_contract"]["extensions"])})
    plan = plan_generic_composition(
        GenericCompositionRequest(description, (peripheral.component_type,),
                                  isa=isa, seed=config.get("composition_seed", 0)),
        base_dir=root, component_catalog=ComponentCatalog((peripheral,)),
        protocol_catalog=load_protocol_catalog(root / "src/myfuzz/protocols/plugins"),
    )
    provenance = RiscvExecutionProvenance(
        source_identity=description.source.source_root,
        source_hash="sha256:" + plan.source_evidence_hash.removeprefix("sha256:"),
        profile_identity=config["id"], profile_hash=digest(config),
        interface_identity=config["interface"], interface_hash=digest(document),
        isa=config["isa"], xlen=isa.xlen, reset_vector=config["reset_vector"],
    )
    randomizable = frozenset(config["randomizable_fields"])
    external = {field.field_id: field.width for field in plan.layout.fields
                if field.field_id in randomizable}
    if set(external) != randomizable:
        raise ValueError("randomizable fields must bind declared physical inputs")
    transducer = compile_contract_transducer(
        isa=isa, protocol=("processor-memory-beat", "1"), address_width=32, data_width=32,
        memory_domains=config["memory_domains"], external_inputs=external, allow_error=False,
    )
    header = TestHeader(
        schema_version="cycle_test.v1", layout_hash=transducer.cycle_layout.layout_hash,
        contract_hash=transducer.contract_hash, **config["test_header"],
    )
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
        contract_transducer=transducer, test_header=header,
        simulator="verilator", isolate_tests=False,
        execution_monitor={"mode": "contract_transducer",
                           "memory_capacity_entries": transducer.memory_capacity_entries},
    )
    records = (artifact.transport.pack(0),) * config["probe_cycles"]
    with RtlSimulator(artifact) as simulator:
        first = simulator.run_test(records)
        execution = dict(simulator.last_execution)
        second = simulator.run_test(records)
        if first != second or execution != simulator.last_execution:
            raise ValueError("real CPU probe replay mismatch")
    if not (execution["instruction_requests"] > 0
            and execution["instruction_responses"] > 0
            and execution["instruction_initializations"] >= 2
            and execution["errors"] == 0):
        raise ValueError(f"real CPU contract execution acceptance failed: {execution}")
    proof = {"status": "passed", "cpu_config": config, "peripheral": personality,
             "provenance": asdict(provenance), "execution": execution,
             "composition_hash": plan.composition_ir_hash, "layout_hash": artifact.layout.layout_hash,
             "constraint_hash": artifact.projector.constraint_hash,
             "transducer_hash": artifact.transducer_hash, "header_hash": artifact.header_hash,
             "implementation_hash": artifact.implementation_hash,
             "test_header": asdict(header), "coverage": list(first),
             "instruction_source": "rfuzz_contract_transducer",
             "progress_kind": "distinct first-time instruction-address initializations",
             "peripheral_execution": "fixed targets disabled in contract mode",
             "probe_input": "zero-valued RFuzz cycle records",
             "replay": "equal coverage and execution after two test_begin resets"}
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
                    or result.get("execution_totals", {}).get("instruction_initializations", 0) < 2):
                raise ValueError("campaign lacks duration, new corpus, or instruction progress")
            rebuilt, replay_proof = build_candidate(root, work / "rebuild", config, personality)
            replay = replay_corpus(rebuilt, work / "live/corpus")
            original = result["corpus_manifest"]["replays"]
            for fresh, saved in zip(replay["replays"], original, strict=True):
                for key in ("input_sha256", "layout_hash", "constraint_hash",
                            "physical_controls_sha256", "simulator_inputs_sha256", "transducer_hash", "header_hash", "implementation_hash"):
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
