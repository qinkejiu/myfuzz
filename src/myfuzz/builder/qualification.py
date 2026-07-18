"""Frozen material qualification and preregistered Slice H acceptance gates."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import random
import statistics
from typing import Mapping, Sequence

from .input_model import InputValidationError


ORACLE_SCHEMA = "myfuzz.qualification-oracle/v1"
ACCEPTANCE_SCHEMA = "myfuzz.acceptance-report/v1"
_SPLITS = {"development", "holdout"}
_KINDS = {"cpu", "ip"}
_STATUSES = {"qualified", "rejected"}
_APPROVED_LICENSES = {
    "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MIT", "SHL-0.51",
}
_AXI_SIGNALS = {
    "clock", "reset", "awvalid", "awready", "awaddr", "wvalid", "wready", "wdata",
    "wstrb", "bvalid", "bready", "bresp", "arvalid", "arready", "araddr", "rvalid",
    "rready", "rdata", "rresp",
}


@dataclass(frozen=True)
class QualificationOracle:
    path: str
    digest: str
    data: Mapping[str, object]

    @property
    def qualified(self) -> tuple[Mapping[str, object], ...]:
        return tuple(item for item in self.data["candidates"] if item["status"] == "qualified")


def compute_oracle_digest(value: Mapping[str, object]) -> str:
    payload = dict(value)
    payload.pop("oracle_digest", None)
    return hashlib.sha256(_canonical(payload)).hexdigest()


def load_qualification_oracle(
    path: str | Path,
    *,
    materials_root: str | Path,
    verify_elaboration: bool = False,
    verilator_bin: str = "verilator",
    timeout_seconds: float = 60.0,
) -> QualificationOracle:
    """Load a frozen oracle and verify every immutable local input fail-closed."""
    oracle_path = Path(path).resolve(strict=True)
    root = Path(materials_root).resolve(strict=True)
    raw = _read_object(oracle_path)
    _exact_fields(raw, {
        "schema", "oracle_version", "oracle_implementation_sha256", "frozen_revision",
        "protocol", "oracle_digest", "dataset", "candidates", "compatibility", "cases",
        "experiment",
    }, "oracle")
    if raw["schema"] != ORACLE_SCHEMA or raw["protocol"] != "axi_lite":
        raise InputValidationError("qualification oracle schema/protocol mismatch")
    expected_digest = compute_oracle_digest(raw)
    if raw["oracle_digest"] != expected_digest:
        raise InputValidationError("qualification oracle digest mismatch")
    for field in ("oracle_version", "oracle_implementation_sha256", "frozen_revision"):
        _nonempty(raw[field], f"oracle.{field}")
    if len(str(raw["oracle_implementation_sha256"])) != 64:
        raise InputValidationError("oracle implementation hash must be SHA-256")
    if raw["oracle_implementation_sha256"] != _sha256(Path(__file__).read_bytes()):
        raise InputValidationError("qualification oracle implementation hash is stale")

    candidates = _objects(raw["candidates"], "oracle.candidates")
    if not candidates:
        raise InputValidationError("qualification oracle must freeze at least one candidate")
    by_id: dict[str, Mapping[str, object]] = {}
    family_split: dict[str, str] = {}
    source_split: dict[str, str] = {}
    for index, candidate in enumerate(candidates):
        normalized = _validate_candidate(candidate, index, root)
        identifier = str(normalized["id"])
        if identifier in by_id:
            raise InputValidationError(f"duplicate qualification candidate {identifier!r}")
        by_id[identifier] = normalized
        family = str(normalized["family"])
        split = str(normalized["split"])
        if family in family_split and family_split[family] != split:
            raise InputValidationError(f"source family {family!r} crosses dataset splits")
        family_split[family] = split
        for source in (*normalized["sources"], *normalized["dependencies"]):
            source_path = str(source["path"])
            if source_path in source_split and source_split[source_path] != split:
                raise InputValidationError(f"source {source_path!r} crosses dataset splits")
            source_split[source_path] = split
        if verify_elaboration and normalized["status"] == "qualified":
            _verify_candidate_elaboration(normalized, root, verilator_bin, timeout_seconds)

    _validate_dataset(raw["dataset"], family_split)
    qualified = {key: value for key, value in by_id.items() if value["status"] == "qualified"}
    cpus = {key: value for key, value in qualified.items() if value["kind"] == "cpu"}
    ips = {key: value for key, value in qualified.items() if value["kind"] == "ip"}
    if not cpus or not ips:
        raise InputValidationError("qualification oracle needs at least one qualified CPU and IP")
    compatible_pairs = _validate_compatibility(raw["compatibility"], cpus, ips)
    _validate_cases(raw["cases"], qualified, compatible_pairs)
    _validate_experiment(raw["experiment"])
    return QualificationOracle(oracle_path.as_posix(), expected_digest, raw)


def evaluate_acceptance(
    oracle: QualificationOracle,
    case_results: Sequence[Mapping[str, object]],
    run_results: Sequence[Mapping[str, object]],
) -> Mapping[str, object]:
    """Require the frozen denominator and summarize paired RAW/CONSTRAINED runs."""
    expected_cases = {str(item["id"]) for item in oracle.data["cases"]}
    for index, result in enumerate(case_results):
        _exact_fields(result, {"case_id", "status"}, f"case_results[{index}]")
    case_by_id = _unique_results(case_results, "case_id")
    if set(case_by_id) != expected_cases:
        raise InputValidationError("acceptance case results do not match the frozen case denominator")
    failed_cases = sorted(key for key, value in case_by_id.items() if value.get("status") != "passed")
    if failed_cases:
        raise InputValidationError("qualification cases failed: " + ", ".join(failed_cases))

    experiment = oracle.data["experiment"]
    seeds = tuple(int(seed) for seed in experiment["seeds"])
    expected_runs = {
        (case_id, seed, mode)
        for case_id in expected_cases for seed in seeds for mode in ("raw", "constrained")
    }
    run_by_key: dict[tuple[str, int, str], Mapping[str, object]] = {}
    for index, result in enumerate(run_results):
        _exact_fields(result, {
            "case_id", "seed", "mode", "status", "bit_budget", "coverage_cleared",
            "first_new_coverage_cycle", "early_coverage", "longest_plateau", "final_coverage",
        }, f"run_results[{index}]")
        key = (str(result["case_id"]), int(result["seed"]), str(result["mode"]))
        if key in run_by_key:
            raise InputValidationError(f"duplicate acceptance run {key}")
        run_by_key[key] = result
        if result["mode"] not in ("raw", "constrained"):
            raise InputValidationError(f"run_results[{index}].mode: invalid mode")
        _positive_integer(result["bit_budget"], f"run_results[{index}].bit_budget")
        for field in (
            "first_new_coverage_cycle", "early_coverage", "longest_plateau", "final_coverage",
        ):
            _nonnegative_number(result[field], f"run_results[{index}].{field}")
    if set(run_by_key) != expected_runs:
        raise InputValidationError("acceptance runs do not match the preregistered denominator")
    for case_id in sorted(expected_cases):
        for seed in seeds:
            raw = run_by_key[(case_id, seed, "raw")]
            constrained = run_by_key[(case_id, seed, "constrained")]
            if raw["status"] != "passed" or constrained["status"] != "passed":
                raise InputValidationError(f"acceptance run failed for {case_id} seed {seed}")
            if not raw["coverage_cleared"] or not constrained["coverage_cleared"]:
                raise InputValidationError(f"coverage was not cleared for {case_id} seed {seed}")
            if raw["bit_budget"] != constrained["bit_budget"]:
                raise InputValidationError(f"RAW/CONSTRAINED bit budgets differ for {case_id} seed {seed}")

    modes = {}
    for mode in ("raw", "constrained"):
        selected = [value for key, value in sorted(run_by_key.items()) if key[2] == mode]
        modes[mode] = {
            "run_count": len(selected),
            "median_first_new_coverage_cycle": statistics.median(
                float(value["first_new_coverage_cycle"]) for value in selected
            ),
            "median_early_coverage": statistics.median(float(value["early_coverage"]) for value in selected),
            "median_longest_plateau": statistics.median(float(value["longest_plateau"]) for value in selected),
            "median_final_coverage": statistics.median(float(value["final_coverage"]) for value in selected),
        }
    paired_intervals = {}
    for field in (
        "first_new_coverage_cycle", "early_coverage", "longest_plateau", "final_coverage",
    ):
        differences = [
            float(run_by_key[(case_id, seed, "constrained")][field])
            - float(run_by_key[(case_id, seed, "raw")][field])
            for case_id in sorted(expected_cases) for seed in seeds
        ]
        paired_intervals[field] = _paired_bootstrap_interval(
            differences,
            resamples=int(experiment["bootstrap_resamples"]),
            seed=int(experiment["bootstrap_seed"]),
            confidence=float(experiment["confidence_level"]),
        )
    improvement = (
        modes["constrained"]["median_early_coverage"] > modes["raw"]["median_early_coverage"]
        and modes["constrained"]["median_longest_plateau"] < modes["raw"]["median_longest_plateau"]
    )
    return {
        "schema": ACCEPTANCE_SCHEMA,
        "oracle_digest": oracle.digest,
        "qualified_candidate_count": len(oracle.qualified),
        "case_count": len(expected_cases),
        "run_count": len(expected_runs),
        "pass_rate": 1.0,
        "modes": modes,
        "paired_delta_intervals": paired_intervals,
        "constrained_reduces_plateau": improvement,
        "claim": (
            "measured improvement under the preregistered paired experiment"
            if improvement else "no measured plateau-reduction claim"
        ),
    }


def _validate_candidate(
    candidate: Mapping[str, object], index: int, root: Path,
) -> Mapping[str, object]:
    path = f"oracle.candidates[{index}]"
    _exact_fields(candidate, {
        "id", "kind", "module", "family", "split", "status", "reason", "protocol",
        "data_width", "address_width", "filelist", "filelist_sha256", "sources", "dependencies",
        "licenses", "provenance", "parameters", "interface",
    }, path)
    for field in ("id", "module", "family", "reason"):
        _nonempty(candidate[field], f"{path}.{field}")
    if candidate["kind"] not in _KINDS or candidate["split"] not in _SPLITS:
        raise InputValidationError(f"{path}: invalid kind or split")
    if candidate["status"] not in _STATUSES or candidate["protocol"] != "axi_lite":
        raise InputValidationError(f"{path}: invalid status or protocol")
    for field in ("data_width", "address_width"):
        value = candidate[field]
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise InputValidationError(f"{path}.{field}: expected a positive integer")
    if candidate["data_width"] % 8:
        raise InputValidationError(f"{path}.data_width: AXI-Lite data width must be byte-aligned")
    parameters = candidate["parameters"]
    if not isinstance(parameters, Mapping):
        raise InputValidationError(f"{path}.parameters: expected an object")
    for name, value in parameters.items():
        if not isinstance(name, str) or not name.isidentifier() or isinstance(value, bool) \
                or not isinstance(value, (int, str)):
            raise InputValidationError(f"{path}.parameters: invalid parameter override")
    interface = candidate["interface"]
    if not isinstance(interface, Mapping) or not set(interface).issubset(_AXI_SIGNALS):
        raise InputValidationError(f"{path}.interface: expected an AXI-Lite semantic map")
    if candidate["status"] == "qualified" and set(interface) != _AXI_SIGNALS:
        raise InputValidationError(f"{path}.interface: expected the complete AXI-Lite semantic map")
    if any(not isinstance(value, str) or not value.isidentifier() for value in interface.values()):
        raise InputValidationError(f"{path}.interface: physical ports must be identifiers")
    if len(set(interface.values())) != len(interface):
        raise InputValidationError(f"{path}.interface: physical ports must be unique")
    filelist = _safe_file(root, candidate["filelist"], f"{path}.filelist")
    if _sha256(filelist.read_bytes()) != candidate["filelist_sha256"]:
        raise InputValidationError(f"{path}: filelist hash mismatch")
    sources = _objects(candidate["sources"], f"{path}.sources")
    if not sources:
        raise InputValidationError(f"{path}: source list cannot be empty")
    listed_paths = []
    for source_index, source in enumerate(sources):
        source_path = f"{path}.sources[{source_index}]"
        _exact_fields(source, {"path", "sha256", "size"}, source_path)
        resolved = _safe_file(root, source["path"], source_path)
        payload = resolved.read_bytes()
        if len(payload) != source["size"] or _sha256(payload) != source["sha256"]:
            raise InputValidationError(f"{source_path}: source content mismatch")
        listed_paths.append(resolved)
    from .contracts import ManifestError, build_elaboration_manifest
    try:
        filelist_manifest = build_elaboration_manifest(
            top_module=str(candidate["module"]), filelists=(filelist,), allow_roots=(root,),
        )
    except (OSError, ManifestError) as exc:
        raise InputValidationError(f"{path}: invalid frozen filelist: {exc}") from exc
    manifest_paths = [Path(item.path) for item in filelist_manifest.sources]
    if manifest_paths != listed_paths:
        raise InputValidationError(f"{path}: filelist expansion does not exactly match sources")
    dependencies = _objects(candidate["dependencies"], f"{path}.dependencies")
    dependency_paths: set[str] = set()
    source_names = {str(source["path"]) for source in sources}
    for dependency_index, dependency in enumerate(dependencies):
        dependency_path = f"{path}.dependencies[{dependency_index}]"
        _exact_fields(dependency, {"path", "sha256", "size"}, dependency_path)
        name = str(dependency["path"])
        if name in source_names or name in dependency_paths:
            raise InputValidationError(f"{dependency_path}: duplicate source or dependency path")
        resolved = _safe_file(root, name, dependency_path)
        payload = resolved.read_bytes()
        if len(payload) != dependency["size"] or _sha256(payload) != dependency["sha256"]:
            raise InputValidationError(f"{dependency_path}: dependency content mismatch")
        dependency_paths.add(name)
    licenses = _objects(candidate["licenses"], f"{path}.licenses")
    covered_sources: set[str] = set()
    for license_index, license_value in enumerate(licenses):
        license_path_name = f"{path}.licenses[{license_index}]"
        _exact_fields(
            license_value, {"spdx", "path", "sha256", "redistribution", "applies_to"},
            license_path_name,
        )
        applies_to = license_value["applies_to"]
        if not isinstance(applies_to, list) or any(not isinstance(item, str) for item in applies_to):
            raise InputValidationError(f"{license_path_name}.applies_to: expected an array of paths")
        all_materials = source_names | dependency_paths
        unknown = set(applies_to) - all_materials
        if unknown:
            raise InputValidationError(f"{license_path_name}: license covers unknown sources")
        covered_sources.update(applies_to)
        if candidate["status"] == "qualified":
            if license_value["spdx"] not in _APPROVED_LICENSES or license_value["redistribution"] is not True:
                raise InputValidationError(f"{path}: qualified material has an unapproved license")
            license_path = _safe_file(root, license_value["path"], f"{license_path_name}.path")
            if _sha256(license_path.read_bytes()) != license_value["sha256"]:
                raise InputValidationError(f"{license_path_name}: license hash mismatch")
    if candidate["status"] == "qualified":
        expected_coverage = source_names | dependency_paths
        if not licenses or covered_sources != expected_coverage:
            raise InputValidationError(f"{path}: qualified material license coverage is incomplete")
    provenance = candidate["provenance"]
    if not isinstance(provenance, Mapping):
        raise InputValidationError(f"{path}.provenance: expected an object")
    _exact_fields(provenance, {"upstreams", "patches"}, f"{path}.provenance")
    upstreams = _objects(provenance["upstreams"], f"{path}.provenance.upstreams")
    if not upstreams:
        raise InputValidationError(f"{path}.provenance.upstreams: cannot be empty")
    for upstream_index, upstream in enumerate(upstreams):
        upstream_path = f"{path}.provenance.upstreams[{upstream_index}]"
        _exact_fields(upstream, {"source", "revision", "archive_sha256", "submodules"}, upstream_path)
        for field in ("source", "revision", "archive_sha256"):
            _nonempty(upstream[field], f"{upstream_path}.{field}")
        _sha256_text(upstream["archive_sha256"], f"{upstream_path}.archive_sha256")
        if not isinstance(upstream["submodules"], list) or any(
            not isinstance(item, str) or not item for item in upstream["submodules"]
        ):
            raise InputValidationError(f"{upstream_path}.submodules: expected an array of revisions")
    if not isinstance(provenance["patches"], list):
        raise InputValidationError(f"{path}.provenance.patches: expected an array")
    patches = _objects(provenance["patches"], f"{path}.provenance.patches")
    for patch_index, patch in enumerate(patches):
        patch_path = f"{path}.provenance.patches[{patch_index}]"
        _exact_fields(patch, {"path", "sha256"}, patch_path)
        resolved = _safe_file(root, patch["path"], f"{patch_path}.path")
        if _sha256(resolved.read_bytes()) != patch["sha256"]:
            raise InputValidationError(f"{patch_path}: patch content mismatch")
    return candidate


def _validate_dataset(value: object, family_split: Mapping[str, str]) -> None:
    if not isinstance(value, Mapping):
        raise InputValidationError("oracle.dataset: expected an object")
    _exact_fields(value, {
        "split_unit", "policy", "development_percent", "holdout_percent",
        "family_assignments",
    }, "oracle.dataset")
    if value["split_unit"] != "source_family" or value["policy"] != "frozen_family_assignments_v1":
        raise InputValidationError("oracle.dataset: unsupported split policy")
    if value["development_percent"] != 80 or value["holdout_percent"] != 20:
        raise InputValidationError("oracle.dataset: development/holdout ratio must be frozen at 80/20")
    assignments = _objects(value["family_assignments"], "oracle.dataset.family_assignments")
    observed: dict[str, str] = {}
    for index, assignment in enumerate(assignments):
        path = f"oracle.dataset.family_assignments[{index}]"
        _exact_fields(assignment, {"family", "split"}, path)
        family = str(assignment["family"])
        split = str(assignment["split"])
        if not family or split not in _SPLITS or family in observed:
            raise InputValidationError(f"{path}: invalid or duplicate family assignment")
        observed[family] = split
    if observed != dict(family_split):
        raise InputValidationError("oracle.dataset assignments do not match the frozen candidates")
    total = len(observed)
    development = sum(split == "development" for split in observed.values())
    holdout = sum(split == "holdout" for split in observed.values())
    if development * 100 != total * 80 or holdout * 100 != total * 20:
        raise InputValidationError("oracle.dataset candidate families do not form an exact 80/20 split")


def _validate_compatibility(
    values: object,
    cpus: Mapping[str, Mapping[str, object]],
    ips: Mapping[str, Mapping[str, object]],
) -> set[tuple[str, str]]:
    entries = _objects(values, "oracle.compatibility")
    by_pair = {}
    for index, entry in enumerate(entries):
        path = f"oracle.compatibility[{index}]"
        _exact_fields(entry, {"cpu", "ip", "compatible", "reason"}, path)
        pair = (str(entry["cpu"]), str(entry["ip"]))
        if pair in by_pair or pair[0] not in cpus or pair[1] not in ips:
            raise InputValidationError(f"{path}: duplicate or unknown compatibility pair")
        expected = (
            cpus[pair[0]]["data_width"] == ips[pair[1]]["data_width"]
            and cpus[pair[0]]["split"] == ips[pair[1]]["split"]
        )
        if not isinstance(entry["compatible"], bool) or entry["compatible"] != expected:
            raise InputValidationError(
                f"{path}: compatibility contradicts the locked width and split-isolation rules"
            )
        _nonempty(entry["reason"], f"{path}.reason")
        by_pair[pair] = bool(entry["compatible"])
    expected_pairs = {(cpu, ip) for cpu in cpus for ip in ips}
    if set(by_pair) != expected_pairs:
        raise InputValidationError("compatibility matrix is not total over qualified CPU x IP")
    return {pair for pair, compatible in by_pair.items() if compatible}


def _validate_cases(
    values: object,
    qualified: Mapping[str, Mapping[str, object]],
    compatible_pairs: set[tuple[str, str]],
) -> None:
    cases = _objects(values, "oracle.cases")
    if not cases:
        raise InputValidationError("qualification oracle must freeze at least one case")
    identifiers = set()
    covered_pairs = set()
    multi_components = set()
    for index, case in enumerate(cases):
        path = f"oracle.cases[{index}]"
        _exact_fields(case, {
            "id", "split", "cpu", "ips", "manifest_hash", "expected_artifact_bytes",
            "resource_budget",
        }, path)
        identifier = str(case["id"])
        if identifier in identifiers:
            raise InputValidationError(f"{path}: duplicate case id")
        identifiers.add(identifier)
        cpu = str(case["cpu"])
        ips = tuple(str(value) for value in case["ips"])
        if cpu not in qualified or qualified[cpu]["kind"] != "cpu" or len(set(ips)) < 2:
            raise InputValidationError(f"{path}: case requires one CPU and at least two distinct IPs")
        if any(ip not in qualified or qualified[ip]["kind"] != "ip" for ip in ips):
            raise InputValidationError(f"{path}: case references an unknown qualified IP")
        split = str(case["split"])
        if split not in _SPLITS or any(qualified[item]["split"] != split for item in (cpu, *ips)):
            raise InputValidationError(f"{path}: case crosses frozen dataset splits")
        for ip in ips:
            pair = (cpu, ip)
            if pair not in compatible_pairs:
                raise InputValidationError(f"{path}: case contains an incompatible CPU/IP pair")
            covered_pairs.add(pair)
        multi_components.update((cpu, *ips))
        _sha256_text(case["manifest_hash"], f"{path}.manifest_hash")
        _positive_integer(case["expected_artifact_bytes"], f"{path}.expected_artifact_bytes")
        if not isinstance(case["resource_budget"], Mapping):
            raise InputValidationError(f"{path}.resource_budget: expected an object")
        _exact_fields(case["resource_budget"], {"compile_seconds", "run_seconds", "max_bytes"},
                      f"{path}.resource_budget")
        for field in ("compile_seconds", "run_seconds", "max_bytes"):
            _positive_integer(case["resource_budget"][field], f"{path}.resource_budget.{field}")
    if covered_pairs != compatible_pairs:
        raise InputValidationError("frozen cases do not cover every compatible CPU x IP pair")
    participating = {item for pair in compatible_pairs for item in pair}
    if not participating.issubset(multi_components):
        raise InputValidationError("every compatible CPU and IP must participate in a multi-IP case")


def _validate_experiment(value: object) -> None:
    if not isinstance(value, Mapping):
        raise InputValidationError("oracle.experiment: expected an object")
    _exact_fields(value, {
        "seeds", "cycles", "timeout_seconds", "early_cycle", "entropy_matched",
        "coverage_reset", "merge", "censoring", "confidence_interval", "confidence_level",
        "bootstrap_resamples", "bootstrap_seed", "determinism_check",
    }, "oracle.experiment")
    seeds = value["seeds"]
    if not isinstance(seeds, list) or not seeds or len(set(seeds)) != len(seeds):
        raise InputValidationError("oracle.experiment.seeds must be a non-empty unique array")
    for index, seed in enumerate(seeds):
        _positive_integer(seed, f"oracle.experiment.seeds[{index}]")
    for field in ("cycles", "timeout_seconds", "early_cycle", "bootstrap_resamples"):
        if isinstance(value[field], bool) or not isinstance(value[field], int) or value[field] <= 0:
            raise InputValidationError(f"oracle.experiment.{field}: expected a positive integer")
    if value["early_cycle"] > value["cycles"] or value["entropy_matched"] is not True:
        raise InputValidationError("experiment must use an entropy-matched early-cycle budget")
    if value["coverage_reset"] != "fresh_process_per_run" or value["merge"] != "point_id_union":
        raise InputValidationError("experiment coverage reset/merge semantics are not locked")
    _positive_integer(value["bootstrap_seed"], "oracle.experiment.bootstrap_seed")
    confidence = value["confidence_level"]
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 < confidence < 1:
        raise InputValidationError("oracle.experiment.confidence_level must be between zero and one")
    if value["determinism_check"] != "repeat_first_seed_byte_identical":
        raise InputValidationError("experiment simulator determinism check is not locked")
    for field in ("censoring", "confidence_interval"):
        _nonempty(value[field], f"oracle.experiment.{field}")


def _verify_candidate_elaboration(
    candidate: Mapping[str, object], root: Path, executable: str, timeout: float,
) -> None:
    from .contracts import build_elaboration_manifest
    from .rtl_analysis import analyze_elaboration
    del timeout  # The isolated shared frontend owns process lifetime and failure cleanup.
    manifest = build_elaboration_manifest(
        top_module=str(candidate["module"]),
        filelists=((root / str(candidate["filelist"])).resolve(),), allow_roots=(root,),
        tools={"verilator": executable},
    )
    try:
        analysis = analyze_elaboration(manifest, project_root=root)
    except (OSError, InputValidationError, ValueError) as exc:
        raise InputValidationError(f"candidate {candidate['id']}: Verilator qualification failed: {exc}") from exc
    module = next((item for item in analysis.modules
                   if item.original_name == candidate["module"] or item.name == candidate["module"]), None)
    if module is None:
        raise InputValidationError(f"candidate {candidate['id']}: top module absent from AST")
    ports = {port.name: port for port in module.ports}
    widths = {
        "clock": 1, "reset": 1, "awvalid": 1, "awready": 1, "awaddr": int(candidate["address_width"]),
        "wvalid": 1, "wready": 1, "wdata": int(candidate["data_width"]),
        "wstrb": int(candidate["data_width"]) // 8, "bvalid": 1, "bready": 1, "bresp": 2,
        "arvalid": 1, "arready": 1, "araddr": int(candidate["address_width"]), "rvalid": 1,
        "rready": 1, "rdata": int(candidate["data_width"]), "rresp": 2,
    }
    cpu_inputs = {
        "clock", "reset", "awready", "wready", "bvalid", "bresp", "arready", "rvalid",
        "rdata", "rresp",
    }
    ip_inputs = {
        "clock", "reset", "awvalid", "awaddr", "wvalid", "wdata", "wstrb", "bready",
        "arvalid", "araddr", "rready",
    }
    input_semantics = cpu_inputs if candidate["kind"] == "cpu" else ip_inputs
    for semantic, physical in candidate["interface"].items():
        port = ports.get(physical)
        if port is None or port.width != widths[semantic]:
            raise InputValidationError(f"candidate {candidate['id']}: AXI-Lite port {semantic} has wrong width or is absent")
        expected_direction = "input" if semantic in input_semantics else "output"
        if port.direction.value != expected_direction:
            raise InputValidationError(f"candidate {candidate['id']}: AXI-Lite port {semantic} has wrong direction")


def _unique_results(values: Sequence[Mapping[str, object]], key: str) -> dict[str, Mapping[str, object]]:
    result = {}
    for value in values:
        identifier = str(value.get(key, ""))
        if not identifier or identifier in result:
            raise InputValidationError(f"acceptance results contain a missing or duplicate {key}")
        result[identifier] = value
    return result


def _paired_bootstrap_interval(
    differences: Sequence[float], *, resamples: int, seed: int, confidence: float,
) -> Mapping[str, object]:
    rng = random.Random(seed)
    count = len(differences)
    medians = sorted(
        statistics.median(differences[rng.randrange(count)] for _ in range(count))
        for _ in range(resamples)
    )
    tail = (1.0 - confidence) / 2.0
    low_index = max(0, min(resamples - 1, math.floor(tail * resamples)))
    high_index = max(0, min(resamples - 1, math.ceil((1.0 - tail) * resamples) - 1))
    return {
        "method": "paired_bootstrap_median_delta",
        "confidence_level": confidence,
        "resamples": resamples,
        "estimate": statistics.median(differences),
        "lower": medians[low_index],
        "upper": medians[high_index],
    }


def _safe_file(root: Path, value: object, path: str) -> Path:
    _nonempty(value, path)
    candidate = Path(str(value))
    if candidate.is_absolute() or ".." in candidate.parts:
        raise InputValidationError(f"{path}: path must be relative and non-escaping")
    resolved = (root / candidate).resolve(strict=True)
    if not resolved.is_relative_to(root) or not resolved.is_file() or resolved.is_symlink():
        raise InputValidationError(f"{path}: path is not a safe regular file")
    return resolved


def _objects(value: object, path: str) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
        raise InputValidationError(f"{path}: expected an array of objects")
    return tuple(value)


def _exact_fields(value: Mapping[str, object], expected: set[str], path: str) -> None:
    missing = expected - set(value)
    unknown = set(value) - expected
    if missing or unknown:
        raise InputValidationError(
            f"{path}: field mismatch; missing={sorted(missing)}, unknown={sorted(unknown)}"
        )


def _nonempty(value: object, path: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise InputValidationError(f"{path}: expected a non-empty string")


def _positive_integer(value: object, path: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise InputValidationError(f"{path}: expected a positive integer")


def _nonnegative_number(value: object, path: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InputValidationError(f"{path}: expected a non-negative finite number")
    if not math.isfinite(float(value)) or value < 0:
        raise InputValidationError(f"{path}: expected a non-negative finite number")


def _sha256_text(value: object, path: str) -> None:
    if not isinstance(value, str) or len(value) != 64:
        raise InputValidationError(f"{path}: expected a SHA-256 digest")
    try:
        int(value, 16)
    except ValueError as exc:
        raise InputValidationError(f"{path}: expected a SHA-256 digest") from exc


def _read_object(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InputValidationError(f"cannot read qualification oracle {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise InputValidationError("qualification oracle must contain an object")
    return value


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
