#!/usr/bin/env python3
"""Run the fixed two-target static-projection training campaign."""

from __future__ import annotations

import argparse
import copy
import json
import math
import os
import re
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from myfuzz.contracts import canonical_bytes, content_hash, validate_contract
from myfuzz.experiments.static_portfolio import (
    PORTFOLIO,
    PromotionDecision,
    promote,
    screened_policy_ids,
)
from myfuzz.harness import StaticPolicyParameters, build_harness
from myfuzz.integration import (
    RfuzzExperimentRunner,
    matrix_promotion_pairs,
    run_experiment_matrix,
)


ROOT = Path(__file__).resolve().parents[2]
_HASH = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z")
_CANONICAL_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CAMPAIGN_KEYS = frozenset(("screen", "promotion", "validation", "targets"))
_STAGE_KEYS = frozenset(("seconds", "seeds"))
_TARGET_KEYS = frozenset(("target_id", "config_path", "candidate_manifest_path"))
_RUN_KEYS = frozenset(
    (
        "coverage_identity",
        "raw_width",
        "mutation",
        "seed",
        "budget",
        "return_code",
        "tests_executed",
        "expected_coverage",
        "elapsed_seconds",
        "declared_artifact_hash",
        "observed_artifact_hash",
        "fifo_paths",
    )
)
_PARAMETER_KEYS = frozenset(
    ("direct_ratio", "event_rarity", "legal_set_strength", "mutual_exclusion")
)


@dataclass(frozen=True, slots=True)
class CampaignStage:
    seconds: int
    seeds: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class CampaignTarget:
    target_id: str
    config_path: str
    candidate_manifest_path: str


@dataclass(frozen=True, slots=True)
class CampaignConfig:
    screen: CampaignStage
    promotion: CampaignStage
    validation: CampaignStage
    targets: tuple[CampaignTarget, ...]
    source_path: str = "configs/experiments/static_projection_training.json"


def _object(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be an object")
    return value


def _strict(value: object, keys: frozenset[str], label: str) -> Mapping[str, object]:
    document = _object(value, label)
    unexpected = sorted(set(document) - keys)
    missing = sorted(keys - set(document))
    if unexpected:
        raise ValueError(f"{label} contains unexpected fields: {unexpected}")
    if missing:
        raise ValueError(f"{label} is missing required fields: {missing}")
    return document


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _integer(value: object, label: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < (1 if positive else 0):
        raise ValueError(f"{label} must be a {'positive' if positive else 'non-negative'} integer")
    return value


def _number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a finite non-negative number")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ValueError(f"{label} must be a finite non-negative number")
    return result


def _array(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{label} must be an array")
    return value


def _repository_path(value: object, label: str, *, must_exist: bool = True) -> str:
    text = _string(value, label)
    path = Path(text)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{label} must be a repository-relative path")
    resolved = (ROOT / path).resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError as error:
        raise ValueError(f"{label} must be a repository-relative path") from error
    if must_exist and not resolved.is_file():
        raise ValueError(f"{label} does not name an existing file")
    return path.as_posix()


def _stage(value: object, label: str, seconds: int, seeds: tuple[int, ...]) -> CampaignStage:
    document = _strict(value, _STAGE_KEYS, label)
    actual_seconds = _integer(document["seconds"], f"{label}.seconds", positive=True)
    actual_seeds = tuple(_integer(seed, f"{label}.seeds") for seed in _array(document["seeds"], f"{label}.seeds"))
    if len(actual_seeds) != len(set(actual_seeds)):
        raise ValueError(f"{label}.seeds must be unique")
    if actual_seconds != seconds or actual_seeds != seeds:
        raise ValueError(f"{label} must use exactly {seconds} seconds and seeds {list(seeds)}")
    return CampaignStage(actual_seconds, actual_seeds)


def _target(value: object, index: int) -> CampaignTarget:
    document = _strict(value, _TARGET_KEYS, f"targets[{index}]")
    target_id = _string(document["target_id"], f"targets[{index}].target_id")
    config_path = _repository_path(document["config_path"], f"targets[{index}].config_path")
    manifest_path = _repository_path(
        document["candidate_manifest_path"], f"targets[{index}].candidate_manifest_path"
    )
    declaration = _object(_read_json(ROOT / config_path), f"target config {target_id}")
    if declaration.get("portfolio") != "static_projection.PORTFOLIO":
        raise ValueError(f"target {target_id} must use static_projection.PORTFOLIO")
    static = _object(declaration.get("static_projection"), f"target {target_id}.static_projection")
    forbidden = sorted(set(static) & {"parameters", "policy"})
    if forbidden:
        raise ValueError(f"target {target_id} must not declare policy or parameters")
    if declaration.get("candidate_manifest") != manifest_path:
        raise ValueError(f"target {target_id} candidate_manifest path mismatch")
    validate_contract(_read_json(ROOT / manifest_path), "candidate_manifest.v1")
    return CampaignTarget(target_id, config_path, manifest_path)


def _read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load JSON file: {path}") from error


def load_campaign(path: Path) -> CampaignConfig:
    """Load the one fixed training campaign with closed-world validation."""
    if not isinstance(path, Path):
        raise TypeError("path must be a pathlib.Path")
    document = _strict(_read_json(path), _CAMPAIGN_KEYS, "campaign")
    targets = tuple(_target(item, index) for index, item in enumerate(_array(document["targets"], "targets")))
    if len(targets) != 2:
        raise ValueError("campaign must declare exactly two training targets")
    ids = tuple(target.target_id for target in targets)
    paths = tuple(target.config_path for target in targets)
    manifests = tuple(target.candidate_manifest_path for target in targets)
    if len(set(ids)) != len(ids) or len(set(paths)) != len(paths) or len(set(manifests)) != len(manifests):
        raise ValueError("campaign contains duplicate target declarations")
    if ids != ("ibex_opentitan_real_ip", "rvx_multicomponent"):
        raise ValueError("campaign must declare the exact two training targets in canonical order")
    source = path.resolve()
    try:
        source_path = source.relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        source_path = "configs/experiments/static_projection_training.json"
    return CampaignConfig(
        _stage(document["screen"], "screen", 60, (1,)),
        _stage(document["promotion"], "promotion", 600, (1, 7, 19)),
        _stage(document["validation"], "validation", 3600, (1, 7, 19)),
        targets,
        source_path,
    )


def _hash(value: object, label: str, *, canonical: bool = True) -> str:
    result = _string(value, label)
    pattern = _CANONICAL_HASH if canonical else _HASH
    if pattern.fullmatch(result) is None:
        raise ValueError(f"{label} must be a SHA-256 hash")
    return result


def _validate_run(value: object, label: str) -> Mapping[str, object]:
    run = _strict(value, _RUN_KEYS, label)
    coverage_identity = _hash(run["coverage_identity"], f"{label}.coverage_identity")
    raw_width = _integer(run["raw_width"], f"{label}.raw_width", positive=True)
    mutation = _object(run["mutation"], f"{label}.mutation")
    if any(not isinstance(key, str) or isinstance(item, bool) or not isinstance(item, (int, str)) for key, item in mutation.items()):
        raise ValueError(f"{label}.mutation contains invalid values")
    seed = _integer(run["seed"], f"{label}.seed")
    budget = _strict(run["budget"], frozenset(("kind", "value")), f"{label}.budget")
    if budget["kind"] != "seconds":
        raise ValueError(f"{label}.budget.kind must be seconds")
    seconds = _integer(budget["value"], f"{label}.budget.value", positive=True)
    return_code = _integer(run["return_code"], f"{label}.return_code")
    if return_code != 0:
        raise ValueError(f"{label} has abnormal return code")
    tests = _integer(run["tests_executed"], f"{label}.tests_executed", positive=True)
    expected = tuple(_integer(item, f"{label}.expected_coverage") for item in _array(run["expected_coverage"], f"{label}.expected_coverage"))
    if not expected or len(expected) != len(set(expected)):
        raise ValueError(f"{label}.expected_coverage must be non-empty and unique")
    elapsed = _number(run["elapsed_seconds"], f"{label}.elapsed_seconds")
    if elapsed < seconds:
        raise ValueError(f"{label} exited before its seconds budget")
    declared_hash = _hash(run["declared_artifact_hash"], f"{label}.declared_artifact_hash")
    observed_hash = _hash(run["observed_artifact_hash"], f"{label}.observed_artifact_hash")
    if declared_hash != observed_hash:
        raise ValueError(f"{label} artifact hash mismatch")
    fifos = tuple(_string(item, f"{label}.fifo_paths") for item in _array(run["fifo_paths"], f"{label}.fifo_paths"))
    if any(Path(path).exists() for path in fifos):
        raise ValueError(f"{label} has a leftover FIFO")
    return {
        "coverage_identity": coverage_identity,
        "raw_width": raw_width,
        "mutation": dict(mutation),
        "seed": seed,
        "budget": {"kind": "seconds", "value": seconds},
        "tests_executed": tests,
        "expected_coverage": expected,
    }


def validate_training_pair(value: object) -> None:
    """Fail closed unless a direct/static result pair is comparable and valid."""
    pair = _strict(value, frozenset(("baseline", "candidate")), "training pair")
    baseline = _validate_run(pair["baseline"], "baseline")
    candidate = _validate_run(pair["candidate"], "candidate")
    for field in ("coverage_identity", "raw_width", "mutation", "seed", "budget"):
        if baseline[field] != candidate[field]:
            raise ValueError(f"training pair {field} mismatch")


def _parameters(value: object) -> StaticPolicyParameters:
    document = _strict(value, _PARAMETER_KEYS, "parameters")
    try:
        return StaticPolicyParameters(
            document["direct_ratio"],
            document["event_rarity"],
            document["legal_set_strength"],
            document["mutual_exclusion"],
        )
    except (TypeError, ValueError) as error:
        raise ValueError("parameters contain invalid values") from error


def _atomic_json(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_bytes(document) + b"\n"
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _beneath_repository(path: Path, label: str) -> Path:
    absolute = path.resolve()
    try:
        absolute.relative_to(ROOT.resolve())
    except ValueError as error:
        raise ValueError(f"{label} must be beneath the repository") from error
    return absolute


def materialize_derived_design_config(
    target: CampaignTarget,
    parameters: Mapping[str, object],
    *,
    output_dir: Path,
    policy_id: str,
) -> Path:
    """Atomically write one existing-flow-compatible config and return its repo path."""
    if not isinstance(target, CampaignTarget):
        raise TypeError("target must be a CampaignTarget")
    if not isinstance(output_dir, Path):
        raise TypeError("output_dir must be a pathlib.Path")
    output = _beneath_repository(output_dir, "output_dir")
    if re.fullmatch(r"[A-Za-z0-9_.-]+", policy_id) is None:
        raise ValueError("policy_id must be a safe path component")
    typed = _parameters(parameters)
    source = copy.deepcopy(_object(_read_json(ROOT / target.config_path), "target config"))
    static = copy.deepcopy(_object(source.get("static_projection"), "static_projection"))
    if set(static) & {"parameters", "policy"}:
        raise ValueError("target config must not override policy or parameters")
    static["parameters"] = asdict(typed)
    source["static_projection"] = static
    source["candidate_manifest"] = target.candidate_manifest_path
    destination = output / "derived" / target.target_id / policy_id / "config.json"
    _atomic_json(destination, source)
    return destination.relative_to(ROOT.resolve())


def _policy_id(parameters: StaticPolicyParameters) -> str:
    return "policy-" + content_hash(asdict(parameters)).removeprefix("sha256:")[:16]


def _manifest_hash(value: str, label: str) -> str:
    """Normalize a compiler digest for the candidate-manifest wire format."""
    digest = _hash(value, label, canonical=False)
    return digest if digest.startswith("sha256:") else f"sha256:{digest}"


def _runtime_manifest(target: CampaignTarget, parameters: StaticPolicyParameters) -> dict[str, object]:
    base = copy.deepcopy(_object(_read_json(ROOT / target.candidate_manifest_path), "candidate manifest"))
    validate_contract(base, "candidate_manifest.v1")
    declaration = _object(_read_json(ROOT / target.config_path), "target config")
    static = _object(declaration.get("static_projection"), "static_projection")
    declarations = _object(static.get("declarations"), "static_projection.declarations")
    direct = build_harness(base, "candidate_direct")
    candidate = build_harness(
        base,
        "candidate_static",
        static_declarations=declarations,
        static_parameters=parameters,
    )
    flat = build_harness(base, "flat_direct")
    policy_id = _policy_id(parameters)
    runtime = copy.deepcopy(dict(base))
    runtime["candidate_id"] = f"{target.target_id}-{policy_id}"
    harnesses = copy.deepcopy(dict(_object(runtime.get("harnesses"), "manifest.harnesses")))
    flat_record = {
        "raw_width": flat.raw_width,
        "content_hash": _manifest_hash(flat.content_hash, "flat content_hash"),
        "abi_hash": _manifest_hash(flat.abi.abi_hash, "flat abi_hash"),
        "instrumented_rtl_hash": flat.top_content_hash,
        "coverage_universe": content_hash({"target_id": target.target_id, "scope": "flat-direct"}),
    }
    harnesses["flat-direct"] = flat_record
    harnesses["candidate-direct"] = {
        "raw_width": direct.raw_width,
        "content_hash": _manifest_hash(direct.content_hash, "direct content_hash"),
        "abi_hash": _manifest_hash(direct.abi.abi_hash, "direct abi_hash"),
    }
    harnesses["candidate-static"] = {
        "raw_width": candidate.raw_width,
        "content_hash": _manifest_hash(candidate.content_hash, "static content_hash"),
        "abi_hash": _manifest_hash(candidate.abi.abi_hash, "static abi_hash"),
        "projection_plan_hash": _manifest_hash(candidate.policy_plan_hash, "static projection_plan_hash"),
    }
    runtime["harnesses"] = harnesses
    mappings = copy.deepcopy(dict(_object(runtime.get("raw_bit_mappings"), "manifest.raw_bit_mappings")))
    mappings["flat-direct"] = flat.manifest_fragment()["mapping"]
    mappings["candidate-direct"] = direct.manifest_fragment()["mapping"]
    mappings["candidate-static"] = candidate.manifest_fragment()["mapping"]
    runtime["raw_bit_mappings"] = mappings
    validate_contract(runtime, "candidate_manifest.v1")
    return runtime


def _matrix_config(
    config: CampaignConfig,
    stage_name: str,
    stage: CampaignStage,
    target: CampaignTarget,
    parameters: StaticPolicyParameters,
    output_dir: Path,
    preparer: Callable[[dict[str, object], Path], dict[str, object]],
) -> dict[str, object]:
    policy_id = _policy_id(parameters)
    derived = materialize_derived_design_config(
        target,
        asdict(parameters),
        output_dir=output_dir,
        policy_id=policy_id,
    )
    manifest = _runtime_manifest(target, parameters)
    expected_harnesses = _object(manifest.get("harnesses"), "manifest.harnesses")
    expected_static = _object(
        expected_harnesses.get("candidate-static"),
        "manifest.harnesses.candidate-static",
    )
    expected_projection_hash = _hash(
        expected_static.get("projection_plan_hash"),
        "manifest candidate-static projection_plan_hash",
        canonical=True,
    )
    manifest = preparer(manifest, derived)
    if not isinstance(manifest, dict):
        raise TypeError("preparer must return a runtime manifest object")
    harnesses = _object(manifest.get("harnesses"), "prepared manifest.harnesses")
    static_harness = _object(
        harnesses.get("candidate-static"),
        "prepared manifest.harnesses.candidate-static",
    )
    prepared_projection_hash = _hash(
        static_harness.get("projection_plan_hash"),
        "prepared manifest candidate-static projection_plan_hash",
        canonical=True,
    )
    if prepared_projection_hash != expected_projection_hash:
        raise ValueError("preparer changed candidate-static projection_plan_hash")
    planner = {
        "schema_version": "experiment.v1",
        "config_path": config.source_path,
        "design_config_path": derived.as_posix(),
        "target": {"target_id": target.target_id, "display": target.target_id},
        "candidate_selection": {"k": 1},
        "harness_groups": ["flat-direct", "candidate-direct", "candidate-static"],
        "candidate_pair": {"seeds": list(stage.seeds)},
        "budgets": [{"name": stage_name, "kind": "seconds", "value": stage.seconds}],
        "coverage": {
            "metric": "branch",
            "comparisons": [
                {"left_harness": "candidate-direct", "right_harness": "candidate-static", "measure": "percentage"},
                {"left_harness": "flat-direct", "right_harness": "candidate-direct", "measure": "shared-stable-source-id"},
            ],
        },
        "mutation": {"max_len": 4096, "timeout_ms": 1000},
        "build_concurrency": 1,
        "waveforms": False,
        "replay_queue_capacity": 128,
        "event_ring_capacity": 4096,
        "field_groups_per_batch": 64,
        "soft_memory_bytes": 6_000_000_000,
        "hard_memory_bytes": 7_000_000_000,
        "token_bytes": 64_000_000,
        "reference": {"mode": "evaluation-only", "allowed_stage": "report", "comparison": "shared-stable-source-id"},
    }
    harnesses = manifest.get("harnesses")
    if not isinstance(harnesses, Mapping):
        raise ValueError("prepared manifest harnesses must be an object")
    static_harness = harnesses.get("candidate-static")
    if not isinstance(static_harness, Mapping):
        raise ValueError("prepared candidate-static harness must be an object")
    projection_plan_hash = static_harness.get("projection_plan_hash")
    if not isinstance(projection_plan_hash, str):
        raise ValueError("prepared candidate-static projection_plan_hash is required")
    return {
        "planner_config": planner,
        "candidate_manifests": [manifest],
        "execution": {
            "interleaving_seed": 1,
            "max_resource_retries": 1,
            "job_timeout_seconds": 0,
        },
        "pair_metadata": {
            "policy_id": policy_id,
            "plan_hash": content_hash(asdict(parameters)),
            "projection_plan_hash": projection_plan_hash,
            "parameters": asdict(parameters),
        },
    }


def _default_selector(results: object) -> PromotionDecision | None:
    decisions = promote(matrix_promotion_pairs(results))
    return decisions[0] if decisions else None


def _frozen_document(
    value: PromotionDecision | Mapping[str, object],
) -> dict[str, object]:
    expected = frozenset(("policy_id", "plan_hash", "parameters", "training_evidence_hash"))
    if isinstance(value, PromotionDecision):
        decision: Mapping[str, object] = {
            "policy_id": value.policy_id,
            "plan_hash": value.plan_hash,
            "parameters": asdict(value.parameters),
            "training_evidence_hash": value.training_evidence_hash,
        }
    else:
        decision = _strict(value, expected, "promotion decision")
    frozen = {
        "schema_version": "static-policy-freeze.v1",
        "policy_id": _string(decision["policy_id"], "promotion decision.policy_id"),
        "plan_hash": _hash(decision["plan_hash"], "promotion decision.plan_hash", canonical=False),
        "parameters": asdict(_parameters(decision["parameters"])),
        "training_evidence_hash": _hash(
            decision["training_evidence_hash"],
            "promotion decision.training_evidence_hash",
            canonical=False,
        ),
    }
    return frozen


def _freeze(value: PromotionDecision | Mapping[str, object], path: Path) -> dict[str, object]:
    frozen = _frozen_document(value)
    _atomic_json(path, frozen)
    return frozen


def run_campaign(
    config: CampaignConfig,
    *,
    runner: object,
    preparer: Callable[[dict[str, object], Path], dict[str, object]] | None = None,
    output_dir: Path,
    stage: str = "training",
    promotion_selector: Callable[[object], PromotionDecision | Mapping[str, object] | None] = _default_selector,
) -> dict[str, object]:
    """Compose screen/promotion/validation exclusively through the existing matrix."""
    if not isinstance(config, CampaignConfig):
        raise TypeError("config must be a CampaignConfig")
    if preparer is None or not callable(preparer):
        raise TypeError("preparer is required and must be callable")
    if not callable(promotion_selector):
        raise TypeError("promotion_selector must be callable")
    if stage not in {"smoke", "training"}:
        raise ValueError("stage must be smoke or training")
    output = _beneath_repository(output_dir, "output_dir")
    output.mkdir(parents=True, exist_ok=True)
    all_parameters = tuple(PORTFOLIO)
    def run_stage(
        stage_name: str,
        stage: CampaignStage,
        policies: tuple[StaticPolicyParameters, ...],
    ) -> tuple[dict[str, object], ...]:
        results: list[dict[str, object]] = []
        for target in config.targets:
            for policy in policies:
                policy_id = _policy_id(policy)
                matrix_input = _matrix_config(
                    config,
                    stage_name,
                    stage,
                    target,
                    policy,
                    output,
                    preparer,
                )
                report_path = output / stage_name / target.target_id / f"{policy_id}-matrix.json"
                report_path.parent.mkdir(parents=True, exist_ok=True)
                results.append(
                    run_experiment_matrix(
                        matrix_input,
                        runner=runner,
                        report_path=report_path,
                    )
                )
        return tuple(results)

    if stage == "smoke":
        smoke = run_stage("smoke", CampaignStage(1, (1,)), all_parameters[:1])
        return {"stages": ["smoke"], "smoke": smoke}

    screen = run_stage("screen", config.screen, all_parameters)
    eligible_ids = screened_policy_ids(
        matrix_promotion_pairs(screen),
        frozenset(target.target_id for target in config.targets),
    )
    eligible_parameters = tuple(
        parameters
        for parameters in all_parameters
        if _policy_id(parameters) in eligible_ids
    )
    promotion = run_stage("promotion", config.promotion, eligible_parameters)
    authoritative_decisions = tuple(
        _frozen_document(decision)
        for decision in promote(matrix_promotion_pairs(promotion))
    )
    selected = promotion_selector(promotion)
    if selected is None:
        negative = {
            "schema_version": "static-projection-promotion.v1",
            "promoted": False,
            "reason": "no-policy-promoted",
        }
        _atomic_json(output / "promotion-result.json", negative)
        return {
            "stages": ["screen", "promotion"],
            "screen": screen,
            "promotion_matrix": promotion,
            "promotion": negative,
        }
    pending_frozen = _frozen_document(selected)
    selected_parameters = _parameters(pending_frozen["parameters"])
    expected_policy_id = _policy_id(selected_parameters)
    if pending_frozen["policy_id"] != expected_policy_id:
        raise ValueError("promotion decision.policy_id does not match parameters")
    if pending_frozen["plan_hash"] != content_hash(asdict(selected_parameters)):
        raise ValueError("promotion decision.plan_hash does not match parameters")
    if expected_policy_id not in eligible_ids:
        raise ValueError("promotion decision policy did not pass screening")
    if pending_frozen not in authoritative_decisions:
        raise ValueError(
            "promotion decision does not match authoritative promotion evidence"
        )
    frozen = _freeze(selected, output / "frozen-policy.json")
    frozen_parameters = (selected_parameters,)
    validation = run_stage("validation", config.validation, frozen_parameters)
    return {
        "stages": ["screen", "promotion", "validation"],
        "screen": screen,
        "promotion": promotion,
        "frozen": frozen,
        "validation": validation,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=("smoke", "training"), default="training")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    campaign = load_campaign(args.config)
    output = _beneath_repository(args.out, "output_dir")
    runner = RfuzzExperimentRunner(ROOT.resolve(), output / "rfuzz-results")
    run_campaign(
        campaign,
        runner=runner,
        preparer=runner.prepare_manifest,
        output_dir=output,
        stage=args.stage,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
