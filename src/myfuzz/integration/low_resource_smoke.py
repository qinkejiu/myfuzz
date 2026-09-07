"""Deterministic, in-process validation of the low-resource runtime path."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import stat
import tempfile

from myfuzz.contracts import content_hash, validate_contract
from myfuzz.composition import (
    GenericCompositionRequest,
    plan_generic_composition,
    write_generic_composition,
)
from myfuzz.experiments import (
    CONSERVATIVE_PROFILE,
    ExperimentJob,
    Job,
    JobKind,
    ResourceProfile,
    apply_resource_profile,
    load_experiment_config,
    plan_experiment,
    prepare_candidate_runtime,
)

from .experiment_matrix import BuildJobResult, FuzzJobResult, run_experiment_matrix
from .pipeline import GenerationRequest, RuntimeRequest, run_candidate_pipeline


_MEMORY_GATE_ENV = "MYFUZZ_MEMORY_GATE_DIR"
_MAX_JSON_BYTES = 16 * 1024 * 1024


def _plain_json(value: object) -> object:
    """Detach the immutable planner records into bounded JSON-shaped data."""
    if isinstance(value, Mapping):
        return {str(key): _plain_json(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain_json(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise TypeError(f"generic smoke result is not JSON-shaped: {type(value).__name__}")


def _generic_runtime_policy(
    profile: ResourceProfile, timeout_seconds: int,
) -> dict[str, object]:
    return {
        "enforcement": "metadata-only",
        "build_concurrency": profile.build_concurrency,
        "frontend_concurrency": profile.frontend_concurrency,
        "active_workers": 1,
        "waveforms": profile.waveforms,
        "replay_queue_capacity": profile.replay_queue_capacity,
        "event_ring_capacity": profile.event_ring_capacity,
        "field_groups_per_batch": profile.field_groups_per_batch,
        "soft_memory_bytes": profile.soft_memory_bytes,
        "hard_memory_bytes": profile.hard_memory_bytes,
        "timeout_seconds": timeout_seconds,
        "rss_enforcement": "not-applied-by-generic-smoke",
        "timeout_enforcement": "not-applied-by-generic-smoke",
    }


def _validate_repo_root(repo_root: Path) -> None:
    if not isinstance(repo_root, Path):
        raise TypeError("repo_root must be a pathlib.Path")
    if not repo_root.is_absolute():
        raise ValueError("repo_root must be absolute")
    try:
        metadata = repo_root.lstat()
    except OSError as error:
        raise ValueError("repo_root must be a real directory") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("repo_root must be a real directory")


def _load_json_document(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect smoke fixture: {path}") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_JSON_BYTES:
        raise ValueError(f"smoke fixture must be a bounded regular file: {path}")
    try:
        payload = path.read_bytes()
        document = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load smoke fixture: {path}") from error
    if len(payload) > _MAX_JSON_BYTES or not isinstance(document, dict):
        raise ValueError(f"smoke fixture must be a bounded object: {path}")
    return document


@contextmanager
def _temporary_memory_gate(directory: Path) -> Iterator[None]:
    previous = os.environ.get(_MEMORY_GATE_ENV)
    os.environ[_MEMORY_GATE_ENV] = str(directory)
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(_MEMORY_GATE_ENV, None)
        else:
            os.environ[_MEMORY_GATE_ENV] = previous


def _make_runner(recorded_jobs: list[Job]):
    def runner(job: Job) -> BuildJobResult | FuzzJobResult:
        recorded_jobs.append(job)
        if job.kind is JobKind.BUILD:
            return BuildJobResult(job.job_id, 1)
        if not isinstance(job, ExperimentJob) or job.kind is not JobKind.FUZZ:
            raise TypeError("low-resource smoke received an unsupported job")
        sample = {
            "job_id": job.job_id,
            "candidate_id": job.candidate_id,
            "harness": job.harness,
            "seed": job.seed,
            "elapsed_seconds": 0,
            "sequence": 0,
            "common_total": 0,
            "covered_point_ids": [],
            "tests_executed": 0,
            "cycles_executed": 0,
            "peak_rss_bytes": job.estimated_rss_bytes,
            "projection_count": 0,
            "correction_counts": {},
            "protocol_event_count": 0,
            "no_progress_cycles": 0,
            "generation_count": 0,
            "validation_passed": 0,
            "failure_reasons": {"dut_crash": 0, "resource_terminated": 0},
        }
        return FuzzJobResult(
            job.job_id,
            1,
            (sample,),
            job.estimated_rss_bytes,
        )

    return runner


def _zero_observation_manifests(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or not value:
        raise ValueError("low-resource pipeline did not return candidate manifests")
    manifests: list[dict[str, object]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ValueError("low-resource pipeline returned an invalid candidate manifest")
        manifests.append(copy.deepcopy(dict(item)))

    empty_coverage_hash = content_hash({"coverage_universe": []})
    for manifest in manifests:
        manifest["coverage_universe"] = []
        manifest["coverage_metadata_hash"] = empty_coverage_hash
        harnesses = manifest.get("harnesses")
        if isinstance(harnesses, Mapping):
            for value in harnesses.values():
                if isinstance(value, Mapping):
                    value["coverage_metadata_hash"] = empty_coverage_hash
    return manifests


def run_low_resource_smoke(
    repo_root: Path,
    *,
    report_path: Path | None = None,
    profile: ResourceProfile = CONSERVATIVE_PROFILE,
) -> dict[str, object]:
    """Run the bounded runtime smoke path without starting an external worker."""
    _validate_repo_root(repo_root)
    if report_path is not None and not isinstance(report_path, Path):
        raise TypeError("report_path must be a pathlib.Path or None")

    pipeline_config = repo_root / "configs" / "experiments" / "synthetic_opaque.json"
    planner_config_path = repo_root / "configs" / "experiments" / "ibex_opentitan.json"
    facts_path = repo_root / "tests" / "fixtures" / "runtime" / "hdl_facts.v2.runtime.json"
    composition_path = repo_root / "tests" / "fixtures" / "runtime" / "composition_ir.v1.runtime.json"
    candidate_path = repo_root / "tests" / "fixtures" / "runtime" / "candidate_manifest.v1.runtime.json"

    _load_json_document(pipeline_config)
    load_experiment_config(pipeline_config)
    planner_document = _load_json_document(planner_config_path)
    facts = _load_json_document(facts_path)
    composition = _load_json_document(composition_path)
    candidate = _load_json_document(candidate_path)
    validate_contract(facts, "hdl_facts.v2")
    validate_contract(composition, "composition_ir.v1")
    validate_contract(candidate, "candidate_manifest.v1")

    profiled_config = apply_resource_profile(planner_document, profile)
    # Validate the complete planner document before the pipeline can acquire a lease.
    plan_experiment(profiled_config, [candidate])

    with tempfile.TemporaryDirectory(prefix="myfuzz-low-resource-") as temporary:
        workspace = Path(temporary)
        output_dir = workspace / "pipeline"
        memory_state_path = workspace / "memory_tokens.json"
        memory_gate_dir = workspace / "memory-gate"
        effective_report_path = (
            workspace / "report.json" if report_path is None else report_path
        )
        recorded_jobs: list[Job] = []

        def composition_producer(_request: GenerationRequest) -> list[dict[str, object]]:
            return [copy.deepcopy(candidate)]

        def runtime_preparer(
            runtime_candidate: dict[str, object],
            _request: RuntimeRequest,
        ) -> object:
            return prepare_candidate_runtime(
                facts,
                composition,
                runtime_candidate,
                profiled_config,
                repo_root,
            )

        with _temporary_memory_gate(memory_gate_dir):
            pipeline_result = run_candidate_pipeline(
                pipeline_config,
                output_dir=output_dir,
                top_k=1,
                dry_run=True,
                composition_producer=composition_producer,
                runtime_preparer=runtime_preparer,
                memory_state_path=memory_state_path,
                repo_root=repo_root,
            )
            manifests = _zero_observation_manifests(pipeline_result["manifests"])
            manifest = manifests[0]

            plan = plan_experiment(profiled_config, manifests)
            if report_path is not None:
                report_path.parent.mkdir(parents=True, exist_ok=True)
            matrix_result = run_experiment_matrix(
                {
                    "planner_config": profiled_config,
                    "candidate_manifests": manifests,
                    "execution": {
                        "interleaving_seed": 0,
                        "max_resource_retries": 0,
                        "job_timeout_seconds": 0,
                    },
                },
                runner=_make_runner(recorded_jobs),
                report_path=effective_report_path,
            )

            build_count = sum(job.kind is JobKind.BUILD for job in recorded_jobs)
            fuzz_count = sum(job.kind is JobKind.FUZZ for job in recorded_jobs)
            summary = {
                "status": "passed",
                "profile": profile.name,
                "candidate_count": pipeline_result["candidate_count"],
                "build_jobs": build_count,
                "fuzz_jobs": fuzz_count,
                "protocols": copy.deepcopy(manifest["protocols"]),
                "dependency_graph": copy.deepcopy(manifest["dependency_graph"]),
                "runtime_policy": {
                    "build_concurrency": plan.runtime_policy.build_concurrency,
                    "frontend_concurrency": profile.frontend_concurrency,
                    "waveforms": plan.runtime_policy.waveforms,
                    "replay_queue_capacity": plan.runtime_policy.replay_queue_capacity,
                    "event_ring_capacity": plan.runtime_policy.event_ring_capacity,
                    "field_groups_per_batch": plan.runtime_policy.field_groups_per_batch,
                    "soft_memory_bytes": plan.runtime_policy.soft_memory_bytes,
                    "hard_memory_bytes": plan.runtime_policy.hard_memory_bytes,
                    "token_bytes": plan.runtime_policy.token_bytes,
                },
                "report_path": (
                    None if report_path is None else str(report_path.absolute())
                ),
                "report": copy.deepcopy(matrix_result["report"]),
            }

    return copy.deepcopy(summary)


def run_generic_composition_smoke(
    repo_root: Path,
    request: GenericCompositionRequest,
    *,
    output_dir: Path,
    component_catalog: object | None = None,
    protocol_catalog: object | None = None,
    profile: ResourceProfile = CONSERVATIVE_PROFILE,
    timeout_seconds: int = 60,
) -> dict[str, object]:
    """Run generic analysis/publication smoke and return policy metadata.

    This is a functional smoke, not an RTL simulator or an RFuzz campaign.
    It never substitutes an in-process fake DUT for a campaign.  A failed
    analysis, source check, protocol check, or publication leaves no output
    artifact and is reported in ``functional_diagnostics``.  The RSS and
    timeout values returned here are metadata; this function does not launch
    a worker and does not enforce process limits.
    """
    _validate_repo_root(repo_root)
    if not isinstance(request, GenericCompositionRequest):
        raise TypeError("request must be a GenericCompositionRequest")
    if not isinstance(output_dir, Path):
        raise TypeError("output_dir must be a pathlib.Path")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be a positive integer")
    if not isinstance(profile, ResourceProfile):
        raise TypeError("profile must be a ResourceProfile")

    runtime_policy = _generic_runtime_policy(profile, timeout_seconds)
    result: dict[str, object] = {
        "schema_version": "generic_composition_smoke.v1",
        "status": "rejected",
        "published": False,
        "artifact_paths": [],
        "annotations": {},
        "capabilities": [],
        "ir": {},
        "input_layout": {},
        "runtime_policy": runtime_policy,
        "functional_diagnostics": [],
        "resource_diagnostics": [],
    }
    try:
        plan = plan_generic_composition(
            request,
            base_dir=repo_root,
            component_catalog=component_catalog,
            protocol_catalog=protocol_catalog,
        )
        artifact = write_generic_composition(plan, output_dir, base_dir=repo_root)
        published = sorted(
            path.as_posix()
            for path in output_dir.iterdir()
            if path.is_file()
        )
        result.update(
            {
                "status": "passed",
                "published": True,
                "artifact_paths": published,
                "annotations": _plain_json(plan.annotations),
                "capabilities": _plain_json(plan.ir.get("capabilities", ())),
                "ir": _plain_json(plan.ir),
                "input_layout": _plain_json(plan.ir.get("input_layout", {})),
                "artifact": _plain_json(artifact),
                "functional_diagnostics": list(plan.diagnostics),
            }
        )
    except (OSError, TypeError, ValueError) as error:
        result["functional_diagnostics"] = [
            f"{type(error).__name__}:{error}"
        ]
        # Do not claim a partial publication.  The writer is atomic; files
        # already present at the requested destination belong to the caller
        # and are never reported as artifacts of this invocation.
        result["artifact_paths"] = []
    return copy.deepcopy(result)


__all__ = ["run_generic_composition_smoke", "run_low_resource_smoke"]
