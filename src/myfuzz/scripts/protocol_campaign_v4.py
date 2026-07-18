#!/usr/bin/env python3
"""Run the frozen protocol-only A/B/C/D v4 experiment serially."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
from typing import Mapping, Sequence

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    AddressBiasConfigV4, EnvironmentReplayLimitsV4, GeneratedTargetServerV4, InputValidationError,
    ProjectedTargetServerV4, RawBitsV4Limits, V4Controller,
    WireReplayEvidenceStoreV4, build_wire_replay_bundle_v4,
    build_component_coverage_projection_v4, build_protocol_only_experiment_manifest_v4,
    cpu_execution_profile_v4_from_dict, environment_plan_v4_from_dict,
    rawbits_v4_layout_from_dict,
    run_legacy_a_protocol_campaign_v4, run_protocol_campaign_v4,
    run_serial_protocol_abcd_v4,
)
from myfuzz.builder.contracts import coverage_abi_v2_from_dict  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one fixed-order, protocol-only A/B/C/D v4 comparison",
    )
    parser.add_argument("--baseline-target", required=True, type=Path)
    parser.add_argument("--generated-target", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--seed", required=True, type=int)
    parser.add_argument("--wall-seconds", required=True, type=float)
    parser.add_argument("--target-peak-rss-bytes", required=True, type=int)
    parser.add_argument("--cycles-per-a-testcase", type=int, default=64)
    parser.add_argument("--records-per-testcase", type=int, default=1)
    parser.add_argument("--testcase-timeout", type=float, default=30.0)
    parser.add_argument("--shutdown-grace", type=float, default=5.0)
    parser.add_argument("--resource-sample-interval", type=float, default=1.0)
    parser.add_argument("--max-resource-samples", type=int, default=4096)
    parser.add_argument("--min-available-memory", type=int, default=0)
    parser.add_argument("--max-testcases", type=int)
    parser.add_argument(
        "--checkpoints", default="",
        help="comma-separated wall-clock seconds; default is 25/50/75/100 percent",
    )
    parser.add_argument("--environment-replay-dir", type=Path)
    parser.add_argument(
        "--primary-component-prefix", action="append", default=None,
        help="component prefix included in the primary catalog; default: all components",
    )
    return parser


def run(args: argparse.Namespace) -> dict[str, object]:
    output = args.output_dir.resolve()
    if output.exists() and any(output.iterdir()):
        raise InputValidationError(f"output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    baseline = args.baseline_target.resolve(strict=True)
    generated = args.generated_target.resolve(strict=True)
    baseline_completion = _read_object(baseline / "completion_manifest.json", "baseline completion")
    generated_completion = _read_object(generated / "completion_manifest.json", "generated completion")
    baseline_abi = coverage_abi_v2_from_dict(
        _read_object(baseline / "evidence/coverage_abi.json", "baseline coverage ABI")
    )
    generated_abi = coverage_abi_v2_from_dict(
        _read_object(generated / "evidence/coverage_abi.json", "generated coverage ABI")
    )
    component_prefixes = tuple(args.primary_component_prefix or sorted({
        str(point.get("component_id", ""))
        for point in baseline_abi.points
        if point.get("included") is True and point.get("component_id")
    }))
    baseline_projection = build_component_coverage_projection_v4(
        baseline_abi, component_prefixes=component_prefixes,
    )
    generated_projection = build_component_coverage_projection_v4(
        generated_abi, component_prefixes=component_prefixes,
    )
    layout = rawbits_v4_layout_from_dict(
        _read_object(generated / "evidence/bit_layout.json", "generated RawBits layout")
    )
    _require_equal(generated_completion.get("layout_digest"), layout.digest, "layout digest")
    _require_equal(
        generated_completion.get("coverage_abi_digest"), generated_abi.manifest_digest,
        "generated coverage ABI digest",
    )
    baseline_abi_digest = baseline_completion.get("coverage_abi_digest")
    if baseline_abi_digest is not None:
        _require_equal(
            baseline_abi_digest, baseline_abi.manifest_digest, "baseline coverage ABI digest",
        )
    raw_limits = _rawbits_limits(generated_completion.get("rawbits_limits"))
    environment_limits = _environment_limits(
        generated_completion.get("environment_replay_limits")
    )
    environment_plan = _environment_plan(generated, generated_completion)
    cpu_profile = _cpu_profile(generated, generated_completion)
    replay_root = None
    if args.environment_replay_dir is not None:
        replay_root = args.environment_replay_dir.resolve(strict=True)
        if not replay_root.is_dir():
            raise InputValidationError("environment replay path must be a directory")
    replay_required = bool(environment_plan is not None and environment_plan.requires_replay)
    if replay_required != bool(replay_root is not None):
        raise InputValidationError(
            "replay-driven generated target requires exactly one environment replay directory"
        )
    if args.records_per_testcase > raw_limits.max_logical_records:
        raise InputValidationError("records per testcase exceeds the generated target limit")

    checkpoints = _checkpoints(args.checkpoints)
    baseline_digest = _sha256_text(baseline_completion.get("target_digest"), "baseline target")
    generated_digest = _sha256_text(generated_completion.get("target_digest"), "generated target")
    manifest = build_protocol_only_experiment_manifest_v4(
        experiment_id=args.experiment_id, seed=args.seed, wall_seconds=args.wall_seconds,
        baseline_coverage_abi=baseline_projection.coverage_abi,
        generated_coverage_abi=generated_projection.coverage_abi,
        baseline_target_digest=baseline_digest, generated_target_digest=generated_digest,
        target_peak_rss_bytes=args.target_peak_rss_bytes,
        min_available_memory_bytes=args.min_available_memory,
        shutdown_grace_seconds=args.shutdown_grace,
        checkpoint_seconds=checkpoints,
        baseline_cycles_per_testcase=args.cycles_per_a_testcase,
        records_per_testcase=args.records_per_testcase,
        testcase_timeout_seconds=args.testcase_timeout,
        resource_sample_interval_seconds=args.resource_sample_interval,
        max_resource_samples=args.max_resource_samples,
        max_testcases=args.max_testcases,
    )
    _write_json_atomic(output / "experiment_manifest.json", manifest.to_dict())
    _write_json_atomic(output / "invocation.json", _invocation(args))

    execution = manifest.execution_contract
    resources = manifest.resource_contract
    used_sidecars: dict[str, Mapping[str, object]] = {}
    evidence_stores: dict[str, Mapping[str, object]] = {}
    generated_attempt_counts = {policy: 0 for policy in ("B", "C", "D")}
    generation_report = _read_object(
        generated / "evidence/target_generation_report.json",
        "generated target generation report",
    )
    address_windows = generated_completion.get("campaign_address_windows", [])
    if not isinstance(address_windows, list):
        raise InputValidationError("generated target campaign address windows are malformed")
    address_bias = None
    if address_windows:
        try:
            address_bias = AddressBiasConfigV4(tuple(
                (str(item["name"]), int(item["base"]), int(item["size"]))
                for item in address_windows if isinstance(item, Mapping)
            ))
        except (KeyError, TypeError, ValueError) as exc:
            raise InputValidationError("generated target campaign address window is malformed") from exc
        if len(address_bias.windows) != len(address_windows):
            raise InputValidationError("generated target campaign address window is malformed")

    def generated_runner(policy: str):
        generated_attempt_counts[policy] += 1
        attempt = generated_attempt_counts[policy]
        evidence_root = output / "replay_evidence" / policy / f"attempt-{attempt}"
        evidence_store = WireReplayEvidenceStoreV4(
            evidence_root,
            max_entries=generated_projection.coverage_abi.width,
            max_bundle_bytes=_wire_replay_bundle_byte_limit(
                raw_limits, environment_limits, generated_abi.width,
            ),
        )
        evidence_stores[f"{policy}:{attempt}"] = {
            "root": evidence_root.as_posix(),
            "index": evidence_store.index_path.as_posix(),
        }

        def replay_for(testcase: object) -> bytes:
            testcase_id = getattr(testcase, "logical_testcase_id", None)
            if isinstance(testcase_id, bool) or not isinstance(testcase_id, int):
                raise InputValidationError("environment replay testcase identity is invalid")
            path = replay_root / policy / f"{testcase_id:016x}.env.v4"  # type: ignore[operator]
            payload = path.read_bytes()
            used_sidecars[f"{policy}:{testcase_id}"] = {
                "path": path.resolve().as_posix(), "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
            return payload

        controller = V4Controller(
            layout, policy=policy, seed=manifest.seed,
            coverage_bits=generated_projection.coverage_abi.width, limits=raw_limits,
            address_bias=address_bias,
        )
        full_server = GeneratedTargetServerV4(
            generated, layout=layout, coverage_abi=generated_abi, limits=raw_limits,
            environment_plan=environment_plan,
            environment_replay_for=replay_for if replay_required else None,
            environment_limits=environment_limits,
            cpu_profile=cpu_profile,
            timeout_seconds=float(execution["testcase_timeout_seconds"]),
        )
        server = ProjectedTargetServerV4(full_server, generated_projection)

        def record_novelty(transport, _projected_result, controller_result):
            context = full_server.replay_context_for(transport)
            bundle = build_wire_replay_bundle_v4(
                layout, transport, context.result,
                soc_digest=_sha256_text(generated_completion.get("soc_digest"), "SoC"),
                profile_digest=_sha256_text(
                    generated_completion.get("protocol_profile_digest"), "protocol profile",
                ),
                target_digest=generated_digest,
                coverage_abi=generated_abi,
                coverage_epoch=context.coverage_epoch,
                toolchain={
                    "verilator_version": generation_report.get("verilator_version"),
                    "executable_sha256": generated_completion.get("executable_sha256"),
                },
                runtime={
                    "runner_schema": generated_completion.get("runner_schema"),
                    "python_version": platform.python_version(),
                    "campaign_schema": "myfuzz.protocol-campaign-result/v4",
                },
                invocation={
                    **_invocation(args), "policy": policy,
                    "attempt": attempt, "testcase_id": controller_result.testcase_id,
                },
                random_seeds={"campaign_seed": manifest.seed},
                deterministic_initialization={
                    "schema": "myfuzz.generated-target-deterministic-initialization/v4",
                    "infrastructure_reset_edges": 2,
                    "start_edges": 1,
                    "simulator_randomization": "disabled",
                    "cpu_profile_digest": generated_completion.get("cpu_profile_digest"),
                },
                external_environment={
                    "mode": "replay" if replay_required else "constant",
                    "environment_plan_digest": generated_completion.get(
                        "environment_plan_digest"
                    ),
                },
                environment_plan=environment_plan,
                environment_replay=context.environment_replay,
                environment_limits=environment_limits,
                limits=raw_limits,
            )
            return evidence_store.record(
                bundle, testcase_id=controller_result.testcase_id,
                new_branch_count=controller_result.new_branch_count,
            )

        return run_protocol_campaign_v4(
            controller, server, wall_seconds=manifest.wall_seconds,
            records_per_testcase=int(execution["records_per_testcase"]),
            max_testcases=execution["max_testcases"],
            min_available_memory_bytes=int(resources["min_available_memory_bytes"]),
            resource_sample_interval_seconds=float(execution["resource_sample_interval_seconds"]),
            max_resource_samples=int(execution["max_resource_samples"]),
            checkpoint_seconds=manifest.checkpoint_seconds,
            novelty_evidence_recorder=record_novelty,
        )

    runners = {
        "A": lambda: run_legacy_a_protocol_campaign_v4(
            baseline, seed=manifest.seed, wall_seconds=manifest.wall_seconds,
            cycles_per_testcase=int(execution["baseline_cycles_per_testcase"]),
            max_testcases=execution["max_testcases"],
            min_available_memory_bytes=int(resources["min_available_memory_bytes"]),
            per_testcase_timeout_seconds=float(execution["testcase_timeout_seconds"]),
            shutdown_grace_seconds=manifest.shutdown_grace_seconds,
            resource_sample_interval_seconds=float(execution["resource_sample_interval_seconds"]),
            max_resource_samples=int(execution["max_resource_samples"]),
            checkpoint_seconds=manifest.checkpoint_seconds,
            coverage_projection=baseline_projection,
        ),
        **{policy: (lambda policy=policy: generated_runner(policy)) for policy in ("B", "C", "D")},
    }
    report = run_serial_protocol_abcd_v4(
        runners, manifest=manifest, output_path=output / "campaign_report.json",
    )
    references = {
        "schema": "myfuzz.protocol-artifact-references/v4",
        "baseline_target": _target_reference(baseline, baseline_completion, baseline_abi),
        "generated_target": {
            **_target_reference(generated, generated_completion, generated_abi),
            "layout_digest": layout.digest,
            "environment_plan_digest": None if environment_plan is None else environment_plan.digest,
            "cpu_profile_digest": None if cpu_profile is None else cpu_profile.digest,
            "address_bias": None if address_bias is None else address_bias.to_dict(),
        },
        "environment_sidecars": used_sidecars,
        "novelty_replay_evidence": evidence_stores,
        "coverage_projection": {
            "baseline": baseline_projection.to_dict(),
            "generated": generated_projection.to_dict(),
        },
    }
    _write_json_atomic(output / "artifact_references.json", references)
    (output / "summary.txt").write_text(_summary(report.to_dict()), encoding="ascii")
    command_report = {
        "schema": "myfuzz.protocol-campaign-command/v4", "status": report.status,
        "experiment_manifest": (output / "experiment_manifest.json").as_posix(),
        "campaign_report": (output / "campaign_report.json").as_posix(),
        "artifact_references": (output / "artifact_references.json").as_posix(),
        "summary": (output / "summary.txt").as_posix(),
        "baseline_a_affected": False,
    }
    _write_json_atomic(output / "command_report.json", command_report)
    return command_report


def _read_object(path: Path, label: str) -> Mapping[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InputValidationError(f"{label} is unreadable: {path}") from exc
    if not isinstance(value, Mapping):
        raise InputValidationError(f"{label} must be a JSON object")
    return value


def _rawbits_limits(value: object) -> RawBitsV4Limits:
    if not isinstance(value, Mapping) or set(value) != {
        "max_chunks", "max_logical_records", "max_chunk_payload_bytes", "max_testcase_bytes",
    }:
        raise InputValidationError("generated completion RawBits limits are missing or malformed")
    try:
        return RawBitsV4Limits(**dict(value))
    except TypeError as exc:
        raise InputValidationError("generated completion RawBits limits are malformed") from exc


def _environment_limits(value: object) -> EnvironmentReplayLimitsV4:
    if not isinstance(value, Mapping) or set(value) != {"max_records", "max_payload_bytes"}:
        raise InputValidationError("generated completion environment limits are missing or malformed")
    try:
        return EnvironmentReplayLimitsV4(**dict(value))
    except TypeError as exc:
        raise InputValidationError("generated completion environment limits are malformed") from exc


def _wire_replay_bundle_byte_limit(
    raw_limits: RawBitsV4Limits,
    environment_limits: EnvironmentReplayLimitsV4,
    coverage_width: int,
) -> int:
    """Bound canonical JSON without allocating buffers at the configured maxima."""
    binary_bytes = (
        raw_limits.max_testcase_bytes
        + environment_limits.max_payload_bytes
        + (coverage_width + 7) // 8
    )
    base64_bytes = 4 * ((binary_bytes + 2) // 3)
    return base64_bytes + 4 * 1024 * 1024


def _environment_plan(target: Path, completion: Mapping[str, object]):
    digest = completion.get("environment_plan_digest")
    path = target / "evidence/environment_plan.json"
    if digest is None:
        if path.exists():
            raise InputValidationError("generated target has an undeclared environment plan")
        return None
    plan = environment_plan_v4_from_dict(_read_object(path, "generated environment plan"))
    _require_equal(plan.digest, digest, "environment plan digest")
    _require_equal(plan.requires_replay, completion.get("environment_replay_required"), "environment replay requirement")
    return plan


def _cpu_profile(target: Path, completion: Mapping[str, object]):
    digest = completion.get("cpu_profile_digest")
    path = target / "evidence/cpu_execution_profile.json"
    if digest is None:
        if path.exists():
            raise InputValidationError("generated target has an undeclared CPU profile")
        return None
    profile = cpu_execution_profile_v4_from_dict(
        _read_object(path, "generated CPU execution profile")
    )
    _require_equal(profile.digest, digest, "CPU execution profile digest")
    _require_equal(
        profile.state_domain.digest,
        completion.get("cpu_state_domain_digest"),
        "CPU state-domain digest",
    )
    return profile


def _target_reference(path: Path, completion: Mapping[str, object], abi) -> dict[str, object]:
    return {
        "path": path.as_posix(), "target_digest": completion.get("target_digest"),
        "completion_sha256": hashlib.sha256(
            (path / "completion_manifest.json").read_bytes()
        ).hexdigest(),
        "coverage_abi_digest": abi.manifest_digest,
    }


def _checkpoints(value: str) -> tuple[float, ...] | None:
    if not value.strip():
        return None
    try:
        return tuple(float(item.strip()) for item in value.split(",") if item.strip())
    except ValueError as exc:
        raise InputValidationError("checkpoints must be comma-separated seconds") from exc


def _invocation(args: argparse.Namespace) -> dict[str, object]:
    return {
        "schema": "myfuzz.protocol-campaign-invocation/v4",
        **{name: value.as_posix() if isinstance(value, Path) else value for name, value in vars(args).items()},
    }


def _summary(report: Mapping[str, object]) -> str:
    lines = [
        f"status: {report['status']}",
        "order: A -> B -> C -> D",
        "coverage: branch-only",
        "warning: fixed serial order is exploratory and may retain order effects",
    ]
    variants = report.get("variants", {})
    if isinstance(variants, Mapping):
        for policy in ("A", "B", "C", "D"):
            item = variants.get(policy)
            if isinstance(item, Mapping):
                lines.append(
                    f"{policy}: coverage_hits={item.get('coverage_hits')} "
                    f"testcases={item.get('completed_count')} dut_cycles={item.get('dut_cycles')}"
                )
    invalid = report.get("invalid_variants", {})
    if invalid:
        lines.append(f"invalid_variants: {json.dumps(invalid, sort_keys=True)}")
    return "\n".join(lines) + "\n"


def _require_equal(actual: object, expected: object, label: str) -> None:
    if actual != expected:
        raise InputValidationError(f"{label} mismatch")


def _sha256_text(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(
        char not in "0123456789abcdef" for char in value
    ):
        raise InputValidationError(f"{label} digest is invalid")
    return value


def _write_json_atomic(path: Path, value: object) -> None:
    payload = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = run(args)
    except (InputValidationError, OSError, ValueError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, indent=2), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
