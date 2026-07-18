"""Wall-clock bounded protocol-only v4 campaign runner and result contract."""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, field, replace
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import resource
import shutil
import subprocess
import tempfile
import time
from typing import Callable, Iterable, Mapping

from .abcd_campaign_v2 import coverage_point_catalog
from .atomic_target import FIXED_CYCLE_RUNNER_SCHEMA
from .contracts import CoverageABIV2, canonical_json
from .checkpoint_v4 import CampaignCheckpointStoreV4
from .controller_v4 import (
    ControllerResult, TargetExecutionResultV4, V4Controller, V4TargetServer,
    canonical_protocol_legality_rules_v4,
)
from .input_model import InputValidationError
from .process_monitor_v4 import TargetProcessTimeoutV4, run_polled_process_v4


@dataclass(frozen=True)
class ResourceSnapshotV4:
    cpu_count: int
    cpu_model: str
    cpu_affinity: tuple[int, ...]
    load_1m: float
    available_memory_bytes: int
    swap_total_bytes: int
    swap_free_bytes: int
    swap_used_bytes: int
    disk_free_bytes: int
    max_rss_bytes: int
    child_max_rss_bytes: int
    cpu_time_seconds: float
    child_cpu_time_seconds: float
    average_cpu_frequency_khz: int
    maximum_thermal_millicelsius: int
    throttling_event_count: int
    platform: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ProtocolCampaignResultV4:
    policy: str
    seed: int
    wall_seconds: float
    deadline_reached: bool
    status: str
    testcase_count: int
    completed_count: int
    censored_inflight: int
    coverage_bits: int
    coverage_digest: str
    lane_counts: Mapping[str, int]
    resource_before: Mapping[str, object]
    resource_after: Mapping[str, object]
    declared_lane_counts: Mapping[str, int] = field(default_factory=dict)
    observed_classification_counts: Mapping[str, int] = field(default_factory=dict)
    legality_rules: Mapping[str, int] = field(default_factory=dict)
    violation_rule_counts: Mapping[str, int] = field(default_factory=dict)
    first_violation_points: tuple[Mapping[str, object], ...] = ()
    transport_bytes: int = 0
    dut_cycles: int = 0
    wire_trace_edges: int = 0
    target_digest: str = ""
    coverage_bitmap_base64: str = ""
    coverage_hits: int = 0
    logical_records: int = 0
    accepted_records: int = 0
    record_stall_cycles: int = 0
    valid_protocol_trace_count: int = 0
    violation_count: int = 0
    resource_samples: tuple[Mapping[str, object], ...] = ()
    resource_samples_truncated: bool = False
    coverage_checkpoints: tuple[Mapping[str, object], ...] = ()
    mutation_diagnostics: Mapping[str, object] = field(default_factory=dict)
    mutation_reason_trace: tuple[Mapping[str, object], ...] = ()
    controller_manifest: Mapping[str, object] = field(default_factory=dict)
    novelty_replay_evidence: tuple[Mapping[str, object], ...] = ()
    schema: str = "myfuzz.protocol-campaign-result/v4"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class CoverageProjectionV4:
    """Dense experiment catalog projected from an unchanged target bitmap."""

    source_width: int
    source_offsets: tuple[int, ...]
    coverage_abi: CoverageABIV2
    component_prefixes: tuple[str, ...]
    schema: str = "myfuzz.coverage-projection/v4"

    def __post_init__(self) -> None:
        if self.source_width <= 0 or not self.source_offsets:
            raise InputValidationError("coverage projection dimensions are invalid")
        if len(self.source_offsets) != self.coverage_abi.width:
            raise InputValidationError("coverage projection offset count is invalid")
        if tuple(sorted(set(self.source_offsets))) != self.source_offsets:
            raise InputValidationError("coverage projection offsets must be ordered and unique")
        if self.source_offsets[-1] >= self.source_width:
            raise InputValidationError("coverage projection offset exceeds source width")
        if not self.component_prefixes or any(not item for item in self.component_prefixes):
            raise InputValidationError("coverage projection prefixes must be non-empty")

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["coverage_abi"] = self.coverage_abi.to_dict()
        return value


def build_component_coverage_projection_v4(
    abi: CoverageABIV2,
    *,
    component_prefixes: tuple[str, ...] = ("ip.",),
) -> CoverageProjectionV4:
    """Select target components without changing target execution or instrumentation."""
    if not component_prefixes or any(not isinstance(item, str) or not item for item in component_prefixes):
        raise InputValidationError("coverage projection prefixes must be non-empty strings")
    selected = sorted(
        (
            dict(point) for point in abi.points
            if point.get("included") is True
            and str(point.get("component_id", "")).startswith(component_prefixes)
        ),
        key=lambda point: int(point["offset"]),
    )
    if not selected:
        raise InputValidationError("coverage projection selected no primary points")
    source_offsets = tuple(int(point["offset"]) for point in selected)
    projected_points = []
    for offset, point in enumerate(selected):
        point["source_offset"] = int(point["offset"])
        point["offset"] = offset
        projected_points.append(point)
    digest_points = tuple(
        {key: value for key, value in point.items() if key != "source_offset"}
        for point in projected_points
    )
    digest_payload = {
        "schema": "myfuzz.coverage-abi/v2",
        "port_name": abi.port_name,
        "width": len(projected_points),
        "epoch_width": abi.epoch_width,
        "writer": abi.writer,
        "sampling": abi.sampling,
        "points": digest_points,
    }
    projected = CoverageABIV2(
        hashlib.sha256(canonical_json(digest_payload)).hexdigest(),
        abi.port_name,
        len(projected_points),
        abi.epoch_width,
        tuple(projected_points),
        transport_width=abi.width,
        writer=abi.writer,
        sampling=abi.sampling,
    )
    return CoverageProjectionV4(
        abi.width, source_offsets, projected, tuple(component_prefixes),
    )


def project_coverage_bitmap_v4(bitmap: bytes, projection: CoverageProjectionV4) -> bytes:
    expected = (projection.source_width + 7) // 8
    if not isinstance(bitmap, bytes) or len(bitmap) != expected:
        raise InputValidationError("coverage projection source bitmap width mismatch")
    result = bytearray((projection.coverage_abi.width + 7) // 8)
    for target_offset, source_offset in enumerate(projection.source_offsets):
        if bitmap[source_offset // 8] & (1 << (source_offset % 8)):
            result[target_offset // 8] |= 1 << (target_offset % 8)
    return bytes(result)


class ProjectedTargetServerV4:
    """Project coverage returned by a target while preserving all run metadata."""

    def __init__(self, server: V4TargetServer, projection: CoverageProjectionV4) -> None:
        self.server = server
        self.projection = projection
        self.target_digest = str(getattr(server, "target_digest", ""))
        self.legality_rules = dict(getattr(server, "legality_rules", {}))

    def handle_result(self, transport: bytes, **kwargs: object) -> TargetExecutionResultV4:
        result = self.server.handle_result(transport, **kwargs)
        return replace(
            result,
            coverage_bitmap=project_coverage_bitmap_v4(
                result.coverage_bitmap, self.projection,
            ),
        )


@dataclass(frozen=True)
class SerialProtocolCampaignResultV4:
    """One fixed-order A/B/C/D protocol-only campaign report."""

    order: tuple[str, ...]
    status: str
    variants: Mapping[str, Mapping[str, object]]
    invalid_variants: Mapping[str, str]
    resource_before: Mapping[str, object]
    resource_after: Mapping[str, object]
    experiment_manifest_digest: str
    failure_classes: Mapping[str, str] = field(default_factory=dict)
    attempt_counts: Mapping[str, int] = field(default_factory=dict)
    branch_coverage_only: bool = True
    schema: str = "myfuzz.serial-protocol-campaign/v4"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ProtocolOnlyExperimentManifestV4:
    experiment_id: str
    seed: int
    wall_seconds: float
    shutdown_grace_seconds: float
    checkpoint_seconds: tuple[float, ...]
    order: tuple[str, ...]
    coverage_catalog: Mapping[str, object]
    target_digests: Mapping[str, str]
    resource_contract: Mapping[str, object]
    execution_contract: Mapping[str, object]
    digest: str = ""
    schema: str = "myfuzz.protocol-only-experiment/v4"

    def __post_init__(self) -> None:
        if self.schema != "myfuzz.protocol-only-experiment/v4":
            raise InputValidationError("protocol-only experiment schema mismatch")
        if not isinstance(self.experiment_id, str) or not self.experiment_id.strip():
            raise InputValidationError("protocol-only experiment_id must be non-empty")
        if isinstance(self.seed, bool) or not isinstance(self.seed, int) or self.seed < 0:
            raise InputValidationError("protocol-only experiment seed is invalid")
        for name in ("wall_seconds", "shutdown_grace_seconds"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
                raise InputValidationError(f"protocol-only {name} must be positive")
        _validate_checkpoint_seconds(self.checkpoint_seconds, float(self.wall_seconds))
        if self.order != ("A", "B", "C", "D"):
            raise InputValidationError("protocol-only experiment order must be A/B/C/D")
        _validate_coverage_catalog(self.coverage_catalog)
        if set(self.target_digests) != set(self.order):
            raise InputValidationError("protocol-only target digests must define A/B/C/D")
        for value in self.target_digests.values():
            _digest(value, "protocol-only target digest")
        if len({self.target_digests[name] for name in ("B", "C", "D")}) != 1:
            raise InputValidationError("protocol-only B/C/D must use the same target digest")
        _validate_resource_contract(self.resource_contract)
        _validate_execution_contract(self.execution_contract)
        if self.digest and self.digest != _content_digest(self.payload_dict()):
            raise InputValidationError("protocol-only experiment manifest digest mismatch")

    def payload_dict(self) -> dict[str, object]:
        value = asdict(self)
        value.pop("digest")
        return value

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class VariantFeasibilityFailureV4(Exception):
    """A variant exhausted or violated its own frozen resource/timeout contract."""


class ExternalInfrastructureFailureV4(Exception):
    """A pre-registered machine or external-service failure invalidated the run."""


class _ResourceSamplerV4:
    def __init__(self, interval_seconds: float, max_samples: int) -> None:
        if (
            isinstance(interval_seconds, bool)
            or not isinstance(interval_seconds, (int, float))
            or interval_seconds <= 0
        ):
            raise InputValidationError("v4 resource sample interval must be positive")
        if isinstance(max_samples, bool) or not isinstance(max_samples, int) or max_samples <= 0:
            raise InputValidationError("v4 maximum resource sample count must be positive")
        self.interval_seconds = float(interval_seconds)
        self.max_samples = max_samples
        self.started = time.monotonic()
        self.next_sample = self.started
        self.samples: list[Mapping[str, object]] = []
        self.truncated = False

    def poll(self) -> None:
        now = time.monotonic()
        if now < self.next_sample:
            return
        self.next_sample = now + self.interval_seconds
        if len(self.samples) >= self.max_samples:
            self.truncated = True
            return
        sample = snapshot_resources().to_dict()
        sample["elapsed_seconds"] = max(0.0, now - self.started)
        self.samples.append(sample)


class _CoverageCheckpointsV4:
    def __init__(
        self, checkpoint_seconds: tuple[float, ...], wall_seconds: float,
        initial_values: tuple[Mapping[str, object], ...] = (),
    ) -> None:
        _validate_checkpoint_seconds(checkpoint_seconds, wall_seconds, allow_empty=True)
        self.seconds = tuple(float(value) for value in checkpoint_seconds)
        self.values: list[Mapping[str, object]] = [dict(item) for item in initial_values]
        self.index = len(self.values)
        if self.index > len(self.seconds) or any(
            item.get("seconds") != self.seconds[index]
            or isinstance(item.get("coverage_hits"), bool)
            or not isinstance(item.get("coverage_hits"), int)
            or item["coverage_hits"] < 0
            for index, item in enumerate(self.values)
        ):
            raise InputValidationError("protocol campaign checkpoint history is malformed")

    def before_completion(self, elapsed_seconds: float, coverage_hits: int) -> None:
        while self.index < len(self.seconds) and self.seconds[self.index] <= elapsed_seconds:
            self.values.append({
                "seconds": self.seconds[self.index],
                "coverage_hits": coverage_hits,
            })
            self.index += 1

    def finish(self, coverage_hits: int) -> None:
        while self.index < len(self.seconds):
            self.values.append({
                "seconds": self.seconds[self.index],
                "coverage_hits": coverage_hits,
            })
            self.index += 1


def build_protocol_only_experiment_manifest_v4(
    *,
    experiment_id: str,
    seed: int,
    wall_seconds: float,
    baseline_coverage_abi: CoverageABIV2,
    generated_coverage_abi: CoverageABIV2,
    baseline_target_digest: str,
    generated_target_digest: str,
    target_peak_rss_bytes: int,
    memory_safety_numerator: int = 2,
    memory_safety_denominator: int = 1,
    min_available_memory_bytes: int = 0,
    shutdown_grace_seconds: float = 5.0,
    checkpoint_seconds: tuple[float, ...] | None = None,
    baseline_cycles_per_testcase: int = 64,
    records_per_testcase: int = 1,
    testcase_timeout_seconds: float = 30.0,
    resource_sample_interval_seconds: float = 1.0,
    max_resource_samples: int = 4096,
    max_testcases: int | None = None,
) -> ProtocolOnlyExperimentManifestV4:
    baseline_catalog = coverage_point_catalog(baseline_coverage_abi.to_dict())
    generated_catalog = coverage_point_catalog(generated_coverage_abi.to_dict())
    if baseline_catalog != generated_catalog:
        raise InputValidationError(
            "protocol-only A and generated targets do not share the coverage catalog"
        )
    for name, value in (
        ("target_peak_rss_bytes", target_peak_rss_bytes),
        ("memory_safety_numerator", memory_safety_numerator),
        ("memory_safety_denominator", memory_safety_denominator),
        ("min_available_memory_bytes", min_available_memory_bytes),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value < (1 if name != "min_available_memory_bytes" else 0):
            raise InputValidationError(f"protocol-only {name} is invalid")
    required_memory = max(
        min_available_memory_bytes,
        (target_peak_rss_bytes * memory_safety_numerator + memory_safety_denominator - 1)
        // memory_safety_denominator,
    )
    affinity = tuple(sorted(os.sched_getaffinity(0))) if hasattr(os, "sched_getaffinity") else tuple(range(os.cpu_count() or 1))
    resource_contract = {
        "schema": "myfuzz.protocol-resource-contract/v4",
        "cpu_affinity": affinity,
        "thread_count": 1,
        "build_jobs": 1,
        "execution_processes": 1,
        "target_peak_rss_bytes": target_peak_rss_bytes,
        "memory_safety_numerator": memory_safety_numerator,
        "memory_safety_denominator": memory_safety_denominator,
        "min_available_memory_bytes": required_memory,
    }
    frozen_checkpoints = checkpoint_seconds
    if frozen_checkpoints is None:
        frozen_checkpoints = tuple(float(wall_seconds) * index / 4 for index in range(1, 5))
    _validate_checkpoint_seconds(frozen_checkpoints, float(wall_seconds))
    execution_contract = {
        "schema": "myfuzz.protocol-execution-contract/v4",
        "baseline_cycles_per_testcase": baseline_cycles_per_testcase,
        "records_per_testcase": records_per_testcase,
        "testcase_timeout_seconds": testcase_timeout_seconds,
        "resource_sample_interval_seconds": resource_sample_interval_seconds,
        "max_resource_samples": max_resource_samples,
        "max_testcases": max_testcases,
        "completion_rule": "completion-before-deadline",
    }
    _validate_execution_contract(execution_contract)
    value = ProtocolOnlyExperimentManifestV4(
        experiment_id, seed, wall_seconds, shutdown_grace_seconds,
        tuple(frozen_checkpoints), ("A", "B", "C", "D"), baseline_catalog,
        {
            "A": baseline_target_digest,
            "B": generated_target_digest,
            "C": generated_target_digest,
            "D": generated_target_digest,
        },
        resource_contract, execution_contract,
    )
    return ProtocolOnlyExperimentManifestV4(
        **{**value.payload_dict(), "digest": _content_digest(value.payload_dict())}
    )


def run_serial_protocol_abcd_v4(
    runners: Mapping[str, Callable[[], ProtocolCampaignResultV4]],
    *,
    manifest: ProtocolOnlyExperimentManifestV4,
    order: tuple[str, ...] = ("A", "B", "C", "D"),
    require_all: bool = True,
    output_path: str | Path | None = None,
) -> SerialProtocolCampaignResultV4:
    """Run supplied variants serially and preserve infrastructure failures.

    The callable boundary keeps A's legacy runner independent from the v4
    controller while making ordering and resource accounting explicit.
    """
    manifest.__post_init__()
    if tuple(order) != manifest.order or set(runners) != set(order):
        raise InputValidationError("serial protocol campaign requires exactly A/B/C/D runners")
    before = snapshot_resources().to_dict()
    required_memory = int(manifest.resource_contract["min_available_memory_bytes"])
    if before["available_memory_bytes"] and before["available_memory_bytes"] < required_memory:
        raise InputValidationError("serial protocol campaign resource preflight rejected memory")
    current_affinity = tuple(sorted(os.sched_getaffinity(0))) if hasattr(os, "sched_getaffinity") else tuple(range(os.cpu_count() or 1))
    if current_affinity != tuple(manifest.resource_contract["cpu_affinity"]):
        raise InputValidationError("serial protocol campaign CPU affinity drifted")
    variants: dict[str, Mapping[str, object]] = {}
    invalid: dict[str, str] = {}
    failure_classes: dict[str, str] = {}
    attempt_counts: dict[str, int] = {}
    for name in order:
        attempt_counts[name] = 0
        for attempt in range(2):
            attempt_counts[name] += 1
            try:
                result = runners[name]()
                if not isinstance(result, ProtocolCampaignResultV4):
                    raise InputValidationError(f"variant {name} runner returned an invalid result")
                _validate_variant_result(name, result, manifest)
                variants[name] = result.to_dict()
                break
            except VariantFeasibilityFailureV4 as exc:
                invalid[name] = str(exc)
                failure_classes[name] = "variant_feasibility_failure"
                break
            except ExternalInfrastructureFailureV4 as exc:
                if attempt == 0:
                    continue
                invalid[name] = str(exc)
                failure_classes[name] = "external_infrastructure_failure"
                break
            except Exception as exc:
                invalid[name] = str(exc)
                failure_classes[name] = "infrastructure_invalid"
                break
        if name in invalid and (require_all or failure_classes[name] == "variant_feasibility_failure"):
            break
    after = snapshot_resources().to_dict()
    status = "valid" if not invalid and len(variants) == len(order) else "infrastructure_invalid"
    if "variant_feasibility_failure" in failure_classes.values():
        status = "variant_feasibility_failure"
    report = SerialProtocolCampaignResultV4(
        tuple(order), status, variants, invalid, before, after, manifest.digest,
        failure_classes, attempt_counts,
    )
    if output_path is not None:
        _write_json_atomic(Path(output_path), {
            "experiment_manifest": manifest.to_dict(),
            "report": report.to_dict(),
            "report_digest": _content_digest(report.to_dict()),
        })
    return report


def snapshot_resources() -> ResourceSnapshotV4:
    mem = _proc_meminfo()
    usage = resource.getrusage(resource.RUSAGE_SELF)
    child_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    disk = shutil.disk_usage(os.getcwd())
    load = os.getloadavg()[0] if hasattr(os, "getloadavg") else 0.0
    swap_total = mem.get("SwapTotal", 0) * 1024
    swap_free = mem.get("SwapFree", 0) * 1024
    return ResourceSnapshotV4(
        cpu_count=os.cpu_count() or 1,
        cpu_model=_cpu_model(),
        cpu_affinity=tuple(sorted(os.sched_getaffinity(0))) if hasattr(os, "sched_getaffinity") else tuple(range(os.cpu_count() or 1)),
        load_1m=float(load),
        available_memory_bytes=mem.get("MemAvailable", 0) * 1024,
        swap_total_bytes=swap_total,
        swap_free_bytes=swap_free,
        swap_used_bytes=max(0, swap_total - swap_free),
        disk_free_bytes=int(disk.free),
        max_rss_bytes=int(usage.ru_maxrss) * (1024 if platform.system() != "Darwin" else 1),
        child_max_rss_bytes=int(child_usage.ru_maxrss) * (1024 if platform.system() != "Darwin" else 1),
        cpu_time_seconds=float(usage.ru_utime + usage.ru_stime),
        child_cpu_time_seconds=float(child_usage.ru_utime + child_usage.ru_stime),
        average_cpu_frequency_khz=_average_integer_files(
            Path("/sys/devices/system/cpu").glob("cpu[0-9]*/cpufreq/scaling_cur_freq")
        ),
        maximum_thermal_millicelsius=_maximum_integer_files(
            Path("/sys/class/thermal").glob("thermal_zone*/temp")
        ),
        throttling_event_count=_sum_integer_files(
            Path("/sys/devices/system/cpu").glob("cpu[0-9]*/thermal_throttle/*_throttle_count")
        ),
        platform=platform.platform(),
    )


def run_legacy_a_protocol_campaign_v4(
    target_dir: str | Path,
    *,
    seed: int,
    wall_seconds: float,
    cycles_per_testcase: int,
    max_testcases: int | None = None,
    min_available_memory_bytes: int = 0,
    per_testcase_timeout_seconds: float = 30.0,
    shutdown_grace_seconds: float = 5.0,
    max_testcase_bytes: int = 64 * 1024 * 1024,
    resource_sample_interval_seconds: float = 1.0,
    max_resource_samples: int = 4096,
    checkpoint_seconds: tuple[float, ...] = (),
    coverage_projection: CoverageProjectionV4 | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> ProtocolCampaignResultV4:
    """Run the untouched fixed-cycle A binary under the v4 wall-clock contract."""
    for name, value in (
        ("seed", seed), ("cycles_per_testcase", cycles_per_testcase),
        ("min_available_memory_bytes", min_available_memory_bytes),
        ("max_testcase_bytes", max_testcase_bytes),
    ):
        minimum = 0 if name in {"seed", "min_available_memory_bytes"} else 1
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            raise InputValidationError(f"legacy A {name} is invalid")
    for name, value in (
        ("wall_seconds", wall_seconds),
        ("per_testcase_timeout_seconds", per_testcase_timeout_seconds),
        ("shutdown_grace_seconds", shutdown_grace_seconds),
    ):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            raise InputValidationError(f"legacy A {name} must be positive")
    if max_testcases is not None and (
        isinstance(max_testcases, bool) or not isinstance(max_testcases, int) or max_testcases < 0
    ):
        raise InputValidationError("legacy A max_testcases is invalid")
    target = Path(target_dir).resolve(strict=True)
    completion = _read_json(target / "completion_manifest.json", "legacy A completion")
    if completion.get("runner_schema") != FIXED_CYCLE_RUNNER_SCHEMA:
        raise InputValidationError("legacy A requires the fixed DUT-cycle runner")
    target_digest = str(completion.get("target_digest", ""))
    _digest(target_digest, "legacy A target digest")
    layout = _read_json(target / "evidence/bit_layout.json", "legacy A bit layout")
    coverage_abi = _read_json(target / "evidence/coverage_abi.json", "legacy A coverage ABI")
    try:
        bytes_per_cycle = int(layout["bytes_per_cycle"])
        cycle_width = int(layout["cycle_width"])
        target_coverage_bits = int(coverage_abi["width"])
    except (KeyError, TypeError, ValueError) as exc:
        raise InputValidationError("legacy A evidence geometry is malformed") from exc
    if bytes_per_cycle <= 0 or cycle_width <= 0 or target_coverage_bits <= 0:
        raise InputValidationError("legacy A evidence geometry is invalid")
    if coverage_projection is not None and coverage_projection.source_width != target_coverage_bits:
        raise InputValidationError("legacy A coverage projection source width mismatch")
    coverage_bits = (
        target_coverage_bits if coverage_projection is None
        else coverage_projection.coverage_abi.width
    )
    testcase_bytes = bytes_per_cycle * cycles_per_testcase
    if testcase_bytes > max_testcase_bytes:
        raise InputValidationError("legacy A testcase exceeds the frozen byte limit")
    target_coverage_bytes = (target_coverage_bits + 7) // 8
    coverage_bytes = (coverage_bits + 7) // 8
    before = snapshot_resources()
    if before.available_memory_bytes and before.available_memory_bytes < min_available_memory_bytes:
        raise InputValidationError("legacy A resource preflight rejected available memory")
    started = clock()
    deadline = started + float(wall_seconds)
    sampler = _ResourceSamplerV4(resource_sample_interval_seconds, max_resource_samples)
    checkpoints = _CoverageCheckpointsV4(checkpoint_seconds, float(wall_seconds))
    union = bytearray(coverage_bytes)
    dispatched = completed_count = censored = transport_bytes = dut_cycles = 0
    accepted_records = stall_cycles = 0
    with tempfile.TemporaryDirectory(prefix="myfuzz-legacy-a-v4-") as directory:
        work = Path(directory)
        while clock() < deadline and (max_testcases is None or dispatched < max_testcases):
            rawbits = _legacy_a_rawbits(seed, dispatched, cycles_per_testcase, bytes_per_cycle)
            rawbits_path = work / "input.rawbits"
            coverage_path = work / "coverage.bin"
            trace_path = work / "trace.bin"
            metrics_path = work / "metrics.json"
            rawbits_path.write_bytes(rawbits)
            for path in (coverage_path, trace_path, metrics_path):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            remaining_with_grace = max(0.001, deadline - clock() + shutdown_grace_seconds)
            try:
                completed = run_polled_process_v4(
                    [
                        target / "bin/myfuzz_target", rawbits_path,
                        str(cycles_per_testcase), "0", coverage_path, trace_path, metrics_path,
                    ],
                    cwd=target,
                    timeout_seconds=min(per_testcase_timeout_seconds, remaining_with_grace),
                    poll_callback=sampler.poll,
                    poll_interval_seconds=resource_sample_interval_seconds,
                )
            except subprocess.TimeoutExpired as exc:
                raise VariantFeasibilityFailureV4("legacy A testcase exceeded its timeout") from exc
            dispatched += 1
            transport_bytes += len(rawbits)
            if completed.returncode:
                raise VariantFeasibilityFailureV4(
                    f"legacy A target failed with exit code {completed.returncode}: "
                    f"{completed.stderr.strip() or completed.stdout.strip()}"
                )
            frozen = coverage_path.read_bytes()
            trace = trace_path.read_bytes()
            metrics = _read_json(metrics_path, "legacy A metrics")
            if len(frozen) != target_coverage_bytes or len(trace) != cycles_per_testcase * target_coverage_bytes:
                raise VariantFeasibilityFailureV4("legacy A target returned invalid coverage geometry")
            if frozen != trace[-target_coverage_bytes:]:
                raise VariantFeasibilityFailureV4("legacy A coverage was not frozen at the final edge")
            if coverage_projection is not None:
                frozen = project_coverage_bitmap_v4(frozen, coverage_projection)
            if metrics.get("schema") != "myfuzz.fixed-dut-cycle-metrics/v1":
                raise VariantFeasibilityFailureV4("legacy A metrics schema mismatch")
            try:
                current_dut_cycles = int(metrics["dut_cycles"])
                current_accepted = int(metrics["accepted_records"])
                current_stalls = int(metrics["stall_cycles"])
            except (KeyError, TypeError, ValueError) as exc:
                raise VariantFeasibilityFailureV4("legacy A metrics are malformed") from exc
            if (
                current_dut_cycles != cycles_per_testcase
                or current_accepted + current_stalls != cycles_per_testcase
            ):
                raise VariantFeasibilityFailureV4("legacy A metrics violate fixed-cycle accounting")
            completion_time = clock()
            checkpoints.before_completion(
                max(0.0, completion_time - started),
                sum(value.bit_count() for value in union),
            )
            if completion_time > deadline:
                censored += 1
                break
            for index, value in enumerate(frozen):
                union[index] |= value
            completed_count += 1
            dut_cycles += current_dut_cycles
            accepted_records += current_accepted
            stall_cycles += current_stalls
    if coverage_bits % 8:
        union[-1] &= (1 << (coverage_bits % 8)) - 1
    after = snapshot_resources()
    bitmap = bytes(union)
    checkpoints.finish(sum(value.bit_count() for value in bitmap))
    status = "completed" if not censored else "completed_with_censored_inflight"
    return ProtocolCampaignResultV4(
        policy="A", seed=seed, wall_seconds=max(0.0, clock() - started),
        deadline_reached=clock() >= deadline, status=status,
        testcase_count=dispatched, completed_count=completed_count,
        censored_inflight=censored, coverage_bits=coverage_bits,
        coverage_digest=hashlib.sha256(bitmap).hexdigest(),
        lane_counts={"RAW_ESCAPE": dispatched},
        resource_before=before.to_dict(), resource_after=after.to_dict(),
        declared_lane_counts={"RAW_ESCAPE": dispatched},
        observed_classification_counts={"raw": completed_count},
        transport_bytes=transport_bytes, dut_cycles=dut_cycles,
        wire_trace_edges=dut_cycles, target_digest=target_digest,
        coverage_bitmap_base64=base64.b64encode(bitmap).decode("ascii"),
        coverage_hits=sum(value.bit_count() for value in bitmap),
        logical_records=accepted_records, accepted_records=accepted_records,
        record_stall_cycles=stall_cycles,
        resource_samples=tuple(sampler.samples),
        resource_samples_truncated=sampler.truncated,
        coverage_checkpoints=tuple(checkpoints.values),
        mutation_diagnostics={},
    )


def run_protocol_campaign_v4(
    controller: V4Controller,
    server: V4TargetServer,
    *,
    wall_seconds: float,
    records_per_testcase: int = 1,
    max_testcases: int | None = None,
    min_available_memory_bytes: int = 0,
    resource_sample_interval_seconds: float = 1.0,
    max_resource_samples: int = 4096,
    checkpoint_seconds: tuple[float, ...] = (),
    decision_checkpoint_store: CampaignCheckpointStoreV4 | None = None,
    decision_checkpoint_interval_testcases: int | None = None,
    resume_progress: Mapping[str, object] | None = None,
    novelty_evidence_recorder: Callable[
        [bytes, TargetExecutionResultV4, ControllerResult], Mapping[str, object]
    ] | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> ProtocolCampaignResultV4:
    if not isinstance(wall_seconds, (int, float)) or isinstance(wall_seconds, bool) or wall_seconds <= 0:
        raise InputValidationError("protocol campaign wall_seconds must be positive")
    if max_testcases is not None and (isinstance(max_testcases, bool) or max_testcases < 0):
        raise InputValidationError("protocol campaign max_testcases must be non-negative")
    if (decision_checkpoint_store is None) != (
        decision_checkpoint_interval_testcases is None
    ):
        raise InputValidationError(
            "decision checkpoint store and interval must be configured together"
        )
    if decision_checkpoint_interval_testcases is not None and (
        isinstance(decision_checkpoint_interval_testcases, bool)
        or not isinstance(decision_checkpoint_interval_testcases, int)
        or decision_checkpoint_interval_testcases <= 0
    ):
        raise InputValidationError("decision checkpoint interval must be positive")
    progress = _restore_campaign_progress_v4(
        resume_progress, controller=controller, server=server,
        records_per_testcase=records_per_testcase, wall_seconds=float(wall_seconds),
        checkpoint_seconds=checkpoint_seconds,
    )
    current_before = snapshot_resources()
    if current_before.available_memory_bytes and current_before.available_memory_bytes < min_available_memory_bytes:
        raise InputValidationError("protocol campaign resource preflight rejected available memory")
    resource_before = progress.get("resource_before") or current_before.to_dict()
    prior_active_seconds = float(progress["active_seconds"])
    prior_completed = int(progress["completed_count"])
    observed = dict(progress["observed_classification_counts"])
    transport_bytes = int(progress["transport_bytes"])
    dut_cycles = int(progress["dut_cycles"])
    wire_trace_edges = int(progress["wire_trace_edges"])
    logical_records = int(progress["logical_records"])
    accepted_records = int(progress["accepted_records"])
    record_stall_cycles = int(progress["record_stall_cycles"])
    violation_count = int(progress["violation_count"])
    violation_rule_counts = dict(progress["violation_rule_counts"])
    first_violation_by_rule = {
        int(item["rule_id"]): dict(item) for item in progress["first_violation_points"]
    }
    legality_rules = dict(getattr(server, "legality_rules", {}))
    rule_names_by_id = {rule_id: name for name, rule_id in legality_rules.items()}
    mutation_reason_trace = [dict(item) for item in progress["mutation_reason_trace"]]
    novelty_replay_evidence = [
        dict(item) for item in progress["novelty_replay_evidence"]
    ]
    prior_resource_samples = [dict(item) for item in progress["resource_samples"]]
    prior_samples_truncated = bool(progress["resource_samples_truncated"])
    started = clock()
    remaining_seconds = max(0.0, float(wall_seconds) - prior_active_seconds)
    deadline = started + remaining_seconds
    sampler = _ResourceSamplerV4(resource_sample_interval_seconds, max_resource_samples)
    checkpoints = _CoverageCheckpointsV4(
        checkpoint_seconds, float(wall_seconds),
        tuple(progress["coverage_checkpoints"]),
    )
    completed = 0
    censored = 0
    dispatch_count = prior_completed
    last_active_seconds = prior_active_seconds

    def campaign_progress() -> Mapping[str, object]:
        samples = prior_resource_samples + [
            {**item, "elapsed_seconds": prior_active_seconds + float(item["elapsed_seconds"])}
            for item in sampler.samples
        ]
        truncated = prior_samples_truncated or sampler.truncated or len(samples) > max_resource_samples
        samples = samples[:max_resource_samples]
        return {
            "schema": "myfuzz.protocol-campaign-progress/v4",
            "policy": controller.policy.name,
            "seed": controller.seed,
            "target_digest": str(getattr(server, "target_digest", "")),
            "records_per_testcase": records_per_testcase,
            "wall_seconds": float(wall_seconds),
            "checkpoint_seconds": list(checkpoint_seconds),
            "active_seconds": last_active_seconds,
            "completed_count": prior_completed + completed,
            "observed_classification_counts": dict(sorted(observed.items())),
            "legality_rules": dict(sorted(legality_rules.items())),
            "transport_bytes": transport_bytes,
            "dut_cycles": dut_cycles,
            "wire_trace_edges": wire_trace_edges,
            "logical_records": logical_records,
            "accepted_records": accepted_records,
            "record_stall_cycles": record_stall_cycles,
            "violation_count": violation_count,
            "violation_rule_counts": dict(sorted(violation_rule_counts.items())),
            "first_violation_points": [
                dict(first_violation_by_rule[rule_id])
                for rule_id in sorted(first_violation_by_rule)
            ],
            "mutation_reason_trace": [dict(item) for item in mutation_reason_trace],
            "novelty_replay_evidence": [
                dict(item) for item in novelty_replay_evidence
            ],
            "resource_before": dict(resource_before),
            "resource_samples": samples,
            "resource_samples_truncated": truncated,
            "coverage_checkpoints": [dict(item) for item in checkpoints.values],
        }

    while clock() < deadline and (max_testcases is None or dispatch_count < max_testcases):
        stopped = False
        completed_execution: tuple[bytes, TargetExecutionResultV4] | None = None
        def dispatch(payload: bytes) -> TargetExecutionResultV4:
            nonlocal completed_execution
            nonlocal stopped, last_active_seconds
            if clock() >= deadline:
                stopped = True
                raise _DeadlineReached
            execution = server.handle_result(
                payload, poll_callback=sampler.poll,
                poll_interval_seconds=resource_sample_interval_seconds,
            )
            completion_time = clock()
            last_active_seconds = min(
                float(wall_seconds),
                prior_active_seconds + max(0.0, completion_time - started),
            )
            checkpoints.before_completion(
                last_active_seconds,
                sum(byte.bit_count() for byte in controller.coverage.snapshot()),
            )
            if completion_time > deadline:
                raise _LateCompletion
            completed_execution = (payload, execution)
            return execution
        try:
            controller.run(dispatch, testcase_count=1, records_per_testcase=records_per_testcase)
        except _DeadlineReached:
            # The controller has already selected and accounted for the lane before
            # dispatch checks the deadline. Keep that prepared testcase censored so
            # testcase and lane accounting remain closed at the boundary.
            dispatch_count += 1
            censored += 1
            break
        except _LateCompletion:
            dispatch_count += 1
            censored += 1
            break
        except TargetProcessTimeoutV4 as exc:
            raise VariantFeasibilityFailureV4(str(exc)) from exc
        dispatch_count += 1
        completed += 1
        item = controller.results[-1]
        if item.new_branch_count > 0 and novelty_evidence_recorder is not None:
            if completed_execution is None:
                raise InputValidationError("novelty replay evidence lacks completed execution")
            evidence = novelty_evidence_recorder(
                completed_execution[0], completed_execution[1], item,
            )
            if not isinstance(evidence, Mapping):
                raise InputValidationError("novelty replay evidence recorder returned malformed data")
            novelty_replay_evidence.append(dict(evidence))
        observed[item.observed_classification] = observed.get(item.observed_classification, 0) + 1
        transport_bytes += item.transport_bytes
        dut_cycles += item.dut_cycles
        wire_trace_edges += item.wire_trace_edges
        logical_records += item.logical_records
        accepted_records += item.accepted_records
        record_stall_cycles += item.record_stall_cycles
        if item.violation_rule is not None:
            if legality_rules and item.violation_rule not in rule_names_by_id:
                raise InputValidationError(
                    "target reported a violation rule absent from its legality evidence"
                )
            violation_count += 1
            rule_name = rule_names_by_id.get(item.violation_rule, f"RULE_{item.violation_rule}")
            violation_rule_counts[rule_name] = violation_rule_counts.get(rule_name, 0) + 1
            first_violation_by_rule.setdefault(item.violation_rule, {
                "testcase_id": item.testcase_id,
                "declared_lane": item.declared_lane,
                "observed_classification": item.observed_classification,
                "rule_id": item.violation_rule,
                "rule_name": rule_name,
                "cycle": item.violation_cycle,
            })
        if item.mutation_operator is not None:
            mutation_reason_trace.append(_mutation_reason_v4(item))
        # Campaign accounting is cumulative; retaining every ControllerResult here
        # only makes resident memory grow with runtime. Keep the latest completed
        # result for diagnostics and late-completion semantics.
        controller.results[:] = [item]
        if (
            decision_checkpoint_store is not None
            and (prior_completed + completed) % decision_checkpoint_interval_testcases == 0
        ):
            decision_checkpoint_store.commit_campaign(controller, campaign_progress())
    ended = clock()
    last_active_seconds = min(
        float(wall_seconds),
        max(last_active_seconds, prior_active_seconds + max(0.0, ended - started)),
    )
    checkpoints.finish(sum(byte.bit_count() for byte in controller.coverage.snapshot()))
    if (
        decision_checkpoint_store is not None
        and sum(controller.scheduler.dispatched.values()) == prior_completed + completed
    ):
        decision_checkpoint_store.commit_campaign(controller, campaign_progress())
    after = snapshot_resources()
    status = "completed" if censored == 0 else "completed_with_censored_inflight"
    total_completed = prior_completed + completed
    combined_samples = campaign_progress()["resource_samples"]
    combined_samples_truncated = campaign_progress()["resource_samples_truncated"]
    return ProtocolCampaignResultV4(
        policy=controller.policy.name, seed=controller.seed,
        wall_seconds=last_active_seconds, deadline_reached=last_active_seconds >= wall_seconds,
        status=status, testcase_count=total_completed + censored,
        completed_count=total_completed,
        censored_inflight=censored, coverage_bits=controller.coverage.width,
        coverage_digest=controller.coverage.digest,
        lane_counts={lane.name: count for lane, count in controller.scheduler.dispatched.items()},
        resource_before=dict(resource_before), resource_after=after.to_dict(),
        declared_lane_counts={
            lane.name: count for lane, count in controller.scheduler.dispatched.items()
        },
        observed_classification_counts=observed,
        legality_rules=legality_rules,
        violation_rule_counts=dict(sorted(violation_rule_counts.items())),
        first_violation_points=tuple(
            first_violation_by_rule[rule_id] for rule_id in sorted(first_violation_by_rule)
        ),
        transport_bytes=transport_bytes,
        dut_cycles=dut_cycles,
        wire_trace_edges=wire_trace_edges,
        target_digest=str(getattr(server, "target_digest", "")),
        coverage_bitmap_base64=base64.b64encode(controller.coverage.snapshot()).decode("ascii"),
        coverage_hits=sum(byte.bit_count() for byte in controller.coverage.snapshot()),
        logical_records=logical_records,
        accepted_records=accepted_records,
        record_stall_cycles=record_stall_cycles,
        valid_protocol_trace_count=observed.get("protocol_valid", 0),
        violation_count=violation_count,
        resource_samples=tuple(combined_samples),
        resource_samples_truncated=bool(combined_samples_truncated),
        coverage_checkpoints=tuple(checkpoints.values),
        mutation_diagnostics=(
            controller.mutation.diagnostics()
            if controller.mutation is not None else {}
        ),
        mutation_reason_trace=tuple(mutation_reason_trace),
        controller_manifest=controller.manifest(),
        novelty_replay_evidence=tuple(novelty_replay_evidence),
    )


def _mutation_reason_v4(item: object) -> Mapping[str, object]:
    return {
        "testcase_id": item.testcase_id,
        "transport_sha256": item.transport_sha256,
        "parent_digest": item.parent_digest,
        "operator": item.mutation_operator,
        "position": item.mutation_position,
        "payload_digest": item.mutation_payload_digest,
        "level": item.mutation_level,
        "mutation_sites": item.mutation_sites,
        "generation": item.mutation_generation,
        "old_value": item.mutation_old_value,
        "new_value": item.mutation_new_value,
        "new_branch_count": item.new_branch_count,
    }


def _restore_campaign_progress_v4(
    value: Mapping[str, object] | None, *, controller: V4Controller,
    server: V4TargetServer, records_per_testcase: int, wall_seconds: float,
    checkpoint_seconds: tuple[float, ...],
) -> Mapping[str, object]:
    default = {
        "schema": "myfuzz.protocol-campaign-progress/v4",
        "policy": controller.policy.name,
        "seed": controller.seed,
        "target_digest": str(getattr(server, "target_digest", "")),
        "records_per_testcase": records_per_testcase,
        "wall_seconds": wall_seconds,
        "checkpoint_seconds": list(checkpoint_seconds),
        "active_seconds": 0.0,
        "completed_count": 0,
        "observed_classification_counts": {},
        "legality_rules": canonical_protocol_legality_rules_v4(
            getattr(server, "legality_rules", {})
        ),
        "transport_bytes": 0,
        "dut_cycles": 0,
        "wire_trace_edges": 0,
        "logical_records": 0,
        "accepted_records": 0,
        "record_stall_cycles": 0,
        "violation_count": 0,
        "violation_rule_counts": {},
        "first_violation_points": [],
        "mutation_reason_trace": [],
        "novelty_replay_evidence": [],
        "resource_before": {},
        "resource_samples": [],
        "resource_samples_truncated": False,
        "coverage_checkpoints": [],
    }
    if value is None:
        return default
    if not isinstance(value, Mapping):
        raise InputValidationError("protocol campaign resume progress is malformed")
    try:
        progress = dict(value)
        for name in default:
            if name not in progress:
                raise KeyError(name)
        if progress["schema"] != default["schema"]:
            raise ValueError("schema")
        for name in ("policy", "seed", "target_digest", "records_per_testcase"):
            if progress[name] != default[name]:
                raise ValueError(name)
        if float(progress["wall_seconds"]) != wall_seconds:
            raise ValueError("wall_seconds")
        if progress["checkpoint_seconds"] != list(checkpoint_seconds):
            raise ValueError("checkpoint_seconds")
        active_seconds = float(progress["active_seconds"])
        raw_completed_count = progress["completed_count"]
        if isinstance(raw_completed_count, bool) or not isinstance(raw_completed_count, int):
            raise ValueError("completed_count")
        completed_count = raw_completed_count
        if active_seconds < 0 or active_seconds > wall_seconds or completed_count < 0:
            raise ValueError("bounds")
        if completed_count != sum(controller.scheduler.dispatched.values()):
            raise ValueError("controller count")
        integer_names = (
            "transport_bytes", "dut_cycles", "wire_trace_edges", "logical_records",
            "accepted_records", "record_stall_cycles", "violation_count",
        )
        for name in integer_names:
            raw = progress[name]
            if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
                raise ValueError(name)
        observed = progress["observed_classification_counts"]
        if not isinstance(observed, Mapping) or any(
            not isinstance(name, str) or not name
            or isinstance(count, bool) or not isinstance(count, int) or count < 0
            for name, count in observed.items()
        ) or sum(observed.values()) != completed_count:
            raise ValueError("observed")
        if (
            canonical_protocol_legality_rules_v4(progress["legality_rules"])
            != default["legality_rules"]
        ):
            raise ValueError("legality_rules")
        rule_counts = progress["violation_rule_counts"]
        if not isinstance(rule_counts, Mapping) or any(
            not isinstance(name, str) or not name
            or isinstance(count, bool) or not isinstance(count, int) or count <= 0
            for name, count in rule_counts.items()
        ) or sum(rule_counts.values()) != progress["violation_count"]:
            raise ValueError("violation_rule_counts")
        for name in (
            "mutation_reason_trace", "novelty_replay_evidence",
            "resource_samples", "coverage_checkpoints", "first_violation_points",
        ):
            if not isinstance(progress[name], list) or any(
                not isinstance(item, Mapping) for item in progress[name]
            ):
                raise ValueError(name)
        first_points = progress["first_violation_points"]
        if len(first_points) != len(rule_counts):
            raise ValueError("first_violation_points count")
        point_ids = []
        for point in first_points:
            rule_id = point.get("rule_id")
            if (
                isinstance(rule_id, bool) or not isinstance(rule_id, int) or rule_id <= 0
                or point.get("rule_name") not in rule_counts
                or not isinstance(point.get("testcase_id"), int)
                or not isinstance(point.get("declared_lane"), str)
                or not isinstance(point.get("observed_classification"), str)
                or not isinstance(point.get("cycle"), int) or point["cycle"] < 0
            ):
                raise ValueError("first_violation_points")
            point_ids.append(rule_id)
        if point_ids != sorted(set(point_ids)):
            raise ValueError("first_violation_points order")
        adversarial_count = sum(
            count for lane, count in controller.scheduler.dispatched.items()
            if lane.name == "ADVERSARIAL_MUTATION"
        )
        if len(progress["mutation_reason_trace"]) != adversarial_count:
            raise ValueError("mutation_reason_trace count")
        _validate_mutation_reason_trace(tuple(progress["mutation_reason_trace"]))
        novelty = progress["novelty_replay_evidence"]
        if len(novelty) > controller.coverage.width or any(
            not isinstance(item.get("testcase_id"), int)
            or isinstance(item.get("testcase_id"), bool)
            or item["testcase_id"] < 0
            for item in novelty
        ):
            raise ValueError("novelty_replay_evidence")
        novelty_ids = [int(item["testcase_id"]) for item in novelty]
        if novelty_ids != sorted(set(novelty_ids)):
            raise ValueError("novelty_replay_evidence order")
        if not isinstance(progress["resource_before"], Mapping):
            raise ValueError("resource_before")
        if not isinstance(progress["resource_samples_truncated"], bool):
            raise ValueError("resource_samples_truncated")
        _CoverageCheckpointsV4(
            checkpoint_seconds, wall_seconds,
            tuple(progress["coverage_checkpoints"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise InputValidationError("protocol campaign resume progress is malformed") from exc
    return progress


class _DeadlineReached(Exception):
    pass


class _LateCompletion(Exception):
    pass


def _proc_meminfo() -> dict[str, int]:
    try:
        with open("/proc/meminfo", encoding="ascii") as stream:
            result = {}
            for line in stream:
                name, value, *_ = line.split()
                result[name.rstrip(":")] = int(value)
            return result
    except (OSError, ValueError):
        return {}


def _cpu_model() -> str:
    try:
        with open("/proc/cpuinfo", encoding="ascii", errors="replace") as stream:
            for line in stream:
                name, separator, value = line.partition(":")
                if separator and name.strip() in {"model name", "Hardware", "Processor"}:
                    model = value.strip()
                    if model:
                        return model
    except OSError:
        pass
    return platform.processor() or "unknown"


def _integer_files(paths: Iterable[Path]) -> tuple[int, ...]:
    values: list[int] = []
    for path in paths:
        try:
            value = int(path.read_text(encoding="ascii").strip())
        except (OSError, ValueError):
            continue
        if value >= 0:
            values.append(value)
    return tuple(values)


def _average_integer_files(paths: Iterable[Path]) -> int:
    values = _integer_files(paths)
    return sum(values) // len(values) if values else 0


def _maximum_integer_files(paths: Iterable[Path]) -> int:
    values = _integer_files(paths)
    return max(values, default=0)


def _sum_integer_files(paths: Iterable[Path]) -> int:
    return sum(_integer_files(paths))


def _legacy_a_rawbits(
    seed: int,
    testcase_index: int,
    cycles_per_testcase: int,
    bytes_per_cycle: int,
) -> bytes:
    output = bytearray()
    first_cycle = testcase_index * cycles_per_testcase
    for local_cycle in range(cycles_per_testcase):
        block = bytearray()
        counter = 0
        cycle = first_cycle + local_cycle
        while len(block) < bytes_per_cycle:
            block.extend(hashlib.sha256(
                b"myfuzz.baseline-a-rawbits/v1\0"
                + seed.to_bytes(8, "little")
                + cycle.to_bytes(8, "little")
                + counter.to_bytes(4, "little")
            ).digest())
            counter += 1
        output.extend(block[:bytes_per_cycle])
    return bytes(output)


def _read_json(path: Path, name: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InputValidationError(f"{name} is unreadable") from exc
    if not isinstance(value, dict):
        raise InputValidationError(f"{name} must contain an object")
    return value


def _validate_variant_result(
    name: str,
    result: ProtocolCampaignResultV4,
    manifest: ProtocolOnlyExperimentManifestV4,
) -> None:
    if result.schema != "myfuzz.protocol-campaign-result/v4" or result.policy != name:
        raise InputValidationError(f"variant {name} result policy/schema mismatch")
    if result.seed != manifest.seed:
        raise InputValidationError(f"variant {name} result seed mismatch")
    if result.target_digest != manifest.target_digests[name]:
        raise InputValidationError(f"variant {name} result target digest mismatch")
    points = len(manifest.coverage_catalog["points"])
    if result.coverage_bits != points:
        raise InputValidationError(f"variant {name} result coverage width mismatch")
    try:
        bitmap = base64.b64decode(result.coverage_bitmap_base64, validate=True)
    except (ValueError, TypeError) as exc:
        raise InputValidationError(f"variant {name} result coverage bitmap is invalid") from exc
    if len(bitmap) != (points + 7) // 8 or hashlib.sha256(bitmap).hexdigest() != result.coverage_digest:
        raise InputValidationError(f"variant {name} result coverage digest mismatch")
    if points % 8 and bitmap[-1] & ~((1 << (points % 8)) - 1):
        raise InputValidationError(f"variant {name} result coverage padding is nonzero")
    if result.coverage_hits != sum(byte.bit_count() for byte in bitmap):
        raise InputValidationError(f"variant {name} result coverage hit count mismatch")
    if len(result.coverage_checkpoints) != len(manifest.checkpoint_seconds):
        raise InputValidationError(f"variant {name} result coverage checkpoints are missing")
    previous_hits = 0
    for item, expected_seconds in zip(
        result.coverage_checkpoints, manifest.checkpoint_seconds,
    ):
        if not isinstance(item, Mapping) or set(item) != {"seconds", "coverage_hits"}:
            raise InputValidationError(f"variant {name} result coverage checkpoint is malformed")
        hits = item["coverage_hits"]
        if (
            item["seconds"] != expected_seconds
            or isinstance(hits, bool)
            or not isinstance(hits, int)
            or not previous_hits <= hits <= result.coverage_hits
        ):
            raise InputValidationError(f"variant {name} result coverage checkpoint is invalid")
        previous_hits = hits
    for field_name in (
        "logical_records", "accepted_records", "record_stall_cycles",
        "valid_protocol_trace_count", "violation_count",
    ):
        value = getattr(result, field_name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise InputValidationError(f"variant {name} result {field_name} is invalid")
    if result.accepted_records > result.logical_records:
        raise InputValidationError(f"variant {name} accepted more records than it declared")
    if dict(result.declared_lane_counts) != dict(result.lane_counts):
        raise InputValidationError(f"variant {name} declared lane counts are inconsistent")
    if sum(result.declared_lane_counts.values()) != result.testcase_count:
        raise InputValidationError(f"variant {name} declared lane count is incomplete")
    if sum(result.observed_classification_counts.values()) != result.completed_count:
        raise InputValidationError(f"variant {name} observed classification count is incomplete")
    if (
        result.valid_protocol_trace_count
        != result.observed_classification_counts.get("protocol_valid", 0)
    ):
        raise InputValidationError(f"variant {name} protocol-valid count is inconsistent")
    legality_rules = canonical_protocol_legality_rules_v4(result.legality_rules)
    if sum(result.violation_rule_counts.values()) != result.violation_count:
        raise InputValidationError(f"variant {name} violation rule count is incomplete")
    if set(result.violation_rule_counts) - set(legality_rules):
        raise InputValidationError(f"variant {name} violation rule is undeclared")
    if len(result.first_violation_points) != len(result.violation_rule_counts):
        raise InputValidationError(f"variant {name} first violation points are incomplete")
    seen_rule_ids: set[int] = set()
    for point in result.first_violation_points:
        if not isinstance(point, Mapping):
            raise InputValidationError(f"variant {name} first violation point is invalid")
        rule_name = point.get("rule_name")
        rule_id = point.get("rule_id")
        if (
            rule_name not in result.violation_rule_counts
            or legality_rules.get(rule_name) != rule_id
            or isinstance(rule_id, bool) or not isinstance(rule_id, int)
            or rule_id in seen_rule_ids
            or isinstance(point.get("testcase_id"), bool)
            or not isinstance(point.get("testcase_id"), int)
            or not 0 <= point["testcase_id"] < result.completed_count
            or not isinstance(point.get("declared_lane"), str)
            or not isinstance(point.get("observed_classification"), str)
            or isinstance(point.get("cycle"), bool)
            or not isinstance(point.get("cycle"), int) or point["cycle"] < 0
        ):
            raise InputValidationError(f"variant {name} first violation point is invalid")
        seen_rule_ids.add(rule_id)
    if result.wall_seconds > manifest.wall_seconds + manifest.shutdown_grace_seconds:
        raise InputValidationError(f"variant {name} exceeded shutdown grace")
    if name == "D":
        _validate_mutation_diagnostics(result.mutation_diagnostics, result.completed_count)
    elif result.mutation_diagnostics:
        raise InputValidationError(f"variant {name} unexpectedly reported mutation diagnostics")
    if name in {"C", "D"}:
        _validate_mutation_reason_trace(result.mutation_reason_trace)
    elif result.mutation_reason_trace:
        raise InputValidationError(f"variant {name} unexpectedly reported mutation reason trace")
    if name == "D" and (
        result.mutation_diagnostics["candidate_results"]
        != len(result.mutation_reason_trace)
    ):
        raise InputValidationError("variant D mutation reason trace is incomplete")


def _validate_mutation_diagnostics(
    value: Mapping[str, object], completed_count: int,
) -> None:
    if value.get("schema") != "myfuzz.adaptive-mutation-diagnostics/v4":
        raise InputValidationError("variant D mutation diagnostics schema mismatch")
    if value.get("history_complete") is not True:
        raise InputValidationError("variant D mutation diagnostics history is incomplete")
    integer_fields = (
        "observed_results", "new_branch_results", "new_branch_total",
        "no_new_branch_results", "cooldown_results", "maximum_stagnant",
        "primary_insertions", "exploration_insertions",
        "exploration_probability_rejections", "duplicate_rejections",
        "exploration_selections", "primary_selections", "promoted_ancestors",
        "seed_insertions", "seed_selections",
        "candidate_results", "candidate_new_branch_results",
        "evictions", "transition_event_count", "seed_size",
        "primary_size", "exploration_size",
    )
    for field_name in integer_fields:
        current = value.get(field_name)
        if isinstance(current, bool) or not isinstance(current, int) or current < 0:
            raise InputValidationError(
                f"variant D mutation diagnostics {field_name} is invalid"
            )
    if value["observed_results"] != completed_count:
        raise InputValidationError("variant D mutation diagnostics missed completed results")
    if value["new_branch_results"] + value["no_new_branch_results"] != value["observed_results"]:
        raise InputValidationError("variant D mutation diagnostics result accounting mismatch")
    level_counts = value.get("level_before_counts")
    if (
        not isinstance(level_counts, Mapping)
        or set(level_counts) != {"L0", "L1", "L2"}
        or any(isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in level_counts.values())
        or sum(level_counts.values()) != value["observed_results"]
    ):
        raise InputValidationError("variant D mutation diagnostics level accounting mismatch")
    transition_counts = value.get("transition_counts")
    expected_transitions = {"L0_TO_L1", "L1_TO_L2", "L2_TO_L1", "L1_TO_L0"}
    if (
        not isinstance(transition_counts, Mapping)
        or set(transition_counts) != expected_transitions
        or any(isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in transition_counts.values())
        or sum(transition_counts.values()) != value["transition_event_count"]
    ):
        raise InputValidationError("variant D mutation diagnostics transition accounting mismatch")
    candidate_levels = value.get("candidate_level_counts")
    if (
        not isinstance(candidate_levels, Mapping)
        or set(candidate_levels) != {"L0", "L1", "L2"}
        or any(isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in candidate_levels.values())
        or sum(candidate_levels.values()) != value["candidate_results"]
    ):
        raise InputValidationError("variant D mutation candidate level accounting mismatch")
    operator_counts = value.get("operator_counts")
    if (
        not isinstance(operator_counts, Mapping)
        or any(
            not isinstance(name, str) or not name
            or isinstance(count, bool) or not isinstance(count, int) or count < 0
            for name, count in operator_counts.items()
        )
        or sum(operator_counts.values()) != value["candidate_results"]
        or value["candidate_new_branch_results"] > value["candidate_results"]
    ):
        raise InputValidationError("variant D mutation operator accounting mismatch")
    events = value.get("recent_transition_events")
    if not isinstance(events, list) or len(events) > 64:
        raise InputValidationError("variant D mutation transition evidence is invalid")
    if value.get("transition_events_truncated") is False and len(events) != value["transition_event_count"]:
        raise InputValidationError("variant D mutation transition evidence is incomplete")
    final_state = value.get("final_state")
    if (
        not isinstance(final_state, Mapping)
        or final_state.get("level") not in {"L0", "L1", "L2"}
        or final_state.get("testcase_index") != value["observed_results"]
    ):
        raise InputValidationError("variant D mutation final state is invalid")


def _validate_mutation_reason_trace(
    values: tuple[Mapping[str, object], ...],
) -> None:
    if not isinstance(values, tuple):
        raise InputValidationError("mutation reason trace must be a tuple")
    expected_keys = {
        "testcase_id", "transport_sha256", "parent_digest", "operator",
        "position", "payload_digest", "level", "mutation_sites",
        "generation", "old_value", "new_value", "new_branch_count",
    }
    previous_testcase_id = -1
    for item in values:
        if not isinstance(item, Mapping) or set(item) != expected_keys:
            raise InputValidationError("mutation reason trace entry is malformed")
        integer_names = (
            "testcase_id", "position", "mutation_sites", "generation",
            "new_branch_count",
        )
        if any(
            isinstance(item[name], bool) or not isinstance(item[name], int)
            or item[name] < 0
            for name in integer_names
        ):
            raise InputValidationError("mutation reason trace integer is invalid")
        if item["testcase_id"] <= previous_testcase_id:
            raise InputValidationError("mutation reason trace is not ordered")
        previous_testcase_id = item["testcase_id"]
        if item["level"] not in {"L0", "L1", "L2"}:
            raise InputValidationError("mutation reason trace level is invalid")
        for name in ("transport_sha256", "payload_digest"):
            digest = item[name]
            if (
                not isinstance(digest, str) or len(digest) != 64
                or any(char not in "0123456789abcdef" for char in digest)
            ):
                raise InputValidationError("mutation reason trace digest is invalid")
        if not isinstance(item["parent_digest"], str) or (
            item["parent_digest"] and len(item["parent_digest"]) != 64
        ):
            raise InputValidationError("mutation reason trace parent digest is invalid")
        operator = item["operator"]
        if operator not in {
            "seed", "protocol_seed", "bit_flip", "record_swap",
            "record_delete", "record_duplicate", "record_insert",
        }:
            raise InputValidationError("mutation reason trace operator is invalid")
        old_value = item["old_value"]
        new_value = item["new_value"]
        if any(
            value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value < 0
            )
            for value in (old_value, new_value)
        ):
            raise InputValidationError("mutation reason trace old/new value is invalid")
        if operator in {"seed", "protocol_seed"}:
            valid_change = (
                item["mutation_sites"] == 0
                and old_value is None and new_value is None
            )
        elif operator == "bit_flip":
            valid_change = (
                old_value in {0, 1} and new_value in {0, 1}
                and old_value != new_value
            )
        elif operator == "record_delete":
            valid_change = old_value is not None and new_value is None
        elif operator in {"record_duplicate", "record_insert"}:
            valid_change = old_value is None and new_value is not None
        else:
            valid_change = old_value is not None and new_value is not None
        if not valid_change:
            raise InputValidationError("mutation reason trace change evidence is invalid")


def _validate_coverage_catalog(value: Mapping[str, object]) -> None:
    if value.get("schema") != "myfuzz.experiment-coverage-catalog/v1":
        raise InputValidationError("protocol-only coverage catalog schema mismatch")
    points = value.get("points")
    if not isinstance(points, (tuple, list)) or not points:
        raise InputValidationError("protocol-only coverage catalog is empty")
    expected = {**dict(value), "points": tuple(dict(item) for item in points)}
    digest = expected.pop("digest", None)
    if digest != _content_digest(expected):
        raise InputValidationError("protocol-only coverage catalog digest mismatch")


def _validate_checkpoint_seconds(
    values: object,
    wall_seconds: float,
    *,
    allow_empty: bool = False,
) -> None:
    if not isinstance(values, (tuple, list)) or (not values and not allow_empty):
        raise InputValidationError("protocol-only coverage checkpoints are empty")
    previous = 0.0
    for value in values:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value <= previous
            or value > wall_seconds
        ):
            raise InputValidationError("protocol-only coverage checkpoints are invalid")
        previous = float(value)


def _validate_resource_contract(value: Mapping[str, object]) -> None:
    expected = {
        "schema", "cpu_affinity", "thread_count", "build_jobs", "execution_processes",
        "target_peak_rss_bytes", "memory_safety_numerator", "memory_safety_denominator",
        "min_available_memory_bytes",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise InputValidationError("protocol-only resource contract fields mismatch")
    if value["schema"] != "myfuzz.protocol-resource-contract/v4":
        raise InputValidationError("protocol-only resource contract schema mismatch")
    affinity = value["cpu_affinity"]
    if not isinstance(affinity, (tuple, list)) or not affinity or any(
        isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in affinity
    ) or tuple(affinity) != tuple(sorted(set(affinity))):
        raise InputValidationError("protocol-only CPU affinity is invalid")
    for name in expected - {"schema", "cpu_affinity"}:
        item = value[name]
        minimum = 0 if name in {"target_peak_rss_bytes", "min_available_memory_bytes"} else 1
        if isinstance(item, bool) or not isinstance(item, int) or item < minimum:
            raise InputValidationError(f"protocol-only resource {name} is invalid")
    if value["thread_count"] != 1 or value["build_jobs"] != 1 or value["execution_processes"] != 1:
        raise InputValidationError("protocol-only resources must remain serial")


def _validate_execution_contract(value: Mapping[str, object]) -> None:
    expected = {
        "schema", "baseline_cycles_per_testcase", "records_per_testcase",
        "testcase_timeout_seconds", "resource_sample_interval_seconds",
        "max_resource_samples", "max_testcases", "completion_rule",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise InputValidationError("protocol-only execution contract fields mismatch")
    if value["schema"] != "myfuzz.protocol-execution-contract/v4":
        raise InputValidationError("protocol-only execution contract schema mismatch")
    if value["completion_rule"] != "completion-before-deadline":
        raise InputValidationError("protocol-only completion rule is unsupported")
    for name in (
        "baseline_cycles_per_testcase", "records_per_testcase", "max_resource_samples",
    ):
        item = value[name]
        if isinstance(item, bool) or not isinstance(item, int) or item <= 0:
            raise InputValidationError(f"protocol-only execution {name} is invalid")
    for name in ("testcase_timeout_seconds", "resource_sample_interval_seconds"):
        item = value[name]
        if (
            isinstance(item, bool)
            or not isinstance(item, (int, float))
            or not math.isfinite(item)
            or item <= 0
        ):
            raise InputValidationError(f"protocol-only execution {name} is invalid")
    maximum = value["max_testcases"]
    if maximum is not None and (
        isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 0
    ):
        raise InputValidationError("protocol-only execution max_testcases is invalid")


def _digest(value: object, name: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(
        char not in "0123456789abcdef" for char in value
    ):
        raise InputValidationError(f"{name} must be a lowercase SHA-256 digest")


def _content_digest(value: object) -> str:
    try:
        payload = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise InputValidationError("protocol-only report contains non-canonical JSON") from exc
    return hashlib.sha256(payload).hexdigest()


def _write_json_atomic(path: Path, value: object) -> None:
    destination = path.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
