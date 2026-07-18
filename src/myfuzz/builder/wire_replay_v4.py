"""Self-contained, digest-bound wire replay bundles for RawBits v4 targets."""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Mapping

from .contracts import CoverageABIV2
from .controller_v4 import TargetExecutionResultV4
from .cpu_semantic_v4 import cpu_execution_profile_v4_from_dict
from .environment_v4 import (
    EnvironmentPlanV4, EnvironmentReplayLimitsV4, environment_plan_v4_from_dict,
    validate_environment_replay_v4,
)
from .generated_target_v4 import run_protocol_verilator_target_v4
from .input_model import InputValidationError
from .rawbits_v4 import RawBitsV4Layout, RawBitsV4Limits, decode_rawbits_v4_testcase


WIRE_REPLAY_SCHEMA_V4 = "myfuzz.wire-replay-bundle/v4"
WIRE_REPLAY_EVIDENCE_INDEX_SCHEMA_V4 = "myfuzz.wire-replay-evidence-index/v4"


@dataclass(frozen=True)
class WireReplayBundleV4:
    layout_digest: str
    soc_digest: str
    profile_digest: str
    target_digest: str
    coverage_abi_digest: str
    coverage_epoch: int
    transport_base64: str
    transport_sha256: str
    toolchain: Mapping[str, object]
    runtime: Mapping[str, object]
    invocation: Mapping[str, object]
    random_seeds: Mapping[str, int]
    deterministic_initialization: Mapping[str, object]
    external_environment: Mapping[str, object]
    environment_plan: Mapping[str, object] | None
    environment_replay_base64: str | None
    environment_replay_sha256: str | None
    environment_replay_limits: Mapping[str, int]
    non_dut_inputs: tuple[Mapping[str, object], ...]
    expected_coverage_base64: str
    expected_coverage_sha256: str
    expected_wire_trace_digest: str
    expected_observed_classification: str
    expected_violation_rule: int | None
    expected_violation_cycle: int | None
    expected_dut_cycles: int
    expected_wire_trace_edges: int
    expected_assertion_events: tuple[Mapping[str, object], ...] = ()
    digest: str = ""
    schema: str = WIRE_REPLAY_SCHEMA_V4

    def __post_init__(self) -> None:
        for name in (
            "layout_digest", "soc_digest", "profile_digest", "target_digest",
            "coverage_abi_digest", "transport_sha256", "expected_coverage_sha256",
            "expected_wire_trace_digest",
        ):
            _digest(getattr(self, name), name)
        if isinstance(self.coverage_epoch, bool) or not 0 <= self.coverage_epoch < 1 << 64:
            raise InputValidationError("wire replay coverage epoch must be an unsigned 64-bit integer")
        transport = _decode_base64(self.transport_base64, "wire replay transport")
        coverage = _decode_base64(self.expected_coverage_base64, "wire replay coverage")
        if not transport or hashlib.sha256(transport).hexdigest() != self.transport_sha256:
            raise InputValidationError("wire replay transport digest mismatch")
        if hashlib.sha256(coverage).hexdigest() != self.expected_coverage_sha256:
            raise InputValidationError("wire replay coverage digest mismatch")
        for name in (
            "toolchain", "runtime", "invocation", "random_seeds",
            "deterministic_initialization", "external_environment",
        ):
            _json_mapping(getattr(self, name), f"wire replay {name}")
        if not self.toolchain or not self.runtime or not self.invocation:
            raise InputValidationError("wire replay toolchain/runtime/invocation must be declared")
        if not self.deterministic_initialization:
            raise InputValidationError("wire replay deterministic initialization must be declared")
        environment_limits = _environment_limits(self.environment_replay_limits)
        if self.environment_plan is None:
            if self.environment_replay_base64 is not None or self.environment_replay_sha256 is not None:
                raise InputValidationError("wire replay has environment bytes without a plan")
        else:
            _json_mapping(self.environment_plan, "wire replay environment plan")
            plan = environment_plan_v4_from_dict(self.environment_plan)
            if plan.soc_digest != self.soc_digest or plan.protocol_profile_digest != self.profile_digest:
                raise InputValidationError("wire replay environment plan target digest mismatch")
            if plan.requires_replay:
                if self.environment_replay_base64 is None or self.environment_replay_sha256 is None:
                    raise InputValidationError("wire replay environment plan requires sidecar bytes")
                sidecar = _decode_base64(
                    self.environment_replay_base64, "wire replay environment sidecar",
                )
                if hashlib.sha256(sidecar).hexdigest() != self.environment_replay_sha256:
                    raise InputValidationError("wire replay environment sidecar digest mismatch")
                validate_environment_replay_v4(plan, sidecar, limits=environment_limits)
            elif self.environment_replay_base64 is not None or self.environment_replay_sha256 is not None:
                raise InputValidationError("wire replay constant environment cannot have sidecar bytes")
        if any(
            not isinstance(name, str) or isinstance(value, bool) or not isinstance(value, int)
            for name, value in self.random_seeds.items()
        ):
            raise InputValidationError("wire replay random seeds must be named integers")
        for index, item in enumerate(self.non_dut_inputs):
            _json_mapping(item, f"wire replay non_dut_inputs[{index}]")
        for index, item in enumerate(self.expected_assertion_events):
            _json_mapping(item, f"wire replay assertion_events[{index}]")
        if self.expected_observed_classification not in {
            "protocol_valid", "adversarial", "raw", "cpu_semantic",
        }:
            raise InputValidationError("wire replay observed classification is invalid")
        if (self.expected_violation_rule is None) != (self.expected_violation_cycle is None):
            raise InputValidationError("wire replay violation rule/cycle must be reported together")
        if self.expected_violation_rule is not None and (
            self.expected_violation_rule <= 0 or self.expected_violation_cycle < 0
        ):
            raise InputValidationError("wire replay violation metadata is invalid")
        for name in ("expected_dut_cycles", "expected_wire_trace_edges"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise InputValidationError(f"wire replay {name} must be non-negative")
        if self.schema != WIRE_REPLAY_SCHEMA_V4:
            raise InputValidationError("wire replay schema version mismatch")
        if self.digest and self.digest != _content_digest(self.payload_dict()):
            raise InputValidationError("wire replay bundle digest mismatch")

    def payload_dict(self) -> dict[str, object]:
        value = asdict(self)
        value.pop("digest")
        return value

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @property
    def transport(self) -> bytes:
        return _decode_base64(self.transport_base64, "wire replay transport")

    @property
    def expected_coverage(self) -> bytes:
        return _decode_base64(self.expected_coverage_base64, "wire replay coverage")

    @property
    def environment_replay(self) -> bytes | None:
        if self.environment_replay_base64 is None:
            return None
        return _decode_base64(self.environment_replay_base64, "wire replay environment sidecar")


class WireReplayEvidenceStoreV4:
    """Durable bounded index of content-addressed novelty replay bundles."""

    def __init__(
        self, root: str | os.PathLike[str], *, max_entries: int,
        max_bundle_bytes: int,
    ) -> None:
        for name, value in (
            ("max_entries", max_entries), ("max_bundle_bytes", max_bundle_bytes),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise InputValidationError(f"wire replay evidence {name} must be positive")
        self.root = Path(root)
        self.objects = self.root / "objects"
        self.index_path = self.root / "index.json"
        self.max_entries = max_entries
        self.max_bundle_bytes = max_bundle_bytes
        self.objects.mkdir(parents=True, exist_ok=True)
        if not self.index_path.exists():
            self._write_index(())
        else:
            entries = self.load_entries()
            self._prune_unreferenced_objects(entries)

    def record(
        self, bundle: WireReplayBundleV4, *, testcase_id: int,
        new_branch_count: int,
    ) -> Mapping[str, object]:
        bundle.__post_init__()
        _digest(bundle.digest, "wire replay evidence bundle digest")
        for name, value in (
            ("testcase_id", testcase_id), ("new_branch_count", new_branch_count),
        ):
            if (
                isinstance(value, bool) or not isinstance(value, int)
                or value < (0 if name == "testcase_id" else 1)
            ):
                raise InputValidationError(f"wire replay evidence {name} is invalid")
        payload = _canonical_json_bytes(bundle.to_dict())
        if len(payload) > self.max_bundle_bytes:
            raise InputValidationError("wire replay evidence bundle exceeds its byte limit")
        entries = list(self.load_entries())
        if any(item["testcase_id"] == testcase_id for item in entries):
            raise InputValidationError("wire replay evidence testcase is already indexed")
        if len(entries) >= self.max_entries:
            raise InputValidationError("wire replay evidence entry limit is exhausted")
        object_sha256 = hashlib.sha256(payload).hexdigest()
        object_path = self.objects / object_sha256
        if object_path.exists():
            if object_path.read_bytes() != payload:
                raise InputValidationError("wire replay evidence object digest collision")
        else:
            self._atomic_write(object_path, payload)
        entry = {
            "testcase_id": testcase_id,
            "new_branch_count": new_branch_count,
            "bundle_digest": bundle.digest,
            "object_sha256": object_sha256,
            "object_bytes": len(payload),
            "transport_sha256": bundle.transport_sha256,
            "coverage_epoch": bundle.coverage_epoch,
        }
        entries.append(entry)
        self._write_index(tuple(entries))
        return dict(entry)

    def load_entries(self) -> tuple[Mapping[str, object], ...]:
        try:
            value = json.loads(self.index_path.read_text(encoding="utf-8"))
            if not isinstance(value, Mapping):
                raise ValueError("index")
            if value.get("schema") != WIRE_REPLAY_EVIDENCE_INDEX_SCHEMA_V4:
                raise ValueError("schema")
            if value.get("max_entries") != self.max_entries:
                raise ValueError("max_entries")
            if value.get("max_bundle_bytes") != self.max_bundle_bytes:
                raise ValueError("max_bundle_bytes")
            raw_entries = value.get("entries")
            if not isinstance(raw_entries, list) or len(raw_entries) > self.max_entries:
                raise ValueError("entries")
            entries = tuple(dict(item) for item in raw_entries)
            previous_id = -1
            for entry in entries:
                if set(entry) != {
                    "testcase_id", "new_branch_count", "bundle_digest",
                    "object_sha256", "object_bytes", "transport_sha256",
                    "coverage_epoch",
                }:
                    raise ValueError("entry fields")
                testcase_id = entry["testcase_id"]
                new_count = entry["new_branch_count"]
                object_bytes = entry["object_bytes"]
                epoch = entry["coverage_epoch"]
                if any(
                    isinstance(item, bool) or not isinstance(item, int)
                    for item in (testcase_id, new_count, object_bytes, epoch)
                ) or testcase_id <= previous_id or new_count <= 0 or not (
                    0 < object_bytes <= self.max_bundle_bytes
                ) or not 0 <= epoch < 1 << 64:
                    raise ValueError("entry values")
                previous_id = testcase_id
                for name in ("bundle_digest", "object_sha256", "transport_sha256"):
                    _digest(entry[name], f"wire replay evidence {name}")
                payload = (self.objects / str(entry["object_sha256"])).read_bytes()
                if len(payload) != object_bytes or hashlib.sha256(payload).hexdigest() != entry["object_sha256"]:
                    raise ValueError("object")
                bundle = wire_replay_bundle_v4_from_dict(json.loads(payload))
                if (
                    bundle.digest != entry["bundle_digest"]
                    or bundle.transport_sha256 != entry["transport_sha256"]
                    or bundle.coverage_epoch != epoch
                ):
                    raise ValueError("bundle reference")
            return entries
        except (OSError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InputValidationError("wire replay evidence index is missing or corrupt") from exc

    def load_bundle(self, object_sha256: str) -> WireReplayBundleV4:
        _digest(object_sha256, "wire replay evidence object_sha256")
        entries = self.load_entries()
        if not any(item["object_sha256"] == object_sha256 for item in entries):
            raise InputValidationError("wire replay evidence object is not indexed")
        try:
            value = json.loads((self.objects / object_sha256).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InputValidationError("wire replay evidence object is unreadable") from exc
        return wire_replay_bundle_v4_from_dict(value)

    def _write_index(self, entries: tuple[Mapping[str, object], ...]) -> None:
        value = {
            "schema": WIRE_REPLAY_EVIDENCE_INDEX_SCHEMA_V4,
            "max_entries": self.max_entries,
            "max_bundle_bytes": self.max_bundle_bytes,
            "entries": [dict(item) for item in entries],
        }
        self._atomic_write(self.index_path, _canonical_json_bytes(value))

    def _prune_unreferenced_objects(
        self, entries: tuple[Mapping[str, object], ...],
    ) -> None:
        referenced = {str(item["object_sha256"]) for item in entries}
        try:
            for path in self.objects.iterdir():
                _digest(path.name, "wire replay evidence object filename")
                if not path.is_file():
                    raise InputValidationError(
                        "wire replay evidence object directory is malformed"
                    )
                if path.name not in referenced:
                    path.unlink()
        except OSError as exc:
            raise InputValidationError(
                "wire replay evidence orphan cleanup failed"
            ) from exc

    @staticmethod
    def _atomic_write(path: Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def build_wire_replay_bundle_v4(
    layout: RawBitsV4Layout,
    transport: bytes,
    result: TargetExecutionResultV4,
    *,
    soc_digest: str,
    profile_digest: str,
    target_digest: str,
    coverage_abi: CoverageABIV2,
    coverage_epoch: int,
    toolchain: Mapping[str, object],
    runtime: Mapping[str, object],
    invocation: Mapping[str, object],
    random_seeds: Mapping[str, int],
    deterministic_initialization: Mapping[str, object],
    external_environment: Mapping[str, object],
    environment_plan: EnvironmentPlanV4 | None = None,
    environment_replay: bytes | None = None,
    environment_limits: EnvironmentReplayLimitsV4 = EnvironmentReplayLimitsV4(),
    non_dut_inputs: tuple[Mapping[str, object], ...] = (),
    limits: RawBitsV4Limits = RawBitsV4Limits(),
) -> WireReplayBundleV4:
    decode_rawbits_v4_testcase(layout, transport, limits=limits)
    result.__post_init__()
    environment_limits.__post_init__()
    if environment_plan is None:
        if environment_replay is not None:
            raise InputValidationError("wire replay received environment bytes without a plan")
    else:
        environment_plan.__post_init__()
        if environment_plan.soc_digest != soc_digest:
            raise InputValidationError("wire replay environment plan/SoC digest mismatch")
        if environment_plan.protocol_profile_digest != profile_digest:
            raise InputValidationError("wire replay environment plan/profile digest mismatch")
        if environment_plan.requires_replay:
            if environment_replay is None:
                raise InputValidationError("wire replay environment plan requires sidecar bytes")
            validate_environment_replay_v4(
                environment_plan, environment_replay, limits=environment_limits,
            )
        elif environment_replay is not None:
            raise InputValidationError("wire replay constant environment cannot have sidecar bytes")
    if result.wire_trace_digest is None:
        raise InputValidationError("wire replay bundle requires an observed wire trace digest")
    expected_coverage_bytes = (coverage_abi.width + 7) // 8
    if len(result.coverage_bitmap) != expected_coverage_bytes:
        raise InputValidationError("wire replay result coverage width does not match the ABI")
    if coverage_abi.width % 8 and result.coverage_bitmap[-1] & ~(
        (1 << (coverage_abi.width % 8)) - 1
    ):
        raise InputValidationError("wire replay result has nonzero coverage padding bits")
    value = WireReplayBundleV4(
        layout_digest=layout.digest, soc_digest=soc_digest, profile_digest=profile_digest,
        target_digest=target_digest, coverage_abi_digest=coverage_abi.manifest_digest,
        coverage_epoch=coverage_epoch,
        transport_base64=base64.b64encode(transport).decode("ascii"),
        transport_sha256=hashlib.sha256(transport).hexdigest(),
        toolchain=dict(toolchain), runtime=dict(runtime), invocation=dict(invocation),
        random_seeds=dict(random_seeds),
        deterministic_initialization=dict(deterministic_initialization),
        external_environment=dict(external_environment),
        environment_plan=None if environment_plan is None else environment_plan.to_dict(),
        environment_replay_base64=(
            None if environment_replay is None
            else base64.b64encode(environment_replay).decode("ascii")
        ),
        environment_replay_sha256=(
            None if environment_replay is None
            else hashlib.sha256(environment_replay).hexdigest()
        ),
        environment_replay_limits={
            "max_records": environment_limits.max_records,
            "max_payload_bytes": environment_limits.max_payload_bytes,
        },
        non_dut_inputs=tuple(dict(item) for item in non_dut_inputs),
        expected_coverage_base64=base64.b64encode(result.coverage_bitmap).decode("ascii"),
        expected_coverage_sha256=hashlib.sha256(result.coverage_bitmap).hexdigest(),
        expected_wire_trace_digest=result.wire_trace_digest,
        expected_observed_classification=result.observed_classification,
        expected_violation_rule=result.violation_rule,
        expected_violation_cycle=result.violation_cycle,
        expected_dut_cycles=result.dut_cycles,
        expected_wire_trace_edges=result.wire_trace_edges,
        expected_assertion_events=tuple(dict(item) for item in result.assertion_events),
    )
    return replace(value, digest=_content_digest(value.payload_dict()))


def replay_wire_bundle_v4(
    bundle: WireReplayBundleV4,
    target_dir: str | Path,
    *,
    layout: RawBitsV4Layout,
    coverage_abi: CoverageABIV2,
    timeout_seconds: float = 30.0,
    limits: RawBitsV4Limits = RawBitsV4Limits(),
) -> TargetExecutionResultV4:
    bundle.__post_init__()
    if bundle.layout_digest != layout.digest:
        raise InputValidationError("wire replay bundle/layout digest mismatch")
    if bundle.coverage_abi_digest != coverage_abi.manifest_digest:
        raise InputValidationError("wire replay bundle/coverage ABI digest mismatch")
    decode_rawbits_v4_testcase(layout, bundle.transport, limits=limits)
    target = Path(target_dir).resolve(strict=True)
    try:
        completion = json.loads((target / "completion_manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InputValidationError("wire replay target completion manifest is unreadable") from exc
    if completion.get("target_digest") != bundle.target_digest:
        raise InputValidationError("wire replay bundle/target digest mismatch")
    if completion.get("soc_digest") != bundle.soc_digest:
        raise InputValidationError("wire replay bundle/SoC digest mismatch")
    if completion.get("protocol_profile_digest") != bundle.profile_digest:
        raise InputValidationError("wire replay bundle/profile digest mismatch")
    environment_plan = (
        None if bundle.environment_plan is None
        else environment_plan_v4_from_dict(bundle.environment_plan)
    )
    environment_limits = _environment_limits(bundle.environment_replay_limits)
    cpu_profile = None
    cpu_profile_digest = completion.get("cpu_profile_digest")
    if cpu_profile_digest is not None:
        try:
            profile_value = json.loads(
                (target / "evidence/cpu_execution_profile.json").read_text(encoding="utf-8")
            )
            cpu_profile = cpu_execution_profile_v4_from_dict(profile_value)
        except (OSError, json.JSONDecodeError) as exc:
            raise InputValidationError("wire replay CPU profile is unreadable") from exc
        if cpu_profile.digest != cpu_profile_digest:
            raise InputValidationError("wire replay CPU profile digest mismatch")
    actual = run_protocol_verilator_target_v4(
        target, bundle.transport, layout_digest=layout.digest, coverage_abi=coverage_abi,
        coverage_epoch=bundle.coverage_epoch, environment_plan=environment_plan,
        environment_replay=bundle.environment_replay,
        environment_limits=environment_limits, cpu_profile=cpu_profile,
        timeout_seconds=timeout_seconds,
    )
    expected = (
        bundle.expected_coverage,
        bundle.expected_wire_trace_digest,
        bundle.expected_observed_classification,
        bundle.expected_violation_rule,
        bundle.expected_violation_cycle,
        bundle.expected_dut_cycles,
        bundle.expected_wire_trace_edges,
        bundle.expected_assertion_events,
    )
    observed = (
        actual.coverage_bitmap, actual.wire_trace_digest, actual.observed_classification,
        actual.violation_rule, actual.violation_cycle, actual.dut_cycles,
        actual.wire_trace_edges, actual.assertion_events,
    )
    if observed != expected:
        raise InputValidationError("wire replay result does not match the frozen bundle")
    return actual


def wire_replay_bundle_v4_from_dict(value: Mapping[str, object]) -> WireReplayBundleV4:
    fields = set(WireReplayBundleV4.__dataclass_fields__)
    missing, unknown = fields - set(value), set(value) - fields
    if missing or unknown:
        detail = sorted(missing or unknown)
        kind = "missing" if missing else "unknown"
        raise InputValidationError(f"wire replay bundle: {kind} field(s): {', '.join(detail)}")
    try:
        normalized = dict(value)
        normalized["non_dut_inputs"] = tuple(
            dict(item) for item in normalized["non_dut_inputs"]
        )
        normalized["expected_assertion_events"] = tuple(
            dict(item) for item in normalized["expected_assertion_events"]
        )
        if normalized["environment_plan"] is not None:
            normalized["environment_plan"] = dict(normalized["environment_plan"])
        normalized["environment_replay_limits"] = dict(
            normalized["environment_replay_limits"]
        )
    except (TypeError, ValueError) as exc:
        raise InputValidationError("wire replay bundle is malformed") from exc
    return WireReplayBundleV4(**normalized)


def _decode_base64(value: object, name: str) -> bytes:
    if not isinstance(value, str):
        raise InputValidationError(f"{name} must be canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise InputValidationError(f"{name} must be canonical base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise InputValidationError(f"{name} must be canonical base64")
    return decoded


def _digest(value: object, name: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(
        char not in "0123456789abcdef" for char in value
    ):
        raise InputValidationError(f"{name} must be a lowercase SHA-256 digest")


def _json_mapping(value: object, name: str) -> None:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise InputValidationError(f"{name} must be a string-keyed object")
    try:
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise InputValidationError(f"{name} must contain canonical JSON values") from exc


def _canonical_json_bytes(value: Mapping[str, object]) -> bytes:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise InputValidationError("wire replay evidence is not canonical JSON") from exc
    return (encoded + "\n").encode("utf-8")


def _environment_limits(value: object) -> EnvironmentReplayLimitsV4:
    if not isinstance(value, Mapping) or set(value) != {"max_records", "max_payload_bytes"}:
        raise InputValidationError("wire replay environment limits are malformed")
    try:
        limits = EnvironmentReplayLimitsV4(
            max_records=value["max_records"],
            max_payload_bytes=value["max_payload_bytes"],
        )
    except (TypeError, ValueError) as exc:
        raise InputValidationError("wire replay environment limits are malformed") from exc
    limits.__post_init__()
    return limits


def _content_digest(value: Mapping[str, object]) -> str:
    try:
        payload = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise InputValidationError("wire replay bundle must contain canonical JSON values") from exc
    return hashlib.sha256(payload).hexdigest()
