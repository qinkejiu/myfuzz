"""Explicit external-environment plans and checked per-edge replay transport."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import re
import struct
from typing import Iterable, Mapping
import zlib

from .contracts import content_digest
from .generated_harness_v4 import EmittedHarnessV4
from .input_model import InputValidationError


ENVIRONMENT_PLAN_SCHEMA_V4 = "myfuzz.environment-plan/v4"
ENVIRONMENT_REPLAY_SCHEMA_V4 = "myfuzz.environment-replay/v4"
ENVIRONMENT_REPLAY_MAGIC_V4 = b"MYFENV4\x00"
ENVIRONMENT_REPLAY_HEADER_BYTES_V4 = 64
_HEADER = struct.Struct("<8sHHIIQ8sQ16sI")

if _HEADER.size != ENVIRONMENT_REPLAY_HEADER_BYTES_V4:
    raise RuntimeError("environment v4 replay header must be exactly 64 bytes")


@dataclass(frozen=True)
class EnvironmentReplayLimitsV4:
    max_records: int = 1_048_576
    max_payload_bytes: int = 512 * 1024 * 1024
    schema: str = "myfuzz.environment-replay-limits/v4"

    def __post_init__(self) -> None:
        if self.schema != "myfuzz.environment-replay-limits/v4":
            raise InputValidationError("environment v4 replay limits schema mismatch")
        for name in ("max_records", "max_payload_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise InputValidationError(f"environment v4 {name} must be positive")
            if value > (1 << 64) - 1:
                raise InputValidationError(f"environment v4 {name} exceeds 64-bit transport limits")


@dataclass(frozen=True)
class EnvironmentInputRuleV4:
    mode: str
    reason: str
    evidence_source: str
    reset_behavior: str
    constant_value: int | None = None
    schema: str = "myfuzz.environment-input-rule/v4"

    def __post_init__(self) -> None:
        if self.schema != "myfuzz.environment-input-rule/v4":
            raise InputValidationError("environment v4 input rule schema mismatch")
        if self.mode not in {"constant", "replay"}:
            raise InputValidationError("environment v4 input mode must be constant or replay")
        for name in ("reason", "evidence_source", "reset_behavior"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise InputValidationError(f"environment v4 {name} must be non-empty")
        if self.mode == "constant":
            if isinstance(self.constant_value, bool) or not isinstance(self.constant_value, int):
                raise InputValidationError("environment v4 constant mode requires an integer value")
        elif self.constant_value is not None:
            raise InputValidationError("environment v4 replay mode cannot declare a constant value")


@dataclass(frozen=True)
class EnvironmentInputBindingV4:
    port_name: str
    width: int
    mode: str
    constant_value: int | None
    reset_behavior: str
    reason: str
    evidence_source: str
    schema: str = "myfuzz.environment-input-binding/v4"


@dataclass(frozen=True)
class EnvironmentOutputObservationV4:
    port_name: str
    width: int
    policy: str = "observe"
    reason: str = "external outputs are observed and never driven"
    evidence_source: str = "unknown-port-policy/v1"
    schema: str = "myfuzz.environment-output-observation/v4"


@dataclass(frozen=True)
class EnvironmentReplayFieldV4:
    port_name: str
    width: int
    offset_bits: int
    storage_bytes: int
    schema: str = "myfuzz.environment-replay-field/v4"


@dataclass(frozen=True)
class EnvironmentPlanV4:
    soc_digest: str
    protocol_profile_digest: str
    inputs: tuple[EnvironmentInputBindingV4, ...]
    observed_outputs: tuple[EnvironmentOutputObservationV4, ...]
    replay_fields: tuple[EnvironmentReplayFieldV4, ...]
    replay_record_width_bits: int
    replay_record_width_bytes: int
    digest: str = ""
    schema: str = ENVIRONMENT_PLAN_SCHEMA_V4

    def __post_init__(self) -> None:
        _digest(self.soc_digest, "environment SoC digest")
        _digest(self.protocol_profile_digest, "environment protocol profile digest")
        if self.schema != ENVIRONMENT_PLAN_SCHEMA_V4:
            raise InputValidationError("environment v4 plan schema mismatch")
        input_names = [item.port_name for item in self.inputs]
        output_names = [item.port_name for item in self.observed_outputs]
        replay_names = [item.port_name for item in self.replay_fields]
        if input_names != sorted(input_names) or len(input_names) != len(set(input_names)):
            raise InputValidationError("environment v4 input bindings must be unique and sorted")
        if output_names != sorted(output_names) or len(output_names) != len(set(output_names)):
            raise InputValidationError("environment v4 observations must be unique and sorted")
        expected_replay = [item.port_name for item in self.inputs if item.mode == "replay"]
        if replay_names != expected_replay:
            raise InputValidationError("environment v4 replay fields do not match replay inputs")
        offset = 0
        binding_widths = {}
        for binding in self.inputs:
            if (
                binding.schema != "myfuzz.environment-input-binding/v4"
                or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", binding.port_name)
                or binding.width <= 0 or binding.mode not in {"constant", "replay"}
                or any(not isinstance(value, str) or not value.strip() for value in (
                    binding.reset_behavior, binding.reason, binding.evidence_source,
                ))
            ):
                raise InputValidationError("environment v4 input binding is invalid")
            binding_widths[binding.port_name] = binding.width
            if binding.mode == "constant":
                if binding.constant_value is None or not 0 <= binding.constant_value < 1 << binding.width:
                    raise InputValidationError(
                        f"environment v4 constant for {binding.port_name} does not fit its width"
                    )
            elif binding.constant_value is not None:
                raise InputValidationError("environment v4 replay binding contains a constant")
        for observation in self.observed_outputs:
            if (
                observation.schema != "myfuzz.environment-output-observation/v4"
                or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", observation.port_name)
                or observation.width <= 0 or observation.policy != "observe"
                or not observation.reason.strip() or not observation.evidence_source.strip()
            ):
                raise InputValidationError("environment v4 output observation is invalid")
        if set(input_names) & set(output_names):
            raise InputValidationError("environment v4 port cannot be both input and output")
        for field in self.replay_fields:
            expected_bytes = (field.width + 7) // 8
            if (
                field.schema != "myfuzz.environment-replay-field/v4"
                or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", field.port_name)
                or field.width <= 0 or binding_widths.get(field.port_name) != field.width
                or field.offset_bits != offset or field.storage_bytes != expected_bytes
            ):
                raise InputValidationError("environment v4 replay field geometry is not canonical")
            offset += expected_bytes * 8
        if self.replay_record_width_bits != offset or self.replay_record_width_bytes * 8 != offset:
            raise InputValidationError("environment v4 replay record geometry mismatch")
        if self.digest and self.digest != content_digest(self.payload_dict()):
            raise InputValidationError("environment v4 plan digest mismatch")

    def payload_dict(self) -> dict[str, object]:
        value = asdict(self)
        value.pop("digest")
        return value

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @property
    def requires_replay(self) -> bool:
        return bool(self.replay_fields)


def build_environment_plan_v4(
    harness: EmittedHarnessV4,
    rules: Mapping[str, EnvironmentInputRuleV4],
) -> EnvironmentPlanV4:
    if not isinstance(rules, Mapping) or any(not isinstance(name, str) for name in rules):
        raise InputValidationError("environment v4 rules must be a port-name mapping")
    invalid_names = sorted(
        port.name for port in harness.environment_ports
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", port.name)
    )
    if invalid_names:
        raise InputValidationError(
            "environment v4 port name is not a Verilog identifier: "
            + ", ".join(invalid_names)
        )
    inputs = sorted(
        (port for port in harness.environment_ports if port.direction == "input"),
        key=lambda port: port.name,
    )
    outputs = sorted(
        (port for port in harness.environment_ports if port.direction == "output"),
        key=lambda port: port.name,
    )
    unsupported = sorted(
        port.name for port in harness.environment_ports
        if port.direction not in {"input", "output"}
    )
    if unsupported:
        raise InputValidationError(
            "environment v4 requires user handling for unsupported port direction(s): "
            + ", ".join(unsupported)
        )
    expected = {port.name for port in inputs}
    missing, unknown = expected - set(rules), set(rules) - expected
    if missing or unknown:
        detail = sorted(missing or unknown)
        kind = "missing" if missing else "unknown"
        raise InputValidationError(f"environment v4 rules have {kind} port(s): {', '.join(detail)}")
    bindings = []
    fields = []
    offset = 0
    for port in inputs:
        rule = rules[port.name]
        if not isinstance(rule, EnvironmentInputRuleV4):
            raise InputValidationError(f"environment v4 rule for {port.name} has the wrong type")
        rule.__post_init__()
        if rule.mode == "constant" and not 0 <= rule.constant_value < 1 << port.width:
            raise InputValidationError(
                f"environment v4 constant for {port.name} does not fit its width"
            )
        bindings.append(EnvironmentInputBindingV4(
            port.name, port.width, rule.mode, rule.constant_value,
            rule.reset_behavior, rule.reason, rule.evidence_source,
        ))
        if rule.mode == "replay":
            storage = (port.width + 7) // 8
            fields.append(EnvironmentReplayFieldV4(port.name, port.width, offset, storage))
            offset += storage * 8
    value = EnvironmentPlanV4(
        harness.soc_digest, harness.protocol_profile_digest, tuple(bindings),
        tuple(EnvironmentOutputObservationV4(port.name, port.width) for port in outputs),
        tuple(fields), offset, offset // 8,
    )
    return replace(value, digest=content_digest(value.payload_dict()))


def encode_environment_replay_v4(
    plan: EnvironmentPlanV4,
    records: Iterable[Mapping[str, int]],
    *,
    limits: EnvironmentReplayLimitsV4 = EnvironmentReplayLimitsV4(),
) -> bytes:
    plan.__post_init__()
    limits.__post_init__()
    if not plan.requires_replay:
        raise InputValidationError("environment v4 plan has no replay-driven inputs")
    payload = bytearray()
    expected_names = {field.port_name for field in plan.replay_fields}
    count = 0
    try:
        iterator = iter(records)
    except TypeError as exc:
        raise InputValidationError("environment v4 replay records must be iterable") from exc
    for index, record in enumerate(iterator):
        if index >= limits.max_records:
            raise InputValidationError("environment v4 replay record count is outside limits")
        if not isinstance(record, Mapping) or set(record) != expected_names:
            raise InputValidationError(
                f"environment v4 replay record[{index}] must define exactly the replay ports"
            )
        encoded = bytearray(plan.replay_record_width_bytes)
        for field in plan.replay_fields:
            value = record[field.port_name]
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 1 << field.width:
                raise InputValidationError(
                    f"environment v4 replay record[{index}].{field.port_name} does not fit"
                )
            start = field.offset_bits // 8
            encoded[start:start + field.storage_bytes] = value.to_bytes(field.storage_bytes, "little")
        payload.extend(encoded)
        count += 1
        if len(payload) > limits.max_payload_bytes:
            raise InputValidationError("environment v4 replay payload exceeds limits")
    if not count:
        raise InputValidationError("environment v4 replay record count is outside limits")
    header = _HEADER.pack(
        ENVIRONMENT_REPLAY_MAGIC_V4, 4, ENVIRONMENT_REPLAY_HEADER_BYTES_V4,
        plan.replay_record_width_bits, plan.replay_record_width_bytes, count,
        bytes.fromhex(plan.digest[:16]), len(payload), b"\x00" * 16, 0,
    )
    crc = zlib.crc32(header[:-4]) & 0xFFFFFFFF
    return header[:-4] + struct.pack("<I", crc) + payload


def decode_environment_replay_v4(
    plan: EnvironmentPlanV4,
    transport: bytes,
    *,
    limits: EnvironmentReplayLimitsV4 = EnvironmentReplayLimitsV4(),
) -> tuple[dict[str, int], ...]:
    count, payload = _validated_environment_replay(plan, transport, limits)
    result = []
    for record_index in range(count):
        base = record_index * plan.replay_record_width_bytes
        record = {}
        for field in plan.replay_fields:
            start = base + field.offset_bits // 8
            raw = int.from_bytes(payload[start:start + field.storage_bytes], "little")
            if raw >= 1 << field.width:
                raise InputValidationError(
                    f"environment v4 replay record[{record_index}].{field.port_name} has padding bits"
                )
            record[field.port_name] = raw
        result.append(record)
    return tuple(result)


def validate_environment_replay_v4(
    plan: EnvironmentPlanV4,
    transport: bytes,
    *,
    limits: EnvironmentReplayLimitsV4 = EnvironmentReplayLimitsV4(),
) -> int:
    """Validate framing and every padding bit without materializing record objects."""
    count, _ = _validated_environment_replay(plan, transport, limits)
    return count


def _validated_environment_replay(
    plan: EnvironmentPlanV4,
    transport: bytes,
    limits: EnvironmentReplayLimitsV4,
) -> tuple[int, memoryview]:
    plan.__post_init__()
    limits.__post_init__()
    if not plan.requires_replay:
        raise InputValidationError("environment v4 plan has no replay-driven inputs")
    if not isinstance(transport, bytes) or len(transport) < ENVIRONMENT_REPLAY_HEADER_BYTES_V4:
        raise InputValidationError("environment v4 replay transport is truncated")
    values = _HEADER.unpack(transport[:ENVIRONMENT_REPLAY_HEADER_BYTES_V4])
    (magic, version, header_bytes, width_bits, width_bytes, count, prefix,
     payload_bytes, reserved, expected_crc) = values
    actual_crc = zlib.crc32(transport[:ENVIRONMENT_REPLAY_HEADER_BYTES_V4 - 4]) & 0xFFFFFFFF
    if magic != ENVIRONMENT_REPLAY_MAGIC_V4 or version != 4 or header_bytes != 64:
        raise InputValidationError("environment v4 replay magic/version/header mismatch")
    if expected_crc != actual_crc or reserved != b"\x00" * 16:
        raise InputValidationError("environment v4 replay CRC/reserved bytes mismatch")
    if prefix != bytes.fromhex(plan.digest[:16]):
        raise InputValidationError("environment v4 replay plan digest prefix mismatch")
    if width_bits != plan.replay_record_width_bits or width_bytes != plan.replay_record_width_bytes:
        raise InputValidationError("environment v4 replay record geometry mismatch")
    if not count or count > limits.max_records:
        raise InputValidationError("environment v4 replay record count is outside limits")
    expected_payload = count * width_bytes
    if payload_bytes != expected_payload or payload_bytes > limits.max_payload_bytes:
        raise InputValidationError("environment v4 replay payload geometry exceeds limits")
    if len(transport) != ENVIRONMENT_REPLAY_HEADER_BYTES_V4 + payload_bytes:
        raise InputValidationError("environment v4 replay transport length mismatch")
    payload = memoryview(transport)[ENVIRONMENT_REPLAY_HEADER_BYTES_V4:]
    for record_index in range(count):
        base = record_index * width_bytes
        for field in plan.replay_fields:
            if field.width % 8:
                last = base + field.offset_bits // 8 + field.storage_bytes - 1
                if payload[last] & ~((1 << (field.width % 8)) - 1):
                    raise InputValidationError(
                        f"environment v4 replay record[{record_index}].{field.port_name} has padding bits"
                    )
    return count, payload


def environment_plan_v4_from_dict(value: Mapping[str, object]) -> EnvironmentPlanV4:
    if not isinstance(value, Mapping):
        raise InputValidationError("environment v4 plan must be an object")
    fields = set(EnvironmentPlanV4.__dataclass_fields__)
    missing, unknown = fields - set(value), set(value) - fields
    if missing or unknown:
        detail = sorted(missing or unknown)
        kind = "missing" if missing else "unknown"
        raise InputValidationError(
            f"environment v4 plan has {kind} field(s): {', '.join(detail)}"
        )
    try:
        normalized = dict(value)
        normalized["inputs"] = tuple(
            EnvironmentInputBindingV4(**dict(item)) for item in normalized["inputs"]
        )
        normalized["observed_outputs"] = tuple(
            EnvironmentOutputObservationV4(**dict(item))
            for item in normalized["observed_outputs"]
        )
        normalized["replay_fields"] = tuple(
            EnvironmentReplayFieldV4(**dict(item))
            for item in normalized["replay_fields"]
        )
        plan = EnvironmentPlanV4(**normalized)
    except (TypeError, ValueError) as exc:
        raise InputValidationError("environment v4 plan is malformed") from exc
    plan.__post_init__()
    if len(plan.digest) != 64:
        raise InputValidationError("environment v4 serialized plan must have a content digest")
    return plan


def _digest(value: object, name: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(
        char not in "0123456789abcdef" for char in value
    ):
        raise InputValidationError(f"{name} must be a lowercase SHA-256 digest")
