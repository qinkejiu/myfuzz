"""Strict, versioned contracts for the CPU/IP A/B/C experiment."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from enum import Enum
import hashlib
import json
from typing import Any, Iterable, Mapping

from ..input_model import InputValidationError


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def content_digest(value: Mapping[str, object]) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _digest(value: str, path: str) -> None:
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise InputValidationError(f"{path}: expected a lowercase SHA-256 digest")


class RomInstallKind(str, Enum):
    EXTERNAL_ROM = "external_rom"
    PRE_RESET_TCM_LOADER = "pre_reset_tcm_loader"


class VariantName(str, Enum):
    FLAT_RANDOM = "flat_random"
    GENERATED_RAW = "generated_raw"
    GENERATED_CONSTRAINED = "generated_constrained"


class TerminalStatus(str, Enum):
    COMPLETED = "completed"
    TIMED_OUT = "timed_out"


@dataclass(frozen=True)
class RomInstallBackend:
    kind: str
    loader_interface: str
    verification: str
    schema: str = "myfuzz.rom-install-backend/v1"

    def __post_init__(self) -> None:
        try:
            RomInstallKind(self.kind)
        except ValueError as exc:
            raise InputValidationError(f"unsupported ROM install backend {self.kind!r}") from exc
        if not self.loader_interface or not self.verification:
            raise InputValidationError("ROM install backend fields must be non-empty")

    def to_dict(self) -> dict[str, object]: return asdict(self)


@dataclass(frozen=True)
class CpuExecutionProfile:
    cpu_id: str
    isa: str
    data_width: int
    address_width: int
    reset_vector: int
    rom_window: Mapping[str, int]
    mailbox_window: Mapping[str, int]
    watchdog_window: Mapping[str, int]
    reset: Mapping[str, object]
    rom_install_backend: Mapping[str, object]
    startup_fragment_digest: str
    schema: str = "myfuzz.cpu-execution-profile/v1"

    def __post_init__(self) -> None:
        if not self.cpu_id or not self.isa or self.data_width != 32 or self.address_width <= 0:
            raise InputValidationError("CPU profile identity or width is invalid")
        if self.reset_vector < 0: raise InputValidationError("reset_vector must be non-negative")
        _digest(self.startup_fragment_digest, "startup_fragment_digest")
        for name, window in (("rom_window", self.rom_window), ("mailbox_window", self.mailbox_window),
                             ("watchdog_window", self.watchdog_window)):
            if set(window) != {"base", "size"} or window["base"] < 0 or window["size"] <= 0:
                raise InputValidationError(f"{name}: expected non-negative base and positive size")
        RomInstallBackend(**{k: v for k, v in self.rom_install_backend.items() if k != "schema"})

    def to_dict(self) -> dict[str, object]: return asdict(self)


@dataclass(frozen=True)
class AccessRecord:
    ip_select: int
    read_write: int
    offset: int
    data: int
    schema: str = "myfuzz.access-record/v1"

    def __post_init__(self) -> None:
        for name, value, maximum in (("ip_select", self.ip_select, 0xFFFFFFFF),
                                     ("read_write", self.read_write, 1),
                                     ("offset", self.offset, 0xFFFFFFFF),
                                     ("data", self.data, 0xFFFFFFFF)):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
                raise InputValidationError(f"AccessRecord.{name}: value is out of range")

    def to_dict(self) -> dict[str, object]: return asdict(self)


@dataclass(frozen=True)
class RecordTerminalAck:
    sequence: int
    status: str
    route: str
    address: int
    direction: str
    response: int | None
    cycles: int
    schema: str = "myfuzz.record-terminal-ack/v1"

    def __post_init__(self) -> None:
        if self.status not in {"completed", "timed_out"} or self.direction not in {"read", "write"}:
            raise InputValidationError("terminal ack status/direction is invalid")
        if not self.route or any(v < 0 for v in (self.sequence, self.address, self.cycles)):
            raise InputValidationError("terminal ack route/counters are invalid")
        if self.response is not None and self.response not in range(4):
            raise InputValidationError("terminal ack response must be 0..3 or null")

    def to_dict(self) -> dict[str, object]: return asdict(self)


@dataclass(frozen=True)
class ExperimentVariant:
    name: str
    generated_soc: bool
    constraints: bool
    schema: str = "myfuzz.experiment-variant/v1"

    def __post_init__(self) -> None:
        expected = {"flat_random": (False, False), "generated_raw": (True, False),
                    "generated_constrained": (True, True)}
        if self.name not in expected or (self.generated_soc, self.constraints) != expected[self.name]:
            raise InputValidationError("experiment variant flags are inconsistent")

    def to_dict(self) -> dict[str, object]: return asdict(self)


@dataclass(frozen=True)
class CoverageABIV2:
    catalog_digest: str
    port_name: str
    width: int
    epoch_width: int
    points: tuple[Mapping[str, object], ...]
    transport_width: int = 0
    writer: str = "instrumented_sequential_processes"
    sampling: str = "after_rising_edge_nba_settle"
    schema: str = "myfuzz.coverage-abi/v2"

    def __post_init__(self) -> None:
        if self.transport_width == 0:
            object.__setattr__(self, "transport_width", self.width)
        _digest(self.catalog_digest, "catalog_digest")
        if not self.port_name or self.width <= 0 or self.transport_width < self.width or self.epoch_width <= 1:
            raise InputValidationError("CoverageABI v2 dimensions are invalid")
        if self.writer != "instrumented_sequential_processes":
            raise InputValidationError("CoverageABI v2 single-writer contract is required")
        offsets = [p.get("offset") for p in self.points if p.get("included") is True]
        if offsets != list(range(self.width)):
            raise InputValidationError("CoverageABI v2 included offsets must densely match width")

    def to_dict(self) -> dict[str, object]: return asdict(self)

    @property
    def manifest_digest(self) -> str:
        return self.catalog_digest


def coverage_abi_v2_from_dict(value: Mapping[str, object]) -> CoverageABIV2:
    if not isinstance(value, Mapping):
        raise InputValidationError("CoverageABI v2 must be an object")
    fields = set(CoverageABIV2.__dataclass_fields__)
    if set(value) != fields:
        detail = sorted((fields - set(value)) or (set(value) - fields))
        kind = "missing" if fields - set(value) else "unknown"
        raise InputValidationError(
            f"CoverageABI v2 has {kind} field(s): {', '.join(detail)}"
        )
    points = value.get("points")
    if not isinstance(points, (tuple, list)) or any(not isinstance(item, Mapping) for item in points):
        raise InputValidationError("CoverageABI v2 points must be an array of objects")
    for name in ("width", "epoch_width", "transport_width"):
        if isinstance(value[name], bool) or not isinstance(value[name], int):
            raise InputValidationError(f"CoverageABI v2 {name} must be an integer")
    try:
        result = CoverageABIV2(
            str(value["catalog_digest"]), str(value["port_name"]),
            int(value["width"]), int(value["epoch_width"]),
            tuple(dict(item) for item in points),
            int(value["transport_width"]), str(value["writer"]),
            str(value["sampling"]), str(value["schema"]),
        )
    except (TypeError, ValueError) as exc:
        raise InputValidationError("CoverageABI v2 is malformed") from exc
    result.__post_init__()
    return result


@dataclass(frozen=True)
class ExperimentManifest:
    experiment_id: str
    cpu_profile: Mapping[str, object]
    variants: tuple[Mapping[str, object], ...]
    components: tuple[Mapping[str, object], ...]
    ip_instances: tuple[Mapping[str, object], ...]
    rawbits_layout_digest: str
    access_record_layout: Mapping[str, object]
    coverage_abi_digest: str
    transaction_slots: int
    cycle_budget: int
    digest: str = ""
    schema: str = "myfuzz.experiment-manifest/v1"

    def __post_init__(self) -> None:
        _digest(self.rawbits_layout_digest, "rawbits_layout_digest")
        _digest(self.coverage_abi_digest, "coverage_abi_digest")
        if not self.experiment_id or self.transaction_slots <= 0 or self.cycle_budget <= 0:
            raise InputValidationError("experiment identity/budgets are invalid")
        if [v.get("name") for v in self.variants] != [v.value for v in VariantName]:
            raise InputValidationError("experiment variants must be ordered A/B/C")
        ids = [v.get("component_id") for v in self.components]
        if ids != sorted(ids) or len(ids) != len(set(ids)):
            raise InputValidationError("component IDs must be unique and sorted")
        if self.digest and self.digest != content_digest(self.payload()):
            raise InputValidationError("experiment manifest digest mismatch")

    def payload(self) -> dict[str, object]:
        value = asdict(self); value.pop("digest"); return value

    def to_dict(self) -> dict[str, object]: return asdict(self)


def build_experiment_manifest(**kwargs: Any) -> ExperimentManifest:
    value = ExperimentManifest(**kwargs)
    return replace(value, digest=content_digest(value.payload()))


@dataclass(frozen=True)
class ExperimentResult:
    experiment_digest: str
    cpu_id: str
    variant: str
    repeat: int
    seed: int
    wall_seconds: float
    testcase_count: int
    consumed_inputs: int
    coverage_points_hit: int
    coverage_points_total: int
    coverage_trace: tuple[Mapping[str, object], ...]
    terminal_counts: Mapping[str, int]
    artifact_digests: tuple[Mapping[str, object], ...]
    schema: str = "myfuzz.experiment-result/v1"

    def __post_init__(self) -> None:
        _digest(self.experiment_digest, "experiment_digest")
        VariantName(self.variant)
        values = (self.repeat, self.seed, self.wall_seconds, self.testcase_count,
                  self.consumed_inputs, self.coverage_points_hit, self.coverage_points_total)
        if any(v < 0 for v in values) or self.coverage_points_hit > self.coverage_points_total:
            raise InputValidationError("experiment result counters are invalid")

    def to_dict(self) -> dict[str, object]: return asdict(self)


def sorted_objects(values: Iterable[Mapping[str, object]], key: str) -> tuple[Mapping[str, object], ...]:
    result = tuple(sorted((dict(v) for v in values), key=lambda v: str(v.get(key, ""))))
    if any(not v.get(key) for v in result): raise InputValidationError(f"missing sort key {key!r}")
    return result
