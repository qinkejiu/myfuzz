"""Controller-owned RawBits v4 producer and coverage decision loop."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Callable, Mapping, Sequence

from .adaptive_mutation_v4 import (
    AdaptiveMutationController, MutationConfig, MutationCandidate,
    MutationLevel, ProtocolLaneScheduler, protocol_campaign_policy,
)
from .input_model import InputValidationError
from .rawbits_v4 import (
    RawBitsV4Field, RawBitsV4Lane, RawBitsV4LaneLayout, RawBitsV4Layout,
    RawBitsV4Limits,
    RawBitsV4Submode,
    decode_rawbits_v4_testcase, encode_rawbits_v4_testcase,
)


@dataclass(frozen=True)
class ControllerResult:
    testcase_id: int
    lane: str
    transport_sha256: str
    new_branch_count: int
    coverage_digest: str
    observed_classification: str = "unknown"
    violation_rule: int | None = None
    violation_cycle: int | None = None
    transport_bytes: int = 0
    dut_cycles: int = 0
    wire_trace_edges: int = 0
    logical_records: int = 0
    accepted_records: int = 0
    record_stall_cycles: int = 0
    parent_digest: str | None = None
    mutation_operator: str | None = None
    mutation_position: int | None = None
    mutation_payload_digest: str | None = None
    mutation_level: str | None = None
    mutation_sites: int = 0
    mutation_generation: int = 0
    mutation_old_value: int | None = None
    mutation_new_value: int | None = None

    @property
    def declared_lane(self) -> str:
        return self.lane


@dataclass(frozen=True)
class AddressBiasConfigV4:
    """Generic mixed-support sampling policy derived from generated SoC windows."""

    windows: tuple[tuple[str, int, int], ...]
    aligned_weight: int = 6
    byte_weight: int = 1
    uniform_weight: int = 1
    schema: str = "myfuzz.address-bias/v4"

    def __post_init__(self) -> None:
        if not self.windows:
            raise InputValidationError("v4 address bias requires at least one target window")
        names: set[str] = set()
        for name, base, size in self.windows:
            if not name or name in names:
                raise InputValidationError("v4 address bias window names must be unique")
            names.add(name)
            if any(isinstance(value, bool) or not isinstance(value, int) for value in (base, size)):
                raise InputValidationError("v4 address bias window bounds must be integers")
            if base < 0 or size <= 0 or base + size > 1 << 64:
                raise InputValidationError("v4 address bias window is outside the 64-bit domain")
        weights = (self.aligned_weight, self.byte_weight, self.uniform_weight)
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in weights):
            raise InputValidationError("v4 address bias weights must be non-negative integers")
        if self.uniform_weight <= 0 or sum(weights) <= 0:
            raise InputValidationError("v4 address bias must retain a non-zero uniform path")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "windows": [
                {"name": name, "base": base, "size": size}
                for name, base, size in self.windows
            ],
            "aligned_weight": self.aligned_weight,
            "byte_weight": self.byte_weight,
            "uniform_weight": self.uniform_weight,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "AddressBiasConfigV4":
        if value.get("schema") != "myfuzz.address-bias/v4":
            raise InputValidationError("v4 address bias schema mismatch")
        raw_windows = value.get("windows")
        if not isinstance(raw_windows, Sequence) or isinstance(raw_windows, (str, bytes)):
            raise InputValidationError("v4 address bias windows are malformed")
        try:
            windows = tuple(
                (str(item["name"]), int(item["base"]), int(item["size"]))
                for item in raw_windows if isinstance(item, Mapping)
            )
            if len(windows) != len(raw_windows):
                raise InputValidationError("v4 address bias window is malformed")
            return cls(
                windows=windows,
                aligned_weight=int(value["aligned_weight"]),
                byte_weight=int(value["byte_weight"]),
                uniform_weight=int(value["uniform_weight"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise InputValidationError("v4 address bias is malformed") from exc


@dataclass(frozen=True)
class TargetExecutionResultV4:
    coverage_bitmap: bytes
    observed_classification: str
    violation_rule: int | None = None
    violation_cycle: int | None = None
    wire_trace_digest: str | None = None
    assertion_events: tuple[Mapping[str, object], ...] = ()
    dut_cycles: int = 0
    wire_trace_edges: int = 0
    logical_records: int = 0
    accepted_records: int = 0
    record_stall_cycles: int = 0
    schema: str = "myfuzz.target-execution-result/v4"

    def __post_init__(self) -> None:
        if not isinstance(self.coverage_bitmap, bytes):
            raise InputValidationError("v4 target coverage bitmap must be bytes")
        if self.observed_classification not in {"protocol_valid", "adversarial", "raw", "cpu_semantic"}:
            raise InputValidationError("v4 target observed classification is invalid")
        if (self.violation_rule is None) != (self.violation_cycle is None):
            raise InputValidationError("v4 target violation rule/cycle must be reported together")
        if self.violation_rule is not None and (self.violation_rule <= 0 or self.violation_cycle < 0):
            raise InputValidationError("v4 target violation metadata is invalid")
        if self.wire_trace_digest is not None and (
            len(self.wire_trace_digest) != 64
            or any(char not in "0123456789abcdef" for char in self.wire_trace_digest)
        ):
            raise InputValidationError("v4 target wire trace digest is invalid")
        for name in (
            "dut_cycles", "wire_trace_edges", "logical_records",
            "accepted_records", "record_stall_cycles",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise InputValidationError(f"v4 target {name} must be non-negative")
        if self.accepted_records > self.logical_records:
            raise InputValidationError("v4 target accepted record count exceeds logical records")


class CoverageUnionV4:
    """Small deterministic bitmap union used by the controller, not the DUT."""

    def __init__(self, width: int) -> None:
        if isinstance(width, bool) or not isinstance(width, int) or width <= 0:
            raise InputValidationError("coverage bitmap width must be positive")
        self.width = width
        self._bits = bytearray((width + 7) // 8)

    @property
    def digest(self) -> str:
        return hashlib.sha256(bytes(self._bits)).hexdigest()

    def merge(self, bitmap: bytes) -> int:
        if not isinstance(bitmap, bytes) or len(bitmap) != len(self._bits):
            raise InputValidationError("coverage bitmap width mismatch")
        new = 0
        for index, value in enumerate(bitmap):
            delta = value & ~self._bits[index]
            new += delta.bit_count()
            self._bits[index] |= value
        if self.width % 8:
            self._bits[-1] &= (1 << (self.width % 8)) - 1
        return new

    def snapshot(self) -> bytes:
        return bytes(self._bits)


def canonical_protocol_legality_rules_v4(
    rules: Mapping[str, int] | None,
) -> dict[str, int]:
    if rules is None:
        return {}
    if not isinstance(rules, Mapping):
        raise InputValidationError("v4 protocol legality rules must be a mapping")
    result: dict[str, int] = {}
    ids: set[int] = set()
    for name, rule_id in sorted(rules.items()):
        if not isinstance(name, str) or not name:
            raise InputValidationError("v4 protocol legality rule name is invalid")
        if (
            isinstance(rule_id, bool) or not isinstance(rule_id, int)
            or not 1 <= rule_id <= 255 or rule_id in ids
        ):
            raise InputValidationError("v4 protocol legality rule id is invalid or duplicated")
        result[name] = rule_id
        ids.add(rule_id)
    return result


class V4TargetServer:
    """Target-side framing gate; malformed chunks never reach the DUT callback."""

    def __init__(
        self, layout: RawBitsV4Layout,
        execute: Callable[[object], bytes | TargetExecutionResultV4],
        limits: RawBitsV4Limits = RawBitsV4Limits(),
        *, legality_rules: Mapping[str, int] | None = None,
    ) -> None:
        self.layout = layout
        self.execute = execute
        self.limits = limits
        self.legality_rules = canonical_protocol_legality_rules_v4(legality_rules)

    def handle(self, transport: bytes) -> bytes:
        return self.handle_result(transport).coverage_bitmap

    def handle_result(
        self,
        transport: bytes,
        *,
        poll_callback: Callable[[], None] | None = None,
        poll_interval_seconds: float = 1.0,
    ) -> TargetExecutionResultV4:
        del poll_interval_seconds
        testcase = decode_rawbits_v4_testcase(self.layout, transport, limits=self.limits)
        if poll_callback is not None:
            poll_callback()
        result = self.execute(testcase)
        if isinstance(result, TargetExecutionResultV4):
            return result
        if isinstance(result, bytes):
            defaults = {
                RawBitsV4Lane.RAW_ESCAPE: "raw",
                RawBitsV4Lane.PROTOCOL_WAVEFORM: "protocol_valid",
                RawBitsV4Lane.ADVERSARIAL_MUTATION: "adversarial",
                RawBitsV4Lane.CPU_SEMANTIC: "cpu_semantic",
            }
            return TargetExecutionResultV4(result, defaults[RawBitsV4Lane[testcase.lane]])
        raise InputValidationError("v4 target server callback must return bytes or TargetExecutionResultV4")


class V4Controller:
    """Produce, dispatch, and account for one v4 campaign in one process."""

    def __init__(
        self,
        layout: RawBitsV4Layout,
        *,
        policy: str,
        seed: int,
        coverage_bits: int,
        limits: RawBitsV4Limits = RawBitsV4Limits(),
        mutation_config: MutationConfig | None = None,
        address_bias: AddressBiasConfigV4 | None = None,
    ) -> None:
        if policy not in {"B", "C", "D"}:
            raise InputValidationError("v4 controller policy must be B, C, or D")
        if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
            raise InputValidationError("v4 controller seed must be non-negative")
        self.layout = layout
        self.policy = protocol_campaign_policy(policy)
        self.seed = seed
        self.limits = limits
        self.coverage = CoverageUnionV4(coverage_bits)
        self.scheduler = ProtocolLaneScheduler(self.policy)
        self.mutation = AdaptiveMutationController(seed, mutation_config) if policy == "D" else None
        self.address_bias = address_bias
        if address_bias is not None:
            self._validate_address_bias_layout(address_bias)
        self.results: list[ControllerResult] = []
        self._counter = 0
        self._next_testcase_id = 0
        self._last_payload: tuple[int, ...] | None = None
        self._protocol_seed_projection = self._build_protocol_seed_projection()
        self._latest_protocol_seed: tuple[int, ...] | None = None
        self._corpus_payloads: dict[str, tuple[int, ...]] = {}
        self._pending_candidate: MutationCandidate | None = None

    def run(
        self,
        dispatch: Callable[[bytes], bytes | TargetExecutionResultV4],
        *,
        testcase_count: int,
        records_per_testcase: int = 1,
    ) -> tuple[ControllerResult, ...]:
        if isinstance(testcase_count, bool) or not isinstance(testcase_count, int) or testcase_count < 0:
            raise InputValidationError("testcase_count must be non-negative")
        if isinstance(records_per_testcase, bool) or not 1 <= records_per_testcase <= self.limits.max_logical_records:
            raise InputValidationError("records_per_testcase is outside manifest limits")
        start = len(self.results)
        for _ in range(testcase_count):
            testcase_id = self._next_testcase_id
            self._next_testcase_id += 1
            lane = self.scheduler.choose()
            submode = RawBitsV4Submode.RAW_LITERAL if lane is RawBitsV4Lane.RAW_ESCAPE else (
                RawBitsV4Submode.GUARDED_INTENT
                if lane is RawBitsV4Lane.PROTOCOL_WAVEFORM
                else RawBitsV4Submode.MUTATION
            )
            self._pending_candidate = None
            payload = self._payload(lane, submode, records_per_testcase)
            transport = encode_rawbits_v4_testcase(
                self.layout, lane=lane, submode=submode,
                logical_testcase_id=testcase_id, records=payload, limits=self.limits,
            )
            try:
                execution = dispatch(transport)
            except BaseException:
                self._pending_candidate = None
                raise
            if isinstance(execution, TargetExecutionResultV4):
                bitmap = execution.coverage_bitmap
                observed = execution.observed_classification
                violation_rule = execution.violation_rule
                violation_cycle = execution.violation_cycle
                dut_cycles = execution.dut_cycles
                wire_trace_edges = execution.wire_trace_edges
                logical_records = execution.logical_records
                accepted_records = execution.accepted_records
                record_stall_cycles = execution.record_stall_cycles
            else:
                bitmap = execution
                observed = {
                    RawBitsV4Lane.RAW_ESCAPE: "raw",
                    RawBitsV4Lane.PROTOCOL_WAVEFORM: "protocol_valid",
                    RawBitsV4Lane.ADVERSARIAL_MUTATION: "adversarial",
                }[lane]
                violation_rule = violation_cycle = None
                dut_cycles = wire_trace_edges = 0
                logical_records = accepted_records = records_per_testcase
                record_stall_cycles = 0
            new_count = self.coverage.merge(bitmap)
            mutation_candidate = self._pending_candidate
            if self.mutation is not None:
                if mutation_candidate is not None:
                    retained = self.mutation.record(
                        mutation_candidate, new_branch=new_count > 0,
                        initial_seed=mutation_candidate.operator in {
                            "seed", "protocol_seed",
                        },
                    )
                    if retained:
                        self._corpus_payloads[
                            mutation_candidate.payload_digest
                        ] = tuple(payload)
                    self._prune_corpus_payloads()
                elif (
                    lane is RawBitsV4Lane.PROTOCOL_WAVEFORM
                    and self.mutation.has_seeds
                    and self._latest_protocol_seed is not None
                ):
                    protocol_digest = self._payload_digest(self._latest_protocol_seed)
                    protocol_candidate = MutationCandidate(
                        parent_digest="", operator="protocol_seed", position=0,
                        payload_digest=protocol_digest, level=MutationLevel.L0,
                        mutation_sites=0, generation=0,
                    )
                    if self.mutation.record_protocol_seed(
                        protocol_candidate, new_branch=new_count > 0,
                    ):
                        self._corpus_payloads[protocol_digest] = self._latest_protocol_seed
                    self._prune_corpus_payloads()
                self.mutation.observe_result(new_count)
            result = ControllerResult(
                testcase_id=testcase_id, lane=lane.name,
                transport_sha256=hashlib.sha256(transport).hexdigest(),
                new_branch_count=new_count, coverage_digest=self.coverage.digest,
                observed_classification=observed, violation_rule=violation_rule,
                violation_cycle=violation_cycle, transport_bytes=len(transport),
                dut_cycles=dut_cycles, wire_trace_edges=wire_trace_edges,
                logical_records=logical_records, accepted_records=accepted_records,
                record_stall_cycles=record_stall_cycles,
                parent_digest=(
                    mutation_candidate.parent_digest if mutation_candidate else None
                ),
                mutation_operator=(
                    mutation_candidate.operator if mutation_candidate else None
                ),
                mutation_position=(
                    mutation_candidate.position if mutation_candidate else None
                ),
                mutation_payload_digest=(
                    mutation_candidate.payload_digest if mutation_candidate else None
                ),
                mutation_level=(
                    mutation_candidate.level.name if mutation_candidate else None
                ),
                mutation_sites=(
                    mutation_candidate.mutation_sites if mutation_candidate else 0
                ),
                mutation_generation=(
                    mutation_candidate.generation if mutation_candidate else 0
                ),
                mutation_old_value=(
                    mutation_candidate.old_value if mutation_candidate else None
                ),
                mutation_new_value=(
                    mutation_candidate.new_value if mutation_candidate else None
                ),
            )
            self.results.append(result)
            self._pending_candidate = None
        return tuple(self.results[start:])

    def manifest(self) -> Mapping[str, object]:
        return {
            "schema": "myfuzz.controller/v4",
            "policy": self.policy.name,
            "seed": self.seed,
            "layout_digest": self.layout.digest,
            "coverage_bits": self.coverage.width,
            "limits": self.limits.__dict__.copy(),
            "mutation": self.mutation.level.name if self.mutation is not None else None,
            "mutation_diagnostics": (
                self.mutation.diagnostics() if self.mutation is not None else None
            ),
            "address_bias": None if self.address_bias is None else self.address_bias.to_dict(),
            "protocol_seed_projection": self._protocol_seed_projection_manifest(),
            "protocol_sequence_templates": {
                "schema": "myfuzz.protocol-sequence-templates/v4",
                "random_share": "11/16",
                "modes": [
                    "random", "write_backpressure", "read_backpressure",
                    "partial_write", "boundary_read", "reset_recovery",
                ],
            },
        }

    def checkpoint(self) -> Mapping[str, object]:
        return {
            "schema": "myfuzz.controller-state/v4",
            "layout_digest": self.layout.digest,
            "policy": self.policy.name,
            "seed": self.seed,
            "coverage_bits": self.coverage.width,
            "coverage_bitmap_hex": self.coverage.snapshot().hex(),
            "producer_counter": self._counter,
            "next_testcase_id": self._next_testcase_id,
            "last_payload": list(self._last_payload) if self._last_payload is not None else None,
            "latest_protocol_seed": (
                list(self._latest_protocol_seed)
                if self._latest_protocol_seed is not None else None
            ),
            "corpus_payloads": {
                digest: list(payload)
                for digest, payload in sorted(self._corpus_payloads.items())
            },
            "dispatched": {lane.name: count for lane, count in self.scheduler.dispatched.items()},
            "mutation": self.mutation.checkpoint() if self.mutation is not None else None,
            "address_bias": None if self.address_bias is None else self.address_bias.to_dict(),
        }

    def decision_checkpoint_bundle(
        self,
    ) -> tuple[Mapping[str, object], Mapping[str, bytes]]:
        """Freeze a pre-dispatch state with content-addressed coverage/corpus objects."""
        if self._pending_candidate is not None:
            raise InputValidationError(
                "v4 decision checkpoint cannot capture an in-flight testcase"
            )
        controller_state = dict(self.checkpoint())
        controller_state.pop("coverage_bitmap_hex")
        controller_state.pop("corpus_payloads")
        coverage = self.coverage.snapshot()
        coverage_digest = hashlib.sha256(coverage).hexdigest()
        objects: dict[str, bytes] = {"coverage": coverage}
        corpus_references: dict[str, str] = {}
        for digest, payload in sorted(self._corpus_payloads.items()):
            encoded = self._payload_bytes(payload)
            if hashlib.sha256(encoded).hexdigest() != digest:
                raise InputValidationError("v4 corpus payload digest changed before checkpoint")
            name = f"corpus/{digest}"
            objects[name] = encoded
            corpus_references[digest] = digest
        state = {
            "schema": "myfuzz.controller-decision-checkpoint/v4",
            "controller": controller_state,
            "object_references": {
                "coverage": coverage_digest,
                "corpus": corpus_references,
            },
        }
        return state, objects

    @classmethod
    def from_decision_checkpoint_bundle(
        cls, layout: RawBitsV4Layout, state: Mapping[str, object],
        objects: Mapping[str, bytes], *,
        limits: RawBitsV4Limits = RawBitsV4Limits(),
    ) -> "V4Controller":
        if state.get("schema") != "myfuzz.controller-decision-checkpoint/v4":
            raise InputValidationError("v4 decision checkpoint schema mismatch")
        try:
            controller_state = dict(state["controller"])
            references = dict(state["object_references"])
            coverage_digest = str(references["coverage"])
            corpus_references = dict(references["corpus"])
        except (KeyError, TypeError, ValueError) as exc:
            raise InputValidationError("v4 decision checkpoint is malformed") from exc
        expected_names = {"coverage"} | {
            f"corpus/{digest}" for digest in corpus_references
        }
        if set(objects) != expected_names:
            raise InputValidationError("v4 decision checkpoint object closure mismatch")
        coverage = objects["coverage"]
        if hashlib.sha256(coverage).hexdigest() != coverage_digest:
            raise InputValidationError("v4 decision checkpoint coverage digest mismatch")
        try:
            coverage_bits = int(controller_state["coverage_bits"])
        except (KeyError, TypeError, ValueError) as exc:
            raise InputValidationError("v4 decision checkpoint coverage width is malformed") from exc
        if len(coverage) != (coverage_bits + 7) // 8:
            raise InputValidationError("v4 decision checkpoint coverage width mismatch")
        if coverage_bits % 8 and coverage[-1] & ~((1 << (coverage_bits % 8)) - 1):
            raise InputValidationError("v4 decision checkpoint coverage padding is nonzero")

        corpus_payloads: dict[str, list[int]] = {}
        for raw_digest, referenced_digest in corpus_references.items():
            digest = str(raw_digest)
            if str(referenced_digest) != digest:
                raise InputValidationError("v4 decision checkpoint corpus reference mismatch")
            payload = objects[f"corpus/{digest}"]
            if hashlib.sha256(payload).hexdigest() != digest:
                raise InputValidationError("v4 decision checkpoint corpus digest mismatch")
            corpus_payloads[digest] = list(
                cls._decode_payload_bytes(layout, payload, limits)
            )
        controller_state["coverage_bitmap_hex"] = coverage.hex()
        controller_state["corpus_payloads"] = corpus_payloads
        return cls.from_checkpoint(layout, controller_state, limits=limits)

    @classmethod
    def from_checkpoint(
        cls, layout: RawBitsV4Layout, value: Mapping[str, object],
        *, limits: RawBitsV4Limits = RawBitsV4Limits(),
    ) -> "V4Controller":
        if value.get("schema") != "myfuzz.controller-state/v4" or value.get("layout_digest") != layout.digest:
            raise InputValidationError("v4 controller checkpoint schema/layout mismatch")
        try:
            raw_bias = value.get("address_bias")
            address_bias = (
                None if raw_bias is None
                else AddressBiasConfigV4.from_dict(raw_bias)
                if isinstance(raw_bias, Mapping)
                else None
            )
            if raw_bias is not None and address_bias is None:
                raise InputValidationError("v4 controller checkpoint address bias is malformed")
            controller = cls(
                layout, policy=str(value["policy"]), seed=int(value["seed"]),
                coverage_bits=int(value["coverage_bits"]), limits=limits,
                address_bias=address_bias,
            )
            bitmap = bytes.fromhex(str(value["coverage_bitmap_hex"]))
            controller.coverage.merge(bitmap)
            controller._counter = int(value["producer_counter"])
            controller._next_testcase_id = int(value["next_testcase_id"])
            last = value["last_payload"]
            controller._last_payload = None if last is None else tuple(int(item) for item in last)
            protocol_seed = value.get("latest_protocol_seed")
            controller._latest_protocol_seed = (
                None if protocol_seed is None
                else tuple(int(item) for item in protocol_seed)
            )
            controller._validate_latest_protocol_seed()
            dispatched = dict(value["dispatched"])
            for lane in controller.scheduler.dispatched:
                controller.scheduler.dispatched[lane] = int(dispatched[lane.name])
            mutation = value["mutation"]
            if controller.mutation is not None:
                if not isinstance(mutation, Mapping):
                    raise InputValidationError("D controller checkpoint lacks mutation state")
                controller.mutation = AdaptiveMutationController.from_checkpoint(mutation)
                raw_payloads = value.get("corpus_payloads", {})
                if not isinstance(raw_payloads, Mapping):
                    raise InputValidationError("D controller corpus payloads are malformed")
                controller._corpus_payloads = {
                    str(digest): tuple(int(item) for item in payload)
                    for digest, payload in raw_payloads.items()
                }
                controller._validate_corpus_payloads()
            elif mutation is not None:
                raise InputValidationError("non-D controller checkpoint contains mutation state")
        except (KeyError, TypeError, ValueError) as exc:
            raise InputValidationError("v4 controller checkpoint is malformed") from exc
        return controller

    def _payload(
        self,
        lane: RawBitsV4Lane,
        submode: RawBitsV4Submode,
        count: int,
    ) -> tuple[int, ...]:
        lane_layout = self.layout.lane_layout(lane)
        masks = dict(lane_layout.submode_used_masks)
        try:
            used_mask = masks[submode.name]
        except KeyError as exc:
            raise InputValidationError(
                f"controller lane {lane.name} does not support submode {submode.name}"
            ) from exc
        if lane is RawBitsV4Lane.ADVERSARIAL_MUTATION:
            values, candidate = self._mutation_payload(used_mask, count)
            self._last_payload = values
            self._pending_candidate = candidate
            return values
        values = []
        for index in range(count):
            digest = hashlib.sha256(
                f"myfuzz-controller-v4:{self.seed}:{self._counter}:{lane.name}:{index}".encode()
            ).digest()
            self._counter += 1
            value = int.from_bytes(digest, "little") & used_mask
            if (
                lane is RawBitsV4Lane.PROTOCOL_WAVEFORM
                and submode is RawBitsV4Submode.GUARDED_INTENT
                and self.address_bias is not None
            ):
                value = self._bias_protocol_addresses(value, digest, lane_layout)
            values.append(value)
        result = tuple(values)
        if (
            lane is RawBitsV4Lane.PROTOCOL_WAVEFORM
            and submode is RawBitsV4Submode.GUARDED_INTENT
        ):
            protocol_ordinal = (
                self.scheduler.dispatched[RawBitsV4Lane.PROTOCOL_WAVEFORM] - 1
            )
            result = self._shape_protocol_sequence(
                result, lane_layout, protocol_ordinal,
            )
        if (
            lane is RawBitsV4Lane.PROTOCOL_WAVEFORM
            and submode is RawBitsV4Submode.GUARDED_INTENT
            and self._protocol_seed_projection is not None
        ):
            self._latest_protocol_seed = self._project_protocol_payload(result)
        return result

    def _mutation_payload(
        self, used_mask: int, count: int,
    ) -> tuple[tuple[int, ...], MutationCandidate]:
        parent = self.mutation.choose_parent() if self.mutation is not None else None
        if parent is not None:
            try:
                base = self._corpus_payloads[parent.payload_digest]
            except KeyError as exc:
                raise InputValidationError(
                    "D controller corpus references a missing payload"
                ) from exc
        elif self.mutation is None and self._last_payload is not None:
            base = self._last_payload
        else:
            if self._latest_protocol_seed is not None:
                values = self._latest_protocol_seed
                operator = "protocol_seed"
            else:
                values = tuple(
                    int.from_bytes(self._producer_draw("mutation-seed", index), "little")
                    & used_mask
                    for index in range(count)
                )
                operator = "seed"
            digest = self._payload_digest(values)
            return values, MutationCandidate(
                parent_digest="", operator=operator, position=0,
                payload_digest=digest, level=MutationLevel.L0,
                mutation_sites=0, generation=0,
            )

        level = self.mutation.level if self.mutation is not None else MutationLevel.L0
        entropy = self._producer_draw("mutation-decision", len(base))
        operators = {
            MutationLevel.L0: ("bit_flip",),
            MutationLevel.L1: ("bit_flip", "record_swap"),
            MutationLevel.L2: (
                "bit_flip", "record_swap", "record_delete",
                "record_duplicate", "record_insert",
            ),
        }[level]
        operator = operators[int.from_bytes(entropy[:8], "little") % len(operators)]
        if len(base) < 2 and operator in {"record_swap", "record_delete"}:
            operator = "bit_flip"
        maximum = (
            1 if self.mutation is None
            else self.mutation.config.max_sites[int(level)]
        )
        requested_sites = 1 + int.from_bytes(entropy[8:16], "little") % maximum
        values, position, actual_sites, old_value, new_value = self._apply_mutation(
            tuple(base), used_mask, operator, requested_sites, entropy,
        )
        digest = self._payload_digest(values)
        parent_digest = (
            parent.payload_digest if parent is not None
            else self._payload_digest(tuple(base))
        )
        generation = 1 if parent is None else parent.generation + 1
        return values, MutationCandidate(
            parent_digest=parent_digest, operator=operator, position=position,
            payload_digest=digest, level=level, mutation_sites=actual_sites,
            generation=generation, old_value=old_value, new_value=new_value,
        )

    def _apply_mutation(
        self, base: tuple[int, ...], used_mask: int, operator: str,
        requested_sites: int, entropy: bytes,
    ) -> tuple[tuple[int, ...], int, int, int | None, int | None]:
        values = list(base)
        first_position = 0
        actual_sites = 0
        first_old_value: int | None = None
        first_new_value: int | None = None
        if operator == "bit_flip":
            positions = [
                record_index * self.layout.record_width_bits + bit
                for record_index in range(len(values))
                for bit in range(self.layout.record_width_bits)
                if used_mask & (1 << bit)
            ]
            available = list(positions)
            for site in range(min(requested_sites, len(available))):
                draw = hashlib.sha256(entropy + site.to_bytes(4, "little")).digest()
                selected_index = int.from_bytes(draw[:8], "little") % len(available)
                position = available.pop(selected_index)
                if actual_sites == 0:
                    first_position = position
                record_index, bit = divmod(position, self.layout.record_width_bits)
                old_bit = (values[record_index] >> bit) & 1
                values[record_index] ^= 1 << bit
                if actual_sites == 0:
                    first_old_value = old_bit
                    first_new_value = old_bit ^ 1
                actual_sites += 1
        elif operator == "record_swap":
            if len(values) >= 2:
                for site in range(requested_sites):
                    draw = hashlib.sha256(entropy + site.to_bytes(4, "little")).digest()
                    left = int.from_bytes(draw[:8], "little") % len(values)
                    right = int.from_bytes(draw[8:16], "little") % len(values)
                    if left == right:
                        right = (right + 1) % len(values)
                    if actual_sites == 0:
                        first_position = min(left, right)
                        first_old_value = values[first_position]
                    values[left], values[right] = values[right], values[left]
                    if actual_sites == 0:
                        first_new_value = values[first_position]
                    actual_sites += 1
        elif operator == "record_delete":
            for site in range(min(requested_sites, max(0, len(values) - 1))):
                draw = hashlib.sha256(entropy + site.to_bytes(4, "little")).digest()
                position = int.from_bytes(draw[:8], "little") % len(values)
                if actual_sites == 0:
                    first_position = position
                    first_old_value = values[position]
                    first_new_value = None
                del values[position]
                actual_sites += 1
        elif operator in {"record_duplicate", "record_insert"}:
            transport_record_limit = min(
                self.limits.max_logical_records,
                self.limits.max_chunk_payload_bytes // self.layout.record_width_bytes,
                max(0, self.limits.max_testcase_bytes - 64)
                // self.layout.record_width_bytes,
            )
            room = transport_record_limit - len(values)
            for site in range(min(requested_sites, room)):
                draw = hashlib.sha256(entropy + site.to_bytes(4, "little")).digest()
                position = int.from_bytes(draw[:8], "little") % (len(values) + 1)
                if operator == "record_duplicate":
                    source = int.from_bytes(draw[8:16], "little") % len(values)
                    value = values[source]
                else:
                    value = int.from_bytes(draw, "little") & used_mask
                if actual_sites == 0:
                    first_position = position
                    first_old_value = None
                    first_new_value = value
                values.insert(position, value)
                actual_sites += 1
        else:
            raise InputValidationError("unknown v4 mutation operator")
        if actual_sites <= 0:
            raise InputValidationError("v4 mutation operator could not mutate its parent")
        return (
            tuple(values), first_position, actual_sites,
            first_old_value, first_new_value,
        )

    def _producer_draw(self, domain: str, ordinal: int) -> bytes:
        digest = hashlib.sha256(
            f"myfuzz-controller-v4:{self.seed}:{self._counter}:{domain}:{ordinal}".encode()
        ).digest()
        self._counter += 1
        return digest

    def _payload_digest(self, values: tuple[int, ...]) -> str:
        return hashlib.sha256(self._payload_bytes(values)).hexdigest()

    def _payload_bytes(self, values: tuple[int, ...]) -> bytes:
        return len(values).to_bytes(8, "little") + b"".join(
            value.to_bytes(self.layout.record_width_bytes, "little")
            for value in values
        )

    @staticmethod
    def _decode_payload_bytes(
        layout: RawBitsV4Layout, payload: bytes, limits: RawBitsV4Limits,
    ) -> tuple[int, ...]:
        if len(payload) < 8:
            raise InputValidationError("v4 decision checkpoint corpus object is truncated")
        count = int.from_bytes(payload[:8], "little")
        if count <= 0 or count > limits.max_logical_records:
            raise InputValidationError("v4 decision checkpoint corpus record count is invalid")
        expected = 8 + count * layout.record_width_bytes
        if expected != len(payload) or len(payload) - 8 > limits.max_chunk_payload_bytes:
            raise InputValidationError("v4 decision checkpoint corpus object size is invalid")
        if len(payload) > limits.max_testcase_bytes:
            raise InputValidationError("v4 decision checkpoint corpus object exceeds testcase limit")
        used_mask = layout.lane_layout(
            RawBitsV4Lane.ADVERSARIAL_MUTATION
        ).used_mask_for(RawBitsV4Submode.MUTATION)
        values = tuple(
            int.from_bytes(
                payload[8 + index * layout.record_width_bytes:
                        8 + (index + 1) * layout.record_width_bytes],
                "little",
            )
            for index in range(count)
        )
        if any(value & ~used_mask for value in values):
            raise InputValidationError("v4 decision checkpoint corpus used-mask mismatch")
        return values

    def _prune_corpus_payloads(self) -> None:
        if self.mutation is None:
            return
        retained = set(self.mutation.retained_payload_digests())
        self._corpus_payloads = {
            digest: payload for digest, payload in self._corpus_payloads.items()
            if digest in retained
        }

    def _validate_corpus_payloads(self) -> None:
        if self.mutation is None:
            return
        expected = set(self.mutation.retained_payload_digests())
        if set(self._corpus_payloads) != expected:
            raise InputValidationError(
                "D controller checkpoint corpus payload closure is incomplete"
            )
        used_mask = self.layout.lane_layout(
            RawBitsV4Lane.ADVERSARIAL_MUTATION
        ).used_mask_for(RawBitsV4Submode.MUTATION)
        for digest, payload in self._corpus_payloads.items():
            if not payload or any(value < 0 or value & ~used_mask for value in payload):
                raise InputValidationError("D controller corpus payload is invalid")
            if self._payload_digest(payload) != digest:
                raise InputValidationError("D controller corpus payload digest mismatch")

    def _validate_address_bias_layout(self, bias: AddressBiasConfigV4) -> None:
        fields = {
            field.name: field
            for field in self.layout.lane_layout(RawBitsV4Lane.PROTOCOL_WAVEFORM).fields
        }
        for name in ("guarded_awaddr", "guarded_araddr"):
            field = fields.get(name)
            if field is None or "GUARDED_INTENT" not in field.submodes:
                raise InputValidationError(f"v4 address bias requires {name} in guarded intent")
            limit = 1 << field.width
            if any(base + size > limit for _window, base, size in bias.windows):
                raise InputValidationError(f"v4 address bias window exceeds {name} width")

    @staticmethod
    def _protocol_seed_role(name: str, prefix: str) -> str | None:
        if not name.startswith(prefix):
            return None
        role = name[len(prefix):]
        return {
            "ar_start": "arvalid",
            "aw_start": "awvalid",
            "w_start": "wvalid",
        }.get(role, role)

    def _build_protocol_seed_projection(
        self,
    ) -> tuple[tuple[RawBitsV4Field, RawBitsV4Field], ...] | None:
        protocol_fields: dict[str, RawBitsV4Field] = {}
        for field in self.layout.lane_layout(
            RawBitsV4Lane.PROTOCOL_WAVEFORM
        ).fields:
            if "GUARDED_INTENT" not in field.submodes:
                continue
            role = self._protocol_seed_role(field.name, "guarded_")
            if role is not None:
                if role in protocol_fields:
                    return None
                protocol_fields[role] = field
        mutation_fields: dict[str, RawBitsV4Field] = {}
        for field in self.layout.lane_layout(
            RawBitsV4Lane.ADVERSARIAL_MUTATION
        ).fields:
            if "MUTATION" not in field.submodes:
                continue
            role = self._protocol_seed_role(field.name, "mutation_")
            if role is None or role in mutation_fields:
                return None
            mutation_fields[role] = field
        if not mutation_fields or set(mutation_fields) - set(protocol_fields):
            return None
        if any(
            protocol_fields[role].width != mutation_field.width
            for role, mutation_field in mutation_fields.items()
        ):
            return None
        return tuple(
            (protocol_fields[role], mutation_fields[role])
            for role in sorted(mutation_fields)
        )

    def _protocol_seed_projection_manifest(self) -> Mapping[str, object]:
        if self._protocol_seed_projection is None:
            return {
                "schema": "myfuzz.guarded-intent-projection/v4",
                "available": False,
                "reason": "incomplete_or_width_mismatched_semantic_fields",
                "fields": [],
            }
        return {
            "schema": "myfuzz.guarded-intent-projection/v4",
            "available": True,
            "reason": None,
            "fields": [
                {
                    "source": source.name,
                    "target": target.name,
                    "width": source.width,
                }
                for source, target in self._protocol_seed_projection
            ],
        }

    def _project_protocol_payload(
        self, payload: tuple[int, ...],
    ) -> tuple[int, ...]:
        if self._protocol_seed_projection is None:
            raise InputValidationError("v4 protocol seed projection is unavailable")
        projected = []
        for record in payload:
            value = 0
            for source, target in self._protocol_seed_projection:
                field_value = (record >> source.offset) & ((1 << source.width) - 1)
                value |= field_value << target.offset
            projected.append(value)
        return tuple(projected)

    def _validate_latest_protocol_seed(self) -> None:
        if self._latest_protocol_seed is None:
            return
        if self._protocol_seed_projection is None or not self._latest_protocol_seed:
            raise InputValidationError("v4 checkpoint protocol seed projection is invalid")
        used_mask = self.layout.lane_layout(
            RawBitsV4Lane.ADVERSARIAL_MUTATION
        ).used_mask_for(RawBitsV4Submode.MUTATION)
        if any(
            value < 0 or value & ~used_mask
            for value in self._latest_protocol_seed
        ):
            raise InputValidationError("v4 checkpoint protocol seed used-mask mismatch")

    def _bias_protocol_addresses(self, value: int, digest: bytes, lane_layout) -> int:
        fields = {field.name: field for field in lane_layout.fields}
        for ordinal, field_name in enumerate(("guarded_awaddr", "guarded_araddr")):
            field = fields[field_name]
            entropy = hashlib.sha256(digest + field_name.encode("ascii") + bytes((ordinal,))).digest()
            total = (
                self.address_bias.aligned_weight
                + self.address_bias.byte_weight
                + self.address_bias.uniform_weight
            )
            choice = int.from_bytes(entropy[:8], "little") % total
            if choice >= self.address_bias.aligned_weight + self.address_bias.byte_weight:
                continue
            window = self.address_bias.windows[
                int.from_bytes(entropy[8:16], "little") % len(self.address_bias.windows)
            ]
            _name, base, size = window
            if choice < self.address_bias.aligned_weight:
                slots = max(1, size // 4)
                offset = (int.from_bytes(entropy[16:24], "little") % slots) * 4
            else:
                offset = int.from_bytes(entropy[16:24], "little") % size
            mask = ((1 << field.width) - 1) << field.offset
            value = (value & ~mask) | ((base + offset) << field.offset)
        return value

    def _shape_protocol_sequence(
        self, values: tuple[int, ...], lane_layout: RawBitsV4LaneLayout,
        ordinal: int,
    ) -> tuple[int, ...]:
        """Mix bounded semantic sequences into the otherwise random bit stream."""
        mode = ordinal % 16
        if mode < 11 or len(values) < 4:
            return values
        fields = {field.name: field for field in lane_layout.fields}
        control_names = (
            "guarded_aw_start", "guarded_w_start", "guarded_bready",
            "guarded_ar_start", "guarded_rready", "guarded_dut_reset",
        )
        if any(name not in fields for name in control_names):
            return values

        def assign(record: int, name: str, field_value: int) -> int:
            field = fields[name]
            mask = ((1 << field.width) - 1) << field.offset
            return (record & ~mask) | ((field_value << field.offset) & mask)

        shaped = list(values)
        for index, record in enumerate(shaped):
            for name in control_names:
                record = assign(record, name, 0)
            shaped[index] = record

        address = None
        if self.address_bias is not None:
            _name, base, size = self.address_bias.windows[
                (ordinal // 16) % len(self.address_bias.windows)
            ]
            address = base if (ordinal // 16) % 2 == 0 else base + max(0, size - 4)

        if mode in {11, 13}:
            shaped[0] = assign(shaped[0], "guarded_aw_start", 1)
            shaped[0] = assign(shaped[0], "guarded_w_start", 1)
            shaped[-1] = assign(shaped[-1], "guarded_bready", 1)
            if address is not None and "guarded_awaddr" in fields:
                shaped[0] = assign(shaped[0], "guarded_awaddr", address)
            if mode == 13 and "guarded_wstrb" in fields:
                strobe_width = fields["guarded_wstrb"].width
                shaped[0] = assign(
                    shaped[0], "guarded_wstrb", 1 << ((ordinal // 16) % strobe_width),
                )
        elif mode in {12, 14}:
            shaped[0] = assign(shaped[0], "guarded_ar_start", 1)
            shaped[-1] = assign(shaped[-1], "guarded_rready", 1)
            if address is not None and "guarded_araddr" in fields:
                shaped[0] = assign(shaped[0], "guarded_araddr", address)
        else:
            middle = len(shaped) // 2
            shaped[middle] = assign(shaped[middle], "guarded_dut_reset", 1)
            shaped[middle + 1] = assign(shaped[middle + 1], "guarded_ar_start", 1)
            shaped[-1] = assign(shaped[-1], "guarded_rready", 1)
            if address is not None and "guarded_araddr" in fields:
                shaped[middle + 1] = assign(
                    shaped[middle + 1], "guarded_araddr", address,
                )
        return tuple(shaped)
