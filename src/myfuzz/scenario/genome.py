"""Canonical, continuous source-action genome for one persistent testcase."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json


DIRECTIONS = frozenset(("CPU_TO_IP", "IP_TO_CPU", "IP_TO_IP",
                        "CPU_TO_IP_TO_CPU", "IP_TO_CPU_TO_IP",
                        "MULTI_COMPONENT_CHAIN"))


def _natural(value: int, name: str, *, minimum: int = 0) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")


@dataclass(frozen=True)
class Trigger:
    kind: str
    source_component: str = ""
    source_port: str = ""
    mask: int = 0
    value: int = 0
    occurrence: int = 1

    def __post_init__(self) -> None:
        if self.kind not in ("START", "AFTER_OUTPUT"):
            raise ValueError("unknown trigger kind")
        if self.kind == "START":
            if (self.source_component or self.source_port or self.mask or self.value
                    or self.occurrence != 1):
                raise ValueError("START trigger cannot refer to an output")
        else:
            if not self.source_component or not self.source_port:
                raise ValueError("AFTER_OUTPUT requires a real output endpoint")
            _natural(self.mask, "trigger mask", minimum=1)
            _natural(self.value, "trigger value")
            _natural(self.occurrence, "trigger occurrence", minimum=1)
            if self.value & ~self.mask:
                raise ValueError("trigger value exceeds mask")


@dataclass(frozen=True)
class Action:
    action_id: str
    component: str
    port: str
    value: int
    direction: str
    trigger: Trigger
    delay_component: str = ""
    delay_ticks: int = 0
    bit_offset: int = 0
    width: int | None = None

    def __post_init__(self) -> None:
        if not self.action_id or not self.component or not self.port:
            raise ValueError("action identity and source endpoint are required")
        if self.direction not in DIRECTIONS:
            raise ValueError("unknown mutation direction")
        if not isinstance(self.trigger, Trigger):
            raise ValueError("action trigger is required")
        _natural(self.value, "action value")
        _natural(self.delay_ticks, "delay_ticks")
        _natural(self.bit_offset, "bit_offset")
        if self.width is not None:
            _natural(self.width, "width", minimum=1)


@dataclass(frozen=True)
class MemoryImage:
    """Fuzzer owned bytes installed before a testcase starts, never per step."""

    image_id: str
    component: str
    address: int
    data_hex: str

    def __post_init__(self) -> None:
        if not self.image_id or not self.component:
            raise ValueError("memory image identity and component are required")
        _natural(self.address, "image address")
        if (not isinstance(self.data_hex, str) or not self.data_hex
                or len(self.data_hex) % 2):
            raise ValueError("memory image must have whole bytes")
        try:
            data = bytes.fromhex(self.data_hex)
        except ValueError as exc:
            raise ValueError("memory image must be hex") from exc
        if data.hex() != self.data_hex:
            raise ValueError("memory image hex must be canonical lowercase")

    @property
    def data(self) -> bytes:
        return bytes.fromhex(self.data_hex)


@dataclass(frozen=True)
class ResetAction:
    """An explicit whole-scenario reset, ordered by a causal trigger."""

    action_id: str
    policy: str
    trigger: Trigger
    delay_component: str = ""
    delay_ticks: int = 0

    def __post_init__(self) -> None:
        if not self.action_id or self.policy not in ("warm_all", "cold_all"):
            raise ValueError("reset action needs an identity and whole-scene policy")
        if not isinstance(self.trigger, Trigger):
            raise ValueError("reset action trigger is required")
        _natural(self.delay_ticks, "reset delay_ticks")


@dataclass(frozen=True)
class ScenarioGenome:
    testcase_id: str
    direction: str
    path_id: str
    schedule_order: tuple[str, ...]
    max_steps: int
    actions: tuple[Action, ...]
    initial_images: tuple[MemoryImage, ...] = ()
    encoding_version: int = 2
    reset_actions: tuple[ResetAction, ...] = ()
    quiesce_steps: int = 0

    def __post_init__(self) -> None:
        if not self.testcase_id or not self.path_id:
            raise ValueError("testcase_id and path_id are required")
        if self.direction not in DIRECTIONS:
            raise ValueError("unknown mutation direction")
        if (not isinstance(self.schedule_order, tuple) or not self.schedule_order
                or any(not item for item in self.schedule_order)
                or len(set(self.schedule_order)) != len(self.schedule_order)):
            raise ValueError("schedule_order must list unique components")
        _natural(self.max_steps, "max_steps", minimum=1)
        if self.encoding_version not in (2, 3):
            raise ValueError("unknown genome encoding version")
        if self.reset_actions and self.encoding_version != 3:
            raise ValueError("reset actions require genome encoding version 3")
        _natural(self.quiesce_steps, "quiesce_steps")
        if self.quiesce_steps > 4096:
            raise ValueError("quiesce_steps exceeds first-stage budget")
        if self.quiesce_steps and self.encoding_version != 3:
            raise ValueError("quiesce steps require genome encoding version 3")
        if not isinstance(self.actions, tuple) or any(not isinstance(item, Action)
                                                      for item in self.actions):
            raise ValueError("actions must be a tuple of Action records")
        if len({item.action_id for item in self.actions}) != len(self.actions):
            raise ValueError("action_id must be unique")
        if (not isinstance(self.reset_actions, tuple)
                or any(not isinstance(item, ResetAction) for item in self.reset_actions)):
            raise ValueError("reset_actions must be a tuple of ResetAction records")
        if len({item.action_id for item in (*self.actions, *self.reset_actions)}) != (
                len(self.actions) + len(self.reset_actions)):
            raise ValueError("action_id must be unique across the testcase")
        if not isinstance(self.initial_images, tuple) or any(
                not isinstance(item, MemoryImage) for item in self.initial_images):
            raise ValueError("initial_images must be a tuple of MemoryImage records")
        if len({item.image_id for item in self.initial_images}) != len(self.initial_images):
            raise ValueError("image_id must be unique")
        for item in self.initial_images:
            if item.component not in self.schedule_order:
                raise ValueError("memory image component is absent from schedule_order")
        for action in self.actions:
            if action.component not in self.schedule_order:
                raise ValueError("action source is absent from schedule_order")
            if action.delay_component and action.delay_component not in self.schedule_order:
                raise ValueError("delay component is absent from schedule_order")
            if (action.trigger.kind == "AFTER_OUTPUT"
                    and action.trigger.source_component not in self.schedule_order):
                raise ValueError("trigger component is absent from schedule_order")
        for action in self.reset_actions:
            if action.delay_component and action.delay_component not in self.schedule_order:
                raise ValueError("reset delay component is absent from schedule_order")
            if (action.trigger.kind == "AFTER_OUTPUT"
                    and action.trigger.source_component not in self.schedule_order):
                raise ValueError("reset trigger component is absent from schedule_order")


class GenomeCodec:
    @staticmethod
    def encode(genome: ScenarioGenome) -> bytes:
        if not isinstance(genome, ScenarioGenome):
            raise ValueError("ScenarioGenome is required")
        document = asdict(genome)
        if genome.encoding_version == 2:
            del document["reset_actions"]
            del document["quiesce_steps"]
        return json.dumps(document, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")

    @staticmethod
    def decode(raw: bytes) -> ScenarioGenome:
        if not isinstance(raw, bytes):
            raise ValueError("genome must be bytes")
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid genome JSON") from exc
        if not isinstance(document, dict):
            raise ValueError("genome must be a JSON object")
        expected = {"testcase_id", "direction", "path_id", "schedule_order",
                    "max_steps", "actions", "initial_images", "encoding_version"}
        if document.get("encoding_version") == 3:
            expected.add("reset_actions")
            expected.add("quiesce_steps")
        if set(document) != expected:
            raise ValueError("unknown or missing genome fields")
        actions: list[Action] = []
        if not isinstance(document["actions"], list):
            raise ValueError("actions must be a list")
        action_fields = set(Action.__dataclass_fields__)
        trigger_fields = set(Trigger.__dataclass_fields__)
        for record in document["actions"]:
            if not isinstance(record, dict) or set(record) != action_fields:
                raise ValueError("unknown or missing action fields")
            trigger = record["trigger"]
            if not isinstance(trigger, dict) or set(trigger) != trigger_fields:
                raise ValueError("unknown or missing trigger fields")
            actions.append(Action(**{**record, "trigger": Trigger(**trigger)}))
        order = document["schedule_order"]
        if not isinstance(order, list):
            raise ValueError("schedule_order must be a list")
        images = document["initial_images"]
        if not isinstance(images, list):
            raise ValueError("initial_images must be a list")
        image_fields = set(MemoryImage.__dataclass_fields__)
        for item in images:
            if not isinstance(item, dict) or set(item) != image_fields:
                raise ValueError("unknown or missing memory image fields")
        reset_actions: list[ResetAction] = []
        reset_fields = set(ResetAction.__dataclass_fields__)
        if not isinstance(document.get("reset_actions", []), list):
            raise ValueError("reset_actions must be a list")
        for item in document.get("reset_actions", []):
            if not isinstance(item, dict) or set(item) != reset_fields:
                raise ValueError("unknown or missing reset action fields")
            trigger = item["trigger"]
            if not isinstance(trigger, dict) or set(trigger) != trigger_fields:
                raise ValueError("unknown or missing reset trigger fields")
            reset_actions.append(ResetAction(**{**item, "trigger": Trigger(**trigger)}))
        return ScenarioGenome(**{**document, "schedule_order": tuple(order),
                                 "actions": tuple(actions),
                                 "reset_actions": tuple(reset_actions),
                                 "initial_images": tuple(MemoryImage(**item)
                                                         for item in images)})


class ChunkAssembler:
    """Reassemble one immutable genome before creating or stepping any RTL."""

    def __init__(self, total_bytes: int, sha256_hex: str, *,
                 max_bytes: int = 1 << 20) -> None:
        _natural(total_bytes, "total_bytes", minimum=1)
        _natural(max_bytes, "max_bytes", minimum=1)
        if total_bytes > max_bytes:
            raise ValueError("genome byte budget exceeded")
        if (not isinstance(sha256_hex, str) or len(sha256_hex) != 64
                or any(char not in "0123456789abcdef" for char in sha256_hex)):
            raise ValueError("sha256 digest must be lowercase hexadecimal")
        self.total_bytes = total_bytes
        self.sha256_hex = sha256_hex
        self._chunks: dict[int, bytes] = {}
        self._received = 0
        self._finished = False

    def accept(self, offset: int, data: bytes) -> None:
        if self._finished:
            raise ValueError("genome is final; no further chunks are accepted")
        _natural(offset, "chunk offset")
        if not isinstance(data, bytes) or not data:
            raise ValueError("chunk must contain bytes")
        if offset in self._chunks:
            if self._chunks[offset] != data:
                raise ValueError("duplicate chunk has changed content")
            return
        if offset < self._received:
            raise ValueError("chunk overlap is forbidden")
        if offset != self._received:
            raise ValueError("chunk order is invalid")
        if offset + len(data) > self.total_bytes:
            raise ValueError("chunk exceeds declared genome size")
        self._chunks[offset] = data
        self._received += len(data)

    def finish(self) -> ScenarioGenome:
        if self._received != self.total_bytes:
            raise ValueError("genome is incomplete")
        raw = b"".join(self._chunks[offset] for offset in sorted(self._chunks))
        if hashlib.sha256(raw).hexdigest() != self.sha256_hex:
            raise ValueError("genome digest mismatch")
        genome = GenomeCodec.decode(raw)
        self._finished = True
        return genome
