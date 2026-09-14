"""Compile declarative ISA/bus contracts into deterministic RFuzz execution."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from typing import TYPE_CHECKING
from types import MappingProxyType

from myfuzz.contracts import content_hash

from .coherent_memory import CoherentMemoryState
from .cycle_input import CycleField, CycleInputLayout, TestHeader, TEST_HEADER_SCHEMA_VERSION
from .protocol_transducer import (
    ProcessorBeatInputs, ProcessorBeatRequest, ProcessorBeatTransducer, _unsigned,
)
from .soc_contracts import INITIALIZATION_POLICIES

if TYPE_CHECKING:
    from myfuzz.isa.constraints import IsaContract


_FUNCTIONS = frozenset(("instruction_memory_master", "data_memory_master"))
MAX_MEMORY_CAPACITY_ENTRIES = 4096

# "address_space" is the historical contract mode: the transducer is the only
# target and every address belongs to it.  "declared_windows" is the P4 mode:
# the transducer owns exactly the declared windows, refuses everything else,
# and coexists with real component instances in the generated top.
MEMORY_MODES = ("address_space", "declared_windows")
_PERMISSIONS = {"read_only": "read_only", "read_write": "read_write",
                "ro": "read_only", "rw": "read_write"}
_SUPPORTED_INITIALIZATION_POLICIES = frozenset(("on_demand", "preload", "rom"))


@dataclass(frozen=True, slots=True)
class MemoryWindow:
    base: int
    size: int
    permissions: str
    physical_memory_id: str
    initialization_policy: str

    def __iter__(self):
        """Keep geometry-only callers source compatible with old triples."""
        return iter((self.base, self.size, self.permissions))


def normalize_memory_windows(
    memory_windows: object, *, address_width: int, data_width: int, memory_mode: str,
) -> tuple[MemoryWindow, ...]:
    """Validate the regions a constrained memory target is allowed to own.

    Windows are beat-aligned so a whole normalized beat is always inside or
    outside one window, never straddling two targets.  They are returned in a
    canonical order so the plan hash does not depend on declaration order.
    """
    if memory_mode not in MEMORY_MODES:
        raise ValueError("memory_mode must be address_space or declared_windows")
    if memory_windows is None:
        memory_windows = ()
    if isinstance(memory_windows, (str, bytes)) or not isinstance(memory_windows, Sequence):
        raise ValueError("memory_windows must be a sequence of window records")
    byte_count = data_width // 8
    limit = 1 << address_width
    records: list[MemoryWindow] = []
    for raw in memory_windows:
        if isinstance(raw, MemoryWindow):
            base, size, permissions = raw.base, raw.size, raw.permissions
            physical_id = raw.physical_memory_id
            initialization_policy = raw.initialization_policy
        elif isinstance(raw, Mapping):
            base, size, permissions = raw.get("base"), raw.get("size"), raw.get("permissions")
            if "permissions" not in raw:
                raise ValueError("memory window must declare base, size, and permissions")
            physical_id = raw.get("physical_memory_id")
            initialization_policy = raw.get("initialization_policy")
            if ("physical_memory_id" in raw) != ("initialization_policy" in raw):
                raise ValueError("physical_memory_id and initialization_policy must be declared together")
        elif isinstance(raw, (tuple, list)) and len(raw) == 3:
            base, size, permissions = raw[0], raw[1], raw[2]
            physical_id, initialization_policy = None, None
        else:
            raise ValueError("memory window must declare base, size, and permissions")
        if (type(base) is not int or type(size) is not int or base < 0 or size <= 0
                or base + size > limit):
            raise ValueError("memory window base/size is not a valid address range")
        if base % byte_count or size % byte_count:
            raise ValueError("memory window must be beat-aligned")
        permission = _PERMISSIONS.get(permissions) if isinstance(permissions, str) else None
        if permission is None:
            raise ValueError("memory window permissions must be read_only or read_write")
        if physical_id is None:
            physical_id = f"virtual:{base:x}:{size:x}"
            initialization_policy = "on_demand"
        if not isinstance(physical_id, str) or not physical_id:
            raise ValueError("physical_memory_id must be a nonempty string")
        if initialization_policy not in INITIALIZATION_POLICIES:
            raise ValueError("initialization_policy is unsupported")
        if initialization_policy not in _SUPPORTED_INITIALIZATION_POLICIES:
            raise ValueError(
                f"initialization_policy {initialization_policy!r} is schema-valid but unsupported by the transducer"
            )
        if initialization_policy == "rom" and permission != "read_only":
            raise ValueError("ROM memory window must be read-only")
        records.append(MemoryWindow(base, size, permission, physical_id, initialization_policy))
    ordered = tuple(sorted(records, key=lambda item: (item.base, item.size, item.permissions,
                                                       item.physical_memory_id,
                                                       item.initialization_policy)))
    for previous, current in zip(ordered, ordered[1:]):
        if current.base < previous.base + previous.size:
            raise ValueError("memory windows must not overlap")
    physical: dict[str, tuple[int, str]] = {}
    for record in ordered:
        signature = (record.size, record.initialization_policy)
        previous = physical.get(record.physical_memory_id)
        if previous is not None and previous != signature:
            raise ValueError(f"conflicting physical memory {record.physical_memory_id}")
        physical[record.physical_memory_id] = signature
    if memory_mode == "declared_windows" and not ordered:
        raise ValueError("declared_windows memory mode requires memory windows")
    if memory_mode == "address_space" and ordered:
        raise ValueError("address_space memory mode does not accept memory_windows")
    return ordered


def plan_memory_windows(plan: ContractTransducerPlan) -> tuple[MemoryWindow, ...]:
    """Re-validate a plan's windows so hand-edited plans fail closed."""
    if not isinstance(plan, ContractTransducerPlan):
        raise ValueError("plan must be a ContractTransducerPlan")
    return normalize_memory_windows(
        plan.memory_windows, address_width=plan.address_width,
        data_width=plan.data_width, memory_mode=plan.memory_mode,
    )


def normalize_memory_images(
    memory_images: object, windows: tuple[MemoryWindow, ...], *,
    data_width: int, memory_capacity_entries: int,
) -> tuple[tuple[str, tuple[int, ...]], ...]:
    if memory_images is None:
        memory_images = {}
    if not isinstance(memory_images, Mapping):
        raise ValueError("memory_images must map physical_memory_id to byte sequences")
    physical = {window.physical_memory_id: window for window in windows}
    required = {identifier for identifier, window in physical.items()
                if window.initialization_policy in {"preload", "rom"}}
    missing = required - set(memory_images)
    if missing:
        raise ValueError("preload/rom physical memory requires an explicit image: " + sorted(missing)[0])
    byte_count = data_width // 8
    populated_beats = 0
    normalized: list[tuple[str, tuple[int, ...]]] = []
    for identifier, raw_bytes in memory_images.items():
        if not isinstance(identifier, str) or identifier not in physical:
            raise ValueError("memory image names an unknown physical memory")
        window = physical[identifier]
        if window.initialization_policy not in {"preload", "rom"}:
            raise ValueError(
                f"{window.initialization_policy} physical memory does not accept an image"
            )
        if isinstance(raw_bytes, (str, bytes, bytearray)) or not isinstance(raw_bytes, Sequence):
            raise ValueError("memory image must be a JSON-compatible byte sequence")
        image = tuple(raw_bytes)
        if any(type(value) is not int or not 0 <= value <= 0xFF for value in image):
            raise ValueError("memory image byte must be an integer from 0 through 255")
        if len(image) > window.size:
            raise ValueError("memory image exceeds physical memory size")
        populated_beats += (len(image) + byte_count - 1) // byte_count
        normalized.append((identifier, image))
    if populated_beats > memory_capacity_entries:
        raise ValueError("memory image populated beats exceed memory capacity")
    return tuple(sorted(normalized))


def plan_memory_image_beats(
    plan: ContractTransducerPlan,
) -> tuple[tuple[str, int, int, int], ...]:
    byte_count = plan.data_width // 8
    beats: list[tuple[str, int, int, int]] = []
    for identifier, image in plan.memory_images:
        for offset in range(0, len(image), byte_count):
            chunk = image[offset:offset + byte_count]
            value = sum(byte << (8 * lane) for lane, byte in enumerate(chunk))
            beats.append((identifier, offset, value, (1 << len(chunk)) - 1))
    return tuple(beats)


@dataclass(frozen=True, slots=True)
class ContractTransducerPlan:
    isa: IsaContract
    protocol: tuple[str, str]
    address_width: int
    data_width: int
    memory_domains: tuple[tuple[str, str], ...]
    external_inputs: tuple[tuple[str, int], ...]
    max_wait_cycles: int
    allow_error: bool
    memory_capacity_entries: int
    cycle_layout: CycleInputLayout
    memory_mode: str = "address_space"
    memory_windows: tuple[MemoryWindow, ...] = ()
    memory_images: tuple[tuple[str, tuple[int, ...]], ...] = ()

    @property
    def implementation_hash(self) -> str:
        from .transducer_rtl import transducer_implementation_hash

        return transducer_implementation_hash(self)

    @property
    def contract_hash(self) -> str:
        return content_hash(self._document())

    def _legacy_document(self) -> dict[str, object]:
        return {
            "schema_version": "contract_transducer.v1",
            "implementation_hash": self.implementation_hash,
            "implementation_identity_policy": "generated_rtl_tokens.v1",
            "isa": asdict(self.isa),
            "protocol": list(self.protocol),
            "address_width": self.address_width,
            "data_width": self.data_width,
            "memory_domains": dict(self.memory_domains),
            "external_inputs": dict(self.external_inputs),
            "max_wait_cycles": self.max_wait_cycles,
            "allow_error": self.allow_error,
            "memory_capacity_entries": self.memory_capacity_entries,
            "memory_addressing": "aligned_beat_base_byte_enable_lanes",
            "capacity_policy": "error_without_eviction",
            "allow_error_scope": "random_injection_only",
            "test_header_schema_version": TEST_HEADER_SCHEMA_VERSION,
            "instruction_addressing_policy": "aligned_beat_uniform_slots_force_compressed_at_halfword_request_or_boot_entry",
            "instruction_slot_policy": "independent_selector_and_payload_per_slot",
            "memory_provenance_policy": "data_generated_fetch_error_cpu_written_fetch_exact",
            "zero_byte_enable_policy": "no_write_no_allocation_no_provenance_change",
            "cycle_layout": self.cycle_layout.document(),
        }

    def _document(self) -> dict[str, object]:
        document = self._legacy_document()
        if self.memory_mode == "address_space":
            return document
        # The declared-window mode is a new schema version: a test header from
        # the old address-space contract can never be replayed into it.
        document["schema_version"] = "contract_transducer.v2"
        document["memory_mode"] = self.memory_mode
        document["memory_windows"] = [
            {"base": window.base, "size": window.size, "permissions": window.permissions,
             "physical_memory_id": window.physical_memory_id,
             "initialization_policy": window.initialization_policy}
            for window in plan_memory_windows(self)
        ]
        document["memory_images"] = {
            identifier: list(image) for identifier, image in self.memory_images
        }
        document["unspecified_image_bytes"] = "deterministic_zero"
        document["memory_ownership_policy"] = "declared_windows_only_unmapped_error"
        document["initialisation_entropy_policy"] = "latched_on_first_accepted_access"
        document["reset_policy"] = "dut_reset_preserves_memory_test_begin_clears_memory"
        return document

    def document(self) -> dict[str, object]:
        document = self._document()
        return {**document, "contract_hash": content_hash(document)}


def compile_contract_transducer(
    *,
    isa: IsaContract,
    protocol: tuple[str, str],
    address_width: int,
    data_width: int,
    memory_domains: Mapping[str, str],
    external_inputs: Mapping[str, int] | None = None,
    max_wait_cycles: int = 16,
    allow_error: bool = True,
    memory_capacity_entries: int = 256,
    memory_mode: str = "address_space",
    memory_windows: Sequence[object] | None = None,
    memory_images: Mapping[str, Sequence[int]] | None = None,
) -> ContractTransducerPlan:
    # Lazy imports also allow the public composition exports to be imported
    # while the ISA package initializes its constraint-IR dependency.
    from myfuzz.isa.constraints import IsaContract
    from myfuzz.isa.transducer import RiscvInstructionTransducer

    if not isinstance(isa, IsaContract):
        raise ValueError("isa must be an IsaContract")
    if protocol != ("processor-memory-beat", "1"):
        raise ValueError("unsupported protocol: expected processor-memory-beat@1")
    if type(address_width) is not int or not 1 <= address_width <= 64:
        raise ValueError("address_width must be between 1 and 64")
    if type(data_width) is not int or data_width not in (32, 64):
        raise ValueError("contract data_width must be 32 or 64")
    if (type(memory_capacity_entries) is not int
            or not 1 <= memory_capacity_entries <= MAX_MEMORY_CAPACITY_ENTRIES):
        raise ValueError(f"memory_capacity_entries must be between 1 and {MAX_MEMORY_CAPACITY_ENTRIES}")
    if not isinstance(memory_domains, Mapping) or not memory_domains:
        raise ValueError("memory_domains must explicitly bind memory functions")
    if any(function not in _FUNCTIONS for function in memory_domains):
        raise ValueError("unsupported memory function")
    if any(not isinstance(domain, str) or not domain for domain in memory_domains.values()):
        raise ValueError("memory domain must be a nonempty string")
    if external_inputs is None:
        external_inputs = {}
    if not isinstance(external_inputs, Mapping):
        raise ValueError("external_inputs must explicitly bind field widths")
    for name, width in external_inputs.items():
        if not isinstance(name, str) or not name or type(width) is not int or width <= 0:
            raise ValueError("external input requires a nonempty identifier and positive width")
    windows = normalize_memory_windows(
        memory_windows, address_width=address_width, data_width=data_width,
        memory_mode=memory_mode,
    )
    images = normalize_memory_images(
        memory_images, windows, data_width=data_width,
        memory_capacity_entries=memory_capacity_entries,
    )
    normalized_isa = replace(
        isa, extensions=tuple(sorted(isa.extensions)),
        privilege_modes=tuple(sorted(set(isa.privilege_modes))),
    )
    instruction = RiscvInstructionTransducer(normalized_isa)
    ProcessorBeatTransducer(data_width, max_wait_cycles, allow_error=allow_error)
    external_fields = tuple(sorted(external_inputs.items()))
    compressed = "C" in normalized_isa.extensions and normalized_isa.instruction_alignment == 2
    selector_count = data_width // (16 if compressed else 32)
    cycle_layout = CycleInputLayout.build([
        CycleField("instruction_selector", instruction.selector_width),
        *(CycleField(f"instruction_selector_{index}", instruction.selector_width)
          for index in range(1, selector_count)),
        CycleField("instruction_payload", data_width),
        *([CycleField("instruction_compressed", 1)] if compressed else []),
        CycleField("response_choice", 3),
        CycleField("response_data", data_width),
        *(CycleField(f"external.{name}", width) for name, width in external_fields),
    ])
    return ContractTransducerPlan(
        normalized_isa, protocol, address_width, data_width,
        tuple(sorted(memory_domains.items())), external_fields,
        max_wait_cycles, allow_error, memory_capacity_entries, cycle_layout,
        memory_mode, windows, images,
    )


class ContractRuntime:
    """Reference execution of one arbitrated normalized memory beat port.

    ``dut_outputs`` is a request (valid asserted), None (valid deasserted),
    or a mapping with optional ``request`` and boolean active-high ``reset``.
    Test headers carry fixed controls; the caller schedules reset/execution
    cycles. ``reset_dut`` cancels protocol state but retains coherent bytes.

    In ``declared_windows`` mode the target owns only its declared windows:
    requests outside them are refused exactly like the generated RTL, writes
    to a read-only window complete with an error and no side effect, the first
    accepted access latches the initialisation entropy, and ``reset_dut``
    abandons only protocol state. ``begin_test`` restores preload/ROM images
    and starts a new physical-memory lifetime.
    """

    def __init__(self, plan: ContractTransducerPlan) -> None:
        from myfuzz.isa.transducer import RiscvInstructionTransducer

        if not isinstance(plan, ContractTransducerPlan):
            raise ValueError("plan must be a ContractTransducerPlan")
        self.plan = plan
        self.protocol = ProcessorBeatTransducer(
            plan.data_width, plan.max_wait_cycles, allow_error=plan.allow_error
        )
        self.memory = CoherentMemoryState()
        self._allocated_entries: set[tuple[str, int]] = set()
        self._memory_provenance: dict[tuple[str, int], str] = {}
        self.instruction = RiscvInstructionTransducer(plan.isa)
        self.header: TestHeader | None = None
        self.windows = plan_memory_windows(plan)
        self._accepted_entropy: tuple[int, int] | None = None
        self._fault_counts: dict[str, int] = {}

    @property
    def memory_provenance(self) -> Mapping[tuple[str, int], str]:
        """Read-only provenance of every allocated beat."""
        return MappingProxyType(self._memory_provenance)

    @property
    def fault_counts(self) -> Mapping[str, int]:
        """Read-only count of explicit refusals, by response_data_source."""
        return MappingProxyType(self._fault_counts)

    def _record_fault(self, source: str) -> None:
        self._fault_counts[source] = self._fault_counts.get(source, 0) + 1

    def _beat_base(self, address: int) -> int:
        return address & ~(self.plan.data_width // 8 - 1)

    def _covers(self, base: int, *, writable: bool) -> bool:
        byte_count = self.plan.data_width // 8
        return any(
            window.base <= base <= window.base + window.size - byte_count
            and (not writable or window.permissions == "read_write")
            for window in self.windows
        )

    def _physical_key(self, base: int) -> tuple[str, int]:
        byte_count = self.plan.data_width // 8
        for window in self.windows:
            if window.base <= base <= window.base + window.size - byte_count:
                return window.physical_memory_id, base - window.base
        raise ValueError("address is outside declared memory windows")

    def _window_for(self, base: int) -> MemoryWindow:
        byte_count = self.plan.data_width // 8
        for window in self.windows:
            if window.base <= base <= window.base + window.size - byte_count:
                return window
        raise ValueError("address is outside declared memory windows")

    def _instruction_data(self, fields: Mapping[str, int], address: int) -> int:
        """Repair one instruction beat from the entropy of the addressed cycle.

        The DUT may align its request before exposing it on the bus; the saved
        test header retains the architectural entry offset.
        """
        assert self.header is not None
        width_bytes = self.plan.data_width // 8
        base = address & ~(width_bytes - 1)
        boot_base = self.header.boot_address & ~(width_bytes - 1)
        halfword_boot = base == boot_base and self.header.boot_address % 4 == 2
        compressed = "instruction_compressed" in fields and (
            fields["instruction_compressed"] or address % 4 == 2 or halfword_boot
        )
        slot_width = 16 if compressed else 32
        word = 0
        for index in range(self.plan.data_width // slot_width):
            selector = "instruction_selector" if index == 0 else f"instruction_selector_{index}"
            payload = (fields["instruction_payload"] >> (index * slot_width)) & ((1 << slot_width) - 1)
            choice = self.instruction.repair(
                fields[selector], payload, width=slot_width,
                illegal=self.header.illegal_instruction,
            )
            word |= choice.word << (index * slot_width)
        return word

    def begin_test(self, header: TestHeader) -> None:
        if not isinstance(header, TestHeader):
            raise ValueError("header must be a TestHeader")
        if header.schema_version != TEST_HEADER_SCHEMA_VERSION:
            raise ValueError("unsupported header schema version")
        if header.layout_hash != self.plan.cycle_layout.layout_hash:
            raise ValueError("header layout hash does not match contract")
        if header.contract_hash != self.plan.contract_hash:
            raise ValueError("header contract hash does not match contract")
        _unsigned(header.boot_address, self.plan.address_width, "boot address")
        if header.boot_address % self.plan.isa.instruction_alignment:
            raise ValueError("boot address violates instruction alignment")
        self.header = header
        self.memory.reset_test()
        self._allocated_entries.clear()
        self._memory_provenance.clear()
        self._accepted_entropy = None
        self._fault_counts.clear()
        self.protocol.reset()
        for physical_id, offset, value, byte_enable in plan_memory_image_beats(self.plan):
            self.memory.write(
                physical_id, offset, value, byte_enable, self.plan.data_width // 8,
            )
            key = (physical_id, offset)
            self._allocated_entries.add(key)
            self._memory_provenance[key] = "preloaded"

    def reset_dut(self) -> None:
        self.protocol.reset()
        # CPU/protocol reset abandons pending transport, not physical memory.
        # Only begin_test owns the lifetime of memory bytes and allocation.
        self._accepted_entropy = None

    def _validate_request(self, request: ProcessorBeatRequest | None) -> None:
        if request is None:
            return
        if not isinstance(request, ProcessorBeatRequest):
            raise ValueError("request must be a ProcessorBeatRequest or None")
        if dict(self.plan.memory_domains).get(request.function) != request.domain:
            raise ValueError("request function/domain is not bound by the contract")
        _unsigned(request.address, self.plan.address_width, "request address")
        width_bytes = self.plan.data_width // 8
        base = request.address & ~(width_bytes - 1)
        if base + width_bytes > 1 << self.plan.address_width:
            raise ValueError("request span exceeds address bounds")
        _unsigned(request.write_data, self.plan.data_width, "write data")
        if request.byte_enable is not None:
            _unsigned(request.byte_enable, width_bytes, "byte enable")
        if request.function == "instruction_memory_master" and request.write:
            raise ValueError("instruction memory function does not permit writes")

    def step(
        self, raw_cycle: int,
        dut_outputs: ProcessorBeatRequest | Mapping[str, object] | None,
    ) -> ProcessorBeatInputs:
        if self.header is None:
            raise ValueError("begin_test must be called before step")
        _unsigned(raw_cycle, self.plan.cycle_layout.raw_width, "raw cycle")
        fields = {
            item.name: (raw_cycle >> item.raw_lo) & ((1 << item.width) - 1)
            for item in self.plan.cycle_layout.fields
        }
        external = {name: fields[f"external.{name}"] for name, _ in self.plan.external_inputs}
        reset = False
        request = dut_outputs
        if isinstance(dut_outputs, Mapping):
            if set(dut_outputs) - {"request", "reset"}:
                raise ValueError("unknown normalized DUT output fields")
            reset = dut_outputs.get("reset", False)
            if type(reset) is not bool:
                raise ValueError("DUT reset must be boolean")
            request = dut_outputs.get("request")
        self._validate_request(request)
        if reset:
            self.reset_dut()
            return ProcessorBeatInputs(external_inputs=external)
        if (self.windows and request is not None and self.protocol.state.pending is None
                and not self._covers(self._beat_base(request.address), writable=False)):
            # Outside the declared windows this target is not addressed at all:
            # it neither accepts nor answers, exactly like the generated RTL.
            self._record_fault("out_of_window")
            return ProcessorBeatInputs(external_inputs=external)
        result = self.protocol.step(fields["response_choice"], fields["response_data"], request)
        if result.req_ready:
            # Initialisation entropy belongs to the accepted access; a stalled
            # transaction must not resample it from later cycles.
            self._accepted_entropy = (
                self._instruction_data(fields, request.address), fields["response_data"],
            )
        if not result.rsp_valid:
            return replace(result, external_inputs=external)
        if result.rsp_error:
            self._record_fault("error")
            return replace(result, response_data_source="error", external_inputs=external)
        pending = result.response_request
        assert pending is not None
        width_bytes = self.plan.data_width // 8
        # The normalized port addresses beats; byte enables identify write
        # lanes. Low address bits never offset the returned beat or write.
        base = pending.address & ~(width_bytes - 1)
        key = self._physical_key(base) if self.windows else (pending.domain, base)
        if pending.write and pending.byte_enable == 0:
            return replace(result, rsp_data=0, response_data_source="write", external_inputs=external)
        if self.windows and pending.write and not self._covers(base, writable=True):
            # A read-only window rejects the write and keeps its loaded bytes.
            self._record_fault("read_only_write_error")
            return replace(result, rsp_data=0, rsp_error=True,
                           response_data_source="read_only_write_error", external_inputs=external)
        if key not in self._allocated_entries:
            if len(self._allocated_entries) >= self.plan.memory_capacity_entries:
                self._record_fault("capacity_error")
                return replace(
                    result, rsp_data=0, rsp_error=True,
                    response_data_source="capacity_error", external_inputs=external,
                )
            self._allocated_entries.add(key)
        if pending.write:
            byte_enable = pending.byte_enable if pending.byte_enable is not None else (1 << width_bytes) - 1
            self.memory.write(
                key[0], key[1], pending.write_data,
                byte_enable,
                width_bytes,
            )
            if byte_enable:
                self._memory_provenance[key] = "cpu_written"
            return replace(result, rsp_data=0, response_data_source="write", external_inputs=external)

        provenance = self._memory_provenance.get(key)
        if pending.function == "instruction_memory_master" and provenance == "data_generated":
            self._record_fault("provenance_error")
            return replace(result, rsp_data=0, rsp_error=True,
                           response_data_source="provenance_error", external_inputs=external)

        def initialize() -> int:
            if (self.windows and
                    self._window_for(base).initialization_policy in {"preload", "rom"}):
                return 0
            if self.windows:
                assert self._accepted_entropy is not None
                instruction_data, response_data = self._accepted_entropy
            else:
                instruction_data = self._instruction_data(fields, pending.address)
                response_data = fields["response_data"]
            if pending.function == "instruction_memory_master" and provenance != "cpu_written":
                return instruction_data
            return response_data

        value = self.memory.read(key[0], key[1], width_bytes, initialize)
        if provenance is None:
            if (self.windows and
                    self._window_for(base).initialization_policy in {"preload", "rom"}):
                self._memory_provenance[key] = "preloaded"
            else:
                self._memory_provenance[key] = (
                    "instruction_generated"
                    if pending.function == "instruction_memory_master" else "data_generated"
                )
        return replace(result, rsp_data=value, response_data_source="stored", external_inputs=external)


__all__ = [
    "MAX_MEMORY_CAPACITY_ENTRIES",
    "MEMORY_MODES",
    "MemoryWindow",
    "ContractTransducerPlan",
    "compile_contract_transducer",
    "normalize_memory_windows",
    "normalize_memory_images",
    "plan_memory_windows",
    "plan_memory_image_beats",
    "ContractRuntime",
]
