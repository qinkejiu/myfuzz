"""Compile declarative ISA/bus contracts into deterministic RFuzz execution."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, replace
from typing import TYPE_CHECKING
from types import MappingProxyType

from myfuzz.contracts import content_hash

from .coherent_memory import CoherentMemoryState
from .cycle_input import CycleField, CycleInputLayout, TestHeader, TEST_HEADER_SCHEMA_VERSION
from .protocol_transducer import (
    ProcessorBeatInputs, ProcessorBeatRequest, ProcessorBeatTransducer, _unsigned,
)

if TYPE_CHECKING:
    from myfuzz.isa.constraints import IsaContract


_FUNCTIONS = frozenset(("instruction_memory_master", "data_memory_master"))
MAX_MEMORY_CAPACITY_ENTRIES = 4096


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

    @property
    def contract_hash(self) -> str:
        return content_hash(self._document())

    def _document(self) -> dict[str, object]:
        return {
            "schema_version": "contract_transducer.v1",
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
    )


class ContractRuntime:
    """Reference execution of one arbitrated normalized memory beat port.

    ``dut_outputs`` is a request (valid asserted), None (valid deasserted),
    or a mapping with optional ``request`` and boolean active-high ``reset``.
    Test headers carry fixed controls; the caller schedules reset/execution
    cycles. ``reset_dut`` cancels protocol state but retains coherent bytes.
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

    @property
    def memory_provenance(self) -> Mapping[tuple[str, int], str]:
        """Read-only provenance of every allocated beat."""
        return MappingProxyType(self._memory_provenance)

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
        self.protocol.reset()

    def reset_dut(self) -> None:
        self.protocol.reset()

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
        result = self.protocol.step(fields["response_choice"], fields["response_data"], request)
        if not result.rsp_valid:
            return replace(result, external_inputs=external)
        if result.rsp_error:
            return replace(result, response_data_source="error", external_inputs=external)
        pending = result.response_request
        assert pending is not None
        width_bytes = self.plan.data_width // 8
        # The normalized port addresses beats; byte enables identify write
        # lanes. Low address bits never offset the returned beat or write.
        base = pending.address & ~(width_bytes - 1)
        key = (pending.domain, base)
        if pending.write and pending.byte_enable == 0:
            return replace(result, rsp_data=0, response_data_source="write", external_inputs=external)
        if key not in self._allocated_entries:
            if len(self._allocated_entries) >= self.plan.memory_capacity_entries:
                return replace(
                    result, rsp_data=0, rsp_error=True,
                    response_data_source="capacity_error", external_inputs=external,
                )
            self._allocated_entries.add(key)
        if pending.write:
            byte_enable = pending.byte_enable if pending.byte_enable is not None else (1 << width_bytes) - 1
            self.memory.write(
                pending.domain, base, pending.write_data,
                byte_enable,
                width_bytes,
            )
            if byte_enable:
                self._memory_provenance[key] = "cpu_written"
            return replace(result, rsp_data=0, response_data_source="write", external_inputs=external)

        provenance = self._memory_provenance.get(key)
        if pending.function == "instruction_memory_master" and provenance == "data_generated":
            return replace(result, rsp_data=0, rsp_error=True,
                           response_data_source="provenance_error", external_inputs=external)

        def initialize() -> int:
            if pending.function == "instruction_memory_master" and provenance != "cpu_written":
                # The DUT may align its request before exposing it on the bus.
                # The saved test header retains the architectural entry offset.
                boot_base = self.header.boot_address & ~(width_bytes - 1)
                halfword_boot = base == boot_base and self.header.boot_address % 4 == 2
                compressed = "instruction_compressed" in fields and (
                    fields["instruction_compressed"] or pending.address % 4 == 2 or halfword_boot
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
            return fields["response_data"]

        value = self.memory.read(pending.domain, base, width_bytes, initialize)
        if provenance is None:
            self._memory_provenance[key] = (
                "instruction_generated" if pending.function == "instruction_memory_master" else "data_generated"
            )
        return replace(result, rsp_data=value, response_data_source="stored", external_inputs=external)


__all__ = ["MAX_MEMORY_CAPACITY_ENTRIES", "ContractTransducerPlan", "compile_contract_transducer", "ContractRuntime"]
