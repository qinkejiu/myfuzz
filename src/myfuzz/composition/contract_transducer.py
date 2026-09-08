"""Compile declarative ISA/bus contracts into deterministic RFuzz execution."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, replace
from typing import TYPE_CHECKING

from myfuzz.contracts import content_hash

from .coherent_memory import CoherentMemoryState
from .cycle_input import CycleField, CycleInputLayout, TestHeader
from .protocol_transducer import (
    ProcessorBeatInputs, ProcessorBeatRequest, ProcessorBeatTransducer, _unsigned,
)

if TYPE_CHECKING:
    from myfuzz.isa.constraints import IsaContract


_FUNCTIONS = frozenset(("instruction_memory_master", "data_memory_master"))


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
    if (type(memory_capacity_entries) is not int or memory_capacity_entries <= 0):
        raise ValueError("memory_capacity_entries must be positive")
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
    cycle_layout = CycleInputLayout.build([
        CycleField("instruction_selector", instruction.selector_width),
        CycleField("instruction_payload", 32),
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
        self.instruction = RiscvInstructionTransducer(plan.isa)
        self.header: TestHeader | None = None

    def begin_test(self, header: TestHeader) -> None:
        if not isinstance(header, TestHeader):
            raise ValueError("header must be a TestHeader")
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
        if key not in self._allocated_entries:
            if len(self._allocated_entries) >= self.plan.memory_capacity_entries:
                return replace(
                    result, rsp_data=0, rsp_error=True,
                    response_data_source="capacity_error", external_inputs=external,
                )
            self._allocated_entries.add(key)
        if pending.write:
            self.memory.write(
                pending.domain, base, pending.write_data,
                pending.byte_enable if pending.byte_enable is not None else (1 << width_bytes) - 1,
                width_bytes,
            )
            return replace(result, rsp_data=0, response_data_source="write", external_inputs=external)

        def initialize() -> int:
            if pending.function == "instruction_memory_master":
                # A beat carries a 32-bit instruction; wider beats retain raw
                # response data in their remaining bytes.
                word = self.instruction.repair(
                    fields["instruction_selector"], fields["instruction_payload"],
                    illegal=self.header.illegal_instruction,
                ).word
                return (fields["response_data"] & ~0xFFFFFFFF) | word
            return fields["response_data"]

        value = self.memory.read(pending.domain, base, width_bytes, initialize)
        return replace(result, rsp_data=value, response_data_source="stored", external_inputs=external)


__all__ = ["ContractTransducerPlan", "compile_contract_transducer", "ContractRuntime"]
