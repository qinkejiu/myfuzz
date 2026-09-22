"""Replayable, byte-coherent instruction initialization for SoC harnesses.

This is a reference/configuration layer for generated RTL memory state.  It
does not execute instructions and deliberately has no interface for changing
CPU outputs or architectural registers.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from collections.abc import Mapping, Sequence

from myfuzz.isa.constraints import IsaContract
from myfuzz.isa.transducer import RiscvInstructionTransducer


class SocInstructionStimulusError(ValueError):
    """A stimulus or explicit CPU capability cannot be supported safely."""


@dataclass(frozen=True, slots=True)
class CpuInstructionCapabilities:
    xlen: int
    extensions: tuple[str, ...]
    instruction_alignment: int
    parameters: Mapping[str, object]
    provenance: str
    privilege_modes: tuple[str, ...] = ("M",)

    def __post_init__(self) -> None:
        if not isinstance(self.parameters, Mapping) or not self.provenance:
            raise SocInstructionStimulusError("invalid-cpu-capabilities")
        object.__setattr__(self, "extensions", tuple(self.extensions))
        object.__setattr__(self, "privilege_modes", tuple(self.privilege_modes))
        object.__setattr__(self, "parameters", MappingProxyType(dict(self.parameters)))
        try:
            IsaContract(self.xlen, self.extensions, self.privilege_modes,
                        self.instruction_alignment)
        except (TypeError, ValueError) as error:
            raise SocInstructionStimulusError(f"invalid-cpu-capabilities:{error}") from error


def _windows(value: Sequence[tuple[int, int]], label: str) -> tuple[tuple[int, int], ...]:
    try:
        result = tuple(sorted((int(base), int(size)) for base, size in value))
    except (TypeError, ValueError) as error:
        raise SocInstructionStimulusError(f"invalid-{label}-windows") from error
    if not result or any(base < 0 or size <= 0 for base, size in result):
        raise SocInstructionStimulusError(f"invalid-{label}-windows")
    if any(base + size > following for (base, size), (following, _) in zip(result, result[1:])):
        raise SocInstructionStimulusError(f"overlapping-{label}-windows")
    return result


class SocInstructionStimulus:
    """Consume P7 instruction corpus fields into a stable byte image."""

    RAW_FIELDS = ("init_offer", "init_address", "init_data", "init_be")

    def __init__(self, capabilities: CpuInstructionCapabilities, *,
                 instruction_windows: Sequence[tuple[int, int]],
                 isa_legal: bool = True, mmio_reachability_bias: bool = True):
        if not isinstance(capabilities, CpuInstructionCapabilities):
            raise SocInstructionStimulusError("invalid-cpu-capabilities")
        if type(isa_legal) is not bool or type(mmio_reachability_bias) is not bool:
            raise SocInstructionStimulusError("invalid-rule-toggle")
        unsupported = sorted(set(capabilities.extensions) - {"I", "M", "C"})
        if isa_legal and unsupported:
            raise SocInstructionStimulusError(f"unsupported-isa-extension:{unsupported[0]}")
        contract = IsaContract(capabilities.xlen, capabilities.extensions,
                               capabilities.privilege_modes,
                               capabilities.instruction_alignment)
        if isa_legal and not contract.supports_legal_instruction_validation:
            raise SocInstructionStimulusError("unsupported-isa-contract")
        self._validate_parameter_evidence(capabilities)
        self._capabilities = capabilities
        self._windows = _windows(instruction_windows, "instruction")
        self._transducer = RiscvInstructionTransducer(contract) if isa_legal else None
        self.isa_legal = isa_legal
        self.mmio_reachability_bias = mmio_reachability_bias
        self._pending: dict[int, dict[str, int]] = {}
        self._bytes: dict[int, int] = {}
        self.initialization_records: list[dict[str, object]] = []
        self.counters = {
            "instruction_initializations": 0,
            "isa_legal_corrections": 0,
            "instruction_candidate_drops": 0,
            "data_initializations": 0,
            "mmio_reachability_bias_corrections": 0,
        }

    @property
    def provenance(self) -> dict[str, object]:
        return {
            "schema_version": "soc_instruction_stimulus.v1",
            "isa": {"xlen": self._capabilities.xlen,
                    "extensions": list(self._capabilities.extensions),
                    "instruction_alignment": self._capabilities.instruction_alignment,
                    "parameters": dict(self._capabilities.parameters),
                    "source": self._capabilities.provenance},
            "rules": {"isa_legal": self.isa_legal,
                      "mmio_reachability_bias": self.mmio_reachability_bias},
            "effects": "memory_initialization_only",
            "counters": dict(self.counters),
        }

    def accept(self, candidate: Mapping[str, object]) -> dict[str, object]:
        if not isinstance(candidate, Mapping) or set(candidate) != set(self.RAW_FIELDS):
            raise SocInstructionStimulusError("invalid-raw-instruction-fields")
        if any(type(candidate[name]) is not int for name in self.RAW_FIELDS):
            raise SocInstructionStimulusError("invalid-raw-instruction-value")
        values = {name: int(candidate[name]) for name in self.RAW_FIELDS}
        if values["init_offer"] not in (0, 1) or not 0 <= values["init_data"] <= 0xFFFFFFFF \
                or not 0 <= values["init_be"] <= 0xF or values["init_address"] < 0:
            raise SocInstructionStimulusError("invalid-raw-instruction-value")
        if not values["init_offer"]:
            return {"accepted": False, "reason": "inactive"}
        address = values["init_address"]
        if address % self._capabilities.instruction_alignment:
            raise SocInstructionStimulusError("instruction-address-alignment")
        beat = address & ~0x3
        shifted_be = values["init_be"] << (address - beat)
        if shifted_be & ~0xF or any(
            shifted_be & (1 << lane) and not self._contains(beat + lane, 1)
            for lane in range(4)
        ):
            raise SocInstructionStimulusError("instruction-address-unmapped")
        if beat in self._pending or any(beat + lane in self._bytes for lane in range(4)):
            self.counters["instruction_candidate_drops"] += 1
            return {"accepted": False, "reason": "already-initialized-or-pending"}
        self._pending[beat] = values
        return {"accepted": True, "address": address, "raw_candidate": dict(values)}

    def flush(self) -> int:
        """Materialise every pending candidate; returns how many were applied.

        `accept` only records a candidate so that a later read sees a consistent
        image.  Building an image artifact needs the opposite direction: every
        accepted candidate must be committed before the image is written.
        """
        committed = 0
        for beat in sorted(list(self._pending)):
            self._materialize(beat)
            committed += 1
        return committed

    def image_base(self) -> int | None:
        """Lowest byte address this stimulus has initialized, or None."""
        return min(self._bytes) if self._bytes else None

    def byte_image(self) -> tuple[int, bytes]:
        """The initialized bytes as one contiguous (base_address, image) pair.

        The reference layer keeps a sparse byte map; a boot image has to be a
        contiguous file that `$readmemh` can load from a known base, so the gaps
        are materialised as zeroes and the base is returned with the bytes.
        """
        if not self._bytes:
            return (0, b"")
        base = min(self._bytes)
        last = max(self._bytes)
        return (base, bytes(self._bytes.get(address, 0)
                            for address in range(base, last + 1)))

    def read_instruction(self, address: int, size: int) -> int:
        allowed_sizes = (1, 2, 4, 8) if self._capabilities.xlen == 64 else (1, 2, 4)
        if type(address) is not int or size not in allowed_sizes or not self._contains(address, size):
            raise SocInstructionStimulusError("invalid-instruction-read")
        first_beat = address & ~0x3
        last_beat = (address + size - 1) & ~0x3
        for beat in range(first_beat, last_beat + 4, 4):
            if beat in self._pending:
                self._materialize(beat)
        return sum(self._bytes.get(address + lane, 0) << (8 * lane) for lane in range(size))

    def _materialize(self, beat: int) -> None:
        raw = self._pending.pop(beat)
        data = raw["init_data"]
        corrected = data
        offset = raw["init_address"] - beat
        mask = raw["init_be"] << offset
        width = (
            16
            if (
                "C" in self._capabilities.extensions
                and raw["init_be"] == 0x3
                and (data & 0x3) != 0x3
            )
            else 32
        )
        if self._transducer is not None:
            choice = self._transducer.repair_payload(data, width=width)
            corrected = choice.word
            if corrected != (data & ((1 << width) - 1)):
                self.counters["isa_legal_corrections"] += 1
        lane_base = offset
        for lane in range(4):
            if mask & (1 << lane):
                source_lane = lane - lane_base if width == 16 else lane
                self._bytes[beat + lane] = (corrected >> (8 * source_lane)) & 0xFF
        self.counters["instruction_initializations"] += 1
        self.initialization_records.append({
            "raw_candidate": dict(raw),
            "corrected_candidate": {"address": beat, "data": corrected, "be": mask,
                                    "width": width},
            "rules_applied": ["isa_legal"] if self._transducer is not None else [],
            "initialization_count": self.counters["instruction_initializations"],
        })

    def initialize_data(self, raw_address: int, value: int, *,
                        windows: Sequence[tuple[int, int]]) -> dict[str, int]:
        normalized = _windows(windows, "data")
        if type(raw_address) is not int or raw_address < 0 or type(value) is not int or value < 0:
            raise SocInstructionStimulusError("invalid-data-candidate")
        address = raw_address
        if self.mmio_reachability_bias:
            base, size = normalized[raw_address % len(normalized)]
            address = base + (raw_address % size)
            if address != raw_address:
                self.counters["mmio_reachability_bias_corrections"] += 1
        elif not any(base <= address < base + size for base, size in normalized):
            raise SocInstructionStimulusError("data-address-unmapped")
        self.counters["data_initializations"] += 1
        return {"address": address, "value": value}

    def preload_directed(self, images: Mapping[int, bytes], *, kind: str) -> dict[str, object]:
        if kind not in {"boot", "isr"}:
            raise SocInstructionStimulusError("invalid-directed-kind")
        for address, image in sorted(images.items()):
            if not isinstance(image, bytes) or not self._contains(address, len(image)):
                raise SocInstructionStimulusError("invalid-directed-image")
            for offset, byte in enumerate(image):
                self._bytes[address + offset] = byte
        return {"classification": "directed", "kind": kind,
                "fuzz_classification": False, "byte_count": sum(map(len, images.values()))}

    def _contains(self, address: int, size: int) -> bool:
        return any(base <= address and address + size <= base + length
                   for base, length in self._windows)

    @staticmethod
    def _validate_parameter_evidence(capabilities: CpuInstructionCapabilities) -> None:
        params = capabilities.parameters
        if "XLEN" in params and params["XLEN"] != capabilities.xlen:
            raise SocInstructionStimulusError("cpu-parameter-mismatch:XLEN")
        for extension in ("M", "C"):
            keys = (f"RV{capabilities.xlen}{extension}", f"ENABLE_{extension}")
            for key in keys:
                if key in params and bool(params[key]) != (extension in capabilities.extensions):
                    raise SocInstructionStimulusError(f"cpu-parameter-mismatch:{key}")


__all__ = ["CpuInstructionCapabilities", "SocInstructionStimulus",
           "SocInstructionStimulusError"]
