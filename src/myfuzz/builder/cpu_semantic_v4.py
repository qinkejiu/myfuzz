"""Versioned, lossless CPU semantic input contracts.

This module describes the finite state/program domain consumed by a CPU
loader.  It intentionally does not execute instructions; execution adapters
must prove that their loader can establish the declared domain first.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Iterable, Mapping

from .input_model import InputValidationError
from .rawbits_v4 import (
    RawBitsV4Lane, RawBitsV4Layout, RawBitsV4Submode, build_rawbits_v4_layout,
)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True)
class CpuMemoryRegion:
    name: str
    base: int
    size: int
    permissions: str
    default_fill: int = 0

    def __post_init__(self) -> None:
        if not self.name or self.base < 0 or self.size <= 0 or self.base + self.size > 1 << 64:
            raise InputValidationError("CPU memory region bounds are invalid")
        if set(self.permissions) - set("rwx") or not self.permissions:
            raise InputValidationError("CPU memory region permissions must be a non-empty subset of rwx")
        if not 0 <= self.default_fill <= 0xFF:
            raise InputValidationError("CPU memory region default_fill must be a byte")

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "base": self.base, "size": self.size,
                "permissions": "".join(sorted(set(self.permissions))), "default_fill": self.default_fill}


@dataclass(frozen=True)
class CpuStateDomain:
    """Loader-realizable finite CPU initial-state domain."""

    xlen: int
    gpr_writable_mask: int
    csr_masks: Mapping[str, int]
    csr_addresses: Mapping[str, int]
    privilege_modes: tuple[str, ...]
    pc_base: int
    pc_size: int
    trap_vector_base: int
    trap_vector_size: int
    memory_regions: tuple[CpuMemoryRegion, ...]
    max_steps: int
    loader: str
    reset_values: Mapping[str, int]
    schema: str = "myfuzz.cpu-state-domain/v4"

    def __post_init__(self) -> None:
        if self.xlen not in (32, 64) or self.gpr_writable_mask < 0:
            raise InputValidationError("CPU state domain xlen or GPR mask is invalid")
        if self.gpr_writable_mask >> 32 or self.gpr_writable_mask & 1:
            raise InputValidationError("CPU GPR writable mask must cover x1..x31 only")
        if not self.privilege_modes or any(not mode for mode in self.privilege_modes):
            raise InputValidationError("CPU state domain must declare privilege modes")
        if self.pc_base < 0 or self.pc_size <= 0 or self.trap_vector_base < 0 or self.trap_vector_size <= 0:
            raise InputValidationError("CPU entry/trap vector bounds are invalid")
        if self.max_steps <= 0 or not self.loader:
            raise InputValidationError("CPU state domain loader and max_steps are required")
        names = [region.name for region in self.memory_regions]
        if len(names) != len(set(names)) or not self.memory_regions:
            raise InputValidationError("CPU state domain memory regions must be named and unique")
        ordered = sorted(self.memory_regions, key=lambda item: item.base)
        if any(left.base + left.size > right.base for left, right in zip(ordered, ordered[1:])):
            raise InputValidationError("CPU state domain memory regions overlap")
        for name, mask in self.csr_masks.items():
            if not name or isinstance(mask, bool) or mask < 0:
                raise InputValidationError("CPU CSR masks must be non-negative integers")
        if set(self.csr_addresses) != set(self.csr_masks):
            raise InputValidationError("CPU CSR masks and addresses must name the same CSRs")
        addresses = tuple(self.csr_addresses.values())
        if (
            any(isinstance(address, bool) or not isinstance(address, int)
                or not 0 <= address < 1 << 12 for address in addresses)
            or len(addresses) != len(set(addresses))
        ):
            raise InputValidationError("CPU CSR addresses must be unique 12-bit integers")
        for name, value in self.reset_values.items():
            if not name or isinstance(value, bool) or value < 0:
                raise InputValidationError("CPU reset values must be non-negative integers")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema, "xlen": self.xlen, "gpr_writable_mask": self.gpr_writable_mask,
            "csr_masks": dict(sorted(self.csr_masks.items())),
            "csr_addresses": dict(sorted(self.csr_addresses.items())),
            "privilege_modes": list(self.privilege_modes),
            "pc": {"base": self.pc_base, "size": self.pc_size},
            "trap_vector": {"base": self.trap_vector_base, "size": self.trap_vector_size},
            "memory_regions": [region.to_dict() for region in self.memory_regions],
            "max_steps": self.max_steps, "loader": self.loader, "reset_values": dict(sorted(self.reset_values.items())),
        }

    @property
    def digest(self) -> str:
        return _digest(self.to_dict())


@dataclass(frozen=True)
class CpuExecutionProfile:
    name: str
    isa: tuple[str, ...]
    extensions: tuple[str, ...]
    state_domain: CpuStateDomain
    load_method: str
    trap_abi: str
    reset_behavior: str
    schema: str = "myfuzz.cpu-execution-profile/v4"

    def __post_init__(self) -> None:
        if not self.name or not self.isa or not self.load_method or not self.trap_abi or not self.reset_behavior:
            raise InputValidationError("CPU execution profile is incomplete")

    def to_dict(self) -> dict[str, object]:
        return {"schema": self.schema, "name": self.name, "isa": list(self.isa),
                "extensions": list(self.extensions), "state_domain": self.state_domain.to_dict(),
                "state_domain_digest": self.state_domain.digest, "load_method": self.load_method,
                "trap_abi": self.trap_abi, "reset_behavior": self.reset_behavior}

    @property
    def digest(self) -> str:
        return _digest(self.to_dict())


@dataclass(frozen=True)
class ProgramFragmentIR:
    words: tuple[int, ...]
    entry_pc: int
    registers: Mapping[int, int]
    csrs: Mapping[str, int]
    memory: Mapping[str, tuple[tuple[int, int], ...]]
    privilege: str
    trap_vector: int
    max_steps: int
    profile_digest: str
    schema: str = "myfuzz.program-fragment/v4"

    def validate(self, profile: CpuExecutionProfile) -> None:
        domain = profile.state_domain
        if self.profile_digest != profile.digest and self.profile_digest != domain.digest:
            raise InputValidationError("program fragment profile/domain digest mismatch")
        if not self.words or len(self.words) > domain.max_steps or self.max_steps <= 0 or self.max_steps > domain.max_steps:
            raise InputValidationError("program fragment length or execution bound is invalid")
        limit = 1 << domain.xlen
        if any(isinstance(word, bool) or not 0 <= word < 1 << 32 for word in self.words):
            raise InputValidationError("program fragment words must be 32-bit values")
        if "RV32I" in profile.isa:
            legal_opcodes = {0x03, 0x0F, 0x13, 0x17, 0x23, 0x33, 0x37, 0x63, 0x67, 0x6F, 0x73}
            if any((word & 0x7F) not in legal_opcodes for word in self.words):
                raise InputValidationError("program fragment contains an opcode outside the declared RV32I subset")
        if self.entry_pc & 3 or self.trap_vector & 3:
            raise InputValidationError("program fragment entry and trap vector must be word aligned")
        if not domain.pc_base <= self.entry_pc < domain.pc_base + domain.pc_size:
            raise InputValidationError("program fragment entry_pc is outside the declared PC domain")
        if not domain.trap_vector_base <= self.trap_vector < domain.trap_vector_base + domain.trap_vector_size:
            raise InputValidationError("program fragment trap vector is outside the declared domain")
        if self.privilege not in domain.privilege_modes:
            raise InputValidationError("program fragment privilege is outside the state domain")
        if any(reg < 0 or reg > 31 or not (domain.gpr_writable_mask & (1 << reg))
               or value < 0 or value >= limit for reg, value in self.registers.items()):
            raise InputValidationError("program fragment register state is invalid")
        if self.entry_pc + len(self.words) * 4 > domain.pc_base + domain.pc_size:
            raise InputValidationError("program fragment instructions exceed the declared PC domain")
        for name, value in self.csrs.items():
            if name not in domain.csr_masks or value < 0 or value & ~int(domain.csr_masks[name]):
                raise InputValidationError(f"program fragment CSR state is not writable: {name}")
        regions = {region.name: region for region in domain.memory_regions}
        for name, overlay in self.memory.items():
            if name not in regions or any(offset < 0 or offset >= regions[name].size or not 0 <= byte <= 0xFF for offset, byte in overlay):
                raise InputValidationError(f"program fragment memory overlay is outside region: {name}")
            offsets = [offset for offset, _byte in overlay]
            if offsets != sorted(set(offsets)):
                raise InputValidationError(f"program fragment memory overlay must have unique ordered offsets: {name}")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema, "words": list(self.words), "entry_pc": self.entry_pc,
            "registers": {str(key): value for key, value in sorted(self.registers.items())},
            "csrs": dict(sorted(self.csrs.items())),
            "memory": {name: [[offset, byte] for offset, byte in overlay] for name, overlay in sorted(self.memory.items())},
            "privilege": self.privilege, "trap_vector": self.trap_vector, "max_steps": self.max_steps,
            "profile_digest": self.profile_digest,
        }

    def encode(self, profile: CpuExecutionProfile) -> bytes:
        self.validate(profile)
        return _canonical(self.to_dict())

    @classmethod
    def decode(cls, payload: bytes, profile: CpuExecutionProfile) -> "ProgramFragmentIR":
        if not isinstance(payload, bytes):
            raise InputValidationError("program fragment payload must be bytes")
        try:
            value = json.loads(payload.decode("ascii"))
            expected = {
                "schema", "words", "entry_pc", "registers", "csrs", "memory",
                "privilege", "trap_vector", "max_steps", "profile_digest",
            }
            if not isinstance(value, dict) or set(value) != expected:
                raise InputValidationError("program fragment fields mismatch")
            if value["schema"] != "myfuzz.program-fragment/v4":
                raise InputValidationError("program fragment schema mismatch")
            fragment = cls(
                tuple(int(word) for word in value["words"]), int(value["entry_pc"]),
                {int(key): int(item) for key, item in value["registers"].items()},
                {str(key): int(item) for key, item in value["csrs"].items()},
                {str(name): tuple((int(item[0]), int(item[1])) for item in overlay) for name, overlay in value["memory"].items()},
                str(value["privilege"]), int(value["trap_vector"]), int(value["max_steps"]), str(value["profile_digest"]),
            )
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InputValidationError("program fragment payload is malformed") from exc
        fragment.validate(profile)
        if fragment.encode(profile) != payload:
            raise InputValidationError("program fragment payload is not canonical")
        return fragment


def build_mmio_smoke_program_fragment_v4(
    profile: CpuExecutionProfile,
    address_windows: tuple[tuple[str, int, int], ...],
    *,
    store_value: int = 0x5A,
    max_steps: int = 1024,
) -> ProgramFragmentIR:
    """Build one portable RV32I fragment that writes and reads every window."""
    profile.__post_init__()
    if "RV32I" not in profile.isa:
        raise InputValidationError("MMIO smoke fragment requires a declared RV32I profile")
    if not address_windows:
        raise InputValidationError("MMIO smoke fragment requires at least one address window")
    if (
        isinstance(store_value, bool) or not isinstance(store_value, int)
        or not 0 <= store_value <= 0x7FF
    ):
        raise InputValidationError("MMIO smoke store value must fit a positive ADDI immediate")
    if (
        isinstance(max_steps, bool) or not isinstance(max_steps, int)
        or not 0 < max_steps <= profile.state_domain.max_steps
    ):
        raise InputValidationError("MMIO smoke execution bound is outside the CPU state domain")
    names: set[str] = set()
    words = [_encode_addi_v4(6, 0, store_value)]
    for item in address_windows:
        if not isinstance(item, tuple) or len(item) != 3:
            raise InputValidationError("MMIO smoke address window is malformed")
        name, base, size = item
        if not isinstance(name, str) or not name or name in names:
            raise InputValidationError("MMIO smoke address window names must be unique")
        names.add(name)
        if any(isinstance(value, bool) or not isinstance(value, int) for value in (base, size)):
            raise InputValidationError("MMIO smoke address window values must be integers")
        if base < 0 or size < 4 or base + size > 1 << 32 or base & 3:
            raise InputValidationError("MMIO smoke address window is outside aligned RV32 space")
        words.extend(_encode_load_address_v4(5, base))
        words.extend((_encode_sw_v4(6, 5, 0), _encode_lw_v4(7, 5, 0)))
    words.append(0x0000006F)  # jal x0, 0
    domain = profile.state_domain
    fragment = ProgramFragmentIR(
        words=tuple(words), entry_pc=domain.pc_base, registers={},
        csrs={name: 0 for name in domain.csr_masks}, memory={},
        privilege=domain.privilege_modes[0], trap_vector=domain.trap_vector_base,
        max_steps=max_steps, profile_digest=profile.digest,
    )
    fragment.validate(profile)
    return fragment


def _encode_load_address_v4(register: int, address: int) -> tuple[int, ...]:
    upper = (address + 0x800) >> 12
    lower = address - (upper << 12)
    lui = ((upper & 0xFFFFF) << 12) | (register << 7) | 0x37
    if lower == 0:
        return (lui,)
    return (lui, _encode_addi_v4(register, register, lower))


def _encode_addi_v4(destination: int, source: int, immediate: int) -> int:
    if not -2048 <= immediate <= 2047:
        raise InputValidationError("RV32I ADDI immediate is out of range")
    return ((immediate & 0xFFF) << 20) | (source << 15) | (destination << 7) | 0x13


def _encode_sw_v4(source: int, base: int, immediate: int) -> int:
    if not -2048 <= immediate <= 2047:
        raise InputValidationError("RV32I SW immediate is out of range")
    value = immediate & 0xFFF
    return (
        ((value >> 5) & 0x7F) << 25
        | source << 20 | base << 15 | 0x2 << 12
        | (value & 0x1F) << 7 | 0x23
    )


def _encode_lw_v4(destination: int, base: int, immediate: int) -> int:
    if not -2048 <= immediate <= 2047:
        raise InputValidationError("RV32I LW immediate is out of range")
    return ((immediate & 0xFFF) << 20) | base << 15 | 0x2 << 12 | destination << 7 | 0x03


@dataclass(frozen=True)
class ProgramLoaderImageV4:
    """A loader-neutral, fully resolved initial CPU image."""

    profile_digest: str
    state_domain_digest: str
    fragment_digest: str
    load_method: str
    entry_pc: int
    trap_vector: int
    privilege: str
    max_steps: int
    memory_bytes: tuple[tuple[int, int], ...]
    registers: tuple[tuple[int, int], ...]
    csrs: tuple[tuple[str, int], ...]
    digest: str = ""
    schema: str = "myfuzz.program-loader-image/v4"

    def __post_init__(self) -> None:
        if self.schema != "myfuzz.program-loader-image/v4":
            raise InputValidationError("program loader image schema mismatch")
        for value, label in (
            (self.profile_digest, "profile"), (self.state_domain_digest, "state domain"),
            (self.fragment_digest, "fragment"),
        ):
            if not isinstance(value, str) or len(value) != 64 or any(
                char not in "0123456789abcdef" for char in value
            ):
                raise InputValidationError(f"program loader image {label} digest is invalid")
        if not self.load_method or self.entry_pc < 0 or self.trap_vector < 0 or self.max_steps <= 0:
            raise InputValidationError("program loader image control fields are invalid")
        addresses = [address for address, _value in self.memory_bytes]
        if addresses != sorted(set(addresses)) or any(
            address < 0 or isinstance(value, bool) or not 0 <= value <= 0xFF
            for address, value in self.memory_bytes
        ):
            raise InputValidationError("program loader image memory bytes are invalid")
        register_ids = [register for register, _value in self.registers]
        if register_ids != sorted(set(register_ids)):
            raise InputValidationError("program loader image registers are invalid")
        csr_names = [name for name, _value in self.csrs]
        if csr_names != sorted(set(csr_names)):
            raise InputValidationError("program loader image CSRs are invalid")
        if self.digest and self.digest != _digest(self.payload_dict()):
            raise InputValidationError("program loader image digest mismatch")

    def payload_dict(self) -> dict[str, object]:
        value = asdict(self)
        value.pop("digest")
        return value

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class CpuBootImageV4:
    """A sparse word image containing a fixed RV32I state loader and fragment."""

    profile_digest: str
    state_domain_digest: str
    loader_image_digest: str
    reset_pc: int
    entry_pc: int
    words: tuple[tuple[int, int], ...]
    hex_text: str
    hex_sha256: str
    digest: str = ""
    schema: str = "myfuzz.cpu-boot-image/v4"

    def __post_init__(self) -> None:
        if self.schema != "myfuzz.cpu-boot-image/v4":
            raise InputValidationError("CPU boot image schema mismatch")
        for value in (
            self.profile_digest, self.state_domain_digest,
            self.loader_image_digest, self.hex_sha256,
        ):
            if not isinstance(value, str) or len(value) != 64 or any(
                char not in "0123456789abcdef" for char in value
            ):
                raise InputValidationError("CPU boot image digest is invalid")
        addresses = [address for address, _word in self.words]
        if (
            addresses != sorted(set(addresses))
            or any(address < 0 or address & 3 or isinstance(word, bool)
                   or not 0 <= word < 1 << 32 for address, word in self.words)
        ):
            raise InputValidationError("CPU boot image words are invalid")
        if not self.hex_text.endswith("\n") or hashlib.sha256(
            self.hex_text.encode("ascii")
        ).hexdigest() != self.hex_sha256:
            raise InputValidationError("CPU boot image hex digest mismatch")
        if self.digest and self.digest != _digest(self.payload_dict()):
            raise InputValidationError("CPU boot image content digest mismatch")

    def payload_dict(self) -> dict[str, object]:
        value = asdict(self)
        value.pop("digest")
        return value

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def materialize_program_fragment_v4(
    profile: CpuExecutionProfile, fragment: ProgramFragmentIR,
) -> ProgramLoaderImageV4:
    """Resolve a valid fragment without knowing the concrete CPU module name."""
    fragment.validate(profile)
    domain = profile.state_domain
    instruction_end = fragment.entry_pc + len(fragment.words) * 4
    executable = next((
        region for region in domain.memory_regions
        if "x" in region.permissions
        and region.base <= fragment.entry_pc
        and instruction_end <= region.base + region.size
    ), None)
    if executable is None:
        raise InputValidationError("program fragment is not contained in an executable loader region")
    if not any(
        "x" in region.permissions
        and region.base <= fragment.trap_vector < region.base + region.size
        for region in domain.memory_regions
    ):
        raise InputValidationError("program fragment trap vector is not executable")
    memory: dict[int, int] = {}
    for index, word in enumerate(fragment.words):
        address = fragment.entry_pc + index * 4
        for byte_index in range(4):
            memory[address + byte_index] = (word >> (byte_index * 8)) & 0xFF
    regions = {region.name: region for region in domain.memory_regions}
    for name, overlay in fragment.memory.items():
        region = regions[name]
        for offset, byte in overlay:
            address = region.base + offset
            previous = memory.get(address)
            if previous is not None and previous != byte:
                raise InputValidationError("program fragment memory overlay conflicts with instructions")
            memory[address] = byte
    fragment_digest = hashlib.sha256(fragment.encode(profile)).hexdigest()
    value = ProgramLoaderImageV4(
        profile.digest, domain.digest, fragment_digest, profile.load_method,
        fragment.entry_pc, fragment.trap_vector, fragment.privilege, fragment.max_steps,
        tuple(sorted(memory.items())), tuple(sorted(fragment.registers.items())),
        tuple(sorted(fragment.csrs.items())),
    )
    return ProgramLoaderImageV4(
        **{**value.payload_dict(), "digest": _digest(value.payload_dict())}
    )


def build_rv32i_boot_image_v4(
    profile: CpuExecutionProfile,
    fragment: ProgramFragmentIR,
) -> CpuBootImageV4:
    """Construct the loader image using only profile-declared state geometry."""
    if profile.state_domain.xlen != 32 or "RV32I" not in profile.isa:
        raise InputValidationError("RV32I boot image requires a declared 32-bit RV32I profile")
    image = materialize_program_fragment_v4(profile, fragment)
    domain = profile.state_domain
    reset_pc = domain.reset_values.get("pc")
    if isinstance(reset_pc, bool) or not isinstance(reset_pc, int) or reset_pc & 3:
        raise InputValidationError("RV32I loader requires an aligned reset_values.pc")
    executable_regions = tuple(
        region for region in domain.memory_regions if "x" in region.permissions
    )
    loader_region = next((
        region for region in executable_regions
        if region.base <= reset_pc < region.base + region.size
    ), None)
    if loader_region is None:
        raise InputValidationError("RV32I loader reset PC is outside executable memory")

    direct_bytes: dict[int, int] = {}
    runtime_bytes: list[tuple[int, int]] = []
    for address, byte in image.memory_bytes:
        if any(region.base <= address < region.base + region.size for region in executable_regions):
            direct_bytes[address] = byte
        else:
            runtime_bytes.append((address, byte))

    loader: list[int] = []
    for address, byte in runtime_bytes:
        loader.extend(_rv32_load_immediate(30, address))
        loader.extend(_rv32_load_immediate(31, byte))
        loader.append(_rv32_store_byte(30, 31, 0))
    for name, value in sorted(image.csrs):
        loader.extend(_rv32_load_immediate(31, value))
        loader.append(_rv32_csrrw(0, domain.csr_addresses[name], 31))
    mtvec_address = domain.csr_addresses.get("mtvec")
    if mtvec_address is not None:
        loader.extend(_rv32_load_immediate(31, image.trap_vector))
        loader.append(_rv32_csrrw(0, mtvec_address, 31))
    register_values = dict(image.registers)
    for register in tuple(sorted(reg for reg in register_values if reg not in {30, 31})) + (
        tuple(reg for reg in (30, 31) if reg in register_values)
    ):
        loader.extend(_rv32_load_immediate(register, register_values[register]))
    jump_pc = reset_pc + len(loader) * 4
    loader.append(_rv32_jump(image.entry_pc - jump_pc))
    loader_end = reset_pc + len(loader) * 4
    if loader_end > loader_region.base + loader_region.size:
        raise InputValidationError("RV32I bootstrap exceeds its executable loader region")
    if any(address in direct_bytes for address in range(reset_pc, loader_end)):
        raise InputValidationError("RV32I bootstrap overlaps program fragment bytes")
    for index, word in enumerate(loader):
        address = reset_pc + index * 4
        for byte_index in range(4):
            direct_bytes[address + byte_index] = (word >> (8 * byte_index)) & 0xFF

    word_values: dict[int, int] = {}
    for address, byte in direct_bytes.items():
        aligned = address & ~3
        word_values[aligned] = word_values.get(aligned, 0) | (byte << (8 * (address & 3)))
    words = tuple(sorted(word_values.items()))
    hex_text = _sparse_word_hex(words)
    unsigned = CpuBootImageV4(
        profile.digest, domain.digest, image.digest, reset_pc, image.entry_pc,
        words, hex_text, hashlib.sha256(hex_text.encode("ascii")).hexdigest(),
    )
    return CpuBootImageV4(
        **{**unsigned.payload_dict(), "digest": _digest(unsigned.payload_dict())}
    )


def _rv32_load_immediate(register: int, value: int) -> list[int]:
    if not 1 <= register <= 31 or isinstance(value, bool) or not 0 <= value < 1 << 32:
        raise InputValidationError("RV32I loader immediate is outside its realizable domain")
    upper = ((value + 0x800) >> 12) & 0xFFFFF
    lower = value & 0xFFF
    return [upper << 12 | register << 7 | 0x37,
            lower << 20 | register << 15 | register << 7 | 0x13]


def _rv32_store_byte(base: int, source: int, offset: int) -> int:
    immediate = offset & 0xFFF
    return ((immediate >> 5) << 25 | source << 20 | base << 15
            | (immediate & 0x1F) << 7 | 0x23)


def _rv32_csrrw(destination: int, csr: int, source: int) -> int:
    return csr << 20 | source << 15 | 1 << 12 | destination << 7 | 0x73


def _rv32_jump(offset: int) -> int:
    if offset & 1 or not -(1 << 20) <= offset < 1 << 20:
        raise InputValidationError("RV32I loader entry is outside PC-relative JAL reach")
    immediate = offset & ((1 << 21) - 1)
    return ((immediate >> 20) << 31 | ((immediate >> 1) & 0x3FF) << 21
            | ((immediate >> 11) & 1) << 20 | ((immediate >> 12) & 0xFF) << 12
            | 0x6F)


def _sparse_word_hex(words: tuple[tuple[int, int], ...]) -> str:
    lines: list[str] = []
    previous_index = None
    for address, word in words:
        index = address // 4
        if previous_index is None or index != previous_index + 1:
            lines.append(f"@{index:08x}")
        lines.append(f"{word:08x}")
        previous_index = index
    return "\n".join(lines) + "\n"


def build_cpu_semantic_v4_layout(base: RawBitsV4Layout) -> RawBitsV4Layout:
    """Extend a v4 layout with lossless byte streams for both CPU submodes."""
    if not isinstance(base, RawBitsV4Layout):
        raise InputValidationError("CPU semantic layout base must be a RawBits v4 layout")
    if any(lane.lane == RawBitsV4Lane.CPU_SEMANTIC.name for lane in base.lanes):
        raise InputValidationError("RawBits v4 layout already enables CPU_SEMANTIC")
    lanes: dict[str, list[dict[str, object]]] = {}
    for lane in base.lanes:
        lanes[lane.lane] = [
            {
                "name": field.name, "width": field.width, "source": field.source,
                "consumer": field.consumer, "used": field.used,
                "submodes": list(field.submodes),
                "default_interpretation": field.default_interpretation,
                "provenance": dict(field.provenance),
            }
            for field in lane.fields
        ]
    lanes[RawBitsV4Lane.CPU_SEMANTIC.name] = [
        {
            "name": "cpu_fragment_byte", "width": 8,
            "source": "program_fragment_canonical_json",
            "consumer": "cpu_program_loader", "used": True,
            "submodes": [RawBitsV4Submode.PROGRAM_FRAGMENT.name],
            "default_interpretation": "canonical-byte-stream",
            "provenance": {
                "schema": "myfuzz.program-fragment/v4",
                "encoding": "ascii-json-canonical",
            },
        },
        {
            "name": "cpu_semantic_byte", "width": 8,
            "source": "cpu_semantic_operation_stream",
            "consumer": "cpu_semantic_loader", "used": True,
            "submodes": [RawBitsV4Submode.SEMANTIC_OPS.name],
            "default_interpretation": "canonical-byte-stream",
            "provenance": {
                "schema": "myfuzz.cpu-semantic-ops/v4",
                "encoding": "opaque-canonical-bytes",
            },
        },
    ]
    return build_rawbits_v4_layout(lanes)


def encode_cpu_semantic_payload_v4(
    layout: RawBitsV4Layout,
    submode: RawBitsV4Submode | int,
    payload: bytes,
) -> tuple[int, ...]:
    """Map every payload byte to one bit-level RawBits record without loss."""
    try:
        mode = RawBitsV4Submode(int(submode))
    except (TypeError, ValueError) as exc:
        raise InputValidationError("CPU semantic RawBits submode is invalid") from exc
    names = {
        RawBitsV4Submode.SEMANTIC_OPS: "cpu_semantic_byte",
        RawBitsV4Submode.PROGRAM_FRAGMENT: "cpu_fragment_byte",
    }
    if mode not in names:
        raise InputValidationError("CPU semantic payload requires a CPU semantic submode")
    if not isinstance(payload, bytes) or not payload:
        raise InputValidationError("CPU semantic payload must be non-empty bytes")
    lane = layout.lane_layout(RawBitsV4Lane.CPU_SEMANTIC)
    field = next((item for item in lane.fields if item.name == names[mode]), None)
    if field is None or field.width != 8 or mode.name not in field.submodes:
        raise InputValidationError("CPU semantic byte field is absent or incompatible")
    return tuple(byte << field.offset for byte in payload)


def decode_cpu_semantic_payload_v4(
    layout: RawBitsV4Layout,
    submode: RawBitsV4Submode | int,
    records: Iterable[int],
) -> bytes:
    try:
        mode = RawBitsV4Submode(int(submode))
    except (TypeError, ValueError) as exc:
        raise InputValidationError("CPU semantic RawBits submode is invalid") from exc
    names = {
        RawBitsV4Submode.SEMANTIC_OPS: "cpu_semantic_byte",
        RawBitsV4Submode.PROGRAM_FRAGMENT: "cpu_fragment_byte",
    }
    if mode not in names:
        raise InputValidationError("CPU semantic payload requires a CPU semantic submode")
    lane = layout.lane_layout(RawBitsV4Lane.CPU_SEMANTIC)
    field = next((item for item in lane.fields if item.name == names[mode]), None)
    if field is None or field.width != 8 or mode.name not in field.submodes:
        raise InputValidationError("CPU semantic byte field is absent or incompatible")
    mask = lane.used_mask_for(mode)
    values = tuple(records)
    if not values:
        raise InputValidationError("CPU semantic record stream must not be empty")
    limit = 1 << layout.record_width_bits
    if any(
        isinstance(record, bool) or not isinstance(record, int)
        or record < 0 or record >= limit or record & ~mask
        for record in values
    ):
        raise InputValidationError("CPU semantic record contains bits outside its submode mask")
    return bytes((record >> field.offset) & 0xFF for record in values)


def encode_program_fragment_records_v4(
    layout: RawBitsV4Layout,
    fragment: ProgramFragmentIR,
    profile: CpuExecutionProfile,
) -> tuple[int, ...]:
    return encode_cpu_semantic_payload_v4(
        layout, RawBitsV4Submode.PROGRAM_FRAGMENT, fragment.encode(profile),
    )


def decode_program_fragment_records_v4(
    layout: RawBitsV4Layout,
    records: Iterable[int],
    profile: CpuExecutionProfile,
) -> ProgramFragmentIR:
    payload = decode_cpu_semantic_payload_v4(
        layout, RawBitsV4Submode.PROGRAM_FRAGMENT, records,
    )
    return ProgramFragmentIR.decode(payload, profile)


def cpu_execution_profile_v4_from_dict(value: Mapping[str, object]) -> CpuExecutionProfile:
    if not isinstance(value, Mapping):
        raise InputValidationError("CPU execution profile must be an object")
    expected = {
        "schema", "name", "isa", "extensions", "state_domain",
        "state_domain_digest", "load_method", "trap_abi", "reset_behavior",
    }
    if set(value) != expected or value.get("schema") != "myfuzz.cpu-execution-profile/v4":
        raise InputValidationError("CPU execution profile fields/schema mismatch")
    domain = cpu_state_domain_v4_from_dict(value.get("state_domain"))
    if value.get("state_domain_digest") != domain.digest:
        raise InputValidationError("CPU execution profile state domain digest mismatch")
    isa, extensions = value.get("isa"), value.get("extensions")
    if not isinstance(isa, (tuple, list)) or not isinstance(extensions, (tuple, list)):
        raise InputValidationError("CPU execution profile ISA fields must be arrays")
    try:
        return CpuExecutionProfile(
            str(value["name"]), tuple(str(item) for item in isa),
            tuple(str(item) for item in extensions), domain,
            str(value["load_method"]), str(value["trap_abi"]), str(value["reset_behavior"]),
            str(value["schema"]),
        )
    except (TypeError, ValueError) as exc:
        raise InputValidationError("CPU execution profile is malformed") from exc


def cpu_state_domain_v4_from_dict(value: object) -> CpuStateDomain:
    if not isinstance(value, Mapping):
        raise InputValidationError("CPU state domain must be an object")
    expected = {
        "schema", "xlen", "gpr_writable_mask", "csr_masks", "csr_addresses", "privilege_modes",
        "pc", "trap_vector", "memory_regions", "max_steps", "loader", "reset_values",
    }
    if set(value) != expected or value.get("schema") != "myfuzz.cpu-state-domain/v4":
        raise InputValidationError("CPU state domain fields/schema mismatch")
    pc, trap = value.get("pc"), value.get("trap_vector")
    regions = value.get("memory_regions")
    if (
        not isinstance(pc, Mapping) or set(pc) != {"base", "size"}
        or not isinstance(trap, Mapping) or set(trap) != {"base", "size"}
        or not isinstance(regions, (tuple, list))
        or any(not isinstance(item, Mapping) for item in regions)
    ):
        raise InputValidationError("CPU state domain geometry is malformed")
    region_fields = {"name", "base", "size", "permissions", "default_fill"}
    if any(set(item) != region_fields for item in regions):
        raise InputValidationError("CPU state domain memory region fields mismatch")
    try:
        return CpuStateDomain(
            int(value["xlen"]), int(value["gpr_writable_mask"]),
            {str(name): int(mask) for name, mask in value["csr_masks"].items()},
            {str(name): int(address) for name, address in value["csr_addresses"].items()},
            tuple(str(item) for item in value["privilege_modes"]),
            int(pc["base"]), int(pc["size"]), int(trap["base"]), int(trap["size"]),
            tuple(CpuMemoryRegion(**dict(item)) for item in regions),
            int(value["max_steps"]), str(value["loader"]),
            {str(name): int(item) for name, item in value["reset_values"].items()},
            str(value["schema"]),
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise InputValidationError("CPU state domain is malformed") from exc


def _builtin_semantic_profile(
    name: str,
    loader: str,
    reset_behavior: str,
    *,
    csr_masks: Mapping[str, int],
    csr_addresses: Mapping[str, int],
    trap_abi: str,
) -> CpuExecutionProfile:
    domain = CpuStateDomain(
        xlen=32, gpr_writable_mask=((1 << 32) - 2),
        csr_masks=csr_masks, csr_addresses=csr_addresses,
        privilege_modes=("M",), pc_base=0x00003000, pc_size=0x0000D000,
        trap_vector_base=0x00003000, trap_vector_size=0x0000D000,
        memory_regions=(
            CpuMemoryRegion("rom", 0x00000000, 0x00010000, "rx", 0),
            CpuMemoryRegion("mailbox", 0x10000000, 0x00001000, "rw", 0),
        ), max_steps=4096, loader=loader, reset_values={"x0": 0, "pc": 0x00002000},
    )
    return CpuExecutionProfile(name, ("RV32I",), (), domain, loader, trap_abi, reset_behavior)


def picorv32_semantic_profile() -> CpuExecutionProfile:
    return _builtin_semantic_profile(
        "picorv32", "external-rom-mailbox", "async-resetn-low",
        csr_masks={}, csr_addresses={}, trap_abi="picorv32-custom-irq",
    )


def ultra_riscv_semantic_profile() -> CpuExecutionProfile:
    return _builtin_semantic_profile(
        "ultra_riscv", "pre-reset-tcm-mailbox", "async-reset-high",
        csr_masks={"mstatus": 0xFFFFFFFF, "mtvec": 0xFFFFFFFF},
        csr_addresses={"mstatus": 0x300, "mtvec": 0x305},
        trap_abi="machine-direct",
    )
