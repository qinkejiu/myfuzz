"""Protocol-independent RISC-V instruction legality constraints."""

from __future__ import annotations

from dataclasses import dataclass


_EXTENSIONS = frozenset(("I", "M", "A", "F", "D", "C"))


@dataclass(frozen=True, slots=True)
class IsaContract:
    """The ISA facts needed to constrain instruction bytes, not bus signals."""

    xlen: int
    extensions: tuple[str, ...]
    privilege_modes: tuple[str, ...] = ("M",)
    instruction_alignment: int = 4

    def __post_init__(self) -> None:
        if self.xlen not in (32, 64):
            raise ValueError("xlen must be 32 or 64")
        extensions = tuple(self.extensions)
        if not extensions or "I" not in extensions or len(set(extensions)) != len(extensions):
            raise ValueError("extensions must be a unique set containing I")
        if any(not isinstance(item, str) or item not in _EXTENSIONS for item in extensions):
            raise ValueError("extensions contain an unsupported extension")
        if self.instruction_alignment not in (2, 4):
            raise ValueError("instruction_alignment must be 2 or 4")
        if not self.privilege_modes or any(not isinstance(item, str) or not item for item in self.privilege_modes):
            raise ValueError("privilege_modes must be nonempty strings")
        object.__setattr__(self, "extensions", extensions)
        object.__setattr__(self, "privilege_modes", tuple(self.privilege_modes))


class RiscvInstructionProvider:
    """Validate a deliberately small I/M/C subset without bus knowledge."""

    def __init__(self, contract: IsaContract):
        if not isinstance(contract, IsaContract):
            raise TypeError("contract must be an IsaContract")
        self.contract = contract

    def constrain_word(self, value: int, *, compressed: bool = False) -> int:
        if not self.is_legal_word(value, compressed=compressed):
            raise ValueError("illegal RISC-V instruction word")
        return value & (0xFFFF if compressed else 0xFFFFFFFF)

    def is_legal_word(self, value: int, *, compressed: bool = False) -> bool:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return False
        if compressed:
            return self._compressed_legal(value)
        if value > 0xFFFFFFFF or value & 0b11 != 0b11:
            return False
        return self._base_legal(value)

    def _compressed_legal(self, value: int) -> bool:
        return "C" in self.contract.extensions and value <= 0xFFFF and value & 0b11 != 0b11

    def _base_legal(self, value: int) -> bool:
        opcode = value & 0x7F
        funct3 = (value >> 12) & 7
        funct7 = (value >> 25) & 0x7F
        if opcode == 0x13:  # OP-IMM
            if funct3 not in (0, 2, 3, 4, 6, 7, 1, 5):
                return False
            return funct3 not in (1, 5) or funct7 in (0, 0x20)
        if opcode == 0x33:  # OP / M extension
            if funct7 == 1:
                return "M" in self.contract.extensions and funct3 in range(8)
            if funct7 == 0:
                return True
            return funct7 == 0x20 and funct3 in (0, 5)
        if opcode in (0x03, 0x23):  # loads / stores
            return funct3 in (0, 1, 2, 3, 4, 5, 6) and not (self.contract.xlen == 32 and funct3 == 3)
        if opcode == 0x63:
            return funct3 in (0, 1, 4, 5, 6, 7)
        if opcode in (0x17, 0x37, 0x6F):
            return True
        if opcode == 0x67:
            return funct3 == 0
        if opcode in (0x0F, 0x73):
            return True
        if opcode in (0x1B, 0x3B):
            return self.contract.xlen == 64
        return False
