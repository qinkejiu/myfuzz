"""Protocol-independent RISC-V instruction legality constraints."""

from __future__ import annotations

from dataclasses import dataclass


_IMPLEMENTED_EXTENSIONS = frozenset(("I", "M", "C"))


@dataclass(frozen=True, slots=True)
class IsaContract:
    """ISA facts; unknown extensions deliberately select raw-only operation."""

    xlen: int
    extensions: tuple[str, ...]
    privilege_modes: tuple[str, ...] = ("M",)
    instruction_alignment: int = 4

    def __post_init__(self) -> None:
        if self.xlen not in (32, 64):
            raise ValueError("xlen must be 32 or 64")
        if isinstance(self.extensions, str):
            raise ValueError("extensions must be a sequence")
        extensions = tuple(self.extensions)
        if not extensions or len(set(extensions)) != len(extensions):
            raise ValueError("extensions must be a nonempty unique set")
        if any(not isinstance(item, str) or not item for item in extensions):
            raise ValueError("extensions must be nonempty strings")
        if self.instruction_alignment not in (2, 4):
            raise ValueError("instruction_alignment must be 2 or 4")
        if not self.privilege_modes or any(not isinstance(item, str) or not item for item in self.privilege_modes):
            raise ValueError("privilege_modes must be nonempty strings")
        object.__setattr__(self, "extensions", extensions)
        object.__setattr__(self, "privilege_modes", tuple(self.privilege_modes))

    @property
    def supports_legal_instruction_validation(self) -> bool:
        return "I" in self.extensions and set(self.extensions) <= _IMPLEMENTED_EXTENSIONS


class RiscvInstructionProvider:
    """Validate the implemented I/M/C encodings without bus knowledge."""

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
        if not self.contract.supports_legal_instruction_validation:
            return False
        if compressed:
            return self._compressed_legal(value)
        if value > 0xFFFFFFFF or value & 0b11 != 0b11:
            return False
        return self._base_legal(value)

    def _compressed_legal(self, value: int) -> bool:
        if ("C" not in self.contract.extensions or self.contract.instruction_alignment != 2
                or value > 0xFFFF or value & 0b11 == 0b11):
            return False
        quadrant = value & 0b11
        funct3 = (value >> 13) & 7
        rd = (value >> 7) & 0x1F
        rs2 = (value >> 2) & 0x1F
        shift = ((value >> 2) & 0x1F) | ((value >> 12) & 1) << 5
        if quadrant == 0:
            if funct3 == 0:  # C.ADDI4SPN
                nzuimm = (value & (0xF << 7)) | (value & (0x3 << 11)) | (value & (1 << 5)) | (value & (1 << 6))
                return nzuimm != 0
            if funct3 in (2, 6):  # C.LW / C.SW
                return True
            return funct3 in (3, 7) and self.contract.xlen == 64  # C.LD / C.SD
        if quadrant == 1:
            immediate = ((value >> 2) & 0x1F) | ((value >> 12) & 1) << 5
            if funct3 == 0:  # C.ADDI / C.NOP
                return rd != 0 or immediate == 0
            if funct3 == 1:  # C.JAL (RV32) / C.ADDIW (RV64)
                return self.contract.xlen == 32 or rd != 0
            if funct3 == 2:  # C.LI
                return rd != 0
            if funct3 == 3:
                if rd == 2:  # C.ADDI16SP
                    return ((value & (1 << 12)) | (value & (1 << 6)) | (value & (1 << 5))
                            | (value & (0x3 << 3)) | (value & (1 << 2))) != 0
                return rd not in (0, 2) and immediate != 0  # C.LUI
            if funct3 in (5, 6, 7):  # C.J / C.BEQZ / C.BNEZ
                return True
            if funct3 != 4:
                return False
            operation = (value >> 10) & 3
            if operation != 3:
                if operation in (0, 1):  # C.SRLI / C.SRAI
                    return shift != 0 and (self.contract.xlen == 64 or (shift & 0x20) == 0)
                return True  # C.ANDI
            operation = (value >> 5) & 3
            if (value >> 12) & 1:
                return self.contract.xlen == 64 and operation in (0, 1)  # C.SUBW / C.ADDW
            return operation in (0, 1, 2, 3)  # C.SUB/XOR/OR/AND
        if quadrant == 2:
            if funct3 == 0:  # C.SLLI
                return rd != 0 and shift != 0 and (self.contract.xlen == 64 or (shift & 0x20) == 0)
            if funct3 == 2:  # C.LWSP
                return rd != 0
            if funct3 == 3:  # C.LDSP
                return self.contract.xlen == 64 and rd != 0
            if funct3 == 4:
                if not ((value >> 12) & 1):
                    return rd != 0  # C.JR or C.MV; rd=x0 is reserved.
                if rd == 0:
                    return rs2 == 0  # C.EBREAK only.
                return True  # C.JALR or C.ADD.
            if funct3 == 6:  # C.SWSP
                return True
            return funct3 == 7 and self.contract.xlen == 64  # C.SDSP
        return False

    def _base_legal(self, value: int) -> bool:
        opcode = value & 0x7F
        funct3 = (value >> 12) & 7
        funct7 = (value >> 25) & 0x7F
        rd = (value >> 7) & 0x1F
        rs1 = (value >> 15) & 0x1F
        if opcode == 0x13:  # OP-IMM
            if funct3 in (0, 2, 3, 4, 6, 7):
                return True
            if funct3 == 1:
                return (value >> 26) == 0 if self.contract.xlen == 64 else funct7 == 0
            if funct3 == 5:
                return (value >> 26) in (0, 0x10) if self.contract.xlen == 64 else funct7 in (0, 0x20)
            return False
        if opcode == 0x1B:  # OP-IMM-32
            if self.contract.xlen != 64:
                return False
            if funct3 == 0:
                return True
            if funct3 == 1:
                return funct7 == 0
            return funct3 == 5 and funct7 in (0, 0x20)
        if opcode == 0x3B:  # OP-32
            if self.contract.xlen != 64:
                return False
            if funct7 == 0:
                return funct3 in (0, 1, 5)  # ADDW / SLLW / SRLW
            if funct7 == 0x20:
                return funct3 in (0, 5)  # SUBW / SRAW
            return funct7 == 1 and funct3 in (0, 4, 5, 6, 7) and "M" in self.contract.extensions
        if opcode == 0x33:  # OP
            if funct7 == 1:
                return "M" in self.contract.extensions
            if funct7 == 0:
                return True
            return funct7 == 0x20 and funct3 in (0, 5)
        if opcode == 0x03:  # LOAD
            return funct3 in ((0, 1, 2, 4, 5) if self.contract.xlen == 32 else (0, 1, 2, 3, 4, 5, 6))
        if opcode == 0x23:  # STORE
            return funct3 in ((0, 1, 2) if self.contract.xlen == 32 else (0, 1, 2, 3))
        if opcode == 0x63:
            return funct3 in (0, 1, 4, 5, 6, 7)
        if opcode in (0x17, 0x37, 0x6F):
            return True
        if opcode == 0x67:
            return funct3 == 0
        if opcode == 0x0F:  # FENCE; Zifencei is not supplied by this provider.
            return funct3 == 0 and rd == 0 and rs1 == 0 and ((value >> 28) & 0xF) == 0
        if opcode == 0x73:  # SYSTEM; Zicsr is not supplied by this provider.
            if funct3 != 0 or rd != 0 or rs1 != 0:
                return False
            immediate = (value >> 20) & 0xFFF
            if immediate in (0, 1):  # ECALL / EBREAK
                return True
            if immediate == 0x302:  # MRET
                return "M" in self.contract.privilege_modes
            if immediate == 0x102:  # SRET
                return "S" in self.contract.privilege_modes
            return immediate == 0x105  # WFI
        return False
