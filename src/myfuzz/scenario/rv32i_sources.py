"""Small, constrained RV32I program sources for initial CPU memory images.

This module produces and validates instruction bytes for startup images or
declared online slots. PersistentMemory owns admission and prevents replacing
bytes already determined by a read, source admission, or real CPU Store.

Every refusal raises a ValueError that also carries a versioned rejection from
``rejection_codes``: the message stays human-readable, while the code and the
failing field pointer are the recomputable contract. Boolean and exception
behavior is unchanged for callers that only catch ValueError.
"""

from __future__ import annotations

from dataclasses import dataclass

from .genome import MemoryImage
from .rejection_codes import (
    Rejection, RejectionCode, RejectionError, reject,
)


_OPERATIONS = frozenset({"LUI", "ADDI", "XORI", "ORI", "ANDI", "SLLI", "SRLI",
                         "SRAI", "LW", "SW", "SB", "NOP"})
_SHIFT_OPERATIONS = frozenset({"SLLI", "SRLI", "SRAI"})
_MEMORY_OPERATIONS = frozenset({"LW", "SW", "SB"})


def _register(value: int, name: str, pointer: str) -> None:
    if type(value) is not int or not 0 <= value < 32:
        reject(RejectionCode.FIELD_BAD_REGISTER,
               f"{name} must be an RV32I register number 0..31", pointer,
               value=value)


def _signed_12(value: int, operation: str) -> None:
    if type(value) is not int or not -(1 << 11) <= value < 1 << 11:
        reject(RejectionCode.FIELD_BAD_IMMEDIATE,
               "immediate must fit signed 12 bits", "instruction.immediate",
               operation=operation, immediate=value)


@dataclass(frozen=True)
class Rv32iInstruction:
    """One supported 32-bit instruction with explicit operand ownership.

    ``immediate`` carries the RV32I shamt for ``SLLI``/``SRLI``/``SRAI``: a
    five-bit shift amount 0..31. SRAI's imm[10] and the zero imm[11:5] of
    SLLI/SRLI are encoding facts derived by :meth:`word`, never caller input.
    """

    operation: str
    rd: int = 0
    rs1: int = 0
    rs2: int = 0
    immediate: int = 0

    def __post_init__(self) -> None:
        if self.operation not in _OPERATIONS:
            reject(RejectionCode.ISA_DISALLOWED_OPERATION,
                   "unsupported first-stage RV32I operation",
                   "instruction.operation", operation=self.operation)
        for name in ("rd", "rs1", "rs2"):
            _register(getattr(self, name), name, f"instruction.{name}")
        if self.operation == "LUI":
            if (type(self.immediate) is not int
                    or not 0 <= self.immediate < 1 << 20):
                reject(RejectionCode.FIELD_BAD_IMMEDIATE,
                       "LUI immediate must fit unsigned 20 bits",
                       "instruction.immediate", operation="LUI",
                       immediate=self.immediate)
            if self.rs1 or self.rs2:
                name = "rs1" if self.rs1 else "rs2"
                reject(RejectionCode.ISA_UNEXPECTED_OPERAND,
                       "LUI has no source registers", f"instruction.{name}",
                       operation="LUI", value=getattr(self, name))
        elif self.operation == "NOP":
            if self.rd or self.rs1 or self.rs2 or self.immediate:
                name = next(name for name in ("rd", "rs1", "rs2", "immediate")
                            if getattr(self, name))
                reject(RejectionCode.ISA_UNEXPECTED_OPERAND,
                       "NOP has no operands", f"instruction.{name}",
                       operation="NOP", value=getattr(self, name))
        elif self.operation in _SHIFT_OPERATIONS:
            # RV32I shamt is five bits; SLLI/SRLI/SRAI have no rs2 field.
            if (type(self.immediate) is not int
                    or not 0 <= self.immediate < 32):
                reject(RejectionCode.FIELD_BAD_SHAMT,
                       "shift amount must be an RV32I shamt 0..31",
                       "instruction.shamt", operation=self.operation,
                       immediate=self.immediate)
            if self.rs2:
                reject(RejectionCode.ISA_UNEXPECTED_OPERAND,
                       f"{self.operation} has no rs2", "instruction.rs2",
                       operation=self.operation, value=self.rs2)
        else:
            _signed_12(self.immediate, self.operation)
            if self.operation in ("ADDI", "XORI", "ORI", "ANDI", "LW") and self.rs2:
                reject(RejectionCode.ISA_UNEXPECTED_OPERAND,
                       f"{self.operation} has no rs2", "instruction.rs2",
                       operation=self.operation, value=self.rs2)
            if self.operation in ("SW", "SB") and self.rd:
                reject(RejectionCode.ISA_UNEXPECTED_OPERAND,
                       f"{self.operation} has no rd", "instruction.rd",
                       operation=self.operation, value=self.rd)
            if self.operation in ("LW", "SW") and self.immediate % 4:
                reject(RejectionCode.FIELD_BAD_ALIGNMENT,
                       "LW/SW offset must be word aligned",
                       "instruction.immediate", operation=self.operation,
                       immediate=self.immediate)

    def word(self) -> int:
        op, imm = self.operation, self.immediate
        if op == "NOP":
            return 0x00000013
        if op == "LUI":
            return (imm << 12) | (self.rd << 7) | 0x37
        if op in _SHIFT_OPERATIONS:
            # OP-IMM shift: funct3 1 for SLLI, 5 for SRLI/SRAI; imm[11:5] is 0
            # except SRAI's imm[10] = 1, and shamt stays in imm[4:0].
            funct3 = 1 if op == "SLLI" else 5
            shift = (imm | 0x400) if op == "SRAI" else imm
            return (((shift & 0xfff) << 20) | (self.rs1 << 15)
                    | (funct3 << 12) | (self.rd << 7) | 0x13)
        if op in ("ADDI", "XORI", "ORI", "ANDI", "LW"):
            funct3, opcode = ((2, 0x03) if op == "LW" else
                              ({"ADDI": 0, "XORI": 4, "ORI": 6, "ANDI": 7}[op], 0x13))
            return (((imm & 0xfff) << 20) | (self.rs1 << 15)
                    | (funct3 << 12) | (self.rd << 7) | opcode)
        funct3 = 2 if op == "SW" else 0
        return (((imm >> 5 & 0x7f) << 25) | (self.rs2 << 20)
                | (self.rs1 << 15) | (funct3 << 12)
                | ((imm & 0x1f) << 7) | 0x23)


@dataclass(frozen=True)
class MmioWindow:
    """Allowed device range and CPU access widths for an MMIO fragment."""

    base: int
    size: int
    readable: bool = True
    writable: bool = True
    write_widths: tuple[int, ...] = (1, 4)

    def __post_init__(self) -> None:
        message = "MMIO window must fit a nonempty RV32 address range"
        if type(self.base) is not int or not 0 <= self.base < 1 << 32:
            reject(RejectionCode.MMIO_BAD_WINDOW, message, "window.base",
                   base=self.base)
        if type(self.size) is not int or self.size <= 0:
            reject(RejectionCode.MMIO_BAD_WINDOW, message, "window.size",
                   size=self.size)
        if self.base + self.size > 1 << 32:
            reject(RejectionCode.MMIO_BAD_WINDOW, message, "window.range",
                   base=self.base, size=self.size)
        if type(self.readable) is not bool:
            reject(RejectionCode.MMIO_BAD_PERMISSION,
                   "MMIO window permissions must be booleans", "window.readable",
                   readable=self.readable)
        if type(self.writable) is not bool:
            reject(RejectionCode.MMIO_BAD_PERMISSION,
                   "MMIO window permissions must be booleans", "window.writable",
                   writable=self.writable)
        if not (self.readable or self.writable):
            reject(RejectionCode.MMIO_BAD_PERMISSION,
                   "MMIO window must permit a read or write",
                   "window.permissions", readable=False, writable=False)
        if (not isinstance(self.write_widths, tuple) or not self.write_widths
                or any(type(width) is not int or width not in (1, 4)
                       for width in self.write_widths)
                or len(set(self.write_widths)) != len(self.write_widths)):
            reject(RejectionCode.MMIO_BAD_WIDTH,
                   "MMIO write widths must be a unique tuple of 1 and/or 4",
                   "window.write_widths", write_widths=self.write_widths)

    def contains(self, address: int, width: int) -> bool:
        return (type(address) is int and type(width) is int and width > 0
                and self.base <= address and address + width <= self.base + self.size)


def _split_address(address: int) -> tuple[int, int]:
    """Split a 32-bit address for LUI plus a signed ADDI/load/store offset."""
    low = ((address & 0xfff) + 0x800) % 0x1000 - 0x800
    high = ((address - low) >> 12) & 0xfffff
    return high, low


def _windows_argument(windows: object) -> None:
    if (not isinstance(windows, tuple) or not windows
            or any(not isinstance(window, MmioWindow) for window in windows)):
        reject(RejectionCode.MMIO_NO_WINDOW,
               "at least one MMIO window is required", "mmio.windows",
               windows=windows)


def mmio_access_fragment(operation: str, address: int, *,
                         windows: tuple[MmioWindow, ...], base_register: int,
                         data_register: int) -> tuple[Rv32iInstruction, ...]:
    """Make LUI + one real CPU MMIO access; the data register is caller owned.

    ``LW`` loads into data_register. ``SW``/``SB`` store its current value.
    No value or response is invented for an IP: the CPU and routed IP RTL own
    the subsequent transaction and result.
    """
    if operation not in _MEMORY_OPERATIONS:
        reject(RejectionCode.ISA_DISALLOWED_OPERATION,
               "MMIO access must be LW, SW, or SB", "mmio.operation",
               operation=operation)
    _windows_argument(windows)
    _register(base_register, "base_register", "mmio.base_register")
    _register(data_register, "data_register", "mmio.data_register")
    if base_register == 0:
        reject(RejectionCode.FIELD_REGISTER_CONFLICT,
               "MMIO base and data registers must be distinct nonzero registers",
               "mmio.base_register", base_register=base_register,
               data_register=data_register)
    if data_register == 0 or base_register == data_register:
        reject(RejectionCode.FIELD_REGISTER_CONFLICT,
               "MMIO base and data registers must be distinct nonzero registers",
               "mmio.data_register", base_register=base_register,
               data_register=data_register)
    width = 1 if operation == "SB" else 4
    if type(address) is not int or not 0 <= address < 1 << 32:
        reject(RejectionCode.FIELD_BAD_ADDRESS, "MMIO address must fit RV32",
               "mmio.address", address=address)
    if address % width:
        reject(RejectionCode.FIELD_BAD_ALIGNMENT,
               "MMIO access address is misaligned", "mmio.address",
               address=address, width=width)
    containing = tuple(window for window in windows
                       if window.contains(address, width))
    if not containing:
        reject(RejectionCode.MMIO_OUT_OF_WINDOW,
               "MMIO access is outside declared target windows", "mmio.address",
               address=address, width=width)
    if not any(window.readable if operation == "LW" else window.writable
               for window in containing):
        reject(RejectionCode.MMIO_WRITE_ONLY if operation == "LW"
               else RejectionCode.MMIO_READ_ONLY,
               "MMIO access is not permitted by declared target windows",
               "mmio.address", operation=operation, address=address)
    if operation != "LW" and not any(
            window.writable and width in window.write_widths
            for window in containing):
        reject(RejectionCode.MMIO_BAD_WIDTH,
               "MMIO access width is not supported by declared target windows",
               "mmio.width", operation=operation, width=width)
    high, low = _split_address(address)
    load_base = Rv32iInstruction("LUI", rd=base_register, immediate=high)
    if operation == "LW":
        access = Rv32iInstruction("LW", rd=data_register,
                                  rs1=base_register, immediate=low)
    else:
        access = Rv32iInstruction(operation, rs1=base_register,
                                  rs2=data_register, immediate=low)
    return load_base, access


def mmio_write_fragment(operation: str, address: int, value: int, *,
                        windows: tuple[MmioWindow, ...], base_register: int,
                        data_register: int) -> tuple[Rv32iInstruction, ...]:
    """Load a concrete RV32 value, then let CPU RTL issue a real MMIO store."""
    if operation not in ("SW", "SB"):
        reject(RejectionCode.ISA_DISALLOWED_OPERATION,
               "MMIO write must be SW or SB", "mmio.operation",
               operation=operation)
    if type(value) is not int or not 0 <= value < 1 << 32:
        reject(RejectionCode.FIELD_BAD_IMMEDIATE,
               "MMIO write value must fit RV32", "mmio.value", value=value)
    access = mmio_access_fragment(operation, address, windows=windows,
                                  base_register=base_register,
                                  data_register=data_register)
    high, low = _split_address(value)
    setup = (Rv32iInstruction("LUI", rd=data_register, immediate=high),
             Rv32iInstruction("ADDI", rd=data_register,
                              rs1=data_register, immediate=low))
    return (*setup, *access)


def mutate_mmio_access(operation: str, entropy: bytes, *,
                       windows: tuple[MmioWindow, ...], base_register: int,
                       data_register: int) -> tuple[Rv32iInstruction, ...]:
    """Select an aligned address inside a declared window from RFuzz bytes."""
    if not isinstance(entropy, bytes) or len(entropy) < 4:
        reject(RejectionCode.DECODE_MALFORMED_ENTROPY,
               "MMIO mutation requires at least four entropy bytes",
               "mutation.entropy", entropy=entropy)
    _windows_argument(windows)
    if operation not in _MEMORY_OPERATIONS:
        reject(RejectionCode.ISA_DISALLOWED_OPERATION,
               "MMIO access must be LW, SW, or SB", "mmio.operation",
               operation=operation)
    width = 1 if operation == "SB" else 4
    accessible = tuple(window for window in windows
                       if (window.readable if operation == "LW" else window.writable))
    if not accessible:
        reject(RejectionCode.MMIO_WINDOW_DENIED,
               "no MMIO window permits this operation", "mmio.operation",
               operation=operation)
    width_permitted = tuple(window for window in accessible
                            if operation == "LW" or width in window.write_widths)
    if not width_permitted:
        reject(RejectionCode.MMIO_BAD_WIDTH,
               f"no MMIO window supports {operation} access width", "mmio.width",
               operation=operation, width=width)
    permitted = tuple(window for window in width_permitted
                      if (window.base + width - 1) // width * width + width
                      <= window.base + window.size)
    if not permitted:
        reject(RejectionCode.MMIO_NO_ALIGNED_ADDRESS,
               f"no MMIO window has an aligned {operation} address",
               "mmio.windows", operation=operation, width=width)
    window = permitted[entropy[0] % len(permitted)]
    first = (window.base + width - 1) // width * width
    slots = (window.base + window.size - width - first) // width + 1
    address = first + (int.from_bytes(entropy[1:4], "little") % slots) * width
    return mmio_access_fragment(operation, address, windows=windows,
                                base_register=base_register,
                                data_register=data_register)


def mutate_instruction(seed: Rv32iInstruction, entropy: bytes) -> Rv32iInstruction:
    """Mutate legal operand fields while retaining the instruction class.

    MMIO programs should use ``mmio_access_fragment`` for address mutation,
    because changing a load/store base register alone loses the window proof.
    """
    message = "instruction seed and at least four entropy bytes are required"
    if not isinstance(seed, Rv32iInstruction):
        reject(RejectionCode.DECODE_MALFORMED_SEED, message, "mutation.seed",
               seed=seed)
    if not isinstance(entropy, bytes) or len(entropy) < 4:
        reject(RejectionCode.DECODE_MALFORMED_ENTROPY, message,
               "mutation.entropy", entropy=entropy)
    field = entropy[0] % 3
    raw_12 = int.from_bytes(entropy[1:3], "little") & 0xfff
    signed = raw_12 - 0x1000 if raw_12 & 0x800 else raw_12
    register = entropy[3] & 31
    op = seed.operation
    if op == "NOP":
        return seed
    if op == "LUI":
        immediate = int.from_bytes(entropy[:4], "little") & 0xfffff
        return Rv32iInstruction(op, rd=register if field == 0 else seed.rd,
                                immediate=immediate if field else seed.immediate)
    if op in _SHIFT_OPERATIONS:
        # The same 5-bit entropy slice names a register or a legal shamt, so a
        # mutated shift stays inside the RV32I shamt field by construction.
        return Rv32iInstruction(
            op, rd=register if field == 0 else seed.rd,
            rs1=register if field == 1 else seed.rs1,
            immediate=register if field == 2 else seed.immediate)
    if op in ("ADDI", "XORI", "ORI", "ANDI", "LW"):
        immediate = signed & ~3 if op == "LW" else signed
        return Rv32iInstruction(
            op, rd=register if field == 0 else seed.rd,
            rs1=register if field == 1 and op != "LW" else seed.rs1,
            immediate=immediate if field == 2 else seed.immediate)
    immediate = signed & ~3 if op == "SW" else signed
    return Rv32iInstruction(
        op, rs1=seed.rs1,
        rs2=register if field == 0 else seed.rs2,
        immediate=immediate if field else seed.immediate)


def fragment_bytes(instructions: tuple[Rv32iInstruction, ...]) -> bytes:
    """Encode a nonempty program fragment for initial memory installation."""
    if not isinstance(instructions, tuple) or not instructions or any(
            not isinstance(item, Rv32iInstruction) for item in instructions):
        reject(RejectionCode.FRAGMENT_INVALID_SEQUENCE,
               "a nonempty RV32I instruction tuple is required",
               "fragment.instructions", instructions=instructions)
    return b"".join(item.word().to_bytes(4, "little") for item in instructions)


def fragment_image(image_id: str, component: str, address: int,
                   instructions: tuple[Rv32iInstruction, ...]) -> MemoryImage:
    """Build a startup MemoryImage, never an online write to fetched bytes."""
    if type(address) is not int or not 0 <= address < 1 << 32:
        reject(RejectionCode.FIELD_BAD_ADDRESS,
               "program image address must be a 32-bit RV32 byte address",
               "image.address", address=address)
    if address % 4:
        reject(RejectionCode.FIELD_BAD_ALIGNMENT,
               "program image address must be word aligned", "image.address",
               address=address)
    data = fragment_bytes(instructions)
    if address + len(data) > 1 << 32:
        reject(RejectionCode.FRAGMENT_EXCEEDS_ADDRESS_SPACE,
               "program fragment exceeds RV32 address space", "image.address",
               address=address, length=len(data))
    return MemoryImage(image_id, component, address,
                       data.hex())


def _check_instruction_bytes(data: bytes) -> None:
    """Raise the versioned rejection for one unsupported instruction fragment."""
    if not isinstance(data, bytes) or not data or len(data) % 4:
        if isinstance(data, bytes):
            reject(RejectionCode.DECODE_MALFORMED_RECORD,
                   "instruction fragment requires complete 32-bit words",
                   "fragment.data", length=len(data))
        reject(RejectionCode.DECODE_MALFORMED_RECORD,
               "instruction fragment requires complete 32-bit words",
               "fragment.data", data=data)
    for offset in range(0, len(data), 4):
        word = int.from_bytes(data[offset:offset + 4], "little")
        opcode, funct3 = word & 0x7f, (word >> 12) & 7
        if opcode == 0x37 or (opcode == 0x13 and funct3 in (0, 4, 6, 7)):
            continue
        if opcode == 0x13 and funct3 in (1, 5):
            # RV32I OP-IMM shifts: imm[11:5] is reserved and must be 0 for
            # SLLI and SRLI, and exactly 0b0100000 for SRAI. Because those
            # high bits are pinned, shamt = imm[4:0] is always below 32 here;
            # a word that tries to encode a wider shamt fails on its reserved
            # bits, which are the bits that are actually wrong.
            immediate = (word >> 20) & 0xfff
            reserved = immediate >> 5
            if reserved == 0 or (funct3 == 5 and reserved == 0x20):
                continue
            reject(RejectionCode.ISA_RESERVED_IMM_BIT,
                   "unsupported RV32I shift immediate encoding",
                   f"fragment[{offset}].immediate", immediate=immediate,
                   shamt=immediate & 31, opcode=opcode, funct3=funct3)
        if opcode == 0x03 and funct3 == 2:
            immediate = (word >> 20) & 0xfff
            if immediate % 4 == 0:
                continue
            reject(RejectionCode.FIELD_BAD_ALIGNMENT,
                   "unsupported first-stage RV32I instruction encoding",
                   f"fragment[{offset}].immediate", immediate=immediate,
                   opcode=opcode, funct3=funct3)
        if opcode == 0x23 and funct3 in (0, 2):
            immediate = ((word >> 25) << 5) | ((word >> 7) & 31)
            if funct3 == 0 or immediate % 4 == 0:
                continue
            reject(RejectionCode.FIELD_BAD_ALIGNMENT,
                   "unsupported first-stage RV32I instruction encoding",
                   f"fragment[{offset}].immediate", immediate=immediate,
                   opcode=opcode, funct3=funct3)
        if opcode == 0x13:
            reject(RejectionCode.ISA_DISALLOWED_OPERATION,
                   f"unsupported RV32I OP-IMM funct3 {funct3} at byte offset {offset}",
                   f"fragment[{offset}].funct3", funct3=funct3, opcode=opcode)
        reject(RejectionCode.ISA_DISALLOWED_OPERATION,
               "unsupported first-stage RV32I instruction encoding",
               f"fragment[{offset}]", opcode=opcode, funct3=funct3)


def validate_instruction_bytes(data: bytes) -> None:
    """Validate the supported 32-bit instruction subset before online admission."""
    _check_instruction_bytes(data)


def validate_instruction_bytes_detailed(data: bytes) -> Rejection | None:
    """Return the versioned rejection of a fragment, or None when it is legal."""
    try:
        _check_instruction_bytes(data)
    except RejectionError as error:
        return error.rejection
    return None


def instruction_operator_id(data: bytes) -> str:
    """Name the exact supported operation sequence in an admitted fragment."""
    validate_instruction_bytes(data)
    operations = []
    for offset in range(0, len(data), 4):
        word = int.from_bytes(data[offset:offset + 4], 'little')
        opcode, funct3 = word & 0x7f, (word >> 12) & 7
        operation = ('NOP' if word == 0x00000013 else
                     'LUI' if opcode == 0x37 else
                     'ADDI' if opcode == 0x13 and funct3 == 0 else
                     'SLLI' if opcode == 0x13 and funct3 == 1 else
                     'XORI' if opcode == 0x13 and funct3 == 4 else
                     'SRLI' if (opcode == 0x13 and funct3 == 5
                                and ((word >> 30) & 1) == 0) else
                     'SRAI' if opcode == 0x13 and funct3 == 5 else
                     'ORI' if opcode == 0x13 and funct3 == 6 else
                     'ANDI' if opcode == 0x13 and funct3 == 7 else
                     'LW' if opcode == 0x03 else
                     'SW' if funct3 == 2 else 'SB')
        operations.append(operation)
    return 'rv32i:' + '+'.join(operations)


def decode_instruction_fragment(entropy: bytes, *, windows: tuple[MmioWindow, ...] = (),
                                allowed_mmio_operations: tuple[str, ...] = ("LW", "SW", "SB")) -> tuple[Rv32iInstruction, ...]:
    """Decode RFuzz bytes as legal instructions or bounded MMIO templates.

    Arithmetic choice 2 can edit a still-uncommitted two-word LUI/ADDI
    candidate: byte six selects the base, deletion of its optional ADDI, or
    insertion of XORI between those words. Without a byte-six edit, byte four's
    bit five selects the RV32I shift family instead of ADDI/ORI/XORI/ANDI: the
    immediate's low five bits become the shamt, byte four's low bits stay rs1,
    and byte six selects SLLI, SRLI or SRAI. The caller owns admission and
    reserves exactly the returned fragment length before any CPU fetch.
    """
    if not isinstance(entropy, bytes) or not entropy:
        reject(RejectionCode.DECODE_MALFORMED_ENTROPY,
               "instruction entropy must be nonempty bytes", "mutation.entropy",
               entropy=entropy)
    if (not isinstance(allowed_mmio_operations, tuple) or not allowed_mmio_operations
            or any(operation not in _MEMORY_OPERATIONS for operation in allowed_mmio_operations)
            or len(set(allowed_mmio_operations)) != len(allowed_mmio_operations)):
        reject(RejectionCode.ISA_DISALLOWED_OPERATION,
               "allowed MMIO operations must be a nonempty unique tuple of LW, SW, SB",
               "mmio.allowed_operations",
               allowed_mmio_operations=allowed_mmio_operations)
    raw = (entropy + bytes(12))[:12]
    choice = raw[0] % (3 + len(allowed_mmio_operations) if windows else 3)
    register = 1 + raw[1] % 31
    if choice == 0:
        return (Rv32iInstruction("NOP"),)
    if choice == 1:
        return (Rv32iInstruction("LUI", rd=register, immediate=int.from_bytes(raw[2:6], "little") & 0xfffff),)
    if choice == 2:
        immediate = int.from_bytes(raw[2:4], "little") & 0xfff
        immediate = immediate - 0x1000 if immediate & 0x800 else immediate
        edit = raw[6] & 0xc0
        if edit:
            base = (
                Rv32iInstruction("LUI", rd=register,
                                  immediate=int.from_bytes(raw[7:11], "little") & 0xfffff),
                Rv32iInstruction("ADDI", rd=register, rs1=register,
                                  immediate=immediate),
            )
            if edit == 0x80:
                return base[:1]
            if edit == 0xc0:
                xor_immediate = int.from_bytes(raw[4:6], "little") & 0xfff
                if xor_immediate & 0x800:
                    xor_immediate -= 0x1000
                return (base[0], Rv32iInstruction("XORI", rd=register,
                                                   rs1=register,
                                                   immediate=xor_immediate),
                        base[1])
            return base
        if raw[4] & 0x20:
            # The shift family is chosen without touching rs1 (raw[4] & 31),
            # and byte six's low bits pick the operation while its 0xc0 bits
            # above already selected the LUI edit.
            operation = ("SLLI", "SRLI", "SRAI")[raw[6] % 3]
            return (Rv32iInstruction(operation, rd=register, rs1=raw[4] & 31,
                                     immediate=immediate & 31),)
        operation = (("ADDI", "ORI"), ("XORI", "ANDI"))[bool(raw[4] & 0x80)][bool(raw[4] & 0x40)]
        return (Rv32iInstruction(operation, rd=register, rs1=raw[4] & 31,
                                 immediate=immediate),)
    operation = allowed_mmio_operations[choice - 3]
    # Byte 1 changes within RFuzz's current decision batch. Using the later
    # high decision byte pinned all observed stores to one device window.
    access = mutate_mmio_access(operation, raw[1:5], windows=windows, base_register=1, data_register=2)
    if operation == "LW":
        return access
    high, low = _split_address(int.from_bytes(raw[8:12], "little"))
    return (Rv32iInstruction("LUI", rd=2, immediate=high),
            Rv32iInstruction("ADDI", rd=2, rs1=2, immediate=low), *access)
