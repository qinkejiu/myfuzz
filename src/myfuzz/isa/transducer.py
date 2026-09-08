"""Capability-derived RISC-V instruction selection and minimal repair."""

from __future__ import annotations

from dataclasses import dataclass

from myfuzz.composition.constraint_ir import select_balanced

from .constraints import IsaContract, RiscvInstructionProvider


_OPCODE_MASK = 0x7F
_FUNCT3_MASK = 0x7 << 12
_FUNCT7_MASK = 0x7F << 25
_RD_MASK = 0x1F << 7
_RS1_MASK = 0x1F << 15
_RS2_MASK = 0x1F << 20
_C_FORMAT_MASK = (0x7 << 13) | 0x3
_C_RD_MASK = 0x1F << 7
_C_RS2_MASK = 0x1F << 2
_C_IMMEDIATE_MASK = (1 << 12) | (0x1F << 2)
_C_ADDI4SPN_IMMEDIATE_MASK = (1 << 12) | (0x3 << 11) | (0xF << 7) | (0x3 << 5)


@dataclass(frozen=True, slots=True)
class InstructionTemplate:
    name: str
    width: int
    extension: str
    fixed_mask: int
    fixed_value: int

    def __post_init__(self) -> None:
        word_mask = (1 << self.width) - 1 if self.width in (16, 32) else 0
        if (
            not self.name
            or self.extension not in {"I", "M", "C"}
            or not word_mask
            or self.fixed_mask & ~word_mask
            or self.fixed_value & ~self.fixed_mask
        ):
            raise ValueError("invalid instruction template")

    def repair(self, raw: int) -> int:
        if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
            raise ValueError("raw instruction payload must be a nonnegative integer")
        word_mask = (1 << self.width) - 1
        return ((raw & ~self.fixed_mask) | self.fixed_value) & word_mask


@dataclass(frozen=True, slots=True)
class InstructionChoice:
    operation: str
    width: int
    word: int
    free_mask: int
    legal: bool


def _base_template(
    name: str,
    extension: str,
    opcode: int,
    funct3: int | None = None,
    funct7: int | None = None,
    *,
    extra_mask: int = 0,
    extra_value: int = 0,
) -> InstructionTemplate:
    fixed_mask = _OPCODE_MASK | extra_mask
    fixed_value = opcode | extra_value
    if funct3 is not None:
        fixed_mask |= _FUNCT3_MASK
        fixed_value |= funct3 << 12
    if funct7 is not None:
        fixed_mask |= _FUNCT7_MASK
        fixed_value |= funct7 << 25
    return InstructionTemplate(name, 32, extension, fixed_mask, fixed_value)


def _compressed_template(
    name: str,
    quadrant: int,
    funct3: int,
    *,
    extra_mask: int = 0,
    extra_value: int = 0,
) -> InstructionTemplate:
    return InstructionTemplate(
        name,
        16,
        "C",
        _C_FORMAT_MASK | extra_mask,
        (funct3 << 13) | quadrant | extra_value,
    )


def _i_templates(contract: IsaContract) -> tuple[InstructionTemplate, ...]:
    templates: list[InstructionTemplate] = []
    for name, funct3 in (
        ("ADDI", 0), ("SLTI", 2), ("SLTIU", 3), ("XORI", 4),
        ("ORI", 6), ("ANDI", 7),
    ):
        templates.append(_base_template(name, "I", 0x13, funct3))

    shift_mask = (_FUNCT7_MASK if contract.xlen == 32 else 0x3F << 26)
    templates.extend((
        _base_template("SLLI", "I", 0x13, 1, extra_mask=shift_mask),
        _base_template("SRLI", "I", 0x13, 5, extra_mask=shift_mask),
        _base_template(
            "SRAI", "I", 0x13, 5,
            extra_mask=shift_mask,
            extra_value=(0x20 << 25),
        ),
    ))

    for name, funct3, funct7 in (
        ("ADD", 0, 0), ("SLL", 1, 0), ("SLT", 2, 0),
        ("SLTU", 3, 0), ("XOR", 4, 0), ("SRL", 5, 0),
        ("OR", 6, 0), ("AND", 7, 0), ("SUB", 0, 0x20),
        ("SRA", 5, 0x20),
    ):
        templates.append(_base_template(name, "I", 0x33, funct3, funct7))

    load_forms = [("LB", 0), ("LH", 1), ("LW", 2), ("LBU", 4), ("LHU", 5)]
    store_forms = [("SB", 0), ("SH", 1), ("SW", 2)]
    if contract.xlen == 64:
        load_forms.extend((("LD", 3), ("LWU", 6)))
        store_forms.append(("SD", 3))
    templates.extend(_base_template(name, "I", 0x03, funct3) for name, funct3 in load_forms)
    templates.extend(_base_template(name, "I", 0x23, funct3) for name, funct3 in store_forms)

    templates.extend(
        _base_template(name, "I", 0x63, funct3)
        for name, funct3 in (
            ("BEQ", 0), ("BNE", 1), ("BLT", 4),
            ("BGE", 5), ("BLTU", 6), ("BGEU", 7),
        )
    )
    templates.extend((
        _base_template("AUIPC", "I", 0x17),
        _base_template("LUI", "I", 0x37),
        _base_template("JAL", "I", 0x6F),
        _base_template("JALR", "I", 0x67, 0),
        _base_template(
            "FENCE", "I", 0x0F, 0,
            extra_mask=(0xF << 28) | _RS1_MASK | _RD_MASK,
        ),
    ))
    templates.extend(
        _base_template(name, "I", 0x73, funct3)
        for name, funct3 in (
            ("CSRRW", 1), ("CSRRS", 2), ("CSRRC", 3),
            ("CSRRWI", 5), ("CSRRSI", 6), ("CSRRCI", 7),
        )
    )
    system_words = [("ECALL", 0x0000_0073), ("EBREAK", 0x0010_0073), ("WFI", 0x1050_0073)]
    if "M" in contract.privilege_modes:
        system_words.append(("MRET", 0x3020_0073))
    if "S" in contract.privilege_modes:
        system_words.append(("SRET", 0x1020_0073))
    templates.extend(
        InstructionTemplate(name, 32, "I", 0xFFFF_FFFF, word)
        for name, word in system_words
    )

    if contract.xlen == 64:
        templates.extend((
            _base_template("ADDIW", "I", 0x1B, 0),
            _base_template("SLLIW", "I", 0x1B, 1, 0),
            _base_template("SRLIW", "I", 0x1B, 5, 0),
            _base_template("SRAIW", "I", 0x1B, 5, 0x20),
        ))
        templates.extend(
            _base_template(name, "I", 0x3B, funct3, funct7)
            for name, funct3, funct7 in (
                ("ADDW", 0, 0), ("SLLW", 1, 0), ("SRLW", 5, 0),
                ("SUBW", 0, 0x20), ("SRAW", 5, 0x20),
            )
        )
    return tuple(templates)


def _m_templates(contract: IsaContract) -> tuple[InstructionTemplate, ...]:
    templates = tuple(
        _base_template(name, "M", 0x33, funct3, 1)
        for name, funct3 in (
            ("MUL", 0), ("MULH", 1), ("MULHSU", 2), ("MULHU", 3),
            ("DIV", 4), ("DIVU", 5), ("REM", 6), ("REMU", 7),
        )
    )
    if contract.xlen == 64:
        templates += tuple(
            _base_template(name, "M", 0x3B, funct3, 1)
            for name, funct3 in (
                ("MULW", 0), ("DIVW", 4), ("DIVUW", 5),
                ("REMW", 6), ("REMUW", 7),
            )
        )
    return templates


def _c_templates(contract: IsaContract) -> tuple[InstructionTemplate, ...]:
    templates = [
        _compressed_template("C.ADDI4SPN", 0, 0),
        _compressed_template("C.LW", 0, 2),
        _compressed_template("C.SW", 0, 6),
        _compressed_template("C.ADDI", 1, 0),
        _compressed_template("C.LI", 1, 2),
        _compressed_template("C.ADDI16SP", 1, 3, extra_mask=_C_RD_MASK,
                             extra_value=2 << 7),
        _compressed_template("C.LUI", 1, 3),
        _compressed_template("C.SRLI", 1, 4, extra_mask=0x3 << 10),
        _compressed_template("C.SRAI", 1, 4, extra_mask=0x3 << 10,
                             extra_value=1 << 10),
        _compressed_template("C.ANDI", 1, 4, extra_mask=0x3 << 10,
                             extra_value=2 << 10),
        _compressed_template("C.SUB", 1, 4, extra_mask=(1 << 12) | (0x3 << 10) | (0x3 << 5),
                             extra_value=3 << 10),
        _compressed_template("C.XOR", 1, 4, extra_mask=(1 << 12) | (0x3 << 10) | (0x3 << 5),
                             extra_value=(3 << 10) | (1 << 5)),
        _compressed_template("C.OR", 1, 4, extra_mask=(1 << 12) | (0x3 << 10) | (0x3 << 5),
                             extra_value=(3 << 10) | (2 << 5)),
        _compressed_template("C.AND", 1, 4, extra_mask=(1 << 12) | (0x3 << 10) | (0x3 << 5),
                             extra_value=(3 << 10) | (3 << 5)),
        _compressed_template("C.J", 1, 5),
        _compressed_template("C.BEQZ", 1, 6),
        _compressed_template("C.BNEZ", 1, 7),
        _compressed_template("C.SLLI", 2, 0),
        _compressed_template("C.LWSP", 2, 2),
        _compressed_template("C.JR", 2, 4, extra_mask=(1 << 12) | _C_RS2_MASK),
        _compressed_template("C.MV", 2, 4, extra_mask=1 << 12),
        InstructionTemplate("C.EBREAK", 16, "C", 0xFFFF, 0x9002),
        _compressed_template("C.JALR", 2, 4,
                             extra_mask=(1 << 12) | _C_RS2_MASK,
                             extra_value=1 << 12),
        _compressed_template("C.ADD", 2, 4, extra_mask=1 << 12,
                             extra_value=1 << 12),
        _compressed_template("C.SWSP", 2, 6),
    ]
    if contract.xlen == 32:
        templates.insert(4, _compressed_template("C.JAL", 1, 1))
        # RV32C shift amounts reserve shamt[5].
        for index, template in enumerate(templates):
            if template.name in {"C.SRLI", "C.SRAI", "C.ANDI", "C.SLLI"}:
                templates[index] = InstructionTemplate(
                    template.name, 16, "C",
                    template.fixed_mask | (1 << 12), template.fixed_value,
                )
    else:
        templates.extend((
            _compressed_template("C.LD", 0, 3),
            _compressed_template("C.SD", 0, 7),
            _compressed_template("C.ADDIW", 1, 1),
            _compressed_template("C.SUBW", 1, 4,
                                 extra_mask=(1 << 12) | (0x3 << 10) | (0x3 << 5),
                                 extra_value=(1 << 12) | (3 << 10)),
            _compressed_template("C.ADDW", 1, 4,
                                 extra_mask=(1 << 12) | (0x3 << 10) | (0x3 << 5),
                                 extra_value=(1 << 12) | (3 << 10) | (1 << 5)),
            _compressed_template("C.LDSP", 2, 3),
            _compressed_template("C.SDSP", 2, 7),
        ))
    return tuple(templates)


class RiscvInstructionTransducer:
    """Select an ISA-supported operation, then alter only its constrained bits."""

    selector_width = 8

    def __init__(self, contract: IsaContract):
        if not isinstance(contract, IsaContract):
            raise TypeError("contract must be an IsaContract")
        if not contract.supports_legal_instruction_validation:
            raise ValueError("instruction transducer requires an implemented ISA contract")
        self.provider = RiscvInstructionProvider(contract)
        templates = list(_i_templates(contract))
        if "M" in contract.extensions:
            templates.extend(_m_templates(contract))
        if "C" in contract.extensions and contract.instruction_alignment == 2:
            templates.extend(_c_templates(contract))
        self.templates = tuple(templates)
        self._by_name = {template.name: template for template in self.templates}

    def repair(
        self,
        raw_selector: int,
        raw_payload: int,
        *,
        illegal: bool = False,
        width: int = 32,
    ) -> InstructionChoice:
        if (
            isinstance(raw_selector, bool)
            or not isinstance(raw_selector, int)
            or not 0 <= raw_selector < 1 << self.selector_width
        ):
            raise ValueError("raw instruction selector must fit eight bits")
        if width not in (16, 32):
            raise ValueError("instruction width must be 16 or 32")
        choices: tuple[InstructionTemplate | None, ...] = tuple(
            template for template in self.templates if template.width == width
        )
        if not choices:
            raise ValueError("no operations available for instruction width")
        if illegal:
            choices += (None,)
        template = select_balanced(raw_selector, self.selector_width, choices)
        if template is None:
            return self._illegal_choice(raw_payload)
        return self._repair_template(template, raw_payload)

    def repair_for_operation(self, operation: str, raw_payload: int) -> InstructionChoice:
        template = self._by_name.get(operation)
        if template is None:
            raise ValueError(f"unavailable operation: {operation}")
        return self._repair_template(template, raw_payload)

    def _repair_template(
        self, template: InstructionTemplate, raw_payload: int
    ) -> InstructionChoice:
        word = template.repair(raw_payload)
        repaired_mask = 0

        def ensure_nonzero(mask: int) -> None:
            nonlocal word, repaired_mask
            if word & mask == 0:
                bit = mask & -mask
                word |= bit
                repaired_mask |= bit

        name = template.name
        if name == "C.ADDI4SPN":
            ensure_nonzero(_C_ADDI4SPN_IMMEDIATE_MASK)
        elif name == "C.ADDI":
            if word & _C_RD_MASK == 0 and word & _C_IMMEDIATE_MASK:
                word |= 1 << 7
                repaired_mask |= 1 << 7
        elif name in {"C.LI", "C.ADDIW", "C.LWSP", "C.LDSP", "C.JR", "C.JALR"}:
            ensure_nonzero(_C_RD_MASK)
        elif name == "C.ADDI16SP":
            ensure_nonzero(_C_IMMEDIATE_MASK)
        elif name == "C.LUI":
            rd = word & _C_RD_MASK
            if rd in (0, 2 << 7):
                word |= 1 << 7
                repaired_mask |= 1 << 7
            ensure_nonzero(_C_IMMEDIATE_MASK)
        elif name in {"C.SRLI", "C.SRAI", "C.SLLI"}:
            if name == "C.SLLI":
                ensure_nonzero(_C_RD_MASK)
            ensure_nonzero(_C_IMMEDIATE_MASK)
        elif name == "C.ANDI" and not self.provider.is_legal_word(
            word, compressed=True
        ):
            word &= ~(1 << 6)
            repaired_mask |= 1 << 6
        elif name in {"C.MV", "C.ADD"}:
            ensure_nonzero(_C_RD_MASK)
            ensure_nonzero(_C_RS2_MASK)

        word_mask = (1 << template.width) - 1
        free_mask = word_mask & ~(template.fixed_mask | repaired_mask)
        legal = self.provider.is_legal_word(word, compressed=template.width == 16)
        if not legal:
            raise AssertionError(f"instruction template produced an illegal word: {name}")
        return InstructionChoice(name, template.width, word, free_mask, True)

    def _illegal_choice(self, raw_payload: int) -> InstructionChoice:
        if isinstance(raw_payload, bool) or not isinstance(raw_payload, int) or raw_payload < 0:
            raise ValueError("raw instruction payload must be a nonnegative integer")
        word_mask = (1 << 32) - 1
        repaired_mask = _OPCODE_MASK
        word = ((raw_payload & word_mask) & ~repaired_mask) | 0x4B
        free_mask = word_mask & ~repaired_mask
        legal = self.provider.is_legal_word(word)
        return InstructionChoice("ILLEGAL", 32, word, free_mask, legal)


__all__ = [
    "InstructionChoice",
    "InstructionTemplate",
    "RiscvInstructionTransducer",
]
