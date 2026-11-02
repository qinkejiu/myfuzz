"""Seeded straight-line RISC-V program generation from a CPU profile.

The default pool is exactly the subset the existing F1 validator
(``myfuzz.scenario.rv32i_sources.validate_instruction_bytes``) accepts, so every
emitted four-byte record can be fed back as ``--record F1:<hex>``.  Encoding
coverage is wider than generation coverage: A and RV64 words are only generated
when ``include_non_f1`` is requested (RV64 also needs an xlen=64 profile),
because the legacy validator rejects them.  Zicsr/Zifencei are encodable and
tested, but CSR and SYSTEM words are never generated since they can trap.

Determinism: only ``random.Random(seed)`` drives choices; register sets are
sorted before selection, so the same seed yields byte-identical output.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from .catalog import CATALOG, InstructionSpec, shamt_limit
from .encoding import encode, format_assembly, pack_compressed_pair
from .profile import RiscvProfile

_MEMORY_KINDS = frozenset(("LOAD", "STORE", "LR", "AMO"))
_UNSUPPORTED_KINDS = frozenset(("SYSTEM", "CSR", "CSR_I"))
_MAX_UNSIGNED_32 = 1 << 32


class InstructionNotAvailable(ValueError):
    """The profile does not declare the extension (or xlen) an instruction needs."""


@dataclass(frozen=True, slots=True)
class ProgramInstruction:
    """One generated instruction and its placement in the program image."""

    pc: int
    assembly: str
    word: int
    width: int
    extension: str
    operands: dict[str, int]
    address: int | None = None


@dataclass(frozen=True, slots=True)
class Program:
    """A generated straight-line program plus its F1 records."""

    profile: RiscvProfile
    seed: int
    ram_base: int
    ram_size: int
    include_non_f1: bool
    compressed: bool | None
    records: tuple[str, ...]
    instructions: tuple[ProgramInstruction, ...]

    @property
    def f1_records(self) -> tuple[str, ...]:
        """The same records ready for ``--record F1:<hex>``."""
        return tuple("F1:" + record for record in self.records)

    def as_dict(self) -> dict[str, object]:
        """JSON-ready metadata; contains no timestamps or absolute paths."""
        return {
            "schema_version": "riscv_profile_program.v1",
            "profile": {
                "component_id": self.profile.component_id,
                "xlen": self.profile.xlen,
                "extensions": sorted(self.profile.extensions),
                "instruction_alignment": self.profile.instruction_alignment,
                "register_count": self.profile.register_count,
                "reset_vector": self.profile.reset_vector,
            },
            "seed": self.seed,
            "ram": {"base": self.ram_base, "size": self.ram_size},
            "options": {
                "include_non_f1": self.include_non_f1,
                "compressed": self.compressed,
            },
            "records": list(self.records),
            "f1_records": list(self.f1_records),
            "instructions": [
                {
                    "pc": item.pc,
                    "assembly": item.assembly,
                    "word": f"0x{item.word:0{item.width * 2}x}",
                    "width": item.width,
                    "extension": item.extension,
                    "operands": item.operands,
                    "address": item.address,
                }
                for item in self.instructions
            ],
        }


def extension_available(profile: RiscvProfile, spec: InstructionSpec) -> bool:
    """Whether the profile declares the extension and xlen ``spec`` requires."""
    if spec.min_xlen > profile.xlen:
        return False
    if spec.extension == "I":
        return "I" in profile.extensions or "E" in profile.extensions
    return spec.extension in profile.extensions


def make_instruction(profile: RiscvProfile, name: str,
                     **operands: object) -> tuple[InstructionSpec, int]:
    """Encode one explicitly requested instruction, gated by the profile.

    Raises :class:`InstructionNotAvailable` when the extension (or RV64 xlen)
    is not declared, and :class:`myfuzz.riscv.encoding.EncodingError` when the
    operands themselves are illegal.
    """
    spec = CATALOG.get(name)
    if spec is None:
        raise InstructionNotAvailable(f"unknown instruction {name!r}")
    if spec.min_xlen > profile.xlen:
        raise InstructionNotAvailable(
            f"{name} requires xlen {spec.min_xlen}, profile is xlen {profile.xlen}"
        )
    if not extension_available(profile, spec):
        raise InstructionNotAvailable(
            f"{name} requires extension {spec.extension}, "
            f"profile declares {sorted(profile.extensions)}"
        )
    return spec, encode(name, xlen=profile.xlen, **operands)


def _pool(profile: RiscvProfile, *, include_non_f1: bool, ram_size: int,
          compressed: bool) -> list[InstructionSpec]:
    pool = []
    for spec in CATALOG.values():
        if spec.compressed != compressed:
            continue
        if spec.control_flow or spec.kind in _UNSUPPORTED_KINDS:
            continue
        if spec.compressed and not spec.f1_safe:
            # Generation uses only F1-safe compressed words; C.LW/C.SW etc.
            # stay available through the encoder but need memory-state setup.
            continue
        if not extension_available(profile, spec):
            continue
        if not include_non_f1 and not spec.f1_safe:
            continue
        if spec.kind in _MEMORY_KINDS and (
                ram_size < 4 or _access_align(spec) > ram_size):
            continue
        pool.append(spec)
    return pool


def _pick_dest(rng: random.Random, profile: RiscvProfile,
               reserved: frozenset[int]) -> int:
    choices = [reg for reg in range(1, profile.register_count)
               if reg not in reserved]
    if not choices:
        raise ValueError("no allocatable destination register in this profile")
    return rng.choice(choices)


def _pick_source(rng: random.Random, profile: RiscvProfile,
                 written: set[int]) -> int:
    choices = sorted({0} | {reg for reg in written if reg < profile.register_count})
    return rng.choice(choices)


def _access_align(spec: InstructionSpec) -> int:
    """Generated memory accesses are at least 4-byte aligned, LD/SD 8-byte."""
    return max(4, spec.imm_align)


def _window_offset(rng: random.Random, align: int, ram_size: int) -> int:
    """A 12-bit-reachable, ``align``-aligned offset inside the RAM window."""
    limit = min(ram_size - align, 2044)
    limit -= limit % align
    return rng.randrange(0, limit // align + 1) * align


def _emit_32(spec: InstructionSpec, rng: random.Random, profile: RiscvProfile,
             written: set[int], reserved: frozenset[int], base_reg: int,
             ram_base: int, ram_size: int, include_non_f1: bool,
             pc: int) -> ProgramInstruction:
    operands: dict[str, int] = {}
    kind = spec.kind
    if "rd" in spec.operands:
        operands["rd"] = _pick_dest(rng, profile, reserved)
    if "rs1" in spec.operands:
        operands["rs1"] = (base_reg if kind in _MEMORY_KINDS
                           else _pick_source(rng, profile, written))
    if "rs2" in spec.operands:
        operands["rs2"] = _pick_source(rng, profile, written)
    address = None
    if kind in ("LR", "AMO"):
        # R-type atomics have no offset field: the effective address is rs1,
        # which the prologue set to exactly the declared window base.
        address = ram_base
    elif kind in _MEMORY_KINDS:
        operands["imm"] = _window_offset(rng, _access_align(spec), ram_size)
        address = ram_base + operands["imm"]
    elif kind == "I":
        operands["imm"] = rng.randrange(-2048, 2048)
    elif kind == "SHIFT":
        # The legacy F1 validator pins imm[11:5], i.e. shamt < 32, even on
        # RV64; keep that cap unless the caller asks for the wider pool.
        limit = shamt_limit(spec, profile.xlen)
        operands["shamt"] = rng.randint(
            0, limit if include_non_f1 else min(limit, 31))
    elif kind == "U":
        operands["imm"] = rng.randrange(0, 1 << 20)
    elif kind == "FENCE":
        operands["pred"] = operands["succ"] = 0xF
    word = encode(spec.name, xlen=profile.xlen, **operands)
    if spec.writes_rd:
        written.add(operands["rd"])
    return ProgramInstruction(pc, format_assembly(spec.name, operands), word, 4,
                              spec.extension, operands, address)


def _emit_compressed(spec: InstructionSpec, rng: random.Random,
                     profile: RiscvProfile, written: set[int],
                     reserved: frozenset[int], pc: int) -> ProgramInstruction:
    prime = [reg for reg in (12, 13, 14, 15)
             if reg < profile.register_count and reg not in reserved]
    if not prime:
        raise ValueError("no F1-safe compressed destination register available")
    operands: dict[str, int] = {"rd": rng.choice(prime)}
    if "rs2" in spec.operands:
        operands["rs2"] = rng.choice(prime)
    if spec.kind == "CI":
        if spec.name == "C.LUI":
            operands["imm"] = rng.choice([*range(-32, 0), *range(1, 32)])
        else:
            operands["imm"] = rng.randint(-32, 31)
    elif spec.kind == "CANDI":
        operands["imm"] = rng.randint(-32, 31)
    elif spec.kind == "CSHIFT":
        operands["shamt"] = rng.randint(1, shamt_limit(spec, profile.xlen))
    word = encode(spec.name, xlen=profile.xlen, **operands)
    written.add(operands["rd"])
    return ProgramInstruction(pc, format_assembly(spec.name, operands), word, 2,
                              spec.extension, operands)


def generate_program(profile: RiscvProfile, *, seed: int, count: int,
                     ram_base: int = 0, ram_size: int = 0,
                     include_non_f1: bool = False,
                     compressed: bool | None = None) -> Program:
    """Generate ``count`` four-byte records of legal straight-line instructions.

    ``count`` counts four-byte slots.  A declared RAM window enables memory
    instructions; every access is at least 4-byte aligned (8 for LD/SD) and
    inside ``[ram_base, ram_base + ram_size)``.  A nonzero window base is
    materialised with ``lui`` (+ ``addi`` when needed) into a reserved
    register, so the prologue costs one or two slots and ``count`` must cover
    it.  ``compressed=True`` forces two F1-safe 16-bit instructions per slot;
    ``None`` mixes both widths.
    """
    if type(seed) is not int or seed < 0:
        raise ValueError("seed must be a non-negative integer")
    if type(count) is not int or count < 1:
        raise ValueError("count must be a positive integer")
    if type(ram_base) is not int or ram_base < 0:
        raise ValueError("ram_base must be a non-negative integer")
    if type(ram_size) is not int or ram_size < 0:
        raise ValueError("ram_size must be a non-negative integer")
    if compressed not in (None, True, False):
        raise ValueError("compressed must be True, False or None")
    if ram_size and (ram_base % 4 or ram_size % 4 or ram_size < 4):
        raise ValueError("ram_base and ram_size must be 4-aligned, ram_size >= 4")
    if ram_size and ram_base + ram_size > _MAX_UNSIGNED_32:
        raise ValueError("RAM window must fit the 32-bit address space")
    if ram_size and profile.xlen == 64 and ram_base + ram_size + 0x800 > 1 << 31:
        raise ValueError(
            "RV64 RAM window must stay below 2 GiB-2 KiB so the lui/addi "
            "prologue does not sign-extend the base")
    if not extension_available(profile, CATALOG["ADDI"]):
        raise InstructionNotAvailable("profile must declare I or E")

    rng = random.Random(seed)
    records: list[str] = []
    instructions: list[ProgramInstruction] = []
    reserved: set[int] = set()
    written: set[int] = set()
    base_reg = 0
    pc = 0
    if ram_size and ram_base:
        base_reg = profile.register_count - 1
        hi = ((ram_base + 0x800) >> 12) & 0xFFFFF
        lo = (ram_base - (hi << 12)) & 0xFFFFFFFF
        if lo >= 1 << 31:
            lo -= 1 << 32
        prologue = [("LUI", {"rd": base_reg, "imm": hi})]
        if lo:
            prologue.append(
                ("ADDI", {"rd": base_reg, "rs1": base_reg, "imm": lo}))
        if len(prologue) > count:
            raise ValueError("count must cover the RAM-base prologue slots")
        for name, operands in prologue:
            word = encode(name, xlen=profile.xlen, **operands)
            spec = CATALOG[name]
            instructions.append(ProgramInstruction(
                pc, format_assembly(name, operands), word, 4, spec.extension,
                dict(operands)))
            records.append(word.to_bytes(4, "little").hex())
            pc += 4
        reserved.add(base_reg)
        written.add(base_reg)

    pool32 = _pool(profile, include_non_f1=include_non_f1, ram_size=ram_size,
                   compressed=False)
    pool_c = _pool(profile, include_non_f1=include_non_f1, ram_size=ram_size,
                   compressed=True)
    if not pool32 and not pool_c:
        raise ValueError("no instruction is available for this profile/window")
    if compressed is True and not pool_c:
        raise ValueError("profile has no F1-safe compressed instruction pool")

    while len(records) < count:
        use_compressed = compressed is True or (
            compressed is None and bool(pool_c) and rng.random() < 0.5)
        if use_compressed:
            first = _emit_compressed(rng.choice(pool_c), rng, profile, written,
                                     frozenset(reserved), pc)
            second = _emit_compressed(rng.choice(pool_c), rng, profile, written,
                                      frozenset(reserved), pc + 2)
            records.append(pack_compressed_pair(first.word, second.word).hex())
            instructions.extend((first, second))
            pc += 4
        else:
            item = _emit_32(rng.choice(pool32), rng, profile, written,
                            frozenset(reserved), base_reg, ram_base, ram_size,
                            include_non_f1, pc)
            records.append(item.word.to_bytes(4, "little").hex())
            instructions.append(item)
            pc += 4

    return Program(profile, seed, ram_base if ram_size else 0, ram_size,
                   include_non_f1, compressed, tuple(records),
                   tuple(instructions))
