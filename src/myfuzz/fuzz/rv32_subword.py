"""Opt-in byte/halfword RV32 data-window programs.

The F1 trampoline contract fixes ``x18`` as the base of a 64-byte data window
(``PROGRAM_DATA_WORDS * 4`` bytes in the host).  The legacy program space only
emits ``LW``/``SW`` (``funct3 == 2``); this module is the single Python
authority for the wider natural-width subset the host RAM and the OBI/Wishbone
byte enables can already execute:

* loads ``LB`` (0), ``LH`` (1), ``LW`` (2), ``LBU`` (4), ``LHU`` (5);
* stores ``SB`` (0), ``SH`` (1), ``SW`` (2).

It owns generation, one-step mutation, admission and the reference model for
that subset.  Memory is little-endian and word-aligned, exactly like the
existing RV32 reference model and the in-process RAM's byte lanes.

Admission is opt-in.  The unified entry exposes a scenario flag
``f1_subword`` and the strategy takes the same name; when the flag is off the
legacy gate still refuses every ``funct3 != 2`` memory word by name.  This
module must therefore only be used as the gate when the flag is on.  The
minimal host/gate patch that turns the flag into real execution is documented
in ``docs/patches/subword-host-integration.md``.

Validation rules (all named with the 0-based instruction index)
---------------------------------------------------------------
1. The profile is RV32 and declares ``I`` or ``E``; every non-memory word is
   checked by :func:`myfuzz.fuzz.rv32_program.validate_program_words`, so the
   straight-line, encoding, extension and reserved-register rules stay in one
   place.
2. A memory word must be a load or a store with one of the ``funct3`` values
   above; its base is ``x18``.
3. ``LB``/``SB`` may use any byte offset, ``LH``/``SH`` a 2-byte aligned one
   and ``LW``/``SW`` a 4-byte aligned one.  ``offset + size <= window_size``
   and the offset is the signed 12-bit immediate, so a negative offset is
   refused by the window rule.
4. ``x8`` (mailbox pointer), ``x9`` (slot base) and ``x18`` (data-window base)
   are reserved.  A load may not write one of them; a store may use any of
   them as its data register, and ``x0`` writes are allowed and ignored.
5. ``rd``/``rs2`` must exist in the profile (an RV32E profile has no ``x18``,
   so it can never carry a memory word).
"""

from __future__ import annotations

import random

from ..riscv.encoding import encode
from .rv32_program import (
    DEFAULT_RESERVED_REGISTERS, generate_program, reference_run,
    validate_program_words,
)

_MASK32 = 0xFFFFFFFF
_MEMORY_BASE = 18
_LOAD_OPCODE = 0x03
_STORE_OPCODE = 0x23
_MEMORY_OPCODES = frozenset((_LOAD_OPCODE, _STORE_OPCODE))

# funct3 -> (name, access size in bytes, sign-extends on load)
_LOADS = {0: ("LB", 1, True), 1: ("LH", 2, True), 2: ("LW", 4, False),
          4: ("LBU", 1, False), 5: ("LHU", 2, False)}
_STORES = {0: ("SB", 1, False), 1: ("SH", 2, False), 2: ("SW", 4, False)}

#: Public names, so an entry gate can classify a decoded access without
#: importing a private table.
LOAD_NAMES = frozenset(name for name, _, _ in _LOADS.values())
STORE_NAMES = frozenset(name for name, _, _ in _STORES.values())

# Deterministic width cycles.  The seed picks the starting point and the
# per-program ordinal advances it, so a batch of seeds always covers byte,
# half and full width even when each program holds a single memory word.
_LOAD_WIDTHS = ("LB", "LH", "LW", "LBU", "LHU")
_STORE_WIDTHS = ("SB", "SH", "SW")
_WIDTH_SIZE = {name: size for name, size, _ in _LOADS.values()}
_WIDTH_SIZE.update({name: size for name, size, _ in _STORES.values()})

_RESERVED_LABELS = {8: "mailbox register", 9: "slot base register",
                    18: "data-window base register"}

# `addi x0, x0, 0` is legal in every accepted profile.  Validation substitutes
# it for each memory word so the shared validator can check the non-memory
# words at their real indices without shifting them.
_PLACEHOLDER = 0x00000013

# The largest offset a signed 12-bit immediate can carry.
_MAX_MEMORY_OFFSET = 2047


def _program_words(words):
    """Return ``words`` as a tuple, refusing text/bytes and non-sequences."""
    if isinstance(words, (str, bytes, bytearray)):
        raise ValueError("words must be a sequence of 32-bit instruction words")
    try:
        return tuple(words)
    except TypeError:
        raise ValueError(
            "words must be a sequence of 32-bit instruction words") from None


def subword_access(word):
    """Decode one load/store word into ``(name, size, signed, rs1, rd_or_rs2,
    offset)``.

    ``rd_or_rs2`` is the load destination register or the store data register.
    ``signed`` says whether the load sign-extends.  A word whose opcode is not
    a load or store returns ``None``; a memory opcode with a ``funct3`` outside
    the supported table raises :class:`ValueError` naming the value.  The
    helper is the shared decoder for the entry gate, the host patch and the
    reference model, so all three classify a word identically.
    """
    if type(word) is not int or not 0 <= word <= _MASK32:
        raise ValueError(
            f"instruction is not a 32-bit unsigned word: {word!r}")
    opcode = word & 0x7F
    if opcode == _LOAD_OPCODE:
        table, names, is_load = _LOADS, "LB/LH/LW/LBU/LHU", True
    elif opcode == _STORE_OPCODE:
        table, names, is_load = _STORES, "SB/SH/SW", False
    else:
        return None
    funct3 = (word >> 12) & 7
    entry = table.get(funct3)
    if entry is None:
        raise ValueError(
            f"memory funct3 {funct3} is not {names}")
    name, size, signed = entry
    base = (word >> 15) & 31
    if is_load:
        target = (word >> 7) & 31
        raw = (word >> 20) & 0xFFF
    else:
        target = (word >> 20) & 31
        raw = ((word >> 25) << 5) | ((word >> 7) & 31)
    offset = raw - 4096 if raw & 0x800 else raw
    return name, size, signed, base, target, offset


def _validate_memory_word(profile, index, word, window_size):
    """Check one decoded memory word; ``profile`` was already checked."""
    name, size, _signed, base, target, offset = subword_access(word)
    if base != _MEMORY_BASE:
        raise ValueError(
            f"instruction {index} memory access must use x18 as its base "
            f"(rs1 = x{base})")
    if base >= profile.register_count:
        raise ValueError(
            f"instruction {index} is not legal for this profile: rs1 x18 "
            f"does not exist in a profile with {profile.register_count} "
            "registers")
    field = "rd" if name in LOAD_NAMES else "rs2"
    if target >= profile.register_count:
        raise ValueError(
            f"instruction {index} is not legal for this profile: {field} "
            f"x{target} does not exist in a profile with "
            f"{profile.register_count} registers")
    if name in LOAD_NAMES and target in DEFAULT_RESERVED_REGISTERS:
        raise ValueError(
            f"instruction {index} writes the reserved "
            f"{_RESERVED_LABELS[target]} x{target}")
    if offset % size:
        raise ValueError(
            f"instruction {index} {name} offset {offset} is not "
            f"{size}-byte aligned")
    if offset < 0 or offset + size > window_size:
        raise ValueError(
            f"instruction {index} {name} access leaves the declared data "
            f"window (offset {offset}, size {size}, window {window_size})")


def validate_subword_program(profile, words, *, window_size):
    """Raise :class:`ValueError` unless ``words`` is a legal subword program.

    Non-memory words are delegated to
    :func:`myfuzz.fuzz.rv32_program.validate_program_words` at their own
    indices (memory words are replaced by a legal no-op for that call), so the
    profile, extension, straight-line and reserved-register rules have one
    definition.  The memory-word rules are stated in the module docstring.
    ``window_size`` is the declared data window in bytes and must be an
    integer; generation and the host always declare one.
    """
    words = _program_words(words)
    if not words:
        raise ValueError("program has no instruction")
    if type(window_size) is not int:
        raise ValueError("window_size must be an integer")
    masked = []
    memory_indices = []
    for index, word in enumerate(words):
        if type(word) is not int or not 0 <= word <= _MASK32:
            raise ValueError(
                f"instruction {index} is not a 32-bit unsigned word: {word!r}")
        if word & 0x7F in _MEMORY_OPCODES:
            masked.append(_PLACEHOLDER)
            memory_indices.append(index)
        else:
            masked.append(word)
    validate_program_words(profile, tuple(masked), window_size=window_size)
    for index in memory_indices:
        _validate_memory_word(profile, index, words[index], window_size)


def _pick_offset(rng, size, window_size):
    """One natural-width offset inside the window and the 12-bit immediate."""
    limit = min(window_size - size, _MAX_MEMORY_OFFSET)
    return rng.randrange(limit // size + 1) * size


def generate_subword_program(profile, *, seed, max_words, window_size):
    """Generate one deterministic legal subword program.

    The base program comes from
    :func:`myfuzz.fuzz.rv32_program.generate_program`; only its memory words
    are rewritten, so the ALU skeleton, length draw and register choices are
    the existing generator's.  ``AUIPC`` is left out (``allow_auipc=False``) so
    the result also passes an entry gate that still applies the strict ISA
    record check.  Widths cycle through the load/store tables from a
    seed-dependent start, which guarantees that a batch of seeds covers
    ``LB``/``SB``, ``LH``/``SH`` and ``LW``/``SW``; offsets are drawn from the
    same seed.  The result is validated before it is returned.
    """
    original = generate_program(profile, seed=seed, max_words=max_words,
                                window_size=window_size, allow_auipc=False)
    rng = random.Random(seed ^ 0x534257)
    words = []
    load_ordinal = store_ordinal = 0
    for word in original.words:
        access = subword_access(word)
        if access is None:
            words.append(word)
            continue
        original_name, _size, _signed, base, target, _offset = access
        if original_name in LOAD_NAMES:
            name = _LOAD_WIDTHS[(seed + load_ordinal) % len(_LOAD_WIDTHS)]
            load_ordinal += 1
            size = _WIDTH_SIZE[name]
            words.append(encode(name, rd=target, rs1=base,
                                imm=_pick_offset(rng, size, window_size)))
        else:
            name = _STORE_WIDTHS[(seed + store_ordinal) % len(_STORE_WIDTHS)]
            store_ordinal += 1
            size = _WIDTH_SIZE[name]
            words.append(encode(name, rs2=target, rs1=base,
                                imm=_pick_offset(rng, size, window_size)))
    result = tuple(words)
    validate_subword_program(profile, result, window_size=window_size)
    return result


def mutate_subword_program(profile, words, *, seed, window_size):
    """Change exactly one memory operation's width and offset.

    The input is validated first.  The chosen word keeps its base and its
    ``rd``/``rs2`` register but switches to a different width of the same
    load/store family (so ``LB``/``LBU``, ``LH``/``LHU`` and ``LW`` are all
    reachable) and draws a fresh legal offset.  Every other word is untouched,
    so exactly one instruction differs from the input.  The result is
    validated before it is returned.
    """
    if type(seed) is not int or seed < 0:
        raise ValueError("seed must be a non-negative integer")
    words = _program_words(words)
    validate_subword_program(profile, words, window_size=window_size)
    candidates = [(index, subword_access(word))
                  for index, word in enumerate(words)
                  if word & 0x7F in _MEMORY_OPCODES]
    if not candidates:
        raise ValueError("program has no memory operation to mutate")
    rng = random.Random(seed)
    index, access = rng.choice(candidates)
    name, _size, _signed, base, target, _offset = access
    is_load = name in LOAD_NAMES
    choices = tuple(candidate for candidate in
                    (_LOAD_WIDTHS if is_load else _STORE_WIDTHS)
                    if candidate != name)
    new_name = rng.choice(choices)
    size = _WIDTH_SIZE[new_name]
    operands = {"rs1": base, "imm": _pick_offset(rng, size, window_size)}
    operands["rd" if is_load else "rs2"] = target
    result = list(words)
    result[index] = encode(new_name, **operands)
    result = tuple(result)
    validate_subword_program(profile, result, window_size=window_size)
    return result


def reference_run_subword(words, *, registers, memory, window_size,
                          data_base=0):
    """Execute mixed ALU and natural-width data-window operations in Python.

    ``registers`` and ``memory`` are the initial states (the sparse memory
    mapping is keyed by aligned 32-bit words, exactly like
    :func:`myfuzz.fuzz.rv32_program.reference_run`).  ``data_base`` is the
    address of the first instruction, so an ``AUIPC`` sees its real PC.  The
    program is validated first; every ALU word is executed by the existing
    reference model, while a load/store reads or writes only its natural-width
    little-endian lane inside the aligned word, so a partial store preserves
    the other lanes.

    The result has the ``rv32_reference_run.v1`` shape: ``retires``,
    ``register_writes`` (with the program index), ``final_registers`` (only
    non-zero registers) and ``memory_changes`` (only words whose final value
    differs from the initial one).  A load writes the sign-extended value for
    ``LB``/``LH``; ``LBU``/``LHU`` zero-extend.  A write to ``x0`` is ignored.
    """
    from .rv32_program import (_REFERENCE_PROFILE, _check_memory_state,
                               _check_register_state)
    if type(data_base) is not int or not 0 <= data_base <= _MASK32:
        raise ValueError("data_base must be a 32-bit unsigned integer")
    words = _program_words(words)
    validate_subword_program(_REFERENCE_PROFILE, words,
                             window_size=window_size)
    state = dict(enumerate(_check_register_state(registers)))
    mem = _check_memory_state(memory)
    initial = dict(mem)
    writes = []
    for index, word in enumerate(words):
        access = subword_access(word)
        pc = (data_base + 4 * index) & _MASK32
        if access is None:
            step = reference_run((word,), registers=state, memory=mem,
                                 data_base=pc, window_size=window_size)
            state = {int(reg): value
                     for reg, value in step["final_registers"].items()}
            writes.extend({**write, "index": index}
                          for write in step["register_writes"])
            continue
        name, size, signed, base, rd_or_rs2, offset = access
        address = (state.get(base, 0) + offset) & _MASK32
        if address % size:
            raise ValueError(
                f"{name} effective address {address:#010x} is not "
                f"{size}-byte aligned")
        lane = address & 3
        aligned = address & ~3
        shift = lane * 8
        mask = (1 << (size * 8)) - 1
        if name in STORE_NAMES:
            value = state.get(rd_or_rs2, 0) & mask
            mem[aligned] = ((mem.get(aligned, 0) & ~(mask << shift))
                            | (value << shift))
        else:
            value = (mem.get(aligned, 0) >> shift) & mask
            if signed and value & (1 << (size * 8 - 1)):
                value |= _MASK32 ^ mask
            if rd_or_rs2:
                state[rd_or_rs2] = value
                writes.append(dict(index=index, pc=pc, name=name,
                                   rd=rd_or_rs2, value=value))
    return dict(
        schema_version="rv32_reference_run.v1",
        retires=len(words),
        register_writes=writes,
        final_registers={reg: value for reg, value in state.items()
                         if reg and value},
        memory_changes={address: value for address, value in sorted(mem.items())
                        if initial.get(address, 0) != value},
    )
