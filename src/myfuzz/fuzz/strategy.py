"""The next input of one in-process fuzz batch: corpus, mutation and the gate.

One :class:`Input` is exactly what the host is handed over: the flow tag, the
words, and the canonical record text/message the existing entry would accept.
Nothing here talks to a process or the RTL; the session driver does that.

The strategy composes three independently declared input spaces:

* F1 is a short RV32I/M program (``myfuzz.fuzz.rv32_program``), one to the
  declared number of words, with the same reserved-register and memory-window
  rules the host enforces.  The declared shapes are drawn only when the
  scenario declared them: computed-base address forms
  (``f1_allow_address_forms``) and strictly-forward branches
  (``f1_allow_branches``).  A branch-mode program is accepted only when its
  retirement trace is a function of the state the host can state (``x0``,
  ``x18`` and the sampled data window), so the reference trace stays comparable
  with the real RVFI retirement stream;
* F2-F6 are word-level inputs from ``myfuzz.fuzz.word_spaces`` (declared
  readable/writable registers, the RAM data window, the declared pin rule, one
  word per F5 trigger and per F6 block word);
* every generated or mutated input passes the entry's own ``gate`` before it is
  returned, so the strategy can never hand the host an input the executor would
  refuse.
"""
from __future__ import annotations

from dataclasses import dataclass
import random

#: The opcodes an F1 record word may carry, and the operand fields each one
#: *reads*.  A branch has no destination register (bits 11:7 are its immediate),
#: a store has none either, and a jump reads only a JALR base.
_READ_FIELDS = {
    0x37: (),              # LUI
    0x17: (),              # AUIPC
    0x13: ('rs1',),        # ADDI/SLTI/.../ANDI
    0x33: ('rs1', 'rs2'),  # ADD/SUB/.../MUL/...
    0x03: ('rs1',),        # LW
    0x23: ('rs1', 'rs2'),  # SW
    0x63: ('rs1', 'rs2'),  # BEQ/BNE/BLT/BGE/BLTU/BGEU
    0x6F: (),              # JAL (PC-relative; reads no register)
    0x67: ('rs1',),        # JALR (the base register holds the target address)
}
#: The opcodes that write a destination register at bits 11:7.
_WRITE_OPCODES = frozenset((0x37, 0x17, 0x13, 0x33, 0x03, 0x6F, 0x67))
#: Registers whose value at slot entry the host declares: x0 reads as zero and
#: the firmware points x18 at the declared program data window before the jump.
_TRACE_BASE_REGISTERS = frozenset((0, 18))
_BRANCH_OPCODE = 0x63
_BRANCH_FUNCT3 = frozenset((0, 1, 4, 5, 6, 7))
_JUMP_OPCODES = frozenset((0x6F, 0x67))


def branch_displacement(word):
    """The signed B-type displacement of one encoded branch word."""
    raw = (((word >> 31) & 1) << 12) | (((word >> 7) & 1) << 11) \
        | (((word >> 25) & 0x3F) << 5) | (((word >> 8) & 0xF) << 1)
    return raw - 0x2000 if raw & 0x1000 else raw


#: The registers one admitted compressed parcel reads, by name.  The parcel
#: module is the authority for what a parcel does; this table only says which
#: operand fields carry a *source* (a C.MV overwrites its destination without
#: reading it, C.LI/C.LUI read no register at all).
_PARCEL_SOURCES = {
    'C.LI': (),
    'C.LUI': (),
    'C.ADDI': ('rd',),
    'C.ANDI': ('rd',),
    'C.SLLI': ('rd',),
    'C.SRLI': ('rd',),
    'C.SRAI': ('rd',),
    'C.MV': ('rs2',),
    'C.ADD': ('rd', 'rs2'),
    'C.SUB': ('rd', 'rs2'),
    'C.XOR': ('rd', 'rs2'),
    'C.OR': ('rd', 'rs2'),
    'C.AND': ('rd', 'rs2'),
    'C.J': (),
    'C.JAL': (),
    'C.JR': ('rs1',),
    'C.JALR': ('rs1',),
    'C.BEQZ': ('rs1',),
    'C.BNEZ': ('rs1',),
    'C.LW': ('rs1',),
    'C.SW': ('rs1', 'rs2'),
    'C.LWSP': ('rs1',),
    'C.SWSP': ('rs1', 'rs2'),
}
#: Parcels that write a destination register (the link register for C.JAL/
#: C.JALR; the loaded word for a load).
_PARCEL_WRITES = frozenset((
    'C.ADDI', 'C.LI', 'C.LUI', 'C.SLLI', 'C.SRLI', 'C.SRAI', 'C.ANDI',
    'C.MV', 'C.ADD', 'C.SUB', 'C.XOR', 'C.OR', 'C.AND',
    'C.JAL', 'C.JALR', 'C.LW', 'C.LWSP',
))
#: Compressed control transfers: the four unconditional ones have no fall-through.
_PARCEL_CONTROL = frozenset((
    'C.J', 'C.JAL', 'C.JR', 'C.JALR', 'C.BEQZ', 'C.BNEZ',
))
_PARCEL_UNCONDITIONAL = frozenset(('C.J', 'C.JAL', 'C.JR', 'C.JALR'))


def _must_known_fixpoint(count, reads_at, writes_at, successors, *,
                         seed_registers=_TRACE_BASE_REGISTERS):
    """Greatest fixpoint of "which registers are written on every path".

    ``reads_at``/``writes_at`` are per-instruction sequences of register
    numbers, ``successors`` the control-flow edges.  A backward edge (a bounded
    loop) is iterated until the known set stops shrinking.  Returns ``None``
    when some instruction reads a register that is not known on every path.
    """
    known = [None] * count
    if not count:
        return True
    known[0] = set(seed_registers)
    work = [0]
    budget = (count + 1) * 40 + 64
    while work:
        budget -= 1
        if budget < 0:  # pragma: no cover - monotone shrink cannot exceed it
            return False
        index = work.pop()
        current = known[index]
        if current is None:  # pragma: no cover - only pushed when reached
            continue
        if any(register not in current for register in reads_at[index]):
            return False
        outgoing = set(current)
        outgoing.update(writes_at[index])
        for successor in successors[index]:
            if not 0 <= successor < count:
                continue
            existing = known[successor]
            merged = outgoing if existing is None else existing & outgoing
            if existing is None or merged != existing:
                known[successor] = merged
                work.append(successor)
    return True


def trace_deterministic(words, *, image_base=None, allow_loops=True):
    """Whether a 32-bit program's retirement trace is decided by declared state.

    The reference expectation the entry compares a real RVFI stream with starts
    from ``{x0: 0, x18: data_base}`` plus the host's sampled data window.  Any
    other register a word reads holds firmware state the entry cannot state, so
    such a program has no portable expectation and is not offered to the fuzzer.

    The check is a forward *must* analysis over the program's control-flow graph
    (branches, jumps and - when ``allow_loops`` - the canonical bounded loop's
    back edge): a register is known at a word when it was written on every path
    that reaches that word.  ``x0`` and ``x18`` start known; a load's destination
    is known because the data window is sampled by the host; a jump's link
    register is known because the model writes ``pc + 4``.  The graph comes from
    :func:`myfuzz.fuzz.rv32_program.control_flow_analysis`, so a ``JALR`` target
    is the same statically proven target the gate admits.  A read of an unknown
    register makes the trace path-dependent, and the program is refused here
    rather than silently failing correspondence later.
    """
    from .rv32_program import control_flow_analysis

    words = tuple(words)
    if not words:
        return False
    if any((word & 0x7F) not in _READ_FIELDS for word in words):
        return False
    if any(word & 0x7F == _BRANCH_OPCODE and ((word >> 12) & 7) not in _BRANCH_FUNCT3
           for word in words):
        return False
    try:
        control = control_flow_analysis(
            words, allow_branches=True, allow_jumps=True,
            allow_loops=allow_loops, image_base=image_base)
    except ValueError:
        return False
    reads_at = []
    writes_at = []
    for word in words:
        opcode = word & 0x7F
        reads = []
        if 'rs1' in _READ_FIELDS[opcode]:
            reads.append((word >> 15) & 31)
        if 'rs2' in _READ_FIELDS[opcode]:
            reads.append((word >> 20) & 31)
        reads_at.append(tuple(reads))
        writes = ()
        if opcode in _WRITE_OPCODES:
            destination = (word >> 7) & 31
            if destination:
                writes = (destination,)
        writes_at.append(writes)
    return _must_known_fixpoint(len(words), reads_at, writes_at,
                                control.successors)


def compressed_trace_deterministic(words, *, control=False, memory=False,
                                   image_base=None):
    """Whether a compressed image's retirement trace is decided by declared state.

    A compressed record retires one instruction per parcel.  The trace hash the
    entry compares with ``f1_reference_expectation`` includes the value each
    instruction read, so an instruction whose source register was never written
    by the image reads firmware state and its trace is not comparable:
    ``C.ADDI x12,5`` as the first instruction is legal, but its result depends
    on what the firmware left in x12.  ``C.LI``/``C.LUI`` read no register,
    which is what makes them the only safe first touch.

    The image is walked over its control-flow graph (``control``/``memory``
    admit the opt-in parcel groups; a control transfer's target is the same
    statically proven one the gate admits), and a register is known when it is
    ``x0``/``x18`` or was written on every path that reaches the instruction.  A
    load's destination is known because the host samples the data window.
    """
    from .rv32_compressed import CompressedPolicy, image_instructions

    words = tuple(words)
    if not words:
        return False
    policy = CompressedPolicy(control, memory)
    try:
        layout = image_instructions(words, policy)
    except ValueError:
        return False
    if any(entry.width == 4 and entry.word & 0x7F == _BRANCH_OPCODE
           for entry in layout):
        # A 32-bit branch in a compressed image is path-dependent for this
        # analysis (the branch mode has its own pass in
        # :func:`trace_deterministic`); it is refused here, as before.
        return False
    count = len(layout)
    position_of = {entry.pc_offset: position
                   for position, entry in enumerate(layout)}
    reads_at = []
    writes_at = []
    successors = []
    for position, entry in enumerate(layout):
        fall_through = position + 1 if position + 1 < count else None
        if entry.width == 2:
            fields = _PARCEL_SOURCES.get(entry.name)
            if fields is None:
                return False
            reads_at.append(tuple(entry.operands[field] for field in fields))
            destination = entry.operands.get('rd') if entry.name in _PARCEL_WRITES else None
            if entry.name in ('C.JAL', 'C.JALR'):
                destination = 1
            writes_at.append((destination,) if destination else ())
            if entry.name in _PARCEL_CONTROL:
                if entry.name in _PARCEL_UNCONDITIONAL:
                    target = (entry.pc_offset + entry.operands['imm']
                              if entry.name in ('C.J', 'C.JAL') else None)
                    edges = ()
                    if target is not None and target in position_of:
                        edges = (position_of[target],)
                    successors.append(edges)
                else:
                    target = entry.pc_offset + entry.operands['imm']
                    edges = [value for value in
                             (fall_through, position_of.get(target))
                             if value is not None]
                    successors.append(tuple(dict.fromkeys(edges)))
                continue
            successors.append(() if fall_through is None else (fall_through,))
            continue
        opcode = entry.word & 0x7F
        if opcode not in _READ_FIELDS:
            return False
        reads = []
        if 'rs1' in _READ_FIELDS[opcode]:
            reads.append((entry.word >> 15) & 31)
        if 'rs2' in _READ_FIELDS[opcode]:
            reads.append((entry.word >> 20) & 31)
        reads_at.append(tuple(reads))
        destination = ((entry.word >> 7) & 31) if opcode in _WRITE_OPCODES else 0
        writes_at.append((destination,) if destination else ())
        if opcode == _BRANCH_OPCODE:
            target = entry.pc_offset + entry.operands['imm']
            edges = [value for value in (fall_through, position_of.get(target))
                     if value is not None]
            successors.append(tuple(dict.fromkeys(edges)))
        else:
            successors.append(() if fall_through is None else (fall_through,))
    return _must_known_fixpoint(count, reads_at, writes_at, successors)


@dataclass(frozen=True, slots=True)
class Input:
    """One legal input, ready for the ``CASE`` handover."""

    flow: str
    fields: tuple[int, ...]
    text: str
    message: str
    origin: str = 'fresh'
    parent: str | None = None
    program: object | None = None


class FuzzStrategy:
    """Choose the next input from the declared spaces and a growing corpus.

    ``word_space`` is any object with ``flows()``, ``fresh(flow, rng)``,
    ``mutate(flow, fields, rng)`` and ``valid(flow, fields)`` (the declared
    F2-F6 space).  ``program_profile`` is a ``RiscvProfile`` when F1 is served
    by the profile-driven program generator, and ``None`` disables F1.  ``gate``
    is the entry's ``(flow, fields) -> (text, message)`` validator; a rejected
    input is retried and never returned.
    """

    def __init__(self, *, flows, gate, program_profile=None, f1_words=1,
                 program_window=64, word_space=None, trigger_values=(),
                 seed=0, corpus=None, mutation_probability=0.85,
                 max_attempts=8, extra_seeds=(), f1_subword=False,
                 f1_allow_address_forms=False, f1_allow_branches=False,
                 f1_allow_compressed=False, f1_allow_jumps=False,
                 f1_allow_loops=False, f1_allow_compressed_control=False,
                 f1_allow_compressed_memory=False, f1_image_base=None):
        if not callable(gate):
            raise ValueError('a gate callable is required')
        flows = tuple(flows)
        if not flows or any(flow not in ('F1', 'F2', 'F3', 'F4', 'F5', 'F6')
                            for flow in flows):
            raise ValueError('unsupported input flow set: ' + repr(flows))
        if type(f1_words) is not int or not 1 <= f1_words <= 16:
            raise ValueError('f1_words must be an integer in 1..16')
        if program_profile is not None and 'F1' not in flows:
            raise ValueError('a program profile was given but F1 is not offered')
        if 'F1' in flows and program_profile is None:
            raise ValueError('F1 needs a declared program profile')
        if f1_subword and (f1_words < 2 or program_profile is None or
                           program_profile.register_count <= 18):
            raise ValueError('subword F1 needs program mode and an x18 data-window base')
        if not isinstance(f1_allow_address_forms, bool):
            raise ValueError('f1_allow_address_forms must be a boolean')
        if not isinstance(f1_allow_branches, bool):
            raise ValueError('f1_allow_branches must be a boolean')
        if f1_allow_address_forms and (f1_words < 2 or program_profile is None or
                                       program_profile.register_count <= 18):
            raise ValueError('address-form F1 needs program mode and an x18 '
                             'data-window base')
        if f1_allow_address_forms and f1_subword:
            raise ValueError('subword and address-form F1 are incompatible')
        if f1_allow_branches and (f1_words < 2 or program_profile is None):
            raise ValueError('branch F1 needs program mode and a declared program '
                             'profile')
        if f1_allow_branches and f1_subword:
            raise ValueError('subword and branch F1 are incompatible')
        if not isinstance(f1_allow_compressed, bool):
            raise ValueError('f1_allow_compressed must be a boolean')
        if f1_allow_compressed and (f1_words < 2 or program_profile is None):
            raise ValueError('compressed F1 needs program mode and a declared '
                             'program profile')
        if f1_allow_compressed and not program_profile.has('C'):
            raise ValueError('compressed F1 needs a program profile that declares '
                             'the C extension, not '
                             + str(sorted(program_profile.extensions)))
        if f1_allow_compressed and program_profile.instruction_alignment != 2:
            raise ValueError('compressed F1 needs a 2-byte instruction alignment, '
                             'not ' + str(program_profile.instruction_alignment))
        if f1_allow_compressed and (f1_subword or f1_allow_address_forms):
            raise ValueError('compressed F1 is incompatible with subword widths '
                             'and computed-base address forms')
        for name, value in (('f1_allow_jumps', f1_allow_jumps),
                            ('f1_allow_loops', f1_allow_loops),
                            ('f1_allow_compressed_control',
                             f1_allow_compressed_control),
                            ('f1_allow_compressed_memory',
                             f1_allow_compressed_memory)):
            if not isinstance(value, bool):
                raise ValueError(name + ' must be a boolean')
        if (f1_allow_jumps or f1_allow_loops) and (
                f1_words < 2 or program_profile is None):
            raise ValueError('jump/loop F1 needs program mode and a declared '
                             'program profile')
        if f1_allow_loops and not f1_allow_branches:
            raise ValueError('f1_allow_loops needs f1_allow_branches: the loop '
                             "back edge is a B-type branch")
        if f1_allow_jumps and (f1_allow_compressed or f1_allow_address_forms
                               or f1_subword):
            raise ValueError('jump F1 is not combined with compressed, '
                             'address-form or subword F1')
        if f1_allow_loops and (f1_allow_compressed or f1_allow_address_forms
                               or f1_subword):
            raise ValueError('loop F1 is not combined with compressed, '
                             'address-form or subword F1')
        if f1_allow_compressed_control and not f1_allow_compressed:
            raise ValueError('f1_allow_compressed_control needs '
                             'f1_allow_compressed')
        if f1_allow_compressed_memory and not f1_allow_compressed:
            raise ValueError('f1_allow_compressed_memory needs '
                             'f1_allow_compressed')
        if f1_image_base is not None and (type(f1_image_base) is not int
                                          or not 0 <= f1_image_base <= 0xFFFFFFFF):
            raise ValueError('f1_image_base must be a 32-bit unsigned integer '
                             'or None')
        if not 0.0 <= mutation_probability <= 1.0:
            raise ValueError('mutation_probability must be in 0..1')
        self.flows = flows
        self.gate = gate
        self.program_profile = program_profile
        self.f1_words = f1_words
        self.f1_subword = f1_subword
        self.f1_allow_address_forms = f1_allow_address_forms
        self.f1_allow_branches = f1_allow_branches
        self.f1_allow_compressed = f1_allow_compressed
        self.f1_allow_jumps = f1_allow_jumps
        self.f1_allow_loops = f1_allow_loops
        self.f1_allow_compressed_control = f1_allow_compressed_control
        self.f1_allow_compressed_memory = f1_allow_compressed_memory
        self.f1_image_base = f1_image_base
        self.program_window = program_window
        self.word_space = word_space
        self.trigger_values = tuple(tuple(row) for row in trigger_values)
        self.rng = random.Random(seed)
        self.seed = seed
        self.corpus = corpus
        self.mutation_probability = mutation_probability
        self.max_attempts = max_attempts
        self.extra_seeds = tuple((flow, tuple(fields)) for flow, fields in extra_seeds)
        for flow, _ in self.extra_seeds:
            if flow not in flows:
                raise ValueError('a seed record uses a flow that is not offered: ' + flow)
        self.generated = 0

    # -- F1 ---------------------------------------------------------------
    def _require_declared_trace(self, program):
        """Refuse a branch program whose trace the entry cannot state.

        The entry compares a real RVFI retirement stream with
        ``f1_reference_expectation``, which starts from ``{x0: 0,
        x18: data_base}`` and the host's sampled data window.  A program that
        reads any other register at slot entry has no portable expectation, so
        the fuzzer does not offer one.
        """
        if not trace_deterministic(program.words):
            raise ValueError('branch program reads firmware state the entry '
                             'cannot declare; the retirement trace would not be '
                             'comparable')
        return program

    def _compressed_literal_program(self, rng):
        """A compressed image whose parcels only read what they wrote first.

        ``C.LI`` reads no register, so a pair word of two ``C.LI`` parcels is
        trace-deterministic even though it is the image's first instruction.  The
        later words extend the same fact: each parcel is drawn from
        :data:`_PARCEL_SOURCES` and every source it names has been written by an
        earlier parcel of this image.  This is the fallback when a drawn program
        reads firmware state; it is a legal compressed record by construction and
        is still checked by the entry's gate before it is returned.
        """
        from .rv32_compressed import pack_parcels
        from ..riscv.encoding import encode

        registers = [12, 13, 14, 15]
        words = []
        known = set(_TRACE_BASE_REGISTERS)
        written = []
        for _ in range(self.f1_words):
            parcels = []
            for _ in range(2):
                # A register no parcel has written yet can only be touched by a
                # form that reads nothing (C.LI / C.LUI); otherwise reuse a
                # register this image already wrote.
                fresh = [reg for reg in registers if reg not in written]
                if fresh:
                    rd = fresh[0]
                    parcels.append(encode('C.LI', xlen=32, rd=rd,
                                          imm=rng.choice([1, 2, 3, 0x17, -1,
                                                          -2, 0x1F])))
                    written.append(rd)
                    known.add(rd)
                    continue
                rd = rng.choice(written)
                name = rng.choice(['C.ADDI', 'C.ANDI', 'C.SLLI', 'C.SRLI',
                                   'C.SRAI', 'C.MV', 'C.ADD'])
                if name in ('C.MV', 'C.ADD'):
                    source = rng.choice([reg for reg in written if reg != rd])
                    parcels.append(encode(name, xlen=32, rd=rd, rs2=source))
                elif name == 'C.ANDI':
                    parcels.append(encode(name, xlen=32, rd=rd,
                                          imm=rng.choice([15, 31, 0x30, -1])))
                elif name == 'C.ADDI':
                    parcels.append(encode(name, xlen=32, rd=rd,
                                          imm=rng.choice([1, 2, -1, 7])))
                else:
                    parcels.append(encode(name, xlen=32, rd=rd,
                                          shamt=rng.randrange(1, 16)))
            words.append(pack_parcels(parcels[0], parcels[1]))
        return tuple(words)

    def _compressed_fresh(self, rng):
        """One fresh compressed program whose trace the entry can compare."""
        from myfuzz.fuzz.rv32_compressed import (
            generate_compressed_control_program,
            generate_compressed_memory_program, generate_compressed_program)
        if self.f1_allow_compressed_control or self.f1_allow_compressed_memory:
            # The opt-in control/memory generators are the only ones that emit
            # the declared parcel groups; each validates its own image.
            generators = []
            if self.f1_allow_compressed_control:
                generators.append(generate_compressed_control_program)
            if self.f1_allow_compressed_memory:
                generators.append(generate_compressed_memory_program)
            generator = generators[rng.randrange(len(generators))]
            for _ in range(16):
                program = generator(
                    self.program_profile, seed=rng.randrange(1 << 31),
                    max_words=self.f1_words,
                    window_size=self.program_window,
                    min_words=min(3 if generator is
                                  generate_compressed_memory_program else 2,
                                  self.f1_words),
                    image_base=self.f1_image_base)
                if compressed_trace_deterministic(
                        program.words,
                        control=self.f1_allow_compressed_control,
                        memory=self.f1_allow_compressed_memory,
                        image_base=self.f1_image_base):
                    return program
            return self._compressed_literal_program(rng)
        for _ in range(16):
            program = generate_compressed_program(
                self.program_profile, seed=rng.randrange(1 << 31),
                max_words=self.f1_words, window_size=self.program_window,
                min_words=min(2, self.f1_words))
            if compressed_trace_deterministic(program.words):
                return program
        # Every draw read a register before the image wrote it: build the
        # deterministic image directly instead of handing the batch a program
        # whose reference trace would not be comparable.
        return self._compressed_literal_program(rng)

    def _compressed_mutate(self, rng, words):
        """One compressed mutation, accepted only when its trace is comparable."""
        from myfuzz.fuzz.rv32_compressed import mutate_compressed_program
        from myfuzz.fuzz.rv32_program import ShortProgram
        # ``compressed=True`` states what the words already show: the base
        # ``mutate_program`` delegates to the parcel mutation when it sees one.
        program = ShortProgram(self.program_profile, 0, self.f1_words,
                               tuple(words), (), 'mutation', True)
        for _ in range(12):
            candidate = mutate_compressed_program(
                self.program_profile, program,
                seed=rng.randrange(1 << 31), max_words=self.f1_words,
                window_size=self.program_window,
                allow_compressed_control=self.f1_allow_compressed_control,
                allow_compressed_memory=self.f1_allow_compressed_memory,
                image_base=self.f1_image_base)
            if compressed_trace_deterministic(
                    candidate.words,
                    control=self.f1_allow_compressed_control,
                    memory=self.f1_allow_compressed_memory,
                    image_base=self.f1_image_base):
                return candidate
        # Every drawn mutation read firmware state: hand the batch a fresh
        # trace-comparable program instead of an unverifiable one.
        return self._compressed_fresh(rng)

    def _f1_fresh(self, rng):
        if self.f1_subword:
            from myfuzz.fuzz.rv32_subword import generate_subword_program
            return generate_subword_program(
                self.program_profile, seed=rng.randrange(1 << 31),
                max_words=self.f1_words, window_size=self.program_window)
        if self.f1_allow_compressed:
            return self._compressed_fresh(rng)
        from myfuzz.fuzz.rv32_program import generate_program
        if self.f1_allow_loops:
            # The scenario declared the canonical bounded loop.  Four words are
            # the shortest image that can hold init, a body, the induction step
            # and the back edge.
            for _ in range(16):
                program = generate_program(
                    self.program_profile, seed=rng.randrange(1 << 31),
                    max_words=self.f1_words, window_size=self.program_window,
                    min_words=min(4, self.f1_words), style='loop',
                    allow_branches=True, allow_loops=True,
                    image_base=self.f1_image_base)
                if trace_deterministic(program.words,
                                       image_base=self.f1_image_base):
                    return program
            raise ValueError('could not generate a trace-deterministic loop '
                             'program')
        if self.f1_allow_jumps:
            for _ in range(16):
                program = generate_program(
                    self.program_profile, seed=rng.randrange(1 << 31),
                    max_words=self.f1_words, window_size=self.program_window,
                    min_words=min(3, self.f1_words), style='jump',
                    allow_jumps=True, image_base=self.f1_image_base)
                if trace_deterministic(program.words,
                                       image_base=self.f1_image_base):
                    return program
            raise ValueError('could not generate a trace-deterministic jump '
                             'program')
        if self.f1_allow_branches:
            # The scenario declared strictly-forward branches.  Three words are
            # the shortest image that can carry a root, the branch and the word
            # it may skip; a two-word image would always branch to the appended
            # return jump and skip nothing.
            style = 'extended' if self.f1_allow_address_forms else 'branch'
            return self._require_declared_trace(generate_program(
                self.program_profile, seed=rng.randrange(1 << 31),
                max_words=self.f1_words, window_size=self.program_window,
                # A three-word image is the shortest one that can skip a word;
                # a two-word declaration still admits a branch to the exit.
                min_words=min(3, self.f1_words), style=style,
                allow_address_forms=self.f1_allow_address_forms,
                allow_branches=True))
        if self.f1_allow_address_forms:
            # The scenario declared computed-base memory words, so the one
            # generator that emits them builds every fresh F1 program.  Two
            # words are the shortest image that can carry one (a base and the
            # LW/SW that uses it), so the length floor is raised only here.
            return generate_program(
                self.program_profile, seed=rng.randrange(1 << 31),
                max_words=self.f1_words, window_size=self.program_window,
                min_words=2, style='address', allow_address_forms=True)
        program = generate_program(
            self.program_profile, seed=rng.randrange(1 << 31),
            max_words=self.f1_words, window_size=self.program_window)
        return program

    def _f1_mutate(self, rng, words):
        if self.f1_allow_compressed:
            return self._compressed_mutate(rng, words)
        if self.f1_subword and any((word & 0x7f) in (3, 35) for word in words):
            from myfuzz.fuzz.rv32_subword import mutate_subword_program
            return mutate_subword_program(self.program_profile, words,
                                          seed=rng.randrange(1 << 31),
                                          window_size=self.program_window)
        from myfuzz.fuzz.rv32_program import (
            ShortProgram, mutate_control_program, mutate_program)
        # The words are enough to mutate: the generator validates and re-decodes
        # them, so a corpus entry loaded from disk needs no extra metadata.
        program = ShortProgram(self.program_profile, 0, self.f1_words,
                               tuple(words), ())
        if self.f1_allow_jumps or self.f1_allow_loops:
            for _ in range(12):
                candidate = mutate_control_program(
                    self.program_profile, program,
                    seed=rng.randrange(1 << 31), max_words=self.f1_words,
                    window_size=self.program_window,
                    allow_branches=True,
                    allow_jumps=self.f1_allow_jumps,
                    allow_loops=self.f1_allow_loops,
                    image_base=self.f1_image_base)
                if trace_deterministic(candidate.words,
                                       image_base=self.f1_image_base):
                    return candidate
            return self._f1_fresh(rng)
        if self.f1_allow_branches:
            # A mutation may read an operand the program did not write (an
            # ``operand`` rewire of a source register).  Such a program still is
            # a legal branch record, but its retirement trace would depend on
            # firmware state, so a different mutation seed is drawn instead.
            for _ in range(12):
                candidate = mutate_program(
                    self.program_profile, program,
                    seed=rng.randrange(1 << 31), max_words=self.f1_words,
                    window_size=self.program_window,
                    allow_address_forms=self.f1_allow_address_forms,
                    allow_branches=True)
                if trace_deterministic(candidate.words):
                    return candidate
            # Every drawn mutation was path-dependent: hand the batch a fresh
            # trace-comparable program instead of an unverifiable one.
            return self._f1_fresh(rng)
        return mutate_program(
            self.program_profile, program, seed=rng.randrange(1 << 31),
            max_words=self.f1_words, window_size=self.program_window,
            allow_address_forms=self.f1_allow_address_forms)

    # -- the declared word space -----------------------------------------
    def _flow_fields(self, flow, rng):
        if self.word_space is None:
            raise ValueError('no word input space is declared for ' + flow)
        return tuple(self.word_space.fresh(flow, rng))

    def _mutate_fields(self, flow, fields, rng):
        if self.word_space is None:
            raise ValueError('no word input space is declared for ' + flow)
        return tuple(self.word_space.mutate(flow, tuple(fields), rng))

    # -- construction -----------------------------------------------------
    def _make(self, flow, fields, *, origin, parent=None, program=None):
        text, message = self.gate(flow, tuple(fields))
        return Input(flow=flow, fields=tuple(fields), text=text, message=message,
                     origin=origin, parent=parent, program=program)

    def _attempt(self, flow, maker, *, origin, parent=None):
        """Try the declared space until the entry's gate accepts one input."""
        last = None
        for _ in range(self.max_attempts):
            try:
                value = maker()
                if flow == 'F1':
                    program = None if isinstance(value, tuple) else value
                    fields = value if program is None else tuple(program.words)
                else:
                    program = None
                    fields = tuple(value)
                input_ = self._make(flow, fields, origin=origin, parent=parent,
                                    program=program)
                self.generated += 1
                return input_
            except ValueError as error:
                last = error
        raise ValueError('could not generate a legal ' + flow + ' input: ' + str(last))

    def _declared_f5_row(self):
        """One declared F5 example row, or None when the behavior has none."""
        rows = [row for row in self.trigger_values if row]
        if not rows:
            return None
        lengths = {len(row) for row in rows}
        if len(lengths) != 1:
            return None
        return rows[self.rng.randrange(len(rows))]

    def _f5_fresh(self):
        """A declared trigger vector, lightly varied, or the word space's own."""
        row = self._declared_f5_row()
        if row is None or self.rng.random() >= 0.5:
            return self._flow_fields('F5', self.rng)
        values = list(row)
        # The last declared trigger is the one that raises the interrupt; keep
        # it and vary the earlier setup words so most fresh F5 cases complete.
        for index in range(len(values) - 1):
            if self.rng.random() < 0.3:
                values[index] = self.rng.getrandbits(32)
        return tuple(values)

    def _f5_mutate(self, fields):
        row = self._declared_f5_row()
        if row is None or len(row) != len(fields) or self.rng.random() >= 0.5:
            return self._mutate_fields('F5', fields, self.rng)
        values = list(fields)
        if self.rng.random() < 0.5:
            index = self.rng.randrange(len(values))
            values[index] = row[index]
        else:
            # Never randomise the triggering word by default: that word only
            # completes near the declared value, so a random replacement there is
            # a guaranteed timeout rather than a new behaviour.
            index = self.rng.randrange(max(1, len(values) - 1))
            values[index] = self.rng.getrandbits(32)
        return tuple(values)

    def fresh(self, flow):
        """One fresh input for ``flow``, accepted by the gate."""
        if flow not in self.flows:
            raise ValueError('flow is not offered: ' + flow)
        if flow == 'F1':
            return self._attempt(flow, lambda: self._f1_fresh(self.rng), origin='fresh')
        if flow == 'F5':
            return self._attempt(flow, self._f5_fresh, origin='fresh')
        return self._attempt(flow, lambda: self._flow_fields(flow, self.rng),
                             origin='fresh')

    def mutate(self, parent):
        """One mutated input derived from ``parent``, accepted by the gate."""
        if parent.flow not in self.flows:
            raise ValueError('flow is not offered: ' + parent.flow)
        if parent.flow == 'F1':
            return self._attempt(parent.flow,
                                 lambda: self._f1_mutate(self.rng, parent.fields),
                                 origin='mutation', parent=parent.text)
        if parent.flow == 'F5':
            return self._attempt(parent.flow,
                                 lambda: self._f5_mutate(parent.fields),
                                 origin='mutation', parent=parent.text)
        return self._attempt(parent.flow,
                             lambda: self._mutate_fields(parent.flow,
                                                         parent.fields, self.rng),
                             origin='mutation', parent=parent.text)

    # -- seeds and selection ---------------------------------------------
    def seed_inputs(self):
        """The declared seed corpus.

        Operator-declared seed records come first: they are the declared
        precondition of a stateful case (for example an F4 that makes a pad an
        output before the F5 that raises its interrupt).  Then one fresh input
        per flow and any declared F5 example.
        """
        seeds = []

        def add(candidate):
            if candidate.text not in {row.text for row in seeds}:
                seeds.append(candidate)

        for flow, fields in self.extra_seeds:
            try:
                add(self._make(flow, fields, origin='seed'))
            except ValueError:
                continue
        # The declared F5 example rows come before the random fresh inputs: they
        # are the behaviour's own completing vector, and a batch should start
        # with one real interrupt rather than a guaranteed timeout.
        if 'F5' in self.flows:
            for row in self.trigger_values:
                try:
                    add(self._make('F5', row, origin='seed'))
                except ValueError:
                    continue
        for flow in self.flows:
            try:
                add(self.fresh(flow))
            except ValueError:
                continue
        return seeds

    def choose_parent(self, rng):
        if self.corpus is None:
            return None
        entry = self.corpus.choose(rng)
        if entry is None:
            return None
        self.corpus.mark_picked(entry)
        return Input(flow=entry.flow, fields=tuple(entry.fields),
                     text=entry.record_text, message='', origin=entry.origin)

    def next_input(self):
        """The next input: a corpus mutation with probability ``p``, else fresh."""
        if self.rng.random() < self.mutation_probability:
            parent = self.choose_parent(self.rng)
            if parent is not None:
                try:
                    return self.mutate(parent)
                except ValueError:
                    pass
        return self.fresh(self.rng.choice(self.flows))
