"""A declared M-mode trap program for the F1 trampoline slot (CVA6 AXI4).

The historical F1 subset refuses every system instruction: a CSR write would
change the state the trampoline returns into, and a trap would escape the
"every installed word retired" accounting.  This module is the one opt-in that
adds a *declared* trap: the slot's first word is a real ``ECALL`` the core takes
as a synchronous exception, and the firmware image (not the slot program) owns
the handler.

What the host and this module compare, and what neither of them invents:

* the RVFI record of the ECALL itself: ``trap == 1``, the record's own
  ``cause`` (the architectural cause code), ``intr == 0`` (a synchronous trap,
  not an interrupt) and ``mode == 3`` (the privilege level it retired in);
* the scoreboard's registered CSR readback after the trap: ``mcause`` and
  ``mepc`` are the values the core wrote, and they are the same snapshot;
* the two words the firmware's own handler stored: it executes ``CSRRS`` on
  ``mcause``/``mepc``, advances ``mepc`` past the ECALL, stores both values to
  the declared RAM cells, clears ``mcause`` and returns with ``MRET``, so the
  words after the ECALL really execute.  Clearing the cause is the handler's own
  architectural write; it is what makes the scoreboard's readback show a clean
  0 -> cause transition for each trap case in one run (the CSR is not reset
  between cases, because the CPU is not either).

The reference trace below is the *in-slot* retirement sequence (the ECALL plus
the declared straight-line ALU words that follow it), hashed with the same
FNV-1a 32 the host prints.  The handler's own retirements are outside the slot
and are not part of that trace; they are witnessed by the stored words and by
the CSR readback instead.

Addresses are declared, never guessed: the firmware builder places the trap
handler and its three RAM cells from the addresses this module returns for one
layout, and the host reads the same three cells back from its own RAM model.

The module is intentionally isolated: it imports no ``scripts`` module, performs
no I/O, and states no RTL result.  The pinned privilege assumption it makes is
the one the pinned CVA6 configuration starts in after reset (M-mode), and the
handler is written for that mode only.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

#: ``riscv::ENV_CALL_MMODE``: an ``ECALL`` executed in M-mode.  This is the one
#: trap the declared program installs a handler for.
ENV_CALL_MMODE = 11
#: The ``ECALL`` encoding, exactly as the RISC-V base ISA defines it.
ECALL_WORD = 0x00000073
#: M-mode, as the RVFI record's ``mode`` field states it (``priv_lvl``).
MODE_M = 3

#: Where the trap handler and its cells live in the RAM image, relative to the
#: image base.  0x600 sits between the interrupt handler (0x400) and the main
#: loop (0x1000); 0x3080 is past the mailbox and its handler block, whose last
#: byte is 0x3053.
TRAP_HANDLER_OFFSET = 0x600
TRAP_BLOCK_OFFSET = 0x3080
TRAP_BLOCK_BYTES = 12
#: The sentinel the host writes into the three cells before a case, so a value
#: surviving it is reported as "the handler never ran" instead of as the
#: previous case's word.
TRAP_SENTINEL = 0xFFFFFFFF

#: Registers the slot program may not write: x8 is the firmware's mailbox
#: pointer and x18 the declared data-window base (the firmware sets both before
#: the jump), and x9 is reserved by the host's program gate.
_RESERVED_DESTINATIONS = frozenset((8, 9, 18))
#: Opcodes the words after the ECALL may carry: the RV32I ALU forms the program
#: gate already admits, without memory, control transfer or any other system
#: word.  A second ECALL is refused: this mode declares exactly one trap.
_ALU_OPCODES = frozenset((0x37, 0x17, 0x13, 0x33))


class TrapProgramError(ValueError):
    """The declared trap program or a submitted record is not legal."""


def trap_declaration(config: Mapping) -> dict | None:
    """The scenario's declared trap program, or ``None``.

    ``f1_trap_program`` is either absent (the historical F1 subset, untouched)
    or an object stating the cause it declares.  Only the M-mode ``ECALL`` is
    admitted; any other cause is refused by name, because the handler this
    firmware builds is an exception handler for that one cause and the host has
    no way to prove a different one.
    """
    declared = config.get('f1_trap_program')
    if declared is None:
        return None
    if not isinstance(declared, Mapping):
        raise TrapProgramError('unsupported-f1-trap:declaration-is-not-an-object')
    unknown = set(declared) - {'cause', 'words', 'notes'}
    if unknown:
        raise TrapProgramError('unsupported-f1-trap:unknown-key:'
                               + ','.join(sorted(str(key) for key in unknown)))
    cause = declared.get('cause', ENV_CALL_MMODE)
    if type(cause) is not int or cause != ENV_CALL_MMODE:
        raise TrapProgramError(
            'unsupported-f1-trap:only-an-m-mode-ecall (cause 11) is declared; '
            'got ' + repr(declared.get('cause')))
    words = declared.get('words', 2)
    if type(words) is not int or not 1 <= words <= 16:
        raise TrapProgramError('unsupported-f1-trap:words-must-be-1..16')
    return dict(cause=ENV_CALL_MMODE, words=words,
                cells=dict(cause='trap_cause', epc='trap_epc', flag='trap_flag'))


def trap_layout(layout: Mapping) -> dict:
    """The same layout plus the trap handler and its three cells.

    The addresses are derived from the image base the firmware builder already
    uses, so every scenario gets the same relative placement and the host's
    ``TRAP_*_CELL`` macros and the handler's ``SW`` targets are one declaration.
    """
    ram = layout['ram_base']
    return dict(layout,
                trap_handler=ram + TRAP_HANDLER_OFFSET,
                trap_cause=ram + TRAP_BLOCK_OFFSET,
                trap_epc=ram + TRAP_BLOCK_OFFSET + 4,
                trap_flag=ram + TRAP_BLOCK_OFFSET + 8,
                trap_block_bytes=TRAP_BLOCK_BYTES,
                trap_sentinel=TRAP_SENTINEL)


def _record_words(record: object) -> list[int]:
    """The word sequence of an entry record, a program object or a sequence."""
    if isinstance(record, Mapping):
        fields = record.get('fields')
        if fields is None:
            raise TrapProgramError('an F1 trap record carries no words')
        return [int(word) & 0xFFFFFFFF for word in fields]
    if hasattr(record, 'words'):
        return [int(word) & 0xFFFFFFFF for word in record.words]
    return [int(word) & 0xFFFFFFFF for word in record]


def validate_trap_record(record: object, *, slot: int,
                         max_words: int = 16) -> list[int]:
    """Raise :class:`TrapProgramError` unless the record is the declared shape.

    * the first word is an ``ECALL`` (the one faulting instruction);
    * at most ``max_words`` words, and exactly one ``ECALL`` in the record;
    * every following word is an admitted RV32I ALU form whose destination is
      not x8/x9/x18 and whose sources were written by an earlier word of this
      same record or are x0/x18, so the reference trace does not read firmware
      state the declaration cannot state.
    """
    words = _record_words(record)
    if not words:
        raise TrapProgramError('F1 trap program is empty')
    if len(words) > max_words:
        raise TrapProgramError(
            'F1 trap program has %d words; the scenario declares at most %d'
            % (len(words), max_words))
    values = [int(word) & 0xFFFFFFFF for word in words]
    if values[0] != ECALL_WORD:
        raise TrapProgramError(
            'F1 trap program word 0 is not an ECALL; the declared trap needs '
            'the ECALL first')
    written = {0}
    for index, word in enumerate(values[1:], start=1):
        if (word & 3) != 3:
            raise TrapProgramError(
                'F1 trap program word %d is not one 32-bit instruction' % index)
        opcode = word & 0x7F
        rd = (word >> 7) & 31
        rs1 = (word >> 15) & 31
        rs2 = (word >> 20) & 31
        if opcode not in _ALU_OPCODES:
            raise TrapProgramError(
                'F1 trap program word %d is outside the declared straight-line '
                'ALU subset after the ECALL' % index)
        if opcode == 0x17:
            raise TrapProgramError(
                'F1 trap program word %d is AUIPC; the value would depend on '
                'the slot address rather than the declared program' % index)
        funct3 = (word >> 12) & 7
        funct7 = (word >> 25) & 0x7F
        if opcode == 0x13:
            if funct3 == 2 or funct3 == 3:
                raise TrapProgramError(
                    'F1 trap program word %d is SLTI/SLTIU, which this declared '
                    'subset does not include' % index)
            if funct3 == 1 and funct7 != 0:
                raise TrapProgramError(
                    'F1 trap program word %d is not an SLLI (funct7 %d)'
                    % (index, funct7))
            if funct3 == 5 and funct7 not in (0, 0x20):
                raise TrapProgramError(
                    'F1 trap program word %d is not SRLI/SRAI (funct7 %d)'
                    % (index, funct7))
        if opcode == 0x33:
            if funct7 not in (0, 0x20):
                raise TrapProgramError(
                    'F1 trap program word %d is not an RV32I OP word (funct7 %d)'
                    % (index, funct7))
            if funct7 == 0x20 and funct3 != 0:
                raise TrapProgramError(
                    'F1 trap program word %d is not SUB (funct7 0x20, funct3 %d)'
                    % (index, funct3))
        if rd in _RESERVED_DESTINATIONS:
            raise TrapProgramError(
                'F1 trap program word %d writes x%d, a reserved register' % (index, rd))
        if opcode == 0x37:  # LUI reads nothing
            sources = ()
        elif opcode == 0x33:
            sources = (rs1, rs2)
        else:
            sources = (rs1,)
        for source in sources:
            if source not in written and source != 18:
                raise TrapProgramError(
                    'F1 trap program word %d reads x%d before this program '
                    'wrote it; the reference trace would depend on firmware '
                    'state' % (index, source))
        written.add(rd)
    return values


def _sext(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value & (sign - 1)) - (value & sign)


def _u32(value: int) -> int:
    return value & 0xFFFFFFFF


def reference_trace(words: Sequence[int], *, slot: int,
                    data_base: int = 0) -> dict:
    """Execute the declared words and return the in-slot reference trace.

    The ECALL contributes the record RVFI state for it: ``rd_addr`` 0 and
    ``rd_wdata`` 0 (RVFI's own rule for a retirement that writes no register),
    with ``trap`` 1 and ``cause`` the declared M-mode environment call.  The
    words after it are RV32I ALU forms executed on a register file that starts
    at ``x0 = 0`` and ``x18 = data_base``; every register they read was either
    written by an earlier word or is one of those two, so the result is the
    reference value and not a guess about firmware state.
    """
    values = [int(word) & 0xFFFFFFFF for word in words]
    registers = {0: 0, 18: data_base & 0xFFFFFFFF}
    trace = []
    pc = slot
    trap_at = None
    for index, word in enumerate(values):
        rd = (word >> 7) & 31
        if index == 0:
            if word != ECALL_WORD:
                raise TrapProgramError('F1 trap reference needs the ECALL first')
            trap_at = pc
            trace.append(dict(pc=_u32(pc), insn_word=word, rd=0, wdata=0,
                              trap=True, cause=ENV_CALL_MMODE, mode=MODE_M))
            pc += 4
            continue
        opcode = word & 0x7F
        funct3 = (word >> 12) & 7
        rs1 = (word >> 15) & 31
        rs2 = (word >> 20) & 31
        imm_i = _sext((word >> 20) & 0xFFF, 12)
        a = registers.get(rs1, 0)
        b = registers.get(rs2, 0)
        value = 0
        if opcode == 0x37:
            value = (word & 0xFFFFF000)
        elif opcode == 0x13:
            # Only the forms the validator admits: ADDI, the four logical
            # immediates and the three shifts.  SLTI/SLTIU are not declared.
            if funct3 == 0:
                value = _u32(a + imm_i)
            elif funct3 == 4:
                value = _u32(a ^ imm_i)
            elif funct3 == 6:
                value = _u32(a | imm_i)
            elif funct3 == 7:
                value = _u32(a & imm_i)
            elif funct3 == 1:
                value = _u32(a << ((word >> 20) & 0x1F))
            elif funct3 == 5:
                shamt = (word >> 20) & 0x1F
                if (word >> 30) & 1:
                    value = _u32(_sext(a, 32) >> shamt)
                else:
                    value = _u32(a >> shamt)
            else:
                raise TrapProgramError('F1 trap reference: unsupported OP-IMM funct3')
        elif opcode == 0x33:
            funct7 = (word >> 25) & 0x7F
            if funct3 == 0:
                value = _u32(a + b) if not funct7 & 0x20 else _u32(a - b)
            elif funct3 == 1:
                value = _u32(a << (b & 0x1F))
            elif funct3 == 2:
                value = int(_sext(a, 32) < _sext(b, 32))
            elif funct3 == 3:
                value = int(_u32(a) < _u32(b))
            elif funct3 == 4:
                value = _u32(a ^ b)
            elif funct3 == 5:
                if funct7 & 0x20:
                    value = _u32(_sext(a, 32) >> (b & 0x1F))
                else:
                    value = _u32(a >> (b & 0x1F))
            elif funct3 == 6:
                value = _u32(a | b)
            elif funct3 == 7:
                value = _u32(a & b)
            else:
                raise TrapProgramError('F1 trap reference: unsupported OP funct3')
        else:
            raise TrapProgramError('F1 trap reference: unsupported opcode')
        value = _u32(value)
        if rd:
            registers[rd] = value
        trace.append(dict(pc=_u32(pc), insn_word=word, rd=(rd if rd else 0),
                          wdata=(value if rd else 0), trap=False))
        pc += 4
    last_rd = 0
    last_wdata = 0
    for entry in trace:
        if entry['rd']:
            last_rd = entry['rd']
            last_wdata = entry['wdata']
    return dict(trace=trace, retired=len(trace), last_rd=last_rd,
                last_wdata=last_wdata, trap_pc=trap_at, cause=ENV_CALL_MMODE,
                mode=MODE_M, resume_pc=_u32(slot + 4), words=len(values))


def trace_hash(trace: Sequence[Mapping]) -> str:
    """FNV-1a 32 of the in-slot trace, exactly as the host computes it.

    The payload is the four 32-bit fields ``pc``, ``insn_word``, ``rd`` and
    ``wdata`` of every retirement, in order, as little-endian bytes.  It is the
    same function the entry uses for the branch/compressed traces
    (``myfuzz.fuzz.f1_program_gate.trace_hash``); this module keeps its own copy
    so the trap mode depends on nothing in the RV32 gate.
    """
    digest = 2166136261
    for entry in trace:
        for field in ('pc', 'insn_word', 'rd', 'wdata'):
            for byte in int(entry[field]).to_bytes(4, 'little'):
                digest ^= byte
                digest = (digest * 16777619) & 0xFFFFFFFF
    return 'fnv1a32:%08x' % digest


def expectation(words: Sequence[int], *, slot: int,
                data_base: int = 0) -> dict:
    """The complete per-case expectation for one declared trap record."""
    reference = reference_trace(words, slot=slot, data_base=data_base)
    reference['trace_hash'] = trace_hash(reference['trace'])
    reference['stored_cause'] = reference['cause']
    reference['stored_epc'] = reference['trap_pc']
    reference['successor_pc'] = _u32(slot + 4 * reference['words'])
    reference['intr'] = 0
    return reference
