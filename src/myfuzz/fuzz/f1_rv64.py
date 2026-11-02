"""A declared RV64I F1 program mode for a 64-bit CPU (CVA6 packed AXI4).

The historical F1 subset is RV32 (or an explicitly declared low-32 projection
of an RV64 core's records).  This module is the *separate* RV64 mode: the slot
program is real RV64I, executed by the core at its own width, and every value
this module states is 64-bit.

The admitted subset is intentionally small and straight-line:

=====================  =====================================================
group                  instructions
=====================  =====================================================
upper immediate        ``LUI``
I-type ALU             ``ADDI``
R-type ALU             ``ADD``, ``SUB``, ``AND``, ``OR``, ``XOR``
word ALU (RV64)        ``ADDIW``, ``ADDW``, ``SLLIW``, ``SRLIW``, ``SRAIW``
doubleword memory      ``LD``, ``SD`` against ``x18`` in the declared window
=====================  =====================================================

No branch, jump, CSR, system, compressed, floating-point or atomic word is
admitted, and no register the firmware set before the jump (x8 mailbox, x18
data-window base, x9 reserved) may be written.  A word may read a register only
if this same program wrote it earlier, or if it is x0/x18, so the reference
trace never depends on firmware state the declaration cannot state.

The reference trace is ``(pc, insn_word, rd, wdata)`` per retirement with 64-bit
``pc``/``wdata``, hashed with **FNV-1a 64** over the four fields as 8-byte
little-endian values (``trace_hash64``).  The host computes the same digest from
its own RVFI retirement stream (``f1_trace64`` in
``scripts/inprocess_obi_apb_f1f4_spike.cpp``); the 32-bit digest of the RV32 gate
is never used here.  A store retires with ``rd = 0`` and ``wdata = 0``, which is
RVFI's own rule for a retirement that writes no register, so the reference trace
and the host's hash are the same projection.

The module is isolated: it imports nothing from ``scripts``, performs no I/O and
states no RTL result.  It also carries the small generator the RV64 fixed-case
batch uses, so the ten generated programs are legal by construction and every
one of them is validated again before it is submitted.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF
#: Registers the firmware owns before the slot program runs.  x8 is the mailbox
#: pointer, x18 the declared data-window base; x9 is reserved by the host gate.
RESERVED_DESTINATIONS = frozenset((8, 9, 18))
#: Opcodes this subset admits, by name (documentation and validation).
SUBSET = ('LUI', 'ADDI', 'ADD', 'SUB', 'AND', 'OR', 'XOR',
          'ADDIW', 'ADDW', 'SLLIW', 'SRLIW', 'SRAIW', 'LD', 'SD')
_FNV64_OFFSET = 14695981039346656037
_FNV64_PRIME = 1099511628211


class Rv64ProgramError(ValueError):
    """A submitted F1 RV64 record is not legal for this mode."""


def _sext(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value & (sign - 1)) - (value & sign)


def _u64(value: int) -> int:
    return value & MASK64


def _sext32(value: int) -> int:
    return _sext(value & MASK32, 32)


def _decode(word: int) -> dict:
    """Decode one admitted word, or raise :class:`Rv64ProgramError`."""
    word &= MASK32
    if (word & 3) != 3:
        raise Rv64ProgramError('not one 32-bit instruction: 0x%08x' % word)
    opcode = word & 0x7F
    rd = (word >> 7) & 31
    funct3 = (word >> 12) & 7
    rs1 = (word >> 15) & 31
    rs2 = (word >> 20) & 31
    funct7 = (word >> 25) & 0x7F
    shamt5 = (word >> 20) & 0x1F
    imm_i = _sext((word >> 20) & 0xFFF, 12)
    imm_s = _sext((((word >> 25) & 0x7F) << 5) | ((word >> 7) & 0x1F), 12)
    if opcode == 0x37:                                  # LUI
        return dict(name='LUI', rd=rd, imm=(word & 0xFFFFF000))
    if opcode == 0x13 and funct3 == 0:                  # ADDI
        return dict(name='ADDI', rd=rd, rs1=rs1, imm=imm_i, wide=True)
    if opcode == 0x1B and funct3 == 0:                  # ADDIW
        return dict(name='ADDIW', rd=rd, rs1=rs1, imm=imm_i, wide=False)
    if opcode == 0x33 and funct7 == 0 and funct3 == 0:  # ADD
        return dict(name='ADD', rd=rd, rs1=rs1, rs2=rs2, wide=True)
    if opcode == 0x33 and funct7 == 0x20 and funct3 == 0:  # SUB
        return dict(name='SUB', rd=rd, rs1=rs1, rs2=rs2, wide=True)
    if opcode == 0x33 and funct7 == 0 and funct3 == 7:  # AND
        return dict(name='AND', rd=rd, rs1=rs1, rs2=rs2, wide=True)
    if opcode == 0x33 and funct7 == 0 and funct3 == 6:  # OR
        return dict(name='OR', rd=rd, rs1=rs1, rs2=rs2, wide=True)
    if opcode == 0x33 and funct7 == 0 and funct3 == 4:  # XOR
        return dict(name='XOR', rd=rd, rs1=rs1, rs2=rs2, wide=True)
    if opcode == 0x3B and funct7 == 0 and funct3 == 0:  # ADDW
        return dict(name='ADDW', rd=rd, rs1=rs1, rs2=rs2, wide=False)
    if opcode == 0x1B and funct3 == 1 and funct7 == 0:  # SLLIW
        return dict(name='SLLIW', rd=rd, rs1=rs1, shamt=shamt5, wide=False)
    if opcode == 0x1B and funct3 == 5 and funct7 == 0:  # SRLIW
        return dict(name='SRLIW', rd=rd, rs1=rs1, shamt=shamt5, wide=False)
    if opcode == 0x1B and funct3 == 5 and funct7 == 0x20:  # SRAIW
        return dict(name='SRAIW', rd=rd, rs1=rs1, shamt=shamt5, wide=False)
    if opcode == 0x03 and funct3 == 3:                  # LD
        return dict(name='LD', rd=rd, rs1=rs1, imm=imm_i, memory='load')
    if opcode == 0x23 and funct3 == 3:                  # SD
        return dict(name='SD', rd=0, rs1=rs1, rs2=rs2, imm=imm_s,
                    memory='store')
    raise Rv64ProgramError(
        'instruction 0x%08x is outside the declared RV64I subset (%s)'
        % (word, ', '.join(SUBSET)))


def _read_registers(decoded: Mapping) -> tuple:
    if decoded['name'] == 'LUI':
        return ()
    if decoded.get('memory') == 'store':
        return (decoded['rs1'], decoded['rs2'])
    if 'rs2' in decoded:
        return (decoded['rs1'], decoded['rs2'])
    return (decoded['rs1'],)


def validate_rv64_record(record: object, *, max_words: int = 16,
                         window_bytes: int = 64) -> list[int]:
    """Raise :class:`Rv64ProgramError` unless ``record`` is legal here.

    ``record`` is an entry record (``{"flow": "F1", "fields": (...)}``) or a
    plain word sequence.  The rules are the module's own: the admitted subset,
    the reserved destinations, the read-after-write discipline and the
    declared data window for LD/SD (``x18`` base, 8-byte aligned, inside it).
    """
    words = _record_words(record)
    if not words:
        raise Rv64ProgramError('F1 RV64 program is empty')
    if len(words) > max_words:
        raise Rv64ProgramError(
            'F1 RV64 program has %d words; the scenario declares at most %d'
            % (len(words), max_words))
    written = {0}
    for index, word in enumerate(words):
        decoded = _decode(word)
        if decoded['name'] in ('LD', 'SD'):
            if decoded['rs1'] != 18:
                raise Rv64ProgramError(
                    'F1 RV64 memory word %d must use x18, the declared '
                    'data-window base' % index)
            offset = decoded['imm']
            if offset < 0 or offset % 8 or offset > window_bytes - 8:
                raise Rv64ProgramError(
                    'F1 RV64 memory word %d offset %d is not an 8-byte aligned '
                    'word inside the declared data window' % (index, offset))
        for source in _read_registers(decoded):
            if source not in written and source not in (0, 18):
                raise Rv64ProgramError(
                    'F1 RV64 word %d reads x%d before this program wrote it; '
                    'the reference trace would depend on firmware state'
                    % (index, source))
        rd = decoded['rd']
        if rd in RESERVED_DESTINATIONS:
            raise Rv64ProgramError(
                'F1 RV64 word %d writes x%d, a reserved register' % (index, rd))
        if rd:
            written.add(rd)
    return [word & MASK32 for word in words]


def _record_words(record: object) -> list[int]:
    if isinstance(record, Mapping):
        fields = record.get('fields')
        if fields is None:
            raise Rv64ProgramError('an F1 RV64 record carries no words')
        return [int(word) & MASK32 for word in fields]
    if hasattr(record, 'words'):
        return [int(word) & MASK32 for word in record.words]
    return [int(word) & MASK32 for word in record]


def _execute(words: Sequence[int], *, slot: int, data_base: int,
             memory: Mapping[int, int] | None) -> dict:
    registers = {0: 0, 18: data_base & MASK64}
    memory = dict(memory or {})
    trace = []
    pc = slot & MASK64
    for index, word in enumerate(words):
        decoded = _decode(word)
        name = decoded['name']
        rd = decoded['rd']
        value = 0
        if name == 'LUI':
            value = _u64(_sext(decoded['imm'] & MASK32, 32))
        elif name in ('ADDI', 'ADDIW'):
            value = _u64(registers.get(decoded['rs1'], 0) + decoded['imm'])
            if name == 'ADDIW':
                value = _u64(_sext32(value))
        else:
            a = registers.get(decoded.get('rs1'), 0)
            if name == 'LD':
                address = _u64(a + decoded['imm'])
                if address % 8:
                    raise Rv64ProgramError('LD address is not 8-byte aligned')
                value = _u64(memory.get(address, 0))
            elif name == 'SD':
                address = _u64(a + decoded['imm'])
                if address % 8:
                    raise Rv64ProgramError('SD address is not 8-byte aligned')
                memory[address] = _u64(registers.get(decoded['rs2'], 0))
            else:
                b = registers.get(decoded.get('rs2'), 0)
                if name == 'ADD':
                    value = _u64(a + b)
                elif name == 'SUB':
                    value = _u64(a - b)
                elif name == 'AND':
                    value = _u64(a & b)
                elif name == 'OR':
                    value = _u64(a | b)
                elif name == 'XOR':
                    value = _u64(a ^ b)
                elif name == 'ADDW':
                    value = _u64(_sext32(a + b))
                elif name == 'SLLIW':
                    value = _u64(_sext32(a << decoded['shamt']))
                elif name == 'SRLIW':
                    value = _u64(_sext32((a & MASK32) >> decoded['shamt']))
                elif name == 'SRAIW':
                    value = _u64(_sext32(_sext32(a) >> decoded['shamt']))
                else:  # pragma: no cover - _decode admits nothing else
                    raise Rv64ProgramError('unsupported subset word ' + name)
        if name == 'SD':
            trace.append(dict(pc=pc, insn_word=word & MASK32, rd=0, wdata=0))
        else:
            if rd:
                registers[rd] = value
            trace.append(dict(pc=pc, insn_word=word & MASK32, rd=rd,
                              wdata=(value if rd else 0)))
        pc = _u64(pc + 4)
    last_rd = 0
    last_wdata = 0
    last_pc = 0
    for entry in trace:
        if entry['rd']:
            last_rd = entry['rd']
            last_wdata = entry['wdata']
            last_pc = entry['pc']
    return dict(trace=trace, retired=len(trace), last_rd=last_rd,
                last_wdata=last_wdata, last_pc=last_pc,
                registers={reg: value for reg, value in registers.items()
                           if reg not in (0,)},
                memory=memory, words=len(words))


def trace_hash64(trace: Sequence[Mapping]) -> str:
    """FNV-1a 64 of one trace, exactly as the host's ``f1_trace64`` computes it.

    The payload is, for every retirement in order, the four fields ``pc``,
    ``insn_word``, ``rd`` and ``wdata`` as 8-byte little-endian values.
    """
    digest = _FNV64_OFFSET
    for entry in trace:
        for field in ('pc', 'insn_word', 'rd', 'wdata'):
            value = int(entry[field]) & MASK64
            for byte in value.to_bytes(8, 'little'):
                digest ^= byte
                digest = (digest * _FNV64_PRIME) & MASK64
    return 'fnv1a64:%016x' % digest


def _window_memory(window: Sequence[int], data_base: int) -> dict:
    """The declared 32-bit data words as the 8-byte memory the subset loads."""
    memory = {}
    for index in range(0, len(window) - 1, 2):
        low = int(window[index]) & MASK32
        high = int(window[index + 1]) & MASK32
        memory[data_base + 4 * index] = (low | (high << 32)) & MASK64
    return memory


def expectation(words: Sequence[int], *, slot: int, data_base: int,
                window: Sequence[int]) -> dict:
    """The complete per-case expectation for one legal RV64 record.

    ``window`` is the declared data window as the host printed it immediately
    before the case (``prog_data_0..N``); SD writes are compared against it, so
    the after-sample is a real store witness.
    """
    validate_rv64_record(words, max_words=len(words), window_bytes=4 * len(window))
    executed = _execute(words, slot=slot, data_base=data_base,
                        memory=_window_memory(window, data_base))
    final = list(int(value) & MASK32 for value in window)
    for address, value in executed['memory'].items():
        offset = address - data_base
        if 0 <= offset < 4 * len(final) and offset % 4 == 0:
            final[offset // 4] = value & MASK32
            if offset // 4 + 1 < len(final):
                final[offset // 4 + 1] = (value >> 32) & MASK32
    changed = sum(1 for before, after in zip(window, final) if before != after)
    return dict(trace=executed['trace'], retired=executed['retired'],
                trace_hash=trace_hash64(executed['trace']),
                last_rd=executed['last_rd'], last_wdata=executed['last_wdata'],
                last_pc=executed['last_pc'], window_after=final,
                window_changed=changed, words=len(words))


# ---------------------------------------------------------------------------
# The small generator the RV64 fixed-case batch uses
# ---------------------------------------------------------------------------

_ALU_NAMES = ('ADDI', 'ADD', 'SUB', 'AND', 'OR', 'XOR',
              'ADDIW', 'ADDW', 'SLLIW', 'SRLIW', 'SRAIW')
_TEMP_REGISTERS = (5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 19, 20, 21)
_IMMEDIATES = (1, 2, 3, 7, 0x1F, -1, -2, 0x2AB, 0x7FF, -0x800)


def _encode(decoded: Mapping) -> int:
    """Encode one subset instruction (the inverse of :func:`_decode`)."""
    name = decoded['name']
    rd = decoded.get('rd', 0)
    rs1 = decoded.get('rs1', 0)
    rs2 = decoded.get('rs2', 0)
    imm = decoded.get('imm', 0)
    if name == 'LUI':
        return ((imm & 0xFFFFF000) | (rd << 7) | 0x37) & MASK32
    if name in ('ADDI', 'ADDIW'):
        opcode = 0x13 if name == 'ADDI' else 0x1B
        return (((imm & 0xFFF) << 20) | (rs1 << 15) | (rd << 7) | opcode) & MASK32
    if name in ('ADD', 'SUB', 'AND', 'OR', 'XOR'):
        funct3 = {'ADD': 0, 'SUB': 0, 'AND': 7, 'OR': 6, 'XOR': 4}[name]
        funct7 = 0x20 if name == 'SUB' else 0
        return ((funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12)
                | (rd << 7) | 0x33) & MASK32
    if name == 'ADDW':
        return ((rs2 << 20) | (rs1 << 15) | (rd << 7) | 0x3B) & MASK32
    if name in ('SLLIW', 'SRLIW', 'SRAIW'):
        funct7 = 0x20 if name == 'SRAIW' else 0
        funct3 = 1 if name == 'SLLIW' else 5
        shamt = decoded.get('shamt', 0) & 0x1F
        return ((funct7 << 25) | (shamt << 20) | (rs1 << 15) | (funct3 << 12)
                | (rd << 7) | 0x1B) & MASK32
    if name == 'LD':
        return (((imm & 0xFFF) << 20) | (rs1 << 15) | (3 << 12)
                | (rd << 7) | 0x03) & MASK32
    if name == 'SD':
        return ((((imm >> 5) & 0x7F) << 25) | (rs2 << 20) | (rs1 << 15)
                | (3 << 12) | ((imm & 0x1F) << 7) | 0x23) & MASK32
    raise Rv64ProgramError('cannot encode ' + name)


def generate_program(seed: int, *, max_words: int = 2,
                     window_bytes: int = 64) -> list[int]:
    """One legal, trace-deterministic RV64I program.

    The first word writes a fresh temporary (``LUI`` or ``ADDI`` from x0), and
    every later word reads only registers this program wrote or x0/x18, so the
    reference trace is decided by the declared state.  ``seed`` selects the
    words; the caller validates the result again with
    :func:`validate_rv64_record`.
    """
    import random

    rng = random.Random(seed)
    words: list[int] = []
    written: list[int] = []
    rd = rng.choice(_TEMP_REGISTERS)
    words.append(_encode(dict(name='LUI', rd=rd,
                              imm=rng.choice((0x1, 0x2AB, 0x12345, 0x7FFFF)))))
    written.append(rd)
    while len(words) < max_words:
        kind = rng.random()
        if kind < 0.18 and len(written) >= 2:
            offset = 8 * rng.randrange(window_bytes // 8)
            target = rng.choice(written)
            words.append(_encode(dict(name='SD', rs1=18, rs2=target, imm=offset)))
            continue
        if kind < 0.30:
            offset = 8 * rng.randrange(window_bytes // 8)
            rd = rng.choice([reg for reg in _TEMP_REGISTERS if reg not in written]
                            or _TEMP_REGISTERS)
            words.append(_encode(dict(name='LD', rd=rd, rs1=18, imm=offset)))
            if rd not in written:
                written.append(rd)
            continue
        rd = rng.choice(written)
        name = rng.choice(_ALU_NAMES)
        if name in ('ADDI', 'ADDIW'):
            words.append(_encode(dict(name=name, rd=rd, rs1=rd,
                                      imm=rng.choice(_IMMEDIATES))))
        elif name in ('SLLIW', 'SRLIW', 'SRAIW'):
            words.append(_encode(dict(name=name, rd=rd, rs1=rd,
                                      shamt=rng.randrange(1, 32))))
        else:
            source = rng.choice(written + [18])
            words.append(_encode(dict(name=name, rd=rd, rs1=rd, rs2=source)))
    return words


def validate_rv64_program_record(record: object, **kwargs) -> None:
    """Compatibility alias: the entry's one record gate for this mode."""
    validate_rv64_record(record, **kwargs)
