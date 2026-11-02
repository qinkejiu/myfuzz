"""Build a small executable RV32I program from CPU profile ISA facts.

The existing ISA transducer owns instruction encodings.  This initial program
uses non-branching immediate ALU instructions with x0 as their input, so it
can execute without a pre-existing register or memory state.  It terminates in
an ordinary JAL-to-self.  Execution feedback only uses observed retirements.
"""
from dataclasses import dataclass

from .constraints import IsaContract, declared_riscv_cpu
from .transducer import RiscvInstructionTransducer


_OPS = ('ADDI', 'XORI', 'ORI', 'ANDI', 'SLTI', 'SLTIU')
_F1_OPS = ('ADDI', 'XORI', 'ORI', 'ANDI', 'SLTI', 'SLTIU',
           'ADD', 'SUB', 'SLL', 'SLT', 'SLTU', 'XOR', 'SRL', 'SRA', 'OR', 'AND',
           'SLLI', 'SRLI', 'SRAI')
_F1_M_OPS = ('MUL', 'MULH', 'MULHSU', 'MULHU', 'DIV', 'DIVU', 'REM', 'REMU')
_F1_C_OPS = ('C.ADDI', 'C.LI', 'C.SUB', 'C.XOR', 'C.OR', 'C.AND', 'C.SLLI',
             'C.SRLI', 'C.SRAI', 'C.ANDI', 'C.MV', 'C.ADD', 'C.LUI')


def _require_rv32i(profile):
    cpu = profile.cpu
    if (not declared_riscv_cpu(cpu) or cpu.xlen != 32
            or 'I' not in {x.upper() for x in cpu.extensions}):
        raise ValueError('RV32I CPU profile required')


def build_ram_dataflow_records(profile, entropy):
    """Schedule real F3 stores followed by F1 reads of the shared RAM scratch.

    The runtime's typed lowerer resolves and bounds the scratch address from
    the actual declared RAM binding. No memory or CPU state is simulated here.
    """
    _require_rv32i(profile)
    if type(entropy) is not bytes or not entropy or len(entropy) % 4:
        raise ValueError('one or more four-byte data records required')
    from myfuzz.runtime.flows.memory import RAM_READ_TOKEN
    records = []
    for offset in range(0, len(entropy), 4):
        records.extend(('F3:' + entropy[offset:offset + 4].hex(), 'F1:' + RAM_READ_TOKEN.hex()))
    return {'schema_version': 'profile_ram_dataflow_records.v1', 'entropy_hex': entropy.hex(),
            'records': records, 'retirement': 'unknown', 'ram_address': 'resolved-from-declared-runtime-window'}


def build_f1_records(profile, entropy, *, register_dependencies=False, enable_m=False, enable_c=False):
    """Generate existing F1 records without touching shared firmware registers.

    Each input record selects an admitted straight-line instruction, x12..x15,
    and a 12-bit immediate. When dependencies are enabled, bits 6 and 7 of the
    register byte select x12..x15 as source registers; bits 2..3 and 4..5
    choose the respective registers. Otherwise both sources remain x0. Both
    entropy and encoded records are returned for replay.
    """
    _require_rv32i(profile)
    if type(entropy) is not bytes or not entropy or len(entropy) % 4:
        raise ValueError('one or more four-byte instruction records required')
    if any(type(flag) is not bool for flag in (register_dependencies, enable_m, enable_c)):
        raise ValueError('instruction generation options must be boolean')
    if enable_m and 'M' not in {x.upper() for x in profile.cpu.extensions}:
        raise ValueError('CPU profile must declare M extension')
    if enable_c and 'C' not in {x.upper() for x in profile.cpu.extensions}:
        raise ValueError('CPU profile must declare C extension')
    if enable_c:
        if enable_m or register_dependencies:
            raise ValueError('C pair mode cannot combine with M or register-dependencies options')
        transducer = RiscvInstructionTransducer(IsaContract(32, ('I', 'C'), instruction_alignment=2))
        records = []
        for offset in range(0, len(entropy), 4):
            code = bytearray()
            for part in (0, 2):
                selector, value = entropy[offset + part:offset + part + 2]
                operation = _F1_C_OPS[selector % len(_F1_C_OPS)]
                rd = 12 + (selector >> 1 & 3)
                immediate = value & 63
                if operation in ('C.SUB', 'C.XOR', 'C.OR', 'C.AND'):
                    payload = (rd - 8) << 7 | (4 + (value & 3)) << 2
                elif operation in ('C.SRLI', 'C.SRAI', 'C.ANDI'):
                    payload = (rd - 8) << 7 | (immediate & 31) << 2 | (immediate & 32) << 7
                elif operation in ('C.MV', 'C.ADD'):
                    payload = rd << 7 | (12 + (value & 3)) << 2
                else:
                    payload = rd << 7 | (immediate & 31) << 2 | (immediate & 32) << 7
                choice = transducer.repair_for_operation(operation, payload)
                code.extend(choice.word.to_bytes(2, 'little'))
            records.append('F1:' + code.hex())
        return {'schema_version': 'profile_f1_records.v1', 'entropy_hex': entropy.hex(),
                'records': records, 'retirement': 'unknown', 'extensions_enabled': ['C'],
                'runtime_admission': 'requires-bound-rv32ic-profile'}
    transducer = RiscvInstructionTransducer(IsaContract(32, ('I', 'M') if enable_m else ('I',)))
    operations = _F1_OPS + _F1_M_OPS if enable_m else _F1_OPS
    records = []
    generated_m = False
    for offset in range(0, len(entropy), 4):
        selector, reg, lo, hi = entropy[offset:offset + 4]
        operation = operations[selector % len(operations)]
        generated_m |= operation in _F1_M_OPS
        payload = (12 + reg % 4) << 7
        if register_dependencies and reg & 0x40:
            payload |= (12 + (reg >> 2 & 3)) << 15
        if operation in _F1_OPS[:6]:
            payload |= ((lo | hi << 8) & 0xfff) << 20
        elif operation in ('SLLI', 'SRLI', 'SRAI'):
            payload |= (lo & 31) << 20
        elif register_dependencies and reg & 0x80:
            payload |= (12 + (reg >> 4 & 3)) << 20
        choice = transducer.repair_for_operation(operation, payload)
        records.append('F1:' + choice.word.to_bytes(4, 'little').hex())
    result = {'schema_version': 'profile_f1_records.v1', 'entropy_hex': entropy.hex(),
              'records': records, 'retirement': 'unknown'}
    if register_dependencies:
        result['register_dependencies'] = True
    if enable_m:
        result['extensions_enabled'] = ['M']
        result['runtime_admission'] = ('requires-bound-rv32im-profile' if generated_m
                                       else 'not_checked')
    return result


@dataclass(frozen=True)
class ProgramInstruction:
    address: int
    operation: str
    word: int
    rd: int
    expected: int
    next_pc: int | None = None


@dataclass(frozen=True)
class AluProgram:
    base: int
    code: bytes
    instructions: tuple[ProgramInstruction, ...]


@dataclass(frozen=True)
class FlowProgram(AluProgram):
    scratch_address: int
    scratch_value: int
    skipped_addresses: tuple[int, ...]


def build_flow_suite_program(profile, *, base):
    """Run real RV32I control flow and byte/word accesses in one RAM page."""
    _require_rv32i(profile)
    if type(base) is not int or base < 0 or base % 4 or (base & 0xfff) + 0x304 > 0x1000 or base + 0x304 > 1 << 32:
        raise ValueError('aligned RV32 program with in-page RAM scratch required')
    transducer = RiscvInstructionTransducer(IsaContract(32, ('I',)))
    # offset, mnemonic, free bits, rd, expected rd, next-PC offset
    rows = [
        (0x00, 'AUIPC', 1 << 7, 1, base, 0x04),
        (0x04, 'ADDI', 1 << 7 | 1 << 15 | 0x300 << 20, 1, base + 0x300, 0x08),
        (0x08, 'ADDI', 2 << 7 | 0xfff << 20, 2, 0xffffffff, 0x0c),
        (0x0c, 'SW', 1 << 15 | 2 << 20, 0, 0, 0x10),
        (0x10, 'LW', 3 << 7 | 1 << 15, 3, 0xffffffff, 0x14),
        (0x14, 'LBU', 4 << 7 | 1 << 15 | 1 << 20, 4, 0xff, 0x18),
        (0x18, 'BEQ', 3 << 15 | 2 << 20 | 8 << 7, 0, 0, 0x20),
        (0x20, 'ADDI', 5 << 7 | 7 << 20, 5, 7, 0x24),
        (0x24, 'BNE', 3 << 15 | 2 << 20 | 8 << 7, 0, 0, 0x28),
        (0x28, 'JAL', 6 << 7 | 8 << 20, 6, base + 0x2c, 0x30),
        (0x30, 'ADDI', 7 << 7 | 9 << 20, 7, 9, 0x34),
        (0x34, 'AUIPC', 8 << 7, 8, base + 0x34, 0x38),
        (0x38, 'JALR', 9 << 7 | 8 << 15 | 12 << 20, 9, base + 0x3c, 0x40),
        (0x40, 'LB', 10 << 7 | 1 << 15 | 1 << 20, 10, 0xffffffff, 0x44),
        (0x44, 'SB', 1 << 15 | 5 << 20 | 1 << 7, 0, 0, 0x48),
        (0x48, 'LHU', 11 << 7 | 1 << 15, 11, 0x7ff, 0x4c),
    ]
    code = bytearray(bytes.fromhex('13000000') * 19)
    instructions = []
    for offset, operation, payload, rd, expected, target in rows:
        word = transducer.repair_for_operation(operation, payload).word
        code[offset:offset + 4] = word.to_bytes(4, 'little')
        instructions.append(ProgramInstruction(base + offset, operation, word, rd, expected, base + target))
    return FlowProgram(base, bytes(code) + bytes.fromhex('6f000000'), tuple(instructions),
                       base + 0x300, 0xffff07ff, tuple(base + i for i in (0x1c, 0x2c, 0x3c)))


def build_c_suite_program(profile, *, base):
    """Run every admitted RV32C ALU kind with dependent register results.

    Build the halfwords through the same F1 profile generator used by the
    shared flow, then check each retirement with the existing CPU collector.
    """
    _require_rv32i(profile)
    if 'C' not in {x.upper() for x in profile.cpu.extensions}:
        raise ValueError('CPU profile must declare C extension')
    if type(base) is not int or base < 0 or base % 4 or base + 32 > 1 << 32:
        raise ValueError('aligned RV32 program address required')
    # operation, destination, entropy operand, expected value
    cases = [('C.LI', 12, 7, 7), ('C.LI', 13, 3, 3),
        ('C.ADDI', 12, 1, 8), ('C.SUB', 12, 1, 5),
        ('C.XOR', 12, 1, 6), ('C.OR', 12, 1, 7),
        ('C.AND', 12, 1, 3), ('C.SLLI', 12, 2, 12),
        ('C.SRLI', 12, 1, 6), ('C.SRAI', 12, 1, 3),
        ('C.ANDI', 12, 1, 1), ('C.MV', 14, 1, 3),
        ('C.ADD', 14, 0, 4), ('C.LUI', 15, 1, 4096)]
    entropy = bytearray()
    for operation, rd, value, _ in cases:
        selector = next(i for i in range(256)
                        if _F1_C_OPS[i % len(_F1_C_OPS)] == operation
                        and 12 + (i >> 1 & 3) == rd)
        entropy.extend((selector, value))
    records = build_f1_records(profile, bytes(entropy), enable_c=True)['records']
    raw = b''.join(bytes.fromhex(record[3:]) for record in records)
    instructions = tuple(ProgramInstruction(base + 2 * index, operation,
        int.from_bytes(raw[2 * index:2 * index + 2], 'little'), rd, expected)
        for index, (operation, rd, _, expected) in enumerate(cases))
    return AluProgram(base, raw + bytes.fromhex('6f000000'), instructions)


def build_m_suite_program(profile, *, base):
    """Exercise RV32M with signed operands and division by zero on the DUT.

    Expectations are architectural results for 7 and -3; the transducer
    supplies encodings and the existing retirement collector checks the CPU.
    """
    _require_rv32i(profile)
    if 'M' not in {x.upper() for x in profile.cpu.extensions}:
        raise ValueError('CPU profile must declare M extension')
    if type(base) is not int or base < 0 or base % 4 or base + 52 > 1 << 32:
        raise ValueError('aligned RV32 program address required')
    transducer = RiscvInstructionTransducer(IsaContract(32, ('I', 'M')))
    cases = [('ADDI', 1, 0, 0, 7, 7), ('ADDI', 2, 0, 0, -3, 0xfffffffd)]
    cases += [(name, rd, 1, rs2, 0, result) for name, rd, rs2, result in (
        ('MUL', 3, 2, 0xffffffeb), ('MULH', 4, 2, 0xffffffff),
        ('MULHSU', 5, 2, 6), ('MULHU', 6, 2, 6),
        ('DIV', 7, 2, 0xfffffffe), ('DIVU', 8, 2, 0),
        ('REM', 9, 2, 1), ('REMU', 10, 2, 7),
        ('DIV', 11, 0, 0xffffffff), ('REM', 12, 0, 7))]
    instructions = []
    for operation, rd, rs1, rs2, immediate, expected in cases:
        payload = rd << 7 | rs1 << 15
        payload |= ((immediate & 0xfff) if operation == 'ADDI' else rs2) << 20
        choice = transducer.repair_for_operation(operation, payload)
        instructions.append(ProgramInstruction(base + 4 * len(instructions), operation,
                                               choice.word, rd, expected))
    code = b''.join(i.word.to_bytes(4, 'little') for i in instructions) + bytes.fromhex('6f000000')
    return AluProgram(base, code, tuple(instructions))


def build_alu_program(profile, records, *, base):
    """Use one 4-byte input per instruction on a declared RV32I CPU profile."""
    _require_rv32i(profile)
    if type(records) is not bytes or not records or len(records) % 4:
        raise ValueError('one or more four-byte instruction records required')
    if type(base) is not int or base < 0 or base % 4 or base + len(records) + 4 > 1 << 32:
        raise ValueError('aligned RV32 program address required')
    transducer = RiscvInstructionTransducer(IsaContract(32, ('I',)))
    words = []
    for offset in range(0, len(records), 4):
        selector, reg, lo, hi = records[offset:offset + 4]
        operation = _OPS[selector % len(_OPS)]
        rd = 1 + reg % 15
        imm = (lo | hi << 8) & 0xfff
        signed = imm - 4096 if imm & 0x800 else imm
        payload = imm << 20 | rd << 7
        choice = transducer.repair_for_operation(operation, payload)
        expected = {
            'ADDI': signed & 0xffffffff, 'XORI': signed & 0xffffffff,
            'ORI': signed & 0xffffffff, 'ANDI': 0,
            'SLTI': int(0 < signed), 'SLTIU': int(0 < (signed & 0xffffffff)),
        }[operation]
        words.append(ProgramInstruction(base + offset, operation, choice.word, rd, expected))
    code = b''.join(item.word.to_bytes(4, 'little') for item in words) + bytes.fromhex('6f000000')
    return AluProgram(base, code, tuple(words))


def collect_retirements(program, events):
    """Join actual CPU retirement observations by instruction address and word.

    A fetch is not a retirement. Missing RVFI result fields remain unobserved;
    this is not a claim that an unattached observation provider is authentic.
    """
    rows = []
    for instruction in program.instructions:
        matches = [event for event in events if event.get('kind') == 'cpu_retire'
                   and event.get('pc_rdata') == instruction.address]
        if not matches:
            rows.append({'address': instruction.address, 'status': 'unobserved', 'result_status': 'unobserved'})
            continue
        if len(matches) != 1:
            rows.append({'address': instruction.address, 'status': 'mismatch', 'reason': 'duplicate-retirement'})
            continue
        event = matches[0]
        if event.get('insn') != instruction.word:
            rows.append({'address': instruction.address, 'status': 'mismatch', 'reason': 'instruction-mismatch'})
            continue
        fields = ('trap', 'rd_addr', 'rd_wdata')
        if any(key not in event or event[key] is None for key in fields):
            rows.append({'address': instruction.address, 'status': 'observed', 'result_status': 'unobserved', 'order': event.get('order')})
            continue
        if instruction.next_pc is not None and event.get('pc_wdata') is None:
            rows.append({'address': instruction.address, 'status': 'observed',
                         'result_status': 'unobserved', 'order': event.get('order')})
            continue
        ok = (event['trap'] == 0 and event['rd_addr'] == instruction.rd
              and event['rd_wdata'] == instruction.expected
              and (instruction.next_pc is None or event['pc_wdata'] == instruction.next_pc))
        rows.append({'address': instruction.address, 'status': 'observed' if ok else 'mismatch',
                     'result_status': 'matched' if ok else 'mismatch', 'order': event.get('order'),
                     'observed_rd': event['rd_addr'], 'observed_value': event['rd_wdata']})
    skipped = getattr(program, 'skipped_addresses', ())
    unexpected = [e['pc_rdata'] for e in events if e.get('kind') == 'cpu_retire' and e.get('pc_rdata') in skipped]
    orders = [row.get('order') for row in rows if row.get('status') == 'observed']
    bad_order = bool(skipped) and any(type(order) is not int for order in orders)
    bad_order |= bool(skipped) and any(a >= b for a, b in zip(orders, orders[1:]))
    if unexpected or bad_order or any(row['status'] == 'mismatch' for row in rows): status = 'mismatch'
    elif all(row['status'] == 'unobserved' for row in rows): status = 'unobserved'
    elif all(row.get('result_status') == 'matched' for row in rows): status = 'verified'
    else: status = 'partial'
    result = {'status': status, 'instructions': rows}
    if skipped:
        result['unexpected_retirements'] = unexpected
    return result
