"""Independent RV32I shift-immediate retirement witness tests.

SLLI/SRLI/SRAI are OP-IMM forms: opcode 0x13, funct3 1 (SLLI) or 5
(SRLI/SRAI), shamt in insn[24:20], and the reserved funct7 = insn[31:25] must
be exactly zero for SLLI/SRLI and exactly 0b0100000 for SRAI. Every word here
is assembled field by field from those ISA facts (``_itype``) and, where the
published P4 encoder gold standard also pins it, asserted again as that
literal hex constant (``tests/scenario/test_rv32i_shift_operators.py``), so a
decoder bug cannot agree with itself.

A shift-imm writes only registers, so its retirement must never claim or
consume a pending data beat, and the pinned Ibex stale LSU masks on
non-memory retirement must not be read as a memory effect.
"""
import copy
import unittest

from myfuzz.scenario.cpu_retirement import CpuRetirementMatcher

SCOPE = dict(execution_id='run', source_component='cpu', source_epoch=0)
OP_IMM = 0x13
SRA_RESERVED = 0b0100000
SW = 0x0020a023

#: The accepted non-memory witness schema, pinned so a shift certificate is
#: exactly as strong as the already certified XORI/ADDI/LUI certificate.
WITNESS_FIELDS = ('byte_cells', 'cpu_scope', 'insn', 'instruction_origin_status',
                  'instruction_responses', 'order', 'pc', 'proof_scope', 'reason',
                  'schema_version', 'source_refs', 'status', 'transaction_keys')


def key(seq, channel='data', case='A', epoch=0):
    return dict(SCOPE, source_epoch=epoch, testcase_id=case, channel_id=channel,
                source_sequence=seq)


def fetch(insn, writer='online-shift', seq=1, pc=0x100, epoch=0):
    return dict(kind='instr_response', transaction=key(seq, 'instr', epoch=epoch),
                address=pc, error=0, rdata=insn, snapshot=dict(address=pc, value=insn,
                data_hex=insn.to_bytes(4, 'little').hex(), versions=((0, seq),)*4,
                writer_event_ids=(writer,)*4, writer_kinds=('INSTRUCTION_SOURCE',)*4))


def shift_word(operation, rd, rs1, shamt, *, funct3=None, reserved=None):
    """Assemble one OP-IMM word from raw fields; no legality check is applied."""
    if funct3 is None:
        funct3 = 1 if operation == 'SLLI' else 5
    if reserved is None:
        reserved = SRA_RESERVED if operation == 'SRAI' else 0
    return (((reserved << 5) | (shamt & 31)) << 20) | (rs1 << 15) | \
        (funct3 << 12) | (rd << 7) | OP_IMM


def shift_result(operation, rs1_rdata, shamt):
    """The ISA result, computed here without importing production helpers."""
    value = rs1_rdata & 0xffffffff
    if operation == 'SLLI':
        return (value << shamt) & 0xffffffff
    if operation == 'SRLI':
        return value >> shamt
    signed = value - (1 << 32) if value & 0x80000000 else value
    return (signed >> shamt) & 0xffffffff


def decode(word):
    """Recover the OP-IMM fields independently, bit by bit."""
    return dict(opcode=word & 0x7f, funct3=(word >> 12) & 7,
                funct7=(word >> 25) & 0x7f, shamt=(word >> 20) & 31,
                rs1=(word >> 15) & 31, rd=(word >> 7) & 31)


def retire(insn, *, order=0, pc=0x100, rs1_addr=0, rs1_rdata=0, rs2_addr=0,
           rs2_rdata=0, rd_addr=0, rd_wdata=0, trap=0, valid=1, epoch=0,
           mem_addr=0, mem_rmask=0, mem_wmask=0, mem_rdata=0, mem_wdata=0):
    return dict(SCOPE, source_epoch=epoch, kind='cpu_retire', order=order,
                pc_rdata=pc, insn=insn, valid=valid, trap=trap, intr=0,
                rs1_addr=rs1_addr, rs1_rdata=rs1_rdata, rs2_addr=rs2_addr,
                rs2_rdata=rs2_rdata, rd_addr=rd_addr, rd_wdata=rd_wdata,
                mem_addr=mem_addr, mem_rmask=mem_rmask, mem_wmask=mem_wmask,
                mem_rdata=mem_rdata, mem_wdata=mem_wdata)


def beat(seq=1, address=0x200, write=True, be=15, wdata=0x44332211):
    return dict(kind='data_accept', transaction=key(seq),
                raw_address=address, aligned_address=address & ~3,
                address=address, write=int(write), be=be, wdata=wdata)


def response(seq=1, rdata=0, error=0):
    return dict(kind='data_response', transaction=key(seq), rdata=rdata, error=error)


def store_retire(order, address=0x200, data=0x44332211, pc=0x104):
    return retire(SW, order=order, pc=pc, rs1_addr=1, rs1_rdata=address,
                  rs2_addr=2, rs2_rdata=data, rd_addr=0, rd_wdata=0,
                  mem_addr=address, mem_rmask=0, mem_wmask=15,
                  mem_rdata=0, mem_wdata=data)


#: (operation, rd, rs1, shamt, rs1_rdata, exact word, golden word from the
#: published P4 encoder standard) -- assertions below pin both.
SHIFT_POSITIVES = (
    ('SLLI', 5, 6, 7, 0x80000001, 0x00731293),
    ('SRLI', 7, 8, 31, 0xF0000000, 0x01F45393),
    ('SRAI', 9, 10, 3, 0x80000000, 0x40355493),
)

#: (funct3, shamt, reserved funct7, legal?) -- the RV32I reserved-bit matrix.
RESERVED_MATRIX = (
    (1, 0, 0b0000000, True),
    (1, 0, 0b0000001, False),   # SLLI imm[5] is not shamt[5] in RV32I
    (1, 0, 0b0100000, False),   # SRAI's imm[10] on funct3 1 is reserved
    (1, 0, 0b1000000, False),   # SLLI imm[11] reserved
    (1, 0, 0b1111111, False),
    (5, 0, 0b0000000, True),    # SRLI
    (5, 0, 0b0100000, True),    # SRAI
    (5, 0, 0b0000001, False),
    (5, 0, 0b0110000, False),   # SRAI imm[10] and imm[9] set
    (5, 0, 0b1000000, False),
    (5, 0, 0b1100000, False),
    (5, 0, 0b1111111, False),
)


class CpuRetirementShiftTests(unittest.TestCase):
    def setUp(self):
        self.matcher = CpuRetirementMatcher(max_pending=16)

    def decide(self, insn, *, writer='online-shift', **fields):
        """Feed one frozen fetch plus one retirement on an isolated matcher."""
        matcher = CpuRetirementMatcher(max_pending=16)
        matcher.consume(fetch(insn, writer=writer))
        return matcher.consume(retire(insn, **fields))

    def freeze_shift_and_store(self, word):
        """Freeze both words plus one pending store beat on ``self.matcher``.

        The shift word is fetched at 0x100 and the real store at 0x104, so a
        shift retirement can be accepted while the store beat stays pending.
        """
        self.matcher.consume(fetch(word, seq=1, pc=0x100))
        self.matcher.consume(fetch(SW, seq=2, pc=0x104))
        self.matcher.consume(beat())
        self.matcher.consume(response())

    def test_each_shift_operation_is_accepted_with_exact_decoded_fields(self):
        for operation, rd, rs1, shamt, rs1_rdata, golden in SHIFT_POSITIVES:
            with self.subTest(operation=operation):
                word = shift_word(operation, rd, rs1, shamt)
                self.assertEqual(golden, word)
                value = shift_result(operation, rs1_rdata, shamt)
                matcher = CpuRetirementMatcher()
                matcher.consume(fetch(word, writer='online-' + operation.lower()))
                reports = matcher.consume(retire(word, rs1_addr=rs1, rs1_rdata=rs1_rdata,
                                                 rd_addr=rd, rd_wdata=value))
                self.assertEqual(1, len(reports))
                proof = reports[0]
                self.assertEqual('accepted', proof['status'])
                self.assertEqual('matched_instruction', proof['reason'])
                self.assertEqual('retired_instruction_origin', proof['proof_scope'])
                self.assertEqual(['online-' + operation.lower()], proof['source_refs'])
                self.assertEqual('typed_writer_refs', proof['instruction_origin_status'])
                self.assertEqual(dict(SCOPE), proof['cpu_scope'])
                self.assertEqual(0x100, proof['pc'])
                self.assertEqual(0, proof['order'])
                # The certificate records the exact instruction, and its own
                # bytes decode back to the exact rd/rs1/shamt the frame used.
                self.assertEqual(word, proof['insn'])
                decoded = decode(proof['insn'])
                self.assertEqual(OP_IMM, decoded['opcode'])
                self.assertEqual(1 if operation == 'SLLI' else 5, decoded['funct3'])
                self.assertEqual(SRA_RESERVED if operation == 'SRAI' else 0,
                                 decoded['funct7'])
                self.assertEqual(shamt, decoded['shamt'])
                self.assertEqual(rd, decoded['rd'])
                self.assertEqual(rs1, decoded['rs1'])
                self.assertEqual(shamt, (golden >> 20) & 31)
                # A register-only instruction owns no memory transaction.
                self.assertEqual([], proof['transaction_keys'])
                self.assertEqual(0, matcher.pending_data_count)
                self.assertEqual(sorted(WITNESS_FIELDS), sorted(proof))
                for cell in proof['byte_cells']:
                    self.assertEqual(['INSTRUCTION_SOURCE'] * 4, cell['writer_kinds'])
                    self.assertEqual(['online-' + operation.lower()] * 4,
                                     cell['writer_event_ids'])

    def test_shift_certificate_has_the_same_witness_schema_as_xori(self):
        xori = 0xFFF34293  # xori x5, x6, -1
        observed = CpuRetirementMatcher()
        observed.consume(fetch(xori, writer='online-xori'))
        xori_proof = observed.consume(retire(xori, rs1_addr=6, rs1_rdata=0x5a,
                                             rd_addr=5, rd_wdata=0xffffffa5))[0]
        self.assertEqual('accepted', xori_proof['status'])
        self.assertEqual(sorted(WITNESS_FIELDS), sorted(xori_proof))
        for operation, rd, rs1, shamt, rs1_rdata, _ in SHIFT_POSITIVES:
            with self.subTest(operation=operation):
                word = shift_word(operation, rd, rs1, shamt)
                matcher = CpuRetirementMatcher()
                matcher.consume(fetch(word))
                proof = matcher.consume(retire(word, rs1_addr=rs1, rs1_rdata=rs1_rdata,
                                               rd_addr=rd,
                                               rd_wdata=shift_result(operation, rs1_rdata,
                                                                     shamt)))[0]
                self.assertEqual('accepted', proof['status'])
                self.assertEqual(sorted(WITNESS_FIELDS), sorted(proof))
                self.assertEqual('matched_instruction', proof['reason'])

    def test_shift_retirement_never_consumes_a_pending_data_beat(self):
        word = shift_word('SLLI', 5, 6, 7)
        self.freeze_shift_and_store(word)
        proof = self.matcher.consume(retire(word, rs1_addr=6, rs1_rdata=0x80000001,
                                            rd_addr=5, rd_wdata=0x80))[0]
        self.assertEqual('accepted', proof['status'])
        self.assertEqual([], proof['transaction_keys'])
        self.assertEqual(1, self.matcher.pending_data_count)
        later = self.matcher.consume(store_retire(order=1))[0]
        self.assertEqual('accepted', later['status'])
        self.assertEqual([key(1)], later['transaction_keys'])
        self.assertEqual(0, self.matcher.pending_data_count)

    def test_shift_retirement_ignores_stale_lsu_masks(self):
        word = shift_word('SRAI', 9, 10, 3)
        for rmask, wmask in ((15, 0), (0, 15), (15, 15)):
            with self.subTest(rmask=rmask, wmask=wmask):
                self.matcher = CpuRetirementMatcher(max_pending=16)
                self.freeze_shift_and_store(word)
                proof = self.matcher.consume(retire(word, rs1_addr=10, rs1_rdata=0x80000000,
                                                    rd_addr=9, rd_wdata=0xf0000000,
                                                    mem_addr=0x200, mem_rmask=rmask,
                                                    mem_wmask=wmask))[0]
                self.assertEqual('accepted', proof['status'])
                self.assertEqual(1, self.matcher.pending_data_count)
                self.assertEqual('accepted',
                                 self.matcher.consume(store_retire(order=1))[0]['status'])

    def test_shift_rs2_field_is_neither_shamt_nor_checked(self):
        word = shift_word('SRLI', 7, 8, 31)
        for rs2_addr, rs2_rdata in ((31, 0xffffffff), (0, 0), (8, 0x12345678)):
            with self.subTest(rs2_addr=rs2_addr):
                self.matcher = CpuRetirementMatcher(max_pending=16)
                self.matcher.consume(fetch(word))
                proof = self.matcher.consume(retire(word, rs1_addr=8, rs1_rdata=0xF0000000,
                                                    rs2_addr=rs2_addr, rs2_rdata=rs2_rdata,
                                                    rd_addr=7, rd_wdata=1))[0]
                self.assertEqual('accepted', proof['status'])

    def test_shift_with_rd_x0_never_compares_the_discarded_write_value(self):
        word = shift_word('SLLI', 0, 6, 7)
        self.assertEqual(0, decode(word)['rd'])
        proof = self.decide(word, rs1_addr=6, rs1_rdata=0x80000001, rd_addr=0,
                             rd_wdata=0xdeadbeef)
        self.assertEqual('accepted', proof[0]['status'])
        # x0 discards its result but the source register encoding still binds.
        self.assertEqual('rejected',
                         self.decide(word, order=1, rs1_addr=7, rs1_rdata=0x80000001,
                                      rd_addr=0, rd_wdata=0x80)[0]['status'])

    def test_reserved_shift_words_stay_unsupported_and_never_poison_later_match(self):
        for funct3, shamt, reserved, legal in RESERVED_MATRIX:
            with self.subTest(funct3=funct3, reserved=reserved):
                word = shift_word('SLLI' if funct3 == 1 else 'SRLI', 5, 6, shamt,
                                  funct3=funct3, reserved=reserved)
                self.assertEqual(reserved, (word >> 25) & 0x7f)
                matcher = CpuRetirementMatcher(max_pending=16)
                matcher.consume(fetch(word, seq=1, pc=0x100))
                matcher.consume(fetch(SW, seq=2, pc=0x104))
                matcher.consume(beat())
                matcher.consume(response())
                proof = matcher.consume(retire(word, order=0, rs1_addr=6,
                                               rs1_rdata=0x80000001, rd_addr=5,
                                               rd_wdata=0x80000001))[0]
                if legal:
                    self.assertEqual('accepted', proof['status'])
                else:
                    self.assertEqual('rejected', proof['status'])
                    self.assertEqual('unsupported_instruction_observation_only',
                                     proof['reason'])
                    self.assertEqual([], proof['transaction_keys'])
                self.assertEqual(1, matcher.pending_data_count)
                self.assertEqual('accepted',
                                 matcher.consume(store_retire(order=1))[0]['status'])

    def test_srai_high_bits_absent_is_decoded_as_srli_and_needs_the_logical_result(self):
        word = shift_word('SRAI', 9, 10, 3, reserved=0)
        self.assertEqual(0, (word >> 25) & 0x7f)
        self.assertEqual(5, decode(word)['funct3'])
        arithmetic = self.decide(word, rs1_addr=10, rs1_rdata=0x80000000,
                                  rd_addr=9, rd_wdata=0xf0000000)
        self.assertEqual('rejected', arithmetic[0]['status'])
        self.assertEqual('illegal_register_effect', arithmetic[0]['reason'])
        logical = self.decide(word, rs1_addr=10, rs1_rdata=0x80000000,
                               rd_addr=9, rd_wdata=0x10000000)
        self.assertEqual('accepted', logical[0]['status'])

    def test_srai_reserved_bits_require_the_arithmetic_result(self):
        word = shift_word('SRAI', 9, 10, 3)
        self.assertEqual(SRA_RESERVED, (word >> 25) & 0x7f)
        logical = self.decide(word, rs1_addr=10, rs1_rdata=0x80000000,
                               rd_addr=9, rd_wdata=0x10000000)
        self.assertEqual('rejected', logical[0]['status'])
        self.assertEqual('illegal_register_effect', logical[0]['reason'])
        arithmetic = self.decide(word, rs1_addr=10, rs1_rdata=0x80000000,
                                  rd_addr=9, rd_wdata=0xf0000000)
        self.assertEqual('accepted', arithmetic[0]['status'])

    def test_shift_result_mismatch_is_rejected(self):
        word = shift_word('SLLI', 5, 6, 7)
        for value, label in ((0x81, 'one_bit_wrong'), (0x40, 'shifted_by_six'),
                             (0x100, 'shifted_by_eight'), (0x80000001, 'no_shift')):
            with self.subTest(label=label):
                proof = self.decide(word, rs1_addr=6, rs1_rdata=0x80000001,
                                     rd_addr=5, rd_wdata=value)
                self.assertEqual('rejected', proof[0]['status'])
                self.assertEqual('illegal_register_effect', proof[0]['reason'])

    def test_shift_amount_is_read_only_from_the_instruction_field(self):
        for operation, rd, rs1, shamt, rs1_rdata, _ in SHIFT_POSITIVES:
            for delta in (-1, 1):
                with self.subTest(operation=operation, delta=delta):
                    word = shift_word(operation, rd, rs1, shamt)
                    wrong, right = shamt + delta, shamt
                    if not 0 <= wrong < 32:
                        continue
                    self.assertNotEqual(wrong, right)
                    # The frame carries no shift-amount field: a result that
                    # fits another shamt is a different result and is refused.
                    if shift_result(operation, rs1_rdata, wrong) == \
                            shift_result(operation, rs1_rdata, right):
                        continue
                    proof = self.decide(word, rs1_addr=rs1, rs1_rdata=rs1_rdata,
                                         rd_addr=rd,
                                         rd_wdata=shift_result(operation, rs1_rdata, wrong))
                    self.assertEqual('rejected', proof[0]['status'])
                    self.assertEqual('illegal_register_effect', proof[0]['reason'])

    def test_shift_register_encoding_mismatch_is_rejected(self):
        word = shift_word('SLLI', 5, 6, 7)
        value = shift_result('SLLI', 0x80000001, 7)
        for fields, label in ((dict(rs1_addr=6, rd_addr=6), 'rd_names_rs1'),
                              (dict(rs1_addr=5, rd_addr=5), 'rs1_names_rd'),
                              (dict(rs1_addr=6, rd_addr=31), 'other_rd'),
                              (dict(rs1_addr=31, rd_addr=5), 'other_rs1'),
                              (dict(rs1_addr=6, rd_addr=5, epoch=0), 'exact_control')):
            with self.subTest(label=label):
                proof = self.decide(word, rs1_rdata=0x80000001, rd_wdata=value, **fields)
                if label == 'exact_control':
                    self.assertEqual('accepted', proof[0]['status'])
                else:
                    self.assertEqual('rejected', proof[0]['status'])
                    self.assertEqual('illegal_register_effect', proof[0]['reason'])

    def test_shift_rd_and_rs1_addresses_are_checked_even_when_value_agrees(self):
        # rs1 = x0 with a nonzero frame rdata still binds the address field:
        # swapping the two address fields of an otherwise valid frame fails.
        word = shift_word('SRLI', 3, 0, 1)
        proof = self.decide(word, rs1_addr=0, rs1_rdata=0x00000002, rd_addr=3,
                             rd_wdata=0x00000001)
        self.assertEqual('accepted', proof[0]['status'])
        swapped = self.decide(word, order=1, rs1_addr=3, rs1_rdata=0x00000002,
                               rd_addr=0, rd_wdata=0x00000001)
        self.assertEqual('rejected', swapped[0]['status'])

    def test_shift_boundary_shift_amounts_zero_and_thirty_one_are_legal(self):
        for operation, funct3 in (('SLLI', 1), ('SRLI', 5), ('SRAI', 5)):
            for shamt in (0, 31):
                with self.subTest(operation=operation, shamt=shamt):
                    word = shift_word(operation, 5, 6, shamt)
                    self.assertEqual(shamt, decode(word)['shamt'])
                    self.assertEqual(funct3, decode(word)['funct3'])
                    value = shift_result(operation, 0xf0f0f0f1, shamt)
                    proof = self.decide(word, rs1_addr=6, rs1_rdata=0xf0f0f0f1,
                                         rd_addr=5, rd_wdata=value)
                    self.assertEqual('accepted', proof[0]['status'])

    def test_trapped_shift_retirement_is_rejected_and_remains_a_barrier(self):
        word = shift_word('SLLI', 5, 6, 7)
        self.freeze_shift_and_store(word)
        trapped = self.matcher.consume(retire(word, rs1_addr=6, rs1_rdata=0x80000001,
                                              rd_addr=5, rd_wdata=0x80, trap=1))[0]
        self.assertEqual('rejected', trapped['status'])
        self.assertEqual('trap_retirement_observation_only', trapped['reason'])
        self.assertEqual([], trapped['transaction_keys'])
        self.assertEqual(1, self.matcher.pending_data_count)
        self.assertEqual('ambiguous',
                         self.matcher.consume(store_retire(order=1))[0]['status'])

    def test_shift_only_accepts_the_exact_opcode_and_funct3(self):
        word = shift_word('SLLI', 5, 6, 7)
        neighbours = (
            (word & ~0x7f) | 0x33,          # OP: SLL is a register-register form
            (word & ~0x7f) | 0x1b,          # OP-IMM-32
            (word & ~(7 << 12)) | (2 << 12),  # SLTI
            (word & ~(7 << 12)) | (3 << 12),  # SLTIU
            (word & ~(7 << 12)) | (6 << 12),  # ORI stays unsupported
            (word & ~(7 << 12)) | (7 << 12),  # ANDI stays unsupported
        )
        for insn in neighbours:
            with self.subTest(insn=hex(insn)):
                proof = self.decide(insn, rs1_addr=6, rs1_rdata=0x80000001,
                                     rd_addr=5, rd_wdata=0x80)
                self.assertEqual('rejected', proof[0]['status'])
                self.assertEqual('unsupported_instruction_observation_only',
                                 proof[0]['reason'])

    def test_shift_accepted_witness_is_detached_from_the_input_frame(self):
        word = shift_word('SLLI', 5, 6, 7)
        matcher = CpuRetirementMatcher(max_pending=16)
        frame = fetch(word)
        matcher.consume(frame)
        event = retire(word, rs1_addr=6, rs1_rdata=0x80000001, rd_addr=5, rd_wdata=0x80)
        proof = matcher.consume(event)[0]
        self.assertEqual('accepted', proof['status'])
        before = copy.deepcopy(proof)
        event['insn'] = 0
        event['rd_wdata'] = 0
        self.assertEqual(before, proof)
        self.assertEqual(word, proof['insn'])


    def test_encoder_field_sweep_is_accepted_by_the_witness(self):
        """Every legal (op, rd, rs1, shamt) the P4 encoder can emit is accepted.

        The word comes from the production encoder while the expected result
        comes from this file's own ISA arithmetic, so a disagreement in either
        implementation shows up here. The field matrix is bounded but covers
        the whole shamt range and both register extremes.
        """
        from myfuzz.scenario.rv32i_sources import Rv32iInstruction
        checked = 0
        for operation in ('SLLI', 'SRLI', 'SRAI'):
            funct3 = 1 if operation == 'SLLI' else 5
            reserved = SRA_RESERVED if operation == 'SRAI' else 0
            for rd in (0, 1, 5, 31):
                for rs1 in (0, 1, 6, 31):
                    for shamt in range(32):
                        word = Rv32iInstruction(operation, rd=rd, rs1=rs1,
                                                immediate=shamt).word()
                        with self.subTest(operation=operation, rd=rd, rs1=rs1,
                                          shamt=shamt):
                            decoded = decode(word)
                            self.assertEqual(OP_IMM, decoded['opcode'])
                            self.assertEqual(funct3, decoded['funct3'])
                            self.assertEqual(reserved, decoded['funct7'])
                            self.assertEqual(shamt, decoded['shamt'])
                            self.assertEqual(rd, decoded['rd'])
                            self.assertEqual(rs1, decoded['rs1'])
                            value = shift_result(operation, 0x9e3779b9, shamt)
                            proof = self.decide(word, rs1_addr=rs1,
                                                rs1_rdata=0x9e3779b9, rd_addr=rd,
                                                rd_wdata=value)
                            self.assertEqual('accepted', proof[0]['status'])
                            checked += 1
        self.assertEqual(3 * 4 * 4 * 32, checked)

    def test_reserved_bit_words_are_refused_by_validator_and_witness_alike(self):
        """The source validator and the witness agree on every reserved word."""
        from myfuzz.scenario import rejection_codes as rc
        from myfuzz.scenario.rv32i_sources import validate_instruction_bytes_detailed
        for funct3, shamt, reserved, legal in RESERVED_MATRIX:
            with self.subTest(funct3=funct3, reserved=reserved):
                word = shift_word('SLLI' if funct3 == 1 else 'SRLI', 5, 6, shamt,
                                  funct3=funct3, reserved=reserved)
                rejection = validate_instruction_bytes_detailed(
                    word.to_bytes(4, 'little'))
                proof = self.decide(word, rs1_addr=6, rs1_rdata=0x80000001,
                                    rd_addr=5, rd_wdata=0x80000001)
                if legal:
                    self.assertIsNone(rejection)
                    self.assertEqual('accepted', proof[0]['status'])
                else:
                    self.assertEqual(rc.RejectionCode.ISA_RESERVED_IMM_BIT,
                                     rejection.code)
                    self.assertEqual('unsupported_instruction_observation_only',
                                     proof[0]['reason'])


if __name__ == '__main__':
    unittest.main()
