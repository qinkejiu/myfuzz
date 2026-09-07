from __future__ import annotations

import unittest

from myfuzz.isa.constraints import IsaContract, RiscvInstructionProvider


class InstructionConstraintsTest(unittest.TestCase):
    def test_i_provider_accepts_addi_and_rejects_multiply(self) -> None:
        provider = RiscvInstructionProvider(IsaContract(32, ("I",)))
        self.assertTrue(provider.is_legal_word(0x0010_0093))
        self.assertFalse(provider.is_legal_word(0x0200_00B3))
        with self.assertRaisesRegex(ValueError, "illegal"):
            provider.constrain_word(0x0200_00B3)

    def test_i_decodes_xlen_opcode_funct_and_reserved_register_fields(self) -> None:
        rv32 = RiscvInstructionProvider(IsaContract(32, ("I",)))
        rv64 = RiscvInstructionProvider(IsaContract(64, ("I",)))
        self.assertFalse(rv32.is_legal_word((6 << 12) | 0x03))
        self.assertTrue(rv64.is_legal_word((6 << 12) | 0x03))
        self.assertFalse(rv64.is_legal_word((6 << 12) | 0x23))
        self.assertFalse(rv64.is_legal_word((4 << 12) | 0x73))
        self.assertFalse(rv64.is_legal_word((2 << 12) | 0x0F))
        self.assertFalse(rv64.is_legal_word((1 << 7) | 0x0F))
        self.assertTrue(rv64.is_legal_word(0x0000_0073))

    def test_compressed_decodes_quadrants_reserved_encodings_and_alignment(self) -> None:
        aligned = RiscvInstructionProvider(IsaContract(32, ("I", "C"), instruction_alignment=2))
        word_aligned = RiscvInstructionProvider(IsaContract(32, ("I", "C"), instruction_alignment=4))
        self.assertTrue(aligned.is_legal_word(0x0001, compressed=True))
        self.assertFalse(aligned.is_legal_word(0x0000, compressed=True))
        self.assertFalse(aligned.is_legal_word(0x4002, compressed=True))
        self.assertFalse(aligned.is_legal_word(0x8006, compressed=True))
        self.assertFalse(aligned.is_legal_word(0x2000, compressed=True))
        self.assertFalse(word_aligned.is_legal_word(0x0001, compressed=True))

    def test_unknown_or_unimplemented_extensions_construct_raw_only_contracts(self) -> None:
        provider = RiscvInstructionProvider(IsaContract(64, ("I", "A", "F", "D", "Zba")))
        self.assertFalse(provider.is_legal_word(0x0010_0093))
        with self.assertRaisesRegex(ValueError, "illegal"):
            provider.constrain_word(0x0010_0093)

    def test_rv64imc_accepts_i_m_and_compressed_encodings(self) -> None:
        provider = RiscvInstructionProvider(IsaContract(64, ("I", "M", "C"), instruction_alignment=2))
        self.assertTrue(provider.is_legal_word(0x0010_0093))
        self.assertTrue(provider.is_legal_word(0x0200_00B3))
        self.assertTrue(provider.is_legal_word(0x0001, compressed=True))

    def test_rv64_op_32_accepts_only_rv64i_m_word_operation_encodings(self) -> None:
        i_provider = RiscvInstructionProvider(IsaContract(64, ("I",)))
        m_provider = RiscvInstructionProvider(IsaContract(64, ("I", "M")))
        for instruction in (
            0x3B,  # ADDW
            (0x20 << 25) | 0x3B,  # SUBW
            (1 << 12) | 0x3B,  # SLLW
            (5 << 12) | 0x3B,  # SRLW
            (0x20 << 25) | (5 << 12) | 0x3B,  # SRAW
        ):
            with self.subTest(instruction=instruction):
                self.assertTrue(i_provider.is_legal_word(instruction))
        self.assertTrue(m_provider.is_legal_word((1 << 25) | 0x3B))  # MULW
        self.assertFalse(i_provider.is_legal_word((1 << 25) | 0x3B))
        self.assertFalse(i_provider.is_legal_word((2 << 12) | 0x3B))
        self.assertFalse(i_provider.is_legal_word((1 << 25) | (1 << 12) | 0x3B))

    def test_rv64m_op_32_accepts_all_word_arithmetic_encodings_and_rejects_reserved(self) -> None:
        rv64i = RiscvInstructionProvider(IsaContract(64, ("I",)))
        rv64im = RiscvInstructionProvider(IsaContract(64, ("I", "M")))
        rv32im = RiscvInstructionProvider(IsaContract(32, ("I", "M")))
        rv64i_encodings = (
            0x3B,  # ADDW
            (0x20 << 25) | 0x3B,  # SUBW
            (1 << 12) | 0x3B,  # SLLW
            (5 << 12) | 0x3B,  # SRLW
            (0x20 << 25) | (5 << 12) | 0x3B,  # SRAW
        )
        rv64m_encodings = (
            (1 << 25) | 0x3B,  # MULW
            (1 << 25) | (4 << 12) | 0x3B,  # DIVW
            (1 << 25) | (5 << 12) | 0x3B,  # DIVUW
            (1 << 25) | (6 << 12) | 0x3B,  # REMW
            (1 << 25) | (7 << 12) | 0x3B,  # REMUW
        )
        for instruction in rv64i_encodings:
            with self.subTest(instruction=instruction, kind="rv64i"):
                self.assertTrue(rv64i.is_legal_word(instruction))
                self.assertTrue(rv64im.is_legal_word(instruction))
        for instruction in rv64m_encodings:
            with self.subTest(instruction=instruction, kind="rv64m"):
                self.assertTrue(rv64im.is_legal_word(instruction))
                self.assertFalse(rv64i.is_legal_word(instruction))
                self.assertFalse(rv32im.is_legal_word(instruction))
        for funct3 in (1, 2, 3):
            instruction = (1 << 25) | (funct3 << 12) | 0x3B
            with self.subTest(instruction=instruction, kind="reserved"):
                self.assertFalse(rv64im.is_legal_word(instruction))

    def test_contract_rejects_invalid_xlen_duplicate_extensions_and_alignment(self) -> None:
        for args in ((48, ("I",)), (32, ("I", "I")), (32, ("I",), ("M",), 3)):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    IsaContract(*args)


if __name__ == "__main__":
    unittest.main()
