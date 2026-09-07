from __future__ import annotations

import unittest

from myfuzz.isa.constraints import IsaContract, RiscvInstructionProvider


class InstructionConstraintsTest(unittest.TestCase):
    def test_i_provider_accepts_addi_and_rejects_multiply(self) -> None:
        provider = RiscvInstructionProvider(IsaContract(32, ("I",)))
        self.assertTrue(provider.is_legal_word(0x0010_0093))  # addi x1, x0, 1
        self.assertFalse(provider.is_legal_word(0x0200_00B3))  # mul x1, x0, x0
        with self.assertRaisesRegex(ValueError, "illegal"):
            provider.constrain_word(0x0200_00B3)

    def test_rv64imafdc_accepts_i_m_and_compressed_encodings(self) -> None:
        provider = RiscvInstructionProvider(IsaContract(64, ("I", "M", "A", "F", "D", "C")))
        self.assertTrue(provider.is_legal_word(0x0010_0093))
        self.assertTrue(provider.is_legal_word(0x0200_00B3))
        self.assertTrue(provider.is_legal_word(0x0001, compressed=True))

    def test_contract_rejects_invalid_xlen_extensions_and_alignment(self) -> None:
        for args in ((48, ("I",)), (32, ("Z",)), (32, ("I",), ("M",), 3)):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    IsaContract(*args)


if __name__ == "__main__":
    unittest.main()
