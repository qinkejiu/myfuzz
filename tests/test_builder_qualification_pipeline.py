import unittest

from myfuzz.builder.input_model import InputValidationError
from myfuzz.builder.qualification_pipeline import BINDING_MODULE, _emit_binding


class QualificationPipelineBindingTests(unittest.TestCase):
    @staticmethod
    def _ip(identifier: str, width: int) -> dict:
        return {"id": identifier, "address_width": width}

    def test_binding_supports_five_ips(self):
        ips = tuple(self._ip(f"ip{index}", width) for index, width in enumerate((16, 12, 5, 32, 32)))
        rtl = _emit_binding(
            ips, (0, 0x10000, 0x11000, 0x12000, 0x13000),
            (0x10000, 0x1000, 0x20, 0x1000, 0x1000),
        )
        self.assertIn(f"module {BINDING_MODULE}", rtl)
        self.assertIn("[159:0] s_awaddr", rtl)
        self.assertIn("ip4_awaddr=s_awaddr[128 +: 32]-32'h13000", rtl)
        self.assertIn("s_rresp[8 +: 2]=ip4_rresp", rtl)

    def test_binding_rejects_too_few_or_mismatched_windows(self):
        with self.assertRaisesRegex(InputValidationError, "at least two"):
            _emit_binding((self._ip("only", 5),), (0,), (0x20,))
        with self.assertRaisesRegex(InputValidationError, "do not match"):
            _emit_binding((self._ip("a", 5), self._ip("b", 5)), (0,), (0x20, 0x20))


if __name__ == "__main__":
    unittest.main()
