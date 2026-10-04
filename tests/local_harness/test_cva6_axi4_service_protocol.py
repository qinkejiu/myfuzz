"""Fail-closed boundaries of the pinned 64-bit CVA6 AXI4 memory service."""
import unittest

from myfuzz.local_harness.cva6_axi4_session import (
    _check_address, _check_write_strobe,
)
from myfuzz.scenario.contracts import ProtocolEnvironmentError


class Cva6Axi4ServiceProtocolTest(unittest.TestCase):
    def test_narrow_write_strobe_must_target_addressed_lanes(self):
        _check_write_strobe(0x400, 2, 0x0f)
        _check_write_strobe(0x404, 2, 0xf0)
        _check_write_strobe(0x404, 2, 0)
        for address, strobe in ((0x400, 0xf0), (0x404, 0x0f),
                                (0x404, 0xff)):
            with self.subTest(address=address, strobe=strobe):
                with self.assertRaises(ProtocolEnvironmentError):
                    _check_write_strobe(address, 2, strobe)

    def test_unsupported_atomic_and_boundary_are_rejected(self):
        row = dict(awaddr=0xff8, awsize=3, awlen=1, awburst=1,
                   awlock=0, awatop=0)
        with self.assertRaises(ProtocolEnvironmentError):
            _check_address(row, 'aw')
        row.update(awaddr=0x400, awlen=0, awatop=1)
        with self.assertRaises(ProtocolEnvironmentError):
            _check_address(row, 'aw')


if __name__ == '__main__':
    unittest.main()
