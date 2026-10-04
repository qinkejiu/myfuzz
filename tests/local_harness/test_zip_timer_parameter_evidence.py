"""Verilog parameter continuation in the pinned ZipCPU timer header."""
from __future__ import annotations

import unittest

from myfuzz.local_harness.parameter_evidence import parameter_evidence
from myfuzz.local_harness.port_rendering import LocalPortRenderError


class ZipTimerParameterEvidenceTests(unittest.TestCase):
    def test_continuation_inherits_explicit_parameter_declaration(self):
        text = 'module ziptimer #(parameter BW = 32, VW = (BW-1), parameter [0:0] RELOADABLE = 1) (); endmodule'
        rows = parameter_evidence('ziptimer', ('BW', 'VW', 'RELOADABLE'), (('ziptimer.v', text),))
        self.assertEqual(['BW', 'RELOADABLE', 'VW'], [row['name'] for row in rows])
        self.assertIn('VW = (BW-1)', rows[-1]['declaration'])

    def test_bare_first_fragment_still_rejected(self):
        text = 'module ziptimer #(BW = 32, parameter VW = 31) (); endmodule'
        with self.assertRaisesRegex(LocalPortRenderError, 'unsupported'):
            parameter_evidence('ziptimer', ('BW',), (('ziptimer.v', text),))


if __name__ == '__main__':
    unittest.main()
