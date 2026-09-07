from __future__ import annotations

import sys
import unittest
from unittest import mock

from myfuzz.composition import protocol_composer
from myfuzz.composition.protocol_composer import _generic_lint


class GenericLintDiagnosticTests(unittest.TestCase):
    def test_failed_lint_preserves_plain_text_source_diagnostic(self) -> None:
        command = (
            sys.executable,
            "-c",
            "import sys; sys.stderr.write('broken.sv:17: syntax error\\n'); raise SystemExit(1)",
        )

        with self.assertRaisesRegex(
            ValueError,
            r"generic composition lint failed:[\s\S]*broken\.sv:17: syntax error",
        ):
            _generic_lint(command)

    def test_failed_lint_truncates_unbounded_plain_text_diagnostic(self) -> None:
        command = (
            sys.executable,
            "-c",
            "import sys; sys.stderr.write('broken.sv:23: ' + 'x' * (256 * 1024)); raise SystemExit(1)",
        )

        with self.assertRaises(ValueError) as raised:
            _generic_lint(command)

        message = str(raised.exception)
        self.assertIn("broken.sv:23:", message)
        self.assertIn("diagnostic truncated", message)
        self.assertLessEqual(len(message.encode("utf-8")), 70 * 1024)

    def test_timed_out_lint_preserves_diagnostic_flushed_before_hang(self) -> None:
        command = (
            sys.executable,
            "-c",
            "import sys, time; sys.stderr.write('hung.sv:31: stalled\\n'); "
            "sys.stderr.flush(); time.sleep(30)",
        )

        with mock.patch.object(protocol_composer, "_GENERIC_LINT_TIMEOUT_SECONDS", 1):
            with self.assertRaisesRegex(
                ValueError,
                r"generic composition lint failed:[\s\S]*hung\.sv:31: stalled",
            ):
                _generic_lint(command)


if __name__ == "__main__":
    unittest.main()
