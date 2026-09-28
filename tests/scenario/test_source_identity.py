"""A replay identity changes when a declared RTL or harness file changes."""

from pathlib import Path
import tempfile
import unittest

from myfuzz.scenario.identity import bundle_identity


class SourceIdentityTests(unittest.TestCase):
    def test_source_bytes_change_bundle_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "rtl.sv"
            source.write_bytes(b"module local; endmodule\n")
            first = bundle_identity(root, (source,))
            source.write_bytes(b"module local; wire x; endmodule\n")
            second = bundle_identity(root, (source,))
            self.assertNotEqual(first, second)
            self.assertEqual("rtl.sv", first["files"][0]["path"])
            self.assertNotIn(str(root), str(first))

    def test_missing_or_outside_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "outside"):
                bundle_identity(root, (Path("/etc/hosts"),))
            with self.assertRaisesRegex(ValueError, "missing"):
                bundle_identity(root, (root / "missing.sv",))


if __name__ == "__main__":
    unittest.main()
