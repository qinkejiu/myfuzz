"""The unsupervised frontend must honor the pinned UART include closure."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
import unittest

from myfuzz.composition.component_profile import (
    _direct_pinned_closure_hash, elaborate_profile, load_component_profile)
from myfuzz.composition.source_crawler import _content_hash
from myfuzz.local_harness import verify_local_source_lock


ROOT = Path(__file__).resolve().parents[2]


class UartDirectFallbackTests(unittest.TestCase):
    def test_full_include_root_pin_rejects_modified_header(self):
        with tempfile.TemporaryDirectory(prefix="myfuzz-uart-direct-pin-") as directory:
            root = Path(directory)
            (root / "rtl").mkdir()
            (root / "include").mkdir()
            (root / "rtl" / "top.sv").write_bytes(b"module top; endmodule\n")
            header = root / "include" / "defs.svh"
            header.write_bytes(b"`define WIDTH 8\n")
            expected = _content_hash({
                "rtl/top.sv": (root / "rtl" / "top.sv").read_bytes(),
                "include/defs.svh": header.read_bytes()})

            def closure_hash():
                contents = {"rtl/top.sv": (root / "rtl" / "top.sv").read_bytes()}
                def read(path):
                    name = path.relative_to(root).as_posix()
                    contents[name] = path.read_bytes()
                    return contents[name]
                return _direct_pinned_closure_hash(
                    root, contents, ("include",), read, expected)

            self.assertEqual(expected, closure_hash())
            header.write_bytes(b"`define WIDTH 9\n")
            self.assertNotEqual(expected, closure_hash())

    @unittest.skipUnless(shutil.which("verilator"), "Verilator is required")
    def test_real_uart_direct_elaboration_keeps_pinned_union_identity(self):
        profile = load_component_profile(json.loads((
            ROOT / "configs/peripherals/opentitan_uart_local/component_profile.json"
        ).read_text()))
        facts = elaborate_profile(profile, base_dir=ROOT, mode="direct")
        self.assertEqual(profile.source.revision, facts.content_hash)
        self.assertEqual(profile.source.revision, facts.revision)
        verified = verify_local_source_lock(profile, base_dir=ROOT)
        self.assertEqual(profile.source.revision, verified["profile_union_revision"])


if __name__ == "__main__":
    unittest.main()
