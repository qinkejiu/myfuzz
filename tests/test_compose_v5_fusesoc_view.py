from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

import yaml

from myfuzz.scripts.prepare_compose_v5_fusesoc_view import (
    FuseSoCViewError,
    prepare_view,
)


class ComposeV5FuseSoCViewTest(unittest.TestCase):
    def test_removes_only_empty_core_file_arrays(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "view"
            report_path = root / "report.json"
            (source / "rtl").mkdir(parents=True)
            rtl = b"module example; endmodule\n"
            (source / "rtl" / "example.sv").write_bytes(rtl)
            (source / "rtl" / "alias.sv").symlink_to("example.sv")
            (source / "example.core").write_text(
                "CAPI=2:\n"
                "name: acme:ip:example:1.0\n"
                "filesets:\n"
                "  rtl:\n"
                "    files: [rtl/example.sv]\n"
                "    file_type: systemVerilogSource\n"
                "  empty_waiver:\n"
                "    depend: [acme:lint:common]\n"
                "    files: []\n"
                "    file_type: vlt\n",
                encoding="ascii",
            )

            report = prepare_view(source, destination, report_path)

            self.assertEqual((destination / "rtl" / "example.sv").read_bytes(), rtl)
            self.assertTrue((destination / "rtl" / "alias.sv").is_symlink())
            self.assertEqual((destination / "rtl" / "alias.sv").readlink(), Path("example.sv"))
            body = (destination / "example.core").read_text(encoding="ascii").split("\n", 1)[1]
            core = yaml.safe_load(body)
            self.assertEqual(core["filesets"]["rtl"]["files"], ["rtl/example.sv"])
            self.assertNotIn("files", core["filesets"]["empty_waiver"])
            self.assertEqual(len(report["transformations"]), 1)
            saved = json.loads(report_path.read_text(encoding="ascii"))
            self.assertEqual(saved["non_core_file_count"], 2)
            self.assertEqual(
                saved["transformations"][0]["changes"],
                ["filesets.empty_waiver.files:remove-empty-array"],
            )

    def test_rejects_existing_or_nested_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with self.assertRaises(FuseSoCViewError):
                prepare_view(source, source / "view", root / "report.json")
            destination = root / "view"
            destination.mkdir()
            with self.assertRaises(FuseSoCViewError):
                prepare_view(source, destination, root / "report.json")

    def test_rejects_non_capi2_core(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "bad.core").write_text("name: bad\n", encoding="ascii")
            with self.assertRaises(FuseSoCViewError):
                prepare_view(source, root / "view", root / "report.json")

    def test_rejects_symlink_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "escape").symlink_to(root / "outside")
            (root / "outside").write_text("outside\n", encoding="ascii")
            with self.assertRaises(FuseSoCViewError):
                prepare_view(source, root / "view", root / "report.json")


if __name__ == "__main__":
    unittest.main()
