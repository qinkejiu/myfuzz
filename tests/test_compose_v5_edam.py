import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.scripts.edam_to_compose_v5_filelist import EdamError, convert_edam  # noqa: E402
from myfuzz.builder.contracts import build_elaboration_manifest  # noqa: E402


class ComposeV5EdamTest(unittest.TestCase):
    def test_conversion_is_contained_and_ignores_user_hooks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "rtl/inc").mkdir(parents=True)
            (root / "rtl/top.sv").write_text("module top; endmodule\n", encoding="ascii")
            (root / "rtl/inc/defs.svh").write_text("`define OK 1\n", encoding="ascii")
            edam = {
                "files": [
                    {"name": "rtl/inc/defs.svh", "file_type": "systemVerilogSource",
                     "is_include_file": True},
                    {"name": "rtl/top.sv", "file_type": "systemVerilogSource"},
                    {"name": "hook.py", "file_type": "user"},
                    {"name": "rtl/top.sv", "file_type": "systemVerilogSource"},
                ],
                "parameters": {
                    "ENABLE": {"paramtype": "vlogdefine", "default": True},
                    "WIDTH": {"paramtype": "vlogdefine", "default": 32},
                    "TOP_PARAM": {"paramtype": "vlogparam", "default": 4},
                },
            }
            path = root / "design.edam.yml"
            path.write_text(yaml.safe_dump(edam), encoding="ascii")
            output = root / "out/design.f"
            self.assertEqual(convert_edam(path, root, output), 1)
            self.assertEqual(output.read_text(encoding="ascii").splitlines(), [
                "+define+ENABLE", "+define+WIDTH=32", "+incdir+../rtl/inc", "../rtl/top.sv",
            ])
            manifest = build_elaboration_manifest(
                top_module="top", filelists=[output], allow_roots=[root],
            )
            self.assertEqual([Path(item.path).name for item in manifest.sources], ["top.sv"])

    def test_escape_unknown_type_and_empty_sources_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root.parent / f"{root.name}-outside.sv"
            outside.write_text("module outside; endmodule\n", encoding="ascii")
            self.addCleanup(outside.unlink)
            path = root / "design.edam.yml"
            output = root / "out.f"
            for files, message in (
                ([{"name": outside.as_posix(), "file_type": "systemVerilogSource"}], "escapes"),
                ([{"name": "x.c", "file_type": "cSource"}], "unsupported"),
                ([{"name": "hook.py", "file_type": "user"}], "no compile sources"),
            ):
                path.write_text(yaml.safe_dump({"files": files}), encoding="ascii")
                with self.assertRaisesRegex(EdamError, message):
                    convert_edam(path, root, output)


if __name__ == "__main__":
    unittest.main()
