from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from myfuzz.builder.contracts import build_elaboration_manifest
from myfuzz.scripts.materialize_compose_v5_filelist import (
    FilelistMaterializationError,
    materialize_filelist,
)


class ComposeV5FilelistMaterializerTest(unittest.TestCase):
    def test_variables_comments_and_nested_filelists_are_flattened(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "inc").mkdir()
            (root / "rtl").mkdir()
            (root / "rtl" / "a.sv").write_text("module a; endmodule\n", encoding="ascii")
            (root / "rtl" / "b.sv").write_text("module b; endmodule\n", encoding="ascii")
            (root / "nested.f").write_text(
                "// nested\n+incdir+${ROOT}/inc\n${ROOT}/rtl/b.sv\n", encoding="ascii"
            )
            source = root / "root.f"
            source.write_text(
                "+define+SYNTHESIS // mode\n${ROOT}/rtl/a.sv\n-F ${ROOT}/nested.f\n",
                encoding="ascii",
            )
            output = root / "out" / "flat.f"
            self.assertEqual(
                materialize_filelist(source, root, output, {"ROOT": str(root)}), 2
            )
            manifest = build_elaboration_manifest(
                top_module="a", filelists=(output,), allow_roots=(root,)
            )
            self.assertEqual(len(manifest.sources), 2)
            self.assertEqual(manifest.defines, ("SYNTHESIS",))

    def test_unknown_variable_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "root.f"
            source.write_text("${MISSING}/a.sv\n", encoding="ascii")
            with self.assertRaisesRegex(FilelistMaterializationError, "unknown variable"):
                materialize_filelist(source, root, root / "flat.f", {})

    def test_expanded_path_must_remain_in_source_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            external = Path(outside) / "a.sv"
            external.write_text("module a; endmodule\n", encoding="ascii")
            source = root / "root.f"
            source.write_text("${OTHER}/a.sv\n", encoding="ascii")
            with self.assertRaisesRegex(FilelistMaterializationError, "escapes source root"):
                materialize_filelist(source, root, root / "flat.f", {"OTHER": outside})


if __name__ == "__main__":
    unittest.main()
