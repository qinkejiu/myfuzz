from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.source_branch_instrumenter import instrument_project


class SourceBranchInstrumenterFilelistTest(unittest.TestCase):
    @staticmethod
    def _write(path: Path, text: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_external_sources_include_dirs_and_nested_flists_form_closed_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project_root = root / "upstream-ibex"
            out_dir = root / "instrumented"
            flist_dir = root / "filelists" / "nested"
            external_wrapper = root / "configs" / "components" / "shared.sv"
            external_protocol = root / "src" / "myfuzz" / "protocols" / "shared.sv"
            include_dir = root / "configs" / "components" / "include"
            include_file = self._write(include_dir / "component_defs.svh", "`define COMPONENT_WIDTH 1\n")

            self._write(
                external_wrapper,
                """`include \"component_defs.svh\"
module composition_wrapper(input wire clk, input wire in_i, output wire out_o);
  shared_protocol u_protocol(.clk(clk), .in_i(in_i), .out_o(out_o));
  always @* begin
    if (in_i) out_o = out_o;
  end
endmodule
""",
            )
            self._write(
                external_protocol,
                """module shared_protocol(input wire clk, input wire in_i, output wire out_o);
  always @(posedge clk) begin
    if (in_i) out_o <= in_i;
  end
endmodule
""",
            )
            nested_flist = self._write(
                flist_dir / "sources.f",
                "../../configs/components/shared.sv\n"
                "../../src/myfuzz/protocols/shared.sv\n",
            )
            flist = self._write(
                root / "filelists" / "top.f",
                "-f nested/sources.f\n"
                f"+incdir+{include_dir}\n",
            )

            manifest = instrument_project(
                project_root,
                out_dir,
                flist=flist,
                top_module="composition_wrapper",
                force=True,
            )

            source_map = manifest["source_map"]
            wrapper_output = Path(source_map[external_wrapper.resolve().as_posix()])
            protocol_output = Path(source_map[external_protocol.resolve().as_posix()])
            self.assertTrue(wrapper_output.is_relative_to(out_dir))
            self.assertTrue(protocol_output.is_relative_to(out_dir))
            self.assertNotEqual(wrapper_output, protocol_output)
            self.assertTrue(wrapper_output.is_file())
            self.assertTrue(protocol_output.is_file())
            self.assertTrue((out_dir / "__external__").is_dir())

            wrapper_text = wrapper_output.read_text(encoding="utf-8")
            self.assertIn("__vi_coverage", wrapper_text)
            self.assertIn("__vi_coverage", protocol_output.read_text(encoding="utf-8"))

            instrumented_flist = Path(manifest["instrumented_flist"])
            self.assertEqual(out_dir / "instrumented_sources.f", instrumented_flist)
            flist_text = instrumented_flist.read_text(encoding="utf-8")
            self.assertNotIn(external_wrapper.resolve().as_posix(), flist_text)
            self.assertNotIn(external_protocol.resolve().as_posix(), flist_text)
            self.assertNotIn(include_dir.resolve().as_posix(), flist_text)
            self.assertNotIn(nested_flist.resolve().as_posix(), flist_text)
            self.assertIn(wrapper_output.as_posix(), flist_text)
            self.assertIn(protocol_output.as_posix(), flist_text)

            include_lines = [line for line in flist_text.splitlines() if line.startswith("+incdir+")]
            self.assertEqual(1, len(include_lines))
            mapped_include = Path(include_lines[0][len("+incdir+") :])
            self.assertTrue(mapped_include.is_relative_to(out_dir))
            self.assertTrue((mapped_include / include_file.name).is_file())

            for line in flist_text.splitlines():
                if not line or line.startswith("+"):
                    continue
                source_token = line.split()[0]
                if source_token.lower().endswith((".sv", ".svh", ".v", ".vh")):
                    self.assertTrue(Path(source_token).is_relative_to(out_dir), line)

    def test_external_same_basename_sources_get_stable_noncolliding_destinations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project_root = root / "project"
            first = self._write(root / "first" / "same.sv", "module first; endmodule\n")
            second = self._write(root / "second" / "same.sv", "module second; endmodule\n")
            flist = self._write(root / "sources.f", f"{first}\n{second}\n")

            first_manifest = instrument_project(
                project_root,
                root / "out-a",
                flist=flist,
                top_module="first,second",
                force=True,
            )
            second_manifest = instrument_project(
                project_root,
                root / "out-b",
                flist=flist,
                top_module="first,second",
                force=True,
            )

            first_map = first_manifest["source_map"]
            second_map = second_manifest["source_map"]
            first_a = Path(first_map[first.resolve().as_posix()])
            first_b = Path(first_map[second.resolve().as_posix()])
            second_a = Path(second_map[first.resolve().as_posix()])
            second_b = Path(second_map[second.resolve().as_posix()])
            self.assertNotEqual(first_a, first_b)
            self.assertEqual(first_a.relative_to(root / "out-a"), second_a.relative_to(root / "out-b"))
            self.assertEqual(first_b.relative_to(root / "out-a"), second_b.relative_to(root / "out-b"))
            self.assertTrue(first_a.is_file())
            self.assertTrue(first_b.is_file())


if __name__ == "__main__":
    unittest.main()
