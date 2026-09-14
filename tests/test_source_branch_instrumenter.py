from __future__ import annotations

import shutil
import subprocess
import tempfile
import textwrap
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


class SourceBranchInstrumenterInstanceMappingTest(unittest.TestCase):
    """The flat coverage vector must stay resolvable back to its instances.

    ``coverage_bits`` is what lets SoC feedback attribute a hit to one instance
    instead of to a module name, so these tests check the mapping against the
    concatenation the instrumenter actually emitted and then against a real
    simulation rather than against a re-derivation of the same arithmetic.
    """

    LEAF = """\
module leaf(input wire clk, input wire sel, output reg q);
  always @(posedge clk) begin
    if (sel) q <= 1'b1;
    else q <= 1'b0;
  end
endmodule
"""

    TOP = """\
module top(input wire clk, input wire sel_a, input wire sel_b,
           output wire qa, output wire qb);
  leaf u_a(.clk(clk), .sel(sel_a), .q(qa));
  leaf u_b(.clk(clk), .sel(sel_b), .q(qb));
endmodule
"""

    def _instrument(self, root: Path) -> tuple[dict, Path]:
        project = root / "project"
        project.mkdir(parents=True, exist_ok=True)
        (project / "leaf.sv").write_text(self.LEAF, encoding="utf-8")
        (project / "top.sv").write_text(self.TOP, encoding="utf-8")
        (project / "sources.f").write_text("leaf.sv\ntop.sv\n", encoding="utf-8")
        manifest = instrument_project(
            project, root / "instrumented",
            flist=project / "sources.f", top_module="top", force=True,
        )
        return manifest, root / "instrumented"

    def test_two_instances_of_one_module_get_distinct_mapped_bits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest, _ = self._instrument(Path(directory))
            bits = manifest["coverage_bits"]
            # Two if/else points in each of two instances.
            self.assertEqual(4, manifest["coverage_vector_width"])
            self.assertEqual(4, len(bits))
            self.assertEqual(4, len({item["bit"] for item in bits}))
            self.assertEqual({"top/u_a", "top/u_b"},
                             {item["instance_path"] for item in bits})
            self.assertEqual({"leaf"}, {item["module"] for item in bits})
            by_key = {(item["instance_path"], item["subtype"]): item["bit"]
                      for item in bits}
            self.assertNotEqual(by_key[("top/u_a", "true")],
                                by_key[("top/u_b", "true")])

    def test_mapped_bits_follow_the_emitted_concatenation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest, instrumented = self._instrument(Path(directory))
            top = (instrumented / "top.sv").read_text(encoding="utf-8")
            assign = [line for line in top.splitlines()
                      if "__vi_coverage" in line and "assign" in line]
            self.assertEqual(1, len(assign), top)
            terms = [term.strip() for term in
                     assign[0].split("=", 1)[1].strip().strip(";").strip("{}").split(",")]
            # A concatenation puts its first term in the most significant bits,
            # so the last term owns the lowest range.
            expected: dict[str, int] = {}
            high = manifest["coverage_vector_width"] - 1
            for term in terms:
                width = 1 if term.startswith("__vi_branch_cov") else 2
                expected[term] = high - width + 1
                high -= width
            self.assertEqual(-1, high, assign[0])
            # u_a is the first child term, so its true arm is the second
            # least-significant bit of its own two-bit field.
            first_child = terms[0]
            self.assertEqual(expected[first_child] + 1,
                             next(item["bit"] for item in manifest["coverage_bits"]
                                  if item["instance_path"] == "top/u_a"
                                  and item["subtype"] == "true"))

    @unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"),
                         "iverilog is required for the instance-mapping simulation")
    def test_a_hit_in_one_instance_sets_only_its_mapped_bit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, instrumented = self._instrument(root)
            by_key = {(item["instance_path"], item["subtype"]): int(item["bit"])
                      for item in manifest["coverage_bits"]}
            width = int(manifest["coverage_vector_width"])
            bench = root / "tb.sv"
            bench.write_text(textwrap.dedent("""\
                module tb;
                  reg clk = 1'b0; reg sel_a = 1'b1; reg sel_b = 1'b0;
                  wire qa, qb;
                  wire [%d:0] cov;
                  top dut(.clk(clk), .sel_a(sel_a), .sel_b(sel_b),
                          .qa(qa), .qb(qb), .__vi_coverage(cov));
                  integer i;
                  initial begin
                    for (i = 0; i < 4; i = i + 1) begin
                      #5 clk = 1'b1; #5 clk = 1'b0;
                    end
                    $display("COV %%b", cov);
                    $finish;
                  end
                endmodule
                """ % (width - 1)), encoding="utf-8")
            sources = sorted(str(path) for path in instrumented.rglob("*.sv"))
            output = root / "tb.vvp"
            compiled = subprocess.run(
                ["iverilog", "-g2012", "-s", "tb", "-o", str(output), *sources,
                 str(bench)], text=True, capture_output=True, timeout=120,
            )
            self.assertEqual(0, compiled.returncode, compiled.stderr)
            result = subprocess.run(["vvp", str(output)], text=True,
                                    capture_output=True, timeout=120)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            match = [line for line in result.stdout.splitlines() if line.startswith("COV ")]
            self.assertEqual(1, len(match), result.stdout)
            vector = int(match[0].split()[1], 2)
            self.assertEqual(1, (vector >> by_key[("top/u_a", "true")]) & 1,
                             "the driven instance's true arm is recorded")
            self.assertEqual(0, (vector >> by_key[("top/u_b", "true")]) & 1,
                             "the sibling instance's true arm stays clear")


if __name__ == "__main__":
    unittest.main()
