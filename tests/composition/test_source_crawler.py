from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from myfuzz.composition.interface_description import SourceLocator, load_interface_description
from myfuzz.composition.source_crawler import (
    SourceCrawler,
    SourceCrawlError,
    annotate_interfaces,
    source_tree_hash,
)


OPAQUE_TILE = """\
module opaque_tile(
  input  logic clk_x,
  input  logic rst_x,
  output logic [31:0] q_addr,
  output logic q_valid,
  input  logic q_ready,
  output logic [31:0] q_wdata,
  input logic [31:0] q_rdata
);
  always_ff @(posedge clk_x) begin
    if (q_valid && !q_ready) q_wdata <= q_wdata;
  end
endmodule
"""


def _tree_hash(root: Path, files: tuple[Path, ...]) -> str:
    return source_tree_hash(root, files)


class SourceCrawlerTests(unittest.TestCase):
    def make_source(self, text: str = OPAQUE_TILE) -> tuple[tempfile.TemporaryDirectory[str], Path, Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name) / "opaque"
        source = root / "rtl" / "opaque_tile.sv"
        source.parent.mkdir(parents=True)
        source.write_text(text, encoding="utf-8")
        return temporary, root, source

    def description(
        self,
        root: Path,
        source: Path,
        *,
        fields: list[dict[str, object]] | None = None,
        revision: str | None = None,
        protocol: list[str] | None = None,
    ) -> object:
        if fields is None:
            fields = [
                {"role": "address", "aliases": ["q_addr"]},
                {"role": "valid", "aliases": ["q_valid"]},
                {"role": "ready", "aliases": ["q_ready"]},
                {"role": "write_data", "aliases": ["q_wdata"]},
                {"role": "read_data", "aliases": ["q_rdata"]},
            ]
        endpoint: dict[str, object] = {
            "endpoint_id": "tile.memory",
            "function": "memory_master",
            "module": "opaque_tile",
            "fields": fields,
        }
        if protocol is not None:
            endpoint["protocol"] = protocol
        return load_interface_description(
            {
                "schema_version": "interface_description.v1",
                "source": {
                    "root": root.name,
                    "revision": revision or _tree_hash(root, (source,)),
                    "top_module": "opaque_tile",
                    "files": ["rtl/opaque_tile.sv"],
                },
                "endpoints": [endpoint],
            }
        )

    def test_annotations_use_hdl_facts_and_observable_stall_evidence(self) -> None:
        temporary, root, source = self.make_source()
        self.addCleanup(temporary.cleanup)

        document = annotate_interfaces(self.description(root, source), base_dir=root.parent)

        self.assertEqual(document["schema_version"], "interface_annotations.v1")
        endpoint = document["endpoints"][0]
        self.assertEqual(endpoint["module"], "opaque_tile")
        self.assertEqual(endpoint["clock"], "clk_x")
        fields = {field["role"]: field for field in endpoint["fields"]}
        self.assertEqual(fields["address"]["direction"], "output")
        self.assertEqual(fields["address"]["width"], 32)
        self.assertEqual(fields["valid"]["width"], 1)
        self.assertEqual(fields["ready"]["direction"], "input")
        self.assertEqual(fields["write_data"]["source"]["file"], "rtl/opaque_tile.sv")
        self.assertGreater(fields["write_data"]["source"]["line"], 0)
        self.assertIn(
            "stall_holds_payload",
            {observation["kind"] for observation in endpoint["timing"]},
        )
        self.assertNotIn("renderer", document)

    def test_content_hash_is_path_independent_and_invalidated_by_source_change(self) -> None:
        temporary, root, source = self.make_source()
        self.addCleanup(temporary.cleanup)
        copied = root.parent / "moved" / root.name
        shutil.copytree(root, copied)
        copied_source = copied / "rtl" / "opaque_tile.sv"

        original_hash = _tree_hash(root, (source,))
        self.assertEqual(original_hash, _tree_hash(copied, (copied_source,)))
        self.assertEqual(SourceCrawler().crawl(self.description(root, source).source, base_dir=root.parent).content_hash, original_hash)

        source.write_text(OPAQUE_TILE.replace("[31:0] q_addr", "[15:0] q_addr"), encoding="utf-8")
        self.assertNotEqual(original_hash, _tree_hash(root, (source,)))
        with self.assertRaisesRegex(SourceCrawlError, "content-hash-mismatch"):
            SourceCrawler().crawl(self.description(root, source, revision=original_hash).source, base_dir=root.parent)

    def test_git_pin_must_name_the_checked_out_commit(self) -> None:
        temporary, root, source = self.make_source()
        self.addCleanup(temporary.cleanup)
        subprocess.run(["git", "init", "-q", root.as_posix()], check=True)
        subprocess.run(["git", "-C", root.as_posix(), "config", "user.email", "tests@example.invalid"], check=True)
        subprocess.run(["git", "-C", root.as_posix(), "config", "user.name", "Tests"], check=True)
        subprocess.run(["git", "-C", root.as_posix(), "add", "rtl/opaque_tile.sv"], check=True)
        subprocess.run(["git", "-C", root.as_posix(), "commit", "-qm", "fixture"], check=True)
        revision = subprocess.run(
            ["git", "-C", root.as_posix(), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

        snapshot = SourceCrawler().crawl(
            self.description(root, source, revision=f"git:{revision}").source,
            base_dir=root.parent,
        )
        self.assertEqual(snapshot.revision, f"git:{revision}")
        with self.assertRaisesRegex(SourceCrawlError, "git-revision-mismatch"):
            SourceCrawler().crawl(
                self.description(root, source, revision="git:" + "0" * 40).source,
                base_dir=root.parent,
            )

    def test_required_aliases_fail_closed_when_missing_or_ambiguous(self) -> None:
        temporary, root, source = self.make_source()
        self.addCleanup(temporary.cleanup)

        with self.assertRaisesRegex(SourceCrawlError, "field-unresolved:tile.memory:address"):
            annotate_interfaces(
                self.description(root, source, fields=[{"role": "address", "aliases": ["not_present"]}]),
                base_dir=root.parent,
            )
        with self.assertRaisesRegex(SourceCrawlError, "field-ambiguous:tile.memory:address"):
            annotate_interfaces(
                self.description(root, source, fields=[{"role": "address", "aliases": ["q_addr", "q_wdata"]}]),
                base_dir=root.parent,
            )

    def test_unsafe_declared_file_and_source_semantic_conflict_fail_closed(self) -> None:
        temporary, root, source = self.make_source()
        self.addCleanup(temporary.cleanup)
        unsafe = SourceLocator(
            root.name,
            _tree_hash(root, (source,)),
            "opaque_tile",
            files=("../outside.sv",),
        )
        with self.assertRaisesRegex(SourceCrawlError, "path-outside-source-root"):
            SourceCrawler().crawl(unsafe, base_dir=root.parent)

        tagged = OPAQUE_TILE.replace(
            "  output logic [31:0] q_wdata,",
            "  // myfuzz: endpoint=tile.memory field=address\n  output logic [31:0] q_wdata,",
        )
        source.write_text(tagged, encoding="utf-8")
        with self.assertRaisesRegex(SourceCrawlError, "source-semantic-conflict:tile.memory:address"):
            annotate_interfaces(self.description(root, source), base_dir=root.parent)

    def test_non_ansi_repeated_signed_declarations_are_preserved(self) -> None:
        temporary, root, source = self.make_source(
            """\
module grouped(a, b, c, d);
  input logic signed [7:0] a, b;
  output logic [3:0] c, d;
endmodule
"""
        )
        self.addCleanup(temporary.cleanup)
        snapshot = SourceCrawler().crawl(
            self.description(
                root,
                source,
                fields=[{"role": "first", "aliases": ["a"]}],
            ).source,
            base_dir=root.parent,
        )
        ports = {port.name: port for port in snapshot.ports}
        self.assertEqual((ports["a"].width, ports["b"].width), (8, 8))
        self.assertTrue(ports["a"].signed)
        self.assertTrue(ports["b"].signed)
        self.assertEqual((ports["c"].width, ports["d"].width), (4, 4))

    def test_symbolic_packed_width_fails_closed(self) -> None:
        temporary, root, source = self.make_source(
            """\
module opaque_tile(input logic [WIDTH-1:0] q_addr);
endmodule
"""
        )
        self.addCleanup(temporary.cleanup)

        with self.assertRaisesRegex(SourceCrawlError, "unsupported-port-width"):
            SourceCrawler().crawl(
                self.description(root, source, fields=[{"role": "address", "aliases": ["q_addr"]}]).source,
                base_dir=root.parent,
            )


if __name__ == "__main__":
    unittest.main()
