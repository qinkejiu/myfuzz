"""Physical port facts must not invent widths for unresolved HDL types."""
from pathlib import Path
import tempfile
import unittest

from myfuzz.composition.interface_description import SourceLocator
from myfuzz.composition.source_crawler import SourceCrawler, SourceCrawlError, source_tree_hash


class SourcePortTypeTests(unittest.TestCase):
    def crawl(self, declaration):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "core.sv"
            source.write_text(f"module core({declaration}); endmodule")
            locator = SourceLocator(root.name, source_tree_hash(root, (source,)), "core", ("core.sv",))
            return SourceCrawler().crawl(locator, base_dir=root.parent).ports

    def test_integral_atom_width_and_default_signedness(self):
        for kind, width, signed in (("byte", 8, True), ("shortint", 16, True),
                                    ("int", 32, True), ("integer", 32, True),
                                    ("longint", 64, True), ("time", 64, False)):
            with self.subTest(kind=kind):
                first, second = self.crawl(f"input {kind} a, b")
                self.assertEqual((first.width, first.signed, second.width, second.signed),
                                 (width, signed, width, signed))

    def test_explicit_signedness_overrides_atom_default(self):
        self.assertEqual([(p.width, p.signed) for p in self.crawl("input int unsigned a, output time signed b")],
                         [(32, False), (64, True)])

    def test_unresolved_type_never_becomes_one_bit(self):
        for kind in ("axi_req_t", "pkg::axi_req_t", "real", "realtime", "string",
                     "struct packed {logic [7:0] data;}", "my_bus.master", "`PORT_TYPE"):
            with self.subTest(kind=kind):
                with self.assertRaises(SourceCrawlError):
                    self.crawl(f"input {kind} a")

    def test_nonconstant_or_malformed_packed_dimensions_rejected(self):
        for shape in ("[W-1:0]", "[8]", "[]", "[7:0][W]", "[7:0"):
            with self.subTest(shape=shape):
                with self.assertRaises(SourceCrawlError):
                    self.crawl(f"input logic {shape} a")

    def test_atom_packed_dimensions_rejected(self):
        with self.assertRaises(SourceCrawlError):
            self.crawl("input int [3:0] a")

    def test_builtin_vectors_and_implicit_nets_unchanged(self):
        ports = self.crawl("input wire logic signed [1:0][7:0] a, input b, output bit [3:0] c")
        self.assertEqual([(p.width, p.signed) for p in ports], [(16, True), (1, False), (4, False)])
