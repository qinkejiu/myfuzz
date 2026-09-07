"""Physical port facts must not invent widths for unresolved HDL types."""
from pathlib import Path
import tempfile
import unittest

from myfuzz.composition.interface_description import SourceLocator
from myfuzz.composition.source_crawler import SourceCrawler, SourceCrawlError, source_tree_hash


class SourcePortTypeTests(unittest.TestCase):
    def crawl(self, declaration):
        return self.crawl_source(f"module core({declaration}); endmodule")

    def crawl_source(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "core.sv"
            source.write_text(text)
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

    def test_directionless_types_rejected_in_every_header_position(self):
        for kind in ("my_bus.master", "my_bus", "pkg::payload_t", "logic"):
            for declaration in (f"input logic clk_i, {kind} bus",
                                f"{kind} bus, input logic clk_i", f"{kind} bus"):
                with self.subTest(declaration=declaration):
                    with self.assertRaises(SourceCrawlError):
                        self.crawl(declaration)

    def test_inherited_prefixes_and_trailing_brackets_rejected(self):
        for declaration in ("input logic a, [] b", "input logic a, [7:0] b",
                            "input logic a, ] b", "input logic a]",
                            "input logic a, b]", "input logic a, signed b"):
            with self.subTest(declaration=declaration):
                with self.assertRaises(SourceCrawlError):
                    self.crawl(declaration)

    def test_bare_names_preserve_ansi_and_nonansi_atom_facts(self):
        for text in ("module core(input int a,b); endmodule",
                     "module core(a,b); input int a,b; endmodule"):
            with self.subTest(text=text):
                ports = self.crawl_source(text)
                self.assertEqual([(p.name, p.direction, p.width, p.signed) for p in ports],
                                 [("a", "input", 32, True), ("b", "input", 32, True)])

    def test_header_import_with_record_parameter_type_fails_closed(self):
        with self.assertRaises(SourceCrawlError):
            self.crawl_source("module core import pkg::*; "
                              "#(parameter type T=struct packed{logic[7:0] data;}) "
                              "(input logic clk, output T o); endmodule")

    def test_header_import_preserves_exact_builtin_port_facts(self):
        for imports in ("import pkg::*;", "import pkg::*; import other::item;"):
            with self.subTest(imports=imports):
                ports = self.crawl_source(
                    f"module core {imports}\n"
                    "#(parameter type T=struct packed{logic[7:0] data;})\n"
                    "(input logic clk, output int o); endmodule")
                self.assertEqual(
                    [(p.module, p.name, p.direction, p.width, p.signed,
                      p.source_file, p.line, p.column) for p in ports],
                    [("core", "clk", "input", 1, False, "core.sv", 3, 14),
                     ("core", "o", "output", 32, True, "core.sv", 3, 30)])

    def test_builtin_vectors_and_implicit_nets_unchanged(self):
        ports = self.crawl("input wire logic signed [1:0][7:0] a, input b, output bit [3:0] c")
        self.assertEqual([(p.width, p.signed) for p in ports], [(16, True), (1, False), (4, False)])
