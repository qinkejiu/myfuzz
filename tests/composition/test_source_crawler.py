from __future__ import annotations

import shutil
import json
import hashlib
import subprocess
import tempfile
import unittest
from unittest import mock
from dataclasses import replace
from pathlib import Path

from myfuzz.composition.interface_description import ElaborationSettings, SourceLocator, load_interface_description
from myfuzz.composition.source_crawler import (
    SourceCrawler,
    SourceCrawlError,
    annotate_interfaces,
    source_tree_hash,
)
from myfuzz.protocols.catalog import ProtocolCatalog
from myfuzz.protocols.model import FieldSpec, ProtocolPlugin
from myfuzz.contracts import ContractError


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
WARNING_SUMMARY = {"sha256": hashlib.sha256(b"").hexdigest(), "byte_count": 0,
                   "warning_classes": {}, "warning_count": 0, "error_count": 0, "parse_complete": True}


def _tree_hash(root: Path, files: tuple[Path, ...]) -> str:
    return source_tree_hash(root, files)


class SourceCrawlerTests(unittest.TestCase):
    def test_elaboration_preserves_compiler_order_and_has_path_independent_identity(self) -> None:
        calls = []

        def crawl_at(parent: Path, files=("types.sv", "top.sv"), includes=("first", "second")):
            root = parent / "source"
            root.mkdir(parents=True)
            (root / "types.sv").write_text("package p; endpackage\n", encoding="utf-8")
            (root / "top.sv").write_text("module top(); endmodule\n", encoding="utf-8")
            for directory, value in (("first", "1"), ("second", "2")):
                path = root / directory / "same.svh"
                path.parent.mkdir()
                path.write_text(value, encoding="utf-8")
            closure = tuple(root / name for name in ("types.sv", "top.sv", "first/same.svh", "second/same.svh"))
            locator = SourceLocator("source", source_tree_hash(root, closure), "top", files=files, include_roots=includes, elaboration=ElaborationSettings("verilator-json"))

            def runner(**arguments):
                calls.append((arguments["source_files"], arguments["include_roots"]))
                output = arguments["output_dir"]
                output.mkdir()
                records = []
                for path in closure:
                    payload = path.read_bytes()
                    records.append({"file": path.relative_to(root).as_posix(), "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)})
                summary = dict(WARNING_SUMMARY)
                summary.update(sha256=hashlib.sha256(str(root).encode()).hexdigest(), byte_count=len(str(root)))
                (output / "manifest.json").write_text(json.dumps({"sources": records, "tool_sources": [], "tool_version": "fake", "warning_summary": summary, "warning_policy": "fatal"}), encoding="utf-8")
                return {"ports": []}

            with mock.patch("myfuzz.composition.source_elaboration.run_verilator_elaboration", side_effect=runner):
                return SourceCrawler().crawl(locator, base_dir=parent).content_hash

        with tempfile.TemporaryDirectory() as left, tempfile.TemporaryDirectory() as right, tempfile.TemporaryDirectory() as reversed_root:
            first = crawl_at(Path(left))
            second = crawl_at(Path(right))
            reversed_hash = crawl_at(Path(reversed_root), files=("top.sv", "types.sv"), includes=("second", "first"))
        self.assertEqual(first, second)
        self.assertNotEqual(first, reversed_hash)
        self.assertEqual((("types.sv", "top.sv"), ("first", "second")), calls[0])
        self.assertEqual((("top.sv", "types.sv"), ("second", "first")), calls[2])

    def test_elaboration_rejects_invalid_manifest_source_records(self) -> None:
        for corruption in ("duplicate", "sha", "size", "missing"):
            with self.subTest(corruption=corruption), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "source"
                root.mkdir()
                source = root / "top.sv"
                source.write_text("module top(); endmodule\n", encoding="utf-8")
                payload = source.read_bytes()
                locator = SourceLocator("source", source_tree_hash(root, (source,)), "top", files=("top.sv",), elaboration=ElaborationSettings("verilator-json"))
                record = {"file": "top.sv", "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}

                def runner(**arguments):
                    output = arguments["output_dir"]
                    output.mkdir()
                    records = [] if corruption == "missing" else [dict(record)]
                    if corruption == "duplicate": records.append(dict(record))
                    if corruption == "sha": records[0]["sha256"] = "0" * 64
                    if corruption == "size": records[0]["size"] += 1
                    (output / "manifest.json").write_text(json.dumps({"sources": records, "tool_sources": [], "tool_version": "fake", "warning_summary": WARNING_SUMMARY, "warning_policy": "fatal"}), encoding="utf-8")
                    return {"ports": []}

                with mock.patch("myfuzz.composition.source_elaboration.run_verilator_elaboration", side_effect=runner):
                    with self.assertRaisesRegex(SourceCrawlError, "manifest-source-mismatch"):
                        SourceCrawler().crawl(locator, base_dir=Path(temporary))

    def test_elaboration_rejects_missing_malformed_or_wrong_policy_summary(self) -> None:
        for corruption in ("missing", "malformed", "policy", "error"):
            with self.subTest(corruption=corruption), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "source"
                root.mkdir()
                source = root / "top.sv"
                source.write_text("module top(); endmodule\n", encoding="utf-8")
                payload = source.read_bytes()
                locator = SourceLocator("source", source_tree_hash(root, (source,)), "top", files=("top.sv",), elaboration=ElaborationSettings("verilator-json"))
                def runner(**arguments):
                    output = arguments["output_dir"]
                    output.mkdir()
                    manifest = {"sources": [{"file": "top.sv", "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}],
                                "tool_sources": [], "tool_version": "fake", "warning_policy": "fatal", "warning_summary": WARNING_SUMMARY}
                    if corruption == "missing": manifest.pop("warning_summary")
                    if corruption == "malformed": manifest["warning_summary"] = {"parse_complete": True}
                    if corruption == "policy": manifest["warning_policy"] = "recorded-nonfatal"
                    if corruption == "error": manifest["warning_summary"] = {**WARNING_SUMMARY, "error_count": 1}
                    (output / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
                    return {"ports": []}
                with mock.patch("myfuzz.composition.source_elaboration.run_verilator_elaboration", side_effect=runner):
                    with self.assertRaisesRegex(SourceCrawlError, "warning-summary-mismatch"):
                        SourceCrawler().crawl(locator, base_dir=Path(temporary))

    def test_filelist_define_rejects_elaboration_before_runner(self) -> None:
        temporary, root, source = self.make_source()
        self.addCleanup(temporary.cleanup)
        filelist = root / "files.f"
        filelist.write_text("+define+WIDTH=8 rtl/opaque_tile.sv\n", encoding="utf-8")
        locator = SourceLocator(root.name, source_tree_hash(root, (source, filelist)), "opaque_tile", filelist="files.f", elaboration=ElaborationSettings("verilator-json"))
        with mock.patch("myfuzz.composition.source_elaboration.run_verilator_elaboration") as runner:
            with self.assertRaisesRegex(SourceCrawlError, "filelist-defines-unsupported"):
                SourceCrawler().crawl(locator, base_dir=root.parent)
        runner.assert_not_called()

    @unittest.skipUnless(shutil.which("verilator"), "verilator is not installed")
    def test_real_elaboration_resolves_parameterized_top_width(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            source = root / "top.sv"
            source.write_text("module top #(parameter W=8) (input logic [W-1:0] a); endmodule\n", encoding="utf-8")
            locator = SourceLocator(
                "source", source_tree_hash(root, (source,)), "top", files=("top.sv",),
                elaboration=ElaborationSettings("verilator-json", parameters=(("W", "13"),)),
            )
            snapshot = SourceCrawler().crawl(locator, base_dir=Path(temporary))
        self.assertEqual(13, next(port.width for port in snapshot.ports if port.name == "a"))
        self.assertEqual(13, next(port.width for port in snapshot.elaborated_ports if port.name == "a"))
        self.assertIsInstance(snapshot.elaboration_evidence, bytes)

    def test_elaboration_replaces_unsupported_structured_top_parse(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            package = root / "types.sv"
            top = root / "top.sv"
            package.write_text("package p; typedef struct packed { logic [7:0] data; } request_t; endpackage\n", encoding="utf-8")
            top.write_text("module top(input p::request_t bus); endmodule\n", encoding="utf-8")
            revision = source_tree_hash(root, (package, top))
            locator = SourceLocator("source", revision, "top", files=("types.sv", "top.sv"), elaboration=ElaborationSettings("verilator-json"))

            def fake_runner(**arguments):
                output = arguments["output_dir"]
                output.mkdir()
                records = []
                for name in ("types.sv", "top.sv"):
                    payload = (root / name).read_bytes()
                    records.append({"file": name, "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)})
                (output / "manifest.json").write_text(json.dumps({"sources": records, "tool_sources": [], "tool_version": "fake", "warning_summary": WARNING_SUMMARY, "warning_policy": "fatal"}), encoding="utf-8")
                return {"schema_version": "elaborated_ports.v1", "top_module": "top", "ports": [{"name": "bus", "direction": "input", "width": 8, "signed": False, "source": {"file": "top.sv", "line": 1, "column": 12}, "members": [{"path": ["data"], "width": 8, "raw_lo": 0, "raw_hi": 7, "signed": False, "source": {"file": "types.sv", "line": 1, "column": 36}}]}]}

            with mock.patch("myfuzz.composition.source_elaboration.run_verilator_elaboration", side_effect=fake_runner) as runner:
                snapshot = SourceCrawler().crawl(locator, base_dir=Path(temporary))
            self.assertEqual(("types.sv", "top.sv"), runner.call_args.kwargs["source_files"])
            self.assertEqual((), snapshot.ports)
            self.assertEqual("bus", snapshot.elaborated_ports[0].name)
            description = load_interface_description({
                "schema_version": "interface_description.v1",
                "source": {"root": "source", "revision": revision, "top_module": "top", "files": ["types.sv", "top.sv"], "elaboration": {"frontend": "verilator-json"}},
                "endpoints": [{"endpoint_id": "structured", "function": "memory_master", "module": "top", "fields": [{"role": "request", "physical": {"port": "bus", "member_path": ["data"]}}]}],
            })
            field = SourceCrawler().annotate(snapshot, description)["endpoints"][0]["fields"][0]
            self.assertEqual((8, False, 0, 7, 8), (field["width"], field["signed"], field["raw_lo"], field["raw_hi"], field["container_width"]))
            self.assertEqual(["explicit_member", "compiler_elaboration"], field["evidence"])
            other_source = replace(description.source, top_module="other_top")
            other_endpoint = replace(description.endpoints[0], module="other_top")
            with self.assertRaisesRegex(SourceCrawlError, "physical-selector-elaboration-identity-mismatch"):
                SourceCrawler().annotate(
                    snapshot,
                    replace(description, source=other_source, endpoints=(other_endpoint,)),
                )
            different_settings = replace(
                description.source,
                elaboration=ElaborationSettings("verilator-json", parameters=(("W", "32"),)),
            )
            with self.assertRaisesRegex(SourceCrawlError, "physical-selector-elaboration-identity-mismatch"):
                SourceCrawler().annotate(snapshot, replace(description, source=different_settings))
            different_revision = replace(description.source, revision="sha256:" + "0" * 64)
            with self.assertRaisesRegex(SourceCrawlError, "physical-selector-elaboration-identity-mismatch"):
                SourceCrawler().annotate(snapshot, replace(description, source=different_revision))
            changed_port = replace(snapshot.elaborated_ports[0], width=9)
            with self.assertRaisesRegex(SourceCrawlError, "physical-selector-elaboration-identity-mismatch"):
                SourceCrawler().annotate(
                    replace(snapshot, elaborated_ports=(changed_port,)),
                    description,
                )

    def test_default_crawl_never_invokes_elaboration_runner(self) -> None:
        temporary, root, source = self.make_source()
        self.addCleanup(temporary.cleanup)
        description = self.description(root, source)
        with mock.patch(
            "myfuzz.composition.source_elaboration.run_verilator_elaboration",
            side_effect=AssertionError("runner called without opt-in"),
        ):
            SourceCrawler().crawl(description.source, base_dir=root.parent)

    def test_elaboration_forwards_include_roots_and_propagates_failure(self) -> None:
        temporary, root, source = self.make_source()
        self.addCleanup(temporary.cleanup)
        include = root / "include"
        include.mkdir()
        header = include / "width.svh"
        header.write_text("`define WIDTH 8\n", encoding="utf-8")
        revision = source_tree_hash(root, (source, header))
        locator = SourceLocator(
            root.name, revision, "opaque_tile", files=("rtl/opaque_tile.sv",),
            include_roots=("include",), elaboration=ElaborationSettings("verilator-json"),
        )
        with mock.patch(
            "myfuzz.composition.source_elaboration.run_verilator_elaboration",
            side_effect=RuntimeError("frontend failed"),
        ) as runner:
            with self.assertRaisesRegex(RuntimeError, "frontend failed"):
                SourceCrawler().crawl(locator, base_dir=root.parent)
        self.assertEqual(("include",), runner.call_args.kwargs["include_roots"])
        self.assertEqual(("rtl/opaque_tile.sv",), runner.call_args.kwargs["source_files"])
        self.assertTrue(runner.call_args.kwargs["output_dir"].parent.name.startswith(".myfuzz-elaboration-"))

    def test_elaboration_keeps_structured_top_port_out_of_scalar_ports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            source = root / "top.sv"
            source.write_text("module top(input logic clk); endmodule\n", encoding="utf-8")
            revision = source_tree_hash(root, (source,))
            locator = SourceLocator("source", revision, "top", files=("top.sv",), elaboration=ElaborationSettings("verilator-json"))

            def fake_runner(**arguments):
                output = arguments["output_dir"]
                output.mkdir()
                payload = source.read_bytes()
                (output / "manifest.json").write_text(json.dumps({"sources": [{"file": "top.sv", "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}], "tool_sources": [], "tool_version": "fake", "warning_summary": WARNING_SUMMARY, "warning_policy": "fatal"}), encoding="utf-8")
                return {"ports": [
                    {"name": "clk", "direction": "input", "width": 1, "signed": False, "source": {"file": "top.sv", "line": 1, "column": 24}, "members": []},
                    {"name": "bus", "direction": "input", "width": 8, "signed": False, "source": {"file": "top.sv", "line": 1, "column": 1}, "members": [{"path": ["data"], "width": 8, "raw_lo": 0, "raw_hi": 7, "signed": False, "source": {"file": "top.sv", "line": 1, "column": 1}}]},
                ]}

            with mock.patch("myfuzz.composition.source_elaboration.run_verilator_elaboration", side_effect=fake_runner):
                snapshot = SourceCrawler().crawl(locator, base_dir=Path(temporary))
            self.assertEqual(["clk"], [port.name for port in snapshot.ports])
            self.assertEqual(["clk", "bus"], [port.name for port in snapshot.elaborated_ports])
            with self.assertRaises(TypeError):
                snapshot.elaboration_evidence[0] = 0
    def test_same_module_instance_aliases_remain_ambiguous(self) -> None:
        temporary, root, source = self.make_source(
            OPAQUE_TILE + "\nmodule wrapper(); opaque_tile u1(); opaque_tile u2(); endmodule"
        )
        self.addCleanup(temporary.cleanup)
        description = self.description(root, source)
        endpoint = replace(description.endpoints[0], module=None, aliases=("u1", "u2"))
        description = replace(description, source=replace(description.source, top_module="wrapper"), endpoints=(endpoint,))
        with self.assertRaisesRegex(SourceCrawlError, "endpoint-ambiguous"):
            annotate_interfaces(description, base_dir=root.parent)

    def test_generated_instance_is_not_flattened_into_false_hierarchy(self) -> None:
        temporary, root, source = self.make_source(
            OPAQUE_TILE + "\nmodule wrapper(); generate if (1) begin : scope\n"
            "opaque_tile u_tile(); end endgenerate endmodule"
        )
        self.addCleanup(temporary.cleanup)
        description = self.description(root, source)
        endpoint = replace(description.endpoints[0], module=None, hierarchy=("wrapper", "u_tile"))
        with self.assertRaisesRegex(SourceCrawlError, "endpoint-unresolved"):
            annotate_interfaces(replace(description, endpoints=(endpoint,)), base_dir=root.parent)

    def test_documentation_endpoint_alias_can_resolve_module(self) -> None:
        temporary, root, source = self.make_source(OPAQUE_TILE.replace(
            "  output logic [31:0] q_addr,", "  // myfuzz: endpoint=legacy field=address\n  output logic [31:0] q_addr,"
        ) + "\nmodule wrapper(); endmodule")
        self.addCleanup(temporary.cleanup)
        description = self.description(root, source, fields=[{"role": "address"}])
        endpoint = replace(description.endpoints[0], module=None, aliases=("legacy",))
        description = replace(description, source=replace(description.source, top_module="wrapper"), endpoints=(endpoint,))
        self.assertEqual(annotate_interfaces(description, base_dir=root.parent)["endpoints"][0]["module"], "opaque_tile")

    def test_snapshot_documentation_tags_are_independent_of_crawler_state(self) -> None:
        tagged_temporary, tagged_root, tagged_source = self.make_source(OPAQUE_TILE.replace(
            "  output logic [31:0] q_addr,", "  // myfuzz: endpoint=legacy field=address\n  output logic [31:0] q_addr,"
        ))
        plain_temporary, plain_root, plain_source = self.make_source()
        self.addCleanup(tagged_temporary.cleanup)
        self.addCleanup(plain_temporary.cleanup)
        tagged_description = self.description(tagged_root, tagged_source, fields=[{"role": "address"}])
        tagged_endpoint = replace(tagged_description.endpoints[0], module=None, aliases=("legacy",))
        tagged_description = replace(
            tagged_description,
            source=replace(tagged_description.source, top_module="opaque_tile"),
            endpoints=(tagged_endpoint,),
        )
        plain_description = self.description(plain_root, plain_source, fields=[{"role": "address"}])
        plain_endpoint = replace(plain_description.endpoints[0], module=None, aliases=("legacy",))
        plain_description = replace(plain_description, endpoints=(plain_endpoint,))

        crawler = SourceCrawler()
        tagged_snapshot = crawler.crawl(tagged_description.source, base_dir=tagged_root.parent)
        plain_snapshot = crawler.crawl(plain_description.source, base_dir=plain_root.parent)

        self.assertIn(
            "source_documentation",
            crawler.annotate(tagged_snapshot, tagged_description)["endpoints"][0]["fields"][0]["evidence"],
        )
        with self.assertRaisesRegex(SourceCrawlError, "endpoint-unresolved"):
            crawler.annotate(plain_snapshot, plain_description)
        self.assertIn(
            "source_documentation",
            SourceCrawler().annotate(tagged_snapshot, tagged_description)["endpoints"][0]["fields"][0]["evidence"],
        )

    def test_transfer_accept_requires_explicit_handshake_signal_names(self) -> None:
        text = OPAQUE_TILE.replace(
            "    if (q_valid && !q_ready) q_wdata <= q_wdata;",
            "    if (q_valid && !q_ready) q_wdata <= q_wdata;\n"
            "    if (foo && bar) q_addr <= q_addr;\n"
            "    if (q_valid && q_ready) q_addr <= q_addr;",
        ).replace("  always_ff", "  logic foo, bar;\n  always_ff")
        temporary, root, source = self.make_source(text)
        self.addCleanup(temporary.cleanup)
        snapshot = SourceCrawler().crawl(self.description(root, source).source, base_dir=root.parent)
        transfers = [observation for observation in snapshot.timing if observation.kind == "transfer_accept"]
        self.assertEqual([(observation.fields, observation.clock) for observation in transfers],
                         [(('q_valid', 'q_ready'), "clk_x")])

    def test_annotate_validates_malformed_snapshot_before_return(self) -> None:
        temporary, root, source = self.make_source()
        self.addCleanup(temporary.cleanup)
        description = self.description(root, source)
        crawler = SourceCrawler()
        snapshot = crawler.crawl(description.source, base_dir=root.parent)
        malformed = replace(snapshot, timing=tuple(replace(item, kind="made_up") for item in snapshot.timing))
        with self.assertRaises(ContractError):
            crawler.annotate(malformed, description)

    def test_git_pin_supports_subdirectory_roots_and_ignores_undeclared_dirt(self) -> None:
        temporary, root, source = self.make_source()
        self.addCleanup(temporary.cleanup)
        revision = self.pin_git(root.parent)
        (root / "undeclared.sv").write_text("not HDL and not a declared input")
        snapshot = SourceCrawler().crawl(self.description(root, source, revision=revision).source, base_dir=root.parent)
        self.assertEqual(snapshot.modules, ("opaque_tile",))

    def test_non_ansi_unpacked_and_symbolic_unpacked_shapes_are_rejected(self) -> None:
        for text in ("module opaque_tile(q_addr); input logic q_addr [7:0]; endmodule",
                     "module opaque_tile(input logic [3:0] q_addr [COUNT-1:0]); endmodule"):
            with self.subTest(text=text):
                temporary, root, source = self.make_source(text)
                self.addCleanup(temporary.cleanup)
                with self.assertRaisesRegex(SourceCrawlError, "unsupported-unpacked-port"):
                    SourceCrawler().crawl(self.description(root, source).source, base_dir=root.parent)

    def protocol_fixture(self, text: str = OPAQUE_TILE, *, function: str = "memory_master",
                         widths: tuple[str, ...] = ("address_width", "1", "1", "data_width", "data_width")):
        temporary, root, source = self.make_source(text)
        self.addCleanup(temporary.cleanup)
        description = self.description(root, source, protocol=["opaque-bus", "1"])
        endpoint = replace(description.endpoints[0], function=function)
        catalog = ProtocolCatalog((ProtocolPlugin("opaque-bus", "1", tuple(
            FieldSpec(role, direction, width, True, 0)
            for role, direction, width in zip(
                ("addr", "valid", "ready", "wdata", "rdata"),
                ("host_to_device", "host_to_device", "device_to_host", "host_to_device", "device_to_host"),
                widths,
            )
        ), ()),))
        return root, replace(description, endpoints=(endpoint,)), catalog

    def test_declared_protocol_requires_catalog(self) -> None:
        root, description, catalog = self.protocol_fixture()
        with self.assertRaisesRegex(SourceCrawlError, "protocol-catalog-required"):
            annotate_interfaces(description, base_dir=root.parent)

    def test_declared_protocol_requires_unambiguous_orientation(self) -> None:
        root, description, catalog = self.protocol_fixture()
        for function in ("memory", "mysterymaster", "master_target"):
            with self.subTest(function=function):
                endpoint = replace(description.endpoints[0], function=function)
                with self.assertRaisesRegex(SourceCrawlError, "protocol-orientation-ambiguous"):
                    annotate_interfaces(replace(description, endpoints=(endpoint,)),
                                        base_dir=root.parent, protocol_catalog=catalog)

    def test_protocol_checks_both_host_and_target_directions(self) -> None:
        for function in ("memory_host", "memory_initiator", "mmio_target", "memory_slave", "bus_device"):
            with self.subTest(function=function):
                root, description, catalog = self.protocol_fixture(function=function)
                if function in ("memory_host", "memory_initiator"):
                    document = annotate_interfaces(description, base_dir=root.parent, protocol_catalog=catalog)
                    self.assertEqual(document["endpoints"][0]["protocol_candidates"][0]["status"], "consistent")
                    source = root / "rtl" / "opaque_tile.sv"
                    source.write_text(OPAQUE_TILE.replace("input  logic q_ready", "output logic q_ready"))
                    description = replace(description, source=replace(description.source,
                                          revision=source_tree_hash(root, (source,))))
                with self.assertRaisesRegex(SourceCrawlError, "protocol-conflict:.*:direction:"):
                    annotate_interfaces(description, base_dir=root.parent, protocol_catalog=catalog)
        inverted = OPAQUE_TILE.replace("input", "TEMP").replace("output", "input").replace("TEMP", "output")
        root, description, catalog = self.protocol_fixture(inverted, function="mmio_target")
        self.assertEqual(annotate_interfaces(description, base_dir=root.parent, protocol_catalog=catalog)
                         ["endpoints"][0]["protocol_candidates"][0]["status"], "consistent")

    def test_protocol_rejects_fixed_and_symbolic_width_conflicts(self) -> None:
        for text, widths in (
            (OPAQUE_TILE.replace("logic q_valid", "logic [1:0] q_valid"), ("address_width", "1", "1", "data_width", "data_width")),
            (OPAQUE_TILE, ("16", "1", "1", "data_width", "data_width")),
            (OPAQUE_TILE.replace("[31:0] q_rdata", "[15:0] q_rdata"), ("address_width", "1", "1", "data_width", "data_width")),
            (OPAQUE_TILE, ("address_width", "data_width / 8", "1", "data_width", "data_width")),
            (OPAQUE_TILE, ("unbound / 8", "1", "1", "data_width", "data_width")),
        ):
            with self.subTest(widths=widths, text=text):
                root, description, catalog = self.protocol_fixture(text, widths=widths)
                with self.assertRaisesRegex(SourceCrawlError, "protocol-conflict:.*:width:"):
                    annotate_interfaces(description, base_dir=root.parent, protocol_catalog=catalog)

    def test_protocol_accepts_safe_symbolic_width_relations(self) -> None:
        root, description, catalog = self.protocol_fixture(
            OPAQUE_TILE.replace("logic q_valid", "logic [3:0] q_valid"),
            widths=("16 * 2", "data_width / 8", "1", "data_width", "data_width"),
        )
        document = annotate_interfaces(description, base_dir=root.parent, protocol_catalog=catalog)
        self.assertEqual(document["endpoints"][0]["protocol_candidates"][0]["status"], "consistent")

    def test_protocol_missing_required_fields_fail_even_if_hint_optional(self) -> None:
        root, description, catalog = self.protocol_fixture()
        endpoint = description.endpoints[0]
        missing = replace(endpoint.fields[0], aliases=("absent",), required=False)
        endpoint = replace(endpoint, fields=(missing, *endpoint.fields[1:]))
        with self.assertRaisesRegex(SourceCrawlError, "protocol-conflict:.*:missing:addr"):
            annotate_interfaces(replace(description, endpoints=(endpoint,)), base_dir=root.parent, protocol_catalog=catalog)

    def test_endpoint_resolution_uses_module_hierarchy_alias_then_top(self) -> None:
        temporary, root, source = self.make_source(
            OPAQUE_TILE + "\nmodule wrapper(); opaque_tile u_tile(); endmodule\n"
        )
        self.addCleanup(temporary.cleanup)
        description = self.description(root, source)
        description = replace(description, source=replace(description.source, top_module="wrapper"))
        original = description.endpoints[0]
        for endpoint, evidence in (
            (replace(original, hierarchy=("invalid",), aliases=("invalid",)), "explicit_module"),
            (replace(original, module=None, hierarchy=("wrapper", "u_tile")), "hierarchy_hint"),
            (replace(original, module=None, hierarchy=("u_tile",)), "hierarchy_hint"),
            (replace(original, module=None, hierarchy=("opaque_tile",)), "hierarchy_hint"),
            (replace(original, module=None, aliases=("opaque_tile",)), "endpoint_alias"),
            (replace(original, module=None, aliases=("u_tile",)), "endpoint_alias"),
        ):
            with self.subTest(endpoint=endpoint):
                document = annotate_interfaces(replace(description, endpoints=(endpoint,)), base_dir=root.parent)
                self.assertEqual(document["endpoints"][0]["module"], "opaque_tile")
                self.assertIn(evidence, document["endpoints"][0]["evidence"])
        fallback = replace(self.description(root, source), endpoints=(replace(original, module=None),))
        self.assertIn("source_top_module", annotate_interfaces(fallback, base_dir=root.parent)["endpoints"][0]["evidence"])

    def test_required_endpoint_hints_do_not_fall_back_on_failure_or_ambiguity(self) -> None:
        temporary, root, source = self.make_source(OPAQUE_TILE + OPAQUE_TILE.replace("opaque_tile", "other_tile"))
        self.addCleanup(temporary.cleanup)
        description = self.description(root, source)
        original = description.endpoints[0]
        for endpoint, error in (
            (replace(original, module="absent"), "endpoint-unresolved"),
            (replace(original, module=None, hierarchy=("absent",)), "endpoint-unresolved"),
            (replace(original, module=None, aliases=("absent",)), "endpoint-unresolved"),
            (replace(original, module=None, aliases=("opaque_tile", "other_tile")), "endpoint-ambiguous"),
        ):
            with self.subTest(endpoint=endpoint):
                with self.assertRaisesRegex(SourceCrawlError, error):
                    annotate_interfaces(replace(description, endpoints=(endpoint,)), base_dir=root.parent)

    def test_endpoint_aliases_match_documentation_tags(self) -> None:
        temporary, root, source = self.make_source(OPAQUE_TILE.replace(
            "  output logic [31:0] q_addr,", "  // myfuzz: endpoint=legacy field=address\n  output logic [31:0] q_addr,"
        ))
        self.addCleanup(temporary.cleanup)
        description = self.description(root, source, fields=[{"role": "address"}])
        endpoint = replace(description.endpoints[0], aliases=("legacy",))
        document = annotate_interfaces(replace(description, endpoints=(endpoint,)), base_dir=root.parent)
        self.assertIn("source_documentation", document["endpoints"][0]["fields"][0]["evidence"])

    def test_duplicate_semantic_port_mapping_is_rejected(self) -> None:
        temporary, root, source = self.make_source()
        self.addCleanup(temporary.cleanup)
        description = self.description(root, source, fields=[
            {"role": "address", "aliases": ["q_addr"]},
            {"role": "write_data", "aliases": ["q_addr"]},
        ])
        with self.assertRaisesRegex(SourceCrawlError, "duplicate-port-mapping"):
            annotate_interfaces(description, base_dir=root.parent)

    def pin_git(self, root: Path) -> str:
        for args in (
            ("init", "-q"), ("config", "user.email", "tests@example.invalid"),
            ("config", "user.name", "Tests"), ("add", "."), ("commit", "-qm", "fixture"),
        ):
            subprocess.run(["git", "-C", str(root), *args], check=True)
        return "git:" + subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()

    def test_git_pin_rejects_dirty_tracked_source_even_when_staged(self) -> None:
        temporary, root, source = self.make_source()
        self.addCleanup(temporary.cleanup)
        locator = self.description(root, source, revision=self.pin_git(root)).source
        source.write_text(OPAQUE_TILE.replace("[31:0]", "[15:0]"))
        for staged in (False, True):
            with self.subTest(staged=staged):
                if staged:
                    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
                with self.assertRaisesRegex(SourceCrawlError, "git-content-mismatch"):
                    SourceCrawler().crawl(locator, base_dir=root.parent)

    def test_git_pin_rejects_untracked_and_missing_declared_sources(self) -> None:
        temporary, root, source = self.make_source()
        self.addCleanup(temporary.cleanup)
        locator = self.description(root, source, revision=self.pin_git(root)).source
        extra = root / "extra.sv"
        extra.write_text("module extra(); endmodule")
        with self.assertRaisesRegex(SourceCrawlError, "git-content-mismatch"):
            SourceCrawler().crawl(replace(locator, files=(*locator.files, "extra.sv")), base_dir=root.parent)
        source.unlink()
        with self.assertRaisesRegex(SourceCrawlError, "source-file-missing"):
            SourceCrawler().crawl(locator, base_dir=root.parent)

    def test_git_pin_verifies_nested_filelists_before_parsing(self) -> None:
        temporary, root, source = self.make_source()
        self.addCleanup(temporary.cleanup)
        filelist = root / "files.f"
        nested = root / "nested.f"
        filelist.write_text("-f nested.f\n")
        nested.write_text("rtl/opaque_tile.sv\n")
        locator = replace(self.description(root, source, revision=self.pin_git(root)).source,
                          files=(), filelist="files.f")
        SourceCrawler().crawl(locator, base_dir=root.parent)
        # Invalid content must be rejected by the pin guard, not parsed as a path.
        nested.write_text("../escape.sv\n")
        with self.assertRaisesRegex(SourceCrawlError, "git-content-mismatch"):
            SourceCrawler().crawl(locator, base_dir=root.parent)
        nested.write_text("rtl/opaque_tile.sv\n")
        untracked = root / "untracked.f"
        untracked.write_text("rtl/opaque_tile.sv\n")
        with self.assertRaisesRegex(SourceCrawlError, "git-content-mismatch"):
            SourceCrawler().crawl(replace(locator, filelist="untracked.f"), base_dir=root.parent)

    def test_filelists_participate_in_content_pin(self) -> None:
        temporary, root, source = self.make_source()
        self.addCleanup(temporary.cleanup)
        filelist = root / "files.f"
        filelist.write_text("rtl/opaque_tile.sv\n")
        locator = replace(self.description(root, source).source, files=(), filelist="files.f",
                          revision=source_tree_hash(root, (source, filelist)))
        snapshot = SourceCrawler().crawl(locator, base_dir=root.parent)
        self.assertIn("files.f", snapshot.files)
        filelist.write_text("# changed\nrtl/opaque_tile.sv\n")
        with self.assertRaisesRegex(SourceCrawlError, "content-hash-mismatch"):
            SourceCrawler().crawl(locator, base_dir=root.parent)

    def test_filelist_include_options_are_contained(self) -> None:
        temporary, root, source = self.make_source()
        self.addCleanup(temporary.cleanup)
        filelist = root / "files.f"
        for option in ("+incdir+../escape", "+incdir+/tmp", "+incdir+rtl+../escape",
                       "-I ../escape", "-I../escape"):
            with self.subTest(option=option):
                filelist.write_text(option + "\nrtl/opaque_tile.sv\n")
                locator = replace(self.description(root, source).source, filelist="files.f")
                with self.assertRaisesRegex(SourceCrawlError, "path-outside-source-root"):
                    SourceCrawler().crawl(locator, base_dir=root.parent)

    def test_filelist_safe_include_options_and_nested_paths(self) -> None:
        temporary, root, source = self.make_source()
        self.addCleanup(temporary.cleanup)
        filelist = root / "files.f"
        nested = root / "rtl" / "nested.f"
        filelist.write_text("+incdir+rtl -Irtl\n-f rtl/nested.f\n")
        nested.write_text("opaque_tile.sv\n")
        locator = replace(self.description(root, source).source, files=(), filelist="files.f",
                          revision=source_tree_hash(root, (source, filelist, nested)))
        self.assertEqual(SourceCrawler().crawl(locator, base_dir=root.parent).modules, ("opaque_tile",))

    def test_hash_frames_path_content_and_entry_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            a, ab, c = (root / name for name in ("a", "ab", "c"))
            a.write_bytes(b"bc")
            ab.write_bytes(b"c")
            self.assertNotEqual(source_tree_hash(root, (a,)), source_tree_hash(root, (ab,)))
            a.write_bytes(b"b")
            c.write_bytes(b"d")
            split = source_tree_hash(root, (a, c))
            self.assertEqual(split, source_tree_hash(root, (c, a)))
            a.write_bytes(b"bcd")
            self.assertNotEqual(split, source_tree_hash(root, (a,)))

    def test_unpacked_ports_fail_closed_without_false_packed_width(self) -> None:
        for declaration in ("input logic q_addr [7:0]", "input logic [31:0] q_addr [7:0]",
                            "input logic [3:0] first, q_addr [7:0]", "input logic q_addr []"):
            with self.subTest(declaration=declaration):
                temporary, root, source = self.make_source(f"module opaque_tile({declaration}); endmodule")
                self.addCleanup(temporary.cleanup)
                with self.assertRaisesRegex(SourceCrawlError, "unsupported-unpacked-port"):
                    SourceCrawler().crawl(self.description(root, source).source, base_dir=root.parent)

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
