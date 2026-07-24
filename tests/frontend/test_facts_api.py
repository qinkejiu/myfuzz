#!/usr/bin/env python3
"""Smoke test for the standalone elaborated RTL facts ABI."""

from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, (ROOT / "src").as_posix())
sys.path.insert(0, (ROOT / "src" / "myfuzz" / "scripts").as_posix())

from myfuzz.contracts import validate_contract  # noqa: E402
from frontend_api import FrontendLibrary, default_frontend_library  # noqa: E402


class FactsApiTest(unittest.TestCase):
    def test_facts_selects_the_facts_abi_symbol(self) -> None:
        payload = b'{"schema_version":"hdl_facts.v2","tool":{},"modules":[],"parameters":[],"ports":[],"instances":[],"pin_bindings":[],"expressions":[],"dataflow_edges":[],"control_edges":[],"clock_reset_checks":[],"local_address_facts":[],"source_locations":[],"source_symbols":[],"diagnostics":[]}'
        buffer = ctypes.create_string_buffer(payload)

        class Function:
            def __init__(self) -> None:
                self.calls: list[list[bytes]] = []

            def __call__(self, argc: int, argv: object) -> int:
                self.calls.append([argv[index] for index in range(argc)])
                return ctypes.addressof(buffer)

        class Library:
            def __init__(self) -> None:
                self.myfuzz_frontend_facts_json = Function()
                self.myfuzz_frontend_manifest_json = Function()

            @staticmethod
            def myfuzz_frontend_free(_value: object) -> None:
                pass

            @staticmethod
            def myfuzz_frontend_last_error() -> bytes:
                return b"unexpected error"

        frontend = FrontendLibrary.__new__(FrontendLibrary)
        frontend.lib = Library()
        result = frontend.facts(["--top-module", "opaque_top"], ROOT)

        self.assertEqual(result["schema_version"], "hdl_facts.v2")
        self.assertEqual(
            frontend.lib.myfuzz_frontend_facts_json.calls,
            [[b"--top-module", b"opaque_top"]],
        )
        self.assertEqual(frontend.lib.myfuzz_frontend_manifest_json.calls, [])

    def test_reports_elaborated_ports_instances_and_branches(self) -> None:
        library = default_frontend_library(ROOT)
        self.assertTrue(library.exists(), f"frontend library not built: {library}")
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            source = workdir / "unit.sv"
            source.write_text(
                "module leaf(input logic [3:0] source, output logic sink);\n"
                "  assign sink = ^source;\n"
                "endmodule\n"
                "module root(input logic [3:0] stimulus, output logic observed, "
                "output logic branch_observed);\n"
                "  logic branch_signal;\n"
                "  leaf u0(.source(stimulus), .sink(observed));\n"
                "  always_comb if (stimulus[0]) begin branch_signal = 1'b1; branch_observed = 1'b1; end "
                "else begin branch_signal = 1'b0; branch_observed = 1'b0; end\n"
                "endmodule\n"
            )
            flist = workdir / "files.f"
            flist.write_text(source.name + "\n")
            args = ["--lint-only", "-Wno-fatal", "-f", flist.name, "--top-module", "root"]
            verilator_root = ROOT / "src" / "myfuzz" / "frontend" / "vendor" / "verilator"
            with patch.dict(os.environ, {"MYFUZZ_FRONTEND_VERILATOR_ROOT": verilator_root.as_posix()}):
                frontend = FrontendLibrary(library)
                facts = frontend.facts(args, workdir)

        self.assertEqual(facts["schema_version"], "hdl_facts.v2")
        validate_contract(facts, "hdl_facts.v2")
        self.assertNotEqual(facts["tool"]["input_hash"], "sha256:" + "0" * 64)
        for key in ("tool", "pin_bindings", "expressions", "dataflow_edges", "control_edges",
                    "clock_reset_checks", "local_address_facts", "diagnostics"):
            self.assertIn(key, facts)

        symbols = {
            (symbol["kind"], symbol["name"]): symbol["entity_id"]
            for symbol in facts["source_symbols"]
        }
        root_id = symbols[("module", "root")]
        leaf_id = symbols[("module", "leaf")]
        modules = {module["id"]: module for module in facts["modules"]}
        ports = {port["id"]: port for port in facts["ports"]}
        instances = {instance["id"]: instance for instance in facts["instances"]}
        pin_bindings = {binding["id"]: binding for binding in facts["pin_bindings"]}
        expressions = {expression["id"]: expression for expression in facts["expressions"]}

        self.assertEqual(len(modules), 2)
        self.assertTrue(all(isinstance(identifier, int) for identifier in modules))
        root_ports = [ports[port_id] for port_id in modules[root_id]["ports"]]
        self.assertEqual(root_ports[0]["width"], 4)
        self.assertTrue(all(port["declared_role"] == "uninterpreted_external" for port in ports.values()))
        root_instances = [instances[instance_id] for instance_id in modules[root_id]["instances"]]
        self.assertEqual(root_instances[0]["parent_module_id"], root_id)
        self.assertEqual(root_instances[0]["module_id"], leaf_id)
        self.assertEqual(len(root_instances[0]["pin_bindings"]), 2)
        bound_pins = [pin_bindings[binding_id] for binding_id in root_instances[0]["pin_bindings"]]
        self.assertEqual(
            {binding["port_id"] for binding in bound_pins},
            set(modules[leaf_id]["ports"]),
        )
        self.assertTrue(
            all(binding["instance_id"] == root_instances[0]["id"] for binding in bound_pins)
        )
        self.assertTrue(
            all(binding["expression_id"] in expressions for binding in bound_pins)
        )
        self.assertTrue(
            all(expressions[binding["expression_id"]]["module_id"] == root_id
                for binding in bound_pins)
        )

        source_port_id = symbols[("port", "source")]
        sink_port_id = symbols[("port", "sink")]
        stimulus_port_id = symbols[("port", "stimulus")]
        observed_port_id = symbols[("port", "observed")]
        bindings_by_port = {binding["port_id"]: binding for binding in bound_pins}
        source_expression = expressions[bindings_by_port[source_port_id]["expression_id"]]
        sink_expression = expressions[bindings_by_port[sink_port_id]["expression_id"]]
        self.assertEqual(source_expression["source_ids"], [stimulus_port_id])
        self.assertEqual(source_expression["target_ids"], [])
        self.assertEqual(sink_expression["source_ids"], [])
        self.assertEqual(sink_expression["target_ids"], [observed_port_id])
        self.assertTrue(facts["dataflow_edges"])
        self.assertTrue(any(edge["module_id"] == root_id for edge in facts["control_edges"]))
        locations = {
            (location["kind"], location["entity_id"])
            for location in facts["source_locations"]
        }
        for section, kind in (
            ("pin_bindings", "pin_binding"),
            ("expressions", "expression"),
            ("dataflow_edges", "dataflow_edge"),
            ("control_edges", "control_edge"),
        ):
            self.assertTrue(
                all((kind, edge["id"]) in locations for edge in facts[section]),
                f"missing source location for {kind}",
            )

    def test_sequential_facts_calls_reset_frontend_tree_state(self) -> None:
        library = default_frontend_library(ROOT)
        self.assertTrue(library.exists(), f"frontend library not built: {library}")
        probe = textwrap.dedent(
            """
            import json
            from pathlib import Path
            import sys

            sys.path.insert(0, sys.argv[1])
            from frontend_api import FrontendLibrary

            frontend = FrontendLibrary(Path(sys.argv[2]))
            workdir = Path(sys.argv[3])
            args = ["--lint-only", "-Wno-fatal", "unit.sv", "--top-module", "unit"]
            first = frontend.facts(args, workdir)
            second = frontend.facts(args, workdir)
            (workdir / "unit.sv").write_text(
                "module unit(input logic source, output logic sink); assign sink = ~source; endmodule\\n"
            )
            changed = frontend.facts(args, workdir)
            print(json.dumps(first, sort_keys=True, separators=(",", ":")))
            print(json.dumps(second, sort_keys=True, separators=(",", ":")))
            print(json.dumps(changed, sort_keys=True, separators=(",", ":")))
            """
        )
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            (workdir / "unit.sv").write_text(
                "module unit(input logic source, output logic sink); assign sink = source; endmodule\n"
            )
            environment = os.environ.copy()
            environment["MYFUZZ_FRONTEND_VERILATOR_ROOT"] = (
                ROOT / "src" / "myfuzz" / "frontend" / "vendor" / "verilator"
            ).as_posix()
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    probe,
                    (ROOT / "src" / "myfuzz" / "scripts").as_posix(),
                    library.as_posix(),
                    workdir.as_posix(),
                ],
                cwd=workdir,
                env=environment,
                capture_output=True,
                check=False,
                text=True,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        first, second, changed = result.stdout.splitlines()
        self.assertEqual(first, second)
        self.assertNotEqual(
            json.loads(first)["tool"]["input_hash"],
            json.loads(changed)["tool"]["input_hash"],
        )

    def test_input_hash_is_independent_of_absolute_source_path(self) -> None:
        library = default_frontend_library(ROOT)
        self.assertTrue(library.exists(), f"frontend library not built: {library}")
        verilator_root = ROOT / "src" / "myfuzz" / "frontend" / "vendor" / "verilator"
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            hashes = []
            frontend = FrontendLibrary(library)
            for directory_name in ("first-location", "second-location"):
                source_dir = workdir / directory_name
                source_dir.mkdir()
                include_dir = source_dir / "include"
                include_dir.mkdir()
                (include_dir / "defs.svh").write_text("`define WIDTH 4\n")
                source = source_dir / "unit.sv"
                source.write_text(
                    '`include "defs.svh"\n'
                    "module unit(input logic [`WIDTH-1:0] source, "
                    "output logic [`WIDTH-1:0] sink); "
                    "assign sink = source; endmodule\n"
                )
                args = [
                    "--lint-only",
                    "-Wno-fatal",
                    f"-I{include_dir.resolve().as_posix()}",
                    source.resolve().as_posix(),
                    "--top-module",
                    "unit",
                ]
                with patch.dict(
                    os.environ,
                    {"MYFUZZ_FRONTEND_VERILATOR_ROOT": verilator_root.as_posix()},
                ):
                    hashes.append(frontend.facts(args, source_dir)["tool"]["input_hash"])

        self.assertEqual(hashes[0], hashes[1])

    def test_input_hash_tracks_preprocessor_include_content(self) -> None:
        library = default_frontend_library(ROOT)
        self.assertTrue(library.exists(), f"frontend library not built: {library}")
        verilator_root = ROOT / "src" / "myfuzz" / "frontend" / "vendor" / "verilator"
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            (workdir / "unit.sv").write_text(
                '`include "defs.svh"\n'
                "module unit(input logic [`WIDTH-1:0] source, "
                "output logic [`WIDTH-1:0] sink); assign sink = source; endmodule\n"
            )
            include = workdir / "defs.svh"
            include.write_text("`define WIDTH 4\n")
            args = ["--lint-only", "-Wno-fatal", "unit.sv", "--top-module", "unit"]
            frontend = FrontendLibrary(library)
            with patch.dict(
                os.environ,
                {"MYFUZZ_FRONTEND_VERILATOR_ROOT": verilator_root.as_posix()},
            ):
                first = frontend.facts(args, workdir)
                include.write_text("`define WIDTH 8\n")
                second = frontend.facts(args, workdir)

        self.assertEqual(first["ports"][0]["width"], 4)
        self.assertEqual(second["ports"][0]["width"], 8)
        self.assertNotEqual(first["tool"]["input_hash"], second["tool"]["input_hash"])

    def test_input_hash_ignores_nonexistent_output_directory_path(self) -> None:
        library = default_frontend_library(ROOT)
        self.assertTrue(library.exists(), f"frontend library not built: {library}")
        verilator_root = ROOT / "src" / "myfuzz" / "frontend" / "vendor" / "verilator"
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            (workdir / "unit.sv").write_text(
                "module unit(input logic source, output logic sink); "
                "assign sink = source; endmodule\n",
                encoding="ascii",
            )
            frontend = FrontendLibrary(library)
            hashes = []
            for host_name in ("host-a", "host-b"):
                args = [
                    "--lint-only",
                    "-Wno-fatal",
                    "--Mdir",
                    (workdir / host_name / "obj").as_posix(),
                    "unit.sv",
                    "--top-module",
                    "unit",
                ]
                with patch.dict(
                    os.environ,
                    {"MYFUZZ_FRONTEND_VERILATOR_ROOT": verilator_root.as_posix()},
                ):
                    hashes.append(frontend.facts(args, workdir)["tool"]["input_hash"])

        self.assertEqual(hashes[0], hashes[1])

    def test_input_hash_preserves_preprocessor_dependency_order(self) -> None:
        library = default_frontend_library(ROOT)
        self.assertTrue(library.exists(), f"frontend library not built: {library}")
        verilator_root = ROOT / "src" / "myfuzz" / "frontend" / "vendor" / "verilator"
        width_one = (
            "`ifdef WIDTH\n`undef WIDTH\n`endif\n`define WIDTH 1\n"
        )
        width_two = (
            "`ifdef WIDTH\n`undef WIDTH\n`endif\n`define WIDTH 2\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            first_dir = workdir / "first-include"
            second_dir = workdir / "second-include"
            first_dir.mkdir()
            second_dir.mkdir()
            (first_dir / "first.svh").write_text(width_one, encoding="ascii")
            (first_dir / "second.svh").write_text(width_two, encoding="ascii")
            (second_dir / "first.svh").write_text(width_two, encoding="ascii")
            (second_dir / "second.svh").write_text(width_one, encoding="ascii")
            (workdir / "unit.sv").write_text(
                '`include "first.svh"\n'
                '`include "second.svh"\n'
                "module unit(input logic [`WIDTH-1:0] source, "
                "output logic [`WIDTH-1:0] sink); assign sink = source; endmodule\n",
                encoding="ascii",
            )
            frontend = FrontendLibrary(library)
            results = []
            for include_dirs in (
                (first_dir, second_dir),
                (second_dir, first_dir),
            ):
                args = [
                    "--lint-only",
                    "-Wno-fatal",
                    *(f"-I{path.as_posix()}" for path in include_dirs),
                    "unit.sv",
                    "--top-module",
                    "unit",
                ]
                with patch.dict(
                    os.environ,
                    {"MYFUZZ_FRONTEND_VERILATOR_ROOT": verilator_root.as_posix()},
                ):
                    results.append(frontend.facts(args, workdir))

        self.assertEqual(results[0]["ports"][0]["width"], 2)
        self.assertEqual(results[1]["ports"][0]["width"], 1)
        self.assertNotEqual(
            results[0]["tool"]["input_hash"],
            results[1]["tool"]["input_hash"],
        )

    def test_dataflow_crosses_internal_signals_and_is_name_independent(self) -> None:
        library = default_frontend_library(ROOT)
        self.assertTrue(library.exists(), f"frontend library not built: {library}")
        verilator_root = ROOT / "src" / "myfuzz" / "frontend" / "vendor" / "verilator"
        variants = (
            (
                "unit",
                "module unit(input logic ingress, output logic egress);\n"
                "  logic first_stage; logic second_stage;\n"
                "  assign first_stage = ingress;\n"
                "  assign second_stage = first_stage;\n"
                "  assign egress = second_stage;\n"
                "endmodule\n",
            ),
            (
                "renamed_unit",
                "module renamed_unit(input logic p, output logic q);\n"
                "  logic r; logic s;\n"
                "  assign r = p;\n"
                "  assign s = r;\n"
                "  assign q = s;\n"
                "endmodule\n",
            ),
        )
        results = []
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            frontend = FrontendLibrary(library)
            for index, (top, rtl) in enumerate(variants):
                source_dir = workdir / str(index)
                source_dir.mkdir()
                (source_dir / "unit.sv").write_text(rtl)
                args = ["--lint-only", "-Wno-fatal", "unit.sv", "--top-module", top]
                with patch.dict(
                    os.environ,
                    {"MYFUZZ_FRONTEND_VERILATOR_ROOT": verilator_root.as_posix()},
                ):
                    results.append(frontend.facts(args, source_dir))

        self.assertEqual(
            results[0]["dataflow_edges"],
            [{
                "id": 1,
                "module_id": 1,
                "source_id": 1,
                "target_id": 2,
                "kind": "assignment",
                "provenance": "rtl",
            }],
        )
        for section in (
            "modules",
            "ports",
            "instances",
            "pin_bindings",
            "expressions",
            "dataflow_edges",
            "control_edges",
        ):
            self.assertEqual(results[0][section], results[1][section], section)

    def test_hierarchy_pin_bindings_are_name_independent(self) -> None:
        library = default_frontend_library(ROOT)
        self.assertTrue(library.exists(), f"frontend library not built: {library}")
        verilator_root = ROOT / "src" / "myfuzz" / "frontend" / "vendor" / "verilator"
        variants = (
            (
                "root",
                "module leaf(input logic source, output logic sink);\n"
                "  assign sink = source;\n"
                "endmodule\n"
                "module root(input logic stimulus, output logic observed);\n"
                "  leaf child(.source(stimulus), .sink(observed));\n"
                "endmodule\n",
            ),
            (
                "renamed_root",
                "module renamed_leaf(input logic a, output logic b);\n"
                "  assign b = a;\n"
                "endmodule\n"
                "module renamed_root(input logic c, output logic d);\n"
                "  renamed_leaf renamed_child(.a(c), .b(d));\n"
                "endmodule\n",
            ),
        )
        results = []
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            frontend = FrontendLibrary(library)
            for index, (top, rtl) in enumerate(variants):
                source_dir = workdir / str(index)
                source_dir.mkdir()
                (source_dir / "unit.sv").write_text(rtl)
                args = ["--lint-only", "-Wno-fatal", "unit.sv", "--top-module", top]
                with patch.dict(
                    os.environ,
                    {"MYFUZZ_FRONTEND_VERILATOR_ROOT": verilator_root.as_posix()},
                ):
                    results.append(frontend.facts(args, source_dir))

        self.assertEqual(len(results[0]["instances"]), 1)
        self.assertEqual(len(results[0]["pin_bindings"]), 2)
        self.assertEqual(len(results[0]["expressions"]), 2)
        for section in (
            "modules",
            "ports",
            "instances",
            "pin_bindings",
            "expressions",
            "dataflow_edges",
            "control_edges",
        ):
            self.assertEqual(results[0][section], results[1][section], section)

    def test_source_symbols_preserve_reemittable_escaped_identifiers(self) -> None:
        library = default_frontend_library(ROOT)
        self.assertTrue(library.exists(), f"frontend library not built: {library}")
        verilator_root = ROOT / "src" / "myfuzz" / "frontend" / "vendor" / "verilator"
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            (workdir / "unit.sv").write_text(
                "module \\leaf.with.dot (input logic \\in.signal , "
                "output logic \\out-signal );\n"
                "  assign \\out-signal = \\in.signal ;\n"
                "endmodule\n"
                "module root(input logic source, output logic sink);\n"
                "  \\leaf.with.dot \\instance.with.dot "
                "(.\\in.signal (source), .\\out-signal (sink));\n"
                "endmodule\n"
            )
            args = ["--lint-only", "-Wno-fatal", "unit.sv", "--top-module", "root"]
            with patch.dict(
                os.environ,
                {"MYFUZZ_FRONTEND_VERILATOR_ROOT": verilator_root.as_posix()},
            ):
                facts = FrontendLibrary(library).facts(args, workdir)

        symbols = {
            (symbol["kind"], symbol["name"], symbol["original_name"])
            for symbol in facts["source_symbols"]
        }
        self.assertIn(
            ("module", "leaf__02ewith__02edot", "\\leaf.with.dot "),
            symbols,
        )
        self.assertIn(("port", "in__02esignal", "\\in.signal "), symbols)
        self.assertIn(("port", "out__02dsignal", "\\out-signal "), symbols)
        self.assertIn(
            ("instance", "instance__02ewith__02edot", "\\instance.with.dot "),
            symbols,
        )

    def test_sequential_facts_calls_do_not_accumulate_source_options(self) -> None:
        library = default_frontend_library(ROOT)
        self.assertTrue(library.exists(), f"frontend library not built: {library}")
        probe = textwrap.dedent(
            """
            import json
            from pathlib import Path
            import sys

            sys.path.insert(0, sys.argv[1])
            from frontend_api import FrontendLibrary

            frontend = FrontendLibrary(Path(sys.argv[2]))
            workdir = Path(sys.argv[3])
            first = frontend.facts(
                ["--lint-only", "-Wno-fatal", "first.sv", "--top-module", "first"],
                workdir,
            )
            second = frontend.facts(
                ["--lint-only", "-Wno-fatal", "second.sv", "--top-module", "second"],
                workdir,
            )
            print(json.dumps(first, sort_keys=True, separators=(",", ":")))
            print(json.dumps(second, sort_keys=True, separators=(",", ":")))
            """
        )
        isolated_probe = textwrap.dedent(
            """
            import json
            from pathlib import Path
            import sys

            sys.path.insert(0, sys.argv[1])
            from frontend_api import FrontendLibrary

            frontend = FrontendLibrary(Path(sys.argv[2]))
            workdir = Path(sys.argv[3])
            result = frontend.facts(
                ["--lint-only", "-Wno-fatal", "second.sv", "--top-module", "second"],
                workdir,
            )
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            """
        )
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            (workdir / "first.sv").write_text(
                '`include "first_defs.svh"\n'
                "module first(input logic [`FIRST_WIDTH-1:0] source, output logic sink); "
                "assign sink = source; endmodule\n"
            )
            (workdir / "second.sv").write_text(
                '`include "second_defs.svh"\n'
                "module second(input logic [`SECOND_WIDTH-1:0] source, output logic sink); "
                "assign sink = ~source; endmodule\n"
            )
            (workdir / "first_defs.svh").write_text("`define FIRST_WIDTH 2\n")
            (workdir / "second_defs.svh").write_text("`define SECOND_WIDTH 3\n")
            environment = os.environ.copy()
            environment["MYFUZZ_FRONTEND_VERILATOR_ROOT"] = (
                ROOT / "src" / "myfuzz" / "frontend" / "vendor" / "verilator"
            ).as_posix()
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    probe,
                    (ROOT / "src" / "myfuzz" / "scripts").as_posix(),
                    library.as_posix(),
                    workdir.as_posix(),
                ],
                cwd=workdir,
                env=environment,
                capture_output=True,
                check=False,
                text=True,
            )
            isolated = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    isolated_probe,
                    (ROOT / "src" / "myfuzz" / "scripts").as_posix(),
                    library.as_posix(),
                    workdir.as_posix(),
                ],
                cwd=workdir,
                env=environment,
                capture_output=True,
                check=False,
                text=True,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(isolated.returncode, 0, isolated.stderr)
        self.assertNotIn("MODDUP", result.stderr)
        first, second = map(json.loads, result.stdout.splitlines())
        self.assertEqual(second, json.loads(isolated.stdout))
        self.assertEqual(len(first["modules"]), 1)
        self.assertEqual(len(second["modules"]), 1)
        self.assertEqual(
            [symbol["name"] for symbol in first["source_symbols"] if symbol["kind"] == "module"],
            ["first"],
        )
        self.assertEqual(
            [symbol["name"] for symbol in second["source_symbols"] if symbol["kind"] == "module"],
            ["second"],
        )

    def test_syntax_error_returns_through_c_abi_and_next_call_succeeds(self) -> None:
        library = default_frontend_library(ROOT)
        self.assertTrue(library.exists(), f"frontend library not built: {library}")
        probe = textwrap.dedent(
            """
            import json
            from pathlib import Path
            import sys

            sys.path.insert(0, sys.argv[1])
            from frontend_api import FrontendLibrary

            frontend = FrontendLibrary(Path(sys.argv[2]))
            workdir = Path(sys.argv[3])
            source = workdir / "unit.sv"
            args = ["--lint-only", "-Wno-fatal", source.name, "--top-module", "unit"]
            try:
                frontend.facts(args, workdir)
            except RuntimeError as error:
                print("caught:" + str(error))
            else:
                raise SystemExit("syntax error unexpectedly succeeded")

            source.write_text(
                "module unit(input logic source, output logic sink); "
                "assign sink = source; endmodule\\n",
                encoding="ascii",
            )
            facts = frontend.facts(args, workdir)
            print(json.dumps(facts["tool"], sort_keys=True))
            """
        )
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            (workdir / "unit.sv").write_text(
                "module unit(input logic source, output logic sink) "
                "assign sink = source; endmodule\n",
                encoding="ascii",
            )
            environment = os.environ.copy()
            environment["MYFUZZ_FRONTEND_VERILATOR_ROOT"] = (
                ROOT / "src" / "myfuzz" / "frontend" / "vendor" / "verilator"
            ).as_posix()
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    probe,
                    (ROOT / "src" / "myfuzz" / "scripts").as_posix(),
                    library.as_posix(),
                    workdir.as_posix(),
                ],
                cwd=workdir,
                env=environment,
                capture_output=True,
                check=False,
                text=True,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.splitlines()[0].startswith("caught:"), result.stdout)
        self.assertEqual(
            json.loads(result.stdout.splitlines()[1])["frontend"],
            "myfuzz-verilator-frontend",
        )

    def test_concurrent_facts_and_composition_calls_share_one_coordinator(self) -> None:
        library = default_frontend_library(ROOT)
        self.assertTrue(library.exists(), f"frontend library not built: {library}")
        probe = textwrap.dedent(
            """
            from concurrent.futures import ThreadPoolExecutor
            import json
            from pathlib import Path
            import sys
            import threading

            sys.path.insert(0, sys.argv[1])
            sys.path.insert(0, sys.argv[2])
            sys.path.insert(0, (Path(sys.argv[2]) / "src").as_posix())
            from frontend_api import FrontendLibrary
            from tests.frontend.test_ast_builder_smoke import composition_fixture, emitter_symbols

            frontend = FrontendLibrary(Path(sys.argv[3]))
            workdir = Path(sys.argv[4])
            args = ["--lint-only", "-Wno-fatal", "unit.sv", "--top-module", "unit"]
            document = composition_fixture()
            symbols = emitter_symbols(document)
            start = threading.Barrier(5)

            def facts_worker():
                start.wait()
                return [frontend.facts(args, workdir)["tool"]["input_hash"] for _ in range(4)]

            def composition_worker():
                start.wait()
                return [frontend.composition(document, symbols)["validation"]["width"] for _ in range(4)]

            with ThreadPoolExecutor(max_workers=4) as pool:
                futures = [
                    pool.submit(facts_worker),
                    pool.submit(facts_worker),
                    pool.submit(composition_worker),
                    pool.submit(composition_worker),
                ]
                start.wait()
                results = [future.result() for future in futures]
            print(json.dumps(results, sort_keys=True))
            """
        )
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            (workdir / "unit.sv").write_text(
                "module unit(input logic source, output logic sink); "
                "assign sink = source; endmodule\n",
                encoding="ascii",
            )
            environment = os.environ.copy()
            environment["MYFUZZ_FRONTEND_VERILATOR_ROOT"] = (
                ROOT / "src" / "myfuzz" / "frontend" / "vendor" / "verilator"
            ).as_posix()
            environment["VERILATOR_ROOT"] = environment["MYFUZZ_FRONTEND_VERILATOR_ROOT"]
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    probe,
                    (ROOT / "src" / "myfuzz" / "scripts").as_posix(),
                    ROOT.as_posix(),
                    library.as_posix(),
                    workdir.as_posix(),
                ],
                cwd=workdir,
                env=environment,
                capture_output=True,
                check=False,
                text=True,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        values = json.loads(result.stdout)
        self.assertEqual(len(values), 4)
        self.assertTrue(all(len(value) == 4 for value in values))

    def test_unsupported_ref_port_fails_without_poisoning_the_next_call(self) -> None:
        library = default_frontend_library(ROOT)
        self.assertTrue(library.exists(), f"frontend library not built: {library}")
        verilator_root = ROOT / "src" / "myfuzz" / "frontend" / "vendor" / "verilator"
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            source = workdir / "unit.sv"
            source.write_text("module unit(ref logic value); endmodule\n")
            frontend = FrontendLibrary(library)
            args = ["--lint-only", "-Wno-fatal", source.name, "--top-module", "unit"]
            with patch.dict(
                os.environ,
                {"MYFUZZ_FRONTEND_VERILATOR_ROOT": verilator_root.as_posix()},
            ):
                with self.assertRaisesRegex(RuntimeError, "unsupported port direction"):
                    frontend.facts(args, workdir)
                source.write_text(
                    "module unit(input logic source, output logic sink); "
                    "assign sink = source; endmodule\n"
                )
                facts = frontend.facts(args, workdir)

        validate_contract(facts, "hdl_facts.v2")


if __name__ == "__main__":
    unittest.main()
