#!/usr/bin/env python3
"""Version-matched V3EmitV smoke and generated-top reparse gate."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from myfuzz.scripts.frontend_api import FrontendLibrary, default_frontend_library
from tests.frontend.test_ast_builder_smoke import (
    CompositionAstLibrary,
    composition_fixture,
    emitter_symbols,
)


ROOT = Path(__file__).resolve().parents[2]


class CompositionEmitterSmokeTest(unittest.TestCase):
    def test_v3emitv_includes_output_formatter_declarations(self) -> None:
        source = (
            ROOT
            / "src"
            / "myfuzz"
            / "frontend"
            / "vendor"
            / "verilator"
            / "src"
            / "V3EmitV.cpp"
        ).read_text(encoding="utf-8")

        self.assertIn('#include "V3File.h"', source)

    def test_v3emitv_emits_only_top_and_reparses_with_original_duts(self) -> None:
        document = composition_fixture()
        document["adapters"] = [
            {
                "edge_id": 501,
                "kind": "identity",
                "source_endpoint_id": 10001,
                "target_endpoint_id": 20001,
            }
        ]
        symbols = emitter_symbols(document)
        for symbol in symbols:
            if symbol["entity_id"] == 11:
                symbol["name"] = "leaf__02ewith__02edot"
                symbol["original_name"] = "\\leaf.with.dot "
            elif symbol["entity_id"] == 101:
                symbol["name"] = "out__02dsignal"
                symbol["original_name"] = "\\out-signal "
        _, result = CompositionAstLibrary().build(document, symbols)
        emitted = result["source_text"]

        self.assertTrue(
            emitted.startswith("module composition_top (external_111, external_211);\n"),
            emitted,
        )
        self.assertNotIn("AstModule:", emitted)
        self.assertNotIn("module \\leaf.with.dot", emitted)
        self.assertNotIn("module opaque_module_22", emitted)
        self.assertIn("\\leaf.with.dot  instance_1001", emitted)
        self.assertIn(".\\out-signal (net_301)", emitted)
        self.assertIn("assign adapter_501_net_301_sink_201 = net_301;", emitted)

        library = default_frontend_library(ROOT)
        verilator_root = ROOT / "src" / "myfuzz" / "frontend" / "vendor" / "verilator"
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            (workdir / "dut.sv").write_text(
                "module \\leaf.with.dot (output logic [7:0] \\out-signal , "
                "input logic opaque_port_111);\n"
                "  assign \\out-signal = {8{opaque_port_111}};\n"
                "endmodule\n"
                "module opaque_module_22(input logic [7:0] opaque_port_201, "
                "input logic opaque_port_211);\n"
                "  logic observed;\n"
                "  assign observed = ^opaque_port_201 ^ opaque_port_211;\n"
                "endmodule\n",
                encoding="ascii",
            )
            (workdir / "generated_top.sv").write_text(emitted, encoding="ascii")
            args = [
                "--lint-only",
                "-Wno-fatal",
                "dut.sv",
                "generated_top.sv",
                "--top-module",
                "composition_top",
            ]
            with patch.dict(
                os.environ,
                {"MYFUZZ_FRONTEND_VERILATOR_ROOT": verilator_root.as_posix()},
            ):
                facts = FrontendLibrary(library).facts(args, workdir)

        module_names = {
            symbol["name"]
            for symbol in facts["source_symbols"]
            if symbol["kind"] == "module"
        }
        self.assertEqual(
            module_names,
            {"composition_top", "leaf__02ewith__02edot", "opaque_module_22"},
        )


if __name__ == "__main__":
    unittest.main()
