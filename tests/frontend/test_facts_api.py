#!/usr/bin/env python3
"""Smoke test for the standalone elaborated RTL facts ABI."""

from __future__ import annotations

import ctypes
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, (ROOT / "src" / "myfuzz" / "scripts").as_posix())

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
                "module root(input logic [3:0] stimulus, output logic observed);\n"
                "  logic branch_signal;\n"
                "  leaf u0(.source(stimulus), .sink(observed));\n"
                "  always_comb if (stimulus[0]) branch_signal = 1'b1; else branch_signal = 1'b0;\n"
                "endmodule\n"
            )
            flist = workdir / "files.f"
            flist.write_text(source.name + "\n")
            args = ["--lint-only", "-Wno-fatal", "-f", flist.name, "--top-module", "root"]
            facts = FrontendLibrary(library).facts(args, workdir)

        self.assertEqual(facts["schema_version"], "hdl_facts.v2")
        for key in ("tool", "pin_bindings", "expressions", "dataflow_edges", "control_edges",
                    "clock_reset_checks", "local_address_facts", "diagnostics"):
            self.assertIn(key, facts)
        modules = {module["name"]: module for module in facts["modules"]}
        self.assertIn("root", modules)
        self.assertIn("leaf", modules)
        self.assertEqual(modules["root"]["ports"][0]["width"], 4)
        self.assertEqual(modules["root"]["instances"][0]["child"], "leaf")
        self.assertTrue(modules["root"]["branches"])


if __name__ == "__main__":
    unittest.main()
