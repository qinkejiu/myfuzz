#!/usr/bin/env python3
"""Smoke tests for the composition_ir.v1 to Verilator AST C ABI."""

from __future__ import annotations

import ctypes
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

from myfuzz.composition.ir import composition_ir
from myfuzz.composition.search import compose_topk
from tests.composition.test_search import design


ROOT = Path(__file__).resolve().parents[2]
LIBRARY = ROOT / "src" / "myfuzz" / "frontend" / "build" / "libmyfuzz_frontend.so"


def build_in_subprocess(document: dict[str, object]) -> subprocess.CompletedProcess[bytes]:
    script = r"""
import ctypes
import json
import sys

library = ctypes.CDLL(sys.argv[1])
library.myfuzz_frontend_composition_json.argtypes = [ctypes.c_char_p]
library.myfuzz_frontend_composition_json.restype = ctypes.c_void_p
library.myfuzz_frontend_free.argtypes = [ctypes.c_void_p]
library.myfuzz_frontend_last_error.restype = ctypes.c_char_p
result = library.myfuzz_frontend_composition_json(sys.stdin.buffer.read())
if not result:
    detail = library.myfuzz_frontend_last_error()
    sys.stdout.write(json.dumps({"last_error": detail.decode("utf-8") if detail else ""}))
    raise SystemExit(2)
try:
    sys.stdout.buffer.write(ctypes.string_at(result))
finally:
    library.myfuzz_frontend_free(result)
"""
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return subprocess.run(
        [sys.executable, "-c", script, str(LIBRARY)],
        input=payload,
        capture_output=True,
        check=False,
    )


def composition_fixture() -> dict[str, object]:
    return {
        "schema_version": "composition_ir.v1",
        "candidate_id": "candidate-000",
        "parent_input_hash": "sha256:" + "0" * 64,
        "graph_hash": "sha256:" + "1" * 64,
        "components": [
            {"id": 1001, "module_id": 11, "role": "initiator"},
            {"id": 2001, "module_id": 22, "role": "target"},
        ],
        "instances": [
            {"id": 1001, "component_id": 1001, "module_id": 11, "role": "initiator"},
            {"id": 2001, "component_id": 2001, "module_id": 22, "role": "target"},
        ],
        "nets": [
            {
                "id": 301,
                "source_port_id": 101,
                "sink_port_ids": [201],
                "semantic_role": "request.data",
            }
        ],
        "endpoint_bindings": [
            {
                "endpoint_id": 10001,
                "component_id": 1001,
                "protocol_id": "bus",
                "side": "initiator",
                "fields": [
                    {
                        "field_role": "request.data",
                        "port_id": 101,
                        "direction": "output",
                        "width": 8,
                    }
                ],
            },
            {
                "endpoint_id": 20001,
                "component_id": 2001,
                "protocol_id": "bus",
                "side": "target",
                "fields": [
                    {
                        "field_role": "request.data",
                        "port_id": 201,
                        "direction": "input",
                        "width": 8,
                    }
                ],
            },
        ],
        "adapters": [],
        "address_regions": [],
        "clock_domains": [
            {
                "component_id": 1001,
                "port_id": 111,
                "domain_id": 7,
                "active_level": "high",
                "synchronous": True,
            },
            {
                "component_id": 2001,
                "port_id": 211,
                "domain_id": 7,
                "active_level": "high",
                "synchronous": True,
            },
        ],
        "reset_domains": [],
        "external_ports": [
            {
                "port_id": 111,
                "component_id": 1001,
                "direction": "input",
                "width": 1,
                "semantic_role": "clock",
            },
            {
                "port_id": 211,
                "component_id": 2001,
                "direction": "input",
                "width": 1,
                "semantic_role": "clock",
            },
        ],
        "unresolved_optional_endpoints": [],
        "evidence": [],
        "assumptions": [],
        "rejected_alternatives": [],
        "score_vector": [0, 0, 0, 0, 0, 0, 0, 0],
        "diagnostics": {"errors": [], "warnings": []},
    }


def emitter_symbols(document: dict[str, object]) -> list[dict[str, object]]:
    """Build the opaque frontend sidecar consumed only at the emitter boundary."""
    module_ids = {
        int(component["module_id"])
        for component in document["components"]
    }
    port_ids: set[int] = set()
    for binding in document["endpoint_bindings"]:
        port_ids.update(int(field["port_id"]) for field in binding["fields"])
    for section in ("clock_domains", "reset_domains", "external_ports"):
        port_ids.update(int(item["port_id"]) for item in document[section])
    return [
        *(
            {
                "entity_id": module_id,
                "kind": "module",
                "name": f"opaque_module_{module_id}",
                "original_name": f"opaque_module_{module_id}",
            }
            for module_id in sorted(module_ids)
        ),
        *(
            {
                "entity_id": port_id,
                "kind": "port",
                "name": f"opaque_port_{port_id}",
                "original_name": f"opaque_port_{port_id}",
            }
            for port_id in sorted(port_ids)
        ),
    ]


class CompositionAstLibrary:
    def __init__(self) -> None:
        self.library = ctypes.CDLL(LIBRARY)
        self.library.myfuzz_frontend_composition_json.argtypes = [ctypes.c_char_p]
        self.library.myfuzz_frontend_composition_json.restype = ctypes.c_void_p
        self.library.myfuzz_frontend_composition_with_symbols_json.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]
        self.library.myfuzz_frontend_composition_with_symbols_json.restype = ctypes.c_void_p
        self.library.myfuzz_frontend_free.argtypes = [ctypes.c_void_p]
        self.library.myfuzz_frontend_last_error.restype = ctypes.c_char_p

    def build(
        self,
        document: dict[str, object],
        source_symbols: list[dict[str, object]] | None = None,
    ) -> tuple[bytes, dict[str, object]]:
        payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        symbols = json.dumps(
            source_symbols if source_symbols is not None else emitter_symbols(document),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        result = self.library.myfuzz_frontend_composition_with_symbols_json(payload, symbols)
        if not result:
            detail = self.library.myfuzz_frontend_last_error()
            self.fail(detail.decode("utf-8") if detail else "composition ABI returned null")
        try:
            raw = ctypes.string_at(result)
        finally:
            self.library.myfuzz_frontend_free(result)
        return raw, json.loads(raw)

    def build_without_symbols(
        self, document: dict[str, object]
    ) -> tuple[bytes, dict[str, object]]:
        payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        result = self.library.myfuzz_frontend_composition_json(payload)
        if not result:
            detail = self.library.myfuzz_frontend_last_error()
            self.fail(detail.decode("utf-8") if detail else "composition ABI returned null")
        try:
            raw = ctypes.string_at(result)
        finally:
            self.library.myfuzz_frontend_free(result)
        return raw, json.loads(raw)

    def fail(self, detail: str) -> None:
        raise AssertionError(detail)


class CompositionAstBuilderSmokeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not LIBRARY.exists():
            raise AssertionError(f"frontend library not built: {LIBRARY}")
        cls.frontend = CompositionAstLibrary()

    def test_builds_deterministic_source_like_ast_structure(self) -> None:
        document = composition_fixture()

        first_raw, result = self.frontend.build(document)
        second_raw, _ = self.frontend.build(document)

        self.assertEqual(first_raw, second_raw)
        self.assertEqual(result["schema_version"], "composition_build_result.v1")
        self.assertEqual(result["diagnostics"], {"errors": [], "warnings": []})
        self.assertEqual(
            result["validation"],
            {
                "dtype": True,
                "link": True,
                "pin": True,
                "unknown_width_ports": [],
                "width": True,
            },
        )
        self.assertEqual(
            result["ast"]["node_counts"],
            {
                "AstAssignW": 0,
                "AstCell": 2,
                "AstModule": 4,
                "AstPin": 4,
                "AstVar": 7,
                "AstVarRef": 4,
            },
        )
        self.assertEqual(
            result["ast"]["module"],
            {"name": "composition_top", "node_type": "AstModule"},
        )
        self.assertEqual(
            [(cell["name"], cell["module"], cell["node_type"]) for cell in result["ast"]["cells"]],
            [
                ("instance_1001", "opaque_module_11", "AstCell"),
                ("instance_2001", "opaque_module_22", "AstCell"),
            ],
        )
        self.assertEqual(
            [
                (pin["port_id"], pin["signal"], pin["node_type"], pin["expression_type"])
                for cell in result["ast"]["cells"]
                for pin in cell["pins"]
            ],
            [
                (101, "net_301", "AstPin", "AstVarRef"),
                (111, "external_111", "AstPin", "AstVarRef"),
                (201, "net_301", "AstPin", "AstVarRef"),
                (211, "external_211", "AstPin", "AstVarRef"),
            ],
        )
        self.assertEqual(
            [(var["name"], var["kind"], var["node_type"]) for var in result["ast"]["variables"]],
            [
                ("net_301", "net", "AstVar"),
                ("external_111", "external_port", "AstVar"),
                ("external_211", "external_port", "AstVar"),
            ],
        )
        self.assertIn("module composition_top", result["source_text"])
        self.assertIn("opaque_module_11 instance_1001", result["source_text"])
        self.assertIn(".opaque_port_101(net_301)", result["source_text"])
        self.assertNotIn("module opaque_module_11", result["source_text"])
        self.assertNotIn("module opaque_module_22", result["source_text"])
        self.assertNotIn("AstModule:", result["source_text"])

    def test_emits_original_escaped_module_and_port_names(self) -> None:
        document = composition_fixture()
        symbols = emitter_symbols(document)
        for symbol in symbols:
            if symbol["entity_id"] == 11:
                symbol["name"] = "leaf__02ewith__02edot"
                symbol["original_name"] = "\\leaf.with.dot "
            elif symbol["entity_id"] == 101:
                symbol["name"] = "out__02dsignal"
                symbol["original_name"] = "\\out-signal "

        _, result = self.frontend.build(document, symbols)

        self.assertEqual(result["diagnostics"]["errors"], [])
        self.assertIn("\\leaf.with.dot  instance_1001", result["source_text"])
        self.assertIn(".\\out-signal (net_301)", result["source_text"])

    def test_source_text_never_declares_empty_dut_shells(self) -> None:
        document = composition_fixture()
        document["nets"] = []
        document["endpoint_bindings"] = []
        document["clock_domains"] = []
        document["reset_domains"] = []
        document["external_ports"] = []

        _, result = self.frontend.build(document)

        self.assertEqual(result["diagnostics"]["errors"], [])
        self.assertNotIn("module opaque_module_11", result["source_text"])
        self.assertNotIn("module opaque_module_22", result["source_text"])
        self.assertIn("opaque_module_11 instance_1001 ();", result["source_text"])
        self.assertIn("opaque_module_22 instance_2001 ();", result["source_text"])

    def test_rejects_build_without_emitter_source_symbols(self) -> None:
        _, result = self.frontend.build_without_symbols(composition_fixture())

        self.assertEqual(
            {diagnostic["code"] for diagnostic in result["diagnostics"]["errors"]},
            {"missing-source-symbol"},
        )
        self.assertIsNone(result["ast"]["module"])

    def test_rejects_net_without_any_sink(self) -> None:
        document = composition_fixture()
        document["nets"][0]["sink_port_ids"] = []

        _, result = self.frontend.build(document)

        self.assertEqual(
            [diagnostic["code"] for diagnostic in result["diagnostics"]["errors"]],
            ["missing-net-sink"],
        )
        self.assertIsNone(result["ast"]["module"])

    def test_cdc_requires_explicit_adapter_capability(self) -> None:
        document = composition_fixture()
        document["clock_domains"][1]["domain_id"] = 8
        document["adapters"] = [
            {
                "edge_id": 501,
                "kind": "async_fifo",
                "source_endpoint_id": 10001,
                "target_endpoint_id": 20001,
            }
        ]

        _, implicit = self.frontend.build(document)
        self.assertEqual(
            [diagnostic["code"] for diagnostic in implicit["diagnostics"]["errors"]],
            ["undeclared-cdc"],
        )

        document["adapters"][0]["allows_cdc"] = True
        _, explicit = self.frontend.build(document)
        self.assertEqual(explicit["diagnostics"]["errors"], [])

    def test_reports_required_hard_constraint_diagnostics(self) -> None:
        cases: list[tuple[str, dict[str, object], str]] = []

        undeclared = composition_fixture()
        undeclared["nets"][0]["sink_port_ids"] = [999]
        cases.append(("undeclared port", undeclared, "undeclared-port"))

        multiple = composition_fixture()
        multiple["endpoint_bindings"][0]["fields"].append(
            {
                "field_role": "request.data",
                "port_id": 102,
                "direction": "output",
                "width": 8,
            }
        )
        multiple["nets"].append(
            {
                "id": 302,
                "source_port_id": 102,
                "sink_port_ids": [201],
                "semantic_role": "request.data",
            }
        )
        cases.append(("multiple drivers", multiple, "multiple-drivers"))

        width = composition_fixture()
        width["endpoint_bindings"][0]["fields"][0]["width"] = 8
        width["endpoint_bindings"][1]["fields"][0]["width"] = 4
        cases.append(("width mismatch", width, "incompatible-width"))

        cdc = composition_fixture()
        cdc["clock_domains"][1]["domain_id"] = 8
        cases.append(("undeclared CDC", cdc, "undeclared-cdc"))

        for label, document, expected_code in cases:
            with self.subTest(label=label):
                first_raw, result = self.frontend.build(document)
                second_raw, _ = self.frontend.build(document)
                self.assertEqual(first_raw, second_raw)
                self.assertEqual(
                    [diagnostic["code"] for diagnostic in result["diagnostics"]["errors"]],
                    [expected_code],
                )
                diagnostic = result["diagnostics"]["errors"][0]
                self.assertIsInstance(diagnostic["path"], str)
                self.assertTrue(diagnostic["related_ids"])
                self.assertEqual(
                    result["validation"],
                    {
                        "dtype": False,
                        "link": False,
                        "pin": False,
                        "unknown_width_ports": [],
                        "width": False,
                    },
                )

    def test_rejects_one_source_port_assigned_to_distinct_nets(self) -> None:
        document = composition_fixture()
        document["endpoint_bindings"][0]["fields"][0].update(
            {"direction": "output", "width": 8}
        )
        document["endpoint_bindings"][1]["fields"][0].update(
            {"direction": "input", "width": 8}
        )
        document["endpoint_bindings"][1]["fields"].append(
            {
                "field_role": "request.extra",
                "port_id": 202,
                "direction": "input",
                "width": 8,
            }
        )
        document["nets"].append(
            {
                "id": 302,
                "source_port_id": 101,
                "sink_port_ids": [202],
                "semantic_role": "request.extra",
            }
        )

        first_raw, result = self.frontend.build(document)
        second_raw, _ = self.frontend.build(document)

        self.assertEqual(first_raw, second_raw)
        self.assertEqual(
            [diagnostic["code"] for diagnostic in result["diagnostics"]["errors"]],
            ["source-port-multiple-nets"],
        )
        self.assertIsNone(result["ast"]["module"])

    def test_rejects_non_bijective_component_instance_cardinality(self) -> None:
        cases: list[tuple[str, dict[str, object], list[int]]] = []

        multiple = composition_fixture()
        multiple["instances"].append(
            {"id": 1002, "component_id": 1001, "module_id": 11, "role": "initiator"}
        )
        cases.append(("multiple", multiple, [1001, 1002]))

        missing = composition_fixture()
        missing["instances"] = [missing["instances"][0]]
        cases.append(("missing", missing, [2001]))

        for label, document, related_ids in cases:
            with self.subTest(label=label):
                first_raw, result = self.frontend.build(document)
                second_raw, _ = self.frontend.build(document)
                self.assertEqual(first_raw, second_raw)
                self.assertEqual(
                    [
                        diagnostic["code"]
                        for diagnostic in result["diagnostics"]["errors"]
                    ],
                    ["component-instance-cardinality"],
                )
                self.assertEqual(
                    result["diagnostics"]["errors"][0]["related_ids"], related_ids
                )
                self.assertIsNone(result["ast"]["module"])

    def test_rejects_multiple_components_for_one_module_representation(self) -> None:
        document = composition_fixture()
        document["components"][1]["module_id"] = 11
        document["instances"][1]["module_id"] = 11

        first_raw, result = self.frontend.build(document)
        second_raw, _ = self.frontend.build(document)

        self.assertEqual(first_raw, second_raw)
        self.assertEqual(
            [diagnostic["code"] for diagnostic in result["diagnostics"]["errors"]],
            ["duplicate-module-representation"],
        )
        self.assertEqual(
            result["diagnostics"]["errors"][0]["related_ids"], [11, 1001, 2001]
        )
        self.assertIsNone(result["ast"]["module"])

    def test_rejects_duplicate_stable_ids_and_unresolved_references(self) -> None:
        cases: list[tuple[str, dict[str, object], str]] = []

        duplicate_adapter = composition_fixture()
        duplicate_adapter["endpoint_bindings"].extend(
            [
                {
                    "endpoint_id": 10002,
                    "component_id": 1001,
                    "protocol_id": "bus",
                    "side": "initiator",
                    "fields": [
                        {
                            "field_role": "request.extra",
                            "port_id": 102,
                            "direction": "output",
                            "width": 8,
                        }
                    ],
                },
                {
                    "endpoint_id": 20002,
                    "component_id": 2001,
                    "protocol_id": "bus",
                    "side": "target",
                    "fields": [
                        {
                            "field_role": "request.extra",
                            "port_id": 202,
                            "direction": "input",
                            "width": 8,
                        }
                    ],
                },
            ]
        )
        duplicate_adapter["adapters"] = [
            {
                "edge_id": 501,
                "kind": "first",
                "source_endpoint_id": 10001,
                "target_endpoint_id": 20001,
            },
            {
                "edge_id": 501,
                "kind": "second",
                "source_endpoint_id": 10002,
                "target_endpoint_id": 20002,
            },
        ]
        cases.append(("adapter ID", duplicate_adapter, "duplicate-adapter"))

        duplicate_endpoint = composition_fixture()
        duplicate_endpoint["endpoint_bindings"].append(
            json.loads(json.dumps(duplicate_endpoint["endpoint_bindings"][0]))
        )
        cases.append(("endpoint ID", duplicate_endpoint, "duplicate-endpoint"))

        duplicate_field = composition_fixture()
        duplicate_field["endpoint_bindings"][0]["fields"].append(
            json.loads(
                json.dumps(duplicate_field["endpoint_bindings"][0]["fields"][0])
            )
        )
        cases.append(("endpoint field", duplicate_field, "duplicate-endpoint-field"))

        duplicate_external = composition_fixture()
        duplicate_external["external_ports"].append(
            json.loads(json.dumps(duplicate_external["external_ports"][0]))
        )
        cases.append(("external port", duplicate_external, "duplicate-external-port"))

        unresolved_adapter = composition_fixture()
        unresolved_adapter["adapters"] = [
            {
                "edge_id": 501,
                "kind": "declared",
                "source_endpoint_id": 99999,
                "target_endpoint_id": 20001,
            }
        ]
        cases.append(
            ("adapter endpoint", unresolved_adapter, "undeclared-adapter-endpoint")
        )

        unresolved_binding = composition_fixture()
        unresolved_binding["endpoint_bindings"].append(
            {
                "endpoint_id": 30001,
                "component_id": 9999,
                "protocol_id": "bus",
                "side": "target",
                "fields": [],
            }
        )
        cases.append(("binding component", unresolved_binding, "undeclared-component"))

        for label, document, expected_code in cases:
            with self.subTest(label=label):
                first_raw, result = self.frontend.build(document)
                second_raw, _ = self.frontend.build(document)
                self.assertEqual(first_raw, second_raw)
                self.assertEqual(
                    [
                        diagnostic["code"]
                        for diagnostic in result["diagnostics"]["errors"]
                    ],
                    [expected_code],
                )
                self.assertIsNone(result["ast"]["module"])

    def test_net_width_resolves_connected_port_widths_before_ast_construction(self) -> None:
        document = composition_fixture()
        del document["endpoint_bindings"][0]["fields"][0]["width"]
        del document["endpoint_bindings"][1]["fields"][0]["width"]
        document["nets"][0]["width"] = 8

        _, result = self.frontend.build(document)

        self.assertEqual(result["diagnostics"], {"errors": [], "warnings": []})
        self.assertEqual(
            result["validation"],
            {
                "dtype": True,
                "link": True,
                "pin": True,
                "unknown_width_ports": [],
                "width": True,
            },
        )
        self.assertIn("logic [7:0]  net_301", result["source_text"])
        self.assertIn(".opaque_port_101(net_301)", result["source_text"])
        self.assertIn(".opaque_port_201(net_301)", result["source_text"])
        self.assertEqual(
            next(
                variable["declared_width"]
                for variable in result["ast"]["variables"]
                if variable["name"] == "net_301"
            ),
            8,
        )

    def test_unknown_widths_short_circuit_before_ast_passes(self) -> None:
        cases: list[tuple[str, dict[str, object], list[int]]] = []

        connected = composition_fixture()
        del connected["endpoint_bindings"][0]["fields"][0]["width"]
        del connected["endpoint_bindings"][1]["fields"][0]["width"]
        cases.append(("connected", connected, [101, 201]))

        one_sided = composition_fixture()
        del one_sided["endpoint_bindings"][1]["fields"][0]["width"]
        cases.append(("one-sided", one_sided, [201]))

        disconnected = composition_fixture()
        disconnected["endpoint_bindings"][0]["fields"].append(
            {
                "field_role": "request.unconnected",
                "port_id": 102,
                "direction": "input",
            }
        )
        cases.append(("disconnected", disconnected, [102]))

        for label, document, unknown_ports in cases:
            with self.subTest(label=label):
                first_raw, result = self.frontend.build(document)
                second_raw, _ = self.frontend.build(document)
                self.assertEqual(first_raw, second_raw)
                self.assertEqual(result["diagnostics"], {"errors": [], "warnings": []})
                self.assertEqual(result["source_text"], "")
                self.assertIsNone(result["ast"]["module"])
                self.assertEqual(
                    result["validation"],
                    {
                        "dtype": False,
                        "link": False,
                        "pin": False,
                        "unknown_width_ports": unknown_ports,
                        "width": False,
                    },
                )

    def test_rejects_explicit_net_width_conflicting_with_source_port(self) -> None:
        document = composition_fixture()
        document["nets"][0]["width"] = 4

        first_raw, result = self.frontend.build(document)
        second_raw, _ = self.frontend.build(document)

        self.assertEqual(first_raw, second_raw)
        self.assertEqual(
            [diagnostic["code"] for diagnostic in result["diagnostics"]["errors"]],
            ["incompatible-width"],
        )
        self.assertIsNone(result["ast"]["module"])

    def test_rejects_invalid_field_and_external_directions(self) -> None:
        cases: list[tuple[str, dict[str, object]]] = []

        field = composition_fixture()
        field["endpoint_bindings"][0]["fields"][0]["direction"] = "sideways"
        cases.append(("field", field))

        external = composition_fixture()
        external["external_ports"][0]["direction"] = "sideways"
        cases.append(("external", external))

        for label, document in cases:
            with self.subTest(label=label):
                first_raw, result = self.frontend.build(document)
                second_raw, _ = self.frontend.build(document)
                self.assertEqual(first_raw, second_raw)
                self.assertEqual(
                    [
                        diagnostic["code"]
                        for diagnostic in result["diagnostics"]["errors"]
                    ],
                    ["invalid-direction"],
                )
                self.assertIsNone(result["ast"]["module"])

    def test_disconnected_field_without_direction_never_terminates_c_abi_process(self) -> None:
        document = composition_fixture()
        document["endpoint_bindings"][0]["fields"].append(
            {
                "field_role": "request.unconnected",
                "port_id": 102,
                "width": 8,
            }
        )

        first = build_in_subprocess(document)
        second = build_in_subprocess(document)

        self.assertEqual(first.returncode, 0, first.stderr.decode("utf-8", errors="replace"))
        self.assertEqual(second.returncode, 0, second.stderr.decode("utf-8", errors="replace"))
        self.assertEqual(first.stdout, second.stdout)
        result = json.loads(first.stdout)
        self.assertEqual(
            [diagnostic["code"] for diagnostic in result["diagnostics"]["errors"]],
            ["missing-direction"],
        )
        self.assertIsNone(result["ast"]["module"])

    def test_public_cpp_builder_rejects_overlapping_live_trees_and_recovers(self) -> None:
        source = textwrap.dedent(
            r"""
            #include "MyFuzzCompositionAstBuilder.h"

            #include <exception>
            #include <iostream>

            myfuzz::CompositionIr fixture() {
                myfuzz::CompositionIr ir;
                ir.components = {{1001, 11}, {2001, 22}};
                ir.instances = {{1001, 1001, 11}, {2001, 2001, 22}};

                myfuzz::CompositionEndpointField source;
                source.role = "request.data";
                source.portId = 101;
                source.width = 8;
                source.direction = "output";
                myfuzz::CompositionEndpointField sink;
                sink.role = "request.data";
                sink.portId = 201;
                sink.width = 8;
                sink.direction = "input";
                ir.endpointBindings = {{10001, 1001, {source}}, {20001, 2001, {sink}}};
                ir.nets = {{301, 101, {201}, std::nullopt}};
                return ir;
            }

            int main() {
                const myfuzz::CompositionIr ir = fixture();
                const std::vector<myfuzz::CompositionSourceSymbol> symbols{
                    {11, "module", "opaque_module_11", "opaque_module_11"},
                    {22, "module", "opaque_module_22", "opaque_module_22"},
                    {101, "port", "opaque_port_101", "opaque_port_101"},
                    {201, "port", "opaque_port_201", "opaque_port_201"},
                };
                {
                    myfuzz::CompositionBuildResult first = myfuzz::buildCompositionAst(ir, symbols);
                    if (!first.tree) return 10;
                    try {
                        myfuzz::CompositionBuildResult second = myfuzz::buildCompositionAst(ir, symbols);
                        (void)second;
                        return 11;
                    } catch (const std::exception& error) {
                        std::cout << error.what() << '\n';
                    }
                }
                myfuzz::CompositionBuildResult recovered = myfuzz::buildCompositionAst(ir, symbols);
                if (!recovered.tree) return 12;
                std::cout << "recovered\n";
                return 0;
            }
            """
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            source_path = temporary / "composition_lifecycle_probe.cpp"
            executable_path = temporary / "composition_lifecycle_probe"
            source_path.write_text(source, encoding="ascii")
            compile_result = subprocess.run(
                [
                    "c++",
                    "-std=c++20",
                    "-I",
                    str(ROOT / "src" / "myfuzz" / "frontend" / "src"),
                    str(source_path),
                    "-L",
                    str(LIBRARY.parent),
                    f"-Wl,-rpath,{LIBRARY.parent}",
                    "-lmyfuzz_frontend",
                    "-o",
                    str(executable_path),
                ],
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run(
                [str(executable_path)], capture_output=True, check=False, text=True
            )

        self.assertEqual(run_result.returncode, 0, run_result.stderr)
        self.assertEqual(
            run_result.stdout.splitlines(),
            ["composition AST tree is already live", "recovered"],
        )

    def test_rejects_connection_when_only_one_component_declares_a_clock(self) -> None:
        document = composition_fixture()
        document["clock_domains"] = [document["clock_domains"][0]]

        first_raw, result = self.frontend.build(document)
        second_raw, _ = self.frontend.build(document)

        self.assertEqual(first_raw, second_raw)
        self.assertEqual(
            [diagnostic["code"] for diagnostic in result["diagnostics"]["errors"]],
            ["undeclared-cdc"],
        )

    def test_swapped_clock_and_reset_ids_do_not_hide_a_clock_crossing(self) -> None:
        document = composition_fixture()
        document["clock_domains"][1]["domain_id"] = 8
        document["reset_domains"] = [
            {
                "component_id": 1001,
                "port_id": 112,
                "domain_id": 8,
                "active_level": "high",
                "synchronous": True,
            },
            {
                "component_id": 2001,
                "port_id": 212,
                "domain_id": 7,
                "active_level": "high",
                "synchronous": True,
            },
        ]

        _, result = self.frontend.build(document)

        self.assertEqual(
            [diagnostic["code"] for diagnostic in result["diagnostics"]["errors"]],
            ["undeclared-cdc"],
        )

    def test_reset_properties_are_validated_without_affecting_clock_cdc(self) -> None:
        for property_name, different_value in (
            ("active_level", "low"),
            ("synchronous", False),
        ):
            with self.subTest(property_name=property_name):
                document = composition_fixture()
                document["reset_domains"] = [
                    {
                        "component_id": 1001,
                        "port_id": 112,
                        "domain_id": 9,
                        "active_level": "high",
                        "synchronous": True,
                    },
                    {
                        "component_id": 2001,
                        "port_id": 212,
                        "domain_id": 9,
                        "active_level": "high",
                        "synchronous": True,
                    },
                ]
                document["reset_domains"][1][property_name] = different_value

                _, result = self.frontend.build(document)

                self.assertEqual(
                    [
                        diagnostic["code"]
                        for diagnostic in result["diagnostics"]["errors"]
                    ],
                    ["incompatible-reset-domain"],
                )

    def test_declared_adapter_builds_assignment_node(self) -> None:
        document = composition_fixture()
        document["endpoint_bindings"][0]["fields"][0]["width"] = 8
        document["endpoint_bindings"][1]["fields"][0]["width"] = 4
        document["adapters"] = [
            {
                "edge_id": 501,
                "kind": "declared_width_adapter",
                "source_endpoint_id": 10001,
                "target_endpoint_id": 20001,
            }
        ]

        _, result = self.frontend.build(document)

        self.assertEqual(result["diagnostics"]["errors"], [])
        self.assertEqual(
            result["ast"]["assignments"],
            [
                {
                    "adapter_id": 501,
                    "lhs": "adapter_501_net_301_sink_201",
                    "node_type": "AstAssignW",
                    "rhs": "net_301",
                }
            ],
        )
        self.assertEqual(result["ast"]["node_counts"]["AstAssignW"], 1)
        self.assertIn(
            "assign adapter_501_net_301_sink_201 = net_301[3:0];",
            result["source_text"],
        )

    def test_edge_adapter_builds_distinct_forward_and_reverse_field_assignments(self) -> None:
        document = composition_fixture()
        document["nets"] = [
            {
                "id": 301,
                "source_port_id": 101,
                "sink_port_ids": [201],
                "semantic_role": "request.data",
            },
            {
                "id": 302,
                "source_port_id": 202,
                "sink_port_ids": [102],
                "semantic_role": "response.data",
            },
        ]
        document["endpoint_bindings"][0]["fields"] = [
            {
                "field_role": "request.data",
                "port_id": 101,
                "direction": "output",
                "width": 8,
            },
            {
                "field_role": "response.data",
                "port_id": 102,
                "direction": "input",
                "width": 8,
            },
        ]
        document["endpoint_bindings"][1]["fields"] = [
            {
                "field_role": "request.data",
                "port_id": 201,
                "direction": "input",
                "width": 4,
            },
            {
                "field_role": "response.data",
                "port_id": 202,
                "direction": "output",
                "width": 16,
            },
        ]
        document["adapters"] = [
            {
                "edge_id": 501,
                "kind": "declared_width_adapter",
                "source_endpoint_id": 10001,
                "target_endpoint_id": 20001,
            }
        ]

        _, result = self.frontend.build(document)

        self.assertEqual(result["diagnostics"]["errors"], [])
        self.assertEqual(
            result["ast"]["assignments"],
            [
                {
                    "adapter_id": 501,
                    "lhs": "adapter_501_net_301_sink_201",
                    "node_type": "AstAssignW",
                    "rhs": "net_301",
                },
                {
                    "adapter_id": 501,
                    "lhs": "adapter_501_net_302_sink_102",
                    "node_type": "AstAssignW",
                    "rhs": "net_302",
                },
            ],
        )
        self.assertEqual(result["ast"]["node_counts"]["AstAssignW"], 2)
        pins = {
            pin["port_id"]: pin["signal"]
            for cell in result["ast"]["cells"]
            for pin in cell["pins"]
        }
        self.assertEqual(
            pins,
            {
                101: "net_301",
                102: "adapter_501_net_302_sink_102",
                201: "adapter_501_net_301_sink_201",
                202: "net_302",
                111: "external_111",
                211: "external_211",
            },
        )
        self.assertIn(
            "assign adapter_501_net_301_sink_201 = net_301[3:0];",
            result["source_text"],
        )
        self.assertIn(
            "assign adapter_501_net_302_sink_102 = net_302[7:0];",
            result["source_text"],
        )

    def test_undirected_endpoint_pair_rejects_ambiguous_adapters(self) -> None:
        document = composition_fixture()
        document["endpoint_bindings"][0]["fields"][0]["width"] = 8
        document["endpoint_bindings"][1]["fields"][0]["width"] = 4
        document["adapters"] = [
            {
                "edge_id": 501,
                "kind": "first_adapter",
                "source_endpoint_id": 10001,
                "target_endpoint_id": 20001,
            },
            {
                "edge_id": 502,
                "kind": "second_adapter",
                "source_endpoint_id": 20001,
                "target_endpoint_id": 10001,
            },
        ]

        first_raw, result = self.frontend.build(document)
        second_raw, _ = self.frontend.build(document)

        self.assertEqual(first_raw, second_raw)
        self.assertEqual(
            result["diagnostics"]["errors"],
            [
                {
                    "code": "ambiguous-adapter",
                    "message": "connection endpoint pair matches more than one declared adapter",
                    "path": "nets[0].sink_port_ids[0]",
                    "related_ids": [501, 502, 10001, 20001],
                }
            ],
        )
        self.assertIsNone(result["ast"]["module"])

    def test_real_a5_composition_ir_flows_into_ast_builder(self) -> None:
        facts, declarations, protocols = design(1)
        candidate = next(compose_topk(facts, declarations, protocols, 1))
        document = composition_ir(candidate)

        _, result = self.frontend.build(document)

        self.assertEqual(result["diagnostics"], {"errors": [], "warnings": []})
        self.assertEqual(
            result["validation"],
            {
                "dtype": True,
                "link": True,
                "pin": True,
                "unknown_width_ports": [],
                "width": True,
            },
        )
        self.assertEqual(
            [(cell["node_type"], len(cell["pins"])) for cell in result["ast"]["cells"]],
            [("AstCell", 1), ("AstCell", 1)],
        )

    def test_malformed_payload_uses_frontend_last_error_convention(self) -> None:
        result = self.frontend.library.myfuzz_frontend_composition_json(b"{")

        self.assertFalse(result)
        detail = self.frontend.library.myfuzz_frontend_last_error()
        self.assertIsNotNone(detail)
        self.assertIn("composition_ir.v1:json", detail.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
