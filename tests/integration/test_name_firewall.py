from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from myfuzz.composition.facts import normalize_facts
from myfuzz.composition.ir import composition_ir
from myfuzz.composition.search import compose_topk
from myfuzz.contracts import content_hash
from myfuzz.experiments import prepare_candidate_runtime
from myfuzz.integration import (
    assert_semantic_rename_invariant,
    semantic_projection,
)
from tests.composition.test_constraints import _declarations, _protocol


ROOT = Path(__file__).resolve().parents[2]


def _fixture(name: str) -> dict[str, object]:
    path = ROOT / "tests" / "fixtures" / "runtime" / name
    document = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def _harness_fragment() -> dict[str, object]:
    mapping = [
        {
            "raw_lo": 0,
            "raw_hi": 7,
            "destination_id": 10,
            "destination_lo": 0,
            "action": "direct",
            "category": "data",
        }
    ]
    harness = {
        "mode": "candidate-direct",
        "candidate_id": "candidate-runtime-001",
        "raw_width": 8,
        "destinations": [
            {"destination_id": 10, "component_id": 100, "port_id": 10, "width": 8}
        ],
        "mapping": mapping,
    }
    return {
        "candidate_id": "candidate-runtime-001",
        "harnesses": {
            "candidate-direct": harness,
            "candidate-depaware": {**harness, "mode": "candidate-depaware"},
        },
        "raw_bit_mappings": {
            "candidate-direct": mapping,
            "candidate-depaware": mapping,
        },
        "protocol_ids": ["ready-valid-mmio"],
        "protocols": [{"protocol_id": "ready-valid-mmio", "version": "1"}],
        "dependency_graph": {
            "document": {
                "schema_version": "dependency_graph.v1",
                "node_ids": [{"kind": "port", "components": [10]}],
                "group_ids": [{"kind": "field_group", "components": [1000, 10]}],
                "indptr": [0, 1],
                "indices": [0],
                "edge_kinds": ["dataflow"],
                "external_endpoint_port_ids": [10],
                "adapter_edges": [
                    {"source_port_id": 10, "target_port_id": 11, "adapter_id": 7}
                ],
            }
        },
    }


class NameFirewallTests(unittest.TestCase):
    def test_actual_composition_producer_is_invariant_to_bound_name_changes(self) -> None:
        original = {
            "schema_version": "hdl_facts.v2",
            "tool": {
                "frontend": "test",
                "verilator_revision": "test",
                "input_hash": "sha256:" + "0" * 64,
            },
            "modules": [
                {"id": 1, "ports": [11], "instances": []},
                {"id": 2, "ports": [21], "instances": []},
            ],
            "parameters": [],
            "ports": [
                {
                    "id": 11,
                    "module_id": 1,
                    "direction": "output",
                    "width": 32,
                    "signed": False,
                    "declared_role": "request.data",
                    "name": "plain_source",
                },
                {
                    "id": 21,
                    "module_id": 2,
                    "direction": "input",
                    "width": 32,
                    "signed": False,
                    "declared_role": "request.data",
                    "name": "plain_sink",
                },
            ],
            "instances": [],
            "pin_bindings": [],
            "expressions": [],
            "dataflow_edges": [{"from_port_id": 11, "to_port_id": 21}],
            "control_edges": [],
            "clock_reset_checks": [],
            "local_address_facts": [],
            "source_locations": [],
            "source_symbols": [],
            "diagnostics": {"errors": [], "warnings": [], "unsupported": []},
        }
        renamed = copy.deepcopy(original)
        renamed["ports"][0]["name"] = "misleading_target_clock"
        renamed["ports"][1]["name"] = "misleading_source_irq"

        def run(document: dict[str, object]) -> dict[str, object]:
            candidate = next(
                compose_topk(
                    normalize_facts(document),
                    _declarations(),
                    {"bus": _protocol()},
                    1,
                )
            )
            return composition_ir(candidate)

        assert_semantic_rename_invariant(original, renamed, run)

    def test_actual_runtime_compiler_is_invariant_to_diagnostic_renames(self) -> None:
        facts = _fixture("hdl_facts.v2.runtime.json")
        composition = _fixture("composition_ir.v1.runtime.json")
        manifest = _fixture("candidate_manifest.v1.runtime.json")
        config = json.loads(
            (ROOT / "configs" / "experiments" / "ibex_opentitan.json").read_text(
                encoding="utf-8"
            )
        )
        original = {
            "facts": facts,
            "composition": composition,
            "manifest": manifest,
            "config": config,
        }
        renamed = copy.deepcopy(original)
        renamed_facts = renamed["facts"]
        renamed_composition = renamed["composition"]
        renamed_manifest = renamed["manifest"]
        renamed_config = renamed["config"]
        renamed_facts["modules"][0]["module_name"] = "rvx"
        renamed_facts["ports"][0]["port_name"] = "uart"
        renamed_composition["components"][0]["instance_name"] = "opentitan"
        renamed_composition["endpoint_bindings"][0]["net_name"] = "rv_timer"
        renamed_manifest["top"]["module"] = "renamed_top"
        renamed_manifest["top"]["source"] = "renamed_source.sv"
        renamed_manifest["top_port_abi"][0]["emitted_name"] = "renamed_port"
        renamed_facts["source_symbols"][0]["name"] = "renamed_top"
        renamed_facts["source_symbols"][1]["name"] = "renamed_port"
        renamed_port = renamed_manifest["top_port_abi"][0]
        actual_port = renamed_facts["ports"][0]
        renamed_port["validation_evidence_id"] = content_hash(
            {
                "top_module_id": renamed_facts["modules"][0]["id"],
                "logical_port_id": renamed_port["port_id"],
                "actual": {
                    "actual_port_id": renamed_port["actual_port_id"],
                    "emitted_name": renamed_port["emitted_name"],
                    "direction": actual_port["direction"],
                    "width": actual_port["width"],
                    "signed": actual_port["signed"],
                    "declared_role": actual_port["declared_role"],
                },
            }
        )
        renamed_config["target"]["display"] = "renamed target"
        renamed_manifest["composition_ir_hash"] = content_hash(renamed_composition)
        facts_hash = content_hash(renamed_facts)
        renamed_manifest["hdl_facts"]["content_hash"] = facts_hash
        renamed_manifest["validation"]["evidence"]["reparse"][
            "hdl_facts_content_hash"
        ] = facts_hash

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            calls = 0

            def run(envelope: dict[str, object]) -> dict[str, object]:
                nonlocal calls
                calls += 1
                runtime = prepare_candidate_runtime(
                    envelope["facts"],
                    envelope["composition"],
                    envelope["manifest"],
                    envelope["config"],
                    root / str(calls),
                )
                return runtime.harness_bundle.manifest_fragment()

            assert_semantic_rename_invariant(original, renamed, run)

    def test_hdl_diagnostic_rename_is_invariant_but_numeric_edge_change_is_not(self) -> None:
        original = _fixture("hdl_facts.v2.runtime.json")
        renamed = copy.deepcopy(original)
        renamed["modules"][0]["module_name"] = "misleading_uart_top"
        renamed["ports"][0]["port_name"] = "looks_like_clock"
        renamed["source_symbols"][0]["name"] = "renamed_symbol"

        assert_semantic_rename_invariant(original, renamed, lambda document: document)

        changed = copy.deepcopy(renamed)
        changed["dataflow_edges"] = [{"from_port_id": 101, "to_port_id": 115}]
        self.assertNotEqual(semantic_projection(original), semantic_projection(changed))
        with self.assertRaisesRegex(AssertionError, "edges"):
            assert_semantic_rename_invariant(original, changed, lambda document: document)

    def test_composition_projection_ignores_emission_names_and_hashes(self) -> None:
        original = _fixture("composition_ir.v1.runtime.json")
        renamed = copy.deepcopy(original)
        renamed["graph_hash"] = "sha256:" + "a" * 64
        renamed["components"][0]["instance_name"] = "renamed_instance"
        renamed["endpoint_bindings"][0]["net_name"] = "renamed_net"
        renamed["diagnostics"] = {"errors": [], "warnings": ["renamed diagnostic"]}

        self.assertEqual(semantic_projection(original), semantic_projection(renamed))

        semantic_mutations = (
            ("protocol", lambda document: document["endpoint_bindings"][0].__setitem__("protocol_id", "other")),
            ("adapter", lambda document: document["adapters"][0].__setitem__("target_port_id", 99)),
            ("score", lambda document: document["score_vector"].__setitem__(0, 1)),
            (
                "address",
                lambda document: document["address_regions"].append(
                    {
                        "component_id": 100,
                        "port_id": 10,
                        "base": 4096,
                        "size": 256,
                        "local_offset": 0,
                        "provenance": "inferred",
                    }
                ),
            ),
        )
        baseline = semantic_projection(original)
        for label, mutate in semantic_mutations:
            with self.subTest(label=label):
                changed = copy.deepcopy(original)
                mutate(changed)
                self.assertNotEqual(baseline, semantic_projection(changed))

    def test_protocol_parameter_names_are_always_semantic(self) -> None:
        original = _fixture("composition_ir.v1.runtime.json")
        parameters = original["endpoint_bindings"][0]["parameters"]
        parameters.update(
            {
                "source": 8,
                "module": 8,
                "name": 8,
                "evidence_policy": 8,
            }
        )
        baseline = semantic_projection(original)

        for parameter_name in ("source", "module", "name", "evidence_policy"):
            with self.subTest(parameter_name=parameter_name):
                changed = copy.deepcopy(original)
                changed["endpoint_bindings"][0]["parameters"][parameter_name] = 16
                self.assertNotEqual(baseline, semantic_projection(changed))

    def test_candidate_manifest_ignores_top_names_but_keeps_port_semantics(self) -> None:
        original = _fixture("candidate_manifest.v1.runtime.json")
        renamed = copy.deepcopy(original)
        renamed["top"]["module"] = "renamed_top"
        renamed["top"]["source"] = "renamed_top.sv"
        renamed["top"]["content_hash"] = "sha256:" + "a" * 64
        renamed["top_port_abi"][0]["emitted_name"] = "renamed_clock"
        renamed["top_port_abi"][0]["validation_evidence_id"] = "sha256:" + "b" * 64

        self.assertEqual(semantic_projection(original), semantic_projection(renamed))

        changed = copy.deepcopy(original)
        changed["top_port_abi"][0]["width"] = 2
        self.assertNotEqual(semantic_projection(original), semantic_projection(changed))

        changed = copy.deepcopy(original)
        changed["hdl_facts"]["top_module_id"] = 901
        self.assertNotEqual(semantic_projection(original), semantic_projection(changed))

    def test_harness_fragment_projects_raw_destinations_mappings_and_csr(self) -> None:
        original = _harness_fragment()
        reordered = copy.deepcopy(original)
        reordered["protocols"].reverse()

        baseline = semantic_projection(original)
        self.assertEqual(baseline, semantic_projection(reordered))

        mutations = (
            lambda document: document["harnesses"]["candidate-direct"]["destinations"][0].__setitem__("destination_id", 11),
            lambda document: document["raw_bit_mappings"]["candidate-direct"][0].__setitem__("raw_hi", 6),
            lambda document: document["dependency_graph"]["document"]["indices"].__setitem__(0, 1),
            lambda document: document["dependency_graph"]["document"]["indptr"].__setitem__(1, 0),
            lambda document: document["dependency_graph"]["document"]["edge_kinds"].__setitem__(0, "control"),
            lambda document: document["dependency_graph"]["document"]["node_ids"].append(
                {"kind": "port", "components": [11]}
            ),
            lambda document: document["protocols"][0].__setitem__("version", "2"),
        )
        for mutate in mutations:
            changed = copy.deepcopy(original)
            mutate(changed)
            self.assertNotEqual(baseline, semantic_projection(changed))

        renamed_budget = copy.deepcopy(original)
        renamed_budget["harnesses"]["candidate-direct"]["budget_name"] = "short"
        other_budget = copy.deepcopy(renamed_budget)
        other_budget["harnesses"]["candidate-direct"]["budget_name"] = "long"
        self.assertNotEqual(
            semantic_projection(renamed_budget),
            semantic_projection(other_budget),
        )

    def test_recognized_documents_reject_malformed_semantic_records(self) -> None:
        facts = _fixture("hdl_facts.v2.runtime.json")
        manifest = _fixture("candidate_manifest.v1.runtime.json")
        fragment = _harness_fragment()
        mutations = (
            (facts, lambda document: document.__setitem__("modules", 7)),
            (facts, lambda document: document["ports"][0].__setitem__("id", True)),
            (facts, lambda document: document["dataflow_edges"][0].pop("target_port_id")),
            (manifest, lambda document: document["hdl_facts"].pop("top_module_id")),
            (fragment, lambda document: document["harnesses"].__setitem__("candidate-direct", 7)),
            (fragment, lambda document: document["raw_bit_mappings"].__setitem__("candidate-direct", [True])),
            (
                fragment,
                lambda document: document["dependency_graph"]["document"][
                    "external_endpoint_port_ids"
                ].__setitem__(0, True),
            ),
            (
                fragment,
                lambda document: document["dependency_graph"]["document"][
                    "external_endpoint_port_ids"
                ].__setitem__(0, "0"),
            ),
            (
                fragment,
                lambda document: document["dependency_graph"]["document"][
                    "external_endpoint_port_ids"
                ].__setitem__(0, "port-ten"),
            ),
            (
                fragment,
                lambda document: document["dependency_graph"]["document"]["node_ids"][0][
                    "components"
                ].__setitem__(0, ""),
            ),
            (
                fragment,
                lambda document: document["dependency_graph"]["document"]["group_ids"][0][
                    "components"
                ].__setitem__(0, -1),
            ),
        )
        for original, mutate in mutations:
            changed = copy.deepcopy(original)
            mutate(changed)
            with self.subTest(mutation=mutate), self.assertRaises((TypeError, ValueError)):
                semantic_projection(changed)

    def test_projection_is_fail_closed_and_run_receives_detached_inputs(self) -> None:
        with self.assertRaises((TypeError, ValueError)):
            semantic_projection({"diagnostics": {"warnings": []}})

        original = _fixture("hdl_facts.v2.runtime.json")
        renamed = copy.deepcopy(original)

        def destructive_run(document: dict[str, object]) -> dict[str, object]:
            document["diagnostics"] = {"warnings": ["changed by runner"]}
            return document

        assert_semantic_rename_invariant(original, renamed, destructive_run)
        self.assertNotEqual(original["diagnostics"], {"warnings": ["changed by runner"]})

        with self.assertRaises(TypeError):
            assert_semantic_rename_invariant(original, renamed, lambda _document: ())


if __name__ == "__main__":
    unittest.main()
