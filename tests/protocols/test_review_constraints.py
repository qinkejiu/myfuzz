"""Regression tests for Task 6 independent review I1--I3."""
import json
from pathlib import Path
import unittest

from myfuzz.protocols.catalog import _parse_plugin, ProtocolCatalog
from myfuzz.protocols.compiler import compile_protocol, _width
from myfuzz.protocols.model import ProtocolDefinitionError
from myfuzz.harness.compiler import _projection_plan
from myfuzz.harness.abi import RawBitAbi, RawBitUse, RawDestination, content_hash
from myfuzz.harness.projection import project_sample, ProjectionState
from myfuzz.dependency.static import build_static_graph
from myfuzz.dependency.csr import to_csr


def document(name="obi"):
    return json.loads((Path(__file__).parents[2] / "src/myfuzz/protocols/plugins" / (name + ".json")).read_text())


def compile_plan(doc):
    plugin = _parse_plugin(doc, Path("fixture.json"))
    params = {"data_width": 32, "address_width": 32, "id_width": 4}
    ports = {f.field_id: str(i + 1) for i, f in enumerate(plugin.fields)}
    compiled = compile_protocol(dict(binding_id="b", protocol_id=plugin.protocol_id, version=plugin.version,
                                    ports=ports, parameters=params),
                                {"port_widths": {ports[f.field_id]: _width(f.width_expression, params) for f in plugin.fields}},
                                ProtocolCatalog((plugin,)))
    inputs = [f for f in compiled.fields if f.direction == "host_to_device"]
    destinations = tuple(RawDestination(i, None, int(f.port_id), f.width) for i, f in enumerate(inputs))
    uses, cursor = [], 0
    for d in destinations:
        uses.append(RawBitUse(cursor, cursor + d.width - 1, d.destination_id, 0, "direct", "direct"))
        cursor += d.width
    abi = RawBitAbi(cursor, destinations, tuple(uses), content_hash({"width": cursor}))
    return compiled, _projection_plan(abi, (compiled,), {plugin.protocol_id: plugin}, to_csr(build_static_graph({}, (compiled,))), None)


class ReviewConstraintsTest(unittest.TestCase):
    def test_unknown_keys_and_kinds_rejected(self):
        for key in (None, "fields", "projection_actions", "channel_relations", "temporal_rules"):
            doc = document()
            target = doc if key is None else doc[key][0]
            target["misspelled_constraint"] = True
            with self.subTest(key=key), self.assertRaises(ProtocolDefinitionError):
                _parse_plugin(doc, Path("fixture.json"))
        for key in ("projection_actions", "channel_relations", "temporal_rules"):
            doc = document()
            doc[key][0]["kind"] = "unsupported"
            with self.subTest(kind=key), self.assertRaises(ProtocolDefinitionError):
                _parse_plugin(doc, Path("fixture.json"))

    def test_x_extensions_remain_accepted(self):
        doc = document()
        doc["x-vendor"] = "note"
        for key in ("fields", "projection_actions", "channel_relations", "temporal_rules"):
            doc[key][0]["x-vendor"] = "note"
        _parse_plugin(doc, Path("fixture.json"))

    def test_metadata_preserved_and_hashed(self):
        doc = document()
        compiled, baseline = compile_plan(doc)
        self.assertTrue(compiled.channel_relations)
        self.assertTrue(compiled.capability_limits)
        doc["channel_relations"][0]["field_ids"].reverse()
        self.assertNotEqual(baseline.plan_hash, compile_plan(doc)[1].plan_hash)
        doc = document()
        doc["capability_limits"]["max_outstanding"] = 2
        self.assertNotEqual(baseline.plan_hash, compile_plan(doc)[1].plan_hash)

    def test_strictest_temporal_and_capability_bound(self):
        for bounds, cap, expected in (([1, 16], 16, 1), ([16, 1], 16, 1), ([16, 16], 3, 3)):
            doc = document()
            for rule, bound in zip(doc["temporal_rules"], bounds):
                rule["max_cycles"] = bound
            doc["capability_limits"]["max_wait_cycles"] = cap
            plan = compile_plan(doc)[1]
            self.assertEqual([a.max_cycles for a in plan.actions if a.kind == "gate"], [expected])

    def test_equivalent_width_and_missing_canonical_port(self):
        doc = document()
        doc["fields"].append(dict(field_id="byte_enable", direction="host_to_device", width="data_width // 8", required=True, reset_value=0))
        _, plan = compile_plan(doc)
        self.assertEqual(len(plan.canonical_byte_enables), 1)
        constraint = plan.canonical_byte_enables[0]
        self.assertEqual(dict(project_sample(plan, 0, ProjectionState.initial(plan)).driven_fields)[constraint.destination_id], 15)
        for name in ("obi", "apb3"):
            _, plan = compile_plan(document(name))
            self.assertFalse(plan.canonical_byte_enables)
            self.assertTrue(any("canonical byte-enable" in d for d in plan.diagnostics))

    def test_explicit_byte_enable_role_uses_evaluated_width(self):
        doc = document()
        doc["fields"].append(dict(field_id="lanes", semantic_role="byte_enable", direction="host_to_device", width="4", required=True, reset_value=0))
        self.assertEqual(compile_plan(doc)[1].canonical_byte_enables[0].value, 15)
        doc["fields"][-1]["width"] = "8"
        with self.assertRaisesRegex(ProtocolDefinitionError, "byte-enable"):
            compile_plan(doc)

    def test_no_action_temporal_rules_use_minimum(self):
        doc = document()
        doc["projection_actions"] = []
        doc["temporal_rules"][0]["max_cycles"] = 1
        plan = compile_plan(doc)[1]
        self.assertTrue(plan.actions)
        self.assertTrue(all(a.max_cycles == 1 for a in plan.actions))
