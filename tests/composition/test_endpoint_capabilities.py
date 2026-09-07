from __future__ import annotations

import copy
import unittest

from myfuzz.composition.endpoint_capabilities import (
    AdapterCapability,
    EndpointCapabilityError,
    match_endpoint_pair,
    normalize_annotations,
    validate_protocol_fingerprint,
)
from myfuzz.composition.constraints import build_capability_constraint_graph
from myfuzz.protocols.catalog import ProtocolCatalog
from myfuzz.protocols.model import CompiledField, CompiledProtocol, FieldSpec, ProtocolPlugin


def _endpoint(
    endpoint_id: str,
    *,
    side: str,
    clock: str = "clock_alpha",
    data_width: int = 32,
    invert_valid: bool = False,
    timing_fields: tuple[str, ...] = ("valid", "ready"),
    protocol: tuple[str, str] = ("opaque-bus", "1"),
    burst: bool = False,
    timing_max_latency: int | None = None,
) -> dict[str, object]:
    directions = {
        "initiator": {"address": "output", "valid": "output", "ready": "input", "data": "output"},
        "target": {"address": "input", "valid": "input", "ready": "output", "data": "input"},
    }[side]
    fields = [
        {"role": role, "port": port, "direction": "output" if role == "valid" and invert_valid else direction,
         "width": data_width if role in {"address", "data"} else 1, "signed": False}
        for role, port, direction in (
            ("address", "left_17" if side == "initiator" else "right_42", directions["address"]),
            ("valid", "left_19" if side == "initiator" else "right_44", directions["valid"]),
            ("ready", "left_23" if side == "initiator" else "right_47", directions["ready"]),
            ("data", "left_31" if side == "initiator" else "right_53", directions["data"]),
        )
    ]
    if burst:
        fields.append({"role": "burst", "port": "left_61", "direction": directions.get("burst", "output"), "width": 2, "signed": False})
    return {
        "endpoint_id": endpoint_id,
        "function": "arbitrary_function",
        "side": side,
        "protocol": list(protocol),
        "fields": fields,
        "clock": clock,
        "reset": "reset_alpha",
        "timing": [{
            "kind": "transfer_accept", "fields": list(timing_fields), "clock": clock,
            **({} if timing_max_latency is None else {"max_latency": timing_max_latency}),
        }],
    }


def _document(*endpoints: dict[str, object]) -> dict[str, object]:
    return {"schema_version": "interface_annotations.v1", "endpoints": list(endpoints)}


def _protocol_context(*endpoints: object) -> tuple[ProtocolCatalog, dict[str, CompiledProtocol]]:
    capabilities = [endpoint for endpoint in endpoints if hasattr(endpoint, "protocol")]
    plugins: dict[tuple[str, str], ProtocolPlugin] = {}
    compiled: dict[str, CompiledProtocol] = {}
    directions = {
        "address": "host_to_device", "valid": "host_to_device", "ready": "device_to_host",
        "data": "host_to_device", "burst": "host_to_device",
    }
    for endpoint in capabilities:
        if endpoint.protocol is None:
            continue
        key = endpoint.protocol
        plugins.setdefault(key, ProtocolPlugin(
            key[0], key[1], tuple(
                FieldSpec(field.role, directions[field.role], str(field.width), True, 0)
                for field in endpoint.fields
            ), (),
        ))
        compiled[endpoint.endpoint_id] = CompiledProtocol(
            endpoint.endpoint_id, key[0], key[1], tuple(
                CompiledField(field.role, directions[field.role], field.width, field.role, 0)
                for field in endpoint.fields
            ),
        )
    return ProtocolCatalog(tuple(plugins.values())), compiled


class EndpointCapabilityTests(unittest.TestCase):
    def test_member_fact_normalization_is_immutable(self) -> None:
        endpoint = _endpoint("source", side="initiator")
        field = endpoint["fields"][0]
        field.update({"member_path": ["aw", "addr"], "raw_lo": 4, "raw_hi": 35, "container_width": 64,
                      "evidence": ["compiler_elaboration", "explicit_member"]})
        normalized = normalize_annotations(_document(endpoint))[0].fields[0]
        self.assertEqual(("aw", "addr"), normalized.member_path)
        self.assertEqual((4, 35, 64), (normalized.raw_lo, normalized.raw_hi, normalized.container_width))

    def test_member_fact_requires_complete_range_and_compiler_evidence(self) -> None:
        mutations = (
            {"raw_lo": 0, "raw_hi": 7, "container_width": 8},
            {"member_path": ["data"], "raw_lo": 0, "raw_hi": 7},
            {"member_path": ["data"], "raw_lo": 0, "raw_hi": 7, "container_width": 8,
             "evidence": ["explicit_member"]},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                endpoint = _endpoint("source", side="initiator", data_width=8)
                endpoint["fields"][0].update(mutation)
                with self.assertRaises(EndpointCapabilityError):
                    normalize_annotations(_document(endpoint))

        endpoint = _endpoint("source", side="initiator", data_width=8)
        for field in endpoint["fields"][:2]:
            field.update({"port": "bus", "member_path": ["data"], "raw_lo": 0, "raw_hi": field["width"] - 1,
                          "container_width": 8, "evidence": ["explicit_member", "compiler_elaboration"]})
        with self.assertRaisesRegex(EndpointCapabilityError, "duplicate-physical"):
            normalize_annotations(_document(endpoint))

    def test_arbitrary_port_names_match_by_roles_not_identifiers(self) -> None:
        source, target = normalize_annotations(_document(
            _endpoint("source", side="initiator"),
            _endpoint("target", side="target"),
        ))

        catalog, compiled = _protocol_context(source, target)
        matches = match_endpoint_pair(source, target, (), protocol_catalog=catalog, compiled_protocols=compiled)

        accepted = [item for item in matches if item["accepted"]]
        self.assertEqual(len(accepted), 1)
        self.assertEqual(accepted[0]["adapter_id"], None)
        self.assertNotIn("left_17", repr(accepted[0]))
        self.assertNotIn("right_42", repr(accepted[0]))

    def test_rejections_retain_direction_width_feature_and_domain_evidence(self) -> None:
        source, target = normalize_annotations(_document(
            _endpoint("source", side="initiator"),
            _endpoint("target", side="target"),
        ))
        cases = (
            (
                "direction",
                normalize_annotations(_document(_endpoint("target", side="target", invert_valid=True)))[0],
                (),
                "direction",
            ),
            (
                "width",
                normalize_annotations(_document(_endpoint("target", side="target", data_width=16)))[0],
                (),
                "width-projection",
            ),
            (
                "feature",
                normalize_annotations(_document(_endpoint("target", side="target", protocol=("axi4-lite", "1"))))[0],
                (AdapterCapability("axi-lite", ("axi4", "1"), ("axi4-lite", "1"), (), 2, True),),
                "unsupported-feature:burst",
            ),
            (
                "domain",
                normalize_annotations(_document(_endpoint("target", side="target", clock="clock_beta")))[0],
                (),
                "clock-domain",
            ),
            (
                "version",
                normalize_annotations(_document(_endpoint("target", side="target", protocol=("opaque-bus", "2"))))[0],
                (),
                "protocol-version",
            ),
            (
                "temporal",
                normalize_annotations(_document(_endpoint("target", side="target", timing_fields=("address", "ready"))))[0],
                (),
                "temporal-relation",
            ),
        )
        burst_source = normalize_annotations(_document(_endpoint(
            "source", side="initiator", protocol=("axi4", "1"), burst=True,
        )))[0]
        for label, case_target, adapters, reason in cases:
            with self.subTest(label=label):
                case_source = burst_source if label == "feature" else source
                catalog, compiled = _protocol_context(case_source, case_target)
                matches = match_endpoint_pair(case_source, case_target, adapters, protocol_catalog=catalog, compiled_protocols=compiled)
                self.assertFalse(any(item["accepted"] for item in matches))
                self.assertTrue(any(any(item_reason.startswith(reason) for item_reason in item["reasons"]) for item in matches))
                self.assertTrue(all(item["evidence"] for item in matches))

    def test_protocol_fingerprint_checks_endpoint_relative_fields(self) -> None:
        source = normalize_annotations(_document(_endpoint("source", side="initiator")))[0]
        compiled = CompiledProtocol(
            "binding",
            "opaque-bus",
            "1",
            tuple(
                CompiledField(role, direction, width, role, 0)
                for role, direction, width in (
                    ("address", "host_to_device", 32),
                    ("valid", "host_to_device", 1),
                    ("ready", "device_to_host", 1),
                    ("data", "host_to_device", 32),
                )
            ),
        )

        self.assertEqual(validate_protocol_fingerprint(source, compiled), ())
        mismatch = copy.deepcopy(_endpoint("source", side="initiator", data_width=16))
        capability = normalize_annotations(_document(mismatch))[0]
        self.assertIn("width:data", validate_protocol_fingerprint(capability, compiled))

    def test_declared_adapter_feature_allows_a_source_only_field(self) -> None:
        source = normalize_annotations(_document(_endpoint(
            "source", side="initiator", protocol=("axi4", "1"), burst=True,
        )))[0]
        target = normalize_annotations(_document(_endpoint(
            "target", side="target", protocol=("axi4-lite", "1"),
        )))[0]

        catalog, compiled = _protocol_context(source, target)
        matches = match_endpoint_pair(source, target, (
            AdapterCapability("axi-burst", ("axi4", "1"), ("axi4-lite", "1"), ("burst",), 2, True),
        ), protocol_catalog=catalog, compiled_protocols=compiled)

        self.assertTrue(any(item["accepted"] and item["adapter_id"] == "axi-burst" for item in matches))

    def test_matching_rejects_unsupported_or_unvalidated_declared_protocols(self) -> None:
        source, target = normalize_annotations(_document(
            _endpoint("source", side="initiator"), _endpoint("target", side="target"),
        ))

        unvalidated = match_endpoint_pair(source, target, ())
        unsupported = match_endpoint_pair(source, target, (), protocol_catalog=ProtocolCatalog(()))

        self.assertTrue(any("protocol-validation-required" in item["reasons"] for item in unvalidated))
        self.assertTrue(any("unsupported-protocol:opaque-bus@1" in item["reasons"] for item in unsupported))

    def test_matching_uses_fingerprints_for_protocol_invalid_directions(self) -> None:
        source_document = _endpoint("source", side="initiator")
        target_document = _endpoint("target", side="target")
        next(field for field in source_document["fields"] if field["role"] == "valid")["direction"] = "input"
        next(field for field in target_document["fields"] if field["role"] == "valid")["direction"] = "output"
        source, target = normalize_annotations(_document(source_document, target_document))
        catalog, compiled = _protocol_context(source, target)

        matches = match_endpoint_pair(source, target, (), protocol_catalog=catalog, compiled_protocols=compiled)

        self.assertFalse(any(item["accepted"] for item in matches))
        self.assertTrue(any("direction:valid" in item["reasons"] for item in matches))

    def test_width_projection_requires_an_explicit_role_declaration(self) -> None:
        target_document = _endpoint("target", side="target")
        next(field for field in target_document["fields"] if field["role"] == "data")["width"] = 16
        source, target = normalize_annotations(_document(_endpoint("source", side="initiator"), target_document))
        catalog, compiled = _protocol_context(source, target)
        legacy = AdapterCapability("legacy", ("opaque-bus", "1"), ("opaque-bus", "1"), (), 2, True)
        declared = AdapterCapability(
            "data-narrow", ("opaque-bus", "1"), ("opaque-bus", "1"), (), 2, True, ("data",),
        )

        matches = match_endpoint_pair(source, target, (legacy, declared), protocol_catalog=catalog, compiled_protocols=compiled)

        self.assertTrue(any(item["adapter_id"] == "legacy" and "width-projection:data" in item["reasons"] for item in matches))
        self.assertTrue(any(item["adapter_id"] == "data-narrow" and item["accepted"] for item in matches))

    def test_temporal_observations_fail_closed_and_bound_declared_adapter_latency(self) -> None:
        source, target = normalize_annotations(_document(
            _endpoint("source", side="initiator", timing_max_latency=2),
            _endpoint("target", side="target", timing_max_latency=2),
        ))
        catalog, compiled = _protocol_context(source, target)
        slow = AdapterCapability("slow", ("opaque-bus", "1"), ("opaque-bus", "1"), (), 3, False)
        fast = AdapterCapability("fast", ("opaque-bus", "1"), ("opaque-bus", "1"), (), 2, False)
        bounded = match_endpoint_pair(source, target, (slow, fast), protocol_catalog=catalog, compiled_protocols=compiled)
        one_sided_document = _endpoint("target", side="target")
        one_sided_document["timing"] = []
        one_sided = normalize_annotations(_document(one_sided_document))[0]
        one_sided_matches = match_endpoint_pair(source, one_sided, (), protocol_catalog=catalog, compiled_protocols=compiled)

        self.assertTrue(any(item["adapter_id"] == "slow" and "temporal-latency" in item["reasons"] for item in bounded))
        self.assertTrue(any(item["adapter_id"] == "fast" and item["accepted"] for item in bounded))
        self.assertTrue(any("temporal-relation" in item["reasons"] for item in one_sided_matches))

    def test_temporal_matching_ignores_provenance_but_retains_it_as_evidence(self) -> None:
        source_document = _endpoint("source", side="initiator")
        target_document = _endpoint("target", side="target")
        source_document["timing"][0].update(
            {"source": {"file": "rtl/source.sv", "line": 11}, "evidence": ["source_trace"]}
        )
        target_document["timing"][0].update(
            {"source": {"file": "rtl/target.sv", "line": 29}, "evidence": ["target_trace"]}
        )
        source, target = normalize_annotations(_document(source_document, target_document))
        catalog, compiled = _protocol_context(source, target)

        matches = match_endpoint_pair(source, target, (), protocol_catalog=catalog, compiled_protocols=compiled)

        accepted = next(item for item in matches if item["accepted"])
        timing_evidence = [item for item in accepted["evidence"] if item["kind"] == "timing"]
        self.assertEqual(len(timing_evidence), 2)
        self.assertEqual({item["source"]["file"] for item in timing_evidence}, {"rtl/source.sv", "rtl/target.sv"})
        self.assertEqual({item["evidence"][0] for item in timing_evidence}, {"source_trace", "target_trace"})

    def test_protocol_matching_rejects_shared_undeclared_role(self) -> None:
        source_document = _endpoint("source", side="initiator")
        target_document = _endpoint("target", side="target")
        base_source, base_target = normalize_annotations(_document(source_document, target_document))
        catalog, compiled = _protocol_context(base_source, base_target)
        for document, port in ((source_document, "left_extra"), (target_document, "right_extra")):
            document["fields"].append(
                {"role": "debug", "port": port, "direction": "output" if document["side"] == "initiator" else "input",
                 "width": 1, "signed": False}
            )
        source, target = normalize_annotations(_document(source_document, target_document))

        matches = match_endpoint_pair(source, target, (), protocol_catalog=catalog, compiled_protocols=compiled)

        self.assertFalse(any(item["accepted"] for item in matches))
        self.assertTrue(any("undeclared-role:debug" in item["reasons"] for item in matches))

    def test_compiled_only_matching_rejects_shared_undeclared_role(self) -> None:
        source_document = _endpoint("source", side="initiator")
        target_document = _endpoint("target", side="target")
        base_source, base_target = normalize_annotations(_document(source_document, target_document))
        _, compiled = _protocol_context(base_source, base_target)
        for document, port in ((source_document, "left_extra"), (target_document, "right_extra")):
            document["fields"].append(
                {"role": "debug", "port": port, "direction": "output" if document["side"] == "initiator" else "input",
                 "width": 1, "signed": False}
            )
        source, target = normalize_annotations(_document(source_document, target_document))

        matches = match_endpoint_pair(source, target, (), compiled_protocols=compiled)

        self.assertFalse(any(item["accepted"] for item in matches))
        self.assertTrue(any("undeclared-role:debug" in item["reasons"] for item in matches))

    def test_normalization_retains_relative_source_evidence_and_unknown_identity(self) -> None:
        source_document = _endpoint("source", side="initiator")
        source_document["fields"][0]["source"] = {"file": "rtl/tile.sv", "line": 7, "column": 3}
        source_document["fields"][0]["evidence"] = ["explicit_alias", "hdl_declaration"]
        unknown = _endpoint("target", side="target")
        unknown.pop("side")
        unknown.pop("protocol")
        source, target = normalize_annotations(_document(source_document, unknown))
        catalog, compiled = _protocol_context(source)
        matches = match_endpoint_pair(source, target, (), protocol_catalog=catalog, compiled_protocols=compiled)
        graph = build_capability_constraint_graph(_document(source_document, unknown), (), protocol_catalog=catalog, compiled_protocols=compiled)

        field_evidence = next(item for item in matches[0]["evidence"] if item["kind"] == "field" and item["role"] == "address")
        self.assertEqual(field_evidence["source"], {"file": "rtl/tile.sv", "line": 7, "column": 3})
        self.assertEqual(field_evidence["evidence"], ["explicit_alias", "hdl_declaration"])
        self.assertTrue(any("side-ambiguous" in item["reasons"] for item in matches))
        self.assertTrue(any("protocol-ambiguous" in item["reasons"] for item in matches))
        self.assertEqual(len(graph.alternatives), len(matches) * 2)


if __name__ == "__main__":
    unittest.main()
