from __future__ import annotations

import copy
import unittest

from myfuzz.composition.endpoint_capabilities import (
    AdapterCapability,
    match_endpoint_pair,
    normalize_annotations,
    validate_protocol_fingerprint,
)
from myfuzz.protocols.model import CompiledField, CompiledProtocol


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
        "timing": [{"kind": "transfer_accept", "fields": list(timing_fields), "clock": clock}],
    }


def _document(*endpoints: dict[str, object]) -> dict[str, object]:
    return {"schema_version": "interface_annotations.v1", "endpoints": list(endpoints)}


class EndpointCapabilityTests(unittest.TestCase):
    def test_arbitrary_port_names_match_by_roles_not_identifiers(self) -> None:
        source, target = normalize_annotations(_document(
            _endpoint("source", side="initiator"),
            _endpoint("target", side="target"),
        ))

        matches = match_endpoint_pair(source, target, ())

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
                matches = match_endpoint_pair(case_source, case_target, adapters)
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

        matches = match_endpoint_pair(source, target, (
            AdapterCapability("axi-burst", ("axi4", "1"), ("axi4-lite", "1"), ("burst",), 2, True),
        ))

        self.assertTrue(any(item["accepted"] and item["adapter_id"] == "axi-burst" for item in matches))


if __name__ == "__main__":
    unittest.main()
