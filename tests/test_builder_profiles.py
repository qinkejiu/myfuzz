import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (
    InputValidationError,
    MatchSource,
    PortAnnotation,
    PortDirection,
    ProfileRegistry,
    ProtocolProfile,
)


def profile(name="base", priority=10, semantic="axi_lite.awvalid"):
    return ProtocolProfile.from_dict({
        "name": name,
        "protocol": "AXI_LITE",
        "interface_role": "target",
        "priority": priority,
        "ports": [{
            "semantic": semantic,
            "direction": "input",
            "aliases": ["s_axi_awvalid", "awvalid"],
        }],
    })


class ProfileRegistryTest(unittest.TestCase):
    def test_example_profile_is_valid_and_protocol_based(self):
        data = json.loads((ROOT / "examples" / "axi_lite_target_profile.json").read_text())
        registry = ProfileRegistry([ProtocolProfile.from_dict(data)])

        result = registry.resolve_port(
            protocol="AXI_LITE",
            interface_role="target",
            port_name="S_AXI_AWVALID",
            direction="input",
        )

        self.assertEqual(result.source, MatchSource.PROFILE)
        self.assertEqual(result.annotation.port_type, "axi_lite.awvalid")
        self.assertEqual(result.profile_name, "axi_lite_target_core")
        self.assertNotIn("module", result.reason)

    def test_user_annotation_has_highest_priority(self):
        registry = ProfileRegistry([profile(priority=1000)])
        declared = PortAnnotation(PortDirection.INPUT, "user.custom_request")

        result = registry.resolve_port(
            protocol="axi_lite",
            interface_role="target",
            port_name="s_axi_awvalid",
            direction="input",
            user_annotation=declared,
        )

        self.assertIs(result.annotation, declared)
        self.assertEqual(result.source, MatchSource.USER)
        self.assertEqual(result.confidence, "declared")

    def test_higher_priority_profile_wins(self):
        registry = ProfileRegistry([
            profile(name="fallback", priority=1, semantic="generic.valid"),
            profile(name="axi", priority=10),
        ])

        result = registry.resolve_port(
            protocol="axi_lite", interface_role="target",
            port_name="awvalid", direction="input",
        )

        self.assertEqual(result.profile_name, "axi")
        self.assertEqual(result.annotation.port_type, "axi_lite.awvalid")

    def test_equal_priority_semantic_conflict_is_rejected(self):
        registry = ProfileRegistry([
            profile(name="one", semantic="axi_lite.awvalid"),
            profile(name="two", semantic="other.valid"),
        ])

        with self.assertRaisesRegex(InputValidationError, "ambiguous profile match.*one, two"):
            registry.resolve_port(
                protocol="axi_lite", interface_role="target",
                port_name="awvalid", direction="input",
            )

    def test_direction_mismatch_stays_unresolved(self):
        registry = ProfileRegistry([profile()])
        result = registry.resolve_port(
            protocol="axi_lite", interface_role="target",
            port_name="awvalid", direction="output",
        )
        self.assertEqual(result.source, MatchSource.UNRESOLVED)
        self.assertIsNone(result.annotation)

    def test_query_is_deterministic(self):
        registry = ProfileRegistry([
            profile(name="z", priority=5),
            profile(name="a", priority=5),
            profile(name="highest", priority=20),
        ])
        self.assertEqual(
            [item.name for item in registry.query("axi_lite", "target")],
            ["highest", "a", "z"],
        )


if __name__ == "__main__":
    unittest.main()
