import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    AxiLiteV4Capability, EmittedHarnessV4, EnvironmentInputRuleV4,
    InputValidationError, RawBitsV4Lane, SocExternalPort,
    build_axi_lite_v4_layout, build_environment_plan_v4,
    decode_environment_replay_v4, encode_environment_replay_v4,
)


def _harness():
    layout = build_axi_lite_v4_layout(AxiLiteV4Capability(32))
    return EmittedHarnessV4(
        "environment_fixture", "", layout, "a" * 64, "b" * 64, None,
        (
            SocExternalPort("gpio_i", "input", 10, "unknown"),
            SocExternalPort("irq_i", "input", 4, "unknown"),
            SocExternalPort("status_o", "output", 3, "unknown"),
        ),
    )


class EnvironmentV4Test(unittest.TestCase):
    def test_plan_is_total_evidence_backed_and_observes_outputs(self):
        plan = build_environment_plan_v4(_harness(), {
            "gpio_i": EnvironmentInputRuleV4(
                "replay", "sampled GPIO stimulus", "user_annotation",
                "first replay record applies during reset",
            ),
            "irq_i": EnvironmentInputRuleV4(
                "constant", "interrupt disabled for protocol-only run", "cpu_profile",
                "held at zero across reset", 0,
            ),
        })
        self.assertEqual([item.port_name for item in plan.inputs], ["gpio_i", "irq_i"])
        self.assertEqual(plan.replay_record_width_bits, 16)
        self.assertEqual(plan.observed_outputs[0].port_name, "status_o")
        self.assertTrue(plan.requires_replay)
        self.assertEqual(len(plan.digest), 64)

    def test_missing_or_out_of_width_rule_fails_closed(self):
        with self.assertRaisesRegex(InputValidationError, "missing port.*irq_i"):
            build_environment_plan_v4(_harness(), {
                "gpio_i": EnvironmentInputRuleV4(
                    "replay", "GPIO", "user", "replay defines reset",
                ),
            })
        with self.assertRaisesRegex(InputValidationError, "does not fit"):
            build_environment_plan_v4(_harness(), {
                "gpio_i": EnvironmentInputRuleV4(
                    "replay", "GPIO", "user", "replay defines reset",
                ),
                "irq_i": EnvironmentInputRuleV4(
                    "constant", "IRQ", "user", "constant across reset", 16,
                ),
            })

    def test_replay_transport_round_trips_and_rejects_corruption(self):
        plan = build_environment_plan_v4(_harness(), {
            "gpio_i": EnvironmentInputRuleV4(
                "replay", "GPIO", "user", "replay defines reset",
            ),
            "irq_i": EnvironmentInputRuleV4(
                "constant", "IRQ", "user", "constant across reset", 0,
            ),
        })
        records = ({"gpio_i": 0}, {"gpio_i": 0x3FF}, {"gpio_i": 0x155})
        transport = encode_environment_replay_v4(plan, records)
        self.assertEqual(decode_environment_replay_v4(plan, transport), records)
        damaged = bytearray(transport)
        damaged[60] ^= 1
        with self.assertRaisesRegex(InputValidationError, "CRC"):
            decode_environment_replay_v4(plan, bytes(damaged))
        padded = bytearray(transport)
        padded[64 + 1] |= 0x80
        with self.assertRaisesRegex(InputValidationError, "padding bits"):
            decode_environment_replay_v4(plan, bytes(padded))


if __name__ == "__main__":
    unittest.main()
