import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (
    DecisionStatus,
    InputValidationError,
    UnknownInputRequest,
    UnknownPortAction,
    decide_unknown_port,
    unknown_port_report,
)


class UnknownPortPolicyTest(unittest.TestCase):
    def test_unknown_input_requires_user_by_default(self):
        decision = decide_unknown_port(module="gpio", port="mode_i", direction="input", width=2)
        self.assertEqual(decision.action, UnknownPortAction.USER_REQUIRED)
        self.assertEqual(decision.status, DecisionStatus.NEEDS_USER)
        self.assertIn("leave undriven", decision.resulting_action)

    def test_unknown_output_is_observed_not_driven(self):
        decision = decide_unknown_port(module="timer", port="event_o", direction="output", width=1)
        self.assertEqual(decision.action, UnknownPortAction.OBSERVE)
        self.assertEqual(decision.status, DecisionStatus.PLANNED)
        self.assertNotIn("drive", decision.resulting_action)

    def test_unknown_inout_is_rejected_and_reported(self):
        decision = decide_unknown_port(module="gpio", port="pad", direction="inout", width=8)
        report = unknown_port_report([decision])
        self.assertEqual(decision.status, DecisionStatus.REJECTED)
        self.assertTrue(report["has_rejections"])
        self.assertEqual(report["unknown_ports"][0]["action"], "reject")
        self.assertEqual(report["unknown_ports"][0]["width"], 8)

    def test_explicit_tieoff_is_reportable(self):
        decision = decide_unknown_port(
            module="uart", port="test_mode", direction="input", width=1,
            input_request=UnknownInputRequest(
                action=UnknownPortAction.TIEOFF,
                reason="unused test mode is documented inactive low",
                tieoff_value=0,
            ),
        )
        self.assertEqual(decision.resulting_action, "drive constant 0")
        self.assertEqual(decision.evidence_source, "user")
        json.dumps(decision.to_report_dict())

    def test_rfuzz_drive_requires_reset_behavior(self):
        request = UnknownInputRequest(
            action=UnknownPortAction.RFUZZ_DRIVE,
            reason="explicitly selected fuzz input",
        )
        with self.assertRaisesRegex(InputValidationError, "reset_behavior"):
            decide_unknown_port(
                module="gpio", port="gpio_i", direction="input", width=8,
                input_request=request,
            )

    def test_constrained_random_records_constraint_and_reset(self):
        decision = decide_unknown_port(
            module="unit", port="mode", direction="input", width=3,
            input_request=UnknownInputRequest(
                action=UnknownPortAction.CONSTRAINED_RANDOM,
                reason="mode field may vary within documented range",
                constraint="value <= 5",
                reset_behavior="hold 0 while reset is asserted",
            ),
        )
        self.assertEqual(decision.constraint, "value <= 5")
        self.assertEqual(decision.reset_behavior, "hold 0 while reset is asserted")

    def test_connect_requires_named_driver(self):
        request = UnknownInputRequest(
            action=UnknownPortAction.CONNECT,
            reason="matched by system integrator",
        )
        with self.assertRaisesRegex(InputValidationError, "connect_to"):
            decide_unknown_port(
                module="unit", port="irq_ack", direction="input", width=1,
                input_request=request,
            )

    def test_unknown_input_can_be_exposed_externally(self):
        decision = decide_unknown_port(
            module="uart", port="rx_i", direction="input", width=1,
            input_request=UnknownInputRequest(
                action=UnknownPortAction.EXTERNAL_INPUT,
                reason="board-level UART receive pin",
            ),
        )
        self.assertEqual(decision.action, UnknownPortAction.EXTERNAL_INPUT)
        self.assertIn("external input", decision.resulting_action)


if __name__ == "__main__":
    unittest.main()
