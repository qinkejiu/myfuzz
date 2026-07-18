import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    InputValidationError, UnknownInputRequest, UnknownPortAction,
    decide_unknown_port, map_unknown_ports_to_harness,
)


def decision(module, port, direction, width, action=None, **kwargs):
    request = None if action is None else UnknownInputRequest(
        action=action, reason=f"evidence for {module}.{port}", **kwargs,
    )
    return decide_unknown_port(
        module=module, port=port, direction=direction, width=width, input_request=request,
    )


class HarnessPolicyTest(unittest.TestCase):
    def test_total_mapping_preserves_mode_and_boundary_semantics(self):
        decisions = (
            decision("unit", "fixed", "input", 1, UnknownPortAction.TIEOFF, tieoff_value=0),
            decision("unit", "direct", "input", 3, UnknownPortAction.RFUZZ_DRIVE,
                     reset_behavior="hold zero during reset"),
            decision("unit", "bounded", "input", 3, UnknownPortAction.CONSTRAINED_RANDOM,
                     constraint="profile range", reset_behavior="hold zero during reset"),
            decision("unit", "board", "input", 1, UnknownPortAction.EXTERNAL_INPUT),
            decision("unit", "linked", "input", 1, UnknownPortAction.CONNECT,
                     connect_to="source.flag"),
            decision("unit", "result", "output", 4),
        )
        plan = map_unknown_ports_to_harness(decisions, constrained_rules={
            "unit.bounded": {"primitive": "RANGE", "minimum": 1, "maximum": 5},
        })
        by_port = {item.qualified_port: item for item in plan.mappings}
        self.assertEqual(len(by_port), len(decisions))
        self.assertEqual(by_port["unit.fixed"].raw_behavior, "fixed:0")
        self.assertEqual(by_port["unit.direct"].constrained_behavior, "DIRECT")
        self.assertEqual(by_port["unit.bounded"].raw_behavior, "DIRECT")
        self.assertEqual(by_port["unit.bounded"].constrained_behavior, "RANGE")
        self.assertEqual(plan.external_inputs, ("ext_unit_board",))
        self.assertEqual(plan.observed_outputs, ("obs_unit_result",))
        self.assertEqual({entry.target for entry in plan.layout.entries}, {
            "ext_unit_bounded", "ext_unit_direct",
        })
        self.assertEqual(plan.constraint_ir.layout_digest, plan.layout.digest)
        self.assertTrue(all(item.evidence for item in plan.mappings))

    def test_mapping_rejects_unresolved_inout_and_unstructured_constraints(self):
        unresolved = decision("unit", "mystery", "input", 1)
        with self.assertRaisesRegex(InputValidationError, "not planned"):
            map_unknown_ports_to_harness((unresolved,))
        inout = decision("unit", "pad", "inout", 1)
        with self.assertRaisesRegex(InputValidationError, "not planned"):
            map_unknown_ports_to_harness((inout,))
        constrained = decision(
            "unit", "mode", "input", 2, UnknownPortAction.CONSTRAINED_RANDOM,
            constraint="value <= 2", reset_behavior="zero during reset",
        )
        with self.assertRaisesRegex(InputValidationError, "structured rule"):
            map_unknown_ports_to_harness((constrained,))


if __name__ == "__main__":
    unittest.main()
