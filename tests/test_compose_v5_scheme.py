import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    ContractV5SystemDiscoveryReport,
    Evidence,
    EvidenceState,
    FrontendV5Behavior,
    FrontendV5Expression,
    FrontendV5Guard,
    FrontendV5ModuleBehavior,
    FrontendV5Process,
    FrontendV5Sensitivity,
    FrontendV5Transition,
    PortDirection,
    RTLAnalysis,
    RTLModule,
    RTLPort,
    build_compose_v5_abcd_scheme_plan,
    build_compose_v5_scheme_a_rawbits_layout,
    discover_contract_v5_system,
)
from myfuzz.builder.contracts import content_digest, validate_contract  # noqa: E402


KNOWN = Evidence(EvidenceState.KNOWN, "fixture", "fixture fact")


def _port(name: str, direction: str, width: int) -> RTLPort:
    return RTLPort(name, PortDirection(direction), width, width, (), False, KNOWN)


def _module(name: str) -> RTLModule:
    return RTLModule(
        name=name,
        original_name=name,
        source_file=f"{name}.sv",
        top=True,
        level=0,
        parameters=(),
        ports=(
            _port("edge_a", "input", 1),
            _port("clear_b", "input", 1),
            _port("gate_c", "input", 1),
            _port("credit_d", "output", 1),
            _port("opaque_e", "input", 8),
            _port("observe_f", "output", 4),
        ),
        instances=(),
        memories=(),
        dependencies=(),
        evidence=KNOWN,
    )


def _sig(name: str, width: int = 1) -> FrontendV5Expression:
    return FrontendV5Expression("VARREF", width, name, None, ())


def _op(kind: str, children: tuple[FrontendV5Expression, ...]) -> FrontendV5Expression:
    return FrontendV5Expression(kind, 1, None, None, children)


def _behavior(name: str) -> FrontendV5Behavior:
    module = FrontendV5ModuleBehavior(
        name=name,
        original_name=name,
        processes=(
            FrontendV5Process(
                0,
                "always_ff",
                (
                    FrontendV5Sensitivity("posedge", _sig("edge_a"), ("edge_a",)),
                    FrontendV5Sensitivity("negedge", _sig("clear_b"), ("clear_b",)),
                ),
                (
                    FrontendV5Transition(
                        "nonblocking",
                        _sig("state_q", 2),
                        FrontendV5Expression("CONST", 2, None, "0", ()),
                        ("state_q",),
                        (),
                        (FrontendV5Guard("true", _op("LOGNOT", (_sig("clear_b"),))),),
                    ),
                    FrontendV5Transition(
                        "nonblocking",
                        _sig("state_q", 2),
                        _sig("opaque_e", 8),
                        ("state_q",),
                        ("opaque_e",),
                        (FrontendV5Guard("true", _op("AND", (_sig("gate_c"), _sig("credit_d")))),),
                    ),
                ),
            ),
        ),
    )
    payload = {"schema": "myfuzz.frontend-behavior/v1", "top_module": name, "modules": [module.name]}
    return FrontendV5Behavior(name, (module,), content_digest(payload))


def _discovery(module: RTLModule) -> ContractV5SystemDiscoveryReport:
    analysis = RTLAnalysis(
        "myfuzz.rtl-analysis/v1",
        "1" * 64,
        "myfuzz.frontend.v1",
        "fixture",
        (module,),
        (),
    )
    return discover_contract_v5_system(analysis, _behavior(module.name))


class ComposeV5SchemePlanTest(unittest.TestCase):
    def test_abcd_plan_preserves_rawbits_and_adds_bit_level_constraints(self) -> None:
        module = _module("unseen_endpoint")
        discovery = _discovery(module)
        layout = build_compose_v5_scheme_a_rawbits_layout({"endpoint0": module}, discovery=discovery)

        plan = build_compose_v5_abcd_scheme_plan(
            {"endpoint0": module},
            layout,
            discovery,
            manifest_digest="2" * 64,
            stall_inputs_before_escalation=17,
        )

        validate_contract(plan.to_dict(), "compose_v5_scheme_plan_v1")
        self.assertEqual(plan.schema, "myfuzz.compose-v5-scheme-plan/v1")
        self.assertEqual([scheme["id"] for scheme in plan.schemes], ["A", "B", "C", "D"])
        self.assertEqual([scheme["record_width_bits"] for scheme in plan.schemes], [11, 11, 11, 19])
        field_owners = {
            field["owner"]
            for scheme in plan.schemes
            for field in scheme["field_uses"]  # type: ignore[index]
        }
        self.assertEqual(field_owners, {
            "endpoint0.clear_b",
            "endpoint0.edge_a",
            "endpoint0.gate_c",
            "endpoint0.opaque_e",
        })
        c_rules = {rule["primitive"]: rule for rule in plan.schemes[2]["constraint_rules"]}  # type: ignore[index]
        self.assertEqual(c_rules["clock_projector"]["target"], "endpoint0.edge_a")
        self.assertEqual(c_rules["reset_window_projector"]["target"], "endpoint0.clear_b")
        self.assertEqual(c_rules["valid_hold_until_accept"]["target"], "endpoint0.gate_c")
        self.assertEqual(c_rules["payload_stable_while_unaccepted"]["target"], "endpoint0.opaque_e")
        d = plan.schemes[3]
        self.assertEqual(d["perturbation"]["stall_inputs_before_escalation"], 17)  # type: ignore[index]
        self.assertEqual(
            [field["name"] for field in d["synthetic_fields"]],  # type: ignore[index]
            ["perturb_strength", "perturb_mask"],
        )
        self.assertTrue(all(
            rule["scope"] == "bit_level"
            for rule in d["constraint_rules"]  # type: ignore[index]
        ))


if __name__ == "__main__":
    unittest.main()
