import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    CONTRACT_V5_SYSTEM_DISCOVERY_SCHEMA,
    FrontendV5Behavior,
    FrontendV5Expression,
    FrontendV5Guard,
    FrontendV5ModuleBehavior,
    FrontendV5Process,
    FrontendV5Sensitivity,
    FrontendV5Transition,
    RTLAnalysis,
    RTLModule,
    RTLPort,
    Evidence,
    EvidenceState,
    PortDirection,
    discover_contract_v5_system,
)
from myfuzz.builder.contracts import content_digest, validate_contract  # noqa: E402
from myfuzz.builder.input_model import InputValidationError  # noqa: E402


KNOWN = Evidence(EvidenceState.KNOWN, "fixture", "fixture fact")


def port(name: str, direction: str, width: int) -> RTLPort:
    return RTLPort(name, PortDirection(direction), width, width, (), False, KNOWN)


def module(
    name: str,
    *,
    original_name: str | None = None,
    prefix: str | None = None,
) -> RTLModule:
    stem = prefix or name
    original = original_name or name
    return RTLModule(
        name=name,
        original_name=original,
        source_file="fixture.sv",
        top=False,
        level=0,
        parameters=(),
        ports=(
            port(f"{stem}_clk", "input", 1),
            port(f"{stem}_rst", "input", 1),
            port(f"{stem}_req_valid", "output", 1),
            port(f"{stem}_req_ready", "input", 1),
            port(f"{stem}_payload", "output", 8),
        ),
        instances=(),
        memories=(),
        dependencies=(),
        evidence=KNOWN,
    )


def sig(name: str, width: int = 1) -> FrontendV5Expression:
    return FrontendV5Expression("VARREF", width, name, None, ())


def const(width: int, value: str) -> FrontendV5Expression:
    return FrontendV5Expression("CONST", width, None, value, ())


def op(kind: str, children: tuple[FrontendV5Expression, ...], width: int = 1) -> FrontendV5Expression:
    return FrontendV5Expression(kind, width, None, None, children)


def transition(
    target: str,
    value: FrontendV5Expression,
    sources: tuple[str, ...],
    guard: FrontendV5Expression,
) -> FrontendV5Transition:
    return FrontendV5Transition(
        "nonblocking",
        sig(target, 2),
        value,
        (target,),
        sources,
        (FrontendV5Guard("true", guard),),
    )


def behavior_module(
    name: str,
    *,
    original_name: str | None = None,
    prefix: str | None = None,
) -> FrontendV5ModuleBehavior:
    stem = prefix or name
    original = original_name or name
    clock = f"{stem}_clk"
    reset = f"{stem}_rst"
    valid = f"{stem}_req_valid"
    ready = f"{stem}_req_ready"
    payload = f"{stem}_payload"
    state = f"{stem}_state"
    return FrontendV5ModuleBehavior(
        name=name,
        original_name=original,
        processes=(
            FrontendV5Process(
                0,
                "always_ff",
                (
                    FrontendV5Sensitivity("posedge", sig(clock), (clock,)),
                    FrontendV5Sensitivity("negedge", sig(reset), (reset,)),
                ),
                (
                    transition(state, const(2, "0"), (), op("LOGNOT", (sig(reset),))),
                    transition(state, sig(payload, 8), (payload,), op("AND", (sig(valid), sig(ready)))),
                ),
            ),
        ),
    )


def behavior(top_module: str, modules: tuple[FrontendV5ModuleBehavior, ...]) -> FrontendV5Behavior:
    module_payload = sorted(
        ({"name": item.name, "original_name": item.original_name} for item in modules),
        key=lambda item: (item["name"], item["original_name"]),
    )
    payload = {
        "schema": "myfuzz.frontend-behavior/v1",
        "top_module": top_module,
        "modules": module_payload,
    }
    return FrontendV5Behavior(top_module=top_module, modules=modules, digest=content_digest(payload))


def analysis(top_module: str, modules: tuple[RTLModule, ...]) -> RTLAnalysis:
    module_names = sorted(item.name for item in modules)
    return RTLAnalysis(
        schema="myfuzz.rtl-analysis/v1",
        manifest_digest=content_digest({"top_module": top_module, "modules": module_names}),
        frontend_schema="myfuzz.frontend-behavior/v1",
        top_module=top_module,
        modules=modules,
        limitations=(),
    )


class ComposeV5SystemContractDiscoveryTest(unittest.TestCase):
    def test_system_discovery_is_order_stable_and_alias_based(self):
        alpha_mod = module("alpha_elab", original_name="alpha_src", prefix="alpha")
        beta_mod = module("beta_elab", original_name="beta_src", prefix="beta")
        alpha_beh = behavior_module("alpha_view", original_name="alpha_src", prefix="alpha")
        beta_beh = behavior_module("beta_view", original_name="beta_src", prefix="beta")

        first = discover_contract_v5_system(
            analysis("system_top", (beta_mod, alpha_mod)),
            behavior("system_top", (beta_beh, alpha_beh)),
        )
        second = discover_contract_v5_system(
            analysis("system_top", (alpha_mod, beta_mod)),
            behavior("system_top", (alpha_beh, beta_beh)),
        )

        self.assertEqual(first.status, "unique")
        self.assertEqual(second.status, "unique")
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first.module_reports[0].module, "alpha_elab")
        self.assertEqual(first.module_reports[1].module, "beta_elab")
        validate_contract(first.to_dict(), "compose_v5_contract_discovery_v1")
        self.assertEqual(first.schema, CONTRACT_V5_SYSTEM_DISCOVERY_SCHEMA)

    def test_system_discovery_reports_partial_missing_and_extra_modules(self):
        alpha_mod = module("alpha_top", prefix="alpha")
        beta_mod = module("beta_top", prefix="beta")
        alpha_beh = behavior_module("alpha_top", prefix="alpha")
        extra_beh = behavior_module("gamma_view", prefix="gamma")

        report = discover_contract_v5_system(
            analysis("system_top", (beta_mod, alpha_mod)),
            behavior("system_top", (alpha_beh, extra_beh)),
        )

        self.assertEqual(report.status, "partial")
        self.assertEqual(report.matched_count, 1)
        self.assertEqual(report.unique_count, 1)
        self.assertEqual(report.empty_count, 1)
        self.assertEqual(report.ambiguous_count, 0)
        self.assertEqual(report.missing_behavior_modules, ("beta_top",))
        self.assertEqual(report.extra_behavior_modules, ("gamma_view",))
        self.assertEqual(report.binding_conflict_modules, ())
        self.assertEqual(
            [item.ambiguity.status for item in report.module_reports],
            ["unique", "empty"],
        )
        validate_contract(report.to_dict(), "compose_v5_contract_discovery_v1")

    def test_system_discovery_reports_binding_conflicts_as_ambiguous(self):
        alpha_mod = module("alpha_top", prefix="alpha")
        beta_mod = module("beta_top", prefix="beta")
        alpha_beh_a = behavior_module("alpha_view_a", original_name="alpha_top", prefix="alpha")
        alpha_beh_b = behavior_module("alpha_view_b", original_name="alpha_top", prefix="alpha")
        beta_beh = behavior_module("beta_view", original_name="beta_top", prefix="beta")

        report = discover_contract_v5_system(
            analysis("system_top", (alpha_mod, beta_mod)),
            behavior("system_top", (alpha_beh_b, beta_beh, alpha_beh_a)),
        )

        self.assertEqual(report.status, "ambiguous")
        self.assertEqual(report.binding_conflict_modules, ("alpha_top",))
        self.assertEqual(report.missing_behavior_modules, ())
        self.assertEqual(report.extra_behavior_modules, ())
        self.assertEqual(report.matched_count, 1)
        self.assertEqual(report.unique_count, 1)
        self.assertEqual(report.empty_count, 1)
        self.assertEqual(report.module_reports[0].ambiguity.status, "empty")
        self.assertEqual(report.module_reports[1].ambiguity.status, "unique")
        validate_contract(report.to_dict(), "compose_v5_contract_discovery_v1")

    def test_system_discovery_reports_empty_when_everything_is_missing(self):
        alpha_mod = module("alpha_top", prefix="alpha")
        report = discover_contract_v5_system(
            analysis("system_top", (alpha_mod,)),
            behavior("system_top", ()),
        )

        self.assertEqual(report.status, "empty")
        self.assertEqual(report.matched_count, 0)
        self.assertEqual(report.unique_count, 0)
        self.assertEqual(report.ambiguous_count, 0)
        self.assertEqual(report.empty_count, 1)
        self.assertEqual(report.missing_behavior_modules, ("alpha_top",))
        self.assertEqual(report.extra_behavior_modules, ())
        self.assertEqual(report.binding_conflict_modules, ())
        validate_contract(report.to_dict(), "compose_v5_contract_discovery_v1")

    def test_system_discovery_rejects_incompatible_types(self):
        with self.assertRaises(InputValidationError):
            discover_contract_v5_system(object(), behavior("system_top", ()))  # type: ignore[arg-type]
        with self.assertRaises(InputValidationError):
            discover_contract_v5_system(analysis("system_top", ()), object())  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
