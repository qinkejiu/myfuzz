import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
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
    build_compose_v5_connection_plan,
    compose_v5_manifest_from_dict,
    discover_contract_v5_system,
)
from myfuzz.builder.contracts import content_digest, validate_contract  # noqa: E402


KNOWN = Evidence(EvidenceState.KNOWN, "fixture", "fixture fact")


def _port(name: str, direction: str, width: int) -> RTLPort:
    return RTLPort(name, PortDirection(direction), width, width, (), False, KNOWN)


def _module(name: str, *, initiator: bool) -> RTLModule:
    return RTLModule(
        name=name,
        original_name=name,
        source_file=f"{name}.sv",
        top=True,
        level=0,
        parameters=(),
        ports=(
            _port(f"{name}_clk", "input", 1),
            _port(f"{name}_rst", "input", 1),
            _port(f"{name}_valid", "output" if initiator else "input", 1),
            _port(f"{name}_ready", "input" if initiator else "output", 1),
            _port(f"{name}_payload", "output" if initiator else "input", 8),
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


def _behavior(name: str) -> FrontendV5ModuleBehavior:
    return FrontendV5ModuleBehavior(
        name=name,
        original_name=name,
        processes=(
            FrontendV5Process(
                0,
                "always_ff",
                (
                    FrontendV5Sensitivity("posedge", _sig(f"{name}_clk"), (f"{name}_clk",)),
                    FrontendV5Sensitivity("negedge", _sig(f"{name}_rst"), (f"{name}_rst",)),
                ),
                (
                    FrontendV5Transition(
                        "nonblocking",
                        _sig(f"{name}_state", 2),
                        FrontendV5Expression("CONST", 2, None, "0", ()),
                        (f"{name}_state",),
                        (),
                        (FrontendV5Guard("true", _op("LOGNOT", (_sig(f"{name}_rst"),))),),
                    ),
                    FrontendV5Transition(
                        "nonblocking",
                        _sig(f"{name}_state", 2),
                        _sig(f"{name}_payload", 8),
                        (f"{name}_state",),
                        (f"{name}_payload",),
                        (FrontendV5Guard("true", _op("AND", (_sig(f"{name}_valid"), _sig(f"{name}_ready")))),),
                    ),
                ),
            ),
        ),
    )


def _manifest() -> object:
    return compose_v5_manifest_from_dict({
        "schema": "myfuzz.compose-v5-manifest/v1",
        "name": "connection_fixture",
        "sources": [
            {"id": name, "rtl_files": [f"rtl/{name}.sv"], "filelists": []}
            for name in ("cpu", "ram", "ip0", "ip1")
        ],
        "components": [
            {"id": "cpu0", "role": "cpu", "module": "cpu", "source_set": "cpu", "parameters": {}},
            {"id": "ram0", "role": "ram", "module": "ram", "source_set": "ram", "parameters": {}},
            {"id": "ip0", "role": "ip", "module": "ip0", "source_set": "ip0", "parameters": {}},
            {"id": "ip1", "role": "ip", "module": "ip1", "source_set": "ip1", "parameters": {}},
        ],
        "digest": "",
    })


class ComposeV5ConnectionPlanTest(unittest.TestCase):
    def test_connection_plan_uses_cpu_as_only_master_and_records_address_windows(self) -> None:
        manifest = _manifest()
        modules = {
            "cpu0": _module("cpu", initiator=True),
            "ram0": _module("ram", initiator=False),
            "ip0": _module("ip0", initiator=False),
            "ip1": _module("ip1", initiator=False),
        }
        behavior_modules = tuple(_behavior(module.name) for module in modules.values())
        behavior_payload = {
            "schema": "myfuzz.frontend-behavior/v1",
            "top_module": "connection_fixture",
            "modules": [module.name for module in behavior_modules],
        }
        discovery = discover_contract_v5_system(
            RTLAnalysis(
                "myfuzz.rtl-analysis/v1",
                manifest.digest,
                "myfuzz.frontend.v1",
                "connection_fixture",
                tuple(modules.values()),
                (),
            ),
            FrontendV5Behavior(
                "connection_fixture",
                behavior_modules,
                content_digest(behavior_payload),
            ),
        )

        plan = build_compose_v5_connection_plan(manifest, modules, discovery)

        validate_contract(plan.to_dict(), "compose_v5_connection_plan_v1")
        self.assertEqual(plan.master_component, "cpu0")
        self.assertEqual(plan.incomplete_reasons, ())
        self.assertEqual(
            {(edge["source_component"], edge["target_component"], edge["status"]) for edge in plan.edges},
            {("cpu0", "ram0", "planned"), ("cpu0", "ip0", "planned"), ("cpu0", "ip1", "planned")},
        )
        windows = {item["component"]: item["base"] for item in plan.address_map}
        self.assertEqual(windows, {"ram0": 0x0000_0000, "ip0": 0x4000_0000, "ip1": 0x4000_1000})
        self.assertTrue(all(item["status"] == "direct" for item in plan.bridge_requirements))


if __name__ == "__main__":
    unittest.main()
