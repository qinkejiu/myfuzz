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
    build_compose_v5_scheme_a_rawbits_layout,
    compose_v5_manifest_from_dict,
    discover_contract_v5_system,
    emit_compose_v5_generated_soc_harness_bundle,
    emit_compose_v5_generated_soc_top,
)
from myfuzz.builder.contracts import content_digest  # noqa: E402


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
        "name": "soc_fixture",
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


def _fixture() -> tuple[object, dict[str, RTLModule], object]:
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
        "top_module": "soc_fixture",
        "modules": [module.name for module in behavior_modules],
    }
    discovery = discover_contract_v5_system(
        RTLAnalysis(
            "myfuzz.rtl-analysis/v1",
            manifest.digest,
            "myfuzz.frontend.v1",
            "soc_fixture",
            tuple(modules.values()),
            (),
        ),
        FrontendV5Behavior("soc_fixture", behavior_modules, content_digest(behavior_payload)),
    )
    return manifest, modules, discovery


class ComposeV5GeneratedSocTest(unittest.TestCase):
    def test_generated_soc_broadcasts_guarded_bit_level_edges_and_exposes_only_remaining_inputs(self) -> None:
        manifest, modules, discovery = _fixture()
        plan = build_compose_v5_connection_plan(manifest, modules, discovery)

        soc = emit_compose_v5_generated_soc_top(modules, plan, module_name="generated_soc_fixture")

        self.assertEqual(soc.connection_plan_digest, plan.digest)
        self.assertIn("module generated_soc_fixture (", soc.rtl)
        self.assertIn("input logic cpu0__cpu_clk", soc.rtl)
        self.assertIn("input logic cpu0__cpu_rst", soc.rtl)
        self.assertNotIn("input logic cpu0__cpu_ready", soc.rtl)
        self.assertNotIn("input logic ip0__ip0_valid", soc.rtl)
        self.assertNotIn("input logic [7:0] ip0__ip0_payload", soc.rtl)
        self.assertIn("assign ip0__ip0_valid = cpu0__cpu_valid;", soc.rtl)
        self.assertIn("assign ip0__ip0_payload = cpu0__cpu_payload;", soc.rtl)
        self.assertIn("assign ip1__ip1_valid = cpu0__cpu_valid;", soc.rtl)
        self.assertIn("assign ram0__ram_valid = cpu0__cpu_valid;", soc.rtl)
        self.assertIn(
            "assign cpu0__cpu_ready = (ip0__ip0_ready | ip1__ip1_ready | ram0__ram_ready);",
            soc.rtl,
        )
        self.assertIn("No address signal role is available in v1 discovery", soc.rtl)

    def test_generated_soc_harness_keeps_rawbits_width_and_ignores_internally_driven_fields(self) -> None:
        manifest, modules, discovery = _fixture()
        plan = build_compose_v5_connection_plan(manifest, modules, discovery)
        layout = build_compose_v5_scheme_a_rawbits_layout(modules, discovery=discovery)

        bundle = emit_compose_v5_generated_soc_harness_bundle(
            modules,
            plan,
            layout,
            soc_module_name="generated_soc_fixture",
            harness_module_name="generated_soc_harness_fixture",
        )

        self.assertEqual(bundle.harness.rawbits_width, layout.record_width_bits)
        self.assertIn("module generated_soc_fixture (", bundle.rtl)
        self.assertIn("module generated_soc_harness_fixture (", bundle.rtl)
        self.assertIn("Unused rawbits fields correspond to ports now driven", bundle.harness.rtl)
        self.assertIn("cpu0.cpu_ready", bundle.harness.unused_layout_owners)
        self.assertIn("ip0.ip0_valid", bundle.harness.unused_layout_owners)
        self.assertIn("ip0.ip0_payload", bundle.harness.unused_layout_owners)
        self.assertNotIn("assign cpu0__cpu_ready = rawbits_i", bundle.harness.rtl)
        self.assertNotIn("assign ip0__ip0_valid = rawbits_i", bundle.harness.rtl)


if __name__ == "__main__":
    unittest.main()
