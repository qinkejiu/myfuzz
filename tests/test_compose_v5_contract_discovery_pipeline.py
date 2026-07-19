import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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
)
from myfuzz.builder.contracts import content_digest, validate_contract  # noqa: E402
from myfuzz.scripts.compose_v5 import main as compose_v5_main  # noqa: E402


KNOWN = Evidence(EvidenceState.KNOWN, "fixture", "fixture fact")


def _manifest() -> dict[str, object]:
    return {
        "schema": "myfuzz.compose-v5-manifest/v1",
        "name": "pipeline_fixture",
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
    }


def _write_fixture(root: Path) -> Path:
    rtl = root / "rtl"
    rtl.mkdir()
    for name in ("cpu", "ram", "ip0", "ip1"):
        (rtl / f"{name}.sv").write_text(
            f"module {name}(input logic clk_i);\nendmodule\n",
            encoding="ascii",
        )
    path = root / "compose-v5.json"
    path.write_text(json.dumps(_manifest()), encoding="ascii")
    return path


def _port(name: str, direction: str, width: int) -> RTLPort:
    return RTLPort(name, PortDirection(direction), width, width, (), False, KNOWN)


def _rtl_module(name: str) -> RTLModule:
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
            _port(f"{name}_valid", "output", 1),
            _port(f"{name}_ready", "input", 1),
            _port(f"{name}_payload", "output", 8),
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


def _transition(
    target: str,
    value: FrontendV5Expression,
    sources: tuple[str, ...],
    guard: FrontendV5Expression,
) -> FrontendV5Transition:
    return FrontendV5Transition(
        "nonblocking",
        _sig(target, 2),
        value,
        (target,),
        sources,
        (FrontendV5Guard("true", guard),),
    )


def _behavior_module(name: str) -> FrontendV5ModuleBehavior:
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
                    _transition(
                        f"{name}_state",
                        FrontendV5Expression("CONST", 2, None, "0", ()),
                        (),
                        _op("LOGNOT", (_sig(f"{name}_rst"),)),
                    ),
                    _transition(
                        f"{name}_state",
                        _sig(f"{name}_payload", 8),
                        (f"{name}_payload",),
                        _op("AND", (_sig(f"{name}_valid"), _sig(f"{name}_ready"))),
                    ),
                ),
            ),
        ),
    )


def _analysis_for(name: str) -> RTLAnalysis:
    return RTLAnalysis(
        schema="myfuzz.rtl-analysis/v1",
        manifest_digest=content_digest({"component": name}),
        frontend_schema="myfuzz.frontend.v1",
        top_module=name,
        modules=(_rtl_module(name),),
        limitations=(),
    )


def _behavior_for(name: str) -> FrontendV5Behavior:
    module = _behavior_module(name)
    payload = {"schema": "myfuzz.frontend-behavior/v1", "top_module": name, "modules": [module.name]}
    return FrontendV5Behavior(name, (module,), content_digest(payload))


class ComposeV5ContractDiscoveryPipelineTest(unittest.TestCase):
    def test_cli_discovers_declared_component_contracts_without_protocol_name_tables(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _write_fixture(root)
            output = root / "contract-discovery.json"

            def fake_analyze(elaboration, **_: object):
                return _analysis_for(elaboration.top_module), {"top": elaboration.top_module}

            def fake_extract(raw: object):
                self.assertIsInstance(raw, dict)
                return _behavior_for(raw["top"])  # type: ignore[index]

            with mock.patch(
                "myfuzz.builder.rtl_analysis.analyze_elaboration_with_frontend",
                side_effect=fake_analyze,
            ) as analyze, mock.patch(
                "myfuzz.builder.frontend_v5.extract_frontend_v5_behavior",
                side_effect=fake_extract,
            ) as extract:
                code = compose_v5_main([
                    "discover-contracts",
                    "--project-root", str(root),
                    "--manifest", str(manifest),
                    "--output", str(output),
                ])

            self.assertEqual(code, 0)
            self.assertEqual(analyze.call_count, 4)
            self.assertEqual(extract.call_count, 4)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["schema"], "myfuzz.contract-system-discovery/v5")
            self.assertEqual(report["status"], "unique")
            self.assertEqual(report["module_count"], 4)
            self.assertEqual(report["unique_count"], 4)
            self.assertEqual(report["missing_behavior_modules"], [])
            self.assertEqual(report["binding_conflict_modules"], [])
            validate_contract(report, "compose_v5_contract_discovery_v1")


if __name__ == "__main__":
    unittest.main()
