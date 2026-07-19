import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    ContractV5DiscoveryResult,
    ContractV5Hypothesis,
    ContractV5SignalRef,
    ContractV5SystemDiscoveryReport,
    Evidence,
    EvidenceState,
    InputValidationError,
    PortDirection,
    RTLModule,
    RTLPort,
    classify_contract_v5_ambiguity,
)
from myfuzz.builder.compose_v5_layout import (  # noqa: E402
    build_compose_v5_scheme_a_rawbits_layout,
)
from myfuzz.builder.contract_discovery_v5 import (  # noqa: E402
    CONTRACT_V5_DISCOVERY_SCHEMA,
)
from myfuzz.builder.contract_v5 import (  # noqa: E402
    CONTRACT_V5_GRAMMAR_VERSION,
)
from myfuzz.builder.system_contract_discovery_v5 import (  # noqa: E402
    CONTRACT_V5_SYSTEM_DISCOVERY_SCHEMA,
)
from myfuzz.builder.contracts import content_digest  # noqa: E402


KNOWN = Evidence(EvidenceState.KNOWN, "fixture", "fixture fact")
NON_PROVABLE = Evidence(EvidenceState.NON_PROVABLE, "fixture", "fixture fact")


def _port(name: str, direction: str, width: int, evidence: Evidence = KNOWN) -> RTLPort:
    return RTLPort(name, PortDirection(direction), width, width, (), False, evidence)


def _module(
    *,
    name: str,
    ports: tuple[RTLPort, ...],
    original_name: str | None = None,
) -> RTLModule:
    return RTLModule(
        name=name,
        original_name=original_name or name,
        source_file=f"{name}.sv",
        top=True,
        level=0,
        parameters=(),
        ports=ports,
        instances=(),
        memories=(),
        dependencies=(),
        evidence=KNOWN,
    )


def _discovery_result(
    *,
    module: str,
    original_module: str,
    signal_roles: tuple[tuple[str, str], ...],
) -> ContractV5DiscoveryResult:
    signals = tuple(
        ContractV5SignalRef(
            source_id=f"{module}.{port}",
            module=original_module,
            port=port,
            direction="input",
            width=1,
            role=role,
        )
        for port, role in signal_roles
    )
    hypothesis = ContractV5Hypothesis(
        interface_kind="stream",
        interface_role="source",
        signals=signals,
        events=(),
    )
    ambiguity = classify_contract_v5_ambiguity((hypothesis,))
    evidence = {
        "frontend_module": module,
        "behavior_module_names": [original_module],
        "reason": "fixture",
        "discovery_rule": "fixture",
    }
    payload = {
        "schema": CONTRACT_V5_DISCOVERY_SCHEMA,
        "grammar_version": CONTRACT_V5_GRAMMAR_VERSION,
        "module": module,
        "original_module": original_module,
        "hypotheses": [
            {
                "interface_kind": hypothesis.interface_kind,
                "interface_role": hypothesis.interface_role,
                "signals": [
                    {
                        "source_id": signal.source_id,
                        "module": signal.module,
                        "port": signal.port,
                        "direction": signal.direction,
                        "width": signal.width,
                        "role": signal.role,
                        "polarity": signal.polarity,
                    }
                    for signal in signals
                ],
                "events": [],
                "invariants": [],
                "ordering": [],
                "source_evidence": {},
            }
        ],
        "ambiguity": ambiguity.to_dict(),
        "rejected_reasons": [],
        "evidence": evidence,
    }
    return ContractV5DiscoveryResult(
        module=module,
        original_module=original_module,
        hypotheses=(hypothesis,),
        ambiguity=ambiguity,
        rejected_reasons=(),
        evidence=evidence,
        digest=content_digest(payload),
    )


def _system_report(
    module_reports: tuple[ContractV5DiscoveryResult, ...],
) -> ContractV5SystemDiscoveryReport:
    payload = {
        "schema": CONTRACT_V5_SYSTEM_DISCOVERY_SCHEMA,
        "grammar_version": CONTRACT_V5_GRAMMAR_VERSION,
        "top_module": "fixture_top",
        "manifest_digest": "0" * 64,
        "frontend_schema": "myfuzz.frontend-behavior/v1",
        "module_reports": [item.to_dict() for item in module_reports],
        "missing_behavior_modules": [],
        "extra_behavior_modules": [],
        "binding_conflict_modules": [],
        "module_count": len(module_reports),
        "matched_count": len(module_reports),
        "unique_count": sum(item.ambiguity.status == "unique" for item in module_reports),
        "ambiguous_count": sum(item.ambiguity.status == "ambiguous" for item in module_reports),
        "empty_count": sum(item.ambiguity.status == "empty" for item in module_reports),
        "status": "unique",
    }
    return ContractV5SystemDiscoveryReport(
        top_module="fixture_top",
        manifest_digest="0" * 64,
        frontend_schema="myfuzz.frontend-behavior/v1",
        module_reports=module_reports,
        missing_behavior_modules=(),
        extra_behavior_modules=(),
        binding_conflict_modules=(),
        module_count=len(module_reports),
        matched_count=len(module_reports),
        unique_count=payload["unique_count"],
        ambiguous_count=payload["ambiguous_count"],
        empty_count=payload["empty_count"],
        status="unique",
        digest=content_digest(payload),
    )


class ComposeV5LayoutTest(unittest.TestCase):
    def test_discovery_roles_override_port_names(self) -> None:
        module = _module(
            name="cpu_renamed",
            original_name="legacy_cpu",
            ports=(
                _port("tick_in", "input", 1),
                _port("reset_n", "input", 1),
                _port("payload_bus", "input", 8),
                _port("status_out", "output", 1),
            ),
        )
        discovery = _system_report((_discovery_result(
            module="analysis_cpu",
            original_module="legacy_cpu",
            signal_roles=(
                ("tick_in", "clock"),
                ("reset_n", "reset"),
            ),
        ),))

        layout = build_compose_v5_scheme_a_rawbits_layout({"cpu0": module}, discovery=discovery)
        kinds = {field.owner: field.kind for field in layout.fields}

        self.assertEqual(layout.schema, "myfuzz.rawbits-layout/v5")
        self.assertEqual(layout.record_width_bits, 10)
        self.assertEqual(kinds["cpu0.tick_in"], "clock")
        self.assertEqual(kinds["cpu0.reset_n"], "reset")
        self.assertEqual(kinds["cpu0.payload_bus"], "external_input")
        self.assertNotIn("cpu0.status_out", kinds)

    def test_rejects_inout_ports(self) -> None:
        module = _module(
            name="cpu",
            ports=(
                _port("tick", "input", 1),
                _port("bidirectional", "inout", 1),
            ),
        )

        with self.assertRaisesRegex(InputValidationError, "rejects inout port"):
            build_compose_v5_scheme_a_rawbits_layout({"cpu0": module})

    def test_rejects_non_provable_inputs(self) -> None:
        module = _module(
            name="cpu",
            ports=(
                _port("tick", "input", 1),
                _port("unstable", "input", 1, evidence=NON_PROVABLE),
            ),
        )

        with self.assertRaisesRegex(InputValidationError, "not fully provable"):
            build_compose_v5_scheme_a_rawbits_layout({"cpu0": module})


if __name__ == "__main__":
    unittest.main()
