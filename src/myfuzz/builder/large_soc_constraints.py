"""Evidence-backed external-bit contract shared by generated schemes B and C."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Mapping

from .constraint_engine import build_constraint_ir
from .contracts import ConstraintIR
from .rawbits import RawBitsLayout, build_rawbits_layout


@dataclass(frozen=True)
class AppliedExternalConstraint:
    target: str
    primitive: str
    source: str
    confidence: str
    evidence: str
    applied: bool
    affected_raw_bits: int
    raw_vs_constrained_difference: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class LargeSocExternalContract:
    layout: RawBitsLayout
    constraint_ir: ConstraintIR
    report: tuple[AppliedExternalConstraint, ...]

    def report_dicts(self) -> tuple[Mapping[str, object], ...]:
        return tuple(item.to_dict() for item in self.report)


def build_large_soc_external_contract() -> LargeSocExternalContract:
    """Build the locked signal-level contract; AccessRecord fields are deliberately absent."""
    layout = build_rawbits_layout((
        {"target": "apb_ready", "raw_width": 1, "value_width": 1,
         "purpose": "APB completion input", "provenance": "amba_apb_profile/v1"},
        {"target": "apb_read_data", "raw_width": 32, "value_width": 32,
         "purpose": "APB read response data", "provenance": "amba_apb_profile/v1"},
        {"target": "apb_error", "raw_width": 1, "value_width": 1,
         "purpose": "APB completion error", "provenance": "amba_apb_profile/v1"},
        {"target": "fuzz_irq", "raw_width": 5, "value_width": 32,
         "purpose": "entropy-matched CPU interrupt selection",
         "provenance": "qualified_cpu_interrupt_profile/v1"},
        {"target": "gpio_input", "raw_width": 33, "value_width": 32,
         "purpose": "GPIO payload plus update bit",
         "provenance": "user_annotation.gpio_sampled_input/v1"},
    ))
    constraints = build_constraint_ir(layout, (
        {"target": "apb_ready", "primitive": "DIRECT",
         "provenance": "amba_apb_profile/v1", "idle_value": 0},
        {"target": "apb_read_data", "primitive": "DEPENDENCY", "source": "apb_ready",
         "equals": 1, "fallback": 0, "provenance": "amba_apb_profile/v1", "idle_value": 0},
        {"target": "apb_error", "primitive": "DEPENDENCY", "source": "apb_ready",
         "equals": 1, "fallback": 0, "provenance": "amba_apb_profile/v1", "idle_value": 0},
        {"target": "fuzz_irq", "primitive": "ONEHOT",
         "provenance": "qualified_cpu_interrupt_profile/v1", "idle_value": 0},
        {"target": "gpio_input", "primitive": "HOLD",
         "provenance": "user_annotation.gpio_sampled_input/v1", "idle_value": 0},
    ))
    report = (
        AppliedExternalConstraint("apb_ready", "DIRECT", "protocol_profile", "proven",
                                  "PREADY is the APB transfer completion input", True, 1,
                                  "none; this bit is the dependency source"),
        AppliedExternalConstraint("apb_read_data", "DEPENDENCY", "protocol_profile", "proven",
                                  "PRDATA is consumed only on a completed APB response", True, 32,
                                  "C drives zero while PREADY=0; B forwards raw bits"),
        AppliedExternalConstraint("apb_error", "DEPENDENCY", "protocol_profile", "proven",
                                  "PSLVERR is meaningful only on a completed APB response", True, 1,
                                  "C drives zero while PREADY=0; B forwards the raw bit"),
        AppliedExternalConstraint("fuzz_irq", "ONEHOT", "cpu_profile", "proven",
                                  "both qualified CPU adapters expose a 32-bit interrupt vector", True, 5,
                                  "C decodes an interrupt index; B forwards the five entropy bits"),
        AppliedExternalConstraint("gpio_input", "HOLD", "user_annotation", "confirmed",
                                  "GPIO input is annotated as sampled payload plus update enable", True, 33,
                                  "C changes payload only when update=1; B forwards payload every cycle"),
    )
    return LargeSocExternalContract(layout, constraints, report)
