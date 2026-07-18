"""Read-only conversion from the retained builder plan into SystemIR v1."""

from __future__ import annotations

from .ir import SystemIR, validate_contract
from ..planner import SystemPlan


def adapt_legacy_plan(plan: SystemPlan) -> SystemIR:
    modules = tuple(
        {"name": item.module, "kind": item.kind.value, "source": item.source}
        for item in sorted(plan.classifications, key=lambda value: value.module)
    )
    connections = tuple(
        {
            "order": edge.order, "source": edge.source.label(), "target": edge.target.label(),
            "width": edge.width, "kind": edge.kind.value, "evidence": edge.evidence_source,
        }
        for edge in plan.graph.connections
    )
    windows = tuple(
        {"module": window.module, "base": window.base, "size": window.size}
        for window in plan.address_plan.windows
    )
    result = SystemIR(plan.name, modules, connections, windows)
    validate_contract(result.to_dict(), "system_ir_v1")
    return result
