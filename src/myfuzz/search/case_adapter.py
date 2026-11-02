"""Per-case interface between a search policy and an existing live runtime.

Adapters execute decisions using explicit case context. Feedback and authority
remain owned by the underlying runtime, and are not inferred from execution.
"""
from dataclasses import dataclass
from typing import Any, Callable, Protocol, runtime_checkable


@dataclass(frozen=True)
class CaseContext:
    case_id: str
    deadline_ns: int | None = None
    replay_advance_count: int | None = None
    # Optional persistence/validation after lowering, before actual submission.
    # The value is backend-specific: a lowered case or an atomic decision.
    on_prepared: Callable[[Any], None] | None = None


@runtime_checkable
class CaseAdapter(Protocol):
    def current_state(self) -> Any: ...
    def execute(self, decision: Any, context: CaseContext) -> Any: ...
    def settle(self, decision: Any, context: CaseContext, receipt: Any,
               current: Any, features: Any, cost_ns: int) -> Any: ...
