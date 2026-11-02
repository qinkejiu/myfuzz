"""Mixed F2+F4 storage campaign: two flow kernels on one shared harness.

The runtime is ``CompiledF4Runtime(mixed_flows=True)``: one CPU session, one
target session, one register-version authority, one PersistentMemory, one
ScenarioRunner and one ScenarioSession.  This module supplies:

* ``MixedStorageKernel`` — the fixed §5.2 kernel interface over two per-flow
  ``StorageFlowKernel`` contexts (requirements union, per-case lower, capture
  dispatched by the flow certificate schema, combined feedback);
* ``MixedStorageFlowBackend`` / ``MixedStorageFlowChannel`` — campaign backend
  that adopts that existing runtime and forwards the per-case flow.

No session, memory, runner or evidence store is created here.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Mapping

from ...runtime.contracts import GenericRuntimeRefused
from .storage import (
    KERNEL_SCHEMA,
    STORAGE_FLOWS,
    FlowContext,
    StorageFlowBackend,
    StorageFlowChannel,
    StorageFlowKernel,
)

MIXED_KERNEL_ID = "storage.kernel.mixed.v1"
MIXED_SCHEMA = "generic_mixed_flow_kernel.v1"
_CERTIFICATE_FLOWS = {
    "compiled_F2_chain.v1": "F2",
    "compiled_F4_chain.v3": "F4",
}


def _refuse(code: str, pointer: str = "", detail=None) -> None:
    raise GenericRuntimeRefused(code, pointer, detail)


@dataclass(slots=True)
class MixedFlowContext:
    """One prepared context per flow; both reference the same bound plan."""

    plan_sha256: str
    flows: dict = field(default_factory=dict)
    kernel_id: str = MIXED_KERNEL_ID

    def document(self) -> dict:
        return {
            "schema_version": MIXED_SCHEMA,
            "kernel_id": self.kernel_id,
            "plan_sha256": self.plan_sha256,
            "flow_ids": sorted(self.flows),
            "flows": {flow: context.document()
                      for flow, context in sorted(self.flows.items())},
            "live_handle": False,
            "owns_session": False,
            "owns_runner": False,
            "owns_memory": False,
        }


class MixedStorageKernel:
    """The design §5.2 interface for one campaign that uses both F2 and F4."""

    kernel_id = MIXED_KERNEL_ID

    def __init__(self, *, include_memory=False, flow_ids=None):
        declared = tuple(flow_ids) if flow_ids is not None else (
            ('F1','F2','F3','F4') if include_memory else STORAGE_FLOWS)
        if not declared or len(set(declared))!=len(declared) or set(declared)-{'F1','F2','F3','F4','F5'}:
            _refuse('generic-flow-unsupported','/flow_ids')
        self._kernels = {flow: StorageFlowKernel() for flow in declared if flow in STORAGE_FLOWS}
        if set(declared)&{'F1','F3'}:
            from .memory import MemoryFlowKernel
            self._kernels.update({flow: MemoryFlowKernel() for flow in declared if flow in ('F1', 'F3')})
        if 'F5' in declared:
            from .irq import PinFlowKernel
            self._kernels['F5']=PinFlowKernel()

    # -- requirements ------------------------------------------------------
    def requirements(self, d3_path) -> tuple:
        """Union of the per-flow kernel requirements for the declared rows."""
        if isinstance(d3_path, Mapping):
            rows = [d3_path]
        elif isinstance(d3_path, (list, tuple)):
            rows = list(d3_path)
        else:
            _refuse("generic-contract-type", "/path",
                    {"expected": "plan path row or sequence of rows"})
        requirements = {}
        for row in rows:
            if not isinstance(row, Mapping):
                _refuse("generic-contract-type", "/path")
            flow = row.get("flow_id")
            if flow not in self._kernels:
                _refuse("generic-flow-unsupported", "/flow_id",
                        {"flow_id": flow, "supported": sorted(self._kernels)})
            derive = getattr(self._kernels[flow], 'requirements', None)
            if not callable(derive):
                _refuse('generic-semantic-unsupported', '/path/requirements',
                        {'flow_id': flow, 'reason': 'flow-requirements-unavailable'})
            for requirement in derive(row):
                key = (requirement.role, requirement.endpoint_id)
                prior = requirements.get(key)
                if prior is not None:
                    # One physical endpoint must satisfy all selected flows.
                    # Never let the last row silently erase a prior obligation.
                    normalized = replace(requirement, operations=prior.operations,
                                         evidence_obligations=prior.evidence_obligations)
                    if normalized != prior:
                        _refuse('generic-template-mismatch', '/path/bindings',
                                {'reason': 'mixed-endpoint-requirements-conflict',
                                 'role': key[0], 'endpoint_id': key[1]})
                    requirement = replace(prior,
                        operations=tuple(sorted(set(prior.operations) | set(requirement.operations))),
                        evidence_obligations=tuple(sorted(set(prior.evidence_obligations)
                                                        | set(requirement.evidence_obligations))))
                requirements[key] = requirement
        return tuple(requirements[key] for key in sorted(requirements))

    # -- prepare -----------------------------------------------------------
    def prepare(self, bound_plan, path_id) -> MixedFlowContext:
        document = bound_plan.plan.document()
        rows = [row for row in document.get("paths", ())
                if isinstance(row, Mapping) and row.get("flow_id") in self._kernels]
        flows = {}
        for row in rows:
            flow = row["flow_id"]
            if flow in flows:
                _refuse("generic-plan-mismatch", "/plan/paths",
                        {"reason": "duplicate-flow-path", "flow_id": flow})
            flows[flow] = self._kernels[flow].prepare(bound_plan, row["path_id"])
        if set(flows) != set(self._kernels):
            _refuse("generic-plan-mismatch", "/plan/paths",
                    {"reason": "mixed-campaign-needs-both-flow-paths",
                     "declared": sorted(flows),
                     "required": sorted(self._kernels)})
        return MixedFlowContext(plan_sha256=bound_plan.plan_sha256, flows=flows)

    # -- per-case work -----------------------------------------------------
    def _flow_of(self, context: MixedFlowContext, case) -> str:
        if not isinstance(case, Mapping):
            _refuse("generic-contract-type", "/case",
                    {"expected": "JSON object"})
        flow = case.get("flow_id")
        path_id = case.get("path_id")
        if flow is None:
            matches = [name for name, ctx in context.flows.items()
                       if ctx.path_id == path_id]
            if len(matches) != 1:
                _refuse("generic-plan-mismatch", "/case/path_id",
                        {"reason": "path-does-not-resolve-to-one-flow",
                         "path_id": path_id, "matches": matches})
            flow = matches[0]
        if flow not in context.flows:
            _refuse("generic-flow-unsupported", "/case/flow_id",
                    {"flow_id": flow, "declared": sorted(context.flows)})
        if path_id is not None and path_id != context.flows[flow].path_id:
            _refuse("generic-plan-mismatch", "/case/path_id",
                    {"reason": "case-path-is-not-the-flow-path",
                     "flow_id": flow, "path_id": path_id})
        return flow

    def lower(self, context, case):
        if type(context) is not MixedFlowContext:
            _refuse("generic-contract-type", "/context",
                    {"expected": "MixedFlowContext"})
        flow = self._flow_of(context, case)
        lowered = self._kernels[flow].lower(context.flows[flow], case)
        if lowered.flow_id != flow:
            _refuse("generic-plan-mismatch", "/case/flow_id",
                    {"reason": "lowered-flow-mismatch"})
        return lowered

    def capture(self, context, receipt) -> tuple:
        if type(context) is not MixedFlowContext:
            _refuse("generic-contract-type", "/context",
                    {"expected": "MixedFlowContext"})
        if not isinstance(receipt, Mapping):
            _refuse("generic-evidence-missing", "/receipt",
                    {"expected": "per-case certificate"})
        flow = (_CERTIFICATE_FLOWS.get(receipt.get("schema_version"))
                or (receipt.get('flow_id') if receipt.get('schema_version') in (
                    'compiled_memory_case.v1','compiled_shared_F5_case.v1','compiled_mmio_case.v1') else None))
        if flow not in context.flows or flow not in self._kernels:
            _refuse("generic-evidence-missing", "/receipt/schema_version",
                    {"reason": "unknown-flow-certificate",
                     "schema_version": receipt.get("schema_version")})
        return self._kernels[flow].capture(context.flows[flow], receipt)

    def feedback(self, context, claims) -> tuple[int, ...]:
        if type(context) is not MixedFlowContext:
            _refuse("generic-contract-type", "/context",
                    {"expected": "MixedFlowContext"})
        values: list[int] = []
        for flow in self._kernels:
            for value in self._kernels[flow].feedback(context.flows[flow], claims):
                if value not in values:
                    values.append(value)
        return tuple(values)


class MixedStorageFlowChannel(StorageFlowChannel):
    """Campaign view of the mixed runtime; forwards the case's flow id."""

    accepts_flow = True
    accepts_lowered_case = True

    def __init__(self, runtime):
        super().__init__(runtime, flow_id="F4",
                         executor="compiled_storage_mixed")
        if not getattr(runtime, "_mixed_flows", False):
            _refuse("generic-binding-drift", "/runtime",
                    {"reason": "mixed-flow-runtime-required"})

    def begin_once(self) -> None:
        if getattr(self.runtime, "_mixed_flows", False):
            super().begin_once()
            return
        _refuse("generic-binding-drift", "/runtime",
                {"reason": "mixed-flow-runtime-required"})

    def submit(self, raw: bytes, flow_id=None):
        f5_enabled = flow_id == 'F5' and getattr(self.runtime, '_f5_preparation', None) is not None
        if flow_id not in STORAGE_FLOWS and not f5_enabled:
            _refuse("generic-flow-unsupported", "/flow_id",
                    {"flow_id": flow_id, "supported": list(STORAGE_FLOWS)})
        return super().submit(raw, flow_id=flow_id)

    def submit_lowered(self, lowered, raw_index):
        flow = lowered.flow_id
        raw = lowered.raw_records[raw_index]
        if ((flow in ('F1', 'F3') and getattr(self.runtime, '_memory_flows', False))
                or (flow == 'F5' and getattr(self.runtime, '_f5_preparation', None) is not None)):
            if not self._begun:
                _refuse('generic-binding-drift', '/session')
            result = self.runtime.submit(raw, flow=flow,
                testcase_id=f'{lowered.testcase_id}:{raw_index}')
            self._submissions += 1
            return result
        return self.submit(raw, flow_id=flow)

    def replay(self, plan, *, audit_sink=None):
        return self.runtime.replay(plan, audit_sink=audit_sink)


class MixedStorageFlowBackend(StorageFlowBackend):
    """Campaign backend for one mixed runtime; one construction, N cases."""

    backend_id = "storage.flow.backend.mixed.v1"
    supports_mixed = True
    flows = frozenset(STORAGE_FLOWS)

    def __init__(self, *, runtime):
        if not getattr(runtime, "_mixed_flows", False):
            _refuse("generic-binding-drift", "/runtime",
                    {"reason": "mixed-flow-runtime-required"})
        super().__init__(runtime=runtime, flow_id="F4")
        if getattr(runtime, '_memory_flows', False):
            self.flows = frozenset(('F1', 'F2', 'F3', 'F4'))
        if getattr(runtime, '_f5_preparation', None) is not None:
            self.flows = self.flows | {'F5'}
            if not getattr(runtime,'_f2_flows',False):
                self.flows = self.flows - {'F2'}
        self._channel = None

    def require_flow(self, flow_id: str) -> None:
        if flow_id not in self.flows:
            _refuse("generic-flow-unsupported", "/flow_id",
                    {"flow_id": flow_id, "supported": sorted(self.flows)})

    def open(self) -> MixedStorageFlowChannel:
        if self._channel is None:
            self._channel = MixedStorageFlowChannel(self._runtime)
        return self._channel

    def unresolved(self) -> tuple[str, ...]:
        return (
            "mixed directed sequence only; an RFuzz wire stream still fixes one "
            "flow layout per campaign (no mixed wire selector exists)",
            "the saved generic_runtime_bundle.v1 producer emits one flow per "
            "case but its effect/read case rules are validated per case; mixed "
            "bundles are not part of this slice",
        )


# The fixed interface as module-level entry points (one code-owned kernel).
_DEFAULT_KERNEL = MixedStorageKernel()


def requirements(d3_path) -> tuple:
    return _DEFAULT_KERNEL.requirements(d3_path)


def prepare(bound_plan, path_id) -> MixedFlowContext:
    return _DEFAULT_KERNEL.prepare(bound_plan, path_id)


def lower(context, case):
    return _DEFAULT_KERNEL.lower(context, case)


def capture(context, receipt) -> tuple:
    return _DEFAULT_KERNEL.capture(context, receipt)


def feedback(context, claims) -> tuple[int, ...]:
    return _DEFAULT_KERNEL.feedback(context, claims)


def plan_has_both_flows(bound_plan) -> bool:
    document = bound_plan.plan.document()
    flows = {row.get("flow_id") for row in document.get("paths", ())
             if isinstance(row, Mapping)}
    return set(STORAGE_FLOWS) <= flows
