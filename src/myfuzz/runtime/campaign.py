"""Unified campaign entry: directed sequences and the first RFuzz adapter.

The selected backend determines whether one or multiple flows can share a
persistent session. Each case keeps its own path and declared wire layout.

The campaign drives the existing persistent runtime through
``PersistentCampaignRuntime`` only: one construction, one begin, N cases on the
same runner/memory/session.  A budget or wall-clock refusal happens *before* a
case effect and keeps the run alive; a failure at or after an effect keeps the
already-effective records, marks the case uncertain and enters ``FAULTED``.
Nothing is reset, retried or dropped.

Everything a campaign can claim here is software evidence.  No native token is
issued or consumed, no PID/nonce is invented and no effect is certified.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256

from .contracts import GenericRuntimeRefused, canonical_json_bytes
from .engine import PersistentCampaignRuntime
from .flows.storage import (
    STORAGE_FLOWS,
    StorageFlowBackend,
    StorageFlowKernel,
    load_case_sequence,
    refuse_mixed_flows,
)

CAMPAIGN_SCHEMA = "generic_campaign_report.v1"

@dataclass(frozen=True, slots=True)
class CampaignBudget:
    """Pre-effect bounds; exceeding them refuses the case, never rewrites history."""

    max_cases: int = 16
    max_search_cases: int = 4
    max_wall_seconds: float | None = None

    def __post_init__(self) -> None:
        for name, value in (("max_cases", self.max_cases),
                            ("max_search_cases", self.max_search_cases)):
            if type(value) is not int or isinstance(value, bool) or value < 1:
                raise GenericRuntimeRefused(
                    "generic-contract-type", "/budget/" + name,
                    {"expected": "positive int"})
        if self.max_wall_seconds is not None and (
                type(self.max_wall_seconds) not in (int, float)
                or isinstance(self.max_wall_seconds, bool)
                or self.max_wall_seconds <= 0):
            raise GenericRuntimeRefused(
                "generic-contract-type", "/budget/max_wall_seconds",
                {"expected": "positive seconds or None"})

    def document(self) -> dict:
        return {"max_cases": self.max_cases,
                "max_search_cases": self.max_search_cases,
                "max_wall_seconds": self.max_wall_seconds}


def plan_path_flows(plan_document) -> dict:
    """Path id -> declared flow id for every path of the bound plan."""
    if not isinstance(plan_document, Mapping):
        raise GenericRuntimeRefused("generic-contract-type", "/plan",
                                    {"expected": "plan document"})
    paths = plan_document.get("paths")
    if not isinstance(paths, list):
        raise GenericRuntimeRefused("generic-plan-mismatch", "/plan/paths",
                                    {"reason": "plan-paths-required"})
    flows = {}
    for index, row in enumerate(paths):
        if not isinstance(row, Mapping):
            raise GenericRuntimeRefused("generic-plan-mismatch",
                                        f"/plan/paths/{index}",
                                        {"expected": "path row"})
        path_id = row.get("path_id")
        flow_id = row.get("flow_id")
        if type(path_id) is not str or not path_id or type(flow_id) is not str:
            raise GenericRuntimeRefused("generic-plan-mismatch",
                                        f"/plan/paths/{index}",
                                        {"reason": "path-identity-undeclared"})
        if path_id in flows:
            raise GenericRuntimeRefused("generic-plan-mismatch",
                                        f"/plan/paths/{index}/path_id",
                                        {"reason": "duplicate-path-id"})
        flows[path_id] = flow_id
    return flows


def _one_flow_one_path(flows: Mapping, rows: Sequence[Mapping]) -> tuple[str, str]:
    selected = sorted({flows[row["path_id"]] for row in rows})
    refuse_mixed_flows(selected)
    if len(selected) != 1:
        raise GenericRuntimeRefused("generic-plan-mismatch", "/sequence/cases",
                                    {"reason": "single-flow-required"})
    flow_id = selected[0]
    path_ids = sorted({row["path_id"] for row in rows})
    if len(path_ids) != 1:
        raise GenericRuntimeRefused(
            "generic-plan-mismatch", "/sequence/cases",
            {"reason": "one-campaign-fixes-one-selected-path-and-layout",
             "path_ids": path_ids})
    if flow_id not in STORAGE_FLOWS:
        raise GenericRuntimeRefused("generic-flow-unsupported", "/flow_id",
                                    {"flow_id": flow_id,
                                     "supported": list(STORAGE_FLOWS)})
    return flow_id, path_ids[0]


def campaign_reporting_scope(backend) -> dict:
    """Report backend limitations without claiming how its sessions ran."""
    return {"known_limitations": list(backend.unresolved()), "software_only": None}


def run_directed_campaign(*, bound_plan, backend: StorageFlowBackend,
                          sequence, kernel=None, budget: CampaignBudget | None = None,
                          run_id: str = "generic-directed-campaign", allow_empty_sequence=False,
                          record_selector=None, selected_count=None, expected_records=None, case_id_prefix=None,
                          case_feedback=None, case_feedback_factory=None):
    """Run one directed ``generic_case_sequence.v1`` on one campaign.

    The caller keeps ownership of the bound handle; this function never closes
    it.  Every case is validated before the first effect, then run through the
    existing persistent runtime, and the returned document is the campaign
    report with per-case records, evidence and the lifecycle counters.
    """
    if not isinstance(backend, StorageFlowBackend):
        raise GenericRuntimeRefused("generic-contract-type", "/backend",
                                    {"expected": "StorageFlowBackend"})
    mixed = bool(getattr(backend, "supports_mixed", False))
    if mixed and kernel is None:
        from .flows.mixed import MixedStorageKernel
        kernel = MixedStorageKernel(include_memory={'F1', 'F3'} <= set(getattr(backend, 'flows', ())))
    kernel = kernel if kernel is not None else StorageFlowKernel()
    budget = budget if budget is not None else CampaignBudget()
    plan_document = bound_plan.plan.document()
    flows = plan_path_flows(plan_document)
    empty = allow_empty_sequence and isinstance(sequence, dict) and sequence.get("cases") == []
    if empty:
        # Reuse closed document/digest validation with no effects or cases.
        from .flows.storage import CASE_SEQUENCE_SCHEMA, SEQUENCE_KEYS
        from .contracts import parse_closed_json
        checked = parse_closed_json(sequence, SEQUENCE_KEYS, pointer="/sequence")
        if checked["schema_version"] != CASE_SEQUENCE_SCHEMA or checked["plan_sha256"] != bound_plan.plan_sha256:
            raise GenericRuntimeRefused("generic-plan-mismatch", "/sequence")
    rows = () if empty else load_case_sequence(plan_sha256=bound_plan.plan_sha256,
                              path_flows=flows, document=sequence,
                              allow_mixed=mixed)
    if mixed:
        used = sorted(set(flows.values()) if empty else {flows[row["path_id"]] for row in rows})
        for flow in used:
            backend.require_flow(flow)
        flow_id = "+".join(used)
        path_id = "mixed:" + flow_id
    else:
        if empty:
            flow_id = backend.flow_id
            paths = [path for path, selected in flows.items() if selected == flow_id]
            if len(paths) != 1:
                raise GenericRuntimeRefused("generic-plan-mismatch", "/sequence")
            path_id = paths[0]
        else:
            flow_id, path_id = _one_flow_one_path(flows, rows)
        backend.require_flow(flow_id)
    # Static refusals (path/layout requirements, plan digest, unbound source,
    # record shape) are settled before the backend may construct or adopt a
    # runtime, so a bad directed sequence can never start a process.
    precheck = kernel.prepare(bound_plan, path_id)
    for row in rows:
        kernel.lower(precheck, row)
    runtime = PersistentCampaignRuntime(
        bound_plan, kernel=kernel, channel=backend.open(), path_id=path_id,
        run_id=run_id, max_cases=budget.max_cases,
        max_wall_seconds=budget.max_wall_seconds)
    if case_feedback_factory is not None:
        if case_feedback is not None:
            raise ValueError("one case feedback source required")
        case_feedback = case_feedback_factory()
    runtime.prepare()
    lowered = tuple(runtime.validate(row) for row in rows)
    runtime.start()
    # The wall budget covers case execution after initialization completes.
    execution_started = runtime._clock()
    runtime._started_seconds = execution_started
    if record_selector is not None and callable(getattr(record_selector, 'start_search_clock', None)):
        record_selector.start_search_clock(runtime._clock, execution_started)
    primary = None
    budget_ended = False
    actual_rows = []
    actual_lowered = []
    feedback_cases = []

    def submit_observed(row):
        if case_feedback is not None:
            case_feedback.prepare_case()
        result = runtime.submit(row)
        if case_feedback is not None:
            feedback_cases.append(case_feedback.observe_case(
                case_id=row["testcase_id"], flow=flows[row["path_id"]]))
        return result

    catalog = {flows[row['path_id']] + ':' + row['raw_records_hex'][0].lower(): row for row in rows}
    try:
        if record_selector is None:
            for row in rows:
                submit_observed(row)
        else:
            for index in range(selected_count):
                checkpoint = record_selector.checkpoint()
                key = record_selector.choose()
                if expected_records is not None and key != expected_records[index]:
                    raise ValueError('mixed replay decision differs from original')
                flow, raw = key.split(':', 1)
                lookup = flow + ':' + raw.lower()
                if lookup not in catalog:
                    raise ValueError('mixed decision outside catalog')
                row = dict(catalog[lookup])
                row['testcase_id'] = f'{case_id_prefix}:{key.split(":", 1)[0]}:{index}'
                try:
                    lowered_row = runtime.validate(row)
                    submit_observed(row)
                except GenericRuntimeRefused as error:
                    if error.code == 'generic-budget-refused' and runtime.state == 'RUNNING':
                        record_selector.restore(checkpoint)
                        budget_ended = True
                        break
                    raise
                record_selector.settle(key)
                actual_rows.append(row)
                actual_lowered.append(lowered_row)
    except GenericRuntimeRefused as error:
        if (error.code == "generic-budget-refused" and runtime.state == "RUNNING"
                and runtime.refusals and runtime.refusals[-1].get("stage") == "budget"):
            budget_ended = True
        else:
            primary = error
    except BaseException as error:
        primary = error
    if primary is None and record_selector is not None and callable(getattr(record_selector, 'finish_search_clock', None)):
        try:
            record_selector.finish_search_clock()
        except BaseException as error:
            primary = error
    execution_seconds = runtime._clock() - execution_started
    report = None
    try:
        if runtime.state in ("RUNNING", "FAULTED"):
            report = runtime.finish()
    except BaseException as error:
        if primary is None:
            primary = error
        else:
            primary.add_note("campaign drain: " + repr(error))
    if primary is not None:
        raise primary
    document = dict(report)
    if case_feedback is not None:
        document["record_consumption_feedback"] = dict(
            cases=feedback_cases, state=case_feedback.snapshot())
    if record_selector is not None:
        sequence = dict(sequence, cases=actual_rows)
        lowered = actual_lowered
    document.update({
        "campaign_schema": CAMPAIGN_SCHEMA,
        "backend_id": backend.backend_id,
        "flow_id": flow_id,
        "path_id": path_id,
        "sequence_sha256": sha256(canonical_json_bytes(sequence)).hexdigest(),
        "sequence_case_count": report["case_count"],
        "requested_case_count": selected_count if record_selector is not None else len(rows),
        "budget_ended": budget_ended,
        "execution_seconds": execution_seconds,
        "wall_budget_overrun_seconds": max(0, execution_seconds - budget.max_wall_seconds) if budget.max_wall_seconds is not None else 0,
        "directed_cases": [case.document() for case in lowered[:report["case_count"]]],
        "budget": budget.document(),
        **campaign_reporting_scope(backend),
    })
    return document


class RfuzzDirectedAdapter:
    """First RFuzz adapter over one fixed compiled flow and layout.

    It proposes only values that the *declared* candidate layout can encode and
    that come from the campaign's actual evidence (``kernel.feedback`` over the
    real per-case claims).  F2 keeps its four-byte address record and F4 keeps
    its packed candidate record: no bit is borrowed for a generic flow
    selector, and a slice without a declared value is a refusal rather than an
    invented constant.
    """

    adapter_id = "rfuzz.directed.storage.v1"

    def __init__(self, *, kernel, context, mutate_source_id: str,
                 fixed_inputs: Mapping | None = None, limit: int | None = None):
        if type(mutate_source_id) is not str or not mutate_source_id:
            raise GenericRuntimeRefused("generic-contract-type",
                                        "/mutate_source_id")
        fixed = dict(fixed_inputs or {})
        for name, value in fixed.items():
            if type(name) is not str or not name or type(value) is not int \
                    or isinstance(value, bool) or value < 0:
                raise GenericRuntimeRefused("generic-contract-type",
                                            "/fixed_inputs",
                                            {"expected": "non-negative ints"})
        self.kernel = kernel
        self.context = context
        self.mutate_source_id = mutate_source_id
        self.fixed_inputs = fixed
        self.limit = limit
        self.used: set[int] = set()
        self.cases: list[dict] = []
        self._slice = self._find_slice()

    # -- documentary -----------------------------------------------------
    def document(self) -> dict:
        return {
            "schema_version": self.adapter_id,
            "flow_id": self.context.flow_id,
            "path_id": self.context.path_id,
            "mutate_source_id": self.mutate_source_id,
            "fixed_inputs": dict(sorted(self.fixed_inputs.items())),
            "declared_domain": self._slice.document(),
            "wire_record_bytes": self.context.record_length,
            "proposed_values": len(self.used),
            "native_authority": False,
        }

    # -- layout ----------------------------------------------------------
    def _find_slice(self):
        rows = getattr(self.context.layout, "slices", None)
        if rows is None:
            rows = getattr(self.context.layout, "source_slices", ())
        matches = [row for row in rows
                   if getattr(row, "source_id", None) == self.mutate_source_id]
        if len(matches) != 1:
            raise GenericRuntimeRefused(
                "generic-source-unverified", "/mutate_source_id",
                {"reason": "mutation-source-not-in-declared-layout",
                 "declared": [row.source_id for row in rows]})
        return next(row for row in self.context.domains
                    if row.source_id == self.mutate_source_id)

    def encode(self, value: int) -> bytes:
        """Encode one declared value in the flow's unchanged wire record."""
        if type(value) is not int or isinstance(value, bool) or value < 0:
            raise GenericRuntimeRefused("generic-contract-type", "/value",
                                        {"expected": "non-negative int"})
        if self.context.flow_id == "F2":
            return int(value).to_bytes(self.context.record_length, "little")
        values = dict(self.fixed_inputs)
        values[self.mutate_source_id] = value
        try:
            return self.context.layout.encode(values)
        except Exception as error:
            raise GenericRuntimeRefused(
                "generic-feedback-unencodable", "/layout",
                {"reason": "declared-layout-cannot-encode-the-value",
                 "mutate_source_id": self.mutate_source_id,
                 "fixed_inputs": sorted(self.fixed_inputs),
                 "error_type": type(error).__name__}) from error

    # -- feedback-driven inputs -----------------------------------------
    def propose(self, claims) -> tuple[tuple[int, bytes], ...]:
        values = self.kernel.feedback(self.context, claims)
        limit = (self.limit if type(self.limit) is int and self.limit > 0
                 else len(values))
        proposed = []
        for value in values:
            if value in self.used or len(proposed) >= limit:
                if len(proposed) >= limit:
                    break
                continue
            proposed.append((value, self.encode(value)))
        return tuple(proposed)

    def run(self, runtime, *, limit: int = 1) -> list[dict]:
        """Submit up to ``limit`` feedback-derived cases on the live campaign."""
        proposed = self.propose(tuple(runtime.claims))[:limit]
        results = []
        for value, raw in proposed:
            row = {
                "testcase_id": f"{runtime.run_id}:feedback:{value}",
                "path_id": self.context.path_id,
                "source_id": self.mutate_source_id,
                "raw_records_hex": [raw.hex()],
            }
            results.append(runtime.submit(row))
            self.used.add(value)
            self.cases.append({"value": value, "raw_hex": raw.hex(),
                               "testcase_id": row["testcase_id"]})
        return results
