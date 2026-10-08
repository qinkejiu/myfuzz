"""Per-case UART routing / target-consumption witnesses for the online report.

The heterogeneous UART session really routes data: a CPU instruction case reads
the OpenTitan UART ``RDATA`` register over TL-UL, the UART component pops the
FIFO entry that answers it, and the CPU retires that read value.  Those facts
already exist in the run's own trace (``uart_rdata_access``, ``uart_fifo_pop``,
``uart_consumption_match``, ``uart_retired_read_match``), but the aggregate
``report.json`` published routing/consumption as ``null`` because nothing read
them back.

This module reads them back, per case, from the case's **own** event slice --
the executor already computes that slice for its receipt -- so nothing is
inferred from names or reconstructed from a global stream:

* every UART register access the case produced, with its measured address,
  ``raw_offset``, ``access_id`` and ``source_transaction``;
* every target-consumption witness the case produced, each carrying the exact
  join that ties it to an access (a witness that joins to nothing is still
  recorded, marked unmatched -- never dropped);
* the gate's own per-candidate decisions (admitted / refused, with the exact
  evidence reference and prerequisite kind), read from the gate that made them.

Every list is bounded and states its own ``truncated`` flag and ``omitted``
count, and every quantity that cannot be derived is ``null`` with a reason
instead of a fabricated zero.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

#: Version of the aggregate document exposed as
#: ``report.json:source_target_transactions``.
SCHEMA_VERSION = "online_source_target_transactions.v1"

#: Trace event kinds that record one UART register access (the source side).
REGISTER_ACCESS_KINDS = ("uart_rdata_access",)
#: Trace event kinds that witness the target consuming an access or its frame.
CONSUMPTION_WITNESS_KINDS = ("uart_fifo_pop", "uart_retired_read_match",
                             "uart_consumption_match")

DEFAULT_CASE_LIMIT = 256
DEFAULT_ACCESS_LIMIT = 16
DEFAULT_WITNESS_LIMIT = 16

#: The exact joins this module proves, quoted in each witness record.
POP_REQUEST_JOIN = ("uart_fifo_pop.observation_event_id == "
                    "uart_rdata_access.actual_request_event_id")
POP_ACCESS_ID_JOIN = ("uart_fifo_pop.access.access_id == "
                      "uart_rdata_access.access_id")
RETIRED_JOIN = ("uart_retired_read_match.uart_access_event_id == "
                "uart_rdata_access.event_id")
CONSUMPTION_EVENT_JOIN = ("uart_consumption_match.observation_event_id == "
                          "uart_rdata_access.event_id")
CONSUMPTION_FRAME_JOIN = ("uart_consumption_match.entry_id == matched "
                          "uart_fifo_pop.entry_id (frame_id is compared too "
                          "when the pop carries one)")

_NO_EVENT_SLICE_REASON = (
    "the case produced no event slice (the candidate was refused before any RTL "
    "command), so neither its register accesses nor its target consumption "
    "witnesses can be read from it")
_EMPTY_SLICE_REASON = ("the case produced no UART register access and no target "
                       "consumption witness in its own event slice")


def _int_or_none(value: object) -> int | None:
    return value if type(value) is int else None


def _str_or_none(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _bounded(items: list[Any], limit: int, *, key: str,
             total: int | None = None) -> dict:
    """A capped list that always states its own truncation and omission."""
    retained = items[:limit]
    count = len(items) if total is None else total
    omitted = max(0, count - len(retained))
    return {key: retained, "count": count, "limit": limit,
            "truncated": omitted > 0, "omitted": omitted}


def _access_record(event: Mapping) -> dict:
    transaction = event.get("source_transaction")
    return {
        "kind": "uart_rdata_access",
        "event_id": _int_or_none(event.get("event_id")),
        "address": _int_or_none(event.get("address")),
        "offset": _int_or_none(event.get("raw_offset")),
        "window_base": _int_or_none(event.get("window_base")),
        "window_size": _int_or_none(event.get("window_size")),
        "access_id": _str_or_none(event.get("access_id")),
        "source_transaction": (dict(transaction)
                               if isinstance(transaction, Mapping) else None),
        "write": event.get("write") if type(event.get("write")) is bool else None,
        "read_value": _int_or_none(event.get("read_value")),
        "local_tick": _int_or_none(event.get("local_tick")),
        "status": _str_or_none(event.get("status")),
        "actual_request_event_id": _int_or_none(
            event.get("actual_request_event_id")),
        "actual_response_event_id": _int_or_none(
            event.get("actual_response_event_id")),
    }


#: The ``source_admission`` keys kept per witness: they name the *origin* case
#: and action whose injected frame the read really consumed, which is the
#: routing half of the witness.
ADMISSION_KEYS = ("schema_version", "admission_id", "case_id", "case_index",
                  "action_id", "component", "direction", "role", "source_id",
                  "input_kind", "input_sha256", "path_id")


def _admission_record(event: Mapping) -> dict | None:
    admission = event.get("source_admission")
    if not isinstance(admission, Mapping):
        return None
    return {key: admission.get(key) for key in ADMISSION_KEYS
            if key in admission}


def _witness_record(event: Mapping, *, matched_access_id: str | None,
                    match_basis: str | None) -> dict:
    entry_id = event.get("entry_id")
    return {
        "origin_admission": _admission_record(event),
        "kind": _str_or_none(event.get("kind")),
        "event_id": _int_or_none(event.get("event_id")),
        "status": _str_or_none(event.get("status")),
        "proof_scope": _str_or_none(event.get("proof_scope")),
        "disposition": _str_or_none(event.get("disposition")),
        "entry_id": list(entry_id) if isinstance(entry_id, list) else entry_id,
        "frame_id": _str_or_none(event.get("frame_id")),
        "read_value": _int_or_none(event.get("read_value")),
        "local_tick": _int_or_none(event.get("local_tick")),
        "observation_event_id": _int_or_none(event.get("observation_event_id")),
        "uart_access_event_id": _int_or_none(event.get("uart_access_event_id")),
        "uart_read_proof_event_id": _int_or_none(
            event.get("uart_read_proof_event_id")),
        "path_id": _str_or_none(event.get("path_id")),
        "matched_access_id": matched_access_id,
        "match_basis": match_basis,
        "matched": matched_access_id is not None,
    }


def _frame_keys(event: Mapping) -> tuple[tuple, ...]:
    """The frame identities a witness can be joined by, most specific first.

    A ``uart_fifo_pop`` carries an ``entry_id`` but no ``frame_id``; a
    ``uart_consumption_match`` carries both, so the entry alone is the key that
    exists on both sides and the frame is compared whenever the pop has one.
    """
    entry_id = event.get("entry_id")
    if not isinstance(entry_id, list):
        return ()
    entry = tuple(str(item) for item in entry_id)
    frame_id = event.get("frame_id")
    if isinstance(frame_id, str):
        return ((entry, frame_id), (entry, None))
    return ((entry, None),)


def case_source_target_transactions(
        *, case_id: str, events: Iterable[dict] | None, case_index: int | None = None,
        component: str | None = None, source_kind: str | None = None,
        source_id: str | None = None, access_limit: int = DEFAULT_ACCESS_LIMIT,
        witness_limit: int = DEFAULT_WITNESS_LIMIT) -> dict:
    """One case's routing/consumption witnesses, read from its own events.

    ``events=None`` means the case produced no event slice at all (a candidate
    refused before any RTL command): both quantities are then ``null`` with a
    reason.  An empty slice is a *measured zero* instead, and says so.
    """
    for name, limit in (("access_limit", access_limit),
                        ("witness_limit", witness_limit)):
        if type(limit) is not int or limit < 1:
            raise ValueError(f"{name} must be a positive integer")

    record: dict = {
        "case_id": _str_or_none(case_id),
        "case_index": _int_or_none(case_index),
        "component": _str_or_none(component),
        "source_kind": _str_or_none(source_kind),
        "source_id": _str_or_none(source_id),
    }
    if events is None:
        empty = {"count": None, "records": [], "limit": None,
                 "truncated": False, "omitted": None,
                 "reason": _NO_EVENT_SLICE_REASON}
        record.update({"register_accesses": dict(empty),
                       "target_consumption_witnesses": dict(empty),
                       "matched": None,
                       "reason": _NO_EVENT_SLICE_REASON})
        return record

    accesses: list[dict] = []
    witnesses: list[dict] = []
    access_total = 0
    witness_total = 0
    for number, event in enumerate(events):
        if not isinstance(event, Mapping):
            raise ValueError(
                f"case {case_id!r} event {number} is not a trace event object")
        kind = event.get("kind")
        if kind in REGISTER_ACCESS_KINDS:
            access_total += 1
            if len(accesses) < access_limit:
                accesses.append(_access_record(event))
        elif kind in CONSUMPTION_WITNESS_KINDS:
            witness_total += 1
            if len(witnesses) < witness_limit:
                witnesses.append(dict(event))

    by_event_id = {row["event_id"]: row for row in accesses
                   if row["event_id"] is not None}
    # A FIFO pop names the access by the request event it answered, which is the
    # access fact's ``actual_request_event_id`` and not its own ``event_id``.
    by_request_id = {row["actual_request_event_id"]: row for row in accesses
                     if row["actual_request_event_id"] is not None}
    by_access_id = {row["access_id"]: row for row in accesses
                    if row["access_id"] is not None}
    # Two passes: a FIFO pop proves which frame an access actually took, and a
    # retention/consumption proof for that same frame then joins to the access.
    frame_access: dict[tuple, str] = {}
    for event in witnesses:
        if event.get("kind") != "uart_fifo_pop":
            continue
        access = by_request_id.get(_int_or_none(event.get("observation_event_id")))
        if access is None:
            inner = event.get("access")
            access = (by_access_id.get(_str_or_none(inner.get("access_id")))
                      if isinstance(inner, Mapping) else None)
        if access is None or not access["access_id"]:
            continue
        for key in _frame_keys(event):
            frame_access.setdefault(key, access["access_id"])

    witness_records: list[dict] = []
    for event in witnesses:
        access_id, basis = _join_of(event, by_event_id=by_event_id,
                                    by_request_id=by_request_id,
                                    by_access_id=by_access_id,
                                    frame_access=frame_access)
        witness_records.append(_witness_record(event, matched_access_id=access_id,
                                               match_basis=basis))

    covered = {row["matched_access_id"] for row in witness_records
               if row["matched_access_id"] is not None}
    matched_count = sum(1 for row in witness_records if row["matched"])
    complete = bool(accesses) and len(covered) == len({row["access_id"] for row
                                                       in accesses
                                                       if row["access_id"]})
    record.update({
        "register_accesses": _bounded(accesses, access_limit, key="records",
                                      total=access_total),
        "target_consumption_witnesses": _bounded(witness_records, witness_limit,
                                                 key="records",
                                                 total=witness_total),
        "matched": {
            "accesses_with_a_consumption_witness": len(covered),
            "accesses_without_a_consumption_witness":
                max(0, len(accesses) - len(covered)),
            "witnesses_matched": matched_count,
            "witnesses_unmatched": len(witness_records) - matched_count,
            "complete": complete,
            "basis": ("an access is covered when at least one recorded witness "
                      "joins to it by the exact event/frame key named in "
                      "match_basis"),
        },
        "reason": None if (accesses or witnesses) else _EMPTY_SLICE_REASON,
    })
    return record


def _join_of(event: Mapping, *, by_event_id: dict, by_request_id: dict,
             by_access_id: dict, frame_access: dict
             ) -> tuple[str | None, str | None]:
    """The access this witness proves, plus the exact join used."""
    kind = event.get("kind")
    if kind == "uart_fifo_pop":
        access = by_request_id.get(_int_or_none(event.get("observation_event_id")))
        if access is not None and access["access_id"]:
            return access["access_id"], POP_REQUEST_JOIN
        inner = event.get("access")
        access = (by_access_id.get(_str_or_none(inner.get("access_id")))
                  if isinstance(inner, Mapping) else None)
        if access is not None and access["access_id"]:
            return access["access_id"], POP_ACCESS_ID_JOIN
        return None, None
    if kind == "uart_retired_read_match":
        access = by_event_id.get(_int_or_none(event.get("uart_access_event_id")))
        return ((access["access_id"], RETIRED_JOIN)
                if access is not None and access["access_id"] else (None, None))
    if kind == "uart_consumption_match":
        access = by_event_id.get(_int_or_none(event.get("observation_event_id")))
        if access is not None and access["access_id"]:
            return access["access_id"], CONSUMPTION_EVENT_JOIN
        for key in _frame_keys(event):
            access_id = frame_access.get(key)
            if access_id is not None:
                return access_id, CONSUMPTION_FRAME_JOIN
    return None, None


class UartRoutingWitnessRecorder:
    """Bounded per-case witness table for one online session.

    The recorder stores one :func:`case_source_target_transactions` record per
    case it observes, up to ``case_limit``; further cases are counted as
    omitted instead of growing the table without bound.
    """

    def __init__(self, *, case_limit: int = DEFAULT_CASE_LIMIT,
                 access_limit: int = DEFAULT_ACCESS_LIMIT,
                 witness_limit: int = DEFAULT_WITNESS_LIMIT) -> None:
        if type(case_limit) is not int or case_limit < 1:
            raise ValueError("case_limit must be a positive integer")
        for name, limit in (("access_limit", access_limit),
                            ("witness_limit", witness_limit)):
            if type(limit) is not int or limit < 1:
                raise ValueError(f"{name} must be a positive integer")
        self.case_limit = case_limit
        self.access_limit = access_limit
        self.witness_limit = witness_limit
        self._cases: list[dict] = []
        self.case_count = 0
        self._origin_cases: set[str] = set()
        self._origin_actions: set[str] = set()
        self._totals: dict[str, int] = {
            "cases_with_register_access": 0,
            "register_accesses": 0,
            "cases_with_target_consumption_witness": 0,
            "target_consumption_witnesses": 0,
            "matched_consumption_witnesses": 0,
            "unmatched_consumption_witnesses": 0,
            "cases_without_any_witness": 0,
            "cases_without_an_event_slice": 0,
        }

    # -- collection ---------------------------------------------------------
    def observe_case(self, *, case_id: str, events, case_index: int | None = None,
                     component: str | None = None, source_kind: str | None = None,
                     source_id: str | None = None) -> dict:
        """Record one case; returns the record even when it is not retained."""
        record = case_source_target_transactions(
            case_id=case_id, events=events, case_index=case_index,
            component=component, source_kind=source_kind, source_id=source_id,
            access_limit=self.access_limit, witness_limit=self.witness_limit)
        self.case_count += 1
        # The totals are accumulated from every observed case, including the
        # ones the case table does not retain, so a capped table never turns
        # into a capped total.
        self._accumulate(record)
        if len(self._cases) < self.case_limit:
            self._cases.append(record)
        return record

    def _accumulate_origins(self, record: Mapping) -> None:
        """Bounded origin identity: the case/action whose frame was consumed."""
        witnesses = record["target_consumption_witnesses"]["records"]
        for witness in witnesses:
            admission = witness.get("origin_admission")
            if not isinstance(admission, Mapping):
                continue
            case_id = admission.get("case_id")
            action_id = admission.get("action_id")
            if isinstance(case_id, str) and case_id:
                self._origin_cases.add(case_id)
            if isinstance(action_id, str) and action_id:
                self._origin_actions.add(action_id)

    def _accumulate(self, record: Mapping) -> None:
        self._accumulate_origins(record)
        accesses = record["register_accesses"]["count"]
        witnesses = record["target_consumption_witnesses"]
        matched = record["matched"]
        matched = matched if isinstance(matched, Mapping) else {}
        if accesses is None:
            self._totals["cases_without_an_event_slice"] += 1
            return
        self._totals["register_accesses"] += accesses
        self._totals["target_consumption_witnesses"] += witnesses["count"] or 0
        self._totals["matched_consumption_witnesses"] += matched.get(
            "witnesses_matched", 0)
        self._totals["unmatched_consumption_witnesses"] += matched.get(
            "witnesses_unmatched", 0)
        if accesses:
            self._totals["cases_with_register_access"] += 1
        if witnesses["count"]:
            self._totals["cases_with_target_consumption_witness"] += 1
        if not accesses and not witnesses["count"]:
            self._totals["cases_without_any_witness"] += 1

    @property
    def retained_case_count(self) -> int:
        return len(self._cases)

    # -- report document ----------------------------------------------------
    def document(self, *, gate=None) -> dict:
        """The bounded, versioned witness document for ``report.json``."""
        cases = _bounded(self._cases, self.case_limit, key="records",
                         total=self.case_count)
        totals = {
            "scope": "all_observed_cases",
            "cases": self.case_count,
            "case_records_retained": len(self._cases),
            "case_records_omitted": max(0, self.case_count - len(self._cases)),
            "event_slices_unavailable":
                self._totals["cases_without_an_event_slice"],
            "distinct_origin_cases": len(self._origin_cases),
            "distinct_origin_actions": len(self._origin_actions),
            "origin_scope": ("origin_case/origin_action come from each "
                             "witness's own source_admission; they name the case "
                             "whose injected frame the read consumed, which may "
                             "differ from the case that produced the access"),
            **{name: value for name, value in self._totals.items()
               if name != "cases_without_an_event_slice"},
        }
        return {
            "schema_version": SCHEMA_VERSION,
            "basis": ("per-case register accesses and target consumption "
                      "witnesses read from each case's own trace event slice, "
                      "plus the admission gate's own per-candidate decisions; "
                      "nothing is inferred from names"),
            "cases": cases,
            "totals": totals,
            "source_action_gate": self._gate_section(gate),
            "limits": [
                "the case table is capped at cases.limit retained records; "
                "cases.omitted counts the rest and totals.scope says so",
                "each capped list inside a case record carries its own "
                "truncated/omitted count",
                "a witness that joins to no recorded access is kept and marked "
                "matched=false instead of being dropped",
            ],
        }

    @staticmethod
    def _gate_section(gate) -> dict:
        section: dict = {"decision_schema_version": None, "component": None,
                         "decisions": None, "reason": None}
        if gate is None:
            section["reason"] = ("no source-action gate is attached to this "
                                 "session, so it made no per-candidate decision")
            return section
        section["component"] = _str_or_none(getattr(gate, "component", None))
        document = (gate.document()
                    if callable(getattr(gate, "document", None)) else None)
        if isinstance(document, Mapping):
            section["decision_schema_version"] = _str_or_none(
                document.get("schema_version"))
        decisions = getattr(gate, "decisions", None)
        if not callable(decisions):
            section["reason"] = ("the attached gate exposes no decisions(), so "
                                 "its per-candidate decisions cannot be read")
            return section
        try:
            section["decisions"] = decisions()
        except Exception as error:  # noqa: BLE001 - reported, never swallowed
            section["reason"] = (f"the attached gate's decisions() failed: "
                                 f"{type(error).__name__}: {error}")
        return section
