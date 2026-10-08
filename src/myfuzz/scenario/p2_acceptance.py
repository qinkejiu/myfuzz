"""P2 acceptance report: one saved run (or two) judged against the P2 plan.

The P2 acceptance condition (see
``docs/superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md``)
asks for six things from one versioned declaration and one saved artifact:

1. both declared directions -- ``Ibex->GPIO A->GPIO B->Ibex``
   (``CPU_TO_IP_TO_CPU``) and ``GPIO B external source->Ibex->GPIO A``
   (``IP_TO_CPU_TO_IP``) -- are instantiated, each with a per-edge
   delivery/consumption record;
2. chain certificates per direction (delegated to
   :mod:`myfuzz.scenario.chain_certificates` through
   :func:`myfuzz.scenario.acceptance_metrics.analyze_run`);
3. a real IP IRQ raised *without* a same-source CPU acceptance is still written
   into the trace;
4. the six trusted declaration breaks are rejected before any RTL process, with
   zero harness effects;
5. a fresh replay of the same graph under a different edge identity is not
   mutually recognized;
6. everything this artifact cannot prove is written ``null`` with a reason.

Nothing here re-implements an existing consumer. Edge hops come from
:func:`myfuzz.scenario.edge_provenance.edge_provenance_report`, chain counts
from :func:`myfuzz.scenario.acceptance_metrics.analyze_run`, and the negative
gates and the replay identity gate from
:mod:`myfuzz.scenario.p2_negative_gates`. This module only joins them into one
evidence document and decides which of the plan's keys are actually measurable.

Evidence rules enforced by the report itself:

* a section that could not be measured is ``null`` (or ``unknown``) **with a
  reason**, never ``0`` and never a pass;
* an edge that only shows part of its required hops stays ``incomplete`` and is
  never counted as certified; a direction is only ``certified`` when *every*
  runtime edge of its declaration is certified;
* the early-IRQ verdict is ``true`` only for an actually observed native
  IRQ trigger/high record with no same-source CPU acceptance anywhere in the
  artifact; "no such instance was observed" stays ``null`` + reason;
* the gate exit code is ``0`` only when every critical key was measured **and**
  its criterion holds, ``2`` otherwise (missing or unmet evidence), so a run
  can never be declared P2-ready silently.

This module never renders a harness, never starts a process and never touches
RTL; every verdict is derived from saved artifacts and declaration-only checks.
"""

from __future__ import annotations

import hashlib
import importlib
import json
from collections.abc import Iterable, Mapping
from pathlib import Path

from .acceptance_metrics import (
    CERTIFICATE_STATUSES,
    CHAIN_DIRECTIONS,
    CERTIFIED_STATUS,
    DEFAULT_CHUNK_CHARS,
    DEFAULT_INGEST_BATCH_SIZE,
    DEFAULT_MAX_CERTIFICATES,
    INCOMPLETE_STATUS,
    TraceEventStream,
    TraceUnavailable,
    analyze_run,
)
from .edge_provenance import (
    CERTIFIED,
    CONSUMER,
    DELIVERY,
    INCOMPLETE,
    PRODUCER,
    UNKNOWN,
    edge_endpoints_from_compiled,
    edge_provenance_report,
)
from .runtime_path_contract import RuntimePathContract

SCHEMA_VERSION = "p2_acceptance_report.v1"
MANIFEST_NAME = "online_session_manifest.json"

#: The two declared directions of the P2 acceptance condition, with the plan's
#: own wording.  The direction names are the run's, not this report's.
DIRECTION_LABELS = {
    "CPU_TO_IP_TO_CPU": "Ibex->GPIO A->GPIO B->Ibex",
    "IP_TO_CPU_TO_IP": "GPIO B external source->Ibex->GPIO A",
}
REQUIRED_DIRECTIONS = ("CPU_TO_IP_TO_CPU", "IP_TO_CPU_TO_IP")

#: A declared hop the compiled runtime contract gives no observable relation:
#: it is reported explicitly and excluded from the direction's status counts.
NOT_A_RUNTIME_EDGE = "not_a_runtime_edge"

#: Native IRQ observation record shapes written by the real GPIO/IP probes.
NATIVE_IRQ_OBSERVATION_KINDS = frozenset(("gpio_irq_trigger", "gpio_irq_observation"))
NATIVE_IRQ_OBSERVATION_SUFFIXES = ("_native_irq_trigger", "_native_irq_high")
#: CPU-side records that accept an IRQ line; a native observation is "accepted"
#: only when one of these names the exact same source identity.
CPU_IRQ_ACCEPTANCE_KINDS = frozenset(("cpu_irq_taken", "cpu_external_irq_taken"))
OBSERVED_STATUS = "observed"

EARLY_IRQ_RECORDED = "early_irq_recorded"
EARLY_IRQ_NOT_OBSERVED = "no_early_irq_instance_observed"
EARLY_IRQ_UNKNOWN = UNKNOWN

EARLY_IRQ_CRITERION = (
    "a native IRQ trigger/high observation record exists whose exact source "
    "identity (trigger_id, or source_event_id with its component) is named by "
    "no CPU acceptance record (cpu_irq_taken/cpu_external_irq_taken) anywhere in "
    "this artifact; the observation is therefore an IRQ the CPU had not accepted "
    "when it was written into the trace")

#: Rejection message of the real fresh-replay identity gate
#: (``ScenarioRfuzzExecutor._install_runtime_replay_identity``), reused verbatim
#: for the manifest-level comparison so both verdicts state the same rule.
REPLAY_DECLARATION_MISMATCH = "fresh replay runtime path declaration mismatch"

DEFAULT_MAX_IRQ_INSTANCES = 256
DEFAULT_MAX_ACCEPTANCE_KEYS = 200_000

#: Bounds of the declared-edge consumer.  A binding whose driver/pulse record
#: was evicted or expired can never recover credit from later events, so the
#: consumer's own documented defaults are used instead of the chain analyzer's
#: smaller streaming bounds; both are reported in ``direction_paths.bounds``.
DEFAULT_EDGE_MAX_PENDING = 4096
DEFAULT_EDGE_MAX_EVENT_GAP = 65536

EXIT_READY = 0
EXIT_NOT_READY = 2

_EDGE_STATUSES = (CERTIFIED, INCOMPLETE, UNKNOWN)


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


def _limit(limits: list[dict], quantity: str, reason: str) -> None:
    limits.append({"quantity": quantity, "reason": reason})


def _module_identity(name: str) -> dict | None:
    """Path and sha256 of one module file, so a verdict names its producer."""
    try:
        module = importlib.import_module(name)
        path = Path(getattr(module, "__file__", "") or "")
        if not path.is_file():
            return None
        return {"module": name, "path": str(path),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    except Exception:  # pragma: no cover - import topology change
        return None


def _read_json_object(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return document if isinstance(document, dict) else None


def _component_of(event: Mapping) -> str | None:
    component = event.get("component")
    if isinstance(component, str) and component:
        return component
    source = event.get("source")
    if (isinstance(source, (list, tuple)) and len(source) == 2
            and isinstance(source[0], str) and source[0]):
        return source[0]
    return None


def _event_id(value: object) -> int | None:
    return value if type(value) is int and value >= 0 else None


# ---------------------------------------------------------------------------
# native IRQ observations without a same-source CPU acceptance
# ---------------------------------------------------------------------------


def _is_native_irq_observation(kind: object) -> bool:
    if not isinstance(kind, str) or not kind:
        return False
    return (kind in NATIVE_IRQ_OBSERVATION_KINDS
            or kind.endswith(NATIVE_IRQ_OBSERVATION_SUFFIXES))


def _asserted(event: Mapping) -> tuple[bool, str]:
    """Is this observation a positive (high/asserted) IRQ record?

    ``mask`` wins when it is an integer, then ``value``; a record that merely
    exists is *not* treated as asserted, so a missing field can never invent an
    early IRQ.
    """
    mask = event.get("mask")
    if type(mask) is int:
        return mask != 0, "mask"
    value = event.get("value")
    if type(value) is bool:
        return value, "value"
    if type(value) is int:
        return value != 0, "value"
    return False, "no_assertion_field"


def _acceptance_index(event: Mapping) -> dict:
    """Exact source identities named by one CPU IRQ acceptance record."""
    keys = {}
    trigger = event.get("source_trigger")
    if isinstance(trigger, Mapping):
        candidate = trigger.get("trigger_id")
        if isinstance(candidate, str) and candidate:
            keys[("trigger_id", candidate)] = "trigger_id"
        trigger_event = _event_id(trigger.get("trigger_event_id"))
        if trigger_event is not None:
            keys[("trigger_event_id", trigger_event)] = "trigger_event_id"
    source_event = _event_id(event.get("source_event_id"))
    if source_event is not None:
        keys[("source_event_id", _component_of(event), source_event)] = (
            "source_event_id")
    return keys


def _instance_key(event: Mapping) -> tuple[tuple, dict]:
    """Exact source identity of one native observation record.

    A record carrying no identity field is its own instance joined by nothing,
    which can never be matched by an acceptance record -- fail closed instead of
    silently crediting it.
    """
    component = _component_of(event)
    trigger_id = event.get("trigger_id")
    if isinstance(trigger_id, str) and trigger_id:
        return ("trigger_id", trigger_id), {"joined_by": "trigger_id",
                                            "component": component,
                                            "trigger_id": trigger_id}
    source_event = _event_id(event.get("source_event_id"))
    if source_event is not None:
        return (("source_event_id", component, source_event),
                {"joined_by": "source_event_id", "component": component,
                 "source_event_id": source_event})
    event_id = _event_id(event.get("event_id"))
    return (("unjoined", component, event_id),
            {"joined_by": "no_join_key", "component": component,
             "trigger_id": None, "source_event_id": None})


class _IrqScan:
    """Single-pass native-IRQ observation and CPU-acceptance collector.

    Bounded: at most ``max_instances`` observation instances keep their event
    ids, and at most ``max_acceptance_keys`` acceptance identities are indexed.
    Overflow never flips a verdict to "pass": a truncated acceptance index makes
    the verdict ``unknown``, and truncated instances make the unaccepted count a
    lower bound instead of a fabricated exact number.
    """

    def __init__(self, *, max_instances: int = DEFAULT_MAX_IRQ_INSTANCES,
                 max_acceptance_keys: int = DEFAULT_MAX_ACCEPTANCE_KEYS) -> None:
        if type(max_instances) is not int or max_instances < 1:
            raise ValueError("max_irq_instances must be a positive integer")
        if type(max_acceptance_keys) is not int or max_acceptance_keys < 1:
            raise ValueError("max_acceptance_keys must be a positive integer")
        self.max_instances = max_instances
        self.max_acceptance_keys = max_acceptance_keys
        self.instances: dict[tuple, dict] = {}
        self.acceptance: dict[tuple, int] = {}
        self.acceptance_records = 0
        self.observation_records = 0
        self.incomplete_records = 0
        self.unasserted_records = 0
        self.instance_count = 0
        self.acceptance_truncated = False
        self.instances_truncated = False
        self.exhausted = False

    def observe(self, event: Mapping) -> None:
        kind = event.get("kind")
        if kind in CPU_IRQ_ACCEPTANCE_KINDS:
            self.acceptance_records += 1
            event_id = _event_id(event.get("event_id"))
            for key in _acceptance_index(event):
                if key in self.acceptance:
                    continue
                if len(self.acceptance) >= self.max_acceptance_keys:
                    self.acceptance_truncated = True
                    continue
                self.acceptance[key] = event_id if event_id is not None else -1
        if not _is_native_irq_observation(kind):
            return
        self.observation_records += 1
        status = event.get("status")
        if isinstance(status, str) and status != OBSERVED_STATUS:
            self.incomplete_records += 1
            return
        asserted, basis = _asserted(event)
        if not asserted:
            self.unasserted_records += 1
            return
        key, identity = _instance_key(event)
        event_id = _event_id(event.get("event_id"))
        row = self.instances.get(key)
        if row is None:
            self.instance_count += 1
            if len(self.instances) >= self.max_instances:
                self.instances_truncated = True
                return
            row = {"instance_key": list(key), "kind": kind,
                   "component": identity.get("component"),
                   "trigger_id": identity.get("trigger_id"),
                   "source_event_id": identity.get("source_event_id"),
                   "joined_by": identity["joined_by"],
                   "event_ids": [], "kinds": [], "masks": [],
                   "assertion_basis": basis, "first_event_id": event_id}
            self.instances[key] = row
        if event_id is not None and event_id not in row["event_ids"]:
            row["event_ids"].append(event_id)
        if kind not in row["kinds"]:
            row["kinds"].append(kind)
        mask = event.get("mask")
        if type(mask) is int and mask not in row["masks"]:
            row["masks"].append(mask)
        if event_id is not None:
            first = row["first_event_id"]
            row["first_event_id"] = event_id if first is None else min(first, event_id)

    def _acceptance_for(self, key: tuple) -> int | None:
        return self.acceptance.get(key)

    def _instance_rows(self) -> list[dict]:
        rows = []
        for key, row in self.instances.items():
            accepted_by = self._acceptance_for(key)
            entry = {name: value for name, value in row.items()
                     if name != "instance_key"}
            entry["instance_key"] = list(key)
            entry["accepted"] = accepted_by is not None
            entry["accepted_by_event_id"] = accepted_by
            entry["event_ids"] = sorted(row["event_ids"])
            rows.append(entry)
        rows.sort(key=lambda row: (row["first_event_id"] is None,
                                   row["first_event_id"] or 0,
                                   str(row["instance_key"])))
        return rows

    def report(self, *, trace_reason: str | None,
               events_ingested: int | None) -> dict:
        """Render the early-IRQ section; never a pass without an instance."""
        rows = self._instance_rows() if self.exhausted else []
        unaccepted = [row for row in rows if not row["accepted"]]
        base = {
            "criterion": EARLY_IRQ_CRITERION,
            "native_irq_observation_kinds": sorted(NATIVE_IRQ_OBSERVATION_KINDS),
            "native_irq_observation_suffixes": list(NATIVE_IRQ_OBSERVATION_SUFFIXES),
            "cpu_acceptance_kinds": sorted(CPU_IRQ_ACCEPTANCE_KINDS),
            "trace_events_ingested": events_ingested,
            "observation_records": self.observation_records if self.exhausted else None,
            "incomplete_observation_records": (self.incomplete_records
                                               if self.exhausted else None),
            "unasserted_observation_records": (self.unasserted_records
                                               if self.exhausted else None),
            "cpu_acceptance_records": (self.acceptance_records
                                       if self.exhausted else None),
            "observed_instance_count": len(rows) if self.exhausted else None,
            "accepted_instance_count": (len(rows) - len(unaccepted)
                                        if self.exhausted else None),
            "unaccepted_instance_count": (len(unaccepted) if self.exhausted
                                          else None),
            "unaccepted_instance_count_is_lower_bound": bool(
                self.exhausted and self.instances_truncated),
            "instances_truncated": self.instances_truncated,
            "acceptance_index_truncated": self.acceptance_truncated,
            "observed_instances": rows,
            "unaccepted_instances": unaccepted,
            "max_instances": self.max_instances,
            "max_acceptance_keys": self.max_acceptance_keys,
        }
        if not self.exhausted:
            base.update({"decision": EARLY_IRQ_UNKNOWN, "decision_value": None,
                         "reason": (trace_reason or
                                    "the event stream was not read to the end, so no "
                                    "IRQ instance can be settled")})
            return base
        if self.acceptance_truncated:
            base.update({
                "decision": EARLY_IRQ_UNKNOWN, "decision_value": None,
                "reason": (f"more than {self.max_acceptance_keys} CPU acceptance "
                           "identities were observed, so the acceptance index is "
                           "incomplete and no instance can be settled")})
            return base
        if not rows:
            base.update({
                "decision": EARLY_IRQ_UNKNOWN, "decision_value": None,
                "reason": (f"no native IRQ trigger/high observation record "
                           f"({sorted(NATIVE_IRQ_OBSERVATION_KINDS)}) is written in "
                           f"this artifact: {self.observation_records} observation "
                           f"records ({self.incomplete_records} incomplete, "
                           f"{self.unasserted_records} not asserted). Not observed "
                           "is not a pass")})
            return base
        if not unaccepted:
            base.update({
                "decision": EARLY_IRQ_NOT_OBSERVED, "decision_value": None,
                "reason": (f"all {len(rows)} native IRQ observation instance(s) are "
                           "joined by an exact identity to a CPU acceptance record; "
                           "no IRQ was observed without a same-source "
                           "cpu_irq_taken in this artifact. Not observed is not a "
                           "pass")})
            return base
        base.update({
            "decision": EARLY_IRQ_RECORDED, "decision_value": True,
            "reason": None,
            "evidence": (f"{len(unaccepted)} of {len(rows)} native IRQ observation "
                         f"instance(s) have no same-source CPU acceptance record; "
                         f"first unaccepted event_id="
                         f"{unaccepted[0]['first_event_id']}, trigger_id="
                         f"{unaccepted[0]['trigger_id']!r}")})
        return base


# ---------------------------------------------------------------------------
# declared direction paths and their per-edge records
# ---------------------------------------------------------------------------


def _selection_edges(prepared_document: Mapping | None) -> dict:
    """Declared edges per direction, in declaration order."""
    declared: dict[str, dict] = {}
    if not isinstance(prepared_document, Mapping):
        return declared
    for row in prepared_document.get("selections") or ():
        if not isinstance(row, Mapping):
            continue
        direction = row.get("direction")
        if not isinstance(direction, str) or not direction:
            continue
        declared[direction] = {
            "path_id": row.get("path_id"),
            "target": row.get("target"),
            "edges": [edge for edge in (row.get("edges") or ())
                      if isinstance(edge, Mapping)]}
    return declared


def _hop_block(hop: Mapping) -> dict:
    return {"hop_id": hop.get("hop_id"), "event_id": hop.get("event_id"),
            "evidence": {key: value for key, value in hop.items()
                         if key not in ("hop_id", "event_id")}}


def _edge_row(edge: Mapping, *, path_id, declared_kind: str,
              contract_keys: frozenset, provenance_row: Mapping | None,
              provenance_reason: str | None) -> dict:
    key = (edge.get("rule_index"), edge.get("prerequisite_index"))
    row = {"rule_index": edge.get("rule_index"),
           "prerequisite_index": edge.get("prerequisite_index"),
           "path_id": path_id,
           "declared_kind": declared_kind,
           "prerequisite": edge.get("prerequisite"),
           "target": edge.get("target"),
           "runtime_edge": key in contract_keys}
    if not row["runtime_edge"]:
        row.update({
            "relation": None, "scope": None, "status": NOT_A_RUNTIME_EDGE,
            "proof_scope": None, "missing": [], "hop_ids": [], "hops": [],
            "producer": None, "delivery": None, "consumer": None,
            "reason": (f"rule {key[0]} is selected as a {declared_kind!r} hop, but "
                       "the compiled runtime path contract declares no observable "
                       "runtime relation for that edge identity, so this consumer "
                       "has no delivery/consumption join for it")})
        return row
    if provenance_row is None:
        row.update({
            "relation": None, "scope": None, "status": None, "proof_scope": None,
            "missing": [], "hop_ids": [], "hops": [], "producer": None,
            "delivery": None, "consumer": None,
            "reason": provenance_reason or "the edge was never observed"})
        return row
    hops = [_hop_block(hop) for hop in (provenance_row.get("hops") or ())
            if isinstance(hop, Mapping)]
    by_hop = {hop["hop_id"]: hop for hop in hops}
    row.update({
        "relation": provenance_row.get("relation"),
        "scope": provenance_row.get("scope"),
        "status": provenance_row.get("status"),
        "proof_scope": provenance_row.get("proof_scope"),
        "reason": provenance_row.get("reason"),
        "missing": list(provenance_row.get("missing") or ()),
        "hop_ids": [hop["hop_id"] for hop in hops],
        "hops": hops,
        "producer": by_hop.get(PRODUCER),
        "delivery": by_hop.get(DELIVERY),
        "consumer": by_hop.get(CONSUMER)})
    return row


def _record_rows(rows: Iterable[dict], hop_id: str) -> list[dict]:
    records = []
    for row in rows:
        hop = row.get(hop_id)
        if hop is None:
            continue
        records.append({"rule_index": row["rule_index"],
                        "prerequisite_index": row["prerequisite_index"],
                        "path_id": row["path_id"], "relation": row["relation"],
                        "hop_id": hop_id, "event_id": hop["event_id"],
                        "evidence": hop["evidence"]})
    return records


def _direction_paths(*, prepared_document: Mapping | None,
                     contract: RuntimePathContract | None,
                     provenance: Mapping | None,
                     provenance_reason: str | None,
                     limits: list[dict]) -> dict:
    declared = _selection_edges(prepared_document)
    contract_keys = (frozenset(edge.key for edge in contract.edges)
                     if contract is not None else frozenset())
    rows_by_key = {}
    if provenance is not None:
        rows_by_key = {(row["rule_index"], row["prerequisite_index"]): row
                       for row in provenance.get("edges") or ()}
    directions: dict[str, dict] = {}
    for direction in sorted(set(declared) | set(REQUIRED_DIRECTIONS)):
        declaration = declared.get(direction)
        entry = {
            "direction": direction,
            "label": DIRECTION_LABELS.get(direction),
            "declared": declaration is not None,
            "path_id": None if declaration is None else declaration["path_id"],
            "target": None if declaration is None else declaration["target"],
            "declared_edge_count": 0 if declaration is None else len(declaration["edges"]),
            "runtime_edge_count": 0,
            "edges": [],
            "counts": {status: 0 for status in _EDGE_STATUSES},
            "non_runtime_edge_count": 0,
            "unobserved_edge_count": 0,
            "certified_edges": 0,
            "incomplete_edges": [],
            "unknown_edges": [],
            "delivery_records": [],
            "consumption_records": [],
            "status": None,
            "reason": None,
        }
        if declaration is None:
            entry["reason"] = ("this run's versioned declaration selects no path "
                               f"for direction {direction!r}")
            limits.append({"quantity": f"direction_paths.{direction}",
                           "reason": entry["reason"]})
            directions[direction] = entry
            continue
        rows = []
        for edge in declaration["edges"]:
            key = (edge.get("rule_index"), edge.get("prerequisite_index"))
            rows.append(_edge_row(
                edge, path_id=declaration["path_id"],
                declared_kind=str(edge.get("kind")),
                contract_keys=contract_keys,
                provenance_row=rows_by_key.get(key),
                provenance_reason=provenance_reason))
        entry["edges"] = rows
        entry["runtime_edge_count"] = sum(1 for row in rows if row["runtime_edge"])
        entry["non_runtime_edge_count"] = sum(
            1 for row in rows if not row["runtime_edge"])
        entry["unobserved_edge_count"] = sum(
            1 for row in rows if row["runtime_edge"] and row["status"] is None)
        for row in rows:
            if row["runtime_edge"] and row["status"] in entry["counts"]:
                entry["counts"][row["status"]] += 1
        entry["certified_edges"] = entry["counts"][CERTIFIED]
        entry["incomplete_edges"] = [
            {"rule_index": row["rule_index"],
             "prerequisite_index": row["prerequisite_index"],
             "missing": row["missing"]}
            for row in rows if row["status"] == INCOMPLETE]
        entry["unknown_edges"] = [
            {"rule_index": row["rule_index"],
             "prerequisite_index": row["prerequisite_index"],
             "reason": row["reason"]}
            for row in rows if row["status"] == UNKNOWN]
        entry["delivery_records"] = _record_rows(rows, DELIVERY)
        entry["consumption_records"] = _record_rows(rows, CONSUMER)
        if entry["non_runtime_edge_count"]:
            limits.append({
                "quantity": f"direction_paths.{direction}.non_runtime_hops",
                "reason": (f"{entry['non_runtime_edge_count']} selected hop(s) of "
                           "this direction are causal-order hops without a declared "
                           "runtime relation, so they carry no cross-component "
                           "delivery/consumption record in this consumer")})
        if provenance is None:
            entry["reason"] = provenance_reason
        elif entry["runtime_edge_count"] == 0:
            entry["status"] = UNKNOWN
            entry["reason"] = "no declared runtime edge carries an observable relation"
        else:
            for status in (UNKNOWN, INCOMPLETE, CERTIFIED):
                if entry["counts"][status]:
                    entry["status"] = status
                    break
            if entry["status"] != CERTIFIED:
                entry["reason"] = (
                    f"{entry['counts'][CERTIFIED]}/{entry['runtime_edge_count']} "
                    f"runtime edge(s) certified; "
                    f"{entry['counts'][INCOMPLETE]} incomplete, "
                    f"{entry['counts'][UNKNOWN]} unknown")
        directions[direction] = entry
    required_status = {direction: directions[direction]["status"]
                       for direction in REQUIRED_DIRECTIONS
                       if direction in directions}
    return {"schema_version": "p2_direction_paths.v1",
            "source": (f"{MANIFEST_NAME}:runtime_paths.declaration.selections "
                       "joined to runtime_edge_provenance_report.v1 rows"),
            "edge_status_vocabulary": list(_EDGE_STATUSES) + [NOT_A_RUNTIME_EDGE],
            "runtime_edge_definition": (
                "a selected hop whose (rule_index, prerequisite_index) the compiled "
                "runtime path contract declares; only these participate in the "
                "direction status counts"),
            "directions": directions,
            "required_directions": list(REQUIRED_DIRECTIONS),
            "required_direction_status": required_status,
            "provenance_counts": None if provenance is None
            else dict(provenance.get("counts") or {}),
            "provenance_events_observed": None if provenance is None
            else provenance.get("events_observed"),
            "provenance_events_rejected": None if provenance is None
            else provenance.get("events_rejected"),
            "provenance_proof_scope": None if provenance is None
            else dict(provenance.get("proof_scope") or {}),
            "provenance_bounds": None if provenance is None
            else dict(provenance.get("bounds") or {}),
            "provenance_resets": None if provenance is None
            else provenance.get("resets"),
            "provenance_dropped_late_hops": None if provenance is None
            else provenance.get("dropped_late_hops")}


# ---------------------------------------------------------------------------
# chain certificates
# ---------------------------------------------------------------------------


class _CountingChainProducer:
    """Delegate to the real producer while counting raw records per direction."""

    def __init__(self, inner: object, sink: dict) -> None:
        self._inner = inner
        self._sink = sink

    def _count(self, certificates, result):
        for certificate in certificates:
            if isinstance(certificate, Mapping):
                direction = certificate.get("direction")
                status = certificate.get("status")
                if direction in CHAIN_DIRECTIONS and status in CERTIFICATE_STATUSES:
                    row = self._sink.setdefault(
                        direction, {"raw_records": 0, "certified": 0,
                                    "incomplete": 0})
                    row["raw_records"] += 1
                    if status == CERTIFIED_STATUS:
                        row["certified"] += 1
                    elif status == INCOMPLETE_STATUS:
                        row["incomplete"] += 1
            result.append(certificate)
        return result

    def ingest(self, events):
        produced = self._inner.ingest(events)
        return self._count(produced, [])

    def flush(self):
        return self._count(self._inner.flush(), [])

    @property
    def pending_count(self):
        return getattr(self._inner, "pending_count", None)

    def close(self) -> None:
        close = getattr(self._inner, "close", None)
        if callable(close):
            close()


def _producer_factory(chain_producer, sinks: list):
    """(factory, source_label, reason) for a producer that counts per direction.

    ``sinks`` is consumed in call order: the analyzer resolves the main-pass
    producer first and (only with a replay comparison) a second producer for the
    replayed trace, so raw counts of the two passes never mix.
    """
    def take_sink() -> dict:
        return sinks.pop(0) if sinks else {}

    if chain_producer is not None:
        inner = chain_producer
        source = "injected chain_producer"
        reason = None
    else:
        try:
            from .chain_certificates import ChainCertificates
        except ImportError as exc:  # pragma: no cover - import topology change
            return None, "unavailable", f"chain certificate producer unavailable: {exc}"
        inner = ChainCertificates
        source = "myfuzz.scenario.chain_certificates.ChainCertificates"
        reason = None

    if hasattr(inner, "ingest") and not isinstance(inner, type):
        def instance_factory(**_):
            return _CountingChainProducer(inner, take_sink())
        return instance_factory, source, reason

    def factory(*, max_pending: int, max_event_gap: int,
                require_native_receipts: bool):
        instance = inner(max_pending=max_pending, max_event_gap=max_event_gap,
                         require_native_receipts=require_native_receipts)
        return _CountingChainProducer(instance, take_sink())

    return factory, source, reason


def _chain_certificates(directory: Path, *, chain_producer, replay_dir,
                        max_certificates: int, max_pending: int,
                        max_event_gap: int, require_native_receipts: bool,
                        ingest_batch_size: int, verify_semantic: bool,
                        limits: list[dict]) -> dict:
    sink: dict = {}
    replay_sink: dict = {}
    factory, source, reason = _producer_factory(chain_producer, [sink, replay_sink])
    if factory is None:
        _limit(limits, "chain_certificates.by_direction", reason)
        return {"source": "myfuzz.scenario.acceptance_metrics.analyze_run",
                "producer": source, "producer_available": False,
                "by_direction": None, "certified_total": None,
                "incomplete_total": None, "analyzer_certified_by_direction": None,
                "cross_check": None, "reason": reason,
                "analyzer": None}
    try:
        analyzer = analyze_run(
            directory, chain_producer=factory, replay_dir=replay_dir,
            max_certificates=max_certificates, max_pending=max_pending,
            max_event_gap=max_event_gap,
            require_native_receipts=require_native_receipts,
            ingest_batch_size=ingest_batch_size,
            verify_semantic=verify_semantic)
    except Exception as exc:  # fail closed: no counts are better than wrong ones
        reason = (f"acceptance_metrics.analyze_run failed: "
                  f"{type(exc).__name__}: {exc}")
        _limit(limits, "chain_certificates.by_direction", reason)
        return {"source": "myfuzz.scenario.acceptance_metrics.analyze_run",
                "producer": source, "producer_available": True,
                "by_direction": None, "certified_total": None,
                "incomplete_total": None, "analyzer_certified_by_direction": None,
                "cross_check": None, "reason": reason, "analyzer": None}

    chains = analyzer.get("certified_chains") or {}
    analyzer_by_direction = chains.get("by_direction")
    by_direction = None
    if analyzer_by_direction is not None:
        by_direction = {}
        for direction in CHAIN_DIRECTIONS:
            raw = sink.get(direction, {"raw_records": 0, "certified": 0,
                                       "incomplete": 0})
            by_direction[direction] = {
                "certified": analyzer_by_direction.get(direction),
                "incomplete": raw["incomplete"],
                "raw_certified_records": raw["certified"],
                "raw_records": raw["raw_records"]}
    cross_check = None
    if by_direction is not None:
        cross_check = ("agree" if all(
            row["certified"] == row["raw_certified_records"]
            for row in by_direction.values()) else "disagree")
        if cross_check == "disagree":
            _limit(limits, "chain_certificates.by_direction",
                   "per-direction raw certificate records disagree with the "
                   "analyzer's deduplicated certified counts; both are reported")
    elif chains.get("cap_reached") is not True:
        _limit(limits, "chain_certificates.by_direction",
               str(analyzer.get("certified_chains_reason") or
                   "chain certificate counts are unavailable for this artifact"))
    certified_total = chains.get("total")
    incomplete_total = chains.get("incomplete_total")
    if certified_total == 0 and incomplete_total:
        first_missing = (analyzer.get("chain_gap_evidence") or {}
                         ).get("first_missing_hop_counts")
        _limit(limits, "chain_certificates.certified_total",
               f"no certified chain in {incomplete_total} admission certificate(s); "
               f"first missing hops: {first_missing}. This states what the artifact "
               "certifies, not that the DUT never completed a chain")
    replay_records = None
    if replay_sink:
        replay_records = {direction: dict(row)
                          for direction, row in sorted(replay_sink.items())}
    return {
        "source": "myfuzz.scenario.acceptance_metrics.analyze_run",
        "producer": source,
        "producer_module": (_module_identity("myfuzz.scenario.chain_certificates")
                            if chain_producer is None else None),
        "producer_available": True,
        "by_direction": by_direction,
        "per_direction_incomplete_source": (
            "raw records counted around the injected producer during the main "
            "pass; the analyzer does not keep per-direction incomplete counts"),
        "replay_pass_raw_records": replay_records,
        "certified_total": certified_total,
        "incomplete_total": incomplete_total,
        "analyzer_certified_by_direction": (None if analyzer_by_direction is None
                                            else dict(analyzer_by_direction)),
        "cross_check": cross_check,
        "same_case": chains.get("same_case"),
        "cross_case": chains.get("cross_case"),
        "cap_reached": chains.get("cap_reached"),
        "duplicate_certificate_ids": chains.get("duplicate_certificate_ids"),
        "conflicting_status_certificate_ids": chains.get(
            "conflicting_status_certificate_ids"),
        "first_missing_hop_counts": (analyzer.get("chain_gap_evidence") or {}
                                     ).get("first_missing_hop_counts"),
        "chain_completion_by_admission": analyzer.get(
            "chain_completion_by_admission"),
        "chain_producer": analyzer.get("chain_producer"),
        "trace_evidence": analyzer.get("trace_evidence"),
        "reason": (None if by_direction is not None
                   else analyzer.get("certified_chains_reason")),
        "analyzer_limits": list(analyzer.get("limits") or ()),
        "analyzer": analyzer,
    }


# ---------------------------------------------------------------------------
# negative gates and replay identity
# ---------------------------------------------------------------------------


def _negative_gates(authority: str, limits: list[dict]) -> dict:
    section = {"source": "myfuzz.scenario.p2_negative_gates",
               "authority": authority,
               "expected_variants": 6,
               "variants": [],
               "rejected_variants": None,
               "all_rejected": None,
               "zero_process_evidence": None,
               "process_counters": {},
               "criterion_met": None,
               "reason": None}
    try:
        from .p2_negative_gates import (
            GATE_IDS,
            PROBE_COUNTERS,
            LaunchProbe,
            expect_preflight_rejection,
            p2_negative_gate_variants,
            trusted_path_declaration,
        )
    except ImportError as exc:  # pragma: no cover - import topology change
        section["reason"] = f"negative gate machinery unavailable: {exc}"
        _limit(limits, "negative_gates", section["reason"])
        return section
    try:
        declaration = trusted_path_declaration(authority)
        variants = p2_negative_gate_variants(declaration=declaration)
        section["gate_ids"] = list(GATE_IDS)
        section["probe_counters"] = list(PROBE_COUNTERS)
        section["declaration_sha256"] = declaration.identity_sha256
        for variant in variants:
            result = expect_preflight_rejection(variant, declaration=declaration,
                                                probe=LaunchProbe())
            section["variants"].append({
                "variant_id": variant.variant_id,
                "kind": variant.kind,
                "operation": variant.operation,
                "expected_reason": variant.expected_reason,
                "rejected": result.get("rejected"),
                "stage": result.get("stage"),
                "reason": result.get("reason"),
                "located_reason": result.get("located_reason"),
                "first_failing_edge": result.get("first_failing_edge"),
                "no_harness_effects": result.get("no_harness_effects"),
                "probe": result.get("probe")})
    except Exception as exc:  # pragma: no cover - declaration machinery change
        section["reason"] = (f"negative gate evaluation failed: "
                             f"{type(exc).__name__}: {exc}")
        _limit(limits, "negative_gates", section["reason"])
        return section
    rejected = [row for row in section["variants"] if row["rejected"]]
    section["rejected_variants"] = len(rejected)
    section["all_rejected"] = (len(section["variants"]) == section["expected_variants"]
                               and len(rejected) == section["expected_variants"])
    section["process_counters"] = {
        name: sum(row["probe"].get(name, 0) for row in section["variants"])
        for name in PROBE_COUNTERS}
    section["zero_process_evidence"] = all(
        count == 0 for count in section["process_counters"].values())
    section["criterion_met"] = bool(section["all_rejected"]
                                    and section["zero_process_evidence"])
    if not section["criterion_met"]:
        section["reason"] = (
            f"{section['rejected_variants']}/{section['expected_variants']} variants "
            f"rejected; process counters: {section['process_counters']}")
        _limit(limits, "negative_gates", section["reason"])
    return section


def _api_replay_identity(limits: list[dict]) -> dict:
    section = {"source": ("myfuzz.scenario.p2_negative_gates."
                          "assert_replay_identity_not_mutually_recognized (real "
                          "fresh-replay identity gate; no RTL, no factory)"),
               "available": False, "same_graph": None,
               "path_ids": None, "swapped_path_ids": None,
               "contract_sha256": None, "swapped_contract_sha256": None,
               "declaration_sha256": None, "swapped_declaration_sha256": None,
               "trusted_recognized_by_trusted": None,
               "swapped_recognized_by_swapped": None,
               "trusted_recognized_by_swapped": None,
               "swapped_recognized_by_trusted": None,
               "trusted_rejected_by_swapped": None,
               "swapped_rejected_by_trusted": None,
               "no_harness_effects": None, "probe": None, "reason": None}
    try:
        from .p2_negative_gates import (
            assert_replay_identity_not_mutually_recognized,
            trusted_gate,
            trusted_path_declaration,
        )
    except ImportError as exc:  # pragma: no cover - import topology change
        section["reason"] = f"replay identity gate unavailable: {exc}"
        _limit(limits, "replay_identity.api_level", section["reason"])
        return section
    try:
        # The gate needs a declaration that carries its trusted source bindings,
        # so the genome authority (same real topology, same runtime contract
        # construction) is the one that can be exercised.
        declaration = trusted_path_declaration("genome")
        swapped = trusted_gate("edge_identity_swap",
                               declaration=declaration).apply(declaration)
        report = assert_replay_identity_not_mutually_recognized(declaration, swapped)
    except Exception as exc:  # pragma: no cover - declaration machinery change
        section["reason"] = (f"replay identity gate failed: "
                             f"{type(exc).__name__}: {exc}")
        _limit(limits, "replay_identity.api_level", section["reason"])
        return section
    section.update({
        "available": True,
        "authority": "genome",
        "same_graph": report["same_graph"],
        "path_ids": list(report["path_ids"]),
        "swapped_path_ids": list(report["swapped_path_ids"]),
        "contract_sha256": report["contract_sha256"],
        "swapped_contract_sha256": report["swapped_contract_sha256"],
        "declaration_sha256": report["declaration_sha256"],
        "swapped_declaration_sha256": report["swapped_declaration_sha256"],
        "trusted_recognized_by_trusted": report["trusted_recognized_by_trusted"],
        "swapped_recognized_by_swapped": report["swapped_recognized_by_swapped"],
        "trusted_recognized_by_swapped": report["trusted_recognized_by_swapped"],
        "swapped_recognized_by_trusted": report["swapped_recognized_by_trusted"],
        "trusted_rejected_by_swapped": report["trusted_rejected_by_swapped"],
        "swapped_rejected_by_trusted": report["swapped_rejected_by_trusted"],
        "no_harness_effects": report["no_harness_effects"],
        "probe": report["probe"], "reason": None})
    if not (section["same_graph"] and section["trusted_recognized_by_swapped"] is False
            and section["swapped_recognized_by_trusted"] is False):
        _limit(limits, "replay_identity.api_level",
               "the real replay identity gate did not refuse both directions of the "
               "swapped-edge-identity declaration")
    return section


def _runtime_paths_of(document: Mapping | None) -> Mapping | None:
    if not isinstance(document, Mapping):
        return None
    paths = document.get("runtime_paths")
    if not isinstance(paths, Mapping):
        return None
    declaration = paths.get("declaration")
    if (not isinstance(declaration, Mapping)
            or not isinstance(declaration.get("graph"), Mapping)
            or not isinstance(declaration.get("contract"), Mapping)):
        return None
    return paths


def _run_pair(document_a: Mapping | None, document_b: Mapping | None,
              status_b: Mapping) -> dict:
    """Manifest-level replay mutual recognition of two declared identities."""
    section = {"available": False, "reason": None, "same_graph": None,
               "declaration_documents_equal": None,
               "contract_identities_equal": None,
               "topology_identities_equal": None,
               "edge_identity_differs": None, "criterion_applicable": None,
               "run_accepts_compare_record": None,
               "compare_accepts_run_record": None,
               "mutually_recognized": None, "rejection_reason": None,
               "run": None, "compare_run": None,
               "comparison_rule": (
                   "the real gate refuses a saved record whose prepared runtime "
                   "path declaration document is not the replay target's own "
                   f"({REPLAY_DECLARATION_MISMATCH}); the same document comparison "
                   "is applied here per direction of the pair")}
    paths_a = _runtime_paths_of(document_a)
    paths_b = _runtime_paths_of(document_b)
    if paths_a is None:
        section["reason"] = "this run has no readable runtime path declaration"
        return section
    if paths_b is None:
        section["reason"] = status_b.get("reason") or (
            "the comparison run has no readable runtime path declaration")
        return section
    declaration_a = paths_a["declaration"]
    declaration_b = paths_b["declaration"]
    same_graph = (paths_a.get("graph_sha256") == paths_b.get("graph_sha256")
                  and declaration_a["graph"] == declaration_b["graph"])
    declaration_equal = declaration_a == declaration_b
    contract_equal = paths_a.get("contract_sha256") == paths_b.get("contract_sha256")
    topology_equal = paths_a.get("topology_sha256") == paths_b.get("topology_sha256")
    path_ids_a = [row.get("path_id") for row in paths_a.get("paths") or ()]
    path_ids_b = [row.get("path_id") for row in paths_b.get("paths") or ()]
    section.update({
        "available": True,
        "same_graph": same_graph,
        "declaration_documents_equal": declaration_equal,
        "contract_identities_equal": contract_equal,
        "topology_identities_equal": topology_equal,
        "edge_identity_differs": not (declaration_equal and contract_equal),
        "run_accepts_compare_record": declaration_equal,
        "compare_accepts_run_record": declaration_equal,
        "mutually_recognized": bool(declaration_equal),
        "path_ids": path_ids_a,
        "compare_path_ids": path_ids_b,
        "contract_sha256": paths_a.get("contract_sha256"),
        "compare_contract_sha256": paths_b.get("contract_sha256"),
        "topology_sha256": paths_a.get("topology_sha256"),
        "compare_topology_sha256": paths_b.get("topology_sha256"),
        "rejection_reason": (None if declaration_equal
                             else REPLAY_DECLARATION_MISMATCH)})
    section["criterion_applicable"] = bool(same_graph
                                           and section["edge_identity_differs"])
    if not same_graph:
        section["reason"] = ("the two runs do not declare the same graph, so the "
                             "different-edge-identity replay criterion does not "
                             "apply to this pair")
    elif not section["edge_identity_differs"]:
        section["reason"] = ("the two runs declare the same edge identity; a fresh "
                             "replay recognizes it by design, which is not the "
                             "criterion under test")
    else:
        section["reason"] = None
    return section


def _replay_identity(document_a: Mapping | None, document_b: Mapping | None,
                     status_b: Mapping, *, requested: bool,
                     trace_replay: Mapping | None, limits: list[dict]) -> dict:
    api = _api_replay_identity(limits)
    pair = _run_pair(document_a, document_b, status_b) if requested else None
    api_value = None
    if api["available"]:
        api_value = bool(api["same_graph"]
                         and api["trusted_recognized_by_swapped"] is False
                         and api["swapped_recognized_by_trusted"] is False)
    value = api_value
    reason = None
    if pair is not None and pair["available"] and pair["criterion_applicable"] \
            and api_value is not None:
        value = bool(api_value and pair["mutually_recognized"] is False)
        if pair["mutually_recognized"] is not False:
            reason = ("the comparison run's declaration is mutually recognized; a "
                      "fresh replay of this graph must not accept the other edge "
                      "identity")
    if value is None:
        reason = reason or api["reason"] or (
            "the replay identity gate could not be evaluated")
    if pair is not None and not pair["available"]:
        _limit(limits, "replay_identity.run_pair", pair["reason"])
    elif pair is not None and not pair["criterion_applicable"]:
        _limit(limits, "replay_identity.run_pair", pair["reason"])
    elif pair is not None and pair["mutually_recognized"] is not False:
        _limit(limits, "replay_identity.run_pair",
               "the two runs are mutually recognized under different edge identities")
    if trace_replay is not None and trace_replay.get("verified") is not True:
        _limit(limits, "replay_identity.trace_replay",
               "the analyzer's run-directory replay comparison could not verify "
               f"{list(trace_replay.get('unverified_items') or ())}; a run-directory "
               "comparison is not a terminal fresh replay, so this is informational")
    return {
            "criterion": ("a fresh replay of the same graph under a different edge "
                          "identity must not be mutually recognized"),
            "api_level": api,
            "run_pair": pair,
            "run_pair_requested": bool(requested),
            "run_pair_available": None if pair is None else bool(pair["available"]),
            "trace_replay": (None if trace_replay is None
                             else {key: trace_replay.get(key) for key in (
                                 "kind", "replay_source", "verified",
                                 "event_count_match", "semantic_sha256_match",
                                 "status_match", "certified_chains_match",
                                 "comparison_matches", "first_difference",
                                 "unverified_items")}),
            "trace_replay_reason": (None if trace_replay is not None else (
                "no fresh-replay trace comparison was requested or possible; pass "
                "--compare-run with a run of the same declaration to compare "
                "event counts, semantic digests and statuses")),
            "not_mutually_recognized": value,
            "reason": reason}


# ---------------------------------------------------------------------------
# gate
# ---------------------------------------------------------------------------


def _gate_item(key: str, *, measured: bool, met, value, reason: str | None) -> dict:
    return {"key": key, "critical": True, "measured": bool(measured),
            "met": met, "value": value, "reason": reason}


def _gate(*, manifest: Mapping, trace: Mapping, directions: Mapping,
          chains: Mapping, early: Mapping, gates: Mapping, replay: Mapping) -> dict:
    items = [
        _gate_item("manifest", measured=bool(manifest.get("available")),
                   met=None, value=manifest.get("graph_sha256"),
                   reason=manifest.get("reason")),
        _gate_item("trace", measured=bool(trace.get("available")
                                          and trace.get("events_ingested") is not None),
                   met=None, value=trace.get("events_ingested"),
                   reason=trace.get("reason")),
    ]
    for direction in REQUIRED_DIRECTIONS:
        entry = directions["directions"].get(direction) or {}
        status = entry.get("status")
        items.append(_gate_item(
            f"direction_paths.{direction}", measured=status is not None,
            met=(status == CERTIFIED), value=status,
            reason=(None if status == CERTIFIED else entry.get("reason")
                    or "the direction has no settled runtime edge status")))
    items.append(_gate_item(
        "chain_certificates.by_direction",
        measured=chains.get("by_direction") is not None, met=None,
        value={"certified_total": chains.get("certified_total"),
               "incomplete_total": chains.get("incomplete_total")},
        reason=chains.get("reason")))
    items.append(_gate_item(
        "early_irq.early_irq_recorded",
        measured=early.get("decision_value") is not None,
        met=(early.get("decision_value") is True), value=early.get("decision"),
        reason=early.get("reason")))
    items.append(_gate_item(
        "negative_gates.six_variants_rejected",
        measured=gates.get("criterion_met") is not None,
        met=(gates.get("criterion_met") is True),
        value={"rejected_variants": gates.get("rejected_variants"),
               "zero_process_evidence": gates.get("zero_process_evidence")},
        reason=gates.get("reason")))
    pair_missing = bool(replay.get("run_pair_requested")
                        and replay.get("run_pair_available") is not True)
    items.append(_gate_item(
        "replay_identity.not_mutually_recognized",
        measured=(replay.get("not_mutually_recognized") is not None
                  and not pair_missing),
        met=(replay.get("not_mutually_recognized") is True),
        value=replay.get("not_mutually_recognized"),
        reason=(replay.get("reason") if not pair_missing else
                "a comparison run was requested but its declaration could not be "
                "read")))
    if replay.get("run_pair_requested"):
        pair = replay.get("run_pair") or {}
        items.append(_gate_item(
            "replay_identity.run_pair",
            measured=replay.get("run_pair_available") is True, met=None,
            value={"same_graph": pair.get("same_graph"),
                   "edge_identity_differs": pair.get("edge_identity_differs"),
                   "mutually_recognized": pair.get("mutually_recognized")},
            reason=pair.get("reason")))
    missing = [item["key"] for item in items
               if item["critical"] and not item["measured"]]
    unmet = [item["key"] for item in items
             if item["critical"] and item["measured"] and item["met"] is False]
    ready = not missing and not unmet
    if ready:
        summary = "all critical P2 keys are measured and their criteria hold"
    else:
        parts = []
        if missing:
            parts.append("missing evidence: " + ", ".join(missing))
        if unmet:
            parts.append("criteria not met: " + ", ".join(unmet))
        summary = "; ".join(parts)
    return {"items": items, "critical_missing": missing, "critical_unmet": unmet,
            "ready": ready, "exit_code": EXIT_READY if ready else EXIT_NOT_READY,
            "summary": summary,
            "exit_code_semantics": (
                "0 = every critical key was measured and its criterion holds; "
                "2 = evidence missing (null) or a criterion is not met; the gate "
                "never reports a null key as a pass")}


# ---------------------------------------------------------------------------
# the report
# ---------------------------------------------------------------------------


def _load_manifest(directory: Path) -> tuple[dict | None, str | None, str | None]:
    path = directory / MANIFEST_NAME
    if not path.is_file():
        return None, f"run directory has no {MANIFEST_NAME}", None
    payload = path.read_bytes()
    try:
        document = json.loads(payload.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return None, f"{MANIFEST_NAME} is not readable JSON: {exc}", None
    if not isinstance(document, dict):
        return None, f"{MANIFEST_NAME} is not a JSON object", None
    return document, None, hashlib.sha256(payload).hexdigest()


def _session_inputs(document: Mapping | None, limits: list[dict]):
    """(contract, endpoints, prepared_document, reason) from one manifest."""
    if document is None:
        return None, None, None, "the run has no session manifest"
    compiled = document.get("runtime_paths")
    if not isinstance(compiled, Mapping):
        return None, None, None, "the session manifest has no runtime_paths document"
    declaration = compiled.get("declaration")
    prepared_document = declaration if isinstance(declaration, Mapping) else None
    contract_document = (declaration.get("contract")
                         if isinstance(declaration, Mapping) else None)
    if not isinstance(contract_document, Mapping):
        return None, None, prepared_document, (
            "the compiled session document has no runtime path contract")
    try:
        contract = RuntimePathContract.from_document(dict(contract_document))
    except (ValueError, TypeError) as exc:
        _limit(limits, "manifest.contract",
               f"the declared runtime path contract is not valid: {exc}")
        return None, None, prepared_document, (
            f"the declared runtime path contract is not valid: {exc}")
    try:
        endpoints = edge_endpoints_from_compiled(contract, compiled)
    except (ValueError, KeyError, TypeError) as exc:
        _limit(limits, "manifest.endpoints",
               f"declared edge endpoints could not be resolved from the compiled "
               f"topology: {exc}")
        return contract, None, prepared_document, (
            "declared edge endpoints could not be resolved from the compiled "
            f"topology: {exc}")
    return contract, endpoints, prepared_document, None


def _trace_section(stream, reason: str | None, *, exhausted: bool) -> dict:
    if stream is None:
        return {"available": False, "reason": reason, "events_file": None,
                "format": None, "path": None, "bytes": None,
                "declared_event_count": None, "events_ingested": None,
                "event_count_match": None, "semantic_sha256_verified": None,
                "declared_status": None}
    descriptor = stream.descriptor
    declared = descriptor["declared_event_count"]
    ingested = stream.event_count if exhausted else None
    return {
        "available": True, "reason": reason,
        "events_file": descriptor["events_file"],
        "format": descriptor["format"], "path": descriptor["path"],
        "bytes": descriptor["bytes"],
        "meta_schema_version": descriptor["meta_schema_version"],
        "declared_event_count": declared,
        "declared_status": descriptor["declared_status"],
        "events_ingested": ingested,
        "event_count_match": (None if type(declared) is not int or ingested is None
                              else declared == ingested),
        "semantic_sha256_verified": (stream.semantic_sha256_verified()
                                     if exhausted else None)}


def _run_id(document: Mapping | None) -> str | None:
    identity = document.get("identity") if isinstance(document, Mapping) else None
    if not isinstance(identity, Mapping):
        return None
    config = identity.get("run_config")
    if not isinstance(config, Mapping):
        return None
    run_id = config.get("run_id")
    return run_id if isinstance(run_id, str) and run_id else None


def p2_acceptance_report(run_dir, *, run_dir_b=None,
                         authority: str = "online",
                         chain_producer=None,
                         max_certificates: int = DEFAULT_MAX_CERTIFICATES,
                         max_pending: int = 128, max_event_gap: int = 4096,
                         edge_max_pending: int = DEFAULT_EDGE_MAX_PENDING,
                         edge_max_event_gap: int = DEFAULT_EDGE_MAX_EVENT_GAP,
                         require_native_receipts: bool = True,
                         ingest_batch_size: int = DEFAULT_INGEST_BATCH_SIZE,
                         verify_semantic: bool = True,
                         max_irq_instances: int = DEFAULT_MAX_IRQ_INSTANCES,
                         max_acceptance_keys: int = DEFAULT_MAX_ACCEPTANCE_KEYS
                         ) -> dict:
    """Judge one saved run directory against the P2 acceptance condition.

    ``run_dir_b`` is a comparison run: when its declaration is identical the
    analyzer's fresh-replay trace comparison is reported; when it declares the
    same graph under a different edge identity the mutual-recognition criterion
    is measured on the pair.  Nothing here starts RTL or renders a harness.

    ``max_pending``/``max_event_gap`` bound the chain-certificate analyzer;
    ``edge_max_pending``/``edge_max_event_gap`` bound the declared-edge consumer,
    whose defaults are larger because an evicted binding record can never be
    credited again.
    """
    directory = Path(run_dir)
    if not directory.is_dir():
        raise ValueError(f"run directory does not exist: {directory}")
    limits: list[dict] = []
    if (max_irq_instances < 1 or max_acceptance_keys < 1
            or edge_max_pending < 1 or edge_max_event_gap < 1):
        raise ValueError("IRQ and edge bounds must be positive integers")

    manifest_document, manifest_reason, manifest_sha256 = _load_manifest(directory)
    if manifest_reason:
        _limit(limits, "manifest", manifest_reason)
    b_directory = None if run_dir_b is None else Path(run_dir_b)
    if run_dir_b is not None and not b_directory.is_dir():
        raise ValueError(f"comparison run directory does not exist: {b_directory}")
    b_document, b_reason, b_sha256 = ((None, None, None) if b_directory is None
                                      else _load_manifest(b_directory))
    if b_reason:
        _limit(limits, "manifest.compare_run", b_reason)

    contract, endpoints, prepared_document, session_reason = _session_inputs(
        manifest_document, limits)
    if session_reason and manifest_reason is None:
        _limit(limits, "manifest.runtime_paths", session_reason)

    trace_reason = None
    stream = None
    try:
        stream = TraceEventStream(directory, chunk_chars=DEFAULT_CHUNK_CHARS,
                                  verify_semantic=verify_semantic)
    except (TraceUnavailable, ValueError) as exc:
        trace_reason = f"no streamable trace artifact: {exc}"
        _limit(limits, "trace", trace_reason)

    scan = _IrqScan(max_instances=max_irq_instances,
                    max_acceptance_keys=max_acceptance_keys)
    provenance = None
    exhausted = False
    if stream is not None:
        def observed():
            for event in stream.events():
                scan.observe(event)
                yield event
            scan.exhausted = True
        try:
            if contract is not None and endpoints is not None:
                provenance = edge_provenance_report(
                    contract, observed(), endpoints=endpoints,
                    max_pending=edge_max_pending,
                    max_event_gap=edge_max_event_gap)
            else:
                for _ in observed():
                    pass
            exhausted = scan.exhausted
        except Exception as exc:
            trace_reason = (f"the event stream was rejected before it could be "
                            f"read to the end: {type(exc).__name__}: {exc}")
            provenance = None
            _limit(limits, "edge_provenance", trace_reason)

    trace = _trace_section(stream, trace_reason, exhausted=exhausted)
    directions = _direction_paths(prepared_document=prepared_document,
                                  contract=contract, provenance=provenance,
                                  provenance_reason=trace_reason or session_reason,
                                  limits=limits)
    pair = _run_pair(manifest_document, b_document,
                     {"reason": b_reason}) if run_dir_b is not None else None
    replay_dir = (b_directory if pair is not None and pair.get("available")
                  and pair.get("declaration_documents_equal") else None)
    chains = _chain_certificates(
        directory, chain_producer=chain_producer, replay_dir=replay_dir,
        max_certificates=max_certificates, max_pending=max_pending,
        max_event_gap=max_event_gap,
        require_native_receipts=require_native_receipts,
        ingest_batch_size=ingest_batch_size, verify_semantic=verify_semantic,
        limits=limits)
    analyzer = chains.pop("analyzer", None)
    early = scan.report(trace_reason=trace_reason,
                        events_ingested=trace["events_ingested"])
    gates = _negative_gates(authority, limits)
    replay = _replay_identity(
        manifest_document, b_document, {"reason": b_reason},
        requested=run_dir_b is not None,
        trace_replay=(None if analyzer is None else analyzer.get("replay")),
        limits=limits)
    identity_document = _read_json_object(directory / "online_run_identity.json")
    manifest_section = {
        "name": MANIFEST_NAME,
        "available": manifest_document is not None,
        "sha256": manifest_sha256,
        "reason": manifest_reason or session_reason,
        "graph_sha256": (None if contract is None else contract.graph_sha256),
        "contract_sha256": (None if contract is None else contract.identity_sha256),
        "topology_sha256": (None if not isinstance(manifest_document, Mapping)
                            else (manifest_document.get("runtime_paths") or {}
                                  ).get("topology_sha256")),
        "path_ids": [] if prepared_document is None else [
            row.get("path_id") for row in prepared_document.get("selections") or ()],
        "endpoints_resolved": endpoints is not None}
    gate = _gate(manifest=manifest_section, trace=trace, directions=directions,
                 chains=chains, early=early, gates=gates, replay=replay)
    _limit(limits, "scope",
           "every verdict in this report is derived from the saved artifacts of "
           "this run plus declaration-only checks; this report executes no RTL, "
           "renders no harness and starts no process")
    _limit(limits, "edge_provenance.certification",
           "an edge hop is certified only by the exact identity joins of "
           "runtime_edge_provenance_report.v1; this report does not re-derive hop "
           "evidence from raw events")
    _limit(limits, "early_irq.trace_only",
           "the early-IRQ verdict covers only native IRQ trigger/high records and "
           "CPU acceptance records written into this trace; an IRQ that never "
           "produced a record cannot be observed here")
    report = {
        "schema_version": SCHEMA_VERSION,
        "run_dir": str(directory),
        "run_id": _run_id(identity_document),
        "run_identity_sha256": (None if identity_document is None
                                else identity_document.get("sha256")),
        "compare_run_dir": None if b_directory is None else str(b_directory),
        "compare_run_manifest_sha256": b_sha256,
        "authority": authority,
        "bounds": {
            "edge_provenance": {"max_pending": edge_max_pending,
                                "max_event_gap": edge_max_event_gap},
            "chain_certificates": {"max_certificates": max_certificates,
                                   "max_pending": max_pending,
                                   "max_event_gap": max_event_gap},
            "irq_scan": {"max_instances": max_irq_instances,
                         "max_acceptance_keys": max_acceptance_keys}},
        "engine": {
            "p2_acceptance": _module_identity("myfuzz.scenario.p2_acceptance"),
            "edge_provenance": _module_identity("myfuzz.scenario.edge_provenance"),
            "chain_certificates": _module_identity(
                "myfuzz.scenario.chain_certificates"),
            "p2_negative_gates": _module_identity(
                "myfuzz.scenario.p2_negative_gates"),
            "acceptance_metrics": _module_identity(
                "myfuzz.scenario.acceptance_metrics")},
        "manifest": manifest_section,
        "trace": trace,
        "direction_paths": directions,
        "chain_certificates": chains,
        "early_irq": early,
        "negative_gates": gates,
        "replay_identity": replay,
        "gate": gate,
        "limits": limits,
    }
    return report


# ---------------------------------------------------------------------------
# markdown
# ---------------------------------------------------------------------------


def _cell(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, float):
        return f"{value:.6g}"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def render_markdown(report: Mapping) -> str:
    """Render one P2 acceptance report, evidence boundary first."""
    lines: list[str] = []
    add = lines.append
    add("# P2 acceptance report")
    add("")
    add(f"- schema: `{report.get('schema_version')}`")
    add(f"- run directory: `{report.get('run_dir')}`")
    if report.get("run_id") is not None:
        add(f"- run id: `{report.get('run_id')}`")
    if report.get("compare_run_dir") is not None:
        add(f"- comparison run directory: `{report.get('compare_run_dir')}`")
    add(f"- gate: **exit code {_cell((report.get('gate') or {}).get('exit_code'))}**"
        f" -- {_cell((report.get('gate') or {}).get('summary'))}")
    add("")

    gate = report.get("gate") or {}
    items = list(gate.get("items") or ())
    measured = [item for item in items if item.get("measured")]
    not_measured = [item for item in items if not item.get("measured")]
    add("## 证据边界 (evidence boundary)")
    add("")
    add("### 实测 (measured)")
    add("")
    if measured:
        add("| key | value | criterion | note |")
        add("|---|---|---|---|")
        for item in measured:
            criterion = ("n/a" if item.get("met") is None
                         else ("met" if item.get("met") else "not met"))
            add(f"| `{item['key']}` | `{_cell(item.get('value'))}` | {criterion} | "
                f"{_cell(item.get('reason'))} |")
    else:
        add("none: no critical key could be measured from this artifact")
    add("")
    add("### null / unknown 与原因 (null, unknown, and why)")
    add("")
    if not_measured:
        for item in not_measured:
            add(f"- `{item['key']}` = null -- {_cell(item.get('reason'))}")
    else:
        add("- none: every critical key carries a measured value")
    early = report.get("early_irq") or {}
    if early.get("decision_value") is None and early.get("decision") != "unknown":
        add(f"- `early_irq` = null ({_cell(early.get('decision'))}) -- "
            f"{_cell(early.get('reason'))}")
    pair = (report.get("replay_identity") or {}).get("run_pair")
    if isinstance(pair, Mapping) and pair.get("available") is False:
        add(f"- `replay_identity.run_pair` = null -- {_cell(pair.get('reason'))}")
    add("")
    add("### 限制 (limits)")
    add("")
    for limit in report.get("limits") or ():
        add(f"- `{_cell(limit.get('quantity'))}`: {_cell(limit.get('reason'))}")
    add("")

    add("## 逐条验收 (per-criterion)")
    add("")
    directions = (report.get("direction_paths") or {}).get("directions") or {}
    add("### 1. 两条方向的逐边交付/消费 (direction paths)")
    add("")
    add("| direction | label | declared edges | runtime edges | certified | "
        "incomplete | unknown | delivery records | consumption records | status |")
    add("|---|---|---:|---:|---:|---:|---:|---:|---:|---|")
    for name in sorted(directions):
        entry = directions[name]
        counts = entry.get("counts") or {}
        add(f"| `{name}` | {_cell(entry.get('label'))} | "
            f"{_cell(entry.get('declared_edge_count'))} | "
            f"{_cell(entry.get('runtime_edge_count'))} | "
            f"{_cell(counts.get('certified'))} | "
            f"{_cell(counts.get('incomplete'))} | "
            f"{_cell(counts.get('unknown'))} | "
            f"{len(entry.get('delivery_records') or ())} | "
            f"{len(entry.get('consumption_records') or ())} | "
            f"{_cell(entry.get('status'))} |")
    add("")
    for name in sorted(directions):
        entry = directions[name]
        add(f"#### `{name}` ({_cell(entry.get('label'))})")
        add("")
        add(f"- path_id: `{_cell(entry.get('path_id'))}`")
        add(f"- status: `{_cell(entry.get('status'))}`"
            + ("" if entry.get("reason") is None
               else f" -- {_cell(entry.get('reason'))}"))
        if entry.get("incomplete_edges"):
            for row in entry["incomplete_edges"]:
                add(f"- incomplete edge ({row['rule_index']}, "
                    f"{row['prerequisite_index']}): missing "
                    f"{_cell(row.get('missing'))}")
        if entry.get("unknown_edges"):
            for row in entry["unknown_edges"]:
                add(f"- unknown edge ({row['rule_index']}, "
                    f"{row['prerequisite_index']}): {_cell(row.get('reason'))}")
        add("")
        add("| edge | relation | status | producer | delivery | consumer | missing |")
        add("|---|---|---|---|---|---|---|")
        for row in entry.get("edges") or ():
            def hop(name):
                hop = row.get(name)
                return "null" if hop is None else _cell(hop.get("event_id"))
            add(f"| ({row['rule_index']}, {row['prerequisite_index']}) | "
                f"`{_cell(row.get('relation'))}` | `{_cell(row.get('status'))}` | "
                f"{hop('producer')} | {hop('delivery')} | {hop('consumer')} | "
                f"{_cell(row.get('missing') or None)} |")
        add("")

    chains = report.get("chain_certificates") or {}
    add("### 2. 方向级链证书 (chain certificates)")
    add("")
    by_direction = chains.get("by_direction")
    if by_direction is None:
        add(f"- null -- {_cell(chains.get('reason'))}")
    else:
        add("| direction | certified | incomplete (raw) |")
        add("|---|---:|---:|")
        for name in sorted(by_direction):
            row = by_direction[name] or {}
            add(f"| `{name}` | {_cell(row.get('certified'))} | "
                f"{_cell(row.get('incomplete'))} |")
        add("")
        add(f"- certified total: {_cell(chains.get('certified_total'))}; "
            f"incomplete total: {_cell(chains.get('incomplete_total'))}; "
            f"first missing hops: "
            f"`{_cell(chains.get('first_missing_hop_counts'))}`")
    add("")

    add("### 3. 真实 IP 提前 IRQ 仍写入 trace (early IRQ)")
    add("")
    add(f"- decision: `{_cell(early.get('decision'))}` "
        f"(value `{_cell(early.get('decision_value'))}`)")
    add(f"- criterion: {_cell(early.get('criterion'))}")
    add(f"- observations: {_cell(early.get('observation_records'))} record(s), "
        f"instances {_cell(early.get('observed_instance_count'))}, accepted "
        f"{_cell(early.get('accepted_instance_count'))}, unaccepted "
        f"{_cell(early.get('unaccepted_instance_count'))}")
    if early.get("reason") is not None:
        add(f"- reason: {_cell(early.get('reason'))}")
    for row in early.get("unaccepted_instances") or ():
        add(f"- unaccepted instance `{_cell(row.get('trigger_id'))}` "
            f"(component `{_cell(row.get('component'))}`) at event_id "
            f"{_cell(row.get('first_event_id'))}, event ids "
            f"{_cell(row.get('event_ids'))}, masks {_cell(row.get('masks'))}")
    add("")

    gates = report.get("negative_gates") or {}
    add("### 4. 声明破坏预检负例 (negative gates)")
    add("")
    add(f"- authority: `{_cell(gates.get('authority'))}`; rejected "
        f"{_cell(gates.get('rejected_variants'))}/"
        f"{_cell(gates.get('expected_variants'))}; zero process evidence: "
        f"`{_cell(gates.get('zero_process_evidence'))}`")
    add("")
    add("| variant | rejected | stage | first failing edge | located by | "
        "zero effects |")
    add("|---|---|---|---|---|---|")
    for row in gates.get("variants") or ():
        edge = row.get("first_failing_edge") or {}
        add(f"| `{row.get('variant_id')}` | `{_cell(row.get('rejected'))}` | "
            f"`{_cell(row.get('stage'))}` | ({_cell(edge.get('rule_index'))}, "
            f"{_cell(edge.get('prerequisite_index'))}) | "
            f"`{_cell(edge.get('located_by'))}` | "
            f"`{_cell(row.get('no_harness_effects'))}` |")
    add("")

    replay = report.get("replay_identity") or {}
    add("### 5. 同 graph 不同 edge identity 的 fresh replay 不互认 (replay identity)")
    add("")
    add(f"- not mutually recognized: "
        f"`{_cell(replay.get('not_mutually_recognized'))}` -- "
        f"{_cell(replay.get('reason'))}")
    api = replay.get("api_level") or {}
    add(f"- API level (real gate, no RTL): available `{_cell(api.get('available'))}`, "
        f"same graph `{_cell(api.get('same_graph'))}`, trusted accepted by swapped "
        f"`{_cell(api.get('trusted_recognized_by_swapped'))}`, swapped accepted by "
        f"trusted `{_cell(api.get('swapped_recognized_by_trusted'))}`")
    pair = replay.get("run_pair")
    if isinstance(pair, Mapping):
        add(f"- run pair: available `{_cell(pair.get('available'))}`, same graph "
            f"`{_cell(pair.get('same_graph'))}`, edge identity differs "
            f"`{_cell(pair.get('edge_identity_differs'))}`, mutually recognized "
            f"`{_cell(pair.get('mutually_recognized'))}`, rejection "
            f"`{_cell(pair.get('rejection_reason'))}`")
        if pair.get("reason") is not None:
            add(f"- run pair reason: {_cell(pair.get('reason'))}")
    else:
        add("- run pair: null (no comparison run was supplied)")
    trace_replay = replay.get("trace_replay")
    if isinstance(trace_replay, Mapping):
        add(f"- fresh-replay trace comparison: verified "
            f"`{_cell(trace_replay.get('verified'))}`, event count match "
            f"`{_cell(trace_replay.get('event_count_match'))}`, semantic sha256 "
            f"match `{_cell(trace_replay.get('semantic_sha256_match'))}`")
    else:
        add(f"- fresh-replay trace comparison: null -- "
            f"{_cell(replay.get('trace_replay_reason'))}")
    add("")

    add("## 门禁 (gate)")
    add("")
    add(f"- exit code: **{_cell(gate.get('exit_code'))}**")
    add(f"- critical missing: `{_cell(gate.get('critical_missing'))}`")
    add(f"- critical not met: `{_cell(gate.get('critical_unmet'))}`")
    add(f"- summary: {_cell(gate.get('summary'))}")
    add("")
    return "\n".join(lines) + "\n"


__all__ = [
    "SCHEMA_VERSION",
    "DIRECTION_LABELS",
    "REQUIRED_DIRECTIONS",
    "EARLY_IRQ_RECORDED",
    "EARLY_IRQ_NOT_OBSERVED",
    "EXIT_READY",
    "EXIT_NOT_READY",
    "p2_acceptance_report",
    "render_markdown",
]
