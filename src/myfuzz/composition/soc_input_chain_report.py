"""One deterministic corpus, three projection arms, one auditable report.

The RFuzz input chain has two halves, and each half already has its own tests:
raw records really project into legal candidates (the projection arms and the
declared candidate program), and a projected record really drives the RTL into
CPU and peer behaviour that replays (the runtime, transport and replay tests).
This module is the *comparison* those halves exist for.  For one shared corpus
and one build it answers: how many inputs did each arm really drive, what did it
have to repair, what did it refuse and under which name, how many distinct
projected inputs came out, what did the CPU and the peers really show, and does
re-running the projected records reproduce the applied stimulus field by field.

It is deliberately a *pure* aggregator.  It reads nothing from disk, imports no
simulator and makes no assumption about Verilator: every recorded run, every
identity hash and every replayed result arrives as an argument, and the returned
document is plain JSON.  That is what lets the same report be produced by a real
run and by a hand-built fixture, and it is why the report can be checked without
a toolchain.

Three accounting rules are enforced rather than described, because each of them
is a way a comparison can silently overstate an arm:

* **One input set.**  Every arm's recorded inputs must reproduce the shared
  corpus exactly, and the report publishes one ``shared_corpus_hash``; an arm
  that saw different inputs is refused instead of being compared.
* **One executable.**  Every outcome carries ``layout_hash``/``policy_hash``/
  ``image_hash``/``source_closure_hash``/``executable_sha256``.  The recorded
  identity must agree with the projectors' own layout/policy/image and with every
  other outcome; a differing executable is a conflict, not a footnote.
* **Separate bus accounting.**  An outcome whose ``execution_mode`` is
  ``bfm_isolated`` or ``contention`` may not claim CPU requests and never counts
  as CPU coverage; ``cpu_request_count`` and ``bfm_request_count`` are reported
  separately and are never summed.  A rejected input produced no run at all, so
  it may not carry applied stimulus, requests or peer applications.

The replay half reuses :mod:`myfuzz.composition.soc_failure_evidence`'s own field
naming (``_comparison_fields``/``_field_location``) so an ``applied`` difference
is located at exactly the ``(index, cycle, field_role, bit)`` a saved evidence
package would report, and a report with no replay evidence says ``not_assessed``
rather than claiming agreement.  "Applied" here means the harness's own
per-cycle applied-port record; the candidate image it placed before releasing the
CPU is reported separately as the image-placement readbacks, which is what shows
that an offered raw candidate became the memory the CPU fetches from.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence

from myfuzz.contracts import content_hash

from .soc_failure_evidence import (
    REPLAY_AGREEMENT,
    REPLAY_DIVERGENCE,
    _comparison_fields,
    _field_location,
)

#: The report document version and the provenance string the seeded-corpus runs
#: must publish.  The three-arm comparison of an *official* RFuzz corpus is a
#: different execution mode and must not reuse this one's claim.
REPORT_SCHEMA = "soc_input_chain_report.v1"
SEEDED_CORPUS_EXECUTION_MODE = "seeded-corpus-real-rtl"

ARM_NAMES = ("direct_input", "constrained_baseline", "dependency_repair")
#: Drive profiles in which the CPU owns the bus, and in which it does not.  The
#: split is by declared ownership (``input_constraints.DRIVE_PROFILES``), never
#: by what a run happens to look like.
CPU_EXECUTION_MODES = ("cpu_execute",)
BFM_EXECUTION_MODES = ("bfm_isolated", "contention")
EXECUTION_MODES = CPU_EXECUTION_MODES + BFM_EXECUTION_MODES

#: Input-chain statuses.  ``executed`` drove the RTL, ``rejected`` was refused by
#: the projection before any RTL was driven, and ``anomaly`` reached the RTL but
#: produced no usable result.  Only ``executed`` counts as an effective input.
OUTCOME_EXECUTED = "executed"
OUTCOME_REJECTED = "rejected"
OUTCOME_ANOMALY = "anomaly"
OUTCOME_STATUSES = (OUTCOME_EXECUTED, OUTCOME_REJECTED, OUTCOME_ANOMALY)

#: Replay statuses beyond the two ``soc_failure_evidence`` defines.
REPLAY_NOT_ASSESSED = "not_assessed"
REPLAY_PARTIAL = "partial"

#: The per-outcome identity fields the report saves and cross-checks.
IDENTITY_FIELDS = (
    "layout_hash",
    "policy_hash",
    "image_hash",
    "source_closure_hash",
    "executable_sha256",
)

#: Bounded evidence kept for a divergence, so one mutated corpus cannot produce a
#: report larger than the corpus it describes.
MAX_MISMATCH_LABELS = 32

CLAIM = (
    "seeded-corpus input-chain metrics: one deterministic corpus, one build and "
    "three projectors; this is NOT an official RFuzz search and NOT three "
    "independent searches"
)

__all__ = [
    "ARM_NAMES",
    "BFM_EXECUTION_MODES",
    "CLAIM",
    "CPU_EXECUTION_MODES",
    "EXECUTION_MODES",
    "IDENTITY_FIELDS",
    "OUTCOME_ANOMALY",
    "OUTCOME_EXECUTED",
    "OUTCOME_REJECTED",
    "OUTCOME_STATUSES",
    "REPLAY_NOT_ASSESSED",
    "REPLAY_PARTIAL",
    "REPORT_SCHEMA",
    "SEEDED_CORPUS_EXECUTION_MODE",
    "SocInputChainReportError",
    "arm_metrics",
    "build_chain_report",
    "compare_replay",
    "corpus_hash",
    "fabric_source_lanes",
]


class SocInputChainReportError(ValueError):
    """The recorded runs cannot be summarised as one honest comparison."""


def _error(reason: str) -> None:
    raise SocInputChainReportError(reason)


# ---------------------------------------------------------------------------
# small validated readers
# ---------------------------------------------------------------------------


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _error(f"{label}-not-an-object")
    return value


def _records(value: object, label: str) -> tuple[object, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        _error(f"{label}-not-a-sequence")
    return tuple(value)


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _error(f"{label}-not-an-integer")
    return int(value)


def _number(value: object) -> object:
    """A counter value that stays JSON-serialisable without changing its type."""
    if isinstance(value, bool) or isinstance(value, (int, float, str)) or value is None:
        return value
    return str(value)


def _words(value: object, label: str) -> list[int]:
    return [_integer(item, f"{label}:word") for item in _records(value, label)]


def _request_records(value: object, label: str) -> list[dict[str, object]]:
    """Bus transactions as recorded, with integer fields left as integers."""
    records: list[dict[str, object]] = []
    for position, item in enumerate(_records(value, label)):
        record = _mapping(item, f"{label}:{position}")
        records.append({str(key): _number(item_value)
                        for key, item_value in record.items()})
    return records


def _applied_records(value: object, label: str) -> list[dict[str, object]]:
    """The applied stimulus, validated where the repository already fixes it.

    ``RunResult.applied`` is ``{"cycle", "port", "value"}``; the comparison below
    reads it back through the evidence module's own field naming, so a record
    that cannot produce an ``applied[<cycle>].<port>`` field is refused here
    instead of silently vanishing from the replay comparison.
    """
    records: list[dict[str, object]] = []
    for position, item in enumerate(_records(value, label)):
        record = _mapping(item, f"{label}:{position}")
        cycle = _integer(record.get("cycle"), f"{label}:{position}:cycle")
        port = record.get("port")
        if not isinstance(port, str) or not port:
            _error(f"{label}:{position}:port-missing")
        value_at = record.get("value")
        if isinstance(value_at, bool) or not isinstance(value_at, int):
            _error(f"{label}:{position}:value-not-an-integer")
        records.append({"cycle": cycle, "port": port, "value": int(value_at)})
    return records


def _differing_bits(expected: object, observed: object) -> list[int]:
    """The bit positions two applied values disagree in, lowest first."""
    if isinstance(expected, bool) or isinstance(observed, bool):
        return []
    if not isinstance(expected, int) or not isinstance(observed, int):
        return []
    difference = int(expected) ^ int(observed)
    return [bit for bit in range(difference.bit_length()) if difference >> bit & 1]


# ---------------------------------------------------------------------------
# corpus
# ---------------------------------------------------------------------------


def corpus_hash(corpus: Sequence[Mapping[str, object]]) -> str:
    """The content hash of the shared input set: one ``(index, raw)`` per entry.

    Only the index and the raw words are hashed.  The corpus ``kind`` labels how
    an entry was generated, but the input set an arm received is the raw record;
    two corpora that drive the same words are the same experiment even if one of
    them was labelled differently.
    """
    entries: list[dict[str, object]] = []
    seen: set[int] = set()
    for position, item in enumerate(_records(corpus, "corpus")):
        record = _mapping(item, f"corpus:{position}")
        index = _integer(record.get("index", position), f"corpus:{position}:index")
        if index in seen:
            _error(f"corpus-index-repeated:{index}")
        seen.add(index)
        entries.append({"index": index, "raw": _words(record.get("raw"),
                                                      f"corpus:{index}:raw")})
    if not entries:
        _error("corpus-is-empty")
    entries.sort(key=lambda item: int(item["index"]))
    return content_hash(entries)


def _corpus_entries(corpus: Sequence[Mapping[str, object]]) -> dict[int, list[int]]:
    entries: dict[int, list[int]] = {}
    for position, item in enumerate(_records(corpus, "corpus")):
        record = _mapping(item, f"corpus:{position}")
        index = _integer(record.get("index", position), f"corpus:{position}:index")
        if index in entries:
            _error(f"corpus-index-repeated:{index}")
        entries[index] = _words(record.get("raw"), f"corpus:{index}:raw")
    if not entries:
        _error("corpus-is-empty")
    return entries


# ---------------------------------------------------------------------------
# one outcome
# ---------------------------------------------------------------------------


def _outcome_view(arm: str, item: object, position: int, *,
                  identity: Mapping[str, object] | None = None,
                  require_identity: bool = False) -> dict[str, object]:
    """One recorded outcome, validated and normalised.

    Every refusal below names the field, the arm and the corpus index, because a
    report that quietly reclassifies a mislabelled run is worse than no report:
    the whole point of the three-arm comparison is that CPU coverage, BFM
    coverage, repairs and refusals are attributable.
    """
    record = _mapping(item, f"outcomes:{arm}:{position}")
    index = _integer(record.get("index", position), f"outcomes:{arm}:{position}:index")
    where = f"{arm}:{index}"
    if str(record.get("arm")) != arm:
        _error(f"outcome-arm-mismatch:{where}:{record.get('arm')}")
    status = str(record.get("status"))
    if status not in OUTCOME_STATUSES:
        _error(f"unknown-outcome-status:{where}:{status}")
    mode = str(record.get("execution_mode"))
    if mode not in EXECUTION_MODES:
        _error(f"unknown-execution-mode:{where}:{mode}")
    reason = str(record.get("reason", ""))
    projected = _words(record.get("projected"), f"outcomes:{where}:projected")
    applied = _applied_records(record.get("applied"), f"outcomes:{where}:applied")
    cpu_requests = _request_records(record.get("cpu_requests"),
                                    f"outcomes:{where}:cpu_requests")
    cpu_writes = _request_records(record.get("cpu_writes"),
                                  f"outcomes:{where}:cpu_writes")
    bfm_requests = _request_records(record.get("bfm_requests"),
                                    f"outcomes:{where}:bfm_requests")
    bfm_writes = _request_records(record.get("bfm_writes"),
                                  f"outcomes:{where}:bfm_writes")
    peer_applied = _request_records(record.get("peer_applied"),
                                    f"outcomes:{where}:peer_applied")
    placements = _request_records(record.get("image_placements"),
                                  f"outcomes:{where}:image_placements")
    image_errors = _request_records(record.get("image_errors"),
                                    f"outcomes:{where}:image_errors")
    repairs: list[dict[str, object]] = []
    for repair_position, entry in enumerate(
            _records(record.get("repairs"), f"outcomes:{where}:repairs")):
        repair = _mapping(entry, f"outcomes:{where}:repairs:{repair_position}")
        kind = repair.get("kind")
        if not isinstance(kind, str) or not kind:
            _error(f"repair-record-without-a-kind:{where}:{repair_position}")
        repairs.append({str(key): _number(value) for key, value in repair.items()})
    counters_value = record.get("counters")
    counters: dict[str, object] = {}
    if counters_value is not None:
        counters = {str(key): _number(value)
                    for key, value in sorted(
                        _mapping(counters_value, f"outcomes:{where}:counters").items())}
    coverage_value = record.get("coverage_bits")
    coverage_bits = None if coverage_value is None else [
        _integer(bit, f"outcomes:{where}:coverage_bits") for bit in
        _records(coverage_value, f"outcomes:{where}:coverage_bits")]
    if status == OUTCOME_REJECTED:
        # A refusal happened before the RTL was driven, so any run evidence on a
        # rejected outcome is a contradiction, not extra data.
        for name, value in (("applied", applied), ("projected", projected),
                            ("cpu_requests", cpu_requests),
                            ("cpu_writes", cpu_writes),
                            ("bfm_requests", bfm_requests),
                            ("bfm_writes", bfm_writes),
                            ("peer_applied", peer_applied),
                            ("image_placements", placements),
                            ("image_errors", image_errors)):
            if value:
                _error(f"rejected-outcome-recorded-a-run:{where}:{name}")
    if status == OUTCOME_EXECUTED and not projected:
        _error(f"executed-outcome-without-a-projected-input:{where}")
    if mode in BFM_EXECUTION_MODES and cpu_requests:
        # The execution mode owns the bus: a bfm_isolated or contention run cannot
        # attribute a transaction to the CPU, so it may not claim one.
        _error(f"bfm-execution-mode-claims-cpu-requests:{where}:{mode}")
    view: dict[str, object] = {
        "index": index,
        "arm": arm,
        "status": status,
        "reason": reason,
        "execution_mode": mode,
        "raw": _words(record.get("raw"), f"outcomes:{where}:raw"),
        "projected": projected,
        "applied": applied,
        "repairs": repairs,
        "counters": counters,
        "cpu_requests": cpu_requests,
        "cpu_writes": cpu_writes,
        "bfm_requests": bfm_requests,
        "bfm_writes": bfm_writes,
        "peer_applied": peer_applied,
        "image_placements": placements,
        "image_errors": image_errors,
        "coverage_bits": coverage_bits,
        "projected_sha256": (content_hash([int(value) for value in projected])
                             if projected else None),
    }
    if require_identity:
        for name in IDENTITY_FIELDS:
            value = record.get(name)
            if value in (None, "") and identity is not None:
                value = identity.get(name)
            if value in (None, ""):
                _error(f"outcome-identity-missing:{name}:{where}")
            view[name] = str(value)
    return view


def _count(values: Sequence[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _rate(numerator: int, denominator: int) -> float:
    return float(numerator) / float(denominator) if denominator else 0.0


def _addresses(requests: Sequence[Mapping[str, object]]) -> list[int]:
    found: set[int] = set()
    for request in requests:
        address = request.get("addr")
        if isinstance(address, int) and not isinstance(address, bool):
            found.add(int(address))
    return sorted(found)


# ---------------------------------------------------------------------------
# per-arm metrics
# ---------------------------------------------------------------------------


def arm_metrics(arm: str, outcomes: Sequence[Mapping[str, object]]) -> dict[str, object]:
    """Everything the comparison reports about one arm's outcomes.

    Pure by construction: no plan, no build and no disk.  Rates are over the
    inputs the arm received (``effective_input_rate``, ``rejection_rate``) and
    over the inputs it really drove (repair and coverage rates), never over an
    implied total; ``cpu_request_count`` and ``bfm_request_count`` stay separate
    and no field of this document is their sum.
    """
    if not isinstance(arm, str) or not arm:
        _error("arm-name-required")
    views = [_outcome_view(arm, item, position)
             for position, item in enumerate(_records(outcomes, f"outcomes:{arm}"))]
    if not views:
        _error(f"arm-without-outcomes:{arm}")
    total = len(views)
    executed = [view for view in views if view["status"] == OUTCOME_EXECUTED]
    rejected = [view for view in views if view["status"] == OUTCOME_REJECTED]
    anomalies = [view for view in views if view["status"] == OUTCOME_ANOMALY]
    cpu_outcomes = [view for view in executed
                    if view["execution_mode"] in CPU_EXECUTION_MODES]
    bfm_outcomes = [view for view in executed
                    if view["execution_mode"] in BFM_EXECUTION_MODES]

    # Repairs are counted over the effective inputs: an input that was refused
    # before the RTL was driven never reached a repairer, and an anomalous run's
    # repairs are not evidence about what the arm drove successfully.
    repair_kinds: list[str] = []
    for view in executed:
        repair_kinds.extend(str(repair["kind"]) for repair in view["repairs"])
    repair_counts = _count(repair_kinds)

    rejection_reasons = [str(view["reason"]) or "unnamed" for view in rejected]
    anomaly_reasons = [str(view["reason"]) or "unnamed" for view in anomalies]
    rejection_counts = _count(rejection_reasons)
    anomaly_counts = _count(anomaly_reasons)

    projected_hashes = [str(view["projected_sha256"]) for view in executed
                        if view["projected_sha256"]]
    unique_hashes = sorted(set(projected_hashes))

    cpu_requests = [request for view in cpu_outcomes for request in view["cpu_requests"]]
    cpu_writes = [request for view in cpu_outcomes for request in view["cpu_writes"]]
    bfm_requests = [request for view in views for request in view["bfm_requests"]]
    bfm_writes = [request for view in views for request in view["bfm_writes"]]
    covered = [view for view in cpu_outcomes if view["cpu_requests"]]
    peer_views = [view for view in executed if view["peer_applied"]]
    peer_events = [event for view in executed for event in view["peer_applied"]]
    coverage_views = [view for view in executed if view["coverage_bits"] is not None]
    coverage_union = sorted({int(bit) for view in coverage_views
                             for bit in view["coverage_bits"] or ()})
    # The candidate-image placements the harness performed before releasing the
    # CPU: the readback is what the memory model the CPU fetches from really
    # held, so it is evidence that an offered raw candidate became executable
    # memory instead of a record that a field was written.
    placement_records = [item for view in executed for item in view["image_placements"]]
    placement_errors = [item for view in executed for item in view["image_errors"]]
    readbacks = [int(item["readback"]) for item in placement_records
                 if isinstance(item.get("readback"), int)
                 and not isinstance(item.get("readback"), bool)]
    counter_totals: dict[str, dict[str, int]] = {}
    for view in executed:
        for name, value in view["counters"].items():
            if isinstance(value, bool) or not isinstance(value, int):
                continue
            record = counter_totals.setdefault(
                str(name), {"outcomes": 0, "total": 0, "min": int(value),
                            "max": int(value)})
            record["outcomes"] += 1
            record["total"] += int(value)
            record["min"] = min(record["min"], int(value))
            record["max"] = max(record["max"], int(value))

    gaps: list[str] = []
    for view in rejected:
        if not str(view["reason"]):
            gaps.append(f"rejection-without-a-named-reason:{view['index']}")
    for view in anomalies:
        gaps.append(f"anomalous-run:{view['index']}:{view['reason'] or 'unnamed'}")
    quiet = [view for view in cpu_outcomes if not view["cpu_requests"]]
    if quiet:
        gaps.append(f"cpu-coverage-gap:executed-without-a-cpu-request:{len(quiet)}")
    if coverage_views and not coverage_union:
        gaps.append("rtl-coverage-bits-empty:the-build-reports-none")
    if not coverage_views:
        gaps.append("rtl-coverage-bits-not-recorded")
    if placement_errors:
        # The harness refused an out-of-region address.  The identity arm has no
        # repair authority, so this is where its addresses are stopped.
        gaps.append(f"image-address-refused:{len(placement_errors)}")
    if readbacks and not any(readbacks):
        gaps.append("image-placement-readback-zero:the-memory-model-held-nothing")

    return {
        "schema_version": REPORT_SCHEMA,
        "arm": arm,
        "outcomes": total,
        "executed": len(executed),
        "rejected": len(rejected),
        "anomalies": len(anomalies),
        "effective_input_rate": _rate(len(executed), total),
        "rejection_rate": _rate(len(rejected), total),
        "anomaly_rate": _rate(len(anomalies), total),
        "rejection_counts": rejection_counts,
        "rejection_rates": {name: _rate(count, total)
                            for name, count in rejection_counts.items()},
        "anomaly_counts": anomaly_counts,
        "anomaly_rates": {name: _rate(count, total)
                          for name, count in anomaly_counts.items()},
        "repair_counts": repair_counts,
        "repair_rates": {name: _rate(count, len(executed))
                         for name, count in repair_counts.items()},
        "unique_projected_inputs": {
            "count": len(unique_hashes),
            "inputs": len(projected_hashes),
            "hashes": unique_hashes,
        },
        "execution_modes": _count([str(view["execution_mode"]) for view in executed]),
        "cpu_request_count": len(cpu_requests),
        "bfm_request_count": len(bfm_requests),
        "cpu_coverage": {
            "execution_modes": list(CPU_EXECUTION_MODES),
            "outcomes": len(cpu_outcomes),
            "outcomes_with_requests": len(covered),
            "outcomes_with_writes": sum(1 for view in cpu_outcomes
                                        if view["cpu_writes"]),
            "outcomes_without_requests": len(quiet),
            "coverage_rate": _rate(len(covered), len(cpu_outcomes)),
            "request_count": len(cpu_requests),
            "write_count": len(cpu_writes),
            "touched_addresses": _addresses(cpu_requests),
            "touched_address_count": len(_addresses(cpu_requests)),
        },
        "bfm_coverage": {
            "execution_modes": list(BFM_EXECUTION_MODES),
            "outcomes": len(bfm_outcomes),
            "request_count": len(bfm_requests),
            "write_count": len(bfm_writes),
            "touched_addresses": _addresses(bfm_requests),
            "touched_address_count": len(_addresses(bfm_requests)),
            # The whole point of the split: a BFM/arbitrated transaction is never
            # promoted into CPU coverage.
            "counted_as_cpu_coverage": False,
        },
        "peer_coverage": {
            "outcomes_with_applied_events": len(peer_views),
            "coverage_rate": _rate(len(peer_views), len(executed)),
            "applied_events": len(peer_events),
            "instances": sorted({str(event.get("instance", ""))
                                 for event in peer_events}),
            "slots": sorted({str(event.get("slot", "")) for event in peer_events}),
        },
        "coverage_bits": {
            "outcomes_recorded": len(coverage_views),
            "hit": len(coverage_union),
            "union": coverage_union,
        },
        # The image half of the input chain: what the offered candidates became
        # in the memory the CPU fetches from, and which addresses were refused.
        "image_placements": {
            "outcomes_recorded": sum(1 for view in executed
                                     if view["image_placements"]),
            "placements": len(placement_records),
            "kinds": _count([str(item.get("kind", ""))
                             for item in placement_records]),
            "slots": sorted({str(item.get("slot", ""))
                             for item in placement_records}),
            "addresses": sorted({int(item["addr"]) for item in placement_records
                                 if isinstance(item.get("addr"), int)
                                 and not isinstance(item.get("addr"), bool)}),
            "readbacks_recorded": len(readbacks),
            "readbacks_nonzero": sum(1 for value in readbacks if value),
            "errors": len(placement_errors),
            "outcomes_with_errors": sum(1 for view in executed
                                        if view["image_errors"]),
        },
        # Per-counter totals over the effective inputs, so a run's own counters
        # (cycles, fabric completions) are visible next to the coverage they may
        # or may not support.
        "counter_totals": {name: counter_totals[name]
                           for name in sorted(counter_totals)},
        "gaps": gaps,
    }


# ---------------------------------------------------------------------------
# replay comparison
# ---------------------------------------------------------------------------


def _replayed_applied(value: object) -> list[object]:
    """The applied stimulus of a replayed run, from a result or a trace."""
    if isinstance(value, Mapping):
        return list(_records(value.get("applied_trace"),
                             "replayed-result:applied_trace"))
    return list(_records(value, "replayed-applied"))


def _applied_fields(records: Sequence[Mapping[str, object]]) -> dict[str, object]:
    """The applied stimulus in the evidence module's own field namespace.

    The comparison is scoped to ``applied[...]`` on purpose: it answers "was the
    same stimulus applied", not "did the whole run reproduce".  The naming and
    the field location still come from ``soc_failure_evidence``, so a difference
    is reported exactly where a replayed evidence package would report it.
    """
    fields = _comparison_fields({"applied_trace": list(records)})
    return {name: value for name, value in fields.items()
            if name.startswith("applied[")}


def compare_replay(*, arm: str, index: int, saved: object, replayed: object,
                   layout: object = None) -> dict[str, object]:
    """Compare one outcome's applied stimulus with a replayed run, field by field.

    The comparison is performed in :mod:`soc_failure_evidence`'s own field
    namespace (``applied[<cycle>].<port>``), so the divergence this report
    publishes is located exactly where a replayed evidence package would locate
    it: ``(index, cycle, field_role, bit)``.  ``bit`` is the lowest disagreeing
    bit, ``bits`` all of them, and both are ``None``/empty when the replayed run
    recorded no value at all at that cycle -- "missing" is not bit zero.
    """
    saved_records = _applied_records(saved, f"outcomes:{arm}:{index}:applied")
    replayed_records = _applied_records(_replayed_applied(replayed),
                                        f"replays:{arm}:{index}")
    expected = _applied_fields(saved_records)
    observed = _applied_fields(replayed_records)
    checked = 0
    matching = 0
    mismatching = 0
    labels: list[str] = []
    divergence: dict[str, object] | None = None
    for name in list(expected) + [item for item in observed if item not in expected]:
        checked += 1
        left = expected.get(name)
        right = observed.get(name)
        if left == right:
            matching += 1
            continue
        mismatching += 1
        if len(labels) < MAX_MISMATCH_LABELS:
            labels.append(name)
        if divergence is not None:
            continue
        cycle, field_role = _field_location(name)
        bits = _differing_bits(left, right)
        divergence = {
            "arm": arm,
            "index": int(index),
            "cycle": cycle,
            "field_role": field_role,
            "bit": bits[0] if bits else None,
            "bits": bits,
            "label": name,
            "kind": "applied-port-value",
            "expected": left,
            "observed": right,
        }
        owner, role = _layout_field(layout, field_role)
        divergence["layout_owner"] = owner
        divergence["layout_role"] = role
    return {
        "arm": arm,
        "index": int(index),
        "checked_fields": checked,
        "matching_fields": matching,
        "mismatching_fields": mismatching,
        "mismatching_labels": labels,
        "mismatching_labels_truncated": mismatching > len(labels),
        "divergence": divergence,
    }


def _layout_field(layout: object, port: object) -> tuple[str | None, str | None]:
    """The ``(owner, role)`` of one applied port, when the layout declares it."""
    for field in getattr(layout, "fields", ()) or ():
        if str(getattr(field, "port", "")) == str(port):
            return str(getattr(field, "owner", "")) or None, \
                str(getattr(field, "role", "")) or None
    return None, None


def _replay_section(views_by_arm: Mapping[str, list[dict[str, object]]],
                    replays: Mapping[str, object],
                    layouts: Mapping[str, object]) -> dict[str, object]:
    """Replay every effective input the caller supplied evidence for."""
    per_arm: dict[str, dict[str, object]] = {}
    compared = 0
    not_assessed = 0
    divergence: dict[str, object] | None = None
    totals = {"checked_fields": 0, "matching_fields": 0, "mismatching_fields": 0}
    labels: list[str] = []
    for arm, views in views_by_arm.items():
        evidence = replays.get(arm)
        if evidence is None:
            evidence = []
        entries: object = evidence
        aligned: list[object]
        if isinstance(entries, Mapping):
            aligned = [entries.get(str(view["index"]), entries.get(int(view["index"])))
                       for view in views]
        else:
            sequence = list(_records(entries, f"replays:{arm}"))
            if sequence and len(sequence) != len(views):
                _error(f"replay-count-mismatch:{arm}:{len(sequence)}!={len(views)}")
            aligned = sequence + [None] * (len(views) - len(sequence))
        arm_checked = 0
        arm_matching = 0
        arm_mismatching = 0
        arm_compared = 0
        arm_missing = 0
        for view, replayed in zip(views, aligned):
            if view["status"] != OUTCOME_EXECUTED:
                continue
            if replayed is None:
                arm_missing += 1
                continue
            result = compare_replay(arm=arm, index=int(view["index"]),
                                    saved=view["applied"], replayed=replayed,
                                    layout=layouts.get(arm))
            arm_compared += 1
            arm_checked += int(result["checked_fields"])
            arm_matching += int(result["matching_fields"])
            arm_mismatching += int(result["mismatching_fields"])
            if result["divergence"] is not None and divergence is None:
                divergence = result["divergence"]
            for label in result["mismatching_labels"]:
                if len(labels) < MAX_MISMATCH_LABELS:
                    labels.append(str(label))
        compared += arm_compared
        not_assessed += arm_missing
        totals["checked_fields"] += arm_checked
        totals["matching_fields"] += arm_matching
        totals["mismatching_fields"] += arm_mismatching
        if arm_mismatching:
            status = REPLAY_DIVERGENCE
        elif arm_compared and arm_missing:
            status = REPLAY_PARTIAL
        elif arm_compared:
            status = REPLAY_AGREEMENT
        else:
            status = REPLAY_NOT_ASSESSED
        per_arm[arm] = {
            "status": status,
            "compared_outcomes": arm_compared,
            "not_assessed_outcomes": arm_missing,
            "checked_fields": arm_checked,
            "matching_fields": arm_matching,
            "mismatching_fields": arm_mismatching,
        }
    if divergence is not None:
        status = REPLAY_DIVERGENCE
        reason = (f"the replayed run diverged at arm {divergence['arm']} "
                  f"index {divergence['index']} cycle {divergence['cycle']} field "
                  f"{divergence['field_role']!r} bit {divergence['bit']}")
    elif compared and not_assessed:
        status = REPLAY_PARTIAL
        reason = (f"{compared} effective input(s) replayed identically; "
                  f"{not_assessed} had no replay evidence and are not claimed")
    elif compared:
        status = REPLAY_AGREEMENT
        reason = (f"{compared} effective input(s) replayed with identical applied "
                  f"stimulus ({totals['checked_fields']} field(s) compared)")
    else:
        status = REPLAY_NOT_ASSESSED
        reason = ("no replay evidence was supplied, so the report does not claim "
                  "the applied stimulus was reproduced")
    return {
        "schema_version": REPORT_SCHEMA,
        "status": status,
        "reason": reason,
        "compared_outcomes": compared,
        "not_assessed_outcomes": not_assessed,
        "checked_fields": totals["checked_fields"],
        "matching_fields": totals["matching_fields"],
        "mismatching_fields": totals["mismatching_fields"],
        "mismatching_labels": labels,
        "mismatching_labels_truncated": totals["mismatching_fields"] > len(labels),
        "divergence": divergence,
        "per_arm": per_arm,
    }


# ---------------------------------------------------------------------------
# the report
# ---------------------------------------------------------------------------


def _arm_identity_from_projectors(arms: Mapping[str, object]) -> dict[str, str]:
    """The layout/policy/image identity the projectors themselves carry.

    ``build_projection_arms`` hands every arm the same combined layout and the
    same compiled policy, and the dependency-repair arm the declared image plan.
    Reading the identity back from the arms is therefore a *check* on the
    recorded hashes, not a replacement for them: an arm whose projector disagrees
    with the record is refused.
    """
    found: dict[str, str] = {}
    for arm, projector in arms.items():
        candidates = {
            "layout_hash": str(getattr(getattr(projector, "layout", None),
                                       "layout_hash", "") or ""),
            "policy_hash": str(getattr(getattr(projector, "policy", None),
                                       "policy_hash", "") or ""),
            "image_hash": str(getattr(getattr(projector, "image_plan", None),
                                      "image_hash", "") or ""),
        }
        for name, value in candidates.items():
            if not value:
                continue
            previous = found.get(name)
            if previous and previous != value:
                _error(f"arms-disagree-on-identity:{name}:{previous}!={value}")
            found[name] = value
    return found


def _source_closure_hash(build: object) -> str:
    """The content hash of the build's recorded source closure, if it has one."""
    hashes = getattr(build, "source_hashes", None)
    if isinstance(hashes, Mapping) and hashes:
        return content_hash({str(key): str(value)
                             for key, value in sorted(hashes.items())})
    return ""


def fabric_source_lanes(plan: object) -> dict[str, list[dict[str, object]]]:
    """The plan's fabric source lanes, split into CPU-owned and everything else.

    The split is by the plan's own declared source kind (``cpu_*`` versus a
    synthetic master such as ``fuzz_mmio``), which is exactly the attribution the
    arbiter publishes per completion.  It is what makes "a BFM transaction is not
    CPU coverage" checkable on real lanes instead of on a naming convention: a
    composition with a synthetic master has two lanes, a CPU-only one has one.
    """
    fabric = getattr(plan, "plan", None)
    sources: object = ()
    if isinstance(fabric, Mapping):
        block = fabric.get("fabric")
        if isinstance(block, Mapping):
            sources = block.get("sources", ())
    lanes: dict[str, list[dict[str, object]]] = {"cpu": [], "other": []}
    for position, item in enumerate(_records(sources, "plan:fabric:sources")):
        record = _mapping(item, f"plan:fabric:sources:{position}")
        kind = str(record.get("kind", ""))
        entry = {
            "index": _integer(record.get("index", position),
                              f"plan:fabric:sources:{position}:index"),
            "source_id": str(record.get("source_id", "")),
            "kind": kind,
        }
        lanes["cpu" if kind.startswith("cpu") else "other"].append(entry)
    return lanes


def build_chain_report(*, plan, build, arms, corpus, evidence) -> dict[str, object]:
    """Summarise one shared corpus driven through every projection arm.

    ``plan`` and ``build`` are the composition and the runtime artifact being
    measured; ``arms`` maps arm name to the projector that produced each arm's
    projections (``build_projection_arms``' return value); ``corpus`` is the
    shared input set (``soc_comparison.build_seed_corpus``' return value).

    ``evidence`` carries what the runs recorded::

        {
          "outcomes": {arm: [outcome, ...]},   # required, one per corpus entry
          "replays":  {arm: [result, ...]},    # optional, aligned with outcomes
          "identity": {field: value, ...},     # optional identity defaults
          "execution_mode": "seeded-corpus-real-rtl",   # optional override
        }

    An outcome is one arm's record of one corpus entry with the fields
    ``index/arm/status/reason/raw/applied/projected/repairs/counters/
    cpu_requests/cpu_writes/peer_applied/coverage_bits/execution_mode`` (plus the
    five identity fields).  A replay entry is either a
    ``RunResult.document()`` or the applied-trace sequence itself; ``None`` marks
    an outcome whose replay was not recorded, and a *missing* ``replays`` key
    makes the whole replay section ``not_assessed``.

    Everything the document claims is cross-checked: the arms' recorded inputs
    must equal the shared corpus, their identity must agree with the projectors
    and with each other, and no BFM-mode outcome may claim a CPU request.
    """
    if not isinstance(arms, Mapping) or not arms:
        _error("arms-mapping-required")
    arm_order = [name for name in ARM_NAMES if name in arms] + \
        [str(name) for name in arms if str(name) not in ARM_NAMES]
    arm_names = [str(name) for name in arm_order]
    if len(set(arm_names)) != len(arm_names):
        _error("arm-names-not-unique")

    entries = _corpus_entries(corpus)
    shared = corpus_hash(corpus)
    evidence_map = _mapping(evidence, "evidence")
    outcomes_by_arm = _mapping(evidence_map.get("outcomes"), "evidence:outcomes")
    replays_value = evidence_map.get("replays")
    replays: dict[str, object] = {} if replays_value is None else dict(
        _mapping(replays_value, "evidence:replays"))

    identity: dict[str, object] = {}
    supplied = evidence_map.get("identity")
    if supplied is not None:
        identity.update({str(key): value
                         for key, value in _mapping(supplied, "evidence:identity").items()})
    derived = _arm_identity_from_projectors(arms)
    for name in ("layout_hash", "policy_hash", "image_hash"):
        if not identity.get(name) and derived.get(name):
            identity[name] = derived[name]
    if not identity.get("source_closure_hash"):
        computed = _source_closure_hash(build)
        if computed:
            identity["source_closure_hash"] = computed

    views_by_arm: dict[str, list[dict[str, object]]] = {}
    for arm in arm_names:
        if arm not in outcomes_by_arm:
            _error(f"arm-without-outcomes:{arm}")
        records = list(_records(outcomes_by_arm[arm], f"outcomes:{arm}"))
        views = [_outcome_view(arm, item, position, identity=identity,
                               require_identity=True)
                 for position, item in enumerate(records)]
        # Prove the arm received the shared input set: every corpus entry exactly
        # once, with exactly the words the corpus declares.
        recorded = {int(view["index"]): list(view["raw"]) for view in views}
        if len(recorded) != len(views):
            _error(f"arm-recorded-one-input-twice:{arm}")
        missing = sorted(set(entries) - set(recorded))
        extra = sorted(set(recorded) - set(entries))
        if missing:
            _error(f"arm-did-not-use-the-shared-corpus:{arm}:missing:{missing}")
        if extra:
            _error(f"arm-did-not-use-the-shared-corpus:{arm}:extra:{extra}")
        for index, raw in sorted(recorded.items()):
            if raw != entries[index]:
                _error(f"arm-did-not-use-the-shared-corpus:{arm}:raw:{index}")
        views_by_arm[arm] = views

    resolved: dict[str, str] = {}
    for arm in arm_names:
        for view in views_by_arm[arm]:
            for name in IDENTITY_FIELDS:
                value = str(view[name])
                previous = resolved.get(name)
                if previous is None:
                    resolved[name] = value
                elif previous != value:
                    _error(f"identity-conflict:{name}:{previous}!={value}")
    for name, value in derived.items():
        if name in resolved and resolved[name] != value:
            _error(f"identity-conflict-with-the-arm:{name}:"
                   f"{resolved[name]}!={value}")

    metrics = {arm: arm_metrics(arm, views_by_arm[arm]) for arm in arm_names}
    report: dict[str, object] = {
        "schema_version": REPORT_SCHEMA,
        "claim": CLAIM,
        "execution_mode": str(evidence_map.get("execution_mode")
                              or SEEDED_CORPUS_EXECUTION_MODE),
        "plan": {
            "plan_hash": str(getattr(plan, "plan_hash", "") or ""),
            "drive_profile": str(getattr(plan, "drive_profile", "") or ""),
            # The composition's own profile layout (its declared special inputs),
            # which is the prefix the constraint arm may project.  The raw ABI the
            # arms really consume is the combined layout below, and the two are
            # different widths on purpose.
            "profile_raw_width": int(
                (getattr(plan, "raw_layout", {}) or {}).get("raw_width", 0)),
        },
        "layout": {
            "layout_hash": resolved.get("layout_hash", ""),
            "raw_width": int(max((getattr(getattr(arms[arm], "layout", None),
                                          "raw_width", 0) or 0) for arm in arm_names)),
        },
        "build": {
            "build_hash": str(getattr(build, "build_hash", "") or ""),
            "raw_width": int(getattr(build, "raw_width", 0) or 0),
            "cpu_data_sources": [int(item)
                                 for item in getattr(build, "cpu_data_sources", ()) or ()],
            # The lanes the arbiter attributes a completion to: the CPU's own
            # lanes versus a synthetic master's.  CPU coverage is read from the
            # CPU lanes only, whatever the execution mode claims.
            "fabric_sources": fabric_source_lanes(plan),
            "source_closure_hash": resolved.get("source_closure_hash", ""),
        },
        "identity": {name: resolved.get(name, "") for name in IDENTITY_FIELDS},
        "executable_sha256": resolved.get("executable_sha256", ""),
        "shared_corpus_hash": shared,
        "corpus": {
            "entries": len(entries),
            "words": sum(len(raw) for raw in entries.values()),
            "hash": shared,
            "kinds": _count([str(_mapping(item, "corpus").get("kind", ""))
                             for item in _records(corpus, "corpus")]),
            "arms": {arm: shared for arm in arm_names},
        },
        "request_accounting": {
            "cpu_request_count": sum(int(metrics[arm]["cpu_request_count"])
                                     for arm in arm_names),
            "bfm_request_count": sum(int(metrics[arm]["bfm_request_count"])
                                     for arm in arm_names),
            "cpu_execution_modes": list(CPU_EXECUTION_MODES),
            "bfm_execution_modes": list(BFM_EXECUTION_MODES),
            "counted_separately": True,
            "note": ("BFM/arbitrated transactions are never added to the CPU count and "
                     "never counted as CPU coverage; the two numbers have no sum in "
                     "this document"),
        },
        "coverage": {
            "cpu": {
                "request_count": sum(int(metrics[arm]["cpu_coverage"]["request_count"])
                                     for arm in arm_names),
                "write_count": sum(int(metrics[arm]["cpu_coverage"]["write_count"])
                                   for arm in arm_names),
                "outcomes_with_requests": sum(
                    int(metrics[arm]["cpu_coverage"]["outcomes_with_requests"])
                    for arm in arm_names),
                "touched_address_count": len({
                    address
                    for arm in arm_names
                    for address in metrics[arm]["cpu_coverage"]["touched_addresses"]}),
            },
            "bfm": {
                "request_count": sum(int(metrics[arm]["bfm_coverage"]["request_count"])
                                     for arm in arm_names),
                "outcomes": sum(int(metrics[arm]["bfm_coverage"]["outcomes"])
                                for arm in arm_names),
                "counted_as_cpu_coverage": False,
            },
            "peer": {
                "applied_events": sum(
                    int(metrics[arm]["peer_coverage"]["applied_events"])
                    for arm in arm_names),
                "outcomes_with_applied_events": sum(
                    int(metrics[arm]["peer_coverage"]["outcomes_with_applied_events"])
                    for arm in arm_names),
            },
            "image": {
                "placements": sum(int(metrics[arm]["image_placements"]["placements"])
                                  for arm in arm_names),
                "readbacks_nonzero": sum(
                    int(metrics[arm]["image_placements"]["readbacks_nonzero"])
                    for arm in arm_names),
                "errors": sum(int(metrics[arm]["image_placements"]["errors"])
                              for arm in arm_names),
            },
        },
        "arms": metrics,
        "outcomes": {arm: views_by_arm[arm] for arm in arm_names},
        "replay": _replay_section(
            views_by_arm, replays,
            {arm: getattr(arms[arm], "layout", None) for arm in arm_names}),
        "gaps": sorted({gap for arm in arm_names for gap in metrics[arm]["gaps"]}),
    }
    document = dict(report)
    document["content_hash"] = content_hash(document)
    return document
