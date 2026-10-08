"""Recomputable cross-case chain evidence over saved runtime traces.

P3 requires that ``CPU -> IP -> CPU`` and ``IP -> CPU -> IP`` complete *across
cases*. :class:`myfuzz.scenario.chain_certificates.ChainCertificates` already
settles one certificate per admitted source and records, on every certificate,
the exact ``source_case_index`` and ``endpoint_case_index`` its joined hops
prove. This module turns that frozen producer into a dedicated, bounded report
that answers four questions from one streaming pass over a saved artifact:

* how many certified chains of each direction actually crossed a case boundary
  (``cross_case_count``) and how many stayed inside one case
  (``same_case_count``);
* how far each certified cross-case chain reached (``case_gap =
  endpoint_case_index - source_case_index``, with the per-direction ``p50`` /
  ``max`` / ``min`` distribution);
* through which exact hops it got there (the ordered ``hop_id`` + ``event_id``
  list, the terminal hop and ``completed_event_id``);
* which declared direction still has *no* cross-case evidence, together with
  that direction's certified same-case count and the first gap reported by its
  ``incomplete`` certificates (``missing_hops[0]``).

Input is the saved terminal trace only: the report streams
:class:`myfuzz.scenario.acceptance_metrics.TraceEventStream` in batches into the
frozen producer, so a 600 s run is recomputed without ever materialising the
event stream. Certificates that are not ``certified`` contribute only to the
per-direction ``incomplete_count`` / first-gap histogram; every detail row in
``chains`` is one ``certified`` certificate.

Fail-closed rules (never a silent skip):

* every certificate is validated by
  :func:`myfuzz.scenario.closed_loop_feedback.certificate_hit`, the same
  contract consumer the closed-loop feedback uses: schema version, direction,
  ``certificate_id`` recomputation, case identities, hop membership, declared
  hop order and strictly increasing hop event ids. Any deviation raises
  :class:`ValueError` for the whole report.
* a certificate that declares its own ``cross_case`` field must agree with the
  comparison of its ``(source_case_id, source_case_index)`` and
  ``(endpoint_case_id, endpoint_case_index)`` pairs; a contradiction raises
  :class:`ValueError`.
* a ``certified`` certificate must carry every declared hop of its direction
  except the producer's optional ones (the two weak hops per direction and the
  ``cpu_irq_serial_token`` witness); a certificate that omits a mandatory hop
  while declaring no ``missing_hops`` raises :class:`ValueError` instead of
  being reported as a shorter chain.
* a certified certificate whose endpoint case index precedes its source case
  index contradicts the monotone case contract the producer enforces, so it
  raises :class:`ValueError` instead of reporting a negative gap.
* a duplicated ``certificate_id`` with identical evidence is deduplicated and
  counted; the same id with different evidence raises :class:`ValueError`.

Boundedness: ``max_gap_cases`` keeps the detail row of every certified chain
whose ``case_gap`` is at most the bound (and of every chain whose endpoint case
is unresolved, which has no comparable gap). A certified cross-case chain
beyond the bound is still counted in ``cross_case_count``, the per-direction
counts and ``max_case_gap_seen``, but contributes no detail row;
``truncated`` / ``truncated_certificate_count`` say so explicitly. The
per-direction ``case_gap`` distribution is therefore computed over retained
cross-case chains only -- its ``scope`` and ``excluded_truncated_count`` name
that restriction, and it is exactly the full distribution whenever
``truncated`` is ``false``. ``p50`` (upper median of the sorted retained gaps)
and ``max`` are ``null`` when there is no sample.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
import hashlib
from pathlib import Path
import sys

from .acceptance_metrics import TraceEventStream
from .chain_certificates import (
    CPU_IRQ_SERIAL_HOP,
    CPU_TO_IP_TO_CPU,
    IP_TO_CPU_TO_IP,
    SCHEMA_VERSION as CERTIFICATE_SCHEMA_VERSION,
    ChainCertificates,
    declared_hop_sequence,
)
# The frozen producer declares two hops per direction as weak (they are skipped
# when it is built with ``require_native_receipts=False``), plus the optional
# ``cpu_irq_serial_token`` witness. Every other declared hop is mandatory, so a
# ``certified`` certificate that omits one contradicts the producer contract
# and is refused instead of being reported as a shorter chain.
from .chain_certificates import _CPU_WEAK_HOPS, _IP_WEAK_HOPS
from .closed_loop_feedback import CERTIFIED, certificate_hit


REPORT_SCHEMA_VERSION = "cross_case_chain_report.v1"
DIRECTIONS = (IP_TO_CPU_TO_IP, CPU_TO_IP_TO_CPU)
GAP_STATS_SCOPE = "retained_cross_case_chains"
DEFAULT_INGEST_BATCH_SIZE = 4096
DEFAULT_MAX_PENDING = 128
DEFAULT_MAX_EVENT_GAP = 4096
_OPTIONAL_HOPS = {
    IP_TO_CPU_TO_IP: frozenset(_IP_WEAK_HOPS | {CPU_IRQ_SERIAL_HOP}),
    CPU_TO_IP_TO_CPU: frozenset(_CPU_WEAK_HOPS),
}


def _nonnegative_integer(value: object) -> bool:
    return type(value) is int and value >= 0


def _positive_integer(value: object) -> bool:
    return type(value) is int and value > 0


def producer_identity() -> dict:
    """Identify the certificate producer bytes this report recomputes."""
    module = sys.modules.get("myfuzz.scenario.chain_certificates")
    path = Path(getattr(module, "__file__", "") or "")
    identity = {"module": "myfuzz.scenario.chain_certificates",
                "path": str(path), "sha256": None}
    try:
        identity["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:  # pragma: no cover - only when the source moved away
        pass
    return identity


def cross_case_chain_row(certificate: Mapping) -> dict:
    """Validate one certified certificate and reduce it to one report row.

    Raises :class:`ValueError` for every deviation from the frozen
    ``runtime_chain_certificate.v1`` contract, for a certificate that is not
    ``certified``, for a declared ``cross_case`` flag that contradicts the case
    index pair, and for an endpoint case index that precedes the source case
    index. A malformed certificate is never silently dropped.
    """
    return _row_from_hit(certificate_hit(certificate), certificate)


def _row_from_hit(hit: Mapping, certificate: Mapping) -> dict:
    """Reduce one already validated certificate to one report row."""
    if hit["status"] != CERTIFIED:
        raise ValueError(
            "cross-case chain rows require a certified certificate, got "
            f"status {hit['status']!r}")
    observed = {hop["hop_id"] for hop in hit["hops"]}
    optional = _OPTIONAL_HOPS[hit["direction"]]
    omitted = [hop_id for hop_id in declared_hop_sequence(hit["direction"])
               if hop_id not in observed and hop_id not in optional]
    if omitted:
        raise ValueError(
            f"certified chain certificate {hit['certificate_id']} omits "
            f"mandatory hop(s) {omitted} and declares no missing_hops")
    cross_case = hit["cross_case"]
    if "cross_case" in certificate:
        declared = certificate["cross_case"]
        if type(declared) is not bool or declared != cross_case:
            raise ValueError(
                f"chain certificate {hit['certificate_id']} declares "
                f"cross_case={declared!r}, but its case indexes "
                f"({hit['source_case_id']!r}, {hit['source_case_index']}) -> "
                f"({hit['endpoint_case_id']!r}, {hit['endpoint_case_index']}) "
                f"imply {cross_case!r}")
    case_gap = None
    if cross_case is not None:
        endpoint_index = hit["endpoint_case_index"]
        if endpoint_index < hit["source_case_index"]:
            raise ValueError(
                f"chain certificate {hit['certificate_id']} ends in case index "
                f"{endpoint_index}, before its source case index "
                f"{hit['source_case_index']}; the producer's case contract is "
                "monotone, so this certificate contradicts itself")
        case_gap = endpoint_index - hit["source_case_index"]
    return {
        "certificate_id": hit["certificate_id"],
        "direction": hit["direction"],
        "status": hit["status"],
        "cross_case": cross_case,
        "case_gap": case_gap,
        "source_admission_id": hit["source_admission_id"],
        "source_id": hit["source_id"],
        "source_component": hit["source_component"],
        "source_case_id": hit["source_case_id"],
        "source_case_index": hit["source_case_index"],
        "endpoint_case_id": hit["endpoint_case_id"],
        "endpoint_case_index": hit["endpoint_case_index"],
        "hop_count": hit["hop_count"],
        "hops": [dict(hop) for hop in hit["hops"]],
        "terminal_hop": dict(hit["hops"][-1]),
        "declared_terminal_hop": hit["declared_terminal_hop"],
        "reached_terminal_hop": hit["reached_terminal_hop"],
        "completed_event_id": hit["completed_event_id"],
        "serial_token_status": hit["serial_token_status"],
    }


def _row_order(row: Mapping) -> tuple:
    endpoint = row["endpoint_case_index"]
    return (row["direction"], row["source_case_index"],
            -1 if endpoint is None else endpoint, row["certificate_id"])


def _dominant_first_gap(direction: str, counts: Mapping[str, int]) -> str | None:
    """Most reported first gap, ties broken by the declared hop order."""
    if not counts:
        return None
    sequence = declared_hop_sequence(direction)
    return min(sorted(counts),
               key=lambda hop: (-counts[hop], sequence.index(hop)))


class CrossCaseChainCollector:
    """Accumulate per-direction cross-case evidence from certificate batches.

    One certified admission is counted once: a re-ingested identical
    ``certificate_id`` is a no-op and is counted in
    ``duplicate_certificate_count``, while the same id carrying different
    evidence raises :class:`ValueError`. Only rows inside ``max_gap_cases``
    (see the module docstring) are retained; every certificate still
    contributes to the counts.
    """

    def __init__(self, *, max_gap_cases: int | None = None) -> None:
        if max_gap_cases is not None and not _nonnegative_integer(max_gap_cases):
            raise ValueError("max_gap_cases must be None or a nonnegative "
                             "integer")
        self.max_gap_cases = max_gap_cases
        self._rows: list[dict] = []
        self._seen: dict[str, dict] = {}
        self._by_direction: dict[str, dict] = {
            direction: {"certified_count": 0, "incomplete_count": 0,
                        "cross_case_count": 0, "same_case_count": 0,
                        "unresolved_case_count": 0,
                        "cross_case_retained_count": 0,
                        "cross_case_truncated_count": 0,
                        "gaps": [],
                        "first_missing_hops": Counter()}
            for direction in DIRECTIONS}
        self.incomplete_count = 0
        self.duplicate_certificate_count = 0
        self.truncated_certificate_count = 0
        self.max_case_gap_seen: int | None = None
        self.limits: list[dict] = []

    # ------------------------------------------------------------------ ingest

    def ingest(self, certificates: Iterable[Mapping]) -> tuple[dict, ...]:
        """Record one validated batch; return the rows it retained, in order."""
        rows = []
        for certificate in certificates:
            hit = certificate_hit(certificate)
            direction = hit["direction"]
            state = self._by_direction[direction]
            if hit["status"] != CERTIFIED:
                self.incomplete_count += 1
                state["incomplete_count"] += 1
                first_gap = hit["first_missing_hop"]
                if first_gap is not None:
                    state["first_missing_hops"][first_gap] += 1
                continue
            previous = self._seen.get(hit["certificate_id"])
            if previous is not None:
                self.duplicate_certificate_count += 1
                if previous != hit:
                    raise ValueError(
                        f"chain certificate {hit['certificate_id']} was "
                        "reused with different evidence")
                continue
            self._seen[hit["certificate_id"]] = hit
            row = _row_from_hit(hit, certificate)
            state["certified_count"] += 1
            if row["cross_case"] is None:
                state["unresolved_case_count"] += 1
            elif row["cross_case"]:
                state["cross_case_count"] += 1
                if (self.max_case_gap_seen is None
                        or row["case_gap"] > self.max_case_gap_seen):
                    self.max_case_gap_seen = row["case_gap"]
            else:
                state["same_case_count"] += 1
            if (row["case_gap"] is not None and self.max_gap_cases is not None
                    and row["case_gap"] > self.max_gap_cases):
                self.truncated_certificate_count += 1
                state["cross_case_truncated_count"] += 1
                continue
            if row["cross_case"]:
                state["cross_case_retained_count"] += 1
                state["gaps"].append(row["case_gap"])
            self._rows.append(row)
            rows.append(row)
        return tuple(rows)

    # ----------------------------------------------------------------- summary

    @property
    def certified_count(self) -> int:
        return len(self._seen)

    @property
    def cross_case_count(self) -> int:
        return sum(state["cross_case_count"]
                   for state in self._by_direction.values())

    @property
    def same_case_count(self) -> int:
        return sum(state["same_case_count"]
                   for state in self._by_direction.values())

    @property
    def unresolved_case_count(self) -> int:
        return sum(state["unresolved_case_count"]
                   for state in self._by_direction.values())

    @property
    def truncated(self) -> bool:
        return self.truncated_certificate_count > 0

    def chains(self) -> list[dict]:
        """Every retained certified chain, in a deterministic order."""
        return [dict(row) for row in sorted(self._rows, key=_row_order)]

    def _direction_summary(self, direction: str) -> dict:
        state = self._by_direction[direction]
        gaps = sorted(state["gaps"])
        retained = [row for row in sorted(self._rows, key=_row_order)
                    if row["direction"] == direction and row["cross_case"]]
        representative = None
        if retained:
            representative = dict(max(
                retained, key=lambda row: (row["case_gap"],
                                           -row["source_case_index"])))
        first_missing = dict(sorted(state["first_missing_hops"].items()))
        return {
            "certified_count": state["certified_count"],
            "incomplete_count": state["incomplete_count"],
            "cross_case_count": state["cross_case_count"],
            "same_case_count": state["same_case_count"],
            "unresolved_case_count": state["unresolved_case_count"],
            "has_cross_case": state["cross_case_count"] > 0,
            "cross_case_retained_count": state["cross_case_retained_count"],
            "cross_case_truncated_count": state["cross_case_truncated_count"],
            "case_gap": {
                "scope": GAP_STATS_SCOPE,
                "sample_count": len(gaps),
                "excluded_truncated_count": state["cross_case_truncated_count"],
                "p50": gaps[len(gaps) // 2] if gaps else None,
                "max": gaps[-1] if gaps else None,
                "min": gaps[0] if gaps else None,
            },
            "first_missing_hop": _dominant_first_gap(
                direction, state["first_missing_hops"]),
            "first_missing_hops": first_missing,
            "representative_cross_case_chain": representative,
        }

    def summary(self, **identity: object) -> dict:
        """Complete report document, independent of certificate arrival order."""
        by_direction = {direction: self._direction_summary(direction)
                        for direction in DIRECTIONS}
        without = [direction for direction in DIRECTIONS
                   if not by_direction[direction]["has_cross_case"]]
        limits = [dict(limit) for limit in self.limits]
        if self.unresolved_case_count:
            limits.append({
                "quantity": "cross_case_chains.case_gap",
                "reason": f"{self.unresolved_case_count} certified "
                          "certificate(s) carry no endpoint case index, so no "
                          "case gap could be computed for them"})
        if self.truncated:
            limits.append({
                "quantity": "cross_case_chains.chains",
                "reason": f"max_gap_cases={self.max_gap_cases} truncated "
                          f"{self.truncated_certificate_count} certified "
                          "cross-case chain(s); they are counted but their hop "
                          "details and gap samples are not retained"})
        return {
            "schema_version": REPORT_SCHEMA_VERSION,
            "certificate_schema_version": CERTIFICATE_SCHEMA_VERSION,
            "max_gap_cases": self.max_gap_cases,
            "certified_count": self.certified_count,
            "incomplete_count": self.incomplete_count,
            "cross_case_count": self.cross_case_count,
            "same_case_count": self.same_case_count,
            "unresolved_case_count": self.unresolved_case_count,
            "duplicate_certificate_count": self.duplicate_certificate_count,
            "retained_certificate_count": len(self._rows),
            "truncated": self.truncated,
            "truncated_certificate_count": self.truncated_certificate_count,
            "max_case_gap_seen": self.max_case_gap_seen,
            "gap_stats_scope": GAP_STATS_SCOPE,
            "all_directions_have_cross_case": not without,
            "directions_without_cross_case": without,
            "chains": self.chains(),
            "by_direction": by_direction,
            "limits": limits,
            **identity,
        }


def _resolve_producer(chain_producer: object, *, max_pending: int,
                      max_event_gap: int, require_native_receipts: bool):
    """Instantiate the frozen producer or the caller's injected one."""
    if chain_producer is None:
        return ChainCertificates(max_pending=max_pending,
                                 max_event_gap=max_event_gap,
                                 require_native_receipts=require_native_receipts)
    if isinstance(chain_producer, type) or not hasattr(chain_producer, "ingest"):
        return chain_producer(max_pending=max_pending,
                              max_event_gap=max_event_gap,
                              require_native_receipts=require_native_receipts)
    return chain_producer


def cross_case_chain_report(
        run_dir: str | Path, *,
        max_gap_cases: int | None = None,
        chain_producer: object = None,
        max_pending: int = DEFAULT_MAX_PENDING,
        max_event_gap: int = DEFAULT_MAX_EVENT_GAP,
        require_native_receipts: bool = True,
        ingest_batch_size: int = DEFAULT_INGEST_BATCH_SIZE,
        verify_semantic: bool = True) -> dict:
    """Stream one saved run into a bounded cross-case chain report.

    ``max_gap_cases`` bounds which certified cross-case chains keep a detail
    row (see the module docstring). ``chain_producer`` injects a certificate
    producer for analysis and tests; by default the frozen
    :class:`~myfuzz.scenario.chain_certificates.ChainCertificates` is used with
    the same ``max_pending`` / ``max_event_gap`` defaults as
    :func:`myfuzz.scenario.acceptance_metrics.analyze_run`, so the recomputed
    counts are comparable with the frozen acceptance gate.

    Raises :class:`ValueError` (including
    :class:`myfuzz.scenario.acceptance_metrics.TraceUnavailable`) when the run
    holds no streamable trace, and for every certificate that deviates from the
    frozen contract; a malformed certificate is never silently skipped.
    """
    if not _positive_integer(max_pending):
        raise ValueError("max_pending must be a positive integer")
    if not _positive_integer(max_event_gap):
        raise ValueError("max_event_gap must be a positive integer")
    if not _positive_integer(ingest_batch_size):
        raise ValueError("ingest_batch_size must be a positive integer")
    if type(verify_semantic) is not bool:
        raise ValueError("verify_semantic must be boolean")
    if max_gap_cases is not None and not _nonnegative_integer(max_gap_cases):
        raise ValueError("max_gap_cases must be None or a nonnegative integer")

    collector = CrossCaseChainCollector(max_gap_cases=max_gap_cases)
    producer = _resolve_producer(chain_producer, max_pending=max_pending,
                                 max_event_gap=max_event_gap,
                                 require_native_receipts=require_native_receipts)
    stream = TraceEventStream(run_dir, verify_semantic=verify_semantic)

    events_ingested = 0
    batch: list[dict] = []
    for event in stream.events():
        events_ingested += 1
        batch.append(event)
        if len(batch) >= ingest_batch_size:
            collector.ingest(producer.ingest(tuple(batch)))
            batch.clear()
    if batch:
        collector.ingest(producer.ingest(tuple(batch)))
    flush = getattr(producer, "flush", None)
    if callable(flush):
        collector.ingest(flush())
    pending_after_flush = getattr(producer, "pending_count", None)
    if type(pending_after_flush) is not int:
        pending_after_flush = None

    descriptor = stream.descriptor
    return collector.summary(
        run_dir=str(Path(run_dir)),
        producer=producer_identity(),
        trace={
            "format": descriptor["format"],
            "events_file": descriptor["events_file"],
            "path": descriptor["path"],
            "bytes": descriptor["bytes"],
            "meta_schema_version": descriptor["meta_schema_version"],
            "declared_event_count": descriptor["declared_event_count"],
            "declared_status": stream.declared_status(),
            "declared_semantic_sha256": stream.declared_semantic_sha256(),
            "semantic_sha256": stream.semantic_sha256(),
            "semantic_sha256_verified": stream.semantic_sha256_verified(),
        },
        events_ingested=events_ingested,
        ingest_batch_size=ingest_batch_size,
        producer_bounds={"max_pending": max_pending,
                         "max_event_gap": max_event_gap,
                         "require_native_receipts": require_native_receipts},
        producer_pending_after_flush=pending_after_flush,
    )


__all__ = ["CERTIFIED", "CrossCaseChainCollector", "DIRECTIONS",
           "GAP_STATS_SCOPE", "REPORT_SCHEMA_VERSION",
           "cross_case_chain_report", "cross_case_chain_row", "producer_identity"]
