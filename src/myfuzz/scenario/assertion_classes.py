"""P5 assertion classes: one saved run judged per checker, per class.

The frozen P5 checklist item asks for three things at once: report problems
*separately* through the protocol checker, through the cross-component
provenance/order invariants and through CPU/IP behaviour assertions; keep the
generation constraints apart from the check expectations; and never let an
abnormal real output disappear because a declared path was not ready
("用协议检查器、跨组件来源/顺序不变量及 CPU/IP 行为断言分别报告问题；生成约束
和检查期望分开，异常真实输出不能因路径未就绪被过滤").

This module answers that from ONE saved run directory, read-only, in ONE
document under ``p5_assertion_classes.v1``. It executes no RTL, renders no
harness, starts no process and re-implements no existing consumer:

``protocol_checker``
    the run's own checker findings. The saved ``receipts.jsonl`` is the
    checker's output stream: one receipt per admitted case, whose
    ``violations`` list holds the violation strings the run's checker returned
    for that case's real RTL events. The checker identity (module, qualname,
    source path and sha256) comes from the saved session manifest, and the
    receipt file's own sha256 is reported, so a finding can be tied to the
    exact checker bytes that produced it.

``cross_component_provenance_and_order``
    the shipped ``runtime_edge_provenance.v1`` /
    ``runtime_edge_provenance_report.v1`` analysis
    (:class:`myfuzz.scenario.edge_provenance.EdgeProvenanceConsumer`) of the
    run's declared runtime edges, plus the shipped
    ``runtime_chain_certificate.v1`` producer
    (:class:`myfuzz.scenario.chain_certificates.ChainCertificates`). Every
    declared edge is listed with its status (``certified`` / ``incomplete`` /
    ``unknown``), its ordered hop ids and hop event ids, its exact ``missing``
    hops and the consumer's ``reason``; every non-certified chain certificate
    is listed with its ``missing_hops``, first gap and reason. A declared hop
    whose ``(rule_index, prerequisite_index)`` the compiled runtime path
    contract does not declare is reported as ``not_a_runtime_edge`` -- never
    counted as certified, never silently skipped.

``cpu_ip_behaviour``
    the CPU/IP behaviour records the run's trace really contains: retirement
    records and their ``cpu_retirement_match`` verdicts, the native IRQ
    observation/acceptance/expiry records and the consumption joins. Only
    records that exist are counted; a class whose artifact holds no such record
    reports ``null`` **with a precise reason**, never ``0``, while a class that
    was measured over records it really has reports an honest ``0``.

Declaration versus expectation
    ``declaration_constraints`` states what the run was *generated* to do
    (decoder manifest, compiled runtime path contract and its declared paths /
    runtime edges, declared targets, run identity, plan) and
    ``check_expectations`` states what the *checkers assert*, one expectation
    per assertion class and record class. Every finding names the assertion
    class and the expectation id it came from, and the two sections never share
    a key.

Fail-closed "not silently filtered"
    Every abnormal record found in the run is enumerated in
    ``not_silently_filtered`` with its own exact evidence keys: declared hops
    that are ``not_a_runtime_edge``, runtime edges that are ``incomplete`` or
    ``unknown`` (with their ``missing`` hops and reason), incomplete chain
    certificates (with their ``missing_hops``), cases refused before any RTL
    command, and every CPU/IP abnormal record. A record that no assertion class
    can represent -- an unknown receipt disposition, a status outside the
    shipped vocabulary, a finding status with no violation string -- is
    reported as ``unclassified_abnormal_record`` and makes the gate FAIL with
    that record's exact key, because the report cannot claim the run was fully
    represented. Truncating findings (``max_findings_per_class``) is fail-closed
    in the same way.

The representation claim is verified *structurally*: after the document is
assembled, every census record id is looked up in the class findings and
fail-closed buckets the document actually carries. A renderer that drops a row
fails the gate with the dropped record id and its expected location, so the
gate cannot pass on a bookkeeping counter that disagrees with the document.

Determinism: no timestamps, no wall-clock data and no iteration-order-dependent
lists. Two runs of the CLI over the same run directory produce byte-identical
JSON.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path

from .acceptance_metrics import (
    CLASSIFIED_STATUSES,
    COMPLETE_STATUSES,
    FINDING_STATUSES,
    INVALID_STATUSES,
    TIMEOUT_STATUSES,
    TraceEventStream,
)
from .chain_certificates import (
    SCHEMA_VERSION as CHAIN_CERTIFICATE_SCHEMA_VERSION,
    ChainCertificates,
)
from .edge_provenance import (
    CERTIFIED,
    INCOMPLETE,
    UNKNOWN,
    EdgeProvenanceConsumer,
    edge_endpoints_from_compiled,
    edge_provenance_session,
)
from .runtime_path_contract import RuntimePathContract


SCHEMA_VERSION = "p5_assertion_classes.v1"

CLASS_PROTOCOL_CHECKER = "protocol_checker"
CLASS_CROSS_COMPONENT = "cross_component_provenance_and_order"
CLASS_CPU_IP = "cpu_ip_behaviour"
ASSERTION_CLASSES = (CLASS_PROTOCOL_CHECKER, CLASS_CROSS_COMPONENT, CLASS_CPU_IP)

#: A declared hop the compiled runtime contract gives no observable relation.
NOT_A_RUNTIME_EDGE = "not_a_runtime_edge"

#: Receipt dispositions the online runner writes; anything else cannot be
#: attributed to an assertion class and fails the gate instead of vanishing.
KNOWN_DISPOSITIONS = frozenset(("admitted", "rejected", "uncertain"))
#: Status values the real online writer emits on top of the shipped
#: ``acceptance_metrics`` classification. ``input_invalid`` is written by
#: ``myfuzz.integration.scenario_rfuzz`` for a candidate the framework refused
#: before any RTL command, while the shipped ``INVALID_STATUSES`` set spells the
#: same condition ``invalid_input``; the divergence is reported as a limit
#: instead of being silently normalised away.
PRODUCTION_STATUSES = frozenset(("input_invalid", "uncertain_effect",
                                 "environment_error", "unsupported_irq_overrun",
                                 "running"))
#: Receipt statuses this report classifies. ``dut_violation``/``finding``/
#: ``assertion_failure`` carry the checker's violation strings.
KNOWN_STATUSES = frozenset(
    COMPLETE_STATUSES | INVALID_STATUSES | TIMEOUT_STATUSES | FINDING_STATUSES
    | PRODUCTION_STATUSES)
ENVIRONMENT_STATUSES = frozenset(("environment_error", "unsupported_irq_overrun"))
REFUSED_STATUSES = frozenset(INVALID_STATUSES | TIMEOUT_STATUSES
                             | {"input_invalid"})

#: Retirement verdicts of the shipped ``cpu_retirement_match.v1`` producer.
RETIREMENT_ACCEPTED = "accepted"
RETIREMENT_REJECTED = "rejected"
RETIREMENT_AMBIGUOUS = "ambiguous"
RETIREMENT_ORIGIN_TYPED = "typed_writer_refs"

#: Native IRQ observation records written by the real GPIO/IP probes, and the
#: CPU-side records that accept an IRQ line (same vocabulary as the frozen
#: ``p2_acceptance`` early-IRQ rule).
NATIVE_IRQ_OBSERVATION_KINDS = frozenset(("gpio_irq_trigger", "gpio_irq_observation"))
NATIVE_IRQ_OBSERVATION_SUFFIXES = ("_native_irq_trigger", "_native_irq_high")
CPU_IRQ_ACCEPTANCE_KINDS = frozenset(("cpu_irq_taken", "cpu_external_irq_taken"))

#: Record kinds of the CPU/IP behaviour class and the bucket each is counted in.
CPU_IP_RECORD_KINDS = {
    "cpu_retire": "retirement",
    "cpu_retirement_match": "retirement_match",
    "cpu_external_irq_sample": "irq_sample",
    "cpu_irq_taken": "irq_acceptance",
    "cpu_external_irq_taken": "irq_acceptance",
    "cpu_irq_input": "irq_input",
    "expired_masked": "irq_expiry",
    "pulse_expired": "irq_expiry",
    "gpio_irq_trigger": "native_irq_observation",
    "gpio_irq_observation": "native_irq_observation",
    "gpio_consumption_match": "consumption_match",
    "cpu_retired_transaction_target_delivery": "consumption_match",
}

DEFAULT_CHAIN_MAX_PENDING = 128
DEFAULT_CHAIN_MAX_EVENT_GAP = 4096
DEFAULT_EDGE_MAX_PENDING = 4096
DEFAULT_EDGE_MAX_EVENT_GAP = 65536
DEFAULT_INGEST_BATCH_SIZE = 2048

TRACE_ARTIFACTS = ("online_final_trace.meta.json", "online_events.jsonl",
                   "online_events.zlib", "online_final_trace.json")

_LOCATION_CLASS = "assertion_class"
_LOCATION_BUCKET = "not_silently_filtered"
UNREPRESENTED = "unrepresented"

#: record class -> assertion class. A record whose class is absent here cannot
#: be represented and therefore fails the gate.
_RECORD_CLASS = {
    "protocol_violation": CLASS_PROTOCOL_CHECKER,
    "not_a_runtime_edge": CLASS_CROSS_COMPONENT,
    "runtime_edge_incomplete": CLASS_CROSS_COMPONENT,
    "runtime_edge_unknown": CLASS_CROSS_COMPONENT,
    "edge_provenance_rejection": CLASS_CROSS_COMPONENT,
    "chain_certificate_incomplete": CLASS_CROSS_COMPONENT,
    "retirement_observation_refused": CLASS_CPU_IP,
    "retirement_observation_ambiguous": CLASS_CPU_IP,
    "retirement_origin_untyped": CLASS_CPU_IP,
    "irq_observed_without_cpu_acceptance": CLASS_CPU_IP,
    "irq_expired_without_cpu_acceptance": CLASS_CPU_IP,
    "irq_input_expectation_mismatch": CLASS_CPU_IP,
    "irq_input_expectation_unmeasurable": CLASS_CPU_IP,
    "consumption_assertion_incomplete": CLASS_CPU_IP,
}
#: record class -> fail-closed bucket for records outside the three classes.
_FAIL_CLOSED_BUCKET = {
    "case_refused_before_rtl": "cases_refused_before_rtl",
    "case_uncertain": "cases_uncertain",
    "case_unfinished": "cases_unfinished",
    "case_environment_error": "case_environment_errors",
    "case_error": "case_errors",
    "case_wall_cut": "case_wall_cuts",
}
FAIL_CLOSED_BUCKETS = ("cases_refused_before_rtl", "cases_uncertain",
                       "cases_unfinished", "case_environment_errors",
                       "case_errors", "case_wall_cuts")

_NOT_SILENTLY_FILTERED_CRITERION = (
    "every abnormal record this run really holds -- a declared hop whose edge "
    "identity the compiled runtime contract does not declare, a runtime edge "
    "or chain certificate that is incomplete or unknown, a case refused before "
    "any RTL command, a checker violation, and every abnormal CPU/IP behaviour "
    "record -- is enumerated in this document with its own exact evidence "
    "keys; a record that no assertion class can represent fails the gate "
    "instead of being dropped because its path or edge was not ready")

#: What each checker asserts, one entry per record class it can produce.
EXPECTATIONS = (
    {
        "expectation_id": "protocol_checker.receipt_violations",
        "assertion_class": CLASS_PROTOCOL_CHECKER,
        "declared_by": "session_runtime online receipt contract: "
                       "receipts.jsonl[].violations",
        "asserts": "a receipt carries a violation string exactly when the "
                   "run's own checker returned it for that case's real RTL "
                   "events; a non-empty violations list forces the case status "
                   "to 'finding' and is never rewritten into a complete case",
    },
    {
        "expectation_id": "cross_component.declared_edge_hops",
        "assertion_class": CLASS_CROSS_COMPONENT,
        "declared_by": "myfuzz.scenario.edge_provenance:"
                       "runtime_edge_provenance_report.v1",
        "asserts": "a declared runtime edge is certified only by the exact "
                   "identity joins of its producer/delivery/consumer hops; a "
                   "partially observed edge stays incomplete with the missing "
                   "hop named, and an edge with no observable shape stays "
                   "unknown with its reason",
    },
    {
        "expectation_id": "cross_component.chain_certificate_hops",
        "assertion_class": CLASS_CROSS_COMPONENT,
        "declared_by": "myfuzz.scenario.chain_certificates:"
                       "runtime_chain_certificate.v1",
        "asserts": "an end-to-end chain is certified only when every declared "
                   "hop of its direction is joined by exact identity; "
                   "otherwise it settles incomplete with missing_hops naming "
                   "the first gap and every required hop after it",
    },
    {
        "expectation_id": "cpu_ip.retirement_observation_supported",
        "assertion_class": CLASS_CPU_IP,
        "declared_by": "myfuzz.scenario.cpu_retirement:"
                       "cpu_retirement_match.v1.status",
        "asserts": "a retired instruction the observation contract cannot "
                   "decode is recorded as status=rejected with its reason "
                   "instead of being dropped from the artifact",
    },
    {
        "expectation_id": "cpu_ip.retirement_instruction_origin",
        "assertion_class": CLASS_CPU_IP,
        "declared_by": "myfuzz.scenario.chain_certificates: "
                       "instruction_origin_status == 'typed_writer_refs'",
        "asserts": "a retirement is usable as an instruction-source hop only "
                   "when its instruction bytes are typed back to writer refs "
                   "(instruction_origin_status=typed_writer_refs)",
    },
    {
        "expectation_id": "cpu_ip.irq_input_expectation",
        "assertion_class": CLASS_CPU_IP,
        "declared_by": "cpu_external_irq_sample.expected_input vs "
                       "actual_post_input",
        "asserts": "the CPU external IRQ input observed after the step equals "
                   "the input the case was generated with",
    },
    {
        "expectation_id": "cpu_ip.irq_acceptance",
        "assertion_class": CLASS_CPU_IP,
        "declared_by": "cpu_irq_taken / cpu_external_irq_taken source identity",
        "asserts": "an IP IRQ observation whose exact source identity "
                   "(trigger_id, or source_event_id) no CPU acceptance record "
                   "names is an IRQ the CPU had not accepted when it was "
                   "written into the trace",
    },
    {
        "expectation_id": "cpu_ip.irq_expiry",
        "assertion_class": CLASS_CPU_IP,
        "declared_by": "expired_masked / pulse_expired mask_observation",
        "asserts": "an IRQ pulse that expires with no same-source CPU "
                   "acceptance anywhere in the artifact is reported with its "
                   "exact expiry event and mask observation",
    },
    {
        "expectation_id": "cpu_ip.consumption_record",
        "assertion_class": CLASS_CPU_IP,
        "declared_by": "gpio_consumption_match / "
                       "cpu_retired_transaction_target_delivery",
        "asserts": "a consumption record names the exact observation and "
                   "producer event ids and the transaction key it consumed",
    },
)

#: Every expectation id this report can cite; a finding always names one.
EXPECTATION_IDS = frozenset(row["expectation_id"] for row in EXPECTATIONS)


# --------------------------------------------------------------------- helpers


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def _nonempty_text(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _integer(value: object) -> bool:
    return type(value) is int


def _record_id(record_class: str, evidence: Mapping) -> str:
    payload = _canonical({"record_class": record_class, "evidence": evidence})
    return f"{record_class}:{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:16]}"


def _module_identity(name: str) -> dict:
    module = sys.modules.get(name)
    path = Path(getattr(module, "__file__", "") or "")
    identity = {"module": name, "path": str(path), "sha256": None}
    try:
        identity["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:  # pragma: no cover - only when the source moved away
        pass
    return identity


def _file_identity(path: Path, *, required: bool = False) -> dict:
    row = {"name": path.name, "path": str(path), "present": path.is_file(),
           "bytes": None, "sha256": None}
    if row["present"]:
        row["bytes"] = path.stat().st_size
        row["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    return row


def _read_json(path: Path):
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _limit(limits: list[dict], quantity: str, reason: str) -> None:
    limits.append({"quantity": quantity, "reason": reason})


class _Census:
    """Every abnormal record one run holds, with its exact evidence keys."""

    def __init__(self) -> None:
        self.rows: list[dict] = []

    def add(self, record_class: str, expectation_id: str | None, location: str,
            evidence: Mapping, reason: str) -> dict:
        row = {
            "assertion_class": (location.split(":", 1)[1]
                                if location.startswith(_LOCATION_CLASS + ":")
                                else None),
            "record_class": record_class,
            "expectation_id": expectation_id,
            "record_id": _record_id(record_class, evidence),
            "location": location,
            "evidence": dict(evidence),
            "reason": reason,
        }
        self.rows.append(row)
        return row

    def add_class(self, record_class: str, expectation_id: str,
                  evidence: Mapping, reason: str) -> dict:
        assertion_class = _RECORD_CLASS.get(record_class)
        if assertion_class is None:
            raise ValueError(f"no assertion class declares record class "
                             f"{record_class!r}")
        return self.add(record_class, expectation_id,
                        f"{_LOCATION_CLASS}:{assertion_class}", evidence, reason)

    def add_bucket(self, record_class: str, evidence: Mapping,
                   reason: str) -> dict:
        bucket = _FAIL_CLOSED_BUCKET.get(record_class)
        if bucket is None:
            raise ValueError(f"no fail-closed bucket declares record class "
                             f"{record_class!r}")
        return self.add(record_class, None, f"{_LOCATION_BUCKET}:{bucket}",
                        evidence, reason)

    def add_unrepresented(self, record_class: str, evidence: Mapping,
                          reason: str) -> dict:
        return self.add(record_class, None, UNREPRESENTED, evidence, reason)

    def sorted_rows(self) -> list[dict]:
        return sorted(self.rows,
                      key=lambda row: (row["record_class"], _canonical(row["evidence"])))

    def class_rows(self, assertion_class: str) -> list[dict]:
        location = f"{_LOCATION_CLASS}:{assertion_class}"
        return [row for row in self.sorted_rows() if row["location"] == location]

    def bucket_rows(self, bucket: str) -> list[dict]:
        location = f"{_LOCATION_BUCKET}:{bucket}"
        return [row for row in self.sorted_rows() if row["location"] == location]


# ------------------------------------------------------------------ CPU/IP scan


def _native_irq_instance(event: Mapping) -> tuple[str, object] | None:
    kind = event.get("kind")
    if not isinstance(kind, str):
        return None
    if kind not in NATIVE_IRQ_OBSERVATION_KINDS \
            and not kind.endswith(NATIVE_IRQ_OBSERVATION_SUFFIXES):
        return None
    trigger_id = event.get("trigger_id")
    if _nonempty_text(trigger_id):
        return ("trigger_id", trigger_id)
    source_event_id = event.get("source_event_id")
    if _integer(source_event_id):
        return ("source_event_id", source_event_id)
    return None


def _cpu_irq_acceptance_instance(event: Mapping) -> tuple[str, object] | None:
    if event.get("kind") not in CPU_IRQ_ACCEPTANCE_KINDS:
        return None
    trigger = event.get("source_trigger")
    if isinstance(trigger, Mapping):
        trigger_id = trigger.get("trigger_id")
        if _nonempty_text(trigger_id):
            return ("trigger_id", trigger_id)
    source_event_id = event.get("source_event_id")
    if _integer(source_event_id):
        return ("source_event_id", source_event_id)
    return None


def _irq_expiry_instance(event: Mapping) -> tuple[str, object] | None:
    trigger = event.get("source_trigger")
    if isinstance(trigger, Mapping):
        trigger_id = trigger.get("trigger_id")
        if _nonempty_text(trigger_id):
            return ("trigger_id", trigger_id)
    source_event_id = event.get("source_event_id")
    if _integer(source_event_id):
        return ("source_event_id", source_event_id)
    return None


class _CpuIpScan:
    """Classify every CPU/IP behaviour record the trace really holds."""

    def __init__(self, census: _Census) -> None:
        self._census = census
        self.counts: Counter = Counter()
        self._irq_observed: dict[tuple, list[int]] = {}
        self._irq_observed_kinds: dict[tuple, set] = {}
        self._irq_observed_components: dict[tuple, set] = {}
        self._irq_observed_source_ids: dict[tuple, int] = {}
        self._irq_observed_event_ids: dict[tuple, list[int]] = {}
        self._accepted_trigger_ids: set = set()
        self._accepted_source_event_ids: set = set()
        self._accepted_events: dict[tuple, list[int]] = {}
        self.retirement = Counter()
        self.consumption_records = 0
        self._expiries: list[tuple] = []

    # -- ingest -------------------------------------------------------------
    def observe(self, event: Mapping) -> None:
        kind = event.get("kind")
        bucket = CPU_IP_RECORD_KINDS.get(kind) if isinstance(kind, str) else None
        if bucket is None:
            return
        self.counts[bucket] += 1
        event_id = event.get("event_id")
        if kind == "cpu_retirement_match":
            self._retirement(event, event_id)
        elif kind == "cpu_external_irq_sample":
            self._irq_sample(event, event_id)
        elif kind in ("expired_masked", "pulse_expired"):
            self._irq_expiry(event, event_id)
        elif kind in CPU_IRQ_ACCEPTANCE_KINDS:
            instance = _cpu_irq_acceptance_instance(event)
            if instance is not None:
                self._accepted_events.setdefault(instance, []).append(event_id)
            trigger = event.get("source_trigger")
            if isinstance(trigger, Mapping) and _nonempty_text(
                    trigger.get("trigger_id")):
                self._accepted_trigger_ids.add(trigger["trigger_id"])
            source_event_id = event.get("source_event_id")
            if _integer(source_event_id):
                self._accepted_source_event_ids.add(source_event_id)
        elif bucket == "native_irq_observation":
            self._native_irq_observation(event, event_id)
        elif bucket == "consumption_match":
            self.consumption_records += 1
            self._consumption(event, event_id, kind)

    def _retirement(self, event: Mapping, event_id) -> None:
        status = event.get("status")
        if status == RETIREMENT_ACCEPTED:
            self.retirement["accepted"] += 1
        elif status == RETIREMENT_REJECTED:
            self.retirement["refused"] += 1
        elif status == RETIREMENT_AMBIGUOUS:
            self.retirement["ambiguous"] += 1
        else:
            self._census.add_unrepresented(
                "unclassified_abnormal_record",
                {"record_kind": "cpu_retirement_match", "event_id": event_id,
                 "status": status, "retirement_event_id":
                     event.get("producer_event_id")},
                f"cpu_retirement_match event {event_id} declares status "
                f"{status!r}, which no assertion class in this report covers, "
                "so the record is not represented and the gate fails")
        origin = event.get("instruction_origin_status")
        evidence = {
            "event_id": event_id,
            "retirement_event_id": event.get("producer_event_id"),
            "pc": event.get("pc"),
            "insn": event.get("insn"),
            "order": event.get("order"),
            "status": status,
            "reason": event.get("reason"),
            "schema_version": event.get("schema_version"),
            "instruction_origin_status": origin,
            "proof_scope": event.get("proof_scope"),
            "origin_relation": event.get("origin_relation"),
        }
        if status == RETIREMENT_REJECTED:
            self._census.add_class(
                "retirement_observation_refused",
                "cpu_ip.retirement_observation_supported", evidence,
                f"cpu_retirement_match event {event_id} refused the retirement "
                f"of instruction {event.get('insn')} at pc {event.get('pc')} "
                f"with reason {event.get('reason')!r}")
        elif status == RETIREMENT_AMBIGUOUS:
            self._census.add_class(
                "retirement_observation_ambiguous",
                "cpu_ip.retirement_observation_supported", evidence,
                f"cpu_retirement_match event {event_id} could not join the "
                f"retirement unambiguously: {event.get('reason')!r}")
        if status == RETIREMENT_ACCEPTED:
            if origin == RETIREMENT_ORIGIN_TYPED:
                self.retirement["origin_typed"] += 1
            else:
                self.retirement["origin_untyped"] += 1
                self._census.add_class(
                    "retirement_origin_untyped",
                    "cpu_ip.retirement_instruction_origin", evidence,
                    f"cpu_retirement_match event {event_id} accepted the "
                    f"retirement but instruction_origin_status is {origin!r}, "
                    "so the retired instruction bytes are not typed back to a "
                    "writer and this retirement cannot certify an "
                    "instruction-source hop")

    def _irq_sample(self, event: Mapping, event_id) -> None:
        expected = event.get("expected_input")
        actual = event.get("actual_post_input")
        evidence = {
            "event_id": event_id,
            "local_tick": event.get("local_tick"),
            "expected_input": expected,
            "actual_pre_input": event.get("actual_pre_input"),
            "actual_post_input": actual,
            "irq_masked_pre": event.get("irq_masked_pre"),
            "irq_taken_pre": event.get("irq_taken_pre"),
            "execution_id": event.get("execution_id"),
        }
        if not _integer(expected) or not _integer(actual):
            self._census.add_class(
                "irq_input_expectation_unmeasurable",
                "cpu_ip.irq_input_expectation", evidence,
                f"cpu_external_irq_sample event {event_id} carries no integer "
                "expected_input/actual_post_input pair, so the IRQ input "
                "expectation cannot be evaluated for it")
            return
        self.retirement["irq_samples"] += 1
        if expected != actual:
            self._census.add_class(
                "irq_input_expectation_mismatch",
                "cpu_ip.irq_input_expectation", evidence,
                f"cpu_external_irq_sample event {event_id} expected IRQ input "
                f"{expected} but the CPU input after the step was {actual}")

    def _irq_expiry(self, event: Mapping, event_id) -> None:
        instance = _irq_expiry_instance(event)
        evidence = {
            "event_id": event_id,
            "record_kind": event.get("kind"),
            "mask_observation": event.get("mask_observation"),
            "source_event_id": event.get("source_event_id"),
            "source_trigger_id": (event.get("source_trigger") or {}).get("trigger_id")
            if isinstance(event.get("source_trigger"), Mapping) else None,
            "end_cpu_tick_exclusive": event.get("end_cpu_tick_exclusive"),
            "source": event.get("source"),
            "target": event.get("target"),
        }
        self._expiries.append((instance, evidence))

    def _native_irq_observation(self, event: Mapping, event_id) -> None:
        instance = _native_irq_instance(event)
        if instance is None:
            self._census.add_unrepresented(
                "unclassified_abnormal_record",
                {"record_kind": event.get("kind"), "event_id": event_id},
                f"{event.get('kind')} event {event_id} is a native IRQ "
                "observation that names no trigger_id or source_event_id, so "
                "its acceptance cannot be checked and the record is not "
                "represented; the gate fails")
            return
        self._irq_observed.setdefault(instance, []).append(event_id)
        self._irq_observed_kinds.setdefault(instance, set()).add(event.get("kind"))
        self._irq_observed_components.setdefault(instance, set()).add(
            event.get("component"))
        source_event_id = event.get("source_event_id")
        if _integer(source_event_id) and instance[0] != "source_event_id":
            self._irq_observed_source_ids.setdefault(instance, source_event_id)
        if instance[0] == "source_event_id":
            self._irq_observed_source_ids.setdefault(instance, instance[1])

    def _consumption(self, event: Mapping, event_id, kind: str) -> None:
        missing = []
        if not _integer(event.get("observation_event_id")) \
                and not isinstance(event.get("consumer_resource"), Mapping):
            missing.append("observation_event_id")
        key = event.get("fullkey")
        if key is None:
            key = event.get("transaction_key")
        if key is None and not isinstance(event.get("consumer_resource"), Mapping):
            missing.append("transaction_key")
        if not missing:
            return
        self._census.add_class(
            "consumption_assertion_incomplete",
            "cpu_ip.consumption_record",
            {"event_id": event_id, "record_kind": kind, "missing": missing},
            f"{kind} event {event_id} names no {'/'.join(missing)}, so this "
            "consumption assertion carries no exact key")

    # -- settle -------------------------------------------------------------
    def finish(self) -> dict:
        accepted_trigger_ids = self._accepted_trigger_ids
        accepted_source_ids = self._accepted_source_event_ids
        for instance, event_ids in sorted(self._irq_observed.items(), key=repr):
            trigger_id = instance[1] if instance[0] == "trigger_id" else None
            source_event_id = self._irq_observed_source_ids.get(instance)
            accepted = (trigger_id is not None
                        and trigger_id in accepted_trigger_ids) or (
                source_event_id is not None
                and source_event_id in accepted_source_ids)
            if accepted:
                continue
            self._census.add_class(
                "irq_observed_without_cpu_acceptance",
                "cpu_ip.irq_acceptance",
                {"instance_key_kind": instance[0],
                 "trigger_id": trigger_id,
                 "source_event_id": source_event_id,
                 "component": sorted(
                     value for value in self._irq_observed_components[instance]
                     if isinstance(value, str)),
                 "observation_kinds": sorted(self._irq_observed_kinds[instance]),
                 "observation_event_ids": sorted(event_ids),
                 "acceptance_event_ids": list(
                     self._accepted_events.get(instance, ()))},
                f"native IRQ observation {instance[0]}={instance[1]!r} was "
                f"written at event(s) {sorted(event_ids)} and no CPU acceptance "
                "record (cpu_irq_taken/cpu_external_irq_taken) names that exact "
                "source identity anywhere in this artifact")
        for instance, evidence in self._expiries:
            trigger_id = evidence["source_trigger_id"]
            source_event_id = evidence["source_event_id"]
            accepted = (trigger_id is not None
                        and trigger_id in accepted_trigger_ids) or (
                _integer(source_event_id)
                and source_event_id in accepted_source_ids)
            if accepted:
                continue
            self._census.add_class(
                "irq_expired_without_cpu_acceptance",
                "cpu_ip.irq_expiry", evidence,
                f"{evidence['record_kind']} event {evidence['event_id']} ended "
                f"the IRQ pulse (mask_observation="
                f"{evidence['mask_observation']!r}) with no same-source CPU "
                "acceptance record anywhere in this artifact")
        return {
            "observed_record_counts": dict(sorted(self.counts.items())),
            "irq": {
                "observed_instance_count": len(self._irq_observed),
                "accepted_trigger_id_count": len(accepted_trigger_ids),
                "accepted_source_event_id_count": len(accepted_source_ids),
                "observation_event_count": sum(
                    len(rows) for rows in self._irq_observed.values()),
            },
            "retirement": {
                "match_records": self.counts.get("retirement_match", 0),
                "accepted": self.retirement.get("accepted", 0),
                "refused": self.retirement.get("refused", 0),
                "ambiguous": self.retirement.get("ambiguous", 0),
                "origin_typed": self.retirement.get("origin_typed", 0),
                "origin_untyped": self.retirement.get("origin_untyped", 0),
            },
            "consumption": {"records": self.consumption_records},
        }


# ------------------------------------------------------------- receipt census


def _scan_receipts(path: Path, census: _Census, limits: list[dict]) -> dict:
    """Census every receipt, including the cases refused before any RTL command."""
    identity = _file_identity(path)
    if not identity["present"]:
        _limit(limits, "protocol_checker.receipts",
               "receipts.jsonl is missing, so the run's own checker findings "
               "cannot be read and the protocol_checker class stays null")
        return {"present": False, "receipts": 0, "violations": 0,
                "refused": 0, "identity": identity}
    receipts = 0
    violations = 0
    refused = 0
    index = -1
    observed_statuses: set = set()
    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.endswith("\n"):
                raise ValueError(
                    f"unterminated receipt line {number} in {path.name}")
            if not line.strip():
                raise ValueError(f"blank receipt line {number} in {path.name}")
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"invalid JSON on line {number} of {path.name}: "
                    f"{exc.msg}") from exc
            if not isinstance(row, Mapping):
                raise ValueError(
                    f"non-object receipt on line {number} of {path.name}")
            index += 1
            receipts += 1
            violations += _classify_receipt(index, row, census)
            if row.get("candidate_disposition") == "rejected":
                refused += 1
            status = row.get("status")
            if isinstance(status, str):
                observed_statuses.add(status)
    divergence = sorted(observed_statuses - CLASSIFIED_STATUSES)
    if divergence:
        _limit(limits, "protocol_checker.status_vocabulary",
               "receipt statuses this run writes that the shipped "
               f"acceptance_metrics classification does not list: {divergence}; "
               "this report classifies them through its own status vocabulary "
               "and reports the divergence instead of dropping the receipts")
    return {"present": True, "receipts": receipts, "violations": violations,
            "refused": refused, "identity": identity,
            "status_vocabulary_divergence": divergence,
            "observed_statuses": sorted(observed_statuses)}


def _classify_receipt(index: int, row: Mapping, census: _Census) -> int:
    """Route one receipt; return the number of violation findings it produced."""
    case_id = row.get("case_id")
    status = row.get("status")
    disposition = row.get("candidate_disposition")
    rejection = row.get("rejection")
    error = row.get("error")
    wall_cut = row.get("wall_cut")
    found = 0
    violation_rows = row.get("violations") or ()
    if not isinstance(violation_rows, (list, tuple)):
        raise ValueError(f"receipt {index} declares a non-list violations field")
    for violation in violation_rows:
        if not _nonempty_text(violation):
            raise ValueError(
                f"receipt {index} declares a non-string violation {violation!r}")
        found += 1
        census.add_class(
            "protocol_violation", "protocol_checker.receipt_violations",
            {"receipt_index": index, "case_id": case_id, "violation": violation,
             "status": status, "candidate_disposition": disposition},
            f"the run's own checker returned violation {violation!r} for case "
            f"{case_id!r} (receipt {index})")
    if status in FINDING_STATUSES and not violation_rows:
        census.add_unrepresented(
            "unclassified_abnormal_record",
            {"receipt_index": index, "case_id": case_id, "status": status,
             "candidate_disposition": disposition},
            f"receipt {index} declares status {status!r} but carries no "
            "violation string, so no assertion class can represent it and the "
            "gate fails")
    if disposition is not None and disposition not in KNOWN_DISPOSITIONS:
        census.add_unrepresented(
            "unclassified_abnormal_record",
            {"receipt_index": index, "case_id": case_id,
             "candidate_disposition": disposition,
             "candidate_disposition_reason":
                 row.get("candidate_disposition_reason")},
            f"receipt {index} declares candidate_disposition "
            f"{disposition!r}, which no assertion class in this report covers; "
            "the record is not represented and the gate fails")
    if status is not None and status not in KNOWN_STATUSES:
        census.add_unrepresented(
            "unclassified_abnormal_record",
            {"receipt_index": index, "case_id": case_id, "status": status},
            f"receipt {index} declares status {status!r}, which the framework "
            "does not classify; the record is not represented and the gate "
            "fails")
    refusal = _refusal_evidence(index, row)
    if disposition == "rejected" or rejection is not None:
        if refusal["rtl_command_observed"]:
            reason = (f"case {case_id!r} (receipt {index}) was refused with "
                      f"rejection {refusal['rejection_code']!r} after an "
                      "online runner timing record was written, and is "
                      "reported instead of dropped")
        else:
            reason = (f"case {case_id!r} (receipt {index}) was refused before "
                      f"any RTL command (no case_id and no online runner "
                      f"timing was written) with rejection "
                      f"{refusal['rejection_code']!r}, and is reported "
                      "instead of dropped")
        census.add_bucket("case_refused_before_rtl", refusal, reason)
    elif disposition == "uncertain" or status == "uncertain_effect":
        evidence = _receipt_evidence(index, row)
        evidence["rtl_command_observed"] = (
            row.get("case_id") is not None
            or row.get("online_runner_timing_seconds") is not None)
        census.add_bucket(
            "case_uncertain", evidence,
            f"case {case_id!r} (receipt {index}) stayed "
            f"{row.get('candidate_disposition_reason')!r} with status "
            f"{status!r}: the runner committed no unambiguous case result for "
            "it, and the record is reported rather than counted as a measured "
            "case")
    elif status in ENVIRONMENT_STATUSES:
        census.add_bucket(
            "case_environment_error", _receipt_evidence(index, row),
            f"case {case_id!r} (receipt {index}) ended with status {status!r}: "
            f"{str(error)[:200]!r}")
    elif status in REFUSED_STATUSES:
        census.add_bucket(
            "case_refused_before_rtl", refusal,
            f"case {case_id!r} (receipt {index}) ended with status {status!r} "
            "and no structured rejection, so it is reported as refused rather "
            "than counted as a measured case")
    elif status == "running":
        census.add_bucket(
            "case_unfinished", _receipt_evidence(index, row),
            f"receipt {index} was still {status!r} when the run artifact was "
            "written, so it holds no committed case result and is reported "
            "instead of being dropped")
    elif error is not None:
        census.add_bucket(
            "case_error", _receipt_evidence(index, row),
            f"receipt {index} carries error {str(error)[:200]!r} without a "
            "structured rejection or a refusal disposition")
    if wall_cut is not None:
        census.add_bucket(
            "case_wall_cut", _receipt_evidence(index, row),
            f"receipt {index} was cut by the wall clock: {str(wall_cut)[:200]!r}")
    return found


def _receipt_evidence(index: int, row: Mapping) -> dict:
    rejection = row.get("rejection")
    code = pointer = schema = None
    if isinstance(rejection, Mapping):
        code = rejection.get("code")
        pointer = rejection.get("pointer")
        schema = rejection.get("schema_version")
    return {
        "receipt_index": index,
        "case_id": row.get("case_id"),
        "status": row.get("status"),
        "candidate_disposition": row.get("candidate_disposition"),
        "candidate_disposition_reason": row.get("candidate_disposition_reason"),
        "rejection_code": code,
        "rejection_pointer": pointer,
        "rejection_schema_version": schema,
        "error": None if row.get("error") is None else str(row.get("error"))[:200],
        "wall_cut": None if row.get("wall_cut") is None
        else str(row.get("wall_cut"))[:200],
    }


def _refusal_evidence(index: int, row: Mapping) -> dict:
    evidence = _receipt_evidence(index, row)
    runner_timing = row.get("online_runner_timing_seconds")
    evidence["rtl_command_observed"] = (row.get("case_id") is not None
                                        or runner_timing is not None)
    return evidence


# ------------------------------------------------------------------ edge joins


def _declared_edges(compiled: Mapping) -> tuple:
    """Declared hops per direction, in declaration order, plus the contract keys."""
    declaration = compiled.get("declaration")
    selections = (declaration.get("selections")
                  if isinstance(declaration, Mapping) else None)
    rows = []
    if isinstance(selections, list):
        for selection in selections:
            if not isinstance(selection, Mapping):
                continue
            for edge in selection.get("edges") or ():
                if not isinstance(edge, Mapping):
                    continue
                rows.append({
                    "direction": selection.get("direction"),
                    "path_id": selection.get("path_id"),
                    "declared_kind": edge.get("kind"),
                    "rule_index": edge.get("rule_index"),
                    "prerequisite_index": edge.get("prerequisite_index"),
                    "prerequisite": edge.get("prerequisite"),
                    "target": edge.get("target"),
                })
    return tuple(rows)


def _edge_index(compiled: Mapping) -> dict:
    index: dict[tuple, dict] = {}
    for row in _declared_edges(compiled):
        key = (row["rule_index"], row["prerequisite_index"])
        state = index.setdefault(key, {"directions": [], "path_ids": [],
                                       "declared_kinds": [],
                                       "prerequisite": row["prerequisite"],
                                       "target": row["target"]})
        for name, value in (("directions", row["direction"]),
                            ("path_ids", row["path_id"]),
                            ("declared_kinds", row["declared_kind"])):
            if value is not None and value not in state[name]:
                state[name].append(value)
    return index


def _not_a_runtime_edge_reason(key: tuple, declared_kind: object) -> str:
    return (f"rule {key[0]} is selected as a {declared_kind!r} hop, but the "
            "compiled runtime path contract declares no observable runtime "
            "relation for that edge identity, so this consumer has no "
            "delivery/consumption join for it")


def _edge_report_row(row: Mapping, index: Mapping, contract_keys: frozenset,
                     declared_kind: str | None) -> dict:
    key = (row.get("rule_index"), row.get("prerequisite_index"))
    hops = []
    for hop in row.get("hops") or ():
        if not isinstance(hop, Mapping):
            continue
        hops.append({
            "hop_id": hop.get("hop_id"),
            "event_id": hop.get("event_id"),
            "evidence": {name: value for name, value in hop.items()
                         if name not in ("hop_id", "event_id")},
        })
    runtime_edge = key in contract_keys
    declared = index.get(key, {"directions": [], "path_ids": [],
                               "declared_kinds": [], "prerequisite": None,
                               "target": None})
    reason = row.get("reason")
    if not runtime_edge:
        reason = _not_a_runtime_edge_reason(key, declared["declared_kinds"][0]
                                            if declared["declared_kinds"] else None)
    return {
        "rule_index": row.get("rule_index"),
        "prerequisite_index": row.get("prerequisite_index"),
        "status": NOT_A_RUNTIME_EDGE if not runtime_edge else row.get("status"),
        "runtime_edge": runtime_edge,
        "relation": None if not runtime_edge else row.get("relation"),
        "scope": None if not runtime_edge else row.get("scope"),
        "proof_scope": None if not runtime_edge else row.get("proof_scope"),
        "missing": [] if not runtime_edge else list(row.get("missing") or ()),
        "reason": reason,
        "prerequisite": (declared["prerequisite"] if not runtime_edge
                         else row.get("prerequisite")),
        "target": declared["target"] if not runtime_edge else row.get("target"),
        "hop_ids": [hop["hop_id"] for hop in hops],
        "hop_event_ids": [hop["event_id"] for hop in hops],
        "hops": hops,
        "directions": list(declared["directions"]),
        "path_ids": list(declared["path_ids"]),
        "declared_kinds": list(declared["declared_kinds"]),
        "declared_kind": declared_kind,
    }


def _certificate_row(certificate: Mapping) -> dict:
    hops = [{"hop_id": hop.get("hop_id"), "event_id": hop.get("event_id"),
             "evidence": {name: value for name, value in hop.items()
                          if name not in ("hop_id", "event_id")}}
            for hop in certificate.get("hops") or ()
            if isinstance(hop, Mapping)]
    missing_hops = list(certificate.get("missing_hops") or ())
    return {
        "certificate_id": certificate.get("certificate_id"),
        "direction": certificate.get("direction"),
        "status": certificate.get("status"),
        "source_admission_id": certificate.get("source_admission_id"),
        "source_id": certificate.get("source_id"),
        "source_case_id": certificate.get("source_case_id"),
        "source_case_index": certificate.get("source_case_index"),
        "endpoint_case_id": certificate.get("endpoint_case_id"),
        "endpoint_case_index": certificate.get("endpoint_case_index"),
        "completed_event_id": certificate.get("completed_event_id"),
        "serial_token_status": certificate.get("serial_token_status"),
        "serial_token_reason": certificate.get("serial_token_reason"),
        "missing_hops": missing_hops,
        "first_missing_hop": missing_hops[0] if missing_hops else None,
        "reason": certificate.get("reason"),
        "hop_ids": [hop["hop_id"] for hop in hops],
        "hop_event_ids": [hop["event_id"] for hop in hops],
        "hops": hops,
    }


# ------------------------------------------------------------------- reporting


def _class_section_base(name: str) -> dict:
    return {"assertion_class": name, "data_present": False,
            "finding_count": None, "finding_count_reason": None,
            "observed_record_count": None, "observed_record_counts": {},
            "findings": [], "truncated": False}


def _apply_truncation(census: _Census, limit: int | None) -> dict:
    """Keep at most ``limit`` findings per class; the rest fail the gate."""
    truncated: dict[str, int] = {}
    if limit is None:
        return truncated
    for name in ASSERTION_CLASSES:
        rows = census.class_rows(name)
        if len(rows) <= limit:
            continue
        dropped = rows[limit:]
        truncated[name] = len(dropped)
        for row in dropped:
            original = dict(row)
            row["record_class"] = "truncated_finding"
            row["expectation_id"] = None
            row["location"] = UNREPRESENTED
            row["evidence"] = {
                "assertion_class": name,
                "record_class": original["record_class"],
                "record_id": original["record_id"],
                "max_findings_per_class": limit,
            }
            row["record_id"] = _record_id("truncated_finding", row["evidence"])
            row["reason"] = (
                f"{name} holds {len(rows)} findings and "
                f"max_findings_per_class={limit} truncated "
                f"{len(dropped)}; the dropped record "
                f"{original['record_id']} is not represented, so the gate "
                "fails instead of passing on a partial list")
    return truncated


def _represented_records(report: Mapping) -> dict:
    found: dict[str, set] = {}
    for name, section in report["assertion_classes"].items():
        location = f"{_LOCATION_CLASS}:{name}"
        for row in section.get("findings") or ():
            found.setdefault(location, set()).add(row["record_id"])
    section = report["not_silently_filtered"]
    for bucket in FAIL_CLOSED_BUCKETS:
        location = f"{_LOCATION_BUCKET}:{bucket}"
        for row in section.get(bucket) or ():
            found.setdefault(location, set()).add(row["record_id"])
    return found


def _representation_check(report: Mapping, census: _Census) -> list[dict]:
    represented = _represented_records(report)
    unrepresented = []
    for row in census.sorted_rows():
        if row["location"] == UNREPRESENTED:
            unrepresented.append(row)
            continue
        if row["record_id"] in represented.get(row["location"], set()):
            continue
        unrepresented.append({
            **row,
            "reason": (f"the report does not carry record {row['record_id']} "
                       f"({row['record_class']}) at its declared location "
                       f"{row['location']}; the record is not represented and "
                       "the gate fails"),
        })
    return unrepresented


def _class_document(name: str, census: _Census, identity: Mapping,
                    limits: list[dict], truncated: Mapping) -> dict:
    section = _class_section_base(name)
    section["findings"] = census.class_rows(name)
    section["truncated"] = bool(truncated.get(name))
    section["limits"] = [dict(row) for row in limits]
    section.update(identity)
    return section


def assertion_class_report(run_dir: str | Path, *, chain_producer: object = None,
                           max_pending: int = DEFAULT_CHAIN_MAX_PENDING,
                           max_event_gap: int = DEFAULT_CHAIN_MAX_EVENT_GAP,
                           require_native_receipts: bool = True,
                           edge_max_pending: int = DEFAULT_EDGE_MAX_PENDING,
                           edge_max_event_gap: int = DEFAULT_EDGE_MAX_EVENT_GAP,
                           ingest_batch_size: int = DEFAULT_INGEST_BATCH_SIZE,
                           verify_semantic: bool = True,
                           max_findings_per_class: int | None = None) -> dict:
    """Report one saved run's three assertion classes, read-only.

    Raises :class:`myfuzz.scenario.acceptance_metrics.TraceUnavailable` when the
    run holds no streamable trace, and :class:`ValueError` for an argument or an
    artifact that contradicts its frozen contract. An abnormal record the report
    cannot represent never raises: it fails ``not_silently_filtered.gate`` with
    that record's exact key.
    """
    for name, value in (("max_pending", max_pending),
                        ("max_event_gap", max_event_gap),
                        ("edge_max_pending", edge_max_pending),
                        ("edge_max_event_gap", edge_max_event_gap),
                        ("ingest_batch_size", ingest_batch_size)):
        if type(value) is not int or value < 1:
            raise ValueError(f"{name} must be a positive integer")
    if type(require_native_receipts) is not bool:
        raise ValueError("require_native_receipts must be boolean")
    if type(verify_semantic) is not bool:
        raise ValueError("verify_semantic must be boolean")
    if max_findings_per_class is not None and (
            type(max_findings_per_class) is not int
            or max_findings_per_class < 1):
        raise ValueError("max_findings_per_class must be None or a positive "
                         "integer")
    directory = Path(run_dir)
    if not directory.is_dir():
        raise ValueError(f"run directory does not exist: {directory}")

    limits: list[dict] = []
    census = _Census()
    scan = _CpuIpScan(census)

    # -- saved declarations -------------------------------------------------
    manifest = _read_json(directory / "online_session_manifest.json")
    compiled = (manifest.get("runtime_paths")
                if isinstance(manifest, Mapping) else None)
    contract = None
    endpoints: Mapping | None = None
    if not isinstance(compiled, Mapping):
        _limit(limits, "cross_component_provenance_and_order.declaration",
               "online_session_manifest.json is missing or holds no "
               "runtime_paths document, so the run's declared runtime edges "
               "cannot be read and the cross-component class stays null")
    else:
        declaration = compiled.get("declaration")
        contract_document = (declaration.get("contract")
                             if isinstance(declaration, Mapping) else None)
        if not isinstance(contract_document, Mapping):
            _limit(limits,
                   "cross_component_provenance_and_order.declaration",
                   "the saved runtime_paths document declares no contract, so "
                   "no declared runtime edge can be resolved")
        else:
            contract = RuntimePathContract.from_document(dict(contract_document))
            try:
                endpoints = edge_endpoints_from_compiled(contract, compiled)
            except ValueError as exc:
                endpoints = None
                _limit(limits,
                       "cross_component_provenance_and_order.endpoints",
                       f"the declared edge endpoints could not be resolved: {exc}")

    # -- census over receipts (the run's own checker) ------------------------
    receipt_identity = _scan_receipts(directory / "receipts.jsonl", census, limits)

    # -- one streaming pass over the saved terminal trace --------------------
    stream = TraceEventStream(directory, verify_semantic=verify_semantic)
    edge_consumer = None
    if contract is not None:
        edge_consumer = EdgeProvenanceConsumer(
            contract, endpoints=endpoints, max_pending=edge_max_pending,
            max_event_gap=edge_max_event_gap)
    certificates: list[dict] = []
    if chain_producer is None:
        producer = ChainCertificates(max_pending=max_pending,
                                     max_event_gap=max_event_gap,
                                     require_native_receipts=require_native_receipts)
    elif isinstance(chain_producer, type) or not hasattr(chain_producer, "ingest"):
        producer = chain_producer(max_pending=max_pending,
                                  max_event_gap=max_event_gap,
                                  require_native_receipts=require_native_receipts)
    else:
        producer = chain_producer

    events_ingested = 0
    batch: list[dict] = []

    def flush(batch_rows: list[dict]) -> None:
        if not batch_rows:
            return
        slice_ = tuple(batch_rows)
        certificates.extend(producer.ingest(slice_))
        if edge_consumer is not None:
            edge_consumer.ingest(slice_)

    for event in stream.events():
        events_ingested += 1
        scan.observe(event)
        batch.append(event)
        if len(batch) >= ingest_batch_size:
            flush(batch)
            batch = []
    flush(batch)
    certificates.extend(producer.flush())
    cpu_ip_summary = scan.finish()
    edge_report = edge_consumer.report() if edge_consumer is not None else None

    # -- cross-component class ----------------------------------------------
    edge_rows: list[dict] = []
    contract_keys: frozenset = frozenset()
    edge_index: dict = {}
    if isinstance(compiled, Mapping) and contract is not None:
        edge_index = _edge_index(compiled)
        contract_keys = frozenset(edge.key for edge in contract.edges)
    provenance_rows = {}
    if edge_report is not None:
        for row in edge_report.get("edges") or ():
            provenance_rows[(row.get("rule_index"),
                             row.get("prerequisite_index"))] = row
    for key in sorted(set(edge_index) | set(provenance_rows)):
        declared = edge_index.get(key)
        row = provenance_rows.get(key)
        declared_kind = declared["declared_kinds"][0] if declared and \
            declared["declared_kinds"] else None
        if row is None:
            row = {"rule_index": key[0], "prerequisite_index": key[1],
                   "status": UNKNOWN, "hops": [], "missing": [],
                   "reason": "the declared edge is absent from the compiled "
                             "runtime path contract"}
        edge_rows.append(_edge_report_row(row, edge_index, contract_keys,
                                          declared_kind))
    for row in edge_rows:
        key = (row["rule_index"], row["prerequisite_index"])
        if not row["runtime_edge"]:
            census.add_class(
                "not_a_runtime_edge", "cross_component.declared_edge_hops",
                {"status": NOT_A_RUNTIME_EDGE,
                 "direction": (row["directions"] or [None])[0],
                 "path_id": (row["path_ids"] or [None])[0],
                 "declared_kind": (row["declared_kinds"] or [None])[0],
                 "rule_index": row["rule_index"],
                 "prerequisite_index": row["prerequisite_index"],
                 "prerequisite": row["prerequisite"],
                 "target": row["target"]},
                f"declared hop {key} is selected by "
                f"{row['directions']} but the compiled runtime path contract "
                "declares no observable runtime relation for that edge "
                "identity, so this consumer has no delivery/consumption join "
                "for it; the hop is reported as not_a_runtime_edge and is "
                "never counted as certified")
            continue
        if row["status"] == CERTIFIED:
            continue
        record_class = ("runtime_edge_incomplete" if row["status"] == INCOMPLETE
                        else "runtime_edge_unknown")
        evidence = {
            "rule_index": row["rule_index"],
            "prerequisite_index": row["prerequisite_index"],
            "relation": row["relation"],
            "status": row["status"],
            "missing": list(row["missing"]),
            "hop_ids": list(row["hop_ids"]),
            "hop_event_ids": list(row["hop_event_ids"]),
            "reason": row["reason"],
            "directions": list(row["directions"]),
            "path_ids": list(row["path_ids"]),
        }
        if row["status"] == INCOMPLETE:
            reason = (f"declared runtime edge {key} is missing "
                      f"{len(row['missing'])} required hop(s) "
                      f"{row['missing']} (reason {row['reason']!r})")
        else:
            reason = (f"declared runtime edge {key} has no observable shape "
                      f"(reason {row['reason']!r}); it is unknown, never zero "
                      "and never certified")
        census.add_class(record_class, "cross_component.declared_edge_hops",
                         evidence, reason)
    for rejection in (edge_report or {}).get("rejections") or ():
        evidence = {name: rejection.get(name) for name in
                    ("rule_index", "prerequisite_index", "reason", "event_id",
                     "kind")}
        census.add_class(
            "edge_provenance_rejection",
            "cross_component.declared_edge_hops", evidence,
            f"the edge provenance consumer refused event "
            f"{rejection.get('event_id')!r}: {rejection.get('reason')!r}")
    certificate_rows = [_certificate_row(row) for row in certificates]
    incomplete_certificates = [row for row in certificate_rows
                               if row["status"] != CERTIFIED]
    for row in incomplete_certificates:
        census.add_class(
            "chain_certificate_incomplete",
            "cross_component.chain_certificate_hops",
            {"certificate_id": row["certificate_id"],
             "direction": row["direction"],
             "source_admission_id": row["source_admission_id"],
             "source_case_id": row["source_case_id"],
             "source_case_index": row["source_case_index"],
             "status": row["status"],
             "missing_hops": list(row["missing_hops"]),
             "first_missing_hop": row["first_missing_hop"],
             "hop_ids": list(row["hop_ids"]),
             "hop_event_ids": list(row["hop_event_ids"]),
             "serial_token_status": row["serial_token_status"],
             "reason": row["reason"]},
            f"chain certificate {row['certificate_id']} ({row['direction']}) is "
            f"{row['status']} with missing hops {row['missing_hops']} starting "
            f"at {row['first_missing_hop']!r}")

    # -- truncation (fail-closed) -------------------------------------------
    truncated = _apply_truncation(census, max_findings_per_class)

    # -- declaration constraints --------------------------------------------
    declaration = _declaration_constraints(directory, compiled, contract,
                                           manifest, limits)
    expectations = _check_expectations(manifest)

    # -- assemble ------------------------------------------------------------
    protocol_identity = {
        "sources": {"receipts": receipt_identity["identity"],
                    "checker": _checker_identity(manifest),
                    "status_vocabulary_divergence":
                        receipt_identity.get("status_vocabulary_divergence", []),
                    "observed_statuses":
                        receipt_identity.get("observed_statuses", [])},
        "observed_record_counts": {"receipt": receipt_identity["receipts"],
                                   "receipt_with_violations":
                                       receipt_identity["violations"],
                                   "case_refused_before_rtl":
                                       receipt_identity["refused"]},
    }
    cross_identity = {
        "observed_record_count": len(edge_rows) + len(certificate_rows),
        "edge_status": _edge_status(edge_rows, edge_report, contract_keys,
                                    declaration_available=compiled is not None),
        "chain_certificates": _chain_certificate_status(
            certificate_rows, incomplete_certificates),
        "provenance": (None if edge_report is None else {
            "schema_version": edge_report.get("schema_version"),
            "edge_schema_version": edge_report.get("edge_schema_version"),
            "contract_identity": edge_report.get("contract_identity"),
            "graph_sha256": edge_report.get("graph_sha256"),
            "events_observed": edge_report.get("events_observed"),
            "events_rejected": edge_report.get("events_rejected"),
            "last_event_id": edge_report.get("last_event_id"),
            "resets": edge_report.get("resets"),
            "dropped_late_hops": edge_report.get("dropped_late_hops"),
            "bounds": edge_report.get("bounds"),
            "proof_scope": edge_report.get("proof_scope"),
        }),
    }
    cpu_identity = {
        "observed_record_count": sum(
            cpu_ip_summary["observed_record_counts"].values()),
        "observed_record_counts": cpu_ip_summary["observed_record_counts"],
        "irq": cpu_ip_summary["irq"],
        "retirement": cpu_ip_summary["retirement"],
        "consumption": cpu_ip_summary["consumption"],
    }
    classes = {
        CLASS_PROTOCOL_CHECKER: _class_document(
            CLASS_PROTOCOL_CHECKER, census, protocol_identity, limits, truncated),
        CLASS_CROSS_COMPONENT: _class_document(
            CLASS_CROSS_COMPONENT, census, cross_identity, limits, truncated),
        CLASS_CPU_IP: _class_document(
            CLASS_CPU_IP, census, cpu_identity, limits, truncated),
    }
    _set_availability(classes[CLASS_PROTOCOL_CHECKER], receipt_identity)
    _set_availability(classes[CLASS_CROSS_COMPONENT], None,
                      cross_reason=(
                          "online_session_manifest.json is missing, so this "
                          "run declares no runtime path contract and holds no "
                          "chain certificate; the class is null with this "
                          "reason instead of 0"))
    _set_availability(classes[CLASS_CPU_IP], None,
                      cpu_ip_summary["observed_record_counts"],
                      empty_reason="no cpu_ip_behaviour record (retirement, "
                      "IRQ acceptance/expiry or consumption) exists in this "
                      "run's saved trace, so the class is reported as null "
                      "with this reason instead of a fabricated zero")

    report = {
        "schema_version": SCHEMA_VERSION,
        "run_dir": str(directory),
        "assertion_classes": classes,
        "declaration_constraints": declaration,
        "check_expectations": expectations,
        "not_silently_filtered": _fail_closed_section(census, None),
        "trace": _trace_identity(stream, events_ingested),
        "engine": {
            "module": _module_identity("myfuzz.scenario.assertion_classes"),
            "producers": {
                "edge_provenance":
                    _module_identity("myfuzz.scenario.edge_provenance"),
                "chain_certificates":
                    _module_identity("myfuzz.scenario.chain_certificates"),
                "acceptance_metrics":
                    _module_identity("myfuzz.scenario.acceptance_metrics"),
            },
        },
        "bounds": {"chain_max_pending": max_pending,
                   "chain_max_event_gap": max_event_gap,
                   "require_native_receipts": require_native_receipts,
                   "edge_max_pending": edge_max_pending,
                   "edge_max_event_gap": edge_max_event_gap,
                   "ingest_batch_size": ingest_batch_size,
                   "max_findings_per_class": max_findings_per_class},
        "limits": limits,
    }
    unrepresented = _representation_check(report, census)
    report["not_silently_filtered"] = _fail_closed_section(census, unrepresented)
    return report


def _set_availability(section: dict, receipt_identity: Mapping | None,
                      counts: Mapping | None = None, *,
                      cross_reason: str | None = None,
                      empty_reason: str | None = None) -> None:
    findings = section["findings"]
    name = section["assertion_class"]
    if name == CLASS_PROTOCOL_CHECKER:
        present = bool(receipt_identity and receipt_identity["present"])
        section["data_present"] = present
        section["observed_record_count"] = (
            receipt_identity["receipts"] if present else None)
        if present:
            section["finding_count"] = len(findings)
        else:
            section["finding_count"] = None
            section["finding_count_reason"] = (
                "receipts.jsonl is missing, so the run's own checker produced "
                "no readable finding stream; the class is null, not 0")
        return
    if name == CLASS_CROSS_COMPONENT:
        present = section["observed_record_count"] not in (None, 0) \
            or section["edge_status"]["available"]
        section["data_present"] = present
        if present:
            section["finding_count"] = len(findings)
        else:
            section["finding_count"] = None
            section["finding_count_reason"] = cross_reason or (
                "this run holds neither a readable runtime path declaration "
                "nor a chain certificate, so the class is null with this "
                "reason instead of 0")
        return
    present = bool(counts)
    section["data_present"] = present
    if present:
        section["finding_count"] = len(findings)
    else:
        section["finding_count"] = None
        section["finding_count_reason"] = empty_reason


def _checker_identity(manifest: Mapping | None) -> dict | None:
    if not isinstance(manifest, Mapping):
        return None
    checker = manifest.get("checker")
    if not isinstance(checker, Mapping):
        return None
    source = checker.get("source")
    return {
        "module": checker.get("module"),
        "qualname": checker.get("qualname"),
        "source_path": (source or {}).get("path")
        if isinstance(source, Mapping) else None,
        "source_sha256": (source or {}).get("sha256")
        if isinstance(source, Mapping) else None,
    }


def _edge_status(rows: Iterable[Mapping], edge_report: Mapping | None,
                 contract_keys: frozenset, *,
                 declaration_available: bool) -> dict:
    rows = list(rows)
    counts = Counter(row["status"] for row in rows)
    unavailable_reason = None
    if not declaration_available:
        unavailable_reason = (
            "online_session_manifest.json declares no readable runtime_paths "
            "document, so this run's declared runtime edges could not be "
            "resolved; the edges are unknown here and are never reported as "
            "certified or as a zero")
    elif edge_report is None:
        unavailable_reason = (
            "the runtime path declaration could not be compiled into a "
            "contract, so no declared edge row exists")
    return {
        "schema_version": (edge_report or {}).get("schema_version"),
        "edge_schema_version": (edge_report or {}).get("edge_schema_version"),
        "available": unavailable_reason is None,
        "unavailable_reason": unavailable_reason,
        "total": len(rows),
        "declared_runtime_edge_count": len(contract_keys),
        "certified": counts.get(CERTIFIED, 0),
        "incomplete": counts.get(INCOMPLETE, 0),
        "unknown": counts.get(UNKNOWN, 0),
        "not_a_runtime_edge_count": counts.get(NOT_A_RUNTIME_EDGE, 0),
        "unresolved": counts.get(None, 0),
        "edges": sorted(rows, key=lambda row: (row["rule_index"] or 0,
                                               row["prerequisite_index"] or 0)),
    }


def _chain_certificate_status(rows: Iterable[Mapping],
                              incomplete: Iterable[Mapping]) -> dict:
    rows = list(rows)
    counts = Counter(row["status"] for row in rows)
    by_direction: dict[str, dict] = {}
    for row in rows:
        state = by_direction.setdefault(
            row["direction"] or "unknown",
            {"certified": 0, "incomplete": 0, "unresolved": 0})
        if row["status"] == CERTIFIED:
            state["certified"] += 1
        elif row["status"] == INCOMPLETE:
            state["incomplete"] += 1
        else:
            state["unresolved"] += 1
    return {
        "schema_version": CHAIN_CERTIFICATE_SCHEMA_VERSION,
        "certified_count": counts.get(CERTIFIED, 0),
        "incomplete_count": counts.get(INCOMPLETE, 0),
        "certificate_count": len(rows),
        "by_direction": {name: by_direction[name] for name in sorted(by_direction)},
        "incomplete_certificates": sorted(
            (dict(row) for row in incomplete),
            key=lambda row: (row["direction"] or "", row["certificate_id"] or "")),
        "reason": None,
    }


def _declaration_constraints(directory: Path, compiled: Mapping | None,
                             contract: RuntimePathContract | None,
                             manifest: Mapping | None,
                             limits: list[dict]) -> dict:
    identity_document = _read_json(directory / "online_run_identity.json")
    identity = (identity_document.get("identity")
                if isinstance(identity_document, Mapping) else None)
    run_config = (identity.get("run_config")
                  if isinstance(identity, Mapping) else None)
    decoder = _read_json(directory / "decoder_manifest.json")
    targets = _read_json(directory / "targets.json")
    plan = _read_json(directory / "online_plan.json")
    if not isinstance(decoder, Mapping):
        _limit(limits, "declaration_constraints.decoder_manifest",
               "decoder_manifest.json is missing or not a JSON object")
    if not isinstance(targets, list):
        _limit(limits, "declaration_constraints.declared_targets",
               "targets.json is missing or not a JSON list")

    declared_rows = _declared_edges(compiled) if isinstance(compiled, Mapping) \
        else ()
    contract_keys = (frozenset(edge.key for edge in contract.edges)
                     if contract is not None else frozenset())
    paths: list[dict] = []
    declarations = (compiled.get("declaration")
                    if isinstance(compiled, Mapping) else None)
    selections = (declarations.get("selections")
                  if isinstance(declarations, Mapping) else None)
    if isinstance(selections, list):
        for selection in selections:
            if not isinstance(selection, Mapping):
                continue
            edges = [edge for edge in (selection.get("edges") or ())
                     if isinstance(edge, Mapping)]
            runtime = [edge for edge in edges
                       if (edge.get("rule_index"),
                           edge.get("prerequisite_index")) in contract_keys]
            paths.append({
                "direction": selection.get("direction"),
                "path_id": selection.get("path_id"),
                "target": selection.get("target"),
                "declared_hop_count": len(edges),
                "runtime_hop_count": len(runtime),
                "not_a_runtime_edge_hop_count": len(edges) - len(runtime),
            })
    declared_edges = []
    edge_index = _edge_index(compiled) if isinstance(compiled, Mapping) else {}
    for key in sorted(edge_index):
        state = edge_index[key]
        declared_edges.append({
            "rule_index": key[0],
            "prerequisite_index": key[1],
            "runtime_edge": key in contract_keys,
            "directions": list(state["directions"]),
            "path_ids": list(state["path_ids"]),
            "declared_kinds": list(state["declared_kinds"]),
        })
    return {
        "run_identity": {
            "name": "online_run_identity.json",
            "schema_version": (identity_document or {}).get("schema_version")
            if isinstance(identity_document, Mapping) else None,
            "sha256": (identity_document or {}).get("sha256")
            if isinstance(identity_document, Mapping) else None,
            "execution_mode": (identity or {}).get("execution_mode")
            if isinstance(identity, Mapping) else None,
            "run_id": (run_config or {}).get("run_id")
            if isinstance(run_config, Mapping) else None,
            "identity_file": _file_identity(directory / "online_run_identity.json"),
        },
        "decoder_manifest": {
            "name": "decoder_manifest.json",
            "schema_version": (decoder or {}).get("schema_version")
            if isinstance(decoder, Mapping) else None,
            "sha256": _file_identity(directory / "decoder_manifest.json")["sha256"],
            "flow_by_target": dict((decoder or {}).get("flow_by_target") or {})
            if isinstance(decoder, Mapping) else {},
            "allowed_mmio_operations": list(
                (decoder or {}).get("allowed_mmio_operations") or ())
            if isinstance(decoder, Mapping) else [],
            "dependency_mode": (decoder or {}).get("dependency_mode")
            if isinstance(decoder, Mapping) else None,
            "declared_graph_edge_count": len(
                ((decoder or {}).get("graph") or {}).get("edges") or ())
            if isinstance(decoder, Mapping) else None,
        },
        "runtime_path_contract": {
            "source": "online_session_manifest.json:runtime_paths.declaration",
            "available": contract is not None,
            "graph_sha256": (contract.graph_sha256 if contract is not None
                             else None),
            "contract_identity_sha256": (contract.identity_sha256
                                         if contract is not None else None),
            "status": (compiled or {}).get("proof_scope")
            if isinstance(compiled, Mapping) else None,
            "proof_scope": (compiled or {}).get("proof_scope")
            if isinstance(compiled, Mapping) else None,
            "runtime_causality_verified": (compiled or {}).get(
                "runtime_causality_verified")
            if isinstance(compiled, Mapping) else None,
            "resource_versions_verified": (compiled or {}).get(
                "resource_versions_verified")
            if isinstance(compiled, Mapping) else None,
            "declared_hop_count": len(declared_rows),
            "declared_runtime_edge_count": len(contract_keys),
            "declared_paths": paths,
            "declared_edges": declared_edges,
        },
        "declared_targets": [dict(row) for row in targets
                             if isinstance(row, Mapping)]
        if isinstance(targets, list) else None,
        "plan": {
            "name": "online_plan.json",
            "schema_version": (plan or {}).get("schema_version")
            if isinstance(plan, Mapping) else None,
            "case_count": len((plan or {}).get("cases") or ())
            if isinstance(plan, Mapping) else None,
            "source_admission_count": len(
                ((plan or {}).get("source_admissions") or {}).get("admissions")
                or ()) if isinstance(plan, Mapping) else None,
        },
    }


def _check_expectations(manifest: Mapping | None) -> dict:
    return {
        "schema_version": "p5_check_expectations.v1",
        "run_checker": _checker_identity(manifest),
        "expectations": [dict(row) for row in EXPECTATIONS],
    }


def _trace_identity(stream: TraceEventStream, events_ingested: int) -> dict:
    descriptor = stream.descriptor
    return {
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
        "events_ingested": events_ingested,
    }


def _fail_closed_section(census: _Census,
                         unrepresented: list[dict] | None) -> dict:
    class_findings = {name: census.class_rows(name) for name in ASSERTION_CLASSES}
    cross_rows = class_findings[CLASS_CROSS_COMPONENT]
    buckets = {name: census.bucket_rows(name) for name in FAIL_CLOSED_BUCKETS}
    by_record_class = Counter(row["record_class"] for row in census.rows)
    rows = census.sorted_rows()
    if unrepresented is None:
        unrepresented = [row for row in rows if row["location"] == UNREPRESENTED]
    represented = len(rows) - len(unrepresented)
    reasons = [row["reason"] for row in unrepresented]
    gate_reason = None
    if reasons:
        gate_reason = (f"{len(unrepresented)} abnormal record(s) are not "
                       "represented in this report: " + " | ".join(reasons[:3]))
    return {
        "criterion": _NOT_SILENTLY_FILTERED_CRITERION,
        "abnormal_record_count": len(rows),
        "represented_record_count": represented,
        "by_record_class": {name: by_record_class[name]
                            for name in sorted(by_record_class)},
        "enumerated": rows,
        "unrepresented": unrepresented,
        "not_ready_declared_paths": {
            "not_a_runtime_edge": [row for row in cross_rows
                                   if row["record_class"] == "not_a_runtime_edge"],
            "incomplete": [row for row in cross_rows
                           if row["record_class"] in ("runtime_edge_incomplete",
                                                      "chain_certificate_incomplete")],
            "unknown": [row for row in cross_rows
                        if row["record_class"] == "runtime_edge_unknown"],
        },
        **buckets,
        "statement": (
            "every abnormal record this run holds is enumerated above with its "
            "own exact evidence keys: the records were reported, not dropped "
            "because a declared path, edge or hop was not ready, and no "
            "finding was rewritten into a complete case"),
        "gate": {
            "passed": not unrepresented,
            "exit_code": 0 if not unrepresented else 2,
            "reason": gate_reason,
            "criterion": ("fail-closed: the gate passes only when every "
                          "abnormal record the run holds is present in this "
                          "document at its declared location, verified "
                          "structurally against the document itself"),
        },
    }


__all__ = ["ASSERTION_CLASSES", "CLASS_CROSS_COMPONENT", "CLASS_CPU_IP",
           "CLASS_PROTOCOL_CHECKER", "EXPECTATIONS", "NOT_A_RUNTIME_EDGE",
           "SCHEMA_VERSION", "assertion_class_report"]
