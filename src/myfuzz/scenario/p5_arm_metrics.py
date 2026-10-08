"""One P5 per-arm document for a fixed-budget comparison of saved runs.

The P5 checklist requires that a single fixed-budget comparison report states,
per arm, the one-time compilation/initialization cost, the per-case admission
statistics, the real RTL transactions, the Router/Scheduler breakdown, the
incremental feedback, the log/evidence footprint, the p50/p95 latencies, the
effective cases/second, the complete real chains/second, the coverage-novelty
rates and the invalid/timeout ratio.  Before this module those numbers lived in
different producers (``myfuzz.scenario.acceptance_metrics.analyze_run``,
``myfuzz.scenario.paired_efficiency``, the run's own ``report.json`` phase
timings and the chain-certificate producer), so no single document could state
them together.

This module is a *read-only aggregator*.  It never starts RTL, Verilator,
cargo or the fuzz client; it reads the saved artifacts at most twice
(``receipts.jsonl`` is streamed once by :func:`acceptance_metrics.analyze_run`
and once by the admission scan here, and the trace container is streamed once
by ``analyze_run``).  Nothing is materialized: an ``MFZ1`` zlib block or a
JSONL line is decoded one item at a time.

Every leaf of the emitted document is ``{"value", "source", "reason"}``:

* ``source`` names the artifact key the number came from, so a reader can
  re-derive it without reading this module;
* a quantity whose inputs are absent from the arm is ``value = null`` with a
  non-empty ``reason`` -- never ``0`` and never a silently dropped key;
* ``reason`` is ``null`` exactly when a value was measured, so ``null`` in the
  value slot is unambiguous.

Number provenance (what is reused and what is re-derived):

* effective cases/second, status counts, invalid/timeout ratio, certified
  chains, the first-missing-hop histogram, target-bit and witnessed-edge
  novelty, phase-timing percentiles and finalization timings are copied
  verbatim from ``acceptance_metrics.analyze_run`` -- the same call
  ``paired_efficiency.compare_runs`` summarizes per group, so the coverage and
  efficiency numbers are bit-identical to that module;
* p50/p95 for the admission scan use ``acceptance_metrics._percentiles``, the
  very function ``paired_efficiency`` imports for its own percentiles;
* cold-start initialization reuses ``paired_efficiency.load_cold_baseline`` and
  the same ``cold_start.json:cases[].init_seconds`` window;
* per-case local ticks, submit timings, coverage records, raw records,
  candidate dispositions and interaction counters are re-derived here from
  ``receipts.jsonl`` because no shipped module exposes them.

Declared boundaries (also emitted in the document's ``boundaries`` list):

* the scenario online report carries no RTL compile/elaboration timing, so
  ``one_time_compile_init.compilation_seconds`` is ``null`` with that reason;
* a continuous session charges no initialization to any single case, so its
  ``per_case_initialization_seconds`` is ``null`` with that reason -- the
  one-time cost it does carry is ``finalization_timing_seconds``;
* ``online_runner_timing_seconds`` phases are nested (scheduler contains
  runner contains router), so their sums must not be added together or read as
  pure RTL time;
* ``report.json:record_semantics`` declares the receipts as mutation decisions
  rather than DUT cycles, and ``total_local_ticks_semantics`` declares the
  ticks as cost-only;
* the chain counts are the certificates the injected producer emitted for the
  artifact; they state artifact capability, not independently re-derived hop
  evidence;
* an arm whose ``report.json`` is a foreign schema with no receipts and no
  scenario trace is reported as ``not_a_scenario_online_session`` with every
  metric ``null`` and the detected schema in the reason.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
import json
from pathlib import Path

from myfuzz.scenario.acceptance_metrics import (
    CHAIN_DIRECTIONS,
    DEFAULT_INGEST_BATCH_SIZE,
    DEFAULT_MAX_CERTIFICATES,
    _finite_non_negative,
    _percentiles,
    analyze_run,
)
from myfuzz.scenario.paired_efficiency import (
    COLD_BASELINE_NAME,
    COLD_INIT_SOURCE,
    RECEIPT_TOTAL_SOURCE,
    PairedEfficiencyInputError,
    load_cold_baseline,
)


SCHEMA_VERSION = "p5_arm_metrics.v1"
REPORT_SCHEMA_NAME = "p5_arm_metrics"
DEFAULT_MAX_TIMING_SAMPLES = 200_000

RECEIPTS_NAME = "receipts.jsonl"
REPORT_NAME = "report.json"
PLAN_NAME = "online_plan.json"
IDENTITY_NAME = "online_run_identity.json"
MANIFEST_NAME = "online_session_manifest.json"
CLIENT_LOG_NAME = "client.log"
TRACE_META_NAME = "online_final_trace.meta.json"
TRACE_MONOLITHIC_NAME = "online_final_trace.json"
TRACE_CONTAINER_NAMES = ("online_events.jsonl", "online_events.zlib")
EVIDENCE_FILES = (
    RECEIPTS_NAME, REPORT_NAME, PLAN_NAME, IDENTITY_NAME, MANIFEST_NAME,
    CLIENT_LOG_NAME, TRACE_META_NAME, TRACE_MONOLITHIC_NAME,
    COLD_BASELINE_NAME, "decoder_manifest.json", "targets.json",
    "mutation_hint.json", "rfuzz.toml", "seed.bin",
) + TRACE_CONTAINER_NAMES

ARM_KIND_CONTINUOUS = "scenario_online_cases"
ARM_KIND_COLD = "scenario_online_cases_per_case_cold_start"
ARM_KIND_UNLABELLED = "scenario_online_session_unlabelled"
ARM_KIND_FOREIGN = "not_a_scenario_online_session"
SESSION_EXECUTION_MODES = {
    "online_cases": ARM_KIND_CONTINUOUS,
    "online_cases_per_case_cold_start": ARM_KIND_COLD,
}

CHECKLIST_METRIC_GROUPS = (
    "one_time_compile_init",
    "per_case_admission",
    "real_rtl_transactions",
    "router_scheduler",
    "incremental_feedback",
    "log_evidence",
    "latency_percentiles",
    "effective_cases_per_second",
    "certified_chains_per_second",
    "coverage_novelty",
    "invalid_or_timeout_ratio",
    "status_counts",
)

#: ``group -> ((leaf, artifact key), ...)``.  The leaf set is static, so a
#: missing input can only change a leaf's value/reason, never the shape.
GROUP_SPECS: dict[str, tuple[tuple[str, str], ...]] = {
    "one_time_compile_init": (
        ("compilation_seconds",
         "report.json (no RTL compile/elaboration timing key exists in the "
         "scenario online run report)"),
        ("finalization_timing_seconds", "report.json:finalization_timing_seconds"),
        ("finalization_total_before_report_seconds",
         "report.json:finalization_timing_seconds.total_before_report"),
        ("effective_search_seconds", "report.json:effective_search_seconds"),
        ("elapsed_seconds", "report.json:elapsed_seconds"),
        ("elapsed_minus_effective_search_seconds",
         "report.json:elapsed_seconds - report.json:effective_search_seconds "
         "(derived)"),
        ("cold_start_baseline_case_count", "cold_start.json:case_count"),
        ("cold_start_init_seconds_p50", COLD_INIT_SOURCE),
        ("cold_start_init_seconds_p95", COLD_INIT_SOURCE),
        ("cold_start_init_seconds_total", COLD_INIT_SOURCE + " (sum)"),
        ("cold_start_document_init_seconds_total",
         "cold_start.json:init_seconds_total"),
        ("cold_start_cases_with_init_seconds", COLD_INIT_SOURCE),
        ("cold_start_share_of_elapsed",
         f"{COLD_INIT_SOURCE} / report.json:elapsed_seconds (derived)"),
        ("cold_start_share_of_wall_clock_seconds",
         f"{COLD_INIT_SOURCE} / report.json:wall_clock_seconds (derived)"),
        ("per_case_initialization_seconds", COLD_INIT_SOURCE),
    ),
    "per_case_admission": (
        ("receipt_rows", "receipts.jsonl (decoded rows)"),
        ("reported_tests", "report.json:tests"),
        ("admissions_total", "online_plan.json:source_admissions.admissions"),
        ("fuzz_source_admissions",
         "online_plan.json:source_admissions.admissions[].role"),
        ("admissions_by_role",
         "online_plan.json:source_admissions.admissions[].role"),
        ("candidate_dispositions", "receipts.jsonl:candidate_disposition"),
        ("candidate_disposition_reasons",
         "receipts.jsonl:candidate_disposition_reason"),
        ("cases_with_online_submit_timing_seconds",
         "receipts.jsonl:online_submit_timing_seconds"),
        ("local_command_count_total",
         "receipts.jsonl:online_submit_timing_seconds.local_command_count"),
        ("local_command_count_p50",
         "receipts.jsonl:online_submit_timing_seconds.local_command_count"),
        ("local_command_count_p95",
         "receipts.jsonl:online_submit_timing_seconds.local_command_count"),
        ("local_command_roundtrip_seconds_p50",
         "receipts.jsonl:online_submit_timing_seconds.local_command_roundtrip"),
        ("local_command_roundtrip_seconds_p95",
         "receipts.jsonl:online_submit_timing_seconds.local_command_roundtrip"),
        ("host_remainder_seconds_p50",
         "receipts.jsonl:online_submit_timing_seconds.host_remainder"),
        ("host_remainder_seconds_p95",
         "receipts.jsonl:online_submit_timing_seconds.host_remainder"),
        ("cases_with_local_ticks", "receipts.jsonl:local_ticks"),
        ("local_ticks_by_component_sum",
         "receipts.jsonl:local_ticks.<component> (sum)"),
        ("total_local_ticks_sum", "receipts.jsonl:total_local_ticks (sum)"),
        ("cases_with_total_local_ticks", "receipts.jsonl:total_local_ticks"),
        ("coverage_records", "receipts.jsonl:coverage_hex"),
        ("coverage_width_bytes", "receipts.jsonl:coverage_hex"),
        ("raw_record_count", "receipts.jsonl:online_raw_records_hex"),
        ("cases_with_violations", "receipts.jsonl:violations"),
    ),
    "real_rtl_transactions": (
        ("cases_with_runner_timing",
         "receipts.jsonl:online_runner_timing_seconds"),
        ("cases_with_rtl_case_committed",
         "receipts.jsonl:candidate_disposition_reason"),
        ("cases_with_total_local_ticks", "receipts.jsonl:total_local_ticks"),
        ("record_semantics", "report.json:record_semantics"),
        ("total_local_ticks_semantics",
         "report.json:total_local_ticks_semantics"),
        ("clock_model", "report.json:clock_model"),
    ),
    "router_scheduler": (
        ("online_runner_timing_seconds",
         "receipts.jsonl:online_runner_timing_seconds"),
        ("cases_with_router_transact",
         "receipts.jsonl:online_runner_timing_seconds.router_transact"),
        ("router_transact_seconds_sum",
         "receipts.jsonl:online_runner_timing_seconds.router_transact (sum)"),
        ("cases_with_scheduler_batch",
         "receipts.jsonl:online_runner_timing_seconds.scheduler_batch"),
        ("scheduler_batch_seconds_sum",
         "receipts.jsonl:online_runner_timing_seconds.scheduler_batch (sum)"),
        ("cases_with_observed_output_route",
         "receipts.jsonl:online_runner_timing_seconds.observed_output_route"),
        ("observed_output_route_seconds_sum",
         "receipts.jsonl:online_runner_timing_seconds.observed_output_route "
         "(sum)"),
        ("nested_phase_semantics", "report.json (declared nested timing contract)"),
    ),
    "incremental_feedback": (
        ("completed_feedback_exchanges",
         "report.json:completed_feedback_exchanges"),
        ("mutation_hint_updates", "report.json:mutation_hint_updates"),
        ("mutation_hint_schema", "report.json:mutation_hint_schema"),
        ("cases_with_interaction_new_features",
         "receipts.jsonl:interaction_new_features"),
        ("cases_with_interaction_feature_deltas",
         "receipts.jsonl:interaction_feature_deltas"),
        ("cases_with_interaction_source_gains",
         "receipts.jsonl:interaction_source_gains"),
        ("cases_deferred", "receipts.jsonl:interaction_deferred"),
        ("source_action_gate_enforce",
         "report.json:source_action_gate.enforce"),
        ("source_action_gate_action_count",
         "report.json:source_action_gate.action_ids"),
        ("path_switch", "report.json:path_switch"),
        ("closed_loop_energy_enabled",
         "report.json:closed_loop_energy.enabled"),
        ("closed_loop_energy_counts", "report.json:closed_loop_energy.counts"),
    ),
    "log_evidence": (
        ("trace_format", f"{TRACE_META_NAME}:schema_version / "
                         f"{TRACE_MONOLITHIC_NAME}"),
        ("trace_meta_schema_version", f"{TRACE_META_NAME}:schema_version"),
        ("trace_events_file", f"{TRACE_META_NAME}:events_file"),
        ("trace_bytes", "trace container file (bytes)"),
        ("trace_meta_container_split",
         f"{TRACE_META_NAME} + {' / '.join(TRACE_CONTAINER_NAMES)}"),
        ("trace_events_ingested", "trace container file (events decoded)"),
        ("trace_declared_event_count", f"{TRACE_META_NAME}:event_count"),
        ("trace_event_count_match",
         f"{TRACE_META_NAME}:event_count vs decoded events"),
        ("trace_semantic_sha256_verified",
         f"{TRACE_META_NAME}:semantic_sha256 vs recomputed digest"),
        ("trace_meta_bytes", f"{TRACE_META_NAME} (bytes)"),
        ("receipts_bytes", f"{RECEIPTS_NAME} (bytes)"),
        ("client_log_bytes", f"{CLIENT_LOG_NAME} (bytes)"),
        ("session_manifest_bytes", f"{MANIFEST_NAME} (bytes)"),
        ("evidence_footprint_bytes", "run directory artifacts (bytes, sum)"),
    ),
    "latency_percentiles": (
        ("online_phase_timing_seconds",
         "receipts.jsonl:online_phase_timing_seconds"),
        ("per_case_total_seconds",
         RECEIPT_TOTAL_SOURCE),
        ("cases_with_online_phase_timing_seconds",
         "receipts.jsonl:online_phase_timing_seconds"),
        ("invalid_timing_values",
         "receipts.jsonl:online_phase_timing_seconds / "
         "online_runner_timing_seconds"),
    ),
    "effective_cases_per_second": (
        ("effective_cases_per_second",
         "receipts.jsonl:status / report.json:effective_search_seconds"),
        ("complete_status_count", "receipts.jsonl:status"),
        ("denominator_seconds", "report.json:effective_search_seconds"),
        ("all_receipt_cases_per_second",
         "receipts.jsonl (rows) / report.json:effective_search_seconds"),
    ),
    "certified_chains_per_second": (
        ("certified_chains",
         "trace events (runtime_chain_certificate.v1 certificates)"),
        ("certified_chains_per_second",
         "trace events (certificates) / report.json:effective_search_seconds"),
        ("certified_chains_by_direction",
         "trace events (certificates:direction)"),
        ("certified_chains_same_case",
         "trace events (certificates:source/endpoint_case_index)"),
        ("certified_chains_cross_case",
         "trace events (certificates:source/endpoint_case_index)"),
        ("incomplete_certificates",
         "trace events (incomplete certificates)"),
        ("first_missing_hop_histogram",
         "trace events (incomplete certificates:missing_hops[0])"),
        ("unresolvable_missing_hops",
         "trace events (incomplete certificates:missing_hops[0])"),
        ("certified_admissions",
         "trace events (certificates:source_admission_id)"),
        ("chain_completion_by_admission",
         "online_plan.json:source_admissions.admissions joined to certificates"),
        ("chain_producer_available", "chain_certificates.ChainCertificates"),
        ("semantics", "trace events (declared certificate contract)"),
    ),
    "coverage_novelty": (
        ("first_seen_target_bits", "receipts.jsonl:coverage_hex"),
        ("first_seen_target_slots", "receipts.jsonl:coverage_hex"),
        ("coverage_width_bytes", "receipts.jsonl:coverage_hex"),
        ("new_target_bits_per_second",
         "receipts.jsonl:coverage_hex / report.json:effective_search_seconds"),
        ("new_target_slots_per_second",
         "receipts.jsonl:coverage_hex / report.json:effective_search_seconds"),
        ("unique_witnessed_edges",
         "trace events:provenance.edge_candidates"),
        ("edge_candidate_observations",
         "trace events:provenance.edge_candidates"),
        ("new_witnessed_edges_per_second",
         "trace events:provenance.edge_candidates / "
         "report.json:effective_search_seconds"),
        ("method", "p5_arm_metrics.v1 (declared reuse)"),
    ),
    "invalid_or_timeout_ratio": (
        ("invalid_or_timeout_ratio", "receipts.jsonl:status"),
        ("invalid_or_timeout_denominator", "receipts.jsonl (decoded rows)"),
        ("complete_count", "receipts.jsonl:status"),
        ("invalid_count", "receipts.jsonl:status"),
        ("timeout_count", "receipts.jsonl:status"),
        ("finding_count", "receipts.jsonl:status"),
        ("unclassified_statuses", "receipts.jsonl:status"),
        ("definition", "acceptance_metrics.invalid_or_timeout_detail.definition"),
    ),
    "status_counts": (
        ("status_counts", "receipts.jsonl:status"),
        ("status_counts_total", "receipts.jsonl (decoded rows)"),
        ("reported_statuses", "report.json:statuses"),
        ("reports_agree", "report.json:statuses vs receipts.jsonl:status"),
    ),
}

COVERAGE_NOVELTY_METHOD = (
    "acceptance_metrics.analyze_run -> local_target_novelty."
    "new_target_bits_per_second and witnessed_edge_novelty."
    "new_edges_per_second; paired_efficiency.compare_runs copies exactly these "
    "two fields into groups.<label>.coverage_novelty / "
    "groups.<label>.witnessed_edge_novelty, so the rates here are bit-identical "
    "to that module's per-group rates"
)

CONTINUOUS_INIT_REASON = (
    "the continuous session charges no initialization to any single case: its "
    "one-time build/init is outside every per-case total and is not recorded per "
    "case, so this quantity stays null rather than 0"
)

COMPILE_REASON = (
    "no artifact in the run directory records RTL compile/elaboration seconds; "
    "report.json carries only finalization_timing_seconds (one-time, after the "
    "search) and the RTL build is prebuilt outside the online session, so this "
    "stays null rather than 0"
)

NESTED_PHASE_SEMANTICS = (
    "online_runner_timing_seconds phases are nested per case (scheduler_batch "
    "contains runner_step, which contains the router phases); the sums in this "
    "group must not be added together and are not pure RTL time"
)

BOUNDARIES = (
    "read-only aggregation of saved run directories; no RTL, Verilator, cargo "
    "or fuzz process is started and no artifact is written back into a run",
    "receipts.jsonl is streamed twice (once by acceptance_metrics.analyze_run, "
    "once by the admission scan here) and the trace container is streamed once "
    "by analyze_run; nothing is materialized and memory stays bounded by the "
    "event batch and the timing-sample cap",
    COMPILE_REASON,
    CONTINUOUS_INIT_REASON,
    NESTED_PHASE_SEMANTICS,
    "report.json:record_semantics declares the receipts as mutation decisions "
    "rather than DUT cycles, and report.json:total_local_ticks_semantics "
    "declares the local ticks as cost-only; neither is a DUT cycle count",
    "certified chain counts are the certificates the frozen producer emitted "
    "for the artifact; they state artifact capability and do not independently "
    "re-derive hop evidence from raw events",
    "the invalid/timeout ratio is null whenever a receipt status falls outside "
    "the shipped invalid/timeout sets; the exact status counts are still "
    "reported, and the ratio is never widened to make a status fit",
    "cold_start.json is written by scripts/bench_ibex_pulp_cold_start.py for the "
    "per-case cold-start group; a continuous online session has no such document "
    "and its per-case initialization stays null",
)


class P5ArmMetricsInputError(ValueError):
    """Raised when a run directory cannot be aggregated at all."""


# --------------------------------------------------------------------------
# leaf plumbing
# --------------------------------------------------------------------------


def _leaf(value: object, source: str, reason: str | None) -> dict:
    if value is None:
        if not isinstance(reason, str) or not reason:
            raise ValueError(
                f"a null metric must carry a reason (source {source!r})")
        return {"value": None, "source": source, "reason": reason}
    if reason is not None:
        raise ValueError(
            f"a measured metric must not carry a reason (source {source!r})")
    return {"value": value, "source": source, "reason": None}


class _Values:
    """Collects ``(group, leaf) -> (value, reason)`` before assembly."""

    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], tuple[object, str | None]] = {}

    def put(self, group: str, leaf: str, value: object,
            reason: str | None = None) -> None:
        if value is None:
            if reason:
                self._entries[(group, leaf)] = (None, reason)
            return
        self._entries[(group, leaf)] = (value, None)

    def unavailable(self, group: str, leaf: str, reason: str) -> None:
        self._entries[(group, leaf)] = (None, reason)

    def get(self, group: str, leaf: str) -> tuple[object, str | None]:
        return self._entries.get((group, leaf), (None, None))


def _default_reason(source: str) -> str:
    return (f"the artifact key(s) {source} are absent from this run directory, "
            "so this quantity is not measurable")


def _assemble(values: _Values, *, arm_reason: str | None = None) -> dict:
    """Materialize the static skeleton; unset leaves become null + reason."""
    metrics: dict[str, dict[str, dict]] = {}
    for group, leaves in GROUP_SPECS.items():
        block: dict[str, dict] = {}
        for leaf, source in leaves:
            value, reason = values.get(group, leaf)
            if value is None:
                reason = reason or arm_reason or _default_reason(source)
            block[leaf] = _leaf(value, source, reason)
        metrics[group] = block
    return metrics


# --------------------------------------------------------------------------
# artifact readers
# --------------------------------------------------------------------------


def _read_json_object(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise P5ArmMetricsInputError(
            f"invalid JSON in {path.name}: {exc.msg}") from exc
    if not isinstance(document, dict):
        raise P5ArmMetricsInputError(f"{path.name} is not a JSON object")
    return document


def _unavailable_scan(reason: str) -> dict:
    return {
        "available": False, "reason": reason, "rows": None,
        "truncated": False, "coverage_widths": set(),
        "local_ticks_sums": {}, "cases_with_local_ticks": None,
        "total_local_ticks_sum": None, "cases_with_total_local_ticks": None,
        "submit_cases": None, "local_command_counts": [],
        "local_command_roundtrips": [], "host_remainders": [],
        "runner_samples": {}, "runner_sums": {}, "runner_positive": {},
        "coverage_records": None, "raw_record_count": None,
        "cases_with_raw_records": None, "dispositions": {},
        "disposition_reasons": {}, "cases_with_rtl_case_committed": None,
        "cases_with_violations": None, "violations_total": None,
        "interaction_new_features_cases": None,
        "interaction_feature_deltas_cases": None,
        "interaction_source_gains_cases": None, "cases_deferred": None,
    }


def _scan_arm_receipts(path: Path, *, max_timing_samples: int) -> dict:
    """One streaming pass over ``receipts.jsonl`` for the per-case detail.

    The shipped analyzer already streams this file for statuses, coverage and
    phase percentiles; the quantities this scan keeps are the ones no shipped
    module exposes (local ticks, submit timings, dispositions, interaction
    counters).  Only aggregates and a bounded sample list are retained.
    """
    if not path.is_file():
        return _unavailable_scan(
            f"{RECEIPTS_NAME} is absent from this run directory, so no per-case "
            "admission statistic can be derived")
    scan = _unavailable_scan("")
    scan["available"] = True
    scan["reason"] = None
    scan["rows"] = 0
    scan["cases_with_local_ticks"] = 0
    scan["total_local_ticks_sum"] = 0
    scan["cases_with_total_local_ticks"] = 0
    scan["submit_cases"] = 0
    scan["coverage_records"] = 0
    scan["raw_record_count"] = 0
    scan["cases_with_raw_records"] = 0
    scan["cases_with_rtl_case_committed"] = 0
    scan["cases_with_violations"] = 0
    scan["violations_total"] = 0
    scan["interaction_new_features_cases"] = 0
    scan["interaction_feature_deltas_cases"] = 0
    scan["interaction_source_gains_cases"] = 0
    scan["cases_deferred"] = 0

    def keep(samples: list, value: object) -> None:
        number = _finite_non_negative(value)
        if number is None:
            return
        if len(samples) >= max_timing_samples:
            scan["truncated"] = True
            return
        samples.append(number)

    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise P5ArmMetricsInputError(
                    f"invalid JSON on line {number} of {path.name}: "
                    f"{exc.msg}") from exc
            if type(row) is not dict:
                raise P5ArmMetricsInputError(
                    f"non-object JSON value on line {number} of {path.name}")
            scan["rows"] += 1

            ticks = row.get("local_ticks")
            if isinstance(ticks, Mapping):
                scan["cases_with_local_ticks"] += 1
                for component, value in ticks.items():
                    number_value = _finite_non_negative(value)
                    if number_value is None:
                        continue
                    key = component if isinstance(component, str) else "unknown"
                    scan["local_ticks_sums"][key] = (
                        scan["local_ticks_sums"].get(key, 0) + number_value)
            total_ticks = _finite_non_negative(row.get("total_local_ticks"))
            if total_ticks is not None:
                scan["cases_with_total_local_ticks"] += 1
                scan["total_local_ticks_sum"] += total_ticks

            submit = row.get("online_submit_timing_seconds")
            if isinstance(submit, Mapping):
                scan["submit_cases"] += 1
                keep(scan["local_command_counts"], submit.get("local_command_count"))
                keep(scan["local_command_roundtrips"],
                     submit.get("local_command_roundtrip"))
                keep(scan["host_remainders"], submit.get("host_remainder"))

            runner = row.get("online_runner_timing_seconds")
            if isinstance(runner, Mapping):
                for name, value in runner.items():
                    if not isinstance(name, str) or not name:
                        continue
                    number_value = _finite_non_negative(value)
                    if number_value is None:
                        continue
                    samples = scan["runner_samples"].setdefault(name, [])
                    keep(samples, number_value)
                    scan["runner_sums"][name] = (
                        scan["runner_sums"].get(name, 0) + number_value)
                    if number_value > 0:
                        scan["runner_positive"][name] = (
                            scan["runner_positive"].get(name, 0) + 1)

            coverage = row.get("coverage_hex")
            if isinstance(coverage, str) and coverage:
                try:
                    flags = bytes.fromhex(coverage)
                except ValueError:
                    flags = None
                if flags is not None and len(coverage) == 2 * len(flags):
                    scan["coverage_records"] += 1
                    scan["coverage_widths"].add(len(flags))

            raw_records = row.get("online_raw_records_hex")
            if isinstance(raw_records, (list, tuple)):
                scan["cases_with_raw_records"] += 1
                scan["raw_record_count"] += len(raw_records)

            disposition = row.get("candidate_disposition")
            if isinstance(disposition, str) and disposition:
                scan["dispositions"][disposition] = (
                    scan["dispositions"].get(disposition, 0) + 1)
            reason_text = row.get("candidate_disposition_reason")
            if isinstance(reason_text, str) and reason_text:
                scan["disposition_reasons"][reason_text] = (
                    scan["disposition_reasons"].get(reason_text, 0) + 1)
                if reason_text == "rtl_case_committed":
                    scan["cases_with_rtl_case_committed"] += 1

            violations = row.get("violations")
            if isinstance(violations, (list, tuple)) and violations:
                scan["cases_with_violations"] += 1
                scan["violations_total"] += len(violations)

            for field, key in (
                    ("interaction_new_features", "interaction_new_features_cases"),
                    ("interaction_feature_deltas",
                     "interaction_feature_deltas_cases"),
                    ("interaction_source_gains",
                     "interaction_source_gains_cases")):
                value = row.get(field)
                if isinstance(value, (list, tuple, Mapping)) and len(value):
                    scan[key] += 1
            if row.get("interaction_deferred") is True:
                scan["cases_deferred"] += 1
    return scan


# --------------------------------------------------------------------------
# metric assembly
# --------------------------------------------------------------------------


def _detect_arm_kind(directory: Path, report: Mapping | None, *,
                     receipts_present: bool, trace_present: bool):
    if isinstance(report, Mapping):
        mode = report.get("execution_mode")
        if mode in SESSION_EXECUTION_MODES:
            return SESSION_EXECUTION_MODES[mode], f"{REPORT_NAME}:execution_mode", None
        if receipts_present:
            return (ARM_KIND_UNLABELLED, f"{REPORT_NAME}:execution_mode",
                    f"{REPORT_NAME} declares execution_mode {mode!r}, which is "
                    f"not a declared scenario online session mode, but "
                    f"{RECEIPTS_NAME} is present so the arm is still analyzed")
    if receipts_present or trace_present:
        return (ARM_KIND_UNLABELLED, "artifact presence",
                f"{REPORT_NAME} declares no scenario online execution_mode, but "
                f"{RECEIPTS_NAME} or a trace container is present")
    schema = report.get("schema_version") if isinstance(report, Mapping) else None
    return (ARM_KIND_FOREIGN, f"{REPORT_NAME}:schema_version",
            f"{REPORT_NAME} declares schema_version {schema!r} and the directory "
            f"carries no {RECEIPTS_NAME} and no online trace container, so this "
            "is not a scenario online dataflow session and every metric is null")


def _analysis_limit(analysis: Mapping, quantity: str) -> str | None:
    for entry in analysis.get("limits") or ():
        if isinstance(entry, Mapping) and entry.get("quantity") == quantity:
            reason = entry.get("reason")
            if isinstance(reason, str) and reason:
                return reason
    return None


def _timing_mapping(analysis: Mapping, field: str) -> dict | None:
    phases = (analysis.get("phase_timing_seconds") or {}).get(field)
    if not isinstance(phases, Mapping):
        return None
    mapping = {}
    samples = 0
    for name, entry in phases.items():
        if not isinstance(entry, Mapping):
            continue
        count = entry.get("count")
        samples += count if type(count) is int else 0
        mapping[name] = {"count": count, "p50": entry.get("p50"),
                         "p95": entry.get("p95")}
    return mapping if samples else None


def _percentile_block(samples: Sequence[float]) -> dict | None:
    if not samples:
        return None
    percentiles = _percentiles(samples, (0.5, 0.95))
    return {"count": len(samples), "p50": percentiles["p50"],
            "p95": percentiles["p95"]}


def _stat(path: Path) -> int | None:
    try:
        return path.stat().st_size
    except OSError:
        return None


def _build_metrics(*, analysis: Mapping | None, report: Mapping | None,
                   scan: Mapping, cold: Mapping | None,
                   directory: Path, arm_reason: str | None) -> dict:
    values = _Values()
    if analysis is None:
        return _assemble(values, arm_reason=arm_reason)

    # -- one-time compile / initialization ---------------------------------
    values.unavailable("one_time_compile_init", "compilation_seconds",
                       COMPILE_REASON)
    finalization = analysis.get("finalization_timing_seconds")
    values.put("one_time_compile_init", "finalization_timing_seconds",
               finalization, analysis.get("finalization_timing_seconds_reason"))
    values.put("one_time_compile_init",
               "finalization_total_before_report_seconds",
               (finalization or {}).get("total_before_report")
               if isinstance(finalization, Mapping) else None,
               analysis.get("finalization_timing_seconds_reason"))
    effective = analysis.get("effective_search_seconds")
    elapsed = analysis.get("elapsed_seconds")
    values.put("one_time_compile_init", "effective_search_seconds", effective,
               analysis.get("effective_search_seconds_reason"))
    values.put("one_time_compile_init", "elapsed_seconds", elapsed,
               analysis.get("elapsed_seconds_reason"))
    if isinstance(effective, (int, float)) and isinstance(elapsed, (int, float)):
        values.put("one_time_compile_init",
                   "elapsed_minus_effective_search_seconds",
                   float(elapsed) - float(effective))
    else:
        values.unavailable(
            "one_time_compile_init", "elapsed_minus_effective_search_seconds",
            "report.json provides no finite elapsed_seconds and "
            "effective_search_seconds pair, so the subtraction is undefined")

    cases = cold.get("cases") if isinstance(cold, Mapping) else None
    init_values: list[float] = []
    if isinstance(cases, list):
        for entry in cases:
            if not isinstance(entry, Mapping):
                continue
            number = _finite_non_negative(entry.get("init_seconds"))
            if number is not None:
                init_values.append(number)
    cold_reason = (
        f"{COLD_BASELINE_NAME} is absent from this arm, so the per-case "
        "cold-start initialization cost was not measured here; a continuous "
        "online session has no per-case cold start")
    values.put("one_time_compile_init", "cold_start_baseline_case_count",
               cold.get("case_count") if isinstance(cold, Mapping) else None,
               f"{COLD_BASELINE_NAME} is absent, so the cold-start baseline "
               "case count is unknown" if cold is None else
               f"{COLD_BASELINE_NAME} carries no integer case_count")
    cold_block = _percentile_block(init_values)
    cold_p50 = cold_block["p50"] if cold_block else None
    cold_p95 = cold_block["p95"] if cold_block else None
    cold_total = sum(init_values) if init_values else None
    cold_missing = (f"{COLD_BASELINE_NAME} carries no finite non-negative "
                    "cases[].init_seconds, so no cold-start initialization "
                    "distribution exists")
    values.put("one_time_compile_init", "cold_start_init_seconds_p50", cold_p50,
               cold_missing if cold is not None else cold_reason)
    values.put("one_time_compile_init", "cold_start_init_seconds_p95", cold_p95,
               cold_missing if cold is not None else cold_reason)
    values.put("one_time_compile_init", "cold_start_init_seconds_total",
               cold_total, cold_missing if cold is not None else cold_reason)
    values.put("one_time_compile_init",
               "cold_start_document_init_seconds_total",
               cold.get("init_seconds_total")
               if isinstance(cold, Mapping) else None,
               f"{COLD_BASELINE_NAME}:init_seconds_total is absent")
    values.put("one_time_compile_init", "cold_start_cases_with_init_seconds",
               len(init_values) or None,
               cold_missing if cold is not None else cold_reason)
    if cold_total is not None and isinstance(elapsed, (int, float)) and elapsed:
        values.put("one_time_compile_init", "cold_start_share_of_elapsed",
                   cold_total / float(elapsed))
    else:
        values.unavailable(
            "one_time_compile_init", "cold_start_share_of_elapsed",
            "either cold_start.json init_seconds or report.json:elapsed_seconds "
            "is unavailable, so the initialization share of elapsed is undefined")
    wall_clock = report.get("wall_clock_seconds") if isinstance(report, Mapping) else None
    if cold_total is not None and isinstance(wall_clock, (int, float)) and wall_clock:
        values.put("one_time_compile_init",
                   "cold_start_share_of_wall_clock_seconds",
                   cold_total / float(wall_clock))
    else:
        values.unavailable(
            "one_time_compile_init", "cold_start_share_of_wall_clock_seconds",
            "report.json carries no finite positive wall_clock_seconds, so the "
            "initialization share of the cold group's wall clock is undefined")
    if cold_block is not None:
        values.put("one_time_compile_init", "per_case_initialization_seconds",
                   cold_block)
    else:
        values.unavailable("one_time_compile_init",
                           "per_case_initialization_seconds",
                           cold_missing if cold is not None
                           else CONTINUOUS_INIT_REASON)

    # -- per-case admission ------------------------------------------------
    scan_reason = scan.get("reason")
    values.put("per_case_admission", "receipt_rows", scan.get("rows"),
               scan_reason)
    values.put("per_case_admission", "reported_tests",
               analysis.get("reported_tests"),
               f"{REPORT_NAME} carries no integer tests key")
    completion = analysis.get("chain_completion_by_admission") or {}
    values.put("per_case_admission", "admissions_total",
               completion.get("admissions_total"))
    values.put("per_case_admission", "fuzz_source_admissions",
               completion.get("fuzz_source_admissions"))
    values.put("per_case_admission", "admissions_by_role",
               completion.get("admissions_by_role") or None,
               f"{PLAN_NAME}:source_admissions.admissions is absent, so the "
               "declared admission roles are unknown")
    if scan.get("available"):
        values.put("per_case_admission", "candidate_dispositions",
                   dict(sorted(scan["dispositions"].items())))
        values.put("per_case_admission", "candidate_disposition_reasons",
                   dict(sorted(scan["disposition_reasons"].items())))
        values.put("per_case_admission",
                   "cases_with_online_submit_timing_seconds",
                   scan["submit_cases"])
        counts = scan["local_command_counts"]
        if counts:
            values.put("per_case_admission", "local_command_count_total",
                       int(sum(counts)))
        else:
            values.unavailable(
                "per_case_admission", "local_command_count_total",
                f"{RECEIPTS_NAME} carries no finite non-negative "
                "online_submit_timing_seconds.local_command_count")
        for leaf, samples in (
                ("local_command_count_p50", counts),
                ("local_command_count_p95", counts),
                ("local_command_roundtrip_seconds_p50",
                 scan["local_command_roundtrips"]),
                ("local_command_roundtrip_seconds_p95",
                 scan["local_command_roundtrips"]),
                ("host_remainder_seconds_p50", scan["host_remainders"]),
                ("host_remainder_seconds_p95", scan["host_remainders"])):
            block = _percentile_block(samples)
            if block is None:
                values.unavailable(
                    "per_case_admission", leaf,
                    f"{RECEIPTS_NAME} carries no sample for this "
                    "online_submit_timing_seconds field")
            else:
                values.put("per_case_admission", leaf,
                           block["p50"] if leaf.endswith("p50") else block["p95"])
        values.put("per_case_admission", "cases_with_local_ticks",
                   scan["cases_with_local_ticks"])
        values.put("per_case_admission", "local_ticks_by_component_sum",
                   dict(sorted(scan["local_ticks_sums"].items())) or None,
                   f"{RECEIPTS_NAME} carries no local_ticks mapping")
        values.put("per_case_admission", "total_local_ticks_sum",
                   scan["total_local_ticks_sum"]
                   if scan["cases_with_total_local_ticks"] else None,
                   f"{RECEIPTS_NAME} carries no finite non-negative "
                   "total_local_ticks")
        values.put("per_case_admission", "cases_with_total_local_ticks",
                   scan["cases_with_total_local_ticks"])
        values.put("per_case_admission", "coverage_records",
                   scan["coverage_records"])
        widths = scan["coverage_widths"]
        if len(widths) == 1:
            values.put("per_case_admission", "coverage_width_bytes",
                       next(iter(widths)))
        elif len(widths) > 1:
            values.unavailable(
                "per_case_admission", "coverage_width_bytes",
                f"{RECEIPTS_NAME}:coverage_hex widths are inconsistent: "
                f"{sorted(widths)}")
        else:
            values.unavailable(
                "per_case_admission", "coverage_width_bytes",
                f"{RECEIPTS_NAME} carries no coverage_hex observation")
        values.put("per_case_admission", "raw_record_count",
                   scan["raw_record_count"] if scan["cases_with_raw_records"]
                   else None,
                   f"{RECEIPTS_NAME} carries no online_raw_records_hex")
        values.put("per_case_admission", "cases_with_violations",
                   scan["cases_with_violations"])

    # -- real RTL transactions ---------------------------------------------
    values.put("real_rtl_transactions", "cases_with_runner_timing",
               (analysis.get("phase_timing_seconds") or {}).get(
                   "cases_with_online_runner_timing_seconds"),
               _analysis_limit(analysis, "phase_timing_seconds."
                                         "online_runner_timing_seconds")
               or f"{RECEIPTS_NAME} carries no online_runner_timing_seconds")
    values.put("real_rtl_transactions", "cases_with_rtl_case_committed",
               scan.get("cases_with_rtl_case_committed")
               if scan.get("available") else None, scan_reason)
    values.put("real_rtl_transactions", "cases_with_total_local_ticks",
               scan.get("cases_with_total_local_ticks")
               if scan.get("available") else None, scan_reason)
    values.put("real_rtl_transactions", "record_semantics",
               report.get("record_semantics")
               if isinstance(report, Mapping) else None,
               f"{REPORT_NAME} carries no record_semantics declaration")
    values.put("real_rtl_transactions", "total_local_ticks_semantics",
               report.get("total_local_ticks_semantics")
               if isinstance(report, Mapping) else None,
               f"{REPORT_NAME} carries no total_local_ticks_semantics declaration")
    values.put("real_rtl_transactions", "clock_model",
               report.get("clock_model") if isinstance(report, Mapping) else None,
               f"{REPORT_NAME} carries no clock_model declaration")

    # -- Router / Scheduler ------------------------------------------------
    runner_samples = scan.get("runner_samples") or {}
    runner_mapping = {}
    for name in sorted(runner_samples):
        block = _percentile_block(runner_samples[name])
        if block is None:
            continue
        runner_mapping[name] = {"count": block["count"], "p50": block["p50"],
                                "p95": block["p95"],
                                "sum_seconds": scan["runner_sums"].get(name)}
    values.put("router_scheduler", "online_runner_timing_seconds",
               runner_mapping or None,
               scan_reason or f"{RECEIPTS_NAME} carries no "
                              "online_runner_timing_seconds samples")
    for leaf, phase in (
            ("cases_with_router_transact", "router_transact"),
            ("cases_with_scheduler_batch", "scheduler_batch"),
            ("cases_with_observed_output_route", "observed_output_route")):
        positive = (scan.get("runner_positive") or {}).get(phase)
        if scan.get("available"):
            values.put("router_scheduler", leaf, positive or 0)
        else:
            values.unavailable("router_scheduler", leaf, scan_reason)
    for leaf, phase in (
            ("router_transact_seconds_sum", "router_transact"),
            ("scheduler_batch_seconds_sum", "scheduler_batch"),
            ("observed_output_route_seconds_sum", "observed_output_route")):
        total = (scan.get("runner_sums") or {}).get(phase)
        if total is not None:
            values.put("router_scheduler", leaf, total)
        elif scan.get("available"):
            values.unavailable(
                "router_scheduler", leaf,
                f"{RECEIPTS_NAME} carries no finite non-negative "
                f"online_runner_timing_seconds.{phase}")
    values.put("router_scheduler", "nested_phase_semantics",
               NESTED_PHASE_SEMANTICS)

    # -- incremental feedback ----------------------------------------------
    values.put("incremental_feedback", "completed_feedback_exchanges",
               report.get("completed_feedback_exchanges")
               if isinstance(report, Mapping) else None,
               f"{REPORT_NAME} carries no completed_feedback_exchanges")
    values.put("incremental_feedback", "mutation_hint_updates",
               report.get("mutation_hint_updates")
               if isinstance(report, Mapping) else None,
               f"{REPORT_NAME} carries no mutation_hint_updates")
    values.put("incremental_feedback", "mutation_hint_schema",
               report.get("mutation_hint_schema")
               if isinstance(report, Mapping) else None,
               f"{REPORT_NAME} carries no mutation_hint_schema")
    for leaf, key in (
            ("cases_with_interaction_new_features",
             "interaction_new_features_cases"),
            ("cases_with_interaction_feature_deltas",
             "interaction_feature_deltas_cases"),
            ("cases_with_interaction_source_gains",
             "interaction_source_gains_cases"),
            ("cases_deferred", "cases_deferred")):
        values.put("incremental_feedback", leaf,
                   scan.get(key) if scan.get("available") else None, scan_reason)
    gate = report.get("source_action_gate") if isinstance(report, Mapping) else None
    values.put("incremental_feedback", "source_action_gate_enforce",
               gate.get("enforce") if isinstance(gate, Mapping) else None,
               f"{REPORT_NAME}:source_action_gate is absent"
               if not isinstance(gate, Mapping) else
               f"{REPORT_NAME}:source_action_gate carries no enforce key")
    actions = gate.get("action_ids") if isinstance(gate, Mapping) else None
    values.put("incremental_feedback", "source_action_gate_action_count",
               len(actions) if isinstance(actions, list) else None,
               f"{REPORT_NAME}:source_action_gate.action_ids is absent")
    values.put("incremental_feedback", "path_switch",
               report.get("path_switch") if isinstance(report, Mapping) else None,
               f"{REPORT_NAME}:path_switch is absent")
    energy = (report.get("closed_loop_energy")
              if isinstance(report, Mapping) else None)
    values.put("incremental_feedback", "closed_loop_energy_enabled",
               energy.get("enabled") if isinstance(energy, Mapping) else None,
               f"{REPORT_NAME}:closed_loop_energy is absent")
    values.put("incremental_feedback", "closed_loop_energy_counts",
               energy.get("counts") if isinstance(energy, Mapping) else None,
               f"{REPORT_NAME}:closed_loop_energy.counts is absent")

    # -- log / evidence ----------------------------------------------------
    trace = analysis.get("trace_evidence") or {}
    trace_reason = _analysis_limit(analysis, "trace_events") or (
        "no streamable trace artifact is present in this run directory")
    for leaf, key in (
            ("trace_format", "format"),
            ("trace_meta_schema_version", "meta_schema_version"),
            ("trace_events_file", "events_file"),
            ("trace_bytes", "bytes"),
            ("trace_events_ingested", "events_ingested"),
            ("trace_declared_event_count", "declared_event_count"),
            ("trace_event_count_match", "event_count_match"),
            ("trace_semantic_sha256_verified", "semantic_sha256_verified")):
        values.put("log_evidence", leaf, trace.get(key), trace_reason)
    meta_present = (directory / TRACE_META_NAME).is_file()
    container = trace.get("events_file")
    if meta_present and container in TRACE_CONTAINER_NAMES:
        values.put("log_evidence", "trace_meta_container_split", True)
    elif (directory / TRACE_MONOLITHIC_NAME).is_file() and not meta_present:
        values.put("log_evidence", "trace_meta_container_split", False)
    else:
        values.unavailable(
            "log_evidence", "trace_meta_container_split",
            f"neither {TRACE_META_NAME} plus a container nor "
            f"{TRACE_MONOLITHIC_NAME} is present, so the trace split is unknown")
    values.put("log_evidence", "trace_meta_bytes",
               _stat(directory / TRACE_META_NAME),
               f"{TRACE_META_NAME} is absent")
    values.put("log_evidence", "receipts_bytes",
               _stat(directory / RECEIPTS_NAME),
               f"{RECEIPTS_NAME} is absent")
    values.put("log_evidence", "client_log_bytes",
               _stat(directory / CLIENT_LOG_NAME),
               f"{CLIENT_LOG_NAME} is absent")
    values.put("log_evidence", "session_manifest_bytes",
               _stat(directory / MANIFEST_NAME),
               f"{MANIFEST_NAME} is absent")
    sizes = [_stat(directory / name) for name in EVIDENCE_FILES]
    present = [size for size in sizes if size is not None]
    if present:
        values.put("log_evidence", "evidence_footprint_bytes", sum(present))
    else:
        values.unavailable(
            "log_evidence", "evidence_footprint_bytes",
            "none of the declared run artifacts is present, so the evidence "
            "footprint is unknown")

    # -- latency percentiles ----------------------------------------------
    phase_mapping = _timing_mapping(analysis, "online_phase_timing_seconds")
    values.put("latency_percentiles", "online_phase_timing_seconds",
               phase_mapping,
               _analysis_limit(analysis, "phase_timing_seconds."
                                         "online_phase_timing_seconds")
               or f"{RECEIPTS_NAME} carries no online_phase_timing_seconds")
    total_entry = (phase_mapping or {}).get("total") if phase_mapping else None
    if isinstance(total_entry, Mapping) and total_entry.get("count"):
        values.put("latency_percentiles", "per_case_total_seconds",
                   dict(total_entry))
    else:
        values.unavailable(
            "latency_percentiles", "per_case_total_seconds",
            f"{RECEIPTS_NAME} carries no online_phase_timing_seconds.total "
            "sample, so no per-case latency percentile exists")
    timing = analysis.get("phase_timing_seconds") or {}
    values.put("latency_percentiles",
               "cases_with_online_phase_timing_seconds",
               timing.get("cases_with_online_phase_timing_seconds"),
               _analysis_limit(analysis, "phase_timing_seconds."
                                         "online_phase_timing_seconds")
               or f"{RECEIPTS_NAME} carries no online_phase_timing_seconds")
    values.put("latency_percentiles", "invalid_timing_values",
               timing.get("invalid_timing_values"),
               f"{RECEIPTS_NAME} is absent, so invalid timing values are unknown")

    # -- effective cases / second -----------------------------------------
    values.put("effective_cases_per_second", "effective_cases_per_second",
               analysis.get("complete_cases_per_second"),
               analysis.get("complete_cases_per_second_reason")
               or "the complete status count or report.json:"
                  "effective_search_seconds is unknown")
    detail = analysis.get("invalid_or_timeout_detail") or {}
    values.put("effective_cases_per_second", "complete_status_count",
               detail.get("complete"),
               _analysis_limit(analysis, "test_counts"))
    values.put("effective_cases_per_second", "denominator_seconds", effective,
               analysis.get("effective_search_seconds_reason"))
    total_cases = analysis.get("test_counts_total")
    if isinstance(total_cases, int) and isinstance(effective, (int, float)) \
            and effective:
        values.put("effective_cases_per_second",
                   "all_receipt_cases_per_second", total_cases / float(effective))
    else:
        values.unavailable(
            "effective_cases_per_second", "all_receipt_cases_per_second",
            f"{RECEIPTS_NAME} row count or report.json:effective_search_seconds "
            "is unavailable, so the per-second rate is undefined")

    # -- certified chains / second ----------------------------------------
    chains = analysis.get("certified_chains") or {}
    chains_reason = analysis.get("certified_chains_reason")
    values.put("certified_chains_per_second", "certified_chains",
               chains.get("total"), chains_reason)
    values.put("certified_chains_per_second", "certified_chains_per_second",
               analysis.get("certified_chains_per_second"),
               analysis.get("certified_chains_per_second_reason"))
    values.put("certified_chains_per_second", "certified_chains_by_direction",
               chains.get("by_direction"), chains_reason)
    values.put("certified_chains_per_second", "certified_chains_same_case",
               chains.get("same_case"), chains_reason)
    values.put("certified_chains_per_second", "certified_chains_cross_case",
               chains.get("cross_case"), chains_reason)
    values.put("certified_chains_per_second", "incomplete_certificates",
               chains.get("incomplete_total"), chains_reason)
    gap = analysis.get("chain_gap_evidence") or {}
    values.put("certified_chains_per_second", "first_missing_hop_histogram",
               gap.get("first_missing_hop_counts"), chains_reason)
    values.put("certified_chains_per_second", "unresolvable_missing_hops",
               gap.get("unresolvable_missing_hops"), chains_reason)
    values.put("certified_chains_per_second", "certified_admissions",
               completion.get("certified_admissions"), chains_reason)
    values.put("certified_chains_per_second", "chain_completion_by_admission",
               completion or None, chains_reason)
    producer = analysis.get("chain_producer") or {}
    values.put("certified_chains_per_second", "chain_producer_available",
               producer.get("available"),
               producer.get("reason")
               or "no chain certificate producer could be resolved")
    values.put("certified_chains_per_second", "semantics",
               analysis.get("certified_chains_semantics") if chains.get("total")
               is not None else None, chains_reason)

    # -- coverage novelty --------------------------------------------------
    targets = analysis.get("local_target_novelty") or {}
    edges = analysis.get("witnessed_edge_novelty") or {}
    for leaf, key in (
            ("first_seen_target_bits", "first_seen_target_bits"),
            ("first_seen_target_slots", "first_seen_target_slots"),
            ("coverage_width_bytes", "coverage_width_bytes"),
            ("new_target_bits_per_second", "new_target_bits_per_second"),
            ("new_target_slots_per_second", "new_target_slots_per_second")):
        values.put("coverage_novelty", leaf, targets.get(key),
                   targets.get("reason"))
    for leaf, key in (
            ("unique_witnessed_edges", "unique_edges"),
            ("edge_candidate_observations", "candidate_observations"),
            ("new_witnessed_edges_per_second", "new_edges_per_second")):
        values.put("coverage_novelty", leaf, edges.get(key), edges.get("reason"))
    values.put("coverage_novelty", "method", COVERAGE_NOVELTY_METHOD)

    # -- invalid / timeout ratio ------------------------------------------
    values.put("invalid_or_timeout_ratio", "invalid_or_timeout_ratio",
               analysis.get("invalid_or_timeout_ratio"),
               analysis.get("invalid_or_timeout_ratio_reason")
               or (f"{RECEIPTS_NAME} carries 0 decoded rows, so no "
                   "invalid/timeout ratio is defined"
                   if total_cases == 0 else
                   "the receipt status set or the receipt row count is unknown"))
    values.put("invalid_or_timeout_ratio", "invalid_or_timeout_denominator",
               total_cases, _analysis_limit(analysis, "test_counts"))
    for leaf, key in (("complete_count", "complete"), ("invalid_count", "invalid"),
                      ("timeout_count", "timeout"), ("finding_count", "findings")):
        values.put("invalid_or_timeout_ratio", leaf, detail.get(key),
                   _analysis_limit(analysis, "test_counts"))
    unclassified = detail.get("unclassified_statuses")
    values.put("invalid_or_timeout_ratio", "unclassified_statuses",
               unclassified, _analysis_limit(analysis, "test_counts"))
    values.put("invalid_or_timeout_ratio", "definition",
               detail.get("definition") if detail else None,
               _analysis_limit(analysis, "test_counts"))

    # -- exact status counts ----------------------------------------------
    counts = analysis.get("test_counts")
    values.put("status_counts", "status_counts",
               dict(sorted(counts.items())) if counts is not None else None,
               analysis.get("test_counts_reason"))
    values.put("status_counts", "status_counts_total", total_cases,
               analysis.get("test_counts_reason"))
    reported_statuses = analysis.get("reported_statuses")
    values.put("status_counts", "reported_statuses",
               dict(sorted(reported_statuses.items()))
               if reported_statuses is not None else None,
               f"{REPORT_NAME} carries no statuses mapping")
    if counts is not None:
        agree = (analysis.get("reported_tests") == total_cases
                 and reported_statuses == counts)
        values.put("status_counts", "reports_agree", agree)
    else:
        values.unavailable(
            "status_counts", "reports_agree",
            f"{RECEIPTS_NAME} is absent, so the report and receipt status "
            "counts cannot be compared")
    return _assemble(values)


# --------------------------------------------------------------------------
# public entry points
# --------------------------------------------------------------------------


def analyze_arm(run_dir: str | Path, *, label: str | None = None,
                chain_producer: object = None,
                max_certificates: int = DEFAULT_MAX_CERTIFICATES,
                max_pending: int = 128, max_event_gap: int = 4096,
                require_native_receipts: bool = True,
                ingest_batch_size: int = DEFAULT_INGEST_BATCH_SIZE,
                max_timing_samples: int = DEFAULT_MAX_TIMING_SAMPLES,
                verify_semantic: bool = True) -> dict:
    """Aggregate the declared P5 metrics of one saved run directory, read-only.

    Nothing is started and nothing is written.  An arm that is not a scenario
    online dataflow session is reported as such with every metric ``null`` and
    the detected schema in the reason instead of being analyzed into zeros.
    """
    if type(max_timing_samples) is not int or max_timing_samples < 1:
        raise ValueError("max_timing_samples must be a positive integer")
    directory = Path(run_dir)
    if not directory.is_dir():
        raise P5ArmMetricsInputError(
            f"run directory does not exist: {directory}")
    try:
        report = _read_json_object(directory / REPORT_NAME)
        receipts_present = (directory / RECEIPTS_NAME).is_file()
        trace_present = any(
            (directory / name).is_file()
            for name in TRACE_CONTAINER_NAMES + (TRACE_META_NAME,
                                                 TRACE_MONOLITHIC_NAME))
        arm_kind, arm_kind_source, arm_kind_reason = _detect_arm_kind(
            directory, report, receipts_present=receipts_present,
            trace_present=trace_present)
        analysis_performed = arm_kind != ARM_KIND_FOREIGN
        analysis = None
        if analysis_performed:
            try:
                analysis = analyze_run(
                    directory, chain_producer=chain_producer,
                    max_certificates=max_certificates, max_pending=max_pending,
                    max_event_gap=max_event_gap,
                    require_native_receipts=require_native_receipts,
                    ingest_batch_size=ingest_batch_size,
                    verify_semantic=verify_semantic)
            except ValueError as exc:
                raise P5ArmMetricsInputError(
                    f"{directory.name} cannot be analyzed: {exc}") from exc
        scan = _scan_arm_receipts(directory / RECEIPTS_NAME,
                                  max_timing_samples=max_timing_samples)
        try:
            cold = load_cold_baseline(directory)
        except PairedEfficiencyInputError as exc:
            raise P5ArmMetricsInputError(
                f"{directory.name} carries an unusable {COLD_BASELINE_NAME}: "
                f"{exc}") from exc
    except P5ArmMetricsInputError:
        raise
    except ValueError as exc:
        raise P5ArmMetricsInputError(f"{directory.name}: {exc}") from exc

    metrics = _build_metrics(analysis=analysis, report=report, scan=scan,
                             cold=cold, directory=directory,
                             arm_reason=arm_kind_reason)
    limits: list[dict] = []
    if analysis is not None:
        limits = [dict(entry) for entry in analysis.get("limits") or ()]
    else:
        limits = [{"quantity": "arm", "reason": arm_kind_reason}]
    if scan.get("truncated"):
        limits.append({
            "quantity": "per_case_admission (timing samples)",
            "reason": f"the timing sample cap max_timing_samples="
                      f"{max_timing_samples} was reached; the percentiles are "
                      "lower bounds over the sampled prefix"})
    cold_measured = metrics["one_time_compile_init"][
        "cold_start_cases_with_init_seconds"]["value"]
    cold_declared = None
    if isinstance(cold, Mapping):
        cold_declared = cold.get("case_count")
        if not isinstance(cold_declared, int) and isinstance(cold.get("cases"),
                                                            list):
            cold_declared = len(cold["cases"])
    if (isinstance(cold_measured, int) and isinstance(cold_declared, int)
            and cold_measured != cold_declared):
        limits.append({
            "quantity": "one_time_compile_init.cold_start_init_seconds_*",
            "reason": f"{COLD_BASELINE_NAME} declares {cold_declared} cases but "
                      f"only {cold_measured} carry a finite non-negative "
                      "cases[].init_seconds; the percentiles cover the measured "
                      "subset and report its count, whereas paired_efficiency "
                      "requires the whole compared window and reports null for a "
                      "partial baseline"})
    run_id = None
    identity = _read_json_object(directory / IDENTITY_NAME)
    if isinstance(identity, Mapping):
        inner = identity.get("identity")
        if isinstance(inner, Mapping):
            config = inner.get("run_config")
            if isinstance(config, Mapping) and isinstance(config.get("run_id"),
                                                          str):
                run_id = config["run_id"]
    return {
        "label": label or directory.name,
        "run_dir": str(directory),
        "run_id": run_id,
        "arm_kind": arm_kind,
        "arm_kind_source": arm_kind_source,
        "arm_kind_reason": arm_kind_reason,
        "analysis_performed": analysis_performed,
        "receipts_present": receipts_present,
        "trace_present": trace_present,
        "metrics": metrics,
        "limits": limits,
    }


def aggregate_arms(run_dirs: Iterable[str | Path], *,
                   labels: Sequence[str] | None = None, **kwargs) -> dict:
    """Aggregate one or more saved run directories into one document."""
    directories = [Path(entry) for entry in run_dirs]
    if labels is not None:
        labels = list(labels)
        if len(labels) != len(directories):
            raise P5ArmMetricsInputError(
                f"{len(labels)} labels were given for {len(directories)} run "
                "directories; labels must match arms one to one")
    arms = []
    for index, directory in enumerate(directories):
        arms.append(analyze_arm(
            directory, label=(labels[index] if labels is not None else None),
            **kwargs))
    return {
        "schema_version": SCHEMA_VERSION,
        "schema_name": REPORT_SCHEMA_NAME,
        "checklist_metric_groups": list(CHECKLIST_METRIC_GROUPS),
        "arm_count": len(arms),
        "arms": arms,
        "boundaries": list(BOUNDARIES),
    }


# --------------------------------------------------------------------------
# markdown rendering
# --------------------------------------------------------------------------


def _format_value(value: object) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, float):
        return f"{value:.6g}"
    if isinstance(value, int):
        return str(value)
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      allow_nan=False)


def _summary_cell(arm: Mapping, path: str) -> str:
    group, _, leaf = path.partition(".")
    entry = (arm.get("metrics") or {}).get(group, {}).get(leaf)
    if not isinstance(entry, Mapping) or entry.get("value") is None:
        return "null"
    return _format_value(entry["value"])


def _summary_row(arm: Mapping) -> str:
    per_case = ((arm["metrics"]["latency_percentiles"]
                 ["per_case_total_seconds"])["value"] or {})
    finalization = ((arm["metrics"]["one_time_compile_init"]
                     ["finalization_total_before_report_seconds"])["value"])
    cells = [
        arm["label"],
        arm["arm_kind"],
        _summary_cell(arm, "effective_cases_per_second.effective_cases_per_second"),
        _summary_cell(arm, "certified_chains_per_second.certified_chains"),
        _summary_cell(arm,
                      "certified_chains_per_second.certified_chains_per_second"),
        _summary_cell(arm, "coverage_novelty.new_target_bits_per_second"),
        _summary_cell(arm, "coverage_novelty.new_witnessed_edges_per_second"),
        _summary_cell(arm,
                      "invalid_or_timeout_ratio.invalid_or_timeout_ratio"),
        _format_value(per_case.get("p50")),
        _format_value(per_case.get("p95")),
        _format_value(finalization),
        _summary_cell(arm, "log_evidence.trace_bytes"),
    ]
    return "| " + " | ".join(cells) + " |"


def render_markdown(document: Mapping) -> str:
    """Render the document as one markdown table set (read-only view)."""
    lines = [
        f"# P5 单臂指标汇总（`{SCHEMA_VERSION}`）",
        "",
        "一个固定预算对照所需的全部声明量集中在本文件：每臂的 一次性编译/初始化、"
        "每例 admission、真实 RTL 事务、Router/Scheduler、增量反馈、日志/证据、"
        "p50/p95 时延、有效例/s、完整真实链/s、覆盖增量/s 与无效/超时比例。",
        "每个数字都标注了它来自哪个 artifact key；输入缺失时为 `null` 并给出原因，"
        "绝不用 0 代替。",
        "",
        f"Checklist metric groups: `{'`, `'.join(document['checklist_metric_groups'])}`",
        "",
        "## 1. 总览",
        "",
        "| 臂 | arm_kind | 有效例/s | 完整链 | 完整链/s | 覆盖增量 位/s | "
        "覆盖增量 边/s | 无效/超时 | 逐例 p50 (s) | 逐例 p95 (s) | "
        "终结 total_before_report (s) | trace 字节 |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for arm in document["arms"]:
        lines.append(_summary_row(arm))
    lines.extend(["", "## 2. 每臂全部声明量", ""])
    for arm in document["arms"]:
        lines.append(f"### 臂 `{arm['label']}`")
        lines.append("")
        lines.append(f"- `run_dir`: `{arm['run_dir']}`")
        lines.append(f"- `run_id`: `{arm.get('run_id')}`")
        lines.append(f"- `arm_kind`: `{arm['arm_kind']}` "
                     f"(来源 `{arm['arm_kind_source']}`)")
        if arm.get("arm_kind_reason"):
            lines.append(f"- `arm_kind_reason`: {arm['arm_kind_reason']}")
        lines.append(f"- `analysis_performed`: "
                     f"{_format_value(arm['analysis_performed'])}")
        lines.append("")
        lines.append("| checklist 组 | 指标 | 值 | 来源 artifact key | null 原因 |")
        lines.append("|---|---|---|---|---|")
        for group in document["checklist_metric_groups"]:
            for leaf, entry in (arm["metrics"].get(group) or {}).items():
                reason = entry.get("reason") or ""
                lines.append(
                    f"| `{group}` | `{leaf}` | "
                    f"{_format_value(entry.get('value')).replace('|', '\\|')} | "
                    f"{entry.get('source', '').replace('|', '\\|')} | "
                    f"{reason.replace('|', '\\|')} |")
        lines.append("")
    lines.extend(["## 3. 边界", ""])
    for boundary in document["boundaries"]:
        lines.append(f"- {boundary}")
    lines.append("")
    return "\n".join(lines)
