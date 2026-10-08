"""Paired continuous-vs-cold efficiency tests over synthetic run directories.

Every expected number is hand-computed from the synthetic artifact bytes written
by the builders below; nothing is copied from a previous run's report. The
synthetic directories are small (3-5 cases) on purpose, and the cold-start
document is written with the ``ibex_pulp_cold_baseline.v1`` schema that
``scripts/bench_ibex_pulp_cold_start.py`` produces, so no RTL is started here.

The stub chain producer implements the frozen ``ChainCertificates`` protocol
(``ingest``/``flush``/``pending_count``) so chain accounting is tested without
depending on the separately developed certificate producer.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import sys
import tracemalloc

import pytest

from myfuzz.scenario.paired_efficiency import (
    COLD_BASELINE_SCHEMA_VERSION,
    COLD_DOCUMENT_TOTAL_SOURCE,
    COLD_INIT_SOURCE,
    COLD_RAW_SOURCE,
    PairedEfficiencyInputError,
    RECEIPT_TOTAL_SOURCE,
    SCHEMA_VERSION,
    compare_runs,
    load_cold_baseline,
    render_paired_markdown,
)


ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "scripts" / "bench_first_step_paired.py"
COLD_PRODUCER = ROOT / "scripts" / "bench_ibex_pulp_cold_start.py"

SOURCE_FILES = [{"path": "src/myfuzz/scenario/uart_session.py", "sha256": "a" * 64},
                {"path": "src/myfuzz/scenario/gpio_session.py", "sha256": "9" * 64}]
SOURCE_FILES_SHA256 = hashlib.sha256(json.dumps(
    sorted((entry["path"], entry["sha256"]) for entry in SOURCE_FILES),
    sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()

# Hand-computed inclusive percentiles (statistics.quantiles, n=100) of
# [1.0, 2.0, 3.0, 4.0]: p50 = 2.5, p95 = 3.85.
TOTALS = (1.0, 2.0, 3.0, 4.0)
P50_TOTALS = statistics.quantiles(TOTALS, n=100, method="inclusive")[49]
P95_TOTALS = statistics.quantiles(TOTALS, n=100, method="inclusive")[94]

CONTINUOUS_EFFECTIVE_SECONDS = 10.0
COLD_EFFECTIVE_SECONDS = 40.0
COLD_ELAPSED_SECONDS = 45.0
INIT_SECONDS = (1.0, 2.0, 3.0, 4.0)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


# --------------------------------------------------------------------------
# synthetic artifact builders
# --------------------------------------------------------------------------


def _receipt(index: int, *, status: str = "complete", total: float | None = 1.0,
             coverage: str = "0100", violations: list | None = None,
             raw: str | None = None, path: str | None = None,
             genome: str | None = None, ticks: dict | None = None,
             sources: list | None = None) -> dict:
    row = {
        "case_id": f"online-{index}-case",
        "status": status,
        "coverage_hex": coverage,
        "violations": [] if violations is None else violations,
        "effective_genome_sha256": genome if genome is not None else f"genome-{index}",
        "raw_sha256": raw if raw is not None else f"raw-{index}",
        "path_id": path if path is not None else f"path-{index}",
        "applied_sources": (["cpu.online_instruction"] if sources is None else sources),
        "local_ticks": ({"cpu": 10 + index, "gpio_a": 20 + index}
                        if ticks is None else ticks),
        "online_raw_records_hex": [f"000000000000000{index}"],
    }
    if total is not None:
        row["online_phase_timing_seconds"] = {"total": total}
    return row


def _default_receipts() -> list[dict]:
    return [
        _receipt(0, total=1.0, coverage="0100"),
        _receipt(1, total=2.0, coverage="0101"),
        _receipt(2, total=3.0, coverage="0110"),
        _receipt(3, status="timeout", total=4.0, coverage="0000"),
    ]


def _default_events() -> list[dict]:
    return [{"event_id": event_id, "component": "cpu", "kind": "dataflow_delivery",
             "address": 4096 + event_id, "data_hex": "0011" * 4}
            for event_id in (1, 2, 3, 4)]


def _write_jsonl_trace(directory: Path, events: list[dict], *,
                       status: str = "complete",
                       local_ticks: dict | None = None) -> dict:
    """Write a JSONL trace plus metadata using the frozen semantic SHA rule."""
    local_ticks = {"cpu": 10} if local_ticks is None else local_ticks
    digest = hashlib.sha256(b'{"events":[')
    with (directory / "online_events.jsonl").open("w", encoding="utf-8") as handle:
        for index, event in enumerate(events):
            encoded = _canonical(event)
            if index:
                digest.update(b",")
            digest.update(encoded)
            handle.write(encoded.decode("utf-8") + "\n")
    digest.update(b'],"local_ticks":')
    digest.update(_canonical(local_ticks))
    digest.update(b',"status":')
    digest.update(_canonical(status))
    digest.update(b"}")
    metadata = {
        "schema_version": "online_trace_jsonl.v1",
        "events_file": "online_events.jsonl",
        "event_count": len(events),
        "genome_sha256": "3" * 64,
        "status": status,
        "local_ticks": local_ticks,
        "semantic_sha256": digest.hexdigest(),
        "manifest_sha256": "4" * 64,
    }
    (directory / "online_final_trace.meta.json").write_text(
        json.dumps(metadata, sort_keys=True) + "\n", encoding="utf-8")
    return metadata


def _identity(run_id: str, *, search_seed: int = 7, max_tests: int = 4,
              duration_seconds: float = 5.0,
              source_files: list | None = None) -> dict:
    return {
        "schema_version": "scenario_online_run_identity_envelope.v1",
        "sha256": "6" * 64,
        "identity": {
            "schema_version": "scenario_online_run_identity.v1",
            "execution_mode": "online_cases",
            "run_config": {"run_id": run_id, "duration_seconds": duration_seconds,
                           "max_tests": max_tests, "search_seed": search_seed,
                           "feedback_interval": 16},
            "source_files": SOURCE_FILES if source_files is None else source_files,
            "session": {"component_identity_sha256": "b" * 64},
            "genome": {"plan_sha256": "c" * 64},
            "feedback": {"targets_sha256": "e" * 64},
            "toolchain": {"client": {"binary_sha256": "f" * 64}},
        },
    }


def _build_run(directory: Path, *, receipts: list[dict] | None = None,
               effective_seconds: float = CONTINUOUS_EFFECTIVE_SECONDS,
               elapsed_seconds: float = 12.0, run_id: str = "paired-run",
               events: list[dict] | None = None, **identity_kwargs) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    rows = _default_receipts() if receipts is None else receipts
    with (directory / "receipts.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    statuses: dict[str, int] = {}
    for row in rows:
        statuses[row["status"]] = statuses.get(row["status"], 0) + 1
    report = {
        "execution_status": "complete",
        "session_status": "complete",
        "tests": len(rows),
        "statuses": statuses,
        "effective_search_seconds": effective_seconds,
        "elapsed_seconds": elapsed_seconds,
        "decoder_manifest_sha256": "d" * 64,
        "global_mutation_seed": identity_kwargs.get("search_seed", 7),
    }
    (directory / "report.json").write_text(
        json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")
    (directory / "online_run_identity.json").write_text(
        json.dumps(_identity(run_id, **identity_kwargs), sort_keys=True) + "\n",
        encoding="utf-8")
    if events is not None:
        _write_jsonl_trace(directory, events)
    return directory


def _write_cold_baseline(directory: Path, *, count: int = 4,
                         init_seconds: tuple = INIT_SECONDS,
                         with_totals: bool = True) -> Path:
    cases = []
    for index in range(count):
        entry = {
            "index": index,
            "raw_hex": f"000000000000000{index}",
            "init_seconds": init_seconds[index],
            "original_status": "complete",
            "cold_status": "complete",
            "original_path": f"path-{index}",
            "cold_path": f"path-{index}",
            "source_compatible": True,
            "path_compatible": True,
        }
        if with_totals:
            entry["total_seconds"] = float(index + 1)
        cases.append(entry)
    document = {
        "schema_version": COLD_BASELINE_SCHEMA_VERSION,
        "comparison_scope": "startup_cost_only_not_coverage_equivalence",
        "source_receipts": "synthetic",
        "case_count": count,
        "elapsed_seconds": COLD_ELAPSED_SECONDS,
        "source_compatible_count": count,
        "path_compatible_count": count,
        "cases": cases,
    }
    (directory / "cold_start.json").write_text(
        json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
    return directory


def _build_pair(base: Path, **overrides) -> tuple[Path, Path]:
    continuous = _build_run(base / "continuous", run_id="paired-continuous",
                            effective_seconds=CONTINUOUS_EFFECTIVE_SECONDS,
                            elapsed_seconds=12.0, **overrides)
    cold = _build_run(base / "cold", run_id="paired-cold",
                      effective_seconds=COLD_EFFECTIVE_SECONDS,
                      elapsed_seconds=COLD_ELAPSED_SECONDS, **overrides)
    _write_cold_baseline(cold)
    return continuous, cold


# --------------------------------------------------------------------------
# frozen schema / producer relationship
# --------------------------------------------------------------------------


def test_exports_frozen_schema_version() -> None:
    assert SCHEMA_VERSION == "paired_efficiency_report.v1"
    assert RECEIPT_TOTAL_SOURCE == "receipts.jsonl:online_phase_timing_seconds.total"
    assert COLD_DOCUMENT_TOTAL_SOURCE == "cold_start.json:cases[].total_seconds"
    assert COLD_INIT_SOURCE == "cold_start.json:cases[].init_seconds"


def test_cold_baseline_schema_matches_the_existing_producer_script() -> None:
    """The consumed schema stays pinned to scripts/bench_ibex_pulp_cold_start.py."""
    source = COLD_PRODUCER.read_text(encoding="utf-8")
    assert "def measure_cold_cases" in source
    assert f'"{COLD_BASELINE_SCHEMA_VERSION}"' in source
    for emitted in ("init_seconds", "total_seconds", "raw_hex"):
        assert f'"{emitted}"' in source


# --------------------------------------------------------------------------
# exact hand-computed values
# --------------------------------------------------------------------------


def test_compare_runs_reports_exact_hand_computed_values(tmp_path: Path) -> None:
    continuous, cold = _build_pair(tmp_path)
    report = compare_runs(continuous, cold)

    assert report["schema_version"] == SCHEMA_VERSION
    assert report["continuous_dir"] == str(continuous)
    assert report["cold_dir"] == str(cold)
    assert report["max_items"] == 200_000

    agreement = report["per_case_agreement"]
    assert agreement["cases_compared"] == 4
    assert agreement["receipt_rows"] == {"continuous": 4, "cold": 4}
    assert agreement["alignment"]["key"] == "receipt_ordinal"
    assert agreement["status_transitions"] == {}
    for name, entry in agreement["fields"].items():
        assert entry["equal"] == 4, name
        assert entry["mismatch"] == 0, name
        assert entry["missing"] == 0, name
    assert len(agreement["case_details"]) == 4
    assert agreement["case_details"][3]["status"] == {
        "continuous": "timeout", "cold": "timeout", "verdict": "equal", "equal": True}
    assert agreement["case_details"][3]["values_truncated"] is False
    assert agreement["case_details_truncated_at"] is None
    # Each tally names the receipt key it compared.
    assert agreement["fields"]["status"]["field"] == "status"
    assert agreement["fields"]["violations"]["field"] == "violations"
    assert agreement["fields"]["raw_identity"]["field"] == "raw_sha256"
    assert agreement["fields"]["local_ticks"]["field"] == "local_ticks"

    validity = report["comparison_validity"]
    assert validity["comparable"] is True
    assert validity["status"] == "comparable"
    assert validity["failed_prerequisites"] == []
    assert validity["unverified_prerequisites"] == []
    assert validity["output_equivalence"]["claimed"] is True
    assert sorted(validity["output_equivalence"]["fields_fully_equal"]) == [
        "applied_sources", "coverage_hex", "effective_genome_sha256", "local_ticks",
        "path_id", "raw_identity", "status", "violations"]
    assert validity["boundaries"]

    groups = report["groups"]
    assert groups["continuous"]["case_count"] == 4
    assert groups["continuous"]["cases_per_second"] == 0.4  # 4 / 10.0
    assert groups["continuous"]["cases_per_second_boundary"] == \
        "effective_search_seconds"
    assert groups["cold"]["cases_per_second"] == 0.1  # 4 / 40.0
    assert groups["cold"]["cases_per_second_boundary"] == "effective_search_seconds"
    for label in ("continuous", "cold"):
        totals = groups[label]["per_case_total_seconds"]
        assert totals["count"] == 4
        assert totals["p50"] == P50_TOTALS == 2.5
        assert totals["p95"] == pytest.approx(P95_TOTALS)  # 3.85
        assert totals["source"] == RECEIPT_TOTAL_SOURCE
        assert totals["reason"] is None
        assert groups[label]["effective_search_seconds"] == (
            CONTINUOUS_EFFECTIVE_SECONDS if label == "continuous"
            else COLD_EFFECTIVE_SECONDS)
        # No trace artifact was written for this pair.
        assert groups[label]["certified_chains"]["total"] is None
        assert groups[label]["certified_chains_per_second"] is None
        assert groups[label]["certified_chains_per_second_reason"]
        assert groups[label]["replay_analyzed"] is False
        assert groups[label]["replay_verified"] is None

    initialization = report["initialization"]
    assert initialization["cold_baseline_document"] == "cold_start.json"
    assert initialization["cold_baseline_case_count"] == 4
    assert initialization["cold_cases_with_init_seconds"] == 4
    assert initialization["cold_init_seconds_source"] == COLD_INIT_SOURCE
    assert initialization["cold_init_seconds_total"] == 10.0  # 1+2+3+4
    assert initialization["cold_init_seconds_p50"] == 2.5
    assert initialization["cold_init_seconds_p95"] == pytest.approx(3.85)
    assert initialization["cold_init_share_of_elapsed"] == pytest.approx(10.0 / 45.0)
    assert initialization["cold_baseline_input_alignment"] == {
        "available": True, "compared": 4, "equal": 4,
        "mismatch_case_indexes": [], "source": COLD_RAW_SOURCE, "reason": None}
    # The continuous session charges no initialization to any case: null, not 0.
    assert initialization["continuous_init_seconds"] is None
    assert initialization["continuous_init_seconds_reason"]
    assert initialization["reason"] is None

    paired = report["paired"]
    ratio = paired["cases_per_second_ratio_cold_over_continuous"]
    assert ratio["value"] == pytest.approx(0.1 / 0.4)  # 0.25
    assert ratio["reason"] is None
    assert "not a speedup" in ratio["interpretation"]
    delta = paired["per_case_total_p50_delta_seconds_cold_minus_continuous"]
    assert delta["value"] == pytest.approx(0.0)
    assert "not a saving estimate" in delta["interpretation"]
    assert paired["certified_chains_delta_cold_minus_continuous"]["value"] is None
    assert paired["certified_chains_delta_cold_minus_continuous"]["reason"]

    assert report["memory_model"]["receipt_rows_retained"] == 0
    assert report["memory_model"]["case_details_retained"] == 4
    # Every null quantity above carries a limit entry.
    quantities = {item["quantity"] for item in report["limits"]}
    assert "groups.continuous.certified_chains_per_second" in quantities
    assert "groups.cold.certified_chains_per_second" in quantities
    assert "initialization.continuous_init_seconds" in quantities
    assert "groups.continuous.replay_verified" in quantities
    assert "certified_chains_delta_cold_minus_continuous" in quantities


# --------------------------------------------------------------------------
# insufficient data fails loudly
# --------------------------------------------------------------------------


def test_unequal_case_counts_fail_explicitly(tmp_path: Path) -> None:
    continuous, cold = _build_pair(tmp_path)
    with (cold / "receipts.jsonl").open("w", encoding="utf-8") as handle:
        for row in _default_receipts()[:3]:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    with pytest.raises(PairedEfficiencyInputError, match="receipt counts differ"):
        compare_runs(continuous, cold)


def test_missing_receipts_fail_explicitly(tmp_path: Path) -> None:
    continuous, cold = _build_pair(tmp_path)
    (cold / "receipts.jsonl").unlink()
    with pytest.raises(PairedEfficiencyInputError, match="has no receipts.jsonl"):
        compare_runs(continuous, cold)


def test_empty_receipt_stream_fails_explicitly(tmp_path: Path) -> None:
    continuous, cold = _build_pair(tmp_path)
    for directory in (continuous, cold):
        (directory / "receipts.jsonl").write_text("", encoding="utf-8")
    with pytest.raises(PairedEfficiencyInputError, match="empty"):
        compare_runs(continuous, cold)


def test_missing_run_directory_fails_explicitly(tmp_path: Path) -> None:
    _, cold = _build_pair(tmp_path)
    with pytest.raises(PairedEfficiencyInputError, match="does not exist"):
        compare_runs(tmp_path / "absent", cold)


def test_malformed_receipt_line_reports_the_line_number(tmp_path: Path) -> None:
    continuous, cold = _build_pair(tmp_path)
    with (cold / "receipts.jsonl").open("a", encoding="utf-8") as handle:
        handle.write("{not json}\n")
    with pytest.raises(PairedEfficiencyInputError, match="line 5"):
        compare_runs(continuous, cold)


# --------------------------------------------------------------------------
# mismatch accounting
# --------------------------------------------------------------------------


def test_raw_and_path_mismatch_break_comparability_but_are_counted(
        tmp_path: Path) -> None:
    continuous, cold = _build_pair(tmp_path)
    rows = _default_receipts()
    rows[1]["raw_sha256"] = "other-raw"
    rows[3]["path_id"] = "other-path"
    _build_run(cold, receipts=rows, effective_seconds=COLD_EFFECTIVE_SECONDS,
               elapsed_seconds=COLD_ELAPSED_SECONDS, run_id="paired-cold")

    report = compare_runs(continuous, cold)
    validity = report["comparison_validity"]
    assert validity["comparable"] is False
    assert validity["status"] == "not_comparable"
    assert "raw_identity_agreement" in validity["failed_prerequisites"]
    assert "path_agreement" in validity["failed_prerequisites"]
    assert "input_sequence_alignment" in validity["failed_prerequisites"]
    assert validity["output_equivalence"]["claimed"] is False

    fields = report["per_case_agreement"]["fields"]
    assert fields["raw_identity"]["equal"] == 3
    assert fields["raw_identity"]["mismatch"] == 1
    assert fields["raw_identity"]["mismatch_case_indexes"] == [1]
    assert fields["path_id"]["equal"] == 3
    assert fields["path_id"]["mismatch_case_indexes"] == [3]
    assert validity["output_equivalence"]["fields_with_mismatch"] == {
        "raw_identity": 1, "path_id": 1}
    # Mismatching cases are named in the bounded detail rows too.
    assert report["per_case_agreement"]["case_details"][1]["raw_identity"]["equal"] \
        is False
    limits = {item["quantity"] for item in report["limits"]}
    assert "comparison_validity.raw_identity_agreement" in limits
    assert "comparison_validity.path_agreement" in limits


def test_coverage_and_tick_mismatch_keep_comparability_but_forbid_equivalence(
        tmp_path: Path) -> None:
    continuous, cold = _build_pair(tmp_path)
    rows = _default_receipts()
    rows[2]["coverage_hex"] = "1111"
    rows[2]["local_ticks"] = {"cpu": 99, "gpio_a": 99}
    _build_run(cold, receipts=rows, effective_seconds=COLD_EFFECTIVE_SECONDS,
               elapsed_seconds=COLD_ELAPSED_SECONDS, run_id="paired-cold")

    report = compare_runs(continuous, cold)
    validity = report["comparison_validity"]
    # Coverage/state differences are the observation, not a broken premise.
    assert validity["comparable"] is True
    assert validity["output_equivalence"]["claimed"] is False
    assert validity["output_equivalence"]["fields_with_mismatch"] == {
        "coverage_hex": 1, "local_ticks": 1}
    assert validity["failed_prerequisites"] == []
    assert report["per_case_agreement"]["fields"]["coverage_hex"][
        "mismatch_case_indexes"] == [2]
    limits = {item["quantity"] for item in report["limits"]}
    assert "comparison_validity.output_equivalence.claimed" in limits


def test_raw_and_tick_fields_fall_back_to_the_alternate_receipt_keys(
        tmp_path: Path) -> None:
    rows = _default_receipts()
    for row in rows:
        row.pop("raw_sha256")
        row.pop("local_ticks")
        row["total_local_ticks"] = 30
    continuous = _build_run(tmp_path / "continuous", receipts=rows,
                            effective_seconds=CONTINUOUS_EFFECTIVE_SECONDS,
                            elapsed_seconds=12.0, run_id="paired-continuous")
    cold = _build_run(tmp_path / "cold", receipts=[dict(row) for row in rows],
                      effective_seconds=COLD_EFFECTIVE_SECONDS,
                      elapsed_seconds=COLD_ELAPSED_SECONDS, run_id="paired-cold")
    _write_cold_baseline(cold)

    report = compare_runs(continuous, cold)
    fields = report["per_case_agreement"]["fields"]
    assert fields["raw_identity"]["field"] == "online_raw_records_hex"
    assert fields["raw_identity"]["equal"] == 4
    assert fields["local_ticks"]["field"] == "total_local_ticks"
    assert fields["local_ticks"]["equal"] == 4
    assert report["comparison_validity"]["comparable"] is True


def test_absent_raw_identity_is_unverified_and_never_assumed_equal(
        tmp_path: Path) -> None:
    continuous, cold = _build_pair(tmp_path)
    rows = _default_receipts()
    for row in rows:
        row.pop("raw_sha256")
        row.pop("online_raw_records_hex")
    _build_run(cold, receipts=rows, effective_seconds=COLD_EFFECTIVE_SECONDS,
               elapsed_seconds=COLD_ELAPSED_SECONDS, run_id="paired-cold")

    report = compare_runs(continuous, cold)
    fields = report["per_case_agreement"]["fields"]["raw_identity"]
    assert fields["field"] is None
    assert fields["equal"] == 0
    assert fields["mismatch"] == 0
    assert fields["missing"] == 4  # absent evidence is never counted as equal
    validity = report["comparison_validity"]
    assert validity["comparable"] is False
    assert "raw_identity_agreement" in validity["unverified_prerequisites"]
    assert validity["output_equivalence"]["claimed"] is False
    limits = {item["quantity"] for item in report["limits"]}
    assert "comparison_validity.raw_identity_agreement" in limits
    assert "per_case_agreement.raw_identity" in limits


def test_status_mismatch_is_recorded_with_its_transition(tmp_path: Path) -> None:
    continuous, cold = _build_pair(tmp_path)
    rows = _default_receipts()
    rows[3]["status"] = "invalid_input"
    _build_run(cold, receipts=rows, effective_seconds=COLD_EFFECTIVE_SECONDS,
               elapsed_seconds=COLD_ELAPSED_SECONDS, run_id="paired-cold")

    report = compare_runs(continuous, cold)
    assert report["per_case_agreement"]["status_transitions"] == {
        "timeout->invalid_input": 1}
    assert report["per_case_agreement"]["fields"]["status"]["equal"] == 3
    assert report["per_case_agreement"]["fields"]["status"]["mismatch"] == 1
    assert report["comparison_validity"]["output_equivalence"]["claimed"] is False


def test_violations_difference_is_reported_as_an_assertion_mismatch(
        tmp_path: Path) -> None:
    continuous, cold = _build_pair(tmp_path)
    rows = _default_receipts()
    rows[0]["violations"] = [{"rule": "gpio_a_settle", "detail": "late"}]
    _build_run(cold, receipts=rows, effective_seconds=COLD_EFFECTIVE_SECONDS,
               elapsed_seconds=COLD_ELAPSED_SECONDS, run_id="paired-cold")

    report = compare_runs(continuous, cold)
    assert report["per_case_agreement"]["fields"]["violations"]["equal"] == 3
    assert report["per_case_agreement"]["fields"]["violations"]["mismatch"] == 1
    assert "assertion_agreement" in report["comparison_validity"][
        "failed_prerequisites"]
    assert report["comparison_validity"]["output_equivalence"]["claimed"] is False


def test_identity_mismatch_makes_the_pair_not_comparable(tmp_path: Path) -> None:
    continuous, cold = _build_pair(tmp_path)
    _build_run(cold, effective_seconds=COLD_EFFECTIVE_SECONDS,
               elapsed_seconds=COLD_ELAPSED_SECONDS, run_id="paired-cold",
               search_seed=99, max_tests=8,
               source_files=[{"path": "src/myfuzz/scenario/uart_session.py",
                              "sha256": "0" * 64}])
    _write_cold_baseline(cold)

    report = compare_runs(continuous, cold)
    validity = report["comparison_validity"]
    assert validity["comparable"] is False
    for name in ("source_identity_equal", "seed_equal", "budget_equal"):
        assert name in validity["failed_prerequisites"], name
    prerequisites = {item["name"]: item for item in validity["prerequisites"]}
    # Both the declared search seed and report.json's global mutation seed follow
    # the fixture's search_seed argument, so both are flagged.
    assert set(prerequisites["seed_equal"]["evidence"]["mismatch_fields"]) == {
        "search_seed", "global_mutation_seed"}
    assert prerequisites["budget_equal"]["evidence"]["mismatch_fields"] == [
        "max_tests"]
    assert prerequisites["source_identity_equal"]["evidence"]["mismatch_fields"] == [
        "source_files_sha256"]
    assert validity["output_equivalence"]["claimed"] is False


def test_missing_identity_documents_leave_prerequisites_unverified(
        tmp_path: Path) -> None:
    continuous, cold = _build_pair(tmp_path)
    (cold / "online_run_identity.json").unlink()
    (cold / "report.json").unlink()
    report = compare_runs(continuous, cold)
    validity = report["comparison_validity"]
    assert validity["comparable"] is False
    assert set(validity["unverified_prerequisites"]) >= {
        "source_identity_equal", "seed_equal", "budget_equal"}
    assert validity["failed_prerequisites"] == []
    limits = {item["quantity"] for item in report["limits"]}
    assert "comparison_validity.seed_equal" in limits
    assert "comparison_validity.budget_equal" in limits


def test_case_index_alignment_mismatch_is_flagged(tmp_path: Path) -> None:
    continuous, cold = _build_pair(tmp_path)
    continuous_rows = _default_receipts()
    for index, row in enumerate(continuous_rows):
        row["case_index"] = 100 + index
    _build_run(continuous, receipts=continuous_rows,
               effective_seconds=CONTINUOUS_EFFECTIVE_SECONDS,
               elapsed_seconds=12.0, run_id="paired-continuous")
    cold_rows = _default_receipts()
    for index, row in enumerate(cold_rows):
        row["case_index"] = index
    _build_run(cold, receipts=cold_rows, effective_seconds=COLD_EFFECTIVE_SECONDS,
               elapsed_seconds=COLD_ELAPSED_SECONDS, run_id="paired-cold")

    report = compare_runs(continuous, cold)
    alignment = report["per_case_agreement"]["alignment"]
    assert alignment["key"] == "case_index"
    assert alignment["case_index_mismatch_count"] == 4
    assert alignment["case_index_mismatch_case_indexes"] == [0, 1, 2, 3]
    assert "input_sequence_alignment" in report["comparison_validity"][
        "failed_prerequisites"]
    assert report["comparison_validity"]["comparable"] is False


# --------------------------------------------------------------------------
# chain certificates need a producer and a streamable trace
# --------------------------------------------------------------------------


def _certificate(certificate_id: str, admission_id: str) -> dict:
    return {
        "schema_version": "runtime_chain_certificate.v1",
        "certificate_id": certificate_id,
        "status": "certified",
        "direction": "IP_TO_CPU_TO_IP",
        "source_admission_id": admission_id,
        "source_case_index": 0,
        "endpoint_case_index": 0,
        "completed_event_id": 1,
        "hops": [{"hop_id": "gpio_b_irq"}, {"hop_id": "cpu_take"}],
        "missing_hops": [],
    }


class ScriptedChainCertificates:
    """Frozen-protocol producer emitting one scripted certificate per event id."""

    script: dict = {}
    last_kwargs: dict | None = None

    def __init__(self, *, max_pending: int = 128, max_event_gap: int = 4096,
                 require_native_receipts: bool = True) -> None:
        type(self).last_kwargs = {"max_pending": max_pending,
                                  "max_event_gap": max_event_gap,
                                  "require_native_receipts": require_native_receipts}
        self.ingested_events = 0

    @property
    def pending_count(self) -> int:
        return 0

    def ingest(self, events) -> tuple[dict, ...]:
        found = []
        for event in events:
            self.ingested_events += 1
            found.extend(self.script.get(event.get("event_id"), ()))
        return tuple(found)

    def flush(self) -> tuple[dict, ...]:
        return ()


def _scripted_producer(script: dict) -> type:
    return type("Scripted", (ScriptedChainCertificates,), {"script": script})


def test_certified_chains_per_second_is_null_without_a_producer_and_not_zero(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    continuous, cold = _build_pair(tmp_path, events=_default_events())

    def _missing() -> object:
        raise ImportError("no module named myfuzz.scenario.chain_certificates")

    monkeypatch.setattr(
        "myfuzz.scenario.acceptance_metrics._load_chain_certificates", _missing)
    report = compare_runs(continuous, cold)
    for label in ("continuous", "cold"):
        group = report["groups"][label]
        # Events were streamed, but no producer could be resolved: the rate is
        # null with a reason rather than 0.
        assert group["trace_evidence"]["events_ingested"] == 4
        assert group["chain_producer_available"] is False
        assert group["certified_chains"]["total"] is None
        assert group["certified_chains"]["total"] != 0  # null, not a zero count
        assert group["certified_chains_per_second"] is None
        assert group["certified_chains_per_second"] != 0  # null, not zero/s
        assert group["certified_chains_per_second_reason"]
    assert report["limits"]
    reasons = {item["quantity"]: item["reason"] for item in report["limits"]}
    assert "chain certificate producer unavailable" in reasons[
        "groups.continuous.certified_chains_per_second"]
    markdown = render_paired_markdown(report)
    assert "`continuous.certified_chains_per_second` = null" in markdown


def test_injected_producer_yields_exact_chain_counts_and_rates(
        tmp_path: Path) -> None:
    """One producer factory, two different traces: the counts differ per group."""
    continuous_events = _default_events()          # event ids 1..4
    cold_events = _default_events()[:2]            # event ids 1..2
    continuous = _build_run(tmp_path / "continuous", events=continuous_events,
                            effective_seconds=CONTINUOUS_EFFECTIVE_SECONDS,
                            elapsed_seconds=12.0, run_id="paired-continuous")
    cold = _build_run(tmp_path / "cold", events=cold_events,
                      effective_seconds=COLD_EFFECTIVE_SECONDS,
                      elapsed_seconds=COLD_ELAPSED_SECONDS, run_id="paired-cold")
    _write_cold_baseline(cold)
    producer = _scripted_producer({
        event_id: (_certificate(f"cert-{event_id}", f"{event_id:064d}"),)
        for event_id in (1, 2, 3, 4)})

    report = compare_runs(continuous, cold, chain_producer=producer)
    assert report["groups"]["continuous"]["certified_chains"]["total"] == 4
    assert report["groups"]["continuous"]["certified_chains"]["by_direction"] == {
        "IP_TO_CPU_TO_IP": 4, "CPU_TO_IP_TO_CPU": 0}
    assert report["groups"]["continuous"]["certified_chains_per_second"] == \
        pytest.approx(4 / 10.0)
    assert report["groups"]["cold"]["certified_chains"]["total"] == 2
    assert report["groups"]["cold"]["certified_chains_per_second"] == \
        pytest.approx(2 / 40.0)
    assert report["paired"]["certified_chains_delta_cold_minus_continuous"][
        "value"] == -2
    assert report["paired"]["certified_chains_delta_cold_minus_continuous"][
        "reason"] is None
    assert report["paired"][
        "certified_chains_per_second_ratio_cold_over_continuous"][
        "value"] == pytest.approx((2 / 40.0) / (4 / 10.0))  # 0.125
    # The context of a chain count travels with the group: semantics plus the
    # admission denominator, which stays null with a reason when no plan declares it.
    for label in ("continuous", "cold"):
        group = report["groups"][label]
        assert "certificate_id" in group["certified_chains_semantics"]
        admissions = group["chain_completion_by_admission"]
        assert admissions["admissions_total"] is None
        assert admissions["certified_ratio"] is None
        assert admissions["certified_ratio"] != 0
        assert "online_plan.json" in admissions["certified_ratio_reason"]
    limits = {item["quantity"] for item in report["limits"]}
    assert "certified_chains_delta_cold_minus_continuous" not in limits
    assert "certified_chains_per_second_ratio_cold_over_continuous" not in limits


# --------------------------------------------------------------------------
# initialization cost evidence
# --------------------------------------------------------------------------


def test_missing_cold_baseline_keeps_initialization_null_with_reason(
        tmp_path: Path) -> None:
    continuous, cold = _build_pair(tmp_path)
    (cold / "cold_start.json").unlink()
    assert load_cold_baseline(cold) is None
    report = compare_runs(continuous, cold)
    initialization = report["initialization"]
    assert initialization["cold_baseline_document"] is None
    assert initialization["cold_init_seconds_total"] is None
    assert initialization["cold_init_seconds_total"] != 0  # null, not zero
    assert initialization["cold_cases_with_init_seconds"] is None
    assert "cold_start.json is absent" in initialization["reason"]
    assert initialization["cold_init_share_of_elapsed"] is None
    assert initialization["cold_init_share_of_elapsed_reason"]
    limits = {item["quantity"]: item["reason"] for item in report["limits"]}
    assert "initialization.cold_init_seconds_total" in limits
    boundaries = report["comparison_validity"]["boundaries"]
    assert any("No cold initialization cost" in item for item in boundaries)


def test_unexpected_cold_baseline_schema_is_rejected(tmp_path: Path) -> None:
    _, cold = _build_pair(tmp_path)
    document = json.loads((cold / "cold_start.json").read_text(encoding="utf-8"))
    document["schema_version"] = "something_else.v9"
    (cold / "cold_start.json").write_text(json.dumps(document) + "\n",
                                          encoding="utf-8")
    with pytest.raises(PairedEfficiencyInputError, match="schema_version"):
        load_cold_baseline(cold)


def test_cold_baseline_raw_hex_mismatch_is_reported(tmp_path: Path) -> None:
    continuous, cold = _build_pair(tmp_path)
    document = json.loads((cold / "cold_start.json").read_text(encoding="utf-8"))
    document["cases"][2]["raw_hex"] = "ffffffffffffffff"
    (cold / "cold_start.json").write_text(json.dumps(document) + "\n",
                                          encoding="utf-8")
    report = compare_runs(continuous, cold)
    alignment = report["initialization"]["cold_baseline_input_alignment"]
    assert alignment["available"] is True
    assert alignment["compared"] == 4
    assert alignment["equal"] == 3
    assert alignment["mismatch_case_indexes"] == [2]


def test_cold_baseline_total_seconds_fallback_when_receipts_lack_timing(
        tmp_path: Path) -> None:
    rows = [_receipt(index, total=None) for index in range(4)]
    rows[3]["status"] = "timeout"
    continuous = _build_run(tmp_path / "continuous", receipts=rows,
                            effective_seconds=CONTINUOUS_EFFECTIVE_SECONDS,
                            elapsed_seconds=12.0, run_id="paired-continuous")
    cold = _build_run(tmp_path / "cold", receipts=rows,
                      effective_seconds=COLD_EFFECTIVE_SECONDS,
                      elapsed_seconds=COLD_ELAPSED_SECONDS, run_id="paired-cold")
    _write_cold_baseline(cold, with_totals=True)

    report = compare_runs(continuous, cold)
    # Continuous totals are absent -> null with a reason, never zero.
    continuous_totals = report["groups"]["continuous"]["per_case_total_seconds"]
    assert continuous_totals["count"] == 0
    assert continuous_totals["p50"] is None
    assert continuous_totals["p95"] is None
    assert continuous_totals["source"] is None
    assert "carry no finite" in continuous_totals["reason"]
    # Cold totals fall back to the cold-start document, with the boundary named.
    cold_totals = report["groups"]["cold"]["per_case_total_seconds"]
    assert cold_totals["count"] == 4
    assert cold_totals["p50"] == 2.5
    assert cold_totals["p95"] == pytest.approx(3.85)
    assert cold_totals["source"] == COLD_DOCUMENT_TOTAL_SOURCE
    limits = {item["quantity"]: item["reason"] for item in report["limits"]}
    assert "groups.cold.per_case_total_seconds" in limits
    assert "falling back to" in limits["groups.cold.per_case_total_seconds"]
    assert any("different artifacts per group" in item
               for item in report["comparison_validity"]["boundaries"])


# --------------------------------------------------------------------------
# rates, boundaries, truncation
# --------------------------------------------------------------------------


def test_rates_use_elapsed_seconds_when_no_effective_window_is_declared(
        tmp_path: Path) -> None:
    continuous, cold = _build_pair(tmp_path)
    for directory, elapsed in ((continuous, 20.0), (cold, 50.0)):
        report = json.loads((directory / "report.json").read_text(encoding="utf-8"))
        report["effective_search_seconds"] = None
        report["elapsed_seconds"] = elapsed
        (directory / "report.json").write_text(json.dumps(report, sort_keys=True) + "\n",
                                              encoding="utf-8")
    result = compare_runs(continuous, cold)
    assert result["groups"]["continuous"]["cases_per_second_boundary"] == \
        "elapsed_seconds"
    assert result["groups"]["continuous"]["cases_per_second"] == 4 / 20.0
    assert result["groups"]["cold"]["cases_per_second"] == 4 / 50.0


def test_rate_ratio_is_null_when_the_two_denominators_differ(
        tmp_path: Path) -> None:
    continuous, cold = _build_pair(tmp_path)
    report = json.loads((cold / "report.json").read_text(encoding="utf-8"))
    report["effective_search_seconds"] = None
    report["elapsed_seconds"] = COLD_ELAPSED_SECONDS
    (cold / "report.json").write_text(json.dumps(report, sort_keys=True) + "\n",
                                      encoding="utf-8")
    result = compare_runs(continuous, cold)
    ratio = result["paired"]["cases_per_second_ratio_cold_over_continuous"]
    assert ratio["value"] is None
    assert ratio["value"] != 0  # null, not a zero ratio
    assert "different rate denominators" in ratio["reason"]
    assert any("different denominator boundary per group" in item
               for item in result["comparison_validity"]["boundaries"])


def test_rates_are_null_when_no_window_is_declared(tmp_path: Path) -> None:
    continuous, cold = _build_pair(tmp_path)
    for directory in (continuous, cold):
        report = json.loads((directory / "report.json").read_text(encoding="utf-8"))
        report["effective_search_seconds"] = None
        report["elapsed_seconds"] = None
        (directory / "report.json").write_text(json.dumps(report, sort_keys=True) + "\n",
                                              encoding="utf-8")
    result = compare_runs(continuous, cold)
    for label in ("continuous", "cold"):
        group = result["groups"][label]
        assert group["cases_per_second"] is None
        assert group["cases_per_second"] != 0  # null, not zero/s
        assert group["cases_per_second_boundary"] is None
        assert "no per-second rate" in group["cases_per_second_reason"]
    limits = {item["quantity"] for item in result["limits"]}
    assert "groups.continuous.cases_per_second" in limits
    assert "groups.cold.cases_per_second" in limits


def test_max_items_truncation_is_recorded(tmp_path: Path) -> None:
    continuous, cold = _build_pair(tmp_path)
    report = compare_runs(continuous, cold, max_items=2)
    agreement = report["per_case_agreement"]
    assert agreement["cases_compared"] == 2
    assert agreement["truncated"] is True
    assert agreement["receipt_rows"] == {"continuous": 4, "cold": 4}
    assert len(agreement["case_details"]) == 2
    # Rates still describe the whole receipt stream; the boundary says so.
    assert report["groups"]["continuous"]["cases_per_second"] == 0.4
    assert any("first max_items=2" in item
               for item in report["comparison_validity"]["boundaries"])
    limits = {item["quantity"]: item["reason"] for item in report["limits"]}
    assert "per_case_agreement" in limits


def test_invalid_max_items_is_rejected(tmp_path: Path) -> None:
    continuous, cold = _build_pair(tmp_path)
    with pytest.raises(ValueError, match="max_items"):
        compare_runs(continuous, cold, max_items=0)
    with pytest.raises(ValueError, match="max_case_details"):
        compare_runs(continuous, cold, max_case_details=0)


def test_single_case_pair_yields_p50_only_and_explains_missing_p95(
        tmp_path: Path) -> None:
    rows = [_receipt(0, total=7.5)]
    continuous = _build_run(tmp_path / "continuous", receipts=rows,
                            effective_seconds=CONTINUOUS_EFFECTIVE_SECONDS,
                            elapsed_seconds=12.0, run_id="paired-continuous")
    cold = _build_run(tmp_path / "cold", receipts=rows,
                      effective_seconds=COLD_EFFECTIVE_SECONDS,
                      elapsed_seconds=COLD_ELAPSED_SECONDS, run_id="paired-cold")
    _write_cold_baseline(cold, count=1, init_seconds=(3.0,))
    report = compare_runs(continuous, cold)
    totals = report["groups"]["continuous"]["per_case_total_seconds"]
    assert totals["count"] == 1
    assert totals["p50"] == 7.5
    assert totals["p95"] is None
    assert report["groups"]["continuous"]["cases_per_second"] == 1 / 10.0
    limits = {item["quantity"]: item["reason"] for item in report["limits"]}
    assert "p95 needs" in limits["groups.continuous.per_case_total_seconds"]
    assert report["initialization"]["cold_init_seconds_total"] == 3.0


def test_replay_directories_are_reported_when_analyzed(tmp_path: Path) -> None:
    continuous, cold = _build_pair(tmp_path, events=_default_events())
    continuous_replay = _build_run(tmp_path / "continuous-replay",
                                   effective_seconds=CONTINUOUS_EFFECTIVE_SECONDS,
                                   elapsed_seconds=12.0, run_id="replay")
    cold_replay = _build_run(tmp_path / "cold-replay",
                             effective_seconds=COLD_EFFECTIVE_SECONDS,
                             elapsed_seconds=COLD_ELAPSED_SECONDS, run_id="replay")
    _write_jsonl_trace(continuous_replay, _default_events())
    _write_jsonl_trace(cold_replay, _default_events())

    report = compare_runs(continuous, cold,
                          continuous_replay_dir=continuous_replay,
                          cold_replay_dir=cold_replay)
    for label in ("continuous", "cold"):
        group = report["groups"][label]
        assert group["replay_analyzed"] is True
        assert group["replay_verified"] is True
    limits = {item["quantity"] for item in report["limits"]}
    assert "groups.continuous.replay_verified" not in limits


# --------------------------------------------------------------------------
# streaming memory discipline
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def fifty_thousand_pair(tmp_path_factory: pytest.TempPathFactory) -> tuple:
    """One 50,000-case pair per module, reused by both memory assertions."""
    base = tmp_path_factory.mktemp("fifty-thousand")
    rows = [_receipt(index, total=None, coverage="0100") for index in range(50_000)]
    continuous = _build_run(base / "continuous", receipts=rows,
                            effective_seconds=CONTINUOUS_EFFECTIVE_SECONDS,
                            elapsed_seconds=12.0, run_id="paired-continuous")
    cold = _build_run(base / "cold", receipts=rows,
                      effective_seconds=COLD_EFFECTIVE_SECONDS,
                      elapsed_seconds=COLD_ELAPSED_SECONDS, run_id="paired-cold")
    _write_cold_baseline(cold, count=4)
    receipt_bytes = (continuous / "receipts.jsonl").stat().st_size
    assert receipt_bytes > 10_000_000
    return continuous, cold, receipt_bytes


def test_streams_fifty_thousand_receipts_with_bounded_extra_memory(
        fifty_thousand_pair: tuple, tmp_path: Path) -> None:
    continuous, cold, receipt_bytes = fifty_thousand_pair
    # Warm up the lazily imported analyzer modules on a tiny pair first: the
    # property under test is per-row streaming, not the one-time import cost of
    # the analyzer (measured separately in the fresh-interpreter test below).
    warm_continuous = _build_run(tmp_path / "warm-continuous",
                                 receipts=[_receipt(0, total=1.0)],
                                 effective_seconds=1.0, elapsed_seconds=1.0,
                                 run_id="warm")
    warm_cold = _build_run(tmp_path / "warm-cold", receipts=[_receipt(0, total=1.0)],
                           effective_seconds=1.0, elapsed_seconds=1.0, run_id="warm")
    compare_runs(warm_continuous, warm_cold)

    tracemalloc.start()
    try:
        report = compare_runs(continuous, cold)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert report["per_case_agreement"]["cases_compared"] == 50_000
    assert report["per_case_agreement"]["receipt_rows"] == {
        "continuous": 50_000, "cold": 50_000}
    assert report["per_case_agreement"]["fields"]["status"]["equal"] == 50_000
    assert report["memory_model"]["receipt_rows_retained"] == 0
    assert report["memory_model"]["case_details_retained"] == 200
    assert report["memory_model"]["timing_samples_retained"] == {
        "continuous": 0, "cold": 0}
    # Two ~17 MB receipt files are streamed line by line; a peak near the file
    # size would mean rows were retained.
    assert receipt_bytes > 10_000_000
    assert peak < 4_000_000, f"peak traced memory {peak} bytes is not bounded"


def test_fresh_interpreter_peak_stays_below_one_receipt_file(
        fifty_thousand_pair: tuple) -> None:
    """A cold interpreter, imports included, still never holds a whole file."""
    continuous, cold, receipt_bytes = fifty_thousand_pair
    program = (
        "import json, sys, tracemalloc\n"
        "sys.path.insert(0, 'src')\n"
        "from myfuzz.scenario.paired_efficiency import compare_runs\n"
        "tracemalloc.start()\n"
        "report = compare_runs(sys.argv[1], sys.argv[2])\n"
        "_, peak = tracemalloc.get_traced_memory()\n"
        "print(json.dumps({'peak': peak,\n"
        "                  'compared': report['per_case_agreement']['cases_compared'],\n"
        "                  'retained': report['memory_model']['receipt_rows_retained']}))\n")
    process = subprocess.run([sys.executable, "-c", program, str(continuous), str(cold)],
                             cwd=str(ROOT), capture_output=True, text=True,
                             check=False)
    assert process.returncode == 0, process.stderr
    observed = json.loads(process.stdout.strip().splitlines()[-1])
    assert observed["compared"] == 50_000
    assert observed["retained"] == 0
    # Includes the interpreter's lazy module imports; staying below one receipt
    # file proves no pass materializes all rows at once.
    assert observed["peak"] < receipt_bytes, observed


def test_details_are_truncated_but_aggregates_cover_every_case(tmp_path: Path) -> None:
    rows = [_receipt(index, total=float(index + 1)) for index in range(5)]
    continuous = _build_run(tmp_path / "continuous", receipts=rows,
                            effective_seconds=CONTINUOUS_EFFECTIVE_SECONDS,
                            elapsed_seconds=12.0, run_id="paired-continuous")
    cold = _build_run(tmp_path / "cold", receipts=rows,
                      effective_seconds=COLD_EFFECTIVE_SECONDS,
                      elapsed_seconds=COLD_ELAPSED_SECONDS, run_id="paired-cold")
    _write_cold_baseline(cold, count=4)
    report = compare_runs(continuous, cold, max_case_details=2)
    agreement = report["per_case_agreement"]
    assert agreement["cases_compared"] == 5
    assert len(agreement["case_details"]) == 2
    assert agreement["case_details_truncated_at"] == 2
    assert agreement["fields"]["status"]["equal"] == 5  # aggregates are complete
    assert report["memory_model"]["case_details_retained"] == 2


# --------------------------------------------------------------------------
# markdown
# --------------------------------------------------------------------------


def test_markdown_puts_the_evidence_boundary_first(tmp_path: Path) -> None:
    continuous, cold = _build_pair(tmp_path)
    markdown = render_paired_markdown(compare_runs(continuous, cold))
    lines = markdown.splitlines()
    assert lines[0].startswith("# Paired first-step efficiency")
    boundary = lines.index("## Evidence boundary")
    assert boundary < lines.index("## Prerequisites for comparability")
    measured = lines.index("Measured by this comparison (recomputable from the two "
                           "run directories):")
    nulls = lines.index("Not provable from these artifacts (reported as `null`, "
                        "never as `0`):")
    limits = lines.index("Limits and non-extrapolable boundaries:")
    assert boundary < measured < nulls < limits
    assert "- `continuous.cases_per_second` = 0.4" in markdown
    assert "- `initialization.cold_init_seconds_total` = 10" in markdown
    assert "- `initialization.continuous_init_seconds` = null" in markdown
    assert "must not be subtracted from each other as a saving" in markdown
    assert markdown.endswith("\n")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _run_cli(*arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(CLI), *arguments],
                          capture_output=True, text=True, check=False,
                          cwd=str(ROOT))


def test_cli_compare_writes_json_and_markdown_and_exits_zero(tmp_path: Path) -> None:
    continuous, cold = _build_pair(tmp_path)
    json_out = tmp_path / "out" / "paired.json"
    markdown_out = tmp_path / "out" / "paired.md"
    process = _run_cli("compare", "--continuous", str(continuous),
                       "--cold", str(cold), "--json-out", str(json_out),
                       "--markdown-out", str(markdown_out))
    assert process.returncode == 0, process.stderr
    printed = json.loads(process.stdout)
    assert printed["schema_version"] == SCHEMA_VERSION
    written = json.loads(json_out.read_text(encoding="utf-8"))
    assert written == printed
    markdown = markdown_out.read_text(encoding="utf-8")
    assert markdown.splitlines()[1] == ""
    assert "## Evidence boundary" in markdown


def test_cli_compare_exits_nonzero_and_explains_unequal_case_counts(
        tmp_path: Path) -> None:
    continuous, cold = _build_pair(tmp_path)
    with (cold / "receipts.jsonl").open("w", encoding="utf-8") as handle:
        for row in _default_receipts()[:2]:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    process = _run_cli("compare", "--continuous", str(continuous),
                       "--cold", str(cold))
    assert process.returncode == 2
    assert "paired-efficiency-insufficient-data" in process.stderr
    assert "receipt counts differ" in process.stderr
    assert process.stdout == ""


def test_cli_compare_exits_nonzero_when_receipts_are_missing(tmp_path: Path) -> None:
    continuous, cold = _build_pair(tmp_path)
    (continuous / "receipts.jsonl").unlink()
    process = _run_cli("compare", "--continuous", str(continuous),
                       "--cold", str(cold))
    assert process.returncode == 2
    assert "has no receipts.jsonl" in process.stderr


def test_cli_no_chain_producer_reports_null_rates(tmp_path: Path) -> None:
    continuous, cold = _build_pair(tmp_path, events=_default_events())
    process = _run_cli("compare", "--continuous", str(continuous),
                       "--cold", str(cold), "--no-chain-producer")
    assert process.returncode == 0, process.stderr
    report = json.loads(process.stdout)
    for label in ("continuous", "cold"):
        assert report["groups"][label]["certified_chains_per_second"] is None
        assert report["groups"][label]["certified_chains_per_second"] != 0
        assert "no-chain-producer" in report["groups"][label][
            "certified_chains_per_second_reason"]


def test_cli_reports_a_missing_directory_as_insufficient_data(tmp_path: Path) -> None:
    _, cold = _build_pair(tmp_path)
    process = _run_cli("compare", "--continuous", str(tmp_path / "absent"),
                       "--cold", str(cold))
    assert process.returncode == 2
    assert "does not exist" in process.stderr
