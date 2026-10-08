"""Tests for the read-only same-condition arm equivalence comparison.

The fixtures are *synthetic but real-shaped*: ``receipts.jsonl``,
``report.json``, ``online_run_identity.json`` and ``decoder_manifest.json`` are
written with the fields the saved Ibex + dual-PULP runs actually carry, so the
comparison is exercised on the same contract the saved run directories expose.
Every fixture directory also carries a deliberately *poisoned* trace file
(``online_final_trace.json`` / ``online_events.jsonl`` hold invalid JSON): if
the comparator ever loaded a trace the test would fail, which pins the
"bounded, streamed read" requirement to an observable.

Nothing here starts RTL, Verilator, cargo or the RFuzz client.  The one test
that touches a real saved pair only reads ``receipts.jsonl``, ``report.json``,
``online_run_identity.json`` and ``decoder_manifest.json``.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from myfuzz.scenario.arm_equivalence import (
    SCHEMA_VERSION,
    ArmEquivalenceInputError,
    compare_arms,
    render_markdown,
)


ROOT = Path(__file__).resolve().parents[2]
CLI_SCRIPT = ROOT / "scripts" / "compare_arm_equivalence.py"

REAL_INITIAL_RAM_OFF = ROOT / "runs" / "current-dataflow-p4-initial-ram-off-20261007-online"
REAL_INITIAL_RAM_ON = ROOT / "runs" / "current-dataflow-p4-initial-ram-on-20261007-online"


# ---------------------------------------------------------------------------
# fixture helpers: synthetic runs with the real artifact shape
# ---------------------------------------------------------------------------


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _receipt(*, index: int, raw: str, status: str = "complete",
             genome: str | None = "genome-a", path_id: str | None = "path-a",
             applied_path: int | None = 0,
             direction: str = "CPU_TO_IP_TO_CPU",
             applied_sources: tuple[str, ...] = ("cpu.online_instruction",),
             violations: tuple[str, ...] = (),
             coverage: str = "00000000",
             local_ticks: dict | None = None,
             total_local_ticks: int = 96,
             rejection: object = None, error: object = None,
             omit: tuple[str, ...] = ()) -> dict:
    """One receipt with the shape the online path persists."""
    ticks = {"cpu": 32, "gpio_a": 32, "gpio_b": 32}
    if local_ticks is not None:
        ticks = dict(local_ticks)
    row = {
        "run_id": "synthetic",
        "slot": index,
        "case_id": f"online-{index}-{raw[:8]}",
        "status": status,
        "raw_sha256": raw,
        "online_raw_records_hex": [raw],
        "effective_genome_sha256": genome,
        "genome_sha256": genome,
        "path_id": path_id,
        "applied_path": applied_path,
        "direction": direction,
        "applied_sources": list(applied_sources),
        "applied_source_ids": list(applied_sources),
        "source_id": applied_sources[0] if applied_sources else None,
        "violations": list(violations),
        "rejection": rejection,
        "error": error,
        "coverage_hex": coverage,
        "local_ticks": ticks,
        "total_local_ticks": total_local_ticks,
        "online_phase_timing_seconds": {"total": 0.25},
    }
    for name in omit:
        row.pop(name, None)
    return row


def _write_run(directory: Path, *, receipts: list[dict],
               run_id: str = "synthetic", max_tests: int | None = None,
               duration_seconds: float = 150.0, search_seed: int = 20261007,
               decoder_manifest: dict | None = None,
               report_decoder_sha: str | None = None,
               source_files_sha: str = "source-files-sha",
               component_identity_sha: str = "component-identity-sha",
               targets_sha: str = "targets-sha",
               omit_receipts: bool = False,
               omit_identity: bool = False,
               poison_trace: bool = True) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    if not omit_receipts:
        with (directory / "receipts.jsonl").open("w", encoding="utf-8") as handle:
            for row in receipts:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
    manifest = ({"flow_by_target": {"cpu_to_ip_to_cpu": ["F4"]},
                 "max_steps": 96, "max_input_bytes": 64}
                if decoder_manifest is None else decoder_manifest)
    (directory / "decoder_manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    manifest_sha = report_decoder_sha or _sha256(manifest)
    statuses: dict[str, int] = {}
    for row in receipts:
        name = row.get("status")
        name = name if isinstance(name, str) and name else "unknown"
        statuses[name] = statuses.get(name, 0) + 1
    report = {
        "tests": len(receipts),
        "statuses": statuses,
        "execution_mode": "online_cases",
        "execution_status": "complete",
        "session_status": "complete",
        "decoder_manifest_sha256": manifest_sha,
        "record_semantics": "mutation_decisions_not_dut_cycles",
        "total_local_ticks_semantics": "sum_of_independent_local_ticks_cost_only",
        "clock_model": "independent_local_ticks_and_causal_order",
        "global_mutation_seed": search_seed,
        "effective_search_seconds": 1.0,
        "elapsed_seconds": 1.25,
    }
    (directory / "report.json").write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    if not omit_identity:
        identity = {
            "schema_version": "scenario_online_run_identity_envelope.v1",
            "sha256": f"identity-{run_id}",
            "identity": {
                "run_config": {
                    "run_id": run_id,
                    "max_tests": len(receipts) if max_tests is None else max_tests,
                    "duration_seconds": duration_seconds,
                    "search_seed": search_seed,
                    "feedback_interval": 16,
                },
                "source_files": [
                    {"path": "rtl/top.sv", "sha256": source_files_sha},
                    {"path": "rtl/cpu.sv", "sha256": "cpu-sha"},
                ],
                "session": {"component_identity_sha256": component_identity_sha},
                "feedback": {"targets_sha256": targets_sha},
            },
        }
        (directory / "online_run_identity.json").write_text(
            json.dumps(identity, sort_keys=True, indent=2) + "\n",
            encoding="utf-8")
    if poison_trace:
        # Never loaded by the comparator; invalid JSON so any load would raise.
        (directory / "online_final_trace.json").write_text(
            '{"broken": ', encoding="utf-8")
        (directory / "online_events.jsonl").write_text(
            '{"broken": \n', encoding="utf-8")
    return directory


def _shared_receipts(count: int = 4) -> list[dict]:
    return [_receipt(index=i, raw=f"{i:064x}", coverage=f"{i:08x}")
            for i in range(count)]


def _family(document: dict, name: str) -> dict:
    for block in document["families"]:
        if block["family"] == name:
            return block
    raise AssertionError(f"family {name!r} missing from the document")


def _field(document: dict, family: str, name: str) -> dict:
    for block in _family(document, family)["fields"]:
        if block["name"] == name:
            return block
    raise AssertionError(f"field {family}.{name} missing from the document")


def _condition(document: dict, name: str) -> dict:
    for block in document["output_equivalence"]["conditions"]:
        if block["condition"] == name:
            return block
    raise AssertionError(f"condition {name!r} missing from the document")


def _load_cli():
    spec = importlib.util.spec_from_file_location("_arm_equivalence_cli",
                                                  CLI_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# 1. identical arms
# ---------------------------------------------------------------------------


def test_identical_arms_claim_output_equivalence(tmp_path: Path) -> None:
    left = _write_run(tmp_path / "left", receipts=_shared_receipts())
    right = _write_run(tmp_path / "right", receipts=_shared_receipts())
    document = compare_arms(left, right)

    assert document["schema_version"] == SCHEMA_VERSION
    assert document["evidence_status"] == "compared"
    assert document["refusal"] is None
    assert document["window"]["shared_prefix_cases"] == 4
    assert document["verdict"]["families"] == {
        name: "equivalent" for name in document["verdict"]["families"]}
    assert document["verdict"]["not_equivalent_families"] == []
    assert document["verdict"]["unknown_families"] == []
    assert document["output_equivalence"]["claimed"] is True
    assert all(block["satisfied"]
               for block in document["output_equivalence"]["conditions"])
    assert document["output_equivalence"]["not_claimed_reasons"] == []


def test_identical_arms_keep_per_field_counts(tmp_path: Path) -> None:
    left = _write_run(tmp_path / "left", receipts=_shared_receipts(3))
    right = _write_run(tmp_path / "right", receipts=_shared_receipts(3))
    document = compare_arms(left, right)

    block = _family(document, "coverage")
    assert block["verdict"] == "equivalent"
    field = _field(document, "coverage", "coverage_hex")
    assert field["role"] == "verdict"
    assert field["in_scope"] is True
    assert field["equal"] == 3
    assert field["unequal"] == 0
    assert field["missing_left"] == 0
    assert field["missing_right"] == 0
    assert field["missing_both"] == 0
    assert field["unequal_case_indexes"] == []
    # a single booleans-only verdict is not enough: the counts are mandatory
    assert set(document["verdict"]["families"]) == {
        "status", "effective_genome", "path", "direction", "applied_sources",
        "checker_violations", "coverage", "local_ticks"}


# ---------------------------------------------------------------------------
# 2. one differing field
# ---------------------------------------------------------------------------


def test_one_differing_field_marks_that_family_not_equivalent(
        tmp_path: Path) -> None:
    left_receipts = _shared_receipts(4)
    right_receipts = _shared_receipts(4)
    right_receipts[1]["coverage_hex"] = "ffffffff"
    left = _write_run(tmp_path / "left", receipts=left_receipts)
    right = _write_run(tmp_path / "right", receipts=right_receipts)
    document = compare_arms(left, right)

    coverage = _family(document, "coverage")
    assert coverage["verdict"] == "not_equivalent"
    assert "coverage_hex" in coverage["reason"]
    field = _field(document, "coverage", "coverage_hex")
    assert field["equal"] == 3
    assert field["unequal"] == 1
    assert field["unequal_case_indexes"] == [1]
    assert field["missing_left"] == 0 and field["missing_right"] == 0

    # only the coverage family flips; the rest stay equivalent
    assert document["verdict"]["not_equivalent_families"] == ["coverage"]
    assert document["verdict"]["families"]["status"] == "equivalent"
    assert document["verdict"]["families"]["local_ticks"] == "equivalent"
    assert document["output_equivalence"]["claimed"] is False
    assert _condition(document, "every_inscope_field_equivalent")["satisfied"] is False
    assert any("coverage" in reason
               for reason in document["output_equivalence"]["not_claimed_reasons"])


def test_divergence_outside_the_window_is_reported_as_window_only(
        tmp_path: Path) -> None:
    left_receipts = _shared_receipts(4)
    right_receipts = _shared_receipts(4)
    # the raw input diverges at case 2; the coverage difference at case 3 is
    # therefore *outside* the comparable window and must not enter the tallies
    right_receipts[2]["raw_sha256"] = "f" * 64
    right_receipts[3]["coverage_hex"] = "ffffffff"
    left = _write_run(tmp_path / "left", receipts=left_receipts)
    right = _write_run(tmp_path / "right", receipts=right_receipts)
    document = compare_arms(left, right)

    assert document["window"]["shared_prefix_cases"] == 2
    assert document["window"]["first_divergent_case"]["case_index"] == 2
    assert _family(document, "coverage")["verdict"] == "equivalent"
    assert _field(document, "coverage", "coverage_hex")["equal"] == 2
    assert document["output_equivalence"]["claimed"] is False
    assert _condition(document, "window_covers_right_arm")["satisfied"] is False


# ---------------------------------------------------------------------------
# 3. missing fields are unknown, never silently equal
# ---------------------------------------------------------------------------


def test_field_missing_on_one_arm_is_unknown_not_equal(tmp_path: Path) -> None:
    left_receipts = _shared_receipts(3)
    right_receipts = _shared_receipts(3)
    right_receipts[2].pop("path_id")
    left = _write_run(tmp_path / "left", receipts=left_receipts)
    right = _write_run(tmp_path / "right", receipts=right_receipts)
    document = compare_arms(left, right)

    path = _family(document, "path")
    assert path["verdict"] == "unknown"
    assert "missing" in path["reason"] or "absent" in path["reason"]
    field = _field(document, "path", "path_id")
    assert field["verdict"] == "unknown"
    assert field["equal"] == 2
    assert field["unequal"] == 0
    assert field["missing_right"] == 1
    assert field["missing_case_indexes"] == [2]
    assert document["output_equivalence"]["claimed"] is False
    assert document["verdict"]["unknown_families"] == ["path"]


def test_field_null_on_both_arms_is_unknown_not_equal(tmp_path: Path) -> None:
    left_receipts = _shared_receipts(3)
    right_receipts = _shared_receipts(3)
    # the same case records "no path" on both arms: symmetric unobservability
    for rows in (left_receipts, right_receipts):
        rows[1]["path_id"] = None
        rows[1]["applied_path"] = None
    left = _write_run(tmp_path / "left", receipts=left_receipts)
    right = _write_run(tmp_path / "right", receipts=right_receipts)
    document = compare_arms(left, right)

    field = _field(document, "path", "path_id")
    assert field["verdict"] == "unknown"
    assert field["equal"] == 2
    assert field["missing_both"] == 1
    assert field["missing_left"] == 0 and field["missing_right"] == 0
    assert field["unequal"] == 0
    assert _family(document, "path")["verdict"] == "unknown"
    assert _family(document, "status")["verdict"] == "equivalent"
    assert document["output_equivalence"]["claimed"] is False


def test_undeclared_receipt_fields_are_reported_outside_the_projection(
        tmp_path: Path) -> None:
    left_receipts = _shared_receipts(3)
    right_receipts = _shared_receipts(3)
    for row in left_receipts:
        row["run_id"] = "arm-left"
        row["semantic_sha256"] = "semantic-left"
    for row in right_receipts:
        row["run_id"] = "arm-right"
        row["semantic_sha256"] = "semantic-right"
    left = _write_run(tmp_path / "left", receipts=left_receipts)
    right = _write_run(tmp_path / "right", receipts=right_receipts)
    document = compare_arms(left, right)

    # the declared projection is identical, so the claim stands ...
    assert all(block["verdict"] == "equivalent" for block in document["families"])
    assert document["output_equivalence"]["claimed"] is True
    # ... but fields outside the declared projection are still reported
    outside = document["outside_declared_projection"]
    assert "semantic_sha256" in outside["fields_with_differences"]
    assert "run_id" in outside["fields_with_differences"]
    entry = next(item for item in outside["fields"]
                 if item["field"] == "semantic_sha256")
    assert entry["classification"] == "other"
    assert entry["unequal"] == 3
    assert outside["difference_classes"]["other"] >= 1
    assert outside["difference_classes"]["run_bookkeeping"] >= 1
    text = render_markdown(document)
    assert "outside" in text.lower()
    assert "semantic_sha256" in text


def test_undeclared_field_tracking_is_bounded(tmp_path: Path) -> None:
    left_receipts = _shared_receipts(2)
    right_receipts = _shared_receipts(2)
    for index, row in enumerate(left_receipts):
        row["extra-alpha"] = f"a{index}"
        row["extra-beta"] = f"b{index}"
        row["extra-gamma"] = f"c{index}"
    for index, row in enumerate(right_receipts):
        row["extra-alpha"] = f"A{index}"
        row["extra-beta"] = f"B{index}"
        row["extra-gamma"] = f"C{index}"
    left = _write_run(tmp_path / "left", receipts=left_receipts)
    right = _write_run(tmp_path / "right", receipts=right_receipts)
    document = compare_arms(left, right, max_undeclared_fields=2)

    outside = document["outside_declared_projection"]
    assert outside["max_tracked_fields"] == 2
    assert outside["truncated"] is True
    assert len(outside["fields"]) <= 2
    assert outside["skipped_field_count"] >= 1


def test_conditional_context_field_cannot_drive_a_family_verdict(
        tmp_path: Path) -> None:
    left_receipts = _shared_receipts(3)
    right_receipts = _shared_receipts(3)
    # ``error`` is null on success cases by contract; only one case carries it
    left_receipts[0]["error"] = "input_invalid: short frame"
    right_receipts[0]["error"] = "input_invalid: short frame"
    left = _write_run(tmp_path / "left", receipts=left_receipts)
    right = _write_run(tmp_path / "right", receipts=right_receipts)
    document = compare_arms(left, right)

    checker = _family(document, "checker_violations")
    assert checker["verdict"] == "equivalent"
    error = _field(document, "checker_violations", "error")
    assert error["role"] == "context"
    assert error["in_scope"] is True
    assert error["equal"] == 1
    assert error["missing_both"] == 2
    assert document["output_equivalence"]["claimed"] is True


# ---------------------------------------------------------------------------
# 4. fail-closed refusals
# ---------------------------------------------------------------------------


def test_refuses_when_the_arms_share_no_raw_prefix(tmp_path: Path) -> None:
    left_receipts = _shared_receipts(3)
    right_receipts = _shared_receipts(3)
    right_receipts[0]["raw_sha256"] = "a" * 64
    left = _write_run(tmp_path / "left", receipts=left_receipts)
    right = _write_run(tmp_path / "right", receipts=right_receipts)
    document = compare_arms(left, right)

    assert document["evidence_status"] == "refused"
    assert document["refusal"]["code"] == "zero_shared_prefix"
    assert document["window"]["shared_prefix_cases"] == 0
    assert document["window"]["first_divergent_case"]["case_index"] == 0
    assert document["output_equivalence"]["claimed"] is False
    assert all(block["verdict"] == "unknown" for block in document["families"])


def test_refuses_on_decoder_manifest_mismatch(tmp_path: Path) -> None:
    left = _write_run(tmp_path / "left", receipts=_shared_receipts())
    right = _write_run(
        tmp_path / "right", receipts=_shared_receipts(),
        decoder_manifest={"flow_by_target": {"cpu_to_ip_to_cpu": ["F9"]},
                          "max_steps": 96, "max_input_bytes": 64})
    document = compare_arms(left, right)

    assert document["evidence_status"] == "refused"
    assert document["refusal"]["code"] == "decoder_manifest_mismatch"
    assert document["window"]["computable"] is False


def test_refuses_on_source_identity_mismatch(tmp_path: Path) -> None:
    left = _write_run(tmp_path / "left", receipts=_shared_receipts())
    right = _write_run(tmp_path / "right", receipts=_shared_receipts(),
                       source_files_sha="other-source-files-sha")
    document = compare_arms(left, right)

    assert document["evidence_status"] == "refused"
    assert document["refusal"]["code"] == "source_identity_mismatch"
    assert "source_files_sha256" in document["refusal"]["reason"]


def test_refuses_when_the_source_identity_is_undecodable(tmp_path: Path) -> None:
    left = _write_run(tmp_path / "left", receipts=_shared_receipts())
    right = _write_run(tmp_path / "right", receipts=_shared_receipts(),
                       omit_identity=True)
    document = compare_arms(left, right)

    assert document["evidence_status"] == "refused"
    assert document["refusal"]["code"] == "source_identity_undecodable"


def test_refuses_when_receipts_are_absent(tmp_path: Path) -> None:
    left = _write_run(tmp_path / "left", receipts=_shared_receipts())
    right = _write_run(tmp_path / "right", receipts=[], omit_receipts=True)
    document = compare_arms(left, right)

    assert document["evidence_status"] == "refused"
    assert document["refusal"]["code"] == "no_receipts"
    assert "right" in document["refusal"]["reason"]


def test_refuses_when_receipts_are_empty(tmp_path: Path) -> None:
    left = _write_run(tmp_path / "left", receipts=_shared_receipts())
    right = _write_run(tmp_path / "right", receipts=[])
    document = compare_arms(left, right)

    assert document["evidence_status"] == "refused"
    assert document["refusal"]["code"] == "empty_receipts"


def test_invalid_receipt_json_is_an_input_error(tmp_path: Path) -> None:
    left = _write_run(tmp_path / "left", receipts=_shared_receipts())
    right = _write_run(tmp_path / "right", receipts=_shared_receipts())
    with (right / "receipts.jsonl").open("a", encoding="utf-8") as handle:
        handle.write("{not json\n")
    with pytest.raises(ArmEquivalenceInputError):
        compare_arms(left, right)


# ---------------------------------------------------------------------------
# 5. window / case-count / budget arithmetic
# ---------------------------------------------------------------------------


def test_window_reports_budgets_and_case_counts(tmp_path: Path) -> None:
    left = _write_run(tmp_path / "left", receipts=_shared_receipts(4),
                      run_id="arm-left", max_tests=4, duration_seconds=25.0)
    right = _write_run(tmp_path / "right", receipts=_shared_receipts(4),
                       run_id="arm-right", max_tests=4, duration_seconds=25.0)
    document = compare_arms(left, right)

    window = document["window"]
    assert window["definition"].startswith("the leading receipt cases")
    assert window["raw_identity_field"] == "raw_sha256"
    assert window["left"]["receipt_cases"] == 4
    assert window["right"]["receipt_cases"] == 4
    assert window["window_case_cap"] == document["read_scope"]["max_window_cases"]
    assert window["truncated_by_window_case_cap"] is False
    assert window["covers"] == {"left": True, "right": True}

    arms = document["arms"]
    assert arms["left"]["run_id"] == "arm-left"
    assert arms["right"]["run_id"] == "arm-right"
    assert arms["left"]["declared_tests"] == 4
    assert arms["left"]["receipt_status_counts"] == {"complete": 4}
    budgets = document["budgets"]
    assert budgets["same_declared_budget"] is True
    assert budgets["max_tests"] == {"left": 4, "right": 4, "equal": True}
    assert budgets["duration_seconds"]["equal"] is True


def test_case_count_mismatch_blocks_the_claim(tmp_path: Path) -> None:
    left = _write_run(tmp_path / "left", receipts=_shared_receipts(3))
    right = _write_run(tmp_path / "right", receipts=_shared_receipts(4))
    document = compare_arms(left, right)

    assert document["evidence_status"] == "compared"
    assert document["window"]["shared_prefix_cases"] == 3
    assert document["window"]["covers"] == {"left": True, "right": False}
    assert document["output_equivalence"]["claimed"] is False
    assert _condition(document, "same_receipt_case_count")["satisfied"] is False
    assert _condition(document, "window_covers_right_arm")["satisfied"] is False
    # the compared window itself is field-identical
    assert all(block["verdict"] == "equivalent" for block in document["families"])


def test_window_case_cap_blocks_the_claim(tmp_path: Path) -> None:
    left = _write_run(tmp_path / "left", receipts=_shared_receipts(4))
    right = _write_run(tmp_path / "right", receipts=_shared_receipts(4))
    document = compare_arms(left, right, max_window_cases=2)

    assert document["window"]["shared_prefix_cases"] == 2
    assert document["window"]["truncated_by_window_case_cap"] is True
    assert _field(document, "coverage", "coverage_hex")["equal"] == 2
    assert document["output_equivalence"]["claimed"] is False
    assert _condition(document, "window_not_truncated")["satisfied"] is False


# ---------------------------------------------------------------------------
# 6. bounded read, determinism, rendering
# ---------------------------------------------------------------------------


def test_never_reads_trace_artifacts(tmp_path: Path) -> None:
    left = _write_run(tmp_path / "left", receipts=_shared_receipts())
    right = _write_run(tmp_path / "right", receipts=_shared_receipts())
    document = compare_arms(left, right)

    read = document["read_scope"]
    assert read["full_trace_loaded"] is False
    assert read["streamed_receipts"] is True
    assert read["artifacts_read"]["left"] == [
        "receipts.jsonl", "report.json", "online_run_identity.json",
        "decoder_manifest.json"]
    assert read["artifacts_read"]["right"] == read["artifacts_read"]["left"]
    for names in read["artifacts_read"].values():
        assert "online_final_trace.json" not in names
        assert "online_events.jsonl" not in names
        assert "online_events.zlib" not in names


def test_document_is_byte_identical_across_two_runs(tmp_path: Path) -> None:
    left_receipts = _shared_receipts(4)
    right_receipts = _shared_receipts(4)
    right_receipts[3]["local_ticks"] = {"cpu": 32, "gpio_a": 40, "gpio_b": 32}
    left = _write_run(tmp_path / "left", receipts=left_receipts)
    right = _write_run(tmp_path / "right", receipts=right_receipts)
    first = json.dumps(compare_arms(left, right), sort_keys=True, indent=2,
                       ensure_ascii=False, allow_nan=False)
    second = json.dumps(compare_arms(left, right), sort_keys=True, indent=2,
                        ensure_ascii=False, allow_nan=False)
    assert first == second
    assert _family(json.loads(first), "local_ticks")["verdict"] == "not_equivalent"


def test_markdown_states_counts_claim_and_boundaries(tmp_path: Path) -> None:
    left_receipts = _shared_receipts(3)
    right_receipts = _shared_receipts(3)
    right_receipts[0]["coverage_hex"] = "ffffffff"
    left = _write_run(tmp_path / "left", receipts=left_receipts)
    right = _write_run(tmp_path / "right", receipts=right_receipts)
    text = render_markdown(compare_arms(left, right))

    assert "arm_equivalence.v1" in text
    assert "coverage" in text
    assert "not_equivalent" in text
    assert "output equivalence claimed" in text.lower()
    assert "does not claim" in text.lower()


def test_refusal_markdown_names_the_precise_reason(tmp_path: Path) -> None:
    left = _write_run(tmp_path / "left", receipts=_shared_receipts(2))
    right_receipts = _shared_receipts(2)
    right_receipts[0]["raw_sha256"] = "b" * 64
    right = _write_run(tmp_path / "right", receipts=right_receipts)
    document = compare_arms(left, right)
    assert document["refusal"]["code"] == "zero_shared_prefix"
    text = render_markdown(document)
    assert "zero_shared_prefix" in text
    assert "refused" in text.lower()


# ---------------------------------------------------------------------------
# 7. the CLI
# ---------------------------------------------------------------------------


def test_cli_writes_a_deterministic_document_and_exits_zero(
        tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    cli = _load_cli()
    left = _write_run(tmp_path / "left", receipts=_shared_receipts(3))
    right = _write_run(tmp_path / "right", receipts=_shared_receipts(3))
    out_one = tmp_path / "one.json"
    out_two = tmp_path / "two.json"
    markdown = tmp_path / "one.md"
    args = [str(left), str(right), "--json-out", str(out_one),
            "--markdown-out", str(markdown), "--quiet"]
    assert cli.main(args) == 0
    args[3] = str(out_two)
    assert cli.main(args) == 0
    assert out_one.read_bytes() == out_two.read_bytes()
    assert markdown.read_text(encoding="utf-8").strip()
    assert "arm_equivalence.v1" in out_one.read_text(encoding="utf-8")
    capsys.readouterr()


def test_cli_exit_codes_for_refusal_and_usage(tmp_path: Path,
                                             capsys: pytest.CaptureFixture) -> None:
    cli = _load_cli()
    left = _write_run(tmp_path / "left", receipts=_shared_receipts(2))
    right_receipts = _shared_receipts(2)
    right_receipts[0]["raw_sha256"] = "c" * 64
    right = _write_run(tmp_path / "right", receipts=right_receipts)
    assert cli.main([str(left), str(right), "--quiet"]) == cli.EXIT_REFUSED
    assert cli.main([str(left), "--quiet"]) == cli.EXIT_USAGE
    assert cli.main([str(left), str(tmp_path / "missing"), "--quiet"]) == \
        cli.EXIT_REFUSED
    capsys.readouterr()


# ---------------------------------------------------------------------------
# 8. a real saved pair, read-only
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not (REAL_INITIAL_RAM_OFF.is_dir()
                         and REAL_INITIAL_RAM_ON.is_dir()),
                    reason="saved initial-RAM arm pair is not present")
def test_real_saved_initial_ram_pair_is_compared_read_only() -> None:
    document = compare_arms(REAL_INITIAL_RAM_OFF, REAL_INITIAL_RAM_ON,
                            left_label="initial_ram_off",
                            right_label="initial_ram_on")

    assert document["evidence_status"] == "compared"
    assert document["window"]["shared_prefix_cases"] == 96
    assert document["window"]["covers"] == {"left": True, "right": True}
    assert document["arms"]["left"]["receipt_cases"] == 96
    assert document["arms"]["right"]["receipt_cases"] == 96
    assert document["verdict"]["families"]["status"] == "equivalent"
    assert document["verdict"]["families"]["coverage"] == "equivalent"
    assert document["verdict"]["families"]["applied_sources"] == "equivalent"
    assert document["verdict"]["families"]["direction"] == "equivalent"
    # the two input_invalid cases record no path and no genome on either arm
    assert document["verdict"]["families"]["effective_genome"] == "unknown"
    assert document["verdict"]["families"]["path"] == "unknown"
    assert _field(document, "path", "path_id")["missing_both"] == 2
    assert _field(document, "path", "path_id")["equal"] == 94
    assert document["output_equivalence"]["claimed"] is False
    assert document["read_scope"]["full_trace_loaded"] is False
    for names in document["read_scope"]["artifacts_read"].values():
        assert "online_final_trace.json" not in names
