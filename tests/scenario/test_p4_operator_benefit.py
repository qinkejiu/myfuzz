"""Tests for the read-only P4 operator benefit comparison.

The fixtures are *synthetic but real-shaped*: every artifact consumed by the
module (``receipts.jsonl``, ``report.json``, ``online_run_identity.json``,
``targets.json``, ``online_final_trace.json``) is written with the fields the
saved Ibex + dual-PULP runs actually carry, so the comparison is exercised on
the same contract the real run directories expose.  Nothing here starts RTL,
Verilator, cargo or the RFuzz client.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from myfuzz.scenario.p4_operator_benefit import (
    SCHEMA_VERSION,
    P4OperatorBenefitEvidenceError,
    compare_arm_pair,
    compare_pairs,
    render_markdown,
    roll_up_edge_directions,
)


# ---------------------------------------------------------------------------
# real-shaped synthetic runs
# ---------------------------------------------------------------------------

TARGETS = [
    {"component": "gpio_a", "mask": 1, "port": "gpio_out",
     "target_id": "gpio_a_output_bit0", "value": 1},
    {"component": "gpio_b", "mask": 1, "port": "irq",
     "target_id": "gpio_b_irq", "value": 1},
    {"component": "cpu", "mask": 4294967295, "port": "instr_addr",
     "target_id": "cpu_external_irq_vector_fetch", "value": 65836},
    {"component": "cpu", "mask": 1, "port": "data_write",
     "target_id": "cpu_data_write", "value": 1},
]


def _receipt(*, case_index: int, raw: str, coverage: str, status: str = "complete",
             path_id: str = "path-a", genome: str = "genome-a",
             applied_sources=("gpio_b.external_pin8",), total_seconds: float = 0.25,
             direction: str = "IP_TO_CPU_TO_IP") -> dict:
    """One receipt with the shape the online path persists."""
    return {
        "run_id": "synthetic",
        "buffer_id": 0,
        "slot": case_index,
        "case_id": f"online-{case_index}-{raw[:8]}",
        "case_index": case_index,
        "status": status,
        "raw_sha256": raw,
        "online_raw_records_hex": [raw],
        "effective_genome_sha256": genome,
        "path_id": path_id,
        "direction": direction,
        "applied_sources": list(applied_sources),
        "operator_id": "external_event",
        "coverage_hex": coverage,
        "violations": [],
        "local_ticks": {"cpu": 32, "gpio_a": 32, "gpio_b": 32},
        "online_phase_timing_seconds": {"total": total_seconds},
    }


def _write_run(directory: Path, *, receipts: list[dict], effective_seconds: float,
               tests: int, statuses: dict, operator_state: dict | None = None,
               trace_events: list[dict] | None = None, targets: bool = True,
               identity: bool = True, run_id: str = "synthetic") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / "receipts.jsonl").open("w", encoding="utf-8") as handle:
        for row in receipts:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    report = {
        "tests": tests,
        "statuses": dict(statuses),
        "effective_search_seconds": effective_seconds,
        "elapsed_seconds": effective_seconds + 0.1,
        "execution_status": "complete",
        "session_status": "complete",
        "client_returncode": 0,
        "global_mutation_seed": 20261007,
    }
    if operator_state:
        report.update(operator_state)
    (directory / "report.json").write_text(
        json.dumps(report, sort_keys=True), encoding="utf-8")
    if targets:
        (directory / "targets.json").write_text(
            json.dumps(TARGETS, sort_keys=True), encoding="utf-8")
    if identity:
        (directory / "online_run_identity.json").write_text(
            json.dumps({"schema_version": "scenario_online_run_identity.v1",
                        "sha256": "0" * 64,
                        "identity": {"run_config": {
                            "run_id": run_id, "search_seed": 20261007,
                            "max_tests": tests, "duration_seconds": 150.0,
                            "feedback_interval": 16}}},
                       sort_keys=True), encoding="utf-8")
    if trace_events is not None:
        (directory / "online_final_trace.json").write_text(
            json.dumps({"events": trace_events, "status": "complete",
                        "local_ticks": {"cpu": 64, "gpio_a": 64, "gpio_b": 64}},
                       sort_keys=True), encoding="utf-8")
    return directory


class _WitnessProducer:
    """Minimal real-shaped ``runtime_chain_certificate.v1`` producer.

    Every ``chain_witness`` event certifies one same-case chain; every
    ``chain_gap`` event emits one incomplete certificate missing ``consumer``.
    The producer is a *factory* (a class) exactly like the shipped one, so each
    ``analyze_run`` call gets a fresh instance and the per-arm counts follow the
    arm's own trace.
    """

    def __init__(self, *, max_pending: int = 128, max_event_gap: int = 4096,
                 require_native_receipts: bool = True) -> None:
        self.pending_count = 0
        self.kwargs = {"max_pending": max_pending, "max_event_gap": max_event_gap,
                       "require_native_receipts": require_native_receipts}

    def ingest(self, events) -> tuple:
        produced = []
        for event in events:
            kind = event.get("kind")
            event_id = event.get("event_id")
            if kind == "chain_witness":
                produced.append({
                    "schema_version": "runtime_chain_certificate.v1",
                    "certificate_id": f"stub:certified:{event_id}",
                    "status": "certified",
                    "direction": ("IP_TO_CPU_TO_IP" if event_id % 2 == 0
                                  else "CPU_TO_IP_TO_CPU"),
                    "hops": ["producer", "delivery", "consumer"],
                    "source_case_index": 0, "endpoint_case_index": 0,
                    "source_admission_id": f"adm:witness:{event_id}"})
            elif kind == "chain_gap":
                produced.append({
                    "schema_version": "runtime_chain_certificate.v1",
                    "certificate_id": f"stub:incomplete:{event_id}",
                    "status": "incomplete",
                    "direction": "IP_TO_CPU_TO_IP",
                    "missing_hops": ["consumer"],
                    "source_admission_id": f"adm:gap:{event_id}"})
        return tuple(produced)

    def flush(self) -> tuple:
        return ()


def _edge_candidate(graph: str, path_id: str, rule: int, relation: str,
                    scope: str) -> dict:
    return {"graph_sha256": graph, "path_ids": [path_id], "relation": relation,
            "rule_index": rule, "scope": scope}


def _provenance(event_id: int, candidates: list[dict]) -> dict:
    return {"schema_version": "event_source_provenance.v1",
            "edge_candidates": candidates, "observed_case": None,
            "origin_admission_ids": [], "origin_status": "unknown",
            "proof_scope": "transport_candidates_only", "resource": None,
            "invalid_origin_references": 0, "unknown_writer_ids": []}


_EDGE_A = _edge_candidate("graph-1", "path-a", 0, "direct_binding", "binding")
_EDGE_B = _edge_candidate("graph-2", "path-b", 1, "mmio_route", "route_window")

TRACE_OFF = [
    {"event_id": 1, "kind": "initial_image"},
    {"event_id": 2, "kind": "chain_witness", "provenance": _provenance(2, [_EDGE_A])},
    {"event_id": 3, "kind": "chain_witness", "provenance": _provenance(3, [_EDGE_A])},
    {"event_id": 4, "kind": "chain_gap", "provenance": _provenance(4, [_EDGE_B])},
]

TRACE_ON = [
    {"event_id": 1, "kind": "initial_image"},
    {"event_id": 2, "kind": "chain_witness", "provenance": _provenance(2, [_EDGE_A])},
    {"event_id": 3, "kind": "chain_witness", "provenance": _provenance(3, [_EDGE_A])},
    {"event_id": 5, "kind": "chain_witness", "provenance": _provenance(5, [_EDGE_B])},
]


def _off_arm(tmp_path: Path) -> Path:
    receipts = [
        _receipt(case_index=0, raw="r0", coverage="01000000"),
        _receipt(case_index=1, raw="r1", coverage="00010000"),
        _receipt(case_index=2, raw="r2", coverage="00000100"),
        _receipt(case_index=3, raw="r3", coverage="00000000"),
    ]
    return _write_run(tmp_path / "off", receipts=receipts, effective_seconds=4.0,
                      tests=4, statuses={"complete": 4},
                      operator_state={"path_switch": {
                          "schema_version": "online_path_switch_state.v1",
                          "enabled": False, "attempts": 0, "granted": 0,
                          "changed": 0}},
                      trace_events=TRACE_OFF, run_id="synthetic-off")


def _on_arm(tmp_path: Path) -> Path:
    receipts = [
        _receipt(case_index=0, raw="r0", coverage="01010101"),
        _receipt(case_index=1, raw="r1", coverage="00000000"),
        _receipt(case_index=2, raw="rX", coverage="00000000",
                 status="input_invalid"),
        _receipt(case_index=3, raw="r3", coverage="00000000"),
    ]
    return _write_run(tmp_path / "on", receipts=receipts, effective_seconds=5.0,
                      tests=4, statuses={"complete": 3, "input_invalid": 1},
                      operator_state={"path_switch": {
                          "schema_version": "online_path_switch_state.v1",
                          "enabled": True, "attempts": 4, "granted": 4,
                          "changed": 2}},
                      trace_events=TRACE_ON, run_id="synthetic-on")


def _compare(tmp_path: Path, **kwargs) -> dict:
    off = _off_arm(tmp_path)
    on = _on_arm(tmp_path)
    return compare_arm_pair(off, on, operator_label="path_switch",
                            chain_producer=_WitnessProducer, **kwargs)


# ---------------------------------------------------------------------------
# per-metric extraction
# ---------------------------------------------------------------------------


def test_pair_document_extracts_every_metric_family(tmp_path):
    document = _compare(tmp_path)

    assert document["schema_version"] == SCHEMA_VERSION
    assert document["evidence_status"] == "measurable"
    assert [pair["pair_id"] for pair in document["pairs"]] == [
        "synthetic-off__vs__synthetic-on"]
    pair = document["pairs"][0]

    # -- operator state evidence: the ON arm really switched the operator on --
    assert pair["operator"]["label"] == "path_switch"
    assert pair["operator"]["arms"]["off"]["state"]["path_switch"]["enabled"] is False
    assert pair["operator"]["arms"]["on"]["state"]["path_switch"]["enabled"] is True
    assert pair["operator"]["arms"]["on"]["state"]["path_switch"]["changed"] == 2
    assert pair["operator"]["enabled_by_key"]["path_switch"] == {
        "off": False, "on": True}

    # -- same-budget evidence -------------------------------------------------
    budget = pair["same_budget"]
    assert budget["arms"]["off"]["cases"] == 4
    assert budget["arms"]["on"]["cases"] == 4
    assert budget["arms"]["off"]["effective_search_seconds"] == 4.0
    assert budget["arms"]["on"]["effective_search_seconds"] == 5.0
    assert budget["arms"]["off"]["tests"] == {"reported": 4, "receipts": 4}
    assert budget["arms"]["on"]["statuses"]["receipts"] == {
        "complete": 3, "input_invalid": 1}
    assert budget["case_count_equal"] is True
    assert budget["declared_budget_equal"] is True
    assert budget["shared_raw_input_prefix"]["length"] == 2
    assert budget["shared_raw_input_prefix"]["first_divergent_case_index"] == 2
    assert budget["shared_raw_input_prefix"]["per_case_pairing_scope"] == \
        "shared_prefix_only"

    # -- coverage: counter layout stated, not assumed -------------------------
    coverage = pair["coverage"]
    layout = coverage["layout"]
    assert layout["hex_characters_per_case"] == {"values": [8], "consistent": True}
    assert layout["counter_bytes_per_case"] == 4
    assert layout["declared_target_count"] == 4
    assert layout["counter_order_confirmed"] is True
    assert "byte" in layout["counter_order_rule"]
    off_hits = coverage["arms"]["off"]["per_target_hit_counts"]
    assert [entry["hit_cases"] for entry in off_hits] == [1, 1, 1, 0]
    assert [entry["target_id"] for entry in off_hits] == [
        "gpio_a_output_bit0", "gpio_b_irq", "cpu_external_irq_vector_fetch",
        "cpu_data_write"]
    assert coverage["arms"]["off"]["targets_hit_at_least_once"] == 3
    assert coverage["arms"]["on"]["targets_hit_at_least_once"] == 4
    # new_target_bits_per_second is the shipped rule: first_seen_target_bits /
    # effective_search_seconds.
    assert coverage["arms"]["off"]["first_seen_target_bits"] == 3
    assert coverage["arms"]["off"]["new_target_bits_per_second"] == pytest.approx(
        3 / 4.0)
    assert coverage["arms"]["on"]["new_target_bits_per_second"] == pytest.approx(
        4 / 5.0)
    assert coverage["arms"]["off"]["new_target_bits_per_second_source"] == (
        "acceptance_metrics.analyze_run:local_target_novelty")

    # -- chains: shipped certificate producer, per arm ------------------------
    chains = pair["chains"]
    assert chains["arms"]["off"]["certified_total"] == 2
    assert chains["arms"]["off"]["incomplete_total"] == 1
    assert chains["arms"]["off"]["by_direction"] == {
        "IP_TO_CPU_TO_IP": 1, "CPU_TO_IP_TO_CPU": 1}
    assert chains["arms"]["off"]["certified_per_second"] == pytest.approx(2 / 4.0)
    assert chains["arms"]["on"]["certified_total"] == 3
    assert chains["arms"]["on"]["incomplete_total"] == 0
    assert chains["arms"]["on"]["by_direction"] == {
        "IP_TO_CPU_TO_IP": 1, "CPU_TO_IP_TO_CPU": 2}
    assert chains["arms"]["on"]["certified_per_second"] == pytest.approx(3 / 5.0)
    assert chains["arms"]["on"]["first_missing_hop_counts"] == {}

    # -- witnessed edges: global novelty + per-direction provenance -----------
    edges = pair["witnessed_edges"]
    assert edges["arms"]["off"]["unique_edges"] == 2
    assert edges["arms"]["on"]["unique_edges"] == 2
    assert edges["arms"]["off"]["new_edges_per_second"] == pytest.approx(2 / 4.0)
    # No session manifest in the synthetic pair -> per-direction provenance is
    # null with a precise reason, never a fabricated zero.
    assert edges["arms"]["off"]["by_direction"] is None
    assert "online_session_manifest.json" in edges["arms"]["off"]["by_direction_reason"]

    # -- explicit non-comparability statements --------------------------------
    boundaries = pair["not_comparable"]
    assert any("raw" in item for item in boundaries)
    assert any("case" in item for item in boundaries)
    assert any("causal" in item for item in boundaries)


def test_full_prefix_enables_per_case_comparison(tmp_path):
    receipts_off = [_receipt(case_index=i, raw=f"r{i}",
                             coverage="01000000") for i in range(3)]
    receipts_on = [_receipt(case_index=i, raw=f"r{i}",
                            coverage="01000000" if i else "00000000")
                   for i in range(3)]
    off = _write_run(tmp_path / "off", receipts=receipts_off,
                     effective_seconds=3.0, tests=3, statuses={"complete": 3},
                     trace_events=TRACE_OFF)
    on = _write_run(tmp_path / "on", receipts=receipts_on,
                    effective_seconds=3.0, tests=3, statuses={"complete": 3},
                    trace_events=TRACE_ON)
    pair = compare_arm_pair(off, on, operator_label="x",
                            chain_producer=_WitnessProducer)["pairs"][0]
    prefix = pair["same_budget"]["shared_raw_input_prefix"]
    assert prefix["length"] == 3
    assert prefix["per_case_pairing_scope"] == "full"
    paired = pair["coverage"]["paired_within_prefix"]
    assert paired["cases_compared"] == 3
    assert paired["fields"]["coverage_hex"]["different"] == 1
    assert paired["fields"]["coverage_hex"]["different_case_indexes"] == [0]
    assert paired["fields"]["status"]["different"] == 0


def test_shared_prefix_stops_at_first_divergence(tmp_path):
    receipts_off = [_receipt(case_index=i, raw=f"r{i}",
                             coverage="01000000") for i in range(4)]
    receipts_on = [_receipt(case_index=i, raw=f"r{i}",
                            coverage="01000000") for i in range(2)] + [
        _receipt(case_index=i, raw=f"x{i}", coverage="01000000") for i in (2, 3)]
    off = _write_run(tmp_path / "off", receipts=receipts_off,
                     effective_seconds=4.0, tests=4, statuses={"complete": 4})
    on = _write_run(tmp_path / "on", receipts=receipts_on,
                    effective_seconds=4.0, tests=4, statuses={"complete": 4})
    pair = compare_arm_pair(off, on, operator_label="x")["pairs"][0]
    prefix = pair["same_budget"]["shared_raw_input_prefix"]
    assert prefix["length"] == 2
    assert prefix["off_cases"] == 4
    assert prefix["on_cases"] == 4
    assert prefix["first_divergent_case_index"] == 2
    assert prefix["capped_by_shorter_arm"] is False
    assert prefix["raw_identity_field"] == "raw_sha256"


def test_under_declared_cast_uses_shared_prefix(tmp_path):
    receipts_off = [_receipt(case_index=i, raw=f"r{i}",
                             coverage="01000000") for i in range(4)]
    receipts_on = [_receipt(case_index=i, raw=f"r{i}",
                            coverage="01000000") for i in range(2)]
    off = _write_run(tmp_path / "off", receipts=receipts_off,
                     effective_seconds=4.0, tests=4, statuses={"complete": 4})
    on = _write_run(tmp_path / "on", receipts=receipts_on,
                    effective_seconds=4.0, tests=2, statuses={"complete": 2})
    pair = compare_arm_pair(off, on, operator_label="x")["pairs"][0]
    prefix = pair["same_budget"]["shared_raw_input_prefix"]
    assert prefix["length"] == 2
    assert prefix["capped_by_shorter_arm"] is True
    assert pair["same_budget"]["case_count_equal"] is False


# ---------------------------------------------------------------------------
# per-direction witness rollup (pure join over the shipped analysis)
# ---------------------------------------------------------------------------


def test_direction_rollup_counts_only_declared_runtime_edges():
    provenance_report = {
        "schema_version": "runtime_edge_provenance_report.v1",
        "counts": {"total": 3, "certified": 2, "incomplete": 1, "unknown": 0,
                   "rejected": 0, "evicted": 0},
        "edges": [
            {"rule_index": 0, "prerequisite_index": 0, "status": "certified",
             "reason": None},
            {"rule_index": 1, "prerequisite_index": 0, "status": "certified",
             "reason": None},
            {"rule_index": 8, "prerequisite_index": 0, "status": "incomplete",
             "reason": "missing_required_hop"},
        ],
    }
    selections = [
        {"direction": "IP_TO_CPU_TO_IP", "path_id": "path-a", "target": "t-a",
         "edges": [{"rule_index": 0, "prerequisite_index": 0},
                   {"rule_index": 1, "prerequisite_index": 0}]},
        {"direction": "CPU_TO_IP_TO_CPU", "path_id": "path-b", "target": "t-b",
         "edges": [{"rule_index": 8, "prerequisite_index": 0},
                   {"rule_index": 9, "prerequisite_index": 0}]},
    ]
    rolled = roll_up_edge_directions(provenance_report, selections)
    assert rolled["IP_TO_CPU_TO_IP"]["declared_edge_count"] == 2
    assert rolled["IP_TO_CPU_TO_IP"]["runtime_edge_count"] == 2
    assert rolled["IP_TO_CPU_TO_IP"]["counts"] == {
        "certified": 2, "incomplete": 0, "unknown": 0}
    assert rolled["CPU_TO_IP_TO_CPU"]["declared_edge_count"] == 2
    assert rolled["CPU_TO_IP_TO_CPU"]["runtime_edge_count"] == 1
    assert rolled["CPU_TO_IP_TO_CPU"]["non_runtime_edge_count"] == 1
    assert rolled["CPU_TO_IP_TO_CPU"]["counts"] == {
        "certified": 0, "incomplete": 1, "unknown": 0}
    assert rolled["CPU_TO_IP_TO_CPU"]["path_id"] == "path-b"


# ---------------------------------------------------------------------------
# null + reason, never a fabricated zero
# ---------------------------------------------------------------------------


def test_missing_trace_yields_null_and_reason_not_zero(tmp_path):
    receipts_off = [_receipt(case_index=0, raw="r0", coverage="01000000")]
    receipts_on = [_receipt(case_index=0, raw="r0", coverage="01000000")]
    off = _write_run(tmp_path / "off", receipts=receipts_off,
                     effective_seconds=1.0, tests=1, statuses={"complete": 1})
    on = _write_run(tmp_path / "on", receipts=receipts_on,
                    effective_seconds=1.0, tests=1, statuses={"complete": 1})
    document = compare_arm_pair(off, on, operator_label="x",
                                required_families=("search_budget", "coverage",
                                                   "chains", "witnessed_edges"))
    pair = document["pairs"][0]
    chains = pair["chains"]["arms"]["off"]
    assert chains["certified_total"] is None
    assert chains["incomplete_total"] is None
    assert chains["certified_per_second"] is None
    assert chains["reason"]
    assert "trace" in chains["reason"].lower()
    edges = pair["witnessed_edges"]["arms"]["off"]
    assert edges["unique_edges"] is None
    assert edges["by_direction"] is None
    assert edges["reason"]
    # Coverage and the search window are still measurable from receipts/report.
    assert pair["coverage"]["arms"]["off"]["targets_hit_at_least_once"] == 1
    assert pair["same_budget"]["arms"]["off"]["effective_search_seconds"] == 1.0
    # ... and the document says which required metrics it cannot support.
    refused = {(item["metric_family"], item["arm"]) for item in document["refusals"]}
    assert ("chains", "off") in refused
    assert ("chains", "on") in refused
    assert ("witnessed_edges", "off") in refused
    assert document["evidence_status"] == "refused"
    for item in document["refusals"]:
        assert item["reason"], item


def test_inconsistent_coverage_width_is_null_with_reason(tmp_path):
    receipts_off = [_receipt(case_index=0, raw="r0", coverage="01000000")]
    receipts_on = [_receipt(case_index=0, raw="r0", coverage="0100")]
    off = _write_run(tmp_path / "off", receipts=receipts_off,
                     effective_seconds=1.0, tests=1, statuses={"complete": 1})
    on = _write_run(tmp_path / "on", receipts=receipts_on,
                    effective_seconds=1.0, tests=1, statuses={"complete": 1})
    pair = compare_arm_pair(off, on, operator_label="x")["pairs"][0]
    layout = pair["coverage"]["layout"]
    assert layout["counter_order_confirmed"] is False
    assert layout["reason"]
    on_coverage = pair["coverage"]["arms"]["on"]
    assert on_coverage["per_target_hit_counts"] is None
    assert on_coverage["targets_hit_at_least_once"] is None


def test_pair_without_targets_document_still_counts_counter_slots(tmp_path):
    receipts_off = [_receipt(case_index=0, raw="r0", coverage="01000000")]
    receipts_on = [_receipt(case_index=0, raw="r0", coverage="00000000")]
    off = _write_run(tmp_path / "off", receipts=receipts_off,
                     effective_seconds=1.0, tests=1, statuses={"complete": 1},
                     targets=False)
    on = _write_run(tmp_path / "on", receipts=receipts_on,
                    effective_seconds=1.0, tests=1, statuses={"complete": 1},
                    targets=False)
    pair = compare_arm_pair(off, on, operator_label="x")["pairs"][0]
    layout = pair["coverage"]["layout"]
    assert layout["counter_order_confirmed"] is False
    assert "targets.json" in (layout["reason"] or "")
    hits = pair["coverage"]["arms"]["off"]["per_target_hit_counts"]
    assert [entry["counter_index"] for entry in hits] == [0, 1, 2, 3]
    assert [entry["hit_cases"] for entry in hits] == [1, 0, 0, 0]
    assert all(entry["target_id"] is None for entry in hits)


# ---------------------------------------------------------------------------
# fail-closed refusal
# ---------------------------------------------------------------------------


def test_missing_core_artifact_refuses_with_precise_reason(tmp_path):
    off = _write_run(tmp_path / "off",
                     receipts=[_receipt(case_index=0, raw="r0",
                                        coverage="01000000")],
                     effective_seconds=1.0, tests=1, statuses={"complete": 1})
    on = tmp_path / "on"
    on.mkdir()
    (on / "report.json").write_text("{}", encoding="utf-8")
    with pytest.raises(P4OperatorBenefitEvidenceError) as excinfo:
        compare_arm_pair(off, on, operator_label="x")
    message = str(excinfo.value)
    assert "on" in message
    assert "receipts.jsonl" in message


def test_cli_exits_nonzero_with_precise_reason(tmp_path, capsys):
    from scripts.compare_p4_operator_benefit import (
        EXIT_REFUSED, EXIT_ERROR, main as cli_main)

    # required metric family unmeasurable -> refusal exit with the reason
    receipts = [_receipt(case_index=0, raw="r0", coverage="01000000")]
    off = _write_run(tmp_path / "off", receipts=receipts, effective_seconds=1.0,
                     tests=1, statuses={"complete": 1})
    on = _write_run(tmp_path / "on", receipts=receipts, effective_seconds=1.0,
                    tests=1, statuses={"complete": 1})
    out = tmp_path / "document.json"
    code = cli_main(["--pair", str(off), str(on), "--operator-label", "x",
                     "--require", "chains", "--json-out", str(out), "--quiet"])
    captured = capsys.readouterr()
    assert code == EXIT_REFUSED
    assert "chains" in captured.err
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["evidence_status"] == "refused"
    assert document["pairs"][0]["chains"]["arms"]["off"]["certified_total"] is None

    # core artifact missing entirely -> the comparison itself is refused
    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "report.json").write_text("{}", encoding="utf-8")
    code = cli_main(["--pair", str(off), str(broken), "--operator-label", "x",
                     "--json-out", str(tmp_path / "broken.json"), "--quiet"])
    captured = capsys.readouterr()
    assert code == EXIT_ERROR
    assert "receipts.jsonl" in captured.err


# ---------------------------------------------------------------------------
# determinism
# ---------------------------------------------------------------------------


def test_json_document_is_byte_identical_across_two_runs(tmp_path):
    first = _compare(tmp_path)
    second = _compare(tmp_path)
    encoded_first = json.dumps(first, sort_keys=True, indent=2,
                               ensure_ascii=False).encode("utf-8")
    encoded_second = json.dumps(second, sort_keys=True, indent=2,
                                ensure_ascii=False).encode("utf-8")
    assert encoded_first == encoded_second
    assert render_markdown(first) == render_markdown(second)


def test_markdown_reports_boundaries_and_refusals(tmp_path):
    document = _compare(tmp_path)
    markdown = render_markdown(document)
    assert "not comparable" in markdown.lower()
    assert "shared raw-input prefix" in markdown
    assert "new_target_bits_per_second" in markdown
    assert "certified" in markdown
    assert "p4_operator_benefit.v1" in markdown


def test_compare_pairs_carries_several_pairs_in_one_document(tmp_path):
    off = _off_arm(tmp_path / "a")
    on = _on_arm(tmp_path / "a")
    off_b = _write_run(tmp_path / "b" / "off",
                       receipts=[_receipt(case_index=0, raw="q0",
                                          coverage="01000000")],
                       effective_seconds=1.0, tests=1, statuses={"complete": 1})
    on_b = _write_run(tmp_path / "b" / "on",
                      receipts=[_receipt(case_index=0, raw="q0",
                                         coverage="01000000")],
                      effective_seconds=1.0, tests=1, statuses={"complete": 1})
    document = compare_pairs([(off, on), (off_b, on_b)],
                             chain_producer=_WitnessProducer)
    assert len(document["pairs"]) == 2
    assert document["pairs"][0]["pair_id"] != document["pairs"][1]["pair_id"]
    assert "pairs[0]" in render_markdown(document)
