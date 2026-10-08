"""P2 acceptance report: every plan criterion against one saved run artifact.

The fixture is a purely synthetic run directory (no RTL, no process): a real
versioned path declaration compiled by the P2 gate machinery, plus a hand-built
event journal whose every hop identity is hand-computed here.  Each assertion
therefore checks a value this test derives by hand, never a value the module
under test produced.

Negative cases are explicit: a removed consumer hop must stay ``incomplete``
(never ``certified``); a missing trace or manifest must stay ``null`` with a
reason; an early IRQ that is *not* observed must stay ``null`` instead of being
reported as a pass; a requested replay comparison that cannot be performed must
leave the gate unready.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

from myfuzz.scenario.p2_acceptance import (
    SCHEMA_VERSION,
    p2_acceptance_report,
    render_markdown,
)
from myfuzz.scenario.p2_negative_gates import (
    compile_declared_paths,
    trusted_path_declaration,
)
from myfuzz.scenario.runtime_path_contract import (
    PreparedRuntimePathContract,
)

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "scripts" / "run_p2_acceptance_gate.py"

CPU = "CPU_TO_IP_TO_CPU"
IP = "IP_TO_CPU_TO_IP"
CPU_EDGES = ((0, 0), (2, 0), (4, 0), (5, 0), (6, 0))
IP_EDGES = ((10, 0), (11, 0), (12, 0), (13, 0))

GPIO_A_DEVICE = "gpio_a"
GPIO_B_DEVICE = "gpio_b"

BOOTSTRAP = 1

_DECLARATION_CACHE: dict = {}


# --------------------------------------------------------------------- fixture


def _declaration():
    if not _DECLARATION_CACHE:
        declaration = trusted_path_declaration("genome")
        compiled = compile_declared_paths(declaration).document()
        _DECLARATION_CACHE["declaration"] = declaration
        _DECLARATION_CACHE["compiled"] = compiled
    return _DECLARATION_CACHE["declaration"], _DECLARATION_CACHE["compiled"]


def _manifest(runtime_paths: dict) -> dict:
    return {"schema_version": "online_session_manifest.v1",
            "runtime_paths": runtime_paths}


def _runtime_paths(compiled: dict | None = None,
                   declaration=None) -> dict:
    declaration, compiled_document = _declaration()
    if declaration is None:
        declaration, _ = _declaration()
    document = dict(compiled if compiled is not None else compiled_document)
    document["declaration"] = (
        compiled["declaration"] if compiled is not None
        else declaration.prepared.document())
    return document


class _Journal:
    """Ordered synthetic journal; ``@name`` references resolve to event ids."""

    def __init__(self) -> None:
        self._rows: list[list] = []

    def add(self, name: str, event: dict) -> "_Journal":
        self._rows.append([name, dict(event)])
        return self

    def ref(self, name: str) -> str:
        return "@" + name

    def drop(self, name: str) -> "_Journal":
        self._rows = [row for row in self._rows if row[0] != name]
        return self

    def build(self) -> list[dict]:
        ids = {row[0]: index + 1 for index, row in enumerate(self._rows)}
        return [_resolve({**row[1], "event_id": index + 1}, ids)
                for index, row in enumerate(self._rows)]


def _resolve(value, ids):
    if isinstance(value, str) and value.startswith("@"):
        return ids[value[1:]]
    if isinstance(value, dict):
        return {key: _resolve(item, ids) for key, item in value.items()}
    if isinstance(value, list):
        return [_resolve(item, ids) for item in value]
    return value


def _provenance(*keys, case_index: int = 1) -> dict:
    return {"schema_version": "event_source_provenance.v1",
            "observed_case": {"case_id": f"case-{case_index}",
                              "case_index": case_index},
            "origin_status": "unknown", "origin_admission_ids": [],
            "invalid_origin_references": 0, "unknown_writer_ids": [],
            "edge_candidates": [{"rule_index": key[0],
                                 "prerequisite_index": key[1]} for key in keys],
            "resource": None, "proof_scope": "observation_only"}


def _transaction(sequence: int) -> dict:
    return {"channel_id": "data", "execution_id": "local-execution",
            "source_component": "cpu", "source_epoch": 0,
            "source_sequence": sequence, "testcase_id": "synthetic"}


def _aperture(device: str) -> int:
    """The versioned declaration's own MMIO base for one device."""
    declaration, _ = _declaration()
    return next(edge.base for edge in declaration.contract.edges
                if edge.device_id == device)


def _mmio_pair(journal: _Journal, *, device: str, base: int, sequence: int,
               keys: tuple) -> None:
    address = base + 8
    journal.add(f"{device}_mmio_acceptance", {
        "kind": "mmio_acceptance", "component": "cpu", "device_id": device,
        "address": address, "offset": 8, "beat_bytes": 4, "byte_enable": 15,
        "write": True, "write_value": 0x5A, "acceptance_order": sequence,
        "source_sequence": sequence, "source_transaction": _transaction(sequence),
        "producer_event_id": BOOTSTRAP, "provenance": _provenance(*keys)})
    journal.add(f"{device}_mmio_delivery", {
        "kind": "mmio_delivery", "component": "cpu", "device_id": device,
        "address": address, "offset": 8, "beat_bytes": 4, "byte_enable": 15,
        "write": True, "write_value": 0x5A, "delivery_order": sequence,
        "target_delivery_order": sequence, "read_value": None,
        "source_sequence": sequence, "source_transaction": _transaction(sequence),
        "producer_event_id": BOOTSTRAP, "provenance": _provenance(*keys)})


def _journal(*, consumer: bool = True, early_irq: bool = True,
             accepted_irq: bool = True) -> _Journal:
    journal = _Journal()
    journal.add("tick_cpu", {
        "kind": "local_tick_sample", "component": "cpu", "local_tick": 1,
        "phase": "post", "producer_event_id": BOOTSTRAP,
        "outputs": {"mmio": 0, "data_write": 0}, "provenance": _provenance()})
    journal.add("tick_gpio_a", {
        "kind": "local_tick_sample", "component": "gpio_a", "local_tick": 2,
        "phase": "post", "producer_event_id": BOOTSTRAP,
        "outputs": {"gpio_out": 0x5A}, "provenance": _provenance((2, 0))})
    journal.add("bind_a_b_delivery", {
        "kind": "dataflow_delivery",
        "producer_event_id": journal.ref("tick_gpio_a"),
        "source": ["gpio_a", "gpio_out"], "source_bit_offset": 0,
        "target": ["gpio_b", "gpio_in"], "target_bit_offset": 0, "width": 8,
        "value": 0x5A, "target_value": 0x5A, "provenance": _provenance((2, 0))})
    if consumer:
        journal.add("bind_a_b_consumer", {
            "kind": "dataflow_consumption",
            "producer_event_id": BOOTSTRAP,
            "source": ["gpio_a", "gpio_out"], "source_bit_offset": 0,
            "target": ["gpio_b", "gpio_in"], "target_bit_offset": 0, "width": 8,
            "value": 0x5A, "source_event_id": journal.ref("bind_a_b_delivery"),
            "provenance": _provenance((2, 0))})
    journal.add("tick_gpio_b_irq", {
        "kind": "local_tick_sample", "component": "gpio_b", "local_tick": 3,
        "phase": "post", "producer_event_id": BOOTSTRAP,
        "outputs": {"irq": 1}, "provenance": _provenance((4, 0), (10, 0))})
    journal.add("irq_delivery", {
        "kind": "dataflow_delivery",
        "producer_event_id": journal.ref("tick_gpio_b_irq"),
        "source": ["gpio_b", "irq"], "source_bit_offset": 0,
        "target": ["cpu", "irq"], "target_bit_offset": 0, "width": 1,
        "value": 1, "target_value": 1,
        "provenance": _provenance((4, 0), (10, 0))})
    journal.add("irq_consumer", {
        "kind": "cpu_irq_input", "cpu_step_event_id": BOOTSTRAP, "cpu_tick": 3,
        "source": ["gpio_b", "irq"], "source_bit_offset": 0,
        "target": ["cpu", "irq"], "target_bit_offset": 0, "width": 1,
        "value": 1, "source_event_id": journal.ref("irq_delivery"),
        "provenance": _provenance((4, 0), (10, 0))})
    _mmio_pair(journal, device=GPIO_A_DEVICE, base=_aperture(GPIO_A_DEVICE),
               sequence=1, keys=((0, 0), (13, 0)))
    _mmio_pair(journal, device=GPIO_B_DEVICE, base=_aperture(GPIO_B_DEVICE),
               sequence=2, keys=((5, 0), (6, 0), (11, 0), (12, 0)))
    if accepted_irq:
        journal.add("irq_trigger_accepted", {
            "kind": "gpio_irq_trigger", "component": "gpio_b", "phase": "post",
            "status": "observed", "mask": 256, "reset_epoch": 0,
            "local_tick": 3, "observation_event_id": BOOTSTRAP,
            "trigger_id": "gpio_b:0:trigger:1"})
        journal.add("cpu_taken_accepted", {
            "kind": "cpu_irq_taken", "cpu_step_event_id": BOOTSTRAP,
            "cpu_tick": 4, "source": ["gpio_b", "irq"], "source_bit_offset": 0,
            "target": ["cpu", "irq"], "target_bit_offset": 0, "width": 1,
            "source_event_id": 1,
            "source_trigger": {
                "trigger_id": "gpio_b:0:trigger:1",
                "trigger_event_id": journal.ref("irq_trigger_accepted"),
                "observation_event_id": BOOTSTRAP, "sample_event_id": BOOTSTRAP}})
    if early_irq:
        journal.add("irq_trigger_early", {
            "kind": "gpio_irq_trigger", "component": "gpio_b", "phase": "post",
            "status": "observed", "mask": 1, "reset_epoch": 0, "local_tick": 5,
            "observation_event_id": BOOTSTRAP,
            "trigger_id": "gpio_b:0:trigger:2"})
        journal.add("irq_observation_early", {
            "kind": "gpio_irq_observation", "component": "gpio_b",
            "phase": "pre", "status": "observed", "mask": 1, "reset_epoch": 0,
            "local_tick": 5, "observation_event_id": BOOTSTRAP,
            "trigger_id": "gpio_b:0:trigger:2"})
    return journal


def _write_run(directory: Path, journal: _Journal, *, manifest: bool = True,
               trace: bool = True, runtime_paths: dict | None = None) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    events = journal.build()
    if manifest:
        document = _runtime_paths() if runtime_paths is None else runtime_paths
        (directory / "online_session_manifest.json").write_text(
            json.dumps(_manifest(document), sort_keys=True), encoding="utf-8")
    if trace:
        (directory / "online_events.jsonl").write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
            encoding="utf-8")
        (directory / "online_final_trace.meta.json").write_text(json.dumps({
            "schema_version": "online_trace_jsonl.v1",
            "events_file": "online_events.jsonl",
            "event_count": len(events),
            "status": "complete",
            "local_ticks": {"cpu": 5, "gpio_a": 3, "gpio_b": 5}}),
            encoding="utf-8")
    (directory / "report.json").write_text(json.dumps({
        "tests": 2, "statuses": {"complete": 2}, "effective_search_seconds": 1.5,
        "elapsed_seconds": 2.0,
        "finalization_timing_seconds": {"trace_write": 0.25}}), encoding="utf-8")
    (directory / "online_plan.json").write_text(json.dumps({
        "source_admissions": {"admissions": [
            {"admission_id": "admission-1", "role": "fuzz_source"},
            {"admission_id": "admission-2", "role": "bootstrap"}]}}),
        encoding="utf-8")
    (directory / "receipts.jsonl").write_text(
        json.dumps({"status": "complete", "coverage_hex": "01"}) + "\n" +
        json.dumps({"status": "complete", "coverage_hex": "03"}) + "\n",
        encoding="utf-8")
    return directory


def _complete_run(tmp_path: Path, **kwargs) -> Path:
    return _write_run(tmp_path / "run", _journal(**kwargs))


def _edges(report: dict, direction: str) -> dict:
    """Declared *runtime* edges of one direction, keyed by edge identity."""
    return {(row["rule_index"], row["prerequisite_index"]): row
            for row in report["direction_paths"]["directions"][direction]["edges"]
            if row["runtime_edge"]}


def _item(report: dict, key: str) -> dict:
    return next(item for item in report["gate"]["items"] if item["key"] == key)


# ------------------------------------------------------------------- positives


def test_complete_run_certifies_both_directions_and_opens_the_gate(tmp_path):
    run = _complete_run(tmp_path)
    report = p2_acceptance_report(run)

    assert report["schema_version"] == SCHEMA_VERSION
    assert report["run_dir"] == str(run)
    assert report["manifest"]["available"] is True
    assert report["trace"]["available"] is True
    assert report["trace"]["events_ingested"] == 15

    directions = report["direction_paths"]["directions"]
    assert set(directions) == {CPU, IP}
    assert directions[CPU]["status"] == "certified"
    assert directions[IP]["status"] == "certified"
    assert directions[CPU]["runtime_edge_count"] == len(CPU_EDGES)
    assert directions[IP]["runtime_edge_count"] == len(IP_EDGES)

    cpu = _edges(report, CPU)
    assert set(cpu) == set(CPU_EDGES)
    # Hand-computed event ids of the synthetic journal (1-based, in order).
    assert cpu[(0, 0)]["status"] == "certified"
    assert cpu[(0, 0)]["hop_ids"] == ["producer", "delivery"]
    assert cpu[(0, 0)]["producer"]["event_id"] == 8
    assert cpu[(0, 0)]["delivery"]["event_id"] == 9
    assert cpu[(2, 0)]["status"] == "certified"
    assert cpu[(2, 0)]["hop_ids"] == ["producer", "delivery", "consumer"]
    assert cpu[(2, 0)]["producer"]["event_id"] == 2
    assert cpu[(2, 0)]["delivery"]["event_id"] == 3
    assert cpu[(2, 0)]["consumer"]["event_id"] == 4
    assert cpu[(4, 0)]["producer"]["event_id"] == 5
    assert cpu[(4, 0)]["delivery"]["event_id"] == 6
    assert cpu[(4, 0)]["consumer"]["event_id"] == 7
    assert cpu[(5, 0)]["producer"]["event_id"] == 10
    assert cpu[(5, 0)]["delivery"]["event_id"] == 11

    ip = _edges(report, IP)
    assert set(ip) == set(IP_EDGES)
    assert ip[(10, 0)]["status"] == "certified"
    assert ip[(10, 0)]["consumer"]["event_id"] == 7
    assert ip[(11, 0)]["producer"]["event_id"] == 10
    assert ip[(13, 0)]["delivery"]["event_id"] == 9

    # Per-edge delivery/consumption records are materialised, not just implied.
    cpu_records = directions[CPU]["delivery_records"]
    assert [row["event_id"] for row in cpu_records] == [9, 3, 6, 11, 11]
    assert [row["rule_index"] for row in cpu_records] == [0, 2, 4, 5, 6]
    assert [row["event_id"] for row in directions[CPU]["consumption_records"]] == [4, 7]
    assert [row["event_id"] for row in directions[IP]["consumption_records"]] == [7]

    chains = report["chain_certificates"]
    assert chains["by_direction"] is not None
    assert chains["certified_total"] == 0  # measured, not null: the journal has no chain
    assert set(chains["by_direction"]) == {CPU, IP}

    early = report["early_irq"]
    assert early["decision"] == "early_irq_recorded"
    assert early["decision_value"] is True
    assert early["observed_instance_count"] == 2
    assert early["accepted_instance_count"] == 1
    assert early["unaccepted_instance_count"] == 1
    assert early["unaccepted_instances"][0]["trigger_id"] == "gpio_b:0:trigger:2"
    assert early["unaccepted_instances"][0]["event_ids"] == [14, 15]

    gates = report["negative_gates"]
    assert gates["rejected_variants"] == 6
    assert gates["expected_variants"] == 6
    assert gates["all_rejected"] is True
    assert gates["zero_process_evidence"] is True
    assert gates["criterion_met"] is True
    assert all(row["rejected"] for row in gates["variants"])
    assert all(row["first_failing_edge"] for row in gates["variants"])

    replay = report["replay_identity"]
    assert replay["api_level"]["available"] is True
    assert replay["api_level"]["same_graph"] is True
    assert replay["api_level"]["trusted_recognized_by_swapped"] is False
    assert replay["api_level"]["swapped_recognized_by_trusted"] is False
    assert replay["not_mutually_recognized"] is True
    assert replay["run_pair"] is None

    gate = report["gate"]
    assert gate["exit_code"] == 0
    assert gate["ready"] is True
    assert gate["critical_missing"] == []
    assert gate["critical_unmet"] == []

    # The declared-edge consumer keeps its own (larger) bounds; an evicted
    # binding record can never be credited to the edge again.
    assert report["bounds"]["edge_provenance"] == {"max_pending": 4096,
                                                   "max_event_gap": 65536}
    assert report["direction_paths"]["provenance_bounds"]["max_pending"] == 4096
    assert report["direction_paths"]["provenance_bounds"]["max_event_gap"] == 65536

    markdown = render_markdown(report)
    assert markdown.startswith("# P2 acceptance report")
    assert "## 证据边界" in markdown
    assert markdown.index("### 实测") < markdown.index("### null / unknown")
    assert markdown.index("### null / unknown") < markdown.index("### 限制")


def test_parallel_cli_analyze_exits_zero_on_a_complete_run(tmp_path):
    run = _complete_run(tmp_path)
    json_out = tmp_path / "out" / "p2.json"
    markdown_out = tmp_path / "out" / "p2.md"
    result = subprocess.run(
        [sys.executable, str(CLI), "analyze", "--run-dir", str(run),
         "--json-out", str(json_out), "--markdown-out", str(markdown_out)],
        capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    assert document["schema_version"] == SCHEMA_VERSION
    assert json.loads(json_out.read_text(encoding="utf-8")) == document
    assert markdown_out.read_text(encoding="utf-8").startswith(
        "# P2 acceptance report")


# ------------------------------------------------------------------- negatives


def test_removed_consumer_hop_is_incomplete_and_never_certified(tmp_path):
    run = _complete_run(tmp_path, consumer=False)
    report = p2_acceptance_report(run)

    cpu = _edges(report, CPU)
    assert cpu[(2, 0)]["status"] == "incomplete"
    assert cpu[(2, 0)]["status"] != "certified"
    assert cpu[(2, 0)]["missing"] == ["consumer"]
    assert cpu[(2, 0)]["consumer"] is None
    assert cpu[(2, 0)]["proof_scope"] == "partial_journal_observation"
    assert cpu[(2, 0)]["hop_ids"] == ["producer", "delivery"]
    assert len(cpu[(2, 0)]["hops"]) == 2
    # The selected but non-runtime hops of the same direction stay explicit.
    declared = {(row["rule_index"], row["prerequisite_index"]): row
                for row in report["direction_paths"]["directions"][CPU]["edges"]}
    assert declared[(1, 0)]["runtime_edge"] is False
    assert declared[(1, 0)]["status"] == "not_a_runtime_edge"
    assert declared[(1, 0)]["reason"]

    directions = report["direction_paths"]["directions"]
    assert directions[CPU]["status"] == "incomplete"
    assert directions[CPU]["counts"]["certified"] == 4
    assert directions[CPU]["counts"]["incomplete"] == 1
    assert directions[CPU]["incomplete_edges"] == [
        {"rule_index": 2, "prerequisite_index": 0, "missing": ["consumer"]}]
    assert directions[IP]["status"] == "certified"

    assert report["gate"]["exit_code"] == 2
    assert report["gate"]["ready"] is False
    assert report["gate"]["critical_missing"] == []
    assert "direction_paths.CPU_TO_IP_TO_CPU" in report["gate"]["critical_unmet"]
    item = _item(report, "direction_paths.CPU_TO_IP_TO_CPU")
    assert item["measured"] is True
    assert item["met"] is False
    assert "incomplete" in item["reason"]


def test_missing_trace_artifact_reports_null_sections_and_exit_two(tmp_path):
    run = _write_run(tmp_path / "run", _journal(), trace=False)
    report = p2_acceptance_report(run)

    assert report["trace"]["available"] is False
    assert report["trace"]["reason"]
    directions = report["direction_paths"]["directions"]
    assert directions[CPU]["declared"] is True
    assert directions[CPU]["status"] is None
    assert directions[CPU]["reason"]
    assert report["chain_certificates"]["by_direction"] is None
    assert report["chain_certificates"]["reason"]
    assert report["early_irq"]["decision_value"] is None
    assert report["early_irq"]["decision"] == "unknown"
    assert "trace" in report["early_irq"]["reason"]

    gate = report["gate"]
    assert gate["exit_code"] == 2
    assert "trace" in gate["critical_missing"]
    assert "direction_paths.CPU_TO_IP_TO_CPU" in gate["critical_missing"]
    assert "chain_certificates.by_direction" in gate["critical_missing"]


def test_missing_manifest_reports_null_declaration_and_exit_two(tmp_path):
    run = _write_run(tmp_path / "run", _journal(), manifest=False)
    report = p2_acceptance_report(run)

    assert report["manifest"]["available"] is False
    assert report["manifest"]["reason"]
    assert report["direction_paths"]["directions"][CPU]["status"] is None
    assert report["direction_paths"]["directions"][CPU]["runtime_edge_count"] == 0
    # The early-IRQ scan reads the trace alone, so it stays measurable.
    assert report["early_irq"]["decision_value"] is True

    gate = report["gate"]
    assert gate["exit_code"] == 2
    assert "manifest" in gate["critical_missing"]
    assert "direction_paths.CPU_TO_IP_TO_CPU" in gate["critical_missing"]


def test_absent_early_irq_is_null_and_never_a_pass(tmp_path):
    accepted_only = _complete_run(tmp_path / "accepted", early_irq=False)
    report = p2_acceptance_report(accepted_only)
    early = report["early_irq"]
    assert early["decision_value"] is None
    assert early["decision"] == "no_early_irq_instance_observed"
    assert early["observed_instance_count"] == 1
    assert early["unaccepted_instance_count"] == 0
    assert "Not observed is not a pass" in early["reason"]
    assert report["gate"]["exit_code"] == 2
    assert "early_irq.early_irq_recorded" in report["gate"]["critical_missing"]

    silent = _write_run(tmp_path / "silent", _journal(early_irq=False,
                                                     accepted_irq=False))
    silent_report = p2_acceptance_report(silent)
    assert silent_report["early_irq"]["decision"] == "unknown"
    assert silent_report["early_irq"]["decision_value"] is None
    assert silent_report["early_irq"]["observed_instance_count"] == 0
    assert "no native IRQ" in silent_report["early_irq"]["reason"]


def test_unrequested_replay_pair_keeps_the_api_level_verdict(tmp_path):
    run = _complete_run(tmp_path)
    empty = tmp_path / "no-manifest-run"
    empty.mkdir()
    report = p2_acceptance_report(run, run_dir_b=empty)
    pair = report["replay_identity"]["run_pair"]
    assert pair["available"] is False
    assert "online_session_manifest.json" in pair["reason"]
    assert pair["mutually_recognized"] is None
    # A requested comparison that could not run is missing evidence, not a pass.
    assert report["gate"]["exit_code"] == 2
    assert "replay_identity.run_pair" in report["gate"]["critical_missing"]


def test_same_graph_with_a_different_edge_identity_is_not_mutually_recognized(
        tmp_path):
    run = _complete_run(tmp_path / "a")
    declaration, compiled = _declaration()
    manifest = json.loads(
        (run / "online_session_manifest.json").read_text(encoding="utf-8"))
    prepared = manifest["runtime_paths"]["declaration"]
    contract = json.loads(json.dumps(prepared["contract"]))
    contract["edges"].append({"rule_index": 3, "prerequisite_index": 0,
                              "relation": "causal_order",
                              "initiator_component": None, "device_id": None,
                              "base": None, "size": None,
                              "resource_component": None, "resource_id": None})
    contract["edges"].sort(key=lambda row: (row["rule_index"],
                                            row["prerequisite_index"]))
    different = PreparedRuntimePathContract.from_document(
        {"schema_version": "prepared_runtime_paths.v1", "graph": prepared["graph"],
         "contract": contract, "selections": prepared["selections"]})
    assert different.path_ids == declaration.prepared.path_ids
    assert different.contract.identity_sha256 != declaration.contract.identity_sha256
    runtime_paths = {**manifest["runtime_paths"],
                     "declaration": different.document(),
                     "contract_sha256": different.contract.identity_sha256}
    other = _write_run(tmp_path / "b", _journal(), runtime_paths=runtime_paths)

    report = p2_acceptance_report(run, run_dir_b=other)
    pair = report["replay_identity"]["run_pair"]
    assert pair["available"] is True
    assert pair["same_graph"] is True
    assert pair["edge_identity_differs"] is True
    assert pair["declaration_documents_equal"] is False
    assert pair["contract_identities_equal"] is False
    assert pair["mutually_recognized"] is False
    assert pair["run_accepts_compare_record"] is False
    assert pair["compare_accepts_run_record"] is False
    assert pair["rejection_reason"] == (
        "fresh replay runtime path declaration mismatch")
    assert report["replay_identity"]["not_mutually_recognized"] is True
    assert report["gate"]["exit_code"] == 0


def test_identical_declaration_pair_is_recognized_and_is_not_the_criterion(
        tmp_path):
    run = _complete_run(tmp_path / "a")
    same = _complete_run(tmp_path / "b")
    report = p2_acceptance_report(run, run_dir_b=same)
    pair = report["replay_identity"]["run_pair"]
    assert pair["available"] is True
    assert pair["same_graph"] is True
    assert pair["edge_identity_differs"] is False
    assert pair["criterion_applicable"] is False
    assert pair["mutually_recognized"] is True
    assert pair["reason"]
    # The criterion is exercised by the API-level gate, so the run pair does
    # not turn a same-identity pair into a failure.
    assert report["replay_identity"]["not_mutually_recognized"] is True
    # The analyzer compared the two traces of one declaration.
    assert report["replay_identity"]["trace_replay"]["event_count_match"] is True
    assert report["chain_certificates"]["cross_check"] == "agree"
    assert any(limit["quantity"] == "replay_identity.trace_replay"
               for limit in report["limits"])
    assert report["gate"]["exit_code"] == 0


def test_truncated_acceptance_index_makes_the_early_irq_verdict_unknown(tmp_path):
    run = _complete_run(tmp_path)
    report = p2_acceptance_report(run, max_acceptance_keys=1)
    early = report["early_irq"]
    assert early["acceptance_index_truncated"] is True
    assert early["decision"] == "unknown"
    assert early["decision_value"] is None
    assert "acceptance index is incomplete" in early["reason"]
    assert report["gate"]["exit_code"] == 2
    assert "early_irq.early_irq_recorded" in report["gate"]["critical_missing"]


def test_injected_chain_producer_counts_are_split_between_the_two_passes(tmp_path):
    """A comparison run's replay pass must not inflate the main-pass counts."""
    counter = {"value": 0}

    class _StubProducer:
        def ingest(self, events):
            counter["value"] += 1
            return [{"schema_version": "runtime_chain_certificate.v1",
                     "certificate_id": f"stub-{counter['value']}",
                     "status": "certified", "direction": CPU,
                     "hops": ["instruction_admission"]}]

        def flush(self):
            return []

    def factory(*, max_pending, max_event_gap, require_native_receipts):
        return _StubProducer()

    run = _complete_run(tmp_path / "a")
    same = _complete_run(tmp_path / "b")
    report = p2_acceptance_report(run, run_dir_b=same, chain_producer=factory)
    assert counter["value"] == 2  # one producer per pass
    chains = report["chain_certificates"]
    assert chains["producer"] == "injected chain_producer"
    assert chains["by_direction"][CPU]["certified"] == 1
    assert chains["by_direction"][CPU]["raw_certified_records"] == 1
    assert chains["replay_pass_raw_records"][CPU]["certified"] == 1
    assert chains["cross_check"] == "agree"


def test_cli_analyze_exits_two_when_a_critical_item_is_missing(tmp_path):
    run = _write_run(tmp_path / "broken", _journal(), trace=False)
    result = subprocess.run(
        [sys.executable, str(CLI), "analyze", "--run-dir", str(run)],
        capture_output=True, text=True)
    assert result.returncode == 2, result.stdout + result.stderr
    document = json.loads(result.stdout)
    assert document["gate"]["exit_code"] == 2
    assert document["gate"]["critical_missing"]


def test_cli_reports_a_hard_error_as_exit_one(tmp_path):
    result = subprocess.run(
        [sys.executable, str(CLI), "analyze",
         "--run-dir", str(tmp_path / "does-not-exist")],
        capture_output=True, text=True)
    assert result.returncode == 1
    assert "does not exist" in result.stderr
