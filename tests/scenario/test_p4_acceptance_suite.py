"""``scripts/run_p4_acceptance_suite.py``: the union document and its exits.

The suite shells out read-only to the *shipped* P4 gates and aggregates their
verdicts into one ``p4_acceptance_suite.v1`` document.  No test here starts
Verilator, RTL, cargo or the RFuzz client, and no test reads the live state of
``runs/``: every gate invocation is stubbed (``suite._run``) and every declared
artifact path is redirected below a private ``tmp_path`` (``suite._file``), so
each expectation is a value this file writes itself.

What is pinned here:

* the document schema and the pass/fail semantics -- all critical items
  measured and met is exit 0, one critical item unmet is exit 2, a failing
  invocation is exit 1, and an item counts only when ``measured`` and ``met``
  are *both* true, so an unmeasured item can never be reported as a pass;
* the per-gate verdict rules for a stubbed PASS, a stubbed FAIL, a stubbed
  missing artifact and a stubbed timeout;
* ``_json_after`` on marker-delimited gate output, including malformed input;
* the receipt scan on zero codes, three codes and a malformed line (the
  ``null`` + reason path, never a fabricated 0);
* the benefit comparator on ``evidence_status`` / ``refusals`` variants;
* determinism: two runs over the same stubbed inputs are byte-identical.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]

from scripts import run_p4_acceptance_suite as suite  # noqa: E402

DOCUMENT_MARKER = "gate-document-json:"

PATH_SWITCH_ARTIFACT = (
    "runs/current-dataflow-p4-path-switch-20261007-logs/path_switch_gate.json")
INITIAL_RAM_ARTIFACT = (
    "runs/current-dataflow-p4-initial-ram-20261007-logs/initial_ram_gate.json")
BENEFIT_ARTIFACT = (
    "runs/current-dataflow-p4-operator-benefit-20261008/p4_operator_benefit.json")
SLOT_ARTIFACT = (
    "runs/current-dataflow-p5-final-20261007-logs/p4_suite_slot_immutability.json")
RECEIPTS = ("runs/current-dataflow-p4-rejection-calibration-20261007-online/"
            "receipts.jsonl")

#: The eight critical keys, in the order ``main`` appends them.
CRITICAL_KEYS = (
    "legal_operator_sequence_edit_insert",
    "legal_operator_sequence_edit_delete",
    "legal_operator_path_switch",
    "legal_operator_initial_ram_data",
    "cpu_side_coverage_identity",
    "first_seen_ledger",
    "cpu_side_gate_decidable",
    "fixed_budget_comparison",
    "slot_immutability",
    "adoption_and_refusal_reasons")
PARTIAL_KEY = "cpu_side_gate_verdict"
#: Every item ``main`` appends, critical and partial, in document order.
ITEM_ORDER = CRITICAL_KEYS[:5] + (PARTIAL_KEY,) + CRITICAL_KEYS[5:]


# --------------------------------------------------------------------- stubs


class _Gates:
    """A stub for ``suite._run``: fixed answers per gate, recorded argv."""

    def __init__(self, default: tuple[int, str, str] = (0, "", "")) -> None:
        self.default = default
        self.routes: list[tuple[str, tuple[int, str, str]]] = []
        self.calls: list[list[str]] = []

    def route(self, needle: str, response: tuple[int, str, str]) -> "_Gates":
        self.routes.append((needle, response))
        return self

    def __call__(self, argv, *, timeout: int = 3600):
        self.calls.append([str(part) for part in argv])
        for needle, response in self.routes:
            if any(needle in part for part in argv):
                return response
        return self.default


@pytest.fixture
def artifacts(tmp_path, monkeypatch):
    """Redirect every declared artifact path below a private directory."""
    root = tmp_path / "artifacts"
    root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(suite, "_file", lambda path: root / Path(path))
    return root


def _write(root: Path, relative: str, text: str) -> Path:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target


def _write_json(root: Path, relative: str, payload) -> Path:
    return _write(root, relative, json.dumps(payload, indent=1, sort_keys=True))


def _gate_stdout(document: dict) -> str:
    """What a gate prints: a human verdict, the marker, then the document."""
    return ("P4 gate verdict: stub\n"
            f"{DOCUMENT_MARKER}\n"
            + json.dumps(document, indent=1, sort_keys=True,
                         ensure_ascii=False) + "\n")


def _item(key: str, *, critical: bool = True, measured: bool = True,
          met=True, value=None, reason: str | None = None) -> dict:
    return suite.item(key, critical, measured, met, value, [], reason)


def _all_met(monkeypatch, *, calls: list | None = None,
             overrides: dict[str, dict] | None = None) -> list:
    """Install pure stubs for every gate check; record the calls made."""
    recorded = calls if calls is not None else []
    overrides = overrides or {}

    def met_item(key: str, critical: bool = True) -> dict:
        return overrides.get(key) or _item(key, critical=critical,
                                           value={"stub": key})

    def check_sequence_edit(arm: str, replay: str) -> dict:
        recorded.append(f"sequence_edit_{arm}")
        return met_item(f"legal_operator_sequence_edit_{arm}")

    def check_path_switch() -> dict:
        recorded.append("path_switch")
        return met_item("legal_operator_path_switch")

    def check_initial_ram() -> dict:
        recorded.append("initial_ram")
        return met_item("legal_operator_initial_ram_data")

    def check_cpu_side_coverage() -> tuple[dict, dict]:
        recorded.append("cpu_side_coverage")
        identity = met_item("cpu_side_coverage_identity")
        partial = overrides.get(PARTIAL_KEY) or _item(
            PARTIAL_KEY, critical=False, measured=True, met=False,
            value={"verdict": "INCONCLUSIVE"}, reason="stub partial")
        return identity, partial

    def check_benefit() -> dict:
        recorded.append("benefit")
        return met_item("fixed_budget_comparison")

    def check_slot_immutability() -> dict:
        recorded.append("slot_immutability")
        return met_item("slot_immutability")

    def check_first_seen_ledger() -> dict:
        recorded.append("first_seen_ledger")
        return met_item("first_seen_ledger")

    def check_cpu_side_decidable() -> dict:
        recorded.append("cpu_side_gate_decidable")
        return met_item("cpu_side_gate_decidable")

    def check_adoption_and_refusals() -> dict:
        recorded.append("adoption_and_refusals")
        return met_item("adoption_and_refusal_reasons")

    monkeypatch.setattr(suite, "check_sequence_edit", check_sequence_edit)
    monkeypatch.setattr(suite, "check_path_switch", check_path_switch)
    monkeypatch.setattr(suite, "check_initial_ram", check_initial_ram)
    monkeypatch.setattr(suite, "check_cpu_side_coverage",
                        check_cpu_side_coverage)
    monkeypatch.setattr(suite, "check_benefit", check_benefit)
    monkeypatch.setattr(suite, "check_slot_immutability",
                        check_slot_immutability)
    monkeypatch.setattr(suite, "check_first_seen_ledger",
                        check_first_seen_ledger)
    monkeypatch.setattr(suite, "check_cpu_side_decidable",
                        check_cpu_side_decidable)
    monkeypatch.setattr(suite, "check_adoption_and_refusals",
                        check_adoption_and_refusals)
    return recorded


def _document(text: str) -> dict:
    """The JSON document ``main`` prints before its one-line summary."""
    return json.JSONDecoder().raw_decode(text.lstrip())[0]


def _run_main(capsys, argv: list[str]) -> tuple[int, dict, str]:
    code = suite.main(argv)
    out = capsys.readouterr().out
    return code, _document(out), out


def _assert_item_shape(row: dict) -> None:
    assert set(row) == {"key", "critical", "measured", "met", "value",
                        "evidence", "reason"}, row
    assert isinstance(row["key"], str) and row["key"]
    assert isinstance(row["critical"], bool)
    assert isinstance(row["measured"], bool)
    assert row["met"] in (True, False, None)
    assert isinstance(row["evidence"], list)
    assert row["reason"] is None or isinstance(row["reason"], str)


# ---------------------------------------------------------------- _json_after


def test_json_after_reads_the_document_after_the_marker():
    payload = {"verdict": "PASS", "criteria": {"a": {"status": "pass"}}}

    parsed = suite._json_after(_gate_stdout(payload), DOCUMENT_MARKER)

    assert parsed == payload


def test_json_after_ignores_json_printed_before_the_marker():
    text = ('prefix {"verdict": "FAIL"}\n' + DOCUMENT_MARKER + "\n"
            + json.dumps({"verdict": "PASS"}) + "\n")

    assert suite._json_after(text, DOCUMENT_MARKER) == {"verdict": "PASS"}


def test_json_after_returns_none_when_the_marker_is_absent():
    assert suite._json_after('{"verdict": "PASS"}', DOCUMENT_MARKER) is None
    assert suite._json_after("", DOCUMENT_MARKER) is None


def test_json_after_returns_none_without_a_document():
    assert suite._json_after(f"{DOCUMENT_MARKER}\nno json here\n",
                             DOCUMENT_MARKER) is None


def test_json_after_returns_none_for_malformed_json():
    for tail in ('{"verdict": "PASS",}', '{"verdict": }', "{oops",
                 '{"verdict": "PASS"'):
        assert suite._json_after(f"{DOCUMENT_MARKER}\n{tail}\n",
                                 DOCUMENT_MARKER) is None, tail


def test_json_after_keeps_reading_past_a_trailing_summary_line():
    # A gate that prints a summary after its document must not lose the
    # verdict: the parser reads the first complete JSON document rather than
    # requiring the document to run to the end of stdout.
    text = (f"{DOCUMENT_MARKER}\n" + json.dumps({"verdict": "PASS"})
            + "\n本脚本未运行任何 RTL/Verilator/Rust/fuzz 作业。\n")

    assert suite._json_after(text, DOCUMENT_MARKER) == {"verdict": "PASS"}


def test_json_after_reads_the_first_marker_delimited_document():
    text = (f"{DOCUMENT_MARKER}\n" + json.dumps({"verdict": "PASS"})
            + f"\n{DOCUMENT_MARKER}\n" + json.dumps({"verdict": "FAIL"}) + "\n")

    assert suite._json_after(text, DOCUMENT_MARKER) == {"verdict": "PASS"}


# ----------------------------------------------------- schema and exit codes


def test_every_critical_item_measured_and_met_exits_zero(monkeypatch, capsys):
    calls = _all_met(monkeypatch)

    code, document, _ = _run_main(capsys, [])

    assert calls == ["sequence_edit_insert", "sequence_edit_delete",
                     "path_switch", "initial_ram", "cpu_side_coverage",
                     "first_seen_ledger", "cpu_side_gate_decidable",
                     "benefit", "slot_immutability", "adoption_and_refusals"]
    assert code == suite.EXIT_READY == 0
    assert document["schema_version"] == suite.SCHEMA_VERSION
    assert document["ready"] is True
    assert document["exit_code"] == 0
    assert document["critical_total"] == len(CRITICAL_KEYS) == 10
    assert document["critical_met"] == 10
    assert document["critical_unmet"] == []
    assert document["partial"] == [PARTIAL_KEY]
    assert document["limits"] == []
    assert [row["key"] for row in document["items"]] == list(ITEM_ORDER)
    for row in document["items"]:
        _assert_item_shape(row)
        if row["critical"]:
            assert row["measured"] is True and row["met"] is True
    assert "unmeasured item as a pass" in document["exit_code_semantics"]


def test_skip_heavy_omits_both_long_gates_and_says_so(monkeypatch, capsys):
    calls = _all_met(monkeypatch)

    code, document, _ = _run_main(capsys, ["--skip-heavy"])

    assert calls == ["sequence_edit_insert", "sequence_edit_delete",
                     "cpu_side_coverage", "first_seen_ledger",
                     "cpu_side_gate_decidable", "benefit", "slot_immutability",
                     "adoption_and_refusals"]
    assert code == suite.EXIT_READY
    # --skip-heavy drops the two long gates, so eight critical items remain.
    assert document["critical_total"] == 8
    assert document["critical_met"] == 8
    assert all("--skip-heavy" in limit for limit in document["limits"])


def test_one_measured_critical_item_unmet_exits_two(monkeypatch, capsys):
    _all_met(monkeypatch, overrides={
        "fixed_budget_comparison": _item(
            "fixed_budget_comparison", measured=True, met=False,
            value={"refused_families": ["chains"]},
            reason="a required metric family is unmeasurable")})

    code, document, _ = _run_main(capsys, [])

    assert code == suite.EXIT_NOT_READY == 2
    assert document["exit_code"] == 2
    assert document["ready"] is False
    assert document["critical_met"] == 9
    assert document["critical_unmet"] == ["fixed_budget_comparison"]
    row = next(row for row in document["items"]
               if row["key"] == "fixed_budget_comparison")
    assert row["measured"] is True and row["met"] is False
    assert row["reason"] == "a required metric family is unmeasurable"


def test_a_critical_item_that_claims_met_without_measurement_exits_two(
        monkeypatch, capsys):
    # The aggregation must require both flags: a stub that reports
    # ``measured=false, met=true`` is exactly the shape an unmeasured item
    # would take if a check ever fabricated a pass.
    _all_met(monkeypatch, overrides={
        "slot_immutability": _item("slot_immutability", measured=False,
                                   met=True, value=None, reason=None)})

    code, document, _ = _run_main(capsys, [])

    assert code == suite.EXIT_NOT_READY
    assert document["critical_unmet"] == ["slot_immutability"]
    assert document["critical_met"] == 9
    row = next(row for row in document["items"]
               if row["key"] == "slot_immutability")
    assert row["measured"] is False and row["met"] is True


def test_an_unmeasured_critical_item_is_unmet_and_never_a_pass(
        monkeypatch, capsys):
    _all_met(monkeypatch, overrides={
        "adoption_and_refusal_reasons": _item(
            "adoption_and_refusal_reasons", measured=False, met=None,
            value=None, reason="the receipts are missing")})

    code, document, _ = _run_main(capsys, [])

    assert code == suite.EXIT_NOT_READY
    assert document["critical_unmet"] == ["adoption_and_refusal_reasons"]
    assert document["ready"] is False
    assert document["partial"] == [PARTIAL_KEY]


def test_a_non_critical_partial_never_changes_the_exit_code(monkeypatch, capsys):
    _all_met(monkeypatch, overrides={
        PARTIAL_KEY: _item(PARTIAL_KEY, critical=False, measured=False,
                           met=None, reason="the gate was not runnable")})

    code, document, _ = _run_main(capsys, [])

    assert code == suite.EXIT_READY
    assert document["ready"] is True
    assert document["partial"] == [PARTIAL_KEY]
    assert PARTIAL_KEY not in document["critical_unmet"]
    row = next(row for row in document["items"] if row["key"] == PARTIAL_KEY)
    assert row["critical"] is False


def test_a_hard_invocation_error_exits_one_with_a_document(monkeypatch, capsys):
    _all_met(monkeypatch)

    def explode() -> dict:
        raise RuntimeError("the comparator cannot be invoked")

    monkeypatch.setattr(suite, "check_benefit", explode)

    code, document, out = _run_main(capsys, [])

    assert code == suite.EXIT_USAGE == 1
    assert document["schema_version"] == suite.SCHEMA_VERSION
    assert document["exit_code"] == 1
    assert document["ready"] is False
    assert "items" not in document  # nothing is fabricated for a hard error
    assert "RuntimeError" in document["error"]
    assert "the comparator cannot be invoked" in document["error"]
    assert _document(out) == document  # the error document is the stdout JSON


def test_two_runs_over_the_same_stubs_are_byte_identical(
        artifacts, capsys, tmp_path, monkeypatch):
    gates = _Gates()
    gates.route("run_p4_sequence_edit_gate.py",
                (0, _gate_stdout({"verdict": "PASS"}), ""))
    gates.route("report_rtl_branch_coverage.py",
                (0, json.dumps(_coverage_document("verified")), ""))
    gates.route("run_p4_cpu_side_branch_gate.py",
                (0, "[PASS] no-dead-counters: none\nverdict=PASS\n", ""))
    monkeypatch.setattr(suite, "_run", gates)
    _write_json(artifacts, PATH_SWITCH_ARTIFACT, {"checks": {"a": True}})
    _write_json(artifacts, INITIAL_RAM_ARTIFACT,
                {"ok": True, "on_first_read": {"event_id": 4}})
    _write_json(artifacts, BENEFIT_ARTIFACT,
                {"evidence_status": "measurable", "refusals": [],
                 "pairs": [{"operator": {"label": "path_switch"}}]})
    _write_json(artifacts, SLOT_ARTIFACT,
                [{"run_conclusion": "immutable"},
                 {"run_conclusion": "immutable"}])
    _write(artifacts, RECEIPTS, "".join(
        json.dumps({"rejection": {"code": f"code.{index}", "pointer": "/p"}})
        + "\n" for index in range(3)))
    first, second = tmp_path / "first.json", tmp_path / "second.json"

    code_one, _, out_one = _run_main(capsys, ["--write", str(first)])
    code_two, _, out_two = _run_main(capsys, ["--write", str(second)])

    assert code_one == code_two == suite.EXIT_READY
    assert first.read_bytes() == second.read_bytes()
    assert out_one == out_two
    assert json.loads(first.read_text(encoding="utf-8"))["critical_met"] == 10


# ------------------------------------------------------------- sequence edit


def test_sequence_edit_stubbed_pass_is_measured_and_met(artifacts, monkeypatch):
    gates = _Gates().route("run_p4_sequence_edit_gate.py",
                           (0, _gate_stdout({"verdict": "PASS"}), ""))
    monkeypatch.setattr(suite, "_run", gates)

    row = suite.check_sequence_edit("insert", "replay.log")

    assert row["key"] == "legal_operator_sequence_edit_insert"
    assert row["measured"] is True and row["met"] is True
    assert row["value"] == "PASS" and row["reason"] is None
    assert row["critical"] is True


def test_sequence_edit_stubbed_fail_is_measured_but_not_met(artifacts,
                                                            monkeypatch):
    gates = _Gates().route("run_p4_sequence_edit_gate.py",
                           (2, _gate_stdout({"verdict": "FAIL"}),
                            "case 3 did not replay"))
    monkeypatch.setattr(suite, "_run", gates)

    row = suite.check_sequence_edit("delete", "replay.log")

    assert row["measured"] is True and row["met"] is False
    assert row["value"] == "FAIL"
    assert "did not replay" in row["reason"]


def test_sequence_edit_without_a_document_is_unmeasured(artifacts, monkeypatch):
    gates = _Gates().route("run_p4_sequence_edit_gate.py",
                           (1, "traceback, no marker\n", "the run is missing"))
    monkeypatch.setattr(suite, "_run", gates)

    row = suite.check_sequence_edit("insert", "replay.log")

    assert row["measured"] is False
    assert row["met"] is not True
    assert row["reason"]


def test_sequence_edit_a_pass_verdict_with_a_failing_exit_is_not_met(
        artifacts, monkeypatch):
    # The document's verdict and the process exit code are two statements about
    # the same run; the item may only pass when both agree that it passed.
    gates = _Gates().route("run_p4_sequence_edit_gate.py",
                           (2, _gate_stdout({"verdict": "PASS"}), "exit 2"))
    monkeypatch.setattr(suite, "_run", gates)

    row = suite.check_sequence_edit("insert", "replay.log")

    assert row["measured"] is True
    assert row["met"] is False
    assert row["reason"]


# --------------------------------------------------------------- path switch


def test_path_switch_all_checks_passed_is_met(artifacts, monkeypatch):
    _write_json(artifacts, PATH_SWITCH_ARTIFACT,
                {"checks": {"on_switches": True, "off_ignores": True}})
    monkeypatch.setattr(suite, "_run", _Gates())

    row = suite.check_path_switch()

    assert row["measured"] is True and row["met"] is True
    assert row["value"]["checks"] == {"on_switches": True, "off_ignores": True}


def test_path_switch_one_failed_check_is_unmet(artifacts, monkeypatch):
    _write_json(artifacts, PATH_SWITCH_ARTIFACT,
                {"checks": {"on_switches": True, "off_ignores": False}})
    monkeypatch.setattr(suite, "_run", _Gates())

    row = suite.check_path_switch()

    assert row["measured"] is True
    assert row["met"] is False
    assert row["reason"]


def test_path_switch_a_failing_exit_code_is_unmet_even_when_checks_pass(
        artifacts, monkeypatch):
    _write_json(artifacts, PATH_SWITCH_ARTIFACT, {"checks": {"a": True}})
    monkeypatch.setattr(suite, "_run",
                        _Gates().route("path_switch_gate.py",
                                       (2, "", "the long arm is missing")))

    row = suite.check_path_switch()

    assert row["measured"] is True and row["met"] is False
    assert "long arm is missing" in row["reason"]


def test_path_switch_a_missing_artifact_with_exit_zero_is_not_met(
        artifacts, monkeypatch):
    # A gate that exits 0 without writing its checks document measured nothing:
    # ``all({}.values())`` is vacuously true, so the criterion must require a
    # non-empty checks document.
    monkeypatch.setattr(suite, "_run", _Gates(default=(0, "", "")))

    row = suite.check_path_switch()

    assert row["measured"] is False
    assert row["met"] is not True
    assert row["value"]["checks"] == {}
    assert row["reason"]


def test_path_switch_a_malformed_artifact_is_unmeasured_not_a_crash(
        artifacts, monkeypatch):
    _write(artifacts, PATH_SWITCH_ARTIFACT, '{"checks": {"a": tru')
    monkeypatch.setattr(suite, "_run", _Gates())

    row = suite.check_path_switch()

    assert row["measured"] is False
    assert row["met"] is not True
    assert row["reason"]


# -------------------------------------------------------------- initial RAM


def test_initial_ram_ok_document_is_met(artifacts, monkeypatch):
    _write_json(artifacts, INITIAL_RAM_ARTIFACT,
                {"ok": True, "on_first_read": {"event_id": 11}})
    monkeypatch.setattr(suite, "_run", _Gates())

    row = suite.check_initial_ram()

    assert row["measured"] is True and row["met"] is True
    assert row["value"] == {"ok": True, "on_first_read": 11}


def test_initial_ram_a_stale_ok_document_with_a_failing_gate_is_not_met(
        artifacts, monkeypatch):
    # The document is left over from an earlier run; the gate itself failed, so
    # the item is not measured *by this invocation* and cannot pass.
    _write_json(artifacts, INITIAL_RAM_ARTIFACT,
                {"ok": True, "on_first_read": {"event_id": 11}})
    monkeypatch.setattr(suite, "_run",
                        _Gates().route("initial_ram_gate.py",
                                       (2, "", "arm comparison refused")))

    row = suite.check_initial_ram()

    assert row["met"] is not True
    assert row["reason"]


def test_initial_ram_without_a_document_is_unmeasured(artifacts, monkeypatch):
    monkeypatch.setattr(suite, "_run", _Gates())

    row = suite.check_initial_ram()

    assert row["measured"] is False
    assert row["met"] is not True
    assert row["reason"]


# ---------------------------------------------------------- slot immutability


def test_slot_immutability_all_runs_immutable_is_met(artifacts, monkeypatch):
    _write_json(artifacts, SLOT_ARTIFACT,
                [{"run_conclusion": "immutable", "run_dir": "a"},
                 {"run_conclusion": "immutable", "run_dir": "b"}])
    monkeypatch.setattr(suite, "_run", _Gates())

    row = suite.check_slot_immutability()

    assert row["measured"] is True and row["met"] is True
    assert row["value"] == {"runs": 2, "immutable": 2, "violated": 0}


def test_slot_immutability_a_violated_run_is_unmet(artifacts, monkeypatch):
    _write_json(artifacts, SLOT_ARTIFACT,
                [{"run_conclusion": "immutable"},
                 {"run_conclusion": "violated"}])
    monkeypatch.setattr(suite, "_run", _Gates())

    row = suite.check_slot_immutability()

    assert row["measured"] is True and row["met"] is False
    assert row["value"]["violated"] == 1
    assert row["reason"]


def test_slot_immutability_a_stale_document_with_a_failing_exit_is_not_met(
        artifacts, monkeypatch):
    _write_json(artifacts, SLOT_ARTIFACT,
                [{"run_conclusion": "immutable"},
                 {"run_conclusion": "immutable"}])
    monkeypatch.setattr(suite, "_run",
                        _Gates().route("myfuzz.scenario.slot_immutability",
                                       (2, "", "run B has no online trace")))

    row = suite.check_slot_immutability()

    assert row["met"] is not True
    assert "no online trace" in row["reason"]


def test_slot_immutability_a_non_list_document_is_unmeasured(artifacts,
                                                             monkeypatch):
    _write_json(artifacts, SLOT_ARTIFACT, {"run_conclusion": "immutable"})
    monkeypatch.setattr(suite, "_run", _Gates())

    row = suite.check_slot_immutability()

    assert row["measured"] is False
    assert row["met"] is not True
    assert row["reason"]


# ------------------------------------------------------------------- benefit


def _comparator(pairs: int = 3, *, evidence_status: str = "measurable",
                refusals: list | None = None) -> dict:
    labels = ["path_switch", "initial_ram_data", "closed_loop_energy"]
    return {
        "schema_version": "p4_operator_benefit.v1",
        "evidence_status": evidence_status,
        "refusals": refusals or [],
        "pairs": [{"operator": {"label": label}} for label in labels[:pairs]],
    }


def test_benefit_a_measurable_document_is_met(artifacts, monkeypatch):
    _write_json(artifacts, BENEFIT_ARTIFACT, _comparator())
    monkeypatch.setattr(suite, "_run", _Gates())

    row = suite.check_benefit()

    assert row["measured"] is True and row["met"] is True
    assert row["value"]["pairs"] == 3
    assert row["value"]["evidence_status"] == "measurable"
    assert row["value"]["refused_families"] == []
    assert row["value"]["operators"] == ["path_switch", "initial_ram_data",
                                         "closed_loop_energy"]
    assert row["reason"] is None


def test_benefit_a_refused_document_names_the_refused_families(artifacts,
                                                               monkeypatch):
    # The comparator's refusal rows carry ``metric_family`` (its own schema);
    # the suite must report those names rather than ``[null]``.
    _write_json(artifacts, BENEFIT_ARTIFACT, _comparator(
        evidence_status="refused",
        refusals=[{"metric_family": "chains", "arm": "on", "quantity": "x",
                   "reason": "no chain certificates on the ON arm"},
                  {"metric_family": "coverage", "arm": "off", "quantity": "y",
                   "reason": "no coverage_hex on the OFF arm"}]))
    monkeypatch.setattr(suite, "_run",
                        _Gates().route("compare_p4_operator_benefit.py",
                                       (2, "", "refused: chains, coverage")))

    row = suite.check_benefit()

    assert row["measured"] is True and row["met"] is False
    assert row["value"]["refused_families"] == ["chains", "coverage"]
    assert None not in row["value"]["refused_families"]
    assert row["value"]["refusal_count"] == 2


def test_benefit_a_refusal_row_without_a_family_key_still_refuses(
        artifacts, monkeypatch):
    _write_json(artifacts, BENEFIT_ARTIFACT, _comparator(
        evidence_status="refused",
        refusals=[{"quantity": "witnessed_edges", "reason": "unmeasurable"}]))
    monkeypatch.setattr(suite, "_run", _Gates())

    row = suite.check_benefit()

    assert row["met"] is False
    assert row["value"]["refused_families"] == ["unnamed"]


def test_benefit_a_missing_document_is_unmeasured(artifacts, monkeypatch):
    monkeypatch.setattr(suite, "_run", _Gates())

    row = suite.check_benefit()

    assert row["measured"] is False
    assert row["met"] is not True
    assert row["reason"]


def test_benefit_a_malformed_document_is_unmeasured(artifacts, monkeypatch):
    _write(artifacts, BENEFIT_ARTIFACT, "[not, a, document")
    monkeypatch.setattr(suite, "_run", _Gates())

    row = suite.check_benefit()

    assert row["measured"] is False
    assert row["met"] is not True
    assert row["reason"]


# ----------------------------------------------------------- CPU-side report


def _coverage_document(status: str, *, binding: bool = True,
                       first_seen: bool = True) -> dict:
    document = {"schema_version": "rtl_branch_coverage.v1", "status": status,
                "external_binding": {"passed": binding},
                "observed_branches": {"observed_points": 30,
                                      "total_points": 128}}
    if first_seen:
        # The same stub answers both the coverage-identity check and the
        # first-seen check, so it must carry the joined ledger the latter reads.
        document["observed_branches"]["first_seen"] = {
            "available": True, "points": 30,
            "earliest": {"bit": 21, "event": 1, "time": 0.01}}
        document["first_seen_source"] = {"available": True}
    return document


def test_cpu_side_identity_verified_is_met_and_its_gate_verdict_is_partial(
        artifacts, monkeypatch):
    gates = _Gates().route("report_rtl_branch_coverage.py",
                           (0, json.dumps(_coverage_document("verified")), ""))
    gates.route("run_p4_cpu_side_branch_gate.py", (
        4,
        "=== P4 CPU-side branch observation gate ===\n"
        "  [PASS] no-dead-counters: none\n"
        "  [FAIL] cpu-stimulus (precondition): no RVFI opcode window\n"
        "verdict=INCONCLUSIVE\n", ""))
    monkeypatch.setattr(suite, "_run", gates)

    identity, partial = suite.check_cpu_side_coverage()

    assert "--json" in gates.calls[0] and "--run" in gates.calls[0]
    assert "verify" in gates.calls[1]
    assert identity["measured"] is True and identity["met"] is True
    assert identity["value"]["status"] == "verified"
    assert identity["value"]["observed_points"] == 30
    assert partial["key"] == PARTIAL_KEY
    assert partial["critical"] is False
    assert partial["measured"] is True and partial["met"] is False
    assert partial["value"] == {
        "verdict": "INCONCLUSIVE", "passed": 1, "total": 2,
        "failed": ["[FAIL] cpu-stimulus (precondition): no RVFI opcode window"]}
    assert "RVFI opcode" in partial["reason"]


def test_cpu_side_identity_unverified_is_unmet(artifacts, monkeypatch):
    gates = _Gates().route("report_rtl_branch_coverage.py", (
        1, json.dumps(_coverage_document("unverified")), "identity mismatch"))
    gates.route("run_p4_cpu_side_branch_gate.py",
                (4, "verdict=INCONCLUSIVE\n", ""))
    monkeypatch.setattr(suite, "_run", gates)

    identity, partial = suite.check_cpu_side_coverage()

    assert identity["measured"] is True and identity["met"] is False
    assert "identity mismatch" in identity["reason"]
    assert partial["measured"] is True and partial["met"] is False


def test_cpu_side_identity_a_verified_document_rejected_by_its_own_exit_is_unmet(
        artifacts, monkeypatch):
    # ``report_rtl_branch_coverage.py`` reports EXIT_OK only when the vector
    # verified *and* the external binding passed; a document that claims
    # ``status: verified`` while that attestation failed is REJECTED by the CLI
    # (exit 1) and must not be counted as met here.
    gates = _Gates().route("report_rtl_branch_coverage.py", (
        1, json.dumps(_coverage_document("verified", binding=False)),
        "external binding failed"))
    gates.route("run_p4_cpu_side_branch_gate.py", (4, "verdict=PASS\n", ""))
    monkeypatch.setattr(suite, "_run", gates)

    identity, _ = suite.check_cpu_side_coverage()

    assert identity["measured"] is True
    assert identity["met"] is False
    assert identity["reason"]


def test_cpu_side_identity_needs_the_external_binding_attestation(
        artifacts, monkeypatch):
    # Even a CLI that exited 0 must not make a rejected document met: the
    # binding is part of the report's own acceptance rule (``_accepted``).
    gates = _Gates().route("report_rtl_branch_coverage.py", (
        0, json.dumps(_coverage_document("verified", binding=False)), ""))
    gates.route("run_p4_cpu_side_branch_gate.py", (4, "verdict=PASS\n", ""))
    monkeypatch.setattr(suite, "_run", gates)

    identity, _ = suite.check_cpu_side_coverage()

    assert identity["measured"] is True
    assert identity["met"] is not True


def test_cpu_side_report_without_json_is_unmeasured(artifacts, monkeypatch):
    gates = _Gates().route("report_rtl_branch_coverage.py",
                           (1, "", "the run has no compiled model"))
    gates.route("run_p4_cpu_side_branch_gate.py", (4, "", ""))
    monkeypatch.setattr(suite, "_run", gates)

    identity, partial = suite.check_cpu_side_coverage()

    assert identity["measured"] is False
    assert identity["met"] is not True
    assert identity["reason"]
    assert partial["measured"] is False  # no verdict line at all


# ------------------------------------------------------------------- timeout


def test_a_timeout_in_every_gate_keeps_the_item_table_and_exits_two(
        artifacts, capsys, monkeypatch):
    def expire(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs.get("timeout", 1))

    monkeypatch.setattr(suite.subprocess, "run", expire)

    code, document, _ = _run_main(capsys, [])

    assert code == suite.EXIT_NOT_READY == 2
    assert document["ready"] is False
    assert [row["key"] for row in document["items"]] == list(ITEM_ORDER)
    assert document["critical_total"] == 10
    assert document["critical_met"] == 0
    assert sorted(document["critical_unmet"]) == sorted(CRITICAL_KEYS)
    for row in document["items"]:
        if row["critical"]:
            _assert_item_shape(row)
            assert row["measured"] is False
            assert row["met"] is not True
            assert row["reason"]
            if row["key"] != "adoption_and_refusal_reasons":  # reads a file
                assert "timeout" in row["reason"].lower(), row["reason"]


def test_a_timeout_is_reported_per_item_with_its_own_reason(artifacts,
                                                            monkeypatch):
    def expire(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs.get("timeout", 1))

    monkeypatch.setattr(suite.subprocess, "run", expire)

    row = suite.check_sequence_edit("insert", "replay.log")

    assert row["measured"] is False and row["met"] is not True
    assert "timeout" in row["reason"].lower()
    assert "3600" in row["reason"]


# ------------------------------------------------------------------ receipts


def _receipt(code: str | None = None, pointer: str = "/fragment") -> str:
    rejection = {}
    if code is not None:
        rejection["code"] = code
        rejection["pointer"] = pointer
    return json.dumps({"case_id": "c1", "rejection": rejection})


def test_receipts_a_missing_file_is_the_null_path(artifacts):
    row = suite.check_adoption_and_refusals()

    assert row["critical"] is True
    assert row["measured"] is False
    assert row["met"] is None
    assert row["value"] is None
    assert "missing" in row["reason"]


def test_receipts_with_no_codes_is_measured_but_unmet(artifacts):
    _write(artifacts, RECEIPTS, _receipt() + "\n" + _receipt() + "\n")

    row = suite.check_adoption_and_refusals()

    assert row["measured"] is True and row["met"] is False
    assert row["value"]["receipts"] == 2
    assert row["value"]["distinct_codes"] == 0
    assert row["value"]["codes"] == {}
    assert "three distinct" in row["reason"]


def test_receipts_with_three_distinct_codes_is_met(artifacts):
    _write(artifacts, RECEIPTS,
           _receipt("mmio.bad_width", "/a") + "\n"
           + _receipt("budget.exhausted", "/b") + "\n"
           + _receipt("ownership.fixed_input", "/c") + "\n"
           + _receipt("mmio.bad_width", "/a") + "\n")

    row = suite.check_adoption_and_refusals()

    assert row["measured"] is True and row["met"] is True
    assert row["value"]["receipts"] == 4
    assert row["value"]["distinct_codes"] == 3
    assert row["value"]["codes"] == {"budget.exhausted": 1, "mmio.bad_width": 2,
                                     "ownership.fixed_input": 1}
    assert row["reason"] is None


def test_receipts_a_malformed_line_is_the_null_path_not_a_fabricated_zero(
        artifacts):
    _write(artifacts, RECEIPTS,
           _receipt("mmio.bad_width") + "\n"
           + "{this is not json}\n"
           + _receipt("budget.exhausted") + "\n")

    row = suite.check_adoption_and_refusals()

    assert row["measured"] is False
    assert row["met"] is None
    assert row["value"] is None  # never "0 codes" from a partial read
    assert "line 2" in row["reason"]
    assert "JSON" in row["reason"]


def test_receipts_an_empty_file_is_the_null_path(artifacts):
    _write(artifacts, RECEIPTS, "\n\n")

    row = suite.check_adoption_and_refusals()

    assert row["measured"] is False
    assert row["met"] is None
    assert row["value"] is None
    assert row["reason"]
