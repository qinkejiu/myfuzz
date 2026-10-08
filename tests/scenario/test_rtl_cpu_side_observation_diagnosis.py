"""Which observed RTL branch points the shipped harness can never light, and why.

The campaign spends a bounded counter budget (``COUNTER_LIMIT`` = 128) on the
instrumented branch universe: 64 CPU points and 64 IP points, chosen by the
production selector.  A point whose instance subtree was *not elaborated* by
Verilator is bound to a wire that no logic drives, so its counter is zero for
every run no matter how good the search is.  Until that is separated from "the
stimulus never reached it", ``branch_points = 50/128`` looks like a search
quality number when part of it is a fixed structural zero.

The classifier under test reads only saved artifacts - the run's
``report.json``, ``build/soc_coverage_plan.json``, the instrumented
``instrumentation.json`` manifest and the compiled Verilator model header - and
answers, per observed point, which of the three cases it is:

``unelaborated-bound`` (a)
    the point's instance chain is absent from the compiled model, so its
    coverage wire exists only as an undriven declaration and is constant.
``elaborated-unexercised`` (b)
    the instance is in the compiled model and the counter stayed at zero.
``probe-unreadable`` (c)
    the point has no counter slot in the shipped readback vector at all.

The synthetic cases pin the three-way split and the fail-closed behaviour when
the compiled model is missing; the two real-artifact cases pin the exact
numbers the P4 diagnosis report quotes, so a change in the selector or in the
CPU configuration cannot silently move them.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.rtl_cpu_side_observation_diagnosis import (
    CLASS_LIT,
    CLASS_UNELABORATED,
    CLASS_UNEXERCISED,
    CLASS_UNKNOWN,
    CLASS_UNREADABLE,
    EXIT_UNELABORATED_PRESENT,
    SCHEMA_VERSION,
    classify_observed_points,
    diagnose_run,
    main,
    summarise,
    verilated_scope_chain,
)
from scripts.run_p4_cpu_side_branch_gate import (
    EXIT_BLOCKED,
    EXIT_INCONCLUSIVE,
    _verdict,
)


ROOT = Path(__file__).resolve().parents[2]

#: Runs frozen by the P4 instrumented-branch window.  The first is the best
#: instrumented run in the workspace (50/128 overall), the second is a CPU-armed
#: run whose RVFI opcode bins are lit, i.e. the CPU really does retire
#: instructions - which is what makes the CPU-side zero a structural result
#: rather than "the CPU never ran".
BEST_RUN = ROOT / "runs" / "ibex-pulp-gpio-spi-mmio-tx-rx-gpio-3600s-20260926"
CPU_RETIRING_RUN = ROOT / "runs" / "ibex-pulp-gpio-spi-cpu-gpio-write-600s-160c-20260926"


def _point(position: int, bit: int, category: str, instance: str, **extra):
    row = {
        "position": position,
        "bit": bit,
        "category": category,
        "instance_id": instance,
        "module": "m",
        "file": "rtl/m.sv",
        "line": 1,
        "kind": "if",
        "subtype": "true",
        "signal": "__vi_branch_cov_0",
    }
    row.update(extra)
    return row


def _require(run: Path) -> Path:
    if not (run / "report.json").is_file():
        pytest.skip(f"saved run absent: {run}")
    if not (run / "build" / "obj_dir").is_dir():
        pytest.skip(f"compiled model absent: {run}")
    return run


# ---------------------------------------------------------------------------
# pure classifier
# ---------------------------------------------------------------------------

def test_unelaborated_instance_is_bound_to_a_wire_no_logic_drives() -> None:
    rows = classify_observed_points(
        [_point(0, 621, "cpu", "myfuzz_soc_top/u_cpu0/i_ibex_trvk")],
        maxima=[0], model_text="myfuzz_live_tb__DOT__dut__DOT__u_cpu0__DOT__x;")
    assert rows[0]["elaborated"] is False
    assert rows[0]["classification"] == CLASS_UNELABORATED
    assert rows[0]["max"] == 0


def test_elaborated_but_zero_counter_is_unexercised_not_unelaborated() -> None:
    model = ("myfuzz_live_tb__DOT__dut__DOT__u_cpu0__DOT__u_ibex_core__DOT__"
             "if_stage_i__DOT__pc_id;")
    rows = classify_observed_points(
        [_point(0, 5, "cpu", "myfuzz_soc_top/u_cpu0/u_ibex_core/if_stage_i")],
        maxima=[0], model_text=model)
    assert rows[0]["elaborated"] is True
    assert rows[0]["classification"] == CLASS_UNEXERCISED


def test_elaborated_and_lit_counter_is_reported_lit() -> None:
    model = ("myfuzz_live_tb__DOT__dut__DOT__u_spi0__DOT__u_spictrl__DOT__"
             "u_rxreg__DOT_____05Fvi_branch_cov_2102;")
    rows = classify_observed_points(
        [_point(0, 162, "ip", "myfuzz_soc_top/u_spi0/u_spictrl/u_rxreg")],
        maxima=[200], model_text=model)
    assert rows[0]["classification"] == CLASS_LIT
    assert rows[0]["max"] == 200


def test_a_scope_the_model_does_not_emit_is_excluded_conservatively() -> None:
    """The probe is deliberately asymmetric.

    A chain that *is* present proves the instance was elaborated.  A chain that
    is absent is treated as unelaborated, which can also happen when Verilator
    inlines a small instance; that direction only ever excludes a point from a
    re-selection, it never claims coverage for a wire nothing drives.
    """
    # Only the parent scope exists here, exactly as in the real run's model.
    model = "myfuzz_live_tb__DOT__dut__DOT__u_cpu0__DOT__u_ibex_core__DOT__pc_id;"
    rows = classify_observed_points(
        [_point(0, 621, "cpu", "myfuzz_soc_top/u_cpu0/u_ibex_lockstep/pmp_i")],
        maxima=[0], model_text=model)
    assert rows[0]["elaborated"] is False
    assert rows[0]["classification"] == CLASS_UNELABORATED


def test_a_point_without_a_counter_slot_is_probe_unreadable() -> None:
    """The shipped testbench indexes counters by position, so a point past the
    end of the readback vector has no probe at all."""
    rows = classify_observed_points(
        [_point(7, 900, "cpu", "myfuzz_soc_top/u_cpu0/u_ibex_core/x")],
        maxima=[0, 1, 2], model_text="u_cpu0__DOT__u_ibex_core__DOT__")
    assert rows[0]["classification"] == CLASS_UNREADABLE
    assert rows[0]["max"] is None


def test_a_missing_compiled_model_is_unknown_not_elaborated() -> None:
    """Fail closed: without the model we cannot claim a wire is armed."""
    rows = classify_observed_points(
        [_point(0, 621, "cpu", "myfuzz_soc_top/u_cpu0/i_ibex_trvk")],
        maxima=[0], model_text=None)
    assert rows[0]["elaborated"] is None
    assert rows[0]["classification"] == CLASS_UNKNOWN
    assert rows[0]["classification"] != CLASS_UNEXERCISED


def test_a_missing_counter_vector_is_probe_unreadable() -> None:
    rows = classify_observed_points(
        [_point(0, 621, "cpu", "myfuzz_soc_top/u_cpu0/i_ibex_trvk")],
        maxima=None, model_text="u_cpu0__DOT__")
    assert rows[0]["classification"] == CLASS_UNREADABLE


def test_scope_chain_mangles_leading_underscores_like_verilator() -> None:
    assert verilated_scope_chain(
        "myfuzz_soc_top/u_cpu0/u_ibex_core") == "u_cpu0__DOT__u_ibex_core__DOT__"
    assert verilated_scope_chain(
        "myfuzz_soc_top/_hidden/leaf") == "__05Fhidden__DOT__leaf__DOT__"
    # The SoC top itself is the harness's ``dut`` instance, so only the
    # segments below it are mangled; an empty path mangles to nothing.
    assert verilated_scope_chain("myfuzz_soc_top") == ""
    assert verilated_scope_chain("") == ""


# ---------------------------------------------------------------------------
# real saved artifacts
# ---------------------------------------------------------------------------

def test_best_run_reports_the_whole_cpu_quota_as_unelaborated_bound() -> None:
    run = _require(BEST_RUN)
    document = diagnose_run(run)
    assert document["schema_version"] == SCHEMA_VERSION
    counts = document["counts"]
    assert counts["points"] == 128
    assert counts["by_category"]["cpu"]["points"] == 64
    assert counts["by_category"]["ip"]["points"] == 64
    # Every CPU point is bound to a subtree the compiled model does not contain.
    assert counts["by_category"]["cpu"][CLASS_UNELABORATED] == 64
    assert counts["by_category"]["cpu"][CLASS_LIT] == 0
    # The IP side, by contrast, is genuinely exercised: the zero there is search
    # quality, and the classifier must keep the two apart.
    assert counts["by_category"]["ip"][CLASS_UNELABORATED] == 0
    assert counts["by_category"]["ip"][CLASS_LIT] == 50
    assert counts["by_category"]["ip"][CLASS_UNEXERCISED] == 14
    assert counts[CLASS_UNREADABLE] == 0
    assert counts[CLASS_UNKNOWN] == 0


def test_best_run_names_the_two_generate_disabled_subtrees() -> None:
    run = _require(BEST_RUN)
    document = diagnose_run(run)
    dead = document["unelaborated_instances"]
    assert dead["myfuzz_soc_top/u_cpu0/i_ibex_trvk"] == 10
    shadow = {instance: n for instance, n in dead.items()
              if instance.startswith("myfuzz_soc_top/u_cpu0/u_ibex_lockstep/")}
    assert sum(shadow.values()) == 54
    assert all("u_shadow_core" in instance or "shadow" in instance
               for instance in shadow)
    # The elaborated core is present in the same model header while both
    # generate-disabled subtrees are absent: the CPU subtree exists, it simply
    # is not the one the selector spent the quota on.
    scopes = {row["name"]: row["present"] for row in document["reference_scopes"]}
    assert scopes["cpu-active-core"] is True
    assert scopes["cpu-lockstep-branch"] is False
    assert scopes["cpu-cheriot-trvk-branch"] is False


def test_classification_is_exhaustive_over_the_observed_vector() -> None:
    run = _require(BEST_RUN)
    counts = diagnose_run(run)["counts"]
    total = (counts[CLASS_LIT] + counts[CLASS_UNEXERCISED]
             + counts[CLASS_UNELABORATED] + counts[CLASS_UNREADABLE]
             + counts[CLASS_UNKNOWN])
    assert total == counts["points"] == len(diagnose_run(run)["points"])


def test_a_second_cpu_retiring_run_reproduces_the_same_cpu_zero() -> None:
    """The CPU in this run retires instructions (its RVFI opcode bins are lit),
    so the CPU-side zero cannot be explained by "the CPU never executed"."""
    run = _require(CPU_RETIRING_RUN)
    document = diagnose_run(run)
    counts = document["counts"]
    assert counts["by_category"]["cpu"][CLASS_UNELABORATED] == 64
    assert counts["by_category"]["cpu"][CLASS_LIT] == 0
    assert counts["by_category"]["ip"][CLASS_LIT] > 0
    observed_bins = [row for row in document["points"]
                     if row["category"] == "cpu" and row["max"]]
    assert observed_bins == []


def test_summary_line_states_the_cpu_side_class_without_claiming_coverage() -> None:
    run = _require(BEST_RUN)
    document = diagnose_run(run)
    line = summarise(document)
    assert "cpu=0/64 lit" in line
    assert "unelaborated-bound=64" in line
    # The summary must never present the CPU-side zero as branch coverage.
    assert "cpu_branch_coverage" not in line


def test_cli_exit_code_flags_unelaborated_observed_points(tmp_path, capsys) -> None:
    run = _require(BEST_RUN)
    out = tmp_path / "diagnosis.json"
    assert main(["--run", str(run), "--quiet", "--out", str(out)]) == \
        EXIT_UNELABORATED_PRESENT
    payload = json.loads(out.read_text())
    assert payload["counts"]["by_category"]["cpu"][CLASS_UNELABORATED] == 64
    assert capsys.readouterr().out == ""


def test_cli_reports_an_unreadable_run_without_crashing(tmp_path, capsys) -> None:
    empty = tmp_path / "no-such-run"
    empty.mkdir()
    assert main(["--run", str(empty)]) == 1
    assert "report.json" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# the prepared gate, exercised read-only against saved runs
# ---------------------------------------------------------------------------

def test_gate_is_blocked_while_the_cpu_quota_is_unelaborated() -> None:
    """On a run whose CPU really retires, the gate must point at the mapping."""
    run = _require(CPU_RETIRING_RUN)
    code, checks, document = _verdict(run, minimum_cpu_points=1)
    assert code == EXIT_BLOCKED
    by_name = {check["criterion"]: check["passed"] for check in checks}
    assert by_name["coverage-identity"] is True
    assert by_name["cpu-stimulus (precondition)"] is True
    assert by_name["no-dead-counters"] is False
    assert by_name["cpu-side-observable"] is False
    assert document["counts"][CLASS_UNELABORATED] == 64


def test_gate_is_inconclusive_when_the_cpu_never_retired() -> None:
    """An mmio-only run lights 50/64 IP points but never runs the CPU, so its
    CPU zero cannot be attributed to the mapping either way."""
    run = _require(BEST_RUN)
    code, checks, document = _verdict(run, minimum_cpu_points=1)
    assert code == EXIT_INCONCLUSIVE
    by_name = {check["criterion"]: check["passed"] for check in checks}
    assert by_name["cpu-stimulus (precondition)"] is False
    assert by_name["coverage-identity"] is True
    assert document["counts"]["by_category"]["ip"][CLASS_LIT] == 50
