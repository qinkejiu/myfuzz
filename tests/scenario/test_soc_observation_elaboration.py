"""The builder must never publish a counter slot the compiled model cannot light.

The P4 instrumented-branch window ends with 0/64 CPU points lit in all 28 runs
because the observation selector spends the CPU quota on the two lowest coverage
bits of ``u_cpu0`` - and those bits belong to ``u_cpu0/i_ibex_trvk`` and
``u_cpu0/u_ibex_lockstep``, generate branches the compiled Verilator model does
not elaborate.  Their counters are undriven wires: a structural zero.

The fix under test moves the proof into the build.  After the instrumented
design compiles, the builder probes the produced model for every planned
observation point's instance scope, drops every point bound to a scope the model
does not contain, re-plans the same counter quota without those instances, and
rebuilds the harness once.  A dropped point is reported as ``unelaborated_scope``
with an explicit reason in ``soc_coverage_plan.json`` and in the build document -
never silently, and never as "unexercised".

These tests are pure software: the compiled model is a synthetic header text and
the compile step is a callback, so no Verilator, no RFuzz client and no run are
started here.  The last group exercises the read-only gate against the frozen
saved runs, whose plans predate the fix and therefore carry no probe record.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from myfuzz.elaboration_probe import (
    CLASS_ELABORATED,
    CLASS_UNELABORATED_SCOPE,
    CLASS_ELABORATION_UNKNOWN,
    REASON_SCOPE_ABSENT,
    REASON_NO_SUBTREE,
    SCHEMA_VERSION,
    CompiledModel,
    ElaborationProbeError,
    ElaborationUnavailable,
    classify_planned_points,
    read_compiled_model,
    replan_observations,
    verilated_scope_chain,
)
from myfuzz.integration.soc_builder import (
    SocBuildError,
    _plan_observations_with_elaboration_probe,
)
from myfuzz.integration.soc_coverage import (
    coverage_observation_plan,
    universe_from_instance_bits,
)
from scripts.rtl_cpu_side_observation_diagnosis import diagnose_run
from scripts.run_p4_cpu_side_branch_gate import EXIT_BLOCKED, _verdict


ROOT = Path(__file__).resolve().parents[2]
#: Best instrumented run of the window (50/128 overall) and the CPU-armed run
#: whose RVFI bins are lit.  Both were produced before this fix, so their saved
#: plans carry no elaboration probe record.
BEST_RUN = ROOT / "runs" / "ibex-pulp-gpio-spi-mmio-tx-rx-gpio-3600s-20260926"
CPU_RETIRING_RUN = ROOT / "runs" / "ibex-pulp-gpio-spi-cpu-gpio-write-600s-160c-20260926"

CPU = "u_cpu0"
DEAD_LOCKSTEP = "myfuzz_soc_top/u_cpu0/u_ibex_lockstep/register_file_shadow_i"
DEAD_TRVK = "myfuzz_soc_top/u_cpu0/i_ibex_trvk"
ALIVE_IF = "myfuzz_soc_top/u_cpu0/u_ibex_core/if_stage_i"
ALIVE_ID = "myfuzz_soc_top/u_cpu0/u_ibex_core/id_stage_i"
IP_RX = "myfuzz_soc_top/u_spi0/u_spictrl/u_rxreg"
IP_GPIO = "myfuzz_soc_top/u_gpio0/u_gpio"


def _bit(index: int, instance: str, module: str) -> dict:
    return {"bit": index, "instance_path": instance, "module": module,
            "signal": "__vi_branch_cov_%d" % index, "kind": "if",
            "subtype": "true", "file": "rtl/%s.sv" % module, "line": 1,
            "column": 1}


#: The dead subtrees own the *lowest* bits, exactly as the instrumenter's
#: source-order concatenation produces them for the real ibex cell.
BITS = (
    _bit(0, DEAD_LOCKSTEP, "ibex_register_file_ff"),
    _bit(1, DEAD_LOCKSTEP, "ibex_register_file_ff"),
    _bit(2, DEAD_TRVK, "ibex_trvk"),
    _bit(3, DEAD_TRVK, "ibex_trvk"),
    _bit(100, ALIVE_IF, "ibex_if_stage"),
    _bit(101, ALIVE_IF, "ibex_if_stage"),
    _bit(102, ALIVE_IF, "ibex_if_stage"),
    _bit(103, ALIVE_ID, "ibex_id_stage"),
    _bit(104, ALIVE_ID, "ibex_id_stage"),
    _bit(200, IP_RX, "spi_rxreg"),
    _bit(201, IP_RX, "spi_rxreg"),
    _bit(202, IP_GPIO, "gpio_reg"),
    _bit(203, IP_GPIO, "gpio_reg"),
)

IP_INSTANCES = ("u_spi0", "u_gpio0")


def _model(*instances: str, template: str = "myfuzz_live_tb__DOT__dut__DOT__%s") -> CompiledModel:
    """A synthetic ``*___024root.h`` carrying only the named instance scopes."""
    body = "\n".join(
        template % verilated_scope_chain(instance) for instance in instances)
    return CompiledModel.of_text(body)


#: The compiled model the real cell produces: the live core and both real
#: peripherals are present, the two generate-disabled CPU subtrees are not.
LIVE_MODEL = _model(ALIVE_IF, ALIVE_ID, IP_RX, IP_GPIO)


def _plan(bits=BITS, limit: int = 6, cpu_instance: str = CPU):
    universe = universe_from_instance_bits(
        bits, cpu_instance=cpu_instance, ip_instances=list(IP_INSTANCES))
    return universe, coverage_observation_plan(universe, list(bits), limit)


def _observed_bits(plan) -> list[int]:
    return [int(row["bit"]) for row in plan["observed"]]


# ---------------------------------------------------------------------------
# re-planning: unelaborated points leave the observed set and are reported
# ---------------------------------------------------------------------------

def test_unelaborated_points_are_excluded_and_the_quota_is_replanned() -> None:
    universe, plan = _plan()
    # The first plan is the production one: ascending bit order spends the whole
    # CPU quota on the two dead subtrees.
    assert _observed_bits(plan) == [0, 1, 2, 200, 201, 202]

    outcome = replan_observations(plan=plan, universe=universe, bits=list(BITS),
                                  limit=6, model=LIVE_MODEL)

    assert outcome["changed"] is True
    final = outcome["plan"]
    # The CPU quota now comes from elaborated CPU points, and no dead bit is
    # reported as observed.
    assert _observed_bits(final) == [100, 101, 102, 200, 201, 202]
    assert final["observed_by_category"] == {"cpu": 3, "ip": 3}
    assert int(final["limit"]) == 6
    assert final["replanned_after_elaboration_probe"] is True
    # The IP side is untouched: it was elaborated all along.
    assert [int(row["bit"]) for row in final["observed"] if row["category"] == "ip"] \
        == [200, 201, 202]


def test_every_exclusion_carries_a_classification_and_a_reason() -> None:
    universe, plan = _plan()
    outcome = replan_observations(plan=plan, universe=universe, bits=list(BITS),
                                  limit=6, model=LIVE_MODEL)
    elaboration = outcome["elaboration"]

    assert elaboration["schema_version"] == SCHEMA_VERSION
    assert elaboration["status"] == "replanned"
    excluded = elaboration["excluded"]
    assert {int(row["bit"]) for row in excluded} == {0, 1, 2}
    for row in excluded:
        assert row["classification"] == CLASS_UNELABORATED_SCOPE
        assert row["reason"] == REASON_SCOPE_ABSENT
        assert row["scope_chain"] == verilated_scope_chain(row["instance_id"])
        assert row["instance_id"] in (DEAD_LOCKSTEP, DEAD_TRVK)
    # The exclusions are attributed to the instances that own them, with the
    # whole candidate population of each dead instance accounted for.
    instances = elaboration["excluded_instances"]
    assert set(instances) == {DEAD_LOCKSTEP, DEAD_TRVK}
    assert instances[DEAD_LOCKSTEP]["candidate_bits"] == 2
    assert instances[DEAD_TRVK]["candidate_bits"] == 2
    assert instances[DEAD_TRVK]["classification"] == CLASS_UNELABORATED_SCOPE
    assert instances[DEAD_TRVK]["reason"] == REASON_SCOPE_ABSENT
    counts = elaboration["counts"]
    assert counts["refused_planned_points"] == 3
    assert counts["excluded_instances"] == 2
    assert counts["excluded_candidate_bits"] == 4
    assert counts["unelaborated_scope"] == 3
    assert counts["elaboration_unknown"] == 0
    # Every *reported* point states its own classification, so nothing in the
    # final observation set is left for a reader to infer.
    assert [row["classification"] for row in elaboration["observations"]] \
        == [CLASS_ELABORATED] * 6
    assert {int(row["bit"]) for row in elaboration["observations"]} \
        == {100, 101, 102, 200, 201, 202}


def test_the_plan_still_accounts_for_every_instrumented_point() -> None:
    """Dropping points must not shrink the universe on paper."""
    universe, plan = _plan()
    outcome = replan_observations(plan=plan, universe=universe, bits=list(BITS),
                                  limit=6, model=LIVE_MODEL)
    final = outcome["plan"]
    assert int(final["unobserved_count"]) == len(BITS) - 6
    assert int(final["eligible_candidate_count"]) == len(BITS) - 4
    assert int(final["excluded_candidate_count"]) == 4
    assert final["elaboration"]["schema_version"] == SCHEMA_VERSION


def test_replanning_converges_before_the_harness_is_rebuilt() -> None:
    """A dead instance the first plan did not touch is still removed.

    The re-plan is iterated against the same compiled model - the model does not
    depend on which counters the harness reads - so convergence costs no extra
    compile.  Here both dead subtrees have to be discovered before the CPU quota
    can land on the live core.
    """
    universe, plan = _plan(limit=4)
    assert _observed_bits(plan) == [0, 1, 200, 201]

    outcome = replan_observations(plan=plan, universe=universe, bits=list(BITS),
                                  limit=4, model=LIVE_MODEL)

    assert outcome["changed"] is True
    assert _observed_bits(outcome["plan"]) == [100, 101, 200, 201]
    elaboration = outcome["elaboration"]
    assert set(elaboration["excluded_instances"]) == {DEAD_LOCKSTEP, DEAD_TRVK}
    # Two probing rounds found a dead instance each; the third found none.
    assert [round_["round"] for round_ in elaboration["rounds"]] == [1, 2, 3]
    assert elaboration["rounds"][0]["excluded_instances"] == [DEAD_LOCKSTEP]
    assert elaboration["rounds"][1]["excluded_instances"] == [DEAD_TRVK]
    assert elaboration["rounds"][2]["unelaborated_scope"] == 0


def test_a_point_whose_scope_cannot_be_derived_is_unknown_not_elaborated() -> None:
    """A point on the SoC top itself has no child scope to probe.

    It cannot be proven armed, so it is excluded as ``elaboration_unknown`` with
    its own reason and is never reported as merely unexercised.
    """
    top_bit = _bit(5, "myfuzz_soc_top", "myfuzz_soc_top")
    bits = list(BITS) + [top_bit]
    universe, plan = _plan(bits=bits, limit=6, cpu_instance="myfuzz_soc_top")
    assert 5 in _observed_bits(plan)

    outcome = replan_observations(plan=plan, universe=universe, bits=bits,
                                  limit=6, model=LIVE_MODEL)

    unknown = [row for row in outcome["elaboration"]["excluded"]
               if row["classification"] == CLASS_ELABORATION_UNKNOWN]
    assert len(unknown) == 1
    assert unknown[0]["bit"] == 5
    assert unknown[0]["reason"] == REASON_NO_SUBTREE
    assert 5 not in _observed_bits(outcome["plan"])
    assert outcome["elaboration"]["counts"]["elaboration_unknown"] == 1


def test_classification_is_per_point_and_names_the_scope_chain() -> None:
    rows = classify_planned_points(
        [{"bit": 0, "instance_id": DEAD_TRVK, "point_id": "p0"},
         {"bit": 100, "instance_id": ALIVE_IF, "point_id": "p1"}],
        LIVE_MODEL)
    assert [row["classification"] for row in rows] \
        == [CLASS_UNELABORATED_SCOPE, CLASS_ELABORATED]
    assert rows[0]["reason"] == REASON_SCOPE_ABSENT
    assert rows[0]["scope_chain"] == "u_cpu0__DOT__i_ibex_trvk__DOT__"
    assert rows[1]["scope_chain"] == \
        "u_cpu0__DOT__u_ibex_core__DOT__if_stage_i__DOT__"


# ---------------------------------------------------------------------------
# default path: everything elaborates, so nothing changes
# ---------------------------------------------------------------------------

def test_plan_is_unchanged_when_every_observed_scope_elaborates() -> None:
    universe, plan = _plan()
    fully_elaborated = _model(DEAD_LOCKSTEP, DEAD_TRVK, ALIVE_IF, ALIVE_ID,
                              IP_RX, IP_GPIO)

    outcome = replan_observations(plan=plan, universe=universe, bits=list(BITS),
                                  limit=6, model=fully_elaborated)

    assert outcome["changed"] is False
    final = outcome["plan"]
    assert _observed_bits(final) == _observed_bits(plan)
    assert final["elaboration"]["status"] == "verified"
    assert final["elaboration"]["excluded"] == []
    assert final["elaboration"]["counts"]["refused_planned_points"] == 0
    assert "replanned_after_elaboration_probe" not in final


def test_an_untouched_plan_is_not_mutated_in_place() -> None:
    universe, plan = _plan()
    before = json.dumps(plan, sort_keys=True)
    fully_elaborated = _model(DEAD_LOCKSTEP, DEAD_TRVK, ALIVE_IF, ALIVE_ID,
                              IP_RX, IP_GPIO)

    replan_observations(plan=plan, universe=universe, bits=list(BITS), limit=6,
                        model=fully_elaborated)

    assert json.dumps(plan, sort_keys=True) == before


# ---------------------------------------------------------------------------
# fail closed: an unavailable or unparseable probe never keeps today's plan
# ---------------------------------------------------------------------------

def test_an_unavailable_compiled_model_refuses_instead_of_claiming_coverage() -> None:
    universe, plan = _plan()
    model = CompiledModel.unavailable("compiled-model-header-missing")

    with pytest.raises(ElaborationUnavailable) as error:
        replan_observations(plan=plan, universe=universe, bits=list(BITS),
                            limit=6, model=model)
    assert "compiled-model-header-missing" in str(error.value)
    assert isinstance(error.value, ElaborationProbeError)


def test_reading_a_missing_model_header_reports_the_reason(tmp_path) -> None:
    model = read_compiled_model(tmp_path)
    assert model.present is False
    assert model.text is None
    assert model.reason


def test_reading_a_model_header_hashes_it(tmp_path) -> None:
    obj_dir = tmp_path / "obj_dir"
    obj_dir.mkdir()
    header = obj_dir / "Vmyfuzz_live_tb___024root.h"
    header.write_text("myfuzz_live_tb__DOT__dut__DOT__u_cpu0__DOT__x;\n")
    model = read_compiled_model(tmp_path)
    assert model.present is True
    assert model.text is not None and "u_cpu0__DOT__" in model.text
    assert len(model.sha256) == 64
    assert model.document()["header"].endswith("Vmyfuzz_live_tb___024root.h")


# ---------------------------------------------------------------------------
# builder wiring: probe, re-plan, rebuild the harness exactly once
# ---------------------------------------------------------------------------

def _compile_callback(build: Path, models: list[CompiledModel], calls: list[list[int]],
                      *, header_name: str = "Vmyfuzz_live_tb___024root.h"):
    """Stand in for "render the harness, run Verilator, probe the executable"."""
    def compile_plan(candidate_plan):
        calls.append(_observed_bits(candidate_plan))
        obj_dir = build / "obj_dir"
        obj_dir.mkdir(parents=True, exist_ok=True)
        model = models[min(len(calls) - 1, len(models) - 1)]
        if model.text is not None:
            (obj_dir / header_name).write_text(model.text)
        (build / "soc_coverage_plan.json").write_bytes(
            json.dumps(candidate_plan, sort_keys=True).encode("utf-8"))
        executable = obj_dir / "Vmyfuzz_live_tb"
        ports = tuple(("__vi_coverage", bit) for bit in _observed_bits(candidate_plan))
        return executable, ports, ports
    return compile_plan


def _run_builder(build: Path, plan, universe, models, limit=6, **kwargs):
    calls: list[list[int]] = []
    return _plan_observations_with_elaboration_probe(
        build=build, plan_document=plan, universe=universe, bits=list(BITS),
        limit=limit, compile_plan=_compile_callback(build, models, calls, **kwargs),
        cell_id="synthetic-cell", stage="profile"), calls


def test_builder_rebuilds_the_harness_once_after_dropping_dead_scopes(tmp_path) -> None:
    build = tmp_path / "build"
    universe, plan = _plan()
    outcome, calls = _run_builder(build, plan, universe, [LIVE_MODEL, LIVE_MODEL])

    assert calls == [[0, 1, 2, 200, 201, 202], [100, 101, 102, 200, 201, 202]]
    assert _observed_bits(outcome["plan"]) == [100, 101, 102, 200, 201, 202]
    assert outcome["elaboration"]["status"] == "replanned"
    # The rebuilt harness is confirmed against the model it produced, so the
    # published artifact can state that every reported point is armed.
    confirmation = outcome["elaboration"]["post_rebuild_confirmation"]
    assert confirmation["observations"] == 6
    assert confirmation["elaborated"] == 6
    assert confirmation["unelaborated_scope"] == 0
    assert confirmation["model"]["present"] is True
    # The published plan is the re-planned one, with the exclusions recorded.
    saved = json.loads((build / "soc_coverage_plan.json").read_text())
    assert _observed_bits(saved) == [100, 101, 102, 200, 201, 202]
    assert len(saved["elaboration"]["excluded"]) == 3
    assert outcome["branch_ports"] == outcome["coverage_ports"]


def test_builder_compiles_once_when_everything_elaborates(tmp_path) -> None:
    build = tmp_path / "build"
    universe, plan = _plan()
    fully = _model(DEAD_LOCKSTEP, DEAD_TRVK, ALIVE_IF, ALIVE_ID, IP_RX, IP_GPIO)
    outcome, calls = _run_builder(build, plan, universe, [fully])

    assert calls == [[0, 1, 2, 200, 201, 202]]
    assert _observed_bits(outcome["plan"]) == [0, 1, 2, 200, 201, 202]
    assert outcome["elaboration"]["status"] == "verified"
    assert "post_rebuild_confirmation" not in outcome["elaboration"]


def test_builder_refuses_when_the_probe_cannot_read_the_model(tmp_path) -> None:
    build = tmp_path / "build"
    universe, plan = _plan()
    absent = CompiledModel.unavailable("compiled-model-header-missing")
    with pytest.raises(SocBuildError) as error:
        _run_builder(build, plan, universe, [absent])
    message = str(error.value)
    assert "profile-coverage-elaboration-probe-failed" in message
    assert "compiled-model-header-missing" in message


def test_builder_refuses_when_the_model_header_cannot_be_parsed(tmp_path) -> None:
    """An empty header is not a readable model, so the build refuses by name."""
    build = tmp_path / "build"
    universe, plan = _plan()
    with pytest.raises(SocBuildError) as error:
        _run_builder(build, plan, universe, [CompiledModel.of_text("")])
    assert "compiled-model-header-empty" in str(error.value)


def test_builder_refuses_when_the_rebuilt_model_still_lacks_a_scope(tmp_path) -> None:
    """A compile that produced something else entirely must not be published."""
    build = tmp_path / "build"
    universe, plan = _plan()
    # First compile: the real model.  Second compile: a model that lost the live
    # core, which the re-plan had just started observing.
    broken = _model(IP_RX, IP_GPIO)
    with pytest.raises(SocBuildError) as error:
        _run_builder(build, plan, universe, [LIVE_MODEL, broken])
    assert "rebuild-still-binds-unelaborated-scope" in str(error.value)


# ---------------------------------------------------------------------------
# the read-only diagnosis and gate learn about the recorded probe
# ---------------------------------------------------------------------------

def _require(run: Path) -> Path:
    if not (run / "report.json").is_file():
        pytest.skip(f"saved run absent: {run}")
    if not (run / "build" / "obj_dir").is_dir():
        pytest.skip(f"compiled model absent: {run}")
    return run


def test_real_run_replans_the_cpu_quota_onto_elaborated_bits() -> None:
    """The exact effect of the fix on the frozen real cell, read-only.

    The saved run carries the pre-fix plan, the instrumenter's own bit map, and
    the model header Verilator produced.  Probing that header and re-planning
    must move the 64-slot CPU quota off the two generate-disabled subtrees and
    onto the lowest CPU bits whose instance scope the model really contains,
    while leaving the IP quota alone.  No RTL is compiled or run here: the model
    header is the one the original run already compiled.

    The measured shape of this cell (pinned below) is why the probe is the
    conservative one: Verilator emits a named scope for the live CSR/counter
    instances but *flattens* smaller ones (``register_file_i``, ``pmp_i``,
    ``if_stage_i``, ...), so their counters are real but not provable by scope
    presence alone.  Of 3926 instrumented points, 1916 have a scope in the
    model and 1295 of those are CPU points.  The fix never observes an unproven
    point; it makes no claim about the flattened ones.
    """
    run = _require(BEST_RUN)
    build = run / "build"
    plan = json.loads((build / "soc_coverage_plan.json").read_text())
    universe = json.loads((build / "soc_coverage_universe.json").read_text())
    bits = json.loads((build / "instrumentation" / "instrumented"
                       / "instrumentation.json").read_text())["coverage_bits"]
    model = read_compiled_model(build)
    assert model.present

    # The pre-fix plan spends the whole CPU quota in the dead window.
    dead_cpu_bits = [int(row["bit"]) for row in plan["observed"]
                     if row["category"] == "cpu"]
    assert dead_cpu_bits[0] == 621 and dead_cpu_bits[-1] == 684
    ip_bits = sorted(int(row["bit"]) for row in plan["observed"]
                     if row["category"] == "ip")
    # The probe's own population on this cell, re-derived independently here.
    present = [entry for entry in bits
               if verilated_scope_chain(str(entry["instance_path"])) in model.text]
    present_cpu = [entry for entry in present
                   if str(entry["instance_path"]).startswith(
                       "myfuzz_soc_top/u_cpu0")]
    assert len(present) == 1916
    assert len(present_cpu) == 1295
    present_cpu_bits = sorted(int(entry["bit"]) for entry in present_cpu)
    assert present_cpu_bits[0] == 2289

    outcome = replan_observations(plan=plan, universe=universe, bits=bits,
                                  limit=128, model=model)

    assert outcome["changed"] is True
    final = outcome["plan"]
    cpu_bits = sorted(int(row["bit"]) for row in final["observed"]
                      if row["category"] == "cpu")
    # The CPU quota now reads proven-scope CPU points only: exactly the lowest
    # 64 of them, so the quota starts at the first CPU point the model emits.
    assert len(cpu_bits) == 64
    assert cpu_bits == present_cpu_bits[:64]
    assert sorted(int(row["bit"]) for row in final["observed"]
                  if row["category"] == "ip") == ip_bits
    assert {str(row["instance_id"]) for row in final["observed"]
            if row["category"] == "cpu"} == {
        "myfuzz_soc_top/u_cpu0/u_ibex_core/cs_registers_i/mcycle_counter_i",
        "myfuzz_soc_top/u_cpu0/u_ibex_core/cs_registers_i/minstret_counter_i",
        "myfuzz_soc_top/u_cpu0/u_ibex_core/cs_registers_i/u_cpuctrlsts_part_csr",
        "myfuzz_soc_top/u_cpu0/u_ibex_core/cs_registers_i/u_dcsr_csr",
        "myfuzz_soc_top/u_cpu0/u_ibex_core/cs_registers_i/u_depc_csr",
        "myfuzz_soc_top/u_cpu0/u_ibex_core/cs_registers_i/u_dscratch0_csr",
        "myfuzz_soc_top/u_cpu0/u_ibex_core/cs_registers_i/u_dscratch1_csr",
        "myfuzz_soc_top/u_cpu0/u_ibex_core/cs_registers_i/u_mcause_csr",
        "myfuzz_soc_top/u_cpu0/u_ibex_core/cs_registers_i/u_mcounteren_csr",
        "myfuzz_soc_top/u_cpu0/u_ibex_core/cs_registers_i/u_mstack_cause_csr",
        "myfuzz_soc_top/u_cpu0/u_ibex_core/cs_registers_i/u_mstack_csr",
        "myfuzz_soc_top/u_cpu0/u_ibex_core/cs_registers_i/u_mstack_epc_csr",
        "myfuzz_soc_top/u_cpu0/u_ibex_core/cs_registers_i/u_mtval_csr",
        "myfuzz_soc_top/u_cpu0/u_ibex_core/cs_registers_i/u_mtvec_csr"}
    counts = outcome["elaboration"]["counts"]
    # Refuting every absent instance the quota walks into took 16 rounds on this
    # cell; the final 128 points are all proven elaborated.
    assert len(outcome["elaboration"]["rounds"]) == 16
    assert outcome["elaboration"]["rounds"][-1]["unelaborated_scope"] == 0
    assert counts["unelaborated_scope"] > 0
    assert counts["elaboration_unknown"] == 0
    assert counts["observed_points"] == 128
    assert counts["elaborated"] == 128
    assert int(final["unobserved_count"]) == len(bits) - 128
    instances = outcome["elaboration"]["excluded_instances"]
    # The two generate-disabled subtrees are named, and every excluded instance
    # is genuinely absent from the model.
    assert "myfuzz_soc_top/u_cpu0/i_ibex_trvk" in instances
    assert "myfuzz_soc_top/u_cpu0/u_ibex_lockstep" in instances
    for name in instances:
        assert verilated_scope_chain(name) not in model.text
    assert all(row["classification"] == CLASS_ELABORATED
               for row in outcome["elaboration"]["observations"])
    # Every reported point is independently re-proven by this test.
    for row in final["observed"]:
        assert verilated_scope_chain(str(row["instance_id"])) in model.text


def test_saved_plans_from_before_the_fix_carry_no_probe_record() -> None:
    run = _require(CPU_RETIRING_RUN)
    document = diagnose_run(run)
    assert document["recorded_elaboration"] is None


def test_gate_fails_a_run_whose_plan_records_no_elaboration_probe() -> None:
    """The gate re-derives its verdict instead of trusting the run's own claims,
    but it still requires the run to *state* what it excluded and why."""
    run = _require(CPU_RETIRING_RUN)
    code, checks, _document = _verdict(run, minimum_cpu_points=1)
    by_name = {check["criterion"]: check["passed"] for check in checks}
    assert by_name["elaboration-attested"] is False
    assert by_name["exclusions-reported"] is False
    # The CPU quota is still spent on unelaborated instances, so the verdict
    # stays BLOCKED rather than FAIL.
    assert code == EXIT_BLOCKED


def _attested_run(directory: Path) -> tuple[Path, dict]:
    """A synthetic run directory that records a real probe outcome.

    The plan is the production one, re-planned by the probe against the model
    header sitting next to it; the manifest is the instrumenter's own bit map.
    No report.json is written: only the two criteria under test are exercised.
    """
    run = directory / "run"
    build = run / "build"
    obj_dir = build / "obj_dir"
    obj_dir.mkdir(parents=True)
    (obj_dir / "Vmyfuzz_live_tb___024root.h").write_text(
        LIVE_MODEL.text or "", encoding="utf-8")
    universe, plan = _plan()
    outcome = replan_observations(plan=plan, universe=universe, bits=list(BITS),
                                  limit=6, model=LIVE_MODEL)
    final = outcome["plan"]
    (build / "soc_coverage_plan.json").write_text(
        json.dumps(final, sort_keys=True), encoding="utf-8")
    instrumented = build / "instrumentation" / "instrumented"
    instrumented.mkdir(parents=True)
    (instrumented / "instrumentation.json").write_text(
        json.dumps({"coverage_bits": list(BITS)}), encoding="utf-8")
    document = {
        "counts": {"points": len(final["observed"])},
        "compiled_model": read_compiled_model(build).document(),
        "recorded_elaboration": final["elaboration"],
    }
    return run, document


def test_gate_accepts_a_run_that_records_the_probe_and_its_exclusions(tmp_path) -> None:
    from scripts.run_p4_cpu_side_branch_gate import _elaboration_checks

    run, document = _attested_run(tmp_path)
    attested, reported, detail = _elaboration_checks(run, document)
    assert attested is True, detail
    assert reported is True, detail
    assert "replanned" in detail


def test_gate_rejects_a_record_that_does_not_match_the_model_on_disk(tmp_path) -> None:
    from scripts.run_p4_cpu_side_branch_gate import _elaboration_checks

    run, document = _attested_run(tmp_path)
    document["recorded_elaboration"]["model"]["sha256"] = "0" * 64
    attested, reported, _detail = _elaboration_checks(run, document)
    assert attested is False
    assert reported is True


def test_gate_rejects_an_exclusion_without_a_classification_or_reason(tmp_path) -> None:
    from scripts.run_p4_cpu_side_branch_gate import _elaboration_checks

    run, document = _attested_run(tmp_path)
    document["recorded_elaboration"]["excluded"][0]["reason"] = ""
    attested, reported, _detail = _elaboration_checks(run, document)
    assert attested is True
    assert reported is False


def test_gate_rejects_excluded_candidate_counts_that_disagree_with_the_manifest(
        tmp_path) -> None:
    from scripts.run_p4_cpu_side_branch_gate import _elaboration_checks

    run, document = _attested_run(tmp_path)
    document["recorded_elaboration"]["excluded_instances"][DEAD_TRVK][
        "candidate_bits"] = 99
    _attested, reported, _detail = _elaboration_checks(run, document)
    assert reported is False
