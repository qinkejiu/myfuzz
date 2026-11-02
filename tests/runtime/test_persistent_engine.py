"""G5: the persistent campaign lifecycle reuses one runner/session set and once only.

Software evidence only.  The fake runtime below is a documented structural
stand-in for an existing ``CompiledF2Runtime``/``CompiledF4Runtime``: its call
counters are real counters of this test, not native PIDs, nonces or tokens, and
nothing here certifies hardware.
"""
from __future__ import annotations

import unittest

from myfuzz.runtime.campaign import (
    CampaignBudget,
    plan_path_flows,
    run_directed_campaign,
)
from myfuzz.runtime.contracts import GenericRuntimeRefused
from myfuzz.runtime.engine import (
    LIFECYCLE_STATES,
    TRANSITIONS,
    PersistentCampaignRuntime,
)
from myfuzz.runtime.flows.storage import (
    StorageFlowBackend,
    StorageFlowChannel,
    StorageFlowKernel,
)
from myfuzz.scenario.ledger import TransactionKey

from tests.runtime.test_storage_kernel import (
    FakeHarnessSession,
    FakeMemory,
    FakeRunner,
    FakeScenarioSession,
    EventLog,
    campaign_world,
    directed_case,
    directed_sequence,
    execution_plan,
    f4_certificate,
    plan_shaped_path,
    raw_path,
)

REGISTER = "TIMER0_CTRL"


class FakePersistentRuntime:
    """Case channel over one fake runner/session/memory set.

    ``submit`` is the fake counterpart of the existing persistent runtimes'
    ``submit(raw) -> certificate`` loop.  It clears only the *case-local*
    scoreboard and keeps the cross-case register file, exactly as the real
    session does, so a per-case reset by the campaign would be visible.
    """

    def __init__(self, runner, session, *, fail_at=None):
        self.runner = runner
        self.session = session
        self.log = runner.log
        self.fail_at = fail_at
        self.records = []
        self.values = []
        self.submit_calls = 0
        self.finish_calls = 0
        self.construction_calls = 1
        self.resets = 0
        self.finished = False
        self.first_fetch = {"address": 0x80000000, "event_id": 1}
        self.execution_binding = {"execution_binding_sha256": "f" * 64}
        self.authority = object()
        self.registers = {}
        self.scoreboard = {}
        self.runner_ids = []
        self.session_ids = []
        self.memory_ids = []

    def submit(self, raw):
        self.submit_calls += 1
        self.runner_ids.append(id(self.runner))
        self.session_ids.append(id(self.session))
        self.memory_ids.append(id(self.runner.sessions["cpu0"].memory))
        if self.fail_at is not None and self.submit_calls == self.fail_at:
            self.runner.sessions["timer0"].service.ledger.pending_keys.append(
                TransactionKey("campaign-1", f"case-{self.submit_calls}",
                               "cpu0", 0, "timer0.TIMER0_CTRL.CTRL", 1))
            raise RuntimeError(
                "simulated mid-case disconnect after source acceptance")
        value = int.from_bytes(raw, "little") & 0xffffffff
        case_id = f"case-{self.submit_calls}"
        self.scoreboard.clear()  # case-local: the register file must survive
        self.scoreboard[case_id] = value
        previous = self.registers.get(REGISTER)
        self.registers[REGISTER] = value
        certificate = f4_certificate(
            self.log, case_id=case_id, value=value,
            extra={"observed_previous": previous,
                   "case_local_entries": len(self.scoreboard)})
        self.records.append({"raw": raw.hex(), "value": value,
                             "certificate": certificate})
        self.values.append(value)
        return certificate

    def finish(self):
        self.finish_calls += 1
        self.finished = True
        return {"schema_version": "fake_prefix.v1",
                "records": list(self.records)}

    def replay(self, plan, *, audit_sink=None):
        raise ValueError("fake-replay-not-supported")

    def feedback(self):
        return {"cases": len(self.records),
                "distinct_values": len(set(self.values))}

    def execution_audit(self):
        return {"exits": {name: {"returncode": 0}
                          for name in self.runner.sessions}}


class NoOpenBackend(StorageFlowBackend):
    """Backend that must never be opened when a static refusal already fired."""

    def open(self):
        raise AssertionError(
            "the backend must not construct/adopt a runtime before the "
            "directed sequence passed its static refusals")


class RepeatedBeginChannel(StorageFlowChannel):
    """Structural channel that reports a second begin (a real drift signal)."""

    def counters(self):
        counters = super().counters()
        counters["begin"] = 2
        return counters


def _world(flow_id="F4", *, fail_at=None):
    bound, runner, log, plan_path = campaign_world(flow_id)
    runtime = FakePersistentRuntime(runner, FakeScenarioSession(),
                                    fail_at=fail_at)
    return bound, runner, plan_path, runtime


def _engine(bound, plan_path, runtime, *, flow_id="F4", max_cases=8,
            max_wall_seconds=None, clock=None, channel=None):
    backend = StorageFlowBackend(runtime=runtime, flow_id=flow_id)
    channel = channel if channel is not None else backend.open()
    return PersistentCampaignRuntime(
        bound, kernel=StorageFlowKernel(), channel=channel,
        path_id=plan_path["path_id"], run_id="campaign",
        max_cases=max_cases, max_wall_seconds=max_wall_seconds,
        **({} if clock is None else {"clock": clock}))


def raw_of(value):
    """The flow's unchanged wire record: a little-endian 32-bit word."""
    return value.to_bytes(4, "little").hex()


CASES = (
    directed_case("case-a", records=(raw_of(0x11),)),
    directed_case("case-b", records=(raw_of(0x22),)),
    directed_case("case-c", records=(raw_of(0x33),)),
)


class LifecycleTests(unittest.TestCase):
    def test_lifecycle_table_is_explicit(self):
        self.assertEqual(("CREATED", "PREPARED", "RUNNING", "QUIESCING",
                          "CLOSED", "FAULTED"), LIFECYCLE_STATES)
        self.assertEqual(("PREPARED", "CLOSED"), TRANSITIONS["CREATED"])
        self.assertEqual(("QUIESCING", "FAULTED"), TRANSITIONS["RUNNING"])
        self.assertEqual(("CLOSED", "FAULTED"), TRANSITIONS["QUIESCING"])
        self.assertNotIn("RUNNING", TRANSITIONS["FAULTED"])
        self.assertEqual((), TRANSITIONS["CLOSED"])

    def test_initialization_happens_exactly_once_and_cases_reuse_objects(self):
        bound, runner, plan_path, runtime = _world()
        engine = _engine(bound, plan_path, runtime)
        engine.start()
        self.assertEqual("RUNNING", engine.state)
        self.assertEqual({"build": 1, "start": 1, "begin": 1, "init": 1},
                         engine.counts)
        for case in CASES:
            engine.submit(case)
        report = engine.finish()
        self.assertEqual("CLOSED", engine.state)
        self.assertEqual(1, runtime.construction_calls)
        self.assertEqual(3, runtime.submit_calls)
        self.assertEqual(1, runtime.finish_calls)
        self.assertEqual(1, len(set(runtime.runner_ids)))
        self.assertEqual(1, len(set(runtime.session_ids)))
        self.assertEqual(1, len(set(runtime.memory_ids)))
        identities = {row["process_identity_sha256"] for row in report["cases"]}
        self.assertEqual(1, len(identities))
        self.assertEqual(set(runner.sessions), set(report["process_identities"]))
        self.assertEqual(3, report["existing_runtime_submissions"])
        self.assertEqual(3, len(report["cases"]))
        self.assertTrue(all(row["status"] == "effective"
                            for row in report["cases"]))
        self.assertEqual(6, report["evidence_count"])  # one case, two records
        self.assertEqual(6, len(report["evidence"]))
        self.assertGreaterEqual(bound.assert_calls, 1 + 2 * 3)

    def test_a_case_with_two_records_submits_both_in_order(self):
        bound, _, plan_path, runtime = _world()
        engine = _engine(bound, plan_path, runtime)
        engine.start()
        case = directed_case("case-pair",
                             records=(raw_of(0x44), raw_of(0x55)))
        record = engine.submit(case)
        self.assertEqual(["44000000", "55000000"],
                         record["raw_records_hex"])
        self.assertEqual(2, len(record["records"]))
        self.assertEqual([0, 1], [row["raw_index"] for row in record["records"]])
        self.assertEqual(2, runtime.submit_calls)
        self.assertEqual([0x44, 0x55], runtime.values)
        engine.finish()

    def test_second_start_is_refused(self):
        bound, _, plan_path, runtime = _world()
        engine = _engine(bound, plan_path, runtime)
        engine.start()
        with self.assertRaises(GenericRuntimeRefused) as raised:
            engine.start()
        self.assertEqual("generic-lifecycle-refused", raised.exception.code)
        self.assertEqual(1, runtime.construction_calls)

    def test_repeated_begin_count_is_refused(self):
        bound, _, plan_path, runtime = _world()
        engine = PersistentCampaignRuntime(
            bound, kernel=StorageFlowKernel(),
            channel=RepeatedBeginChannel(runtime, flow_id="F4"),
            path_id=plan_path["path_id"])
        with self.assertRaises(GenericRuntimeRefused) as raised:
            engine.start()
        self.assertEqual("generic-binding-drift", raised.exception.code)
        self.assertEqual("CLOSED", engine.state)
        self.assertEqual(0, engine.counts["begin"])
        self.assertTrue(engine.faults)
        self.assertEqual(0, runtime.submit_calls)

    def test_illegal_transitions_are_refused(self):
        bound, _, plan_path, runtime = _world()
        engine = _engine(bound, plan_path, runtime)
        for operation in (lambda: engine.submit(CASES[0]),
                          lambda: engine.finish()):
            with self.assertRaises(GenericRuntimeRefused) as raised:
                operation()
            self.assertEqual("generic-lifecycle-refused",
                             raised.exception.code)
        engine.start()
        with self.assertRaises(GenericRuntimeRefused) as raised:
            engine.close()
        self.assertEqual("generic-lifecycle-refused", raised.exception.code)
        engine.submit(CASES[0])
        engine.finish()
        with self.assertRaises(GenericRuntimeRefused) as raised:
            engine.submit(CASES[1])
        self.assertEqual("generic-lifecycle-refused", raised.exception.code)
        with self.assertRaises(GenericRuntimeRefused) as raised:
            engine.finish()
        self.assertEqual("generic-lifecycle-refused", raised.exception.code)
        engine.close()  # idempotent after CLOSED

    def test_abort_from_prepared_closes_without_effect(self):
        bound, _, plan_path, runtime = _world()
        engine = _engine(bound, plan_path, runtime)
        engine.prepare()
        report = engine.abort("operator-stop")
        self.assertEqual("CLOSED", engine.state)
        self.assertEqual("operator-stop", report["aborted"])
        self.assertEqual(0, runtime.submit_calls)
        self.assertEqual(0, runtime.finish_calls)

    def test_prepare_refusal_keeps_created_state(self):
        bound, _, _, runtime = _world()
        engine = PersistentCampaignRuntime(
            bound, kernel=StorageFlowKernel(), channel=StorageFlowBackend(
                runtime=runtime, flow_id="F4").open(), path_id="F4:not-there")
        with self.assertRaises(GenericRuntimeRefused) as raised:
            engine.start()
        self.assertEqual("generic-plan-mismatch", raised.exception.code)
        self.assertEqual("CREATED", engine.state)
        self.assertEqual(1, len(engine.refusals))
        self.assertFalse(engine.refusals[0]["effect"])

    def test_context_manager_aborts_an_active_run(self):
        bound, _, plan_path, runtime = _world()
        with self.assertRaises(RuntimeError):
            with _engine(bound, plan_path, runtime) as engine:
                engine.start()
                raise RuntimeError("boom")
        self.assertEqual("CLOSED", engine.state)
        self.assertEqual("context-exit-with-error", engine.aborted)


class PersistenceTests(unittest.TestCase):
    def test_case_local_scoreboard_reset_keeps_cross_case_state(self):
        bound, runner, plan_path, runtime = _world()
        engine = _engine(bound, plan_path, runtime)
        engine.start()
        for case in CASES:
            engine.submit(case)
        report = engine.finish()
        self.assertEqual(0, runtime.resets)
        self.assertFalse(hasattr(engine, "reset"))
        entries = [row["records"][0]["certificate"]["case_local_entries"]
                   for row in report["cases"]]
        self.assertEqual([1, 1, 1], entries)
        previous = [row["records"][0]["certificate"]["observed_previous"]
                    for row in report["cases"]]
        self.assertEqual([None, 0x11, 0x22], previous)
        self.assertEqual(0x33, runtime.registers[REGISTER])
        self.assertEqual([0x11, 0x22, 0x33], runtime.values)
        self.assertEqual({"cases": 3, "distinct_values": 3},
                         report["existing_runtime_feedback"])

    def test_fault_keeps_effective_records_and_pending_keys(self):
        bound, _, plan_path, runtime = _world(fail_at=2)
        engine = _engine(bound, plan_path, runtime)
        engine.start()
        engine.submit(CASES[0])
        with self.assertRaises(RuntimeError):
            engine.submit(CASES[1])
        self.assertEqual("FAULTED", engine.state)
        self.assertEqual(2, len(engine.cases))
        self.assertEqual("effective", engine.cases[0]["status"])
        self.assertEqual("uncertain", engine.cases[1]["status"])
        self.assertTrue(engine.cases[1]["uncertain"]["effect_possible"])
        self.assertFalse(engine.cases[1]["uncertain"]["retried"])
        self.assertTrue(engine.pending)
        self.assertIn("pending_keys", {row["kind"] for row in engine.pending})
        report = engine.abort("mid-run-disconnect")
        self.assertEqual("CLOSED", engine.state)
        self.assertEqual(2, len(report["cases"]))
        self.assertEqual("effective", report["cases"][0]["status"])
        self.assertTrue(report["pending"])
        self.assertEqual("mid-run-disconnect", report["aborted"])
        self.assertIn("timer0", report["terminal_records"])
        self.assertEqual(1, runtime.finish_calls)

    def test_runner_replacement_faults_before_the_next_effect(self):
        bound, runner, plan_path, runtime = _world()
        engine = _engine(bound, plan_path, runtime)
        engine.start()
        engine.submit(CASES[0])
        runtime.runner = FakeRunner(runner.sessions)
        with self.assertRaises(GenericRuntimeRefused) as raised:
            engine.submit(CASES[1])
        self.assertEqual("generic-binding-drift", raised.exception.code)
        self.assertEqual("FAULTED", engine.state)
        self.assertEqual(1, runtime.submit_calls)

    def test_process_identity_change_faults(self):
        bound, runner, plan_path, runtime = _world()
        engine = _engine(bound, plan_path, runtime)
        engine.start()
        engine.submit(CASES[0])
        runner.sessions["timer0"].process = FakeHarnessSession(
            "timer0", 9999).process
        with self.assertRaises(GenericRuntimeRefused) as raised:
            engine.submit(CASES[1])
        self.assertEqual("generic-binding-drift", raised.exception.code)
        self.assertIn("process-identity-changed-after-begin",
                      str(raised.exception.detail))
        self.assertEqual("FAULTED", engine.state)

    def test_bound_authority_drift_faults_without_effect(self):
        bound, _, plan_path, runtime = _world()
        bound.fail_after = 2  # prepare + start assertions pass, case one fails
        engine = _engine(bound, plan_path, runtime)
        engine.start()
        with self.assertRaises(GenericRuntimeRefused) as raised:
            engine.submit(CASES[0])
        self.assertEqual("generic-binding-drift", raised.exception.code)
        self.assertEqual("FAULTED", engine.state)
        self.assertEqual(0, runtime.submit_calls)
        self.assertEqual(0, len(engine.cases))

    def test_wall_clock_budget_refusal_keeps_run_alive(self):
        bound, _, plan_path, runtime = _world()
        ticks = iter(range(100000))
        engine = _engine(bound, plan_path, runtime, max_wall_seconds=1,
                         clock=lambda: next(ticks) * 10)
        engine.start()
        with self.assertRaises(GenericRuntimeRefused) as raised:
            engine.submit(CASES[0])
        self.assertEqual("generic-budget-refused", raised.exception.code)
        self.assertIn("/max_wall_seconds", raised.exception.pointer)
        self.assertEqual("RUNNING", engine.state)
        self.assertEqual(0, runtime.submit_calls)
        self.assertEqual(1, len(engine.refusals))
        self.assertFalse(engine.refusals[0]["effect"])

    def test_case_budget_refusal_keeps_run_alive(self):
        bound, _, plan_path, runtime = _world()
        engine = _engine(bound, plan_path, runtime, max_cases=1)
        engine.start()
        engine.submit(CASES[0])
        with self.assertRaises(GenericRuntimeRefused) as raised:
            engine.submit(CASES[1])
        self.assertEqual("generic-budget-refused", raised.exception.code)
        self.assertEqual("RUNNING", engine.state)
        report = engine.finish()
        self.assertEqual(1, len(report["cases"]))
        self.assertEqual(1, len(report["refusals"]))
        self.assertEqual(1, runtime.submit_calls)

    def test_terminal_records_cover_every_started_child(self):
        bound, runner, plan_path, runtime = _world()
        engine = _engine(bound, plan_path, runtime)
        engine.start()
        engine.submit(CASES[0])
        report = engine.finish()
        self.assertEqual(set(runner.sessions), set(report["terminal_records"]))
        for name, row in report["terminal_records"].items():
            self.assertEqual("exited", row["terminal"])
            self.assertEqual(0, row["returncode"])
            self.assertEqual("existing-execution-audit", row["basis"])
        counts = len(report["terminal_records"])
        self.assertEqual(2, counts)

    def test_report_never_claims_native_certification(self):
        bound, _, plan_path, runtime = _world()
        engine = _engine(bound, plan_path, runtime)
        engine.start()
        engine.submit(CASES[0])
        report = engine.finish()
        self.assertFalse(report["native_certification"]["claimed"])
        self.assertIn("G6", report["native_certification"]["reason"])
        self.assertEqual(2, report["evidence_count"])
        first = report["evidence"][0]
        self.assertEqual("certified", first["status"])
        self.assertEqual("f" * 64, first["binding_sha256"])


class DirectedCampaignTests(unittest.TestCase):
    def test_directed_campaign_runs_the_sequence_and_records_every_case(self):
        bound, runner, log, plan_path = campaign_world("F4")
        runtime = FakePersistentRuntime(runner, FakeScenarioSession())
        backend = StorageFlowBackend(runtime=runtime, flow_id="F4")
        sequence = directed_sequence(*CASES, plan_sha256=bound.plan_sha256)
        report = run_directed_campaign(
            bound_plan=bound, backend=backend, sequence=sequence,
            budget=CampaignBudget(max_cases=4))
        self.assertEqual("CLOSED", report["state"])
        self.assertEqual("F4", report["flow_id"])
        self.assertEqual(3, report["sequence_case_count"])
        self.assertEqual(3, len(report["directed_cases"]))
        self.assertEqual(3, len(report["cases"]))
        self.assertIsNone(report["software_only"])
        self.assertEqual({"build": 1, "start": 1, "begin": 1, "init": 1},
                         report["initialization_counts"])
        self.assertEqual(3, runtime.submit_calls)
        limitations = " ".join(report["known_limitations"])
        self.assertIn("generic-flow-mixed-unsupported", limitations)
        self.assertNotIn("no campaign is wired", limitations)
        self.assertFalse(report["native_certification"]["claimed"])

    def test_mixed_sequence_is_refused_before_construction(self):
        plan_f4 = plan_shaped_path(raw_path("F4"))
        plan_f2 = plan_shaped_path(raw_path("F2"))
        log = EventLog()
        runner = FakeRunner({"cpu0": FakeHarnessSession("cpu0", 21),
                             "timer0": FakeHarnessSession("timer0", 22,
                                                          FakeMemory(2))},
                            log)
        plan = execution_plan([plan_f4, plan_f2])
        bound = type("Bound", (), {})()
        bound.plan = plan
        bound.plan_sha256 = plan.identity_sha256
        bound.runner = runner
        bound.sessions = dict(runner.sessions)
        bound.prepared_paths = {}
        bound.adapters = ()
        bound.assert_calls = 0
        bound.assert_current = lambda: None
        bound.documentary = lambda: {"plan_sha256": plan.identity_sha256}
        bound.close = lambda: None
        runtime = FakePersistentRuntime(runner, FakeScenarioSession())
        backend = NoOpenBackend(runtime=runtime, flow_id="F4")
        sequence = directed_sequence(
            directed_case("case-a", path_id="F4:timer0",
                          records=(raw_of(0x11),)),
            directed_case("case-b", path_id="F2:timer0",
                          source_id="timer0.TIMER0_CTRL.CTRL.address",
                          records=(raw_of(0x22),)),
            plan_sha256=plan.identity_sha256)
        with self.assertRaises(GenericRuntimeRefused) as raised:
            run_directed_campaign(bound_plan=bound, backend=backend,
                                  sequence=sequence)
        self.assertEqual("generic-flow-mixed-unsupported",
                         raised.exception.code)
        self.assertEqual(0, runtime.submit_calls)
        self.assertEqual(0, runtime.finish_calls)

    def test_unbound_source_is_refused_before_any_construction(self):
        bound, runner, log, plan_path = campaign_world("F4")
        runtime = FakePersistentRuntime(runner, FakeScenarioSession())
        backend = NoOpenBackend(runtime=runtime, flow_id="F4")
        sequence = directed_sequence(
            directed_case("case-a", source_id="timer0.NOT_DECLARED.value"),
            plan_sha256=bound.plan_sha256)
        with self.assertRaises(GenericRuntimeRefused) as raised:
            run_directed_campaign(bound_plan=bound, backend=backend,
                                  sequence=sequence)
        self.assertEqual("generic-source-unverified", raised.exception.code)
        self.assertEqual(0, runtime.submit_calls)
        self.assertEqual(0, runtime.finish_calls)

    def test_sequence_for_another_flow_than_the_campaign_is_refused(self):
        bound, runner, log, plan_path = campaign_world("F4")
        runtime = FakePersistentRuntime(runner, FakeScenarioSession())
        backend = StorageFlowBackend(runtime=runtime, flow_id="F2")
        sequence = directed_sequence(*CASES, plan_sha256=bound.plan_sha256)
        with self.assertRaises(GenericRuntimeRefused) as raised:
            run_directed_campaign(bound_plan=bound, backend=backend,
                                  sequence=sequence)
        self.assertEqual("generic-plan-mismatch", raised.exception.code)
        self.assertEqual(0, runtime.submit_calls)

    def test_equally_declared_paths_are_listed_from_the_plan(self):
        bound, _, _, plan_path = campaign_world("F4")
        flows = plan_path_flows(bound.plan.document())
        self.assertEqual({"F4:timer0": "F4"}, flows)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
