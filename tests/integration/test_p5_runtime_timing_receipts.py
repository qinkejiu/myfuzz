"""Online receipts expose Runner, Router and scheduler timing separately."""

import json

from tests.integration import test_scenario_rfuzz_terminal_identity as transport_tests


def test_online_receipt_persists_runtime_timing_without_trace_events():
    harness = transport_tests.TerminalIdentityTests(
        methodName="test_online_receipt_journals_case_phase_timings")
    harness.setUp()
    try:
        executor = harness.online()
        harness.run_transport(executor)
        row = json.loads((harness.output / "receipts.jsonl").read_text().splitlines()[0])
        timing = row["online_runner_timing_seconds"]
        assert set(timing) == {
            "scheduler_batch", "runner_step", "router_enqueue",
            "router_drain", "router_transact", "observed_output_route",
        }
        assert all(type(value) is float and value >= 0 for value in timing.values())
        assert timing["scheduler_batch"] > 0
        assert timing["runner_step"] > 0
        assert timing == executor.online_decisions[0]["runner_timing_seconds"]
        assert all("runner_timing_seconds" not in event
                   for event in executor.session.runner.events)
    finally:
        harness.doCleanups()
