import base64
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from myfuzz.builder import (  # noqa: E402
    AdaptiveMutationController, CampaignCheckpointStoreV4,
    ExternalInfrastructureFailureV4, InputValidationError,
    ProjectedTargetServerV4, ProtocolCampaignResultV4, RawBitsV4Lane,
    RawBitsV4Submode, TargetExecutionResultV4, V4Controller, V4TargetServer,
    VariantFeasibilityFailureV4, build_component_coverage_projection_v4,
    build_protocol_only_experiment_manifest_v4, encode_rawbits_v4_testcase,
    project_coverage_bitmap_v4,
    run_legacy_a_protocol_campaign_v4, run_protocol_campaign_v4,
    run_serial_protocol_abcd_v4,
)
from myfuzz.builder.contracts import CoverageABIV2  # noqa: E402
from myfuzz.builder.process_monitor_v4 import TargetProcessTimeoutV4  # noqa: E402
from test_builder_controller_v4 import _layout  # noqa: E402


class ProtocolCampaignV4Test(unittest.TestCase):
    @staticmethod
    def _mutation_diagnostics(completed_count=1):
        controller = AdaptiveMutationController(1)
        for _ in range(completed_count):
            controller.observe_result(0)
        return controller.diagnostics()

    @staticmethod
    def _experiment_manifest():
        abi = CoverageABIV2("a" * 64, "__vi_coverage", 8, 64, tuple(
            {"point_id": f"fixture.{offset}", "component_id": "fixture.ip",
             "included": True, "offset": offset, "source_offset": offset}
            for offset in range(8)
        ))
        return build_protocol_only_experiment_manifest_v4(
            experiment_id="protocol-smoke", seed=1, wall_seconds=1,
            baseline_coverage_abi=abi, generated_coverage_abi=abi,
            baseline_target_digest="a" * 64, generated_target_digest="b" * 64,
            target_peak_rss_bytes=1, min_available_memory_bytes=0,
        )

    def test_wall_clock_runner_reports_lanes_and_resources(self):
        layout = _layout()
        server = V4TargetServer(layout, lambda testcase: bytes((1 << (testcase.logical_testcase_id % 8), 0)))
        controller = V4Controller(layout, policy="C", seed=5, coverage_bits=16)
        now = [0.0]
        def clock():
            value = now[0]
            now[0] += 0.00001
            return value
        result = run_protocol_campaign_v4(
            controller, server, wall_seconds=0.001, max_testcases=10,
            resource_sample_interval_seconds=1e-9, max_resource_samples=1,
            clock=clock,
        )
        self.assertEqual(result.schema, "myfuzz.protocol-campaign-result/v4")
        self.assertEqual(result.testcase_count, 10)
        self.assertEqual(result.completed_count, 10)
        self.assertEqual(result.censored_inflight, 0)
        self.assertEqual(sum(result.lane_counts.values()), 10)
        self.assertIn("available_memory_bytes", result.resource_before)
        self.assertIn("cpu_model", result.resource_before)
        self.assertIn("cpu_affinity", result.resource_before)
        self.assertIn("swap_used_bytes", result.resource_before)
        self.assertIn("child_cpu_time_seconds", result.resource_after)
        self.assertIn("average_cpu_frequency_khz", result.resource_after)
        self.assertIn("maximum_thermal_millicelsius", result.resource_after)
        self.assertIn("throttling_event_count", result.resource_after)
        self.assertEqual(len(result.resource_samples), 1)
        self.assertTrue(result.resource_samples_truncated)
        self.assertIn("elapsed_seconds", result.resource_samples[0])
        self.assertEqual(result.mutation_diagnostics, {})
        self.assertEqual(
            result.controller_manifest["protocol_seed_projection"]["available"],
            False,
        )

    def test_d_result_reports_feedback_state_and_non_d_does_not(self):
        layout = _layout()
        server = V4TargetServer(
            layout,
            lambda testcase: bytes((1 << (testcase.logical_testcase_id % 8),)),
        )
        result = run_protocol_campaign_v4(
            V4Controller(layout, policy="D", seed=5, coverage_bits=8),
            server, wall_seconds=30, max_testcases=5,
        )
        diagnostics = result.mutation_diagnostics
        self.assertEqual(diagnostics["schema"], "myfuzz.adaptive-mutation-diagnostics/v4")
        self.assertEqual(diagnostics["observed_results"], result.completed_count)
        self.assertEqual(sum(diagnostics["level_before_counts"].values()), 5)
        self.assertEqual(
            diagnostics["new_branch_results"] + diagnostics["no_new_branch_results"],
            5,
        )
        self.assertEqual(diagnostics["candidate_results"], 1)
        self.assertEqual(len(result.mutation_reason_trace), 1)
        self.assertEqual(result.mutation_reason_trace[0]["operator"], "seed")
        self.assertIn("old_value", result.mutation_reason_trace[0])
        self.assertIn("new_value", result.mutation_reason_trace[0])

    def test_novelty_evidence_records_only_new_coverage(self):
        layout = _layout()
        server = V4TargetServer(layout, lambda _testcase: b"\x01")
        recorded = []

        def recorder(transport, _execution, controller_result):
            reference = {
                "testcase_id": controller_result.testcase_id,
                "transport_sha256": hashlib.sha256(transport).hexdigest(),
            }
            recorded.append(reference)
            return reference

        result = run_protocol_campaign_v4(
            V4Controller(layout, policy="B", seed=5, coverage_bits=8),
            server, wall_seconds=30, max_testcases=3,
            novelty_evidence_recorder=recorder,
        )
        self.assertEqual(len(recorded), 1)
        self.assertEqual(recorded[0]["testcase_id"], 0)
        self.assertEqual(result.novelty_replay_evidence, tuple(recorded))

    def test_report_separates_declared_lane_from_observed_legality(self):
        layout = _layout()
        rules = {"AW_STABLE_UNTIL_READY": 2, "W_STABLE_UNTIL_READY": 3}

        def execute(testcase):
            rule_id = 2 if testcase.logical_testcase_id < 2 else 3
            return TargetExecutionResultV4(
                b"\x00", "raw", violation_rule=rule_id,
                violation_cycle=testcase.logical_testcase_id + 7,
            )

        result = run_protocol_campaign_v4(
            V4Controller(layout, policy="B", seed=5, coverage_bits=8),
            V4TargetServer(layout, execute, legality_rules=rules),
            wall_seconds=30, max_testcases=3,
        )
        self.assertEqual(result.declared_lane_counts["RAW_ESCAPE"], 3)
        self.assertEqual(sum(result.declared_lane_counts.values()), 3)
        self.assertEqual(result.observed_classification_counts, {"raw": 3})
        self.assertEqual(result.legality_rules, rules)
        self.assertEqual(result.violation_rule_counts, {
            "AW_STABLE_UNTIL_READY": 2,
            "W_STABLE_UNTIL_READY": 1,
        })
        self.assertEqual(len(result.first_violation_points), 2)
        self.assertEqual(result.first_violation_points[0], {
            "testcase_id": 0,
            "declared_lane": "RAW_ESCAPE",
            "observed_classification": "raw",
            "rule_id": 2,
            "rule_name": "AW_STABLE_UNTIL_READY",
            "cycle": 7,
        })

    def test_report_rejects_violation_absent_from_target_evidence(self):
        layout = _layout()
        server = V4TargetServer(
            layout,
            lambda _testcase: TargetExecutionResultV4(
                b"\x00", "raw", violation_rule=9, violation_cycle=1,
            ),
            legality_rules={"AW_STABLE_UNTIL_READY": 2},
        )
        with self.assertRaisesRegex(InputValidationError, "absent from its legality evidence"):
            run_protocol_campaign_v4(
                V4Controller(layout, policy="B", seed=5, coverage_bits=8),
                server, wall_seconds=30, max_testcases=1,
            )

    def test_resume_rejects_legality_rule_table_drift(self):
        layout = _layout()
        first_server = V4TargetServer(
            layout, lambda _testcase: b"\x00",
            legality_rules={"AW_STABLE_UNTIL_READY": 2},
        )
        with tempfile.TemporaryDirectory() as directory:
            store = CampaignCheckpointStoreV4(directory)
            controller = V4Controller(layout, policy="B", seed=5, coverage_bits=8)
            run_protocol_campaign_v4(
                controller, first_server, wall_seconds=30, max_testcases=1,
                decision_checkpoint_store=store,
                decision_checkpoint_interval_testcases=1,
            )
            resumed, progress = store.load_campaign(layout)
            changed_server = V4TargetServer(
                layout, lambda _testcase: b"\x00",
                legality_rules={"W_STABLE_UNTIL_READY": 3},
            )
            with self.assertRaisesRegex(InputValidationError, "resume progress is malformed"):
                run_protocol_campaign_v4(
                    resumed, changed_server, wall_seconds=30, max_testcases=2,
                    resume_progress=progress,
                )

    def test_late_d_completion_does_not_update_feedback_or_drop_prior_result(self):
        layout = _layout()
        controller = V4Controller(layout, policy="D", seed=5, coverage_bits=8)
        server = V4TargetServer(
            layout,
            lambda testcase: TargetExecutionResultV4(
                bytes((1 << (testcase.logical_testcase_id % 8),)),
                "protocol_valid" if testcase.lane == "PROTOCOL_WAVEFORM" else "adversarial",
                dut_cycles=1, logical_records=1, accepted_records=1,
            ),
        )
        now = [0.0]
        timeline = iter((0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 1.1, 1.2, 1.3))
        def clock():
            try:
                now[0] = next(timeline)
            except StopIteration:
                now[0] += 0.1
            return now[0]
        result = run_protocol_campaign_v4(
            controller, server, wall_seconds=1, max_testcases=2, clock=clock,
        )
        self.assertEqual(result.completed_count, 1)
        self.assertEqual(result.censored_inflight, 1)
        self.assertEqual(result.dut_cycles, 1)
        self.assertEqual(result.mutation_diagnostics["observed_results"], 1)
        self.assertEqual(len(controller.results), 1)

    def test_campaign_decision_checkpoint_resumes_exact_next_transport(self):
        layout = _layout()
        server = V4TargetServer(layout, lambda _testcase: b"\x00")
        expected_controller = V4Controller(
            layout, policy="D", seed=47, coverage_bits=8,
        )
        expected = expected_controller.run(
            server.handle_result, testcase_count=10, records_per_testcase=3,
        )
        continuous_result = run_protocol_campaign_v4(
            V4Controller(layout, policy="D", seed=47, coverage_bits=8),
            server, wall_seconds=30, max_testcases=10, records_per_testcase=3,
        )
        with tempfile.TemporaryDirectory() as directory:
            store = CampaignCheckpointStoreV4(directory)
            first = V4Controller(layout, policy="D", seed=47, coverage_bits=8)
            run_protocol_campaign_v4(
                first, server, wall_seconds=30, max_testcases=5,
                records_per_testcase=3, decision_checkpoint_store=store,
                decision_checkpoint_interval_testcases=2,
            )
            resumed, progress = store.load_campaign(layout)
            actual = run_protocol_campaign_v4(
                resumed, server, wall_seconds=30, max_testcases=10,
                records_per_testcase=3,
                resume_progress=progress,
            )
        self.assertEqual(
            [item.transport_sha256 for item in resumed.results],
            [expected[-1].transport_sha256],
        )
        self.assertEqual(actual.completed_count, 10)
        self.assertEqual(actual.testcase_count, 10)
        self.assertEqual(sum(actual.lane_counts.values()), 10)
        self.assertEqual(
            len(actual.mutation_reason_trace),
            sum(item.mutation_operator is not None for item in expected),
        )
        for name in (
            "coverage_digest", "coverage_hits", "lane_counts", "declared_lane_counts",
            "transport_bytes",
            "dut_cycles", "wire_trace_edges", "logical_records", "accepted_records",
            "record_stall_cycles", "observed_classification_counts",
            "violation_rule_counts", "first_violation_points",
            "mutation_reason_trace", "mutation_diagnostics",
        ):
            self.assertEqual(getattr(actual, name), getattr(continuous_result, name), name)

    def test_component_projection_filters_only_coverage_and_preserves_metadata(self):
        points = tuple(
            {
                "point_id": f"fixture.{offset}",
                "component_id": component,
                "included": True,
                "offset": offset,
                "source_offset": offset,
            }
            for offset, component in enumerate(("cpu.main", "ip.ram", "ip.gpio", "cpu.main"))
        )
        abi = CoverageABIV2("a" * 64, "__vi_coverage", 4, 64, points)
        projection = build_component_coverage_projection_v4(abi)
        self.assertEqual(projection.source_offsets, (1, 2))
        self.assertEqual(projection.coverage_abi.width, 2)
        self.assertEqual(project_coverage_bitmap_v4(b"\x06", projection), b"\x03")
        server = ProjectedTargetServerV4(
            V4TargetServer(
                _layout(),
                lambda _testcase: TargetExecutionResultV4(
                    b"\x06", "protocol_valid", dut_cycles=7,
                    logical_records=1, accepted_records=1,
                ),
            ),
            projection,
        )
        transport = encode_rawbits_v4_testcase(
            _layout(), lane=RawBitsV4Lane.PROTOCOL_WAVEFORM,
            submode=RawBitsV4Submode.LITERAL_TRACE,
            logical_testcase_id=0, records=(0,),
        )
        result = server.handle_result(transport)
        self.assertEqual(result.coverage_bitmap, b"\x03")
        self.assertEqual(result.dut_cycles, 7)

    def test_memory_preflight_fails_closed(self):
        layout = _layout()
        controller = V4Controller(layout, policy="B", seed=1, coverage_bits=8)
        server = V4TargetServer(layout, lambda _testcase: b"\x00")
        with self.assertRaises(InputValidationError):
            run_protocol_campaign_v4(
                controller, server, wall_seconds=1, min_available_memory_bytes=10**30,
            )

    def test_target_timeout_is_a_non_retryable_variant_feasibility_failure(self):
        layout = _layout()
        controller = V4Controller(layout, policy="B", seed=1, coverage_bits=8)
        def timeout(_testcase):
            raise TargetProcessTimeoutV4("target guard exhausted")
        server = V4TargetServer(layout, timeout)
        with self.assertRaisesRegex(
            VariantFeasibilityFailureV4, "target guard exhausted",
        ):
            run_protocol_campaign_v4(
                controller, server, wall_seconds=1, max_testcases=1,
            )

    def test_legacy_a_binary_is_wrapped_without_changing_its_fixed_cycle_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "bin").mkdir()
            (target / "evidence").mkdir()
            digest = "a" * 64
            (target / "completion_manifest.json").write_text(json.dumps({
                "runner_schema": "myfuzz.fixed-dut-cycle-runner/v1",
                "target_digest": digest,
            }), encoding="ascii")
            (target / "evidence/bit_layout.json").write_text(json.dumps({
                "bytes_per_cycle": 1, "cycle_width": 8,
            }), encoding="ascii")
            (target / "evidence/coverage_abi.json").write_text(json.dumps({
                "width": 8,
            }), encoding="ascii")
            executable = target / "bin/myfuzz_target"
            executable.write_text(
                "#!/usr/bin/env python3\n"
                "import json, pathlib, sys\n"
                "cycles=int(sys.argv[2]); data=pathlib.Path(sys.argv[1]).read_bytes()\n"
                "coverage=bytes((1 << (sum(data) % 8),))\n"
                "pathlib.Path(sys.argv[4]).write_bytes(coverage)\n"
                "pathlib.Path(sys.argv[5]).write_bytes(coverage*cycles)\n"
                "pathlib.Path(sys.argv[6]).write_text(json.dumps({"
                "'schema':'myfuzz.fixed-dut-cycle-metrics/v1','dut_cycles':cycles,"
                "'accepted_records':cycles,'stall_cycles':0,'unconsumed_records':0}))\n",
                encoding="ascii",
            )
            executable.chmod(0o755)
            result = run_legacy_a_protocol_campaign_v4(
                target, seed=1, wall_seconds=10, cycles_per_testcase=4,
                max_testcases=2,
            )
            self.assertEqual(result.policy, "A")
            self.assertEqual(result.target_digest, digest)
            self.assertEqual(result.testcase_count, 2)
            self.assertEqual(result.completed_count, 2)
            self.assertEqual(result.transport_bytes, 8)
            self.assertEqual(result.dut_cycles, 8)
            self.assertEqual(result.logical_records, 8)
            self.assertEqual(result.accepted_records, 8)
            self.assertEqual(result.record_stall_cycles, 0)
            self.assertGreaterEqual(result.coverage_hits, 1)
            self.assertGreaterEqual(len(result.resource_samples), 1)

    def test_completion_after_deadline_is_censored(self):
        layout = _layout()
        controller = V4Controller(layout, policy="B", seed=1, coverage_bits=8)
        server = V4TargetServer(layout, lambda _testcase: b"\xff")
        now = [0.0]
        def clock():
            value = now[0]
            now[0] += 0.4
            return value
        result = run_protocol_campaign_v4(controller, server, wall_seconds=1, clock=clock)
        self.assertEqual(result.completed_count, 0)
        self.assertEqual(result.censored_inflight, 1)
        self.assertEqual(controller.coverage.snapshot(), b"\x00")

    def test_deadline_after_lane_selection_keeps_campaign_accounting_closed(self):
        layout = _layout()
        controller = V4Controller(layout, policy="C", seed=1, coverage_bits=8)
        server = V4TargetServer(layout, lambda _testcase: b"\xff")
        timeline = iter((0.0, 0.5, 1.0, 1.1, 1.2))

        def clock():
            return next(timeline, 1.2)

        result = run_protocol_campaign_v4(
            controller, server, wall_seconds=1, clock=clock,
        )
        self.assertEqual(result.completed_count, 0)
        self.assertEqual(result.censored_inflight, 1)
        self.assertEqual(result.testcase_count, 1)
        self.assertEqual(sum(result.declared_lane_counts.values()), 1)
        self.assertEqual(controller.coverage.snapshot(), b"\x00")

    def test_serial_abcd_orchestrator_is_fixed_order_and_fail_closed(self):
        manifest = self._experiment_manifest()
        def result(name):
            bitmap = b"\x01"
            return ProtocolCampaignResultV4(
                policy=name, seed=1, wall_seconds=0.1, deadline_reached=True,
                status="completed", testcase_count=1, completed_count=1,
                censored_inflight=0, coverage_bits=8,
                coverage_digest=hashlib.sha256(bitmap).hexdigest(),
                lane_counts={"FIXTURE": 1}, declared_lane_counts={"FIXTURE": 1},
                observed_classification_counts={"raw": 1},
                resource_before={}, resource_after={},
                target_digest=manifest.target_digests[name],
                coverage_bitmap_base64=base64.b64encode(bitmap).decode("ascii"),
                coverage_hits=1,
                coverage_checkpoints=tuple(
                    {"seconds": seconds, "coverage_hits": 1}
                    for seconds in manifest.checkpoint_seconds
                ),
                mutation_diagnostics=(
                    self._mutation_diagnostics() if name == "D" else {}
                ),
            )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            report = run_serial_protocol_abcd_v4(
                {name: (lambda name=name: result(name)) for name in "ABCD"},
                manifest=manifest, output_path=output,
            )
            self.assertEqual(report.status, "valid")
            self.assertEqual(report.order, ("A", "B", "C", "D"))
            self.assertEqual(tuple(report.variants), tuple("ABCD"))
            frozen = json.loads(output.read_text(encoding="ascii"))
            self.assertEqual(frozen["experiment_manifest"]["digest"], manifest.digest)
        with self.assertRaises(InputValidationError):
            run_serial_protocol_abcd_v4(
                {"A": lambda: result("A")}, manifest=manifest,
            )

    def test_variant_feasibility_failure_is_not_reclassified_as_infrastructure(self):
        manifest = self._experiment_manifest()
        def fail():
            raise VariantFeasibilityFailureV4("bounded exploration pool exhausted")
        report = run_serial_protocol_abcd_v4(
            {"A": fail, "B": fail, "C": fail, "D": fail}, manifest=manifest,
        )
        self.assertEqual(report.status, "variant_feasibility_failure")
        self.assertEqual(report.failure_classes["A"], "variant_feasibility_failure")
        self.assertEqual(report.attempt_counts["A"], 1)

    def test_external_infrastructure_failure_is_retried_exactly_once(self):
        manifest = self._experiment_manifest()
        attempts = {name: 0 for name in "ABCD"}
        def runner(name):
            attempts[name] += 1
            if name == "A" and attempts[name] == 1:
                raise ExternalInfrastructureFailureV4("transient host interruption")
            bitmap = b"\x01"
            return ProtocolCampaignResultV4(
                policy=name, seed=1, wall_seconds=0.1, deadline_reached=True,
                status="completed", testcase_count=1, completed_count=1,
                censored_inflight=0, coverage_bits=8,
                coverage_digest=hashlib.sha256(bitmap).hexdigest(),
                lane_counts={"FIXTURE": 1}, declared_lane_counts={"FIXTURE": 1},
                observed_classification_counts={"raw": 1},
                resource_before={}, resource_after={},
                target_digest=manifest.target_digests[name],
                coverage_bitmap_base64=base64.b64encode(bitmap).decode("ascii"),
                coverage_hits=1,
                coverage_checkpoints=tuple(
                    {"seconds": seconds, "coverage_hits": 1}
                    for seconds in manifest.checkpoint_seconds
                ),
                mutation_diagnostics=(
                    self._mutation_diagnostics() if name == "D" else {}
                ),
            )
        report = run_serial_protocol_abcd_v4(
            {name: (lambda name=name: runner(name)) for name in "ABCD"},
            manifest=manifest,
        )
        self.assertEqual(report.status, "valid")
        self.assertEqual(report.attempt_counts, {"A": 2, "B": 1, "C": 1, "D": 1})
        self.assertEqual(report.failure_classes, {})

    def test_checkpoints_exclude_a_testcase_that_completes_after_each_boundary(self):
        layout = _layout()
        server = V4TargetServer(
            layout,
            lambda testcase: bytes((1 << testcase.logical_testcase_id,)),
        )
        controller = V4Controller(layout, policy="B", seed=1, coverage_bits=8)
        now = [0.0]
        def clock():
            value = now[0]
            now[0] += 0.1
            return value
        result = run_protocol_campaign_v4(
            controller, server, wall_seconds=1, max_testcases=2,
            checkpoint_seconds=(0.15, 0.35, 0.8), clock=clock,
        )
        self.assertEqual(result.coverage_hits, 2)
        self.assertEqual(result.coverage_checkpoints, (
            {"seconds": 0.15, "coverage_hits": 0},
            {"seconds": 0.35, "coverage_hits": 1},
            {"seconds": 0.8, "coverage_hits": 2},
        ))


if __name__ == "__main__":
    unittest.main()
