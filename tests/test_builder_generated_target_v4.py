import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from builder_fixtures import system_spec  # noqa: E402
from myfuzz.builder import (  # noqa: E402
    DiscoveryResult, EnvironmentInputRuleV4, GeneratedTargetServerV4,
    InputValidationError, PortDirection,
    ProtocolCampaignResultV4,
    RawBitsV4Lane, RawBitsV4Submode, SocExternalPort, build_environment_plan_v4,
    build_protocol_verilator_target_v4, build_soc_ir_v2,
    WireReplayEvidenceStoreV4, build_wire_replay_bundle_v4,
    emit_protocol_harness_v4, emit_soc_ir_v4, encode_environment_replay_v4,
    encode_rawbits_v4_testcase,
    V4Controller, build_protocol_only_experiment_manifest_v4, plan_system,
    replay_wire_bundle_v4, run_protocol_campaign_v4,
    run_protocol_verilator_target_v4, run_serial_protocol_abcd_v4,
    wire_replay_bundle_v4_from_dict,
)
from myfuzz.builder.contracts import CoverageABIV2, build_elaboration_manifest  # noqa: E402
from test_builder_generated_soc_v2 import AXI, _module  # noqa: E402


def _component_stubs():
    stubs = []
    for name, role in (("cpu_target_v4", "initiator"), ("ip_target_v4", "target")):
        def direction(value):
            if role != "initiator":
                return value
            return PortDirection.OUTPUT if value == PortDirection.INPUT else PortDirection.INPUT

        declarations = ", ".join(
            f"{direction(item_direction).value} logic [{width-1}:0] {physical}"
            if width > 1 else f"{direction(item_direction).value} logic {physical}"
            for physical, item_direction, width in AXI.values()
        )
        stubs.append(f"module {name}({declarations}); endmodule")
    return "\n".join(stubs)


class GeneratedTargetV4Test(unittest.TestCase):
    @staticmethod
    def _fixture(root, *, with_environment=False):
        specs, facts = zip(
            _module("cpu_target_v4", "initiator", "axi_lite"),
            _module("ip_target_v4", "target", "axi_lite", 0x23000000),
        )
        specification = system_spec(list(specs))
        discovery = DiscoveryResult(("/cpu_target_v4.sv", "/ip_target_v4.sv"), facts)
        plan = plan_system(specification, discovery)
        if not plan.valid:
            raise AssertionError(plan.validation_issues)
        ir = build_soc_ir_v2(
            specification, discovery, plan,
            source_digests={"cpu_target_v4": "1" * 64, "ip_target_v4": "2" * 64},
            analysis_manifest_digest="3" * 64,
        )
        soc = emit_soc_ir_v4(ir, module_name="instrumented_target_soc_v4")
        environment_declarations = (
            ",\n  input logic [9:0] stimulus_i,\n  output logic [2:0] status_o"
            if with_environment else ""
        )
        environment_assignments = (
            "\n  assign status_o=stimulus_i[2:0];"
            if with_environment else ""
        )
        rtl = soc.rtl.replace(
            ");",
            ",\n  input logic [63:0] coverage_epoch_i,\n"
            f"  output logic [2:0] __vi_coverage{environment_declarations}\n);",
            1,
        ).replace(
            "\nendmodule\n",
            "\n  assign __vi_coverage=coverage_epoch_i[2:0]"
            + ("^stimulus_i[2:0]" if with_environment else "")
            + f";{environment_assignments}\nendmodule\n",
            1,
        )
        environment_specs = (
            SocExternalPort("stimulus_i", "input", 10, "unknown"),
            SocExternalPort("status_o", "output", 3, "unknown"),
        ) if with_environment else ()
        soc = replace(
            soc, rtl=rtl,
            external_port_specs=soc.external_port_specs + (
                SocExternalPort("coverage_epoch_i", "input", 64, "coverage"),
                SocExternalPort("__vi_coverage", "output", 3, "coverage"),
            ) + environment_specs,
        )
        coverage = CoverageABIV2(
            "b" * 64, "__vi_coverage", 2, 64,
            (
                {"point_id": "fixture.branch.0", "included": True, "offset": 0,
                 "source_offset": 0},
                {"point_id": "fixture.branch.2", "included": True, "offset": 1,
                 "source_offset": 2},
            ),
            transport_width=3,
        )
        source_root = root / "instrumented"
        source_root.mkdir()
        source = source_root / "instrumented_target_soc_v4.sv"
        source.write_text(rtl + _component_stubs(), encoding="utf-8")
        manifest = build_elaboration_manifest(
            top_module=soc.module_name, rtl_files=(source,), allow_roots=(source_root,),
        )
        harness = emit_protocol_harness_v4(
            soc, module_name="protocol_target_harness_v4", coverage_abi=coverage,
            embed_soc_rtl=False,
        )
        return manifest, source_root, harness, coverage

    def test_environment_replay_drives_unknown_input_each_edge(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, source_root, harness, coverage = self._fixture(
                root, with_environment=True,
            )
            plan = build_environment_plan_v4(harness, {
                "stimulus_i": EnvironmentInputRuleV4(
                    "replay", "external stimulus is fuzz-controlled",
                    "fixture annotation", "first record applies while reset is asserted",
                ),
            })
            with self.assertRaisesRegex(InputValidationError, "explicit environment driver"):
                build_protocol_verilator_target_v4(
                    root / "rejected", manifest=manifest, source_root=source_root,
                    harness=harness, coverage_abi=coverage,
                )
            built = build_protocol_verilator_target_v4(
                root / "targets", manifest=manifest, source_root=source_root,
                harness=harness, coverage_abi=coverage, environment_plan=plan,
            )
            transport = encode_rawbits_v4_testcase(
                harness.layout, lane=RawBitsV4Lane.RAW_ESCAPE,
                submode=RawBitsV4Submode.RAW_LITERAL, logical_testcase_id=10,
                records=(0,),
            )
            sidecar = encode_environment_replay_v4(
                plan, tuple({"stimulus_i": value} for value in (0, 0, 0, 0, 0, 1)),
            )
            replayed = run_protocol_verilator_target_v4(
                built.path, transport, layout_digest=harness.layout.digest,
                coverage_abi=coverage, coverage_epoch=5,
                environment_plan=plan, environment_replay=sidecar,
            )
            self.assertEqual(replayed.coverage_bitmap, b"\x02")
            bundle = build_wire_replay_bundle_v4(
                harness.layout, transport, replayed, soc_digest=harness.soc_digest,
                profile_digest=harness.protocol_profile_digest,
                target_digest=built.target_digest, coverage_abi=coverage,
                coverage_epoch=5, toolchain={"verilator": "5.020"},
                runtime={"runner": "v4"}, invocation={"mode": "raw"},
                random_seeds={},
                deterministic_initialization={"schema": "fixture-reset/v1"},
                external_environment={"source": "per-edge-sidecar"},
                environment_plan=plan, environment_replay=sidecar,
            )
            serialized = json.loads(json.dumps(bundle.to_dict()))
            reproduced = replay_wire_bundle_v4(
                wire_replay_bundle_v4_from_dict(serialized), built.path,
                layout=harness.layout, coverage_abi=coverage,
            )
            self.assertEqual(reproduced.coverage_bitmap, b"\x02")
            serialized["environment_replay_base64"] = (
                serialized["environment_replay_base64"][:-1] + "A"
            )
            with self.assertRaisesRegex(InputValidationError, "environment sidecar"):
                wire_replay_bundle_v4_from_dict(serialized)
            too_short = encode_environment_replay_v4(
                plan, tuple({"stimulus_i": 0} for _ in range(5)),
            )
            with self.assertRaisesRegex(InputValidationError, "exit code 21"):
                run_protocol_verilator_target_v4(
                    built.path, transport, layout_digest=harness.layout.digest,
                    coverage_abi=coverage, coverage_epoch=5,
                    environment_plan=plan, environment_replay=too_short,
                )

    def test_build_cache_run_and_reject_bad_crc_before_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, source_root, harness, coverage = self._fixture(root)
            built = build_protocol_verilator_target_v4(
                root / "targets", manifest=manifest, source_root=source_root,
                harness=harness, coverage_abi=coverage,
            )
            cached = build_protocol_verilator_target_v4(
                root / "targets", manifest=manifest, source_root=source_root,
                harness=harness, coverage_abi=coverage,
            )
            self.assertTrue(cached.cached)
            completion = json.loads(
                Path(built.completion_manifest).read_text(encoding="utf-8")
            )
            rules_evidence = json.loads(
                (Path(built.path) / "evidence/protocol_legality_rules.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                completion["protocol_legality_rules"], rules_evidence["rules"]
            )
            self.assertEqual(
                rules_evidence["protocol_profile_digest"], harness.protocol_profile_digest
            )

            transport = encode_rawbits_v4_testcase(
                harness.layout, lane=RawBitsV4Lane.RAW_ESCAPE,
                submode=RawBitsV4Submode.RAW_LITERAL, logical_testcase_id=9,
                records=(0,),
            )
            input_path = root / "input.v4"
            coverage_path = root / "coverage.bin"
            result_path = root / "result.json"
            input_path.write_bytes(transport)
            completed = subprocess.run(
                [Path(built.path) / "bin/myfuzz_target", input_path, coverage_path,
                 result_path, "5"],
                cwd=built.path, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
            self.assertEqual(coverage_path.read_bytes(), b"\x03")
            result = json.loads(result_path.read_text(encoding="utf-8"))
            self.assertEqual(result["observed_classification"], "raw")
            self.assertIsNone(result["violation_rule"])

            replayed = run_protocol_verilator_target_v4(
                built.path, transport, layout_digest=harness.layout.digest,
                coverage_abi=coverage, coverage_epoch=5,
            )
            replayed_again = run_protocol_verilator_target_v4(
                built.path, transport, layout_digest=harness.layout.digest,
                coverage_abi=coverage, coverage_epoch=5,
            )
            self.assertEqual(replayed.coverage_bitmap, b"\x03")
            self.assertEqual(replayed.wire_trace_digest, replayed_again.wire_trace_digest)
            self.assertEqual(len(replayed.wire_trace_digest), 64)
            server = GeneratedTargetServerV4(
                built.path, layout=harness.layout, coverage_abi=coverage,
                first_coverage_epoch=100,
            )
            self.assertEqual(server.legality_rules, completion["protocol_legality_rules"])
            campaign = run_protocol_campaign_v4(
                V4Controller(harness.layout, policy="B", seed=13, coverage_bits=2),
                server, wall_seconds=30, max_testcases=1,
            )
            self.assertEqual(campaign.completed_count, 1)
            self.assertGreater(campaign.transport_bytes, 64)
            self.assertGreater(campaign.dut_cycles, 0)
            self.assertGreater(campaign.wire_trace_edges, campaign.dut_cycles)
            self.assertEqual(campaign.logical_records, 1)
            self.assertEqual(campaign.accepted_records, 1)
            self.assertGreaterEqual(campaign.record_stall_cycles, 0)
            experiment = build_protocol_only_experiment_manifest_v4(
                experiment_id="real-bcd-smoke", seed=17, wall_seconds=30,
                baseline_coverage_abi=coverage, generated_coverage_abi=coverage,
                baseline_target_digest="a" * 64,
                generated_target_digest=built.target_digest,
                target_peak_rss_bytes=1,
            )
            def baseline_result():
                bitmap = b"\x00"
                return ProtocolCampaignResultV4(
                    policy="A", seed=17, wall_seconds=0.01,
                    deadline_reached=False, status="completed", testcase_count=1,
                    completed_count=1, censored_inflight=0, coverage_bits=2,
                    coverage_digest=hashlib.sha256(bitmap).hexdigest(),
                    lane_counts={"RAW_ESCAPE": 1},
                    declared_lane_counts={"RAW_ESCAPE": 1},
                    observed_classification_counts={"raw": 1},
                    resource_before={}, resource_after={}, target_digest="a" * 64,
                    coverage_bitmap_base64=base64.b64encode(bitmap).decode("ascii"),
                    coverage_hits=0,
                    coverage_checkpoints=tuple(
                        {"seconds": seconds, "coverage_hits": 0}
                        for seconds in experiment.checkpoint_seconds
                    ),
                )
            def generated_result(policy):
                return run_protocol_campaign_v4(
                    V4Controller(harness.layout, policy=policy, seed=17, coverage_bits=2),
                    GeneratedTargetServerV4(
                        built.path, layout=harness.layout, coverage_abi=coverage,
                        first_coverage_epoch=200,
                    ),
                    wall_seconds=30, max_testcases=1,
                    checkpoint_seconds=experiment.checkpoint_seconds,
                )
            serial = run_serial_protocol_abcd_v4({
                "A": baseline_result,
                "B": lambda: generated_result("B"),
                "C": lambda: generated_result("C"),
                "D": lambda: generated_result("D"),
            }, manifest=experiment)
            self.assertEqual(serial.status, "valid", serial.invalid_variants)
            self.assertEqual(tuple(serial.variants), ("A", "B", "C", "D"))
            self.assertEqual({serial.variants[name]["target_digest"] for name in "BCD"}, {
                built.target_digest,
            })
            bundle = build_wire_replay_bundle_v4(
                harness.layout, transport, replayed, soc_digest=harness.soc_digest,
                profile_digest=harness.protocol_profile_digest,
                target_digest=built.target_digest,
                coverage_abi=coverage, coverage_epoch=5,
                toolchain={"verilator": "5.020"}, runtime={"runner": "v4"},
                invocation={"mode": "raw", "timeout_seconds": 30},
                random_seeds={},
                deterministic_initialization={"schema": "fixture-reset/v1", "memory": []},
                external_environment={},
            )
            serialized = json.loads(json.dumps(bundle.to_dict()))
            loaded = wire_replay_bundle_v4_from_dict(serialized)
            store = WireReplayEvidenceStoreV4(
                root / "replay-evidence", max_entries=2, max_bundle_bytes=1024 * 1024,
            )
            reference = store.record(loaded, testcase_id=9, new_branch_count=2)
            self.assertEqual(store.load_entries(), (reference,))
            self.assertEqual(
                store.load_bundle(str(reference["object_sha256"])).digest,
                loaded.digest,
            )
            orphan_payload = b"orphan"
            orphan_digest = hashlib.sha256(orphan_payload).hexdigest()
            orphan_path = root / "replay-evidence/objects" / orphan_digest
            orphan_path.write_bytes(orphan_payload)
            WireReplayEvidenceStoreV4(
                root / "replay-evidence", max_entries=2, max_bundle_bytes=1024 * 1024,
            )
            self.assertFalse(orphan_path.exists())
            reproduced = replay_wire_bundle_v4(
                loaded, built.path, layout=harness.layout, coverage_abi=coverage,
            )
            self.assertEqual(reproduced.wire_trace_digest, bundle.expected_wire_trace_digest)
            serialized["target_digest"] = "d" * 64
            with self.assertRaisesRegex(InputValidationError, "bundle digest mismatch"):
                wire_replay_bundle_v4_from_dict(serialized)

            object_path = (
                root / "replay-evidence/objects" / str(reference["object_sha256"])
            )
            object_path.write_bytes(b"not-json")
            with self.assertRaisesRegex(InputValidationError, "missing or corrupt"):
                store.load_entries()

            damaged = bytearray(transport)
            damaged[60] ^= 1
            bad_path = root / "bad-crc.v4"
            bad_path.write_bytes(damaged)
            rejected = subprocess.run(
                [Path(built.path) / "bin/myfuzz_target", bad_path,
                 root / "bad-coverage.bin", root / "bad-result.json"],
                cwd=built.path, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(rejected.returncode, 6)
            self.assertFalse((root / "bad-coverage.bin").exists())
            self.assertFalse((root / "bad-result.json").exists())


if __name__ == "__main__":
    unittest.main()
