import importlib.util
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from myfuzz.integration.rfuzz_simulator import RtlSimulator


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "examples/real_ibex_rfuzz/run_example.py"
INPUT_PATH = ROOT / "examples/real_ibex_rfuzz/input/ibex-scratch.json"
GUIDE_PATH = ROOT / "examples/real_ibex_rfuzz/README.zh-CN.md"
COMMANDS_PATH = ROOT / "examples/real_ibex_rfuzz/commands.sh"
EXPECTED_PATH = ROOT / "examples/real_ibex_rfuzz/expected/bounded-result.json"
OVERVIEW_PATH = ROOT / "examples/real_ibex_rfuzz/系统能力与工作原理.md"
HANDOFF_PATH = ROOT / "项目目标与后续任务交接.md"


def load_module():
    spec = importlib.util.spec_from_file_location("real_ibex_rfuzz_example", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RealIbexRfuzzExampleTests(unittest.TestCase):
    def test_example_entrypoint_exists(self):
        self.assertTrue(MODULE_PATH.is_file(), "real Ibex example entrypoint is missing")

    def test_real_ibex_input_exists(self):
        self.assertTrue(INPUT_PATH.is_file(), "real Ibex example input is missing")

    def test_load_example_translates_single_personality(self):
        module = load_module()
        config, personality = module.load_example(INPUT_PATH, ROOT)
        self.assertNotIn("schema_version", config)
        self.assertNotIn("personality", config)
        self.assertEqual(config["protocol"], ["obi", "1"])
        self.assertEqual(config["interface"], "configs/cpus/ibex/official_core_interface_description.json")
        self.assertEqual(personality["name"], "scratch-registers")
        self.assertEqual(personality["mode"], 0)
        self.assertEqual(config.get("input_mode"), "contract_transducer")
        self.assertEqual(config.get("memory_domains"), {
            "instruction_memory_master": "main", "data_memory_master": "main",
        })
        self.assertNotIn("memory_module", config)

    @unittest.skipUnless(shutil.which("verilator") and (ROOT / "third_party/rfuzz/upstream/ibex/rtl/ibex_top.sv").is_file(),
                         "real Ibex sources and Verilator required")
    def test_candidate_uses_rfuzz_instruction_initialization_without_boot_image(self):
        module = load_module()
        config, personality = module.load_example(INPUT_PATH, ROOT)
        config["test_header"] = {**config["test_header"], "illegal_instruction": True}
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            artifact, proof = module.build_candidate(ROOT, Path(tmp) / "build", config, personality)
            self.assertEqual(proof.get("instruction_source"), "rfuzz_contract_transducer")
            self.assertNotIn("boot_sha256", proof)
            self.assertFalse((Path(tmp) / "build/boot").exists())
            self.assertFalse(any("riscv_boot_image" in arg for arg in artifact.simulator_args))
            self.assertEqual(artifact.projector.constraint_hash, artifact.transducer_hash)
            self.assertGreater(proof["execution"]["instruction_requests"], 0)
            self.assertGreater(proof["execution"]["instruction_responses"], 0)
            self.assertGreaterEqual(proof["execution"]["instruction_initializations"], 2)
            self.assertEqual(proof["execution"]["errors"], 0)
            # Explicit illegal-class coverage is authorized by this test header.
            # Upstream diagnostic stdout must not corrupt protocol frames.
            fields = {field.name: field for field in artifact.layout.fields}
            raw = 255 << fields["instruction_selector"].raw_lo
            raw |= 3 << fields["response_choice"].raw_lo
            records = (artifact.transport.pack(raw),) * config["probe_cycles"]
            with RtlSimulator(artifact) as simulator:
                first = simulator.run_test(records)
                self.assertTrue(simulator.last_diagnostics)
                self.assertEqual(simulator.last_execution["errors"], 0)
                self.assertEqual(first, simulator.run_test(records))

    def test_example_fixes_every_nonrandomized_execution_control(self):
        document = json.loads(INPUT_PATH.read_text())
        controls = document["control_defaults"]
        self.assertIn("trvk_read_integrity", controls)
        self.assertNotIn("trvk_identity", controls)

    def test_load_example_rejects_unknown_keys(self):
        module = load_module()
        document = json.loads(INPUT_PATH.read_text())
        document["surprise"] = True
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.json"
            path.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, "unknown keys"):
                module.load_example(path, ROOT)

    def test_load_example_rejects_wrong_schema(self):
        module = load_module()
        document = json.loads(INPUT_PATH.read_text())
        document["schema_version"] = "real_ibex_rfuzz_example.v2"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.json"
            path.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, "schema_version"):
                module.load_example(path, ROOT)

    def test_load_example_rejects_invalid_contract_controls(self):
        module = load_module()
        document = json.loads(INPUT_PATH.read_text())
        variants = [
            {"input_mode": "boot_image"},
            {"memory_domains": {"instruction_memory_master": "code", "data_memory_master": "data"}},
            {"test_header": {**document["test_header"], "execution_cycles": 201}},
            {"test_header": {**document["test_header"], "boot_address": -2}},
            {"test_header": {**document["test_header"], "illegal_instruction": 1}},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.json"
            for variant in variants:
                path.write_text(json.dumps(document | variant))
                with self.subTest(variant=variant), self.assertRaises(ValueError):
                    module.load_example(path, ROOT)

    def test_test_example_rejects_nonpositive_duration_before_build(self):
        module = load_module()
        with self.assertRaisesRegex(ValueError, "seconds must be a positive integer"):
            module.test_example(ROOT, INPUT_PATH, Path("kfuzz"), Path("out"), 0)

    def test_test_example_rejects_missing_client_before_build(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "kfuzz"
            with self.assertRaisesRegex(ValueError, "RFuzz client does not exist"):
                module.test_example(ROOT, INPUT_PATH, missing, Path(tmp) / "out", 5)

    def test_compose_publishes_inspectable_summary(self):
        module = load_module()
        artifact = object()
        proof = {
            "execution": {"instruction_requests": 2, "instruction_responses": 2,
                          "instruction_initializations": 2, "errors": 0},
            "composition_hash": "sha256:composition",
            "layout_hash": "sha256:layout",
            "constraint_hash": "sha256:contract",
            "transducer_hash": "sha256:contract",
            "implementation_hash": "sha256:implementation",
            "header_hash": "sha256:header",
            "instruction_source": "rfuzz_contract_transducer",
            "coverage": [12, 11],
        }
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "compose"
            with mock.patch.object(module, "build_candidate", return_value=(artifact, proof), create=True) as build:
                summary = module.compose_example(ROOT, INPUT_PATH, output)
            self.assertEqual(summary["mode"], "compose")
            self.assertEqual(summary.get("transducer_hash"), proof["transducer_hash"])
            self.assertEqual(summary.get("instruction_source"), proof["instruction_source"])
            self.assertEqual(summary, module.inspect_example(output))
            build.assert_called_once()

    def test_bounded_acceptance_rejects_missing_replays_before_publishing_pass(self):
        module = load_module()
        proof = {"execution": {}, "composition_hash": "sha256:composition"}
        live = dict(duration_seconds=5, returncode=0, tests=1, corpus_entries=2,
                    execution_totals={}, layout_hash="sha256:layout", remaining_segments=[])
        replay = dict(entries=1, constraint_hash="sha256:contract")
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "test"
            with mock.patch.object(module, "build_candidate", return_value=(object(), proof)), \
                    mock.patch.object(module, "run_live", return_value=live), \
                    mock.patch.object(module, "replay_corpus", return_value=replay):
                with self.assertRaisesRegex(ValueError, "replay count"):
                    module.test_example(ROOT, INPUT_PATH, Path(shutil.which("true")), output, 5)
            self.assertFalse((output / "summary.json").exists())

    def test_replay_command_has_explicit_rebuild_output(self):
        module = load_module()
        args = module._parser().parse_args([
            "replay", "--input", str(INPUT_PATH), "--output", "existing-run", "--build-output", "fresh-build",
        ])
        self.assertEqual(args.command, "replay")
        self.assertEqual(args.build_output, Path("fresh-build"))

    def test_independent_replay_binds_coverage_receipt_and_retained_trace_hashes(self):
        module = load_module()
        digest = lambda payload: "sha256:" + hashlib.sha256(bytes(payload)).hexdigest()
        proof = dict(layout_hash="layout", constraint_hash="contract", transducer_hash="contract", implementation_hash="implementation",
                     header_hash="header")
        identity = proof | dict(input_sha256="input", physical_controls_sha256="controls",
                                simulator_inputs_sha256="sim-inputs")
        fresh = identity | {"counters": [1], "trace_sha256": digest([1, 0, 0, 0, 0, 0])}
        original = identity | {"coverage_sha256": digest([1]), "trace_sha256": fresh["trace_sha256"]}
        replay = {"entries": 1, "layout_hash": "layout", "constraint_hash": "contract", "replays": [fresh]}
        saved = {"entries": 1, "replays": [original]}
        module._verify_replay_identity(proof, replay, saved)
        for value in ("different-implementation", None):
            with self.assertRaisesRegex(ValueError, "implementation_hash"):
                module._verify_replay_identity(proof, replay, saved | {
                    "replays": [original | {"implementation_hash": value}]
                })
        for key in ("coverage_sha256", "trace_sha256"):
            for value in ("sha256:tampered", None):
                with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, "replay .* hash"):
                    module._verify_replay_identity(proof, replay, saved | {"replays": [original | {key: value}]})
        changed = fresh | {"counters": [2], "trace_sha256": digest([2, 0, 0, 0, 0, 0])}
        with self.assertRaisesRegex(ValueError, "replay coverage hash"):
            module._verify_replay_identity(proof, replay | {"replays": [changed]}, saved)

    def test_inspect_rejects_malformed_summary(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            (output / "summary.json").write_text("[]\n")
            with self.assertRaisesRegex(ValueError, "summary must be a JSON object"):
                module.inspect_example(output)

    def test_chinese_guide_documents_all_commands_and_acceptance_boundary(self):
        self.assertTrue(GUIDE_PATH.is_file(), "Chinese walkthrough is missing")
        guide = GUIDE_PATH.read_text()
        for text in ("run_example.py compose", "run_example.py test", "run_example.py inspect", "5 秒", "3×300 秒"):
            self.assertIn(text, guide)
        self.assertIn("不等同", guide)

    def test_chinese_guide_explains_contract_cycle_inputs(self):
        guide = GUIDE_PATH.read_text()
        for term in ("cycle_test.v1", "instruction_selector", "instruction_payload", "response_choice",
                     "memory_domains", "test_begin", "run_example.py replay"):
            self.assertIn(term, guide)

    def test_handoff_keeps_task14_formal_closure_pending(self):
        handoff = HANDOFF_PATH.read_text()
        pending = " ".join(handoff.split("## 6. 未完成项与下一轮顺序", 1)[1].split())
        self.assertRegex(pending, r"\d+\. Task 14 正式收口仍暂缓、未完成")
        self.assertIn("当前有界短测证据不自动完成原计划 Task 14 的验收与正式收口", pending)

    def test_command_sheet_exists(self):
        self.assertTrue(COMMANDS_PATH.is_file(), "command sheet is missing")

    def test_reference_result_is_machine_readable(self):
        self.assertTrue(EXPECTED_PATH.is_file(), "bounded reference result is missing")
        result = json.loads(EXPECTED_PATH.read_text())
        self.assertGreater(result["rtl_tests"], 0)
        self.assertEqual(result["instruction_source"], "rfuzz_contract_transducer")
        self.assertGreater(result["instruction_initializations"], 1)
        self.assertEqual(result["constraint_hash"], result["transducer_hash"])
        self.assertFalse(result["formal_3x300_seconds_passed"])
        self.assertFalse(result["boom_processor_acceptance_passed"])

    def test_root_readme_links_chinese_walkthrough(self):
        readme = (ROOT / "README.md").read_text()
        self.assertIn("examples/real_ibex_rfuzz/README.zh-CN.md", readme)

    def test_standalone_system_overview_covers_the_complete_flow(self):
        self.assertTrue(OVERVIEW_PATH.is_file(), "standalone system overview is missing")
        overview = OVERVIEW_PATH.read_text()
        for heading in ("系统目标", "分层架构", "自动组合", "输入约束", "RFuzz 反馈闭环", "语料重放", "接入更多 CPU 和外设", "CPU 直接组合条件", "外设直接组合条件", "系统不会自动猜测", "当前测试结果", "尚未完成"):
            self.assertIn(heading, overview)


if __name__ == "__main__":
    unittest.main()
