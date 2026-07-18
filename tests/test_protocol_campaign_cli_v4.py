import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_builder_controller_v4 import _layout  # noqa: E402


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _abi() -> dict[str, object]:
    return {
        "catalog_digest": "c" * 64,
        "port_name": "__vi_coverage",
        "width": 8,
        "epoch_width": 64,
        "points": [
            {
                "point_id": f"fixture.{offset}", "component_id": "fixture.ip",
                "included": True, "offset": offset, "source_offset": offset,
            }
            for offset in range(8)
        ],
        "transport_width": 8,
        "writer": "instrumented_sequential_processes",
        "sampling": "after_rising_edge_nba_settle",
        "schema": "myfuzz.coverage-abi/v2",
    }


class ProtocolCampaignCliV4Test(unittest.TestCase):
    def test_cli_runs_a_b_c_d_and_writes_self_contained_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "baseline"
            generated = root / "generated"
            output = root / "report"
            self._baseline(baseline)
            self._generated(generated)
            command = [
                sys.executable, str(ROOT / "src/myfuzz/scripts/protocol_campaign_v4.py"),
                "--baseline-target", str(baseline),
                "--generated-target", str(generated),
                "--output-dir", str(output),
                "--experiment-id", "cli-smoke", "--seed", "7",
                "--wall-seconds", "10", "--target-peak-rss-bytes", "1",
                "--cycles-per-a-testcase", "2", "--max-testcases", "2",
                "--resource-sample-interval", "0.01",
            ]
            completed = subprocess.run(
                command, cwd=ROOT, capture_output=True, text=True, timeout=30,
                env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                {path.name for path in output.iterdir()},
                {
                    "artifact_references.json", "campaign_report.json", "command_report.json",
                    "experiment_manifest.json", "invocation.json", "summary.txt",
                    "replay_evidence",
                },
            )
            campaign = json.loads((output / "campaign_report.json").read_text())
            report = campaign["report"]
            self.assertEqual(report["status"], "valid", report.get("invalid_variants"))
            self.assertEqual(report["order"], ["A", "B", "C", "D"])
            self.assertEqual(list(report["variants"]), ["A", "B", "C", "D"])
            self.assertTrue(all(item["completed_count"] == 2 for item in report["variants"].values()))
            manifest = json.loads((output / "experiment_manifest.json").read_text())
            self.assertEqual(manifest["execution_contract"]["max_testcases"], 2)
            self.assertTrue((output / "replay_evidence").is_dir())
            self.assertIn("fixed serial order is exploratory", (output / "summary.txt").read_text())

    @staticmethod
    def _baseline(target: Path) -> None:
        (target / "bin").mkdir(parents=True)
        (target / "evidence").mkdir()
        abi = _abi()
        (target / "evidence/coverage_abi.json").write_text(json.dumps(abi), encoding="ascii")
        (target / "evidence/bit_layout.json").write_text(
            json.dumps({"bytes_per_cycle": 1, "cycle_width": 8}), encoding="ascii",
        )
        executable = target / "bin/myfuzz_target"
        executable.write_text(
            "#!/usr/bin/env python3\n"
            "import json,pathlib,sys\n"
            "cycles=int(sys.argv[2]); cov=b'\\x01'\n"
            "pathlib.Path(sys.argv[4]).write_bytes(cov)\n"
            "pathlib.Path(sys.argv[5]).write_bytes(cov*cycles)\n"
            "pathlib.Path(sys.argv[6]).write_text(json.dumps({"
            "'schema':'myfuzz.fixed-dut-cycle-metrics/v1','dut_cycles':cycles,"
            "'accepted_records':cycles,'stall_cycles':0,'unconsumed_records':0}))\n",
            encoding="ascii",
        )
        executable.chmod(0o755)
        (target / "completion_manifest.json").write_text(json.dumps({
            "runner_schema": "myfuzz.fixed-dut-cycle-runner/v1",
            "target_digest": "a" * 64,
            "coverage_abi_digest": abi["catalog_digest"],
        }), encoding="ascii")

    @staticmethod
    def _generated(target: Path) -> None:
        (target / "bin").mkdir(parents=True)
        evidence = target / "evidence"
        evidence.mkdir()
        abi = _abi()
        layout = _layout().to_dict()
        (evidence / "coverage_abi.json").write_text(json.dumps(abi), encoding="ascii")
        (evidence / "bit_layout.json").write_text(json.dumps(layout), encoding="ascii")
        (evidence / "target_generation_report.json").write_text(
            json.dumps({"verilator_version": "fixture"}), encoding="ascii",
        )
        legality_rules = {"AW_STABLE_UNTIL_READY": 2}
        (evidence / "protocol_legality_rules.json").write_text(json.dumps({
            "schema": "myfuzz.protocol-legality-rules/v4",
            "protocol_profile_digest": "e" * 64,
            "rules": legality_rules,
        }), encoding="ascii")
        executable = target / "bin/myfuzz_target"
        executable.write_text(
            "#!/usr/bin/env python3\n"
            "import json,pathlib,sys\n"
            "data=pathlib.Path(sys.argv[1]).read_bytes(); lane=data[12]\n"
            "pathlib.Path(sys.argv[2]).write_bytes(bytes((1 << (lane-1),)))\n"
            "kind={1:'raw',2:'protocol_valid',3:'adversarial'}[lane]\n"
            "pathlib.Path(sys.argv[3]).write_text(json.dumps({"
            "'schema':'myfuzz.target-execution-result/v4','observed_classification':kind,"
            "'violation_rule':None,'violation_cycle':None,'dut_cycles':1,"
            "'logical_records':1,'accepted_records':1,'record_stall_cycles':0}))\n"
            "pathlib.Path(sys.argv[5]).write_bytes(bytes(32))\n",
            encoding="ascii",
        )
        executable.chmod(0o755)
        evidence_hashes = {
            path.relative_to(evidence).as_posix(): _sha256(path.read_bytes())
            for path in sorted(evidence.rglob("*")) if path.is_file()
        }
        (target / "completion_manifest.json").write_text(json.dumps({
            "schema": "myfuzz.verilator-target-completion/v4",
            "runner_schema": "myfuzz.generated-target-runner/v4",
            "target_digest": "b" * 64,
            "soc_digest": "d" * 64,
            "protocol_profile_digest": "e" * 64,
            "protocol_legality_rules": legality_rules,
            "layout_digest": layout["digest"],
            "coverage_abi_digest": abi["catalog_digest"],
            "rawbits_limits": {
                "max_chunks": 1024, "max_logical_records": 1_048_576,
                "max_chunk_payload_bytes": 64 * 1024 * 1024,
                "max_testcase_bytes": 512 * 1024 * 1024,
            },
            "environment_plan_digest": None,
            "environment_replay_required": False,
            "environment_replay_limits": {
                "max_records": 1_048_576, "max_payload_bytes": 512 * 1024 * 1024,
            },
            "executable_sha256": _sha256(executable.read_bytes()),
            "evidence_files": evidence_hashes,
        }), encoding="ascii")


if __name__ == "__main__":
    unittest.main()
