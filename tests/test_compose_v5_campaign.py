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

from myfuzz.builder.rawbits_v5 import build_rawbits_v5_layout  # noqa: E402


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _layout():
    return build_rawbits_v5_layout((
        {"name": "clk", "component": "soc", "owner": "soc.clk", "kind": "clock", "width": 1},
        {"name": "rst", "component": "soc", "owner": "soc.rst", "kind": "reset", "width": 1},
        {
            "name": "gpio", "component": "ip0", "owner": "ip0.gpio",
            "kind": "external_input", "width": 6,
        },
    ))


def _write_artifact(root: Path) -> None:
    (root / "evidence").mkdir(parents=True)
    (root / "bin").mkdir()
    layout = _layout()
    (root / "evidence" / "rawbits_layout.json").write_text(
        json.dumps(layout.to_dict()), encoding="ascii",
    )
    target = root / "bin" / "myfuzz_target"
    target.write_text(
        "#!/usr/bin/env python3\n"
        "import hashlib,json,pathlib,sys\n"
        "payload=pathlib.Path(sys.argv[1]).read_bytes()\n"
        "layout_digest=sys.argv[2]\n"
        "coverage=bytes([(len(payload)&255),(sum(payload)&255)])\n"
        "result={\n"
        " 'schema':'myfuzz.compose-v5-target-execution/v1',\n"
        " 'layout_digest':layout_digest,\n"
        " 'steps':len(payload),\n"
        " 'eval_count':len(payload)*2,\n"
        " 'rising_edges':{'soc.clk':sum(1 for b in payload if b & 1)},\n"
        " 'falling_edges':{'soc.clk':sum(1 for b in payload if not (b & 1))},\n"
        " 'wire_digest':hashlib.sha256(payload).hexdigest(),\n"
        " 'coverage_digest':hashlib.sha256(coverage).hexdigest(),\n"
        " 'coverage_hex':coverage.hex(),\n"
        " 'settled':True,\n"
        " 'failure':None,\n"
        "}\n"
        "pathlib.Path(sys.argv[3]).write_text(json.dumps(result,sort_keys=True)+'\\n')\n",
        encoding="ascii",
    )
    target.chmod(0o755)


class ComposeV5CampaignCliTest(unittest.TestCase):
    def test_b_raw_campaign_runs_fresh_target_processes_and_reports_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact"
            output = root / "out"
            _write_artifact(artifact)
            command = [
                sys.executable, str(ROOT / "src/myfuzz/scripts/compose_v5_campaign.py"),
                "--artifact", str(artifact), "--scheme", "B", "--seconds", "10",
                "--output-dir", str(output), "--seed", "5", "--max-testcases", "4",
                "--testcase-bytes", "9",
            ]
            completed = subprocess.run(
                command, cwd=ROOT, capture_output=True, text=True, timeout=30,
                env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                {path.name for path in output.iterdir()},
                {"campaign_report.json", "command_report.json", "invocation.json",
                 "results", "source_testcases", "summary.txt", "testcases"},
            )
            report = json.loads((output / "campaign_report.json").read_text())
            self.assertEqual(report["schema"], "myfuzz.compose-v5-campaign-report/v1")
            self.assertEqual(report["scheme"], "B")
            self.assertTrue(report["fresh_process_per_testcase"])
            self.assertEqual(report["projection_policy"]["mode"], "identity")
            self.assertEqual(report["completed_count"], 4)
            self.assertGreater(report["coverage_hits"], 0)
            raw_sizes = [item["raw_bytes"] for item in report["cases"]]
            self.assertGreater(len(set(raw_sizes)), 1)
            for item in report["cases"]:
                raw = Path(item["raw_path"]).read_bytes()
                source = Path(item["source_raw_path"]).read_bytes()
                self.assertEqual(item["raw_sha256"], _sha256(raw))
                self.assertEqual(item["source_raw_sha256"], _sha256(source))
                self.assertEqual(item["projection"]["mode"], "identity")

    def test_c_scheme_projects_bit_level_source_payloads_before_target_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact"
            output = root / "out"
            _write_artifact(artifact)
            command = [
                sys.executable, str(ROOT / "src/myfuzz/scripts/compose_v5_campaign.py"),
                "--artifact", str(artifact), "--scheme", "C", "--seconds", "10",
                "--output-dir", str(output), "--seed", "7", "--max-testcases", "3",
                "--testcase-bytes", "5",
            ]
            completed = subprocess.run(
                command, cwd=ROOT, capture_output=True, text=True, timeout=30,
                env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads((output / "campaign_report.json").read_text())
            self.assertEqual(report["scheme"], "C")
            self.assertEqual(report["projection_policy"]["mode"], "bit_level_projection")
            self.assertEqual(report["completed_count"], 3)
            self.assertTrue(
                all(item["projection"]["mode"] == "bit_level_projection" for item in report["cases"])
            )
            self.assertTrue(any(
                Path(item["source_raw_path"]).read_bytes() != Path(item["raw_path"]).read_bytes()
                for item in report["cases"]
            ))

    def test_d_scheme_escalates_perturbation_strength_after_coverage_stalls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact"
            output = root / "out"
            _write_artifact(artifact)
            source = root / "d_source.rawbits"
            source.write_bytes(b"\xff\xff")
            command = [
                sys.executable, str(ROOT / "src/myfuzz/scripts/compose_v5_campaign.py"),
                "--artifact", str(artifact), "--scheme", "D", "--seconds", "10",
                "--output-dir", str(output), "--testcase-file", str(source),
                "--testcase-file", str(source), "--testcase-file", str(source),
                "--stall-inputs-before-escalation", "1",
            ]
            completed = subprocess.run(
                command, cwd=ROOT, capture_output=True, text=True, timeout=30,
                env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads((output / "campaign_report.json").read_text())
            self.assertEqual(report["scheme"], "D")
            self.assertEqual(report["projection_policy"]["mode"], "adaptive_bit_level_projection")
            self.assertEqual(report["completed_count"], 3)
            self.assertGreaterEqual(report["max_adaptive_strength"], 1)
            self.assertTrue(all(
                item["projection"]["source_record_width_bits"]
                == report["projection_policy"]["source_record_width_bits"]
                for item in report["cases"]
            ))


if __name__ == "__main__":
    unittest.main()
