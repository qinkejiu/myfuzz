import csv
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


def _layout():
    return build_rawbits_v5_layout((
        {"name": "gpio", "component": "ip0", "owner": "ip0.gpio",
         "kind": "external_input", "width": 4},
        {"name": "clk", "component": "soc", "owner": "soc.clk", "kind": "clock",
         "width": 1},
        {"name": "rst", "component": "soc", "owner": "soc.rst", "kind": "reset",
         "width": 1},
    ))


def _write_fake_artifact(root: Path, label: str) -> None:
    layout = _layout()
    artifact = root / label
    (artifact / "evidence").mkdir(parents=True)
    (artifact / "bin").mkdir()
    (artifact / "evidence" / "rawbits_layout.json").write_text(
        json.dumps(layout.to_dict()), encoding="ascii",
    )
    target = artifact / "bin" / "myfuzz_target"
    target.write_text(
        "#!/usr/bin/env python3\n"
        "import hashlib,json,pathlib,sys\n"
        "payload=pathlib.Path(sys.argv[1]).read_bytes()\n"
        "layout_digest=sys.argv[2]\n"
        "coverage=bytearray(2)\n"
        "coverage[0]=len(payload)&255\n"
        "coverage[1]=sum(payload)&255\n"
        "result={\n"
        " 'schema':'myfuzz.compose-v5-target-execution/v1',\n"
        " 'layout_digest':layout_digest,\n"
        " 'steps':len(payload),\n"
        " 'eval_count':len(payload)*2,\n"
        " 'rising_edges':{'soc.clk':sum(1 for b in payload if b & 16)},\n"
        " 'falling_edges':{'soc.clk':sum(1 for b in payload if not (b & 16))},\n"
        " 'wire_digest':hashlib.sha256(payload).hexdigest(),\n"
        " 'coverage_digest':hashlib.sha256(coverage).hexdigest(),\n"
        " 'coverage_hex':bytes(coverage).hex(),\n"
        " 'settled':True,\n"
        " 'failure':None,\n"
        "}\n"
        "pathlib.Path(sys.argv[3]).write_text(json.dumps(result,sort_keys=True)+'\\n')\n",
        encoding="ascii",
    )
    target.chmod(0o755)


class ComposeV5AbcdRunnerTest(unittest.TestCase):
    def test_existing_artifacts_run_four_schemes_and_write_summary_csv(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_fake_artifact(root, "flat")
            _write_fake_artifact(root, "generated")
            output = root / "abcd"
            command = [
                sys.executable,
                str(ROOT / "src/myfuzz/scripts/compose_v5_abcd.py"),
                "--flat-artifact",
                str(root / "flat"),
                "--generated-artifact",
                str(root / "generated"),
                "--seconds",
                "10",
                "--output-dir",
                str(output),
                "--seed",
                "3",
                "--max-testcases",
                "2",
                "--testcase-bytes",
                "5",
            ]
            completed = subprocess.run(
                command,
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=30,
                env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads((output / "abcd_report.json").read_text())
            self.assertEqual(report["schema"], "myfuzz.compose-v5-abcd-report/v1")
            self.assertEqual(report["mode"], "existing_artifacts")
            self.assertEqual([row["scheme"] for row in report["rows"]], ["A", "B", "C", "D"])
            with (output / "abcd_summary.csv").open(newline="", encoding="ascii") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual([row["scheme"] for row in rows], ["A", "B", "C", "D"])
            self.assertTrue(all(int(row["completed_count"]) == 2 for row in rows))
            self.assertTrue((output / "campaigns" / "scheme_d" / "campaign_report.json").is_file())


if __name__ == "__main__":
    unittest.main()
