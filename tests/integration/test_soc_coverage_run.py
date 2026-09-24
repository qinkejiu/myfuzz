"""P13 instrumented eight-cell coverage acceptance (opt-in).

MYFUZZ_SOC_REAL=1 is required.  Each of the eight matrix cells is built with the
production campaign builder, which branch-instruments the cell closure and
points the harness's coverage counters at the instrumented top.  The test then
runs a short real campaign and checks the coverage the fuzzer actually received:
it must contain at least one real CPU or real-IP internal branch point, resolved
to its exact instance path, rather than a sampled input or output event.

The duration is deliberately short.  This test establishes that branch feedback
reaches RFuzz for every cell; it is not a coverage measurement and makes no
statement about how much of a cell a long run would reach.  The >=300 s per-cell
campaign is P15 and is out of scope here.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from myfuzz.integration.soc_builder import build_soc_campaign_artifact
from myfuzz.integration.soc_campaign import run_soc_campaign


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))

_DEFAULT_CLIENT = ROOT / "runs/rfuzz_client_native_build/target/debug/kfuzz"
CLIENT = Path(os.environ.get("MYFUZZ_RFuzz_CLIENT") or _DEFAULT_CLIENT)
MATRIX = ROOT / "configs/soc/matrix.json"
#: Enough real fuzz time to reach the CPU and a peripheral, far short of P15.
DURATION_SECONDS = int(os.environ.get("MYFUZZ_SOC_COVERAGE_SECONDS") or 10)
INSTRUMENTED_KIND = "source-instrumented-rtl-branch-u8-saturating"


def _missing_dependencies():
    missing = []
    if shutil.which("verilator") is None:
        missing.append("verilator")
    if not CLIENT.is_file():
        missing.append("rfuzz client %s" % CLIENT)
    return missing


def cell_campaign_config(config_path: str, cell_id: str, *, mode: str,
                         seed: int) -> dict:
    """Build the campaign config for one matrix cell from its resolved config."""
    from integration.test_soc_renderer_cells import load_cell_config, cell_entries

    cells = {entry["cell_id"]: entry for entry in cell_entries()}
    resolved = load_cell_config(cells[cell_id])
    cpu = resolved["cpu"]
    peripherals = resolved["peripherals"]
    cpu_id = cpu["id"] if isinstance(cpu, dict) else str(cpu)
    peripheral_ids = [item["id"] if isinstance(item, dict) else str(item)
                      for item in peripherals]
    families = sorted({item.get("family", "") for item in peripherals
                       if isinstance(item, dict)} - {""}) or list(resolved.get("families", []))
    return {
        "config_id": "%s/%s/coverage-p13" % (cell_id, mode),
        "cell_id": cell_id,
        "cell_config": config_path,
        "cpu": cpu_id,
        "families": families,
        "peripherals": peripheral_ids,
        "mode": mode,
        "seed": seed,
        "simulator": "verilator",
        "duration_seconds": DURATION_SECONDS,
        "seed_cycles": 5,
        "bias_off": False,
        "root": str(ROOT),
        "source_paths": [config_path, "configs/soc/sources.lock.json"],
        "client_binary": str(CLIENT),
        "reset_contract": {"driver": True, "memory": True, "cpu": True,
                           "peripherals": True, "irq": True, "coverage": True},
    }


@unittest.skipUnless(os.environ.get("MYFUZZ_SOC_REAL") == "1",
                     "set MYFUZZ_SOC_REAL=1 for the instrumented coverage run")
class SocInstrumentedCoverageRunTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        missing = _missing_dependencies()
        if missing:
            raise AssertionError(
                "MYFUZZ_SOC_REAL=1 requires the real coverage dependencies; missing: "
                + ", ".join(missing))
        cls.matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
        cls.temporary = tempfile.TemporaryDirectory(prefix="soc-coverage-p13-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.records = {}
        for index, entry in enumerate(cls.matrix["cells"]):
            cell_id = entry["cell_id"]
            output = Path(cls.temporary.name) / cell_id
            config = cell_campaign_config(entry["config"], cell_id, mode="mixed",
                                          seed=20260914 + index)
            result = run_soc_campaign(
                config, output, root=ROOT,
                environment={"MYFUZZ_SOC_REAL": "1"},
                rebuilder=build_soc_campaign_artifact)
            cls.records[cell_id] = (result, output)

    def _hits(self, cell_id: str):
        """Return (nonzero counter hits, artifact coverage, live report)."""
        _result, output = self.records[cell_id]
        build = json.loads((output / "build/artifact_provenance.json").read_text(encoding="utf-8"))
        live = json.loads((output / "live/report.json").read_text(encoding="utf-8"))
        plan = json.loads((output / "build/soc_coverage_plan.json").read_text(encoding="utf-8"))
        corpus = sorted((output / "live/corpus").glob("entry_*.json"))
        self.assertTrue(corpus, "%s: the campaign retained no corpus entry" % cell_id)
        # Every retained entry is what the fuzzer kept, so its trace is the
        # coverage feedback the client actually received over the IPC channel.
        best = None
        for path in corpus:
            trace = json.loads(path.read_text(encoding="utf-8"))["trace_bits"]
            hits = [(index, value) for index, value in enumerate(trace) if value]
            if best is None or len(hits) > len(best):
                best = hits
        return best, build["coverage"], live, plan

    def test_every_cell_reports_source_instrumented_branch_coverage(self):
        for entry in self.matrix["cells"]:
            cell_id = entry["cell_id"]
            with self.subTest(cell=cell_id):
                _hits, coverage, live, _plan = self._hits(cell_id)
                self.assertEqual(INSTRUMENTED_KIND, coverage["kind"])
                build = json.loads((self.records[cell_id][1]
                                    / "build/artifact_provenance.json")
                                   .read_text(encoding="utf-8"))
                self.assertEqual(
                    "restart process: source instrumentation contains sticky branch hits",
                    build["test_isolation"])
                self.assertTrue(
                    coverage["instrumenter"]["source_sha256"].startswith("sha256:"))
                self.assertTrue(
                    coverage["instrumented_output_sha256"].startswith("sha256:"))
                self.assertTrue(Path(coverage["instrumented_flist"]).is_file())
                self.assertEqual(INSTRUMENTED_KIND, live["coverage_kind"])
                self.assertEqual("__vi_coverage", coverage["signal"])
                self.assertEqual(128, coverage["counter_count"])
                self.assertGreater(coverage["branch_point_count"], 0)
                self.assertTrue(coverage["universe_hash"].startswith("sha256:"))
                for category in ("cpu", "ip", "fabric", "model", "harness"):
                    self.assertIn(category, coverage["universe_categories"])
                self.assertGreater(coverage["universe_categories"]["cpu"], 0)
                self.assertGreater(coverage["universe_categories"]["ip"], 0)

    def test_every_cell_observes_cpu_and_ip_points_not_sampled_events(self):
        for entry in self.matrix["cells"]:
            cell_id = entry["cell_id"]
            with self.subTest(cell=cell_id):
                _hits, coverage, _live, _plan = self._hits(cell_id)
                observed = coverage["observed_by_category"]
                self.assertGreater(observed.get("cpu", 0), 0,
                                   "%s observed no CPU point" % cell_id)
                self.assertGreater(observed.get("ip", 0), 0,
                                   "%s observed no real-IP point" % cell_id)
                self.assertGreater(coverage["vector_width"], coverage["counter_count"])

    def test_every_cell_feeds_a_real_cpu_or_ip_branch_hit_to_rfuzz(self):
        """The point of P13: a real internal point reaches feedback, per cell."""
        for entry in self.matrix["cells"]:
            cell_id = entry["cell_id"]
            with self.subTest(cell=cell_id):
                hits, coverage, live, plan = self._hits(cell_id)
                self.assertGreater(live["actual_rtl_execution"]["coverage_records"], 0)
                self.assertTrue(coverage["unobserved_branch_points"] >= 0)
                observed = plan["observed"]
                resolved = []
                for index, value in hits:
                    if index < len(observed):
                        resolved.append((observed[index], value))
                self.assertTrue(
                    resolved,
                    "%s: no retained corpus entry carried a nonzero branch counter"
                    % cell_id)
                categories = {item["category"] for item, _value in resolved}
                self.assertTrue(
                    categories & {"cpu", "ip"},
                    "%s: hits were %s, expected a real CPU or IP point"
                    % (cell_id, sorted(categories)))
                for point, _value in resolved:
                    self.assertTrue(point["instance_id"].startswith("myfuzz_soc_top/"))
                    self.assertTrue(point["module"])

    def test_the_universe_document_is_retained_and_hashed(self):
        for entry in self.matrix["cells"]:
            cell_id = entry["cell_id"]
            with self.subTest(cell=cell_id):
                _hits, coverage, _live, _plan = self._hits(cell_id)
                _result, output = self.records[cell_id]
                document = json.loads(
                    (output / "build" / coverage["universe_document"]).read_text(encoding="utf-8"))
                self.assertEqual(coverage["universe_hash"], document["universe_hash"])
                self.assertEqual("source-instrumented-rtl", document["backend"])
                self.assertTrue(document["branch_feedback_is_rtl_only"])
                self.assertEqual(len(document["points"]),
                                 sum(coverage["universe_categories"].values()))


if __name__ == "__main__":
    unittest.main()
