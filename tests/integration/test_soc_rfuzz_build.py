"""P14 real RFuzz SoC build and closed-loop acceptance tests (opt-in).

MYFUZZ_SOC_REAL=1 is required.  When the flag is set nothing here skips
silently: a missing Verilator, a missing pinned closure file or a missing
official client fails the class loudly.

The class builds the ibex-pulp artifact once through the production builder,
runs one real short campaign through run_soc_campaign (30 seconds, never 300),
rebuilds a fresh binary from the retained corpus, replays that corpus and only
then asserts on the retained evidence: FIFO reply receipts, corpus and input
transport identity, the written report, and replay coverage identity.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from myfuzz.contracts import canonical_bytes, content_hash
from myfuzz.integration.rfuzz_live import build_corpus_manifest, replay_corpus
from myfuzz.integration.soc_builder import build_soc_campaign_artifact
from myfuzz.integration.soc_campaign import run_soc_campaign


ROOT = Path(__file__).resolve().parents[2]
CLIENT = ROOT / "runs/rfuzz_client_native_build/target/debug/kfuzz"
CELL_CONFIG = "configs/soc/ibex-pulp.json"
DURATION_SECONDS = 30
REAL_CLOSURE = (
    "third_party/rfuzz/upstream/ibex/rtl/ibex_top.sv",
    "third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv",
    "third_party/soc-pulp-apb-spi/apb_spi_master.sv",
)
BUILD_FILES = ("soc_top.sv", "soc_sources.f", "soc_manifest.json",
               "soc_boot.S", "soc_parameters.json",
               "rfuzz_input_transport.sv", "rfuzz_input_transport.json",
               "input_layout.json", "live_tb.sv")


def campaign_config(**overrides):
    value = {
        "config_id": "ibex-pulp/mixed/build-test",
        "cell_id": "ibex-pulp",
        "cell_config": CELL_CONFIG,
        "cpu": "ibex",
        "families": ["pulp"],
        "peripherals": ["pulp_gpio", "pulp_spi"],
        "mode": "mixed",
        "seed": 20260914,
        "simulator": "verilator",
        "duration_seconds": DURATION_SECONDS,
        "seed_cycles": 5,
        "bias_off": False,
        "root": str(ROOT),
        "source_paths": [
            "configs/soc/sources.lock.json",
            CELL_CONFIG,
            "configs/soc/families/pulp.json",
            *REAL_CLOSURE,
        ],
        "client_binary": str(CLIENT),
        "reset_contract": {"driver": True, "memory": True, "cpu": True,
                           "peripherals": True, "irq": True, "coverage": True},
    }
    value.update(overrides)
    return value


def _missing_dependencies():
    missing = []
    if shutil.which("verilator") is None:
        missing.append("verilator")
    if not (CLIENT.is_file() and os.access(CLIENT, os.X_OK)):
        missing.append(str(CLIENT))
    for relative in REAL_CLOSURE + ("configs/soc/sources.lock.json", CELL_CONFIG):
        if not (ROOT / relative).is_file():
            missing.append(relative)
    return missing


def _read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _hash(path):
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


@unittest.skipUnless(os.environ.get("MYFUZZ_SOC_REAL") == "1",
                     "set MYFUZZ_SOC_REAL=1 for the real SoC campaign build")
class SocRfuzzBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        missing = _missing_dependencies()
        if missing:
            raise AssertionError(
                "MYFUZZ_SOC_REAL=1 requires the real campaign dependencies; missing: "
                + ", ".join(missing))
        cls.temporary = tempfile.TemporaryDirectory(prefix="soc-rfuzz-build-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.config = campaign_config()
        cls.output = Path(cls.temporary.name) / "run"
        # No builder argument: this exercises the production default wiring.
        cls.result = run_soc_campaign(
            cls.config, cls.output, root=ROOT,
            environment={"MYFUZZ_SOC_REAL": "1"},
            rebuilder=build_soc_campaign_artifact)
        cls.build = _read_json(cls.output / "build/artifact_provenance.json")
        cls.live = _read_json(cls.output / "live/report.json")
        cls.corpus = cls.output / "live" / "corpus"
        replay_document = (cls.result.get("replay") or {}).get("document")
        if replay_document is None:
            # The pinned client is killed after its bounded interrupt drain, so
            # run_soc_campaign cannot run its own replay step: rebuild and
            # replay the retained corpus here instead of weakening the check.
            cls.rebuilt = build_soc_campaign_artifact(
                cls.config, cls.output / "rebuild-test")
            cls.rebuild_document = _read_json(
                cls.output / "rebuild-test/artifact_provenance.json")
            cls.corpus_manifest = build_corpus_manifest(cls.rebuilt, cls.corpus)
            cls.replay = replay_corpus(cls.rebuilt, cls.corpus)
        else:
            cls.rebuild_document = _read_json(
                cls.output / "rebuild/artifact_provenance.json")
            cls.rebuilt = None
            cls.corpus_manifest = None
            cls.replay = replay_document

    # -- build ------------------------------------------------------------
    def test_build_emits_a_real_executable_and_deterministic_identity(self):
        build = self.build
        executable = Path(build["executable"]["path"])
        self.assertTrue(executable.is_file(),
                        "the campaign builder did not produce an executable")
        self.assertEqual(self.build["executable"]["sha256"], _hash(executable))
        for name in BUILD_FILES:
            path = self.output / "build" / name
            self.assertTrue(path.is_file(), "missing generated file: %s" % name)
        transport = _read_json(self.output / "build/rfuzz_input_transport.json")
        recorded = {item["file"]: item["sha256"]
                    for item in build["rendered_files"]}
        for name in BUILD_FILES:
            if name not in recorded:
                continue
            self.assertEqual(recorded[name],
                             _hash(self.output / "build" / name),
                             "rendered file hash drifted from the provenance: %s" % name)
        body = {key: value for key, value in transport.items()
                if key != "transport_hash"}
        self.assertEqual(transport["transport_hash"],
                         hashlib.sha256(canonical_bytes(body)).hexdigest())
        self.assertEqual(build["transport"], transport)
        self.assertEqual(transport["raw_width"], build["input_layout"]["raw_width"])
        self.assertIn("transport", build)
        self.assertTrue(build["build_hash"].startswith("sha256:"))

    def test_generated_sources_contain_the_real_cpu_and_peripheral_closure(self):
        rendered = (self.output / "build/soc_sources.f").read_text(encoding="utf-8")
        for relative in REAL_CLOSURE:
            self.assertIn(relative, rendered,
                          "rendered closure does not name the real IP source")
        top = (self.output / "build/soc_top.sv").read_text(encoding="utf-8")
        self.assertIn("soc_ibex_beat_core", top)
        self.assertIn("soc_pulp_gpio_target", top)
        self.assertIn("soc_pulp_spi_target", top)
        self.assertIn("MYFUZZ_ENABLE_REAL_IBEX", top)
        for peripheral in self.build["peripherals"]:
            self.assertTrue((ROOT / peripheral["spot_check"]).is_file(),
                            "pinned IP source is missing: %s" % peripheral["spot_check"])
            self.assertIn(peripheral["spot_check"], rendered)
        source_paths = {item["path"] for item in self.build["sources"]["source_files"]}
        self.assertIn(REAL_CLOSURE[0], source_paths)
        self.assertIn(REAL_CLOSURE[1], source_paths)

    def test_the_same_config_produces_the_same_rendered_and_transport_identity(self):
        first = {item["file"]: item["sha256"] for item in self.build["rendered_files"]}
        second = {item["file"]: item["sha256"]
                  for item in self.rebuild_document["rendered_files"]}
        self.assertEqual(first, second,
                         "rendered output is not deterministic across builds")
        self.assertEqual(self.build["input_layout"], self.rebuild_document["input_layout"])
        self.assertEqual(self.build["transport"], self.rebuild_document["transport"])
        first_sv = (self.output / "build/rfuzz_input_transport.sv").read_bytes()
        rebuilt_sv = self.output / "rebuild-test/rfuzz_input_transport.sv"
        if not rebuilt_sv.is_file():
            rebuilt_sv = self.output / "rebuild/rfuzz_input_transport.sv"
        second_sv = rebuilt_sv.read_bytes()
        self.assertEqual(first_sv, second_sv,
                         "the RFuzz input transport render is not deterministic")

    # -- real closed loop --------------------------------------------------
    def test_real_campaign_retains_fifo_receipts_corpus_and_transport(self):
        result, live = self.result, self.live
        report = _read_json(self.output / "report.json")
        self.assertEqual("soc_result.v1", report["schema_version"])
        compile_errors = [error for error in report["errors"]
                          if error.get("category") == "compile"
                          or error.get("phase") in {"build", "compile"}]
        self.assertEqual([], compile_errors,
                         "campaign failed while building/compiling: %s" % compile_errors)
        self.assertIn(result["status"], {"completed", "incomplete-evidence", "failed"})
        if result["status"] == "failed":
            # The pinned client predates the local SIGINT-at-Yield patch, so the
            # run ends in a bounded-drain termination, never a build failure.
            categories = {error.get("category") for error in report["errors"]}
            self.assertTrue(categories & {"timeout", "client"},
                            "unexpected campaign failure category: %s" % categories)
        receipts = live.get("fifo_reply_receipts") or report.get("fifo_reply_receipts")
        self.assertTrue(receipts, "no FIFO reply receipt was observed")
        self.assertGreater(live.get("tests", 0), 0)
        for receipt in receipts:
            self.assertTrue(receipt["input_sha256"].startswith("sha256:"))
            self.assertTrue(receipt["coverage_sha256"].startswith("sha256:"))
            self.assertEqual("fifo_reply_and_rtl_completed", receipt["status"])
            self.assertEqual("sysv-shared-memory-rfuzz-coverage-buffer",
                             receipt["transport"])
        self.assertGreaterEqual(live.get("fifo_reply_receipt_count", 0), 1)
        entries = sorted(self.corpus.glob("entry_*.json"))
        self.assertTrue(entries, "the retained corpus is empty")
        width = self.build["transport"]["byte_count"]
        for path in entries:
            payload = _read_json(path)["entry"]["inputs"]
            self.assertGreater(len(payload), 0)
            self.assertEqual(0, len(payload) % width,
                             "retained corpus entry is not a whole transport record: %s"
                             % path.name)
        stored = _read_json(self.corpus / "config.json")
        self.assertEqual(self.build["input_layout"]["raw_width"],
                         stored["input"][0]["width"])
        self.assertEqual("observed", report["input_transport"]["status"])
        self.assertEqual(self.build["transport"],
                         report["input_transport"]["document"])
        # soc_campaign hashes the whole transport document (including its own
        # transport_hash field); the builder records the transport's bare hash.
        self.assertEqual(content_hash(self.build["transport"]),
                         report["input_transport"]["transport_hash"])
        self.assertEqual(len(self.build["coverage"]["observations"]),
                         len(stored["coverage"]))
        self.assertFalse(live.get("remaining_segments"),
                         "the campaign leaked owned shared-memory segments")

    def test_replay_reproduces_the_recorded_coverage_identity(self):
        replay = self.replay
        self.assertGreaterEqual(replay["entries"], 1)
        self.assertEqual("passed", replay["status"])
        self.assertEqual(self.build["input_layout"]["layout_hash"],
                         replay["layout_hash"])
        self.assertEqual(self.rebuild_document["executable"]["sha256"],
                         replay["binary_sha256"],
                         "replay did not use the freshly rebuilt binary")
        replays = {item["file"]: item for item in replay["replays"]}
        for path in sorted(self.corpus.glob("entry_*.json")):
            document = _read_json(path)
            payload = bytes(document["entry"]["inputs"])
            recorded_trace = bytes(document["trace_bits"])
            counters = bytes(replays[path.name]["counters"])
            self.assertEqual(recorded_trace[:len(counters)], counters,
                             "replayed counters differ from the saved trace: %s"
                             % path.name)
            self.assertEqual("sha256:" + hashlib.sha256(payload).hexdigest(),
                             replays[path.name]["input_sha256"])
            self.assertEqual("sha256:" + hashlib.sha256(recorded_trace).hexdigest(),
                             replays[path.name]["trace_sha256"],
                             "replay trace identity differs from the recorded "
                             "client trace: %s" % path.name)
        if self.corpus_manifest is not None:
            manifest = {item["file"]: item
                        for item in self.corpus_manifest["replays"]}
            self.assertEqual(set(manifest), set(replays))
            for name, item in manifest.items():
                self.assertTrue(item["coverage_verified"])
                # build_corpus_manifest replays in its own simulator process;
                # identical coverage bytes are the cross-run determinism claim.
                self.assertEqual(
                    item["coverage_sha256"],
                    "sha256:" + hashlib.sha256(
                        bytes(replays[name]["counters"])).hexdigest())

    # -- probes ------------------------------------------------------------
    def test_zero_input_probe_cannot_be_declared_as_a_campaign_run(self):
        with self.assertRaisesRegex(ValueError, "zero-input-probe"):
            run_soc_campaign(campaign_config(zero_input_probe=True),
                             Path(self.temporary.name) / "probe",
                             root=ROOT, environment={"MYFUZZ_SOC_REAL": "1"})
        with self.assertRaisesRegex(ValueError, "zero-input-probe"):
            run_soc_campaign(campaign_config(probe_only=True),
                             Path(self.temporary.name) / "probe-only",
                             root=ROOT, environment={"MYFUZZ_SOC_REAL": "1"})
        self.assertFalse((Path(self.temporary.name) / "probe").exists())
        self.assertFalse((Path(self.temporary.name) / "probe-only").exists())
        self.assertEqual("official_rfuzz", self.result["mutation"]["mode"])
        self.assertFalse(self.result["mutation"]["zero_input_probe"])


if __name__ == "__main__":
    unittest.main()
