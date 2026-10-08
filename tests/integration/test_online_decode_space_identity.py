"""The online run identity records and verifies the decode-space closure.

An online run's evidence is only reproducible while the sources that decide how
raw records become admitted cases are unchanged.  The session manifest binds
what the *executor* runs; this module's tests fix the second, independent
closure: the modules that decide the *decoded payload* (legal instruction
operators, source selection, ownership of fuzzable bits, candidate paths).

Three semantics are pinned here:

* a new run identity records the decode-space fingerprint of the sources it was
  produced with;
* a legacy bundle that does not record it (or records only part of it) is still
  accepted, and the unrecorded paths are reported as ``unknown`` -- never as a
  mismatch;
* a path recorded on both sides with different bytes is refused, and the error
  names the drifted file.
"""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import pytest

from myfuzz.integration.scenario_rfuzz_live import (
    _recorded_session_decode_space, _verify_online_run_identity,
    _write_online_run_identity,
)
from myfuzz.scenario.decode_space import (
    DECODE_SPACE_STATUS_DRIFT, DECODE_SPACE_STATUS_UNKNOWN,
    DECODE_SPACE_STATUS_VERIFIED, ONLINE_DECODE_SPACE_PATHS,
    compare_online_decode_space, online_decode_space_document,
    online_decode_space_sha256, online_decode_space_sources,
    recorded_decode_space,
)
from myfuzz.scenario.replay import ScenarioTrace

ROOT = Path(__file__).resolve().parents[2]
FROZEN_RUN = (ROOT / "runs" /
              "current-dataflow-p5-chain-acceptance-20261007-online")

#: Sources that decide the decode space and were absent from saved identities.
NAMED_DECODE_SOURCES = (
    "src/myfuzz/scenario/rv32i_sources.py",
    "src/myfuzz/scenario/online_case_decoder.py",
    "src/myfuzz/scenario/ibex_pulp_dual_source.py",
)


def _sha(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode()).hexdigest()


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False) + "\n").encode()


def _direct_source_imports(module: Path) -> set[str]:
    """Every ``myfuzz`` module one source file imports directly."""
    tree = ast.parse(module.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level == 1 and node.module:
                found.add("src/myfuzz/scenario/"
                          + node.module.replace(".", "/") + ".py")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("myfuzz."):
                    found.add("src/myfuzz/"
                              + alias.name[len("myfuzz."):].replace(".", "/")
                              + ".py")
    return found


#: Modules whose direct imports are decode inputs by construction.  The
#: declaration module is excluded: it also imports the harness and runner it
#: builds, which execute the decoded payload instead of deciding it.
DECODE_IMPLEMENTATION_MODULES = (
    ROOT / "src" / "myfuzz" / "scenario" / "online_case_decoder.py",
    ROOT / "src" / "myfuzz" / "scenario" / "rv32i_sources.py",
)


class DecodeSpaceClosureTests(unittest.TestCase):
    def test_closure_names_the_sources_that_decide_the_decode_space(self):
        declared = set(ONLINE_DECODE_SPACE_PATHS)
        for name in NAMED_DECODE_SOURCES:
            self.assertIn(name, declared)

    def test_every_declared_closure_path_is_a_real_repository_source(self):
        for name in ONLINE_DECODE_SPACE_PATHS:
            path = ROOT / name
            self.assertTrue(path.is_file(), f"decode space source is missing: {name}")
            self.assertTrue(name.startswith("src/myfuzz/"), name)
        self.assertEqual(len(set(ONLINE_DECODE_SPACE_PATHS)),
                         len(ONLINE_DECODE_SPACE_PATHS))

    def test_closure_covers_every_module_the_decoder_imports_directly(self):
        for module in DECODE_IMPLEMENTATION_MODULES:
            missing = sorted(_direct_source_imports(module)
                             - set(ONLINE_DECODE_SPACE_PATHS))
            self.assertEqual([], missing,
                             f"{module.name} imports decode inputs that are not "
                             "in the decode-space closure; add them to "
                             "ONLINE_DECODE_SPACE_PATHS (or document why they "
                             "cannot decide a decoded case)")

    def test_fingerprint_is_the_canonical_digest_of_the_recorded_sources(self):
        sources = online_decode_space_sources()
        document = online_decode_space_document()
        self.assertEqual([item["path"] for item in sources],
                         list(ONLINE_DECODE_SPACE_PATHS))
        self.assertEqual(list(sources), document["source_files"])
        self.assertEqual(hashlib.sha256(json.dumps(
            {"schema_version": document["schema_version"],
             "source_files": document["source_files"]},
            sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode()).hexdigest(),
            online_decode_space_sha256())
        self.assertEqual(document["sha256"], online_decode_space_sha256())


class DecodeSpaceFingerprintTests(unittest.TestCase):
    """The fingerprint follows real bytes, not a declared constant."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for name in ONLINE_DECODE_SPACE_PATHS:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)

    def tearDown(self):
        self.temporary.cleanup()

    def test_a_changed_source_file_changes_the_fingerprint_and_names_it(self):
        recorded = online_decode_space_document(root=self.root)
        drifted_name = "src/myfuzz/scenario/rv32i_sources.py"
        source = self.root / drifted_name
        source.write_bytes(source.read_bytes() + b"\n# drifted legal operator\n")
        self.assertNotEqual(recorded["sha256"],
                            online_decode_space_sha256(root=self.root))
        comparison = compare_online_decode_space(recorded, root=self.root)
        self.assertEqual(DECODE_SPACE_STATUS_DRIFT, comparison.status)
        self.assertEqual((drifted_name,), comparison.drifted)
        self.assertEqual((), comparison.unrecorded)
        with self.assertRaises(ValueError) as caught:
            comparison.raise_for_drift()
        self.assertIn(drifted_name, str(caught.exception))

    def test_an_unchanged_tree_verifies(self):
        recorded = online_decode_space_document(root=self.root)
        comparison = compare_online_decode_space(recorded, root=self.root)
        self.assertEqual(DECODE_SPACE_STATUS_VERIFIED, comparison.status)
        self.assertEqual((), comparison.drifted)
        self.assertEqual((), comparison.unrecorded)
        comparison.raise_for_drift()

    def test_a_missing_closure_source_is_refused_when_recorded(self):
        (self.root / "src/myfuzz/scenario/genome.py").unlink()
        with self.assertRaises(ValueError) as caught:
            online_decode_space_sources(root=self.root)
        self.assertIn("src/myfuzz/scenario/genome.py", str(caught.exception))


class DecodeSpaceCompatibilityTests(unittest.TestCase):
    """Legacy bundles stay replayable; only a two-sided mismatch refuses."""

    def legacy_comparison(self, record):
        recorded: dict = {"online_source_files": []}
        if record is not None:
            recorded["decode_space"] = record
        return compare_online_decode_space(recorded_decode_space(recorded))

    def test_a_bundle_without_the_record_is_unknown_not_a_mismatch(self):
        comparison = self.legacy_comparison(None)
        self.assertEqual(DECODE_SPACE_STATUS_UNKNOWN, comparison.status)
        self.assertEqual((), comparison.drifted)
        self.assertEqual(tuple(sorted(ONLINE_DECODE_SPACE_PATHS)),
                         comparison.unrecorded)
        comparison.raise_for_drift()
        self.assertEqual(False, comparison.document()["recorded_present"])
        self.assertEqual(sorted(ONLINE_DECODE_SPACE_PATHS),
                         list(comparison.document()["unrecorded"]))

    def test_a_partial_record_marks_only_the_missing_paths_unknown(self):
        sources = {item["path"]: item["sha256"]
                   for item in online_decode_space_sources()}
        partial = {
            "schema_version": "online_decode_space.v1",
            "sha256": "recorded-with-partial-closure",
            "source_files": [{"path": name, "sha256": sources[name]}
                             for name in NAMED_DECODE_SOURCES],
        }
        comparison = self.legacy_comparison(partial)
        self.assertEqual(DECODE_SPACE_STATUS_UNKNOWN, comparison.status)
        self.assertEqual((), comparison.drifted)
        self.assertEqual(tuple(sorted(set(ONLINE_DECODE_SPACE_PATHS)
                                      - set(NAMED_DECODE_SOURCES))),
                         comparison.unrecorded)
        comparison.raise_for_drift()

    def test_a_two_sided_mismatch_refuses_and_names_the_drifted_file(self):
        sources = {item["path"]: item["sha256"]
                   for item in online_decode_space_sources()}
        drifted_name = "src/myfuzz/scenario/online_case_decoder.py"
        self.assertNotEqual("0" * 64, sources[drifted_name])
        record = {
            "schema_version": "online_decode_space.v1",
            "sha256": "recorded-before-drift",
            "source_files": [{"path": name, "sha256": value}
                             for name, value in sources.items()
                             if name != drifted_name]
            + [{"path": drifted_name, "sha256": "0" * 64}],
        }
        comparison = compare_online_decode_space(record)
        self.assertEqual(DECODE_SPACE_STATUS_DRIFT, comparison.status)
        self.assertEqual((drifted_name,), comparison.drifted)
        with self.assertRaises(ValueError) as caught:
            comparison.raise_for_drift()
        self.assertIn(drifted_name, str(caught.exception))
        self.assertIn("0" * 12, str(caught.exception))


class OnlineRunIdentityDecodeSpaceTests(unittest.TestCase):
    """The saved identity carries the fingerprint and replay checks it."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.output = Path(self.temporary.name)
        (self.output / "decoder_manifest.json").write_text(
            '{"graph":{"rules":[]},"schema_version":"decoder.v1"}\n')
        (self.output / "targets.json").write_text('[{"target_id":"irq"}]\n')
        (self.output / "rfuzz.toml").write_text('[general]\nfilename = "plan"\n')
        (self.output / "seed.bin").write_bytes(b"seed")
        self.plan = b'{"schema_version":1,"cases":[]}\n'
        (self.output / "online_plan.json").write_bytes(self.plan)
        self.manifest = {
            "schema_version": "online_session_manifest.v1",
            "runner": {"sessions": {"cpu": {"identity": {"build_identity": {}}}}},
            "online_source_files": [],
            "checker": None,
        }
        self.trace = self.record_session_sources([])

    def record_session_sources(self, entries) -> ScenarioTrace:
        """Record session-manifest sources, as a saved bundle would."""
        self.manifest["online_source_files"] = list(entries)
        self.trace = ScenarioTrace(
            hashlib.sha256(self.plan).hexdigest(), "complete", [], {"cpu": 1},
            "semantic-hash", _sha(self.manifest))
        (self.output / "online_final_trace.json").write_text(json.dumps({
            "genome_sha256": self.trace.genome_sha256,
            "status": self.trace.status,
            "events": list(self.trace.events),
            "local_ticks": self.trace.local_ticks,
            "semantic_sha256": self.trace.semantic_sha256,
            "manifest_sha256": self.trace.manifest_sha256,
        }, sort_keys=True, separators=(",", ":")) + "\n")
        return self.trace

    def tearDown(self):
        self.temporary.cleanup()

    def write_identity(self) -> str:
        return _write_online_run_identity(
            self.output, session_manifest=self.manifest, plan_bytes=self.plan,
            trace=self.trace, client_binary=self._client_binary(),
            run_config={"duration_seconds": 1, "max_tests": 2,
                        "search_seed": 3, "max_runs_per_batch": 1})

    def _client_binary(self) -> Path:
        binary = self.output / "kfuzz"
        if not binary.exists():
            binary.write_bytes(b"rfuzz-client")
        return binary

    def read_identity(self) -> dict:
        envelope = json.loads((self.output / "online_run_identity.json").read_bytes())
        return envelope["identity"]

    def reseal(self, mutate) -> str:
        path = self.output / "online_run_identity.json"
        envelope = json.loads(path.read_bytes())
        mutate(envelope["identity"])
        envelope["sha256"] = _sha(envelope["identity"])
        path.write_bytes(_canonical(envelope))
        return envelope["sha256"]

    def verify(self) -> dict | None:
        return _verify_online_run_identity(
            self.output, plan_path=self.output / "online_plan.json",
            trace_path=self.output / "online_final_trace.json",
            trace=self.trace)

    def test_a_new_identity_records_the_current_decode_space(self):
        identity_sha256 = self.write_identity()
        identity = self.read_identity()
        self.assertEqual(online_decode_space_document(), identity["decode_space"])
        document = json.loads((self.output / "online_run_identity.json").read_bytes())
        self.assertEqual(identity_sha256, document["sha256"])
        self.assertEqual(identity_sha256, _sha(identity))
        without = {key: value for key, value in identity.items()
                   if key != "decode_space"}
        self.assertNotEqual(identity_sha256, _sha(without))

    def test_the_recorded_decode_space_verifies_against_the_sources(self):
        self.write_identity()
        verified = self.verify()
        self.assertEqual(DECODE_SPACE_STATUS_VERIFIED,
                         verified["decode_space_status"]["status"])

    def test_a_legacy_identity_without_the_record_still_verifies_as_unknown(self):
        self.write_identity()
        self.reseal(lambda identity: identity.pop("decode_space"))
        verified = self.verify()
        status = verified["decode_space_status"]
        self.assertEqual(DECODE_SPACE_STATUS_UNKNOWN, status["status"])
        self.assertEqual([], list(status["drifted"]))
        self.assertEqual(sorted(ONLINE_DECODE_SPACE_PATHS),
                         sorted(status["unrecorded"]))

    def test_a_recorded_drifted_decode_source_is_refused_by_name(self):
        self.write_identity()
        drifted_name = "src/myfuzz/scenario/rv32i_sources.py"

        def drift(identity):
            for item in identity["decode_space"]["source_files"]:
                if item["path"] == drifted_name:
                    item["sha256"] = "0" * 64

        self.reseal(drift)
        with self.assertRaises(ValueError) as caught:
            self.verify()
        self.assertIn("decode space", str(caught.exception))
        self.assertIn(drifted_name, str(caught.exception))

    def test_a_legacy_session_manifest_entry_is_a_two_sided_claim(self):
        """A pre-record bundle still names a decode source its manifest bound."""
        drifted_name = "src/myfuzz/scenario/rv32i_sources.py"
        self.record_session_sources(({"path": drifted_name,
                                      "sha256": "0" * 64},))
        self.write_identity()
        self.reseal(lambda identity: identity.pop("decode_space"))
        with self.assertRaises(ValueError) as caught:
            self.verify()
        self.assertIn("decode space", str(caught.exception))
        self.assertIn(drifted_name, str(caught.exception))

    def test_a_legacy_session_manifest_matching_entry_stays_unknown(self):
        sources = {item["path"]: item["sha256"]
                   for item in online_decode_space_sources()}
        recorded_name = "src/myfuzz/scenario/ibex_pulp_dual_source.py"
        self.record_session_sources(({"path": recorded_name,
                                      "sha256": sources[recorded_name]},))
        self.write_identity()
        self.reseal(lambda identity: identity.pop("decode_space"))
        status = self.verify()["decode_space_status"]
        self.assertEqual(DECODE_SPACE_STATUS_UNKNOWN, status["status"])
        self.assertEqual([], list(status["drifted"]))
        self.assertNotIn(recorded_name, status["unrecorded"])
        self.assertIn("src/myfuzz/scenario/rv32i_sources.py",
                      status["unrecorded"])


@pytest.mark.skipif(not (FROZEN_RUN / "online_run_identity.json").is_file(),
                    reason="the frozen real continuous run directory is absent")
def test_frozen_legacy_identity_names_its_drifted_decode_sources():
    """The real 20261007 bundle refuses by name, not behind a generic message.

    The frozen identity has no ``decode_space`` member, but its session
    manifest already recorded the decode sources, so the two-sided mismatch is
    reported by file.  Without this check the same bundle fails later on a
    drifted host source and the decode drift stays invisible.
    """
    identity = json.loads(
        (FROZEN_RUN / "online_run_identity.json").read_bytes())["identity"]
    if identity.get("trace_format") != "json.v1":
        pytest.skip("the frozen run does not use the json.v1 trace format")
    assert recorded_decode_space(identity) is None
    comparison = compare_online_decode_space(
        _recorded_session_decode_space(FROZEN_RUN))
    if not comparison.drifted:
        pytest.skip("the frozen run's decode sources still match this tree")
    assert "src/myfuzz/scenario/rv32i_sources.py" in comparison.drifted
    trace = ScenarioTrace(
        identity["trace"]["genome_sha256"], identity["trace"]["status"], [],
        identity["trace"]["local_ticks"], identity["trace"]["semantic_sha256"],
        identity["trace"]["manifest_sha256"])
    with pytest.raises(ValueError) as caught:
        _verify_online_run_identity(
            FROZEN_RUN, plan_path=FROZEN_RUN / "online_plan.json",
            trace_path=FROZEN_RUN / "online_final_trace.json", trace=trace)
    assert "online decode space source identity mismatch" in str(caught.value)
    for name in comparison.drifted:
        assert name in str(caught.value)


@pytest.mark.skipif(
    not (FROZEN_RUN / "online_session_manifest.json").is_file(),
    reason="the frozen real continuous run directory is absent")
def test_a_rebuilt_frozen_identity_reports_every_drifted_decode_source():
    """A run recorded today from the frozen manifest names its drift exactly."""
    manifest = json.loads(
        (FROZEN_RUN / "online_session_manifest.json").read_bytes())
    recorded = {item["path"]: item["sha256"]
                for item in manifest["online_source_files"]}
    record = {
        "schema_version": "online_decode_space.v1",
        "sha256": "recorded-by-the-frozen-run",
        "source_files": [{"path": name, "sha256": recorded[name]}
                         for name in ONLINE_DECODE_SPACE_PATHS
                         if name in recorded],
    }
    comparison = compare_online_decode_space(record)
    if not comparison.drifted:
        pytest.skip("the frozen run's decode sources still match this tree")
    with pytest.raises(ValueError) as caught:
        comparison.raise_for_drift()
    for name in comparison.drifted:
        assert name in str(caught.value)
    assert "src/myfuzz/scenario/rv32i_sources.py" in comparison.drifted


if __name__ == "__main__":
    unittest.main()
