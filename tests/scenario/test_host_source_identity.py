"""Host Python source identity is checked before fresh RTL replay."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.host_identity import host_source_identity, verify_host_source_identity
from tests.scenario.test_evidence_bundle import EvidenceBundleTests


class HostSourceIdentityTests(unittest.TestCase):
    def test_explicit_list_covers_runtime_and_replay_modules(self):
        identity = host_source_identity()
        paths = {item["path"] for item in identity["files"]}
        for path in ("src/myfuzz/scenario/runner.py",
                     "src/myfuzz/scenario/scheduler.py",
                     "src/myfuzz/scenario/router.py",
                     "src/myfuzz/scenario/memory.py",
                     "src/myfuzz/scenario/ownership.py",
                     "src/myfuzz/scenario/genome.py",
                     "src/myfuzz/scenario/replay.py",
                     "src/myfuzz/scenario/irq.py",
                     "src/myfuzz/scenario/checker.py",
                     "src/myfuzz/scenario/feedback.py",
                     "src/myfuzz/scenario/evidence.py",
                     "src/myfuzz/scenario/ibex_session.py",
                     "src/myfuzz/scenario/cva6_session.py",
                     "src/myfuzz/scenario/gpio_session.py"):
            self.assertIn(path, paths)
        self.assertEqual(identity, verify_host_source_identity(identity))

    def test_replay_rejects_changed_host_source_before_factory(self):
        fixture = EvidenceBundleTests()
        fixture.setUp()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            save_evidence_bundle(fixture.genome, fixture.factory, output)
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertIn("host_sources", manifest)
            before = len(fixture.instances)
            with patch("myfuzz.scenario.host_identity._hash_file",
                       return_value="0" * 64):
                with self.assertRaisesRegex(ValueError, "host source.*sha256"):
                    replay_evidence_bundle(output, fixture.factory)
            self.assertEqual(before, len(fixture.instances))


if __name__ == "__main__":
    unittest.main()
