"""Stored port evidence: reuse is only accepted when both sources agree.

These tests are hermetic: a two-port component is written into a temporary
directory together with a ``source_manifest.json`` / evidence file in the shape
the derived Chipyard component publishes, so the reader is exercised without the
18 MB BOOM top and without a Verilator frontend run.
"""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from myfuzz.composition.component_profile import (
    ComponentProfileError, elaborate_profile, load_component_profile,
)
from myfuzz.composition.source_crawler import _content_hash
from myfuzz.composition.stored_elaboration import (
    EVIDENCE_SOURCE, StoredElaborationError, stored_elaboration_facts,
)

TOP = """\
module demo_top(
  input         clock,
  input         reset,
  output        bus_valid,
  output [7:0]  bus_data,
  input  [3:0]  bus_size,
  output        bus_signed_probe
);
  assign bus_valid = 1'b0;
  assign bus_data = 8'b0;
  assign bus_signed_probe = 1'b0;
endmodule
"""

#: One port whose declared width is wrong on purpose, never used by the happy
#: path: it exists to prove the two evidence sources must agree exactly.
PROFILE = {
    "schema_version": "component_profile.v1",
    "component_id": "demo",
    "kind": "cpu",
    "source": {
        "root": "configs/demo/generated",
        "files": ["demo_top.v"],
        "top_module": "demo_top",
        "top_port_selection": "all",
    },
    "clocks": [{"port": "clock", "domain": "core", "frequency_hz": 1000000}],
    "resets": [{"port": "reset", "domain": "core", "polarity": "active_high",
                   "synchronous": False}],
    "cpu": {"family": "riscv", "xlen": 32, "extensions": ["i"],
            "master_endpoints": ["cpu.bus"], "reset_vector": 0,
            "boot_address_required": False},
    "endpoints": [{
        "endpoint_id": "cpu.bus",
        "function": "memory_master",
        "protocol": ["demo-bus", "1"],
        "fields": [
            {"role": "valid", "aliases": ["bus_valid"]},
            {"role": "data", "aliases": ["bus_data"]},
            {"role": "size", "aliases": ["bus_size"]},
        ],
    }],
}


def _evidence_rows(text: str) -> list[dict[str, object]]:
    """The physical port rows the pinned text declares (name/direction/width)."""
    return [
        {"name": "clock", "direction": "input", "width": 1, "packed_range": None},
        {"name": "reset", "direction": "input", "width": 1, "packed_range": None},
        {"name": "bus_valid", "direction": "output", "width": 1, "packed_range": None},
        {"name": "bus_data", "direction": "output", "width": 8, "packed_range": "7:0"},
        {"name": "bus_size", "direction": "input", "width": 4, "packed_range": "3:0"},
        {"name": "bus_signed_probe", "direction": "output", "width": 1, "packed_range": None},
    ] if text else []


class StoredElaborationTest(unittest.TestCase):
    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory(prefix="myfuzz-stored-")
        self.root = Path(self._temporary.name)
        (self.root / "configs" / "demo").mkdir(parents=True)
        (self.root / "configs" / "demo" / "generated").mkdir()
        (self.root / "configs" / "demo" / "evidence").mkdir()
        (self.root / "configs" / "demo" / "generated" / "demo_top.v").write_text(TOP, encoding="utf-8")
        self.revision = _content_hash({"demo_top.v": TOP.encode("utf-8")})
        self.profile_path = self.root / "configs" / "demo" / "component_profile.json"
        document = json.loads(json.dumps(PROFILE))
        document["source"]["revision"] = self.revision
        self.profile_path.write_text(json.dumps(document), encoding="utf-8")
        self._declare(revision=self.revision, rows=_evidence_rows("all"))

    def tearDown(self):
        self._temporary.cleanup()

    # -- fixture helpers ---------------------------------------------------
    def _declare(self, *, revision: str, rows: list[dict[str, object]],
                 files: tuple[str, ...] = ("demo_top.v",)) -> None:
        evidence = {
            "derived_source": True,
            "configuration": "demo",
            "semantic_adapter_verified": False,
            "modules": {"demo_top": {"file": "demo_top.v", "ports": rows}},
        }
        payload = json.dumps(evidence, indent=2).encode("utf-8")
        (self.root / "configs" / "demo" / "evidence" / "ports.json").write_bytes(payload)
        from hashlib import sha256
        manifest = {
            "schema_version": "demo_generated_source.v1",
            "derived_source": True,
            "files": [{"path": name, "bytes": len((self.root / "configs" / "demo" / "generated" / name).read_bytes())}
                      for name in files],
            "top_module": "demo_top",
            "physical_ports": "../evidence/ports.json",
            "physical_ports_sha256": sha256(payload).hexdigest(),
            "revision": revision,
        }
        (self.root / "configs" / "demo" / "generated" / "source_manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    def _profile(self, **overrides):
        document = json.loads(self.profile_path.read_text(encoding="utf-8"))
        document.update(overrides)
        return load_component_profile(document)

    # -- the accepted path -------------------------------------------------
    def test_reuse_returns_text_positions_and_provenance(self):
        facts = stored_elaboration_facts(self._profile(), base_dir=self.root)
        self.assertIsNotNone(facts)
        self.assertEqual(facts.evidence_source, EVIDENCE_SOURCE)
        self.assertEqual(len(facts.evidence_sha256), 64)
        self.assertEqual(facts.selection, "all")
        self.assertEqual([port.name for port in facts.ports],
                         ["clock", "reset", "bus_valid", "bus_data", "bus_size",
                          "bus_signed_probe"])
        data = facts.port("bus_data")
        # Positions and signedness come from the pinned source text, not the
        # stored artifact (which does not record either).
        self.assertEqual((data.width, data.signed, data.source_file), (8, False, "demo_top.v"))
        self.assertGreater(data.line, 1)
        self.assertEqual(facts.revision, self._profile().source.revision)

    def test_auto_mode_prefers_stored_evidence_without_a_frontend(self):
        facts = elaborate_profile(self._profile(), base_dir=self.root)
        self.assertEqual(facts.evidence_source, EVIDENCE_SOURCE)
        self.assertEqual(len(facts.ports), 6)

    def test_component_without_evidence_keeps_the_frontend_path(self):
        (self.root / "configs" / "demo" / "generated" / "source_manifest.json").unlink()
        self.assertIsNone(stored_elaboration_facts(self._profile(), base_dir=self.root))

    def test_naming_the_stored_mode_requires_declared_evidence(self):
        (self.root / "configs" / "demo" / "generated" / "source_manifest.json").unlink()
        with self.assertRaisesRegex(ComponentProfileError,
                                    "stored-evidence-not-declared:demo"):
            elaborate_profile(self._profile(), base_dir=self.root, mode="stored")

    # -- every refusal path ------------------------------------------------
    def test_evidence_digest_mismatch_is_refused(self):
        manifest = json.loads((self.root / "configs" / "demo" / "generated" /
                               "source_manifest.json").read_text(encoding="utf-8"))
        manifest["physical_ports_sha256"] = "0" * 64
        (self.root / "configs" / "demo" / "generated" / "source_manifest.json").write_text(
            json.dumps(manifest) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(StoredElaborationError, "stored-evidence-digest-mismatch"):
            stored_elaboration_facts(self._profile(), base_dir=self.root)
        with self.assertRaisesRegex(ComponentProfileError,
                                    "elaboration-evidence-error:demo:stored-evidence-digest-mismatch"):
            elaborate_profile(self._profile(), base_dir=self.root)

    def test_manifest_for_another_revision_is_refused(self):
        self._declare(revision="sha256:" + "1" * 64, rows=_evidence_rows("all"))
        with self.assertRaisesRegex(StoredElaborationError, "stored-evidence-revision-mismatch"):
            stored_elaboration_facts(self._profile(), base_dir=self.root)

    def test_changed_source_bytes_are_refused(self):
        (self.root / "configs" / "demo" / "generated" / "demo_top.v").write_text(
            TOP.replace("8'b0", "8'b1"), encoding="utf-8")
        self._declare(revision=self.revision, rows=_evidence_rows("all"))
        with self.assertRaisesRegex(StoredElaborationError, "stored-evidence-source-mismatch"):
            stored_elaboration_facts(self._profile(), base_dir=self.root)

    def test_stored_port_that_the_text_does_not_declare_is_refused(self):
        rows = _evidence_rows("all") + [
            {"name": "phantom", "direction": "input", "width": 1, "packed_range": None}]
        self._declare(revision=self.revision, rows=rows)
        with self.assertRaisesRegex(StoredElaborationError,
                                    "stored-evidence-port-mismatch:demo"):
            stored_elaboration_facts(self._profile(), base_dir=self.root)

    def test_stored_width_that_disagrees_with_the_text_is_refused(self):
        rows = [dict(row) for row in _evidence_rows("all")]
        rows[3] = {"name": "bus_data", "direction": "output", "width": 16, "packed_range": "15:0"}
        self._declare(revision=self.revision, rows=rows)
        with self.assertRaisesRegex(StoredElaborationError,
                                    "stored-evidence-port-mismatch:demo"):
            stored_elaboration_facts(self._profile(), base_dir=self.root)

    def test_evidence_outside_the_component_directory_is_refused(self):
        outside = self.root / "elsewhere.json"
        outside.write_text("{}", encoding="utf-8")
        manifest = json.loads((self.root / "configs" / "demo" / "generated" /
                               "source_manifest.json").read_text(encoding="utf-8"))
        manifest["physical_ports"] = "../../elsewhere.json"
        (self.root / "configs" / "demo" / "generated" / "source_manifest.json").write_text(
            json.dumps(manifest) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(StoredElaborationError,
                                    "outside-component-directory"):
            stored_elaboration_facts(self._profile(), base_dir=self.root)

    def test_absolute_evidence_path_is_refused(self):
        manifest = json.loads((self.root / "configs" / "demo" / "generated" /
                               "source_manifest.json").read_text(encoding="utf-8"))
        manifest["physical_ports"] = "/etc/passwd"
        (self.root / "configs" / "demo" / "generated" / "source_manifest.json").write_text(
            json.dumps(manifest) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(StoredElaborationError,
                                    "stored-evidence-declaration-invalid:absolute-path"):
            stored_elaboration_facts(self._profile(), base_dir=self.root)

    def test_stored_module_must_be_the_declared_top(self):
        rows = _evidence_rows("all")
        self._declare(revision=self.revision, rows=rows)
        evidence = json.loads((self.root / "configs" / "demo" / "evidence" /
                              "ports.json").read_text(encoding="utf-8"))
        evidence["modules"] = {"other_top": evidence["modules"]["demo_top"]}
        payload = json.dumps(evidence).encode("utf-8")
        (self.root / "configs" / "demo" / "evidence" / "ports.json").write_bytes(payload)
        from hashlib import sha256
        manifest = json.loads((self.root / "configs" / "demo" / "generated" /
                               "source_manifest.json").read_text(encoding="utf-8"))
        manifest["physical_ports_sha256"] = sha256(payload).hexdigest()
        (self.root / "configs" / "demo" / "generated" / "source_manifest.json").write_text(
            json.dumps(manifest) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(StoredElaborationError,
                                    "stored-evidence-module-missing:demo_top"):
            stored_elaboration_facts(self._profile(), base_dir=self.root)


if __name__ == "__main__":
    unittest.main()
