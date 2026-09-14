"""Offline P1 provenance regression tests; no compiler or network required."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/verify_soc_sources.py"


class SourceLockTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), "P1 verifier has not been implemented")
        spec = importlib.util.spec_from_file_location("soc_sources", SCRIPT)
        self.verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.verifier)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.repo = self.base / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "P1 test")
        (self.repo / "top.sv").write_text("module top(input logic clk); endmodule\n")
        (self.repo / "LICENSE").write_text("Test fixture license\n")
        self.git("add", ".")
        self.git("commit", "-qm", "first")
        self.record = {"id": "fixture", "source": {"root": "repo", "revision": "git:" + self.git("rev-parse", "HEAD"), "top_module": "top", "files": ["top.sv"], "include_roots": [], "repositories": []}, "artifacts": [], "closure_status": "selected", "source_status": "source_verified", "elaboration_status": "elaboration_unverified", "runtime_status": "runtime_unverified"}
        self.refresh()

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], text=True, stderr=subprocess.STDOUT).strip()

    def refresh(self):
        self.record["artifacts"] = [{"path": p, "sha256": hashlib.sha256((self.repo / p).read_bytes()).hexdigest(), "kind": "license" if p == "LICENSE" else "source"} for p in ["top.sv", "LICENSE"]]
        from myfuzz.composition.source_crawler import source_tree_hash
        self.record["selected_content_hash"] = source_tree_hash(self.repo, [self.repo / "top.sv"])

    def verify(self):
        return self.verifier.verify_record(self.record, self.base)

    def enable_elaboration(self, **changes):
        """Record a validated elaboration claim backed by an evidence document."""
        closure = {
            "schema_version": "soc_elaboration_closure.v1",
            "component": "fixture",
            "root": "repo",
            "top_module": "top",
            "tool": {"name": "verilator", "version": "Verilator test", "frontend": "verilator-lint"},
            "command": ["verilator", "--lint-only", "-Wno-fatal", "--top-module", "top", "repo/top.sv"],
            "include_roots": [], "defines": [], "parameters": [],
            "closure_files": [{"root": "repo", "path": "top.sv",
                               "sha256": hashlib.sha256((self.repo / "top.sv").read_bytes()).hexdigest()}],
            "status": "elaboration_verified",
            "lint": {"errors": 0, "warnings": 1, "exit_code": 0, "log": "log.txt"},
            "capability_findings": [], "unsupported": [],
        }
        closure.update(changes)
        evidence = self.base / "closure.json"
        evidence.write_text(json.dumps(closure))
        self.record["elaboration_status"] = "elaboration_verified"
        self.record["elaboration"] = {
            "status": "elaboration_verified",
            "top_module": closure["top_module"],
            "tool": closure["tool"],
            "evidence": "closure.json",
            "evidence_sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
            "closure_files": len(closure["closure_files"]),
            "lint": {k: closure["lint"][k] for k in ("errors", "warnings", "exit_code")},
        }
        return evidence

    def rewrite_closure(self, evidence, closure):
        evidence.write_text(json.dumps(closure))
        self.record["elaboration"]["evidence_sha256"] = hashlib.sha256(
            evidence.read_bytes()).hexdigest()

    def test_clean_selected_sources_and_untracked_manifest(self):
        (self.repo / "manifest.json").write_text(json.dumps(self.record))
        self.assertEqual("source_verified", self.verify()["source_status"])

    def test_wrong_revision_even_if_both_commits_exist(self):
        self.git("commit", "--allow-empty", "-qm", "second")
        with self.assertRaisesRegex(ValueError, "git-revision-mismatch"):
            self.verify()

    def test_typed_ports_defer_only_parsing_not_provenance(self):
        (self.repo / "top.sv").write_text("module top(input bus_t bus); endmodule\n")
        self.git("add", "top.sv")
        self.git("commit", "-qm", "typed port")
        self.record["source"]["revision"] = "git:" + self.git("rev-parse", "HEAD")
        self.refresh()
        self.assertEqual("parameterized_ports_pending_elaboration", self.verify()["parse_status"])
        (self.repo / "top.sv").write_text("module top(input other_t bus); endmodule\n")
        self.refresh()
        with self.assertRaisesRegex(ValueError, "git-content-mismatch"):
            self.verify()

    def test_source_symlink_rejected(self):
        (self.repo / "alias.sv").symlink_to("top.sv")
        self.record["source"]["files"] = ["alias.sv"]
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.verify()

    def test_dirty_selected_source_even_with_updated_hash(self):
        (self.repo / "top.sv").write_text("module top(input logic reset); endmodule\n")
        self.refresh()
        with self.assertRaisesRegex(ValueError, "git-content-mismatch"):
            self.verify()

    def test_missing_nested_pin(self):
        nested = self.repo / "child"
        nested.mkdir()
        for args in [("init", "-q"), ("config", "user.email", "test@example.invalid"), ("config", "user.name", "P1 test")]:
            subprocess.run(["git", "-C", str(nested), *args], check=True)
        (nested / "child.sv").write_text("module child; endmodule\n")
        subprocess.run(["git", "-C", str(nested), "add", "."], check=True)
        subprocess.run(["git", "-C", str(nested), "commit", "-qm", "child"], check=True)
        self.git("add", "child")
        self.git("commit", "-qm", "nested")
        self.record["source"]["revision"] = "git:" + self.git("rev-parse", "HEAD")
        self.record["source"]["files"].append("child/child.sv")
        with self.assertRaisesRegex(ValueError, "git-content-mismatch"):
            self.verify()

    def test_modified_license_rejected(self):
        (self.repo / "LICENSE").write_text("different license")
        self.refresh()
        with self.assertRaisesRegex(ValueError, "git-content-mismatch"):
            self.verify()

    def test_missing_license_record_rejected(self):
        self.record["artifacts"] = self.record["artifacts"][:1]
        with self.assertRaisesRegex(ValueError, "license"):
            self.verify()

    def test_pending_cannot_be_promoted(self):
        self.record["closure_status"] = "pending"
        with self.assertRaisesRegex(ValueError, "pending"):
            self.verify()

    def test_interface_description_hash_is_bound(self):
        (self.base / "interface.json").write_text("{}")
        self.record["interface_description"] = "interface.json"
        self.record["interface_description_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "interface-description-hash"):
            self.verify()

    def test_missing_cross_repository_dependency_rejected(self):
        self.assertTrue(hasattr(self.verifier, "validate_document"), "lock dependency validation missing")
        self.record["dependencies"] = ["missing_spi_dependency"]
        with self.assertRaisesRegex(ValueError, "missing-source-dependency"):
            self.verifier.validate_document({"schema_version": "soc_sources.v1", "components": [self.record]})

    def test_wrong_packed_coordinates_reuse_existing_contract_validator(self):
        from myfuzz.contracts import ContractError, validate_contract
        from tests.contracts.test_interface_contracts import valid_annotation_document
        doc = valid_annotation_document()
        field = doc["endpoints"][0]["fields"][0]
        field.update(member_path=["valid"], raw_lo=0, raw_hi=0, container_width=1,
                     evidence=["explicit_member", "compiler_elaboration"])
        validate_contract(doc, "interface_annotations.v1")
        field["raw_hi"] = 1
        with self.assertRaisesRegex(ContractError, "invalid-member-range"):
            validate_contract(doc, "interface_annotations.v1")

    def test_manifest_has_all_components_and_separate_statuses(self):
        lock = ROOT / "configs/soc/sources.lock.json"
        self.assertTrue(lock.is_file(), "P1 lock missing")
        doc = json.loads(lock.read_text())
        self.assertEqual("soc_sources.v1", doc["schema_version"])
        self.assertEqual({"ibex", "cva6", "opentitan_uart", "opentitan_gpio", "pulp_gpio", "pulp_spi", "pulp_spi_dependencies", "zipcpu_uart", "zipcpu_timer"}, {r["id"] for r in doc["components"]})
        for record in doc["components"]:
            self.assertRegex(record["source"]["revision"], r"^git:[0-9a-f]{40}$")
            self.assertEqual("runtime_unverified", record["runtime_status"])
        for family in ("opentitan", "pulp", "zipcpu"):
            data = json.loads((ROOT / f"configs/soc/families/{family}.json").read_text())
            self.assertEqual("soc_family.v1", data["schema_version"])
            self.assertEqual(2, len(data["peripherals"]))
            for ip in data["peripherals"]:
                self.assertTrue(ip["capabilities"])
                for capability in ip["capabilities"]:
                    for key in ("input", "output", "provenance", "runtime_status"):
                        self.assertIn(key, capability)

    def test_verified_elaboration_requires_the_evidence_document(self):
        self.record["elaboration_status"] = "elaboration_verified"
        with self.assertRaisesRegex(ValueError, "unsupported-verification-claim"):
            self.verify()

    def test_unverified_elaboration_cannot_ship_evidence(self):
        self.enable_elaboration()
        self.record["elaboration_status"] = "elaboration_unverified"
        with self.assertRaisesRegex(ValueError, "unsupported-verification-claim"):
            self.verify()

    def test_valid_elaboration_claim_verifies(self):
        self.enable_elaboration()
        result = self.verify()
        self.assertEqual("elaboration_verified", result["elaboration_status"])
        self.assertEqual(1, result["elaboration"]["closure_files"])
        self.assertEqual(["repo"], result["elaboration"]["closure_roots"])

    def test_tampered_evidence_document_is_rejected(self):
        evidence = self.enable_elaboration()
        closure = json.loads(evidence.read_text())
        closure["lint"]["errors"] = 0
        closure["top_module"] = "other"
        evidence.write_text(json.dumps(closure))
        with self.assertRaisesRegex(ValueError, "elaboration-evidence-hash-mismatch"):
            self.verify()

    def test_closure_file_hash_is_bound_to_disk_bytes(self):
        evidence = self.enable_elaboration()
        closure = json.loads(evidence.read_text())
        closure["closure_files"][0]["sha256"] = "0" * 64
        self.rewrite_closure(evidence, closure)
        with self.assertRaisesRegex(ValueError, "closure-hash-mismatch"):
            self.verify()

    def test_closure_file_must_match_the_pinned_git_blob(self):
        evidence = self.enable_elaboration()
        (self.repo / "top.sv").write_text("module top(input logic clk); endmodule // edited\n")
        closure = json.loads(evidence.read_text())
        closure["closure_files"][0]["sha256"] = hashlib.sha256(
            (self.repo / "top.sv").read_bytes()).hexdigest()
        self.rewrite_closure(evidence, closure)
        with self.assertRaisesRegex(ValueError, "git-content-mismatch"):
            self.verify()

    def test_closure_root_must_be_pinned(self):
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "extra.sv").write_text("module extra; endmodule\n")
        evidence = self.enable_elaboration(
            closure_files=[{"root": "outside", "path": "extra.sv",
                            "sha256": hashlib.sha256((outside / "extra.sv").read_bytes()).hexdigest()}])
        self.record["elaboration"]["closure_files"] = 1
        with self.assertRaisesRegex(ValueError, "unpinned-closure-root"):
            self.verify()

    def test_command_sources_must_all_be_in_the_closure(self):
        self.enable_elaboration(
            command=["verilator", "--lint-only", "--top-module", "top", "repo/top.sv", "repo/LICENSE"])
        with self.assertRaisesRegex(ValueError, "command-file-not-in-closure"):
            self.verify()

    def test_command_top_must_match_the_closure_top(self):
        self.enable_elaboration(
            command=["verilator", "--lint-only", "--top-module", "other", "repo/top.sv"])
        with self.assertRaisesRegex(ValueError, "elaboration-command-top-mismatch"):
            self.verify()

    def test_failed_elaboration_lint_cannot_be_claimed_verified(self):
        self.enable_elaboration(lint={"errors": 1, "warnings": 0, "exit_code": 1, "log": "log.txt"})
        self.record["elaboration"]["lint"] = {"errors": 1, "warnings": 0, "exit_code": 1}
        with self.assertRaisesRegex(ValueError, "elaboration-lint-failed"):
            self.verify()

    def test_lock_lint_summary_must_match_the_evidence(self):
        self.enable_elaboration()
        self.record["elaboration"]["lint"]["warnings"] = 99
        with self.assertRaisesRegex(ValueError, "elaboration-lint-mismatch"):
            self.verify()

    def test_empty_elaboration_closure_is_rejected(self):
        self.enable_elaboration(closure_files=[])
        self.record["elaboration"]["closure_files"] = 0
        with self.assertRaisesRegex(ValueError, "empty-elaboration-closure"):
            self.verify()


    def test_duplicate_closure_entries_are_rejected(self):
        evidence = self.enable_elaboration()
        closure = json.loads(evidence.read_text())
        closure['closure_files'].append(dict(closure['closure_files'][0]))
        self.record['elaboration']['closure_files'] = 2
        self.rewrite_closure(evidence, closure)
        with self.assertRaisesRegex(ValueError, 'duplicate-closure-entry'):
            self.verify()

    def test_closure_top_must_match_the_declared_source_top(self):
        self.enable_elaboration()
        self.record['source']['top_module'] = 'other_top'
        with self.assertRaisesRegex(ValueError, 'elaboration-source-top-mismatch'):
            self.verify()

    def test_closure_root_must_be_a_declared_dependency(self):
        outside = self.base / 'other'
        outside.mkdir()
        (outside / 'extra.sv').write_text('module extra; endmodule\n')
        evidence = self.enable_elaboration(closure_files=[{
            'root': 'other', 'path': 'extra.sv',
            'sha256': hashlib.sha256((outside / 'extra.sv').read_bytes()).hexdigest()}])
        self.record['elaboration']['closure_files'] = 1
        document = {'components': [
            self.record,
            {'id': 'unrelated', 'source': {'root': 'other', 'revision': 'git:' + 'a' * 40}},
        ]}
        owners = self.verifier.document_owners(document, self.base)
        allowed = self.verifier.document_roots(document)
        with self.assertRaisesRegex(ValueError, 'undeclared-closure-root'):
            self.verifier.verify_record(self.record, self.base, owners=owners,
                                        allowed_roots=allowed['fixture'])
        self.assertTrue(evidence.exists())

    def test_lock_parameters_must_match_the_elaborated_parameters(self):
        self.record['typed_parameters'] = [{'name': 'WIDTH', 'type': 'integer', 'value': '99'}]
        self.enable_elaboration(parameters=[{'name': 'WIDTH', 'value': '32'}])
        with self.assertRaisesRegex(ValueError, 'elaboration-parameter-mismatch'):
            self.verify()

    def test_declared_parameter_must_appear_in_the_closure(self):
        self.record['typed_parameters'] = [{'name': 'EXTRA', 'type': 'integer', 'value': '1'}]
        self.enable_elaboration()
        with self.assertRaisesRegex(ValueError, 'lock-parameter-not-elaborated'):
            self.verify()

    def test_include_root_outside_the_pinned_sources_is_rejected(self):
        (self.base / 'evil').mkdir()
        (self.base / 'evil' / 'prim_assert.sv').write_text('// poisoned header\n')
        self.enable_elaboration(command=[
            'verilator', '--lint-only', '--top-module', 'top', '-Ievil', 'repo/top.sv'])
        with self.assertRaisesRegex(ValueError, 'include-root-outside-pinned-sources'):
            self.verify()

    def test_repeated_top_module_option_is_rejected(self):
        self.enable_elaboration(command=[
            'verilator', '--lint-only', '--top-module', 'top',
            '--top-module', 'other', 'repo/top.sv'])
        with self.assertRaisesRegex(ValueError, 'elaboration-command-top-count'):
            self.verify()

    def test_evidence_must_be_under_version_control(self):
        self.enable_elaboration()
        for args in (('init', '-q'), ('config', 'user.email', 't@example.invalid'),
                     ('config', 'user.name', 'P1 test')):
            subprocess.run(['git', '-C', str(self.base), *args], check=True, capture_output=True)
        with self.assertRaisesRegex(ValueError, 'untracked-elaboration-evidence'):
            self.verify()
        subprocess.run(['git', '-C', str(self.base), 'add', 'closure.json'], check=True)
        subprocess.run(['git', '-C', str(self.base), 'commit', '-qm', 'evidence'],
                       check=True, capture_output=True)
        self.assertEqual('source_verified', self.verify()['source_status'])

    def test_real_lock_binds_parameters_and_roots_to_the_closures(self):
        document = json.loads((ROOT / "configs/soc/sources.lock.json").read_text())
        records = {record["id"]: record for record in document["components"]}
        for identifier, record in records.items():
            closure_path = ROOT / ("configs/soc/closures/%s.json" % identifier)
            if not closure_path.exists():
                continue
            closure = json.loads(closure_path.read_text())
            declared = {item["name"]: str(item["value"])
                        for item in record.get("typed_parameters", [])}
            constants = {str(key): str(value)
                         for key, value in (record.get("generated_constants") or {}).items()}
            for item in closure["parameters"]:
                name = str(item["name"])
                if "::" in name:
                    self.assertEqual(constants.get(name), str(item["value"]), name)
                else:
                    self.assertEqual(declared.get(name), str(item["value"]), name)
            allowed = self.verifier.document_roots(document)[identifier]
            for item in closure["closure_files"]:
                self.assertIn(item["root"], allowed, identifier)

    def test_real_lock_verifies_every_component_offline(self):
        document = json.loads((ROOT / "configs/soc/sources.lock.json").read_text())
        self.verifier.validate_document(document)
        owners = self.verifier.document_owners(document, ROOT)
        allowed = self.verifier.document_roots(document)
        records = {record["id"]: record for record in document["components"]}
        for component in ("opentitan_uart", "opentitan_gpio", "pulp_gpio", "pulp_spi",
                          "pulp_spi_dependencies", "zipcpu_uart", "zipcpu_timer"):
            with self.subTest(component=component):
                self.assertEqual("elaboration_verified", records[component]["elaboration_status"])
                self.assertEqual("runtime_unverified", records[component]["runtime_status"])
                self.assertIn("elaboration", records[component])
        for component in ("ibex", "cva6"):
            self.assertEqual("elaboration_unverified", records[component]["elaboration_status"])
            self.assertEqual("runtime_unverified", records[component]["runtime_status"])
        for record in document["components"]:
            with self.subTest(record=record["id"]):
                self.assertIn(record["elaboration_status"],
                              {"elaboration_verified", "elaboration_unverified"})
                self.assertEqual("source_verified", record["source_status"])
                self.verifier.verify_record(record, ROOT, owners=owners,
                                            allowed_roots=allowed[record["id"]])

    def test_real_lock_records_the_three_families_and_two_cpus(self):
        document = json.loads((ROOT / "configs/soc/sources.lock.json").read_text())
        records = {record["id"]: record for record in document["components"]}
        for component in ("opentitan_uart", "opentitan_gpio", "pulp_gpio", "pulp_spi",
                          "zipcpu_uart", "zipcpu_timer"):
            closure = json.loads((ROOT / records[component]["elaboration"]["evidence"]).read_text())
            self.assertEqual("soc_elaboration_closure.v1", closure["schema_version"])
            self.assertTrue(closure["capability_findings"], component)
            self.assertIn("unsupported", closure)
            for finding in closure["capability_findings"]:
                self.assertIn(finding["provenance"], {"rtl_read", "elaboration", "source_declared"})
                self.assertTrue(finding["evidence_path"])



if __name__ == "__main__":
    unittest.main()
