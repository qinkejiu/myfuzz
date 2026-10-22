"""The independent Task 5 auditor uses a caller-pinned evidence identity."""

from __future__ import annotations

import hashlib
import gzip
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
AUDIT_PATH = ROOT / "scripts/audit_native_source_completion_evidence.py"
SPEC = importlib.util.spec_from_file_location("task5_identity_auditor", AUDIT_PATH)
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def _fixture(tmp_path, *, operation_name="native-source-completion-attempt-new"):
    workspace = tmp_path / "workspace"
    operation = workspace / "operations" / operation_name
    evidence = workspace / "evidence" / operation_name
    operation.mkdir(parents=True)
    evidence.mkdir(parents=True)

    def row(root, relative, payload):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        return {"path": relative, "sha256": hashlib.sha256(payload).hexdigest()}

    operation_files = {
        name: row(operation, name + ".json", _canonical({"kind": name}))
        for name in ("intent", "plan", "controller_receipt", "claim",
                     "launch_intent", "gate_start", "gate_end",
                     "post_run_integrity", "source_postflight",
                     "lock_postflight", "source_manifest")
    }
    operation_files["controller"] = row(operation, "controller.py", b"# frozen controller\n")
    operation_files["gate_script"] = row(
        operation, "project/scripts/verify_picorv32_native_online.py", b"# frozen gate\n")
    operation_files["auditor"] = row(
        operation, "independent_audit_task5.py", AUDIT_PATH.read_bytes())
    operation_files["gate_stdout"] = row(operation, "gate.stdout.log", b"")
    operation_files["gate_stderr"] = row(operation, "gate.stderr.log", b"")
    workspace_files = {"tool_freeze": row(
        workspace, "operations/environment/tool-freeze.json", _canonical({
            "python3": {"path": str(workspace / "tools/python3"),
                        "sha256": hashlib.sha256(b"frozen python\n").hexdigest()}}))}
    (workspace / "tools").mkdir()
    (workspace / "tools/python3").write_bytes(b"frozen python\n")
    gate_run_id = "a" * 64
    evidence_files = {
        name: row(evidence, name + "/result.json.gz", gzip.compress(_canonical({
            "status": ("native_source_completion_refusal_gate_passed"
                       if name == "native-source-refusal" else "bounded_directed_gate_passed"),
            "gate_run_id": gate_run_id, "gate_branch": name, "gate_pid": 71,
            "operation_name": operation_name}), mtime=0))
        for name in ("positive", "controlled-response", "native-source-refusal")
    }
    evidence_files["summary"] = row(evidence, "summary.json.gz", gzip.compress(_canonical({
        "schema_version": "native_online_directed_gate.v1",
        "gate_run_id": gate_run_id, "gate_pid": 71,
        "positive_status": "bounded_directed_gate_passed",
        "controlled_status": "bounded_directed_gate_passed",
        "native_source_refusal_status": "native_source_completion_refusal_gate_passed",
        "native_completion_observation": True, "native_source_binding": True,
        "native_source_completion": True,
        "script_sha256": operation_files["gate_script"]["sha256"],
        **AUDIT.CLAIMS}), mtime=0))
    flags = ["--native-completion-observation", "--native-source-binding",
             "--native-source-completion"]
    run = {
        "argv": ["python3", "-B", str(operation / operation_files["gate_script"]["path"]),
                 "--output", str(evidence), "--cache-dir", str(operation / "native-cache"),
                 "--heavy-lock", str(workspace / ".superpowers/heavy-worker.lock"),
                 "--gate-run-id", gate_run_id, *flags],
        "cwd": str(operation / "project"), "output": str(evidence),
        "cache_dir": str(operation / "native-cache"),
        "heavy_lock": str(workspace / ".superpowers/heavy-worker.lock"),
        "gate_run_id": gate_run_id,
        "requested_gate_flags": flags,
        "requested_gates": ["native_completion_observation", "native_source_binding",
                            "native_source_completion"],
    }
    identity = {
        "schema_version": "task5_native_source_completion_audit_identity.v1",
        "operation_dir": str(operation), "evidence_dir": str(evidence),
        "workspace_dir": str(workspace),
        "output_file": str(evidence / "independent-audit.json"),
        "run": run, "operation_files": operation_files,
        "workspace_files": workspace_files, "evidence_files": evidence_files,
    }
    encoded = _canonical(identity)
    (operation / "audit-identity.json").write_bytes(encoded)
    return operation, evidence, workspace, hashlib.sha256(encoded).hexdigest()


def test_new_operation_identity_verifies_explicit_file_hashes(tmp_path):
    operation, evidence, workspace, digest = _fixture(tmp_path)
    reader = AUDIT.Reader(operation, evidence, workspace)
    identity = AUDIT.load_audit_identity(reader, "audit-identity.json", digest)
    assert identity["operation_dir"] == str(operation)
    assert identity["evidence_dir"] == str(evidence)
    assert "operation/gate_end.json" in reader.inputs
    assert "evidence/positive/result.json.gz" in reader.inputs


def test_obsolete_attempt6_directory_is_refused(tmp_path):
    operation, evidence, workspace, digest = _fixture(
        tmp_path, operation_name="p6-native-instruction-bus-completion-v1-20261018-attempt6")
    reader = AUDIT.Reader(operation, evidence, workspace)
    with pytest.raises(AUDIT.AuditError, match="obsolete-attempt6"):
        AUDIT.load_audit_identity(reader, "audit-identity.json", digest)


def test_identity_pin_and_evidence_hash_mismatch_are_refused(tmp_path):
    operation, evidence, workspace, digest = _fixture(tmp_path)
    reader = AUDIT.Reader(operation, evidence, workspace)
    with pytest.raises(AUDIT.AuditError, match="identity-manifest-sha256"):
        AUDIT.load_audit_identity(reader, "audit-identity.json", "0" * 64)
    (evidence / "positive/result.json.gz").write_bytes(b"tampered")
    with pytest.raises(AUDIT.AuditError, match="identity-file-sha256"):
        AUDIT.load_audit_identity(reader, "audit-identity.json", digest)


def test_identity_requires_a_pinned_auditor_source(tmp_path):
    operation, evidence, workspace, _ = _fixture(tmp_path)
    identity_path = operation / "audit-identity.json"
    identity = json.loads(identity_path.read_bytes())
    identity["operation_files"].pop("auditor")
    encoded = _canonical(identity)
    identity_path.write_bytes(encoded)
    reader = AUDIT.Reader(operation, evidence, workspace)
    with pytest.raises(AUDIT.AuditError, match="identity-file-inventory"):
        AUDIT.load_audit_identity(reader, "audit-identity.json",
                                  hashlib.sha256(encoded).hexdigest())


def test_pinned_auditor_must_match_the_running_source(tmp_path):
    operation, evidence, workspace, _ = _fixture(tmp_path)
    identity_path = operation / "audit-identity.json"
    identity = json.loads(identity_path.read_bytes())
    auditor_path = operation / identity["operation_files"]["auditor"]["path"]
    auditor_path.write_bytes(b"# a different auditor\n")
    identity["operation_files"]["auditor"]["sha256"] = hashlib.sha256(
        auditor_path.read_bytes()).hexdigest()
    encoded = _canonical(identity)
    identity_path.write_bytes(encoded)
    reader = AUDIT.Reader(operation, evidence, workspace)
    with pytest.raises(AUDIT.AuditError, match="identity-auditor-runtime-sha256"):
        AUDIT.load_audit_identity(reader, "audit-identity.json",
                                  hashlib.sha256(encoded).hexdigest())


def _terminal_fixture(tmp_path):
    operation, evidence, workspace, _ = _fixture(tmp_path)
    identity_path = operation / "audit-identity.json"
    identity = json.loads(identity_path.read_bytes())
    files = identity["operation_files"]

    def replace(name, document):
        raw = _canonical(document)
        (operation / files[name]["path"]).write_bytes(raw)
        files[name]["sha256"] = hashlib.sha256(raw).hexdigest()
        return files[name]["sha256"]

    source_manifest = {"schema_version": "source_tree_manifest.v1",
                       "entries": [{"path": "project/scripts/verify_picorv32_native_online.py",
                                    "sha256": files["gate_script"]["sha256"]}]}
    source_hash = replace("source_manifest", source_manifest)
    run = identity["run"]
    tool_freeze = json.loads((workspace / identity["workspace_files"]["tool_freeze"]["path"]).read_bytes())
    intent = {"schema_version": "task5_gate_intent.v1", "run": run,
              "source_manifest_sha256": source_hash,
              "tool_freeze_sha256": identity["workspace_files"]["tool_freeze"]["sha256"],
              "gate_script_sha256": files["gate_script"]["sha256"],
              "source": {"manifest": {
                  "path": str(operation / files["source_manifest"]["path"]),
                  "sha256": source_hash, "entries": len(source_manifest["entries"]),
                  "canonical_entries_sha256": hashlib.sha256(
                      _canonical(source_manifest["entries"])).hexdigest()},
                  "task5_files": [{"path": "scripts/verify_picorv32_native_online.py",
                                   "sha256": files["gate_script"]["sha256"]}]},
              "environment": {"tool_freeze": str(workspace / identity["workspace_files"]["tool_freeze"]["path"]),
                              "tool_freeze_sha256": identity["workspace_files"]["tool_freeze"]["sha256"],
                              "tool_count": len(tool_freeze),
                              "tools": [{"name": name, **tool} for name, tool in tool_freeze.items()]},
              "claims": AUDIT.CLAIMS, "acceptance_matrix": AUDIT.ACCEPTANCE_MATRIX,
              "gate_started": False, "gate_executed": False}
    intent_hash = replace("intent", intent)
    controller_hash = files["controller"]["sha256"]
    controller_receipt = {"schema_version": "task5_controller_receipt.v1",
                          "path": str(operation / files["controller"]["path"]),
                          "controller_sha256": controller_hash,
                          "intent_sha256": intent_hash,
                          "gate_started": False, "gate_executed": False}
    receipt_hash = replace("controller_receipt", controller_receipt)
    plan = {"schema_version": "task5_frozen_run.v1", "run": run,
            "gate_run_id": run["gate_run_id"],
            "intent_sha256": intent_hash, "intent": intent,
            "controller_sha256": controller_hash,
            "controller_receipt_sha256": receipt_hash,
            "claims": AUDIT.CLAIMS,
            "post_gate_audit": {
                "path": str(operation / files["auditor"]["path"]),
                "sha256": files["auditor"]["sha256"]},
            "acceptance_matrix": AUDIT.ACCEPTANCE_MATRIX,
            "gate_started": False, "gate_executed": False}
    plan_hash = replace("plan", plan)
    claim = {"schema_version": "task5_launch_claim.v1", "plan_sha256": plan_hash,
             "intent_sha256": intent_hash, "controller_sha256": controller_hash,
             "argv": run["argv"], "pid": 42, "one_shot": True,
             "gate_run_id": run["gate_run_id"],
             "gate_started": False, "gate_executed": False}
    replace("claim", claim)
    launch = {"schema_version": "task5_launch_intent.v1", "plan_sha256": plan_hash,
              "intent_sha256": intent_hash, "controller_sha256": controller_hash,
              "argv": run["argv"], "cwd": run["cwd"], "output": run["output"],
              "controller_pid": 42, "gate_run_id": run["gate_run_id"],
              "gate_started": False, "gate_executed": False}
    replace("launch_intent", launch)
    start = {"schema_version": "task5_gate_start.v1", "plan_sha256": plan_hash,
             "controller_sha256": controller_hash, "argv": run["argv"],
             "cwd": run["cwd"], "output": run["output"], "pid": 71,
             "controller_pid": 42, "process_group_id": 71, "status": "running",
             "gate_run_id": run["gate_run_id"]}
    replace("gate_start", start)
    end = {"schema_version": "task5_gate_end.v1", "pid": 71,
           "controller_pid": 42, "process_group_id": 71, "returncode": 0,
           "gate_run_id": run["gate_run_id"],
           "gate_started": True, "gate_executed": True,
           "reaped_by_wait": True, "process_group_gone": True,
           "terminal_status": "gate_process_completed", "claims": AUDIT.CLAIMS,
           "stdout_sha256": files["gate_stdout"]["sha256"],
           "stderr_sha256": files["gate_stderr"]["sha256"],
           "branch_result_sha256": {
               name: identity["evidence_files"][name]["sha256"]
               for name in ("positive", "controlled-response", "native-source-refusal")},
           "summary_sha256": identity["evidence_files"]["summary"]["sha256"]}
    end_hash = replace("gate_end", end)
    source_post = {"schema_version": "task5_source_postflight.v1",
                   "status": "source_tree_manifest_match", "matches_preflight": True,
                   "source_manifest_sha256": source_hash, "claims": AUDIT.CLAIMS}
    source_post_hash = replace("source_postflight", source_post)
    lock = {"path": run["heavy_lock"], "mode": 0o644, "size": 0}
    lock_post = {"schema_version": "task5_lock_postflight.v1", "status": "match",
                 "expected": lock, "observed": lock,
                 "matches_preflight": True, "claims": AUDIT.CLAIMS}
    lock_post_hash = replace("lock_postflight", lock_post)
    post = {"schema_version": "task5_post_run_integrity.v1", "gate_end": end,
            "gate_end_sha256": end_hash, "plan_sha256": plan_hash,
            "gate_run_id": run["gate_run_id"],
            "controller_sha256": controller_hash, "gate_returncode": 0,
            "gate_started": True, "gate_executed": True,
            "process_group_gone": True, "output_created_by_gate": True,
            "source_tree_matches_preflight": True,
            "protected_baselines_match_preflight": True,
            "submodules_match_preflight": True,
            "canonical_lock_matches_preflight": True,
            "postflight_receipts": {
                "source_tree": {
                    "path": str(operation / files["source_postflight"]["path"]),
                    "sha256": source_post_hash},
                "canonical_lock": {
                    "path": str(operation / files["lock_postflight"]["path"]),
                    "sha256": lock_post_hash}},
            "terminal_status": "completed", "claims": AUDIT.CLAIMS}
    replace("post_run_integrity", post)
    encoded = _canonical(identity)
    identity_path.write_bytes(encoded)
    return operation, evidence, workspace, hashlib.sha256(encoded).hexdigest()


def test_new_operation_terminal_receipts_can_be_audited(tmp_path):
    operation, evidence, workspace, digest = _terminal_fixture(tmp_path)
    reader = AUDIT.Reader(operation, evidence, workspace)
    identity = AUDIT.load_audit_identity(reader, "audit-identity.json", digest)
    report = AUDIT.operation_terminal_audit(reader, identity)
    assert report["returncode"] == 0
    assert report["gate_end_sha256"] == identity["operation_files"]["gate_end"]["sha256"]
    assert report["source_manifest_entries_verified"] is True
    assert report["source_tree_closure_verified"] is False
    assert report["external_tool_bytes_verified"] is False
    assert report["gate_executable_identity_verified"] is False


@pytest.mark.parametrize("auditor_path", [
    "scripts/audit_native_source_completion_evidence.py",
    "scripts/task5_native_completion_r11/r11-independent-auditor.v1.py",
], ids=["source-auditor", "r11-auditor"])
@pytest.mark.parametrize("claim_name", tuple(AUDIT.CLAIMS))
@pytest.mark.parametrize("numeric_false", [0, 0.0], ids=["integer-zero", "float-zero"])
@pytest.mark.parametrize("receipt_name, refusal", [
    ("intent", "intent-run-and-claim-identity"),
    ("plan", "plan-intent-controller-identity"),
    ("gate_end", "gate-end-identity"),
    ("source_postflight", "source-postflight-identity"),
    ("lock_postflight", "lock-postflight-identity"),
    ("post_run_integrity", "post-run-identity"),
    ("plan.intent", "plan-intent-controller-identity"),
    ("post_run_integrity.gate_end", "post-run-identity"),
])
def test_numeric_false_claim_is_refused_after_manifest_reseal(
        tmp_path, monkeypatch, auditor_path, claim_name, numeric_false,
        receipt_name, refusal):
    path = ROOT / auditor_path
    spec = importlib.util.spec_from_file_location("claims_identity_auditor", path)
    auditor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(auditor)
    monkeypatch.setitem(globals(), "AUDIT", auditor)
    monkeypatch.setitem(globals(), "AUDIT_PATH", path)
    operation, evidence, workspace, digest = _terminal_fixture(tmp_path)
    reader = auditor.Reader(operation, evidence, workspace)
    identity = auditor.load_audit_identity(reader, "audit-identity.json", digest)
    assert auditor.operation_terminal_audit(reader, identity)["status"] == "passed"

    identity_path = operation / "audit-identity.json"
    identity = json.loads(identity_path.read_bytes())
    files = identity["operation_files"]
    names = ("intent", "controller_receipt", "plan", "claim", "launch_intent",
             "gate_start", "gate_end", "source_postflight", "lock_postflight",
             "post_run_integrity")
    docs = {name: json.loads((operation / files[name]["path"]).read_bytes())
            for name in names}
    if "." not in receipt_name:
        docs[receipt_name]["claims"][claim_name] = numeric_false

    def reseal(name):
        raw = _canonical(docs[name])
        (operation / files[name]["path"]).write_bytes(raw)
        files[name]["sha256"] = hashlib.sha256(raw).hexdigest()

    # Rebuild every dependent digest/reference, so refusal must come from the
    # selected receipt's claim semantics rather than a stale identity join.
    reseal("intent")
    docs["controller_receipt"]["intent_sha256"] = files["intent"]["sha256"]
    reseal("controller_receipt")
    docs["plan"].update(intent=docs["intent"],
                        intent_sha256=files["intent"]["sha256"],
                        controller_receipt_sha256=files["controller_receipt"]["sha256"])
    if receipt_name == "plan.intent":
        assert all(value is False for value in docs["intent"]["claims"].values())
        docs["plan"]["intent"] = json.loads(_canonical(docs["intent"]))
        docs["plan"]["intent"]["claims"][claim_name] = numeric_false
    reseal("plan")
    for name in ("claim", "launch_intent", "gate_start"):
        docs[name]["plan_sha256"] = files["plan"]["sha256"]
        if name != "gate_start":
            docs[name]["intent_sha256"] = files["intent"]["sha256"]
        reseal(name)
    for name in ("gate_end", "source_postflight", "lock_postflight"):
        reseal(name)
    post = docs["post_run_integrity"]
    post.update(plan_sha256=files["plan"]["sha256"], gate_end=docs["gate_end"],
                gate_end_sha256=files["gate_end"]["sha256"])
    if receipt_name == "post_run_integrity.gate_end":
        assert all(value is False for value in docs["gate_end"]["claims"].values())
        post["gate_end"] = json.loads(_canonical(docs["gate_end"]))
        post["gate_end"]["claims"][claim_name] = numeric_false
    for field, name in (("source_tree", "source_postflight"),
                        ("canonical_lock", "lock_postflight")):
        post["postflight_receipts"][field]["sha256"] = files[name]["sha256"]
    reseal("post_run_integrity")
    raw_identity = _canonical(identity)
    identity_path.write_bytes(raw_identity)
    reader = auditor.Reader(operation, evidence, workspace)
    identity = auditor.load_audit_identity(
        reader, "audit-identity.json", hashlib.sha256(raw_identity).hexdigest())
    with pytest.raises(auditor.AuditError, match="^" + refusal + "$"):
        auditor.operation_terminal_audit(reader, identity)


def test_cross_receipt_identity_mismatch_is_refused_even_when_manifest_is_resealed(tmp_path):
    operation, evidence, workspace, _ = _terminal_fixture(tmp_path)
    identity_path = operation / "audit-identity.json"
    identity = json.loads(identity_path.read_bytes())
    gate_end_path = operation / identity["operation_files"]["gate_end"]["path"]
    end = json.loads(gate_end_path.read_bytes())
    end["pid"] = 72
    raw = _canonical(end)
    gate_end_path.write_bytes(raw)
    identity["operation_files"]["gate_end"]["sha256"] = hashlib.sha256(raw).hexdigest()
    encoded = _canonical(identity)
    identity_path.write_bytes(encoded)
    reader = AUDIT.Reader(operation, evidence, workspace)
    loaded = AUDIT.load_audit_identity(reader, "audit-identity.json",
                                       hashlib.sha256(encoded).hexdigest())
    with pytest.raises(AUDIT.AuditError, match="gate-end|post-run"):
        AUDIT.operation_terminal_audit(reader, loaded)


def test_postflight_receipt_hash_mismatch_is_refused(tmp_path):
    operation, evidence, workspace, _ = _terminal_fixture(tmp_path)
    identity_path = operation / "audit-identity.json"
    identity = json.loads(identity_path.read_bytes())
    post_path = operation / identity["operation_files"]["post_run_integrity"]["path"]
    post = json.loads(post_path.read_bytes())
    post["postflight_receipts"]["source_tree"]["sha256"] = "0" * 64
    raw = _canonical(post)
    post_path.write_bytes(raw)
    identity["operation_files"]["post_run_integrity"]["sha256"] = hashlib.sha256(raw).hexdigest()
    encoded = _canonical(identity)
    identity_path.write_bytes(encoded)
    reader = AUDIT.Reader(operation, evidence, workspace)
    loaded = AUDIT.load_audit_identity(reader, "audit-identity.json",
                                       hashlib.sha256(encoded).hexdigest())
    with pytest.raises(AUDIT.AuditError, match="post-run-postflight"):
        AUDIT.operation_terminal_audit(reader, loaded)


def test_cli_requires_explicit_identity_manifest_and_digest():
    import subprocess
    import sys

    script = ROOT / "scripts/audit_native_source_completion_evidence.py"
    output = subprocess.run([sys.executable, str(script), "--help"],
                            check=True, capture_output=True, text=True).stdout
    assert "--identity-manifest" in output
    assert "--identity-sha256" in output
    assert "--workspace-dir" in output


def test_stale_branch_reuse_is_refused_even_when_manifest_is_resealed(tmp_path):
    old_operation, old_evidence, _, _ = _fixture(
        tmp_path / "old", operation_name="old-operation")
    operation, evidence, workspace, _ = _terminal_fixture(tmp_path / "new")
    identity_path = operation / "audit-identity.json"
    identity = json.loads(identity_path.read_bytes())
    old_bytes = (old_evidence / "positive/result.json.gz").read_bytes()
    (evidence / "positive/result.json.gz").write_bytes(old_bytes)
    identity["evidence_files"]["positive"]["sha256"] = hashlib.sha256(old_bytes).hexdigest()
    encoded = _canonical(identity)
    identity_path.write_bytes(encoded)
    reader = AUDIT.Reader(operation, evidence, workspace)
    loaded = AUDIT.load_audit_identity(reader, "audit-identity.json",
                                       hashlib.sha256(encoded).hexdigest())
    with pytest.raises(AUDIT.AuditError, match="terminal-branch-result-identity"):
        AUDIT.operation_terminal_audit(reader, loaded)


def test_replacement_after_identity_load_is_refused(tmp_path):
    operation, evidence, workspace, digest = _terminal_fixture(tmp_path)
    reader = AUDIT.Reader(operation, evidence, workspace)
    identity = AUDIT.load_audit_identity(reader, "audit-identity.json", digest)
    (operation / "gate_end.json").write_bytes(b'{"schema_version":"replacement"}')
    with pytest.raises(AUDIT.AuditError, match="identity-file-changed-after-pin"):
        AUDIT.operation_terminal_audit(reader, identity)


def test_external_heavy_lock_is_refused(tmp_path):
    operation, evidence, workspace, _ = _fixture(tmp_path)
    identity_path = operation / "audit-identity.json"
    identity = json.loads(identity_path.read_bytes())
    identity["run"]["heavy_lock"] = "/tmp/arbitrary.lock"
    identity["run"]["argv"][identity["run"]["argv"].index("--heavy-lock") + 1] = "/tmp/arbitrary.lock"
    encoded = _canonical(identity)
    identity_path.write_bytes(encoded)
    with pytest.raises(AUDIT.AuditError, match="identity-gate-run-mismatch"):
        AUDIT.load_audit_identity(AUDIT.Reader(operation, evidence, workspace),
                                  "audit-identity.json", hashlib.sha256(encoded).hexdigest())


def test_source_manifest_entry_tampering_is_refused(tmp_path):
    operation, evidence, workspace, _ = _terminal_fixture(tmp_path)
    identity_path = operation / "audit-identity.json"
    identity = json.loads(identity_path.read_bytes())
    manifest_path = operation / identity["operation_files"]["source_manifest"]["path"]
    manifest = json.loads(manifest_path.read_bytes())
    manifest["entries"][0]["sha256"] = "0" * 64
    raw = _canonical(manifest)
    manifest_path.write_bytes(raw)
    identity["operation_files"]["source_manifest"]["sha256"] = hashlib.sha256(raw).hexdigest()
    encoded = _canonical(identity)
    identity_path.write_bytes(encoded)
    reader = AUDIT.Reader(operation, evidence, workspace)
    loaded = AUDIT.load_audit_identity(reader, "audit-identity.json",
                                       hashlib.sha256(encoded).hexdigest())
    with pytest.raises(AUDIT.AuditError, match="source-manifest-entry-hash"):
        AUDIT.operation_terminal_audit(reader, loaded)


def test_tool_freeze_binary_tampering_is_refused(tmp_path):
    operation, evidence, workspace, digest = _terminal_fixture(tmp_path)
    reader = AUDIT.Reader(operation, evidence, workspace)
    identity = AUDIT.load_audit_identity(reader, "audit-identity.json", digest)
    (workspace / "tools/python3").write_bytes(b"tampered python\n")
    with pytest.raises(AUDIT.AuditError, match="tool-freeze-binary-hash"):
        AUDIT.operation_terminal_audit(reader, identity)


def test_noncanonical_inventory_path_cannot_bypass_later_pin(tmp_path):
    operation, evidence, workspace, _ = _terminal_fixture(tmp_path)
    identity_path = operation / "audit-identity.json"
    identity = json.loads(identity_path.read_bytes())
    identity["operation_files"]["gate_end"]["path"] = "./gate_end.json"
    encoded = _canonical(identity)
    identity_path.write_bytes(encoded)
    with pytest.raises(AUDIT.AuditError, match="identity-file-row"):
        AUDIT.load_audit_identity(AUDIT.Reader(operation, evidence, workspace),
                                  "audit-identity.json", hashlib.sha256(encoded).hexdigest())


def test_noncanonical_manifest_relative_path_is_refused(tmp_path):
    operation, evidence, workspace, digest = _fixture(tmp_path)
    with pytest.raises(AUDIT.AuditError, match="identity-manifest-path"):
        AUDIT.load_audit_identity(AUDIT.Reader(operation, evidence, workspace),
                                  "./audit-identity.json", digest)


def _reseal_evidence_document(operation, evidence, name, document):
    manifest_path = operation / "audit-identity.json"
    identity = json.loads(manifest_path.read_bytes())
    raw = gzip.compress(_canonical(document), mtime=0)
    path = evidence / identity["evidence_files"][name]["path"]
    path.write_bytes(raw)
    identity["evidence_files"][name]["sha256"] = hashlib.sha256(raw).hexdigest()
    encoded = _canonical(identity)
    manifest_path.write_bytes(encoded)
    return hashlib.sha256(encoded).hexdigest()


def test_run_id_and_summary_are_required_identity_inputs(tmp_path):
    operation, evidence, workspace, digest = _fixture(tmp_path)
    identity = AUDIT.load_audit_identity(
        AUDIT.Reader(operation, evidence, workspace), "audit-identity.json", digest)
    assert identity["run"]["gate_run_id"] == "a" * 64
    assert identity["evidence_files"]["summary"]["path"] == "summary.json.gz"


@pytest.mark.parametrize("field,value", [
    ("gate_run_id", "b" * 64),
    ("gate_branch", "controlled-response"),
    ("gate_pid", 72),
])
def test_branch_identity_mismatch_refused_after_manifest_reseal(tmp_path, field, value):
    operation, evidence, workspace, _ = _terminal_fixture(tmp_path)
    result_path = evidence / "positive/result.json.gz"
    result = json.loads(gzip.decompress(result_path.read_bytes()))
    result[field] = value
    digest = _reseal_evidence_document(operation, evidence, "positive", result)
    reader = AUDIT.Reader(operation, evidence, workspace)
    identity = AUDIT.load_audit_identity(reader, "audit-identity.json", digest)
    with pytest.raises(AUDIT.AuditError, match="branch-result-run-identity"):
        AUDIT.audit_branch(reader, "positive", identity=identity, gate_start={"pid": 71})


def test_summary_run_id_mismatch_refused_after_manifest_reseal(tmp_path):
    operation, evidence, workspace, _ = _terminal_fixture(tmp_path)
    summary = json.loads(gzip.decompress((evidence / "summary.json.gz").read_bytes()))
    summary["gate_run_id"] = "b" * 64
    _reseal_evidence_document(operation, evidence, "summary", summary)
    identity_path = operation / "audit-identity.json"
    identity = json.loads(identity_path.read_bytes())
    end_path = operation / identity["operation_files"]["gate_end"]["path"]
    end = json.loads(end_path.read_bytes())
    end["summary_sha256"] = identity["evidence_files"]["summary"]["sha256"]
    raw_end = _canonical(end)
    end_path.write_bytes(raw_end)
    identity["operation_files"]["gate_end"]["sha256"] = hashlib.sha256(raw_end).hexdigest()
    post_path = operation / identity["operation_files"]["post_run_integrity"]["path"]
    post = json.loads(post_path.read_bytes())
    post["gate_end"] = end
    post["gate_end_sha256"] = identity["operation_files"]["gate_end"]["sha256"]
    raw_post = _canonical(post)
    post_path.write_bytes(raw_post)
    identity["operation_files"]["post_run_integrity"]["sha256"] = hashlib.sha256(raw_post).hexdigest()
    raw_identity = _canonical(identity)
    identity_path.write_bytes(raw_identity)
    digest = hashlib.sha256(raw_identity).hexdigest()
    reader = AUDIT.Reader(operation, evidence, workspace)
    identity = AUDIT.load_audit_identity(reader, "audit-identity.json", digest)
    with pytest.raises(AUDIT.AuditError, match="summary-run-identity"):
        AUDIT.operation_terminal_audit(reader, identity)
