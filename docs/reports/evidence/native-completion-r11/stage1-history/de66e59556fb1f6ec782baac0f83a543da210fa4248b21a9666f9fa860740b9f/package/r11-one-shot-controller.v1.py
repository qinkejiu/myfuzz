#!/usr/bin/env python3
"""One-shot Task 5 gate controller. No import from the gate or auditor.

The controller is deliberately fail closed: it only writes success receipts after
the frozen inputs and every postflight comparison have been independently read.
It never creates the gate's evidence directory or sends a process-group signal.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import posixpath
from pathlib import PurePosixPath
import re
import stat
import subprocess
import sys
import time


WORKSPACE = "/root/fanzehui/myfuzz"
FLAGS = ["--native-completion-observation", "--native-source-binding",
         "--native-source-completion"]
GATES = ["native_completion_observation", "native_source_binding",
         "native_source_completion"]
BRANCHES = ("positive", "controlled-response", "native-source-refusal")
STAGE1_ARTIFACTS = tuple(sorted((
    "r11-plan-schema.v1.json",
    "r11-source-byte-bootstrap.v1.py",
    "r11-post-gate-audit-runner.v1.py",
    "r11-independent-auditor.v1.py",
    "r11-gate-script.v1.py",
    "r11-one-shot-controller.v1.py",
    "r11-external-launch-contract.v1.json",
)))
CLAIMS = {"coverage_guided_search": False, "formal_p6_complete": False,
          "retirement_authority": False, "source_authority": False}
ACCEPTANCE_MATRIX = [
    {"id": "selected_source_positive", "expected": "only the exact selected source-bound four-byte native instruction-bus transfer can issue completion evidence"},
    {"id": "noncandidate_no_grant", "expected": "unrelated/bootstrap/noncandidate reads remain diagnostic and receive no completion grant"},
    {"id": "controlled_response", "expected": "the controlled selected-source transaction follows its planned response path and produces the exact bound transfer result"},
    {"id": "selected_source_contradiction_original", "expected": "selected-source contradiction is terminally refused in the original run"},
    {"id": "selected_source_contradiction_fresh", "expected": "the same selected-source contradiction is terminally refused in the full fresh replay"},
    {"id": "full_fresh_replay", "expected": "the complete configured replay executes from fresh inputs"},
    {"id": "independent_raw_audit", "expected": "raw gate evidence is checked by the independent audit path"},
]
INPUTS = {"intent": "control/intent.v1.json", "plan": "control/run-plan.v1.json",
          "controller": "control/r11-one-shot-controller.v1.py",
          "controller_receipt": "control/controller-receipt.v1.json",
          "source_manifest": "control/source-manifest.v1.json",
          "tool_freeze": "control/tool-freeze.v1.json",
          "gate_script": "project/scripts/verify_picorv32_native_online.py",
          "auditor": "control/r11-independent-auditor.v1.py",
          "environment": "control/environment.v1.json",
          "source_snapshot_map": "control/source-snapshot-map.v1.json",
          "submodule_manifest": "control/submodule-manifest.v1.json",
          "plan_schema": "control/r11-plan-schema.v1.json",
          "external_contract": "control/r11-external-launch-contract.v1.json",
          "static_code_manifest": "control/r11-static-code-manifest.v1.json",
          "stage2_manifest": "control/stage2-manifest.v1.json"}
OUTPUTS = {"claim": "control/claim.v1.json",
           "launch_intent": "control/launch-intent.v1.json",
           "gate_start": "control/gate-start.v1.json",
           "gate_end": "control/gate-end.v1.json",
           "post_run_integrity": "control/post-run-integrity.v1.json",
           "source_postflight": "control/source-postflight.v1.json",
           "source_snapshot_postflight": "control/source-snapshot-postflight.v1.json",
           "lock_postflight": "control/lock-postflight.v1.json",
           "gate_stdout": "control/gate.stdout.log",
           "gate_stderr": "control/gate.stderr.log",
           "protected_preflight": "control/protected-baselines-preflight.v1.json",
           "protected_postflight": "control/protected-baselines-postflight.v1.json",
           "submodules_preflight": "control/submodules-preflight.v1.json",
           "submodules_postflight": "control/submodules-postflight.v1.json"}
RECEIPT_MODE = 0o600
MAX_JSON_BYTES = 64 * 1024 * 1024
WAIT_INTERVAL = 60
GROUP_WINDOW = 60


class Refusal(Exception):
    pass


def need(ok, code):
    if not ok:
        raise Refusal(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def canonical_ascii(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def decode(raw, code):
    need(len(raw) <= MAX_JSON_BYTES, code + ":size")
    def reject_constant(value):
        raise Refusal(code + ":nonfinite:" + value)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, code + ":duplicate-key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=reject_constant)


def hex64(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def commit_id(value):
    return (type(value) is str and
            re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value) is not None)


def exact_claims(value):
    return (type(value) is dict and set(value) == set(CLAIMS)
            and all(value[key] is False for key in CLAIMS))


def components(path, absolute=False):
    need(type(path) is str and bool(path), "path:empty")
    pure = PurePosixPath(path)
    need(bool(pure.parts) and pure.is_absolute() is absolute and pure.as_posix() == path
         and all(p not in ("", ".", "..") for p in pure.parts), "path:canonical")
    return pure.parts[1:] if absolute else pure.parts


def under(path, root):
    components(path, absolute=True)
    return path.startswith(root + "/")


def open_dir(path):
    """Open each absolute component without following any symlink."""
    parts = components(path, absolute=True)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def parent_leaf(rootfd, relative):
    parts = components(relative)
    fd = os.dup(rootfd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise


def read_file(rootfd, relative, *, executable=False):
    parent, leaf = parent_leaf(rootfd, relative)
    try:
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                     os.O_CLOEXEC,
                     dir_fd=parent)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and before.st_size <= MAX_JSON_BYTES,
                 "file:type-or-links:" + relative)
            if executable:
                need(bool(before.st_mode & 0o111), "file:not-executable:" + relative)
            chunks = []
            total_size = 0
            while True:
                part = os.read(fd, 1024 * 1024)
                if not part:
                    break
                chunks.append(part)
                total_size += len(part)
                need(total_size <= MAX_JSON_BYTES,
                     "file:oversize:" + relative)
            after = os.fstat(fd)
            need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                 == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
                 "file:changed:" + relative)
            raw = b"".join(chunks)
            need(len(raw) == before.st_size, "file:short-read:" + relative)
            return raw, before
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def read_absolute(path, *, executable=False):
    parts = components(path, absolute=True)
    parent = open_dir("/" + "/".join(parts[:-1]))
    try:
        return read_file(parent, parts[-1], executable=executable)
    finally:
        os.close(parent)


def leaf_stat(rootfd, relative):
    parent, leaf = parent_leaf(rootfd, relative)
    try:
        try:
            return os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return None
    finally:
        os.close(parent)


def first_path_executable(path_dirs, name):
    need(type(name) is str and bool(name) and "/" not in name
         and name not in (".", ".."), "environment:command-name")
    for directory in path_dirs:
        fd = open_dir(directory)
        try:
            try:
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            need(not stat.S_ISLNK(st.st_mode),
                 "environment:command-symlink:" + name)
            if stat.S_ISREG(st.st_mode) and (st.st_mode & 0o111):
                need(st.st_nlink == 1 and
                     os.access(name, os.X_OK, dir_fd=fd, follow_symlinks=False),
                     "environment:command-inaccessible:" + name)
                return directory + "/" + name
        finally:
            os.close(fd)
    return None


def write_exclusive(rootfd, relative, raw, mode=RECEIPT_MODE):
    parent, leaf = parent_leaf(rootfd, relative)
    try:
        fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=parent)
        try:
            os.fchmod(fd, mode)
            offset = 0
            while offset < len(raw):
                offset += os.write(fd, raw[offset:])
            os.fsync(fd)
            st = os.fstat(fd)
            need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1
                 and stat.S_IMODE(st.st_mode) == mode and st.st_size == len(raw),
                 "write:postcheck:" + relative)
        finally:
            os.close(fd)
        os.fsync(parent)
    finally:
        os.close(parent)
    return digest(raw)


def write_json(rootfd, relative, value):
    raw = canonical(value) + b"\n"
    expected = write_exclusive(rootfd, relative, raw)
    reread, st = read_file(rootfd, relative)
    need(reread == raw and digest(reread) == expected
         and stat.S_IMODE(st.st_mode) == RECEIPT_MODE,
         "receipt:readback:" + relative)
    return digest(reread)


def source_manifest_check(opfd, doc, intent, manifest_sha, gate_sha):
    need(type(doc) is dict and set(doc) == {"schema_version", "entries"}
         and doc["schema_version"] == "source_tree_manifest.v1"
         and type(doc["entries"]) is list and bool(doc["entries"]),
         "source:manifest-shape")
    seen = set()
    for row in doc["entries"]:
        need(type(row) is dict and set(row) == {"path", "sha256"}
             and type(row["path"]) is str and hex64(row["sha256"])
             and row["path"].startswith("project/"),
             "source:entry-shape")
        components(row["path"])
        need(row["path"] not in seen, "source:duplicate")
        seen.add(row["path"])
        raw, _ = read_file(opfd, row["path"])
        need(digest(raw) == row["sha256"], "source:hash:" + row["path"])
    need(INPUTS["gate_script"] in seen, "source:gate-absent")
    source = intent.get("source")
    need(type(source) is dict and set(source) == {"manifest", "task5_files"},
         "source:intent-shape")
    ref = source["manifest"]
    need(type(ref) is dict and set(ref) == {"path", "sha256", "entries",
                                           "canonical_entries_sha256"}
         and ref["path"] == intent["run"]["cwd"].removesuffix("/project") + "/" + INPUTS["source_manifest"]
         and ref["sha256"] == manifest_sha
         and type(ref["entries"]) is int and ref["entries"] == len(seen)
         and ref["canonical_entries_sha256"] == digest(canonical(doc["entries"])),
         "source:intent-manifest")
    task5 = source["task5_files"]
    need(type(task5) is list and bool(task5), "source:task5-empty")
    task_seen = set()
    for row in task5:
        need(type(row) is dict and set(row) == {"path", "sha256"}
             and type(row["path"]) is str and hex64(row["sha256"]),
             "source:task5-shape")
        path = "project/" + row["path"]
        components(path)
        need(path in seen and path not in task_seen, "source:task5-path")
        task_seen.add(path)
        raw, _ = read_file(opfd, path)
        need(digest(raw) == row["sha256"], "source:task5-hash:" + path)
    need(INPUTS["gate_script"] in task_seen and
         intent.get("source_manifest_sha256", manifest_sha) == manifest_sha and
         intent.get("gate_script_sha256") == gate_sha,
         "source:intent-gate")


def static_code_manifest_check(opfd, raw, gate_raw):
    manifest = decode(raw, "static-code-manifest")
    need(type(manifest) is dict and set(manifest) == {"schema_version", "entries"}
         and manifest["schema_version"] == "r11_static_code_manifest.v1"
         and type(manifest["entries"]) is list
         and len(manifest["entries"]) == len(STAGE1_ARTIFACTS),
         "static-code-manifest:shape")
    rows = {}
    for entry in manifest["entries"]:
        need(type(entry) is dict and set(entry) == {"path", "size", "sha256"}
             and type(entry["path"]) is str
             and type(entry["size"]) is int
             and 0 <= entry["size"] <= MAX_JSON_BYTES
             and hex64(entry["sha256"]), "static-code-manifest:row")
        rows[entry["path"]] = entry
    need([entry["path"] for entry in manifest["entries"]] == list(STAGE1_ARTIFACTS)
         and len(rows) == len(STAGE1_ARTIFACTS),
         "static-code-manifest:inventory")
    gate = rows["r11-gate-script.v1.py"]
    need(gate["size"] == len(gate_raw) and gate["sha256"] == digest(gate_raw),
         "static-code-manifest:gate-stage1-stage2")
    required_copies = {"r11-one-shot-controller.v1.py",
                       "r11-independent-auditor.v1.py",
                       "r11-post-gate-audit-runner.v1.py",
                       "r11-plan-schema.v1.json",
                       "r11-external-launch-contract.v1.json"}
    for name, row in rows.items():
        copy = "control/" + name
        exists = leaf_stat(opfd, copy) is not None
        need(exists or name not in required_copies,
             "static-code-manifest:runtime-copy-missing:" + name)
        if exists:
            actual, _ = read_file(opfd, copy)
            need(len(actual) == row["size"] and digest(actual) == row["sha256"],
                 "static-code-manifest:runtime-copy-mismatch:" + name)
            if name == "r11-gate-script.v1.py":
                need(actual == gate_raw, "static-code-manifest:gate-copy-bytes")
    return rows


def stage2_member(operation, rows, path, kind, code, *, executable=False):
    need(under(path, operation), code + ":outside-operation")
    if kind == "file":
        need(under(path, operation + "/tools"), code + ":outside-tools")
    relative = path[len(operation) + 1:]
    row = rows.get(relative)
    need(type(row) is dict and row.get("kind") == kind,
         code + ":missing-stage2-row")
    if kind == "file":
        raw, st = read_absolute(path, executable=executable)
        need(row == {"path": relative, "kind": "file",
                     "mode": stat.S_IMODE(st.st_mode), "size": len(raw),
                     "sha256": digest(raw)}, code + ":stage2-file")
    else:
        fd = open_dir(path)
        try:
            st = os.fstat(fd)
            need(row == {"path": relative, "kind": "directory",
                         "mode": stat.S_IMODE(st.st_mode)},
                 code + ":stage2-directory")
        finally:
            os.close(fd)


def validate_run(run, operation, evidence, workspace):
    run_id = run.get("gate_run_id") if type(run) is dict else None
    need(type(run) is dict and set(run) == {"argv", "cwd", "output", "cache_dir",
                                            "heavy_lock", "gate_run_id",
                                            "requested_gate_flags", "requested_gates"}
         and hex64(run_id), "run:shape")
    expected = ["python3", "-B", operation + "/" + INPUTS["gate_script"],
                "--output", evidence, "--cache-dir", operation + "/native-cache",
                "--heavy-lock", workspace + "/.superpowers/heavy-worker.lock",
                "--gate-run-id", run_id, *FLAGS]
    need(run == {"argv": expected, "cwd": operation + "/project",
                 "output": evidence, "cache_dir": operation + "/native-cache",
                 "heavy_lock": workspace + "/.superpowers/heavy-worker.lock",
                 "gate_run_id": run_id, "requested_gate_flags": FLAGS,
                 "requested_gates": GATES}, "run:identity")
    return run_id


def output_identity(path):
    parts = components(path, absolute=True)
    parent = open_dir("/" + "/".join(parts[:-1]))
    try:
        try:
            st = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return None
    finally:
        os.close(parent)
    need(stat.S_ISDIR(st.st_mode), "output:not-directory")
    return {"path": path, "device": st.st_dev, "inode": st.st_ino,
            "mode": stat.S_IMODE(st.st_mode), "uid": st.st_uid,
            "gid": st.st_gid}


def group_gone(pgid):
    try:
        os.killpg(pgid, 0)  # Existence probe only; delivers no signal.
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def observe_group(pgid, deadline):
    while True:
        if group_gone(pgid):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))


def gzip_json(raw, code):
    need(len(raw) <= MAX_JSON_BYTES, code + ":compressed-size")
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as source:
        decoded = source.read(MAX_JSON_BYTES + 1)
    need(len(decoded) <= MAX_JSON_BYTES, code + ":decoded-size")
    return decode(decoded, code)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operation-dir", required=True)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--workspace-dir", required=True)
    parser.add_argument("--stage2-manifest-sha256", required=True)
    parser.add_argument("--execute", action="store_true", required=True)
    args = parser.parse_args()
    operation, evidence, workspace = (args.operation_dir, args.evidence_dir,
                                      args.workspace_dir)
    op_name = operation[len(WORKSPACE + "/operations/"):] if operation.startswith(
        WORKSPACE + "/operations/") else ""
    ev_name = evidence[len(WORKSPACE + "/evidence/"):] if evidence.startswith(
        WORKSPACE + "/evidence/") else ""
    need(workspace == WORKSPACE and under(operation, workspace + "/operations")
         and under(evidence, workspace + "/evidence")
         and bool(op_name) and "/" not in op_name and op_name == ev_name,
         "roots:identity")
    need(hex64(args.stage2_manifest_sha256), "stage2:external-sha256")
    opfd = open_dir(operation)
    wsfd = open_dir(workspace)
    try:
        return execute(opfd, wsfd, operation, evidence, workspace,
                       args.stage2_manifest_sha256)
    finally:
        os.close(wsfd)
        os.close(opfd)


def execute(opfd, wsfd, operation, evidence, workspace, stage2_expected_sha):
    frozen = {}
    for name, path in INPUTS.items():
        raw, st = read_file(opfd, path)
        frozen[name] = {"raw": raw, "sha256": digest(raw), "mode": stat.S_IMODE(st.st_mode)}
    need(frozen["stage2_manifest"]["sha256"] == stage2_expected_sha,
         "stage2:external-sha256-mismatch")
    stage2 = decode(frozen["stage2_manifest"]["raw"], "stage2-manifest")
    need(type(stage2) is dict and set(stage2) == {"schema_version", "entries"}
         and stage2["schema_version"] == "r11_stage2_manifest.v1",
         "stage2:shape")
    validate_map_rows(stage2["entries"])
    need(all(row["path"] != INPUTS["stage2_manifest"]
             for row in stage2["entries"]), "stage2:self-listed")
    stage2_actual = [row for row in scan_tree(opfd)
                     if row["path"] != INPUTS["stage2_manifest"]]
    need(stage2_actual == stage2["entries"], "stage2:inventory-mismatch")
    stage2_rows = {row["path"]: row for row in stage2["entries"]}
    intent = decode(frozen["intent"]["raw"], "intent")
    plan = decode(frozen["plan"]["raw"], "plan")
    controller_receipt = decode(frozen["controller_receipt"]["raw"], "controller-receipt")
    source_manifest = decode(frozen["source_manifest"]["raw"], "source-manifest")
    tool_freeze = decode(frozen["tool_freeze"]["raw"], "tool-freeze")
    static_rows = static_code_manifest_check(
        opfd, frozen["static_code_manifest"]["raw"], frozen["gate_script"]["raw"])
    need(static_rows["r11-one-shot-controller.v1.py"]["sha256"] ==
             frozen["controller"]["sha256"]
         and static_rows["r11-independent-auditor.v1.py"]["sha256"] ==
             frozen["auditor"]["sha256"]
         and static_rows["r11-plan-schema.v1.json"]["sha256"] ==
             frozen["plan_schema"]["sha256"]
         and static_rows["r11-external-launch-contract.v1.json"]["sha256"] ==
             frozen["external_contract"]["sha256"],
         "static-code-manifest:runtime-pin")
    run = intent.get("run") if type(intent) is dict else None
    run_id = validate_run(run, operation, evidence, workspace)
    need(type(plan) is dict and type(controller_receipt) is dict
         and plan.get("run") == run and plan.get("intent") == intent
         and plan.get("gate_run_id") == run_id
         and plan.get("intent_sha256") == frozen["intent"]["sha256"]
         and plan.get("controller_sha256") == frozen["controller"]["sha256"]
         and plan.get("controller_receipt_sha256") == frozen["controller_receipt"]["sha256"]
         and exact_claims(plan.get("claims")) and exact_claims(intent.get("claims"))
         and plan.get("acceptance_matrix") == intent.get("acceptance_matrix") == ACCEPTANCE_MATRIX
         and plan.get("gate_started") is intent.get("gate_started") is False
         and plan.get("gate_executed") is intent.get("gate_executed") is False,
         "plan:intent-identity")
    need(type(controller_receipt) is dict and
         set(controller_receipt) == {"schema_version", "path", "controller_sha256",
                                     "intent_sha256", "gate_started", "gate_executed"}
         and controller_receipt.get("schema_version") == "task5_r11_controller_receipt.v1"
         and controller_receipt.get("path") == operation + "/" + INPUTS["controller"]
         and controller_receipt.get("controller_sha256") == frozen["controller"]["sha256"]
         and controller_receipt.get("intent_sha256") == frozen["intent"]["sha256"]
         and controller_receipt.get("gate_started") is False
         and controller_receipt.get("gate_executed") is False,
         "controller:receipt")
    need(plan.get("post_gate_audit") == {"path": operation + "/" + INPUTS["auditor"],
                                           "sha256": frozen["auditor"]["sha256"]},
         "auditor:pin")
    controller_path = os.path.abspath(__file__)
    need(controller_path == operation + "/" + INPUTS["controller"],
         "controller:runtime-path")
    actual_controller, _ = read_absolute(controller_path)
    need(digest(actual_controller) == frozen["controller"]["sha256"],
         "controller:runtime-sha256")
    source_manifest_check(opfd, source_manifest, intent,
                          frozen["source_manifest"]["sha256"], frozen["gate_script"]["sha256"])
    need(type(tool_freeze) is dict and "python3" in tool_freeze,
         "tool-freeze:shape")
    for name, row in tool_freeze.items():
        need(type(name) is str and bool(name) and type(row) is dict
             and set(row) == {"path", "sha256"} and hex64(row["sha256"])
             and under(row["path"], workspace), "tool-freeze:row")
        raw, _ = read_absolute(row["path"], executable=name == "python3")
        need(digest(raw) == row["sha256"], "tool-freeze:hash:" + name)
        stage2_member(operation, stage2_rows, row["path"], "file",
                      "tool-freeze:" + name, executable=True)
    envref = intent.get("environment")
    need(type(envref) is dict and envref.get("tool_freeze") == operation + "/" + INPUTS["tool_freeze"]
         and envref.get("tool_freeze_sha256") == frozen["tool_freeze"]["sha256"]
         and type(envref.get("tool_count")) is int
         and envref.get("tool_count") == len(tool_freeze)
         and type(envref.get("tools")) is list, "environment:tool-ref")
    need(all(type(r) is dict and set(r) == {"name", "path", "sha256"}
             and type(r["name"]) is str and bool(r["name"])
             for r in envref["tools"]), "environment:tool-rows")
    need(len({r["name"] for r in envref["tools"]}) == len(envref["tools"]),
         "environment:tool-duplicate")
    need({r["name"]: {"path": r["path"], "sha256": r["sha256"]}
          for r in envref["tools"]} == tool_freeze, "environment:tools")
    environment = decode(frozen["environment"]["raw"], "environment")
    need(type(environment) is dict and set(environment) == {
         "schema_version", "vars", "interpreters", "runtime_closure", "resolved_commands"}
         and environment["schema_version"] == "r11_runtime_environment.v1"
         and type(environment["vars"]) is dict
         and all(type(k) is str and bool(k) and type(v) is str
                 for k, v in environment["vars"].items())
         and type(environment["interpreters"]) is dict
         and set(environment["interpreters"]) == {"controller", "gate", "auditor"}
         and type(environment["runtime_closure"]) is list
         and bool(environment["runtime_closure"])
         and type(environment["resolved_commands"]) is dict
         and bool(environment["resolved_commands"]),
         "environment:shape")
    child_env = environment["vars"]
    for role, path in environment["interpreters"].items():
        need(under(path, workspace), "environment:interpreter-path:" + role)
        stage2_member(operation, stage2_rows, path, "file",
                      "environment:interpreter:" + role, executable=True)
    need(os.path.abspath(sys.executable) == environment["interpreters"]["controller"]
         and environment["interpreters"]["controller"] !=
             environment["interpreters"]["gate"],
         "environment:controller-runtime")
    need(environment["interpreters"]["gate"] == tool_freeze["python3"]["path"],
         "environment:gate-interpreter")
    closure_paths = set()
    for row in environment["runtime_closure"]:
        need(type(row) is dict and set(row) == {"path", "sha256", "role"}
             and type(row["role"]) is str and bool(row["role"])
             and under(row["path"], workspace) and hex64(row["sha256"])
             and row["path"] not in closure_paths, "environment:closure-row")
        closure_paths.add(row["path"])
        raw, _ = read_absolute(row["path"])
        need(digest(raw) == row["sha256"], "environment:closure-hash")
        stage2_member(operation, stage2_rows, row["path"], "file",
                      "environment:closure")
    need(all(path in closure_paths for path in environment["interpreters"].values()),
         "environment:interpreter-not-in-closure")
    for name, path in environment["resolved_commands"].items():
        need(type(name) is str and bool(name) and under(path, workspace)
             and path in closure_paths, "environment:command-row")
        read_absolute(path, executable=True)
        stage2_member(operation, stage2_rows, path, "file",
                      "environment:command:" + name, executable=True)
    need(type(child_env.get("PYTHONPATH")) is str
         and all(under(p, workspace) for p in child_env["PYTHONPATH"].split(":"))
         and all(under(p, workspace) for p in child_env["PATH"].split(":"))
         and child_env.get("TMPDIR") == run["cache_dir"], "environment:paths")
    need(all(child_env.get(key, run["cache_dir"]) == run["cache_dir"]
             for key in ("TMP", "TEMP", "XDG_CACHE_HOME", "PYTHONPYCACHEPREFIX")),
         "environment:dynamic-cache-paths")
    path_dirs = child_env["PATH"].split(":")
    for path in [*path_dirs, *child_env["PYTHONPATH"].split(":")]:
        stage2_member(operation, stage2_rows, path, "directory",
                      "environment:search-directory")
    for name, path in environment["resolved_commands"].items():
        need(path.rsplit("/", 1)[-1] == name
             and path.rsplit("/", 1)[0] in path_dirs,
             "environment:command-resolution:" + name)
        need(first_path_executable(path_dirs, name) == path,
             "environment:command-shadowed:" + name)
    need(environment["resolved_commands"].get("python3") ==
         environment["interpreters"]["gate"],
         "environment:python3-resolution")
    need(leaf_stat(opfd, "project") is not None, "project:missing")
    # Compare the copied source map and capture independent protected inventories.
    preflight = full_map_preflight(opfd, wsfd, operation, workspace,
                                   frozen["source_snapshot_map"],
                                   frozen["submodule_manifest"])
    lock_before = lock_identity(wsfd, run["heavy_lock"], workspace)
    absent = [*OUTPUTS.values(), "control/audit-identity.v1.json"]
    need(all(leaf_stat(opfd, path) is None for path in absent), "outputs:already-present")
    need(output_identity(evidence) is None, "output:already-present")
    need(leaf_stat(opfd, "native-cache") is None, "cache:already-present")
    preflight.output_absent = True
    preflight.write_preflight(opfd)
    claim = {"schema_version": "task5_r11_claim.v1", "plan_sha256": frozen["plan"]["sha256"],
             "intent_sha256": frozen["intent"]["sha256"],
             "controller_sha256": frozen["controller"]["sha256"],
             "stage2_manifest_sha256": stage2_expected_sha,
             "gate_run_id": run_id, "argv": run["argv"], "pid": os.getpid(),
             "one_shot": True, "gate_started": False, "gate_executed": False}
    write_json(opfd, OUTPUTS["claim"], claim)
    preflight.sole_authorized_writer = True
    return claimed_run(opfd, wsfd, operation, evidence, workspace, run, run_id,
                       frozen, child_env, environment["interpreters"]["gate"],
                       preflight, lock_before, claim)


def symlink_inside_tree(relative, target):
    need(type(target) is str and bool(target) and not target.startswith("/"),
         "snapshot:symlink-absolute:" + relative)
    target_path = posixpath.normpath(posixpath.join(posixpath.dirname(relative), target))
    need(target_path != ".." and not target_path.startswith("../")
         and not target_path.startswith("/"), "snapshot:symlink-escape:" + relative)


def scan_tree(rootfd, *, max_file_size=MAX_JSON_BYTES):
    """Inventory a tree using only held directory descriptors and no-follow opens."""
    rows = []

    def visit(fd, prefix):
        before = os.fstat(fd)
        need(stat.S_ISDIR(before.st_mode), "snapshot:directory-type")
        rows.append({"path": prefix or ".", "kind": "directory",
                     "mode": stat.S_IMODE(before.st_mode)})
        names = sorted(os.listdir(fd))
        for name in names:
            need(name not in (".", "..") and "/" not in name, "snapshot:name")
            relative = prefix + "/" + name if prefix else name
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            mode = stat.S_IMODE(st.st_mode)
            if stat.S_ISDIR(st.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY |
                                os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                try:
                    opened = os.fstat(child)
                    need((opened.st_dev, opened.st_ino) == (st.st_dev, st.st_ino),
                         "snapshot:directory-race:" + relative)
                    visit(child, relative)
                    after = os.fstat(child)
                    need((after.st_dev, after.st_ino) == (st.st_dev, st.st_ino),
                         "snapshot:directory-changed:" + relative)
                finally:
                    os.close(child)
            elif stat.S_ISREG(st.st_mode):
                need(st.st_nlink == 1, "snapshot:file-links:" + relative)
                need(max_file_size is None or st.st_size <= max_file_size,
                     "snapshot:file-oversize:" + relative)
                filefd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW |
                                 os.O_NONBLOCK | os.O_CLOEXEC,
                                 dir_fd=fd)
                try:
                    opened = os.fstat(filefd)
                    need(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
                         and (opened.st_dev, opened.st_ino, opened.st_size,
                              opened.st_mtime_ns) == (st.st_dev, st.st_ino,
                                                     st.st_size, st.st_mtime_ns),
                         "snapshot:file-race:" + relative)
                    hasher = hashlib.sha256()
                    size = 0
                    while True:
                        block = os.read(filefd, 1024 * 1024)
                        if not block:
                            break
                        size += len(block)
                        need(max_file_size is None or size <= max_file_size,
                             "snapshot:file-grew-oversize:" + relative)
                        hasher.update(block)
                    after = os.fstat(filefd)
                    need((after.st_dev, after.st_ino, after.st_size,
                          after.st_mtime_ns) == (st.st_dev, st.st_ino,
                                                  st.st_size, st.st_mtime_ns)
                         and size == st.st_size, "snapshot:file-changed:" + relative)
                    rows.append({"path": relative, "kind": "file", "mode": mode,
                                 "size": size, "sha256": hasher.hexdigest()})
                finally:
                    os.close(filefd)
            elif stat.S_ISLNK(st.st_mode):
                need(st.st_nlink == 1, "snapshot:symlink-links:" + relative)
                target = os.readlink(name, dir_fd=fd)
                symlink_inside_tree(relative, target)
                after = os.stat(name, dir_fd=fd, follow_symlinks=False)
                need((after.st_dev, after.st_ino, after.st_mtime_ns) ==
                     (st.st_dev, st.st_ino, st.st_mtime_ns),
                     "snapshot:symlink-changed:" + relative)
                rows.append({"path": relative, "kind": "symlink",
                             "mode": mode, "target": target})
            else:
                raise Refusal("snapshot:special-file:" + relative)
        after = os.fstat(fd)
        need((before.st_dev, before.st_ino, before.st_mtime_ns) ==
             (after.st_dev, after.st_ino, after.st_mtime_ns),
             "snapshot:directory-mutated:" + (prefix or "."))

    visit(rootfd, "")
    rows.sort(key=lambda row: row["path"])
    return rows


def validate_map_rows(rows):
    need(type(rows) is list and bool(rows), "snapshot:entries")
    paths = []
    for row in rows:
        need(type(row) is dict and type(row.get("path")) is str
             and type(row.get("kind")) is str, "snapshot:row")
        path, kind = row["path"], row["kind"]
        if path != ".":
            components(path)
        expected = {"directory": {"path", "kind", "mode"},
                    "file": {"path", "kind", "mode", "size", "sha256"},
                    "symlink": {"path", "kind", "mode", "target"}}.get(kind)
        need(expected is not None and set(row) == expected
             and type(row["mode"]) is int and 0 <= row["mode"] <= 0o7777,
             "snapshot:row-shape:" + path)
        if kind == "file":
            need(type(row["size"]) is int
                 and 0 <= row["size"] <= MAX_JSON_BYTES
                 and hex64(row["sha256"]), "snapshot:file-row:" + path)
        if kind == "symlink":
            symlink_inside_tree(path, row["target"])
        paths.append(path)
    need(paths == sorted(set(paths)) and rows[0]["path"] == "."
         and rows[0]["kind"] == "directory", "snapshot:ordering")


def full_map_preflight(opfd, wsfd, operation, workspace, frozen_map, submodule_manifest):
    """Compare the Stage-2 source map to the copied project tree."""
    doc = decode(frozen_map["raw"], "source-snapshot-map")
    need(type(doc) is dict and set(doc) == {"schema_version", "source_root",
                                        "entries", "exclusions"}
         and doc["schema_version"] == "r11_source_snapshot_map.v1"
         and type(doc["source_root"]) is str and doc["source_root"].startswith("/")
         and type(doc["exclusions"]) is list, "source-snapshot-map:shape")
    validate_map_rows(doc["entries"])
    need(all(type(row) is dict and set(row) == {"path", "kind", "reason"}
             and type(row["path"]) is str and type(row["reason"]) is str
             and bool(row["reason"]) and row["kind"] in
             ("directory", "file", "symlink") for row in doc["exclusions"]),
         "source-snapshot-map:exclusions")
    excluded_paths = [row["path"] for row in doc["exclusions"]]
    for path in excluded_paths:
        components(path)
    need(excluded_paths == sorted(set(excluded_paths))
         and not set(excluded_paths).intersection(
             row["path"] for row in doc["entries"]),
         "source-snapshot-map:exclusion-order")
    projectfd = open_dir(operation + "/project")
    try:
        before = scan_tree(projectfd)
    finally:
        os.close(projectfd)
    need(before == doc["entries"], "source-snapshot-map:preflight-mismatch")
    # Capture protected roots and project submodule projections before claim.
    protected = protected_map_preflight()
    submodules = submodule_map_preflight(before, submodule_manifest)
    return Preflight(operation, doc["entries"], frozen_map["sha256"],
                     protected, submodules)


class Preflight:
    output_absent = False
    sole_authorized_writer = False

    def __init__(self, operation, source_rows, map_sha, protected, submodules):
        self.operation = operation
        self.source_rows = source_rows
        self.map_sha = map_sha
        self.protected = protected
        self.submodules = submodules
        self.protected_preflight_sha = None
        self.submodules_preflight_sha = None

    def write_preflight(self, opfd):
        self.protected_preflight_sha = write_json(
            opfd, OUTPUTS["protected_preflight"], self.protected)
        self.submodules_preflight_sha = write_json(
            opfd, OUTPUTS["submodules_preflight"], self.submodules)

    def __call__(self):
        fd = open_dir(self.operation + "/project")
        try:
            source_now = scan_tree(fd)
        finally:
            os.close(fd)
        protected_now = protected_map_preflight()
        submodules_now = submodule_map_runtime(source_now, self.submodules)
        protected_match = protected_now == self.protected
        submodules_match = submodules_now == self.submodules
        return {"source_match": source_now == self.source_rows,
                "protected_match": protected_match,
                "submodules_match": submodules_match,
                "preflight_sha256": digest(canonical(self.source_rows)),
                "postflight_sha256": digest(canonical(source_now)),
                "source_postflight": {
                    "schema_version": "r11_source_snapshot_postflight.v1",
                    "entries": source_now},
                "protected_postflight": protected_now,
                "submodules_postflight": submodules_now}


def protected_map_preflight():
    roots = []
    for path in ("/root/fanzehui/system-20261016", "/root/fanzehui/myfuzz/project"):
        fd = open_dir(path)
        try:
            roots.append({"path": path, "entries": scan_tree(fd, max_file_size=None)})
        finally:
            os.close(fd)
    return {"schema_version": "r11_protected_baselines_map.v1", "roots": roots}


def submodule_map_preflight(source_rows, frozen_manifest):
    static = decode(frozen_manifest["raw"], "submodule-manifest")
    need(type(static) is dict and set(static) == {"schema_version", "entries"}
         and static["schema_version"] == "r11_submodule_manifest.v1"
         and type(static["entries"]) is list, "submodule-manifest:shape")
    runtime = submodule_map_runtime(source_rows, static)
    need(runtime["entries"] == static["entries"], "submodule-manifest:source-mismatch")
    return runtime


def submodule_map_runtime(source_rows, static_or_runtime):
    static_rows = static_or_runtime["entries"]
    need(type(static_rows) is list, "submodule-manifest:entries")
    result = []
    paths = []
    required = {"path", "tracked_mode", "gitlink_commit", "checked_out",
                "checked_out_head", "selected_entries_sha256",
                "selected_entries_count"}
    for row in static_rows:
        need(type(row) is dict and set(row) == required, "submodule-manifest:row")
        path = row["path"]
        components(path)
        need(row["tracked_mode"] == "160000" and hex64(row["selected_entries_sha256"])
             and type(row["selected_entries_count"]) is int
             and row["selected_entries_count"] >= 0
             and type(row["checked_out"]) is bool
             and commit_id(row["gitlink_commit"])
             and (commit_id(row["checked_out_head"])
                  if row["checked_out"] else row["checked_out_head"] is None),
             "submodule-manifest:metadata")
        selected = [entry for entry in source_rows if entry["path"] == path
                    or entry["path"].startswith(path + "/")]
        need(not selected or (selected[0]["path"] == path
             and selected[0]["kind"] == "directory"),
             "submodule:invalid-root:" + path)
        need(not row["checked_out"] or bool(selected),
             "submodule:checkout-missing:" + path)
        result.append({"path": path, "tracked_mode": row["tracked_mode"],
                       "gitlink_commit": row["gitlink_commit"],
                       "checked_out": row["checked_out"],
                       "checked_out_head": row["checked_out_head"],
                       "selected_entries_sha256": digest(canonical_ascii(selected)),
                       "selected_entries_count": len(selected)})
        paths.append(path)
    need(paths == sorted(set(paths)), "submodule-manifest:ordering")
    return {"schema_version": "r11_submodule_runtime_map.v1", "entries": result}


def lock_identity(wsfd, path, workspace):
    need(under(path, workspace), "lock:path")
    relative = path[len(workspace) + 1:]
    st = leaf_stat(wsfd, relative)
    need(st is not None and stat.S_ISREG(st.st_mode) and st.st_nlink == 1,
         "lock:type")
    raw, read_st = read_file(wsfd, relative)
    need(read_st.st_ino == st.st_ino and read_st.st_dev == st.st_dev,
         "lock:changed")
    return {"path": path, "sha256": digest(raw), "size": st.st_size,
            "mode": stat.S_IMODE(st.st_mode), "device": st.st_dev,
            "inode": st.st_ino}


def claimed_run(opfd, wsfd, operation, evidence, workspace, run, run_id,
                frozen, child_env, gate_interpreter, preflight, lock_before, claim):
    plan_sha = frozen["plan"]["sha256"]
    controller_sha = frozen["controller"]["sha256"]
    intent_sha = frozen["intent"]["sha256"]
    launch = {"schema_version": "task5_r11_launch_intent.v1",
              "plan_sha256": plan_sha, "intent_sha256": intent_sha,
              "controller_sha256": controller_sha, "gate_run_id": run_id,
              "stage2_manifest_sha256": frozen["stage2_manifest"]["sha256"],
              "argv": run["argv"], "cwd": run["cwd"], "output": evidence,
              "controller_pid": claim["pid"], "gate_started": False,
              "gate_executed": False}
    proc = None
    pgid = None
    gone = None
    group_deadline = None
    group_observation_error = None
    reaped = False
    rc = None
    observed_output = None
    observation_errors = []
    stage = "launch-intent"
    try:
        write_json(opfd, OUTPUTS["launch_intent"], launch)
        stage = "dynamic-cache"
        os.mkdir("native-cache", 0o700, dir_fd=opfd)
        cache_fd = os.open("native-cache", os.O_RDONLY | os.O_DIRECTORY |
                           os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=opfd)
        try:
            os.fchmod(cache_fd, 0o700)
            cache_stat = os.fstat(cache_fd)
            cache_readback = os.stat("native-cache", dir_fd=opfd,
                                     follow_symlinks=False)
            need(stat.S_ISDIR(cache_stat.st_mode)
                 and cache_stat.st_uid == os.geteuid()
                 and stat.S_IMODE(cache_stat.st_mode) == 0o700
                 and (cache_stat.st_dev, cache_stat.st_ino) ==
                     (cache_readback.st_dev, cache_readback.st_ino),
                 "dynamic-cache:identity")
            os.fsync(cache_fd)
            os.fsync(opfd)
        finally:
            os.close(cache_fd)
        stdout_fd = open_log(opfd, OUTPUTS["gate_stdout"])
        try:
            stderr_fd = open_log(opfd, OUTPUTS["gate_stderr"])
            try:
                stage = "spawn"
                proc = subprocess.Popen(run["argv"], executable=gate_interpreter,
                                        cwd=run["cwd"], env=child_env,
                                        stdin=subprocess.PIPE, stdout=stdout_fd,
                                        stderr=stderr_fd, start_new_session=True,
                                        close_fds=True)
                pgid = proc.pid  # Candidate from start_new_session, retained on early exit.
                proc.stdin.close()
            finally:
                os.close(stderr_fd)
        finally:
            os.close(stdout_fd)
        stage = "process-group-identity"
        try:
            observed_pgid = os.getpgid(proc.pid)
        except ProcessLookupError as exc:
            raise Refusal("spawn:pgid-unverified-child-exited") from exc
        need(observed_pgid == pgid, "spawn:pgid-mismatch")
        start = {"schema_version": "task5_r11_gate_start.v1", "plan_sha256": plan_sha,
                 "controller_sha256": controller_sha, "gate_run_id": run_id,
                 "argv": run["argv"], "cwd": run["cwd"], "output": evidence,
                 "controller_pid": claim["pid"], "pid": proc.pid,
                 "process_group_id": pgid, "status": "running"}
        stage = "gate-start"
        write_json(opfd, OUTPUTS["gate_start"], start)
        stage = "wait"
        while True:
            if observed_output is None:
                observed_output = output_identity(evidence)
            try:
                rc = proc.wait(timeout=WAIT_INTERVAL)
                reaped = True
                group_deadline = time.monotonic() + GROUP_WINDOW
                break
            except subprocess.TimeoutExpired:
                observation = {"schema_version": "task5_r11_wait_observation.v1",
                               "gate_run_id": run_id, "controller_pid": claim["pid"],
                               "gate_pid": proc.pid, "process_group_id": pgid,
                               "kind": "wait_timeout", "monotonic_ns": time.monotonic_ns()}
                try:
                    write_json(opfd, "control/observation-%d.v1.json" %
                               observation["monotonic_ns"], observation)
                except Exception as exc:
                    observation_errors.append(type(exc).__name__ + ":" + str(exc))
        if observed_output is None:
            observed_output = output_identity(evidence)
        stage = "process-group-observation"
        gone = observe_group(pgid, group_deadline)
        need(gone, "process-group:still-live")
        stage = "collection"
        return collect(opfd, wsfd, operation, evidence, workspace, run, run_id,
                       frozen, preflight, lock_before, claim, proc.pid, pgid,
                       rc, observed_output, observation_errors)
    except BaseException as exc:
        if stage == "process-group-observation" and gone is None:
            group_observation_error = {"type": type(exc).__name__,
                                       "message": str(exc)}
            observation_errors.append("process-group-observation:" +
                                      type(exc).__name__ + ":" + str(exc))
        if proc is not None and not reaped:
            # Preserve the sole Popen handle and keep observing until reaped.
            while True:
                try:
                    rc = proc.wait(timeout=WAIT_INTERVAL)
                    reaped = True
                    group_deadline = time.monotonic() + GROUP_WINDOW
                    break
                except subprocess.TimeoutExpired:
                    observation = {"schema_version": "task5_r11_wait_observation.v1",
                                   "gate_run_id": run_id,
                                   "controller_pid": claim["pid"],
                                   "gate_pid": proc.pid,
                                   "kind": "wait_timeout_after_failure",
                                   "failure_stage": stage,
                                   "monotonic_ns": time.monotonic_ns()}
                    if pgid is not None:
                        observation["process_group_id"] = pgid
                    try:
                        write_json(opfd, "control/observation-%d.v1.json" %
                                   observation["monotonic_ns"], observation)
                    except Exception as observe_exc:
                        observation_errors.append(type(observe_exc).__name__ +
                                                  ":" + str(observe_exc))
        if proc is not None and pgid is not None and reaped and gone is None:
            if group_deadline is None:
                group_deadline = time.monotonic() + GROUP_WINDOW
            try:
                gone = observe_group(pgid, group_deadline)
            except Exception as observe_exc:
                retry_error = {"type": type(observe_exc).__name__,
                               "message": str(observe_exc)}
                group_observation_error = (
                    {"initial": group_observation_error, "retry": retry_error}
                    if group_observation_error is not None else retry_error)
                observation_errors.append("process-group-observation:" +
                                          type(observe_exc).__name__ + ":" +
                                          str(observe_exc))
        failure = {"schema_version": "task5_r11_gate_end.v1",
                   "terminal_status": "failed", "failure_stage": stage,
                   "failure_type": type(exc).__name__, "failure": str(exc),
                   "gate_run_id": run_id, "controller_pid": claim["pid"],
                   "plan_sha256": plan_sha, "controller_sha256": controller_sha,
                   "stage2_manifest_sha256": frozen["stage2_manifest"]["sha256"],
                   "reaped_by_wait": reaped, "observation_errors": observation_errors,
                   "claims": CLAIMS}
        if proc is not None:
            failure["pid"] = proc.pid
        if pgid is not None:
            failure["process_group_id"] = pgid
        if type(rc) is int:
            failure["returncode"] = rc
        if observed_output is not None:
            failure["observed_output"] = observed_output
        if type(gone) is bool:
            failure["process_group_gone"] = gone
        if group_observation_error is not None:
            failure["process_group_observation_error"] = group_observation_error
        end_sha = None
        try:
            if leaf_stat(opfd, OUTPUTS["gate_end"]) is None:
                end_sha = write_json(opfd, OUTPUTS["gate_end"], failure)
            else:
                raw, _ = read_file(opfd, OUTPUTS["gate_end"])
                end_sha = digest(raw)
        except Exception as write_exc:
            print("gate-end receipt write failed: " + str(write_exc), file=sys.stderr)
        if leaf_stat(opfd, OUTPUTS["post_run_integrity"]) is None:
            partial = {"schema_version": "task5_r11_post_run_integrity.v1",
                       "terminal_status": "failed", "failure_stage": stage,
                       "gate_run_id": run_id, "plan_sha256": plan_sha,
                       "stage2_manifest_sha256": frozen["stage2_manifest"]["sha256"],
                       "controller_sha256": controller_sha, "claims": CLAIMS}
            if end_sha is not None:
                partial["gate_end_sha256"] = end_sha
            if type(rc) is int:
                partial["gate_returncode"] = rc
            if type(gone) is bool:
                partial["process_group_gone"] = gone
            if group_observation_error is not None:
                partial["process_group_observation_error"] = group_observation_error
            if proc is not None:
                partial["gate_pid"] = proc.pid
            try:
                write_json(opfd, OUTPUTS["post_run_integrity"], partial)
            except Exception as write_exc:
                print("post-run failure receipt write failed: " + str(write_exc),
                      file=sys.stderr)
        raise


def open_log(opfd, relative):
    parent, leaf = parent_leaf(opfd, relative)
    try:
        fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, RECEIPT_MODE, dir_fd=parent)
        try:
            os.fchmod(fd, RECEIPT_MODE)
            st = os.fstat(fd)
            need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, "log:inode")
            os.fsync(fd)
            os.fsync(parent)
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(parent)


def collect(opfd, wsfd, operation, evidence, workspace, run, run_id,
            frozen, preflight, lock_before, claim, pid, pgid, rc,
            observed_output, observation_errors):
    # The reviewed full-map adapter must return a callable that re-inventories
    # source, protected roots and submodules. A mismatch is a refusal.
    postflight = preflight()
    source_snapshot_post_sha = write_json(
        opfd, OUTPUTS["source_snapshot_postflight"],
        postflight["source_postflight"])
    protected_post_sha = write_json(opfd, OUTPUTS["protected_postflight"],
                                    postflight["protected_postflight"])
    submodules_post_sha = write_json(opfd, OUTPUTS["submodules_postflight"],
                                     postflight["submodules_postflight"])
    source_match = postflight["source_match"] is True
    protected_match = postflight["protected_match"] is True
    submodules_match = postflight["submodules_match"] is True
    lock_after = lock_identity(wsfd, run["heavy_lock"], workspace)
    lock_match = lock_before == lock_after
    source_receipt = {"schema_version": "task5_r11_source_postflight.v1",
                      "status": "source_tree_manifest_match" if source_match else "mismatch",
                      "matches_preflight": source_match,
                      "source_manifest_sha256": frozen["source_manifest"]["sha256"],
                      "full_map_preflight_sha256": postflight["preflight_sha256"],
                      "full_map_postflight_sha256": postflight["postflight_sha256"],
                      "source_snapshot_map_sha256": preflight.map_sha,
                      "source_snapshot_postflight": {
                          "path": operation + "/" + OUTPUTS["source_snapshot_postflight"],
                          "sha256": source_snapshot_post_sha},
                      "claims": CLAIMS}
    source_sha = write_json(opfd, OUTPUTS["source_postflight"], source_receipt)
    lock_receipt = {"schema_version": "task5_r11_lock_postflight.v1",
                    "status": "match" if lock_match else "mismatch",
                    "matches_preflight": lock_match, "expected": lock_before,
                    "observed": lock_after, "claims": CLAIMS}
    lock_sha = write_json(opfd, OUTPUTS["lock_postflight"], lock_receipt)
    stdout, _ = read_file(opfd, OUTPUTS["gate_stdout"])
    stderr, _ = read_file(opfd, OUTPUTS["gate_stderr"])
    evidence_fd = open_dir(evidence) if observed_output is not None else None
    branches = {}
    branch_status = {}
    summary_sha = None
    evidence_valid = False
    try:
        if evidence_fd is not None:
            for branch in BRANCHES:
                raw, _ = read_file(evidence_fd, branch + "/result.json.gz")
                doc = gzip_json(raw, "branch:" + branch)
                need(doc.get("gate_run_id") == run_id
                     and doc.get("gate_branch") == branch
                     and type(doc.get("gate_pid")) is int and doc["gate_pid"] == pid,
                     "branch:identity:" + branch)
                branches[branch] = digest(raw)
                branch_status[branch] = doc.get("status")
            raw, _ = read_file(evidence_fd, "summary.json.gz")
            summary = gzip_json(raw, "summary")
            need(summary.get("gate_run_id") == run_id
                 and type(summary.get("gate_pid")) is int and summary["gate_pid"] == pid
                 and summary.get("schema_version") == "native_online_directed_gate.v1"
                 and summary.get("positive_status") == branch_status["positive"]
                    == "bounded_directed_gate_passed"
                 and summary.get("controlled_status") == branch_status["controlled-response"]
                    == "bounded_directed_gate_passed"
                 and summary.get("native_source_refusal_status") == branch_status["native-source-refusal"]
                    == "native_source_completion_refusal_gate_passed"
                 and all(summary.get(name) is True for name in
                         ("native_completion_observation", "native_source_binding",
                          "native_source_completion"))
                 and all(summary.get(name) is False for name in CLAIMS)
                 and summary.get("script_sha256") == frozen["gate_script"]["sha256"],
                 "summary:identity")
            summary_sha = digest(raw)
            evidence_valid = True
    finally:
        if evidence_fd is not None:
            os.close(evidence_fd)
    output_now = output_identity(evidence)
    output_owned = (observed_output is not None and output_now == observed_output
                    and preflight.output_absent is True
                    and preflight.sole_authorized_writer is True)
    gate_process_completed = (type(rc) is int and rc == 0 and evidence_valid
                              and output_owned and not observation_errors)
    success = (gate_process_completed and source_match and protected_match
               and submodules_match and lock_match)
    end = {"schema_version": "task5_r11_gate_end.v1", "pid": pid,
           "gate_run_id": run_id, "controller_pid": claim["pid"],
           "stage2_manifest_sha256": frozen["stage2_manifest"]["sha256"],
           "process_group_id": pgid, "returncode": rc,
           "gate_started": True, "gate_executed": True,
           "reaped_by_wait": True, "process_group_gone": True,
           "terminal_status": ("gate_process_completed" if gate_process_completed
                               else "failed"),
           "claims": CLAIMS, "stdout_sha256": digest(stdout),
           "stderr_sha256": digest(stderr),
           "observed_output": observed_output,
           "observation_errors": observation_errors}
    if branches:
        end["branch_result_sha256"] = branches
    if summary_sha is not None:
        end["summary_sha256"] = summary_sha
    end_sha = write_json(opfd, OUTPUTS["gate_end"], end)
    post = {"schema_version": "task5_r11_post_run_integrity.v1",
            "gate_end": end, "gate_end_sha256": end_sha,
            "gate_run_id": run_id, "plan_sha256": frozen["plan"]["sha256"],
            "stage2_manifest_sha256": frozen["stage2_manifest"]["sha256"],
            "controller_sha256": frozen["controller"]["sha256"],
            "gate_returncode": rc, "gate_started": True,
            "gate_executed": True, "process_group_gone": True,
            "output_created_by_gate": output_owned,
            "source_tree_matches_preflight": source_match,
            "protected_baselines_match_preflight": protected_match,
            "submodules_match_preflight": submodules_match,
            "canonical_lock_matches_preflight": lock_match,
            "postflight_receipts": {"source_tree": {
                                        "path": operation + "/" + OUTPUTS["source_postflight"],
                                        "sha256": source_sha},
                                    "canonical_lock": {
                                        "path": operation + "/" + OUTPUTS["lock_postflight"],
                                        "sha256": lock_sha},
                                    "source_snapshot_postflight": {
                                        "path": operation + "/" + OUTPUTS["source_snapshot_postflight"],
                                        "sha256": source_snapshot_post_sha},
                                    "protected_baselines_preflight": {
                                        "path": operation + "/" + OUTPUTS["protected_preflight"],
                                        "sha256": preflight.protected_preflight_sha},
                                    "protected_baselines_postflight": {
                                        "path": operation + "/" + OUTPUTS["protected_postflight"],
                                        "sha256": protected_post_sha},
                                    "submodules_preflight": {
                                        "path": operation + "/" + OUTPUTS["submodules_preflight"],
                                        "sha256": preflight.submodules_preflight_sha},
                                    "submodules_postflight": {
                                        "path": operation + "/" + OUTPUTS["submodules_postflight"],
                                        "sha256": submodules_post_sha}},
            "claims": CLAIMS, "terminal_status": "completed" if success else "failed"}
    write_json(opfd, OUTPUTS["post_run_integrity"], post)
    need(success, "terminal:integrity-failed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Refusal, OSError, ValueError, KeyError, TypeError) as exc:
        print("r11 controller refused: " + str(exc), file=sys.stderr)
        sys.exit(1)
