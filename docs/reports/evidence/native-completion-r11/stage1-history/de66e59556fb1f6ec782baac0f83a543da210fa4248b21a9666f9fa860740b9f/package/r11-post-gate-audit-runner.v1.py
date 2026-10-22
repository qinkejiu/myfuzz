#!/usr/bin/env python3
"""Seal one completed r11 gate run, then invoke its frozen independent auditor.

The prepare phase creates the exclusive final identity. A separate reviewer
recomputes its raw SHA-256 and supplies that value to the audit phase. This
program never starts the gate.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import math
import os
import posixpath
from pathlib import PurePosixPath
import re
import stat
import subprocess
import sys


IDENTITY_REL = "control/audit-identity.v1.json"
AUDIT_REL = "independent-audit.json"
LIMIT = 64 * 1024 * 1024
EXPANDED_LIMIT = 256 * 1024 * 1024
HEX = re.compile(r"[0-9a-f]{64}\Z")
CLAIMS = {"coverage_guided_search": False, "formal_p6_complete": False,
          "retirement_authority": False, "source_authority": False}
OPERATION_FILES = {
    "intent": "control/intent.v1.json",
    "plan": "control/run-plan.v1.json",
    "controller": "control/r11-one-shot-controller.v1.py",
    "controller_receipt": "control/controller-receipt.v1.json",
    "claim": "control/claim.v1.json",
    "launch_intent": "control/launch-intent.v1.json",
    "gate_start": "control/gate-start.v1.json",
    "gate_end": "control/gate-end.v1.json",
    "post_run_integrity": "control/post-run-integrity.v1.json",
    "source_postflight": "control/source-postflight.v1.json",
    "lock_postflight": "control/lock-postflight.v1.json",
    "source_manifest": "control/source-manifest.v1.json",
    "gate_script": "project/scripts/verify_picorv32_native_online.py",
    "auditor": "control/r11-independent-auditor.v1.py",
    "gate_stdout": "control/gate.stdout.log",
    "gate_stderr": "control/gate.stderr.log",
}
EVIDENCE_FILES = {
    "positive": "positive/result.json.gz",
    "controlled-response": "controlled-response/result.json.gz",
    "native-source-refusal": "native-source-refusal/result.json.gz",
    "summary": "summary.json.gz",
}
STAGE2_REL = "control/stage2-manifest.v1.json"
SOURCE_MAP_REL = "control/source-snapshot-map.v1.json"
STATIC_CODE_REL = "control/r11-static-code-manifest.v1.json"
SOURCE_POST_REL = "control/source-snapshot-postflight.v1.json"
STAGE1_ARTIFACTS = tuple(sorted((
    "r11-plan-schema.v1.json", "r11-source-byte-bootstrap.v1.py",
    "r11-post-gate-audit-runner.v1.py", "r11-independent-auditor.v1.py",
    "r11-gate-script.v1.py", "r11-one-shot-controller.v1.py",
    "r11-external-launch-contract.v1.json")))
MAP_RELS = {
    "protected_baselines_preflight": "control/protected-baselines-preflight.v1.json",
    "protected_baselines_postflight": "control/protected-baselines-postflight.v1.json",
    "submodules_preflight": "control/submodules-preflight.v1.json",
    "submodules_postflight": "control/submodules-postflight.v1.json",
}
DYNAMIC_LEAVES = {
    STAGE2_REL, "control/claim.v1.json", "control/launch-intent.v1.json",
    "control/gate-start.v1.json", "control/gate-end.v1.json",
    "control/post-run-integrity.v1.json", "control/source-postflight.v1.json",
    SOURCE_POST_REL, "control/lock-postflight.v1.json",
    "control/gate.stdout.log", "control/gate.stderr.log",
    "control/audit-identity.v1.json", "control/auditor-terminal.v1.json",
    "control/auditor.stdout.log", "control/auditor.stderr.log",
    *MAP_RELS.values(),
}
OBSERVATION = re.compile(r"control/observation-[0-9]+\.v1\.json\Z")
SUCCESS_RECEIPTS = {
    "controller_receipt": ("task5_r11_controller_receipt.v1", {
        "schema_version", "path", "controller_sha256", "intent_sha256",
        "gate_started", "gate_executed"}),
    "claim": ("task5_r11_claim.v1", {
        "schema_version", "plan_sha256", "intent_sha256", "controller_sha256",
        "stage2_manifest_sha256", "gate_run_id", "argv", "pid", "one_shot",
        "gate_started", "gate_executed"}),
    "launch_intent": ("task5_r11_launch_intent.v1", {
        "schema_version", "plan_sha256", "intent_sha256", "controller_sha256",
        "gate_run_id", "stage2_manifest_sha256", "argv", "cwd", "output",
        "controller_pid", "gate_started", "gate_executed"}),
    "gate_start": ("task5_r11_gate_start.v1", {
        "schema_version", "plan_sha256", "controller_sha256", "gate_run_id",
        "argv", "cwd", "output", "controller_pid", "pid", "process_group_id",
        "status"}),
    "gate_end": ("task5_r11_gate_end.v1", {
        "schema_version", "pid", "gate_run_id", "controller_pid",
        "stage2_manifest_sha256", "process_group_id", "returncode",
        "gate_started", "gate_executed", "reaped_by_wait", "process_group_gone",
        "terminal_status", "claims", "stdout_sha256", "stderr_sha256",
        "observed_output", "observation_errors", "branch_result_sha256",
        "summary_sha256"}),
    "post_run_integrity": ("task5_r11_post_run_integrity.v1", {
        "schema_version", "gate_end", "gate_end_sha256", "gate_run_id",
        "plan_sha256", "stage2_manifest_sha256", "controller_sha256",
        "gate_returncode", "gate_started", "gate_executed", "process_group_gone",
        "output_created_by_gate", "source_tree_matches_preflight",
        "protected_baselines_match_preflight", "submodules_match_preflight",
        "canonical_lock_matches_preflight", "postflight_receipts", "claims",
        "terminal_status"}),
    "source_postflight": ("task5_r11_source_postflight.v1", {
        "schema_version", "status", "matches_preflight", "source_manifest_sha256",
        "full_map_preflight_sha256", "full_map_postflight_sha256",
        "source_snapshot_map_sha256", "source_snapshot_postflight", "claims"}),
    "lock_postflight": ("task5_r11_lock_postflight.v1", {
        "schema_version", "status", "matches_preflight", "expected", "observed",
        "claims"}),
}


def verify_success_receipt_shapes(docs: dict) -> None:
    for name, (schema, keys) in SUCCESS_RECEIPTS.items():
        receipt = docs[name]
        require(type(receipt) is dict and
                receipt.get("schema_version") == schema and
                set(receipt) == keys, "success-receipt-shape:" + name)


def verify_static_code_manifest(operation: Root, stage2_entries: list[dict]) -> None:
    manifest = document(operation.read(STATIC_CODE_REL), "static-code-manifest")
    require(set(manifest) == {"schema_version", "entries"} and
            manifest["schema_version"] == "r11_static_code_manifest.v1" and
            type(manifest["entries"]) is list and
            len(manifest["entries"]) == len(STAGE1_ARTIFACTS),
            "static-code-manifest-shape")
    require([item.get("path") if type(item) is dict else None
             for item in manifest["entries"]] == list(STAGE1_ARTIFACTS),
            "static-code-manifest-paths")
    stage2_paths = {item["path"] for item in stage2_entries}
    required_copies = {"r11-one-shot-controller.v1.py",
                       "r11-independent-auditor.v1.py",
                       "r11-post-gate-audit-runner.v1.py",
                       "r11-plan-schema.v1.json",
                       "r11-external-launch-contract.v1.json"}
    for item in manifest["entries"]:
        require(type(item) is dict and set(item) == {"path", "size", "sha256"}
                and type(item["size"]) is int and 0 <= item["size"] <= LIMIT
                and type(item["sha256"]) is str and HEX.fullmatch(item["sha256"]),
                "static-code-manifest-row")
        copy = "control/" + item["path"]
        require(copy in stage2_paths or item["path"] not in required_copies,
                "static-code-runtime-copy-missing")
        if copy in stage2_paths:
            actual = operation.read(copy)
            require(len(actual) == item["size"] and
                    digest(actual) == item["sha256"],
                    "static-code-runtime-copy-mismatch:" + item["path"])
        if item["path"] == "r11-gate-script.v1.py":
            gate = operation.read(OPERATION_FILES["gate_script"])
            require(len(gate) == item["size"] and
                    digest(gate) == item["sha256"],
                    "static-code-gate-stage2-mismatch")
            if copy in stage2_paths:
                equal(operation.read(copy), gate, "static-code-gate-copy-bytes")
FLAGS = ["--native-completion-observation", "--native-source-binding",
         "--native-source-completion"]
GATES = ["native_completion_observation", "native_source_binding",
         "native_source_completion"]
ACCEPTANCE_MATRIX = [
    {"id": "selected_source_positive", "expected":
     "only the exact selected source-bound four-byte native instruction-bus transfer can issue completion evidence"},
    {"id": "noncandidate_no_grant", "expected":
     "unrelated/bootstrap/noncandidate reads remain diagnostic and receive no completion grant"},
    {"id": "controlled_response", "expected":
     "the controlled selected-source transaction follows its planned response path and produces the exact bound transfer result"},
    {"id": "selected_source_contradiction_original", "expected":
     "selected-source contradiction is terminally refused in the original run"},
    {"id": "selected_source_contradiction_fresh", "expected":
     "the same selected-source contradiction is terminally refused in the full fresh replay"},
    {"id": "full_fresh_replay", "expected":
     "the complete configured replay executes from fresh inputs"},
    {"id": "independent_raw_audit", "expected":
     "raw gate evidence is checked by the independent audit path"},
]


class RunnerError(Exception):
    pass


def require(ok: bool, code: str) -> None:
    if not ok:
        raise RunnerError(code)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def commit_id(value: object) -> bool:
    return (type(value) is str and
            re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value) is not None)


def first_path_executable(path_dirs: list[str], name: str) -> str | None:
    require(type(name) is str and name and "/" not in name and
            name not in (".", ".."), "resolved-command-name")
    for directory in path_dirs:
        root = Root(directory)
        try:
            try:
                info = os.stat(name, dir_fd=root.fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            require(not stat.S_ISLNK(info.st_mode),
                    "resolved-command-symlink:" + name)
            if stat.S_ISREG(info.st_mode) and info.st_mode & 0o111:
                require(info.st_nlink == 1 and
                        os.access(name, os.X_OK, dir_fd=root.fd,
                                  follow_symlinks=False),
                        "resolved-command-inaccessible:" + name)
                return directory + "/" + name
        finally:
            root.close()
    return None


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def document(raw: bytes, label: str) -> dict:
    def unique(pairs):
        row = {}
        for key, value in pairs:
            require(key not in row, "duplicate-json-key:" + label)
            row[key] = value
        return row

    def reject(value):
        raise RunnerError("nonfinite-json:" + label + ":" + value)

    def finite_float(token):
        value = float(token)
        require(math.isfinite(value), "nonfinite-json:" + label)
        return value

    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=reject,
                           parse_float=finite_float)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RunnerError("invalid-json:" + label) from exc
    require(type(value) is dict, "not-json-object:" + label)
    return value


def relative(path: str) -> tuple[str, ...]:
    require(type(path) is str and path and not path.startswith("/"),
            "unsafe-relative-path")
    parts = tuple(path.split("/"))
    require(all(part not in ("", ".", "..") for part in parts)
            and PurePosixPath(path).as_posix() == path, "unsafe-relative-path")
    return parts


def absolute(path: str) -> str:
    require(type(path) is str and path.startswith("/") and
            all(part not in (".", "..", "") for part in path.split("/")[1:]),
            "unsafe-absolute-path")
    return path


class Root:
    """Read regular files through directory descriptors without following links."""

    def __init__(self, path: str):
        self.path = absolute(path)
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for part in path.split("/")[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                                os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd)
                fd = child
            self.fd = fd
        except BaseException:
            os.close(fd)
            raise

    def close(self) -> None:
        os.close(self.fd)

    def read(self, path: str) -> bytes:
        parts = relative(path)
        parent = os.dup(self.fd)
        fd = None
        try:
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                                os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                os.close(parent)
                parent = child
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW |
                         os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and before.st_size <= LIMIT, "unsafe-input:" + path)
            chunks = []
            size = 0
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                require(size <= LIMIT, "oversize-input:" + path)
                chunks.append(chunk)
            after = os.fstat(fd)
            require((before.st_dev, before.st_ino, before.st_size,
                     before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_dev, after.st_ino, after.st_size,
                     after.st_mtime_ns, after.st_ctime_ns),
                    "input-changed:" + path)
            return b"".join(chunks)
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent)

    def inventory(self) -> list[dict]:
        """Scan operation bytes including modes and symlinks, omitting fixed leaves."""
        rows = []

        def visit(directory_fd: int, prefix: str) -> None:
            directory = os.fstat(directory_fd)
            require(stat.S_ISDIR(directory.st_mode), "inventory-directory")
            rows.append({"path": prefix or ".", "kind": "directory",
                         "mode": stat.S_IMODE(directory.st_mode)})
            with os.scandir(directory_fd) as iterator:
                names = sorted(entry.name for entry in iterator)
            for name in names:
                require(name not in ("", ".", "..") and "/" not in name,
                        "inventory-entry-name")
                path = prefix + "/" + name if prefix else name
                if path in DYNAMIC_LEAVES or OBSERVATION.fullmatch(path):
                    excluded = os.stat(name, dir_fd=directory_fd,
                                       follow_symlinks=False)
                    require(stat.S_ISREG(excluded.st_mode) and
                            excluded.st_nlink == 1,
                            "dynamic-leaf-not-regular:" + path)
                    continue
                before = os.stat(name, dir_fd=directory_fd,
                                 follow_symlinks=False)
                if path == "native-cache":
                    require(stat.S_ISDIR(before.st_mode), "native-cache-not-directory")
                    continue
                mode = stat.S_IMODE(before.st_mode)
                if stat.S_ISDIR(before.st_mode):
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY |
                                    os.O_NOFOLLOW | os.O_CLOEXEC,
                                    dir_fd=directory_fd)
                    try:
                        opened = os.fstat(child)
                        require((before.st_dev, before.st_ino) ==
                                (opened.st_dev, opened.st_ino),
                                "inventory-directory-race:" + path)
                        visit(child, path)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(before.st_mode):
                    require(before.st_nlink == 1 and before.st_size <= LIMIT,
                            "inventory-file-links-or-size:" + path)
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW |
                                 os.O_CLOEXEC, dir_fd=directory_fd)
                    try:
                        opened = os.fstat(fd)
                        require(stat.S_ISREG(opened.st_mode) and
                                opened.st_nlink == 1 and
                                (opened.st_dev, opened.st_ino, opened.st_size,
                                 opened.st_mtime_ns, opened.st_ctime_ns) ==
                                (before.st_dev, before.st_ino, before.st_size,
                                 before.st_mtime_ns, before.st_ctime_ns),
                                "inventory-file-race:" + path)
                        hasher = hashlib.sha256()
                        size = 0
                        while True:
                            block = os.read(fd, 1024 * 1024)
                            if not block:
                                break
                            hasher.update(block)
                            size += len(block)
                            require(size <= LIMIT, "inventory-file-oversize:" + path)
                        after = os.fstat(fd)
                        require((after.st_dev, after.st_ino, after.st_size,
                                 after.st_mtime_ns, after.st_ctime_ns) ==
                                (before.st_dev, before.st_ino, before.st_size,
                                 before.st_mtime_ns, before.st_ctime_ns) and
                                size == before.st_size,
                                "inventory-file-changed:" + path)
                        rows.append({"path": path, "kind": "file", "mode": mode,
                                     "size": size, "sha256": hasher.hexdigest()})
                    finally:
                        os.close(fd)
                elif stat.S_ISLNK(before.st_mode):
                    require(before.st_nlink == 1, "inventory-symlink-links:" + path)
                    target = os.readlink(name, dir_fd=directory_fd)
                    require(type(target) is str and target and not target.startswith("/"),
                            "inventory-symlink-target:" + path)
                    resolved = posixpath.normpath(posixpath.join(
                        posixpath.dirname(path), target))
                    require(resolved != ".." and not resolved.startswith("../"),
                            "inventory-symlink-escape:" + path)
                    after = os.stat(name, dir_fd=directory_fd,
                                    follow_symlinks=False)
                    require((before.st_dev, before.st_ino, before.st_mtime_ns) ==
                            (after.st_dev, after.st_ino, after.st_mtime_ns),
                            "inventory-symlink-race:" + path)
                    rows.append({"path": path, "kind": "symlink",
                                 "mode": mode, "target": target})
                else:
                    raise RunnerError("inventory-special-file:" + path)
            after_directory = os.fstat(directory_fd)
            require((directory.st_dev, directory.st_ino, directory.st_mode,
                     directory.st_mtime_ns) ==
                    (after_directory.st_dev, after_directory.st_ino,
                     after_directory.st_mode, after_directory.st_mtime_ns),
                    "inventory-directory-changed:" + (prefix or "."))

        visit(self.fd, "")
        rows.sort(key=lambda value: value["path"])
        return rows

    def write_exclusive(self, path: str, raw: bytes) -> None:
        parts = relative(path)
        parent = os.dup(self.fd)
        fd = None
        try:
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                                os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                os.close(parent)
                parent = child
            fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            opened = os.fstat(fd)
            require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1,
                    "identity-output-not-regular")
            view = memoryview(raw)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
            os.fsync(parent)
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent)


def gzip_document(raw: bytes, label: str) -> dict:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
            expanded = stream.read(EXPANDED_LIMIT + 1)
        require(len(expanded) <= EXPANDED_LIMIT, "oversize-gzip:" + label)
    except (OSError, EOFError) as exc:
        raise RunnerError("invalid-gzip:" + label) from exc
    return document(expanded, label)


def row(root: Root, path: str) -> dict:
    return {"path": path, "sha256": digest(root.read(path))}


def exact_value(actual: object, expected: object) -> bool:
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return (actual.keys() == expected.keys() and
                all(exact_value(actual[key], value) for key, value in expected.items()))
    if type(expected) in (list, tuple):
        return (len(actual) == len(expected) and
                all(exact_value(left, right) for left, right in zip(actual, expected)))
    return actual == expected


def equal(actual: object, expected: object, label: str) -> None:
    require(exact_value(actual, expected), "mismatch:" + label)


def validate_entries(entries: object, label: str,
                     *, max_file_size: int | None = LIMIT) -> list[dict]:
    require(type(entries) is list and entries, "empty-entry-map:" + label)
    paths = []
    for entry in entries:
        require(type(entry) is dict and type(entry.get("path")) is str and
                type(entry.get("kind")) is str, "entry-shape:" + label)
        path, kind = entry["path"], entry["kind"]
        if path != ".":
            relative(path)
        keys = {"directory": {"path", "kind", "mode"},
                "file": {"path", "kind", "mode", "size", "sha256"},
                "symlink": {"path", "kind", "mode", "target"}}.get(kind)
        require(keys is not None and set(entry) == keys and
                type(entry["mode"]) is int and 0 <= entry["mode"] <= 0o7777,
                "entry-kind-or-mode:" + label + ":" + path)
        if kind == "file":
            require(type(entry["size"]) is int and entry["size"] >= 0 and
                    (max_file_size is None or entry["size"] <= max_file_size) and
                    type(entry["sha256"]) is str and HEX.fullmatch(entry["sha256"]),
                    "file-entry:" + label + ":" + path)
        if kind == "symlink":
            target = entry["target"]
            require(type(target) is str and target and not target.startswith("/"),
                    "symlink-entry:" + label + ":" + path)
            resolved = posixpath.normpath(posixpath.join(
                posixpath.dirname(path), target))
            require(resolved != ".." and not resolved.startswith("../"),
                    "symlink-entry-escape:" + label + ":" + path)
        paths.append(path)
    require(paths == sorted(set(paths)) and entries[0]["path"] == "." and
            entries[0]["kind"] == "directory", "entry-order:" + label)
    return entries


def verify_stage2(operation: Root, expected_sha: str) -> tuple[dict, list[dict]]:
    require(type(expected_sha) is str and HEX.fullmatch(expected_sha),
            "stage2-external-sha-format")
    raw = operation.read(STAGE2_REL)
    equal(digest(raw), expected_sha, "stage2-external-sha")
    manifest = document(raw, "stage2-manifest")
    require(set(manifest) == {"schema_version", "entries"} and
            manifest["schema_version"] == "r11_stage2_manifest.v1",
            "stage2-manifest-shape")
    entries = validate_entries(manifest["entries"], "stage2")
    require(not any(row["path"] in DYNAMIC_LEAVES or
                    OBSERVATION.fullmatch(row["path"]) or
                    row["path"] == "native-cache" or
                    row["path"].startswith("native-cache/") for row in entries),
            "stage2-dynamic-row")
    equal(operation.inventory(), entries, "stage2-live-inventory")
    return manifest, entries


def run_contract(operation: str, evidence: str, workspace: str, run: dict) -> None:
    require(type(run) is dict and set(run) == {
        "argv", "cwd", "output", "cache_dir", "heavy_lock", "gate_run_id",
        "requested_gate_flags", "requested_gates"}, "run-shape")
    run_id = run["gate_run_id"]
    require(type(run_id) is str and HEX.fullmatch(run_id), "run-id")
    argv = ["python3", "-B", operation + "/" + OPERATION_FILES["gate_script"],
            "--output", evidence, "--cache-dir", operation + "/native-cache",
            "--heavy-lock", workspace + "/.superpowers/heavy-worker.lock",
            "--gate-run-id", run_id, *FLAGS]
    equal(run["argv"], argv, "gate-argv")
    equal(run["cwd"], operation + "/project", "gate-cwd")
    equal(run["output"], evidence, "gate-output")
    equal(run["cache_dir"], operation + "/native-cache", "gate-cache")
    equal(run["heavy_lock"], workspace + "/.superpowers/heavy-worker.lock",
          "gate-lock")
    equal(run["requested_gate_flags"], FLAGS, "gate-flags")
    equal(run["requested_gates"], GATES, "gate-list")


def collect(operation: Root, evidence: Root, workspace: Root,
            stage2_sha: str) -> dict:
    op = operation.path
    ev = evidence.path
    ws = workspace.path
    require(op == ws + "/operations/" + op.rsplit("/", 1)[1] and
            ev == ws + "/evidence/" + op.rsplit("/", 1)[1] and
            op.rsplit("/", 1)[1] != "p6-native-instruction-bus-completion-v1-20261018-attempt6",
            "operation-evidence-roots")
    _, stage2_entries = verify_stage2(operation, stage2_sha)
    verify_static_code_manifest(operation, stage2_entries)
    operation_files = {key: row(operation, path)
                       for key, path in OPERATION_FILES.items()}
    evidence_files = {key: row(evidence, path)
                      for key, path in EVIDENCE_FILES.items()}
    tool_path = "operations/" + op.rsplit("/", 1)[1] + "/control/tool-freeze.v1.json"
    workspace_files = {"tool_freeze": row(workspace, tool_path)}
    docs = {key: document(operation.read(path), key)
            for key, path in OPERATION_FILES.items()
            if key not in {"controller", "gate_script", "auditor",
                           "gate_stdout", "gate_stderr"}}
    verify_success_receipt_shapes(docs)
    intent, plan, run = docs["intent"], docs["plan"], docs["intent"].get("run")
    run_contract(op, ev, ws, run)
    hashes = {key: value["sha256"] for key, value in operation_files.items()}
    equal(plan.get("run"), run, "plan-run")
    equal(plan.get("intent"), intent, "plan-intent")
    equal(plan.get("gate_run_id"), run["gate_run_id"], "plan-run-id")
    equal(plan.get("intent_sha256"), hashes["intent"], "plan-intent-sha")
    equal(plan.get("controller_sha256"), hashes["controller"], "plan-controller-sha")
    equal(plan.get("controller_receipt_sha256"), hashes["controller_receipt"],
          "plan-controller-receipt-sha")
    auditor_ref = plan.get("post_gate_audit")
    require(type(auditor_ref) is dict, "plan-auditor")
    equal(auditor_ref.get("path"), op + "/" + OPERATION_FILES["auditor"],
          "plan-auditor-path")
    equal(auditor_ref.get("sha256"), hashes["auditor"], "plan-auditor-sha")
    for name in ("intent", "plan"):
        equal(docs[name].get("claims"), CLAIMS, name + "-claims")
        equal(docs[name].get("acceptance_matrix"), ACCEPTANCE_MATRIX,
              name + "-acceptance-matrix")
        equal(docs[name].get("gate_started"), False, name + "-gate-started")
        equal(docs[name].get("gate_executed"), False, name + "-gate-executed")
    source_manifest = docs["source_manifest"]
    require(set(source_manifest) == {"schema_version", "entries"} and
            source_manifest["schema_version"] == "source_tree_manifest.v1" and
            type(source_manifest["entries"]) is list and source_manifest["entries"],
            "source-manifest")
    source_paths = set()
    for item in source_manifest["entries"]:
        require(type(item) is dict and set(item) == {"path", "sha256"} and
                type(item["sha256"]) is str and HEX.fullmatch(item["sha256"]),
                "source-entry-shape")
        path = item["path"]
        require(relative(path)[0] == "project" and path not in source_paths,
                "source-entry-path")
        source_paths.add(path)
        equal(digest(operation.read(path)), item["sha256"], "source-entry:" + path)
    require(OPERATION_FILES["gate_script"] in source_paths, "gate-script-source")
    task5_rows = intent.get("source", {}).get("task5_files")
    require(type(task5_rows) is list and task5_rows, "task5-source-rows")
    task5_paths = set()
    for item in task5_rows:
        require(type(item) is dict and set(item) == {"path", "sha256"} and
                type(item["sha256"]) is str and HEX.fullmatch(item["sha256"]),
                "task5-source-row")
        path = "project/" + item["path"]
        require(path in source_paths and path not in task5_paths,
                "task5-source-path")
        task5_paths.add(path)
        equal(digest(operation.read(path)), item["sha256"],
              "task5-source-sha:" + path)
    require(OPERATION_FILES["gate_script"] in task5_paths,
            "task5-gate-script-missing")
    equal(intent.get("gate_script_sha256"), hashes["gate_script"],
          "intent-gate-script-sha")
    source_ref = intent.get("source", {}).get("manifest", {})
    equal(source_ref.get("path"), op + "/" + OPERATION_FILES["source_manifest"],
          "source-manifest-path")
    equal(source_ref.get("sha256"), hashes["source_manifest"], "source-manifest-sha")
    equal(source_ref.get("entries"), len(source_paths), "source-count")
    equal(source_ref.get("canonical_entries_sha256"),
          digest(canonical(source_manifest["entries"])), "source-entries-sha")
    tools = document(workspace.read(tool_path), "tool-freeze")
    require("python3" in tools, "python3-not-frozen")
    for name, tool in tools.items():
        require(type(tool) is dict and set(tool) == {"path", "sha256"} and
                type(tool["sha256"]) is str and HEX.fullmatch(tool["sha256"]),
                "tool-row:" + name)
        tool_absolute = absolute(tool["path"])
        require(tool_absolute.startswith(ws + "/"), "tool-outside-workspace")
        equal(digest(workspace.read(tool_absolute[len(ws) + 1:])), tool["sha256"],
              "tool-sha:" + name)
    frozen_environment(operation, workspace, stage2_entries)
    env = intent.get("environment", {})
    equal(env.get("tool_freeze"), ws + "/" + tool_path, "intent-tool-path")
    equal(env.get("tool_freeze_sha256"), workspace_files["tool_freeze"]["sha256"],
          "intent-tool-sha")
    equal(env.get("tool_count"), len(tools), "intent-tool-count")
    equal({i["name"]: {"path": i["path"], "sha256": i["sha256"]}
           for i in env.get("tools", [])}, tools, "intent-tools")
    equal(docs["controller_receipt"].get("controller_sha256"),
          hashes["controller"], "controller-receipt-sha")
    equal(docs["controller_receipt"].get("intent_sha256"),
          hashes["intent"], "controller-receipt-intent")
    equal(docs["controller_receipt"].get("path"),
          op + "/" + OPERATION_FILES["controller"], "controller-receipt-path")
    require(docs["controller_receipt"].get("gate_started") is False and
            docs["controller_receipt"].get("gate_executed") is False,
            "controller-receipt-pre-run-state")
    verify_terminal(docs, run, hashes, evidence_files, evidence,
                    operation, stage2_sha, stage2_entries)
    return {"schema_version": "task5_native_source_completion_audit_identity.v1",
            "operation_dir": op, "evidence_dir": ev, "workspace_dir": ws,
            "output_file": ev + "/" + AUDIT_REL, "run": run,
            "operation_files": operation_files,
            "workspace_files": workspace_files,
            "evidence_files": evidence_files}


def verify_postflight_maps(operation: Root, stage2_entries: list[dict],
                           source: dict, post: dict) -> None:
    source_map_raw = operation.read(SOURCE_MAP_REL)
    source_map = document(source_map_raw, "source-snapshot-map")
    require(set(source_map) == {"schema_version", "source_root", "entries",
                                "exclusions"} and
            source_map["schema_version"] == "r11_source_snapshot_map.v1" and
            type(source_map["source_root"]) is str and
            type(source_map["exclusions"]) is list,
            "source-snapshot-map-shape")
    absolute(source_map["source_root"])
    selected = validate_entries(source_map["entries"], "source-snapshot-static")
    exclusions = source_map["exclusions"]
    require(all(type(item) is dict and set(item) == {"path", "kind", "reason"}
                and type(item["path"]) is str and
                item["kind"] in {"directory", "file", "symlink"} and
                type(item["reason"]) is str and item["reason"]
                for item in exclusions), "source-snapshot-exclusions")
    excluded_paths = [item["path"] for item in exclusions]
    for path in excluded_paths:
        relative(path)
    require(excluded_paths == sorted(set(excluded_paths)),
            "source-snapshot-exclusion-order")
    project_entries = []
    for item in stage2_entries:
        if item["path"] == "project" or item["path"].startswith("project/"):
            projected = dict(item)
            projected["path"] = ("." if item["path"] == "project" else
                                 item["path"][len("project/"):])
            project_entries.append(projected)
    equal(project_entries, selected, "stage2-project-source-map")
    post_raw = operation.read(SOURCE_POST_REL)
    post_map = document(post_raw, "source-snapshot-postflight")
    require(set(post_map) == {"schema_version", "entries"} and
            post_map["schema_version"] == "r11_source_snapshot_postflight.v1",
            "source-snapshot-postflight-shape")
    equal(validate_entries(post_map["entries"], "source-snapshot-postflight"),
          selected, "source-snapshot-pre-post-entries")
    snapshot_ref = {"path": operation.path + "/" + SOURCE_POST_REL,
                    "sha256": digest(post_raw)}
    equal(source.get("source_snapshot_postflight"), snapshot_ref,
          "source-receipt-snapshot-ref")
    equal(source.get("source_snapshot_map_sha256"), digest(source_map_raw),
          "source-receipt-static-map-sha")
    entries_sha = digest(canonical(selected))
    equal(source.get("full_map_preflight_sha256"), entries_sha,
          "source-preflight-entries-sha")
    equal(source.get("full_map_postflight_sha256"), entries_sha,
          "source-postflight-entries-sha")
    receipts = post.get("postflight_receipts")
    require(type(receipts) is dict and set(receipts) == {
        "source_tree", "canonical_lock", "source_snapshot_postflight",
        *MAP_RELS}, "postflight-receipts-shape")
    equal(receipts.get("source_snapshot_postflight"), snapshot_ref,
          "post-run-snapshot-ref")

    map_raw = {}
    map_doc = {}
    for name, path in MAP_RELS.items():
        raw = operation.read(path)
        expected = {"path": operation.path + "/" + path,
                    "sha256": digest(raw)}
        equal(receipts.get(name), expected, "post-run-map-ref:" + name)
        map_raw[name] = raw
        map_doc[name] = document(raw, name)
    equal(map_raw["protected_baselines_preflight"],
          map_raw["protected_baselines_postflight"],
          "protected-pre-post-bytes")
    equal(map_raw["submodules_preflight"],
          map_raw["submodules_postflight"], "submodule-pre-post-bytes")
    protected = map_doc["protected_baselines_preflight"]
    require(set(protected) == {"schema_version", "roots"} and
            protected["schema_version"] == "r11_protected_baselines_map.v1" and
            type(protected["roots"]) is list and len(protected["roots"]) == 2,
            "protected-map-shape")
    equal([root.get("path") for root in protected["roots"]],
          ["/root/fanzehui/system-20261016", operation.path.rsplit(
              "/operations/", 1)[0] + "/project"], "protected-map-roots")
    for index, root in enumerate(protected["roots"]):
        require(type(root) is dict and set(root) == {"path", "entries"},
                "protected-root-shape")
        validate_entries(root["entries"], "protected-root-" + str(index),
                         max_file_size=None)

    static_submodules = document(operation.read("control/submodule-manifest.v1.json"),
                                 "submodule-manifest")
    runtime_submodules = map_doc["submodules_preflight"]
    require(set(static_submodules) == {"schema_version", "entries"} and
            static_submodules["schema_version"] == "r11_submodule_manifest.v1" and
            set(runtime_submodules) == {"schema_version", "entries"} and
            runtime_submodules["schema_version"] == "r11_submodule_runtime_map.v1" and
            type(static_submodules["entries"]) is list and
            type(runtime_submodules["entries"]) is list,
            "submodule-map-shape")
    equal(runtime_submodules["entries"], static_submodules["entries"],
          "submodule-preflight-static-map")
    paths = []
    for submodule in static_submodules["entries"]:
        require(type(submodule) is dict and set(submodule) == {
            "path", "tracked_mode", "gitlink_commit", "checked_out",
            "checked_out_head", "selected_entries_sha256",
            "selected_entries_count"}, "submodule-row-shape")
        require(submodule["tracked_mode"] == "160000" and
                commit_id(submodule["gitlink_commit"]) and
                type(submodule["checked_out"]) is bool and
                (commit_id(submodule["checked_out_head"])
                 if submodule["checked_out"] else
                 submodule["checked_out_head"] is None) and
                type(submodule["selected_entries_count"]) is int and
                submodule["selected_entries_count"] >= 0 and
                type(submodule["selected_entries_sha256"]) is str and
                HEX.fullmatch(submodule["selected_entries_sha256"]),
                "submodule-row-metadata")
        path = submodule["path"]
        relative(path)
        paths.append(path)
        projection = [entry for entry in selected if entry["path"] == path or
                      entry["path"].startswith(path + "/")]
        require(not projection or (projection[0]["path"] == path and
                projection[0]["kind"] == "directory"), "submodule-projection")
        require(not submodule["checked_out"] or bool(projection),
                "submodule-checkout-projection")
        equal(submodule["selected_entries_count"], len(projection),
              "submodule-projection-count:" + path)
        ascii_projection = json.dumps(projection, sort_keys=True,
                                      separators=(",", ":"), ensure_ascii=True,
                                      allow_nan=False).encode("ascii")
        equal(submodule["selected_entries_sha256"], digest(ascii_projection),
              "submodule-projection-sha:" + path)
    require(paths == sorted(set(paths)), "submodule-row-order")


def verify_terminal(docs: dict, run: dict, hashes: dict,
                    evidence_files: dict, evidence: Root, operation: Root,
                    stage2_sha: str, stage2_entries: list[dict]) -> None:
    claim, launch = docs["claim"], docs["launch_intent"]
    start, end = docs["gate_start"], docs["gate_end"]
    post = docs["post_run_integrity"]
    source, lock = docs["source_postflight"], docs["lock_postflight"]
    verify_postflight_maps(operation, stage2_entries, source, post)
    run_id = run["gate_run_id"]
    for name, receipt in (("claim", claim), ("launch", launch),
                          ("start", start), ("end", end), ("post", post)):
        equal(receipt.get("gate_run_id"), run_id, name + "-run-id")
    for name, receipt in (("claim", claim), ("launch", launch),
                          ("end", end), ("post", post)):
        equal(receipt.get("stage2_manifest_sha256"), stage2_sha,
              name + "-stage2-manifest-sha")
    for name, receipt in (("claim", claim), ("launch", launch),
                          ("start", start), ("post", post)):
        equal(receipt.get("plan_sha256"), hashes["plan"], name + "-plan-sha")
        equal(receipt.get("controller_sha256"), hashes["controller"],
              name + "-controller-sha")
    equal(claim.get("intent_sha256"), hashes["intent"], "claim-intent-sha")
    equal(launch.get("intent_sha256"), hashes["intent"], "launch-intent-sha")
    pid = claim.get("pid")
    require(type(pid) is int and pid > 0, "controller-pid")
    require(claim.get("one_shot") is True and
            claim.get("gate_started") is False and
            claim.get("gate_executed") is False, "claim-state")
    for name, receipt in (("launch", launch), ("start", start)):
        equal(receipt.get("controller_pid"), pid, name + "-controller-pid")
        equal(receipt.get("argv"), run["argv"], name + "-argv")
        equal(receipt.get("cwd"), run["cwd"], name + "-cwd")
        equal(receipt.get("output"), run["output"], name + "-output")
    equal(claim.get("argv"), run["argv"], "claim-argv")
    require(launch.get("gate_started") is False and
            launch.get("gate_executed") is False,
            "launch-pre-run-state")
    gate_pid = start.get("pid")
    require(type(gate_pid) is int and gate_pid > 0 and
            start.get("process_group_id") == gate_pid and
            start.get("status") == "running", "gate-start")
    for name, receipt in (("end", end), ("post", post)):
        if name == "end":
            equal(receipt.get("pid"), gate_pid, "end-pid")
            equal(receipt.get("controller_pid"), pid, "end-controller-pid")
            equal(receipt.get("process_group_id"), gate_pid, "end-pgid")
    require(type(end.get("returncode")) is int and end["returncode"] == 0 and
            end.get("gate_started") is True and end.get("gate_executed") is True and
            end.get("reaped_by_wait") is True and
            end.get("process_group_gone") is True and
            end.get("terminal_status") == "gate_process_completed" and
            exact_value(end.get("claims"), CLAIMS), "gate-end-terminal")
    equal(end.get("stdout_sha256"), hashes["gate_stdout"], "stdout-sha")
    equal(end.get("stderr_sha256"), hashes["gate_stderr"], "stderr-sha")
    equal(end.get("branch_result_sha256"),
          {name: evidence_files[name]["sha256"] for name in
           ("positive", "controlled-response", "native-source-refusal")},
          "branch-result-sha")
    equal(end.get("summary_sha256"), evidence_files["summary"]["sha256"],
          "summary-sha")
    expected_statuses = {"positive": "bounded_directed_gate_passed",
                         "controlled-response": "bounded_directed_gate_passed",
                         "native-source-refusal":
                         "native_source_completion_refusal_gate_passed"}
    for name, status in expected_statuses.items():
        result = gzip_document(evidence.read(EVIDENCE_FILES[name]), name)
        equal(result.get("gate_run_id"), run_id, name + "-run-id")
        equal(result.get("gate_branch"), name, name + "-branch")
        equal(result.get("gate_pid"), gate_pid, name + "-pid")
        equal(result.get("status"), status, name + "-status")
    summary = gzip_document(evidence.read(EVIDENCE_FILES["summary"]), "summary")
    equal(summary.get("schema_version"), "native_online_directed_gate.v1",
          "summary-schema")
    equal(summary.get("gate_run_id"), run_id, "summary-run-id")
    equal(summary.get("gate_pid"), gate_pid, "summary-gate-pid")
    for field, name in (("positive_status", "positive"),
                        ("controlled_status", "controlled-response"),
                        ("native_source_refusal_status", "native-source-refusal")):
        equal(summary.get(field), expected_statuses[name], "summary-" + field)
    for field in ("native_completion_observation", "native_source_binding",
                  "native_source_completion"):
        equal(summary.get(field), True, "summary-" + field)
    equal(summary.get("script_sha256"), hashes["gate_script"],
          "summary-script-sha")
    for field in CLAIMS:
        equal(summary.get(field), False, "summary-claim-" + field)
    require(source.get("status") == "source_tree_manifest_match" and
            source.get("matches_preflight") is True and
            exact_value(source.get("claims"), CLAIMS), "source-postflight")
    if "source_manifest_sha256" in source:
        equal(source["source_manifest_sha256"], hashes["source_manifest"],
              "source-postflight-manifest-sha")
    require(lock.get("status") == "match" and
            lock.get("matches_preflight") is True and
            type(lock.get("expected")) is dict and
            lock.get("expected") == lock.get("observed") and
            lock["expected"].get("path") == run["heavy_lock"] and
            exact_value(lock.get("claims"), CLAIMS), "lock-postflight")
    equal(post.get("gate_end"), end, "post-gate-end")
    end_ref = post.get("gate_end_sha256")
    if end_ref is None:
        end_ref = (post.get("gate_end_receipt") or {}).get("sha256")
    equal(end_ref, hashes["gate_end"], "post-gate-end-sha")
    receipts = post.get("postflight_receipts") or {}
    equal(receipts.get("source_tree"),
          {"path": operation.path + "/" + OPERATION_FILES["source_postflight"],
           "sha256": hashes["source_postflight"]}, "source-postflight-ref")
    equal(receipts.get("canonical_lock"),
          {"path": operation.path + "/" + OPERATION_FILES["lock_postflight"],
           "sha256": hashes["lock_postflight"]}, "lock-postflight-ref")
    require(type(post.get("gate_returncode")) is int and
            post["gate_returncode"] == 0 and
            all(post.get(field) is True for field in (
                "gate_started", "gate_executed", "process_group_gone",
                "output_created_by_gate", "source_tree_matches_preflight",
                "protected_baselines_match_preflight",
                "submodules_match_preflight", "canonical_lock_matches_preflight"))
            and post.get("terminal_status") == "completed"
            and exact_value(post.get("claims"), CLAIMS), "post-run-terminal")


def stage2_member(operation: Root, rows: dict[str, dict], path: str,
                  kind: str, label: str, *, executable: bool = False) -> None:
    absolute(path)
    require(path.startswith(operation.path + "/"),
            label + ":outside-operation")
    if kind == "file":
        require(path.startswith(operation.path + "/tools/") and
                path != operation.path + "/tools/",
                label + ":outside-tools")
    relative_path = path[len(operation.path) + 1:]
    row = rows.get(relative_path)
    require(type(row) is dict and row.get("kind") == kind,
            label + ":missing-stage2-row")
    if kind == "file":
        parent_path, leaf = path.rsplit("/", 1)
        parent = Root(parent_path)
        try:
            before = os.stat(leaf, dir_fd=parent.fd, follow_symlinks=False)
            raw = operation.read(relative_path)
            after = os.stat(leaf, dir_fd=parent.fd, follow_symlinks=False)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                    (before.st_dev, before.st_ino, before.st_mode,
                     before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_dev, after.st_ino, after.st_mode,
                     after.st_size, after.st_mtime_ns, after.st_ctime_ns) and
                    row == {"path": relative_path, "kind": "file",
                            "mode": stat.S_IMODE(before.st_mode),
                            "size": len(raw), "sha256": digest(raw)} and
                    (not executable or bool(before.st_mode & 0o111)),
                    label + ":stage2-file")
        finally:
            parent.close()
    else:
        directory = Root(path)
        try:
            require(row["mode"] == stat.S_IMODE(os.fstat(directory.fd).st_mode),
                    label + ":stage2-directory")
        finally:
            directory.close()


def frozen_environment(operation: Root, workspace: Root,
                       stage2_entries: list[dict]) -> tuple[dict[str, str], str]:
    stage2_rows = {item["path"]: item for item in stage2_entries}
    frozen = document(operation.read("control/environment.v1.json"), "environment")
    require(set(frozen) == {"schema_version", "vars", "interpreters",
                            "runtime_closure", "resolved_commands"} and
            frozen["schema_version"] == "r11_runtime_environment.v1",
            "environment-shape")
    variables = frozen["vars"]
    require(type(variables) is dict and variables, "environment-env-map-required")
    require(all(type(key) is str and key and "=" not in key and "\0" not in key
                and type(value) is str and "\0" not in value
                for key, value in variables.items()), "environment-env-row")
    path_parts = variables.get("PATH", "").split(":")
    require(path_parts and all(part.startswith(workspace.path + "/") and
                               all(component not in ("", ".", "..")
                                   for component in part.split("/")[1:])
                               for part in path_parts), "environment-path")
    interpreters = frozen["interpreters"]
    require(type(interpreters) is dict and
            set(interpreters) == {"controller", "gate", "auditor"},
            "environment-interpreters")
    for name, path in interpreters.items():
        require(type(path) is str and path.startswith(workspace.path + "/"),
                "interpreter-outside-workspace:" + name)
        stage2_member(operation, stage2_rows, path, "file",
                      "interpreter:" + name, executable=True)
    closure = frozen["runtime_closure"]
    require(type(closure) is list and closure, "runtime-closure")
    closure_paths = set()
    for item in closure:
        require(type(item) is dict and set(item) == {"path", "sha256", "role"}
                and type(item["path"]) is str and
                item["path"].startswith(workspace.path + "/")
                and type(item["sha256"]) is str and HEX.fullmatch(item["sha256"])
                and type(item["role"]) is str and item["role"]
                and item["path"] not in closure_paths, "runtime-closure-row")
        closure_paths.add(item["path"])
        equal(digest(workspace.read(item["path"][len(workspace.path) + 1:])),
              item["sha256"], "runtime-closure-sha:" + item["path"])
        stage2_member(operation, stage2_rows, item["path"], "file",
                      "runtime-closure:" + item["path"])
    require(set(interpreters.values()) <= closure_paths,
            "interpreter-not-in-runtime-closure")
    commands = frozen["resolved_commands"]
    require(type(commands) is dict and commands and
            all(type(name) is str and name and type(path) is str and
                path.startswith(workspace.path + "/") and path in closure_paths
                for name, path in commands.items()), "resolved-commands")
    for name, path in commands.items():
        stage2_member(operation, stage2_rows, path, "file",
                      "resolved-command:" + name, executable=True)
        equal(first_path_executable(path_parts, name), path,
              "resolved-command-first-match:" + name)
    equal(commands.get("python3"), interpreters["gate"],
          "resolved-python3-gate")
    python_parts = variables.get("PYTHONPATH", "").split(":")
    require(all(path.startswith(workspace.path + "/") for path in python_parts),
            "environment-pythonpath")
    for path in [*path_parts, *python_parts]:
        stage2_member(operation, stage2_rows, path, "directory",
                      "environment-search-directory")
    cache = operation.path + "/native-cache"
    require(variables.get("TMPDIR") == cache and
            all(variables.get(name, cache) == cache for name in
                ("TMP", "TEMP", "XDG_CACHE_HOME", "PYTHONPYCACHEPREFIX")),
            "environment-dynamic-cache")
    cache_dir = Root(cache)
    try:
        cache_st = os.fstat(cache_dir.fd)
        require(cache_st.st_uid == os.geteuid() and
                stat.S_IMODE(cache_st.st_mode) == 0o700,
                "environment-dynamic-cache-mode")
    finally:
        cache_dir.close()
    tools = document(operation.read("control/tool-freeze.v1.json"), "tool-freeze")
    require(type(tools) is dict and tools, "tool-freeze-shape")
    for name, item in tools.items():
        require(type(name) is str and name and type(item) is dict and
                set(item) == {"path", "sha256"} and
                type(item["sha256"]) is str and HEX.fullmatch(item["sha256"]),
                "tool-freeze-row")
        stage2_member(operation, stage2_rows, item["path"], "file",
                      "tool-freeze:" + name, executable=True)
        equal(item["sha256"], stage2_rows[item["path"][len(operation.path) + 1:]]["sha256"],
              "tool-freeze-stage2-sha:" + name)
    return variables, interpreters["auditor"]


def auditor_interpreter(workspace: Root, operation: Root) -> str:
    tools = document(operation.read("control/tool-freeze.v1.json"), "tool-freeze")
    python = tools.get("python3")
    require(type(python) is dict and set(python) == {"path", "sha256"},
            "frozen-python3-row")
    path = absolute(python["path"])
    require(path.startswith(workspace.path + "/"), "python3-outside-workspace")
    equal(digest(workspace.read(path[len(workspace.path) + 1:])),
          python["sha256"], "frozen-python3-sha")
    return path


def audit(operation: Root, evidence: Root, workspace: Root,
          identity: dict, external_sha: str, stage2_sha: str) -> int:
    require(type(external_sha) is str and HEX.fullmatch(external_sha),
            "external-identity-sha-format")
    raw = operation.read(IDENTITY_REL)
    equal(digest(raw), external_sha, "external-identity-sha")
    equal(document(raw, "identity"), identity, "identity-drift")
    auditor_interpreter(workspace, operation)
    _, stage2_entries = verify_stage2(operation, stage2_sha)
    env, interpreter = frozen_environment(operation, workspace, stage2_entries)
    argv = ["python3", "-B", operation.path + "/" + OPERATION_FILES["auditor"],
            "--operation-dir", operation.path, "--evidence-dir", evidence.path,
            "--workspace-dir", workspace.path,
            "--identity-manifest", IDENTITY_REL,
            "--identity-sha256", external_sha,
            "--output", evidence.path + "/" + AUDIT_REL]
    # The auditor owns its exclusive report leaf. The runner retains its process
    # terminal in control/ without altering any gate receipt or evidence input.
    require(not os.path.lexists(evidence.path + "/" + AUDIT_REL),
            "audit-report-already-exists")
    try:
        process = subprocess.Popen(argv, executable=interpreter,
                                   cwd=operation.path + "/project", env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        operation.write_exclusive("control/auditor-terminal.v1.json", canonical({
            "schema_version": "r11_post_gate_auditor_terminal.v1",
            "argv": argv, "executable": interpreter,
            "cwd": operation.path + "/project", "status": "spawn_failed",
            "error_type": type(exc).__name__,
            "identity_sha256": external_sha}) + b"\n")
        raise
    stdout, stderr = process.communicate()
    terminal = {"schema_version": "r11_post_gate_auditor_terminal.v1",
                "argv": argv, "executable": interpreter, "cwd": operation.path + "/project",
                "environment_sha256": digest(canonical(env)),
                "pid": process.pid, "returncode": process.returncode,
                "reaped_by_communicate": True,
                "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr),
                "identity_sha256": external_sha}
    operation.write_exclusive("control/auditor.stdout.log", stdout)
    operation.write_exclusive("control/auditor.stderr.log", stderr)
    operation.write_exclusive("control/auditor-terminal.v1.json",
                              canonical(terminal) + b"\n")
    require(type(process.returncode) is int and process.returncode == 0,
            "auditor-returncode")
    report = document(evidence.read(AUDIT_REL), "independent-audit")
    equal(report.get("status"), "passed", "independent-audit-status")
    equal(report.get("identity_sha256"), external_sha,
          "independent-audit-identity-sha")
    equal(set(report.get("branch_audits", {})), set(EVIDENCE_FILES) - {"summary"},
          "independent-audit-branches")
    terminal_audit = report.get("operation_terminal")
    require(type(terminal_audit) is dict and
            terminal_audit.get("status") == "passed" and
            terminal_audit.get("gate_run_id") == identity["run"]["gate_run_id"] and
            terminal_audit.get("source_tree_closure_verified") is False and
            terminal_audit.get("external_tool_bytes_verified") is False and
            terminal_audit.get("gate_executable_identity_verified") is False,
            "independent-audit-terminal-scope")
    equal(report.get("false_claims"), {
        "decode": False, "execution": False,
        "architectural_retirement": False, "semantic_cpu_consumption": False,
        "peripheral_payload_consumption": False, "feedback_authority": False,
        "formal_p6_completion": False, "source_authority": False,
        "controlled_response_proves_source_credential": False},
          "independent-audit-false-claims")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "audit"))
    parser.add_argument("--operation-dir", required=True)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--workspace-dir", required=True)
    parser.add_argument("--stage2-manifest-sha256", required=True,
                        help="externally reviewed raw Stage 2 manifest SHA-256")
    parser.add_argument("--identity-sha256", help="independently recomputed raw SHA-256; audit only")
    args = parser.parse_args()
    if args.phase == "prepare" and args.identity_sha256 is not None:
        parser.error("prepare does not accept --identity-sha256")
    if args.phase == "audit" and args.identity_sha256 is None:
        parser.error("audit requires --identity-sha256")
    roots = []
    try:
        workspace = Root(args.workspace_dir)
        roots.append(workspace)
        operation = Root(args.operation_dir)
        roots.append(operation)
        evidence = Root(args.evidence_dir)
        roots.append(evidence)
        identity = collect(operation, evidence, workspace,
                           args.stage2_manifest_sha256)
        if args.phase == "prepare":
            raw = canonical(identity) + b"\n"
            operation.write_exclusive(IDENTITY_REL, raw)
            print(digest(raw))
            return 0
        return audit(operation, evidence, workspace, identity,
                     args.identity_sha256, args.stage2_manifest_sha256)
    except Exception as exc:
        print("r11 post-gate runner failed: " + str(exc), file=sys.stderr)
        return 1
    finally:
        for root in reversed(roots):
            root.close()


if __name__ == "__main__":
    sys.exit(main())
