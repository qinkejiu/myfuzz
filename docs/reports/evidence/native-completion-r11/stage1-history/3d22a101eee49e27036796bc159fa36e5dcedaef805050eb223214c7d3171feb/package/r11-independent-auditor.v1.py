#!/usr/bin/env python3
"""Standalone offline audit for native exact-source completion gate evidence.

This file deliberately uses only the Python standard library. It does not import
myfuzz, verifier, gate code, or project modules, and it never starts a process.
It independently inspects retained event bundles; gate-internal checker status
fields are never used as evidence.
"""
from __future__ import annotations

import argparse
import ast
from copy import deepcopy
import ctypes
import gzip
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys


SCHEMA = "task5_native_source_completion_independent_audit.v6"
MAX_INPUT_FILE_BYTES = 64 * 1024 * 1024
MAX_GZIP_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
ZERO_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
AUDIT_OUTPUT_RELATIVE_PATH = "independent-audit.json"
GATE_FLAGS = ["--native-completion-observation", "--native-source-binding",
              "--native-source-completion"]
ACCEPTANCE_MATRIX = [
    {"id": "selected_source_positive",
     "expected": "only the exact selected source-bound four-byte native instruction-bus transfer can issue completion evidence"},
    {"id": "noncandidate_no_grant",
     "expected": "unrelated/bootstrap/noncandidate reads remain diagnostic and receive no completion grant"},
    {"id": "controlled_response",
     "expected": "the controlled selected-source transaction follows its planned response path and produces the exact bound transfer result"},
    {"id": "selected_source_contradiction_original",
     "expected": "selected-source contradiction is terminally refused in the original run"},
    {"id": "selected_source_contradiction_fresh",
     "expected": "the same selected-source contradiction is terminally refused in the full fresh replay"},
    {"id": "full_fresh_replay",
     "expected": "the complete configured replay executes from fresh inputs"},
    {"id": "independent_raw_audit",
     "expected": "raw gate evidence is checked by the independent audit path"},
]
CLAIMS = {
    "coverage_guided_search": False,
    "formal_p6_complete": False,
    "retirement_authority": False,
    "source_authority": False,
}
SCOPE_FIELDS = {"execution", "command_sequence", "reset_epoch", "local_tick"}
TX_FIELDS = {
    "execution_id", "testcase_id", "source_component", "source_epoch",
    "channel_id", "source_sequence",
}
NATIVE_KINDS = {
    "native_backend_request_accepted",
    "native_backend_response_consumed",
    "native_bus_completed",
}
FALSE_CLAIMS = {
    "decode": False,
    "execution": False,
    "architectural_retirement": False,
    "semantic_cpu_consumption": False,
    "peripheral_payload_consumption": False,
    "feedback_authority": False,
    "formal_p6_completion": False,
    "source_authority": False,
    "controlled_response_proves_source_credential": False,
}
SOURCE_DIRECTIONS = {
    "CPU_TO_IP", "IP_TO_CPU", "IP_TO_IP", "CPU_TO_IP_TO_CPU",
    "IP_TO_CPU_TO_IP", "MULTI_COMPONENT_CHAIN",
}


class AuditError(Exception):
    pass


def require(ok, code):
    if not ok:
        raise AuditError(code)


def _case_index_by_id(plan):
    cases = plan.get("cases") if type(plan) is dict else None
    require(type(cases) is list and cases, "plan-case-index-source-shape")
    result = {}
    for index, case in enumerate(cases):
        case_id = case.get("case_id") if type(case) is dict else None
        require(type(case_id) is str and case_id.strip()
                and case_id not in result,
                "plan-case-index-source-identity")
        result[case_id] = index
    return result


def plan_session_testcase_id(plan):
    template = plan.get("template") if type(plan) is dict else None
    testcase_id = template.get("testcase_id") if type(template) is dict else None
    require(type(testcase_id) is str and testcase_id.strip(),
            "plan-session-testcase-id")
    return testcase_id


def _provenance_resource(event):
    fields = ("memory_id", "generation", "byte_offset", "address",
              "width_bytes", "byte_enable", "transaction", "version",
              "versions", "writer_event_id", "writer_event_ids", "writer_kinds")
    resource = {}
    for name in fields:
        if name in event:
            value = event[name]
            resource[name] = list(deepcopy(value)) if isinstance(value, tuple) else deepcopy(value)
    return resource


def _require_observation_provenance(event, case_id, case_index, resource=None,
                                    *, code="event-provenance-envelope"):
    provenance = event.get("provenance") if type(event) is dict else None
    observed_case = (provenance.get("observed_case")
                     if type(provenance) is dict else None)
    if case_id is None and case_index is None:
        observed_case_matches = observed_case is None
    else:
        observed_case_matches = (type(observed_case) is dict
            and set(observed_case) == {"case_id", "case_index"}
            and type(observed_case.get("case_id")) is str
            and observed_case.get("case_id") == case_id
            and type(observed_case.get("case_index")) is int
            and observed_case.get("case_index") == case_index)
    require(type(provenance) is dict
            and set(provenance) == {
                "schema_version", "observed_case", "origin_admission_ids",
                "origin_status", "unknown_writer_ids", "invalid_origin_references",
                "proof_scope", "edge_candidates", "resource"}
            and provenance.get("schema_version") == "event_source_provenance.v1"
            and observed_case_matches
            and provenance.get("origin_admission_ids") == []
            and provenance.get("origin_status") == "unknown"
            and provenance.get("unknown_writer_ids") == []
            and type(provenance.get("invalid_origin_references")) is int
            and provenance.get("invalid_origin_references") == 0
            and provenance.get("proof_scope") == "observation_only"
            and provenance.get("edge_candidates") == []
            and provenance.get("resource") == resource,
            code)


def require_native_transaction_projection_identity(projection, session_testcase_id,
                                                   case_index_by_id):
    """Bind transaction IDs to the session and projection provenance to an action case."""
    require(type(session_testcase_id) is str and session_testcase_id.strip(),
            "native-projection-session-testcase-id")
    transaction = projection.get("transaction") if type(projection) is dict else None
    require(type(transaction) is dict and key_token(transaction) == canonical(transaction)
            and transaction.get("testcase_id") == session_testcase_id,
            "native-projection-session-transaction-identity")
    provenance = projection.get("provenance")
    observed_case = (provenance.get("observed_case")
                     if type(provenance) is dict else None)
    if observed_case is None:
        _require_observation_provenance(projection, None, None, None,
            code="native-projection-provenance-envelope")
        return transaction
    require(type(case_index_by_id) is dict
            and type(observed_case) is dict
            and set(observed_case) == {"case_id", "case_index"}
            and type(observed_case.get("case_id")) is str
            and observed_case.get("case_id") in case_index_by_id
            and type(observed_case.get("case_index")) is int
            and type(case_index_by_id[observed_case["case_id"]]) is int
            and observed_case.get("case_index")
                == case_index_by_id[observed_case["case_id"]],
            "native-projection-action-case-identity")
    _require_observation_provenance(projection, observed_case["case_id"],
        observed_case["case_index"], None,
        code="native-projection-provenance-envelope")
    return transaction


def _require_completion_provenance(event, case_id, case_index):
    provenance = event.get("provenance") if type(event) is dict else None
    observed_case = (provenance.get("observed_case")
                     if type(provenance) is dict else None)
    # The pinned RuntimeEdgeIndex matcher recognizes explicit dataflow/IRQ and
    # MMIO event kinds. This completion kind has no matcher branch, so its
    # independently expected candidate set is empty and scope stays observational.
    require(type(event) is dict
            and event.get("kind") == "native_instruction_bus_completion"
            and type(provenance) is dict
            and set(provenance) == {
                "schema_version", "observed_case", "origin_admission_ids",
                "origin_status", "unknown_writer_ids", "invalid_origin_references",
                "proof_scope", "edge_candidates", "resource"}
            and provenance.get("schema_version") == "event_source_provenance.v1"
            and type(observed_case) is dict
            and set(observed_case) == {"case_id", "case_index"}
            and type(observed_case.get("case_id")) is str
            and observed_case.get("case_id") == case_id
            and type(observed_case.get("case_index")) is int
            and observed_case.get("case_index") == case_index
            and provenance.get("origin_admission_ids") == []
            and provenance.get("origin_status") == "unknown"
            and provenance.get("unknown_writer_ids") == []
            and type(provenance.get("invalid_origin_references")) is int
            and provenance.get("invalid_origin_references") == 0
            and provenance.get("edge_candidates") == []
            and provenance.get("proof_scope") == "observation_only"
            and provenance.get("resource") is None,
            "completion-provenance-case-resource-scope")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def strict_json_loads(data):
    def reject_constant(value):
        raise AuditError("json-nonfinite-constant:" + value)

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise AuditError("json-duplicate-key")
            result[key] = value
        return result

    def finite_float(token):
        value = float(token)
        if not math.isfinite(value):
            raise AuditError("json-nonfinite-number")
        return value

    try:
        return json.loads(data, parse_constant=reject_constant,
                          parse_float=finite_float,
                          object_pairs_hook=unique_object)
    except AuditError:
        raise
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AuditError("json-decode:" + type(exc).__name__) from exc


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def _close_acquired_fd(fd, identity=None, *, directory=False):
    """Close only a descriptor still naming the inode acquired by this reader."""
    if fd is None:
        return
    try:
        if identity is not None:
            opened = os.fstat(fd)
            expected_type = stat.S_ISDIR if directory else stat.S_ISREG
            if (not expected_type(opened.st_mode)
                    or (opened.st_dev, opened.st_ino) != identity):
                return
        os.close(fd)
    except BaseException:
        pass


def json_sha(value):
    return sha256(canonical(value))


def key_token(value):
    require(type(value) is dict and set(value) == TX_FIELDS, "transaction-key-shape")
    require(value.get("execution_id") == "local-execution"
            and all(type(value[name]) is str and value[name] for name in
                ("execution_id", "testcase_id", "source_component", "channel_id"))
            and type(value["source_epoch"]) is int and value["source_epoch"] >= 0
            and type(value["source_sequence"]) is int and value["source_sequence"] > 0,
            "transaction-key-fields")
    return canonical(value)


def tx_text(value):
    require(type(value) is dict and set(value) == TX_FIELDS, "transaction-key-shape")
    key_token(value)
    fields = ("execution_id", "testcase_id", "source_component", "source_epoch",
              "channel_id", "source_sequence")
    return "TransactionKey(" + ", ".join(
        f"{name}={value[name]!r}" for name in fields) + ")"


def _positive_int(value):
    return type(value) is int and value > 0


def _open_directory_path(path):
    """Open an absolute directory through no-follow dirfd traversal."""
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts,
            "unsafe-directory-path")
    require(hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW"),
            "no-follow-directory-open-unavailable")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path.anchor, flags)
    try:
        root_info = os.fstat(fd)
    except BaseException:
        _close_acquired_fd(fd, directory=True)
        raise
    owned = {fd: (root_info.st_dev, root_info.st_ino)}
    try:
        for part in path.parts[1:]:
            child_fd = os.open(part, flags, dir_fd=fd)
            owned[child_fd] = None
            child_info = os.fstat(child_fd)
            require(stat.S_ISDIR(child_info.st_mode), "directory-path-component-not-directory")
            owned[child_fd] = (child_info.st_dev, child_info.st_ino)
            old_fd = fd
            os.close(old_fd)
            owned.pop(old_fd, None)
            fd = child_fd
        return fd
    except BaseException:
        for owned_fd, identity in tuple(owned.items()):
            _close_acquired_fd(owned_fd, identity, directory=True)
        raise


class Reader:
    """Read regular, non-symlink files beneath frozen operation/evidence roots."""

    def __init__(self, operation, evidence, workspace):
        self.operation, operation_identity = self._root(operation)
        self.evidence, evidence_identity = self._root(evidence)
        self.workspace, workspace_identity = self._root(workspace)
        self.root_identities = {"operation": operation_identity,
                                "evidence": evidence_identity,
                                "workspace": workspace_identity}
        self.inputs = {}
        self.input_metadata = {}
        self.pinned_inputs = {}

    @staticmethod
    def _root(value):
        raw = Path(value)
        require(".." not in raw.parts, "parent-traversal-input-root")
        path = raw.absolute()
        fd = None
        identity = None
        try:
            fd = _open_directory_path(path)
            info = os.fstat(fd)
            identity = (info.st_dev, info.st_ino)
        except OSError as exc:
            raise AuditError("input-root-unavailable:" + str(path)) from exc
        finally:
            _close_acquired_fd(fd, identity, directory=True)
        require(stat.S_ISDIR(info.st_mode),
                "input-root-not-directory")
        return path, (info.st_dev, info.st_ino)

    def _open_root(self, root_name):
        roots = {"operation": self.operation, "evidence": self.evidence,
                 "workspace": self.workspace}
        require(root_name in roots, "unknown-input-root")
        fd = _open_directory_path(roots[root_name])
        try:
            info = os.fstat(fd)
            require(stat.S_ISDIR(info.st_mode)
                    and (info.st_dev, info.st_ino) == self.root_identities[root_name],
                    "input-root-identity-changed:" + root_name)
            return fd
        except BaseException:
            _close_acquired_fd(fd, self.root_identities[root_name], directory=True)
            raise

    def bytes(self, root_name, relative):
        roots = {"operation": self.operation, "evidence": self.evidence,
                 "workspace": self.workspace}
        require(root_name in roots, "unknown-input-root")
        root = roots[root_name]
        rel = PurePosixPath(str(relative))
        require(bool(rel.parts) and not rel.is_absolute()
                and all(part not in ("", ".", "..") for part in rel.parts),
                "unsafe-relative-input-path")
        directory_fd = self._open_root(root_name)
        owned_directories = {directory_fd: self.root_identities[root_name]}
        fd = None
        fd_identity = None
        try:
            directory_flags = (os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                               | os.O_CLOEXEC)
            for part in rel.parts[:-1]:
                child_fd = os.open(part, directory_flags, dir_fd=directory_fd)
                owned_directories[child_fd] = None
                child_info = os.fstat(child_fd)
                require(stat.S_ISDIR(child_info.st_mode), "input-parent-not-directory")
                old_fd = directory_fd
                os.close(old_fd)
                owned_directories.pop(old_fd, None)
                directory_fd = child_fd
                owned_directories[child_fd] = (child_info.st_dev, child_info.st_ino)
            fd = os.open(rel.parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                         | os.O_NONBLOCK,
                         dir_fd=directory_fd)
            opened = os.fstat(fd)
            fd_identity = (opened.st_dev, opened.st_ino)
            require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1,
                    "input-not-single-link-regular-file:" + str(root / Path(*rel.parts)))
            require(opened.st_size <= MAX_INPUT_FILE_BYTES,
                    "input-file-size-limit:" + str(root / Path(*rel.parts)))
            metadata = {"uid": opened.st_uid, "gid": opened.st_gid,
                        "mode": stat.S_IMODE(opened.st_mode),
                        "nlink": opened.st_nlink}
            blocks = []
            total = 0
            while True:
                part = os.read(fd, 1024 * 1024)
                if not part:
                    break
                total += len(part)
                require(total <= MAX_INPUT_FILE_BYTES,
                        "input-file-size-limit:" + str(root / Path(*rel.parts)))
                blocks.append(part)
            data = b"".join(blocks)
            final_info = os.fstat(fd)
            require((opened.st_dev, opened.st_ino, opened.st_size,
                     opened.st_mtime_ns, opened.st_ctime_ns)
                    == (final_info.st_dev, final_info.st_ino, final_info.st_size,
                        final_info.st_mtime_ns, final_info.st_ctime_ns),
                    "input-changed-during-read")
        finally:
            _close_acquired_fd(fd, fd_identity)
            for owned_fd, identity in tuple(owned_directories.items()):
                _close_acquired_fd(owned_fd, identity, directory=True)
        label = root_name + "/" + rel.as_posix()
        if label in self.pinned_inputs:
            require(sha256(data) == self.pinned_inputs[label],
                    "identity-file-changed-after-pin:" + label)
        self.inputs[label] = {"sha256": sha256(data), "bytes": len(data)}
        self.input_metadata[label] = metadata
        return data

    def absolute_workspace_bytes(self, absolute_path):
        raw = Path(absolute_path)
        require(raw.is_absolute() and ".." not in raw.parts,
                "unsafe-absolute-workspace-input")
        path = raw.absolute()
        try:
            relative = path.relative_to(self.workspace)
        except ValueError as exc:
            raise AuditError("pinned-path-outside-workspace") from exc
        return self.bytes("workspace", PurePosixPath(relative.as_posix()))

    def absent(self, root_name, relative):
        roots = {"operation": self.operation, "evidence": self.evidence,
                 "workspace": self.workspace}
        require(root_name in roots, "unknown-input-root")
        root = roots[root_name]
        rel = PurePosixPath(str(relative))
        require(bool(rel.parts) and not rel.is_absolute()
                and all(part not in ("", ".", "..") for part in rel.parts),
                "unsafe-relative-absent-path")
        directory_fd = self._open_root(root_name)
        owned_directories = {directory_fd: self.root_identities[root_name]}
        try:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            for index, part in enumerate(rel.parts):
                try:
                    info = os.stat(part, dir_fd=directory_fd, follow_symlinks=False)
                except FileNotFoundError:
                    return True
                except OSError as exc:
                    raise AuditError("absent-path-check-failed") from exc
                require(not stat.S_ISLNK(info.st_mode), "symlink-in-absent-path")
                if index == len(rel.parts) - 1:
                    return False
                require(stat.S_ISDIR(info.st_mode), "non-directory-absent-path-parent")
                child_fd = os.open(part, flags, dir_fd=directory_fd)
                owned_directories[child_fd] = None
                opened = os.fstat(child_fd)
                require(stat.S_ISDIR(opened.st_mode)
                        and (opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino),
                        "absent-parent-changed-during-open")
                old_fd = directory_fd
                os.close(old_fd)
                owned_directories.pop(old_fd, None)
                directory_fd = child_fd
                owned_directories[child_fd] = (opened.st_dev, opened.st_ino)
            raise AuditError("absent-path-unreachable")
        finally:
            for owned_fd, identity in tuple(owned_directories.items()):
                _close_acquired_fd(owned_fd, identity, directory=True)

    def document(self, root_name, relative, *, compressed=False):
        data = self.bytes(root_name, relative)
        if compressed:
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as stream:
                    expanded = stream.read(MAX_GZIP_UNCOMPRESSED_BYTES + 1)
                    require(len(expanded) <= MAX_GZIP_UNCOMPRESSED_BYTES,
                            "gzip-expanded-size-limit")
                    require(stream.read(1) == b"", "gzip-expanded-size-limit")
                    data = expanded
            except (OSError, EOFError) as exc:
                raise AuditError("gzip-decode:" + type(exc).__name__) from exc
        return strict_json_loads(data)

    def branch_document(self, branch, filename, *, compressed=False):
        return self.document("evidence", PurePosixPath(branch) / filename,
                             compressed=compressed)


_AUDIT_IDENTITY_SCHEMA = "task5_native_source_completion_audit_identity.v1"
_OBSOLETE_ATTEMPT6 = "p6-native-instruction-bus-completion-v1-20261018-attempt6"
_OPERATION_IDENTITY_FILES = {
    "intent", "plan", "controller", "controller_receipt", "claim",
    "launch_intent", "gate_start", "gate_end", "post_run_integrity",
    "source_postflight", "lock_postflight", "source_manifest",
    "gate_script", "auditor", "gate_stdout", "gate_stderr",
}
_BRANCH_IDENTITY_FILES = {
    "positive", "controlled-response", "native-source-refusal",
}
_EVIDENCE_IDENTITY_FILES = _BRANCH_IDENTITY_FILES | {"summary"}


def _canonical_relative_path(value):
    if type(value) is not str:
        return False
    path = PurePosixPath(value)
    return (bool(path.parts) and not path.is_absolute()
            and all(part not in ("", ".", "..") for part in path.parts)
            and path.as_posix() == value)


def load_audit_identity(reader, relative_path, expected_sha256):
    """Verify a separately pinned manifest and every named evidence input."""
    require(type(reader) is Reader, "identity-reader-required")
    require(type(expected_sha256) is str
            and re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is not None,
            "identity-manifest-sha256")
    require(_canonical_relative_path(relative_path), "identity-manifest-path")
    raw = reader.bytes("operation", relative_path)
    require(sha256(raw) == expected_sha256, "identity-manifest-sha256")
    identity = strict_json_loads(raw)
    require(type(identity) is dict and set(identity) == {
        "schema_version", "operation_dir", "evidence_dir", "workspace_dir",
        "output_file", "run", "operation_files", "workspace_files",
        "evidence_files"}, "identity-manifest-shape")
    require(identity["schema_version"] == _AUDIT_IDENTITY_SCHEMA,
            "identity-manifest-schema")
    require(reader.operation.name != _OBSOLETE_ATTEMPT6,
            "obsolete-attempt6-identity")
    require(identity["operation_dir"] == str(reader.operation)
            and identity["evidence_dir"] == str(reader.evidence)
            and identity["workspace_dir"] == str(reader.workspace)
            and identity["output_file"] == str(reader.evidence / AUDIT_OUTPUT_RELATIVE_PATH)
            and reader.operation.name == reader.evidence.name,
            "identity-root-or-output-mismatch")
    run = identity["run"]
    require(type(run) is dict and set(run) == {
        "argv", "cwd", "output", "cache_dir", "heavy_lock", "gate_run_id",
        "requested_gate_flags", "requested_gates"}, "identity-run-shape")
    flags = list(GATE_FLAGS)
    script = str(reader.operation / "project/scripts/verify_picorv32_native_online.py")
    expected_argv = ["python3", "-B", script, "--output", str(reader.evidence),
                     "--cache-dir", str(reader.operation / "native-cache"),
                     "--heavy-lock", run["heavy_lock"],
                     "--gate-run-id", run["gate_run_id"], *flags]
    require(type(run["heavy_lock"]) is str
            and run["heavy_lock"] == str(reader.workspace / ".superpowers/heavy-worker.lock")
            and type(run["gate_run_id"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", run["gate_run_id"]) is not None
            and run["argv"] == expected_argv
            and run["cwd"] == str(reader.operation / "project")
            and run["output"] == str(reader.evidence)
            and run["cache_dir"] == str(reader.operation / "native-cache")
            and run["requested_gate_flags"] == flags
            and run["requested_gates"] == [
                "native_completion_observation", "native_source_binding",
                "native_source_completion"], "identity-gate-run-mismatch")
    groups = (
        ("operation", identity["operation_files"], _OPERATION_IDENTITY_FILES),
        ("workspace", identity["workspace_files"], {"tool_freeze"}),
        ("evidence", identity["evidence_files"], _EVIDENCE_IDENTITY_FILES),
    )
    pinned = {"operation/" + str(relative_path): expected_sha256}
    for root_name, rows, required in groups:
        require(type(rows) is dict and set(rows) == required,
                "identity-file-inventory:" + root_name)
        seen = set()
        for name, row in rows.items():
            require(type(row) is dict and set(row) == {"path", "sha256"}
                    and _canonical_relative_path(row["path"])
                    and type(row["sha256"]) is str
                    and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is not None
                    and row["path"] not in seen,
                    "identity-file-row:" + root_name + "/" + name)
            seen.add(row["path"])
            actual = reader.bytes(root_name, row["path"])
            require(sha256(actual) == row["sha256"],
                    "identity-file-sha256:" + root_name + "/" + name)
            pinned[root_name + "/" + row["path"]] = row["sha256"]
    require(sha256(Path(__file__).read_bytes())
            == identity["operation_files"]["auditor"]["sha256"],
            "identity-auditor-runtime-sha256")
    require(identity["operation_files"]["gate_script"]["path"]
            == "project/scripts/verify_picorv32_native_online.py",
            "identity-gate-script-path")
    for name in _BRANCH_IDENTITY_FILES:
        require(identity["evidence_files"][name]["path"]
                == name + "/result.json.gz", "identity-branch-result-path")
    require(identity["evidence_files"]["summary"]["path"] == "summary.json.gz",
            "identity-summary-path")
    reader.pinned_inputs = pinned
    return identity


def _scope(event, owner_nonce):
    scope = event.get("native_driver_scope")
    require(type(scope) is dict and set(scope) == SCOPE_FIELDS
            and scope.get("execution") == owner_nonce
            and type(scope.get("reset_epoch")) is int and scope["reset_epoch"] == 0
            and type(scope.get("command_sequence")) is int and scope["command_sequence"] > 0
            and type(scope.get("local_tick")) is int and scope["local_tick"] > 0,
            "native-scope-owner-or-shape")
    return scope


def _native_tuple(raw, artifact):
    contract = artifact["native_completion_observation"]
    traces = artifact["base_protocol_traces"]["traces"]
    completion = contract.get("completion") if type(contract) is dict else None
    require(type(contract) is dict
            and contract.get("schema_version") == "native_completion_observation.v1"
            and type(completion) is dict
            and completion.get("phase") == "pre",
            "native-completion-observation-contract")
    require(len(traces) == 1, "native-trace-count")
    trace = traces[0]
    widths = {"valid": 1, "ready": 1, "addr": 32, "wdata": 32,
              "wstrb": 4, "rdata": 32}
    require(trace.get("protocol") == "ready-valid-memory"
            and trace.get("boundary") == contract.get("boundary") == "cpu_physical_abi"
            and trace.get("endpoint_id") == contract.get("endpoint_id")
            and trace.get("clock_domain") == contract.get("clock_domain")
            and trace.get("signal_widths") == widths
            and set(trace.get("signals", {})) == set(widths)
            and type(trace.get("max_wait_cycles")) is int
            and trace.get("max_wait_cycles") > 0,
            "native-trace-contract")
    taps = raw["outputs"]["protocol_taps"]
    values = {role: taps[name] for role, name in trace["signals"].items()}
    marker = contract["instruction_marker"]
    require(marker.get("sample_group") == "physical"
            and type(marker.get("width")) is int and marker.get("width") == 1,
            "instruction-marker-contract")
    values["instruction"] = raw["outputs"]["physical"][marker["signal"]]
    for role, width in {**widths, "instruction": 1}.items():
        value = values[role]
        require(type(value) is int and 0 <= value < (1 << width),
                "native-signal-width:" + role)
    return values, trace


def _service_response(service):
    kind = service.get("kind")
    if kind == "memory_read":
        data = bytes.fromhex(service["data_hex"])
        require(type(service.get("width_bytes")) is int
                and type(service.get("value")) is int
                and len(data) == service.get("width_bytes") == 4
                and int.from_bytes(data, "little") == service.get("value"),
                "ram-read-service-value")
        return service["value"]
    if kind == "memory_write":
        return 0
    if kind == "mmio_delivery":
        if service.get("write") is True:
            return 0
        value = service.get("read_value")
        require(type(value) is int and 0 <= value < (1 << 32),
                "mmio-read-service-value")
        return value
    raise AuditError("unknown-service-kind")


def raw_transaction_audit(events, artifact, cpu_process, faults, *, allow_terminal=False,
                         session_testcase_id=None, case_ids=None,
                         case_index_by_id=None):
    """Rebuild raw PRE/POST and service/projection joins without saved checker output."""
    require(type(events) is list and events, "raw-event-list-shape")
    require(type(faults) is list, "controlled-fault-list-shape")
    require(type(session_testcase_id) is str and session_testcase_id.strip(),
            "raw-session-testcase-id")
    require(type(case_ids) is set and case_ids
            and all(type(case_id) is str and case_id for case_id in case_ids),
            "raw-plan-case-id-set")
    require(type(case_index_by_id) is dict
            and set(case_index_by_id) == case_ids
            and all(type(index) is int and index >= 0
                    for index in case_index_by_id.values())
            and len(set(case_index_by_id.values())) == len(case_index_by_id),
            "raw-plan-case-index-map")
    owner = cpu_process["execution_nonce"]
    require(artifact.get("artifact_digest") == cpu_process.get("artifact_digest"),
            "artifact-process-identity")
    require(type(owner) is str and re.fullmatch(r"[0-9a-f]{32}", owner) is not None,
            "cpu-process-nonce")
    by_id = {}
    frames = {}
    for event in events:
        require(type(event) is dict, "raw-event-shape")
        event_id = event.get("event_id")
        require(type(event_id) is int and event_id > 0 and event_id not in by_id,
                "duplicate-or-invalid-event-id")
        require(event_id == len(by_id) + 1, "raw-event-id-gap-or-order")
        by_id[event_id] = event
        if (event.get("kind") == "local_tick_sample"
                and event.get("component") == "cpu"):
            require("native_driver_scope" in event
                    and event.get("phase") in ("pre", "post"),
                    "cpu-local-tick-native-scope-required")
            scope = _scope(event, owner)
            require(type(event.get("reset_epoch")) is int
                    and event.get("reset_epoch") == scope["reset_epoch"]
                    and type(event.get("local_tick")) is int
                    and event.get("local_tick") == scope["local_tick"], "raw-scope-fields")
            row = frames.setdefault(scope["command_sequence"], {})
            require(event.get("phase") in ("pre", "post")
                    and event["phase"] not in row, "raw-phase-duplicate")
            row[event["phase"]] = event

    cpu_commands = [event for event in events
                    if event.get("component") == "cpu" and event.get("kind") is None]
    require(all(_positive_int(event.get("event_id"))
                and type(event.get("local_tick")) is int
                and type(event.get("outputs")) is dict
                for event in cpu_commands),
            "cpu-step-command-event-shape")

    require(frames, "raw-native-frames-missing")
    sequence_rows = []
    terminal_failure_id = None
    last_tick = 0
    for command, pair in frames.items():
        expected_command_sequence = len(sequence_rows) + 1
        require(type(command) is int and command == expected_command_sequence,
                "raw-command-order")
        require("pre" in pair, "raw-pre-missing")
        pre = pair["pre"]
        scope = _scope(pre, owner)
        require(scope["command_sequence"] == command and scope["local_tick"] == last_tick + 1,
                "raw-tick-gap-or-order")
        last_tick = scope["local_tick"]
        producer_id = pre.get("producer_event_id")
        require(_positive_int(producer_id) and producer_id < pre["event_id"],
                "raw-pre-command-reference")
        producer = by_id.get(producer_id)
        is_terminal_failure = (allow_terminal
            and command == next(reversed(frames))
            and type(producer) is dict and producer.get("kind") == "harness_failure")
        require(type(producer) is dict and producer.get("component") == "cpu"
                and ((is_terminal_failure and producer.get("kind") == "harness_failure")
                     or (not is_terminal_failure and producer.get("kind") is None
                         and type(producer.get("local_tick")) is int
                         and producer.get("local_tick") == pre.get("local_tick")
                         and command <= len(cpu_commands)
                         and producer_id == cpu_commands[command - 1].get("event_id"))),
                "raw-pre-producer-is-not-current-cpu-step")
        require(set(pair) == {"pre", "post"}, "raw-phase-pair-required")
        post = pair["post"]
        require(post["event_id"] > pre["event_id"]
                and _positive_int(post.get("producer_event_id"))
                and post.get("producer_event_id") == pre.get("producer_event_id")
                and post.get("native_driver_scope") == pre.get("native_driver_scope"),
                "raw-pre-post-pair")
        if is_terminal_failure:
            terminal_failure_id = producer_id
        else:
            require(producer.get("kind") is None,
                    "unexpected-harness-failure-producer")
        npre, trace = _native_tuple(pre, artifact)
        npost = _native_tuple(post, artifact)[0]
        sequence_rows.append((command, pre, post, npre, npost, trace))

    terminal_count = int(terminal_failure_id is not None)
    require((terminal_failure_id is not None) == bool(allow_terminal),
            "terminal-failure-frame-presence")
    cpu_failures = [event for event in events
                    if event.get("component") == "cpu"
                    and event.get("kind") == "harness_failure"]
    require(len(cpu_failures) == (1 if allow_terminal else 0)
            and (not allow_terminal
                 or cpu_failures[0].get("event_id") == terminal_failure_id),
            "cpu-harness-failure-cardinality-and-frame-join")
    require(len(cpu_commands) == len(sequence_rows) - terminal_count,
            "cpu-command-to-native-tick-count")

    service_rows = {}
    poison_service_rows = {}
    mmio_acceptances = {}
    projections = {}
    for event in events:
        kind = event.get("kind")
        if kind in ("memory_read", "memory_write", "mmio_delivery") and event.get("component") == "cpu":
            key = event.get("transaction", event.get("source_transaction"))
            token = key_token(key)
            require(key.get("testcase_id") == session_testcase_id,
                    "service-transaction-session-id")
            if key.get("channel_id") != "memory":
                require(allow_terminal and kind == "memory_write"
                        and key.get("channel_id") == "native-source-poison"
                        and token not in poison_service_rows,
                        "unexpected-non-memory-cpu-service")
                poison_service_rows[token] = event
                continue
            require(token not in service_rows and key.get("channel_id") == "memory",
                    "service-transaction-duplicate")
            service_rows[token] = event
        elif kind == "mmio_acceptance" and event.get("component") == "cpu":
            key = event.get("source_transaction")
            token = key_token(key)
            require(key.get("testcase_id") == session_testcase_id,
                    "mmio-acceptance-session-id")
            require(token not in mmio_acceptances
                    and key.get("channel_id") == "memory",
                    "duplicate-or-invalid-mmio-acceptance")
            mmio_acceptances[token] = event
        elif event.get("schema_version") == "native_bus_observation.v1":
            require(kind in NATIVE_KINDS and event.get("component") == "cpu"
                    and event.get("phase") == "pre", "native-projection-shape")
            producer_id = event.get("producer_event_id")
            projection_id = event.get("event_id")
            require(type(producer_id) is int and producer_id > 0
                    and type(projection_id) is int and projection_id > producer_id,
                    "native-projection-event-order")
            token = (producer_id, kind)
            require(token not in projections, "native-projection-duplicate")
            projections[token] = event

    require(len(poison_service_rows) == (1 if allow_terminal else 0),
            "poison-service-row-count")

    raw_by_event_id = {row[1]["event_id"]: row for row in sequence_rows}
    accepted = {}
    responses = {}
    completions = {}
    projection_by_raw_kind = {}
    runtime_contract = artifact.get("native_completion_observation")
    expected_digest = artifact.get("artifact_digest")
    require(type(runtime_contract) is dict
            and type(expected_digest) is str
            and re.fullmatch(r"[0-9a-f]{64}", expected_digest) is not None,
            "native-runtime-projection-identity")
    for (producer_id, kind), projection in projections.items():
        require(producer_id in raw_by_event_id, "projection-raw-producer-missing")
        _, pre, _, native, _, _ = raw_by_event_id[producer_id]
        scope = pre["native_driver_scope"]
        common_fields = {"event_id", "producer_event_id", "schema_version", "kind",
                         "proof_scope", "grants_source_authority", "retirement", "phase",
                         "artifact_digest", "endpoint_id", "clock_domain", "execution",
                         "command_sequence", "reset_epoch", "local_tick", "transaction",
                         "component", "provenance"}
        kind_fields = {
            "native_backend_request_accepted": {"native"},
            "native_backend_response_consumed": {"value", "native_post_is_offer_only"},
            "native_bus_completed": {"native", "accepted_scope", "response_scope",
                                      "memory_read_snapshot", "transfer_type"},
        }[kind]
        require(set(projection) == common_fields | kind_fields
                and projection.get("schema_version") == "native_bus_observation.v1"
                and projection.get("transaction") is not None
                and projection.get("proof_scope") == "native_bus_transfer_only"
                and projection.get("grants_source_authority") is False
                and projection.get("retirement") is False
                and projection.get("phase") == "pre"
                and projection.get("component") == "cpu"
                and projection.get("artifact_digest") == expected_digest
                and projection.get("endpoint_id") == runtime_contract.get("endpoint_id")
                and projection.get("clock_domain") == runtime_contract.get("clock_domain")
                and projection.get("execution") == owner
                and type(projection.get("reset_epoch")) is int
                and projection.get("reset_epoch") == scope.get("reset_epoch")
                and type(projection.get("command_sequence")) is int
                and projection.get("command_sequence") == scope.get("command_sequence")
                and type(projection.get("local_tick")) is int
                and projection.get("local_tick") == scope.get("local_tick")
                and type(projection.get("event_id")) is int
                and projection.get("event_id") > producer_id,
                "projection-runtime-and-raw-binding")
        transaction = projection.get("transaction")
        require_native_transaction_projection_identity(
            projection, session_testcase_id, case_index_by_id)
        if kind in ("native_backend_request_accepted", "native_bus_completed"):
            require(projection.get("native") == native,
                    "projection-native-tuple-join:" + kind)
        token = key_token(projection["transaction"])
        require(projection.get("execution") == owner
                and type(projection.get("reset_epoch")) is int
                and projection.get("reset_epoch") == 0
                and type(projection.get("command_sequence")) is int
                and projection.get("command_sequence") == pre["native_driver_scope"]["command_sequence"]
                and type(projection.get("local_tick")) is int
                and projection.get("local_tick") == pre["local_tick"],
                "projection-owned-scope")
        backend = pre["outputs"]["backend"]
        if kind == "native_backend_request_accepted":
            require(native["valid"] == 1 and native["ready"] == 0
                    and backend.get("m_req_valid") == backend.get("m_req_ready") == 1,
                    "accepted-projection-without-raw-handshake")
        elif kind == "native_backend_response_consumed":
            require(backend.get("m_rsp_valid") == backend.get("m_rsp_ready") == 1,
                    "response-projection-without-raw-handshake")
        else:
            require(native["valid"] == native["ready"] == 1,
                    "completion-projection-without-raw-handshake")
        target = (accepted if kind == "native_backend_request_accepted" else
                  responses if kind == "native_backend_response_consumed" else completions)
        require(token not in target, "projection-transaction-duplicate")
        target[token] = (projection, pre, native)
        projection_by_raw_kind[(producer_id, kind)] = projection

    def stable_native(actual, saved):
        return (actual["valid"] == 1
                and all(actual[name] == saved[name]
                        for name in ("addr", "wstrb", "instruction"))
                and (not saved["wstrb"] or actual["wdata"] == saved["wdata"]))

    state_used_projections = set()
    state_counts = {"accepted": 0, "responses": 0, "raw_completed": 0,
                    "completed": 0, "terminal_refusals": 0}
    offered = None
    pending = None
    memory_sequence = 0
    terminal_state = None
    for row_index, (command, pre, post, native_pre, native_post, trace) in enumerate(sequence_rows):
        backend = pre["outputs"].get("backend")
        require(type(backend) is dict, "raw-backend-shape")
        backend_widths = {"m_req_valid": 1, "m_req_ready": 1, "m_req_addr": 32,
                          "m_req_write": 1, "m_req_wdata": 32, "m_req_be": 4,
                          "m_rsp_valid": 1, "m_rsp_ready": 1,
                          "m_rsp_rdata": 32, "m_rsp_error": 1}
        require(all(type(backend.get(name)) is int
                    and 0 <= backend[name] < 1 << width
                    for name, width in backend_widths.items()),
                "raw-backend-widths")
        accepted_now = backend["m_req_valid"] == backend["m_req_ready"] == 1
        consumed_now = backend["m_rsp_valid"] == backend["m_rsp_ready"] == 1
        completed_now = native_pre["valid"] == native_pre["ready"] == 1
        require(not (accepted_now and consumed_now),
                "native-backend-handshake-overlap")

        if offered is None and native_pre["valid"]:
            offered = native_pre
        if offered is not None:
            require(stable_native(native_pre, offered), "native-offered-request-changed")
        if pending is not None:
            require(pre["local_tick"] - pending["accepted_scope"]["local_tick"]
                    <= 2 * trace["max_wait_cycles"] + 4,
                    "native-pending-wait-bound")

        terminal_this_tick = (allow_terminal
            and pre.get("producer_event_id") == terminal_failure_id)
        if completed_now:
            state_counts["raw_completed"] += 1
            require(pending is not None and "response_scope" in pending
                    and pre["local_tick"] == pending["response_scope"]["local_tick"] + 1
                    and stable_native(native_pre, pending["native"])
                    and native_pre["rdata"] == pending["response"],
                    "native-completion-without-matching-pending-response")
            if terminal_this_tick:
                service = pending["service"]
                require(row_index == len(sequence_rows) - 1
                        and service.get("kind") == "memory_read"
                        and native_pre["instruction"] == 1 and native_pre["wstrb"] == 0
                        and native_pre["addr"] == pending["native"]["addr"]
                        and (pre["event_id"], "native_bus_completed")
                            not in projection_by_raw_kind
                        and not any(event.get("kind") == "native_instruction_bus_completion"
                            and (event.get("key") == pending["key"]
                                 or event.get("producer_event_id") == pre["event_id"])
                            for event in events),
                        "native-terminal-refusal-raw-shape")
                pending["terminal_refusal"] = pre["event_id"]
                terminal_state = {"raw_event_id": pre["event_id"],
                                  "producer_event_id": pre["producer_event_id"],
                                  "transaction": pending["key"],
                                  "accepted_scope": pending["accepted_scope"],
                                  "response_scope": pending["response_scope"],
                                  "refused_scope": pre["native_driver_scope"],
                                  "native": native_pre,
                                  "service_event_id": pending["service"]["event_id"]}
                state_counts["terminal_refusals"] += 1
                offered = native_post if native_post["valid"] else None
            else:
                completion_projection = projection_by_raw_kind.get(
                    (pre["event_id"], "native_bus_completed"))
                require(type(completion_projection) is dict
                        and completion_projection.get("accepted_scope")
                            == pending["accepted_scope"]
                        and completion_projection.get("response_scope")
                            == pending["response_scope"]
                        and completion_projection.get("transfer_type") ==
                            ("instruction_bus_transfer" if native_pre["instruction"]
                             else "data_bus_transfer"),
                        "native-completion-projection-state-join")
                service = pending["service"]
                snapshot = completion_projection.get("memory_read_snapshot")
                if service.get("kind") == "memory_read":
                    require(type(snapshot) is dict, "native-read-snapshot-missing")
                    for name in ("memory_id", "generation", "byte_offset", "data_hex",
                                 "versions", "writer_event_ids"):
                        require(canonical(snapshot.get(name)) == canonical(service.get(name)),
                                "native-snapshot-service-join:" + name)
                    kinds = snapshot.get("writer_kinds")
                    require(type(kinds) is list and len(kinds) == 4
                            and all(type(value) is str and value for value in kinds),
                            "native-snapshot-writer-kinds")
                    if "writer_kinds" in service:
                        require(canonical(kinds) == canonical(service["writer_kinds"]),
                                "native-snapshot-writer-kinds-service-join")
                    require(snapshot.get("transaction_id") == tx_text(pending["key"])
                            and int.from_bytes(bytes.fromhex(snapshot["data_hex"]), "little")
                                == native_pre["rdata"],
                            "native-snapshot-transaction-rdata-join")
                else:
                    require(snapshot is None, "native-nonread-snapshot-present")
                state_used_projections.add((pre["event_id"], "native_bus_completed"))
                state_counts["completed"] += 1
                pending = None
                offered = native_post if native_post["valid"] else None
        else:
            require(native_pre["ready"] == 0, "native-ready-without-valid")
            if offered is not None:
                require(stable_native(native_post, offered), "native-post-offer-changed")
            if pending is not None:
                require(stable_native(native_pre, pending["native"]),
                        "native-pending-request-changed")
            if offered is None and native_post["valid"]:
                offered = native_post

        if accepted_now:
            require(pending is None and not consumed_now and not completed_now
                    and native_pre["valid"] == 1
                    and backend["m_req_addr"] == native_pre["addr"]
                    and backend["m_req_write"] == int(bool(native_pre["wstrb"]))
                    and backend["m_req_be"] == (native_pre["wstrb"] or 15)
                    and (not native_pre["wstrb"]
                         or backend["m_req_wdata"] == native_pre["wdata"])
                    and not (native_pre["instruction"] and native_pre["wstrb"]),
                    "native-backend-accepted-request")
            accepted_projection = projection_by_raw_kind.get(
                (pre["event_id"], "native_backend_request_accepted"))
            require(type(accepted_projection) is dict,
                    "native-accepted-projection-missing")
            transaction = accepted_projection["transaction"]
            memory_sequence += 1
            require(transaction.get("source_sequence") == memory_sequence
                    and transaction.get("source_epoch") == pre["native_driver_scope"]["reset_epoch"],
                    "native-memory-sequence-state")
            token = key_token(transaction)
            service = service_rows.get(token)
            require(type(service) is dict and service.get("event_id")
                    > pre.get("producer_event_id"), "native-accepted-service-state-join")
            state_used_projections.add((pre["event_id"], "native_backend_request_accepted"))
            pending = {"key": transaction, "native": native_pre, "service": service,
                       "accepted_scope": pre["native_driver_scope"],
                       "accepted_raw": pre["event_id"]}
            state_counts["accepted"] += 1

        if consumed_now:
            require(pending is not None and "response_scope" not in pending
                    and not native_pre["ready"] and backend["m_rsp_error"] == 0
                    and native_post["ready"] == 1
                    and stable_native(native_post, pending["native"])
                    and native_post["rdata"] == backend["m_rsp_rdata"],
                    "native-backend-response-state")
            service = pending["service"]
            require(service["event_id"] < pre["event_id"],
                    "native-service-before-response-pre")
            actual = _service_response(service)
            delivered = actual
            matching_faults = [index for index, fault in enumerate(faults)
                               if fault.get("transaction") == service.get(
                                   "transaction", service.get("source_transaction"))]
            require(len(matching_faults) <= 1, "native-response-duplicate-fault")
            if matching_faults:
                fault = faults[matching_faults[0]]
                actual_pair = fault.get("actual_target_response")
                delivered_pair = fault.get("delivered_response")
                require(key_token(fault.get("transaction")) == key_token(pending["key"])
                        and service.get("kind") == "mmio_delivery"
                        and service.get("write") is False
                        and service.get("address") == fault.get("address") == 0x4000000c
                        and type(actual_pair) is list and len(actual_pair) == 2
                        and all(type(value) is int for value in actual_pair)
                        and type(delivered_pair) is list and len(delivered_pair) == 2
                        and all(type(value) is int for value in delivered_pair)
                        and actual_pair == [actual, 0]
                        and delivered_pair == [actual ^ 1, 0],
                        "native-controlled-response-fault-join")
                delivered ^= 1
            response_projection = projection_by_raw_kind.get(
                (pre["event_id"], "native_backend_response_consumed"))
            command_id = pre.get("producer_event_id")
            cpu_command = by_id.get(command_id)
            require(type(response_projection) is dict
                    and type(command_id) is int and type(cpu_command) is dict
                    and service["event_id"] < command_id < pre["event_id"]
                    and type(cpu_command.get("outputs")) is dict
                    and type(cpu_command["outputs"].get("data_rsp_consumed")) is int
                    and cpu_command["outputs"].get("data_rsp_consumed") == 1
                    and type(cpu_command["outputs"].get("data_rsp_source_sequence")) is int
                    and cpu_command["outputs"].get("data_rsp_source_sequence")
                        == pending["key"].get("source_sequence")
                    and type(cpu_command["outputs"].get("data_rsp_source_epoch")) is int
                    and cpu_command["outputs"].get("data_rsp_source_epoch")
                        == pending["key"].get("source_epoch")
                    and type(cpu_command["outputs"].get("data_rsp_rdata")) is int
                    and cpu_command["outputs"].get("data_rsp_rdata") == delivered
                    and type(response_projection.get("value")) is int
                    and response_projection.get("value") == delivered
                    and response_projection.get("native_post_is_offer_only") is True
                    and backend["m_rsp_rdata"] == delivered,
                    "native-response-projection-cpu-pending-join")
            pending.update(response=delivered, response_scope=pre["native_driver_scope"],
                           response_raw=pre["event_id"],
                           actual_service_response=actual)
            state_used_projections.add((pre["event_id"], "native_backend_response_consumed"))
            state_counts["responses"] += 1

    require(state_used_projections == set(projection_by_raw_kind),
            "native-state-machine-orphan-projection")
    if allow_terminal:
        require(type(terminal_state) is dict and pending is not None
                and pending.get("terminal_refusal") == terminal_state["raw_event_id"]
                and "response_scope" in pending,
                "native-state-machine-terminal-pending")
    else:
        require(pending is None and terminal_state is None,
                "native-state-machine-pending-at-end")

    for _, pre, _, native, _, _ in sequence_rows:
        backend = pre["outputs"]["backend"]
        if backend.get("m_req_valid") == backend.get("m_req_ready") == 1:
            require((pre["event_id"], "native_backend_request_accepted") in projections,
                    "raw-accepted-handshake-without-projection")
        if backend.get("m_rsp_valid") == backend.get("m_rsp_ready") == 1:
            require((pre["event_id"], "native_backend_response_consumed") in projections,
                    "raw-response-handshake-without-projection")
        if native["valid"] == native["ready"] == 1:
            is_refusal_terminal = (allow_terminal
                and pre.get("producer_event_id") == terminal_failure_id)
            if not is_refusal_terminal:
                require((pre["event_id"], "native_bus_completed") in projections,
                        "raw-native-completion-without-projection")

    # Every accepted request must name one actual service result and one raw CPU
    # response sample. Completion is a separate PRE handshake exactly one tick later.
    joins = []
    used_services = set()
    used_responses = set()
    used_completions = set()
    used_faults = set()
    ordered = sorted(accepted.items(), key=lambda item: item[1][1]["event_id"])
    for expected_sequence, (token, (accepted_projection, accepted_pre, accepted_native)) in enumerate(
            ordered, start=1):
        transaction = accepted_projection["transaction"]
        require(transaction.get("source_component") == "cpu"
                and transaction.get("source_epoch") == 0
                and transaction.get("channel_id") == "memory"
                and transaction.get("source_sequence") == expected_sequence,
                "native-transaction-sequence")
        require(accepted_native["valid"] == 1 and accepted_native["ready"] == 0,
                "accepted-not-native-offer")
        backend = accepted_pre["outputs"]["backend"]
        require(backend.get("m_req_valid") == backend.get("m_req_ready") == 1
                and backend.get("m_req_addr") == accepted_native["addr"]
                and backend.get("m_req_write") == int(bool(accepted_native["wstrb"]))
                and backend.get("m_req_be") == (accepted_native["wstrb"] or 15),
                "accepted-raw-backend-request")
        service = service_rows.get(token)
        require(service is not None and token not in used_services, "accepted-service-join")
        used_services.add(token)
        require(type(service.get("address")) is int
                and service.get("address") == accepted_native["addr"]
                and (service.get("kind") == "memory_write" or service.get("write") is True)
                    == bool(accepted_native["wstrb"]), "accepted-service-operation")
        if accepted_native["wstrb"]:
            require(backend.get("m_req_wdata") == accepted_native["wdata"]
                    and service.get("value", service.get("write_value"))
                        == accepted_native["wdata"]
                    and service.get("byte_enable") == accepted_native["wstrb"],
                    "accepted-native-write-data")
        if service.get("kind") in ("memory_read", "memory_write"):
            require(type(service.get("width_bytes")) is int
                    and service.get("width_bytes") == 4, "memory-service-width")
        if service.get("kind") == "mmio_delivery":
            acceptance_event = mmio_acceptances.get(token)
            service_key = service.get("source_transaction")
            acceptance_key = (acceptance_event.get("source_transaction")
                              if type(acceptance_event) is dict else None)
            require(acceptance_event is not None
                    and type(service_key) is dict
                    and type(acceptance_key) is dict
                    and _positive_int(acceptance_event.get("event_id"))
                    and _positive_int(acceptance_event.get("producer_event_id"))
                    and _positive_int(service.get("event_id"))
                    and _positive_int(service.get("producer_event_id"))
                    and key_token(service_key) == token
                    and key_token(acceptance_key) == token
                    and acceptance_key == service_key
                    and acceptance_key == service.get("source_transaction")
                    and acceptance_event.get("producer_event_id") == accepted_pre.get("producer_event_id")
                    and acceptance_event.get("event_id", 0) > accepted_pre.get("producer_event_id", 0)
                    and type(acceptance_event.get("address")) is int
                    and acceptance_event.get("address") == service.get("address")
                        == accepted_native["addr"]
                    and type(acceptance_event.get("offset")) is int
                    and acceptance_event["offset"] >= 0
                    and acceptance_event.get("offset") == service.get("offset")
                    and type(acceptance_event.get("beat_bytes")) is int
                    and acceptance_event["beat_bytes"] == 4
                    and acceptance_event.get("beat_bytes") == service.get("beat_bytes")
                    and type(acceptance_event.get("write")) is bool
                    and acceptance_event.get("write") is service.get("write")
                    and type(acceptance_event.get("byte_enable")) is int
                    and type(service.get("byte_enable")) is int
                    and acceptance_event.get("byte_enable") == service.get("byte_enable")
                    and acceptance_event.get("byte_enable") == backend.get("m_req_be")
                    and acceptance_event.get("write_value") == service.get("write_value")
                    and type(acceptance_event.get("device_id")) is str
                    and bool(acceptance_event["device_id"])
                    and acceptance_event.get("device_id") == service.get("device_id")
                    and type(service.get("address")) is int
                    and type(service.get("offset")) is int
                    and type(service.get("beat_bytes")) is int
                    and (accepted_native["wstrb"] == acceptance_event["byte_enable"]
                         if acceptance_event["write"] else accepted_native["wstrb"] == 0)
                    and (type(acceptance_event.get("write_value")) is int
                         and type(service.get("write_value")) is int
                         and acceptance_event.get("write_value") == accepted_native.get("wdata")
                         if acceptance_event["write"] else
                         acceptance_event.get("write_value") is None)
                    and (type(service.get("read_value")) is int
                         if not acceptance_event["write"] else
                         service.get("read_value") is None)
                    and service.get("event_id", 0) > acceptance_event.get("event_id", 0)
                    and type(service.get("producer_event_id")) is int
                    and service.get("producer_event_id") in by_id
                    and by_id[service["producer_event_id"]].get("component")
                        == acceptance_event.get("device_id"),
                    "mmio-acceptance-full-key-command-fields")
        else:
            require(_positive_int(service.get("event_id"))
                    and _positive_int(service.get("producer_event_id"))
                    and service.get("event_id") > accepted_pre.get("producer_event_id", 0)
                    and service.get("producer_event_id") == accepted_pre.get("producer_event_id"),
                    "service-command-reference")
        response = responses.get(token)
        require(response is not None, "accepted-response-missing")
        used_responses.add(token)
        response_projection, response_pre, response_native = response
        require(response_pre["event_id"] > service["event_id"]
                and response_pre["event_id"] > accepted_pre["event_id"]
                and response_native["valid"] == 1 and response_native["ready"] == 0,
                "response-order-or-native-state")
        backend_response = response_pre["outputs"]["backend"]
        require(backend_response.get("m_rsp_valid") == backend_response.get("m_rsp_ready") == 1
                and backend_response.get("m_rsp_error") == 0,
                "response-raw-backend")
        response_post = frames[response_pre["native_driver_scope"]["command_sequence"]].get("post")
        require(response_post is not None, "response-post-missing")
        npost, _ = _native_tuple(response_post, artifact)
        require(npost["ready"] == 1 and npost["rdata"] == backend_response.get("m_rsp_rdata"),
                "response-post-offer")
        actual = _service_response(service)
        delivered = actual
        matching_faults = [i for i, fault in enumerate(faults)
                           if fault.get("transaction") == service.get("transaction",
                              service.get("source_transaction"))]
        require(len(matching_faults) <= 1, "duplicate-controlled-fault")
        if matching_faults:
            fault_index = matching_faults[0]
            fault = faults[fault_index]
            require(key_token(fault.get("transaction")) == token
                    and service.get("kind") == "mmio_delivery"
                    and service.get("write") is False
                    and service.get("address") == fault.get("address") == 0x4000000c
                    and fault.get("actual_target_response") == [actual, 0]
                    and fault.get("delivered_response") == [actual ^ 1, 0],
                    "controlled-fault-actual-delivered-join")
            delivered ^= 1
            used_faults.add(fault_index)
        response_command_id = response_pre.get("producer_event_id")
        require(_positive_int(response_command_id), "response-command-reference-type")
        response_command = by_id.get(response_command_id)
        require(type(response_command) is dict
                and service["event_id"] < response_command_id < response_pre["event_id"]
                and response_pre.get("producer_event_id") == response_command_id
                and response_post["event_id"] > response_pre["event_id"]
                and response_post.get("producer_event_id") == response_command_id
                and response_post.get("native_driver_scope")
                    == response_pre.get("native_driver_scope")
                and response_command.get("component") == "cpu"
                and response_command.get("kind") is None
                and type(response_command.get("outputs")) is dict
                and type(response_command["outputs"].get("data_rsp_consumed")) is int
                and response_command["outputs"].get("data_rsp_consumed") == 1
                and type(response_command["outputs"].get("data_rsp_source_sequence")) is int
                and response_command["outputs"].get("data_rsp_source_sequence")
                    == transaction.get("source_sequence")
                and type(response_command["outputs"].get("data_rsp_source_epoch")) is int
                and response_command["outputs"].get("data_rsp_source_epoch")
                    == transaction.get("source_epoch")
                and type(response_command["outputs"].get("data_rsp_rdata")) is int
                and response_command["outputs"].get("data_rsp_rdata") == delivered
                and response_command["outputs"].get("data_rsp_rdata")
                    == backend_response.get("m_rsp_rdata"),
                "response-command-full-pending-key-data-join")
        require(type(backend_response.get("m_rsp_rdata")) is int
                and backend_response.get("m_rsp_rdata") == delivered
                and type(response_projection.get("value")) is int
                and response_projection.get("value") == delivered
                and response_projection.get("native_post_is_offer_only") is True,
                "delivered-response-join")
        completion = completions.get(token)
        terminal_raw = None
        if completion is None and allow_terminal:
            terminal_events = [event for event in events
                if event.get("kind") == "local_tick_sample"
                and event.get("component") == "cpu" and event.get("phase") == "pre"
                and event.get("producer_event_id") == terminal_failure_id]
            if terminal_events:
                terminal_raw = terminal_events[-1]
        if completion is not None:
            completion_projection, completion_pre, completion_native = completion
            require(completion_pre["event_id"] > response_pre["event_id"]
                    and completion_pre["event_id"] > response_post["event_id"]
                    and completion_native["valid"] == completion_native["ready"] == 1
                    and completion_native["addr"] == accepted_native["addr"]
                    and completion_native["wstrb"] == accepted_native["wstrb"]
                    and completion_native["instruction"] == accepted_native["instruction"]
                    and completion_native["rdata"] == delivered
                    and completion_pre["local_tick"] == response_pre["local_tick"] + 1,
                    "native-next-pre-completion")
            require(completion_projection.get("accepted_scope") == accepted_pre["native_driver_scope"]
                    and completion_projection.get("response_scope") == response_pre["native_driver_scope"],
                    "completion-scope-join")
            used_completions.add(token)
        elif terminal_raw is not None:
            require(terminal_raw["event_id"] > response_post["event_id"]
                    and terminal_raw["native_driver_scope"]["local_tick"]
                    == response_pre["local_tick"] + 1, "terminal-refusal-next-pre")
        else:
            raise AuditError("raw-completion-or-terminal-refusal-missing")
        completion_projection = completion[0] if completion else None
        joins.append({
            "transaction": accepted_projection["transaction"],
            "service_event_id": service["event_id"],
            "accepted_raw_event_id": accepted_pre["event_id"],
            "response_raw_event_id": response_pre["event_id"],
            "response_post_event_id": response_post["event_id"],
            "accepted_projection_event_id": accepted_projection["event_id"],
            "response_projection_event_id": response_projection["event_id"],
            "response_command_event_id": response_command_id,
            "completion_projection_event_id": (completion_projection["event_id"]
                                                  if completion_projection else None),
            "completed_raw_event_id": completion[1]["event_id"] if completion else
                (terminal_raw["event_id"] if terminal_raw else None),
            "actual_service_response": actual,
            "delivered_response": delivered,
            "faulted": bool(matching_faults),
            "native": completion[2] if completion else None,
            "accepted_native": accepted_native,
            "service_kind": service["kind"],
            "service_address": service.get("address"),
            "service_write": service.get("write"),
            "service_byte_enable": service.get("byte_enable"),
            "service_device_id": service.get("device_id"),
            "service_offset": service.get("offset"),
            "service_beat_bytes": service.get("beat_bytes"),
            "snapshot": (completion_projection.get("memory_read_snapshot")
                         if completion_projection else None),
        })

    require(used_services == set(service_rows), "orphan-service-event")
    require(set(mmio_acceptances) == {token for token, service in service_rows.items()
                                      if service.get("kind") == "mmio_delivery"},
            "orphan-or-missing-mmio-acceptance")
    require(used_responses == set(responses), "orphan-response-projection")
    require(used_completions == set(completions), "orphan-completion-projection")
    if faults:
        require(used_faults == set(range(len(faults))), "unjoined-controlled-fault")
    require(len(accepted) == len(responses), "accepted-response-count")
    if not allow_terminal:
        require(len(accepted) == len(completions), "accepted-completion-count")
    else:
        require(len(accepted) == len(completions) + 1, "refusal-terminal-count")
    require(state_counts["accepted"] == state_counts["responses"]
            == state_counts["raw_completed"]
            and state_counts["raw_completed"]
                == state_counts["completed"] + state_counts["terminal_refusals"]
            and state_counts["terminal_refusals"] == (1 if allow_terminal else 0),
            "native-state-machine-transfer-counts")
    return {"joins": joins, "poison_service_event_ids": sorted(
                event["event_id"] for event in poison_service_rows.values()),
            "fault_count": len(faults), "accepted_count": len(accepted),
            "completion_count": len(completions),
            "state_machine_counts": state_counts,
            "terminal_refusal": terminal_state,
            "response_consumer_join_scope": (
                "response_PRE_producer_event_id_to_CPU_command_then_unique_pending_sequence_epoch_and_data")}


def semantic_digest(trace):
    return json_sha({key: trace[key] for key in ("status", "events", "local_ticks")})


def normalized_events(events, process):
    owner = process["execution_nonce"]
    result = deepcopy(events)
    for row in result:
        if "native_driver_scope" in row:
            require(row.get("component") == "cpu" and row.get("kind") == "local_tick_sample",
                    "fresh-raw-normalization-scope")
            scope = row["native_driver_scope"]
            require(_scope(row, owner) == scope, "fresh-raw-normalization-owner")
            scope["execution"] = "<owned-cpu-reset-epoch-0>"
        if row.get("schema_version") == "native_bus_observation.v1":
            require(row.get("component") == "cpu" and row.get("kind") in NATIVE_KINDS,
                    "fresh-projection-normalization-kind")
            require(row.get("execution") == owner
                    and type(row.get("reset_epoch")) is int
                    and row.get("reset_epoch") == 0,
                    "fresh-projection-normalization-owner")
            row["execution"] = "<owned-cpu-reset-epoch-0>"
            for name in ("accepted_scope", "response_scope"):
                if name in row:
                    require(type(row.get(name)) is dict
                            and row[name].get("execution") == owner
                            and type(row[name].get("reset_epoch")) is int
                            and row[name].get("reset_epoch") == 0,
                            "fresh-projection-nested-scope")
                    row[name]["execution"] = "<owned-cpu-reset-epoch-0>"
        if row.get("schema_version") == "native_instruction_source_binding.v1":
            require(row.get("execution") == owner
                    and type(row.get("reset_epoch")) is int
                    and row.get("reset_epoch") == 0,
                    "fresh-binding-normalization-owner")
            row["execution"] = "<owned-cpu-reset-epoch-0>"
        if row.get("schema_version") == "native_instruction_bus_completion.v1":
            require(row.get("kind") == "native_instruction_bus_completion"
                    and row.get("grants_source_authority") is False
                    and row.get("proof_scope") == "native_instruction_bus_transfer_completed",
                    "fresh-source-completion-shape")
            binding = row.get("binding")
            require(type(binding) is dict and binding.get("execution") == owner
                    and type(binding.get("reset_epoch")) is int
                    and binding.get("reset_epoch") == 0,
                    "fresh-completion-binding-owner")
            binding["execution"] = "<owned-cpu-reset-epoch-0>"
            for name in ("accepted_scope", "response_scope", "completion_scope"):
                require(type(row.get(name)) is dict
                        and row[name].get("execution") == owner
                        and type(row[name].get("reset_epoch")) is int
                        and row[name].get("reset_epoch") == 0, "fresh-completion-scope-owner")
                row[name]["execution"] = "<owned-cpu-reset-epoch-0>"
    return result


def full_fresh_audit(original, fresh, original_processes, fresh_processes):
    require(original.get("status") == fresh.get("status"), "fresh-trace-status")
    require(original.get("local_ticks") == fresh.get("local_ticks"), "fresh-local-ticks")
    require(original.get("manifest_sha256") == fresh.get("manifest_sha256")
            and original.get("genome_sha256") == fresh.get("genome_sha256"),
            "fresh-manifest-or-genome")
    require(semantic_digest(original) == original.get("semantic_sha256")
            and semantic_digest(fresh) == fresh.get("semantic_sha256"),
            "fresh-semantic-hash")
    original_cpu = process_for(original_processes, "cpu", "runner-0")
    fresh_cpu = process_for(fresh_processes, "cpu", "runner-1")
    left = normalized_events(original["events"], original_cpu)
    right = normalized_events(fresh["events"], fresh_cpu)
    require(canonical(left) == canonical(right), "full-fresh-event-mismatch")
    return {"events_equal_after_owned_nonce_normalization": True,
            "events": len(left), "semantic_sha256": original["semantic_sha256"]}


def process_for(rows, component, runner):
    matches = [row for row in rows if row.get("component") == component
               and row.get("runner_namespace") == runner]
    require(len(matches) == 1, "process-receipt-cardinality:" + component + ":" + runner)
    return matches[0]


def process_audit(rows):
    require(type(rows) is list and len(rows) == 4, "four-process-receipts-required")
    pids = [row.get("pid") for row in rows]
    nonces = [row.get("execution_nonce") for row in rows]
    require(all(type(pid) is int and pid > 0 for pid in pids)
            and len(set(pids)) == 4, "process-pid-uniqueness")
    require(all(type(nonce) is str and re.fullmatch(r"[0-9a-f]{32}", nonce)
                for nonce in nonces) and len(set(nonces)) == 4,
            "process-nonce-uniqueness")
    for row in rows:
        require(row.get("component") in ("cpu", "gpio0")
                and row.get("runner_namespace") in ("runner-0", "runner-1")
                and type(row.get("reset_epoch")) is int
                and row.get("reset_epoch") == 0
                and type(row.get("terminal_returncode")) is int
                and row["terminal_returncode"] == 0
                and type(row.get("artifact_digest")) is str
                and re.fullmatch(r"[0-9a-f]{64}", row["artifact_digest"]) is not None,
                "process-terminal-row")
    for component in ("cpu", "gpio0"):
        pair = [row for row in rows if row["component"] == component]
        require(len(pair) == 2 and pair[0]["pid"] != pair[1]["pid"]
                and pair[0]["execution_nonce"] != pair[1]["execution_nonce"]
                and pair[0]["artifact_digest"] == pair[1]["artifact_digest"],
                "fresh-process-pair")
    return rows


def bundle_reference(reader, branch, result, result_key, expected_name):
    reference = result.get(result_key)
    require(type(reference) is dict
            and set(reference) == {"path", "json_sha256", "gzip_sha256"},
            "bundle-reference-shape:" + result_key)
    name = reference.get("path")
    require(type(name) is str and name == expected_name
            and PurePosixPath(name).name == name,
            "unsafe-bundle-reference:" + result_key)
    raw_bytes = reader.bytes("evidence", PurePosixPath(branch) / name)
    require(sha256(raw_bytes) == reference.get("gzip_sha256"),
            "bundle-gzip-reference-hash:" + result_key)
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw_bytes), mode="rb") as stream:
            raw = stream.read(MAX_GZIP_UNCOMPRESSED_BYTES + 1)
            require(len(raw) <= MAX_GZIP_UNCOMPRESSED_BYTES
                    and stream.read(1) == b"", "bundle-expanded-size-limit:" + result_key)
    except (OSError, EOFError) as exc:
        raise AuditError("bundle-gzip-decode:" + result_key) from exc
    require(sha256(raw) == reference.get("json_sha256"),
            "bundle-json-reference-hash:" + result_key)
    return strict_json_loads(raw)


def relation_for_case(case_row, plan_case, *, session_testcase_id):
    receipt = case_row.get("receipt")
    events = receipt.get("events") if type(receipt) is dict else None
    return relation_for_events(events, plan_case,
        case_id=case_row.get("case", {}).get("case_id"),
        session_testcase_id=session_testcase_id)


def raw_padout_join(relation, raw, *, session_testcase_id):
    transaction = relation.get("padout_read_transaction")
    token = key_token(transaction)
    require(type(relation.get("case_id")) is str and relation.get("case_id")
            and type(session_testcase_id) is str and session_testcase_id.strip()
            and transaction.get("testcase_id") == session_testcase_id,
            "padout-transaction-session-id")
    event_id = relation.get("delivery_event_ids", [None, None])[1]
    matches = [join for join in raw.get("joins", [])
               if key_token(join.get("transaction")) == token
               and join.get("service_event_id") == event_id]
    require(len(matches) == 1, "padout-full-key-raw-service-response-join")
    join = matches[0]
    require(join.get("service_kind") == "mmio_delivery"
            and join.get("service_address") == 0x4000000c
            and join.get("service_offset") == 12
            and join.get("service_beat_bytes") == 4
            and join.get("service_write") is False
            and join.get("service_byte_enable") == 15
            and join.get("service_device_id") == "gpio0"
            and join.get("accepted_native", {}).get("addr") == 0x4000000c
            and join.get("accepted_native", {}).get("wstrb") == 0
            and join.get("actual_service_response") == relation.get("actual_a")
            and type(join.get("delivered_response")) is int,
            "padout-raw-service-response-fields")
    consumers = relation.get("response_consumers")
    require(type(consumers) is list and len(consumers) >= 1
            and consumers[0].get("target_event_id") == event_id
            and consumers[0].get("cpu_event_id") == join.get("response_command_event_id")
            and consumers[0].get("target_value") == join.get("actual_service_response")
            and consumers[0].get("cpu_value") == join.get("delivered_response"),
            "padout-case-consumer-full-key-response-join")
    return join


def relation_for_events(events, plan_case, *, case_id=None, session_testcase_id=None):
    require(type(events) is list and events, "case-event-bundle-missing")
    current_case_id = case_id
    require(type(current_case_id) is str and current_case_id
            and current_case_id == plan_case.get("case_id"),
            "case-receipt-current-case-id")
    require(type(session_testcase_id) is str and session_testcase_id.strip(),
            "case-receipt-session-testcase-id")
    for event in events:
        require(type(event) is dict, "case-event-shape")
        for key_name in ("source_transaction", "transaction"):
            transaction = event.get(key_name)
            if type(transaction) is dict:
                key_token(transaction)
                require(transaction.get("testcase_id") == session_testcase_id,
                        "case-receipt-transaction-session-id")
    deliveries = [event for event in events if event.get("kind") == "mmio_delivery"]
    require(all(type(event.get("write")) is bool
                and type(event.get("device_id")) is str
                and type(event.get("offset")) is int
                and type(event.get("beat_bytes")) is int
                and type(event.get("byte_enable")) is int
                for event in deliveries), "case-mmio-numeric-fields")
    shape = [(event.get("write"), event.get("offset")) for event in deliveries]
    require(shape == [(True, 12), (False, 12), (False, 8), (True, 12)],
            "case-mmio-delivery-shape")
    require(all(event.get("device_id") == "gpio0"
                and event.get("byte_enable") == 15
                and event.get("beat_bytes") == 4 for event in deliveries),
            "case-mmio-delivery-fields")
    first, a_read, b_read, final = deliveries
    a, b = a_read["read_value"], b_read["read_value"]
    require(type(a) is int and type(b) is int
            and type(first.get("write_value")) is int,
            "case-read-value-shape")
    require(a == first["write_value"], "case-padout-readback")
    source = plan_case["source"]
    if source.get("kind") == "instruction":
        word = int.from_bytes(bytes.fromhex(source["data_hex"]), "little")
        require(a == ((word >> 20) & 0xfff), "case-cpu-source-value")
    elif source.get("kind") == "source_event" and source.get("component") == "gpio0":
        require(b == source.get("value"), "case-gpio-source-value")
    joint = a ^ b
    writes = [event for event in events if event.get("kind") == "memory_write"
              and type(event.get("address")) is int
              and event.get("address") == 0x100]
    require(len(writes) == 1 and type(writes[0].get("byte_enable")) is int
            and writes[0].get("byte_enable") == 15
            and type(writes[0].get("value")) is int,
            "case-joint-ram-write")
    require(type(final.get("write_value")) is int,
            "case-final-gpio-write-value-type")
    require(b_read["event_id"] < writes[0]["event_id"] < final["event_id"],
            "case-joint-event-order")
    response_rows = []
    for target in (a_read, b_read):
        key = target.get("source_transaction")
        consumers = [event for event in events if event.get("component") == "cpu"
                     and event.get("kind") is None
                     and type(event.get("outputs", {}).get("data_rsp_consumed")) is int
                     and event.get("outputs", {}).get("data_rsp_consumed") == 1
                     and type(event.get("outputs", {}).get("data_rsp_source_sequence")) is int
                     and event["outputs"].get("data_rsp_source_sequence") == key["source_sequence"]
                     and type(event.get("outputs", {}).get("data_rsp_source_epoch")) is int
                     and event["outputs"].get("data_rsp_source_epoch") == key["source_epoch"]]
        require(len(consumers) == 1 and consumers[0]["event_id"] > target["event_id"],
                "case-cpu-response-consumer")
        cpu_value = consumers[0]["outputs"]["data_rsp_rdata"]
        require(type(cpu_value) is int, "case-cpu-response-value-type")
        response_rows.append({"target_event_id": target["event_id"],
                              "cpu_event_id": consumers[0]["event_id"],
                              "target_value": target["read_value"], "cpu_value": cpu_value})
    findings = []
    if any(row["target_value"] != row["cpu_value"] for row in response_rows):
        findings.append("routed_read_response_mismatch")
    if writes[0].get("value") != joint:
        findings.append("joint_ram_mismatch")
    if final.get("write_value") != joint:
        findings.append("joint_gpio_mismatch")
    return {"case_id": current_case_id,
            "actual_a": a, "actual_b": b, "expected_joint": joint,
            "actual_ram": writes[0].get("value"),
            "actual_final_gpio": final.get("write_value"),
            "findings": findings, "response_consumers": response_rows,
            "padout_read_transaction": a_read.get("source_transaction"),
            "delivery_event_ids": [event.get("event_id") for event in deliveries]}


def _nonnegative_int(value):
    return type(value) is int and value >= 0


def _u64(value):
    return type(value) is int and 0 <= value < (1 << 64)


def _version_pairs(value, length, *, generation=None, u64=False):
    if type(value) is not list or len(value) != length:
        return False
    natural = _u64 if u64 else _nonnegative_int
    for pair in value:
        if type(pair) is not list or len(pair) != 2:
            return False
        if not all(natural(part) for part in pair):
            return False
        if generation is not None and pair[0] != generation:
            return False
    return True


def _version_sequences_positive(value, length):
    return (type(value) is list and len(value) == length
            and all(type(pair) is list and len(pair) == 2
                    and _nonnegative_int(pair[0]) and _positive_int(pair[1])
                    for pair in value))


def _source_topology_id(plan, case, action):
    case_id = case.get("case_id")
    require(type(case_id) is str and case_id
            and type(action) is str and action.startswith(case_id + ":"),
            "source-action-topology-prefix")
    source_id = action[len(case_id) + 1:]
    require(source_id and source_id.strip() == source_id,
            "source-action-topology-source-id")
    runtime = plan.get("runtime_paths")
    declaration = runtime.get("declaration") if type(runtime) is dict else None
    require(type(declaration) is dict
            and declaration.get("schema_version") == "prepared_runtime_paths.v1"
            and type(declaration.get("selections")) is list
            and type(declaration.get("graph")) is dict
            and type(declaration["graph"].get("sources")) is list,
            "source-runtime-topology-shape")
    selections = [row for row in declaration["selections"]
                  if type(row) is dict
                  and row.get("path_id") == case.get("path_id")
                  and row.get("direction") == case.get("direction")]
    require(len(selections) == 1
            and type(selections[0].get("source_ids")) is list,
            "source-runtime-selection-cardinality")
    sources_by_id = {row.get("source_id"): row for row in declaration["graph"]["sources"]
                     if type(row) is dict}
    eligible = [sources_by_id.get(source_key)
                for source_key in selections[0]["source_ids"]]
    eligible = [row for row in eligible if type(row) is dict
                and row.get("kind") == "instruction"
                and row.get("component") == "cpu"]
    sources = [row for row in declaration["graph"]["sources"]
               if type(row) is dict and row.get("source_id") == source_id]
    require(len(eligible) == 1 and eligible[0].get("source_id") == source_id
            and source_id in selections[0].get("source_ids", [])
            and len(sources) == 1
            and sources[0].get("kind") == "instruction"
            and sources[0].get("component") == "cpu"
            and case.get("direction") in sources[0].get("directions", []),
            "source-runtime-path-topology-join")
    return source_id


def source_binding_chain(events, plan, case_index, case, *, expected_execution=None):
    """Rebuild one selected instruction admission -> service -> binding chain."""
    source = case.get("source")
    require(type(source) is dict
            and set(source) == {"action_id", "component", "address", "data_hex", "kind"}
            and source.get("kind") == "instruction"
            and source.get("component") == "cpu"
            and type(source.get("address")) is int
            and source["address"] >= 0 and source["address"] % 4 == 0
            and type(source.get("data_hex")) is str,
            "selected-source-document-shape")
    try:
        data = bytes.fromhex(source["data_hex"])
    except ValueError as exc:
        raise AuditError("selected-source-hex") from exc
    require(len(data) == 4 and data.hex() == source["data_hex"],
            "selected-source-four-byte-canonical")
    action = source["action_id"]
    source_id = _source_topology_id(plan, case, action)
    binding_rows = [event for event in events
                    if event.get("schema_version") == "native_instruction_source_binding.v1"
                    and event.get("kind") == "native_instruction_source_bound"
                    and event.get("source", {}).get("action_id") == action]
    require(len(binding_rows) == 1, "source-binding-chain-cardinality")
    binding = binding_rows[0]
    expected_binding_keys = {
        "event_id", "producer_event_id", "schema_version", "kind", "proof_scope",
        "grants_source_authority", "native_bus_completion_observed", "retirement",
        "grants_feedback", "admission_event_id", "service_event_index", "component",
        "execution", "reset_epoch", "case_index", "admission", "source", "acceptance",
        "provenance",
    }
    require(set(binding) == expected_binding_keys
            and _positive_int(binding.get("event_id"))
            and _positive_int(binding.get("admission_event_id"))
            and _positive_int(binding.get("producer_event_id"))
            and binding.get("component") == "cpu"
            and (expected_execution is None or binding.get("execution") == expected_execution)
            and type(binding.get("execution")) is str
            and re.fullmatch(r"[0-9a-f]{32}", binding["execution"]) is not None
            and binding.get("reset_epoch") == 0
            and type(binding.get("reset_epoch")) is int
            and binding.get("case_index") == case_index
            and type(binding.get("case_index")) is int
            and _nonnegative_int(binding.get("service_event_index"))
            and binding.get("proof_scope") == "host_instruction_input_bound"
            and binding.get("grants_source_authority") is False
            and binding.get("native_bus_completion_observed") is False
            and binding.get("retirement") is False
            and binding.get("grants_feedback") is False
            and binding.get("source") == source,
            "source-binding-exact-identity-scope")
    _require_observation_provenance(
        binding, case.get("case_id"), case_index, None,
        code="source-binding-provenance-envelope")

    admission = binding.get("admission")
    admission_keys = {"schema_version", "admission_id", "case_id", "case_index",
                      "source_id", "path_id", "direction", "component", "action_id",
                      "role", "input_kind", "input_sha256"}
    require(type(admission) is dict and set(admission) == admission_keys
            and admission.get("schema_version") == "source_admission.v1"
            and all(type(admission.get(name)) is str and admission[name].strip()
                    for name in admission_keys - {"schema_version", "case_index"})
            and type(admission.get("case_index")) is int
            and admission["case_index"] >= 0
            and admission.get("case_id") == case.get("case_id")
            and admission.get("case_index") == case_index
            and admission.get("source_id") == source_id
            and admission.get("path_id") == case.get("path_id")
            and admission.get("direction") in SOURCE_DIRECTIONS
            and admission.get("direction") == case.get("direction")
            and admission.get("component") == source.get("component") == "cpu"
            and admission.get("action_id") == action
            and admission.get("role") == "fuzz_source"
            and admission.get("input_kind") == "instruction"
            and re.fullmatch(r"[0-9a-f]{64}", admission.get("input_sha256", "")) is not None
            and admission.get("input_sha256") == json_sha(source),
            "source-admission-exact-selected-input")
    admission_material = {key: value for key, value in admission.items()
                          if key != "admission_id"}
    require(admission.get("admission_id") == json_sha(admission_material),
            "source-admission-id-digest")
    registry = plan.get("source_admissions")
    require(type(registry) is dict
            and set(registry) == {"schema_version", "admissions"}
            and registry.get("schema_version") == "source_admission_registry.v1"
            and type(registry.get("admissions")) is list
            and sum(row == admission for row in registry["admissions"]) == 1,
            "source-admission-plan-registry-join")

    acceptance = binding.get("acceptance")
    acceptance_keys = {"memory_id", "address", "byte_offset", "generation", "data_hex",
                       "source_event_id", "versions", "writer_event_ids", "writer_kinds"}
    versions = acceptance.get("versions") if type(acceptance) is dict else None
    require(type(acceptance) is dict and set(acceptance) == acceptance_keys
            and type(acceptance.get("memory_id")) is str and acceptance["memory_id"].strip()
            and _nonnegative_int(acceptance.get("address"))
            and acceptance.get("address") == source.get("address")
            and _nonnegative_int(acceptance.get("byte_offset"))
            and _nonnegative_int(acceptance.get("generation"))
            and acceptance.get("data_hex") == source.get("data_hex")
            and acceptance.get("source_event_id") == action
            and _version_pairs(versions, 4, generation=acceptance.get("generation"))
            and _version_sequences_positive(versions, 4)
            and acceptance.get("writer_event_ids") == [action] * 4
            and acceptance.get("writer_kinds") == ["INSTRUCTION_SOURCE"] * 4,
            "source-acceptance-four-byte-lanes")

    by_id = {event.get("event_id"): event for event in events
             if type(event.get("event_id")) is int}
    admission_ref = binding.get("admission_event_id")
    service_ref = binding.get("producer_event_id")
    require(_positive_int(admission_ref) and _positive_int(service_ref),
            "source-binding-event-reference-type")
    admission_event = by_id.get(admission_ref)
    service_event = by_id.get(service_ref)
    require(type(admission_event) is dict
            and _positive_int(admission_event.get("event_id"))
            and admission_event.get("kind") == "source_admission"
            and admission_event.get("admission") == admission
            and type(service_event) is dict
            and _positive_int(service_event.get("event_id"))
            and _positive_int(service_event.get("producer_event_id"))
            and service_event.get("kind") == "instruction_source"
            and service_event.get("component") == "cpu"
            and service_event.get("producer_event_id") == admission_event.get("event_id")
            and service_event.get("source_event_id") == acceptance.get("source_event_id")
            and service_event.get("source_event_id") == action
            and type(service_event.get("address")) is int
            and service_event.get("address") == source.get("address")
            and _nonnegative_int(service_event.get("generation"))
            and service_event.get("data_hex") == source.get("data_hex")
            and service_event.get("generation") == acceptance.get("generation")
            and admission_event["event_id"] < service_event["event_id"]
            < binding["event_id"],
            "source-admission-service-binding-event-join")
    service_inventory = {"instruction_source", "memory_initialization", "memory_read",
                         "memory_write"}
    service_index = sum(1 for event in events
        if event.get("component") == "cpu"
        and event.get("kind") in service_inventory
        and event.get("event_id", 0) < service_event["event_id"])
    require(service_event.get("kind") == "instruction_source"
            and binding.get("service_event_index") == service_index,
            "source-service-buffer-index-raw-inventory-join")
    span = [row for row in events if row.get("kind") == "memory_read"
            and row.get("component") == "cpu"
            and row.get("address") == source.get("address")
            and row.get("width_bytes") == 4
            and row.get("memory_id") == acceptance.get("memory_id")
            and _nonnegative_int(row.get("generation"))
            and _nonnegative_int(row.get("byte_offset"))
            and row.get("generation") == acceptance.get("generation")
            and row.get("byte_offset") == acceptance.get("byte_offset")]
    require(span, "source-acceptance-span-not-observed")
    return {"source_id": source_id, "binding_event": binding,
            "admission_event": admission_event, "service_event": service_event,
            "acceptance": acceptance, "source_data": data,
            "service_event_index": service_index,
            "service_event_index_basis": "count-prior-cpu-instruction_source-memory_initialization-memory_read-memory_write-events-in-contiguous-raw-event-journal"}


def source_completion_audit(events, plan, raw):
    require(type(plan.get("cases")) is list
            and type(plan.get("schema_version")) is int
            and plan.get("schema_version") == 22,
            "positive-plan-schema")
    session_testcase_id = plan_session_testcase_id(plan)
    selected = {}
    support = {}
    for index, case in enumerate(plan["cases"]):
        source = case.get("source", {})
        if case.get("source_role") == "fuzz_source" and source.get("kind") == "instruction":
            data = bytes.fromhex(source.get("data_hex", ""))
            require(source.get("component") == "cpu" and type(source.get("address")) is int
                    and source["address"] % 4 == 0 and len(data) == 4,
                    "selected-instruction-source-shape")
            action = source.get("action_id")
            require(type(action) is str and action and action not in selected,
                    "selected-instruction-action")
            selected[action] = (index, case, data)
        for instruction in case.get("support_instructions", []):
            support[(instruction.get("address"), instruction.get("data_hex"))] = case.get("case_id")
    require(selected, "selected-instruction-source-missing")
    selected_addresses = {row[1]["source"]["address"] for row in selected.values()}
    require(len(selected_addresses) == len(selected), "selected-instruction-alias")

    by_id = {event["event_id"]: event for event in events if type(event.get("event_id")) is int}
    bindings = {}
    service_index_checks = []
    for action, (index, case, _) in selected.items():
        chain = source_binding_chain(events, plan, index, case)
        bindings[action] = chain["binding_event"]
        service_index_checks.append({"action_id": action,
            "service_event_index": chain["service_event_index"],
            "instruction_source_event_id": chain["service_event"]["event_id"],
            "raw_inventory_basis": chain["service_event_index_basis"],
            "matched": True})
    observed_bindings = [event for event in events
                         if event.get("schema_version") == "native_instruction_source_binding.v1"]
    require(len(observed_bindings) == len(bindings), "binding-foreign-or-duplicate")
    require(set(bindings) == set(selected), "selected-binding-count")

    raw_by_completion = {join["completed_raw_event_id"]: join for join in raw["joins"]}
    completion_rows = [event for event in events
                       if event.get("schema_version") == "native_instruction_bus_completion.v1"
                       or event.get("kind") == "native_instruction_bus_completion"]
    require(all(event.get("schema_version") == "native_instruction_bus_completion.v1"
                and event.get("kind") == "native_instruction_bus_completion"
                for event in completion_rows), "malformed-source-completion-row")
    completions = {}
    by_raw = {}
    for event in completion_rows:
        action = event.get("binding", {}).get("source", {}).get("action_id")
        raw_id = event.get("producer_event_id")
        require(_positive_int(event.get("event_id")) and _positive_int(raw_id)
                and action in selected and action not in completions and raw_id not in by_raw,
                "completion-foreign-or-duplicate")
        completions[action] = event
        by_raw[raw_id] = event
    require(set(completions) == set(selected), "selected-completion-count")

    completion_reports = []
    for action, (index, case, source_bytes) in selected.items():
        event = completions[action]
        binding_event = bindings[action]
        refs = (event.get("admission_event_id"), event.get("service_event_id"),
                event.get("host_binding_event_id"), event.get("native_accepted_event_id"),
                event.get("native_response_event_id"), event.get("native_completed_event_id"),
                event.get("producer_event_id"))
        require(all(_positive_int(ref) for ref in refs),
                "completion-reference-exact-integer-positive")
        completion_fields = {
            "schema_version", "kind", "proof_scope", "grants_source_authority", "component",
            "event_id", "producer_event_id", "key", "snapshot", "binding", "address",
            "data_hex", "reset_epoch", "accepted_scope", "response_scope", "completion_scope",
            "native_pre", "admission_event_id", "host_binding_event_id", "service_event_id",
            "native_accepted_event_id", "native_response_event_id", "native_completed_event_id",
            "provenance",
        }
        binding = {key: binding_event[key] for key in
                   ("component", "execution", "reset_epoch", "case_index",
                    "admission", "source", "acceptance")}
        require(set(event) == completion_fields
                and event.get("schema_version") == "native_instruction_bus_completion.v1"
                and event.get("kind") == "native_instruction_bus_completion"
                and event.get("proof_scope") == "native_instruction_bus_transfer_completed"
                and event.get("grants_source_authority") is False
                and event.get("component") == "cpu"
                and type(event.get("reset_epoch")) is int and event.get("reset_epoch") == 0
                and event.get("binding") == binding
                and type(event.get("address")) is int
                and event.get("address") == case["source"]["address"]
                and event.get("data_hex") == case["source"]["data_hex"],
                "completion-proof-scope-or-binding")
        _require_completion_provenance(event, case.get("case_id"), index)
        join = raw_by_completion.get(event["producer_event_id"])
        require(join is not None and join.get("transaction") == event.get("key")
                and join.get("completed_raw_event_id") == event.get("producer_event_id")
                and join.get("accepted_native", {}).get("instruction") == 1
                and join.get("native", {}).get("instruction") == 1,
                "completion-raw-transaction-join")
        snapshot = event.get("snapshot")
        acceptance = binding["acceptance"]
        source = case["source"]
        source_data = bytes.fromhex(source["data_hex"])
        snapshot_keys = {"transaction_id", "memory_id", "generation", "byte_offset",
                         "data_hex", "versions", "writer_event_ids",
                         "materialized_offsets", "writer_kinds"}
        require(type(snapshot) is dict and set(snapshot) == snapshot_keys
                and snapshot.get("data_hex") == case["source"]["data_hex"]
                and snapshot.get("memory_id") == acceptance.get("memory_id")
                and _nonnegative_int(snapshot.get("generation"))
                and snapshot.get("generation") == acceptance.get("generation")
                and _nonnegative_int(snapshot.get("byte_offset"))
                and snapshot.get("byte_offset") == acceptance.get("byte_offset")
                and type(snapshot.get("data_hex")) is str
                and len(bytes.fromhex(snapshot["data_hex"])) == 4
                and _version_pairs(snapshot.get("versions"), 4,
                                   generation=acceptance.get("generation"))
                and _version_sequences_positive(snapshot.get("versions"), 4)
                and snapshot.get("versions") == acceptance.get("versions")
                and snapshot.get("writer_event_ids") == acceptance.get("writer_event_ids")
                and snapshot.get("writer_kinds") == acceptance.get("writer_kinds")
                and snapshot.get("materialized_offsets") == []
                and snapshot.get("transaction_id") == tx_text(event["key"]),
                "completion-exact-snapshot")
        read_event_id = join.get("service_event_id")
        require(_positive_int(read_event_id), "completion-read-event-reference")
        read_event = by_id.get(read_event_id)
        require(type(read_event) is dict and read_event.get("kind") == "memory_read"
                and read_event.get("event_id") == read_event_id
                and read_event.get("transaction") == event.get("key")
                and type(read_event.get("address")) is int
                and read_event.get("address") == case["source"]["address"]
                and type(read_event.get("width_bytes")) is int
                and read_event.get("width_bytes") == 4
                and read_event.get("data_hex") == snapshot["data_hex"]
                and type(read_event.get("value")) is int
                and read_event.get("value") == int.from_bytes(source_data, "little")
                and read_event.get("memory_id") == snapshot.get("memory_id")
                and _nonnegative_int(read_event.get("generation"))
                and read_event.get("generation") == snapshot.get("generation")
                and _nonnegative_int(read_event.get("byte_offset"))
                and read_event.get("byte_offset") == snapshot.get("byte_offset")
                and _version_pairs(read_event.get("versions"), 4,
                                   generation=snapshot.get("generation"))
                and _version_sequences_positive(read_event.get("versions"), 4)
                and read_event.get("versions") == snapshot.get("versions")
                and read_event.get("writer_event_ids") == snapshot.get("writer_event_ids")
                and ("writer_kinds" not in read_event
                     or read_event.get("writer_kinds") == snapshot.get("writer_kinds")),
                "completion-real-read-join")
        tx = event.get("key")
        require(type(tx) is dict and key_token(tx) == canonical(tx)
                and tx.get("source_component") == "cpu"
                and tx.get("source_epoch") == 0 and tx.get("channel_id") == "memory"
                and tx.get("testcase_id") == session_testcase_id
                and tx.get("source_sequence") > 0,
                "completion-source-transaction-identity")
        admission_event = by_id.get(event["admission_event_id"])
        binding_ref = by_id.get(event["host_binding_event_id"])
        source_event = by_id.get(event["service_event_id"])
        accepted_projection = by_id.get(event["native_accepted_event_id"])
        response_projection = by_id.get(event["native_response_event_id"])
        completed_projection = by_id.get(event["native_completed_event_id"])
        require(type(admission_event) is dict
                and admission_event.get("kind") == "source_admission"
                and admission_event.get("admission") == binding["admission"]
                and type(binding_ref) is dict
                and binding_ref.get("schema_version") == "native_instruction_source_binding.v1"
                and binding_ref.get("event_id") == bindings[action]["event_id"]
                and binding_ref.get("admission_event_id") == admission_event.get("event_id")
                and type(source_event) is dict
                and source_event.get("kind") == "instruction_source"
                and source_event.get("component") == "cpu"
                and source_event.get("source_event_id") == action
                and _positive_int(source_event.get("event_id"))
                and _positive_int(source_event.get("producer_event_id"))
                and source_event.get("producer_event_id") == admission_event.get("event_id")
                and source_event.get("address") == case["source"]["address"]
                and source_event.get("data_hex") == case["source"]["data_hex"]
                and binding_ref.get("producer_event_id") == source_event.get("event_id"),
                "completion-admission-host-service-join")
        require(type(accepted_projection) is dict
                and accepted_projection.get("kind") == "native_backend_request_accepted"
                and accepted_projection.get("transaction") == event.get("key")
                and accepted_projection.get("producer_event_id") == join.get("accepted_raw_event_id")
                and accepted_projection.get("event_id") == join.get("accepted_projection_event_id")
                and type(response_projection) is dict
                and response_projection.get("kind") == "native_backend_response_consumed"
                and response_projection.get("transaction") == event.get("key")
                and response_projection.get("producer_event_id") == join.get("response_raw_event_id")
                and response_projection.get("event_id") == join.get("response_projection_event_id")
                and type(completed_projection) is dict
                and completed_projection.get("kind") == "native_bus_completed"
                and completed_projection.get("transaction") == event.get("key")
                and completed_projection.get("producer_event_id") == event.get("producer_event_id")
                and completed_projection.get("event_id") == join.get("completion_projection_event_id"),
                "completion-native-projection-reference-join")
        for projection in (accepted_projection, response_projection, completed_projection):
            _require_observation_provenance(
                projection, case.get("case_id"), index, None,
                code="completion-native-projection-case-provenance")
        def projection_scope(row):
            return {name: row.get(name) for name in
                    ("execution", "command_sequence", "reset_epoch", "local_tick")}
        require(event.get("accepted_scope") == projection_scope(accepted_projection)
                and event.get("response_scope") == projection_scope(response_projection)
                and event.get("completion_scope") == projection_scope(completed_projection)
                and response_projection.get("value") == int.from_bytes(source_data, "little")
                and accepted_projection.get("native", {}).get("addr") == source["address"]
                and accepted_projection.get("native", {}).get("instruction") == 1
                and accepted_projection.get("native", {}).get("wstrb") == 0
                and response_projection.get("transaction") == event.get("key")
                and event.get("native_pre") == [
                    completed_projection.get("native", {}).get(name)
                    for name in ("valid", "ready", "addr", "wstrb", "rdata", "instruction")]
                and completed_projection.get("memory_read_snapshot") == snapshot,
                "completion-projection-scopes-values")
        event_refs = refs[:-1]
        require(all(ref < event["event_id"] for ref in event_refs)
                and admission_event["event_id"] < source_event["event_id"]
                < binding_ref["event_id"]
                < join["accepted_raw_event_id"]
                < accepted_projection["event_id"]
                < join["response_raw_event_id"]
                < response_projection["event_id"]
                < join["completed_raw_event_id"]
                < completed_projection["event_id"] < event["event_id"],
                "completion-reference-event-order")
        raw_pre = by_id.get(event.get("producer_event_id"))
        require(type(raw_pre) is dict and raw_pre.get("kind") == "local_tick_sample"
                and raw_pre.get("component") == "cpu" and raw_pre.get("phase") == "pre"
                and raw_pre.get("native_driver_scope") == event.get("completion_scope")
                and event.get("native_pre") == [1, 1, case["source"]["address"], 0,
                       int.from_bytes(source_bytes, "little"), 1],
                "completion-raw-pre")
        require(type(event.get("event_id")) is int
                and event["event_id"] > raw_pre["event_id"]
                and event.get("producer_event_id") == raw_pre.get("event_id"),
                "completion-event-after-completed-raw-pre")
        projections = [row for row in events
                      if row.get("schema_version") == "native_bus_observation.v1"
                      and row.get("kind") == "native_bus_completed"
                      and row.get("producer_event_id") == event.get("producer_event_id")]
        require(len(projections) == 1
                and projections[0].get("transaction") == event.get("key")
                and projections[0].get("memory_read_snapshot") == snapshot,
                "completion-transfer-projection")
        completion_reports.append({"action_id": action, "case_index": index,
                                   "address": case["source"]["address"],
                                   "data_hex": case["source"]["data_hex"],
                                   "completion_event_id": event.get("event_id"),
                                   "raw_event_id": event.get("producer_event_id")})

    no_grants = []
    selected_by_address_bytes = {
        (case["source"]["address"], bytes.fromhex(case["source"]["data_hex"])): action
        for action, (_, case, _) in selected.items()
    }
    for join in raw["joins"]:
        native = join.get("native")
        if native and native.get("instruction") == 1:
            raw_id = join.get("completed_raw_event_id")
            transaction = join.get("transaction")
            token = key_token(transaction)
            snapshot = join.get("snapshot")
            data_hex = snapshot.get("data_hex") if type(snapshot) is dict else None
            require(type(data_hex) is str and len(bytes.fromhex(data_hex)) == 4,
                    "instruction-fetch-four-byte-snapshot-required")
            candidate_rows = [event for event in completion_rows
                              if event.get("producer_event_id") == raw_id
                              or key_token(event.get("key")) == token]
            require(len(candidate_rows) <= 1, "duplicate-completion-for-instruction-transfer")
            if candidate_rows:
                event = candidate_rows[0]
                action = event.get("binding", {}).get("source", {}).get("action_id")
                require(event.get("producer_event_id") == raw_id
                        and event.get("key") == transaction
                        and action in selected
                        and event.get("address") == native.get("addr")
                        and event.get("data_hex") == data_hex
                        and bytes.fromhex(data_hex or "")
                            == selected[action][2],
                        "completion-not-exact-selected-transfer-identity")
                continue
            address = native.get("addr")
            require(address not in selected_addresses,
                    "native-source-completion-selected-fetch-without-grant")
            observed_bytes = bytes.fromhex(data_hex) if type(data_hex) is str else None
            selected_action = selected_by_address_bytes.get((address, observed_bytes))
            support_case = support.get((address, data_hex))
            if address in selected_addresses and observed_bytes is not None:
                selected_bytes_at_address = [source_bytes for _, case, source_bytes in selected.values()
                                             if case["source"]["address"] == address]
                if selected_action is None and selected_bytes_at_address:
                    classification = ("same_address_different_bytes"
                                      if observed_bytes not in selected_bytes_at_address
                                      else "same_bytes_unselected_transaction")
                else:
                    classification = "selected_address_unselected"
            else:
                classification = "fixed_support" if support_case else "unselected"
            no_grants.append({"raw_event_id": raw_id, "transaction": transaction,
                              "address": address, "data_hex": data_hex,
                              "classification": classification,
                              "support_case_id": support_case,
                              "completion_identity": {
                                  "matching_raw_event_id": None,
                                  "matching_transaction": None,
                                  "matching_action_id": None,
                                  "completion_event_id": None}})
    require(no_grants, "no-noncandidate-instruction-fetch-observed")
    return {"selected_completions": completion_reports,
            "noncandidate_no_grants": no_grants,
            "source_binding_service_index_checks": service_index_checks}


def events_for_case_index(events, case_id, case_index):
    """Select a fresh case by observed identity and bind it to its plan ordinal."""
    selected = []
    for event in events:
        provenance = event.get("provenance")
        observed = provenance.get("observed_case") if type(provenance) is dict else None
        if type(observed) is dict and observed.get("case_id") == case_id:
            require(set(observed) == {"case_id", "case_index"}
                    and type(observed.get("case_index")) is int
                    and observed["case_index"] == case_index,
                    "fresh-directed-case-index")
            selected.append(event)
    require(selected, "fresh-directed-case-events-missing")
    return selected


def require_case_receipt_identity(events, case_id, case_index):
    """Bind a saved case receipt to its exact case ID and list ordinal."""
    require(type(events) is list and events, "directed-case-events-missing")
    for event in events:
        provenance = event.get("provenance")
        observed = provenance.get("observed_case") if type(provenance) is dict else None
        require(type(observed) is dict
                and set(observed) == {"case_id", "case_index"}
                and observed.get("case_id") == case_id
                and type(observed.get("case_index")) is int
                and observed.get("case_index") == case_index,
                "original-directed-case-index")


def exact_case_event_subset(events, case_id, case_index):
    return events_for_case_index(events, case_id, case_index)


def load_plan(reader, branch):
    raw = reader.bytes("evidence", PurePosixPath(branch) / "plan.json")
    return strict_json_loads(raw), sha256(raw)


def require_plan_trace_identity(plan_sha256, *traces):
    require(re.fullmatch(r"[0-9a-f]{64}", plan_sha256) is not None,
            "plan-sha256-shape")
    for trace in traces:
        require(type(trace) is dict
                and trace.get("genome_sha256") == plan_sha256,
                "plan-trace-genome-sha256-join")


def directed_relation_audit(reader, branch, result, plan, original_events, fresh_events,
                            original_raw, fresh_raw, *, controlled):
    faults = result.get("controlled_response_records")
    cases = result.get("cases")
    plan_cases = plan.get("cases")
    session_testcase_id = plan_session_testcase_id(plan)
    require(type(cases) is list and type(plan_cases) is list
            and len(cases) == len(plan_cases), "directed-case-count")
    if controlled:
        require(len(cases) == 1 and cases[0].get("selected_source") == "cpu.instructions"
                and type(faults) is list and len(faults) == 2,
                "controlled-case-count-source-faults")
    else:
        require(len(cases) == 3
                and [case.get("selected_source") for case in cases]
                    == ["cpu.instructions", "gpio0.pin_byte", "cpu.instructions"],
                "positive-directed-source-sequence")
    expected = ({"routed_read_response_mismatch", "joint_ram_mismatch",
                 "joint_gpio_mismatch"} if controlled else set())
    original_relations = []
    fresh_relations = []
    original_by_id = {event.get("event_id"): event for event in original_events
                      if type(event.get("event_id")) is int}
    case_identity = []
    for plan_index, (case_row, plan_case) in enumerate(zip(cases, plan_cases)):
        case_id = plan_case.get("case_id")
        case_document = case_row.get("case")
        receipt = case_row.get("receipt")
        require(type(case_id) is str and case_id
                and type(case_document) is dict
                and case_document.get("case_id") == case_id
                and type(receipt) is dict and receipt.get("case_id") == case_id,
                "directed-case-id-plan-join")
        receipt_events = receipt.get("events")
        require_case_receipt_identity(receipt_events, case_id, plan_index)
        standalone = reader.branch_document(branch, f"case-{plan_index + 1}.json.gz",
                                            compressed=True)
        require(canonical(standalone) == canonical(case_row),
                "standalone-case-bundle-result-row-mismatch")
        original_subset = exact_case_event_subset(original_events, case_id, plan_index)
        all_original_ids = [event.get("event_id") for event in original_events]
        positions = {event_id: index for index, event_id in enumerate(all_original_ids)}
        subset_positions = [positions[event.get("event_id")] for event in original_subset]
        require(subset_positions == list(range(min(subset_positions), max(subset_positions) + 1)),
                "original-case-events-not-contiguous-half-open-slice")
        original_slice = original_events[min(subset_positions):max(subset_positions) + 1]
        require(canonical(original_slice) == canonical(original_subset),
                "original-case-half-open-slice-mismatch")
        receipt_by_id = {event.get("event_id"): event for event in receipt_events}
        subset_by_id = {event.get("event_id"): event for event in original_subset}
        require(len(receipt_by_id) == len(receipt_events)
                and len(subset_by_id) == len(original_subset)
                and set(receipt_by_id) == set(subset_by_id)
                and canonical([receipt_by_id[eid] for eid in sorted(receipt_by_id)])
                    == canonical([subset_by_id[eid] for eid in sorted(subset_by_id)]),
                "case-receipt-not-exact-original-case-subset")
        for event in receipt_events:
            saved = original_by_id.get(event.get("event_id"))
            require(saved is not None and canonical(saved) == canonical(event),
                    "case-receipt-not-subset-of-original-trace")
        relation = relation_for_case(case_row, plan_case,
                                     session_testcase_id=session_testcase_id)
        require(set(relation["findings"]) == expected,
                "original-directed-relation-findings")
        original_relations.append(relation)
        fresh_case_events = events_for_case_index(fresh_events, case_id, plan_index)
        fresh_relation = relation_for_events(fresh_case_events, plan_case,
            case_id=case_id, session_testcase_id=session_testcase_id)
        require(set(fresh_relation["findings"]) == expected,
                "fresh-directed-relation-findings")
        fresh_relations.append(fresh_relation)
        actual_indices = {event["provenance"]["observed_case"]["case_index"]
                          for event in receipt_events}
        require(actual_indices == {plan_index}, "case-row-index-plan-ordinal")
        case_identity.append({"case_id": case_id, "actual_case_index": next(iter(actual_indices)),
                              "plan_index": plan_index, "indices_match": True})
    if controlled:
        raw_joins = (raw_padout_join(original_relations[0], original_raw,
                                     session_testcase_id=session_testcase_id),
                     raw_padout_join(fresh_relations[0], fresh_raw,
                                     session_testcase_id=session_testcase_id))
        for index, (relation, raw_join) in enumerate(
                zip((original_relations[0], fresh_relations[0]), raw_joins)):
            fault = faults[index]
            consumer = relation["response_consumers"][0]
            actual = fault.get("actual_target_response")
            delivered = fault.get("delivered_response")
            require(key_token(fault.get("transaction"))
                        == key_token(relation["padout_read_transaction"])
                    and raw_join.get("faulted") is True
                    and type(actual) is list and len(actual) == 2
                    and type(delivered) is list and len(delivered) == 2
                    and actual == [relation["actual_a"], 0]
                    and delivered == [actual[0] ^ 1, 0]
                    and consumer["target_value"] == actual[0]
                    and consumer["cpu_value"] == delivered[0]
                    and raw_join["actual_service_response"] == actual[0]
                    and raw_join["delivered_response"] == delivered[0],
                    "controlled-padout-cpu-delivery-join")
            relation = (original_relations if index == 0 else fresh_relations)[0]
            require(relation["actual_ram"] == (relation["expected_joint"] ^ 1)
                    and relation["actual_final_gpio"] == (relation["expected_joint"] ^ 1),
                    "controlled-padout-xor1-joint-difference")
    # Controlled response demonstrates the CPU->GPIO PADOUT actual/delivered
    # response and its relation differences. Positive alone checks credentials.
    return {"original_relations": original_relations,
            "fresh_relations": fresh_relations,
            "case_identity": case_identity,
            "controlled_response_joins": ([
                {"transaction": raw_joins[index]["transaction"],
                 "service_event_id": raw_joins[index]["service_event_id"],
                 "response_command_event_id": raw_joins[index]["response_command_event_id"],
                 "actual_response": raw_joins[index]["actual_service_response"],
                 "delivered_response": raw_joins[index]["delivered_response"],
                 "faulted": raw_joins[index]["faulted"]}
                for index in range(2)] if controlled else []),
            "native_instruction_source_credential_checked": False,
            "controlled_padout_address": (0x4000000c if controlled else None),
            "controlled_response_xor": (1 if controlled else None)}


def refusal_audit(bundle, result, plan, raw, artifact):
    trace = bundle["trace"]
    events = trace["events"]
    require(type(plan.get("schema_version")) is int
            and plan.get("schema_version") == 23, "refusal-plan-schema")
    session_testcase_id = plan_session_testcase_id(plan)
    injection = bundle["injection"]
    refusal = bundle["refusal_record"]
    source_case = [case for case in plan["cases"]
                   if case.get("source_role") == "fuzz_source"
                   and case.get("source", {}).get("kind") == "instruction"]
    require(len(source_case) == 1, "refusal-selected-source-count")
    case_index = plan["cases"].index(source_case[0])
    source_chain = source_binding_chain(events, plan, case_index, source_case[0])
    binding_event = source_chain["binding_event"]
    acceptance = source_chain["acceptance"]
    source = source_case[0]["source"]
    terminal_failure = plan.get("terminal_failure")
    terminal_advances = source_case[0].get("advances")
    require(type(terminal_failure) is dict
            and terminal_failure.get("phase") == "step"
            and type(terminal_failure.get("case_index")) is int
            and terminal_failure.get("case_index") == case_index == len(plan["cases"]) - 1
            and type(terminal_advances) is list and len(terminal_advances) == 128
            and type(terminal_failure.get("command_index")) is int
            and 0 <= terminal_failure.get("command_index") < len(terminal_advances)
            and terminal_failure.get("case_id") == source_case[0].get("case_id")
            and terminal_failure.get("error_type") == "ValueError"
            and terminal_failure.get("error_message") == "native_source_candidate_refused",
            "refusal-plan-terminal-failure")
    write_key = injection["transaction"]
    native_key = refusal.get("native_transaction")
    require(type(injection) is dict
            and set(injection) == {"transaction", "write_receipt_object", "write_receipt",
                                   "write_service_event", "binding_event_id"}
            and _positive_int(injection.get("binding_event_id"))
            and injection.get("binding_event_id") == binding_event.get("event_id")
            and key_token(write_key) == canonical(write_key)
            and write_key["source_component"] == "cpu"
            and write_key["testcase_id"] == session_testcase_id
            and write_key["source_epoch"] == 0
            and write_key["channel_id"] == "native-source-poison"
            and write_key["source_sequence"] == 1
            and key_token(native_key) == canonical(native_key)
            and native_key["source_component"] == "cpu"
            and native_key["testcase_id"] == session_testcase_id
            and native_key["source_epoch"] == 0
            and native_key["channel_id"] == "memory"
            and native_key["execution_id"] == write_key["execution_id"]
            and native_key != write_key,
            "refusal-transaction-identity")
    refusal_fields = {"schema_version", "selected_action_id", "native_transaction",
                      "refused_raw_event_id", "write_transaction", "write_receipt_object",
                      "write_receipt", "write_service_event", "write_journal_event_id",
                      "write_journal_event", "original_acceptance"}
    require(type(refusal) is dict and set(refusal) == refusal_fields
            and refusal.get("schema_version") == "native_source_candidate_refusal.v1"
            and refusal.get("selected_action_id") == source["action_id"]
            and refusal.get("write_transaction") == write_key,
            "refusal-record-exact-shape")
    write_service = injection["write_service_event"]
    receipt = injection["write_receipt"]
    expected_payload = {"op": "write", "address": source["address"], "value": 0x13,
                        "width_bytes": 4, "byte_enable": 15}
    receipt_fields = {"schema_version", "fullkey", "memory_kind", "memory_id", "generation",
                      "byte_offset", "width_bytes", "byte_enable", "version", "payload_sha256",
                      "commit_status", "performed_effect", "enabled_byte_cells", "commit_id"}
    version = receipt.get("version") if type(receipt) is dict else None
    require(type(receipt) is dict and set(receipt) == receipt_fields
            and sha256(canonical(expected_payload)) == receipt.get("payload_sha256"),
            "refusal-payload-hash")
    material = {key: value for key, value in receipt.items() if key != "commit_id"}
    expected_commit_id = sha256(json.dumps(material, sort_keys=True, separators=(",", ":"),
                                           allow_nan=False).encode("utf-8"))
    require(expected_commit_id == receipt.get("commit_id"),
            "refusal-commit-id")
    require(receipt.get("schema_version") == "memory_write_commit_receipt.v1"
            and receipt.get("fullkey") == write_key
            and receipt.get("memory_kind") == "modeled_host_persistent_memory"
            and type(receipt.get("memory_id")) is str and receipt["memory_id"].strip()
            and _u64(receipt.get("generation"))
            and _u64(receipt.get("byte_offset"))
            and receipt["byte_offset"] <= (1 << 64) - 4
            and receipt.get("commit_status") == "complete"
            and receipt.get("performed_effect") is True
            and type(receipt.get("width_bytes")) is int and receipt["width_bytes"] == 4
            and type(receipt.get("byte_enable")) is int and receipt["byte_enable"] == 15
            and type(version) is list and len(version) == 2
            and all(_u64(part) for part in version)
            and version[0] == receipt.get("generation") and version[1] > 0
            and _version_pairs([version], 1, generation=receipt.get("generation"), u64=True)
            and receipt.get("memory_id") == write_service.get("memory_id")
            and receipt.get("generation") == write_service.get("generation")
            and receipt.get("byte_offset") == write_service.get("byte_offset")
            and receipt.get("version") == write_service.get("version"),
            "refusal-actual-commit-fields")
    require(type(write_service) is dict
            and set(write_service) == {"kind", "transaction", "address", "width_bytes",
                "memory_id", "generation", "byte_offset", "value", "byte_enable", "version"}
            and write_service.get("kind") == "memory_write"
            and write_service.get("transaction") == write_key
            and type(write_service.get("address")) is int
            and write_service.get("address") == source["address"]
            and type(write_service.get("width_bytes")) is int
            and write_service.get("width_bytes") == 4
            and type(write_service.get("memory_id")) is str
            and write_service["memory_id"].strip()
            and _u64(write_service.get("generation"))
            and _u64(write_service.get("byte_offset"))
            and write_service["byte_offset"] <= (1 << 64) - 4
            and type(write_service.get("value")) is int
            and write_service.get("value") == 0x13
            and type(write_service.get("byte_enable")) is int
            and write_service.get("byte_enable") == 15
            and _version_pairs([write_service.get("version")], 1,
                               generation=receipt.get("generation"), u64=True)
            and write_service.get("version") == version,
            "refusal-service-write")
    write_object = injection.get("write_receipt_object")
    require(type(write_object) is dict
            and set(write_object) == {"transaction_id", "version", "byte_enable"}
            and write_object.get("transaction_id") == write_key
            and write_object.get("version") == receipt.get("version")
            and _version_pairs([write_object.get("version")], 1,
                               generation=receipt.get("generation"), u64=True)
            and type(write_object.get("byte_enable")) is int
            and write_object.get("byte_enable") == 15,
            "refusal-typed-write-receipt")
    require(refusal.get("write_receipt_object") == write_object
            and refusal.get("write_receipt") == receipt
            and refusal.get("write_service_event") == write_service,
            "refusal-payload-receipt-reference-join")
    writer_id = tx_text(write_key)
    byte_values = list(bytes.fromhex("13000000"))
    cells = receipt.get("enabled_byte_cells")
    require(type(cells) is list and len(cells) == 4
            and all(type(cell) is dict
                    and set(cell) == {"byte_offset", "value", "version", "writer_kind",
                                      "writer_event_id"}
                    and type(cell.get("byte_offset")) is int
                    and cell.get("byte_offset") == receipt["byte_offset"] + lane
                    and type(cell.get("value")) is int
                    and cell.get("value") == byte_values[lane]
                    and type(cell.get("version")) is list
                    and _version_pairs([cell["version"]], 1,
                                       generation=receipt.get("generation"), u64=True)
                    and cell.get("version") == version
                    and cell.get("writer_kind") == "STORE"
                    and cell.get("writer_event_id") == writer_id
                    for lane, cell in enumerate(cells)),
            "refusal-typed-write-byte-cells")
    by_id = {event["event_id"]: event for event in events if type(event.get("event_id")) is int}
    journal_ref = refusal.get("write_journal_event_id")
    require(_positive_int(journal_ref), "refusal-journal-event-reference-type")
    journal_write = by_id.get(journal_ref)
    require(journal_write == refusal.get("write_journal_event")
            and type(journal_write) is dict
            and set(journal_write) == {"kind", "transaction", "address", "width_bytes",
                "memory_id", "generation", "byte_offset", "value", "byte_enable", "version",
                "event_id", "producer_event_id", "component", "provenance"}
            and journal_write.get("kind") == "memory_write"
            and journal_write.get("component") == "cpu"
            and journal_write.get("transaction") == write_key
            and type(journal_write.get("address")) is int
            and journal_write.get("address") == source["address"]
            and type(journal_write.get("width_bytes")) is int
            and journal_write.get("width_bytes") == 4
            and type(journal_write.get("memory_id")) is str
            and journal_write["memory_id"].strip()
            and _u64(journal_write.get("generation"))
            and _u64(journal_write.get("byte_offset"))
            and journal_write["byte_offset"] <= (1 << 64) - 4
            and type(journal_write.get("value")) is int
            and journal_write.get("value") == 0x13
            and type(journal_write.get("byte_enable")) is int
            and journal_write.get("byte_enable") == 15
            and _version_pairs([journal_write.get("version")], 1,
                               generation=receipt.get("generation"), u64=True)
            and journal_write.get("version") == version,
            "refusal-journal-write")
    _require_observation_provenance(
        journal_write, source_case[0].get("case_id"), case_index,
        _provenance_resource(journal_write),
        code="refusal-journal-write-provenance-envelope")
    write_producer_id = journal_write.get("producer_event_id")
    require(_positive_int(write_producer_id), "refusal-write-producer-reference-type")
    write_producer = by_id.get(write_producer_id)
    binding_event_for_source = [event for event in events
        if event.get("schema_version") == "native_instruction_source_binding.v1"
        and event.get("kind") == "native_instruction_source_bound"
        and event.get("source", {}).get("action_id") == source["action_id"]]
    require(len(binding_event_for_source) == 1
            and binding_event_for_source[0] == binding_event
            and type(write_producer) is dict
            and write_producer.get("component") == "cpu"
            and (write_producer.get("kind") == "harness_failure"
                 or ("kind" not in write_producer
                     and type(write_producer.get("outputs")) is dict))
            and binding_event_for_source[0]["event_id"] < write_producer["event_id"]
            < journal_write["event_id"]
            and write_service.get("memory_id") == journal_write.get("memory_id")
            and write_service.get("generation") == journal_write.get("generation")
            and write_service.get("byte_offset") == journal_write.get("byte_offset")
            and write_service.get("version") == journal_write.get("version"),
            "refusal-write-journal-producer-order")
    read_key = native_key
    reads = [event for event in events if event.get("kind") == "memory_read"
             and event.get("component") == "cpu" and event.get("transaction") == read_key]
    require(len(reads) == 1, "refusal-source-read-count")
    read = reads[0]
    try:
        read_bytes = bytes.fromhex(read.get("data_hex", ""))
    except (TypeError, ValueError) as exc:
        raise AuditError("refusal-read-data-hex") from exc
    read_versions = read.get("versions")
    read_writer_ids = read.get("writer_event_ids")
    read_writer_kinds = read.get("writer_kinds")
    require(_positive_int(read.get("event_id"))
            and _positive_int(read.get("producer_event_id"))
            and read.get("transaction") == native_key
            and type(read.get("address")) is int and read.get("address") == source["address"]
            and type(read.get("width_bytes")) is int and read.get("width_bytes") == 4
            and read.get("data_hex") == "13000000" and len(read_bytes) == 4
            and read_bytes.hex() == "13000000"
            and type(read.get("value")) is int and read.get("value") == 0x13
            and read.get("version") is None
            and read.get("memory_id") == receipt.get("memory_id")
            and _u64(read.get("generation"))
            and read.get("generation") == receipt.get("generation")
            and _u64(read.get("byte_offset"))
            and read.get("byte_offset") == receipt.get("byte_offset")
            and _version_pairs(read_versions, 4, generation=receipt.get("generation"), u64=True)
            and read_versions == [version] * 4
            and type(read_writer_ids) is list and len(read_writer_ids) == 4
            and all(type(writer) is str for writer in read_writer_ids)
            and read_writer_ids == [writer_id] * 4
            and type(read_writer_kinds) is list and len(read_writer_kinds) == 4
            and all(type(kind) is str for kind in read_writer_kinds)
            and read_writer_kinds == ["STORE"] * 4,
            "refusal-read-is-poison-snapshot")
    original_acceptance = refusal.get("original_acceptance")
    require(original_acceptance == acceptance
            and type(original_acceptance) is dict
            and original_acceptance.get("data_hex") == source["data_hex"]
            and original_acceptance.get("address") == source["address"]
            and original_acceptance.get("memory_id") == receipt.get("memory_id")
            and original_acceptance.get("generation") == receipt.get("generation")
            and original_acceptance.get("byte_offset") == receipt.get("byte_offset")
            and acceptance.get("data_hex") != read["data_hex"]
            and acceptance.get("versions") != read["versions"]
            and acceptance.get("writer_event_ids") != read["writer_event_ids"]
            and acceptance.get("writer_kinds") != read["writer_kinds"],
            "refusal-original-binding-contradiction")
    binding_rows = [event for event in events
                    if event.get("schema_version") == "native_instruction_source_binding.v1"
                    and event.get("kind") == "native_instruction_source_bound"
                    and event.get("source", {}).get("action_id") == source["action_id"]]
    require(len(binding_rows) == 1
            and binding_rows[0].get("acceptance") == acceptance
            and binding_rows[0].get("source") == source,
            "refusal-binding-event-join")
    refused_id = refusal.get("refused_raw_event_id")
    require(_positive_int(refused_id), "refusal-raw-event-reference-type")
    terminal_raw = by_id.get(refused_id)
    require(type(terminal_raw) is dict and terminal_raw.get("kind") == "local_tick_sample"
            and terminal_raw.get("phase") == "pre"
            and _positive_int(terminal_raw.get("producer_event_id"))
            and terminal_raw.get("native_driver_scope") is not None,
            "refusal-terminal-raw-pre")
    terminal_native, _ = _native_tuple(terminal_raw, artifact)
    require(terminal_native["valid"] == terminal_native["ready"] == 1
            and terminal_native["instruction"] == 1
            and terminal_native["addr"] == source["address"]
            and terminal_native["rdata"] == 0x13,
            "refusal-terminal-native-pre")
    terminal_state = raw.get("terminal_refusal")
    require(type(terminal_state) is dict
            and terminal_state.get("raw_event_id") == refused_id
            and terminal_state.get("producer_event_id") == terminal_raw.get("producer_event_id")
            and terminal_state.get("transaction") == native_key
            and terminal_state.get("refused_scope") == terminal_raw.get("native_driver_scope")
            and terminal_state.get("native") == terminal_native,
            "refusal-terminal-state-machine-join")
    terminal_joins = [join for join in raw["joins"]
                      if join.get("completed_raw_event_id") == refused_id]
    terminal_join = terminal_joins[0] if len(terminal_joins) == 1 else None
    if type(terminal_join) is dict:
        require(_positive_int(terminal_join.get("accepted_raw_event_id"))
                and _positive_int(terminal_join.get("response_raw_event_id"))
                and _positive_int(terminal_join.get("response_post_event_id")),
                "refusal-terminal-join-reference-type")
    accepted_raw = by_id.get(terminal_join.get("accepted_raw_event_id")) \
        if type(terminal_join) is dict else None
    response_raw = by_id.get(terminal_join.get("response_raw_event_id")) \
        if type(terminal_join) is dict else None
    accepted_command_id = (accepted_raw.get("producer_event_id")
                           if type(accepted_raw) is dict else None)
    response_command_id = (response_raw.get("producer_event_id")
                           if type(response_raw) is dict else None)
    require(len(terminal_joins) == 1
            and type(terminal_join) is dict
            and terminal_join.get("transaction") == native_key
            and terminal_join.get("delivered_response") == 0x13
            and terminal_join.get("service_event_id") == read.get("event_id")
            and type(accepted_raw) is dict and accepted_raw.get("kind") == "local_tick_sample"
            and accepted_raw.get("component") == "cpu" and accepted_raw.get("phase") == "pre"
            and type(response_raw) is dict and response_raw.get("kind") == "local_tick_sample"
            and response_raw.get("component") == "cpu" and response_raw.get("phase") == "pre"
            and type(accepted_command_id) is int
            and type(response_command_id) is int
            and read.get("producer_event_id") == accepted_command_id
            and terminal_join.get("response_command_event_id") == response_command_id
            and accepted_command_id < read.get("event_id", 0) < accepted_raw.get("event_id", 0)
            < response_command_id < response_raw.get("event_id", 0)
            < terminal_join.get("response_post_event_id", 0) < refused_id,
            "refusal-raw-terminal-transaction-join")
    poison_ids = raw.get("poison_service_event_ids")
    require(type(poison_ids) is list and len(poison_ids) == 1
            and poison_ids[0] == journal_write.get("event_id")
            and _positive_int(journal_write.get("event_id"))
            and journal_write.get("transaction") == write_key
            and key_token(journal_write.get("transaction")) == canonical(write_key),
            "refusal-unique-poison-service-row-join")
    require(journal_write["event_id"] < read["event_id"] < terminal_raw["event_id"],
            "refusal-write-read-terminal-order")
    failures = [event for event in events if event.get("kind") == "harness_failure"
                and event.get("component") == "cpu"
                and event.get("event_id") == terminal_raw.get("producer_event_id")
                and event.get("error_type") == terminal_failure.get("error_type")]
    require(len(failures) == 1
            and _positive_int(failures[0].get("event_id"))
            and terminal_raw.get("producer_event_id") == failures[0]["event_id"],
            "refusal-terminal-error")
    require(not [event for event in events
                 if event.get("kind") == "native_instruction_bus_completion"]
            and not [event for event in events
                     if event.get("kind") == "native_bus_completed"
                     and event.get("producer_event_id") == refused_id],
            "refusal-must-not-grant-completion")
    return {"selected_action_id": source["action_id"], "address": source["address"],
            "source_binding_service_event_index": source_chain["service_event_index"],
            "source_binding_service_index_basis": source_chain["service_event_index_basis"],
            "write_event_id": journal_write["event_id"], "read_event_id": read["event_id"],
            "terminal_raw_event_id": refused_id, "no_completion": True}


def audit_branch(reader, name, *, identity, gate_start, controlled=False, refusal=False):
    branch = name
    result = reader.branch_document(branch, "result.json.gz", compressed=True)
    require(type(identity) is dict and type(gate_start) is dict
            and result.get("gate_run_id") == identity["run"]["gate_run_id"]
            and result.get("gate_branch") == branch
            and type(result.get("gate_pid")) is int
            and result["gate_pid"] > 0
            and result["gate_pid"] == gate_start.get("pid"),
            "branch-result-run-identity:" + branch)
    plan, plan_sha256 = load_plan(reader, branch)
    expected_status = ("native_source_completion_refusal_gate_passed" if refusal
                       else "bounded_directed_gate_passed")
    require(result.get("status") == expected_status, "gate-result-status:" + branch)
    processes = process_audit(result.get("processes"))
    require(result.get("capture_errors") == [], "process-capture-errors")
    if not refusal:
        initial = result.get("initial_process_identities")
        require(type(initial) is dict, "initial-process-identities-missing")
        for component in ("cpu", "gpio0"):
            process = process_for(processes, component, "runner-0")
            identity = initial.get(component)
            require(type(identity) is dict
                    and type(identity.get("pid")) is int
                    and identity.get("pid") == process.get("pid")
                    and identity.get("execution_nonce") == process.get("execution_nonce")
                    and identity.get("artifact_digest") == process.get("artifact_digest")
                    and type(identity.get("reset_epoch")) is int
                    and identity.get("reset_epoch") == process.get("reset_epoch"),
                    "initial-process-identity-join")
    first = bundle_reference(reader, branch, result,
                             "original_bundle" if refusal else "first_bundle",
                             "original-terminal.json.gz" if refusal else "first.json.gz")
    if refusal:
        original = first["trace"]
        require(type(result.get("fresh_replay")) is dict,
                "refusal-fresh-replay-reference-missing")
        fresh_bundle = bundle_reference(reader, branch, result, "fresh_replay",
                                        "fresh-terminal-replay.json.gz")
        bundle_reference(reader, branch, result, "native_source_completion_checks",
                         "native-source-refusal-checks.json.gz")
        comparison = fresh_bundle.get("comparison")
        require(type(comparison) is dict and comparison.get("matches") is True
                and comparison.get("first_difference") is None
                and comparison.get("verification_scope") == "full",
                "refusal-fresh-comparison-full-success")
        fresh = comparison["actual_trace"]
        require_plan_trace_identity(plan_sha256, original, fresh)
        full_fresh = full_fresh_audit(original, fresh, processes, processes)
        # Refusal branch uses a terminal-refusal raw path with no source-completion grant.
        artifact = load_artifact_for_refusal(reader, branch, original, processes)
        raw = raw_transaction_audit(original["events"], artifact,
                                    process_for(processes, "cpu", "runner-0"), [],
                                    allow_terminal=True,
                                    session_testcase_id=plan_session_testcase_id(plan),
                                    case_ids={case.get("case_id") for case in plan["cases"]},
                                    case_index_by_id=_case_index_by_id(plan))
        refusal_report = refusal_audit(first, result, plan, raw, artifact)
        fresh_refusal = refusal_audit(
            {"trace": fresh, "injection": fresh_bundle["injection"],
             "refusal_record": fresh_bundle["refusal_record"]},
            result, plan, raw_transaction_audit(
                fresh["events"], artifact,
                process_for(processes, "cpu", "runner-1"), [], allow_terminal=True,
                session_testcase_id=plan_session_testcase_id(plan),
                case_ids={case.get("case_id") for case in plan["cases"]},
                case_index_by_id=_case_index_by_id(plan)), artifact)
        return {"processes": processes, "plan_sha256": plan_sha256,
                "full_fresh": full_fresh,
                "raw": raw, "refusal": refusal_report,
                "fresh_refusal": fresh_refusal}

    require_plan_trace_identity(plan_sha256, first)
    fresh_doc = bundle_reference(reader, branch, result, "fresh_bundle",
                                 "fresh-comparison.json.gz")
    fresh = fresh_doc["actual_trace"]
    require_plan_trace_identity(plan_sha256, fresh)
    require(fresh_doc.get("matches") is True and fresh_doc.get("first_difference") is None
            and fresh_doc.get("verification_scope") == "full", "fresh-full-scope")
    bundle_reference(reader, branch, result, "native_source_binding_checks",
                     "native-source-binding-checks.json.gz")
    if not controlled:
        bundle_reference(reader, branch, result, "native_source_completion_checks",
                         "native-source-completion-checks.json.gz")
    fresh_report = full_fresh_audit(first, fresh, processes, processes)
    obs_ref = result.get("native_observation_checks")
    require(type(obs_ref) is dict, "native-observation-document-reference")
    obs_doc = bundle_reference(reader, branch, result, "native_observation_checks",
                               "native-observation-checks.json.gz")
    # Only artifact metadata is used. Saved checker status/counts/errors are not read.
    original_artifact = obs_doc["original"]["artifact_document"]
    fresh_artifact = obs_doc["fresh"]["artifact_document"]
    require(original_artifact == fresh_artifact, "fresh-artifact-metadata-match")
    faults = result.get("controlled_response_records", [])
    raw = raw_transaction_audit(first["events"], original_artifact,
                                process_for(processes, "cpu", "runner-0"),
                                faults[:1] if controlled else [],
                                session_testcase_id=plan_session_testcase_id(plan),
                                case_ids={case.get("case_id") for case in plan["cases"]},
                                case_index_by_id=_case_index_by_id(plan))
    raw_fresh = raw_transaction_audit(fresh["events"], fresh_artifact,
                                      process_for(processes, "cpu", "runner-1"),
                                      faults[1:] if controlled else [],
                                      session_testcase_id=plan_session_testcase_id(plan),
                                      case_ids={case.get("case_id") for case in plan["cases"]},
                                      case_index_by_id=_case_index_by_id(plan))
    require(len(raw["joins"]) == len(raw_fresh["joins"]), "fresh-raw-join-count")
    relation_report = None
    source_report = None
    if controlled:
        require(raw["fault_count"] == raw_fresh["fault_count"] == 1,
                "controlled-original-fresh-fault-count")
        relation_report = directed_relation_audit(
            reader, branch, result, plan, first["events"], fresh["events"],
            raw, raw_fresh, controlled=True)
    else:
        source_report = source_completion_audit(first["events"], plan, raw)
        source_report["fresh"] = source_completion_audit(fresh["events"], plan, raw_fresh)
        relation_report = directed_relation_audit(
            reader, branch, result, plan, first["events"], fresh["events"],
            raw, raw_fresh, controlled=False)
    return {"processes": processes, "plan_sha256": plan_sha256,
            "full_fresh": fresh_report, "raw": raw,
            "fresh_raw": raw_fresh, "directed_relations": relation_report,
            "controlled_response": (relation_report if controlled else None),
            "source_completion": source_report}


def load_artifact_for_refusal(reader, branch, original, processes):
    # The positive branch pins the same CPU artifact contract for all branches.
    # Only its artifact metadata is used; checker conclusions are ignored.
    positive_result = reader.branch_document("positive", "result.json.gz",
                                             compressed=True)
    reference = positive_result.get("native_observation_checks")
    require(type(reference) is dict and type(reference.get("path")) is str,
            "positive-native-observation-reference-missing")
    document = bundle_reference(reader, "positive", positive_result,
                                "native_observation_checks",
                                "native-observation-checks.json.gz")
    artifact = document["original"]["artifact_document"]
    require(artifact.get("artifact_digest")
            == process_for(processes, "cpu", "runner-0").get("artifact_digest"),
            "refusal-artifact-does-not-match-process")
    return artifact


def operation_terminal_audit(reader, identity):
    """Join pinned input bytes to the gate's terminal receipts."""
    require(type(identity) is dict and identity.get("schema_version")
            == _AUDIT_IDENTITY_SCHEMA, "operation-identity-required")
    files = identity["operation_files"]

    def document(name):
        row = reader.document("operation", files[name]["path"])
        require(type(row) is dict and type(row.get("schema_version")) is str
                and bool(row["schema_version"]), "operation-document-shape:" + name)
        return row

    intent, plan = document("intent"), document("plan")
    controller_receipt = document("controller_receipt")
    claim, launch = document("claim"), document("launch_intent")
    start, end = document("gate_start"), document("gate_end")
    post = document("post_run_integrity")
    source_post, lock_post = document("source_postflight"), document("lock_postflight")
    source_manifest = document("source_manifest")
    run = identity["run"]
    hashes = {name: row["sha256"] for name, row in files.items()}
    require(set(source_manifest) == {"schema_version", "entries"}
            and source_manifest["schema_version"] == "source_tree_manifest.v1"
            and type(source_manifest["entries"]) is list
            and bool(source_manifest["entries"]), "source-manifest-entries")
    source_paths = set()
    for entry in source_manifest["entries"]:
        require(type(entry) is dict and set(entry) == {"path", "sha256"}
                and type(entry["path"]) is str
                and type(entry["sha256"]) is str
                and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is not None,
                "source-manifest-entry-shape")
        source_path = PurePosixPath(entry["path"])
        require(source_path.parts[:1] == ("project",)
                and len(source_path.parts) > 1
                and not source_path.is_absolute()
                and all(part not in ("", ".", "..") for part in source_path.parts)
                and source_path.as_posix() == entry["path"]
                and entry["path"] not in source_paths,
                "source-manifest-entry-path")
        source_paths.add(entry["path"])
        require(sha256(reader.bytes("operation", entry["path"])) == entry["sha256"],
                "source-manifest-entry-hash:" + entry["path"])
    require(files["gate_script"]["path"] in source_paths,
            "source-manifest-gate-script-missing")
    source = intent.get("source")
    require(type(source) is dict and set(source) == {"manifest", "task5_files"}
            and type(source["manifest"]) is dict
            and set(source["manifest"]) == {
                "path", "sha256", "entries", "canonical_entries_sha256"}
            and source["manifest"]["path"]
                == str(reader.operation / files["source_manifest"]["path"])
            and source["manifest"]["sha256"] == hashes["source_manifest"]
            and type(source["manifest"]["entries"]) is int
            and source["manifest"]["entries"] == len(source_paths)
            and source["manifest"]["canonical_entries_sha256"]
                == sha256(canonical(source_manifest["entries"]))
            and type(source["task5_files"]) is list and bool(source["task5_files"]),
            "intent-source-manifest-identity")
    task5_paths = set()
    for item in source["task5_files"]:
        require(type(item) is dict and set(item) == {"path", "sha256"}
                and type(item["path"]) is str
                and type(item["sha256"]) is str
                and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None,
                "intent-task5-file-shape")
        path = "project/" + item["path"]
        require(path in source_paths and path not in task5_paths
                and sha256(reader.bytes("operation", path)) == item["sha256"],
                "intent-task5-source-identity:" + path)
        task5_paths.add(path)
    require(files["gate_script"]["path"] in task5_paths,
            "intent-task5-gate-script-missing")
    tool_freeze = reader.document("workspace", identity["workspace_files"]["tool_freeze"]["path"])
    require(type(tool_freeze) is dict and "python3" in tool_freeze,
            "tool-freeze-shape")
    checked_workspace_tools = []
    for name, tool in tool_freeze.items():
        require(type(name) is str and bool(name)
                and type(tool) is dict and set(tool) == {"path", "sha256"}
                and type(tool["path"]) is str and type(tool["sha256"]) is str
                and re.fullmatch(r"[0-9a-f]{64}", tool["sha256"]) is not None,
                "tool-freeze-row-shape")
        path = Path(tool["path"])
        require(path.is_absolute() and ".." not in path.parts
                and str(path) == tool["path"], "tool-freeze-path")
        if path.is_relative_to(reader.workspace):
            require(sha256(reader.absolute_workspace_bytes(path)) == tool["sha256"],
                    "tool-freeze-binary-hash:" + name)
            checked_workspace_tools.append(name)
    environment = intent.get("environment")
    require(type(environment) is dict
            and type(environment.get("tools")) is list
            and type(environment.get("tool_count")) is int
            and environment["tool_count"] == len(tool_freeze)
            and environment.get("tool_freeze") == str(
                reader.workspace / identity["workspace_files"]["tool_freeze"]["path"])
            and environment.get("tool_freeze_sha256")
                == identity["workspace_files"]["tool_freeze"]["sha256"],
            "intent-tool-freeze-identity")
    intent_tools = {}
    for item in environment["tools"]:
        require(type(item) is dict and set(item) == {"name", "path", "sha256"}
                and type(item["name"]) is str
                and item["name"] not in intent_tools,
                "intent-tool-row-shape")
        intent_tools[item["name"]] = {"path": item["path"],
                                      "sha256": item["sha256"]}
    require(intent_tools == tool_freeze, "intent-tool-freeze-map-mismatch")
    source_reference = intent.get("source_manifest_sha256")
    if source_reference is None:
        source_reference = (intent.get("source") or {}).get("manifest", {}).get("sha256")
    freeze_reference = intent.get("tool_freeze_sha256")
    if freeze_reference is None:
        freeze_reference = (intent.get("environment") or {}).get("tool_freeze_sha256")
    script_reference = intent.get("gate_script_sha256")
    if script_reference is None:
        rows = (intent.get("source") or {}).get("task5_files")
        if type(rows) is list:
            matches = [row.get("sha256") for row in rows if type(row) is dict
                and row.get("path") == "scripts/verify_picorv32_native_online.py"]
            script_reference = matches[0] if len(matches) == 1 else None
    require(source_reference == hashes["source_manifest"]
            and freeze_reference == identity["workspace_files"]["tool_freeze"]["sha256"]
            and intent.get("gate_script_sha256") == hashes["gate_script"]
            and script_reference == hashes["gate_script"],
            "intent-source-and-tool-identity")
    require(intent.get("run") == run and intent.get("claims") == CLAIMS
            and intent.get("acceptance_matrix") == ACCEPTANCE_MATRIX
            and intent.get("gate_started") is False
            and intent.get("gate_executed") is False,
            "intent-run-and-claim-identity")
    require(controller_receipt.get("path")
                == str(reader.operation / files["controller"]["path"])
            and controller_receipt.get("controller_sha256") == hashes["controller"]
            and controller_receipt.get("intent_sha256") == hashes["intent"]
            and controller_receipt.get("gate_started") is False
            and controller_receipt.get("gate_executed") is False,
            "controller-receipt-identity")
    require(plan.get("run") == run and plan.get("gate_run_id") == run["gate_run_id"]
            and plan.get("intent") == intent
            and plan.get("intent_sha256") == hashes["intent"]
            and plan.get("controller_sha256") == hashes["controller"]
            and plan.get("controller_receipt_sha256") == hashes["controller_receipt"]
            and plan.get("claims") == CLAIMS
            and plan.get("acceptance_matrix") == ACCEPTANCE_MATRIX
            and plan.get("gate_started") is False
            and plan.get("gate_executed") is False,
            "plan-intent-controller-identity")
    auditor = plan.get("post_gate_audit")
    require(type(auditor) is dict
            and auditor.get("path")
                == str(reader.operation / files["auditor"]["path"])
            and auditor.get("sha256") == hashes["auditor"],
            "plan-auditor-source-identity")
    require(claim.get("plan_sha256") == hashes["plan"]
            and claim.get("intent_sha256") == hashes["intent"]
            and claim.get("controller_sha256") == hashes["controller"]
            and claim.get("gate_run_id") == run["gate_run_id"]
            and claim.get("argv") == run["argv"]
            and type(claim.get("pid")) is int and claim["pid"] > 0
            and claim.get("one_shot") is True
            and claim.get("gate_started") is False
            and claim.get("gate_executed") is False,
            "launch-claim-identity")
    require(launch.get("plan_sha256") == hashes["plan"]
            and launch.get("controller_sha256") == hashes["controller"]
            and launch.get("gate_run_id") == run["gate_run_id"]
            and launch.get("argv") == run["argv"]
            and launch.get("cwd") == run["cwd"]
            and launch.get("output") == run["output"]
            and launch.get("controller_pid") == claim["pid"]
            and launch.get("gate_started") is False
            and launch.get("gate_executed") is False,
            "launch-intent-identity")
    require(start.get("plan_sha256") == hashes["plan"]
            and start.get("controller_sha256") == hashes["controller"]
            and start.get("gate_run_id") == run["gate_run_id"]
            and start.get("argv") == run["argv"]
            and start.get("cwd") == run["cwd"]
            and start.get("output") == run["output"]
            and start.get("controller_pid") == claim["pid"]
            and type(start.get("pid")) is int and start["pid"] > 0
            and start.get("process_group_id") == start["pid"]
            and start.get("status") == "running",
            "gate-start-identity")
    require(end.get("pid") == start["pid"]
            and end.get("gate_run_id") == run["gate_run_id"]
            and end.get("controller_pid") == claim["pid"]
            and end.get("process_group_id") == start["process_group_id"]
            and type(end.get("returncode")) is int and end["returncode"] == 0
            and end.get("gate_started") is True and end.get("gate_executed") is True
            and end.get("reaped_by_wait") is True
            and end.get("process_group_gone") is True
            and end.get("terminal_status") == "gate_process_completed"
            and end.get("claims") == CLAIMS
            and end.get("stdout_sha256") == hashes["gate_stdout"]
            and end.get("stderr_sha256") == hashes["gate_stderr"],
            "gate-end-identity")
    require(end.get("branch_result_sha256") == {
                name: identity["evidence_files"][name]["sha256"]
                for name in _BRANCH_IDENTITY_FILES},
            "terminal-branch-result-identity")
    require(end.get("summary_sha256") == identity["evidence_files"]["summary"]["sha256"],
            "terminal-summary-identity")
    summary = reader.document("evidence", "summary.json.gz", compressed=True)
    require(type(summary) is dict
            and summary.get("schema_version") == "native_online_directed_gate.v1"
            and summary.get("gate_run_id") == run["gate_run_id"]
            and type(summary.get("gate_pid")) is int
            and summary["gate_pid"] == start["pid"],
            "summary-run-identity")
    branch_status = {
        name: reader.branch_document(name, "result.json.gz", compressed=True).get("status")
        for name in _BRANCH_IDENTITY_FILES}
    require(summary.get("positive_status") == branch_status["positive"]
            == "bounded_directed_gate_passed"
            and summary.get("controlled_status") == branch_status["controlled-response"]
            == "bounded_directed_gate_passed"
            and summary.get("native_source_refusal_status")
                == branch_status["native-source-refusal"]
                == "native_source_completion_refusal_gate_passed"
            and summary.get("native_completion_observation") is True
            and summary.get("native_source_binding") is True
            and summary.get("native_source_completion") is True
            and summary.get("script_sha256") == hashes["gate_script"]
            and all(summary.get(name) is False for name in CLAIMS),
            "summary-branch-status-identity")
    require(source_post.get("status") == "source_tree_manifest_match"
            and source_post.get("matches_preflight") is True
            and source_post.get("claims") == CLAIMS,
            "source-postflight-identity")
    if "source_manifest_sha256" in source_post:
        require(source_post["source_manifest_sha256"] == hashes["source_manifest"],
                "source-postflight-manifest-identity")
    require(lock_post.get("status") == "match"
            and lock_post.get("matches_preflight") is True
            and lock_post.get("expected") == lock_post.get("observed")
            and type(lock_post.get("expected")) is dict
            and lock_post["expected"].get("path") == run["heavy_lock"]
            and lock_post.get("claims") == CLAIMS,
            "lock-postflight-identity")
    gate_end_reference = post.get("gate_end_sha256")
    if gate_end_reference is None:
        gate_end_reference = (post.get("gate_end_receipt") or {}).get("sha256")
    postflight = post.get("postflight_receipts")
    require(type(postflight) is dict
            and postflight.get("source_tree") == {
                "path": str(reader.operation / files["source_postflight"]["path"]),
                "sha256": hashes["source_postflight"]}
            and postflight.get("canonical_lock") == {
                "path": str(reader.operation / files["lock_postflight"]["path"]),
                "sha256": hashes["lock_postflight"]},
            "post-run-postflight-identity")
    require(post.get("gate_end") == end
            and post.get("gate_run_id") == run["gate_run_id"]
            and gate_end_reference == hashes["gate_end"]
            and post.get("plan_sha256") == hashes["plan"]
            and post.get("controller_sha256") == hashes["controller"]
            and type(post.get("gate_returncode")) is int
            and post["gate_returncode"] == 0
            and post.get("gate_started") is True
            and post.get("gate_executed") is True
            and post.get("process_group_gone") is True
            and post.get("output_created_by_gate") is True
            and post.get("source_tree_matches_preflight") is True
            and post.get("protected_baselines_match_preflight") is True
            and post.get("submodules_match_preflight") is True
            and post.get("canonical_lock_matches_preflight") is True
            and post.get("terminal_status") == "completed"
            and post.get("claims") == CLAIMS,
            "post-run-identity")
    return {"schema_version": "task5_gate_terminal_audit.v1",
            "status": "passed", "returncode": 0,
            "gate_run_id": run["gate_run_id"], "gate_pid": start["pid"],
            "gate_end_sha256": hashes["gate_end"],
            "plan_sha256": hashes["plan"],
            "controller_sha256": hashes["controller"],
            "source_manifest_sha256": hashes["source_manifest"],
            "tool_freeze_sha256": identity["workspace_files"]["tool_freeze"]["sha256"],
            "source_manifest_verified_entries": len(source_paths),
            "source_manifest_entries_verified": True,
            "source_tree_closure_verified": False,
            "workspace_tool_bytes_verified": sorted(checked_workspace_tools),
            "external_tool_bytes_verified": False,
            "gate_executable_identity_verified": False}


def _remove_report_leaf(directory_fd, created_info):
    """Remove the audit output only if its current inode is ours."""
    if created_info is None:
        return []
    try:
        current = os.stat(AUDIT_OUTPUT_RELATIVE_PATH,
                          dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return []
    except BaseException as exc:
        return ["stat:" + type(exc).__name__]
    if (not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino)
                != (created_info.st_dev, created_info.st_ino)):
        return ["output-leaf-not-owned-inode"]
    try:
        os.unlink(AUDIT_OUTPUT_RELATIVE_PATH, dir_fd=directory_fd)
        os.fsync(directory_fd)
        return []
    except BaseException as exc:
        return ["unlink:" + type(exc).__name__]


def _remove_report_leaf_by_root(root, root_info, created_info):
    directory_fd = None
    errors = []
    try:
        directory_fd = _open_directory_path(root)
        opened = os.fstat(directory_fd)
        if (not stat.S_ISDIR(opened.st_mode)
                or (opened.st_dev, opened.st_ino)
                    != (root_info.st_dev, root_info.st_ino)):
            return ["output-parent-identity-changed"]
        errors.extend(_remove_report_leaf(directory_fd, created_info))
    except BaseException as exc:
        errors.append("reopen-parent:" + type(exc).__name__)
    finally:
        if directory_fd is not None:
            try:
                os.close(directory_fd)
            except BaseException as exc:
                errors.append("close-parent:" + type(exc).__name__)
    return errors


def _failed_report_bytes(code):
    fallback = {
        "schema_version": SCHEMA,
        "status": "failed",
        "operation_dir": None,
        "evidence_dir": None,
        "output_file": None,
        "inputs": {},
        "input_limits_bytes": {"compressed": MAX_INPUT_FILE_BYTES,
                                "expanded_gzip": MAX_GZIP_UNCOMPRESSED_BYTES},
        "findings": [{"phase": "report-write", "type": "AuditError",
                      "code": code}],
        "false_claims": dict(FALSE_CLAIMS),
        "branch_audits": {},
    }
    return json.dumps(fallback, sort_keys=True, indent=2, ensure_ascii=False,
                      allow_nan=False).encode("utf-8") + b"\n"


def _write_failed_report_fd(fd, created_info, code):
    """Best-effort downgrade through the already opened inode, without path races."""
    try:
        opened = os.fstat(fd)
        require(stat.S_ISREG(opened.st_mode)
                and created_info is not None
                and (opened.st_dev, opened.st_ino)
                    == (created_info.st_dev, created_info.st_ino),
                "failed-report-fd-identity-changed")
        data = _failed_report_bytes(code)
        os.fchmod(fd, 0o600)
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        offset = 0
        while offset < len(data):
            count = os.write(fd, data[offset:])
            if count <= 0:
                raise OSError("zero-length failure report write")
            offset += count
        rewritten = os.fstat(fd)
        require(rewritten.st_size == len(data), "failed-report-size-mismatch")
        os.fsync(fd)
        return []
    except BaseException as exc:
        return ["rewrite-inode-failed:" + type(exc).__name__]


def _replace_report_with_failed(directory_fd, created_info, code):
    """Downgrade our report inode if safe unlink failed after publication."""
    if created_info is None:
        return ["created-inode-unknown"]
    fd = None
    try:
        current = os.stat(AUDIT_OUTPUT_RELATIVE_PATH,
                          dir_fd=directory_fd, follow_symlinks=False)
        require(stat.S_ISREG(current.st_mode)
                and (current.st_dev, current.st_ino)
                    == (created_info.st_dev, created_info.st_ino),
                "failed-report-leaf-identity-changed")
        fd = os.open(AUDIT_OUTPUT_RELATIVE_PATH,
                     os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=directory_fd)
        errors = _write_failed_report_fd(fd, created_info, code)
        if errors:
            return errors
        os.fsync(directory_fd)
        return []
    except BaseException as exc:
        return ["rewrite-failed:" + type(exc).__name__]
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except BaseException:
                pass


def _replace_report_with_failed_by_root(root, root_info, created_info, code):
    directory_fd = None
    try:
        directory_fd = _open_directory_path(root)
        opened = os.fstat(directory_fd)
        require(stat.S_ISDIR(opened.st_mode)
                and (opened.st_dev, opened.st_ino)
                    == (root_info.st_dev, root_info.st_ino),
                "failed-report-parent-identity-changed")
        return _replace_report_with_failed(directory_fd, created_info, code)
    except BaseException as exc:
        return ["rewrite-parent-failed:" + type(exc).__name__]
    finally:
        if directory_fd is not None:
            try:
                os.close(directory_fd)
            except BaseException:
                pass


def _close_report_fd_checked(fd, expected_info, *, directory):
    opened = os.fstat(fd)
    if directory:
        require(stat.S_ISDIR(opened.st_mode)
                and (opened.st_dev, opened.st_ino)
                    == (expected_info.st_dev, expected_info.st_ino),
                "report-parent-fd-identity-changed")
    else:
        require(stat.S_ISREG(opened.st_mode)
                and (opened.st_dev, opened.st_ino)
                    == (expected_info.st_dev, expected_info.st_ino),
                "report-output-fd-identity-changed")
    os.close(fd)


def _close_report_fd_if_owned(fd, expected_info, *, directory):
    if fd is None or expected_info is None:
        return
    try:
        opened = os.fstat(fd)
        owned = ((stat.S_ISDIR(opened.st_mode)
                  and (opened.st_dev, opened.st_ino)
                      == (expected_info.st_dev, expected_info.st_ino))
                 if directory else
                 (stat.S_ISREG(opened.st_mode)
                  and (opened.st_dev, opened.st_ino)
                      == (expected_info.st_dev, expected_info.st_ino)))
        if owned:
            os.close(fd)
    except BaseException:
        # The descriptor may already be closed. Never retry close by number
        # unless fstat proved that it still names the inode acquired here.
        pass


def _rollback_report(root, root_info, created_info, code):
    errors = _remove_report_leaf_by_root(root, root_info, created_info)
    if not errors:
        return []
    rewrite_errors = _replace_report_with_failed_by_root(
        root, root_info, created_info, code)
    if not rewrite_errors:
        return []
    return errors + rewrite_errors


def write_report(output, evidence_root, report):
    raw_output = Path(output)
    root = Path(evidence_root)
    require(".." not in raw_output.parts and ".." not in root.parts,
            "output-parent-traversal")
    path = raw_output.absolute()
    root = root.absolute()
    require(str(path) == str(root / AUDIT_OUTPUT_RELATIVE_PATH),
            "output-path-must-match-frozen-audit-leaf")
    require(path.parent == root and AUDIT_OUTPUT_RELATIVE_PATH not in ("", ".", ".."),
            "output-must-be-new-evidence-leaf")
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise AuditError("output-evidence-root-unavailable") from exc
    require(stat.S_ISDIR(root_info.st_mode) and not stat.S_ISLNK(root_info.st_mode),
            "output-evidence-root-not-directory")
    require(root_info.st_uid == os.geteuid()
            and not (stat.S_IMODE(root_info.st_mode) & 0o022),
            "output-evidence-root-not-private-writable")
    try:
        data = json.dumps(report, sort_keys=True, indent=2,
                          ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise AuditError("report-json-serialization:" + type(exc).__name__) from exc
    require(hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW")
            and hasattr(os, "O_TMPFILE") and hasattr(os, "O_CLOEXEC"),
            "output-anonymous-no-follow-open-unavailable")
    directory_fd = None
    fd = None
    created_info = None
    try:
        directory_fd = _open_directory_path(root)
        opened_root = os.fstat(directory_fd)
        require(stat.S_ISDIR(opened_root.st_mode)
                and opened_root.st_dev == root_info.st_dev
                and opened_root.st_ino == root_info.st_ino,
                "output-evidence-root-changed")
        # O_TMPFILE keeps all incomplete bytes unnamed. AT_EMPTY_PATH hard-links
        # the fully written inode to the final leaf without replacing anything.
        fd = os.open(".", os.O_WRONLY | os.O_CLOEXEC | os.O_TMPFILE,
                     0o600, dir_fd=directory_fd)
        os.fchmod(fd, 0o600)
        created_info = os.fstat(fd)
        require(stat.S_ISREG(created_info.st_mode) and created_info.st_nlink == 0
                and stat.S_IMODE(created_info.st_mode) == 0o600,
                "output-anonymous-leaf-not-private-regular-file")
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise OSError("zero-length report write")
            offset += written
        os.fsync(fd)
        linkat = getattr(ctypes.CDLL(None, use_errno=True), "linkat", None)
        require(linkat is not None, "output-linkat-unavailable")
        linkat.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                           ctypes.c_char_p, ctypes.c_int)
        linkat.restype = ctypes.c_int
        result = linkat(fd, b"", directory_fd,
                        AUDIT_OUTPUT_RELATIVE_PATH.encode("ascii"), 0x1000)
        if result != 0:
            error_number = ctypes.get_errno()
            raise OSError(error_number, os.strerror(error_number),
                          AUDIT_OUTPUT_RELATIVE_PATH)
        published_info = os.stat(AUDIT_OUTPUT_RELATIVE_PATH,
                                 dir_fd=directory_fd, follow_symlinks=False)
        require(stat.S_ISREG(published_info.st_mode)
                and (published_info.st_dev, published_info.st_ino)
                    == (created_info.st_dev, created_info.st_ino)
                and stat.S_IMODE(published_info.st_mode) == 0o600,
                "output-published-leaf-identity-mismatch")
        os.fsync(directory_fd)
        _close_report_fd_checked(fd, created_info, directory=False)
        fd = None
        _close_report_fd_checked(directory_fd, root_info, directory=True)
        directory_fd = None
        return path
    except BaseException as original_error:
        cleanup_errors = []
        if root_info is not None and created_info is not None:
            try:
                cleanup_errors = _rollback_report(
                    root, root_info, created_info, "report-write-rollback-failed")
            except BaseException as cleanup_error:
                cleanup_errors = ["rollback:" + type(cleanup_error).__name__]
        _close_report_fd_if_owned(fd, created_info, directory=False)
        _close_report_fd_if_owned(directory_fd, root_info, directory=True)
        if cleanup_errors:
            raise AuditError("report-write-rollback-failed:"
                             + ",".join(cleanup_errors)) from original_error
        if isinstance(original_error, AuditError):
            raise
        if isinstance(original_error, OSError):
            raise AuditError("report-write-failed:"
                             + type(original_error).__name__) from original_error
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operation-dir", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--workspace-dir", required=True, type=Path)
    parser.add_argument("--identity-manifest", required=True,
                        help="relative path to the frozen manifest under operation-dir")
    parser.add_argument("--identity-sha256", required=True,
                        help="independently pinned SHA-256 of the manifest bytes")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    report = {
        "schema_version": SCHEMA,
        "status": "failed",
        "operation_dir": str(args.operation_dir.absolute()),
        "evidence_dir": str(args.evidence_dir.absolute()),
        "workspace_dir": str(args.workspace_dir.absolute()),
        "output_file": str(args.output.absolute()),
        "identity_manifest": args.identity_manifest,
        "identity_sha256": args.identity_sha256,
        "inputs": {},
        "input_limits_bytes": {"compressed": MAX_INPUT_FILE_BYTES,
                                "expanded_gzip": MAX_GZIP_UNCOMPRESSED_BYTES},
        "findings": [],
        "false_claims": dict(FALSE_CLAIMS),
        "branch_audits": {},
    }
    reader = None
    phase = "input-roots"
    try:
        reader = Reader(args.operation_dir, args.evidence_dir, args.workspace_dir)
        phase = "identity-manifest"
        identity = load_audit_identity(
            reader, args.identity_manifest, args.identity_sha256)
        phase = "operation-terminal"
        report["operation_terminal"] = operation_terminal_audit(reader, identity)
        gate_start = {"pid": report["operation_terminal"]["gate_pid"]}
        for branch, kwargs in (
            ("positive", {}),
            ("controlled-response", {"controlled": True}),
            ("native-source-refusal", {"refusal": True}),
        ):
            phase = branch
            report["branch_audits"][branch] = audit_branch(
                reader, branch, identity=identity, gate_start=gate_start, **kwargs)
        report["status"] = "passed"
    except Exception as error:
        report["findings"].append({"phase": phase, "type": type(error).__name__,
                                   "code": (str(error) if isinstance(error, AuditError)
                                            else "unexpected-" + type(error).__name__)})
    finally:
        if reader is not None:
            report["inputs"] = reader.inputs
    try:
        write_report(args.output, args.evidence_dir.absolute(), report)
    except AuditError as error:
        if str(error).startswith("report-json-serialization:"):
            fallback = {
                "schema_version": SCHEMA,
                "status": "failed",
                "operation_dir": str(args.operation_dir.absolute()),
                "evidence_dir": str(args.evidence_dir.absolute()),
                "output_file": str(args.output.absolute()),
                "inputs": {},
                "input_limits_bytes": {"compressed": MAX_INPUT_FILE_BYTES,
                                        "expanded_gzip": MAX_GZIP_UNCOMPRESSED_BYTES},
                "findings": [{"phase": "report-serialization",
                              "type": "AuditError", "code": str(error)}],
                "false_claims": dict(FALSE_CLAIMS),
                "branch_audits": {},
            }
            try:
                write_report(args.output, args.evidence_dir.absolute(), fallback)
                return 1
            except (AuditError, OSError):
                print("audit-failure-report-unwritable", file=sys.stderr)
                return 2
        print("audit-report-unwritable:" + str(error), file=sys.stderr)
        return 2
    except OSError:
        print("audit-report-unwritable:OSError", file=sys.stderr)
        return 2
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
