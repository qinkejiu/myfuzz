"""R11 software admission boundaries; these tests never launch the real gate."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "scripts/task5_native_completion_r11"
CONTROLLER_PATH = PACKAGE / "r11-one-shot-controller.v1.py"
SPEC = importlib.util.spec_from_file_location("r11_filesystem_controller", CONTROLLER_PATH)
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


@contextmanager
def directory_fd(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield fd
    finally:
        os.close(fd)


@pytest.mark.parametrize("path", ["", ".", "..", "../escape", "a/../b",
                                      "/absolute", "a//b", "a/./b", "a/"])
def test_noncanonical_relative_paths_are_refused(path):
    with pytest.raises(C.Refusal, match="path:"):
        C.components(path)


def test_two_claim_writers_have_exactly_one_durable_winner(tmp_path):
    (tmp_path / "control").mkdir()
    barrier = threading.Barrier(2)
    with directory_fd(tmp_path) as fd:
        def write_claim(writer):
            barrier.wait(timeout=3)
            try:
                C.write_json(fd, C.OUTPUTS["claim"], {"writer": writer})
            except FileExistsError:
                return "already_claimed"
            return writer

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(write_claim, (1, 2)))
        assert results.count("already_claimed") == 1
        winner = next(item for item in results if type(item) is int)
        raw, observed = C.read_file(fd, C.OUTPUTS["claim"])
    assert json.loads(raw) == {"writer": winner}
    assert stat.S_IMODE(observed.st_mode) == 0o600
    assert observed.st_nlink == 1


@pytest.mark.parametrize("parent_symlink", [False, True])
def test_reads_and_exclusive_writes_do_not_follow_symlinks(tmp_path, parent_symlink):
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_bytes(b"preserve")
    operation = tmp_path / "operation"
    operation.mkdir()
    if parent_symlink:
        (operation / "linked").symlink_to(outside, target_is_directory=True)
        relative = "linked/sentinel"
    else:
        (operation / "linked").symlink_to(sentinel)
        relative = "linked"
    with directory_fd(operation) as fd:
        with pytest.raises(OSError):
            C.read_file(fd, relative)
        with pytest.raises(OSError):
            C.write_exclusive(fd, relative, b"changed")
    assert sentinel.read_bytes() == b"preserve"


def test_hardlinked_regular_input_is_refused(tmp_path):
    (tmp_path / "payload").write_bytes(b"x")
    os.link(tmp_path / "payload", tmp_path / "alias")
    with directory_fd(tmp_path) as fd:
        with pytest.raises(C.Refusal, match="file:type-or-links"):
            C.read_file(fd, "payload")
        with pytest.raises(C.Refusal, match="snapshot:file-links"):
            C.scan_tree(fd)


@pytest.mark.parametrize("target", ["../outside", "/absolute/outside"])
def test_tree_inventory_rejects_escaping_symlinks(tmp_path, target):
    (tmp_path / "link").symlink_to(target)
    with directory_fd(tmp_path) as fd:
        with pytest.raises(C.Refusal, match="snapshot:symlink-"):
            C.scan_tree(fd)


def test_tree_inventory_preserves_internal_symlink_and_file_identity(tmp_path):
    (tmp_path / "payload").write_bytes(b"abc")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested/link").symlink_to("../payload")
    with directory_fd(tmp_path) as fd:
        rows = C.scan_tree(fd)
    indexed = {row["path"]: row for row in rows}
    assert list(indexed) == sorted(indexed)
    assert indexed["nested/link"]["target"] == "../payload"
    assert indexed["payload"]["size"] == 3
    assert indexed["payload"]["sha256"] == hashlib.sha256(b"abc").hexdigest()


def test_oversize_sparse_input_is_refused_without_reading(tmp_path, monkeypatch):
    with (tmp_path / "payload").open("wb") as handle:
        handle.truncate(C.MAX_JSON_BYTES + 1)
    def unexpected_read(*args, **kwargs):
        pytest.fail("oversized input reached read")
    monkeypatch.setattr(C.os, "read", unexpected_read)
    with directory_fd(tmp_path) as fd:
        with pytest.raises(C.Refusal, match="file:type-or-links"):
            C.read_file(fd, "payload")
        with pytest.raises(C.Refusal, match="snapshot:file-oversize"):
            C.scan_tree(fd)


def test_stream_growth_is_refused_before_oversize_block_is_hashed(tmp_path, monkeypatch):
    payload = tmp_path / "payload"
    payload.write_bytes(b"abcd")
    original_read = os.read
    hashed_blocks = []
    hasher = hashlib.sha256()
    class RecordingHasher:
        def update(self, block):
            hashed_blocks.append(block)
            hasher.update(block)
        def hexdigest(self):
            return hasher.hexdigest()
    first = True
    def growing_read(fd, size):
        nonlocal first
        data = original_read(fd, size)
        if first and data:
            first = False
            with payload.open("ab") as handle:
                handle.write(b"e")
        return data
    monkeypatch.setattr(C, "hashlib", SimpleNamespace(sha256=RecordingHasher))
    monkeypatch.setattr(C.os, "read", growing_read)
    with directory_fd(tmp_path) as fd:
        with pytest.raises(C.Refusal, match="snapshot:file-grew-oversize"):
            C.scan_tree(fd, max_file_size=4)
    assert hashed_blocks == [b"abcd"]


def test_exact_limit_is_allowed_and_protected_digest_scan_can_be_uncapped(tmp_path):
    (tmp_path / "payload").write_bytes(b"abcd")
    with directory_fd(tmp_path) as fd:
        assert C.scan_tree(fd, max_file_size=4)[1]["size"] == 4
        with pytest.raises(C.Refusal, match="snapshot:file-oversize"):
            C.scan_tree(fd, max_file_size=3)
        assert C.scan_tree(fd, max_file_size=None)[1]["size"] == 4


@pytest.mark.parametrize("race", [False, True], ids=["initial-fifo", "regular-to-fifo"])
def test_fifo_input_cannot_block_admission(tmp_path, race):
    # Run the syscall regression in our own disposable child so a broken open
    # yields a bounded test failure rather than hanging the entire test runner.
    code = r'''
import importlib.util, os, pathlib, sys
spec=importlib.util.spec_from_file_location("fifo_controller", sys.argv[1])
c=importlib.util.module_from_spec(spec); spec.loader.exec_module(c)
root=pathlib.Path(sys.argv[2]); race=sys.argv[3]=="True"
payload=root/"payload"
if race:
    payload.write_bytes(b"x")
    original_open=c.os.open
    def swap_open(path, flags, *args, **kwargs):
        if path=="payload":
            payload.unlink(); os.mkfifo(payload)
        return original_open(path, flags, *args, **kwargs)
    c.os.open=swap_open
else:
    os.mkfifo(payload)
fd=c.open_dir(str(root))
try:
    try:
        c.scan_tree(fd) if race else c.read_file(fd,"payload")
    except c.Refusal as exc:
        print(str(exc)); sys.exit(0)
    raise AssertionError("FIFO admitted")
finally:
    os.close(fd)
'''
    completed = subprocess.run(
        [sys.executable, "-B", "-c", code, str(CONTROLLER_PATH), str(tmp_path), str(race)],
        capture_output=True, text=True, timeout=5, check=True)
    assert ("snapshot:file-race" if race else "file:type-or-links") in completed.stdout


@pytest.fixture
def static_package(tmp_path):
    (tmp_path / "control").mkdir()
    manifest = json.loads((PACKAGE / "r11-static-code-manifest.v1.json").read_bytes())
    for row in manifest["entries"]:
        (tmp_path / "control" / row["path"]).write_bytes((PACKAGE / row["path"]).read_bytes())
    return tmp_path, manifest, (PACKAGE / "r11-gate-script.v1.py").read_bytes()


def test_actual_stage1_package_joins_selected_gate_and_control_copies(static_package):
    operation, manifest, gate = static_package
    with directory_fd(operation) as fd:
        rows = C.static_code_manifest_check(fd, C.canonical(manifest), gate)
    assert tuple(rows) == C.STAGE1_ARTIFACTS


@pytest.mark.parametrize("change,code", [
    ("missing", "runtime-copy-missing"),
    ("tampered", "runtime-copy-mismatch"),
    ("gate", "gate-stage1-stage2"),
    ("order", "inventory"),
    ("dynamic", "shape"),
    ("self", "shape"),
])
def test_static_manifest_refuses_missing_drifted_or_dynamic_members(static_package, change, code):
    operation, manifest, gate = static_package
    if change == "missing":
        (operation / "control/r11-plan-schema.v1.json").unlink()
    elif change == "tampered":
        (operation / "control/r11-external-launch-contract.v1.json").write_bytes(b"{}")
    elif change == "gate":
        gate += b"# drift\n"
    elif change == "order":
        manifest["entries"].reverse()
    else:
        manifest["entries"].append({"path": ("control/source-snapshot-postflight.v1.json"
                                            if change == "dynamic" else
                                            "r11-static-code-manifest.v1.json"),
                                   "size": 0, "sha256": "0" * 64})
    with directory_fd(operation) as fd:
        with pytest.raises(C.Refusal, match="static-code-manifest:.*" + code):
            C.static_code_manifest_check(fd, C.canonical(manifest), gate)


def test_tool_file_requires_exact_stage2_row_and_tools_location(tmp_path):
    (tmp_path / "tools").mkdir()
    tool = tmp_path / "tools/python3"
    tool.write_bytes(b"pinned executable")
    tool.chmod(0o700)
    with directory_fd(tmp_path) as fd:
        rows = {row["path"]: row for row in C.scan_tree(fd)}
    C.stage2_member(str(tmp_path), rows, str(tool), "file", "tool", executable=True)
    tool.write_bytes(b"changed executable")
    with pytest.raises(C.Refusal, match="tool:stage2-file"):
        C.stage2_member(str(tmp_path), rows, str(tool), "file", "tool", executable=True)
    with pytest.raises(C.Refusal, match="tool:outside-tools"):
        C.stage2_member(str(tmp_path), rows, str(tmp_path / "project/python3"), "file", "tool")


def test_run_identity_rejects_changed_id_flags_paths_and_extra_fields():
    workspace = "/workspace"
    operation = workspace + "/operations/r11"
    evidence = workspace + "/evidence/r11"
    run_id = "a" * 64
    run = {"argv": ["python3", "-B", operation + "/" + C.INPUTS["gate_script"],
                    "--output", evidence, "--cache-dir", operation + "/native-cache",
                    "--heavy-lock", workspace + "/.superpowers/heavy-worker.lock",
                    "--gate-run-id", run_id, *C.FLAGS],
           "cwd": operation + "/project", "output": evidence,
           "cache_dir": operation + "/native-cache",
           "heavy_lock": workspace + "/.superpowers/heavy-worker.lock",
           "gate_run_id": run_id, "requested_gate_flags": list(C.FLAGS),
           "requested_gates": list(C.GATES)}
    assert C.validate_run(run, operation, evidence, workspace) == run_id
    changes = [{"gate_run_id": "b" * 64}, {"requested_gate_flags": list(reversed(C.FLAGS))},
               {"cwd": workspace}, {"unexpected": True}, {"gate_run_id": "A" * 64}]
    for change in changes:
        mutated = copy.deepcopy(run)
        mutated.update(change)
        with pytest.raises(C.Refusal, match="run:"):
            C.validate_run(mutated, operation, evidence, workspace)
