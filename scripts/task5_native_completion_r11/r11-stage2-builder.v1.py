#!/usr/bin/env python3
"""Build one local r11 Stage 2 operation package from a clean Git HEAD.

The builder never runs the gate, the controller, or the auditor.  It materialises
the selected source bytes (the committed HEAD tree plus the one checked-out
gitlink the selected native-source gate reads), a workspace-local Python
runtime/tool closure, the pinned Stage 1 code copies, and the frozen
intent/plan/controller-receipt documents under ``<operation>/control``.  The
Stage 2 manifest is then produced from a live no-follow inventory of the
operation root.

All recorded absolute paths are target-workspace paths (by default
``/root/fanzehui/myfuzz``).  The package may therefore be built inside a local
mirror of that workspace and later copied/uploaded byte-for-byte to the target
without rewriting any recorded identity.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

sys.dont_write_bytecode = True

TARGET_WORKSPACE = "/root/fanzehui/myfuzz"
TARGET_SYSTEM = "/root/fanzehui/system-20261016"
STAGE1 = ("r11-external-launch-contract.v1.json", "r11-gate-script.v1.py",
          "r11-independent-auditor.v1.py", "r11-one-shot-controller.v1.py",
          "r11-plan-schema.v1.json", "r11-post-gate-audit-runner.v1.py",
          "r11-source-byte-bootstrap.v1.py")
FLAGS = ["--native-completion-observation", "--native-source-binding",
         "--native-source-completion"]
GATES = ["native_completion_observation", "native_source_binding",
         "native_source_completion"]
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
TASK5_FILES = (
    "configs/cpus/picorv32/component_profile.json",
    "scripts/verifier/native_completion_gate_checks.py",
    "scripts/verify_picorv32_native_online.py",
    "src/myfuzz/integration/picorv32_native_online.py",
    "src/myfuzz/local_harness/session.py",
    "src/myfuzz/scenario/contracts.py",
    "src/myfuzz/scenario/native_packet_session.py",
    "src/myfuzz/scenario/picorv32_native_cpu_example.py",
    "src/myfuzz/scenario/picorv32_native_online.py",
    "src/myfuzz/scenario/session_runtime.py",
    "third_party/picorv32_upstream_reference/picorv32.v",
)
DEFAULT_EXCLUSIONS = {
    "docs": "report/evidence archive (454 MiB of prior evidence tarballs and logs); no selected native-source gate input",
    ".superpowers": "progress/checkpoint state, not a source or execution input for the selected gate",
    "examples": "sample scenario bundles, not part of the selected gate execution closure",
    "runs": "saved run outputs, not source input for the selected gate",
}
ABSENT_LEAVES = (
    "control/claim.v1.json", "control/launch-intent.v1.json",
    "control/gate-start.v1.json", "control/gate-end.v1.json",
    "control/post-run-integrity.v1.json", "control/source-postflight.v1.json",
    "control/source-snapshot-postflight.v1.json",
    "control/lock-postflight.v1.json", "control/gate.stdout.log",
    "control/gate.stderr.log", "control/protected-baselines-preflight.v1.json",
    "control/protected-baselines-postflight.v1.json",
    "control/submodules-preflight.v1.json",
    "control/submodules-postflight.v1.json", "control/audit-identity.v1.json",
    "native-cache",
)
STDLIB_SKIP = {"sitecustomize.py", "config-3.12-x86_64-linux-gnu"}


class BuildError(Exception):
    pass


def need(ok, message):
    if not ok:
        raise BuildError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def jbytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def write_new(path, raw, mode=0o644):
    parent = os.path.dirname(path)
    if not os.path.isdir(parent):
        os.makedirs(parent, mode=0o755, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(fd, raw[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(path, mode)


def write_json(path, value, mode=0o644):
    raw = jbytes(value)
    write_new(path, raw, mode)
    return sha(raw)


def read_bytes(path):
    with open(path, "rb") as stream:
        return stream.read()


def copy_file(source, target, mode=0o644):
    raw = read_bytes(source)
    write_new(target, raw, mode)
    return raw


def run_git(repo, *args, timeout=300):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("GIT_")}
    env.update({"GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1",
                "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull})
    result = subprocess.run(["git", "-C", repo, *args], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env, timeout=timeout,
                            check=False)
    need(result.returncode == 0,
         "git %s failed: %s" % (args[0], result.stderr.decode("utf-8", "replace")[:400]))
    return result.stdout


def git_archive(repo, treeish, destination, exclude=()):
    """Extract one Git tree into destination without Git metadata."""
    archive = os.path.join(tempfile.mkdtemp(prefix="r11-archive-"), "tree.tar")
    command = ["archive", "--format=tar", treeish, "--"]
    command.extend([":(exclude)" + path for path in exclude] or ["."])
    with open(archive, "wb") as stream:
        result = subprocess.run(["git", "-C", repo, *command], stdout=stream,
                                stderr=subprocess.PIPE, check=False)
    need(result.returncode == 0, "git archive failed: %s" %
         result.stderr.decode("utf-8", "replace")[:400])
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        for member in members:
            name = member.name
            need(not name.startswith("/") and ".." not in name.split("/"),
                 "unsafe archive member: " + name)
        tar.extractall(destination, filter="fully_trusted")
    shutil.rmtree(os.path.dirname(archive), ignore_errors=True)


def materialise_submodule(repo, path, commit, destination):
    sub = os.path.join(repo, *path.split("/"))
    need(os.path.isdir(sub), "missing submodule checkout: " + path)
    run_git(sub, "cat-file", "-e", commit + "^{commit}")
    os.makedirs(destination, mode=0o755, exist_ok=True)
    os.chmod(destination, 0o755)
    git_archive(sub, commit, destination)


def load_controller(repo):
    path = os.path.join(repo, "scripts", "task5_native_completion_r11",
                        "r11-one-shot-controller.v1.py")
    spec = importlib.util.spec_from_file_location("_r11_frozen_controller_build", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def scan(controller, path):
    fd = controller.open_dir(path)
    try:
        return controller.scan_tree(fd)
    finally:
        os.close(fd)


def ldd_files(binary):
    result = subprocess.run(["ldd", binary], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, check=False)
    paths = set()
    for line in result.stdout.decode("utf-8", "replace").splitlines():
        if "=>" in line:
            candidate = line.split("=>", 1)[1].strip().split(" ")[0]
        else:
            candidate = line.strip().split(" ")[0]
        if candidate.startswith("/") and os.path.isfile(candidate):
            paths.add(os.path.realpath(candidate))
    return paths


def copy_runtime(operation, python_bin, python_lib):
    tools = operation + "/tools"
    os.makedirs(tools, mode=0o755)
    os.chmod(tools, 0o755)
    bin_sha = sha(read_bytes(os.path.realpath(python_bin)))
    for leaf in ("python3", "python3-controller", "python3-auditor"):
        copy_file(os.path.realpath(python_bin), tools + "/" + leaf, 0o755)
        need(sha(read_bytes(tools + "/" + leaf)) == bin_sha, "interpreter copy changed")
    libdir = tools + "/lib"
    os.makedirs(libdir, mode=0o755)
    os.chmod(libdir, 0o755)
    loader = os.path.realpath("/lib64/ld-linux-x86-64.so.2")
    libraries = ldd_files(os.path.realpath(python_bin))
    for name in sorted(os.listdir(python_lib + "/lib-dynload")):
        path = python_lib + "/lib-dynload/" + name
        if name.endswith(".so") and os.path.isfile(path):
            libraries |= ldd_files(path)
    copied = []
    for path in sorted(libraries | {loader}):
        target = libdir + "/" + os.path.basename(path)
        if os.path.exists(target):
            need(sha(read_bytes(target)) == sha(read_bytes(path)),
                 "library basename collision: " + path)
            continue
        copy_file(path, target, 0o755)
        copied.append({"source": path, "path": target,
                       "sha256": sha(read_bytes(target))})
    home = tools + "/pythonlib"
    libdir_home = home + "/lib/python3.12"
    os.makedirs(libdir_home, mode=0o755)
    stdlib = 0
    for current, dirs, files in os.walk(python_lib):
        dirs[:] = sorted(name for name in dirs if name not in STDLIB_SKIP)
        relative = os.path.relpath(current, python_lib)
        target_dir = libdir_home if relative == "." else libdir_home + "/" + relative
        os.makedirs(target_dir, mode=0o755, exist_ok=True)
        os.chmod(target_dir, 0o755)
        for name in sorted(files):
            if relative == "." and name in STDLIB_SKIP:
                continue
            source = os.path.join(current, name)
            if not os.path.isfile(source):
                continue
            target = target_dir + "/" + name
            mode = 0o755 if os.stat(source).st_mode & 0o111 else 0o644
            copy_file(os.path.realpath(source), target, mode)
            stdlib += 1
    return {"binaries": [tools + "/python3", tools + "/python3-controller",
                         tools + "/python3-auditor"],
            "loader": loader, "libraries": copied, "stdlib_files": stdlib,
            "pythonlib": home, "python_lib_dir": libdir_home}


def build(args):
    repo = os.path.abspath(args.source_repo)
    head = run_git(repo, "rev-parse", args.head).decode().strip()
    need(len(head) in (40, 64), "invalid HEAD object id")
    need(os.path.isdir(repo), "missing source repository")
    need(not os.path.exists(args.stage2_root), "stage2 root already exists")
    need(type(args.gate_run_id) is str
         and re.fullmatch(r"[0-9a-f]{64}", args.gate_run_id) is not None,
         "--gate-run-id must be 64 lowercase hex")
    need(args.operation_id and "/" not in args.operation_id
         and args.operation_id not in (".", ".."), "invalid operation id")
    operation = TARGET_WORKSPACE + "/operations/" + args.operation_id
    evidence = TARGET_WORKSPACE + "/evidence/" + args.operation_id
    root = os.path.abspath(args.stage2_root)
    os.makedirs(root, mode=0o755)
    os.chmod(root, 0o755)
    os.makedirs(root + "/operations", mode=0o755)
    os.makedirs(root + "/evidence", mode=0o755)
    os.makedirs(root + "/.superpowers", mode=0o755)
    os.makedirs(root + "/project", mode=0o755)
    lock = root + "/.superpowers/heavy-worker.lock"
    write_new(lock, b"", 0o644)
    opdir = root + "/operations/" + args.operation_id
    os.makedirs(opdir, mode=0o755)
    project = opdir + "/project"
    os.makedirs(project, mode=0o755)
    os.chmod(project, 0o755)
    exclusions = dict(DEFAULT_EXCLUSIONS)
    for spec in args.exclude:
        path, _, reason = spec.partition("=")
        need(bool(path) and bool(reason), "invalid --exclude: " + spec)
        exclusions[path] = reason
    for path in exclusions:
        need(run_git(repo, "cat-file", "-e", head + ":" + path) is not None,
             "excluded path absent from HEAD: " + path)
    git_archive(repo, head, project, sorted(exclusions))
    for path in ("third_party/picorv32_upstream_reference",):
        commit = run_git(repo, "rev-parse", head + ":" + path).decode().strip()
        materialise_submodule(repo, path, commit, project + "/" + path)
    controller = load_controller(repo)
    entries = scan(controller, project)
    controller.validate_map_rows(entries)
    control = opdir + "/control"
    os.makedirs(control, mode=0o755)
    # Pinned Stage 1 copies.
    stage1_dir = os.path.join(repo, "scripts", "task5_native_completion_r11")
    static_raw = read_bytes(stage1_dir + "/r11-static-code-manifest.v1.json")
    static_manifest = json.loads(static_raw)
    need(static_manifest.get("schema_version") == "r11_static_code_manifest.v1"
         and sorted(row["path"] for row in static_manifest["entries"])
         == sorted(STAGE1), "static manifest inventory differs")
    stage1_sha = {}
    for name in STAGE1:
        raw, expected = read_bytes(stage1_dir + "/" + name), None
        for row in static_manifest["entries"]:
            if row["path"] == name:
                expected = row
        need(expected is not None and expected["size"] == len(raw)
             and expected["sha256"] == sha(raw),
             "Stage 1 artifact differs from its manifest row: " + name)
        stage1_sha[name] = sha(raw)
    for name in list(STAGE1) + ["r11-static-code-manifest.v1.json"]:
        copy_file(stage1_dir + "/" + name, control + "/" + name, 0o644)
    gate_script = project + "/scripts/verify_picorv32_native_online.py"
    need(read_bytes(gate_script) == read_bytes(stage1_dir + "/r11-gate-script.v1.py"),
         "HEAD gate script differs from frozen Stage 1 gate script")
    # Source snapshot map (static).
    map_document = {"schema_version": "r11_source_snapshot_map.v1",
                    "source_root": repo, "entries": entries,
                    "exclusions": [{"path": path, "kind": "directory",
                                    "reason": exclusions[path]}
                                   for path in sorted(exclusions)]}
    map_raw = jbytes(map_document)
    write_new(control + "/source-snapshot-map.v1.json", map_raw, 0o644)
    # Submodule manifest: every committed gitlink, selected projections from map.
    gitlinks = []
    for line in run_git(repo, "ls-tree", "-r", head).decode().splitlines():
        meta, _, path = line.partition("\t")
        fields = meta.split()
        if fields[0] == "160000":
            gitlinks.append((path, fields[2]))
    gitlinks.sort()
    materialised = {"third_party/picorv32_upstream_reference"}
    submodule_rows = []
    for path, commit in gitlinks:
        selected = [row for row in entries
                    if row["path"] == path or row["path"].startswith(path + "/")]
        if path in materialised:
            checkout, head_id = True, commit
        else:
            checkout, head_id = False, None
        submodule_rows.append({"path": path, "tracked_mode": "160000",
                               "gitlink_commit": commit,
                               "checked_out": checkout,
                               "checked_out_head": head_id,
                               "selected_entries_sha256": sha(
                                   controller.canonical_ascii(selected)),
                               "selected_entries_count": len(selected)})
    submodule_document = {"schema_version": "r11_submodule_manifest.v1",
                          "entries": submodule_rows}
    submodule_raw = jbytes(submodule_document)
    write_new(control + "/submodule-manifest.v1.json", submodule_raw, 0o644)
    # Compact auditor source manifest: every regular project file.
    source_rows = [{"path": "project/" + row["path"], "sha256": row["sha256"]}
                   for row in entries if row["kind"] == "file"]
    source_document = {"schema_version": "source_tree_manifest.v1",
                       "entries": source_rows}
    source_manifest_sha = write_json(control + "/source-manifest.v1.json",
                                     source_document, 0o644)
    seen = {row["path"] for row in source_rows}
    need("project/scripts/verify_picorv32_native_online.py" in seen,
         "gate script missing from source manifest")
    task5_rows = []
    for relative in sorted(TASK5_FILES):
        path = "project/" + relative
        need(path in seen, "task5 file missing from source manifest: " + path)
        for row in source_rows:
            if row["path"] == path:
                task5_rows.append({"path": relative, "sha256": row["sha256"]})
    need(len(task5_rows) == len(TASK5_FILES), "duplicate task5 file")
    # Workspace-local Python/tool closure.
    runtime = copy_runtime(opdir, args.python_bin, args.python_lib)
    def target(local):
        need(local == opdir or local.startswith(opdir + "/"),
             "local path outside operation: " + local)
        return operation + local[len(opdir):]
    tool_rows = {"python3": {"path": operation + "/tools/python3",
                             "sha256": sha(read_bytes(opdir + "/tools/python3"))}}
    write_json(control + "/tool-freeze.v1.json", tool_rows, 0o644)
    tool_freeze_sha = sha(read_bytes(control + "/tool-freeze.v1.json"))
    closure = [
        {"path": operation + "/tools/python3", "sha256": tool_rows["python3"]["sha256"],
         "role": "gate-interpreter"},
        {"path": operation + "/tools/python3-controller",
         "sha256": sha(read_bytes(opdir + "/tools/python3-controller")),
         "role": "controller-interpreter"},
        {"path": operation + "/tools/python3-auditor",
         "sha256": sha(read_bytes(opdir + "/tools/python3-auditor")),
         "role": "auditor-interpreter"},
    ]
    for row in runtime["libraries"]:
        closure.append({"path": target(row["path"]), "sha256": row["sha256"],
                        "role": "shared-library:" + os.path.basename(row["path"])})
    for relative, role in ((("os.py"), "python-stdlib:os"),
                           (("site.py"), "python-stdlib:site"),
                           (("codecs.py"), "python-stdlib:codecs"),
                           (("encodings/__init__.py"), "python-stdlib:encodings"),
                           (("json/__init__.py"), "python-stdlib:json"),
                           (("gzip.py"), "python-stdlib:gzip"),
                           (("hashlib.py"), "python-stdlib:hashlib")):
        path = runtime["python_lib_dir"] + "/" + relative
        need(os.path.isfile(path), "stdlib closure file missing: " + relative)
        closure.append({"path": target(path), "sha256": sha(read_bytes(path)),
                        "role": role})
    closure.sort(key=lambda row: row["path"])
    environment = {
        "schema_version": "r11_runtime_environment.v1",
        "vars": {
            "PATH": operation + "/tools",
            "PYTHONHOME": target(runtime["pythonlib"]),
            "PYTHONPATH": target(runtime["python_lib_dir"]),
            "LD_LIBRARY_PATH": operation + "/tools/lib",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONHASHSEED": "0",
            "LC_ALL": "C.UTF-8",
            "LANG": "C.UTF-8",
            "TZ": "UTC",
            "TMPDIR": operation + "/native-cache",
            "TMP": operation + "/native-cache",
            "TEMP": operation + "/native-cache",
            "XDG_CACHE_HOME": operation + "/native-cache",
            "PYTHONPYCACHEPREFIX": operation + "/native-cache",
        },
        "interpreters": {
            "controller": operation + "/tools/python3-controller",
            "gate": operation + "/tools/python3",
            "auditor": operation + "/tools/python3-auditor",
        },
        "runtime_closure": closure,
        "resolved_commands": {"python3": operation + "/tools/python3"},
    }
    write_json(control + "/environment.v1.json", environment, 0o644)
    # Frozen run identity.
    run = {"argv": ["python3", "-B",
                    operation + "/project/scripts/verify_picorv32_native_online.py",
                    "--output", evidence,
                    "--cache-dir", operation + "/native-cache",
                    "--heavy-lock", TARGET_WORKSPACE + "/.superpowers/heavy-worker.lock",
                    "--gate-run-id", args.gate_run_id, *FLAGS],
           "cwd": operation + "/project",
           "output": evidence,
           "cache_dir": operation + "/native-cache",
           "heavy_lock": TARGET_WORKSPACE + "/.superpowers/heavy-worker.lock",
           "gate_run_id": args.gate_run_id,
           "requested_gate_flags": FLAGS, "requested_gates": GATES}
    controller_sha = stage1_sha["r11-one-shot-controller.v1.py"]
    intent = {
        "schema_version": "task5_r11_native_intent.v1",
        "run": run, "claims": CLAIMS, "acceptance_matrix": ACCEPTANCE_MATRIX,
        "gate_started": False, "gate_executed": False,
        "source": {
            "manifest": {"path": operation + "/control/source-manifest.v1.json",
                         "sha256": source_manifest_sha,
                         "entries": len(source_rows),
                         "canonical_entries_sha256": sha(
                             controller.canonical(source_rows))},
            "task5_files": task5_rows,
        },
        "environment": {
            "tools": [{"name": name, "path": row["path"], "sha256": row["sha256"]}
                      for name, row in sorted(tool_rows.items())],
            "tool_count": len(tool_rows),
            "tool_freeze": operation + "/control/tool-freeze.v1.json",
            "tool_freeze_sha256": tool_freeze_sha,
        },
        "source_manifest_sha256": source_manifest_sha,
        "tool_freeze_sha256": tool_freeze_sha,
        "gate_script_sha256": stage1_sha["r11-gate-script.v1.py"],
    }
    intent_sha = write_json(control + "/intent.v1.json", intent, 0o644)
    receipt = {"schema_version": "task5_r11_controller_receipt.v1",
               "path": operation + "/control/r11-one-shot-controller.v1.py",
               "controller_sha256": controller_sha, "intent_sha256": intent_sha,
               "gate_started": False, "gate_executed": False}
    receipt_sha = write_json(control + "/controller-receipt.v1.json", receipt, 0o644)
    plan = {"schema_version": "task5_r11_run_plan.v1", "run": run, "intent": intent,
            "gate_run_id": args.gate_run_id, "intent_sha256": intent_sha,
            "controller_sha256": controller_sha,
            "controller_receipt_sha256": receipt_sha, "claims": CLAIMS,
            "acceptance_matrix": ACCEPTANCE_MATRIX, "gate_started": False,
            "gate_executed": False,
            "post_gate_audit": {"path": operation + "/control/r11-independent-auditor.v1.py",
                                "sha256": stage1_sha["r11-independent-auditor.v1.py"]}}
    write_json(control + "/run-plan.v1.json", plan, 0o644)
    # Stage 2 manifest over the complete live operation inventory.
    opfd = controller.open_dir(opdir)
    try:
        live = controller.scan_tree(opfd)
    finally:
        os.close(opfd)
    manifest_entries = [row for row in live
                        if row["path"] != "control/stage2-manifest.v1.json"]
    missing = [path for path in ABSENT_LEAVES
               if any(row["path"] == path for row in live)]
    need(not missing, "dynamic output leaves must be absent: " + repr(missing))
    manifest = {"schema_version": "r11_stage2_manifest.v1",
                "entries": manifest_entries}
    manifest_path = control + "/stage2-manifest.v1.json"
    manifest_sha = write_json(manifest_path, manifest, 0o644)
    self_row = {"path": "control/stage2-manifest.v1.json", "kind": "file",
                "mode": stat.S_IMODE(os.stat(manifest_path).st_mode),
                "size": len(read_bytes(manifest_path)), "sha256": manifest_sha}
    receipt_document = {
        "schema_version": "r11_stage2_build_receipt.v1",
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "head": head, "source_repo": repo,
        "operation_id": args.operation_id, "gate_run_id": args.gate_run_id,
        "workspace_dir": TARGET_WORKSPACE, "operation_dir": operation,
        "evidence_dir": evidence, "local_package_root": root,
        "run": run, "exclusions": map_document["exclusions"],
        "source_snapshot_entries": len(entries),
        "source_snapshot_map_sha256": sha(map_raw),
        "source_manifest_entries": len(source_rows),
        "source_manifest_sha256": source_manifest_sha,
        "submodule_manifest_sha256": sha(submodule_raw),
        "submodule_entries": len(submodule_rows),
        "tool_freeze_sha256": tool_freeze_sha,
        "stage2_manifest": self_row,
        "stage2_member_count": len(manifest_entries),
        "python_closure": {"python_bin": os.path.realpath(args.python_bin),
                           "python_lib": os.path.realpath(args.python_lib),
                           "loader_copy": operation + "/tools/lib/" +
                                          os.path.basename(runtime["loader"]),
                           "library_count": len(runtime["libraries"]),
                           "stdlib_files": runtime["stdlib_files"]},
        "absent_dynamic_leaves": list(ABSENT_LEAVES),
        "gate_launched": False,
        "preflight_argv": [
            operation + "/tools/python3-controller",
            operation + "/control/r11-one-shot-controller.v1.py",
            "--operation-dir", operation, "--evidence-dir", evidence,
            "--workspace-dir", TARGET_WORKSPACE,
            "--stage2-manifest-sha256", manifest_sha, "--execute"],
    }
    write_json(root + "/stage2-build-receipt.v1.json", receipt_document, 0o644)
    print(json.dumps({"stage2_root": root, "operation_dir": operation,
                      "evidence_dir": evidence, "head": head,
                      "stage2_manifest_sha256": manifest_sha,
                      "stage2_member_count": len(manifest_entries),
                      "source_entries": len(entries),
                      "source_files": len(source_rows),
                      "submodules": len(submodule_rows),
                      "tool_rows": len(tool_rows),
                      "stdlib_files": runtime["stdlib_files"]},
                     sort_keys=True))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage2-root", required=True)
    parser.add_argument("--operation-id", required=True)
    parser.add_argument("--gate-run-id", required=True)
    parser.add_argument("--source-repo", default="/home/qinkejiu/myfuzz")
    parser.add_argument("--head", default="8485893482bea029998e3738057d310bfb499a6c")
    parser.add_argument("--python-bin", default="/usr/bin/python3.12")
    parser.add_argument("--python-lib", default="/usr/lib/python3.12")
    parser.add_argument("--exclude", action="append", default=[],
                        metavar="PATH=REASON")
    args = parser.parse_args()
    try:
        return build(args)
    except BuildError as error:
        print("r11 stage2 builder: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
