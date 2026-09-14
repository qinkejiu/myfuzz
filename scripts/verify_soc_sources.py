"""Offline selected-source locks. Never downloads, generates RTL, or compiles.

soc_sources.v1: components contain source (SourceLocator JSON), artifacts
({path, sha256, kind}), selected_content_hash, closure_status, and independent
source/elaboration/runtime statuses. Source verification covers selected bytes,
not a compiler-proven transitive closure. Pending entries are never promoted.

elaboration_verified additionally requires an elaboration evidence document
(configs/soc/closures/<id>.json) whose sha256 is pinned in the lock. The
verifier re-reads that document and checks, for every recorded closure file,
that the bytes on disk match both the recorded sha256 and the git blob at the
pinned revision of the owning root, that the command's --top-module and file
arguments agree with the closure, and that the recorded lint result is clean.
Pass --elaborate to replay each recorded command as a real elaboration.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from myfuzz.composition.interface_description import RepositoryPin, SourceLocator
from myfuzz.composition.source_crawler import (
    SourceCrawler, SourceCrawlError, _declared_files, _safe_child, source_tree_hash,
)

ELABORATION_UNVERIFIED = "elaboration_unverified"
ELABORATION_VERIFIED = "elaboration_verified"
CLOSURE_SCHEMA = "soc_elaboration_closure.v1"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def _declared_relative(value):
    if not isinstance(value, str) or not value:
        raise ValueError("invalid-declared-path")
    if "\\" in value or value.startswith("/") or Path(value).is_absolute():
        raise ValueError("absolute-declared-path")
    parts = Path(value).parts
    if any(part in ("..", ".") for part in parts):
        raise ValueError("declared-path-escape")
    return value


def locator_from_source(source):
    """Deliberately omit elaboration settings: this command is source-only."""
    return SourceLocator(
        source_root=source["root"], revision=source["revision"],
        top_module=source["top_module"], files=tuple(source.get("files", [])),
        filelist=source.get("filelist"), include_roots=tuple(source.get("include_roots", [])),
        repositories=tuple(RepositoryPin(**p) for p in source.get("repositories", [])),
        filelist_variables=tuple((p["name"], p["value"]) for p in source.get("filelist_variables", [])),
    )


def selected_paths(source, base_dir):
    """Use the same safe filelist expansion as SourceCrawler, including inputs."""
    locator = locator_from_source(source)
    root = _safe_child(Path(base_dir).resolve(), locator.source_root)
    paths = set()

    def read(path):
        paths.add(path.relative_to(root).as_posix())
        return path.read_bytes()

    _declared_files(root, locator, read)
    return root, sorted(paths)


def document_owners(document, base_dir):
    """Map every pinned root in the document to its git revision."""
    owners = {}
    for record in document.get("components", []):
        source = record.get("source", {})
        if "root" in source and "revision" in source:
            owners[source["root"]] = source["revision"]
        for pin in source.get("repositories", []):
            owners[pin["path"]] = pin["revision"]
    return owners


def document_roots(document):
    """Map each component id to the roots its elaboration may legitimately use.

    A closure may span its own root, its own nested repository pins, and the
    roots of components it declares as dependencies - nothing else, so a
    closure can no longer borrow a file from an unrelated upstream tree.
    """
    by_id = {record["id"]: record for record in document.get("components", [])}
    allowed = {}
    for identifier, record in by_id.items():
        source = record.get("source", {})
        roots = set()
        if "root" in source:
            roots.add(source["root"])
        for pin in source.get("repositories", []):
            roots.add(pin["path"])
        for dependency in record.get("dependencies", []):
            other = by_id.get(dependency, {}).get("source", {})
            if "root" in other:
                roots.add(other["root"])
            for pin in other.get("repositories", []):
                roots.add(pin["path"])
        allowed[identifier] = roots
    return allowed


def _is_git_worktree(base):
    return subprocess.run(["git", "-C", str(base), "rev-parse", "--git-dir"],
                          capture_output=True, check=False).returncode == 0


def _is_tracked(base, path):
    return subprocess.run(
        ["git", "-C", str(base), "ls-files", "--error-unmatch", "--", str(path)],
        capture_output=True, check=False).returncode == 0


def _command_options(command):
    """Collect -I/-y/-f include options and every -G/-D define from an argv."""
    include_dirs, include_files, defines, parameter_tokens = [], [], [], []
    index = 0
    while index < len(command):
        token = command[index]
        if token in ("-I", "-y", "-f") and index + 1 < len(command):
            value = command[index + 1]
            index += 2
            (include_dirs if token == "-I" else include_dirs if token == "-y"
             else include_files).append(value)
            continue
        if token.startswith("-I") and len(token) > 2:
            include_dirs.append(token[2:])
        elif token.startswith("-y") and len(token) > 2:
            include_dirs.append(token[2:])
        elif token.startswith("+incdir+"):
            include_dirs.extend(part for part in token[len("+incdir+"):].split("+") if part)
        elif token.startswith("-D") and len(token) > 2:
            defines.append(token[2:])
        elif token.startswith("-G") and len(token) > 2:
            parameter_tokens.append(token[2:])
        elif token == "-G" and index + 1 < len(command):
            parameter_tokens.append(command[index + 1])
            index += 1
        index += 1
    return include_dirs, include_files, defines, parameter_tokens


def verify_elaboration(record, base_dir, owners, allowed_roots=None):
    """Re-derive the elaboration claim from the pinned evidence document."""
    status = record["elaboration_status"]
    block = record.get("elaboration")
    if status == ELABORATION_UNVERIFIED:
        if block is not None:
            raise ValueError("unsupported-verification-claim")
        return {"elaboration_status": status, "closure_files": 0, "elaboration_status_detail": "no-evidence"}
    if status != ELABORATION_VERIFIED:
        raise ValueError("invalid-elaboration-status")
    if not isinstance(block, dict) or block.get("status") != ELABORATION_VERIFIED:
        raise ValueError("unsupported-verification-claim")
    for field in ("top_module", "tool", "evidence", "evidence_sha256", "closure_files", "lint"):
        if field not in block:
            raise ValueError("missing-elaboration-field:" + field)
    if not isinstance(block["evidence_sha256"], str) or not HEX64.fullmatch(block["evidence_sha256"]):
        raise ValueError("invalid-elaboration-evidence-hash")

    base = Path(base_dir).resolve()
    evidence = _safe_child(base, _declared_relative(block["evidence"]))
    raw = evidence.read_bytes()
    if hashlib.sha256(raw).hexdigest() != block["evidence_sha256"]:
        raise ValueError("elaboration-evidence-hash-mismatch")
    try:
        closure = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError("invalid-elaboration-evidence") from error
    if not isinstance(closure, dict) or closure.get("schema_version") != CLOSURE_SCHEMA:
        raise ValueError("invalid-elaboration-evidence")
    if closure.get("component") != record["id"]:
        raise ValueError("elaboration-component-mismatch")
    if closure.get("status") != ELABORATION_VERIFIED:
        raise ValueError("unsupported-verification-claim")
    if closure.get("top_module") != block["top_module"]:
        raise ValueError("elaboration-top-mismatch")
    if record["source"].get("top_module") != block["top_module"]:
        # The elaboration must be about the component's declared top, not some
        # other module that happens to live in the same checkout.
        raise ValueError("elaboration-source-top-mismatch:" + record["id"])
    if closure.get("tool") != block["tool"]:
        raise ValueError("elaboration-tool-mismatch")

    lint = closure.get("lint") or {}
    if lint.get("errors") != 0 or lint.get("exit_code") != 0:
        raise ValueError("elaboration-lint-failed")
    for key in ("errors", "warnings", "exit_code"):
        if block["lint"].get(key) != lint.get(key):
            raise ValueError("elaboration-lint-mismatch:" + key)

    files = closure.get("closure_files")
    if not isinstance(files, list) or not files:
        raise ValueError("empty-elaboration-closure")
    if not isinstance(block["closure_files"], int) or block["closure_files"] != len(files):
        raise ValueError("elaboration-closure-count-mismatch")
    entries = set()
    for item in files:
        if not isinstance(item, dict):
            raise ValueError("invalid-closure-entry")
        key = (_declared_relative(item.get("root")), _declared_relative(item.get("path")))
        if key in entries:
            # Duplicates would inflate the recorded count without pinning more.
            raise ValueError("duplicate-closure-entry:" + key[1])
        entries.add(key)
    allowed = allowed_roots if allowed_roots is not None else (
        {record["source"]["root"]}
        | {pin["path"] for pin in record["source"].get("repositories", [])})

    command = closure.get("command")
    if not isinstance(command, list) or not command or not all(isinstance(t, str) for t in command):
        raise ValueError("missing-elaboration-command")
    tops = [index for index, token in enumerate(command) if token == "--top-module"]
    if len(tops) != 1:
        # A second --top-module silently changes what the tool elaborates.
        raise ValueError("elaboration-command-top-count:%d" % len(tops))
    if command[tops[0] + 1] != closure["top_module"]:
        raise ValueError("elaboration-command-top-mismatch")

    # Parameters must agree three ways: what the closure records, what the lock
    # declares and what the command actually passes. A lying value in any of
    # them means the elaboration proves a different configuration.
    declared = {str(item.get("name")): str(item.get("value"))
                for item in record.get("typed_parameters", [])}
    constants = {str(key): str(value)
                 for key, value in (record.get("generated_constants") or {}).items()}
    listed = {}
    for item in closure.get("parameters", []):
        if not isinstance(item, dict) or "name" not in item or "value" not in item:
            raise ValueError("invalid-elaboration-parameter")
        name, value = str(item["name"]), str(item["value"])
        listed[name] = value
        if "::" in name:
            # Generated-package constants are reported separately from the
            # module's typed parameters, but they must still be pinned.
            if constants.get(name) != value:
                raise ValueError("generated-constant-mismatch:" + name)
        elif name not in declared:
            raise ValueError("undeclared-elaboration-parameter:" + name)
        elif declared[name] != value:
            raise ValueError("elaboration-parameter-mismatch:" + name)
    for name, value in declared.items():
        if listed.get(name) != value:
            raise ValueError("lock-parameter-not-elaborated:" + name)
    include_dirs, include_files, defines, parameter_tokens = _command_options(command)
    for token in parameter_tokens:
        name, _, value = token.partition("=")
        if listed.get(name) != value:
            raise ValueError("command-parameter-mismatch:" + name)
    for token in defines:
        name = token.partition("=")[0]
        if not any(str(item).partition("=")[0] == name for item in closure.get("defines", [])):
            raise ValueError("undeclared-elaboration-define:" + name)

    # Include and filelist options must stay inside the pinned closure roots:
    # an extra -I pointing elsewhere can silently override a pinned header.
    for value in include_dirs:
        directory = _safe_child(base, _declared_relative(value))
        if not directory.is_dir():
            raise ValueError("include-root-missing:" + value)
        if not any(_safe_child(base, root) in directory.parents or
                   _safe_child(base, root) == directory for root in allowed):
            raise ValueError("include-root-outside-pinned-sources:" + value)
    for value in include_files:
        target = _safe_child(base, _declared_relative(value))
        if not target.is_file():
            raise ValueError("filelist-missing:" + value)
        if target.relative_to(base).as_posix() not in {path for _, path in entries}:
            raise ValueError("filelist-not-in-closure:" + value)

    labelled = set()
    roots = set()
    for item in files:
        if not isinstance(item, dict):
            raise ValueError("invalid-closure-entry")
        root_relative = _declared_relative(item.get("root"))
        relative = _declared_relative(item.get("path"))
        digest = item.get("sha256")
        if not isinstance(digest, str) or not HEX64.fullmatch(digest):
            raise ValueError("invalid-closure-hash:" + relative)
        revision = owners.get(root_relative)
        if not isinstance(revision, str) or not revision.startswith("git:"):
            raise ValueError("unpinned-closure-root:" + root_relative)
        if root_relative not in allowed:
            raise ValueError("undeclared-closure-root:" + root_relative)
        root = _safe_child(base, root_relative)
        path = _safe_child(root, relative)
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != digest:
            raise ValueError("closure-hash-mismatch:" + relative)
        blob = subprocess.run(
            ["git", "-C", str(root), "cat-file", "blob", revision[4:] + ":" + relative],
            capture_output=True, check=False,
        )
        if blob.returncode or blob.stdout != content:
            raise ValueError("git-content-mismatch:" + relative)
        labelled.add(path.relative_to(base).as_posix())
        roots.add(root_relative)

    for token in command:
        if token.startswith("-") or token.startswith("+") or "=" in token:
            continue
        candidate = base / token
        if candidate.is_file() and base in candidate.resolve().parents:
            if candidate.resolve().relative_to(base).as_posix() not in labelled:
                raise ValueError("command-file-not-in-closure:" + token)

    if _is_git_worktree(base) and not _is_tracked(base, block["evidence"]):
        # Untracked evidence is not durable: it can be edited with no trace in
        # any commit, so the claim would not be reviewable after the fact.
        raise ValueError("untracked-elaboration-evidence:" + block["evidence"])

    return {
        "elaboration_status": status,
        "closure_files": len(files),
        "closure_roots": sorted(roots),
        "top_module": closure["top_module"],
        "tool": closure["tool"]["version"],
        "lint": lint,
    }


def replay_elaboration(record, base_dir):
    """Re-run the recorded command and require it to read exactly the closure.

    Replay alone is not proof: a command naming no sources, or an extra include
    directory, still exits zero. Verilator is asked for its own dependency list
    and the set of files it actually read must equal the pinned closure.
    """
    base = Path(base_dir).resolve()
    block = record.get("elaboration")
    evidence = _safe_child(base, _declared_relative(block["evidence"]))
    closure = json.loads(evidence.read_text())
    command = list(closure["command"])

    version = subprocess.run([command[0], "--version"], capture_output=True, text=True,
                             check=False)
    if version.returncode != 0 or version.stdout.strip() != closure["tool"]["version"]:
        raise ValueError("elaboration-tool-version-mismatch:" + record["id"])

    with tempfile.TemporaryDirectory() as directory:
        argv = []
        index = 0
        while index < len(command):
            token = command[index]
            if token == "--MMD":
                index += 1
                continue
            if token == "--Mdir":
                index += 2
                continue
            if token.startswith("--Mdir"):
                index += 1
                continue
            argv.append(token)
            index += 1
        argv += ["--MMD", "--Mdir", directory]
        result = subprocess.run(argv, cwd=str(base), capture_output=True, text=True,
                                check=False)
        if result.returncode != 0:
            raise ValueError("elaboration-replay-failed:" + record["id"])
        if "%Error" in result.stderr + result.stdout:
            raise ValueError("elaboration-replay-errors:" + record["id"])
        reports = sorted(Path(directory).glob("*.d"))
        if len(reports) != 1:
            raise ValueError("elaboration-replay-no-dependency-report:" + record["id"])
        text = reports[0].read_text().replace("\\\n", " ")
        _, _, dependencies = text.partition(":")
        read = set()
        for token in dependencies.split():
            read.add((base / token.replace("\\ ", " ")).resolve())

    pinned = set()
    for item in closure["closure_files"]:
        pinned.add(_safe_child(_safe_child(base, item["root"]), item["path"]))
    missing = sorted(path.relative_to(base).as_posix() for path in pinned - read)
    extra = sorted(path.relative_to(base).as_posix() for path in read - pinned
                   if base in path.parents)
    if missing:
        raise ValueError("closure-file-not-read:" + missing[0])
    if extra:
        raise ValueError("unrecorded-file-read:" + extra[0])
    return {"replayed": True, "returncode": result.returncode,
            "read_set_matches_closure": True}


def verify_record(record, base_dir, owners=None, replay=False, allowed_roots=None):
    for field in ("id", "source", "artifacts", "selected_content_hash", "closure_status", "source_status", "elaboration_status", "runtime_status"):
        if field not in record:
            raise ValueError("missing-lock-field:" + field)
    if record["closure_status"] not in {"selected", "pending"}:
        raise ValueError("invalid-closure-status")
    pending = record["closure_status"] == "pending"
    if record["source_status"] != ("source_pending" if pending else "source_verified"):
        raise ValueError("pending-or-invalid-source-status")
    if record["runtime_status"] != "runtime_unverified":
        raise ValueError("unsupported-verification-claim")
    if owners is None:
        owners = document_owners({"components": [record]}, base_dir)
    if allowed_roots is None:
        allowed_roots = document_roots({"components": [record]}).get(record["id"], set())
    elaboration = verify_elaboration(record, base_dir, owners, allowed_roots)
    if "interface_description" in record:
        interface = _safe_child(Path(base_dir).resolve(), record["interface_description"])
        if hashlib.sha256(interface.read_bytes()).hexdigest() != record.get("interface_description_sha256"):
            raise ValueError("interface-description-hash-mismatch")
    locator = locator_from_source(record["source"])
    parse_status = "source_parsed"
    try:
        SourceCrawler().crawl(locator, base_dir=Path(base_dir))
    except SourceCrawlError as error:
        # These exact parser errors occur AFTER every declared source/filelist
        # has passed crawler Git provenance checks. No other errors are deferred.
        if str(error) in {"unsupported-port-width", "unsupported-unpacked-port", "unsupported-port-type"} or str(error).startswith("unsupported-port-type:"):
            parse_status = "parameterized_ports_pending_elaboration"
        else:
            raise
    root, paths = selected_paths(record["source"], base_dir)
    if not paths:
        raise ValueError("empty-selected-sources")
    digest = source_tree_hash(root, [root / p for p in paths])
    if digest != record["selected_content_hash"]:
        raise ValueError("selected-content-hash-mismatch")
    artifacts = record["artifacts"]
    if not any(a["kind"] == "license" for a in artifacts):
        raise ValueError("license-record-missing")
    labels = [a["path"] for a in artifacts]
    if len(set(labels)) != len(labels) or not set(paths).issubset(labels):
        raise ValueError("artifact-closure-mismatch")
    for artifact in artifacts:
        path = _safe_child(root, artifact["path"])
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != artifact["sha256"]:
            raise ValueError("artifact-hash-mismatch:" + artifact["path"])
        # Crawler already validates HDL and filelist provenance. Ancillary
        # license/docs/generator inputs require a blob check against that pin too.
        if artifact["path"] not in paths:
            owners_for_artifact = [(root, locator.revision)] + [(_safe_child(root, p.path), p.revision) for p in locator.repositories]
            owner, revision = max((p for p in owners_for_artifact if p[0] in path.parents), key=lambda p: len(p[0].parts))
            blob = subprocess.run(["git", "-C", str(owner), "cat-file", "blob", revision[4:] + ":" + path.relative_to(owner).as_posix()], capture_output=True, check=False)
            if blob.returncode or blob.stdout != content:
                raise ValueError("git-content-mismatch:" + artifact["path"])
    if replay and record["elaboration_status"] == ELABORATION_VERIFIED:
        elaboration.update(replay_elaboration(record, base_dir))
    return {
        "id": record["id"], "source_status": record["source_status"],
        "elaboration_status": record["elaboration_status"],
        "runtime_status": record["runtime_status"], "parse_status": parse_status,
        "selected_files": len(paths), "selected_content_hash": digest,
        "elaboration": elaboration,
    }


def validate_document(document):
    if document.get("schema_version") != "soc_sources.v1":
        raise ValueError("invalid-lock-schema")
    records = document.get("components")
    if not isinstance(records, list) or not records:
        raise ValueError("empty-source-lock")
    ids = [r["id"] for r in records]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate-source-id")
    for record in records:
        if any(dependency not in ids for dependency in record.get("dependencies", [])):
            raise ValueError("missing-source-dependency:" + record["id"])
        if record.get("elaboration_status") not in {ELABORATION_UNVERIFIED, ELABORATION_VERIFIED}:
            raise ValueError("invalid-elaboration-status:" + record["id"])


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base-dir", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--lock", type=Path, default=Path("configs/soc/sources.lock.json"))
    parser.add_argument("--elaborate", action="store_true",
                        help="replay each recorded elaboration command (slow)")
    args = parser.parse_args()
    document = json.loads((args.base_dir / args.lock).read_text())
    validate_document(document)
    owners = document_owners(document, args.base_dir)
    allowed = document_roots(document)
    results = []
    failed = False
    for record in document["components"]:
        try:
            results.append(verify_record(record, args.base_dir, owners=owners,
                                         replay=args.elaborate,
                                         allowed_roots=allowed[record["id"]]))
        except (ValueError, OSError, KeyError) as error:
            failed = True
            results.append({"id": record.get("id"), "source_status": "source_failed", "error": str(error)})
    print(json.dumps({"schema_version": "soc_source_verification.v1", "components": results}, indent=2))
    return 1 if failed else (2 if any(r["source_status"] == "source_pending" for r in results) else 0)


if __name__ == "__main__":
    raise SystemExit(main())
