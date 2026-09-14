#!/usr/bin/env python3
"""Conservative repository inventory with a reversible quarantine.

The audit is read-only. It classifies every tracked file, every untracked
non-ignored file and every rebuildable cache candidate in the worktree, and it
only ever marks a cache file eligible when all of the following hold:

* it matches an enabled rebuildable rule (currently compiled Python bytecode),
* git does not track it,
* no path component is a symlink and the file really lives inside the worktree,
* no tracked or untracked text file references its path,
* the source it was compiled from is tracked, present and unmodified,
* the recorded source timestamp and size still match, so the cache is not stale,
* the bytecode does not use checked-hash invalidation, which cannot be confirmed
  here without recompiling.

Nothing is moved unless an explicit selection is applied, and applying a
selection re-runs the audit: a path that has since become dirty, referenced,
stale or unpinned is rejected. Every store directory is created one level at a
time with a symlink check, every source is re-resolved and re-hashed immediately
before it moves, and the manifest is rewritten after each individual move, so a
failure always leaves a manifest that matches reality and a working restore
command. Paths that are absolute, escape the worktree, cross a symlink, are
tracked, are not rebuildable caches, or whose hash changed are rejected before
anything moves.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys

SCHEMA_VERSION = "repository_audit.v1"
SELECTION_SCHEMA_VERSION = "repository_quarantine_selection.v1"
QUARANTINE_SCHEMA_VERSION = "repository_quarantine.v1"
QUARANTINE_DIRNAME = "runs/quarantine"
AUDIT_DIRNAME = "runs/repository-audit"
TOOL_DIR_PREFIXES = (QUARANTINE_DIRNAME + "/", AUDIT_DIRNAME + "/")
OWN_ARTIFACT_SCHEMAS = frozenset(
    {SCHEMA_VERSION, SELECTION_SCHEMA_VERSION, QUARANTINE_SCHEMA_VERSION})
BATCH_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
# Manifest entry states that restore will still try to act on: a rollback that
# itself failed, and a kill between the manifest rewrite and the move, both
# leave a stored file that must remain recoverable.
RECOVERABLE_STATUSES = ("moved", "planned", "rollback-failed")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_OWN_ARTIFACT_MARKER = re.compile(
    r'"schema_version"\s*:\s*"repository_(?:audit|quarantine|quarantine_selection)\.v1"')

# Directories whose contents are compiled-code caches. Only files below one of
# these directories, with one of the cache suffixes, can ever be eligible.
CACHE_DIR_NAMES = frozenset({"__pycache__", ".mypy_cache", ".ruff_cache", ".pytest_cache"})
CACHE_SUFFIXES = frozenset({".pyc", ".pyo"})

# The reference scan reads every tracked and untracked file, including ones with
# no extension (Makefile, .gitignore) and stub/typing files, so a build script
# that names a cache path cannot be missed. Only files whose head looks binary,
# or that exceed the cap, are skipped.
MAX_REFERENCE_BYTES = 32 * 1024 * 1024
BINARY_PROBE_BYTES = 8192
PATH_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_./+@-]+")


class AuditError(ValueError):
    """Raised when the request itself is invalid, never for a kept file."""


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, check=False,
    )


def _git_paths(root: Path, *args: str) -> set:
    result = _git(root, *args)
    if result.returncode != 0:
        raise AuditError("git-failed:git " + " ".join(args))
    return {p for p in result.stdout.decode("utf-8", "surrogateescape").split("\0") if p}


def tracked_paths(root: Path) -> set:
    return _git_paths(root, "ls-files", "-z")


def _dirty_paths(root: Path) -> set:
    """Tracked paths with a staged or unstaged change; never removes anything."""
    result = _git(root, "status", "--porcelain", "-z", "--untracked-files=no")
    if result.returncode != 0:
        raise AuditError("git-failed:git status")
    tokens = [t for t in result.stdout.decode("utf-8", "surrogateescape").split("\0") if t]
    dirty = set()
    index = 0
    while index < len(tokens):
        token = tokens[index]
        index += 1
        status = token[:2]
        path = token[3:] if len(token) > 3 and token[2] == " " else token[2:]
        if path:
            dirty.add(path)
        if "R" in status or "C" in status:
            # A -z rename/copy record appends the original path as a bare field.
            if index < len(tokens):
                dirty.add(tokens[index])
                index += 1
    return dirty


def is_cache_file(relative) -> bool:
    if not isinstance(relative, str):
        return False
    pure = PurePosixPath(relative)
    parts = pure.parts
    if len(parts) < 2:
        return False
    if not any(part in CACHE_DIR_NAMES for part in parts[:-1]):
        return False
    return pure.suffix in CACHE_SUFFIXES


def _is_tool_artifact(relative: str) -> bool:
    return relative.startswith(TOOL_DIR_PREFIXES)


def _validate_relative(relative) -> str:
    if not isinstance(relative, str) or not relative:
        raise AuditError("invalid-path")
    if "\\" in relative or relative.startswith("/") or PurePosixPath(relative).is_absolute():
        raise AuditError("absolute-path")
    parts = PurePosixPath(relative).parts
    if not parts or any(part in ("..", ".", "") for part in parts):
        raise AuditError("path-escape")
    if str(PurePosixPath(*parts)) != relative:
        raise AuditError("non-normalized-path")
    return relative


def _contained(root: Path, relative: str) -> Path:
    """root/relative with no symlinked component and resolving inside root."""
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        if current.is_symlink():
            raise AuditError("symlink-component:" + relative)
    resolved = (root / relative).resolve()
    if resolved != root and root not in resolved.parents:
        raise AuditError("path-escape:" + relative)
    return resolved


def _contained_file(root: Path, relative: str) -> Path:
    resolved = _contained(root, relative)
    if not resolved.is_file():
        raise AuditError("missing-path:" + relative)
    return resolved


def _make_contained_dir(root: Path, relative: str) -> Path:
    """Create root/relative level by level, refusing any symlinked component."""
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        if current.is_symlink():
            raise AuditError("symlink-component:" + relative)
        if current.exists():
            if not current.is_dir():
                raise AuditError("not-a-directory:" + relative)
        else:
            current.mkdir()
    return _contained(root, relative)


def pyc_source_relative(relative: str) -> str:
    pure = PurePosixPath(relative)
    module = pure.name.split(".", 1)[0]
    return str(pure.parent.parent / (module + ".py"))


def _pyc_unusable_reason(root: Path, relative: str):
    """Return why the bytecode cannot be proven current, or None when it can."""
    try:
        with open(root / relative, "rb") as handle:
            header = handle.read(16)
    except OSError:
        return "unreadable"
    if len(header) < 16:
        return "malformed-cache"
    flags = int.from_bytes(header[4:8], "little")
    if flags & 0b1:
        # Checked-hash invalidation embeds a source hash that this tool cannot
        # confirm without recompiling, so keep the file instead of guessing.
        return "hash-invalidated-cache"
    mtime = int.from_bytes(header[8:12], "little")
    size = int.from_bytes(header[12:16], "little")
    source = root / pyc_source_relative(relative)
    if not source.is_file():
        return "missing-source"
    stat = source.stat()
    if int(stat.st_mtime) != mtime or stat.st_size != size:
        return "stale-cache"
    return None


def _is_own_artifact(path: Path, text: str) -> bool:
    """True only for one of this tool's own JSON documents.

    Only the head of the file is examined: parsing arbitrary repository JSON is
    what previously let a legal file (a huge integer literal, thousands of
    nested arrays) crash the whole audit, and a very large inventory would have
    been truncated past the read cap. The marker must be our exact schema
    literal and the entry-list key must be present, so a note that merely
    quotes the schema name does not hide a reference.
    """
    if path.suffix != ".json":
        return False
    head = text[:BINARY_PROBE_BYTES]
    if not _OWN_ARTIFACT_MARKER.search(head):
        return False
    return '"entries"' in head or '"quarantine_candidates"' in head


def _reference_index(root: Path, candidates, scan) -> set:
    """Return the cache paths (or their directories) mentioned by text files."""
    referenced = set()
    wanted = set(candidates)
    by_name = {}
    for candidate in candidates:
        by_name.setdefault(PurePosixPath(candidate).name, set()).add(candidate)
    parents = {str(PurePosixPath(c).parent) for c in candidates}
    for relative in sorted(scan):
        path = root / relative
        try:
            with open(path, "rb") as handle:
                head = handle.read(BINARY_PROBE_BYTES)
                if b"\0" in head:
                    continue
                body = handle.read(MAX_REFERENCE_BYTES)
        except OSError:
            continue
        text = (head + body).decode("utf-8", "ignore")
        if "__pycache__" not in text and ".pyc" not in text and ".pyo" not in text:
            continue
        if _is_own_artifact(path, text):
            # This tool's own inventory, selection and manifest files list
            # candidates by path; counting them would erase the next audit.
            continue
        tokens = set(PATH_TOKEN_PATTERN.findall(text))
        for token in tokens:
            normalized = token.lstrip("./")
            if normalized in wanted:
                referenced.add(normalized)
            elif "/" not in normalized:
                referenced.update(by_name.get(normalized, ()))
        # A whole path token counts as a directory reference. Trailing slashes
        # and leading "./" are stripped first, otherwise "rm -rf src/__pycache__/"
        # would not pin the cache it names. Matching a bare cache directory name
        # against a root-level candidate is deliberately kept: it over-protects,
        # which is the safe direction for a tool that moves files.
        for token in tokens:
            normalized = token.strip("./").rstrip("/")
            if normalized in parents:
                referenced.add(normalized)
    return referenced


def _cache_candidates(root: Path):
    """Ignored cache files from git plus anything the pruned walk still sees."""
    patterns = [":(glob)**/%s/**" % name for name in sorted(CACHE_DIR_NAMES)]
    discovered = {p for p in _git_paths(
        root, "ls-files", "--others", "--ignored", "--exclude-standard", "-z", "--", *patterns,
    ) if is_cache_file(p) and not _is_tool_artifact(p)}
    ignored = _git_paths(
        root, "ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z",
    )
    pruned = {p.rstrip("/") for p in ignored if p.endswith("/")}
    entries = {}
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root)
        rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")
        kept = []
        for name in dirnames:
            child = os.path.join(dirpath, name)
            relative = name if not rel_dir else rel_dir + "/" + name
            if os.path.islink(child):
                entries.setdefault(relative, "symlink-outside-tree")
                continue
            if name == ".git":
                if rel_dir:
                    entries.setdefault(relative, "nested-repository")
                continue
            if os.path.lexists(os.path.join(child, ".git")):
                entries.setdefault(relative, "nested-repository")
                continue
            if relative in pruned and name not in CACHE_DIR_NAMES:
                continue
            kept.append(name)
        dirnames[:] = kept
        for name in filenames:
            relative = name if not rel_dir else rel_dir + "/" + name
            if os.path.islink(os.path.join(dirpath, name)):
                entries.setdefault(relative, "symlink-outside-tree")
            elif is_cache_file(relative) and not _is_tool_artifact(relative):
                discovered.add(relative)
    return sorted(discovered), entries


def audit(root: Path, exclude=()) -> dict:
    """Classify the worktree without reading or writing anything but metadata."""
    root = Path(root).resolve()
    if _git(root, "rev-parse", "--git-dir").returncode != 0:
        raise AuditError("not-a-git-worktree")
    excluded = {_validate_relative(item) for item in exclude}

    tracked = tracked_paths(root)
    untracked = _git_paths(root, "ls-files", "--others", "--exclude-standard", "-z")
    dirty = _dirty_paths(root)
    candidates, walk_entries = _cache_candidates(root)

    entries = {}
    for relative in sorted(tracked):
        entries[relative] = {"action": "keep", "reason": "tracked"}
    for relative in sorted(untracked):
        entries.setdefault(relative, {"action": "keep", "reason": "untracked-not-a-rebuild-cache"})
    for relative, reason in walk_entries.items():
        entries.setdefault(relative, {"action": "keep", "reason": reason})

    referenced = _reference_index(root, candidates, (tracked | untracked) - excluded)

    def keep(relative, reason):
        entries.setdefault(relative, {"action": "keep", "reason": reason})

    for relative in candidates:
        if relative in tracked:
            keep(relative, "tracked-cache-file")
            continue
        try:
            path = _contained_file(root, relative)
        except AuditError as error:
            keep(relative, "unusable-candidate:" + str(error))
            continue
        source = pyc_source_relative(relative)
        source_path = root / source
        if source not in tracked:
            keep(relative, "untracked-source" if source_path.is_file() else "unpinned-source")
            continue
        if source in dirty:
            keep(relative, "dirty-source")
            continue
        unusable = _pyc_unusable_reason(root, relative)
        if unusable is not None:
            keep(relative, unusable)
            continue
        if relative in referenced or str(PurePosixPath(relative).parent) in referenced:
            keep(relative, "referenced")
            continue
        try:
            payload = path.read_bytes()
        except OSError:
            keep(relative, "unreadable")
            continue
        entries[relative] = {
            "action": "eligible",
            "reason": "rebuildable compiled cache: ignored, untracked, unreferenced, source clean",
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
        }

    ordered = dict(sorted(entries.items()))
    candidates_out = [
        {"path": relative, "restore_path": relative, "sha256": record["sha256"],
         "reason": record["reason"]}
        for relative, record in ordered.items() if record["action"] == "eligible"
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "root": str(root),
        "head": _git(root, "rev-parse", "HEAD").stdout.decode().strip(),
        "policy": {
            "eligible_rule": "compiled Python cache under a cache directory",
            "keep_rules": [
                "tracked", "untracked-not-a-rebuild-cache", "tracked-cache-file",
                "untracked-source", "unpinned-source", "dirty-source", "stale-cache",
                "missing-source", "malformed-cache", "hash-invalidated-cache",
                "referenced", "symlink-outside-tree", "nested-repository",
                "unreadable", "unusable-candidate",
            ],
        },
        "summary": {
            "entries": len(ordered),
            "keep": sum(1 for r in ordered.values() if r["action"] == "keep"),
            "eligible": len(candidates_out),
        },
        "entries": ordered,
        "quarantine_candidates": candidates_out,
    }


def _validate_selection_item(root: Path, item, eligible: dict) -> dict:
    if not isinstance(item, dict):
        raise AuditError("invalid-selection-item")
    relative = _validate_relative(item.get("path"))
    if not is_cache_file(relative):
        raise AuditError("not-a-rebuildable-cache:" + relative)
    digest = item.get("sha256")
    if not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest):
        raise AuditError("invalid-sha256:" + relative)
    reason = item.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise AuditError("missing-reason:" + relative)
    if relative not in eligible:
        raise AuditError("not-eligible-now:" + relative)
    path = _contained_file(root, relative)
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise AuditError("sha256-mismatch:" + relative)
    return {"path": relative, "sha256": digest, "size": path.stat().st_size, "reason": reason}


def _safe_output_path(root: Path, relative: str) -> Path:
    """Resolve a tool-owned output path, refusing any symlinked component."""
    parent = str(PurePosixPath(relative).parent)
    directory = root if parent == "." else _make_contained_dir(root, parent)
    target = directory / PurePosixPath(relative).name
    if target.is_symlink():
        raise AuditError("symlink-component:" + relative)
    return target


def _atomic_write(target: Path, text: str) -> None:
    """Write through a temporary file and rename, so no torn file is ever read."""
    temporary = target.with_name(target.name + ".tmp")
    if temporary.is_symlink():
        raise AuditError("symlink-component:" + temporary.name)
    try:
        with open(temporary, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _manifest_text(batch: str, root: Path, manifest: Path, records, indent) -> str:
    return json.dumps({
        "schema_version": QUARANTINE_SCHEMA_VERSION,
        "batch": batch,
        "root": str(root),
        "restore_command": "python3 scripts/audit_repository.py --root %s --restore %s" % (root, manifest),
        "entries": records,
    }, indent=indent) + "\n"


def _batch_relative(batch: str, *parts: str) -> str:
    return "/".join((QUARANTINE_DIRNAME, batch, *parts))


def quarantine(root: Path, selection, batch, selection_source=None) -> Path:
    """Move a fully validated selection into recoverable storage; all or nothing."""
    root = Path(root).resolve()
    if not isinstance(batch, str) or not BATCH_PATTERN.fullmatch(batch):
        raise AuditError("invalid-batch-name")
    if not isinstance(selection, list) or not selection:
        raise AuditError("empty-selection")
    exclude = []
    if selection_source is not None:
        try:
            exclude.append(Path(selection_source).resolve().relative_to(root).as_posix())
        except ValueError:
            pass
    eligible = {record["path"]: record["sha256"]
                for record in audit(root, exclude=exclude)["quarantine_candidates"]}
    validated = [_validate_selection_item(root, item, eligible) for item in selection]
    if len({item["path"] for item in validated}) != len(validated):
        raise AuditError("duplicate-selection-path")

    try:
        manifest = _safe_output_path(root, _batch_relative(batch, "manifest.json"))
    except OSError as error:
        raise AuditError("quarantine-failed:" + str(error)) from error
    if manifest.exists() or manifest.is_symlink():
        raise AuditError("batch-already-exists:" + batch)
    files_relative = _batch_relative(batch, "files")
    try:
        _make_contained_dir(root, files_relative)
        # Create every destination directory before touching the tree, so a
        # directory, symlink or permission failure cannot strand a half-moved batch.
        for item in validated:
            parent = str(PurePosixPath(item["path"]).parent)
            if parent != ".":
                _make_contained_dir(root, files_relative + "/" + parent)
            destination = _contained(root, _batch_relative(batch, "files", item["path"]))
            if destination.exists() or destination.is_symlink():
                raise AuditError("stored-path-collision:" + item["path"])
        records = [{
            "path": item["path"],
            "restore_path": item["path"],
            "stored_path": _batch_relative(batch, "files", item["path"]),
            "sha256": item["sha256"],
            "size": item["size"],
            "reason": item["reason"],
            "status": "planned",
        } for item in validated]
        _atomic_write(manifest, _manifest_text(batch, root, manifest, records, 2))
        # The verdict was derived before the store directories existed; deriving
        # it once more here narrows the window in which a source can go dirty.
        fresh = {record["path"]: record["sha256"]
                 for record in audit(root, exclude=exclude)["quarantine_candidates"]}
        for item in validated:
            if fresh.get(item["path"]) != item["sha256"]:
                raise AuditError("not-eligible-now:" + item["path"])
    except OSError as error:
        raise AuditError("quarantine-failed:" + str(error)) from error

    moved = []
    try:
        for item, record in zip(validated, records):
            # Re-resolve and re-hash right before the move: the audit verdict and
            # the earlier validation may both be stale by now.
            source = _contained_file(root, item["path"])
            if hashlib.sha256(source.read_bytes()).hexdigest() != item["sha256"]:
                raise AuditError("sha256-mismatch-at-move:" + item["path"])
            destination = _contained(root, record["stored_path"])
            if destination.exists() or destination.is_symlink():
                raise AuditError("stored-path-collision:" + item["path"])
            shutil.move(str(source), str(destination))
            record["status"] = "moved"
            moved.append(record)
            _atomic_write(manifest, _manifest_text(batch, root, manifest, records, None))
    except (OSError, AuditError) as error:
        for record in moved:
            record["status"] = "rolled-back"
            try:
                shutil.move(str(_contained(root, record["stored_path"])), str(root / record["path"]))
            except (OSError, AuditError):
                record["status"] = "rollback-failed"
        try:
            _atomic_write(manifest, _manifest_text(batch, root, manifest, records, 2))
        except (OSError, AuditError):
            pass
        raise AuditError("quarantine-failed:" + str(error)) from error
    try:
        _atomic_write(manifest, _manifest_text(batch, root, manifest, records, 2))
    except OSError as error:
        raise AuditError("quarantine-failed:" + str(error)) from error
    return manifest


def restore(root: Path, manifest: Path) -> None:
    """Restore every moved entry after validating the whole manifest."""
    root = Path(root).resolve()
    manifest = Path(manifest)
    try:
        document = json.loads(manifest.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise AuditError("unreadable-manifest") from error
    if not isinstance(document, dict):
        raise AuditError("invalid-manifest-document")
    if document.get("schema_version") != QUARANTINE_SCHEMA_VERSION:
        raise AuditError("invalid-manifest-schema")
    batch = document.get("batch")
    if not isinstance(batch, str) or not BATCH_PATTERN.fullmatch(batch):
        raise AuditError("invalid-batch-name")
    recorded_root = document.get("root")
    if not isinstance(recorded_root, str) or Path(recorded_root).resolve() != root:
        raise AuditError("manifest-root-mismatch")
    entries = document.get("entries")
    if not isinstance(entries, list):
        raise AuditError("invalid-manifest-entries")
    tracked = tracked_paths(root)

    planned = []
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("status") not in RECOVERABLE_STATUSES:
            continue
        relative = _validate_relative(entry.get("path"))
        if not is_cache_file(relative):
            raise AuditError("not-a-rebuildable-cache:" + relative)
        digest = entry.get("sha256")
        if not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest):
            raise AuditError("invalid-sha256:" + relative)
        expected = _batch_relative(batch, "files", relative)
        if entry.get("stored_path") != expected:
            raise AuditError("unexpected-stored-path:" + relative)
        stored = _contained(root, expected)
        destination = _contained(root, relative)
        if stored.is_symlink() or not stored.is_file():
            if destination.exists() and not destination.is_symlink():
                # A crash between a move and the manifest rewrite, or a failed
                # rollback, can leave the file already back at its destination.
                # Only bytes that still match the recorded hash may be called
                # restored; anything else is a real conflict, not a recovery.
                try:
                    unchanged = hashlib.sha256(
                        destination.read_bytes()).hexdigest() == digest
                except OSError:
                    unchanged = False
                if unchanged:
                    entry["status"] = "restored"
                    continue
                raise AuditError("destination-content-mismatch:" + relative)
            if entry.get("status") in ("planned", "rollback-failed"):
                # Never left the tree, so there is nothing to restore.
                entry["status"] = "not-moved"
                continue
            raise AuditError("stored-entry-missing:" + relative)
        if hashlib.sha256(stored.read_bytes()).hexdigest() != digest:
            raise AuditError("stored-entry-tampered:" + relative)
        if relative in tracked:
            raise AuditError("tracked-destination:" + relative)
        if destination.exists():
            raise AuditError("restore-collision:" + relative)
        planned.append((stored, destination, entry))

    for stored, destination, entry in planned:
        parent = str(PurePosixPath(entry["path"]).parent)
        try:
            if parent != ".":
                _make_contained_dir(root, parent)
            shutil.move(str(stored), str(destination))
        except OSError as error:
            try:
                _atomic_write(manifest, json.dumps(document, indent=2) + "\n")
            except (OSError, AuditError):
                pass
            raise AuditError("restore-failed:" + str(error)) from error
        # Rewrite after every move: a later failure must not leave a manifest
        # that claims untouched entries are still recoverable in the store.
        entry["status"] = "restored"
        try:
            _atomic_write(manifest, json.dumps(document, indent=2) + "\n")
        except OSError as error:
            raise AuditError("restore-failed:" + str(error)) from error

    # Persist reconciliation-only updates (already back in place, never moved).
    try:
        _atomic_write(manifest, json.dumps(document, indent=2) + "\n")
    except OSError as error:
        raise AuditError("restore-failed:" + str(error)) from error


def _write_user_file(path: Path, text: str) -> None:
    """Write a caller-supplied output path without following a symlink."""
    path = Path(path)
    if path.is_symlink():
        raise AuditError("symlink-component:" + str(path))
    if path.exists():
        raise AuditError("refusing-to-overwrite:" + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def _protected_tool_paths(root: Path):
    """Only the quarantine store is protected, not the audit output directory.

    Writing an inventory under runs/repository-audit/<batch>/ is the documented
    workflow, but writing one over a manifest or a stored batch would destroy
    the only record needed to restore the quarantined files.
    """
    return (root / QUARANTINE_DIRNAME,)


def _write_new(root: Path, relative: str, payload) -> None:
    target = _safe_output_path(root, relative)
    if target.exists() or target.is_symlink():
        raise AuditError("refusing-to-overwrite:" + relative)
    _atomic_write(target, json.dumps(payload, indent=2) + "\n")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1],
                        help="worktree to inspect (default: this checkout)")
    parser.add_argument("--output", type=Path, default=None,
                        help="write the inventory here; existing files are never overwritten")
    parser.add_argument("--quarantine-list", type=Path, default=None,
                        help="write the eligible selection list here")
    parser.add_argument("--apply", type=Path, default=None,
                        help="quarantine the selection in this file (requires --batch)")
    parser.add_argument("--batch", default=None,
                        help="batch name; requires --apply and records the audit under runs/")
    parser.add_argument("--restore", type=Path, default=None, help="restore a quarantine manifest")
    args = parser.parse_args(argv)

    try:
        if args.restore is not None:
            if any(value is not None for value in
                   (args.output, args.quarantine_list, args.apply, args.batch)):
                print(json.dumps({"error": "--restore cannot be combined with other actions"}))
                return 1
            restore(args.root, args.restore)
            print(json.dumps({"restored": str(args.restore)}))
            return 0
        if args.apply is not None and args.batch is None:
            print(json.dumps({"error": "--apply requires --batch"}))
            return 1
        if args.batch is not None and args.apply is None:
            print(json.dumps({"error": "--batch requires --apply"}))
            return 1
        if args.batch is not None and not BATCH_PATTERN.fullmatch(str(args.batch)):
            print(json.dumps({"error": "invalid-batch-name"}))
            return 1
        root = Path(args.root).resolve()
        outputs = [p for p in (args.output, args.quarantine_list) if p is not None]
        if len({Path(p).resolve() for p in outputs}) != len(outputs):
            print(json.dumps({"error": "output-paths-must-differ"}))
            return 1
        for target in outputs:
            resolved = Path(target).resolve()
            if any(resolved == guard or guard in resolved.parents
                   for guard in _protected_tool_paths(root)):
                # Writing the inventory over a manifest or a stored batch would
                # destroy the only record needed to restore the quarantined files.
                print(json.dumps({"error": "output-path-inside-tool-state",
                                  "path": str(target)}))
                return 1
            if Path(target).is_symlink() or Path(target).exists():
                print(json.dumps({"error": "refusing-to-overwrite", "path": str(target)}))
                return 1
        report = audit(root)
        selection = {"schema_version": SELECTION_SCHEMA_VERSION,
                     "entries": report["quarantine_candidates"]}
        if args.quarantine_list is not None:
            _write_user_file(args.quarantine_list, json.dumps(selection, indent=2) + "\n")
        if args.apply is not None:
            try:
                payload = json.loads(Path(args.apply).read_bytes().decode("utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
                raise AuditError("unreadable-selection") from error
            entries = payload["entries"] if isinstance(payload, dict) else payload
            if args.batch is not None:
                # Resolve the batch artifact paths before moving anything, so an
                # unusable runs/repository-audit location cannot leave the tree
                # half-quarantined.
                for name in ("inventory.json", "quarantine-candidates.json"):
                    target = _safe_output_path(
                        root, AUDIT_DIRNAME + "/" + args.batch + "/" + name)
                    if target.exists() or target.is_symlink():
                        raise AuditError("refusing-to-overwrite:" + name)
            manifest = quarantine(root, entries, args.batch, selection_source=args.apply)
            # Record the batch only once the move actually succeeded, so a
            # rejected selection does not burn the batch name.
            warning = None
            if args.batch is not None:
                try:
                    _write_new(root, AUDIT_DIRNAME + "/" + args.batch + "/inventory.json", report)
                    _write_new(root, AUDIT_DIRNAME + "/" + args.batch
                               + "/quarantine-candidates.json", selection)
                except (AuditError, OSError) as error:
                    # The move already happened and its manifest exists, so the
                    # command succeeded; only the bookkeeping write failed.
                    warning = "batch-bookkeeping-failed:" + str(error)
            if args.output is not None:
                _write_user_file(args.output, json.dumps(report, indent=2) + "\n")
            result = {"manifest": str(manifest)}
            if warning is not None:
                result["warning"] = warning
            print(json.dumps(result))
            return 0
        if args.output is not None:
            _write_user_file(args.output, json.dumps(report, indent=2) + "\n")
        print(json.dumps(report["summary"], sort_keys=True))
        return 0
    except (AuditError, OSError, KeyError, TypeError, ValueError, UnicodeDecodeError) as error:
        print(json.dumps({"error": str(error)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
