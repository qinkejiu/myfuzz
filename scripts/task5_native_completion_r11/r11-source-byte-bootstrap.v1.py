#!/usr/bin/env python3
"""Offline, current-working-tree source snapshot for the r11 package.

The snapshot is output/project; its complete inventory and source Git index
gitlinks are recorded under output/control. Git is read locally for gitlink
metadata only; it never supplies copied bytes. A failed output is consumed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys


SCHEMA = "r11_source_snapshot_map.v1"
MAP_RELATIVE = "control/source-snapshot-map.v1.json"
SUBMODULE_RELATIVE = "control/submodule-manifest.v1.json"
SUBMODULE_SCHEMA = "r11_submodule_manifest.v1"
CHUNK = 1024 * 1024
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class SnapshotError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SnapshotError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=True,
                       separators=(",", ":")) + "\n").encode("ascii")


def components(path: str) -> tuple[str, ...]:
    absolute = os.path.abspath(path)
    require(os.path.isabs(absolute), "path must be absolute")
    return tuple(part for part in absolute.split("/") if part)


def open_directory_chain(path: str) -> int:
    """Open an existing absolute directory without following any component."""
    fd = os.open("/", DIR_FLAGS)
    try:
        for part in components(path):
            child = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def mode(info: os.stat_result) -> int:
    return stat.S_IMODE(info.st_mode)


def same_identity(before: os.stat_result, after: os.stat_result) -> bool:
    return (before.st_dev, before.st_ino, before.st_mode,
            before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
                after.st_dev, after.st_ino, after.st_mode,
                after.st_size, after.st_mtime_ns, after.st_ctime_ns)


def relative_path(value: str) -> str:
    require(value != "" and not value.startswith("/") and
            not value.endswith("/") and "\\" not in value and
            "\x00" not in value,
            f"path must be relative POSIX path: {value!r}")
    parts = value.split("/")
    require(all(part not in ("", ".", "..") for part in parts),
            f"invalid exclude path: {value!r}")
    return value


def parse_excludes(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        path, separator, reason = value.partition("=")
        path = relative_path(path)
        require(not any(char in path for char in "*?[]{}"),
                f"exclude cannot contain wildcard syntax: {path!r}")
        require(separator and reason.strip(), f"exclude needs path=reason: {value!r}")
        require(path not in result, f"duplicate exclude: {path}")
        result[path] = reason.strip()
    for path in result:
        require(not any(path.startswith(parent + "/") for parent in result
                        if parent != path),
                f"exclude is below another excluded directory: {path}")
    return result


def open_regular(parent_fd: int, name: str, before: os.stat_result) -> int:
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
            f"source is not a singly linked regular file: {name}")
    fd = os.open(name, FILE_FLAGS, dir_fd=parent_fd)
    try:
        after = os.fstat(fd)
        require(same_identity(before, after) and after.st_nlink == 1,
                f"source file changed or is aliased: {name}")
        return fd
    except BaseException:
        os.close(fd)
        raise


def mkdir_open_exclusive(parent_fd: int, name: str) -> int:
    """Create beneath a held private parent; same-UID hostile races are out of scope.

    mkdirat does not return the created inode's fd. The parent ownership/mode
    check excludes other ordinary users from swapping the leaf between mkdirat
    and openat; a hostile concurrent writer with this effective UID is not
    distinguishable here and must be excluded by the caller's operating setup.
    """
    parent_before = os.fstat(parent_fd)
    require(stat.S_ISDIR(parent_before.st_mode) and
            parent_before.st_uid == os.geteuid() and
            not (stat.S_IMODE(parent_before.st_mode) & 0o022),
            "output parent must be owned by the effective UID and private")
    os.mkdir(name, 0o700, dir_fd=parent_fd)
    child = os.open(name, DIR_FLAGS, dir_fd=parent_fd)
    try:
        opened = os.fstat(child)
        readback = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        parent_after = os.fstat(parent_fd)
        require(stat.S_ISDIR(opened.st_mode) and
                opened.st_uid == os.geteuid() and
                stat.S_IMODE(opened.st_mode) == 0o700 and
                same_identity(opened, readback) and
                (parent_before.st_dev, parent_before.st_ino,
                 parent_before.st_uid, parent_before.st_mode) ==
                (parent_after.st_dev, parent_after.st_ino,
                 parent_after.st_uid, parent_after.st_mode),
                f"new directory changed: {name}")
        return child
    except BaseException:
        os.close(child)
        raise


def scan(root_fd: int, exclusions: dict[str, str],
         copy_fd: int | None = None) -> tuple[list[dict], list[dict]]:
    """Inventory one tree, optionally copying each entry to copy_fd."""
    entries: list[dict] = []
    omitted: list[dict] = []
    found_exclusions: set[str] = set()

    def visit(source_fd: int, target_fd: int | None, prefix: str) -> None:
        parent_before = os.fstat(source_fd)
        require(stat.S_ISDIR(parent_before.st_mode), f"not a directory: {prefix}")
        entries.append({"path": prefix or ".", "kind": "directory",
                        "mode": mode(parent_before)})
        with os.scandir(source_fd) as iterator:
            names = sorted(entry.name for entry in iterator)
        for name in names:
            require(name not in (".", "..") and "/" not in name,
                    "invalid directory entry")
            path = f"{prefix}/{name}" if prefix else name
            before = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
            if path in exclusions:
                found_exclusions.add(path)
                if stat.S_ISDIR(before.st_mode):
                    kind = "directory"
                elif stat.S_ISREG(before.st_mode):
                    kind = "file"
                elif stat.S_ISLNK(before.st_mode):
                    kind = "symlink"
                else:
                    raise SnapshotError(f"special file cannot be excluded: {path}")
                omitted.append({"path": path, "kind": kind,
                                "reason": exclusions[path]})
                continue
            if stat.S_ISDIR(before.st_mode):
                child = os.open(name, DIR_FLAGS, dir_fd=source_fd)
                try:
                    require(same_identity(before, os.fstat(child)),
                            f"directory changed: {path}")
                    copied = None
                    if target_fd is not None:
                        copied = mkdir_open_exclusive(target_fd, name)
                    try:
                        visit(child, copied, path)
                        require(same_identity(before, os.fstat(child)),
                                f"directory changed during copy: {path}")
                        if copied is not None:
                            os.fchmod(copied, mode(before))
                            os.fsync(copied)
                    finally:
                        if copied is not None:
                            os.close(copied)
                finally:
                    os.close(child)
            elif stat.S_ISREG(before.st_mode):
                source = open_regular(source_fd, name, before)
                try:
                    output = None
                    if target_fd is not None:
                        output = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                                         dir_fd=target_fd)
                    try:
                        hasher = hashlib.sha256()
                        size = 0
                        while True:
                            block = os.read(source, CHUNK)
                            if not block:
                                break
                            hasher.update(block)
                            size += len(block)
                            if output is not None:
                                view = memoryview(block)
                                while view:
                                    view = view[os.write(output, view):]
                        require(same_identity(before, os.fstat(source)) and
                                size == before.st_size, f"file changed: {path}")
                        if output is not None:
                            os.fchmod(output, mode(before))
                            os.fsync(output)
                        entries.append({"path": path, "kind": "file",
                                        "mode": mode(before), "size": size,
                                        "sha256": hasher.hexdigest()})
                    finally:
                        if output is not None:
                            os.close(output)
                finally:
                    os.close(source)
            elif stat.S_ISLNK(before.st_mode):
                require(before.st_nlink == 1, f"aliased symlink: {path}")
                target = os.readlink(name, dir_fd=source_fd)
                after = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
                require(same_identity(before, after) and after.st_nlink == 1,
                        f"symlink changed: {path}")
                if target_fd is not None:
                    os.symlink(target, name, dir_fd=target_fd)
                entries.append({"path": path, "kind": "symlink",
                                "mode": mode(before), "target": target})
            else:
                raise SnapshotError(f"special file in source tree: {path}")
        require(same_identity(parent_before, os.fstat(source_fd)),
                f"directory changed during scan: {prefix or '.'}")
        if target_fd is not None:
            os.fsync(target_fd)

    visit(root_fd, copy_fd, "")
    require(found_exclusions == set(exclusions),
            f"exclude path absent: {sorted(set(exclusions) - found_exclusions)}")
    entries.sort(key=lambda row: row["path"])
    omitted.sort(key=lambda row: row["path"])
    return entries, omitted


def assert_output_parent_outside_source(source_fd: int, parent_fd: int) -> None:
    """Reject aliases of every source directory, including excluded subtrees."""
    parent_ancestors: set[tuple[int, int]] = set()
    current = os.dup(parent_fd)
    try:
        while True:
            here = os.fstat(current)
            parent_ancestors.add((here.st_dev, here.st_ino))
            upper = os.open("..", DIR_FLAGS, dir_fd=current)
            try:
                upper_info = os.fstat(upper)
                at_root = ((upper_info.st_dev, upper_info.st_ino) ==
                           (here.st_dev, here.st_ino))
            except BaseException:
                os.close(upper)
                raise
            if at_root:
                os.close(upper)
                break
            os.close(current)
            current = upper
    finally:
        os.close(current)

    active: set[tuple[int, int]] = set()
    def visit(directory_fd: int, path: str) -> None:
        before = os.fstat(directory_fd)
        require(stat.S_ISDIR(before.st_mode), f"source directory changed: {path}")
        identity = (before.st_dev, before.st_ino)
        require(identity not in parent_ancestors,
                f"output parent aliases source directory: {path}")
        require(identity not in active,
                f"source directory bind-mount cycle: {path}")
        active.add(identity)
        try:
            with os.scandir(directory_fd) as iterator:
                names = sorted(entry.name for entry in iterator)
            for name in names:
                require(name not in ("", ".", "..") and "/" not in name,
                        f"invalid source directory entry: {path}")
                child_before = os.stat(name, dir_fd=directory_fd,
                                       follow_symlinks=False)
                if not stat.S_ISDIR(child_before.st_mode):
                    continue
                child_path = f"{path}/{name}" if path != "." else name
                child = os.open(name, DIR_FLAGS, dir_fd=directory_fd)
                try:
                    require(same_identity(child_before, os.fstat(child)),
                            f"source directory changed: {child_path}")
                    visit(child, child_path)
                    require(same_identity(child_before, os.fstat(child)),
                            f"source directory changed during alias scan: {child_path}")
                finally:
                    os.close(child)
            require(same_identity(before, os.fstat(directory_fd)),
                    f"source directory changed during alias scan: {path}")
        finally:
            active.remove(identity)

    visit(source_fd, ".")


def create_output(path: str, source_fd: int) -> int:
    absolute = os.path.abspath(path)
    parent, leaf = os.path.split(absolute)
    require(leaf not in ("", ".", ".."), "invalid output directory")
    parent_fd = open_directory_chain(parent)
    try:
        assert_output_parent_outside_source(source_fd, parent_fd)
        child = mkdir_open_exclusive(parent_fd, leaf)
        try:
            os.fsync(parent_fd)
            return child
        except BaseException:
            os.close(child)
            raise
    finally:
        os.close(parent_fd)


def write_exclusive(parent_fd: int, name: str, raw: bytes) -> None:
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
    try:
        view = memoryview(raw)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(parent_fd)


def projection_bytes(rows: list[dict]) -> bytes:
    """The controller's exact selected-entry canonicalization (no newline)."""
    return json.dumps(rows, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def local_git(root: str, *args: str, optional: bool = False) -> bytes | None:
    """Read repository metadata with no optional locks, hooks, or protocols."""
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("GIT_")}
    env.update({"GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1",
                "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull})
    command = ["git", "-C", root, "-c", "protocol.allow=never",
               "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
               *args]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=env, timeout=60,
                                check=False)
    except subprocess.TimeoutExpired as error:
        raise SnapshotError(f"local Git metadata read timed out: {args[0]}") from error
    if result.returncode != 0:
        if optional:
            return None
        raise SnapshotError(f"local Git metadata read failed: {args[0]}")
    return result.stdout


def commit_id(value: str) -> bool:
    return bool(re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value))


def gitlinks(root: str) -> list[tuple[str, str]]:
    top = local_git(root, "rev-parse", "--show-toplevel")
    require(top is not None and os.path.abspath(os.fsdecode(top).rstrip("\n")) == root,
            "source root is not the Git worktree root")
    raw = local_git(root, "ls-files", "--stage", "-z", "--")
    require(raw is not None and (not raw or raw.endswith(b"\0")),
            "invalid Git index output")
    result: list[tuple[str, str]] = []
    for record in raw.split(b"\0")[:-1]:
        header, separator, path_bytes = record.partition(b"\t")
        fields = header.split(b" ")
        require(separator and len(fields) == 3 and path_bytes,
                "invalid Git index entry")
        tracked_mode, sha_bytes, stage = fields
        require(stage == b"0", "unmerged Git index cannot be frozen")
        if tracked_mode != b"160000":
            continue
        path = relative_path(os.fsdecode(path_bytes))
        commit = sha_bytes.decode("ascii")
        require(commit_id(commit), f"invalid gitlink object ID: {path}")
        result.append((path, commit))
    result.sort()
    require([path for path, _ in result] ==
            sorted({path for path, _ in result}), "duplicate gitlink path")
    return result


def checked_out_head(root: str, path: str, selected: list[dict]) -> tuple[bool, str | None]:
    if not selected or selected[0]["path"] != path or selected[0]["kind"] != "directory":
        return False, None
    checkout = os.path.join(root, *path.split("/"))
    # The source scan has established directory, not symlink, ancestry.
    top = local_git(checkout, "rev-parse", "--show-toplevel", optional=True)
    if top is None or os.path.abspath(os.fsdecode(top).rstrip("\n")) != checkout:
        return False, None
    raw_head = local_git(checkout, "rev-parse", "HEAD", optional=True)
    if raw_head is None:
        return False, None
    head = raw_head.decode("ascii").strip()
    require(commit_id(head), f"invalid checkout HEAD: {path}")
    return True, head


def submodule_document(root: str, source_rows: list[dict]) -> dict:
    rows = []
    for path, commit in gitlinks(root):
        selected = [entry for entry in source_rows
                    if entry["path"] == path or entry["path"].startswith(path + "/")]
        checked_out, head = checked_out_head(root, path, selected)
        rows.append({"path": path, "tracked_mode": "160000",
                     "gitlink_commit": commit, "checked_out": checked_out,
                     "checked_out_head": head,
                     "selected_entries_sha256": digest(projection_bytes(selected)),
                     "selected_entries_count": len(selected)})
    return {"schema_version": SUBMODULE_SCHEMA, "entries": rows}


def require_git_metadata_excluded(source_rows: list[dict]) -> None:
    selected = [row["path"] for row in source_rows
                if row["path"].split("/")[-1] == ".git"]
    require(not selected,
            "Git metadata paths require explicit exact --exclude reasons: " +
            ", ".join(selected))


def validate_submodule_document(document: object, source_rows: list[dict]) -> int:
    require(type(document) is dict and set(document) ==
            {"schema_version", "entries"} and
            document["schema_version"] == SUBMODULE_SCHEMA and
            type(document["entries"]) is list, "invalid submodule manifest")
    paths = []
    required = {"path", "tracked_mode", "gitlink_commit", "checked_out",
                "checked_out_head", "selected_entries_sha256",
                "selected_entries_count"}
    for row in document["entries"]:
        require(type(row) is dict and set(row) == required,
                "invalid submodule manifest row")
        require(type(row["path"]) is str,
                "invalid submodule path")
        path = relative_path(row["path"])
        require(row["tracked_mode"] == "160000" and
                type(row["gitlink_commit"]) is str and
                commit_id(row["gitlink_commit"]) and
                type(row["checked_out"]) is bool and
                (row["checked_out_head"] is None if not row["checked_out"]
                 else type(row["checked_out_head"]) is str and
                 commit_id(row["checked_out_head"])) and
                type(row["selected_entries_count"]) is int and
                row["selected_entries_count"] >= 0 and
                type(row["selected_entries_sha256"]) is str and
                bool(re.fullmatch(r"[0-9a-f]{64}", row["selected_entries_sha256"])),
                f"invalid gitlink metadata: {path}")
        selected = [entry for entry in source_rows
                    if entry["path"] == path or entry["path"].startswith(path + "/")]
        require(len(selected) == row["selected_entries_count"] and
                digest(projection_bytes(selected)) == row["selected_entries_sha256"],
                f"gitlink selected entries differ: {path}")
        paths.append(path)
    require(paths == sorted(set(paths)), "gitlink paths are not unique and sorted")
    return len(paths)


def snapshot(root: str, output: str, exclusions: dict[str, str]) -> None:
    source = os.path.abspath(root)
    destination = os.path.abspath(output)
    require(source != "/" and destination != "/" and
            source != destination and
            os.path.commonpath((source, destination)) != source and
            os.path.commonpath((source, destination)) != destination,
            "source and output roots overlap")
    source_fd = open_directory_chain(source)
    try:
        before, omitted = scan(source_fd, exclusions)
        require_git_metadata_excluded(before)
        submodules_before = submodule_document(source, before)
        validate_submodule_document(submodules_before, before)
        output_fd = create_output(destination, source_fd)
        try:
            project_fd = mkdir_open_exclusive(output_fd, "project")
            try:
                copied, copied_omitted = scan(source_fd, exclusions, project_fd)
                require((copied, copied_omitted) == (before, omitted),
                        "source changed while copying")
                after, after_omitted = scan(source_fd, exclusions)
                require((after, after_omitted) == (before, omitted),
                        "source changed after copying")
                require(submodule_document(source, after) == submodules_before,
                        "Git index or checkout HEAD changed while copying")
                os.fchmod(project_fd, mode(os.fstat(source_fd)))
                os.fsync(project_fd)
                verified, verified_omitted = scan(project_fd, {})
                require(verified == before and verified_omitted == [],
                        "copied project does not match source map")
            finally:
                os.close(project_fd)
            control_fd = mkdir_open_exclusive(output_fd, "control")
            try:
                document = {"schema_version": SCHEMA, "source_root": source,
                            "entries": before, "exclusions": omitted}
                raw = json_bytes(document)
                submodule_raw = json_bytes(submodules_before)
                write_exclusive(control_fd, "source-snapshot-map.v1.json", raw)
                write_exclusive(control_fd, "submodule-manifest.v1.json",
                                submodule_raw)
            finally:
                os.close(control_fd)
            os.fsync(output_fd)
        finally:
            os.close(output_fd)
    finally:
        os.close(source_fd)
    print(json.dumps({"output": destination, "map": MAP_RELATIVE,
                      "map_sha256": digest(raw), "entries": len(before),
                      "exclusions": len(omitted),
                      "submodule_manifest": SUBMODULE_RELATIVE,
                      "submodule_manifest_sha256": digest(submodule_raw),
                      "submodules": len(submodules_before["entries"])},
                     sort_keys=True))


def validate_document(document: object) -> tuple[list[dict], list[dict]]:
    require(type(document) is dict and set(document) ==
            {"schema_version", "source_root", "entries", "exclusions"} and
            document["schema_version"] == SCHEMA and
            type(document["source_root"]) is str and
            os.path.isabs(document["source_root"]), "invalid map header")
    entries, exclusions = document["entries"], document["exclusions"]
    require(type(entries) is list and type(exclusions) is list, "invalid map arrays")
    paths: list[str] = []
    for row in entries:
        require(type(row) is dict and type(row.get("path")) is str and
                type(row.get("kind")) is str, "invalid map row")
        path, kind = row["path"], row["kind"]
        require(path == "." or relative_path(path) == path, "invalid map path")
        required = {"directory": {"path", "kind", "mode"},
                    "file": {"path", "kind", "mode", "size", "sha256"},
                    "symlink": {"path", "kind", "mode", "target"}}.get(kind)
        require(required is not None and set(row) == required,
                f"invalid map fields: {path}")
        require(type(row["mode"]) is int and 0 <= row["mode"] <= 0o7777,
                f"invalid mode: {path}")
        if kind == "file":
            require(type(row["size"]) is int and row["size"] >= 0 and
                    type(row["sha256"]) is str and len(row["sha256"]) == 64 and
                    all(c in "0123456789abcdef" for c in row["sha256"]),
                    f"invalid file metadata: {path}")
        if kind == "symlink":
            require(type(row["target"]) is str and row["target"] != "",
                    f"invalid symlink target: {path}")
        paths.append(path)
    require(paths == sorted(set(paths)) and paths and
            entries[0] == {"path": ".", "kind": "directory",
                           "mode": entries[0].get("mode")},
            "map entries are not complete and sorted")
    omitted_paths: list[str] = []
    for row in exclusions:
        require(type(row) is dict and set(row) == {"path", "kind", "reason"} and
                type(row["path"]) is str and relative_path(row["path"]) == row["path"] and
                row["kind"] in ("file", "directory", "symlink") and
                type(row["reason"]) is str and row["reason"].strip(),
                "invalid exclusion")
        omitted_paths.append(row["path"])
    require(omitted_paths == sorted(set(omitted_paths)),
            "exclusions are not unique and sorted")
    require(not set(paths).intersection(omitted_paths),
            "included and excluded paths overlap")
    return entries, exclusions


def read_control_file(control_fd: int, name: str) -> bytes:
    info = os.stat(name, dir_fd=control_fd, follow_symlinks=False)
    fd = open_regular(control_fd, name, info)
    with os.fdopen(fd, "rb") as stream:
        raw = stream.read()
    require(same_identity(info, os.stat(name, dir_fd=control_fd,
                                        follow_symlinks=False)),
            f"control file changed during read: {name}")
    return raw


def verify(output: str, expected_map_sha256: str | None,
           expected_submodule_sha256: str | None) -> None:
    output_fd = open_directory_chain(output)
    try:
        control_fd = os.open("control", DIR_FLAGS, dir_fd=output_fd)
        try:
            raw = read_control_file(control_fd, "source-snapshot-map.v1.json")
            submodule_raw = read_control_file(control_fd,
                                              "submodule-manifest.v1.json")
            with os.scandir(control_fd) as iterator:
                require(sorted(item.name for item in iterator) ==
                        ["source-snapshot-map.v1.json",
                         "submodule-manifest.v1.json"],
                        "control has unexpected entries")
        finally:
            os.close(control_fd)
        actual_sha = digest(raw)
        if expected_map_sha256 is not None:
            require(actual_sha == expected_map_sha256, "map digest differs from pin")
        actual_submodule_sha = digest(submodule_raw)
        if expected_submodule_sha256 is not None:
            require(actual_submodule_sha == expected_submodule_sha256,
                    "submodule manifest digest differs from pin")
        document = json.loads(raw)
        expected_entries, expected_omitted = validate_document(document)
        project_fd = os.open("project", DIR_FLAGS, dir_fd=output_fd)
        try:
            actual_entries, actual_omitted = scan(project_fd, {})
        finally:
            os.close(project_fd)
        require(actual_omitted == [] and actual_entries == expected_entries,
                "snapshot does not match complete map")
        submodules = validate_submodule_document(json.loads(submodule_raw),
                                                actual_entries)
        with os.scandir(output_fd) as iterator:
            require(sorted(item.name for item in iterator) == ["control", "project"],
                    "output root has unexpected entries")
    finally:
        os.close(output_fd)
    print(json.dumps({"output": os.path.abspath(output), "map_sha256": actual_sha,
                      "entries": len(expected_entries),
                      "exclusions": len(expected_omitted),
                      "submodule_manifest_sha256": actual_submodule_sha,
                      "submodules": submodules, "verified": True},
                     sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("snapshot", help="copy a current working tree once")
    build.add_argument("--root", required=True, help="existing source directory")
    build.add_argument("--output", required=True, help="new, absent output directory")
    build.add_argument("--exclude", action="append", default=[], metavar="PATH=REASON",
                       help="exact relative file or directory path and read-set reason")
    check = commands.add_parser("verify", help="independently rehash output/project")
    check.add_argument("--output", required=True)
    check.add_argument("--map-sha256", help="externally pinned raw map SHA-256")
    check.add_argument("--submodule-sha256",
                       help="externally pinned raw submodule manifest SHA-256")
    args = parser.parse_args()
    try:
        if args.command == "snapshot":
            snapshot(args.root, args.output, parse_excludes(args.exclude))
        else:
            for label, value in (("map", args.map_sha256),
                                 ("submodule", args.submodule_sha256)):
                if value is not None:
                    require(len(value) == 64 and
                            all(c in "0123456789abcdef" for c in value),
                            f"{label} pin must be lowercase SHA-256")
            verify(args.output, args.map_sha256, args.submodule_sha256)
    except (SnapshotError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"r11 source bootstrap: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
