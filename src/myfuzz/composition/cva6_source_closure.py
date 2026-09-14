"""Resolve the pinned CVA6 filelist without consulting floating sources.

The CVA6 checkout uses a Verilog filelist with one nested HPDcache filelist
and repository variables.  A plain ``verilator -f core/Flist.cva6`` is not a
reproducible boundary when invoked from another working directory, and it can
also accidentally select a different ``TARGET_CFG`` package.  This module
expands only the variables declared by ``sources.lock.json``, verifies the
pinned root and nested git revisions, and returns an ordered, base-relative
closure suitable for a compiler command.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any


class Cva6SourceClosureError(ValueError):
    """The pinned CVA6 source boundary is absent, ambiguous, or unsafe."""


_VARIABLE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")


def _fail(reason: str) -> None:
    raise Cva6SourceClosureError(reason)


def _safe_relative(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        _fail(f"{label}:unsafe-path")
    path = Path(value)
    # ``Path`` normalizes ``.`` while parsing, so inspect ``..`` after
    # normalization and reject the empty/current-directory path explicitly.
    # A leading ``./`` is harmless in a filelist; publishing the normalized
    # spelling keeps the closure independent of that cosmetic variation.
    if path.is_absolute() or not path.parts or ".." in path.parts:
        _fail(f"{label}:unsafe-path")
    normalized = Path(*path.parts)
    if normalized == Path("."):
        _fail(f"{label}:unsafe-path")
    return normalized.as_posix()


def _expand(value: str, variables: dict[str, str], label: str) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        if name not in variables:
            _fail(f"{label}:undeclared-variable:{name}")
        return variables[name]

    expanded = _VARIABLE.sub(replace, value)
    if "$" in expanded:
        _fail(f"{label}:unexpanded-variable")
    return expanded


def _git_revision(root: Path, label: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        _fail(f"{label}:not-git")
    return result.stdout.strip()


def _gitlink_revision(repository: Path, relative: str, label: str) -> str:
    """Read a declared submodule's commit from its parent tree."""
    result = subprocess.run(
        ["git", "-C", str(repository), "ls-tree", "-z", "HEAD", "--", relative],
        capture_output=True, check=False,
    )
    if result.returncode != 0:
        _fail(f"{label}:parent-not-git")
    entries = [entry for entry in result.stdout.split(b"\x00") if entry]
    if len(entries) != 1 or b"\t" not in entries[0]:
        _fail(f"{label}:parent-gitlink-missing")
    header, _path = entries[0].split(b"\t", 1)
    fields = header.decode("ascii", errors="strict").split()
    if len(fields) != 3 or fields[0] != "160000" or fields[1] != "commit":
        _fail(f"{label}:parent-gitlink-type")
    return fields[2]


def _load_source_record(base_dir: Path, lock_path: Path) -> dict[str, Any]:
    try:
        document = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise Cva6SourceClosureError("cva6-source-lock:unreadable") from error
    components = document.get("components") if isinstance(document, dict) else None
    if not isinstance(components, list):
        _fail("cva6-source-lock:components")
    record = next((item for item in components
                   if isinstance(item, dict) and item.get("id") == "cva6"), None)
    if not isinstance(record, dict) or not isinstance(record.get("source"), dict):
        _fail("cva6-source-lock:record")
    source = record["source"]
    if source.get("top_module") != "cva6" or source.get("filelist") != "core/Flist.cva6":
        _fail("cva6-source-lock:top-or-filelist")
    return source


def _root_path(base_dir: Path, source_root: object) -> Path:
    relative = _safe_relative(source_root, "cva6-source-root")
    base = base_dir.resolve()
    candidate = base / relative
    if candidate.is_symlink():
        _fail("cva6-source-root:symlink")
    root = candidate.resolve()
    try:
        root.relative_to(base)
    except ValueError:
        _fail("cva6-source-root:outside-base")
    if not root.is_dir() or root.is_symlink():
        _fail("cva6-source-root:missing")
    return root


def _flatten_filelist(root: Path, filelist: Path, variables: dict[str, str]) -> tuple[list[Path], list[Path], list[str]]:
    sources: list[Path] = []
    includes: list[Path] = []
    defines: list[str] = []
    source_seen: set[Path] = set()
    include_seen: set[Path] = set()
    active: set[Path] = set()

    def resolve_path(raw: str, label: str) -> Path:
        normalized = _safe_relative(_expand(raw, variables, label), label)
        candidate_path = root / normalized
        if candidate_path.is_symlink():
            _fail(f"{label}:symlink")
        candidate = candidate_path.resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            _fail(f"{label}:outside-root")
        return candidate

    def visit(path: Path) -> None:
        path = path.resolve()
        if path in active:
            _fail("cva6-filelist:include-cycle")
        if not path.is_file() or path.is_symlink():
            _fail(f"cva6-filelist:missing:{path.relative_to(root).as_posix()}")
        active.add(path)
        try:
            for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                line = raw_line.strip()
                if not line or line.startswith(("#", "//", "/*")):
                    continue
                if line.startswith("-F"):
                    nested = line[2:].strip()
                    if not nested:
                        _fail(f"cva6-filelist:empty-include:{line_number}")
                    visit(resolve_path(nested, f"cva6-filelist:{line_number}"))
                    continue
                if line.startswith("+incdir+"):
                    values = line[len("+incdir+"):].split("+")
                    if not values or any(not item for item in values):
                        _fail(f"cva6-filelist:invalid-include:{line_number}")
                    for item in values:
                        include = resolve_path(item, f"cva6-filelist:{line_number}")
                        if not include.is_dir() or include.is_symlink():
                            _fail(f"cva6-filelist:include-missing:{item}")
                        if include not in include_seen:
                            include_seen.add(include)
                            includes.append(include)
                    continue
                if line.startswith("+define+"):
                    payload = line[len("+define+"):]
                    if not payload or any(not part for part in payload.split("+")):
                        _fail(f"cva6-filelist:invalid-define:{line_number}")
                    defines.append(line)
                    continue
                if line.startswith("-"):
                    _fail(f"cva6-filelist:unsupported-option:{line}")
                source = resolve_path(line, f"cva6-filelist:{line_number}")
                if not source.is_file() or source.is_symlink():
                    _fail(f"cva6-filelist:source-missing:{line}")
                if source not in source_seen:
                    source_seen.add(source)
                    sources.append(source)
        except UnicodeDecodeError as error:
            raise Cva6SourceClosureError(f"cva6-filelist:invalid-utf8:{path}") from error
        finally:
            active.remove(path)

    visit(filelist)
    return sources, includes, defines


def _base_relative(base: Path, paths: list[Path]) -> list[str]:
    return [path.relative_to(base).as_posix() for path in paths]


def resolve_cva6_source_closure(
    base_dir: str | Path,
    *,
    lock_path: str | Path | None = None,
) -> dict[str, object]:
    """Return an ordered, pinned CVA6 closure for a compiler invocation.

    The returned paths are all relative to ``base_dir``.  No network or
    generator is invoked; a missing checkout, nested pin, or undeclared
    filelist variable is an explicit error.
    """
    base = Path(base_dir).resolve()
    lock = (base / "configs/soc/sources.lock.json" if lock_path is None
            else (base / lock_path if not Path(lock_path).is_absolute() else Path(lock_path))).resolve()
    source = _load_source_record(base, lock)
    root = _root_path(base, source.get("root"))
    root_revision = source.get("revision")
    if not isinstance(root_revision, str) or not root_revision.startswith("git:"):
        _fail("cva6-source-lock:root-revision")
    actual_root_revision = _git_revision(root, "cva6-source-root")
    if actual_root_revision != root_revision[4:]:
        _fail("cva6-source-lock:root-revision-mismatch")

    variables_raw = source.get("filelist_variables", [])
    if not isinstance(variables_raw, list):
        _fail("cva6-source-lock:filelist-variables")
    variables: dict[str, str] = {}
    for item in variables_raw:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("value"), str):
            _fail("cva6-source-lock:filelist-variable")
        name, value = item["name"], item["value"]
        if not _SAFE_COMPONENT.fullmatch(name):
            _fail("cva6-source-lock:filelist-variable-name")
        variables[name] = value
    target_cfg = variables.get("TARGET_CFG")
    if target_cfg != "cv64a6_imafdc_sv39":
        _fail("cva6-source-lock:target-config")
    filelist = root / _safe_relative(source.get("filelist"), "cva6-filelist")
    if not filelist.is_file():
        _fail("cva6-filelist:missing")
    sources, includes, defines = _flatten_filelist(root, filelist, variables)

    nested: list[dict[str, str]] = []
    repositories = source.get("repositories", [])
    if not isinstance(repositories, list) or not repositories:
        _fail("cva6-source-lock:nested-repositories")
    nested_specs: list[tuple[str, str]] = []
    nested_seen: set[str] = set()
    for item in repositories:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not isinstance(item.get("revision"), str):
            _fail("cva6-source-lock:nested-pin")
        relative = _safe_relative(item["path"], "cva6-nested-pin")
        expected = item["revision"]
        if not expected.startswith("git:"):
            _fail("cva6-source-lock:nested-revision")
        if relative in nested_seen:
            _fail("cva6-source-lock:nested-duplicate")
        nested_seen.add(relative)
        nested_specs.append((relative, expected[4:]))

    # Validate both the checked-out child and the commit recorded by its
    # parent tree.  Checking only ``child/.git/HEAD`` would allow a detached
    # checkout to disagree with the parent revision recorded by the lock.
    verified_nested: dict[str, str] = {}
    for relative, expected_revision in sorted(nested_specs, key=lambda item: (item[0].count("/"), item[0])):
        child_path = root / relative
        if child_path.is_symlink():
            _fail(f"cva6-source-lock:nested-symlink:{relative}")
        child = child_path.resolve()
        try:
            child.relative_to(root)
        except ValueError:
            _fail("cva6-source-lock:nested-outside-root")
        if not child.is_dir() or child.is_symlink():
            _fail(f"cva6-source-lock:nested-missing:{relative}")
        if _git_revision(child, f"cva6-nested:{relative}") != expected_revision:
            _fail(f"cva6-source-lock:nested-revision-mismatch:{relative}")

        child_path = Path(relative)
        parent_relative = Path()
        for candidate, _candidate_revision in nested_specs:
            candidate_path = Path(candidate)
            if candidate_path == child_path:
                continue
            try:
                child_path.relative_to(candidate_path)
            except ValueError:
                continue
            if len(candidate_path.parts) > len(parent_relative.parts):
                parent_relative = candidate_path
        parent_repository = root / parent_relative
        link_relative = child_path.relative_to(parent_relative).as_posix()
        if _gitlink_revision(parent_repository, link_relative, f"cva6-nested:{relative}") != expected_revision:
            _fail(f"cva6-source-lock:nested-parent-mismatch:{relative}")
        verified_nested[relative] = expected_revision

    for relative, _expected_revision in nested_specs:
        nested.append({"path": relative, "revision": f"git:{verified_nested[relative]}"})

    base_relative_root = root.relative_to(base).as_posix()
    return {
        "schema_version": "cva6_source_closure.v1",
        "root": base_relative_root,
        "root_revision": root_revision,
        "nested_repositories": nested,
        "top_module": "cva6",
        "target_cfg": target_cfg,
        "include_dirs": _base_relative(base, includes),
        "defines": defines,
        "source_files": _base_relative(base, sources),
    }


__all__ = ["Cva6SourceClosureError", "resolve_cva6_source_closure"]
