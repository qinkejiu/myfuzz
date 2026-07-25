#!/usr/bin/env python3
"""Resolve the pinned OpenTitan RTL closure for the real common-IP target."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
import re
import subprocess
import sys

import yaml


EXPECTED_OPENTITAN_REVISION = "13a8919bceac625dbd1b6ad804e62f9bdeadee86"
ROOT_CORES = (
    "lowrisc:ip:uart",
    "lowrisc:earlgrey_ip:gpio",
    "lowrisc:ip:rv_timer",
)
VIRTUAL_PROVIDERS = {
    "lowrisc:virtual_constants:top_pkg": "lowrisc:earlgrey_constants:top_pkg",
    "lowrisc:virtual_constants:top_racl_pkg": "lowrisc:earlgrey_constants:top_racl_pkg",
}
MAPPING_CORES = (
    "lowrisc:systems:top_earlgrey",
    "lowrisc:prim_generic:all",
)
SOURCE_SUFFIXES = frozenset({".sv", ".v"})
HEADER_SUFFIXES = frozenset({".svh", ".vh"})


def read_revision(repository: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _core_key(value: str) -> str:
    match = re.match(r"^([^:\s]+):([^:\s]+):([^:\s]+)", value.strip())
    if not match:
        raise RuntimeError(f"invalid FuseSoC core identifier: {value!r}")
    return ":".join(match.groups())


def _load_core(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if text.startswith("CAPI=2:"):
        text = text.split("\n", 1)[1]
    document = yaml.safe_load(text)
    if not isinstance(document, dict) or "name" not in document:
        raise RuntimeError(f"invalid CAPI2 core: {path}")
    return document


def _build_index(opentitan_root: Path) -> dict[str, tuple[Path, dict]]:
    index: dict[str, tuple[Path, dict]] = {}
    for path in sorted(opentitan_root.rglob("*.core")):
        document = _load_core(path)
        key = _core_key(str(document["name"]))
        if key in index:
            previous = index[key][0]
            raise RuntimeError(f"duplicate FuseSoC core {key}: {previous}, {path}")
        index[key] = (path, document)
    return index


def _default_filesets(document: dict) -> tuple[str, ...]:
    targets = document.get("targets", {})
    target = targets.get("default", {}) if isinstance(targets, dict) else {}
    raw = target.get("filesets", ()) if isinstance(target, dict) else ()
    names: list[str] = []
    for item in raw or ():
        name = str(item).strip()
        if "?" not in name:
            names.append(name)
    return tuple(names)


def _file_path(item: object) -> tuple[str, bool]:
    if isinstance(item, str):
        return item, False
    if isinstance(item, dict) and len(item) == 1:
        name, attributes = next(iter(item.items()))
        is_include = isinstance(attributes, dict) and bool(attributes.get("is_include_file"))
        return str(name), is_include
    raise RuntimeError(f"unsupported FuseSoC file entry: {item!r}")


def resolve_synthesizable_core_closure(
    opentitan_root: Path,
    root_cores: tuple[str, ...] = ROOT_CORES,
) -> tuple[Path, ...]:
    index = _build_index(opentitan_root)
    providers = dict(VIRTUAL_PROVIDERS)
    for mapping_core in MAPPING_CORES:
        mapping_key = _core_key(mapping_core)
        if mapping_key not in index:
            raise RuntimeError(f"missing FuseSoC mapping core: {mapping_key}")
        mapping = index[mapping_key][1].get("mapping", {})
        if not isinstance(mapping, dict):
            raise RuntimeError(f"invalid FuseSoC mapping in {index[mapping_key][0]}")
        for virtual, provider in mapping.items():
            providers[_core_key(str(virtual))] = _core_key(str(provider))
    resolved: list[Path] = []
    visited: set[str] = set()
    visiting: set[str] = set()

    def visit(requested_key: str) -> None:
        requested = _core_key(requested_key)
        key = providers.get(requested, requested)
        if key in visited:
            return
        if key in visiting:
            raise RuntimeError(f"FuseSoC dependency cycle at {key}")
        if key not in index:
            raise RuntimeError(f"missing FuseSoC dependency: {key}")
        visiting.add(key)
        core_path, document = index[key]
        filesets = document.get("filesets", {})
        if not isinstance(filesets, dict):
            raise RuntimeError(f"invalid filesets in {core_path}")
        for fileset_name in _default_filesets(document):
            fileset = filesets.get(fileset_name)
            if not isinstance(fileset, dict):
                raise RuntimeError(f"missing fileset {fileset_name!r} in {core_path}")
            for dependency in fileset.get("depend", ()) or ():
                visit(str(dependency))
            for entry in fileset.get("files", ()) or ():
                relative, is_include = _file_path(entry)
                path = (core_path.parent / relative).resolve()
                if not path.is_file():
                    raise RuntimeError(f"missing FuseSoC source: {path}")
                if not is_include and path.suffix in SOURCE_SUFFIXES and path not in resolved:
                    resolved.append(path)
                if is_include and path.suffix not in SOURCE_SUFFIXES | HEADER_SUFFIXES:
                    raise RuntimeError(f"unsupported include file: {path}")
        visiting.remove(key)
        visited.add(key)

    for root_core in root_cores:
        visit(root_core)
    return tuple(resolved)


def _relative(repo_root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError as error:
        raise RuntimeError(f"source escapes repository root: {path}") from error


def write_relative_flist(repo_root: Path, sources: tuple[Path, ...]) -> Path:
    target = repo_root / "configs/designs/ibex_opentitan_real_ip/rtl/opentitan_sources.f"
    target.parent.mkdir(parents=True, exist_ok=True)
    include_dirs = sorted({path.parent for path in sources})
    lines = [f"+incdir+{_relative(repo_root, path)}" for path in include_dirs]
    lines.extend(_relative(repo_root, path) for path in sources)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return target


def prepare_sources(
    repo_root: Path,
    revision_reader: Callable[[Path], str] = read_revision,
) -> tuple[Path, ...]:
    opentitan_root = repo_root / "external_designs/opentitan"
    actual_revision = revision_reader(opentitan_root)
    if actual_revision != EXPECTED_OPENTITAN_REVISION:
        raise RuntimeError(
            f"OpenTitan revision {actual_revision!r}, expected "
            f"{EXPECTED_OPENTITAN_REVISION}"
        )
    sources = resolve_synthesizable_core_closure(opentitan_root)
    required = {"uart.sv", "gpio.sv", "rv_timer.sv"}
    if not required.issubset({path.name for path in sources}):
        raise RuntimeError("official OpenTitan IP tops are incomplete")
    write_relative_flist(repo_root, sources)
    return sources


def main() -> int:
    repo_root = Path(__file__).resolve().parents[4]
    sources = prepare_sources(repo_root)
    categories = {
        "uart": sum("/hw/ip/uart/" in path.as_posix() for path in sources),
        "gpio": sum("/ip_autogen/gpio/" in path.as_posix() for path in sources),
        "rv_timer": sum("/hw/ip/rv_timer/" in path.as_posix() for path in sources),
        "prim": sum("/hw/ip/prim/" in path.as_posix() for path in sources),
        "tlul": sum("/hw/ip/tlul/" in path.as_posix() for path in sources),
    }
    counts = " ".join(f"{name}={count}" for name, count in categories.items())
    print(f"OpenTitan {EXPECTED_OPENTITAN_REVISION}: sources={len(sources)} {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
