#!/usr/bin/env python3
"""Create a contained FuseSoC source view with compatible CAPI2 metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
from typing import Mapping

import yaml


class FuseSoCViewError(ValueError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_digest(root: Path, *, include_core: bool) -> tuple[str, int]:
    digest = hashlib.sha256()
    count = 0
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if ".git" in relative.parts or (not include_core and path.suffix == ".core"):
            continue
        encoded = relative.as_posix().encode("utf-8")
        if path.is_symlink():
            target = path.readlink().as_posix().encode("utf-8")
            digest.update(b"L")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
            digest.update(len(target).to_bytes(8, "big"))
            digest.update(target)
            count += 1
            continue
        if not path.is_file():
            continue
        digest.update(b"F")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        count += 1
    return digest.hexdigest(), count


def _validate_symlinks(root: Path) -> None:
    for path in sorted(item for item in root.rglob("*") if item.is_symlink()):
        try:
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise FuseSoCViewError(f"invalid symlink {path}: {exc}") from exc
        if resolved != root and root not in resolved.parents:
            raise FuseSoCViewError(f"symlink escapes source root: {path}")


def _load_core(path: Path) -> Mapping[str, object]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FuseSoCViewError(f"cannot read {path}: {exc}") from exc
    first, separator, body = text.partition("\n")
    if first.strip() != "CAPI=2:" or not separator:
        raise FuseSoCViewError(f"unsupported core header in {path}")
    try:
        value = yaml.safe_load(body)
    except yaml.YAMLError as exc:
        raise FuseSoCViewError(f"invalid core metadata in {path}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise FuseSoCViewError(f"core metadata must be an object: {path}")
    return value


def _normalize_core(path: Path) -> tuple[dict[str, object], tuple[str, ...]]:
    value = dict(_load_core(path))
    filesets = value.get("filesets")
    if filesets is None:
        return value, ()
    if not isinstance(filesets, Mapping):
        raise FuseSoCViewError(f"filesets must be an object: {path}")
    normalized_filesets: dict[str, object] = {}
    changes: list[str] = []
    for raw_name, raw_fileset in filesets.items():
        name = str(raw_name)
        if not isinstance(raw_fileset, Mapping):
            raise FuseSoCViewError(f"fileset {name} must be an object: {path}")
        fileset = dict(raw_fileset)
        if fileset.get("files") == []:
            del fileset["files"]
            changes.append(f"filesets.{name}.files:remove-empty-array")
        normalized_filesets[name] = fileset
    value["filesets"] = normalized_filesets
    return value, tuple(changes)


def prepare_view(source: Path, destination: Path, report_path: Path) -> Mapping[str, object]:
    source = source.resolve()
    destination = destination.resolve()
    report_path = report_path.resolve()
    if not source.is_dir():
        raise FuseSoCViewError(f"source is not a directory: {source}")
    if destination.exists():
        raise FuseSoCViewError(f"destination already exists: {destination}")
    if source == destination or source in destination.parents or destination in source.parents:
        raise FuseSoCViewError("source and destination must not contain one another")

    _validate_symlinks(source)
    source_data_digest, source_data_files = _tree_digest(source, include_core=False)
    shutil.copytree(
        source, destination, symlinks=True, ignore=shutil.ignore_patterns(".git"),
    )
    _validate_symlinks(destination)

    transformations: list[dict[str, object]] = []
    for path in sorted(destination.rglob("*.core")):
        normalized, changes = _normalize_core(path)
        if not changes:
            continue
        before = _sha256(path)
        serialized = "CAPI=2:\n" + yaml.safe_dump(
            normalized, allow_unicode=False, sort_keys=False,
        )
        path.write_text(serialized, encoding="ascii")
        transformations.append({
            "path": path.relative_to(destination).as_posix(),
            "before_sha256": before,
            "after_sha256": _sha256(path),
            "changes": list(changes),
        })

    result_data_digest, result_data_files = _tree_digest(destination, include_core=False)
    if (source_data_digest, source_data_files) != (result_data_digest, result_data_files):
        raise FuseSoCViewError("non-core source bytes changed while preparing the view")

    report: dict[str, object] = {
        "schema": "myfuzz.compose-v5-fusesoc-view/v1",
        "source": str(source),
        "destination": str(destination),
        "non_core_file_count": source_data_files,
        "non_core_tree_sha256": source_data_digest,
        "transformations": transformations,
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii",
    )
    return report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = prepare_view(args.source, args.destination, args.report)
    print(
        f"prepared {report['destination']} with "
        f"{len(report['transformations'])} metadata normalization(s)"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FuseSoCViewError as exc:
        raise SystemExit(f"compose-v5 FuseSoC view: {exc}") from exc
