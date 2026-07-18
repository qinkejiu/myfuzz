#!/usr/bin/env python3
"""Convert a FuseSoC EDAM source graph into a contained compose-v5 filelist."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shlex

import yaml


class EdamError(ValueError):
    pass


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def convert_edam(edam_path: Path, source_root: Path, output: Path) -> int:
    edam_path = edam_path.resolve(strict=True)
    source_root = source_root.resolve(strict=True)
    output = output.resolve()
    try:
        value = yaml.safe_load(edam_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise EdamError(f"cannot read EDAM {edam_path}: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("files"), list):
        raise EdamError("EDAM must contain a files array")
    include_dirs: set[str] = set()
    sources: list[str] = []
    for index, item in enumerate(value["files"]):
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise EdamError(f"EDAM files[{index}] is not a source object")
        file_type = item.get("file_type")
        if file_type == "user":
            continue
        if file_type not in {"verilogSource", "systemVerilogSource"}:
            raise EdamError(f"EDAM files[{index}] has unsupported file_type {file_type!r}")
        path = (edam_path.parent / item["name"]).resolve(strict=True)
        if not _inside(path, source_root):
            raise EdamError(f"EDAM source escapes source root: {path}")
        relative = Path(os.path.relpath(path, output.parent)).as_posix()
        if item.get("is_include_file"):
            include_dirs.add(Path(os.path.relpath(path.parent, output.parent)).as_posix())
        elif relative not in sources:
            sources.append(relative)
    defines: list[str] = []
    parameters = value.get("parameters", {})
    if not isinstance(parameters, dict):
        raise EdamError("EDAM parameters must be an object")
    for name, parameter in sorted(parameters.items()):
        if not isinstance(name, str) or not isinstance(parameter, dict):
            raise EdamError("EDAM parameter entries must be named objects")
        parameter_type = parameter.get("paramtype")
        if parameter_type == "vlogdefine":
            default = parameter.get("default")
            if default is True:
                defines.append(name)
            elif default not in (False, None):
                defines.append(f"{name}={default}")
        elif parameter_type != "vlogparam":
            raise EdamError(f"EDAM parameter {name!r} has unsupported paramtype {parameter_type!r}")
    lines = [f"+define+{shlex.quote(item)}" for item in defines]
    lines.extend(f"+incdir+{shlex.quote(item)}" for item in sorted(include_dirs))
    lines.extend(shlex.quote(item) for item in sources)
    if not sources:
        raise EdamError("EDAM contains no compile sources")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="ascii")
    return len(sources)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--edam", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    count = convert_edam(args.edam, args.source_root, args.output)
    print(f"wrote {args.output}: {count} compile sources")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except EdamError as exc:
        raise SystemExit(f"compose-v5 EDAM conversion: {exc}") from exc
