#!/usr/bin/env python3
"""Flatten a variable-bearing HDL filelist into a contained deterministic filelist."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shlex
from typing import Mapping


_VARIABLE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_VARIABLE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class FilelistMaterializationError(ValueError):
    pass


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _expand(value: str, variables: Mapping[str, str], path: str) -> str:
    names = set(_VARIABLE.findall(value))
    unknown = names - set(variables)
    if unknown:
        raise FilelistMaterializationError(
            f"{path}: unknown variable(s): {', '.join(sorted(unknown))}"
        )
    result = _VARIABLE.sub(lambda match: variables[match.group(1)], value)
    if "$" in result:
        raise FilelistMaterializationError(f"{path}: unsupported variable expression {value!r}")
    return result


def materialize_filelist(
    source: Path, source_root: Path, output: Path, variables: Mapping[str, str],
    *, max_depth: int = 16,
) -> int:
    source_root = source_root.resolve(strict=True)
    source = source.resolve(strict=True)
    output = output.resolve()
    if not _inside(source, source_root):
        raise FilelistMaterializationError("source filelist is outside source root")
    if output.exists():
        raise FilelistMaterializationError(f"output already exists: {output}")
    if any(not _VARIABLE_NAME.fullmatch(name) or not isinstance(value, str) or not value
           for name, value in variables.items()):
        raise FilelistMaterializationError("variables must have identifier keys and non-empty values")

    include_dirs: set[Path] = set()
    defines: set[str] = set()
    sources: list[Path] = []
    active: set[Path] = set()

    def contained(value: str, base: Path, path: str) -> Path:
        candidate = Path(value)
        candidate = candidate if candidate.is_absolute() else base / candidate
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise FilelistMaterializationError(f"{path}: cannot resolve {candidate}: {exc}") from exc
        if not _inside(resolved, source_root):
            raise FilelistMaterializationError(f"{path}: path escapes source root: {resolved}")
        return resolved

    def walk(filelist: Path, depth: int) -> None:
        if depth > max_depth:
            raise FilelistMaterializationError("nested filelist depth exceeds limit")
        if filelist in active:
            raise FilelistMaterializationError(f"nested filelist cycle at {filelist}")
        active.add(filelist)
        try:
            text = filelist.read_text(encoding="utf-8")
            tokens: list[str] = []
            for line_number, line in enumerate(text.splitlines(), 1):
                content = line.split("//", 1)[0]
                try:
                    tokens.extend(shlex.split(content, comments=True, posix=True))
                except ValueError as exc:
                    raise FilelistMaterializationError(
                        f"{filelist}:{line_number}: invalid filelist syntax: {exc}"
                    ) from exc
            index = 0
            while index < len(tokens):
                token = _expand(tokens[index], variables, str(filelist))
                if token in {"-f", "-F"}:
                    index += 1
                    if index >= len(tokens):
                        raise FilelistMaterializationError(f"{filelist}: {token} requires a path")
                    nested = _expand(tokens[index], variables, str(filelist))
                    walk(contained(nested, filelist.parent, str(filelist)), depth + 1)
                elif token.startswith("-f") and len(token) > 2:
                    walk(contained(token[2:], filelist.parent, str(filelist)), depth + 1)
                elif token.startswith("+incdir+"):
                    values = token[len("+incdir+"):].split("+")
                    include_dirs.update(contained(item, filelist.parent, str(filelist)) for item in values)
                elif token == "-I":
                    index += 1
                    if index >= len(tokens):
                        raise FilelistMaterializationError(f"{filelist}: -I requires a path")
                    value = _expand(tokens[index], variables, str(filelist))
                    include_dirs.add(contained(value, filelist.parent, str(filelist)))
                elif token.startswith("-I"):
                    include_dirs.add(contained(token[2:], filelist.parent, str(filelist)))
                elif token.startswith("+define+"):
                    defines.update(item for item in token[len("+define+"):].split("+") if item)
                elif token.startswith("-D") and len(token) > 2:
                    defines.add(token[2:])
                elif token.startswith(("+", "-")):
                    raise FilelistMaterializationError(
                        f"{filelist}: unsupported filelist option {token!r}"
                    )
                else:
                    resolved = contained(token, filelist.parent, str(filelist))
                    if not resolved.is_file():
                        raise FilelistMaterializationError(f"{filelist}: source is not a file: {resolved}")
                    if resolved not in sources:
                        sources.append(resolved)
                index += 1
        finally:
            active.remove(filelist)

    walk(source, 1)
    if not sources:
        raise FilelistMaterializationError("materialized filelist contains no RTL sources")
    output.parent.mkdir(parents=True, exist_ok=True)
    relative = lambda path: Path(os.path.relpath(path, output.parent)).as_posix()
    lines = [f"+define+{shlex.quote(item)}" for item in sorted(defines)]
    lines.extend(f"+incdir+{shlex.quote(relative(item))}" for item in sorted(include_dirs))
    lines.extend(shlex.quote(relative(item)) for item in sources)
    output.write_text("\n".join(lines) + "\n", encoding="ascii")
    return len(sources)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--variable", action="append", default=[], metavar="NAME=VALUE")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    variables: dict[str, str] = {}
    for item in args.variable:
        name, separator, value = item.partition("=")
        if not separator or name in variables:
            raise FilelistMaterializationError(f"invalid or duplicate variable assignment {item!r}")
        variables[name] = value
    count = materialize_filelist(args.source, args.source_root, args.output, variables)
    print(f"wrote {args.output}: {count} compile sources")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FilelistMaterializationError as exc:
        raise SystemExit(f"compose-v5 filelist materialization: {exc}") from exc
