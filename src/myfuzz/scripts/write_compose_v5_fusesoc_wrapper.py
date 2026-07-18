#!/usr/bin/env python3
"""Write a minimal CAPI2 wrapper target for a dependency with no toplevel."""

from __future__ import annotations

import argparse
from pathlib import Path
import re

import yaml


_VLNV = re.compile(r"^[A-Za-z0-9_.+-]+:[A-Za-z0-9_.+-]+:[A-Za-z0-9_.+-]+(?::[A-Za-z0-9_.+-]+)?$")
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")


class WrapperCoreError(ValueError):
    pass


def write_wrapper_core(
    output: Path, *, name: str, dependency: str, top_module: str,
) -> None:
    if not _VLNV.fullmatch(name):
        raise WrapperCoreError("wrapper name must be a CAPI2 VLNV")
    if not _VLNV.fullmatch(dependency):
        raise WrapperCoreError("dependency must be a CAPI2 VLNV")
    if not _IDENTIFIER.fullmatch(top_module):
        raise WrapperCoreError("top module must be a SystemVerilog identifier")
    if output.exists():
        raise WrapperCoreError(f"output already exists: {output}")
    value = {
        "name": name,
        "description": "myfuzz compose-v5 qualification metadata wrapper",
        "filesets": {"dependency": {"depend": [dependency]}},
        "targets": {
            "default": {
                "filesets": ["dependency"],
                "toplevel": top_module,
            }
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        "CAPI=2:\n" + yaml.safe_dump(value, allow_unicode=False, sort_keys=False),
        encoding="ascii",
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--dependency", required=True)
    parser.add_argument("--top-module", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    write_wrapper_core(
        args.output, name=args.name, dependency=args.dependency, top_module=args.top_module,
    )
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except WrapperCoreError as exc:
        raise SystemExit(f"compose-v5 FuseSoC wrapper: {exc}") from exc
