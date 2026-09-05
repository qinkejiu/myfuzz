#!/usr/bin/env python3
"""Generate deterministic, reparsed Top-K composition candidates."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.as_posix() not in sys.path:
    sys.path.insert(0, SRC.as_posix())

from myfuzz.composition import write_protocol_composition  # noqa: E402
from myfuzz.scripts.composition_api import generate_compositions  # noqa: E402


_PROTOCOL_SUMMARY_KEYS = (
    "schema_version",
    "manifest_hash",
    "ir_path",
    "wrapper_path",
    "source_list_path",
    "complete",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate deterministic protocol-composition sources or reparse "
            "Top-K composition candidates."
        )
    )
    parser.add_argument("--config", type=Path, help="legacy declaration config")
    parser.add_argument("--frontend", type=Path, help="legacy HDL facts")
    parser.add_argument("--top-k", type=int, help="legacy candidate count")
    parser.add_argument("--protocol-manifest", type=Path, help="protocol_composition.v1 manifest")
    parser.add_argument("--out-dir", type=Path, help="directory for generated files")
    parser.add_argument(
        "--root",
        type=Path,
        help="repository root used to resolve protocol sources (default: script repository)",
    )
    parser.add_argument("--frontend-library", type=Path)
    args = parser.parse_args()
    try:
        _validate_mode_arguments(args)
    except ValueError as error:
        parser.error(str(error))
    return args


def _validate_mode_arguments(args: argparse.Namespace) -> None:
    protocol_manifest = getattr(args, "protocol_manifest", None)
    legacy_values = {
        "--config": getattr(args, "config", None),
        "--frontend": getattr(args, "frontend", None),
        "--top-k": getattr(args, "top_k", None),
        "--frontend-library": getattr(args, "frontend_library", None),
    }
    if protocol_manifest is not None:
        if any(value is not None for value in legacy_values.values()):
            raise ValueError("--protocol-manifest cannot be combined with legacy options")
    else:
        if getattr(args, "root", None) is not None:
            raise ValueError("--root requires --protocol-manifest")
        missing = [
            name
            for name in ("--config", "--frontend", "--top-k")
            if getattr(args, name[2:].replace("-", "_"), None) is None
        ]
        if missing:
            raise ValueError("legacy mode requires " + ", ".join(missing))

    if getattr(args, "out_dir", None) is None:
        raise ValueError("--out-dir is required")


def _resolve_from_root(root: Path, value: Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = root / path
    return path.resolve()


def _validate_protocol_summary(summary: object) -> dict[str, object]:
    if not isinstance(summary, Mapping):
        raise ValueError("protocol composition summary must be an object")
    missing = [key for key in _PROTOCOL_SUMMARY_KEYS if key not in summary]
    if missing:
        raise ValueError(
            "protocol composition summary missing keys: " + ", ".join(missing)
        )
    for key in ("schema_version", "manifest_hash", "ir_path", "wrapper_path", "source_list_path"):
        value = summary[key]
        if not isinstance(value, str) or not value:
            raise ValueError(f"protocol composition summary {key} must be a non-empty string")
    if not isinstance(summary["complete"], bool):
        raise ValueError("protocol composition summary complete must be boolean")
    return dict(summary)


def main() -> int:
    args = parse_args()
    try:
        _validate_mode_arguments(args)
        protocol_manifest = getattr(args, "protocol_manifest", None)
        if protocol_manifest is not None:
            root_value = ROOT if getattr(args, "root", None) is None else args.root
            root = _resolve_from_root(Path.cwd(), root_value)
            manifest_path = _resolve_from_root(root, protocol_manifest)
            output_path = _resolve_from_root(root, args.out_dir)
            summary = _validate_protocol_summary(
                write_protocol_composition(manifest_path, output_path, root=root)
            )
        else:
            if args.config is None or args.frontend is None or args.top_k is None:
                raise ValueError("legacy mode requires --config, --frontend, and --top-k")
            summary = generate_compositions(
                args.config,
                args.frontend,
                args.top_k,
                args.out_dir,
                frontend_library=args.frontend_library,
            )
    except (OSError, RuntimeError, ValueError) as error:
        print(f"composition generation failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(summary, ensure_ascii=True, sort_keys=True))
    return 0 if summary.get("complete") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
