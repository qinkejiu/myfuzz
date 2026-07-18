#!/usr/bin/env python3
"""Freeze selected repository artifacts into a deterministic SHA-256 inventory."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder.artifact_inventory import (  # noqa: E402
    artifact_inventory_from_dict, build_artifact_inventory,
    verify_artifact_inventory,
    write_artifact_inventory,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--label", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "paths", nargs="*",
        help="files or directories below --root; omit with --check to verify frozen entries",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare with --output instead of replacing it",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.check:
        if not args.output.is_file():
            raise SystemExit(f"inventory does not exist: {args.output}")
        expected = json.loads(args.output.read_text(encoding="ascii"))
        frozen = artifact_inventory_from_dict(expected)
        if frozen.label != args.label:
            raise SystemExit(
                f"artifact inventory label mismatch: expected {args.label}, got {frozen.label}"
            )
        if not args.paths:
            verify_artifact_inventory(frozen, args.root)
            print(f"verified {len(frozen.entries)} files, {frozen.total_bytes} bytes")
            return 0
        inventory = build_artifact_inventory(args.root, args.paths, label=args.label)
        actual = json.loads(json.dumps(inventory.to_dict(), sort_keys=True, ensure_ascii=True))
        if expected != actual:
            raise SystemExit("artifact inventory drift detected")
        print(f"verified {len(inventory.entries)} files, {inventory.total_bytes} bytes")
        return 0
    if not args.paths:
        raise SystemExit("at least one path is required unless --check is used")
    inventory = build_artifact_inventory(args.root, args.paths, label=args.label)
    write_artifact_inventory(inventory, args.output)
    print(
        f"wrote {args.output}: {len(inventory.entries)} files, "
        f"{inventory.total_bytes} bytes, digest {inventory.digest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
