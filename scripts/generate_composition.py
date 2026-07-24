#!/usr/bin/env python3
"""Generate deterministic, reparsed Top-K composition candidates."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.as_posix() not in sys.path:
    sys.path.insert(0, SRC.as_posix())

from myfuzz.scripts.composition_api import generate_compositions  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate and reparse deterministic Top-K composition candidates."
    )
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--frontend", required=True, type=Path)
    parser.add_argument("--top-k", required=True, type=int)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--frontend-library", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
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
