#!/usr/bin/env python3
"""Losslessly wrap historical RawBits v2 bytes in an opaque v3 JSON envelope."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder.rawbits_v3 import envelope_rawbits_v2  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path, help="existing myfuzz.rawbits/v2 byte file")
    parser.add_argument("output", type=Path, help="new opaque v3 JSON envelope")
    parser.add_argument("--source", default="historical-a-baseline")
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve():
        parser.error("input and output must differ; v2 artifacts are read-only")
    if args.output.exists():
        parser.error(f"output already exists: {args.output}")
    envelope = envelope_rawbits_v2(args.input.read_bytes(), provenance={"source": args.source})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(envelope.to_dict(), stream, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        stream.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
