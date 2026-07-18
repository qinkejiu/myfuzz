#!/usr/bin/env python3
"""Repository-local entry point for the protocol-driven system builder."""

from __future__ import annotations

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from myfuzz.builder.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
