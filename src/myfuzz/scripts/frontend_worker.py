#!/usr/bin/env python3
"""One-shot process boundary for the non-reentrant embedded Verilator frontend."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from myfuzz.scripts.frontend_api import FrontendLibrary


def main() -> int:
    request = json.load(sys.stdin)
    result = FrontendLibrary(Path(request["library"])).manifest(
        list(request["args"]), Path(request["cwd"]),
    )
    json.dump(result, sys.stdout, sort_keys=True, separators=(",", ":"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
