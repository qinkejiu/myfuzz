#!/usr/bin/env python3
"""Local lightweight checks for the Ibex + common-IP scaffold.

This intentionally does not run RFuzz, Verilator, or the myfuzz design flow.
Those stages require the remote machine because the local workspace lacks the
full RFuzz/Ibex toolchain and has limited memory.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
DESIGN = ROOT / "configs/designs/ibex_multicomponent_ip"


def load_json(path: Path) -> dict:
    with path.open() as infile:
        return json.load(infile)


def require(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(path)


def harness_input_width(path: Path) -> int:
    text = re.sub(r"/\*.*?\*/", "", path.read_text(), flags=re.S)
    text = re.sub(r"//.*", "", text)
    match = re.search(r"\binput\s+logic\s+\[\s*(\d+)\s*:\s*(\d+)\s*\]\s+rfuzz_input_bits\b", text)
    if not match:
        raise RuntimeError(f"rfuzz_input_bits declaration not found: {path}")
    left, right = int(match.group(1)), int(match.group(2))
    return abs(left - right) + 1


def check_config(rel: str) -> None:
    path = DESIGN / rel / "config.json"
    cfg = load_json(path)
    require(ROOT / cfg["flist"])
    require(ROOT / cfg["harness"]["manual_harness"])
    require(ROOT / cfg["dependency_manifest"])
    width = harness_input_width(ROOT / cfg["harness"]["manual_harness"])
    if width != 512:
        raise RuntimeError(f"{path}: expected 512-bit rfuzz_input_bits, got {width}")
    if cfg["top"] != "ibex_multicomponent_ip_top":
        raise RuntimeError(f"{path}: unexpected top {cfg['top']}")


def main() -> int:
    for rel in [
        "baseline_direct_slice",
        "depaware_projection",
    ]:
        check_config(rel)

    local_sources = DESIGN / "rtl/local_sources.f"
    for raw in local_sources.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        require(local_sources.parent / line)

    manifest = load_json(DESIGN / "manifests/ibex_common_ip_dependency_manifest.json")
    if manifest["cpu"]["module"] != "ibex_core":
        raise RuntimeError("manifest CPU is not ibex_core")
    if len(manifest["components"]) < 6:
        raise RuntimeError("manifest should include Ibex plus at least five common IP components")

    print("ok: ibex_multicomponent_ip local scaffold checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
