#!/usr/bin/env python3
"""Build an original-RFuzz compatible Verilator server for a manual harness."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from myfuzz.rfuzz_compat import (
    render_adapter,
    render_dut_header,
    render_rfuzz_toml,
    server_build_command,
)


def coverage_width(instrumentation: dict, top: str) -> int:
    for module in instrumentation.get("module_coverage", []):
        if module.get("module") == top and module.get("active"):
            return int(module.get("coverage_width", 0))
    return int(instrumentation.get("coverage_point_count", 0))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--top", required=True)
    parser.add_argument("--manual-module", required=True)
    parser.add_argument("--manual-harness", type=Path, required=True)
    parser.add_argument("--input-name", default="rfuzz_input_bits")
    parser.add_argument("--input-width", type=int, required=True)
    parser.add_argument("--coverage-port", default="__vi_coverage")
    parser.add_argument("--instrumentation", type=Path, required=True)
    parser.add_argument("--instrumented-flist", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--verilator", type=Path, required=True)
    parser.add_argument("--rfuzz-verilator-dir", type=Path, required=True)
    parser.add_argument("--verilator-arg", action="append", default=[])
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    instrumentation = json.loads(args.instrumentation.resolve().read_text())
    width = coverage_width(instrumentation, args.top)
    if width <= 0:
        raise RuntimeError(f"no active coverage points for {args.top}")

    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    adapter = out_dir / f"{args.top}_VHarness.sv"
    toml = out_dir / f"{args.top}.rfuzz.toml"
    adapter.write_text(
        render_adapter(
            top=args.top,
            manual_module=args.manual_module,
            input_name=args.input_name,
            input_width=args.input_width,
            coverage_port=args.coverage_port,
            coverage_width=width,
        )
    )
    timestamp = dt.datetime.now().astimezone().isoformat(timespec="seconds")
    toml.write_text(
        render_rfuzz_toml(
            top=args.top,
            input_name=args.input_name,
            input_width=args.input_width,
            coverage_width=width,
            instrumentation=instrumentation,
            timestamp=timestamp,
        )
    )

    rfuzz_dir = args.rfuzz_verilator_dir.resolve()
    (out_dir / "dut.hpp").write_text(
        render_dut_header(top=args.top, input_width=args.input_width, coverage_width=width)
    )
    command = server_build_command(
        verilator=args.verilator.resolve(),
        flist=args.instrumented_flist.resolve(),
        manual_harness=args.manual_harness.resolve(),
        adapter=adapter,
        top=args.top,
        out_dir=out_dir,
        rfuzz_verilator_dir=rfuzz_dir,
        extra_args=list(args.verilator_arg),
    )
    env = os.environ.copy()
    subprocess.run(command, cwd=ROOT, env=env, check=True)
    print(json.dumps({"server": str(out_dir / "server"), "toml": str(toml), "coverage_width": width}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
