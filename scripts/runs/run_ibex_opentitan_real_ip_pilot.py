#!/usr/bin/env python3
"""Build and run a fair RFuzz pilot on the real Ibex + OpenTitan target."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "configs/designs/ibex_opentitan_real_ip"
TOP = "ibex_opentitan_real_ip_top"
EXPECTED_OPENTITAN_REVISION = "13a8919bceac625dbd1b6ad804e62f9bdeadee86"
VARIANTS = ("baseline_direct_slice", "depaware_projection")


def top_coverage_width(instrumentation: dict) -> int:
    for module in instrumentation.get("module_coverage", []):
        if module.get("module") == TOP and module.get("active"):
            return int(module.get("coverage_width", 0))
    return 0


def coverage_identity(instrumentation: dict, instrumented_flist: Path) -> str:
    digest = hashlib.sha256()
    digest.update(
        json.dumps(
            {
                "top": TOP,
                "width": top_coverage_width(instrumentation),
                "module_coverage": instrumentation.get("module_coverage", []),
                "coverage": instrumentation.get("coverage", []),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    digest.update(instrumented_flist.read_bytes())
    for raw_line in instrumented_flist.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("+", "-")):
            continue
        source = Path(line.split()[0])
        if source.is_file():
            digest.update(source.read_bytes())
    return "sha256:" + digest.hexdigest()


def coverage_record(instrumentation_path: Path, instrumented_flist: Path) -> dict:
    instrumentation = json.loads(instrumentation_path.read_text(encoding="utf-8"))
    width = top_coverage_width(instrumentation)
    if width <= 0:
        raise RuntimeError(f"no active coverage points for {TOP}")
    return {
        "coverage_width": width,
        "coverage_identity": coverage_identity(instrumentation, instrumented_flist),
        "instrumentation": str(instrumentation_path),
        "instrumented_flist": str(instrumented_flist),
    }


def validate_pair(baseline: dict, depaware: dict) -> None:
    if (
        baseline.get("coverage_width") != depaware.get("coverage_width")
        or baseline.get("coverage_identity") != depaware.get("coverage_identity")
    ):
        raise RuntimeError("baseline and dependency-aware coverage universe differs")


def build_summary(baseline: dict, depaware: dict) -> dict:
    validate_pair(baseline, depaware)
    return {
        "target": "ibex_opentitan_real_ip",
        "opentitan_revision": EXPECTED_OPENTITAN_REVISION,
        "top": TOP,
        "input_width": 512,
        "coverage_width": baseline["coverage_width"],
        "coverage_identity": baseline["coverage_identity"],
        "execution": "sequential",
        "variants": {
            "baseline_direct_slice": baseline,
            "depaware_projection": depaware,
        },
    }


def available_memory_bytes() -> int:
    for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) * 1024
    return 0


def require_memory(reserve_gib: float) -> None:
    available = available_memory_bytes()
    reserve = int(reserve_gib * 1024**3)
    if available < reserve:
        raise RuntimeError(
            f"memory reserve violated: available={available}, required={reserve}"
        )


def tool_environment(root: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        filter(None, (str(root / "src"), str(root), env.get("PYTHONPATH", "")))
    )
    env["VERILATOR_ROOT"] = str(
        root / "third_party/rfuzz/upstream/.tools/apt-root/usr/share/verilator"
    )
    return env


def instrument_shared(root: Path) -> tuple[Path, Path]:
    out_dir = root / "runs/designs/ibex_opentitan_real_ip_shared/instrumented"
    subprocess.run(
        [
            sys.executable,
            str(root / "scripts/source_branch_instrumenter.py"),
            "--project-root",
            str(root),
            "--out-dir",
            str(out_dir),
            "--flist",
            str(TARGET / "rtl/sources.f"),
            "--instrumentation-config",
            str(TARGET / "baseline_direct_slice/config.json"),
            "--top-module",
            TOP,
            "--force",
        ],
        cwd=root,
        env=tool_environment(root),
        check=True,
    )
    return out_dir / "instrumentation.json", out_dir / "instrumented_sources.f"


def build_server(
    root: Path,
    variant: str,
    record: dict,
    reserve_gib: float,
) -> dict:
    require_memory(reserve_gib)
    config = json.loads((TARGET / variant / "config.json").read_text(encoding="utf-8"))
    out_dir = root / config["out_dir"] / "server"
    width = int(record["coverage_width"])
    command = [
        sys.executable,
        str(root / "scripts/runs/build_rfuzz_compat_server.py"),
        "--top",
        TOP,
        "--manual-module",
        config["harness"]["manual_harness_module"],
        "--manual-harness",
        str(root / config["harness"]["manual_harness"]),
        "--input-width",
        "512",
        "--instrumentation",
        record["instrumentation"],
        "--instrumented-flist",
        record["instrumented_flist"],
        "--out-dir",
        str(out_dir),
        "--verilator",
        str(root / "third_party/rfuzz/upstream/.tools/apt-root/usr/bin/verilator"),
        "--rfuzz-verilator-dir",
        str(root / "third_party/rfuzz/rfuzz_flow/verilator"),
        f"--verilator-arg=-DIBEX_OT_COVERAGE_MSB={width - 1}",
    ]
    command.extend(
        f"--verilator-arg={argument}" for argument in config.get("verilator_args", [])
    )
    subprocess.run(command, cwd=root, env=tool_environment(root), check=True)
    return {
        **record,
        "server": str(out_dir / "server"),
        "toml": str(out_dir / f"{TOP}.rfuzz.toml"),
    }


def clean_channel(server_id: int) -> Path:
    channel = Path("/tmp/fpga") / str(server_id)
    for name in ("tx.fifo", "rx.fifo"):
        path = channel / name
        if path.is_fifo():
            path.unlink()
    try:
        channel.rmdir()
    except OSError:
        pass
    channel.parent.mkdir(parents=True, exist_ok=True)
    return channel


def smoke_server(server: Path, server_id: int) -> None:
    channel = clean_channel(server_id)
    process = subprocess.Popen(
        [str(server), str(server_id)],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if (channel / "tx.fifo").is_fifo() and (channel / "rx.fifo").is_fifo():
                return
            if process.poll() is not None:
                raise RuntimeError(f"server smoke failed: {server}")
            time.sleep(0.05)
        raise RuntimeError(f"server smoke timeout: {server}")
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        clean_channel(server_id)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument("--memory-reserve-gib", type=float, default=4.0)
    parser.add_argument("--server-id", type=int, default=17)
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()

    root = args.repo.resolve()
    instrumentation, flist = instrument_shared(root)
    shared = coverage_record(instrumentation, flist)
    records: dict[str, dict] = {}
    for variant in VARIANTS:
        record = dict(shared)
        if not args.skip_build:
            record = build_server(root, variant, record, args.memory_reserve_gib)
            smoke_server(Path(record["server"]), args.server_id)
            record["smoke"] = "passed"
        records[variant] = record
    summary = build_summary(
        records["baseline_direct_slice"], records["depaware_projection"]
    )
    output = root / "runs/designs/ibex_opentitan_real_ip_shared/build_summary.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
