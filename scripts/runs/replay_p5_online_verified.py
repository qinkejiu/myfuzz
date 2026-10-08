#!/usr/bin/env python3
"""Run fresh P5 RTL replay and bind its result to the exact saved input bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


SNAPSHOT_ROOT = Path("/home/qinkejiu/myfuzz_snapshot_p5_runner_zlib_600s_20261007")
SNAPSHOT_MANIFEST_SHA256 = "ee6191e8f5344f260d2ce17a51f5e6cd2f711bd3562decfe7d657eede49100bd"
TRUSTED_CLI_SHA256 = "91f15293b27ee7316823d834b7fcbbca22a8e2085cae527c30228ba9e612b91b"
INPUT_NAMES = ("online_plan.json", "online_final_trace.meta.json",
               "online_events.zlib", "online_run_identity.json", "report.json")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run_verified_replay(cli: Path, cache_dir: Path, plan: Path,
                        trace: Path, result_path: Path) -> dict:
    """Execute the supplied frozen CLI once and write its byte-bound result."""
    cli, plan, trace = Path(cli).resolve(), Path(plan).resolve(), Path(trace).resolve()
    cache_dir = Path(cache_dir).resolve()
    trusted_cli = SNAPSHOT_ROOT / "scripts/run_ibex_pulp_online.py"
    if (cli.resolve() != trusted_cli.resolve()
            or _sha256(cli) != TRUSTED_CLI_SHA256):
        raise ValueError("trusted frozen replay CLI is required")
    output = plan.parent
    if (plan.name != "online_plan.json" or trace.parent != output
            or trace.name != "online_final_trace.meta.json"):
        raise ValueError("plan and trace must be in the same online output directory")
    manifest = output.parent / "snapshot.sha256"
    if _sha256(manifest) != SNAPSHOT_MANIFEST_SHA256:
        raise ValueError("trusted frozen snapshot manifest is required")
    source_check = subprocess.run(
        ["sha256sum", "-c", "--quiet", str(manifest)], cwd=SNAPSHOT_ROOT,
        capture_output=True, text=True, check=False)
    if source_check.returncode != 0:
        raise ValueError("frozen replay sources do not match snapshot manifest")
    paths = {name: output / name for name in INPUT_NAMES}
    paths["run-time.txt"] = output.parent / "run-time.txt"
    paths["snapshot.sha256"] = manifest
    before = {name: _sha256(path) for name, path in paths.items()}
    cli_sha256 = _sha256(cli)
    command = [sys.executable, str(cli), "replay", "--cache-dir", str(cache_dir),
               "--plan", str(plan), "--trace", str(trace)]
    process = subprocess.run(command, capture_output=True, text=True, check=False)
    after = {name: _sha256(path) for name, path in paths.items()}
    if before != after or cli_sha256 != _sha256(cli):
        raise ValueError("replay input bytes changed during execution")
    source_check = subprocess.run(
        ["sha256sum", "-c", "--quiet", str(manifest)], cwd=SNAPSHOT_ROOT,
        capture_output=True, text=True, check=False)
    if source_check.returncode != 0:
        raise ValueError("frozen replay sources changed during execution")
    try:
        comparison = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"replay produced no JSON result: {process.stderr.strip()}") from exc
    if not isinstance(comparison, dict):
        raise RuntimeError("replay produced a non-object JSON result")
    result = {**comparison, "replay_exit_code": process.returncode,
              "inputs": before, "replay_cli_sha256": cli_sha256}
    Path(result_path).write_text(json.dumps(result, sort_keys=True) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot-cli", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args(argv)
    result = run_verified_replay(args.snapshot_cli, args.cache_dir, args.plan,
                                 args.trace, args.result)
    print(json.dumps(result, sort_keys=True))
    return 0 if (result.get("replay_exit_code") == 0
                 and result.get("matches") is True
                 and result.get("first_difference") is None) else 2


if __name__ == "__main__":
    raise SystemExit(main())
