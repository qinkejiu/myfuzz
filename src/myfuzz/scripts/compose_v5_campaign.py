#!/usr/bin/env python3
"""Run the first compose-v5 rawbits target campaign entry point.

This is the Slice-1 executable boundary: every testcase is a flat v5 bitstream,
the target is launched as a fresh process for each testcase, and the campaign
only trusts machine-readable rawbits layout and target result artifacts.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from typing import Mapping, Sequence

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder.contracts import content_digest  # noqa: E402
from myfuzz.builder.input_model import InputValidationError  # noqa: E402
from myfuzz.builder.rawbits_v5 import (  # noqa: E402
    RAWBITS_V5_MAX_TESTCASE_BYTES,
    RawBitsV5Layout,
    decode_rawbits_v5_testcase,
    rawbits_v5_layout_from_dict,
)


CAMPAIGN_SCHEMA = "myfuzz.compose-v5-campaign-report/v1"
COMMAND_SCHEMA = "myfuzz.compose-v5-campaign-command/v1"
TARGET_RESULT_SCHEMA = "myfuzz.compose-v5-target-execution/v1"
MAX_RESULT_JSON_BYTES = 16 * 1024 * 1024


class ComposeV5CampaignError(ValueError):
    pass


class DeterministicRng:
    """Small versioned integer-only generator for reproducible byte streams."""

    def __init__(self, seed: int) -> None:
        if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
            raise ComposeV5CampaignError("seed must be a non-negative integer")
        self.state = (seed ^ 0x6A09E667F3BCC909) & ((1 << 64) - 1)

    def u64(self) -> int:
        self.state = (self.state + 0x9E3779B97F4A7C15) & ((1 << 64) - 1)
        z = self.state
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9 & ((1 << 64) - 1)
        z = (z ^ (z >> 27)) * 0x94D049BB133111EB & ((1 << 64) - 1)
        return z ^ (z >> 31)

    def bounded(self, upper_exclusive: int) -> int:
        if upper_exclusive <= 0:
            raise ComposeV5CampaignError("invalid deterministic RNG bound")
        return self.u64() % upper_exclusive

    def bytes(self, count: int) -> bytes:
        return bytes(self.u64() & 0xFF for _ in range(count))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--scheme", choices=("A", "B", "C", "D"), required=True)
    parser.add_argument("--seconds", type=float, required=True)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--max-testcases", type=int)
    parser.add_argument("--testcase-bytes", type=int, default=64)
    parser.add_argument("--testcase-file", type=Path, action="append", default=[])
    parser.add_argument("--target-timeout", type=float, default=10.0)
    parser.add_argument("--target-name", default="myfuzz_target")
    return parser


def run(args: argparse.Namespace) -> dict[str, object]:
    if args.scheme != "B":
        raise ComposeV5CampaignError(
            "compose-v5 Slice 1 campaign only implements B/raw; "
            "A flat aggregation and C/D constraint/adaptive modes require later slices"
        )
    if args.seconds <= 0:
        raise ComposeV5CampaignError("--seconds must be positive")
    if args.max_testcases is not None and args.max_testcases <= 0:
        raise ComposeV5CampaignError("--max-testcases must be positive when provided")
    if args.testcase_bytes <= 0 or args.testcase_bytes > RAWBITS_V5_MAX_TESTCASE_BYTES:
        raise ComposeV5CampaignError("--testcase-bytes must be within the v5 testcase byte limit")
    if args.target_timeout <= 0:
        raise ComposeV5CampaignError("--target-timeout must be positive")

    artifact = args.artifact.resolve(strict=True)
    layout = _load_layout(artifact)
    target = artifact / "bin" / args.target_name
    if not target.is_file() or not os.access(target, os.X_OK):
        raise ComposeV5CampaignError(f"target executable is unavailable: {target}")
    output = _output_dir(artifact, args)
    if output.exists() and any(output.iterdir()):
        raise ComposeV5CampaignError(f"output directory is not empty: {output}")
    (output / "testcases").mkdir(parents=True, exist_ok=True)
    (output / "results").mkdir(parents=True, exist_ok=True)

    invocation = _invocation(args, artifact=artifact, output=output)
    _write_json_atomic(output / "invocation.json", invocation)

    deadline = time.monotonic() + float(args.seconds)
    cases: list[dict[str, object]] = []
    coverage_union = bytearray()
    rising_total: dict[str, int] = {}
    falling_total: dict[str, int] = {}
    total_steps = 0
    total_eval_count = 0
    failed_count = 0
    settled_count = 0

    for testcase_id, payload in enumerate(_testcases(args, layout)):
        if time.monotonic() >= deadline:
            break
        raw_path = output / "testcases" / f"{testcase_id:016x}.rawbits-v5.bin"
        result_path = output / "results" / f"{testcase_id:016x}.json"
        raw_path.write_bytes(payload)
        result = _run_target(
            target=target, payload=raw_path, layout_digest=layout.digest,
            result_path=result_path, timeout_seconds=float(args.target_timeout),
        )
        coverage = _coverage_bytes(result)
        _or_in_place(coverage_union, coverage)
        _merge_counts(rising_total, _edge_counts(result.get("rising_edges"), "rising_edges"))
        _merge_counts(falling_total, _edge_counts(result.get("falling_edges"), "falling_edges"))
        steps = _nonnegative_int(result.get("steps"), "target result steps")
        eval_count = _nonnegative_int(result.get("eval_count"), "target result eval_count")
        settled = _bool(result.get("settled"), "target result settled")
        total_steps += steps
        total_eval_count += eval_count
        settled_count += 1 if settled else 0
        failed_count += 0 if settled else 1
        cases.append({
            "id": testcase_id,
            "raw_path": raw_path.as_posix(),
            "raw_bytes": len(payload),
            "raw_sha256": _sha256_file(raw_path),
            "result_path": result_path.as_posix(),
            "coverage_hits": _count_bits(coverage),
            "settled": settled,
            "failure": result.get("failure"),
            "steps": steps,
            "eval_count": eval_count,
        })
        if args.max_testcases is not None and len(cases) >= args.max_testcases:
            break

    report: dict[str, object] = {
        "schema": CAMPAIGN_SCHEMA,
        "status": "valid",
        "artifact": artifact.as_posix(),
        "scheme": args.scheme,
        "layout_digest": layout.digest,
        "seed": args.seed,
        "seconds_requested": float(args.seconds),
        "testcase_byte_limit": int(args.testcase_bytes),
        "fresh_process_per_testcase": True,
        "completed_count": len(cases),
        "settled_count": settled_count,
        "failed_count": failed_count,
        "dut_steps": total_steps,
        "eval_count": total_eval_count,
        "coverage_bytes": len(coverage_union),
        "coverage_hits": _count_bits(bytes(coverage_union)),
        "rising_edges": dict(sorted(rising_total.items())),
        "falling_edges": dict(sorted(falling_total.items())),
        "cases": cases,
    }
    report["digest"] = content_digest(report)
    _write_json_atomic(output / "campaign_report.json", report)
    summary = _summary(report)
    (output / "summary.txt").write_text(summary, encoding="ascii")
    command = {
        "schema": COMMAND_SCHEMA,
        "status": report["status"],
        "campaign_report": (output / "campaign_report.json").as_posix(),
        "invocation": (output / "invocation.json").as_posix(),
        "summary": (output / "summary.txt").as_posix(),
    }
    _write_json_atomic(output / "command_report.json", command)
    return command


def _load_layout(artifact: Path) -> RawBitsV5Layout:
    candidates = (artifact / "evidence" / "rawbits_layout.json", artifact / "rawbits_layout.json")
    for path in candidates:
        if not path.exists():
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ComposeV5CampaignError(f"cannot read rawbits layout {path}: {exc}") from exc
        if not isinstance(value, Mapping):
            raise ComposeV5CampaignError("rawbits layout must be a JSON object")
        return rawbits_v5_layout_from_dict(value)
    raise ComposeV5CampaignError("artifact does not contain evidence/rawbits_layout.json")


def _output_dir(artifact: Path, args: argparse.Namespace) -> Path:
    if args.output_dir is not None:
        return args.output_dir.resolve()
    return artifact / "runs" / f"compose-v5-{args.scheme.lower()}-{os.getpid()}-{time.time_ns()}"


def _testcases(args: argparse.Namespace, layout: RawBitsV5Layout):
    if args.testcase_file:
        for path in args.testcase_file:
            payload = path.resolve(strict=True).read_bytes()
            decode_rawbits_v5_testcase(layout, payload)
            yield payload
        return
    rng = DeterministicRng(int(args.seed))
    generated = 0
    while args.max_testcases is None or generated < args.max_testcases:
        size = 1 + rng.bounded(int(args.testcase_bytes))
        payload = rng.bytes(size)
        decode_rawbits_v5_testcase(layout, payload)
        generated += 1
        yield payload


def _run_target(
    *, target: Path, payload: Path, layout_digest: str, result_path: Path, timeout_seconds: float,
) -> Mapping[str, object]:
    command = [target.as_posix(), payload.as_posix(), layout_digest, result_path.as_posix()]
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONNOUSERSITE": "1",
    }
    try:
        completed = subprocess.run(
            command, cwd=target.parent, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding="utf-8", errors="replace", timeout=timeout_seconds, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ComposeV5CampaignError(f"target execution timed out after {timeout_seconds}s") from exc
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise ComposeV5CampaignError(
            f"target execution failed ({completed.returncode}): {detail[-2000:]}"
        )
    if not result_path.is_file():
        raise ComposeV5CampaignError("target did not write its result JSON")
    if result_path.stat().st_size > MAX_RESULT_JSON_BYTES:
        raise ComposeV5CampaignError("target result JSON exceeds the campaign limit")
    try:
        value = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ComposeV5CampaignError(f"target result JSON is unreadable: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ComposeV5CampaignError("target result must be a JSON object")
    _validate_target_result(value, layout_digest)
    return value


def _validate_target_result(value: Mapping[str, object], layout_digest: str) -> None:
    expected = {
        "schema", "layout_digest", "steps", "eval_count", "rising_edges", "falling_edges",
        "wire_digest", "coverage_digest", "coverage_hex", "settled", "failure",
    }
    if set(value) != expected:
        raise ComposeV5CampaignError("target result fields do not match compose-v5 v1")
    if value["schema"] != TARGET_RESULT_SCHEMA:
        raise ComposeV5CampaignError("target result schema mismatch")
    if value["layout_digest"] != layout_digest:
        raise ComposeV5CampaignError("target result layout digest mismatch")
    _nonnegative_int(value["steps"], "target result steps")
    _nonnegative_int(value["eval_count"], "target result eval_count")
    _edge_counts(value["rising_edges"], "rising_edges")
    _edge_counts(value["falling_edges"], "falling_edges")
    _digest(value["wire_digest"], "wire_digest")
    _digest(value["coverage_digest"], "coverage_digest")
    _coverage_bytes(value)
    settled = _bool(value["settled"], "settled")
    failure = value["failure"]
    if failure is not None and (not isinstance(failure, str) or not failure):
        raise ComposeV5CampaignError("target result failure must be null or a non-empty string")
    if settled and failure is not None:
        raise ComposeV5CampaignError("settled target result must not carry a failure")


def _coverage_bytes(value: Mapping[str, object]) -> bytes:
    raw = value.get("coverage_hex")
    if not isinstance(raw, str) or len(raw) % 2:
        raise ComposeV5CampaignError("target result coverage_hex must be even-length hex")
    if any(char not in "0123456789abcdefABCDEF" for char in raw):
        raise ComposeV5CampaignError("target result coverage_hex must be hex")
    return bytes.fromhex(raw)


def _edge_counts(value: object, label: str) -> dict[str, int]:
    if not isinstance(value, Mapping):
        raise ComposeV5CampaignError(f"target result {label} must be an object")
    result: dict[str, int] = {}
    for key, count in value.items():
        if not isinstance(key, str) or not key:
            raise ComposeV5CampaignError(f"target result {label} keys must be strings")
        result[key] = _nonnegative_int(count, f"target result {label}.{key}")
    return result


def _merge_counts(total: dict[str, int], update: Mapping[str, int]) -> None:
    for key, value in update.items():
        total[key] = total.get(key, 0) + int(value)


def _or_in_place(total: bytearray, update: bytes) -> None:
    if len(total) < len(update):
        total.extend(b"\x00" * (len(update) - len(total)))
    for index, value in enumerate(update):
        total[index] |= value


def _count_bits(data: bytes) -> int:
    return sum(item.bit_count() for item in data)


def _nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ComposeV5CampaignError(f"{label} must be a non-negative integer")
    return value


def _bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ComposeV5CampaignError(f"{label} must be a boolean")
    return value


def _digest(value: object, label: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(
        char not in "0123456789abcdef" for char in value
    ):
        raise ComposeV5CampaignError(f"{label} must be a lowercase SHA-256 digest")


def _sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _summary(report: Mapping[str, object]) -> str:
    lines = [
        f"status: {report['status']}",
        f"scheme: {report['scheme']}",
        "coverage: primary branch bitmap supplied by target result",
        f"completed_count: {report['completed_count']}",
        f"coverage_hits: {report['coverage_hits']}",
        f"dut_steps: {report['dut_steps']}",
        "fresh_process_per_testcase: true",
    ]
    return "\n".join(lines) + "\n"


def _invocation(args: argparse.Namespace, *, artifact: Path, output: Path) -> dict[str, object]:
    values = {
        name: value.as_posix() if isinstance(value, Path) else value
        for name, value in vars(args).items()
    }
    values["testcase_file"] = [path.as_posix() for path in args.testcase_file]
    return {
        "schema": "myfuzz.compose-v5-campaign-invocation/v1",
        "artifact_resolved": artifact.as_posix(),
        "output_dir_resolved": output.as_posix(),
        **values,
    }


def _write_json_atomic(path: Path, value: object) -> None:
    payload = json.dumps(
        value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False,
    ) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = run(args)
    except (ComposeV5CampaignError, InputValidationError, OSError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, indent=2), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
