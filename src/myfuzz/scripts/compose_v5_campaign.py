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
    encode_rawbits_v5_records,
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


class RawbitsProjectionController:
    def __init__(
        self,
        layout: RawBitsV5Layout,
        *,
        scheme: str,
        scheme_plan: Mapping[str, object] | None,
        stall_inputs_before_escalation: int,
    ) -> None:
        if scheme not in {"A", "B", "C", "D"}:
            raise ComposeV5CampaignError("scheme must be A, B, C, or D")
        self.layout = layout
        self.scheme = scheme
        self.scheme_plan = dict(scheme_plan or {})
        self.field_rules = _field_rules_for_scheme(self.scheme_plan, scheme)
        self.stall_inputs_before_escalation = stall_inputs_before_escalation
        self.stall_count = 0
        self.adaptive_strength = 0
        self.max_strength_seen = 0
        self._reset_initials: dict[str, int] = {}
        self._previous_values: dict[str, int] = {
            field.owner: field.initial_value for field in layout.fields
        }

    @property
    def source_record_width_bits(self) -> int:
        return self.layout.record_width_bits + (8 if self.scheme == "D" else 0)

    @property
    def source_record_width_bytes(self) -> int:
        return (self.source_record_width_bits + 7) // 8

    def validate_source_payload(self, payload: bytes) -> None:
        if self.scheme == "D":
            _decode_virtual_records(payload, self.source_record_width_bits)
            return
        decode_rawbits_v5_testcase(self.layout, payload)

    def project(self, payload: bytes, *, testcase_id: int) -> tuple[bytes, dict[str, object]]:
        if self.scheme in {"A", "B"}:
            decode_rawbits_v5_testcase(self.layout, payload)
            return payload, {
                "mode": "identity",
                "source_record_width_bits": self.layout.record_width_bits,
                "target_record_width_bits": self.layout.record_width_bits,
                "modified_records": 0,
                "adaptive_strength": self.adaptive_strength,
            }

        if self.scheme == "D":
            records, selectors = _decode_virtual_records(payload, self.source_record_width_bits)
        else:
            testcase = decode_rawbits_v5_testcase(self.layout, payload)
            records = testcase.records
            selectors = tuple({"strength": 0, "mask": 0} for _ in records)

        projected: list[int] = []
        modified = 0
        bypassed_fields = 0
        for step, record in enumerate(records):
            selector = selectors[step]
            next_record, step_modified, step_bypassed = self._project_record(
                record,
                step=step,
                testcase_id=testcase_id,
                selector_strength=int(selector["strength"]),
                selector_mask=int(selector["mask"]),
            )
            projected.append(next_record)
            modified += 1 if step_modified else 0
            bypassed_fields += step_bypassed

        return encode_rawbits_v5_records(self.layout, tuple(projected)), {
            "mode": "bit_level_projection" if self.scheme == "C" else "adaptive_bit_level_projection",
            "source_record_width_bits": self.source_record_width_bits,
            "target_record_width_bits": self.layout.record_width_bits,
            "modified_records": modified,
            "bypassed_fields": bypassed_fields,
            "adaptive_strength": self.adaptive_strength,
            "stall_count_before_result": self.stall_count,
        }

    def update_after_result(self, new_coverage_bits: int) -> None:
        if self.scheme != "D":
            return
        if new_coverage_bits > 0:
            self.stall_count = 0
            return
        self.stall_count += 1
        if self.stall_count < self.stall_inputs_before_escalation:
            return
        self.stall_count = 0
        self.adaptive_strength = min(7, self.adaptive_strength + 1)
        self.max_strength_seen = max(self.max_strength_seen, self.adaptive_strength)

    def policy_report(self) -> dict[str, object]:
        if self.scheme in {"A", "B"}:
            return {
                "scheme": self.scheme,
                "mode": "identity",
                "source_record_width_bits": self.layout.record_width_bits,
                "target_record_width_bits": self.layout.record_width_bits,
            }
        return {
            "scheme": self.scheme,
            "mode": "bit_level_projection" if self.scheme == "C" else "adaptive_bit_level_projection",
            "source_record_width_bits": self.source_record_width_bits,
            "target_record_width_bits": self.layout.record_width_bits,
            "clock_rule": "project one-bit clock fields to step parity unless D perturbation bypasses them",
            "reset_rule": (
                "use first raw reset bit as asserted level for two records, then drive the opposite level"
            ),
            "rule_count_from_scheme_plan": len(self.field_rules),
            "stall_inputs_before_escalation": self.stall_inputs_before_escalation,
        }

    def _project_record(
        self,
        record: int,
        *,
        step: int,
        testcase_id: int,
        selector_strength: int,
        selector_mask: int,
    ) -> tuple[int, bool, int]:
        next_record = record
        modified = False
        bypassed = 0
        effective_strength = min(7, max(0, min(selector_strength, self.adaptive_strength)))
        for field in self.layout.fields:
            raw_value = _get_field(record, field.offset, field.width)
            field_class = _field_class(field.kind, self.field_rules.get(field.owner, ()))
            if self.scheme == "D" and _bypass_field(
                field_class,
                selector_mask=selector_mask,
                effective_strength=effective_strength,
                testcase_id=testcase_id,
                step=step,
                offset=field.offset,
            ):
                projected_value = raw_value
                bypassed += 1
            else:
                projected_value = self._project_field(field, raw_value, step)
            if projected_value != raw_value:
                modified = True
            next_record = _set_field(next_record, field.offset, field.width, projected_value)
            self._previous_values[field.owner] = projected_value
        return next_record, modified, bypassed

    def _project_field(self, field, raw_value: int, step: int) -> int:
        rules = self.field_rules.get(field.owner, ())
        primitives = {str(rule.get("primitive")) for rule in rules}
        if field.kind == "clock":
            return step & 1
        if field.kind == "reset":
            if field.owner not in self._reset_initials:
                self._reset_initials[field.owner] = raw_value & ((1 << field.width) - 1)
            asserted = self._reset_initials[field.owner]
            released = asserted ^ ((1 << field.width) - 1)
            return asserted if step < 2 else released
        previous = self._previous_values.get(field.owner, field.initial_value)
        if "ready_sampled_backpressure" in primitives and step % 2:
            return previous
        if "valid_hold_until_accept" in primitives and previous and not raw_value:
            return previous
        if "payload_stable_while_unaccepted" in primitives and step % 2:
            return previous
        return raw_value


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
    parser.add_argument("--stall-inputs-before-escalation", type=int, default=256)
    return parser


def run(args: argparse.Namespace) -> dict[str, object]:
    if args.seconds <= 0:
        raise ComposeV5CampaignError("--seconds must be positive")
    if args.max_testcases is not None and args.max_testcases <= 0:
        raise ComposeV5CampaignError("--max-testcases must be positive when provided")
    if args.testcase_bytes <= 0 or args.testcase_bytes > RAWBITS_V5_MAX_TESTCASE_BYTES:
        raise ComposeV5CampaignError("--testcase-bytes must be within the v5 testcase byte limit")
    if args.target_timeout <= 0:
        raise ComposeV5CampaignError("--target-timeout must be positive")
    if args.stall_inputs_before_escalation <= 0:
        raise ComposeV5CampaignError("--stall-inputs-before-escalation must be positive")

    artifact = args.artifact.resolve(strict=True)
    layout = _load_layout(artifact)
    scheme_plan = _load_optional_json(
        artifact / "evidence" / "scheme_plan.json",
        artifact / "scheme_plan.json",
    )
    projector = RawbitsProjectionController(
        layout,
        scheme=args.scheme,
        scheme_plan=scheme_plan,
        stall_inputs_before_escalation=int(args.stall_inputs_before_escalation),
    )
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

    for testcase_id, source_payload in enumerate(_testcases(args, projector)):
        if time.monotonic() >= deadline:
            break
        projected_payload, projection = projector.project(source_payload, testcase_id=testcase_id)
        source_path = output / "source_testcases" / f"{testcase_id:016x}.fuzzer-rawbits.bin"
        raw_path = output / "testcases" / f"{testcase_id:016x}.rawbits-v5.bin"
        result_path = output / "results" / f"{testcase_id:016x}.json"
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_bytes(source_payload)
        raw_path.write_bytes(projected_payload)
        result = _run_target(
            target=target, payload=raw_path, layout_digest=layout.digest,
            result_path=result_path, timeout_seconds=float(args.target_timeout),
        )
        coverage = _coverage_bytes(result)
        new_coverage_bits = _new_bit_count(coverage_union, coverage)
        _or_in_place(coverage_union, coverage)
        projector.update_after_result(new_coverage_bits)
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
            "source_raw_path": source_path.as_posix(),
            "source_raw_bytes": len(source_payload),
            "source_raw_sha256": _sha256_file(source_path),
            "raw_path": raw_path.as_posix(),
            "raw_bytes": len(projected_payload),
            "raw_sha256": _sha256_file(raw_path),
            "result_path": result_path.as_posix(),
            "coverage_hits": _count_bits(coverage),
            "new_coverage_bits": new_coverage_bits,
            "projection": projection,
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
        "projection_policy": projector.policy_report(),
        "completed_count": len(cases),
        "settled_count": settled_count,
        "failed_count": failed_count,
        "dut_steps": total_steps,
        "eval_count": total_eval_count,
        "coverage_bytes": len(coverage_union),
        "coverage_hits": _count_bits(bytes(coverage_union)),
        "max_adaptive_strength": projector.max_strength_seen,
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


def _load_optional_json(*candidates: Path) -> Mapping[str, object] | None:
    for path in candidates:
        if not path.exists():
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ComposeV5CampaignError(f"cannot read optional JSON {path}: {exc}") from exc
        if not isinstance(value, Mapping):
            raise ComposeV5CampaignError(f"optional JSON {path} must be an object")
        return value
    return None


def _output_dir(artifact: Path, args: argparse.Namespace) -> Path:
    if args.output_dir is not None:
        return args.output_dir.resolve()
    return artifact / "runs" / f"compose-v5-{args.scheme.lower()}-{os.getpid()}-{time.time_ns()}"


def _testcases(args: argparse.Namespace, projector: RawbitsProjectionController):
    if args.testcase_file:
        for path in args.testcase_file:
            payload = path.resolve(strict=True).read_bytes()
            projector.validate_source_payload(payload)
            yield payload
        return
    rng = DeterministicRng(int(args.seed))
    generated = 0
    while args.max_testcases is None or generated < args.max_testcases:
        size = 1 + rng.bounded(int(args.testcase_bytes))
        payload = rng.bytes(size)
        projector.validate_source_payload(payload)
        generated += 1
        yield payload


def _decode_virtual_records(
    payload: bytes,
    record_width_bits: int,
) -> tuple[tuple[int, ...], tuple[dict[str, int], ...]]:
    if not isinstance(payload, bytes):
        raise ComposeV5CampaignError("virtual rawbits testcase must be bytes")
    if len(payload) > RAWBITS_V5_MAX_TESTCASE_BYTES:
        raise ComposeV5CampaignError("virtual rawbits testcase exceeds 1 MiB")
    if record_width_bits <= 0:
        raise ComposeV5CampaignError("virtual rawbits record width must be positive")
    record_bytes = (record_width_bits + 7) // 8
    if not payload:
        return (), ()
    count = (len(payload) + record_bytes - 1) // record_bytes
    if count > RAWBITS_V5_MAX_TESTCASE_BYTES // record_bytes:
        raise ComposeV5CampaignError("virtual rawbits testcase exceeds the maximum step count")
    padded = payload + b"\x00" * (count * record_bytes - len(payload))
    base_mask = (1 << (record_width_bits - 8)) - 1
    full_mask = (1 << record_width_bits) - 1
    records: list[int] = []
    selectors: list[dict[str, int]] = []
    for offset in range(0, len(padded), record_bytes):
        raw = int.from_bytes(padded[offset:offset + record_bytes], "little") & full_mask
        selector = raw >> (record_width_bits - 8)
        records.append(raw & base_mask)
        selectors.append({"strength": selector & 0x7, "mask": (selector >> 3) & 0x1f})
    return tuple(records), tuple(selectors)


def _field_rules_for_scheme(
    scheme_plan: Mapping[str, object],
    scheme: str,
) -> dict[str, tuple[Mapping[str, object], ...]]:
    schemes = scheme_plan.get("schemes", ())
    if not isinstance(schemes, (list, tuple)):
        return {}
    selected = None
    for item in schemes:
        if isinstance(item, Mapping) and item.get("id") == scheme:
            selected = item
            break
    if selected is None:
        return {}
    rules = selected.get("constraint_rules", ())
    if not isinstance(rules, (list, tuple)):
        return {}
    result: dict[str, list[Mapping[str, object]]] = {}
    for rule in rules:
        if not isinstance(rule, Mapping):
            continue
        target = rule.get("target")
        if not isinstance(target, str) or not target:
            continue
        result.setdefault(target, []).append(rule)
    return {owner: tuple(items) for owner, items in result.items()}


def _field_class(kind: str, rules: tuple[Mapping[str, object], ...]) -> str:
    primitives = {str(rule.get("primitive")) for rule in rules}
    if kind == "clock":
        return "clock"
    if kind == "reset":
        return "reset"
    if primitives & {"valid_hold_until_accept", "ready_sampled_backpressure"}:
        return "handshake"
    if "payload_stable_while_unaccepted" in primitives:
        return "payload"
    return "external"


def _bypass_field(
    field_class: str,
    *,
    selector_mask: int,
    effective_strength: int,
    testcase_id: int,
    step: int,
    offset: int,
) -> bool:
    if effective_strength <= 0:
        return False
    class_bits = {
        "clock": 0,
        "reset": 1,
        "handshake": 2,
        "payload": 3,
        "external": 4,
    }
    bit = class_bits.get(field_class, 4)
    if not (selector_mask & (1 << bit)):
        return False
    score = (testcase_id * 17 + step * 5 + offset * 3 + bit) & 0x7
    return score < effective_strength


def _get_field(record: int, offset: int, width: int) -> int:
    return (record >> offset) & ((1 << width) - 1)


def _set_field(record: int, offset: int, width: int, value: int) -> int:
    mask = ((1 << width) - 1) << offset
    return (record & ~mask) | ((value << offset) & mask)


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


def _new_bit_count(total: bytearray, update: bytes) -> int:
    count = 0
    for index, value in enumerate(update):
        old = total[index] if index < len(total) else 0
        count += (value & ~old).bit_count()
    return count


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
