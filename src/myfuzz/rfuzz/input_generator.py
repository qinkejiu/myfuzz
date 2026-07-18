"""RFUZZ-style byte/bit testcase generation for generated fuzz harnesses.

The current generated harness consumes one byte per cycle:

- bits [7:6] select the action class.
- lower bits carry the action payload.

This module keeps that encoding centralized so harnesses do not need ad-hoc
testcase generation scripts.
"""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ACTION_IDLE = 0b00 << 6
ACTION_UART_EVENT = 0b01 << 6
ACTION_PIN_EVENT = 0b10 << 6
ACTION_MMIO_EVENT = 0b11 << 6
LEGACY_RFUZZ_FORMAT = "legacy-v1"


@dataclass(frozen=True)
class GeneratedTestcase:
    name: str
    seed: int
    cycles: int
    actions: list[dict[str, Any]]
    byte_stream: bytes


def load_supported_actions(generated_dir: Path) -> set[str]:
    action_path = generated_dir / "action_definitions.json"
    if not action_path.exists():
        return {"WAIT", "UART_RX_INJECT", "PIN_INJECT"}
    data = json.loads(action_path.read_text())
    return {action["name"] for action in data.get("actions", [])}


def load_scenario_selectors(generated_dir: Path) -> dict[str, int]:
    """Map SCENARIO_* actions to the harness region selector bits.

    The harness orders scenario regions by transaction_plan.regions priority and
    consumes sequence_data_q[4:2] as the case selector.
    """
    plan_path = generated_dir / "transaction_plan.json"
    if not plan_path.exists():
        return {}
    plan = json.loads(plan_path.read_text())
    scenario_regions = [
        region for region in plan.get("regions", [])
        if int(region.get("scenario_priority", 0)) >= 70
    ][:8]
    component_to_selector = {
        region.get("component"): idx for idx, region in enumerate(scenario_regions)
    }
    selectors = {}
    for sequence in plan.get("sequences", []):
        selector = component_to_selector.get(sequence.get("component"))
        if selector is not None:
            selectors[sequence["name"]] = selector
    return selectors


def encode_action(action: str, value: int) -> int:
    value &= 0x3f
    if action.startswith("SCENARIO_"):
        # bit[5] asks the generated harness to execute a short stateful
        # scenario: MMIO prep -> external event/wait -> MMIO observe.
        return ACTION_MMIO_EVENT | 0x20 | (value & 0x1f)
    if action == "UART_RX_INJECT":
        return ACTION_UART_EVENT | (value & 0x01)
    if action == "PIN_INJECT":
        return ACTION_PIN_EVENT | value
    if action in {"MMIO_READ", "MMIO_WRITE"}:
        # bit[5] must stay zero; the harness reserves 11_1xxxxx for scenarios.
        # bit[0] is consumed by the harness as write-enable.
        return ACTION_MMIO_EVENT | ((value & 0x1e) | (1 if action == "MMIO_WRITE" else 0))
    return ACTION_IDLE


def generate_testcase(
    generated_dir: Path,
    cycles: int = 1024,
    seed: int = 1,
    name: str = "rfuzz_seed",
    *,
    format_version: str,
) -> GeneratedTestcase:
    _require_legacy_format(format_version)
    supported = load_supported_actions(generated_dir)
    scenario_selectors = load_scenario_selectors(generated_dir)
    rng = random.Random(seed)
    action_pool = ["WAIT"]
    if "UART_RX_INJECT" in supported:
        action_pool.append("UART_RX_INJECT")
    if "PIN_INJECT" in supported:
        action_pool.append("PIN_INJECT")
    if "MMIO_READ" in supported:
        action_pool.append("MMIO_READ")
    if "MMIO_WRITE" in supported:
        action_pool.append("MMIO_WRITE")
    scenario_actions = sorted(action for action in supported if action.startswith("SCENARIO_"))
    action_pool.extend(scenario_actions)

    actions: list[dict[str, Any]] = []
    stream = bytearray()
    for cycle in range(cycles):
        # Bias toward idle/wait cycles so short pulses remain visible.
        weights = []
        for candidate in action_pool:
            if candidate == "WAIT":
                weights.append(6)
            elif candidate.startswith("SCENARIO_"):
                weights.append(4)
            else:
                weights.append(2)
        action = rng.choices(action_pool, weights=weights, k=1)[0]
        value = rng.randrange(0, 256)
        if action.startswith("SCENARIO_") and action in scenario_selectors:
            value = ((scenario_selectors[action] & 0x7) << 2) | (value & 0x03)
        byte = encode_action(action, value)
        stream.append(byte)
        actions.append({
            "cycle": cycle,
            "action": action,
            "value": value,
            "encoded_byte": byte,
        })

    return GeneratedTestcase(
        name=name,
        seed=seed,
        cycles=cycles,
        actions=actions,
        byte_stream=bytes(stream),
    )


def write_testcase(testcase: GeneratedTestcase, output_dir: Path) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    bin_path = output_dir / f"{testcase.name}.bin"
    json_path = output_dir / f"{testcase.name}.json"
    bin_path.write_bytes(testcase.byte_stream)
    json_path.write_text(json.dumps({
        "name": testcase.name,
        "seed": testcase.seed,
        "cycles": testcase.cycles,
        "encoding": {
            "idle": "00xxxxxx",
            "uart_rx_inject": "01xxxxxB",
            "pin_inject": "10VVVVVV",
            "mmio": "110RRROW",
            "scenario": "111SSSSS",
        },
        "actions": testcase.actions,
    }, indent=2))
    return {"bin": str(bin_path), "json": str(json_path)}


def generate_and_write(
    generated_dir: Path,
    output_dir: Path,
    cycles: int = 1024,
    seed: int = 1,
    name: str = "rfuzz_seed",
    *,
    format_version: str,
) -> dict[str, str]:
    testcase = generate_testcase(
        generated_dir, cycles=cycles, seed=seed, name=name,
        format_version=format_version,
    )
    return write_testcase(testcase, output_dir)


def _require_legacy_format(format_version: str) -> None:
    if format_version != LEGACY_RFUZZ_FORMAT:
        raise ValueError(
            f"legacy RFUZZ action generator requires format_version={LEGACY_RFUZZ_FORMAT!r}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate RFUZZ-style byte testcases for a fuzz harness")
    parser.add_argument("--generated-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--cycles", type=int, default=1024)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--name", default="rfuzz_seed")
    parser.add_argument("--format", choices=(LEGACY_RFUZZ_FORMAT,), required=True)
    args = parser.parse_args()

    outputs = generate_and_write(
        args.generated_dir,
        args.output_dir,
        cycles=args.cycles,
        seed=args.seed,
        name=args.name,
        format_version=args.format,
    )
    print(json.dumps(outputs, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
