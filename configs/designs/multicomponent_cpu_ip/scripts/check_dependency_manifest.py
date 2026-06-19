#!/usr/bin/env python3
"""Lightweight checks for CPU + multi-IP dependency manifests."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REQUIRED_TOP_LEVEL = {
    "name",
    "version",
    "target",
    "components",
    "connections",
    "address_map",
    "dependency_rules",
    "fairness",
}


def load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: manifest must be a JSON object")
    return data


def require_keys(context: str, item: dict, keys: set[str]) -> None:
    missing = sorted(keys - set(item))
    if missing:
        raise SystemExit(f"{context}: missing required key(s): {', '.join(missing)}")


def require_list(context: str, data: dict, key: str) -> list:
    value = data.get(key)
    if not isinstance(value, list) or not value:
        raise SystemExit(f"{context}: {key} must be a non-empty list")
    return value


def check_manifest(path: Path) -> None:
    data = load_json(path)
    require_keys(path.as_posix(), data, REQUIRED_TOP_LEVEL)

    target = data["target"]
    if not isinstance(target, dict):
        raise SystemExit(f"{path}: target must be an object")
    require_keys("target", target, {"top", "style"})

    for index, component in enumerate(require_list(path.as_posix(), data, "components")):
        if not isinstance(component, dict):
            raise SystemExit(f"components[{index}]: must be an object")
        require_keys(f"components[{index}]", component, {"instance", "module", "kind"})

    for index, connection in enumerate(require_list(path.as_posix(), data, "connections")):
        if not isinstance(connection, dict):
            raise SystemExit(f"connections[{index}]: must be an object")
        require_keys(f"connections[{index}]", connection, {"from", "to", "role"})

    for index, entry in enumerate(require_list(path.as_posix(), data, "address_map")):
        if not isinstance(entry, dict):
            raise SystemExit(f"address_map[{index}]: must be an object")
        require_keys(f"address_map[{index}]", entry, {"name", "base", "size", "target"})

    for index, rule in enumerate(require_list(path.as_posix(), data, "dependency_rules")):
        if not isinstance(rule, dict):
            raise SystemExit(f"dependency_rules[{index}]: must be an object")
        require_keys(f"dependency_rules[{index}]", rule, {"name", "kind", "baseline", "depaware"})

    fairness = data["fairness"]
    if not isinstance(fairness, dict):
        raise SystemExit(f"{path}: fairness must be an object")
    require_keys(
        "fairness",
        fairness,
        {"same_target", "same_instrumentation", "same_coverage_denominator"},
    )
    for key in ("same_target", "same_instrumentation", "same_coverage_denominator"):
        if fairness[key] is not True:
            raise SystemExit(f"fairness.{key} must be true for a valid comparison")

    print(
        f"ok: {path} "
        f"components={len(data['components'])} "
        f"connections={len(data['connections'])} "
        f"regions={len(data['address_map'])} "
        f"rules={len(data['dependency_rules'])}"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", nargs="+", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    for path in args.manifest:
        check_manifest(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
