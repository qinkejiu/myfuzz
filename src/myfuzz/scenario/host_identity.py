"""Auditable source closure for scenario host semantics and replay checks.

Keep this list explicit. Adding a new Python module that affects direct
scenario execution, decoding, checking, or replay requires adding its path.
Campaign orchestration and the Rust search client have separate identities;
changing those does not change a fixed Genome replay.
"""

from __future__ import annotations

import hashlib
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[3]
HOST_SOURCE_PATHS = (
    "src/myfuzz/scenario/campaign.py",
    "src/myfuzz/scenario/checker.py",
    "src/myfuzz/scenario/contracts.py",
    "src/myfuzz/scenario/cva6_gpio_example.py",
    "src/myfuzz/scenario/cva6_session.py",
    "src/myfuzz/scenario/dependency.py",
    "src/myfuzz/scenario/edge_experiments.py",
    "src/myfuzz/scenario/evidence.py",
    "src/myfuzz/scenario/examples.py",
    "src/myfuzz/scenario/feedback.py",
    "src/myfuzz/scenario/genome.py",
    "src/myfuzz/scenario/gpio_session.py",
    "src/myfuzz/scenario/host_identity.py",
    "src/myfuzz/scenario/ibex_session.py",
    "src/myfuzz/scenario/identity.py",
    "src/myfuzz/scenario/ip_cpu_ip_example.py",
    "src/myfuzz/scenario/irq.py",
    "src/myfuzz/scenario/ledger.py",
    "src/myfuzz/scenario/memory.py",
    "src/myfuzz/scenario/memory_service.py",
    "src/myfuzz/scenario/mutation.py",
    "src/myfuzz/scenario/ownership.py",
    "src/myfuzz/scenario/protocol_io.py",
    "src/myfuzz/scenario/replay.py",
    "src/myfuzz/scenario/rfuzz_decoder.py",
    "src/myfuzz/scenario/router.py",
    "src/myfuzz/scenario/runner.py",
    "src/myfuzz/scenario/scheduler.py",
    "src/myfuzz/scenario/state_dependency.py",
    "src/myfuzz/scenario/uart_gpio_example.py",
    "src/myfuzz/scenario/uart_example.py",
    "src/myfuzz/scenario/uart_session.py",
    "scripts/record_scenario.py",
    "scripts/replay_scenario.py",
)


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def host_source_identity() -> dict:
    files = []
    for name in HOST_SOURCE_PATHS:
        path = _ROOT / name
        if not path.is_file():
            raise ValueError(f"host source is missing: {name}")
        files.append({"path": name, "sha256": _hash_file(path)})
    return {"schema_version": "scenario_host_sources.v1", "files": files}


def verify_host_source_identity(saved: dict) -> dict:
    """Reject a missing, reordered, changed, or added semantic source."""
    if not isinstance(saved, dict) or set(saved) != {"schema_version", "files"}:
        raise ValueError("host source identity shape is invalid")
    if saved["schema_version"] != "scenario_host_sources.v1":
        raise ValueError("host source schema_version is unsupported")
    files = saved["files"]
    if not isinstance(files, list) or len(files) != len(HOST_SOURCE_PATHS):
        raise ValueError("host source list differs from the declared closure")
    for expected_path, record in zip(HOST_SOURCE_PATHS, files):
        if (not isinstance(record, dict) or set(record) != {"path", "sha256"}
                or record["path"] != expected_path):
            raise ValueError("host source path list differs from the declared closure")
        path = _ROOT / expected_path
        if not path.is_file():
            raise ValueError(f"host source is missing: {expected_path}")
        if record["sha256"] != _hash_file(path):
            raise ValueError(f"host source sha256 mismatch: {expected_path}")
    return saved
