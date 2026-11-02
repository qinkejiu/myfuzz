#!/usr/bin/env python3
"""Measure the duplicated shared-slot export: two renders vs one render + copy.

``run_shared_slot_descriptor`` publishes one prefix document to two paths,
``prefix.json`` and ``compiled_f6_prefix.json`` (211 425 765 identical bytes
each in the recorded ``tail-v1`` artifacts).  Before this change the document
was rendered twice with ``json.dumps(indent=2, sort_keys=True, default=str)``;
now it is rendered once and the second path receives the same bytes.

This script measures that difference on a real recorded document:

* ``legacy``  -- two independent renders + two writes (the old behaviour),
* ``shipped`` -- one render + two writes (the current writer),

and asserts every written document is byte-identical to a direct
``json.dumps`` of the same value, so the saving can never come from writing
different bytes.  ``--replay`` repeats the measurement for the ``replay.json``
pair, which is deliberately *not* deduplicated (its first write is the audit
sink call inside ``CompiledF6Runtime.replay``), so those numbers are an estimate
of the remaining opportunity, not a change.  ``--compact`` measures the rejected
option (compact separators) so the rejection can be quoted with real numbers.

Usage
-----
::

    PYTHONPATH=src:. python3 scripts/bench_shared_slot_export_writes.py \
      --source research/input-strategy-audit-20261027/runs/\
shared-performance-20261029/tail-v1/workload/original/prefix.json --compact
    PYTHONPATH=src:. python3 scripts/bench_shared_slot_export_writes.py \
      --replay research/input-strategy-audit-20261027/runs/\
shared-performance-20261029/tail-v1/workload/original/replay.json

Scratch files are written to a fresh temporary directory (never under
``research/`` or ``runs/``) and removed unless ``--keep`` is given.  No RTL, no
campaign, no network.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.as_posix() not in sys.path:
    sys.path.insert(0, SRC.as_posix())

from myfuzz.runtime.generic_campaign import _json  # noqa: E402


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def measure_pair(document, directory: Path, stem: str) -> dict:
    """Time two-render and one-render publication of the same document."""
    first = directory / f"{stem}.legacy-1.json"
    second = directory / f"{stem}.legacy-2.json"
    shipped = directory / f"{stem}.shipped-2.json"

    started = time.perf_counter()
    _json(document, first)
    _json(document, second)
    legacy_seconds = time.perf_counter() - started

    started = time.perf_counter()
    rendered = _json(document, first)
    _json(document, shipped, rendered=rendered)
    shipped_seconds = time.perf_counter() - started

    started = time.perf_counter()
    direct = json.dumps(document, indent=2, sort_keys=True, default=str) + "\n"
    render_seconds = time.perf_counter() - started

    started = time.perf_counter()
    shipped.write_text(direct)
    write_seconds = time.perf_counter() - started

    legacy_bytes = first.read_bytes()
    assert legacy_bytes == second.read_bytes(), "legacy renders differ"
    assert legacy_bytes == shipped.read_bytes(), "republished export differs"
    assert direct == first.read_text(), "direct render differs from _json"
    return {"stem": stem,
            "bytes_per_file": len(legacy_bytes),
            "sha256": sha256(first),
            "legacy_two_renders_seconds": round(legacy_seconds, 3),
            "shipped_one_render_seconds": round(shipped_seconds, 3),
            "saved_seconds": round(legacy_seconds - shipped_seconds, 3),
            "one_render_seconds": round(render_seconds, 3),
            "one_write_seconds": round(write_seconds, 3),
            "render_mb_per_second": round(len(legacy_bytes) / 1e6 / render_seconds, 1),
            "renders": {"legacy": 2, "shipped": 1},
            "writes": {"legacy": 2, "shipped": 2},
            "byte_identical": True}


def measure_compact(document, pretty_bytes: int) -> dict:
    """The rejected option: compact separators change every recorded hash."""
    started = time.perf_counter()
    compact = json.dumps(document, sort_keys=True, separators=(",", ":"),
                         default=str) + "\n"
    seconds = time.perf_counter() - started
    return {"pretty_bytes": pretty_bytes, "compact_bytes": len(compact),
            "compact_render_seconds": round(seconds, 3),
            "pretty_over_compact_bytes": round(pretty_bytes / len(compact), 3),
            "compact_render_mb_per_second": round(len(compact) / 1e6 / seconds, 1),
            "implemented": False,
            "reason": "changes every recorded document hash (prefix.json, "
                      "compiled_f6_prefix.json, replay.json are identity-bound by "
                      "SHA256 in manifests and by the recorded A/B artifacts)"}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source", type=Path, default=None,
                        help="recorded prefix.json whose document is exported")
    parser.add_argument("--replay", type=Path, default=None,
                        help="recorded replay.json (estimate only; not implemented)")
    parser.add_argument("--compact", action="store_true",
                        help="also measure the rejected compact-rendering option")
    parser.add_argument("--keep", action="store_true",
                        help="keep the scratch export directory")
    parser.add_argument("--json", type=Path, default=None,
                        help="also write the measurement here")
    args = parser.parse_args(argv)
    if args.source is None and args.replay is None:
        raise SystemExit("--source and/or --replay is required")

    directory = Path(tempfile.mkdtemp(prefix="myfuzz-export-bench-"))
    report = {"source": str(args.source) if args.source else None,
              "pairs": [], "estimates_not_implemented": [], "rejected": [],
              "scratch": str(directory)}
    try:
        if args.source is not None:
            document = json.loads(args.source.read_text())
            pair = measure_pair(document, directory, "prefix")
            report["pairs"].append(pair)
            if args.compact:
                report["rejected"].append(measure_compact(
                    document, pair["bytes_per_file"]))
            del document
        if args.replay is not None:
            envelope = json.loads(args.replay.read_text())
            replay_pair = measure_pair(envelope, directory, "replay")
            report["estimates_not_implemented"].append({
                **replay_pair,
                "reason": "the first replay.json write is "
                          "CompiledF6Runtime.replay's audit_sink call; republishing "
                          "would couple the export writer to that sink's document "
                          "identity and would drop the failure-path artifact"})
            if args.compact:
                report["rejected"].append(measure_compact(
                    envelope, replay_pair["bytes_per_file"]))
            del envelope
    finally:
        if args.keep:
            report["scratch_kept"] = True
        else:
            shutil.rmtree(directory, ignore_errors=True)
            report["scratch"] = "removed"
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.json is not None:
        args.json.write_text(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
