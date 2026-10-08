#!/usr/bin/env python3
"""Read-only survey of one saved online trace's event kinds (no RTL, no writes).

Usage: python3 scripts/survey_online_trace_kinds.py RUN_DIR [--json-out PATH]
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, (ROOT / "src").as_posix())

from myfuzz.scenario.acceptance_metrics import TraceEventStream  # noqa: E402


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir")
    parser.add_argument("--json-out")
    parser.add_argument("--samples", type=int, default=2)
    args = parser.parse_args(argv[1:])

    stream = TraceEventStream(Path(args.run_dir))
    kinds: Counter = Counter()
    per_component: dict[str, Counter] = defaultdict(Counter)
    samples: dict[str, list[dict]] = defaultdict(list)
    total = 0
    for event in stream.events():
        total += 1
        kind = event.get("kind")
        kind_key = kind if isinstance(kind, str) else "<no-kind>"
        component = event.get("component")
        # A record without a component is a real category of its own; it is named
        # explicitly rather than dropped, so the census counts every event.
        component_key = component if isinstance(component, str) else "<no-component>"
        kinds[kind_key] += 1
        per_component[component_key][kind_key] += 1
        if len(samples[kind_key]) < args.samples:
            samples[kind_key].append(event)
    document = {
        "schema_version": "online_trace_kind_survey.v1",
        "run_dir": args.run_dir,
        "events": total,
        "kind_counts": dict(kinds.most_common()),
        "component_kind_counts": {
            component: dict(counter.most_common())
            for component, counter in sorted(per_component.items())},
        "samples": {kind: rows for kind, rows in sorted(samples.items())},
    }
    text = json.dumps(document, indent=1, sort_keys=True)
    if args.json_out:
        Path(args.json_out).write_text(text + "\n", encoding="utf-8")
    print(f"events={total} kinds={len(kinds)}")
    for kind, count in kinds.most_common(40):
        print(f"  {count:8d}  {kind}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
