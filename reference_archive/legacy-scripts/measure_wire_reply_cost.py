#!/usr/bin/env python3
"""Offline cost of one recorded driver reply, split into its host stages.

The per-tick wire roundtrip is the only host cost that cannot be replayed
offline, so this script measures everything the host does with a reply it has
already read, on the replies a real run actually produced:

* ``fromhex``          -- decode the payload hex (``bytes.fromhex``),
* ``json.loads``       -- parse it with the driver's unique-key hook,
* ``validate``         -- ``wire._payload`` (value scan + canonical re-render +
                          schema/sample validation) on the same bytes,
* ``deepcopy``         -- detach ``payload['samples']`` the way a session does.

The input is a saved ``local_commands.json`` (recorded by
``--record-local-commands``); nothing is executed and no artifact is modified.
Reported seconds are for the whole saved sequence, so they can be compared with
the ``command_roundtrips`` seconds of the same run: the difference is the pipe +
driver time, which is exactly what an IPC batching change could remove.
"""
import argparse
from collections import defaultdict
from copy import deepcopy
import json
from pathlib import Path
import statistics
import sys
import time

sys.path[:0] = [str(Path(__file__).resolve().parents[1] / 'src')]


def _median(values):
    return statistics.median(values) if values else None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trace', type=Path, required=True,
                        help='local_commands.json recorded by a real run')
    parser.add_argument('--output', type=Path,
                        help='optional JSON report path')
    args = parser.parse_args(argv)
    from myfuzz.local_harness import wire

    document = json.loads(args.trace.read_text())
    sessions = document.get('sessions')
    if type(sessions) is not dict or not sessions:
        raise ValueError('saved local command trace required')
    rows = defaultdict(lambda: defaultdict(list))
    sizes = defaultdict(list)
    for name, session in sessions.items():
        records = session.get('records') or []
        for record in records:
            command = record.get('command') or ''
            reply = record.get('reply') or ''
            before, after = record.get('tick_before'), record.get('tick_after')
            if type(before) is not int or type(after) is not int:
                continue
            parts = reply.split(' ')
            if len(parts) != 6 or parts[0] != 'RESULT':
                continue
            encoded = parts[5]
            # The recorded payload names its own kind; the receipt parser takes
            # it from the artifact, so this stays a faithful stage measurement.
            raw = bytes.fromhex(encoded)
            kind = json.loads(raw.decode('utf-8')).get('kind')
            operation = command.split(' ')[3] if len(command.split(' ')) > 3 else 'unknown'
            key = (name, operation)
            started = time.perf_counter()
            bytes.fromhex(encoded)
            rows[key]['fromhex'].append(time.perf_counter() - started)
            started = time.perf_counter()
            parsed = json.loads(raw.decode('utf-8'),
                                object_pairs_hook=wire._unique_object)
            rows[key]['json_loads'].append(time.perf_counter() - started)
            started = time.perf_counter()
            payload = wire._payload(encoded, kind=kind, before=before, after=after)
            rows[key]['validate'].append(time.perf_counter() - started)
            started = time.perf_counter()
            deepcopy(payload['samples'])
            rows[key]['deepcopy_samples'].append(time.perf_counter() - started)
            sizes[key].append(len(encoded) // 2)
            if parsed.get('kind') != kind:
                raise ValueError('payload kind mismatch')
    report = dict(schema_version='wire_reply_cost.v1', trace=str(args.trace),
                  scope='host-only stages of already-read recorded replies',
                  not_measured=['pipe write/read syscalls', 'driver-side eval and '
                                'payload render', 'session bookkeeping after the reply'],
                  sessions={})
    totals = defaultdict(float)
    for (name, operation), stages in sorted(rows.items()):
        count = len(stages['validate'])
        row = dict(count=count,
                   payload_bytes=dict(median=_median(sizes[(name, operation)]),
                                      maximum=max(sizes[(name, operation)])))
        for stage in ('fromhex', 'json_loads', 'validate', 'deepcopy_samples'):
            total = sum(stages[stage])
            totals[stage] += total
            row[stage] = dict(total_seconds=round(total, 6),
                              median_ms=round(1000 * _median(stages[stage]), 3))
        report['sessions'].setdefault(name, {})[operation] = row
    report['totals'] = {stage: round(total, 6) for stage, total in sorted(totals.items())}
    report['totals']['host_stage_seconds'] = round(sum(totals.values()), 6)
    encoded = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded)
    sys.stdout.write(encoded)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
