#!/usr/bin/env python3
"""One thin entry for the already-verified in-process F5/F6 prototypes.

Step A of ``docs/stage2-prototype-implementation-20261031.md``: select the
existing C++ loop by flow, forward stdin/stdout unchanged (so the ``NEED_RECORD``
online handshake keeps working), and write one normalized ``flow_summary.json``
next to the delegate's own ``summary.json``.

The two loops stay two implementations: this module only *dispatches* and
*normalizes*.  It creates no certificate, no replay and no per-cycle journal;
facts the loop did not print stay ``unknown``.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]

#: Flow -> delegate script.  The delegate keeps its own command line; this
#: table is the only place the entry knows about the two implementations.
DELEGATES = {
    'F5': 'scripts/run_inprocess_irq.py',
    'F6': 'scripts/run_inprocess_f6.py',
}

SCHEMA = 'inprocess_flow_run.v1'

#: Facts neither loop reports.  ``retirement``/``irq_take`` are removed only
#: when the loop itself prints ``*_evidence observed`` (or, for takes, a real
#: take counter); the rest stay unknown by construction.
BASE_UNKNOWN = {
    'dut_internal_state': 'the host sees boundary transactions and declared signals only',
    'cross_case_origin': 'state carried across cases is not attributed to an origin',
    'host_source_discovery': 'the delegate reuses nested host source discovery; not re-observed here',
}

#: Delegate summary key that reports whether a fact was really observed.
EVIDENCE_KEYS = {'retirement': 'retirement_evidence', 'irq_take': 'irq_take_evidence'}


def _value(token):
    """Numbers stay numbers; everything else is kept as the printed token."""
    try:
        return int(token)
    except ValueError:
        pass
    if token.lstrip('+-').lower().startswith('0x'):
        try:
            return int(token, 16)
        except ValueError:
            return token
    try:
        return float(token)
    except ValueError:
        return token


def _pairs(tokens):
    """``key value key value ...`` -> dict; an odd trailing token maps to None."""
    result = {}
    index = 0
    while index < len(tokens):
        key = tokens[index]
        result[key] = _value(tokens[index + 1]) if index + 1 < len(tokens) else None
        index += 2
    return result


def parse_run_log(text):
    """Extract the per-case observations and the closing summary line.

    The C++ loops print one ``case <n> <status> k v ...`` line per finished case
    and one ``summary <status> k v ...`` line at the end; every other line
    (``NEED_RECORD``, ``mmio``, ``dma_read``, ...) is transport detail and is
    deliberately not promoted into the normalized result.
    """
    cases = []
    summary = None
    for line in text.splitlines():
        tokens = line.split()
        if not tokens:
            continue
        if tokens[0] == 'case' and len(tokens) >= 3:
            row = _pairs(tokens[3:])
            row.update(case=_value(tokens[1]), status=tokens[2])
            cases.append(row)
        elif tokens[0] == 'summary' and len(tokens) >= 2:
            row = _pairs(tokens[2:])
            row.update(status=tokens[1])
            summary = row
    return cases, summary


def evidence(raw_summary, summary):
    """Collect ``retirement``/``irq_take`` statements from either result file."""
    result = {}
    for source in (summary or {}, raw_summary or {}):
        for fact, key in EVIDENCE_KEYS.items():
            if key in source and fact not in result:
                result[fact] = source[key]
    return result


def unknown_facts(*, raw_summary, raw_summary_error, cases, summary, inputs):
    """Return the ordered ``unknown -> reason`` map for this run.

    Only printed facts are trusted: a missing evidence key, a summary that
    claims more cases than the log printed, or an absent ``summary.json`` all
    become unknown instead of a default "passed".
    """
    reasons = dict(BASE_UNKNOWN)
    seen = evidence(raw_summary, summary)
    if seen.get('retirement') != 'observed':
        reasons['retirement'] = 'no retirement observation is printed by this loop'
    take_known = seen.get('irq_take') == 'observed'
    if not take_known and seen.get('irq_take') is None:
        take_known = any(key in (source or {})
                         for source in (summary, raw_summary)
                         for key in ('takes', 'irq_takes'))
    if not take_known:
        reasons['irq_take'] = 'no IRQ take observation is printed by this loop'
    if summary is None:
        reasons['summary_line'] = 'run.log has no closing summary line'
    else:
        count = summary.get('cases')
        if type(count) is int and count > len(cases):
            reasons['per_case_observations'] = (
                'summary reports {} cases but the log printed {} case lines'.format(count, len(cases)))
    if raw_summary is None:
        reasons['delegate_summary'] = raw_summary_error or 'the delegate wrote no summary.json'
    if not inputs:
        reasons['case_inputs'] = 'no case input was reported or declared'
    return reasons


def normalize(flow, *, delegate, returncode, raw_summary, raw_summary_error, cases,
              summary, config, output, inputs, input_source, input_mode,
              entry_seconds):
    """Build the one normalized result both flows share."""
    delegate_status = (raw_summary or {}).get('status')
    log_status = (summary or {}).get('status')
    # Any explicit failure wins; a zero exit code alone never invents a pass.
    if returncode != 0 or 'failed' in (delegate_status, log_status):
        status = 'failed'
    else:
        status = delegate_status or log_status or 'unknown'
    reasons = unknown_facts(raw_summary=raw_summary, raw_summary_error=raw_summary_error,
                            cases=cases, summary=summary, inputs=inputs)
    return {
        'schema_version': SCHEMA,
        'flow': flow,
        'path': flow,
        'delegate': {'script': delegate, 'returncode': returncode, 'status': delegate_status},
        'config': str(config),
        'output': str(output),
        'input_mode': input_mode,
        'input_source': input_source,
        'inputs': inputs,
        'observations': {'cases': cases, 'case_count': len(cases), 'summary': summary},
        'timings': {
            'entry_seconds': round(entry_seconds, 6),
            'link_seconds': (raw_summary or {}).get('link_seconds'),
            'run_seconds': (raw_summary or {}).get('run_seconds'),
            'total_seconds': (raw_summary or {}).get('total_seconds'),
        },
        'status': status,
        'unknown': list(reasons),
        'unknown_reasons': reasons,
        'scope': 'one in-process loop selected by flow; compact observations only',
    }


def _absolute(path):
    """Relative arguments mean "relative to the caller", like any CLI."""
    path = Path(path)
    return path if path.is_absolute() else (Path.cwd() / path).resolve()


def _delegate_argv(flow, args, *, config, cache, output):
    """Map the one entry command line onto the selected delegate's command line.

    Flow-specific flags are rejected for the other flow instead of being
    dropped silently; F6 keeps the delegate's own mutually exclusive choice of
    ``--online``/``--records``/``--record``.
    """
    argv = [sys.executable, str(ROOT / DELEGATES[flow]), '--config', str(config),
            '--cache', str(cache), '--output', str(output)]
    if flow == 'F5':
        if args.record is not None or args.records is not None:
            raise SystemExit('--record/--records apply to --flow F6 only')
        if args.assume_lockstep:
            raise SystemExit('--assume-lockstep applies to --flow F6 only')
        argv += ['--max-ticks', str(3000 if args.max_ticks is None else args.max_ticks)]
        if args.online:
            argv.append('--online')
    else:
        if args.max_ticks is not None:
            raise SystemExit('--max-ticks applies to --flow F5 only')
        if args.online and (args.record is not None or args.records is not None):
            raise SystemExit('--online cannot be combined with --record/--records')
        if args.online:
            argv.append('--online')
        elif args.records is not None:
            argv += ['--records', args.records]
        elif args.record is not None:
            argv += ['--record', args.record]
        if args.assume_lockstep:
            argv.append('--assume-lockstep')
    return argv


def _config_document(config_path):
    """Read the scenario declaration only when the delegate did not report inputs."""
    try:
        return json.loads(Path(config_path).read_text())
    except (OSError, ValueError):
        return None


def _inputs_from(raw_summary, flow, config, online):
    """Only facts the delegate wrote or the config declares; never inferred."""
    if raw_summary:
        if flow == 'F5' and isinstance(raw_summary.get('submitted'), list):
            return [list(row) for row in raw_summary['submitted']], 'summary.json:submitted'
        if flow == 'F6' and raw_summary.get('records'):
            return list(raw_summary['records']), 'summary.json:records'
    if flow == 'F5' and not online:
        document = _config_document(config)
        writes = (document or {}).get('trigger_writes')
        if (isinstance(writes, list) and writes
                and all(isinstance(row, (list, tuple)) and len(row) >= 2 for row in writes)):
            return [[int(row[1]) for row in writes]], 'config.json:trigger_writes'
    return [], None


def _parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--flow', required=True, choices=sorted(DELEGATES))
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True,
                        help='new directory inside the workspace')
    parser.add_argument('--online', action='store_true',
                        help='read one input per line on demand (NEED_RECORD)')
    parser.add_argument('--max-ticks', type=int, default=None,
                        help='F5 only: tick budget per case (delegate default 3000)')
    records = parser.add_mutually_exclusive_group()
    records.add_argument('--record', help='F6 only: one raw8 record in hexadecimal')
    records.add_argument('--records', help='F6 only: comma-separated raw8 records')
    parser.add_argument('--assume-lockstep', action='store_true',
                        help='F6 only: explicitly simulate equal periods')
    return parser


def main(argv=None):
    parser = _parser()
    args = parser.parse_args(argv)
    if args.max_ticks is not None and args.max_ticks < 1:
        parser.error('--max-ticks must be positive')
    config, cache, output = _absolute(args.config), _absolute(args.cache), _absolute(args.output)
    if output.exists():
        raise SystemExit('output directory already exists: ' + str(output))
    delegate_argv = _delegate_argv(args.flow, args, config=config, cache=cache, output=output)
    started = time.monotonic()
    # Inherit stdin/stdout/stderr on purpose: the online mode is a live
    # ``NEED_RECORD`` conversation between the loop and whoever runs this entry.
    try:
        returncode = subprocess.run(delegate_argv, cwd=str(ROOT)).returncode
    except KeyboardInterrupt:
        returncode = -2
    entry_seconds = time.monotonic() - started
    raw_summary, raw_summary_error = None, None
    summary_path = output / 'summary.json'
    if summary_path.is_file():
        try:
            raw_summary = json.loads(summary_path.read_text())
        except (OSError, ValueError) as error:
            raw_summary_error = 'summary.json is unreadable: ' + str(error)
    log_path = output / 'run.log'
    try:
        text = log_path.read_text(errors='replace') if log_path.is_file() else ''
    except OSError:
        text = ''
    cases, summary = parse_run_log(text)
    inputs, input_source = _inputs_from(raw_summary, args.flow, config, args.online)
    result = normalize(args.flow, delegate=DELEGATES[args.flow], returncode=returncode,
                       raw_summary=raw_summary, raw_summary_error=raw_summary_error,
                       cases=cases, summary=summary, config=config, output=output,
                       inputs=inputs, input_source=input_source,
                       input_mode='online' if args.online else 'preloaded',
                       entry_seconds=entry_seconds)
    # The delegate refuses a pre-existing directory, so the entry creates the
    # output only now: a failure before that point must still leave a summary.
    output.mkdir(parents=True, exist_ok=True)
    flow_summary = output / 'flow_summary.json'
    flow_summary.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'flow': args.flow, 'status': result['status'],
                      'flow_summary': str(flow_summary), 'cases': len(cases),
                      'entry_seconds': result['timings']['entry_seconds']}), flush=True)
    return returncode if returncode >= 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
