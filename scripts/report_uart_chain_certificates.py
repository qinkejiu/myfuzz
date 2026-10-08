#!/usr/bin/env python3
"""Write the UART chain certificate report of one saved run as JSON.

Read-only: the report is recomputed from the run's saved terminal trace by
:func:`myfuzz.scenario.uart_chain_certificates.uart_chain_certificates`, one
streaming pass that never renders RTL, never starts a fuzzer and never writes
into the run directory.

Exit codes:

``0``
    the scan completed and every emitted certificate is self-consistent. The
    totals, the per-hop witness counts, the first-missing-hop histogram and the
    refusal histogram are printed.
``1``
    the run holds no streamable trace, its artifacts contradict the frozen
    ``runtime_uart_chain_certificate.v1`` contract, or a self-consistency check
    of the emitted certificates failed. The document is still written when the
    scan itself completed, so the failure can be inspected.
``3``
    usage error (unknown option, missing ``--run``, or ``--run`` is not a
    directory). Nothing is read and nothing is written.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from myfuzz.scenario.acceptance_metrics import TraceUnavailable
from myfuzz.scenario.uart_chain_certificates import (
    IRQ_HOPS,
    SCHEMA_VERSION,
    UART_HOPS,
    uart_chain_certificates,
)


EXIT_OK = 0
EXIT_READ_ERROR = 1
EXIT_USAGE = 3


class _UsageParser(argparse.ArgumentParser):
    """Argparse that reports usage errors with this tool's exit code."""

    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(EXIT_USAGE)


def configure_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--run", type=Path, required=True,
                        help="saved run directory holding a streamable online trace")
    parser.add_argument("--json-out", type=Path, default=None,
                        help="optional JSON document to write; nothing is written "
                             "when omitted and the run directory is never modified")
    parser.add_argument("--max-pending", type=int, default=128,
                        help="unsettled candidate bound (default 128)")
    parser.add_argument("--max-event-gap", type=int, default=65536,
                        help="events a candidate may go without a new hop before "
                             "it settles incomplete (default 65536)")
    parser.add_argument("--max-identities", type=int, default=4096,
                        help="retained entries per identity index (default 4096)")
    parser.add_argument("--polling-tolerant", action="store_true",
                        help="do not require the four CPU IRQ hops, so a frame "
                             "whose read chain completed without a joined "
                             "interrupt can certify and reports irq_mode instead")


def _hop_lines(document: dict) -> list:
    lines = []
    counts = document["witness_counts"]
    events = document["hop_event_counts"]
    for hop in UART_HOPS:
        lines.append(f"  {hop}: certificates={counts[hop]}")
    for kind in sorted(events):
        lines.append(f"  kind {kind}: events={events[kind]}")
    return lines


def _report(document: dict) -> str:
    lines = [
        f"schema={document['schema_version']} direction={document['direction']} "
        f"require_irq_leg={document['require_irq_leg']}",
        f"trace: format={document['trace']['format']} "
        f"events_ingested={document['trace']['events_ingested']} "
        f"semantic_sha256_verified={document['trace']['semantic_sha256_verified']}",
        f"candidates={document['candidates_total']} "
        f"certificates={document['certificates_total']} "
        f"certified={document['certified_total']} "
        f"incomplete={document['incomplete_total']}",
        f"first_missing_hop_histogram="
        f"{json.dumps(document['first_missing_hop_histogram'], sort_keys=True)}",
        f"irq_mode_histogram="
        f"{json.dumps(document['irq_mode_histogram'], sort_keys=True)}",
        f"refusals={document['refusals_total']} "
        f"{json.dumps(document['refusals_by_reason'], sort_keys=True)} "
        f"refused_hops={json.dumps(document['refused_hops'])}",
        f"expired={document['expired_total']} evicted={document['evicted_total']} "
        f"contradicted={document['contradicted_total']} "
        f"late_events_after_settlement="
        f"{document['late_events_after_settlement']}",
        f"self_consistent={document['self_consistent']}",
    ]
    irq_witnessed = sum(document["witness_counts"][hop] for hop in IRQ_HOPS)
    lines.append(f"irq_hop_witnesses={irq_witnessed}")
    lines.extend(_hop_lines(document))
    return "\n".join(lines)


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if not args.run.is_dir():
        parser.error(f"run directory does not exist: {args.run}")
    try:
        document = uart_chain_certificates(
            args.run, max_pending=args.max_pending,
            max_event_gap=args.max_event_gap,
            max_identities=args.max_identities,
            require_irq_leg=not args.polling_tolerant)
    except (TraceUnavailable, ValueError, OSError) as exc:
        print(f"no UART chain certificates for {args.run}: {exc}", file=sys.stderr)
        return EXIT_READ_ERROR

    if document["schema_version"] != SCHEMA_VERSION:
        print(f"unsupported schema {document['schema_version']!r}", file=sys.stderr)
        return EXIT_READ_ERROR

    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(document, indent=1, sort_keys=True) + "\n",
            encoding="utf-8")

    print(f"{args.run}: {_report(document)}")
    if args.json_out is not None:
        print(f"wrote {args.json_out}")

    if not document["self_consistent"]:
        for check in document["self_consistency_checks"]:
            if not check["ok"]:
                print(f"inconsistent: {check['check']}: {check['detail']}",
                      file=sys.stderr)
        return EXIT_READ_ERROR
    return EXIT_OK


def main(argv=None) -> int:
    parser = _UsageParser(description=__doc__)
    configure_parser(parser)
    return run(parser.parse_args(argv), parser)


if __name__ == "__main__":
    raise SystemExit(main())
