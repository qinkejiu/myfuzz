#!/usr/bin/env python3
"""P5 acceptance **suite**: judge declared runs and union their P5 evidence.

``--run ROLE=DIR[@COMPARE_DIR]`` declares one saved run with an explicit role
(repeatable); ``--artifact ROLE=KEY=PATH`` declares one extra evidence artifact
that a role needs but that does not sit inside the run directory (repeatable).
:func:`myfuzz.scenario.p5_acceptance.p5_acceptance_suite` judges every declared
run against the six P5 critical items and unions the verdicts into a
``p5_acceptance_suite.v1`` document: which run proves which item, which run
measured an item without meeting it, and which item no run proves at all.

Exit codes: ``0`` = every critical item has at least one run that measured and
met it, ``2`` = a critical item has no proving run (or a declared run proves no
item and is reported as such), ``1`` = the command could not run at all (bad
declaration, missing directory, unreadable path).

``--reports-dir`` writes each run's own ``p5_acceptance_report.v1`` document, so
every verdict in the suite can be recomputed field by field.

The command never renders a harness and never starts an RTL process.  With
``--invoke-assertion-classes`` it runs the shipped, read-only
``scripts/report_p5_assertion_classes.py`` over a declared run and writes its
document into ``--scratch-dir``; without the flag it reads the saved assertion
class report instead.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.as_posix() not in sys.path:
    sys.path.insert(0, SRC.as_posix())

from myfuzz.scenario.p5_acceptance import (  # noqa: E402
    ERROR_SCHEMA_VERSION,
    EXIT_NOT_READY,
    EXIT_READY,
    EXIT_USAGE,
    p5_acceptance_report,
    p5_acceptance_suite,
    parse_artifact_declaration,
    parse_run_declaration,
    render_markdown,
)

_UNSAFE_NAME = re.compile(r"[^0-9A-Za-z._-]+")

#: Default scratch directory for CLI-produced assertion-class documents.  It is
#: a new directory in the repository's own ``*-logs`` convention; no saved run
#: is ever written to.
DEFAULT_SCRATCH = ROOT / "runs" / "p5-acceptance-suite-20261008-logs"


class _Parser(argparse.ArgumentParser):
    """ArgumentParser whose usage errors are hard errors, not 'not ready'.

    argparse exits 2 on a usage error by default, which is indistinguishable
    from the suite's own "evidence missing" exit code, so usage errors are
    raised and mapped to ``EXIT_USAGE`` with the same error document as every
    other hard failure.
    """

    def error(self, message: str):  # type: ignore[override]
        raise ValueError(f"argument error: {message}")


def _dump(document: object) -> str:
    return json.dumps(document, sort_keys=True, allow_nan=False)


def _write_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _report_name(role: str) -> str:
    return f"report-{_UNSAFE_NAME.sub('_', role)}.json"


def _declarations(runs: list[str], artifacts: list[str]) -> list[dict]:
    declarations = [parse_run_declaration(spec) for spec in runs]
    by_role = {declaration["role"]: declaration for declaration in declarations}
    for spec in artifacts:
        parsed = parse_artifact_declaration(spec)
        declaration = by_role.get(parsed["role"])
        if declaration is None:
            raise ValueError(
                f"artifact declaration {spec!r} names role {parsed['role']!r}, "
                "which no --run declares")
        declaration["artifacts"][parsed["key"]] = parsed["path"]
    return declarations


def _run(args: argparse.Namespace) -> int:
    declarations = _declarations(args.run, args.artifact or [])
    suite = p5_acceptance_suite(declarations,
                                invoke_assertion_classes=args.invoke_assertion_classes,
                                scratch_dir=args.scratch_dir)
    payload = _dump(suite)
    print(payload)
    if args.json_out is not None:
        _write_text(Path(args.json_out), payload + "\n")
    if args.markdown_out is not None:
        _write_text(Path(args.markdown_out), render_markdown(suite))
    if args.reports_dir is not None:
        directory = Path(args.reports_dir)
        for declaration, run in zip(declarations, suite["runs"]):
            # Judge the run once more on exactly the artifacts the suite
            # resolved, so the dumped report is field-by-field reproducible and
            # the shipped assertion-class CLI is not invoked a second time.
            resolved = {key: record["path"]
                        for key, record in (run.get("resolved_artifacts") or {}).items()
                        if record.get("available") and record.get("path")}
            report = p5_acceptance_report(
                declaration["run_dir"], role=declaration["role"],
                compare_run=declaration["compare_run"],
                artifacts=resolved,
                expected_findings=suite["antecedent_findings"],
                scratch_dir=args.scratch_dir)
            _write_text(directory / _report_name(declaration["role"]),
                        _dump(report) + "\n")
    gate = suite["gate"]
    print(f"p5 acceptance suite: exit={gate['exit_code']} ready={gate['ready']} "
          f"critical={gate['critical_met']}/{gate['critical_total']} "
          f"no_proving_run={gate['no_proving_run']}", file=sys.stderr)
    return EXIT_READY if gate["exit_code"] == EXIT_READY else EXIT_NOT_READY


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description=__doc__)
    parser.add_argument("--run", action="append", required=True,
                        metavar="ROLE=DIR[@COMPARE_DIR]",
                        help="one declared run with an explicit role "
                             "(repeatable)")
    parser.add_argument("--artifact", action="append", metavar="ROLE=KEY=PATH",
                        help="one extra declared artifact for a role "
                             "(repeatable)")
    parser.add_argument("--invoke-assertion-classes", action="store_true",
                        help="run the shipped read-only assertion-class CLI over "
                             "each declared run instead of reading a saved "
                             "report")
    parser.add_argument("--scratch-dir", type=Path, default=None,
                        help=f"where CLI-produced documents are written "
                             f"(default: {DEFAULT_SCRATCH})")
    parser.add_argument("--json-out", type=Path,
                        help="write the suite document here as well as stdout")
    parser.add_argument("--markdown-out", type=Path,
                        help="write the rendered union table here")
    parser.add_argument("--reports-dir", type=Path,
                        help="write each run's own p5_acceptance_report.v1 "
                             "document here (one file per role)")
    last_spec = None
    try:
        args = parser.parse_args(argv)
        if args.run:
            last_spec = args.run[-1]
        if args.scratch_dir is None:
            args.scratch_dir = DEFAULT_SCRATCH
        return _run(args)
    except (ValueError, OSError) as exc:
        print(_dump({"schema_version": ERROR_SCHEMA_VERSION,
                     "command": "suite", "run": last_spec,
                     "error_type": type(exc).__name__, "error": str(exc),
                     "exit_code": EXIT_USAGE}))
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
