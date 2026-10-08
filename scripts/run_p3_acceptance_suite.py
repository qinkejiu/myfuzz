#!/usr/bin/env python3
"""P3 acceptance **suite**: judge declared runs and union their P3 evidence.

``--run ROLE=DIR[@COMPARE_DIR]`` declares one saved run with an explicit role
(repeatable).  Each declaration is judged by the frozen per-run consumer
:func:`myfuzz.scenario.p3_acceptance.p3_acceptance_report`, and this command
aggregates the verdicts into a ``p3_acceptance_suite.v1`` document: which run
proves which critical item, which item no run proves, and what the union can
never show (see the report's own ``limits``).

Exit codes: ``0`` = every critical item has at least one proving run, ``2`` =
some critical item has no proving run (or a declared run's report could not be
produced, or an engine hash does not match), ``1`` = the command could not run
at all (bad declaration, missing directory).

``--reports-dir`` writes each run's own ``p3_acceptance_report.v1`` document, so
every ``evidence_digest`` in the suite can be recomputed field by field.

This entry point never renders a harness, never starts an RTL process and never
touches a simulator.
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

from myfuzz.scenario.p3_acceptance import (  # noqa: E402
    p3_acceptance_report,
)
from myfuzz.scenario.p3_acceptance_suite import (  # noqa: E402
    EXIT_NOT_READY,
    EXIT_READY,
    p3_acceptance_suite,
    render_markdown,
)

#: The command could not run at all (bad arguments, missing run directory).
EXIT_USAGE = 1
ERROR_SCHEMA_VERSION = "p3_acceptance_suite_error.v1"
_UNSAFE_NAME = re.compile(r"[^0-9A-Za-z._-]+")


class _Parser(argparse.ArgumentParser):
    """ArgumentParser whose usage errors are hard errors, not 'not ready'.

    argparse exits 2 on a usage error by default, which is indistinguishable
    from the gate's own "evidence missing" exit code, so usage errors are
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


def parse_run_declaration(spec: str) -> dict:
    """``ROLE=DIR[@COMPARE_DIR]`` -> one explicit run declaration.

    The role is taken from the text before the first ``=`` and is never guessed
    from the directory name; the comparison directory is taken from the last
    ``@`` so a path may contain ``@``.
    """
    if not isinstance(spec, str) or "=" not in spec:
        raise ValueError(
            f"run declaration {spec!r} is not ROLE=DIR[@COMPARE_DIR]")
    role, _, remainder = spec.partition("=")
    run_dir, _, compare_run = remainder.rpartition("@")
    if not run_dir:
        run_dir = remainder
        compare_run = ""
    if not role.strip():
        raise ValueError(f"run declaration {spec!r} has an empty role")
    if not run_dir.strip():
        raise ValueError(f"run declaration {spec!r} has an empty run directory")
    return {"role": role, "run_dir": run_dir,
            "compare_run": compare_run or None}


def _declarations(specs: list[str]) -> list[dict]:
    return [parse_run_declaration(spec) for spec in specs]


def _engine_hashes(values: list[str] | None) -> dict | None:
    if not values:
        return None
    hashes: dict[str, str] = {}
    for value in values:
        module, separator, digest = value.partition("=")
        if not separator or not module.strip() or not digest.strip():
            raise ValueError(
                f"--engine-hash {value!r} is not MODULE=SHA256")
        hashes[module.strip()] = digest.strip()
    return hashes


def _report_name(role: str) -> str:
    return f"report-{_UNSAFE_NAME.sub('_', role)}.json"


def _run(args: argparse.Namespace) -> int:
    declarations = _declarations(args.run)
    suite = p3_acceptance_suite(declarations,
                                engine_hashes=_engine_hashes(args.engine_hash))
    payload = _dump(suite)
    print(payload)
    if args.json_out is not None:
        _write_text(Path(args.json_out), payload + "\n")
    if args.markdown_out is not None:
        _write_text(Path(args.markdown_out), render_markdown(suite))
    if args.reports_dir is not None:
        directory = Path(args.reports_dir)
        for declaration in declarations:
            role = declaration["role"]
            # The frozen producer is deterministic on saved artifacts, so this
            # second call returns exactly the document the suite judged; it is
            # dumped so every evidence_digest can be recomputed field by field.
            report = p3_acceptance_report(
                declaration["run_dir"],
                compare_run=declaration["compare_run"])
            _write_text(directory / _report_name(role), _dump(report) + "\n")
    gate = suite["gate"]
    print(f"p3 acceptance suite: exit={gate['exit_code']} ready={gate['ready']} "
          f"{gate['summary']}", file=sys.stderr)
    return EXIT_READY if gate["exit_code"] == EXIT_READY else EXIT_NOT_READY


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description=__doc__)
    parser.add_argument("--run", action="append", required=True,
                        metavar="ROLE=DIR[@COMPARE_DIR]",
                        help="one declared run with an explicit role "
                             "(repeatable)")
    parser.add_argument("--json-out", type=Path,
                        help="write the suite document here as well as stdout")
    parser.add_argument("--markdown-out", type=Path,
                        help="write the rendered evidence-boundary report here")
    parser.add_argument("--reports-dir", type=Path,
                        help="write each run's own p3_acceptance_report.v1 "
                             "document here (one file per role)")
    parser.add_argument("--engine-hash", action="append",
                        metavar="MODULE=SHA256",
                        help="declare the sha256 a producer module must have "
                             "(repeatable); a mismatch forces exit 2")
    last_spec = None
    try:
        args = parser.parse_args(argv)
        if args.run:
            last_spec = args.run[-1]
        return _run(args)
    except (ValueError, OSError) as exc:
        print(_dump({"schema_version": ERROR_SCHEMA_VERSION,
                     "command": "suite", "run": last_spec,
                     "error_type": type(exc).__name__, "error": str(exc)}))
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
