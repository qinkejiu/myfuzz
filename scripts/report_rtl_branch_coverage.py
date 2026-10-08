#!/usr/bin/env python3
"""Recompute internal RTL branch coverage from saved instrumented artifacts.

Read-only: it loads a saved ``report.json`` plus the instrumented source tree
that run actually compiled, re-derives the instrumentation identity with the
frozen producer, and reports how many instrumented branch points the real run
lit - separately from the port semantic hits observed in the same run.

Nothing here is inferred from port behaviour. A run only yields branch coverage
when :class:`myfuzz.scenario.rtl_branch_coverage.RtlBranchCoverage` verifies the
instrumenter version and source digest, the instrumented RTL file digests, the
aggregate instrumented-output digest, the exposed coverage-port list and width,
and the manifest's branch-point kinds. Otherwise the run is reported as
rejected, with the reason, and never as "port semantics matched".

Per-point **first-seen** evidence is read from the ledger the run itself wrote
(``build/coverage_first_seen.json``, declared by
:func:`myfuzz.integration.soc_builder.coverage_first_seen_evidence`): each entry
is the RTL test whose per-test counter readback first showed that point
non-zero, joined to the run's own plan by identity. A run that declares no such
ledger - every artifact built before this existed - keeps reporting
``first_seen.available=false`` with a reason, never a fabricated count.

Usage::

    PYTHONPATH=src python3 scripts/report_rtl_branch_coverage.py
    PYTHONPATH=src python3 scripts/report_rtl_branch_coverage.py --run runs/<cell>
    PYTHONPATH=src python3 scripts/report_rtl_branch_coverage.py --runs-root runs --json

Exit codes:

``0``
    at least one scanned run carries verified internal branch coverage.
``2``
    no scanned run carries instrumented branch evidence (the branch number is
    genuinely unavailable, not zero).
``1``
    a requested run or the workspace root could not be read, or a requested
    ``--run`` failed verification.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from myfuzz.scenario.rtl_branch_coverage import (
    ENCODING_COUNTER,
    RtlBranchCoverage,
    VERIFIED,
    coverage_attestation,
    coverage_kind,
    digest_of,
    executable_sha256,
)
from myfuzz.integration.soc_coverage import MAX_FIRST_SEEN_LEDGER_BYTES


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NO_INSTRUMENTED_EVIDENCE = 2

DEFAULT_RUNS_ROOT = "runs"
#: Every coverage kind the campaign emits for source-instrumented RTL branch
#: feedback shares this prefix; the suffix names the extra non-branch port
#: classes the run also exports (checker bits, RVFI opcode bins). Matching the
#: prefix structurally avoids a brittle list as the campaign adds classes.
INSTRUMENTED_COVERAGE_KIND_PREFIX = "source-instrumented-rtl-branch"


class ArtifactUnavailable(Exception):
    """The saved run does not carry the artifact this report needs."""


def configure_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--run", type=Path, default=None,
                        help="one saved run directory holding report.json")
    parser.add_argument("--runs-root", type=Path, default=Path(DEFAULT_RUNS_ROOT),
                        help="directory of saved runs to scan when --run is absent")
    parser.add_argument("--json", action="store_true",
                        help="print the full verification document instead of a summary")
    parser.add_argument("--out", type=Path, default=None,
                        help="write the JSON document(s) here")
    parser.add_argument("--quiet", action="store_true",
                        help="suppress the per-run summary lines")


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text())
    except OSError as error:
        raise ArtifactUnavailable(f"unreadable: {path}") from error
    except json.JSONDecodeError as error:
        raise ArtifactUnavailable(f"invalid JSON: {path}") from error


def _harness_top(provenance: dict) -> str:
    """The harness top is under ``sources`` in newer runs and ``source_closure``
    in older ones; either way it is the run's own declaration."""
    for key in ("sources", "source_closure"):
        block = provenance.get(key)
        if isinstance(block, dict) and block.get("harness_top"):
            return str(block["harness_top"])
    return ""


def _first_seen_source(run_dir: Path, attestation: object, coverage_ports: list,
                       maxima: list) -> tuple[list | None, dict]:
    """Join this run's per-point first-seen ledger to the run's own plan.

    The ledger is written by the readback that produced the counters
    (:class:`myfuzz.integration.rfuzz_simulator.CoverageFirstSeenLedger`): each
    entry names the RTL test whose counter readback first showed the point
    non-zero.  It is *not* a timestamp invented here, and it is never
    reconstructed from post-run survivors.

    The join is by identity, not by position: the ledger's ``points`` list must
    equal the plan's exposed ``(port, bit)`` list element for element, and the
    entries must cover every point this run's counters actually lit.  Anything
    else - no declaration, a missing or unreadable file, another schema, a
    different point list, a truncated ledger, an omitted lit point - is
    reported as **unavailable with the precise reason** instead of being
    guessed.  A well-formed list is handed to the shipped checker unchanged, so
    its own fail-closed rules (length, entry shape, a sighting claimed for a
    dark point) still decide the verdict.

    Returns ``(entries_or_None, source_document)``.
    """
    source = {
        "evidence": None,
        "declared": None,
        "ledger": None,
        "available": False,
        "reason": "the artifact declares no per-point first-seen ledger",
        "points": 0,
        "entries": 0,
    }
    declaration = (attestation.get("first_seen")
                   if isinstance(attestation, dict) else None)
    if not isinstance(declaration, dict):
        return None, source
    source["declared"] = dict(declaration)
    source["evidence"] = declaration.get("evidence")
    name = declaration.get("ledger")
    if not isinstance(name, str) or not name or Path(name).name != name:
        source["reason"] = ("the first-seen declaration names no ledger file: "
                            f"{name!r}")
        return None, source
    path = Path(run_dir) / "build" / name
    source["ledger"] = path.as_posix()
    if not path.is_file():
        source["reason"] = f"the declared first-seen ledger is missing: {path}"
        return None, source
    try:
        if path.stat().st_size > MAX_FIRST_SEEN_LEDGER_BYTES:
            source["reason"] = (
                f"the first-seen ledger exceeds the reader's bound of "
                f"{MAX_FIRST_SEEN_LEDGER_BYTES} bytes: {path}")
            return None, source
    except OSError as error:
        source["reason"] = (f"the declared first-seen ledger is unreadable: "
                            f"{path} ({type(error).__name__})")
        return None, source
    try:
        ledger = _load_json(path)
    except ArtifactUnavailable as error:
        source["reason"] = (f"the declared first-seen ledger is unreadable: "
                            f"{error}")
        return None, source
    if not isinstance(ledger, dict):
        source["reason"] = f"the first-seen ledger is not an object: {path}"
        return None, source
    if ledger.get("schema_version") != declaration.get("schema_version"):
        source["reason"] = ("unsupported first-seen ledger schema: "
                            f"{ledger.get('schema_version')!r}")
        return None, source
    if ledger.get("counter_count") != len(coverage_ports):
        source["reason"] = (
            f"the first-seen ledger covers {ledger.get('counter_count')!r} "
            f"counters while the run exposes {len(coverage_ports)}")
        return None, source
    points = ledger.get("points")
    normalised = ([list(item) if isinstance(item, list) else item
                   for item in points] if isinstance(points, list) else None)
    if normalised != [[name_, bit] for name_, bit in coverage_ports]:
        source["reason"] = ("the first-seen ledger names different points than "
                            "the run's plan, so its entries cannot be joined")
        return None, source
    if ledger.get("truncated") is True:
        source["reason"] = "the first-seen ledger declares itself truncated"
        return None, source
    entries = ledger.get("entries")
    if not isinstance(entries, list):
        source["reason"] = "the first-seen ledger carries no entry list"
        return None, source
    for index, entry in enumerate(entries):
        if entry is None:
            continue
        if (index >= len(normalised) or not isinstance(entry, dict)
                or entry.get("point") != list(normalised[index])):
            source["reason"] = (
                f"the first-seen ledger entry {index} does not name its own "
                f"point, so its sightings cannot be attributed")
            return None, source
    omitted = [index for index, value in enumerate(maxima)
               if value and (index >= len(entries) or entries[index] is None)]
    if omitted:
        source["reason"] = (
            f"the first-seen ledger omits {len(omitted)} point(s) the run's "
            f"counters lit")
        return None, source
    source.update(available=True, reason=None,
                  points=sum(1 for item in entries if item is not None),
                  entries=len(entries))
    return entries, source


def _run_document(run_dir: Path) -> dict:
    """Load one saved run and return its verification document."""
    report = _load_json(run_dir / "report.json")
    if not isinstance(report, dict):
        raise ArtifactUnavailable("report.json is not an object")
    client = report.get("client_result")
    if not isinstance(client, dict):
        raise ArtifactUnavailable("report.json has no client_result")
    provenance = client.get("artifact_provenance")
    if not isinstance(provenance, dict):
        raise ArtifactUnavailable("client_result has no artifact_provenance")
    maxima = client.get("coverage_maxima")
    if not isinstance(maxima, list):
        raise ArtifactUnavailable("client_result carries no coverage_maxima")
    instrumentation, coverage_ports, branch_ports, shape = coverage_attestation(provenance, run_dir)

    root = Path(str(instrumentation.get("instrumented_root", "")))
    flist = instrumentation.get("instrumented_flist")
    manifest_path = root / "instrumentation.json"
    manifest = _load_json(manifest_path) if manifest_path.is_file() else None
    if not isinstance(manifest, dict):
        raise ArtifactUnavailable(f"instrumented manifest missing: {manifest_path}")

    identity = {
        "run_id": run_dir.name,
        "harness_top": _harness_top(provenance),
        "build_hash": str(provenance.get("build_hash", "")),
        "executable_sha256": executable_sha256(provenance),
    }
    attribution = {
        "instrumenter": instrumentation.get("instrumenter"),
        "instrumented_root": str(root),
        "instrumented_flist": str(flist),
        "instrumented_output_sha256": instrumentation.get("instrumented_output_sha256"),
        "coverage_port": manifest.get("coverage_port"),
        "coverage_vector_width": manifest.get("coverage_vector_width"),
        "coverage_ports": coverage_ports,
        "branch_coverage_ports": branch_ports,
        "encoding": ENCODING_COUNTER,
        "counter_max": 255,
        "harness": dict(identity),
        "instrumentation_manifest_sha256": digest_of(manifest_path.read_bytes()),
    }
    observation = {"coverage_port": manifest.get("coverage_port"),
                   "coverage_ports": coverage_ports,
                   "counters": maxima}
    entries, first_seen_source = _first_seen_source(
        run_dir, instrumentation, coverage_ports, maxima)
    if entries is not None:
        observation["first_seen"] = entries
    document = RtlBranchCoverage(
        attribution=attribution,
        harness_identity=identity,
        observation=observation,
        instrumented_root=root,
        instrumentation_manifest=manifest,
        manifest_sha256=attribution["instrumentation_manifest_sha256"],
        # The saved provenance attests the aggregate tree digest; the per-file
        # digest list is re-derived from that same tree.
        derive_rtl_file_digests=True,
    ).evaluate()
    document["run"] = run_dir.as_posix()
    document["first_seen_source"] = first_seen_source
    document["external_binding"] = _external_binding(run_dir, root, provenance,
                                                     document)
    return document


def _external_binding(run_dir: Path, root: Path, provenance: dict,
                      document: dict) -> dict:
    """Checks that need the run directory itself, not just its self-description.

    The saved attestation is the run's own claim. These checks tie that claim to
    the directory the data was found in, so provenance copied from another run
    cannot pass: the attested tree must live inside this run, the saved build
    identity must be a run build, and the declared coverage kind must assert
    instrumented RTL branch feedback.
    """
    findings: list[str] = []
    try:
        root.resolve().relative_to(run_dir.resolve())
    except ValueError:
        findings.append("instrumented-root-outside-run")
    if not (root / "instrumented_sources.f").is_file():
        findings.append("instrumented-flist-missing")
    if not provenance.get("build_hash"):
        findings.append("build-identity-missing")
    if not coverage_kind(provenance).startswith(
            INSTRUMENTED_COVERAGE_KIND_PREFIX):
        findings.append("coverage-kind-not-instrumented-branch")
    if document.get("status") != VERIFIED:
        findings.append("verification-rejected")
    return {"run": run_dir.as_posix(),
            "instrumented_root_inside_run": "instrumented-root-outside-run"
            not in findings,
            "coverage_kind": coverage_kind(provenance),
            "findings": findings,
            "passed": not findings}


def _candidate_runs(runs_root: Path) -> list[Path]:
    if not runs_root.is_dir():
        raise ArtifactUnavailable(f"runs root is not a directory: {runs_root}")
    rows = []
    for path in sorted(runs_root.glob("*/report.json")):
        try:
            report = _load_json(path)
        except ArtifactUnavailable:
            continue
        client = report.get("client_result") if isinstance(report, dict) else None
        if not isinstance(client, dict):
            continue
        provenance = client.get("artifact_provenance")
        if not isinstance(provenance, dict):
            continue
        ports = provenance.get("branch_coverage_ports")
        if isinstance(ports, list) and ports and isinstance(provenance.get(
                "coverage_instrumentation"), dict):
            rows.append(path.parent)
    return rows


def _accepted(document: dict) -> bool:
    """A run counts only when the vector verified *and* the attestation binds to
    the directory it was found in."""
    binding = document.get("external_binding")
    return (document.get("status") == VERIFIED
            and isinstance(binding, dict) and bool(binding.get("passed")))


def _summary_line(document: dict) -> str:
    identity = document["instrumentation"]
    if document["status"] != VERIFIED:
        reasons = ",".join(item["reason"] for item in document["rejections"][:3])
        return f"REJECTED  {document['run']}  reasons={reasons}"
    observed = document["observed_branches"]
    separation = document["separation"]
    first_seen = observed["first_seen"]
    return (f"verified  {document['run']}  "
            f"branch_points={observed['observed_points']}/{observed['total_points']} "
            f"ratio={observed['ratio']:.4f} "
            f"first_seen={'yes' if first_seen['available'] else 'no'} "
            f"branch={separation['branch_coverage']} "
            f"semantic_targets={separation['port_semantic_hits']} "
            f"non_branch_lit_ports={separation['non_branch_lit_ports']} "
            f"rtl_files={identity['rtl_file_count']} "
            f"tree={identity['instrumented_output_verified']}")


def _first_seen_line(document: dict) -> str:
    """The per-point first-seen verdict, with the reason when it is unavailable.

    ``first_seen=no`` must always come with a reason: an artifact that carries
    no per-point evidence says exactly that, and never "no point was ever seen".
    """
    observed = document.get("observed_branches") or {}
    verdict = observed.get("first_seen") or {}
    source = document.get("first_seen_source") or {}
    if verdict.get("available"):
        earliest = verdict.get("earliest") or {}
        return ("  first_seen: yes points={} earliest=bit:{}@event:{} time={} "
                "ledger={}".format(verdict.get("points"), earliest.get("bit"),
                                   earliest.get("event"), earliest.get("time"),
                                   source.get("ledger")))
    return "  first_seen: no reason={} evidence={}".format(
        verdict.get("reason") or "unavailable", source.get("reason"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    configure_parser(parser)
    args = parser.parse_args(argv)

    if args.run is not None:
        try:
            document = _run_document(args.run)
        except ArtifactUnavailable as error:
            print(f"{args.run}: {error}", file=sys.stderr)
            return EXIT_ERROR
        payload = json.dumps(document, indent=1, sort_keys=True) + "\n"
        if args.out is not None:
            args.out.write_text(payload)
        if args.json:
            sys.stdout.write(payload)
        elif not args.quiet:
            print(_summary_line(document))
            print(_first_seen_line(document))
            binding = document["external_binding"]
            print(f"  external binding passed={binding['passed']} "
                  f"findings={binding['findings']}")
        return EXIT_OK if _accepted(document) else EXIT_ERROR

    try:
        candidates = _candidate_runs(args.runs_root)
    except ArtifactUnavailable as error:
        print(str(error), file=sys.stderr)
        return EXIT_ERROR
    documents = []
    for run_dir in candidates:
        try:
            documents.append(_run_document(run_dir))
        except ArtifactUnavailable as error:
            if not args.quiet:
                print(f"skipped   {run_dir.as_posix()}  {error}", file=sys.stderr)
    if args.out is not None:
        args.out.write_text(json.dumps(documents, indent=1, sort_keys=True) + "\n")
    if args.json:
        sys.stdout.write(json.dumps(documents, indent=1, sort_keys=True) + "\n")
    elif not args.quiet:
        for document in documents:
            print(_summary_line(document))
            print(_first_seen_line(document))
        verified = [item for item in documents if _accepted(item)]
        print(f"scanned={len(candidates)} verified={len(verified)} "
              f"rejected={len(documents) - len(verified)}")
    if not documents:
        print("no run in the workspace carries instrumented branch evidence",
              file=sys.stderr)
        return EXIT_NO_INSTRUMENTED_EVIDENCE
    return EXIT_OK if any(_accepted(item) for item in documents) else EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
