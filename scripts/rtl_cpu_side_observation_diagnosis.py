#!/usr/bin/env python3
"""Why the observed CPU-side branch points never light, from saved artifacts only.

The P4 instrumented-branch window established that a saved SoC run can carry
*proven* internal RTL branch coverage, but that the CPU half of the observed
vector is zero in every instrumented run (best case 50/128 overall, 0/64 on
``u_cpu0``).  A report that only prints ``50/128`` cannot tell three very
different situations apart, because the shipped harness reads its counters *by
position in the observed list*:

``unelaborated-bound`` (a)
    the point's instance chain does not occur in the compiled Verilator model,
    so the RTL only *declares* the coverage wire while the generate branch that
    would drive it was elaborated away.  The wire is undriven, its counter is a
    structural zero, and no amount of search can move it.
``elaborated-unexercised`` (b)
    the instance is in the compiled model and the counter stayed at zero: a real
    search-quality statement.
``probe-unreadable`` (c)
    the point has no counter slot in the saved readback vector, so there is no
    probe to read even in principle.

This module answers that question per point, reading only

* ``<run>/report.json`` - ``client_result.coverage_maxima`` and
  ``client_result.artifact_provenance.branch_coverage_ports``;
* ``<run>/build/soc_coverage_plan.json`` - the production observation plan, whose
  ``observed`` list is positionally the branch-port list;
* ``<run>/build/instrumentation/instrumented/instrumentation.json`` - the
  instrumenter's own per-bit map (instance path, module, file, line, kind,
  subtype, signal);
* ``<run>/build/obj_dir/*___024root.h`` - the compiled model, which is the only
  artifact that states which instances Verilator actually elaborated.

Nothing is inferred from port behaviour and no coverage number is claimed here.
The elaboration probe is a *negative* test on purpose: a chain is reported
present only when the mangled instance path occurs in the model header, and when
the model is missing every point is reported ``elaboration-unknown`` rather than
assumed armed.  The probe primitives come from :mod:`myfuzz.elaboration_probe`,
which the production build uses too, so a run's build-time decision and this
read-only diagnosis can never drift apart.

The document also carries ``recorded_elaboration``: what the *build* recorded
about this run's own observation set (probe status, probed model digest, and
every point it refused to observe with its classification and reason).  A run
produced before the build probed for elaboration simply has no such record.

Usage::

    PYTHONPATH=src python3 scripts/rtl_cpu_side_observation_diagnosis.py \\
        --run runs/<cell>
    PYTHONPATH=src python3 scripts/rtl_cpu_side_observation_diagnosis.py \\
        --runs-root runs --out /tmp/cpu_side.json

Exit codes:

``0``
    the diagnosis ran and no observed point is bound to an unelaborated chain.
``3``
    the diagnosis ran and at least one observed point is bound to an
    unelaborated chain (the P4 CPU-side defect is reproduced).
``1``
    a requested run or the runs root could not be read.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Iterable, Mapping, Sequence

# The probe primitives are shared with the production build
# (``myfuzz.integration.soc_builder``), so the diagnosis of a saved run and the
# build-time decision cannot drift apart.  They are re-exported below: this
# module is the read-only consumer, and callers that imported
# ``verilated_scope_chain`` from here keep working.
from myfuzz.elaboration_probe import (  # noqa: F401
    ELABORATION_RULE,
    MAX_MODEL_BYTES,
    MODEL_GLOB,
    compiled_model_path,
    read_compiled_model,
    verilated_scope_chain,
)
#: The coverage attestation reader is shared with the report CLI so both read
#: the same two shipped provenance shapes (flat keys and nested ``coverage``).
from myfuzz.scenario.rtl_branch_coverage import (
    ArtifactUnavailable as ModuleAttestationUnavailable,
    coverage_attestation,
)


SCHEMA_VERSION = "rtl_cpu_side_observation_diagnosis.v1"

#: Three-way classification of one observed branch point.
CLASS_LIT = "elaborated-lit"
CLASS_UNEXERCISED = "elaborated-unexercised"
CLASS_UNELABORATED = "unelaborated-bound"
CLASS_UNREADABLE = "probe-unreadable"
CLASS_UNKNOWN = "elaboration-unknown"

CLASSES = (CLASS_LIT, CLASS_UNEXERCISED, CLASS_UNELABORATED, CLASS_UNREADABLE,
           CLASS_UNKNOWN)

#: Scopes the diagnosis always probes, whatever the observed vector contains.
#: They are the ibex/pulp cell's CPU branches: the core Verilator elaborates and
#: the two generate-disabled alternatives the production selector currently
#: spends the CPU quota on.  Recording all three is what separates "the CPU
#: subtree is missing" from "the CPU subtree is present but the wrong branch of
#: it was chosen".
REFERENCE_SCOPES = (
    ("cpu-active-core", "myfuzz_soc_top/u_cpu0/u_ibex_core"),
    ("cpu-lockstep-branch", "myfuzz_soc_top/u_cpu0/u_ibex_lockstep"),
    ("cpu-cheriot-trvk-branch", "myfuzz_soc_top/u_cpu0/i_ibex_trvk"),
)

MAX_POINTS = 1 << 16

EXIT_CLEAN = 0
EXIT_ERROR = 1
EXIT_UNELABORATED_PRESENT = 3


class ArtifactUnavailable(Exception):
    """The saved run does not carry an artifact this diagnosis needs."""


def compiled_model_text(run_dir: Path) -> tuple[Path | None, str | None]:
    """Read one saved run's compiled model header, or ``(path, None)``.

    The build directory is ``<run>/build``.  A run without a usable header is
    reported as unknown, never assumed armed.
    """
    model = read_compiled_model(Path(run_dir) / "build")
    return model.header, model.text


def classify_observed_points(points: Sequence[Mapping[str, object]],
                             maxima: Sequence[int] | None,
                             model_text: str | None) -> list[dict]:
    """Classify each observed branch point against the readback and the model.

    ``points`` entries carry ``position`` (index into the counter vector),
    ``bit`` (index into ``__vi_coverage``) and ``instance_id``; see
    :func:`diagnose_run` for the full row shape.
    """
    rows: list[dict] = []
    for point in points:
        row = dict(point)
        position = int(row["position"])
        chain = verilated_scope_chain(str(row.get("instance_id", "")))
        row["scope_chain"] = chain
        if maxima is None:
            row["max"] = None
            row["classification"] = CLASS_UNREADABLE
            row["reason"] = "counter-vector-unavailable"
            row["elaborated"] = None
            rows.append(row)
            continue
        if position < 0 or position >= len(maxima):
            row["max"] = None
            row["classification"] = CLASS_UNREADABLE
            row["reason"] = "no-counter-slot-for-observed-point"
            row["elaborated"] = None
            rows.append(row)
            continue
        value = int(maxima[position])
        row["max"] = value
        if model_text is None:
            row["elaborated"] = None
            row["classification"] = CLASS_UNKNOWN
            row["reason"] = "compiled-model-unavailable"
        elif not chain:
            row["elaborated"] = None
            row["classification"] = CLASS_UNKNOWN
            row["reason"] = "instance-path-has-no-subtree"
        elif chain in model_text:
            row["elaborated"] = True
            row["reason"] = "instance-scope-present-in-compiled-model"
            row["classification"] = CLASS_LIT if value > 0 else CLASS_UNEXERCISED
        else:
            row["elaborated"] = False
            row["reason"] = "instance-scope-absent-from-compiled-model"
            row["classification"] = CLASS_UNELABORATED
            # A lit counter on an absent chain would mean the probe itself is
            # wrong; surface it instead of hiding it.
            row["contradiction"] = value > 0
        rows.append(row)
    return rows


def _counts(rows: Sequence[Mapping[str, object]]) -> dict:
    counts: dict[str, object] = {name: 0 for name in CLASSES}
    counts["points"] = len(rows)
    counts["contradictions"] = 0
    by_category: dict[str, dict] = {}
    for row in rows:
        category = str(row.get("category", "unknown"))
        bucket = by_category.setdefault(
            category, {name: 0 for name in CLASSES} | {"points": 0})
        bucket["points"] += 1
        bucket[str(row["classification"])] += 1
        counts[str(row["classification"])] += 1
        if row.get("contradiction"):
            counts["contradictions"] += 1
    counts["by_category"] = dict(sorted(by_category.items()))
    return counts


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ArtifactUnavailable(f"unreadable: {path}") from error
    except json.JSONDecodeError as error:
        raise ArtifactUnavailable(f"invalid JSON: {path}") from error


def _observed_points(run_dir: Path) -> list[dict]:
    report = _load_json(run_dir / "report.json")
    if not isinstance(report, dict):
        raise ArtifactUnavailable(f"not an object: {run_dir / 'report.json'}")
    client = report.get("client_result")
    if not isinstance(client, dict):
        raise ArtifactUnavailable("report.json has no client_result")
    provenance = client.get("artifact_provenance")
    if not isinstance(provenance, dict):
        raise ArtifactUnavailable("client_result has no artifact_provenance")
    try:
        _instrumentation, _coverage_ports, ports, _shape = coverage_attestation(
            provenance, run_dir)
    except ModuleAttestationUnavailable as error:
        raise ArtifactUnavailable(str(error)) from error
    if not ports:
        raise ArtifactUnavailable("no branch_coverage_ports in the attestation")
    if len(ports) > MAX_POINTS:
        raise ArtifactUnavailable(f"branch_coverage_ports exceeds {MAX_POINTS}")

    plan = _load_json(run_dir / "build" / "soc_coverage_plan.json")
    observed = plan.get("observed") if isinstance(plan, dict) else None
    if not isinstance(observed, list) or len(observed) != len(ports):
        raise ArtifactUnavailable(
            "build/soc_coverage_plan.json has no observed list matching the "
            "declared branch ports")
    # The harness indexes counters by position, so the two lists must agree
    # element-wise; a mismatch would make every row below meaningless.
    for index, (port, entry) in enumerate(zip(ports, observed)):
        if not isinstance(port, list) or len(port) != 2 or port[1] != entry.get(
                "bit"):
            raise ArtifactUnavailable(
                f"observed plan disagrees with branch port at position {index}")

    manifest = _load_json(run_dir / "build" / "instrumentation" / "instrumented"
                          / "instrumentation.json")
    bits = manifest.get("coverage_bits") if isinstance(manifest, dict) else None
    if not isinstance(bits, list):
        raise ArtifactUnavailable("instrumentation.json has no coverage_bits")
    by_bit = {entry.get("bit"): entry for entry in bits
              if isinstance(entry, Mapping)}

    points: list[dict] = []
    for position, entry in enumerate(observed):
        bit = entry.get("bit")
        source = by_bit.get(bit)
        if not isinstance(source, Mapping):
            raise ArtifactUnavailable(f"no manifest entry for coverage bit {bit}")
        points.append({
            "position": position,
            "bit": bit,
            "category": str(entry.get("category", "")),
            "instance_id": str(entry.get("instance_id", "")),
            "module": str(entry.get("module", "")),
            "file": str(source.get("file", "")),
            "line": source.get("line"),
            "kind": str(source.get("kind", "")),
            "subtype": str(source.get("subtype", "")),
            "signal": str(source.get("signal", "")),
        })
    recorded = plan.get("elaboration") if isinstance(plan, Mapping) else None
    return points, client.get("coverage_maxima"), (
        dict(recorded) if isinstance(recorded, Mapping) else None)


def _unelaborated_instances(rows: Iterable[Mapping[str, object]]) -> dict[str, int]:
    tally: dict[str, int] = {}
    for row in rows:
        if row.get("classification") != CLASS_UNELABORATED:
            continue
        instance = str(row.get("instance_id", ""))
        tally[instance] = tally.get(instance, 0) + 1
    return dict(sorted(tally.items(), key=lambda item: (-item[1], item[0])))


def _reference_scopes(model_text: str | None) -> list[dict]:
    rows = []
    for name, instance in REFERENCE_SCOPES:
        chain = verilated_scope_chain(instance)
        rows.append({
            "name": name,
            "instance": instance,
            "scope_chain": chain,
            "present": None if model_text is None else chain in model_text,
        })
    return rows


def diagnose_run(run_dir: Path) -> dict:
    """Classify every observed branch point of one saved run."""
    points, maxima, recorded = _observed_points(run_dir)
    model = read_compiled_model(run_dir / "build")
    rows = classify_observed_points(points, maxima, model.text)
    document = {
        "schema_version": SCHEMA_VERSION,
        "run": run_dir.as_posix(),
        "elaboration_rule": dict(ELABORATION_RULE),
        "counts": _counts(rows),
        "unelaborated_instances": _unelaborated_instances(rows),
        "reference_scopes": _reference_scopes(model.text),
        "compiled_model": model.document(),
        # What the *build* recorded about this run's own observation set: the
        # probe status, the model digest it probed, and every point it refused
        # to observe with its classification and reason.  A run produced before
        # the build probed for elaboration simply has no such record.
        "recorded_elaboration": recorded,
        "counter_vector_length": None if maxima is None else len(maxima),
        "points": rows,
    }
    return document


def summarise(document: Mapping[str, object]) -> str:
    counts = document["counts"]
    by_category = counts["by_category"]
    cpu = by_category.get("cpu", {name: 0 for name in CLASSES} | {"points": 0})
    ip = by_category.get("ip", {name: 0 for name in CLASSES} | {"points": 0})
    model = document["compiled_model"]
    return (f"diagnosed  {document['run']}  "
            f"points={counts['points']} "
            f"cpu={cpu[CLASS_LIT]}/{cpu['points']} lit "
            f"ip={ip[CLASS_LIT]}/{ip['points']} lit "
            f"{CLASS_UNELABORATED}={counts[CLASS_UNELABORATED]} "
            f"{CLASS_UNEXERCISED}={counts[CLASS_UNEXERCISED]} "
            f"{CLASS_UNREADABLE}={counts[CLASS_UNREADABLE]} "
            f"{CLASS_UNKNOWN}={counts[CLASS_UNKNOWN]} "
            f"contradictions={counts['contradictions']} "
            f"model={'yes' if model['present'] else 'no'}")


def _candidate_runs(runs_root: Path) -> list[Path]:
    if not runs_root.is_dir():
        raise ArtifactUnavailable(f"runs root is not a directory: {runs_root}")
    return sorted(path.parent for path in runs_root.glob("*/report.json"))


def configure_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--run", type=Path, default=None,
                        help="one saved run directory holding report.json")
    parser.add_argument("--runs-root", type=Path, default=None,
                        help="scan every saved run below this directory")
    parser.add_argument("--json", action="store_true",
                        help="print the full document instead of a summary line")
    parser.add_argument("--out", type=Path, default=None,
                        help="write the JSON document(s) here")
    parser.add_argument("--quiet", action="store_true",
                        help="suppress the summary lines")
    parser.add_argument("--require-model", action="store_true",
                        help="treat a run without a compiled model as an error")


def _emit(documents: list[dict], args) -> int:
    if args.out is not None:
        payload = documents[0] if args.run is not None else documents
        args.out.write_text(json.dumps(payload, indent=1, sort_keys=True) + "\n",
                            encoding="utf-8")
    if args.json:
        payload = documents[0] if args.run is not None else documents
        sys.stdout.write(json.dumps(payload, indent=1, sort_keys=True) + "\n")
    elif not args.quiet:
        for document in documents:
            print(summarise(document))
    if args.require_model and any(not document["compiled_model"]["present"]
                                  for document in documents):
        print("a scanned run has no compiled model header", file=sys.stderr)
        return EXIT_ERROR
    if any(document["counts"][CLASS_UNELABORATED] for document in documents):
        return EXIT_UNELABORATED_PRESENT
    return EXIT_CLEAN


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    configure_parser(parser)
    args = parser.parse_args(argv)
    if (args.run is None) == (args.runs_root is None):
        parser.error("exactly one of --run and --runs-root is required")

    if args.run is not None:
        try:
            document = diagnose_run(args.run)
        except ArtifactUnavailable as error:
            print(f"{args.run}: {error}", file=sys.stderr)
            return EXIT_ERROR
        return _emit([document], args)

    try:
        candidates = _candidate_runs(args.runs_root)
    except ArtifactUnavailable as error:
        print(str(error), file=sys.stderr)
        return EXIT_ERROR
    documents = []
    for run_dir in candidates:
        try:
            documents.append(diagnose_run(run_dir))
        except ArtifactUnavailable as error:
            if not args.quiet:
                print(f"skipped   {run_dir.as_posix()}  {error}", file=sys.stderr)
    if not documents:
        print("no saved run carries an observed branch vector", file=sys.stderr)
        return EXIT_ERROR
    if not args.quiet and not args.json:
        totals = {name: 0 for name in CLASSES}
        points = 0
        for document in documents:
            counts = document["counts"]
            points += counts["points"]
            for name in CLASSES:
                totals[name] += counts[name]
        print(f"scanned={len(documents)} points={points} "
              + " ".join(f"{name}={totals[name]}" for name in CLASSES))
    return _emit(documents, args)


if __name__ == "__main__":
    raise SystemExit(main())
