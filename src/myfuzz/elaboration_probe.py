"""Does the compiled Verilator model actually contain a planned observation point?

The P4 instrumented-branch window ended with 0/64 lit CPU branch points in every
instrumented run.  The cause is structural, not a search failure: the observation
plan spends the CPU quota on the lowest raw coverage bits of ``u_cpu0``, and the
instrumenter concatenates child vectors in source order with the *first* declared
child at the most significant end, so the lowest CPU bits belong to the last
declared children - the generate-disabled ``u_cpu0/u_ibex_lockstep`` and
``u_cpu0/i_ibex_trvk`` subtrees.  Those instances are not in the elaborated
design, their coverage wires have no driver, and their counters can never move.

The only artifact that states which instances the design actually contains is the
compiled model header ``build/obj_dir/*___024root.h``.  This module is the shared
probe over it:

* :func:`verilated_scope_chain` turns an instrumenter instance path into the
  member-name prefix Verilator emits;
* :func:`read_compiled_model` reads and digests the model header;
* :func:`classify_planned_points` classifies each planned point as
  ``elaborated``, ``unelaborated_scope`` or ``elaboration_unknown``;
* :func:`replan_observations` drops every point that is not proven elaborated,
  re-plans the same counter quota without those instances, and records each
  exclusion with its classification and reason.

It is deliberately an asymmetric, negative test: ``present`` proves the instance
was elaborated, while ``absent`` is used only to *withhold* a point (Verilator
can also inline a very small instance away).  That direction can lose an
observable point; it can never claim coverage for a wire nothing drives.

Two consumers share it, so neither can drift from the other:
:mod:`myfuzz.integration.soc_builder` (the production build, which must never
publish a counter slot the model cannot light) and
``scripts/rtl_cpu_side_observation_diagnosis.py`` (the read-only diagnosis of
saved runs, which must classify the same points the same way).

The re-plan needs :func:`myfuzz.integration.soc_coverage.coverage_observation_plan`,
which is imported lazily inside :func:`replan_observations` so the read-only
diagnosis path does not have to load the campaign stack to probe a model.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path


SCHEMA_VERSION = "soc_observation_elaboration.v1"

#: Verilator names the model header after the top module; the harness top is
#: ``myfuzz_live_tb`` in every build this project produces.
MODEL_GLOB = "*___024root.h"
#: A model header larger than this is reported unavailable rather than read
#: partially: a truncated read would make a present scope look absent, which is
#: the one error direction this probe must never make.
MAX_MODEL_BYTES = 64 * 1024 * 1024
#: Each re-plan round refutes at least one instance and the plan only shows the
#: current quota, so convergence takes one round per *layer* of refuted
#: instances.  The real ibex/pulp cell needs 16 rounds (Verilator emits a named
#: scope for the live CSR/counter instances while flattening smaller ones, so
#: the refuted set is discovered a layer at a time).  This bound is a safety
#: valve, not an expected limit: hitting it refuses the build.
MAX_REPLAN_ROUNDS = 64

#: One planned observation point, classified against the compiled model.
CLASS_ELABORATED = "elaborated"
CLASS_UNELABORATED_SCOPE = "unelaborated_scope"
CLASS_ELABORATION_UNKNOWN = "elaboration_unknown"
CLASSIFICATIONS = (CLASS_ELABORATED, CLASS_UNELABORATED_SCOPE,
                   CLASS_ELABORATION_UNKNOWN)
#: Classifications that forbid reporting the point as observed.
CLASSES_THAT_BLOCK_OBSERVATION = (CLASS_UNELABORATED_SCOPE,
                                  CLASS_ELABORATION_UNKNOWN)

REASON_SCOPE_PRESENT = "instance-scope-present-in-compiled-model"
REASON_SCOPE_ABSENT = "instance-scope-absent-from-compiled-model"
REASON_NO_SUBTREE = "instance-path-has-no-subtree"
REASON_MODEL_MISSING = "compiled-model-header-missing"
REASON_MODEL_UNREADABLE = "compiled-model-header-unreadable"
REASON_MODEL_TOO_LARGE = "compiled-model-header-exceeds-probe-bound"
REASON_MODEL_EMPTY = "compiled-model-header-empty"

#: Recorded in every document so a reader never has to guess which direction of
#: the probe is sound.
ELABORATION_RULE = {
    "probe": "the mangled instance scope occurs in build/obj_dir/*___024root.h, "
             "the compiled Verilator model the build produced",
    "present_means": "the instance was elaborated and its coverage wire is part "
                     "of the compiled design",
    "absent_means": "the instance scope was not emitted, so the point is bound "
                    "to an undriven declaration; Verilator can also omit members "
                    "for inlined instances, so absence is used as a conservative "
                    "filter and is never read as coverage",
    "unknown_means": "nothing could be probed for that point - no usable model "
                     "header, or an instance path with no child scope - so it is "
                     "not observed",
}


class ElaborationProbeError(Exception):
    """The probe could not decide, and the caller must not guess."""


class ElaborationUnavailable(ElaborationProbeError):
    """No usable compiled model: observation cannot be claimed (fail closed)."""


def mangle_member(name: str) -> str:
    """Verilator escapes a leading underscore so the name cannot be reserved.

    ``__vi_coverage`` is emitted as ``_____05Fvi_coverage``-style members while
    interior underscores survive untouched (``u_ibex_core`` stays
    ``u_ibex_core``), so only the leading character needs rewriting.
    """
    return "__05F" + name[1:] if name.startswith("_") else name


def verilated_scope_chain(instance_path: str) -> str:
    """The member-name prefix Verilator emits for an instrumented instance.

    The instrumenter's instance path starts with the rendered SoC top module,
    which the harness instantiates as ``dut``; only the segments below it are
    mangled.  A trailing ``__DOT__`` is required so that a chain is only
    reported present when the *scope* exists - matching the bare text would also
    match an undriven child wire name (``...__vi_cov_child_i_ibex_trvk_4``) and
    silently turn "not elaborated" into "elaborated but not hit".
    """
    segments = [segment for segment in str(instance_path).split("/") if segment]
    below = segments[1:]
    if not below:
        return ""
    return "__DOT__".join(mangle_member(segment) for segment in below) + "__DOT__"


@dataclass(frozen=True)
class CompiledModel:
    """The compiled model header, or why it could not be used."""

    header: Path | None
    present: bool
    reason: str
    sha256: str = ""
    size: int | None = None
    text: str | None = None

    @classmethod
    def of_text(cls, text: str, header: Path | None = None) -> "CompiledModel":
        """An in-memory model document (tests, and callers that already read it)."""
        payload = text.encode("utf-8", errors="replace")
        return cls(header=header, present=True, reason=REASON_SCOPE_PRESENT,
                   sha256=hashlib.sha256(payload).hexdigest(), size=len(payload),
                   text=text)

    @classmethod
    def unavailable(cls, reason: str,
                    header: Path | None = None) -> "CompiledModel":
        return cls(header=header, present=False, reason=reason)

    def document(self) -> dict:
        """The serializable subset; ``text`` is deliberately never published."""
        return {
            "header": None if self.header is None else self.header.as_posix(),
            "present": bool(self.present),
            "reason": str(self.reason),
            "sha256": str(self.sha256),
            "bytes": self.size,
        }


def compiled_model_path(build_dir: Path) -> Path | None:
    """The model header inside one build directory, if there is exactly a choice."""
    obj_dir = Path(build_dir) / "obj_dir"
    if not obj_dir.is_dir():
        return None
    headers = sorted(obj_dir.glob(MODEL_GLOB))
    return headers[0] if headers else None


def read_compiled_model(build_dir: Path) -> CompiledModel:
    """Read the compiled model header of one build directory.

    Every failure is named: a missing, oversized, empty or unreadable header
    yields ``present=False`` with a reason, never a partial read.
    """
    path = compiled_model_path(build_dir)
    if path is None:
        return CompiledModel.unavailable(REASON_MODEL_MISSING)
    try:
        if not path.is_file():
            return CompiledModel.unavailable(REASON_MODEL_MISSING, path)
        size = path.stat().st_size
        if size > MAX_MODEL_BYTES:
            return CompiledModel.unavailable(REASON_MODEL_TOO_LARGE, path)
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return CompiledModel.unavailable(REASON_MODEL_UNREADABLE, path)
    if not text.strip():
        return CompiledModel.unavailable(REASON_MODEL_EMPTY, path)
    return CompiledModel(header=path, present=True, reason=REASON_SCOPE_PRESENT,
                         sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                         size=size, text=text)


def classify_planned_points(points: Iterable[Mapping[str, object]],
                            model: CompiledModel) -> list[dict]:
    """Classify each planned observation point against the compiled model.

    ``points`` entries carry at least ``bit`` and ``instance_id``; the returned
    rows copy them and add ``scope_chain``, ``classification`` and ``reason``.
    An unusable model classifies every point ``elaboration_unknown``; the caller
    that cannot proceed on that must ask :func:`replan_observations`, which
    refuses instead.
    """
    rows: list[dict] = []
    for point in points:
        row = dict(point)
        chain = verilated_scope_chain(str(row.get("instance_id", "")))
        row["scope_chain"] = chain
        if not model.present or model.text is None:
            row["classification"] = CLASS_ELABORATION_UNKNOWN
            row["reason"] = model.reason or REASON_MODEL_MISSING
        elif not chain:
            row["classification"] = CLASS_ELABORATION_UNKNOWN
            row["reason"] = REASON_NO_SUBTREE
        elif chain in model.text:
            row["classification"] = CLASS_ELABORATED
            row["reason"] = REASON_SCOPE_PRESENT
        else:
            row["classification"] = CLASS_UNELABORATED_SCOPE
            row["reason"] = REASON_SCOPE_ABSENT
        rows.append(row)
    return rows


def _candidate_bits_by_instance(bits: Sequence[Mapping[str, object]]) -> dict[str, int]:
    tally: dict[str, int] = {}
    for entry in bits:
        instance = str(entry.get("instance_path", ""))
        tally[instance] = tally.get(instance, 0) + 1
    return tally


def _exclusion_counts(rows: Sequence[Mapping[str, object]]) -> dict:
    counts = {CLASS_UNELABORATED_SCOPE: 0, CLASS_ELABORATION_UNKNOWN: 0}
    for row in rows:
        classification = str(row.get("classification"))
        if classification in counts:
            counts[classification] += 1
    return counts


def _elaboration_document(*, planned: Sequence[Mapping[str, object]],
                          final: Sequence[Mapping[str, object]],
                          excluded: Sequence[Mapping[str, object]],
                          excluded_instances: Mapping[str, Mapping[str, object]],
                          rounds: Sequence[Mapping[str, object]],
                          model: CompiledModel,
                          changed: bool,
                          total_bits: int,
                          eligible_bits: int) -> dict:
    dropped = _exclusion_counts(excluded)
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "replanned" if changed else "verified",
        "rule": dict(ELABORATION_RULE),
        # What the probe classified, exactly: the *planned* points, re-planned
        # until every reported point is proven elaborated.  The counts below are
        # therefore about planned slots and the candidate bits of the instances
        # the probe refuted - never about the whole instrumented universe.
        "classification_scope": "planned-observation-points-across-replan-rounds",
        "model": model.document(),
        "changed": bool(changed),
        "rounds": [dict(round_) for round_ in rounds],
        "counts": {
            "instrumented_branch_points": total_bits,
            "candidates_after_exclusion": eligible_bits,
            "excluded_candidate_bits": total_bits - eligible_bits,
            "planned_points": len(planned),
            "observed_points": len(final),
            "elaborated": len(final),
            # Planned observation slots the probe refused, by classification.
            "unelaborated_scope": dropped[CLASS_UNELABORATED_SCOPE],
            "elaboration_unknown": dropped[CLASS_ELABORATION_UNKNOWN],
            "refused_planned_points": len(excluded),
            "excluded_instances": len(excluded_instances),
        },
        "excluded": [dict(row) for row in excluded],
        "excluded_instances": {name: dict(entry)
                               for name, entry in sorted(excluded_instances.items())},
        "observations": [
            {"bit": row.get("bit"), "point_id": row.get("point_id"),
             "instance_id": row.get("instance_id"),
             "classification": row.get("classification"),
             "reason": row.get("reason"), "scope_chain": row.get("scope_chain")}
            for row in final],
    }


def replan_observations(*, plan: Mapping[str, object],
                        universe: Mapping[str, object],
                        bits: Sequence[Mapping[str, object]],
                        limit: int,
                        model: CompiledModel,
                        max_rounds: int = MAX_REPLAN_ROUNDS) -> dict:
    """Re-plan the observation set so no observed point is unproven.

    Returns ``{"changed", "plan", "elaboration"}``.  ``plan`` is a new document
    (the input mapping is never mutated); when nothing had to be dropped it keeps
    the caller's observed set and simply records the verified probe.

    The loop re-classifies against the *same* compiled model each round, because
    which counters the harness reads does not change what the design elaborates.
    That is what lets the caller rebuild the harness exactly once, after the plan
    has converged.

    Raises :class:`ElaborationUnavailable` when the model is unusable, when
    nothing eligible remains, or when the re-plan does not converge: a build that
    cannot prove its counters are armed must not publish them as coverage.
    """
    if not model.present or model.text is None:
        raise ElaborationUnavailable(
            model.reason or REASON_MODEL_MISSING)
    bit_list = list(bits)
    candidate_bits = _candidate_bits_by_instance(bit_list)
    excluded_instances: dict[str, dict] = {}
    excluded_rows: list[dict] = []
    rounds: list[dict] = []
    current = dict(plan)
    current["observed"] = [dict(row) for row in plan.get("observed", [])]
    planned = [dict(row) for row in current["observed"]]
    rows = classify_planned_points(current["observed"], model)
    changed = False
    for round_index in range(1, max_rounds + 1):
        round_instances: list[str] = []
        for row in rows:
            if row["classification"] == CLASS_ELABORATED:
                continue
            instance = str(row.get("instance_id", ""))
            if instance not in round_instances:
                round_instances.append(instance)
            if instance not in excluded_instances:
                excluded_instances[instance] = {
                    "instance_id": instance,
                    "classification": row["classification"],
                    "reason": row["reason"],
                    "scope_chain": row["scope_chain"],
                    "planned_points": 0,
                    "candidate_bits": int(candidate_bits.get(instance, 0)),
                }
            excluded_instances[instance]["planned_points"] += 1
            excluded_rows.append(dict(row))
        rounds.append({
            "round": round_index,
            "planned_points": len(rows),
            "unelaborated_scope": sum(
                1 for row in rows
                if row["classification"] == CLASS_UNELABORATED_SCOPE),
            "elaboration_unknown": sum(
                1 for row in rows
                if row["classification"] == CLASS_ELABORATION_UNKNOWN),
            "excluded_instances": round_instances,
        })
        if not round_instances:
            # Nothing was dropped in this pass: the observed set is proven.
            break
        eligible = [entry for entry in bit_list
                    if str(entry.get("instance_path", "")) not in excluded_instances]
        if not eligible:
            raise ElaborationUnavailable(
                "every instrumented branch point is bound to an unelaborated or "
                "unprobeable instance")
        # Lazy on purpose: the read-only diagnosis imports the probe primitives
        # without loading the campaign package.
        from myfuzz.integration.soc_coverage import coverage_observation_plan
        current = coverage_observation_plan(universe, eligible, limit)
        # The selector only sees the eligible candidates, so its own
        # ``unobserved_count`` would hide the dropped population; report the
        # whole instrumented universe instead of the filtered one.
        current["unobserved_count"] = len(bit_list) - len(current["observed"])
        current["eligible_candidate_count"] = len(eligible)
        current["excluded_candidate_count"] = len(bit_list) - len(eligible)
        current["plan_revision"] = int(plan.get("plan_revision", 1) or 1) + round_index
        current["replanned_after_elaboration_probe"] = True
        changed = True
        rows = classify_planned_points(current["observed"], model)
    else:
        raise ElaborationUnavailable(
            "observation re-plan did not converge within %d rounds" % max_rounds)
    elaboration = _elaboration_document(
        planned=planned, final=rows, excluded=excluded_rows,
        excluded_instances=excluded_instances, rounds=rounds, model=model,
        changed=changed, total_bits=len(bit_list),
        eligible_bits=len(bit_list) - sum(
            int(entry["candidate_bits"]) for entry in excluded_instances.values()))
    current["elaboration"] = elaboration
    return {"changed": changed, "plan": current, "elaboration": elaboration}


def unelaborated_rows(rows: Iterable[Mapping[str, object]]) -> list[dict]:
    """The rows that must never be reported as observed."""
    return [dict(row) for row in rows
            if row.get("classification") in CLASSES_THAT_BLOCK_OBSERVATION]


__all__ = [
    "CLASSIFICATIONS", "CLASSES_THAT_BLOCK_OBSERVATION", "CLASS_ELABORATED",
    "CLASS_ELABORATION_UNKNOWN", "CLASS_UNELABORATED_SCOPE", "CompiledModel",
    "ELABORATION_RULE", "ElaborationProbeError", "ElaborationUnavailable",
    "MAX_MODEL_BYTES", "MAX_REPLAN_ROUNDS", "MODEL_GLOB", "REASON_MODEL_EMPTY",
    "REASON_MODEL_MISSING", "REASON_MODEL_TOO_LARGE", "REASON_MODEL_UNREADABLE",
    "REASON_NO_SUBTREE", "REASON_SCOPE_ABSENT", "REASON_SCOPE_PRESENT",
    "SCHEMA_VERSION", "classify_planned_points", "compiled_model_path",
    "mangle_member", "read_compiled_model", "replan_observations",
    "unelaborated_rows", "verilated_scope_chain",
]
