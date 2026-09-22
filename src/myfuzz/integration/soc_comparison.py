"""Three-arm SoC campaign comparison with a strict identity boundary.

The comparison is deliberately a report builder, not a statistical claim.  It
accepts the reports produced by :func:`run_soc_campaign` (or equivalent JSON
documents), verifies that all arms exercised the same generated SoC/coverage
identity, and preserves missing measurements as ``None``.  A repaired arm is
never called better merely because its projection count is larger.

:func:`execute_soc_campaign_arms` additionally *executes* the three arms over
one build: the same SoC, source closure, coverage instrumentation, budget and
seed.  Only the input projection differs (identity, constrained policy, or
dependency repair), so a difference between the arms is a difference of
projection policy rather than of build.  Every arm runs the shared seeded corpus
through the real RTL simulator, persists the corpus it really executed, verifies
it by replay, and records its own projection, repair, rejection and anomaly
counters.  The comparison of the executed arms is then produced by
:func:`compare_soc_campaign_arms` from those reports.
"""
from __future__ import annotations

import json
import math
import random
import shutil
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path

from myfuzz.contracts import canonical_bytes, content_hash


COMPARISON_SCHEMA = "soc_campaign_comparison.v1"
ARM_NAMES = ("direct_input", "constrained_baseline", "dependency_repair")
#: The executed-arm report and corpus identities.
ARMS_EXECUTION_SCHEMA = "soc_campaign_arms_execution.v1"
ARM_REPORT_SCHEMA = "soc_campaign_arm_run.v1"
#: The shared seeded corpus defaults: the same corpus for every arm.
DEFAULT_CORPUS_ENTRIES = 12
DEFAULT_CORPUS_CYCLES = 4
#: Exact JSON characters per raw byte bound used by the corpus reader, mirroring
#: ``rfuzz_live`` so a saved entry can always be replayed by the same machinery.
CORPUS_ENTRY_SIZE_FACTOR = 5


COMPARISON_SCHEMA = "soc_campaign_comparison.v1"
ARM_NAMES = ("direct_input", "constrained_baseline", "dependency_repair")


class SocComparisonError(ValueError):
    """The three reports cannot be compared under one identity."""


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _hash_bytes(data: bytes) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(data).hexdigest()


def _document(value: object, label: str) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, (str, Path)):
        try:
            parsed = json.loads(Path(value).read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError) as error:
            raise SocComparisonError(f"{label}:report-unreadable") from error
        if isinstance(parsed, Mapping):
            return parsed
    raise SocComparisonError(f"{label}:report-mapping-required")


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(float(value)) or value < 0:
        return None
    return float(value)


def _integer(value: object) -> int | None:
    number = _number(value)
    if number is None or number != int(number):
        return None
    return int(number)


def _artifact(report: Mapping[str, object]) -> Mapping[str, object]:
    value = report.get("artifact")
    return value if isinstance(value, Mapping) else {}


def _positive_int(value: object) -> int | None:
    number = _integer(value)
    return number if number is not None and number > 0 else None


def _identity(report: Mapping[str, object]) -> dict[str, object]:
    artifact = _artifact(report)
    return {
        "config_id": report.get("config_id"),
        "cell_id": report.get("cell_id"),
        "composition_hash": artifact.get("composition_hash"),
        "layout_hash": artifact.get("layout_hash") or report.get("layout_hash"),
        "coverage_kind": artifact.get("coverage_kind"),
        "structure_audit_status": (
            artifact.get("structure_audit", {}).get("status")
            if isinstance(artifact.get("structure_audit"), Mapping) else None),
        "binary_sha256": (
            report.get("client_result", {}).get("binary_sha256")
            if isinstance(report.get("client_result"), Mapping) else None),
    }


def _transactions(report: Mapping[str, object]) -> dict[str, int | None]:
    value = report.get("source_target_transactions")
    if not isinstance(value, Mapping):
        return {"source": None, "target": None}
    result: dict[str, int | None] = {}
    for side in ("source", "target"):
        side_value = value.get(side)
        if not isinstance(side_value, Mapping):
            result[side] = None
            continue
        counts = [_integer(item) for item in side_value.values()]
        counts = [item for item in counts if item is not None]
        result[side] = sum(counts) if counts else None
    return result


def _metrics(report: Mapping[str, object]) -> dict[str, object]:
    execution = report.get("rtl_execution")
    execution = execution if isinstance(execution, Mapping) else {}
    corpus = report.get("corpus")
    corpus = corpus if isinstance(corpus, Mapping) else {}
    projection = report.get("input_projection")
    projection = projection if isinstance(projection, Mapping) else {}
    duration = _number(report.get("effective_fuzz_seconds", report.get("duration_seconds")))
    tests = _integer(execution.get("tests"))
    cycles = None
    totals = execution.get("execution_totals")
    if isinstance(totals, Mapping):
        cycle_values = [_integer(value) for key, value in totals.items()
                        if "cycle" in str(key).lower()]
        cycle_values = [value for value in cycle_values if value is not None]
        cycles = sum(cycle_values) if cycle_values else None
    return {
        "status": report.get("final_status", report.get("status")),
        "tests": tests,
        "cycles": cycles,
        "duration_seconds": duration,
        "tests_per_second": (tests / duration if tests is not None and duration and duration > 0
                              else None),
        "coverage_records": _integer(execution.get("coverage_records")),
        "corpus_entries": _integer(corpus.get("entries")),
        "corpus_verified": corpus.get("status") == "verified",
        "projection": _plain(dict(projection)) if projection else None,
        "transactions": _transactions(report),
        "evidence_missing": list(report.get("evidence_missing", []))
        if isinstance(report.get("evidence_missing"), list) else [],
    }


def compare_soc_campaign_arms(
    arms: Mapping[str, object], *, require_complete: bool = True,
) -> dict[str, object]:
    """Compare direct, constrained and dependency-repair campaign reports.

    ``arms`` maps the stable names in :data:`ARM_NAMES` to report mappings or
    JSON paths.  Identity mismatches are errors by default.  If
    ``require_complete`` is false, absent arms are retained as an explicit
    ``missing`` record; no aggregate comparison is then marked valid.
    """
    if not isinstance(arms, Mapping):
        raise SocComparisonError("arms:mapping-required")
    unknown = sorted(set(str(key) for key in arms) - set(ARM_NAMES))
    if unknown:
        raise SocComparisonError(f"arms:unknown-arm:{unknown[0]}")
    missing = [name for name in ARM_NAMES if name not in arms]
    if missing and require_complete:
        raise SocComparisonError("arms:missing:" + ",".join(missing))
    reports: dict[str, Mapping[str, object]] = {}
    for name, value in arms.items():
        reports[str(name)] = _document(value, str(name))
    identities = {name: _identity(report) for name, report in reports.items()}
    identity_keys = ("composition_hash", "layout_hash", "coverage_kind")
    identity_errors: list[str] = []
    for key in identity_keys:
        observed = {identity.get(key) for identity in identities.values()}
        if None in observed:
            identity_errors.append(f"identity-missing:{key}")
        elif len(observed) != 1:
            identity_errors.append(f"identity-mismatch:{key}")
    if identity_errors:
        raise SocComparisonError("arms:" + ",".join(identity_errors))
    if any(identity.get("structure_audit_status") != "pass"
           for identity in identities.values()):
        raise SocComparisonError("arms:structure-audit-not-passed")
    metrics = {name: _metrics(report) for name, report in reports.items()}
    comparable = not missing and not identity_errors
    document = {
        "schema_version": COMPARISON_SCHEMA,
        "arms": list(ARM_NAMES),
        "present_arms": [name for name in ARM_NAMES if name in reports],
        "missing_arms": missing,
        "identity": identities,
        "metrics": metrics,
        "comparison": {
            "status": "valid" if comparable else "incomplete",
            "same_generated_soc": comparable,
            "same_coverage_identity": comparable,
            "component_bug_claim": "not-claimed",
            "interpretation": (
                "metrics are descriptive; increased validity or throughput alone is not "
                "a success claim when unique effective inputs or DUT coverage decrease"
            ),
        },
    }
    document["comparison_hash"] = content_hash(document)
    return document


def _arm_source(artifact: object, arm: str):
    """The projector one arm uses, from the artifact's own arm table."""
    arms = getattr(artifact, "projection_arms", None)
    if not isinstance(arms, Mapping) or not arms:
        raise SocComparisonError("arms:artifact-without-arm-projectors")
    projector = arms.get(arm)
    if projector is None:
        raise SocComparisonError(f"arms:arm-not-built:{arm}")
    return projector


def _arm_artifact(artifact: object, arm: str):
    """One arm's view of the shared build: same binary, its own projector."""
    projector = _arm_source(artifact, arm)
    document = getattr(artifact, "build_document", None)
    document = dict(document) if isinstance(document, Mapping) else {}
    document["projection_arm"] = arm
    document["projection_instruction_mode"] = str(
        getattr(projector, "instruction_mode", "none"))
    return replace(artifact, projector=projector, build_document=document)


def build_seed_corpus(artifact: object, *, seed: int, entries: int = DEFAULT_CORPUS_ENTRIES,
                      cycles: int = DEFAULT_CORPUS_CYCLES,
                      image_plan: Mapping[str, object] | None = None) -> tuple[dict, ...]:
    """Build the shared initial corpus for every arm.

    The corpus is a deterministic function of the compiled layout and the seed:
    it never depends on the arm, so all three arms start from the same inputs.
    Entries alternate between:

    * ``candidate`` - the offer fields of the dependency segments (image
      instruction/data, or the synthetic master's offer) are raised, their
      address-like fields cycle through the declared addresses and seeded
      values, and their payload fields carry a legal encoding and seeded words.
      A projection that repairs or rejects addresses has something real to do.
    * ``special`` - only the profile layout's own special inputs are driven and
      every dependency bit stays zero, which is the input the constrained
      baseline can accept without any dependency handling.
    """
    for value, label in ((seed, "seed"), (entries, "entries"), (cycles, "cycles")):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise SocComparisonError(f"corpus:{label}-invalid")
    if entries <= 0 or cycles <= 0:
        raise SocComparisonError("corpus:bounds-invalid")
    dependency_owners = ("soc_image", "soc_stimulus")
    fields = [field for field in getattr(artifact, "layout").fields
              if int(getattr(field, "width", 0)) > 0 and str(getattr(field, "role", "")) != "reserved"]
    if not fields:
        raise SocComparisonError("corpus:no-driveable-fields")
    special = [field for field in fields
               if getattr(field, "port", "") and str(field.owner) not in dependency_owners]
    # The dependency dimension of a composition is what its own compiled ABI
    # declares: the synthetic master's request fields when it has a synthetic
    # master, otherwise the instruction/data image segments.  A composition is
    # exercised through the dependency it really has, and the other segment
    # owners stay at zero.
    stimulus = [field for field in fields if str(field.owner) == "soc_stimulus"]
    image = [field for field in fields if str(field.owner) == "soc_image"]
    if any("offer" in str(field.role) for field in stimulus):
        dependency = stimulus
    elif any("offer" in str(field.role) for field in image):
        dependency = image
    else:
        dependency = []
    if not special and not dependency:
        raise SocComparisonError("corpus:no-driveable-fields")
    legal: dict[str, int] = {}
    if isinstance(image_plan, Mapping):
        entry = image_plan.get("entry_address")
        if isinstance(entry, int) and not isinstance(entry, bool):
            legal["init"] = int(entry)
        data_region = image_plan.get("data_region")
        if isinstance(data_region, Mapping) and isinstance(data_region.get("base"), int):
            legal["data"] = int(data_region["base"])
        # A plan that declares several candidate slots publishes each slot's
        # declared address; seeding them keeps every slot's candidate inside its
        # own declared program window instead of at the zero address.
        candidates = image_plan.get("candidates")
        if isinstance(candidates, Mapping):
            for kind in ("instruction", "data"):
                for item in candidates.get(kind, ()):
                    if not isinstance(item, Mapping):
                        continue
                    address = item.get("declared_address")
                    if isinstance(address, int) and not isinstance(address, bool):
                        legal[str(item.get("prefix", ""))] = int(address)
    offers = [field for field in dependency if "offer" in str(field.role)]
    # The instruction/data image projection accepts at most one offer per test
    # (``multiple-image-candidates-unsupported``), so an image offer is raised in
    # exactly one cycle.  A synthetic master's offer may stay raised: its driver
    # owns the latch and counts the offers it has to drop while busy.
    single_cycle_roles = {str(field.role) for field in offers
                          if str(field.owner) == "soc_image"}
    addresses = [field for field in dependency
                 if int(field.width) >= 32 and ("address" in str(field.role)
                                                or "offset" in str(field.role))]
    payloads = [field for field in dependency
                if int(field.width) >= 32 and field not in addresses]
    # A composition may declare several instruction slots, and a declared program
    # must have every one of them offered (`require_all_slots`).  The slot a
    # payload field belongs to is the field's own ordinal among the declared
    # payloads, which is the order the layout appends the slots in, so a caller
    # that wants a *different* instruction per entry can address each slot
    # separately instead of forcing every slot to carry one word.
    rng = random.Random(int(seed))
    corpus: list[dict] = []
    for index in range(entries):
        candidate = index % 2 == 0
        words: list[int] = []
        for cycle in range(cycles):
            value = 0
            # A `special` entry drives only the profile's own inputs, but it still
            # carries the declared instruction words: a declared program must have
            # every instruction slot offered in *every* entry, so an entry that
            # left them zero would be refused for a hole it did not intend to
            # leave and the arm's rejection would say nothing about the projector.
            enabled = special + dependency if candidate else special
            for field in enabled:
                width = int(field.width)
                mask = (1 << width) - 1
                role = str(field.role)
                if field in offers:
                    raw = 0 if (role in single_cycle_roles and cycle) else 1
                elif "be" in role:
                    # A byte-enable field carries the full-word enable: a partial
                    # enable is a separate declared capability, not the default.
                    raw = mask
                elif field in addresses:
                    prefix = role.split("_", 1)[0]
                    legal_value = legal.get(prefix, 0x0000_0000)
                    choices = (legal_value, 0xFFFF_FFFF,
                               rng.getrandbits(32), legal_value + 0x0010_0000)
                    # The offer cycle carries a different address per candidate
                    # entry, so in-window and out-of-window candidates both occur.
                    raw = choices[(index // 2 + cycle) % len(choices)]
                elif field in payloads:
                    choices = (0x0000_0013, rng.getrandbits(32), 0x0000_0000)
                    raw = choices[cycle % len(choices)]
                else:
                    raw = rng.getrandbits(width)
                value |= (raw & mask) << int(field.raw_lo)
            words.append(value)
        corpus.append({"index": index,
                       "kind": "candidate" if candidate else "special",
                       "raw": tuple(words)})
    return tuple(corpus)


def _corpus_payload(artifact: object, raw_values: Sequence[int]) -> bytes:
    return b"".join(artifact.transport.pack(int(value)) for value in raw_values)


def _padded_trace(counters: bytes, coverage_count: int) -> list[int]:
    """Pad the counter bytes exactly the way the upstream corpus format does."""
    padded = ((coverage_count + 9) // 8) * 8 - 2
    if len(counters) != coverage_count:
        raise SocComparisonError("arm:coverage-length-mismatch")
    return list(counters) + [0] * (padded - coverage_count)


def _run_arm(artifact: object, arm: str, corpus: Sequence[Mapping[str, object]], *,
             output_dir: Path, budget_seconds: float, timeout_seconds: float,
             config_id: str = "", cell_id: str = "") -> dict:
    """Execute one arm over the shared corpus and persist its evidence."""
    from .rfuzz_live import (
        build_corpus_manifest,
        peer_event_hash,
        replay_corpus,
        replay_identity,
    )
    from .rfuzz_simulator import RtlSimulator

    view = _arm_artifact(artifact, arm)
    projector = view.projector
    coverage_count = len(view.coverage_ports)
    corpus_dir = Path(output_dir) / "corpus"
    if corpus_dir.exists():
        raise SocComparisonError(f"arm-output-must-be-new:{corpus_dir}")
    corpus_dir.mkdir(parents=True)
    accepted = rejected = anomalies = 0
    coverage_records = 0
    cycles_executed = 0
    coverage_union: set[int] = set()
    per_bit_totals: list[int] = [0] * coverage_count
    rejection_reasons: Counter = Counter()
    anomaly_reasons: Counter = Counter()
    image_writes: Counter = Counter()
    projection_seconds = 0.0
    execution_seconds = 0.0
    truncated = False
    started = time.monotonic()
    entries: list[dict] = []
    saved = 0
    for entry in corpus:
        if time.monotonic() - started > budget_seconds:
            truncated = True
            break
        raw_values = [int(value) for value in entry["raw"]]  # type: ignore[index]
        project_started = time.perf_counter()
        try:
            project_records = getattr(projector, "project_records", None)
            if project_records is not None:
                projected_values = project_records(raw_values)
                # Projectors return a repaired sequence; older identity
                # projectors may return ``None`` after validating in place.
                if projected_values is None:
                    projected_values = raw_values
            else:
                projected_values = [projector.project(value) for value in raw_values]
        except BaseException as error:  # a rejection is evidence, not a crash
            rejected += 1
            projection_seconds += time.perf_counter() - project_started
            reason = f"{type(error).__name__}:{error}"
            rejection_reasons[reason[:160]] += 1
            entries.append({"entry": entry["index"], "kind": entry["kind"],
                            "status": "rejected", "reason": reason[:240]})
            continue
        projection_seconds += time.perf_counter() - project_started
        projected_values = [int(value) for value in projected_values]
        records = [view.transport.pack(value) for value in projected_values]
        simulator = RtlSimulator(view, timeout_seconds=timeout_seconds)
        peer_events = ()
        try:
            execution_started = time.perf_counter()
            counters = simulator.run_test(records)
            peer_events = tuple(getattr(simulator, "last_peer_events", ()) or ())
            execution_seconds += time.perf_counter() - execution_started
            for line in getattr(simulator, "last_diagnostics", ()):
                if line.startswith("MYFUZZ_IMAGE"):
                    fields = dict(part.split("=", 1) for part in line.split()[1:]
                                  if "=" in part)
                    image_writes[str(fields.get("kind", "unknown"))] += 1
        except BaseException as error:  # a DUT/harness anomaly is evidence too
            anomalies += 1
            execution_seconds += time.perf_counter() - execution_started
            diagnostics = [str(line)[:240] for line in
                           tuple(getattr(simulator, "last_diagnostics", ()))[-4:]]
            reason = f"{type(error).__name__}:{error}"
            anomaly_reasons[reason[:160]] += 1
            entries.append({"entry": entry["index"], "kind": entry["kind"],
                            "status": "anomaly", "reason": reason[:240],
                            "diagnostics": diagnostics})
            continue
        finally:
            simulator.close()
        accepted += 1
        cycles_executed += len(records)
        coverage_records += len(counters)
        for bit, count in enumerate(counters):
            per_bit_totals[bit] += int(count)
            if count:
                coverage_union.add(bit)
        payload = _corpus_payload(view, projected_values)
        document = {
            "entry": {"inputs": list(payload)},
            "trace_bits": _padded_trace(counters, coverage_count),
            "replay_identity": replay_identity(view, payload),
            "arm": arm,
        }
        if getattr(view, "peer_slots", ()):
            document["peer_events"] = [dict(item) for item in peer_events]
            document["peer_event_hash"] = peer_event_hash(peer_events)
        path = corpus_dir / f"entry_{saved:04d}.json"
        path.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
        saved += 1
        entries.append({"entry": entry["index"], "kind": entry["kind"],
                        "status": "executed", "file": path.name,
                        "coverage_nonzero": sum(1 for value in counters if value),
                        "cycles": len(records),
                        **({"peer_events": len(peer_events),
                            "peer_event_hash": peer_event_hash(peer_events)}
                           if getattr(view, "peer_slots", ()) else {})})
    elapsed = time.monotonic() - started
    corpus_document: dict[str, object] = {"status": "empty", "entries": 0}
    replay_document: dict[str, object] = {"status": "not-run"}
    if saved:
        manifest = build_corpus_manifest(view, corpus_dir)
        (Path(output_dir) / "corpus_manifest.json").write_text(
            json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
        corpus_document = {"status": "verified", "entries": int(manifest["entries"]),
                           "manifest": manifest}
        replayed = replay_corpus(view, corpus_dir)
        replay_document = {"status": str(replayed.get("status", "failed")),
                           "entries": int(replayed.get("entries", 0)),
                           "document": _plain(replayed)}
    gaps: list[str] = []
    if not saved:
        gaps.append("no-executed-corpus-entry")
    if truncated:
        gaps.append("arm-budget-truncated")
    if anomalies:
        gaps.append("dut-or-harness-anomalies-recorded")
    gaps.append("source-target-transactions-not-observed-in-corpus-mode")
    build = getattr(view, "build_document", {})
    assert isinstance(build, Mapping)
    report = {
        "schema_version": ARM_REPORT_SCHEMA,
        "config_id": config_id or build.get("composition_hash"),
        "cell_id": cell_id or config_id or build.get("composition_hash"),
        "arm": arm,
        "drive_profile": build.get("drive_profile"),
        "mode": build.get("mode"),
        "status": "completed" if saved and not truncated else "incomplete-evidence",
        "final_status": "passed" if saved and not truncated else "failed-acceptance",
        "artifact": {
            "composition_hash": build.get("composition_hash"),
            "layout_hash": build.get("layout_hash"),
            "policy_hash": build.get("policy_hash"),
            "constraint_hash": build.get("constraint_hash"),
            "image_hash": build.get("image_hash"),
            "coverage_kind": build.get("coverage_kind"),
            "mode": build.get("mode"),
            "drive_profile": build.get("drive_profile"),
            "projection_arm": arm,
            "structure_audit": _plain(build.get("structure_audit")),
            "source_closure_hash": content_hash(build.get("sources", {})),
        },
        "rtl_execution": {
            "tests": accepted,
            "coverage_records": coverage_records,
            "execution_totals": {"cycles": cycles_executed},
            "coverage_bits_total": coverage_count,
            "coverage_bits_hit": len(coverage_union),
            "coverage_bit_totals": per_bit_totals,
            "image_writes": dict(sorted(image_writes.items())),
        },
        "corpus": corpus_document,
        "replay": replay_document,
        "peer_event_evidence": ({
            "mode": "raw-abi-derived-v1",
            "entries": sum(1 for item in entries if "peer_event_hash" in item),
        } if getattr(view, "peer_slots", ()) else {"mode": "not-applicable", "entries": 0}),
        "input_projection": {
            "raw_samples": len(corpus) * (len(corpus[0]["raw"]) if corpus else 0),
            "projected_samples": accepted * (len(corpus[0]["raw"]) if corpus else 0),
            "projection_rejections": rejected,
            "rejected_entries": rejected,
            "accepted_entries": accepted,
            "anomaly_entries": anomalies,
            "rejection_reasons": dict(sorted(rejection_reasons.items())),
            "anomaly_reasons": dict(sorted(anomaly_reasons.items())),
            "instruction_mode": str(getattr(projector, "instruction_mode", "none")),
            "constraint_hash": getattr(projector, "constraint_hash", None),
            "repair_counts": {
                str(name): int(value)
                for name, value in (getattr(projector, "repair_counts", {}) or {}).items()
                if isinstance(value, int) and not isinstance(value, bool)
            },
        },
        "timing": {
            "wall_seconds": elapsed,
            "projection_seconds": projection_seconds,
            "execution_seconds": execution_seconds,
            "samples_per_second": (accepted / elapsed if elapsed > 0 else None),
            "cycles_per_second": (cycles_executed / elapsed if elapsed > 0 else None),
        },
        "entries": entries,
        # The corpus path observes the generated RTL and its own coverage; it
        # does not run the official RFuzz client, so the client-side fields the
        # live path reports stay explicitly absent rather than being invented.
        "client_result": {"binary_sha256": _binary_hash(view)},
        "fifo_reply_receipts": [],
        "evidence_missing": sorted(set(gaps)),
        "budget_seconds": budget_seconds,
        "seed": None,
        "duration_seconds": elapsed,
        "effective_fuzz_seconds": elapsed,
        "execution_mode": "seeded-corpus-real-rtl",
    }
    return report


def _binary_hash(artifact: object) -> str:
    import hashlib

    executable = getattr(artifact, "executable", None)
    if executable is None or not Path(executable).is_file():
        return "unavailable"
    return "sha256:" + hashlib.sha256(Path(executable).read_bytes()).hexdigest()


def _build_identity(artifact: object) -> dict[str, object]:
    """Identity that must remain fixed while an official corpus is replayed."""
    build = getattr(artifact, "build_document", None)
    if not isinstance(build, Mapping):
        raise SocComparisonError("official-replay:artifact-without-build-document")
    sources = build.get("sources")
    tool = build.get("tool_identity")
    required = {
        "composition_hash": build.get("composition_hash"),
        "layout_hash": build.get("layout_hash") or getattr(
            getattr(artifact, "layout", None), "layout_hash", None),
        "coverage_kind": build.get("coverage_kind") or getattr(
            artifact, "coverage_kind", None),
        "source_closure_hash": content_hash(sources) if isinstance(sources, Mapping) else None,
        "tool_identity": _plain(tool) if isinstance(tool, Mapping) else None,
        "binary_sha256": _binary_hash(artifact),
    }
    missing = [key for key, value in required.items() if value in (None, "unavailable")]
    if missing:
        raise SocComparisonError("official-replay:identity-missing:" + ",".join(sorted(missing)))
    return required


def _official_report_identity(report: Mapping[str, object]) -> dict[str, object]:
    artifact = report.get("artifact")
    if not isinstance(artifact, Mapping):
        raise SocComparisonError("official-replay:report-without-artifact")
    source_closure = artifact.get("source_closure")
    tool = artifact.get("tool_identity")
    return {
        "composition_hash": artifact.get("composition_hash"),
        "layout_hash": artifact.get("layout_hash"),
        "coverage_kind": artifact.get("coverage_kind"),
        "source_closure_hash": (
            content_hash(source_closure) if isinstance(source_closure, Mapping)
            else artifact.get("source_closure_hash")),
        "tool_identity": _plain(tool) if isinstance(tool, Mapping) else None,
        "binary_sha256": (
            (report.get("client_result", {}).get("binary_sha256")
             if isinstance(report.get("client_result"), Mapping) else None)
            or artifact.get("executable_sha256")),
    }


def _assert_official_replay_identity(artifact: object, report: Mapping[str, object],
                                     manifest: Mapping[str, object]) -> dict[str, object]:
    current = _build_identity(artifact)
    published = _official_report_identity(report)
    mismatches = []
    for key in current:
        if published.get(key) is None:
            mismatches.append(f"identity-missing:{key}")
        elif published[key] != current[key]:
            mismatches.append(f"identity-mismatch:{key}")
    if manifest.get("layout_hash") not in (None, current["layout_hash"]):
        mismatches.append("identity-mismatch:layout_hash")
    if manifest.get("binary_sha256") not in (None, current["binary_sha256"]):
        mismatches.append("identity-mismatch:binary_sha256")
    if mismatches:
        raise SocComparisonError("official-replay:" + ",".join(sorted(set(mismatches))))
    return current


def replay_official_corpus_arms(
    artifact: object, corpus_dir: Path | str, *, campaign_report: Mapping[str, object] | str | Path,
    output_dir: Path | str | None = None, arms: Sequence[str] = ARM_NAMES,
    timeout_seconds: float = 60.0,
) -> dict[str, object]:
    """Replay one *official* RFuzz corpus with the three input projectors.

    This is intentionally separate from :func:`execute_soc_campaign_arms`:
    that function generates a deterministic seeded corpus, whereas this entry
    point accepts only a corpus proven by a completed official client run.  The
    raw bytes and the compiled artifact are fixed; each arm may change only the
    projection and therefore its acceptance/repair/coverage observations.
    """
    if tuple(arms) != ARM_NAMES:
        raise SocComparisonError("official-replay:arms-must-be-direct-constrained-repair")
    report = _document(campaign_report, "campaign")
    if report.get("execution_kind") != "official_rfuzz_source_backed_soc":
        raise SocComparisonError("official-replay:official-execution-required")
    if report.get("final_status") not in {"passed", "passed_with_client_termination"}:
        raise SocComparisonError("official-replay:official-campaign-not-accepted")
    execution = report.get("rtl_execution")
    if (not isinstance(execution, Mapping)
            or not isinstance(execution.get("tests"), int)
            or execution.get("tests", 0) <= 0
            or not isinstance(execution.get("coverage_records"), int)
            or execution.get("coverage_records", 0) <= 0):
        raise SocComparisonError("official-replay:positive-rtl-coverage-required")
    corpus_evidence = report.get("corpus")
    if (not isinstance(corpus_evidence, Mapping)
            or corpus_evidence.get("status") != "verified"
            or not isinstance(corpus_evidence.get("entries"), int)
            or corpus_evidence.get("entries", 0) <= 0):
        raise SocComparisonError("official-replay:official-corpus-not-verified")
    receipts = report.get("fifo_reply_receipts")
    if not isinstance(receipts, Sequence) or isinstance(receipts, (str, bytes)) or not receipts:
        raise SocComparisonError("official-replay:official-receipts-required")
    for index, receipt in enumerate(receipts):
        if (not isinstance(receipt, Mapping)
                or not isinstance(receipt.get("input_sha256"), str)
                or not receipt.get("input_sha256")
                or not isinstance(receipt.get("coverage_sha256"), str)
                or not receipt.get("coverage_sha256")
                or receipt.get("status") != "fifo_reply_and_rtl_completed"
                or receipt.get("transport") != "sysv-shared-memory-rfuzz-coverage-buffer"):
            raise SocComparisonError(f"official-replay:receipt-invalid:{index}")
    corpus = Path(corpus_dir).resolve()
    if not corpus.is_dir() or corpus.is_symlink():
        raise SocComparisonError("official-replay:corpus-directory-required")
    paths = sorted(corpus.glob("entry_*.json"))
    if not paths:
        raise SocComparisonError("official-replay:corpus-empty")
    manifest_path = corpus.parent / "corpus_manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise SocComparisonError("official-replay:corpus-manifest-required")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError) as error:
        raise SocComparisonError("official-replay:corpus-manifest-invalid") from error
    if (not isinstance(manifest, Mapping)
            or manifest.get("schema_version") != "rfuzz_corpus_manifest.v1"
            or manifest.get("coverage_transport")
            != "sysv-shared-memory-rfuzz-coverage-buffer"):
        raise SocComparisonError("official-replay:corpus-manifest-invalid")
    identity = _assert_official_replay_identity(artifact, report, manifest)
    replay_rows = manifest.get("replays")
    if (manifest.get("entries") != len(paths) or not isinstance(replay_rows, list)
            or {row.get("file") for row in replay_rows if isinstance(row, Mapping)}
            != {path.name for path in paths}):
        raise SocComparisonError("official-replay:corpus-manifest-entries-mismatch")
    required_replay_fields = (
        "file", "input_sha256", "coverage_sha256", "trace_sha256",
        "coverage_verified", "shared_memory_exchange_verified", "layout_hash",
        "constraint_hash", "binary_sha256",
    )
    for index, row in enumerate(replay_rows):
        if (not isinstance(row, Mapping)
                or any(key not in row or row.get(key) in (None, "")
                       for key in required_replay_fields)
                or row.get("coverage_verified") is not True
                or row.get("shared_memory_exchange_verified") is not True):
            raise SocComparisonError(f"official-replay:manifest-replay-invalid:{index}")

    from .rfuzz_live import _corpus_document, replay_identity
    raw_entries = []
    for path in paths:
        try:
            document, payload, expected = _corpus_document(
                path, byte_count=artifact.transport.byte_count)
        except (OSError, TypeError, ValueError) as error:
            raise SocComparisonError(f"official-replay:corpus-entry-invalid:{path.name}") from error
        current_entry_identity = replay_identity(artifact, payload)
        declared = document.get("replay_identity")
        if isinstance(declared, Mapping):
            # The original arm's constraint hash is intentionally allowed to
            # differ.  Raw bytes, layout, executable and physical simulator
            # controls must still identify the same official run.
            for key in ("raw_sha256", "layout_hash", "binary_sha256",
                        "physical_controls_sha256", "simulator_inputs_sha256"):
                if declared.get(key) not in (None, current_entry_identity.get(key)):
                    raise SocComparisonError(
                        f"official-replay:entry-identity-mismatch:{key}:{path.name}")
        row = next(item for item in replay_rows if isinstance(item, Mapping)
                   and item.get("file") == path.name)
        if row.get("input_sha256") not in (None, current_entry_identity["raw_sha256"]):
            raise SocComparisonError(f"official-replay:entry-identity-mismatch:raw:{path.name}")
        if row.get("layout_hash") != identity["layout_hash"]:
            raise SocComparisonError(f"official-replay:entry-identity-mismatch:layout:{path.name}")
        if row.get("binary_sha256") != identity["binary_sha256"]:
            raise SocComparisonError(f"official-replay:entry-identity-mismatch:binary:{path.name}")
        if row.get("trace_sha256") != _hash_bytes(bytes(expected)):
            raise SocComparisonError(f"official-replay:entry-trace-mismatch:{path.name}")
        raw_entries.append({"file": path.name, "payload": payload,
                            "trace_sha256": _hash_bytes(bytes(expected)),
                            "raw_sha256": current_entry_identity["raw_sha256"]})
    corpus_hash = content_hash({
        "schema_version": "official_rfuzz_raw_corpus.v1",
        "entries": [{"file": item["file"], "raw_sha256": item["raw_sha256"]}
                    for item in raw_entries],
    })

    reports: dict[str, dict[str, object]] = {}
    output = None if output_dir is None else Path(output_dir).absolute()
    if output is not None:
        if output.exists() or output.is_symlink():
            raise SocComparisonError("official-replay:output-must-be-new")
        output.mkdir(parents=True)
    for arm in ARM_NAMES:
        view = _arm_artifact(artifact, arm)
        projector = view.projector
        accepted = rejected = anomalies = 0
        coverage_records = 0
        coverage_union: set[int] = set()
        per_bit_totals = [0] * len(view.coverage_ports)
        entries = []
        started = time.monotonic()
        try:
            from .rfuzz_simulator import RtlSimulator
            simulator_context = RtlSimulator(view, timeout_seconds=timeout_seconds)
            with simulator_context as simulator:
                for item in raw_entries:
                    payload = item["payload"]
                    values = [
                        view.transport.unpack(payload[index:index + view.transport.byte_count])
                        for index in range(0, len(payload), view.transport.byte_count)
                    ]
                    try:
                        project_records = getattr(projector, "project_records", None)
                        projected = (project_records(values) if callable(project_records)
                                     else [projector.project(value) for value in values])
                        projected = values if projected is None else list(projected)
                        records = [view.transport.pack(int(value)) for value in projected]
                    except BaseException as error:
                        rejected += 1
                        entries.append({"file": item["file"], "status": "rejected",
                                        "reason": f"{type(error).__name__}:{error}"[:240]})
                        continue
                    try:
                        counters = simulator.run_test(records)
                        if len(counters) != len(view.coverage_ports):
                            raise SocComparisonError("official-replay:coverage-length-mismatch")
                    except BaseException as error:
                        anomalies += 1
                        entries.append({"file": item["file"], "status": "anomaly",
                                        "reason": f"{type(error).__name__}:{error}"[:240]})
                        continue
                    accepted += 1
                    coverage_records += len(counters)
                    for bit, count in enumerate(counters):
                        per_bit_totals[bit] += int(count)
                        if count:
                            coverage_union.add(bit)
                    entries.append({"file": item["file"], "status": "executed",
                                    "raw_sha256": item["raw_sha256"],
                                    "trace_sha256": item["trace_sha256"],
                                    "projected_cycles": len(records),
                                    "coverage_sha256": _hash_bytes(bytes(counters))})
        except SocComparisonError:
            raise
        except BaseException as error:
            raise SocComparisonError(f"official-replay:{arm}-runner-failed:{error}") from error
        arm_report = {
            "schema_version": ARM_REPORT_SCHEMA,
            "execution_mode": "official-rfuzz-corpus-replay-3arm",
            "arm": arm,
            "status": "completed" if not anomalies else "incomplete-evidence",
            "final_status": "passed" if accepted and not anomalies else "failed-acceptance",
            "artifact": {
                "composition_hash": identity["composition_hash"],
                "layout_hash": identity["layout_hash"],
                "coverage_kind": identity["coverage_kind"],
                "structure_audit": {"status": "pass"},
                "source_closure_hash": identity["source_closure_hash"],
                "tool_identity": identity["tool_identity"],
                "executable_sha256": identity["binary_sha256"],
            },
            "rtl_execution": {"tests": accepted, "coverage_records": coverage_records,
                               "execution_totals": {"cycles": sum(
                                   int(item.get("projected_cycles", 0)) for item in entries
                                   if item.get("status") == "executed")}},
            "corpus": {"status": "verified", "entries": len(raw_entries),
                       "raw_corpus_hash": corpus_hash},
            "input_projection": {
                "raw_samples": sum(len(item["payload"]) // artifact.transport.byte_count
                                    for item in raw_entries),
                "projected_samples": sum(int(item.get("projected_cycles", 0)) for item in entries
                                         if item.get("status") == "executed"),
                "accepted_entries": accepted, "rejected_entries": rejected,
                "anomaly_entries": anomalies,
                "repair_counts": {str(name): int(value) for name, value in
                                   (getattr(projector, "repair_counts", {}) or {}).items()
                                   if type(value) is int and value >= 0},
            },
            "client_result": {"binary_sha256": identity["binary_sha256"]},
            "entries": entries,
            "source_corpus": {"raw_corpus_hash": corpus_hash,
                              "official_manifest": str(manifest_path)},
            "evidence_missing": (["no-accepted-entry"] if not accepted else []),
            "duration_seconds": time.monotonic() - started,
        }
        reports[arm] = arm_report
        if output is not None:
            arm_dir = output / arm
            arm_dir.mkdir()
            (arm_dir / "report.json").write_text(
                json.dumps(arm_report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    comparison = compare_soc_campaign_arms(reports, require_complete=True)
    result = {
        "schema_version": "soc_campaign_official_corpus_replay.v1",
        "execution_mode": "official-rfuzz-corpus-replay-3arm",
        "arms": list(ARM_NAMES),
        "shared": {
            **identity,
            "raw_corpus_hash": corpus_hash,
            "corpus_entries": len(raw_entries),
            "identity_shared": True,
        },
        "arm_reports": {arm: (f"{arm}/report.json" if output is not None else reports[arm])
                        for arm in ARM_NAMES},
        "comparison": comparison,
        "not_verified": [
            "the official client is not rerun for each arm; all three observations are "
            "projections of one retained official raw corpus",
        ],
    }
    result["replay_hash"] = content_hash(result)
    if output is not None:
        (output / "replay.json").write_text(
            json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return result


def execute_soc_campaign_arms(
    config: Mapping[str, object], output: Path, *, root: Path | None = None,
    builder: object | None = None, corpus: Sequence[Mapping[str, object]] | None = None,
    arms: Sequence[str] = ARM_NAMES, timeout_seconds: float = 60.0,
    environment: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Build once, execute the three projection arms, compare them.

    The SoC, the source closure, the coverage instrumentation, the budget and the
    seed come from one config and one build; only the arm's input projector
    differs.  Every arm's corpus, projection counters, repair counters, coverage
    and replay are persisted under ``output/arms/<arm>/`` and the executed
    comparison is written to ``output/comparison.json``.
    """
    from .soc_builder import build_soc_campaign_artifact
    from .soc_campaign import _normalise_config, real_soc_opt_in

    if not isinstance(config, Mapping):
        raise SocComparisonError("config:mapping-required")
    names = tuple(str(name) for name in arms)
    if sorted(names) != sorted(ARM_NAMES):
        raise SocComparisonError("arms:unknown-arm:" + ",".join(sorted(set(names) - set(ARM_NAMES))))
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise SocComparisonError(f"arms-output-must-be-new:{output}")
    normal = _normalise_config(config)
    if not real_soc_opt_in(environment):
        raise SocComparisonError("arms:real-opt-in-required:MYFUZZ_SOC_REAL=1")
    root = Path(root or config.get("root") or Path.cwd()).resolve()
    output.mkdir(parents=True)
    build_hook = builder or config.get("build_artifact") or build_soc_campaign_artifact
    if not callable(build_hook):
        raise SocComparisonError("arms:builder-not-callable")
    artifact = build_hook(dict(config), output / "build")
    build = getattr(artifact, "build_document", None)
    if not isinstance(build, Mapping):
        raise SocComparisonError("arms:artifact-without-build-document")
    audit = build.get("structure_audit")
    if not isinstance(audit, Mapping) or audit.get("status") != "pass":
        raise SocComparisonError("arms:structure-audit-not-passed")
    image_plan = None
    image_plan_path = Path(output) / "build" / "image_plan.json"
    if image_plan_path.is_file():
        image_plan = json.loads(image_plan_path.read_text(encoding="utf-8"))
    shared = corpus if corpus is not None else build_seed_corpus(
        artifact, seed=int(normal["seed"]),
        entries=int(config.get("corpus_entries", DEFAULT_CORPUS_ENTRIES)),
        cycles=int(config.get("corpus_cycles", DEFAULT_CORPUS_CYCLES)),
        image_plan=image_plan if isinstance(image_plan, Mapping) else None)
    budget = float(normal["duration_seconds"])
    reports: dict[str, dict] = {}
    for arm in names:
        arm_dir = output / "arms" / arm
        arm_dir.mkdir(parents=True)
        report = _run_arm(artifact, arm, shared, output_dir=arm_dir,
                          budget_seconds=budget, timeout_seconds=float(timeout_seconds),
                          config_id=str(normal["config_id"]),
                          cell_id=str(normal["cell_id"]))
        report["seed"] = int(normal["seed"])
        report["budget_seconds"] = budget
        (arm_dir / "report.json").write_text(
            json.dumps(report, sort_keys=True, default=str) + "\n", encoding="utf-8")
        reports[arm] = report
    comparison = compare_soc_campaign_arms(
        {arm: reports[arm] for arm in names}, require_complete=True)
    # The fixed-identity claim is checked, not assumed: same composition, same
    # layout, same coverage kind, same executable and same source closure.
    identity_values = {
        "composition_hash": {report["artifact"]["composition_hash"] for report in reports.values()},
        "layout_hash": {report["artifact"]["layout_hash"] for report in reports.values()},
        "coverage_kind": {report["artifact"]["coverage_kind"] for report in reports.values()},
        "source_closure_hash": {report["artifact"]["source_closure_hash"]
                                for report in reports.values()},
        "binary_sha256": {report["client_result"]["binary_sha256"]
                          for report in reports.values()},
    }
    identity_shared = all(len(values) == 1 for values in identity_values.values())
    if not identity_shared:
        raise SocComparisonError("arms:identity-not-shared:" + ",".join(
            sorted(name for name, values in identity_values.items() if len(values) != 1)))
    document: dict[str, object] = {
        "schema_version": ARMS_EXECUTION_SCHEMA,
        "config_id": normal["config_id"],
        "drive_profile": build.get("drive_profile"),
        "mode": build.get("mode"),
        "execution_mode": "seeded-corpus-real-rtl",
        "arms": list(names),
        "shared": {
            "composition_hash": next(iter(identity_values["composition_hash"])),
            "layout_hash": next(iter(identity_values["layout_hash"])),
            "coverage_kind": next(iter(identity_values["coverage_kind"])),
            "source_closure_hash": next(iter(identity_values["source_closure_hash"])),
            "executable_sha256": next(iter(identity_values["binary_sha256"])),
            "seed": int(normal["seed"]),
            "budget_seconds": budget,
            "seed_cycles": int(normal["seed_cycles"]),
            "corpus_entries": len(shared),
            "corpus_cycles": len(shared[0]["raw"]) if shared else 0,
            "identity_shared": identity_shared,
        },
        "arm_reports": {arm: f"arms/{arm}/report.json" for arm in names},
        "comparison": comparison,
        "not_verified": [
            "the official RFuzz mutator/client is not executed in this mode: the corpus is a "
            "seeded deterministic schedule, so fifo reply receipts and mutator search "
            "behaviour are absent",
            "source/target transaction counters are not observed by the corpus runner",
        ],
    }
    document["arms_hash"] = content_hash(document)
    (output / "comparison.json").write_text(
        json.dumps(comparison, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    (output / "arms_report.json").write_text(
        json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return document


__all__ = [
    "ARM_NAMES", "ARMS_EXECUTION_SCHEMA", "ARM_REPORT_SCHEMA", "COMPARISON_SCHEMA",
    "DEFAULT_CORPUS_CYCLES", "DEFAULT_CORPUS_ENTRIES", "SocComparisonError",
    "build_seed_corpus", "compare_soc_campaign_arms",
    "execute_soc_campaign_arms", "replay_official_corpus_arms",
]
