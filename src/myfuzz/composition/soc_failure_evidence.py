"""Failure evidence, replay and boundary attribution for a composed SoC.

Step 9 of the assurance plan (``#### 步骤 9：异常证据、缩减和归因``) requires one
package per anomaly that carries the identity of everything that produced it,
the raw input that was really applied, the observed result, a shrink log and an
attribution reason; and it requires that a conclusion of "component internal
defect" is only drawn when the wiring, profile semantics, legality and
observation criteria have been checked (``### 1.10.3``).

This module implements that package without softening any of those rules:

* :func:`build_evidence_package` binds the plan, layout, per-component profile
  content hashes, the compiled constraint-policy hash, the rendered top hash,
  the testbench hash, the build hash, the boot-image hash and the runtime/tool
  identity into one :class:`EvidencePackage`.  The plan/layout half is read back
  from the build's own generated testbench record, so a package cannot claim an
  identity the build directory does not carry.
* :func:`replay_package` re-runs the *saved* raw inputs and compares the whole
  applied stimulus, peer applications and observation set, reporting the first cycle/field that
  differs instead of a bare "failed".  A package whose identity does not match
  the build is refused, never replayed.
* :func:`classify_boundary` separates the categories the plan names and returns
  ``undiagnosed`` whenever a required identity or legality field is missing.  It
  never returns ``component_candidate`` for incomplete evidence; the gate is
  factored into :func:`component_candidate_ready` so that property is directly
  testable.
* :func:`minimize_sample` shrinks the raw input with a caller-supplied predicate
  (delta debugging over contiguous chunks plus a word-zeroing pass), re-running
  the real build for every candidate, and reports why it stopped: the step
  budget or a fixed point.

The safety default is deliberate: a package built without a legality record is
classified ``undiagnosed``, and a package built without an explicit criterion is
classified ``observation_insufficient``.  The compiler's own rule set is *not*
used as a criterion automatically, because software and checkers generated from
one profile are not independent evidence of that profile's semantics
(``### 1.10.3``, ``同源错误验证``).
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from myfuzz.contracts import canonical_bytes

from .soc_composition import CompositionPlan
from .soc_runtime import (
    RUNTIME_SCHEMA,
    TESTBENCH_MODULE,
    TOP_MODULE,
    ExternalEvent,
    PeerStimulusEvent,
    RunResult,
    RuntimeBuild,
    RuntimeSample,
    run_sample,
)

EVIDENCE_SCHEMA = "soc_failure_evidence.v1"
EVIDENCE_DOCUMENT = "evidence_package.json"
RAW_INPUT_DIRECTORY = "raw_inputs"
RAW_INPUT_INDEX = "raw_inputs.json"
APPLIED_TRACE_DOCUMENT = "applied_trace.json"

#: The boundary categories step 9 requires to stay apart.
COMPONENT_CANDIDATE = "component_candidate"
COMPOSITION_DEFECT = "composition_defect"
PROFILE_DEFECT = "profile_defect"
SOFTWARE_OR_MODEL_DEFECT = "software_or_model_defect"
DRIVER_VIOLATION = "driver_violation"
OBSERVATION_INSUFFICIENT = "observation_insufficient"
UNDIAGNOSED = "undiagnosed"
BOUNDARY_CLASSES = (
    COMPONENT_CANDIDATE,
    COMPOSITION_DEFECT,
    PROFILE_DEFECT,
    SOFTWARE_OR_MODEL_DEFECT,
    DRIVER_VIOLATION,
    OBSERVATION_INSUFFICIENT,
    UNDIAGNOSED,
)

#: Replay outcomes.  ``refused`` means the package was not replayed at all
#: because its identity does not describe the build it was handed.
REPLAY_AGREEMENT = "agreement"
REPLAY_DIVERGENCE = "divergence"
REPLAY_REFUSED = "refused"

#: Environment-legality states of one package.
LEGALITY_CONFIRMED = "confirmed"
LEGALITY_VIOLATED = "violated"
LEGALITY_UNAVAILABLE = "unavailable"

#: Identity fields a package must carry before any boundary conclusion is
#: attempted.  ``tool`` is validated as a record, see :func:`missing_identity`.
REQUIRED_IDENTITY = (
    "plan_hash",
    "layout_hash",
    "profile_hashes",
    "policy_hash",
    "policy_drive_profile",
    "rendered_top_hash",
    "testbench_hash",
    "build_hash",
    "boot_image_hash",
    "isa",
    "runtime",
    "tool",
)

#: Legality fields a package must carry before any boundary conclusion is
#: attempted.  A record without ``environment_legality`` says nothing about
#: whether the environment was legal, which is exactly the evidence the plan
#: requires before a component-internal conclusion.
REQUIRED_LEGALITY = (
    "environment_legality",
    "driver_violations",
    "constraint_rejections",
    "monitor_results",
)

#: The markers ``soc_runtime.render_profile_testbench`` writes into the head of
#: the generated testbench; they are how a build records the plan and layout it
#: was made from.
PLAN_MARKER = "// plan: "
LAYOUT_MARKER = "// raw-input layout: "

#: The minimiser's default search budget, in real re-runs of the build.
DEFAULT_MINIMIZE_BUDGET = 64
MAX_MINIMIZE_BUDGET = 4096
#: Bound on the recorded per-candidate history so a shrink log stays readable.
MAX_MINIMIZE_HISTORY = 1024


class SocFailureEvidenceError(ValueError):
    """The evidence package cannot be built, written, read or replayed."""


def _error(reason: str) -> None:
    raise SocFailureEvidenceError(reason)


def _sha256_file(path: object) -> str:
    target = Path(str(path))
    if not target.is_file():
        return "missing"
    return "sha256:" + hashlib.sha256(target.read_bytes()).hexdigest()


def _sha256_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _is_sha256(value: object) -> bool:
    return (isinstance(value, str) and value.startswith("sha256:")
            and len(value) == len("sha256:") + 64)


def _records(value: object) -> tuple[object, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes)):
        return (value,)
    if isinstance(value, Sequence):
        return tuple(value)
    if isinstance(value, Mapping):
        return (dict(value),)
    return (value,)


# ---------------------------------------------------------------------------
# identity
# ---------------------------------------------------------------------------


def recorded_build_identity(build: RuntimeBuild) -> dict[str, str]:
    """The plan/layout identity the build directory itself records.

    ``RuntimeBuild`` has no ``layout_hash`` field, so the identity is read from
    the build's own generated testbench: ``render_profile_testbench`` writes the
    plan hash and the raw-layout hash into its header, on the lines that begin
    with ``// plan: `` and ``// raw-input layout: ``.  A build whose record is
    missing or truncated is an error, not a silent pass: without it the layout a
    package was saved under cannot be compared with anything.

    ``soc_runtime.run_sample_with_policy`` performs the same check inline; it
    cannot import this module because this module imports it.
    """
    path = Path(build.testbench_path)
    if not path.is_file():
        _error(f"build-record-unreadable:{path}")
    plan_hash = ""
    layout_hash = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        if not plan_hash and line.startswith(PLAN_MARKER):
            plan_hash = line[len(PLAN_MARKER):].strip()
        elif not layout_hash and line.startswith(LAYOUT_MARKER):
            layout_hash = line[len(LAYOUT_MARKER):].strip()
    if not plan_hash or not layout_hash:
        _error(f"build-record-without-identity:{path}")
    return {"plan_hash": plan_hash, "layout_hash": layout_hash}


def profile_identities(plan: CompositionPlan) -> dict[str, object]:
    """The per-component profile content and binding identity of one plan."""
    records: dict[str, object] = {}
    for instance in plan.instances:
        component = str(instance.component_id)
        record = records.setdefault(component, {
            "component_id": component,
            "top_module": str(instance.binding.facts.top_module),
            "content_hash": str(instance.binding.facts.content_hash),
            "binding_hashes": {},
            "instances": [],
        })
        assert isinstance(record, dict)
        record["binding_hashes"][str(instance.instance_id)] = str(  # type: ignore[index]
            instance.binding.binding_hash)
        record["instances"].append(str(instance.instance_id))  # type: ignore[union-attr]
    for record in records.values():
        assert isinstance(record, dict)
        record["instances"] = sorted(record["instances"])
    return dict(sorted(records.items()))


def isa_identity(plan: CompositionPlan) -> dict[str, object] | None:
    """The declared ISA/execution identity of the CPU the plan composes."""
    for instance in plan.instances:
        if instance.kind != "cpu":
            continue
        contract = instance.profile.cpu
        if contract is None:
            return None
        return {
            "instance_id": str(instance.instance_id),
            "component_id": str(instance.component_id),
            "family": str(contract.family),
            "xlen": int(contract.xlen),
            "extensions": sorted(str(item).upper() for item in contract.extensions),
            "reset_vector": int(contract.reset_vector),
            "boot_address_required": bool(contract.boot_address_required),
            "provenance": f"component_profile:{instance.component_id}",
        }
    return None


def tool_identity(build: RuntimeBuild, *, probe: bool = True) -> dict[str, object]:
    """The simulator/tool identity available for a build.

    The always-available part is the compiled executable's content hash, which
    is what actually produced every observation.  The Verilator version string
    is recorded when it can be probed and recorded as ``unavailable`` (with the
    reason) when it is not probed or the probe fails; :func:`missing_identity`
    only requires the executable hash, so a machine without ``verilator`` on PATH
    can still package evidence honestly instead of failing or inventing a
    version.
    """
    version = "unavailable"
    provenance = "unavailable: verilator was not found on PATH"
    if probe:
        executable = shutil.which("verilator")
        if executable:
            try:
                result = subprocess.run((executable, "--version"), capture_output=True,
                                        text=True, check=False, timeout=30)
                lines = (result.stdout or result.stderr or "").strip().splitlines()
                if result.returncode == 0 and lines:
                    version = lines[0].strip()
                    provenance = f"probe:{executable} --version"
                else:
                    provenance = f"unavailable: probe-returncode={result.returncode}"
            except (OSError, subprocess.TimeoutExpired) as error:  # pragma: no cover
                provenance = f"unavailable: probe-failed:{error}"
    return {
        "simulator": "verilator",
        "verilator": version,
        "runtime_schema": RUNTIME_SCHEMA,
        "executable_hash": _sha256_file(build.executable),
        "provenance": provenance,
    }


def policy_rule_list(policy: object) -> list[dict[str, object]]:
    """The compiled constraint list, in the order the policy holds it.

    The full rule documents stay in the policy (they are recoverable from the
    plan and the rule set); the package records the identifiers, categories,
    owners, primitives, failure classes and checkers, which is what makes the
    list auditable next to the run it constrained.
    """
    records = []
    for rule in getattr(policy, "rules", ()) or ():
        records.append({
            "rule_id": str(getattr(rule, "rule_id", "")),
            "category": str(getattr(rule, "category", "")),
            "owner": str(getattr(rule, "owner", "")),
            "primitive": str(getattr(rule, "primitive", "")),
            "phase": str(getattr(rule, "phase", "")),
            "failure_class": str(getattr(rule, "failure_class", "")),
            "checker": str(getattr(rule, "checker", "")),
        })
    return records


def build_identity(plan: CompositionPlan, build: RuntimeBuild, policy: object, *,
                   tool: Mapping[str, object] | None = None) -> dict[str, object]:
    """Bind the plan, the build and the constraint policy into one identity."""
    recorded = recorded_build_identity(build)
    raw_layout = getattr(plan, "raw_layout", {}) or {}
    policy_record = {
        "policy_hash": str(getattr(policy, "policy_hash", "") or ""),
        "drive_profile": str(getattr(policy, "drive_profile", "") or ""),
        "profile_version": int(getattr(policy, "profile_version", 0) or 0),
        "layout_hash": str(getattr(policy, "layout_hash", "") or ""),
        "plan_hash": str(getattr(policy, "plan_hash", "") or ""),
        "rule_count": len(getattr(policy, "rules", ()) or ()),
        "rules": policy_rule_list(policy),
        "gaps": [str(item) for item in getattr(policy, "gaps", ()) or ()],
    }
    boot_image = getattr(build, "boot_image", None)
    return {
        "plan_hash": str(getattr(plan, "plan_hash", "") or ""),
        "layout_hash": str(raw_layout.get("layout_hash", "") or ""),
        "profile_hashes": profile_identities(plan),
        "policy_hash": policy_record["policy_hash"],
        "policy_drive_profile": policy_record["drive_profile"],
        "policy": policy_record,
        "rendered_top_hash": _sha256_file(build.top_path),
        "testbench_hash": _sha256_file(build.testbench_path),
        "build_hash": str(getattr(build, "build_hash", "") or ""),
        "boot_image_hash": "none" if boot_image is None else _sha256_file(boot_image),
        "boot_image_policy": str(getattr(build, "boot_image_policy", "") or ""),
        "isa": isa_identity(plan),
        "runtime": {
            "schema_version": RUNTIME_SCHEMA,
            "top_module": TOP_MODULE,
            "testbench_module": TESTBENCH_MODULE,
            "raw_width": int(getattr(build, "raw_width", 0) or 0),
            "executable_hash": _sha256_file(build.executable),
            "warnings": int(getattr(build, "warnings", 0) or 0),
            "sources": [str(item) for item in getattr(build, "sources", ()) or ()],
            "source_hashes": dict(getattr(build, "source_hashes", {}) or {}),
            "boot_image_policy": str(getattr(build, "boot_image_policy", "") or ""),
        },
        "tool": dict(tool) if tool is not None else tool_identity(build),
        "recorded_build_identity": recorded,
    }


def missing_identity(identity: Mapping[str, object]) -> tuple[str, ...]:
    """Required identity fields that are absent from one package identity."""
    missing: list[str] = []
    for name in REQUIRED_IDENTITY:
        value = identity.get(name)
        if value is None or value == "" or value == {} or value == () or value == []:
            missing.append(name)
    if "boot_image_hash" not in missing:
        # "none" is only a recorded absence when the build itself says no region
        # preloads an image; otherwise the image hash is required evidence.
        if (str(identity.get("boot_image_hash")) == "none"
                and str(identity.get("boot_image_policy")) != "no_preloaded_region"):
            missing.append("boot_image_hash")
    tool = identity.get("tool")
    if not isinstance(tool, Mapping) or not _is_sha256(tool.get("executable_hash")):
        if "tool" not in missing:
            missing.append("tool")
    return tuple(missing)


def identity_conflicts(identity: Mapping[str, object]) -> tuple[str, ...]:
    """Identity fields whose recorded value contradicts the build record.

    The plan/layout half is compared against the identity the build itself
    recorded in its generated testbench, and the constraint policy is compared
    against the same record.  A conflict means the package describes a different
    generation than the build, which is exactly the legacy-layout case step 6C
    requires to be refused instead of silently re-interpreted.
    """
    recorded = identity.get("recorded_build_identity")
    if not isinstance(recorded, Mapping):
        return ()
    conflicts: list[str] = []
    for name in ("plan_hash", "layout_hash"):
        saved = identity.get(name)
        if saved and recorded.get(name) and str(saved) != str(recorded[name]):
            conflicts.append(name)
    policy = identity.get("policy")
    if isinstance(policy, Mapping):
        for name, key in (("policy_layout_hash", "layout_hash"),
                          ("policy_plan_hash", "plan_hash")):
            saved = policy.get(key)
            if saved and recorded.get(key) and str(saved) != str(recorded[key]):
                conflicts.append(name)
    return tuple(conflicts)


# ---------------------------------------------------------------------------
# package
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EvidencePackage:
    """One anomaly's identity, saved inputs, results and boundary conclusion.

    ``samples`` and ``results`` are stored in their JSON document form so what
    :func:`write_evidence_package` writes and :func:`read_evidence_package`
    reads back is the same object that gets replayed; :meth:`sample` and
    :meth:`result` decode them without losing the raw words or the event plan.
    """

    schema_version: str
    kind: str
    identity: Mapping[str, object]
    samples: tuple[Mapping[str, object], ...]
    results: tuple[Mapping[str, object], ...]
    inputs_complete: bool
    criteria: tuple[Mapping[str, object], ...] = ()
    legality: Mapping[str, object] = field(default_factory=dict)
    attribution: Mapping[str, object] = field(default_factory=dict)
    anomaly: Mapping[str, object] = field(default_factory=dict)
    classification: tuple[str, str] = (UNDIAGNOSED, "unclassified")
    notes: tuple[str, ...] = ()

    def document(self) -> dict[str, object]:
        return {
            "schema_version": EVIDENCE_SCHEMA,
            "kind": self.kind,
            "identity": _json(self.identity),
            "inputs_complete": bool(self.inputs_complete),
            "samples": [_json(item) for item in self.samples],
            "results": [_json(item) for item in self.results],
            "criteria": [_json(item) for item in self.criteria],
            "legality": _json(self.legality),
            "attribution": _json(self.attribution),
            "anomaly": _json(self.anomaly),
            "classification": {
                "classification": str(self.classification[0]),
                "reason": str(self.classification[1]),
            },
            "notes": [str(item) for item in self.notes],
        }

    def sample(self, index: int = 0) -> RuntimeSample:
        """Reconstruct one saved sample, exactly as it was applied."""
        return _sample_from_document(self.samples[index])

    def result(self, index: int = 0) -> Mapping[str, object]:
        return self.results[index]


def _json(value: object) -> object:
    """Normalise a document to plain JSON types so round trips compare equal."""
    if isinstance(value, Mapping):
        return {str(key): _json(item) for key, item in value.items()}
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, (str, bool, int, float)) or value is None:
        return value
    if isinstance(value, Sequence):
        return [_json(item) for item in value]
    return str(value)


def _sample_document(sample: RuntimeSample) -> dict[str, object]:
    return {
        "request_id": int(sample.request_id),
        "raw": [int(value) for value in sample.raw],
        "events": [dict(event.document()) for event in sample.events],
        # The peer stimulus plan is part of the input: a replay that dropped it
        # would reproduce a run that never drove the peer models at all.
        "peer_events": [dict(event.document()) for event in sample.peer_events],
    }


def _sample_from_document(document: Mapping[str, object]) -> RuntimeSample:
    if not isinstance(document, Mapping) or "raw" not in document:
        _error("saved-sample-without-raw-input")
    raw = document.get("raw")
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        _error("saved-sample-raw-not-a-sequence")
    events = []
    for item in _records(document.get("events")):
        if isinstance(item, Mapping):
            events.append(ExternalEvent(slot=str(item.get("slot")),
                                        cycle=int(item.get("cycle", 0)),
                                        value=int(item.get("value", 0))))
    peer_events = []
    for item in _records(document.get("peer_events")):
        if isinstance(item, Mapping):
            peer_events.append(PeerStimulusEvent(slot=int(item.get("slot", 0)),
                                                 cycle=int(item.get("cycle", 0)),
                                                 payload=int(item.get("payload", 0))))
    return RuntimeSample(request_id=int(document.get("request_id", 0)),
                         raw=tuple(int(value) for value in raw),
                         events=tuple(sorted(events, key=lambda item: (item.cycle, item.slot))),
                         peer_events=tuple(sorted(peer_events,
                                                  key=lambda item: (item.cycle, item.slot))))


def _sample_payload(sample: Mapping[str, object]) -> str:
    """The exact stdin payload the saved raw input produced."""
    return _sample_from_document(sample).payload()


def _result_document(result: object) -> dict[str, object]:
    if isinstance(result, RunResult):
        document: dict[str, object] = dict(result.document())
    elif isinstance(result, Mapping):
        document = _json(result)  # type: ignore[assignment]
    else:
        _error(f"unsupported-run-result:{type(result).__name__}")
    document.setdefault("request_id", 0)
    document.setdefault("status", "unknown")
    document.setdefault("cycles", 0)
    document.setdefault("counters", {})
    document.setdefault("observations", {})
    document.setdefault("trace", [])
    document.setdefault("applied_trace", [])
    document.setdefault("peer_applied", [])
    return document


def _sample_from_result(document: Mapping[str, object]) -> dict[str, object]:
    """Rebuild the applied raw input from a run's own trace.

    The per-cycle trace carries the raw word that was applied, so a package can
    still be replayed when the caller did not hand over the original
    ``RuntimeSample`` -- but the *event plan* is not in the trace, so such a
    package is marked ``inputs_complete=False`` and :func:`replay_package`
    refuses it rather than replaying a different experiment.
    """
    trace = document.get("trace")
    raw = [int(entry.get("raw", 0)) for entry in _records(trace)
           if isinstance(entry, Mapping)]
    return {"request_id": int(document.get("request_id", 0)), "raw": raw, "events": []}


def _legality_document(legality: Mapping[str, object] | None) -> dict[str, object]:
    record: dict[str, object] = _json(legality or {})  # type: ignore[assignment]
    assert isinstance(record, dict)
    record.setdefault("environment_legality", LEGALITY_UNAVAILABLE)
    record.setdefault("driver_violations", [])
    record.setdefault("constraint_rejections", [])
    record.setdefault("monitor_results", [])
    notes = list(_records(record.get("notes")))
    if legality is None:
        notes.insert(0, "no legality record was supplied: the environment's "
                        "conformance to the interface contract is unverified")
    record["notes"] = [str(item) for item in notes]
    return record


def _anomaly_document(anomaly: Mapping[str, object] | None) -> dict[str, object]:
    record: dict[str, object] = _json(anomaly or {})  # type: ignore[assignment]
    assert isinstance(record, dict)
    record.setdefault("present", False)
    record.setdefault("kind", "")
    record.setdefault("criterion", "")
    record.setdefault("basis", "")
    record.setdefault("basis_independent", False)
    record.setdefault("reproducible", False)
    record.setdefault("expected", None)
    record.setdefault("observed", None)
    record.setdefault("first_divergence", None)
    return record


def build_evidence_package(plan: CompositionPlan, build: RuntimeBuild, policy: object,
                           results: Sequence[object], *, kind: str,
                           samples: Sequence[RuntimeSample] | None = None,
                           legality: Mapping[str, object] | None = None,
                           attribution: Mapping[str, object] | None = None,
                           criteria: Sequence[Mapping[str, object]] = (),
                           anomaly: Mapping[str, object] | None = None,
                           tool: Mapping[str, object] | None = None,
                           notes: Sequence[str] = ()) -> EvidencePackage:
    """Package one failure (or one clean run) with its identity and inputs.

    ``results`` are the ``RunResult`` objects of the run; ``samples`` are the raw
    inputs they were produced from.  When ``samples`` is omitted the raw words
    are recovered from each result's trace and the package records
    ``inputs_complete=False``, because the event plan is not in the trace and a
    replay of a guessed event plan would be a different experiment.

    ``legality``, ``criteria``, ``attribution`` and ``anomaly`` are the caller's
    evidence.  Omitting them is safe by construction: the resulting package is
    classified ``undiagnosed`` or ``observation_insufficient``, never
    ``component_candidate``.
    """
    if not isinstance(kind, str) or not kind:
        _error("evidence-kind-required")
    documents = tuple(_result_document(item) for item in results)
    if samples is None:
        saved = tuple(_sample_from_result(item) for item in documents)
        inputs_complete = False
        extra_notes = ["the saved raw words were recovered from the run trace; "
                       "the event plan was not supplied, so a replay is refused"]
    else:
        saved = tuple(_sample_document(item) for item in samples)
        inputs_complete = True
        extra_notes = []
        if len(saved) != len(documents):
            _error(f"sample-result-count-mismatch:{len(saved)}!={len(documents)}")
    for index, (sample, result) in enumerate(zip(saved, documents)):
        if int(sample["request_id"]) != int(result["request_id"]):
            _error(f"sample-result-request-mismatch:{index}:"
                   f"{sample['request_id']}!={result['request_id']}")
    package = EvidencePackage(
        schema_version=EVIDENCE_SCHEMA,
        kind=kind,
        identity=build_identity(plan, build, policy, tool=tool),
        samples=saved,
        results=documents,
        inputs_complete=inputs_complete,
        criteria=tuple(_json(item) for item in _records(criteria)),  # type: ignore[arg-type]
        legality=_legality_document(legality),
        attribution=_json(attribution or {}),  # type: ignore[arg-type]
        anomaly=_anomaly_document(anomaly),
        classification=(UNDIAGNOSED, "unclassified"),
        notes=tuple([str(item) for item in notes] + extra_notes),
    )
    return replace(package, classification=classify_boundary(package))


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------


def _observation_names(package: EvidencePackage) -> tuple[str, ...]:
    names: set[str] = set()
    for result in package.results:
        if not isinstance(result, Mapping):
            continue
        observations = result.get("observations")
        if isinstance(observations, Mapping):
            names.update(str(key) for key in observations)
    return tuple(sorted(names))


def _describe_divergence(anomaly: Mapping[str, object]) -> str:
    point = anomaly.get("first_divergence")
    if not isinstance(point, Mapping):
        return "the divergence point was not recorded"
    cycle = point.get("cycle")
    field = point.get("field")
    return f"first divergence cycle={cycle} field={field}"


def component_candidate_ready(package: EvidencePackage) -> tuple[bool, str]:
    """Whether the package supports a component-internal conclusion.

    Every prerequisite of ``### 1.10.3`` is checked here: complete identity
    (including a build whose layout/profile/firmware hashes are all present), a
    legality record that confirms the environment, a recorded criterion with an
    independent basis, a reproduced anomaly and at least one observation.  This
    is the single gate :func:`classify_boundary` uses for
    ``component_candidate``; it is public so the "never on incomplete evidence"
    property can be tested directly, branch by branch.
    """
    identity = package.identity if isinstance(package.identity, Mapping) else {}
    missing = missing_identity(identity)
    if missing:
        return False, "missing-identity:" + ",".join(missing)
    conflicts = identity_conflicts(identity)
    if conflicts:
        return False, "identity-conflict:" + ",".join(conflicts)
    legality = package.legality if isinstance(package.legality, Mapping) else {}
    absent = tuple(name for name in REQUIRED_LEGALITY if name not in legality)
    if absent:
        return False, "missing-legality-evidence:" + ",".join(absent)
    state = str(legality.get("environment_legality"))
    if state == LEGALITY_VIOLATED:
        return False, "environment-legality-violated"
    if state != LEGALITY_CONFIRMED:
        return False, f"environment-legality-{state or 'missing'}"
    if not _records(package.criteria):
        return False, "no-criterion-recorded"
    if not _observation_names(package):
        return False, "no-observation-recorded"
    anomaly = package.anomaly if isinstance(package.anomaly, Mapping) else {}
    if not anomaly.get("present"):
        return False, "no-anomaly-recorded"
    if not str(anomaly.get("criterion", "")) or not str(anomaly.get("basis", "")):
        return False, "anomaly-without-criterion-or-basis"
    if not anomaly.get("reproducible"):
        return False, "anomaly-not-reproduced"
    attribution = package.attribution if isinstance(package.attribution, Mapping) else {}
    if not anomaly.get("basis_independent") or attribution.get("self_consistency_only"):
        return False, ("profile-semantics-basis-missing: the criterion is not independent of "
                       "the profile that generated the stimulus and the checker")
    return True, ""


def classify_boundary(package: EvidencePackage) -> tuple[str, str]:
    """Classify where one anomaly's evidence points.

    Precedence, first match wins: missing identity, identity conflict, missing
    legality record, driver violation, profile finding, composition finding,
    software/model finding, insufficient observation, then the component gate.
    Anything the evidence does not settle is ``undiagnosed`` with the field that
    was missing, which is the plan's ``待诊断``/``未定位`` outcome.
    """
    if not isinstance(package, EvidencePackage):
        _error("evidence-package-required")
    identity = package.identity if isinstance(package.identity, Mapping) else {}
    missing = missing_identity(identity)
    if missing:
        return UNDIAGNOSED, "missing-identity:" + ",".join(missing)
    conflicts = identity_conflicts(identity)
    if conflicts:
        return UNDIAGNOSED, ("identity-conflict:" + ",".join(conflicts)
                             + ": the package describes a different generation than the build")
    legality = package.legality if isinstance(package.legality, Mapping) else {}
    absent = tuple(name for name in REQUIRED_LEGALITY if name not in legality)
    if absent:
        return UNDIAGNOSED, "missing-legality-evidence:" + ",".join(absent)
    state = str(legality.get("environment_legality"))
    if state not in (LEGALITY_CONFIRMED, LEGALITY_VIOLATED, LEGALITY_UNAVAILABLE):
        return UNDIAGNOSED, f"unknown-environment-legality:{state}"
    violations = _records(legality.get("driver_violations"))
    if state == LEGALITY_VIOLATED or violations:
        detail = "; ".join(str(item) for item in violations[:4]) or "legality state violated"
        return DRIVER_VIOLATION, (
            "the environment, not the DUT, broke the interface contract: " + detail)
    attribution = package.attribution if isinstance(package.attribution, Mapping) else {}
    for key, category, label in (
            ("profile_findings", PROFILE_DEFECT, "profile semantics"),
            ("composition_findings", COMPOSITION_DEFECT, "wiring/decode/adapter/controller"),
            ("software_or_model_findings", SOFTWARE_OR_MODEL_DEFECT, "software/model/checker")):
        findings = _records(attribution.get(key))
        if findings:
            detail = "; ".join(str(item) for item in findings[:4])
            return category, f"{label} evidence: {detail}"
    if not _records(package.criteria):
        return OBSERVATION_INSUFFICIENT, (
            "no criterion was recorded: without a specification, assertion or reference "
            "model there is nothing a DUT could violate")
    if not _observation_names(package):
        return OBSERVATION_INSUFFICIENT, (
            "the runs recorded no observation, so no behaviour was judged")
    anomaly = package.anomaly if isinstance(package.anomaly, Mapping) else {}
    if not anomaly.get("present"):
        return UNDIAGNOSED, "no-anomaly-recorded: this package documents a run, not a failure"
    if not str(anomaly.get("criterion", "")) or not str(anomaly.get("basis", "")):
        return OBSERVATION_INSUFFICIENT, (
            "the anomaly names no criterion or no basis for it: " + _describe_divergence(anomaly))
    if not anomaly.get("reproducible"):
        return UNDIAGNOSED, ("anomaly-not-reproduced: the recorded anomaly did not reproduce "
                             "on the saved input; " + _describe_divergence(anomaly))
    ready, reason = component_candidate_ready(package)
    if not ready:
        return UNDIAGNOSED, reason
    criterion = str(anomaly.get("criterion"))
    basis = str(anomaly.get("basis"))
    return COMPONENT_CANDIDATE, (
        f"complete identity, confirmed environment legality, {_describe_divergence(anomaly)}, "
        f"criterion {criterion!r} with independent basis {basis!r}")


# ---------------------------------------------------------------------------
# write / read
# ---------------------------------------------------------------------------


def write_evidence_package(package: EvidencePackage, directory: object) -> Path:
    """Write the package, its byte-exact raw inputs and its applied trace.

    Returns the path of the main ``evidence_package.json`` document.  The raw
    inputs are written as the exact stdin payload ``run_sample`` consumed, so the
    saved input can be handed back to the same executable byte for byte.
    """
    if not isinstance(package, EvidencePackage):
        _error("evidence-package-required")
    target = Path(str(directory))
    raw_dir = target / RAW_INPUT_DIRECTORY
    raw_dir.mkdir(parents=True, exist_ok=True)
    # A rewritten package must not keep stdin files of samples it no longer has.
    for stale in sorted(raw_dir.glob("*.stdin")):
        stale.unlink()
    index: list[dict[str, object]] = []
    applied: list[dict[str, object]] = []
    for position, sample in enumerate(package.samples):
        payload = _sample_payload(sample).encode("utf-8")
        name = f"sample-{position:04d}-{int(sample.get('request_id', 0)):08x}.stdin"
        (raw_dir / name).write_bytes(payload)
        index.append({
            "position": position,
            "request_id": int(sample.get("request_id", 0)),
            "file": f"{RAW_INPUT_DIRECTORY}/{name}",
            "bytes": len(payload),
            "sha256": _sha256_bytes(payload),
            "raw_words": len(sample.get("raw", ())),
            "events": len(sample.get("events", ())),
            "peer_events": len(sample.get("peer_events", ())),
        })
        result = package.results[position] if position < len(package.results) else {}
        applied.append({
            "position": position,
            "request_id": int(sample.get("request_id", 0)),
            "status": str(result.get("status", "unknown")),
            "cycles": int(result.get("cycles", 0)),
            "trace": _json(result.get("trace", [])),
            "applied_trace": _json(result.get("applied_trace", [])),
        })
    (target / RAW_INPUT_INDEX).write_bytes(canonical_bytes({
        "schema_version": EVIDENCE_SCHEMA,
        "kind": package.kind,
        "samples": index,
    }))
    (target / APPLIED_TRACE_DOCUMENT).write_bytes(canonical_bytes({
        "schema_version": EVIDENCE_SCHEMA,
        "kind": package.kind,
        "samples": applied,
    }))
    document_path = target / EVIDENCE_DOCUMENT
    document_path.write_bytes(canonical_bytes(package.document()))
    return document_path


def read_evidence_package(directory: object) -> EvidencePackage:
    """Read a package back and verify its raw-input archive against it."""
    target = Path(str(directory))
    path = target / EVIDENCE_DOCUMENT
    if not path.is_file():
        _error(f"evidence-package-missing:{path}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as error:
        _error(f"evidence-package-unreadable:{path}:{error}")
    if not isinstance(document, Mapping):
        _error(f"evidence-package-not-an-object:{path}")
    if str(document.get("schema_version")) != EVIDENCE_SCHEMA:
        _error(f"evidence-schema-mismatch:{document.get('schema_version')}")
    package = _package_from_document(document)
    _verify_raw_inputs(package, target)
    # Recompute rather than trust the stored value: a package whose stored
    # classification was edited must not be able to claim a stronger conclusion.
    return replace(package, classification=classify_boundary(package))


def _package_from_document(document: Mapping[str, object]) -> EvidencePackage:
    for name in ("kind", "identity", "samples", "results", "inputs_complete"):
        if name not in document:
            _error(f"evidence-field-missing:{name}")
    identity = document["identity"]
    if not isinstance(identity, Mapping):
        _error("evidence-identity-not-an-object")
    samples = document["samples"]
    results = document["results"]
    if not isinstance(samples, Sequence) or isinstance(samples, (str, bytes)):
        _error("evidence-samples-not-a-sequence")
    if not isinstance(results, Sequence) or isinstance(results, (str, bytes)):
        _error("evidence-results-not-a-sequence")
    if len(samples) != len(results):
        _error(f"evidence-sample-result-count-mismatch:{len(samples)}!={len(results)}")
    for sample in samples:
        _sample_from_document(sample)  # validates raw/events
    classification = document.get("classification") or {}
    if isinstance(classification, Mapping):
        stored = (str(classification.get("classification", UNDIAGNOSED)),
                  str(classification.get("reason", "")))
    else:
        stored = (UNDIAGNOSED, "unclassified")
    return EvidencePackage(
        schema_version=EVIDENCE_SCHEMA,
        kind=str(document["kind"]),
        identity=dict(identity),
        samples=tuple(dict(item) for item in samples),
        results=tuple(dict(item) for item in results),
        inputs_complete=bool(document["inputs_complete"]),
        criteria=tuple(dict(item) for item in _records(document.get("criteria"))
                       if isinstance(item, Mapping)),
        legality=dict(document.get("legality") or {}),
        attribution=dict(document.get("attribution") or {}),
        anomaly=dict(document.get("anomaly") or {}),
        classification=stored,
        notes=tuple(str(item) for item in _records(document.get("notes"))),
    )


def _verify_raw_inputs(package: EvidencePackage, directory: Path) -> None:
    index_path = directory / RAW_INPUT_INDEX
    if not index_path.is_file():
        _error(f"raw-input-index-missing:{index_path}")
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except ValueError as error:
        _error(f"raw-input-index-unreadable:{index_path}:{error}")
    entries = index.get("samples") if isinstance(index, Mapping) else None
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
        _error(f"raw-input-index-without-samples:{index_path}")
    if len(entries) != len(package.samples):
        _error(f"raw-input-count-mismatch:{len(entries)}!={len(package.samples)}")
    for position, (entry, sample) in enumerate(zip(entries, package.samples)):
        if not isinstance(entry, Mapping):
            _error(f"raw-input-entry-not-an-object:{position}")
        path = directory / str(entry.get("file", ""))
        if not path.is_file():
            _error(f"raw-input-file-missing:{path}")
        payload = path.read_bytes()
        if _sha256_bytes(payload) != str(entry.get("sha256")):
            _error(f"raw-input-file-tampered:{path}")
        expected = _sample_payload(sample).encode("utf-8")
        if payload != expected:
            _error(f"raw-input-document-mismatch:{path}: "
                   "the package document and its raw-input archive disagree")


# ---------------------------------------------------------------------------
# replay
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ReplayResult:
    """The outcome of re-running a package's saved inputs on a build."""

    status: str
    reason: str
    checked_fields: tuple[str, ...] = ()
    matching_fields: tuple[str, ...] = ()
    mismatching_fields: tuple[str, ...] = ()
    divergence: Mapping[str, object] | None = None
    reruns: tuple[Mapping[str, object], ...] = ()

    def document(self) -> dict[str, object]:
        return {
            "schema_version": EVIDENCE_SCHEMA,
            "status": self.status,
            "reason": self.reason,
            "checked_fields": list(self.checked_fields),
            "matching_fields": list(self.matching_fields),
            "mismatching_fields": list(self.mismatching_fields),
            "divergence": None if self.divergence is None else _json(self.divergence),
            "reruns": [_json(item) for item in self.reruns],
        }

    @property
    def agreed(self) -> bool:
        return self.status == REPLAY_AGREEMENT


def identity_mismatches(package: EvidencePackage, build: RuntimeBuild) -> tuple[str, ...]:
    """Saved-identity fields that do not describe this build.

    Every field is recomputed from the build directory (top and testbench
    content, boot image bytes, executable bytes) or read from the build's own
    recorded identity, so a legacy package is refused instead of being replayed
    against a build it was not produced by.
    """
    identity = package.identity if isinstance(package.identity, Mapping) else {}
    problems: list[str] = []
    try:
        recorded = recorded_build_identity(build)
    except SocFailureEvidenceError as error:
        return (f"build-record:{error}",)
    boot_image = getattr(build, "boot_image", None)
    expected = {
        "plan_hash": recorded["plan_hash"],
        "layout_hash": recorded["layout_hash"],
        "build_hash": str(getattr(build, "build_hash", "") or ""),
        "testbench_hash": _sha256_file(build.testbench_path),
        "rendered_top_hash": _sha256_file(build.top_path),
        "boot_image_hash": "none" if boot_image is None else _sha256_file(boot_image),
    }
    for name, actual in expected.items():
        saved = identity.get(name)
        if saved and str(saved) != actual:
            problems.append(f"{name}:saved={saved}:build={actual}")
    runtime = identity.get("runtime")
    if isinstance(runtime, Mapping):
        saved_executable = runtime.get("executable_hash")
        actual_executable = _sha256_file(build.executable)
        if saved_executable and str(saved_executable) != actual_executable:
            problems.append(f"runtime.executable_hash:saved={saved_executable}:"
                            f"build={actual_executable}")
    return tuple(problems)


def _applied_fields(document: Mapping[str, object]) -> dict[str, object]:
    fields: dict[str, object] = {}
    for entry in _records(document.get("applied_trace")):
        if not isinstance(entry, Mapping):
            continue
        cycle = int(entry.get("cycle", 0))
        port = str(entry.get("port", ""))
        fields[f"applied[{cycle}].{port}"] = entry.get("value")
    return fields


def _comparison_fields(document: Mapping[str, object]) -> dict[str, object]:
    """The compared field set of one run, in reporting order.

    Order inside a cycle is the applied raw input first, then the driven values
    it produced: the saved input is the thing a replay is a replay *of*, so a
    mutated word is reported as ``trace[<cycle>].raw`` rather than as one of its
    derived port values.
    """
    fields: dict[str, object] = {}
    trace = document.get("trace")
    cycles: dict[int, dict[str, object]] = {}
    for entry in _records(trace):
        if not isinstance(entry, Mapping):
            continue
        cycle = int(entry.get("cycle", 0))
        cycles.setdefault(cycle, {}).update(
            {str(name): value for name, value in entry.items() if name != "cycle"})
    for cycle in sorted(cycles):
        entry = cycles[cycle]
        names = sorted(name for name in entry if name != "raw")
        for name in ["raw", *names]:
            if name in entry:
                fields[f"trace[{cycle}].{name}"] = entry[name]
    fields.update(_applied_fields(document))
    for entry in _records(document.get("peer_applied")):
        if not isinstance(entry, Mapping):
            continue
        cycle = int(entry.get("cycle", 0))
        instance = str(entry.get("instance", ""))
        slot = str(entry.get("slot", ""))
        prefix = f"peer_applied[{cycle}].{instance}.{slot}"
        for name in ("cycle", "instance", "slot", "value"):
            if name in entry:
                fields[f"{prefix}.{name}"] = entry[name]
    for entry in _records(document.get("peer_wire_trace")):
        if not isinstance(entry, Mapping):
            continue
        cycle = int(entry.get("cycle", 0))
        instance = str(entry.get("instance_id", ""))
        for name in ("sck", "cs", "mosi", "miso"):
            fields[f"peer_wire[{cycle}].{instance}.{name}"] = entry.get(name)
    for index, entry in enumerate(_records(document.get("fabric_requests"))):
        if not isinstance(entry, Mapping):
            continue
        address = int(entry.get("addr", 0))
        for name in ("cycle", "addr", "write", "wdata", "be", "source"):
            fields[f"fabric_request[{index}].0x{address:x}.{name}"] = entry.get(name)
    for entry in _records(document.get("peer_wire_status")):
        if not isinstance(entry, Mapping):
            continue
        instance = str(entry.get("instance_id", ""))
        fields[f"peer_wire_status:{instance}:count"] = entry.get("count")
        fields[f"peer_wire_status:{instance}:truncated"] = entry.get("truncated")
    fields["fabric_requests_truncated"] = document.get("fabric_requests_truncated")
    # The pre-release image placement is part of what the harness *did* to the
    # DUT, so a replay that places a different word (or places it at a different
    # address, or refuses an address the saved run accepted) is a divergence like
    # any other.  Without this the two runs would compare equal while the CPU
    # fetched a different program.
    for entry in _records(document.get("image_placements")):
        if not isinstance(entry, Mapping):
            continue
        slot = str(entry.get("slot", ""))
        kind = str(entry.get("kind", ""))
        prefix = f"image_placement[{kind}].{slot}"
        for name in ("addr", "readback", "reset_held"):
            fields[f"{prefix}.{name}"] = entry.get(name)
    for index, entry in enumerate(_records(document.get("image_errors"))):
        if not isinstance(entry, Mapping):
            continue
        fields[f"image_error[{index}].{entry.get('slot', '')}"] = entry.get("reason")
    observations = document.get("observations")
    if isinstance(observations, Mapping):
        for name in sorted(str(key) for key in observations):
            fields[f"observation:{name}"] = observations[name]
    counters = document.get("counters")
    if isinstance(counters, Mapping):
        for name in sorted(str(key) for key in counters):
            fields[f"counter:{name}"] = counters[name]
    peer_oracle = document.get("peer_oracle")
    if isinstance(peer_oracle, Mapping):
        # Compare the independent peer evidence as a single content-addressed
        # record plus its status.  The full checks remain in the package; the
        # hash makes replay detect any altered check without flattening all
        # diagnostic prose into the boundary field namespace.
        if "oracle_hash" in peer_oracle:
            fields["peer_oracle:hash"] = peer_oracle["oracle_hash"]
        if "status" in peer_oracle:
            fields["peer_oracle:status"] = peer_oracle["status"]
    fields["status"] = str(document.get("status", "unknown"))
    fields["cycles"] = int(document.get("cycles", 0))
    return fields


def replay_package(package: EvidencePackage, build: RuntimeBuild, *,
                   timeout_seconds: int = 600) -> ReplayResult:
    """Re-run the saved raw inputs and report agreement field by field.

    The package is refused when its identity does not describe ``build`` or when
    its inputs are incomplete.  Otherwise every saved sample is re-run through
    ``run_sample`` and the applied stimulus, peer applications, observations, counters and
    the status are compared; the first difference is reported with its cycle and
    field name (or the field name alone for a final-value difference).
    """
    if not isinstance(package, EvidencePackage):
        _error("evidence-package-required")
    mismatches = identity_mismatches(package, build)
    if mismatches:
        return ReplayResult(
            status=REPLAY_REFUSED,
            reason=("refused: the package identity does not describe this build: "
                    + "; ".join(mismatches)),
            mismatching_fields=mismatches)
    if not package.inputs_complete:
        return ReplayResult(
            status=REPLAY_REFUSED,
            reason=("refused: the saved event plan is unknown, so replaying would be a "
                    "different experiment"))
    saved_samples = [package.sample(index) for index in range(len(package.samples))]
    reruns = tuple(run_sample(build, item, timeout_seconds=timeout_seconds)
                   for item in saved_samples)
    return compare_replay_results(package.results, reruns)


def compare_replay_results(saved_results: Sequence[Mapping[str, object]],
                           reruns: Sequence[RunResult]) -> ReplayResult:
    """Compare already-executed runs with the shared replay field schema.

    This checks behavioral agreement only; callers bind inputs/build identity
    and execute the runs themselves. No executable identity is inferred here.
    """
    if len(saved_results) != len(reruns):
        return ReplayResult(status=REPLAY_REFUSED, reason="replay-result-count-mismatch",
                            mismatching_fields=("result-count",))
    matching: list[str] = []
    mismatching: list[str] = []
    checked: list[str] = []
    divergence: Mapping[str, object] | None = None
    prefix = "sample0:" if len(saved_results) > 1 else ""
    for index, (before, after) in enumerate(zip(saved_results, reruns)):
        if index:
            prefix = f"sample{index}:"
        expected = _comparison_fields(before)
        observed = _comparison_fields(_result_document(after))
        for name in list(expected) + [item for item in observed if item not in expected]:
            label = prefix + name
            if label not in checked:
                checked.append(label)
            left = expected.get(name)
            right = observed.get(name)
            if left == right:
                matching.append(label)
                continue
            mismatching.append(label)
            if divergence is None:
                cycle, field = _field_location(name)
                divergence = {
                    "sample": index,
                    "request_id": int(before.get("request_id", 0)),
                    "cycle": cycle,
                    "field": field,
                    "label": label,
                    "expected": left,
                    "observed": right,
                    "kind": _field_kind(name),
                }
    if divergence is None:
        return ReplayResult(
            status=REPLAY_AGREEMENT,
            reason=(f"{len(reruns)} saved sample(s) replayed with identical applied stimulus "
                    f"and observations ({len(checked)} field(s) compared)"),
            checked_fields=tuple(checked), matching_fields=tuple(matching),
            mismatching_fields=(),
            reruns=tuple(_result_document(item) for item in reruns))
    return ReplayResult(
        status=REPLAY_DIVERGENCE,
        reason=(f"{len(mismatching)} field(s) diverged; first at cycle "
                f"{divergence['cycle']} field {divergence['field']!r} "
                f"({divergence['label']}): saved={divergence['expected']!r} "
                f"replayed={divergence['observed']!r}"),
        checked_fields=tuple(checked), matching_fields=tuple(matching),
        mismatching_fields=tuple(mismatching), divergence=divergence,
        reruns=tuple(_result_document(item) for item in reruns))


def _field_location(name: str) -> tuple[int | None, str]:
    if name.startswith("trace[") and "]." in name:
        cycle, _, field = name[len("trace["):].partition("].")
        try:
            return int(cycle), field
        except ValueError:
            return None, name
    if name.startswith("applied[") and "]." in name:
        cycle, _, field = name[len("applied["):].partition("].")
        try:
            return int(cycle), field
        except ValueError:
            return None, name
    if name.startswith("peer_applied[") and "]." in name:
        cycle, _, field = name[len("peer_applied["):].partition("].")
        try:
            return int(cycle), field
        except ValueError:
            return None, name
    if name.startswith("peer_wire[") and "]." in name:
        cycle, _, field = name[len("peer_wire["):].partition("].")
        try:
            return int(cycle), field
        except ValueError:
            return None, name
    return None, name


def _field_kind(name: str) -> str:
    if name.startswith("trace["):
        return "applied-stimulus"
    if name.startswith("applied["):
        return "applied-port-value"
    if name.startswith("peer_applied["):
        return "applied-peer-event"
    if name.startswith("peer_wire[") or name.startswith("peer_wire_status:"):
        return "observed-peer-wire"
    if name.startswith("fabric_request[") or name == "fabric_requests_truncated":
        return "observed-fabric-request"
    if name.startswith("observation:"):
        return "observation"
    if name.startswith("counter:"):
        return "counter"
    return "status"


# ---------------------------------------------------------------------------
# minimisation
# ---------------------------------------------------------------------------


def _callable_name(predicate: Callable[[RunResult], bool]) -> str:
    name = getattr(predicate, "__qualname__", None) or getattr(predicate, "__name__", None)
    return str(name) if name else repr(predicate)


def _payload_hash(raw: Sequence[int], request_id: int, events: int,
                  peer_events: int = 0) -> str:
    payload = {"request_id": int(request_id), "raw": [int(value) for value in raw],
               "events": int(events), "peer_events": int(peer_events)}
    return "sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest()


def minimize_sample(build: RuntimeBuild, sample: RuntimeSample, *,
                    predicate: Callable[[RunResult], bool],
                    budget: int = DEFAULT_MINIMIZE_BUDGET,
                    timeout_seconds: int = 600) -> tuple[RuntimeSample, dict[str, object]]:
    """Shrink the raw input while the caller's predicate still holds.

    Delta debugging: contiguous chunks of raw words are dropped, coarse first,
    and once no chunk can be dropped each remaining word is tried for zeroing.
    Every candidate is a real ``run_sample`` on ``build``; the predicate is the
    caller's definition of "the same failure nature", so a reduction is accepted
    only when that nature survives.  ``budget`` bounds the number of search
    candidates (the original check and the final verification always run) and the
    returned record states whether the search stopped at a fixed point or on the
    budget, with the hash and outcome digest of every candidate it tried.

    The returned sample is verified against the predicate once more before it is
    handed back.  A predicate that is not stable (one that stops holding between
    two runs of the same input) is reported with ``preserved=False`` instead of
    being presented as a reduced witness it is not.
    """
    if not isinstance(sample, RuntimeSample):
        _error("runtime-sample-required")
    if not callable(predicate):
        _error("minimize-requires-a-callable-predicate")
    if isinstance(budget, bool) or not isinstance(budget, int) \
            or budget < 1 or budget > MAX_MINIMIZE_BUDGET:
        _error(f"minimize-budget-out-of-bounds:{budget}")

    steps = 0
    candidates = 0
    accepted = 0
    rejected = 0
    history: list[dict[str, object]] = []

    def evaluate(raw: tuple[int, ...], *, candidate: bool) -> tuple[bool, RunResult]:
        nonlocal steps, candidates
        steps += 1
        if candidate:
            candidates += 1
        result = run_sample(build, RuntimeSample(request_id=sample.request_id, raw=raw,
                                                 events=sample.events,
                                                 peer_events=sample.peer_events),
                            timeout_seconds=timeout_seconds)
        held = bool(predicate(result))
        if len(history) < MAX_MINIMIZE_HISTORY:
            history.append({
                "step": steps,
                "words": len(raw),
                "holds": held,
                "raw_sha256": _payload_hash(raw, sample.request_id, len(sample.events),
                                              len(sample.peer_events)),
                "status": result.status,
                "cycles": result.cycles,
                "observation_digest": "sha256:" + hashlib.sha256(canonical_bytes(
                    {str(key): int(value)
                     for key, value in sorted(result.observations.items())})).hexdigest(),
            })
        return held, result

    original = tuple(int(value) for value in sample.raw)
    held, _ = evaluate(original, candidate=False)
    if not held:
        return sample, {
            "schema_version": EVIDENCE_SCHEMA,
            "predicate": _callable_name(predicate),
            "stopped": "predicate-false-on-original",
            "preserved": False,
            "budget": budget,
            "steps": steps,
            "candidates": candidates,
            "accepted": accepted,
            "rejected": rejected,
            "original": {"words": len(original),
                         "sha256": _payload_hash(original, sample.request_id,
                                                 len(sample.events),
                                                 len(sample.peer_events))},
            "minimal": {"words": len(original),
                        "sha256": _payload_hash(original, sample.request_id,
                                                len(sample.events),
                                                len(sample.peer_events))},
            "removed_words": 0,
            "zeroed_words": 0,
            "events_preserved": len(sample.events),
            "continuity": ("the original sample does not satisfy the predicate, so nothing "
                           "was reduced and nothing is claimed to be preserved"),
            "history": history,
        }

    current = list(original)
    stopped = "fixed_point"
    granularity = 2
    while len(current) >= 2:
        if candidates >= budget:
            stopped = "budget"
            break
        chunk = max(1, -(-len(current) // granularity))
        reduced = False
        for start in range(0, len(current), chunk):
            if candidates >= budget:
                stopped = "budget"
                break
            candidate = current[:start] + current[start + chunk:]
            if not candidate:
                # A sample may not be empty; an empty raw input is not a replay
                # of this experiment, it is a different request.
                continue
            held, _ = evaluate(tuple(candidate), candidate=True)
            if held:
                current = candidate
                accepted += 1
                granularity = max(2, granularity - 1)
                reduced = True
                break
            rejected += 1
        if stopped == "budget":
            break
        if reduced:
            continue
        if granularity >= len(current):
            stopped = "fixed_point"
            break
        granularity = min(len(current), granularity * 2)

    zeroed = 0
    if stopped != "budget":
        for index in range(len(current)):
            if candidates >= budget:
                stopped = "budget"
                break
            if current[index] == 0:
                continue
            candidate = list(current)
            candidate[index] = 0
            held, _ = evaluate(tuple(candidate), candidate=True)
            if held:
                current = candidate
                zeroed += 1
                accepted += 1
            else:
                rejected += 1

    minimal = RuntimeSample(request_id=sample.request_id, raw=tuple(current),
                            events=sample.events, peer_events=sample.peer_events)
    final_held, final_result = evaluate(tuple(current), candidate=False)
    record: dict[str, object] = {
        "schema_version": EVIDENCE_SCHEMA,
        "predicate": _callable_name(predicate),
        "stopped": stopped,
        "preserved": bool(final_held),
        "budget": budget,
        "steps": steps,
        "candidates": candidates,
        "accepted": accepted,
        "rejected": rejected,
        "original": {"words": len(original),
                     "sha256": _payload_hash(original, sample.request_id,
                                             len(sample.events), len(sample.peer_events))},
        "minimal": {"words": len(current),
                    "sha256": _payload_hash(current, sample.request_id,
                                            len(sample.events), len(sample.peer_events))},
        "removed_words": len(original) - len(current),
        "zeroed_words": zeroed,
        "events_preserved": len(sample.events),
        "final_replay": {
            "status": final_result.status,
            "cycles": final_result.cycles,
            "observations": {str(key): int(value)
                             for key, value in sorted(final_result.observations.items())},
        },
        "continuity": ("every accepted candidate re-ran the real build and satisfied the same "
                       "predicate, so the recorded failure nature is the one that was shrunk; "
                       "the original check and the final verification are outside the search "
                       "budget"),
        "history": history,
        "history_truncated": steps > len(history),
    }
    return minimal, record


__all__ = [
    "APPLIED_TRACE_DOCUMENT",
    "BOUNDARY_CLASSES",
    "COMPONENT_CANDIDATE",
    "COMPOSITION_DEFECT",
    "DEFAULT_MINIMIZE_BUDGET",
    "DRIVER_VIOLATION",
    "EVIDENCE_DOCUMENT",
    "EVIDENCE_SCHEMA",
    "LEGALITY_CONFIRMED",
    "LEGALITY_UNAVAILABLE",
    "LEGALITY_VIOLATED",
    "MAX_MINIMIZE_BUDGET",
    "MAX_MINIMIZE_HISTORY",
    "OBSERVATION_INSUFFICIENT",
    "PROFILE_DEFECT",
    "RAW_INPUT_DIRECTORY",
    "RAW_INPUT_INDEX",
    "REPLAY_AGREEMENT",
    "REPLAY_DIVERGENCE",
    "REPLAY_REFUSED",
    "REQUIRED_IDENTITY",
    "REQUIRED_LEGALITY",
    "SOFTWARE_OR_MODEL_DEFECT",
    "UNDIAGNOSED",
    "EvidencePackage",
    "ReplayResult",
    "SocFailureEvidenceError",
    "build_evidence_package",
    "build_identity",
    "classify_boundary",
    "compare_replay_results",
    "component_candidate_ready",
    "identity_conflicts",
    "identity_mismatches",
    "isa_identity",
    "minimize_sample",
    "missing_identity",
    "policy_rule_list",
    "profile_identities",
    "read_evidence_package",
    "recorded_build_identity",
    "replay_package",
    "tool_identity",
    "write_evidence_package",
]
