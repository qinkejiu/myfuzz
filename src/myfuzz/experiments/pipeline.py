"""Pure fixture-to-experiment runtime preparation."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from myfuzz.contracts import validate_contract
from myfuzz.harness import HarnessBundle, compile_harness_bundle
from myfuzz.protocols import load_builtin_protocol

from .planner import ExperimentPlan, plan_experiment
from .rfuzz_adapter import RfuzzAdapter, RfuzzAvailability


@dataclass(frozen=True, slots=True)
class PreparedCandidateRuntime:
    harness_bundle: HarnessBundle
    experiment_plan: ExperimentPlan
    manifest_fragment: dict[str, object]
    rfuzz_availability: RfuzzAvailability


def _declared_protocols(bindings: object):
    if not isinstance(bindings, Sequence) or isinstance(
        bindings,
        (str, bytes, bytearray),
    ):
        raise ValueError("composition_ir.endpoint_bindings must be an array")
    identities: set[tuple[str, str]] = set()
    for index, binding in enumerate(bindings):
        if not isinstance(binding, Mapping):
            raise ValueError(f"composition_ir.endpoint_bindings[{index}] must be an object")
        protocol_id = binding.get("protocol_id")
        version = binding.get("version")
        if not isinstance(protocol_id, str) or not protocol_id:
            raise ValueError(
                f"composition_ir.endpoint_bindings[{index}].protocol_id must be explicit"
            )
        if not isinstance(version, str) or not version:
            raise ValueError(
                f"composition_ir.endpoint_bindings[{index}].version must be explicit"
            )
        identities.add((protocol_id, version))
    return {
        f"{protocol_id}@{version}": load_builtin_protocol(protocol_id, version)
        for protocol_id, version in sorted(identities)
    }


def prepare_candidate_runtime(
    hdl_facts: object,
    composition_ir: object,
    candidate_manifest: object,
    experiment_config: object,
    repo_root: Path,
) -> PreparedCandidateRuntime:
    """Prepare deterministic runtime data without launching or writing anything."""
    validate_contract(hdl_facts, "hdl_facts.v2")
    validate_contract(composition_ir, "composition_ir.v1")
    validate_contract(candidate_manifest, "candidate_manifest.v1")
    if not isinstance(composition_ir, Mapping):
        raise ValueError("composition_ir must be an object")
    bindings = composition_ir.get("endpoint_bindings")
    protocols = _declared_protocols(bindings)
    bundle = compile_harness_bundle(hdl_facts, composition_ir, candidate_manifest, protocols)
    fragment = bundle.manifest_fragment()
    if not isinstance(candidate_manifest, Mapping):
        raise ValueError("candidate_manifest must be an object")
    runtime_manifest = dict(candidate_manifest)
    runtime_manifest.update(fragment)
    plan = plan_experiment(experiment_config, [runtime_manifest])
    availability = RfuzzAdapter(repo_root).availability()
    return PreparedCandidateRuntime(bundle, plan, fragment, availability)
