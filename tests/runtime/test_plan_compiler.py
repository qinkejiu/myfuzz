"""G4: same-pass static execution-plan compilation.

Software only.  A passing test proves that one real ``PreparationContext``
derives one canonical static plan covering both requested flows; it starts no
RTL, issues no native token and proves no executed effect.

Every negative below asserts the machine code *and* the JSON pointer, because a
refusal without a pointer cannot be audited.
"""
from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from myfuzz.runtime.admission import verify_component
from myfuzz.runtime.compiler import (
    CPU_SEMANTIC_KIND,
    PLAN_MEMORY_SCHEMA,
    PLAN_SCHEDULING_SCHEMA,
    PLAN_TERMINATION_SCHEMA,
    STORAGE_SEMANTIC_KIND,
    SUPPORTED_FLOWS,
    assert_plan_content,
    compile_execution_plan,
    load_execution_plan_document,
    plan_bindings,
    requirement_for_binding,
    verify_execution_plan,
)
from myfuzz.runtime.contracts import (
    PLAN_SCHEMA,
    PLAN_TOP_LEVEL,
    AdapterSelection,
    CapabilityRequirement,
    GenericExecutionPlan,
    GenericRuntimeRefused,
    VerifiedComponent,
    canonical_json_bytes,
)
from myfuzz.runtime.preparation import PreparationContext, create_preparation
from myfuzz.runtime.registry import CPU_ADAPTER_ID, STORAGE_ADAPTER_ID, select_adapter
from myfuzz.scenario.compiled_paths import compiled_document_sha256

ROOT = Path(__file__).resolve().parents[2]
TIMER = ROOT / "configs/scenarios/compiled-f4-obi-apb-timer"

_DIGEST = "0" * 64


def _create_preparation(tmp_path_factory, label: str):
    output = tmp_path_factory.mktemp(label)
    return create_preparation(
        base_dir=ROOT,
        compose_path=TIMER / "compose.json",
        capability_paths=(TIMER / "test_capability.json",),
        supplement_path=TIMER / "execution_supplement.json",
        generated_dir=output / "generated",
        flow_ids=("F2", "F4"),
    )


@pytest.fixture(scope="module")
def timer_preparation(tmp_path_factory):
    context = _create_preparation(tmp_path_factory, "g4-plan-a")
    yield context
    context.close()


@pytest.fixture(scope="module")
def second_preparation(tmp_path_factory):
    context = _create_preparation(tmp_path_factory, "g4-plan-b")
    yield context
    context.close()


def compile_from_context(context):
    """The explicit prepare sequence: verify -> derive -> select -> compile."""
    components = tuple(
        verify_component(context.artifact(instance_id), preparation=context,
                         base_dir=ROOT)
        for instance_id in sorted(context.artifacts))
    bindings = plan_bindings(context)
    component_by_instance = {component.instance_id: component
                             for component in components}
    requirements = tuple(
        requirement_for_binding(component_by_instance[binding.instance_id],
                                binding)
        for binding in bindings)
    selections = tuple(
        select_adapter(component_by_instance[binding.instance_id],
                       requirement, preparation=context)
        for binding, requirement in zip(bindings, requirements))
    plan = compile_execution_plan(
        context, components=components, selections=selections,
        requirements=requirements)
    return SimpleNamespace(context=context, components=components,
                           bindings=bindings, requirements=requirements,
                           selections=selections, plan=plan)


@pytest.fixture(scope="module")
def timer_plan(timer_preparation):
    return compile_from_context(timer_preparation)


@pytest.fixture(scope="module")
def second_plan(second_preparation):
    return compile_from_context(second_preparation)


def _target_binding(planning):
    return next(binding for binding in planning.bindings
                if binding.role == "target")


def _cpu_binding(planning):
    return next(binding for binding in planning.bindings
                if binding.role == "cpu")


def _requirement(planning, endpoint_id: str) -> CapabilityRequirement:
    return next(requirement for requirement in planning.requirements
                if requirement.endpoint_id == endpoint_id)


def _replace_requirement(planning, endpoint_id: str,
                         replacement: CapabilityRequirement):
    return tuple(replacement if requirement.endpoint_id == endpoint_id
                 else requirement for requirement in planning.requirements)


def _refusal(callable_):
    with pytest.raises(GenericRuntimeRefused) as caught:
        callable_()
    error = caught.value
    assert type(error.code) is str and error.code
    assert type(error.pointer) is str
    return error


# ---------------------------------------------------------------------------
# positive: one preparation, both flows
# ---------------------------------------------------------------------------

def test_plan_has_the_fixed_top_level_shape(timer_plan):
    document = timer_plan.plan.document()
    assert tuple(sorted(document)) == tuple(sorted(PLAN_TOP_LEVEL))
    assert document["schema_version"] == PLAN_SCHEMA
    assert timer_plan.plan.document_bytes == canonical_json_bytes(document)
    assert timer_plan.plan.identity_sha256 == sha256(
        timer_plan.plan.document_bytes).hexdigest()
    # The issued plan is a member of exactly this preparation.
    assert timer_plan.context.plans() == (timer_plan.plan,)


def test_one_preparation_covers_both_flows(timer_plan):
    document = timer_plan.plan.document()
    assert timer_plan.context.flow_ids == ("F2", "F4")
    assert sorted(path["flow_id"] for path in document["paths"]) == [
        "F2", "F4"]
    assert {path["status"] for path in document["paths"]} == {"executable"}
    assert document["input_digests"] == timer_plan.context.input_digests
    assert {row["instance_id"] for row in document["components"]} == {
        "peripheral", "processor"}
    for path in document["paths"]:
        assert path["path_id"].startswith(path["flow_id"] + ":")
        assert path["kernel"]["flow_id"] == path["flow_id"]
        assert path["kernel"]["id"] == (
            f"generic.flow.{path['flow_id']}.static.v1")
        assert path["kernel"]["executor"] in {"compiled_f2_obi_apb",
                                              "compiled_f4_obi_apb"}
        assert len(path["kernel"]["implementation_sha256"]) == 64
        roles = {binding["role"]: binding for binding in path["bindings"]}
        assert set(roles) == {"cpu", "target"}
        assert roles["target"]["semantic_kind"] == STORAGE_SEMANTIC_KIND
        assert roles["target"]["adapter"]["adapter_id"] == STORAGE_ADAPTER_ID
        assert roles["cpu"]["semantic_kind"] == CPU_SEMANTIC_KIND
        assert roles["cpu"]["adapter"]["adapter_id"] == CPU_ADAPTER_ID
        assert roles["target"]["required_operations"] == ["read", "write"]
        assert path["edges"]
        for edge in path["edges"]:
            assert edge["provider"]["kind"] in {
                "persistent_memory", "target_endpoint", "cpu_endpoint"}
            assert edge["from"] and edge["to"]
        # The provider/consumer references D3 already declares stay visible.
        assert path["runtime_source_ids"]
        assert path["source_ids"]
        assert path["consumer_node_id"] == path["edges"][-1]["to"]


def test_plan_records_d3_constraints_seeds_and_assertions(timer_plan):
    document = timer_plan.plan.document()
    d3 = timer_plan.context.d3_document()
    d3_paths = {path["path_id"]: path for path in d3["paths"]}
    for row in document["constraints"]:
        source = d3_paths[row["path_id"]]["constraints"]
        assert row["policy_hash"] == source["policy_hash"]
        assert row["rule_ids"] == source["rule_ids"]
        assert len(row["source_constraints"]) == len(
            source["source_constraints"])
    for row in document["seeds"]:
        source = d3_paths[row["path_id"]]
        seed_source = next(item for item in source["sources"]
                           if item["source_id"] == row["source_id"])
        assert row["range"] == seed_source["range"]
        assert row["mask"] == seed_source["mask"]
        assert row["alignment"] == seed_source["alignment"]
        assert row["origin"] == "fuzzable"
    expectation_ids = {row["expectation_id"] for row in document["assertions"]}
    assert {"protocol_checker.receipt_violations",
            "cross_component.declared_edge_hops"} <= expectation_ids
    assert document["evidence_obligations"] == sorted(set(
        document["evidence_obligations"]))
    assert {"component_semantic_effect", "physical_protocol_sample",
            "cross_component_source",
            "cross_component_consumption"} == set(
                document["evidence_obligations"])


def test_plan_memory_references_the_declared_shared_resources(timer_plan):
    document = timer_plan.plan.document()
    memory = document["memory"]
    assert memory["schema_version"] == PLAN_MEMORY_SCHEMA
    assert memory["shared"] is True
    wiring = timer_plan.context.compiled_inputs()["request"].wiring.document
    assert [(row["resource_id"], row["component_instance"], row["base"],
             row["size"]) for row in memory["resources"]] == [
        (row["resource_id"], row["component_instance"], row["base"],
         row["size"]) for row in sorted(wiring["resources"],
                                        key=lambda item: item["resource_id"])]
    assert memory["d3_references"]
    for reference in memory["d3_references"]:
        assert reference["resource_id"] in {
            row["resource_id"] for row in memory["resources"]}
        assert reference["relation"] == "persistent_state"
    # A second RAM is never fabricated: there is exactly the declared one.
    assert [row["resource_id"] for row in memory["resources"]] == ["ram"]


def test_plan_scheduling_and_termination_are_static_only(timer_plan):
    document = timer_plan.plan.document()
    scheduling = document["scheduling"]
    assert scheduling["schema_version"] == PLAN_SCHEDULING_SCHEMA
    assert scheduling["flows"] == ["F2", "F4"]
    assert scheduling["shared_persistent_memory"] is True
    assert scheduling["scope"] == "static_plan_no_live_execution"
    assert {row["instance_id"] for row in scheduling["clock_reset"]} == {
        "peripheral", "processor"}
    termination = document["termination"]
    assert termination["schema_version"] == PLAN_TERMINATION_SCHEMA
    assert {row["path_id"] for row in termination["per_path"]} == {
        path["path_id"] for path in document["paths"]}
    assert all(row["kind"] for row in termination["per_path"])


# ---------------------------------------------------------------------------
# cross-preparation membership
# ---------------------------------------------------------------------------

def test_second_preparation_same_hashes_cannot_donate(timer_plan,
                                                      second_plan):
    first = timer_plan.context
    second = second_plan.context
    assert second is not first
    # Same input files prepared twice are genuinely independent processes.
    assert second.input_digests["d2"] == first.input_digests["d2"]
    for component in timer_plan.components:
        error = _refusal(lambda: second.require_component(component))
        assert error.code == "generic-binding-drift"
        assert error.detail["reason"] == "not-issued-by-this-process"
    for selection in timer_plan.selections:
        error = _refusal(lambda: second.require_selection(selection))
        assert error.code == "generic-binding-drift"
    error = _refusal(lambda: second.require_plan(timer_plan.plan))
    assert error.code == "generic-binding-drift"
    # Compiling with borrowed live objects is refused before a plan is issued.
    error = _refusal(lambda: compile_execution_plan(
        second, components=timer_plan.components,
        selections=timer_plan.selections,
        requirements=timer_plan.requirements))
    assert error.code == "generic-binding-drift"
    assert error.pointer == "/component"


def test_equal_value_rebuilt_objects_are_not_members(timer_plan,
                                                     timer_preparation):
    component = timer_plan.components[0]
    rebuilt = VerifiedComponent(
        component.instance_id, component.source_sha256,
        component.profile_sha256, component.artifact_sha256,
        component.semantic_contract_sha256, component.descriptor_bytes)
    assert rebuilt == component
    error = _refusal(lambda: timer_preparation.require_component(rebuilt))
    assert error.code == "generic-binding-drift"

    selection = timer_plan.selections[0]
    rebuilt_selection = AdapterSelection(**selection.document())
    assert rebuilt_selection == selection
    error = _refusal(lambda: timer_preparation.require_selection(
        rebuilt_selection))
    assert error.code == "generic-binding-drift"

    rebuilt_plan = GenericExecutionPlan(
        timer_plan.plan.schema_version, timer_plan.plan.document_bytes,
        timer_plan.plan.identity_sha256)
    assert rebuilt_plan == timer_plan.plan
    error = _refusal(lambda: timer_preparation.require_plan(rebuilt_plan))
    assert error.code == "generic-binding-drift"


# ---------------------------------------------------------------------------
# capability / evidence comparison
# ---------------------------------------------------------------------------

def test_removed_evidence_obligation_is_refused(timer_plan):
    binding = _target_binding(timer_plan)
    requirement = _requirement(timer_plan, binding.endpoint_id)
    reduced = replace(requirement, evidence_obligations=tuple(
        obligation for obligation in requirement.evidence_obligations
        if obligation != "physical_protocol_sample"))
    error = _refusal(lambda: compile_execution_plan(
        timer_plan.context, components=timer_plan.components,
        selections=timer_plan.selections,
        requirements=_replace_requirement(timer_plan, binding.endpoint_id,
                                          reduced)))
    assert error.code == "generic-plan-mismatch"
    assert error.pointer.endswith("/evidence_obligations")
    assert error.detail["reason"] == "required-evidence-obligation-removed"
    assert error.detail["missing"] == ["physical_protocol_sample"]


def test_removed_operation_is_refused(timer_plan):
    binding = _target_binding(timer_plan)
    requirement = _requirement(timer_plan, binding.endpoint_id)
    reduced = replace(requirement, operations=("read",))
    error = _refusal(lambda: compile_execution_plan(
        timer_plan.context, components=timer_plan.components,
        selections=timer_plan.selections,
        requirements=_replace_requirement(timer_plan, binding.endpoint_id,
                                          reduced)))
    assert error.code == "generic-plan-mismatch"
    assert error.pointer.endswith("/operations")
    assert error.detail["reason"] == "required-operation-removed"
    assert error.detail["missing"] == ["write"]


def test_caller_cannot_claim_unverified_evidence(timer_plan):
    binding = _cpu_binding(timer_plan)
    requirement = _requirement(timer_plan, binding.endpoint_id)
    overclaimed = replace(requirement, evidence_obligations=tuple(
        sorted(set(requirement.evidence_obligations) | {"retirement_proof"})))
    component = next(component for component in timer_plan.components
                     if component.instance_id == binding.instance_id)
    error = _refusal(lambda: select_adapter(component, overclaimed,
                                            preparation=timer_plan.context))
    assert error.code == "generic-evidence-missing"
    error = _refusal(lambda: compile_execution_plan(
        timer_plan.context, components=timer_plan.components,
        selections=timer_plan.selections,
        requirements=_replace_requirement(timer_plan, binding.endpoint_id,
                                          overclaimed)))
    assert error.code == "generic-evidence-missing"
    assert error.pointer.endswith("/evidence_obligations")
    assert error.detail["unsupported"] == ["retirement_proof"]


def test_kernel_substitution_is_refused(timer_plan):
    binding = _target_binding(timer_plan)
    requirement = _requirement(timer_plan, binding.endpoint_id)
    for field, replacement, pointer_suffix in (
            ("semantic_kind", "dma.csr.v1", "/semantic_kind"),
            ("template", ("target.apb3", "1", "narrow"), "/template")):
        swapped = replace(requirement, **{field: replacement})
        error = _refusal(lambda: compile_execution_plan(
            timer_plan.context, components=timer_plan.components,
            selections=timer_plan.selections,
            requirements=_replace_requirement(timer_plan,
                                              binding.endpoint_id, swapped)))
        assert error.code == "generic-plan-mismatch"
        assert error.pointer.endswith(pointer_suffix)
        assert error.detail["reason"] == (
            "requirement-does-not-match-derived-capability")


def test_missing_requirement_or_selection_is_refused(timer_plan):
    binding = _target_binding(timer_plan)
    requirements = tuple(requirement for requirement in timer_plan.requirements
                         if requirement.endpoint_id != binding.endpoint_id)
    error = _refusal(lambda: compile_execution_plan(
        timer_plan.context, components=timer_plan.components,
        selections=timer_plan.selections, requirements=requirements))
    assert error.code == "generic-plan-mismatch"
    assert error.pointer == "/requirements"
    assert error.detail["reason"] == "requirement-set-mismatch"

    target_component = next(component for component in timer_plan.components
                            if component.instance_id == binding.instance_id)
    target_selection = next(
        selection for selection in timer_plan.selections
        if selection.component_artifact_sha256
        == target_component.artifact_sha256)
    selections = tuple(selection for selection in timer_plan.selections
                       if selection is not target_selection)
    assert len(selections) == len(timer_plan.selections) - 1
    error = _refusal(lambda: compile_execution_plan(
        timer_plan.context, components=timer_plan.components,
        selections=selections,
        requirements=timer_plan.requirements))
    assert error.code == "generic-plan-mismatch"
    assert error.pointer == "/selections"
    assert error.detail["reason"] == "selection-missing-for-binding"


def test_unverified_component_is_refused(timer_plan, second_preparation):
    foreign = verify_component(second_preparation.artifact("peripheral"),
                               preparation=second_preparation, base_dir=ROOT)
    error = _refusal(lambda: compile_execution_plan(
        timer_plan.context, components=timer_plan.components + (foreign,),
        selections=timer_plan.selections,
        requirements=timer_plan.requirements))
    assert error.code == "generic-binding-drift"


# ---------------------------------------------------------------------------
# tampered plan documents
# ---------------------------------------------------------------------------

def test_tampered_plan_json_is_refused(timer_plan):
    raw = timer_plan.plan.document_bytes
    error = _refusal(lambda: load_execution_plan_document(raw + b"\n"))
    assert error.code == "generic-plan-mismatch"
    assert error.detail["reason"] == "noncanonical-plan-bytes"

    document = timer_plan.plan.document()
    path = document["paths"][0]
    path["assertions"].pop(0)
    tampered = GenericExecutionPlan.freeze(document)
    assert tampered.identity_sha256 != timer_plan.plan.identity_sha256
    error = _refusal(lambda: verify_execution_plan(
        timer_plan.context, tampered, components=timer_plan.components,
        selections=timer_plan.selections,
        requirements=timer_plan.requirements))
    assert error.code == "generic-plan-mismatch"
    assert error.pointer.startswith("/paths/0/assertions")
    assert error.detail["reason"] == "plan-document-mismatch"

    document = timer_plan.plan.document()
    document["evidence_obligations"].remove("physical_protocol_sample")
    tampered = GenericExecutionPlan.freeze(document)
    error = _refusal(lambda: verify_execution_plan(
        timer_plan.context, tampered, components=timer_plan.components,
        selections=timer_plan.selections,
        requirements=timer_plan.requirements))
    assert error.code == "generic-plan-mismatch"
    assert error.pointer == "/evidence_obligations"


def test_tampered_same_pass_d3_is_refused(timer_plan):
    context = timer_plan.context
    compiled = context.compiled_inputs()["compiled"]
    path = next(path for path in compiled["paths"]
                if path["path_id"] == "F2:ram.image")
    saved = path["assertions"]
    try:
        path["assertions"] = saved[:-1]
        error = _refusal(lambda: compile_execution_plan(
            context, components=timer_plan.components,
            selections=timer_plan.selections,
            requirements=timer_plan.requirements))
        assert error.code == "generic-binding-drift"
        assert error.pointer == "/input_digests/d3"
    finally:
        path["assertions"] = saved


# ---------------------------------------------------------------------------
# canonical determinism / detachment
# ---------------------------------------------------------------------------

def test_plan_is_detached_and_recomputes_canonically(timer_plan):
    original_bytes = timer_plan.plan.document_bytes
    original_identity = timer_plan.plan.identity_sha256
    document = timer_plan.plan.document()
    document["paths"].clear()
    document["evidence_obligations"].append("fabricated_obligation")
    assert timer_plan.plan.document_bytes == original_bytes
    assert timer_plan.plan.identity_sha256 == original_identity
    # Same caller objects, shuffled tuple order: the same bytes come back.
    result = verify_execution_plan(
        timer_plan.context, timer_plan.plan,
        components=tuple(reversed(timer_plan.components)),
        selections=tuple(reversed(timer_plan.selections)),
        requirements=tuple(reversed(timer_plan.requirements)))
    assert result is timer_plan.plan
    assert result.document_bytes == original_bytes
    assert GenericExecutionPlan.freeze(
        timer_plan.plan.document()).identity_sha256 == original_identity


def _difference_pointers(expected, actual, pointer: str = "") -> list[str]:
    if type(expected) is not type(actual):
        return [pointer or "/"]
    if isinstance(expected, dict):
        rows = []
        for key in sorted(set(expected) | set(actual)):
            location = (pointer or "") + "/" + key
            if key not in expected or key not in actual:
                rows.append(location)
            elif expected[key] != actual[key]:
                rows += _difference_pointers(expected[key], actual[key],
                                             location)
        return rows
    if isinstance(expected, list):
        if len(expected) != len(actual):
            return [pointer or "/"]
        rows = []
        for index, (left, right) in enumerate(zip(expected, actual)):
            if left != right:
                rows += _difference_pointers(left, right,
                                             (pointer or "") + f"/{index}")
        return rows
    return [pointer or "/"]


def test_same_file_inputs_recompute_the_same_plan_except_d3_identity(
        timer_plan, second_plan):
    first = timer_plan.plan.document()
    second = second_plan.plan.document()
    assert first["input_digests"]["d2"] == second["input_digests"]["d2"]
    differences = set(_difference_pointers(first, second))
    f2_index = next(index for index, path in enumerate(first["paths"])
                    if path["flow_id"] == "F2")
    # Documented upstream fact: compiled_paths.v1 identity.request_sha256
    # embeds the generated directory path, so the D3 digest (and the F2 flow
    # support digest that re-pins it) differ between two output directories.
    # No other plan content differs, i.e. derivation is canonical.
    assert differences == {
        "/input_digests/d3",
        f"/paths/{f2_index}/kernel/producer_binding_sha256",
    }
    projection_first = json.loads(json.dumps(first))
    projection_second = json.loads(json.dumps(second))
    for document in (projection_first, projection_second):
        document.pop("input_digests")
        for path in document["paths"]:
            path["kernel"].pop("producer_binding_sha256", None)
    assert projection_first == projection_second


# ---------------------------------------------------------------------------
# empty / unbindable plans
# ---------------------------------------------------------------------------

def _minimal_plan_document(**overrides) -> dict:
    document = {
        "schema_version": PLAN_SCHEMA,
        "components": [{"instance_id": "processor"}],
        "selections": [{"instance_id": "processor",
                        "endpoint_id": "processor.data"}],
        "paths": [{"path_id": "F2:ram.image",
                   "bindings": [{"role": "cpu"}, {"role": "target"}],
                   "kernel": {"id": "generic.flow.F2.static.v1"},
                   "edges": [{"provider": {"kind": "persistent_memory"}}]}],
        "sources": [{"source_id": "ram.image"}],
        "constraints": [{"path_id": "F2:ram.image"}],
        "seeds": [{"path_id": "F2:ram.image", "origin": "fuzzable"}],
        "assertions": [{"expectation_id": "protocol_checker.receipt_violations"}],
        "memory": {},
        "scheduling": {},
        "termination": {},
        "evidence_obligations": ["physical_protocol_sample"],
        "input_digests": {"d2": "1" * 64, "d3": "2" * 64},
    }
    document.update(overrides)
    return document


def test_empty_plan_document_is_refused_field_by_field():
    assert_plan_content(_minimal_plan_document())
    cases = (
        ({"paths": []}, "/paths"),
        ({"components": []}, "/components"),
        ({"selections": []}, "/selections"),
        ({"seeds": []}, "/seeds"),
        ({"assertions": []}, "/assertions"),
        ({"evidence_obligations": []}, "/evidence_obligations"),
    )
    for overrides, pointer in cases:
        document = _minimal_plan_document(**overrides)
        error = _refusal(lambda document=document: assert_plan_content(
            document))
        assert error.code == "generic-plan-mismatch"
        assert error.pointer == pointer
    incomplete = _minimal_plan_document(
        paths=[{"path_id": "F2:ram.image",
                "bindings": [{"role": "target"}],
                "kernel": {"id": "generic.flow.F2.static.v1"},
                "edges": [{"provider": {"kind": "persistent_memory"}}]}])
    error = _refusal(lambda: assert_plan_content(incomplete))
    assert error.code == "generic-plan-mismatch"
    assert error.pointer == "/paths/0/bindings"


def test_compile_refuses_empty_component_set(timer_plan):
    error = _refusal(lambda: compile_execution_plan(
        timer_plan.context, components=(), selections=(),
        requirements=()))
    assert error.code == "generic-plan-mismatch"
    assert error.pointer == "/components"
    assert error.detail["reason"] == "no-verified-component"


def test_compile_refuses_a_context_without_same_pass_inputs():
    context = PreparationContext._for_tests()
    error = _refusal(lambda: compile_execution_plan(
        context, components=(), selections=(), requirements=()))
    assert error.code == "generic-plan-mismatch"
    assert error.pointer == "/compiled-inputs"
    assert error.detail["reason"] == "incomplete-compiled-inputs"


def test_compile_refuses_a_d3_without_executable_paths():
    context = PreparationContext._for_tests()
    compiled = {"schema_version": "compiled_paths.v1", "paths": []}
    context._inputs = SimpleNamespace(flow_ids=("F2",))
    context._compiled_inputs = {
        "request": SimpleNamespace(wiring=SimpleNamespace(
            document={"resources": []})),
        "compiled": compiled,
        "ownership": object(),
        "physical_port_map": {},
    }
    context._input_digests = {"d2": _DIGEST,
                              "d3": compiled_document_sha256(compiled)}
    error = _refusal(lambda: compile_execution_plan(
        context, components=(), selections=(), requirements=()))
    assert error.code == "generic-plan-mismatch"
    assert error.pointer == "/paths"
    assert error.detail["reason"] == "no-executable-path"


def test_supported_flow_set_is_fixed(tmp_path):
    assert SUPPORTED_FLOWS == ("F1", "F2", "F3", "F4", "F5")
    error = _refusal(lambda: create_preparation(
        base_dir=ROOT, compose_path=TIMER / "compose.json",
        capability_paths=(TIMER / "test_capability.json",),
        supplement_path=TIMER / "execution_supplement.json",
        generated_dir=tmp_path / "generated", flow_ids=("F7",)))
    assert error.code == "generic-flow-unsupported"
    assert error.pointer == "/flow_ids"
