"""G2: trusted artifact admission into one same-pass preparation context.

Software only: a passing test admits a static component description.  It starts
no RTL, issues no native token and proves no executed effect.

Refusal layers are exercised where the fact belongs:

* ``preparation.assert_artifact_current`` -> ``generic-binding-drift`` when the
  in-memory document or a generated file no longer matches the sealed bytes;
* ``admission._storage_observation_facts`` -> the storage observation, source
  contract, decode and semantic refusal codes;
* ``admission._trusted_verifier`` -> ``generic-source-unverified`` for an
  artifact kind no code-owned verifier accepts.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import pytest

from myfuzz.local_harness.apb_storage_source_contract import (
    validate_apb_storage_source_contract,
)
from myfuzz.local_harness.runtime_artifact import LocalRuntimeArtifact
from myfuzz.runtime import admission
from myfuzz.runtime.admission import (
    APB_STORAGE_VERIFIER_ID,
    CPU_SEMANTIC_KIND,
    OBI_CPU_VERIFIER_ID,
    _storage_observation_facts,
    _trusted_verifier,
    cpu_execution_surface_document,
    verify_component,
)
from myfuzz.runtime.contracts import CapabilityRequirement, GenericRuntimeRefused
from myfuzz.runtime.preparation import (
    create_preparation,
    load_preparation_snapshot,
)
from myfuzz.runtime.registry import select_adapter
from myfuzz.runtime.semantics.storage import (
    storage_register_facts,
    storage_semantic_contract,
)

ROOT = Path(__file__).resolve().parents[2]
TIMER = ROOT / "configs/scenarios/compiled-f4-obi-apb-timer"
SPI = ROOT / "configs/scenarios/compiled-f4-obi-apb-spi-cv32e40p"


def _preparation(tmp_path_factory, scenario: Path, supplement: str,
                 flows=("F2", "F4")):
    output = tmp_path_factory.mktemp("generic-preparation")
    context = create_preparation(
        base_dir=ROOT,
        compose_path=scenario / "compose.json",
        capability_paths=(scenario / "test_capability.json",),
        supplement_path=scenario / supplement,
        generated_dir=output / "generated",
        flow_ids=tuple(flows),
    )
    return context


@pytest.fixture(scope="module")
def timer_preparation(tmp_path_factory):
    context = _preparation(tmp_path_factory, TIMER, "execution_supplement.json")
    yield context
    context.close()


@pytest.fixture(scope="module")
def spi_preparation(tmp_path_factory):
    context = _preparation(tmp_path_factory, SPI, "f2_execution_supplement.json")
    yield context
    context.close()


@pytest.fixture(scope="module")
def timer_components(timer_preparation):
    target = verify_component(timer_preparation.artifact("peripheral"),
                              preparation=timer_preparation, base_dir=ROOT)
    cpu = verify_component(timer_preparation.artifact("processor"),
                           preparation=timer_preparation, base_dir=ROOT)
    return target, cpu


def requirement_for(endpoint: dict, **overrides) -> CapabilityRequirement:
    document = {
        "role": endpoint["role"],
        "endpoint_id": endpoint["endpoint_id"],
        "protocol": tuple(endpoint["protocol"]),
        "template": tuple(endpoint["template"]),
        "semantic_kind": endpoint["semantic_kind"],
        "operations": tuple(endpoint["operations"]),
        "data_width": endpoint["data_width"],
        "address_width": endpoint["address_width"],
        "max_outstanding": endpoint["max_outstanding"],
        "completion_kind": endpoint["completion_kind"],
        "byte_enable_required": endpoint["byte_enable"],
        "address_units": endpoint["address_units"],
        "evidence_obligations": tuple(endpoint["evidence_capabilities"]),
    }
    document.update(overrides)
    return CapabilityRequirement(**document)


# ---------------------------------------------------------------------------
# same-pass preparation facts
# ---------------------------------------------------------------------------

def test_preparation_owns_one_artifact_mapping_and_same_pass_d3(timer_preparation):
    context = timer_preparation
    assert tuple(sorted(context.artifacts)) == ("peripheral", "processor")
    for instance_id, artifact in context.artifacts.items():
        assert type(artifact) is LocalRuntimeArtifact
        assert artifact.plan.request.instance_id == instance_id
    digests = context.input_digests
    assert set(digests) == {"d2", "d3"}
    for digest in digests.values():
        assert len(digest) == 64 and digest == digest.lower()
    # Both flow assessments were made from the same objects, not a second pass.
    for flow in ("F2", "F4"):
        support = context.flow_support(flow)
        assert support["execution_supported"] == 1, (flow, support)
        assert support["runtime_admitted"] is False
    # The real support documents carry different identity fields: F4's producer
    # binding is self-hashed, F2's binding identity is its canonical document.
    f2 = context.flow_support("F2")
    assert f2["schema_version"] == "compiled_F2_support.v1"
    assert f2["executor"] == "compiled_f2_obi_apb"
    assert f2["flow_id"] == "F2"
    f2_binding = f2["producer_binding"]
    assert f2_binding["schema_version"] == "compiled_F2_read_producer_binding.v1"
    assert f2_binding["row"] == "generic_apb_storage_read_abi"
    assert f2_binding["live_authority"] == "not_claimed"
    assert f2_binding["target_component"] == "peripheral"
    assert len(f2_binding["target_artifact_digest"]) == 64
    assert len(f2_binding["compiled_sha256"]) == 64
    assert f2_binding["register"]["operation"] == "read"
    assert f2_binding["producer"]["grants_reset_prerequisite"] is False
    assert "actual_native_current_register_version_token" in f2["startup_requires"]
    f4 = context.flow_support("F4")
    assert f4["schema_version"] == "compiled_F4_support.v1"
    assert f4["executor"] == "compiled_f4_obi_apb"
    f4_binding = f4["producer_binding"]
    assert f4_binding["schema_version"] == "compiled_F4_storage_producer_binding.v1"
    assert f4_binding["row"] == "generic_apb_storage_abi"
    assert f4_binding["live_authority"] == "not_claimed"
    assert len(f4_binding["binding_sha256"]) == 64
    assert len(f4_binding["target_artifact_digest"]) == 64
    # The D2/D3 digests of both assessments are the preparation's own pair.
    assert f2_binding["target_artifact_digest"] == f4_binding[
        "target_artifact_digest"]


def test_context_snapshot_is_documentary_not_live(timer_preparation, timer_components):
    snapshot = timer_preparation.snapshot()
    assert snapshot["schema_version"] == "preparation_snapshot.v1"
    assert snapshot["scope"].startswith("process_local_documentary")
    assert snapshot["flows"] == ["F2", "F4"]
    assert [row["instance_id"] for row in snapshot["components"]] == [
        "peripheral", "processor"]
    parsed = load_preparation_snapshot(json.loads(json.dumps(snapshot)))
    assert parsed == snapshot
    with pytest.raises(GenericRuntimeRefused) as caught:
        load_preparation_snapshot({"schema_version": "wrong"})
    assert caught.value.code == "generic-plan-mismatch"
    # A snapshot is documentation; it is not accepted where the context is.
    with pytest.raises(GenericRuntimeRefused):
        verify_component(timer_preparation.artifact("peripheral"),
                         preparation=snapshot, base_dir=ROOT)


def test_flow_support_refuses_flow_that_was_not_prepared(timer_preparation):
    with pytest.raises(GenericRuntimeRefused) as caught:
        timer_preparation.flow_support("F6")
    assert caught.value.code == "generic-flow-unsupported"


def test_create_preparation_refuses_unknown_and_empty_flow(tmp_path):
    with pytest.raises(GenericRuntimeRefused) as caught:
        create_preparation(base_dir=ROOT, compose_path=TIMER / "compose.json",
                           capability_paths=(TIMER / "test_capability.json",),
                           supplement_path=TIMER / "execution_supplement.json",
                           generated_dir=tmp_path / "a" / "generated",
                           flow_ids=("F7",))
    assert caught.value.code == "generic-flow-unsupported"
    with pytest.raises(GenericRuntimeRefused):
        create_preparation(base_dir=ROOT, compose_path=TIMER / "compose.json",
                           capability_paths=(TIMER / "test_capability.json",),
                           supplement_path=TIMER / "execution_supplement.json",
                           generated_dir=tmp_path / "b" / "generated",
                           flow_ids=())


# ---------------------------------------------------------------------------
# positive admission
# ---------------------------------------------------------------------------

def test_timer_target_admission_is_source_backed(timer_preparation, timer_components):
    target, _ = timer_components
    document = target.document()
    assert document["schema_version"] == "verified_component_descriptor.v1"
    assert document["source_verifier"]["id"] == APB_STORAGE_VERIFIER_ID
    assert len(document["source_verifier"]["implementation_sha256"]) == 64
    assert len(document["endpoints"]) == 1
    endpoint = document["endpoints"][0]
    assert endpoint["endpoint_id"] == "timer.bus"
    assert endpoint["role"] == "target"
    assert endpoint["protocol"] == ["apb", "3"]
    assert endpoint["template"] == ["target.apb3", "1", "full-word"]
    assert endpoint["semantic_kind"] == "storage.rw.v1"
    assert endpoint["operations"] == ["read", "write"]
    assert endpoint["address_width"] == 12
    assert endpoint["address_units"] == "byte"
    assert endpoint["byte_enable"] is False
    assert endpoint["completion_kind"] == "setup_access_response"

    artifact = timer_preparation.artifact("peripheral")
    observation = artifact.runtime_document["storage_observation"]
    registered = validate_apb_storage_source_contract(
        observation["source_contract"], artifact.plan.profile, base_dir=ROOT)
    semantic = storage_semantic_contract(
        registered=registered, endpoint_id="timer.bus",
        template=("target.apb3", "1", "full-word"),
        observation_scope="generated_expression_source_mapped")
    assert semantic.sha256_hex == target.semantic_contract_sha256
    facts = storage_register_facts(semantic)
    assert facts["write_mask"] == 0xFFFFFFFF
    assert facts["decode_value"] == 4
    assert facts["reset_observed"] is False
    # Source closure, profile and artifact digests are distinct identities.
    assert len({target.source_sha256, target.profile_sha256,
                target.artifact_sha256, target.semantic_contract_sha256}) == 4


def test_cpu_admission_records_existing_execution_surface(timer_preparation,
                                                          timer_components):
    _, cpu = timer_components
    document = cpu.document()
    assert document["source_verifier"]["id"] == OBI_CPU_VERIFIER_ID
    endpoint = document["endpoints"][0]
    assert endpoint["endpoint_id"] == "processor.data"
    assert endpoint["role"] == "cpu"
    assert endpoint["protocol"] == ["obi", "1"]
    assert endpoint["template"][0] == "cpu.obi"
    assert endpoint["semantic_kind"] == CPU_SEMANTIC_KIND
    assert endpoint["operations"] == ["read", "write"]
    assert endpoint["address_width"] == 32
    surface = cpu_execution_surface_document(timer_preparation.artifact("processor"))
    assert sha256(json.dumps(surface, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False).encode()).hexdigest() \
        == cpu.semantic_contract_sha256
    assert surface["instruction_endpoints"] == ["processor.instruction"]
    assert "dut_semantics_verified" not in endpoint


def test_admission_is_idempotent_for_the_same_descriptor(timer_preparation,
                                                         timer_components):
    target, _ = timer_components
    again = verify_component(timer_preparation.artifact("peripheral"),
                             preparation=timer_preparation, base_dir=ROOT)
    assert again is target


def test_both_registered_sources_admit_the_same_way(spi_preparation):
    target = verify_component(spi_preparation.artifact("peripheral"),
                              preparation=spi_preparation, base_dir=ROOT)
    endpoint = target.endpoints()[0]
    assert endpoint["endpoint_id"] == "spi.bus"
    assert endpoint["semantic_kind"] == "storage.rw.v1"
    assert endpoint["template"] == ["target.apb3", "1", "full-word"]
    cpu = verify_component(spi_preparation.artifact("processor"),
                           preparation=spi_preparation, base_dir=ROOT)
    assert cpu.endpoints()[0]["template"] == [
        "cpu.obi", "1", "read-write-no-error-pins"]
    # Different RTL source closure, different semantic contract, same adapter.
    assert target.source_sha256 != cpu.source_sha256
    assert target.semantic_contract_sha256 != cpu.semantic_contract_sha256


def test_storage_observation_facts_accept_the_prepared_artifact(timer_preparation,
                                                                timer_components):
    """The reused deep check accepts the real observation (not refuse-only)."""
    target, _ = timer_components
    facts = _storage_observation_facts(
        timer_preparation.artifact("peripheral"),
        preparation=timer_preparation, base_dir=ROOT)
    assert facts["semantic_contract_sha256"] == target.semantic_contract_sha256
    assert facts["source_verifier"]["id"] == APB_STORAGE_VERIFIER_ID
    assert facts["endpoints"][0]["endpoint_id"] == "timer.bus"
    assert facts["endpoints"][0]["semantic_kind"] == "storage.rw.v1"
    registered = facts["facts"]["registered"]
    assert registered["contract_id"] == "pulp-apb-timer.ctrl0.source.v1"
    assert registered["register"]["name"] == "TIMER0_CTRL"
    assert registered["register"]["canonical_offset"] == 4
    assert facts["facts"]["limits"]["completion"] == "setup_access_response"
    assert facts["facts"]["limits"]["max_outstanding"] == 1
    # The deep copy proves this function does not need object membership.
    clone = deepcopy(timer_preparation.artifact("peripheral"))
    assert _storage_observation_facts(
        clone, preparation=timer_preparation, base_dir=ROOT
    )["semantic_contract_sha256"] == target.semantic_contract_sha256


def test_cpu_endpoint_facts_accept_the_prepared_artifact(timer_preparation,
                                                         timer_components):
    _, cpu = timer_components
    facts = admission._cpu_endpoints(
        timer_preparation.artifact("processor"),
        preparation=timer_preparation, base_dir=ROOT)
    assert facts["semantic_contract_sha256"] == cpu.semantic_contract_sha256
    assert facts["source_verifier"]["id"] == OBI_CPU_VERIFIER_ID
    assert facts["endpoints"][0]["endpoint_id"] == "processor.data"
    assert facts["endpoints"][0]["semantic_kind"] == CPU_SEMANTIC_KIND


# ---------------------------------------------------------------------------
# negatives: object membership and sealed bytes
# ---------------------------------------------------------------------------

def test_foreign_context_artifact_refused(timer_preparation, spi_preparation):
    with pytest.raises(GenericRuntimeRefused) as caught:
        verify_component(timer_preparation.artifact("peripheral"),
                         preparation=spi_preparation, base_dir=ROOT)
    assert caught.value.code == "generic-source-unverified"
    assert caught.value.detail["reason"] == "not-the-preparation-object"


def test_rebuilt_artifact_is_not_the_preparation_object(timer_preparation):
    artifact = timer_preparation.artifact("peripheral")
    clone = LocalRuntimeArtifact(
        artifact.plan, artifact.structural, artifact.source_verification,
        artifact.runtime_sv, artifact.cpp_text, artifact.runtime_document)
    with pytest.raises(GenericRuntimeRefused) as caught:
        verify_component(clone, preparation=timer_preparation, base_dir=ROOT)
    assert caught.value.code == "generic-source-unverified"
    assert caught.value.detail["reason"] == "not-the-preparation-object"


def test_wrong_base_dir_refused(timer_preparation):
    with pytest.raises(GenericRuntimeRefused) as caught:
        verify_component(timer_preparation.artifact("peripheral"),
                         preparation=timer_preparation, base_dir=ROOT.parent)
    assert caught.value.code == "generic-source-unverified"
    assert caught.value.detail["reason"] == "preparation-base-dir-mismatch"


def test_in_place_document_mutation_is_refused_as_sealed_bytes(timer_preparation,
                                                               timer_components):
    """Mutating the live document breaks the generated artifact.json pin.

    That is the intended sealed-bytes refusal: the in-memory document is no
    longer the artifact the preparation generated and pinned.  The deeper
    semantic layers are exercised on deep copies below.
    """
    target, _ = timer_components
    artifact = timer_preparation.artifact("peripheral")
    document = artifact.runtime_document
    original = deepcopy(document)
    try:
        document["storage_observation"]["source_authority"] = True
        with pytest.raises(GenericRuntimeRefused) as caught:
            verify_component(artifact, preparation=timer_preparation,
                             base_dir=ROOT)
        assert caught.value.code == "generic-binding-drift"
        assert caught.value.pointer == "/artifact"
        assert caught.value.detail == {"reason": "generated-file-changed",
                                       "file": "artifact.json"}
    finally:
        document.clear()
        document.update(original)
    # The restore returns the artifact to the sealed bytes and to membership.
    assert verify_component(artifact, preparation=timer_preparation,
                            base_dir=ROOT) is target


def test_changed_generated_file_refused(timer_preparation):
    path = (timer_preparation.generated_dir / "peripheral" / "runtime.sv")
    original = path.read_bytes()
    try:
        path.write_bytes(original[:-1] + bytes([original[-1] ^ 0xFF]))
        with pytest.raises(GenericRuntimeRefused) as caught:
            verify_component(timer_preparation.artifact("peripheral"),
                             preparation=timer_preparation, base_dir=ROOT)
        assert caught.value.code == "generic-binding-drift"
        assert caught.value.detail["reason"] == "generated-file-changed"
    finally:
        path.write_bytes(original)


# ---------------------------------------------------------------------------
# negatives: storage observation semantics (deep copies, no pin re-check)
# ---------------------------------------------------------------------------

def _mutated_artifact(timer_preparation, mutate):
    """Deep copy of the real storage artifact with one in-memory mutation.

    The copy is deliberately not a preparation member and its generated files
    are untouched, so only the deep admission function runs.
    """
    artifact = deepcopy(timer_preparation.artifact("peripheral"))
    mutate(artifact.runtime_document)
    return artifact


def test_tampered_storage_selection_refused(timer_preparation):
    for name, value in (("register", "OTHER"),
                        ("contract_id", "pulp-apb-timer.other.source.v1"),
                        ("endpoint_id", "timer.other")):
        def mutate(document, name=name, value=value):
            document["storage_observation"]["selection"][name] = value

        with pytest.raises(GenericRuntimeRefused) as caught:
            _storage_observation_facts(
                _mutated_artifact(timer_preparation, mutate),
                preparation=timer_preparation, base_dir=ROOT)
        assert caught.value.code == "generic-semantic-unsupported", name
        assert caught.value.pointer == "/artifact/storage_observation"
        assert caught.value.detail == {
            "reason": "closed-storage-observation-required"}


def test_observation_schema_version_change_refused(timer_preparation):
    def mutate(document):
        document["storage_observation"]["schema_version"] = "apb_storage_probe.v2"

    with pytest.raises(GenericRuntimeRefused) as caught:
        _storage_observation_facts(
            _mutated_artifact(timer_preparation, mutate),
            preparation=timer_preparation, base_dir=ROOT)
    assert caught.value.code == "generic-semantic-unsupported"
    assert caught.value.pointer == "/artifact/storage_observation"


def test_authority_claim_in_observation_refused(timer_preparation):
    for flag in ("reset_authority", "version_authority", "source_authority"):
        def mutate(document, flag=flag):
            observation = document["storage_observation"]
            assert observation[flag] is False
            observation[flag] = True

        with pytest.raises(GenericRuntimeRefused) as caught:
            _storage_observation_facts(
                _mutated_artifact(timer_preparation, mutate),
                preparation=timer_preparation, base_dir=ROOT)
        assert caught.value.code == "generic-semantic-unsupported", flag
        assert caught.value.pointer == "/artifact/storage_observation"
        assert caught.value.detail["reason"] == \
            "closed-storage-observation-required"


def test_tampered_source_contract_refused(timer_preparation):
    for name, value in (("digest", "0" * 64),
                        ("contract_id", "pulp-apb-timer.ctrl0.source.v2"),
                        ("scope", "claimed_runtime_authority")):
        def mutate(document, name=name, value=value):
            document["storage_observation"]["source_contract"][name] = value

        with pytest.raises(GenericRuntimeRefused) as caught:
            _storage_observation_facts(
                _mutated_artifact(timer_preparation, mutate),
                preparation=timer_preparation, base_dir=ROOT)
        assert caught.value.code == "generic-source-unverified", name
        assert caught.value.pointer == "/storage_observation/source_contract"


def test_tampered_source_contract_register_refused(timer_preparation):
    def mutate(document):
        document["storage_observation"]["source_contract"]["register"][
            "name"] = "TIMER1_CTRL"

    with pytest.raises(GenericRuntimeRefused) as caught:
        _storage_observation_facts(
            _mutated_artifact(timer_preparation, mutate),
            preparation=timer_preparation, base_dir=ROOT)
    assert caught.value.code == "generic-source-unverified"
    assert caught.value.pointer == "/storage_observation/source_contract"


def test_observation_scope_change_refused(timer_preparation):
    def mutate(document):
        document["storage_observation"]["scope"] = "claimed_native_hierarchy"

    with pytest.raises(GenericRuntimeRefused) as caught:
        _storage_observation_facts(
            _mutated_artifact(timer_preparation, mutate),
            preparation=timer_preparation, base_dir=ROOT)
    assert caught.value.code == "generic-semantic-unsupported"
    assert caught.value.pointer == "/artifact/storage_observation"


def test_kind_without_trusted_verifier_refused(timer_preparation, timer_components):
    """verify_component's dispatch refuses a kind no code-owned verifier takes."""
    artifact = timer_preparation.artifact("peripheral")
    assert _trusted_verifier(artifact) is admission._storage_endpoint
    assert _trusted_verifier(timer_preparation.artifact("processor")) is \
        admission._cpu_endpoints
    clone = deepcopy(artifact)
    clone.runtime_document["kind"] = "mystery_protocol"
    with pytest.raises(GenericRuntimeRefused) as caught:
        _trusted_verifier(clone)
    assert caught.value.code == "generic-source-unverified"
    assert caught.value.pointer == "/artifact/kind"
    assert caught.value.detail == {"reason": "no-trusted-verifier",
                                   "kind": "mystery_protocol"}


def test_input_producer_artifact_refused(timer_preparation):
    clone = deepcopy(timer_preparation.artifact("peripheral"))
    clone.runtime_document["bound_physical_inputs"] = {"external": "producer"}
    with pytest.raises(GenericRuntimeRefused) as caught:
        _storage_observation_facts(clone, preparation=timer_preparation,
                                   base_dir=ROOT)
    assert caught.value.code == "generic-semantic-unsupported"
    assert caught.value.pointer == "/artifact/inputs"
    assert caught.value.detail == {"reason": "input-producer-unsupported"}


# ---------------------------------------------------------------------------
# closed context revokes every issued handle
# ---------------------------------------------------------------------------

def test_closed_context_revokes_live_membership(tmp_path_factory):
    context = _preparation(tmp_path_factory, SPI, "f2_execution_supplement.json",
                           flows=("F4",))
    artifact = context.artifact("peripheral")
    component = verify_component(artifact, preparation=context, base_dir=ROOT)
    requirement = requirement_for(component.endpoints()[0])
    selection = select_adapter(component, requirement, preparation=context)
    assert context.components() == (component,)
    assert context.selections() == (selection,)
    context.close()
    assert context.closed is True
    assert context.components() == ()
    assert context.selections() == ()
    with pytest.raises(GenericRuntimeRefused) as caught:
        verify_component(artifact, preparation=context, base_dir=ROOT)
    assert caught.value.code == "generic-binding-drift"
    assert caught.value.pointer == "/preparation"
    assert caught.value.detail == {"reason": "preparation-closed"}
    # A previously issued component is no longer a member of the closed context.
    with pytest.raises(GenericRuntimeRefused) as caught:
        context.require_component(component)
    assert caught.value.code == "generic-binding-drift"
    with pytest.raises(GenericRuntimeRefused) as caught:
        select_adapter(component, requirement, preparation=context)
    assert caught.value.code == "generic-binding-drift"
    assert caught.value.detail == {"reason": "preparation-closed"}
