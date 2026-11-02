"""G8.1: the Wishbone classic CPU adapter boundary (facts, never a driver).

Software only.  The real generated ``wishbone_cpu`` artifact for the pinned
PicoRV32 ``picorv32_wb`` profile is built in-process and the real
``GeneratedWishboneCpuSession`` is constructed without a native build
(construction starts nothing); no RTL, Verilator build or CPU step happens here.

The component descriptor and the D3 plan are built here because no Wishbone
admission verifier exists yet: the artifact, the session class and every width,
role and boot fact are real and re-derived from the artifact document.
"""
from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from myfuzz.local_harness import (
    load_local_harness_request,
    plan_local_harness,
    render_local_driver,
    render_local_harness,
    render_local_runtime,
    verify_local_source_lock,
)
from myfuzz.local_harness.wishbone_cpu_session import GeneratedWishboneCpuSession
from myfuzz.runtime.adapters import obi_cpu, wishbone_cpu as wc
from myfuzz.runtime.adapters.contracts import BoundProtocolAdapter, CpuDriver
from myfuzz.runtime.contracts import (
    AdapterSelection,
    GenericRuntimeRefused,
    VerifiedComponent,
    canonical_json_bytes,
)
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.router import DataflowRouter, DeviceWindow

ROOT = Path(__file__).resolve().parents[2]
ENDPOINT = "processor.memory"


def _artifact():
    request = load_local_harness_request(dict(
        schema_version="local_harness.v1",
        profile_path="configs/cpus/picorv32_wb/component_profile.json",
        instance_id="processor", reset_assert_ticks=2, reset_release_ticks=2,
        max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    top = render_local_runtime(plan, render_local_harness(plan),
                               verify_local_source_lock(plan.profile,
                                                        base_dir=ROOT),
                               base_dir=ROOT)
    return render_local_driver(top, base_dir=ROOT)


def _descriptor(artifact, *, endpoint_overrides=None, artifact_sha256=None,
                semantic_sha256=None):
    surface = wc.wishbone_cpu_surface_document(artifact)
    endpoint = {
        "endpoint_id": ENDPOINT,
        "role": "cpu",
        "protocol": ["wishbone", "classic"],
        "template": ["cpu.wishbone", "1", "no-err-stall"],
        "semantic_kind": "cpu.wishbone.v1",
        "operations": ["read", "write"],
        "data_width": 32,
        "address_width": 32,
        "address_units": "byte",
        "max_outstanding": 1,
        "completion_kind": "cycle_strobe_held_until_ack",
        "byte_enable": True,
        "evidence_capabilities": sorted([
            "cross_component_consumption", "cross_component_source",
            "physical_protocol_sample"]),
    }
    endpoint.update(endpoint_overrides or {})
    return {
        "schema_version": "verified_component_descriptor.v1",
        "instance_id": "processor",
        "source_sha256": sha256(
            canonical_json_bytes(artifact.source_verification)).hexdigest(),
        "profile_sha256": artifact.plan.profile_sha256,
        "artifact_sha256": (artifact_sha256
                            or artifact.runtime_document["artifact_digest"]),
        "semantic_contract_sha256": semantic_sha256 or wc._digest(surface),
        "source_verifier": {"id": "wishbone-cpu-source.v1", "version": "1",
                            "implementation_sha256": "0" * 64},
        "endpoints": [endpoint],
    }


def _component(artifact, *, endpoint_overrides=None, artifact_sha256=None,
               semantic_sha256=None):
    document = _descriptor(artifact, endpoint_overrides=endpoint_overrides,
                           artifact_sha256=artifact_sha256,
                           semantic_sha256=semantic_sha256)
    return VerifiedComponent(
        "processor", document["source_sha256"], document["profile_sha256"],
        document["artifact_sha256"], document["semantic_contract_sha256"],
        canonical_json_bytes(document))


def _selection(component, *, adapter_id=wc.CPU_ADAPTER_ID, pin=None,
               artifact_sha256=None, semantic_sha256=None):
    return AdapterSelection(
        adapter_id, "1",
        pin if pin is not None else wc.selection_implementation_pin()[0],
        artifact_sha256 or component.artifact_sha256,
        semantic_sha256 or component.semantic_contract_sha256)


def _session(artifact, tmp_path):
    memory = PersistentMemory(
        regions=(MemoryRegion("ram", 0, 4096),), initialization_seed=3,
        max_initialized_bytes=4096)
    router = DataflowRouter((
        DeviceWindow("peripheral", 0x40000000, 0x1000, SimpleNamespace()),))
    return GeneratedWishboneCpuSession(
        artifact, base_dir=ROOT, cache_dir=tmp_path / "cache", memory=memory,
        router=router)


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    artifact = _artifact()
    component = _component(artifact)
    tmp = tmp_path_factory.mktemp("g81-wishbone-cpu")
    session = _session(artifact, tmp)
    selection = _selection(component)
    yield {"artifact": artifact, "component": component, "session": session,
           "selection": selection}
    session.close() if hasattr(session, "close") else None


@pytest.fixture()
def bound(world):
    adapter = wc.bind_wishbone_cpu_adapter(
        component=world["component"], session=world["session"],
        selection=world["selection"])
    yield adapter
    adapter.close()


def refuse(code: str, call):
    with pytest.raises(GenericRuntimeRefused) as caught:
        call()
    assert caught.value.code == code, (caught.value.code, code,
                                       caught.value.document())
    return caught.value


def _document(world):
    return world["artifact"].runtime_document


# ---------------------------------------------------------------------------
# Registration document and pins
# ---------------------------------------------------------------------------

def test_registration_document_and_pin_shape(world):
    document = wc.registration_document()
    assert wc.CPU_ADAPTER_ID == "wishbone.cpu.v1"
    assert wc.CPU_ADAPTER_VERSION == "1"
    assert document["adapter_id"] == "wishbone.cpu.v1"
    assert document["role"] == "cpu"
    assert document["protocol"] == ["wishbone", "classic"]
    assert document["template"] == ["cpu.wishbone", "1", "no-err-stall"]
    assert document["semantic_kinds"] == ["cpu.wishbone.v1"]
    assert document["address_units"] == ["byte"]
    assert document["completion_kind"] == "cycle_strobe_held_until_ack"
    assert document["operations"] == ["read", "write"]
    assert document["drives_cpu"] is False
    assert document["error_observed"] is False
    assert document["stall_observed"] is False
    assert document["software_only"] is False
    assert document["session_class"] == (
        "myfuzz.local_harness.wishbone_cpu_session."
        "GeneratedWishboneCpuSession")
    assert document["implementation_sha256"] == wc.implementation_sha256()
    assert document["implementation_pin"] == wc.implementation_sha256()
    state = wc.registration_state()
    if state["registered"]:
        assert wc.selection_implementation_pin()[0] == (
            state["registry_implementation_sha256"])
    else:
        assert wc.selection_implementation_pin() == (
            wc.implementation_sha256(), False)


# ---------------------------------------------------------------------------
# Certified ABI facts derived from the artifact
# ---------------------------------------------------------------------------

def test_facts_come_from_the_executor_binding(world):
    facts = wc.derive_wishbone_cpu_abi_facts(
        runtime_document=_document(world), instance_id="processor",
        endpoint_id=ENDPOINT, template=wc.WISHBONE_CPU_TEMPLATE,
        instruction_endpoints=())
    assert type(facts) is wc.WishboneCpuAbiFacts
    assert facts.instance_id == "processor"
    assert facts.endpoint_id == ENDPOINT
    assert facts.function == "memory_master"
    assert facts.protocol == ("wishbone", "classic")
    assert facts.template == ("cpu.wishbone", "1", "no-err-stall")
    assert dict(facts.roles) == {
        "cyc": 1, "stb": 1, "we": 1, "adr": 32, "dat_w": 32, "sel": 4,
        "ack": 1, "dat_r": 32}
    assert facts.request_roles == tuple(sorted(
        ("cyc", "stb", "we", "adr", "dat_w", "sel")))
    assert facts.response_roles == ("ack", "dat_r")
    assert facts.data_width == 32
    assert facts.address_width == 32
    # A byte-addressed master: the target adapter converts to a word index.
    assert facts.address_units == "byte"
    assert facts.byte_enable_width == 4
    assert facts.read_select == "zero_full_word_data"
    assert facts.write_capable is True
    assert facts.read_capable is True
    assert facts.max_outstanding == 1
    # No ERR/STALL role exists on this master, so none is claimed.
    assert facts.error_observed is False
    assert facts.stall_observed is False
    assert facts.boot_base == 0
    assert facts.first_fetch_verification == "runtime_observation_required"
    assert facts.instruction_identity_observation == (
        _document(world)["instruction_identity_observation"])
    assert facts.sha256() == replace(facts).sha256()


def test_facts_ignore_the_instance_name(world):
    first = wc.derive_wishbone_cpu_abi_facts(
        runtime_document=_document(world), instance_id="processor",
        endpoint_id=ENDPOINT, template=wc.WISHBONE_CPU_TEMPLATE,
        instruction_endpoints=())
    second = wc.derive_wishbone_cpu_abi_facts(
        runtime_document=_document(world), instance_id="another_cpu",
        endpoint_id=ENDPOINT, template=wc.WISHBONE_CPU_TEMPLATE,
        instruction_endpoints=())
    left = first.document()
    right = second.document()
    assert left.pop("instance_id") == "processor"
    assert right.pop("instance_id") == "another_cpu"
    assert left == right


def test_facts_refuse_another_artifact_kind(world):
    document = dict(_document(world))
    document["kind"] = "obi_cpu"
    error = refuse("generic-semantic-unsupported",
                   lambda: wc.derive_wishbone_cpu_abi_facts(
                       runtime_document=document, instance_id="processor",
                       endpoint_id=ENDPOINT,
                       template=wc.WISHBONE_CPU_TEMPLATE,
                       instruction_endpoints=()))
    assert error.detail == {"expected": "wishbone_cpu", "actual": "obi_cpu"}


def test_facts_refuse_wrong_protocol_and_template(world):
    for protocol in (["obi", "1"], ["wishbone", "pipelined"]):
        document = _mutated(world, protocol=protocol)
        error = refuse("generic-template-mismatch",
                       lambda document=document: wc.derive_wishbone_cpu_abi_facts(
                           runtime_document=document, instance_id="processor",
                           endpoint_id=ENDPOINT,
                           template=wc.WISHBONE_CPU_TEMPLATE,
                           instruction_endpoints=()))
        assert error.pointer == "/artifact/endpoints/protocol"
    refuse("generic-template-mismatch", lambda: wc.derive_wishbone_cpu_abi_facts(
        runtime_document=_document(world), instance_id="processor",
        endpoint_id=ENDPOINT, template=("cpu.obi", "1", "read-write"),
        instruction_endpoints=()))


@pytest.mark.parametrize("role", ["err", "rty", "stall"])
def test_facts_refuse_error_or_stall_roles(world, role):
    document = _mutated(world, extra_role=(role, 1))
    error = refuse("generic-template-mismatch",
                   lambda: wc.derive_wishbone_cpu_abi_facts(
                       runtime_document=document, instance_id="processor",
                       endpoint_id=ENDPOINT,
                       template=wc.WISHBONE_CPU_TEMPLATE,
                       instruction_endpoints=()))
    assert error.detail["reason"] == "role-not-present-on-wishbone-classic-cpu"


def test_facts_refuse_incomplete_or_widened_roles(world):
    error = refuse("generic-template-mismatch",
                   lambda: wc.derive_wishbone_cpu_abi_facts(
                       runtime_document=_mutated(world, drop_role="sel"),
                       instance_id="processor", endpoint_id=ENDPOINT,
                       template=wc.WISHBONE_CPU_TEMPLATE,
                       instruction_endpoints=()))
    assert error.detail["missing"] == ["sel"]
    error = refuse("generic-template-mismatch",
                   lambda: wc.derive_wishbone_cpu_abi_facts(
                       runtime_document=_mutated(world, widen=("sel", 8)),
                       instance_id="processor", endpoint_id=ENDPOINT,
                       template=wc.WISHBONE_CPU_TEMPLATE,
                       instruction_endpoints=()))
    assert error.pointer == "/artifact/endpoints/roles/sel"
    error = refuse("generic-template-mismatch",
                   lambda: wc.derive_wishbone_cpu_abi_facts(
                       runtime_document=_mutated(world, widen=("dat_r", 16)),
                       instance_id="processor", endpoint_id=ENDPOINT,
                       template=wc.WISHBONE_CPU_TEMPLATE,
                       instruction_endpoints=()))
    assert error.pointer == "/artifact/endpoints/roles/dat_r"


def test_facts_refuse_profile_fact_disagreement(world):
    document = _mutated(world, declared={"address_units": "word"})
    error = refuse("generic-template-mismatch",
                   lambda: wc.derive_wishbone_cpu_abi_facts(
                       runtime_document=document, instance_id="processor",
                       endpoint_id=ENDPOINT,
                       template=wc.WISHBONE_CPU_TEMPLATE,
                       instruction_endpoints=()))
    assert error.detail["reason"] == "declared-facts-disagree-with-role-rows"


def test_facts_require_the_measured_instruction_identity(world):
    document = _mutated(world, drop_instruction_identity=True)
    error = refuse("generic-semantic-unsupported",
                   lambda: wc.derive_wishbone_cpu_abi_facts(
                       runtime_document=document, instance_id="processor",
                       endpoint_id=ENDPOINT,
                       template=wc.WISHBONE_CPU_TEMPLATE,
                       instruction_endpoints=()))
    assert error.pointer == "/artifact/instruction_identity_observation"


def _mutated(world, *, protocol=None, extra_role=None, drop_role=None,
             widen=None, declared=None, drop_instruction_identity=False):
    import copy
    document = copy.deepcopy(_document(world))
    binding = document["selected_template"]["executor"]["binding"]
    endpoint = binding["endpoints"][0]
    if protocol is not None:
        endpoint["protocol"] = list(protocol)
    if extra_role is not None:
        endpoint["roles"].append({"role": extra_role[0], "width": extra_role[1],
                                  "direction": "input", "physical_port": "x"})
    if drop_role is not None:
        endpoint["roles"] = [row for row in endpoint["roles"]
                             if row["role"] != drop_role]
    if widen is not None:
        for row in endpoint["roles"]:
            if row["role"] == widen[0]:
                row["width"] = widen[1]
    if declared:
        binding["declared_profile_facts"].update(declared)
    if drop_instruction_identity:
        document.pop("instruction_identity_observation")
    return document


# ---------------------------------------------------------------------------
# Binding: exact session, selection, cross-protocol refusals
# ---------------------------------------------------------------------------

def test_bind_pins_the_real_session_and_facts(world, bound):
    assert bound.component_instance_id == "processor"
    assert bound.adapter_id == wc.CPU_ADAPTER_ID == "wishbone.cpu.v1"
    assert bound.adapter_version == wc.CPU_ADAPTER_VERSION == "1"
    assert bound.endpoint_id == ENDPOINT
    assert bound.protocol == ("wishbone", "classic")
    assert bound.template == ("cpu.wishbone", "1", "no-err-stall")
    assert bound.semantic_kind == "cpu.wishbone.v1"
    assert bound.address_units == "byte"
    assert bound.drives_cpu is False
    assert len(bound.binding_sha256) == 64
    assert bound.implementation_sha256 == wc.implementation_sha256()
    assert bound.abi_facts.artifact_sha256 == world["component"].artifact_sha256
    assert isinstance(bound.driver, CpuDriver)
    assert isinstance(bound, BoundProtocolAdapter)
    bound.assert_current()


def test_program_slots_and_step_map_are_facts_only(world, bound):
    slots = bound.program_slots
    assert set(slots) == {"instruction.boot", "data." + ENDPOINT}
    boot = slots["instruction.boot"]
    assert boot["boot_base"] == 0
    assert boot["address_width"] == 32
    assert boot["instr_width"] == 32
    assert boot["address_units"] == "byte"
    data = slots["data." + ENDPOINT]
    assert data["address_units"] == "byte"
    assert data["byte_enable_width"] == 4
    assert data["read_select"] == "zero_full_word_data"
    assert data["function"] == "memory_master"
    step = bound.local_step_map
    assert step["schema_version"] == "wishbone_cpu_local_step_map.v1"
    assert step["max_local_ticks_per_step"] == 1
    assert step["max_transaction_events_per_step"] == 1
    assert step["no_error_or_stall_role"] is True
    assert step["defer_mmio"] is True
    assert step["max_mmio_target_accesses_per_step"] == 0
    assert step["pending_responses"] == 0
    # The maps are copies: mutating a returned document changes nothing.
    slots["instruction.boot"]["boot_base"] = 0x1000
    step["defer_mmio"] = False
    assert bound.program_slots["instruction.boot"]["boot_base"] == 0
    assert bound.local_step_map["defer_mmio"] is True
    # Nothing in this module drives the CPU.
    source = Path(wc.__file__).read_text(encoding="utf-8")
    assert ".step_local(" not in source
    assert "execute_instruction" not in source


def test_bind_refuses_foreign_and_cross_protocol_selections(world):
    error = refuse("generic-adapter-missing",
                   lambda: wc.bind_wishbone_cpu_adapter(
                       component=world["component"], session=world["session"],
                       selection=_selection(world["component"],
                                            adapter_id="obi.cpu.v1")))
    assert error.detail["expected_id"] == "wishbone.cpu.v1"
    error = refuse("generic-binding-drift",
                   lambda: wc.bind_wishbone_cpu_adapter(
                       component=world["component"], session=world["session"],
                       selection=_selection(world["component"], pin="0" * 64)))
    assert error.detail["reason"] == (
        "registry-implementation-changed-since-import")
    error = refuse("generic-plan-mismatch",
                   lambda: wc.bind_wishbone_cpu_adapter(
                       component=world["component"], session=world["session"],
                       selection=_selection(world["component"],
                                            semantic_sha256="0" * 64)))
    assert error.detail["reason"] == (
        "selection-does-not-belong-to-this-component")
    # An OBI CPU adapter must not accept this Wishbone descriptor.
    error = refuse("generic-semantic-unsupported",
                   lambda: obi_cpu._descriptor_cpu_endpoint(
                       world["component"]))
    assert error.detail["reason"] == "obi-cpu-endpoint-required"
    # And this adapter must not accept an OBI CPU descriptor.
    obi_like = _component(world["artifact"],
                          endpoint_overrides={
                              "protocol": ["obi", "1"],
                              "semantic_kind": "cpu.obi.v1"})
    error = refuse("generic-semantic-unsupported",
                   lambda: wc._descriptor_cpu_endpoint(obi_like))
    assert error.detail["reason"] == "wishbone-classic-cpu-endpoint-required"


def test_bind_refuses_an_unrelated_session(world):
    for wrong in (object(), SimpleNamespace(artifact=world["artifact"])):
        error = refuse("generic-binding-drift",
                       lambda wrong=wrong: wc.bind_wishbone_cpu_adapter(
                           component=world["component"], session=wrong,
                           selection=world["selection"]))
        assert error.detail["reason"] == (
            "exact-GeneratedWishboneCpuSession-required")


def test_bind_refuses_artifact_and_semantic_digest_drift(world):
    # Each component below is internally consistent but does not describe the
    # live artifact, so the artifact checks refuse instead of trusting it.
    wrong = _component(world["artifact"], artifact_sha256="0" * 64)
    error = refuse("generic-source-unverified",
                   lambda: wc.bind_wishbone_cpu_adapter(
                       component=wrong, session=world["session"],
                       selection=_selection(wrong)))
    assert error.detail["reason"] == "artifact-digest-mismatch"
    wrong = _component(world["artifact"], semantic_sha256="0" * 64)
    error = refuse("generic-source-unverified",
                   lambda: wc.bind_wishbone_cpu_adapter(
                       component=wrong, session=world["session"],
                       selection=_selection(wrong)))
    assert error.detail["reason"] == "semantic-contract-digest-mismatch"


def test_bind_refuses_a_descriptor_that_disagrees_with_the_abi(world):
    component = _component(world["artifact"],
                           endpoint_overrides={"address_width": 64})
    error = refuse("generic-template-mismatch",
                   lambda: wc.bind_wishbone_cpu_adapter(
                       component=component, session=world["session"],
                       selection=_selection(component)))
    assert error.detail["reason"] == (
        "descriptor-widths-do-not-match-artifact-abi")


def test_assert_current_detects_artifact_drift(world):
    adapter = wc.bind_wishbone_cpu_adapter(
        component=world["component"], session=world["session"],
        selection=world["selection"])
    original = world["session"].artifact
    try:
        world["session"].artifact = SimpleNamespace(runtime_document={})
        error = refuse("generic-binding-drift", adapter.assert_current)
        assert error.detail["reason"] == "session-artifact-replaced"
    finally:
        world["session"].artifact = original
    adapter.assert_current()
    adapter.close()
    refuse("generic-provider-closed", adapter.assert_current)


def test_surface_document_is_the_admission_contract(world):
    surface = wc.wishbone_cpu_surface_document(world["artifact"])
    assert surface["schema_version"] == "wishbone_cpu_execution_surface.v1"
    assert surface["kind"] == "cpu.wishbone.v1"
    assert surface["artifact_sha256"] == world["component"].artifact_sha256
    assert surface["profile_sha256"] == world["artifact"].plan.profile_sha256
    assert surface["boot_contract"]["configured_boot_base"] == 0
    assert surface["instruction_identity_observation"] == (
        _document(world)["instruction_identity_observation"])
    assert surface["instruction_endpoints"] == []
    assert [row["endpoint_id"] for row in surface["endpoints"]] == [ENDPOINT]
    assert surface["endpoints"][0]["protocol"] == ["wishbone", "classic"]
    assert wc._digest(surface) == world["component"].semantic_contract_sha256
