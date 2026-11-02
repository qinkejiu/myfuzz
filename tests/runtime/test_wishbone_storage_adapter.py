"""G8.1: the real Wishbone storage target adapter and its bounded provider.

Software only.  The real ``GeneratedWishboneRegisterSession`` and the real
generated ``wishbone_register_observe`` artifact (carrying the sibling-owned
``wishbone_storage_probe.v1`` observation) are constructed in-process; no
Verilator build, no native process and no native token are ever started or
consumed.  Everything that would need a live native process is refused before
the session transport, and the registered-ack span checks are exercised through
the module-private software fixture whose evidence is always ``unsupported``.

The D3 ``register_access`` row and the ``PreparationContext`` are built here
because no Wishbone scenario fixture and no Wishbone admission verifier exist
yet; the artifact, session, source contract and protocol trace are real.
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
from myfuzz.local_harness.wishbone_register_session import (
    GeneratedWishboneRegisterSession,
)
from myfuzz.local_harness.wishbone_storage_probe_verification import (
    verified_wishbone_storage_observation,
)
from myfuzz.runtime.adapters import apb3_storage, wishbone_storage as ws
from myfuzz.runtime.adapters.contracts import (
    BoundProtocolAdapter,
    PreparedTargetOperation,
    ProviderProgress,
    TargetProvider,
    TargetRequest,
)
from myfuzz.runtime.contracts import (
    AdapterSelection,
    GenericRuntimeRefused,
    VerifiedComponent,
    canonical_json_bytes,
)
from myfuzz.runtime.evidence.contracts import EvidenceRef
from myfuzz.runtime.preparation import PreparationContext, PreparationInputs
from myfuzz.scenario.ledger import TransactionKey

ROOT = Path(__file__).resolve().parents[2]
ENDPOINT = "uart.bus"
WINDOW_BASE = 0x40002000
CANONICAL_ADDRESS = WINDOW_BASE
WORD1_ADDRESS = WINDOW_BASE + 4
BYTE_MISALIGNED_ADDRESS = WINDOW_BASE + 2
OUT_OF_WINDOW_ADDRESS = WINDOW_BASE + 16


def _artifact():
    request = load_local_harness_request(dict(
        schema_version="local_harness.v2",
        profile_path="configs/peripherals/zipcpu_uart/component_profile.json",
        instance_id="peripheral", reset_assert_ticks=2, reset_release_ticks=2,
        max_wait_cycles=16,
        tuning={
            "endpoint_policies": [dict(
                endpoint_id=ENDPOINT, template_id="target.wishbone",
                template_version="1",
                variant_id="word-addressed-registered-ack",
                max_outstanding=1)],
            "fixed_inputs": [dict(endpoint_id="uart.pins", role="rx", value=1),
                             dict(endpoint_id="uart.pins", role="cts_n", value=0)],
            "wishbone_storage_observations": [dict(
                endpoint_id=ENDPOINT,
                contract_id="zipcpu-wbuart.setup.storage.v1",
                register="SETUP")],
        }))
    plan = plan_local_harness(request, base_dir=ROOT)
    top = render_local_runtime(plan, render_local_harness(plan),
                               verify_local_source_lock(plan.profile,
                                                        base_dir=ROOT),
                               base_dir=ROOT)
    return render_local_driver(top, base_dir=ROOT)


def _descriptor(*, artifact, semantic_sha256, endpoint_overrides=None):
    endpoint = {
        "endpoint_id": ENDPOINT,
        "role": "target",
        "protocol": ["wishbone", "classic"],
        "template": ["target.wishbone", "1", "word-addressed-registered-ack"],
        "semantic_kind": "storage.rw.v1",
        "operations": ["read", "write"],
        "data_width": 32,
        "address_width": 2,
        "address_units": "word",
        "max_outstanding": 1,
        "completion_kind": "registered_ack",
        "byte_enable": True,
        "evidence_capabilities": sorted([
            "component_semantic_effect", "cross_component_consumption",
            "cross_component_source", "physical_protocol_sample"]),
    }
    endpoint.update(endpoint_overrides or {})
    return {
        "schema_version": "verified_component_descriptor.v1",
        "instance_id": "peripheral",
        "source_sha256": sha256(
            canonical_json_bytes(artifact.source_verification)).hexdigest(),
        "profile_sha256": artifact.plan.profile_sha256,
        "artifact_sha256": artifact.runtime_document["artifact_digest"],
        "semantic_contract_sha256": semantic_sha256,
        "source_verifier": {"id": "wishbone-storage-source.v1", "version": "1",
                            "implementation_sha256": "0" * 64},
        "endpoints": [endpoint],
    }


def _component(artifact, *, endpoint_overrides=None):
    _, semantic, _, _ = ws.artifact_contract_facts(
        artifact, base_dir=ROOT, endpoint_id=ENDPOINT,
        template=ws.WISHBONE_STORAGE_TEMPLATE)
    document = _descriptor(artifact=artifact, semantic_sha256=semantic.sha256_hex,
                           endpoint_overrides=endpoint_overrides)
    return VerifiedComponent(
        "peripheral", document["source_sha256"], document["profile_sha256"],
        document["artifact_sha256"], document["semantic_contract_sha256"],
        canonical_json_bytes(document))


def _selection(component, *, adapter_id=ws.STORAGE_ADAPTER_ID,
               pin=None, artifact_sha256=None, semantic_sha256=None):
    return AdapterSelection(
        adapter_id, "1",
        pin if pin is not None else ws.selection_implementation_pin()[0],
        artifact_sha256 or component.artifact_sha256,
        semantic_sha256 or component.semantic_contract_sha256)


def _register_access(**overrides):
    row = {
        "schema_version": "register_source_access.v1",
        "source_component": "processor",
        "source_endpoint": "processor.memory",
        "target_component": "peripheral",
        "target_endpoint": ENDPOINT,
        "device_id": "peripheral",
        "register": "SETUP",
        "field": "value",
        "register_offset": 0,
        "address": WINDOW_BASE,
        "window_base": WINDOW_BASE,
        "window_size": 16,
        "window_alignment": 16,
        "access_alignment": 4,
        "width_bytes": 4,
        "byte_enable_domain": "target_word_lanes",
        "allowed_byte_enables": [15],
        "operation": "write",
        "value_origin": "cpu_transaction_wdata",
        "register_origin": "bound_target_register_commit",
        "value_mask": 0x7FFFFFFF,
    }
    row.update(overrides)
    return row


def _path(*, access=None, endpoint_id=ENDPOINT, component="peripheral",
          protocol=("wishbone", "classic"), function="mmio_slave",
          flow_id="F4", status="executable"):
    return {
        "flow_id": flow_id,
        "status": status,
        "path_id": "F4:ram.image",
        "target": {"component": component},
        "endpoints": [{"instance_id": component, "endpoint_id": endpoint_id,
                       "protocol": list(protocol), "function": function}],
        "sources": [{"register_access": access or _register_access()}],
    }


def _preparation(artifact, component, *, paths):
    inputs = PreparationInputs(
        base_dir=ROOT, compose_path=ROOT / "compose.json",
        capability_paths=(), supplement_path=ROOT / "supplement.json",
        generated_dir=ROOT / "generated", flow_ids=("F2", "F4"))
    prepared = SimpleNamespace(
        artifacts={component.instance_id: artifact},
        inputs={"compiled": {"paths": list(paths)}}, supports={},
        request_document={}, capability_selection={})
    context = PreparationContext._build(
        inputs=inputs, prepared=prepared, source_pins={}, generated_pins={},
        input_digests={"d2": "0" * 64, "d3": "1" * 64})
    context._components.issue(component, snapshot=component.descriptor_bytes)
    return context


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    artifact = _artifact()
    component = _component(artifact)
    registered, semantic, facts, trace = ws.artifact_contract_facts(
        artifact, base_dir=ROOT, endpoint_id=ENDPOINT,
        template=ws.WISHBONE_STORAGE_TEMPLATE)
    context = _preparation(artifact, component, paths=[_path()])
    route = ws.declare_target_route(
        preparation=context, component=component, endpoint_id=ENDPOINT)
    selection = _selection(component)
    yield {
        "artifact": artifact,
        "component": component,
        "registered": registered,
        "semantic": semantic,
        "facts": facts,
        "trace": trace,
        "context": context,
        "route": route,
        "selection": selection,
    }
    context.close()


@pytest.fixture()
def session(world, tmp_path):
    return GeneratedWishboneRegisterSession(
        world["artifact"], base_dir=ROOT, cache_dir=tmp_path / "cache")


@pytest.fixture()
def bound(world, session):
    adapter = ws.bind_wishbone_storage_adapter(
        component=world["component"], session=session,
        selection=world["selection"], route=world["route"])
    yield adapter
    adapter.close()


def _key(sequence: int = 1) -> TransactionKey:
    return TransactionKey("execution-g81", "case-g81", "processor", 0,
                          "processor.data", sequence)


def _source_ref() -> EvidenceRef:
    return EvidenceRef("processor", 7, "cpu_acceptance")


def _write(value: int = 0x5A5A5A5A, *, address: int = CANONICAL_ADDRESS,
           byte_enable: int = 15, size_bytes: int = 4,
           path_id: str = "F4:ram.image") -> TargetRequest:
    return TargetRequest(path_id=path_id, source_ref=_source_ref(),
                         address=address, operation="write", write_data=value,
                         byte_enable=byte_enable, size_bytes=size_bytes)


def _read(*, address: int = CANONICAL_ADDRESS, byte_enable: int = 15,
          size_bytes: int = 4, path_id: str = "F4:ram.image") -> TargetRequest:
    return TargetRequest(path_id=path_id, source_ref=_source_ref(),
                         address=address, operation="read", write_data=None,
                         byte_enable=byte_enable, size_bytes=size_bytes)


def refuse(code: str, call):
    with pytest.raises(GenericRuntimeRefused) as caught:
        call()
    assert caught.value.code == code, (caught.value.code, code,
                                       caught.value.document())
    return caught.value


def _fixture(world, program, *, max_ticks=12):
    return ws._software_wishbone_storage_fixture(
        component=world["component"], artifact=world["artifact"],
        route=world["route"], program=program, max_ticks=max_ticks)


# ---------------------------------------------------------------------------
# Registration document, pins, source facts
# ---------------------------------------------------------------------------

def test_registration_document_and_pin_shape(world):
    document = ws.registration_document()
    assert ws.STORAGE_ADAPTER_ID == "wishbone.storage.v1"
    assert ws.STORAGE_ADAPTER_VERSION == "1"
    assert document["adapter_id"] == "wishbone.storage.v1"
    assert document["protocol"] == ["wishbone", "classic"]
    assert document["template"] == ["target.wishbone", "1",
                                    "word-addressed-registered-ack"]
    assert document["semantic_kinds"] == ["storage.rw.v1"]
    assert document["address_units"] == ["word"]
    assert document["role"] == "target"
    assert document["session_class"] == (
        "myfuzz.local_harness.wishbone_register_session."
        "GeneratedWishboneRegisterSession")
    assert document["issuer_class"] == "WishboneStorageRegisterVersionAuthority"
    assert document["transport"]["host_alignment_bytes"] == 4
    assert document["transport"]["byte_enable"] == 0xF
    assert document["transport"]["byte_enable_policy"] == "runtime_full_word_only"
    assert document["transport"]["address_units"] == "word"
    assert document["transport"]["error_role"] is None
    assert document["software_only"] is False
    # The pin is a digest of the pinned modules and the sibling witnesses.
    assert document["implementation_sha256"] == ws.implementation_sha256()
    assert document["implementation_pin"] == ws.implementation_sha256()
    pinned_witnesses = document["witness_modules"]
    assert "myfuzz.local_harness.wishbone_storage_probe_verification" in (
        pinned_witnesses)
    for module_name, digest in pinned_witnesses.items():
        assert len(digest) == 64
        assert module_name.startswith("myfuzz.")
    # Registry row is the lead's step; until it exists the pin is this module.
    state = ws.registration_state()
    if state["registered"]:
        assert state["registry_implementation_sha256"] == (
            ws.selection_implementation_pin()[0])
    else:
        assert ws.selection_implementation_pin() == (
            ws.implementation_sha256(), False)


def test_artifact_facts_are_derived_not_declared(world):
    facts = world["facts"]
    assert facts.instance_id == "peripheral"
    assert facts.endpoint_id == ENDPOINT
    assert facts.source_contract_id == "zipcpu-wbuart.setup.storage.v1"
    assert facts.source_contract_digest == world["registered"]["digest"]
    assert facts.register == "SETUP"
    assert facts.canonical_offset == 0
    # The conversion is real: byte offset 0 -> word index 0, and the word
    # address width comes from the reviewed row, not from the caller.
    assert facts.word_index == 0
    assert facts.address_units == "word"
    assert facts.address_width == 2
    assert facts.window_bytes == 16
    assert facts.alias_period_bytes == 16
    assert facts.host_alignment_bytes == 4
    assert facts.register_width == 32
    assert facts.max_wait_cycles == 16
    assert facts.stall_policy == "observed_zero_only"
    assert facts.has_error is False
    assert facts.storage_observation_present is True
    assert facts.observation_scope == "generated_expression_source_mapped"
    assert dict(facts.trace_roles) == {
        "cyc": 1, "stb": 1, "we": 1, "adr": 2, "dat_w": 32, "sel": 4,
        "ack": 1, "dat_r": 32, "stall": 1}
    assert facts.sha256() == replace(facts).sha256()
    # The semantic contract carries the Wishbone transport, not APB3.
    document = world["semantic"].document()
    assert document["endpoint"]["protocol"] == ["wishbone", "classic"]
    assert document["decode"]["address_units"] == "word"
    assert document["decode"]["alignment_bytes"] == 4
    assert document["issuer_contract"]["authority"] is False
    assert document["issuer_contract"]["single_use"] is True
    assert document["observations"][0]["native"] is True


def test_probe_document_is_the_sibling_verified_one(world):
    artifact = world["artifact"]
    observation = artifact.runtime_document["storage_observation"]
    assert observation["schema_version"] == ws.WISHBONE_STORAGE_OBSERVATION_SCHEMA
    assert observation["selection"]["endpoint_id"] == ENDPOINT
    assert observation["selection"]["register"] == "SETUP"
    assert observation["address_units"] == "word"
    # The sibling verifier accepts it (returns None: prospective, not proof).
    assert verified_wishbone_storage_observation(
        observation, artifact, base_dir=ROOT) is None
    # A tampered digest is refused before any fact is derived.
    tampered = dict(observation)
    tampered["digest"] = "0" * 64
    artifact.runtime_document["storage_observation"] = tampered
    try:
        refuse("generic-source-unverified", lambda: ws.artifact_contract_facts(
            artifact, base_dir=ROOT, endpoint_id=ENDPOINT,
            template=ws.WISHBONE_STORAGE_TEMPLATE))
    finally:
        artifact.runtime_document["storage_observation"] = observation


# ---------------------------------------------------------------------------
# Route: byte -> word index conversion and refusals
# ---------------------------------------------------------------------------

def test_route_records_the_word_index_conversion(world):
    route = world["route"]
    assert type(route) is ws.WishboneTargetRoute
    assert route.path_id == "F4:ram.image"
    assert route.device_id == "peripheral"
    assert route.endpoint_id == ENDPOINT
    assert route.window_base == WINDOW_BASE
    assert route.window_size == 16
    assert route.register == "SETUP"
    assert route.register_offset == 0
    assert route.word_index == 0
    assert route.address_units == "word"
    assert route.access_alignment == 4
    assert route.width_bytes == 4
    assert route.allowed_byte_enables == (15,)
    assert route.source_contract_id == "zipcpu-wbuart.setup.storage.v1"
    assert route.source_contract_digest == world["registered"]["digest"]
    # Same facts, same digest; the conversion is part of the identity.
    assert route.sha256() == replace(route).sha256()
    # A recorded word index that no longer matches the byte offset is refused by
    # the route itself: there is one conversion, not two sources of truth.
    error = refuse("generic-route-refused",
                   lambda: replace(route, word_index=1))
    assert error.detail["derived"] == 0
    # A self-consistent route at another byte offset would be another word.
    with pytest.raises(GenericRuntimeRefused):
        ws.WishboneTargetRoute(
            path_id=route.path_id, device_id=route.device_id,
            endpoint_id=route.endpoint_id, window_base=route.window_base,
            window_size=route.window_size, register=route.register,
            register_offset=2, word_index=1, address_units="word",
            access_alignment=4, width_bytes=4, allowed_byte_enables=(15,),
            declared_value_mask=0x7FFFFFFF, declared_operation="write",
            source_contract_id=route.source_contract_id,
            source_contract_digest=route.source_contract_digest)


def test_route_from_a_non_zero_window_base_converts_offsets(world):
    # A different window base is a different route, but offset 0 is still word 0.
    component = world["component"]
    context = _preparation(world["artifact"], component, paths=[
        _path(access=_register_access(window_base=0x80000000,
                                      address=0x80000000))])
    try:
        route = ws.declare_target_route(preparation=context, component=component,
                                        endpoint_id=ENDPOINT)
        assert route.window_base == 0x80000000
        assert route.register_offset == 0
        assert route.word_index == 0
        assert route.word_index == ws.wishbone_word_index(route.register_offset)
        assert route.sha256() != world["route"].sha256()
    finally:
        context.close()


def test_route_refuses_unaligned_and_non_certified_offsets(world):
    component = world["component"]
    # Byte offset 2 is not a whole word: the conversion itself refuses.
    unaligned = _preparation(world["artifact"], component, paths=[
        _path(access=_register_access(register_offset=2,
                                      address=WINDOW_BASE + 2))])
    try:
        error = refuse("generic-route-refused", lambda: ws.declare_target_route(
            preparation=unaligned, component=component, endpoint_id=ENDPOINT))
        assert error.detail["reason"].startswith("wishbone-storage-offset")
    finally:
        unaligned.close()
    # Byte offset 4 is a whole word, but word index 1 is not the SETUP row.
    wrong_word = _preparation(world["artifact"], component, paths=[
        _path(access=_register_access(register_offset=4,
                                      address=WINDOW_BASE + 4))])
    try:
        error = refuse("generic-route-refused", lambda: ws.declare_target_route(
            preparation=wrong_word, component=component, endpoint_id=ENDPOINT))
        assert error.detail["reason"] == (
            "route-offset-is-not-the-certified-word-index")
        assert error.detail["word_index"] == 1
    finally:
        wrong_word.close()


def test_route_refuses_wrong_endpoint_protocol_and_register(world):
    component = world["component"]
    error = refuse("generic-route-refused", lambda: ws.declare_target_route(
        preparation=world["context"], component=component,
        endpoint_id="uart.pins"))
    assert error.detail["reason"] == "certified-endpoint-required"
    # A prepared path that presents the endpoint as APB must not be routed.
    apb_path = _preparation(world["artifact"], component, paths=[
        _path(protocol=("apb", "3"))])
    try:
        error = refuse("generic-route-refused", lambda: ws.declare_target_route(
            preparation=apb_path, component=component, endpoint_id=ENDPOINT))
        assert error.detail["reason"] == (
            "prepared-path-wishbone-mmio-slave-endpoint-required")
    finally:
        apb_path.close()
    wrong_register = _preparation(world["artifact"], component, paths=[
        _path(access=_register_access(register="FIFO_STATUS"))])
    try:
        error = refuse("generic-route-refused", lambda: ws.declare_target_route(
            preparation=wrong_register, component=component,
            endpoint_id=ENDPOINT))
        assert error.detail["reason"] == (
            "route-register-does-not-match-certified-register")
    finally:
        wrong_register.close()
    two_paths = _preparation(world["artifact"], component,
                             paths=[_path(), _path()])
    try:
        error = refuse("generic-route-refused", lambda: ws.declare_target_route(
            preparation=two_paths, component=component, endpoint_id=ENDPOINT))
        assert error.detail["reason"] == "one-declared-register-route-required"
    finally:
        two_paths.close()


# ---------------------------------------------------------------------------
# Binding: exact session, selection and cross-protocol refusals
# ---------------------------------------------------------------------------

def test_bind_pins_the_real_session_and_facts(world, session):
    adapter = ws.bind_wishbone_storage_adapter(
        component=world["component"], session=session,
        selection=world["selection"], route=world["route"])
    try:
        assert adapter.component_instance_id == "peripheral"
        assert adapter.adapter_id == ws.STORAGE_ADAPTER_ID == (
            "wishbone.storage.v1")
        assert adapter.adapter_version == ws.STORAGE_ADAPTER_VERSION == "1"
        assert adapter.endpoint_id == ENDPOINT
        assert adapter.binding_sha256 == adapter.provider.binding_sha256
        assert len(adapter.binding_sha256) == 64
        assert adapter.semantic_contract.sha256_hex == (
            world["component"].semantic_contract_sha256)
        assert adapter.provider.software_only is False
        assert adapter.provider.route_sha256 == world["route"].sha256()
        assert isinstance(adapter.provider, TargetProvider)
        assert isinstance(adapter, BoundProtocolAdapter)
        assert adapter.implementation_sha256 == ws.implementation_sha256()
        adapter.assert_current()
    finally:
        adapter.close()


def test_bind_refuses_the_software_fixture_session(world):
    fixture = _fixture(world, [])
    error = refuse("generic-binding-drift",
                   lambda: ws.bind_wishbone_storage_adapter(
                       component=world["component"], session=fixture.session,
                       selection=world["selection"], route=world["route"]))
    assert error.detail["reason"] in ("software-fixture-session-refused",
                                      "session-subclass-replaced-transport")


def test_bind_refuses_a_subclass_that_replaces_the_transport(world, session):
    class _ForgedSession(type(session)):
        software_fixture = False

        def read_register(self, offset):  # pragma: no cover - must never run
            raise AssertionError("a replaced transport must never be bound")

    forged = _ForgedSession(world["artifact"], base_dir=ROOT,
                            cache_dir=ROOT / "unused")
    error = refuse("generic-binding-drift",
                   lambda: ws.bind_wishbone_storage_adapter(
                       component=world["component"], session=forged,
                       selection=world["selection"], route=world["route"]))
    assert error.detail["reason"] == "session-subclass-replaced-transport"
    assert error.detail["method"] == "read_register"


def test_bind_refuses_foreign_and_cross_protocol_selections(world, session):
    error = refuse("generic-adapter-missing",
                   lambda: ws.bind_wishbone_storage_adapter(
                       component=world["component"], session=session,
                       selection=_selection(world["component"],
                                            adapter_id="apb3.storage.v1"),
                       route=world["route"]))
    assert error.detail["expected_id"] == "wishbone.storage.v1"
    # A Wishbone selection pinned to another implementation is drift, not trust.
    error = refuse("generic-binding-drift",
                   lambda: ws.bind_wishbone_storage_adapter(
                       component=world["component"], session=session,
                       selection=_selection(world["component"], pin="0" * 64),
                       route=world["route"]))
    assert error.detail["reason"] == (
        "registry-implementation-changed-since-import")
    # A selection issued for another component must not bind this one.
    error = refuse("generic-plan-mismatch",
                   lambda: ws.bind_wishbone_storage_adapter(
                       component=world["component"], session=session,
                       selection=_selection(world["component"],
                                            artifact_sha256="0" * 64),
                       route=world["route"]))
    assert error.detail["reason"] == (
        "selection-does-not-belong-to-this-component")


def test_apb_adapter_refuses_the_wishbone_session_and_component(world, session):
    # The APB3 factory must not bind a Wishbone session/component even when it is
    # handed a Wishbone selection: the session class check refuses first.
    error = refuse("generic-binding-drift",
                   lambda: apb3_storage.bind_storage_adapter(
                       component=world["component"], session=session,
                       selection=world["selection"]))
    assert error.detail["reason"] == "exact-GeneratedApb3RegisterSession-required"
    # And the Wishbone adapter refuses an APB3/protocol artifact kind outright.
    fake = SimpleNamespace(
        runtime_document={"kind": "apb3_register_observe"},
        plan=world["artifact"].plan)
    error = refuse("generic-semantic-unsupported",
                   lambda: ws.artifact_contract_facts(
                       fake, base_dir=ROOT, endpoint_id=ENDPOINT,
                       template=ws.WISHBONE_STORAGE_TEMPLATE))
    assert error.detail["expected"] == "wishbone_register_observe"


def test_route_window_base_requires_the_same_pass_declaration(world, session):
    # The artifact does not know the SoC address map, so a self-consistent route
    # at another window base binds only as a declaration.
    shifted = replace(world["route"], window_base=0x90000000)
    declared = ws.bind_wishbone_storage_adapter(
        component=world["component"], session=session,
        selection=world["selection"], route=shifted)
    try:
        declared.assert_current()
    finally:
        declared.close()
    # With the issuing preparation the route is re-derived from the same-pass D3
    # document and compared byte for byte, so the shifted base is refused.
    error = refuse("generic-route-refused",
                   lambda: ws.bind_wishbone_storage_adapter(
                       component=world["component"], session=session,
                       selection=world["selection"], route=shifted,
                       preparation=world["context"]))
    assert error.detail["reason"] == "route-differs-from-same-pass-declaration"
    # A route whose register offset is not the certified word is refused even
    # without a preparation, because the artifact facts know the word.
    error = refuse("generic-route-refused",
                   lambda: ws.bind_wishbone_storage_adapter(
                       component=world["component"], session=session,
                       selection=world["selection"],
                       route=ws.WishboneTargetRoute(
                           path_id=world["route"].path_id,
                           device_id=world["route"].device_id,
                           endpoint_id=world["route"].endpoint_id,
                           window_base=world["route"].window_base,
                           window_size=world["route"].window_size,
                           register=world["route"].register,
                           register_offset=4, word_index=1,
                           address_units="word", access_alignment=4,
                           width_bytes=4, allowed_byte_enables=(15,),
                           declared_value_mask=0x7FFFFFFF,
                           declared_operation="write",
                           source_contract_id=world["route"].source_contract_id,
                           source_contract_digest=(
                               world["route"].source_contract_digest))))
    assert error.detail["reason"] == (
        "route-register-offset-is-not-the-certified-word")


def test_bind_without_route_keeps_prepare_closed(world, session):
    adapter = ws.bind_wishbone_storage_adapter(
        component=world["component"], session=session,
        selection=world["selection"])
    try:
        error = refuse("generic-route-refused",
                       lambda: adapter.provider.prepare(_key(), _write()))
        assert error.detail["reason"] == "route-not-declared"
    finally:
        adapter.close()


# ---------------------------------------------------------------------------
# prepare: conversion, alias, alignment, full-word select, budget
# ---------------------------------------------------------------------------

def test_prepare_has_no_side_effect(world, session, monkeypatch):
    calls = []
    monkeypatch.setattr(session, "read_register",
                        lambda *a, **k: calls.append(a))
    monkeypatch.setattr(session, "write_register",
                        lambda *a, **k: calls.append(a))
    adapter = ws.bind_wishbone_storage_adapter(
        component=world["component"], session=session,
        selection=world["selection"], route=world["route"])
    try:
        handle = adapter.provider.prepare(_key(), _write())
        assert type(handle) is PreparedTargetOperation
        assert handle.request_sha256 == _write().sha256()
        assert handle.route_sha256 == world["route"].sha256()
        assert handle.binding_sha256 == adapter.binding_sha256
        assert handle.key == _key()
        assert len(handle.operation_id) == 64
        assert calls == []
        assert session.local_ticks == 0
        assert session._sequence == 0
        assert list(session._samples) == []
        assert len(adapter.provider) == 1
        # Idempotent for the same key and payload.
        assert adapter.provider.prepare(_key(), _write()) is handle
    finally:
        adapter.close()


def test_prepare_refuses_non_alias_unaligned_and_out_of_window(world, bound):
    provider = bound.provider
    error = refuse("generic-route-refused",
                   lambda: provider.prepare(_key(), _write(address=WORD1_ADDRESS)))
    assert error.detail["reason"] == "not-the-certified-storage-word"
    assert error.detail["word_index"] == 1
    error = refuse("generic-route-refused",
                   lambda: provider.prepare(
                       _key(), _write(address=BYTE_MISALIGNED_ADDRESS)))
    assert error.detail["reason"] == "transport-alignment"
    error = refuse("generic-route-refused",
                   lambda: provider.prepare(
                       _key(), _write(address=OUT_OF_WINDOW_ADDRESS)))
    assert error.detail["reason"] == "outside-declared-window"
    error = refuse("generic-route-refused",
                   lambda: provider.prepare(
                       _key(), _write(path_id="F2:ram.image")))
    assert error.detail["declared"] == "F4:ram.image"
    assert len(provider) == 0


def test_prepare_refuses_non_full_word_select_and_payload(world, bound):
    provider = bound.provider
    for enables in (1, 3, 7, 14):
        error = refuse("generic-semantic-unsupported",
                       lambda enables=enables: provider.prepare(
                           _key(), _write(byte_enable=enables)))
        assert error.detail["reason"] == "runtime-full-word-sel-only"
        assert error.detail["expected"] == 15
    error = refuse("generic-semantic-unsupported",
                   lambda: provider.prepare(
                       _key(), _write(value=0x5A, size_bytes=2, byte_enable=3)))
    assert error.detail["reason"] == "registered-full-word-contract"
    # A write outside the declared writable mask is refused before any access.
    error = refuse("generic-route-refused",
                   lambda: provider.prepare(
                       _key(), _write(value=0x80000000 | 1)))
    assert error.detail["reason"] == "write-outside-declared-mask"
    refuse("generic-contract-type", lambda: provider.prepare(_key(), "nope"))


def test_prepare_refuses_a_different_payload_for_the_same_key(world, bound):
    provider = bound.provider
    provider.prepare(_key(1), _write(0x01020304))
    error = refuse("generic-plan-mismatch",
                   lambda: provider.prepare(_key(1), _write(0x05060708)))
    assert error.detail["reason"] == "same-key-different-payload"


def test_prepare_refuses_when_the_operation_budget_is_exhausted(
        world, session, monkeypatch):
    adapter = ws.bind_wishbone_storage_adapter(
        component=world["component"], session=session,
        selection=world["selection"], route=world["route"])
    monkeypatch.setattr(ws, "_MAX_OPERATIONS", 1)
    try:
        adapter.provider.prepare(_key(1), _write())
        error = refuse("generic-provider-budget",
                       lambda: adapter.provider.prepare(_key(2), _write()))
        assert error.detail["reason"] == (
            "operation-or-sample-capacity-exhausted")
        assert len(adapter.provider) == 1
    finally:
        adapter.close()


# ---------------------------------------------------------------------------
# advance/complete: real session refusal, foreign/tampered handles
# ---------------------------------------------------------------------------

def test_real_advance_refuses_before_the_transport(world, session, monkeypatch):
    calls = []

    def spy(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("a real non-running session must not be driven")

    monkeypatch.setattr(session, "read_register", spy)
    monkeypatch.setattr(session, "write_register", spy)
    adapter = ws.bind_wishbone_storage_adapter(
        component=world["component"], session=session,
        selection=world["selection"], route=world["route"])
    try:
        handle = adapter.provider.prepare(_key(), _write())
        error = refuse("generic-provider-closed",
                       lambda: adapter.provider.advance(handle, 64))
        assert error.detail["reason"] == "session-not-running"
        assert calls == []
        assert session.local_ticks == 0
        refuse("generic-provider-incomplete",
               lambda: adapter.provider.complete(handle))
    finally:
        adapter.close()


def test_provider_refuses_foreign_and_tampered_handles(world, session):
    first = ws.bind_wishbone_storage_adapter(
        component=world["component"], session=session,
        selection=world["selection"], route=world["route"])
    second = ws.bind_wishbone_storage_adapter(
        component=world["component"], session=session,
        selection=world["selection"], route=world["route"])
    try:
        handle = first.provider.prepare(_key(), _write())
        error = refuse("generic-binding-drift",
                       lambda: second.provider.advance(handle, 64))
        assert error.detail["reason"] == "not-issued-by-this-process"
        tampered = replace(handle, request_sha256="0" * 64)
        error = refuse("generic-binding-drift",
                       lambda: first.provider.advance(tampered, 64))
        assert error.detail["reason"] == "not-issued-by-this-process"
        error = refuse("generic-binding-drift",
                       lambda: first.provider.complete(tampered))
        assert error.detail["reason"] == "not-issued-by-this-process"
        # The genuine handle is still usable/known to its own provider.
        assert first.provider.operation_count == 1
    finally:
        first.close()
        second.close()


def test_provider_refuses_a_duplicate_completion(world):
    fixture = _fixture(world, [{"phases": ["request", "ack"], "rdata": 3}])
    provider = fixture.provider
    handle = provider.prepare(_key(), _read())
    provider.advance(handle, 12)
    first = provider.complete(handle)
    assert first.status == "unsupported"
    error = refuse("generic-binding-drift",
                   lambda: provider.complete(handle))
    assert error.detail["reason"] == "single-use-token-already-consumed"


def test_provider_refuses_a_stale_operation_after_a_reset(world):
    fixture = _fixture(world, [{"phases": ["request", "ack"], "rdata": 3}])
    provider = fixture.provider
    handle = provider.prepare(_key(), _read())
    # Fixture-only epoch bump: the real session's reset_local needs a live
    # process, but a reset is exactly a new reset_epoch for this provider.
    fixture.session.reset_epoch += 1
    error = refuse("generic-provider-stale",
                   lambda: provider.advance(handle, 12))
    assert error.detail["reason"] == "session-reset-or-case-change-since-prepare"


# ---------------------------------------------------------------------------
# advance: registered-ack span validation through the real code path
# ---------------------------------------------------------------------------

def test_fixture_completes_one_registered_ack_read(world):
    fixture = _fixture(world, [{
        "phases": ["idle", "request", "wait", "ack"], "rdata": 0xDEADBEEF}])
    provider = fixture.provider
    handle = provider.prepare(_key(), _read())
    progress = provider.advance(handle, 12)
    assert type(progress) is ProviderProgress
    assert progress.status == "completed"
    assert progress.advanced_ticks == 4
    assert progress.response_bytes == (0xDEADBEEF).to_bytes(4, "little")
    assert progress.reason_code is None
    kinds = [ref.kind for ref in progress.raw_refs]
    assert kinds[0] == "software_wishbone_storage_command"
    assert set(kinds[1:]) == {"software_wishbone_storage_tick_sample"}
    assert len(progress.raw_refs) == 5           # one command + four ticks
    assert all(ref.component == "peripheral" for ref in progress.raw_refs)
    # The real session API was used exactly once, with the converted offset.
    assert len(fixture.session.calls) == 1
    call = fixture.session.calls[0]
    assert call == {"offset": 0, "write": False, "value": 0, "be": 15}
    evidence = provider.complete(handle)
    assert evidence.status == "unsupported"
    assert evidence.scope == "component_semantic_effect"
    assert evidence.native_refs == ()
    assert evidence.source_refs == (_source_ref(),)
    assert evidence.binding_sha256 == provider.binding_sha256
    assert [name for name, _ in evidence.obligation_results] == sorted(
        name for name, _ in evidence.obligation_results)
    assert all(status == "unsupported"
               for _, status in evidence.obligation_results)
    events = provider.raw_events
    assert events
    assert {row["kind"] for row in events.values()} <= {
        "software_wishbone_storage_command", "software_wishbone_storage_tick_sample"}


def test_fixture_completes_one_registered_ack_write(world):
    fixture = _fixture(world, [{
        "phases": ["request", "wait", "wait", "ack"], "rdata": 0x11223344}])
    provider = fixture.provider
    handle = provider.prepare(_key(), _write(0x12345678))
    progress = provider.advance(handle, 12)
    assert progress.status == "completed"
    assert progress.advanced_ticks == 4
    assert progress.response_bytes == (0x11223344).to_bytes(4, "little")
    assert fixture.session.calls == [
        {"offset": 0, "write": True, "value": 0x12345678, "be": 15}]


@pytest.mark.parametrize("phases,reason", [
    (["request", "wait"], "wishbone-observation-invalid"),          # no ack
    (["request", "wait", "idle", "ack"], "wishbone-observation-invalid"),
    (["request", "request", "ack"], "wishbone-observation-invalid"),
    (["wait", "ack"], "wishbone-observation-invalid"),              # no request
    (["request", "ack", "ack"], "wishbone-observation-invalid"),
])
def test_fixture_refuses_a_malformed_registered_ack_span(world, phases, reason):
    fixture = _fixture(world, [{"phases": phases, "rdata": 1}])
    provider = fixture.provider
    handle = provider.prepare(_key(), _read())
    progress = provider.advance(handle, 12)
    assert progress.status == "uncertain_effect"
    assert progress.reason_code == reason
    assert progress.response_bytes is None


def test_fixture_refuses_an_observed_stall(world):
    fixture = _fixture(world, [{
        "phases": ["request", "wait", "ack"], "rdata": 5, "stall": 1}])
    provider = fixture.provider
    handle = provider.prepare(_key(), _read())
    progress = provider.advance(handle, 12)
    assert progress.status == "uncertain_effect"
    assert progress.reason_code == "wishbone-stall-observed"
    # A contradicted physical observation is never completed.
    evidence = provider.complete(handle)
    assert evidence.status == "unsupported"


def test_fixture_refuses_a_wait_cycle_bound_violation(world):
    fixture = _fixture(world, [{
        "phases": ["request"] + ["wait"] * 17 + ["ack"], "rdata": 1}],
        max_ticks=32)
    provider = fixture.provider
    progress = provider.advance(provider.prepare(_key(), _read()), 32)
    assert progress.status == "uncertain_effect"
    assert progress.reason_code == "wishbone-observation-invalid"


def test_fixture_refuses_a_read_payload_mismatch(world):
    # The measured dat_r disagrees with what the transport returned: the
    # provider must not believe either side.
    fixture = _fixture(world, [{
        "phases": ["request", "ack"], "rdata": 0x1234, "dat_r": 0x4321}])
    provider = fixture.provider
    progress = provider.advance(provider.prepare(_key(), _read()), 12)
    assert progress.status == "uncertain_effect"
    assert progress.reason_code == "response-payload-mismatch"


def test_fixture_driver_fault_and_refusal_are_distinguished(world):
    fixture = _fixture(world, [
        {"phases": ["request", "wait", "ack"], "rdata": 9,
         "fault_after_ticks": True},
        {"driver_refusal": True},
    ])
    provider = fixture.provider
    faulted = provider.advance(provider.prepare(_key(1), _read()), 12)
    assert faulted.status == "uncertain_effect"
    assert faulted.reason_code == "driver-failure"
    assert faulted.advanced_ticks == 3
    refused = provider.advance(provider.prepare(_key(2), _read()), 12)
    assert refused.status == "refused"
    assert refused.advanced_ticks == 0
    assert refused.response_bytes is None
    assert refused.raw_refs == ()
    assert refused.reason_code == "driver-refused-before-effect"


def test_advance_budget_is_enforced_before_the_transport(world):
    fixture = _fixture(world, [{"phases": ["request", "ack"], "rdata": 1}])
    provider = fixture.provider
    handle = provider.prepare(_key(), _read())
    error = refuse("generic-provider-budget",
                   lambda: provider.advance(handle, 0))
    assert error.detail["reason"] == "zero-budget"
    error = refuse("generic-provider-budget",
                   lambda: provider.advance(handle, 3))
    assert error.detail["reason"] == "budget-below-bounded-access"
    assert fixture.session.calls == []
    refuse("generic-contract-type", lambda: provider.advance(handle, True))
    # A sufficient grant runs the access exactly once.
    progress = provider.advance(handle, 12)
    assert progress.status == "completed"
    assert len(fixture.session.calls) == 1
    # A second advance returns the cached terminal result, never a re-access.
    again = provider.advance(handle, 12)
    assert again is progress
    assert len(fixture.session.calls) == 1


# ---------------------------------------------------------------------------
# Binding drift and lifecycle
# ---------------------------------------------------------------------------

def test_assert_current_detects_artifact_drift(world, session):
    adapter = ws.bind_wishbone_storage_adapter(
        component=world["component"], session=session,
        selection=world["selection"], route=world["route"])
    original = session.artifact
    try:
        session.artifact = SimpleNamespace(runtime_document={})
        error = refuse("generic-binding-drift", adapter.assert_current)
        assert error.detail["reason"] == "session-artifact-replaced"
    finally:
        session.artifact = original
    adapter.assert_current()
    adapter.close()
    refuse("generic-provider-closed", adapter.assert_current)
    refuse("generic-provider-closed",
           lambda: adapter.provider.prepare(_key(), _write()))


def test_provider_never_issues_or_consumes_a_native_token(world):
    source = Path(ws.__file__).read_text(encoding="utf-8")
    # The provider's only issuance is its own process-local operation authority;
    # the native version authority is never imported, constructed or consumed.
    assert "WishboneStorageRegisterVersionAuthority(" not in source
    assert ".consume(" not in source
    assert "_TOKENS" not in source
    assert "_AUTHORITIES" not in source
    assert "storage_version_basis" not in source
    fixture = _fixture(world, [{"phases": ["request", "ack"], "rdata": 1}])
    provider = fixture.provider
    handle = provider.prepare(_key(), _read())
    progress = provider.advance(handle, 12)
    assert progress.status == "completed"
    assert all(ref.kind.startswith("software_") for ref in progress.raw_refs)
    evidence = provider.complete(handle)
    assert evidence.native_refs == ()
    assert evidence.destination_refs == ()
    names = dict(evidence.obligation_results)
    assert names["storage_version_token"] == "unsupported"
    assert names["physical_protocol_sample"] == "unsupported"
    assert names["wishbone_target_response"] == "unsupported"
