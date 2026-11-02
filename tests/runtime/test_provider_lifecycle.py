"""G3: provider lifecycle, identity revocation and the OBI CPU boundary.

Software only.  Prepared operations are process-local members: an equal
dataclass value, a handle from another provider or a hand-built reconstruction
never continues.  Session reset / provider close revoke live operations, and
module/ABI/artifact drift refuses the binding instead of being re-baselined.

The OBI CPU half checks the certified ABI facts derived from the real artifact;
nothing here drives the CPU.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import pytest

from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.runtime.adapters import apb3_storage, obi_cpu
from myfuzz.runtime.adapters.apb3_storage import (
    bind_storage_adapter,
    declare_target_route,
)
from myfuzz.runtime.adapters.contracts import (
    PreparedTargetOperation,
    ProviderProgress,
    TargetRequest,
    operation_id_for,
)
from myfuzz.runtime.adapters.obi_cpu import (
    CPU_ADAPTER_ID,
    bind_cpu_adapter,
    derive_cpu_abi_facts,
)
from myfuzz.runtime.admission import verify_component
from myfuzz.runtime.contracts import (
    CapabilityRequirement,
    GenericRuntimeRefused,
    VerifiedComponent,
    canonical_json_bytes,
)
from myfuzz.runtime.evidence.contracts import EffectEvidence, EvidenceRef
from myfuzz.runtime.preparation import create_preparation
from myfuzz.runtime.registry import select_adapter
from myfuzz.scenario.apb_storage_register_version import (
    ApbStorageRegisterVersionAuthority,
)
from myfuzz.scenario.ledger import TransactionKey
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.router import DataflowRouter, DeviceWindow

ROOT = Path(__file__).resolve().parents[2]
TIMER = ROOT / "configs/scenarios/compiled-f4-obi-apb-timer"
WINDOW_BASE = 0x40001000
CANONICAL_ADDRESS = WINDOW_BASE + 4


@pytest.fixture(scope="module")
def prepared(tmp_path_factory):
    output = tmp_path_factory.mktemp("g3-provider-lifecycle")
    context = create_preparation(
        base_dir=ROOT,
        compose_path=TIMER / "compose.json",
        capability_paths=(TIMER / "test_capability.json",),
        supplement_path=TIMER / "execution_supplement.json",
        generated_dir=output / "generated",
        flow_ids=("F2", "F4"),
    )
    target = verify_component(context.artifact("peripheral"),
                              preparation=context, base_dir=ROOT)
    cpu = verify_component(context.artifact("processor"),
                           preparation=context, base_dir=ROOT)
    selection = select_adapter(target, _requirement(target.endpoints()[0]),
                               preparation=context)
    cpu_selection = select_adapter(cpu, _requirement(cpu.endpoints()[0]),
                                   preparation=context)
    route = declare_target_route(preparation=context, component=target,
                                 endpoint_id=target.endpoints()[0]["endpoint_id"])
    yield {
        "context": context,
        "artifact": context.artifact("peripheral"),
        "cpu_artifact": context.artifact("processor"),
        "component": target,
        "cpu_component": cpu,
        "selection": selection,
        "cpu_selection": cpu_selection,
        "route": route,
    }
    context.close()


def _requirement(endpoint: dict) -> CapabilityRequirement:
    return CapabilityRequirement(
        role=endpoint["role"], endpoint_id=endpoint["endpoint_id"],
        protocol=tuple(endpoint["protocol"]), template=tuple(endpoint["template"]),
        semantic_kind=endpoint["semantic_kind"],
        operations=tuple(endpoint["operations"]),
        data_width=endpoint["data_width"],
        address_width=endpoint["address_width"],
        max_outstanding=endpoint["max_outstanding"],
        completion_kind=endpoint["completion_kind"],
        byte_enable_required=endpoint["byte_enable"],
        address_units=endpoint["address_units"],
        evidence_obligations=tuple(endpoint["evidence_capabilities"]))


def _key(sequence: int = 1) -> TransactionKey:
    return TransactionKey("execution-g3", "case-g3", "processor", 0,
                          "processor.data", sequence)


def _ref() -> EvidenceRef:
    return EvidenceRef("processor", 3, "cpu_acceptance")


def _write(value: int = 0x11112222) -> TargetRequest:
    return TargetRequest(path_id="F4:ram.image", source_ref=_ref(),
                         address=CANONICAL_ADDRESS, operation="write",
                         write_data=value, byte_enable=15, size_bytes=4)


def _read() -> TargetRequest:
    return TargetRequest(path_id="F4:ram.image", source_ref=_ref(),
                         address=CANONICAL_ADDRESS, operation="read",
                         write_data=None, byte_enable=15, size_bytes=4)


def refuse(code: str, call):
    with pytest.raises(GenericRuntimeRefused) as caught:
        call()
    assert caught.value.code == code, (caught.value.code, code,
                                       caught.value.document())
    return caught.value


def _fixture(prepared, program, *, max_ticks=12):
    return apb3_storage._software_storage_fixture(
        component=prepared["component"], artifact=prepared["artifact"],
        route=prepared["route"], program=program, max_ticks=max_ticks)


@pytest.fixture()
def real_pair(prepared, tmp_path):
    session = GeneratedApb3RegisterSession(
        prepared["artifact"], base_dir=ROOT, cache_dir=tmp_path / "cache")
    return session, ApbStorageRegisterVersionAuthority(session)


def _bind_real(prepared, real_pair, **kwargs):
    session, _ = real_pair
    return bind_storage_adapter(component=prepared["component"],
                                session=session,
                                selection=prepared["selection"],
                                route=prepared["route"], **kwargs)


# ---------------------------------------------------------------------------
# Issuance, idempotency and payload identity
# ---------------------------------------------------------------------------

def test_repeated_prepare_returns_the_same_issued_handle(prepared):
    fixture = _fixture(prepared, [
        {"phases": ["setup", "access", "response"], "rdata": 0x10},
        {"phases": ["setup", "access", "response"], "rdata": 0x10},
    ])
    provider = fixture.provider
    first = provider.prepare(_key(), _read())
    second = provider.prepare(_key(), _read())
    assert first is second
    assert provider.operation_count == 1
    progress = provider.advance(first, 12)
    assert progress.status == "completed"
    # A completed operation returns the recorded result; it is never re-issued.
    again = provider.advance(second, 12)
    assert again is progress
    assert len(fixture.session.calls) == 1


def test_same_key_with_another_payload_is_refused(prepared):
    fixture = _fixture(prepared, [])
    provider = fixture.provider
    provider.prepare(_key(), _write(0x11112222))
    error = refuse("generic-plan-mismatch",
                   lambda: provider.prepare(_key(), _write(0x33334444)))
    assert error.pointer == "/key"
    assert error.detail["reason"] == "same-key-different-payload"
    error = refuse("generic-plan-mismatch",
                   lambda: provider.prepare(_key(), _read()))
    assert error.detail["reason"] == "same-key-different-payload"
    assert provider.operation_count == 1


def test_another_key_creates_another_operation(prepared):
    fixture = _fixture(prepared, [
        {"phases": ["setup", "access", "response"], "rdata": 1},
        {"phases": ["setup", "access", "response"], "rdata": 2},
    ])
    provider = fixture.provider
    first = provider.prepare(_key(1), _read())
    second = provider.prepare(_key(2), _read())
    assert first is not second
    assert first.operation_id != second.operation_id
    assert provider.operation_count == 2
    assert provider.advance(first, 12).status == "completed"
    assert provider.advance(second, 12).status == "completed"
    assert len(fixture.session.calls) == 2


def test_hand_built_and_foreign_handles_are_refused(prepared):
    fixture = _fixture(prepared, [])
    provider = fixture.provider
    handle = provider.prepare(_key(), _write())
    forged = PreparedTargetOperation(
        key=handle.key, operation_id=handle.operation_id,
        request_sha256=handle.request_sha256, route_sha256=handle.route_sha256,
        binding_sha256=handle.binding_sha256)
    assert forged == handle and forged is not handle
    for call in (lambda: provider.advance(forged, 12),
                 lambda: provider.complete(forged)):
        error = refuse("generic-binding-drift", call)
        assert error.detail["reason"] == "not-issued-by-this-process"
    # A handle issued by a different provider of the same component is foreign too.
    other = _fixture(prepared, []).provider
    other_handle = other.prepare(_key(), _write())
    refuse("generic-binding-drift", lambda: provider.advance(other_handle, 12))
    refuse("generic-binding-drift", lambda: provider.complete(other_handle))
    refuse("generic-contract-type", lambda: provider.advance("handle", 12))
    assert fixture.session.calls == []


def test_operation_identity_covers_key_request_route_and_binding(prepared):
    fixture = _fixture(prepared, [])
    provider = fixture.provider
    handle = provider.prepare(_key(), _write())
    expected = operation_id_for(
        key=handle.key, request_sha256=handle.request_sha256,
        route_sha256=handle.route_sha256, binding_sha256=handle.binding_sha256)
    assert handle.operation_id == expected
    assert handle.request_sha256 == _write().sha256()
    assert handle.route_sha256 == prepared["route"].sha256()
    assert handle.binding_sha256 == provider.binding_sha256


# ---------------------------------------------------------------------------
# Budget, completion ordering
# ---------------------------------------------------------------------------

def test_budget_refusals_happen_before_the_driver(prepared, real_pair,
                                                  monkeypatch):
    session, _ = real_pair
    calls = []
    monkeypatch.setattr(session, "routed_register_access",
                        lambda *a, **k: calls.append(a))
    adapter = _bind_real(prepared, real_pair)
    try:
        handle = adapter.provider.prepare(_key(), _write())
        bounded = session.max_local_ticks_per_register_access
        assert bounded == 37
        error = refuse("generic-provider-budget",
                       lambda: adapter.provider.advance(handle, 0))
        assert error.detail["reason"] == "zero-budget"
        error = refuse("generic-provider-budget",
                       lambda: adapter.provider.advance(handle, bounded - 1))
        assert error.detail["reason"] == "budget-below-bounded-access"
        assert error.detail["bounded_ticks"] == bounded
        refuse("generic-contract-type",
               lambda: adapter.provider.advance(handle, True))
        refuse("generic-contract-type",
               lambda: adapter.provider.advance(handle, -1))
        assert calls == []
        assert session.local_ticks == 0
    finally:
        adapter.close()


def test_complete_before_advance_is_refused(prepared):
    fixture = _fixture(prepared, [])
    provider = fixture.provider
    handle = provider.prepare(_key(), _write())
    error = refuse("generic-provider-incomplete",
                   lambda: provider.complete(handle))
    assert error.detail["reason"] == "advance-before-complete"


def test_complete_is_idempotent(prepared):
    fixture = _fixture(prepared, [
        {"phases": ["setup", "access", "response"], "rdata": 0x20}])
    provider = fixture.provider
    handle = provider.prepare(_key(), _read())
    progress = provider.advance(handle, 12)
    assert progress.status == "completed"
    first = provider.complete(handle)
    second = provider.complete(handle)
    assert first is second
    assert type(first) is EffectEvidence
    assert type(progress) is ProviderProgress


# ---------------------------------------------------------------------------
# Reset and close revocation
# ---------------------------------------------------------------------------

def test_reset_revokes_previously_prepared_operations(prepared):
    fixture = _fixture(prepared, [
        {"phases": ["setup", "access", "response"], "rdata": 0x30}])
    provider = fixture.provider
    handle = provider.prepare(_key(), _read())
    assert fixture.session.reset_epoch == 0
    fixture.session.reset_local()
    assert fixture.session.reset_epoch == 1
    error = refuse("generic-provider-stale",
                   lambda: provider.advance(handle, 12))
    assert error.detail["reason"] == "session-reset-or-case-change-since-prepare"
    refuse("generic-provider-stale", lambda: provider.complete(handle))
    assert fixture.session.calls == []
    # A new epoch issues a new operation that can be driven normally.
    fresh = provider.prepare(_key(), _read())
    assert fresh is not handle
    assert provider.advance(fresh, 12).status == "completed"


def test_close_revokes_handles_and_stops_the_adapter(prepared):
    fixture = _fixture(prepared, [
        {"phases": ["setup", "access", "response"], "rdata": 0x30}])
    provider = fixture.provider
    adapter = fixture.bound
    handle = provider.prepare(_key(), _read())
    progress = provider.advance(handle, 12)
    assert progress.status == "completed"
    adapter.close()
    adapter.close()
    refuse("generic-provider-closed", lambda: provider.prepare(_key(2), _read()))
    refuse("generic-provider-closed", lambda: provider.advance(handle, 12))
    refuse("generic-provider-closed", lambda: provider.complete(handle))
    refuse("generic-provider-closed", adapter.assert_current)
    assert provider.operation_count == 0
    assert provider.raw_events == {}


# ---------------------------------------------------------------------------
# Binding drift
# ---------------------------------------------------------------------------

def test_session_method_drift_invalidates_the_binding(prepared, real_pair,
                                                      monkeypatch):
    adapter = _bind_real(prepared, real_pair)
    try:
        handle = adapter.provider.prepare(_key(), _write())
        original = GeneratedApb3RegisterSession.routed_register_access

        def stolen(self, *args, **kwargs):
            raise AssertionError("replaced driver must never run")

        monkeypatch.setattr(GeneratedApb3RegisterSession,
                            "routed_register_access", stolen)
        error = refuse("generic-binding-drift", adapter.assert_current)
        assert "apb3-storage-adapter-drift" in error.detail["reason"]
        refuse("generic-binding-drift", lambda: adapter.provider.advance(handle, 64))
        monkeypatch.setattr(GeneratedApb3RegisterSession,
                            "routed_register_access", original)
        adapter.assert_current()
    finally:
        adapter.close()


def test_issuer_method_drift_invalidates_the_binding(prepared, real_pair,
                                                     monkeypatch):
    adapter = _bind_real(prepared, real_pair)
    try:
        original = ApbStorageRegisterVersionAuthority.consume
        monkeypatch.setattr(ApbStorageRegisterVersionAuthority, "consume",
                            lambda self, token: None)
        refuse("generic-binding-drift", adapter.assert_current)
        monkeypatch.setattr(ApbStorageRegisterVersionAuthority, "consume",
                            original)
        adapter.assert_current()
    finally:
        adapter.close()


def test_artifact_digest_drift_invalidates_the_binding(prepared, real_pair):
    session, _ = real_pair
    adapter = _bind_real(prepared, real_pair)
    document = session.artifact.runtime_document
    original = document["artifact_digest"]
    try:
        handle = adapter.provider.prepare(_key(), _write())
        document["artifact_digest"] = "0" * 64
        error = refuse("generic-binding-drift", adapter.assert_current)
        assert error.pointer in ("/artifact", "/session")
        refuse("generic-binding-drift", lambda: adapter.provider.advance(handle, 64))
    finally:
        document["artifact_digest"] = original
        adapter.close()


def test_selection_and_authority_must_be_current(prepared, real_pair):
    session, _ = real_pair
    drifted = replace(prepared["selection"], implementation_sha256="0" * 64)
    error = refuse("generic-binding-drift", lambda: bind_storage_adapter(
        component=prepared["component"], session=session, selection=drifted,
        route=prepared["route"]))
    assert error.detail["reason"] == "registry-implementation-changed-since-import"
    # A session without the registered storage-version authority cannot be bound.
    bare = GeneratedApb3RegisterSession(
        prepared["artifact"], base_dir=ROOT, cache_dir=ROOT / ".g3-bare-cache")
    try:
        error = refuse("generic-binding-drift", lambda: bind_storage_adapter(
            component=prepared["component"], session=bare,
            selection=prepared["selection"], route=prepared["route"]))
        assert error.detail["reason"] == "storage-version-authority-not-registered"
    finally:
        path = ROOT / ".g3-bare-cache"
        if path.exists():
            path.rmdir()


def test_forged_storage_descriptor_gets_no_binding(prepared, real_pair):
    session, _ = real_pair
    component = prepared["component"]
    document = deepcopy(component.document())
    document["semantic_contract_sha256"] = "1" * 64
    forged = VerifiedComponent(
        component.instance_id, component.source_sha256, component.profile_sha256,
        component.artifact_sha256, "1" * 64, canonical_json_bytes(document))
    error = refuse("generic-source-unverified", lambda: bind_storage_adapter(
        component=forged, session=session,
        selection=replace(prepared["selection"],
                          semantic_contract_sha256="1" * 64),
        route=prepared["route"]))
    assert error.detail["reason"] == "semantic-contract-digest-mismatch"


# ---------------------------------------------------------------------------
# OBI CPU boundary: facts derived from the artifact, never from the name
# ---------------------------------------------------------------------------

@pytest.fixture()
def cpu_session(prepared, tmp_path):
    class _StubTarget:
        def write_register(self, offset, value, *, be=15):
            raise AssertionError("no CPU step in G3")

        def read_register(self, offset):
            raise AssertionError("no CPU step in G3")

    memory = PersistentMemory(
        regions=(MemoryRegion("ram", 0x10000, 0x30000),),
        initialization_seed=0, max_initialized_bytes=1 << 20)
    router = DataflowRouter((DeviceWindow("peripheral", WINDOW_BASE, 4096,
                                          _StubTarget()),))
    return GeneratedCve2Session(prepared["cpu_artifact"], base_dir=ROOT,
                                cache_dir=tmp_path / "cpu-cache",
                                memory=memory, router=router)


def test_cpu_facts_come_from_the_artifact_abi(prepared):
    artifact = prepared["cpu_artifact"]
    document = artifact.runtime_document
    instruction = tuple(sorted(
        row.endpoint_id for row in artifact.plan.binding.endpoints
        if row.function == "instruction_memory_master"))
    facts = derive_cpu_abi_facts(
        runtime_document=document, instance_id="processor",
        endpoint_id="processor.data", template=("cpu.obi", "1", "read-write"),
        instruction_endpoints=instruction)
    assert facts.protocol == ("obi", "1")
    assert facts.function == "data_memory_master"
    assert facts.data_width == 32
    assert facts.address_width == 32
    assert facts.byte_enable_width == 4
    assert facts.boot_base == 0x10000
    assert facts.instruction_endpoints == instruction
    assert dict(facts.roles) == {"addr": 32, "be": 4, "error": 1, "gnt": 1,
                                 "rdata": 32, "req": 1, "rvalid": 1,
                                 "wdata": 32, "we": 1}
    # The instance name is copied, never used to derive a width or a role.
    renamed = derive_cpu_abi_facts(
        runtime_document=document, instance_id="renamed_cpu_instance",
        endpoint_id="processor.data", template=("cpu.obi", "1", "read-write"),
        instruction_endpoints=instruction)
    assert renamed.instance_id != facts.instance_id
    assert renamed.roles == facts.roles
    assert renamed.data_width == facts.data_width
    assert renamed.address_width == facts.address_width
    assert renamed.boot_base == facts.boot_base


def test_cpu_facts_refuse_wrong_kind_protocol_and_role(prepared):
    document = prepared["cpu_artifact"].runtime_document
    instruction = ("processor.instruction",)

    def derive(candidate):
        return derive_cpu_abi_facts(
            runtime_document=candidate, instance_id="processor",
            endpoint_id="processor.data",
            template=("cpu.obi", "1", "read-write"),
            instruction_endpoints=instruction)

    wrong_kind = deepcopy(document)
    wrong_kind["kind"] = "apb3_register_observe"
    error = refuse("generic-semantic-unsupported",
                   lambda: derive(wrong_kind))
    assert error.pointer == "/artifact/kind"

    wrong_protocol = deepcopy(document)
    for row in wrong_protocol["selected_template"]["executor"]["binding"]["endpoints"]:
        if row["endpoint_id"] == "processor.data":
            row["protocol"] = ["apb", "3"]
    error = refuse("generic-template-mismatch", lambda: derive(wrong_protocol))
    assert error.pointer == "/artifact/endpoints/protocol"

    wrong_function = deepcopy(document)
    for row in wrong_function["selected_template"]["executor"]["binding"]["endpoints"]:
        if row["endpoint_id"] == "processor.data":
            row["function"] = "mmio_slave"
    error = refuse("generic-template-mismatch", lambda: derive(wrong_function))
    assert error.pointer == "/artifact/endpoints/function"

    missing_role = deepcopy(document)
    for row in missing_role["selected_template"]["executor"]["binding"]["endpoints"]:
        if row["endpoint_id"] == "processor.data":
            row["roles"] = [role for role in row["roles"] if role["role"] != "be"]
    error = refuse("generic-template-mismatch", lambda: derive(missing_role))
    assert error.detail["reason"] == "incomplete-obi-data-abi"

    read_only = deepcopy(document)
    for row in read_only["selected_template"]["executor"]["binding"]["endpoints"]:
        if row["endpoint_id"] == "processor.data":
            row["roles"] = [role for role in row["roles"]
                            if role["role"] not in ("we", "wdata")]
    error = refuse("generic-template-mismatch", lambda: derive(read_only))
    assert error.detail["reason"] == "incomplete-obi-data-abi"

    bad_width = deepcopy(document)
    for row in bad_width["selected_template"]["executor"]["binding"]["endpoints"]:
        if row["endpoint_id"] == "processor.data":
            for role in row["roles"]:
                if role["role"] == "addr":
                    role["width"] = 16
    facts = derive(bad_width)
    assert facts.address_width == 16        # a fact, not silently accepted


def test_cpu_binding_exposes_facts_without_driving_the_cpu(prepared, cpu_session):
    adapter = bind_cpu_adapter(component=prepared["cpu_component"],
                               session=cpu_session,
                               selection=prepared["cpu_selection"])
    try:
        assert adapter.adapter_id == CPU_ADAPTER_ID == "obi.cpu.v1"
        assert adapter.adapter_version == "1"
        assert adapter.component_instance_id == "processor"
        assert adapter.endpoint_id == "processor.data"
        assert adapter.template == ("cpu.obi", "1", "read-write")
        assert adapter.protocol == ("obi", "1")
        assert len(adapter.binding_sha256) == 64
        assert adapter.abi_facts.surface_sha256 == (
            prepared["cpu_component"].semantic_contract_sha256)
        slots = adapter.program_slots
        assert slots["instruction.boot"]["boot_base"] == 0x10000
        assert slots["instruction.boot"]["endpoints"] == ["processor.instruction"]
        step_map = adapter.local_step_map
        assert step_map["max_local_ticks_per_step"] == 1
        assert step_map["max_transaction_events_per_step"] == 2
        assert step_map["defer_mmio"] is True
        assert step_map["pending_responses"] == 0
        adapter.assert_current()
        # Facts only: no CPU step, no instruction injection, no process.
        assert cpu_session.local_ticks == 0
        assert cpu_session.process is None
        assert cpu_session.pending_responses == 0
    finally:
        adapter.close()


def test_cpu_binding_refuses_foreign_session_and_descriptor(
        prepared, cpu_session):
    refuse("generic-binding-drift", lambda: bind_cpu_adapter(
        component=prepared["cpu_component"],
        session=object(), selection=prepared["cpu_selection"]))
    error = refuse("generic-plan-mismatch", lambda: bind_cpu_adapter(
        component=prepared["cpu_component"], session=cpu_session,
        selection=replace(prepared["cpu_selection"],
                          component_artifact_sha256="0" * 64)))
    assert error.detail["reason"] == "selection-does-not-belong-to-this-component"

    component = prepared["cpu_component"]
    document = deepcopy(component.document())
    document["endpoints"][0]["data_width"] = 64
    forged = VerifiedComponent(
        component.instance_id, component.source_sha256,
        component.profile_sha256, component.artifact_sha256,
        component.semantic_contract_sha256, canonical_json_bytes(document))
    error = refuse("generic-template-mismatch", lambda: bind_cpu_adapter(
        component=forged, session=cpu_session,
        selection=prepared["cpu_selection"]))
    assert error.detail["reason"] == (
        "descriptor-widths-do-not-match-artifact-abi")


def test_cpu_drift_invalidates_the_binding(prepared, cpu_session, monkeypatch):
    adapter = bind_cpu_adapter(component=prepared["cpu_component"],
                               session=cpu_session,
                               selection=prepared["cpu_selection"])
    try:
        original = GeneratedCve2Session._serve
        monkeypatch.setattr(GeneratedCve2Session, "_serve",
                            lambda *args, **kwargs: None)
        error = refuse("generic-binding-drift", adapter.assert_current)
        assert "obi-cpu-adapter-drift" in error.detail["reason"]
        monkeypatch.setattr(GeneratedCve2Session, "_serve", original)
        adapter.assert_current()
        adapter.close()
        refuse("generic-provider-closed", adapter.assert_current)
    finally:
        adapter.close()


def test_route_and_adapter_documents_are_documentary(prepared):
    document = apb3_storage.registration_document()
    assert document["adapter_id"] == "apb3.storage.v1"
    assert document["implementation_sha256"] == apb3_storage.implementation_sha256()
    assert document["software_only"] is False
    assert document["transport"] == {"host_alignment_bytes": 4,
                                     "register_bytes": 4, "byte_enable": 15}
    cpu_document = obi_cpu.registration_document()
    assert cpu_document["adapter_id"] == "obi.cpu.v1"
    assert cpu_document["drives_cpu"] is False
    assert cpu_document["implementation_sha256"] == obi_cpu.implementation_sha256()
    # Documents are not handles: no live object accepts them, and the software
    # fixture session is only reachable through the module-private hook.
    refuse("generic-binding-drift", lambda: bind_storage_adapter(
        component=prepared["component"],
        session=apb3_storage._software_storage_fixture(
            component=prepared["component"], artifact=prepared["artifact"],
            route=prepared["route"], program=[]).session,
        selection=prepared["selection"], route=prepared["route"]))
