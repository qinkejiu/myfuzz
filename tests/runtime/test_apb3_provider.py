"""G3: the real APB3 storage target provider and its APB3 boundary.

Software only.  The real ``GeneratedApb3RegisterSession`` and the real
``ApbStorageRegisterVersionAuthority`` are constructed without any native build
(construction does not start RTL); everything that would need a live native
process is either refused before the driver hook or exercised through the
module-private software fixture, whose evidence is always ``unsupported``.

No test here starts RTL, consumes a native token or claims an executed effect.
"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import pytest

from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
from myfuzz.runtime.adapters import apb3_storage
from myfuzz.runtime.adapters.apb3_storage import (
    STORAGE_ADAPTER_ID,
    STORAGE_ADAPTER_VERSION,
    TargetRoute,
    bind_storage_adapter,
    declare_target_route,
    implementation_sha256,
)
from myfuzz.runtime.adapters.contracts import (
    BoundProtocolAdapter,
    ProviderProgress,
    TargetProvider,
    TargetRequest,
)
from myfuzz.runtime.admission import verify_component
from myfuzz.runtime.contracts import (
    CapabilityRequirement,
    GenericRuntimeRefused,
)
from myfuzz.runtime.evidence.contracts import EvidenceRef
from myfuzz.runtime.preparation import create_preparation
from myfuzz.runtime.registry import select_adapter
from myfuzz.scenario.apb_storage_register_version import (
    ApbStorageRegisterVersionAuthority,
)
from myfuzz.scenario.ledger import TransactionKey

ROOT = Path(__file__).resolve().parents[2]
TIMER = ROOT / "configs/scenarios/compiled-f4-obi-apb-timer"

WINDOW_BASE = 0x40001000
WINDOW_SIZE = 4096
CANONICAL_ADDRESS = WINDOW_BASE + 4          # TIMER0_CTRL canonical offset
ALIAS_ADDRESS = WINDOW_BASE + 0x24           # PADDR[4:2] == 1 alias
HIGH_ALIAS_ADDRESS = WINDOW_BASE + 0x104     # another alias period
NON_ALIAS_ADDRESS = WINDOW_BASE + 8          # TIMER0_CMP, not the certified row
WORD_ADDRESS = WINDOW_BASE + 1               # word-unit confusion: 4 >> 2


@pytest.fixture(scope="module")
def prepared(tmp_path_factory):
    """One same-pass preparation; static only (no frontend/model/native)."""
    output = tmp_path_factory.mktemp("g3-apb3-provider")
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
    endpoint = target.endpoints()[0]
    selection = select_adapter(target, _requirement(endpoint), preparation=context)
    route = declare_target_route(preparation=context, component=target,
                                 endpoint_id=endpoint["endpoint_id"])
    yield {
        "context": context,
        "artifact": context.artifact("peripheral"),
        "component": target,
        "cpu_component": cpu,
        "selection": selection,
        "endpoint": endpoint,
        "route": route,
    }
    context.close()


def _requirement(endpoint: dict) -> CapabilityRequirement:
    return CapabilityRequirement(
        role=endpoint["role"],
        endpoint_id=endpoint["endpoint_id"],
        protocol=tuple(endpoint["protocol"]),
        template=tuple(endpoint["template"]),
        semantic_kind=endpoint["semantic_kind"],
        operations=tuple(endpoint["operations"]),
        data_width=endpoint["data_width"],
        address_width=endpoint["address_width"],
        max_outstanding=endpoint["max_outstanding"],
        completion_kind=endpoint["completion_kind"],
        byte_enable_required=endpoint["byte_enable"],
        address_units=endpoint["address_units"],
        evidence_obligations=tuple(endpoint["evidence_capabilities"]),
    )


@pytest.fixture()
def real_pair(prepared, tmp_path):
    """A fresh real session plus its real storage-version authority (no native)."""
    session = GeneratedApb3RegisterSession(
        prepared["artifact"], base_dir=ROOT, cache_dir=tmp_path / "cache")
    authority = ApbStorageRegisterVersionAuthority(session)
    return session, authority


@pytest.fixture()
def bound(prepared, real_pair):
    session, _ = real_pair
    adapter = bind_storage_adapter(component=prepared["component"],
                                   session=session,
                                   selection=prepared["selection"],
                                   route=prepared["route"])
    yield adapter
    adapter.close()


def _key(sequence: int = 1) -> TransactionKey:
    return TransactionKey("execution-g3", "case-g3", "processor", 0,
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


# ---------------------------------------------------------------------------
# Route facts and the strict binding
# ---------------------------------------------------------------------------

def test_route_is_derived_from_the_same_pass_d3(prepared):
    route = prepared["route"]
    assert type(route) is TargetRoute
    assert route.path_id == "F4:ram.image"
    assert route.device_id == "peripheral"
    assert route.endpoint_id == "timer.bus"
    assert route.window_base == WINDOW_BASE
    assert route.window_size == WINDOW_SIZE
    assert route.register == "TIMER0_CTRL"
    assert route.register_offset == 4
    assert route.access_alignment == 4
    assert route.width_bytes == 4
    assert route.allowed_byte_enables == (15,)
    assert route.declared_value_mask == 0xFFFFFFFF
    # Same facts, same digest: the route is a documentary declaration.
    assert route.sha256() == replace(route).sha256()
    assert replace(route).document() == route.document()
    assert replace(route, register_offset=8).sha256() != route.sha256()
    refuse("generic-contract-type", lambda: TargetRoute(
        path_id="F4:ram.image", device_id="peripheral", endpoint_id="timer.bus",
        window_base=-1, window_size=WINDOW_SIZE, register="TIMER0_CTRL",
        register_offset=4, access_alignment=4, width_bytes=4,
        allowed_byte_enables=(15,), declared_value_mask=0xFFFFFFFF,
        declared_operation="write"))


def test_cpu_component_has_no_storage_route(prepared):
    error = refuse("generic-route-refused", lambda: declare_target_route(
        preparation=prepared["context"], component=prepared["cpu_component"],
        endpoint_id="processor.data"))
    assert error.detail["reason"] == "apb3-target-endpoint-required"


def test_bind_pins_the_real_session_and_issuer(prepared, real_pair):
    session, authority = real_pair
    adapter = bind_storage_adapter(component=prepared["component"],
                                   session=session,
                                   selection=prepared["selection"],
                                   route=prepared["route"])
    try:
        assert adapter.component_instance_id == "peripheral"
        assert adapter.adapter_id == STORAGE_ADAPTER_ID == "apb3.storage.v1"
        assert adapter.adapter_version == STORAGE_ADAPTER_VERSION == "1"
        assert adapter.endpoint_id == "timer.bus"
        assert adapter.binding_sha256 == adapter.provider.binding_sha256
        assert len(adapter.binding_sha256) == 64
        assert adapter.semantic_contract.sha256_hex == (
            prepared["component"].semantic_contract_sha256)
        assert adapter.provider.software_only is False
        assert isinstance(adapter.provider, TargetProvider)
        assert isinstance(adapter, BoundProtocolAdapter)
        assert authority.target is session
        assert implementation_sha256() == apb3_storage.registration_document()[
            "implementation_pin"]
        adapter.assert_current()
    finally:
        adapter.close()


def test_route_must_match_the_live_artifact(prepared, real_pair):
    session, _ = real_pair
    wrong = replace(prepared["route"], window_size=0x2000)
    error = refuse("generic-route-refused", lambda: bind_storage_adapter(
        component=prepared["component"], session=session,
        selection=prepared["selection"], route=wrong))
    assert error.pointer == "/route/window_size"
    # With the issuing preparation the whole route is re-derived and compared,
    # so even a self-consistent but different window base is refused.
    shifted = replace(prepared["route"], window_base=0x40002000)
    error = refuse("generic-route-refused", lambda: bind_storage_adapter(
        component=prepared["component"], session=session,
        selection=prepared["selection"], route=shifted,
        preparation=prepared["context"]))
    assert error.detail["reason"] == "route-differs-from-same-pass-declaration"
    # With only the issuing preparation the provider derives that same route.
    derived = bind_storage_adapter(
        component=prepared["component"], session=session,
        selection=prepared["selection"], preparation=prepared["context"])
    try:
        derived.assert_current()
        assert derived.provider.route_sha256 == prepared["route"].sha256()
        derived.provider.prepare(_key(), _write())
    finally:
        derived.close()


def test_bind_refuses_a_software_session(prepared):
    fixture = apb3_storage._software_storage_fixture(
        component=prepared["component"], artifact=prepared["artifact"],
        route=prepared["route"], program=[])
    with pytest.raises(GenericRuntimeRefused) as caught:
        bind_storage_adapter(component=prepared["component"],
                             session=fixture.session,
                             selection=prepared["selection"],
                             route=prepared["route"])
    assert caught.value.code == "generic-binding-drift"
    assert caught.value.detail["reason"] == (
        "exact-GeneratedApb3RegisterSession-required")


def test_bind_refuses_foreign_selection(prepared, real_pair):
    session, _ = real_pair
    foreign = replace(prepared["selection"], component_artifact_sha256="0" * 64)
    error = refuse("generic-plan-mismatch", lambda: bind_storage_adapter(
        component=prepared["component"], session=session,
        selection=foreign, route=prepared["route"]))
    assert error.detail["reason"] == "selection-does-not-belong-to-this-component"


def test_bind_without_route_keeps_prepare_closed(prepared, real_pair):
    # G4's plan binding calls the factory without a route; the provider then
    # binds its facts but refuses every prepare instead of guessing a route.
    session, _ = real_pair
    adapter = bind_storage_adapter(component=prepared["component"],
                                   session=session,
                                   selection=prepared["selection"])
    try:
        error = refuse("generic-route-refused",
                       lambda: adapter.provider.prepare(_key(), _write()))
        assert error.detail["reason"] == "route-not-declared"
    finally:
        adapter.close()


# ---------------------------------------------------------------------------
# prepare: verification only, never an IP step
# ---------------------------------------------------------------------------

def test_prepare_has_no_side_effect(prepared, real_pair, monkeypatch):
    session, _ = real_pair
    calls = []

    def driver_spy(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("prepare must not drive the IP")

    monkeypatch.setattr(session, "routed_register_access", driver_spy)
    adapter = bind_storage_adapter(component=prepared["component"],
                                   session=session,
                                   selection=prepared["selection"],
                                   route=prepared["route"])
    try:
        handle = adapter.provider.prepare(_key(), _write())
        assert handle.request_sha256 == _write().sha256()
        assert handle.route_sha256 == prepared["route"].sha256()
        assert handle.binding_sha256 == adapter.binding_sha256
        assert handle.key == _key()
        assert len(handle.operation_id) == 64
        assert calls == []
        assert session.local_ticks == 0
        assert session._sequence == 0
        assert list(session._samples) == []
        assert len(adapter.provider) == 1
    finally:
        adapter.close()


def test_alias_rule_and_transport_alignment(prepared, bound):
    provider = bound.provider
    canonical = provider.prepare(_key(1), _write())
    alias = provider.prepare(_key(2), _write(address=ALIAS_ADDRESS))
    high_alias = provider.prepare(_key(3), _read(address=HIGH_ALIAS_ADDRESS))
    assert canonical is not alias and canonical is not high_alias
    # Aliases reach the same certified register but are distinct operations.
    assert canonical.request_sha256 != alias.request_sha256
    assert len({canonical.operation_id, alias.operation_id,
                high_alias.operation_id}) == 3


def test_non_alias_wrong_offset_refused_before_any_advance(prepared, bound,
                                                           monkeypatch):
    calls = []
    monkeypatch.setattr(bound.provider._session, "routed_register_access",
                        lambda *a, **k: calls.append(a))
    error = refuse("generic-route-refused",
                   lambda: bound.provider.prepare(_key(), _write(
                       address=NON_ALIAS_ADDRESS)))
    assert error.detail["reason"] == "not-a-certified-storage-alias"
    assert calls == []
    assert len(bound.provider) == 0


def test_word_address_confusion_refused(prepared, bound):
    error = refuse("generic-route-refused",
                   lambda: bound.provider.prepare(_key(), _write(
                       address=WORD_ADDRESS)))
    assert error.detail["reason"] == "transport-alignment"


def test_out_of_window_refused(prepared, bound):
    error = refuse("generic-route-refused",
                   lambda: bound.provider.prepare(_key(), _write(
                       address=WINDOW_BASE + WINDOW_SIZE)))
    assert error.detail["reason"] == "outside-declared-window"


def test_byte_enable_not_full_word_refused(prepared, bound):
    for enables in (0b0011, 0b0001, 0b1110):
        error = refuse("generic-semantic-unsupported",
                       lambda enables=enables: bound.provider.prepare(
                           _key(), _write(byte_enable=enables)))
        assert error.detail["reason"] == (
            "registered-contract-has-no-byte-enables")


def test_non_full_word_size_refused(prepared, bound):
    error = refuse("generic-semantic-unsupported",
                   lambda: bound.provider.prepare(
                       _key(), _write(value=0x5A, size_bytes=2, byte_enable=3)))
    assert error.detail["reason"] == "registered-full-word-contract"


def test_request_contract_rejects_inconsistent_payload(prepared, bound):
    refuse("generic-contract-type", lambda: TargetRequest(
        path_id="F4:ram.image", source_ref=_source_ref(),
        address=CANONICAL_ADDRESS, operation="read", write_data=1,
        byte_enable=15, size_bytes=4))
    refuse("generic-contract-type", lambda: TargetRequest(
        path_id="F4:ram.image", source_ref=_source_ref(),
        address=CANONICAL_ADDRESS, operation="read", write_data=None,
        byte_enable=1, size_bytes=4))
    refuse("generic-contract-type", lambda: bound.provider.prepare(
        _key(), "not-a-request"))


def test_undeclared_path_refused(prepared, bound):
    error = refuse("generic-route-refused",
                   lambda: bound.provider.prepare(
                       _key(), _write(path_id="F2:ram.image")))
    assert error.detail["declared"] == "F4:ram.image"


# ---------------------------------------------------------------------------
# advance: only through the existing driver hook
# ---------------------------------------------------------------------------

def test_real_advance_refuses_before_the_driver_hook(prepared, real_pair,
                                                     monkeypatch):
    session, _ = real_pair
    calls = []

    def driver_spy(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("a real non-running session must not be driven")

    monkeypatch.setattr(session, "routed_register_access", driver_spy)
    adapter = bind_storage_adapter(component=prepared["component"],
                                   session=session,
                                   selection=prepared["selection"],
                                   route=prepared["route"])
    try:
        handle = adapter.provider.prepare(_key(), _write())
        error = refuse("generic-provider-closed",
                       lambda: adapter.provider.advance(handle, 64))
        assert error.detail["reason"] == "session-not-running"
        assert calls == []
        assert session.local_ticks == 0
        # No terminal state was fabricated for a refused advance.
        refuse("generic-provider-incomplete",
               lambda: adapter.provider.complete(handle))
    finally:
        adapter.close()


def _fixture(prepared, program, *, max_ticks=12):
    return apb3_storage._software_storage_fixture(
        component=prepared["component"], artifact=prepared["artifact"],
        route=prepared["route"], program=program, max_ticks=max_ticks)


def test_apb3_setup_access_wait_response_ordering(prepared):
    fixture = _fixture(prepared, [{
        "phases": ["idle", "setup", "access", "wait", "wait", "response"],
        "rdata": 0xDEADBEEF,
    }])
    provider = fixture.provider
    handle = provider.prepare(_key(), _read())
    progress = provider.advance(handle, 12)
    assert type(progress) is ProviderProgress
    assert progress.status == "completed"
    assert progress.advanced_ticks == 6
    assert progress.response_bytes == (0xDEADBEEF).to_bytes(4, "little")
    assert progress.reason_code is None
    kinds = [ref.kind for ref in progress.raw_refs]
    assert kinds[0] == "software_apb3_command"
    assert set(kinds[1:]) == {"software_apb3_tick_sample"}
    assert len(progress.raw_refs) == 7            # one command + six ticks
    assert all(ref.component == "peripheral" for ref in progress.raw_refs)
    # Only the existing driver hook was used, exactly once, with the key.
    assert len(fixture.session.calls) == 1
    call = fixture.session.calls[0]
    assert call["address"] == CANONICAL_ADDRESS
    assert call["offset"] == 4
    assert call["write"] is False
    assert call["value"] == 0
    assert call["be"] == 15
    assert call["context"]["device_id"] == "peripheral"
    assert call["context"]["window_base"] == WINDOW_BASE
    assert call["context"]["window_size"] == WINDOW_SIZE
    assert call["context"]["source_transaction"]["execution_id"] == "execution-g3"


def test_backpressure_wait_states_and_write_commit(prepared):
    fixture = _fixture(prepared, [{
        "phases": ["setup", "access"] + ["wait"] * 5 + ["response"],
        "rdata": 0,
    }])
    provider = fixture.provider
    handle = provider.prepare(_key(), _write(0x12345678))
    progress = provider.advance(handle, 12)
    assert progress.status == "completed"
    assert progress.advanced_ticks == 8            # setup+access+5 waits+response
    assert progress.response_bytes == bytes(4)
    assert fixture.session.calls[0]["write"] is True
    assert fixture.session.calls[0]["value"] == 0x12345678
    assert fixture.session.calls[0]["be"] == 15
    evidence = provider.complete(handle)
    assert evidence.status == "unsupported"
    assert evidence.scope == "component_semantic_effect"
    assert evidence.native_refs == ()
    assert evidence.source_refs == (_source_ref(),)
    assert evidence.binding_sha256 == provider.binding_sha256
    assert evidence.semantic_contract_sha256 == provider.semantic_contract.sha256_hex
    assert [name for name, _ in evidence.obligation_results] == sorted(
        name for name, _ in evidence.obligation_results)
    assert all(status == "unsupported"
               for _, status in evidence.obligation_results)


def test_error_response_faults_read_and_marks_write_uncertain(prepared):
    fixture = _fixture(prepared, [
        {"phases": ["setup", "access", "response"], "rdata": 0, "error": True},
        {"phases": ["setup", "access", "response"], "rdata": 0, "error": True},
    ])
    provider = fixture.provider
    read = provider.advance(provider.prepare(_key(1), _read()), 12)
    assert read.status == "faulted"
    assert read.reason_code == "target-error-response"
    assert read.response_bytes is None
    write = provider.advance(provider.prepare(_key(2), _write()), 12)
    assert write.status == "uncertain_effect"
    assert write.reason_code == "target-error-response"
    evidence = provider.complete(provider.prepare(_key(2), _write()))
    assert evidence.status == "unsupported"


def test_invalid_ordering_is_uncertain_and_never_completed(prepared):
    for phases in (["access", "response"], ["setup", "response"],
                   ["setup", "access", "wait", "setup", "response"]):
        fixture = _fixture(prepared, [{"phases": phases, "rdata": 1}])
        provider = fixture.provider
        handle = provider.prepare(_key(), _read())
        progress = provider.advance(handle, 12)
        assert progress.status == "uncertain_effect", phases
        assert progress.reason_code == "apb3-observation-invalid"
        assert progress.response_bytes is None


def test_wait_cycle_bound_of_the_artifact_is_enforced(prepared):
    trace = prepared["artifact"].runtime_document["base_protocol_trace"]
    fixture = _fixture(prepared, [{
        "phases": ["setup", "access"]
                  + ["wait"] * (trace["max_wait_cycles"] + 1) + ["response"],
        "rdata": 0,
    }], max_ticks=trace["max_wait_cycles"] + 8)
    provider = fixture.provider
    progress = provider.advance(provider.prepare(_key(), _read()),
                                trace["max_wait_cycles"] + 8)
    assert progress.status == "uncertain_effect"
    assert progress.reason_code == "apb3-observation-invalid"


def test_driver_fault_and_driver_refusal_are_distinguished(prepared):
    fixture = _fixture(prepared, [
        {"phases": ["setup", "access", "response"], "rdata": 9,
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


# ---------------------------------------------------------------------------
# Evidence and native-token boundary
# ---------------------------------------------------------------------------

def test_provider_never_issues_or_consumes_native_tokens(prepared, real_pair):
    from myfuzz.scenario import apb_storage_register_version as version_module
    session, authority = real_pair
    tokens_before = dict(version_module._TOKENS[authority])
    source = Path(apb3_storage.__file__).read_text(encoding="utf-8")
    # The adapter's only issuance is its own process-local handle registry.
    assert "consume(" not in source
    assert "_TOKENS" not in source
    assert "ApbStorageRegisterVersionAuthority.issue" not in source
    assert "ApbStorageRegisterVersionAuthority.consume" not in source
    adapter = bind_storage_adapter(component=prepared["component"],
                                   session=session,
                                   selection=prepared["selection"],
                                   route=prepared["route"])
    try:
        handle = adapter.provider.prepare(_key(), _write(0xA5A5A5A5))
        refuse("generic-provider-closed",
               lambda: adapter.provider.advance(handle, 64))
        assert dict(version_module._TOKENS[authority]) == tokens_before
        assert adapter.provider.raw_events == {}
    finally:
        adapter.close()


def test_software_completion_carries_no_native_authority(prepared):
    fixture = _fixture(prepared, [{
        "phases": ["setup", "access", "response"], "rdata": 0x01020304}])
    provider = fixture.provider
    handle = provider.prepare(_key(), _read())
    progress = provider.advance(handle, 12)
    assert progress.status == "completed"
    assert all(ref.kind.startswith("software_") for ref in progress.raw_refs)
    evidence = provider.complete(handle)
    assert evidence.status == "unsupported"
    assert evidence.native_refs == ()
    assert evidence.destination_refs == ()
    names = dict(evidence.obligation_results)
    assert names["physical_protocol_sample"] == "unsupported"
    assert names["storage_version_token"] == "unsupported"
    assert names["component_semantic_effect"] == "unsupported"
    # The provider records the raw observation, but the raw index is bounded and
    # software-tagged; it never contains a native token coordinate.
    events = provider.raw_events
    assert events, "the provider retains its own raw observation"
    assert {row["kind"] for row in events.values()} <= {
        "software_apb3_command", "software_apb3_tick_sample"}
    # Swapping the issuer methods would break the binding instead of being used.
    original_issue = ApbStorageRegisterVersionAuthority.issue
    original_consume = ApbStorageRegisterVersionAuthority.consume
    try:
        ApbStorageRegisterVersionAuthority.issue = lambda self, **kwargs: (
            pytest.fail("provider must never issue a native token"))
        ApbStorageRegisterVersionAuthority.consume = lambda self, token: (
            pytest.fail("provider must never consume a native token"))
        refuse("generic-binding-drift", lambda: provider.complete(handle))
    finally:
        ApbStorageRegisterVersionAuthority.issue = original_issue
        ApbStorageRegisterVersionAuthority.consume = original_consume
