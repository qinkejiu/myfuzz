"""G2: code-owned adapter registry, unique capability selection, no injection.

Positive matching uses the real timer preparation (``compiled-f4-obi-apb-timer``)
and the artifacts it owns.  Synthetic ``VerifiedComponent`` fixtures are issued
only through the documented ``PreparationContext._for_tests()`` fixture context;
production never calls it.  Software only: a selection is a static implementation
choice, not a source or native token.
"""
from __future__ import annotations

import dataclasses
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import pytest

from myfuzz.runtime import registry
from myfuzz.runtime.admission import verify_component
from myfuzz.runtime.contracts import (
    CapabilityRequirement,
    GenericRuntimeRefused,
    VerifiedComponent,
    canonical_json_bytes,
)
from myfuzz.runtime.preparation import PreparationContext, create_preparation
from myfuzz.runtime.registry import (
    CPU_ADAPTER_ID,
    STORAGE_ADAPTER_ID,
    select_adapter,
)

ROOT = Path(__file__).resolve().parents[2]
TIMER = ROOT / "configs/scenarios/compiled-f4-obi-apb-timer"
MATCH_TABLE = ROOT / "runs/generic-runtime/G2/match-table.json"


@pytest.fixture(scope="module")
def timer_preparation(tmp_path_factory):
    output = tmp_path_factory.mktemp("generic-registry-preparation")
    context = create_preparation(
        base_dir=ROOT,
        compose_path=TIMER / "compose.json",
        capability_paths=(TIMER / "test_capability.json",),
        supplement_path=TIMER / "execution_supplement.json",
        generated_dir=output / "generated",
        flow_ids=("F2", "F4"),
    )
    yield context
    context.close()


@pytest.fixture(scope="module")
def real_components(timer_preparation):
    storage = verify_component(timer_preparation.artifact("peripheral"),
                               preparation=timer_preparation, base_dir=ROOT)
    cpu = verify_component(timer_preparation.artifact("processor"),
                           preparation=timer_preparation, base_dir=ROOT)
    return storage, cpu


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


@pytest.fixture(scope="module")
def real_selections(timer_preparation, real_components):
    storage, cpu = real_components
    storage_selection = select_adapter(
        storage, requirement_for(storage.endpoints()[0]),
        preparation=timer_preparation)
    cpu_selection = select_adapter(
        cpu, requirement_for(cpu.endpoints()[0]), preparation=timer_preparation)
    return storage_selection, cpu_selection


def synthetic_component(base: VerifiedComponent, *, instance_id=None,
                        artifact_sha256=None, endpoint_updates=None):
    """Build a closed descriptor from a real one; test fixture only."""
    document = deepcopy(base.document())
    if instance_id is not None:
        document["instance_id"] = instance_id
    if artifact_sha256 is not None:
        document["artifact_sha256"] = artifact_sha256
    for row in document["endpoints"]:
        row.update(endpoint_updates or {})
    frozen = canonical_json_bytes(document)
    return VerifiedComponent(
        document["instance_id"], document["source_sha256"],
        document["profile_sha256"], document["artifact_sha256"],
        document["semantic_contract_sha256"], frozen)


def fixture_context(component: VerifiedComponent) -> PreparationContext:
    """The documented software-test fixture; production never calls it."""
    context = PreparationContext._for_tests()
    assert context._issue_test_fixture(component) is component
    return context


# ---------------------------------------------------------------------------
# positive: real certified endpoints select exactly one code-owned adapter
# ---------------------------------------------------------------------------

def test_real_storage_and_cpu_capabilities_select_unique_adapters(
        timer_preparation, real_components, real_selections):
    storage, cpu = real_components
    storage_selection, cpu_selection = real_selections
    assert storage.endpoints()[0]["role"] == "target"
    assert cpu.endpoints()[0]["role"] == "cpu"
    assert storage_selection.adapter_id == STORAGE_ADAPTER_ID == "apb3.storage.v1"
    assert cpu_selection.adapter_id == CPU_ADAPTER_ID == "obi.cpu.v1"
    assert storage_selection.adapter_version == "1"
    assert cpu_selection.adapter_version == "1"
    for selection, component in ((storage_selection, storage),
                                 (cpu_selection, cpu)):
        assert len(selection.implementation_sha256) == 64
        assert selection.implementation_sha256 == \
            selection.implementation_sha256.lower()
        assert selection.component_artifact_sha256 == component.artifact_sha256
        assert selection.semantic_contract_sha256 == \
            component.semantic_contract_sha256
        document = selection.document()
        assert document["adapter_id"] == selection.adapter_id
        assert document["implementation_sha256"] == selection.implementation_sha256
    assert storage_selection.implementation_sha256 != \
        cpu_selection.implementation_sha256
    # Both selections belong to the same preparation, in issuance order.
    assert timer_preparation.selections() == (storage_selection, cpu_selection)
    snapshot = timer_preparation.snapshot()
    assert [row["adapter_id"] for row in snapshot["selections"]] == [
        STORAGE_ADAPTER_ID, CPU_ADAPTER_ID]
    # The implementation pin is the registration's own digest, not caller data.
    registrations = {row.adapter_id: row for row in registry.registrations()}
    for selection in (storage_selection, cpu_selection):
        assert selection.implementation_sha256 == \
            registrations[selection.adapter_id].implementation_sha256()


def test_repeated_selection_returns_the_recorded_selection(
        timer_preparation, real_components, real_selections):
    storage, cpu = real_components
    storage_selection, cpu_selection = real_selections
    assert select_adapter(storage, requirement_for(storage.endpoints()[0]),
                          preparation=timer_preparation) is storage_selection
    assert select_adapter(cpu, requirement_for(cpu.endpoints()[0]),
                          preparation=timer_preparation) is cpu_selection
    assert len(timer_preparation.selections()) == 2


def test_real_capability_match_table_is_recorded(timer_preparation,
                                                 real_components,
                                                 real_selections):
    """Record the real registration x certified endpoint matrix as evidence."""
    legacy = tuple(row for row in registry.registrations()
                   if row.adapter_id in (STORAGE_ADAPTER_ID, CPU_ADAPTER_ID))
    rows = []
    for component in real_components:
        for endpoint in component.endpoints():
            matching = [row.adapter_id for row in legacy
                        if registry._registration_matches(row, endpoint)]
            refused = [row.adapter_id for row in legacy
                       if not registry._registration_matches(row, endpoint)]
            rows.append({
                "component": component.instance_id,
                "endpoint_id": endpoint["endpoint_id"],
                "protocol": endpoint["protocol"],
                "semantic_kind": endpoint["semantic_kind"],
                "template": endpoint["template"],
                "matching_adapters": matching,
                "refused_adapters": refused,
            })
    table = {
        "schema_version": "generic_runtime_match_table.v1",
        "scope": "software_static_capability_selection_no_native_authority",
        "generated_by": "tests/runtime/test_registry.py",
        "preparation_id": timer_preparation.preparation_id,
        "flows": list(timer_preparation.flow_ids),
        "input_digests": timer_preparation.input_digests,
        "components": [component.document() for component in real_components],
        "registrations": [row.document() for row in legacy],
        "rows": rows,
        "selections": [selection.document() for selection in real_selections],
    }
    for row in rows:
        print(f"{row['component']:<12} {row['endpoint_id']:<16} "
              f"{'/'.join(row['protocol']):<8} {row['semantic_kind']:<14} -> "
              f"{','.join(row['matching_adapters'])} "
              f"(refused: {','.join(row['refused_adapters']) or '-'})")
    MATCH_TABLE.parent.mkdir(parents=True, exist_ok=True)
    MATCH_TABLE.write_text(json.dumps(table, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")
    recorded = json.loads(MATCH_TABLE.read_text(encoding="utf-8"))
    assert recorded == json.loads(json.dumps(table))
    # Exactly one code-owned adapter matches each certified endpoint, and every
    # other registration is refused; no adapter serves both roles.
    assert [row["matching_adapters"] for row in rows] == [
        [STORAGE_ADAPTER_ID], [CPU_ADAPTER_ID]]
    assert [row["refused_adapters"] for row in rows] == [
        [CPU_ADAPTER_ID], [STORAGE_ADAPTER_ID]]
    assert [row["matching_adapters"][0] for row in rows] == [
        selection.adapter_id for selection in real_selections]


# ---------------------------------------------------------------------------
# instance rename changes identity, not the adapter choice
# ---------------------------------------------------------------------------

def test_instance_rename_keeps_adapter_identity_but_changes_digests(
        timer_preparation, real_components, real_selections):
    storage, _ = real_components
    storage_selection, _ = real_selections
    base_endpoint = storage.endpoints()[0]
    renamed_artifact = sha256(
        b"g2-synthetic-renamed-peripheral-artifact").hexdigest()
    renamed = synthetic_component(
        storage, instance_id="peripheral_renamed",
        artifact_sha256=renamed_artifact)
    assert renamed.instance_id == "peripheral_renamed"
    assert renamed.artifact_sha256 == renamed_artifact != storage.artifact_sha256
    assert renamed.descriptor_sha256() != storage.descriptor_sha256()
    assert renamed.source_sha256 == storage.source_sha256
    assert renamed.endpoints() == storage.endpoints()
    context = fixture_context(renamed)
    selection = select_adapter(renamed, requirement_for(base_endpoint),
                               preparation=context)
    assert selection.adapter_id == storage_selection.adapter_id
    assert selection.adapter_version == storage_selection.adapter_version
    assert selection.implementation_sha256 == \
        storage_selection.implementation_sha256
    assert selection.component_artifact_sha256 == renamed_artifact
    assert selection.semantic_contract_sha256 == \
        renamed.semantic_contract_sha256 == storage.semantic_contract_sha256
    assert context.selections() == (selection,)
    # The rename is a fixture: it never enters the real preparation.
    assert len(timer_preparation.selections()) == 2
    assert timer_preparation.components() == real_components


def test_test_fixture_issuance_is_refused_by_a_real_preparation(
        timer_preparation, real_components):
    storage, _ = real_components
    renamed = synthetic_component(
        storage, instance_id="peripheral_renamed",
        artifact_sha256=sha256(b"g2-refused-fixture").hexdigest())
    with pytest.raises(GenericRuntimeRefused) as caught:
        timer_preparation._issue_test_fixture(renamed)
    assert caught.value.code == "generic-binding-drift"
    assert caught.value.detail == {"reason": "test-fixture-issuance-refused"}


# ---------------------------------------------------------------------------
# similar name / wrong protocol / wrong semantic
# ---------------------------------------------------------------------------

def test_wrong_protocol_refuses_missing_adapter(real_components):
    storage, _ = real_components
    apb4 = synthetic_component(
        storage, endpoint_updates={"protocol": ["apb", "4"]})
    context = fixture_context(apb4)
    requirement = requirement_for(apb4.endpoints()[0])
    assert requirement.protocol == ("apb", "4")
    with pytest.raises(GenericRuntimeRefused) as caught:
        select_adapter(apb4, requirement, preparation=context)
    assert caught.value.code == "generic-adapter-missing"
    assert caught.value.pointer == "/selection"
    assert caught.value.detail == {
        "endpoint_id": "timer.bus", "protocol": ["apb", "4"],
        "semantic_kind": "storage.rw.v1",
        "template": ["target.apb3", "1", "full-word"]}
    assert context.selections() == ()


@pytest.mark.parametrize("semantic_kind", ["storage.w1c.v1",
                                           "storage.w1s.v1",
                                           "fifo.push.v1",
                                           "command.start.v1"])
def test_same_protocol_other_semantics_refuses_missing_adapter(
        real_components, semantic_kind):
    storage, _ = real_components
    other = synthetic_component(
        storage, instance_id="peripheral_" + semantic_kind.replace(".", "_"),
        endpoint_updates={"semantic_kind": semantic_kind})
    context = fixture_context(other)
    requirement = requirement_for(other.endpoints()[0])
    assert requirement.semantic_kind == semantic_kind
    with pytest.raises(GenericRuntimeRefused) as caught:
        select_adapter(other, requirement, preparation=context)
    assert caught.value.code == "generic-adapter-missing"
    assert caught.value.pointer == "/selection"
    assert caught.value.detail["semantic_kind"] == semantic_kind
    assert caught.value.detail["protocol"] == ["apb", "3"]
    assert context.selections() == ()


# ---------------------------------------------------------------------------
# requirement mismatches: exact code and JSON pointer
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("overrides,code,pointer", [
    ({"template": ("target.apb3", "1", "narrow")},
     "generic-template-mismatch", "/requirement/template"),
    ({"protocol": ("apb", "4")},
     "generic-template-mismatch", "/requirement/protocol"),
    ({"data_width": 16},
     "generic-template-mismatch", "/requirement/data_width"),
    ({"address_width": 16},
     "generic-template-mismatch", "/requirement/address_width"),
    ({"address_units": "word"},
     "generic-template-mismatch", "/requirement/address_units"),
    ({"max_outstanding": 2},
     "generic-template-mismatch", "/requirement/max_outstanding"),
    ({"completion_kind": "single_cycle"},
     "generic-template-mismatch", "/requirement/completion_kind"),
    ({"evidence_obligations": ("retirement_proof",)},
     "generic-evidence-missing", "/requirement/evidence_obligations"),
    ({"byte_enable_required": True},
     "generic-semantic-unsupported", "/requirement/byte_enable"),
    ({"endpoint_id": "timer.other"},
     "generic-source-unverified", "/requirement/endpoint_id"),
])
def test_requirement_mismatch_refuses_with_exact_pointer(
        timer_preparation, real_components, real_selections,
        overrides, code, pointer):
    storage, _ = real_components
    requirement = requirement_for(storage.endpoints()[0], **overrides)
    before = timer_preparation.selections()
    with pytest.raises(GenericRuntimeRefused) as caught:
        select_adapter(storage, requirement, preparation=timer_preparation)
    assert caught.value.code == code, overrides
    assert caught.value.pointer == pointer, overrides
    assert timer_preparation.selections() == before
    assert len(before) == 2


def test_requirement_asking_for_unproven_operation_refused(real_components):
    """A write requirement is refused by a component that only proved reads."""
    storage, _ = real_components
    read_only = synthetic_component(
        storage, instance_id="peripheral_read_only",
        endpoint_updates={"operations": ["read"]})
    context = fixture_context(read_only)
    requirement = requirement_for(read_only.endpoints()[0],
                                  operations=("read", "write"))
    with pytest.raises(GenericRuntimeRefused) as caught:
        select_adapter(read_only, requirement, preparation=context)
    assert caught.value.code == "generic-semantic-unsupported"
    assert caught.value.pointer == "/requirement/operations"
    assert caught.value.detail == {"missing": ["write"], "supported": ["read"]}
    assert context.selections() == ()


def test_requirement_without_byte_enable_accepts_a_capable_provider(
        timer_preparation, real_components, real_selections):
    """A provider that supports byte enables serves a requirement that needs none."""
    _, cpu = real_components
    endpoint = cpu.endpoints()[0]
    assert endpoint["byte_enable"] is True
    requirement = requirement_for(endpoint, byte_enable_required=False)
    assert select_adapter(cpu, requirement,
                          preparation=timer_preparation) is real_selections[1]


# ---------------------------------------------------------------------------
# no caller-supplied implementation, no mutation API
# ---------------------------------------------------------------------------

def test_selection_api_accepts_no_factory_import_string_or_callback(
        timer_preparation, real_components):
    storage, _ = real_components
    requirement = requirement_for(storage.endpoints()[0])
    for kwargs in ({"factory": object()},
                   {"import_string": "builtins.object"},
                   {"callback": (lambda *args: None)},
                   {"verifier": object()},
                   {"adapter": object()}):
        with pytest.raises(TypeError):
            select_adapter(storage, requirement,
                           preparation=timer_preparation, **kwargs)


def test_registry_is_a_frozen_code_owned_constant():
    registrations = registry.registrations()
    assert type(registrations) is tuple
    assert type(registry._REGISTRATIONS) is tuple
    assert tuple(row.adapter_id for row in registrations) == (
        "wishbone.mmio.v1", "apb3.mmio.v1", "tlul.mmio.v1", "axi4lite.mmio.v1",
        "ahb-lite.mmio.v1", STORAGE_ADAPTER_ID, "wishbone.storage.v1",
        "ahb-lite.cpu.v1", "axi4-lite.cpu.v1", "axi4.cpu.v1",
        "cva6.axi4.cpu.v1", "wishbone.cpu.v1", "tilelink.cpu.v1",
        CPU_ADAPTER_ID, "gpio.causal-storage.v1")
    assert len(registrations) == 15
    for forbidden in ("register", "register_adapter", "add_registration",
                      "unregister", "install", "override", "load",
                      "load_registrations", "from_json", "from_dict",
                      "set_registration", "replace_registration"):
        assert not hasattr(registry, forbidden), forbidden
    for row in registrations:
        assert dataclasses.is_dataclass(row)
        with pytest.raises(dataclasses.FrozenInstanceError):
            row.adapter_id = "caller.adapter"
        assert len(row.implementation_sha256()) == 64
        assert row.implementation_sha256() == registry._IMPLEMENTATION_PINS[
            row.adapter_id]


def test_hand_built_component_is_not_a_member(timer_preparation, real_components,
                                              real_selections):
    storage, _ = real_components
    clone = VerifiedComponent(
        storage.instance_id, storage.source_sha256, storage.profile_sha256,
        storage.artifact_sha256, storage.semantic_contract_sha256,
        storage.descriptor_bytes)
    assert clone == storage and clone is not storage
    with pytest.raises(GenericRuntimeRefused) as caught:
        select_adapter(clone, requirement_for(storage.endpoints()[0]),
                       preparation=timer_preparation)
    assert caught.value.code == "generic-binding-drift"
    assert caught.value.pointer == "/component"
    assert caught.value.detail["reason"] == "not-issued-by-this-process"
    assert timer_preparation.selections() == real_selections


# ---------------------------------------------------------------------------
# 0 matches and >1 matches are both refusals; never a priority tie-break
# ---------------------------------------------------------------------------

def test_zero_match_refuses_missing_adapter(real_components):
    storage, _ = real_components
    endpoint = storage.endpoints()[0]
    cpu_registration = next(row for row in registry.registrations()
                            if row.adapter_id == CPU_ADAPTER_ID)
    for candidates in ((), (cpu_registration,)):
        with pytest.raises(GenericRuntimeRefused) as caught:
            registry._select_from(candidates, storage, endpoint)
        assert caught.value.code == "generic-adapter-missing"
        assert caught.value.pointer == "/selection"
        assert caught.value.detail == {
            "endpoint_id": "timer.bus", "protocol": ["apb", "3"],
            "semantic_kind": "storage.rw.v1",
            "template": ["target.apb3", "1", "full-word"]}
    assert len(registry.registrations()) == 15


def test_multiple_matches_refuse_ambiguous_adapter(real_components):
    storage, _ = real_components
    endpoint = storage.endpoints()[0]
    registration = next(row for row in registry.registrations()
                        if row.adapter_id == STORAGE_ADAPTER_ID)
    duplicate = dataclasses.replace(registration)
    with pytest.raises(GenericRuntimeRefused) as caught:
        registry._select_from(registry.registrations() + (duplicate,),
                              storage, endpoint)
    assert caught.value.code == "generic-adapter-ambiguous"
    assert caught.value.pointer == "/selection"
    assert caught.value.detail == {
        "adapters": [STORAGE_ADAPTER_ID, STORAGE_ADAPTER_ID]}
    # The module constant is unchanged: no selection mutated the registry.
    assert registry.registrations() == registry._REGISTRATIONS
    assert len(registry.registrations()) == 15


# ---------------------------------------------------------------------------
# implementation drift
# ---------------------------------------------------------------------------

def test_implementation_drift_refuses_binding_drift(timer_preparation,
                                                    real_components,
                                                    real_selections):
    storage, _ = real_components
    requirement = requirement_for(storage.endpoints()[0])
    pin = registry._IMPLEMENTATION_PINS[STORAGE_ADAPTER_ID]
    assert len(pin) == 64
    with pytest.MonkeyPatch.context() as patched:
        patched.setitem(registry._IMPLEMENTATION_PINS, STORAGE_ADAPTER_ID,
                        "0" * 64)
        with pytest.raises(GenericRuntimeRefused) as caught:
            select_adapter(storage, requirement,
                           preparation=timer_preparation)
        assert caught.value.code == "generic-binding-drift"
        assert caught.value.pointer == "/adapter"
        assert caught.value.detail == {"adapter_id": STORAGE_ADAPTER_ID,
                                       "reason": "implementation-changed"}
        assert timer_preparation.selections() == real_selections
    # The patch was restored, so the real implementation still selects.
    assert registry._IMPLEMENTATION_PINS[STORAGE_ADAPTER_ID] == pin
    assert pin == next(row for row in registry.registrations()
                       if row.adapter_id == STORAGE_ADAPTER_ID
                       ).implementation_sha256()
    assert select_adapter(storage, requirement,
                          preparation=timer_preparation) is real_selections[0]
