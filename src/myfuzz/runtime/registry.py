"""Code-owned adapter registry and the unique capability match.

Registration is a module constant.  There is no public registration function,
no JSON/import-string/factory loading and no priority or "first match wins"
tie-break: zero matches refuse ``generic-adapter-missing`` and several matches
refuse ``generic-adapter-ambiguous``.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from .contracts import (
    AdapterSelection,
    CapabilityRequirement,
    GenericRuntimeRefused,
    VerifiedComponent,
    canonical_json_bytes,
)
from .preparation import PreparationContext

_ROOT = Path(__file__).resolve().parents[3]

GPIO_STORAGE_ADAPTER_ID = "gpio.causal-storage.v1"
STORAGE_ADAPTER_ID = "apb3.storage.v1"
STORAGE_ADAPTER_VERSION = "1"
CPU_ADAPTER_ID = "obi.cpu.v1"
CPU_ADAPTER_VERSION = "1"
WISHBONE_STORAGE_ADAPTER_ID = "wishbone.storage.v1"
WISHBONE_STORAGE_ADAPTER_VERSION = "1"
WISHBONE_CPU_ADAPTER_ID = "wishbone.cpu.v1"
WISHBONE_CPU_ADAPTER_VERSION = "1"
AHB_CPU_ADAPTER_ID = "ahb-lite.cpu.v1"
AHB_CPU_ADAPTER_VERSION = "1"
AXI4LITE_CPU_ADAPTER_ID = "axi4-lite.cpu.v1"
AXI4LITE_CPU_ADAPTER_VERSION = "1"
AXI4_CPU_ADAPTER_ID = "axi4.cpu.v1"
AXI4_CPU_ADAPTER_VERSION = "1"

STORAGE_ADAPTER_FILES = (
    "src/myfuzz/local_harness/apb3_register_session.py",
    "src/myfuzz/scenario/apb_storage_register_version.py",
    "src/myfuzz/integration/generated_storage_consumer.py",
    "src/myfuzz/integration/compiled_storage_producer.py",
    "src/myfuzz/runtime/semantics/storage.py",
    "src/myfuzz/runtime/adapters/contracts.py",
    # G3: the bound adapter/provider implementation is part of the pin.
    "src/myfuzz/runtime/adapters/apb3_storage.py",
)
CPU_ADAPTER_FILES = (
    "src/myfuzz/local_harness/cpu_session.py",
    "src/myfuzz/local_harness/native_physical_observation.py",
    "src/myfuzz/runtime/adapters/contracts.py",
    # G3: the OBI CPU driver adapter is part of the pin.
    "src/myfuzz/runtime/adapters/obi_cpu.py",
)
WISHBONE_STORAGE_ADAPTER_FILES = (
    "src/myfuzz/local_harness/wishbone_register_session.py",
    "src/myfuzz/local_harness/tlul_register_session.py",
    "src/myfuzz/local_harness/wishbone_storage_source_contract.py",
    "src/myfuzz/local_harness/wishbone_storage_probe_contract.py",
    "src/myfuzz/local_harness/wishbone_storage_probe_verification.py",
    "src/myfuzz/scenario/wishbone_storage_register_version.py",
    "src/myfuzz/integration/generated_wishbone_storage_consumer.py",
    "src/myfuzz/local_harness/wishbone_register_template.py",
    "src/myfuzz/runtime/semantics/contracts.py",
    "src/myfuzz/runtime/semantics/storage.py",
    "src/myfuzz/runtime/adapters/contracts.py",
    "src/myfuzz/runtime/adapters/wishbone_storage.py",
)
WISHBONE_CPU_ADAPTER_FILES = (
    "src/myfuzz/local_harness/wishbone_cpu_session.py",
    "src/myfuzz/local_harness/session.py",
    "src/myfuzz/runtime/adapters/contracts.py",
    "src/myfuzz/runtime/adapters/wishbone_cpu.py",
)

AHB_CPU_ADAPTER_FILES = (
    'src/myfuzz/runtime/adapters/ahb_cpu.py','src/myfuzz/local_harness/ahb_lite_session.py',
    'src/myfuzz/local_harness/native_session.py','src/myfuzz/local_harness/session.py',
    'src/myfuzz/scenario/ahb_cpu_events.py','src/myfuzz/local_harness/ahb_manager_domain.py',
    'src/myfuzz/local_harness/ahb_startup.py',
)

AXI4LITE_CPU_ADAPTER_FILES = (
    'src/myfuzz/runtime/adapters/axi4lite_cpu.py','src/myfuzz/local_harness/axi_lite_session.py',
    'src/myfuzz/local_harness/native_session.py','src/myfuzz/local_harness/session.py',
)

#: The full AXI4 CPU pin spans the bound adapter, the generated single-beat
#: wrapper session it requires, the native parser the executor reads and the
#: session/transport it is built on.
AXI4_CPU_ADAPTER_FILES = (
    'src/myfuzz/runtime/adapters/axi4_cpu.py',
    'src/myfuzz/integration/cpu_axi4.py',
    'src/myfuzz/local_harness/vexii_axi_mmio_session.py',
    'src/myfuzz/local_harness/vexii_axi_session.py',
    'src/myfuzz/local_harness/vexii_axi_fields.py',
    'src/myfuzz/local_harness/session.py',
    'src/myfuzz/scenario/reduced_axi_events.py',
)
CVA6_AXI4_CPU_ADAPTER_ID = "cva6.axi4.cpu.v1"
CVA6_AXI4_CPU_ADAPTER_VERSION = "1"
CVA6_AXI4_CPU_ADAPTER_FILES = (
    'src/myfuzz/runtime/adapters/cva6_axi4_cpu.py',
    'src/myfuzz/integration/cva6_axi_mmio.py',
    'src/myfuzz/integration/native_mmio_data_hops.py',
    'src/myfuzz/local_harness/cva6_axi_mmio_session.py',
    'src/myfuzz/local_harness/cva6_axi4_session.py',
    'src/myfuzz/local_harness/cva6_axi4_fields.py',
    'src/myfuzz/scenario/full_axi_events.py',
    'src/myfuzz/local_harness/session.py',
)

#: The coherent TileLink CPU row.  The pin spans the bound adapter, the host
#: player that answers the generated backend beat face, and the session/link it
#: is built on.  ``runtime/adapters/tilelink_cpu.py`` is what actually reads the
#: artifact's declared taps; ``integration/cpu_tlul.py`` is the selection seam.
TL_COHERENT_CPU_ADAPTER_ID = "tilelink.cpu.v1"
TL_COHERENT_CPU_ADAPTER_VERSION = "1"
TL_COHERENT_CPU_SEMANTIC_KIND = "cpu.tilelink-coherent.v1"
TL_COHERENT_CPU_ADAPTER_FILES = (
    'src/myfuzz/runtime/adapters/tilelink_cpu.py',
    'src/myfuzz/integration/cpu_tlul.py',
    'src/myfuzz/local_harness/tilelink_coherent_session.py',
    'src/myfuzz/local_harness/tilelink_coherent_fields.py',
    'src/myfuzz/local_harness/session.py',
)


def _refuse(code: str, pointer: str = "", detail=None) -> None:
    raise GenericRuntimeRefused(code, pointer, detail)


@dataclass(frozen=True, slots=True)
class AdapterRegistration:
    """Fixed capability surface of one code-owned adapter implementation."""

    adapter_id: str
    adapter_version: str
    roles: tuple[str, ...]
    protocol: tuple[str, str]
    semantic_kinds: tuple[str, ...]
    templates: tuple[tuple[str, str, str], ...]
    operations: tuple[str, ...]
    data_widths: tuple[int, ...]
    address_widths: tuple[int, ...]
    address_units: tuple[str, ...]
    completion_kinds: tuple[str, ...]
    byte_enable: bool
    max_outstanding: int
    evidence_capabilities: tuple[str, ...]
    implementation_files: tuple[str, ...]

    def implementation_sha256(self) -> str:
        digests = {}
        for relative in self.implementation_files:
            try:
                digests[relative] = sha256((_ROOT / relative).read_bytes()).hexdigest()
            except OSError as error:
                _refuse("generic-adapter-missing", "/adapter",
                        {"reason": "implementation-unreadable",
                         "file": relative, "adapter_id": self.adapter_id})
        return sha256(canonical_json_bytes(digests)).hexdigest()

    def document(self) -> dict:
        return {
            "schema_version": "generic_adapter_registration.v1",
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "roles": list(self.roles),
            "protocol": list(self.protocol),
            "semantic_kinds": list(self.semantic_kinds),
            "templates": [list(row) for row in self.templates],
            "operations": list(self.operations),
            "data_widths": list(self.data_widths),
            "address_widths": list(self.address_widths),
            "address_units": list(self.address_units),
            "completion_kinds": list(self.completion_kinds),
            "byte_enable": self.byte_enable,
            "max_outstanding": self.max_outstanding,
            "evidence_capabilities": list(self.evidence_capabilities),
            "implementation_files": list(self.implementation_files),
            "implementation_sha256": self.implementation_sha256(),
        }


_REGISTRATIONS: tuple[AdapterRegistration, ...] = (
    AdapterRegistration(adapter_id='wishbone.mmio.v1',adapter_version='1',roles=('target',),
        protocol=('wishbone','classic'),semantic_kinds=('mmio.register-bank.v1',),
        templates=(('target.wishbone','1','word-addressed-registered-ack'),),operations=('read','write'),
        data_widths=(32,),address_widths=tuple(range(1,33)),address_units=('word',),
        completion_kinds=('registered_ack',),byte_enable=True,max_outstanding=1,
        evidence_capabilities=('cross_component_consumption','cross_component_source','physical_protocol_sample'),
        implementation_files=('src/myfuzz/runtime/adapters/wishbone_mmio.py',
                              'src/myfuzz/integration/wishbone_mmio_target.py')),
    AdapterRegistration(adapter_id='apb3.mmio.v1',adapter_version='1',roles=('target',),
        protocol=('apb','3'),semantic_kinds=('mmio.register-bank.v1',),
        templates=(('target.apb3','1','full-word'),),operations=('read','write'),data_widths=(32,),
        address_widths=(12,),address_units=('byte',),completion_kinds=('setup_access_response',),
        byte_enable=False,max_outstanding=1,
        evidence_capabilities=('cross_component_consumption','cross_component_source','physical_protocol_sample'),
        implementation_files=('src/myfuzz/runtime/adapters/apb3_mmio.py',)),
    AdapterRegistration(adapter_id='tlul.mmio.v1',adapter_version='1',roles=('target',),
        protocol=('tl-ul','1'),semantic_kinds=('mmio.register-bank.v1',),
        templates=(('target.tl-ul','1','user-integrity'),),operations=('read','write'),
        data_widths=(32,),address_widths=tuple(range(1,33)),address_units=('byte',),
        completion_kinds=('a_valid_ready_then_d_valid_ready',),byte_enable=True,max_outstanding=1,
        evidence_capabilities=('cross_component_consumption','cross_component_source','physical_protocol_sample'),
        implementation_files=('src/myfuzz/integration/target_tlul.py',)),
    AdapterRegistration(adapter_id='axi4lite.mmio.v1',adapter_version='1',roles=('target',),
        protocol=('axi4-lite','1'),semantic_kinds=('mmio.register-bank.v1',),
        templates=(('target.axi4-lite','1','single-outstanding-error-codes'),),operations=('read','write'),
        data_widths=(32,),address_widths=tuple(range(1,33)),address_units=('byte',),
        completion_kinds=('independent_channels_response',),byte_enable=True,max_outstanding=1,
        evidence_capabilities=('cross_component_consumption','cross_component_source','physical_protocol_sample'),
        implementation_files=('src/myfuzz/integration/target_axi4lite.py',)),
    AdapterRegistration(adapter_id='ahb-lite.mmio.v1',adapter_version='1',roles=('target',),
        protocol=('ahb-lite','1'),semantic_kinds=('mmio.register-bank.v1',),
        templates=(('target.ahb-lite','1','full-word-single'),),operations=('read','write'),
        data_widths=(32,),address_widths=tuple(range(1,33)),address_units=('byte',),
        completion_kinds=('address_phase_then_ready_completion',),byte_enable=True,max_outstanding=1,
        evidence_capabilities=('cross_component_consumption','cross_component_source','physical_protocol_sample'),
        implementation_files=('src/myfuzz/integration/target_ahb_lite.py',)),

    AdapterRegistration(
        adapter_id=STORAGE_ADAPTER_ID,
        adapter_version=STORAGE_ADAPTER_VERSION,
        roles=("target",),
        protocol=("apb", "3"),
        semantic_kinds=("storage.rw.v1",),
        templates=(("target.apb3", "1", "full-word"),),
        operations=("read", "write"),
        data_widths=(32,),
        address_widths=(12,),
        address_units=("byte",),
        completion_kinds=("setup_access_response",),
        byte_enable=False,
        max_outstanding=1,
        evidence_capabilities=("component_semantic_effect",
                                "cross_component_consumption",
                                "cross_component_source",
                                "physical_protocol_sample"),
        implementation_files=STORAGE_ADAPTER_FILES,
    ),
    AdapterRegistration(
        adapter_id=WISHBONE_STORAGE_ADAPTER_ID,
        adapter_version=WISHBONE_STORAGE_ADAPTER_VERSION,
        roles=("target",),
        protocol=("wishbone", "classic"),
        semantic_kinds=("storage.rw.v1",),
        templates=(("target.wishbone", "1", "word-addressed-registered-ack"),),
        operations=("read", "write"),
        data_widths=(32,),
        address_widths=(2,),
        address_units=("word",),
        completion_kinds=("registered_ack",),
        byte_enable=True,
        max_outstanding=1,
        evidence_capabilities=("component_semantic_effect",
                               "cross_component_consumption",
                               "cross_component_source",
                               "physical_protocol_sample"),
        implementation_files=WISHBONE_STORAGE_ADAPTER_FILES,
    ),
    AdapterRegistration(
        adapter_id=AHB_CPU_ADAPTER_ID,adapter_version=AHB_CPU_ADAPTER_VERSION,
        roles=('cpu',),protocol=('ahb-lite','1'),semantic_kinds=('cpu.ahb-lite.v1',),
        templates=(('cpu.ahb-lite','1','cvw-external-bus'),),operations=('read','write'),
        data_widths=(32,),address_widths=(34,),address_units=('byte',),
        completion_kinds=('address_phase_then_ready_completion',),byte_enable=True,max_outstanding=1,
        evidence_capabilities=('cross_component_consumption','cross_component_source','physical_protocol_sample'),
        implementation_files=AHB_CPU_ADAPTER_FILES,
    ),
    AdapterRegistration(
        adapter_id=AXI4LITE_CPU_ADAPTER_ID,adapter_version=AXI4LITE_CPU_ADAPTER_VERSION,
        roles=('cpu',),protocol=('axi4-lite','1'),semantic_kinds=('cpu.axi4-lite.v1',),
        templates=(('cpu.axi4-lite','1','no-response-code'),),operations=('read','write'),
        data_widths=(32,),address_widths=(32,),address_units=('byte',),
        completion_kinds=('independent_channels_response',),byte_enable=True,max_outstanding=1,
        evidence_capabilities=('cross_component_consumption','cross_component_source','physical_protocol_sample'),
        implementation_files=AXI4LITE_CPU_ADAPTER_FILES,
    ),
    AdapterRegistration(
        adapter_id=AXI4_CPU_ADAPTER_ID,adapter_version=AXI4_CPU_ADAPTER_VERSION,
        roles=('cpu',),protocol=('axi4','1'),semantic_kinds=('cpu.axi4.v1',),
        templates=(('cpu.axi4-reduced','1','fetch-single'),
                   ('cpu.axi4-reduced','1','data-single')),
        operations=('read','write'),
        data_widths=(32,),address_widths=(32,),address_units=('byte',),
        completion_kinds=('independent_channels_response',),byte_enable=True,max_outstanding=1,
        evidence_capabilities=('cross_component_consumption','cross_component_source','physical_protocol_sample'),
        implementation_files=AXI4_CPU_ADAPTER_FILES,
    ),
    AdapterRegistration(
        adapter_id=CVA6_AXI4_CPU_ADAPTER_ID,adapter_version=CVA6_AXI4_CPU_ADAPTER_VERSION,
        roles=('cpu',),protocol=('axi4','1'),semantic_kinds=('cpu.axi4.v1',),
        templates=(('cpu.axi4','1','single-beat-id'),),
        operations=('read','write'),
        data_widths=(32,64),address_widths=(64,),address_units=('byte',),
        completion_kinds=('independent_channels_response',),byte_enable=True,max_outstanding=1,
        evidence_capabilities=('cross_component_consumption','cross_component_source','physical_protocol_sample'),
        implementation_files=CVA6_AXI4_CPU_ADAPTER_FILES,
    ),
    AdapterRegistration(
        adapter_id=WISHBONE_CPU_ADAPTER_ID,
        adapter_version=WISHBONE_CPU_ADAPTER_VERSION,
        roles=("cpu",),
        protocol=("wishbone", "classic"),
        semantic_kinds=("cpu.wishbone.v1",),
        templates=(("cpu.wishbone", "1", "no-err-stall"),),
        operations=("read", "write"),
        data_widths=(32,),
        address_widths=(32,),
        address_units=("byte",),
        completion_kinds=("cycle_strobe_held_until_ack",),
        byte_enable=True,
        max_outstanding=1,
        evidence_capabilities=("cross_component_consumption",
                               "cross_component_source",
                               "physical_protocol_sample"),
        implementation_files=WISHBONE_CPU_ADAPTER_FILES,
    ),
    AdapterRegistration(
        adapter_id=TL_COHERENT_CPU_ADAPTER_ID,
        adapter_version=TL_COHERENT_CPU_ADAPTER_VERSION,
        roles=("cpu",),
        protocol=("tilelink-coherent", "1"),
        semantic_kinds=(TL_COHERENT_CPU_SEMANTIC_KIND,),
        templates=(("cpu.tilelink-coherent", "1",
                    "coherent-ab-cd-e-single-outstanding"),),
        operations=("read", "write"),
        data_widths=(64,),
        address_widths=(32,),
        address_units=("byte",),
        completion_kinds=("independent_channels_response",),
        byte_enable=True,
        max_outstanding=1,
        evidence_capabilities=("cross_component_consumption",
                               "cross_component_source",
                               "physical_protocol_sample"),
        implementation_files=TL_COHERENT_CPU_ADAPTER_FILES,
    ),
    AdapterRegistration(
        adapter_id=CPU_ADAPTER_ID,
        adapter_version=CPU_ADAPTER_VERSION,
        roles=("cpu",),
        protocol=("obi", "1"),
        semantic_kinds=("cpu.obi.v1",),
        templates=(("cpu.obi", "1", "read-write"),
                   ("cpu.obi", "1", "read-only"),
                   ("cpu.obi", "1", "read-write-no-error-pins"),
                   ("cpu.obi", "1", "read-only-no-error-pins")),
        operations=("read", "write"),
        data_widths=(32,),
        address_widths=(32,),
        address_units=("byte",),
        completion_kinds=("grant_then_response",),
        byte_enable=True,
        max_outstanding=1,
        evidence_capabilities=("cross_component_consumption",
                                "cross_component_source",
                                "physical_protocol_sample"),
        implementation_files=CPU_ADAPTER_FILES,
    ),
    AdapterRegistration(
        adapter_id=GPIO_STORAGE_ADAPTER_ID,adapter_version='1',roles=('target',),
        protocol=('apb','3'),semantic_kinds=('gpio.register-bank.v1',),
        templates=(('pulp.gpio.causal','1','pulp_gpio_causal_v1'),),operations=('read','write'),
        data_widths=(32,),address_widths=(12,),address_units=('byte',),
        completion_kinds=('setup_access_response',),byte_enable=False,max_outstanding=1,
        evidence_capabilities=('component_semantic_effect','cross_component_consumption',
                               'cross_component_source','physical_protocol_sample'),
        implementation_files=('src/myfuzz/runtime/adapters/gpio_storage.py',
            'src/myfuzz/local_harness/gpio_session.py','src/myfuzz/local_harness/pulp_gpio_probe_contract.py',
            'src/myfuzz/scenario/gpio_register_version.py')),

)


def registrations() -> tuple[AdapterRegistration, ...]:
    """Read-only view of the code-owned registry; there is no mutation API."""
    return _REGISTRATIONS


def _endpoint_for(component: VerifiedComponent,
                  requirement: CapabilityRequirement) -> dict:
    rows = [row for row in component.endpoints()
            if row["endpoint_id"] == requirement.endpoint_id]
    if not rows:
        _refuse("generic-source-unverified", "/requirement/endpoint_id",
                {"reason": "endpoint-not-in-verified-component",
                 "endpoint_id": requirement.endpoint_id,
                 "endpoints": [row["endpoint_id"] for row in component.endpoints()]})
    if len(rows) > 1:
        _refuse("generic-source-unverified", "/requirement/endpoint_id",
                {"reason": "duplicate-endpoint"})
    return rows[0]


def _verify_requirement(endpoint: dict, requirement: CapabilityRequirement) -> None:
    """Design section 4.4 exact/subset matching, checked item by item.

    Exact identity fields must be equal.  A provider that supports byte enables
    satisfies a requirement that does not need them, so byte-enable support is a
    one-way proof obligation checked after the exact fields.
    """
    exact = (("role", requirement.role, endpoint["role"]),
             ("protocol", list(requirement.protocol), endpoint["protocol"]),
             ("template", list(requirement.template), endpoint["template"]),
             ("semantic_kind", requirement.semantic_kind,
              endpoint["semantic_kind"]),
             ("data_width", requirement.data_width, endpoint["data_width"]),
             ("address_width", requirement.address_width,
              endpoint["address_width"]),
             ("address_units", requirement.address_units,
              endpoint["address_units"]),
             ("completion_kind", requirement.completion_kind,
              endpoint["completion_kind"]))
    for name, required, supported in exact:
        if required != supported:
            _refuse("generic-template-mismatch", "/requirement/" + name,
                    {"required": required, "supported": supported})
    if requirement.max_outstanding > endpoint["max_outstanding"]:
        _refuse("generic-template-mismatch", "/requirement/max_outstanding",
                {"required": requirement.max_outstanding,
                 "supported": endpoint["max_outstanding"]})
    missing_operations = sorted(set(requirement.operations)
                                - set(endpoint["operations"]))
    if missing_operations:
        _refuse("generic-semantic-unsupported", "/requirement/operations",
                {"missing": missing_operations,
                 "supported": endpoint["operations"]})
    missing_evidence = sorted(set(requirement.evidence_obligations)
                              - set(endpoint["evidence_capabilities"]))
    if missing_evidence:
        _refuse("generic-evidence-missing",
                "/requirement/evidence_obligations",
                {"missing": missing_evidence,
                 "supported": endpoint["evidence_capabilities"]})
    if requirement.byte_enable_required and endpoint["byte_enable"] is not True:
        _refuse("generic-semantic-unsupported", "/requirement/byte_enable",
                {"reason": "byte-enable-not-proven"})


def _registration_matches(registration: AdapterRegistration, endpoint: dict) -> bool:
    return (
        endpoint["role"] in registration.roles
        and tuple(endpoint["protocol"]) == registration.protocol
        and endpoint["semantic_kind"] in registration.semantic_kinds
        and tuple(endpoint["template"]) in registration.templates
        and set(endpoint["operations"]) <= set(registration.operations)
        and endpoint["data_width"] in registration.data_widths
        and endpoint["address_width"] in registration.address_widths
        and endpoint["address_units"] in registration.address_units
        and endpoint["completion_kind"] in registration.completion_kinds
        and (endpoint["byte_enable"] is False or registration.byte_enable)
        and endpoint["max_outstanding"] <= registration.max_outstanding
        and set(endpoint["evidence_capabilities"])
        <= set(registration.evidence_capabilities)
    )


def _select_from(registrations_, component: VerifiedComponent,
                 endpoint: dict) -> AdapterRegistration:
    candidates = [row for row in registrations_
                  if _registration_matches(row, endpoint)]
    if not candidates:
        _refuse("generic-adapter-missing", "/selection",
                {"endpoint_id": endpoint["endpoint_id"],
                 "protocol": endpoint["protocol"],
                 "semantic_kind": endpoint["semantic_kind"],
                 "template": endpoint["template"]})
    if len(candidates) > 1:
        _refuse("generic-adapter-ambiguous", "/selection",
                {"adapters": sorted(row.adapter_id for row in candidates)})
    return candidates[0]


def _check_drift(registration: AdapterRegistration, expected: str) -> None:
    if registration.implementation_sha256() != expected:
        _refuse("generic-binding-drift", "/adapter",
                {"adapter_id": registration.adapter_id,
                 "reason": "implementation-changed"})


# Import-time pins: drift is a refusal, never a silent re-baseline.
_IMPLEMENTATION_PINS = {
    row.adapter_id: row.implementation_sha256() for row in _REGISTRATIONS
}


def select_adapter(component: VerifiedComponent,
                   requirement: CapabilityRequirement, *,
                   preparation: PreparationContext) -> AdapterSelection:
    """Select the unique adapter; record it in the issuing preparation."""
    if type(preparation) is not PreparationContext:
        _refuse("generic-contract-type", "/preparation")
    preparation.require_open()
    if type(component) is not VerifiedComponent:
        _refuse("generic-contract-type", "/component")
    if type(requirement) is not CapabilityRequirement:
        _refuse("generic-contract-type", "/requirement")
    preparation.require_component(component)
    endpoint = _endpoint_for(component, requirement)
    _verify_requirement(endpoint, requirement)
    registration = _select_from(_REGISTRATIONS, component, endpoint)
    _check_drift(registration, _IMPLEMENTATION_PINS[registration.adapter_id])
    if registration.protocol != tuple(requirement.protocol):
        _refuse("generic-adapter-missing", "/selection",
                {"reason": "requirement-protocol-not-supported"})
    selection = AdapterSelection(
        adapter_id=registration.adapter_id,
        adapter_version=registration.adapter_version,
        implementation_sha256=_IMPLEMENTATION_PINS[registration.adapter_id],
        component_artifact_sha256=component.artifact_sha256,
        semantic_contract_sha256=component.semantic_contract_sha256)
    return preparation.issue_selection(selection)


def selection_document(selection: AdapterSelection) -> dict:
    return selection.document()
