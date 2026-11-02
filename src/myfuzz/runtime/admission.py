"""Trusted admission of a real runtime artifact into a VerifiedComponent.

The verifier is code-owned.  Callers cannot inject a verifier, factory, class or
import string.  Every positive path reuses the existing source-lock, generated
artifact, native-trace, storage-probe and template checks; a passing admission is
still only a static component description, never a native grant.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from pathlib import Path

from myfuzz.local_harness.apb_storage_probe_contract import storage_probe_selection
from myfuzz.local_harness.apb_storage_probe_verification import (
    verified_storage_observation,
)
from myfuzz.local_harness.apb_storage_source_contract import (
    apb_storage_address_matches,
    validate_apb_storage_source_contract,
)
from myfuzz.local_harness.wishbone_storage_probe_contract import (
    wishbone_storage_probe_selection,
)
from myfuzz.local_harness.wishbone_storage_probe_verification import (
    verified_wishbone_storage_observation,
)
from myfuzz.local_harness.wishbone_storage_source_contract import (
    validate_wishbone_storage_source_contract,
    wishbone_setup_matches,
)
from myfuzz.local_harness.native_physical_observation import (
    verify_apb_register_trace,
    verify_cpu_obi_protocol_traces,
)
from myfuzz.local_harness.runtime_artifact import LocalRuntimeArtifact
from myfuzz.local_harness.template_contracts import list_template_contracts

from .contracts import (
    DESCRIPTOR_SCHEMA,
    GenericRuntimeRefused,
    VerifiedComponent,
    canonical_json_bytes,
    require_digest,
)
from .preparation import PreparationContext
from .semantics.storage import (
    STORAGE_RW,
    storage_register_facts,
    storage_semantic_contract,
)

_ROOT = Path(__file__).resolve().parents[3]

APB_STORAGE_VERIFIER_ID = "apb.storage.admission.v1"
OBI_CPU_VERIFIER_ID = "obi.cpu.admission.v1"
CPU_SEMANTIC_KIND = "cpu.obi.v1"

_CPU_FUNCTIONS = frozenset({"memory_master", "processor_memory_master",
                            "instruction_memory_master", "data_memory_master"})

_STORAGE_VERIFIER_FILES = (
    "src/myfuzz/runtime/admission.py",
    "src/myfuzz/runtime/semantics/storage.py",
    "src/myfuzz/runtime/semantics/contracts.py",
    "src/myfuzz/local_harness/apb_storage_source_contract.py",
    "src/myfuzz/local_harness/apb_storage_probe_verification.py",
    "src/myfuzz/local_harness/apb_storage_probe_contract.py",
    "src/myfuzz/local_harness/native_physical_observation.py",
    "src/myfuzz/integration/generated_storage_consumer.py",
)
_CPU_VERIFIER_FILES = (
    "src/myfuzz/runtime/admission.py",
    "src/myfuzz/local_harness/native_physical_observation.py",
    "src/myfuzz/local_harness/cpu_session.py",
    "src/myfuzz/local_harness/template_contracts.py",
)

_STORAGE_EVIDENCE = ("component_semantic_effect",
                     "cross_component_consumption",
                     "cross_component_source",
                     "physical_protocol_sample")
_CPU_EVIDENCE = ("cross_component_consumption", "cross_component_source",
                 "physical_protocol_sample")
_WISHBONE_CPU_VERIFIER_FILES = (
    "src/myfuzz/runtime/admission.py",
    "src/myfuzz/runtime/adapters/wishbone_cpu.py",
    "src/myfuzz/local_harness/wishbone_cpu_session.py",
)
_INSTRUCTION_EVIDENCE = ("cross_component_source", "physical_protocol_sample")


def _refuse(code: str, pointer: str = "", detail=None) -> None:
    raise GenericRuntimeRefused(code, pointer, detail)


def _file_sha(relative: str) -> str:
    try:
        return sha256((_ROOT / relative).read_bytes()).hexdigest()
    except OSError as error:
        _refuse("generic-source-unverified", "/source_verifier",
                {"reason": "implementation-unreadable", "file": relative})


def _pin(files: tuple[str, ...]) -> str:
    return sha256(canonical_json_bytes(
        {name: _file_sha(name) for name in files})).hexdigest()


def apb_storage_verifier_identity() -> dict:
    return {"id": APB_STORAGE_VERIFIER_ID, "version": "1",
            "implementation_sha256": _pin(_STORAGE_VERIFIER_FILES)}


def obi_cpu_verifier_identity() -> dict:
    return {"id": OBI_CPU_VERIFIER_ID, "version": "1",
            "implementation_sha256": _pin(_CPU_VERIFIER_FILES)}


def _source_sha256(artifact: LocalRuntimeArtifact) -> str:
    try:
        return sha256(canonical_json_bytes(artifact.source_verification)).hexdigest()
    except GenericRuntimeRefused:
        _refuse("generic-source-unverified", "/source_verification",
                {"reason": "source-closure-not-canonical"})
    raise AssertionError("unreachable")


def _artifact_sha256(artifact: LocalRuntimeArtifact) -> str:
    digest = artifact.runtime_document.get("artifact_digest")
    require_digest(digest, "/artifact_digest")
    return digest


def _profile_sha256(artifact: LocalRuntimeArtifact) -> str:
    digest = getattr(artifact.plan, "profile_sha256", None)
    require_digest(digest, "/profile_sha256")
    return digest


def _template_contract(protocol, triple, function: str):
    side_cpu = function in _CPU_FUNCTIONS
    rows = [row for row in list_template_contracts()
            if (row.template_id, row.template_version, row.variant_id) == triple]
    if len(rows) != 1:
        _refuse("generic-template-mismatch", "/template",
                {"template": list(triple), "matches": len(rows)})
    contract = rows[0]
    if tuple(contract.protocol) != tuple(protocol):
        _refuse("generic-template-mismatch", "/template/protocol",
                {"declared": list(protocol), "template": list(contract.protocol)})
    if (contract.side in ("cpu", "master")) != side_cpu:
        _refuse("generic-template-mismatch", "/template/side",
                {"function": function, "side": contract.side})
    return contract


def _operations_of(contract) -> tuple[str, ...]:
    roles = set(contract.required_roles) | set(contract.optional_roles)
    operations = []
    if roles & {"rdata", "prdata", "dat_r", "hrdata"}:
        operations.append("read")
    if ({"pwrite", "pwdata"} <= roles or {"we", "wdata"} <= roles
            or {"stb", "we", "dat_w"} <= roles):
        operations.append("write")
    if not operations:
        _refuse("generic-semantic-unsupported", "/template/roles",
                {"reason": "no-read-write-role"})
    return tuple(sorted(operations))


def _binding_endpoint(artifact: LocalRuntimeArtifact, endpoint_id: str) -> dict:
    document = artifact.runtime_document
    selection = document.get("selected_template")
    try:
        binding = selection["executor"]["binding"]
        endpoints = binding["endpoints"]
    except (KeyError, TypeError):
        _refuse("generic-template-mismatch", "/selected_template",
                {"reason": "generated-template-binding-required"})
    rows = [row for row in endpoints if row.get("endpoint_id") == endpoint_id]
    if len(rows) != 1:
        _refuse("generic-template-mismatch", "/selected_template/endpoints",
                {"endpoint_id": endpoint_id, "matches": len(rows)})
    return rows[0]


def _verify_artifact_roles(artifact: LocalRuntimeArtifact, endpoint_id: str,
                           protocol, contract, profile) -> dict:
    """The generated artifact must physically implement the declared template."""
    row = _binding_endpoint(artifact, endpoint_id)
    if [str(item) for item in row.get("protocol") or ()] != list(protocol):
        _refuse("generic-template-mismatch", "/selected_template/protocol",
                {"endpoint_id": endpoint_id})
    roles = {role.get("role"): role for role in row.get("roles") or ()}
    missing = [role for role in contract.required_roles if role not in roles]
    if missing:
        _refuse("generic-template-mismatch", "/selected_template/roles",
                {"endpoint_id": endpoint_id, "missing": sorted(missing)})
    capabilities = getattr(profile, "capabilities", {}) or {}
    data_width = capabilities.get("data_width")
    address_width = capabilities.get("address_width")
    if type(data_width) is not int or type(address_width) is not int:
        _refuse("generic-source-unverified", "/profile/capabilities",
                {"reason": "declared-width-required"})
    for role in ("pwdata", "prdata", "wdata", "rdata", "dat_w", "dat_r", "hrdata",
                 "hwdata"):
        if role in roles and roles[role].get("width") != data_width:
            _refuse("generic-template-mismatch", "/selected_template/roles/" + role,
                    {"expected": data_width, "actual": roles[role].get("width")})
    for role in ("paddr", "addr", "haddr", "adr"):
        if role in roles and roles[role].get("width") != address_width:
            _refuse("generic-template-mismatch", "/selected_template/roles/" + role,
                    {"expected": address_width,
                     "actual": roles[role].get("width")})
    return {"roles": {name: {"width": value.get("width"),
                             "physical_port": value.get("physical_port"),
                             "direction": value.get("direction")}
                      for name, value in sorted(roles.items())}}


def _limits(contract) -> dict:
    return {key: value for key, value in contract.limits}


def _endpoint_document(*, endpoint_id: str, role: str, protocol, template,
                       semantic_kind: str, operations, data_width: int,
                       address_width: int, address_units: str,
                       max_outstanding: int, completion_kind: str,
                       byte_enable: bool, evidence_capabilities) -> dict:
    document = {
        "endpoint_id": endpoint_id,
        "role": role,
        "protocol": list(protocol),
        "template": list(template),
        "semantic_kind": semantic_kind,
        "operations": sorted(set(operations)),
        "data_width": data_width,
        "address_width": address_width,
        "address_units": address_units,
        "max_outstanding": max_outstanding,
        "completion_kind": completion_kind,
        "byte_enable": bool(byte_enable),
        "evidence_capabilities": sorted(set(evidence_capabilities)),
    }
    return document


def _storage_observation_facts(artifact: LocalRuntimeArtifact, *,
                               preparation: PreparationContext, base_dir: Path):
    """Storage observation semantics of one prepared artifact.

    This is admission's reusable deep check for the storage layer.  It reads the
    artifact's plan, runtime document, generated runtime source and observation
    ``{contract_id, register}`` and derives the closed storage semantics.  It
    deliberately performs no generated-file pin check and no full runtime
    projection: those belong to ``verify_component``/``assert_artifact_current``
    and to the structural check that runs after this function, so a wrong
    register selection, an authority claim or a tampered source contract each
    refuses at the layer that owns the fact.
    """
    instance_id = artifact.plan.request.instance_id
    endpoints = [endpoint for endpoint in artifact.plan.binding.endpoints
                 if endpoint.protocol == ("apb", "3")
                 and endpoint.function == "mmio_slave"]
    if len(endpoints) != 1:
        _refuse("generic-semantic-unsupported", "/profile/endpoints",
                {"reason": "one-apb3-mmio-slave-required",
                 "matches": len(endpoints)})
    endpoint = endpoints[0]
    endpoint_id = endpoint.endpoint_id
    template = preparation.declared_endpoint_template(instance_id, endpoint_id)
    contract = _template_contract(("apb", "3"), template, endpoint.function)
    role_facts = _verify_artifact_roles(artifact, endpoint_id, ("apb", "3"),
                                        contract, artifact.plan.profile)
    limits = _limits(contract)

    document = artifact.runtime_document
    if document.get("kind") != "apb3_register_observe":
        _refuse("generic-semantic-unsupported", "/artifact/kind",
                {"expected": "apb3_register_observe",
                 "actual": document.get("kind")})
    if document.get("dynamic_physical_inputs") or document.get(
            "bound_physical_inputs"):
        _refuse("generic-semantic-unsupported", "/artifact/inputs",
                {"reason": "input-producer-unsupported"})

    try:
        selection = storage_probe_selection(artifact.plan)
    except ValueError as error:
        _refuse("generic-semantic-unsupported", "/plan/tuning/storage",
                {"reason": str(error)[:160]})
    observation = document.get("storage_observation")
    if (not isinstance(observation, dict) or selection is None
            or observation.get("schema_version") != "apb_storage_probe.v1"
            or observation.get("scope") != "generated_expression_source_mapped"
            or observation.get("sample_group") != "storage_probes"
            or observation.get("selection") != selection
            or any(observation.get(key) is not False for key in (
                "reset_authority", "version_authority", "source_authority"))):
        _refuse("generic-semantic-unsupported", "/artifact/storage_observation",
                {"reason": "closed-storage-observation-required"})
    try:
        registered = validate_apb_storage_source_contract(
            observation.get("source_contract"), artifact.plan.profile,
            base_dir=Path(base_dir))
    except ValueError as error:
        _refuse("generic-source-unverified", "/storage_observation/source_contract",
                {"reason": str(error)[:160]})
    if (selection.get("contract_id") != registered.get("contract_id")
            or selection.get("register") != registered["register"]["name"]):
        _refuse("generic-semantic-unsupported", "/artifact/storage_observation/selection",
                {"reason": "source-contract-selection-mismatch"})
    register = registered["register"]
    if (type(register.get("width")) is not int or register["width"] != 32
            or type(register.get("canonical_offset")) is not int
            or type(register.get("write_mask")) is not int
            or type(register.get("read_mask")) is not int):
        _refuse("generic-semantic-unsupported", "/storage_observation/register",
                {"reason": "full-word-storage-required"})
    if apb_storage_address_matches(registered,
                                   register["canonical_offset"]) is not True:
        _refuse("generic-semantic-unsupported", "/storage_observation/decode",
                {"reason": "canonical-offset-not-a-storage-alias"})
    try:
        verification = verified_storage_observation(
            observation, runtime_sv=artifact.runtime_sv,
            wrapper_sha256=(document.get("structural_build") or {}).get(
                "wrapper_sha256"),
            base_dir=Path(base_dir))
    except ValueError as error:
        _refuse("generic-source-unverified",
                "/artifact/storage_observation/expression",
                {"reason": str(error)[:160]})

    semantic = storage_semantic_contract(
        registered=registered, endpoint_id=endpoint_id, template=template,
        observation_scope=observation["scope"])
    facts = storage_register_facts(semantic)
    capabilities = artifact.plan.profile.capabilities
    if (capabilities.get("data_width") != 32
            or capabilities.get("address_width") != facts["address_width"]):
        _refuse("generic-template-mismatch", "/profile/capabilities",
                {"reason": "width-mismatch", "semantic_address_width":
                 facts["address_width"]})
    endpoint_document = _endpoint_document(
        endpoint_id=endpoint_id, role="target", protocol=("apb", "3"),
        template=template, semantic_kind=STORAGE_RW,
        operations=("read", "write"),
        data_width=32, address_width=facts["address_width"],
        address_units=facts["address_units"],
        max_outstanding=limits.get("max_outstanding", 1),
        completion_kind=limits.get("completion", "setup_access_response"),
        byte_enable=bool(limits.get("byte_enable", False)),
        evidence_capabilities=_STORAGE_EVIDENCE)
    return {
        "semantic_contract_sha256": semantic.sha256_hex,
        "endpoints": [endpoint_document],
        "source_verifier": apb_storage_verifier_identity(),
        "facts": {"registered": registered, "semantic": semantic,
                  "observation": verification, "roles": role_facts,
                  "limits": limits},
    }


def _storage_endpoint(artifact: LocalRuntimeArtifact, *,
                      preparation: PreparationContext, base_dir: Path):
    """Trusted storage verifier: closed semantics, then the generated projection."""
    if artifact.runtime_document.get('storage_observation') is None:
        from .adapters.apb3_mmio import admission_facts
        return admission_facts(artifact,preparation=preparation,base_dir=base_dir)
    facts = _storage_observation_facts(artifact, preparation=preparation,
                                       base_dir=base_dir)
    try:
        verified = verify_apb_register_trace(artifact)
    except ValueError as error:
        _refuse("generic-source-unverified", "/artifact/protocol_trace",
                {"reason": str(error)[:160]})
    if verified is not True:
        _refuse("generic-source-unverified", "/artifact/protocol_trace")
    facts["facts"]["protocol_trace"] = True
    return facts


def wishbone_cpu_verifier_identity() -> dict:
    return {"id": "wishbone.cpu.admission.v1", "version": "1",
            "implementation_sha256": _pin(_WISHBONE_CPU_VERIFIER_FILES)}


def _wishbone_verifier_identity() -> dict:
    from .adapters.wishbone_storage import verifier_identity
    return verifier_identity()


def _wishbone_storage_observation_facts(artifact: LocalRuntimeArtifact, *,
                                            preparation: PreparationContext,
                                            base_dir: Path):
    """Deep Wishbone storage verifier for the WBUART SETUP row.

    The source row, probe document, semantic contract and protocol trace are
    re-derived by the code-owned Wishbone adapter; admission only joins that
    derivation to the component descriptor.  No native hierarchy proof exists,
    so hierarchy/native authority stays false.
    """
    from .adapters.wishbone_storage import (
        artifact_contract_facts as wishbone_artifact_contract_facts,
    )
    instance_id = artifact.plan.request.instance_id
    endpoints = [endpoint for endpoint in artifact.plan.binding.endpoints
                 if endpoint.protocol == ("wishbone", "classic")
                 and endpoint.function == "mmio_slave"]
    if len(endpoints) != 1:
        _refuse("generic-semantic-unsupported", "/profile/endpoints",
                {"reason": "one-wishbone-mmio-slave-required",
                 "matches": len(endpoints)})
    endpoint_id = endpoints[0].endpoint_id
    template = preparation.declared_endpoint_template(instance_id, endpoint_id)
    document = artifact.runtime_document
    observation = document.get("storage_observation")
    if observation is not None:
        try:
            verified_wishbone_storage_observation(
                observation, artifact, base_dir=Path(base_dir))
        except ValueError as error:
            _refuse("generic-source-unverified",
                    "/artifact/storage_observation/expression",
                    {"reason": str(error)[:160]})
    registered, semantic, bound, trace = wishbone_artifact_contract_facts(
        artifact, base_dir=Path(base_dir), endpoint_id=endpoint_id,
        template=template)
    facts = storage_register_facts(semantic)
    endpoint_document = _endpoint_document(
        endpoint_id=endpoint_id, role="target",
        protocol=("wishbone", "classic"), template=template,
        semantic_kind=STORAGE_RW, operations=("read", "write"),
        data_width=32, address_width=facts["address_width"],
        address_units=facts["address_units"],
        max_outstanding=1, completion_kind="registered_ack",
        byte_enable=True, evidence_capabilities=_STORAGE_EVIDENCE)
    return {
        "semantic_contract_sha256": semantic.sha256_hex,
        "endpoints": [endpoint_document],
        "source_verifier": _wishbone_verifier_identity(),
        "facts": {"registered": registered, "semantic": semantic,
                  "bound": bound, "trace": trace},
    }


def _wishbone_storage_endpoint(artifact: LocalRuntimeArtifact, *,
                                  preparation: PreparationContext,
                                  base_dir: Path):
    if artifact.runtime_document.get('storage_observation') is None:
        from .adapters.wishbone_mmio import admission_facts
        return admission_facts(artifact, preparation=preparation, base_dir=base_dir)
    facts = _wishbone_storage_observation_facts(
        artifact, preparation=preparation, base_dir=base_dir)
    facts["facts"]["protocol_trace"] = True
    return facts


def cpu_execution_surface_document(artifact: LocalRuntimeArtifact) -> dict:
    """Documentary CPU execution surface; the CPU ABI layer is not yet certified."""
    document = artifact.runtime_document
    binding = document.get("selected_template", {}).get("executor", {}).get(
        "binding", {})
    endpoints = []
    for row in binding.get("endpoints") or ():
        endpoints.append({
            "endpoint_id": row.get("endpoint_id"),
            "function": row.get("function"),
            "protocol": list(row.get("protocol") or ()),
            "roles": [
                {"role": role.get("role"), "width": role.get("width"),
                 "direction": role.get("direction"),
                 "physical_port": role.get("physical_port")}
                for role in sorted(row.get("roles") or (),
                                   key=lambda item: item.get("role") or "")
            ],
        })
    surface = {
        "schema_version": "cpu_execution_surface.v1",
        "kind": CPU_SEMANTIC_KIND,
        "source_sha256": _source_sha256(artifact),
        "profile_sha256": _profile_sha256(artifact),
        "artifact_sha256": _artifact_sha256(artifact),
        "executor_template": deepcopy(document.get("selected_template", {}).get(
            "contract")),
        "boot_contract": deepcopy(document.get("boot_contract")),
        "instruction_endpoints": sorted(
            endpoint.endpoint_id for endpoint in artifact.plan.binding.endpoints
            if endpoint.function == "instruction_memory_master"),
        "endpoints": endpoints,
    }
    return surface


def _cpu_endpoints(artifact: LocalRuntimeArtifact, *,
                   preparation: PreparationContext, base_dir: Path):
    """CPU execution-surface facts of one prepared artifact.

    Like the storage check this is the reusable deep layer: it verifies the OBI
    protocol projection, the declared CPU data endpoint and the certified run
    roles, and it performs no generated-file pin check (``verify_component``
    runs that first) and issues no CPU-ABI authority.
    """
    instance_id = artifact.plan.request.instance_id
    document = artifact.runtime_document
    if document.get("kind") != "obi_cpu":
        _refuse("generic-semantic-unsupported", "/artifact/kind",
                {"expected": "obi_cpu", "actual": document.get("kind")})
    try:
        verified = verify_cpu_obi_protocol_traces(artifact)
    except ValueError as error:
        _refuse("generic-source-unverified", "/artifact/protocol_trace",
                {"reason": str(error)[:160]})
    if verified is not True:
        _refuse("generic-source-unverified", "/artifact/protocol_trace")
    capabilities = artifact.plan.profile.capabilities
    data_width = capabilities.get("data_width")
    address_width = capabilities.get("address_width")
    if type(data_width) is not int or type(address_width) is not int:
        _refuse("generic-source-unverified", "/profile/capabilities",
                {"reason": "declared-width-required"})
    surface = cpu_execution_surface_document(artifact)
    if not surface["instruction_endpoints"]:
        _refuse("generic-semantic-unsupported", "/artifact/endpoints",
                {"reason": "instruction-endpoint-required"})
    endpoint_id = preparation.declared_cpu_data_endpoint(instance_id)
    rows = [endpoint for endpoint in artifact.plan.binding.endpoints
            if endpoint.endpoint_id == endpoint_id]
    if len(rows) != 1 or rows[0].protocol != ("obi", "1"):
        _refuse("generic-template-mismatch", "/profile/endpoints",
                {"reason": "declared-obi-data-endpoint-required",
                 "endpoint_id": endpoint_id})
    endpoint = rows[0]
    template = preparation.declared_endpoint_template(instance_id,
                                                      endpoint.endpoint_id)
    contract = _template_contract(("obi", "1"), template, endpoint.function)
    _verify_artifact_roles(artifact, endpoint.endpoint_id, ("obi", "1"),
                           contract, artifact.plan.profile)
    limits = _limits(contract)
    operations = _operations_of(contract)
    endpoint_document = _endpoint_document(
        endpoint_id=endpoint.endpoint_id, role="cpu", protocol=("obi", "1"),
        template=template, semantic_kind=CPU_SEMANTIC_KIND,
        operations=operations, data_width=data_width,
        address_width=address_width, address_units="byte",
        max_outstanding=limits.get("max_outstanding", 1),
        completion_kind=limits.get("completion", "grant_then_response"),
        byte_enable=bool(limits.get("byte_enable", False)),
        evidence_capabilities=_CPU_EVIDENCE)
    return {
        "semantic_contract_sha256": sha256(
            canonical_json_bytes(surface)).hexdigest(),
        "endpoints": [endpoint_document],
        "source_verifier": obi_cpu_verifier_identity(),
        "facts": {"surface": surface},
    }


def _ahb_cpu_endpoints(artifact: LocalRuntimeArtifact, *, preparation: PreparationContext, base_dir: Path):
    from .adapters.ahb_cpu import (ahb_cpu_surface_document,AHB_CPU_SEMANTIC_KIND,
        AHB_CPU_PROTOCOL,AHB_CPU_TEMPLATE,AHB_CPU_COMPLETION)
    try:surface=ahb_cpu_surface_document(artifact)
    except ValueError as error:
        _refuse('generic-source-unverified','/artifact/cpu_surface',{'reason':str(error)[:160]})
    instance=artifact.plan.request.instance_id
    endpoint_id=preparation.declared_cpu_data_endpoint(instance)
    if endpoint_id!=surface['endpoint_id']:
        _refuse('generic-template-mismatch','/cpu/data_endpoint')
    template=preparation.declared_endpoint_template(instance,endpoint_id)
    if template!=AHB_CPU_TEMPLATE:_refuse('generic-template-mismatch','/cpu/template')
    endpoint=next(e for e in artifact.plan.binding.endpoints if e.endpoint_id==endpoint_id)
    contract=_template_contract(AHB_CPU_PROTOCOL,template,endpoint.function)
    _verify_artifact_roles(artifact,endpoint_id,AHB_CPU_PROTOCOL,contract,artifact.plan.profile)
    document=_endpoint_document(endpoint_id=endpoint_id,role='cpu',protocol=AHB_CPU_PROTOCOL,
        template=template,semantic_kind=AHB_CPU_SEMANTIC_KIND,operations=('read','write'),
        data_width=32,address_width=34,address_units='byte',max_outstanding=1,
        completion_kind=AHB_CPU_COMPLETION,byte_enable=True,evidence_capabilities=_CPU_EVIDENCE)
    files=('src/myfuzz/runtime/admission.py','src/myfuzz/runtime/adapters/ahb_cpu.py',
        'src/myfuzz/local_harness/ahb_lite_session.py','src/myfuzz/scenario/ahb_cpu_events.py')
    return dict(semantic_contract_sha256=sha256(canonical_json_bytes(surface)).hexdigest(),
        endpoints=[document],source_verifier=dict(id='ahb-lite.cpu.admission.v1',version='1',implementation_sha256=_pin(files)),
        facts=dict(surface=surface,limits=_limits(contract)))


def _tl_coherent_cpu_endpoints(artifact: LocalRuntimeArtifact, *,
                                preparation: PreparationContext,
                                base_dir: Path):
    """CPU execution-surface facts of the coherent TileLink client.

    Mirrors the AHB row: the deep check verifies the declared 39-role shape, the
    profile's widths and the artifact's own tap bindings, and performs no
    generated-file pin check (``verify_component`` runs that first).  The
    instruction hop is *refused by name*: the artifact publishes that one shared
    A/D boundary carries fetches and data, so no instruction-hop authority is
    issued here.
    """
    from .adapters.tilelink_cpu import (TL_CPU_COMPLETION, TL_CPU_PROTOCOL,
        TL_CPU_SEMANTIC_KIND, TL_CPU_TEMPLATE, tl_coherent_cpu_surface_document)
    document = artifact.runtime_document
    if document.get("kind") != "tilelink_coherent_cpu":
        _refuse("generic-semantic-unsupported", "/artifact/kind",
                {"expected": "tilelink_coherent_cpu", "actual": document.get("kind")})
    try:
        surface = tl_coherent_cpu_surface_document(artifact)
    except ValueError as error:
        _refuse('generic-source-unverified', '/artifact/cpu_surface',
                {'reason': str(error)[:160]})
    instance = artifact.plan.request.instance_id
    endpoint_id = preparation.declared_cpu_data_endpoint(instance)
    if endpoint_id != surface['endpoint_id']:
        _refuse('generic-template-mismatch', '/cpu/data_endpoint')
    template = preparation.declared_endpoint_template(instance, endpoint_id)
    if template != TL_CPU_TEMPLATE:
        _refuse('generic-template-mismatch', '/cpu/template')
    endpoint = next(row for row in artifact.plan.binding.endpoints
                    if row.endpoint_id == endpoint_id)
    contract = _template_contract(TL_CPU_PROTOCOL, template, endpoint.function)
    _verify_artifact_roles(artifact, endpoint_id, TL_CPU_PROTOCOL, contract,
                           artifact.plan.profile)
    endpoint_document = _endpoint_document(
        endpoint_id=endpoint_id, role="cpu", protocol=TL_CPU_PROTOCOL,
        template=template, semantic_kind=TL_CPU_SEMANTIC_KIND,
        operations=("read", "write"),
        data_width=surface["data_width"],
        address_width=surface["address_width"],
        address_units="byte", max_outstanding=surface["max_outstanding"],
        completion_kind=TL_CPU_COMPLETION, byte_enable=True,
        evidence_capabilities=_CPU_EVIDENCE)
    files = ('src/myfuzz/runtime/admission.py',
             'src/myfuzz/runtime/adapters/tilelink_cpu.py',
             'src/myfuzz/integration/cpu_tlul.py',
             'src/myfuzz/local_harness/tilelink_coherent_session.py',
             'src/myfuzz/local_harness/tilelink_coherent_fields.py',
             'src/myfuzz/local_harness/session.py')
    return dict(
        semantic_contract_sha256=sha256(canonical_json_bytes(surface)).hexdigest(),
        endpoints=[endpoint_document],
        source_verifier=dict(id='tilelink.cpu.admission.v1', version='1',
                             implementation_sha256=_pin(files)),
        facts=dict(surface=surface, limits=_limits(contract)))


def _wishbone_cpu_endpoints(artifact: LocalRuntimeArtifact, *,
                              preparation: PreparationContext,
                              base_dir: Path):
    from .adapters.wishbone_cpu import (
        WISHBONE_CPU_SEMANTIC_KIND,
        wishbone_cpu_surface_document,
    )
    document = artifact.runtime_document
    if document.get("kind") != "wishbone_cpu":
        _refuse("generic-semantic-unsupported", "/artifact/kind",
                {"expected": "wishbone_cpu", "actual": document.get("kind")})
    try:
        surface = wishbone_cpu_surface_document(artifact)
    except ValueError as error:
        _refuse("generic-source-unverified", "/artifact/cpu_surface",
                {"reason": str(error)[:160]})
    instance_id = artifact.plan.request.instance_id
    endpoint_id = preparation.declared_cpu_data_endpoint(instance_id)
    rows = [endpoint for endpoint in artifact.plan.binding.endpoints
            if endpoint.endpoint_id == endpoint_id]
    if (len(rows) != 1
            or rows[0].protocol != ("wishbone", "classic")):
        _refuse("generic-template-mismatch", "/profile/endpoints",
                {"reason": "declared-wishbone-data-endpoint-required",
                 "endpoint_id": endpoint_id})
    endpoint = rows[0]
    template = preparation.declared_endpoint_template(instance_id,
                                                      endpoint.endpoint_id)
    contract = _template_contract(("wishbone", "classic"), template,
                                  endpoint.function)
    capabilities = artifact.plan.profile.capabilities
    _verify_artifact_roles(artifact, endpoint.endpoint_id,
                           ("wishbone", "classic"), contract,
                           artifact.plan.profile)
    limits = _limits(contract)
    operations = _operations_of(contract)
    endpoint_document = _endpoint_document(
        endpoint_id=endpoint.endpoint_id, role="cpu",
        protocol=("wishbone", "classic"), template=template,
        semantic_kind=WISHBONE_CPU_SEMANTIC_KIND,
        operations=operations, data_width=32, address_width=32,
        address_units="byte", max_outstanding=1,
        completion_kind="cycle_strobe_held_until_ack",
        byte_enable=True, evidence_capabilities=_CPU_EVIDENCE)
    return {
        "semantic_contract_sha256": sha256(
            canonical_json_bytes(surface)).hexdigest(),
        "endpoints": [endpoint_document],
        "source_verifier": wishbone_cpu_verifier_identity(),
        "facts": {"surface": surface, "limits": limits},
    }


def _axi4lite_cpu_endpoints(artifact: LocalRuntimeArtifact, *,
                            preparation: PreparationContext, base_dir: Path):
    from .adapters.axi4lite_cpu import (
        AXI4LITE_CPU_COMPLETION, AXI4LITE_CPU_PROTOCOL, AXI4LITE_CPU_SEMANTIC_KIND,
        AXI4LITE_CPU_TEMPLATE, axi4lite_cpu_surface_document)
    document = artifact.runtime_document
    if document.get("kind") != "axi4_lite_cpu":
        _refuse("generic-semantic-unsupported", "/artifact/kind",
                {"expected": "axi4_lite_cpu", "actual": document.get("kind")})
    try:
        surface = axi4lite_cpu_surface_document(artifact)
    except ValueError as error:
        _refuse("generic-source-unverified", "/artifact/cpu_surface",
                {"reason": str(error)[:160]})
    instance_id = artifact.plan.request.instance_id
    endpoint_id = preparation.declared_cpu_data_endpoint(instance_id)
    if endpoint_id != surface["endpoint_id"]:
        _refuse("generic-template-mismatch", "/cpu/data_endpoint",
                {"declared": endpoint_id, "certified": surface["endpoint_id"]})
    template = preparation.declared_endpoint_template(instance_id, endpoint_id)
    if template != AXI4LITE_CPU_TEMPLATE:
        _refuse("generic-template-mismatch", "/cpu/template")
    endpoint = next(row for row in artifact.plan.binding.endpoints
                    if row.endpoint_id == endpoint_id)
    contract = _template_contract(AXI4LITE_CPU_PROTOCOL, template, endpoint.function)
    _verify_artifact_roles(artifact, endpoint_id, AXI4LITE_CPU_PROTOCOL, contract,
                           artifact.plan.profile)
    limits = _limits(contract)
    endpoint_document = _endpoint_document(
        endpoint_id=endpoint_id, role="cpu", protocol=AXI4LITE_CPU_PROTOCOL,
        template=template, semantic_kind=AXI4LITE_CPU_SEMANTIC_KIND,
        operations=("read", "write"), data_width=32, address_width=32,
        address_units="byte", max_outstanding=1,
        completion_kind=AXI4LITE_CPU_COMPLETION, byte_enable=True,
        evidence_capabilities=_CPU_EVIDENCE)
    files = ("src/myfuzz/runtime/admission.py",
             "src/myfuzz/runtime/adapters/axi4lite_cpu.py",
             "src/myfuzz/local_harness/axi_lite_session.py")
    return {"semantic_contract_sha256": sha256(
                canonical_json_bytes(surface)).hexdigest(),
            "endpoints": [endpoint_document],
            "source_verifier": {"id": "axi4-lite.cpu.admission.v1",
                                "version": "1",
                                "implementation_sha256": _pin(files)},
            "facts": {"surface": surface, "limits": limits}}


def _reduced_axi_cpu_endpoints(artifact: LocalRuntimeArtifact, *,
                              preparation: PreparationContext, base_dir: Path):
    """Admit the pinned full AXI4 CPU and certify its execution surface.

    The surface document is one pure function of the generated artifact, so the
    bound adapter recomputes byte-identical facts and a plan cannot be bound to
    a different artifact.
    """
    from .adapters.axi4_cpu import (
        CPU_COMPLETION, CPU_PROTOCOL, CPU_SEMANTIC_KIND, CPU_TEMPLATE_DATA,
        CPU_TEMPLATE_FETCH, reduced_axi_cpu_surface_document, verifier_identity)
    document = artifact.runtime_document
    if document.get("kind") != "reduced_dual_axi_cpu":
        _refuse("generic-semantic-unsupported", "/artifact/kind",
                {"expected": "reduced_dual_axi_cpu",
                 "actual": document.get("kind")})
    try:
        surface = reduced_axi_cpu_surface_document(artifact)
    except ValueError as error:
        _refuse("generic-source-unverified", "/artifact/cpu_surface",
                {"reason": str(error)[:160]})
    instance_id = artifact.plan.request.instance_id
    endpoint_id = preparation.declared_cpu_data_endpoint(instance_id)
    if endpoint_id != surface["endpoint_id"]:
        _refuse("generic-template-mismatch", "/cpu/data_endpoint",
                {"declared": endpoint_id, "certified": surface["endpoint_id"]})
    template = preparation.declared_endpoint_template(instance_id, endpoint_id)
    if template != CPU_TEMPLATE_DATA:
        _refuse("generic-template-mismatch", "/cpu/template",
                {"declared": list(template),
                 "required": list(CPU_TEMPLATE_DATA)})
    endpoint = next(row for row in artifact.plan.binding.endpoints
                    if row.endpoint_id == endpoint_id)
    contract = _template_contract(CPU_PROTOCOL, template, endpoint.function)
    _verify_artifact_roles(artifact, endpoint_id, CPU_PROTOCOL, contract,
                           artifact.plan.profile)
    limits = _limits(contract)
    endpoint_document = _endpoint_document(
        endpoint_id=endpoint_id, role="cpu", protocol=CPU_PROTOCOL,
        template=template, semantic_kind=CPU_SEMANTIC_KIND,
        operations=("read", "write"), data_width=32, address_width=32,
        address_units="byte", max_outstanding=1,
        completion_kind=CPU_COMPLETION, byte_enable=True,
        evidence_capabilities=_CPU_EVIDENCE)
    facts = {"surface": surface, "limits": limits,
             "fetch_template": list(CPU_TEMPLATE_FETCH)}
    return {"semantic_contract_sha256": sha256(
                canonical_json_bytes(surface)).hexdigest(),
            "endpoints": [endpoint_document],
            "source_verifier": verifier_identity(),
            "facts": facts}


def _cva6_cpu_endpoints(artifact: LocalRuntimeArtifact, *,
                        preparation: PreparationContext, base_dir: Path):
    """Admit the packed single-port CVA6 AXI4 CPU and certify its surface.

    Same shape as the reduced dual AXI4 row, with two differences the artifact
    itself declares: one 64-bit packed master (so one request channel and no
    fetch endpoint) and an explicit ``instruction_hop_refusal`` -- the certified
    surface names the data chain only because the port carries no instruction
    attribute (core/axi_shim.sv:101,257,263).
    """
    from .adapters.cva6_axi4_cpu import (
        CVA6_CPU_COMPLETION, CVA6_CPU_PROTOCOL, CVA6_CPU_SEMANTIC_KIND,
        CVA6_CPU_TEMPLATE, cva6_axi4_cpu_surface_document, verifier_identity)
    document = artifact.runtime_document
    if document.get("kind") != "cva6_packed_axi4_cpu":
        _refuse("generic-semantic-unsupported", "/artifact/kind",
                {"expected": "cva6_packed_axi4_cpu",
                 "actual": document.get("kind")})
    try:
        surface = cva6_axi4_cpu_surface_document(artifact)
    except ValueError as error:
        _refuse("generic-source-unverified", "/artifact/cpu_surface",
                {"reason": str(error)[:160]})
    instance_id = artifact.plan.request.instance_id
    endpoint_id = preparation.declared_cpu_data_endpoint(instance_id)
    if endpoint_id != surface["endpoint_id"]:
        _refuse("generic-template-mismatch", "/cpu/data_endpoint",
                {"declared": endpoint_id, "certified": surface["endpoint_id"]})
    template = preparation.declared_endpoint_template(instance_id, endpoint_id)
    if template != CVA6_CPU_TEMPLATE:
        _refuse("generic-template-mismatch", "/cpu/template",
                {"declared": list(template),
                 "required": list(CVA6_CPU_TEMPLATE)})
    endpoint = next(row for row in artifact.plan.binding.endpoints
                    if row.endpoint_id == endpoint_id)
    contract = _template_contract(CVA6_CPU_PROTOCOL, template, endpoint.function)
    _verify_artifact_roles(artifact, endpoint_id, CVA6_CPU_PROTOCOL, contract,
                           artifact.plan.profile)
    limits = _limits(contract)
    endpoint_document = _endpoint_document(
        endpoint_id=endpoint_id, role="cpu", protocol=CVA6_CPU_PROTOCOL,
        template=template, semantic_kind=CVA6_CPU_SEMANTIC_KIND,
        # 32 is the certified *register transaction* width the executor
        # consumes (the MMIO register beat); the physical packed AXI4 data bus
        # is 64 bits wide and is declared in ``surface`` as
        # ``native_data_width``.
        operations=("read", "write"), data_width=32, address_width=64,
        address_units="byte", max_outstanding=1,
        completion_kind=CVA6_CPU_COMPLETION, byte_enable=True,
        evidence_capabilities=_CPU_EVIDENCE)
    facts = {"surface": surface, "limits": limits,
             "channel_model": "unified",
             "instruction_hop_refusal": surface["instruction_hop_refusal"],
             "supported_flows": list(surface["supported_flows"]),
             "refused_flows": list(surface["refused_flows"])}
    return {"semantic_contract_sha256": sha256(
                canonical_json_bytes(surface)).hexdigest(),
            "endpoints": [endpoint_document],
            "source_verifier": verifier_identity(),
            "facts": facts}


def _gpio_storage_endpoint(artifact, *, preparation, base_dir):
    from .adapters.gpio_storage import bank_contract_facts, verifier_identity, GPIO_TEMPLATE, GPIO_BANK_KIND
    rows=[e for e in artifact.plan.binding.endpoints if e.protocol == ('apb','3') and e.function == 'mmio_slave']
    if len(rows)!=1:
        _refuse('generic-semantic-unsupported','/profile/endpoints',{'reason':'one-causal-gpio-bus-required'})
    endpoint_id=rows[0].endpoint_id
    # Validate the APB wire roles without relabeling the causal executor ABI.
    wire_contract=_template_contract(('apb','3'),('target.apb3','1','full-word'),rows[0].function)
    _verify_artifact_roles(artifact,endpoint_id,('apb','3'),wire_contract,artifact.plan.profile)
    semantic=bank_contract_facts(artifact,base_dir=base_dir,endpoint_id=endpoint_id,template=GPIO_TEMPLATE)
    endpoint=_endpoint_document(endpoint_id=endpoint_id,role='target',protocol=('apb','3'),
        template=GPIO_TEMPLATE,semantic_kind=GPIO_BANK_KIND,operations=('read','write'),data_width=32,
        address_width=12,address_units='byte',max_outstanding=1,completion_kind='setup_access_response',
        byte_enable=False,evidence_capabilities=_STORAGE_EVIDENCE)
    return dict(semantic_contract_sha256=semantic.sha256_hex,endpoints=[endpoint],
        source_verifier=verifier_identity(),facts={'semantic':semantic,'registers':('GPIOEN','PADIN')})


_EXTENDED_TARGET_SPECS = {
    'tlul_register_observe': (('tl-ul', '1'),
        ('target.tl-ul', '1', 'user-integrity'),
        'myfuzz.integration.target_tlul', 'tlul_mmio_bank_facts',
        'tlul.mmio.admission.v1', 'a_valid_ready_then_d_valid_ready'),
    'axi4lite_register_observe': (('axi4-lite', '1'),
        ('target.axi4-lite', '1', 'single-outstanding-error-codes'),
        'myfuzz.integration.target_axi4lite', 'axi4lite_mmio_bank_facts',
        'axi4lite.mmio.admission.v1', 'independent_channels_response'),
    'ahb_lite_register_observe': (('ahb-lite', '1'),
        ('target.ahb-lite', '1', 'full-word-single'),
        'myfuzz.integration.target_ahb_lite', 'ahb_lite_mmio_bank_facts',
        'ahb-lite.mmio.admission.v1', 'address_phase_then_ready_completion'),
}


def _extended_storage_endpoint(artifact, *, preparation, base_dir):
    """Admit one of the extension target buses through its adapter module."""
    from importlib import import_module
    kind = artifact.runtime_document.get('kind')
    protocol, template, module_name, bank_name, verifier_id, completion = (
        _EXTENDED_TARGET_SPECS[kind])
    rows = [row for row in artifact.plan.binding.endpoints
            if row.protocol == protocol and row.function == 'mmio_slave']
    if len(rows) != 1:
        _refuse('generic-semantic-unsupported', '/profile/endpoints',
                {'reason': 'one-mmio-slave-target-required',
                 'protocol': list(protocol), 'matches': len(rows)})
    endpoint = rows[0]
    contract = _template_contract(protocol, template, endpoint.function)
    _verify_artifact_roles(artifact, endpoint.endpoint_id, protocol, contract,
                           artifact.plan.profile)
    module = import_module(module_name)
    bank = getattr(module, bank_name)(artifact, endpoint_id=endpoint.endpoint_id)
    address = artifact.plan.profile.address
    window = getattr(address, 'window_size', None)
    if type(window) is not int or window < 2:
        _refuse('generic-semantic-unsupported', '/profile/address',
                {'reason': 'declared-mmio-window-required'})
    address_width = (window - 1).bit_length()
    document = _endpoint_document(
        endpoint_id=endpoint.endpoint_id, role='target', protocol=protocol,
        template=template, semantic_kind='mmio.register-bank.v1',
        operations=('read', 'write'), data_width=32,
        address_width=address_width, address_units='byte',
        max_outstanding=1, completion_kind=completion, byte_enable=True,
        evidence_capabilities=_CPU_EVIDENCE)
    files = ('src/myfuzz/runtime/admission.py',
             f'src/myfuzz/integration/{module_name.rsplit(".", 1)[-1]}.py')
    return {'semantic_contract_sha256': bank.sha256_hex,
            'endpoints': [document],
            'source_verifier': {'id': verifier_id, 'version': '1',
                                'implementation_sha256': _pin(files)},
            'facts': {'semantic': bank}}


_BUILTIN_VERIFIERS = {
    "apb3_register_observe": _storage_endpoint,
    "apb_gpio": _gpio_storage_endpoint,
    "wishbone_register_observe": _wishbone_storage_endpoint,
    "wishbone_cpu": _wishbone_cpu_endpoints,
    "ahb_lite_cpu": _ahb_cpu_endpoints,
    "axi4_lite_cpu": _axi4lite_cpu_endpoints,
    "reduced_dual_axi_cpu": _reduced_axi_cpu_endpoints,
    "cva6_packed_axi4_cpu": _cva6_cpu_endpoints,
    "obi_cpu": _cpu_endpoints,
    "tilelink_coherent_cpu": _tl_coherent_cpu_endpoints,
    "tlul_register_observe": _extended_storage_endpoint,
    "axi4lite_register_observe": _extended_storage_endpoint,
    "ahb_lite_register_observe": _extended_storage_endpoint,
}


def _trusted_verifier(artifact: LocalRuntimeArtifact):
    """``verify_component``'s code-owned dispatch on the artifact kind.

    Callers cannot register or inject a verifier.  The dispatch is kept separate
    from the generated-file pin check so it can be exercised on a synthetic
    deep copy; ``verify_component`` always runs the pin check first.
    """
    kind = artifact.runtime_document.get("kind")
    verifier = _BUILTIN_VERIFIERS.get(kind)
    if verifier is None:
        _refuse("generic-source-unverified", "/artifact/kind",
                {"reason": "no-trusted-verifier", "kind": kind})
    return verifier


def verify_component(artifact: LocalRuntimeArtifact, *,
                     preparation: PreparationContext,
                     base_dir: Path) -> VerifiedComponent:
    """Admit one preparation-owned artifact; issue it into the same context."""
    if type(preparation) is not PreparationContext:
        _refuse("generic-contract-type", "/preparation")
    preparation.require_open()
    if type(artifact) is not LocalRuntimeArtifact:
        _refuse("generic-source-unverified", "/artifact",
                {"reason": "LocalRuntimeArtifact-required"})
    base = Path(base_dir).resolve()
    if preparation.inputs is None or base != Path(preparation.inputs.base_dir):
        _refuse("generic-source-unverified", "/base_dir",
                {"reason": "preparation-base-dir-mismatch"})
    instance_id = artifact.plan.request.instance_id
    if preparation.artifacts.get(instance_id) is not artifact:
        _refuse("generic-source-unverified", "/artifact",
                {"reason": "not-the-preparation-object",
                 "instance_id": instance_id})
    # Sealed bytes first: an artifact mutated in place is not the prepared one.
    preparation.assert_artifact_current(artifact)
    verifier = _trusted_verifier(artifact)
    try:
        facts = verifier(artifact, preparation=preparation, base_dir=base)
    except GenericRuntimeRefused:
        raise
    except ValueError as error:
        _refuse("generic-source-unverified", "/artifact",
                {"reason": str(error)[:160]})
    descriptor = {
        "schema_version": DESCRIPTOR_SCHEMA,
        "instance_id": instance_id,
        "source_sha256": _source_sha256(artifact),
        "profile_sha256": _profile_sha256(artifact),
        "artifact_sha256": _artifact_sha256(artifact),
        "semantic_contract_sha256": facts["semantic_contract_sha256"],
        "source_verifier": facts["source_verifier"],
        "endpoints": facts["endpoints"],
    }
    frozen = canonical_json_bytes(descriptor)
    component = VerifiedComponent(
        instance_id, descriptor["source_sha256"], descriptor["profile_sha256"],
        descriptor["artifact_sha256"], descriptor["semantic_contract_sha256"],
        frozen)
    return preparation.issue_component(component)


def admission_facts(component: VerifiedComponent) -> dict:
    """Decode a descriptor for adapters; membership still gates acceptance."""
    document = component.document()
    return {"source_verifier": document["source_verifier"],
            "endpoints": tuple(document["endpoints"])}
