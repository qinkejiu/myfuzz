"""AXI4-Lite CPU as the fourth generic CPU protocol: config-only, no CPUxIP code.

The scope of this module is the protocol adapter boundary, not a campaign.
``create_preparation`` really generates and compiles the execution files for the
pinned PicoRV32 AXI4-Lite CPU and the existing PULP APB3 I2C target, both
artifacts are admitted through the code-owned verifier, the registry selects the
AXI4-Lite CPU adapter from the admitted descriptor alone, and the real generated
``GeneratedAxiLiteMemorySession`` carries the bound adapter.

What the last test pins is the honest limit: the F2/F4 *executor* needs a native
CPU-protocol beat/first-fetch observation that this pinned AXI4-Lite CPU harness
does not export, so the plan compiler refuses with the existing typed refusal
instead of a synthesised support row.
"""
from __future__ import annotations

import ast
import json
from dataclasses import replace
from pathlib import Path

import pytest

from myfuzz.runtime.admission import verify_component
from myfuzz.runtime.compiler import _EXPECTATION_BY_ROLE, plan_bindings
from myfuzz.runtime.contracts import CapabilityRequirement, GenericRuntimeRefused
from myfuzz.runtime.generic_campaign import load_descriptor
from myfuzz.runtime.preparation import create_preparation
from myfuzz.runtime.registry import CPU_ADAPTER_ID as OBI_CPU_ADAPTER_ID, registrations, select_adapter

ROOT = Path(__file__).resolve().parents[2]
DESCRIPTOR = ROOT / "configs/scenarios/compiled-f2-f4-axil-apb-i2c-picorv32/generic_scenario.json"
CPU_ADAPTER_ID = "axi4-lite.cpu.v1"
ADAPTER_MODULE = ROOT / "src/myfuzz/runtime/adapters/axi4lite_cpu.py"

_CPU_OBLIGATIONS = ("cross_component_consumption", "cross_component_source",
                    "physical_protocol_sample")


def _cpu_requirement(component) -> CapabilityRequirement:
    row = next(row for row in component.endpoints() if row["role"] == "cpu")
    return CapabilityRequirement(
        role="cpu", endpoint_id=row["endpoint_id"],
        protocol=tuple(row["protocol"]), template=tuple(row["template"]),
        semantic_kind=row["semantic_kind"], operations=tuple(row["operations"]),
        data_width=row["data_width"], address_width=row["address_width"],
        max_outstanding=row["max_outstanding"],
        completion_kind=row["completion_kind"],
        byte_enable_required=row["byte_enable"],
        address_units=row["address_units"], evidence_obligations=_CPU_OBLIGATIONS)


@pytest.fixture(scope="module")
def prepared(tmp_path_factory):
    """One real D2 generation and D3 compilation of the config-only descriptor."""
    directory = tmp_path_factory.mktemp("axil-generic")
    descriptor = load_descriptor(DESCRIPTOR, base_dir=ROOT)
    context = create_preparation(
        base_dir=ROOT, compose_path=descriptor.compose,
        capability_paths=(descriptor.capability,),
        supplement_path=descriptor.supplement,
        generated_dir=directory / "generated", flow_ids=descriptor.flow_ids)
    try:
        components = tuple(verify_component(context.artifact(instance_id),
                                           preparation=context, base_dir=ROOT)
                           for instance_id in sorted(context.artifacts))
        yield descriptor, context, {component.instance_id: component
                                    for component in components}
    finally:
        context.close()


def _cpu_component(components):
    for component in components.values():
        if any(row["role"] == "cpu" for row in component.endpoints()):
            return component
    raise AssertionError("no admitted cpu component")


def _cpu_selection(prepared):
    _, context, components = prepared
    component = _cpu_component(components)
    return component, select_adapter(component, _cpu_requirement(component),
                                     preparation=context)


def _artifact():
    from myfuzz.scenario.axil_uart_cpu_example import _cpu_artifact
    return _cpu_artifact()


@pytest.fixture(scope="module")
def artifact():
    return _artifact()


# ---------------------------------------------------------------------------
# Config-only preparation and typed admission
# ---------------------------------------------------------------------------

def test_config_only_descriptor_loads_the_shared_mmio_executor():
    descriptor = load_descriptor(DESCRIPTOR, base_dir=ROOT)
    assert descriptor.flow_ids == ("F2", "F4")
    # Protocol-neutral shared executor ids: no CPUxIP executor is introduced.
    assert descriptor.executors == {"F2": "compiled_mmio", "F4": "compiled_mmio"}
    assert descriptor.compose.name == "compose.json"


def test_create_preparation_produces_executable_f2_f4_paths(prepared):
    descriptor, context, _components = prepared
    document = context.d3_document()
    status = {row["flow_id"]: row["status"] for row in document["paths"]}
    assert status["F2"] == "executable" and status["F4"] == "executable"
    assert status["F1"] == "executable" and status["F3"] == "executable"
    # The D3 derivation itself records F5/F6 as unsupported for this CPU: no
    # interrupt consumer and no DMA provider exists in the pinned profile.
    assert status["F5"] == "unsupported" and status["F6"] == "unsupported"
    cpu = [row for row in document["paths"] if row["flow_id"] == "F4"][0]
    assert cpu["path_id"].endswith(":ram.image") or "ram" in cpu["path_id"]
    assert set(context.artifacts) == {"cpu", "peripheral"}
    assert context.artifacts["cpu"].runtime_document["kind"] == "axi4_lite_cpu"
    assert (context.artifacts["peripheral"].runtime_document["kind"]
            == "apb3_register_observe")
    assert descriptor.scenario_id == "axil-apb-i2c-picorv32-mmio"


def test_typed_admission_certifies_the_axi4lite_cpu_endpoint(prepared):
    _descriptor, _context, components = prepared
    component = _cpu_component(components)
    document = component.document()
    assert document["source_verifier"]["id"] == "axi4-lite.cpu.admission.v1"
    endpoint, = document["endpoints"]
    assert endpoint["role"] == "cpu"
    assert endpoint["endpoint_id"] == "processor.memory"
    assert endpoint["protocol"] == ["axi4-lite", "1"]
    assert endpoint["template"] == ["cpu.axi4-lite", "1", "no-response-code"]
    assert endpoint["semantic_kind"] == "cpu.axi4-lite.v1"
    assert endpoint["completion_kind"] == "independent_channels_response"
    assert endpoint["address_units"] == "byte"
    assert (endpoint["data_width"], endpoint["address_width"]) == (32, 32)
    assert endpoint["byte_enable"] is True
    assert endpoint["operations"] == ["read", "write"]


def test_registry_selects_the_axi4lite_adapter_from_the_descriptor(prepared):
    component, selection = _cpu_selection(prepared)
    assert selection.adapter_id == CPU_ADAPTER_ID
    assert selection.adapter_version == "1"
    assert selection.component_artifact_sha256 == component.artifact_sha256
    row, = [row for row in registrations() if row.adapter_id == CPU_ADAPTER_ID]
    assert selection.implementation_sha256 == row.implementation_sha256()
    assert row.protocol == ("axi4-lite", "1")
    assert row.templates == (("cpu.axi4-lite", "1", "no-response-code"),)
    assert row.completion_kinds == ("independent_channels_response",)
    assert row.address_widths == (32,) and row.data_widths == (32,)
    assert set(row.evidence_capabilities) == set(_CPU_OBLIGATIONS)


def test_generic_plan_compile_admits_the_axil_cpu_mmio_rows(prepared):
    """The witness reader is admitted: F2/F4 compile against the sampled pins.

    Before the reader existed the same row refused
    ``MMIO-CPU-adapter-unsupported:axi4-lite:witness_reader_not_admitted``.  The
    support row is now backed by the reviewed
    ``collect_axi4lite_cpu_beats``/``collect_axi4lite_cpu_fetches`` projections
    over the real per-tick ``base_protocol_traces`` taps, and the plan compiles
    with the protocol-neutral ``compiled_mmio`` executor.
    """
    _descriptor, context, _components = prepared
    for flow in ("F2", "F4"):
        support = context.flow_support(flow)
        assert support["execution_supported"] == 1
        assert support["status"] == "supported"
        assert support["executor"] == "compiled_mmio"
        assert support["support_scope"] == (
            "native_CPU_MMIO_transport_no_internal_storage_version")
    plan = plan_bindings(context)
    assert {row.protocol for row in plan} == {("axi4-lite", "1"), ("apb", "3")}
    cpu, = [row for row in plan if row.role == "cpu"]
    assert cpu.endpoint_id == "processor.memory"
    assert cpu.semantic_kind == "cpu.axi4-lite.v1"
    assert set(cpu.flows) == {"F2", "F4"}


# ---------------------------------------------------------------------------
# AXI4-Lite protocol observation gate: named refusals, never a witness
# ---------------------------------------------------------------------------

def _documented_trace(document):
    """The exact trace the reviewed renderer patch emits, derived from real ABI.

    Taps are the sideband copies of the admitted ``functional`` ABI spans, so the
    fixture is built from the artifact's own ``structural_abi`` rather than
    transcribed from the patch file.
    """
    from myfuzz.integration.axil_cpu_protocol_observations import (
        FETCH_BASIS, SHAPE, TRACE_SCHEMA)
    endpoint_id = "processor.memory"
    owners = {row["role"]: row for row in document["structural_abi"]["ports"]
              if row.get("endpoint_id") == endpoint_id and row.get("role")}
    assert set(owners) == set(SHAPE)
    signals, widths, taps = {}, {}, []
    for role, (_, width) in sorted(SHAPE.items()):
        name = "cpu_axil_trace_" + role
        signals[role], widths[role] = name, width
        taps.append({"name": name, "direction": "output", "width": width,
                     "role": role, "endpoint_id": endpoint_id,
                     "source_wire": "link_" + owners[role]["wrapper_name"]})
    trace = {
        "schema_version": TRACE_SCHEMA,
        "protocol": "axi4-lite",
        "endpoint_id": endpoint_id,
        "clock_domain": document["clock_schedule"]["primary_clock_domain"],
        "signals": signals,
        "signal_widths": widths,
        "sample_group": "protocol_taps",
        "boundary": "cpu_physical_abi",
        "fetch_observation": {"role": "arprot", "bit": 2,
                              "asserted": "instruction_fetch",
                              "qualified_by": ["arvalid", "arready"],
                              "basis": FETCH_BASIS},
    }
    group = {"schema_version": "ip_protocol_trace_set.v1", "sampling": "pre_post",
             "sample_group": "protocol_taps", "traces": [trace]}
    return group, taps


def _observable(document, *, group=None, taps=None):
    document = json.loads(json.dumps(document))
    if group is None and taps is None:
        group, taps = _documented_trace(document)
    document["base_protocol_traces"] = group
    document["protocol_tap_ports"] = taps
    return document


def test_real_artifact_carries_the_observed_cpu_protocol_trace(artifact):
    """The applied renderer change exports real per-tick AXI4-Lite master pins."""
    from myfuzz.integration.axil_cpu_protocol_observations import (
        axi4lite_cpu_protocol_observations)
    document = artifact.runtime_document
    group = document["base_protocol_traces"]
    assert group["sampling"] == "pre_post" and group["sample_group"] == "protocol_taps"
    trace, = group["traces"]
    assert trace["protocol"] == "axi4-lite"
    assert trace["boundary"] == "cpu_physical_abi"
    assert len(trace["signals"]) == 17
    assert trace["fetch_observation"]["role"] == "arprot"
    assert trace["fetch_observation"]["bit"] == 2
    taps = document["protocol_tap_ports"]
    assert len(taps) == 17
    # Every tap is a passive copy of an admitted `functional` ABI span; the DUT
    # pin itself is never re-dispositioned.
    abi = {row["role"]: row for row in document["structural_abi"]["ports"]
           if row.get("endpoint_id") == "processor.memory" and row.get("role")}
    assert set(abi) == set(trace["signals"])
    assert {row["disposition"] for row in abi.values()} == {"functional"}
    for tap in taps:
        assert tap["source_wire"] == "link_" + abi[tap["role"]]["wrapper_name"]
    observations = axi4lite_cpu_protocol_observations(
        document, endpoint_id="processor.memory")
    assert len(observations["roles"]) == 17
    assert observations["fetch_observation"]["asserted"] == "instruction_fetch"


def test_artifact_without_the_trace_refuses_by_name(artifact):
    """No trace means no observation: refused, never assumed from ARPROT."""
    from myfuzz.integration.axil_cpu_protocol_observations import (
        AxilProtocolObservationRefused, axi4lite_cpu_protocol_observations)
    document = json.loads(json.dumps(artifact.runtime_document))
    assert document.pop("base_protocol_traces")
    assert document.pop("protocol_tap_ports")
    with pytest.raises(AxilProtocolObservationRefused) as refusal:
        axi4lite_cpu_protocol_observations(document,
                                          endpoint_id="processor.memory")
    assert refusal.value.reason == "no_cpu_protocol_trace"
    assert refusal.value.detail["artifact_kind"] == "axi4_lite_cpu"
    assert str(refusal.value).startswith(
        "MMIO-CPU-adapter-unsupported:axi4-lite:no_cpu_protocol_trace")


def test_documented_observation_shape_is_admitted_with_its_readers(artifact):
    """The authenticated contract now yields the adapter, not a refusal."""
    from myfuzz.integration.axil_cpu_protocol_observations import (
        axi4lite_cpu_protocol_observations, select_axi4lite_cpu_protocol)
    from myfuzz.integration.mmio_cpu_adapter import MmioCpuAdapter
    from myfuzz.local_harness.axi_lite_session import GeneratedAxiLiteMemorySession
    document = _observable(artifact.runtime_document)
    observations = axi4lite_cpu_protocol_observations(
        document, endpoint_id="processor.memory")
    assert len(observations["roles"]) == 17
    assert observations["fetch_observation"]["role"] == "arprot"
    assert observations["fetch_observation"]["bit"] == 2
    assert observations["authority"] == (
        "sampled_pin_reader_no_retirement_no_irq_no_storage_version")
    stream = {"register_access": {"source_endpoint": "processor.memory"}}
    artifact_like = type("ArtifactLike", (), {"runtime_document": document})()
    adapter = select_axi4lite_cpu_protocol(artifact_like, {"endpoint_id": "x"}, stream)
    assert type(adapter) is MmioCpuAdapter
    assert adapter.protocol == "axi4-lite"
    assert adapter.session_type is GeneratedAxiLiteMemorySession
    assert adapter.channel_model == "unified"
    assert adapter.instruction_granule == 4
    assert adapter.policy["native_error_observation"] is False
    assert adapter.traces["observation"] == observations
    assert adapter.traces["read_transfer"] == observations["read_transfer"]


def test_default_endpoint_is_the_single_declared_trace(artifact):
    from myfuzz.integration.axil_cpu_protocol_observations import (
        AxilProtocolObservationRefused, axi4lite_cpu_protocol_observations)
    document = _observable(artifact.runtime_document)
    assert (axi4lite_cpu_protocol_observations(document)["endpoint_id"]
            == "processor.memory")
    group = json.loads(json.dumps(document["base_protocol_traces"]))
    group["traces"].append(dict(group["traces"][0], endpoint_id="processor.other"))
    document["base_protocol_traces"] = group
    with pytest.raises(AxilProtocolObservationRefused) as refusal:
        axi4lite_cpu_protocol_observations(document)
    assert refusal.value.reason == "trace_shape"
    assert refusal.value.detail["reason"] == "one-trace-per-endpoint"


@pytest.mark.parametrize("defect", ["group-fields", "protocol", "boundary",
                                    "row-fields", "missing-role", "width",
                                    "tap-missing", "tap-wire", "tap-direction"])
def test_wrong_trace_shape_is_refused_by_name(artifact, defect):
    from myfuzz.integration.axil_cpu_protocol_observations import (
        AxilProtocolObservationRefused, axi4lite_cpu_protocol_observations)
    group, taps = _documented_trace(json.loads(json.dumps(artifact.runtime_document)))
    trace = group["traces"][0]
    expected = "trace_group_shape" if defect == "group-fields" else "trace_shape"
    if defect == "group-fields":
        group.pop("sampling")
    elif defect == "protocol":
        trace["protocol"] = "axi4"
    elif defect == "boundary":
        trace["boundary"] = "cpu_functional"
    elif defect == "row-fields":
        trace["max_outstanding"] = 1
    elif defect == "missing-role":
        trace["signals"].pop("arprot")
        trace["signal_widths"].pop("arprot")
    elif defect == "width":
        trace["signal_widths"]["rdata"] = 16
    elif defect == "tap-missing":
        taps.pop(0)
    elif defect == "tap-wire":
        taps[3]["source_wire"] = "link_forged"
    elif defect == "tap-direction":
        taps[2]["direction"] = "input"
    document = _observable(artifact.runtime_document, group=group, taps=taps)
    with pytest.raises(AxilProtocolObservationRefused) as refusal:
        axi4lite_cpu_protocol_observations(document,
                                          endpoint_id="processor.memory")
    assert refusal.value.reason == expected
    assert str(refusal.value).startswith("MMIO-CPU-adapter-unsupported:axi4-lite:")


@pytest.mark.parametrize("defect", ["absent", "bit", "qualified", "role"])
def test_fetch_flag_must_be_declared_by_the_observation(artifact, defect):
    from myfuzz.integration.axil_cpu_protocol_observations import (
        AxilProtocolObservationRefused, axi4lite_cpu_protocol_observations)
    group, taps = _documented_trace(json.loads(json.dumps(artifact.runtime_document)))
    declaration = group["traces"][0]["fetch_observation"]
    if defect == "absent":
        group["traces"][0].pop("fetch_observation")
    elif defect == "bit":
        declaration["bit"] = 0
    elif defect == "qualified":
        declaration["qualified_by"] = ["arvalid"]
    elif defect == "role":
        declaration["role"] = "awprot"
    document = _observable(artifact.runtime_document, group=group, taps=taps)
    with pytest.raises(AxilProtocolObservationRefused) as refusal:
        axi4lite_cpu_protocol_observations(document,
                                          endpoint_id="processor.memory")
    assert refusal.value.reason == "no_fetch_observation"


def test_mmio_cpu_selection_returns_the_real_axil_row(prepared):
    """``select_mmio_cpu`` selects by protocol and carries the real readers."""
    from myfuzz.integration.mmio_cpu_adapter import (
        MmioCpuAdapter, native_cpu_protocol, select_mmio_cpu)
    from myfuzz.local_harness.axi_lite_session import GeneratedAxiLiteMemorySession
    _descriptor, context, _components = prepared
    artifact = context.artifact("cpu")
    assert artifact.runtime_document["base_protocol_traces"]["traces"]
    document = context.d3_document()
    path = next(row for row in document["paths"] if row["flow_id"] == "F2")
    image = next(source for source in path["sources"]
                 if source["kind"] == "instruction_image")
    stream = next(source for source in path["sources"]
                  if source["kind"] == "cpu_load_stream")
    adapter = select_mmio_cpu(artifact, image, stream)
    assert type(adapter) is MmioCpuAdapter
    assert adapter.protocol == "axi4-lite"
    assert adapter.session_type is GeneratedAxiLiteMemorySession
    assert adapter.channel_model == "unified"
    assert adapter.traces["endpoint_id"] == "processor.memory"
    assert adapter.traces["fetch_observation"]["qualified_by"] == ["arvalid",
                                                                  "arready"]
    assert adapter.traces["read_transfer"]["granularity"] == "whole_addressed_word"
    assert native_cpu_protocol(artifact.runtime_document) == "axi4-lite"


def test_artifact_without_a_trace_still_refuses_before_any_session(prepared):
    """No trace means no reader: the refusal is still the named one."""
    from myfuzz.integration.axil_cpu_protocol_observations import (
        AxilProtocolObservationRefused)
    from myfuzz.integration.mmio_cpu_adapter import select_mmio_cpu
    _descriptor, context, _components = prepared
    artifact = context.artifact("cpu")
    document = json.loads(json.dumps(artifact.runtime_document))
    document.pop("base_protocol_traces")
    document.pop("protocol_tap_ports")
    stripped = replace(artifact, runtime_document=document)
    path = next(row for row in context.d3_document()["paths"]
                if row["flow_id"] == "F2")
    image = next(source for source in path["sources"]
                 if source["kind"] == "instruction_image")
    stream = next(source for source in path["sources"]
                  if source["kind"] == "cpu_load_stream")
    with pytest.raises(AxilProtocolObservationRefused) as refusal:
        select_mmio_cpu(stripped, image, stream)
    assert refusal.value.reason == "no_cpu_protocol_trace"
    assert str(refusal.value).startswith(
        "MMIO-CPU-adapter-unsupported:axi4-lite:")


# ---------------------------------------------------------------------------
# No CPUxIP executor / special case
# ---------------------------------------------------------------------------

def test_adapter_module_names_no_target_and_no_executor():
    source = ADAPTER_MODULE.read_text()
    lowered = source.lower()
    # No target/IP name and no executor id may appear: the adapter is selected by
    # protocol facts only, so it cannot carry a CPUxIP special case.
    for forbidden in ("apb", "i2c", "pulp", "uart", "gpio", "spi", "zipcpu",
                      "axiluart", "compiled_"):
        assert forbidden not in lowered, forbidden
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.add(("." * node.level) + (node.module or ""))
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    assert imported <= {"copy", "dataclasses", "hashlib", "pathlib",
                        "myfuzz.local_harness.axi_lite_session", "..contracts",
                        "..registry"}, sorted(imported)


def test_registration_and_kernel_row_are_protocol_keyed_not_ip_keyed():
    row, = [row for row in registrations() if row.adapter_id == CPU_ADAPTER_ID]
    assert not [name for name in row.implementation_files if "/integration/" in name]
    assert all(key[0] in ("cpu", "target") and isinstance(key[1], tuple)
               for key in _EXPECTATION_BY_ROLE)
    expectation = _EXPECTATION_BY_ROLE[("cpu", ("axi4-lite", "1"))]
    assert expectation.adapter_id == CPU_ADAPTER_ID
    assert expectation.semantic_kind == "cpu.axi4-lite.v1"
    assert expectation.completion_kind == "independent_channels_response"
    assert expectation.evidence_obligations == _CPU_OBLIGATIONS
    # The other three CPU protocols keep their own rows: adding AXI4-Lite did
    # not replace or widen an existing CPU expectation.
    assert _EXPECTATION_BY_ROLE[("cpu", ("obi", "1"))].adapter_id == OBI_CPU_ADAPTER_ID
    assert {_EXPECTATION_BY_ROLE[("cpu", protocol)].adapter_id for protocol in
            (("obi", "1"), ("wishbone", "classic"), ("ahb-lite", "1"),
             ("axi4-lite", "1"))} == {"obi.cpu.v1", "wishbone.cpu.v1",
                                      "ahb-lite.cpu.v1", CPU_ADAPTER_ID}
    from myfuzz.runtime.binding import _FACTORIES
    assert set(_FACTORIES) >= {CPU_ADAPTER_ID, OBI_CPU_ADAPTER_ID}
    assert _FACTORIES[CPU_ADAPTER_ID].__name__ == "_bind_axi4lite_cpu_adapter"


# ---------------------------------------------------------------------------
# Certified AXI4-Lite surface: what it claims and what it refuses
# ---------------------------------------------------------------------------

def test_surface_states_only_observed_capabilities(artifact):
    from myfuzz.runtime.adapters.axi4lite_cpu import axi4lite_cpu_surface_document
    surface = axi4lite_cpu_surface_document(artifact)
    assert surface["kind"] == "cpu.axi4-lite.v1"
    assert surface["endpoint_id"] == "processor.memory"
    assert surface["function"] == "memory_master"
    assert surface["completion_kind"] == "independent_channels_response"
    assert (surface["address_width"], surface["data_width"]) == (32, 32)
    assert surface["byte_enable_width"] == 4
    assert surface["max_outstanding"] == 1
    assert surface["write_channels"] == ["aw", "w", "b"]
    assert surface["read_channels"] == ["ar", "r"]
    assert surface["signals"]["arprot"] == "mem_axi_arprot"
    # Honest limits, stated in the certified surface itself.
    assert surface["instruction_identity"] == "unsupported"
    assert surface["instruction_retirement"] == "unknown"
    assert surface["native_IRQ"] == "unsupported"
    assert surface["first_fetch_observation"] == "unavailable_through_bound_session"
    assert surface["error_observed"] is False
    limits = surface["capability_limits"]
    # The fetch identity is *sampled* from the declared ARPROT tap; there is
    # still no physical instruction-identity export and nothing claims one.
    assert limits["instruction_identity"].startswith("sampled")
    assert limits["instruction_slots"].startswith("supported")
    assert limits["deferred_mmio"].startswith("supported")
    assert limits["byte_enable"].startswith("write_only:four_lane_wstrb_reads_present_zero")
    assert limits["native_IRQ"].startswith("unsupported")
    assert limits["error_response"].startswith("unsupported")
    assert limits["F6"].startswith("unsupported")
    assert limits["mmio_beats"].startswith("supported")
    assert limits["ram_read_write"].startswith("supported")
    assert json.dumps(surface)  # canonical-JSON clean


@pytest.mark.parametrize("change", ["kind", "protocol", "data-width", "address-width",
                                    "boot-base", "absent-role", "template", "role-width"])
def test_surface_refuses_a_changed_axi4lite_abi(artifact, change):
    from myfuzz.runtime.adapters.axi4lite_cpu import axi4lite_cpu_surface_document
    document = json.loads(json.dumps(artifact.runtime_document))
    plan = artifact.plan
    binding = plan.binding
    endpoints = binding.endpoints
    endpoint = endpoints[0]
    if change == "kind":
        document["kind"] = "ahb_lite_cpu"
    elif change == "protocol":
        endpoints = (replace(endpoint, protocol=("axi4", "1")),)
    elif change == "data-width":
        document["selected_template"]["executor"]["binding"][
            "declared_profile_facts"]["data_width"] = 64
    elif change == "address-width":
        plan = replace(plan, profile=replace(
            plan.profile, capabilities={**plan.profile.capabilities,
                                        "address_width": 34}))
    elif change == "boot-base":
        # Outside this CPU's own 32-bit address space: not a configured base.
        document["boot_contract"]["configured_boot_base"] = 1 << 32
    elif change == "absent-role":
        rows = document["selected_template"]["executor"]["binding"]["endpoints"][0]["roles"]
        rows.append({"role": "rresp", "physical_port": "mem_axi_rresp",
                     "member_path": [], "direction": "input", "width": 2,
                     "raw_lo": 0, "raw_hi": 1, "port_width": 2})
    elif change == "template":
        document["selected_template"]["contract"]["variant_id"] = "full-axi4"
    elif change == "role-width":
        for row in document["selected_template"]["executor"]["binding"]["endpoints"][0]["roles"]:
            if row["role"] == "rdata":
                row["width"] = 64
    mutated = replace(artifact, runtime_document=document,
                      plan=replace(plan, binding=replace(binding, endpoints=endpoints)))
    with pytest.raises(ValueError):
        axi4lite_cpu_surface_document(mutated)


# ---------------------------------------------------------------------------
# Session binding: the existing generated AXI4-Lite memory session carries it
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def bound(prepared):
    """Bind the adapter to the real generated session class (no RTL process)."""
    from myfuzz.local_harness.axi_lite_session import GeneratedAxiLiteMemorySession
    from myfuzz.runtime.adapters.axi4lite_cpu import bind_axi4lite_cpu_adapter
    from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
    _descriptor, context, _components = prepared
    component, selection = _cpu_selection(prepared)
    cpu_artifact = context.artifact(component.instance_id)
    memory = PersistentMemory(regions=(MemoryRegion("ram", 0, 0x10000),),
                              initialization_seed=0,
                              max_initialized_bytes=0x10000)
    session = GeneratedAxiLiteMemorySession(
        cpu_artifact, base_dir=ROOT, cache_dir=Path("/nonexistent-axil-cache"),
        memory=memory)
    bound = bind_axi4lite_cpu_adapter(component=component, session=session,
                                      selection=selection, preparation=context,
                                      endpoint_id="processor.memory")
    yield bound, session, selection, component
    bound.close()


def test_binding_uses_the_existing_session_and_never_drives_the_cpu(bound):
    adapter, session, _selection, component = bound
    from myfuzz.local_harness.axi_lite_session import GeneratedAxiLiteMemorySession
    assert type(session) is GeneratedAxiLiteMemorySession
    assert adapter.adapter_id == CPU_ADAPTER_ID
    assert adapter.adapter_version == "1"
    assert adapter.protocol == ("axi4-lite", "1")
    assert adapter.template == ("cpu.axi4-lite", "1", "no-response-code")
    assert adapter.semantic_kind == "cpu.axi4-lite.v1"
    assert adapter.endpoint_id == "processor.memory"
    assert adapter.component_instance_id == component.instance_id
    assert adapter.drives_cpu is False
    assert adapter.implementation_sha256 == next(
        row for row in registrations() if row.adapter_id == CPU_ADAPTER_ID
    ).implementation_sha256()
    assert len(adapter.binding_sha256) == 64
    # The session is not started by the adapter: no local tick was consumed.
    assert session.local_ticks == 0
    adapter.assert_current()


def test_program_slots_and_step_map_describe_the_real_boundary(bound):
    adapter, _session, _selection, _component = bound
    slots = adapter.program_slots
    boot = slots["instruction.boot"]
    assert boot["boot_base"] == 0
    assert boot["endpoints"] == ["processor.memory"]
    assert boot["instruction_identity"] == "unsupported"
    assert boot["first_fetch_observation"] == "unavailable_through_bound_session"
    assert (boot["address_width"], boot["instr_width"]) == (32, 32)
    assert boot["source"] == "artifact_boot_contract_no_online_instruction_slot"
    step = adapter.local_step_map
    assert step["schema_version"] == "axi4lite_cpu_local_step_map.v1"
    assert step["completion_kind"] == "independent_channels_response"
    assert step["mmio_service"] == "queued_routed_target_response"
    assert step["defer_mmio"] is True
    assert step["read_byte_enable"] == "zero"
    assert step["error_observation"] == "not_exposed_to_cpu_boundary"
    assert step["address_units"] == "byte"


@pytest.mark.parametrize("case", ["session-class", "component-type", "selection-pin",
                                  "declared-endpoint", "artifact-kind"])
def test_binding_refusals_are_typed(bound, prepared, artifact, case, monkeypatch):
    from myfuzz.runtime.adapters import axi4lite_cpu
    _adapter, session, selection, component = bound
    _descriptor, context, _components = prepared
    with pytest.raises(GenericRuntimeRefused) as refusal:
        if case == "session-class":
            axi4lite_cpu.bind_axi4lite_cpu_adapter(
                component=component, session=object(), selection=selection)
        elif case == "component-type":
            axi4lite_cpu.bind_axi4lite_cpu_adapter(
                component=object(), session=session, selection=selection)
        elif case == "selection-pin":
            axi4lite_cpu.bind_axi4lite_cpu_adapter(
                component=component, session=session,
                selection=replace(selection, implementation_sha256="0" * 64))
        elif case == "declared-endpoint":
            axi4lite_cpu.bind_axi4lite_cpu_adapter(
                component=component, session=session, selection=selection,
                endpoint_id="processor.data")
        else:
            monkeypatch.setattr(session, "artifact", replace(
                artifact, runtime_document=dict(artifact.runtime_document,
                                                kind="obi_cpu")))
            axi4lite_cpu.bind_axi4lite_cpu_adapter(
                component=component, session=session, selection=selection)
    assert refusal.value.code == "generic-binding-drift"
    assert refusal.value.pointer.startswith("/axi4lite_cpu")
    assert refusal.value.detail["reason"]


def test_drifted_registry_implementation_is_refused(bound, monkeypatch):
    from myfuzz.runtime.adapters import axi4lite_cpu
    adapter, _session, selection, component = bound
    original = axi4lite_cpu._MODULE_DIGESTS
    monkeypatch.setattr(axi4lite_cpu, "_MODULE_DIGESTS",
                        {**original,
                         "src/myfuzz/runtime/adapters/axi4lite_cpu.py": "0" * 64})
    with pytest.raises(GenericRuntimeRefused) as refusal:
        adapter.assert_current()
    assert refusal.value.code == "generic-binding-drift"
    assert refusal.value.detail["reason"] == "module-source"
    monkeypatch.setattr(axi4lite_cpu, "_MODULE_DIGESTS", original)
    adapter.assert_current()
