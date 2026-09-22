"""Compose a validated SoC plan from user profiles and a composition request.

The flow is the one the assurance plan freezes for the generation phase:

1. elaborate every component's pinned source closure and bind the profile to
   real ports (``component_profile``);
2. classify every port and bit segment (``soc_port_dispositions``);
3. resolve the processor-side adapter chain and the per-target adapters from
   declared protocol capabilities (``processor_adapters`` / ``target_adapters``);
4. allocate non-overlapping address windows, keeping every user-fixed address;
5. assign interrupt sources and instantiate the verified controller
   (``soc_interrupt_plan``);
6. build the shared ``soc_spec.v1`` -> ``build_soc_plan`` -> ``soc_plan.v1``
   structure so the fabric, address map, reset distribution and stimulus modes
   come from the existing validated plan layer;
7. export special inputs and external pins as stable top-level ports with a
   raw-input layout.

Nothing here is selected by component name, model or path: every decision comes
from the profile's declared interfaces, the protocol/capability tables and the
elaborated RTL facts.  A missing capability is reported with the instance,
endpoint and field it concerns.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from myfuzz.contracts import canonical_bytes

from .component_profile import (
    AddressPolicy,
    ComponentInstance,
    ComponentProfile,
    ComponentProfileError,
    CompositionRequest,
    ProfileBinding,
    bind_profile,
    elaborate_profile,
    elaborate_rtl_module,
)
from .endpoint_capabilities import EndpointFieldFact, SourceReference
from .input_constraints import DRIVE_PROFILES
from .input_layout import build_input_layout, input_layout_document
from .processor_adapters import ProcessorAdapterError, resolve_processor_adapter
from .processor_boundary import ProcessorMemoryBinding
from .soc_contracts import SocContractError, soc_spec_hash
from .soc_peer_plan import (
    PEER_ENDPOINT_FUNCTION,
    PeerPlan,
    PeerPlanError,
    export_reason,
    match_models,
    plan_peer,
)
from .soc_stimulus import DRIVER_MODULE, DRIVER_SOURCE, compile_soc_stimulus
from .soc_interrupt_plan import (
    InterruptPlan,
    InterruptPlanError,
    InterruptSourceRequest,
    build_interrupt_plan,
    interrupt_plan_document,
)
from .soc_plan import build_soc_plan
from .soc_port_dispositions import (
    DispositionEntry,
    PortDispositionError,
    aligned_segments,
    build_port_dispositions,
    dispositions_document,
    fuzz_ports,
    port_is_aggregated,
    port_segments,
    segment_expression,
)
from .soc_scope import (
    bound_scope_refusals,
    cpu_input_records,
    declared_scope_refusals,
    soc_adapter_scope,
)
from .target_adapters import resolve_target_adapter

COMPOSITION_SCHEMA = "soc_composition.v1"
PROCESSOR_ADAPTERS_DIR = "src/myfuzz/protocols/rtl"
MEMORY_MODEL_32 = "riscv_boot_memory_32"
MEMORY_MODEL_64 = "riscv_boot_memory_64"
MEMORY_MODEL_SOURCE = "src/myfuzz/integration/rtl/riscv_boot_memory.sv"

#: Endpoint functions that make a CPU endpoint a bus master, and the master
#: kind the fabric plan understands for each.
MASTER_KINDS: dict[str, str] = {
    "memory_master": "cpu_unified",
    "processor_memory_master": "cpu_unified",
    "instruction_memory_master": "cpu_instruction",
    "data_memory_master": "cpu_data",
}

#: The bus owners declared by ``input_constraints.DRIVE_PROFILES`` that need a
#: generated synthetic master.  ``cpu`` means "no synthetic master"; anything
#: else names an owner the plan must instantiate.
CPU_BUS_OWNER = "cpu"

#: The declared drive profile a composition defaults to.  The profile record
#: itself stays in ``input_constraints.DRIVE_PROFILES``; this module only turns
#: it into structure.
DEFAULT_DRIVE_PROFILE = "cpu_execute"

#: The address strategy the composition's stimulus document is compiled with.
#: ``bias_off`` keeps the raw offer address as the plan address, so the address
#: map stays the evidence for where a transaction lands.
STIMULUS_ADDRESS_STRATEGY = "bias_off"

#: Structural names of the synthetic master's spec component, fabric source and
#: instance.  They are stable so a failure can be traced, and they carry no
#: behaviour: the module, its source and every parameter come from the compiled
#: ``soc_stimulus.v1`` document (``rtl_projection``), and the ports come from
#: elaborating that module with exactly those parameters.
SYNTHETIC_SOURCE_ID = "fuzz_mmio0"
SYNTHETIC_INSTANCE_ID = "fuzz_mmio0"
SYNTHETIC_COMPONENT_ID = "fuzz_mmio0"
SYNTHETIC_MASTER_PORT = "mmio"
SYNTHETIC_MASTER_KIND = "fuzz_mmio"
SYNTHETIC_MASTER_PROTOCOL = ("processor-memory-beat", "1")
#: ``soc_spec.v1`` has no separate "system" kind: a generator-owned module that
#: is neither a user component nor memory is declared ``clock_reset``, exactly
#: like the generated interrupt controller.
SYNTHETIC_COMPONENT_KIND = "clock_reset"
#: Clock and reset ports of the generated driver, declared once here so the
#: renderer and the audit apply the same contract instead of guessing from the
#: module name.  ``reset`` is synchronous active high in the driver's own header.
SYNTHETIC_CLOCK_PORT = "clk"
SYNTHETIC_RESET_CONTRACT: Mapping[str, str] = {"port": "reset", "polarity": "active_high"}

#: The stimulus modes a CPU master and a synthetic master may participate in.
#: ``soc_contracts.KIND_MODES`` is the authority; these sets are the two halves
#: used to distribute the request's modes between the two master kinds.
CPU_MASTER_MODE_SET = ("cpu_only", "mixed")
SYNTHETIC_MASTER_MODE_SET = ("mmio_only", "mixed")


class CompositionError(ValueError):
    """The request cannot be composed under the declared and verified capabilities."""


def _error(reason: str) -> None:
    raise CompositionError(reason)


def _raise_scope_refusals(refusals: Sequence[str]) -> None:
    """Raise the first out-of-scope combination ``soc_scope`` refused.

    ``soc_scope`` owns both the scope record and the reason builders, so the
    string raised here is the one the published record documents.
    """
    if refusals:
        _error(refusals[0])


def _positive(value: object, reason: str, *, minimum: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        _error(reason)
    return value


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


@dataclass(frozen=True, slots=True)
class InstanceComposition:
    instance_id: str
    component_id: str
    kind: str
    top_module: str
    profile: ComponentProfile
    binding: ProfileBinding
    dispositions: tuple[DispositionEntry, ...]
    parameters: Mapping[str, object] = field(default_factory=dict)
    window_base: int | None = None
    window_size: int | None = None
    #: One record per multi-role physical port (a struct/array port bound member
    #: by member, or a vector port sliced by bit range): the elaborated member
    #: layout, the disposition segments and the connection expression each
    #: segment must appear as in the generated top.  The structural audit
    #: re-reads the elaborated netlist against this record, and the record itself
    #: is derived from the profile binding and the disposition ledger rather than
    #: from the rendered text.
    port_bindings: tuple[Mapping[str, object], ...] = ()

    @property
    def clock_domain(self) -> str:
        return self.binding.clocks[0][0].domain

    @property
    def reset_domain(self) -> str:
        return self.binding.resets[0][0].domain

    def disposition(self, port: str) -> DispositionEntry | None:
        for entry in self.dispositions:
            if entry.port == port and entry.bit_lo == 0:
                return entry
        return None


@dataclass(frozen=True, slots=True)
class CompositionPlan:
    request_id: str
    request: CompositionRequest
    instances: tuple[InstanceComposition, ...]
    spec: Mapping[str, object]
    plan: Mapping[str, object]
    interrupt_plan: InterruptPlan
    interrupt_document: Mapping[str, object]
    processor_execution: Mapping[str, object]
    cpu_adapter: Mapping[str, object]
    target_records: tuple[Mapping[str, object], ...]
    raw_layout: Mapping[str, object]
    gaps: tuple[str, ...]
    plan_hash: str
    #: The declared drive profile this composition was built for, the profile
    #: record itself (``input_constraints.DRIVE_PROFILES``), the compiled
    #: ``soc_stimulus.v1`` document and the resolved synthetic-master record.
    #: ``synthetic`` is empty for a composition whose bus owner is the CPU.
    drive_profile: str = DEFAULT_DRIVE_PROFILE
    drive: Mapping[str, object] = field(default_factory=dict)
    stimulus: Mapping[str, object] = field(default_factory=dict)
    synthetic: Mapping[str, object] = field(default_factory=dict)
    #: One record per CPU input port (``soc_scope.cpu_input_records``): the
    #: declared disposition, the value or drive strategy and the net the
    #: generated top must drive it with.  The structural audit re-reads the
    #: elaborated netlist against this record.
    cpu_inputs: tuple[Mapping[str, object], ...] = ()
    #: The peer models bound to declared external interfaces, in instance order.
    #: Empty means every external interface is exported to the top, which is what
    #: a request that attaches no peer always produced.
    peers: tuple[PeerPlan, ...] = ()

    def instance(self, instance_id: str) -> InstanceComposition:
        for item in self.instances:
            if item.instance_id == instance_id:
                return item
        raise CompositionError(f"unknown-instance:{instance_id}")

    def peer(self, instance_id: str) -> PeerPlan | None:
        for item in self.peers:
            if item.instance_id == instance_id:
                return item
        return None

    @property
    def cpu_held_in_reset(self) -> bool:
        return bool(self.drive.get("cpu_held_in_reset", False))


def _cached_facts(profile: ComponentProfile, *, base_dir: Path, mode: str,
                  cache: dict[str, ProfileBinding]) -> ProfileBinding:
    key = profile.component_id
    if key not in cache:
        facts = elaborate_profile(profile, base_dir=base_dir, mode=mode)  # type: ignore[arg-type]
        cache[key] = bind_profile(profile, facts)
    return cache[key]


def _drive_profile(name: object) -> tuple[str, Mapping[str, object]]:
    """Resolve one declared drive profile by name.

    ``input_constraints.DRIVE_PROFILES`` is the only declaration of who owns the
    bus and whether the CPU is held; an unknown name is refused instead of
    silently falling back to the CPU-owns-everything profile.
    """
    if not isinstance(name, str) or name not in DRIVE_PROFILES:
        _error(f"unknown-drive-profile:{name}")
    return name, DRIVE_PROFILES[name]


def _synthetic_master(*, profile_name: str, profile: Mapping[str, object],
                      request: CompositionRequest, fabric_address_width: int,
                      fabric_data_width: int) -> dict | None:
    """The spec record of the synthetic master the drive profile requires.

    Returns ``None`` for the CPU-owned profile, which adds no master and keeps
    the composition byte-for-byte the plan the CPU-only path always produced.
    """
    owner = str(profile.get("bus_owner", ""))
    if owner == CPU_BUS_OWNER:
        if bool(profile.get("cpu_held_in_reset")):
            _error(f"drive-profile-contradiction:{profile_name}:cpu-owner-held-in-reset")
        return None
    if owner not in ("bfm", "arbitrated"):
        _error(f"unsupported-bus-owner:{profile_name}:{owner}")
    modes = tuple(str(item) for item in profile.get("legacy_modes", ()))
    if len(modes) != 1:
        _error(f"drive-profile-without-single-mode:{profile_name}")
    mode = modes[0]
    requested = tuple(str(item) for item in request.test_modes)
    if mode not in requested:
        _error(f"drive-profile-mode-not-requested:{profile_name}:{mode}")
    # The plan's own mode record declares whether the CPU is held in reset for a
    # mode (soc_contracts: held == mode == mmio_only).  A profile that disagrees
    # with it is a contradiction between two declarations, not a preference.
    if bool(profile.get("cpu_held_in_reset")) != (mode == "mmio_only"):
        _error(f"drive-profile-reset-contradiction:{profile_name}:{mode}")
    test_modes = sorted(item for item in requested if item in SYNTHETIC_MASTER_MODE_SET)
    if mode not in test_modes:
        _error(f"drive-profile-mode-not-declared:{profile_name}:{mode}")
    return {
        "source_id": SYNTHETIC_SOURCE_ID,
        "instance_id": SYNTHETIC_INSTANCE_ID,
        "component_id": SYNTHETIC_COMPONENT_ID,
        "port": SYNTHETIC_MASTER_PORT,
        "kind": SYNTHETIC_MASTER_KIND,
        "protocol": list(SYNTHETIC_MASTER_PROTOCOL),
        "mode": mode,
        "test_modes": test_modes,
        "address_width": fabric_address_width,
        "data_width": fabric_data_width,
        # The generator-owned driver module the stimulus compiler projects.  The
        # spec component is built before the stimulus document exists, so the
        # compiled projection is re-checked against these two facts afterwards.
        "module": DRIVER_MODULE,
        "source": DRIVER_SOURCE,
    }


def _packed_literal(values: Sequence[int], width: int, slots: int) -> str:
    """The SystemVerilog literal of a flat packed ``slots`` x ``width`` vector."""
    text = "".join(f"{int(value) & ((1 << width) - 1):0{width}b}"
                   for value in reversed(list(values)))
    return f"{slots * width}'b{text}"


def _parameter_literals(parameters: Mapping[str, object]) -> dict[str, str]:
    """``-G`` literals of one driver's projection parameters.

    Scalars become decimal digits; the two packed window vectors become the
    exact literal the renderer also writes, so the elaboration used to read the
    port widths is the elaboration of the instance that will be generated.
    """
    literals: dict[str, str] = {}
    address_width = _positive(parameters.get("ADDRESS_WIDTH"), "driver-address-width")
    num_windows = _positive(parameters.get("NUM_WINDOWS"), "driver-num-windows")
    for name, value in parameters.items():
        key = str(name)
        if isinstance(value, bool):
            _error(f"unsupported-driver-parameter:{key}")
        if isinstance(value, int):
            literals[key] = str(value)
            continue
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            if key not in ("WINDOW_BASE", "WINDOW_SIZE"):
                _error(f"unsupported-driver-parameter:{key}")
            if len(value) > num_windows:
                _error(f"driver-parameter-too-wide:{key}")
            literals[key] = _packed_literal([int(item) for item in value],
                                            address_width, num_windows)
            continue
        _error(f"unsupported-driver-parameter:{key}")
    return literals


def _synthetic_document(*, synthetic: Mapping[str, object], stimulus: Mapping[str, object],
                        base_bit: int, base_dir: Path) -> dict:
    """Resolve the rendered synthetic driver from the compiled stimulus document.

    The module, its source, its parameters and the raw field offsets are read
    from ``soc_stimulus.v1``; the port widths come from elaborating that module
    with exactly those parameters.  The beat interface is the field set of the
    master's own declared protocol, so no component or model name selects a
    connection.
    """
    from myfuzz.protocols.catalog import load_builtin_protocol

    from .soc_stimulus import MMIO_FIELD_ORDER

    projection = stimulus.get("rtl_projection")
    if not isinstance(projection, Mapping):
        _error("stimulus-without-rtl-projection")
    module = str(projection.get("module", ""))
    source = str(projection.get("source", ""))
    parameters = projection.get("parameters")
    declared_ports = projection.get("ports")
    if not module or not source or not isinstance(parameters, Mapping) \
            or not isinstance(declared_ports, Mapping):
        _error("invalid-rtl-projection")
    literals = _parameter_literals(parameters)
    widths = _adapter_port_widths(base_dir, module, source, tuple(sorted(literals.items())),
                                 warning_policy="recorded-nonfatal")
    directions = {str(name): str(value) for name, value in declared_ports.items()}
    if set(widths) != set(directions):
        difference = sorted(set(widths) ^ set(directions))
        _error(f"driver-port-set-mismatch:{module}:{','.join(difference)}")
    plugin = load_builtin_protocol(*SYNTHETIC_MASTER_PROTOCOL)
    beat_fields = {item.field_id for item in plugin.fields}
    layout = stimulus.get("raw_layout")
    segments = layout.get("segments") if isinstance(layout, Mapping) else None
    segment = next((item for item in segments or []
                    if isinstance(item, Mapping) and item.get("segment_id") == "mmio"), None)
    if segment is None:
        _error("stimulus-without-mmio-segment")
    fields = {str(item["port"]): item for item in segment.get("fields", [])
              if isinstance(item, Mapping) and item.get("port")}
    field_order = tuple(str(item.get("name")) for item in segment.get("fields", [])
                        if isinstance(item, Mapping) and item.get("port"))
    if field_order != tuple(MMIO_FIELD_ORDER):
        _error(f"stimulus-mmio-field-set:{','.join(field_order)}")
    clock_port = SYNTHETIC_CLOCK_PORT
    reset_port = str(SYNTHETIC_RESET_CONTRACT["port"])
    instance_id = str(synthetic["instance_id"])
    raw_ports: list[dict] = []
    beat_ports: list[dict] = []
    observations: list[dict] = []
    for name in sorted(directions):
        direction = directions[name]
        width = int(widths[name])
        if name in (clock_port, reset_port):
            if direction != "input" or width != 1:
                _error(f"driver-clock-reset-port:{module}:{name}")
            continue
        if name in fields:
            field = fields[name]
            if direction != "input" or int(field["width"]) != width:
                _error(f"driver-raw-port:{module}:{name}")
            raw_lo = base_bit + int(field["bit_offset"])
            raw_ports.append({
                "port": name,
                "name": f"{instance_id}__{name}",
                "width": width,
                "segment_bit_offset": int(field["bit_offset"]),
                "lsb": int(field["lsb"]),
                "raw_lo": raw_lo,
                "raw_hi": raw_lo + width - 1,
            })
            continue
        if name in beat_fields:
            beat_ports.append({"port": name, "direction": direction, "width": width})
            continue
        if direction != "output":
            _error(f"driver-input-without-source:{module}:{name}")
        observations.append({"port": name, "name": f"{instance_id}__{name}", "width": width})
    if len(raw_ports) != len(MMIO_FIELD_ORDER):
        _error(f"driver-raw-port-set:{module}")
    if {item["port"] for item in beat_ports} != beat_fields:
        _error(f"driver-beat-port-set:{module}")
    return {
        "source_id": str(synthetic["source_id"]),
        "instance_id": instance_id,
        "component_id": str(synthetic["component_id"]),
        "port": str(synthetic["port"]),
        "kind": str(synthetic["kind"]),
        "protocol": list(synthetic["protocol"]),
        "mode": str(synthetic["mode"]),
        "test_modes": list(synthetic["test_modes"]),
        "module": module,
        "source": source,
        "parameters": _plain(parameters),
        "parameter_literals": dict(sorted(literals.items())),
        "ports": {name: {"direction": directions[name], "width": int(widths[name])}
                  for name in sorted(directions)},
        "reset_contract": {"port": reset_port,
                           "polarity": str(SYNTHETIC_RESET_CONTRACT["polarity"])},
        "raw_base_bit": base_bit,
        "raw_ports": raw_ports,
        "beat_ports": sorted(beat_ports, key=lambda item: str(item["port"])),
        "observations": sorted(observations, key=lambda item: str(item["port"])),
    }


#: Adapter parameters whose value is a *protocol* width the profile declares as
#: a capability, not a fabric width.  An AXI4 adapter whose ID_WIDTH/USER_WIDTH
#: are left at their module defaults would be instantiated 1 bit wide against a
#: 4-bit ID and a 64-bit user sideband, which is a silently truncated bus.
CPU_ADAPTER_WIDTH_CAPABILITIES: tuple[tuple[str, str], ...] = (
    ("ID_WIDTH", "id_width"),
    ("USER_WIDTH", "user_width"),
)


def _cpu_adapter(cpu: InstanceComposition, *, fabric_address_width: int,
                 fabric_data_width: int,
                 base_dir: Path | None = None) -> tuple[Mapping[str, object], list[dict]]:
    cpu_contract = cpu.profile.cpu
    assert cpu_contract is not None
    endpoint_ids = list(cpu_contract.master_endpoints)
    masters: list[dict] = []
    adapter_record: dict[str, object] | None = None
    for endpoint_id in endpoint_ids:
        endpoint = cpu.binding.endpoint(endpoint_id)
        kind = MASTER_KINDS.get(endpoint.function)
        if kind is None:
            _error(f"unsupported-cpu-master-function:{endpoint.function}")
        if endpoint.protocol is None:
            _error(f"cpu-master-endpoint-without-protocol:{endpoint_id}")
        binding = ProcessorMemoryBinding(
            endpoint_id=endpoint_id,
            function=endpoint.function,
            protocol=endpoint.protocol,
            fields=tuple(
                EndpointFieldFact(
                    role=item.role, port=item.port, direction=item.direction, width=item.width,
                    signed=item.signed,
                    source=SourceReference(item.source_file, item.line),
                    member_path=item.member_path, raw_lo=item.raw_lo, raw_hi=item.raw_hi,
                    container_width=item.width,
                )
                for item in endpoint.fields
            ),
            extension_fields=(),
        )
        try:
            adapter = resolve_processor_adapter(binding)
        except ProcessorAdapterError as error:
            raise CompositionError(f"cpu-adapter:{endpoint_id}:{error}") from error
        if adapter_record is None:
            adapter_record = {
                "module": adapter.rtl_module,
                "source": adapter.rtl_source,
                "protocol": list(adapter.source_protocol),
                "features": list(adapter.features),
                "reset_contract": {"polarity": adapter.reset_polarity,
                                   "synchrony": adapter.reset_synchrony},
                "source_ports": [
                    {"role": role, "adapter_port": port, "adapter_direction": direction}
                    for role, port, direction in adapter.source_ports
                ],
                "parameter_values": {name: value for name, value in adapter.parameter_values},
            }
        elif adapter_record["module"] != adapter.rtl_module:
            _error(f"mixed-cpu-adapters:{endpoint_id}")
        route_parameters = {"ADDRESS_WIDTH": fabric_address_width,
                            "DATA_WIDTH": fabric_data_width}
        route_parameters.update({name: value for name, value in adapter.parameter_values})
        for parameter, capability in CPU_ADAPTER_WIDTH_CAPABILITIES:
            declared = cpu.profile.capabilities.get(capability)
            if declared is None:
                continue
            route_parameters[parameter] = _positive(
                declared, f"invalid-cpu-capability:{capability}", minimum=1)
        if base_dir is not None:
            # Every declared role is checked against the real port width of the
            # adapter elaborated with exactly these parameters, so a truncating
            # or widening connection is a located error instead of a lint.
            widths = _adapter_port_widths(
                base_dir, adapter.rtl_module, adapter.rtl_source,
                tuple((str(name), str(value))
                      for name, value in sorted(route_parameters.items())))
            ports = {role: port for role, port, _direction in adapter.source_ports}
            for item in endpoint.fields:
                port = ports.get(item.role)
                if port is None:
                    _error(f"cpu-adapter-role-unmapped:{endpoint_id}:{item.role}")
                adapter_width = widths.get(port)
                if adapter_width is None:
                    _error(f"adapter-port-missing:{adapter.rtl_module}:{port}")
                if adapter_width != item.width:
                    _error(f"cpu-adapter-width-incompatible:{endpoint_id}:{item.role}:"
                           f"adapter={adapter_width}:component={item.width}")
        masters.append({
            "source_id": f"cpu_master{len(masters)}",
            "endpoint_id": endpoint_id,
            "kind": kind,
            "function": endpoint.function,
            "protocol": list(endpoint.protocol),
            "fields": [{"role": item.role, "port": item.port, "direction": item.direction,
                        "width": item.width} for item in endpoint.fields],
            "route_parameters": route_parameters,
            "adapter": {
                "adapter_id": adapter.adapter_id,
                "rtl_module": adapter.rtl_module,
                "rtl_source": adapter.rtl_source,
                "features": list(adapter.features),
                "parameter_values": dict(adapter.parameter_values),
                "reset_polarity": adapter.reset_polarity,
                "reset_synchrony": adapter.reset_synchrony,
            },
        })
    assert adapter_record is not None
    return adapter_record, masters


def _processor_execution(masters: Sequence[Mapping[str, object]], *,
                         fabric_address_width: int, fabric_data_width: int,
                         max_wait_cycles: int) -> dict:
    routes = []
    for index, master in enumerate(sorted(masters, key=lambda item: str(item["source_id"])), start=1):
        routes.append({
            "route_id": index,
            "function": master["function"],
            "source_protocol": list(master["protocol"]),
            "target_protocol": ["processor-memory-beat", "1"],
            "adapter_id": master["adapter"]["adapter_id"],
            "rtl_module": master["adapter"]["rtl_module"],
            "rtl_source": master["adapter"]["rtl_source"],
            "parameters": dict(master["route_parameters"]),
            "widths": {"address": fabric_address_width, "data": fabric_data_width},
            "field_connections": [],
            "extension_policies": [],
            "reset_contract": {"polarity": master["adapter"]["reset_polarity"],
                               "synchrony": master["adapter"]["reset_synchrony"]},
            "backend_contract": {
                "mode": "single_outstanding_request_response",
                "protocol": ["processor-memory-beat", "1"],
                "capabilities": {"max_outstanding": 1, "max_wait_cycles": max_wait_cycles},
            },
        })
    document = {
        "schema_version": "processor_execution.v1",
        "adapter_sources": sorted({str(route["rtl_source"]) for route in routes}),
        "classification": None,
        "routes": routes,
    }
    document["execution_hash"] = "sha256:" + hashlib.sha256(canonical_bytes(document)).hexdigest()
    return document


_ADAPTER_FACT_CACHE: dict[tuple[str, str, tuple[tuple[str, str], ...]], Mapping[str, int]] = {}


def _adapter_port_widths(base_dir: Path, module: str, source: str,
                         parameters: Sequence[tuple[str, str]], *,
                         warning_policy: str = "fatal") -> Mapping[str, int]:
    """Real port widths of a generator-owned adapter, from its own elaboration.

    ``warning_policy="recorded-nonfatal"`` is used for a module whose own
    parameter defaults make the frontend emit width-expansion lints (the
    synthetic driver compares a sized selector parameter to an integer
    parameter); the widths it returns are the widths of the elaborated instance
    either way, and the lints stay visible in the same build the runtime and the
    audit compile with ``-Wno-fatal``.
    """
    key = (module, source, tuple(sorted(parameters)), warning_policy)
    if key not in _ADAPTER_FACT_CACHE:
        facts = elaborate_rtl_module(
            base_dir=base_dir, source_root=_module_root(source), top_module=module,
            files=(_module_file(source),), parameters=tuple(sorted(parameters)),
            warning_policy=warning_policy)
        _ADAPTER_FACT_CACHE[key] = {port.name: port.width for port in facts.ports}
    return _ADAPTER_FACT_CACHE[key]


def _module_root(source: str) -> str:
    parts = source.split("/")
    if len(parts) < 2:
        _error(f"invalid-module-source:{source}")
    return "/".join(parts[:-1])


def _module_file(source: str) -> str:
    return source.split("/")[-1]


def _protocol_address_roles(protocol: tuple[str, str]) -> frozenset[str]:
    """Roles the referenced protocol declares with its address width.

    The address field is protocol data, not a name guess: the plugin declares it
    with the ``address_width`` width expression and a host-to-device direction.
    Knowing which interface the decode window applies to is what makes an
    address narrowing provable instead of silent.
    """
    from myfuzz.protocols.catalog import load_builtin_protocol

    plugin = load_builtin_protocol(protocol[0], protocol[1])
    return frozenset(item.field_id for item in plugin.fields
                     if item.direction == "host_to_device"
                     and item.width_expression.strip() == "address_width")


def _bind_role_widths(instance: InstanceComposition, adapter: Mapping[str, object], *,
                      base_dir: Path, window_base: int, window_size: int,
                      address_roles: frozenset[str]) -> dict[str, dict]:
    """Check every adapter port against the real component port it drives.

    An equal width is a direct connection.  A narrower component address port is
    admissible only when the declared window proves the truncation lossless:
    a window that starts at a multiple of the component's address space and fits
    inside it cannot alias two distinct addresses onto one register offset.
    Anything else is reported as an incompatibility instead of being truncated.
    """
    module = str(adapter["rtl_module"])
    source = str(adapter["rtl_source"])
    parameters = tuple((str(item["name"]), str(item["value"]))
                       for item in adapter["parameters"])
    widths = _adapter_port_widths(base_dir, module, source, parameters)
    endpoint = _mmio_endpoint(instance)
    fields = {item.role: item for item in endpoint.fields}
    result: dict[str, dict] = {}
    for item in adapter["target_side_ports"]:
        role = str(item["role"])
        port = str(item["port"])
        adapter_width = widths.get(port)
        if adapter_width is None:
            _error(f"adapter-port-missing:{module}:{port}")
        field = fields.get(role)
        if field is None:
            _error(f"target-adapter-role-unbound:{instance.instance_id}:{role}")
        if adapter_width == field.width:
            result[role] = {"mode": "direct", "width": adapter_width,
                            "component_port": field.port}
            continue
        if field.width < adapter_width and role in address_roles:
            limit = 1 << field.width
            if window_base % limit or window_size > limit:
                _error(f"address-narrowing-unproven:{instance.instance_id}:{role}:"
                       f"base=0x{window_base:x}:size=0x{window_size:x}:"
                       f"port_bits={field.width}")
            result[role] = {
                "mode": "narrow_address",
                "width": adapter_width,
                "component_port": field.port,
                "component_width": field.width,
                "bits": field.width,
                "proof": (f"window base 0x{window_base:x} is a multiple of 2**{field.width} and "
                          f"window size 0x{window_size:x} <= 2**{field.width}, so the low "
                          f"{field.width} bits carry the local offset without aliasing"),
            }
            continue
        _error(f"adapter-width-incompatible:{instance.instance_id}:{role}:"
               f"adapter={adapter_width}:component={field.width}")
    return result


def _peripheral_target_adapter(instance: InstanceComposition, *, target_id: str,
                               base: int, size: int, fabric_address_width: int,
                               base_dir: Path) -> Mapping[str, object]:
    capabilities = dict(instance.profile.capabilities)
    if "partial_write" not in capabilities:
        _error(f"missing-target-capability:{instance.instance_id}:partial_write")
    if "data_width" not in capabilities:
        _error(f"missing-target-capability:{instance.instance_id}:data_width")
    endpoint = _mmio_endpoint(instance)
    # Every declared capability is carried with its declared basis.  The topic
    # names the profile fact the adapter consumed; it is a declaration, not an
    # independent proof, and independence is still owed by the review gate.
    evidence = {
        name: {"topic": f"component_profile.capabilities.{name}",
               "evidence_path": f"component_profile:{instance.component_id}",
               "provenance": "component_profile"}
        for name in capabilities
    }
    record = {
        "component_id": instance.component_id,
        "target_id": target_id,
        "protocol": list(endpoint.protocol),  # type: ignore[arg-type]
        "version": endpoint.protocol[1],  # type: ignore[index]
        "data_width": int(capabilities["data_width"]),
        "window": {"base": base, "size": size},
        "capabilities": capabilities,
        "evidence": evidence,
        "max_wait_cycles": int(capabilities.get("max_wait_cycles", 16)),
    }
    try:
        adapter = resolve_target_adapter(
            {"protocol": "processor-memory-beat", "version": "1",
             "address_width": fabric_address_width,
             "data_width": int(capabilities["data_width"])},
            record,
        )
    except (ValueError, ComponentProfileError) as error:
        raise CompositionError(f"target-adapter:{instance.instance_id}:{error}") from error
    bound_roles = {item.role for item in endpoint.fields}  # type: ignore[union-attr]
    # APB3 targets have no write strobe. The shared APB3/APB4 bridge still
    # exposes the output physically, but HAS_PSTRB=0 makes it unused. Record
    # the explicit open output instead of requiring a fictitious target port.
    adapter = dict(adapter)
    parameters = {str(item["name"]): item["value"] for item in adapter["parameters"]}
    if endpoint.protocol == ("apb", "3") and parameters.get("HAS_PSTRB") == 0 \
            and "pstrb" not in bound_roles:
        unused = [dict(item, reason="APB3 has no PSTRB; HAS_PSTRB=0")
                  for item in adapter["target_side_ports"]
                  if item["role"] == "pstrb" and item["direction"] == "output"]
        adapter["unconnected_outputs"] = unused
        unused_roles = {item["role"] for item in unused}
        adapter["target_side_ports"] = [item for item in adapter["target_side_ports"]
                                        if item["role"] not in unused_roles]
    required_roles = {str(item["role"]) for item in adapter["target_side_ports"]}
    missing = sorted(required_roles - bound_roles)
    if missing:
        _error(f"target-adapter-roles-unbound:{instance.instance_id}:{','.join(missing)}")
    extra = sorted(bound_roles - required_roles)
    if extra:
        # A role the bridge has no pin for would silently leave a peripheral
        # input undriven, so it is a binding error rather than a warning.
        _error(f"target-adapter-roles-unsupported:{instance.instance_id}:{','.join(extra)}")
    endpoint_protocol = endpoint.protocol
    assert endpoint_protocol is not None
    adapter = dict(adapter)
    adapter["role_widths"] = _bind_role_widths(
        instance, adapter, base_dir=base_dir, window_base=base, window_size=size,
        address_roles=_protocol_address_roles(endpoint_protocol))
    return adapter


def _mmio_endpoint(instance: InstanceComposition):
    for endpoint in instance.binding.endpoints:
        if endpoint.function == "mmio_slave":
            if endpoint.protocol is None:
                _error(f"mmio-endpoint-without-protocol:{instance.instance_id}")
            return endpoint
    _error(f"peripheral-without-mmio-endpoint:{instance.instance_id}")


def _allocate_windows(request: CompositionRequest, instances: Sequence[InstanceComposition],
                      controller_size: int) -> dict[str, tuple[int, int]]:
    """Keep every fixed address, place the rest, and never overlap anything."""
    policy: AddressPolicy = request.address_policy
    occupied: list[tuple[int, int, str]] = [
        (region.base, region.base + region.size, f"memory:{region.region_id}")
        for region in request.memory
    ]
    planned: dict[str, tuple[int, int]] = {}
    requests: list[tuple[str, int, int]] = []
    for instance in instances:
        address = instance.profile.address
        assert address is not None
        size = address.window_size
        alignment = max(address.alignment, policy.alignment)
        if instance.window_base is not None:
            base = instance.window_base
        else:
            base = None
        requests.append((instance.instance_id, size, alignment))
        if base is None:
            continue
        end = base + size
        if base % alignment:
            _error(f"fixed-address-misaligned:{instance.instance_id}:{base}!%{alignment}")
        if base + size > (1 << 64):
            _error(f"fixed-address-out-of-range:{instance.instance_id}")
        for other_base, other_end, owner in occupied:
            if base < other_end and other_base < end:
                _error(f"fixed-address-overlap:{instance.instance_id}:{owner}")
        occupied.append((base, end, f"mmio:{instance.instance_id}"))
        planned[instance.instance_id] = (base, size)

    if controller_size:
        requests.append(("__interrupt_controller__", controller_size, controller_size))
    # Deterministic placement order: the request order of `instances` is already
    # the stable instance-id order, and the controller is placed last.
    for instance_id, size, alignment in requests:
        if instance_id in planned:
            continue
        limit = policy.mmio_base + policy.mmio_limit
        candidate = _align_up(policy.mmio_base, alignment)
        while True:
            if candidate + size > limit:
                _error(f"auto-address-space-exhausted:{instance_id}")
            conflict = next(((base, end, owner) for base, end, owner in occupied
                             if candidate < end and base < candidate + size), None)
            if conflict is None:
                break
            candidate = _align_up(conflict[1], alignment)
        occupied.append((candidate, candidate + size, f"mmio:{instance_id}"))
        planned[instance_id] = (candidate, size)
    return planned


def _instance_parameters(instance: ComponentInstance) -> dict:
    parameters: dict[str, object] = {}
    for name, value in instance.parameters.items():
        if not isinstance(name, str) or not name.isidentifier():
            _error(f"invalid-instance-parameter:{instance.instance_id}:{name}")
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            _error(f"unsupported-instance-parameter:{instance.instance_id}:{name}")
        parameters[name] = value
    return parameters


def _check_elaborated_parameters(instance: ComponentInstance,
                                 parameters: Mapping[str, object]) -> None:
    """Every rendered instance parameter must be the one the profile elaborated.

    ``bind_profile`` reads the component's ports, widths and roles from an
    elaboration of the profile's own declared parameters.  An instance that
    renders a *different* value would be a generated top whose structure was
    never the structure the plan bound to, so a parameter the profile did not
    declare (or declared with another value) is refused here instead of being
    rendered and silently contradicting the binding.
    """
    settings = instance.profile.source.elaboration
    declared = {str(name): str(value)
                for name, value in (settings.parameters if settings is not None else ())}
    for name, value in sorted(parameters.items()):
        if str(name) not in declared:
            _error(f"instance-parameter-not-elaborated:{instance.instance_id}:{name}")
        if str(value) != declared[str(name)]:
            _error(f"instance-parameter-mismatch:{instance.instance_id}:{name}:"
                   f"instance={value}:elaborated={declared[str(name)]}")


def _resolve_peers(instances: Sequence[InstanceComposition], request: CompositionRequest, *,
                   declared: Mapping[str, Mapping[str, object]],
                   gaps: list[str]) -> tuple[dict[str, dict[str, str]], tuple[PeerPlan, ...]]:
    """Bind the request's declared peer attachments to the implemented models.

    Resolution is by role signature only (``soc_peer_plan.match_models``): the
    component id, the instance id and every port name are irrelevant to the
    choice.  An interface the request leaves alone keeps ``external``
    dispositions and is exported exactly as before; an interface whose declared
    roles match no implemented model is exported and recorded when the request
    does not demand attachment, and refused with a located capability gap when
    it does.
    """
    attachments: dict[str, dict[str, object]] = {}
    for item in request.peers:
        attachments.setdefault(item.instance_id, {})[item.endpoint_id] = item
    peer_endpoints: dict[str, dict[str, str]] = {}
    plans: list[PeerPlan] = []
    for instance in instances:
        requested = attachments.get(instance.instance_id, {})
        for endpoint in instance.binding.endpoints:
            if endpoint.function != PEER_ENDPOINT_FUNCTION:
                continue
            attachment = requested.get(endpoint.endpoint_id)
            candidates = match_models(endpoint.fields)
            if attachment is None or not attachment.attach:
                if attachment is not None:
                    reason = ("the request declares this interface external, so the pins stay "
                              "exported and the environment drives them")
                elif candidates:
                    reason = (f"the request declares no peer attachment for this interface, so the "
                              f"pins stay exported; the {','.join(item.peer_id for item in candidates)} "
                              f"peer model matches its declared roles and could drive it")
                else:
                    reason = export_reason(endpoint.fields)
                gaps.append(f"{instance.instance_id}.{endpoint.endpoint_id}: {reason}")
                continue
            try:
                plan = plan_peer(
                    instance_id=instance.instance_id,
                    component_id=instance.component_id,
                    endpoint_id=endpoint.endpoint_id,
                    fields=endpoint.fields,
                    declared=attachment.parameters,
                    component_parameters=declared.get(instance.instance_id, {}))
            except PeerPlanError as error:
                # ``plan_peer`` refuses an interface no model implements
                # (peer-role-unsupported) and one whose parameters or timing the
                # component cannot honour; both are located capability gaps.
                raise CompositionError(
                    f"peer-attach:{instance.instance_id}:{endpoint.endpoint_id}:{error}") \
                    from error
            component_ports = {f"{instance.instance_id}__{port.name}"
                               for port in instance.binding.facts.ports}
            collision = sorted(component_ports.intersection(plan.top_ports))
            if collision:
                # A peer top-level port that collides with a component port would
                # short two different pins of one instance together.
                _error(f"peer-top-port-collision:{instance.instance_id}:{','.join(collision)}")
            peer_endpoints.setdefault(instance.instance_id, {})[endpoint.endpoint_id] = \
                plan.peer_id
            plans.append(plan)
    plans.sort(key=lambda item: (item.instance_id, item.endpoint_id))
    return peer_endpoints, tuple(plans)


def build_composition(request: CompositionRequest, *, base_dir: Path,
                      elaboration_mode: str = "auto",
                      drive_profile: str = DEFAULT_DRIVE_PROFILE) -> CompositionPlan:
    """Build the full, validated composition plan for one request.

    ``drive_profile`` selects the declared ownership profile from
    ``input_constraints.DRIVE_PROFILES``.  ``cpu_execute`` adds no synthetic
    master and keeps the CPU-only composition unchanged; a profile whose bus
    owner is the synthetic master adds one ``fuzz_mmio`` master plus its system
    component, declares that master's modes and compiles the ``soc_stimulus.v1``
    document the renderer and the runtime both consume.
    """
    profile_name, drive = _drive_profile(drive_profile)
    base = Path(base_dir)
    # The declared adapter scope is checked before anything is bound: a refused
    # protocol/feature combination is named even when the profile's ports could
    # not be bound at all, so the caller never sees a width or port conflict
    # where the real reason is "this combination is out of scope".
    _raise_scope_refusals(declared_scope_refusals(request))
    bindings: dict[str, ProfileBinding] = {}
    order = sorted(request.instances(), key=lambda item: item.instance_id)
    declared: dict[str, dict[str, object]] = {}
    provisional: list[InstanceComposition] = []
    for instance in order:
        binding = _cached_facts(instance.profile, base_dir=base, mode=elaboration_mode,
                                cache=bindings)
        parameters = _instance_parameters(instance)
        _check_elaborated_parameters(instance, parameters)
        declared[instance.instance_id] = parameters
        provisional.append(InstanceComposition(
            instance_id=instance.instance_id,
            component_id=instance.profile.component_id,
            kind=instance.profile.kind,
            top_module=instance.profile.source.top_module,
            profile=instance.profile,
            binding=binding,
            dispositions=(),
            parameters=parameters,
            window_base=instance.address,
            window_size=(instance.profile.address.window_size
                         if instance.profile.address is not None else None),
        ))
    # Peer resolution precedes the disposition ledger: an interface a peer model
    # drives is *not* exported, and the ledger must say so from the start rather
    # than be patched afterwards.
    peer_gaps: list[str] = []
    try:
        peer_endpoints, peers = _resolve_peers(provisional, request, declared=declared,
                                               gaps=peer_gaps)
    except PeerPlanError as error:
        raise CompositionError(f"peer-plan:{error}") from error
    instances: list[InstanceComposition] = []
    for item in provisional:
        try:
            dispositions = build_port_dispositions(
                item.instance_id, item.binding,
                clock_domain=item.profile.clocks[0].domain,
                reset_domain=item.profile.resets[0].domain,
                profile_port_actions=item.profile.port_actions,
                peer_endpoints=peer_endpoints.get(item.instance_id))
        except PortDispositionError as error:
            raise CompositionError(f"dispositions:{item.instance_id}:{error}") from error
        instances.append(replace(item, dispositions=dispositions))
    by_instance = {item.instance_id: item for item in instances}
    cpu_instance = by_instance.get(request.cpu.instance_id)
    if cpu_instance is None or cpu_instance.kind != "cpu":
        _error("cpu-instance-missing")

    # Structural scope, checked once every component is bound and disposed: a
    # peripheral master endpoint, a debug transport, a trace-role CPU input and
    # a route that would cross a clock domain are all refused here rather than
    # reaching the renderer as an unconnected functional port.
    _raise_scope_refusals(bound_scope_refusals(request, instances))
    cpu_inputs = tuple(cpu_input_records(cpu_instance))

    cpu_adapter, masters = _cpu_adapter(
        cpu_instance, base_dir=base,
        fabric_address_width=int(cpu_instance.profile.capabilities["address_width"]),
        fabric_data_width=int(cpu_instance.profile.capabilities["data_width"]))

    # Interrupt topology before address allocation: the controller needs a window.
    sources: list[tuple[InterruptSourceRequest, object]] = []
    for instance in instances:
        if instance.kind != "peripheral":
            continue
        for source in instance.profile.interrupts:
            sources.append((InterruptSourceRequest(
                instance_id=instance.instance_id,
                component_id=instance.component_id,
                endpoint_id=source.endpoint_id,
                role=source.role,
                declared_source_id=source.source_id,
                bit=source.bit,
            ), source))
    try:
        interrupt_plan = build_interrupt_plan(
            sources=sources,
            bindings={item.instance_id: item.binding for item in instances},
            cpu_instance_id=cpu_instance.instance_id,
            cpu_binding=cpu_instance.binding,
            cpu_profile=cpu_instance.profile,
            address_width=int(cpu_instance.profile.capabilities["address_width"]))
    except InterruptPlanError as error:
        raise CompositionError(f"interrupt-plan:{error}") from error

    peripherals = [item for item in instances if item.kind == "peripheral"]
    windows = _allocate_windows(request, peripherals,
                                interrupt_plan.window_size if interrupt_plan.present else 0)
    controller_base = windows.get("__interrupt_controller__", (None, None))[0]
    try:
        interrupt_document = interrupt_plan_document(
            interrupt_plan, window_base=controller_base,
            provenance={"controller_version": interrupt_plan.version,
                        "verified_sources": interrupt_plan.verified_max_sources})
    except InterruptPlanError as error:
        raise CompositionError(f"interrupt-plan:{error}") from error

    fabric_address_width = int(cpu_instance.profile.capabilities["address_width"])
    fabric_data_width = int(cpu_instance.profile.capabilities["data_width"])
    max_wait = max([int(item.profile.capabilities.get("max_wait_cycles", 16))
                    for item in peripherals] + [16])
    processor_execution = _processor_execution(
        masters, fabric_address_width=fabric_address_width,
        fabric_data_width=fabric_data_width, max_wait_cycles=max_wait)
    synthetic = _synthetic_master(
        profile_name=profile_name, profile=drive, request=request,
        fabric_address_width=fabric_address_width, fabric_data_width=fabric_data_width)

    spec, target_records = _build_spec(
        request, instances, cpu_instance, masters, processor_execution, windows,
        interrupt_plan, interrupt_document, controller_base,
        fabric_address_width, fabric_data_width, max_wait, base, synthetic, peers)
    try:
        plan = build_soc_plan(dict(spec), processor_execution, target_records)
    except SocContractError as error:
        raise CompositionError(f"soc-plan:{error}") from error

    layout = _raw_layout(instances, cpu_instance)
    # The stimulus document is compiled from the built plan, so it is the single
    # source of the driver parameters, the raw segment offsets and the declared
    # reset semantics the renderer and the runtime both consume.
    stimulus = _compile_stimulus(plan, mode=str(synthetic["mode"]) if synthetic is not None
                                 else "cpu_only")
    synthetic_document: Mapping[str, object] = {}
    if synthetic is not None:
        projection = stimulus["rtl_projection"]
        if str(projection["module"]) != str(synthetic["module"]) \
                or str(projection["source"]) != str(synthetic["source"]):
            _error(f"stimulus-driver-mismatch:{projection['module']}")
        lane = next((int(source["index"]) for source in plan["fabric"]["sources"]
                     if str(source["source_id"]) == str(synthetic["source_id"])), None)
        if lane is None:
            _error(f"synthetic-master-lane-missing:{synthetic['source_id']}")
        synthetic_document = _synthetic_document(
            synthetic=synthetic, stimulus=stimulus,
            base_bit=int(layout["raw_width"]), base_dir=base)
        synthetic_document = {**synthetic_document, "lane": lane}
    gaps = list(interrupt_plan.gaps)
    gaps.extend(peer_gaps)
    available_modes = list(plan["stimulus"]["available_modes"])
    for mode in request.test_modes:
        if mode in available_modes:
            continue
        if synthetic is None:
            gaps.append(
                f"{mode}: no generated synthetic beat-master lane is available; "
                "the plan exposes cpu_only only and must not be used as BFM evidence")
        else:
            gaps.append(
                f"{mode}: the compiled plan does not declare this mode as available, so no "
                f"sample may claim it")
    for instance in instances:
        if instance.profile.kind == "peripheral":
            address = instance.profile.address
            if address is None or not address.registers:
                gaps.append(
                    f"{instance.instance_id}: no register semantics are declared, so functional "
                    f"checks against its registers are not available")
    # The multi-role port record is derived from the profile binding and the
    # disposition ledger alone, so the renderer and the independent audit read the
    # same claim: which member of which struct port each role's net carries.
    bridged: dict[str, frozenset[str]] = {}
    for target in target_records:
        if "instance_id" not in target:
            continue
        adapter = target.get("resolved_adapter")
        if not isinstance(adapter, Mapping):
            continue
        bridged[str(target["instance_id"])] = frozenset(
            str(item["role"]) for item in adapter.get("target_side_ports", []))
    cpu_entry = interrupt_document.get("cpu_entry")
    instances = [
        replace(item,
                port_bindings=port_binding_records(
                    item, bridged_roles=bridged.get(item.instance_id, frozenset()),
                    interrupt_document=interrupt_document,
                    cpu_entry=cpu_entry if isinstance(cpu_entry, Mapping) else None))
        for item in instances]
    cpu_instance = next(item for item in instances if item.kind == "cpu")
    payload = {
        "request_id": request.request_id,
        "spec_hash": soc_spec_hash(dict(spec)),
        "plan_hash": hashlib.sha256(canonical_bytes(_plain(plan))).hexdigest(),
        # The drive profile changes the rendered top (the synthetic master and the
        # CPU reset hold) without changing the fabric plan, so the composition
        # identity has to carry it: two profiles are two different builds.
        "drive_profile": profile_name,
        # The attached peers change the rendered boundary (an interface is driven
        # inside the top instead of being exported), so they are part of the
        # identity even when the fabric plan is identical.
        "peers": [item.document() for item in peers],
    }
    return CompositionPlan(
        request_id=request.request_id,
        request=request,
        instances=tuple(instances),
        spec=spec,
        plan=plan,
        interrupt_plan=interrupt_plan,
        interrupt_document=interrupt_document,
        processor_execution=processor_execution,
        cpu_adapter=cpu_adapter,
        target_records=tuple(target_records),
        raw_layout=layout,
        gaps=tuple(gaps),
        plan_hash="sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest(),
        drive_profile=profile_name,
        drive=dict(drive),
        stimulus=stimulus,
        synthetic=synthetic_document,
        cpu_inputs=cpu_inputs,
        peers=peers,
    )


def port_binding_records(instance: InstanceComposition, *,
                         bridged_roles: frozenset[str] = frozenset(),
                         interrupt_document: Mapping[str, object] | None = None,
                         cpu_entry: Mapping[str, object] | None = None
                         ) -> tuple[Mapping[str, object], ...]:
    """The member-to-net record of every multi-role physical port of one instance.

    A port is recorded when it is an aggregate (it has an elaborated member
    layout) or when it carries more than one disposition segment, because those
    are exactly the ports whose connection is assembled from several nets.  The
    fields are computed from the elaboration facts and the disposition ledger, so
    the record is a claim the audit can re-check rather than a copy of the
    rendered text.
    """
    records: list[Mapping[str, object]] = []
    grouped = port_segments(instance.dispositions)
    for port in sorted(grouped):
        entries = grouped[port]
        fact = instance.binding.facts.port(port)
        members = tuple(getattr(fact, "members", ()))
        if not members and not port_is_aggregated(entries):
            continue
        segments = aligned_segments(entries, members, entries[0].width)
        records.append({
            "instance_id": instance.instance_id,
            "component_id": instance.component_id,
            "port": port,
            "direction": entries[0].direction,
            "width": entries[0].width,
            "members": [{"path": list(member.path), "bit_lo": member.raw_lo,
                         "bit_hi": member.raw_hi, "width": member.width,
                         "signed": bool(member.signed),
                         "enum_type": str(getattr(member, "enum_type", ""))}
                        for member in members],
            "segments": [{
                "bit_lo": low, "bit_hi": high, "member_path": list(path),
                "disposition": entry.disposition,
                "endpoint_id": entry.endpoint_id, "role": entry.role,
                "expression": segment_expression(
                    entry, bridged_roles=bridged_roles,
                    interrupt_document=interrupt_document, cpu_entry=cpu_entry),
            } for low, high, path, entry in segments],
        })
    return tuple(records)


def _compile_stimulus(plan: Mapping[str, object], *, mode: str) -> dict:
    """Compile the plan's ``soc_stimulus.v1`` document for one declared mode."""
    try:
        return compile_soc_stimulus(_plain(plan), {  # type: ignore[arg-type]
            "mode": mode, "address_strategy": STIMULUS_ADDRESS_STRATEGY})
    except (ValueError, SocContractError) as error:
        raise CompositionError(f"soc-stimulus:{mode}:{error}") from error


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [_plain(item) for item in value]
    return value


def _raw_layout(instances: Sequence[InstanceComposition],
                cpu_instance: InstanceComposition) -> dict[str, object]:
    """The raw-input layout: one segment per declared special input."""
    annotations: list[dict[str, object]] = []
    for instance in instances:
        for entry in fuzz_ports(instance.dispositions):
            annotations.append({
                "endpoint_id": f"{instance.instance_id}::{entry.port}",
                "protocol_candidates": [],
                "fields": [{
                    "role": entry.role or entry.port,
                    "direction": "input",
                    "width": entry.bit_hi - entry.bit_lo + 1,
                    "port": _top_port_name(entry),
                    "randomizable": True,
                    "source": {"file": instance.binding.facts.ports[0].source_file
                               if instance.binding.facts.ports else entry.evidence,
                               "line": 1},
                    "evidence": [entry.evidence],
                }],
            })
    isa = None
    cpu_contract = cpu_instance.profile.cpu
    if cpu_contract is not None:
        from myfuzz.isa.constraints import IsaContract

        try:
            isa = IsaContract(int(cpu_contract.xlen), tuple(cpu_contract.extensions))
        except Exception:
            isa = None
    if annotations:
        try:
            layout = build_input_layout({"endpoints": annotations}, isa=isa)
        except Exception as error:
            raise CompositionError(f"raw-layout:{error}") from error
        document = input_layout_document(layout)
    else:
        document = {"schema_version": "input_layout.v1", "raw_width": 0, "fields": []}
        document["layout_hash"] = hashlib.sha256(canonical_bytes(document)).hexdigest()
    strategies: dict[str, str] = {}
    by_owner = {f"{instance.instance_id}::{entry.port}": entry
                for instance in instances for entry in fuzz_ports(instance.dispositions)}
    records: list[dict[str, object]] = []
    for item in document.get("fields", []):
        owner = str(item.get("owner", ""))
        entry = by_owner.get(owner)
        binding = item.get("binding")
        top_port = str(binding.get("port")) if isinstance(binding, Mapping) else ""
        if entry is not None:
            strategies[top_port] = str(entry.strategy)
        records.append({
            "instance_id": owner.split("::")[0],
            "port": owner.split("::", 1)[1] if "::" in owner else owner,
            "top_port": top_port,
            "field_id": str(item.get("field_id", "")),
            "role": str(item.get("role", "")),
            "width": int(item.get("width", 1)),
            # The raw-input coordinates recorded by the layout, not the port bit
            # indices: the policy and the driver both address raw bits.
            "raw_lo": int(item.get("raw_lo", 0)),
            "raw_hi": int(item.get("raw_hi", 0)),
            "strategy": str(entry.strategy) if entry is not None else "cycle_value",
            "drive": {str(name): value
                      for name, value in (entry.drive.items() if entry is not None else ())},
            "basis": str(entry.evidence) if entry is not None else "input_layout",
        })
    document["drive_strategies"] = strategies
    document["special_inputs"] = records
    document["phase"] = ("static layout and drive policy; per-cycle driving is implemented by "
                         "soc_special_input_driver instances generated from this record")
    return document


def _top_port_name(entry: DispositionEntry) -> str:
    """A stable, instance-unique, legal top-level port name."""
    span = "" if (entry.bit_lo, entry.bit_hi) == (0, entry.width - 1) else \
        f"_{entry.bit_hi}_{entry.bit_lo}"
    name = f"{entry.instance_id}__{entry.port}{span}"
    if not name.replace("_", "").isalnum() or name[0].isdigit():
        _error(f"invalid-top-port-name:{name}")
    return name


def _build_spec(request: CompositionRequest, instances: Sequence[InstanceComposition],
                cpu_instance: InstanceComposition, masters: Sequence[Mapping[str, object]],
                processor_execution: Mapping[str, object], windows: Mapping[str, tuple[int, int]],
                interrupt_plan: InterruptPlan, interrupt_document: Mapping[str, object],
                controller_base: int | None, fabric_address_width: int,
                fabric_data_width: int, max_wait: int, base_dir: Path,
                synthetic: Mapping[str, object] | None = None,
                peers: Sequence[PeerPlan] = ()) -> tuple[dict, list[dict]]:
    memory_model = MEMORY_MODEL_32 if fabric_data_width == 32 else MEMORY_MODEL_64
    components: list[dict] = []
    # One spec component per distinct RTL/profile; every instance of it is listed
    # under that component, which is what lets uart0 and uart1 share one profile
    # without duplicating the component description.
    grouped: dict[str, list[InstanceComposition]] = {}
    for instance in instances:
        grouped.setdefault(instance.component_id, []).append(instance)
    for component_id, members in sorted(grouped.items()):
        head = members[0]
        components.append({
            "component_id": component_id,
            "kind": head.kind,
            "source_lock": component_id,
            "top_module": head.top_module,
            "clock_domain": head.clock_domain,
            "reset_domain": head.reset_domain,
            "instances": [{"instance_id": item.instance_id,
                           "parameters": dict(item.parameters)}
                          for item in sorted(members, key=lambda item: item.instance_id)],
            "capability_evidence": {
                "profile_binding_hash": head.binding.binding_hash,
                "content_hash": head.binding.facts.content_hash,
                "revision": head.binding.facts.revision,
                "provenance": f"component_profile:{component_id}",
            },
        })
    for region in request.memory:
        components.append({
            "component_id": region.component_id,
            "kind": "memory",
            "source_lock": region.component_id,
            "top_module": memory_model,
            "clock_domain": instance_clock(instances, cpu_instance),
            "reset_domain": instance_reset(instances, cpu_instance),
            "instances": [{"instance_id": region.component_id,
                           "parameters": {"BASE_ADDR": region.base, "BYTES": region.size}}],
            "capability_evidence": {
                "model": "byte image memory model",
                "provenance": MEMORY_MODEL_SOURCE,
            },
        })
    if interrupt_plan.present:
        components.append({
            "component_id": interrupt_plan.controller_instance_id,
            "kind": "clock_reset",
            "source_lock": interrupt_plan.version,
            "top_module": interrupt_plan.module,
            "clock_domain": instance_clock(instances, cpu_instance),
            "reset_domain": instance_reset(instances, cpu_instance),
            "instances": [{"instance_id": interrupt_plan.controller_instance_id,
                           "parameters": {"NUM_SOURCES": interrupt_plan.num_sources,
                                          "ADDRESS_WIDTH": interrupt_plan.address_width}}],
            "capability_evidence": {
                "controller_version": interrupt_plan.version,
                "verified_max_sources": interrupt_plan.verified_max_sources,
                "provenance": interrupt_plan.rtl_source,
            },
        })

    # Only modes a master can actually participate in are declared.  Without a
    # synthetic master the CPU is the only ingress, so only the CPU modes are
    # advertised; with one, the request's modes are split between the two master
    # kinds exactly as soc_contracts.KIND_MODES declares them.
    spec_masters: list[dict] = []
    if synthetic is None:
        declared_modes = sorted({mode for master in masters
                                 for mode in request.test_modes
                                 if mode in ("cpu_only",)})
        if not declared_modes:
            declared_modes = ["cpu_only"]
        cpu_modes = list(declared_modes)
        synthetic_modes: list[str] = []
    else:
        cpu_modes = sorted(mode for mode in request.test_modes if mode in CPU_MASTER_MODE_SET)
        if not cpu_modes:
            # Every master must declare a non-empty mode list and the CPU lane is
            # physically present, so the structural CPU mode is the honest
            # minimum when the request asked for none of the CPU's own modes.
            cpu_modes = ["cpu_only"]
        synthetic_modes = [str(mode) for mode in synthetic["test_modes"]]
        declared_modes = sorted(set(cpu_modes) | set(synthetic_modes))
    for master in masters:
        endpoint = cpu_instance.binding.endpoint(str(master["endpoint_id"]))
        spec_masters.append({
            "source_id": master["source_id"],
            "kind": master["kind"],
            "component_id": cpu_instance.component_id,
            "port": str(master["endpoint_id"]),
            "protocol": list(endpoint.protocol),  # type: ignore[arg-type]
            "data_width": fabric_data_width,
            "address_width": fabric_address_width,
            "test_modes": [mode for mode in cpu_modes
                           if master["kind"] in ("cpu_instruction", "cpu_data", "cpu_unified")],
        })
    if synthetic is not None:
        components.append({
            "component_id": str(synthetic["component_id"]),
            "kind": SYNTHETIC_COMPONENT_KIND,
            "source_lock": str(synthetic["source_id"]),
            "top_module": str(synthetic["module"]),
            "clock_domain": instance_clock(instances, cpu_instance),
            "reset_domain": instance_reset(instances, cpu_instance),
            "instances": [{"instance_id": str(synthetic["instance_id"]), "parameters": {}}],
            "capability_evidence": {
                "module": str(synthetic["module"]),
                "protocol": list(synthetic["protocol"]),
                "provenance": str(synthetic["source"]),
                "contract": "soc_stimulus.v1#/rtl_projection",
            },
        })
        spec_masters.append({
            "source_id": str(synthetic["source_id"]),
            "kind": str(synthetic["kind"]),
            "component_id": str(synthetic["component_id"]),
            "port": str(synthetic["port"]),
            "protocol": list(synthetic["protocol"]),
            "data_width": fabric_data_width,
            "address_width": fabric_address_width,
            "test_modes": list(synthetic_modes),
        })
    # Every declared ingress owns the same windows: the fabric's per-window
    # source mask, not a name, decides who may reach which target.
    request_sources = [str(master["source_id"]) for master in masters]
    if synthetic is not None:
        request_sources.append(str(synthetic["source_id"]))

    memory_targets: list[dict] = []
    for region in request.memory:
        memory_targets.append({
            "target_id": f"{region.region_id}_win",
            "component_id": region.component_id,
            "port": "mem",
            "protocol": ["ready-valid-memory", "1"],
            "window": {"base": region.base, "size": region.size},
            "request_sources": list(request_sources),
            "response_owner": "soc_fabric",
            "byte_enable": bool(region.permissions["write"]),
            "data_width": fabric_data_width,
            "width_conversion": {"spanning_write": "reject", "spanning_read": "reject"},
        })
    peripheral_targets: list[dict] = []
    target_records: list[dict] = []
    for region in request.memory:
        writable = bool(region.permissions["write"])
        target_records.append({
            "target_id": f"{region.region_id}_win",
            "component_id": region.component_id,
            "port": "mem",
            "protocol": ["ready-valid-memory", "1"],
            "adapter_module": memory_model,
            "adapter_source": MEMORY_MODEL_SOURCE,
            "adapter_modules": {"processor-memory-beat@1": memory_model},
            "capabilities": {"partial_write": writable, "read": True, "write": writable,
                             "data_width": fabric_data_width},
            "evidence": {"provenance": MEMORY_MODEL_SOURCE,
                         "model": "byte image memory model"},
        })
    for instance in instances:
        if instance.kind != "peripheral":
            continue
        base, size = windows[instance.instance_id]
        target_id = f"{instance.instance_id}_win"
        capabilities = dict(instance.profile.capabilities)
        peripheral_targets.append({
            "target_id": target_id,
            "component_id": instance.component_id,
            "port": "mmio",
            "protocol": list(_mmio_endpoint(instance).protocol),  # type: ignore[arg-type]
            "window": {"base": base, "size": size},
            "request_sources": list(request_sources),
            "response_owner": "soc_fabric",
            "byte_enable": bool(capabilities.get("partial_write", False)),
            "data_width": int(capabilities["data_width"]),
            "width_conversion": {"spanning_write": "reject", "spanning_read": "reject"},
        })
        adapter = _peripheral_target_adapter(instance, target_id=target_id, base=base, size=size,
                                             fabric_address_width=fabric_address_width,
                                             base_dir=base_dir)
        target_records.append({
            "target_id": target_id,
            "component_id": instance.component_id,
            "port": "mmio",
            "protocol": list(_mmio_endpoint(instance).protocol),  # type: ignore[arg-type]
            "adapter_module": adapter["rtl_module"],
            "adapter_source": adapter["rtl_source"],
            "adapter_modules": {"processor-memory-beat@1": adapter["rtl_module"]},
            "capabilities": capabilities,
            "evidence": {
                name: {"topic": f"component_profile.capabilities.{name}",
                       "evidence_path": f"component_profile:{instance.component_id}",
                       "provenance": "component_profile"}
                for name in capabilities
            },
            # Kept for the renderer: the resolved bridge plus the instance it
            # belongs to.  Two instances of one component share the capability
            # record but not the window or the wiring.
            "resolved_adapter": adapter,
            "instance_id": instance.instance_id,
            "window": {"base": base, "size": size},
        })

    controller_target: dict | None = None
    if interrupt_plan.present:
        controller_id = str(interrupt_plan.controller_instance_id)
        base, size = windows["__interrupt_controller__"]
        controller_target = {
            "target_id": f"{controller_id}_win",
            "component_id": controller_id,
            "port": "mmio",
            "protocol": ["processor-memory-beat", "1"],
            "window": {"base": base, "size": size},
            "request_sources": list(request_sources),
            "response_owner": "soc_fabric",
            "byte_enable": False,
            "data_width": 32,
            "width_conversion": {"spanning_write": "reject", "spanning_read": "reject"},
        }
        target_records.append({
            "target_id": f"{controller_id}_win",
            "component_id": controller_id,
            "port": "mmio",
            "protocol": ["processor-memory-beat", "1"],
            "adapter_module": interrupt_plan.module,
            "adapter_source": interrupt_plan.rtl_source,
            "adapter_modules": {"processor-memory-beat@1": interrupt_plan.module},
            "capabilities": {"partial_write": False, "read": True, "write": True,
                             "data_width": 32, "byte_enable": False},
            "evidence": {"provenance": interrupt_plan.rtl_source,
                         "version": interrupt_plan.version},
        })

    # External pin endpoints are recorded as explicit environment links even
    # when no peer model is attached.  This keeps the generated top's physical
    # boundary in the plan and prevents a later harness from treating an
    # unconnected UART/SPI/GPIO pin as an implicit random input or an accidental
    # same-name peer.  When a peer *is* attached, the link carries the resolved
    # peer record and the connection says the pins are driven inside the top.
    environment_links: list[dict[str, object]] = []
    by_peer = {(item.instance_id, item.endpoint_id): item for item in peers}
    for instance in sorted(instances, key=lambda item: item.instance_id):
        for endpoint in instance.binding.endpoints:
            if endpoint.function != "external_pins":
                continue
            protocol = endpoint.protocol or ("external-pins", "1")
            bound = by_peer.get((instance.instance_id, endpoint.endpoint_id))
            environment_links.append({
                "link_id": f"{instance.instance_id}:{endpoint.endpoint_id}",
                "component_id": instance.component_id,
                "endpoint_id": endpoint.endpoint_id,
                "protocol": list(protocol),
                "parameters": {
                    "clock_domain": instance.clock_domain,
                    "connection": "internal_peer" if bound is not None else "top_level_unbound",
                    "peer": bound.document() if bound is not None else None,
                    "roles": [{"role": field.role, "port": field.port,
                               "direction": field.direction, "width": field.width}
                              for field in endpoint.fields],
                    "role_bindings": ([item.document() for item in bound.bindings]
                                      if bound is not None else []),
                },
            })

    spec = {
        "schema_version": "soc_spec.v1",
        "spec_id": request.request_id,
        "source_locks": sorted({str(component["source_lock"]) for component in components}),
        "components": components,
        "memory_regions": [{
            "region_id": region.region_id,
            "component_id": region.component_id,
            "base": region.base,
            "size": region.size,
            "permissions": dict(region.permissions),
            "physical_memory_id": region.physical_memory_id,
            "initialization_policy": region.initialization_policy,
        } for region in request.memory],
        "masters": spec_masters,
        "targets": memory_targets + peripheral_targets
        + ([controller_target] if controller_target else []),
        # The first-phase topology never assigns a peripheral source to a CPU irq
        # number.  The controller plan below is the authoritative record.
        "test_modes": list(declared_modes),
        "interrupt_routes": [],
        "environment_links": environment_links,
        "resources": {
            "clock_domains": [{"name": request.clock_domain,
                               "frequency_hz": request.clock_frequency_hz}],
            "resets": [{"name": "rst_sys_ni", "domain": request.reset_domain,
                        "polarity": request.reset_polarity,
                        "synchronous": request.reset_synchronous}],
            "clock_adapters": [],
            "limits": {"build_timeout_s": 600, "run_timeout_s": 120,
                       "rss_limit_mb": 2048, "cycles_per_sample": 100000,
                       "max_wait_cycles": max_wait},
        },
        "assumptions": [{
            "assumption_id": "single_runtime_clock",
            "statement": "Every composed component runs on the single declared runtime clock "
                         "domain and the single declared reset domain.",
            "provenance": f"composition_request:{request.request_id}",
        }, {
            "assumption_id": "single_outstanding_fabric",
            "statement": "The shared beat fabric allows exactly one outstanding transaction, so "
                         "concurrent and out-of-order behaviour is not covered by this build.",
            "provenance": "src/myfuzz/protocols/rtl/soc_arbiter.sv",
        }],
        "interrupt_controller": interrupt_document,
        "provenance": {
            "request": request.request_id,
            "profiles": ",".join(sorted({item.component_id for item in instances})),
            "generator": "myfuzz.composition.soc_composition",
        },
    }
    return spec, target_records


def instance_clock(instances: Sequence[InstanceComposition], cpu: InstanceComposition) -> str:
    return cpu.clock_domain


def instance_reset(instances: Sequence[InstanceComposition], cpu: InstanceComposition) -> str:
    return cpu.reset_domain


def composition_document(plan: CompositionPlan) -> dict[str, object]:
    """The complete generation record for one composition."""
    return {
        "schema_version": COMPOSITION_SCHEMA,
        "request_id": plan.request_id,
        "plan_hash": plan.plan_hash,
        "instances": [{
            "instance_id": item.instance_id,
            "component_id": item.component_id,
            "kind": item.kind,
            "top_module": item.top_module,
            "clock_domain": item.clock_domain,
            "reset_domain": item.reset_domain,
            "binding_hash": item.binding.binding_hash,
            "content_hash": item.binding.facts.content_hash,
            "parameters": _plain(item.parameters),
            "window": ({"base": item.window_base, "size": item.window_size}
                       if item.window_base is not None else None),
            "multi_role_ports": _plain(item.port_bindings),
        } for item in plan.instances],
        "profile_bindings": {
            item.component_id: {
                "binding_hash": item.binding.binding_hash,
                "revision": item.binding.facts.revision,
                "content_hash": item.binding.facts.content_hash,
                "top_module": item.binding.facts.top_module,
                "endpoints": [{
                    "endpoint_id": endpoint.endpoint_id,
                    "function": endpoint.function,
                    "protocol": list(endpoint.protocol) if endpoint.protocol else None,
                    "fields": [{"role": field.role, "port": field.port,
                                "member_path": list(field.member_path),
                                "direction": field.direction, "width": field.width,
                                "raw_lo": field.raw_lo, "raw_hi": field.raw_hi,
                                "source": {"file": field.source_file, "line": field.line}}
                               for field in endpoint.fields],
                } for endpoint in item.binding.endpoints],
            }
            for item in {inst.component_id: inst for inst in plan.instances}.values()
        },
        "dispositions": dispositions_document(
            [entry for item in plan.instances for entry in item.dispositions],
            instances={item.instance_id: item.dispositions for item in plan.instances},
            provenance={"request": plan.request_id}),
        "raw_layout": _plain(plan.raw_layout),
        "drive_profile": plan.drive_profile,
        "drive": _plain(plan.drive),
        "stimulus": _plain(plan.stimulus),
        "synthetic_master": _plain(plan.synthetic),
        "peers": [item.document() for item in plan.peers],
        "interrupts": _plain(plan.interrupt_document),
        "processor_execution": _plain(plan.processor_execution),
        "cpu_adapter": _plain(plan.cpu_adapter),
        "cpu_inputs": _plain(plan.cpu_inputs),
        "soc_spec": _plain(plan.spec),
        "soc_plan": _plain(plan.plan),
        "gaps": list(plan.gaps),
    }


def composition_summary(plan: CompositionPlan) -> dict[str, object]:
    return {
        "schema_version": COMPOSITION_SCHEMA,
        "request_id": plan.request_id,
        "plan_hash": plan.plan_hash,
        "drive_profile": plan.drive_profile,
        "synthetic_master": (str(plan.synthetic["source_id"]) if plan.synthetic else None),
        "peers": {item.instance_id: item.peer_id for item in plan.peers},
        "peer_counters": {item.instance_id: [counter.top_port for counter in item.counters]
                          for item in plan.peers},
        "instances": [item.instance_id for item in plan.instances],
        "targets": [window["target_id"] for window in plan.plan["address_map"]["windows"]],
        "interrupt_sources": plan.interrupt_plan.num_sources,
        "raw_width": int(plan.raw_layout["raw_width"]),
        "gaps": list(plan.gaps),
    }


__all__ = [
    "COMPOSITION_SCHEMA",
    "DEFAULT_DRIVE_PROFILE",
    "MASTER_KINDS",
    "MEMORY_MODEL_32",
    "MEMORY_MODEL_64",
    "STIMULUS_ADDRESS_STRATEGY",
    "SYNTHETIC_CLOCK_PORT",
    "SYNTHETIC_COMPONENT_ID",
    "SYNTHETIC_INSTANCE_ID",
    "SYNTHETIC_MASTER_KIND",
    "SYNTHETIC_MASTER_PORT",
    "SYNTHETIC_MASTER_PROTOCOL",
    "SYNTHETIC_RESET_CONTRACT",
    "SYNTHETIC_SOURCE_ID",
    "CompositionError",
    "CompositionPlan",
    "InstanceComposition",
    "build_composition",
    "composition_document",
    "composition_summary",
]
