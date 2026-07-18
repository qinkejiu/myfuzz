"""Evidence-gated planning from the shared RTL analysis into SystemIR v1."""

from __future__ import annotations

from dataclasses import dataclass, replace

from .contracts import SystemIR, adapt_legacy_plan
from .discovery import DiscoveredInstance, DiscoveredModule, DiscoveredPort, DiscoveryResult
from .input_model import AddressMode, AddressRequest, InputValidationError, ModuleKind, SystemSpec
from .planner import SystemPlan, plan_system
from .profiles import InterfaceRole, ProfileRegistry
from .rtl_analysis import EvidenceState, RTLAnalysis, RTLModule


@dataclass(frozen=True)
class AnalyzedSystemPlan:
    analysis_manifest_digest: str
    system_ir: SystemIR
    plan: SystemPlan


def plan_analyzed_system(
    spec: SystemSpec,
    analysis: RTLAnalysis,
    registry: ProfileRegistry | None = None,
) -> AnalyzedSystemPlan:
    """Plan only after all critical RTL facts are proven by the Verilator AST."""
    declared = {module.name: module for module in spec.modules}
    analyzed: dict[str, RTLModule] = {}
    for module in analysis.modules:
        if module.original_name in declared:
            key = module.original_name
        elif module.name in declared:
            key = module.name
        else:
            continue
        if key in analyzed:
            raise InputValidationError(
                f"{key}: multiple parameter-specialized elaborated modules require an explicit instance mapping"
            )
        analyzed[key] = module
    missing = sorted(set(declared) - set(analyzed))
    if missing:
        raise InputValidationError(f"declared module(s) absent from Verilator analysis: {', '.join(missing)}")

    protocols = {
        interface.protocol
        for module in spec.modules
        for interface in module.interfaces
    }
    if len(protocols) > 1:
        raise InputValidationError(
            f"v1 does not support mixed protocols: {', '.join(sorted(protocols))}"
        )
    initiators = [
        (module.name, interface.name)
        for module in spec.modules
        for interface in module.interfaces
        if _role(interface.role) is InterfaceRole.INITIATOR
    ]
    if len(initiators) != 1:
        names = ", ".join(f"{module}.{interface}" for module, interface in initiators) or "none"
        raise InputValidationError(f"v1 requires exactly one protocol initiator; found {names}")

    discovered_modules: list[DiscoveredModule] = []
    for module_spec in spec.modules:
        module = analyzed[module_spec.name]
        by_name = {port.name: port for port in module.ports}
        critical = set(module_spec.ports)
        critical.update(port for interface in module_spec.interfaces for port in interface.ports.values())
        for port_name in sorted(critical):
            port = by_name.get(port_name)
            if port is None:
                raise InputValidationError(
                    f"{module_spec.name}.{port_name}: critical port is absent from Verilator analysis"
                )
            if port.evidence.state is not EvidenceState.KNOWN:
                analysis.require_provable(
                    "protocol planning", module=module.name, signals=(port_name,),
                )
                raise InputValidationError(
                    f"{module_spec.name}.{port_name}: critical fact is {port.evidence.state.value}"
                )
        discovered_modules.append(DiscoveredModule(
            module_spec.name,
            module.source_file,
            module_spec.source_set,
            dict(module.parameters),
            tuple(
                DiscoveredPort(port.name, port.direction, port.width, None)
                for port in module.ports
            ),
            tuple(
                DiscoveredInstance(instance.name, instance.module_type)
                for instance in module.instances
            ),
            module.top,
            "Verilator elaborated hierarchy",
        ))
    discovery = DiscoveryResult(
        tuple(sorted({module.source_file for module in analysis.modules})),
        tuple(sorted(discovered_modules, key=lambda module: module.name)),
    )
    planning_spec = _with_inferred_memory_windows(spec, analyzed, registry)
    plan = plan_system(planning_spec, discovery, registry)
    if not plan.valid:
        raise InputValidationError("analyzed system plan is invalid: " + "; ".join(plan.validation_issues))
    return AnalyzedSystemPlan(analysis.manifest_digest, adapt_legacy_plan(plan), plan)


def _role(value: str) -> InterfaceRole:
    try:
        return InterfaceRole(value)
    except ValueError as exc:
        raise InputValidationError(f"unsupported interface role {value!r}") from exc


def _with_inferred_memory_windows(
    spec: SystemSpec,
    analyzed: dict[str, RTLModule],
    registry: ProfileRegistry | None,
) -> SystemSpec:
    memory_kinds = {ModuleKind.MEMORY, ModuleKind.ROM, ModuleKind.RAM}
    modules = []
    effective_registry = registry
    if effective_registry is None:
        from .builtin_profiles import builtin_profile_registry
        effective_registry = builtin_profile_registry()
    for module_spec in spec.modules:
        if module_spec.kind not in memory_kinds or module_spec.address is not None:
            modules.append(module_spec)
            continue
        memories = analyzed[module_spec.name].memories
        if len(memories) != 1:
            raise InputValidationError(
                f"{module_spec.name}: RAM address size requires exactly one proven fixed memory; "
                f"found {len(memories)}"
            )
        memory = memories[0]
        if memory.evidence.state is not EvidenceState.KNOWN:
            raise InputValidationError(
                f"{module_spec.name}.{memory.name}: memory shape is {memory.evidence.state.value}"
            )
        if memory.word_width % 8:
            raise InputValidationError(
                f"{module_spec.name}.{memory.name}: {memory.word_width}-bit words cannot define a byte address window"
            )
        size = memory.depth * (memory.word_width // 8)
        alignment = None
        target_interfaces = [item for item in module_spec.interfaces if _role(item.role) is InterfaceRole.TARGET]
        if len(target_interfaces) == 1:
            profiles = effective_registry.query(target_interfaces[0].protocol, InterfaceRole.TARGET)
            if profiles and profiles[0].address_rule:
                alignment = profiles[0].address_rule.alignment
        modules.append(replace(
            module_spec,
            address=AddressRequest(AddressMode.AUTO, size, None, alignment),
        ))
    return replace(spec, modules=tuple(modules))
