// Build a fresh source-like Verilator tree from composition_ir.v1.

#define VL_MT_CONTROL_CODE_UNIT 1

#include "MyFuzzCompositionAstBuilder.h"

#include "V3Ast.h"
#include "V3EmitV.h"
#include "V3Error.h"
#include "V3Global.h"
#include "V3LinkDot.h"
#include "V3LinkLValue.h"
#include "V3LinkParse.h"
#include "V3LinkResolve.h"
#include "V3Width.h"
#include "V3WidthCommit.h"

#include <algorithm>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <tuple>
#include <unordered_map>
#include <utility>

namespace myfuzz {

namespace {

std::mutex s_compositionTreeMutex;
bool s_compositionTreeLive = false;

AstNetlist* bootCompositionTree() {
    const std::lock_guard<std::mutex> lock{s_compositionTreeMutex};
    if (s_compositionTreeLive || v3Global.rootp()) {
        throw std::runtime_error{"composition AST tree is already live"};
    }
    s_compositionTreeLive = true;
    try {
        V3Error::resetSession();
        v3Global.boot();
        return v3Global.rootp();
    } catch (...) {
        if (v3Global.rootp()) v3Global.shutdown();
        s_compositionTreeLive = false;
        throw;
    }
}

void releaseCompositionTree(AstNetlist* rootp) {
    const std::lock_guard<std::mutex> lock{s_compositionTreeMutex};
    if (rootp && v3Global.rootp() == rootp) v3Global.shutdown();
    s_compositionTreeLive = false;
}

}  // namespace

struct CompositionTreeFactory final {
    static std::unique_ptr<CompositionAstTree> make(AstNetlist* rootp,
                                                    AstModule* topModulep) {
        return std::unique_ptr<CompositionAstTree>{
            new CompositionAstTree{rootp, topModulep}};
    }
};

CompositionAstTree::CompositionAstTree(AstNetlist* rootp, AstModule* topModulep)
    : m_rootp{rootp}
    , m_topModulep{topModulep} {}

CompositionAstTree::~CompositionAstTree() { releaseCompositionTree(m_rootp); }

AstNetlist* CompositionAstTree::rootp() const { return m_rootp; }

AstModule* CompositionAstTree::topModulep() const { return m_topModulep; }

namespace {

struct PortInfo final {
    CompositionId id = 0;
    CompositionId componentId = 0;
    CompositionId moduleId = 0;
    CompositionId endpointId = 0;
    std::optional<unsigned> width;
    std::optional<std::string> direction;
    std::optional<bool> signedness;
    bool external = false;
    std::string declarationPath;
};

struct NetPlan final {
    const CompositionNet* netp = nullptr;
    const CompositionAdapter* adapterp = nullptr;
    CompositionId sinkPortId = 0;
    std::string sourceSignal;
    std::string sinkSignal;
    std::optional<unsigned> sourceWidth;
    std::optional<unsigned> sinkWidth;
    std::optional<bool> sourceSignedness;
    std::optional<bool> sinkSignedness;
};

struct VariableArtifact final {
    AstVar* nodep = nullptr;
    CompositionId stableId = 0;
    std::string kind;
    std::optional<unsigned> declaredWidth;
};

struct CellArtifact final {
    AstCell* nodep = nullptr;
    CompositionId instanceId = 0;
};

struct AssignmentArtifact final {
    AstAssignW* nodep = nullptr;
    CompositionId adapterId = 0;
    CompositionId netId = 0;
    CompositionId sinkPortId = 0;
    std::optional<unsigned> sourceWidth;
    std::optional<unsigned> sinkWidth;
};

struct BuildArtifacts final {
    AstModule* topp = nullptr;
    std::vector<CellArtifact> cells;
    std::vector<VariableArtifact> variables;
    std::vector<AssignmentArtifact> assignments;
    std::unordered_map<const AstVar*, CompositionId> portIds;
};

std::string idName(std::string_view prefix, CompositionId id) {
    return std::string{prefix} + std::to_string(id);
}

void addDiagnostic(std::vector<CompositionDiagnostic>& diagnostics, std::string code,
                   std::string path, std::string message,
                   std::vector<CompositionId> relatedIds) {
    std::sort(relatedIds.begin(), relatedIds.end());
    relatedIds.erase(std::unique(relatedIds.begin(), relatedIds.end()), relatedIds.end());
    diagnostics.push_back(
        {std::move(code), std::move(path), std::move(message), std::move(relatedIds)});
}

void sortDiagnostics(std::vector<CompositionDiagnostic>& diagnostics) {
    std::sort(diagnostics.begin(), diagnostics.end(), [](const auto& lhs, const auto& rhs) {
        return std::tie(lhs.path, lhs.code, lhs.relatedIds, lhs.message)
               < std::tie(rhs.path, rhs.code, rhs.relatedIds, rhs.message);
    });
}

bool isValidDirection(const std::string& direction) {
    return direction == "input" || direction == "output" || direction == "inout";
}

VDirection astDirection(const std::optional<std::string>& direction) {
    if (!direction) throw std::logic_error{"composition port direction is unresolved"};
    if (*direction == "input") return VDirection::INPUT;
    if (direction == "output") return VDirection::OUTPUT;
    if (direction == "inout") return VDirection::INOUT;
    throw std::logic_error{"composition port direction is invalid"};
}

std::vector<const CompositionAdapter*> adaptersFor(
    CompositionId sourceEndpointId, CompositionId targetEndpointId,
    const std::vector<CompositionAdapter>& adapters) {
    std::vector<const CompositionAdapter*> matches;
    for (const CompositionAdapter& adapter : adapters) {
        const bool forward = adapter.sourceEndpointId == sourceEndpointId
                             && adapter.targetEndpointId == targetEndpointId;
        const bool reverse = adapter.sourceEndpointId == targetEndpointId
                             && adapter.targetEndpointId == sourceEndpointId;
        if (forward || reverse) {
            matches.push_back(&adapter);
        }
    }
    return matches;
}

using AdapterPlanKey = std::tuple<CompositionId, CompositionId, CompositionId>;

AdapterPlanKey adapterPlanKey(const NetPlan& plan) {
    return {plan.adapterp->edgeId, plan.netp->id, plan.sinkPortId};
}

std::string adapterSignalName(CompositionId edgeId, CompositionId netId,
                              CompositionId sinkPortId) {
    return idName("adapter_", edgeId) + idName("_net_", netId)
           + idName("_sink_", sinkPortId);
}

bool adapterAllowsCdc(const CompositionAdapter* adapterp) {
    return adapterp && adapterp->allowsCdc;
}

void setDirection(PortInfo& port, std::string direction,
                  std::vector<CompositionDiagnostic>& errors, const std::string& path) {
    if (port.direction && *port.direction != direction && *port.direction != "inout") {
        addDiagnostic(errors, "incompatible-direction", path,
                      "connected port direction conflicts with the net endpoint", {port.id});
        return;
    }
    if (!port.direction) port.direction = std::move(direction);
}

struct PreparedComposition final {
    std::map<CompositionId, CompositionComponent> components;
    std::map<CompositionId, CompositionInstance> instances;
    std::map<CompositionId, PortInfo> ports;
    std::map<CompositionId, std::set<CompositionId>> componentClockDomains;
    std::map<CompositionId, std::set<std::tuple<CompositionId, std::string, bool>>>
        componentResetDomains;
    std::vector<NetPlan> nets;
    std::vector<CompositionId> unknownWidthPorts;
    std::vector<CompositionDiagnostic> errors;
};

struct PreparedSourceSymbols final {
    struct Name final {
        std::string internal;
        std::string original;
    };

    std::map<CompositionId, Name> modules;
    std::map<CompositionId, Name> ports;
    std::vector<CompositionDiagnostic> errors;
};

PreparedComposition prepareComposition(const CompositionIr& ir) {
    PreparedComposition prepared;

    std::map<CompositionId, CompositionId> moduleComponents;
    for (std::size_t index = 0; index < ir.components.size(); ++index) {
        const CompositionComponent& component = ir.components[index];
        if (!prepared.components.emplace(component.id, component).second) {
            addDiagnostic(prepared.errors, "duplicate-component", "components",
                          "component ID is declared more than once", {component.id});
        }
        const auto [moduleIt, inserted]
            = moduleComponents.emplace(component.moduleId, component.id);
        if (!inserted && moduleIt->second != component.id) {
            addDiagnostic(prepared.errors, "duplicate-module-representation",
                          "components[" + std::to_string(index) + "].module_id",
                          "module ID is represented by more than one component",
                          {component.moduleId, moduleIt->second, component.id});
        }
    }
    std::map<CompositionId, std::vector<CompositionId>> componentInstances;
    for (std::size_t index = 0; index < ir.instances.size(); ++index) {
        const CompositionInstance& instance = ir.instances[index];
        if (!prepared.instances.emplace(instance.id, instance).second) {
            addDiagnostic(prepared.errors, "duplicate-instance", "instances",
                          "instance ID is declared more than once", {instance.id});
            continue;
        }
        const auto componentIt = prepared.components.find(instance.componentId);
        if (componentIt == prepared.components.end() || componentIt->second.moduleId != instance.moduleId) {
            addDiagnostic(prepared.errors, "undeclared-component",
                          "instances[" + std::to_string(index) + "].component_id",
                          "instance references an undeclared or incompatible component",
                          {instance.id, instance.componentId});
        } else {
            componentInstances[instance.componentId].push_back(instance.id);
        }
    }
    for (const auto& [componentId, component] : prepared.components) {
        (void)component;
        const auto instancesIt = componentInstances.find(componentId);
        if (instancesIt != componentInstances.end() && instancesIt->second.size() == 1) continue;
        std::vector<CompositionId> relatedIds{componentId};
        if (instancesIt != componentInstances.end()) {
            relatedIds.insert(relatedIds.end(), instancesIt->second.begin(),
                              instancesIt->second.end());
        }
        addDiagnostic(prepared.errors, "component-instance-cardinality", "instances",
                      "each component must be represented by exactly one instance",
                      std::move(relatedIds));
    }

    std::set<CompositionId> invalidDirectionPorts;
    auto mergePort = [&](CompositionId portId, CompositionId componentId,
                         CompositionId endpointId, std::optional<unsigned> width,
                         std::optional<std::string> direction,
                         std::optional<bool> signedness, bool external,
                         const std::string& path) {
        if (width
            && (*width == 0
                || *width > static_cast<unsigned>(std::numeric_limits<int>::max()))) {
            addDiagnostic(prepared.errors, "invalid-width", path + ".width",
                          "port width is outside the supported positive integer range",
                          {portId});
            width.reset();
        }
        if (direction && !isValidDirection(*direction)) {
            addDiagnostic(prepared.errors, "invalid-direction", path + ".direction",
                          "port direction must be input, output, or inout", {portId});
            invalidDirectionPorts.insert(portId);
            direction.reset();
        }
        const auto componentIt = prepared.components.find(componentId);
        if (componentIt == prepared.components.end()) {
            addDiagnostic(prepared.errors, "undeclared-component", path,
                          "port references an undeclared component", {portId, componentId});
            return;
        }
        auto [portIt, inserted] = prepared.ports.emplace(
            portId, PortInfo{portId, componentId, componentIt->second.moduleId, endpointId, width,
                             direction, signedness, external, path});
        if (inserted) return;
        PortInfo& existing = portIt->second;
        if (existing.componentId != componentId) {
            addDiagnostic(prepared.errors, "conflicting-port-owner", path,
                          "port ID is declared by more than one component",
                          {portId, existing.componentId, componentId});
            return;
        }
        if (endpointId) {
            if (existing.endpointId && existing.endpointId != endpointId) {
                addDiagnostic(prepared.errors, "conflicting-port-endpoint", path,
                              "port ID is bound to more than one endpoint", {portId});
            } else {
                existing.endpointId = endpointId;
            }
        }
        if (width) {
            if (existing.width && existing.width != width) {
                addDiagnostic(prepared.errors, "conflicting-port-width", path,
                              "port ID has conflicting declared widths", {portId});
            } else {
                existing.width = width;
            }
        }
        if (direction) {
            if (existing.direction && existing.direction != direction) {
                addDiagnostic(prepared.errors, "conflicting-port-direction", path,
                              "port ID has conflicting declared directions", {portId});
            } else {
                existing.direction = std::move(direction);
            }
        }
        if (signedness.has_value()) {
            if (existing.signedness.has_value()
                && existing.signedness != signedness) {
                addDiagnostic(prepared.errors, "conflicting-port-signedness", path,
                              "port ID has conflicting declared signedness", {portId});
            } else {
                existing.signedness = signedness;
            }
        }
        existing.external = existing.external || external;
    };

    std::set<CompositionId> endpointIds;
    for (std::size_t bindingIndex = 0; bindingIndex < ir.endpointBindings.size();
         ++bindingIndex) {
        const CompositionEndpointBinding& binding = ir.endpointBindings[bindingIndex];
        const std::string bindingPath
            = "endpoint_bindings[" + std::to_string(bindingIndex) + "]";
        if (!endpointIds.insert(binding.endpointId).second) {
            addDiagnostic(prepared.errors, "duplicate-endpoint", bindingPath + ".endpoint_id",
                          "endpoint ID is declared more than once", {binding.endpointId});
        }
        if (!prepared.components.count(binding.componentId)) {
            addDiagnostic(prepared.errors, "undeclared-component",
                          bindingPath + ".component_id",
                          "endpoint binding references an undeclared component",
                          {binding.endpointId, binding.componentId});
        }
        std::set<CompositionId> fieldPortIds;
        for (std::size_t fieldIndex = 0; fieldIndex < binding.fields.size(); ++fieldIndex) {
            const CompositionEndpointField& field = binding.fields[fieldIndex];
            const std::string fieldPath = bindingPath + ".fields["
                                          + std::to_string(fieldIndex) + "]";
            if (!fieldPortIds.insert(field.portId).second) {
                addDiagnostic(prepared.errors, "duplicate-endpoint-field",
                              fieldPath + ".port_id",
                              "port ID is declared more than once in one endpoint binding",
                              {binding.endpointId, field.portId});
            }
            mergePort(field.portId, binding.componentId, binding.endpointId, field.width,
                      field.direction, field.signedness, false, fieldPath);
        }
    }

    std::set<CompositionId> adapterIds;
    for (std::size_t index = 0; index < ir.adapters.size(); ++index) {
        const CompositionAdapter& adapter = ir.adapters[index];
        const std::string adapterPath = "adapters[" + std::to_string(index) + "]";
        if (!adapterIds.insert(adapter.edgeId).second) {
            addDiagnostic(prepared.errors, "duplicate-adapter", adapterPath + ".edge_id",
                          "adapter edge ID is declared more than once", {adapter.edgeId});
        }
        std::vector<CompositionId> missingEndpoints;
        if (!endpointIds.count(adapter.sourceEndpointId)) {
            missingEndpoints.push_back(adapter.sourceEndpointId);
        }
        if (!endpointIds.count(adapter.targetEndpointId)) {
            missingEndpoints.push_back(adapter.targetEndpointId);
        }
        if (!missingEndpoints.empty()) {
            missingEndpoints.push_back(adapter.edgeId);
            addDiagnostic(prepared.errors, "undeclared-adapter-endpoint", adapterPath,
                          "adapter references an undeclared endpoint",
                          std::move(missingEndpoints));
        }
    }

    auto mergeDomainPorts = [&](const std::vector<CompositionDomain>& domains,
                                std::string_view section) {
        for (std::size_t index = 0; index < domains.size(); ++index) {
            const CompositionDomain& domain = domains[index];
            mergePort(domain.portId, domain.componentId, 0, 1, "input", std::nullopt,
                      false,
                      std::string{section} + "[" + std::to_string(index) + "]");
        }
    };
    mergeDomainPorts(ir.clockDomains, "clock_domains");
    mergeDomainPorts(ir.resetDomains, "reset_domains");
    for (const CompositionDomain& domain : ir.clockDomains) {
        prepared.componentClockDomains[domain.componentId].insert(domain.domainId);
    }
    for (const CompositionDomain& domain : ir.resetDomains) {
        prepared.componentResetDomains[domain.componentId].emplace(
            domain.domainId, domain.activeLevel, domain.synchronous);
    }

    std::set<CompositionId> externalPortIds;
    for (std::size_t index = 0; index < ir.externalPorts.size(); ++index) {
        const CompositionExternalPort& external = ir.externalPorts[index];
        if (!externalPortIds.insert(external.portId).second) {
            addDiagnostic(prepared.errors, "duplicate-external-port",
                          "external_ports[" + std::to_string(index) + "].port_id",
                          "external port ID is declared more than once", {external.portId});
        }
        mergePort(external.portId, external.componentId, 0, external.width, external.direction,
                  external.signedness, true,
                  "external_ports[" + std::to_string(index) + "]");
    }

    std::set<CompositionId> drivenPorts;
    std::set<CompositionId> netIds;
    std::map<CompositionId, CompositionId> sourceNets;
    std::set<CompositionId> unknownWidths;
    for (std::size_t index = 0; index < ir.nets.size(); ++index) {
        const CompositionNet& net = ir.nets[index];
        const std::string netPath = "nets[" + std::to_string(index) + "]";
        if (!netIds.insert(net.id).second) {
            addDiagnostic(prepared.errors, "duplicate-net", netPath + ".id",
                          "net ID is declared more than once", {net.id});
            continue;
        }
        if (net.sinkPortIds.empty()) {
            addDiagnostic(prepared.errors, "missing-net-sink", netPath + ".sink_port_ids",
                          "net must declare at least one sink port", {net.id});
            continue;
        }
        if (net.width
            && (*net.width == 0
                || *net.width > static_cast<unsigned>(std::numeric_limits<int>::max()))) {
            addDiagnostic(prepared.errors, "invalid-width", netPath + ".width",
                          "net width is outside the supported positive integer range",
                          {net.id});
            continue;
        }
        const auto sourceIt = prepared.ports.find(net.sourcePortId);
        if (sourceIt == prepared.ports.end()) {
            addDiagnostic(prepared.errors, "undeclared-port", netPath + ".source_port_id",
                          "net references an undeclared source port", {net.sourcePortId});
            continue;
        }
        if (net.width) {
            if (!sourceIt->second.width) {
                sourceIt->second.width = net.width;
            } else if (sourceIt->second.width != net.width) {
                addDiagnostic(prepared.errors, "incompatible-width", netPath + ".width",
                              "net width conflicts with its source port width",
                              {net.id, sourceIt->second.id});
                continue;
            }
        }
        const auto [sourceNetIt, inserted]
            = sourceNets.emplace(net.sourcePortId, net.id);
        if (!inserted && sourceNetIt->second != net.id) {
            addDiagnostic(prepared.errors, "source-port-multiple-nets",
                          netPath + ".source_port_id",
                          "source port is assigned to more than one distinct net",
                          {net.sourcePortId, sourceNetIt->second, net.id});
            continue;
        }
        setDirection(sourceIt->second, "output", prepared.errors,
                     netPath + ".source_port_id");

        for (std::size_t sinkIndex = 0; sinkIndex < net.sinkPortIds.size(); ++sinkIndex) {
            const CompositionId sinkId = net.sinkPortIds[sinkIndex];
            const std::string sinkPath = netPath + ".sink_port_ids["
                                         + std::to_string(sinkIndex) + "]";
            const auto sinkIt = prepared.ports.find(sinkId);
            if (sinkIt == prepared.ports.end()) {
                addDiagnostic(prepared.errors, "undeclared-port", sinkPath,
                              "net references an undeclared sink port", {sinkId});
                continue;
            }
            setDirection(sinkIt->second, "input", prepared.errors, sinkPath);
            if (!drivenPorts.insert(sinkId).second) {
                addDiagnostic(prepared.errors, "multiple-drivers", sinkPath,
                              "sink port is driven by more than one net", {sinkId});
                continue;
            }

            const std::vector<const CompositionAdapter*> matchingAdapters
                = adaptersFor(sourceIt->second.endpointId, sinkIt->second.endpointId, ir.adapters);
            if (matchingAdapters.size() > 1) {
                std::vector<CompositionId> relatedIds{sourceIt->second.endpointId,
                                                      sinkIt->second.endpointId};
                for (const CompositionAdapter* const adapterp : matchingAdapters) {
                    relatedIds.push_back(adapterp->edgeId);
                }
                addDiagnostic(prepared.errors, "ambiguous-adapter", sinkPath,
                              "connection endpoint pair matches more than one declared adapter",
                              std::move(relatedIds));
                continue;
            }
            const CompositionAdapter* const adapterp
                = matchingAdapters.empty() ? nullptr : matchingAdapters.front();
            if (net.width && !sinkIt->second.width) sinkIt->second.width = net.width;
            const std::optional<unsigned> sourceWidth = sourceIt->second.width;
            const std::optional<unsigned> sinkWidth = sinkIt->second.width;
            if (sourceWidth && sinkWidth && sourceWidth != sinkWidth && !adapterp) {
                addDiagnostic(prepared.errors, "incompatible-width", sinkPath,
                              "connected ports have incompatible declared widths and no adapter",
                              {sourceIt->second.id, sinkIt->second.id});
                continue;
            }

            const auto sourceClockDomains
                = prepared.componentClockDomains.find(sourceIt->second.componentId);
            const auto sinkClockDomains
                = prepared.componentClockDomains.find(sinkIt->second.componentId);
            const bool sourceHasClock = sourceClockDomains != prepared.componentClockDomains.end()
                                        && !sourceClockDomains->second.empty();
            const bool sinkHasClock = sinkClockDomains != prepared.componentClockDomains.end()
                                      && !sinkClockDomains->second.empty();
            const bool incompatibleClock
                = sourceHasClock != sinkHasClock
                  || (sourceHasClock && sourceClockDomains->second != sinkClockDomains->second);
            if (incompatibleClock && !adapterAllowsCdc(adapterp)) {
                addDiagnostic(prepared.errors, "undeclared-cdc", sinkPath,
                              "connection crosses declared clock domains without a CDC adapter",
                              {sourceIt->second.componentId, sinkIt->second.componentId});
                continue;
            }

            const auto sourceResetDomains
                = prepared.componentResetDomains.find(sourceIt->second.componentId);
            const auto sinkResetDomains
                = prepared.componentResetDomains.find(sinkIt->second.componentId);
            const bool sourceHasReset = sourceResetDomains != prepared.componentResetDomains.end()
                                        && !sourceResetDomains->second.empty();
            const bool sinkHasReset = sinkResetDomains != prepared.componentResetDomains.end()
                                      && !sinkResetDomains->second.empty();
            const bool incompatibleReset
                = sourceHasReset != sinkHasReset
                  || (sourceHasReset && sourceResetDomains->second != sinkResetDomains->second);
            if (incompatibleReset) {
                addDiagnostic(prepared.errors, "incompatible-reset-domain", sinkPath,
                              "connected components have incompatible declared reset domains",
                              {sourceIt->second.componentId, sinkIt->second.componentId});
                continue;
            }

            const std::string netSignal = idName("net_", net.id);
            const std::string sinkSignal
                = adapterp ? adapterSignalName(adapterp->edgeId, net.id, sinkId) : netSignal;
            prepared.nets.push_back(
                {&net, adapterp, sinkId, netSignal, sinkSignal, sourceWidth, sinkWidth,
                 sourceIt->second.signedness, sinkIt->second.signedness});
        }
    }

    for (const auto& [portId, port] : prepared.ports) {
        if (!port.width) unknownWidths.insert(portId);
        if (!port.direction && !invalidDirectionPorts.count(portId)) {
            addDiagnostic(prepared.errors, "missing-direction", port.declarationPath + ".direction",
                          "port direction cannot be resolved from its declaration or connections",
                          {portId});
        }
    }
    prepared.unknownWidthPorts.assign(unknownWidths.begin(), unknownWidths.end());
    sortDiagnostics(prepared.errors);
    return prepared;
}

PreparedSourceSymbols prepareSourceSymbols(
    const PreparedComposition& prepared,
    const std::vector<CompositionSourceSymbol>& sourceSymbols) {
    PreparedSourceSymbols result;
    std::set<std::pair<std::string, CompositionId>> seen;
    for (std::size_t index = 0; index < sourceSymbols.size(); ++index) {
        const CompositionSourceSymbol& symbol = sourceSymbols[index];
        const std::string path = "source_symbols[" + std::to_string(index) + "]";
        if (!seen.emplace(symbol.kind, symbol.entityId).second) {
            addDiagnostic(result.errors, "duplicate-source-symbol", path,
                          "source symbol kind and entity ID are declared more than once",
                          {symbol.entityId});
            continue;
        }
        const auto invalidName = [](const std::string& name) {
            return name.empty()
                   || std::any_of(name.begin(), name.end(), [](unsigned char value) {
                          return value == 0 || value == '\n' || value == '\r';
                      });
        };
        if (invalidName(symbol.name)) {
            addDiagnostic(result.errors, "invalid-source-symbol", path + ".name",
                          "source symbol is not a legal single-line identifier",
                          {symbol.entityId});
            continue;
        }
        if (invalidName(symbol.originalName)) {
            addDiagnostic(result.errors, "invalid-source-symbol", path + ".original_name",
                          "original source symbol is not a re-emittable single-line identifier",
                          {symbol.entityId});
            continue;
        }
        const PreparedSourceSymbols::Name name{symbol.name, symbol.originalName};
        if (symbol.kind == "module") {
            result.modules.emplace(symbol.entityId, name);
        } else if (symbol.kind == "port") {
            result.ports.emplace(symbol.entityId, name);
        }
    }

    std::map<std::string, CompositionId> moduleNames;
    for (const auto& [componentId, component] : prepared.components) {
        (void)componentId;
        const auto found = result.modules.find(component.moduleId);
        if (found == result.modules.end()) {
            addDiagnostic(result.errors, "missing-source-symbol", "source_symbols",
                          "emitter source map does not contain a component module",
                          {component.moduleId});
            continue;
        }
        const auto [nameIt, inserted]
            = moduleNames.emplace(found->second.internal, component.moduleId);
        if (!inserted && nameIt->second != component.moduleId) {
            addDiagnostic(result.errors, "duplicate-source-name", "source_symbols",
                          "different module IDs resolve to the same source symbol",
                          {nameIt->second, component.moduleId});
        }
    }
    std::map<std::pair<CompositionId, std::string>, CompositionId> portNames;
    for (const auto& [portId, port] : prepared.ports) {
        const auto found = result.ports.find(portId);
        if (found == result.ports.end()) {
            addDiagnostic(result.errors, "missing-source-symbol", "source_symbols",
                          "emitter source map does not contain a component port", {portId});
            continue;
        }
        const auto key = std::make_pair(port.moduleId, found->second.internal);
        const auto [nameIt, inserted] = portNames.emplace(key, portId);
        if (!inserted && nameIt->second != portId) {
            addDiagnostic(result.errors, "duplicate-source-name", "source_symbols",
                          "different port IDs in one module resolve to the same source symbol",
                          {nameIt->second, portId});
        }
    }
    sortDiagnostics(result.errors);
    return result;
}

AstVar* makeVariable(FileLine* filelinep, VVarType type, const std::string& name,
                     std::optional<unsigned> width, std::optional<std::string> direction,
                     bool signedness) {
    AstVar* const varp
        = new AstVar{filelinep, type, name, VFlagLogicPacked{}, static_cast<int>(width.value_or(1))};
    varp->dtypeSetLogicSized(static_cast<int>(width.value_or(1)),
                             VSigning::fromBool(signedness));
    if (direction) {
        const VDirection astDir = astDirection(direction);
        varp->direction(astDir);
        varp->declDirection(astDir);
        varp->ansi(true);
    }
    return varp;
}

class AstInventoryVisitor final : public VNVisitorConst {
    CompositionAstNodeCounts& m_counts;

    void visit(AstModule* nodep) override {
        ++m_counts.modules;
        iterateChildrenConst(nodep);
    }
    void visit(AstCell* nodep) override {
        ++m_counts.cells;
        iterateChildrenConst(nodep);
    }
    void visit(AstVar* nodep) override {
        ++m_counts.variables;
        iterateChildrenConst(nodep);
    }
    void visit(AstPin* nodep) override {
        ++m_counts.pins;
        iterateChildrenConst(nodep);
    }
    void visit(AstVarRef* nodep) override {
        ++m_counts.variableReferences;
        iterateChildrenConst(nodep);
    }
    void visit(AstAssignW* nodep) override {
        ++m_counts.wireAssignments;
        iterateChildrenConst(nodep);
    }
    void visit(AstNode* nodep) override { iterateChildrenConst(nodep); }

public:
    AstInventoryVisitor(AstNetlist* rootp, CompositionAstNodeCounts& counts)
        : m_counts{counts} {
        iterateConst(rootp);
    }
};

BuildArtifacts constructTree(const PreparedComposition& prepared,
                             const PreparedSourceSymbols& sourceSymbols) {
    BuildArtifacts artifacts;
    AstNetlist* const rootp = v3Global.rootp();
    FileLine* const filelinep = rootp->fileline();
    AstModule* const topp = new AstModule{filelinep, "composition_top", "work"};
    topp->depth(1);
    topp->level(1);
    topp->modPublic(true);
    rootp->resolvedTopModuleName(topp->name());
    rootp->addModulesp(topp);
    artifacts.topp = topp;

    std::map<CompositionId, AstModule*> modules;
    std::map<std::pair<CompositionId, CompositionId>, AstVar*> modulePorts;
    for (const auto& [componentId, component] : prepared.components) {
        (void)componentId;
        if (modules.count(component.moduleId)) continue;
        const PreparedSourceSymbols::Name& moduleName
            = sourceSymbols.modules.at(component.moduleId);
        AstModule* const modulep = new AstModule{filelinep, moduleName.original, "work"};
        modulep->name(moduleName.internal);
        modulep->depth(2);
        modulep->level(2);
        modules.emplace(component.moduleId, modulep);
        rootp->addModulesp(modulep);
    }

    std::map<std::pair<CompositionId, CompositionId>, int> modulePinNumbers;
    std::map<CompositionId, int> nextModulePin;
    for (const auto& [portId, port] : prepared.ports) {
        AstModule* const modulep = modules.at(port.moduleId);
        const int pinNumber = ++nextModulePin[port.moduleId];
        const PreparedSourceSymbols::Name& portName = sourceSymbols.ports.at(portId);
        modulep->addStmtsp(new AstPort{filelinep, pinNumber, portName.internal});
        modulePinNumbers.emplace(std::make_pair(port.moduleId, portId), pinNumber);
    }
    for (const auto& [portId, port] : prepared.ports) {
        AstModule* const modulep = modules.at(port.moduleId);
        const PreparedSourceSymbols::Name& portName = sourceSymbols.ports.at(portId);
        AstVar* const portp = makeVariable(filelinep, VVarType::PORT, portName.internal,
                                           port.width, port.direction,
                                           port.signedness.value_or(false));
        portp->origName(portName.original);
        portp->pinNum(modulePinNumbers.at({port.moduleId, portId}));
        modulep->addStmtsp(portp);
        modulePorts.emplace(std::make_pair(port.moduleId, portId), portp);
        artifacts.portIds.emplace(portp, portId);
    }

    std::map<CompositionId, AstVar*> sourceSignals;
    std::map<AdapterPlanKey, AstVar*> sinkSignals;
    for (const NetPlan& plan : prepared.nets) {
        const CompositionId netId = plan.netp->id;
        if (!sourceSignals.count(netId)) {
            AstVar* const netp = makeVariable(filelinep, VVarType::WIRE, plan.sourceSignal,
                                              plan.sourceWidth, std::nullopt,
                                              plan.sourceSignedness.value_or(false));
            topp->addStmtsp(netp);
            sourceSignals.emplace(netId, netp);
            artifacts.variables.push_back({netp, netId, "net", plan.sourceWidth});
        }
        if (plan.adapterp) {
            const CompositionId adapterId = plan.adapterp->edgeId;
            const AdapterPlanKey key = adapterPlanKey(plan);
            if (!sinkSignals.count(key)) {
                AstVar* const adapterVarp
                    = makeVariable(filelinep, VVarType::WIRE, plan.sinkSignal, plan.sinkWidth,
                                   std::nullopt, plan.sinkSignedness.value_or(false));
                topp->addStmtsp(adapterVarp);
                sinkSignals.emplace(key, adapterVarp);
                artifacts.variables.push_back(
                    {adapterVarp, adapterId, "adapter", plan.sinkWidth});
                AstNodeExpr* sourceExprp
                    = new AstVarRef{filelinep, sourceSignals.at(netId), VAccess::READ};
                if (plan.sourceWidth && plan.sinkWidth
                    && plan.sourceWidth != plan.sinkWidth) {
                    if (*plan.sourceWidth > *plan.sinkWidth) {
                        sourceExprp = new AstSel{filelinep, sourceExprp, 0,
                                                static_cast<int>(*plan.sinkWidth)};
                    } else {
                        sourceExprp = new AstExtend{filelinep, sourceExprp,
                                                   static_cast<int>(*plan.sinkWidth)};
                    }
                }
                AstAssignW* const assignp = new AstAssignW{
                    filelinep, new AstVarRef{filelinep, adapterVarp, VAccess::WRITE},
                    sourceExprp};
                topp->addStmtsp(assignp);
                artifacts.assignments.push_back(
                    {assignp, adapterId, netId, plan.sinkPortId, plan.sourceWidth, plan.sinkWidth});
            }
        }
    }

    std::map<CompositionId, AstVar*> externalSignals;
    std::map<CompositionId, int> externalPinNumbers;
    int nextExternalPin = 0;
    for (const auto& [portId, port] : prepared.ports) {
        if (!port.external) continue;
        const int pinNumber = ++nextExternalPin;
        topp->addStmtsp(
            new AstPort{filelinep, pinNumber, idName("external_", portId)});
        externalPinNumbers.emplace(portId, pinNumber);
    }
    for (const auto& [portId, port] : prepared.ports) {
        if (!port.external) continue;
        AstVar* const externalp
            = makeVariable(filelinep, VVarType::PORT, idName("external_", portId), port.width,
                           port.direction, port.signedness.value_or(false));
        externalp->pinNum(externalPinNumbers.at(portId));
        externalp->primaryIO(true);
        topp->addStmtsp(externalp);
        externalSignals.emplace(portId, externalp);
        artifacts.variables.push_back({externalp, portId, "external_port", port.width});
    }

    std::map<CompositionId, AstVar*> connectedSignals;
    for (const NetPlan& plan : prepared.nets) {
        connectedSignals[plan.netp->sourcePortId] = sourceSignals.at(plan.netp->id);
        connectedSignals[plan.sinkPortId]
            = plan.adapterp ? sinkSignals.at(adapterPlanKey(plan))
                            : sourceSignals.at(plan.netp->id);
    }
    for (const auto& [portId, signalp] : externalSignals) {
        connectedSignals.emplace(portId, signalp);
    }

    for (const auto& [instanceId, instance] : prepared.instances) {
        AstModule* const modulep = modules.at(instance.moduleId);
        AstCell* const cellp = new AstCell{filelinep, filelinep, idName("instance_", instanceId),
                                           modulep->name(), nullptr, nullptr, nullptr};
        cellp->modp(modulep);
        topp->addStmtsp(cellp);
        artifacts.cells.push_back({cellp, instanceId});

        for (const auto& [portId, port] : prepared.ports) {
            if (port.componentId != instance.componentId) continue;
            const auto signalIt = connectedSignals.find(portId);
            if (signalIt == connectedSignals.end()) continue;
            AstVar* const modulePortp = modulePorts.at({port.moduleId, portId});
            const VAccess access
                = astDirection(port.direction).isWritable() ? VAccess::WRITE : VAccess::READ;
            AstPin* const pinp = new AstPin{
                filelinep, modulePortp->pinNum(), modulePortp->name(),
                new AstVarRef{filelinep, signalIt->second, access}};
            pinp->modVarp(modulePortp);
            cellp->addPinsp(pinp);
        }
    }
    return artifacts;
}

void runCompositionPasses(AstNetlist* rootp) {
    V3LinkParse::linkParse(rootp);
    V3LinkDot::linkDotPrimary(rootp);
    rootp->checkTree();
    V3LinkResolve::linkResolve(rootp);
    V3LinkLValue::linkLValue(rootp);
    V3Error::abortIfErrors();
    V3Width::width(rootp);
    V3Error::abortIfErrors();
    V3WidthCommit::widthCommit(rootp);
    v3Global.assertDTypesResolved(true);
    v3Global.widthMinUsage(VWidthMinUsage::MATCHES_WIDTH);
    rootp->checkTree();
}

CompositionAstSnapshot snapshotTree(AstNetlist* rootp, const BuildArtifacts& artifacts) {
    CompositionAstSnapshot snapshot;
    AstInventoryVisitor inventory{rootp, snapshot.nodeCounts};

    for (const VariableArtifact& artifact : artifacts.variables) {
        if (!artifact.nodep) {
            throw std::runtime_error{"composition AST variable was not retained"};
        }
        snapshot.variables.push_back(
            {artifact.stableId, artifact.nodep->name(), artifact.kind, artifact.declaredWidth});
    }
    std::sort(snapshot.variables.begin(), snapshot.variables.end(), [](const auto& lhs, const auto& rhs) {
        const auto rank = [](const std::string& kind) {
            if (kind == "net") return 0;
            if (kind == "external_port") return 1;
            return 2;
        };
        return std::make_tuple(rank(lhs.kind), lhs.stableId, lhs.name)
               < std::make_tuple(rank(rhs.kind), rhs.stableId, rhs.name);
    });

    for (const CellArtifact& artifact : artifacts.cells) {
        if (!artifact.nodep || !artifact.nodep->modp()) {
            throw std::runtime_error{"composition AST cell was not linked"};
        }
        CompositionAstCell cell;
        cell.instanceId = artifact.instanceId;
        cell.name = artifact.nodep->name();
        cell.module = artifact.nodep->modp()->name();
        for (AstPin* pinp = artifact.nodep->pinsp(); pinp;
             pinp = VN_AS(pinp->nextp(), Pin)) {
            const auto portIt = artifacts.portIds.find(pinp->modVarp());
            AstVarRef* const refp = VN_CAST(pinp->exprp(), VarRef);
            if (portIt == artifacts.portIds.end() || !refp || !refp->varp()) {
                throw std::runtime_error{"composition AST pin was not linked to a variable"};
            }
            cell.pins.push_back({portIt->second, refp->varp()->name()});
        }
        std::sort(cell.pins.begin(), cell.pins.end(), [](const auto& lhs, const auto& rhs) {
            return std::tie(lhs.portId, lhs.signal) < std::tie(rhs.portId, rhs.signal);
        });
        snapshot.cells.push_back(std::move(cell));
    }
    std::sort(snapshot.cells.begin(), snapshot.cells.end(), [](const auto& lhs, const auto& rhs) {
        return std::tie(lhs.instanceId, lhs.name) < std::tie(rhs.instanceId, rhs.name);
    });

    for (const AssignmentArtifact& artifact : artifacts.assignments) {
        if (!artifact.nodep) {
            throw std::runtime_error{"composition adapter was not retained as AstAssignW"};
        }
        AstVarRef* const lhsp = VN_CAST(artifact.nodep->lhsp(), VarRef);
        AstNodeExpr* rhsExprp = artifact.nodep->rhsp();
        if (AstSel* const selp = VN_CAST(rhsExprp, Sel)) rhsExprp = selp->fromp();
        if (AstExtend* const extendp = VN_CAST(rhsExprp, Extend)) {
            rhsExprp = extendp->lhsp();
        }
        AstVarRef* const rhsp = VN_CAST(rhsExprp, VarRef);
        if (!lhsp || !rhsp || !lhsp->varp() || !rhsp->varp()) {
            throw std::runtime_error{"composition adapter assignment is unresolved"};
        }
        snapshot.assignments.push_back(
            {artifact.adapterId, lhsp->varp()->name(), rhsp->varp()->name(),
             artifact.sourceWidth, artifact.sinkWidth});
    }
    std::sort(snapshot.assignments.begin(), snapshot.assignments.end(),
              [](const auto& lhs, const auto& rhs) {
                  return std::tie(lhs.adapterId, lhs.lhs, lhs.rhs)
                         < std::tie(rhs.adapterId, rhs.lhs, rhs.rhs);
              });
    return snapshot;
}

CompositionValidation validateTree(const CompositionAstSnapshot& snapshot,
                                   const PreparedComposition& prepared) {
    CompositionValidation validation;
    std::set<CompositionId> moduleIds;
    for (const auto& [componentId, component] : prepared.components) {
        (void)componentId;
        moduleIds.insert(component.moduleId);
    }
    validation.link = snapshot.nodeCounts.modules >= moduleIds.size() + 1
                      && snapshot.nodeCounts.cells == prepared.instances.size();
    std::size_t expectedPins = 0;
    for (const CompositionAstCell& cell : snapshot.cells) expectedPins += cell.pins.size();
    validation.pin = validation.link && snapshot.nodeCounts.pins == expectedPins
                     && snapshot.nodeCounts.variableReferences
                            == expectedPins + 2 * snapshot.nodeCounts.wireAssignments;
    validation.dtype = validation.pin;
    validation.unknownWidthPorts = prepared.unknownWidthPorts;
    validation.width = validation.dtype && validation.unknownWidthPorts.empty();
    return validation;
}

}  // namespace

CompositionBuildResult buildCompositionAst(
    const CompositionIr& ir, const std::vector<CompositionSourceSymbol>& sourceSymbols) {
    CompositionBuildResult result;
    PreparedComposition prepared = prepareComposition(ir);
    result.validation.unknownWidthPorts = prepared.unknownWidthPorts;
    if (!prepared.errors.empty()) {
        result.errors = std::move(prepared.errors);
        return result;
    }
    if (!prepared.unknownWidthPorts.empty()) return result;

    PreparedSourceSymbols preparedSymbols
        = prepareSourceSymbols(prepared, sourceSymbols);
    if (!preparedSymbols.errors.empty()) {
        result.errors = std::move(preparedSymbols.errors);
        return result;
    }

    AstNetlist* const rootp = bootCompositionTree();
    try {
        v3Global.assertDTypesResolved(false);
        BuildArtifacts artifacts = constructTree(prepared, preparedSymbols);
        runCompositionPasses(rootp);
        result.ast = snapshotTree(rootp, artifacts);
        result.validation = validateTree(result.ast, prepared);
        std::ostringstream emitted;
        V3EmitV::verilogForTree(artifacts.topp, emitted);
        result.sourceText = emitted.str();
        result.tree = CompositionTreeFactory::make(rootp, artifacts.topp);
        return result;
    } catch (...) {
        releaseCompositionTree(rootp);
        throw;
    }
}

CompositionBuildResult buildCompositionAst(const CompositionIr& ir) {
    return buildCompositionAst(ir, {});
}

}  // namespace myfuzz
