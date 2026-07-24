#ifndef MYFUZZ_COMPOSITION_AST_BUILDER_H_
#define MYFUZZ_COMPOSITION_AST_BUILDER_H_

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

class AstNetlist;
class AstModule;

namespace myfuzz {

using CompositionId = std::uint64_t;

struct CompositionComponent final {
    CompositionId id = 0;
    CompositionId moduleId = 0;
};

struct CompositionInstance final {
    CompositionId id = 0;
    CompositionId componentId = 0;
    CompositionId moduleId = 0;
};

struct CompositionEndpointField final {
    std::string role;
    CompositionId portId = 0;
    std::optional<unsigned> width;
    std::optional<std::string> direction;
    bool signedness = false;
};

struct CompositionEndpointBinding final {
    CompositionId endpointId = 0;
    CompositionId componentId = 0;
    std::vector<CompositionEndpointField> fields;
};

struct CompositionNet final {
    CompositionId id = 0;
    CompositionId sourcePortId = 0;
    std::vector<CompositionId> sinkPortIds;
    std::optional<unsigned> width;
};

struct CompositionAdapter final {
    CompositionId edgeId = 0;
    std::string kind;
    CompositionId sourceEndpointId = 0;
    CompositionId targetEndpointId = 0;
    bool allowsCdc = false;
};

struct CompositionDomain final {
    CompositionId componentId = 0;
    CompositionId portId = 0;
    CompositionId domainId = 0;
    std::string activeLevel;
    bool synchronous = false;
};

struct CompositionExternalPort final {
    CompositionId portId = 0;
    CompositionId componentId = 0;
    std::string direction;
    unsigned width = 0;
    bool signedness = false;
};

struct CompositionIr final {
    std::vector<CompositionComponent> components;
    std::vector<CompositionInstance> instances;
    std::vector<CompositionNet> nets;
    std::vector<CompositionEndpointBinding> endpointBindings;
    std::vector<CompositionAdapter> adapters;
    std::vector<CompositionDomain> clockDomains;
    std::vector<CompositionDomain> resetDomains;
    std::vector<CompositionExternalPort> externalPorts;
};

struct CompositionSourceSymbol final {
    CompositionId entityId = 0;
    std::string kind;
    std::string name;
    std::string originalName;
};

struct CompositionDiagnostic final {
    std::string code;
    std::string path;
    std::string message;
    std::vector<CompositionId> relatedIds;
};

struct CompositionAstPin final {
    CompositionId portId = 0;
    std::string signal;
};

struct CompositionAstCell final {
    CompositionId instanceId = 0;
    std::string name;
    std::string module;
    std::vector<CompositionAstPin> pins;
};

struct CompositionAstVariable final {
    CompositionId stableId = 0;
    std::string name;
    std::string kind;
    std::optional<unsigned> declaredWidth;
};

struct CompositionAstAssignment final {
    CompositionId adapterId = 0;
    std::string lhs;
    std::string rhs;
    std::optional<unsigned> sourceWidth;
    std::optional<unsigned> sinkWidth;
};

struct CompositionAstNodeCounts final {
    std::size_t modules = 0;
    std::size_t cells = 0;
    std::size_t variables = 0;
    std::size_t pins = 0;
    std::size_t variableReferences = 0;
    std::size_t wireAssignments = 0;
};

struct CompositionAstSnapshot final {
    std::vector<CompositionAstCell> cells;
    std::vector<CompositionAstVariable> variables;
    std::vector<CompositionAstAssignment> assignments;
    CompositionAstNodeCounts nodeCounts;
};

struct CompositionValidation final {
    bool link = false;
    bool pin = false;
    bool width = false;
    bool dtype = false;
    std::vector<CompositionId> unknownWidthPorts;
};

class CompositionAstTree final {
public:
    CompositionAstTree(const CompositionAstTree&) = delete;
    CompositionAstTree& operator=(const CompositionAstTree&) = delete;
    ~CompositionAstTree();

    AstNetlist* rootp() const;
    AstModule* topModulep() const;

private:
    friend struct CompositionTreeFactory;
    CompositionAstTree(AstNetlist* rootp, AstModule* topModulep);

    AstNetlist* m_rootp = nullptr;
    AstModule* m_topModulep = nullptr;
};

struct CompositionBuildResult final {
    std::unique_ptr<CompositionAstTree> tree;
    std::string sourceText;
    CompositionAstSnapshot ast;
    CompositionValidation validation;
    std::vector<CompositionDiagnostic> errors;
    std::vector<CompositionDiagnostic> warnings;
};

CompositionBuildResult buildCompositionAst(const CompositionIr& ir);
CompositionBuildResult buildCompositionAst(
    const CompositionIr& ir, const std::vector<CompositionSourceSymbol>& sourceSymbols);
CompositionIr parseCompositionIrJson(std::string_view payload);
std::vector<CompositionSourceSymbol> parseCompositionSourceSymbolsJson(
    std::string_view payload);
std::string compositionBuildResultJson(const CompositionBuildResult& result);

}  // namespace myfuzz

#endif
