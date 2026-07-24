// -*- mode: C++; c-file-style: "cc-mode" -*-
//*************************************************************************
// DESCRIPTION: Verilator: Verilog Instrumenter frontend extraction pass
//*************************************************************************

#include "V3PchAstNoMT.h"  // VL_MT_DISABLED_CODE_UNIT

#include "V3VIFrontend.h"

#include "V3Ast.h"
#include "V3Global.h"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

VL_DEFINE_DEBUG_FUNCTIONS;

namespace {

string s_lastManifestJson;

struct Loc final {
    string file;
    int line = 0;
    int column = 0;
};

struct Port final {
    const AstVar* varp = nullptr;
    string name;
    string sourceName;
    string sourceOriginalName;
    string direction;
    int width = 1;
    int packedWidth = 1;
    bool isSigned = false;
    std::vector<std::pair<int, int>> unpackedRanges;
    int pin = 0;
    Loc loc;
};

struct PinBinding final {
    const AstVar* childPortp = nullptr;
    std::vector<const AstVar*> sources;
    std::vector<const AstVar*> targets;
    bool connected = false;
    Loc loc;
};

struct Instance final {
    const AstNodeModule* childp = nullptr;
    string name;
    string origName;
    string sourceName;
    string sourceOriginalName;
    string child;
    string childOrig;
    std::vector<PinBinding> pinBindings;
    Loc loc;
};

struct Branch final {
    int index = 0;
    string kind;
    string subtype;
    std::vector<const AstVar*> sources;
    std::vector<const AstVar*> targets;
    Loc loc;
};

struct Assignment final {
    std::vector<const AstVar*> sources;
    std::vector<const AstVar*> targets;
    Loc loc;
};

struct DataflowEdge final {
    int sourceId = 0;
    int targetId = 0;
    Loc loc;
};

struct Module final {
    const AstNodeModule* nodep = nullptr;
    string name;
    string origName;
    string sourceName;
    string sourceOriginalName;
    bool top = false;
    int level = 0;
    Loc loc;
    std::vector<Port> ports;
    std::vector<Instance> instances;
    std::vector<Branch> branches;
    std::vector<Assignment> assignments;
};

string jsonEscape(const string& value) {
    std::ostringstream os;
    for (const char ch : value) {
        switch (ch) {
        case '\\': os << "\\\\"; break;
        case '"': os << "\\\""; break;
        case '\b': os << "\\b"; break;
        case '\f': os << "\\f"; break;
        case '\n': os << "\\n"; break;
        case '\r': os << "\\r"; break;
        case '\t': os << "\\t"; break;
        default:
            if (static_cast<unsigned char>(ch) < 0x20) {
                os << "\\u00";
                constexpr char hex[] = "0123456789abcdef";
                os << hex[(ch >> 4) & 0xf] << hex[ch & 0xf];
            } else {
                os << ch;
            }
            break;
        }
    }
    return os.str();
}

string quote(const string& value) { return "\"" + jsonEscape(value) + "\""; }

Loc locOf(FileLine* fl) {
    Loc loc;
    if (fl) {
        loc.file = fl->filename();
        loc.line = fl->firstLineno();
        loc.column = fl->firstColumn();
    }
    return loc;
}

string directionName(const VDirection& direction) {
    if (direction == VDirection::INPUT) return "input";
    if (direction == VDirection::OUTPUT) return "output";
    if (direction == VDirection::INOUT) return "inout";
    if (direction == VDirection::REF) return "ref";
    return "";
}

int dtypeWidth(const AstNodeDType* dtypep) {
    if (!dtypep) return 1;
    dtypep = dtypep->skipRefp();
    const int width = dtypep->width();
    return width > 0 ? width : 1;
}

int rangeElements(const std::pair<int, int>& range) {
    const int diff = range.first - range.second;
    return (diff < 0 ? -diff : diff) + 1;
}

std::vector<std::pair<int, int>> dtypeUnpackedRanges(const AstNodeDType* dtypep) {
    std::vector<std::pair<int, int>> ranges;
    for (const AstNodeDType* dtp = dtypep; dtp;) {
        dtp = dtp->skipRefp();
        const AstNodeArrayDType* const arrayp = VN_CAST(dtp, NodeArrayDType);
        if (!arrayp) break;
        if (VN_IS(dtp, UnpackArrayDType)) {
            ranges.emplace_back(arrayp->declRange().left(), arrayp->declRange().right());
        }
        dtp = arrayp->subDTypep();
    }
    return ranges;
}

int dtypePackedWidth(const AstNodeDType* dtypep) {
    return dtypeWidth(dtypep);
}

int dtypeTotalWidth(const AstNodeDType* dtypep, const std::vector<std::pair<int, int>>& unpacked) {
    int total = dtypePackedWidth(dtypep);
    for (const auto& range : unpacked) {
        const int elements = rangeElements(range);
        if (elements > 0) total *= elements;
    }
    return total > 0 ? total : 1;
}

void writeLoc(std::ostream& os, const Loc& loc) {
    os << ", \"file\": " << quote(loc.file) << ", \"line\": " << loc.line
       << ", \"column\": " << loc.column;
}

class VarRefCollector final : public VNVisitor {
    std::vector<const AstVar*> m_reads;
    std::vector<const AstVar*> m_writes;

    static void appendUnique(std::vector<const AstVar*>& values, const AstVar* varp) {
        if (varp && std::find(values.begin(), values.end(), varp) == values.end())
            values.push_back(varp);
    }

    void visit(AstNodeVarRef* nodep) override {
        if (nodep->access().isReadOrRW()) appendUnique(m_reads, nodep->varp());
        if (nodep->access().isWriteOrRW()) appendUnique(m_writes, nodep->varp());
        iterateChildren(nodep);
    }

    void visit(AstNode* nodep) override { iterateChildren(nodep); }

public:
    explicit VarRefCollector(AstNode* nodep) {
        if (nodep) iterate(nodep);
    }

    const std::vector<const AstVar*>& reads() const { return m_reads; }
    const std::vector<const AstVar*>& writes() const { return m_writes; }
};

class FrontendCollector final : public VNVisitor {
    std::vector<Module> m_modules;
    Module* m_modp = nullptr;
    AstCase* m_casep = nullptr;

    void visit(AstNodeModule* nodep) override {
        if (nodep->dead() || nodep->internal()) return;
        if (nodep->name().empty() || nodep->name()[0] == '@') return;
        if (nodep->fileline() && nodep->fileline()->filename() == "<built-in>") return;
        m_modules.emplace_back();
        Module* const oldModp = m_modp;
        m_modp = &m_modules.back();
        m_modp->nodep = nodep;
        m_modp->name = nodep->name();
        m_modp->origName = nodep->origName();
        m_modp->sourceName = nodep->name();
        m_modp->sourceOriginalName = nodep->verilogName();
        m_modp->top = nodep->isTop();
        m_modp->level = nodep->level();
        m_modp->loc = locOf(nodep->fileline());
        iterateChildren(nodep);
        m_modp = oldModp;
    }

    void visit(AstVar* nodep) override {
        if (m_modp && nodep->isIO()) {
            Port port;
            port.varp = nodep;
            port.name = nodep->name();
            port.sourceName = nodep->name();
            port.sourceOriginalName = nodep->verilogName();
            port.direction = directionName(nodep->direction());
            port.unpackedRanges = dtypeUnpackedRanges(nodep->dtypep());
            port.packedWidth = dtypePackedWidth(nodep->dtypep());
            port.width = dtypeTotalWidth(nodep->dtypep(), port.unpackedRanges);
            port.isSigned = nodep->isSigned();
            port.pin = nodep->pinNum();
            port.loc = locOf(nodep->fileline());
            m_modp->ports.push_back(port);
        }
        iterateChildren(nodep);
    }

    void visit(AstCell* nodep) override {
        if (m_modp) {
            Instance inst;
            inst.childp = nodep->modp();
            inst.name = nodep->name();
            inst.origName = nodep->origName();
            inst.sourceName = nodep->name();
            inst.sourceOriginalName = nodep->verilogName();
            inst.child = nodep->modp() ? nodep->modp()->name() : nodep->modName();
            inst.childOrig = nodep->modp() ? nodep->modp()->origName() : nodep->modName();
            inst.loc = locOf(nodep->fileline());
            for (AstPin* pinp = nodep->pinsp(); pinp; pinp = VN_AS(pinp->nextp(), Pin)) {
                if (!pinp->modVarp()) continue;
                PinBinding binding;
                binding.childPortp = pinp->modVarp();
                binding.connected = pinp->exprp();
                binding.loc = locOf(pinp->fileline());
                VarRefCollector expression{pinp->exprp()};
                binding.sources = expression.reads();
                binding.targets = expression.writes();
                inst.pinBindings.push_back(std::move(binding));
            }
            m_modp->instances.push_back(inst);
        }
        iterateChildren(nodep);
    }

    void addBranch(AstNode* nodep, const string& kind, const string& subtype,
                   const std::vector<const AstVar*>& sources,
                   const std::vector<const AstVar*>& targets) {
        if (!m_modp) return;
        Branch branch;
        branch.index = static_cast<int>(m_modp->branches.size());
        branch.kind = kind;
        branch.subtype = subtype;
        branch.sources = sources;
        branch.targets = targets;
        branch.loc = locOf(nodep->fileline());
        m_modp->branches.push_back(branch);
    }

    void visit(AstIf* nodep) override {
        VarRefCollector condition{nodep->condp()};
        VarRefCollector thenBody{nodep->thensp()};
        addBranch(nodep, "if", "true", condition.reads(), thenBody.writes());
        if (nodep->elsesp()) {
            VarRefCollector elseBody{nodep->elsesp()};
            addBranch(nodep, "if", "false", condition.reads(), elseBody.writes());
        }
        iterateChildren(nodep);
    }

    void visit(AstCase* nodep) override {
        AstCase* const oldCasep = m_casep;
        m_casep = nodep;
        iterateChildren(nodep);
        m_casep = oldCasep;
    }

    void visit(AstCaseItem* nodep) override {
        if (m_casep) {
            VarRefCollector condition{m_casep->exprp()};
            VarRefCollector body{nodep->stmtsp()};
            addBranch(nodep, m_casep->verilogKwd(), "item", condition.reads(), body.writes());
        }
        iterateChildren(nodep);
    }

    void visit(AstNodeAssign* nodep) override {
        if (m_modp) {
            VarRefCollector lhs{nodep->lhsp()};
            VarRefCollector rhs{nodep->rhsp()};
            Assignment assignment;
            assignment.sources = rhs.reads();
            assignment.targets = lhs.writes();
            assignment.loc = locOf(nodep->fileline());
            m_modp->assignments.push_back(assignment);
        }
        iterateChildren(nodep);
    }

    void visit(AstNode* nodep) override { iterateChildren(nodep); }

    int portIdFor(const AstVar* varp) const {
        int portId = 1;
        for (const Module& mod : m_modules) {
            for (const Port& port : mod.ports) {
                if (port.varp == varp) return portId;
                ++portId;
            }
        }
        return 0;
    }

    std::vector<DataflowEdge> dataflowEdgesFor(const Module& mod) const {
        std::vector<DataflowEdge> edges;
        for (const Port& sourcePort : mod.ports) {
            std::vector<const AstVar*> reachable{sourcePort.varp};
            std::vector<std::pair<const AstVar*, Loc>> reachedLocations;
            bool changed = true;
            while (changed) {
                changed = false;
                for (const Assignment& assignment : mod.assignments) {
                    const bool sourceReached
                        = std::any_of(assignment.sources.begin(), assignment.sources.end(),
                                      [&](const AstVar* sourcep) {
                                          return std::find(reachable.begin(), reachable.end(), sourcep)
                                                 != reachable.end();
                                      });
                    if (!sourceReached) continue;
                    for (const AstVar* targetp : assignment.targets) {
                        if (std::find(reachable.begin(), reachable.end(), targetp)
                            != reachable.end())
                            continue;
                        reachable.push_back(targetp);
                        reachedLocations.emplace_back(targetp, assignment.loc);
                        changed = true;
                    }
                }
            }

            const int sourceId = portIdFor(sourcePort.varp);
            for (const Port& targetPort : mod.ports) {
                if (targetPort.varp == sourcePort.varp
                    || std::find(reachable.begin(), reachable.end(), targetPort.varp)
                           == reachable.end())
                    continue;
                const auto locationIt
                    = std::find_if(reachedLocations.begin(), reachedLocations.end(),
                                   [&](const std::pair<const AstVar*, Loc>& reached) {
                                       return reached.first == targetPort.varp;
                                   });
                UASSERT(locationIt != reachedLocations.end(), "Missing dataflow edge location");
                edges.push_back(
                    DataflowEdge{sourceId, portIdFor(targetPort.varp), locationIt->second});
            }
        }
        return edges;
    }

    static void writePorts(std::ostream& os, const std::vector<Port>& ports) {
        for (size_t i = 0; i < ports.size(); ++i) {
            const Port& port = ports[i];
            if (i) os << ",";
            os << "\n        {\"name\": " << quote(port.name)
               << ", \"direction\": " << quote(port.direction)
               << ", \"width\": " << port.width
               << ", \"packedWidth\": " << port.packedWidth
               << ", \"unpackedRanges\": [";
            for (size_t j = 0; j < port.unpackedRanges.size(); ++j) {
                if (j) os << ", ";
                os << "[" << port.unpackedRanges[j].first << ", " << port.unpackedRanges[j].second
                   << "]";
            }
            os << "]"
               << ", \"pin\": " << port.pin;
            writeLoc(os, port.loc);
            os << "}";
        }
        if (!ports.empty()) os << "\n      ";
    }

    static void writeInstances(std::ostream& os, const std::vector<Instance>& instances) {
        for (size_t i = 0; i < instances.size(); ++i) {
            const Instance& inst = instances[i];
            if (i) os << ",";
            os << "\n        {\"name\": " << quote(inst.name)
               << ", \"origName\": " << quote(inst.origName)
               << ", \"child\": " << quote(inst.child)
               << ", \"childOrig\": " << quote(inst.childOrig);
            writeLoc(os, inst.loc);
            os << "}";
        }
        if (!instances.empty()) os << "\n      ";
    }

    static void writeBranches(std::ostream& os, const std::vector<Branch>& branches) {
        for (size_t i = 0; i < branches.size(); ++i) {
            const Branch& branch = branches[i];
            if (i) os << ",";
            os << "\n        {\"index\": " << branch.index
               << ", \"kind\": " << quote(branch.kind)
               << ", \"subtype\": " << quote(branch.subtype);
            writeLoc(os, branch.loc);
            os << "}";
        }
        if (!branches.empty()) os << "\n      ";
    }

public:
    explicit FrontendCollector(AstNetlist* rootp) { iterate(rootp); }
    ~FrontendCollector() override = default;

    void writeJson(std::ostream& os) const {
        os << "{\n"
           << "  \"schema\": \"myfuzz.frontend.v1\",\n"
           << "  \"source\": \"verilator-frontend-ast\",\n"
           << "  \"topModule\": " << quote(v3Global.opt.topModule()) << ",\n"
           << "  \"modules\": [\n";
        for (size_t i = 0; i < m_modules.size(); ++i) {
            const Module& mod = m_modules[i];
            if (i) os << ",\n";
            os << "    {\n"
               << "      \"name\": " << quote(mod.name) << ",\n"
               << "      \"origName\": " << quote(mod.origName) << ",\n"
               << "      \"top\": " << (mod.top ? "true" : "false") << ",\n"
               << "      \"level\": " << mod.level << ",\n"
               << "      \"file\": " << quote(mod.loc.file) << ",\n"
               << "      \"line\": " << mod.loc.line << ",\n"
               << "      \"ports\": [";
            writePorts(os, mod.ports);
            os << "],\n"
               << "      \"instances\": [";
            writeInstances(os, mod.instances);
            os << "],\n"
               << "      \"branches\": [";
            writeBranches(os, mod.branches);
            os << "]\n"
               << "    }";
        }
        os << "\n  ]\n"
           << "}\n";
    }

    string json() const {
        std::ostringstream os;
        writeJson(os);
        return os.str();
    }

    string facts(const string& inputHash) const {
        for (const Module& mod : m_modules) {
            for (const Port& port : mod.ports) {
                if (port.direction != "input" && port.direction != "output"
                    && port.direction != "inout") {
                    throw std::runtime_error{"unsupported port direction in hdl_facts.v2: "
                                             + port.direction};
                }
            }
        }
        std::vector<std::vector<DataflowEdge>> dataflowEdges;
        dataflowEdges.reserve(m_modules.size());
        for (const Module& mod : m_modules) dataflowEdges.push_back(dataflowEdgesFor(mod));

        std::ostringstream os;
        os << "{\n  \"schema_version\": \"hdl_facts.v2\",\n"
           << "  \"tool\": {\"frontend\": \"myfuzz-verilator-frontend\", "
           << "\"verilator_revision\": \"7e2fe64ae2799bea9c6a3edc2ccbe94fa84fb916\", "
           << "\"input_hash\": " << quote(inputHash) << "},\n"
           << "  \"modules\": [";
        int nextPortId = 1;
        int nextInstanceId = 1;
        for (size_t i = 0; i < m_modules.size(); ++i) {
            const Module& mod = m_modules[i];
            if (i) os << ",";
            os << "{\"id\": " << i + 1 << ", \"ports\": [";
            for (size_t j = 0; j < mod.ports.size(); ++j) {
                if (j) os << ",";
                os << nextPortId++;
            }
            os << "], \"instances\": [";
            for (size_t j = 0; j < mod.instances.size(); ++j) {
                if (j) os << ",";
                os << nextInstanceId++;
            }
            os << "], \"top\": " << (mod.top ? "true" : "false") << "}";
        }
        os << "],\n  \"parameters\": [],\n  \"ports\": [";
        bool first = true;
        nextPortId = 1;
        for (size_t i = 0; i < m_modules.size(); ++i) {
            const Module& mod = m_modules[i];
            for (const Port& port : mod.ports) {
                if (!first) os << ",";
                first = false;
                os << "{\"id\": " << nextPortId++ << ", \"module_id\": " << i + 1
                   << ", \"direction\": " << quote(port.direction) << ", \"width\": "
                   << port.width << ", \"signed\": " << (port.isSigned ? "true" : "false")
                   << ", \"declared_role\": \"uninterpreted_external\"}";
            }
        }
        os << "],\n  \"instances\": [";
        first = true;
        nextInstanceId = 1;
        int nextPinBindingId = 1;
        for (size_t i = 0; i < m_modules.size(); ++i) {
            const Module& mod = m_modules[i];
            for (const Instance& inst : mod.instances) {
                int childModuleId = 0;
                for (size_t j = 0; j < m_modules.size(); ++j) {
                    if (m_modules[j].nodep == inst.childp) {
                        childModuleId = static_cast<int>(j + 1);
                        break;
                    }
                }
                if (!childModuleId) {
                    throw std::runtime_error{"facts instance has no collected child module: "
                                             + inst.name};
                }
                if (!first) os << ",";
                first = false;
                os << "{\"id\": " << nextInstanceId++ << ", \"parent_module_id\": " << i + 1
                   << ", \"module_id\": " << childModuleId << ", \"pin_bindings\": [";
                for (size_t j = 0; j < inst.pinBindings.size(); ++j) {
                    if (j) os << ",";
                    os << nextPinBindingId++;
                }
                os << "]}";
            }
        }
        os << "],\n  \"pin_bindings\": [";
        first = true;
        nextInstanceId = 1;
        nextPinBindingId = 1;
        int nextExpressionId = 1;
        for (const Module& mod : m_modules) {
            for (const Instance& inst : mod.instances) {
                for (const PinBinding& binding : inst.pinBindings) {
                    const int childPortId = portIdFor(binding.childPortp);
                    if (!childPortId)
                        throw std::runtime_error{"facts pin has no collected child port"};
                    if (!first) os << ",";
                    first = false;
                    os << "{\"id\": " << nextPinBindingId++ << ", \"instance_id\": "
                       << nextInstanceId << ", \"port_id\": " << childPortId
                       << ", \"expression_id\": " << nextExpressionId++
                       << ", \"provenance\": \"rtl\"}";
                }
                ++nextInstanceId;
            }
        }
        os << "],\n  \"expressions\": [";
        first = true;
        nextExpressionId = 1;
        for (size_t i = 0; i < m_modules.size(); ++i) {
            for (const Instance& inst : m_modules[i].instances) {
                for (const PinBinding& binding : inst.pinBindings) {
                    if (!first) os << ",";
                    first = false;
                    os << "{\"id\": " << nextExpressionId++ << ", \"module_id\": " << i + 1
                       << ", \"kind\": "
                       << quote(binding.connected ? "pin_connection" : "unconnected")
                       << ", \"source_ids\": [";
                    bool firstId = true;
                    bool hasInternalSources = false;
                    for (const AstVar* sourcep : binding.sources) {
                        const int sourceId = portIdFor(sourcep);
                        if (!sourceId) {
                            hasInternalSources = true;
                            continue;
                        }
                        if (!firstId) os << ",";
                        firstId = false;
                        os << sourceId;
                    }
                    os << "], \"target_ids\": [";
                    firstId = true;
                    bool hasInternalTargets = false;
                    for (const AstVar* targetp : binding.targets) {
                        const int targetId = portIdFor(targetp);
                        if (!targetId) {
                            hasInternalTargets = true;
                            continue;
                        }
                        if (!firstId) os << ",";
                        firstId = false;
                        os << targetId;
                    }
                    os << "], \"has_internal_sources\": "
                       << (hasInternalSources ? "true" : "false")
                       << ", \"has_internal_targets\": "
                       << (hasInternalTargets ? "true" : "false")
                       << ", \"provenance\": \"rtl\"}";
                }
            }
        }
        os << "],\n  \"dataflow_edges\": [";
        first = true;
        int nextDataflowId = 1;
        for (size_t i = 0; i < m_modules.size(); ++i) {
            for (const DataflowEdge& edge : dataflowEdges[i]) {
                if (!first) os << ",";
                first = false;
                os << "{\"id\": " << nextDataflowId++ << ", \"module_id\": " << i + 1
                   << ", \"source_id\": " << edge.sourceId << ", \"target_id\": "
                   << edge.targetId << ", \"kind\": \"assignment\", \"provenance\": \"rtl\"}";
            }
        }
        os << "],\n  \"control_edges\": [";
        first = true;
        int nextControlId = 1;
        for (size_t i = 0; i < m_modules.size(); ++i) {
            for (const Branch& branch : m_modules[i].branches) {
                for (const AstVar* sourcep : branch.sources) {
                    const int sourceId = portIdFor(sourcep);
                    if (!sourceId) continue;
                    for (const AstVar* targetp : branch.targets) {
                        const int targetId = portIdFor(targetp);
                        if (!targetId || sourceId == targetId) continue;
                        if (!first) os << ",";
                        first = false;
                        os << "{\"id\": " << nextControlId++ << ", \"module_id\": " << i + 1
                           << ", \"source_id\": " << sourceId << ", \"target_id\": "
                           << targetId << ", \"kind\": " << quote(branch.kind)
                           << ", \"subtype\": " << quote(branch.subtype)
                           << ", \"provenance\": \"rtl\"}";
                    }
                }
            }
        }
        os << "],\n  \"clock_reset_checks\": [],\n  \"local_address_facts\": [],\n"
           << "  \"source_locations\": [";
        first = true;
        int nextLocationId = 1;
        nextPortId = 1;
        nextInstanceId = 1;
        nextPinBindingId = 1;
        nextExpressionId = 1;
        nextDataflowId = 1;
        nextControlId = 1;
        for (size_t i = 0; i < m_modules.size(); ++i) {
            const Module& mod = m_modules[i];
            const auto writeLocation = [&](const char* kind, int entityId, const Loc& loc) {
                if (!first) os << ",";
                first = false;
                os << "{\"id\": " << nextLocationId++ << ", \"kind\": " << quote(kind)
                   << ", \"entity_id\": " << entityId << ", \"file\": " << quote(loc.file)
                   << ", \"line\": " << loc.line << ", \"column\": " << loc.column << "}";
            };
            writeLocation("module", static_cast<int>(i + 1), mod.loc);
            for (const Port& port : mod.ports) writeLocation("port", nextPortId++, port.loc);
            for (const Instance& inst : mod.instances) {
                writeLocation("instance", nextInstanceId++, inst.loc);
                for (const PinBinding& binding : inst.pinBindings) {
                    writeLocation("pin_binding", nextPinBindingId++, binding.loc);
                    writeLocation("expression", nextExpressionId++, binding.loc);
                }
            }
            for (const DataflowEdge& edge : dataflowEdges[i])
                writeLocation("dataflow_edge", nextDataflowId++, edge.loc);
            for (const Branch& branch : mod.branches) {
                for (const AstVar* sourcep : branch.sources) {
                    const int sourceId = portIdFor(sourcep);
                    if (!sourceId) continue;
                    for (const AstVar* targetp : branch.targets) {
                        const int targetId = portIdFor(targetp);
                        if (!targetId || sourceId == targetId) continue;
                        writeLocation("control_edge", nextControlId++, branch.loc);
                    }
                }
            }
        }
        os << "],\n  \"source_symbols\": [";
        first = true;
        int nextSymbolId = 1;
        nextPortId = 1;
        nextInstanceId = 1;
        for (size_t i = 0; i < m_modules.size(); ++i) {
            const Module& mod = m_modules[i];
            const auto writeSymbol = [&](const char* kind, int entityId, const string& name,
                                         const string& originalName) {
                if (!first) os << ",";
                first = false;
                os << "{\"id\": " << nextSymbolId++ << ", \"kind\": " << quote(kind)
                   << ", \"entity_id\": " << entityId << ", \"name\": " << quote(name)
                   << ", \"original_name\": " << quote(originalName) << "}";
            };
            writeSymbol("module", static_cast<int>(i + 1), mod.sourceName,
                        mod.sourceOriginalName);
            for (const Port& port : mod.ports)
                writeSymbol("port", nextPortId++, port.sourceName, port.sourceOriginalName);
            for (const Instance& inst : mod.instances)
                writeSymbol("instance", nextInstanceId++, inst.sourceName,
                            inst.sourceOriginalName);
        }
        os << "],\n  \"diagnostics\": {\"errors\": [], \"warnings\": [], \"unsupported\": []}\n}\n";
        return os.str();
    }

    void writeJsonFile(const string& filename) const {
        std::ofstream os{filename};
        UASSERT(os, "Unable to open myfuzz frontend manifest");
        writeJson(os);
    }
};

}  // namespace

void V3VIFrontend::emitManifest(AstNetlist* rootp) {
    s_lastManifestJson = manifestJson(rootp);
    const char* const outp = std::getenv("MYFUZZ_FRONTEND_JSON");
    if (!outp || !*outp) return;
    std::ofstream os{outp};
    UASSERT(os, "Unable to open myfuzz frontend manifest");
    os << s_lastManifestJson;
}

string V3VIFrontend::manifestJson(AstNetlist* rootp) {
    FrontendCollector collector{rootp};
    return collector.json();
}

string V3VIFrontend::factsJson(AstNetlist* rootp, const string& inputHash) {
    FrontendCollector collector{rootp};
    return collector.facts(inputHash);
}

void V3VIFrontend::clearLastManifest() {
    s_lastManifestJson.clear();
}

const string& V3VIFrontend::lastManifestJson() {
    return s_lastManifestJson;
}
