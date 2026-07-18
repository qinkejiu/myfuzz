// -*- mode: C++; c-file-style: "cc-mode" -*-
//*************************************************************************
// DESCRIPTION: Verilator: Verilog Instrumenter frontend extraction pass
//*************************************************************************

#include "V3PchAstNoMT.h"  // VL_MT_DISABLED_CODE_UNIT

#include "V3VIFrontend.h"

#include "V3Ast.h"
#include "V3Global.h"

#include <cstdlib>
#include <fstream>
#include <set>
#include <sstream>
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
    string name;
    string direction;
    int width = 1;
    int packedWidth = 1;
    std::vector<std::pair<int, int>> unpackedRanges;
    int pin = 0;
    bool isSigned = false;
    Loc loc;
};

struct Dependency final {
    string target;
    std::vector<string> sources;
    string kind;
    Loc loc;
};

struct Parameter final {
    string name;
    string value;
    Loc loc;
};

struct Memory final {
    string name;
    int wordWidth = 1;
    uint64_t depth = 0;
    std::vector<std::pair<int, int>> unpackedRanges;
    Loc loc;
};

struct Limitation final {
    string module;
    string construct;
    string reason;
    std::vector<string> signals;
    Loc loc;
};

struct PinBinding final {
    string port;
    string direction;
    int width = 1;
    string expressionKind;
    std::vector<string> signals;
    Loc loc;
};

struct Instance final {
    string name;
    string origName;
    string child;
    string childOrig;
    std::vector<PinBinding> pins;
    Loc loc;
};

struct Branch final {
    int index = 0;
    string kind;
    string subtype;
    Loc loc;
};

struct Sensitivity final {
    string edge;
    string expression;
    std::vector<string> signals;
    Loc loc;
};

struct Guard final {
    string polarity;
    string expression;
};

struct Transition final {
    string kind;
    string targetExpression;
    string valueExpression;
    std::vector<string> targets;
    std::vector<string> sources;
    std::vector<Guard> guards;
    Loc loc;
};

struct BehaviorProcess final {
    int index = 0;
    string kind;
    std::vector<Sensitivity> sensitivities;
    std::vector<Transition> transitions;
    Loc loc;
};

struct Module final {
    string name;
    string origName;
    bool top = false;
    int level = 0;
    Loc loc;
    std::vector<Port> ports;
    std::vector<Instance> instances;
    std::vector<Branch> branches;
    std::vector<Dependency> dependencies;
    std::vector<Parameter> parameters;
    std::vector<Memory> memories;
    std::vector<BehaviorProcess> behaviorProcesses;
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

string sensitivityEdgeName(const VEdgeType& edge) {
    if (edge == VEdgeType::ET_POSEDGE) return "posedge";
    if (edge == VEdgeType::ET_NEGEDGE) return "negedge";
    if (edge == VEdgeType::ET_BOTHEDGE) return "bothedge";
    if (edge == VEdgeType::ET_COMBO || edge == VEdgeType::ET_COMBO_STAR) return "combinational";
    return edge.ascii();
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

void writeExpression(std::ostream& os, const AstNode* nodep, int depth = 0) {
    if (!nodep) {
        os << "null";
        return;
    }
    if (depth >= 64) {
        os << "{\"kind\":\"DEPTH_LIMIT\"}";
        return;
    }
    os << "{\"kind\":" << quote(nodep->typeName());
    if (const AstNodeExpr* const exprp = VN_CAST(nodep, NodeExpr)) {
        os << ",\"width\":" << dtypeWidth(exprp->dtypep());
    }
    if (const AstVarRef* const refp = VN_CAST(nodep, VarRef)) {
        os << ",\"signal\":" << quote(refp->varp() ? refp->varp()->name() : refp->name());
    } else if (const AstConst* const constp = VN_CAST(nodep, Const)) {
        const V3Number& number = constp->num();
        string value;
        if (number.isString()) value = number.toString();
        else if (number.isDouble()) value = std::to_string(number.toDouble());
        else value = number.isSigned() ? number.toDecimalS() : number.toDecimalU();
        os << ",\"value\":" << quote(value);
    }
    os << ",\"children\":[";
    bool first = true;
    for (const AstNode* headp : {nodep->op1p(), nodep->op2p(), nodep->op3p(), nodep->op4p()}) {
        for (const AstNode* childp = headp; childp; childp = childp->nextp()) {
            if (!first) os << ",";
            first = false;
            writeExpression(os, childp, depth + 1);
        }
    }
    os << "]}";
}

string expressionJson(const AstNode* nodep) {
    std::ostringstream os;
    writeExpression(os, nodep);
    return os.str();
}

std::vector<string> expressionSignals(const AstNode* nodep) {
    std::set<string> signals;
    if (nodep) {
        nodep->foreach([&](const AstVarRef* refp) {
            if (refp->varp()) signals.insert(refp->varp()->name());
        });
    }
    return std::vector<string>{signals.begin(), signals.end()};
}

string caseGuardJson(const AstCase* casep, const AstCaseItem* itemp) {
    std::ostringstream os;
    os << "{\"kind\":\"CASE_MATCH\",\"caseKind\":" << quote(casep->verilogKwd())
       << ",\"width\":1,\"subject\":";
    writeExpression(os, casep->exprp());
    os << ",\"default\":" << (itemp->isDefault() ? "true" : "false") << ",\"items\":[";
    bool first = true;
    for (AstNodeExpr* condp = itemp->condsp(); condp; condp = VN_AS(condp->nextp(), NodeExpr)) {
        if (!first) os << ",";
        first = false;
        writeExpression(os, condp);
    }
    os << "],\"children\":[";
    writeExpression(os, casep->exprp());
    for (AstNodeExpr* condp = itemp->condsp(); condp; condp = VN_AS(condp->nextp(), NodeExpr)) {
        os << ",";
        writeExpression(os, condp);
    }
    os << "]}";
    return os.str();
}

class FrontendCollector final : public VNVisitor {
    std::set<const AstNodeModule*> m_reachableModules;
    std::vector<Module> m_modules;
    std::vector<Limitation> m_limitations;
    Module* m_modp = nullptr;
    AstCase* m_casep = nullptr;
    BehaviorProcess* m_processp = nullptr;
    std::vector<Guard> m_guards;

    static std::set<const AstNodeModule*> reachableModules(AstNetlist* rootp) {
        std::set<const AstNodeModule*> reachable;
        std::vector<AstNodeModule*> pending;
        for (AstNodeModule* modp = rootp->modulesp(); modp;
             modp = VN_AS(modp->nextp(), NodeModule)) {
            if (modp->isTop()) pending.push_back(modp);
        }
        while (!pending.empty()) {
            AstNodeModule* const modp = pending.back();
            pending.pop_back();
            if (!reachable.insert(modp).second) continue;
            modp->foreach([&](const AstCell* cellp) {
                if (cellp->modp() && !reachable.count(cellp->modp())) {
                    pending.push_back(cellp->modp());
                }
            });
        }
        return reachable;
    }

    void addLimitation(AstNode* nodep, const string& construct, const string& reason,
                       const string& directSignal = "") {
        if (!m_modp) return;
        Limitation limitation;
        limitation.module = m_modp->name;
        limitation.construct = construct;
        limitation.reason = reason;
        limitation.loc = locOf(nodep->fileline());
        std::set<string> signals;
        if (!directSignal.empty()) signals.insert(directSignal);
        nodep->foreach([&](const AstVarRef* refp) {
            if (refp->varp()) signals.insert(refp->varp()->name());
        });
        limitation.signals.assign(signals.begin(), signals.end());
        m_limitations.push_back(std::move(limitation));
    }

    void visit(AstNodeModule* nodep) override {
        if (!m_reachableModules.count(nodep)) return;
        if (nodep->dead() || nodep->internal()) return;
        if (nodep->name().empty() || nodep->name()[0] == '@') return;
        if (nodep->fileline() && nodep->fileline()->filename() == "<built-in>") return;
        m_modules.emplace_back();
        Module* const oldModp = m_modp;
        m_modp = &m_modules.back();
        m_modp->name = nodep->name();
        m_modp->origName = nodep->origName();
        m_modp->top = nodep->isTop();
        m_modp->level = nodep->level();
        m_modp->loc = locOf(nodep->fileline());
        iterateChildren(nodep);
        m_modp = oldModp;
    }

    void visit(AstVar* nodep) override {
        if (m_modp && nodep->isParam()) {
            Parameter parameter;
            parameter.name = nodep->name();
            if (const AstConst* const constp = VN_CAST(nodep->valuep(), Const)) {
                const V3Number& number = constp->num();
                if (number.isString()) parameter.value = number.toString();
                else if (number.isDouble()) parameter.value = std::to_string(number.toDouble());
                else parameter.value = number.isSigned() ? number.toDecimalS() : number.toDecimalU();
            } else {
                parameter.value = "<non-constant>";
            }
            parameter.loc = locOf(nodep->fileline());
            m_modp->parameters.push_back(std::move(parameter));
        }
        if (m_modp && nodep->isIO()) {
            Port port;
            port.name = nodep->name();
            port.direction = directionName(nodep->direction());
            port.unpackedRanges = dtypeUnpackedRanges(nodep->dtypep());
            port.packedWidth = dtypePackedWidth(nodep->dtypep());
            port.width = dtypeTotalWidth(nodep->dtypep(), port.unpackedRanges);
            port.pin = nodep->pinNum();
            port.isSigned = nodep->dtypep() && nodep->dtypep()->skipRefp()->isSigned();
            port.loc = locOf(nodep->fileline());
            m_modp->ports.push_back(port);
            if (nodep->direction() == VDirection::INOUT || nodep->isTristate()) {
                addLimitation(nodep, "tri_state", "tri-state resolution is not modeled", nodep->name());
            }
        } else if (m_modp && VN_IS(nodep->dtypep()->skipRefp(), UnpackArrayDType)) {
            Memory memory;
            memory.name = nodep->name();
            memory.unpackedRanges = dtypeUnpackedRanges(nodep->dtypep());
            memory.wordWidth = dtypePackedWidth(nodep->dtypep());
            memory.depth = 1;
            for (const auto& range : memory.unpackedRanges) {
                memory.depth *= static_cast<uint64_t>(rangeElements(range));
            }
            memory.loc = locOf(nodep->fileline());
            m_modp->memories.push_back(std::move(memory));
        } else if (m_modp && (VN_IS(nodep->dtypep()->skipRefp(), DynArrayDType)
                              || VN_IS(nodep->dtypep()->skipRefp(), AssocArrayDType)
                              || VN_IS(nodep->dtypep()->skipRefp(), QueueDType))) {
            addLimitation(nodep, "behavioral_memory", "dynamic memory semantics are not modeled",
                          nodep->name());
        }
        iterateChildren(nodep);
    }

    void visit(AstAssignForce* nodep) override {
        addLimitation(nodep, "force", "force semantics are not modeled");
        visit(static_cast<AstNodeAssign*>(nodep));
    }

    void visit(AstRelease* nodep) override {
        addLimitation(nodep, "release", "release semantics are not modeled");
        iterateChildren(nodep);
    }

    void visit(AstDelay* nodep) override {
        addLimitation(nodep, "timing_control", "delay timing control is not modeled");
        iterateChildren(nodep);
    }

    void visit(AstEventControl* nodep) override {
        addLimitation(nodep, "timing_control", "event timing control is not modeled");
        iterateChildren(nodep);
    }

    void visit(AstWait* nodep) override {
        addLimitation(nodep, "timing_control", "wait timing control is not modeled");
        iterateChildren(nodep);
    }

    void visit(AstNodeFTask* nodep) override {
        if (nodep->dpiImport() || nodep->dpiExport()) {
            addLimitation(nodep, "dpi", "DPI import/export behavior is not modeled");
        }
        iterateChildren(nodep);
    }

    static void writeParameters(std::ostream& os, const std::vector<Parameter>& parameters) {
        for (size_t i = 0; i < parameters.size(); ++i) {
            const Parameter& parameter = parameters[i];
            if (i) os << ",";
            os << "\n        {\"name\": " << quote(parameter.name)
               << ", \"value\": " << quote(parameter.value);
            writeLoc(os, parameter.loc);
            os << "}";
        }
        if (!parameters.empty()) os << "\n      ";
    }

    static void writeMemories(std::ostream& os, const std::vector<Memory>& memories) {
        for (size_t i = 0; i < memories.size(); ++i) {
            const Memory& memory = memories[i];
            if (i) os << ",";
            os << "\n        {\"name\": " << quote(memory.name)
               << ", \"wordWidth\": " << memory.wordWidth
               << ", \"depth\": " << memory.depth
               << ", \"unpackedRanges\": [";
            for (size_t j = 0; j < memory.unpackedRanges.size(); ++j) {
                if (j) os << ", ";
                os << "[" << memory.unpackedRanges[j].first << ", "
                   << memory.unpackedRanges[j].second << "]";
            }
            os << "]";
            writeLoc(os, memory.loc);
            os << "}";
        }
        if (!memories.empty()) os << "\n      ";
    }

    void visit(AstNodeAssign* nodep) override {
        if (m_modp) {
            std::set<string> targets;
            std::set<string> sources;
            nodep->lhsp()->foreach([&](const AstVarRef* refp) {
                if (refp->varp()) targets.insert(refp->varp()->name());
            });
            nodep->rhsp()->foreach([&](const AstVarRef* refp) {
                if (refp->varp()) sources.insert(refp->varp()->name());
            });
            for (const string& target : targets) {
                Dependency dependency;
                dependency.target = target;
                dependency.sources.assign(sources.begin(), sources.end());
                dependency.kind = nodep->typeName();
                dependency.loc = locOf(nodep->fileline());
                m_modp->dependencies.push_back(std::move(dependency));
            }
            if (m_processp) {
                Transition transition;
                transition.kind = nodep->typeName();
                transition.targetExpression = expressionJson(nodep->lhsp());
                transition.valueExpression = expressionJson(nodep->rhsp());
                transition.targets.assign(targets.begin(), targets.end());
                transition.sources.assign(sources.begin(), sources.end());
                transition.guards = m_guards;
                transition.loc = locOf(nodep->fileline());
                m_processp->transitions.push_back(std::move(transition));
            }
        }
        iterateChildren(nodep);
    }

    void visit(AstAlways* nodep) override {
        if (!m_modp) {
            iterateChildren(nodep);
            return;
        }
        m_modp->behaviorProcesses.emplace_back();
        BehaviorProcess* const oldProcessp = m_processp;
        m_processp = &m_modp->behaviorProcesses.back();
        m_processp->index = static_cast<int>(m_modp->behaviorProcesses.size() - 1);
        m_processp->kind = nodep->keyword().ascii();
        m_processp->loc = locOf(nodep->fileline());
        if (nodep->sentreep()) {
            for (AstSenItem* senp = nodep->sentreep()->sensesp(); senp;
                 senp = VN_AS(senp->nextp(), SenItem)) {
                Sensitivity sensitivity;
                sensitivity.edge = sensitivityEdgeName(senp->edgeType());
                sensitivity.expression = expressionJson(senp->sensp());
                sensitivity.signals = expressionSignals(senp->sensp());
                sensitivity.loc = locOf(senp->fileline());
                m_processp->sensitivities.push_back(std::move(sensitivity));
            }
        }
        iterateAndNextNull(nodep->stmtsp());
        m_processp = oldProcessp;
    }

    void visit(AstCell* nodep) override {
        if (m_modp) {
            Instance inst;
            inst.name = nodep->name();
            inst.origName = nodep->origName();
            inst.child = nodep->modp() ? nodep->modp()->name() : nodep->modName();
            inst.childOrig = nodep->modp() ? nodep->modp()->origName() : nodep->modName();
            for (AstPin* pinp = nodep->pinsp(); pinp; pinp = VN_AS(pinp->nextp(), Pin)) {
                if (pinp->param()) continue;
                PinBinding binding;
                binding.port = pinp->modVarp() ? pinp->modVarp()->name() : pinp->name();
                binding.direction
                    = pinp->modVarp() ? directionName(pinp->modVarp()->direction()) : "";
                binding.width
                    = pinp->modVarp() ? dtypeTotalWidth(
                          pinp->modVarp()->dtypep(), dtypeUnpackedRanges(pinp->modVarp()->dtypep()))
                                      : 1;
                binding.expressionKind = pinp->exprp() ? pinp->exprp()->typeName() : "unconnected";
                std::set<string> signals;
                if (pinp->exprp()) {
                    pinp->exprp()->foreach([&](const AstVarRef* refp) {
                        if (refp->varp()) signals.insert(refp->varp()->name());
                    });
                }
                binding.signals.assign(signals.begin(), signals.end());
                binding.loc = locOf(pinp->fileline());
                inst.pins.push_back(std::move(binding));
            }
            inst.loc = locOf(nodep->fileline());
            m_modp->instances.push_back(inst);
        }
        iterateChildren(nodep);
    }

    void addBranch(AstNode* nodep, const string& kind, const string& subtype) {
        if (!m_modp) return;
        Branch branch;
        branch.index = static_cast<int>(m_modp->branches.size());
        branch.kind = kind;
        branch.subtype = subtype;
        branch.loc = locOf(nodep->fileline());
        m_modp->branches.push_back(branch);
    }

    void visit(AstIf* nodep) override {
        addBranch(nodep, "if", "true");
        if (nodep->elsesp()) addBranch(nodep, "if", "false");
        iterateNull(nodep->condp());
        m_guards.push_back(Guard{"true", expressionJson(nodep->condp())});
        iterateAndNextNull(nodep->thensp());
        m_guards.pop_back();
        if (nodep->elsesp()) {
            m_guards.push_back(Guard{"false", expressionJson(nodep->condp())});
            iterateAndNextNull(nodep->elsesp());
            m_guards.pop_back();
        }
    }

    void visit(AstCase* nodep) override {
        AstCase* const oldCasep = m_casep;
        m_casep = nodep;
        iterateChildren(nodep);
        m_casep = oldCasep;
    }

    void visit(AstCaseItem* nodep) override {
        if (m_casep) addBranch(nodep, m_casep->verilogKwd(), "item");
        if (!m_casep) {
            iterateChildren(nodep);
            return;
        }
        iterateAndNextNull(nodep->condsp());
        m_guards.push_back(Guard{"match", caseGuardJson(m_casep, nodep)});
        iterateAndNextNull(nodep->stmtsp());
        m_guards.pop_back();
    }

    void visit(AstNode* nodep) override { iterateChildren(nodep); }

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
            os << ", \"signed\": " << (port.isSigned ? "true" : "false");
            writeLoc(os, port.loc);
            os << "}";
        }
        if (!ports.empty()) os << "\n      ";
    }

    static void writeDependencies(std::ostream& os, const std::vector<Dependency>& dependencies) {
        for (size_t i = 0; i < dependencies.size(); ++i) {
            const Dependency& dependency = dependencies[i];
            if (i) os << ",";
            os << "\n        {\"target\": " << quote(dependency.target)
               << ", \"sources\": [";
            for (size_t j = 0; j < dependency.sources.size(); ++j) {
                if (j) os << ", ";
                os << quote(dependency.sources[j]);
            }
            os << "], \"kind\": " << quote(dependency.kind);
            writeLoc(os, dependency.loc);
            os << "}";
        }
        if (!dependencies.empty()) os << "\n      ";
    }

    static void writeLimitations(std::ostream& os, const std::vector<Limitation>& limitations) {
        for (size_t i = 0; i < limitations.size(); ++i) {
            const Limitation& limitation = limitations[i];
            if (i) os << ",";
            os << "\n    {\"module\": " << quote(limitation.module)
               << ", \"construct\": " << quote(limitation.construct)
               << ", \"reason\": " << quote(limitation.reason)
               << ", \"signals\": [";
            for (size_t j = 0; j < limitation.signals.size(); ++j) {
                if (j) os << ", ";
                os << quote(limitation.signals[j]);
            }
            os << "]";
            writeLoc(os, limitation.loc);
            os << "}";
        }
        if (!limitations.empty()) os << "\n  ";
    }

    static void writeInstances(std::ostream& os, const std::vector<Instance>& instances) {
        for (size_t i = 0; i < instances.size(); ++i) {
            const Instance& inst = instances[i];
            if (i) os << ",";
            os << "\n        {\"name\": " << quote(inst.name)
               << ", \"origName\": " << quote(inst.origName)
               << ", \"child\": " << quote(inst.child)
               << ", \"childOrig\": " << quote(inst.childOrig)
               << ", \"pins\": [";
            for (size_t j = 0; j < inst.pins.size(); ++j) {
                const PinBinding& pin = inst.pins[j];
                if (j) os << ",";
                os << "\n          {\"port\": " << quote(pin.port)
                   << ", \"direction\": " << quote(pin.direction)
                   << ", \"width\": " << pin.width
                   << ", \"expressionKind\": " << quote(pin.expressionKind)
                   << ", \"signals\": [";
                for (size_t k = 0; k < pin.signals.size(); ++k) {
                    if (k) os << ", ";
                    os << quote(pin.signals[k]);
                }
                os << "]";
                writeLoc(os, pin.loc);
                os << "}";
            }
            if (!inst.pins.empty()) os << "\n        ";
            os << "]";
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

    static void writeBehaviorProcesses(std::ostream& os,
                                       const std::vector<BehaviorProcess>& processes) {
        for (size_t i = 0; i < processes.size(); ++i) {
            const BehaviorProcess& process = processes[i];
            if (i) os << ",";
            os << "\n        {\"index\":" << process.index << ",\"kind\":" << quote(process.kind)
               << ",\"sensitivities\":[";
            for (size_t j = 0; j < process.sensitivities.size(); ++j) {
                const Sensitivity& sensitivity = process.sensitivities[j];
                if (j) os << ",";
                os << "{\"edge\":" << quote(sensitivity.edge) << ",\"expression\":"
                   << sensitivity.expression << ",\"signals\":[";
                for (size_t k = 0; k < sensitivity.signals.size(); ++k) {
                    if (k) os << ",";
                    os << quote(sensitivity.signals[k]);
                }
                os << "]";
                writeLoc(os, sensitivity.loc);
                os << "}";
            }
            os << "],\"transitions\":[";
            for (size_t j = 0; j < process.transitions.size(); ++j) {
                const Transition& transition = process.transitions[j];
                if (j) os << ",";
                os << "{\"kind\":" << quote(transition.kind) << ",\"targetExpression\":"
                   << transition.targetExpression << ",\"valueExpression\":"
                   << transition.valueExpression << ",\"targets\":[";
                for (size_t k = 0; k < transition.targets.size(); ++k) {
                    if (k) os << ",";
                    os << quote(transition.targets[k]);
                }
                os << "],\"sources\":[";
                for (size_t k = 0; k < transition.sources.size(); ++k) {
                    if (k) os << ",";
                    os << quote(transition.sources[k]);
                }
                os << "],\"guards\":[";
                for (size_t k = 0; k < transition.guards.size(); ++k) {
                    if (k) os << ",";
                    os << "{\"polarity\":" << quote(transition.guards[k].polarity)
                       << ",\"expression\":" << transition.guards[k].expression << "}";
                }
                os << "]";
                writeLoc(os, transition.loc);
                os << "}";
            }
            os << "]";
            writeLoc(os, process.loc);
            os << "}";
        }
        if (!processes.empty()) os << "\n      ";
    }

public:
    explicit FrontendCollector(AstNetlist* rootp)
        : m_reachableModules{reachableModules(rootp)} {
        iterate(rootp);
    }
    ~FrontendCollector() override = default;

    void writeJson(std::ostream& os) const {
        os << "{\n"
           << "  \"schema\": \"myfuzz.frontend.v1\",\n"
           << "  \"behaviorSchema\": \"myfuzz.frontend-behavior/v1\",\n"
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
               << "      \"parameters\": [";
            writeParameters(os, mod.parameters);
            os << "],\n"
               << "      \"memories\": [";
            writeMemories(os, mod.memories);
            os << "],\n"
               << "      \"ports\": [";
            writePorts(os, mod.ports);
            os << "],\n"
               << "      \"instances\": [";
            writeInstances(os, mod.instances);
            os << "],\n"
               << "      \"dependencies\": [";
            writeDependencies(os, mod.dependencies);
            os << "],\n"
               << "      \"behaviorProcesses\": [";
            writeBehaviorProcesses(os, mod.behaviorProcesses);
            os << "],\n"
               << "      \"branches\": [";
            writeBranches(os, mod.branches);
            os << "]\n"
               << "    }";
        }
        os << "\n  ],\n"
           << "  \"limitations\": [";
        writeLimitations(os, m_limitations);
        os << "]\n"
           << "}\n";
    }

    string json() const {
        std::ostringstream os;
        writeJson(os);
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

void V3VIFrontend::clearLastManifest() {
    s_lastManifestJson.clear();
}

const string& V3VIFrontend::lastManifestJson() {
    return s_lastManifestJson;
}
