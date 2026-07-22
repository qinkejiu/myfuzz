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
    Loc loc;
};

struct Instance final {
    string name;
    string origName;
    string child;
    string childOrig;
    Loc loc;
};

struct Branch final {
    int index = 0;
    string kind;
    string subtype;
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
        m_modp->name = nodep->name();
        m_modp->origName = nodep->origName();
        m_modp->top = nodep->isTop();
        m_modp->level = nodep->level();
        m_modp->loc = locOf(nodep->fileline());
        iterateChildren(nodep);
        m_modp = oldModp;
    }

    void visit(AstVar* nodep) override {
        if (m_modp && nodep->isIO()) {
            Port port;
            port.name = nodep->name();
            port.direction = directionName(nodep->direction());
            port.unpackedRanges = dtypeUnpackedRanges(nodep->dtypep());
            port.packedWidth = dtypePackedWidth(nodep->dtypep());
            port.width = dtypeTotalWidth(nodep->dtypep(), port.unpackedRanges);
            port.pin = nodep->pinNum();
            port.loc = locOf(nodep->fileline());
            m_modp->ports.push_back(port);
        }
        iterateChildren(nodep);
    }

    void visit(AstCell* nodep) override {
        if (m_modp) {
            Instance inst;
            inst.name = nodep->name();
            inst.origName = nodep->origName();
            inst.child = nodep->modp() ? nodep->modp()->name() : nodep->modName();
            inst.childOrig = nodep->modp() ? nodep->modp()->origName() : nodep->modName();
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
        iterateChildren(nodep);
    }

    void visit(AstCase* nodep) override {
        AstCase* const oldCasep = m_casep;
        m_casep = nodep;
        iterateChildren(nodep);
        m_casep = oldCasep;
    }

    void visit(AstCaseItem* nodep) override {
        if (m_casep) addBranch(nodep, m_casep->verilogKwd(), "item");
        iterateChildren(nodep);
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

    string facts() const {
        std::ostringstream os;
        os << "{\n  \"schema_version\": \"hdl_facts.v2\",\n"
           << "  \"tool\": {\"name\": \"verilator\", \"source\": \"elaborated-ast\"},\n  \"modules\": [";
        for (size_t i = 0; i < m_modules.size(); ++i) {
            const Module& mod = m_modules[i];
            if (i) os << ",";
            os << "{\"id\": " << quote("module:" + mod.name) << ", \"name\": " << quote(mod.name)
               << ", \"top\": " << (mod.top ? "true" : "false") << "}";
        }
        os << "],\n  \"parameters\": [],\n  \"ports\": [";
        bool first = true;
        for (const Module& mod : m_modules) for (const Port& port : mod.ports) {
            if (!first) os << ",";
            first = false;
            os << "{\"id\": " << quote("module:" + mod.name + "/port:" + port.name)
               << ", \"module_id\": " << quote("module:" + mod.name)
               << ", \"name\": " << quote(port.name) << ", \"direction\": " << quote(port.direction)
               << ", \"width\": " << port.width << "}";
        }
        os << "],\n  \"instances\": [";
        first = true;
        for (const Module& mod : m_modules) for (const Instance& inst : mod.instances) {
            if (!first) os << ",";
            first = false;
            os << "{\"id\": " << quote("module:" + mod.name + "/instance:" + inst.name)
               << ", \"module_id\": " << quote("module:" + mod.name) << ", \"child\": " << quote(inst.child) << "}";
        }
        os << "],\n  \"pin_bindings\": [],\n  \"expressions\": [],\n  \"dataflow_edges\": [],\n"
           << "  \"control_edges\": [],\n  \"clock_reset_checks\": [],\n  \"local_address_facts\": [],\n"
           << "  \"source_locations\": [],\n  \"source_symbols\": [],\n  \"diagnostics\": []\n}\n";
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

string V3VIFrontend::factsJson(AstNetlist* rootp) {
    FrontendCollector collector{rootp};
    return collector.facts();
}

void V3VIFrontend::clearLastManifest() {
    s_lastManifestJson.clear();
}

const string& V3VIFrontend::lastManifestJson() {
    return s_lastManifestJson;
}
