// Minimal Verilator global/runtime implementation for myfuzz frontend parsing.

#define VL_MT_CONTROL_CODE_UNIT 1

#include "V3Ast.h"
#include "V3Broken.h"
#include "V3File.h"
#include "V3Global.h"
#include "V3LibMap.h"
#include "V3LinkCells.h"
#include "V3Parse.h"
#include "V3ParseImp.h"
#include "V3PreShell.h"

#include <iomanip>
#include <stdexcept>
#include <string>

VL_DEFINE_DEBUG_FUNCTIONS;

V3Global v3Global;

void V3Global::boot() {
    UASSERT(!m_rootp, "call once");
    m_rootp = new AstNetlist;
    m_libMapp = new V3LibMap;
}

void V3Global::shutdown() {
    V3PreShell::shutdown();
    VL_DO_CLEAR(delete m_hierGraphp, m_hierGraphp = nullptr);
    VL_DO_CLEAR(delete m_threadPoolp, m_threadPoolp = nullptr);
    VL_DO_CLEAR(delete m_libMapp, m_libMapp = nullptr);
    if (m_rootp) VL_DO_CLEAR(m_rootp->deleteTree(), m_rootp = nullptr);
    FileLine::deleteAllRemaining();
}

void V3Global::vlExit(int status) {
    throw std::runtime_error{"Verilator frontend failed with status " + std::to_string(status)};
}

void V3Global::checkTree() const { rootp()->checkTree(); }

void V3Global::readFiles() {
    const VNUser4InUse inuser4;
    VInFilter filter{v3Global.opt.pipeFilter()};

    {
        V3Parse parser{v3Global.rootp(), &filter};

        if (v3Global.opt.stdWaiver()) {
            parser.parseFile(new FileLine{V3Options::getStdWaiverPath()},
                             V3Options::getStdWaiverPath(), false, false, "work",
                             "Cannot find verilated_std_waiver.vlt: ");
        }
        for (const VFileLibName& filelib : v3Global.opt.vltFiles()) {
            parser.parseFile(new FileLine{FileLine::commandLineFilename()}, filelib.filename(),
                             false, false, filelib.libname(),
                             "Cannot find file containing .vlt file: ");
        }
        if (v3Global.opt.stdPackage()) {
            parser.parseFile(new FileLine{V3Options::getStdPackagePath()},
                             V3Options::getStdPackagePath(), false, false, "work",
                             "Cannot find verilated_std.sv: ");
        }
        for (const string& filename : v3Global.opt.libmapFiles()) {
            parser.parseFile(new FileLine{FileLine::commandLineFilename()}, filename, false, true,
                             "work", "Cannot find file containing libmap definitions: ");
        }

        V3LibMap::map(v3Global.rootp());

        for (const auto& filelib : v3Global.opt.vFiles()) {
            const string& libname = filelib.libname() == "work"
                                        ? v3Global.libMapp()->matchMapping(filelib.filename())
                                        : filelib.libname();
            parser.parseFile(new FileLine{FileLine::commandLineFilename()}, filelib.filename(),
                             false, false, libname, "Cannot find file containing module: ");
        }
        for (const auto& filelib : v3Global.opt.libraryFiles()) {
            parser.parseFile(new FileLine{FileLine::commandLineFilename()}, filelib.filename(),
                             true, false, filelib.libname(),
                             "Cannot find file containing library module: ");
        }
        for (const auto& filelib : v3Global.opt.hierParamFile()) {
            parser.parseFile(new FileLine{FileLine::commandLineFilename()}, filelib.filename(),
                             false, false, filelib.libname(),
                             "Cannot open file containing hierarchical parameter declarations: ");
        }
    }

    V3Error::abortIfErrors();
    if (!v3Global.opt.preprocOnly() || v3Global.opt.preprocResolve()) {
        V3LinkCells::link(v3Global.rootp(), &filter);
    }
    V3Global::dumpCheckGlobalTree("cells", false, dumpTreeEitherLevel() >= 9);
}

void V3Global::removeStd() {
    if (!usesStdPackage()) {
        if (AstNodeModule* stdp = v3Global.rootp()->stdPackagep()) {
            v3Global.rootp()->stdPackagep(nullptr);
            v3Global.rootp()->stdPackageProcessp(nullptr);
            VL_DO_DANGLING(stdp->unlinkFrBack()->deleteTree(), stdp);
        }
    }
}

string V3Global::debugFilename(const string& nameComment, int newNumber) {
    ++m_debugFileNumber;
    if (newNumber) m_debugFileNumber = newNumber;
    return opt.hierTopDataDir() + "/" + opt.prefix() + "_" + digitsFilename(m_debugFileNumber)
           + "_" + nameComment;
}

string V3Global::digitsFilename(int number) {
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(3) << number;
    return ss.str();
}

void V3Global::dumpCheckGlobalTree(const string& stagename, int newNumber, bool doDump,
                                   bool doCheck) {
    (void)stagename;
    (void)newNumber;
    if (doDump && dumpTreeLevel()) {
        v3Global.rootp()->dumpTreeFile(v3Global.debugFilename(stagename + ".tree", newNumber),
                                       doDump);
    }
    if (doCheck && (v3Global.opt.debugCheck() || dumpTreeEitherLevel())) {
        v3Global.rootp()->checkTree();
        V3Broken::brokenAll(v3Global.rootp());
    }
}

void V3Global::idPtrMapDumpJson(std::ostream& os) {
    os << "\"pointers\": {}";
}

void V3Global::saveJsonPtrFieldName(const std::string& fieldName) {
    m_jsonPtrNames.insert(fieldName);
}

void V3Global::ptrNamesDumpJson(std::ostream& os) {
    std::string sep = "\n  ";
    os << "\"ptrFieldNames\": [";
    for (const auto& itr : m_jsonPtrNames) {
        os << sep << '"' << itr << '"';
        sep = ",\n  ";
    }
    os << "\n ]";
}

const std::string& V3Global::ptrToId(const void* p) {
    const auto pair = m_ptrToId.emplace(p, "");
    if (pair.second) {
        std::ostringstream os;
        if (p) {
            os << "(";
            unsigned id = m_ptrToId.size();
            do { os << static_cast<char>('A' + id % 26); } while (id /= 26);
            os << ")";
        } else {
            os << "0";
        }
        pair.first->second = os.str();
    }
    return pair.first->second;
}

std::vector<std::string> V3Global::verilatedCppFiles() {
    return {};
}
