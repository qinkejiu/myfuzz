// myfuzz frontend driver: Verilator parsing/elaboration without backend emission.

#define VL_MT_CONTROL_CODE_UNIT 1

#include "MyFuzzFrontend.h"

#include "V3Ast.h"
#include "V3Dead.h"
#include "V3Error.h"
#include "V3File.h"
#include "V3Global.h"
#include "V3LinkDot.h"
#include "V3LinkDotIfaceCapture.h"
#include "V3LinkInc.h"
#include "V3LinkJump.h"
#include "V3LinkLValue.h"
#include "V3LinkLevel.h"
#include "V3LinkParse.h"
#include "V3LinkResolve.h"
#include "V3LinkWith.h"
#include "V3Options.h"
#include "V3Os.h"
#include "V3PreShell.h"
#include "V3String.h"
#include "V3Stats.h"
#include "V3Udp.h"
#include "V3VIFrontend.h"
#include "V3Width.h"
#include "V3WidthCommit.h"
#include "V3Param.h"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <set>
#include <stdexcept>
#include <vector>

VL_DEFINE_DEBUG_FUNCTIONS;

namespace {

void runFrontendPasses() {
    V3LinkLevel::modSortByLevel();
    V3Error::abortIfErrors();
    if (v3Global.opt.debugExitParse()) return;

    V3LinkParse::linkParse(v3Global.rootp());
    V3LinkDot::linkDotPrimary(v3Global.rootp());
    v3Global.checkTree();
    v3Global.opt.checkParameters();
    V3LinkResolve::linkResolve(v3Global.rootp());
    V3LinkLValue::linkLValue(v3Global.rootp());
    V3LinkJump::linkJump(v3Global.rootp());
    V3LinkInc::linkIncrements(v3Global.rootp());
    V3Error::abortIfErrors();

    V3Param::param(v3Global.rootp());
    V3LinkDot::linkDotParamed(v3Global.rootp());
    V3Param::finalizeDeferredParams(v3Global.rootp());
    V3LinkLValue::linkLValue(v3Global.rootp());
    V3LinkWith::linkWith(v3Global.rootp());
    V3Error::abortIfErrors();

    V3LinkDotIfaceCapture::finalizeIfaceCapture();
    V3Dead::deadifyModules(v3Global.rootp());
    v3Global.checkTree();
    if (v3Global.hasTable()) V3Udp::udpResolve(v3Global.rootp());

    V3Width::width(v3Global.rootp());
    V3Error::abortIfErrors();
    V3WidthCommit::widthCommit(v3Global.rootp());
    v3Global.assertDTypesResolved(true);
    v3Global.widthMinUsage(VWidthMinUsage::MATCHES_WIDTH);
}

std::vector<char*> makeArgv(std::vector<std::string>& owned) {
    std::vector<char*> argv;
    argv.reserve(owned.size());
    for (std::string& item : owned) argv.push_back(item.data());
    return argv;
}

void resetFrontendGlobal() {
    if (v3Global.rootp())
        throw std::logic_error{"cannot reset Verilator while an AST is live"};
    std::destroy_at(&v3Global);
    std::construct_at(&v3Global);
    V3File::clearDependencies();
    V3Error::resetSession();
}

std::string canonicalHashPath(const std::string& arg) {
    std::error_code error;
    const std::filesystem::path path{arg};
    if (std::filesystem::is_regular_file(path, error)) return "<file>";
    error.clear();
    if (std::filesystem::is_directory(path, error)) return "<directory>";
    return "<path>";
}

std::vector<std::string> canonicalHashArgs(const std::vector<std::string>& args) {
    static const std::set<std::string> pathValueOptions{
        "-F", "-I", "-Mdir", "-f", "-v", "-y", "--Mdir"};
    std::vector<std::string> canonical;
    canonical.reserve(args.size());
    bool pathValue = false;
    for (const std::string& arg : args) {
        if (pathValue) {
            canonical.push_back(canonicalHashPath(arg));
            pathValue = false;
            continue;
        }
        if (pathValueOptions.contains(arg)) {
            canonical.push_back(arg);
            pathValue = true;
            continue;
        }
        if (arg.rfind("--Mdir=", 0) == 0 || arg.rfind("-Mdir=", 0) == 0) {
            canonical.push_back(arg.substr(0, arg.find('=') + 1) + "<directory>");
            continue;
        }
        if (arg.rfind("-I", 0) == 0 && arg.size() > 2) {
            canonical.push_back("-I<directory>");
            continue;
        }
        if (arg.rfind("+incdir+", 0) == 0) {
            std::string value = "+incdir+<directory>";
            for (size_t pos = 8; (pos = arg.find('+', pos)) != std::string::npos; ++pos)
                value += "+<directory>";
            canonical.push_back(std::move(value));
            continue;
        }

        std::error_code error;
        const std::filesystem::path path{arg};
        if (std::filesystem::is_regular_file(path, error)
            || (!arg.empty() && arg.front() != '-' && arg.front() != '+'
                && (path.is_absolute() || arg.find('/') != std::string::npos))) {
            canonical.push_back("<file>");
            continue;
        }
        error.clear();
        if (std::filesystem::is_directory(path, error)) {
            canonical.push_back("<directory>");
            continue;
        }
        canonical.push_back(arg);
    }
    if (pathValue) canonical.push_back("<missing-path-value>");
    return canonical;
}

std::string frontendInputHash(const std::vector<std::string>& args) {
    VHashSha256 digest;
    for (const std::string& canonicalArg : canonicalHashArgs(args)) {
        digest.insert(static_cast<uint64_t>(canonicalArg.size()));
        digest.insert(canonicalArg);
    }

    digest.insert(static_cast<uint64_t>(v3Global.opt.vFiles().size()));
    for (const VFileLibName& source : v3Global.opt.vFiles()) {
        VHashSha256 sourceDigest;
        sourceDigest.insertFile(source.filename());
        digest.insert(sourceDigest.digestBinary());
    }

    const std::vector<std::string> dependencies = V3File::getAllDepsInReadOrder();
    digest.insert(static_cast<uint64_t>(dependencies.size()));
    for (const std::string& dependency : dependencies) {
        VHashSha256 dependencyDigest;
        dependencyDigest.insertFile(dependency);
        digest.insert(dependencyDigest.digestBinary());
    }
    return "sha256:" + digest.digestHex();
}

}  // namespace

namespace myfuzz {

std::string frontendManifestJson(const std::vector<std::string>& args) {
    V3VIFrontend::clearLastManifest();
    std::vector<std::string> owned;
    owned.emplace_back("myfuzz_frontend");
    owned.insert(owned.end(), args.begin(), args.end());
    std::vector<char*> argv = makeArgv(owned);

    resetFrontendGlobal();
    v3Global.boot();
    v3Global.assertDTypesResolved(false);
    v3Global.assertScoped(false);
    v3Global.widthMinUsage(VWidthMinUsage::LINT_WIDTH);
    try {
        const char* rootp = std::getenv("VERILATOR_ROOT");
        if (!rootp || !*rootp) {
            const char* envp = std::getenv("MYFUZZ_FRONTEND_VERILATOR_ROOT");
            if (envp && *envp) {
                V3Os::setenvStr("VERILATOR_ROOT", envp, "myfuzz frontend root");
            }
        }

        V3PreShell::boot();
        v3Global.opt.buildDepBin("myfuzz_frontend");
        v3Global.opt.parseOpts(new FileLine{FileLine::commandLineFilename()},
                               static_cast<int>(argv.size()) - 1, argv.data() + 1);

        v3Global.opt.notify();
        v3Global.rootp()->timeInit();
        V3Error::abortIfErrors();

        v3Global.readFiles();
        v3Global.removeStd();
        if (!v3Global.opt.preprocOnly()) runFrontendPasses();
        V3Error::abortIfErrors();
        V3VIFrontend::emitManifest(v3Global.rootp());
        std::string manifest = V3VIFrontend::lastManifestJson();
        v3Global.rootp()->deleteContents();
        v3Global.shutdown();
        return manifest;
    } catch (...) {
        v3Global.shutdown();
        throw;
    }
}

std::string frontendFactsJson(const std::vector<std::string>& args) {
    V3VIFrontend::clearLastManifest();
    std::vector<std::string> owned;
    owned.emplace_back("myfuzz_frontend");
    owned.insert(owned.end(), args.begin(), args.end());
    std::vector<char*> argv = makeArgv(owned);
    resetFrontendGlobal();
    v3Global.boot();
    v3Global.assertDTypesResolved(false);
    v3Global.assertScoped(false);
    v3Global.widthMinUsage(VWidthMinUsage::LINT_WIDTH);
    try {
        const char* rootp = std::getenv("VERILATOR_ROOT");
        if ((!rootp || !*rootp) && std::getenv("MYFUZZ_FRONTEND_VERILATOR_ROOT"))
            V3Os::setenvStr("VERILATOR_ROOT", std::getenv("MYFUZZ_FRONTEND_VERILATOR_ROOT"), "myfuzz frontend root");
        V3PreShell::boot();
        v3Global.opt.buildDepBin("myfuzz_frontend");
        v3Global.opt.parseOpts(new FileLine{FileLine::commandLineFilename()}, static_cast<int>(argv.size()) - 1,
                               argv.data() + 1);
        v3Global.opt.notify();
        v3Global.rootp()->timeInit();
        V3Error::abortIfErrors();
        v3Global.readFiles();
        v3Global.removeStd();
        if (!v3Global.opt.preprocOnly()) runFrontendPasses();
        V3Error::abortIfErrors();
        std::string facts = V3VIFrontend::factsJson(v3Global.rootp(), frontendInputHash(args));
        v3Global.rootp()->deleteContents();
        v3Global.shutdown();
        return facts;
    } catch (...) {
        v3Global.shutdown();
        throw;
    }
}

}  // namespace myfuzz
