// myfuzz frontend driver: Verilator parsing/elaboration without backend emission.

#define VL_MT_CONTROL_CODE_UNIT 1

#include "MyFuzzFrontend.h"

#include "V3Ast.h"
#include "V3Dead.h"
#include "V3Error.h"
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
#include "V3Stats.h"
#include "V3Udp.h"
#include "V3VIFrontend.h"
#include "V3Width.h"
#include "V3WidthCommit.h"
#include "V3Param.h"

#include <cstdlib>

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

}  // namespace

namespace myfuzz {

std::string frontendManifestJson(const std::vector<std::string>& args) {
    V3VIFrontend::clearLastManifest();
    std::vector<std::string> owned;
    owned.emplace_back("myfuzz_frontend");
    owned.insert(owned.end(), args.begin(), args.end());
    std::vector<char*> argv = makeArgv(owned);

    v3Global.boot();
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
    // V3VIFrontend emits facts from the elaborated tree.  Keeping this as a
    // separate public entry point lets composition consume that stable source
    // without changing the legacy instrumentation manifest ABI.
    return frontendManifestJson(args);
}

}  // namespace myfuzz
