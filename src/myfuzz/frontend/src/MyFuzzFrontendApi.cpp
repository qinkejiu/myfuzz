#include "MyFuzzFrontend.h"

#include <cstdlib>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::string s_lastError;

char* copyCString(const std::string& value) {
    char* const out = static_cast<char*>(std::malloc(value.size() + 1));
    if (!out) return nullptr;
    std::memcpy(out, value.c_str(), value.size() + 1);
    return out;
}

}  // namespace

extern "C" const char* myfuzz_frontend_last_error() {
    return s_lastError.c_str();
}

extern "C" void myfuzz_frontend_free(char* value) {
    std::free(value);
}

extern "C" char* myfuzz_frontend_manifest_json(int argc, const char* const* argv) {
    s_lastError.clear();
    if (argc < 0 || (argc > 0 && !argv)) {
        s_lastError = "invalid frontend arguments";
        return nullptr;
    }
    std::vector<std::string> args;
    args.reserve(argc);

    try {
        for (int i = 0; i < argc; ++i) {
            if (!argv[i]) throw std::invalid_argument("frontend argument is null");
            args.emplace_back(argv[i]);
        }
        std::string manifest = myfuzz::frontendManifestJson(args);
        if (manifest.empty()) {
            s_lastError = "myfuzz frontend did not produce a manifest";
            return nullptr;
        }
        char* out = copyCString(manifest);
        if (!out) s_lastError = "unable to allocate frontend manifest";
        return out;
    } catch (const std::exception& ex) {
        s_lastError = ex.what();
        return nullptr;
    } catch (...) {
        s_lastError = "unknown myfuzz frontend exception";
        return nullptr;
    }
}

extern "C" char* myfuzz_frontend_facts_json(int argc, const char* const* argv) {
    s_lastError.clear();
    if (argc < 0 || (argc > 0 && !argv)) {
        s_lastError = "invalid frontend arguments";
        return nullptr;
    }
    std::vector<std::string> args;
    args.reserve(argc);

    try {
        for (int i = 0; i < argc; ++i) {
            if (!argv[i]) throw std::invalid_argument("frontend argument is null");
            args.emplace_back(argv[i]);
        }
        std::string facts = myfuzz::frontendFactsJson(args);
        if (facts.empty()) {
            s_lastError = "myfuzz frontend did not produce facts";
            return nullptr;
        }
        char* out = copyCString(facts);
        if (!out) s_lastError = "unable to allocate frontend facts";
        return out;
    } catch (const std::exception& ex) {
        s_lastError = ex.what();
        return nullptr;
    } catch (...) {
        s_lastError = "unknown myfuzz frontend exception";
        return nullptr;
    }
}
