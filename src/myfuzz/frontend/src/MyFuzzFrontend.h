#ifndef MYFUZZ_FRONTEND_H_
#define MYFUZZ_FRONTEND_H_

#include <mutex>
#include <string>
#include <vector>

namespace myfuzz {

std::string frontendManifestJson(const std::vector<std::string>& args);
// Facts are the elaborated Verilator AST observations.  The legacy manifest
// entry point remains available for the existing instrumentation flow.
std::string frontendFactsJson(const std::vector<std::string>& args);
std::mutex& frontendInvocationMutex();
void frontendSetLastError(std::string value);

}  // namespace myfuzz

#endif
