#ifndef MYFUZZ_FRONTEND_H_
#define MYFUZZ_FRONTEND_H_

#include <string>
#include <vector>

namespace myfuzz {

std::string frontendManifestJson(const std::vector<std::string>& args);

}  // namespace myfuzz

#endif
