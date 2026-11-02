// Unit test for the AXI4 CPU identity declaration (no RTL, no Verilator).
//
// What it pins down:
//   * the CVA6 pinned map is ARID 0 -> instruction, every other ARID -> data,
//     and RID 0 -> instruction, every other RID -> data (wt_axi_adapter.sv);
//   * a write is data on both declarations, even with the instruction ARID;
//   * an undeclared identity reports Unknown and never Instruction, so a caller
//     that forgot the declaration cannot count fetches from data beats;
//   * the structural (Vexii) declaration is per channel, not per ID.
//
// Build/run:
//   g++ -std=c++17 -Wall -Wextra -Werror tests/native/inprocess_axi4_identity_test.cpp
//       -o /tmp/myfuzz-axi4-identity-test && /tmp/myfuzz-axi4-identity-test
#include <cstdio>
#include <cstdlib>

#include "../../scripts/inprocess_axi4_identity.h"

namespace {

int failures = 0;
int expectations = 0;

void expect(bool condition, const char *what) {
  ++expectations;
  if (condition) return;
  std::fprintf(stderr, "FAIL %s\n", what);
  ++failures;
}

const char *name(Axi4CpuIdentity::Kind kind) {
  switch (kind) {
    case Axi4CpuIdentity::Instruction: return "instruction";
    case Axi4CpuIdentity::Data: return "data";
    default: return "unknown";
  }
}

}  // namespace

int main() {
  // --- CVA6 packed declaration (ARID 0 / RID 0 = I-cache) -------------------
  const Axi4CpuIdentity cva6 = Axi4CpuIdentity::packed_instruction_ids(0, 0);
  expect(cva6.instruction_id_declared(), "cva6 declares an instruction id");
  expect(cva6.request(0, false) == Axi4CpuIdentity::Instruction,
         "cva6 ARID 0 is an instruction fetch");
  for (unsigned id = 1; id < 16; ++id) {
    expect(cva6.request(id, false) == Axi4CpuIdentity::Data,
           "cva6 ARID != 0 is a data read");
    expect(cva6.response(id) == Axi4CpuIdentity::Data,
           "cva6 RID != 0 is a data response");
  }
  expect(cva6.response(0) == Axi4CpuIdentity::Instruction,
         "cva6 RID 0 is an instruction response");
  // The direction comes from the channel, not from the address: a write with the
  // instruction ID is still data (the core never does that; the classifier must
  // not turn it into a fetch if it ever did).
  expect(cva6.request(0, true) == Axi4CpuIdentity::Data,
         "a write is data even on ARID 0");
  expect(cva6.request_channel('i') == Axi4CpuIdentity::Unknown,
         "a packed identity has no per-port channel classification");
  expect(cva6.response_channel('d') == Axi4CpuIdentity::Unknown,
         "a packed identity has no per-port channel classification");

  // --- undeclared identity --------------------------------------------------
  const Axi4CpuIdentity none = Axi4CpuIdentity::undeclared();
  expect(!none.instruction_id_declared(), "undeclared identity states it");
  expect(none.request(0, false) == Axi4CpuIdentity::Unknown,
         "undeclared identity: no fetch identity");
  expect(none.response(0) == Axi4CpuIdentity::Unknown,
         "undeclared identity: no response identity");
  expect(none.request(0, true) == Axi4CpuIdentity::Data,
         "a write is still data without a declared id");

  // --- structural declaration (Vexii i_* / d_*) -----------------------------
  const Axi4CpuIdentity structural = Axi4CpuIdentity::structural();
  expect(structural.instruction_id_declared(), "structural identity is declared");
  expect(structural.request_channel('i') == Axi4CpuIdentity::Instruction,
         "i_* request is an instruction fetch");
  expect(structural.request_channel('d') == Axi4CpuIdentity::Data,
         "d_* request is data");
  expect(structural.response_channel('i') == Axi4CpuIdentity::Instruction,
         "i_* response is an instruction response");
  expect(structural.response_channel('d') == Axi4CpuIdentity::Data,
         "d_* response is data");
  expect(structural.request_channel('x') == Axi4CpuIdentity::Unknown,
         "an undeclared structural channel is unknown");
  expect(structural.request(0, false) == Axi4CpuIdentity::Unknown,
         "a structural identity needs the channel, not an id");

  // --- counters -------------------------------------------------------------
  Axi4ChannelCounts counts;
  Axi4CpuIdentity::Kind kinds[] = {Axi4CpuIdentity::Instruction,
                                   Axi4CpuIdentity::Data,
                                   Axi4CpuIdentity::Unknown};
  for (Axi4CpuIdentity::Kind kind : kinds) {
    counts.count_request(kind);
    counts.count_response(kind);
  }
  expect(counts.ar == 3 && counts.r == 3, "three requests and responses counted");
  expect(counts.ar_instruction == 1 && counts.ar_data == 1 && counts.ar_unknown == 1,
         "the request identity split is kept");
  expect(counts.r_instruction == 1 && counts.r_data == 1 && counts.r_unknown == 1,
         "the response identity split is kept");
  // The two sides are independent: a response must be counted from R, not from
  // the request that happened to be earlier.
  counts.count_response(Axi4CpuIdentity::Instruction);
  expect(counts.r == 4 && counts.ar == 3, "responses are counted on R only");

  if (failures) {
    std::fprintf(stderr, "%d identity expectation(s) failed\n", failures);
    return EXIT_FAILURE;
  }
  std::printf("axi4 identity: %d expectations passed (%s)\n", expectations,
              name(Axi4CpuIdentity::Data));
  return EXIT_SUCCESS;
}
