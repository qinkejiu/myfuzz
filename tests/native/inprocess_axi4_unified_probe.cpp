// Native probe for the reusable CVA6 packed-AXI4 host link
// (scripts/inprocess_axi4_host.h) against the CURRENT CVA6 cache/model.
//
// What runs:
//   * the real generated packed CVA6 model `local_runtime_processor` from
//     runs/round1-cva6-cache/<digest>/obj/Vlocal_runtime_processor__ALL.a,
//   * the repository's existing `axi4_processor_memory_adapter` RTL elaborated
//     with ADDRESS_WIDTH=64 DATA_WIDTH=64 ID_WIDTH=4 USER_WIDTH=64,
//   * a sparse byte-addressed host RAM owned by this probe.
//
// The probe does not re-implement any AXI4 channel logic: every handshake and
// every beat comes out of the adapter, and the CPU<->adapter wiring, sampling,
// identity classification and 64-bit/32-bit conversion all live in the header
// under test.  The probe only supplies RAM behind the header's beat service.
//
// Program (RV64, program_base 0x8000_0000, uncached data window 0x2000_0xxx):
//   ld  a4, 0x30(a0)   ; 8-byte data read, assembled from two 32-bit RAM words
//   lw  a5, 8(a0)      ; 4-byte data read of the preloaded 0x1234
//   sw  a5, 4(a0)      ; data write
//   sd  a2, 0x10(a0)   ; 0x1122_3344_5566_7788 -> two 32-bit RAM words
//   sd  a4, 0x20(a0)   ; the value the 8-byte read returned -> round trip
//   sb  a5, 0x18(a0)   ; one byte lane (WSTRB 0x01)
//   jal x0, ld         ; keep reading so the explicit-beat phase sees traffic
//
// Build/run: python3 scripts/run_inprocess_axi4_unified_probe.py
#include "Vaxi4_processor_memory_adapter.h"
#include "Vlocal_runtime_processor.h"
#include "verilated.h"

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <string>
#include <vector>

#include "../../scripts/inprocess_axi4_host.h"

namespace {

using myfuzz::axi4::BeatRequest;
using myfuzz::axi4::BeatResponse;
using myfuzz::axi4::CpuLink;
using myfuzz::axi4::Observation;
using myfuzz::axi4::WordAccess;

constexpr std::uint64_t kBootAddress = 0x10000;     // artifact boot_contract
constexpr std::uint64_t kProgramBase = 0x80000000;  // CachedRegionAddrBase
constexpr std::uint64_t kDataBase = 0x20000;        // uncached data window

// --- sparse host RAM: 32-bit words, byte lanes exactly as WSTRB selected ----
class Ram {
 public:
  std::uint32_t read32(std::uint64_t address) const {
    std::uint64_t word = 0;
    for (unsigned byte = 0; byte < 4; ++byte) {
      const auto it = bytes_.find(address + byte);
      if (it != bytes_.end()) word |= std::uint64_t(it->second) << (8 * byte);
    }
    return std::uint32_t(word);
  }

  void write32(std::uint64_t address, std::uint32_t value, unsigned be) {
    for (unsigned byte = 0; byte < 4; ++byte) {
      if (!(be & (1u << byte))) continue;
      bytes_[address + byte] = std::uint8_t((value >> (8 * byte)) & 0xffu);
    }
  }

  std::uint32_t peek32(std::uint64_t address) const {
    return read32(address & ~std::uint64_t(3));
  }

  void poke32(std::uint64_t address, std::uint32_t value) {
    write32(address & ~std::uint64_t(3), value, 0x0fu);
  }

  void poke_program(std::uint64_t base, const std::vector<std::uint32_t> &words) {
    for (std::size_t index = 0; index < words.size(); ++index)
      poke32(base + 4 * index, words[index]);
  }

 private:
  std::map<std::uint64_t, std::uint8_t> bytes_;
};

// The header's beat service: one 64-bit beat -> the 32-bit words a word RAM has.
bool service_ram(void *context, const BeatRequest &request, BeatResponse &response) {
  Ram &ram = *static_cast<Ram *>(context);
  WordAccess words[2];
  const unsigned count = CpuLink::split_beat(request, words);
  if (request.write) {
    for (unsigned index = 0; index < count; ++index)
      ram.write32(words[index].address, words[index].value, words[index].be);
    response.rdata = 0;
    response.error = false;
    return true;
  }
  std::uint32_t low = 0;
  std::uint32_t high = 0;
  for (unsigned index = 0; index < count; ++index) {
    const std::uint32_t value = ram.read32(words[index].address);
    if ((words[index].address & 4) != 0) high = value;
    else low = value;
  }
  response.rdata = CpuLink::join_beat_read(low, high);
  response.error = false;
  return true;
}

std::uint32_t jal_x0(std::int32_t offset) {
  const std::uint32_t imm = std::uint32_t(offset) & 0x1fffffu;
  return (((imm >> 20) & 1u) << 31) | (((imm >> 1) & 0x3ffu) << 21) |
         (((imm >> 11) & 1u) << 20) | (((imm >> 12) & 0xffu) << 12) | 0x6fu;
}

std::vector<std::uint32_t> program() {
  std::vector<std::uint32_t> words = {
      0x00020537u,  // lui   a0, 0x20              -> a0 = 0x20000
      0x03053703u,  // ld    a4, 0x30(a0)          -> 0xdeadbeefcafebabe
      0x00852783u,  // lw    a5, 8(a0)             -> 0x1234
      0x00f52223u,  // sw    a5, 4(a0)             -> [0x20004] = 0x1234
      0x11223637u,  // lui   a2, 0x11223
      0x34460613u,  // addi  a2, a2, 0x344
      0x02061613u,  // slli  a2, a2, 32
      0x556676b7u,  // lui   a3, 0x55667
      0x78868693u,  // addi  a3, a3, 0x788
      0x00d66633u,  // or    a2, a2, a3            -> 0x1122334455667788
      0x00c53823u,  // sd    a2, 0x10(a0)
      0x02e53023u,  // sd    a4, 0x20(a0)
      0x00f50c23u,  // sb    a5, 0x18(a0)
  };
  // Loop back to `ld` so the explicit-beat phase keeps seeing real beats.
  const std::int32_t offset =
      4 * (std::int32_t(1) - std::int32_t(words.size()));
  words.push_back(jal_x0(offset));
  return words;
}

std::string hex(std::uint64_t value) {
  char text[32];
  std::snprintf(text, sizeof(text), "0x%llx",
                static_cast<unsigned long long>(value));
  return text;
}

struct ExpectedWord {
  std::uint64_t address;
  std::uint32_t value;
  const char *name;
};

class Probe {
 public:
  explicit Probe(std::uint64_t max_ticks) : max_ticks_(max_ticks) {}

  int run(const std::string &archive_identity);

 private:
  int split_self_test();
  void load_ram();
  void reset();
  void note();          // count the channel facts of the current observation
  void step();          // one full tick with the beat service
  bool expected_ram() const;
  void report_ram(const char *label) const;

  VerilatedContext context_;
  Vlocal_runtime_processor cpu_{&context_, "cpu"};
  Vaxi4_processor_memory_adapter adapter_{&context_, "adapter"};
  CpuLink link_{cpu_, adapter_};
  Ram ram_;
  std::uint64_t max_ticks_ = 4000;
  unsigned long long aw8_ = 0;      // AW beats that declared an 8-byte transfer
  unsigned long long aw4_ = 0;      // AW beats that declared a 4-byte transfer
  unsigned long long r_errors_ = 0;  // sampled R beats with RRESP != OKAY
  unsigned long long b_errors_ = 0;  // sampled B beats with BRESP != OKAY
  unsigned long long data_r_beats_ = 0;
  unsigned long long data_read_0x30_ = 0;
  std::uint64_t last_data_rdata_ = 0;
  unsigned long long explicit_beats_ = 0;
};

int Probe::split_self_test() {
  WordAccess words[2];
  unsigned checks = 0;
  unsigned failures = 0;
  auto expect = [&](bool condition) {
    ++checks;
    if (!condition) ++failures;
    return condition;
  };

  // 8-byte store, every lane selected: two 32-bit words, each with its nibble.
  const BeatRequest full{true, kDataBase + 0x10, 0x1122334455667788ull, 0xff};
  unsigned count = CpuLink::split_beat(full, words);
  expect(count == 2);
  expect(words[0].address == kDataBase + 0x10);
  expect(words[0].value == 0x55667788u);
  expect(words[0].be == 0x0fu);
  expect(words[1].address == kDataBase + 0x14);
  expect(words[1].value == 0x11223344u);
  expect(words[1].be == 0x0fu);
  std::printf("selftest full_store words=%u low=%s:%s/0x%x high=%s:%s/0x%x\n",
              count, hex(words[0].address).c_str(), hex(words[0].value).c_str(),
              words[0].be, hex(words[1].address).c_str(),
              hex(words[1].value).c_str(), words[1].be);

  // The upper 32-bit word only: one access, AXI lanes 4..7 -> be 0x0f inside
  // that word.  AXI data lanes are absolute, so the value rides in wdata[63:32].
  const BeatRequest upper{true, kDataBase + 0x04, 0x1234ull << 32, 0xf0};
  count = CpuLink::split_beat(upper, words);
  expect(count == 1);
  expect(words[0].address == kDataBase + 0x04);
  expect(words[0].value == 0x1234u);
  expect(words[0].be == 0x0fu);
  std::printf("selftest upper_store words=%u address=%s value=%s be=0x%x\n",
              count, hex(words[0].address).c_str(), hex(words[0].value).c_str(),
              words[0].be);

  // One byte lane: one access, be 0x01.
  const BeatRequest lane{true, kDataBase + 0x18, 0x34u, 0x01};
  count = CpuLink::split_beat(lane, words);
  expect(count == 1);
  expect(words[0].address == kDataBase + 0x18);
  expect(words[0].be == 0x01u);
  std::printf("selftest byte_lane words=%u address=%s value=%s be=0x%x\n",
              count, hex(words[0].address).c_str(), hex(words[0].value).c_str(),
              words[0].be);

  // 8-byte read: both words, and the join reproduces the 64-bit payload.
  const BeatRequest read{false, kDataBase + 0x30, 0, 0xff};
  count = CpuLink::split_beat(read, words);
  expect(count == 2);
  expect(words[0].address == kDataBase + 0x30);
  expect(words[1].address == kDataBase + 0x34);
  const std::uint64_t joined = CpuLink::join_beat_read(0xcafebabeu, 0xdeadbeefu);
  expect(joined == 0xdeadbeefcafebabeull);
  std::printf("selftest full_read words=%u low=%s high=%s joined=%s\n", count,
              hex(words[0].address).c_str(), hex(words[1].address).c_str(),
              hex(joined).c_str());

  std::printf("selftest split_beat=%s checks=%u failures=%u\n",
              failures == 0 ? "pass" : "fail", checks, failures);
  return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

void Probe::load_ram() {
  // Boot trampoline: li a0, 1<<31 ; jr a0  -> jumps to the cached program.
  ram_.poke_program(kBootAddress, {0x00100513u, 0x01f51513u, 0x00050067u});
  ram_.poke_program(kProgramBase, program());
  ram_.poke32(kDataBase + 0x08, 0x00001234u);  // 4-byte data read source
  ram_.poke32(kDataBase + 0x30, 0xcafebabeu);  // 8-byte data read source
  ram_.poke32(kDataBase + 0x34, 0xdeadbeefu);
}

void Probe::reset() {
  link_.set_reset(true);
  link_.settle();
  for (unsigned index = 0; index < 12; ++index) link_.clock_edge();
  link_.set_reset(false);
  link_.settle();
  for (unsigned index = 0; index < 8; ++index) link_.clock_edge();
  link_.forget();  // reset edges are not a sampling window
}

void Probe::note() {
  const Observation &observed = link_.observation();
  if (observed.aw.valid) {
    if (observed.aw.size == 3) ++aw8_;
    else if (observed.aw.size == 2) ++aw4_;
  }
  if (observed.r.valid) {
    if (observed.r.resp != 0) ++r_errors_;
    if (observed.r.kind == Axi4CpuIdentity::Data) {
      ++data_r_beats_;
      last_data_rdata_ = observed.r.data;
    }
  }
  if (observed.b.valid && observed.b.resp != 0) ++b_errors_;
  if (observed.ar.valid && observed.ar.address == kDataBase + 0x30) ++data_read_0x30_;
}

void Probe::step() {
  link_.tick();
  note();
  if (link_.ticks() > max_ticks_) {
    std::printf("stop tick_budget ticks=%llu\n",
                static_cast<unsigned long long>(link_.ticks()));
    std::exit(EXIT_FAILURE);
  }
}

bool Probe::expected_ram() const {
  const ExpectedWord expected[] = {
      {kDataBase + 0x04, 0x00001234u, "sw_word"},
      {kDataBase + 0x10, 0x55667788u, "sd_low"},
      {kDataBase + 0x14, 0x11223344u, "sd_high"},
      {kDataBase + 0x18, 0x00000034u, "sb_lane"},
      {kDataBase + 0x20, 0xcafebabeu, "roundtrip_low"},
      {kDataBase + 0x24, 0xdeadbeefu, "roundtrip_high"},
  };
  for (const ExpectedWord &word : expected)
    if (ram_.peek32(word.address) != word.value) return false;
  return true;
}

void Probe::report_ram(const char *label) const {
  std::printf(
      "ram %s sw_0x04=%s sd_0x10=%s sd_0x14=%s sb_0x18=%s rt_0x20=%s rt_0x24=%s\n",
      label, hex(ram_.peek32(kDataBase + 0x04)).c_str(),
      hex(ram_.peek32(kDataBase + 0x10)).c_str(),
      hex(ram_.peek32(kDataBase + 0x14)).c_str(),
      hex(ram_.peek32(kDataBase + 0x18)).c_str(),
      hex(ram_.peek32(kDataBase + 0x20)).c_str(),
      hex(ram_.peek32(kDataBase + 0x24)).c_str());
}

int Probe::run(const std::string &archive_identity) {
  std::printf("probe cva6_unified archive=%s\n", archive_identity.c_str());
  std::printf(
      "identity packed arid_mask=0x0001 rid_mask=0x0001 source=wt_axi_adapter.sv\n");
  std::printf(
      "adapter axi4_processor_memory_adapter ADDRESS_WIDTH=64 DATA_WIDTH=64 "
      "ID_WIDTH=4 USER_WIDTH=64\n");
  std::printf("header inprocess_axi4_host.h API=CpuLink split_beat=64to32\n");
  std::printf("boot_address %s program_base %s data_base %s\n",
              hex(kBootAddress).c_str(), hex(kProgramBase).c_str(),
              hex(kDataBase).c_str());

  if (split_self_test() != EXIT_SUCCESS) {
    std::printf("verdict all=fail reason=split_selftest\n");
    return EXIT_FAILURE;
  }

  load_ram();
  link_.set_beat_service(service_ram, &ram_);
  reset();

  // --- boot: the first accepted AR must be the profile's boot address ---------
  bool saw_boot = false;
  std::uint64_t boot_tick = 0;
  unsigned boot_arid = 0;
  unsigned boot_arlen = 0;
  Axi4CpuIdentity::Kind boot_kind = Axi4CpuIdentity::Unknown;
  const std::uint64_t boot_start = link_.ticks();
  while (!saw_boot && link_.ticks() - boot_start < 800) {
    step();
    const auto &ar = link_.observation().ar;
    if (ar.valid && ar.address == kBootAddress) {
      saw_boot = true;
      boot_tick = ar.tick;
      boot_arid = ar.id;
      boot_arlen = ar.len;
      boot_kind = ar.kind;
    }
  }
  if (!saw_boot) {
    std::printf("verdict boot_fetch=missing ticks=%llu\n",
                static_cast<unsigned long long>(link_.ticks()));
    std::printf("verdict all=fail\n");
    return EXIT_FAILURE;
  }
  std::printf(
      "verdict boot_fetch=observed tick=%llu address=%s arid=%u arlen=%u kind=%s\n",
      static_cast<unsigned long long>(boot_tick), hex(kBootAddress).c_str(),
      boot_arid, boot_arlen, CpuLink::kind_name(boot_kind));

  // --- phase A: execute the program until its RAM effects are all visible ----
  const auto ar_before = link_.counts().ar;
  const auto r_before = link_.counts().r;
  const auto aw_before = link_.counts().aw;
  const auto w_before = link_.counts().w;
  const auto b_before = link_.counts().b;
  const auto beats_before = link_.traffic().requests;
  const std::uint64_t phase_start = link_.ticks();
  while (!expected_ram() && link_.ticks() - phase_start < 1500) step();
  const std::uint64_t phase_ticks = link_.ticks() - phase_start;

  report_ram("observed");
  std::printf(
      "phase A ticks=%llu ar=%llu r=%llu aw=%llu w=%llu b=%llu beats=%llu\n",
      static_cast<unsigned long long>(phase_ticks),
      static_cast<unsigned long long>(link_.counts().ar - ar_before),
      static_cast<unsigned long long>(link_.counts().r - r_before),
      static_cast<unsigned long long>(link_.counts().aw - aw_before),
      static_cast<unsigned long long>(link_.counts().w - w_before),
      static_cast<unsigned long long>(link_.counts().b - b_before),
      static_cast<unsigned long long>(link_.traffic().requests - beats_before));

  bool passed = true;
  auto check = [&](bool condition, const char *name, const char *detail) {
    std::printf("check %s=%s%s%s\n", name, condition ? "pass" : "fail",
                detail[0] != '\0' ? " detail=" : "", detail);
    if (!condition) passed = false;
  };
  check(boot_arid == 0, "boot_arid", "packed i-cache id 0");
  check(boot_kind == Axi4CpuIdentity::Instruction, "boot_identity",
        "ARID 0 classified instruction");
  check(link_.counts().r_data > 0, "data_read", "R beat classified data");
  check(link_.counts().aw_data > 0, "data_write", "AW beat classified data");
  check(link_.counts().b_data > 0, "write_response", "B beat classified data");
  check(r_errors_ == 0, "rresp_okay", "every sampled RRESP is OKAY");
  check(b_errors_ == 0, "bresp_okay", "every sampled BRESP is OKAY");
  check(link_.counts().ar_instruction > 0 && link_.counts().ar_data > 0,
        "identity_split", "both instruction and data AR beats classified by ID");
  const ExpectedWord expected[] = {
      {kDataBase + 0x04, 0x00001234u, "sw_word"},
      {kDataBase + 0x10, 0x55667788u, "sd_low"},
      {kDataBase + 0x14, 0x11223344u, "sd_high"},
      {kDataBase + 0x18, 0x00000034u, "sb_lane"},
      {kDataBase + 0x20, 0xcafebabeu, "roundtrip_low"},
      {kDataBase + 0x24, 0xdeadbeefu, "roundtrip_high"},
  };
  for (const ExpectedWord &word : expected) {
    const std::uint32_t got = ram_.peek32(word.address);
    char detail[96];
    std::snprintf(detail, sizeof(detail), "%s got %s want %s",
                  hex(word.address).c_str(), hex(got).c_str(),
                  hex(word.value).c_str());
    check(got == word.value, word.name, detail);
  }
  check(aw8_ > 0, "aw_8byte_beats", "an 8-byte AW beat was sampled");
  check(link_.traffic().full_strobe > 0, "wstrb_full",
        "an 8-byte WSTRB=0xff beat reached the RAM split");
  std::printf(
      "verdict split_8byte_live=%s aw_size3=%llu aw_size2=%llu full_strb=%llu "
      "partial_strb=%llu\n",
      aw8_ > 0 ? "observed" : "not_observed",
      static_cast<unsigned long long>(aw8_),
      static_cast<unsigned long long>(aw4_),
      static_cast<unsigned long long>(link_.traffic().full_strobe),
      static_cast<unsigned long long>(link_.traffic().partial_strobe));
  std::printf("data_0x30_reads=%llu last_data_rdata=%s data_r_beats=%llu\n",
              static_cast<unsigned long long>(data_read_0x30_),
              hex(last_data_rdata_).c_str(),
              static_cast<unsigned long long>(data_r_beats_));

  // --- explicit beat path: no callback, answer through the public API --------
  link_.clear_beat_service();
  const auto explicit_before = link_.traffic().requests;
  const std::uint64_t explicit_start = link_.ticks();
  while (explicit_beats_ < 4 && link_.ticks() - explicit_start < 400 &&
         link_.ticks() < max_ticks_) {
    link_.begin_tick();
    BeatRequest request;
    if (link_.beat_request(request)) {
      BeatResponse response;
      service_ram(&ram_, request, response);
      link_.beat_response(response);
      ++explicit_beats_;
    }
    link_.end_tick();
    note();
  }
  std::printf(
      "phase B explicit_beats=%llu adapter_requests=%llu ticks=%llu\n",
      explicit_beats_,
      static_cast<unsigned long long>(link_.traffic().requests - explicit_before),
      static_cast<unsigned long long>(link_.ticks() - explicit_start));
  check(explicit_beats_ > 0, "explicit_beat_api",
        "beat_request/beat_response served a real beat");
  // The adapter is one-outstanding by construction: a beat served on the last
  // tick of the window legitimately still has its response in flight.
  const unsigned long long outstanding =
      link_.traffic().requests - link_.traffic().responses;
  check(outstanding <= 1, "beat_one_outstanding",
        "at most the adapter's one outstanding beat is open");

  std::printf(
      "summary ticks=%llu ar=%llu r=%llu aw=%llu w=%llu b=%llu "
      "ar_instruction=%llu ar_data=%llu r_instruction=%llu r_data=%llu "
      "aw_data=%llu w_data=%llu b_data=%llu\n",
      static_cast<unsigned long long>(link_.ticks()),
      link_.counts().ar, link_.counts().r, link_.counts().aw, link_.counts().w,
      link_.counts().b, link_.counts().ar_instruction, link_.counts().ar_data,
      link_.counts().r_instruction, link_.counts().r_data,
      link_.counts().aw_data, link_.counts().w_data, link_.counts().b_data);
  std::printf(
      "beat_traffic requests=%llu reads=%llu writes=%llu responses=%llu "
      "errors=%llu outstanding=%llu\n",
      link_.traffic().requests, link_.traffic().reads, link_.traffic().writes,
      link_.traffic().responses, link_.traffic().errors,
      link_.traffic().requests - link_.traffic().responses);
  std::printf("identity last_arid=%u last_rid=%u last_bid=%u boot_arid=%u\n",
              link_.last_ar_id(), link_.last_rid(), link_.last_bid(), boot_arid);
  std::printf(
      "retirement unknown rvfi_pin=absent source=artifact.rvfi_probes_o_unconnected\n");
  std::printf("verdict all=%s\n", passed ? "pass" : "fail");

  cpu_.final();
  adapter_.final();
  return passed ? EXIT_SUCCESS : EXIT_FAILURE;
}

}  // namespace

int main(int argc, char **argv) {
  std::uint64_t max_ticks = 4000;
  std::string identity = "unstated";
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "--max-ticks" && index + 1 < argc) {
      max_ticks = std::strtoull(argv[++index], nullptr, 0);
    } else if (argument == "--identity" && index + 1 < argc) {
      identity = argv[++index];
    } else {
      std::fprintf(stderr, "unknown argument: %s\n", argument.c_str());
      return EXIT_FAILURE;
    }
  }
  std::printf("probe_start max_ticks=%llu\n",
              static_cast<unsigned long long>(max_ticks));
  Probe probe(max_ticks);
  return probe.run(identity);
}
