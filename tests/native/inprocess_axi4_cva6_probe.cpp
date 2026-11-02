// Native probe: a real CVA6 AXI4 CPU archive linked against the existing
// full-AXI4 processor-memory adapter, driven here as one process with host RAM.
//
// What it is and is not:
//
//   * The CPU is the real generated model of the pinned
//     cv64a6_imafdc_sv39 configuration (`local_runtime_processor`, the archive
//     produced by the CVA6 F1-F4 run).  The AXI4 side is the same 45-role
//     `processor.memory.unified` packed master the profile declares: one AXI4
//     port for both the I-cache and the D-cache.
//   * The AXI4 target side is the repository's own
//     `src/myfuzz/protocols/rtl/axi4_processor_memory_adapter.sv`, Verilated with
//     ADDRESS_WIDTH=64, DATA_WIDTH=64, ID_WIDTH=4, USER_WIDTH=64.  It is the
//     existing CPU-side AXI4 -> beat adapter, not a new host-side AXI4 slave, so
//     the multi-beat and response sequencing under test is the RTL's.
//   * The host serves the adapter's single beat channel from a sparse host RAM.
//     No AXI4 channel state machine is written here.
//   * Identity is the pinned configuration's own ARID/RID map: the I-cache is
//     request 0 and return id 0 (wt_axi_adapter.sv).  Every accepted beat is
//     classified from the ID it really carried; an address never decides.
//   * Retirement: the generated runtime top does not export the CVA6 RVFI bundle
//     (the profile leaves `rvfi_probes_o` unconnected), so this probe has no
//     retirement witness and prints `retirement unknown`.  A store reaching RAM
//     and a load value being consumed are real architectural effects of executed
//     instructions, but they are not an RVFI retirement witness and are not
//     reported as one.
//
// Cases:
//   A  program at 0x8000_0000 (cached region) stores 0x11, loads 0x20008 and
//      stores the loaded 0x1234, then loops.  This proves real fetch (2-beat
//      I-cache line fills), real load, real store.
//   B  the same slot is rewritten with 0x22 and the CPU is not reset.  With no
//      fence.i the I-cache keeps the old line, so the CPU keeps executing 0x11.
//      The probe reports whether the rewrite was observed.
//   C  hard reset, install the fence.i variant (0x33), run.  Reports whether the
//      reset refetched the cached line.
//   D  rewrite to 0x44 while the fence.i loop runs.  The next iteration executes
//      fence.i and refetches the line, so the new value is observed.
//
// Build (see scripts/run_inprocess_axi4_cpu_probe.py for the exact command and
// source identity checks):
//   verilator --cc --exe --build -j 2 --top-module axi4_processor_memory_adapter
//     -Wno-fatal -GADDRESS_WIDTH=64 -GDATA_WIDTH=64 -GID_WIDTH=4 -GUSER_WIDTH=64
//     --Mdir <build>/adapter src/myfuzz/protocols/rtl/axi4_processor_memory_adapter.sv
//     <dummy-main>
//   g++ -std=c++17 -O2 -I <cva6-obj> -I <adapter-obj> -I <verilator-include>
//       tests/native/inprocess_axi4_cva6_probe.cpp
//       <cva6-obj>/Vlocal_runtime_processor__ALL.a
//       <adapter-obj>/Vaxi4_processor_memory_adapter__ALL.a
//       <verilator-include>/verilated.cpp <verilator-include>/verilated_threads.cpp
//       -pthread -latomic -o inprocess_axi4_cva6_probe
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

#include "../../scripts/inprocess_axi4_identity.h"

namespace {

constexpr uint64_t kBootAddress = 0x10000;        // profile boot_addr_i constant
constexpr uint64_t kProgramBase = 0x80000000;     // CachedRegionAddrBase
constexpr uint64_t kDataBase = 0x20000;           // uncached data window
constexpr unsigned kProgramWords = 8;             // one 16-byte line pair + slack

// --- sparse host RAM -------------------------------------------------------
// A byte map, so a partial write strobe writes exactly the lanes it selected and
// an unprogrammed read returns zero instead of whatever a previous case left.
class Ram {
 public:
  uint64_t read64(uint64_t aligned) const {
    uint64_t word = 0;
    for (unsigned byte = 0; byte < 8; ++byte) {
      const auto it = bytes_.find(aligned + byte);
      if (it != bytes_.end()) word |= uint64_t(it->second) << (8 * byte);
    }
    return word;
  }

  void write_be(uint64_t aligned, uint64_t data, unsigned strobe) {
    for (unsigned byte = 0; byte < 8; ++byte) {
      if (!(strobe & (1u << byte))) continue;
      bytes_[aligned + byte] = uint8_t((data >> (8 * byte)) & 0xffu);
    }
  }

  uint32_t peek32(uint64_t address) const {
    return uint32_t(read64(address & ~uint64_t(7)) >> (8 * (address & 7)));
  }

  void poke32(uint64_t address, uint32_t value) { write_be(address & ~uint64_t(7),
                                                          uint64_t(value) << (8 * (address & 7)),
                                                          0xfu << (address & 7)); }

  void poke_program(uint64_t base, const std::vector<uint32_t> &words) {
    for (std::size_t index = 0; index < words.size(); ++index)
      poke32(base + 4 * index, words[index]);
  }

 private:
  std::map<uint64_t, uint8_t> bytes_;
};

std::vector<uint32_t> program_no_fence(uint32_t value) {
  return {
      0x00020537u,           // lui   a0, 0x20        -> a0 = 0x20000
      0x00000593u | (value << 20),  // addi  a1, x0, value
      0x00b52023u,           // sw    a1, 0(a0)       -> [0x20000] = value
      0x00852603u,           // lw    a2, 8(a0)       -> a2 = [0x20008]
      0x00c52223u,           // sw    a2, 4(a0)       -> [0x20004] = a2
      0xfedff06fu,           // jal   x0, -20         -> 0x8000_0000
  };
}

std::vector<uint32_t> program_with_fence(uint32_t value) {
  return {
      0x00020537u,                  // lui   a0, 0x20
      0x00000593u | (value << 20),  // addi  a1, x0, value
      0x00b52023u,                  // sw    a1, 0(a0)
      0x0000100fu,                  // fence.i
      0x00852603u,                  // lw    a2, 8(a0)
      0x00c52223u,                  // sw    a2, 4(a0)
      0xfe9ff06fu,                  // jal   x0, -24         -> 0x8000_0000
  };
}

std::string hex(uint64_t value) {
  char text[32];
  std::snprintf(text, sizeof(text), "0x%llx", static_cast<unsigned long long>(value));
  return text;
}

struct Beat {
  bool active = false;
  bool write = false;
  uint64_t address = 0;
  uint64_t wdata = 0;
  unsigned strobe = 0;
  uint64_t rdata = 0;
  bool error = false;
};

struct Store {
  uint64_t tick = 0;
  uint64_t address = 0;
  uint64_t value = 0;
};

class Probe {
 public:
  explicit Probe(uint64_t max_ticks) : max_ticks_(max_ticks) {}

  int run(const std::string &archive_identity);

 private:
  void settle();
  void edge();
  void tick();
  void reset_cpu();
  void run_ticks(const char *what, uint64_t count);

  void note_request(uint64_t address, unsigned arid, unsigned arlen, unsigned arsize);
  void note_response(unsigned rid, uint64_t data, unsigned rlast);
  void note_write(uint64_t address, uint64_t data, unsigned strobe);
  void dump_phase(const char *name, uint64_t ticks, unsigned long long ar, unsigned long long r,
                  unsigned long long aw, unsigned long long w, unsigned long long b,
                  unsigned long long ar_program, unsigned long long beats);
  bool saw_boot_fetch() const { return saw_boot_fetch_; }
  void report(const char *key, const std::string &value) {
    std::printf("%s %s\n", key, value.c_str());
  }

  VerilatedContext context_;
  Vlocal_runtime_processor cpu_{&context_, "cpu"};
  Vaxi4_processor_memory_adapter adapter_{&context_, "adapter"};
  Ram ram_;
  Axi4CpuIdentity identity_ = Axi4CpuIdentity::packed_instruction_ids(0, 0);
  Axi4ChannelCounts counts_;
  Beat beat_;
  uint64_t tick_ = 0;
  uint64_t max_ticks_ = 20000;
  bool saw_boot_fetch_ = false;
  uint64_t boot_fetch_tick_ = 0;
  unsigned boot_fetch_arid_ = 0;
  unsigned boot_fetch_arlen_ = 0;
  unsigned long long program_ar_ = 0;      // accepted AR inside the program window
  unsigned long long beats_ = 0;           // adapter-side req handshakes
  unsigned long long w_full_strb_ = 0;     // W beats with every byte lane selected
  unsigned long long w_partial_strb_ = 0;  // W beats with a narrow strobe
  unsigned long long aw_size3_ = 0;        // AW beats declared as an 8-byte transfer
  unsigned long long aw_size2_ = 0;        // AW beats declared as a 4-byte transfer
  std::vector<Store> stores_;
  std::vector<Store> loads_;
  std::vector<std::pair<uint64_t, uint32_t>> store_log_;   // writes to 0x20000
};

void Probe::settle() {
  for (unsigned pass = 0; pass < 3; ++pass) {
    cpu_.eval();
    adapter_.awid_i = cpu_.axi_awid;
    adapter_.awaddr_i = cpu_.axi_awaddr;
    adapter_.awlen_i = cpu_.axi_awlen;
    adapter_.awsize_i = cpu_.axi_awsize;
    adapter_.awburst_i = cpu_.axi_awburst;
    adapter_.awlock_i = cpu_.axi_awlock;
    adapter_.awcache_i = cpu_.axi_awcache;
    adapter_.awprot_i = cpu_.axi_awprot;
    adapter_.awqos_i = cpu_.axi_awqos;
    adapter_.awregion_i = cpu_.axi_awregion;
    adapter_.awatop_i = cpu_.axi_awatop;
    adapter_.awuser_i = cpu_.axi_awuser;
    adapter_.awvalid_i = cpu_.axi_awvalid;
    adapter_.wdata_i = cpu_.axi_wdata;
    adapter_.wstrb_i = cpu_.axi_wstrb;
    adapter_.wlast_i = cpu_.axi_wlast;
    adapter_.wuser_i = cpu_.axi_wuser;
    adapter_.wvalid_i = cpu_.axi_wvalid;
    adapter_.bready_i = cpu_.axi_bready;
    adapter_.arid_i = cpu_.axi_arid;
    adapter_.araddr_i = cpu_.axi_araddr;
    adapter_.arlen_i = cpu_.axi_arlen;
    adapter_.arsize_i = cpu_.axi_arsize;
    adapter_.arburst_i = cpu_.axi_arburst;
    adapter_.arlock_i = cpu_.axi_arlock;
    adapter_.arcache_i = cpu_.axi_arcache;
    adapter_.arprot_i = cpu_.axi_arprot;
    adapter_.arqos_i = cpu_.axi_arqos;
    adapter_.arregion_i = cpu_.axi_arregion;
    adapter_.aruser_i = cpu_.axi_aruser;
    adapter_.arvalid_i = cpu_.axi_arvalid;
    adapter_.rready_i = cpu_.axi_rready;
    // The beat side: one outstanding request, one response per request.
    adapter_.req_ready_i = beat_.active ? 0 : 1;
    adapter_.rsp_valid_i = beat_.active ? 1 : 0;
    adapter_.rsp_rdata_i = beat_.rdata;
    adapter_.rsp_error_i = beat_.error ? 1 : 0;
    adapter_.eval();
    cpu_.axi_awready = adapter_.awready_o;
    cpu_.axi_arready = adapter_.arready_o;
    cpu_.axi_wready = adapter_.wready_o;
    cpu_.axi_bvalid = adapter_.bvalid_o;
    cpu_.axi_bid = adapter_.bid_o;
    cpu_.axi_bresp = adapter_.bresp_o;
    cpu_.axi_buser = adapter_.buser_o;
    cpu_.axi_rvalid = adapter_.rvalid_o;
    cpu_.axi_rid = adapter_.rid_o;
    cpu_.axi_rdata = adapter_.rdata_o;
    cpu_.axi_rresp = adapter_.rresp_o;
    cpu_.axi_rlast = adapter_.rlast_o;
    cpu_.axi_ruser = adapter_.ruser_o;
  }
}

void Probe::edge() {
  cpu_.clk = 1;
  adapter_.clk_i = 1;
  cpu_.eval();
  adapter_.eval();
  cpu_.clk = 0;
  adapter_.clk_i = 0;
  cpu_.eval();
  adapter_.eval();
}

void Probe::note_request(uint64_t address, unsigned arid, unsigned arlen,
                         unsigned arsize) {
  const Axi4CpuIdentity::Kind kind = identity_.request(arid, false);
  counts_.count_request(kind);
  const bool in_program = address >= kProgramBase && address < kProgramBase + 4 * kProgramWords;
  if (in_program) ++program_ar_;
  std::printf("ar %llu %s id=%u len=%u size=%u kind=%s\n",
              static_cast<unsigned long long>(tick_), hex(address).c_str(), arid, arlen,
              arsize, kind == Axi4CpuIdentity::Instruction ? "instruction" : "data");
  if (!saw_boot_fetch_ && address == kBootAddress) {
    saw_boot_fetch_ = true;
    boot_fetch_tick_ = tick_;
    boot_fetch_arid_ = arid;
    boot_fetch_arlen_ = arlen;
  }
}

void Probe::note_response(unsigned rid, uint64_t data, unsigned rlast) {
  const Axi4CpuIdentity::Kind kind = identity_.response(rid);
  counts_.count_response(kind);
  std::printf("r %llu %s id=%u last=%u kind=%s\n",
              static_cast<unsigned long long>(tick_), hex(data).c_str(), rid, rlast,
              kind == Axi4CpuIdentity::Instruction ? "instruction" : "data");
}

void Probe::note_write(uint64_t address, uint64_t data, unsigned strobe) {
  const Store store{tick_, address, data};
  stores_.push_back(store);
  if (address == kDataBase) store_log_.emplace_back(tick_, uint32_t(data));
  std::printf("write %llu %s data=%s strb=%x\n",
              static_cast<unsigned long long>(tick_), hex(address).c_str(),
              hex(data).c_str(), strobe);
}

void Probe::tick() {
  cpu_.clk = 0;
  adapter_.clk_i = 0;
  settle();

  // Pre-edge samples: the values that the coming rising edge captures.
  const bool ar_hs = cpu_.axi_arvalid && adapter_.arready_o;
  const bool r_hs = adapter_.rvalid_o && cpu_.axi_rready;
  const bool aw_hs = cpu_.axi_awvalid && adapter_.awready_o;
  const bool w_hs = cpu_.axi_wvalid && adapter_.wready_o;
  const bool b_hs = adapter_.bvalid_o && cpu_.axi_bready;
  const bool req_hs = adapter_.req_valid_o && adapter_.req_ready_i;
  const bool rsp_hs = adapter_.rsp_valid_i && adapter_.rsp_ready_o;

  if (ar_hs) note_request(cpu_.axi_araddr, cpu_.axi_arid, cpu_.axi_arlen, cpu_.axi_arsize);
  if (r_hs) note_response(adapter_.rid_o, adapter_.rdata_o, adapter_.rlast_o);
  if (aw_hs) {
    ++counts_.aw;
    ++counts_.aw_data;
    if (cpu_.axi_awsize == 3) ++aw_size3_;
    if (cpu_.axi_awsize == 2) ++aw_size2_;
    std::printf("aw %llu %s id=%u len=%u size=%u\n",
                static_cast<unsigned long long>(tick_),
                hex(cpu_.axi_awaddr).c_str(), cpu_.axi_awid, cpu_.axi_awlen,
                cpu_.axi_awsize);
  }
  if (w_hs) {
    ++counts_.w;
    ++counts_.w_data;
    if (cpu_.axi_wstrb == 0xff) ++w_full_strb_;
    else ++w_partial_strb_;
    std::printf("w %llu data=%s strb=%x last=%u\n",
                static_cast<unsigned long long>(tick_),
                hex(cpu_.axi_wdata).c_str(), cpu_.axi_wstrb, cpu_.axi_wlast);
  }
  if (b_hs) {
    ++counts_.b;
    ++counts_.b_data;
    std::printf("b %llu id=%u resp=%u\n", static_cast<unsigned long long>(tick_),
                adapter_.bid_o, adapter_.bresp_o);
  }
  if (req_hs) {
    ++beats_;
    ++counts_.beats;
    beat_.active = true;
    beat_.write = adapter_.req_write_o;
    beat_.address = adapter_.req_addr_o;
    beat_.wdata = adapter_.req_wdata_o;
    beat_.strobe = adapter_.req_be_o;
    if (beat_.write) {
      ram_.write_be(beat_.address & ~uint64_t(7), beat_.wdata, beat_.strobe);
      beat_.rdata = 0;
      note_write(beat_.address, beat_.wdata, beat_.strobe);
    } else {
      beat_.rdata = ram_.read64(beat_.address & ~uint64_t(7));
      loads_.push_back(Store{tick_, beat_.address, beat_.rdata});
      std::printf("beat_read %llu %s data=%s\n",
                  static_cast<unsigned long long>(tick_), hex(beat_.address).c_str(),
                  hex(beat_.rdata).c_str());
    }
  }
  if (rsp_hs) std::printf("beat_rsp %llu %s\n",
                          static_cast<unsigned long long>(tick_),
                          beat_.write ? "write" : "read");

  edge();
  ++tick_;
  if (rsp_hs) beat_.active = false;
  if (tick_ > max_ticks_) {
    std::printf("stop tick_budget %llu\n", static_cast<unsigned long long>(tick_));
    std::exit(EXIT_FAILURE);
  }
}

void Probe::reset_cpu() {
  // The generated runtime top normalizes reset to active high and the adapter's
  // rst_ni is active low; both are asserted together, as the driver does.
  beat_ = Beat();
  cpu_.rt_lh_p_7_0_0 = 0;
  cpu_.rt_lh_p_12_0_0 = 0;
  cpu_.reset = 0;
  adapter_.rst_ni = 0;
  cpu_.clk = 0;
  adapter_.clk_i = 0;
  settle();
  cpu_.reset = 1;
  settle();
  for (unsigned index = 0; index < 12; ++index) edge();
  cpu_.reset = 0;
  adapter_.rst_ni = 1;
  settle();
  for (unsigned index = 0; index < 8; ++index) edge();
}

void Probe::run_ticks(const char *what, uint64_t count) {
  (void)what;
  for (uint64_t index = 0; index < count; ++index) tick();
}

void Probe::dump_phase(const char *name, uint64_t ticks, unsigned long long ar,
                       unsigned long long r, unsigned long long aw, unsigned long long w,
                       unsigned long long b, unsigned long long ar_program,
                       unsigned long long beats) {
  std::printf("phase %s ticks=%llu ar=%llu r=%llu aw=%llu w=%llu b=%llu "
              "ar_program=%llu beatreq=%llu\n",
              name, static_cast<unsigned long long>(ticks), ar, r, aw, w, b, ar_program,
              beats);
}

int Probe::run(const std::string &archive_identity) {
  cpu_.rt_lh_p_7_0_0 = 0;
  cpu_.rt_lh_p_12_0_0 = 0;
  cpu_.reset = 0;
  adapter_.rst_ni = 0;

  ram_.poke_program(kBootAddress,
                    {0x00100513u, 0x01f51513u, 0x00050067u});  // li a0,1<<31; jr a0
  ram_.poke_program(kProgramBase, program_no_fence(0x11));
  ram_.poke32(kDataBase + 8, 0x1234u);

  std::printf("probe cva6 archive=%s\n", archive_identity.c_str());
  std::printf("identity packed arid_mask=0x0001 rid_mask=0x0001 source=wt_axi_adapter.sv\n");
  std::printf("adapter axi4_processor_memory_adapter ADDRESS_WIDTH=64 DATA_WIDTH=64 "
              "ID_WIDTH=4 USER_WIDTH=64\n");
  std::printf("boot_address %s program_base %s data_base %s\n",
              hex(kBootAddress).c_str(), hex(kProgramBase).c_str(), hex(kDataBase).c_str());

  reset_cpu();

  // --- boot: the first fetch must be the profile's boot address -------------
  uint64_t boot_ticks = 0;
  while (!saw_boot_fetch_ && boot_ticks < 800) {
    tick();
    ++boot_ticks;
  }
  if (!saw_boot_fetch_) {
    std::printf("verdict boot_fetch=missing budget=%llu\n",
                static_cast<unsigned long long>(boot_ticks));
    return EXIT_FAILURE;
  }
  std::printf("verdict boot_fetch=observed tick=%llu address=%s arid=%u arlen=%u\n",
              static_cast<unsigned long long>(boot_fetch_tick_), hex(kBootAddress).c_str(),
              boot_fetch_arid_, boot_fetch_arlen_);

  // --- case A: real fetch (two-beat line fill), real load, real store -------
  auto ar0 = counts_.ar, r0 = counts_.r, aw0 = counts_.aw, w0 = counts_.w, b0 = counts_.b;
  auto prog0 = program_ar_, beats0 = beats_;
  run_ticks("A", 900);
  dump_phase("A", 900, counts_.ar - ar0, counts_.r - r0, counts_.aw - aw0,
             counts_.w - w0, counts_.b - b0, program_ar_ - prog0, beats_ - beats0);
  const uint32_t case_a_store = ram_.peek32(kDataBase);
  const uint32_t case_a_loaded = ram_.peek32(kDataBase + 4);
  std::printf("case A store_value %s loaded_and_stored %s ar_program %llu\n",
              hex(case_a_store).c_str(), hex(case_a_loaded).c_str(),
              static_cast<unsigned long long>(program_ar_));
  if (case_a_store != 0x11u || case_a_loaded != 0x1234u) {
    std::printf("verdict case_A=missing (store=%s loaded=%s)\n",
                hex(case_a_store).c_str(), hex(case_a_loaded).c_str());
    return EXIT_FAILURE;
  }
  std::printf("verdict case_A=observed (real fetch, load 0x1234 through RAM, store 0x11)\n");

  // --- case B: rewrite the same slot, no reset, no fence.i ------------------
  const auto program_ar_before_b = program_ar_;
  const auto store_count_before_b = store_log_.size();
  ram_.poke_program(kProgramBase, program_no_fence(0x22));
  std::printf("rewrite case_B address=%s value=0x22 fence=none tick=%llu\n",
              hex(kProgramBase).c_str(), static_cast<unsigned long long>(tick_));
  ar0 = counts_.ar; r0 = counts_.r; aw0 = counts_.aw; w0 = counts_.w; b0 = counts_.b;
  prog0 = program_ar_; beats0 = beats_;
  run_ticks("B", 900);
  dump_phase("B", 900, counts_.ar - ar0, counts_.r - r0, counts_.aw - aw0,
             counts_.w - w0, counts_.b - b0, program_ar_ - prog0, beats_ - beats0);
  const auto program_ar_b = program_ar_ - program_ar_before_b;
  bool saw_22 = false, saw_11 = false;
  for (std::size_t index = store_count_before_b; index < store_log_.size(); ++index) {
    if (store_log_[index].second == 0x22u) saw_22 = true;
    if (store_log_[index].second == 0x11u) saw_11 = true;
  }
  std::printf("case B ar_program_after_rewrite %llu stores_since_rewrite %zu "
              "saw_0x11 %d saw_0x22 %d\n",
              static_cast<unsigned long long>(program_ar_b),
              store_log_.size() - store_count_before_b, int(saw_11), int(saw_22));
  const char *case_b = program_ar_b == 0 && saw_11 && !saw_22
                           ? "stale_line_no_refetch"
                           : (saw_22 ? "refetched" : "unknown");
  std::printf("verdict case_B=%s\n", case_b);

  // --- case C: hard reset, fence.i program, watch the cached line -----------
  ram_.poke_program(kProgramBase, program_with_fence(0x33));
  const auto program_ar_before_c = program_ar_;
  reset_cpu();
  ar0 = counts_.ar; r0 = counts_.r; aw0 = counts_.aw; w0 = counts_.w; b0 = counts_.b;
  prog0 = program_ar_; beats0 = beats_;
  run_ticks("C", 900);
  dump_phase("C", 900, counts_.ar - ar0, counts_.r - r0, counts_.aw - aw0,
             counts_.w - w0, counts_.b - b0, program_ar_ - prog0, beats_ - beats0);
  const auto program_ar_c = program_ar_ - program_ar_before_c;
  const uint32_t case_c_store = ram_.peek32(kDataBase);
  std::printf("case C ar_program_after_reset %llu last_store %s\n",
              static_cast<unsigned long long>(program_ar_c), hex(case_c_store).c_str());
  std::printf("verdict case_C=%s\n",
              program_ar_c > 0 && case_c_store == 0x33u ? "refetch_after_reset" : "unknown");

  // --- case D: rewrite while the fence.i loop runs --------------------------
  const auto store_count_before_d = store_log_.size();
  ram_.poke_program(kProgramBase, program_with_fence(0x44));
  std::printf("rewrite case_D address=%s value=0x44 fence=fence.i tick=%llu\n",
              hex(kProgramBase).c_str(), static_cast<unsigned long long>(tick_));
  ar0 = counts_.ar; r0 = counts_.r; aw0 = counts_.aw; w0 = counts_.w; b0 = counts_.b;
  prog0 = program_ar_; beats0 = beats_;
  run_ticks("D", 900);
  dump_phase("D", 900, counts_.ar - ar0, counts_.r - r0, counts_.aw - aw0,
             counts_.w - w0, counts_.b - b0, program_ar_ - prog0, beats_ - beats0);
  bool saw_44 = false;
  for (std::size_t index = store_count_before_d; index < store_log_.size(); ++index)
    if (store_log_[index].second == 0x44u) saw_44 = true;
  const uint32_t case_d_store = ram_.peek32(kDataBase);
  std::printf("case D last_store %s saw_0x44 %d\n", hex(case_d_store).c_str(), int(saw_44));
  std::printf("verdict case_D=%s\n", saw_44 ? "refetched_after_fence" : "stale");

  std::printf("summary ticks=%llu ar=%llu r=%llu aw=%llu w=%llu b=%llu "
              "ar_instruction=%llu ar_data=%llu r_instruction=%llu r_data=%llu "
              "aw_data=%llu w_data=%llu b_data=%llu beatreq=%llu\n",
              static_cast<unsigned long long>(tick_), counts_.ar, counts_.r, counts_.aw,
              counts_.w, counts_.b, counts_.ar_instruction, counts_.ar_data,
              counts_.r_instruction, counts_.r_data, counts_.aw_data, counts_.w_data,
              counts_.b_data, counts_.beats);
  std::printf("w_channels full_strb=%llu partial_strb=%llu aw_size3=%llu aw_size2=%llu\n",
              w_full_strb_, w_partial_strb_, aw_size3_, aw_size2_);
  std::printf("retirement unknown rvfi_pin=absent source=artifact.rvfi_probes_o_unconnected\n");
  std::printf("store_values");
  for (std::size_t index = 0; index < store_log_.size() && index < 64; ++index)
    std::printf(" %s", hex(store_log_[index].second).c_str());
  std::printf("\n");
  std::printf("cache_no_fence=%s cache_with_fence=%s\n", case_b,
              saw_44 ? "refetched" : "stale");
  cpu_.final();
  adapter_.final();
  return EXIT_SUCCESS;
}

}  // namespace

int main(int argc, char **argv) {
  const uint64_t max_ticks = argc > 1 ? std::strtoull(argv[1], nullptr, 0) : 20000;
  const std::string identity = argc > 2 ? argv[2] : "unstated";
  std::printf("probe_start max_ticks=%llu\n", static_cast<unsigned long long>(max_ticks));
  Probe probe(max_ticks);
  return probe.run(identity);
}
