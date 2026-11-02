// One initialized OBI CPU, one AXI4-Lite IP target and the host RAM.  The CPU
// fetches and executes real instructions from host RAM; the target's own
// AXI4-Lite slave port is driven by the generated AXI4-Lite bridge, whose beat
// side this host serves; every AXI4-Lite channel handshake is read from the
// passive per-tick taps of that port.  All of them are separate generated
// Verilator models: the address route, the RAM, the response timing and the
// fixed pin constants live in this host.
//
// What is wired comes from the macros the binding header declares (which models
// were generated, the I/O names of those models and the constant inputs the
// profile pins at a value).  There is no CPU x IP identity branch here: the same
// loop drives F1..F4, and a flow the selected components cannot serve is refused
// by name instead of being guessed.
//
// What is claimed and what is not: an AXI4-Lite write is accepted only when AW
// and W have each completed their handshake and B completes the pair; a read is
// AR followed by R.  BRESP/RRESP are physical pins, but this slave only ever
// drives OKAY, so the error path stays `unknown` (reported as such) instead of
// being claimed as covered.  No RVFI probe is requested beyond the retirement
// witness the CPU profile declares, and no trap/cause semantics are inferred.
#include "spike_config.h"
#include "verilated.h"
#include "inprocess_memory.h"
#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// The generated header states these for every target; the defaults keep an
// older binding readable instead of failing to compile.
#ifndef IP_FIXED_INPUT_COUNT
#define IP_FIXED_INPUT_COUNT 0
#endif
#ifndef IP_FIXED_INPUTS
#define IP_FIXED_INPUTS(X)
#endif

static constexpr uint32_t kRamBase = RAM_BASE, kRamSize = RAM_SIZE;
static constexpr uint32_t kIpBase = IP_BASE, kIpSize = IP_SIZE;
static constexpr uint32_t kSlot = SLOT_ADDRESS;
static constexpr uint32_t kCommand = MAILBOX_ADDRESS;
static constexpr uint32_t kArgument = MAILBOX_ADDRESS + 4;
static constexpr uint32_t kEcho = MAILBOX_ADDRESS + 8;
static constexpr uint32_t kValue = MAILBOX_ADDRESS + 12;
static constexpr uint32_t kDataBase = DATA_BASE;

using myfuzz::inprocess_spike::Memory;
using myfuzz::inprocess_spike::Response;

namespace {

// One AXI4-Lite request started by a real CPU data beat.  The address is the
// CPU's own byte address; the target offset is derived from the declared window.
struct Mmio {
  bool busy = false, sent = false, write = false;
  uint32_t address = 0, value = 0;
  unsigned be = 0;
};

// The five AXI4-Lite channels of one in-flight target transaction, sampled
// pre-edge once per host tick.  Each counter counts completed handshakes only.
struct Axil {
  bool pending = false, write = false;
  unsigned aw = 0, w = 0, b = 0, ar = 0, r = 0;
  uint32_t awaddr = 0, awprot = 0, wdata = 0, bresp = 0;
  uint32_t araddr = 0, arprot = 0, rdata = 0, rresp = 0;
  unsigned wstrb = 0;
};

enum Flow { kNone = 0, kF1 = 1, kF2 = 2, kF3 = 3, kF4 = 4 };

struct Record {
  Flow flow = kNone;
  uint32_t first = 0, second = 0;
};

struct Observation {
  unsigned i_fetches = 0, d_reads = 0, d_writes = 0, retires = 0;
  unsigned axi_reads = 0, axi_writes = 0;
  unsigned axi_aw = 0, axi_w = 0, axi_b = 0, axi_ar = 0, axi_r = 0;
  unsigned bresp_non_okay = 0, rresp_non_okay = 0;
  bool slot_fetch = false, slot_retire = false, slot_successor = false;
  uint32_t slot_fetch_address = 0, slot_retire_pc = 0, slot_retire_insn = 0;
  uint32_t slot_successor_pc = 0;
  bool read_accepted = false, read_from_ip = false, echo_stored = false;
  uint32_t read_address = 0, read_value = 0, echo_value = 0;
  bool write_accepted = false;
  uint32_t write_address = 0, write_value = 0, ram_before = 0;
  unsigned write_be = 0;
  uint32_t mmio_address = 0, mmio_value = 0;
  // The last completed AXI4-Lite transaction of this case: the values the
  // target's own pins carried, never a value derived from the profile.
  uint32_t axil_awaddr = 0, axil_awprot = 0, axil_wdata = 0, axil_bresp = 0;
  uint32_t axil_araddr = 0, axil_arprot = 0, axil_rdata = 0, axil_rresp = 0;
  unsigned axil_wstrb = 0;
};

std::string hex32(uint32_t value) {
  std::ostringstream text;
  text << "0x" << std::hex << std::setw(8) << std::setfill('0') << value;
  return text.str();
}

// Canonical record text, the same shape the Python entry accepts and sends.
std::string hex8(uint32_t value) {
  std::ostringstream text;
  text << std::hex << std::setw(8) << std::setfill('0') << value;
  return text.str();
}

std::string seconds_text(double value) {
  std::ostringstream text;
  text << std::setprecision(9) << value;
  return text.str();
}

const char *flow_name(Flow flow) {
  switch (flow) {
    case kF1: return "F1";
    case kF2: return "F2";
    case kF3: return "F3";
    case kF4: return "F4";
    default: return "none";
  }
}

// How many input words one record carries; the target protocol does not change
// that, so these are the F1-F4 arities.
unsigned word_count(Flow flow) {
  switch (flow) {
    case kF1: case kF2: return 1;
    case kF3: case kF4: return 2;
    default: return 0;
  }
}

uint32_t word_at(const Record &record, unsigned index) {
  switch (index) {
    case 0: return record.first;
    case 1: return record.second;
    default: throw std::runtime_error("record word index out of range");
  }
}

uint32_t parse_hex(const std::string &text, const char *what) {
  if (text.empty() || text.size() > 8) throw std::runtime_error(std::string("invalid ") + what);
  uint32_t value = 0;
  for (const char raw : text) {
    const auto character = static_cast<unsigned char>(raw);
    if (!std::isxdigit(character)) throw std::runtime_error(std::string("invalid ") + what);
    value = value * 16u + uint32_t(std::isdigit(character) ? character - '0'
                                                          : std::tolower(character) - 'a' + 10);
  }
  return value;
}

bool in_ram(uint64_t address) {
  return address >= kRamBase && address - kRamBase <= uint64_t(kRamSize) - 4;
}

bool in_ip(uint64_t address) {
  return address >= kIpBase && address - kIpBase <= uint64_t(kIpSize) - 4;
}

std::vector<std::string> split(const std::string &text, char separator) {
  std::vector<std::string> parts;
  std::string current;
  for (const char character : text) {
    if (character == separator) { parts.push_back(current); current.clear(); }
    else current.push_back(character);
  }
  parts.push_back(current);
  return parts;
}

// The host re-checks shape and window; Python already rejected anything that is
// not a record the selected components can serve before either model was
// initialized.
Record make_record(Flow flow, const uint32_t *words, unsigned count) {
  if (flow == kF1) {
    // One 32-bit straight-line ALU word executes in the fixed trampoline slot.
    // Loads, stores, control flow, CSRs and a write to the loop's own mailbox
    // pointer would break the trampoline, so they are refused, not guessed.
    const uint32_t first = words[0];
    const unsigned opcode = first & 0x7fu, rd = (first >> 7) & 31u;
    if ((first & 3u) != 3u)
      throw std::runtime_error("F1 input must be one 32-bit instruction");
    if (opcode != 0x37u && opcode != 0x17u && opcode != 0x13u && opcode != 0x33u)
      throw std::runtime_error("F1 input opcode is outside the executed ALU subset");
    if ((opcode == 0x13u || opcode == 0x33u || opcode == 0x37u || opcode == 0x17u) && rd == 8u)
      throw std::runtime_error("F1 input may not overwrite the mailbox pointer");
  } else if (flow == kF2) {
    if ((words[0] & 3u) || !(in_ip(words[0]) || (in_ram(words[0]) && words[0] >= kDataBase)))
      throw std::runtime_error("F2 address must be an aligned AXI4-Lite or data-window RAM word");
  } else if (flow == kF3) {
    if ((words[0] & 3u) || words[0] < kDataBase || !in_ram(words[0]))
      throw std::runtime_error("F3 address must be an aligned data-window RAM word");
  } else if (flow == kF4) {
    if ((words[0] & 3u) || !in_ip(words[0]))
      throw std::runtime_error("F4 address must be an aligned word in the AXI4-Lite window");
  } else {
    throw std::runtime_error("unsupported flow tag");
  }
  Record record;
  record.flow = flow;
  record.first = words[0];
  record.second = count > 1 ? words[1] : 0;
  return record;
}

Flow parse_flow(const std::string &text) {
  if (text == "F1") return kF1;
  if (text == "F2") return kF2;
  if (text == "F3") return kF3;
  if (text == "F4") return kF4;
  // A flow whose components are not part of this build is refused by name.
  throw std::runtime_error("unsupported flow tag: " + text);
}

Record parse_fields(const std::vector<std::string> &fields) {
  if (fields.size() < 2 || fields.size() > 3)
    throw std::runtime_error("one record needs a flow tag and one to two words");
  const Flow flow = parse_flow(fields[0]);
  const unsigned count = word_count(flow);
  if (fields.size() != 1 + count)
    throw std::runtime_error(std::string("wrong operand count for ") + flow_name(flow));
  uint32_t words[2] = {0, 0};
  for (unsigned index = 0; index < count; ++index)
    words[index] = parse_hex(fields[1 + index], "record address or value");
  return make_record(flow, words, count);
}

}  // namespace

int main(int argc, char **argv) {
  if (argc < 3 || argc > 4) {
    std::cerr << "usage: spike firmware.txt records|--online [max_ticks]\n";
    return 2;
  }
  try {
    const std::string input = argv[2];
    const bool online = input == "--online";
    std::vector<Record> records;
    if (!online) {
      for (const std::string &text : split(input, ','))
        records.push_back(parse_fields(split(text, ':')));
    }
    const uint64_t kMaxTicks = argc == 4 ? std::stoull(argv[3]) : 20000;
    if (!kMaxTicks) throw std::runtime_error("max_ticks must be positive");
    if (online) std::cout << std::unitbuf;
    const auto started = std::chrono::steady_clock::now();
    Memory memory(kRamBase, kRamSize);
    memory.load(argv[1]);
    VerilatedContext context;
    CPU_MODEL cpu(&context, "cpu");
    IP_MODEL ip(&context, "target");
    // Every selected model is driven by the same host tick.  The declaration
    // states whether the models' own clock rates match; a mismatch is reported,
    // never silently hidden.
    auto set_clock = [&](int level) {
      cpu.clk = level; ip.clk = level;
    };
    auto eval_all = [&] {
      cpu.eval(); ip.eval();
    };
    auto set_reset = [&](unsigned step) {
      cpu.reset = step < CPU_RESET_ASSERT; ip.reset = step < IP_RESET_ASSERT;
    };
    auto clear_reset = [&] {
      cpu.reset = 0; ip.reset = 0;
    };
    const unsigned kAssertTicks = std::max(CPU_RESET_ASSERT, IP_RESET_ASSERT);
    const unsigned kReleaseTicks = std::max(CPU_RESET_RELEASE, IP_RESET_RELEASE);
    auto timed_events = [&] {
      return cpu.eventsPending() || ip.eventsPending();
    };
    auto finalize = [&] {
      cpu.final(); ip.final();
    };
    auto edge = [&] {
      set_clock(0); eval_all();
      set_clock(1); eval_all();
      set_clock(0); eval_all();
    };
    // The profile pins some target inputs at a constant.  They are driven from
    // the generated header, so a target with no such pin needs no edit here.
#define APPLY_FIXED_INPUT(name, value) ip.name = (value);
    IP_FIXED_INPUTS(APPLY_FIXED_INPUT)
#undef APPLY_FIXED_INPUT
    set_clock(0); clear_reset(); eval_all();
    set_reset(0); eval_all();
    for (unsigned n = 0; n < kAssertTicks; ++n) { set_reset(n); edge(); }
    clear_reset(); eval_all();
    for (unsigned n = 0; n < kReleaseTicks; ++n) edge();
    if (timed_events()) throw std::runtime_error("unsupported timed model events");

    Response ins, dat;
    Mmio mmio;
    Axil axi;
    Observation observation;
    Record record;
    bool ack_pending = false, frame_done = false, normal_finish = false;
    uint64_t tick = 0, case_tick = 0;
    unsigned cases = 0;
    unsigned total_axi_reads = 0, total_axi_writes = 0;
    unsigned total_aw = 0, total_w = 0, total_b = 0, total_ar = 0, total_r = 0;
    unsigned total_bresp_non_okay = 0, total_rresp_non_okay = 0;
    unsigned total_d_reads = 0, total_d_writes = 0, total_fetches = 0, total_retires = 0;
    auto case_started = std::chrono::steady_clock::now();

    // Handing over one input never resets any model: the fragment lands in the
    // immutable trampoline slot, in a mailbox cell, or in the input block the
    // CPU itself reads; the CPU observes the command word on its next poll.
    auto install = [&](const Record &next) {
      record = next;
      observation = Observation();
      axi = Axil();
      ack_pending = frame_done = false;
      case_tick = tick;
      case_started = std::chrono::steady_clock::now();
      if (record.flow == kF1) memory.write(kSlot, record.first, 15);
      if (record.flow == kF2) memory.write(kArgument, record.first, 15);
      if (record.flow == kF3 || record.flow == kF4) {
        memory.write(kArgument, record.first, 15);
        memory.write(kValue, record.second, 15);
        if (record.flow == kF3) observation.ram_before = memory.read(record.first);
      }
      memory.write(kCommand, unsigned(record.flow), 15);
    };

    auto receive = [&](size_t index) {
      std::cout << "NEED_RECORD " << index << " tick " << tick << '\n';
      std::string line;
      if (!std::getline(std::cin, line) || line == "END") return false;
      std::istringstream message(line);
      std::vector<std::string> tokens;
      for (std::string token; message >> token;) tokens.push_back(token);
      if (tokens.size() < 2 || tokens.front() != "CASE")
        throw std::runtime_error("invalid online record");
      tokens.erase(tokens.begin());
      install(parse_fields(tokens));
      std::cout << "CASE_INSTALLED " << index << '\n';
      return true;
    };

    if (online) {
      if (!receive(0)) throw std::runtime_error("no online record");
    } else if (!records.empty()) {
      install(records.front());
    } else {
      throw std::runtime_error("no record");
    }

    for (; tick < kMaxTicks; ++tick) {
      // The CPU's interrupt input carries no source in this build.
      cpu.CPU_IRQ = 0;
      cpu.CPU_I_REQ_READY = !ins.valid;
      cpu.CPU_I_RSP_VALID = ins.valid; cpu.CPU_I_RSP_RDATA = ins.value; cpu.CPU_I_RSP_ERROR = 0;
      cpu.CPU_D_REQ_READY = !dat.valid && !mmio.busy;
      cpu.CPU_D_RSP_VALID = dat.valid; cpu.CPU_D_RSP_RDATA = dat.value; cpu.CPU_D_RSP_ERROR = 0;
      ip.IP_REQ_VALID = mmio.busy && !mmio.sent;
      ip.IP_REQ_WRITE = mmio.write;
      ip.IP_REQ_ADDR = mmio.address - kIpBase;
      ip.IP_REQ_WDATA = mmio.value;
      ip.IP_REQ_BE = mmio.be;
      ip.IP_RSP_READY = 1;
      eval_all();
      const bool itake = cpu.CPU_I_REQ_VALID && cpu.CPU_I_REQ_READY;
      const bool dtake = cpu.CPU_D_REQ_VALID && cpu.CPU_D_REQ_READY;
      const bool iconsume = cpu.CPU_I_RSP_VALID && cpu.CPU_I_RSP_READY;
      const bool dconsume = cpu.CPU_D_RSP_VALID && cpu.CPU_D_RSP_READY;
      const uint32_t ia = cpu.CPU_I_REQ_ADDR;
      const uint32_t da = cpu.CPU_D_REQ_ADDR, dv = cpu.CPU_D_REQ_WDATA;
      const unsigned dbe = cpu.CPU_D_REQ_BE;
      const bool dw = cpu.CPU_D_REQ_WRITE;
      const bool iptake = ip.IP_REQ_VALID && ip.IP_REQ_READY;
      const bool ipdone = ip.IP_RSP_VALID && ip.IP_RSP_READY;
      const uint32_t ipvalue = ip.IP_RSP_RDATA;
      const bool iperror = ip.IP_RSP_ERROR;
      // A completed AXI4-Lite channel handshake is valid&&ready on the same
      // pre-edge sample; a channel that is only half-present is not a transfer.
      const bool aw_hs = ip.IP_TRACE_AWVALID && ip.IP_TRACE_AWREADY;
      const bool w_hs = ip.IP_TRACE_WVALID && ip.IP_TRACE_WREADY;
      const bool b_hs = ip.IP_TRACE_BVALID && ip.IP_TRACE_BREADY;
      const bool ar_hs = ip.IP_TRACE_ARVALID && ip.IP_TRACE_ARREADY;
      const bool r_hs = ip.IP_TRACE_RVALID && ip.IP_TRACE_RREADY;
      if (aw_hs || w_hs || b_hs || ar_hs || r_hs) {
        if (!axi.pending)
          throw std::runtime_error("AXI4-Lite handshake outside a CPU MMIO transaction");
      }
      if (aw_hs) {
        ++axi.aw; ++observation.axi_aw;
        axi.awaddr = ip.IP_TRACE_AWADDR; axi.awprot = ip.IP_TRACE_AWPROT;
        std::cout << "axi aw " << tick << ' ' << hex32(axi.awaddr)
                  << " prot " << axi.awprot << '\n';
      }
      if (w_hs) {
        ++axi.w; ++observation.axi_w;
        axi.wdata = ip.IP_TRACE_WDATA; axi.wstrb = ip.IP_TRACE_WSTRB;
        std::cout << "axi w " << tick << ' ' << hex32(axi.wdata)
                  << " strb " << axi.wstrb << '\n';
      }
      if (b_hs) {
        ++axi.b; ++observation.axi_b;
        axi.bresp = ip.IP_TRACE_BRESP;
        if (axi.bresp != 0) ++observation.bresp_non_okay;
        std::cout << "axi b " << tick << " resp " << axi.bresp << '\n';
      }
      if (ar_hs) {
        ++axi.ar; ++observation.axi_ar;
        axi.araddr = ip.IP_TRACE_ARADDR; axi.arprot = ip.IP_TRACE_ARPROT;
        std::cout << "axi ar " << tick << ' ' << hex32(axi.araddr)
                  << " prot " << axi.arprot << '\n';
      }
      if (r_hs) {
        ++axi.r; ++observation.axi_r;
        axi.rdata = ip.IP_TRACE_RDATA; axi.rresp = ip.IP_TRACE_RRESP;
        if (axi.rresp != 0) ++observation.rresp_non_okay;
        std::cout << "axi r " << tick << ' ' << hex32(axi.rdata)
                  << " resp " << axi.rresp << '\n';
      }
      set_clock(1); eval_all();
      if (cpu.CPU_RVFI_VALID) {
        if (cpu.CPU_RVFI_TRAP) throw std::runtime_error("CPU retirement trap");
        const uint32_t pc = cpu.CPU_RVFI_PC_RDATA, insn = cpu.CPU_RVFI_INSN;
        ++observation.retires;
        std::cout << "retire " << tick << ' ' << hex32(pc) << ' ' << hex32(insn) << '\n';
        if (pc == kSlot) {
          observation.slot_retire = true;
          observation.slot_retire_pc = pc;
          observation.slot_retire_insn = insn;
        } else if (observation.slot_retire && pc == kSlot + 4) {
          observation.slot_successor = true;
          observation.slot_successor_pc = pc;
        }
      }
      set_clock(0); eval_all();
      if (timed_events()) throw std::runtime_error("unsupported timed model events");
      if (iconsume) ins.valid = false;
      if (dconsume) {
        dat.valid = false;
        if (ack_pending) { ack_pending = false; frame_done = true; }
      }
      if (itake) {
        if (!in_ram(ia))
          throw std::runtime_error("CPU instruction fetch outside the declared RAM");
        ++observation.i_fetches;
        if (ia == kSlot) {
          observation.slot_fetch = true;
          observation.slot_fetch_address = ia;
        }
        ins.value = memory.read(ia);
        ins.valid = true;
      }
      if (dtake) {
        if (in_ip(da)) {
          if (dbe != 15)
            throw std::runtime_error("partial AXI4-Lite word access is outside this spike");
          mmio.busy = true; mmio.sent = false; mmio.write = dw;
          mmio.address = da; mmio.value = dv; mmio.be = dbe;
          if (axi.pending)
            throw std::runtime_error("a previous AXI4-Lite transaction is still in flight");
          axi = Axil();
          axi.pending = true; axi.write = dw;
          std::cout << "cpu_mmio " << tick << ' ' << (dw ? "write" : "read")
                    << ' ' << hex32(da) << ' ' << hex32(dv) << '\n';
        } else if (in_ram(da)) {
          if (dbe > 15) throw std::runtime_error("invalid RAM byte enable");
          if (dw) {
            memory.write(da, dv, dbe);
            ++observation.d_writes;
            if (da == kCommand && dbe == 15 && dv == 0) ack_pending = true;
            if (da == kEcho && dbe == 15) {
              observation.echo_stored = true;
              observation.echo_value = dv;
            }
            if (da >= kDataBase) {
              observation.write_accepted = true;
              observation.write_address = da;
              observation.write_value = dv;
              observation.write_be = dbe;
            }
          } else {
            ++observation.d_reads;
            if (da >= kDataBase && !in_ip(da)) {
              observation.read_accepted = true;
              observation.read_address = da;
              observation.read_from_ip = false;
              observation.read_value = memory.read(da);
            }
          }
          dat.value = dw ? 0 : memory.read(da);
          dat.valid = true;
        } else {
          throw std::runtime_error("CPU data access outside RAM and the declared target window");
        }
        std::cout << "cpu_data " << tick << ' ' << (dw ? "write" : "read") << ' '
                  << hex32(da) << ' ' << hex32(dv) << std::dec << " be " << dbe << '\n';
      }
      if (iptake) mmio.sent = true;
      if (ipdone) {
        if (iperror) throw std::runtime_error("AXI4-Lite target answered with an error response");
        if (!mmio.busy || !mmio.sent)
          throw std::runtime_error("AXI4-Lite target answered without a completed request");
        const uint32_t offset = mmio.address - kIpBase;
        if (mmio.write) {
          // AW and W are independent channels; the write is accepted on the edge
          // that completes both, and B is the response that follows the pair.
          if (axi.aw != 1 || axi.w != 1 || axi.b != 1)
            throw std::runtime_error("AXI4-Lite write did not complete AW, W and B exactly once");
          if (axi.awaddr != offset || axi.wdata != mmio.value || axi.wstrb != 15)
            throw std::runtime_error("AXI4-Lite write address, data or strobes differ from the CPU beat");
          if (axi.bresp != 0)
            throw std::runtime_error("AXI4-Lite write response is not OKAY");
          ++observation.axi_writes;
          observation.mmio_address = mmio.address;
          observation.mmio_value = mmio.value;
          observation.axil_awaddr = axi.awaddr; observation.axil_awprot = axi.awprot;
          observation.axil_wdata = axi.wdata; observation.axil_wstrb = axi.wstrb;
          observation.axil_bresp = axi.bresp;
        } else {
          if (axi.ar != 1 || axi.r != 1)
            throw std::runtime_error("AXI4-Lite read did not complete AR and R exactly once");
          if (axi.araddr != offset)
            throw std::runtime_error("AXI4-Lite read address differs from the CPU beat");
          if (axi.rresp != 0)
            throw std::runtime_error("AXI4-Lite read response is not OKAY");
          if (axi.rdata != ipvalue)
            throw std::runtime_error("AXI4-Lite read data differs from the CPU response");
          ++observation.axi_reads;
          observation.read_accepted = true;
          observation.read_address = mmio.address;
          observation.read_from_ip = true;
          observation.read_value = ipvalue;
          observation.axil_araddr = axi.araddr; observation.axil_arprot = axi.arprot;
          observation.axil_rdata = axi.rdata; observation.axil_rresp = axi.rresp;
        }
        dat.value = ipvalue;
        dat.valid = true;
        mmio = Mmio();
        axi = Axil();
      }
      if (tick - case_tick + 1 > 4000) throw std::runtime_error("case exceeded its tick budget");
      if (!frame_done || dat.valid || mmio.busy) continue;

      // The CPU's own store of zero into the command word is the only case
      // delimiter; everything below is what the models already did.
      const uint32_t ram_after = record.flow == kF3 ? memory.read(record.first) : 0;
      bool passed = true;
      switch (record.flow) {
        case kF1:
          passed = observation.slot_fetch && observation.slot_retire
              && observation.slot_retire_insn == record.first
              && observation.slot_retire_pc == kSlot
              && observation.slot_successor;
          break;
        case kF2:
          passed = observation.read_accepted && observation.read_address == record.first
              && observation.echo_stored && observation.echo_value == observation.read_value
              && (observation.read_from_ip
                      ? observation.axi_reads == 1 && observation.axil_araddr == record.first - kIpBase
                            && observation.axil_rdata == observation.read_value
                            && observation.axil_rresp == 0
                      : observation.axi_reads == 0);
          break;
        case kF3:
          passed = observation.write_accepted && observation.write_address == record.first
              && observation.write_value == record.second && observation.write_be == 15
              && ram_after == record.second;
          break;
        case kF4:
          passed = observation.axi_writes == 1 && observation.axi_reads == 0
              && observation.axil_awaddr == record.first - kIpBase
              && observation.axil_wdata == record.second
              && observation.axil_wstrb == 15 && observation.axil_bresp == 0
              && !observation.write_accepted;
          break;
        default:
          passed = false;
          break;
      }
      const double case_seconds =
          std::chrono::duration<double>(std::chrono::steady_clock::now() - case_started).count();
      std::string record_text = std::string(flow_name(record.flow)) + ':' + hex8(record.first);
      for (unsigned index = 1; index < word_count(record.flow); ++index)
        record_text += ':' + hex8(word_at(record, index));
      std::cout << "case " << cases << ' ' << (passed ? "observations_passed" : "failed")
                << " flow " << flow_name(record.flow)
                << " record " << record_text
                << " ticks " << (tick - case_tick + 1)
                << " seconds " << seconds_text(case_seconds)
                << " i_fetches " << observation.i_fetches
                << " d_reads " << observation.d_reads
                << " d_writes " << observation.d_writes
                << " axi_reads " << observation.axi_reads
                << " axi_writes " << observation.axi_writes
                << " axi_aw " << observation.axi_aw
                << " axi_w " << observation.axi_w
                << " axi_b " << observation.axi_b
                << " axi_ar " << observation.axi_ar
                << " axi_r " << observation.axi_r;
      if (record.flow == kF1)
        std::cout << " fetch " << hex32(observation.slot_fetch_address)
                  << " retire_pc " << hex32(observation.slot_retire_pc)
                  << " retire_insn " << hex32(observation.slot_retire_insn)
                  << " successor_pc " << hex32(observation.slot_successor_pc);
      if (record.flow == kF2) {
        std::cout << " read_addr " << hex32(observation.read_address)
                  << " read_value " << hex32(observation.read_value)
                  << " echo_value " << hex32(observation.echo_value)
                  << " read_from " << (observation.read_from_ip ? "axi4lite" : "ram");
        // A RAM read performed no AXI4-Lite transfer, so no channel field is
        // printed for it: a zeroed default would look like an observed beat.
        if (observation.axi_reads)
          std::cout << " axil_araddr " << hex32(observation.axil_araddr)
                    << " axil_arprot " << observation.axil_arprot
                    << " axil_rdata " << hex32(observation.axil_rdata)
                    << " axil_rresp " << observation.axil_rresp;
      }
      if (record.flow == kF3)
        std::cout << " write_addr " << hex32(observation.write_address)
                  << " write_value " << hex32(observation.write_value)
                  << " write_be " << observation.write_be
                  << " ram_before " << hex32(observation.ram_before)
                  << " ram_after " << hex32(ram_after);
      if (record.flow == kF4) {
        std::cout << " mmio_addr " << hex32(record.first)
                  << " mmio_value " << hex32(record.second)
                  << " ram_store " << int(observation.write_accepted);
        if (observation.axi_writes)
          std::cout << " axil_awaddr " << hex32(observation.axil_awaddr)
                    << " axil_awprot " << observation.axil_awprot
                    << " axil_wdata " << hex32(observation.axil_wdata)
                    << " axil_wstrb " << observation.axil_wstrb
                    << " axil_bresp " << observation.axil_bresp;
      }
      std::cout << '\n';
      total_axi_reads += observation.axi_reads;
      total_axi_writes += observation.axi_writes;
      total_aw += observation.axi_aw;
      total_w += observation.axi_w;
      total_b += observation.axi_b;
      total_ar += observation.axi_ar;
      total_r += observation.axi_r;
      total_bresp_non_okay += observation.bresp_non_okay;
      total_rresp_non_okay += observation.rresp_non_okay;
      total_d_reads += observation.d_reads;
      total_d_writes += observation.d_writes;
      total_fetches += observation.i_fetches;
      total_retires += observation.retires;
      ++cases;
      if (!passed) throw std::runtime_error("case observation failed");
      if (memory.read(kCommand) != 0) throw std::runtime_error("CPU did not consume the mailbox");
      if (!online) {
        if (cases == records.size()) { normal_finish = true; break; }
        install(records[cases]);
        continue;
      }
      if (cases == records.size()) { normal_finish = true; break; }
      if (!receive(cases)) { normal_finish = true; break; }
    }
    const auto elapsed =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
    const bool ok = normal_finish && cases > 0;
    const uint64_t executed = tick + (tick < kMaxTicks ? 1 : 0);
    // A response that was never driven is not claimed: this slave only ever
    // shows OKAY, so the error path stays unknown even though the pins exist.
    const bool okay_only = total_bresp_non_okay == 0 && total_rresp_non_okay == 0;
    std::cout << "summary " << (ok ? "observations_passed" : "failed") << " cases " << cases
              << " ticks " << executed << " instruction_fetches " << total_fetches
              << " instruction_fetch_evidence " << (total_fetches ? "observed" : "missing")
              << " rvfi_retire_events " << total_retires
              << " retirement_evidence " << (total_retires ? "observed" : "missing")
              << " ram_reads " << total_d_reads << " ram_writes " << total_d_writes
              << " axi_transfers " << (total_axi_reads + total_axi_writes)
              << " axi_reads " << total_axi_reads << " axi_writes " << total_axi_writes
              << " axi_aw " << total_aw << " axi_w " << total_w << " axi_b " << total_b
              << " axi_ar " << total_ar << " axi_r " << total_r
              << " bresp_okay " << (total_b - total_bresp_non_okay)
              << " bresp_non_okay " << total_bresp_non_okay
              << " rresp_okay " << (total_r - total_rresp_non_okay)
              << " rresp_non_okay " << total_rresp_non_okay
              << " error_response " << (okay_only ? "unknown" : "observed")
              << " irq_delivery unknown dma not_present"
              << " fixed_target_inputs " << IP_FIXED_INPUT_COUNT
              << " runtime_seconds " << seconds_text(elapsed) << '\n';
    finalize();
    return ok ? 0 : 1;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
