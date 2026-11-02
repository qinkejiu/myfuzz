// One initialized Wishbone CPU (PicoRV32), one APB3 target, the host RAM.
//
// This is the second CPU bus in the in-process loop.  Unlike the OBI hosts, the
// selected CPU has a *single* Wishbone master port: instruction fetches and data
// accesses share the same cyc/stb/adr/we/sel/dat_w cycle stream, and the only
// thing that tells them apart is the CPU's own mem_instr output, which this host
// samples instead of assuming.  One outstanding request exists at a time: the
// host acknowledges a RAM access in the cycle it decodes it, and defers the
// acknowledgement of an APB-window access until the APB3 target has actually
// answered, so the CPU's own bus state machine holds cyc/stb through the wait.
//
// F1..F4 keep the semantics of the other in-process hosts (the same fixed
// mailbox program and the same one-word hand-over), so a flow the selected
// components cannot serve is still refused by name rather than guessed.  What is
// observed per retirement is richer than the OBI host's: this CPU declares the
// RVFI order, rd_addr/rd_wdata and the mem_* writemask as its own outputs, so
// every retirement prints them.
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

static constexpr uint32_t kRamBase = RAM_BASE, kRamSize = RAM_SIZE;
static constexpr uint32_t kIpBase = IP_BASE;
static constexpr uint32_t kSlot = SLOT_ADDRESS;
static constexpr uint32_t kMailbox = MAILBOX_ADDRESS;
static constexpr uint32_t kCommand = MAILBOX_ADDRESS;
static constexpr uint32_t kArgument = MAILBOX_ADDRESS + 4;
static constexpr uint32_t kEcho = MAILBOX_ADDRESS + 8;
static constexpr uint32_t kValue = MAILBOX_ADDRESS + 12;
static constexpr uint32_t kDataBase = DATA_BASE;

using myfuzz::inprocess_spike::Memory;
using myfuzz::inprocess_spike::Response;

namespace {

// One APB3 request started by a real CPU data beat.
struct Mmio {
  bool busy = false, sent = false, write = false;
  uint32_t address = 0, value = 0;
  unsigned be = 0;
};

enum Flow { kNone = 0, kF1 = 1, kF2 = 2, kF3 = 3, kF4 = 4 };

struct Record {
  Flow flow = kNone;
  uint32_t first = 0, second = 0;
};

struct Observation {
  unsigned i_fetches = 0, d_reads = 0, d_writes = 0;
  unsigned apb_reads = 0, apb_writes = 0, retires = 0;
  unsigned ordered_retires = 0, rising_order = 0;
  bool slot_fetch = false, slot_retire = false, slot_successor = false;
  uint32_t slot_fetch_address = 0, slot_retire_pc = 0, slot_retire_insn = 0;
  uint32_t slot_successor_pc = 0, slot_rd_wdata = 0, slot_order = 0;
  bool read_accepted = false, read_from_ip = false, echo_stored = false;
  uint32_t read_address = 0, read_value = 0, echo_value = 0;
  bool write_accepted = false, apb_pready = false;
  uint32_t write_address = 0, write_value = 0, ram_before = 0;
  unsigned write_be = 0;
  uint32_t apb_address = 0, apb_wdata = 0, apb_rdata = 0;
};

std::string hex32(uint32_t value) {
  std::ostringstream text;
  text << "0x" << std::hex << std::setw(8) << std::setfill('0') << value;
  return text.str();
}

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
  return address >= kIpBase && address - kIpBase <= uint64_t(IP_SIZE) - 4;
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

Record make_record(Flow flow, const uint32_t *words, unsigned count) {
  if (flow == kF1) {
    const uint32_t first = words[0];
    const unsigned opcode = first & 0x7fu, rd = (first >> 7) & 31u;
    if ((first & 3u) != 3u)
      throw std::runtime_error("F1 input must be one 32-bit instruction");
    if (opcode != 0x37u && opcode != 0x17u && opcode != 0x13u && opcode != 0x33u)
      throw std::runtime_error("F1 input opcode is outside the executed ALU subset");
    if (rd == 8u) throw std::runtime_error("F1 input may not overwrite the mailbox pointer");
  } else if (flow == kF2) {
    if ((words[0] & 3u) || !(in_ip(words[0]) || (in_ram(words[0]) && words[0] >= kDataBase)))
      throw std::runtime_error("F2 address must be an aligned APB or data-window RAM word");
  } else if (flow == kF3) {
    if ((words[0] & 3u) || words[0] < kDataBase || !in_ram(words[0]))
      throw std::runtime_error("F3 address must be an aligned data-window RAM word");
  } else if (flow == kF4) {
    if ((words[0] & 3u) || !in_ip(words[0]))
      throw std::runtime_error("F4 address must be an aligned word in the APB window");
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
  throw std::runtime_error("unsupported flow tag: " + text);
}

Record parse_fields(const std::vector<std::string> &fields) {
  if (fields.size() < 2 || fields.size() > 3)
    throw std::runtime_error("one record needs a flow tag and one or two words");
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
    auto set_clock = [&](int level) { cpu.clk = level; ip.clk = level; };
    auto eval_all = [&] { cpu.eval(); ip.eval(); };
    auto set_reset = [&](unsigned step) {
      cpu.reset = step < CPU_RESET_ASSERT; ip.reset = step < IP_RESET_ASSERT;
    };
    auto clear_reset = [&] { cpu.reset = 0; ip.reset = 0; };
    const unsigned kAssertTicks = std::max(CPU_RESET_ASSERT, IP_RESET_ASSERT);
    const unsigned kReleaseTicks = std::max(CPU_RESET_RELEASE, IP_RESET_RELEASE);
    auto timed_events = [&] { return cpu.eventsPending() || ip.eventsPending(); };
    auto finalize = [&] { cpu.final(); ip.final(); };
    auto edge = [&] {
      set_clock(0); eval_all();
      set_clock(1); eval_all();
      set_clock(0); eval_all();
    };
    set_clock(0); clear_reset(); eval_all();
    set_reset(0); eval_all();
    for (unsigned n = 0; n < kAssertTicks; ++n) { set_reset(n); edge(); }
    clear_reset(); eval_all();
    for (unsigned n = 0; n < kReleaseTicks; ++n) edge();
    if (timed_events()) throw std::runtime_error("unsupported timed model events");

    Mmio mmio;
    Observation observation;
    Record record;
    bool ack_pending = false, frame_done = false, normal_finish = false;
    bool response_ready = false, response_write = false;
    uint32_t response_data = 0;
    uint64_t tick = 0, case_tick = 0;
    unsigned cases = 0, total_apb_reads = 0, total_apb_writes = 0;
    unsigned total_d_reads = 0, total_d_writes = 0, total_fetches = 0;
    unsigned total_retires = 0, total_wb_transfers = 0;
    uint64_t previous_order = 0;
    auto case_started = std::chrono::steady_clock::now();

    auto install = [&](const Record &next) {
      record = next;
      observation = Observation();
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
      // The CPU has no interrupt input wired in this build and declares no
      // error response on its bus, so the host answers data only.
      cpu.CPU_IRQ = 0;
      cpu.CPU_WB_ACK = 0;
      cpu.CPU_WB_DAT_R = 0;
      ip.IP_REQ_VALID = mmio.busy && !mmio.sent;
      ip.IP_REQ_WRITE = mmio.write;
      ip.IP_REQ_ADDR = mmio.address - kIpBase;
      ip.IP_REQ_WDATA = mmio.value;
      ip.IP_REQ_BE = mmio.be;
      ip.IP_RSP_READY = 1;
      eval_all();
      // Sample the one shared Wishbone request, the CPU's own fetch marker and
      // the target's answer of this cycle.
      const bool request = cpu.CPU_WB_CYC && cpu.CPU_WB_STB;
      const bool fetch_beat = cpu.CPU_WB_INSTR;
      const bool req_write = cpu.CPU_WB_WE;
      const uint64_t req_wide = cpu.CPU_WB_ADR;
      const uint32_t req_addr = uint32_t(req_wide);
      const uint32_t req_wdata = cpu.CPU_WB_DAT_W;
      const unsigned req_sel = cpu.CPU_WB_SEL;
      const bool iptake = ip.IP_REQ_VALID && ip.IP_REQ_READY;
      const bool ipdone = ip.IP_RSP_VALID && ip.IP_RSP_READY;
      const uint32_t ipvalue = ip.IP_RSP_RDATA;
      const bool iperror = ip.IP_RSP_ERROR;
      if (ipdone) {
        if (iperror || !mmio.busy || !mmio.sent)
          throw std::runtime_error("APB target answered without a completed request");
        if (!mmio.write) {
          observation.read_accepted = true;
          observation.read_address = mmio.address;
          observation.read_from_ip = true;
          observation.read_value = ipvalue;
        }
        response_data = ipvalue;
        response_write = mmio.write;
        response_ready = true;
        mmio = Mmio();
      }
      if (request && !response_ready && !mmio.busy) {
        if (req_wide > UINT32_MAX)
          throw std::runtime_error("Wishbone address out of range");
        ++total_wb_transfers;
        response_write = req_write;
        if (req_write && req_sel != 15)
          throw std::runtime_error("partial Wishbone store is outside this spike");
        if (in_ip(req_addr)) {
          if (fetch_beat)
            throw std::runtime_error("instruction fetch inside the APB window");
          mmio.busy = true; mmio.sent = false; mmio.write = req_write;
          mmio.address = req_addr; mmio.value = req_wdata; mmio.be = req_sel;
          std::cout << "cpu_mmio " << tick << ' ' << (req_write ? "write" : "read")
                    << ' ' << hex32(req_addr) << ' ' << hex32(req_wdata) << '\n';
        } else if (in_ram(req_addr)) {
          if (req_write) {
            memory.write(req_addr, req_wdata, req_sel);
            response_data = 0;
            ++observation.d_writes;
            if (req_addr == kCommand && req_sel == 15 && req_wdata == 0) ack_pending = true;
            if (req_addr == kEcho && req_sel == 15) {
              observation.echo_stored = true;
              observation.echo_value = req_wdata;
            }
            if (req_addr >= kDataBase) {
              observation.write_accepted = true;
              observation.write_address = req_addr;
              observation.write_value = req_wdata;
              observation.write_be = req_sel;
            }
          } else {
            response_data = memory.read(req_addr);
            if (fetch_beat) {
              ++observation.i_fetches;
              if (req_addr == kSlot) {
                observation.slot_fetch = true;
                observation.slot_fetch_address = req_addr;
              }
            } else {
              ++observation.d_reads;
              if (req_addr >= kDataBase) {
                observation.read_accepted = true;
                observation.read_address = req_addr;
                observation.read_from_ip = false;
                observation.read_value = response_data;
              }
            }
          }
          response_ready = true;
        } else {
          throw std::runtime_error("CPU bus access outside RAM and the APB window");
        }
        std::cout << "wb " << tick << ' ' << (fetch_beat ? "fetch" : (req_write ? "write" : "read"))
                  << ' ' << hex32(req_addr) << ' ' << hex32(req_wdata)
                  << std::dec << " sel " << req_sel << '\n';
      }
      if (request && response_ready) {
        // One acknowledged Wishbone beat.  The CPU's state machine leaves
        // WBSTART on the following edge and drops cyc/stb.  A store of zero into
        // the command word is the case delimiter, so the acknowledgement of that
        // store is what ends the case, exactly like the CPU's own completion
        // store in the OBI hosts.
        cpu.CPU_WB_ACK = 1;
        cpu.CPU_WB_DAT_R = response_data;
        eval_all();
        if (ack_pending) { ack_pending = false; frame_done = true; }
      }
      if (ip.IP_TRACE_PSEL && ip.IP_TRACE_PENABLE && ip.IP_TRACE_PREADY) {
        observation.apb_pready = true;
        observation.apb_address = ip.IP_TRACE_PADDR;
        if (ip.IP_TRACE_PWRITE) {
          ++observation.apb_writes;
          observation.apb_wdata = ip.IP_TRACE_PWDATA;
        } else {
          ++observation.apb_reads;
          observation.apb_rdata = ip.IP_TRACE_PRDATA;
        }
        std::cout << "apb " << tick << ' ' << (ip.IP_TRACE_PWRITE ? "write" : "read")
                  << ' ' << hex32(ip.IP_TRACE_PADDR) << ' ' << hex32(ip.IP_TRACE_PWDATA)
                  << ' ' << hex32(ip.IP_TRACE_PRDATA) << '\n';
      }
      set_clock(1); eval_all();
      response_ready = false;
      if (cpu.CPU_RVFI_VALID) {
        if (cpu.CPU_RVFI_TRAP) throw std::runtime_error("CPU retirement trap");
        const uint32_t pc = cpu.CPU_RVFI_PC_RDATA, insn = cpu.CPU_RVFI_INSN;
        const uint64_t order = cpu.CPU_RVFI_ORDER;
        const unsigned rd = cpu.CPU_RVFI_RD_ADDR;
        const uint32_t rd_wdata = cpu.CPU_RVFI_RD_WDATA;
        ++observation.retires;
        if (order) ++observation.ordered_retires;
        // PicoRV32 numbers its first retirement zero and counts up from there,
        // so "strictly rising" is stated from the first retirement, not from 1.
        if (observation.retires == 1 || order > previous_order) ++observation.rising_order;
        previous_order = order;
        std::cout << "retire " << tick << ' ' << hex32(pc) << ' ' << hex32(insn)
                  << std::dec << " order " << order << " rd " << rd
                  << std::hex << " rd_wdata " << hex32(rd_wdata) << '\n';
        if (pc == kSlot) {
          observation.slot_retire = true;
          observation.slot_retire_pc = pc;
          observation.slot_retire_insn = insn;
          observation.slot_rd_wdata = rd_wdata;
          observation.slot_order = uint32_t(order);
        } else if (observation.slot_retire && pc == kSlot + 4) {
          observation.slot_successor = true;
          observation.slot_successor_pc = pc;
        }
      }
      set_clock(0); eval_all();
      if (timed_events()) throw std::runtime_error("unsupported timed model events");
      if (iptake) mmio.sent = true;
      if (tick - case_tick + 1 > 4000) throw std::runtime_error("case exceeded its tick budget");
      if (!frame_done || mmio.busy) continue;

      const uint32_t ram_after = record.flow == kF3 ? memory.read(record.first) : 0;
      bool passed = true;
      switch (record.flow) {
        case kF1:
          passed = observation.slot_fetch && observation.slot_retire
              && observation.slot_retire_insn == record.first
              && observation.slot_retire_pc == kSlot
              && observation.slot_successor
              && observation.rising_order == observation.retires;
          break;
        case kF2:
          passed = observation.read_accepted && observation.read_address == record.first
              && observation.echo_stored && observation.echo_value == observation.read_value
              && (observation.read_from_ip ? observation.apb_reads == 1
                                           : observation.apb_reads == 0);
          break;
        case kF3:
          passed = observation.write_accepted && observation.write_address == record.first
              && observation.write_value == record.second && observation.write_be == 15
              && ram_after == record.second;
          break;
        case kF4:
          passed = observation.apb_writes == 1 && observation.apb_pready
              && observation.apb_address == record.first - kIpBase
              && observation.apb_wdata == record.second
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
                << " wb_retires " << observation.retires
                << " wb_rvfi_order_rising " << observation.rising_order
                << " apb_reads " << observation.apb_reads
                << " apb_writes " << observation.apb_writes;
      if (record.flow == kF1)
        std::cout << " fetch " << hex32(observation.slot_fetch_address)
                  << " retire_pc " << hex32(observation.slot_retire_pc)
                  << " retire_insn " << hex32(observation.slot_retire_insn)
                  << " successor_pc " << hex32(observation.slot_successor_pc)
                  << " slot_rd_wdata " << hex32(observation.slot_rd_wdata)
                  << " slot_order " << observation.slot_order;
      if (record.flow == kF2)
        std::cout << " read_addr " << hex32(observation.read_address)
                  << " read_value " << hex32(observation.read_value)
                  << " echo_value " << hex32(observation.echo_value)
                  << " read_from " << (observation.read_from_ip ? "apb" : "ram")
                  << " apb_rdata " << hex32(observation.apb_rdata);
      if (record.flow == kF3)
        std::cout << " write_addr " << hex32(observation.write_address)
                  << " write_value " << hex32(observation.write_value)
                  << " write_be " << observation.write_be
                  << " ram_before " << hex32(observation.ram_before)
                  << " ram_after " << hex32(ram_after);
      if (record.flow == kF4)
        std::cout << " mmio_addr " << hex32(record.first)
                  << " mmio_value " << hex32(record.second)
                  << " apb_offset " << hex32(observation.apb_address)
                  << " apb_pwdata " << hex32(observation.apb_wdata)
                  << " apb_pready " << int(observation.apb_pready);
      std::cout << '\n';
      total_apb_reads += observation.apb_reads;
      total_apb_writes += observation.apb_writes;
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
    std::cout << "summary " << (ok ? "observations_passed" : "failed") << " cases " << cases
              << " ticks " << executed << " instruction_fetches " << total_fetches
              << " ram_reads " << total_d_reads << " ram_writes " << total_d_writes
              << " wb_transfers " << total_wb_transfers
              << " wb_retires " << total_retires
              << " apb_transfers " << (total_apb_reads + total_apb_writes)
              << " apb_reads " << total_apb_reads << " apb_writes " << total_apb_writes
              << " cpu_bus wishbone-single-master"
              << " fetch_marker mem_instr"
              << " instruction_fetch_evidence observed"
              << " retirement_evidence observed"
              << " runtime_seconds " << seconds_text(elapsed) << '\n';
    finalize();
    return ok ? 0 : 1;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
