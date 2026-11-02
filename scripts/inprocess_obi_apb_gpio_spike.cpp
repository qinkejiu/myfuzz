// One initialized OBI CPU, the pinned PULP apb_gpio target and a host pad model.
//
// Everything the CPU does is real: it fetches and executes the fixed polling
// program from host RAM, and it reaches the device only through completed APB3
// transfers.  What is new here is the pin side, which no other in-process host
// had: every tick this host resolves the pad wire from the device's own
// gpio_out/gpio_dir ports and one declared external pin value, drives that
// resolution back into the device's gpio_in port, and samples the device's
// synchronizer, its transition probes and its interrupt output.  A pad value is
// therefore never a constant copied from a config: it is either the device's
// own registered output (that pin is an output) or the host driver value (that
// pin is an input), and the host prints the resolution it applied.
//
// The flows are the same compact loop as the other in-process hosts:
//
//   F1  the CPU fetches and retires one word from the trampoline slot
//   F2  the CPU reads one RAM word or one APB register
//   F3  the CPU stores one word to RAM
//   F4  the CPU stores one word through the APB window; the pin consequence of
//       that store (PADOUT family) is checked against the sampled gpio_out
//   P   the host drives the declared external pin value, then the CPU reads the
//       device's PADIN register: the value the CPU commits is compared with the
//       pad the host itself resolved for those pins
//   F5  the CPU performs the declared trigger writes; a real pin transition
//       inside the device produces the device's own interrupt, which the host
//       samples and delivers to the CPU input; the ISR reads the declared
//       status register (reading INTSTATUS is the device's own clear), stores
//       the value it read and sets the flag
//
// A flow the selected components cannot serve is refused by name.  When the
// generated binding header declares no IRQ wiring (TRIGGER_COUNT == 0) the F5
// code below compiles out and the loop is exactly F1-F4 plus the pin flows.
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

#ifndef HAVE_CPU_TAKE
#define HAVE_CPU_TAKE 0
#endif
#ifndef HAVE_IRQ_LINK
#define HAVE_IRQ_LINK 0
#endif
#ifndef TRIGGER_COUNT
#define TRIGGER_COUNT 0
#endif
#ifndef PAD_WIDTH
#define PAD_WIDTH 32
#endif

static constexpr uint32_t kRamBase = RAM_BASE, kRamSize = RAM_SIZE;
static constexpr uint32_t kIpBase = IP_BASE;
static constexpr uint32_t kSlot = SLOT_ADDRESS;
static constexpr uint32_t kMailbox = MAILBOX_ADDRESS;
static constexpr uint32_t kCommand = MAILBOX_ADDRESS;
static constexpr uint32_t kArgument = MAILBOX_ADDRESS + 4;
static constexpr uint32_t kEcho = MAILBOX_ADDRESS + 8;
static constexpr uint32_t kValue = MAILBOX_ADDRESS + 12;
static constexpr uint32_t kInput = MAILBOX_ADDRESS + 16;
static constexpr uint32_t kDataBase = DATA_BASE;
#if HAVE_IRQ_LINK
static constexpr uint32_t kIpStatusOffset = IP_STATUS_OFFSET;
static constexpr uint32_t kIpResult = IP_RESULT_ADDRESS;
static constexpr uint32_t kFlagAddress = FLAG_ADDRESS;
#endif
// The declared pin value the host drives while a pad bit is an input.
static constexpr uint32_t kPadExternalDefault = IP_PAD_EXT_DEFAULT;
static constexpr uint32_t kPadMask =
    PAD_WIDTH >= 32 ? 0xffffffffu : ((uint32_t(1) << PAD_WIDTH) - 1u);

using myfuzz::inprocess_spike::Memory;
using myfuzz::inprocess_spike::Response;

namespace {

// One APB3 request started by a real CPU data beat.
struct Mmio {
  bool busy = false, sent = false, write = false;
  uint32_t address = 0, value = 0;
  unsigned be = 0;
};

#if HAVE_IRQ_LINK
// One real interrupt output of the selected model.  The declared source is a
// native one-clock transition pulse, so the host holds the CPU line for the
// declared delivery width; the pulse itself is sampled, never synthesized.
struct IrqLink {
  unsigned pulse_ticks = 0, remaining = 0, edges = 0, high = 0;
  bool last = false;
};
#endif

// The host pad model.  ``ext`` is the declared external driver, ``out`` and
// ``dir`` are sampled from the device's own ports, and ``value`` is the wire
// the host drives into gpio_in.
struct Pads {
  uint32_t ext = kPadExternalDefault, value = 0, out = 0, dir = 0, sync = 0;
};

uint32_t resolve_pads(uint32_t out, uint32_t dir, uint32_t ext) {
  // A pin whose direction bit is high is driven by the device; the remaining
  // pins are driven by the host.  There is no third driver and no contention.
  return ((out & dir) | (ext & ~dir)) & kPadMask;
}

enum Flow { kNone = 0, kF1 = 1, kF2 = 2, kF3 = 3, kF4 = 4, kF5 = 5, kP = 6 };

struct Record {
  Flow flow = kNone;
  uint32_t first = 0, second = 0, third = 0, fourth = 0;
};

struct Observation {
  unsigned i_fetches = 0, d_reads = 0, d_writes = 0;
  unsigned apb_reads = 0, apb_writes = 0;
  bool slot_fetch = false, slot_retire = false, slot_successor = false;
  uint32_t slot_fetch_address = 0, slot_retire_pc = 0, slot_retire_insn = 0;
  uint32_t slot_successor_pc = 0;
  bool read_accepted = false, read_from_ip = false, echo_stored = false;
  uint32_t read_address = 0, read_value = 0, echo_value = 0;
  bool write_accepted = false, apb_pready = false;
  uint32_t write_address = 0, write_value = 0, ram_before = 0;
  unsigned write_be = 0;
  uint32_t apb_address = 0, apb_wdata = 0, apb_rdata = 0;
  // Pin model: snapshots of the resolved wire and of the sampled device ports.
  uint32_t pad_before = 0, pad_after = 0, pad_at_read = 0;
  uint32_t out_before = 0, out_after = 0, dir_before = 0, dir_after = 0;
  uint32_t sync_at_read = 0, padin_latch = 0, padin_latch_at_read = 0;
  uint32_t ext_value = 0;
  unsigned pad_changes = 0, pad_rise_events = 0;
  uint32_t rise_mask = 0, fall_mask = 0;
  uint64_t first_rise_tick = 0;
  // F5: only completed APB transfers and real device outputs land here.
  uint32_t apb_read_offset = 0, apb_read_data = 0;
  uint32_t apb_last_write_offset = 0, apb_last_write_data = 0;
  unsigned irq_edges = 0, irq_takes = 0, irq_high = 0;
  uint64_t first_irq_tick = 0;
  uint32_t irq_cause_pins = 0, inten_at_irq = 0, status_after_read = 0;
  bool isr_flag = false;
  uint32_t isr_result = 0;
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
    case kF5: return "F5";
    case kP: return "P";
    default: return "none";
  }
}

// How many input words one record carries.  Zero means the selected components
// cannot serve that flow at all.
unsigned word_count(Flow flow) {
  switch (flow) {
    case kF1: case kF2: return 1;
    case kF3: case kF4: return 2;
    case kP: return 2;
    case kF5: return TRIGGER_COUNT;
    default: return 0;
  }
}

uint32_t word_at(const Record &record, unsigned index) {
  switch (index) {
    case 0: return record.first;
    case 1: return record.second;
    case 2: return record.third;
    case 3: return record.fourth;
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
    if ((opcode == 0x13u || opcode == 0x33u || opcode == 0x37u || opcode == 0x17u) && rd == 8u)
      throw std::runtime_error("F1 input may not overwrite the mailbox pointer");
  } else if (flow == kF2) {
    if ((words[0] & 3u) || !(in_ip(words[0]) || (in_ram(words[0]) && words[0] >= kDataBase)))
      throw std::runtime_error("F2 address must be an aligned APB or data-window RAM word");
  } else if (flow == kF3) {
    if ((words[0] & 3u) || words[0] < kDataBase || !in_ram(words[0]))
      throw std::runtime_error("F3 address must be an aligned data-window RAM word");
  } else if (flow == kF4) {
    if ((words[0] & 3u) || !in_ip(words[0]))
      throw std::runtime_error("F4 address must be an aligned word in the APB window");
  } else if (flow == kP) {
    if (words[0] != kIpBase + IP_PADIN_OFFSET)
      throw std::runtime_error("P needs the declared PADIN address as its first word");
    if (words[1] & ~kPadMask)
      throw std::runtime_error("P input value exceeds the declared pad width");
  } else if (flow == kF5) {
    if (!TRIGGER_COUNT) throw std::runtime_error("F5 needs a declared IRQ trigger sequence");
  } else {
    throw std::runtime_error("unsupported flow tag");
  }
  Record record;
  record.flow = flow;
  record.first = words[0];
  record.second = count > 1 ? words[1] : 0;
  record.third = count > 2 ? words[2] : 0;
  record.fourth = count > 3 ? words[3] : 0;
  return record;
}

Flow parse_flow(const std::string &text) {
  if (text == "F1") return kF1;
  if (text == "F2") return kF2;
  if (text == "F3") return kF3;
  if (text == "F4") return kF4;
  if (text == "P") return kP;
  if (text == "F5" && TRIGGER_COUNT > 0) return kF5;
  throw std::runtime_error("unsupported flow tag: " + text);
}

Record parse_fields(const std::vector<std::string> &fields) {
  if (fields.size() < 2 || fields.size() > 5)
    throw std::runtime_error("one record needs a flow tag and one to four words");
  const Flow flow = parse_flow(fields[0]);
  const unsigned count = word_count(flow);
  if (!count) throw std::runtime_error(std::string("flow is not wired in this build: ") + fields[0]);
  if (fields.size() != 1 + count)
    throw std::runtime_error(std::string("wrong operand count for ") + flow_name(flow));
  uint32_t words[4] = {0, 0, 0, 0};
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
    Pads pads;
    ip.IP_PIN_IN = pads.ext;      // the declared external driver, before any case
    set_clock(0); clear_reset(); eval_all();
    set_reset(0); eval_all();
    for (unsigned n = 0; n < kAssertTicks; ++n) { set_reset(n); edge(); }
    clear_reset(); eval_all();
    for (unsigned n = 0; n < kReleaseTicks; ++n) edge();
    if (timed_events()) throw std::runtime_error("unsupported timed model events");

    Response ins, dat;
    Mmio mmio;
    Observation observation;
    Record record;
#if HAVE_IRQ_LINK
    IrqLink irq;
    irq.pulse_ticks = IP_IRQ_PULSE_TICKS;
#endif
    bool ack_pending = false, frame_done = false, normal_finish = false;
    bool irq_delivered = false;
    uint64_t tick = 0, case_tick = 0;
    unsigned cases = 0, total_apb_reads = 0, total_apb_writes = 0;
    unsigned total_d_reads = 0, total_d_writes = 0, total_fetches = 0;
    unsigned total_pad_changes = 0, total_pad_rises = 0;
    unsigned total_irq_edges = 0, total_irq_takes = 0, total_irq_high = 0;
    auto case_started = std::chrono::steady_clock::now();

    // Handing over one input never resets any model: the fragment lands in the
    // immutable trampoline slot, in a mailbox cell, or in the input block the
    // CPU itself reads.  A P case additionally rewrites the host's own external
    // pin driver, which is the stimulus side of the pad model.
    auto install = [&](const Record &next) {
      record = next;
      observation = Observation();
      observation.pad_before = pads.value;
      observation.out_before = pads.out;
      observation.dir_before = pads.dir;
      observation.padin_latch = pads.sync;
      ack_pending = frame_done = false;
      case_tick = tick;
      case_started = std::chrono::steady_clock::now();
      pads.ext = record.flow == kP ? record.second : kPadExternalDefault;
      observation.ext_value = pads.ext;
      if (record.flow == kF1) memory.write(kSlot, record.first, 15);
      if (record.flow == kF2 || record.flow == kP) memory.write(kArgument, record.first, 15);
      if (record.flow == kF3 || record.flow == kF4) {
        memory.write(kArgument, record.first, 15);
        memory.write(kValue, record.second, 15);
        if (record.flow == kF3) observation.ram_before = memory.read(record.first);
      }
      if (record.flow == kF5) {
        for (unsigned index = 0; index < word_count(record.flow); ++index)
          memory.write(kInput + 4 * index, word_at(record, index), 15);
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
      cpu.CPU_IRQ = irq_delivered ? 1 : 0;
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
      // Resolve the wire from the ports the device just drove, then drive the
      // device's own input with it.  A pad bit is the device's output when the
      // device says that pin is an output, and the host value otherwise.
      const uint32_t sampled_out = ip.IP_PIN_OUT & kPadMask;
      const uint32_t sampled_dir = ip.IP_PIN_DIR & kPadMask;
      const uint32_t sampled_sync = ip.IP_PIN_IN_SYNC & kPadMask;
      const uint32_t pad = resolve_pads(sampled_out, sampled_dir, pads.ext);
      if (pad != pads.value || sampled_out != pads.out || sampled_dir != pads.dir) {
        if (sampled_dir != pads.dir)
          std::cout << "pin " << tick << " dir " << hex32(pads.dir) << ' ' << hex32(sampled_dir)
                    << '\n';
        if (sampled_out != pads.out)
          std::cout << "pin " << tick << " out " << hex32(pads.out) << ' ' << hex32(sampled_out)
                    << '\n';
        if (pad != pads.value) {
          std::cout << "pin " << tick << " pad " << hex32(pads.value) << ' ' << hex32(pad)
                    << " out " << hex32(sampled_out) << " dir " << hex32(sampled_dir)
                    << " ext " << hex32(pads.ext) << '\n';
          ++observation.pad_changes;
          ++total_pad_changes;
        }
        pads.value = pad; pads.out = sampled_out; pads.dir = sampled_dir;
      }
      pads.sync = sampled_sync;
      if ((ip.IP_PIN_IN & kPadMask) != pad) { ip.IP_PIN_IN = pad; eval_all(); }
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
      // The device's own transition probes name the pin whose synchronized
      // input moved this cycle; they are sampled, never derived by the host.
      const uint32_t rise = ip.IP_PROBE_RISE & kPadMask;
      const uint32_t fall = ip.IP_PROBE_FALL & kPadMask;
      if (rise || fall) {
        std::cout << "pin " << tick << " edge rise " << hex32(rise)
                  << " fall " << hex32(fall) << '\n';
        observation.rise_mask |= rise;
        observation.fall_mask |= fall;
        if (rise && !observation.first_rise_tick) observation.first_rise_tick = tick + 1;
        if (rise) ++observation.pad_rise_events;
      }
      observation.padin_latch = ip.IP_PROBE_PADIN_LATCH & kPadMask;
#if HAVE_IRQ_LINK
      // A declared pulse source: the native transition pulse is sampled from the
      // device's own output and stretched to the declared delivery width.
      {
        const unsigned raw = ip.IP_IRQ ? 1u : 0u;
        if (raw) ++observation.irq_high;
        if (raw && !irq.last) {
          ++irq.edges;
          ++observation.irq_edges;
          if (!observation.first_irq_tick) observation.first_irq_tick = tick + 1;
          observation.irq_cause_pins = rise;
          observation.inten_at_irq = ip.IP_PROBE_INTEN & kPadMask;
          std::cout << "irq_edge " << tick << " cause " << hex32(rise) << '\n';
        }
        if (raw) {
          irq.remaining = irq.pulse_ticks;
        } else if (irq.remaining) {
          --irq.remaining;
        }
        irq_delivered = irq.remaining > 0;
        irq.last = raw != 0;
      }
#endif
      if (ip.IP_TRACE_PSEL && ip.IP_TRACE_PENABLE && ip.IP_TRACE_PREADY) {
        observation.apb_pready = true;
        observation.apb_address = ip.IP_TRACE_PADDR;
        if (ip.IP_TRACE_PWRITE) {
          ++observation.apb_writes;
          observation.apb_wdata = ip.IP_TRACE_PWDATA;
          observation.apb_last_write_offset = ip.IP_TRACE_PADDR;
          observation.apb_last_write_data = ip.IP_TRACE_PWDATA;
        } else {
          ++observation.apb_reads;
          observation.apb_rdata = ip.IP_TRACE_PRDATA;
          observation.apb_read_offset = ip.IP_TRACE_PADDR;
          observation.apb_read_data = ip.IP_TRACE_PRDATA;
        }
        std::cout << "apb " << tick << ' ' << (ip.IP_TRACE_PWRITE ? "write" : "read")
                  << ' ' << hex32(ip.IP_TRACE_PADDR) << ' ' << hex32(ip.IP_TRACE_PWDATA)
                  << ' ' << hex32(ip.IP_TRACE_PRDATA) << '\n';
      }
#if HAVE_CPU_TAKE
      if (cpu.CPU_IRQ_TAKE) {
        if (!irq_delivered)
          throw std::runtime_error("CPU took an interrupt no delivered source asserted");
        ++observation.irq_takes;
        std::cout << "irq_take " << tick << '\n';
      }
#endif
      set_clock(1); eval_all();
      if (cpu.CPU_RVFI_VALID) {
        if (cpu.CPU_RVFI_TRAP) throw std::runtime_error("CPU retirement trap");
        const uint32_t pc = cpu.CPU_RVFI_PC_RDATA, insn = cpu.CPU_RVFI_INSN;
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
            throw std::runtime_error("partial APB word access is outside this spike");
          mmio.busy = true; mmio.sent = false; mmio.write = dw;
          mmio.address = da; mmio.value = dv; mmio.be = dbe;
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
            if (da >= kDataBase) {
              observation.read_accepted = true;
              observation.read_address = da;
              observation.read_from_ip = false;
              observation.read_value = memory.read(da);
            }
          }
          dat.value = dw ? 0 : memory.read(da);
          dat.valid = true;
        } else {
          throw std::runtime_error("CPU data access outside RAM and the APB window");
        }
        std::cout << "cpu_data " << tick << ' ' << (dw ? "write" : "read") << ' '
                  << hex32(da) << ' ' << hex32(dv) << std::dec << " be " << dbe << '\n';
      }
      if (iptake) mmio.sent = true;
      if (ipdone) {
        if (iperror || !mmio.busy || !mmio.sent)
          throw std::runtime_error("APB target answered without a completed request");
        if (!mmio.write) {
          observation.read_accepted = true;
          observation.read_address = mmio.address;
          observation.read_from_ip = true;
          observation.read_value = ipvalue;
          // The pad as the host resolved it, and the device's own synchronizer
          // latch, both taken at the tick the read completed.
          observation.pad_at_read = pads.value;
          observation.sync_at_read = pads.sync;
          observation.padin_latch_at_read = observation.padin_latch;
        }
        dat.value = ipvalue;
        dat.valid = true;
        mmio = Mmio();
      }
      if (tick - case_tick + 1 > 4000) throw std::runtime_error("case exceeded its tick budget");
      if (!frame_done || dat.valid || mmio.busy) continue;

      const uint32_t ram_after = record.flow == kF3 ? memory.read(record.first) : 0;
      observation.pad_after = pads.value;
      observation.out_after = pads.out;
      observation.dir_after = pads.dir;
      observation.padin_latch = pads.sync;
#if HAVE_IRQ_LINK
      if (record.flow == kF5) {
        observation.isr_result = memory.read(kIpResult);
        observation.isr_flag = memory.read(kFlagAddress) != 0;
        observation.status_after_read = ip.IP_PROBE_STATUS & kPadMask;
      }
#endif
      bool passed = true;
      switch (record.flow) {
        case kF1:
          passed = observation.slot_fetch && observation.slot_retire
              && observation.slot_retire_insn == record.first
              && observation.slot_retire_pc == kSlot
              && observation.slot_successor;
          break;
        case kF2:
        case kP: {
          const uint32_t offset = record.first - kIpBase;
          passed = observation.read_accepted && observation.read_address == record.first
              && observation.echo_stored && observation.echo_value == observation.read_value
              && observation.apb_reads == 1 && observation.apb_read_offset == offset
              && observation.read_value == observation.apb_rdata;
          if (passed && offset == IP_PADIN_OFFSET) {
            // PADIN returns the device's synchronizer latch; the host also
            // resolves the wire itself, so a P case can be tied to its input.
            passed = observation.read_value == observation.padin_latch_at_read
                && observation.read_value == observation.pad_at_read;
          }
          if (passed && record.flow == kP)
            passed = (observation.pad_at_read & ~observation.dir_after) ==
                     (record.second & ~observation.dir_after);
          break;
        }
        case kF3:
          passed = observation.write_accepted && observation.write_address == record.first
              && observation.write_value == record.second && observation.write_be == 15
              && ram_after == record.second;
          break;
        case kF4: {
          const uint32_t offset = record.first - kIpBase;
          // The declared register semantics of the PADOUT family, applied to the
          // output value the host sampled *before* the store.
          uint32_t expected_out = observation.out_before;
          if (offset == IP_PADOUT_OFFSET) expected_out = record.second;
          else if (offset == IP_PADOUTSET_OFFSET) expected_out = observation.out_before | record.second;
          else if (offset == IP_PADOUTCLR_OFFSET) expected_out = observation.out_before & ~record.second;
          expected_out &= kPadMask;
          // The APB write is the input; the sampled output port and the pad the
          // host resolved from it are the two consequences this case insists on.
          // A register outside that family must leave the pads untouched.
          passed = observation.apb_writes == 1 && observation.apb_pready
              && observation.apb_address == offset
              && observation.apb_wdata == record.second
              && !observation.write_accepted
              && observation.out_after == expected_out
              && (observation.pad_after & observation.dir_after) ==
                 (expected_out & observation.dir_after)
              && (observation.pad_after & ~observation.dir_after & kPadMask) ==
                 (observation.ext_value & ~observation.dir_after & kPadMask);
          break;
        }
#if HAVE_IRQ_LINK && TRIGGER_COUNT > 0
        case kF5:
          // Every term is a real completion: the declared trigger writes, the
          // pin transition the device itself reported, one ISR read of the
          // declared status word (reading INTSTATUS is the device's clear), the
          // dependent RAM store of the value just read, the handler flag and the
          // CPU's own take of the sampled interrupt.
          passed = observation.irq_edges >= 1 && observation.irq_takes >= 1
              && observation.apb_writes == TRIGGER_COUNT && observation.apb_reads == 1
              && observation.apb_read_offset == kIpStatusOffset
              && observation.isr_result == observation.apb_read_data
              && observation.isr_flag
              && observation.apb_last_write_offset == IP_TRIGGER_LAST_OFFSET
              && observation.apb_last_write_data == word_at(record, TRIGGER_COUNT - 1)
              && observation.pad_rise_events >= 1 && observation.first_rise_tick > 0
              && observation.first_irq_tick >= observation.first_rise_tick
              && (observation.irq_cause_pins & observation.inten_at_irq) != 0;
          break;
#endif
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
                << " apb_reads " << observation.apb_reads
                << " apb_writes " << observation.apb_writes
                << " pad_before " << hex32(observation.pad_before)
                << " pad_after " << hex32(observation.pad_after)
                << " out_after " << hex32(observation.out_after)
                << " dir_after " << hex32(observation.dir_after)
                << " ext_value " << hex32(observation.ext_value)
                << " pad_changes " << observation.pad_changes
                << " pad_rise_events " << observation.pad_rise_events
                << " rise_mask " << hex32(observation.rise_mask)
                << " fall_mask " << hex32(observation.fall_mask);
      if (record.flow == kF1)
        std::cout << " fetch " << hex32(observation.slot_fetch_address)
                  << " retire_pc " << hex32(observation.slot_retire_pc)
                  << " retire_insn " << hex32(observation.slot_retire_insn)
                  << " successor_pc " << hex32(observation.slot_successor_pc);
      if (record.flow == kF2 || record.flow == kP)
        std::cout << " read_addr " << hex32(observation.read_address)
                  << " read_value " << hex32(observation.read_value)
                  << " echo_value " << hex32(observation.echo_value)
                  << " read_from " << (observation.read_from_ip ? "apb" : "ram")
                  << " apb_rdata " << hex32(observation.apb_rdata)
                  << " pad_at_read " << hex32(observation.pad_at_read)
                  << " padin_latch " << hex32(observation.padin_latch_at_read);
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
                  << " apb_pready " << int(observation.apb_pready)
                  << " out_before " << hex32(observation.out_before)
                  << " dir_before " << hex32(observation.dir_before);
      if (record.flow == kF5)
        std::cout << " trigger_writes " << TRIGGER_COUNT
                  << " apb_read_offset " << hex32(observation.apb_read_offset)
                  << " apb_read_data " << hex32(observation.apb_read_data)
                  << " apb_last_write_offset " << hex32(observation.apb_last_write_offset)
                  << " apb_last_write_data " << hex32(observation.apb_last_write_data)
                  << " irq_edges " << observation.irq_edges
                  << " irq_high_ticks " << observation.irq_high
                  << " irq_takes " << observation.irq_takes
                  << " irq_cause_pins " << hex32(observation.irq_cause_pins)
                  << " inten_at_irq " << hex32(observation.inten_at_irq)
                  << " first_rise_tick " << observation.first_rise_tick
                  << " first_irq_tick " << observation.first_irq_tick
                  << " status_after_read " << hex32(observation.status_after_read)
                  << " isr_result " << hex32(observation.isr_result)
                  << " isr_flag " << int(observation.isr_flag);
      std::cout << '\n';
      total_apb_reads += observation.apb_reads;
      total_apb_writes += observation.apb_writes;
      total_d_reads += observation.d_reads;
      total_d_writes += observation.d_writes;
      total_fetches += observation.i_fetches;
      total_pad_rises += observation.pad_rise_events;
      total_irq_edges += observation.irq_edges;
      total_irq_takes += observation.irq_takes;
      total_irq_high += observation.irq_high;
      ++cases;
      if (!passed) throw std::runtime_error("case observation failed");
      if (memory.read(kCommand) != 0) throw std::runtime_error("CPU did not consume the mailbox");
#if HAVE_IRQ_LINK
      // The next case starts from a low interrupt baseline; a source that is
      // still asserted belongs to the case that just ended.
      irq.edges = 0; irq.remaining = 0;
#endif
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
              << " apb_transfers " << (total_apb_reads + total_apb_writes)
              << " apb_reads " << total_apb_reads << " apb_writes " << total_apb_writes
              << " pad_changes " << total_pad_changes
              << " pad_rise_events " << total_pad_rises
              << " final_pad " << hex32(pads.value)
              << " final_out " << hex32(pads.out) << " final_dir " << hex32(pads.dir)
#if HAVE_IRQ_LINK
              << " irq_high_ticks " << total_irq_high
              << " irq_edges " << total_irq_edges << " irq_takes " << total_irq_takes
              << " irq_delivery observed"
#else
              << " irq_delivery unknown"
#endif
              << " pad_driver device_when_dir_high_else_host"
              << " pin_model observed"
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
