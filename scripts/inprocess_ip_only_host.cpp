// One in-process IP-only run: a single generated register-target model, no CPU.
//
// The host links exactly one generated local-runtime artifact (the target IP),
// drives the declared protocol transactions through the model's own req/rsp beat
// port, and records the device's real responses plus the passive protocol trace.
// No CPU model, no DMA model and no RAM image exist in this executable: the
// generated ``ip_only_config.h`` states one model, one request/response channel
// and one protocol trace, and the port traits it carries are the same
// ``myfuzz_ip::IpTarget<0>`` interface the combined host renders
// (``_generated_target_traits``), so this loop has no device-name branch.
//
// Four target protocols are driven through that one beat face; only the passive
// trace sample, the completion criterion and the case-line words differ, and each
// comes from the artifact's own trace roles:
//
//   APB3       psel & penable & pready in one sample is one completed transfer
//   Wishbone   cyc & ack in one sample; the word-addressed slave's adr*4 is the
//              byte offset a case reports, and the optional stall pin is sampled
//              only when this target's trace carries it
//   TL-UL      the A-channel handshake accepts the request, the D-channel
//              handshake completes it; the payload is the accepted A channel's
//              and the completed D channel's
//   AXI4-Lite  AW+W then B for a write, AR then R for a read; the response code
//              is sampled from BRESP/RRESP and reported as observed or unknown
//
// Inputs are the same session shapes the combined entry uses: a comma-separated
// record list handed over on argv (fixed transactions) or ``--online``, where the
// host asks for one ``NEED_RECORD <n>`` at a time and the parent answers with one
// ``CASE ...`` line.  The online shape is also how a closed-loop session runs:
// the parent's next record is a function of the case lines this host already
// printed.  A transaction is one of
//
//   CASE R <offset>            read one word at the declared window offset
//   CASE W <offset> <value>    write one word at the declared window offset
//   CASE WAIT <ticks>          drive no request for the declared number of ticks
//
// The record text is canonical (offsets and values are 8 hex digits); the host
// re-parses it and prints one ``case`` line per executed transaction.  A
// transaction that never sees its request accepted or its response returned
// inside the declared case budget is a bus timeout and is printed as an
// ``environment_timeout`` case: a missing answer is an environment fact, not a
// device answer and not an assertion.  Verilator's own assertion support is on by
// default in 5.x, so a DUT assertion aborts this process; the parent captures the
// abort (exit code and stderr) and attributes it to the last ``case_begin``/
// ``tick`` line this host printed.  A real device assertion is therefore reported
// by the parent as an assertion event, never fabricated here.
//
// The host also prints one ``timing`` line: the wall seconds it spent and the
// seconds it spent inside the model's own evaluation (the clock edges and the
// pre-edge samples), with the ticks those seconds advanced.  That is what lets
// the summary state how much of a session was the DUT and how much was process
// start-up or I/O, in this shape and in the one-child-per-case shape.
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "ip_only_config.h"

namespace {

using Model = IP_ONLY_MODEL;
using Target = myfuzz_ip::IpTarget<0>;

constexpr unsigned kRequestBe = 15u;

uint64_t g_tick = 0;
bool g_trace_ticks = IP_ONLY_TRACE_TICKS != 0;
unsigned g_case = 0;
const char *g_phase = "idle";

// Wall time spent inside the model's own evaluation: the clock advance of every
// tick and the pre-edge samples.  Everything else this process does (parsing,
// formatting, printing) is host overhead, so the ratio below is a measured
// "how much of this run was the DUT really being advanced" and not an estimate.
using Clock = std::chrono::steady_clock;
const Clock::time_point g_started = Clock::now();
double g_dut_seconds = 0.0;

double seconds_since(Clock::time_point start) {
  return std::chrono::duration<double>(Clock::now() - start).count();
}

std::string decimal6(double value) {
  char text[32];
  std::snprintf(text, sizeof(text), "%.6f", value);
  return std::string(text);
}

std::string hex32(uint32_t value) {
  char text[11];
  std::snprintf(text, sizeof(text), "0x%08x", value);
  return std::string(text);
}

void flush_line(const std::string &line) {
  std::cout << line << '\n';
  std::cout.flush();
}

enum class Op { kRead, kWrite, kWait };

struct Transaction {
  Op op = Op::kRead;
  uint32_t offset = 0;
  uint32_t value = 0;
  uint32_t ticks = 0;
};

const char *op_name(Op op) {
  switch (op) {
    case Op::kRead: return "read";
    case Op::kWrite: return "write";
    default: return "wait";
  }
}

struct Run {
  VerilatedContext context;
  Model model{&context, "ip"};

  void set_clock(int level) { Target::clock(model, level); }
  void set_reset(int level) { Target::set_reset(model, level); }
  void eval() {
    const Clock::time_point started = Clock::now();
    model.eval();
    g_dut_seconds += seconds_since(started);
  }

  // One declared target clock edge.  The combined host's OBI/Wishbone edge is
  // the same three-phase sample, so a target behaves identically here.
  void edge() {
    set_clock(0);
    eval();
    set_clock(1);
    eval();
    set_clock(0);
    eval();
    ++g_tick;
    if (g_trace_ticks) {
      flush_line("tick " + std::to_string(g_tick) + " case " +
                 std::to_string(g_case) + " phase " + g_phase);
    }
  }

  void drive(bool valid, bool write, uint32_t offset, uint32_t value) {
    Target::drive_request(model, valid, write, offset, value, kRequestBe);
  }
};

// The per-case observations the parent reads.  Every word here is sampled from
// the model's own ports after an edge; nothing is derived from the declaration.
struct Observation {
  unsigned transfers = 0;   // completed protocol transfers sampled from the trace
  // The address the target's own address port carried on the transfer that
  // completed.  It is the sampled fact a case is checked against, not the request
  // the host drove.
  uint32_t trace_offset = 0;
  unsigned have_offset = 0;
  // APB3 taps.
  unsigned apb_sel = 0, apb_enable = 0, apb_ready = 0, apb_write = 0;
  uint32_t apb_addr = 0, apb_wdata = 0, apb_rdata = 0;
  unsigned apb_error = 0;
  bool have_trace = false;
  // Wishbone classic taps.  ``wb_acks`` is the completion (cyc held with ack);
  // ``wb_stb_pulses`` is the one-cycle request pulse the registered-ack variants
  // drive, counted where it really is instead of being inferred from the ack.
  unsigned wb_cyc = 0, wb_stb = 0, wb_ack = 0, wb_we = 0, wb_sel = 0, wb_stall = 0;
  uint32_t wb_addr = 0, wb_wdata = 0, wb_rdata = 0;
  unsigned wb_acks = 0, wb_stb_pulses = 0;
  // TL-UL taps: the A channel the request was accepted on and the D channel the
  // response completed on.  The payload printed is the accepted A channel's and
  // the completed D channel's, the values the target's own pins carried.
  unsigned tlul_a_valid = 0, tlul_a_ready = 0, tlul_a_opcode = 0, tlul_a_mask = 0;
  uint32_t tlul_a_address = 0, tlul_a_data = 0;
  unsigned tlul_d_valid = 0, tlul_d_ready = 0, tlul_d_error = 0;
  uint32_t tlul_d_data = 0;
  unsigned tlul_a_handshakes = 0, tlul_d_handshakes = 0;
  // AXI4-Lite taps: five channels counted apart and joined at the beat response
  // below, because a write needs AW and W before B and a read needs AR before R.
  unsigned axi_aw = 0, axi_w = 0, axi_b = 0, axi_ar = 0, axi_r = 0;
  uint32_t axi_awaddr = 0, axi_wdata = 0, axi_araddr = 0, axi_rdata = 0;
  unsigned axi_wstrb = 0, axi_bresp = 0, axi_rresp = 0, axi_resp_non_okay = 0;
  // The device's answer on its own beat response port.
  uint32_t rdata = 0;
  unsigned response_error = 0;
  unsigned response_seen = 0;
  unsigned irq_edges = 0, irq_high_ticks = 0;
  uint32_t irq_final = 0;
  bool irq_previous = false;
  unsigned waited = 0;
};

#if IP_ONLY_PROTOCOL_APB3
constexpr bool kApb3 = true;
#else
constexpr bool kApb3 = false;
#endif

// One passive-trace sample after an edge, per protocol.  The criterion is the
// protocol's own completion: psel+penable+pready for APB3, cyc+ack for a classic
// Wishbone, the D-channel handshake after the A-channel handshake for TL-UL, and
// the B/R response after its request channels for AXI4-Lite.  The trace is kept
// apart from the beat response: a trace that never shows the completion is zero
// transfers while the response is reported as it is.
//
// The per-protocol selection is made from this target's own generated traits
// (``Target::apb``/``wishbone``/``tlul``, the AXI4-Lite fallback), exactly like
// the combined host: the host has no device-name and no component-name branch.
void trace_tick(Run &run, Observation &observation) {
#if IP_ONLY_PROTOCOL_APB3
    if (!(Target::apb_sel(run.model) && Target::apb_enable(run.model)
          && Target::apb_ready(run.model)))
      return;
    observation.apb_sel = 1;
    observation.apb_enable = 1;
    observation.apb_ready = 1;
    observation.apb_write = Target::apb_write(run.model) ? 1u : 0u;
    observation.apb_addr = Target::apb_addr(run.model);
    observation.apb_wdata = Target::apb_wdata(run.model);
    observation.apb_rdata = Target::apb_rdata(run.model);
#if IP_ONLY_APB_ERROR_SAMPLED
    observation.apb_error = Target::apb_error(run.model) ? 1u : 0u;
#endif
    observation.trace_offset = observation.apb_addr;
    observation.have_offset = 1;
    observation.have_trace = true;
    ++observation.transfers;
#elif IP_ONLY_PROTOCOL_WISHBONE
    const bool cyc = Target::wb_cyc(run.model);
    const bool stb = Target::wb_stb(run.model);
    const bool ack = Target::wb_ack(run.model);
    if (cyc && stb) ++observation.wb_stb_pulses;
#if IP_ONLY_WB_STALL_SAMPLED
    if (Target::wb_stall(run.model)) ++observation.wb_stall;
#endif
    if (!(cyc && ack)) return;
    observation.wb_cyc = 1;
    observation.wb_stb = stb ? 1u : 0u;
    observation.wb_ack = 1;
    observation.wb_we = Target::wb_we(run.model) ? 1u : 0u;
    // The pinned kernel is word addressed, so the byte offset it decoded is the
    // slave's own address port times four.
    observation.wb_addr = Target::wb_adr(run.model) * 4u;
    observation.wb_wdata = Target::wb_dat_w(run.model);
    observation.wb_rdata = Target::wb_dat_r(run.model);
    observation.wb_sel = Target::wb_sel(run.model);
    observation.trace_offset = observation.wb_addr;
    observation.have_offset = 1;
    observation.have_trace = true;
    ++observation.wb_acks;
    ++observation.transfers;
#elif IP_ONLY_PROTOCOL_TLUL
    // The A channel's payload is meaningful while the channel is valid; the last
    // sample before acceptance is the request the target took.
    const bool a_valid = Target::tlul_a_valid(run.model);
    const bool a_ready = Target::tlul_a_ready(run.model);
    if (a_valid && a_ready) ++observation.tlul_a_handshakes;
    if (a_valid) {
      observation.tlul_a_valid = 1;
      observation.tlul_a_ready = a_ready ? 1u : 0u;
      observation.tlul_a_opcode = Target::tlul_a_opcode(run.model);
      observation.tlul_a_address = Target::tlul_a_address(run.model);
      observation.tlul_a_mask = Target::tlul_a_mask(run.model);
      observation.tlul_a_data = Target::tlul_a_data(run.model);
    }
    const bool d_valid = Target::tlul_d_valid(run.model);
    const bool d_ready = Target::tlul_d_ready(run.model);
    if (!d_valid) return;
    observation.tlul_d_valid = 1;
    observation.tlul_d_ready = d_ready ? 1u : 0u;
    observation.tlul_d_data = Target::tlul_d_data(run.model);
    observation.tlul_d_error = Target::tlul_d_error(run.model) ? 1u : 0u;
    if (!(d_valid && d_ready)) return;
    // One completed response: this is the case's target transfer.  The request
    // it answers is the A channel this host already captured (the address and
    // the write flag come from there; opcode 4 is Get, everything else is a Put).
    ++observation.tlul_d_handshakes;
    observation.trace_offset = observation.tlul_a_address;
    observation.have_offset = 1;
    observation.have_trace = true;
    ++observation.transfers;
#else
    const bool aw = Target::axi_awvalid(run.model) && Target::axi_awready(run.model);
    const bool w = Target::axi_wvalid(run.model) && Target::axi_wready(run.model);
    const bool b = Target::axi_bvalid(run.model) && Target::axi_bready(run.model);
    const bool ar = Target::axi_arvalid(run.model) && Target::axi_arready(run.model);
    const bool r = Target::axi_rvalid(run.model) && Target::axi_rready(run.model);
    if (aw) {
      ++observation.axi_aw;
      observation.axi_awaddr = Target::axi_awaddr(run.model);
    }
    if (w) {
      ++observation.axi_w;
      observation.axi_wdata = Target::axi_wdata(run.model);
      observation.axi_wstrb = Target::axi_wstrb(run.model);
    }
    if (ar) {
      ++observation.axi_ar;
      observation.axi_araddr = Target::axi_araddr(run.model);
    }
    if (b) {
      ++observation.axi_b;
      observation.axi_bresp = Target::axi_bresp(run.model);
      if (observation.axi_bresp != 0) observation.axi_resp_non_okay = 1;
      observation.trace_offset = observation.axi_awaddr;
      observation.have_offset = 1;
      observation.have_trace = true;
      ++observation.transfers;
    }
    if (r) {
      ++observation.axi_r;
      observation.axi_rdata = Target::axi_rdata(run.model);
      observation.axi_rresp = Target::axi_rresp(run.model);
      if (observation.axi_rresp != 0) observation.axi_resp_non_okay = 1;
      observation.trace_offset = observation.axi_araddr;
      observation.have_offset = 1;
      observation.have_trace = true;
      ++observation.transfers;
    }
#endif
}

// The device's own interrupt output, sampled per tick.  An edge is a transition
// from no asserted bit to at least one asserted bit; ``high_ticks`` counts every
// sampled tick with any bit high.  This observes the real output and drives
// nothing: the IP-only host has no interrupt consumer.
void sample_irq(Run &run, Observation &observation) {
#if IP_ONLY_HAS_IRQ
  const uint32_t value = uint32_t(Target::irq_value(run.model));
  observation.irq_final = value;
  const bool high = value != 0;
  if (high) ++observation.irq_high_ticks;
  if (high && !observation.irq_previous) ++observation.irq_edges;
  observation.irq_previous = high;
#else
  (void)run;
  (void)observation;
#endif
}

// One recorded input line.  ``CASE`` is the combined entry's canonical message
// prefix, kept so the same parent hand-over driver can answer either host.
bool parse_transaction(const std::string &text, Transaction &out) {
  std::vector<std::string> tokens;
  {
    std::string token;
    std::istringstream stream(text);
    while (stream >> token) tokens.push_back(token);
  }
  std::size_t position = 0;
  if (!tokens.empty() && tokens[0] == "CASE") position = 1;
  if (position >= tokens.size()) return false;
  const std::string &tag = tokens[position++];
  auto hex = [](const std::string &word, uint32_t &value) {
    const char *start = word.c_str();
    if (word.rfind("0x", 0) == 0 || word.rfind("0X", 0) == 0) start += 2;
    char *end = nullptr;
    const unsigned long parsed = std::strtoul(start, &end, 16);
    if (end == start || (end != nullptr && *end != '\0')) return false;
    if (parsed > 0xfffffffful) return false;
    value = uint32_t(parsed);
    return true;
  };
  if (tag == "R") {
    if (position + 1 != tokens.size()) return false;
    out.op = Op::kRead;
    return hex(tokens[position], out.offset);
  }
  if (tag == "W") {
    if (position + 2 != tokens.size()) return false;
    out.op = Op::kWrite;
    return hex(tokens[position], out.offset) && hex(tokens[position + 1], out.value);
  }
  if (tag == "WAIT") {
    if (position + 1 != tokens.size()) return false;
    out.op = Op::kWait;
    return hex(tokens[position], out.ticks);
  }
  return false;
}

// The canonical text of one transaction, echoed in the log so a saved line can
// be replayed without the input file.
std::string transaction_text(const Transaction &transaction) {
  if (transaction.op == Op::kRead) return "CASE R " + hex32(transaction.offset).substr(2);
  if (transaction.op == Op::kWrite)
    return "CASE W " + hex32(transaction.offset).substr(2) + " " +
           hex32(transaction.value).substr(2);
  return "CASE WAIT " + hex32(transaction.ticks).substr(2);
}

// The address a transaction really presents: the declared window base plus the
// offset the record carried.  The record names a window offset, never a host RAM
// address, because there is no RAM image in an IP-only run.
constexpr uint32_t kWindowBase = IP_ONLY_BASE;
constexpr uint32_t kWindowSize = IP_ONLY_SIZE;

bool offset_in_window(uint32_t offset) {
  return kWindowSize >= 4u && offset <= kWindowSize - 4u;
}

}  // namespace

int main(int argc, char **argv) {
  bool online = false;
  unsigned base_index = 0;
  unsigned loops_override = 0;
  std::string record_text;
  long max_ticks = -1;
  auto is_decimal = [](const std::string &word) {
    if (word.empty()) return false;
    for (char character : word)
      if (character < '0' || character > '9') return false;
    return true;
  };
  for (int position = 1; position < argc; ++position) {
    const std::string argument = argv[position];
    if (argument == "--online") {
      online = true;
    } else if (argument == "--trace-ticks") {
      g_trace_ticks = true;
    } else if (argument == "--base-index" && position + 1 < argc) {
      base_index = unsigned(std::strtoul(argv[++position], nullptr, 10));
    } else if (argument == "--loops" && position + 1 < argc) {
      loops_override = unsigned(std::strtoul(argv[++position], nullptr, 10));
    } else if (max_ticks < 0 && is_decimal(argument)) {
      max_ticks = std::strtol(argument.c_str(), nullptr, 10);
    } else if (record_text.empty()) {
      record_text = argument;
    } else {
      std::cerr << "ip_only: unexpected argument " << argument << '\n';
      return 2;
    }
  }
  if (max_ticks < 1) {
    std::cerr << "ip_only: a positive tick budget is required\n";
    return 2;
  }
  if (!online && record_text.empty()) {
    std::cerr << "ip_only: no record text and not --online\n";
    return 2;
  }
  // The declared sequence loop is a property of the scenario; a per-case child
  // (case_isolation) states 1 because it executes exactly one transaction.
  const unsigned loops = loops_override == 0 ? IP_ONLY_LOOP_COUNT : loops_override;

  Run run;
  Observation observation;
  Target::fixed_inputs(run.model);
  run.set_clock(0);
  run.set_reset(1);
  run.eval();
  for (unsigned step = 0; step < IP_ONLY_RESET_ASSERT; ++step) run.edge();
  run.set_clock(0);
  run.set_reset(0);
  run.eval();
  for (unsigned step = 0; step < IP_ONLY_RESET_RELEASE; ++step) run.edge();
  if (run.model.eventsPending()) {
    std::cerr << "ip_only: the selected model schedules timed events; this host has no "
                 "timing scheduler\n";
    return 2;
  }
  flush_line(std::string("ip_only model ") + IP_ONLY_MODEL_NAME + " protocol " +
             IP_ONLY_PROTOCOL + " base " + hex32(kWindowBase) + " size " +
             std::to_string(kWindowSize) + " reset_assert " +
             std::to_string(IP_ONLY_RESET_ASSERT) + " reset_release " +
             std::to_string(IP_ONLY_RESET_RELEASE) + " case_tick_budget " +
             std::to_string(IP_ONLY_CASE_TICK_BUDGET) + " loops " +
             std::to_string(loops) + " declared_loops " +
             std::to_string(IP_ONLY_LOOP_COUNT));

  std::vector<Transaction> transactions;
  if (!online) {
    std::string token;
    std::istringstream stream(record_text);
    while (std::getline(stream, token, ',')) {
      if (!token.empty() && token.back() == '\r') token.pop_back();
      Transaction transaction;
      if (!parse_transaction(token, transaction)) {
        std::cerr << "ip_only: unreadable record " << token << '\n';
        return 2;
      }
      transactions.push_back(transaction);
    }
  }

  unsigned case_index = base_index;
  unsigned executed = 0, passed = 0, failed = 0, timeouts = 0;
  auto begin_case = [&](const Transaction &transaction, unsigned loop) {
    g_case = case_index;
    g_phase = "reset";
    // A WAIT transaction indexes no offset; the log states it as such instead of
    // borrowing a register address the record never named.
    const bool wait = transaction.op == Op::kWait;
    flush_line("case_begin " + std::to_string(case_index) + " op " +
               op_name(transaction.op) + " offset " +
               (wait ? std::string("none") : hex32(transaction.offset)) + " value " +
               hex32(transaction.value) + " ticks " +
               std::to_string(transaction.ticks) + " loop " + std::to_string(loop) +
               " record " + transaction_text(transaction));
  };

  auto execute = [&](const Transaction &transaction, unsigned loop) {
    observation = Observation();
    if (transaction.op != Op::kWait && !offset_in_window(transaction.offset)) {
      flush_line("case " + std::to_string(case_index) +
                 " environment_timeout reason offset-outside-window offset " +
                 hex32(transaction.offset));
      ++timeouts;
      ++case_index;
      return;
    }
    begin_case(transaction, loop);
    unsigned waited = 0;
    bool timed_out = false;
    std::string timeout_phase;
    if (transaction.op == Op::kWait) {
      g_phase = "wait";
      for (uint32_t step = 0; step < transaction.ticks; ++step) {
        if (g_tick >= uint64_t(max_ticks)) {
          timed_out = true;
          timeout_phase = "global-tick-budget";
          break;
        }
        run.drive(false, false, 0, 0);
        run.eval();
        trace_tick(run, observation);
        sample_irq(run, observation);
        run.edge();
        ++waited;
      }
    } else {
      const bool write = transaction.op == Op::kWrite;
      g_phase = "request";
      bool sent = false, done = false;
      while (!done && !timed_out) {
        if (g_tick >= uint64_t(max_ticks)) {
          timed_out = true;
          timeout_phase = "global-tick-budget";
          break;
        }
        if (waited >= IP_ONLY_CASE_TICK_BUDGET) {
          timed_out = true;
          timeout_phase = sent ? "response-not-valid" : "request-not-ready";
          break;
        }
        run.drive(!sent, write, transaction.offset, transaction.value);
        // Sample the model's own handshake and trace *before* the edge: req_ready
        // is combinational in IDLE, the request is accepted at this edge, and the
        // response register is visible in the following tick's pre-edge sample.
        // This is the same sample point the combined host uses.
        run.eval();
        const bool take = !sent && Target::request_ready(run.model);
        const bool respond = sent && Target::response_valid(run.model);
        if (respond) {
          observation.response_seen = 1;
          observation.rdata = Target::response_rdata(run.model);
          observation.response_error = Target::response_error(run.model) ? 1u : 0u;
        }
        trace_tick(run, observation);
        sample_irq(run, observation);
        run.edge();
        if (take) {
          sent = true;
          g_phase = "response";
        }
        if (respond) done = true;
        ++waited;
      }
      // Return the request port to its idle state and let the model settle, so
      // the last observation is not a dangling request.
      run.drive(false, false, 0, 0);
      run.eval();
      sample_irq(run, observation);
    }
    observation.waited = waited;
    const std::string prefix = "case " + std::to_string(case_index) + ' ';
    if (timed_out) {
      flush_line(prefix + "environment_timeout reason " + timeout_phase + " waited " +
                 std::to_string(waited) + " op " + op_name(transaction.op));
      ++timeouts;
      ++executed;
    } else {
      // The device's answer is real: the beat response states the data word and
      // the declared error channel, and the protocol trace states the transfer
      // the slave's own pins completed.  A read whose trace completed but whose
      // beat response never arrived is not reported as a passed read.
      const bool wait = transaction.op == Op::kWait;
      const bool ok = wait || (observation.response_seen && observation.have_trace
                               && observation.transfers == 1u);
      std::string line = prefix + (ok ? "observations_passed" : "failed") + " op " +
                         op_name(transaction.op);
      if (!wait) {
        line += " offset " + hex32(transaction.offset) + " addr " +
                hex32(kWindowBase + transaction.offset) + " be " +
                hex32(kRequestBe) + " wdata " + hex32(transaction.value) + " rdata " +
                hex32(observation.rdata) + " response_error " +
                std::to_string(observation.response_error) + " response_seen " +
                std::to_string(observation.response_seen);
      } else {
        line += " waited " + std::to_string(observation.waited);
      }
      line += " ticks " + std::to_string(observation.waited) + " total_tick " +
              std::to_string(g_tick) + " target_transfers " +
              std::to_string(observation.transfers) + " target_ready " +
              std::to_string(observation.have_trace ? 1 : 0) +
              " irq_edges " + std::to_string(observation.irq_edges) +
              " irq_high_ticks " + std::to_string(observation.irq_high_ticks) +
              " irq_final " + hex32(observation.irq_final) + " loop " +
              std::to_string(loop);
#if IP_ONLY_PROTOCOL_APB3
        line += std::string(" protocol ") + IP_ONLY_PROTOCOL + " apb_psel " +
                std::to_string(observation.apb_sel) + " apb_penable " +
                std::to_string(observation.apb_enable) + " apb_pready " +
                std::to_string(observation.apb_ready) + " apb_pwrite " +
                std::to_string(observation.apb_write) + " apb_paddr " +
                hex32(observation.apb_addr) + " apb_pwdata " +
                hex32(observation.apb_wdata) + " apb_prdata " +
                hex32(observation.apb_rdata);
#if IP_ONLY_APB_ERROR_SAMPLED
        line += " apb_pslverr " + std::to_string(observation.apb_error);
#endif
#elif IP_ONLY_PROTOCOL_WISHBONE
        // The classic handshake the slave's own pins carried, plus the two
        // counters that state which sample was the request pulse and which was
        // the completion.
        line += std::string(" protocol ") + IP_ONLY_PROTOCOL + " wb_cyc " +
                std::to_string(observation.wb_cyc) + " wb_stb " +
                std::to_string(observation.wb_stb) + " wb_ack " +
                std::to_string(observation.wb_ack) + " wb_we " +
                std::to_string(observation.wb_we) + " wb_adr " +
                hex32(observation.wb_addr / 4u) + " wb_offset " +
                hex32(observation.wb_addr) + " wb_dat_w " +
                hex32(observation.wb_wdata) + " wb_dat_r " +
                hex32(observation.wb_rdata) + " wb_sel " +
                std::to_string(observation.wb_sel) + " wb_acks " +
                std::to_string(observation.wb_acks) + " wb_stb_pulses " +
                std::to_string(observation.wb_stb_pulses);
#if IP_ONLY_WB_STALL_SAMPLED
        line += " wb_stall " + std::to_string(observation.wb_stall);
#endif
        line += " target_offset " + hex32(observation.trace_offset);
#elif IP_ONLY_PROTOCOL_TLUL
        line += std::string(" protocol ") + IP_ONLY_PROTOCOL + " tlul_a_valid " +
                std::to_string(observation.tlul_a_valid) + " tlul_a_ready " +
                std::to_string(observation.tlul_a_ready) + " tlul_a_opcode " +
                std::to_string(observation.tlul_a_opcode) + " tlul_a_address " +
                hex32(observation.tlul_a_address) + " tlul_a_mask " +
                std::to_string(observation.tlul_a_mask) + " tlul_a_data " +
                hex32(observation.tlul_a_data) + " tlul_d_valid " +
                std::to_string(observation.tlul_d_valid) + " tlul_d_ready " +
                std::to_string(observation.tlul_d_ready) + " tlul_d_data " +
                hex32(observation.tlul_d_data) + " tlul_d_error " +
                std::to_string(observation.tlul_d_error) + " tlul_a_handshakes " +
                std::to_string(observation.tlul_a_handshakes) + " tlul_d_handshakes " +
                std::to_string(observation.tlul_d_handshakes) + " target_offset " +
                hex32(observation.trace_offset);
#else
        line += std::string(" protocol ") + IP_ONLY_PROTOCOL + " axi_aw " +
                std::to_string(observation.axi_aw) + " axi_w " +
                std::to_string(observation.axi_w) + " axi_b " +
                std::to_string(observation.axi_b) + " axi_ar " +
                std::to_string(observation.axi_ar) + " axi_r " +
                std::to_string(observation.axi_r) + " axi_awaddr " +
                hex32(observation.axi_awaddr) + " axi_wdata " +
                hex32(observation.axi_wdata) + " axi_wstrb " +
                std::to_string(observation.axi_wstrb) + " axi_bresp " +
                std::to_string(observation.axi_bresp) + " axi_araddr " +
                hex32(observation.axi_araddr) + " axi_rdata " +
                hex32(observation.axi_rdata) + " axi_rresp " +
                std::to_string(observation.axi_rresp) + " axi_resp_non_okay " +
                std::to_string(observation.axi_resp_non_okay) + " target_offset " +
                hex32(observation.trace_offset);
#endif
      flush_line(line);
      ++executed;
      if (ok)
        ++passed;
      else
        ++failed;
    }
    ++case_index;
  };

  if (online) {
    // One record per NEED_RECORD, exactly like the combined online hand-over.
    unsigned loop = 0;
    while (true) {
      flush_line("NEED_RECORD " + std::to_string(executed));
      std::string line;
      if (!std::getline(std::cin, line)) break;
      if (!line.empty() && line.back() == '\r') line.pop_back();
      if (line == "END" || line.empty()) break;
      Transaction transaction;
      if (!parse_transaction(line, transaction)) {
        std::cerr << "ip_only: unreadable record " << line << '\n';
        return 2;
      }
      execute(transaction, loop);
    }
  } else {
    for (unsigned loop = 0; loop < loops; ++loop) {
      for (const Transaction &transaction : transactions) execute(transaction, loop);
    }
  }

  Target::finalize(run.model);
  // The one measurement that separates "the DUT was being advanced" from
  // "this process was starting up, printing or parsing": how much of this
  // process's wall time was spent inside the model's own evaluation, and how
  // many ticks that really advanced it.  A prefix-replay session runs one
  // process per case, so summing this line over its children states both the
  // repeated DUT work and the restart overhead.
  const double wall_seconds = seconds_since(g_started);
  flush_line("timing wall_seconds " + decimal6(wall_seconds) + " dut_seconds " +
             decimal6(g_dut_seconds) + " dut_fraction " +
             decimal6(wall_seconds > 0.0 ? g_dut_seconds / wall_seconds : 0.0) +
             " ticks " + std::to_string(g_tick) + " cases " +
             std::to_string(executed));
  flush_line("summary mode ip-only model " + std::string(IP_ONLY_MODEL_NAME) +
             " protocol " + IP_ONLY_PROTOCOL + " base " + hex32(kWindowBase) +
             " size " + std::to_string(kWindowSize) + " transactions " +
             std::to_string(executed) + " cases " + std::to_string(executed) +
             " passed " + std::to_string(passed) + " failed " + std::to_string(failed) +
             " timeouts " + std::to_string(timeouts) + " ticks " +
             std::to_string(g_tick));
  return failed == 0 && timeouts == 0 ? 0 : 1;
}
