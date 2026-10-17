#include "Vlocal_runtime_cpu.h"
#include "verilated.h"
#include "local_driver_v1.h"



#include <iostream>
#include <map>
#include <string>
#include <vector>

#ifndef MYFUZZ_ARTIFACT_DIGEST
#error MYFUZZ_ARTIFACT_DIGEST must identify the final generated artifact
#endif
#define MYFUZZ_STRINGIFY_IMPL(value) #value
#define MYFUZZ_STRINGIFY(value) MYFUZZ_STRINGIFY_IMPL(value)

using Model = Vlocal_runtime_cpu;
using namespace myfuzz::local_driver_v1;
using JsonObject = std::map<std::string, std::string>;
static std::uint64_t local_ticks = 0;




static std::string quote(const std::string &value) {
  return "\"" + value + "\"";
}
static std::string object(const JsonObject &values) {
  std::string answer = "{";
  for (const auto &entry : values) {
    if (answer.size() > 1) answer += ',';
    answer += quote(entry.first) + ':' + entry.second;
  }
  return answer + '}';
}
static std::string array(const std::vector<std::string> &values) {
  std::string answer = "[";
  for (const auto &value : values) {
    if (answer.size() > 1) answer += ',';
    answer += value;
  }
  return answer + ']';
}
template <typename Wide>
static std::string wide_hex(const Wide &value, unsigned width) {
  const char *digits = "0123456789abcdef";
  std::string answer((width + 3) / 4, '0');
  for (unsigned nibble = 0; nibble < answer.size(); ++nibble) {
    const unsigned bit = 4 * nibble;
    const unsigned remaining = width - bit;
    const unsigned mask = remaining < 4 ? (1u << remaining) - 1 : 15;
    answer[answer.size() - nibble - 1] = digits[(value[bit / 32] >> (bit % 32)) & mask];
  }
  return answer;
}
static std::string backend_snapshot(const Model &dut) {
  return object({
    {"m_req_valid", std::to_string(static_cast<std::uint64_t>(dut.m_req_valid))},
    {"m_req_ready", std::to_string(static_cast<std::uint64_t>(dut.m_req_ready))},
    {"m_req_write", std::to_string(static_cast<std::uint64_t>(dut.m_req_write))},
    {"m_req_addr", std::to_string(static_cast<std::uint64_t>(dut.m_req_addr))},
    {"m_req_wdata", std::to_string(static_cast<std::uint64_t>(dut.m_req_wdata))},
    {"m_req_be", std::to_string(static_cast<std::uint64_t>(dut.m_req_be))},
    {"m_rsp_valid", std::to_string(static_cast<std::uint64_t>(dut.m_rsp_valid))},
    {"m_rsp_ready", std::to_string(static_cast<std::uint64_t>(dut.m_rsp_ready))},
    {"m_rsp_rdata", std::to_string(static_cast<std::uint64_t>(dut.m_rsp_rdata))},
    {"m_rsp_error", std::to_string(static_cast<std::uint64_t>(dut.m_rsp_error))}
  });
}
static std::string snapshot(const Model &dut) {
  JsonObject values = {
    {"protocol_taps", object({
      {"cpu_ahb_trace_haddr", std::to_string(static_cast<std::uint64_t>(dut.cpu_ahb_trace_haddr))},
      {"cpu_ahb_trace_hburst", std::to_string(static_cast<std::uint64_t>(dut.cpu_ahb_trace_hburst))},
      {"cpu_ahb_trace_hmastlock", std::to_string(static_cast<std::uint64_t>(dut.cpu_ahb_trace_hmastlock))},
      {"cpu_ahb_trace_hprot", std::to_string(static_cast<std::uint64_t>(dut.cpu_ahb_trace_hprot))},
      {"cpu_ahb_trace_hrdata", std::to_string(static_cast<std::uint64_t>(dut.cpu_ahb_trace_hrdata))},
      {"cpu_ahb_trace_hready", std::to_string(static_cast<std::uint64_t>(dut.cpu_ahb_trace_hready))},
      {"cpu_ahb_trace_hresp", std::to_string(static_cast<std::uint64_t>(dut.cpu_ahb_trace_hresp))},
      {"cpu_ahb_trace_hsel", std::to_string(static_cast<std::uint64_t>(dut.cpu_ahb_trace_hsel))},
      {"cpu_ahb_trace_hsize", std::to_string(static_cast<std::uint64_t>(dut.cpu_ahb_trace_hsize))},
      {"cpu_ahb_trace_htrans", std::to_string(static_cast<std::uint64_t>(dut.cpu_ahb_trace_htrans))},
      {"cpu_ahb_trace_hwdata", std::to_string(static_cast<std::uint64_t>(dut.cpu_ahb_trace_hwdata))},
      {"cpu_ahb_trace_hwrite", std::to_string(static_cast<std::uint64_t>(dut.cpu_ahb_trace_hwrite))},
      {"cpu_ahb_trace_hwstrb", std::to_string(static_cast<std::uint64_t>(dut.cpu_ahb_trace_hwstrb))}
    })},
    {"backend", backend_snapshot(dut)},
    {"physical", object({
    {"rt_lh_p_2_0_0", std::to_string(static_cast<std::uint64_t>(dut.rt_lh_p_2_0_0))},
    {"rt_lh_p_6_0_0", std::to_string(static_cast<std::uint64_t>(dut.rt_lh_p_6_0_0))},
    {"rt_lh_p_8_0_0", std::to_string(static_cast<std::uint64_t>(dut.rt_lh_p_8_0_0))}
    })}
  };
  return object(values);
}

static void tick(Model &dut, std::vector<std::string> *samples) {

  dut.clk = 0;
  dut.eval();



  const auto pre = samples ? snapshot(dut) : "";
  dut.clk = 1;
  dut.eval();


  ++local_ticks;


  const auto post = samples ? snapshot(dut) : "";
  dut.clk = 0;
  dut.eval();
  if (samples) samples->push_back(object({{"local_tick", std::to_string(local_ticks)},
                                       {"pre", pre}, {"post", post}}));
}
static std::vector<std::string> ahb_startup_records;
static std::size_t ahb_startup_bytes = 0;
static unsigned ahb_startup_next_page = 0;
static void capture_ahb_startup(Model &dut) {
  const auto reset_pre = static_cast<unsigned>(dut.reset);
  std::vector<std::string> measured;
  tick(dut, &measured);
  const auto reset_post = static_cast<unsigned>(dut.reset);
  const auto index = ahb_startup_records.size() + 1;
  const unsigned expected_reset = index <= 8 ? 1 : 0;
  if (measured.size() != 1 || index > 16 ||
      reset_pre != expected_reset || reset_post != expected_reset)
    throw std::runtime_error("ahb_startup_capture_shape");
  const auto record = object({{"startup_edge_index", std::to_string(index)},
      {"reset_pre", std::to_string(reset_pre)}, {"reset_post", std::to_string(reset_post)},
      {"sample", measured[0]}});
  if (record.size() > 1526 ||
      ahb_startup_bytes + record.size() + 1 > 24434)
    throw std::length_error("ahb_startup_buffer_bound");
  ahb_startup_bytes += record.size() + 1;
  ahb_startup_records.push_back(record);
}
static std::string ahb_startup_page(unsigned page) {
  if (page >= 1 || ahb_startup_records.size() != 16)
    throw std::runtime_error("ahb_startup_page_shape");
  const auto start = page * 32;
  std::vector<std::string> records;
  for (unsigned i = start; i < start + 32 && i < 16; ++i)
    records.push_back(ahb_startup_records[i]);
  const auto result = object({{"schema_version", quote("cpu_ahb_startup_page.v1")},
      {"page_index", std::to_string(page)}, {"page_count", "1"},
      {"total_ticks", "16"}, {"assert_ticks", "8"},
      {"release_ticks", "8"}, {"records", array(records)}});
  if (result.size() > 54230) throw std::length_error("ahb_startup_page_bound");
  return result;
}
static std::string encode_hex(const std::string &value) {
  if (value.size() > kMaxPayloadJsonBytes) throw std::length_error("payload_bound");
  const char *digits = "0123456789abcdef";
  std::string answer;
  answer.reserve(2 * value.size());
  for (const unsigned char byte : value) {
    answer += digits[byte >> 4];
    answer += digits[byte & 15];
  }
  return answer;
}
// A bounded reader never materializes an arbitrarily long input line. Oversize
// input is drained through newline, then rejected before replay admission.
static bool read_command(std::string &line, bool &oversize) {
  line.clear(); oversize = false;
  char byte;
  while (std::cin.get(byte)) {
    if (byte == '\n') return true;
    if (line.size() < kMaxCommandBytes) line += byte;
    else oversize = true;
  }
  return !line.empty() || oversize;
}
int main(int argc, char **argv) {
  Verilated::commandArgs(argc, argv);
  Model dut;
  dut.clk = 0;
  dut.reset = 0;
  dut.m_req_ready = 0;
  dut.m_rsp_valid = 0;
  dut.m_rsp_rdata = 0;
  dut.m_rsp_error = 0;
  // Evaluate inactive reset first to create a real asynchronous assertion edge.
  dut.reset = 0;
  dut.eval();
  dut.reset = 1;
  dut.eval();
  std::uint64_t asserted_ticks = 0, released_ticks = 0;
  for (unsigned i = 0; i < 8; ++i) {
    capture_ahb_startup(dut);
    ++asserted_ticks;
  }
  dut.reset = 0;
  dut.eval();
  for (unsigned i = 0; i < 8; ++i) {
    capture_ahb_startup(dut);
    ++released_ticks;
  }


  local_ticks = 0;
  std::cout << "READY local_driver.v1 " << MYFUZZ_STRINGIFY(MYFUZZ_ARTIFACT_DIGEST)
            << " " << hex_integer(asserted_ticks) << " " << hex_integer(released_ticks) << std::endl;
  BoundedReplay replay(67108864, kMaxReplyBytes, CommandSet::AhbStartup);
  std::string line;
  bool oversize;
  while (read_command(line, oversize)) {
    if (!oversize && line == "END") break;
    if (oversize) {
      std::cout << error_reply("-", 0, local_ticks, "command_too_long", "wire_bound") << std::endl;
      continue;
    }
    if (line.rfind("ACK ", 0) == 0) {
      const auto ack = parse_ack(line);
      if (!ack.ok) {
        std::cout << error_reply(ack.execution, ack.sequence, local_ticks,
                                 ack.code, ack.detail) << std::endl;
      } else {
        const auto failure = replay.retire(ack.execution, ack.sequence);
        if (failure.empty())
          std::cout << "ACKED " << ack.execution << ' ' << hex_integer(ack.sequence)
                    << ' ' << hex_integer(local_ticks) << std::endl;
        else
          std::cout << error_reply(ack.execution, ack.sequence, local_ticks,
                                   failure, "ack_rejected") << std::endl;
      }
      continue;
    }
    const auto parsed = parse_command(line, CommandSet::AhbStartup);
    if (!parsed.ok) {
      std::cout << error_reply(parsed.command.execution, parsed.command.sequence,
          local_ticks, parsed.code, parsed.detail) << std::endl;
      continue;
    }
    const auto &command = parsed.command;
    if ((command.operation != "STEP_MEMORY" && command.operation != "READ_AHB_STARTUP")) {
      std::cout << error_reply(command.execution, command.sequence, local_ticks,
                              "invalid_operation", "wrong_runtime_kind") << std::endl;
      continue;
    }
    const auto admission = replay.accept(command, local_ticks, 108972);
    if (admission.decision != Decision::Fresh) {
      std::cout << admission.reply << std::endl;
      continue;
    }
    const auto before = local_ticks;
    std::vector<std::string> samples;
    std::string pre_backend, terminal;
    std::string observations_override;
    std::uint32_t rdata = 0, error = 0;
    try {
      if (command.operation == "READ_AHB_STARTUP") {
        pre_backend = backend_snapshot(dut);
        if (local_ticks != 0 || command.fields[0] != ahb_startup_next_page) {
          terminal = error_reply(command.execution, command.sequence, local_ticks,
                                 "protocol_environment", "ahb_startup_page_order");
        } else {
          observations_override = object({{"ahb_startup", ahb_startup_page(command.fields[0])}});
        }
      } else if (ahb_startup_next_page != 1) {
        terminal = error_reply(command.execution, command.sequence, local_ticks,
                               "protocol_environment", "ahb_startup_incomplete");
      } else {
      dut.m_req_ready = command.fields[0];
      dut.m_rsp_valid = command.fields[1];
      dut.m_rsp_rdata = command.fields[2];
      dut.m_rsp_error = command.fields[3];
      dut.eval();
      pre_backend = backend_snapshot(dut);
      if (false || (dut.m_rsp_valid && !dut.m_rsp_ready)) {
        terminal = error_reply(command.execution, command.sequence, local_ticks,
                               "protocol_environment", "native_unsolicited_or_fault");
      } else {
        tick(dut, &samples);
        if (false) {
          terminal = error_reply(command.execution, command.sequence, local_ticks,
                                 "protocol_environment", "native_completion_fault");
        }
      }

      }
      if (terminal.empty()) {
        const auto payload = object({
          {"schema_version", quote("local_driver_result.v1")}, {"kind", quote("ahb_lite_cpu")},
          {"samples", array(samples)}, {"observations", (observations_override.empty() ? snapshot(dut) : observations_override)},
          {"pre_backend", pre_backend}, {"rdata", std::to_string(rdata)},
          {"error", std::to_string(error)}
        });
        terminal = "RESULT " + command.execution + ' ' + hex_integer(command.sequence) + ' ' +
            hex_integer(before) + ' ' + hex_integer(local_ticks) + ' ' + encode_hex(payload);
      }
      replay.finish(command.sequence, terminal);
      if (command.operation == "READ_AHB_STARTUP" && terminal.rfind("RESULT ", 0) == 0) ++ahb_startup_next_page;
      std::cout << terminal << std::endl;
    } catch (const std::exception &) {
      const auto failure = error_reply(command.execution, command.sequence, local_ticks,
                                       "uncertain_effect", "driver_execution_failed");
      // Best effort receipt; incomplete replay still prevents another execution.
      try { replay.finish(command.sequence, failure); } catch (const std::exception &) {}
      std::cout << failure << std::endl;
      break;
    }
  }
  dut.final();
  return 0;
}
