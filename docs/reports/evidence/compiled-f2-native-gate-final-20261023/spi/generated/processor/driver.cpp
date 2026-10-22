#include "Vlocal_runtime_processor.h"
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

using Model = Vlocal_runtime_processor;
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
    {"d_req_valid", std::to_string(static_cast<std::uint64_t>(dut.d_req_valid))},
    {"d_req_ready", std::to_string(static_cast<std::uint64_t>(dut.d_req_ready))},
    {"d_req_write", std::to_string(static_cast<std::uint64_t>(dut.d_req_write))},
    {"d_req_addr", std::to_string(static_cast<std::uint64_t>(dut.d_req_addr))},
    {"d_req_wdata", std::to_string(static_cast<std::uint64_t>(dut.d_req_wdata))},
    {"d_req_be", std::to_string(static_cast<std::uint64_t>(dut.d_req_be))},
    {"d_rsp_valid", std::to_string(static_cast<std::uint64_t>(dut.d_rsp_valid))},
    {"d_rsp_ready", std::to_string(static_cast<std::uint64_t>(dut.d_rsp_ready))},
    {"d_rsp_rdata", std::to_string(static_cast<std::uint64_t>(dut.d_rsp_rdata))},
    {"d_rsp_error", std::to_string(static_cast<std::uint64_t>(dut.d_rsp_error))},
    {"i_req_valid", std::to_string(static_cast<std::uint64_t>(dut.i_req_valid))},
    {"i_req_ready", std::to_string(static_cast<std::uint64_t>(dut.i_req_ready))},
    {"i_req_write", std::to_string(static_cast<std::uint64_t>(dut.i_req_write))},
    {"i_req_addr", std::to_string(static_cast<std::uint64_t>(dut.i_req_addr))},
    {"i_req_wdata", std::to_string(static_cast<std::uint64_t>(dut.i_req_wdata))},
    {"i_req_be", std::to_string(static_cast<std::uint64_t>(dut.i_req_be))},
    {"i_rsp_valid", std::to_string(static_cast<std::uint64_t>(dut.i_rsp_valid))},
    {"i_rsp_ready", std::to_string(static_cast<std::uint64_t>(dut.i_rsp_ready))},
    {"i_rsp_rdata", std::to_string(static_cast<std::uint64_t>(dut.i_rsp_rdata))},
    {"i_rsp_error", std::to_string(static_cast<std::uint64_t>(dut.i_rsp_error))}
  });
}
static std::string snapshot(const Model &dut) {
  JsonObject values = {
    {"protocol_taps", object({
      {"trace_obi_d_req", std::to_string(static_cast<std::uint64_t>(dut.trace_obi_d_req))},
      {"trace_obi_d_addr", std::to_string(static_cast<std::uint64_t>(dut.trace_obi_d_addr))},
      {"trace_obi_d_gnt", std::to_string(static_cast<std::uint64_t>(dut.trace_obi_d_gnt))},
      {"trace_obi_d_rvalid", std::to_string(static_cast<std::uint64_t>(dut.trace_obi_d_rvalid))},
      {"trace_obi_d_rdata", std::to_string(static_cast<std::uint64_t>(dut.trace_obi_d_rdata))},
      {"trace_obi_d_we", std::to_string(static_cast<std::uint64_t>(dut.trace_obi_d_we))},
      {"trace_obi_d_wdata", std::to_string(static_cast<std::uint64_t>(dut.trace_obi_d_wdata))},
      {"trace_obi_d_be", std::to_string(static_cast<std::uint64_t>(dut.trace_obi_d_be))},
      {"trace_obi_i_req", std::to_string(static_cast<std::uint64_t>(dut.trace_obi_i_req))},
      {"trace_obi_i_addr", std::to_string(static_cast<std::uint64_t>(dut.trace_obi_i_addr))},
      {"trace_obi_i_gnt", std::to_string(static_cast<std::uint64_t>(dut.trace_obi_i_gnt))},
      {"trace_obi_i_rvalid", std::to_string(static_cast<std::uint64_t>(dut.trace_obi_i_rvalid))},
      {"trace_obi_i_rdata", std::to_string(static_cast<std::uint64_t>(dut.trace_obi_i_rdata))}
    })},
    {"backend", backend_snapshot(dut)},
    {"physical", object({
    {"rt_lh_p_0_0_0", std::to_string(static_cast<std::uint64_t>(dut.rt_lh_p_0_0_0))},
    {"rt_lh_p_2_14_0", std::to_string(static_cast<std::uint64_t>(dut.rt_lh_p_2_14_0))},
    {"rt_lh_p_4_5_0", std::to_string(static_cast<std::uint64_t>(dut.rt_lh_p_4_5_0))},
    {"rt_lh_p_5_95_0", quote(wide_hex(dut.rt_lh_p_5_95_0, 96))},
    {"rt_lh_p_6_0_0", std::to_string(static_cast<std::uint64_t>(dut.rt_lh_p_6_0_0))},
    {"rt_lh_p_11_0_0", std::to_string(static_cast<std::uint64_t>(dut.rt_lh_p_11_0_0))},
    {"rt_lh_p_20_0_0", std::to_string(static_cast<std::uint64_t>(dut.rt_lh_p_20_0_0))},
    {"rt_lh_p_21_0_0", std::to_string(static_cast<std::uint64_t>(dut.rt_lh_p_21_0_0))},
    {"rt_lh_p_23_0_0", std::to_string(static_cast<std::uint64_t>(dut.rt_lh_p_23_0_0))},
    {"rt_lh_p_33_0_0", std::to_string(static_cast<std::uint64_t>(dut.rt_lh_p_33_0_0))},
    {"rt_lh_p_34_11_11", std::to_string(static_cast<std::uint64_t>(dut.rt_lh_p_34_11_11))},
    {"rt_lh_p_35_4_0", std::to_string(static_cast<std::uint64_t>(dut.rt_lh_p_35_4_0))}
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
  dut.rt_lh_p_34_11_11 = 0;
  dut.d_req_ready = 0;
  dut.d_rsp_valid = 0;
  dut.d_rsp_rdata = 0;
  dut.d_rsp_error = 0;
  dut.i_req_ready = 0;
  dut.i_rsp_valid = 0;
  dut.i_rsp_rdata = 0;
  dut.i_rsp_error = 0;
  // Evaluate inactive reset first to create a real asynchronous assertion edge.
  dut.reset = 0;
  dut.eval();
  dut.reset = 1;
  dut.eval();
  std::uint64_t asserted_ticks = 0, released_ticks = 0;
  for (unsigned i = 0; i < 8; ++i) {
    tick(dut, nullptr);
    ++asserted_ticks;
  }
  dut.reset = 0;
  dut.eval();
  for (unsigned i = 0; i < 8; ++i) {
    tick(dut, nullptr);
    ++released_ticks;
  }


  local_ticks = 0;
  std::cout << "READY local_driver.v1 " << MYFUZZ_STRINGIFY(MYFUZZ_ARTIFACT_DIGEST)
            << " " << hex_integer(asserted_ticks) << " " << hex_integer(released_ticks) << std::endl;
  BoundedReplay replay(67108864, kMaxReplyBytes);
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
    const auto parsed = parse_command(line);
    if (!parsed.ok) {
      std::cout << error_reply(parsed.command.execution, parsed.command.sequence,
          local_ticks, parsed.code, parsed.detail) << std::endl;
      continue;
    }
    const auto &command = parsed.command;
    if (command.operation != "STEP_CPU") {
      std::cout << error_reply(command.execution, command.sequence, local_ticks,
                              "invalid_operation", "wrong_runtime_kind") << std::endl;
      continue;
    }
    const auto admission = replay.accept(command, local_ticks, 9560);
    if (admission.decision != Decision::Fresh) {
      std::cout << admission.reply << std::endl;
      continue;
    }
    const auto before = local_ticks;
    std::vector<std::string> samples;
    std::string pre_backend, terminal;
    std::uint32_t rdata = 0, error = 0;
    try {
      dut.rt_lh_p_34_11_11 = command.fields[0];
      dut.i_req_ready = command.fields[1];
      dut.i_rsp_valid = command.fields[2];
      dut.i_rsp_rdata = command.fields[3];
      dut.i_rsp_error = command.fields[4];
      dut.d_req_ready = command.fields[5];
      dut.d_rsp_valid = command.fields[6];
      dut.d_rsp_rdata = command.fields[7];
      dut.d_rsp_error = command.fields[8];
      dut.eval();
      pre_backend = backend_snapshot(dut);
      if ((dut.i_rsp_valid && !dut.i_rsp_ready) || (dut.d_rsp_valid && !dut.d_rsp_ready)) {
        terminal = error_reply(command.execution, command.sequence, local_ticks,
                               "protocol_environment", "unsolicited_response");
      } else {
        tick(dut, &samples);
      }

      if (terminal.empty()) {
        const auto payload = object({
          {"schema_version", quote("local_driver_result.v1")}, {"kind", quote("obi_cpu")},
          {"samples", array(samples)}, {"observations", snapshot(dut)},
          {"pre_backend", pre_backend}, {"rdata", std::to_string(rdata)},
          {"error", std::to_string(error)}
        });
        terminal = "RESULT " + command.execution + ' ' + hex_integer(command.sequence) + ' ' +
            hex_integer(before) + ' ' + hex_integer(local_ticks) + ' ' + encode_hex(payload);
      }
      replay.finish(command.sequence, terminal);
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
