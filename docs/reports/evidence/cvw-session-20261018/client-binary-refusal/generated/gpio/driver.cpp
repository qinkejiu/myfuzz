#include "Vlocal_runtime_gpio.h"
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

using Model = Vlocal_runtime_gpio;
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
    {"gpio_req_valid", std::to_string(static_cast<std::uint64_t>(dut.gpio_req_valid))},
    {"gpio_req_ready", std::to_string(static_cast<std::uint64_t>(dut.gpio_req_ready))},
    {"gpio_req_write", std::to_string(static_cast<std::uint64_t>(dut.gpio_req_write))},
    {"gpio_req_addr", std::to_string(static_cast<std::uint64_t>(dut.gpio_req_addr))},
    {"gpio_req_wdata", std::to_string(static_cast<std::uint64_t>(dut.gpio_req_wdata))},
    {"gpio_req_be", std::to_string(static_cast<std::uint64_t>(dut.gpio_req_be))},
    {"gpio_rsp_valid", std::to_string(static_cast<std::uint64_t>(dut.gpio_rsp_valid))},
    {"gpio_rsp_ready", std::to_string(static_cast<std::uint64_t>(dut.gpio_rsp_ready))},
    {"gpio_rsp_rdata", std::to_string(static_cast<std::uint64_t>(dut.gpio_rsp_rdata))},
    {"gpio_rsp_error", std::to_string(static_cast<std::uint64_t>(dut.gpio_rsp_error))}
  });
}
static std::string snapshot(const Model &dut) {
  JsonObject values = {
    {"backend", backend_snapshot(dut)},
    {"physical", object({
    {"rt_lh_p_11_31_0", std::to_string(static_cast<std::uint64_t>(dut.rt_lh_p_11_31_0))},
    {"rt_lh_p_12_31_0", std::to_string(static_cast<std::uint64_t>(dut.rt_lh_p_12_31_0))},
    {"rt_lh_p_13_31_0", std::to_string(static_cast<std::uint64_t>(dut.rt_lh_p_13_31_0))},
    {"rt_lh_p_14_31_0", std::to_string(static_cast<std::uint64_t>(dut.rt_lh_p_14_31_0))},
    {"rt_lh_p_15_127_0", quote(wide_hex(dut.rt_lh_p_15_127_0, 128))},
    {"rt_lh_p_16_0_0", std::to_string(static_cast<std::uint64_t>(dut.rt_lh_p_16_0_0))}
    })}
  };
  values["gpio_out"] = std::to_string(static_cast<std::uint64_t>(dut.rt_lh_p_14_31_0));
  values["gpio_dir"] = std::to_string(static_cast<std::uint64_t>(dut.rt_lh_p_11_31_0));
  values["gpio_in_sync"] = std::to_string(static_cast<std::uint64_t>(dut.rt_lh_p_13_31_0));
  values["gpio_padcfg"] = quote(wide_hex(dut.rt_lh_p_15_127_0, 128));
  values["interrupt"] = std::to_string(static_cast<std::uint64_t>(dut.rt_lh_p_16_0_0));
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
  dut.rt_lh_p_12_31_0 = 0;
  dut.gpio_req_valid = 0;
  dut.gpio_req_write = 0;
  dut.gpio_req_addr = 0;
  dut.gpio_req_wdata = 0;
  dut.gpio_req_be = 0;
  dut.gpio_rsp_ready = 0;
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
    if (command.operation != "STEP_GPIO" && command.operation != "ACCESS_GPIO") {
      std::cout << error_reply(command.execution, command.sequence, local_ticks,
                              "invalid_operation", "wrong_runtime_kind") << std::endl;
      continue;
    }
    const auto admission = replay.accept(command, local_ticks, 96800);
    if (admission.decision != Decision::Fresh) {
      std::cout << admission.reply << std::endl;
      continue;
    }
    const auto before = local_ticks;
    std::vector<std::string> samples;
    std::string pre_backend, terminal;
    std::uint32_t rdata = 0, error = 0;
    try {
      dut.rt_lh_p_12_31_0 = command.fields[0];
      dut.eval();
      if (command.operation == "STEP_GPIO") {
        pre_backend = backend_snapshot(dut);
        tick(dut, &samples);
      } else {
        dut.gpio_req_valid = 1;
        dut.gpio_req_write = command.fields[1];
        dut.gpio_req_addr = command.fields[2];
        dut.gpio_req_wdata = command.fields[3];
        dut.gpio_req_be = command.fields[4];
        dut.gpio_rsp_ready = 0;
        dut.eval();
        pre_backend = backend_snapshot(dut);
        unsigned waits = 0;
        while (!dut.gpio_req_ready) {
          if (waits++ >= 16) throw std::runtime_error("request_timeout");
          tick(dut, &samples);
        }
        tick(dut, &samples);
        dut.gpio_req_valid = 0;
        dut.eval();
        waits = 0;
        while (!dut.gpio_rsp_valid) {
          if (waits++ >= 19) throw std::runtime_error("response_timeout");
          tick(dut, &samples);
        }
        rdata = dut.gpio_rsp_rdata;
        error = dut.gpio_rsp_error;
        dut.gpio_rsp_ready = 1;
        tick(dut, &samples);
        dut.gpio_rsp_ready = 0;
        dut.eval();
      }

      if (terminal.empty()) {
        const auto payload = object({
          {"schema_version", quote("local_driver_result.v1")}, {"kind", quote("apb_gpio")},
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
