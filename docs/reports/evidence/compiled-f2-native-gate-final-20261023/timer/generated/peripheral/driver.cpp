#include "Vlocal_runtime_peripheral.h"
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

using Model = Vlocal_runtime_peripheral;
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
    {"trace_paddr", std::to_string(static_cast<std::uint64_t>(dut.trace_paddr))},
    {"trace_psel", std::to_string(static_cast<std::uint64_t>(dut.trace_psel))},
    {"trace_penable", std::to_string(static_cast<std::uint64_t>(dut.trace_penable))},
    {"trace_pwrite", std::to_string(static_cast<std::uint64_t>(dut.trace_pwrite))},
    {"trace_pwdata", std::to_string(static_cast<std::uint64_t>(dut.trace_pwdata))},
    {"trace_pready", std::to_string(static_cast<std::uint64_t>(dut.trace_pready))},
    {"trace_prdata", std::to_string(static_cast<std::uint64_t>(dut.trace_prdata))},
    {"trace_pslverr", std::to_string(static_cast<std::uint64_t>(dut.trace_pslverr))},
    {"reg_req_valid", std::to_string(static_cast<std::uint64_t>(dut.reg_req_valid))},
    {"reg_req_ready", std::to_string(static_cast<std::uint64_t>(dut.reg_req_ready))},
    {"reg_req_write", std::to_string(static_cast<std::uint64_t>(dut.reg_req_write))},
    {"reg_req_addr", std::to_string(static_cast<std::uint64_t>(dut.reg_req_addr))},
    {"reg_req_wdata", std::to_string(static_cast<std::uint64_t>(dut.reg_req_wdata))},
    {"reg_req_be", std::to_string(static_cast<std::uint64_t>(dut.reg_req_be))},
    {"reg_rsp_valid", std::to_string(static_cast<std::uint64_t>(dut.reg_rsp_valid))},
    {"reg_rsp_ready", std::to_string(static_cast<std::uint64_t>(dut.reg_rsp_ready))},
    {"reg_rsp_rdata", std::to_string(static_cast<std::uint64_t>(dut.reg_rsp_rdata))},
    {"reg_rsp_error", std::to_string(static_cast<std::uint64_t>(dut.reg_rsp_error))}
  });
}
static std::string snapshot(const Model &dut) {
  JsonObject values = {
    {"storage_probes", object({
      {"storage_value", std::to_string(static_cast<std::uint64_t>(dut.storage_value))},
      {"storage_reset", std::to_string(static_cast<std::uint64_t>(dut.storage_reset))},
      {"storage_paddr", std::to_string(static_cast<std::uint64_t>(dut.storage_paddr))},
      {"storage_psel", std::to_string(static_cast<std::uint64_t>(dut.storage_psel))},
      {"storage_penable", std::to_string(static_cast<std::uint64_t>(dut.storage_penable))},
      {"storage_pwrite", std::to_string(static_cast<std::uint64_t>(dut.storage_pwrite))},
      {"storage_pwdata", std::to_string(static_cast<std::uint64_t>(dut.storage_pwdata))},
      {"storage_prdata", std::to_string(static_cast<std::uint64_t>(dut.storage_prdata))},
      {"storage_pready", std::to_string(static_cast<std::uint64_t>(dut.storage_pready))},
      {"storage_pslverr", std::to_string(static_cast<std::uint64_t>(dut.storage_pslverr))}
    })},
    {"backend", backend_snapshot(dut)},
    {"physical", object({
    {"rt_lh_p_10_3_0", std::to_string(static_cast<std::uint64_t>(dut.rt_lh_p_10_3_0))}
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
  dut.reg_req_valid = 0;
  dut.reg_req_write = 0;
  dut.reg_req_addr = 0;
  dut.reg_req_wdata = 0;
  dut.reg_req_be = 0;
  dut.reg_rsp_ready = 0;
  // Evaluate inactive reset first to create a real asynchronous assertion edge.
  dut.reset = 0;
  dut.eval();
  dut.reset = 1;
  dut.eval();
  std::uint64_t asserted_ticks = 0, released_ticks = 0;
  for (unsigned i = 0; i < 2; ++i) {
    tick(dut, nullptr);
    ++asserted_ticks;
  }
  dut.reset = 0;
  dut.eval();
  for (unsigned i = 0; i < 3; ++i) {
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
    if (command.operation != "STEP_APB3_REG" && command.operation != "ACCESS_APB3_REG" && command.operation != "BIND_APB3_REG" && command.operation != "SOURCE_APB3_REG") {
      std::cout << error_reply(command.execution, command.sequence, local_ticks,
                              "invalid_operation", "wrong_runtime_kind") << std::endl;
      continue;
    }
    const auto admission = replay.accept(command, local_ticks, 109124);
    if (admission.decision != Decision::Fresh) {
      std::cout << admission.reply << std::endl;
      continue;
    }
    const auto before = local_ticks;
    std::vector<std::string> samples;
    std::string pre_backend, terminal;
    std::uint32_t rdata = 0, error = 0;
    try {
      if (command.operation == "SOURCE_APB3_REG") {
        pre_backend = backend_snapshot(dut);
        switch (command.fields[0]) {
        default: throw std::runtime_error("source_index");
        }
        tick(dut, &samples);
      } else if (command.operation == "BIND_APB3_REG") {
        pre_backend = backend_snapshot(dut);
        switch (command.fields[0]) {
        default: throw std::runtime_error("bound_index");
        }
        tick(dut, &samples);
      } else {
      dut.eval();
      if (command.operation == "STEP_APB3_REG") {
        pre_backend = backend_snapshot(dut);
        tick(dut, &samples);
      } else {
        dut.reg_req_valid = 1;
        dut.reg_req_write = command.fields[0];
        dut.reg_req_addr = command.fields[1];
        dut.reg_req_wdata = command.fields[2];
        dut.reg_req_be = command.fields[3];
        dut.reg_rsp_ready = 0;
        dut.eval();
        pre_backend = backend_snapshot(dut);
        unsigned waits = 0;
        while (!dut.reg_req_ready) {
          if (waits++ >= 16) throw std::runtime_error("request_timeout");
          tick(dut, &samples);
        }
        tick(dut, &samples);
        dut.reg_req_valid = 0;
        dut.eval();
        waits = 0;
        while (!dut.reg_rsp_valid) {
          if (waits++ >= 19) throw std::runtime_error("response_timeout");
          tick(dut, &samples);
        }
        rdata = dut.reg_rsp_rdata;
        error = dut.reg_rsp_error;
        dut.reg_rsp_ready = 1;
        tick(dut, &samples);
        dut.reg_rsp_ready = 0;
        dut.eval();
      }
      }

      if (terminal.empty()) {
        const auto payload = object({
          {"schema_version", quote("local_driver_result.v1")}, {"kind", quote("apb3_register_observe")},
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
