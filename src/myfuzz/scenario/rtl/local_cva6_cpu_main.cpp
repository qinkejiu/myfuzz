#include "Vlocal_cva6_cpu.h"
#include "verilated.h"
#include "local_command_replay.h"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>

static uint64_t local_ticks = 0;

static void tick(Vlocal_cva6_cpu &dut) {
  dut.clk = 0;
  dut.eval();
  ++local_ticks;
  dut.clk = 1;
  dut.eval();
  dut.clk = 0;
  dut.eval();
}

int main(int argc, char **argv) {
  Verilated::commandArgs(argc, argv);
  Vlocal_cva6_cpu dut;
  dut.clk = 0;
  dut.reset = 1;
  dut.irq = 0;
  dut.req_ready = 0;
  dut.rsp_valid = 0;
  dut.rsp_rdata = 0;
  dut.rsp_error = 0;
  for (int i = 0; i < 15; ++i) tick(dut);
  dut.reset = 0;
  dut.eval();
  local_ticks = 0;
  std::cout << "READY" << std::endl;

  LocalCommandReplay replay;
  std::string line;
  while (std::getline(std::cin, line)) {
    if (line == "END") break;
    std::istringstream command(line);
    std::string operation, execution;
    uint64_t sequence = 0;
    uint64_t irq = 0, ready = 0, valid = 0, data = 0, error = 0;
    command >> operation >> execution >> std::hex >> sequence
            >> irq >> ready >> valid >> data >> error;
    std::string extra;
    if (!command || operation != "CMD" || irq > 3 || ready > 1 ||
        valid > 1 || error > 1 || (command >> extra)) {
      std::cout << "ERROR invalid command" << std::endl;
      continue;
    }
    std::string cached;
    auto decision = replay.accept(execution, sequence, line, cached);
    if (decision != LocalCommandReplay::Decision::Fresh) {
      std::cout << cached << std::endl;
      continue;
    }
    dut.irq = irq;
    dut.req_ready = ready;
    dut.rsp_valid = valid;
    dut.rsp_rdata = data;
    dut.rsp_error = error;
    dut.eval();
    std::ostringstream reply;
    reply << "RESULT " << execution << ' ' << std::hex << sequence << ' '
          << static_cast<uint64_t>(dut.req_valid) << ' '
          << static_cast<uint64_t>(dut.req_write) << ' '
          << static_cast<uint64_t>(dut.req_addr) << ' '
          << static_cast<uint64_t>(dut.req_wdata) << ' '
          << static_cast<uint64_t>(dut.req_be) << ' '
          << static_cast<uint64_t>(dut.rsp_ready);
    tick(dut);
    reply << ' ' << std::hex << local_ticks;
    if (std::getenv("MYFUZZ_TEST_CRASH_AFTER_CPU_TICK")) std::_Exit(87);
    replay.finish(sequence, reply.str());
    std::cout << reply.str() << std::endl;
  }
  dut.final();
  return 0;
}
