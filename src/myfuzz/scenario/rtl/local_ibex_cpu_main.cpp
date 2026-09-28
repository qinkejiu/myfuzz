#include "Vlocal_ibex_cpu.h"
#include "verilated.h"
#include "local_command_replay.h"

#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

static uint64_t local_ticks = 0;

static void tick(Vlocal_ibex_cpu &dut) {
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
  Vlocal_ibex_cpu dut;
  dut.clk = 0;
  // Force a real falling edge on rst_ni before the gated core clock starts.
  // Verilator's two-state initialization otherwise leaves gated CSR flops at 0.
  dut.reset = 0;
  dut.irq = 0;
  dut.instr_req_ready = 0;
  dut.instr_rsp_valid = 0;
  dut.instr_rdata = 0;
  dut.instr_error = 0;
  dut.data_req_ready = 0;
  dut.data_rsp_valid = 0;
  dut.data_rdata = 0;
  dut.data_error = 0;
  dut.eval();
  dut.reset = 1;
  dut.eval();
  for (int i = 0; i < 10; ++i) tick(dut);
  dut.reset = 0;
  dut.eval();
  local_ticks = 0;
  std::cout << "READY " << static_cast<uint32_t>(dut.startup_priv) << std::endl;

  LocalCommandReplay replay;
  std::string line;
  while (std::getline(std::cin, line)) {
    if (line == "END") break;
    std::istringstream command(line);
    std::string operation, execution;
    uint64_t sequence = 0;
    uint32_t irq = 0, iready = 0, ivalid = 0, idata = 0, ierr = 0,
             dready = 0, dvalid = 0, ddata = 0, derr = 0;
    command >> operation >> execution >> std::hex >> sequence
            >> irq >> iready >> ivalid >> idata >> ierr
            >> dready >> dvalid >> ddata >> derr;
    std::string extra;
    if (!command || operation != "CMD" || irq > 3 || iready > 1 ||
        ivalid > 1 || ierr > 1 || dready > 1 || dvalid > 1 ||
        derr > 1 || (command >> extra)) {
      std::cout << "ERROR invalid command" << std::endl;
      continue;
    }
    std::string cached;
    auto decision = replay.accept(execution, sequence, line, cached);
    if (decision != LocalCommandReplay::Decision::Fresh) {
      std::cout << cached << std::endl;
      continue;
    }
    if (sequence == 1 && std::getenv("MYFUZZ_TEST_BAD_CPU_RESPONSE")) {
      // Deliberately violate the local OBI response rule before any data
      // request has been granted. This is a driver fault, not an Ibex result.
      dut.irq = irq;
      dut.instr_req_ready = 0;
      dut.instr_rsp_valid = 0;
      dut.data_req_ready = 0;
      dut.data_rsp_valid = 1;
      dut.data_rdata = 0xdeadbeef;
      dut.data_error = 0;
      tick(dut);
      std::ostringstream failure;
      failure << "ERROR protocol_environment " << execution << ' ' << std::hex
              << sequence << ' ' << local_ticks
              << " unsolicited_data_response_without_request";
      replay.finish(sequence, failure.str());
      std::cout << failure.str() << std::endl;
      continue;
    }
    dut.irq = irq;
    dut.instr_req_ready = iready;
    dut.instr_rsp_valid = ivalid;
    dut.instr_rdata = idata;
    dut.instr_error = ierr;
    dut.data_req_ready = dready;
    dut.data_rsp_valid = dvalid;
    dut.data_rdata = ddata;
    dut.data_error = derr;
    dut.eval();
    std::ostringstream reply;
    reply << "RESULT " << execution << ' ' << std::hex << sequence << ' '
          << static_cast<uint32_t>(dut.instr_req_valid) << ' '
          << static_cast<uint32_t>(dut.instr_write) << ' '
          << static_cast<uint32_t>(dut.instr_addr) << ' '
          << static_cast<uint32_t>(dut.instr_wdata) << ' '
          << static_cast<uint32_t>(dut.instr_be) << ' '
          << static_cast<uint32_t>(dut.instr_rsp_ready) << ' '
          << static_cast<uint32_t>(dut.data_req_valid) << ' '
          << static_cast<uint32_t>(dut.data_write) << ' '
          << static_cast<uint32_t>(dut.data_addr) << ' '
          << static_cast<uint32_t>(dut.data_wdata) << ' '
          << static_cast<uint32_t>(dut.data_be) << ' '
          << static_cast<uint32_t>(dut.data_rsp_ready) << ' '
          << static_cast<uint32_t>(dut.irq_masked_pre) << ' '
          << static_cast<uint32_t>(dut.irq_taken_pre);
    tick(dut);
    reply << ' ' << std::hex << local_ticks;
    if (std::getenv("MYFUZZ_TEST_CRASH_AFTER_CPU_TICK")) std::_Exit(87);
    replay.finish(sequence, reply.str());
    std::cout << reply.str() << std::endl;
  }
  dut.final();
  return 0;
}
