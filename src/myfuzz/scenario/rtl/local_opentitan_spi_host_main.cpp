#include "Vlocal_opentitan_spi_host.h"
#include "verilated.h"
#include "local_command_replay.h"

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

static uint64_t local_ticks = 0;

static void tick(Vlocal_opentitan_spi_host &dut, bool interactive) {
  dut.clk = 0;
  dut.eval();
  ++local_ticks;
  dut.clk = 1;
  dut.eval();
  dut.clk = 0;
  dut.eval();
  if (!interactive) return;
  // The Python external peer sees pins produced by real RTL after this edge.
  // It supplies the MISO value that will be stable before the next edge.
  std::cout << "TICK " << std::hex << static_cast<uint32_t>(dut.sck)
            << ' ' << static_cast<uint32_t>(dut.sck_en)
            << ' ' << static_cast<uint32_t>(dut.csb)
            << ' ' << static_cast<uint32_t>(dut.csb_en)
            << ' ' << static_cast<uint32_t>(dut.sd_out)
            << ' ' << static_cast<uint32_t>(dut.sd_en)
            << ' ' << static_cast<uint32_t>(dut.native_pending)
            << ' ' << local_ticks << std::endl;
  std::string line, operation;
  uint32_t next_sd_i = 0;
  if (!std::getline(std::cin, line)) throw std::runtime_error("peer reply EOF");
  std::istringstream response(line);
  response >> operation >> std::hex >> next_sd_i;
  std::string extra;
  if (!response || operation != "DRIVE" || next_sd_i > 15 || (response >> extra))
    throw std::runtime_error("invalid SPI peer reply");
  dut.spi_sd_i = next_sd_i;
  dut.eval();
}

static uint32_t transaction(Vlocal_opentitan_spi_host &dut, bool write,
                            uint32_t address, uint32_t data, uint8_t be,
                            bool &error) {
  dut.req_valid = 1;
  dut.req_write = write;
  dut.req_addr = address;
  dut.req_wdata = data;
  dut.req_be = be;
  dut.eval();
  int waits = 0;
  while (!dut.req_ready && waits++ < 200) tick(dut, true);
  if (!dut.req_ready) throw std::runtime_error("request acceptance timeout");
  tick(dut, true);
  dut.req_valid = 0;
  dut.eval();
  waits = 0;
  while (!dut.rsp_valid && waits++ < 200) tick(dut, true);
  if (!dut.rsp_valid) throw std::runtime_error("response timeout");
  const uint32_t result = dut.rsp_rdata;
  error = dut.rsp_error;
  tick(dut, true);
  return result;
}

int main(int argc, char **argv) {
  Verilated::commandArgs(argc, argv);
  Vlocal_opentitan_spi_host dut;
  dut.clk = 0;
  dut.reset = 1;
  dut.rsp_ready = 1;
  dut.req_valid = 0;
  dut.req_write = 0;
  dut.req_addr = 0;
  dut.req_wdata = 0;
  dut.req_be = 0;
  dut.spi_sd_i = 0;
  for (int i = 0; i < 8; ++i) tick(dut, false);
  dut.reset = 0;
  for (int i = 0; i < 8; ++i) tick(dut, false);
  local_ticks = 0;
  std::cout << "READY" << std::endl;

  LocalCommandReplay replay;
  std::string line;
  while (std::getline(std::cin, line)) {
    if (line == "END") break;
    std::istringstream command(line);
    std::string operation, execution;
    uint64_t sequence = 0;
    uint32_t sd_i = 0, valid = 0, write = 0, address = 0, data = 0,
             be = 0, cycles = 0;
    command >> operation >> execution >> std::hex >> sequence
            >> sd_i >> valid >> write >> address >> data >> be >> cycles;
    std::string extra;
    if (!command || operation != "CMD" || sd_i > 15 || cycles > 100000 ||
        valid > 1 || write > 1 || be > 15 || (command >> extra)) {
      std::cout << "ERROR invalid command" << std::endl;
      continue;
    }
    std::string cached;
    auto decision = replay.accept(execution, sequence, line, cached);
    if (decision != LocalCommandReplay::Decision::Fresh) {
      std::cout << cached << std::endl;
      continue;
    }
    try {
      dut.spi_sd_i = sd_i;
      dut.eval();
      bool error = false;
      uint32_t readback = 0;
      if (valid) readback = transaction(dut, write, address, data, be, error);
      for (uint32_t i = 0; i < cycles; ++i) tick(dut, true);
      std::ostringstream reply;
      reply << "RESULT " << execution << ' ' << std::hex << sequence << ' '
            << static_cast<uint32_t>(dut.sck) << ' '
            << static_cast<uint32_t>(dut.sck_en) << ' '
            << static_cast<uint32_t>(dut.csb) << ' '
            << static_cast<uint32_t>(dut.csb_en) << ' '
            << static_cast<uint32_t>(dut.sd_out) << ' '
            << static_cast<uint32_t>(dut.sd_en) << ' '
            << static_cast<uint32_t>(dut.irq_event) << ' '
            << static_cast<uint32_t>(dut.irq_error) << ' '
            << static_cast<uint32_t>(dut.native_pending) << ' '
            << readback << ' ' << static_cast<uint32_t>(error)
            << ' ' << local_ticks;
      replay.finish(sequence, reply.str());
      std::cout << reply.str() << std::endl;
    } catch (const std::exception &e) {
      std::string failure = std::string("ERROR uncertain_effect ") + e.what();
      replay.finish(sequence, failure);
      std::cout << failure << std::endl;
    }
  }
  dut.final();
  return 0;
}
