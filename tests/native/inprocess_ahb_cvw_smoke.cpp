// Small CVW model smoke for the AHB manager-domain identity tracker.  The
// generated CPU model and its bus adapter are real; the host supplies RAM.
#include "Vlocal_runtime_cpu.h"
#include "../../scripts/inprocess_ahb_identity.h"
#include <cassert>
#include <cstdint>
#include <iostream>
#include <unordered_map>

int main() {
  Vlocal_runtime_cpu cpu;
  AhbIdentity identity;
  std::unordered_map<uint64_t, uint32_t> ram;
  constexpr uint64_t base = 0xc0000000u;
  for (unsigned n = 0; n < 16; ++n) ram[base + 4 * n] = 0x00000013u;
  ram[base] = 0xc00000b7u;       // lui x1,0xc0000
  ram[base + 4] = 0x02a00113u;   // addi x2,x0,42
  ram[base + 8] = 0x2020a023u;   // sw x2,0x200(x1)
  ram[base + 12] = 0x2000a183u;  // lw x3,0x200(x1)
  ram[base + 16] = 0x0000006fu;  // jal x0,0
  bool response = false, got_write = false, got_read = false;
  uint32_t response_data = 0;
  unsigned ifetches = 0, data_reads = 0, data_writes = 0, unknown = 0;
  for (unsigned tick = 0; tick < 3000 && !got_read; ++tick) {
    cpu.clk = 0;
    cpu.reset = tick < 16;
    cpu.m_req_ready = !response;
    cpu.m_rsp_valid = response;
    cpu.m_rsp_rdata = response_data;
    cpu.m_rsp_error = 0;
    cpu.eval();
    const bool request = cpu.m_req_valid && cpu.m_req_ready;
    const bool consume = cpu.m_rsp_valid && cpu.m_rsp_ready;
    if (request) {
      const uint64_t addr = cpu.m_req_addr;
      const auto kind = identity.classify(addr, cpu.m_req_write);
      if (kind == AhbIdentity::Unknown) {
        ++unknown;
        std::cerr << "unknown request tick=" << tick << " addr=" << std::hex
                  << addr << std::dec << " write=" << unsigned(cpu.m_req_write) << '\n';
      } else if (kind == AhbIdentity::Instruction) {
        assert(!cpu.m_req_write);
        ++ifetches;
      } else if (cpu.m_req_write) {
        ++data_writes;
        assert(cpu.m_req_be == 15);
        ram[addr] = cpu.m_req_wdata;
        if (addr == base + 0x200) got_write = cpu.m_req_wdata == 42;
      } else {
        ++data_reads;
        if (addr == base + 0x200) got_read = got_write && ram[addr] == 42;
      }
      response_data = ram.count(addr) ? ram[addr] : 0x00000013u;
    }
    identity.edge(cpu.rt_lh_p_8_0_0, cpu.rt_lh_p_6_0_0,
                  cpu.cpu_ahb_trace_hsel, cpu.cpu_ahb_trace_htrans,
                  cpu.cpu_ahb_trace_haddr, cpu.cpu_ahb_trace_hwrite,
                  cpu.cpu_ahb_trace_hprot);
    cpu.clk = 1; cpu.eval();
    if (consume) response = false;
    if (request) response = true;
  }
  cpu.final();
  std::cout << "instruction_reads=" << ifetches << " unknown=" << unknown << " data_reads=" << data_reads
            << " data_writes=" << data_writes << " store=" << got_write
            << " reload=" << got_read << '\n';
  assert(ifetches && got_write && got_read);
}
