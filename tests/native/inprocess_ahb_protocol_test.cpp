#include "Vahb_lite_memory_target.h"
#include "../../scripts/inprocess_ahb_identity.h"
#include <cassert>
#include <cstdint>

int main() {
  Vahb_lite_memory_target dut;
  AhbIdentity identity;
  dut.clk_i = 0;
  dut.rst_ni = 0;
  dut.req_ready_i = 1;
  dut.rsp_valid_i = 0;
  dut.rsp_error_i = 0;
  dut.HTRANS = 0;
  dut.HSELEXT = 0;
  dut.eval();
  dut.clk_i = 1; dut.eval(); dut.clk_i = 0; dut.eval();
  identity.edge(false, false, false, 0, 0, false, 0);
  dut.rst_ni = 1;

  unsigned offered = 0, accepted = 0, completed = 0;
  bool response = false;
  for (unsigned tick = 0; tick < 100 && completed < 2; ++tick) {
    dut.rsp_valid_i = response;
    dut.rsp_rdata_i = 0xabcdef01;
    dut.eval();
    // Offer the next address only when the current data phase completes or
    // the bus is idle; the transfer type stays idle during other cycles.
    bool offer = dut.HREADYEXT && offered < 2;
    dut.HSELEXT = offer;
    dut.HTRANS = offer ? 2 : 0;
    dut.HADDR = offered == 0 ? 0xc0000100u : 0x40000000u;
    dut.HWRITE = offered != 0;
    dut.HPROT = offered == 0 ? 0 : 1;
    dut.HWDATA = 0x12345678;
    dut.HWSTRB = 15;
    dut.eval();
    bool ready = dut.HREADYEXT;
    bool request = dut.req_valid_o && dut.req_ready_i;
    bool answer = dut.rsp_ready_o && dut.rsp_valid_i;
    if (request) {
      const auto kind = identity.classify(dut.req_addr_o, dut.req_write_o);
      assert(kind == (accepted == 0 ? AhbIdentity::Instruction : AhbIdentity::Data));
      ++accepted;
    }
    identity.edge(true, ready, dut.HSELEXT, dut.HTRANS,
                  dut.HADDR, dut.HWRITE, dut.HPROT);
    dut.clk_i = 1; dut.eval(); dut.clk_i = 0; dut.eval();
    if (offer) ++offered;
    if (answer) ++completed;
    if (answer) response = false;
    if (request) response = true;
  }
  assert(offered == 2 && accepted == 2 && completed == 2);
}
