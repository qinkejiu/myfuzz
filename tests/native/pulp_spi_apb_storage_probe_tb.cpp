// Native hierarchy-probe proof testbench for the generated PULP APB SPI SPICMD
// runtime.  It drives the register beat interface, reads every storage_* top
// port each cycle, and fails closed on an unbound, constant or displaced
// hierarchy expression.  Verilator is invoked with --prefix Vtop so this file
// is independent of the generated instance name.
#include "Vtop.h"
#include "verilated.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

static Vtop* dut;
static long cycle_no = 0;

static void eval() { dut->eval(); }

struct Sample {
    long cycle;
    uint32_t value, pwdata, prdata, paddr;
    uint32_t psel, penable, pwrite, pready, pslverr, reset;
};

static std::vector<Sample> trace;

static Sample sample() {
    Sample s;
    s.cycle = cycle_no;
    s.value = dut->storage_value;
    s.paddr = dut->storage_paddr;
    s.psel = dut->storage_psel;
    s.penable = dut->storage_penable;
    s.pwrite = dut->storage_pwrite;
    s.pwdata = dut->storage_pwdata;
    s.prdata = dut->storage_prdata;
    s.pready = dut->storage_pready;
    s.pslverr = dut->storage_pslverr;
    s.reset = dut->storage_reset;
    trace.push_back(s);
    return s;
}

static void tick() {
    dut->clk = 0;
    eval();
    dut->clk = 1;
    eval();
    ++cycle_no;
    sample();
}

static void idle_inputs() {
    dut->reg_req_valid = 0;
    dut->reg_req_write = 0;
    dut->reg_req_addr = 0;
    dut->reg_req_wdata = 0;
    dut->reg_req_be = 0;
    dut->reg_rsp_ready = 1;
}

[[noreturn]] static void fail(const char* what) {
    std::fprintf(stderr, "PROBE-TB-FAIL: %s (cycle %ld)\n", what, cycle_no);
    std::exit(1);
}

static void require(bool cond, const char* what) {
    if (!cond) fail(what);
}

static void drain_response() {
    idle_inputs();
    for (int i = 0; i < 4 && dut->reg_rsp_valid; ++i) tick();
}

// Issue one full-word write; expect the storage_value probe to reach
// expect_probe once the APB write commits.
static void issue_write(uint32_t addr, uint32_t wdata, uint32_t expect_probe) {
    drain_response();
    dut->reg_req_valid = 1;
    dut->reg_req_write = 1;
    dut->reg_req_addr = addr & 0xffffffffu;
    dut->reg_req_wdata = wdata;
    dut->reg_req_be = 0xf;
    dut->reg_rsp_ready = 1;
    tick();  // accepted in IDLE
    dut->reg_req_valid = 0;
    require(!(dut->reg_rsp_valid && dut->reg_rsp_error), "write rejected locally");
    bool seen_access = false;
    bool seen_commit = false;
    for (int i = 0; i < 12; ++i) {
        if (dut->storage_psel && dut->storage_penable) {
            const Sample& access = trace.back();
            seen_access = true;
            require(access.pwrite == 1, "storage_pwrite not asserted for write");
            require(access.paddr == (addr & 0xfff),
                    "storage_paddr does not track PADDR");
            require(access.pwdata == wdata,
                    "storage_pwdata does not track PWDATA");
        }
        if (seen_access && !dut->storage_psel && dut->storage_value == expect_probe)
            seen_commit = true;
        if (dut->reg_rsp_valid) {
            require(dut->reg_rsp_error == 0, "write response error");
            break;
        }
        tick();
    }
    require(seen_access,
            "no APB ACCESS phase observed on storage_paddr/psel/penable");
    require(seen_commit,
            "storage_value did not reach the expected post-write value");
}

static void issue_read(uint32_t addr, uint32_t expected) {
    drain_response();
    dut->reg_req_valid = 1;
    dut->reg_req_write = 0;
    dut->reg_req_addr = addr & 0xffffffffu;
    dut->reg_req_wdata = 0;
    dut->reg_req_be = 0xf;
    dut->reg_rsp_ready = 1;
    tick();  // accepted in IDLE
    dut->reg_req_valid = 0;
    bool seen_access = false;
    bool seen_rsp = false;
    for (int i = 0; i < 12; ++i) {
        if (dut->storage_psel && dut->storage_penable) {
            const Sample& access = trace.back();
            seen_access = true;
            require(access.pwrite == 0, "storage_pwrite asserted for read");
            require(access.pready == 1, "storage_pready not high");
            require(access.pslverr == 0, "storage_pslverr not low");
            require(access.prdata == expected,
                    "storage_prdata does not sample register storage");
        }
        if (dut->reg_rsp_valid) {
            require(dut->reg_rsp_error == 0, "read response error");
            require(dut->reg_rsp_rdata == expected, "readback mismatch");
            seen_rsp = true;
            break;
        }
        tick();
    }
    require(seen_access, "no APB ACCESS phase observed on read");
    require(seen_rsp, "no read response observed");
}

int main(int argc, char** argv) {
    Verilated::commandArgs(argc, argv);
    dut = new Vtop;
    idle_inputs();
    dut->clk = 0;
    dut->reset = 1;
    eval();

    for (int i = 0; i < 3; ++i) tick();
    const Sample& reset_sample = trace.back();
    require(reset_sample.value == 0, "storage_value not zero in reset");
    require(reset_sample.reset == 1, "storage_reset does not track reset");

    dut->reset = 0;
    tick();
    require(trace.back().value == 0, "storage_value not zero after reset release");
    require(trace.back().reset == 0, "storage_reset stuck asserted");

    // SPIADR (0x0c) must not change SPICMD; STATUS is never written.
    issue_write(0x0c, 0x5a5a5a5au, 0u);
    require(dut->storage_value == 0, "SPICMD moved on SPIADR write");

    issue_write(0x08, 0xa5c30001u, 0xa5c30001u);
    require(dut->storage_value == 0xa5c30001u, "SPICMD write did not commit");

    // Readback must agree on both storage_value and the PRDATA probe.
    issue_read(0x08, 0xa5c30001u);

    // Repeat the noninterference control with nonzero storage.
    issue_write(0x0c, 0xdeadbeefu, 0xa5c30001u);
    require(dut->storage_value == 0xa5c30001u, "SPIADR changed SPICMD");

    // A second write proves the probe is not a one-shot constant.
    issue_write(0x08, 0x13572468u, 0x13572468u);
    require(dut->storage_value == 0x13572468u,
            "storage_value did not update on second write");
    issue_read(0x08, 0x13572468u);

    std::printf("PROBE-TB-OK cycles=%ld samples=%zu\n", cycle_no, trace.size());
    for (const auto& s : trace) {
        std::printf("PROBE-SAMPLE {\"cycle\":%ld,\"value\":%u,\"paddr\":%u,"
                    "\"psel\":%u,\"penable\":%u,\"pwrite\":%u,\"pwdata\":%u,"
                    "\"prdata\":%u,\"pready\":%u,\"pslverr\":%u,\"reset\":%u}\n",
                    s.cycle, s.value, s.paddr, s.psel, s.penable, s.pwrite,
                    s.pwdata, s.prdata, s.pready, s.pslverr, s.reset);
    }
    delete dut;
    return 0;
}
