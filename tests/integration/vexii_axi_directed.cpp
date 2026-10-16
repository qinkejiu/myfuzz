// Directed VexiiRiscv AXI smoke. Build against the pinned generated RTL.
// This exercises actual CPU fetch, LSU read/write and external RAM responses.
#include "VVexiiRiscv.h"
#include "verilated.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <stdexcept>

#define LSU(field) dut.LsuCachelessAxi4Plugin_logic_axi_##field
#define FETCH(field) dut.FetchCachelessAxi4Plugin_logic_bridge_axi_##field

struct ReadReply { uint32_t data; uint8_t id; };

int main(int argc, char** argv) {
    Verilated::commandArgs(argc, argv);
    const bool fault_read = argc == 2 && std::strcmp(argv[1], "--fault-read") == 0;
    if (argc > 2 || (argc == 2 && !fault_read))
        throw std::runtime_error("usage: vexii_axi_directed [--fault-read]");
    VVexiiRiscv dut;
    const uint32_t boot = 0x80000000u;
    std::map<uint32_t, uint32_t> ram = {
        {boot + 0, 0x800000b7u}, // lui x1,0x80000
        {boot + 4, 0x10008093u}, // addi x1,x1,256
        {boot + 8, 0x03500113u}, // addi x2,x0,53
        {boot + 12, 0x0020a023u}, // sw x2,0(x1)
        {boot + 16, 0x0000a183u}, // lw x3,0(x1)
        {boot + 20, 0x00118213u}, // addi x4,x3,1
        {boot + 24, 0x0040a223u}, // sw x4,4(x1)
        {boot + 28, 0x0000006fu}  // jal x0,0
    };
    std::deque<ReadReply> fetch_reads, data_reads;
    bool b_pending = false, aw_pending = false, w_pending = false;
    uint32_t aw_addr = 0, w_data = 0;
    uint8_t aw_id = 0, w_strb = 0;
    unsigned fetch_count = 0, data_read_count = 0, data_write_count = 0;
    unsigned b_count = 0;
    for (unsigned tick = 0; tick < 3000; ++tick) {
        dut.clk = 0;
        dut.reset = tick < 12;
        dut.PrivilegedPlugin_logic_rdtime = tick;
        dut.PrivilegedPlugin_logic_harts_0_int_m_timer = 0;
        dut.PrivilegedPlugin_logic_harts_0_int_m_software = 0;
        dut.PrivilegedPlugin_logic_harts_0_int_m_external = 0;

        FETCH(ar_ready) = 1;
        FETCH(r_valid) = !fetch_reads.empty();
        FETCH(r_payload_data) = fetch_reads.empty() ? 0 : fetch_reads.front().data;
        FETCH(r_payload_id) = fetch_reads.empty() ? 0 : fetch_reads.front().id;
        FETCH(r_payload_resp) = 0;
        FETCH(r_payload_last) = 1;
        LSU(aw_ready) = 1;
        LSU(w_ready) = 1;
        LSU(b_valid) = b_pending;
        LSU(b_payload_id) = aw_id;
        LSU(b_payload_resp) = 0;
        LSU(ar_ready) = 1;
        LSU(r_valid) = !data_reads.empty();
        LSU(r_payload_data) = data_reads.empty() ? 0 : data_reads.front().data;
        LSU(r_payload_id) = data_reads.empty() ? 0 : data_reads.front().id;
        LSU(r_payload_resp) = 0;
        LSU(r_payload_last) = 1;
        dut.eval();

        const bool fetch_ar = FETCH(ar_valid) && FETCH(ar_ready);
        const bool fetch_r = FETCH(r_valid) && FETCH(r_ready);
        const uint32_t fetch_addr = FETCH(ar_payload_addr);
        const uint8_t fetch_id = FETCH(ar_payload_id);
        const bool data_ar = LSU(ar_valid) && LSU(ar_ready);
        const bool data_r = LSU(r_valid) && LSU(r_ready);
        const uint32_t data_addr = LSU(ar_payload_addr);
        const uint8_t data_id = LSU(ar_payload_id);
        const bool data_aw = LSU(aw_valid) && LSU(aw_ready);
        const bool data_w = LSU(w_valid) && LSU(w_ready);
        const bool data_b = LSU(b_valid) && LSU(b_ready);
        const uint32_t next_aw_addr = LSU(aw_payload_addr);
        const uint8_t next_aw_id = LSU(aw_payload_id);
        const uint32_t next_w_data = LSU(w_payload_data);
        const uint8_t next_w_strb = LSU(w_payload_strb);

        dut.clk = 1;
        dut.eval();
        if (fetch_r) fetch_reads.pop_front();
        if (data_r) data_reads.pop_front();
        if (data_b) { b_pending = false; ++b_count; }
        if (fetch_ar) {
            fetch_reads.push_back({ram.count(fetch_addr) ? ram.at(fetch_addr) : 0x00000013u,
                                   fetch_id});
            ++fetch_count;
        }
        if (data_ar) {
            data_reads.push_back({fault_read && data_addr == boot + 0x100 ? 0u :
                                  (ram.count(data_addr) ? ram.at(data_addr) : 0u), data_id});
            ++data_read_count;
        }
        if (data_aw) {
            if (aw_pending) throw std::runtime_error("overlapping AXI AW");
            aw_pending = true;
            aw_addr = next_aw_addr;
            aw_id = next_aw_id;
        }
        if (data_w) {
            if (w_pending) throw std::runtime_error("overlapping AXI W");
            w_pending = true;
            w_data = next_w_data;
            w_strb = next_w_strb;
        }
        if (aw_pending && w_pending) {
            if (b_pending) throw std::runtime_error("overlapping AXI B");
            if (w_strb != 15 || (aw_addr & 3))
                throw std::runtime_error("unexpected byte strobe or address");
            ram[aw_addr] = w_data;
            ++data_write_count;
            b_pending = true;
            aw_pending = w_pending = false;
        }
        if (ram[boot + 0x100] == 53 && ram[boot + 0x104] == (fault_read ? 1u : 54u)
                && b_count >= 2 && data_read_count == 1 && data_write_count == 2) {
            std::printf("vexii_directed: fault_read=%u ticks=%u fetch=%u read=%u "
                        "write=%u b=%u ram=[%u,%u]\n", fault_read, tick + 1,
                        fetch_count, data_read_count,
                        data_write_count, b_count, ram[boot + 0x100], ram[boot + 0x104]);
            dut.final();
            return 0;
        }
    }
    std::fprintf(stderr, "vexii_directed timeout: fetch=%u read=%u write=%u b=%u "
                         "ram=[%u,%u]\n", fetch_count, data_read_count,
                 data_write_count, b_count, ram[boot + 0x100], ram[boot + 0x104]);
    dut.final();
    return 1;
}
