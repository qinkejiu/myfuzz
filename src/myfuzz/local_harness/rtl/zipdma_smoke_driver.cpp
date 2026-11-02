#include <cstdint>
#include <iostream>
#include <string>
#include "Vzipdma.h"
#include "verilated.h"

int main(int argc, char **argv) {
    Verilated::commandArgs(argc, argv);
    Vzipdma dut;
    dut.i_clk = 0;
    dut.i_dev_ints = 0;
    dut.eval();
    std::cout << "READY" << std::endl;
    std::string command;
    while (std::cin >> command) {
        if (command == "EXIT") break;
        if (command != "STEP") return 2;
        uint32_t reset, cyc, stb, we, addr, data, sel, stall, ack, rdata, err;
        if (!(std::cin >> reset >> cyc >> stb >> we >> addr >> data >> sel
              >> stall >> ack >> rdata >> err)) return 3;
        dut.i_clk = 0;
        dut.i_reset = reset;
        dut.i_swb_cyc = cyc;
        dut.i_swb_stb = stb;
        dut.i_swb_we = we;
        dut.i_swb_addr = addr;
        dut.i_swb_data = data;
        dut.i_swb_sel = sel;
        dut.i_mwb_stall = stall;
        dut.i_mwb_ack = ack;
        dut.i_mwb_data = rdata;
        dut.i_mwb_err = err;
        dut.eval();
        const unsigned mc = dut.o_mwb_cyc, ms = dut.o_mwb_stb, mw = dut.o_mwb_we;
        const uint32_t ma = dut.o_mwb_addr, md = dut.o_mwb_data, me = dut.o_mwb_sel;
        const unsigned ss = dut.o_swb_stall, irq_pre = dut.o_interrupt;
        dut.i_clk = 1;
        dut.eval();
        const unsigned sa = dut.o_swb_ack, irq = dut.o_interrupt;
        const uint32_t sd = dut.o_swb_data;
        dut.i_clk = 0;
        dut.eval();
        std::cout << "{\"cyc\":" << mc << ",\"stb\":" << ms
                  << ",\"we\":" << mw << ",\"addr\":" << ma
                  << ",\"data\":" << md << ",\"sel\":" << me
                  << ",\"control_stall\":" << ss << ",\"control_ack\":" << sa
                  << ",\"control_data\":" << sd << ",\"irq_pre\":" << irq_pre
                  << ",\"irq\":" << irq
                  << "}" << std::endl;
    }
    dut.final();
    return 0;
}
