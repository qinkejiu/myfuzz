// Profile-selected OBI CPU + APB IRQ exploration. Two independent generated
// models; RAM, routing and IRQ delivery are simulated by this host program.
#include "spike_config.h"
#include "verilated.h"
#include "inprocess_memory.h"
#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

static constexpr uint32_t kRamBase = RAM_BASE, kRamSize = RAM_SIZE;
static constexpr uint32_t kIpBase = IP_BASE, kIpSize = IP_SIZE;

using myfuzz::inprocess_spike::Memory;
using myfuzz::inprocess_spike::Response;

struct Mmio { bool busy=false, sent=false, write=false; uint32_t address=0, value=0; unsigned be=0; };

int main(int argc, char **argv) {
  if (argc < 2 || argc > 4) { std::cerr << "usage: spike firmware.txt [--online] [max_ticks]\n"; return 2; }
  try {
    const bool online=argc>=3 && std::string(argv[2])=="--online";
    if (online && !SUPPORT_ONLINE) throw std::runtime_error("online mailbox firmware required");
    if (!online && argc==4) throw std::runtime_error("unexpected input arguments");
    if (online) std::cout << std::unitbuf;
    auto started = std::chrono::steady_clock::now();
    Memory memory(kRamBase,kRamSize); memory.load(argv[1]);
    VerilatedContext context;
    CPU_MODEL cpu(&context, "cpu");
    IP_MODEL ip(&context, "target");
    cpu.clk=ip.clk=0; cpu.reset=ip.reset=0; cpu.eval(); ip.eval();
    cpu.reset=ip.reset=1; cpu.eval(); ip.eval();
    auto edge=[&] { cpu.clk=ip.clk=0; cpu.eval(); ip.eval(); cpu.clk=ip.clk=1;
      cpu.eval(); ip.eval(); cpu.clk=ip.clk=0; cpu.eval(); ip.eval(); };
    for (unsigned n=0;n<CPU_RESET_ASSERT || n<IP_RESET_ASSERT;++n) {
      cpu.reset=n<CPU_RESET_ASSERT; ip.reset=n<IP_RESET_ASSERT; edge();
    }
    cpu.reset=ip.reset=0; cpu.eval(); ip.eval();
    for (unsigned n=0;n<CPU_RESET_RELEASE || n<IP_RESET_RELEASE;++n) edge();
    if (cpu.eventsPending() || ip.eventsPending()) throw std::runtime_error("unsupported timed model events");
    Response ins, dat; Mmio mmio; unsigned pulse=0, takes=0, irqs=0, reads=0, writes=0;
    unsigned apb_transfers=0;
    bool last_irq=false, mret=false, result_store=false, result_complete=false;
    bool pending_result=false, saw_successor=false, read_observed=false, normal_finish=false;
    uint32_t last_pc=0, read_value=0;
    uint64_t tick=0;
    const uint64_t kMaxTicks=online ? (argc==4 ? std::stoull(argv[3]) : 3000)
                                    : (argc==3 ? std::stoull(argv[2]) : 3000);
    if (!kMaxTicks) throw std::runtime_error("max_ticks must be positive");
    std::array<uint32_t,TRIGGER_COUNT> values{};
    for (unsigned i=0;i<TRIGGER_COUNT;++i) values[i]=triggers[i].value;
    unsigned cases=0;
    auto receive=[&](uint64_t at_tick) {
      std::cout << "NEED_RECORD " << cases << " tick " << at_tick << '\n';
      std::string line;
      if (!std::getline(std::cin,line) || line=="END") return false;
      std::istringstream input(line); std::string tag,extra;
      if (!(input>>tag) || tag!="CASE") throw std::runtime_error("invalid online F5 record");
      for (unsigned i=0;i<TRIGGER_COUNT;++i) {
        uint64_t value;
        if (!(input>>std::hex>>value) || value>0xffffffffu)
          throw std::runtime_error("invalid online F5 trigger values");
        values[i]=value;
        memory.write(MAILBOX_ADDRESS+4*(i+1),values[i],15);
      }
      if (input>>extra) throw std::runtime_error("extra online F5 trigger value");
      memory.write(MAILBOX_ADDRESS,1,15);
      std::cout << "CASE_INSTALLED " << cases << '\n';
      return true;
    };
    if (online && !receive(0)) throw std::runtime_error("no online F5 record");
    for (; tick<kMaxTicks; ++tick) {
      cpu.CPU_IRQ = pulse != 0;
      cpu.CPU_I_REQ_READY = !ins.valid; cpu.CPU_I_RSP_VALID=ins.valid; cpu.CPU_I_RSP_RDATA=ins.value; cpu.CPU_I_RSP_ERROR=0;
      cpu.CPU_D_REQ_READY = !dat.valid && !mmio.busy; cpu.CPU_D_RSP_VALID=dat.valid; cpu.CPU_D_RSP_RDATA=dat.value; cpu.CPU_D_RSP_ERROR=0;
      ip.IP_REQ_VALID=mmio.busy && !mmio.sent; ip.IP_REQ_WRITE=mmio.write;
      ip.IP_REQ_ADDR=mmio.address; ip.IP_REQ_WDATA=mmio.value; ip.IP_REQ_BE=mmio.be;
      ip.IP_RSP_READY=1;
      cpu.eval(); ip.eval();
      const bool itake=cpu.CPU_I_REQ_VALID && cpu.CPU_I_REQ_READY;
      const bool dtake=cpu.CPU_D_REQ_VALID && cpu.CPU_D_REQ_READY;
      const bool iconsume=cpu.CPU_I_RSP_VALID && cpu.CPU_I_RSP_READY;
      const bool dconsume=cpu.CPU_D_RSP_VALID && cpu.CPU_D_RSP_READY;
      const uint32_t ia=cpu.CPU_I_REQ_ADDR, da=cpu.CPU_D_REQ_ADDR, dv=cpu.CPU_D_REQ_WDATA;
      const unsigned dbe=cpu.CPU_D_REQ_BE; const bool dw=cpu.CPU_D_REQ_WRITE;
      const bool iptake=ip.IP_REQ_VALID && ip.IP_REQ_READY;
      const bool ipdone=ip.IP_RSP_VALID && ip.IP_RSP_READY;
      const uint32_t ipvalue=ip.IP_RSP_RDATA; const bool iperror=ip.IP_RSP_ERROR;
      if (cpu.CPU_IRQ_TAKE) { if (!pulse) throw std::runtime_error("IRQ take without actual delivered source");
        ++takes; std::cout << "irq_take " << tick << '\n'; }
      if (ip.IP_TRACE_PSEL && ip.IP_TRACE_PENABLE && ip.IP_TRACE_PREADY) {
        ++apb_transfers;
        std::cout << "apb_access " << tick << ' ' << (ip.IP_TRACE_PWRITE?"write":"read") << ' '
                  << std::hex << ip.IP_TRACE_PADDR << ' ' << ip.IP_TRACE_PWDATA << ' ' << ip.IP_TRACE_PRDATA << std::dec << '\n';
      }
      cpu.clk=ip.clk=1; cpu.eval(); ip.eval();
      if (cpu.CPU_RVFI_VALID) {
        if (cpu.CPU_RVFI_TRAP) throw std::runtime_error("CPU retirement trap");
        last_pc=cpu.CPU_RVFI_PC_RDATA;
        if (cpu.CPU_RVFI_INSN==MRET_WORD) { mret=true; std::cout << "mret " << tick << " pc " << std::hex << last_pc << std::dec << '\n'; }
        else if (mret) saw_successor=true;
      }
      bool irq=((uint64_t(ip.TIMER_IRQ) >> IRQ_BIT) & 1) != 0;
      if (irq && !last_irq) { ++irqs; pulse=IRQ_WIDTH; std::cout << "irq_source " << tick << '\n'; }
      else if (pulse) --pulse;
      last_irq=irq;
      cpu.clk=ip.clk=0; cpu.eval(); ip.eval();
      if (cpu.eventsPending() || ip.eventsPending()) throw std::runtime_error("unsupported timed model events");
      if (iconsume) ins.valid=false;
      if (dconsume) { dat.valid=false; if (pending_result) { result_complete=true; pending_result=false; } }
      if (itake) { ins.value=memory.read(ia); ins.valid=true; }
      if (dtake) {
        if (da>=kIpBase && da<kIpBase+kIpSize) {
          if (dw && (writes>=TRIGGER_COUNT || da!=kIpBase+triggers[writes].offset || dv!=values[writes] || dbe!=15))
            throw std::runtime_error("unexpected CPU MMIO write");
          if (!dw && (da!=kIpBase+STATUS_OFFSET || dbe!=15)) throw std::runtime_error("unexpected CPU MMIO read");
          mmio={true,false,dw,da-kIpBase,dv,dbe};
          std::cout << "mmio " << tick << ' ' << (dw?"write":"read") << ' ' << std::hex << da << ' ' << dv << std::dec << '\n';
        } else {
          if (dw) { memory.write(da,dv,dbe); if (da==RESULT_ADDRESS) {
            if (!read_observed || dbe!=15 || dv!=read_value) throw std::runtime_error("result differs from target read");
            result_store=true; pending_result=true;
          }}
          dat.value=dw?0:memory.read(da); dat.valid=true;
        }
      }
      if (iptake) mmio.sent=true;
      if (ipdone) {
        if (iperror || !mmio.busy || !mmio.sent) throw std::runtime_error("APB transaction error");
        if (mmio.write) ++writes; else { ++reads; read_value=ipvalue; read_observed=true;
          std::cout << "ip_read " << tick << ' ' << ipvalue << '\n'; }
        dat.value=ipvalue; dat.valid=true; mmio={};
      }
      if (mret && saw_successor && result_store && result_complete && !dat.valid && !mmio.busy
              && !pulse && !last_irq) {
        const bool passed=irqs>=1 && takes==1 && writes==TRIGGER_COUNT && reads==1
            && apb_transfers==TRIGGER_COUNT+1 && memory.read(RESULT_ADDRESS)==read_value;
        if (!passed) throw std::runtime_error("F5 case observation failed");
        ++cases;
        if (!online) { normal_finish=true; break; }
        if (memory.read(MAILBOX_ADDRESS)!=0) throw std::runtime_error("CPU did not consume mailbox");
        std::cout << "case " << cases-1 << " observations_passed irq_sources " << irqs
                  << " takes " << takes << " result " << read_value << '\n';
        if (!receive(tick+1)) { normal_finish=true; break; }
        reads=writes=irqs=takes=apb_transfers=0;
        mret=result_store=result_complete=saw_successor=read_observed=false;
      }
    }
    const auto elapsed=std::chrono::duration<double>(std::chrono::steady_clock::now()-started).count();
    const bool ok=normal_finish && cases>0;
    const uint64_t executed_ticks=tick+(tick<kMaxTicks ? 1 : 0);
    std::cout << "summary " << (ok?"observations_passed":"failed") << " cases " << cases << " ticks " << executed_ticks << " irqs " << irqs << " takes " << takes
              << " writes " << writes << " reads " << reads << " result " << memory.read(RESULT_ADDRESS)
              << " apb_transfers " << apb_transfers << " mret " << mret << " successor " << saw_successor << " runtime_seconds " << elapsed << '\n';
    cpu.final(); ip.final();
    return ok ? 0 : 1;
  } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
