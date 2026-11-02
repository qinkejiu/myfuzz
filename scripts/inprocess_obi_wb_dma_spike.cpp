// Profile-bound OBI + Wishbone DMA experiment. Both are separate generated
// Verilator models; RAM, MMIO routing and IRQ delivery live in this C++ host.
// It is neither a synthesized SoC nor a generic execution backend.
#include "f6_binding.h"
#include F6_CPU_HEADER
#include F6_DMA_HEADER
#include "verilated.h"
#include "inprocess_memory.h"
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

static constexpr uint32_t kRamBase=F6_RAM_BASE, kRamSize=F6_RAM_SIZE;
static constexpr uint32_t kDmaBase=F6_DMA_BASE, kDmaSize=F6_DMA_SIZE;
static constexpr uint32_t kSrc=F6_SRC, kDst=F6_DST, kResult=F6_RESULT;

using myfuzz::inprocess_spike::Memory;
using myfuzz::inprocess_spike::Response;

struct Control { bool busy=false,accepted=false,write=false; uint32_t address=0,value=0; unsigned be=0; };
struct Master { bool pending=false; unsigned delay=0; uint32_t data=0; };

static std::array<uint32_t,4> decode_record(const std::string &raw) {
  if (raw.size()!=16) throw std::runtime_error("F6 record must be exactly 8 bytes");
  uint64_t encoded=0;
  for (unsigned i=0;i<8;++i) {
    if (!std::isxdigit(static_cast<unsigned char>(raw[2*i])) ||
        !std::isxdigit(static_cast<unsigned char>(raw[2*i+1])))
      throw std::runtime_error("F6 record must be hexadecimal");
    encoded|=uint64_t(std::stoul(raw.substr(2*i,2),nullptr,16))<<(8*i);
  }
  if (encoded>>44) throw std::runtime_error("F6 reserved input bits must be zero");
  std::array<uint32_t,4> words{};
  for (unsigned i=0;i<4;++i) {
    words[i]=(encoded>>(11*i))&2047;
    for (unsigned j=0;j<i;++j)
      if (words[i]==words[j]) throw std::runtime_error("F6 input words must differ");
  }
  return words;
}

int main(int argc,char **argv) {
  if (argc!=3) { std::cerr << "usage: spike firmware.txt raw8_hex[,raw8_hex...]|--online\n"; return 2; }
  try {
    const std::string input=argv[2];
    const bool online=input=="--online";
    if (online) std::cout << std::unitbuf;
    std::vector<std::array<uint32_t,4>> records;
    for (size_t start=0;!online;) {
      const auto end=input.find(',',start);
      const auto raw=input.substr(start,end==std::string::npos ? end : end-start);
      records.push_back(decode_record(raw));
      if (records.size()>F6_SLOT_COUNT) throw std::runtime_error("F6 batch exceeds firmware slots");
      if (end==std::string::npos) break;
      start=end+1;
    }
    if ((online || records.size()>1) && !F6_HAVE_RVFI)
      throw std::runtime_error("multiple F6 cases require observable ISR retirement");
    auto started=std::chrono::steady_clock::now();
    Memory mem(kRamBase,kRamSize); mem.load(argv[1]); VerilatedContext context;
    F6_CPU_MODEL cpu(&context,"cpu"); F6_DMA_MODEL dma(&context,"dma");
    cpu.clk=dma.clk=0; cpu.reset=dma.reset=0; cpu.eval(); dma.eval();
    cpu.reset=dma.reset=1; cpu.eval(); dma.eval();
    auto edge=[&] { cpu.clk=dma.clk=0; cpu.eval(); dma.eval();
      cpu.clk=dma.clk=1; cpu.eval(); dma.eval();
      cpu.clk=dma.clk=0; cpu.eval(); dma.eval(); };
    const int cpu_reset_end=F6_CPU_RESET_ASSERT+F6_CPU_RESET_RELEASE;
    const int dma_reset_end=F6_DMA_RESET_ASSERT+F6_DMA_RESET_RELEASE;
    const int reset_ticks=cpu_reset_end>dma_reset_end?cpu_reset_end:dma_reset_end;
    for(int n=0;n<reset_ticks;++n) {
      cpu.reset=n<F6_CPU_RESET_ASSERT; dma.reset=n<F6_DMA_RESET_ASSERT; edge();
    }
    Response ins,dat; Control ctl; Master master;
    unsigned reads=0,writes=0,config=0,irq_high=0,takes=0,clears=0;
    unsigned total_reads=0,total_writes=0,total_config=0,total_irq_high=0,total_takes=0,total_clears=0;
    unsigned total_mret=0,total_successor=0,total_marker=0;
    size_t case_index=0; bool waiting_instr=false,normal_finish=false; uint32_t waiting_address=0;
    bool mret=false,marker=false,successor=false,last_irq=bool(dma.F6_DMA_IRQ); unsigned pulse=0; uint64_t tick=0;
    if (F6_PULSE_TICKS && last_irq) throw std::runtime_error("pulse IRQ lacks low baseline");
    for (;tick<5000;++tick) {
      // Level uses the native IRQ; pulse delivery is host-stretched only when
      // the declared IRQ contract requires a fixed delivery window.
      const bool delivered=F6_PULSE_TICKS ? pulse!=0 : bool(dma.F6_DMA_IRQ);
      cpu.F6_CPU_IRQ=delivered;
      cpu.i_req_ready=!ins.valid&&!waiting_instr; cpu.i_rsp_valid=ins.valid; cpu.i_rsp_rdata=ins.value; cpu.i_rsp_error=0;
      cpu.d_req_ready=!dat.valid && !ctl.busy; cpu.d_rsp_valid=dat.valid; cpu.d_rsp_rdata=dat.value; cpu.d_rsp_error=0;
      dma.swb_cyc=ctl.busy; dma.swb_stb=ctl.busy && !ctl.accepted; dma.swb_we=ctl.write;
      dma.swb_adr=ctl.address>>2; dma.swb_dat_w=ctl.value;
#if F6_CONTROL_SEL
      dma.swb_sel=ctl.be;
#else
      if (ctl.busy&&ctl.be!=15) throw std::runtime_error("partial DMA control write unsupported");
#endif
      dma.mwb_stall=master.pending; dma.mwb_ack=master.pending && master.delay==0;
      dma.mwb_err=0; dma.mwb_dat_r=master.data;
      cpu.eval(); dma.eval();
      const bool itake=cpu.i_req_valid&&cpu.i_req_ready, dtake=cpu.d_req_valid&&cpu.d_req_ready;
      const bool iconsume=cpu.i_rsp_valid&&cpu.i_rsp_ready, dconsume=cpu.d_rsp_valid&&cpu.d_rsp_ready;
      const uint32_t ia=cpu.i_req_addr, da=cpu.d_req_addr, dv=cpu.d_req_wdata;
      const unsigned be=cpu.d_req_be; const bool dw=cpu.d_req_write;
      const bool control_accept=ctl.busy&&!ctl.accepted&&!dma.swb_stall;
      const bool control_ack=ctl.busy&&dma.swb_ack;
      const uint32_t control_data=dma.swb_dat_r;
      if (control_ack&&!ctl.accepted) throw std::runtime_error("control ACK before acceptance");
      const bool master_accept=dma.mwb_cyc&&dma.mwb_stb&&!dma.mwb_stall;
      const bool master_ack=dma.mwb_cyc&&dma.mwb_ack;
      const bool master_write=dma.mwb_we;
      const uint64_t master_wide_address=uint64_t(dma.mwb_adr)<<2;
      if (master_accept&&master_wide_address>UINT32_MAX)
        throw std::runtime_error("DMA master address out of range");
      const uint32_t master_addr=uint32_t(master_wide_address), master_data=dma.mwb_dat_w;
      const unsigned master_sel=
#if F6_MASTER_SEL
        dma.mwb_sel;
#else
        15;
#endif
      if (master.pending&&!dma.mwb_cyc) throw std::runtime_error("DMA dropped pending cycle");
#if F6_HAVE_TAKE
      if (cpu.F6_CPU_TAKE) { if (!delivered) throw std::runtime_error("IRQ taken without delivered source"); ++takes; }
#endif
      if (dma.F6_DMA_IRQ) ++irq_high;
      cpu.clk=dma.clk=1; cpu.eval(); dma.eval();
      const bool master_post_stb=dma.mwb_stb;
#if F6_HAVE_RVFI
      if (cpu.F6_RVFI_VALID) {
        if (cpu.F6_RVFI_TRAP) throw std::runtime_error("CPU retirement trap");
        if (cpu.F6_RVFI_INSN==0x30200073) { mret=true; std::cout << "mret " << tick << '\n'; }
        else if (mret) successor=true;
      }
#endif
      const bool raw_irq=dma.F6_DMA_IRQ;
      if (F6_PULSE_TICKS) {
        if (raw_irq&&!last_irq) pulse=F6_PULSE_TICKS;
        else if (pulse) --pulse;
      }
      last_irq=raw_irq;
      cpu.clk=dma.clk=0; cpu.eval(); dma.eval();
      if (iconsume) ins.valid=false;
      if (dconsume) dat.valid=false;
      if (itake) {
        const uint64_t offset=uint64_t(ia)-uint64_t(F6_SLOT_BASE);
        const bool slot_address=ia>=F6_SLOT_BASE && offset<uint64_t(F6_SLOT_BYTES)*F6_SLOT_COUNT;
        const size_t slot=slot_address ? offset/F6_SLOT_BYTES : 0;
        const bool in_prefix=slot_address && offset%F6_SLOT_BYTES<F6_PREFIX_BYTES;
        if (online&&in_prefix&&slot>=records.size()) {
          if (slot!=records.size()) throw std::runtime_error("non-sequential F6 instruction fetch");
          waiting_instr=true; waiting_address=ia;
          std::cout << "FETCH_HELD " << slot << " tick " << tick << " address " << std::hex << ia << std::dec << '\n';
        } else { ins.value=mem.read(ia); ins.valid=true; }
      }
      if (dtake) {
        if (da>=kDmaBase&&da<kDmaBase+kDmaSize) {
          ctl={true,false,dw,da-kDmaBase,dv,be};
          std::cout << "cpu_mmio " << tick << ' ' << (dw?"write":"read") << ' ' << std::hex << da << ' ' << dv << std::dec << '\n';
        } else {
          if (dw) { if (be>15) throw std::runtime_error("invalid RAM write"); mem.write(da,dv,be);
            if(da==kResult+24*case_index+20) marker=true; }
          dat.value=dw?0:mem.read(da); dat.valid=true;
        }
      }
      if (control_accept) ctl.accepted=true;
      if (control_ack) {
        if (ctl.write) { ++config; if (F6_CLEAR_REQUIRED&&ctl.address==F6_CLEAR_OFFSET&&ctl.value==F6_CLEAR_VALUE) ++clears; }
        dat.value=control_data; dat.valid=true; ctl={};
      }
      if (master.pending && master.delay) --master.delay;
      if (master_ack) master={};
      if (master_accept) {
        if (master_sel!=15) throw std::runtime_error("non-full DMA SEL outside spike scope");
        if (master_write) {
          if (writes>=4 || master_addr!=kDst+4*writes) throw std::runtime_error("unexpected DMA write address");
          mem.write(master_addr,master_data,master_sel); ++writes;
        } else {
          if (reads>=4 || master_addr!=kSrc+4*reads) throw std::runtime_error("unexpected DMA read address");
          ++reads;
        }
        master.pending=true; master.data=master_write?0:mem.read(master_addr);
        master.delay=master_write&&!master_post_stb;
        std::cout << "dma_" << (master_write?"write ":"read ") << tick << ' '
                  << std::hex << master_addr << ' ' << (master_write?master_data:master.data) << std::dec << '\n';
      }
      if (marker && (!F6_HAVE_RVFI || (mret&&successor))) {
        bool values=true;
        for(unsigned i=0;i<4;++i)
          values &= mem.read(kDst+4*i)==records[case_index][i]
            && mem.read(kResult+24*case_index+4+4*i)==records[case_index][i];
        const bool passed=reads==4&&writes==4&&irq_high&&(!F6_HAVE_TAKE||takes==1)
          &&(!F6_CLEAR_REQUIRED||clears==1)&&(!F6_HAVE_RVFI||(mret&&successor))
          &&values&&mem.read(kResult+24*case_index+20)==1&&!dma.F6_DMA_IRQ;
        std::cout << "case " << case_index << ' ' << (passed?"observations_passed":"failed")
                  << " reads " << reads << " writes " << writes << " irq_takes " << takes
                  << " irq_clears " << clears << " values " << values << '\n';
        if (!passed) throw std::runtime_error("F6 case observation failed");
        total_reads+=reads; total_writes+=writes; total_config+=config;
        total_irq_high+=irq_high; total_takes+=takes; total_clears+=clears;
        total_mret+=mret; total_successor+=successor; total_marker+=marker;
        ++case_index;
        if ((!online && case_index==records.size()) || case_index==F6_SLOT_COUNT) {
          normal_finish=true; break;
        }
        reads=writes=config=irq_high=takes=clears=0;
        mret=marker=successor=false;
      }
      if (online&&waiting_instr&&case_index==records.size()&&!ctl.busy&&!master.pending
          &&!dat.valid&&!dma.F6_DMA_IRQ&&!pulse) {
        std::cout << "NEED_RECORD " << case_index << " tick " << tick << '\n';
        std::string line;
        if (!std::getline(std::cin,line) || line=="END") { normal_finish=true; break; }
        std::istringstream message(line); std::string tag,raw,hex,extra;
        if (!(message>>tag>>raw>>hex) || tag!="CASE" || (message>>extra)
            || hex.size()!=F6_PREFIX_BYTES*2)
          throw std::runtime_error("invalid online F6 case message");
        const auto words=decode_record(raw);
        std::array<uint8_t,F6_PREFIX_BYTES> prefix{};
        for (size_t i=0;i<prefix.size();++i) {
          if (!std::isxdigit(static_cast<unsigned char>(hex[2*i])) ||
              !std::isxdigit(static_cast<unsigned char>(hex[2*i+1])))
            throw std::runtime_error("invalid online F6 prefix hex");
          prefix[i]=std::stoul(hex.substr(2*i,2),nullptr,16);
        }
        const uint32_t base=F6_SLOT_BASE+F6_SLOT_BYTES*case_index;
        if (waiting_address<base || waiting_address>=base+F6_PREFIX_BYTES)
          throw std::runtime_error("pending fetch is not in next F6 prefix");
        for (size_t i=0;i<prefix.size();i+=4) {
          uint32_t word=0; for (unsigned j=0;j<4;++j) word|=uint32_t(prefix[i+j])<<(8*j);
          mem.write(base+i,word,15);
        }
        records.push_back(words);
        ins.value=mem.read(waiting_address); ins.valid=true; waiting_instr=false;
        std::cout << "CASE_INSTALLED " << case_index << '\n';
      }
    }
    const bool ok=normal_finish&&case_index>0&&case_index==records.size();
    const auto elapsed=std::chrono::duration<double>(std::chrono::steady_clock::now()-started).count();
    std::cout << "summary " << (ok?"observations_passed":"failed") << " cases " << case_index << " ticks " << tick+1 << " reads " << total_reads
      << " writes " << total_writes << " control_writes " << total_config << " irq_high_ticks " << total_irq_high
      << " irq_takes " << total_takes << " irq_clears " << total_clears << " mret " << total_mret
      << " irq_take_evidence " << (F6_HAVE_TAKE?"observed":"unknown")
      << " retirement_evidence " << (F6_HAVE_RVFI?"observed":"unknown")
      << " simulated_lockstep_assumed " << F6_ASSUMED_LOCKSTEP
      << " cpu_declared_hz " << F6_CPU_DECLARED_HZ << " dma_declared_hz " << F6_DMA_DECLARED_HZ
      << " successor " << total_successor << " marker " << total_marker << " runtime_seconds " << elapsed << '\n';
    cpu.final(); dma.final(); return ok?0:1;
  } catch (const std::exception &e) { std::cerr << e.what() << '\n'; return 1; }
}
