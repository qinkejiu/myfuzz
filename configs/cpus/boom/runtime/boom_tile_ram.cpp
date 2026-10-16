#include "VBoomTile.h"
#include "verilated.h"
#include "tl_ram.h"
#include <iostream>
#include <iomanip>
#define TL(name) auto_tl_other_masters_out_##name
static uint32_t lui(unsigned rd,unsigned imm) {return (imm<<12)|(rd<<7)|0x37;}
static uint32_t addi(unsigned rd,unsigned rs,int imm) {return (unsigned(imm)&4095)<<20|(rs<<15)|(rd<<7)|0x13;}
static uint32_t store(unsigned rs,unsigned base,int imm,unsigned funct=3) {return ((unsigned(imm)>>5&127)<<25)|(rs<<20)|(base<<15)|(funct<<12)|((imm&31)<<7)|0x23;}
static uint32_t load(unsigned rd,unsigned base,int imm) {return (unsigned(imm)&4095)<<20|(base<<15)|(3<<12)|(rd<<7)|3;}
int main(int argc,char**argv) {
  VerilatedContext context;
  context.commandArgs(argc,argv);
  VBoomTile dut{&context};
  TlRam ram;
  std::cout.setf(std::ios::unitbuf);
  ram.write32(0x10040,addi(5,0,1));
  ram.write32(0x10044,(31<<20)|(5<<15)|(1<<12)|(5<<7)|0x13);
  ram.write32(0x10048,(5<<15)|0x67);
  uint32_t pc=0x80000000;
  auto emit=[&](uint32_t insn) {ram.write32(pc,insn); pc+=4;};
  emit(lui(1,0x80001)); emit((32<<20)|(1<<15)|(1<<12)|(1<<7)|0x13); emit((32<<20)|(1<<15)|(5<<12)|(1<<7)|0x13); emit(addi(2,0,0x123)); emit(store(2,1,0)); emit(load(3,1,0));
  emit(lui(4,4)); emit(store(3,4,0,2));
  emit(lui(6,1));
  for(unsigned i=0;i<12;++i) {emit((6<<20)|(1<<15)|(1<<7)|0x33); emit(addi(2,2,1)); emit(store(2,1,0));}
  emit(lui(1,0x80001)); emit((32<<20)|(1<<15)|(1<<12)|(1<<7)|0x13); emit((32<<20)|(1<<15)|(5<<12)|(1<<7)|0x13); emit(load(3,1,0)); emit(store(3,4,8,2)); emit(0x6f);
  dut.auto_hartid_in=0;
  dut.auto_int_local_in_0_0=0; dut.auto_int_local_in_1_0=0; dut.auto_int_local_in_1_1=0;
  dut.auto_int_local_in_2_0=0; dut.auto_int_local_in_3_0=0;
  dut.TL(b_valid)=0; dut.TL(b_bits_opcode)=0; dut.TL(b_bits_param)=0; dut.TL(b_bits_size)=0;
  dut.TL(b_bits_source)=0; dut.TL(b_bits_address)=0; dut.TL(b_bits_mask)=0; dut.TL(b_bits_corrupt)=0;
  unsigned transactions=0;
  auto trace=[&](char channel,TlRequest req) {
    if(transactions++<400) std::cout<<"{\"channel\":\""<<channel<<"\",\"opcode\":"<<req.opcode<<",\"param\":"<<req.param<<",\"mask\":"<<req.mask<<",\"size\":"<<req.size<<",\"source\":"<<req.source<<",\"address\":"<<req.address<<",\"data\":"<<req.data<<"}\n";
  };
  try {
    for(uint64_t cycle=0;cycle<250000;++cycle) {
      dut.reset=cycle<20;
      dut.TL(a_ready)=!dut.reset && ram.ready(); dut.TL(c_ready)=!dut.reset && ram.ready(); dut.TL(e_ready)=!dut.reset;
      dut.TL(d_valid)=!dut.reset && !ram.empty();
      dut.TL(d_bits_opcode)=0; dut.TL(d_bits_param)=0; dut.TL(d_bits_size)=0; dut.TL(d_bits_source)=0;
      dut.TL(d_bits_sink)=0; dut.TL(d_bits_denied)=0; dut.TL(d_bits_data)=0; dut.TL(d_bits_corrupt)=0;
      if(dut.TL(d_valid)) {const auto &r=ram.front(); dut.TL(d_bits_opcode)=r.opcode; dut.TL(d_bits_param)=r.param; dut.TL(d_bits_size)=r.size; dut.TL(d_bits_source)=r.source; dut.TL(d_bits_sink)=r.sink; dut.TL(d_bits_data)=ram.front_data();}
      dut.clock=0; dut.eval();
      bool a=dut.TL(a_ready)&&dut.TL(a_valid), c=dut.TL(c_ready)&&dut.TL(c_valid), d=dut.TL(d_ready)&&dut.TL(d_valid), e=dut.TL(e_ready)&&dut.TL(e_valid);
      TlRequest ar{dut.TL(a_bits_opcode),dut.TL(a_bits_param),dut.TL(a_bits_size),dut.TL(a_bits_source),dut.TL(a_bits_address),dut.TL(a_bits_mask),dut.TL(a_bits_data)};
      TlRequest cr{dut.TL(c_bits_opcode),dut.TL(c_bits_param),dut.TL(c_bits_size),dut.TL(c_bits_source),dut.TL(c_bits_address),255,dut.TL(c_bits_data)};
      unsigned sink=dut.TL(e_bits_sink);
      context.timeInc(1); dut.clock=1; dut.eval(); context.timeInc(1);
      if(d) {if(transactions++<400) std::cout<<"{\"channel\":\"D\",\"opcode\":"<<ram.front().opcode<<",\"size\":"<<ram.front().size<<",\"source\":"<<ram.front().source<<",\"sink\":"<<ram.front().sink<<",\"param\":"<<ram.front().param<<",\"beat\":"<<ram.front().beat<<",\"data\":"<<ram.front_data()<<"}\n"; ram.accept_d();}
      if(e) {std::cout<<"{\"channel\":\"E\",\"sink\":"<<sink<<"}\n"; ram.accept_e(sink);}
      if(a) {trace('A',ar); ram.accept_a(ar);}
      if(c) {trace('C',cr); ram.accept_c(cr);}
      if(context.gotFinish()) throw std::runtime_error("RTL stopped before completion");
      if(ram.read64(0x4000)==0x123 && ram.read64(0x4008)==0x123 && ram.c_release_data && ram.a_acquire && ram.e_count && ram.read64(0x80001000)==0x123 && ram.drained() && ram.e_count==ram.a_acquire) {
        std::cout<<"{\"result\":\"pass\",\"cycles\":"<<cycle<<",\"A_Get\":"<<ram.a_get<<",\"A_Acquire\":"<<ram.a_acquire<<",\"A_Put\":"<<ram.a_put<<",\"C_ReleaseData\":"<<ram.c_release_data<<",\"D_beats\":"<<ram.d_count<<",\"E_GrantAck\":"<<ram.e_count<<",\"cached_ram_value\":"<<ram.read64(0x80001000)<<",\"first_load_result\":"<<ram.read64(0x4000)<<",\"reload_result\":"<<ram.read64(0x4008)<<",\"B_valid\":0}\n";
        dut.final(); return 0;
      }
    }
    std::cerr<<"timeout marker="<<ram.read64(0x4000)<<" reload="<<ram.read64(0x4008)<<" acquire="<<ram.a_acquire<<" release="<<ram.c_release_data<<"\n";
  } catch(const std::exception&ex) {std::cerr<<ex.what()<<"\n";}
  dut.final(); return 1;
}
