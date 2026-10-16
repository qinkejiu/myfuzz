#include "VBoomTile.h"
#include "verilated.h"
#include "tl_ram.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <memory>
#define TL(name) auto_tl_other_masters_out_##name
int main(int argc,char**argv) {
  VerilatedContext context;
  context.commandArgs(argc,argv);
  VBoomTile dut{&context};
  TlRam ram;
  // Pinned tile reset vector: jump from the boot ROM window to RV64 RAM.
  ram.write32(0x10040,0x00100293);
  ram.write32(0x10044,0x01f29293);
  ram.write32(0x10048,0x00028067);
  std::cout.setf(std::ios::unitbuf);
  dut.auto_hartid_in=0;
  dut.auto_int_local_in_0_0=0; dut.auto_int_local_in_1_0=0; dut.auto_int_local_in_1_1=0;
  dut.auto_int_local_in_2_0=0; dut.auto_int_local_in_3_0=0;
  dut.TL(b_valid)=0; dut.TL(b_bits_opcode)=0; dut.TL(b_bits_param)=0; dut.TL(b_bits_size)=0;
  dut.TL(b_bits_source)=0; dut.TL(b_bits_address)=0; dut.TL(b_bits_mask)=0; dut.TL(b_bits_corrupt)=0;
  uint64_t cycle=0;
  bool quiescing=false;
  uint64_t external_start=0, external_end=0;
  bool pending_external=false, external_response=false;
  TlRequest external_request{};
  uint64_t external_data=0;
  std::ostringstream events;
  bool first=true;
  auto event=[&]() -> std::ostream& {if(!first) events<<","; first=false; return events;};
  auto trace=[&](char channel,TlRequest req) {
    event()<<"{\"channel\":\""<<channel<<"\",\"opcode\":"<<req.opcode<<",\"param\":"<<req.param<<",\"mask\":"<<req.mask<<",\"size\":"<<req.size<<",\"source\":"<<req.source<<",\"address\":"<<req.address<<",\"data\":"<<req.data<<"}";
  };
  try {
    std::cout<<"{\"ready\":true}\n";
    std::string line;
    while(std::getline(std::cin,line)) {
      std::istringstream command(line);
      std::string op; command>>op;
      if(op=="END") break;
      if(op=="LOAD") {
        uint64_t address, value; command>>address>>value;
        if(!command || address<0x80000000ULL || address>0xffffffffULL || value>255) throw std::runtime_error("invalid LOAD");
        ram.write64(uint32_t(address), value, 1);
        std::cout<<"{\"ok\":true}\n"; continue;
      }
      if(op=="READ") {
        uint64_t address; command>>address;
        if(!command || address>0xfffffff8ULL) throw std::runtime_error("invalid READ");
        std::cout<<"{\"value\":"<<ram.read64(uint32_t(address))<<"}\n"; continue;
      }
      if(op=="EXTERNAL") {
        command>>external_start>>external_end;
        if(!command || external_start<0x4000 || external_start>=external_end || external_end>0x5000 || cycle) throw std::runtime_error("invalid external range");
        std::cout<<"{\"ok\":true}\n"; continue;
      }
      if(op=="RESPOND") {
        unsigned source, size; command>>source>>size>>external_data;
        if(!command || !pending_external || external_response || source!=external_request.source || size!=external_request.size) throw std::runtime_error("invalid external response");
        external_response=true; std::cout<<"{\"ok\":true}\n"; continue;
      }
      if(op=="QUIESCE") {quiescing=true; std::cout<<"{\"ok\":true}\n"; continue;}
      if(op!="STEP") throw std::runtime_error("unknown command");
      events.str(""); events.clear(); first=true;
      dut.reset=cycle<20;
      dut.TL(a_ready)=!dut.reset && !quiescing && !pending_external && ram.ready(); dut.TL(c_ready)=!dut.reset && ram.ready(); dut.TL(e_ready)=!dut.reset;
      bool external_d=external_response && ram.empty();
      dut.TL(d_valid)=!dut.reset && (!ram.empty() || external_d);
      dut.TL(d_bits_opcode)=0; dut.TL(d_bits_param)=0; dut.TL(d_bits_size)=0; dut.TL(d_bits_source)=0;
      dut.TL(d_bits_sink)=0; dut.TL(d_bits_denied)=0; dut.TL(d_bits_data)=0; dut.TL(d_bits_corrupt)=0;
      if(dut.TL(d_valid) && !external_d) {const auto &r=ram.front(); dut.TL(d_bits_opcode)=r.opcode; dut.TL(d_bits_param)=r.param; dut.TL(d_bits_size)=r.size; dut.TL(d_bits_source)=r.source; dut.TL(d_bits_sink)=r.sink; dut.TL(d_bits_data)=ram.front_data();}
      if(external_d) {dut.TL(d_bits_opcode)=external_request.opcode==4 ? 1 : 0; dut.TL(d_bits_size)=external_request.size; dut.TL(d_bits_source)=external_request.source; dut.TL(d_bits_data)=external_data;}
      dut.clock=0; dut.eval();
      bool a=dut.TL(a_ready)&&dut.TL(a_valid), c=dut.TL(c_ready)&&dut.TL(c_valid), d=dut.TL(d_ready)&&dut.TL(d_valid), e=dut.TL(e_ready)&&dut.TL(e_valid);
      TlRequest ar{dut.TL(a_bits_opcode),dut.TL(a_bits_param),dut.TL(a_bits_size),dut.TL(a_bits_source),dut.TL(a_bits_address),dut.TL(a_bits_mask),dut.TL(a_bits_data)};
      TlRequest cr{dut.TL(c_bits_opcode),dut.TL(c_bits_param),dut.TL(c_bits_size),dut.TL(c_bits_source),dut.TL(c_bits_address),255,dut.TL(c_bits_data)};
      unsigned sink=dut.TL(e_bits_sink);
      context.timeInc(1); dut.clock=1; dut.eval(); context.timeInc(1);
      if(d && external_d) {
        event()<<"{\"channel\":\"D\",\"opcode\":"<<unsigned(dut.TL(d_bits_opcode))<<",\"source\":"<<external_request.source<<",\"size\":"<<external_request.size<<",\"data\":"<<external_data<<",\"external\":true}";
        pending_external=false; external_response=false;
      }
      if(d && !external_d) {event()<<"{\"channel\":\"D\",\"opcode\":"<<ram.front().opcode<<",\"size\":"<<ram.front().size<<",\"source\":"<<ram.front().source<<",\"sink\":"<<ram.front().sink<<",\"param\":"<<ram.front().param<<",\"beat\":"<<ram.front().beat<<",\"data\":"<<ram.front_data()<<"}"; ram.accept_d();}
      if(e) {event()<<"{\"channel\":\"E\",\"sink\":"<<sink<<"}"; ram.accept_e(sink);}
      if(a) {
        trace('A',ar);
        if(ar.address>=external_start && ar.address<external_end) {
          if((ar.opcode!=4 && ar.opcode!=0 && ar.opcode!=1) || ar.size>3 || uint64_t(ar.address)+(1ULL<<ar.size)>external_end) throw std::runtime_error("unsupported external request");
          external_request=ar; pending_external=true;
        } else ram.accept_a(ar);
      }
      if(c) {trace('C',cr); ram.accept_c(cr);}
      if(context.gotFinish()) throw std::runtime_error("RTL stopped before completion");
      ++cycle;
      std::cout<<"{\"kind\":\"tilelink_coherent_cpu\",\"new_ticks\":1,\"cycle\":"<<cycle<<",\"events\":["<<events.str()<<"],\"drained\":"<<(ram.drained() && !pending_external?"true":"false")<<",\"reset\":"<<(dut.reset?"true":"false")<<"}\n";
    }
  } catch(const std::exception&ex) {std::cerr<<ex.what()<<"\n"; dut.final(); return 1;}
  dut.final(); return 0;
}
