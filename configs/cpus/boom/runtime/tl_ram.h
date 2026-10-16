#ifndef BOOM_TL_RAM_H
#define BOOM_TL_RAM_H
#include <cstdint>
#include <deque>
#include <map>
#include <set>
#include <vector>
#include <stdexcept>
struct TlRequest {
  unsigned opcode, param, size, source;
  uint32_t address;
  unsigned mask;
  uint64_t data;
};
struct TlResponse {
  unsigned opcode, param, size, source, sink, beats, beat=0;
  uint32_t address;
  std::vector<uint64_t> data{};
};
class TlRam {
  std::map<uint32_t,uint8_t> bytes;
  std::deque<TlResponse> responses;
  std::set<unsigned> grants;
  unsigned c_beat=0, a_beat=0;
  TlRequest c_first{}, a_first{};
  unsigned allocate_sink() {
    for(unsigned i=0;i<8;++i) if(!grants.count(i)) {grants.insert(i); return i;}
    throw std::runtime_error("all grant sink IDs occupied");
  }
  static unsigned beats(unsigned size) {if(size>12) throw std::runtime_error("invalid TL size"); return size>3 ? 1u<<(size-3) : 1;}
  void enqueue(TlResponse response) {
    for(unsigned i=0;i<response.beats;++i)
      response.data.push_back(response.opcode==1 || response.opcode==5 ? read64((response.address&~7u)+8*i) : 0);
    responses.push_back(response);
  }
public:
  uint64_t a_get=0,a_acquire=0,a_put=0,c_release=0,c_release_data=0,d_count=0,e_count=0;
  bool empty() const {return responses.empty();}
  bool drained() const {return responses.empty() && grants.empty() && !a_beat && !c_beat;}
  bool ready() const {return responses.size()<16 && grants.size()<8;}
  const TlResponse& front() const {return responses.front();}
  uint64_t read64(uint32_t address) const {
    uint64_t data=0;
    for(unsigned i=0;i<8;++i) {auto it=bytes.find(address+i); if(it!=bytes.end()) data|=uint64_t(it->second)<<(8*i);}
    return data;
  }
  void write64(uint32_t address,uint64_t data,unsigned mask) {
    for(unsigned i=0;i<8;++i) if(mask&(1u<<i)) bytes[address+i]=data>>(8*i);
  }
  void write32(uint32_t address,uint32_t data) {
    for(unsigned i=0;i<4;++i) bytes[address+i]=data>>(8*i);
  }
  uint64_t front_data() const {return front().data.at(front().beat);}
  void accept_a(TlRequest a) {
    if(a.opcode==4) {++a_get; enqueue({1,0,a.size,a.source,0,beats(a.size),0,a.address});}
    else if(a.opcode==6 || a.opcode==7) {
      ++a_acquire;
      enqueue({a.opcode==6 ? 5u:4u,a.param==0 ? 1u:0u,a.size,a.source,allocate_sink(),a.opcode==6 ? beats(a.size):1u,0,a.address});
    } else if(a.opcode==0 || a.opcode==1) {
      if(!a_beat) a_first=a;
      if(a.source!=a_first.source || a.size!=a_first.size || a.address!=a_first.address) throw std::runtime_error("A multibeat identity changed");
      write64((a.address&~7u)+8*a_beat,a.data,a.mask);
      if(++a_beat==beats(a.size)) {++a_put; enqueue({0,0,a.size,a.source,0,1,0,a.address}); a_beat=0;}
    } else throw std::runtime_error("unsupported A opcode");
  }
  void accept_c(TlRequest c) {
    if(c.opcode!=6 && c.opcode!=7) throw std::runtime_error("unexpected C opcode without probes");
    if(!c_beat) c_first=c;
    if(c.source!=c_first.source || c.size!=c_first.size || c.address!=c_first.address) throw std::runtime_error("C multibeat identity changed");
    if(c.opcode==7) write64((c.address&~7u)+8*c_beat,c.data,255);
    if(++c_beat==(c.opcode==7 ? beats(c.size):1)) {
      if(c.opcode==7) ++c_release_data; else ++c_release;
      enqueue({6,0,c.size,c.source,0,1,0,c.address}); c_beat=0;
    }
  }
  void accept_d() {++d_count; if(++responses.front().beat==responses.front().beats) responses.pop_front();}
  void accept_e(unsigned sink) {if(!grants.erase(sink)) throw std::runtime_error("unallocated GrantAck sink"); ++e_count;}
};
#endif
