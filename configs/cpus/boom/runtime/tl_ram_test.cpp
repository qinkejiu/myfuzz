#include "tl_ram.h"
#include <cassert>
int main() {
  TlRam ram;
  ram.write64(0x80001000, 0x123, 255);
  ram.accept_a({6,1,6,2,0x80001000,255,0});
  assert(ram.front().opcode==5 && ram.front().param==0);
  assert(ram.front().source==2 && ram.front().beats==8);
  const unsigned sink=ram.front().sink;
  assert(ram.front_data()==0x123);
  for(int i=0;i<8;++i) ram.accept_d();
  ram.accept_e(sink);
  for(int i=0;i<8;++i) ram.accept_c({7,1,6,3,0x80002000,0,0x100u+unsigned(i)});
  assert(ram.front().opcode==6 && ram.front().source==3);
  ram.accept_d();
  assert(ram.read64(0x80002038)==0x107);
  ram.accept_a({4,0,3,4,0x80002038,255,0});
  assert(ram.front().opcode==1 && ram.front_data()==0x107);
  ram.accept_d();
  ram.accept_a({1,0,3,1,0x80002038,2,0x5500});
  assert(ram.read64(0x80002038)==0x5507);
  assert(ram.front().opcode==0);
  ram.accept_d();
  ram.accept_a({7,2,6,5,0x80003000,255,0});
  assert(ram.front().opcode==4 && ram.front().beats==1 && ram.front().param==0);
  const unsigned perm_sink=ram.front().sink;
  ram.accept_d(); ram.accept_e(perm_sink);
  ram.accept_c({6,2,6,5,0x80003000,0,0});
  assert(ram.front().opcode==6 && ram.front().source==5);
  ram.accept_d();
  for(unsigned i=0;i<8;++i) ram.accept_a({0,0,6,6,0x80004000,255,0x200+i});
  assert(ram.front().opcode==0 && ram.front().source==6);
  assert(ram.read64(0x80004038)==0x207);
  ram.accept_d();
  assert(ram.empty() && ram.e_count==2);
  bool rejected=false;
  try {ram.accept_e(7);} catch(const std::runtime_error&) {rejected=true;}
  assert(rejected);
  ram.write64(0x80005000,0xabcd,255);
  ram.accept_a({4,0,3,1,0x80005000,255,0});
  ram.write64(0x80005000,0x1234,255);
  assert(ram.front_data()==0xabcd); // D data stays stable while backpressured.
  ram.accept_d();
}
