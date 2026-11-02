#include "inprocess_memory.h"
#include <cassert>
#include <stdexcept>
using myfuzz::inprocess_spike::Memory;
using myfuzz::inprocess_spike::Response;
int main() {
  Memory memory(0xfffffff0u,16);
  memory.write(0xfffffffcu,0x12345678u,15);
  assert(memory.read(0xfffffffcu)==0x12345678u);
  memory.write(0xfffffffcu,0xaabbccddu,5);
  assert(memory.read(0xfffffffcu)==0x12bb56ddu);
  assert(!Response{}.valid && Response{}.value==0);
  for(auto address : {0x100000000ull,0x1fffffffcull,0xfffffffdull}) {
    bool refused=false;
    try { memory.read(address); } catch(const std::runtime_error&) { refused=true; }
    assert(refused);
  }
}
