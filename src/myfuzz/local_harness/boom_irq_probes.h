#ifndef MYFUZZ_BOOM_IRQ_PROBES_H
#define MYFUZZ_BOOM_IRQ_PROBES_H
#include "verilated_vpi.h"
#include "vpi_user.h"
#include <cstdint>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
struct BoomProbe {const char *id; const char *path; unsigned width; vpiHandle handle=nullptr;};
#include "boom_irq_probe_specs.h"
class BoomIrqProbes {
  std::vector<BoomProbe> probes=boom_probe_specs();
public:
  BoomIrqProbes() {
    for(auto &probe:probes) {
      probe.handle=vpi_handle_by_name(const_cast<char*>(probe.path),nullptr);
      if(!probe.handle) throw std::runtime_error(std::string("missing generated VPI probe: ")+probe.path);
      const std::string actual=vpi_get_str(vpiFullName,probe.handle);
      if(actual!=probe.path || unsigned(vpi_get(vpiSize,probe.handle))!=probe.width)
        throw std::runtime_error(std::string("generated VPI instance/width mismatch: ")+probe.path);
    }
  }
  std::string inventory() const {
    std::ostringstream out; out<<"[";bool first=true;
    for(const auto &probe:probes) {
      if(!first) out<<",";first=false;
      // Query the generated handle again; never print an assumed width/name.
      out<<"{\"id\":\""<<probe.id<<"\",\"path\":\""<<vpi_get_str(vpiFullName,probe.handle)
         <<"\",\"width\":"<<vpi_get(vpiSize,probe.handle)<<"}";
    }
    out<<"]";return out.str();
  }
  std::string sample() const {
    std::ostringstream out;out<<"{";bool first=true;
    for(const auto &probe:probes) {
      s_vpi_value value{};value.format=vpiVectorVal;vpi_get_value(probe.handle,&value);
      if(!value.value.vector) throw std::runtime_error("missing actual VPI vector value");
      uint64_t data=0;
      for(unsigned index=0;index<(probe.width+31)/32;++index) {
        if(value.value.vector[index].bval) throw std::runtime_error("unknown VPI probe bits unsupported");
        data|=uint64_t(uint32_t(value.value.vector[index].aval))<<(32*index);
      }
      if(probe.width<64) data&=(uint64_t(1)<<probe.width)-1;
      if(!first) out<<",";first=false;
      out<<"\""<<probe.id<<"\":"<<data;
    }
    out<<"}";return out.str();
  }
};
#endif
