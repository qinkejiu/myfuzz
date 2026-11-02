#pragma once
// Byte-addressed RAM used by the two host-side exploration programs.
#include <cstdint>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace myfuzz { namespace inprocess_spike {
class Memory {
  std::uint64_t base_;
  std::vector<std::uint8_t> data_;
  std::size_t offset(std::uint64_t address) const {
    if ((address & 3) || address < base_ || data_.size() < 4
        || address-base_ > data_.size()-4)
      throw std::runtime_error("RAM access out of bounds or unaligned");
    return static_cast<std::size_t>(address-base_);
  }
public:
  Memory(std::uint32_t base, std::uint32_t size):base_(base),data_(size,0) {}
  std::uint32_t read(std::uint64_t address) const {
    const auto start=offset(address);
    std::uint32_t value=0;
    for (unsigned i=0;i<4;++i) value|=std::uint32_t(data_[start+i])<<(8*i);
    return value;
  }
  void write(std::uint64_t address,std::uint32_t value,unsigned be) {
    const auto start=offset(address);
    for (unsigned i=0;i<4;++i) if ((be>>i)&1) data_[start+i]=value>>(8*i);
  }
  void load(const char *path) {
    std::ifstream in(path); std::uint64_t address; std::string hex;
    if (!in) throw std::runtime_error("firmware input not found");
    while (in>>std::hex>>address>>hex) {
      if (hex.size()%2 || address<base_ || address-base_>data_.size()
          || hex.size()/2>data_.size()-(address-base_))
        throw std::runtime_error("firmware segment out of bounds");
      for (std::size_t i=0;i<hex.size();i+=2)
        data_[address-base_+i/2]=std::stoul(hex.substr(i,2),nullptr,16);
    }
  }
};
struct Response { bool valid=false; std::uint32_t value=0; };
}} // namespace myfuzz::inprocess_spike
