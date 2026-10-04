#pragma once

#include <cstdint>
#include <stdexcept>
#include <vector>

// A source of serial input bits owned by the test case. The DUT alone owns
// SCK, CS, MOSI and events. This object advances only on observed SCK edges.
class PulpSpiMode0Peer {
 public:
  void append(unsigned chip_select, std::uint32_t word, unsigned bits) {
    if (chip_select > 3 || bits < 1 || bits > 32 || source_.size() + bits > 4096)
      throw std::runtime_error("spi_source_range");
    if (source_chosen_ && chip_select != chip_select_)
      throw std::runtime_error("spi_source_chip_select_change");
    chip_select_ = chip_select;
    source_chosen_ = true;
    for (unsigned i = 0; i < bits; ++i)
      source_.push_back((word >> (bits - 1 - i)) & 1u);
  }

  unsigned drive_bit() const {
    return consumed_ < source_.size()
               ? source_[consumed_] : 0;
  }

  void observe(unsigned sck, unsigned active_cs, unsigned mode, unsigned mosi) {
    if (sck > 1 || active_cs > 15 || mode > 3 || mosi > 1)
      throw std::runtime_error("spi_invalid_pins");
    const bool selected = active_cs != 0;
    if (selected && (!source_chosen_ || active_cs != (1u << chip_select_)))
      throw std::runtime_error("spi_unsupported_chip_select");
    const bool edge = selected && selected_ && sck != last_sck_;
    const bool setup = mode == 2 && sck == 0 && !selected_edge_ && !edge;
    if (selected && mode != 0 && !setup)
      throw std::runtime_error("spi_unsupported_line_mode");
    if (selected && !selected_ && sck)
      throw std::runtime_error("spi_missing_setup");
    if (edge && sck) {
      if (consumed_ == source_.size())
        throw std::runtime_error("spi_source_exhausted");
      captured_.push_back(mosi);
      ++consumed_;
    }
    selected_edge_ = selected ? selected_edge_ || edge : false;
    selected_ = selected;
    last_sck_ = sck;
    mode_ = mode;
  }

 private:
  bool source_chosen_ = false;
  unsigned chip_select_ = 0;
  std::vector<unsigned char> source_;
  std::vector<unsigned char> captured_;
  std::size_t consumed_ = 0;
  bool selected_ = false;
  bool selected_edge_ = false;
  unsigned last_sck_ = 0;
  unsigned mode_ = 0;
};
