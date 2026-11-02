#pragma once

#include <cstdint>

// The generated AHB subordinate exposes a single pending m beat.  The
// protocol's HPROT accompanies its address phase, which may be several edges
// earlier than that backend beat.  Preserve the accepted manager-domain
// address, rather than attributing the live HPROT to a different transfer.
class AhbIdentity {
 public:
  enum Kind { Unknown, Instruction, Data };

  // Call once per rising edge with pre-edge bus samples.  manager_ready is the
  // CPU's measured aggregate HREADY, not the external target's HREADYEXT.
  // Backend classification for this edge must occur before calling edge().
  void edge(bool bus_reset_n, bool manager_ready, bool hsel, unsigned htrans,
            uint64_t address, bool write, unsigned hprot) {
    if (!bus_reset_n) {
      valid_ = false;
      return;
    }
    if (!manager_ready) return;
    valid_ = hsel && (htrans & 2u);
    if (valid_) {
      address_ = address;
      write_ = write;
      instruction_ = !(hprot & 1u);
    }
  }

  Kind classify(uint64_t address, bool write) const {
    if (!valid_ || address_ != address || write_ != write ||
        (instruction_ && write_)) return Unknown;
    return instruction_ ? Instruction : Data;
  }

 private:
  uint64_t address_ = 0;
  bool valid_ = false;
  bool write_ = false;
  bool instruction_ = false;
};
