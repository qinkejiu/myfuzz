#pragma once

#include <cstdint>

// AXI4 CPU-side identity: which accepted beat is an instruction fetch and which
// is data.  The repository contains two different declarations of that identity,
// and neither may be inferred from the address:
//
//   * packed single master (CVA6, `processor.memory.unified`): the AXI ID carries
//     the channel identity.  In the pinned cv64a6_imafdc_sv39 configuration the
//     write-through AXI adapter arbitrates the I-cache as request 0 and decodes
//     return id 0 as the I-cache
//     (third_party/cva6_upstream_reference/core/cache_subsystem/wt_axi_adapter.sv:
//     116 arb_req = {dcache, icache}; 144/159 axi_*_id_in = {0, arb_idx};
//     597 `axi_rd_id_out == 0` -> icache; 638 `axi_rd_id_out[0]` -> dcache).
//     The AXI user bits and ARPROT are tied to zero by the same core
//     (core/axi_shim.sv:258/263), so they must not be used as a fetch marker.
//
//   * structural two-master (VexiiRiscv `reduced_dual_axi_cpu`): the generated
//     top has separate `i_*` (AR/R only) and `d_*` (AW/W/B/AR/R) pins, so the
//     port itself is the identity and there is no ID map to declare.
//
// Both declarations are properties of a configuration, not of AXI4.  A model
// whose profile does not declare one keeps this class in its "undeclared" state:
// every beat then classifies as Unknown (never as a fetch), and the caller must
// say so in its output instead of counting a data beat as an instruction.
class Axi4CpuIdentity {
 public:
  enum Kind { Unknown, Instruction, Data };

  // A packed port whose ID map is not declared has no fetch identity at all.
  static Axi4CpuIdentity undeclared() { return Axi4CpuIdentity(0, 0, false); }

  // CVA6 pinned declaration: ARID 0 and RID 0 are the I-cache, every other ID is
  // the D-cache.  It is stated as a 16-bit one-bit-per-ID mask because the AXI ID
  // of this configuration is 4 bits wide.
  static Axi4CpuIdentity packed_instruction_ids(unsigned arid, unsigned rid) {
    return Axi4CpuIdentity(arid < 16 ? uint16_t(1) << arid : uint16_t(0),
                           rid < 16 ? uint16_t(1) << rid : uint16_t(0), false);
  }

  // Structural two-master CPU: the channel name is the identity.
  static Axi4CpuIdentity structural() { return Axi4CpuIdentity(0, 0, true); }

  bool instruction_id_declared() const {
    return structural_ || instruction_arid_mask_ != 0;
  }

  // One accepted read address beat.  A write can never be an instruction fetch
  // on either declaration, which is why the direction is an argument and not a
  // guess from the address.
  Kind request(unsigned arid, bool write) const {
    if (write) return Data;
    if (structural_) return Unknown;  // no per-port call: use request_channel()
    if (!instruction_arid_mask_) return Unknown;
    return ((uint16_t(1) << (arid & 15u)) & instruction_arid_mask_)
               ? Instruction
               : Data;
  }

  // One accepted read data beat.  On the packed port this is the return ID the
  // adapter put back on RID; on a structural port the caller knows the channel.
  Kind response(unsigned rid) const {
    if (structural_) return Unknown;  // no per-port call: use response_channel()
    if (!instruction_rid_mask_) return Unknown;
    return ((uint16_t(1) << (rid & 15u)) & instruction_rid_mask_)
               ? Instruction
               : Data;
  }

  // One accepted beat of a structural port, named by the generated pin prefix.
  Kind request_channel(char channel) const {
    if (!structural_) return Unknown;
    if (channel == 'i') return Instruction;
    if (channel == 'd') return Data;
    return Unknown;
  }

  Kind response_channel(char channel) const {
    if (!structural_) return Unknown;
    if (channel == 'i') return Instruction;
    if (channel == 'd') return Data;
    return Unknown;
  }

 private:
  Axi4CpuIdentity(uint16_t arid_mask, uint16_t rid_mask, bool structural)
      : instruction_arid_mask_(arid_mask),
        instruction_rid_mask_(rid_mask),
        structural_(structural) {}

  uint16_t instruction_arid_mask_;
  uint16_t instruction_rid_mask_;
  bool structural_;
};

// Per-channel handshake counters.  They count what the two sides really
// handshook, never what a state machine expected: a channel is incremented only
// when valid and ready were both sampled in the same cycle.  The instruction and
// data splits are filled from Axi4CpuIdentity, and an undeclared identity leaves
// the *instruction* counters at zero rather than borrowing the data counts.
struct Axi4ChannelCounts {
  unsigned long long ar = 0, r = 0, aw = 0, w = 0, b = 0;
  unsigned long long ar_instruction = 0, ar_data = 0, ar_unknown = 0;
  unsigned long long r_instruction = 0, r_data = 0, r_unknown = 0;
  unsigned long long aw_data = 0, w_data = 0, b_data = 0;
  unsigned long long beats = 0;  // adapter-side req/rsp handshakes

  void count_request(Axi4CpuIdentity::Kind kind) {
    ++ar;
    if (kind == Axi4CpuIdentity::Instruction) ++ar_instruction;
    else if (kind == Axi4CpuIdentity::Data) ++ar_data;
    else ++ar_unknown;
  }

  void count_response(Axi4CpuIdentity::Kind kind) {
    ++r;
    if (kind == Axi4CpuIdentity::Instruction) ++r_instruction;
    else if (kind == Axi4CpuIdentity::Data) ++r_data;
    else ++r_unknown;
  }
};
