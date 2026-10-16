#pragma once

namespace myfuzz { namespace local_driver_v1 {
// A deliberately conservative environment for a pipelined master. Stall may
// remain asserted while a previous request completes. No same-edge acceptance
// plus completion is supported by this version; the DUT protocol remains pipelined.
class WishboneDmaEdgeState {
  bool pending_ = false;
public:
  const char *check(bool cyc, bool stb, bool stall, bool ack, bool err,
                    bool control_cyc, bool control_stb) const {
    if (control_stb && !control_cyc) return "dma_control_stb_without_cyc";
    if (ack && err) return "dma_master_ack_and_err";
    if ((ack || err) && (!cyc || !pending_)) return "dma_master_unsolicited_completion";
    const bool accept = cyc && stb && !stall;
    const bool complete = cyc && (ack || err);
    if (accept && complete) return "dma_master_same_edge_not_supported";
    if (accept && pending_) return "dma_master_environment_capacity";
    if (pending_ && !cyc) return "dma_master_cycle_dropped_with_pending";
    return nullptr;
  }
  void commit(bool accepted, bool completed) {
    if (completed) pending_ = false;
    else if (accepted) pending_ = true;
  }
};
}}  // namespace myfuzz::local_driver_v1
