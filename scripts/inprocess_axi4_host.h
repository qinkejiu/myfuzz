#pragma once

// Host-side link that drives the packed AXI4 CPU model through the repository's
// existing `axi4_processor_memory_adapter` RTL.
//
// The CPU is the generated packed CVA6 runtime model (`Vlocal_runtime_processor`,
// one `processor.memory.unified` AXI4 master for I-cache and D-cache).  The
// adapter is the repository's CPU-side AXI4 -> single-beat adapter
// (src/myfuzz/protocols/rtl/axi4_processor_memory_adapter.sv) elaborated with
// ADDRESS_WIDTH=64, DATA_WIDTH=64, ID_WIDTH=4, USER_WIDTH=64.  This header owns
// only the wiring: it drives the CPU's AXI4 target inputs from the adapter and
// the adapter's AXI4 master inputs from the CPU, settles the combinational
// feedback between the two models, samples every channel handshake once per
// clock, and hands the adapter's one-outstanding beat face to a caller-provided
// callback.  It does not own RAM, an address map, or any channel state machine:
// those stay in the caller (the native probe or the unified host).
//
// Identity is the pinned configuration's own declaration, not an address guess:
// the write-through AXI adapter arbitrates the I-cache as request 0 and decodes
// return id 0 as the I-cache (core/cache_subsystem/wt_axi_adapter.sv), which is
// what scripts/inprocess_axi4_identity.h records.  Every accepted AR/R beat is
// classified from the ID it really carried; an undeclared identity classifies as
// Unknown and never as a fetch.
//
// 64-bit beats vs a 32-bit-word host RAM: the adapter's beat face is 64 bits and
// its WSTRB lanes are relative to the 8-byte-aligned address.  split_beat() turns
// one beat into up to two 32-bit word accesses (low word = lanes 0..3 at
// address&~7, high word = lanes 4..7 at (address&~7)+4) and join_beat_read() puts two
// 32-bit words back into the adapter's 64-bit rsp_rdata, so a caller whose RAM is
// word-addressed (scripts/inprocess_memory.h Memory) serves the lane pattern the
// CPU really emitted instead of inventing a width.
//
// One clock cycle is:
//   link.begin_tick();   // clk low, 3-pass settle, sample, run the beat service
//   ... optional explicit answer through beat_request()/beat_response() ...
//   link.end_tick();     // rising edge, falling edge, tick++, carry the answer
// `tick()` is begin_tick()+end_tick() and needs an installed beat service.
//
// The request handshake is a pre-edge fact: req_valid_o and req_ready_i are both
// high in the low phase before the rising edge that accepts the beat.  That
// handshake must therefore stay asserted *through* that edge, and only the
// response may be driven afterwards, in the next low phase, when the adapter is
// in WRITE_RESPONSE/READ_RESPONSE and exposes rsp_ready_o.  Deasserting
// req_ready_i in the same low phase as the capture (the obvious "I already have
// the beat, stop asking" move) leaves the adapter in its REQUEST state forever:
// it never reaches the response state, rsp_ready_o never rises, and the host
// waits for a response that cannot come.  That deadlock is exactly what a first
// CVA6 boot fetch looked like: two beats served, then silence.
//
// The generated wrapper's environment pins (irq_i, time_irq_i) default to low
// through set_irq(false, false); F5 is out of scope on this path and no IRQ is
// invented here.
//
// Retirement observation is a third, optional model rather than part of this
// link: the packed AXI4 CPU exports its RVFI probe bundle as one flat vector,
// and the pinned scoreboard that turns it into RVFI instruction records
// (core/cva6_rvfi.sv, not in the core filelist) is Verilated beside the run.
// attach_probe_adapter() carries the vector across in every low phase and clocks
// that model on this link's single rising edge, so it observes exactly the probe
// bits the CPU presented.  A build without it simply leaves the sink unattached;
// nothing here invents a retirement.

#include "Vaxi4_processor_memory_adapter.h"
#include "Vlocal_runtime_processor.h"

#include <cstdint>

#include "inprocess_axi4_identity.h"

namespace myfuzz {
namespace axi4 {

// One adapter beat, exactly the adapter's req_* face.  `be` is the 8-lane byte
// enable of the aligned 8-byte word (WSTRB for a write, the ARSIZE/ARADDR lane
// pattern for a read).
struct BeatRequest {
  bool write = false;
  std::uint64_t address = 0;
  std::uint64_t wdata = 0;
  unsigned be = 0;
};

// One adapter response.  The adapter's rsp_rdata_i is DATA_WIDTH=64 bits, so the
// data is 64-bit even when a 32-bit-word host RAM produced it as two words.
struct BeatResponse {
  std::uint64_t rdata = 0;
  bool error = false;
};

// One 32-bit word access derived from a 64-bit beat: the shape a word-addressed
// host RAM needs.  `be` is the 4-bit byte enable inside this word.
struct WordAccess {
  std::uint64_t address = 0;
  std::uint32_t value = 0;  // write payload (0 for a read)
  unsigned be = 0;
};

struct ArBeat {
  bool valid = false;
  std::uint64_t tick = 0;
  unsigned id = 0;
  std::uint64_t address = 0;
  unsigned len = 0, size = 0, burst = 0, prot = 0, lock = 0;
  std::uint64_t user = 0;
  Axi4CpuIdentity::Kind kind = Axi4CpuIdentity::Unknown;
};

struct RBeat {
  bool valid = false;
  std::uint64_t tick = 0;
  unsigned id = 0;
  std::uint64_t data = 0;
  unsigned resp = 0, last = 0;
  Axi4CpuIdentity::Kind kind = Axi4CpuIdentity::Unknown;
};

struct AwBeat {
  bool valid = false;
  std::uint64_t tick = 0;
  unsigned id = 0;
  std::uint64_t address = 0;
  unsigned len = 0, size = 0, burst = 0;
};

struct WBeat {
  bool valid = false;
  std::uint64_t tick = 0;
  std::uint64_t data = 0;
  unsigned strobe = 0;
  bool last = false;
};

struct BBeat {
  bool valid = false;
  std::uint64_t tick = 0;
  unsigned id = 0;
  unsigned resp = 0;
};

// One sampled clock of every AXI4 channel plus the adapter beat face.
struct Observation {
  std::uint64_t tick = 0;
  ArBeat ar;
  RBeat r;
  AwBeat aw;
  WBeat w;
  BBeat b;
  bool beat_request = false;
  bool beat_response = false;
  BeatRequest beat;
};

// Adapter-side beat traffic.  These are handshakes the two models really made,
// not beats a state machine expected.
struct Traffic {
  unsigned long long requests = 0;
  unsigned long long reads = 0;
  unsigned long long writes = 0;
  unsigned long long responses = 0;
  unsigned long long errors = 0;
  unsigned long long full_strobe = 0;
  unsigned long long partial_strobe = 0;
};

class CpuLink {
 public:
  // Services one adapter beat from the caller's RAM/address routing.  Returning
  // false leaves the beat unanswered (the adapter keeps waiting in its response
  // state); returning true is the whole answer.
  using BeatService = bool (*)(void *context, const BeatRequest &request,
                               BeatResponse &response);

  CpuLink(Vlocal_runtime_processor &cpu, Vaxi4_processor_memory_adapter &adapter);

  // Identity declaration; the default is the pinned CVA6 packed map (ARID 0 /
  // RID 0 are the I-cache).
  void set_identity(const Axi4CpuIdentity &identity) { identity_ = identity; }
  const Axi4CpuIdentity &identity() const { return identity_; }

  void set_beat_service(BeatService service, void *context) {
    service_ = service;
    service_context_ = context;
  }
  void clear_beat_service() {
    service_ = nullptr;
    service_context_ = nullptr;
  }

  // Environment pins of the generated runtime wrapper.  Both default to low so
  // no X reaches the CPU; the unified host may raise them only when it has a
  // declared source (F5 is not claimed by this path).
  void set_irq(bool irq, bool timer_irq) {
    cpu_.rt_lh_p_7_0_0 = irq ? 1 : 0;        // irq_i, machine external
    cpu_.rt_lh_p_12_0_0 = timer_irq ? 1 : 0;  // time_irq_i, machine timer
  }

  // --- clock, reset, combinational convergence ------------------------------
  void set_clock(bool level);
  // reset=true drives cpu.reset=1 and adapter.rst_ni=0.  Any half-finished beat
  // is dropped, because reset clears the adapter's channel state.
  void set_reset(bool reset);
  void drive();    // one pass: CPU outputs -> adapter, adapter outputs -> CPU
  void settle();   // three passes: the combinational feedback between the models
  void clock_edge();  // clk high eval, clk low eval; does not sample or count

  // --- one tick --------------------------------------------------------------
  void begin_tick();  // clk low, settle, sample, capture/service the beat
  void end_tick();    // clock edge, tick++, carry the answer, settle the face
  void tick() {       // convenience for a caller that installed a beat service
    begin_tick();
    end_tick();
  }

  // --- probe-bundle adapter (optional) ---------------------------------------
  // The packed AXI4 CPU exports its RVFI probe bundle as one flat top-level
  // vector.  The pinned scoreboard that turns that bundle into RVFI instruction
  // records (core/cva6_rvfi.sv) is not in the core filelist, so it is Verilated
  // as a second model beside this one and attached here.  This link carries the
  // vector across in every low phase and clocks the adapter on the same rising
  // edge as the CPU and the AXI4 adapter, so the scoreboard sees exactly the
  // probe bits the CPU presented at that edge.  Nothing else is inferred: the
  // adapter is a pass-through of one real port and its own clock.
  struct ProbeAdapter {
    void *context = nullptr;
    const std::uint32_t *source = nullptr;  // the CPU model's probe-bundle words
    unsigned words = 0;
    // Copy `words` probe words into the adapter's input port and evaluate it.
    void (*drive)(void *, const std::uint32_t *, unsigned) = nullptr;
    // Drive the adapter's reset input.
    void (*reset)(void *, bool) = nullptr;
    // Set the adapter's clock level and evaluate it.
    void (*clock)(void *, bool) = nullptr;
  };
  void attach_probe_adapter(const ProbeAdapter &adapter) { probe_ = adapter; }
  // The reset level this link is currently driving (CPU and adapter alike), so
  // an attached model can be reset with the same value.
  bool reset_level() const { return reset_; }

  // --- adapter beat face -----------------------------------------------------
  // True while a captured beat request has not been answered yet.  The request
  // stays available across ticks until beat_response() answers it.
  bool beat_request(BeatRequest &out) const;
  void beat_response(const BeatResponse &response);

  // True while any part of one adapter beat is still in flight: the pre-edge
  // request handshake, an unanswered request, or an answer the adapter has not
  // consumed yet.  A case is not over while this is true.
  bool beat_outstanding() const {
    return request_handshaked_ || request_waiting_ || pending_;
  }
  // True between the edge that consumes the beat's answer and the edge that
  // handshakes the adapter's B or R back to the CPU.  The adapter is then in
  // WRITE_AXI_RESPONSE/READ_AXI_RESPONSE: the beat is not complete for the CPU
  // yet, even though the host has answered it.
  bool response_phase_pending() const { return response_phase_pending_; }
  // Everything one adapter beat still owes: a request, an answer, or the AXI
  // response that carries that answer back.
  bool busy() const { return beat_outstanding() || response_phase_pending_; }
  // The answer currently driven on the rsp_* face (valid only while it is
  // pending).  A caller that reports an event needs the value it handed over.
  bool response_pending() const { return pending_; }
  std::uint64_t response_rdata() const { return pending_rdata_; }
  bool response_error() const { return pending_error_; }
  bool last_beat_was_write() const { return pending_write_; }
  // True in the low phase in which this tick's beat request handshake was
  // sampled; the rising edge at the end of that tick is the accepting edge.
  bool request_handshaked() const { return request_handshaked_; }

  // --- sampled facts ---------------------------------------------------------
  const Observation &observation() const { return observation_; }
  const ArBeat &last_request() const { return last_ar_; }         // last AR
  const RBeat &last_response() const { return last_r_; }          // last R
  const AwBeat &last_write_address() const { return last_aw_; }   // last AW
  const WBeat &last_write_data() const { return last_w_; }        // last W
  const BBeat &last_write_response() const { return last_b_; }    // last B
  const Axi4ChannelCounts &counts() const { return counts_; }
  const Traffic &traffic() const { return traffic_; }
  std::uint64_t ticks() const { return tick_; }

  unsigned last_ar_id() const { return last_ar_.id; }
  unsigned last_rid() const { return last_r_.id; }
  unsigned last_bid() const { return last_b_.id; }
  Axi4CpuIdentity::Kind request_kind(unsigned arid) const {
    return identity_.request(arid, false);  // a write is never a fetch
  }
  Axi4CpuIdentity::Kind response_kind(unsigned rid) const {
    return identity_.response(rid);
  }

  // Zero the counters and the last-beat facts; tick_ keeps counting.
  void forget();

  // --- 64-bit beat <-> 32-bit word helpers -----------------------------------
  // Emits the 32-bit words one beat covers: for a write only lanes that WSTRB
  // selected (an all-zero strobe emits nothing), for a read the lane pattern the
  // adapter derived from ARSIZE/ARADDR (an empty pattern falls back to the whole
  // 8 bytes so a caller never silently reads nothing).  Returns 0..2.
  static unsigned split_beat(const BeatRequest &beat, WordAccess words[2]);
  static std::uint64_t join_beat_read(std::uint32_t low_word,
                                      std::uint32_t high_word) {
    return std::uint64_t(low_word) | (std::uint64_t(high_word) << 32);
  }
  static const char *kind_name(Axi4CpuIdentity::Kind kind);

 private:
  void sample();

  Vlocal_runtime_processor &cpu_;
  Vaxi4_processor_memory_adapter &adapter_;
  Axi4CpuIdentity identity_ = Axi4CpuIdentity::packed_instruction_ids(0, 0);
  BeatService service_ = nullptr;
  void *service_context_ = nullptr;
  ProbeAdapter probe_;   // optional probe-bundle consumer, see attach_probe_adapter
  bool reset_ = false;   // the reset level driven to the CPU and the adapter

  Observation observation_;
  ArBeat last_ar_;
  RBeat last_r_;
  AwBeat last_aw_;
  WBeat last_w_;
  BBeat last_b_;
  Axi4ChannelCounts counts_;
  Traffic traffic_;

  BeatRequest request_;         // captured, not yet answered
  bool request_handshaked_ = false;  // sampled on this low phase, edge pending
  bool request_waiting_ = false;     // captured, no answer given yet
  bool answered_ = false;            // answer given in the capture low phase
  std::uint64_t answered_rdata_ = 0;
  bool answered_error_ = false;
  bool response_phase_pending_ = false;  // B/R not handshaked to the CPU yet
  bool pending_ = false;        // response driven on rsp_*
  bool pending_write_ = false;  // direction of the response being driven
  std::uint64_t pending_rdata_ = 0;
  bool pending_error_ = false;
  std::uint64_t tick_ = 0;
};

inline CpuLink::CpuLink(Vlocal_runtime_processor &cpu,
                        Vaxi4_processor_memory_adapter &adapter)
    : cpu_(cpu), adapter_(adapter) {
  // Environment pins of the generated runtime wrapper, held low: this link does
  // not claim F5 and must not leave an X on the interrupt inputs.
  set_irq(false, false);
  cpu_.reset = 0;
  adapter_.rst_ni = 0;
  set_clock(false);
}

inline void CpuLink::set_clock(bool level) {
  cpu_.clk = level ? 1 : 0;
  adapter_.clk_i = level ? 1 : 0;
}

inline void CpuLink::set_reset(bool reset) {
  cpu_.reset = reset ? 1 : 0;
  adapter_.rst_ni = reset ? 0 : 1;
  reset_ = reset;
  // An attached probe-bundle adapter is reset with the same level as the CPU it
  // observes: it holds no state of its own that may outlive the core's.
  if (probe_.reset != nullptr) probe_.reset(probe_.context, reset);
  if (reset) {
    request_ = BeatRequest();
    request_handshaked_ = false;
    request_waiting_ = false;
    answered_ = false;
    answered_rdata_ = 0;
    answered_error_ = false;
    response_phase_pending_ = false;
    pending_ = false;
    pending_write_ = false;
    pending_rdata_ = 0;
    pending_error_ = false;
  }
}

inline void CpuLink::drive() {
  cpu_.eval();
  adapter_.awid_i = cpu_.axi_awid;
  adapter_.awaddr_i = cpu_.axi_awaddr;
  adapter_.awlen_i = cpu_.axi_awlen;
  adapter_.awsize_i = cpu_.axi_awsize;
  adapter_.awburst_i = cpu_.axi_awburst;
  adapter_.awlock_i = cpu_.axi_awlock;
  adapter_.awcache_i = cpu_.axi_awcache;
  adapter_.awprot_i = cpu_.axi_awprot;
  adapter_.awqos_i = cpu_.axi_awqos;
  adapter_.awregion_i = cpu_.axi_awregion;
  adapter_.awatop_i = cpu_.axi_awatop;
  adapter_.awuser_i = cpu_.axi_awuser;
  adapter_.awvalid_i = cpu_.axi_awvalid;
  adapter_.wdata_i = cpu_.axi_wdata;
  adapter_.wstrb_i = cpu_.axi_wstrb;
  adapter_.wlast_i = cpu_.axi_wlast;
  adapter_.wuser_i = cpu_.axi_wuser;
  adapter_.wvalid_i = cpu_.axi_wvalid;
  adapter_.bready_i = cpu_.axi_bready;
  adapter_.arid_i = cpu_.axi_arid;
  adapter_.araddr_i = cpu_.axi_araddr;
  adapter_.arlen_i = cpu_.axi_arlen;
  adapter_.arsize_i = cpu_.axi_arsize;
  adapter_.arburst_i = cpu_.axi_arburst;
  adapter_.arlock_i = cpu_.axi_arlock;
  adapter_.arcache_i = cpu_.axi_arcache;
  adapter_.arprot_i = cpu_.axi_arprot;
  adapter_.arqos_i = cpu_.axi_arqos;
  adapter_.arregion_i = cpu_.axi_arregion;
  adapter_.aruser_i = cpu_.axi_aruser;
  adapter_.arvalid_i = cpu_.axi_arvalid;
  adapter_.rready_i = cpu_.axi_rready;
  // The adapter accepts one beat at a time.  While the request handshake of
  // this low phase is still waiting for its rising edge, req_ready must stay
  // high: that edge is what moves the adapter into its response state.  Only
  // after the edge (when the answer is committed to `pending_`) may req_ready
  // drop and rsp_valid rise.
  adapter_.req_ready_i = request_handshaked_ ? 1
                         : (request_waiting_ || pending_) ? 0
                                                          : 1;
  adapter_.rsp_valid_i = pending_ ? 1 : 0;
  adapter_.rsp_rdata_i = pending_rdata_;
  adapter_.rsp_error_i = pending_error_ ? 1 : 0;
  adapter_.eval();
  cpu_.axi_awready = adapter_.awready_o;
  cpu_.axi_arready = adapter_.arready_o;
  cpu_.axi_wready = adapter_.wready_o;
  cpu_.axi_bvalid = adapter_.bvalid_o;
  cpu_.axi_bid = adapter_.bid_o;
  cpu_.axi_bresp = adapter_.bresp_o;
  cpu_.axi_buser = adapter_.buser_o;
  cpu_.axi_rvalid = adapter_.rvalid_o;
  cpu_.axi_rid = adapter_.rid_o;
  cpu_.axi_rdata = adapter_.rdata_o;
  cpu_.axi_rresp = adapter_.rresp_o;
  cpu_.axi_rlast = adapter_.rlast_o;
  cpu_.axi_ruser = adapter_.ruser_o;
  // The probe bundle is a CPU output on this same low phase; hand the adapter a
  // copy now so its rising edge sees the bits the core presented at that edge.
  if (probe_.drive != nullptr && probe_.source != nullptr)
    probe_.drive(probe_.context, probe_.source, probe_.words);
}

inline void CpuLink::settle() {
  for (unsigned pass = 0; pass < 3; ++pass) drive();
}

inline void CpuLink::clock_edge() {
  set_clock(true);
  cpu_.eval();
  adapter_.eval();
  // The probe-bundle adapter is clocked on this one edge and no other: its
  // inputs were copied in the preceding low phase, so what it registers is the
  // core's pre-edge probe bundle.
  if (probe_.clock != nullptr) probe_.clock(probe_.context, true);
  set_clock(false);
  cpu_.eval();
  adapter_.eval();
  if (probe_.clock != nullptr) probe_.clock(probe_.context, false);
}

inline void CpuLink::sample() {
  observation_ = Observation();
  observation_.tick = tick_;

  const bool ar = cpu_.axi_arvalid != 0 && adapter_.arready_o != 0;
  const bool r = adapter_.rvalid_o != 0 && cpu_.axi_rready != 0;
  const bool aw = cpu_.axi_awvalid != 0 && adapter_.awready_o != 0;
  const bool w = cpu_.axi_wvalid != 0 && adapter_.wready_o != 0;
  const bool b = adapter_.bvalid_o != 0 && cpu_.axi_bready != 0;

  if (ar) {
    ArBeat &beat = observation_.ar;
    beat.valid = true;
    beat.tick = tick_;
    beat.id = cpu_.axi_arid;
    beat.address = cpu_.axi_araddr;
    beat.len = cpu_.axi_arlen;
    beat.size = cpu_.axi_arsize;
    beat.burst = cpu_.axi_arburst;
    beat.prot = cpu_.axi_arprot;
    beat.lock = cpu_.axi_arlock;
    beat.user = cpu_.axi_aruser;
    beat.kind = identity_.request(beat.id, false);
    last_ar_ = beat;
    counts_.count_request(beat.kind);
  }
  if (r) {
    RBeat &beat = observation_.r;
    beat.valid = true;
    beat.tick = tick_;
    beat.id = adapter_.rid_o;
    beat.data = adapter_.rdata_o;
    beat.resp = adapter_.rresp_o;
    beat.last = adapter_.rlast_o;
    beat.kind = identity_.response(beat.id);
    last_r_ = beat;
    counts_.count_response(beat.kind);
  }
  if (aw) {
    AwBeat &beat = observation_.aw;
    beat.valid = true;
    beat.tick = tick_;
    beat.id = cpu_.axi_awid;
    beat.address = cpu_.axi_awaddr;
    beat.len = cpu_.axi_awlen;
    beat.size = cpu_.axi_awsize;
    beat.burst = cpu_.axi_awburst;
    last_aw_ = beat;
    ++counts_.aw;
    ++counts_.aw_data;
  }
  if (w) {
    WBeat &beat = observation_.w;
    beat.valid = true;
    beat.tick = tick_;
    beat.data = cpu_.axi_wdata;
    beat.strobe = cpu_.axi_wstrb;
    beat.last = cpu_.axi_wlast != 0;
    last_w_ = beat;
    ++counts_.w;
    ++counts_.w_data;
  }
  if (b) {
    BBeat &beat = observation_.b;
    beat.valid = true;
    beat.tick = tick_;
    beat.id = adapter_.bid_o;
    beat.resp = adapter_.bresp_o;
    last_b_ = beat;
    ++counts_.b;
    ++counts_.b_data;
  }

  observation_.beat_request = adapter_.req_valid_o != 0 && adapter_.req_ready_i != 0;
  observation_.beat_response = pending_ && adapter_.rsp_ready_o != 0;
  if (observation_.beat_request) {
    observation_.beat.write = adapter_.req_write_o != 0;
    observation_.beat.address = adapter_.req_addr_o;
    observation_.beat.wdata = adapter_.req_wdata_o;
    observation_.beat.be = unsigned(adapter_.req_be_o) & 0xffu;
  }
}

inline void CpuLink::begin_tick() {
  set_clock(false);
  settle();
  sample();
  if (!observation_.beat_request) return;

  // The beat request handshake belongs to the rising edge at the end of this
  // tick; the adapter is still in its REQUEST state until then.  The beat is
  // captured now, so the caller may answer it in this low phase, but the answer
  // is only driven after that edge (see end_tick()).
  request_ = observation_.beat;
  request_handshaked_ = true;
  request_waiting_ = true;
  ++traffic_.requests;
  if (request_.write) {
    ++traffic_.writes;
    if ((request_.be & 0xffu) == 0xffu) ++traffic_.full_strobe;
    else ++traffic_.partial_strobe;
  } else {
    ++traffic_.reads;
  }
  if (service_ != nullptr) {
    BeatResponse response;
    if (service_(service_context_, request_, response)) beat_response(response);
  }
}

inline void CpuLink::end_tick() {
  // The one rising edge of this host tick: the adapter accepts the request that
  // was sampled above (req_ready is still high) and, if this tick already
  // answered the captured beat, enters its response state ready for the answer
  // that end_tick() now commits.
  clock_edge();
  ++tick_;
  if (request_handshaked_) {
    request_handshaked_ = false;
    if (answered_) {
      pending_ = true;
      pending_write_ = request_.write;
      pending_rdata_ = answered_rdata_;
      pending_error_ = answered_error_;
      answered_ = false;
      answered_rdata_ = 0;
      answered_error_ = false;
    }
  } else if (observation_.beat_response) {
    // The answer was sampled with rsp_ready_o high: this edge consumes it and
    // the adapter moves to its AXI response state, so the beat now owes the CPU
    // one B or R handshake before the case can end.
    ++traffic_.responses;
    if (pending_error_) ++traffic_.errors;
    response_phase_pending_ = true;
    pending_ = false;
    pending_write_ = false;
    pending_rdata_ = 0;
    pending_error_ = false;
  }
  // A B or R handshake sampled in this tick's low phase is completed by this
  // edge; that ends the response phase the beat was carrying.
  if (observation_.b.valid || observation_.r.valid) response_phase_pending_ = false;
  // Present the committed answer (or the idle face) to the adapter for the next
  // low phase; the next edge is then the one that consumes it.
  drive();
}

inline bool CpuLink::beat_request(BeatRequest &out) const {
  if (!request_waiting_) return false;
  out = request_;
  return true;
}

inline void CpuLink::beat_response(const BeatResponse &response) {
  if (!request_waiting_) return;
  request_waiting_ = false;
  if (request_handshaked_) {
    // The accepting edge has not happened yet; the adapter cannot take an
    // answer until it has entered its response state, so keep the value and
    // drive it from end_tick().
    answered_ = true;
    answered_rdata_ = response.rdata;
    answered_error_ = response.error;
    return;
  }
  pending_ = true;
  pending_write_ = request_.write;
  pending_rdata_ = response.rdata;
  pending_error_ = response.error;
}

inline void CpuLink::forget() {
  response_phase_pending_ = false;
  counts_ = Axi4ChannelCounts();
  traffic_ = Traffic();
  last_ar_ = ArBeat();
  last_r_ = RBeat();
  last_aw_ = AwBeat();
  last_w_ = WBeat();
  last_b_ = BBeat();
  observation_ = Observation();
}

inline unsigned CpuLink::split_beat(const BeatRequest &beat, WordAccess words[2]) {
  const unsigned lanes = beat.be & 0xffu;
  const std::uint64_t low_address = beat.address & ~std::uint64_t(7);
  const std::uint64_t high_address = low_address + 4;
  unsigned low_be = lanes & 0x0fu;
  unsigned high_be = (lanes >> 4) & 0x0fu;
  if (lanes == 0) {
    // No lane selected: a write has nothing to do, a read still has to return a
    // deterministic 8-byte word (the CPU masks the lanes it asked for).
    if (!beat.write) {
      low_be = 0x0f;
      high_be = 0x0f;
    }
  }
  unsigned count = 0;
  if (low_be != 0) {
    words[count].address = low_address;
    words[count].value = std::uint32_t(beat.wdata & 0xffffffffu);
    words[count].be = low_be;
    ++count;
  }
  if (high_be != 0) {
    words[count].address = high_address;
    words[count].value = std::uint32_t((beat.wdata >> 32) & 0xffffffffu);
    words[count].be = high_be;
    ++count;
  }
  return count;
}

inline const char *CpuLink::kind_name(Axi4CpuIdentity::Kind kind) {
  switch (kind) {
    case Axi4CpuIdentity::Instruction:
      return "instruction";
    case Axi4CpuIdentity::Data:
      return "data";
    default:
      return "unknown";
  }
}

}  // namespace axi4
}  // namespace myfuzz
