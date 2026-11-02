// Copyright 2024 Thales DIS France SAS (cva6_rvfi.sv original author)
// Licensed under the Solderpad Hardware Licence, Version 2.0 WITH SHL-2.0.
//
// cva6_rvfi_top: the pinned CVA6's own RVFI scoreboard, wrapped as a second
// Verilated model beside a generated CVA6 runtime model.
//
// WHY THIS FILE EXISTS
//   The pinned CVA6 exports its 6974-bit RVFI probe bundle as a top-level port
//   (`output rvfi_probes_t rvfi_probes_o`, core/cva6.sv:339) whose own comment
//   says it may be left open when no monitor is attached.  A probe bundle is
//   not an instruction record: the record is produced by core/cva6_rvfi.sv,
//   which recovers the committing uop's instruction word from its own
//   issue/commit scoreboard (`mem_q[commit_pointer]`), and derives trap / intr
//   / cause from the commit stage's exception path.  Sampling the core's
//   `instruction[0]` at commit time instead would report the most recently
//   issued word, which can belong to a younger uop than the committing one.
//
//   cva6_rvfi.sv and its type packages are NOT in the core filelist
//   (core/Flist.cva6 lists only cva6_rvfi_probes.sv), so compiling it into the
//   generated harness model would add a source to a pinned closure.  Instead
//   this wrapper is Verilated as its own model and linked beside the run, the
//   same way `axi4_processor_memory_adapter` is: the host copies the probe
//   vector into rvfi_probes_i in every low phase and clocks both models on the
//   same rising edge, so the scoreboard sees exactly the probe bits the core
//   presented at that edge.
//
// TWO COMMIT LANES -> ONE RETIREMENT LANE
//   The pinned configuration has NrCommitPorts = 2 (single-issue, two commit
//   ports: cv64a6_imafdc_sv39_config_pkg.sv), so cva6_rvfi can report two
//   valid records on one clock.  The host's retirement observation is a
//   one-record-per-clock RVFI face (`rvfi_valid` plus one record, the same
//   shape the OBI/Wishbone CPUs export), so this wrapper queues the records it
//   is given and emits one per clock, oldest first.  It adds no fact: every
//   emitted record is one cva6_rvfi record, unmodified apart from the order
//   field explained below, and `retire_dropped` is sticky evidence that the
//   queue could not keep up.  A drop is a lost retirement and must never be
//   reported as a pass.
//
// THE ORDER FIELD
//   The pinned cva6_rvfi.sv never assigns `rvfi_instr_o.order` (the field is
//   declared in the `RVFI_INSTR_T` macro and then never written), so it would
//   carry no information.  The order emitted here is the core's own MINSTRET
//   (`rvfi_csr_o.instret.rdata`, the architectural retired-instruction counter
//   sampled on the same edge) plus the lane index, which is that record's index
//   in the architectural retirement sequence.  It is a real CPU counter, not a
//   host-invented sequence number.
//
// TRAP / INTERRUPT WITNESS
//   A retirement record is not enough to claim a trap: the pinned scoreboard
//   also states, per commit lane, ``trap`` (a synchronous exception the core
//   took), ``cause`` (the architectural cause code, XLEN bits), ``intr`` and
//   ``mode`` (the privilege level the instruction retired in).  Those four
//   fields are emitted with the record, unmodified.
//
//   ``intr`` is wider than one bit in the pinned source: the scoreboard
//   assigns it the constants 'b101 (asynchronous interrupt) and 'b11
//   (synchronous trap), and it clears it on the next *valid* retirement
//   (core/cva6_rvfi.sv:498-509).  It is therefore emitted as the scoreboard's
//   own XLEN-wide value, and it reads non-zero on the first retirement after an
//   asynchronous interrupt.  A synchronous trap is stated by ``trap`` plus
//   ``cause``; the host must not read ``intr`` as "this record trapped".
//
//   The CSR readback ports are the scoreboard's own registered view of the
//   core's CSRs (``rvfi_csr_o.<csr>.rdata``, core/cva6_rvfi.sv:563-568): each
//   value is the CSR as the core held it immediately before the sampled edge,
//   so the values of one sampled edge are one consistent snapshot.  Two CSRs
//   read on the same edge are therefore comparable to each other, but a value
//   on the edge that *writes* that CSR still shows the value before the write
//   (the register updates with that edge).  The trap's own cause is the
//   record's ``cause``; these readbacks are the architectural CSR state after
//   it, and the firmware's own CSR reads are the independent witness.
//
// HOST CONTRACT
//   clk_i / rst_ni are the CPU model's own clock and reset.  rvfi_probes_i is
//   driven from the model's exported rvfi_probes_o port; rvfi_probes_width_o
//   reports $bits(rvfi_probes_t) so the host can prove the two widths agree
//   instead of trusting them.

`include "rvfi_types.svh"

module cva6_rvfi_top #(
    // The width the generated harness exports.  It is checked against the
    // scoreboard's own type below; a mismatch is an elaboration error, never a
    // silent truncation.
    parameter int unsigned PROBES_WIDTH = 6974,
    // Records held while two lanes commit on one clock.  The core is
    // single-issue, so at most one record per clock can be produced on average
    // and the queue drains one per clock; depth 4 leaves margin for bursts of
    // two-lane commits without ever being reachable in steady state.
    parameter int unsigned QUEUE_DEPTH = 4
) (
    input  logic                    clk_i,
    input  logic                    rst_ni,
    input  logic [PROBES_WIDTH-1:0] rvfi_probes_i,
    // One retirement per clock, oldest first.
    output logic                    rvfi_valid,
    output logic [63:0]             rvfi_order,
    output logic [31:0]             rvfi_insn,
    output logic [63:0]             rvfi_pc_rdata,
    output logic                    rvfi_trap,
    output logic [4:0]              rvfi_rd_addr,
    output logic [63:0]             rvfi_rd_wdata,
    // Trap / interrupt witness of the same record: the commit lane's own
    // exception cause (XLEN bits), the scoreboard's ``intr`` word (see above),
    // and the privilege level the instruction retired in (2'b11 = M-mode).
    output logic [63:0]             rvfi_cause,
    output logic [63:0]             rvfi_intr,
    output logic [1:0]              rvfi_mode,
    // The scoreboard's registered CSR readback on the sampled edge.  mcause /
    // mepc / mtval / mtvec are the trap state the handler reads; mstatus is
    // emitted so the host can state the privilege/MIE facts without inferring
    // them.  Each is the CSR's own value, not a host guess.
    output logic [63:0]             rvfi_mcause,
    output logic [63:0]             rvfi_mepc,
    output logic [63:0]             rvfi_mtval,
    output logic [63:0]             rvfi_mtvec,
    output logic [63:0]             rvfi_mstatus,
    // Diagnostics: lanes the scoreboard registered on the sampled edge, whether
    // any record was lost, and the probe type's own width.
    output logic [1:0]              retire_lanes,
    output logic                    retire_dropped,
    output logic [31:0]             rvfi_probes_width_o
);

  import config_pkg::*;

  localparam config_pkg::cva6_cfg_t CVA6Cfg =
      build_config_pkg::build_config(cva6_config_pkg::cva6_cfg);

  // The RVFI record and probe types are the pinned package's own macros; the
  // testbench declares them the same way (corev_apu/tb/ariane_testharness.sv).
  localparam type rvfi_instr_t = `RVFI_INSTR_T(CVA6Cfg);
  localparam type rvfi_csr_elmt_t = `RVFI_CSR_ELMT_T(CVA6Cfg);
  localparam type rvfi_csr_t = `RVFI_CSR_T(CVA6Cfg, rvfi_csr_elmt_t);
  localparam type rvfi_probes_instr_t = `RVFI_PROBES_INSTR_T(CVA6Cfg);
  localparam type rvfi_probes_csr_t = `RVFI_PROBES_CSR_T(CVA6Cfg);
  localparam type rvfi_probes_t = struct packed {
    rvfi_probes_csr_t csr;
    rvfi_probes_instr_t instr;
  };
  localparam type rvfi_to_iti_t = `RVFI_TO_ITI_T(CVA6Cfg);

  localparam int unsigned PROBES_BITS = $bits(rvfi_probes_t);
  localparam int unsigned COMMIT_PORTS = CVA6Cfg.NrCommitPorts;

  // A width disagreement means the exported vector is not this bundle; refuse
  // the elaboration rather than reinterpreting bits.
  if (PROBES_BITS != PROBES_WIDTH) begin : g_probe_width_mismatch
    $error("cva6_rvfi_top: rvfi_probes_t is %0d bits but the port is %0d bits",
           PROBES_BITS, PROBES_WIDTH);
  end

  // This wrapper's diagnostics are two-lane shaped; the scoreboard type above
  // is generic, so state the assumption instead of relying on it.
  if (COMMIT_PORTS != 2) begin : g_commit_ports_unsupported
    $error("cva6_rvfi_top: this wrapper serialises exactly two commit lanes, got %0d",
           COMMIT_PORTS);
  end

  assign rvfi_probes_width_o = 32'(PROBES_BITS);

  rvfi_probes_t probes;
  assign probes = rvfi_probes_i;

  rvfi_instr_t [COMMIT_PORTS-1:0] rvfi_instr;
  rvfi_to_iti_t rvfi_to_iti;
  rvfi_csr_t rvfi_csr;

  cva6_rvfi #(
      .CVA6Cfg             (CVA6Cfg),
      .rvfi_instr_t        (rvfi_instr_t),
      .rvfi_csr_t          (rvfi_csr_t),
      .rvfi_probes_instr_t (rvfi_probes_instr_t),
      .rvfi_probes_csr_t   (rvfi_probes_csr_t),
      .rvfi_probes_t       (rvfi_probes_t),
      .rvfi_to_iti_t       (rvfi_to_iti_t)
  ) i_cva6_rvfi (
      .clk_i        (clk_i),
      .rst_ni       (rst_ni),
      .rvfi_probes_i(probes),
      .rvfi_instr_o (rvfi_instr),
      .rvfi_to_iti_o(rvfi_to_iti),
      .rvfi_csr_o   (rvfi_csr)
  );

  // One retirement record, exactly the fields the host's RVFI trace carries.
  typedef struct packed {
    logic [63:0] order;
    logic [63:0] pc;
    logic [63:0] rd_wdata;
    logic [63:0] cause;
    logic [63:0] intr;
    logic [31:0] insn;
    logic [4:0]  rd_addr;
    logic [1:0]  mode;
    logic        trap;
  } record_t;

  localparam int unsigned COUNT_BITS = $clog2(QUEUE_DEPTH + 2);

  record_t [QUEUE_DEPTH-1:0] queue_q;
  logic [COUNT_BITS-1:0]     count_q;
  logic                      dropped_q;
  // Exactly one record leaves the head every clock when one is present: the
  // host samples this face once per clock and consumes every valid record.
  logic [COUNT_BITS-1:0]     shift;
  // The core's architectural retirement index for the oldest committing lane.
  logic [63:0]               base_order;
  logic [1:0]                lanes_valid;

  assign lanes_valid = {rvfi_instr[1].valid, rvfi_instr[0].valid};
  assign shift = (count_q != 0) ? COUNT_BITS'(1) : COUNT_BITS'(0);
  assign base_order = 64'(rvfi_csr.instret.rdata);

  always_ff @(posedge clk_i or negedge rst_ni) begin : queue
    record_t [QUEUE_DEPTH-1:0] next_queue;
    logic [COUNT_BITS-1:0]     next_count;
    if (!rst_ni) begin
      count_q   <= '0;
      dropped_q <= 1'b0;
      for (int unsigned i = 0; i < QUEUE_DEPTH; ++i) queue_q[i] <= '0;
    end else begin
      next_count = count_q - shift;
      // Shift the queue down past the consumed record, then append the lanes the
      // scoreboard registered on this edge, oldest first.
      for (int unsigned i = 0; i < QUEUE_DEPTH; ++i) begin
        if (i + shift < QUEUE_DEPTH) next_queue[i] = queue_q[i + shift];
        else next_queue[i] = '0;
      end
      for (int unsigned lane = 0; lane < 2; ++lane) begin
        if (rvfi_instr[lane].valid) begin
          if (next_count < QUEUE_DEPTH) begin
            next_queue[next_count].order    = base_order + 64'(lane);
            next_queue[next_count].pc       = 64'(rvfi_instr[lane].pc_rdata);
            next_queue[next_count].rd_wdata = 64'(rvfi_instr[lane].rd_wdata);
            next_queue[next_count].insn     = 32'(rvfi_instr[lane].insn);
            next_queue[next_count].rd_addr  = 5'(rvfi_instr[lane].rd_addr);
            next_queue[next_count].trap     = rvfi_instr[lane].trap;
            next_queue[next_count].cause    = 64'(rvfi_instr[lane].cause);
            next_queue[next_count].intr     = 64'(rvfi_instr[lane].intr);
            next_queue[next_count].mode     = 2'(rvfi_instr[lane].mode);
            next_count = next_count + COUNT_BITS'(1);
          end else begin
            dropped_q <= 1'b1;
          end
        end
      end
      count_q <= next_count;
      queue_q <= next_queue;
    end
  end

  assign rvfi_valid     = (count_q != 0);
  assign rvfi_order     = queue_q[0].order;
  assign rvfi_insn      = queue_q[0].insn;
  assign rvfi_pc_rdata  = queue_q[0].pc;
  assign rvfi_trap      = queue_q[0].trap;
  assign rvfi_rd_addr   = queue_q[0].rd_addr;
  assign rvfi_rd_wdata  = queue_q[0].rd_wdata;
  assign rvfi_cause     = queue_q[0].cause;
  assign rvfi_intr      = queue_q[0].intr;
  assign rvfi_mode      = queue_q[0].mode;
  assign rvfi_mcause    = 64'(rvfi_csr.mcause.rdata);
  assign rvfi_mepc      = 64'(rvfi_csr.mepc.rdata);
  assign rvfi_mtval     = 64'(rvfi_csr.mtval.rdata);
  assign rvfi_mtvec     = 64'(rvfi_csr.mtvec.rdata);
  assign rvfi_mstatus   = 64'(rvfi_csr.mstatus.rdata);
  assign retire_lanes   = lanes_valid;
  assign retire_dropped = dropped_q;

endmodule
