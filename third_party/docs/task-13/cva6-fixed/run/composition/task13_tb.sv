`timescale 1ns/1ps
module tb;
  logic clock = 1'b0;
  logic reset_n = 1'b0;
  integer unsigned cycles = 0;
  integer unsigned fetches = 0;
  integer unsigned progress = 0;
  integer unsigned completions = 0;
  integer unsigned illegal_or_trap_records = 0;
  logic [63:0] previous_fetch = '1;
  logic pass_seen = 1'b0;
  logic first_fetch_checked = 1'b0;
  logic commit_seen = 1'b0;
  always #1 clock = ~clock;

  generic_composition_top dut (
    .p_383812aaf51f5c02(1'b0),
    .p_4cd92fc9a17d34ce(64'h0),
    .p_75d018274eec347f(2'b0),
    .p_76a7e203dba8986e(clock),
    .p_98965e3be3553707(reset_n),
    .p_bb4e1f746b3702c1(1'b0),
    .p_d845d6b234ff56a9(1'b0),
    .p_e036cb8b170a5306(64'h80)
  );

  always @(posedge clock) begin
    cycles <= cycles + 1;
    if (reset_n && dut.source_e7cde6a4ffc55876[1] &&
        dut.source_07a9bde03ff39377[208])
      $display("AXI_AR cycle=%0d addr=%h len=%0d size=%0d burst=%0d",
               cycles, dut.source_e7cde6a4ffc55876[158:95],
               dut.source_e7cde6a4ffc55876[94:87],
               dut.source_e7cde6a4ffc55876[86:84],
               dut.source_e7cde6a4ffc55876[83:82]);
    if (reset_n && dut.backend_target_req_valid && dut.backend_target_req_ready) begin
      $display("BACKEND_REQ cycle=%0d write=%0d addr=%h data=%h be=%h",
               cycles, dut.backend_target_write, dut.backend_target_addr,
               dut.backend_target_wdata, dut.backend_target_be);
      if (!dut.backend_target_write) begin
        fetches <= fetches + 1;
        if (dut.backend_target_addr != previous_fetch) begin
          progress <= progress + 1;
          previous_fetch <= dut.backend_target_addr;
        end
      end else if (dut.backend_target_addr == 64'h400 &&
                   dut.backend_target_wdata[31:0] == 32'h600dcafe) begin
        pass_seen <= 1'b1;
      end
    end
    if (reset_n && dut.backend_target_rsp_valid && dut.backend_target_rsp_ready)
      begin
        completions <= completions + 1;
        $display("BACKEND_RSP cycle=%0d data=%h error=%0d",
                 cycles, dut.backend_target_rdata, dut.backend_target_error);
        if (!first_fetch_checked) begin
          if (dut.backend_target_addr != 64'h80 ||
              dut.backend_target_rdata != 64'h600dd33740000293 ||
              dut.backend_target_error)
            $fatal(1, "initial fetch mismatch addr=%h data=%h error=%0d",
                   dut.backend_target_addr, dut.backend_target_rdata,
                   dut.backend_target_error);
          first_fetch_checked <= 1'b1;
          $display("BOOT_FETCH addr=%h data=%h",
                   dut.backend_target_addr, dut.backend_target_rdata);
        end
      end
    if (reset_n && |dut.u_4fc0e2ef899df534.commit_ack_commit_id) begin
      commit_seen <= 1'b1;
      $display("COMMIT cycle=%0d ack=%b pc0=%h pc1=%h",
               cycles, dut.u_4fc0e2ef899df534.commit_ack_commit_id,
               dut.u_4fc0e2ef899df534.commit_instr_id_commit[0].pc,
               dut.u_4fc0e2ef899df534.commit_instr_id_commit[1].pc);
    end
    if (pass_seen && first_fetch_checked && commit_seen) begin
      $display("EXEC reset=1 fetches=%0d progress=%0d completions=%0d pass=1 cycles=%0d illegal_or_trap_records=%0d exit=pass", fetches, progress, completions, cycles, illegal_or_trap_records);
      $finish;
    end
    if (cycles >= 2000) begin
      $display("EXEC reset=%0d fetches=%0d progress=%0d completions=%0d pass=%0d cycles=%0d exit=timeout", reset_n, fetches, progress, completions, pass_seen, cycles);
      $fatal(1, "execution timeout");
    end
  end
  initial begin
    repeat (10) @(negedge clock);
    reset_n = 1'b1;
  end
endmodule
