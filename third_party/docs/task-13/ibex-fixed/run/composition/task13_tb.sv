module tb;
logic clock=0, reset_n=0; integer cycles=0, fetches=0, progress=0, completions=0;
logic [31:0] last_fetch=0; integer illegal_or_trap_records=0;
logic reset_released=0, pass_seen=0, first_fetch_checked=0;
always #1 clock=~clock;
generic_composition_top dut(
 .p_76a7e203dba8986e(clock),
 .p_98965e3be3553707(reset_n),
 .p_e036cb8b170a5306(32'h00000080),
 .p_4cd92fc9a17d34ce(32'h0),
 .p_88de547440c710d0(1'b0),
 .p_1675d0ea821ed0fd(1'b0),
 .p_b8a7cd262410caf5(1'b0),
 .p_ee300435f6caa83b(15'h0),
 .p_bb4e1f746b3702c1(1'b0),
 .p_6d17b9b611052f86(4'b0101),
 .p_44698aa8b04e6752(1'b1),
 .p_61aae37a0aca31e4(1'b0),
 .p_f0679b70d3982ecf(4'b0101),
 .p_b39e50b36d56f511(4'b1010),
 .p_edbf1bb5dce303cf('0),
 .p_c3bbc328aab2d3f0('0),
 .p_f77659d1ab76abfa('0),
 .p_619e912101197846('0),
 .p_48ce350cb465138b('0),
 .p_80240ac4c2da1227('0),
 .p_f81fe4356c222350('0),
 .p_771fdce65f7e4270('0),
 .p_0b3b30ccc88cc021('0),
 .p_afe51855e2886000('0),
 .p_8a541c272dc7de03('0),
 .p_75cfcb7c955f748d('0),
 .p_682f0ad4e3b9f3f9('0)
);
always @(posedge clock) if(reset_n) begin
 cycles <= cycles + 1; reset_released <= 1;
 if(dut.backend_target_req_valid && dut.backend_target_req_ready) begin
   if(!dut.backend_target_write) begin
     fetches <= fetches + 1;
     if(dut.backend_target_addr != last_fetch) begin progress <= progress + 1; last_fetch <= dut.backend_target_addr; end
   end
   if(dut.backend_target_write && dut.backend_target_addr == 32'h00000400 &&
      dut.backend_target_wdata[31:0] == 32'h600dcafe) pass_seen <= 1;
 end
 if(dut.backend_target_rsp_valid && dut.backend_target_rsp_ready) begin
   completions <= completions + 1;
   if(!first_fetch_checked) begin
     if(dut.backend_target_addr != 32'h00000080 ||
        dut.backend_target_rdata[31:0] != 32'h40000293)
       $fatal(1,"initial fetch mismatch addr=%h data=%h",dut.backend_target_addr,dut.backend_target_rdata);
     first_fetch_checked <= 1;
     $display("BOOT_FETCH addr=%h data=%h",dut.backend_target_addr,dut.backend_target_rdata[31:0]);
   end
 end
 if(pass_seen && completions > 0 && first_fetch_checked) begin
   $display("EXEC reset=%0d fetches=%0d progress=%0d completions=%0d pass=1 cycles=%0d illegal_or_trap_records=%0d exit=pass", reset_released,fetches,progress,completions,cycles,illegal_or_trap_records);
   $finish;
 end
 if(cycles >= 400) begin
   $display("EXEC reset=%0d fetches=%0d progress=%0d completions=%0d pass=%0d cycles=%0d exit=timeout", reset_released,fetches,progress,completions,pass_seen,cycles);
   $fatal(1,"execution timeout");
 end
end
initial begin repeat(5) @(negedge clock); reset_n=1; end
endmodule
