// CPU-independent processor-memory-beat target personalities:
// MODE=0: 16-word scratch registers; MODE=1: GPIO output/direction registers;
// MODE=2: timer compare/control registers with a free-running cycle counter.
// Registers repeat every 64 bytes within the assigned address window.
module processor_register_target #(
    parameter integer MODE = 0
) (
    input logic clock, reset,
    input logic req_valid,
    output logic req_ready,
    input logic write,
    input logic [31:0] addr, wdata,
    input logic [3:0] be,
    output logic rsp_valid,
    input logic rsp_ready,
    output logic [31:0] rdata,
    output logic error
);
  logic [31:0] registers [0:15];
  logic [31:0] cycles;
  integer index, lane;
  assign req_ready = reset && !rsp_valid;
  always_ff @(posedge clock or negedge reset) begin
    if (!reset) begin
      for (index=0; index<16; index=index+1) registers[index] <= 0;
      cycles <= 0;
      rsp_valid <= 0;
      rdata <= 0;
      error <= 0;
    end else begin
      cycles <= cycles + 1;
      if (rsp_valid && rsp_ready) rsp_valid <= 0;
      if (req_valid && req_ready) begin
        rsp_valid <= 1;
        error <= |addr[1:0];
        rdata <= 0;
        if (addr[1:0] == 0) begin
          if (MODE == 2 && addr[5:2] == 2) rdata <= cycles;
          else if (MODE == 1 && addr[5:2] == 2)
            rdata <= registers[0] & registers[1];
          else rdata <= registers[addr[5:2]];
          if (write && !(MODE != 0 && addr[5:2] == 2))
            for (lane=0; lane<4; lane=lane+1)
              if (be[lane]) registers[addr[5:2]][lane*8 +: 8] <= wdata[lane*8 +: 8];
        end
      end
    end
  end
endmodule
