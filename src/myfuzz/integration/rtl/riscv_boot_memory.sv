module riscv_boot_memory_32 #(
    parameter integer BASE_ADDR = 0,
    parameter integer BYTES = 4096,
    parameter integer LOAD_IMAGE = 1
) (
    input logic clock,
    input logic reset,
    input logic flush,
    input logic req_valid,
    output logic req_ready,
    input logic write,
    input logic [31:0] addr,
    input logic [31:0] wdata,
    input logic [3:0] be,
    output logic rsp_valid,
    input logic rsp_ready,
    output logic [31:0] rdata,
    output logic error
);
  logic [7:0] memory [0:BYTES-1];
  logic [7:0] initial_memory [0:BYTES-1];
  logic pending;
  integer index;
  integer init_index;
  string image_path;

  initial begin
    for (init_index = 0; init_index < BYTES; init_index = init_index + 1) initial_memory[init_index] = 8'h00;
    if (LOAD_IMAGE != 0) begin
      if (!$value$plusargs("riscv_boot_image=%s", image_path))
        $fatal(1, "missing +riscv_boot_image");
      $readmemh(image_path, initial_memory);
    end
    for (init_index = 0; init_index < BYTES; init_index = init_index + 1) memory[init_index] = initial_memory[init_index];
  end

  assign req_ready = reset && !pending && !rsp_valid;
  // Every write to ``memory`` is a *non-delayed* assignment.  The pinned RFuzz
  // tool refuses a delayed array assignment inside a for loop (BLKLOOPINIT:
  // "non-delayed is ok"), and both the reset reload and the byte-enable write
  // below are array assignments in a loop, so a clocked non-blocking form does
  // not elaborate under it at all.  ``memory`` has exactly one writer -- this
  // always_ff -- and each of these loops writes each element once, so the
  // blocking form has the same effect at the same edge.
  task automatic reload_memory();
    for (init_index = 0; init_index < BYTES; init_index = init_index + 1)
      memory[init_index] = initial_memory[init_index];
  endtask

  always_ff @(posedge clock or negedge reset) begin
    if (!reset) begin
      reload_memory();
      pending <= 1'b0;
      rsp_valid <= 1'b0;
      rdata <= '0;
      error <= 1'b0;
    end else if (flush) begin
      pending <= 1'b0;
      rsp_valid <= 1'b0;
      rdata <= '0;
      error <= 1'b0;
    end else begin
      if (rsp_valid && rsp_ready) rsp_valid <= 1'b0;
      if (req_valid && req_ready) begin
        pending <= 1'b1;
        rdata <= '0;
        if ((addr >= BASE_ADDR) && (addr - BASE_ADDR <= BYTES - 4)) begin
          error <= 1'b0;
          for (index = 0; index < 4; index = index + 1) begin
            rdata[index*8 +: 8] <= memory[(addr - BASE_ADDR) + index];
            if (write && be[index]) memory[(addr - BASE_ADDR) + index] = wdata[index*8 +: 8];
          end
        end else begin
          error <= 1'b1;
        end
      end
      if (pending && !rsp_valid) begin
        pending <= 1'b0;
        rsp_valid <= 1'b1;
      end
    end
  end
endmodule

module riscv_boot_memory_64 #(
    parameter longint BASE_ADDR = 0,
    parameter integer BYTES = 4096,
    parameter integer LOAD_IMAGE = 1
) (
    input logic clock,
    input logic reset,
    input logic flush,
    input logic req_valid,
    output logic req_ready,
    input logic write,
    input logic [63:0] addr,
    input logic [63:0] wdata,
    input logic [7:0] be,
    output logic rsp_valid,
    input logic rsp_ready,
    output logic [63:0] rdata,
    output logic error
);
  logic [7:0] memory [0:BYTES-1];
  logic [7:0] initial_memory [0:BYTES-1];
  logic pending;
  integer index;
  integer init_index;
  string image_path;

  initial begin
    for (init_index = 0; init_index < BYTES; init_index = init_index + 1) initial_memory[init_index] = 8'h00;
    if (LOAD_IMAGE != 0) begin
      if (!$value$plusargs("riscv_boot_image=%s", image_path))
        $fatal(1, "missing +riscv_boot_image");
      $readmemh(image_path, initial_memory);
    end
    for (init_index = 0; init_index < BYTES; init_index = init_index + 1) memory[init_index] = initial_memory[init_index];
  end

  assign req_ready = reset && !pending && !rsp_valid;
  // Every write to ``memory`` is a *non-delayed* assignment.  The pinned RFuzz
  // tool refuses a delayed array assignment inside a for loop (BLKLOOPINIT:
  // "non-delayed is ok"), and both the reset reload and the byte-enable write
  // below are array assignments in a loop, so a clocked non-blocking form does
  // not elaborate under it at all.  ``memory`` has exactly one writer -- this
  // always_ff -- and each of these loops writes each element once, so the
  // blocking form has the same effect at the same edge.
  task automatic reload_memory();
    for (init_index = 0; init_index < BYTES; init_index = init_index + 1)
      memory[init_index] = initial_memory[init_index];
  endtask

  always_ff @(posedge clock or negedge reset) begin
    if (!reset) begin
      reload_memory();
      pending <= 1'b0;
      rsp_valid <= 1'b0;
      rdata <= '0;
      error <= 1'b0;
    end else if (flush) begin
      pending <= 1'b0;
      rsp_valid <= 1'b0;
      rdata <= '0;
      error <= 1'b0;
    end else begin
      if (rsp_valid && rsp_ready) rsp_valid <= 1'b0;
      if (req_valid && req_ready) begin
        pending <= 1'b1;
        rdata <= '0;
        if ((addr >= BASE_ADDR) && (addr - BASE_ADDR <= BYTES - 8)) begin
          error <= 1'b0;
          for (index = 0; index < 8; index = index + 1) begin
            rdata[index*8 +: 8] <= memory[(addr - BASE_ADDR) + index];
            if (write && be[index]) memory[(addr - BASE_ADDR) + index] = wdata[index*8 +: 8];
          end
        end else begin
          error <= 1'b1;
        end
      end
      if (pending && !rsp_valid) begin
        pending <= 1'b0;
        rsp_valid <= 1'b1;
      end
    end
  end
endmodule
