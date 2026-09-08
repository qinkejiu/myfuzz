module riscv_boot_memory_32 (
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
  localparam integer BYTES = 4096;
  logic [7:0] memory [0:4095];
  logic pending;
  integer index;
  integer init_index;
  string image_path;

  initial begin
    for (init_index = 0; init_index < BYTES; init_index = init_index + 1) memory[init_index] = 8'h00;
    if (!$value$plusargs("riscv_boot_image=%s", image_path))
      $fatal(1, "missing +riscv_boot_image");
    $readmemh(image_path, memory);
  end

  assign req_ready = reset && !pending && !rsp_valid;
  always_ff @(posedge clock or negedge reset) begin
    if (!reset) begin
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
        if (addr <= 32'd4092) begin
          error <= 1'b0;
          for (index = 0; index < 4; index = index + 1) begin
            rdata[index*8 +: 8] <= memory[addr[11:0] + index[11:0]];
            if (write && be[index]) memory[addr[11:0] + index[11:0]] <= wdata[index*8 +: 8];
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

module riscv_boot_memory_64 (
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
  localparam integer BYTES = 4096;
  logic [7:0] memory [0:4095];
  logic pending;
  integer index;
  integer init_index;
  string image_path;

  initial begin
    for (init_index = 0; init_index < BYTES; init_index = init_index + 1) memory[init_index] = 8'h00;
    if (!$value$plusargs("riscv_boot_image=%s", image_path))
      $fatal(1, "missing +riscv_boot_image");
    $readmemh(image_path, memory);
  end

  assign req_ready = reset && !pending && !rsp_valid;
  always_ff @(posedge clock or negedge reset) begin
    if (!reset) begin
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
        if (addr <= 64'd4088) begin
          error <= 1'b0;
          for (index = 0; index < 8; index = index + 1) begin
            rdata[index*8 +: 8] <= memory[addr[11:0] + index[11:0]];
            if (write && be[index]) memory[addr[11:0] + index[11:0]] <= wdata[index*8 +: 8];
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
