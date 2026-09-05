module apb4_mmio_target #(
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer DATA_WIDTH = 32,
    parameter integer MAX_WAIT_CYCLES = 16
) (
    input  logic                          clk_i,
    input  logic                          rst_ni,

    input  logic [ADDRESS_WIDTH-1:0]      paddr_i,
    input  logic [2:0]                    pprot_i,
    input  logic                          psel_i,
    input  logic                          penable_i,
    input  logic                          pwrite_i,
    input  logic [DATA_WIDTH-1:0]         pwdata_i,
    input  logic [(DATA_WIDTH/8)-1:0]     pstrb_i,
    output logic                          pready_o,
    output logic [DATA_WIDTH-1:0]         prdata_o,
    output logic                          pslverr_o,

    output logic                          valid_o,
    output logic                          write_o,
    output logic [ADDRESS_WIDTH-1:0]      addr_o,
    output logic [DATA_WIDTH-1:0]         wdata_o,
    output logic [(DATA_WIDTH/8)-1:0]     be_o,
    input  logic [DATA_WIDTH-1:0]         rdata_i,
    input  logic                          ready_i,
    input  logic                          error_i
);

    logic access;

    assign access = psel_i && penable_i;
    assign valid_o = access;
    assign write_o = pwrite_i;
    assign addr_o = paddr_i;
    assign wdata_o = pwdata_i;
    assign be_o = pstrb_i;
    assign pready_o = access && ready_i;
    assign prdata_o = rdata_i;
    assign pslverr_o = access && ready_i && error_i;

endmodule
