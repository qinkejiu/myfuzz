// novauart: a first-time input MMIO UART peripheral (APB4 slave, level IRQ).
//
// Register map (byte offsets inside the declared window):
//   0x00 CTRL       rw   bit0 enable, bit1 irq-enable
//   0x04 STATUS     ro   bit0 rx-valid, bit1 tx-ready
//   0x08 TXDATA     wo   write transmits one byte (write side effect)
//   0x0c RXDATA     ro   read pops the receive holding register (read clears)
//   0x10 IRQ_STATUS rw1c bit0 rx-valid interrupt cause
module novauart #(
    parameter integer ADDR_WIDTH = 12,
    parameter integer DATA_WIDTH = 32
) (
    input  logic                        clk_i,
    input  logic                        rst_ni,

    // APB4 slave interface.
    input  logic [ADDR_WIDTH-1:0]       paddr_i,
    input  logic                        psel_i,
    input  logic                        penable_i,
    input  logic                        pwrite_i,
    input  logic [DATA_WIDTH-1:0]       pwdata_i,
    input  logic [DATA_WIDTH/8-1:0]     pstrb_i,
    output logic                        pready_o,
    output logic [DATA_WIDTH-1:0]       prdata_o,
    output logic                        pslverr_o,

    // External pins.
    input  logic                        uart_rx_i,
    output logic                        uart_tx_o,

    // Level interrupt source.
    output logic                        irq_o
);
    localparam logic [7:0] OFF_CTRL       = 8'h00;
    localparam logic [7:0] OFF_STATUS     = 8'h04;
    localparam logic [7:0] OFF_TXDATA     = 8'h08;
    localparam logic [7:0] OFF_RXDATA     = 8'h0c;
    localparam logic [7:0] OFF_IRQ_STATUS = 8'h10;

    logic [7:0] ctrl_q;
    logic [7:0] tx_shift_q;
    logic [7:0] rx_hold_q;
    logic       rx_valid_q;
    logic       irq_pending_q;

    wire access = psel_i && penable_i && pready_o;
    wire [7:0] offset = paddr_i[7:0];

    assign pready_o   = 1'b1;
    assign uart_tx_o  = tx_shift_q[0];
    assign irq_o      = irq_pending_q && ctrl_q[1];

    always_comb begin
        prdata_o  = {DATA_WIDTH{1'b0}};
        pslverr_o = 1'b0;
        if (access && !pwrite_i) begin
            case (offset)
                OFF_CTRL:       prdata_o[7:0] = ctrl_q;
                OFF_STATUS:     prdata_o[1:0] = {~rx_hold_q[7], 1'b1};
                OFF_RXDATA:     prdata_o[7:0] = rx_hold_q;
                OFF_IRQ_STATUS: prdata_o[0]   = irq_pending_q;
                default:        pslverr_o     = 1'b1;
            endcase
        end else if (access && pwrite_i) begin
            case (offset)
                OFF_CTRL,
                OFF_TXDATA,
                OFF_IRQ_STATUS: pslverr_o = 1'b0;
                default:        pslverr_o = 1'b1;
            endcase
        end
    end

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            ctrl_q        <= 8'h00;
            tx_shift_q    <= 8'h00;
            rx_hold_q     <= 8'h00;
            rx_valid_q    <= 1'b0;
            irq_pending_q <= 1'b0;
        end else begin
            if (access && pwrite_i) begin
                case (offset)
                    OFF_CTRL: begin
                        ctrl_q <= pwdata_i[7:0] & {8{|pstrb_i[0]}};
                    end
                    OFF_TXDATA: begin
                        if (pstrb_i[0]) begin
                            tx_shift_q <= pwdata_i[7:0];
                        end
                    end
                    OFF_IRQ_STATUS: begin
                        irq_pending_q <= irq_pending_q & ~pwdata_i[0];
                    end
                    default: begin end
                endcase
            end
            if (access && !pwrite_i && (offset == OFF_RXDATA)) begin
                rx_valid_q <= 1'b0;
            end
            if (uart_rx_i === 1'b0 && !rx_valid_q) begin
                rx_hold_q     <= 8'h55;
                rx_valid_q    <= 1'b1;
                irq_pending_q <= 1'b1;
            end
        end
    end
endmodule
