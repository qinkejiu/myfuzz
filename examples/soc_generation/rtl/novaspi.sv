// novaspi: a first-time input MMIO SPI master (APB4 slave, mode 0..3).
//
// This is a *new* example peripheral: the example set had no SPI component at
// all, so the generic external SPI peer model
// (src/myfuzz/protocols/rtl/soc_spi_peer.sv) had nothing to talk to.  The
// component is the master: it drives sck_o, cs_o and mosi_o, and samples miso_i.
//
// Register map (byte offsets inside the declared window):
//   0x00 CTRL       rw   bit0 start (write 1 starts a transfer when idle),
//                        bit1 irq-enable
//   0x04 STATUS     ro   bit0 busy, bit1 rx-valid, bit2 done (sticky until the
//                        received byte is read)
//   0x08 TXDATA     wo   the byte the next transfer shifts out
//   0x0c RXDATA     ro   the byte the transfer assembled (read clears rx-valid)
//   0x10 IRQ_STATUS rw1c bit0 transfer-done
//
// Timing, and why it is declared per cycle
//   SCK_HALF_DIV is the number of clk_i cycles each sck_o level is held, so the
//   peer model (which oversamples sck_o with clk_i) needs it to be at least two:
//   it reacts one clk_i cycle after it sees an edge, and the master samples
//   miso_i on the second cycle of the level.  CS_SETUP is the number of clk_i
//   cycles cs_o is asserted before the first leading edge, and CS_HOLD the
//   number after the last one; the peer needs at least one cycle in each state,
//   and a CPHA=0 selection needs its first bit presented before that sample.
//
// Mode semantics (identical to the peer model's):
//   CPOL selects the idle sck_o level and therefore which edge is the leading
//   one.  With CPHA=0 the master presents the first bit when cs_o is asserted and
//   changes it on every trailing edge, and samples miso_i on the leading edges;
//   with CPHA=1 it presents the first bit on the first leading edge and changes
//   it on every leading edge, and samples miso_i on the trailing edges.  The
//   byte travels most significant bit first in both directions.
module novaspi #(
    parameter integer ADDR_WIDTH = 12,
    parameter integer DATA_WIDTH = 32,   // APB data width
    parameter integer BITS = 8,          // bits per transferred byte, 1..8
    parameter integer CPOL = 0,          // idle sck_o level, 0 or 1
    parameter integer CPHA = 0,          // sample/shift edge selection, 0 or 1
    parameter integer SCK_HALF_DIV = 4,  // clk_i cycles per sck_o level, >= 2
    parameter integer CS_SETUP = 2,      // clk_i cycles cs_o low before the first edge
    parameter integer CS_HOLD = 2        // clk_i cycles cs_o low after the last edge
) (
    input  logic                    clk_i,
    input  logic                    rst_ni,

    // APB4 slave interface.
    input  logic [ADDR_WIDTH-1:0]   paddr_i,
    input  logic                    psel_i,
    input  logic                    penable_i,
    input  logic                    pwrite_i,
    input  logic [DATA_WIDTH-1:0]   pwdata_i,
    input  logic [DATA_WIDTH/8-1:0] pstrb_i,
    output logic                    pready_o,
    output logic [DATA_WIDTH-1:0]   prdata_o,
    output logic                    pslverr_o,

    // SPI master pins.
    output logic                    spi_sck_o,
    output logic                    spi_cs_o,   // active low
    output logic                    spi_mosi_o,
    input  logic                    spi_miso_i,

    // Level interrupt source.
    output logic                    irq_o
);
    localparam logic [7:0] OFF_CTRL       = 8'h00;
    localparam logic [7:0] OFF_STATUS     = 8'h04;
    localparam logic [7:0] OFF_TXDATA     = 8'h08;
    localparam logic [7:0] OFF_RXDATA     = 8'h0c;
    localparam logic [7:0] OFF_IRQ_STATUS = 8'h10;

    localparam logic SCK_IDLE   = (CPOL == 0) ? 1'b0 : 1'b1;
    localparam logic SCK_ACTIVE = ~SCK_IDLE;

    localparam logic [2:0] ST_IDLE       = 3'd0;  // cs_o high, no transfer
    localparam logic [2:0] ST_SETUP      = 3'd1;  // cs_o low, before the first edge
    localparam logic [2:0] ST_LEVEL      = 3'd2;  // sck_o at its active level
    localparam logic [2:0] ST_IDLE_LEVEL = 3'd3;  // sck_o at its idle level
    localparam logic [2:0] ST_HOLD       = 3'd4;  // cs_o low, after the last edge

    logic [7:0]      ctrl_q;
    logic [7:0]      irq_status_q;
    logic [2:0]      state_q;
    integer          count_q;
    integer          bit_q;
    logic [BITS-1:0] tx_data_q;
    logic [BITS-1:0] rx_shift_q;
    logic [BITS-1:0] rx_data_q;
    logic            rx_valid_q;
    logic            done_q;

    initial begin
        if ((BITS < 1) || (BITS > 8) || ((CPOL != 0) && (CPOL != 1)) ||
            ((CPHA != 0) && (CPHA != 1)) || (SCK_HALF_DIV < 2) ||
            (CS_SETUP < 1) || (CS_HOLD < 1) || (DATA_WIDTH < 8) || (ADDR_WIDTH < 1))
            $fatal(1, "invalid novaspi parameters");
    end

    wire access = psel_i && penable_i && pready_o;
    wire [7:0] offset = paddr_i[7:0];
    wire busy = (state_q != ST_IDLE);
    wire start = access && pwrite_i && (offset == OFF_CTRL) && pstrb_i[0] &&
                 pwdata_i[0] && !busy;

    assign pready_o  = 1'b1;
    assign spi_cs_o  = (state_q == ST_IDLE) ? 1'b1 : 1'b0;
    assign spi_sck_o = (state_q == ST_LEVEL) ? SCK_ACTIVE : SCK_IDLE;
    assign irq_o     = (irq_status_q != 8'h00) && ctrl_q[1];

    always_comb begin
        prdata_o  = {DATA_WIDTH{1'b0}};
        pslverr_o = 1'b0;
        if (access && !pwrite_i) begin
            case (offset)
                OFF_CTRL:   prdata_o[1:0] = {ctrl_q[1], busy};
                OFF_STATUS: prdata_o[2:0] = {done_q, rx_valid_q, busy};
                OFF_RXDATA: prdata_o[BITS-1:0] = rx_data_q;
                OFF_IRQ_STATUS: prdata_o[0] = irq_status_q[0];
                default:    pslverr_o = 1'b1;
            endcase
        end else if (access && pwrite_i) begin
            case (offset)
                OFF_CTRL, OFF_TXDATA, OFF_IRQ_STATUS: pslverr_o = 1'b0;
                default: pslverr_o = 1'b1;
            endcase
        end
    end

    // The bit the frame assigns to one index, most significant bit first.
    function automatic logic bit_value(input integer index);
        begin
            if ((index >= 0) && (index < BITS))
                bit_value = tx_data_q[BITS-1-index];
            else
                bit_value = 1'b0;
        end
    endfunction

    wire first_leading_edge = (state_q == ST_SETUP) && (count_q == CS_SETUP - 1);
    wire leading_edge_now = first_leading_edge ||
                            ((state_q == ST_IDLE_LEVEL) &&
                             (count_q == SCK_HALF_DIV - 1));
    wire trailing_edge_now = (state_q == ST_LEVEL) && (count_q == SCK_HALF_DIV - 1);

    // ------------------------------------------------------------------
    // Register file and transfer engine.
    // ------------------------------------------------------------------
    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            ctrl_q      <= 8'h00;
            irq_status_q <= 8'h00;
            state_q     <= ST_IDLE;
            count_q     <= 0;
            bit_q       <= 0;
            tx_data_q   <= {BITS{1'b0}};
            rx_shift_q  <= {BITS{1'b0}};
            rx_data_q   <= {BITS{1'b0}};
            rx_valid_q  <= 1'b0;
            done_q      <= 1'b0;
        end else begin
            if (access && pwrite_i) begin
                case (offset)
                    OFF_CTRL: begin
                        if (pstrb_i[0])
                            ctrl_q[1] <= pwdata_i[1];
                    end
                    OFF_TXDATA: begin
                        tx_data_q <= pwdata_i[BITS-1:0];
                    end
                    OFF_IRQ_STATUS: begin
                        irq_status_q[0] <= irq_status_q[0] & ~pwdata_i[0];
                    end
                    default: begin end
                endcase
            end
            if (access && !pwrite_i && (offset == OFF_RXDATA)) begin
                rx_valid_q <= 1'b0;
                done_q     <= 1'b0;
                irq_status_q[0] <= 1'b0;
            end

            case (state_q)
                ST_IDLE: begin
                    if (start) begin
                        state_q    <= ST_SETUP;
                        count_q    <= 0;
                        bit_q      <= 0;
                        rx_shift_q <= {BITS{1'b0}};
                        done_q     <= 1'b0;
                    end
                end
                ST_SETUP: begin
                    // cs_o has been low since the start edge; the first leading
                    // edge comes after CS_SETUP full clk_i cycles.
                    if (count_q == CS_SETUP - 1) begin
                        state_q <= ST_LEVEL;
                        count_q <= 0;
                    end else begin
                        count_q <= count_q + 1;
                    end
                end
                ST_LEVEL: begin
                    // The second cycle of the level is the sample point: the peer
                    // reacts one clk_i cycle after it sees the edge, so the bit it
                    // presents is stable from then on.
                    if (count_q == 1)
                        rx_shift_q[BITS-1-bit_q] <= spi_miso_i;
                    if (count_q == SCK_HALF_DIV - 1) begin
                        state_q <= ST_IDLE_LEVEL;
                        count_q <= 0;
                    end else begin
                        count_q <= count_q + 1;
                    end
                end
                ST_IDLE_LEVEL: begin
                    if (count_q == SCK_HALF_DIV - 1) begin
                        if (bit_q == BITS - 1) begin
                            state_q    <= ST_HOLD;
                            count_q    <= 0;
                            rx_data_q  <= rx_shift_q;
                            rx_valid_q <= 1'b1;
                            done_q     <= 1'b1;
                            irq_status_q[0] <= 1'b1;
                        end else begin
                            state_q <= ST_LEVEL;
                            count_q <= 0;
                            bit_q   <= bit_q + 1;
                        end
                    end else begin
                        count_q <= count_q + 1;
                    end
                end
                default: begin
                    // ST_HOLD: cs_o stays asserted for CS_HOLD full cycles after
                    // the last edge, then the selection ends.
                    if (count_q == CS_HOLD - 1) begin
                        state_q <= ST_IDLE;
                        count_q <= 0;
                    end else begin
                        count_q <= count_q + 1;
                    end
                end
            endcase
        end
    end

    // mosi_o is registered on the edge the mode assigns to the master: the
    // trailing edge with CPHA=0 (the first bit is presented when cs_o is
    // asserted) and the leading edge with CPHA=1 (the first bit appears on the
    // first leading edge).  Outside a transfer the pin reads 0.
    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            spi_mosi_o <= 1'b0;
        end else if (start) begin
            // The transfer starts on this edge; the first bit is presented with
            // it, before the first leading edge in either mode.
            spi_mosi_o <= tx_data_q[BITS-1];
        end else if (state_q == ST_IDLE) begin
            spi_mosi_o <= 1'b0;
        end else if (first_leading_edge && (CPHA == 1)) begin
            // The first leading edge presents the first bit itself: with CPHA=1
            // nothing the master drove before it is sampled.
            spi_mosi_o <= bit_value(bit_q);
        end else if (leading_edge_now && (CPHA == 1)) begin
            spi_mosi_o <= bit_value(bit_q + 1);
        end else if (trailing_edge_now && (CPHA == 0)) begin
            spi_mosi_o <= bit_value(bit_q + 1);
        end
    end
endmodule
