// novauart_link: a first-time input MMIO UART with a real serial frame engine.
//
// This is a *new* example peripheral (the existing novauart is untouched): it
// exists because the generic external peer model
// (src/myfuzz/protocols/rtl/soc_uart_peer.sv) can only be exercised by a
// component that really frames a byte.  novauart's profile says so itself - it
// declares no baud rate and its transmit pin is one register bit - so the peer
// path refuses to attach to it and this component declares the frame timing.
//
// Register map (byte offsets inside the declared window):
//   0x00 CTRL       rw   bit0 rx-enable, bit1 tx-enable, bit2 irq-enable
//   0x04 STATUS     ro   bit0 rx-valid, bit1 tx-ready, bit2 tx-busy,
//                        bit3 framing-error (sticky until IRQ_STATUS clears it)
//   0x08 TXDATA     wo   write starts one frame (write side effect)
//   0x0c RXDATA     ro   read pops the received byte (read clears rx-valid)
//   0x10 IRQ_STATUS rw1c bit0 rx-valid cause, bit1 framing-error cause
//
// Frame format, identical to the peer model's:
//   one start bit at the complement of IDLE_LEVEL, SERIAL_WIDTH data bits least
//   significant bit first, STOP_BITS stop bits at IDLE_LEVEL, every bit held for
//   exactly BAUD_DIV clk_i cycles.  The transmitter drives the start bit on the
//   edge that accepts the write; the receiver detects the start level on an idle
//   line, then samples every bit inside its period (BAUD_DIV + BAUD_DIV/2 - 1
//   edges after the start sample, then every BAUD_DIV edges), so a frame whose
//   bits are not aligned to the sampling edge is still received.
//
// Deliberately not modelled: parity, fractional baud rates, FIFOs, flow control,
// glitch filtering and every electrical property of the line.
module novauart_link #(
    parameter integer ADDR_WIDTH = 12,
    parameter integer DATA_WIDTH = 32,   // APB data width
    parameter integer SERIAL_WIDTH = 8,  // data bits per serial frame, 1..8
    parameter integer BAUD_DIV = 8,      // clk_i cycles per serial bit period
    parameter integer STOP_BITS = 1,     // stop bit periods per frame
    parameter integer IDLE_LEVEL = 1     // line level between frames, 0 or 1
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

    // External serial pins.
    input  logic                    uart_rx_i,
    output logic                    uart_tx_o,

    // Level interrupt source.
    output logic                    irq_o
);
    localparam logic [7:0] OFF_CTRL       = 8'h00;
    localparam logic [7:0] OFF_STATUS     = 8'h04;
    localparam logic [7:0] OFF_TXDATA     = 8'h08;
    localparam logic [7:0] OFF_RXDATA     = 8'h0c;
    localparam logic [7:0] OFF_IRQ_STATUS = 8'h10;

    localparam logic IDLE  = (IDLE_LEVEL == 0) ? 1'b0 : 1'b1;
    localparam logic START = ~IDLE;

    localparam integer FRAME_BITS = 1 + SERIAL_WIDTH + STOP_BITS;
    localparam integer CENTER_CYCLES = BAUD_DIV / 2;
    localparam integer FIRST_SAMPLE_WAIT = BAUD_DIV + CENTER_CYCLES - 1;

    localparam logic [1:0] RX_IDLE  = 2'd0;
    localparam logic [1:0] RX_DATA  = 2'd1;
    localparam logic [1:0] RX_STOP  = 2'd2;

    logic [7:0]  ctrl_q;
    logic [7:0]  irq_status_q;

    // Transmitter.
    logic [SERIAL_WIDTH-1:0] tx_data_q;
    integer                  tx_bit_q;
    integer                  tx_baud_q;
    logic                    tx_busy_q;
    logic                    tx_line_q;

    // Receiver.
    logic [1:0]              rx_state_q;
    integer                  rx_bit_q;
    integer                  rx_phase_q;
    logic [SERIAL_WIDTH-1:0] rx_shift_q;
    logic [SERIAL_WIDTH-1:0] rx_hold_q;
    logic                    rx_valid_q;
    logic                    framing_error_q;

    integer assemble_index;

    initial begin
        if ((SERIAL_WIDTH < 1) || (SERIAL_WIDTH > 8) || (BAUD_DIV < 1) ||
            (STOP_BITS < 1) || ((IDLE_LEVEL != 0) && (IDLE_LEVEL != 1)) ||
            (DATA_WIDTH < 8) || (ADDR_WIDTH < 1))
            $fatal(1, "invalid novauart_link parameters");
    end

    wire access = psel_i && penable_i && pready_o;
    wire [7:0] offset = paddr_i[7:0];
    wire tx_start = access && pwrite_i && (offset == OFF_TXDATA) && pstrb_i[0] &&
                    ctrl_q[1] && !tx_busy_q;
    wire rx_start = (rx_state_q == RX_IDLE) && (uart_rx_i == START) && ctrl_q[0];

    assign pready_o  = 1'b1;
    assign uart_tx_o = tx_line_q;
    assign irq_o     = (irq_status_q != 8'h00) && ctrl_q[2];

    always_comb begin
        prdata_o  = {DATA_WIDTH{1'b0}};
        pslverr_o = 1'b0;
        if (access && !pwrite_i) begin
            case (offset)
                OFF_CTRL:   prdata_o[7:0] = ctrl_q;
                OFF_STATUS: prdata_o[3:0] = {framing_error_q, tx_busy_q, ~tx_busy_q,
                                             rx_valid_q};
                OFF_RXDATA: prdata_o[SERIAL_WIDTH-1:0] = rx_hold_q;
                OFF_IRQ_STATUS: prdata_o[1:0] = irq_status_q[1:0];
                default:    pslverr_o = 1'b1;
            endcase
        end else if (access && pwrite_i) begin
            case (offset)
                OFF_CTRL, OFF_TXDATA, OFF_IRQ_STATUS: pslverr_o = 1'b0;
                default: pslverr_o = 1'b1;
            endcase
        end
    end

    // The level the transmitter drives for a bit index of the frame it is sending.
    function automatic logic frame_level(input integer index);
        begin
            if (index == 0)
                frame_level = START;
            else if (index <= SERIAL_WIDTH)
                frame_level = tx_data_q[index-1];
            else
                frame_level = IDLE;
        end
    endfunction

    // The bits sampled so far with the bit sampled in this cycle placed at the
    // position the frame assigns to it (least significant bit first).
    function automatic [SERIAL_WIDTH-1:0] with_sample(input [SERIAL_WIDTH-1:0] accumulated,
                                                      input integer index,
                                                      input logic bit_value);
        begin
            with_sample = accumulated;
            for (assemble_index = 0; assemble_index < SERIAL_WIDTH;
                 assemble_index = assemble_index + 1)
                if (assemble_index == index)
                    with_sample[assemble_index] = bit_value;
        end
    endfunction

    // ------------------------------------------------------------------
    // Register file, transmitter and receiver.
    // ------------------------------------------------------------------
    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            ctrl_q           <= 8'h00;
            irq_status_q     <= 8'h00;
            tx_data_q        <= {SERIAL_WIDTH{1'b0}};
            tx_bit_q         <= 0;
            tx_baud_q        <= 0;
            tx_busy_q        <= 1'b0;
            tx_line_q        <= IDLE;
            rx_state_q       <= RX_IDLE;
            rx_bit_q         <= 0;
            rx_phase_q       <= 0;
            rx_shift_q       <= {SERIAL_WIDTH{1'b0}};
            rx_hold_q        <= {SERIAL_WIDTH{1'b0}};
            rx_valid_q       <= 1'b0;
            framing_error_q  <= 1'b0;
        end else begin
            if (access && pwrite_i) begin
                case (offset)
                    OFF_CTRL: begin
                        if (pstrb_i[0])
                            ctrl_q <= pwdata_i[7:0];
                    end
                    OFF_TXDATA: begin
                        tx_data_q <= pwdata_i[SERIAL_WIDTH-1:0];
                    end
                    OFF_IRQ_STATUS: begin
                        irq_status_q <= irq_status_q & ~pwdata_i[7:0];
                        if (pwdata_i[1])
                            framing_error_q <= 1'b0;
                    end
                    default: begin end
                endcase
            end
            if (access && !pwrite_i && (offset == OFF_RXDATA)) begin
                rx_valid_q <= 1'b0;
                irq_status_q[0] <= 1'b0;
            end

            // Transmitter: one frame per accepted write.
            if (!tx_busy_q) begin
                tx_line_q <= IDLE;
                if (tx_start) begin
                    tx_bit_q  <= 0;
                    tx_baud_q <= BAUD_DIV - 1;
                    tx_busy_q <= 1'b1;
                    tx_line_q <= START;
                end
            end else if (tx_baud_q == 0) begin
                tx_baud_q <= BAUD_DIV - 1;
                if (tx_bit_q == FRAME_BITS - 1) begin
                    tx_busy_q <= 1'b0;
                    tx_line_q <= IDLE;
                end else begin
                    tx_bit_q  <= tx_bit_q + 1;
                    tx_line_q <= frame_level(tx_bit_q + 1);
                end
            end else begin
                tx_baud_q <= tx_baud_q - 1;
            end

            // Receiver: sample the line, report only what was sampled.
            case (rx_state_q)
                RX_IDLE: begin
                    if (rx_start) begin
                        rx_state_q <= RX_DATA;
                        rx_bit_q   <= 0;
                        rx_shift_q <= {SERIAL_WIDTH{1'b0}};
                        rx_phase_q <= FIRST_SAMPLE_WAIT;
                    end
                end
                RX_DATA: begin
                    if (rx_phase_q == 0) begin
                        rx_phase_q <= BAUD_DIV - 1;
                        rx_shift_q[rx_bit_q] <= uart_rx_i;
                        if (rx_bit_q == SERIAL_WIDTH - 1) begin
                            rx_hold_q <= with_sample(rx_shift_q, rx_bit_q, uart_rx_i);
                            rx_bit_q  <= 0;
                            rx_state_q <= RX_STOP;
                        end else begin
                            rx_bit_q <= rx_bit_q + 1;
                        end
                    end else begin
                        rx_phase_q <= rx_phase_q - 1;
                    end
                end
                default: begin
                    // RX_STOP: the byte is reported after the last stop bit was
                    // sampled; a stop bit at the start level is a framing error.
                    if (rx_phase_q == 0) begin
                        rx_phase_q <= BAUD_DIV - 1;
                        if (uart_rx_i != IDLE)
                            framing_error_q <= 1'b1;
                        if (rx_bit_q == STOP_BITS - 1) begin
                            rx_state_q <= RX_IDLE;
                            rx_valid_q <= 1'b1;
                            if (uart_rx_i != IDLE)
                                irq_status_q[1] <= 1'b1;
                            else
                                irq_status_q[0] <= 1'b1;
                        end else begin
                            rx_bit_q <= rx_bit_q + 1;
                        end
                    end else begin
                        rx_phase_q <= rx_phase_q - 1;
                    end
                end
            endcase
        end
    end
endmodule
