// novagpio: a first-time input MMIO GPIO peripheral (APB4 slave, level IRQ).
//
// Register map (byte offsets inside the declared window):
//   0x00 DATA_OUT rw   output value
//   0x04 DIR      rw   1 = drive output
//   0x08 DATA_IN  ro   sampled input pins
//   0x0c IRQ_EN   rw   bit0 enable pin-event interrupt
//   0x10 IRQ_STAT ro   bit0 pin-event pending (cleared by writing DATA_IN)
module novagpio #(
    parameter integer ADDR_WIDTH = 12,
    parameter integer DATA_WIDTH = 32,
    parameter integer PINS = 8
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

    // External pins.
    input  logic [PINS-1:0]         gpio_in_i,
    output logic [PINS-1:0]         gpio_out_o,
    output logic [PINS-1:0]         gpio_dir_o,

    // Special random input: pin-drive mode select, allowed to change every cycle.
    input  logic [2:0]              pin_mode_i,

    // Level interrupt source.
    output logic                    irq_o
);
    localparam logic [7:0] OFF_DATA_OUT = 8'h00;
    localparam logic [7:0] OFF_DIR      = 8'h04;
    localparam logic [7:0] OFF_DATA_IN  = 8'h08;
    localparam logic [7:0] OFF_IRQ_EN   = 8'h0c;
    localparam logic [7:0] OFF_IRQ_STAT = 8'h10;

    logic [PINS-1:0] data_out_q;
    logic [PINS-1:0] dir_q;
    logic            irq_en_q;
    logic            irq_stat_q;
    logic [PINS-1:0] prev_in_q;

    wire access = psel_i && penable_i && pready_o;
    wire [7:0] offset = paddr_i[7:0];
    wire [PINS-1:0] sampled = gpio_in_i ^ {5'b0, pin_mode_i};

    assign pready_o    = 1'b1;
    assign gpio_out_o  = data_out_q;
    assign gpio_dir_o  = dir_q;
    assign irq_o       = irq_stat_q && irq_en_q;

    always_comb begin
        prdata_o  = {DATA_WIDTH{1'b0}};
        pslverr_o = 1'b0;
        if (access) begin
            case (offset)
                OFF_DATA_OUT: prdata_o[PINS-1:0] = data_out_q;
                OFF_DIR:      prdata_o[PINS-1:0] = dir_q;
                OFF_DATA_IN:  prdata_o[PINS-1:0] = sampled;
                OFF_IRQ_EN:   prdata_o[0]        = irq_en_q;
                OFF_IRQ_STAT: prdata_o[0]        = irq_stat_q;
                default:      pslverr_o          = 1'b1;
            endcase
        end
    end

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            data_out_q <= {PINS{1'b0}};
            dir_q      <= {PINS{1'b0}};
            irq_en_q   <= 1'b0;
            irq_stat_q <= 1'b0;
            prev_in_q  <= {PINS{1'b0}};
        end else begin
            prev_in_q <= sampled;
            if (access && pwrite_i) begin
                case (offset)
                    OFF_DATA_OUT: data_out_q <= pwdata_i[PINS-1:0];
                    OFF_DIR:      dir_q      <= pwdata_i[PINS-1:0];
                    OFF_IRQ_EN:   irq_en_q   <= pwdata_i[0];
                    OFF_DATA_IN:  irq_stat_q <= 1'b0;
                    default: begin end
                endcase
            end
            if (access && !pwrite_i && (offset == OFF_DATA_IN)) begin
                irq_stat_q <= 1'b0;
            end
            if (sampled != prev_in_q) begin
                irq_stat_q <= 1'b1;
            end
        end
    end
endmodule
