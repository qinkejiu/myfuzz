// Self-contained simple-bus models for famous CPU/IP material testing.
//
// These modules are dependency-free validation models. They intentionally use
// AutoTop's simple bus so the material library can stress composition without
// pulling native TL-UL/APB/AXI dependency trees into every random case.

module opentitan_aes_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  logic [31:0] key_q, data_q, ctrl_q, status_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      key_q <= 32'h0;
      data_q <= 32'h0;
      ctrl_q <= 32'h0;
      status_q <= 32'h0;
    end else begin
      status_q[0] <= 1'b0;
      if (req_i && we_i) begin
        unique case (addr_i)
          8'h00: ctrl_q <= wdata_i;
          8'h04: key_q <= wdata_i;
          8'h08: data_q <= wdata_i;
          8'h0c: status_q[0] <= wdata_i[0] | ctrl_q[0];
          default: begin end
        endcase
      end
    end
  end

  always_comb begin
    unique case (addr_i)
      8'h00: rdata_o = ctrl_q;
      8'h04: rdata_o = key_q;
      8'h08: rdata_o = data_q ^ key_q;
      8'h0c: rdata_o = status_q;
      default: rdata_o = 32'h0;
    endcase
  end

  assign irq_o = status_q[0];
endmodule

module opentitan_hmac_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  logic [31:0] msg_q, key_q, digest_q, status_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      msg_q <= 32'h0;
      key_q <= 32'h0;
      digest_q <= 32'h0;
      status_q <= 32'h0;
    end else if (req_i && we_i) begin
      unique case (addr_i)
        8'h00: msg_q <= wdata_i;
        8'h04: key_q <= wdata_i;
        8'h08: begin
          digest_q <= {msg_q[15:0], key_q[15:0]} ^ wdata_i;
          status_q[0] <= 1'b1;
        end
        8'h0c: status_q <= status_q & ~wdata_i;
        default: begin end
      endcase
    end
  end

  always_comb begin
    unique case (addr_i)
      8'h00: rdata_o = msg_q;
      8'h04: rdata_o = key_q;
      8'h08: rdata_o = digest_q;
      8'h0c: rdata_o = status_q;
      default: rdata_o = 32'h0;
    endcase
  end

  assign irq_o = status_q[0];
endmodule

module opentitan_kmac_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  logic [31:0] cfg_q, absorb_q, squeeze_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      cfg_q <= 32'h0;
      absorb_q <= 32'h0;
      squeeze_q <= 32'h0;
    end else if (req_i && we_i) begin
      unique case (addr_i)
        8'h00: cfg_q <= wdata_i;
        8'h04: absorb_q <= absorb_q ^ wdata_i;
        8'h08: squeeze_q <= {absorb_q[7:0], absorb_q[31:8]} ^ cfg_q;
        default: begin end
      endcase
    end
  end

  always_comb begin
    unique case (addr_i)
      8'h00: rdata_o = cfg_q;
      8'h04: rdata_o = absorb_q;
      8'h08: rdata_o = squeeze_q;
      default: rdata_o = 32'h0;
    endcase
  end

  assign irq_o = squeeze_q != 32'h0;
endmodule

module opentitan_i2c_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  input  logic        scl_i,
  input  logic        sda_i,
  output logic        scl_o,
  output logic        sda_o,
  output logic        irq_o
);
  logic [31:0] ctrl_q, tx_q, rx_q, status_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      ctrl_q <= 32'h0;
      tx_q <= 32'h0;
      rx_q <= 32'h0;
      status_q <= 32'h0;
    end else begin
      rx_q <= {30'h0, scl_i, sda_i};
      if (req_i && we_i) begin
        unique case (addr_i)
          8'h00: ctrl_q <= wdata_i;
          8'h04: tx_q <= wdata_i;
          8'h0c: status_q <= status_q & ~wdata_i;
          default: begin end
        endcase
        status_q[0] <= 1'b1;
      end
    end
  end

  always_comb begin
    unique case (addr_i)
      8'h00: rdata_o = ctrl_q;
      8'h04: rdata_o = tx_q;
      8'h08: rdata_o = rx_q;
      8'h0c: rdata_o = status_q;
      default: rdata_o = 32'h0;
    endcase
  end

  assign scl_o = ctrl_q[0] ? tx_q[0] : 1'b1;
  assign sda_o = ctrl_q[0] ? tx_q[1] : 1'b1;
  assign irq_o = status_q[0];
endmodule

module opentitan_spi_host_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        sck_o,
  output logic        csb_o,
  output logic        mosi_o,
  input  logic        miso_i,
  output logic        irq_o
);
  logic [31:0] ctrl_q, tx_q, rx_q, status_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      ctrl_q <= 32'h0;
      tx_q <= 32'h0;
      rx_q <= 32'h0;
      status_q <= 32'h0;
    end else begin
      rx_q <= {31'h0, miso_i};
      if (req_i && we_i) begin
        unique case (addr_i)
          8'h00: ctrl_q <= wdata_i;
          8'h04: tx_q <= wdata_i;
          8'h0c: status_q <= status_q & ~wdata_i;
          default: begin end
        endcase
        status_q[0] <= 1'b1;
      end
    end
  end

  always_comb begin
    unique case (addr_i)
      8'h00: rdata_o = ctrl_q;
      8'h04: rdata_o = tx_q;
      8'h08: rdata_o = rx_q;
      8'h0c: rdata_o = status_q;
      default: rdata_o = 32'h0;
    endcase
  end

  assign sck_o = ctrl_q[0] & clk_i;
  assign csb_o = ~ctrl_q[1];
  assign mosi_o = tx_q[0];
  assign irq_o = status_q[0];
endmodule

module opentitan_spi_device_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  input  logic        sck_i,
  input  logic        csb_i,
  input  logic        mosi_i,
  output logic        miso_o,
  output logic        irq_o
);
  logic [31:0] cfg_q, rx_q, tx_q, status_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      cfg_q <= 32'h0;
      rx_q <= 32'h0;
      tx_q <= 32'h0;
      status_q <= 32'h0;
    end else begin
      rx_q <= {29'h0, sck_i, csb_i, mosi_i};
      if (req_i && we_i) begin
        unique case (addr_i)
          8'h00: cfg_q <= wdata_i;
          8'h04: tx_q <= wdata_i;
          8'h0c: status_q <= status_q & ~wdata_i;
          default: begin end
        endcase
        status_q[0] <= 1'b1;
      end
    end
  end

  always_comb begin
    unique case (addr_i)
      8'h00: rdata_o = cfg_q;
      8'h04: rdata_o = tx_q;
      8'h08: rdata_o = rx_q;
      8'h0c: rdata_o = status_q;
      default: rdata_o = 32'h0;
    endcase
  end

  assign miso_o = tx_q[0];
  assign irq_o = status_q[0];
endmodule

module opentitan_pattgen_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic [7:0]  patt_o,
  output logic        irq_o
);
  logic [31:0] pattern_q, repeat_q, count_q, ctrl_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      pattern_q <= 32'h0;
      repeat_q <= 32'h0;
      count_q <= 32'h0;
      ctrl_q <= 32'h0;
    end else begin
      if (ctrl_q[0]) count_q <= count_q + 1'b1;
      if (req_i && we_i) begin
        unique case (addr_i)
          8'h00: ctrl_q <= wdata_i;
          8'h04: pattern_q <= wdata_i;
          8'h08: repeat_q <= wdata_i;
          default: begin end
        endcase
      end
    end
  end

  always_comb begin
    unique case (addr_i)
      8'h00: rdata_o = ctrl_q;
      8'h04: rdata_o = pattern_q;
      8'h08: rdata_o = repeat_q;
      8'h0c: rdata_o = count_q;
      default: rdata_o = 32'h0;
    endcase
  end

  assign patt_o = pattern_q[7:0] ^ count_q[7:0];
  assign irq_o = repeat_q != 32'h0 && count_q >= repeat_q;
endmodule

module opentitan_aon_timer_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  logic [31:0] counter_q, threshold_q, ctrl_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      counter_q <= 32'h0;
      threshold_q <= 32'hffff_ffff;
      ctrl_q <= 32'h0;
    end else begin
      if (ctrl_q[0]) counter_q <= counter_q + 1'b1;
      if (req_i && we_i) begin
        unique case (addr_i)
          8'h00: ctrl_q <= wdata_i;
          8'h04: threshold_q <= wdata_i;
          8'h08: counter_q <= wdata_i;
          default: begin end
        endcase
      end
    end
  end

  always_comb begin
    unique case (addr_i)
      8'h00: rdata_o = ctrl_q;
      8'h04: rdata_o = threshold_q;
      8'h08: rdata_o = counter_q;
      default: rdata_o = 32'h0;
    endcase
  end

  assign irq_o = ctrl_q[0] && counter_q >= threshold_q;
endmodule

module opentitan_plic_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  input  logic [7:0]  irq_sources_i,
  output logic        irq_o
);
  logic [7:0] enable_q, pending_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      enable_q <= 8'h0;
      pending_q <= 8'h0;
    end else begin
      pending_q <= pending_q | irq_sources_i;
      if (req_i && we_i) begin
        unique case (addr_i)
          8'h00: enable_q <= wdata_i[7:0];
          8'h04: pending_q <= pending_q & ~wdata_i[7:0];
          default: begin end
        endcase
      end
    end
  end

  always_comb begin
    unique case (addr_i)
      8'h00: rdata_o = {24'h0, enable_q};
      8'h04: rdata_o = {24'h0, pending_q};
      8'h08: rdata_o = {31'h0, |(pending_q & enable_q)};
      default: rdata_o = 32'h0;
    endcase
  end

  assign irq_o = |(pending_q & enable_q);
endmodule

module pulp_axi_lite_regs_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o
);
  logic [31:0] regs_q [0:7];
  logic [2:0] index;
  assign index = addr_i[4:2];

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      for (int i = 0; i < 8; i++) regs_q[i] = 32'h0;
    end else if (req_i && we_i) begin
      regs_q[index] <= wdata_i;
    end
  end

  assign rdata_o = regs_q[index];
endmodule

module pulp_axi_lite_mailbox_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  logic [31:0] msg_q, status_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      msg_q <= 32'h0;
      status_q <= 32'h0;
    end else if (req_i && we_i) begin
      unique case (addr_i)
        8'h00: begin
          msg_q <= wdata_i;
          status_q[0] <= 1'b1;
        end
        8'h04: status_q <= status_q & ~wdata_i;
        default: begin end
      endcase
    end
  end

  always_comb begin
    unique case (addr_i)
      8'h00: rdata_o = msg_q;
      8'h04: rdata_o = status_q;
      default: rdata_o = 32'h0;
    endcase
  end

  assign irq_o = status_q[0];
endmodule

module pulp_axi_sim_mem_model #(
  parameter int WORDS = 256
) (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [31:0] addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o
);
  logic [31:0] mem [0:WORDS-1];
  logic [$clog2(WORDS)-1:0] index;
  assign index = addr_i[$clog2(WORDS)+1:2];

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      for (int i = 0; i < WORDS; i++) mem[i] = 32'h0;
    end else if (req_i && we_i) begin
      mem[index] <= wdata_i;
    end
  end

  assign rdata_o = mem[index];
endmodule

module core_v_mcu_apb_gpio_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  input  logic [15:0] gpio_i,
  output logic [15:0] gpio_o,
  output logic        irq_o
);
  logic [15:0] out_q, mask_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      out_q <= 16'h0;
      mask_q <= 16'h0;
    end else if (req_i && we_i) begin
      unique case (addr_i)
        8'h00: out_q <= wdata_i[15:0];
        8'h08: mask_q <= wdata_i[15:0];
        default: begin end
      endcase
    end
  end

  always_comb begin
    unique case (addr_i)
      8'h00: rdata_o = {16'h0, out_q};
      8'h04: rdata_o = {16'h0, gpio_i};
      8'h08: rdata_o = {16'h0, mask_q};
      default: rdata_o = 32'h0;
    endcase
  end

  assign gpio_o = out_q;
  assign irq_o = |(gpio_i & mask_q);
endmodule

module core_v_mcu_apb_timer_unit_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  logic [31:0] count_q, cmp_q, ctrl_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      count_q <= 32'h0;
      cmp_q <= 32'hffff_ffff;
      ctrl_q <= 32'h0;
    end else begin
      if (ctrl_q[0]) count_q <= count_q + 1'b1;
      if (req_i && we_i) begin
        unique case (addr_i)
          8'h00: ctrl_q <= wdata_i;
          8'h04: cmp_q <= wdata_i;
          8'h08: count_q <= wdata_i;
          default: begin end
        endcase
      end
    end
  end

  always_comb begin
    unique case (addr_i)
      8'h00: rdata_o = ctrl_q;
      8'h04: rdata_o = cmp_q;
      8'h08: rdata_o = count_q;
      default: rdata_o = 32'h0;
    endcase
  end

  assign irq_o = ctrl_q[0] && count_q >= cmp_q;
endmodule

module core_v_mcu_apb_i2cs_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  input  logic        scl_i,
  input  logic        sda_i,
  output logic        sda_o,
  output logic        irq_o
);
  logic [31:0] cfg_q, status_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      cfg_q <= 32'h0;
      status_q <= 32'h0;
    end else begin
      status_q[2:1] <= {scl_i, sda_i};
      if (req_i && we_i) begin
        if (addr_i == 8'h00) cfg_q <= wdata_i;
        if (addr_i == 8'h04) status_q <= status_q & ~wdata_i;
        status_q[0] <= 1'b1;
      end
    end
  end

  assign rdata_o = (addr_i == 8'h00) ? cfg_q : status_q;
  assign sda_o = cfg_q[0];
  assign irq_o = status_q[0];
endmodule

module core_v_mcu_apb_adv_timer_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic [3:0]  pwm_o,
  output logic        irq_o
);
  logic [31:0] cfg_q, period_q, duty_q, count_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      cfg_q <= 32'h0;
      period_q <= 32'h100;
      duty_q <= 32'h40;
      count_q <= 32'h0;
    end else begin
      if (cfg_q[0]) count_q <= (count_q >= period_q) ? 32'h0 : count_q + 1'b1;
      if (req_i && we_i) begin
        unique case (addr_i)
          8'h00: cfg_q <= wdata_i;
          8'h04: period_q <= wdata_i;
          8'h08: duty_q <= wdata_i;
          default: begin end
        endcase
      end
    end
  end

  always_comb begin
    unique case (addr_i)
      8'h00: rdata_o = cfg_q;
      8'h04: rdata_o = period_q;
      8'h08: rdata_o = duty_q;
      8'h0c: rdata_o = count_q;
      default: rdata_o = 32'h0;
    endcase
  end

  assign pwm_o = {4{cfg_q[0] && count_q < duty_q}};
  assign irq_o = cfg_q[0] && count_q == period_q;
endmodule

module litex_uart_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        tx_o,
  input  logic        rx_i,
  output logic        irq_o
);
  logic [7:0] tx_q, rx_q;
  logic [31:0] status_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      tx_q <= 8'h0;
      rx_q <= 8'h0;
      status_q <= 32'h0;
    end else begin
      rx_q <= {rx_q[6:0], rx_i};
      if (req_i && we_i) begin
        if (addr_i == 8'h00) begin
          tx_q <= wdata_i[7:0];
          status_q[0] <= 1'b1;
        end
        if (addr_i == 8'h04) status_q <= status_q & ~wdata_i;
      end
    end
  end
  assign rdata_o = (addr_i == 8'h00) ? {24'h0, rx_q} : status_q;
  assign tx_o = tx_q[0];
  assign irq_o = status_q[0];
endmodule

module litex_timer_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  logic [31:0] load_q, value_q, ctrl_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      load_q <= 32'h100;
      value_q <= 32'h100;
      ctrl_q <= 32'h0;
    end else begin
      if (ctrl_q[0]) value_q <= (value_q == 32'h0) ? load_q : value_q - 1'b1;
      if (req_i && we_i) begin
        if (addr_i == 8'h00) ctrl_q <= wdata_i;
        if (addr_i == 8'h04) load_q <= wdata_i;
        if (addr_i == 8'h08) value_q <= wdata_i;
      end
    end
  end
  assign rdata_o = (addr_i == 8'h00) ? ctrl_q : (addr_i == 8'h04) ? load_q : value_q;
  assign irq_o = ctrl_q[0] && value_q == 32'h0;
endmodule

module litex_gpio_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  input  logic [31:0] gpio_i,
  output logic [31:0] gpio_o,
  output logic        irq_o
);
  logic [31:0] out_q, mask_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      out_q <= 32'h0;
      mask_q <= 32'h0;
    end else if (req_i && we_i) begin
      if (addr_i == 8'h00) out_q <= wdata_i;
      if (addr_i == 8'h08) mask_q <= wdata_i;
    end
  end
  assign rdata_o = (addr_i == 8'h00) ? out_q : (addr_i == 8'h04) ? gpio_i : mask_q;
  assign gpio_o = out_q;
  assign irq_o = |(gpio_i & mask_q);
endmodule

module litex_spi_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        sck_o,
  output logic        mosi_o,
  input  logic        miso_i,
  output logic        irq_o
);
  logic [31:0] data_q, ctrl_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      data_q <= 32'h0;
      ctrl_q <= 32'h0;
    end else begin
      data_q[31] <= miso_i;
      if (req_i && we_i) begin
        if (addr_i == 8'h00) data_q <= wdata_i;
        if (addr_i == 8'h04) ctrl_q <= wdata_i;
      end
    end
  end
  assign rdata_o = (addr_i == 8'h00) ? data_q : ctrl_q;
  assign sck_o = ctrl_q[0] & clk_i;
  assign mosi_o = data_q[0];
  assign irq_o = ctrl_q[1];
endmodule

module wishbone_sram_model #(
  parameter int WORDS = 128
) (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [31:0] addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o
);
  logic [31:0] mem [0:WORDS-1];
  logic [$clog2(WORDS)-1:0] index;
  assign index = addr_i[$clog2(WORDS)+1:2];
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      for (int i = 0; i < WORDS; i++) mem[i] = 32'h0;
    end else if (req_i && we_i) begin
      mem[index] <= wdata_i;
    end
  end
  assign rdata_o = mem[index];
endmodule

module wishbone_uart_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        tx_o,
  input  logic        rx_i,
  output logic        irq_o
);
  litex_uart_model u_uart (.*);
endmodule

module wishbone_timer_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  litex_timer_model u_timer (.*);
endmodule

module apb_uart_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        tx_o,
  input  logic        rx_i,
  output logic        irq_o
);
  litex_uart_model u_uart (.*);
endmodule

module apb_gpio_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  input  logic [31:0] gpio_i,
  output logic [31:0] gpio_o,
  output logic        irq_o
);
  litex_gpio_model u_gpio (.*);
endmodule

module apb_timer_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  litex_timer_model u_timer (.*);
endmodule

module sifive_clint_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  logic [31:0] mtime_q, mtimecmp_q, msip_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      mtime_q <= 32'h0;
      mtimecmp_q <= 32'hffff_ffff;
      msip_q <= 32'h0;
    end else begin
      mtime_q <= mtime_q + 1'b1;
      if (req_i && we_i) begin
        if (addr_i == 8'h00) msip_q <= wdata_i;
        if (addr_i == 8'h04) mtimecmp_q <= wdata_i;
        if (addr_i == 8'h08) mtime_q <= wdata_i;
      end
    end
  end
  assign rdata_o = (addr_i == 8'h00) ? msip_q : (addr_i == 8'h04) ? mtimecmp_q : mtime_q;
  assign irq_o = msip_q[0] || mtime_q >= mtimecmp_q;
endmodule

module simple_dma_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  logic [31:0] src_q, dst_q, len_q, ctrl_q, progress_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      src_q <= 32'h0;
      dst_q <= 32'h0;
      len_q <= 32'h0;
      ctrl_q <= 32'h0;
      progress_q <= 32'h0;
    end else begin
      if (ctrl_q[0] && progress_q < len_q) progress_q <= progress_q + 1'b1;
      if (req_i && we_i) begin
        if (addr_i == 8'h00) src_q <= wdata_i;
        if (addr_i == 8'h04) dst_q <= wdata_i;
        if (addr_i == 8'h08) len_q <= wdata_i;
        if (addr_i == 8'h0c) begin
          ctrl_q <= wdata_i;
          progress_q <= 32'h0;
        end
      end
    end
  end
  always_comb begin
    unique case (addr_i)
      8'h00: rdata_o = src_q;
      8'h04: rdata_o = dst_q;
      8'h08: rdata_o = len_q;
      8'h0c: rdata_o = ctrl_q;
      default: rdata_o = progress_q;
    endcase
  end
  assign irq_o = ctrl_q[0] && progress_q >= len_q && len_q != 32'h0;
endmodule

module pwm_controller_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic [7:0]  pwm_o,
  output logic        irq_o
);
  logic [31:0] period_q, duty_q, count_q, ctrl_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      period_q <= 32'hff;
      duty_q <= 32'h40;
      count_q <= 32'h0;
      ctrl_q <= 32'h0;
    end else begin
      if (ctrl_q[0]) count_q <= (count_q >= period_q) ? 32'h0 : count_q + 1'b1;
      if (req_i && we_i) begin
        if (addr_i == 8'h00) ctrl_q <= wdata_i;
        if (addr_i == 8'h04) period_q <= wdata_i;
        if (addr_i == 8'h08) duty_q <= wdata_i;
      end
    end
  end
  assign rdata_o = (addr_i == 8'h00) ? ctrl_q : (addr_i == 8'h04) ? period_q : duty_q;
  assign pwm_o = {8{ctrl_q[0] && count_q < duty_q}};
  assign irq_o = ctrl_q[0] && count_q == period_q;
endmodule

module qspi_flash_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        sck_o,
  output logic        csb_o,
  output logic [3:0]  dq_o,
  input  logic [3:0]  dq_i,
  output logic        irq_o
);
  logic [31:0] cmd_q, addr_q, data_q, status_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      cmd_q <= 32'h0;
      addr_q <= 32'h0;
      data_q <= 32'h0;
      status_q <= 32'h0;
    end else begin
      data_q[3:0] <= dq_i;
      if (req_i && we_i) begin
        if (addr_i == 8'h00) cmd_q <= wdata_i;
        if (addr_i == 8'h04) addr_q <= wdata_i;
        if (addr_i == 8'h08) data_q <= wdata_i;
        status_q[0] <= 1'b1;
      end
    end
  end
  assign rdata_o = (addr_i == 8'h00) ? cmd_q : (addr_i == 8'h04) ? addr_q : (addr_i == 8'h08) ? data_q : status_q;
  assign sck_o = cmd_q[0] & clk_i;
  assign csb_o = ~cmd_q[1];
  assign dq_o = data_q[3:0];
  assign irq_o = status_q[0];
endmodule

module i2s_audio_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        bclk_o,
  output logic        lrclk_o,
  output logic        sdata_o,
  output logic        irq_o
);
  logic [31:0] sample_q, ctrl_q, count_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      sample_q <= 32'h0;
      ctrl_q <= 32'h0;
      count_q <= 32'h0;
    end else begin
      if (ctrl_q[0]) count_q <= count_q + 1'b1;
      if (req_i && we_i) begin
        if (addr_i == 8'h00) ctrl_q <= wdata_i;
        if (addr_i == 8'h04) sample_q <= wdata_i;
      end
    end
  end
  assign rdata_o = (addr_i == 8'h00) ? ctrl_q : sample_q;
  assign bclk_o = count_q[1];
  assign lrclk_o = count_q[6];
  assign sdata_o = sample_q[count_q[4:0]];
  assign irq_o = ctrl_q[0] && count_q[7:0] == 8'hff;
endmodule

module eth_mac_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  input  logic        rx_dv_i,
  output logic        tx_en_o,
  output logic        irq_o
);
  logic [31:0] ctrl_q, tx_q, rx_q, status_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      ctrl_q <= 32'h0;
      tx_q <= 32'h0;
      rx_q <= 32'h0;
      status_q <= 32'h0;
    end else begin
      rx_q <= {31'h0, rx_dv_i};
      if (rx_dv_i) status_q[1] <= 1'b1;
      if (req_i && we_i) begin
        if (addr_i == 8'h00) ctrl_q <= wdata_i;
        if (addr_i == 8'h04) begin
          tx_q <= wdata_i;
          status_q[0] <= 1'b1;
        end
        if (addr_i == 8'h0c) status_q <= status_q & ~wdata_i;
      end
    end
  end
  always_comb begin
    unique case (addr_i)
      8'h00: rdata_o = ctrl_q;
      8'h04: rdata_o = tx_q;
      8'h08: rdata_o = rx_q;
      8'h0c: rdata_o = status_q;
      default: rdata_o = 32'h0;
    endcase
  end
  assign tx_en_o = ctrl_q[0] && status_q[0];
  assign irq_o = |status_q[1:0];
endmodule

module sram_1rw_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [31:0] addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o
);
  logic [31:0] mem_q [0:255];
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      rdata_o <= 32'h0;
    end else if (req_i) begin
      if (we_i) mem_q[addr_i[9:2]] <= wdata_i;
      rdata_o <= mem_q[addr_i[9:2]];
    end
  end
endmodule

module boot_rom_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [31:0] addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o
);
  logic [31:0] patch_q;
  function automatic logic [31:0] rom_word(input logic [7:0] word_addr);
    unique case (word_addr[3:0])
      4'h0: rom_word = 32'h00000013;
      4'h1: rom_word = 32'h00100093;
      4'h2: rom_word = 32'h00200113;
      4'h3: rom_word = 32'h00308193;
      default: rom_word = {16'hb007, 8'h00, word_addr};
    endcase
  endfunction
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      patch_q <= 32'h0;
      rdata_o <= 32'h0;
    end else if (req_i) begin
      if (we_i) patch_q <= wdata_i;
      rdata_o <= (addr_i[9:2] == 8'hff) ? patch_q : rom_word(addr_i[9:2]);
    end
  end
  logic unused_write;
  assign unused_write = we_i ^ ^wdata_i;
endmodule

module bram_controller_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [31:0] addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o
);
  logic [31:0] bank0_q [0:127];
  logic [31:0] bank1_q [0:127];
  logic        bank_sel;
  assign bank_sel = addr_i[9];
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      rdata_o <= 32'h0;
    end else if (req_i) begin
      if (we_i && !bank_sel) bank0_q[addr_i[8:2]] <= wdata_i;
      if (we_i && bank_sel) bank1_q[addr_i[8:2]] <= wdata_i;
      rdata_o <= bank_sel ? bank1_q[addr_i[8:2]] : bank0_q[addr_i[8:2]];
    end
  end
endmodule

module ddr_controller_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [31:0] addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o
);
  logic [31:0] mem_q [0:511];
  logic [31:0] status_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      rdata_o <= 32'h0;
      status_q <= 32'h1;
    end else if (req_i) begin
      status_q[1] <= we_i;
      if (addr_i[11:2] == 10'h3ff) begin
        if (we_i) status_q <= wdata_i;
        rdata_o <= status_q;
      end else begin
        if (we_i) mem_q[addr_i[10:2]] <= wdata_i;
        rdata_o <= mem_q[addr_i[10:2]];
      end
    end
  end
endmodule

module scratchpad_ram_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [31:0] addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o
);
  logic [31:0] mem_q [0:63];
  logic [31:0] last_addr_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      rdata_o <= 32'h0;
      last_addr_q <= 32'h0;
    end else if (req_i) begin
      last_addr_q <= addr_i;
      if (addr_i[7:2] == 6'h3f) begin
        rdata_o <= last_addr_q;
      end else begin
        if (we_i) mem_q[addr_i[7:2]] <= wdata_i;
        rdata_o <= mem_q[addr_i[7:2]];
      end
    end
  end
endmodule

module ns16550_uart_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  input  logic        rx_i,
  output logic        tx_o,
  output logic        irq_o
);
  logic [7:0] rbr_q, thr_q, ier_q, lsr_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      rbr_q <= 8'h0;
      thr_q <= 8'h0;
      ier_q <= 8'h0;
      lsr_q <= 8'h60;
    end else begin
      if (!rx_i) begin
        rbr_q <= 8'h55;
        lsr_q[0] <= 1'b1;
      end
      if (req_i && we_i) begin
        if (addr_i[4:0] == 5'h00) begin
          thr_q <= wdata_i[7:0];
          lsr_q[5] <= 1'b0;
        end
        if (addr_i[4:0] == 5'h04) ier_q <= wdata_i[7:0];
      end else begin
        lsr_q[5] <= 1'b1;
      end
      if (req_i && !we_i && addr_i[4:0] == 5'h00) lsr_q[0] <= 1'b0;
    end
  end
  always_comb begin
    unique case (addr_i[4:0])
      5'h00: rdata_o = {24'h0, rbr_q};
      5'h04: rdata_o = {24'h0, ier_q};
      5'h14: rdata_o = {24'h0, lsr_q};
      default: rdata_o = 32'h0;
    endcase
  end
  assign tx_o = thr_q[0];
  assign irq_o = (ier_q[0] && lsr_q[0]) || (ier_q[1] && lsr_q[5]);
endmodule

module arm_pl011_uart_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  input  logic        rx_i,
  output logic        tx_o,
  output logic        irq_o
);
  logic [31:0] dr_q, cr_q, imsc_q, ris_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      dr_q <= 32'h0;
      cr_q <= 32'h0;
      imsc_q <= 32'h0;
      ris_q <= 32'h0;
    end else begin
      if (!rx_i) begin
        dr_q <= 32'h41;
        ris_q[4] <= 1'b1;
      end
      if (req_i && we_i) begin
        if (addr_i == 8'h00) begin
          dr_q <= wdata_i;
          ris_q[5] <= 1'b1;
        end
        if (addr_i == 8'h30) cr_q <= wdata_i;
        if (addr_i == 8'h38) imsc_q <= wdata_i;
        if (addr_i == 8'h44) ris_q <= ris_q & ~wdata_i;
      end
    end
  end
  always_comb begin
    unique case (addr_i)
      8'h00: rdata_o = dr_q;
      8'h18: rdata_o = 32'h90;
      8'h30: rdata_o = cr_q;
      8'h38: rdata_o = imsc_q;
      8'h3c: rdata_o = ris_q;
      default: rdata_o = 32'h0;
    endcase
  end
  assign tx_o = dr_q[0] & cr_q[8];
  assign irq_o = |(ris_q & imsc_q);
endmodule

module arm_systick_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  logic [31:0] ctrl_q, reload_q, value_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      ctrl_q <= 32'h0;
      reload_q <= 32'h100;
      value_q <= 32'h100;
    end else begin
      if (ctrl_q[0]) begin
        if (value_q == 32'h0) value_q <= reload_q;
        else value_q <= value_q - 1'b1;
      end
      if (req_i && we_i) begin
        if (addr_i == 8'h00) ctrl_q <= wdata_i;
        if (addr_i == 8'h04) reload_q <= wdata_i;
        if (addr_i == 8'h08) value_q <= wdata_i;
      end
    end
  end
  assign irq_o = ctrl_q[1] && value_q == 32'h0;
  always_comb begin
    unique case (addr_i)
      8'h00: rdata_o = ctrl_q;
      8'h04: rdata_o = reload_q;
      8'h08: rdata_o = value_q;
      default: rdata_o = 32'h0;
    endcase
  end
endmodule

module watchdog_timer_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  logic [31:0] ctrl_q, limit_q, count_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      ctrl_q <= 32'h0;
      limit_q <= 32'h80;
      count_q <= 32'h0;
    end else begin
      if (ctrl_q[0]) count_q <= count_q + 1'b1;
      if (req_i && we_i) begin
        if (addr_i == 8'h00) ctrl_q <= wdata_i;
        if (addr_i == 8'h04) limit_q <= wdata_i;
        if (addr_i == 8'h08) count_q <= 32'h0;
      end
    end
  end
  assign irq_o = ctrl_q[1] && count_q >= limit_q;
  always_comb begin
    unique case (addr_i)
      8'h00: rdata_o = ctrl_q;
      8'h04: rdata_o = limit_q;
      8'h08: rdata_o = count_q;
      default: rdata_o = 32'h0;
    endcase
  end
endmodule

module rng_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  logic [31:0] lfsr_q, ctrl_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      lfsr_q <= 32'h1ace_b00c;
      ctrl_q <= 32'h0;
    end else begin
      lfsr_q <= {lfsr_q[30:0], lfsr_q[31] ^ lfsr_q[21] ^ lfsr_q[1] ^ lfsr_q[0]};
      if (req_i && we_i && addr_i == 8'h00) ctrl_q <= wdata_i;
    end
  end
  assign rdata_o = (addr_i == 8'h00) ? ctrl_q : lfsr_q;
  assign irq_o = ctrl_q[0] && (&lfsr_q[7:0]);
endmodule

module adc_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  input  logic [7:0]  analog_i,
  output logic        irq_o
);
  logic [31:0] ctrl_q, sample_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      ctrl_q <= 32'h0;
      sample_q <= 32'h0;
    end else begin
      if (ctrl_q[0]) sample_q <= {24'h0, analog_i};
      if (req_i && we_i && addr_i == 8'h00) ctrl_q <= wdata_i;
    end
  end
  assign rdata_o = (addr_i == 8'h00) ? ctrl_q : sample_q;
  assign irq_o = ctrl_q[1] && sample_q[7];
endmodule

module can_controller_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  input  logic        rx_i,
  output logic        tx_o,
  output logic        irq_o
);
  logic [31:0] ctrl_q, tx_q, rx_q, status_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      ctrl_q <= 32'h0;
      tx_q <= 32'h0;
      rx_q <= 32'h0;
      status_q <= 32'h0;
    end else begin
      if (!rx_i) begin
        rx_q <= 32'hca11;
        status_q[1] <= 1'b1;
      end
      if (req_i && we_i) begin
        if (addr_i == 8'h00) ctrl_q <= wdata_i;
        if (addr_i == 8'h04) begin
          tx_q <= wdata_i;
          status_q[0] <= 1'b1;
        end
        if (addr_i == 8'h0c) status_q <= status_q & ~wdata_i;
      end
    end
  end
  always_comb begin
    unique case (addr_i)
      8'h00: rdata_o = ctrl_q;
      8'h04: rdata_o = tx_q;
      8'h08: rdata_o = rx_q;
      8'h0c: rdata_o = status_q;
      default: rdata_o = 32'h0;
    endcase
  end
  assign tx_o = tx_q[0] & ctrl_q[0];
  assign irq_o = |status_q[1:0];
endmodule

module usb_device_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  input  logic        dp_i,
  input  logic        dm_i,
  output logic        dp_o,
  output logic        dm_o,
  output logic        irq_o
);
  logic [31:0] ctrl_q, ep_q, status_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      ctrl_q <= 32'h0;
      ep_q <= 32'h0;
      status_q <= 32'h0;
    end else begin
      status_q[1:0] <= {dp_i, dm_i};
      if (req_i && we_i) begin
        if (addr_i == 8'h00) ctrl_q <= wdata_i;
        if (addr_i == 8'h04) ep_q <= wdata_i;
        if (addr_i == 8'h08) status_q <= status_q & ~wdata_i;
      end
    end
  end
  always_comb begin
    unique case (addr_i)
      8'h00: rdata_o = ctrl_q;
      8'h04: rdata_o = ep_q;
      8'h08: rdata_o = status_q;
      default: rdata_o = 32'h0;
    endcase
  end
  assign dp_o = ctrl_q[0] ^ ep_q[0];
  assign dm_o = ctrl_q[0] ^ ep_q[1];
  assign irq_o = ctrl_q[1] && |status_q[1:0];
endmodule

module sdio_controller_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  input  logic        cmd_i,
  output logic        cmd_o,
  input  logic [3:0]  dat_i,
  output logic [3:0]  dat_o,
  output logic        clk_o,
  output logic        irq_o
);
  logic [31:0] ctrl_q, cmd_q, data_q, status_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      ctrl_q <= 32'h0;
      cmd_q <= 32'h0;
      data_q <= 32'h0;
      status_q <= 32'h0;
    end else begin
      status_q[4:0] <= {cmd_i, dat_i};
      if (req_i && we_i) begin
        if (addr_i == 8'h00) ctrl_q <= wdata_i;
        if (addr_i == 8'h04) cmd_q <= wdata_i;
        if (addr_i == 8'h08) data_q <= wdata_i;
      end
    end
  end
  always_comb begin
    unique case (addr_i)
      8'h00: rdata_o = ctrl_q;
      8'h04: rdata_o = cmd_q;
      8'h08: rdata_o = data_q;
      8'h0c: rdata_o = status_q;
      default: rdata_o = 32'h0;
    endcase
  end
  assign cmd_o = cmd_q[0];
  assign dat_o = data_q[3:0];
  assign clk_o = ctrl_q[0] & clk_i;
  assign irq_o = ctrl_q[1] && |status_q[4:0];
endmodule

module i3c_controller_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  input  logic        scl_i,
  input  logic        sda_i,
  output logic        scl_o,
  output logic        sda_o,
  output logic        irq_o
);
  logic [31:0] ctrl_q, tx_q, rx_q, status_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      ctrl_q <= 32'h0;
      tx_q <= 32'h0;
      rx_q <= 32'h0;
      status_q <= 32'h0;
    end else begin
      rx_q <= {30'h0, scl_i, sda_i};
      status_q[0] <= scl_i ^ sda_i;
      if (req_i && we_i) begin
        if (addr_i == 8'h00) ctrl_q <= wdata_i;
        if (addr_i == 8'h04) tx_q <= wdata_i;
        if (addr_i == 8'h0c) status_q <= status_q & ~wdata_i;
      end
    end
  end
  always_comb begin
    unique case (addr_i)
      8'h00: rdata_o = ctrl_q;
      8'h04: rdata_o = tx_q;
      8'h08: rdata_o = rx_q;
      8'h0c: rdata_o = status_q;
      default: rdata_o = 32'h0;
    endcase
  end
  assign scl_o = tx_q[0] & ctrl_q[0];
  assign sda_o = tx_q[1] & ctrl_q[0];
  assign irq_o = ctrl_q[1] && status_q[0];
endmodule

module riscv_debug_module_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  input  logic        haltreq_i,
  output logic        ndmreset_o,
  output logic        irq_o
);
  logic [31:0] dmcontrol_q, dmstatus_q, data0_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      dmcontrol_q <= 32'h0;
      dmstatus_q <= 32'h00030c82;
      data0_q <= 32'h0;
    end else begin
      if (haltreq_i) dmstatus_q[9] <= 1'b1;
      if (req_i && we_i) begin
        if (addr_i == 8'h10) dmcontrol_q <= wdata_i;
        if (addr_i == 8'h11) dmstatus_q <= dmstatus_q & ~wdata_i;
        if (addr_i == 8'h04) data0_q <= wdata_i;
      end
    end
  end
  always_comb begin
    unique case (addr_i)
      8'h10: rdata_o = dmcontrol_q;
      8'h11: rdata_o = dmstatus_q;
      8'h04: rdata_o = data0_q;
      default: rdata_o = 32'h0;
    endcase
  end
  assign ndmreset_o = dmcontrol_q[1];
  assign irq_o = haltreq_i | dmcontrol_q[31];
endmodule

module jtag_dtm_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  input  logic        tck_i,
  input  logic        tms_i,
  input  logic        tdi_i,
  output logic        tdo_o,
  output logic        irq_o
);
  logic [31:0] dtmcs_q, dmi_q, shift_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      dtmcs_q <= 32'h71;
      dmi_q <= 32'h0;
      shift_q <= 32'h0;
    end else begin
      shift_q <= {shift_q[30:0], tdi_i ^ tms_i ^ tck_i};
      if (req_i && we_i) begin
        if (addr_i == 8'h00) dtmcs_q <= wdata_i;
        if (addr_i == 8'h04) dmi_q <= wdata_i;
      end
    end
  end
  assign rdata_o = (addr_i == 8'h00) ? dtmcs_q : (addr_i == 8'h04) ? dmi_q : shift_q;
  assign tdo_o = shift_q[31];
  assign irq_o = dtmcs_q[0] && tms_i;
endmodule

module pcie_endpoint_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  input  logic        perst_i,
  input  logic        rx_valid_i,
  output logic        tx_valid_o,
  output logic        irq_o
);
  logic [31:0] cfg_q, bar0_q, status_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      cfg_q <= 32'h00018086;
      bar0_q <= 32'h0;
      status_q <= 32'h0;
    end else begin
      status_q[0] <= !perst_i;
      if (rx_valid_i) status_q[1] <= 1'b1;
      if (req_i && we_i) begin
        if (addr_i == 8'h00) cfg_q <= wdata_i;
        if (addr_i == 8'h10) bar0_q <= wdata_i;
        if (addr_i == 8'h04) status_q <= status_q & ~wdata_i;
      end
    end
  end
  always_comb begin
    unique case (addr_i)
      8'h00: rdata_o = cfg_q;
      8'h04: rdata_o = status_q;
      8'h10: rdata_o = bar0_q;
      default: rdata_o = 32'h0;
    endcase
  end
  assign tx_valid_o = cfg_q[0] && status_q[0];
  assign irq_o = cfg_q[1] && status_q[1];
endmodule

module mipi_dsi_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        dsi_clk_o,
  output logic [3:0]  dsi_data_o,
  output logic        irq_o
);
  logic [31:0] ctrl_q, pixel_q, status_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      ctrl_q <= 32'h0;
      pixel_q <= 32'h0;
      status_q <= 32'h0;
    end else begin
      if (ctrl_q[0]) status_q[0] <= 1'b1;
      if (req_i && we_i) begin
        if (addr_i == 8'h00) ctrl_q <= wdata_i;
        if (addr_i == 8'h04) pixel_q <= wdata_i;
        if (addr_i == 8'h08) status_q <= status_q & ~wdata_i;
      end
    end
  end
  assign rdata_o = (addr_i == 8'h00) ? ctrl_q : (addr_i == 8'h04) ? pixel_q : status_q;
  assign dsi_clk_o = ctrl_q[0] & clk_i;
  assign dsi_data_o = pixel_q[3:0];
  assign irq_o = ctrl_q[1] && status_q[0];
endmodule

module camera_csi_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  input  logic        csi_valid_i,
  input  logic [7:0]  csi_data_i,
  output logic        irq_o
);
  logic [31:0] ctrl_q, frame_q, status_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      ctrl_q <= 32'h0;
      frame_q <= 32'h0;
      status_q <= 32'h0;
    end else begin
      if (csi_valid_i) begin
        frame_q <= {24'h0, csi_data_i};
        status_q[0] <= 1'b1;
      end
      if (req_i && we_i) begin
        if (addr_i == 8'h00) ctrl_q <= wdata_i;
        if (addr_i == 8'h08) status_q <= status_q & ~wdata_i;
      end
    end
  end
  assign rdata_o = (addr_i == 8'h00) ? ctrl_q : (addr_i == 8'h04) ? frame_q : status_q;
  assign irq_o = ctrl_q[0] && status_q[0];
endmodule

module sensor_hub_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  input  logic [15:0] sensor_i,
  output logic        irq_o
);
  logic [31:0] ctrl_q, sample_q, threshold_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      ctrl_q <= 32'h0;
      sample_q <= 32'h0;
      threshold_q <= 32'h8000;
    end else begin
      sample_q <= {16'h0, sensor_i};
      if (req_i && we_i) begin
        if (addr_i == 8'h00) ctrl_q <= wdata_i;
        if (addr_i == 8'h08) threshold_q <= wdata_i;
      end
    end
  end
  assign rdata_o = (addr_i == 8'h00) ? ctrl_q : (addr_i == 8'h04) ? sample_q : threshold_q;
  assign irq_o = ctrl_q[0] && sample_q >= threshold_q;
endmodule

module nand_flash_controller_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        cle_o,
  output logic        ale_o,
  input  logic        rb_i,
  output logic        irq_o
);
  logic [31:0] cmd_q, addr_q, data_q, status_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      cmd_q <= 32'h0;
      addr_q <= 32'h0;
      data_q <= 32'h0;
      status_q <= 32'h1;
    end else begin
      status_q[0] <= rb_i;
      if (req_i && we_i) begin
        if (addr_i == 8'h00) cmd_q <= wdata_i;
        if (addr_i == 8'h04) addr_q <= wdata_i;
        if (addr_i == 8'h08) data_q <= wdata_i;
      end
    end
  end
  assign rdata_o = (addr_i == 8'h00) ? cmd_q : (addr_i == 8'h04) ? addr_q : (addr_i == 8'h08) ? data_q : status_q;
  assign cle_o = cmd_q[0];
  assign ale_o = cmd_q[1];
  assign irq_o = cmd_q[2] && status_q[0];
endmodule

module emmc_controller_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  input  logic        cmd_i,
  output logic        cmd_o,
  input  logic [7:0]  dat_i,
  output logic [7:0]  dat_o,
  output logic        irq_o
);
  logic [31:0] ctrl_q, cmd_q, data_q, status_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      ctrl_q <= 32'h0;
      cmd_q <= 32'h0;
      data_q <= 32'h0;
      status_q <= 32'h0;
    end else begin
      status_q[8:0] <= {cmd_i, dat_i};
      if (req_i && we_i) begin
        if (addr_i == 8'h00) ctrl_q <= wdata_i;
        if (addr_i == 8'h04) cmd_q <= wdata_i;
        if (addr_i == 8'h08) data_q <= wdata_i;
      end
    end
  end
  assign rdata_o = (addr_i == 8'h00) ? ctrl_q : (addr_i == 8'h04) ? cmd_q : (addr_i == 8'h08) ? data_q : status_q;
  assign cmd_o = cmd_q[0];
  assign dat_o = data_q[7:0];
  assign irq_o = ctrl_q[0] && |status_q[8:0];
endmodule

module iommu_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        fault_o,
  output logic        irq_o
);
  logic [31:0] ctrl_q, base_q, fault_addr_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      ctrl_q <= 32'h0;
      base_q <= 32'h0;
      fault_addr_q <= 32'h0;
    end else begin
      if (ctrl_q[0] && base_q[1:0] != 2'b00) fault_addr_q <= base_q;
      if (req_i && we_i) begin
        if (addr_i == 8'h00) ctrl_q <= wdata_i;
        if (addr_i == 8'h04) base_q <= wdata_i;
        if (addr_i == 8'h08) fault_addr_q <= 32'h0;
      end
    end
  end
  assign rdata_o = (addr_i == 8'h00) ? ctrl_q : (addr_i == 8'h04) ? base_q : fault_addr_q;
  assign fault_o = fault_addr_q != 32'h0;
  assign irq_o = ctrl_q[1] && fault_o;
endmodule
