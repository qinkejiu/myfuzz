module ibex_opentitan_real_ip_top (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        uart_rx_i,
  input  logic [31:0] gpio_i,
  input  logic        strap_en_i,
  input  logic        debug_req_i,
  input  logic        irq_software_i,
  input  logic        irq_external_i,
  output logic        uart_tx_o,
  output logic        uart_tx_en_o,
  output logic [31:0] gpio_o,
  output logic [31:0] gpio_oe_o,
  output logic        timer_irq_o,
  output logic [31:0] core_instr_addr_o
);
  logic        instr_req;
  logic        instr_gnt;
  logic        instr_rvalid;
  logic [31:0] instr_addr;
  logic [31:0] instr_rdata;

  logic        data_req;
  logic        data_gnt;
  logic        data_rvalid;
  logic        data_we;
  logic [3:0]  data_be;
  logic [31:0] data_addr;
  logic [31:0] data_wdata;
  logic [6:0]  data_wdata_intg;
  logic [31:0] data_rdata;
  logic [6:0]  data_rdata_intg;
  logic        data_err;

  logic        ram_data_gnt;
  logic        ram_data_rvalid;
  logic [31:0] ram_data_rdata;
  logic        data_is_mmio;

  logic        mmio_gnt;
  logic        mmio_rvalid;
  logic [31:0] mmio_rdata;
  logic [6:0]  mmio_rdata_intg;
  logic        mmio_err;
  logic        unused_mmio_intg_err;
  logic [1:0]  mmio_select;

  tlul_pkg::tl_h2d_t tl_host_h2d;
  tlul_pkg::tl_d2h_t tl_host_d2h;
  tlul_pkg::tl_h2d_t tl_device_h2d [3];
  tlul_pkg::tl_d2h_t tl_device_d2h [3];

  logic [31:0] gpio_irq;
  logic [8:0]  uart_irq;

  prim_alert_pkg::alert_rx_t [uart_reg_pkg::NumAlerts-1:0] uart_alert_rx;
  prim_alert_pkg::alert_tx_t [uart_reg_pkg::NumAlerts-1:0] uart_alert_tx;
  prim_alert_pkg::alert_rx_t [gpio_reg_pkg::NumAlerts-1:0] gpio_alert_rx;
  prim_alert_pkg::alert_tx_t [gpio_reg_pkg::NumAlerts-1:0] gpio_alert_tx;
  prim_alert_pkg::alert_rx_t [rv_timer_reg_pkg::NumAlerts-1:0] timer_alert_rx;
  prim_alert_pkg::alert_tx_t [rv_timer_reg_pkg::NumAlerts-1:0] timer_alert_tx;

  assign core_instr_addr_o = instr_addr;
  assign data_is_mmio = data_addr[31:18] == 14'h1000;
  assign mmio_select = data_addr[17:16];

  assign data_gnt = data_is_mmio ? mmio_gnt : ram_data_gnt;
  assign data_rvalid = ram_data_rvalid | mmio_rvalid;
  assign data_rdata = mmio_rvalid ? mmio_rdata : ram_data_rdata;
  assign data_rdata_intg = mmio_rvalid ? mmio_rdata_intg : '0;
  assign data_err = mmio_rvalid & mmio_err;

  assign uart_alert_rx = '{default: prim_alert_pkg::ALERT_RX_DEFAULT};
  assign gpio_alert_rx = '{default: prim_alert_pkg::ALERT_RX_DEFAULT};
  assign timer_alert_rx = '{default: prim_alert_pkg::ALERT_RX_DEFAULT};

  ibex_top #(
    .RegFile   (ibex_pkg::RegFileFF),
    .ICache    (1'b0),
    .SecureIbex(1'b0),
    .MemECC    (1'b0)
  ) u_ibex (
    .clk_i,
    .rst_ni,
    .test_en_i                  (1'b0),
    .ram_cfg_icache_tag_i       (prim_ram_1p_pkg::RAM_1P_CFG_DEFAULT),
    .ram_cfg_rsp_icache_tag_o   (),
    .ram_cfg_icache_data_i      (prim_ram_1p_pkg::RAM_1P_CFG_DEFAULT),
    .ram_cfg_rsp_icache_data_o  (),
    .hart_id_i                  ('0),
    .boot_addr_i                ('0),
    .instr_req_o                (instr_req),
    .instr_gnt_i                (instr_gnt),
    .instr_rvalid_i             (instr_rvalid),
    .instr_addr_o               (instr_addr),
    .instr_rdata_i              (instr_rdata),
    .instr_rdata_intg_i         ('0),
    .instr_err_i                (1'b0),
    .data_req_o                 (data_req),
    .data_gnt_i                 (data_gnt),
    .data_rvalid_i              (data_rvalid),
    .data_we_o                  (data_we),
    .data_be_o                  (data_be),
    .data_addr_o                (data_addr),
    .data_wdata_o               (data_wdata),
    .data_wdata_intg_o          (data_wdata_intg),
    .data_rdata_i               (data_rdata),
    .data_rdata_intg_i          (data_rdata_intg),
    .data_err_i                 (data_err),
    .irq_software_i,
    .irq_timer_i                (timer_irq_o),
    .irq_external_i             (irq_external_i | (|gpio_irq) | (|uart_irq)),
    .irq_fast_i                 ('0),
    .irq_nm_i                   (1'b0),
    .scramble_key_valid_i       (1'b0),
    .scramble_key_i             ('0),
    .scramble_nonce_i           ('0),
    .scramble_req_o             (),
    .debug_req_i,
    .crash_dump_o               (),
    .double_fault_seen_o        (),
    .fetch_enable_i             (ibex_pkg::IbexMuBiOn),
    .alert_minor_o              (),
    .alert_major_internal_o     (),
    .alert_major_bus_o          (),
    .core_sleep_o               (),
    .scan_rst_ni                (rst_ni),
    .lockstep_cmp_en_o          (),
    .data_req_shadow_o          (),
    .data_we_shadow_o           (),
    .data_be_shadow_o           (),
    .data_addr_shadow_o         (),
    .data_wdata_shadow_o        (),
    .data_wdata_intg_shadow_o   (),
    .instr_req_shadow_o         (),
    .instr_addr_shadow_o        ()
  );

  ibex_ot_ram u_ram (
    .clk_i,
    .rst_ni,
    .instr_req_i    (instr_req),
    .instr_addr_i   (instr_addr),
    .instr_gnt_o    (instr_gnt),
    .instr_rvalid_o (instr_rvalid),
    .instr_rdata_o  (instr_rdata),
    .data_req_i     (data_req & ~data_is_mmio),
    .data_we_i      (data_we),
    .data_be_i      (data_be),
    .data_addr_i    (data_addr),
    .data_wdata_i   (data_wdata),
    .data_gnt_o     (ram_data_gnt),
    .data_rvalid_o  (ram_data_rvalid),
    .data_rdata_o   (ram_data_rdata)
  );

  tlul_adapter_host #(
    .MAX_REQS         (1),
    .EnableDataIntgGen(1'b1)
  ) u_data_adapter (
    .clk_i,
    .rst_ni,
    .req_i        (data_req & data_is_mmio),
    .gnt_o        (mmio_gnt),
    .addr_i       (data_addr),
    .we_i         (data_we),
    .wdata_i      (data_wdata),
    .wdata_intg_i (data_wdata_intg),
    .be_i         (data_be),
    .instr_type_i (prim_mubi_pkg::MuBi4False),
    .user_rsvd_i  ('0),
    .valid_o      (mmio_rvalid),
    .rdata_o      (mmio_rdata),
    .rdata_intg_o (mmio_rdata_intg),
    .err_o        (mmio_err),
    .intg_err_o   (unused_mmio_intg_err),
    .tl_o         (tl_host_h2d),
    .tl_i         (tl_host_d2h)
  );

  tlul_socket_1n #(
    .N           (3),
    .HReqDepth   (0),
    .HRspDepth   (0),
    .DReqDepth   ('0),
    .DRspDepth   ('0),
    .ExplicitErrs(1'b1)
  ) u_peripheral_socket (
    .clk_i,
    .rst_ni,
    .tl_h_i      (tl_host_h2d),
    .tl_h_o      (tl_host_d2h),
    .tl_d_o      (tl_device_h2d),
    .tl_d_i      (tl_device_d2h),
    .dev_select_i(mmio_select)
  );

  uart u_uart (
    .clk_i,
    .rst_ni,
    .tl_i                  (tl_device_h2d[0]),
    .tl_o                  (tl_device_d2h[0]),
    .alert_rx_i            (uart_alert_rx),
    .alert_tx_o            (uart_alert_tx),
    .racl_policies_i       (top_racl_pkg::RACL_POLICY_VEC_DEFAULT),
    .racl_error_o          (),
    .lsio_trigger_o        (),
    .cio_rx_i              (uart_rx_i),
    .cio_tx_o              (uart_tx_o),
    .cio_tx_en_o           (uart_tx_en_o),
    .intr_tx_watermark_o   (uart_irq[0]),
    .intr_tx_empty_o       (uart_irq[1]),
    .intr_rx_watermark_o   (uart_irq[2]),
    .intr_tx_done_o        (uart_irq[3]),
    .intr_rx_overflow_o    (uart_irq[4]),
    .intr_rx_frame_err_o   (uart_irq[5]),
    .intr_rx_break_err_o   (uart_irq[6]),
    .intr_rx_timeout_o     (uart_irq[7]),
    .intr_rx_parity_err_o  (uart_irq[8])
  );

  gpio u_gpio (
    .clk_i,
    .rst_ni,
    .strap_en_i      (strap_en_i),
    .sampled_straps_o(),
    .tl_i            (tl_device_h2d[1]),
    .tl_o            (tl_device_d2h[1]),
    .intr_gpio_o     (gpio_irq),
    .alert_rx_i      (gpio_alert_rx),
    .alert_tx_o      (gpio_alert_tx),
    .racl_policies_i (top_racl_pkg::RACL_POLICY_VEC_DEFAULT),
    .racl_error_o    (),
    .cio_gpio_i      (gpio_i),
    .cio_gpio_o      (gpio_o),
    .cio_gpio_en_o   (gpio_oe_o)
  );

  rv_timer u_rv_timer (
    .clk_i,
    .rst_ni,
    .tl_i                               (tl_device_h2d[2]),
    .tl_o                               (tl_device_d2h[2]),
    .alert_rx_i                         (timer_alert_rx),
    .alert_tx_o                         (timer_alert_tx),
    .racl_policies_i                    (top_racl_pkg::RACL_POLICY_VEC_DEFAULT),
    .racl_error_o                       (),
    .intr_timer_expired_hart0_timer0_o  (timer_irq_o)
  );
endmodule
