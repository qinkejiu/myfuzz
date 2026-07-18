// Auto-generated dependency-free bulk IP models for AutoTop material testing.

module bulk_mmio_irq_model #(
  parameter logic [31:0] ID = 32'h0
) (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  logic [31:0] ctrl_q, data_q, status_q, count_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      ctrl_q <= 32'h0;
      data_q <= ID;
      status_q <= 32'h0;
      count_q <= 32'h0;
    end else begin
      count_q <= count_q + 1'b1;
      status_q[0] <= ctrl_q[0] & count_q[3];
      status_q[31:16] <= ID[15:0];
      if (req_i && we_i) begin
        unique case (addr_i[5:2])
          4'h0: ctrl_q <= wdata_i;
          4'h1: data_q <= wdata_i ^ ID;
          4'h2: status_q <= status_q & ~wdata_i;
          default: data_q <= data_q + wdata_i + ID;
        endcase
      end
    end
  end
  always_comb begin
    unique case (addr_i[5:2])
      4'h0: rdata_o = ctrl_q;
      4'h1: rdata_o = data_q;
      4'h2: rdata_o = status_q;
      4'h3: rdata_o = count_q;
      default: rdata_o = ID;
    endcase
  end
  assign irq_o = ctrl_q[1] && status_q[0];
endmodule

module ti_adc128s022_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000001)) u_model (.*);
endmodule

module maxim_max11100_adc_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000002)) u_model (.*);
endmodule

module xilinx_xadc_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000003)) u_model (.*);
endmodule

module ads8688_adc_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000004)) u_model (.*);
endmodule

module ac97_controller_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000005)) u_model (.*);
endmodule

module spdif_tx_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000006)) u_model (.*);
endmodule

module wm8731_i2s_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000007)) u_model (.*);
endmodule

module soundwire_master_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000008)) u_model (.*);
endmodule

module ov7670_camera_if_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000009)) u_model (.*);
endmodule

module mipi_csi2_rx_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000000a)) u_model (.*);
endmodule

module arducam_controller_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000000b)) u_model (.*);
endmodule

module cmos_camera_if_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000000c)) u_model (.*);
endmodule

module canopen_controller_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000000d)) u_model (.*);
endmodule

module bosch_mcan_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000000e)) u_model (.*);
endmodule

module sja1000_can_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000000f)) u_model (.*);
endmodule

module ctucanfd_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000010)) u_model (.*);
endmodule

module rocket_clint_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000011)) u_model (.*);
endmodule

module litex_clint_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000012)) u_model (.*);
endmodule

module pulp_timer_clint_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000013)) u_model (.*);
endmodule

module riscv_aclint_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000014)) u_model (.*);
endmodule

module chacha20_accel_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000015)) u_model (.*);
endmodule

module sha256_accel_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000016)) u_model (.*);
endmodule

module arm_coresight_apb_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000017)) u_model (.*);
endmodule

module openocd_jtag_bridge_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000018)) u_model (.*);
endmodule

module dmi_debug_rom_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000019)) u_model (.*);
endmodule

module hdmi_tx_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000001a)) u_model (.*);
endmodule

module vga_controller_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000001b)) u_model (.*);
endmodule

module displayport_tx_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000001c)) u_model (.*);
endmodule

module lcd_tft_controller_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000001d)) u_model (.*);
endmodule

module axi_dma_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000001e)) u_model (.*);
endmodule

module xdma_engine_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000001f)) u_model (.*);
endmodule

module mchan_dma_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000020)) u_model (.*);
endmodule

module litex_dma_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000021)) u_model (.*);
endmodule

module litex_ethmac_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000022)) u_model (.*);
endmodule

module opencores_ethmac_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000023)) u_model (.*);
endmodule

module greth_gbit_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000024)) u_model (.*);
endmodule

module xgbe_mac_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000025)) u_model (.*);
endmodule

module spi_nor_flash_ctrl_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000026)) u_model (.*);
endmodule

module litex_spiflash_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000027)) u_model (.*);
endmodule

module openmtd_nand_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000028)) u_model (.*);
endmodule

module hyperflash_ctrl_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000029)) u_model (.*);
endmodule

module opencores_i2c_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000002a)) u_model (.*);
endmodule

module litex_i2c_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000002b)) u_model (.*);
endmodule

module i2c_master_top_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000002c)) u_model (.*);
endmodule

module cadence_i3c_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000002d)) u_model (.*);
endmodule

module synopsys_i3c_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000002e)) u_model (.*);
endmodule

module mipi_i3c_hci_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000002f)) u_model (.*);
endmodule

module open_i3c_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000030)) u_model (.*);
endmodule

module riscv_iommu_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000031)) u_model (.*);
endmodule

module arm_smmu_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000032)) u_model (.*);
endmodule

module intel_vtd_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000033)) u_model (.*);
endmodule

module amd_iommu_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000034)) u_model (.*);
endmodule

module arm_mhu_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000035)) u_model (.*);
endmodule

module mbox_controller_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000036)) u_model (.*);
endmodule

module opencores_mailbox_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000037)) u_model (.*);
endmodule

module rpmsg_mailbox_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000038)) u_model (.*);
endmodule

module litepcie_endpoint_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000039)) u_model (.*);
endmodule

module xilinx_pcie_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000003a)) u_model (.*);
endmodule

module alcor_pcie_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000003b)) u_model (.*);
endmodule

module nvme_pcie_ep_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000003c)) u_model (.*);
endmodule

module rocket_plic_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000003d)) u_model (.*);
endmodule

module sifive_plic_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000003e)) u_model (.*);
endmodule

module litex_plic_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000003f)) u_model (.*);
endmodule

module pulp_irq_ctrl_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000040)) u_model (.*);
endmodule

module litex_pwm_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000041)) u_model (.*);
endmodule

module opencores_pwm_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000042)) u_model (.*);
endmodule

module servo_pwm_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000043)) u_model (.*);
endmodule

module opentitan_entropy_src_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000044)) u_model (.*);
endmodule

module avalanche_rng_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000045)) u_model (.*);
endmodule

module trng90b_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000046)) u_model (.*);
endmodule

module litex_trng_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000047)) u_model (.*);
endmodule

module litex_sdcard_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000048)) u_model (.*);
endmodule

module sdhci_controller_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000049)) u_model (.*);
endmodule

module opencores_sdc_controller_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000004a)) u_model (.*);
endmodule

module cadence_sdmmc_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000004b)) u_model (.*);
endmodule

module bmi160_sensor_hub_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000004c)) u_model (.*);
endmodule

module lis3dh_sensor_if_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000004d)) u_model (.*);
endmodule

module bme280_sensor_if_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000004e)) u_model (.*);
endmodule

module max30102_sensor_if_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h0000004f)) u_model (.*);
endmodule

module opencores_spi_master_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000050)) u_model (.*);
endmodule

module ahci_sata_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000051)) u_model (.*);
endmodule

module nvme_controller_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000052)) u_model (.*);
endmodule

module virtio_blk_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000053)) u_model (.*);
endmodule

module ata_controller_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000054)) u_model (.*);
endmodule

module opencores_usbhost_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000055)) u_model (.*);
endmodule

module usb_ohci_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000056)) u_model (.*);
endmodule

module usb_ehci_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000057)) u_model (.*);
endmodule

module usb_xhci_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,
  output logic        irq_o
);
  bulk_mmio_irq_model #(.ID(32'h00000058)) u_model (.*);
endmodule
