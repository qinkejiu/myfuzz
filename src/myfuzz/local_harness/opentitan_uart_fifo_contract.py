"""Pinned passive UART RX/FIFO, TL-UL and native interrupt measurements.

The original scalar wrapper is unchanged. Measurements do not themselves
establish admitted frame origins or CPU interrupt causality.
"""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
from types import MappingProxyType
from myfuzz.composition.component_profile import load_component_profile

UART_FIFO_PROFILE = 'configs/peripherals/opentitan_uart_fifo_local/component_profile.json'
_PROFILE_SHA256 = 'e4204b40e2369635c956da51301cfeff3348ab6370515c55440c52a90f282d11'
_CLOSURE_SHA256 = 'a056c107fbe5b707d639da4314b71e8f9b3d44a5403398804a7f87942a586290'
UART_FIFO_PROBES = MappingProxyType({'sync_intq': (1, 'u_component.u_dut.u_uart.uart_core.sync_rx.intq'),
 'sync_input': (1, 'u_component.u_dut.u_uart.uart_core.sync_rx.d_o'),
 'rx_sync': (1, 'u_component.u_dut.u_uart.uart_core.rx_sync'),
 'rx_sync_q1': (1, 'u_component.u_dut.u_uart.uart_core.rx_sync_q1'),
 'rx_sync_q2': (1, 'u_component.u_dut.u_uart.uart_core.rx_sync_q2'),
 'rx_in_mx': (1, 'u_component.u_dut.u_uart.uart_core.rx_in_mx'),
 'rx_in_maj': (1, 'u_component.u_dut.u_uart.uart_core.rx_in_maj'),
 'rx_in': (1, 'u_component.u_dut.u_uart.uart_core.rx_in'),
 'tx_out': (1, 'u_component.u_dut.u_uart.uart_core.tx_out'),
 'rx_enable': (1, 'u_component.u_dut.u_uart.uart_core.rx_enable'),
 'rxnf_enable': (1, 'u_component.u_dut.u_uart.uart_core.rxnf_enable'),
 'sys_loopback': (1, 'u_component.u_dut.u_uart.uart_core.sys_loopback'),
 'line_loopback': (1, 'u_component.u_dut.u_uart.uart_core.line_loopback'),
 'parity_en': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.ctrl.parity_en.q'),
 'parity_odd': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.ctrl.parity_odd.q'),
 'nco': (16, 'u_component.u_dut.u_uart.uart_core.reg2hw.ctrl.nco.q'),
 'nco_sum': (17, 'u_component.u_dut.u_uart.uart_core.nco_sum_q'),
 'tick_baud_x16': (1, 'u_component.u_dut.u_uart.uart_core.tick_baud_x16'),
 'rx_valid': (1, 'u_component.u_dut.u_uart.uart_core.rx_valid'),
 'rx_data': (8, 'u_component.u_dut.u_uart.uart_core.rx_fifo_data'),
 'frame_err': (1, 'u_component.u_dut.u_uart.uart_core.event_rx_frame_err'),
 'parity_err': (1, 'u_component.u_dut.u_uart.uart_core.event_rx_parity_err'),
 'fifo_wvalid': (1, 'u_component.u_dut.u_uart.uart_core.rx_fifo_wvalid'),
 'fifo_wready': (1, 'u_component.u_dut.u_uart.uart_core.rx_fifo_wready'),
 'fifo_rvalid': (1, 'u_component.u_dut.u_uart.uart_core.rx_fifo_rvalid'),
 'fifo_rdata_re': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.rdata.re'),
 'fifo_data': (8, 'u_component.u_dut.u_uart.uart_core.rx_fifo_data'),
 'fifo_head': (8, 'u_component.u_dut.u_uart.uart_core.uart_rdata'),
 'fifo_depth': (7, 'u_component.u_dut.u_uart.uart_core.rx_fifo_depth'),
 'fifo_clear': (1, 'u_component.u_dut.u_uart.uart_core.uart_fifo_rxrst'),
 'watermark_threshold': (7, 'u_component.u_dut.u_uart.uart_core.rx_watermark_thresh'),
 'watermark_level': (3, 'u_component.u_dut.u_uart.uart_core.uart_fifo_rxilvl'),
 'timeout_enable': (1, 'u_component.u_dut.u_uart.uart_core.uart_rxto_en'),
 'timeout_limit': (24, 'u_component.u_dut.u_uart.uart_core.uart_rxto_val'),
 'timeout_count': (24, 'u_component.u_dut.u_uart.uart_core.rx_timeout_count_q'),
 'break_state': (1, 'u_component.u_dut.u_uart.uart_core.break_st_q'),
 'break_count': (5, 'u_component.u_dut.u_uart.uart_core.allzero_cnt_q'),
 'break_level': (2, 'u_component.u_dut.u_uart.uart_core.reg2hw.ctrl.rxblvl.q'),
 'watermark_test': (1, 'u_component.u_dut.u_uart.uart_core.intr_hw_rx_watermark.g_intr_status.test_q'),
 'idle': (1, 'u_component.u_dut.u_uart.uart_core.uart_rx.idle_q'),
 'bit_cnt': (4, 'u_component.u_dut.u_uart.uart_core.uart_rx.bit_cnt_q'),
 'baud_div': (4, 'u_component.u_dut.u_uart.uart_core.uart_rx.baud_div_q'),
 'tick_baud': (1, 'u_component.u_dut.u_uart.uart_core.uart_rx.tick_baud_q'),
 'sreg': (11, 'u_component.u_dut.u_uart.uart_core.uart_rx.sreg_q'),
 'fifo_wptr': (6, 'u_component.u_dut.u_uart.uart_core.u_uart_rxfifo.gen_normal_fifo.fifo_wptr'),
 'fifo_rptr': (6, 'u_component.u_dut.u_uart.uart_core.u_uart_rxfifo.gen_normal_fifo.fifo_rptr'),
 'fifo_under_rst': (1, 'u_component.u_dut.u_uart.uart_core.u_uart_rxfifo.gen_normal_fifo.under_rst'),
 'fifo_incr_wptr': (1, 'u_component.u_dut.u_uart.uart_core.u_uart_rxfifo.gen_normal_fifo.fifo_incr_wptr'),
 'fifo_incr_rptr': (1, 'u_component.u_dut.u_uart.uart_core.u_uart_rxfifo.gen_normal_fifo.fifo_incr_rptr'),
 'reg_addr': (6, 'u_component.u_dut.u_uart.u_reg.reg_addr'),
 'reg_re': (1, 'u_component.u_dut.u_uart.u_reg.reg_re'),
 'reg_we': (1, 'u_component.u_dut.u_uart.u_reg.reg_we'),
 'reg_wdata': (32, 'u_component.u_dut.u_uart.u_reg.reg_wdata'),
 'reg_be': (4, 'u_component.u_dut.u_uart.u_reg.reg_be'),
 'reg_error': (1, 'u_component.u_dut.u_uart.u_reg.reg_error'),
 'reg_rdata_re': (1, 'u_component.u_dut.u_uart.u_reg.rdata_re'),
 'reg_rdata': (32, 'u_component.u_dut.u_uart.u_reg.reg_rdata'),
 'intr_state_we': (1, 'u_component.u_dut.u_uart.u_reg.intr_state_we'),
 'intr_enable_we': (1, 'u_component.u_dut.u_uart.u_reg.intr_enable_we'),
 'intr_test_we': (1, 'u_component.u_dut.u_uart.u_reg.intr_test_we'),
 'a_accept': (1, 'u_component.u_dut.u_uart.u_reg.u_reg_if.a_ack'),
 'd_accept': (1, 'u_component.u_dut.u_uart.u_reg.u_reg_if.d_ack'),
 'captured_rdata': (32, 'u_component.u_dut.u_uart.u_reg.u_reg_if.rdata_q'),
 'captured_source': (8, 'u_component.u_dut.u_uart.u_reg.u_reg_if.reqid_q'),
 'captured_error': (1, 'u_component.u_dut.u_uart.u_reg.u_reg_if.error_q'),
 'outstanding': (1, 'u_component.u_dut.u_uart.u_reg.u_reg_if.outstanding_q'),
 'access_internal_error': (1, 'u_component.u_dut.u_uart.u_reg.u_reg_if.err_internal'),
 'tl_a_valid': (1, 'u_component.u_dut.u_uart.tl_i.a_valid'),
 'tl_a_opcode': (3, 'u_component.u_dut.u_uart.tl_i.a_opcode'),
 'tl_a_address': (32, 'u_component.u_dut.u_uart.tl_i.a_address'),
 'tl_a_mask': (4, 'u_component.u_dut.u_uart.tl_i.a_mask'),
 'tl_a_data': (32, 'u_component.u_dut.u_uart.tl_i.a_data'),
 'tl_a_source': (8, 'u_component.u_dut.u_uart.tl_i.a_source'),
 'tl_a_size': (2, 'u_component.u_dut.u_uart.tl_i.a_size'),
 'tl_d_ready': (1, 'u_component.u_dut.u_uart.tl_i.d_ready'),
 'tl_a_ready': (1, 'u_component.u_dut.u_uart.tl_o.a_ready'),
 'tl_d_valid': (1, 'u_component.u_dut.u_uart.tl_o.d_valid'),
 'tl_d_opcode': (3, 'u_component.u_dut.u_uart.tl_o.d_opcode'),
 'tl_d_data': (32, 'u_component.u_dut.u_uart.tl_o.d_data'),
 'tl_d_source': (8, 'u_component.u_dut.u_uart.tl_o.d_source'),
 'tl_d_error': (1, 'u_component.u_dut.u_uart.tl_o.d_error'),
 'tl_d_size': (2, 'u_component.u_dut.u_uart.tl_o.d_size'),
 'event_tx_watermark': (1, 'u_component.u_dut.u_uart.uart_core.event_tx_watermark'),
 'irq_tx_watermark': (1, 'u_component.u_dut.u_uart.uart_core.intr_tx_watermark_o'),
 'intr_state_tx_watermark': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_state.tx_watermark.q'),
 'intr_enable_tx_watermark': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_enable.tx_watermark.q'),
 'intr_test_tx_watermark': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_test.tx_watermark.q'),
 'intr_test_qe_tx_watermark': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_test.tx_watermark.qe'),
 'hw_state_de_tx_watermark': (1, 'u_component.u_dut.u_uart.uart_core.hw2reg.intr_state.tx_watermark.de'),
 'hw_state_d_tx_watermark': (1, 'u_component.u_dut.u_uart.uart_core.hw2reg.intr_state.tx_watermark.d'),
 'event_rx_watermark': (1, 'u_component.u_dut.u_uart.uart_core.event_rx_watermark'),
 'irq_rx_watermark': (1, 'u_component.u_dut.u_uart.uart_core.intr_rx_watermark_o'),
 'intr_state_rx_watermark': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_state.rx_watermark.q'),
 'intr_enable_rx_watermark': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_enable.rx_watermark.q'),
 'intr_test_rx_watermark': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_test.rx_watermark.q'),
 'intr_test_qe_rx_watermark': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_test.rx_watermark.qe'),
 'hw_state_de_rx_watermark': (1, 'u_component.u_dut.u_uart.uart_core.hw2reg.intr_state.rx_watermark.de'),
 'hw_state_d_rx_watermark': (1, 'u_component.u_dut.u_uart.uart_core.hw2reg.intr_state.rx_watermark.d'),
 'event_tx_done': (1, 'u_component.u_dut.u_uart.uart_core.event_tx_done'),
 'irq_tx_done': (1, 'u_component.u_dut.u_uart.uart_core.intr_tx_done_o'),
 'intr_state_tx_done': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_state.tx_done.q'),
 'intr_enable_tx_done': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_enable.tx_done.q'),
 'intr_test_tx_done': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_test.tx_done.q'),
 'intr_test_qe_tx_done': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_test.tx_done.qe'),
 'hw_state_de_tx_done': (1, 'u_component.u_dut.u_uart.uart_core.hw2reg.intr_state.tx_done.de'),
 'hw_state_d_tx_done': (1, 'u_component.u_dut.u_uart.uart_core.hw2reg.intr_state.tx_done.d'),
 'event_rx_overflow': (1, 'u_component.u_dut.u_uart.uart_core.event_rx_overflow'),
 'irq_rx_overflow': (1, 'u_component.u_dut.u_uart.uart_core.intr_rx_overflow_o'),
 'intr_state_rx_overflow': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_state.rx_overflow.q'),
 'intr_enable_rx_overflow': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_enable.rx_overflow.q'),
 'intr_test_rx_overflow': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_test.rx_overflow.q'),
 'intr_test_qe_rx_overflow': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_test.rx_overflow.qe'),
 'hw_state_de_rx_overflow': (1, 'u_component.u_dut.u_uart.uart_core.hw2reg.intr_state.rx_overflow.de'),
 'hw_state_d_rx_overflow': (1, 'u_component.u_dut.u_uart.uart_core.hw2reg.intr_state.rx_overflow.d'),
 'event_rx_frame_err': (1, 'u_component.u_dut.u_uart.uart_core.event_rx_frame_err'),
 'irq_rx_frame_err': (1, 'u_component.u_dut.u_uart.uart_core.intr_rx_frame_err_o'),
 'intr_state_rx_frame_err': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_state.rx_frame_err.q'),
 'intr_enable_rx_frame_err': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_enable.rx_frame_err.q'),
 'intr_test_rx_frame_err': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_test.rx_frame_err.q'),
 'intr_test_qe_rx_frame_err': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_test.rx_frame_err.qe'),
 'hw_state_de_rx_frame_err': (1, 'u_component.u_dut.u_uart.uart_core.hw2reg.intr_state.rx_frame_err.de'),
 'hw_state_d_rx_frame_err': (1, 'u_component.u_dut.u_uart.uart_core.hw2reg.intr_state.rx_frame_err.d'),
 'event_rx_break_err': (1, 'u_component.u_dut.u_uart.uart_core.event_rx_break_err'),
 'irq_rx_break_err': (1, 'u_component.u_dut.u_uart.uart_core.intr_rx_break_err_o'),
 'intr_state_rx_break_err': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_state.rx_break_err.q'),
 'intr_enable_rx_break_err': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_enable.rx_break_err.q'),
 'intr_test_rx_break_err': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_test.rx_break_err.q'),
 'intr_test_qe_rx_break_err': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_test.rx_break_err.qe'),
 'hw_state_de_rx_break_err': (1, 'u_component.u_dut.u_uart.uart_core.hw2reg.intr_state.rx_break_err.de'),
 'hw_state_d_rx_break_err': (1, 'u_component.u_dut.u_uart.uart_core.hw2reg.intr_state.rx_break_err.d'),
 'event_rx_timeout': (1, 'u_component.u_dut.u_uart.uart_core.event_rx_timeout'),
 'irq_rx_timeout': (1, 'u_component.u_dut.u_uart.uart_core.intr_rx_timeout_o'),
 'intr_state_rx_timeout': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_state.rx_timeout.q'),
 'intr_enable_rx_timeout': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_enable.rx_timeout.q'),
 'intr_test_rx_timeout': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_test.rx_timeout.q'),
 'intr_test_qe_rx_timeout': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_test.rx_timeout.qe'),
 'hw_state_de_rx_timeout': (1, 'u_component.u_dut.u_uart.uart_core.hw2reg.intr_state.rx_timeout.de'),
 'hw_state_d_rx_timeout': (1, 'u_component.u_dut.u_uart.uart_core.hw2reg.intr_state.rx_timeout.d'),
 'event_rx_parity_err': (1, 'u_component.u_dut.u_uart.uart_core.event_rx_parity_err'),
 'irq_rx_parity_err': (1, 'u_component.u_dut.u_uart.uart_core.intr_rx_parity_err_o'),
 'intr_state_rx_parity_err': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_state.rx_parity_err.q'),
 'intr_enable_rx_parity_err': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_enable.rx_parity_err.q'),
 'intr_test_rx_parity_err': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_test.rx_parity_err.q'),
 'intr_test_qe_rx_parity_err': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_test.rx_parity_err.qe'),
 'hw_state_de_rx_parity_err': (1, 'u_component.u_dut.u_uart.uart_core.hw2reg.intr_state.rx_parity_err.de'),
 'hw_state_d_rx_parity_err': (1, 'u_component.u_dut.u_uart.uart_core.hw2reg.intr_state.rx_parity_err.d'),
 'event_tx_empty': (1, 'u_component.u_dut.u_uart.uart_core.event_tx_empty'),
 'irq_tx_empty': (1, 'u_component.u_dut.u_uart.uart_core.intr_tx_empty_o'),
 'intr_state_tx_empty': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_state.tx_empty.q'),
 'intr_enable_tx_empty': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_enable.tx_empty.q'),
 'intr_test_tx_empty': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_test.tx_empty.q'),
 'intr_test_qe_tx_empty': (1, 'u_component.u_dut.u_uart.uart_core.reg2hw.intr_test.tx_empty.qe'),
 'hw_state_de_tx_empty': (1, 'u_component.u_dut.u_uart.uart_core.hw2reg.intr_state.tx_empty.de'),
 'hw_state_d_tx_empty': (1, 'u_component.u_dut.u_uart.uart_core.hw2reg.intr_state.tx_empty.d')})
_SOURCE_HASHES = {'third_party/soc-opentitan/hw/ip/prim/rtl/prim_alert_pkg.sv': '32d9e1647d61bab570c41c5d61b7464c29925c9d38f03d0648b626e8ce42c1f4',
 'third_party/soc-opentitan/hw/ip/prim/rtl/prim_count_pkg.sv': '8e465ed25b7d59f29faf0f315243a774cf0e50d178ec2068d8c71983cb2f18df',
 'third_party/soc-opentitan/hw/ip/prim/rtl/prim_mubi_pkg.sv': '11a2f1a16ddaf750d859c95e07fc48c54743fe6ad3b5c5eabe2e14a51d9fb1af',
 'third_party/soc-opentitan/hw/ip/prim/rtl/prim_secded_pkg.sv': 'bcbd03333a30e7a1cb01195d1c40c7d0e736f91d9f73c2347ef5b0bd9dc3c82b',
 'third_party/soc-opentitan/hw/ip/prim/rtl/prim_subreg_pkg.sv': 'a38c3243535348fb4b0e5d233c0baa89eea3588b976d8bb050c7de4a2fd09bf0',
 'third_party/soc-opentitan/hw/ip/prim/rtl/prim_util_pkg.sv': 'f71235ef5b92eaa3d2ed5c676f76108082df93b8aae8f9baa816584d1d285208',
 'third_party/soc-opentitan/hw/ip/uart/rtl/uart_reg_pkg.sv': '106f8da3d41f8cfe585a58e91c251e23e76c81d25956cb751f61644023dfa01b',
 'third_party/soc-opentitan/hw/top_earlgrey/rtl/top_pkg.sv': '5f8a0e366b9e6f300dc58552e693342173b4e0a716221b583a2a55550785b55f',
 'third_party/soc-opentitan/hw/ip/tlul/rtl/tlul_pkg.sv': 'c8b95a4457bc594031d6b28dec6ba58af44c94ba74580bcdc3ebe5549797040a',
 'third_party/soc-opentitan/hw/top_earlgrey/rtl/autogen/top_racl_pkg.sv': 'fd932f944025a1ab8f064fc03afeaafdae4fce3f3c69d40083b3ef206bebaf7f',
 'third_party/soc-opentitan/hw/ip/prim/rtl/prim_alert_sender.sv': '288561001fd344dffb0d935cf85de264ca16e1296f1f30fdc8386659a9683b98',
 'third_party/soc-opentitan/hw/ip/prim/rtl/prim_count.sv': 'b48580aefff674a48a674489c9b21a98d5399ca5b4c7623f3a7c907a75d8f0cb',
 'third_party/soc-opentitan/hw/ip/prim/rtl/prim_diff_decode.sv': 'e3ed6f83329589eed061c893d8b9ad1e00e975e23e9347ed31f68b50f0822d6d',
 'third_party/soc-opentitan/hw/ip/prim/rtl/prim_fifo_sync.sv': '2655befe56a70ee672c2f1259a82ef2beb2adf429ed0405bcf26bea7c4de3630',
 'third_party/soc-opentitan/hw/ip/prim/rtl/prim_fifo_sync_cnt.sv': '33b87939c31a6d71ccd2fe005e5a5dcaaeb343990f9425568cb8686def9f4fb7',
 'third_party/soc-opentitan/hw/ip/prim/rtl/prim_intr_hw.sv': '2fb312f9db786982dd4c2bb656f9ba7862637b045dd704ea128a4ce6a4a1f8bc',
 'third_party/soc-opentitan/hw/ip/prim/rtl/prim_onehot_check.sv': '97aefa2e7ebd26e12ea9fc691908a62315e2135bdbb127f3c3d640eeb15096ca',
 'third_party/soc-opentitan/hw/ip/prim/rtl/prim_onehot_enc.sv': 'e9a65c74e4478063ea00fc3d80eaff214fdbacfe07e91f13f28ceb725e5ad362',
 'third_party/soc-opentitan/hw/ip/prim/rtl/prim_reg_we_check.sv': '0f38519d831f24bb9a1afc1041f6840eb42187a958788a5256aa0c698819af4a',
 'third_party/soc-opentitan/hw/ip/prim/rtl/prim_sec_anchor_buf.sv': '073be7f3daa8a738add627e1055704cc94d82cfb8ff11f6952c644abde20c702',
 'third_party/soc-opentitan/hw/ip/prim/rtl/prim_sec_anchor_flop.sv': '7bb3cb240164715f3956831e35e95f1a3e7e901deae02cc1297669318986d7bf',
 'third_party/soc-opentitan/hw/ip/prim/rtl/prim_secded_inv_39_32_dec.sv': 'f07f26fd2375952e4ec7cfc1641cebcea373a8030d82dd5977a76f81c430cb12',
 'third_party/soc-opentitan/hw/ip/prim/rtl/prim_secded_inv_39_32_enc.sv': '4588fda3fd5ebdd711c98f6900caaaaddddf1257337c5b931ca86de7fb0ef8ff',
 'third_party/soc-opentitan/hw/ip/prim/rtl/prim_secded_inv_64_57_dec.sv': 'e598eef60254ac4a0e6899f6d1e4af5ae5bbd2ac22395ac53ee925296bc8a826',
 'third_party/soc-opentitan/hw/ip/prim/rtl/prim_secded_inv_64_57_enc.sv': '74b3b327047b90682468614708bb4b1104b1f069c0dc3189e2b078622ac566b8',
 'third_party/soc-opentitan/hw/ip/prim/rtl/prim_subreg.sv': '25fb080996e7a9f1a8db6b827d57926850324e254c2758a921f4d67d13445992',
 'third_party/soc-opentitan/hw/ip/prim/rtl/prim_subreg_arb.sv': '16530c91931e97b25e33334bfc5942fd254324189115f942585f26f56d8ae758',
 'third_party/soc-opentitan/hw/ip/prim/rtl/prim_subreg_ext.sv': 'dc22ea14c164661970db2a76060fc54cbbe1d432534eaadce0caa8a3a2935ce5',
 'third_party/soc-opentitan/hw/ip/prim_generic/rtl/prim_buf.sv': '9b00bd8ac203169268262ac9337076781fa962b19beed36f28dde54e360aaaf5',
 'third_party/soc-opentitan/hw/ip/prim_generic/rtl/prim_flop.sv': '6645d657b107b024f9211d3a0134890d1e20146f68ba1772bf62575f7b4e5549',
 'third_party/soc-opentitan/hw/ip/prim_generic/rtl/prim_flop_2sync.sv': '5780aef67607c161eb8a4b3326757af5b416eb5337aef0afc457fdebf2891c53',
 'third_party/soc-opentitan/hw/ip/prim_generic/rtl/prim_xnor2.sv': 'ebdd3179c32a81303227775e3e6ef0afdf8959efebf7a6892d122d4bc6a776c7',
 'third_party/soc-opentitan/hw/ip/tlul/rtl/tlul_adapter_reg.sv': '6993b14697bc826c619793697ffaea382d4bba3775c23af3add25ad3914ef531',
 'third_party/soc-opentitan/hw/ip/tlul/rtl/tlul_cmd_intg_chk.sv': '1b56b9fca7e0b8643110622f6e9d5e6d8bb263bec923a5836748ba3b6f7f76ad',
 'third_party/soc-opentitan/hw/ip/tlul/rtl/tlul_data_integ_dec.sv': '0df25d94c03bef617e6ef309375c2d40cbc27719a0696fb1119ca53c3a68d2cb',
 'third_party/soc-opentitan/hw/ip/tlul/rtl/tlul_data_integ_enc.sv': '28567bc5483eddcf20b51890bc82497f32728b6a46b134a43c01f7180a14c7a9',
 'third_party/soc-opentitan/hw/ip/tlul/rtl/tlul_err.sv': '850cefc36e1a5c6f78161b8bf04786dc72138336a48edaf5ca92242690294462',
 'third_party/soc-opentitan/hw/ip/tlul/rtl/tlul_rsp_intg_gen.sv': '673bce2f23ef8e60f95f96f14bb3a71de6e88d788e12f0b3e89bc7125ed7e145',
 'third_party/soc-opentitan/hw/ip/uart/rtl/uart.sv': 'b2ea9b88abb25f8a7cdbe317dfc91e6b2b456647781d2bdc33ef384c526412a5',
 'third_party/soc-opentitan/hw/ip/uart/rtl/uart_core.sv': '4df7acad038cdb06f81e4b7681ddf3b0bc091eb38dae63c385812f980c47d0be',
 'third_party/soc-opentitan/hw/ip/uart/rtl/uart_reg_top.sv': '8c40c957fbd7c1155f58d2c7696340b7ea6b82c2b0626ec684463f991538ae27',
 'third_party/soc-opentitan/hw/ip/uart/rtl/uart_rx.sv': '08a72a3f045562eee419f42fe2abb4f68f3282b90bb0a6e268872fd39748782b',
 'third_party/soc-opentitan/hw/ip/uart/rtl/uart_tx.sv': '1cd4f59b8a58bb8e99c2a24081aae093f6528ac1887abb7cb5f31b911f949241',
 'src/myfuzz/composition/rtl/soc_opentitan_uart_local_target.sv': '5991b251cf20be9a447cd4ecab0ed0643b36f4f768451a21649e9a5fe687f68b'}

def _sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def uart_fifo_probe_document():
    return {
        'schema_version':'opentitan_uart_fifo_probe_contract.v1',
        'template_id':'opentitan.uart.rx_fifo','template_version':'1',
        'variant_id':'opentitan_uart_rx_fifo_v1',
        'source':{'root':'third_party/soc-opentitan',
                  'revision':'git:fca045df919a26c47e71616b9dac917b1ea4fd07',
                  'files_sha256':dict(_SOURCE_HASHES)},
        'hierarchy':'u_component.u_dut.u_uart',
        'parameters':{'EnableRacl':0,'RaclErrorRsp':0,'RxFifoDepth':64,
                      'Width':8,'Pass':False,'OutputZeroIfEmpty':True,'Secure':False,
                      'AccessLatency':0},
        'probes':{name:{'width':width,'expression':expression,
                        'physical_port':'uart_probe_'+name,'runtime_name':'probe_uart_'+name}
                  for name,(width,expression) in UART_FIFO_PROBES.items()},
        'sampling':'pre_post_rising',
        'cdc':{'SIMULATION':False,'input':'sync_rx.d_o','first':'sync_rx.intq','second':'rx_sync'},
        'receiver_semantics':'source_pinned_shift_samples',
        'fifo_semantics':{'push':'pre_wvalid_and_wready','pop':'pre_rvalid_and_rdata_re_and_not_under_rst',
                          'clear':'pointer_reset_wins_physical_write_may_occur',
                          'simultaneous':'pop_old_head_then_push','full_pop':'no_same_edge_write_credit'},
        'register_semantics':{'RDATA':{'offset':24,'read':'racl_addr_hit_read[6]&reg_re&!reg_error',
                                     'capture':'pre_reg_rdata_at_Aaccept','response':'captured_source_and_data'},
                              'INTR_STATE':{'offset':0,'event_w1c':'(de?d:old)&(we?~wd:all_ones)',
                                            'rx_watermark':'RO_status_with_test_q'},
                              'INTR_ENABLE':{'offset':4},'INTR_TEST':{'offset':8}},
        'interrupt_bits':{role:bit for bit,role in enumerate(['tx_watermark', 'rx_watermark', 'tx_done', 'rx_overflow', 'rx_frame_err', 'rx_break_err', 'rx_timeout', 'rx_parity_err', 'tx_empty'])},
        'irq_semantics':'flopped_status_or_sticky_event_and_enable',
    }

def uart_fifo_observation_contract():
    document=uart_fifo_probe_document()
    return {'schema_version':'uart_fifo_observation.v1',
            'template_id':'opentitan.uart.rx_fifo','template_version':'1',
            'variant_id':'opentitan_uart_rx_fifo_v1',
            'probe_manifest_sha256':_sha(document),
            'receiver_semantics':'source_pinned_shift_samples',
            'fifo_depth':64,'pass':False,'sampling':'pre_post_rising'}

def validate_uart_fifo_observation_contract(value):
    if _sha(value) != _sha(uart_fifo_observation_contract()):
        raise ValueError('uart-fifo-observation-contract-mismatch')

def validate_uart_fifo_probe_document(value):
    if _sha(value) != _sha(uart_fifo_probe_document()):
        raise ValueError('uart-fifo-probe-document-mismatch')

def verify_opentitan_uart_fifo_source_contract(profile, *, base_dir: Path):
    from .opentitan_uart_contract import verify_opentitan_uart_source_contract
    root=Path(base_dir).resolve()
    raw=(root/UART_FIFO_PROFILE).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=_PROFILE_SHA256:
        raise ValueError('uart-fifo-profile-changed')
    if (load_component_profile(json.loads(raw)) != profile
            or _sha(dict(profile.capabilities)) != _sha(json.loads(raw)['capabilities'])):
        raise ValueError('uart-fifo-profile-object-mismatch')
    original_path='configs/peripherals/opentitan_uart_local/component_profile.json'
    original=load_component_profile(json.loads((root/original_path).read_bytes()))
    if _sha(dict(profile.source_document)) != _sha(dict(original.source_document)):
        raise ValueError('uart-fifo-source-locator-mismatch')
    verified=verify_opentitan_uart_source_contract(original,base_dir=root)
    for name,digest in _SOURCE_HASHES.items():
        if hashlib.sha256((root/name).read_bytes()).hexdigest()!=digest:
            raise ValueError('uart-fifo-probe-source-changed:'+name)
    closure_path='configs/soc/closures/opentitan_uart_fifo_local.json'
    closure_raw=(root/closure_path).read_bytes()
    if hashlib.sha256(closure_raw).hexdigest()!=_CLOSURE_SHA256:
        raise ValueError('uart-fifo-closure-changed')
    closure=json.loads(closure_raw)
    validate_uart_fifo_probe_document(closure['passive_probe_manifest'])
    if closure['passive_probe_manifest_sha256'] != _sha(uart_fifo_probe_document()):
        raise ValueError('uart-fifo-closure-probe-manifest-mismatch')
    lock=json.loads((root/'configs/soc/sources.lock.json').read_bytes())
    expected=copy.deepcopy(next(row for row in lock['components'] if row['id']=='opentitan_uart'))
    expected['id']='opentitan_uart_fifo_local'
    expected['elaboration']['evidence']=closure_path
    expected['elaboration']['evidence_sha256']=_CLOSURE_SHA256
    expected['closure_note']=json.loads(closure_raw)['observation_note']
    if _sha([row for row in lock['components'] if row['id']=='opentitan_uart_fifo_local']) != _sha([expected]):
        raise ValueError('uart-fifo-variant-lock-mismatch')
    capture_paths=[UART_FIFO_PROFILE,original_path,closure_path,'configs/soc/closures/opentitan_uart.json',
                   'src/myfuzz/composition/rtl/soc_opentitan_uart_local_target.sv',
                   'src/myfuzz/local_harness/opentitan_uart_fifo_contract.py']
    return {**verified,'closure_sha256':_CLOSURE_SHA256,'profile_sha256':_PROFILE_SHA256,
            'uart_fifo_observation_contract':uart_fifo_observation_contract(),
            'uart_fifo_probe_contract_sha256':_sha(uart_fifo_probe_document()),
            'authenticated_inputs':[{'path':name,'sha256':hashlib.sha256((root/name).read_bytes()).hexdigest()}
                                    for name in capture_paths]}
