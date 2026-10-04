# Generated local wrapper evidence — 2026-10-04

This milestone produces deterministic structural SystemVerilog wrappers. It does not provide a C++ driver or Python session; Generated and runtime levels remain unproven. No transaction, ISA, interrupt servicing or behavioral validation is claimed.

## Verification

`PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_request tests.local_harness.test_plan tests.local_harness.test_renderer -q` passed 25 tests. `git diff --check` passed. Renderer tests include actual CVE2/PULP lint, full physical coverage, width >64, split aggregate ordering, reset polarity, unconnected output ledger, malformed coverage/direction/identifiers and missing/ambiguous parameter types.

Tool: Verilator 5.051 devel rev vUNKNOWN-built20260806-e413e67

JSON hashes below use UTF-8, sorted keys, separators `,` and `:`, `ensure_ascii=False`, no trailing newline. Wrapper hashes cover UTF-8 text including its final LF.

## cv32e20

- Profile: `configs/cpus/cv32e20/component_profile.json`
- Profile SHA-256: `18ef425486107690d2fb92bb80141cbfab4013b05768c8c2a5ee706fe223d7ec`
- Source revision: `git:d079e8c8e6a08b330940ae123876ba0612bec18d`
- Source content hash: `sha256:afe5ca029cc2ba2078bb7524475dc8061c32f88bcb91e197ae2861512c00b338`
- Plan SHA-256: `af5c32653555403a52dec99c647b802acc4b2e4217937555e68cc4c000a492e4`
- Wrapper SHA-256: `84db5687be8b3d6fbbc0509ba34e5176f4cbd4823df5da5a44b000a239d4b12d`
- ABI SHA-256: `63fcf8b0804551ea911fa1780682cd668a1dbfb13a25e62571b714e4517ab094`
- Build SHA-256: `3a9f0bd2cf5bf8fc48027c4fb83df1cb4fff1b4fd73af426def0004cd0a029e1`
- Physical ports: 70; physical input bits: 314; physical output bits: 994.
- Exposed ABI segments: 52; exposed input bits: 71; exposed output bits: 994.
- Parameters: `{"MHPMCounterNum": "10", "MHPMCounterWidth": "40", "RV32E": "0", "RV32M": "2", "XInterface": "0"}`
- Lint exit: 0; warnings: 94 (`COMBDLY=1, UNOPTFLAT=3, WIDTHEXPAND=45, WIDTHTRUNC=45`); no `%Error`.

Exact command (`WRAPPER` is the temporary wrapper path; run from repository root):

```sh
verilator --lint-only -Wno-fatal --top-module local_cpu_0 -Ithird_party/cv32e20_upstream_reference/rtl -Ithird_party/cv32e20_upstream_reference/vendor/lowrisc_ip/ip/prim/rtl -Ithird_party/cv32e20_upstream_reference/vendor/lowrisc_ip/dv/sv/dv_utils -DRVFI=1 third_party/cv32e20_upstream_reference/rtl/cve2_pkg.sv third_party/cv32e20_upstream_reference/rtl/cve2_tracer_pkg.sv third_party/cv32e20_upstream_reference/vendor/lowrisc_ip/ip/prim/rtl/prim_secded_pkg.sv third_party/cv32e20_upstream_reference/vendor/lowrisc_ip/ip/prim/rtl/prim_ram_1p_pkg.sv third_party/cv32e20_upstream_reference/rtl/cve2_alu.sv third_party/cv32e20_upstream_reference/rtl/cve2_compressed_decoder.sv third_party/cv32e20_upstream_reference/rtl/cve2_controller.sv third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv third_party/cv32e20_upstream_reference/rtl/cve2_csr.sv third_party/cv32e20_upstream_reference/rtl/cve2_counter.sv third_party/cv32e20_upstream_reference/rtl/cve2_decoder.sv third_party/cv32e20_upstream_reference/rtl/cve2_ex_block.sv third_party/cv32e20_upstream_reference/rtl/cve2_fetch_fifo.sv third_party/cv32e20_upstream_reference/rtl/cve2_id_stage.sv third_party/cv32e20_upstream_reference/rtl/cve2_if_stage.sv third_party/cv32e20_upstream_reference/rtl/cve2_load_store_unit.sv third_party/cv32e20_upstream_reference/rtl/cve2_multdiv_fast.sv third_party/cv32e20_upstream_reference/rtl/cve2_multdiv_slow.sv third_party/cv32e20_upstream_reference/rtl/cve2_prefetch_buffer.sv third_party/cv32e20_upstream_reference/rtl/cve2_pmp.sv third_party/cv32e20_upstream_reference/rtl/cve2_register_file_ff.sv third_party/cv32e20_upstream_reference/rtl/cve2_wb.sv third_party/cv32e20_upstream_reference/rtl/cve2_core.sv third_party/cv32e20_upstream_reference/rtl/cve2_top.sv third_party/cv32e20_upstream_reference/rtl/cve2_top_tracing.sv third_party/cv32e20_upstream_reference/rtl/cve2_tracer.sv third_party/cv32e20_upstream_reference/rtl/cve2_clock_gate.sv third_party/cv32e20_upstream_reference/rtl/cve2_branch_predict.sv "$WRAPPER"
```

Diagnostics:

```text
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:933:78: Logical operator COND expects 1 bit on the Conditional Test, but Conditional Test's VARREF 'UmodeEnabled' generates 32 bits.
                                                                                           : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
  933 |   localparam status_stk_t MSTACK_RESET_VAL = '{mpie: 1'b1, mpp: UmodeEnabled ? PRIV_LVL_U : PRIV_LVL_M};
      |                                                                              ^
                     ... For warning description see https://verilator.org/warn/WIDTHTRUNC?v=5.051
                     ... Use "/* verilator lint_off WIDTHTRUNC */" and lint_on around source to disable this message.
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1518:47: Operator OR expects 64 bits on the LHS, but LHS's VARREF 'csr_save_cause_i' generates 1 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1518 |     assign rvfi_csr_bypass = csr_save_cause_i | debug_csr_save_i;
      |                                               ^
                      ... For warning description see https://verilator.org/warn/WIDTHEXPAND?v=5.051
                      ... Use "/* verilator lint_off WIDTHEXPAND */" and lint_on around source to disable this message.
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1518:47: Operator OR expects 64 bits on the RHS, but RHS's VARREF 'debug_csr_save_i' generates 1 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1518 |     assign rvfi_csr_bypass = csr_save_cause_i | debug_csr_save_i;
      |                                               ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1535:24: Operator ASSIGN expects 64 bits on the Assign RHS, but Assign RHS's VARREF 'csr_addr_i' generates 12 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1535 |         rvfi_csr_addr  = csr_addr_i;
      |                        ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1536:24: Operator ASSIGN expects 64 bits on the Assign RHS, but Assign RHS's VARREF 'csr_rdata_int' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1536 |         rvfi_csr_rdata = csr_rdata_int;
      |                        ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1537:24: Operator ASSIGN expects 64 bits on the Assign RHS, but Assign RHS's VARREF 'csr_wdata_int' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1537 |         rvfi_csr_wdata = csr_wdata_int;
      |                        ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1562:44: Bit extraction of var[63:0] requires 6 bit index, not 12 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1562 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MSTATUS] = (!rvfi_csr_bypass) ? rvfi_mstatus_csr_rdata : mstatus_extended_read;
      |                                            ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1562:61: Logical operator LOGNOT expects 1 bit on the LHS, but LHS's VARREF 'rvfi_csr_bypass' generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1562 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MSTATUS] = (!rvfi_csr_bypass) ? rvfi_mstatus_csr_rdata : mstatus_extended_read;
      |                                                             ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1562:58: Operator ASSIGNW expects 1 bits on the Assign RHS, but Assign RHS's COND generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1562 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MSTATUS] = (!rvfi_csr_bypass) ? rvfi_mstatus_csr_rdata : mstatus_extended_read;
      |                                                          ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1563:44: Bit extraction of var[63:0] requires 6 bit index, not 12 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1563 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MIE] = (!rvfi_csr_bypass) ? rvfi_mie_csr_rdata : mie_extended_read;
      |                                            ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1563:57: Logical operator LOGNOT expects 1 bit on the LHS, but LHS's VARREF 'rvfi_csr_bypass' generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1563 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MIE] = (!rvfi_csr_bypass) ? rvfi_mie_csr_rdata : mie_extended_read;
      |                                                         ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1563:54: Operator ASSIGNW expects 1 bits on the Assign RHS, but Assign RHS's COND generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1563 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MIE] = (!rvfi_csr_bypass) ? rvfi_mie_csr_rdata : mie_extended_read;
      |                                                      ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1564:44: Bit extraction of var[63:0] requires 6 bit index, not 12 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1564 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MIP] = (!rvfi_csr_bypass) ? rvfi_mip_csr_rdata : mip_extended_read;
      |                                            ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1564:57: Logical operator LOGNOT expects 1 bit on the LHS, but LHS's VARREF 'rvfi_csr_bypass' generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1564 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MIP] = (!rvfi_csr_bypass) ? rvfi_mip_csr_rdata : mip_extended_read;
      |                                                         ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1564:54: Operator ASSIGNW expects 1 bits on the Assign RHS, but Assign RHS's COND generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1564 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MIP] = (!rvfi_csr_bypass) ? rvfi_mip_csr_rdata : mip_extended_read;
      |                                                      ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1565:44: Bit extraction of var[63:0] requires 6 bit index, not 12 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1565 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MISA] = (!rvfi_csr_bypass) ? rvfi_misa_csr_rdata : MISA_VALUE;
      |                                            ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1565:58: Logical operator LOGNOT expects 1 bit on the LHS, but LHS's VARREF 'rvfi_csr_bypass' generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1565 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MISA] = (!rvfi_csr_bypass) ? rvfi_misa_csr_rdata : MISA_VALUE;
      |                                                          ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1565:76: Operator COND expects 64 bits on the Conditional False, but Conditional False's VARREF 'MISA_VALUE' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1565 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MISA] = (!rvfi_csr_bypass) ? rvfi_misa_csr_rdata : MISA_VALUE;
      |                                                                            ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1565:55: Operator ASSIGNW expects 1 bits on the Assign RHS, but Assign RHS's COND generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1565 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MISA] = (!rvfi_csr_bypass) ? rvfi_misa_csr_rdata : MISA_VALUE;
      |                                                       ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1565:29: Operator ASSIGN expects 64 bits on the Assign RHS, but Assign RHS's VARREF 'MISA_VALUE' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1565 |         rvfi_misa_csr_rdata = MISA_VALUE;
      |                             ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1566:44: Bit extraction of var[63:0] requires 6 bit index, not 12 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1566 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MTVEC] = (!rvfi_csr_bypass) ? rvfi_mtvec_csr_rdata : mtvec_q;
      |                                            ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1566:59: Logical operator LOGNOT expects 1 bit on the LHS, but LHS's VARREF 'rvfi_csr_bypass' generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1566 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MTVEC] = (!rvfi_csr_bypass) ? rvfi_mtvec_csr_rdata : mtvec_q;
      |                                                           ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1566:77: Operator COND expects 64 bits on the Conditional False, but Conditional False's VARREF 'mtvec_q' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1566 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MTVEC] = (!rvfi_csr_bypass) ? rvfi_mtvec_csr_rdata : mtvec_q;
      |                                                                             ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1566:56: Operator ASSIGNW expects 1 bits on the Assign RHS, but Assign RHS's COND generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1566 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MTVEC] = (!rvfi_csr_bypass) ? rvfi_mtvec_csr_rdata : mtvec_q;
      |                                                        ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1566:77: Operator COND expects 64 bits on the Conditional False, but Conditional False's VARREF 'mtvec_d' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1566 |     assign rvfi_csr_if.rvfi_named_csr_wdata[CSR_MTVEC] = (!rvfi_csr_bypass) ? rvfi_mtvec_csr_wdata : mtvec_d;
      |                                                                             ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1566:30: Operator ASSIGN expects 64 bits on the Assign RHS, but Assign RHS's VARREF 'mtvec_q' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1566 |         rvfi_mtvec_csr_rdata = mtvec_q;
      |                              ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1566:30: Operator ASSIGN expects 64 bits on the Assign RHS, but Assign RHS's VARREF 'mtvec_d' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1566 |         rvfi_mtvec_csr_wdata = mtvec_d;
      |                              ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1567:44: Bit extraction of var[63:0] requires 6 bit index, not 12 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1567 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MEPC] = (!rvfi_csr_bypass) ? rvfi_mepc_csr_rdata : mepc_q;
      |                                            ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1567:58: Logical operator LOGNOT expects 1 bit on the LHS, but LHS's VARREF 'rvfi_csr_bypass' generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1567 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MEPC] = (!rvfi_csr_bypass) ? rvfi_mepc_csr_rdata : mepc_q;
      |                                                          ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1567:76: Operator COND expects 64 bits on the Conditional False, but Conditional False's VARREF 'mepc_q' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1567 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MEPC] = (!rvfi_csr_bypass) ? rvfi_mepc_csr_rdata : mepc_q;
      |                                                                            ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1567:55: Operator ASSIGNW expects 1 bits on the Assign RHS, but Assign RHS's COND generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1567 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MEPC] = (!rvfi_csr_bypass) ? rvfi_mepc_csr_rdata : mepc_q;
      |                                                       ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1567:76: Operator COND expects 64 bits on the Conditional False, but Conditional False's VARREF 'mepc_d' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1567 |     assign rvfi_csr_if.rvfi_named_csr_wdata[CSR_MEPC] = (!rvfi_csr_bypass) ? rvfi_mepc_csr_wdata : mepc_d;
      |                                                                            ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1567:29: Operator ASSIGN expects 64 bits on the Assign RHS, but Assign RHS's VARREF 'mepc_q' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1567 |         rvfi_mepc_csr_rdata = mepc_q;
      |                             ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1567:29: Operator ASSIGN expects 64 bits on the Assign RHS, but Assign RHS's VARREF 'mepc_d' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1567 |         rvfi_mepc_csr_wdata = mepc_d;
      |                             ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1568:44: Bit extraction of var[63:0] requires 6 bit index, not 12 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1568 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MCAUSE] = (!rvfi_csr_bypass) ? rvfi_mcause_csr_rdata : mcause_extended_read;
      |                                            ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1568:60: Logical operator LOGNOT expects 1 bit on the LHS, but LHS's VARREF 'rvfi_csr_bypass' generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1568 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MCAUSE] = (!rvfi_csr_bypass) ? rvfi_mcause_csr_rdata : mcause_extended_read;
      |                                                            ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1568:57: Operator ASSIGNW expects 1 bits on the Assign RHS, but Assign RHS's COND generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1568 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MCAUSE] = (!rvfi_csr_bypass) ? rvfi_mcause_csr_rdata : mcause_extended_read;
      |                                                         ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1569:44: Bit extraction of var[63:0] requires 6 bit index, not 12 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1569 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MTVAL] = (!rvfi_csr_bypass) ? rvfi_mtval_csr_rdata : mtval_q;
      |                                            ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1569:59: Logical operator LOGNOT expects 1 bit on the LHS, but LHS's VARREF 'rvfi_csr_bypass' generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1569 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MTVAL] = (!rvfi_csr_bypass) ? rvfi_mtval_csr_rdata : mtval_q;
      |                                                           ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1569:77: Operator COND expects 64 bits on the Conditional False, but Conditional False's VARREF 'mtval_q' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1569 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MTVAL] = (!rvfi_csr_bypass) ? rvfi_mtval_csr_rdata : mtval_q;
      |                                                                             ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1569:56: Operator ASSIGNW expects 1 bits on the Assign RHS, but Assign RHS's COND generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1569 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MTVAL] = (!rvfi_csr_bypass) ? rvfi_mtval_csr_rdata : mtval_q;
      |                                                        ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1569:77: Operator COND expects 64 bits on the Conditional False, but Conditional False's VARREF 'mtval_d' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1569 |     assign rvfi_csr_if.rvfi_named_csr_wdata[CSR_MTVAL] = (!rvfi_csr_bypass) ? rvfi_mtval_csr_wdata : mtval_d;
      |                                                                             ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1569:30: Operator ASSIGN expects 64 bits on the Assign RHS, but Assign RHS's VARREF 'mtval_q' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1569 |         rvfi_mtval_csr_rdata = mtval_q;
      |                              ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1569:30: Operator ASSIGN expects 64 bits on the Assign RHS, but Assign RHS's VARREF 'mtval_d' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1569 |         rvfi_mtval_csr_wdata = mtval_d;
      |                              ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1570:44: Bit extraction of var[63:0] requires 6 bit index, not 12 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1570 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MSTATUSH] = (!rvfi_csr_bypass) ? rvfi_mstatush_csr_rdata : 'h0;
      |                                            ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1570:62: Logical operator LOGNOT expects 1 bit on the LHS, but LHS's VARREF 'rvfi_csr_bypass' generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1570 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MSTATUSH] = (!rvfi_csr_bypass) ? rvfi_mstatush_csr_rdata : 'h0;
      |                                                              ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1570:59: Operator ASSIGNW expects 1 bits on the Assign RHS, but Assign RHS's COND generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1570 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MSTATUSH] = (!rvfi_csr_bypass) ? rvfi_mstatush_csr_rdata : 'h0;
      |                                                           ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1570:80: Operator COND expects 64 bits on the Conditional False, but Conditional False's VARREF 'csr_wdata_int' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1570 |     assign rvfi_csr_if.rvfi_named_csr_wdata[CSR_MSTATUSH] = (!rvfi_csr_bypass) ? rvfi_mstatush_csr_wdata : csr_wdata_int;
      |                                                                                ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1570:33: Operator ASSIGN expects 64 bits on the Assign RHS, but Assign RHS's VARREF 'csr_wdata_int' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1570 |         rvfi_mstatush_csr_wdata = csr_wdata_int;
      |                                 ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1571:44: Bit extraction of var[63:0] requires 6 bit index, not 12 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1571 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_DCSR] = (!rvfi_csr_bypass) ? rvfi_dcsr_csr_rdata : dcsr_q;
      |                                            ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1571:58: Logical operator LOGNOT expects 1 bit on the LHS, but LHS's VARREF 'rvfi_csr_bypass' generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1571 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_DCSR] = (!rvfi_csr_bypass) ? rvfi_dcsr_csr_rdata : dcsr_q;
      |                                                          ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1571:76: Operator COND expects 64 bits on the Conditional False, but Conditional False's VARREF 'dcsr_q' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1571 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_DCSR] = (!rvfi_csr_bypass) ? rvfi_dcsr_csr_rdata : dcsr_q;
      |                                                                            ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1571:55: Operator ASSIGNW expects 1 bits on the Assign RHS, but Assign RHS's COND generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1571 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_DCSR] = (!rvfi_csr_bypass) ? rvfi_dcsr_csr_rdata : dcsr_q;
      |                                                       ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1571:76: Operator COND expects 64 bits on the Conditional False, but Conditional False's VARREF 'dcsr_d' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1571 |     assign rvfi_csr_if.rvfi_named_csr_wdata[CSR_DCSR] = (!rvfi_csr_bypass) ? rvfi_dcsr_csr_wdata : dcsr_d;
      |                                                                            ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1571:29: Operator ASSIGN expects 64 bits on the Assign RHS, but Assign RHS's VARREF 'dcsr_q' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1571 |         rvfi_dcsr_csr_rdata = dcsr_q;
      |                             ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1571:29: Operator ASSIGN expects 64 bits on the Assign RHS, but Assign RHS's VARREF 'dcsr_d' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1571 |         rvfi_dcsr_csr_wdata = dcsr_d;
      |                             ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1572:44: Bit extraction of var[63:0] requires 6 bit index, not 12 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1572 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_DPC] = (!rvfi_csr_bypass) ? rvfi_dpc_csr_rdata : depc_q;
      |                                            ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1572:57: Logical operator LOGNOT expects 1 bit on the LHS, but LHS's VARREF 'rvfi_csr_bypass' generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1572 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_DPC] = (!rvfi_csr_bypass) ? rvfi_dpc_csr_rdata : depc_q;
      |                                                         ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1572:75: Operator COND expects 64 bits on the Conditional False, but Conditional False's VARREF 'depc_q' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1572 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_DPC] = (!rvfi_csr_bypass) ? rvfi_dpc_csr_rdata : depc_q;
      |                                                                           ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1572:54: Operator ASSIGNW expects 1 bits on the Assign RHS, but Assign RHS's COND generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1572 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_DPC] = (!rvfi_csr_bypass) ? rvfi_dpc_csr_rdata : depc_q;
      |                                                      ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1572:75: Operator COND expects 64 bits on the Conditional False, but Conditional False's VARREF 'depc_d' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1572 |     assign rvfi_csr_if.rvfi_named_csr_wdata[CSR_DPC] = (!rvfi_csr_bypass) ? rvfi_dpc_csr_wdata : depc_d;
      |                                                                           ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1572:28: Operator ASSIGN expects 64 bits on the Assign RHS, but Assign RHS's VARREF 'depc_q' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1572 |         rvfi_dpc_csr_rdata = depc_q;
      |                            ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1572:28: Operator ASSIGN expects 64 bits on the Assign RHS, but Assign RHS's VARREF 'depc_d' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1572 |         rvfi_dpc_csr_wdata = depc_d;
      |                            ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1573:44: Bit extraction of var[63:0] requires 6 bit index, not 12 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1573 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_DSCRATCH0] = (!rvfi_csr_bypass) ? rvfi_dscratch0_csr_rdata : dscratch0_q;
      |                                            ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1573:63: Logical operator LOGNOT expects 1 bit on the LHS, but LHS's VARREF 'rvfi_csr_bypass' generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1573 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_DSCRATCH0] = (!rvfi_csr_bypass) ? rvfi_dscratch0_csr_rdata : dscratch0_q;
      |                                                               ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1573:81: Operator COND expects 64 bits on the Conditional False, but Conditional False's VARREF 'dscratch0_q' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1573 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_DSCRATCH0] = (!rvfi_csr_bypass) ? rvfi_dscratch0_csr_rdata : dscratch0_q;
      |                                                                                 ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1573:60: Operator ASSIGNW expects 1 bits on the Assign RHS, but Assign RHS's COND generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1573 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_DSCRATCH0] = (!rvfi_csr_bypass) ? rvfi_dscratch0_csr_rdata : dscratch0_q;
      |                                                            ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1573:81: Operator COND expects 64 bits on the Conditional False, but Conditional False's VARREF 'csr_wdata_int' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1573 |     assign rvfi_csr_if.rvfi_named_csr_wdata[CSR_DSCRATCH0] = (!rvfi_csr_bypass) ? rvfi_dscratch0_csr_wdata : csr_wdata_int;
      |                                                                                 ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1573:34: Operator ASSIGN expects 64 bits on the Assign RHS, but Assign RHS's VARREF 'dscratch0_q' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1573 |         rvfi_dscratch0_csr_rdata = dscratch0_q;
      |                                  ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1573:34: Operator ASSIGN expects 64 bits on the Assign RHS, but Assign RHS's VARREF 'csr_wdata_int' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1573 |         rvfi_dscratch0_csr_wdata = csr_wdata_int;
      |                                  ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1574:44: Bit extraction of var[63:0] requires 6 bit index, not 12 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1574 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_DSCRATCH1] = (!rvfi_csr_bypass) ? rvfi_dscratch1_csr_rdata : dscratch1_q;
      |                                            ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1574:63: Logical operator LOGNOT expects 1 bit on the LHS, but LHS's VARREF 'rvfi_csr_bypass' generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1574 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_DSCRATCH1] = (!rvfi_csr_bypass) ? rvfi_dscratch1_csr_rdata : dscratch1_q;
      |                                                               ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1574:81: Operator COND expects 64 bits on the Conditional False, but Conditional False's VARREF 'dscratch1_q' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1574 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_DSCRATCH1] = (!rvfi_csr_bypass) ? rvfi_dscratch1_csr_rdata : dscratch1_q;
      |                                                                                 ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1574:60: Operator ASSIGNW expects 1 bits on the Assign RHS, but Assign RHS's COND generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1574 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_DSCRATCH1] = (!rvfi_csr_bypass) ? rvfi_dscratch1_csr_rdata : dscratch1_q;
      |                                                            ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1574:81: Operator COND expects 64 bits on the Conditional False, but Conditional False's VARREF 'csr_wdata_int' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1574 |     assign rvfi_csr_if.rvfi_named_csr_wdata[CSR_DSCRATCH1] = (!rvfi_csr_bypass) ? rvfi_dscratch1_csr_wdata : csr_wdata_int;
      |                                                                                 ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1574:34: Operator ASSIGN expects 64 bits on the Assign RHS, but Assign RHS's VARREF 'dscratch1_q' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1574 |         rvfi_dscratch1_csr_rdata = dscratch1_q;
      |                                  ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1574:34: Operator ASSIGN expects 64 bits on the Assign RHS, but Assign RHS's VARREF 'csr_wdata_int' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1574 |         rvfi_dscratch1_csr_wdata = csr_wdata_int;
      |                                  ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1575:44: Bit extraction of var[63:0] requires 6 bit index, not 12 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1575 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MSCRATCH] = (!rvfi_csr_bypass) ? rvfi_mscratch_csr_rdata : mscratch_q;
      |                                            ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1575:62: Logical operator LOGNOT expects 1 bit on the LHS, but LHS's VARREF 'rvfi_csr_bypass' generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1575 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MSCRATCH] = (!rvfi_csr_bypass) ? rvfi_mscratch_csr_rdata : mscratch_q;
      |                                                              ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1575:80: Operator COND expects 64 bits on the Conditional False, but Conditional False's VARREF 'mscratch_q' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1575 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MSCRATCH] = (!rvfi_csr_bypass) ? rvfi_mscratch_csr_rdata : mscratch_q;
      |                                                                                ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1575:59: Operator ASSIGNW expects 1 bits on the Assign RHS, but Assign RHS's COND generates 64 bits.
                                                                                            : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1575 |     assign rvfi_csr_if.rvfi_named_csr_rdata[CSR_MSCRATCH] = (!rvfi_csr_bypass) ? rvfi_mscratch_csr_rdata : mscratch_q;
      |                                                           ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1575:80: Operator COND expects 64 bits on the Conditional False, but Conditional False's VARREF 'csr_wdata_int' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1575 |     assign rvfi_csr_if.rvfi_named_csr_wdata[CSR_MSCRATCH] = (!rvfi_csr_bypass) ? rvfi_mscratch_csr_wdata : csr_wdata_int;
      |                                                                                ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1575:33: Operator ASSIGN expects 64 bits on the Assign RHS, but Assign RHS's VARREF 'mscratch_q' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1575 |         rvfi_mscratch_csr_rdata = mscratch_q;
      |                                 ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv:1575:33: Operator ASSIGN expects 64 bits on the Assign RHS, but Assign RHS's VARREF 'csr_wdata_int' generates 32 bits.
                                                                                             : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core.cs_registers_i'
 1575 |         rvfi_mscratch_csr_wdata = csr_wdata_int;
      |                                 ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_core.sv:998:25: Operator ASSIGNW expects 1 bits on the Assign RHS, but Assign RHS's ARRAYSEL generates 16 bits.
                                                                                   : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core'
  998 |   assign rvfi_intr      = rvfi_stage_intr     [RVFI_STAGES-1];
      |                         ^
%Warning-WIDTHTRUNC: third_party/cv32e20_upstream_reference/rtl/cve2_core.sv:1041:39: Operator ASSIGNW expects 5 bits on the Assign RHS, but Assign RHS's ARRAYSEL generates 32 bits.
                                                                                    : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core'
 1041 |   assign rvfi_instr_if.rvfi_mem_wdata = rvfi_stage_mem_wdata[RVFI_STAGES-1];
      |                                       ^
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_core.sv:1115:28: Operator ASSIGNDLY expects 4 bits on the Assign RHS, but Assign RHS's CONST '1'h0' generates 1 bits.
                                                                                     : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core'
 1115 |       captured_debug_cause <= 1'b0;
      |                            ^~
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_core.sv:1129:30: Operator ASSIGNDLY expects 4 bits on the Assign RHS, but Assign RHS's VARREF 'debug_cause' generates 3 bits.
                                                                                     : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core'
 1129 |         captured_debug_cause <= debug_cause;
      |                              ^~
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_core.sv:1206:40: Operator ASSIGNDLY expects 16 bits on the Assign RHS, but Assign RHS's REPLICATE generates 9 bits.
                                                                                     : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core'
 1206 |                     rvfi_stage_intr[i] <= { cs_registers_i.mcause_q[5:0], 3'b101};
      |                                        ^~
%Warning-WIDTHEXPAND: third_party/cv32e20_upstream_reference/rtl/cve2_core.sv:1208:40: Operator ASSIGNDLY expects 16 bits on the Assign RHS, but Assign RHS's REPLICATE generates 9 bits.
                                                                                     : ... note: In instance 'local_cpu_0.u_dut.u_cve2_core'
 1208 |                     rvfi_stage_intr[i] <= { cs_registers_i.mcause_q[5:0], 3'b011};
      |                                        ^~
%Warning-COMBDLY: third_party/cv32e20_upstream_reference/rtl/cve2_clock_gate.sv:31:31: Non-blocking assignment '<=' in combinational logic process
                                                                                     : ... This will be executed as a blocking assignment '='!
   31 |     if (clk_i == 1'b0) clk_en <= en_i | scan_cg_en_i;
      |                               ^~
                  ... For warning description see https://verilator.org/warn/COMBDLY?v=5.051
                  ... Use "/* verilator lint_off COMBDLY */" and lint_on around source to disable this message.
                  *** See https://verilator.org/warn/COMBDLY?v=5.051 before disabling this,
                  else you may end up with different sim results.
%Warning-UNOPTFLAT: third_party/cv32e20_upstream_reference/rtl/cve2_id_stage.sv:199:16: Signal unoptimizable: Circular combinational logic: 'local_cpu_0.u_dut.u_cve2_core.id_stage_i.instr_executing_spec'
  199 |   logic        instr_executing_spec;
      |                ^~~~~~~~~~~~~~~~~~~~
                    ... For warning description see https://verilator.org/warn/UNOPTFLAT?v=5.051
                    ... Use "/* verilator lint_off UNOPTFLAT */" and lint_on around source to disable this message.
                    third_party/cv32e20_upstream_reference/rtl/cve2_id_stage.sv:199:16:      Example path: local_cpu_0.u_dut.u_cve2_core.id_stage_i.instr_executing_spec
                    third_party/cv32e20_upstream_reference/rtl/cve2_id_stage.sv:778:3:      Example path: ALWAYS
                    third_party/cv32e20_upstream_reference/rtl/cve2_id_stage.sv:247:16:      Example path: local_cpu_0.u_dut.u_cve2_core.id_stage_i.stall_alu
                    third_party/cv32e20_upstream_reference/rtl/cve2_controller.sv:739:16:      Example path: ASSIGNW
                    third_party/cv32e20_upstream_reference/rtl/cve2_controller.sv:129:9:      Example path: local_cpu_0.u_dut.u_cve2_core.id_stage_i.controller_i.stall
                    third_party/cv32e20_upstream_reference/rtl/cve2_controller.sv:341:3:      Example path: ALWAYS
                    third_party/cv32e20_upstream_reference/rtl/cve2_controller.sv:130:9:      Example path: local_cpu_0.u_dut.u_cve2_core.id_stage_i.controller_i.halt_if
                    third_party/cv32e20_upstream_reference/rtl/cve2_controller.sv:742:33:      Example path: ASSIGNW
                    third_party/cv32e20_upstream_reference/rtl/cve2_controller.sv:742:33:      Example path: __VdfgRegularize_h6e95ff9d_0_147
                    third_party/cv32e20_upstream_reference/rtl/cve2_controller.sv:341:3:      Example path: ALWAYS
%Warning-UNOPTFLAT: third_party/cv32e20_upstream_reference/rtl/cve2_controller.sv:742:33: Signal unoptimizable: Circular combinational logic: '__VdfgRegularize_h6e95ff9d_0_147'
  742 |   assign id_in_ready_o = ~stall & ~halt_if & ~retain_id;
      |                                 ^
                    third_party/cv32e20_upstream_reference/rtl/cve2_controller.sv:742:33:      Example path: __VdfgRegularize_h6e95ff9d_0_147
                    third_party/cv32e20_upstream_reference/rtl/cve2_controller.sv:341:3:      Example path: ALWAYS
                    third_party/cv32e20_upstream_reference/rtl/cve2_controller.sv:130:9:      Example path: local_cpu_0.u_dut.u_cve2_core.id_stage_i.controller_i.halt_if
                    third_party/cv32e20_upstream_reference/rtl/cve2_controller.sv:742:33:      Example path: ASSIGNW
                    third_party/cv32e20_upstream_reference/rtl/cve2_controller.sv:742:33:      Example path: __VdfgRegularize_h6e95ff9d_0_147
%Warning-UNOPTFLAT: third_party/cv32e20_upstream_reference/rtl/cve2_id_stage.sv:201:16: Signal unoptimizable: Circular combinational logic: 'local_cpu_0.u_dut.u_cve2_core.id_stage_i.instr_done'
  201 |   logic        instr_done;
      |                ^~~~~~~~~~
                    third_party/cv32e20_upstream_reference/rtl/cve2_id_stage.sv:201:16:      Example path: local_cpu_0.u_dut.u_cve2_core.id_stage_i.instr_done
                    third_party/cv32e20_upstream_reference/rtl/cve2_id_stage.sv:715:34:      Example path: ASSIGNW
                    third_party/cv32e20_upstream_reference/rtl/cve2_core.sv:218:16:      Example path: local_cpu_0.u_dut.u_cve2_core.csr_op_en
                    third_party/cv32e20_upstream_reference/rtl/cve2_controller.sv:246:22:      Example path: ASSIGNW
                    third_party/cv32e20_upstream_reference/rtl/cve2_controller.sv:136:9:      Example path: local_cpu_0.u_dut.u_cve2_core.id_stage_i.controller_i.special_req
                    third_party/cv32e20_upstream_reference/rtl/cve2_controller.sv:341:3:      Example path: ALWAYS
                    third_party/cv32e20_upstream_reference/rtl/cve2_controller.sv:130:9:      Example path: local_cpu_0.u_dut.u_cve2_core.id_stage_i.controller_i.halt_if
                    third_party/cv32e20_upstream_reference/rtl/cve2_controller.sv:742:33:      Example path: ASSIGNW
                    third_party/cv32e20_upstream_reference/rtl/cve2_controller.sv:742:33:      Example path: __VdfgRegularize_h6e95ff9d_0_147
                    third_party/cv32e20_upstream_reference/rtl/cve2_controller.sv:341:3:      Example path: ALWAYS
```

Parameter cast derives from `rtl/cve2_top.sv`: `parameter rv32m_e RV32M = RV32MFast`. Type `cve2_pkg::rv32m_e` resolves uniquely in `rtl/cve2_pkg.sv`; numeric profile value is preserved by the static cast.

## pulp_gpio

- Profile: `configs/peripherals/pulp_gpio/component_profile.json`
- Profile SHA-256: `2268967fa909658fbc079fc41112a10bba88e7484909153cbc1a5a1b222a0b56`
- Source revision: `git:f82caeb7f7d89427f05e9af5ed31e0675efe0d83`
- Source content hash: `sha256:bde1f2c536e833582ab80faf74f8e56394aeb2af8cf6528a9452c34daa1da456`
- Plan SHA-256: `ce7c7c9027bd9def1f0f1a84729cc9a016b7271a3a281cc5e7740e93d3271db5`
- Wrapper SHA-256: `4dd42442937289662279e07d85717f2680ee66e27a3ed4e0b89eb68057819d22`
- ABI SHA-256: `96399777e801ee25063a9c24b30ecc91f4c1be30bb47db86d12ae7b57fdb46b8`
- Build SHA-256: `1a306b370b406c58127cc5bcde6a46fe33ce413170afacdba010b691ce29931d`
- Physical ports: 17; physical input bits: 82; physical output bits: 259.
- Exposed ABI segments: 14; exposed input bits: 79; exposed output bits: 259.
- Parameters: `{"APB_ADDR_WIDTH": "12", "NBIT_PADCFG": "4", "PAD_NUM": "32"}`
- Lint exit: 0; warnings: 1 (`CASEINCOMPLETE=1`); no `%Error`.

Exact command (`WRAPPER` is the temporary wrapper path; run from repository root):

```sh
verilator --lint-only -Wno-fatal --top-module local_gpio_a third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv "$WRAPPER"
```

Diagnostics:

```text
%Warning-CASEINCOMPLETE: third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv:276:13: Case values incompletely covered (example pattern 0x2)
  276 |             case (s_apb_addr)
      |             ^~~~
                         ... For warning description see https://verilator.org/warn/CASEINCOMPLETE?v=5.051
                         ... Use "/* verilator lint_off CASEINCOMPLETE */" and lint_on around source to disable this message.
```

## Limits and remaining work

- Exactly one component instance is emitted; no bus/fabric, peer model, protocol driver, random stimulus or fabricated DUT outputs are emitted. PULP interrupt remains the real pulse output.
- The boundary reset is assertion-high; DUT active-low resets receive `~reset`. Raw backing vectors and slices preserve packed order; ABI rows identify every exposed physical span. All constant/unconnected dispositions remain in the ABI ledger.
- Filelist-backed sources are refused because PhysicalFacts does not retain resolved filelist include/define options. Explicit ordered source files and include roots/defines are retained in the build document.
- Parameter parsing supports simple explicit top header declarations, numeric builtin types and uniquely imported or qualified package enum typedefs. Inherited declarations, macros in the parameter header, unsupported type syntax, missing or ambiguous origins fail closed. Parameter source snapshots are captured before elaboration, checked afterward and included in plan/build/ABI identity. Renderer performs no filesystem reads.
- Review follow-up: rendering now rejects a profile whose source/elaboration settings differ from the captured planning source, enum type evidence from preprocessor-controlled package regions, and profiles with more than one declared clock or reset. Three regression cases failed before this change and now pass; the focused request/plan/renderer/source-lock suite passes 41 tests including both real lint cases. Multi-domain timing needs a separate explicit ABI before it can be supported.
- Escaped names and SystemVerilog reserved words are refused. Bidirectional ports and any gaps/overlaps are refused.
- Lint uses `-Wno-fatal` to record source warnings; it is structural evidence only. The existing CVE2 WIDTHTRUNC warning is retained, with no warning suppression injected into RTL.
- A later milestone must supply protocol-specific C++ drivers, Python sessions and operational tests before claiming runnable harness or runtime support.
