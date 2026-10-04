# Generated CPU AXI4-Lite and AXI4 source inventory

## AXI4-Lite: executable narrow target

The smallest source-pinned AXI4-Lite CPU is `picorv32_axi` in
`third_party/picorv32_upstream_reference/picorv32.v:2517` at
`ef203c2b0a3fb793280f5114941416c425c5b461`. Its complete RTL closure is
that one file; `configs/soc/closures/picorv32_axi.json` records a clean
Verilator elaboration with `ENABLE_PCPI=0` and `ENABLE_IRQ=0`.

The physical top at lines 2550–2584 has 32-bit AW/AR addresses, 32-bit W/R
data, four WSTRB bits, AWPROT/ARPROT, and all five VALID/READY channel pairs.
It has **no BRESP or RRESP input**. The local profile
`configs/cpus/picorv32_axi/component_profile.json` binds those actual pins,
including observed `trap`, `eoi`, PCPI and trace outputs. Its
`error_response=false` is source fact, not a promise that AXI errors can be
delivered to the CPU.

The generated runtime selects the registered `cpu.axi4-lite` /
`no-response-code` template and the existing
`axi4_lite_processor_memory_adapter.sv`. BRESP and RRESP are local unused
adapter outputs; they are never invented as physical CPU pins. The memory
service admits one transaction at a time and sends a backend response only
after a successful persistent RAM/ROM access. An unmapped or failed access
terminates the local execution without a fabricated successful CPU response.
AW and W may be accepted independently by the adapter. The CPU profile keeps
PCPI and IRQ disabled, so this acceptance does not claim IRQ or coprocessor
behavior.

The generated real RTL acceptance executes the 12-word RV32I program from
`tests/integration/test_local_native_memory_generated_real.py` through this
AXI4-Lite top, performs two load/increment/store rounds, observes four writes,
checks values 7 at addresses `0x100` and `0x104`, saves a formal evidence
bundle, and checks full replay with a fresh RTL process. A second run hits an unmapped address and requires
termination with zero writes. Focused checks after the Wishbone merge:
`tests/local_harness/test_axi_lite_runtime.py` 2 passed;
`MYFUZZ_SCENARIO_REAL=1 tests/integration/test_local_axi_lite_generated_real.py`
2 passed. The existing generated session contract, native runtime and Wishbone
focused checks also passed (19 tests and 26 subtests). Earlier direct adapter benches in
`docs/reports/picorv32-protocol-benches-20260915.md` cover PicoRV32 byte and
halfword lane behavior; the new generated program checks full-word persistent
operations and replay.

## Full AXI4: physical candidates and acceptance boundary

| Candidate | Physical source facts | Current generated-runtime decision |
| --- | --- | --- |
| CVA6 cached configuration | `third_party/cva6_upstream_reference/core/cva6.sv:235–347` at `2e1336dcff3d1a0b49fbe6282b97802f32ea32af` defines packed AXI AW, W, B, AR and R members on `noc_req_o` (470 bits) and `noc_resp_i` (210 bits). `cv64a6_imafdc_sv39_config_pkg.sv:32–34` selects 64-bit address/data and four-bit ID; user width is 64. Existing `configs/cpus/cva6/component_profile.json` binds 45 protocol members. | Genuine full AXI4 pins and pinned closure exist. The current beat backend and profile declare one outstanding and `bursts=false`; the RTL can issue a two-beat instruction fetch. A generated real boot must first support the observed bursts and IDs or use a separately proven physical configuration that emits only admitted transfers. The existing profile's `bursts=false` is a **fabric restriction**, not an RTL capability claim. |
| ZipCPU `zipaxi` | `third_party/soc-zipcpu/rtl/zipaxi.v:57–240` at `42606d2d6ef55df313772232977621b2d72f0159` exposes separate `M_INSN_*` and `M_DATA_*` AXI4 masters with AWLEN/ARLEN, IDs, WLAST/RLAST, BRESP/RRESP and 32-bit default address/data; `rtl/Makefile:173–179` lists its RTL closure. It also has an AXI-Lite debug slave. | Plausible smaller 32-bit full AXI4 CPU. It has no pinned local component profile or elaborated closure receipt yet. The instruction and data ports require separate endpoint treatment, and actual burst behavior must be measured before claiming a one-beat runtime. |

`zipaxil.v` is another genuine AXI4-Lite ZipCPU top, with separate
instruction/data masters and debug slave; it is larger than the one-file
PicoRV32 target for the first Lite runtime. PicoRV32 `picorv32_axi` is
AXI4-Lite only; its name is not evidence of full AXI4. Existing generic AXI4
processor adapter documentation in
`docs/reports/p1_axi4_processor_memory_adapter_20260908.md` limits executable
backend requests to supported single transfers and rejects unsupported
bursts/atomics. A full AXI4 CPU acceptance should show real RTL fetch and
load/store through its physical AXI channels, correct ID/last/response
association, persistent memory effects, and a fresh replay; source binding or
adapter unit tests alone do not establish that acceptance.
