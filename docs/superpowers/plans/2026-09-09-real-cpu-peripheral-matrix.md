# Real CPU and Peripheral Matrix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run source-backed Ibex, CV32E40P, CV32E20, and CVA6 through randomized generic compositions that instantiate real RAM/UART/SPI/Timer/GPIO RTL behind the existing processor-memory-beat backend.

**Architecture:** Keep CPU-specific OBI/AXI4 adapters unchanged. Add source-backed peripheral target wrappers that expose the common processor-memory-beat contract and internally use the existing TL-UL, AXI4-Lite, or APB4 bridges to drive the real peripheral modules. Use temporary upstream checkouts for CV32E40P and CV32E20 during the matrix run; do not add upstream source trees to `third_party/`.

**Tech Stack:** Python composition planner, SystemVerilog bridge wrappers, Verilator lint/smoke simulation, pytest integration tests.

## Global Constraints

- Preserve the existing generic CPU and processor-memory-beat contracts.
- Do not modify or clean user-owned `third_party/` content.
- Do not claim a peripheral combination passed unless its generated top is linted and its smoke test exits successfully.
- Keep the matrix deterministic through an explicit random seed and record every selected CPU/peripheral combination.
- Treat peripheral IRQ pins as tied-off for this bounded smoke matrix; do not claim interrupt-functional coverage.

## Task 1: Add source-backed real peripheral target wrappers

**Files:**
- Create: `configs/designs/ibex_multicomponent_ip/rtl/real_targets/real_tl_ram_target.sv`
- Create: `configs/designs/ibex_multicomponent_ip/rtl/real_targets/real_axi_uart_target.sv`
- Create: `configs/designs/ibex_multicomponent_ip/rtl/real_targets/real_axi_spi_target.sv`
- Create: `configs/designs/ibex_multicomponent_ip/rtl/real_targets/real_apb_timer_target.sv`
- Create: `configs/designs/ibex_multicomponent_ip/rtl/real_targets/real_apb_gpio_target.sv`
- Create: `configs/designs/ibex_multicomponent_ip/rtl/real_targets/real_tl_ram_target64.sv`
- Create: `configs/designs/ibex_multicomponent_ip/rtl/real_targets/real_axi_uart_target64.sv`
- Create: `configs/designs/ibex_multicomponent_ip/rtl/real_targets/real_axi_spi_target64.sv`
- Create: `configs/designs/ibex_multicomponent_ip/rtl/real_targets/real_apb_timer_target64.sv`
- Create: `configs/designs/ibex_multicomponent_ip/rtl/real_targets/real_apb_gpio_target64.sv`
- Create: `src/myfuzz/components/profiles/real_ram.json`
- Create: `src/myfuzz/components/profiles/real_uart.json`
- Create: `src/myfuzz/components/profiles/real_spi.json`
- Create: `src/myfuzz/components/profiles/real_timer.json`
- Create: `src/myfuzz/components/profiles/real_gpio.json`

**Interfaces:** Each wrapper exposes `clock`, `reset`, `req_valid`, `req_ready`, `write`, `addr`, `wdata`, `be`, `rsp_valid`, `rsp_ready`, `rdata`, and `error`. The 32-bit wrappers instantiate the existing real `ibex_mcip_*` modules directly. The 64-bit RAM keeps both lanes in coherent 32-bit banks; 64-bit MMIO wrappers select one aligned 32-bit lane and fail closed on unsupported lane, alignment, or partial-write shapes. Each wrapper includes the existing protocol bridge sources in its profile source list and ties UART/SPI/GPIO/timer external stimulus to deterministic zero values.

- [x] Write one 32-bit TL-UL RAM wrapper and its profile.
- [x] Write 32-bit AXI4-Lite UART/SPI wrappers and profiles.
- [x] Write 32-bit APB4 Timer/GPIO wrappers and profiles.
- [x] Write the corresponding 64-bit CVA6 wrappers and profiles.
- [x] Run Verilator lint on each wrapper with its native peripheral source and bridge source list.

## Task 2: Add CV32E20 and temporary CV32E40P source-backed manifests

**Files:**
- Create: `configs/cpus/cv32e20/official_core_interface_description.json`
- Modify: `configs/cpus/cv32e40p/official_core_interface_description.json` only if upstream port names differ from the existing template.
- Create: `tests/integration/test_real_cpu_peripheral_matrix.py`

**Interfaces:** The test driver provisions official OpenHW CV32E40P and CV32E20 checkouts under a temporary directory, computes source revisions, and constructs interface descriptions with split OBI instruction/data endpoints. It must fail with a clear provisioning diagnostic when network or an upstream checkout is unavailable.

- [x] Inspect the upstream CV32E40P top-level port names and update the existing OBI manifest only when necessary.
- [x] Inspect the upstream CV32E20 top-level module and construct its split OBI manifest.
- [x] Add a deterministic source-tree hash and source-file closure to both descriptions.
- [x] Add a test that rejects missing temporary source roots before composition publication.

## Task 3: Build the randomized real CPU/peripheral matrix

**Files:**
- Create: `scripts/run_real_cpu_peripheral_matrix.py`
- Test: `tests/integration/test_real_cpu_peripheral_matrix.py`
- Modify: `README.md`
- Modify: `examples/real_ibex_rfuzz/README.zh-CN.md`

**Interfaces:** The runner accepts `--seed`, `--out-dir`, and optional `--keep-artifacts`. It selects repeated combinations from:

```text
CPUs: ibex, cv32e40p, cv32e20, cva6
32-bit peripherals: real_ram, real_uart, real_spi, real_timer, real_gpio
64-bit peripherals: real_ram64, real_uart64, real_spi64, real_timer64, real_gpio64
```

It calls `plan_generic_composition`, `write_generic_composition`, Verilator `--lint-only`, and a generated clocked smoke testbench. The smoke runs 2048 bounded clock edges so CVA6 can complete its reset-time instruction-cache clear. The report records CPU, peripheral set, protocol bridge, width, plan status, lint status, smoke status, and reuse counts.

- [x] Add a fixed-seed candidate list with every CPU appearing in at least two combinations.
- [x] Ensure RAM/UART/SPI/Timer/GPIO each appear in more than one combination where their width is compatible.
- [x] Use separate 32-bit and 64-bit target profiles rather than silently truncating a CVA6 route.
- [x] Emit a machine-readable `matrix_report.json` and a concise text summary.
- [x] Keep failed combinations in the report with the exact diagnostic instead of dropping them.

## Task 4: Verify and document the matrix

**Files:**
- Modify: `docs/superpowers/examples/generic-riscv-cpu-direct-integration.md`
- Modify: `examples/real_ibex_rfuzz/README.zh-CN.md`
- Modify: `README.md`

- [x] Run focused wrapper tests.
- [x] Run the full matrix with the documented seed.
- [x] Run `PYTHONPATH=src pytest -q --ignore=third_party`.
- [x] Verify the worktree contains no generated matrix artifacts unless explicitly kept by the user.
- [x] Record the exact pass counts and the limitation that IRQ behavior is tied off in this smoke matrix.
