# PicoRV32 Wishbone and ZipCPU UART RX IRQ acceptance

## Goal

Prove a CPU and UART in separate generated harnesses can form one persistent
cross-component testcase: a real PicoRV32 program configures the real ZipCPU
`wbuart`, one genome-owned external byte enters through the UART RX pin, the
UART's real RX FIFO level IRQ reaches Pico `irq[3]`, and Pico's real custom IRQ
handler reads RXREG and stores the received byte in persistent RAM.

### Task 1: generated PicoRV32 and ZipCPU UART RX IRQ scenario

## Implementation scope

- Add a gated real-RTL integration scenario using the existing
  `picorv32_wb_irq` and `zipcpu_uart` profiles and existing local sessions.
- Keep the CPU and UART in independent harness processes. Route accepted CPU
  Wishbone MMIO transactions through `DataflowRouter` to the native UART
  Wishbone target service.
- Make `uart_rx_byte[7:0]` the only fuzzable source. Bind the actual
  `uart_rx_int` output to CPU IRQ bit 3; fix all other CPU IRQ bits inactive.
- Keep the UART in CPU-routed mode, with no harness startup writes and no
  harness RXREG reads. CPU setup and RX FIFO consumption must be real CPU MMIO.
- Use a test-local external UART peer tuning that adds one fixed 25-tick idle
  interval after the session's built-in idle guard. The payload remains the
  only fuzzable UART input; the extra idle interval lets the real receiver
  complete its line synchronization after the CPU's SETUP write reset.
- Use the pinned Pico custom0 ABI (`getq`, `maskirq`, `retirq`), not machine
  CSR or `mret` interrupt handling. The ISR reads RXREG once, stores the byte
  and q1 pending mask, masks further interrupts for the one-shot testcase, and
  returns. Main code records a post-handler marker.
- Run two legal source values, demonstrate a dependency-aware mutation between
  them, and save/replay each evidence bundle with fresh RTL sessions.
- Add an acceptance report and one capability-matrix row. Do not modify RTL,
  source locks, generic runtime/session code, or unrelated profiles.

## Required evidence

- Ownership contains exactly one source field (`uart_rx_byte`), one bound
  field (`cpu.irq[3]` from `uart.uart_rx_int`), and fixed inactive CPU IRQ
  ranges `[0:3]` and `[4:32]`.
- The DUT's physical `i_uart_rx` receipts show the selected external 8N1
  start/data/stop bits at the declared 25 local ticks per bit; CPU MMIO
  deliveries contain one real SETUP write and one real RXREG read, with no
  duplicate transaction and no harness-owned register access.
- The real SETUP commit precedes the RX start by at least 425 UART local ticks:
  the RTL requires 400 ticks for its 16 configured bit-cell line-sync interval
  plus its registered reset release, and the test-local peer adds a 25-tick
  idle interval. This ordering is checked only in the UART's local tick domain.
- Real UART local samples show `uart_rx_int` high before the CPU RXREG read and
  low after its real FIFO pop. The actual level reaches CPU input value `8`.
- CPU samples show custom IRQ `eoi` asserted during the handler and cleared
  after `retirq`; q1 is `8`; `trap` remains zero; no machine-mode CSR behavior
  is claimed. The CPU consumes the actual RXREG value and writes that value to
  RAM before the mainline post-handler marker.
- Each payload's saved evidence replays against fresh CPU/UART sessions with
  matching semantic trace and RAM result. No reset occurs inside the testcase.
- A second payload changes only the declared external UART source and changes
  the real byte observed by the CPU. Do not randomize CPU IRQ or UART outputs.

## Verification

Run the new gated real-RTL integration test with
`MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest
tests.integration.test_scenario_picorv32_wb_zipcpu_uart_irq_real -v`, the
focused Pico IRQ and Wishbone UART scenario regressions, and `git diff --check`.

## Limits

This acceptance covers one 8N1 RX byte per fresh testcase and the ZipCPU UART
RX-not-empty level IRQ. It does not claim FIFO-watermark IRQ, arbitrary UART
baud rates, a physical shared Wishbone fabric, a PLIC, global cycle-accurate
timing, or a complete SoC.
