# P7-D1 ZipCPU AXI UART RX IRQ polarity

## Scope

The declaration reviewer now source-checks one interrupt cone: ZipCPU `axiluart`, source revision `f43a6b83c3a70fb2ac0696a45c5545b233fb860b`, IRQ role `rx`, physical port `o_uart_rx_int`. It reads the pinned `rtl/axiluart.v` and `rtl/ufifo.v` through `_pinned_source_reader`. It verifies the `rxfifo` status connection, `o_uart_rx_int = rxf_status[0]`, and the complete `o_status` concatenation with `!will_underflow` in bit 0. For an RX FIFO (`RXFIFO=1`), reset sets `will_underflow=1`, an accepted FIFO write clears it, and draining the last entry restores it. The derived asserted polarity is `active_high`.

A profile that declares this IRQ `active_low` now returns `interrupt-polarity-source-conflict` at `/interrupts/0/polarity` and does not generate a harness. A missing or changed source cone returns `unsupported`. The source oracle matches by source identity, interrupt role, and physical alias; other IRQ declarations remain declaration-only. Multiple gaps are accumulated and classified by the existing `unsupported > conflict > missing` severity.

## Verification

- TDD declaration-review suite: `PYTHONPATH=src pytest -q tests/local_harness/test_declaration_review.py` — **19 passed**. Cases include a flipped profile polarity, source-layout mutation that moves the expected expression away from status bit 0, and a simultaneous polarity conflict plus unsupported trigger.
- Native RTL check: `PYTHONPATH=src python3 -m pytest -q tests/local_harness/test_axil_uart_runtime.py::AxilUartRuntimeAcceptance::test_full_top_and_real_axi_channels_with_serial_peer --disable-warnings --maxfail=1` — **1 passed in 17.11s**. The test observed the pin sequence `0→1→0` during one serial RX and FIFO read.
- `git diff --check` passed after the change.

## Boundary

This verifies the declared ZipCPU RX IRQ polarity and the IP output/FIFO level transition. The test has no CPU connected to the interrupt output and does not prove CPU IRQ input delivery, interrupt take, ISR execution, or any other IRQ profile. It is a narrow D1 correction, not full P7 or six-CPU/four-IP acceptance.
