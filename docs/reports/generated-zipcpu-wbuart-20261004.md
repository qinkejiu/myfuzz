# CPU protocol audit and generated ZipCPU Wishbone UART acceptance

## Executable CPU protocol coverage

The current generated local runtime has five CPU bus forms backed by real RTL:

| CPU bus form | Pinned RTL instance and acceptance | Current limit |
|---|---|---|
| OBI | CV32E20 and full-top Ibex; real fetch, data Store/Load, byte enables and replay | Other OBI variants still require a port and timing profile |
| Native Ready/Valid memory | PicoRV32; persistent RAM Store/Load and replay | RAM/ROM only |
| Classic Wishbone initiator | PicoRV32 Wishbone; real fetch, RAM and deferred MMIO | No CPU IRQ |
| AXI4-Lite initiator | PicoRV32 AXI; AW/W/B/AR/R and persistent RAM replay | Fixed no-response-code variant; RAM/ROM only |
| Full AXI4 initiator | ZipCPU zipaxi; five-channel burst transactions and replay | RAM only; no exclusive transactions |

Existing generated peripheral target buses include PULP APB3 (GPIO, SPI, Timer, I2C), OpenTitan TL-UL (GPIO and RV Timer), ZipCPU Wishbone (ziptimer), and ZipCPU AXI4-Lite (axiluart). This branch validates a second Wishbone target shape, `wbuart`: two word-address bits, implemented byte-select lanes, one-cycle STB with registered ACK and CYC held through the response, plus UART serial pins and four level interrupt outputs. It is a new parameterized target variant on the existing Wishbone protocol, not an additional CPU bus family.

## Generated `wbuart` result

The pinned source lock records `soc-zipcpu-wbuart@f43a6b83c3a70fb2ac0696a45c5545b233fb860b`, four RTL files and the 19-port top. Planning re-elaborates and binds all 19 ports. `local_runtime_variant=wishbone_uart` selects the Wishbone target adapter with `WB_FLAVOUR=1`, `TARGET_ADDRESS_WIDTH=2`, `ADDRESS_UNITS=1`, `SUPPORTS_PARTIAL_WRITE=1`, and a 16-byte local window. The generated driver records every local tick and exposes the actual serial pins and native FIFO-level interrupts. The session keeps one RTL process for the full testcase and drives one bounded 8N1 source frame from a selected testcase byte.

Acceptance on 2026-10-04:

- `MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src python3 -m unittest tests.integration.test_local_wishbone_uart_generated_real -v`: 2/2 passed. The real Wishbone target accepted setup and TX writes, emitted TX byte `0x41` on its serial pin, received external RX byte `0x5A`, returned it from RXREG, and asserted its native RX IRQ. Each access had exactly one observed target STB.
- The Genome chose `0x5A` and `0xA6` in separate testcases. Each byte propagated through the serial peer into the real RX FIFO, was read back, and matched a fresh-process replay. The three direct register transactions per testcase were counted under `max_transactions=3` and recorded in bounded evidence.
- `PYTHONPATH=src python3 -m unittest tests.local_harness.test_runtime_renderer tests.local_harness.test_generation_cli -q`: 12/12 passed.

This acceptance is an independent UART harness. It does not claim a CPU→UART→CPU chain, hardware flow-control coverage beyond CTS held low, multi-byte FIFO saturation, parity/break modes, or other baud configurations. Those need separate testcases and protocol-specific tuning.
