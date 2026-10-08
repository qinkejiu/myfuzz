# Generated CVA6 to OpenTitan SPI Host acceptance

## Scope

This testcase runs pinned CVA6 AXI4 RTL and OpenTitan SPI Host TL-UL RTL in
independent generated harnesses. The CPU's real accepted AXI4 requests are
delivered to the separate SPI Host session through `DataflowRouter`. This is
abstract transaction routing; it does not instantiate an AXI-to-TL-UL bridge,
bus fabric, or globally synchronized SoC.

The accepted route shape is one aligned 32-bit MMIO beat on a packed 64-bit
AXI4 data bus. The Router selects the addressed 32-bit lane and byte enables.
The response keeps AXI lane positioning and the CPU session verifies the real
response ID, `RRESP`, and `RLAST` handshake. The test's RXDATA access uses the
upper 32-bit lane at address `0x40000024`.

## Scenario

The CPU program writes OpenTitan SPI Host `CONTROL`, `CONFIGOPTS`, and
`COMMAND`, then waits while the scenario scheduler advances the Host's local
clock. A Genome mutation changes the four-byte SPI source from
`0x12345678` to `0x12345679`. The local SPI peer observes the actual RTL
`CSB`, `SCK`, `SD_O`, and `SD_EN` outputs and changes MISO at the configured
mode-0 boundaries; it does not invent Host RXDATA.

The real SPI Host completes 32 sample edges and fills its RXDATA register. The
CPU then reads offset `0x24` through real AXI4, receives the true TL-UL RTL
value in the addressed AXI lane, and stores the decoded word to persistent RAM
at `0x20000`. The testcase checks the source injection, all three CPU MMIO
writes, the 64-bit lane response, 32 peer sample edges, four source bytes
consumed, the RAM write with its low-lane byte enable, and the final RAM value.

## Evidence

Command:

```sh
PYTHONPATH=src:. python3 -m unittest \
  tests.integration.test_scenario_cva6_generated_opentitan_spi_host_real -v
```

Result: 1/1 passed in 86.560 seconds, including evidence replay with fresh CPU
and SPI Host harness processes.

## Limits

This acceptance covers one CVA6 implementation, one OpenTitan SPI Host, one
four-byte mode-0 transfer, and aligned 32-bit single-beat MMIO. It does not
verify sub-word or burst MMIO, CPU interrupt delivery/ISR behavior for CVA6,
other SPI modes, or profile-only reuse for other packed AXI4 CPUs. Component
local timing is retained; there is no global cycle-accurate SoC timing claim.
The three configuration writes in this scenario use full 32-bit byte enables
(`WSTRB=0xf`); partial-byte writes into the real SPI Host CSRs are not covered.
