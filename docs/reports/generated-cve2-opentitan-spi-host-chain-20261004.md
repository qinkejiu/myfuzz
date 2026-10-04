# CVE2 → generated OpenTitan SPI Host → CVE2 RAM

This testcase runs CV32E20/CVE2 and OpenTitan SPI Host as separate generated
real RTL processes. The CPU boots the testcase program image. Its genuine OBI
data requests configure the Host through `DataflowRouter` and the generated
TL-UL target: CONTROL=`0xa0000001`, CONFIGOPTS=`8`, then COMMAND=`0x68`.
There are no prewritten Host setup registers in this route.

The scenario genome owns a 32-bit `spi_source_word`. A dependency path from the
CPU RAM result through the Host RX FIFO selects that upstream source for
mutation. The source word is converted to four serial bytes and held for the
whole testcase. The peer advances MISO only from the real Host SCK/CSB pins;
the Host receives 32 selected rising edges. After the local transfer completes,
the CPU executes a genuine MMIO read of RXDATA and stores the returned word to
persistent RAM at `0x20000`. A source mutation from `0x12345678` to
`0x12345679` changes the real RXDATA and CPU RAM value from `0x78563412` to
`0x79563412`. Each variant has a bounded evidence bundle and matching fresh
RTL replay.

The routed session restricts the first stage to one full-width, four-byte,
single-line mode-0 read. CPU accesses that would overlap active serial input
are rejected because the current generated register command holds its input
pad fixed while completing a bounded TL-UL transaction. The CPU program uses a
delay loop so its RXDATA read follows the real 32-edge completion. This loop
is a scenario ordering choice, not a global cycle-accurate SoC model.

The CPU IRQ input is fixed to zero. The Host IRQ pins remain observable, but
the test does not claim CPU interrupt delivery or ISR execution. It also does not claim
multiple commands, transmit FIFO traffic, other SPI modes, chip selects, or a
complete OpenTitan SoC fabric.

Acceptance command:

```sh
PYTHONPATH=src MYFUZZ_SCENARIO_REAL=1 python3 -m unittest \
  tests.integration.test_scenario_cve2_opentitan_spi_host_generated_real -v
```
