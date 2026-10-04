# CVE2 → generated OpenTitan UART → CVE2 RAM

This testcase runs the pinned CV32E20/CVE2 and OpenTitan UART RTL in separate
generated harnesses. The CPU issues genuine OBI MMIO writes through
`DataflowRouter` into the UART's native TL-UL target: CTRL=`0x80000003` enables
TX/RX and WDATA=`0x41` starts a transmit frame. The serial peer observes the
real `uart_tx` pin and captures `0x41`; no session startup writes configure the
UART in this route.

The genome owns one 8-bit `uart_rx_byte` environmental source. Its byte is
held constant during the testcase and turned into one 8N1 waveform on the
UART's native RX pin. The real UART receives that frame and supplies RDATA at
offset `0x18`. The CPU genuinely reads RDATA and writes its low byte to
persistent RAM at `0x20000`. A dependency path from that RAM result through
UART RDATA selects the upstream source for mutation. Two source bytes,
`0x35` and `0xa6`, produce matching RAM words. Each case has bounded evidence
and a matching fresh RTL replay. The router returns the UART RTL's read value;
it never substitutes a fresh random value at the CPU input.

The CPU-routed UART session has a distinct v3 identity. Its contract requires
a genome-owned RX source, empty startup writes, and no session-driven RDATA
read. Identity validation rejects attempts to add a fixed source or session
setup. This first-stage profile supports one 8N1 RX byte, a CPU-driven CTRL and
WDATA write, and one CPU RDATA read. The serial peer uses local UART ticks; the
CPU program waits for the frame before reading. No global cycle-accurate SoC
bus or interrupt controller is modeled.

The CPU IRQ input is fixed to zero. Native UART IRQ pins remain observable,
but this testcase does not deliver an IRQ to the CPU or execute an ISR.

Acceptance commands:

```sh
PYTHONPATH=src MYFUZZ_SCENARIO_REAL=1 python3 -m unittest \
  tests.integration.test_scenario_cve2_opentitan_uart_generated_real -v
PYTHONPATH=src python3 -m unittest \
  tests.local_harness.test_opentitan_uart_routed_identity -v
```
