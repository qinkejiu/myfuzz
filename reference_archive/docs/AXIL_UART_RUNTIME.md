# Pinned AXI4-Lite UART local runtime

The generated `axi4_lite_uart` variant selects the real `axiluart` top in
`third_party/soc-zipcpu-wbuart` at
`f43a6b83c3a70fb2ac0696a45c5545b233fb860b`. The profile binds all 29
physical top ports: 19 AXI4-Lite channel pins, four serial and flow-control
pins, two clock/reset pins, and four interrupt pins. The five-file source
closure pins `axiluart.v`, `ufifo.v`, `rxuart.v`, `txuart.v`, and
`skidbuffer.v`; a fresh Verilator dependency replay reads exactly those files.

The local driver presents AW and W as distinct AXI4-Lite channels and holds
each valid signal until its handshake. With the pinned `OPT_SKIDBUFFER=0`, the
RTL accepts AW and W together; the driver then waits for the real B response.
Reads issue AR and wait for R. The driver records every tick
and returns the RTL response code and data. The session checks exactly one
handshake on each required channel before admitting a register completion.

The serial peer drives RX as clocked 8N1 bits and decodes TX from sampled
physical pin levels. It waits 17 bit cells of idle after reset, matching the
full `rxuart` synchronization requirement. In the real RTL test, an AXI4-Lite
read returns setup value `25`, an accepted TX register write of `0x41`
produces an observed serial `0x41`, and a peer-driven `0x5a` appears in the
real RX register. A 780-step budgeted scenario saves both the generated
artifact and peer source identity, then replays from a fresh process.

With `source=None`, the session instead owns an 8-bit `uart_rx_byte` Fuzzable
Source. A Genome START action selects one byte for the testcase; the value is
latched before the first frame and cannot be changed mid-frame. Dependency
selection and mutation changed `0x35` to `0xA6`; the two runs produced the
corresponding distinct real RTL RX register values, and both evidence bundles
matched fresh replay. This is a local IP source mutation proof; a generated
CPU-to-UART-to-CPU chain is tracked separately.

The admitted subset fixes baud to 25 clocks per bit, 8N1 framing, one RX
source byte, setup writes of exactly `25`, and byte writes to TXREG. Reads are
limited to the four 32-bit registers. CTS is held active and no arbitrary
baud, break, flow-control transition, FIFO overflow, or concurrent serial
source and AXI register access is claimed. The AXI channels remain distinct;
this variant does not replace them with a synthesized register result.
