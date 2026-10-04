# CVE2 ↔ ZipCPU AXI4-Lite UART generated harness chain

The bounded testcase runs a generated CV32E20 CPU harness and a generated
ZipCPU `axiluart` target harness as separate RTL processes. Its program writes
one byte to UART TX through a real CPU OBI data request, the transaction ledger,
and `DataflowRouter`. The target accepts one AXI4-Lite AW/W/B transaction and
the serial peer decodes the UART's real TX pin as `0x41`.

The testcase also injects one genome-owned `uart_rx_byte` through the serial
peer. The peer drives a timed 8N1 waveform to the real UART RX pin. After the
RTL receives it, the CPU issues a genuine MMIO read of the UART RX register and
stores the low byte in persistent RAM at `0x20000`. A dependency path from the
external serial source through the UART RX FIFO to the CPU RAM result selects
the source for mutation. Four bit flips transform `0x35` to `0xa6`. Both values
are observed in the final CPU RAM, and both complete bundles replay in fresh
RTL processes with matching semantic traces.

The UART session permits MMIO transactions before a scheduled serial waveform
starts. It still rejects an AXI transaction whose bounded local tick span may
overlap an active waveform, because the current AXI access driver holds the RX
pin at idle for the duration of its bounded register command. The CPU program
waits before reading RX. This is a local UART peer restriction; it does not
impose global cycle alignment between the CPU and UART harnesses.

The CPU IRQ input is fixed to zero in this testcase. A real `uart_rx_int` pin
assertion is captured as RTL evidence, but CPU interrupt delivery or ISR
execution is not claimed. AXI4-Lite access is the pinned single outstanding
target variant with accepted byte strobe for TX and a 32-bit RX read. The serial
peer supports one 8N1 source byte per testcase.

Acceptance command:

```sh
PYTHONPATH=src MYFUZZ_SCENARIO_REAL=1 python3 -m unittest \
  tests.integration.test_scenario_cve2_zip_axil_uart_real -v
```
