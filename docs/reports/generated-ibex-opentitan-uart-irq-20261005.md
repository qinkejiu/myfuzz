# Ibex ↔ OpenTitan UART RX watermark interrupt

This scenario runs the pinned Ibex OBI CPU and OpenTitan UART RTL in separate
local harnesses. Ibex configures the UART through the abstract MMIO router. The
genome owns one external RX byte, which an 8N1 peer drives on the UART's real
RX pin. The testcase does not instantiate a SoC bus or interrupt controller.

Ibex enables the UART RX watermark interrupt and installs a machine external
interrupt handler. The true `uart_rx_watermark` output is bound to Ibex's
external interrupt input. After interrupt entry, the handler reads the real
UART `INTR_STATE` and `RDATA` responses, then stores both in testcase-persistent
RAM. Reading `RDATA` empties the single-byte FIFO; the status signal and bound
IRQ then fall. The handler does not write the RX watermark state bit: pinned
OpenTitan UART RTL implements this interrupt as `Status`, and `INTR_STATE[1]`
is a read-only reflection of the FIFO condition.

The run checks the external source injection, native IRQ assertion and
delivery, CPU MMIO reads after IRQ delivery, the actual status and RX byte,
RAM persistence, IRQ deassertion after the FIFO pop, absence of a reset barrier,
and fresh-harness evidence replay. The selected RX byte is `0x5a`; the test
verifies the RX watermark bit and preserves the full observed status word in
RAM.

The UART session rejects TL-UL accesses while the external RX waveform is
active. A blocking access would hold the sampled RX value for extra local
clocks and distort serial bit timing. This scenario therefore executes 64 real
Ibex NOP instructions after interrupt entry; the UART frame completes while
Ibex continues to run, before the handler accesses the UART. Concurrent MMIO
and an active RX waveform remain unsupported.

The initial real run caught a missing legal configuration write: Ibex's
`INTR_ENABLE=2` OBI transaction reached the routed UART but the session rejected
it, leaving an uncertain target transaction. The session and its identity
contract now allow that exact full-word write while retaining rejection of
unsupported `INTR_STATE` writes and other unlisted register writes.

Verification:

```sh
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest \
  tests.integration.test_scenario_ibex_opentitan_uart_irq_real -v
PYTHONPATH=src:. python3 -m unittest \
  tests.local_harness.test_opentitan_uart_routed_identity -v
```

Both passed on 2026-10-05. The real integration test completed one testcase and
fresh replay (`Ran 1 test in 42.688s`, `OK`). The identity test passed one
contract test (`Ran 1 test`, `OK`). This is a directed RTL acceptance; it does
not report coverage-guided RTL bug discovery.
