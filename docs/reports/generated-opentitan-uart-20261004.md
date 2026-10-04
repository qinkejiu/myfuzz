# Generated OpenTitan UART TL-UL real RTL acceptance

The pinned OpenTitan UART at `fca045df919a26c47e71616b9dac917b1ea4fd07` now has an independent generated local TL-UL harness. A complete scalar boundary exposes all 37 physical ports: 20 TL-UL fields, clock/reset, serial RX/TX/TX-enable, nine native interrupt outputs, the LSIO trigger, and alert/RACL diagnostics. The alert receiver and RACL policy inputs use package defaults, with RACL disabled for this local parameterization. One real UART RTL process persists throughout each testcase.

The source gate verifies the original lock and closure, the exact local profile and wrapper hashes, and the union of all 43 explicitly read source files plus the wrapper and included directories. The runtime selects `tlul_uart`, routes one bounded beat at a time through `beat_to_tlul` with integrity generation, and records each local clock's pre/post outputs. The serial peer drives one 8N1 RX frame at 32 local clocks per bit, selected before transmission by the Genome. The TX byte is decoded from the actual `cio_tx_o` waveform. RX data is accepted only after the real `uart_rx`/FIFO path and the subsequent TL-UL RDATA response.

Acceptance command:

```bash
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src python3 -m unittest tests.integration.test_local_opentitan_uart_generated_real -v
```

Result: 2/2 passed. The direct real RTL test configured NCO, TX/RX enable and native interrupts, sent TX byte `0x41`, decoded it from the serial pin, drove external RX byte `0x5A`, read the same byte from the real RDATA register, and observed native TX_DONE and RX watermark. The formal scenario tested two Fuzzable Source bytes, `0x5A` and `0xA6`; each reached the real RDATA read, each had exactly four counted direct register transactions under `max_transactions=4`, and each evidence bundle matched a fresh-process replay.

The proof covers one 8N1 frame at NCO `0x8000`, one TX and one RX byte, default alert/RACL settings, and real UART-native interrupt outputs. It does not yet cover CPU trap entry, a CPU→UART→CPU chain, multi-byte FIFO behavior, flow-control interactions, parity/break modes, or other NCO settings. It does not instantiate a complete SoC bus topology.
