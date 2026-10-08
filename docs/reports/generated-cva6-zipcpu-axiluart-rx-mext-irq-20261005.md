# Generated CVA6 + ZipCPU AXI-Lite UART RX M_EXT acceptance

This directed scenario verifies one externally supplied UART RX byte through
the pinned ZipCPU `axiluart` RTL, its native RX FIFO level interrupt, a CVA6
machine-external interrupt handler, and CPU RAM. It uses the existing CVA6
profile at `configs/cpus/cva6/component_profile.json` and the AXI-Lite UART
profile at `configs/peripherals/zipcpu_axiluart/component_profile.json`.
The UART profile pins `third_party/soc-zipcpu-wbuart` revision
`f43a6b83c3a70fb2ac0696a45c5545b233fb860b` and elaborates `rtl/axiluart.v`
with its FIFO, RX, TX, and skid-buffer sources. CVA6 is built from the pinned
closure and packed AXI4 interface declared in its component profile.

The CPU and UART run in separate generated RTL harnesses with independent
local clocks. Accepted CVA6 MMIO requests pass through `DataflowRouter` to the
UART register service. This is a local register-delivery path; it does not
instantiate or claim a physical AXI4-to-AXI4-Lite bridge or a shared SoC bus.
The actual UART AXI-Lite target performs its own AW/W/B and AR/R handshakes.

## Source and CPU behavior

The only fuzzable field is the 8-bit external `uart_rx_byte`. The genome seed
is `0x35`; the dependency-aware mutation flips bits 0, 1, 4, and 7 to produce
`0xa6`. Firmware, initial memory images, and the `START` trigger remain
identical. The real CPU writes `SETUP=25` to UART offset `0x00` and its M_EXT
ISR reads RXREG at offset `0x08`. The UART session runs in
`cpu_routed_mode=True`, with no constructor byte, startup writes, or automatic
RX read. Its v3 evidence identity keeps the genome source pending until a
successful CPU-routed RXREG read completes; a frame arriving by itself does
not discharge that obligation.

Each trace contains exactly two UART MMIO acceptances and two deliveries:
the SETUP write and the RXREG read. Their source transaction identities pair
one-to-one and are unique. SETUP has value `25`, byte enable `0x0f`, and an
8-byte CVA6 beat. RXREG returns the expected byte with byte enable `0x0f`.
The scenario ties the CPU's UART-base AWID to the consumed setup BID and ties
the CPU's UART-base-plus-eight ARID to the RX response RID and data. It also
checks the native UART's corresponding AXI-Lite handshakes, including one
completed B response and one AR/R response per transaction.

The SETUP write resets the UART receiver. A diagnostic run recorded its
native B handshake at UART-local tick 328 and the physical RX start bit at
tick 776, leaving a 448-tick idle interval. The test applies a fixed,
test-local 350-tick peer idle extension and asserts from receipts that the
SETUP B handshake precedes the physical start by at least 17 bit cells, or
425 ticks (`17 * 25`). This timing adjustment is fixed environment setup;
it is not a source or mutated genome field. For all 250 UART-local samples in
the 8N1 frame, the test checks the actual exported `i_uart_rx` pin for start,
eight LSB-first data bits, and stop, each held for 25 ticks.

## Interrupt, state, and replay evidence

The actual `uart_rx_int` RX-not-empty level is bound to CVA6
`irq_external`; `irq_timer` is held at zero. The UART's post-tick native
samples include IRQ high before the RXREG delivery. The RXREG target R
handshake occurs after the physical frame end. The binding carries the IRQ
level into CVA6, whose CPU input samples include the asserted interrupt. The
ISR records `mcause=0x800000000000000b`, confirming machine-external interrupt
cause 11. After the FIFO pop, a post-tick native low sample for the RX
delivery's producer appears within the UART-local AR/R handshake interval.

The CPU R-consume receipt is selected only after the RXREG delivery and up to
the next CVA6 AR acceptance, including a possible same-step R-consume/AR
acceptance. It must match RXREG's ARID, RID, and data and assert `RLAST=1`.
That consumed response precedes the accepted RAM store of the received byte.
Persistent RAM holds the following values:

| Address | Meaning | Source `0x35` | Source `0xa6` |
|---|---|---:|---:|
| `0x20000` | received byte | `0x35` | `0xa6` |
| `0x20008` | M_EXT `mcause` | `0x800000000000000b` | `0x800000000000000b` |
| `0x20010` | ISR marker, low 32-bit lane | `0x55` | `0x55` |
| `0x20018` | mainline marker after MRET | `0x66` | `0x66` |

The ISR marker write uses byte enable `0x0f`, and its accepted RAM write
precedes the mainline marker. Both component reset epochs remain zero. The
scenario saves and replays evidence for each source value with fresh session
objects and distinct runner and component execution IDs. Full event and
local-tick traces match their saved traces, and the replayed CPU RAM contains
the same byte and interrupt cause. The two source values produce different
semantic trace hashes.

## Verification

Syntax check:

```sh
python3 -m py_compile tests/integration/test_scenario_cva6_generated_zipcpu_axiluart_rx_mext_irq_real.py
```

Result: exit 0.

New real-RTL scenario:

```sh
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_scenario_cva6_generated_zipcpu_axiluart_rx_mext_irq_real -v
```

```text
test_uart_rx_level_irq_reaches_cva6_mext_isr_and_replays (tests.integration.test_scenario_cva6_generated_zipcpu_axiluart_rx_mext_irq_real.GeneratedCva6ZipcpuAxilUartRxMextIrqRealTests.test_uart_rx_level_irq_reaches_cva6_mext_isr_and_replays) ... ok

Ran 1 test in 93.897s

OK
```

Independent source-stable root rerun:

```sh
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_scenario_cva6_generated_zipcpu_axiluart_rx_mext_irq_real -v
```

```text
Ran 1 test in 94.072s

OK
```

An earlier combined root run hit the replay factory source identity guard
after the integration test source changed during evidence save/replay. The
guard rejected that mixed-source replay as designed. Once source edits
stopped, the standalone run above passed with fresh replays for both bytes.

Focused session and integration regressions:

```sh
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_axil_uart_runtime tests.local_harness.test_axil_uart_pending tests.local_harness.test_axil_uart_routed_identity tests.integration.test_scenario_cve2_zip_axil_uart_real tests.integration.test_scenario_cva6_generated_opentitan_gpio_mext_irq_real -v
```

```text
Ran 11 tests in 169.157s

OK
```

This acceptance covers one 8N1 RX byte per fresh testcase and the RX-not-empty
level interrupt. It does not cover UART TX exchange in this CVA6 scenario,
multiple FIFO entries, other baud settings, nested interrupts, physical bus
bridging, a PLIC, global cycle timing, or a complete SoC. No RTL source or
generic harness template changed. The existing AXI-Lite UART session received
only the bounded CPU-routed pending-read mode needed to represent the real
CPU-owned RXREG transaction.
