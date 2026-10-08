# PicoRV32 Wishbone / ZipCPU wbuart RX custom IRQ acceptance

The directed scenario uses the existing `picorv32_wb_irq` CPU profile
(`ENABLE_IRQ=1`) and `zipcpu_uart` peripheral profile. CPU and UART run in
separate generated harness processes. Accepted CPU Wishbone transactions pass
through `DataflowRouter` to the native `wbuart` Wishbone target. No production
runtime, session, RTL, source lock, or profile was changed.

Only external `uart_rx_byte[7:0]` is fuzzable. The UART's actual
`uart_rx_int` RX FIFO nonempty level binds CPU `irq[3]`; CPU IRQ bits `[2:0]`
and `[31:4]` are fixed zero. The bound IRQ input cannot be mutated. The
dependency path selects the external byte through RX FIFO data, real IRQ and
CPU result RAM. Mutation flips source bits 0, 1, 4 and 7, changing `0x35` to
`0xa6`; every other Genome field, including firmware, images and action timing,
is identical.

The UART session uses `source=None, cpu_routed_mode=True`, with empty startup
writes and automatic RX reads disabled. The real CPU commits exactly one
`SETUP=25` write at offset `0x00`, then its custom IRQ handler reads RXREG at
offset `0x08` exactly once. The acceptance checks both source transaction
identity and the two actual one-cycle native target STB pulses, their register
addresses, byte enables, write/read direction, and real target responses.
There are no harness-owned register transactions or duplicate deliveries.

`SETUP` occupies the first three CPU reset-entry instructions, before the
jump to main at `0x80`. SETUP resets the UART receiver. The pinned receiver
requires a 16-cell idle interval (`16 * 25 = 400` UART local ticks), followed
by its reset/synchronization state updates. The external peer therefore adds
one fixed 25-tick idle cell to the session's existing 17-cell startup mark.
This timing is fixed environment configuration and is not a Fuzzer source.
The factory's source hash covers the local peer helper during evidence replay.

The test selects the byte at `Trigger('START')`, then checks actual native
SETUP STB pre/post receipts and the completed MMIO delivery before the first
physical RX start bit. It checks the same UART clock domain's idle interval,
and all 250 physical `i_uart_rx` pre receipts for start, eight data bits in
LSB-first order, and stop at 25 ticks per bit. These are DUT pin receipts,
not an inferred waveform from the Genome action. CPU/UART local clocks are
not compared as a global clock.

The real RX FIFO IRQ rises before the ISR's RXREG transaction, remains high
until that access, and falls within the actual native read's pre/post samples
after the FIFO pop. The UART physical IRQ export agrees with the semantic
alias. Binding deliveries carry the one-bit fragment `1`; actual CPU input
samples carry the full vector `8`. The CPU consumes the exact RXREG response
before it writes the received byte to persistent RAM.

Firmware uses the pinned Pico custom0 ABI: `getq x5,q1` at handler entry
`0x10`, `maskirq` at `0x30` and `retirq` at `0x34`. Main enables only IRQ3 with mask
`-9`. The ISR masks further IRQs with `-1` before returning, suppressing any
retained pending bit under the profile's default `LATCHED_IRQ=0xffffffff`.
The acceptance observes exactly one `eoi=8` entry interval, `trap=0`
throughout, q1=`8`, then `eoi=0` after the real return. No CSR/MRET behavior
is claimed.

Each payload produces these RAM values and exactly these four result writes:

| Address | Meaning | Source `0x35` | Source `0xa6` |
|---|---|---|---|
| `0x200` | received byte | `0x35` | `0xa6` |
| `0x204` | custom q1 pending vector | `8` | `8` |
| `0x208` | ISR completion marker | `0x55` | `0x55` |
| `0x20c` | main after `retirq` | `0x66` | `0x66` |

RAM write events indicate accepted stores. The test additionally checks each
real CPU store response consumption and that the main marker request follows
the ISR stores' completion and EOI clear. There is no reset inside a testcase;
both component epochs remain zero.

Each payload's evidence bundle is saved separately and replayed with new CPU
and UART session objects and process execution IDs. Full semantic trace
comparison matches; every ownership, physical waveform, MMIO, IRQ, custom
handler and RAM assertion is rerun on each fresh trace. The two payloads
have different semantic hashes and different actual CPU RAM bytes. Temporary
evidence bundles are removed when the test ends.

The strengthened acceptance passed with the exact command:

```sh
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_scenario_picorv32_wb_zipcpu_uart_irq_real -v
```

```text
Ran 1 test in 24.175s

OK
```

This run exited zero and contains four actual RTL executions: two source
bytes and their respective fresh replays. A preceding GREEN also passed in
23.805 seconds, followed by the strengthened run in 24.227 seconds. The
24.175-second final run includes the clarified peer timing comment. The
controlled RED kept main's IRQ mask at `-1` while the
fixed idle adjustment allowed real UART FIFO IRQ high. Both payloads passed
that native IRQ check and failed specifically with
`real Pico never entered custom IRQ3 handler`; `Ran 1 test in 19.635s`,
`FAILED (failures=3)`, exit one. The third failure was the final collected
payload comparison after the two failed subtests. Restoring only main's mask
to `-9` enables the real handler; ISR masking remains `-1`.

Initial attempts exposed insufficient receiver synchronization: SETUP at
UART tick 50 left 376 ticks until RX start 426. Moving SETUP to reset entry
advanced the actual target strobe to tick 26, leaving exactly 400 ticks,
which still did not cover the derived reset/synchronization updates. The
fixed extra idle cell resolves this environment timing issue. The final test
requires at least 425 UART local ticks between SETUP's actual post receipt
and physical RX start. This was not a defect in the CPU or UART RTL.

The requested focused regression command was:

```sh
PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_wishbone_cpu_irq tests.integration.test_scenario_picorv32_wb_opentitan_gpio_irq_real tests.integration.test_scenario_cve2_zip_wb_uart_real -q
```

The final run ran four tests in 19.178 seconds and exited zero with
`OK (skipped=2)`; the preceding run passed in 18.910 seconds.
The two existing integration modules have the `MYFUZZ_SCENARIO_REAL` gate;
the requested command omits that environment flag. The Pico IRQ profile and
real timer/handler/replay regressions ran. This result does not claim the
two gated integration modules ran RTL in that command.

`git diff --check` exited zero with no output. Checks of both newly added
files using `git diff --no-index --check /dev/null <file>` emitted no
whitespace diagnostics (exit one denotes their new file differences).

This accepts one 8N1 RX byte per fresh testcase with a fixed 25-tick bit cell
and RX-not-empty level IRQ. It does not cover TX exchange in this new
scenario, FIFO-watermark IRQ, arbitrary baud settings, repeated or nested
interrupts, a physical shared Wishbone fabric, a PLIC, global cycle timing,
or a complete SoC. This is directed dependency-aware source mutation, not
a coverage-guided defect search. No RTL defect was identified.
