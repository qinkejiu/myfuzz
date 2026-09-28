# OpenTitan SPI Device integration, 2026-09-28

## Scope and architecture

SPI Device is now a persistent, independent OpenTitan RTL harness. It uses its
native TL-UL and SPI pins. Ibex runs in a separate RTL harness; the scenario
router forwards accepted CPU MMIO transactions to Device, and the scheduler
delivers only the IRQ value observed from Device RTL. There is no SoC bus,
crossbar, bridge, PLIC, or shared cycle clock. Each harness preserves its own
local timing, while one testcase preserves both RTL instances and RAM state.

An external mode-0 SPI master is a fuzzable source. Its opcode/address/payload
or JEDEC read request becomes legal pin transitions with eight Device system
ticks per SCK half period. The master samples Device MISO; it never supplies
MISO, IRQ, FIFO data, or CPU rdata as random input. A CSb-high SCK reset pulse
initializes SPI-clocked RTL flops before the process reports READY. This was
required by the local Verilator initialization behavior and occurs outside
any transfer.

## Real paths demonstrated

1. CPU -> Device -> external master: Ibex writes CONTROL, JEDEC_ID, and
   CMD_INFO_3. The external master sends opcode 0x9F and observes the actual
   Device MISO bytes A1 34 12.
2. External master -> Device -> CPU: two uploaded 0x02 frames carry different
   24-bit addresses and payload bytes. Device raises its native command FIFO
   IRQ; Ibex takes the interrupt, reads the native command/address FIFOs and
   ingress SRAM, and stores those values in persistent RAM. Both frames run in
   one testcase without reset.
3. RFuzz source mutation: one eight-byte record changes the first external
   address bit, changing Ibex's later FIFO read from 0x1234 to 0x1235. Another
   record changes an Ibex ADDI immediate, changing its real CMD_INFO write to
   0x81010203 and suppressing the 0x02-frame IRQ in real Device RTL.
4. Cutting the Device-to-CPU IRQ binding leaves the external frame executed
   but prevents the CPU FIFO reads and RAM writes; the chain reports
   `path_incomplete`.

The adapter processes at most one pending external frame per local step and
records sent source ports. A new testcase clears those ports; an explicit
reset starts a new RTL epoch while local tick accounting remains monotonic.
The local process caches repeated command results by execution ID and sequence.
The SPI Device mutation graph marks CPU configuration and the later upload
FIFO as `PERSISTENT_STATE_RULE` nodes. These nodes guide source selection;
the graph does not synthesize FIFO contents or IRQ, which remain RTL outputs.

## Source evidence

The SPI Device profile pins OpenTitan revision
`fca045df919a26c47e71616b9dac917b1ea4fd07`. Its native closure has 93
explicit source files and 99 actual vendor files including nested includes.
Native and closure-wrapper Verilator lint complete with zero errors. The
source-lock record was checked through its full hash/read-set replay path.

The repository's formal `verify_soc_sources.py` gate still reports the four
new OpenTitan closure JSON files as untracked. The sandbox mounts `.git`
read-only, so `git add` cannot complete here. This is a Git tracking gate;
the independent source/read-set replay and runtime tests passed. With a
temporary Git index and temporary object directory under `/tmp`, both the
full source gate and `--elaborate` replay exited 0, including exact read-set
matches for SPI Host, I2C, RV Timer, and SPI Device. The real repository index
was not modified. The conditional gate result is recorded at
`runs/scenario/acceptance/opentitan-source-gate-temporary-index-20260928.json`.
The existing
Ibex interface description hash was refreshed after the already-present RVFI
interface update, leaving the four untracked closure paths as the reported
source-lock failures.

When `.git` is writable, the remaining repository-index step is:

```sh
git add -- configs/soc/closures/opentitan_spi_host.json \
  configs/soc/closures/opentitan_i2c.json \
  configs/soc/closures/opentitan_rv_timer.json \
  configs/soc/closures/opentitan_spi_device.json
PYTHONPATH=src python3 scripts/verify_soc_sources.py --elaborate
```

A source-lock-only Git patch was prepared at
`patches/opentitan/opentitan-source-lock-review.patch`. It applies
cleanly to base commit `3f96d5729d375e4f8e569985bf7860816f83f155`
in a writable mirror and contains 15 selected source-lock/profile files.
Its path and SHA256 manifest is
`patches/opentitan/opentitan-git-preparation-20260928.json`.
Generated Verilator lint logs retain upstream trailing spaces in quoted source
lines; `git diff --check` flags those log lines, while other selected files
pass the whitespace check. The real worktree's `.git` was not modified.

## Verification

- Focused SPI Device source closure, runtime, CPU chain, source-contract,
  mutation, and bounded RFuzz campaign tests: 21/21 passed with the current
  code.
- The fixed acceptance bundle at
  `runs/scenario/acceptance/case-ibex-opentitan-spi-device-two-rounds-v1`
  records 6004 events, finishes `complete`, and matches a fresh-process replay
  with `verification_scope=full`.
- Real upload payload is observed at the ingress SRAM TL window; the CPU also
  reads this RTL-backed value in the two-round chain.
- A three-testcase real RTL RFuzz feedback smoke returned coverage bytes
  `01 -> 00 -> 01`. The mutation hint selected the CPU program source, then
  the external SPI frame source; both selected mutations were consumed and
  changed the semantic trace. The middle `path_incomplete` outcome is the
  expected effect of changing the CPU-configured opcode.

This first SPI Device path covers flash mode, a single-line mode-0 external
master, JEDEC read, and one configured upload command. TPM, passthrough,
multi-lane SPI, and a long coverage-guided campaign have not been exercised.
The fixed evidence bundle does not claim coverage-target hits; the separate
bounded campaign supplies feedback evidence. PWM RTL is absent
from the pinned local OpenTitan source and remains unavailable for integration.
