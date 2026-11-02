# round1 DMA read route: the ZipDMA master reads a declared APB3 register into RAM

**Date:** 2026-11-02.  **Scope:** the third DMA increment of the in-process
F1–F6 entry.  `runs/round1-dma-a/` ran ZipDMA blocks against host RAM;
`runs/round1-dma-b/` made the DMA master *write* the PULP SPI TX FIFO.  This
increment executes the other direction: the Wishbone DMA master issues a real
read beat (`we=0`) at a declared readable APB3 register, the host serves that
beat from the target's own APB3 port (`PWRITE=0`, `PREADY`/`PRDATA`), and the
DMA writes the captured word into the incrementing RAM destination block.

Evidence: `runs/round1-dma-read/` (`README.md`, `campaign.log`, `run_campaign.sh`,
per-run `run.log`/`summary.json`/`spike_config.h`).

## result in one line

Fixed chain **2/2**, two routed reads in one process **3/3**, mixed flows
**5/5**, fuzz 10 cases **10/10** (F6 2/2, correspondence 10/10), and six
regressions all pass; the DMA read `0x00005a5a` from the PULP I2C `PRESCALER` at
`0x20001000` (a value an earlier F4 case wrote), wrote it to all four RAM
destination words, and the CPU's own pre/post readback and destination readback
agree with it.  `dma_ram_reads 0` — the routed read was never served from RAM.

## what changed

### planner — `src/myfuzz/composition/dma_transfer.py`

The declaration layer already accepted `direction: "read"` and a fixed
`address_mode`; it refused a read from a write-only register and a fixed route
whose source increments.  Two things were wrong for this increment:

* `_route_evidence_description` stated the write-route evidence for every
  direction ("the declared field must change").  It is now direction-aware: a
  read route's `register_readback` evidence is the returned word, and the
  expectation states that the DMA's captured word, the CPU's pre/post readback
  and the RAM destination words must all agree.
* `dma_route_target`'s `host_support` said `not_implemented` and described a host
  that "serves the DMA master from RAM only" — stale since the write route
  landed.  It now names the entry that executes the declared shape and keeps
  `completion_claimed: false`, so the planner still never claims a transfer.

`tests/composition/test_dma_transfer.py` gained two tests (44 total, all
passing): the accepted read route (fixed source, start word `0x00040000`,
read expectation text, geometry/evidence) and the named refusals (read from a
write-only register, an undeclared register, a fixed route whose source
increments).  One existing assertion was updated from `not_implemented` to the
new `host_support` status.

### entry — `scripts/run_inprocess_f1f6.py`

* `DMA_ROUTE_DIRECTIONS` now includes `read`.  `dma_route_support` is
  direction-aware: a write route requires the fixed *destination* and a writable
  register; a read route requires the fixed *source*, an incrementing RAM
  destination and a readable register.  A read route's evidence must be
  `register_readback` **on the routed register itself** (`read-evidence-kind`,
  `read-evidence-register-mismatch` refusals); a FIFO read route is refused by
  name because this host does not pop a FIFO.
* `reset_before_case` is now `direction == "write"`.  A write route resets the
  devices before its case so the FIFO starts empty; a read route must not,
  because the register state an earlier case left is the transfer's source data.
  The header and the case line state the policy
  (`DMA_ROUTE_RESET_BEFORE_CASE`, `dma_route_reset_before_case`).
* `build_firmware` programs `DMA_SOURCE` with the route address and
  `DMA_DESTINATION` with the RAM block for a read route (the reverse of the write
  route), skips the record-payload copy into the RAM source window (a read route
  has no RAM source), and after the completion flag loads the four RAM
  destination words with the CPU and stores them into dedicated evidence cells
  (`layout['route_dst']`).  `build_layout` takes a `result_span` so those cells
  are inside the checked image.
* `render_bindings` renders `DMA_ROUTE_READS` and `DMA_ROUTE_DST_ADDRESS`
  beside the existing `DMA_ROUTE_*` macros.
* `correspondence` has a read-route branch: routed read count/acks/target reads,
  `dma_ram_reads == 0`, stable captured word across the beats, every RAM
  destination word and every CPU readback cell equal to its captured word, CPU
  pre/post readback equal to the captured word, and — for the fixed record chain
  — the captured word equal to the value the preceding F4 case **observed** it
  wrote (`RouteReadExpectation`, reported as `route_read_expected_value` in the
  case document).  The fuzz path states no F4 expectation because the generator
  owns the sequence; the route's own evidence still applies there.

### host — `scripts/inprocess_obi_apb_f1f4_spike.cpp`

* `MasterRoute` gained a `read` flag.  On an accepted routed read beat the host
  does not touch RAM: it drives the routed target's APB3 request with
  `PWRITE=0` at the declared offset, holds the master (`mwb_stall`) until the
  target's `rsp_valid`, captures `PRDATA`, and returns it on `mwb_dat_r` with the
  ACK.  The CPU keeps priority on the shared target port and is stalled while the
  route owns it (the existing write-route arbitration).
* the APB trace counts the target's completed routed reads
  (`dma_route_target_reads`) and keeps the trace `PRDATA` for comparison with the
  bridge response; `dma_ram_reads` counts master reads served from RAM.
* the case line prints the read group (`dma_route_direction read`,
  `dma_route_source`, `dma_route_reads/acks/target_reads`, `dma_route_read_value`,
  `dma_route_read_stable`, `dma_route_read_matched`, `dma_route_cpu_matched`,
  `dma_ram_reads`, `dma_ram_writes`, `dma_route_evidence_before/after`,
  `dma_route_cpu_dst0..N`), and the summary prints `dma_route fixed_read` with
  the read totals.  Write-route and RAM-only builds print exactly what they
  printed before (all read fields are compiled out).

### scenarios

* new `configs/scenarios/inprocess-obi-apb-timer-i2c-dma-read-f1f6.json`:
  timer at `0x40001000` (F5), PULP I2C at `0x20001000`, ZipDMA block 4, read
  route to `PRESCALER` offset 0, `dma_increment_source false`,
  `dma_increment_destination true`, `fuzz_seed_records ["F4:20001000:00005a5a"]`.
* negative controls under `runs/round1-dma-read/configs/`: read route to a
  write-only register, read route with FIFO-level evidence, incrementing
  (aperture) read route.

## evidence

`runs/round1-dma-read/read-fixed/run.log` (exact case lines are in the run
README):

```
F4:20001000:00005a5a  -> mmio_addr 0x20001000 mmio_value 0x00005a5a
                         apb_pwdata 0x00005a5a apb_pready 1 target1_writes 1
F6:...                -> dma_reads 4 dma_writes 4
                         dma_first_read_addr 0x20001000 dma_first_read_value 0x00005a5a
                         dma_route_direction read dma_route_source 0x20001000
                         dma_route_reads 4 dma_route_acks 4 dma_route_target_reads 4
                         dma_route_read_value 0x00005a5a dma_route_read_stable 4
                         dma_route_read_matched 4 dma_route_cpu_matched 4
                         dma_ram_reads 0 dma_ram_writes 4
                         dma_ram_lane_written 16 dma_ram_lane_missing 0
                         dma_guard_lo/hi 0xa5a5a5a5
                         dma_start_word 0x00040000 dma_start_write 0x00040000
                         dma_route_evidence_before/after 0x00005a5a
                         dst0..3 0x00005a5a  dma_route_cpu_dst0..3 0x00005a5a
```

The F4 case's `target1_writes 1`/`apb_pready 1` is the write that put the value
into the register; the F6 case's `dma_route_target_reads 4` is the target's own
completed APB3 reads; the CPU's `F2:20001000` in `read-flows` returns
`0x00005a5a` after the DMA read it, so the routed read is non-destructive.

## regressions

| run | result |
|---|---|
| RAM→IP FIFO write route (`inprocess-obi-apb-ibex-timer-zipdma-fifo-f1f6.json`) | 1/1, `dma_route_writes 8 dma_route_acks 8 dma_route_target_writes 8 dma_ram_writes 0`, TX level 0→8, start word `0x00400000` — same facts as `runs/round1-dma-b/fifo-fixed` |
| RAM→RAM 8-word block (`...len8-f1f6.json`) | 1/1, 8 reads/8 writes, `dma_lane_written 32`, guards intact |
| device byte enables (`...byteen-f1f6.json`) | 1/1, 16/16 beats, start `0x00330000`, `dma_sel_partial 16 dma_sel_full 0` |
| declared delay (`...delay-f1f6.json`) | 1/1, `dma_response_delay_declared 2 dma_delayed_acks 8 dma_wait_min 3 dma_wait_max 4 dma_delay_evidence observed` |
| timer + ZipDMA F1–F6 (`...timer-zipdma-f1f6.json`) | 6/6, every case line identical to `runs/round1-dma-a/regressions/zipdma-block4/run.log` except another increment's `level_stuck 0` field |
| two-IP timer + I2C F1–F6 (`...two-ip-timer-i2c-f1f6.json`) | 6/6, identical to `runs/round1-multi-ip/fixed/run.log` except the F5 `level_stuck 0` field |

## tests

```
PYTHONPATH=src:. python3 -m pytest \
  tests/composition/test_dma_transfer.py \
  tests/composition/test_inprocess_behavior.py \
  tests/integration/test_inprocess_f1f6_entry.py -q
-> 297 passed
```

`tests/composition/test_dma_transfer.py` alone: 44 passed (the historical 42
plus the accepted read route and the read-route refusals).

## two device facts this increment surfaced

* the pinned ZipDMA cannot address `>= 0x40000000`: its `SOURCE`/`DESTINATION`
  CSR fields are 30-bit byte addresses
  (`third_party/soc-zipcpu/rtl/zipdma/zipdma_ctrl.v:73-74,161-181,259-260` with
  `ADDRESS_WIDTH=32`, `BUS_WIDTH=32`).  A route to the I2C's SoC base
  `0x40002000` is refused by the planner (`dma-route-target-unreachable`) rather
  than silently truncated; this scenario maps the I2C at `0x20001000` for the
  route, the same choice the FIFO increment made for the SPI.
* the PULP I2C `PRESCALER` stores `PWDATA[15:0]` and reads back
  `{16'h0, r_pre}` (`third_party/soc-pulp-apb-i2c/apb_i2c.sv:87-88,113`), while
  its profile declares a 32-bit register.  The deterministic source word is
  therefore `0x00005a5a`, and the fuzz path deliberately does not check a
  preceding F4 value (a random 32-bit write would be truncated by the device).

## limits

One outstanding master beat; no error injection (`mwb_err` low); no FIFO read
route and no aperture read route (refused by name); the route target must be an
APB3 target of this build on the OBI CPU bus; the destination is a RAM block and
the RAM source window is never read for a routed beat; the fixed chain's expected
word is the observed value of the preceding F4 case, the fuzz path states none.
No coverage, certificate or replay claim is made.

## code state and concurrency caveat

The four files this increment owns (`src/myfuzz/composition/dma_transfer.py`,
its test file, `scripts/run_inprocess_f1f6.py` and
`scripts/inprocess_obi_apb_f1f4_spike.cpp`) are **untracked** in this repository
snapshot (`git status --porcelain` reports `??`), so `git diff --stat` shows no
hunks for them; the new scenario config is untracked as well.  The shared entry
and host were edited concurrently by other increments (F1/F5/CVA6 sections) while
this directory was produced; the campaign was re-run as a whole after the last of
those edits landed, and `campaign.log` is one clean pass.  The saved case lines
are the authoritative observation.
