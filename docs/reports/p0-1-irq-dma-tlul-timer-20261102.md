# P0-1 agent B: IRQ/DMA declarations, the OpenTitan TL-UL rv_timer, and the wires they drive

Date: 2026-11-02.  Scope: the P0-1 agent-B increment of the unified in-process
executor (`scripts/run_inprocess_f1f6.py` + `scripts/inprocess_obi_apb_f1f4_spike.cpp`).
This report states what was declared, what was wired, what really ran, and what
stays refused.  It does not claim coverage, a certificate, a replay, full SoC, or
a CPU vector.

The evidence package is `runs/p0-1-ip/`; its `README.md` holds the full case and
summary lines, `batch2/campaign.log` the exact command output, `hunks.diff` this
increment's three Python hunks, and `batch2/` the reference runs.

## 1. Required IRQ and DMA declaration fields, and the host wires

The split is deliberate: the CPU profile states the interrupt **entry**, the
target behavior file states the **device facts**, and the C++ host wires only
what those declarations say.  The profile/behavior cross-check remains the
entry's job.

### 1.1 IRQ

| field | declaration | cross-check | host wire / observed fact |
|---|---|---|---|
| CPU interrupt entry | CPU profile `processor.interrupts`, field `external`, width 1, alias `irq_external_i` | only external input; NMI/software/timer/fast held 0 by `port_actions` | `CPU_IRQ` binding, `CPU_IRQ_WIDTH`, `CPU_IRQ_WIRED`, `CPU_IRQ_TAKE`; `irq_takes` |
| CPU vector | same entry | width 1 = one OR'ed input | no per-source vector; `irq_cause` is status content. NMI (`unsupported-irq:nmi-uncomposed:`), PLIC (`unsupported-irq:plic-not-composed:`), multi-bit vector (`unsupported-irq:cpu-multibit-vector:`) refuse by name |
| IRQ output | behavior `source_port` | profile `interrupts[].endpoint_id` + field alias | `IRQ_SOURCES(X)` row, `IP_HAS_IRQ_n`, `IP_IRQ_BIT_n`, `target<n>_irq_high_ticks` |
| IRQ bit | behavior `source_bit_offset` | output bit range | bit select; `irq_link_edges` |
| trigger kind | profile `interrupts[].trigger` | behavior `pulse_width_ticks` for pulse | `IRQ_LINK_LEVEL`; `device_high_ticks` vs `delivered_high_ticks` |
| polarity | profile `interrupts[].polarity` | active high/low | link inversion; active-low without a composed source keeps `unsupported-irq:device-active-low:` |
| trigger writes | behavior `trigger_writes` | each writable 32-bit profile register | F5 stores into the selected link window; `trigger_writes_observed`, `last_trigger_offset/data` |
| status word | behavior `status_offsets` (one) | readable 32-bit profile register | ISR load; `target_read_offset`, `target_read_data`, `isr_read_addr`, `isr_result`, `isr_read_register_kind` |
| status cause | behavior `status_cause_bits` | bit positions in that word | `IRQ_LINK_CAUSE_MASKS`; `isr_cause` (masked read or `unknown`) |
| status side effect | profile register `side_effect` | `read_clears` or W1C | `IRQ_LINK_READ_CLEARS`; a read-clearing status may declare no clear write |
| clear write | behavior `clear_writes` (0/1) | one writable 32-bit profile register | ISR store after the read; `clear_writes`, `last_clear_offset/data`; a level source without a clear (or read-clearing status) is refused |
| link table | v2 `irq_sources` or v1 flat facts | all links share one trigger-write count | one global link index + trigger words in the F5 record; `irq_link`, `irq_link_edges`, `irq_link_target`, `irq_level_final`, `level_stuck` |
| both row | two targets, one link each | same trigger count | one OR'ed CPU input, two status reads, `F5_BOTH_*` group, no vector claim |

The timer's declaration is the minimal complete one:
`configs/behaviors/opentitan_rv_timer_f5.json` states one output/bit, four
trigger writes, one status word, one cause bit and one clear write.  The host
returns `trigger_offsets [0x4, 0x118, 0x11c, 0x100]`, `status_offset 0x104`,
`status_kind status`, `cause_mask 0x1`, `clear {0x118, 0xffffff00}`.
`tests/integration/test_p0_1_irq_dma_declarations.py` pins the mapping and the
refusals for a missing trigger, a level source without a clear, a non-readable
status word, and a source port the profile does not export.

### 1.2 DMA

| field | declaration | cross-check | host wire / fact |
|---|---|---|---|
| control port | DMA profile `control` offset | generated 2-bit-index `swb` port, `CONTROL_STATUS` side effect | `DMA_BASE/SIZE`, `DMA_CONTROL_OFFSET`; `ctl_config_writes`, `ctl_start_writes`, `ctl_clear_writes` |
| status bits | behavior `busy_bit` 31, `err_bit` 30, `status_kind` | profile/edge contract; reported file-declared | `DMA_BUSY_BIT/ERR_BIT`; `busy_before/after`, `err_before/after`, `ctl_status` |
| DMA IRQ | provider profile + behavior `irq_pulse_ticks` | level/pulse | one extra IRQ link, `IRQ_DMA_LINK_INDEX`, `DMA_IRQ_LEVEL`; F6 `irq_edges`, `irq_takes`, `isr_result` |
| DMA clear | provider `irq_clear` | full-word write, declared register | `DMA_CLEAR_DECLARED/MASK`; `dma_clear_declared`, `ctl_clear_writes` |
| block words | `dma_block_words` + behavior `block_words` | host cap 8, plan block | `DMA_BLOCK_WORDS`; one F6 input word per block word |
| source/destination/length | scenario + plan | profile register map, address units | `DMA_SOURCE/DESTINATION/LENGTH_VALUE`, `DMA_START_WORD`; `dma_first_read_addr`, `dma_last_write_addr`, `dst0..7` |
| master byte enable | plan `master_byte_enable` | full word mask 15 for the APB3 route | `DMA_MASTER_SEL/SHIFT/LANE_MASKS`; `dma_sel_full/partial`, `dma_lane_missing` |
| response delay | plan `response_delay` + backpressure | host cap 8, one outstanding | `DMA_RESPONSE_DELAY`, `DMA_STALL_EXPECT_*`; `dma_acks`, `dma_delayed_acks`, `dma_wait_min/max` |
| error injection | plan `error_injection` | read route only, declared beat | `dma_error_injected`, `dma_error_beat`, sticky `err_after` |
| route direction | `dma_route.direction` | plan increment flags | `DMA_ROUTE_DIRECTION/READ`; `dma_route_direction`, `dma_route_reads/writes` |
| route address mode | `dma_route.address_mode` fixed/aperture | register map | `DMA_ROUTE_FIXED/APERTURE`; `dma_route_address_mode`, `dma_route_sequence` |
| route target | index/name/profile/window | built target rows | `DMA_ROUTE_TARGET_INDEX/BASE/ADDRESS`; `dma_route_target_index`, `dma_route_offset` |
| route evidence | `evidence.kind`, register/offset/bits/depth/expected word | routed register side effect, CPU pre/post readback | `DMA_ROUTE_EVIDENCE_*`; `fifo_status_before/after`, `dma_route_evidence`, `dma_route_cpu_matched` |
| route protocol | target artifact protocol | must be `apb3` | `unsupported-dma-route:apb3-target-only:<protocol>:<name>`; the real run and `dma_route_protocol_check` now agree |

The route presents each accepted master beat on the routed target's APB3
request/response port (`psel`/`penable`/`pwrite`/`paddr`/`pwdata` → `pready`,
`prdata` back on `mwb_dat_r`; a declared injected beat drives `mwb_err`).  The
APB3 route path is unchanged after the new target protocols.

## 2. The new IP: OpenTitan rv_timer TL-UL

### 2.1 RTL facts

`rv_timer_reg_pkg.sv`: `CTRL 0x004` (bit 0 active), `INTR_ENABLE0 0x100` (bit 0
IE), `INTR_STATE0 0x104` (**rw1c**, bit 0 IS), `INTR_TEST0 0x108` (wo),
`TIMER_V_LOWER0/UPPER0 0x110/0x114`, `COMPARE_LOWER0_0/UPPER0_0 0x118/0x11c`
(reset value `0xffffffff` **each**, so the reset mtimecmp is
`0xffffffffffffffff`).

`rv_timer.sv:77-101`, `timer_core.sv:39-41`: the output is
`state & enable`; the event is `active & (mtime >= mtimecmp)`; `prim_intr_hw`
is the Event type, so the state is set while the expired condition holds and
cleared only by W1C or a compare update.  `rv_timer.sv:82-83` makes
`mtimecmp_update` clear `intr_state0`; `prim_subreg_arb.sv`/`prim_intr_hw.sv`
make a W1C win only for the write cycle.

### 2.2 Trigger

Four real writes: `CTRL=1`, `COMPARE_LOWER0_0=0`, `COMPARE_UPPER0_0=0`,
`INTR_ENABLE0=1`.  The upper compare write is required; with only the lower
word at 0 the model's `mtimecmp` was `0xffffffff00000000` and no interrupt ever
asserted (`batch2/negative-upper`).  With both words at 0, `mtime` (real
counter; `0x132` = 306 in the F1–F5 batch `runs/p0-1-ip/tlul-timer-f1f5`) is `>= mtimecmp`, the output
asserts, and the CPU takes it.

### 2.3 Clear, and the W1C blocker

The ISR reads `INTR_STATE0` (status; bit 0 cause), stores it, then writes
`COMPARE_LOWER0_0 = 0xffffff00`.  That is the RTL's own compare-update clear:
it deasserts `intr_state0` and makes `mtime < mtimecmp`, so the raw output falls.
A W1C of `INTR_STATE0` alone is **not** an honest clear while the timer is
still enabled and expired: the Event-type `prim_intr_hw` re-sets the state on
the next tick.  A direct probe compiled against the same cached Verilator model
read `state=1 irq=1` after the W1C and `state=0 irq=0` after the compare re-arm.
The run therefore declares the compare write as its clear, not a W1C write, and
does not use `INTR_TEST0` or a host-driven `mtime`.  This is the exact RTL fact
that makes the W1C-only clear impossible; the ISR still reads the real status
word before clearing.

### 2.4 Real run

`batch2/all-six`, scenario
`configs/scenarios/inprocess-obi-tlul-timer-zipdma-f1f6.json`:

```
PYTHONPATH=src:. python3 scripts/run_inprocess_f1f6.py \
  --config configs/scenarios/inprocess-obi-tlul-timer-zipdma-f1f6.json \
  --cache runs/round3-target-protocols-cache --output runs/p0-1-ip/batch2/all-six \
  --records 'F1:2ab00693,F2:40004104,F2:40004118,F3:00014004:0badf00d,F4:40004004:00000001,F2:40004004,F5:1:0:0:1,F2:40004104,F6:11111111:22222222:33333333:44444444'
```

9/9 `observations_passed`; host run 4.70 ms, wall 11.16 s, one relink
(`link_seconds 5.49`), per-case 128.86/43.01/38.85/39.95/55.56/37.91/201.20/
48.22/288.74 µs.  The F5 line (full text in the package README):

```
case 6 observations_passed flow F5 record F5:00000001:00000000:00000000:00000001 ... irq_edges 1 irq_high_ticks 39 device_high_ticks 39 delivered_high_ticks 39 irq_takes 1 wait_timeout 0 isr_result 0x00000001 isr_flag 1 isr_read_addr 0x40004104 isr_read_value 0x00000001 isr_read_register_kind status trigger_writes_declared 4 trigger_writes_observed 4 clear_writes 1 last_trigger_offset 0x00000100 last_trigger_data 0x00000001 last_clear_offset 0x00000118 last_clear_data 0xffffff00 isr_cause 0x00000001 irq_link 0 irq_link_edges 1 irq_level_final 0x00000000 level_stuck 0
```

`irq_edges 1` is the link's real output, `irq_takes 1` the CPU's accepted
interrupt, `isr_read_addr 0x40004104`/`isr_read_value 1`/`isr_cause 1` the ISR's
own read of `INTR_STATE0`, `clear_writes 1` at `0x118` with `0xffffff00` the
declared clear, `irq_level_final 0` the level after the clear.  The next F2 case
reads `INTR_STATE0 = 0`; the status word really was cleared.
`tests/integration/test_p0_1_irq_dma_declarations.py` parses this saved line.

### 2.5 Negative control

`batch2/negative-upper` leaves the upper compare at `0xffffffff`; the F5 case
times out (`irq_edges 0`, `wait_timeout 1`), the host performs its reported
devices-only reset, and the following proper F5 case passes.  This is the
measured reason the upper word is a declared trigger.

## 3. Data-flow statement

| combination | F1 | F2 | F3 | F4 | F5 | F6 | reason |
|---|---|---|---|---|---|---|---|
| TL-UL rv_timer alone | yes | yes | yes | yes | **yes** | no | no DMA model -> `unsupported-f6:no-dma-model:TL-UL` |
| TL-UL rv_timer + ZipDMA RAM-to-RAM | **yes** | **yes** | **yes** | **yes** | **yes** | **yes** | `batch2/all-six` 9/9 |
| TL-UL rv_timer + DMA route to the timer | yes | yes | yes | yes | yes | no | route needs an APB3 request port -> `unsupported-dma-route:apb3-target-only:tl-ul:tlultimer` |
| TL-UL rv_timer + APB3 target | no | no | no | no | no | no | new protocols are homogeneous -> `unsupported-targets:mixed-protocol:apb3,tl-ul` |
| APB3 timer + I2C + ZipDMA (existing) | yes | yes | yes | yes | yes | yes | `batch2/f5-multif5` 10/10 |
| APB3 I2C + DMA read route, declared ERR (existing) | yes | yes | yes | yes | yes | yes | `batch2/dma-read-error` 2/2, `declared_error_injected` |
| target without F5 facts | yes | yes | yes | yes | no | if DMA | `unsupported-f5:target-irq-semantics:<protocol>:<missing facts>` |
| F5 declaration under Wishbone/AXI4-Lite | yes | yes | yes | yes | no | if DMA | `unsupported-f5:target-protocol-not-run:<protocol>:<name>` |
| DMA route to Wishbone/AXI4-Lite/TL-UL | yes | yes | yes | yes | depends | no | `unsupported-dma-route:apb3-target-only:<protocol>:<name>` |

A missing declaration removes exactly the flow that needs it: no IRQ facts
removes F5, no DMA removes F6, a non-APB3 route removes the routed F6, and the
other flows keep running by name.

## 4. DMA route wiring after the new target protocols

The APB3 route is unchanged: `batch2/dma-read-error` reads the I2C
`PRESCALER` word at `0x20001000`, injects the declared error on beat 1, latches
the device's sticky `CONTROL_STATUS[30]`, and the F6 handler reads
`ctl_status 0x40040040` with `err_after 1`.  The AXI4-Lite target + ZipDMA
session still runs its RAM-to-RAM F6 block 5/5 with the AXI4-Lite channel
counters unchanged (`axi_aw/w/b/ar/r` 1 each, `target_resp_okay 2`); only a
DMA *route* to an AXI4-Lite target is refused.  A route to Wishbone or TL-UL is
refused by name.  The host used to emit
`unsupported-dma-route:target-protocol:tl-ul` from `dma_route_support` and
`unsupported-dma-route:apb3-target-only:tl-ul:<name>` from
`dma_route_protocol_check`; they now state the same word:

```
unsupported-dma-route:apb3-target-only:tl-ul:tlultimer
```

(`batch2/refusal-dma-route.stdout`; config
`runs/p0-1-ip/configs/tlul-timer-dma-route.json`).  That probe places the timer
at `0x20004000` only so the ZipDMA route address is reachable; the F2/F4/F5
scenario keeps it at `0x40004000`.

## 5. Refusals and updated expectations

* `unsupported-f5:one-f5-target:apb3-only:...` is gone.  F5 was always the
  CPU's own load/store through the target adapter; the admitted set is now
  `('apb3', 'tl-ul')`, and an unrun protocol keeps
  `unsupported-f5:target-protocol-not-run:<protocol>:<name>`.
  `test_inprocess_target_protocols.py` and `test_inprocess_mixed_targets.py`
  assert the new word; the TL-UL F5 declaration is admitted.
* `unsupported-targets:mixed-protocol:apb3,tl-ul` — the optional APB target in
  the same session is refused by name (`batch2/refusal-mixed.stdout`).
* `unsupported-dma-route:apb3-target-only:tl-ul:tlultimer` — route refusal.
* `unsupported-f6:no-dma-model:TL-UL` — the timer-only scenario declares no DMA,
  so its F6 record is refused before any case runs
  (`batch2/refusal-f6-no-dma.stdout`).
* A TL-UL target with an incomplete F5 declaration keeps
  `unsupported-f5:target-irq-semantics:tl-ul:<missing facts>`; the focused test
  asserts the exact list.

## 6. Code changes and the no-combination-code statement

This increment added **no device-name branch, no CPU x IP branch, no per-IP
wiring, and no combination code**.  The new IP is declared in
`configs/behaviors/opentitan_rv_timer_f5.json` and two scenarios; its IRQ path
is the generic link table the APB3 targets already use.  The only host edits are
generic:

1. the F5 admitted-protocol tuple (`apb3`, `tl-ul`) and its refusal word
   (protocol-level),
2. the DMA route refusal word in `dma_route_support`, aligned with the
   documented `dma_route_protocol_check` word (protocol-level),
3. `register_kind` recognizing OpenTitan's `INTR_STATE` spelling as a status
   word (a generic register-name taxonomy; it is not a device branch and no
   other profile changes behaviour).

`runs/p0-1-ip/hunks.diff` lists those three Python hunks against the snapshot
`runs/p0-1-ip/before/`.  `scripts/inprocess_obi_apb_f1f4_spike.cpp` was not
modified by this increment; its digest change in the working tree belongs to the
concurrent P0-2 timed-model increment.  CPU onboarding/assembly/address routing,
P0-2 mode plumbing, the build assertion flag, and F1 semantics were not touched.

## 7. Regressions and limits

`batch2/campaign.log`: `all-six` 9/9; `negative-upper` 3 cases (1 expected
timeout, recovery passes); `f5-multif5` 10/10; `dma-read-error` 2/2
(`declared_error_injected`); `tlul-f2f4` 6/6; `refusal-mixed`,
`refusal-dma-route` expected exceptions; `pytest` 386 passed (focused P0-1
tests + entry + target protocols + mixed targets + F5 + DMA authority).  The
AXI4-Lite target + ZipDMA regression (`batch2/regression-axil-dma`) is 5/5;
it was run after the campaign under the same `2325...` C++ digest and the
then-current Python digest.

The two Python digests in the batch (`33532d...` for the five runs, `67ea...`
for the refusal/pytest runs) are a concurrent edit by another agent, recorded
per command; both contain the F5 admission, the route refusal and the
`INTR_STATE` rule.  After the last concurrent edit the all-six batch was re-run
once more under `3a04c82...`/`2325ca5...` and again passed 9/9
(`revalidate-all-six`).  No `runs/` or `docs/` artifact was deleted or rewritten.

Not claimed: coverage, certificate, replay, full SoC, CPU vector, "the RTL
proves the declaration", or that the timer's W1C status can be cleared by a W1C
write while the timer is still expired.  `bus_error unknown`, `irq_cause
observed`, and `dma_status_bits undeclared_in_profile` are stated as unknown,
not as passes.
