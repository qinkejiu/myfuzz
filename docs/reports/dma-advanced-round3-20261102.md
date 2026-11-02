# DMA advanced increment (round 3): FIFO read, aperture read, declared error injection

**Date:** 2026-11-02 · **Scope:** `src/myfuzz/composition/dma_transfer.py`, the DMA
sections of `scripts/run_inprocess_f1f6.py` and
`scripts/inprocess_obi_apb_f1f4_spike.cpp`, new configs under `configs/scenarios/`,
`tests/composition/test_dma_transfer.py`, real runs under `runs/round3-dma/`.

This increment adds three transfer shapes to the in-process F6 entry and refuses two
more by name with the pinned RTL facts.  Every accepted shape is executed by the real
models in the pinned cache and its evidence is a device readback, not a host claim.

| item | outcome | one-line witness |
| --- | --- | --- |
| 1. FIFO read route | **implemented** (PULP SPI **RX** FIFO) | `dma_route_level_before 8`, `dma_route_level_after 0`, `dma_route_fifo_matched 8`, `dma_ram_reads 0` |
| — FIFO read of the **TX** FIFO | **refused by name** | TXFIFO has no read arm (`spi_master_apb_if.sv:185-212`), `read-from-write-only` |
| 2. Aperture / incrementing read | **implemented** (4 consecutive SPI registers) | `dma_route_beat_offset0..3 0x04/0x08/0x0c/0x10`, `dma_route_sequence 4`, `dma_route_cpu_aper_matched 4` |
| 3. Error injection | **implemented** (master `mwb_err` with the ack) | `dma_error_injected 1`, `err_after 1`, `ctl_status 0x40040040` (bit 30 = sticky device ERR) |
| 4. Multi-outstanding | **refused by name** | one `Master`, one Wishbone response; `zipdma_fsm.v:160-197` alternates the engines |
| 5. Multi-channel / wider beat | **refused by name** | one CSR set (`zipdma_ctrl.v:106-129`); the largest size class is `SZ_BUS = 4` bytes (`zipdma_mm2s.v:103-106`) |

## 1. The pinned RTL facts this increment rests on

### 1.1 The SPI RX FIFO pops on the APB read; the TX FIFO has no read arm

`third_party/soc-pulp-apb-spi/spi_master_apb_if.sv`:

* line 198: the read mux returns `PRDATA = spi_data_rx` for `` `REG_RXFIFO `` (0x20);
* line 217: the same access asserts the FIFO's pop input,
  `spi_data_rx_ready = PSEL & PENABLE & ~PWRITE & (read_address == `REG_RXFIFO)`;
* lines 185-212: `` `REG_TXFIFO `` (0x18) has **no** read arm — a read falls through
  to `default: PRDATA = '0`.  The TX FIFO's only consumer is the controller's
  `DATA_TX` stream (`spi_master_controller.sv`, `ctrl_data_mux = DATA_FIFO`), and in a
  read transaction the controller drives `DATA_NULL`/`DATA_EMPTY` instead, so an APB
  read of the TX FIFO pops nothing;
* line 79: `assign PSLVERR = 1'b0` — this IP can never answer with an error.
  The routed error injection therefore has to be at the master response.

`third_party/soc-pulp-axi-spi/spi_master_fifo.sv` makes the pop real: `elements`
decrements only on `ready_i && valid_o` (lines 63-64, 121) and `data_o` is
`buffer[pointer_out]`, i.e. the head (lines 134-135).  One APB access phase is one
`HCLK` cycle in the host's bridge (`src/myfuzz/protocols/rtl/apb3_mmio_bridge.sv:50-51`:
`PSEL` is high in `SETUP` and `ACCESS`, `PENABLE` only in `ACCESS`), so one routed read
pops exactly one entry and returns exactly that entry's word.

The level is `STATUS[20:16]` (`third_party/soc-pulp-apb-spi/apb_spi_master.sv:114`:
`spi_status = {{FILL_BITS{1'b0}}, elements_tx, {FILL_BITS{1'b0}}, elements_rx, 9'h0,
spi_ctrl_status}` with `BUFFER_DEPTH=10`, `LOG_BUFFER_DEPTH=4`, `FILL_BITS=3`, so the
TX fill is `[28:24]` and the RX fill is `[20:16]`).  The SPI component profile already
declares the two ports' side effects, which is what the planner keys on:

```
"RXFIFO", offset 32, access "ro", side_effect "read_pops_fifo"
"TXFIFO", offset 24, access "wo", side_effect "write_pushes_fifo"
```

### 1.2 The ZipDMA cannot have two master beats outstanding, has one channel, one width

* `third_party/soc-zipcpu/rtl/zipdma/zipdma_fsm.v:160-197`: the FSM is
  `S_READ → S_WRITE → S_READ …`; `S_READ` leaves only when
  `!i_mm2s_busy && !o_mm2s_request`, and `S_WRITE` raises the next read request only
  when `!i_s2mm_busy && !o_s2mm_request`.  A second beat cannot be issued before the
  first response was consumed.
* `zipdma_mm2s.v:274-335`: one `o_rd_cyc`/`o_rd_stb` pair per read; the next address
  is computed only after `o_rd_stb && !i_rd_stall`.
* `zipdma.v:412`: `assign wb_err = i_mwb_err;` — one master port, one error input.
* `zipdma_ctrl.v:106-129`: exactly one `CONTROL_STATUS`/`SOURCE`/`DESTINATION`/`LENGTH`
  register set; there is no per-channel CSR a second channel could be declared with.
* `zipdma_mm2s.v:103-106`: the beat size is a two-bit class
  (`SZ_BYTE=1`, `SZ_16B=2`, `SZ_32B=4`, `SZ_BUS=BUS_WIDTH/8=4`), so 8-byte beats have
  no encoding on this 32-bit bus.
* `zipdma_ctrl.v:117,283-300,319`: `w_control_reg[30] = r_err || i_dma_err` — the ERR
  status bit is a **sticky** latch (`r_err <= 1` on `i_dma_err`, cleared only by a
  control write with `data[30]`), and `o_interrupt` is raised when
  `r_busy && (!i_dma_busy || i_dma_err)`.  That is the device readback the error case
  uses.

## 2. What the declaration says now

New/extended `dma_route.evidence` keys (`dma_transfer.py`):

| key | meaning |
| --- | --- |
| `expected_word` | FIFO read only: the word every popped entry must carry.  Refused with any other evidence kind (`dma-route-evidence-invalid:expected-word-without-fifo`). |
| `words` | aperture read only: the number of consecutive readable target registers the CPU reads back; must equal the routed beat count. |

Read-route rules (`_route_read_evidence`):

* **fixed register read** — `register_readback` on the routed register (unchanged);
* **FIFO read** — `kind: fifo`, `address_mode: fixed`, evidence `fifo_level` on a
  *different* readable register, and the routed port's own declared side effect must
  be `read_pops_fifo` (else `fifo-read-not-popping`).  The declared `depth` must hold
  the whole block (`fifo-read-beyond-declared-depth`) and the declaration states that
  the level before the transfer is the beat count and after it zero
  (`dma_route_target(...)['level_bounds'] == {before: N, after: 0, drop: N}`);
* **aperture read** — `address_mode: aperture` with `increment_source` and
  `increment_destination` both true, `words == beats`
  (`aperture-read-words-mismatch`), and **every** offset in
  `[offset, offset+4*(words-1)]` must be a readable 32-bit register of the target's
  own profile map (`dma-target-profile-mismatch:aperture-offset:*`,
  `dma-route-evidence-absent:aperture-not-readable:*`).

Error injection (`dma_error_injection`):

```json
{"beat_index": 1, "mode": "master_response"}
```

`beat_index` is a 0-based routed **read** beat; `mode` has exactly one member
(`master_response`); an optional `direction` must equal the route's direction
(`error-injection-direction-mismatch`); `beat_index` must be inside the block
(`error-injection-beyond-block`).  The plan records `kind
host_injected_master_response`, `signal mwb_err`, `device_err_status_bit 30`,
`device_err_status_source builtin_zipdma_rtl_default`, `aborts_transfer true`.
A write-beat injection is refused by the entry
(`error-injection-needs-read-route`) because this host drives only the read side's
response; the S2MM error input exists in the RTL but is not driven here.

## 3. Hunks in the two shared scripts (both are untracked)

`scripts/run_inprocess_f1f6.py`:

1. `DMA_ROUTE_ADDRESS_MODES = ('fixed', 'aperture')` and
   `DMA_ROUTE_FIFO_POP_SIDE_EFFECT = 'read_pops_fifo'` (route constants).
2. `_dma_result_span()`: an aperture read adds one carry cell per beat.
3. `build_layout(..., dma_block_words=0)` and the new `route_aper` cell
   (`result+24+4*block_words`), plus the one call site that passes
   `dma['block_words']`.
4. `dma_route_support()`: read-source increment rules per address mode; the
   fifo-read branch (pop side effect, level bits/depth, `expected_word`, declared
   level bounds); the aperture branch (`words`, per-offset readable register check,
   declared address table); `error_beat` from the plan (refused on a write route);
   the returned record carries `fifo`, `aperture`, `aperture_addresses`,
   `level_before/after`, `expected_word`, `error_beat`.
5. `dma_host_limits()`: answers the planner's `host-error-injection-absent` limit
   when a route beat is declared, and refuses `error-injection-requires-route`
   otherwise.
6. `render_bindings()`: `DMA_ROUTE_FIFO`, `DMA_ROUTE_APERTURE`,
   `DMA_ROUTE_LEVEL_BEFORE/AFTER`, `DMA_ROUTE_EXPECT_WORD/VALUE`,
   `DMA_ROUTE_ERROR_BEAT`, `DMA_ROUTE_APERTURE_COUNT/ADDRESSES/ADDRESS`.
7. `build_firmware()`: the F6 body reads every aperture word back into `route_aper`
   after the transfer (only when the route is an aperture).
8. `dma_declaration()`: the returned declaration carries `error_injection`.
9. `F6_ROUTE_READ_CASE_KEYS`: the new case-line keys (level, expected word, aperture
   sequence, CPU aperture cells, per-beat offsets, injection facts).
10. `correspondence()`: injection-aware declared beat counts; read-route checks for
    FIFO level/pops/word, aperture sequence/CPU readback, per-word destination words
    (an aborted transfer's unwritten words must stay the sentinel); the byte-enable
    count and the derived-completion check follow the injected write count.
11. `FAILURE_CLASSES` / `EXPECTED_FAILURE_CLASSES` / `FAILURE_SEVERITY` /
    `classify_case()`: the new expected outcome class `declared_error_injected`.

`scripts/inprocess_obi_apb_f1f4_spike.cpp`:

1. Macro defaults for the new `DMA_ROUTE_*` facts (a header that declares none keeps
   the previous behaviour).
2. `constexpr` route facts (`kDmaRouteFifo`, `kDmaRouteAperture`,
   `kDmaRouteLevelBefore/After`, `kDmaRouteExpectWord/Value`,
   `kDmaRouteErrorBeat`, the aperture table, `kDmaRouteCellPrefill`).
3. `Master.error`, `MasterRoute.offset`; observation fields for the per-beat offsets,
   the aperture sequence, the FIFO word matches, the CPU aperture cells and the
   injection counters.
4. Target request drive uses the beat's own offset (`route.offset`); routed-beat
   detection for a fixed route or the next declared aperture address (an
   out-of-order aperture beat throws).
5. `dma.mwb_err` is asserted with the ack of the declared beat
   (`dma.mwb_ack && master.error`) — an ERR without ACK is not a Wishbone error
   response and the device drops its cycle on it (found and fixed during this work).
6. Per-case route evidence cells are prefilled with `kDmaRouteCellPrefill`, which
   moves off `0xffffffff` when the declared expected word *is* that sentinel (a FIFO
   returning `0xffffffff` would otherwise look "never written").
7. F6 pass criteria: injected beat counts, lane coverage of the written words, FIFO
   level/word clauses, aperture sequence/CPU-readback clauses, and the declared ERR
   bit for the injected case.
8. Case line: the read group gained `dma_route_address_mode`, `dma_route_source_kind`,
   `dma_route_level_before/after` (+ declared), `dma_route_expected_word`,
   `dma_route_fifo_matched`, `dma_route_sequence`, `dma_route_cpu_aper_matched`,
   `dma_error_injected/injections/beat`, and — for an aperture — `dma_route_beat_offset0..N`
   and `dma_route_cpu_aper0..N`.

## 4. Evidence

All numbers below are from `runs/round3-dma/` (see its `README.md` for the exact
commands, the full case lines and the wall clock).

**FIFO read** (`runs/round3-dma/fiforead/`, 21/21 cases): the fill is a real SPI read
transaction (F4 `SPILEN = 256 bits`, F4 `STATUS.spi_rd`) and the level time series is
the CPU's own `STATUS` readback (`0,0,1,1,2,2,3,3,4,4,5,5,6,7,7,8,8,8,8,8`).  The F6
case: `dma_route_reads 8`, `dma_route_acks 8`, `dma_route_target_reads 8`,
`dma_route_level_before 8`, `dma_route_level_after 0`, `dma_route_fifo_matched 8`,
`dma_route_read_value 0xffffffff`, `dma_ram_reads 0`, `dma_ram_writes 8`,
`dst0..7 = dma_route_cpu_dst0..7 = 0xffffffff`, both guards `0xa5a5a5a5`,
`err_after 0`, `isr_result == ctl_status == 0x00040040`, `dma_done_tick 1009`.
The master traffic is 8 reads (ticks 892…934, each acked 3 ticks later) and then 8 RAM
writes (944…958): every ack precedes the next accept.

**Aperture read** (`runs/round3-dma/aperture/`, 5/5): `dma_route_beat_offset0..3 =
0x04, 0x08, 0x0c, 0x10`, `dma_route_sequence 4`, `dst0..3 = 0x00000005, 0x0000000a,
0x0000000b, 0x0000002a`, `dma_route_cpu_aper0..3` equal to them,
`dma_route_cpu_aper_matched 4`, `dma_route_evidence_before/after 0x00000005`,
`dma_ram_reads 0`, `dma_ram_lane_written 16`.

**Error injection** (`runs/round3-dma/error/` beat 1, `.../error-beat0/` beat 0):
`dma_error_injected 1`, `dma_error_injections 1`, `dma_error_beat 1`,
`err_after 1`, `ctl_status = isr_result = 0x40040040`, `dma_reads 2`, `dma_writes 0`,
`dma_ram_writes 0`, `dma_ram_lane_missing 16`, every destination word still
`0xa5a5a5a5`; the case's own classification is `declared_error_injected`
(severity `expected`).  `error-beat0` shows the same with one read and beat 0.

**Regressions** (all green, same `runs/round3-dma/`): SPI TX FIFO write route
(`dma_route_writes 8`, level `0 → 8`, `dma_ram_writes 0`), I2C `PRESCALER` read route
(`dma_route_reads 4`, `dma_ram_reads 0`), RAM→RAM eight-word block, size-derived byte
enables (`dma_sel_partial 16`), declared delay (`dma_wait_min 3`,
`dma_delay_evidence observed`), timer+ZipDMA F1–F6 6/6, two-IP F1–F6 6/6.

**Refusals** (each exit non-zero, before any model is built):

```
dma-route-direction-unsupported:read-from-write-only          # SPI TX FIFO read
fifo-read-not-popping:STATUS:write_starts_transfer            # readable, no pop
fifo-read-beyond-declared-depth:4<8
aperture-read-words-mismatch:2!=4
error-injection-beyond-block:4>=4
error-injection-direction-mismatch:write!=read
outstanding-beyond-one:dma_max_outstanding
master-byte-enable-unsupported:size-bytes:8
```

## 5. Tests

`tests/composition/test_dma_transfer.py`: **59 tests**, the 44 previous ones unchanged
in meaning (three of them now also assert the register's declared `side_effect`, which
the plan reports because the read rules key on it) plus 15 new focused tests:
accepted FIFO read declaration, non-popping port refused, write-only port refused,
depth-beyond-block refused, missing level evidence refused, `expected_word` limited to
FIFO evidence, accepted aperture declaration (per-word register rows), aperture word
count, aperture over a write-only register, accepted error declaration, beat beyond
block, direction mismatch, unknown injection mode, multi-outstanding refusal (with the
pinned `max_outstanding == 1` fact), and the width/channel refusal (the device has one
CSR set and no 8-byte size class).

Required suite: `PYTHONPATH=src:. python3 -m pytest
tests/composition/test_dma_transfer.py tests/composition/test_inprocess_behavior.py
tests/integration/test_inprocess_f1f6_entry.py -q` → **319 passed**.

## 6. Honest limits and what stays refused

* **Multi-outstanding is refused, not emulated.**  The host has exactly one `Master`
  response record, stalls the device while it is pending, and throws if a routed
  second beat arrives while one is outstanding; no run in this campaign triggered
  that guard.  The device fact is the FSM alternation above.  There *is* a real
  two-engine pipeline in the device — the read side (MM2S) and the write side (S2MM) —
  but it is not two outstanding master beats: measured, the read side buffers the
  whole chunk and the write side then drains it (8 reads, then 8 writes, in
  `fiforead/` and `regressions/fifo-write/`), and the single master port carries one
  beat at a time.  This increment therefore claims no overlap and implements none.
* **No second channel and no wider beat.**  Refused by name with the CSR/size facts
  above; the planner has no key that could even express a second channel, and the
  entry refuses `dma_max_outstanding > 1`.
* **The error is injected at the master response.**  The routed APB3 targets tie
  `PSLVERR` low, so a target-side error cannot be produced by this IP; the case line
  always states the injection and the ERR bit it produced is the device's own sticky
  latch, read back by the completion handler.
* **A write-beat injection is refused** (`error-injection-needs-read-route`) even
  though the S2MM side has an error input; this host does not drive it.
* **The FIFO read needs a fill that runs in real time.**  The chain uses 18 `F2`
  `STATUS` reads as filler (they double as the level time series); the closed-loop
  fuzz generator does not emit such a fill sequence yet, so the new shapes run from
  explicit records only.
* **The `run_inprocess_f1f6.py` `read-aperture` refusal documented in
  `runs/round1-dma-read/README.md` is superseded**: an aperture read is now a named
  accepted shape, and the same negative config is refused because it declares no
  aperture `words` (`aperture-read-words-absent`) rather than because aperture reads
  are unsupported.  That older README is left as the historical record of its
  increment.
