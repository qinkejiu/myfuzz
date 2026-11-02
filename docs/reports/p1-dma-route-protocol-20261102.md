# P1 DMA route protocol: a routed master beat on the target's own adapter

Date: 2026-11-02.  Scope: the DMA-route-protocol increment of the unified
in-process executor (`scripts/run_inprocess_f1f6.py`,
`scripts/inprocess_obi_apb_f1f4_spike.cpp`,
`src/myfuzz/composition/dma_transfer.py`).  This report states what was
generalized, which routes really ran on which wire, what was refused by name, and
what stays out of scope.  It claims no coverage, certificate, replay or SoC
acceptance.

The evidence package is `runs/p1-dma-route/`; its `README.md` holds the exact
commands, the full F6 case lines, the per-protocol trace counts, the captured and
readback values, and the wall/per-case time.  `runs/p1-dma-route/hunks.diff`
lists this increment's hunks inside the two shared scripts (filtered from the
concurrent increments' hunks), and `runs/p1-dma-route/code/` is the code the
runs used, with `code/md5.txt`.

## 1. What changed

The route used to be a single-protocol feature: `DMA_ROUTE_PROTOCOL_REFUSAL =
'unsupported-dma-route:apb3-target-only:'` refused every target that was not
APB3, and the host's `MasterRoute` described its completion as the APB3
`psel`/`penable`/`pready` handshake.  That was an assumption about the *wire*, not
about the transfer: a routed beat is one master word carried to one target
register, and every generated target artifact already binds its own protocol
bridge to the same generic beat port (`req_valid`/`req_ready`/`req_write`/
`req_addr`/`req_wdata`/`req_be` in, `rsp_valid`/`rsp_ready`/`rsp_rdata`/
`rsp_error` out).  The increment makes the wire a **fact of the routed target's
own artifact**:

| layer | before | after |
|---|---|---|
| planner (`dma_transfer.py`) | route facts had no protocol; `host_support` named the APB3 target only | `_target_profile_facts` reads the target's own `mmio_slave` endpoint protocol (`PROFILE_PROTOCOL_NAMES`: `apb` -> `apb3`, `wishbone`, `tl-ul`, `axi4-lite`) and reports it as `protocol`/`target_protocol`; `ROUTE_PROTOCOLS` is the admitted set; a profile whose endpoint names another wire is refused with `dma-route-target-protocol-unsupported`; `host_support` states the generic beat port and the four protocols |
| entry gate (`run_inprocess_f1f6.py`) | `dma_route_protocol_check` admitted `apb3` only | `DMA_ROUTE_PROTOCOLS = ('apb3','tl-ul','wishbone','axi4-lite')`; a protocol outside it is refused by `unsupported-dma-route:target-protocol-not-admitted:<protocol>:<name>` |
| entry dispatch | `dma_route_support` raised the APB3-only refusal for any other target | the routed target's artifact protocol is admitted, and the answer states `target_protocol`, `target_bridge` and the beat port beside the existing geometry/evidence facts |
| header | no route-protocol macro | `DMA_ROUTE_PROTOCOL "<protocol>"` (from the routed target's artifact) and `DMA_ROUTE_TRACE` (1 only when the routed target is not APB3, so an APB3 route case line keeps its exact field set) |
| host (`MasterRoute`) | completion described as APB3 | the beat is driven/completed through the target trait's generic beat interface (`request_ready`/`response_valid`/`response_rdata`/`response_error`), unchanged in mechanism; a *new route-only trace sampler* counts the routed beat on the target's own passive taps: Wishbone `cyc`/`stb`/`ack`/`we`/`adr`/`dat_w`/`dat_r`, TL-UL `a_valid`/`a_ready` then `d_valid`/`d_ready`, AXI4-Lite `AW`/`W`/`B` or `AR`/`R` |
| case line | route facts only | a non-APB3 route adds `dma_route_protocol`, `dma_route_protocol_transfers` and that protocol's own counters (`dma_route_wb_acks`, `dma_route_tlul_a/d_handshakes`, `dma_route_axi_aw/w/b/ar/r`); the F6 correspondence check verifies each of them equals the routed beat count |

The route geometry (direction, fixed/aperture, block, full-word beat, one
outstanding master beat, declared error injection, RAM-read/write counts) is
unchanged; the only new dimension is *which target adapter carries the beat*.

## 2. The routes that really ran

| run | target / wire | routed beats and evidence |
|---|---|---|
| `tlul-timer-read` | OpenTitan rv_timer, TL-UL, `COMPARE_LOWER0_0` `0x118` read | `dma_route_tlul_a_handshakes 4`, `dma_route_tlul_d_handshakes 4`, captured `0x0badc0de` on all four beats (`read_stable 4`), RAM `dst0..3 = 0x0badc0de`, `dma_ram_reads 0`, CPU pre/post readback `0x0badc0de` |
| `tlul-timer-read-flows` | the same route inside one F1/F2/F3/F5/F4/F6 batch | all six cases `observations_passed`, F5 `irq_takes 1`, F6 the same route facts |
| `wb-uart-write` | ZipCPU `wbuart`, Wishbone classic, `SETUP` fixed write | `dma_route_wb_acks 4`, `dma_route_wb_stb_pulses 4`, `dma_route_target_writes 4`, `we=1` with `adr 0x0` on every beat, evidence `SETUP 0x00000019 -> 0x12345678` (the last pushed word), `dma_ram_writes 0` |
| `wb-uart-read` | ZipCPU `wbuart`, Wishbone classic, `SETUP` fixed read | `dma_route_wb_acks 4`, `we=0`, `dat_r 0xabcd` on every beat, captured `0xabcd`, `dma_ram_reads 0`, `dst0..3 = 0xabcd` |
| `axil-uart-read` | ZipCPU `axiluart`, AXI4-Lite, `SETUP` fixed read | `dma_route_axi_ar 4`, `dma_route_axi_r 4`, `rresp 0`, captured `0xabcd`, `dma_ram_reads 0`, `dst0..3 = 0xabcd` |
| `axil-uart-write` | ZipCPU `axiluart`, AXI4-Lite, `SETUP` fixed write | `dma_route_axi_aw 4 / w 4 / b 4`, `bresp 0`, evidence `SETUP 0x00000019 -> 0x12345678`, `dma_ram_writes 0` |

Two register choices were driven by the RTL, not by convenience:

* **rv_timer `COMPARE_LOWER0_0`** (not `TIMER_V_LOWER0`): the timer core never
  writes the compare register (it compares `TIMER_V` against it), so the routed
  read is stable across the four beats and the CPU's pre/post readback is the
  same word.  `TIMER_V_LOWER0` is the free-running counter; four routed beats
  there would return four different words and the entry's own stability
  criterion (`dma_route_read_stable`) would fail the case instead of being
  explained away.
* **UART `SETUP`** (not `TXREG`): see section 4.

One interaction is a real RTL fact stated in the scenario and the evidence:
the rv_timer's own **F5 clear is a write to `COMPARE_LOWER0_0`**
(`rv_timer.sv:82-83` clears `intr_state` on a compare update), so an F4 write of
the routed source *before* F5 is overwritten by that clear.  The six-flow batch
therefore runs F5 before F4; the first attempt (F4 before F5) is the exact
`F6 the DMA read 0xffffff00 but the preceding F4 case wrote 0x0badc0de`
correspondence mismatch in the probe notes, not a defect.

## 3. Refusals kept by name

| refusal | exact fact |
|---|---|
| `unsupported-dma-route:target-protocol-not-admitted:<protocol>:<name>` | `dma_route_protocol_check` and `dma_route_support` refuse a wire outside the four admitted protocols (an `ahb-lite` target has no beat adapter and no passive trace in this host) |
| `dma-route-target-protocol-unsupported:<protocol>` | the planner refuses a scenario whose routed target profile declares such an endpoint protocol |
| `dma-route-direction-unsupported:read-from-write-only` | TL-UL `ALERT_TEST` is SW `wo`; a read route there is refused before any model (the **same per-protocol register validation** runs for every wire) |
| `dma-route-direction-unsupported:write-to-read-only` | AXI4-Lite `FIFO_STATUS` is RO |
| `dma-target-profile-mismatch:register:NODECODE` | offset `0x20` is outside the UART 16-byte window |
| `dma-route-target-unreachable:zipdma:0x40004118>0x3fffffff` | the pinned ZipDMA's 30-bit byte-address `SOURCE`/`DESTINATION` cannot encode the rv_timer SoC base |

No route was ever substituted by a CPU transfer: every accepted route is a real
`mwb` master beat, and the cases print `dma_ram_reads 0` / `dma_ram_writes 0` as
the witness that RAM did not serve it.

## 4. A device fact: the TXREG write route is not admissible

The first UART write route targeted `TXREG` (`0x0c`, a write pushes the TX FIFO)
with `FIFO_STATUS` (`0x04`) as its evidence.  The routed beats completed on both
slaves (Wishbone `we=1`+`ack` per push, AXI4-Lite `AW/W/B 4` each,
`dma_route_target_writes 4`), but the evidence word did not move:
`fifo_status_before 0x403f4000`, `fifo_status_after 0x403f4000`.  The pinned
`ufifo` reports, for a transmit FIFO, the number of **empty** slots
(`ufifo.v:283-299`, `RXFIFO=0`) and the transmitter pops one entry per push
(`i_rd=(!tx_busy)&&(empty_n)`), so a short push burst leaves the status word
where it was.  The F6 criterion then fails the case with `F6 evidence word did
not change across the routed transfer` and the process status is `failed` — the
declared evidence is not true, and the entry says so.  The admitted UART write
route therefore stores into `SETUP`, whose readback *is* the last word the master
stored.  Both TXREG attempts (Wishbone and AXI4-Lite) are kept under
`runs/p1-dma-route/probe/previous-txreg-attempt/`.

## 5. One shared-host change (AXI4-Lite completion criterion)

A routed F6 case reads its declared evidence register **before and after** the
transfer, so a route to an AXI4-Lite target is the first case shape that performs
two CPU MMIO transactions on the same AXI4-Lite target in one case.  The host's
completion check compared the **case-wide** channel counters against one
(`observation.axi_ar != 1 || observation.axi_r != 1`, and the `AW`/`W`/`B` twin),
so the second read was rejected with `AXI4-Lite read did not complete AR and R
exactly once` even though both transactions completed on the target's channels.
The fix (`AxiMark` in `inprocess_obi_apb_f1f4_spike.cpp`) snapshots the five
channel counters when `iptake` accepts a request and the check compares
`observation.axi_* - mark.* == 1`: still exactly one handshake per transaction,
now scoped to the transaction instead of the case.  The case line keeps the
cumulative counters, and the routed beats are counted by the route's own
`dma_route_axi_*` group, so the two are never conflated.  The diagnosis was
reproduced with the route trace compiled out, which rules the new sampler out as
the cause.

## 6. Regressions

`runs/p1-dma-route/regressions/` re-runs the APB3 route shapes the earlier
increments proved (SPI TX FIFO write, I2C `PRESCALER` fixed read, SPI RX FIFO
read with level 8 -> 0, four-register aperture read, declared `ACK+ERR` on routed
read beat 1 with `err_after 1`, RAM -> RAM len8, and the PULP timer + ZipDMA
F1-F6 batch).  All are `observations_passed`.  The APB3 route case lines carry
**no new field**: the route protocol group is printed only for a non-APB3 route
(`DMA_ROUTE_TRACE` is 0 for an APB3 route), which is checked by
`test_the_saved_apb3_routes_keep_their_own_case_lines`.

## 7. Tests

* `tests/integration/test_inprocess_dma_route_protocols.py` (new): the planner
  admits the four protocols and reports the routed target's own protocol
  (`target_profile_facts`, `validate_transfer_plan`, `dma_route_target`), refuses
  an AHB-Lite endpoint from the target profile and an unadmitted protocol at the
  host gate, dispatches `dma_route_support` per protocol (protocol, bridge, beat
  port, reads/pushes), pins the route trace group per protocol, and re-reads the
  saved runs: the TL-UL A/D counters, the captured word, `dma_ram_reads 0`, the
  RAM block values, the Wishbone write/read facts, the AXI4-Lite AR/R and AW/W/B
  facts, and the unchanged APB3 route lines.
* The three older assertions that a route to a non-APB3 target is refused
  (`test_p0_1_irq_dma_declarations.py`,
  `test_inprocess_target_protocols.py`, `test_inprocess_mixed_targets.py`) now
  assert admission of the four wires and refusal of an unadmitted one; the
  planner's route-dict assertions in `tests/composition/test_dma_transfer.py`
  gained the new `protocol` field.

## 8. Not claimed

* No coverage, certificate, replay, differential-equivalence or SoC claim; each
  evidence directory is one run of the scenario it names.
* One outstanding master beat per route (the device's `dma_max_outstanding 1`);
  multi-outstanding, multi-channel and wider-beat routes remain refused by the
  planner/host.
* The route's evidence is the target's own response and trace plus the CPU's own
  readback; a RAM word that happens to match is never accepted as the witness.
* The two UART targets declare no F5 facts, so their scenarios keep F5 refused by
  name and cover F1-F4/F6 (the TL-UL timer scenario carries the real F5 path).
