# p2 IRQ round two: two clear forms really executed, and the exact layer behind NMI / PLIC / Wishbone-F5 (2026-11-03)

Status: **real RTL** for the two clear forms; **named refusals with cited RTL** for
the other three requirements.  Three real batches (10 cases), two
expected-negative batches, zero case-line regressions.

Evidence, exact commands, verbatim case lines and per-item limits:
`runs/p2-irq-20261103/README.md`; batch `runs/p2-irq-20261103/run.sh`; its own
stdout `runs/p2-irq-20261103/campaign.log`; machine-readable facts
`runs/p2-irq-20261103/irq-advanced.json`.

Headline: the repository now has an F5 clear that is a **real write-one-to-clear
which holds the level low** (OpenTitan GPIO, TL-UL), and a recorded
**read-clear** batch.  The other three requirements are answered with the layer,
the port and the line that block them — and in one case (PLIC) with a correction
to the standing assumption.

## 1. What really ran

| batch | cases | result | wall |
|---|---|---|---|
| `w1c-gpio` (new TL-UL GPIO W1C) | 3 (F5, F2, F5) | `observations_passed` | 17.1 s |
| `readclear-gpio` (PULP GPIO read-clear) | 4 | `observations_passed` | 14.2 s |
| `cva6-multibit` (CVA6 two-bit entry) | 3 (F5, F2, F5) | `observations_passed` | 17.9 s |
| `refuse-…-wb-uart-f5-refused` | — | exit 1, named refusal | 2.2 s |
| `refuse-…-axi4lite-axiluart-f5-refused` | — | exit 1, named refusal | 2.3 s |

The W1C case, read off its own case line: `isr_read_value 0x00000001` (the ISR
read `INTR_STATE[0]=1`), `last_clear_offset 0x00000000` /
`last_clear_data 0x00000001` (the write of 1 to that same bit),
`irq_level_final 0x00000000`, `level_stuck 0`, `irq_takes 1`; and a second F5 two
cases later takes again, so the device was really re-armed.  The read-clear case:
`isr_read_clears 1`, `clear_writes 0`, `irq_level_final 0x00000000`.
`summary.json` for the W1C build reports `irq_advanced.write_one_clear: null` —
the W1C refusal is lifted by a **declared target register this run really
exercised**, not by editing the refusal out of the code.

## 2. Hunk list

This round changed **no** IRQ code path: no `F5_TARGET_PROTOCOLS`, no
`advanced_irq_refusals`, no `irq_declaration`, no `MAX_CLEAR_WRITES`, no ISR and
no host clear classifier.  §3 and §4 show that widening any of them this round
would have admitted or claimed something the pinned devices cannot support.  What
it added is declarations, evidence, tests — plus one repair it did not own.

| file | kind | behaviour |
|---|---|---|
| `configs/behaviors/opentitan_gpio_w1c_f5.json` | new declaration | OpenTitan GPIO F5: `intr_gpio_o` bit 0; status `INTR_STATE` 0x00; ordered triggers `INTR_ENABLE(0x04)=1` then `INTR_TEST(0x08)=1`; clear `INTR_STATE(0x00)=1` (W1C) |
| `configs/scenarios/inprocess-obi-tlul-gpio-w1c-f5.json` | new scenario | Ibex OBI + TL-UL GPIO at 0x40004000, 128-byte window, two owned pin inputs (`gpio.pins/in`, `gpio.pins/strap_en`), no DMA |
| `configs/behaviors/zipcpu_uart_fifo_level_f5.json` | new declaration | the wbuart F5 question: `o_uart_tx_int`, `FIFO_STATUS` 0x04, `TXREG` trigger, **no** clear, so the level rule has something honest to decide |
| `configs/scenarios/inprocess-obi-wb-uart-f5-refused.json` | new scenario | Wishbone ask |
| `configs/scenarios/inprocess-obi-axi4lite-axiluart-f5-refused.json` | new scenario | AXI4-Lite ask, same wbuart RTL |
| `scripts/run_inprocess_f1f6.py` `TARGET_ERROR_RESPONSES` | **repair, another increment's region** | the `'ahb-lite'` value had an apostrophe inside a single-quoted Python literal (`(sha256_ctrl.sv .err(1'b0))`), making the module a `SyntaxError` and blocking every agent's runs.  Fixed by moving that one literal to double quotes; the value's text is unchanged |
| `tests/integration/test_p2_irq_round_two.py` | new tests | see §6 |
| `runs/p2-irq-20261103/*` | new evidence | README, `run.sh`, `campaign.log`, five run directories, `irq-advanced.json` |

## 3. Requirement-by-requirement

**R5 read-clear — executed.**  The PULP GPIO `INTSTATUS` word at 0x24 is declared
`access: ro`, `side_effect: read_clears`, and the RTL says so at
`third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv:154`/`:160` ("clears int if status
is read").  The case shows `clear_writes 0` with the level ending low: the read is
the whole clear.

**R5 write-one-to-clear — executed, and it holds.**  Three facts together make it
a device clear: the event is raised through the register interface
(`INTR_TEST` → `new_event`, `prim_intr_hw.sv:62-70`); the state word is the
profile's `write_one_clears` register; and `gpio.sv:171` instantiates
`prim_intr_hw` with the default `IntrT="Event"`, so nothing re-drives the state
after the clear (`prim_intr_hw.sv:62-70`).  This is precisely the form p1 could
not claim: `rv_timer`'s `INTR_STATE0` is `IntrT="Status"` and is rewritten every
cycle (`prim_intr_hw.sv:73-88`).

**R5 sequences longer than two writes — refused, with the basis.**  The handler
carries one address/value cell pair per step (`scripts/run_inprocess_f1f6.py:174`)
and the classifier matches step order (`inprocess_obi_apb_f1f4_spike.cpp:1649-1691`,
applied at `:2037-2044`); the bound is
`MAX_CLEAR_WRITES = 2` (`:181`) with the refusal
`unsupported: this host performs at most 2 declared clear writes`
(`:1646-1648`).  The only composed multi-write acknowledge in the tree is PULP
I2C's two-step one (`third_party/soc-pulp-apb-i2c/apb_i2c.sv:136`, `:183`, `:193`), and no profile declares a third
step — so widening the bound would have been an untested claim.

**R1 Wishbone / AXI4-Lite target F5 — refused one layer earlier than expected,
both protocols, real batches.**  Both asks hit
`a level IRQ source needs a declared clear write or a read-clearing status word`
(`scripts/run_inprocess_f1f6.py:1666-1672`) **before** the target-protocol gate.
The device layer is the binding constraint, and the enumeration is complete: of
every profile with a Wishbone-classic or AXI4-Lite `mmio_slave` endpoint, the only
ones with interrupts are the wbuart family, whose four outputs are all
combinational FIFO levels (`wbuart.v:207,212,365,369`; bit meanings
`ufifo.v:297-303`): `tx`/`txfifo` are high out of reset so no write raises them,
`rx`/`rxfifo` need a byte the receiver clocked in and the register interface cannot
make one (`wbuart.v:284-293`, `wbuart.v:157 assign rx_break = 1'b0;`).  The one
Wishbone register target with a writable interrupt, `zipcpu_timer`, has **no
address port** at all, so it is refused as `…:wishbone:addressless:…`.  The DMA
profiles are pipelined controllers, not register windows.
`F5_TARGET_PROTOCOLS` therefore stays `('apb3', 'tl-ul')`; the README names the two
shapes that would open it.

**R2 NMI — the blocking layer is the port-disposition layer, not the RTL and not
RVFI.**  Verified against the artifact this batch built: the pinned Ibex really
has the input (`ibex_pkg.sv:355-356` `ExcCauseIrqNm` with `lower_cause 5'd31`;
`ibex_controller.sv:736-745`), the repo wrapper this CPU uses declares *and*
connects it (`soc_ibex_rvfi_local.sv:45`, `:197`), and the generated composition
ties it: `structural.sv:175-176 assign dut_p_43[0:0] = 1'd0;` wired at `:357
.irq_nm_i(dut_p_43)`, while the sibling `irq_external_i` is live at `:171-172`
because the profile declares it.  The observation face is already exported by the
same artifact (`rvfi_ext_nmi → rt_lh_p_64_0_0`, `rvfi_ext_nmi_int →
rt_lh_p_65_0_0`, plus `rvfi_ext_pre_mip`/`post_mip`), so RVFI is not the blocker.
Clearing the constant is a re-pin: that profile is SHA256-pinned by
`ibex_rvfi_contract.py:_PROFILE_SHA256`.  A separate profile declaring the NMI
entry was built and tested this round and does not authenticate — it passes the
manifest, content-hash, closure and elaboration checks, then fails the generic
crawler with `content-hash-mismatch`, because this component's `source.revision`
is a hand-computed union hash rather than the crawler's own selection.  For
CV32E20 the block is one layer earlier and is RTL:
`cv32e20_real_wrapper.sv:41 .irq_nm_i(1'b0)` (and `.irq_external_i(1'b0)`).
Refusals keep their names.

**R3 CVA6's two-bit entry — per bit, with the architectural reason.**  Bit 0
(`IRQ_M_EXT`, `csr_regfile.sv:2073`) is driven and taken twice with the
`mcause_readback` witness; bit 1 (`IRQ_S_EXT`, `csr_regfile.sv:2661`,
`:2724-2729`) is held at constant 0 by the profile and the summary states
`cpu_vector_partial:cva6:irq_i[1]=constant-0-not-taken` with
`held_bits: [{port: irq_i, bit: 1, value: 0}]`.  The reason is architectural, not a
missing port: an S-targeted interrupt is masked while the hart runs in M-mode,
which is the mode the pinned firmware runs in, and taking it would need an S-mode
bootstrap (`mstatus.MPP=01`, `mret`, `stvec`, `sstatus.SIE`, `sie.SEIE`) plus an
`scause` witness this CPU's take contract does not read.  The host also carries
exactly one `CPU_IRQ` word
(`inprocess_obi_apb_f1f4_spike.cpp:5341`) because the profile declares exactly one
entry (`bit_range [0,0]`); a second real source needs a declared second entry, a
per-link CPU-bit field, and the S-mode witness.

**R4 PLIC — five missing composed facts, and one standing assumption corrected.**
`rv_plic` is a **TL-UL** device (`rv_plic.sv:34-37` `tl_i`/`tl_o`,
`rv_plic_reg_top.sv` present), so AHB target adaptation is *not* on its critical
path.  Claim and complete are ordinary MMIO: `rv_plic.sv:299-301`
`claim_re[0] = reg2hw.cc0.re`, `complete_we[0] = reg2hw.cc0.qe` — so **no CPU-side
claim/complete port is missing**, contrary to the earlier note.  What is missing:
(1) no component profile at all (no source selection, no register map, no
`interrupts`); (2) a fan-in for `intr_src_i[NumSrc-1:0]`, `NumSrc = 184`
(`rv_plic_reg_pkg.sv:10`) — the composition layer has no vector fan-in primitive;
(3) owners for `irq_o[0]`, `irq_id_o[0]` (`SRCW` bits) and `msip_o`
(`rv_plic.sv:47-49`, `NumTarget = 1` at `rv_plic_reg_pkg.sv:11`); (4) an
`alert_rx_i`/`alert_tx_o` tie-off declaration (`rv_plic.sv:43-44`,
`NumAlerts = 1` at `rv_plic_reg_pkg.sv:13`); (5) a clock/reset binding.  The
refusal name stands.

## 4. Regressions

The two batches that re-run shipped scenarios are **byte-identical** to p1's saved
case lines once `seconds` is removed:

```text
cva6-f5 (p1)            1702748999166993b7897cfaaf6ceef8
cva6-multibit (p2)      1702748999166993b7897cfaaf6ceef8
repro-gpio-multibit (p1) 804f4dff34d5211e774034395117a23b
readclear-gpio (p2)      804f4dff34d5211e774034395117a23b
```

## 5. Still refused / still unknown

* `unsupported-irq:nmi-uncomposed:ibex_rvfi_local:irq_nm_i=constant-0` — the
  constant lives in a SHA256-pinned profile; clearing it is a re-pin.
* `unsupported-irq:nmi-uncomposed:cva6:no-declared-nmi-port` — CVA6 has no NMI
  port.
* `unsupported-irq:plic-not-composed:<cpu>:no-declared-interrupt-controller-endpoint`
  — five composed facts missing (§3 R4).
* `unsupported-irq:cpu-vector-partial:cva6:irq_i[1]=constant-0-not-taken` — bit 1
  is masked in M-mode, not missing.
* `unsupported-irq:cpu-multibit-vector:ibex_rvfi_local:one-external-input:irq_external_i-width-1`
  — the Ibex entry really is one bit.
* `unsupported-irq:device-active-low:no-declared-target-output-active-low` — no
  polarity inversion was claimed.
* `unsupported: this host performs at most 2 declared clear writes`
  (`scripts/run_inprocess_f1f6.py:1646-1648`).
* `a level IRQ source needs a declared clear write or a read-clearing status
  word` (`:1666-1672`) — the Wishbone/AXI4-Lite answer.
* `unsupported-f5:target-protocol-not-run:<protocol>:<name>`
  (`:260`, `:1750-1752`) — still unreached by any honest declaration; see §3 R1.
* Unknown by construction: `target_error unknown` for the TL-UL GPIO (the trace
  carries `d_error`, and `tlul_errors 0` this batch — a clean run, not a proven
  clean bus); `isr_cause unknown` on the CVA6 batch (its profile declares no
  cause bits).

## 6. Tests

`tests/integration/test_p2_irq_round_two.py` — pure-Python, no model build:

* the TL-UL GPIO W1C declaration is complete and self-consistent against the
  shipped profile (status word readable and `write_one_clears`, every trigger
  register writable, `INTR_TEST` before `INTR_ENABLE` in declaration order, the
  clear word addressing the status word);
* `advanced_irq_refusals` reports `write_one_clear: None` for that target and
  keeps the refusal for a target set that declares no W1C status;
* the wbuart F5 declarations are refused by the level rule, and the two scenarios
  differ only in the target protocol (so the identical refusal is meaningful);
* the Wishbone/AXI4-Lite refusal paths: `f5_protocol_check` raises
  `unsupported-f5:target-protocol-not-run:<protocol>:<name>` for both protocols
  and admits `apb3`/`tl-ul`, i.e. `F5_TARGET_PROTOCOLS` is unchanged;
* the CVA6 per-bit facts and the NMI/PLIC refusal names, re-derived from the
  shipped profiles so a profile edit that invalidates the report fails here;
* the saved evidence is consistent: every `run.sh` command names a config that
  exists, and each saved `run.log` case-count matches its `summary.json` cases.

Plus the regression suites this round must not break:
`tests/integration/test_inprocess_f1f6_entry.py`.

Results (`runs/p2-irq-20261103/tests.log`): **26 passed** (this round),
**79 passed** (the p1 IRQ fuzz suites: `test_irq_generalization.py`,
`test_irq_declaration_expansion.py`, `test_irq_clear_cause.py`), and
**182 passed / 14 failed** in the entry suite.  All 14 entry failures are the
single `KeyError: 'device_capabilities'` raised inside `render_bindings` at
`scripts/run_inprocess_f1f6.py:5195`/`:5197` — the F6 DMA declaration block
(`dma["device_capabilities"]`), which this round did not touch and which belongs
to the DMA increment.  This round's only edit to that file is the
`TARGET_ERROR_RESPONSES['ahb-lite']` string-literal delimiter repair (§2), and a
quote delimiter cannot produce a `KeyError`; before that repair the module did not
even import, so those 14 could not have been introduced here.

## 7. Needs another agent

* **AHB-target increment (C)**: review the `TARGET_ERROR_RESPONSES['ahb-lite']`
  string-literal repair (§2).  It was a module-level `SyntaxError` blocking every
  agent, so it was fixed rather than left; the value's text is unchanged.
* **`src/myfuzz/local_harness/source_crawler.py` owner** (nobody claimed it in
  the p2 split): to deliver a real NMI, either teach `verify_record`/
  `SourceCrawler` to accept a derived-union `sha256:` revision for a
  profile-declared `local_source_manifest`, or re-pin
  `ibex_rvfi_contract._PROFILE_SHA256` with `irq_nm_i` declared.  §3 R2 already
  names the exact profile line and the exact two exports to read.
* **PLIC (unclaimed)**: needs a new `configs/peripherals/rv_plic` profile with a
  TL-UL `mmio_slave` endpoint and the priority/pending/enable/threshold/CC
  register map, a 184-bit source fan-in primitive in the composition layer, and
  owners for `irq_id_o`/`msip_o`/`alert_*`.  The bus side is TL-UL, so C's AHB
  work is not required.
