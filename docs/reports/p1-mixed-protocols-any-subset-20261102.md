# Any subset of 2..4 target protocols in one mixed session (2026-11-02)

Status: **generalized, integrated into the unified in-process executor and passed
on real RTL** for four new sessions.  Evidence: `runs/p1-mixed-protocols/`
(`README.md` with the full case/summary lines, `commands.log`, `run-all.sh`,
eight `run.log`/`summary.json`, `code/`, `tests.log`, this report).

Scope: the target-protocol axis of the unified executor
(`scripts/run_inprocess_f1f6.py` + `scripts/inprocess_obi_apb_f1f4_spike.cpp`).
The previous increment admitted exactly one mixed pair, APB3 + AXI4-Lite; this
one admits any subset of 2..4 supported target protocols (APB3, AXI4-Lite,
Wishbone classic, TL-UL) and keeps each target's own protocol, trace sample and
completion criterion.  Homogeneous builds and the historical exact pair are
unchanged.  No coverage, certificate, replay, full-SoC or CPU-vector claim is
made here.

## 1. The declaration axis

`target_protocol_axis(protocols)` is still the one decision every caller uses,
but the admitted set is now "any subset of 2..4 supported protocols":

- one protocol -> the historical homogeneous build (the four
  `TARGET_PROTOCOL_*` build-wide macros are that protocol's);
- 2..4 supported protocols -> a mixed build (all four build-wide macros stay
  neutral and each target's generated trait carries its own protocol);
- a set containing a protocol outside `SUPPORTED_TARGET_PROTOCOLS` -> the
  historical named refusal `unsupported-targets:mixed-protocol:<names>`, listing
  the protocols the declaration asked for (e.g.
  `unsupported-targets:mixed-protocol:ahb-lite,apb3`);
- an empty set -> `unsupported-targets:none`.

`MIXED_TARGET_PROTOCOL_PAIRS` is kept as the **historical pair** (APB3 +
AXI4-Lite) because that pair's words are part of saved evidence, and the new
`MIXED_TARGET_PROTOCOLS`, `MIXED_TARGET_PROTOCOL_MIN/MAX` state the general
admission.  The build-wide words are rendered from the declared set in the
canonical `SUPPORTED_TARGET_PROTOCOLS` order, so a declaration always prints the
same text:

```
historical pair:  mixed:apb3_mmio_bridge+axi4_lite_mmio_bridge
APB3 + TL-UL:     mixed:apb3_mmio_bridge+beat_to_tlul
three protocols:  mixed:apb3_mmio_bridge+axi4_lite_mmio_bridge+beat_to_tlul
```

New pure helpers: `ordered_target_protocols()`, `mixed_target_bridge()`,
`TARGET_TRANSFER_CRITERIA`, `mixed_target_criterion()`,
`TARGET_ERROR_RESPONSES` and `target_protocol_label()`.  The run document's
`target_protocol` block now states the declared set's bridge, per-target transfer
criterion and per-target error-response word instead of the pair's two words;
the historical pair renders byte-identical bridge/criterion/error words.

## 2. Generated header: presence macros and per-target traits

A mixed header now also states which protocols the build really contains, since
all four `TARGET_PROTOCOL_*` macros are neutral for it:

```
#define TARGET_MIXED_HAS_APB3 1
#define TARGET_MIXED_HAS_AXI4LITE 0
#define TARGET_MIXED_HAS_WISHBONE 1
#define TARGET_MIXED_HAS_TLUL 0
```

The host derives `TARGET_HAS_{APB3,AXI4LITE,WISHBONE,TLUL}` from those and its own
`TARGET_PROTOCOL_*` macro (a header rendered before the presence macros defines
none of them, so a one-protocol build is exactly what it was).  Every
protocol-specific sample/completion/print step is guarded by those words, not by
`TARGET_PROTOCOLS_MIXED`, so a mixed build compiles and prints only the groups it
has.  The generated `IpTarget<n>` traits keep one protocol per target; the
missing `wb_stall_sampled` constant (only the one-target fallback trait had it)
is now emitted per Wishbone target, guarded by whether that target's trace
carries the optional stall pin.

## 3. Sampling and completion stay per target

| protocol | sampled from the target's own passive trace | completion |
| --- | --- | --- |
| APB3 | `psel`/`penable`/`pready` (+`pwrite`/`paddr`/`pwdata`/`prdata`; `pslverr` when the trace carries it) | `psel && penable && pready` in one sample |
| AXI4-Lite | AW/W/B and AR/R handshakes, `wstrb`, `bresp`/`rresp` | AW+W+B or AR+R exactly once |
| Wishbone classic | `cyc`/`stb`/`ack`/`we`/`adr`/`dat_w`/`dat_r`/`sel` (+`stall`) | one `stb` request phase, then a held `cyc`+`ack` completion |
| TL-UL | A channel `a_*`, D channel `d_*` | one A handshake, then one D handshake |

Three host changes make this true for every mixed set:

1. The Wishbone and TL-UL sampling blocks are compiled for any build that has
   such a target (`TARGET_HAS_*`), not only for a homogeneous one.
2. The neutral counter words `target_transfers` and `target_error` are printed by
   exactly one protocol group (`TARGET_NEUTRAL_COUNTERS_*`: AXI4-Lite when the
   build has one, else Wishbone, else TL-UL).  A build that samples several
   protocols prints each protocol's own counters and the other groups print
   `<proto>_error`, so no line repeats a key.  The same rule applies to the
   summary line.
3. A Wishbone or TL-UL trace field group prints only for a case whose routed
   target is that protocol (`ip_is_wishbone` / `ip_is_tlul`): a case routed to
   another target never reads as a zero handshake.  The per-target
   `target<n>_last_offset` is now recorded for Wishbone and TL-UL completions
   too (multi-target lines only).

## 4. New scenarios

All four use the Ibex RVFI OBI CPU, RAM `0x10000..0x30000`, no DMA, and the
PULP timer as the one F5 target (APB3, `configs/behaviors/pulp_timer_f5.json`).

| scenario | index | target | protocol | bridge | window |
| --- | --- | --- | --- | --- | --- |
| `inprocess-obi-apb-tlul-mixed-timer-rvtimer-f1f4` | 0 | PULP timer | `apb3` | `apb3_mmio_bridge` | `0x40001000` + 4096 |
| | 1 | OpenTitan rv_timer | `tl-ul` | `beat_to_tlul` | `0x40003000` + 4096 |
| `inprocess-obi-apb-wb-mixed-timer-uart-f1f4` | 0 | PULP timer | `apb3` | `apb3_mmio_bridge` | `0x40001000` + 4096 |
| | 1 | ZipCPU UART | `wishbone` | `beat_to_wishbone` | `0x40002000` + 16 |
| `inprocess-obi-apb-axi4lite-tlul-mixed-three-protocol-f1f4` | 0 | PULP timer | `apb3` | `apb3_mmio_bridge` | `0x40001000` + 4096 |
| | 1 | ZipCPU axiluart | `axi4-lite` | `axi4_lite_mmio_bridge` | `0x40002000` + 16 |
| | 2 | OpenTitan rv_timer | `tl-ul` | `beat_to_tlul` | `0x40003000` + 4096 |
| `inprocess-obi-apb-wb-tlul-mixed-timer-uart-rvtimer-f1f4` | 0 | PULP timer | `apb3` | `apb3_mmio_bridge` | `0x40001000` + 4096 |
| | 1 | ZipCPU UART | `wishbone` | `beat_to_wishbone` | `0x40002000` + 16 |
| | 2 | OpenTitan rv_timer | `tl-ul` | `beat_to_tlul` | `0x40003000` + 4096 |

The windows are disjoint from each other and from the RAM image.  The TL-UL,
AXI4-Lite and Wishbone targets declare no behavior file, so they declare no F5
facts and the summary states `target1_f5 no` / `target2_f5 no`; F5 remains the
APB3 timer's own window.  The fourth scenario is the **no-AXI4-Lite**
three-protocol case: its case lines have no `axi_*` group at all, its neutral
counter group is the Wishbone one (`target_transfers`, `target_error`), and the
TL-UL group prints its own `tlul_error` word.  The summary names only
`bus_error_wb`, `bus_error_tlul` and `bus_error_apb`.

## 5. Real runs

All commands are in `runs/p1-mixed-protocols/run-all.sh`; every run's digest is
recorded before and after in `commands.log`.

| run | cases | wall | status |
| --- | --- | --- | --- |
| `apb3-tlul` | 8 | 13 s | `observations_passed` 8/8 |
| `apb3-wb` | 8 | 13 s | `observations_passed` 8/8 |
| `three-protocol` | 8 | 13 s | `observations_passed` 8/8 |
| `apb3-wb-tlul` | 8 | 13 s | `observations_passed` 8/8 |
| `regression-mixed-pair` | 6 | 13 s | `observations_passed` 6/6 |
| `regression-wb-fixed` | 5 | 11 s | `observations_passed` 5/5 |
| `regression-tlul-fixed` | 6 | 13 s | `observations_passed` 6/6 |
| `regression-two-ip` | 6 | 14 s | `observations_passed` 6/6 |

Per-target facts from the summaries:

- `apb3-tlul`: `target_protocols apb3,tl-ul`; `target0_protocol apb3`
  `target0_bridge apb3_mmio_bridge` `target0_f5 yes`; `target1_protocol tl-ul`
  `target1_bridge beat_to_tlul` `target1_f5 no`; `tlul_a_handshakes 4`
  `tlul_d_handshakes 4` `tlul_errors 0`; totals `target0 2/4`, `target1 2/2`.
- `apb3-wb`: `target_protocols apb3,wishbone`; `target1_bridge beat_to_wishbone`;
  `wb_acks 4` `wb_stb_pulses 4` `wb_stalls 0`; totals `target0 2/4`,
  `target1 2/2`.
- `three-protocol`: `ip_count 3`, `target_protocols apb3,axi4-lite,tl-ul`, one
  bridge per target; totals `target0 2/4`, `target1 1/1`, `target2 1/1`;
  the remaining `clock_*` words are the timing increment's.
- `apb3-wb-tlul`: `ip_count 3`, `target_protocols apb3,wishbone,tl-ul`, one
  bridge per target; `wb_acks 2` `tlul_a_handshakes 2` `tlul_d_handshakes 2`;
  no `axi_*` word anywhere in the log; totals `target0 2/4`, `target1 1/1`,
  `target2 1/1`.

The three-protocol case lines show the routing is independent (each row is the
printed per-target counter pair; the routed target is the only one that moved):

| case | flow | target_index | protocol | t0 r/w | t1 r/w | t2 r/w |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | F2 | 0 | apb3 | 1/0 | 0/0 | 0/0 |
| 1 | F4 | 0 | apb3 | 0/1 | 0/0 | 0/0 |
| 2 | F5 | 0 | apb3 | 1/3 | 0/0 | 0/0 |
| 3 | F2 | 1 | axi4-lite | 0/0 | 1/0 | 0/0 |
| 4 | F4 | 1 | axi4-lite | 0/0 | 0/1 | 0/0 |
| 5 | F2 | 2 | tl-ul | 0/0 | 0/0 | 1/0 |
| 6 | F4 | 2 | tl-ul | 0/0 | 0/0 | 0/1 |
| 7 | F3 | -1 | none | 0/0 | 0/0 | 0/0 |

The routed protocol's own handshake is on the same lines.  Examples (full lines
are in `runs/p1-mixed-protocols/README.md`):

```
case 3 ... target_index 1 ... axi_aw 0 axi_w 0 axi_b 0 axi_ar 1 axi_r 1
     target_error unknown tlul_a_handshakes 0 tlul_d_handshakes 0 tlul_errors 0
     tlul_error unknown target_protocol axi4-lite ... target_offset 0x00000004
case 5 ... target_index 2 ... axi_aw 0 ... tlul_a_handshakes 1 tlul_d_handshakes 1
     tlul_errors 0 ... target_protocol tl-ul ...
     tlul_a_valid 1 tlul_a_ready 1 tlul_a_opcode 4 tlul_a_address 0x00000004
     tlul_a_mask 15 tlul_d_valid 1 tlul_d_ready 1 tlul_d_data 0x00000000
     tlul_d_error 0
```

The APB3 + Wishbone lines likewise carry `wb_cyc 1 wb_stb 0 wb_ack 1
wb_we 0/1 wb_adr <word> wb_dat_w/wb_dat_r wb_sel 15` on a Wishbone-routed case,
and nothing on an APB3-routed one.  The APB3 + TL-UL run's `tlul_a_address`
equals the printed byte offset (`wb_adr * 4` for Wishbone), so the slave's own
address port is what the case states.

## 6. Compatibility

- **Historical exact pair** (`regression-mixed-pair`): case lines are byte-
  identical to `runs/round3-mixed-targets/fixed/run.log` after masking the
  `ticks`/`seconds` fields (verified by `diff`).  The summary's protocol words
  are identical; the only added words are the timing increment's
  `clock_plan`/`clock_*`/`clock_cpu_take_witness`.
- **Homogeneous Wishbone and TL-UL** (`regression-wb-fixed`,
  `regression-tlul-fixed`): case lines identical to
  `runs/round3-target-protocols/{wb,tlul}-fixed` after masking; summaries differ
  only by the timing increment's clock words.
- **Homogeneous same-protocol two-IP** (`regression-two-ip`): still prints the
  historical APB3 spelling `apb_transfers`/`apb_reads`/`apb_writes`, not the
  neutral `target_*` group.

## 7. What stays refused

- A protocol outside the supported set:
  `unsupported-targets:mixed-protocol:ahb-lite,apb3`.
- A mixed declaration that states a pin model:
  `unsupported-pins:multiple-targets` (a pin model is a one-target feature,
  independent of protocols).
- F5 on Wishbone or AXI4-Lite:
  `unsupported-f5:target-protocol-not-run:<protocol>:<name>`.
- The AHB-Lite target kind keeps `unsupported-target-protocol:ahb-lite-target:...`.

## 8. Tests

```
PYTHONPATH=src:. python3 -m pytest \
  tests/integration/test_inprocess_mixed_protocols.py \
  tests/integration/test_inprocess_mixed_targets.py \
  tests/integration/test_inprocess_target_protocols.py -q
# 67 passed

PYTHONPATH=src:. python3 -m pytest tests/integration/test_inprocess_f1f6_entry.py -q
# 196 passed
```

The 22 new tests in `tests/integration/test_inprocess_mixed_protocols.py` cover
the axis (every pair and triple, the four-protocol set, the empty set and a
protocol outside the supported set), the build-wide bridge/criterion/label
words, the mixed case/counter projection (the historical pair still projects
exactly the AXI tables), the generated per-target macros/traits (`wb_stall_sampled`
included), the mixed pin-model and F5 refusals, and the parsing of the four
saved sessions (protocol word per case, per-target 0/0, per-protocol counters,
summary protocol/bridge, and the entry's own correspondence check on the saved
lines).

All four suites are green at the end of the increment.  (Earlier in the day the
entry suite also carried two Wishbone-DMA-port refusal-word failures from the
concurrent DMA increment; that increment updated the assertions and the final run
passes.)  The exact pytest output is `runs/p1-mixed-protocols/tests.log`.

## 9. Hunks

`scripts/run_inprocess_f1f6.py`:

1. Protocol constants (new `MIXED_TARGET_PROTOCOLS`,
   `MIXED_TARGET_PROTOCOL_MIN/MAX`; the historical pair kept under its old
   name).
2. `target_protocol_axis()` admission and by-name refusal.
3. New helpers `ordered_target_protocols()`, `mixed_target_bridge()`,
   `TARGET_TRANSFER_CRITERIA`, `mixed_target_criterion()`,
   `TARGET_ERROR_RESPONSES`, `target_protocol_label()`.
4. `render_bindings()`: `TARGET_MIXED_HAS_*` presence macros and the mixed
   `TARGET_BRIDGE` word from the declared set.
5. `_generated_target_traits()`: `wb_stall_sampled` per Wishbone target.
6. Case projection: `NEUTRAL_CASE_OBSERVATION_KEYS`,
   `mixed_case_observation_keys()`, `mixed_case_counter_keys()` and the
   `protocols` argument of `case_observation_keys`/`case_counter_keys`/
   `case_document`.
7. Run path: `axis_label` at the record-parse labels, the F6 refusal label and
   the run scope; `case_document(..., protocols=...)`.
8. Run document `target_protocol`: generalized bridge/criterion/error words.

`scripts/inprocess_obi_apb_f1f4_spike.cpp`:

1. Presence/`TARGET_HAS_*`/`TARGET_NEUTRAL_COUNTERS_*` macros.
2. Protocol-specific guards switched to the presence words (sampling,
   completion, case counters, trace prints, summary groups).
3. Neutral counter group printed once per case/summary line.
4. Wishbone/TL-UL trace fields printed only for the routed target.
5. Per-target `last_offset` recorded for Wishbone/TL-UL completions.
6. Mixed `bus_error` declarations list only the channels the build has.

New files: the three scenario configs, the new test module and
`runs/p1-mixed-protocols/`.

## 10. Limits

- Only the four new sessions were really run.  The axis admits every 2..4
  subset, but no run of, for example, AXI4-Lite + Wishbone or of a four-protocol
  session is claimed.
- No mixed pin model; no F5 on Wishbone or AXI4-Lite; no DMA-to-target route is
  declared in these sessions.
- No coverage, certificate or replay claim; the evidence is the eight printed
  run logs in `runs/p1-mixed-protocols/`.
