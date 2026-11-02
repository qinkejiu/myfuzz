# Non-APB/AXI4 target protocols: real Wishbone and TL-UL register targets in the unified loop (2026-11-02)

Status: **integrated into the unified in-process executor and passed on real RTL**
for Wishbone classic and TL-UL.  AHB-Lite is **refused by name** (reason and
profile fact below).  Evidence: `runs/round3-target-protocols/` (`README.md`,
`commands.log`, `run-all.sh`, seven `run.log`/`summary.json`, `code/`, `before/`,
`hunks.diff`, `_lines_for_test.txt`).

This increment adds two target protocols to the unified entry and host without
touching the F1, F5/IRQ-link, DMA, CVA6/AXI4-CPU or APB3/AXI4-Lite target paths,
and without changing `src/myfuzz/local_harness/*`.  Every protocol decision is a
per-target fact; each case line states the protocol of the target it was routed
to and the handshake that target's own pins carried.

## 1. What was already there, and what this increment used

The local harness already generated complete real artifacts for both protocols
(`runtime_renderer.py`):

* classic Wishbone: `wishbone_register_observe` (generic kernel) renders
  `beat_to_wishbone` + the pinned IP, and exposes the slave's
  `cyc/stb/we/adr/dat_w/sel/ack/dat_r[/stall]` as passive taps;
* TL-UL: `tlul_register_observe` renders `beat_to_tlul` + the pinned IP, and
  exposes the 10 A-channel and 10 D-channel roles as passive taps.

No local-harness or RTL change was needed.  The entry and the C++ host did not
know either protocol; that is what this increment adds.

## 2. Targets and scenarios

| protocol | scenario | profile | window | target kind | bridge |
|---|---|---|---|---|---|
| Wishbone classic | `configs/scenarios/inprocess-obi-wb-uart-f1f4.json` | `configs/peripherals/zipcpu_uart` (`wishbone/classic`, word-addressed, registered-ack, `sel` implemented) | `0x40001000` + 16 | `wishbone_register_observe` | `beat_to_wishbone` |
| TL-UL | `configs/scenarios/inprocess-obi-tlul-timer-f1f4.json` | `configs/peripherals/opentitan_rv_timer_local` (`tl-ul/1`, 32-bit, integrity required) | `0x40003000` + 4096 | `tlul_register_observe` | `beat_to_tlul` |

Both scenarios are one Ibex RVFI OBI CPU + one target + the RAM image
`0x10000..0x30000`.  The Wishbone target declares the two pin constants the
wishbone register template requires (`rx=1`, `cts_n=0`).  Neither scenario
declares a behavior file (so no F5 facts) and neither declares a DMA (so F6 is
refused).  See the run README for the full register maps and case rationale.

Why this target and not `zipcpu_timer`: the timer's generic variant is
addressless (`addressless-select-ignored`), so its artifact has no `adr` port
and no case could print the offset the slave decoded.  The request builder
refuses it by name (`unsupported-target-trace:wishbone:addressless:...`) instead
of printing the host's own request as a "sampled" address.  The UART is the
same Word-addressed registered-ack kernel with four real registers and an
address port, which is what the required `cyc/stb/ack/we/adr/dat_w/dat_r/sel`
sample needs.

## 3. Host/entry changes (summary; full diff in `runs/round3-target-protocols/hunks.diff`)

Entry `scripts/run_inprocess_f1f6.py`:

* `TARGET_PROTOCOLS` maps only the **generic** kinds
  (`wishbone_register_observe`, `tlul_register_observe`); the specialised kinds
  are refused as `unsupported-target-kind:<kind>` because their kernels expose
  no passive trace (timer) or omit `dat_r` (uart) or carry pin endpoints (GPIO);
* `PROTOCOL_TRACE_ROLES` / `WB_TRACE_ROLES` / `TLUL_TRACE_ROLES` bind the exact
  taps a case samples; `PROFILE_PROTOCOLS` maps `wishbone/classic` and `tl-ul/1`;
* `generic_target_request_from_profile()` builds the v2 request (pinned template
  variant + declared fixed inputs);
* `TARGET_PROTOCOL_WISHBONE`/`TARGET_PROTOCOL_TLUL`/`TARGET_PROTOCOL_VERBOSE`
  and per-target `TARGET_PROTOCOL_*_<n>`; the generated `IpTarget<n>` trait
  carries `wishbone`/`tlul` and only that protocol's accessors; the one-target
  fallback trait does the same from the flat macros;
* case key tables `WB_*`/`TLUL_*` and the neutral counter group; the historical
  APB3/AXI4-Lite tables and spellings are untouched;
* `correspondence()` checks the real handshake against the record (Wishbone:
  held `cyc+ack`, one `stb` pulse, direction, full `sel`, `adr` = offset/4,
  `dat_w`/`dat_r`; TL-UL: one A handshake of the right opcode, one D handshake,
  full mask, `a_address`/`a_data`, `d_error 0`), so a case cannot pass on a
  request the host only drove;
* the report JSON states each protocol's trace roles, transfer criterion and
  error channel.

Host `scripts/inprocess_obi_apb_f1f4_spike.cpp`:

* the two new protocol macros and the one-of-four header check; the trait gains
  `wishbone`, `tlul`, `protocol`, `bus_channel` and the `wb_*`/`tlul_*`
  accessors;
* one Wishbone sampling block and one TL-UL sampling block beside the existing
  APB3/AXI4-Lite ones, each `if constexpr` on the routed target;
* Wishbone transfer = `cyc && ack` (the registered-ack variant pulses STB for one
  cycle and holds CYC through the answer), with a separate `wb_stb_pulses`
  counter for the request phase; TL-UL transfer = one A handshake followed by
  one D handshake, with the payload taken from the channel that carried it;
* case line: `target_protocol` under the verbose axis, the neutral counters plus
  `wb_acks/wb_stb_pulses/wb_stalls` or
  `tlul_a_handshakes/tlul_d_handshakes/tlul_errors`, and the F2/F4 sampled
  handshake group;
* summary: `target_protocols`, `target0_protocol`, `target0_bridge`,
  `target0_fixed_inputs`, the protocol's totals and its own
  `bus_error unknown <channel>`;
* a TL-UL `d_error` is recorded and fails the case (it is a real observation);
  every other protocol keeps the historical abort on a beat error without a
  sampled protocol error.

No change to `src/myfuzz/composition/multi_target.py` (digest unchanged) and no
change to `src/myfuzz/local_harness/*`.

## 4. Real fixed batches

```
# Wishbone classic — 5/5 observations_passed (18.6 s wall, host 4.3 ms)
PYTHONPATH=src:. python3 scripts/run_inprocess_f1f6.py \
  --config configs/scenarios/inprocess-obi-wb-uart-f1f4.json \
  --cache runs/round3-target-protocols-cache \
  --output runs/round3-target-protocols/wb-fixed \
  --records 'F2:40001004,F4:40001000:0000005a,F2:40001000,F4:4000100c:00000041,F3:00014004:0badf00d'

# TL-UL — 6/6 observations_passed (13.7 s wall, host 4.3 ms)
PYTHONPATH=src:. python3 scripts/run_inprocess_f1f6.py \
  --config configs/scenarios/inprocess-obi-tlul-timer-f1f4.json \
  --cache runs/round3-target-protocols-cache \
  --output runs/round3-target-protocols/tlul-fixed \
  --records 'F2:40003004,F4:40003004:00000001,F2:40003004,F4:40003118:00000100,F2:40003118,F3:00014004:0badf00d'
```

Key facts (full lines in the run README):

* Wishbone: `F2:40001004` read `FIFO_STATUS = 0x403f4000` (the same reset word
  the AXI4-Lite version of this RTL returned), `F4:40001000` wrote `0x5a` into
  `SETUP` and the next `F2:40001000` read `0x5a` back through the same slave,
  `F4:4000100c` pushed `0x41` into `TXREG`.  Each target case states
  `wb_cyc 1 wb_stb 0 wb_ack 1 wb_we .. wb_adr .. wb_dat_w .. wb_dat_r .. wb_sel 15`,
  `wb_acks 1 wb_stb_pulses 1`; the summary states
  `target_protocols wishbone target0_bridge beat_to_wishbone`, `wb_acks 4`,
  `wb_stb_pulses 4`, `wb_stalls 0`, `target_errors 0`.
* TL-UL: `CTRL` (0x4) read 0, `F4` wrote 1 (`a_opcode 0`, `a_mask 15`,
  `a_address 4`, `a_data 1`, `d_error 0`) and the next case read 1 back;
  `COMPARE_LOWER0_0` (0x118) was written with 0x100 and read back 0x100.  The
  summary states `target_protocols tl-ul target0_bridge beat_to_tlul`,
  `tlul_a_handshakes 5`, `tlul_d_handshakes 5`, `tlul_errors 0`,
  `target_errors 0`.

`wb_stb 0` at the completed sample is not a missing strobe: the admitted
word-addressed registered-ack variant asserts STB for one cycle and holds CYC
through ACK, so the request phase and the completion are different cycles and
are counted apart (`wb_stb_pulses` = the pulse, `wb_acks` = the ack).

## 5. Regressions (same code, same batch)

| run | verdict |
|---|---|
| mixed APB3 + AXI4-Lite | 6/6, `target_protocols apb3,axi4-lite` (unchanged) |
| same-protocol two APB3 IPs | 6/6, historical `apb_transfers/apb_reads/apb_writes` spelling |
| single AXI4-Lite target + ZipDMA | 5/5, `axi_aw/w/b/ar/r 1/1/1/1/1`, F6 unchanged |
| CVA6 AXI4 CPU | 3/3 |
| DMA RAM→SPI TX FIFO fixed write | 1/1 |

All seven commands, their digests before/after and their wall times are in
`runs/round3-target-protocols/commands.log`.  Code identity:
`40cabbb80d2265f6e666fb1b8ac1447a` (entry),
`59dd65eb9f73ffb9bf74bbbc6bc6c968` (host), `c33a1d99...` (multi_target, unchanged).

## 6. AHB-Lite target: named refusal, with the profile/closure fact

The tree has exactly one AHB-Lite *target* profile:
`configs/peripherals/caliptra_sha256`.  It is the Caliptra SHA-256 accelerator,
whose `sha256.bus` is an `ahb-lite/1` slave with a 4 KiB register window and a
separate debug/configuration endpoint; its capabilities declare
`byte_enable: false`, `partial_write: false`, `has_error: false`.  I verified
that its artifact renders (`kind=ahb_lite_register_observe` through
`ahb_lite_mmio_target`, 10-signal `ahb-lite` trace), so a real AHB target kernel
exists, but this increment did not add the two-phase AHB sampling to the unified
host, and the only profile is a crypto accelerator rather than a generic
register window.  AHB is therefore refused by name in two places:

* before any RTL, at the profile protocol mapping:
  `unsupported-target-protocol:ahb-lite/1`;
* at the artifact kind:
  `unsupported-target-protocol:ahb-lite-target:no-two-phase-sampling-in-this-increment:caliptra_sha256`.

The CVW AHB-Lite CPU boundary is **not** used as a target.  No AHB case was run
and no AHB coverage/certificate/replay is claimed.

## 7. Named refusals and limits

* `unsupported-target-kind:<kind>` — specialised Wishbone/TL-UL kinds whose
  kernels expose no passive protocol trace (or omit a role the case states).
* `unsupported-target-trace:wishbone:addressless:<profile>` — the addressless
  classic variant (`zipcpu_timer`).
* `unsupported-targets:mixed-protocol:<set>` — any multi-protocol session other
  than `{apb3, axi4-lite}`; a mixed Wishbone+APB3 session is a named refusal,
  not a claim (the per-target dispatch exists but no run backs that pair).
* `unsupported-f5:target-irq-semantics:{wishbone,tl-ul}:<missing>` for the two
  scenarios as declared (no F5 facts) and
  `unsupported-f5:one-f5-target:apb3-only:<protocol>:<name>` if such a target
  declared the four facts; the TL-UL timer's interrupt output is observed, not
  delivered.
* `unsupported-f6:no-dma-model:Wishbone|TL-UL` and
  `unsupported-dma-route:apb3-target-only:<protocol>:<name>` for a DMA route to
  either new protocol.
* one host tick drives both models (both profiles declare 50 MHz,
  `assume_single_clock: true`); only compact observations are claimed.

## 8. Tests

New `tests/integration/test_inprocess_target_protocols.py` (21 pure-Python
tests): kind→protocol mapping, the homogeneous axis and the mixed refusal, the
profile mapping, the AHB artifact refusal, trace role tables, the two request
builders (including the addressless refusal), generated traits per protocol, the
real case lines (Wishbone and TL-UL) parsed and credited, case-key sets, summary
words, tampered-handshake refusals, the F5/DMA-route named refusals, and the
real `run.log` parse.

Updated expectations that asserted the old refusals (semantics changed, so the
words changed): `tests/integration/test_inprocess_f1f6_entry.py` (the
unmapped-kind example is now `tlul_gpio`, a TL-UL kind with a contradicting
trace asserts the trace refusal, and the event-document channel map includes
`tlul`) and `tests/fuzz/test_new_ip_2_onboarding.py` (the admitted TL-UL/Wishbone
profiles moved to an admitted list; the addressless ziptimer and Caliptra keep
their named refusals).

Required four-file set: 371 passed; with the new protocol tests 392; with the
adjacent integration/entry files (including the onboarding file) 732.  The whole-tree combined suite is the coordinating
campaign's batch (13 batches, 1502 tests); this increment states only the sets
it ran itself.
