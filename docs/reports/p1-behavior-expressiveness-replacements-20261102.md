# P1: behavior-schema expressiveness and three replacement samples (2026-11-02)

Scope: one increment on one source tree.  Three deliverables, each backed by a
real run through the unified entry `scripts/run_inprocess_f1f6.py`:

1. the behavior declaration layer (`configs/behaviors/*` +
   `src/myfuzz/composition/inprocess_behavior.py`) can now state an **ordered
   clear sequence**, **named pad groups / a serial peer** and a DMA **capability
   block**, and refuses by name everything this host or the pinned device cannot
   execute;
2. three **replacement samples** run through the existing generic paths with
   profile/behavior/scenario changes only: a CPU (`picorv32_wb_irq_rvfi`, F1-F6),
   a normal MMIO IP (`opentitan_uart_local`, TL-UL, F1-F5) and an additional DMA
   profile (`shared_profile_dma`, F6 RAM block);
3. **data-flow honesty**: a target with no IRQ facts keeps F1-F4/F6 and F5 is
   refused by name; a declaration with no DMA model refuses F6 by name; a
   declared-but-unexecutable clear/pad/DMA-capability form is refused by name
   instead of being silently dropped.

Evidence: `runs/p1-replacements/` (`README.md`, `run-all.sh`, `commands.log`,
`case-lines.txt`, three run directories, `refusals/`, `code/`, `probes/`).
Nothing here claims coverage, a certificate or a replay; a fetch is never counted
as a retirement.

## 1. What the declaration layer now accepts, and what it refuses

All three extensions are **additive**: a minimal declaration normalizes to exactly
the fact dict it produced before, and all shipped behavior files are unchanged
(`tests/composition/test_inprocess_behavior.py` still pins their exact dicts).

### 1.1 Ordered clear sequence (`clear_sequence`)

One IRQ link may state its clear as an ordered sequence instead of the single
`clear_writes` row.  Two spellings normalize to the same steps:

```json
"clear_sequence": [{"kind": "write", "offset": 0, "value": 4}]
"clear_sequence": [[0, 4]]
```

* a one-write sequence **is** the executor's single clear write, so it is derived
  into `clear_writes` and runs (the UART sample does exactly this,
  `clear_writes 1` in its case line);
* a longer sequence, or a read step, is refused by name:
  `unsupported-behavior-execution:multi_step_clear:<n>`,
  `unsupported-behavior-execution:clear_read_step`;
* shape errors are named per field:
  `unsupported-behavior-value:clear_sequence{,.kind,.offset,.value,.mixed}`,
  `unsupported-behavior-field:clear_sequence.<key>`;
* stating both `clear_writes` and `clear_sequence` for one link is the ambiguous
  form and is refused as `behavior-source-conflict:clear_writes`;
* the legacy `clear_writes` row keeps its historical one-row bound, so the
  existing out-of-shape test stays true; the multi-write spelling lives in
  `clear_sequence`.

**Seam with the concurrent IRQ increment.**  The entry now has its own scenario
key `irq_clear_sequence` and executes up to `MAX_CLEAR_WRITES = 2` writes; its own
comment says "the behavior schema's `clear_sequence` spelling is still bounded to
one step by its host capability fact".  That is exactly what
`HOST_SOURCE_EXECUTION['clear_steps'] = 1` states here: the behavior-file spelling
is refused above one step because the entry does not forward the schema's sequence
to the handler.  Nothing in the entry was edited by this increment; the two
spellings do not merge, and a longer sequence is never truncated.

### 1.2 Named pad groups and a serial peer (`pin_groups`)

One or more named groups, each either the dir-resolved pad word this host already
resolves or a serial peer:

```json
{"name": "pads", "kind": "dir_resolved_pad_word", "direction": "inout",
 "hold_ticks": 0, "padin_offset": 8, "external_value": 0,
 "pad_resolution": "device_drives_when_dir_bit_high_else_host"}
{"name": "serial0", "kind": "serial_peer", "rx_role": "rx", "tx_role": "tx",
 "tx_en_role": "tx_en", "idle_level": 1, "bit_ticks": 434, "frame": "8n1"}
```

* a single dir-resolved group is executable and is **derived into the `pins` fact**
  the host already consumes, so the group spelling is usable now, not report-only;
* more than one group, or a serial peer, is refused by name:
  `unsupported-behavior-execution:pin_groups:<n>`,
  `unsupported-behavior-execution:serial_peer` — **2026-11-03 更正**：这两条已被
  P2 取代，宿主现在按声明顺序执行最多 4 个 `dir_resolved_pad_word` 组并真驱动/采样
  `serial_peer`（8n1/8e1/8o1 三种帧都有真实批次），见
  [p2 引脚/串行报告](p2-pins-serial-execution-20261103.md)；仍拒绝的是多停止位、
  半双工、两个 peer、第二个 pad 字等形态；
* shape errors are named under `pin_groups.<field>` (kind, name, direction,
  hold_ticks, padin_offset, external_value, pad_resolution, rx_role, tx_role,
  tx_en_role, idle_level, bit_ticks, frame), duplicate names are
  `unsupported-behavior-value:pin_groups.name`, and stating both `pins` and
  `pin_groups` is `behavior-source-conflict:pins`.

The reuse claim is tested rather than asserted: the same two-group and
serial-peer declarations become executable under a widened
`limits={...}` argument, so a later host admits them by raising
`HOST_SOURCE_EXECUTION`, not by editing the parser.

### 1.3 DMA capability block (`capabilities`)

`inprocess_dma_behavior.v1` gains one optional object:

```json
"capabilities": {"channels": 1, "beat_bytes": 4, "max_outstanding": 1,
                 "burst_beats": 1}
```

* the declaration layer shape-checks it (`beat_bytes` must be a power of two;
  names and ranges are bounded) and reports it, with named host refusals, from
  `dma_behavior()`;
* the **planner** is the device-bound authority: `devices facts` now state
  `channels: 1`, `beat_bytes: 4`, `burst_beats: 1` (plus the existing
  `max_outstanding: 1`) for both pinned DMA families, and any declared value above
  them is refused as
  `dma-capability-beyond-device:<key>:<declared>><device>`.  A *profile* that
  declares such a capability is refused as
  `dma-profile-capability-beyond-device:<family>:<key>:<declared>><device>`;
* the plan carries `declaration.declared_capabilities`,
  `declaration.device_capabilities` and
  `declaration.declared_profile_capabilities`, and `validate_transfer_plan`
  rechecks the declared capabilities against the profile, so a plan cannot keep a
  capability its device cannot have;
* **no execution is faked**: the executed transfer stays the single-channel,
  four-byte-beat, one-outstanding four-word block, and the sample says so.

## 2. The three replacement samples

Evidence and full case lines: `runs/p1-replacements/README.md`.  Every sample is
one build + one run of the unified entry; the model set is reused from
`runs/p1-replacements/cache`.

| sample | scenario | flows run | flows refused | verdict | wall | host run | per case |
|---|---|---|---|---|---|---|---|
| CPU | `configs/scenarios/p1-replacements/cpu-picorv32-wb-irq-rvfi-f1f6.json` | F1-F6 | — | 6/6 | 5.07 s | 5.3 ms | 89-256 µs |
| MMIO IP | `.../ip-opentitan-uart-local-tlul-f1f5.json` | F1-F5 | F6 (`unsupported-f6:no-dma-model:TL-UL`) | 5/5 | 5.69 s | 6.3 ms | 25-218 µs |
| DMA | `.../dma-shared-profile-dma-f6.json` | F1-F4, F6 | F5 (`unsupported-f5:target-irq-semantics:apb3:source_port,source_bit_offset,trigger_writes,status_offsets`) | 5/5 | 5.45 s | 5.2 ms | 27-175 µs |

### 2.1 CPU: `picorv32_wb_irq_rvfi` (Wishbone, custom IRQ, RVFI)

The scenario differs from the Ibex baseline
`configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6.json` only in
`cpu_profile`, `cpu_irq_bit` (3: the profile's custom-IRQ ABI, bits 0-2 internal),
`cpu_timing` (4/4), `pulse_width_ticks` (1), `image_start`/`image_end`
(0/131072, the same 128 KiB image at this CPU's boot base),
`handler_wait_iterations` (64) and `case_tick_budget` (12000).  The target, DMA,
windows and every F5/F6 fact are byte-identical.

What the case lines show: `rvfi_writebacks 17/5/6/7/32/54`,
`rvfi_order_monotonic 1` (F1 is a retirement claim); F5 `irq_edges 1`,
`irq_takes 1`, `device_high_ticks 1`, `delivered_high_ticks 1`,
`isr_read_register_kind count`; F6 `dma_reads 4`, `dma_writes 4`,
`ctl_status 0x00000040`, `dst0..dst3` equal to the record words.  The summary
states `cpu_bus wishbone-single-master`, `cpu_irq declared_custom_bit_3`,
`cpu_irq_observation eoi`, `cpu_irq_delivery edge_to_latched_input`,
`irq_edges 2`, `irq_takes 2`, `dma observed`, `failures 0`.

`traps 0` on this CPU is the RVFI trap face's own value (the profile exports
`rvfi_trap`), not a host default.

### 2.2 MMIO IP: `opentitan_uart_local` (TL-UL), real `tx_done` interrupt

The scenario differs from the TL-UL timer F5 scenario only in the target profile
(`opentitan_uart_local`), the behavior file, the window base (`0x40003000`) and one
fixed input (`rx=1`, the UART's idle serial level).  It uses the same generic
`tlul_register_observe` kernel and `beat_to_tlul` bridge.

F2/F4 answer on the real A/D channels (`tlul_a_handshakes 7`,
`tlul_d_handshakes 7`, `tlul_errors 0`).  F5 is the honest device interrupt:
`INTR_ENABLE(4)=4` unmasks `tx_done`, `CTRL(16)=0xffff0001` enables the
transmitter and sets `NCO=0xffff` so the 16x baud tick runs, `WDATA(28)=0x5a`
pushes one byte, the RTL really serializes it, the `tx_done` event sets
`INTR_STATE` bit 2, `intr_tx_done_o` stays high for 37 ticks, the ISR reads
`INTR_STATE` (`isr_read_value 0x105`) and writes the declared one-step clear
(`clear_writes 1`, `last_clear_data 0x4`); the line falls
(`irq_level_final 0x00000000`, `level_stuck 0`, `isr_cause 0x00000004`).
`INTR_ENABLE` masks the two `Status`-type bits that are high while the FIFOs are
empty, so the declared source is the `Event`-type `tx_done` and not
`tx_watermark`/`tx_empty`.

**Finding (reported, not papered over).**  The profile declares each of the nine
interrupts as a one-bit port with `bit: 0` and does **not** state the
`INTR_STATE`/`INTR_ENABLE` bit.  The first declaration used bit 3 (the position in
the profile's list) and the run failed honestly (`probes/uart-f1f5b/run.log`:
`wait_timeout 1`, `target_read_data 0x00000000`), while a register probe read
`INTR_STATE 0x105` (`probes/uart-diag1b`) - bit 2 was already set and the line was
masked.  `uart_reg_pkg.sv`'s `uart_hw2reg_intr_state_reg_t` field order (packed
struct, first field MSB) gives `tx_done = bit 2`, which the behavior file now
states with its evidence.  A profile that carried the register bit would have made
the wrong first declaration impossible; that gap is the honest residual finding of
this sample.

### 2.3 DMA: `shared_profile_dma`, same pinned RTL, different declaration

`shared_profile_dma` and `zipdma_smoke` share `component_id
zipdma_selected_wishbone`, source revision
`git:42606d2d6ef55df313772232977621b2d72f0159`, top module `zipdma` and the same
nine files; the documents differ (local harness block, test capability reference,
`f6_dma` declaration).  The sample selects the shared profile, its own
`test_capability.json` and its own behavior file
`configs/behaviors/zipdma_capability_f6.json` (block 4, status bits 31/30, and the
capability block 1/4/1/1).  It is **the same device behind a different profile**,
not a new device.

The four-word RAM block still runs: `dma_reads 4`, `dma_writes 4`,
`dma_lane_masks 0x0000000f`, `ctl_status 0x00000040`, `dst0..dst3` equal to the
record, `dma_acks 8`, `irq_edges 1`, `irq_takes 1`, `failures 0`.  `summary.json`'s
`behavior.dma` reports the declared capability block beside the executed transfer.
No multi-channel, wide-beat or multiple-outstanding transfer is claimed: a file or
profile that declares one is refused by the planner
(`refusals/dma-two-channel-*.txt`).

## 3. Named refusals (the data-flow honesty rule)

Six captures under `runs/p1-replacements/refusals/`, each with its command, exit
status and final message:

| what is absent | message |
|---|---|
| no DMA in the UART scenario | `unsupported-f6:no-dma-model:TL-UL` |
| no F5 facts in the DMA scenario | `unsupported-f5:target-irq-semantics:apb3:source_port,source_bit_offset,trigger_writes,status_offsets` |
| a serial peer | `unsupported-behavior-execution:serial_peer`（**2026-11-03 更正**：单个 peer 现已可执行，见 [p2 引脚/串行报告](p2-pins-serial-execution-20261103.md)；仍拒绝的是两 peer、半双工等形态） |
| an ordered write/read/write clear | `unsupported-behavior-execution:multi_step_clear:3` |
| a behavior file declaring 2 channels / 8-byte beats | `unsupported-dma-declaration:dma-capability-beyond-device:channels:2>1` |
| a profile declaring 2 channels / 8-byte beats | `unsupported-dma-declaration:dma-profile-capability-beyond-device:zipdma:channels:2>1` |

The declaration-only files (`configs/behaviors/declaration-only/`) and their
scenarios (`configs/scenarios/p1-replacements/refused-*.json`) exist only to
exercise these names; none of them is a runnable device declaration.

## 4. Tests

```
PYTHONPATH=src:. python3 -m pytest tests/composition/test_p1_behavior_extension.py \
  tests/integration/test_p1_replacement_configs.py -q
# 66 passed
```

* `tests/composition/test_p1_behavior_extension.py` (52 tests): minimal
  declaration unchanged; one write step derived into `clear_writes`; two steps and
  a read step refused; every named shape error; two pad groups and a serial peer
  normalize **and** are refused; the same forms execute under widened limits; the
  shipped executable behavior file normalizes and the shipped declaration-only
  files are refused by name; the DMA capability block normalizes and is reported;
  the planner refuses an over-declared behavior file, an over-declared profile and
  a tampered plan.
* `tests/integration/test_p1_replacement_configs.py` (14 tests): the CPU scenario
  differs from the Ibex baseline only in `CPU_SIDE_KEYS`; the CPU profile is the
  pinned Wishbone/custom-IRQ/RVFI one; the UART behavior declares the four F5
  facts for a port the profile really exposes and the port bit is not the register
  bit; the UART scenario declares no DMA; `shared_profile_dma` is the same pinned
  RTL as `zipdma_smoke` with a different document; the DMA plan keeps the declared
  and device capability facts; the DMA scenario declares no F5 facts; every
  refusal scenario names its refusal.

One command runs the new tests beside every suite this increment depends on:

```
PYTHONPATH=src:. python3 -m pytest \
  tests/composition/test_p1_behavior_extension.py \
  tests/integration/test_p1_replacement_configs.py \
  tests/composition/test_inprocess_behavior.py \
  tests/composition/test_dma_transfer.py \
  tests/composition/test_multi_target.py \
  tests/integration/test_inprocess_f1f6_entry.py \
  tests/integration/test_inprocess_target_protocols.py \
  tests/fuzz/test_irq_declaration_expansion.py \
  tests/fuzz/test_wbdmac_behavior_declaration.py \
  tests/integration/test_p0_1_irq_dma_declarations.py \
  tests/test_doc_link_check.py -q
# 593 passed in 2.24s
```

That is the behavior layer, the DMA planner, the multi-target axis, the IRQ and
WBDMAC declaration tests, the P0-1 IRQ/DMA declarations, the target-protocol and
unified-entry suites, the documentation link check and the 66 new tests.

The wider run over `tests/composition`, `tests/fuzz` and
`tests/integration/test_inprocess_f1f6_entry.py` reports 21 failures in six files,
all of them outside this increment and all in areas other increments are editing
at the same time:

| file | failing tests | what the failure is about |
|---|---|---|
| `test_soc_adapter_scope.py` | 4 (+4 subtests) | the rendered AXI4/AXI4-Lite/TL-UL/Wishbone master adapters |
| `test_elaboration_execution_reuse.py` | 4 | re-validation call count across an execution scope |
| `test_elaboration_mode_scope.py` | 3 | `component_profile.py:2152` `AttributeError` on a test namespace fake |
| `test_real_component_profiles.py` | 3 subtests (`zipcpu_uart`) | declared capabilities/evidence of that profile |
| `test_ibex_component_profile.py` | 2 | expected port-kind counts (`observe` 20 vs 25) |
| `test_legacy_entrypoint_compatibility.py` | 1 | a golden matrix digest |

None of those six files imports either module this increment touches
(`grep` for `inprocess_behavior` / `dma_transfer` in them returns nothing), the
failure messages are about profile port counts, elaboration-scope call counts,
adapter rendering, a profile's capability evidence and a golden digest, and
`src/myfuzz/composition/component_profile.py` is modified in the working tree by
another increment.  (Earlier in the session
`tests/fuzz/test_irq_declaration_expansion.py` and
`tests/fuzz/test_new_ip_2_onboarding.py` also failed while those increments were
mid-edit; the IRQ one is green now, and the onboarding one fails on three
`pulp_timer_*mhz*` profiles the timing increment added - the only profile this
increment adds is a **Wishbone DMA** profile, outside that test's APB3/AXI4-Lite
set.)

## 5. Changed files (hunks)

Owned module — `src/myfuzz/composition/inprocess_behavior.py`:

* module docstring: the three new declarable forms and the fact/execution split;
* new constants: `PIN_GROUP_KINDS`, `PIN_GROUP_DIRECTIONS`,
  `PIN_GROUP_DIR_KEYS`, `PIN_GROUP_SERIAL_KEYS`, `SERIAL_FRAMES`,
  `MAX_PIN_GROUPS`, `MAX_PIN_HOLD_TICKS`, `MAX_SERIAL_BIT_TICKS`,
  `CLEAR_STEP_KINDS`, `CLEAR_STEP_KEYS`, `MAX_CLEAR_STEPS`,
  `HOST_SOURCE_EXECUTION`, `HOST_DMA_CAPABILITY`, `DMA_CAPABILITY_KEYS`,
  `DMA_CAPABILITY_BOUNDS`, `SOURCE_DOCUMENT_EXTRA_KEYS`; `SOURCE_LINK_KEYS` gains
  `clear_sequence`; `DMA_BEHAVIOR_KEYS` gains `capabilities`;
* `_pad_word` (refactored out of `_pins`), `_clear_sequence`, `_pin_group`,
  `_pin_groups`, `execution_refusals`, `dma_capabilities`,
  `dma_capability_refusals`;
* `_source_facts`: a `clear_sequence` is normalized and a one-write sequence is
  derived into `clear_writes`; both clear spellings together are refused;
* `source_behavior(config, base_dir, limits=None)`: numeric pads are parsed before
  the "is this an F5 declaration" question, `pin_groups` normalizes and derives
  `pins`, and every declared form the host cannot execute is refused by name
  before the facts are returned;
* `dma_behavior`: reports `capabilities`, `capability_refusals`,
  `capabilities_executable` when a file declares the block (absent otherwise, so
  the historical dict is byte-identical);
* docstrings for the two public functions, and `__all__`.

Planner — `src/myfuzz/composition/dma_transfer.py` (capability fields only; the
route/geometry code is untouched):

* imports `BehaviorError`, `dma_capabilities`, `dma_capability_refusals` from the
  declaration layer so both readers parse one shape;
* `BEHAVIOR_KEYS` gains `capabilities`; new `DMA_CAPABILITY_KEYS`;
* `DEVICE_FACTS` gains `channels: 1`, `beat_bytes: 4`, `burst_beats: 1` for
  `zipdma` and `wbdmac`, with their evidence comments;
* `_device_declaration`: refuses an out-of-shape or over-device **profile**
  capability (`dma-profile-capability-invalid`,
  `dma-profile-capability-beyond-device`) and returns `device_capabilities` /
  `declared_profile_capabilities`; new `_device_capabilities`;
* `_behavior_declaration(..., device_capabilities=)`: normalizes and refuses the
  behavior file's capability block (`dma-capability-invalid`,
  `dma-capability-beyond-device`) and returns it;
* `dma_transfer_declaration`: passes the device capabilities and records the three
  capability facts in `plan['declaration']`;
* `validate_transfer_plan`: rechecks the plan's declared capabilities against the
  profile (`dma-capability-beyond-device`), and the module docstring states the
  new declaration.

New declaration files:

* `configs/behaviors/opentitan_uart_tx_done_f5.json` (executable, one-step
  `clear_sequence`);
* `configs/behaviors/zipdma_capability_f6.json` (executable capability block);
* `configs/behaviors/declaration-only/`: `pulp_i2c_three_step_clear_f5.json`,
  `opentitan_uart_serial_peer_f5.json`, `two_pad_groups_f5.json`,
  `ambiguous_clear_f5.json`, `zipdma_two_channel_f6.json`;
* `configs/peripherals/p1_zipdma_two_channel_declaration/component_profile.json`
  (declaration-only copy of the pinned ZipDMA profile that adds
  `channels: 2`, `beat_bytes: 8`);
* `configs/scenarios/p1-replacements/`: three runnable samples and four
  `refused-*` scenarios.

Tests: `tests/composition/test_p1_behavior_extension.py` (52),
`tests/integration/test_p1_replacement_configs.py` (14).

Evidence: `runs/p1-replacements/` as described in its `README.md`
(`run-all.sh`, `commands.log`, `case-lines.txt`, three run directories,
`refusals/`, `code/`, `probes/`).

## 6. Limits and what is not claimed

* The behavior-file clear sequence is executed for **one write step only** (the
  entry's own `irq_clear_sequence` supports two writes, a concurrent increment);
  longer sequences and read steps are refused by name, never truncated.
* No serial driver: a serial peer is declarable and refused; the UART's `rx_*`
  sources are not exercised.
* No multi-channel, wide-beat or multiple-outstanding DMA execution; those are
  declared capabilities only and are refused above the pinned device.
* The UART profile's missing `INTR_STATE` bit is a profile gap reported in §2.2,
  not something this increment changed (profiles are owned elsewhere).
* `probes/` keeps the failed/diagnostic runs (wrong-bit F5 attempt, register
  probes, a first Wishbone probe with a wrong window base); none of them is
  counted in the three claims.
* No coverage, certificate or replay claim is made; the case lines are
  observations of real handshakes on the models that produced them.
