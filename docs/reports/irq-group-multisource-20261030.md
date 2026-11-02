# Two-source IRQ group native case — 2026-10-30

Scope: close the two `directed-irq-matrix.json` multi-source cases that were
refused with `no-public-native-two-source-runner`:

* `two-source-ambiguous` — two declared-output targets in one real host OR group
  are **both active at the single native CPU take**, the real `irq_group_delivery`
  frame is `attribution_status='joint'` with both members' real native pulses,
  the CPU take still occurs, and `observe_declared_irq_consumption` returns
  `status='ambiguous'`, `irq_consumption='unknown'`, refusal
  `declared-F5-OR-attribution-not-unique` and zero credit;
* `unique-two-source-each` — each member of the same real two-member group
  triggered alone is `unique` with its own real native pulse and the full
  verified consumption chain through the same observation function.

No DUT was built and no native session was started by this work (the frozen
window belongs to the lead). Everything below is pure Python/pytest plus the
real journals already saved under `research/` (read-only) and the public
factories of `scripts/run_timer_irq_smoke.py` / `scripts/run_declared_irq_f5.py`.
`grants_F5`, `grants_F6` and `reward_eligible` are false everywhere; the case
grants nothing.

| File | Role |
|---|---|
| `scripts/run_irq_group_native.py` | new config-driven native case (`--native`, `--config`, `--output`, `--cache`, `--max-steps`, `--mode original\|fresh\|both`); reuses `timer_artifact`, `target_session`, `source_backed_boot_fetch`, `_artifact`, `build_declared_irq_firmware`, `f5_fields`, `cpu_obi_traces`, `declared_irq_runtime_mapping`, `GeneratedCve2Session`, `DataflowRouter`, `IrqDeliveryGroup`/`IrqDeliveryMember`, `ScenarioRunner` and `observe_declared_irq_consumption`; no new adapter, no per-CPU/IP code |
| `configs/scenarios/directed-irq-group/joint-two-targets-ibex.json` | joint case: wb-timer + apb-spi, `mie_gate=true`, observed member = timer |
| `configs/scenarios/directed-irq-group/unique-wb-timer-ibex.json` | timer alone, unique, F5-proven host width 16 |
| `configs/scenarios/directed-irq-group/unique-apb-spi-ibex.json` | SPI alone, unique, F5-proven host width 16 |
| `tests/integration/test_irq_group_script.py` | 52 pure tests: declaration/refusals, program layout, offline derivation over synthetic journals, summary grants |

## Why the joint take needs a real CSR gate (and why widths are bounded)

The OR group delivers value `1` on the **first** rising member pulse and the CPU
takes on that tick (`src/myfuzz/scenario/irq_delivery_group.py:139`,
`src/myfuzz/scenario/runner.py:1932`). With `mstatus.MIE` enabled while the two
declared stores execute, the take is therefore always **unique to whichever
member pulses first**, whatever the pulse width. The joint case reuses the
masked-phase idiom of the existing fixed program
(`scripts/run_cv32e20_irq_smoke.py:15-17`: `csrrc mstatus, 8` … later
`csrrs mstatus, 8`): the fixed case image is

```
addi x3, 0, 8 ; csrrc mstatus, x3        # mstatus.MIE = 0
<declared trigger writes in plan order>  # real CPU stores
csrrs mstatus, x3                        # mstatus.MIE = 1
jal park, park
```

so the **one** real take happens after both native pulses are already high.
That is real CPU CSR state, not a host-invented pulse; the overlap itself is
still re-derived from the actual frame/samples and refused when absent.

Width bound, from the saved real F5 journals
(`research/input-strategy-audit-20261027/runs/declared-irq-f5-20261030/`):

* the fixed case image retires one word every ~2 CPU ticks and the ZipTimer
  `o_int` rises ~6 CPU ticks after its store delivery
  (`wb-timer/.../events.json`: store delivered between ticks 40-41, pulse
  `[46,62)`); the PULP SPI `events_o` rises ~1-2 ticks after its store;
* the handler returns **46-47 CPU ticks after the take**
  (`wb-timer`: take tick 47, MRET tick 94; `apb-spi`: take 44, MRET 90);
* with the 14-word gated program the enable retires ~25-27 ticks after the
  entry and the take follows ~1-3 ticks later, i.e. ~19-21 ticks after the
  timer pulse rises and ~2-4 after the SPI pulse rises.

So a width must satisfy `~15 <= width <= ~40` for the joint case. The joint
config uses 22 (≈13 ticks of margin at the late-pulse end and >25 ticks before
MRET). Wider pulses are possible, but a pulse still high when `MRET` restores
`mstatus.MIE` produces a **second** take and the shared observer refuses
(`declared-F5-one-actual-native-CPU-take-required`), so 64-128 as sometimes
suggested would not work.

The single-member configs reuse the **proven** F5 native width 16 for both
members, which matters for the SPI: its ISR read of `INTSTA(0x28)` re-arms the
event and produces a *real second native pulse* during the handler
(`apb-spi/.../events.json`: pulse `[41,57)`, take 44, INTSTA read ~69, second
pulse `[72,88)`, MRET 90 — two ticks of margin). The joint case observes the
**timer** (`COUNT(0x0)`, side-effect free), so its ISR does not re-fire the SPI
event and the wider 22-tick stretch is safe.

## What the script derives from the actual journal (never assumed)

`transport_evidence()` re-derives, in order, and raises an `irq-group-*`
`ValueError` on any violation:

1. the actual `mmio_delivery` writes of both group targets equal the declared
   plan in order, at `base + offset`, with the declared values;
2. exactly one `cpu_external_irq_taken`; exactly one `irq_group_delivery` frame
   joined to it at the take tick; group id/sha/target/port identities match the
   declared group; `value == 1`;
3. the frame's members are exactly the declared group members; every active
   source is a declared member; the frame attribution is `joint` **iff** two
   members are active and `unique` **iff** exactly one, and it must equal
   `expected_attribution`;
4. per member: its `native_source` reference resolves to that component's own
   `local_tick_sample` (kind/component/phase/tick/epoch), the declared
   `runtime_name` raw value in `outputs.physical`, the declared bit equals the
   frame member value, and `outputs[source_port]` projects that raw value; an
   active member's pulse sample must come after *its own* trigger delivery;
5. the parsed CPU input (`expected/pre/post`) equals the OR value, the take
   probe `irq_taken_pre == 1` unmasked and undiverted, the decision serial is
   non-zero, exactly one `intr=1` handler-entry retirement exists, and its
   serial equals the decision serial;
6. joint: both members active in the take frame and both raw bits `1`, and the
   shared observer returns `status='ambiguous'`, `irq_consumption='unknown'`,
   `refusals == ['declared-F5-OR-attribution-not-unique']`,
   `consumption.active_sources` equal to the frame's, no
   `register_reads`/`result_ram_writes`, all four grant fields false;
7. unique: exactly one active member (the observed one), `unique_source` is its
   exact `id.port`, the idle member is never active in any frame, and the
   shared observer returns `status='verified'`, `irq_consumption='verified'`,
   the full value join (`delivery_read_value==OBI_rdata==retirement_mem_value==RAM_write_value`
   for full-field CPUs), the MRET word and successor, unknown internal
   version/origin, zero refusals and zero grants.

`--mode both` then requires semantic equality of the two case documents,
per-component distinct `pid` and `execution_nonce`, and every process reaped
with `exit_code == 0`. Evidence written per case: `config.json`,
`admission.json`, `program.json`, `<component>-artifact.json`, `original/` and
`fresh/` (`events.json`, `local_commands.json`, `executions.json`,
`observation.json`, `case.json`), and `summary.json` with an explicit `scope`
(including `excludes=[F5-pin-grammar, F6-storage-version, ISR-MMIO-authority,
internal-IP-cause, internal-IP-version, case-origin,
cross-case-writer-attribution, reward]`) and `grants_F5=false`,
`grants_F6=false`, `reward_eligible=false`, `grants_prerequisites=false`.

## Tests (pure, no DUT)

```
PYTHONPATH=src:. python3 -m pytest tests/integration/test_irq_group_script.py -q
# 52 passed in 0.4s

PYTHONPATH=src:. python3 -m pytest \
  tests/integration/test_irq_group_script.py \
  tests/integration/test_declared_irq_f5_script.py \
  tests/integration/test_declared_irq_f5_consumption.py \
  tests/integration/test_declared_irq_f5_firmware.py \
  tests/integration/test_directed_irq_matrix.py \
  tests/integration/test_directed_irq_matrix_config.py \
  tests/scenario/test_irq_delivery_group.py \
  tests/local_harness/test_declared_irq_output.py -q
# 195 passed, 1 skipped in 19.7s
```

The joint journal in the test is fed to the **real**
`observe_declared_irq_consumption`, so the ambiguous document and the exact
refusal are the production ones. The unique-path test uses a synthetic
observation document shaped exactly like the real verified F5 document (the
full consumption journal lives in `test_declared_irq_f5_consumption.py`); the
tests that matter for the two matrix cases are:

* `test_joint_journal_derives_joint_and_the_shared_observer_refuses`
* `test_joint_frame_is_never_accepted_as_unique`
* `test_joint_case_needs_two_members_active_in_the_take_frame`
* `test_joint_frame_without_a_take_refuses` / `test_two_takes_refuse`
* `test_frame_with_a_foreign_member_refuses`
* `test_member_raw_bit_must_match_the_frame_value`
* `test_member_pulse_must_follow_its_own_trigger_write`
* `test_trigger_sequence_must_be_the_declared_plan`
* `test_unique_case_requires_exactly_one_active_member`
* `test_unique_case_refuses_an_other_member_active_anywhere_else`
* `test_unique_observation_must_be_the_verified_chain`
* `test_summary_never_grants_f5_f6_or_reward`
* `test_joint_program_gates_mie_around_both_ordered_stores`

## Configs

All three declare the same two real members (same ids, ports, bit offsets,
bases and trigger values); only the host pulse stretch and the trigger plan
differ. `wb_timer` at `0x40001000` (ZipTimer, Wishbone, window 4, `o_int`),
`spi` at `0x40002000` (PULP SPI, APB3, window 4096, `events_o`), both
`declared-output.v1`, `source_bit_offset=0`; plan values are the F5 working
values `(wb_timer, 0, 8)` and `(spi, 36, 0x80000000)`.

| config | expectation | gate | observed | widths | plan |
|---|---|---|---|---|---|
| `joint-two-targets-ibex.json` | joint | on | `wb_timer` (`COUNT` 0x0) | 22 / 22 | timer then SPI |
| `unique-wb-timer-ibex.json` | unique | off | `wb_timer` (`COUNT` 0x0) | 16 / 16 | timer only |
| `unique-apb-spi-ibex.json` | unique | off | `spi` (`INTSTA` 0x28) | 16 / 16 | SPI only |

## `directed-irq-matrix.json` entries the lead should use

Do **not** edit the matrix here; replace the two existing case objects with the
following (they use only evidence layers already declared in the matrix and a
`runner` file the preflight accepts).

```json
{
  "id": "two-source-ambiguous",
  "kind": "multi-source",
  "description": "two simultaneously active members of one real host OR group are ambiguous at the single native take: joint attribution with both real native pulses, no unique source id and no source credit",
  "software_gate": "tests/integration/test_irq_group_script.py",
  "runner": "scripts/run_irq_group_native.py",
  "real_config": "configs/scenarios/directed-irq-group/joint-two-targets-ibex.json",
  "declared_scenario": "configs/scenarios/declared-irq-f5-wb-timer",
  "secondary_scenario": "configs/scenarios/declared-irq-f5-apb-spi",
  "profiles": [
    "configs/cpus/ibex_rvfi_local/component_profile.json"
  ],
  "native_ready": true,
  "required_evidence_layers": [
    "declared_output_mapping",
    "irq_group_joint_attribution",
    "cpu_native_take",
    "unknown_origin_no_credit"
  ],
  "measurable_layers": [
    "declared_output_mapping",
    "irq_group_joint_attribution",
    "irq_group_unique_attribution",
    "cpu_native_sample",
    "cpu_native_take",
    "cpu_retirement_serial",
    "unknown_origin_no_credit",
    "no_delivery_frame_no_join",
    "overrun_or_cancelled_no_credit"
  ],
  "claimed_layers": [
    "declared_output_mapping",
    "irq_group_joint_attribution",
    "cpu_native_sample",
    "cpu_native_take",
    "cpu_retirement_serial",
    "unknown_origin_no_credit"
  ],
  "unavailable": [
    "native_joint_consumption_value_chain",
    "native_second_member_take_separation",
    "native_internal_ip_cause"
  ]
}
```

```json
{
  "id": "unique-two-source-each",
  "kind": "multi-source",
  "description": "each member of the real two-member group is uniquely attributable when it is the only active source, with the exact source id, its real native sample and the full verified consumption chain",
  "software_gate": "tests/integration/test_irq_group_script.py",
  "runner": "scripts/run_irq_group_native.py",
  "real_config": "configs/scenarios/directed-irq-group/unique-wb-timer-ibex.json",
  "secondary_real_config": "configs/scenarios/directed-irq-group/unique-apb-spi-ibex.json",
  "declared_scenario": "configs/scenarios/declared-irq-f5-wb-timer",
  "secondary_scenario": "configs/scenarios/declared-irq-f5-apb-spi",
  "profiles": [
    "configs/cpus/ibex_rvfi_local/component_profile.json"
  ],
  "native_ready": true,
  "required_evidence_layers": [
    "declared_output_mapping",
    "irq_group_unique_attribution",
    "cpu_native_take",
    "irq_serial_certificate"
  ],
  "measurable_layers": [
    "declared_output_mapping",
    "irq_group_unique_attribution",
    "cpu_native_sample",
    "cpu_native_take",
    "cpu_retirement_serial",
    "irq_serial_certificate"
  ],
  "claimed_layers": [
    "declared_output_mapping",
    "irq_group_unique_attribution",
    "cpu_native_sample",
    "cpu_native_take",
    "cpu_retirement_serial",
    "irq_serial_certificate"
  ],
  "unavailable": [
    "native_both_member_unique_runs_in_one_invocation"
  ]
}
```

`native_ready: true` is only honest once
`scripts/run_directed_irq_native.py` can delegate to this runner: its
`_run_delegate` already passes exactly `--native --config --output --cache
--max-steps` (the new CLI defaults `--mode both`), but `derive_evidence`
(`scripts/run_directed_irq_native.py:279-404`, `_group_from_config` at
`:249`) assumes the single-source smoke config shape (`active_id`/`idle_id`,
one unique attribution) and must gain a two-source/joint branch that reads
`<output>/summary.json` + `<output>/original/case.json`. Until then the two
entries should stay `native_ready: false` with a refusal pointing at that
follow-up, or the lead should treat the new runner's `summary.json`/`case.json`
as the case evidence directly.

## Native commands for the lead (frozen window, output dirs must not exist)

```sh
# joint: both members active at the one take -> ambiguous / unknown / exact refusal
PYTHONPATH=src:. python3 scripts/run_irq_group_native.py --native \
  --config configs/scenarios/directed-irq-group/joint-two-targets-ibex.json \
  --output runs/irq-group-native-20261030/joint-two-targets-ibex \
  --cache runs/config-driven-20261028/cache --max-steps 2000 --mode both

# unique: timer alone -> verified consumption chain
PYTHONPATH=src:. python3 scripts/run_irq_group_native.py --native \
  --config configs/scenarios/directed-irq-group/unique-wb-timer-ibex.json \
  --output runs/irq-group-native-20261030/unique-wb-timer-ibex \
  --cache runs/config-driven-20261028/cache --max-steps 2000 --mode both

# unique: SPI alone -> verified consumption chain (INTSTA re-arms; one take)
PYTHONPATH=src:. python3 scripts/run_irq_group_native.py --native \
  --config configs/scenarios/directed-irq-group/unique-apb-spi-ibex.json \
  --output runs/irq-group-native-20261030/unique-apb-spi-ibex \
  --cache runs/config-driven-20261028/cache --max-steps 2000 --mode both
```

Each prints one JSON line and writes `summary.json` with `status='verified'`
(joint: `attribution='joint'`, `observation.status='ambiguous'`; unique:
`attribution='unique'`, `observation.irq_consumption='verified'`,
`fresh_matches=true`).

## What remains

1. The three native runs above (only the lead's frozen window may execute them;
   this work ran no DUT and no Verilator build).
2. If a native run refuses: `original/failure.json` (if the derivation raised)
   and `original/events.json` are always written. `irq-group-attribution-mismatch`
   means the take frame was not joint (or not unique) — read
   `original/events.json` for the frame's `active_sources`/`cpu_tick` and the
   two `pulse_start` windows, then adjust only that config's
   `pulse_width_ticks` (see the bound derivation above); do not relax the
   refusal. `irq-group-one-actual-native-CPU-take` means a pulse survived
   `MRET` (width too large) or a second source rose; reduce the width.
3. `scripts/run_directed_irq_native.py` two-source derivation branch (see the
   matrix note) if the matrix is to drive these cases end-to-end.
4. The matrix file itself is untouched by this work (`git status` shows only
   the new script, config directory and test file).

## Limits of this case

The case proves attribution/transport (joint) and the declared-status
read/consume chain (unique) for two real declared outputs in one OR group. It
does not claim F5 pin grammar, F6 storage version, ISR-MMIO authority, an
IP-internal cause/version, case origin or cross-case writer attribution; all
four grant fields are false and each summary carries the explicit `scope`
document and `excludes` list.
