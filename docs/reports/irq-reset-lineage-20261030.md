# Directed IRQ reset case: a measured barrier between a native IRQ acceptance and its retirement

Date: 2026-10-30. Scope of this record: **software gates and a native runner that
has not been run here**. No RTL campaign, no DUT simulation, no Verilator build
and no `--native` invocation of any script was started for this document. The
only native evidence cited is read-only source (pinned RTL and pinned Python)
under this worktree. Nothing below is a native pass.

This closes the missing runner for the `reset-then-irq` case that
`configs/scenarios/directed-irq-matrix.json` currently refuses with
`native_ready=false` / `no-public-native-reset-case-runner`. That file was **not**
edited here: the exact entry the lead should use is in
[§4](#4-the-exact-matrix-entry-the-lead-should-use).

## 1. What was implemented

| File | Purpose |
|---|---|
| `scripts/run_irq_reset_native.py` | Directed native CLI: one CPU session + two declared-output target sessions, fixed program, real IRQ take, real handler retirement, real `ScenarioRunner.reset_all('warm_all')` barrier, bounded post-reset phase, epoch-qualified lineage reducer, explicit-scope summary |
| `configs/scenarios/directed-irq-reset/ibex-wb-timer.json` | CPU `configs/cpus/ibex_rvfi_local/component_profile.json`; target `configs/peripherals/zipcpu_timer_irq/request.json` through `declared-output.v1`, port `o_int`, bit 0, base `0x40001000` (`1073745920`), idle base `0x40002000`, trigger write `(0, 8)`, pulse width 32 ticks, `warm_all`, 1500 post-reset steps |
| `tests/integration/test_irq_reset_script.py` | 55 pure gates: config validation/refusals, fixed program layout, the lineage reducer over synthetic journals shaped exactly like the exported ones, delivery attribution, summary non-authority, process identities, CLI refusals. No native, no RTL, no build |
| `docs/reports/irq-reset-lineage-20261030.md` | this record |

### Construction (no new adapter, no per-CPU/IP code)

The runner copies the public pattern of `scripts/run_timer_irq_smoke.py`
byte-for-byte where it matters, and imports its factories instead of
re-implementing them:

* `source_options()` and `timer_program()` from `scripts.run_timer_irq_smoke` for
  the declared source wiring and the fixed ROM layout;
* `target_session()` from the same module and `declared_irq_target_session_type`
  for the declared-output target sessions;
* `myfuzz.scenario.ibex_pulp_dual_source._artifact` for the CPU artifact;
* `IrqDeliveryGroup` / `IrqDeliveryMember` for the OR group, `DataflowRouter` /
  `DeviceWindow` for the declared windows, `record_local_commands()` for the
  process/command receipts, and `runner.install_protocol_checker()` for the
  target's real WB raw fields.

Phase order inside one native session:

1. `runner.begin_test('irq-reset-lineage')`, then one step of each target — the
   real reset-idle samples before any CPU clock (same as the smoke).
2. Step `cpu`, then `router.ready_targets`, then both sources, until a real
   `cpu_external_irq_taken` appears **and** a `cpu_retire` at `program['handler']`
   exists after it. The first handler body retirement is the stop condition: the
   barrier therefore lands *inside a live handler*, never on an idle or parked
   CPU. The budget is `--max-steps` (default 1500, bounded 1..10000).
3. Record `epochs_before = {session: session.reset_epoch}` and
   `runner.command_epoch`, then call the real
   `runner.reset_all('warm_all')` (`src/myfuzz/scenario/runner.py:1396`). That is
   a real whole-scenario reset: every session's `reset_local()`
   (`src/myfuzz/local_harness/session.py:780`,
   `src/myfuzz/local_harness/cpu_session.py:271`) ends its actual RTL process,
   increments its epoch and relaunches it; memory follows the warm policy; the
   runner appends the `reset_barrier` event with memory generations, cancelled
   responses/targets and cancelled IRQ pulses, and advances `command_epoch`.
4. Record `epochs_after` and `command_epoch`, drain the barrier's own
   `cpu_reset` fact (see §5.1), take one fresh native sample of each source, then
   step a bounded post-reset budget (`post_reset_steps`, config, 1..10000).
5. Reduce the exported journal (`runner.events`, contiguous `event_id` 1..N) into
   the verified document, and write `config.json`, `program.json`,
   `cpu|wb_timer_active|wb_timer_idle-artifact.json`, `original/`
   (`events.json`, `executions.json`, `local_commands.json`, `result.json`,
   `failure.json` on failure) and/or `fresh/`, plus `summary.json`.

`--mode original|fresh|both` (default `both`) runs the whole thing once or twice
**in one invocation**. `both` additionally requires: identical semantic result
documents (`results['original'] == results['fresh']`, digest in
`summary.semantic_sha256`), two launches per component per invocation (pre-reset
and post-reset), every process `reaped` with `exit_code=0`, and distinct
`pid`/`execution_nonce` for every component across the two invocations.

### What the reducer derives

`summary.json` (and the embedded `result`) carries:

| Field | Meaning |
|---|---|
| `barrier` | `reset_barrier` event id, policy, `memory_generations`, cancelled responses/target requests/IRQ pulses (count too), cancelled dataflow targets, pending events before/after |
| `epochs` | per-session `before`/`after`, `command_epoch` before/after, `pre_reset_epoch`, `post_reset_epoch = old+1` |
| `pre_reset` | the one real take (`event_id`, `decision_serial`, `reset_epoch`, `take_key`, tick), decision tokens, retirement count, every trap-path retirement event id, the handler entry retirement, certificate count |
| `post_reset` | every post-reset take (`event_id`, `epoch`, `token`, `take_key`/`identity`, tick), **every** post-reset `cpu_retire` as a compact `[event_id, reset_epoch, retirement_serial, intr, pc_rdata]` row plus counts, linked take→retirement pairs and certificate count/epochs |
| `lineage` | `no_lineage_after_reset`, the exact join semantics, raw pre/post tokens, `raw_token_reuse_across_reset` (+ count) and `raw_token_reuse_is_not_lineage`, `cross_epoch_joins` |
| top level | `barrier_observed`, `epochs_advanced`, `no_lineage_after_reset`, `pre_reset_handler_retirements`, `post_reset_take_count`, `post_reset_serial_distinct`, `post_reset_fresh_take_observed`, `post_reset_fresh_retirement_observed`, `layers` for the matrix, `serial_certificates` |

`summary.json` additionally carries `scope`,
`grants_F5=false`, `grants_F6=false`, `reward_eligible=false`,
`native_authority=false`, `isr_mmio='unknown'`, `irq_consumption='unknown'`, the
`terminal_probe` marker (`terminal=true`, `normal_campaign_completion=false`),
`process_identity` (`all_reaped_exit_zero`), `required_layers` /
`measured_layers` and `limitations`.

### The lineage rule (the important part)

The passive Ibex sideband counter is cleared by the same reset:
`src/myfuzz/composition/rtl/ibex_irq_serial_sideband.sv:32` (`sequence_q <= '0`
on `!rst_ni`) and `:38` (increment only on an external decision). A real reset
also ends and relaunches the actual CPU process
(`src/myfuzz/local_harness/session.py:780` → `end_case()` → `begin_case()`), so
the post-reset take legitimately repeats the *numeric* token of the pre-reset
take (typically `1`). The epoch is what makes the evidence distinct — exactly
the rule the production consumer `IrqSerialCertificates` already implements
(`_reset_floor` at `src/myfuzz/scenario/irq_serial_certificates.py:286`,
`_epoch_fresh` at `:314`) and the rule the existing software gate
`tests/integration/test_directed_irq_matrix.py::test_post_reset_lineage_requires_a_fresh_epoch_and_take_identity`
already certifies.

The reducer therefore keys lineage on **(execution scope, reset_epoch,
component, token)** and additionally on the take/receipt identity:

* **not** lineage (verified, and reported as `raw_token_reuse_across_reset`):
  a post-reset retirement in the **new** epoch whose numeric token equals a
  pre-reset decision token;
* **lineage (refused)**: a post-reset retirement in the **old** epoch, a
  post-reset retirement that joins a pre-reset decision scope (same epoch *and*
  token, decision first), a post-reset retirement that re-uses a pre-reset
  receipt `(execution, sequence)` or a pre-reset decision event id, and a
  pre-reset decision stamped with the post-reset epoch;
* **refused**: a post-reset take whose epoch is not exactly `old+1`, whose epoch
  is not its `take_key[1]`, whose `take_key[0]` is not the accepting component,
  whose take identity/receipt repeats a pre-reset one, or whose
  `(epoch, token)` repeats a pre-reset decision scope;
* **refused**: a missing/duplicated `reset_barrier`, a policy other than
  `warm_all`, a barrier without memory generations, either epoch set not
  advancing (sessions and `command_epoch`), no pre-reset take, a pre-reset take
  without a real acceptance/token, no trap-path retirement before the barrier,
  a non-contiguous journal, a malformed post-reset take, and a journal the
  production serial consumer refuses. A missing pre-reset serial certificate is
  also refused: the barrier must interrupt a real decision→retirement join.

Every refusal is raised as `ResetLineageRefused(code, detail)`; `main()` writes
`summary.json` with `status='refused'`, the code and the stage, prints the same
JSON and exits **2**. A `verified` result is written only after all of the above
holds; there is no code path that writes `verified` with a false grant field.

## 2. Commands and results (exact)

All commands were run from the repository root with `PYTHONPATH=src:.` (this
repository has no `conftest.py`). No native flag was used anywhere.

```
PYTHONPATH=src:. python3 -m pytest tests/integration/test_irq_reset_script.py -q
# 55 passed in 0.37s
```

Per-file, the neighbours this runner reuses:

```
PYTHONPATH=src:. python3 -m pytest tests/integration/test_irq_reset_script.py \
  tests/integration/test_directed_irq_matrix.py \
  tests/integration/test_directed_irq_matrix_config.py \
  tests/integration/test_cv32e20_irq_smoke_script.py \
  tests/local_harness/test_timer_irq_smoke.py \
  tests/local_harness/test_wb_timer_irq_configuration.py \
  tests/scenario/test_irq_serial_certificates.py \
  tests/scenario/test_reset_policy.py \
  tests/scenario/test_irq_delivery.py \
  tests/scenario/test_irq_delivery_group.py -q
# 175 passed, 1 skipped in 19.97s
```

Individual counts: `test_irq_reset_script.py` 55 passed ·
`test_directed_irq_matrix.py` 19 passed / 1 skipped (the opt-in ~41 s compiled
preparation test) · `test_directed_irq_matrix_config.py` 14 passed ·
`test_cv32e20_irq_smoke_script.py` 4 passed ·
`test_timer_irq_smoke.py` 7 passed ·
`test_wb_timer_irq_configuration.py` 1 passed ·
`test_irq_serial_certificates.py` 35 passed · `test_reset_policy.py` 3 passed ·
`test_irq_delivery.py` 19 passed · `test_irq_delivery_group.py` 18 passed.

What the 55 gates cover:

* the declared config resolves to the exact wiring (profile, request,
  `declared-output.v1`, `o_int`, bit 0, `0x40001000`, trigger `(0, 8)`,
  `warm_all`, ≥16-tick pulse) and 18 refusal variants are refused by name;
* the fixed program keeps the main image, both vector stubs, the 7-word handler
  and the park loop disjoint, ends with the trigger write plus the park
  self-loop, and a 4-byte trigger window that does not fit is refused;
* the reducer **accepts** a fresh-epoch numeric token repeat (reporting
  `raw_token_reuse_count=1` and `cross_epoch_joins=[]`), **accepts** a distinct
  post-reset token, and refuses: old-epoch retirement after the barrier, a
  retirement joining the pre-reset serial, a retirement re-using a pre-reset
  receipt, a pre-reset decision stamped with the new epoch, a post-reset take
  re-using the pre-reset take/receipt identity, a take identity naming another
  epoch/component, a missing barrier, a wrong policy, three shapes of
  non-advancing epochs, a barrier without any trap-path retirement, a journal
  without a pre-reset take, a non-contiguous journal;
* delivery attribution is recomputed from the journal (unique source, group
  sha256, epoch, referenced native sample with the declared bit set) and refused
  for a joint/mismatched/missing frame or an unverified native source;
* the summary asserts `grants_F5=grants_F6=reward_eligible=false`,
  `irq_consumption='unknown'`, the `terminal_probe` marker, the layer set, and
  refuses a missing launch, a non-reaped/exit-1 process and a re-used
  pid/nonce;
* the CLI returns 2 and writes nothing for a bad config, an existing output and
  an unbounded step budget (no build, no process);
* a run that observed no post-reset take stays `verified` for the two layers it
  really closed (barrier + no lineage) but records
  `post_reset_fresh_take_observed=false` and an explicit limitation instead of
  silently passing the fresh-epoch take clause.

## 3. What the native run will prove (and only that)

With `--mode both`: one measured `warm_all` barrier in the middle of a taken
handler, four real native launches per component across the two invocations (all
reaped, exit 0, independent pids/nonces), zero post-reset retirements joining a
pre-reset decision scope, a post-reset take at `epoch = old+1` with a fresh take
identity, and one exact serial certificate per epoch. It does **not** prove ISR
effect, instruction/operand origin, a propagation chain, storage versions or
reward (`isr_mmio='unknown'`, `irq_consumption='unknown'`, all grants false).

## 4. The exact matrix entry the lead should use

`configs/scenarios/directed-irq-matrix.json` must not be edited by this task.
Replace the current `reset-then-irq` case object (its `native_ready` is `false`,
its refusal code `no-public-native-reset-case-runner`, and it also declares the
compiled `declared_scenario`/`secondary_scenario`/`profiles`/`unavailable`
fields) with exactly:

```json
{
  "id": "reset-then-irq",
  "kind": "reset",
  "description": "measured reset barrier invalidates serial lineage, pending take identities and installed GPIO/ISR register state; a post-reset observation in the old epoch is refused, a post-reset take carries the next epoch and a distinct take identity, and a repeated numeric token in the new epoch is not lineage",
  "software_gate": "tests/integration/test_irq_reset_script.py",
  "real_config": "configs/scenarios/directed-irq-reset/ibex-wb-timer.json",
  "runner": "scripts/run_irq_reset_native.py",
  "declared_scenario": "configs/scenarios/compiled-f1-f6-ibex-gpio-dma-shared",
  "secondary_scenario": "configs/scenarios/compiled-f1-f6-cv32e20-gpio-dma-shared",
  "profiles": [
    "configs/cpus/ibex_rvfi_local/component_profile.json",
    "configs/cpus/cv32e20/component_profile.json"
  ],
  "native_ready": true,
  "required_evidence_layers": [
    "reset_barrier",
    "no_lineage_after_reset",
    "post_reset_fresh_epoch"
  ],
  "measurable_layers": [
    "reset_barrier",
    "no_lineage_after_reset",
    "post_reset_fresh_epoch",
    "irq_serial_certificate"
  ],
  "claimed_layers": [
    "reset_barrier",
    "no_lineage_after_reset",
    "post_reset_fresh_epoch"
  ]
}
```

Notes for the lead:

* `native_refusal` and `unavailable` are dropped: the refusal they encode (no
  public reset-case runner) is what this task removes.
* `--preflight` accepts this entry: `native_ready` requires a `runner` file, a
  `real_config` string and `required_evidence_layers` inside
  `scripts/run_directed_irq_native.py::LAYERS` — all three hold.
* Run the case **directly**, not through
  `scripts/run_directed_irq_native.py --case reset-then-irq` (see §5.2).

Exact native commands (frozen window; the lead owns the cache path):

```bash
# full case: two independent native sessions in one invocation (recommended)
PYTHONPATH=src:. python3 scripts/run_irq_reset_native.py \
  --native \
  --config configs/scenarios/directed-irq-reset/ibex-wb-timer.json \
  --output runs/irq-reset/directed-irq-reset-ibex-wb-timer-20261030 \
  --cache runs/config-driven-20261028/cache \
  --max-steps 1500 --mode both

# one session only (either half), same config and output layout
PYTHONPATH=src:. python3 scripts/run_irq_reset_native.py \
  --native --mode original \
  --config configs/scenarios/directed-irq-reset/ibex-wb-timer.json \
  --output runs/irq-reset/directed-irq-reset-original-20261030 \
  --cache runs/config-driven-20261028/cache

# declaration preflight only (starts nothing), with the matrix entry from above
PYTHONPATH=src:. python3 scripts/run_directed_irq_native.py \
  --config configs/scenarios/directed-irq-matrix.json \
  --case reset-then-irq --output <dir>/preflight --native --preflight
```

A pass is `status=verified`, `fresh_matches=true`, `no_lineage_after_reset=true`,
`epochs_advanced=true`, `post_reset_serial_distinct=true`,
`process_identity.all_reaped_exit_zero=true` and `layers` containing all three
required layers. The strong form of `post_reset_fresh_epoch` additionally needs
`post_reset_take_count >= 1`: a run whose bounded post-reset phase produced no
take is still `verified` (that is not one of the declared refusal conditions)
but the summary then carries `post_reset_fresh_take_observed=false` and an
explicit limitation saying the fresh-epoch *take* clause is untested — raise
`post_reset_steps` (config) or `--max-steps` and re-run. Anything refused exits
non-zero with `summary.json.status='refused'` and `summary.refusal.code` naming
the exact condition.

Practical expectations for the lead's read of the journal (all real, none
synthetic): the CPU session emits one `cpu_external_irq_sample` per CPU step, so
the journal holds one sample per step and only the take step's sample carries a
nonzero decision token; with the 32-tick OR pulse the input can still be
asserted after `mret`, so the post-reset phase may record **several** takes in
the same new epoch — each with its own increasing token, all of them
`post_reset_take_count` — while the pre-reset phase stops at the first handler
body retirement and therefore records exactly one pre-reset take. `result.json`
carries every post-reset retirement compactly (about 1500 rows for the default
budget), so `summary.json` is a few hundred KB.

## 5. Blockers, limitations and what remains

### 5.1 One private drain, with the exact reason (no core edit)

`ScenarioRunner._execute_step` sets the installed IRQ-group frame
(`runner.py:1815`, `state.begin_step`) *before* it drains the stepped session's
buffered facts (`runner.py:2866`, called from the step body) and closes the frame
(`runner.py:1930`, `state.finish_step`). The barrier's own `cpu_reset` fact is
buffered by `reset_local()` and would be drained inside the next CPU step, where
`_consume_dependency_event` (`runner.py:679`) treats `cpu_reset` as a reset and
clears the live frame — `finish_step` would then raise
`IRQ group parsed CPU input receipt missing`.

`scripts/run_irq_reset_native.py::flush_component_facts` therefore drains that
one fact immediately after the barrier with the runner's own private
`_append_external_events(component, runner.event_count)` (the same method
`reset_all` uses for the GPIO/UART consumption trackers). The journal keeps the
`cpu_reset` fact and its epoch; no core file was edited. A public
`drain_component_facts(component)` on `ScenarioRunner` (or draining the reset
facts inside `reset_all` unconditionally) would remove the private call — that is
an owner decision, recorded here rather than made in `runner.py`.

### 5.2 The matrix delegate cannot derive this case

`scripts/run_directed_irq_native.py::derive_evidence` is written for the
single-take transport cases: it refuses a journal with more than one
`cpu_external_irq_taken` (`run_directed_irq_native.py:269`) and a journal with
more than one exact serial certificate (`:314`). This case deliberately carries a
pre-reset **and** a post-reset take plus two certificates, so routing it through
`--case reset-then-irq` would end in
`refusal.code='evidence-derivation-failed'` even after a clean native run. That
is why §4 runs the dedicated runner directly and cites its `summary.json`.
Extending `derive_evidence` with a reset branch (or adding the reset layers to
that file) is the one remaining integration step and is outside this task's file
list.

### 5.3 What remains

1. The native run itself, by the lead, in the frozen window (§4). Nothing here
   may be reported as a native pass.
2. Optional strengthening: install `runner.install_native_reset_evidence()` so
   the barrier also carries the first-class `NativeResetEvidence` lifecycle
   document. It is not installed today (its target/instance configuration would
   have to be declared per session); the barrier's own event, the session epoch
   advance and the per-component relaunch receipts already carry the barriered
   evidence this case needs.
3. Optional: replace §5.1's private drain with a public runner hook, and add the
   reset derivation to `scripts/run_directed_irq_native.py` so the matrix case
   can also be delegated.

### 5.4 Limitations of the claim

* One directed case, one CPU adapter (`ibex_rvfi_local`), one declared-output
  target (`zipcpu_timer_irq.o_int`). It is not a statement about other CPUs or
  other targets.
* Lineage is the exact decision→retirement serial hop only; the case asserts
  nothing about ISR effect, IMMIO access, instruction or operand origin.
* `reset-then-irq` still needs its matrix edit (§4) applied by whoever owns
  `configs/scenarios/directed-irq-matrix.json`.
