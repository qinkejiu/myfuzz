# Reset recovery: re-installing provider/authority/source bindings for the new reset epoch

Date: 2026-10-30. Scope of this record: **software gates and a native runner that has
not been run here**. No RTL campaign, no DUT simulation, no Verilator build and no
`--native` invocation of any script was started for this document. The only native
artefacts cited are read-only recordings under `research/` plus pinned source. Nothing
below is a native pass.

## 0. Status matrix (TL;DR)

| Capability | Implemented | Software-tested | Native-verified |
|---|---|---|---|
| Declared, epoch-scoped reset recovery (provider + authority + source bindings) | yes (`src/myfuzz/scenario/native_reset_recovery.py`) | yes, 26 tests | **no** |
| Post-reset re-install bound to the **new** epoch (epoch+1, fresh execution/pid, command epoch+1, warm/cold memory policy) | yes | yes, incl. a real `ScenarioRunner.reset_all` over real `PersistentMemory` | **no** |
| Old-epoch lineage/credit is refused after the barrier; an old authority token can never be re-stamped as new-epoch credit | yes | yes (negative tests, both directions) | **no** |
| A same numeric token in the new epoch is *not* lineage (reported as a raw cross-epoch reuse) | yes | yes | **no** |
| Typed refusal when a re-install is undeclared/impossible (`generic-evidence-missing` / `generic-binding-drift` / `generic-semantic-unsupported`, all from the closed `REFUSAL_CODES`) | yes | yes, codes asserted against `REFUSAL_CODES` | **no** |
| **Continuing slot execution** in the new epoch on the compiled shared-slot carrier | **no — architecturally blocked** (§4) | the runner reproduces the carrier's own typed refusal and writes `status=unavailable` (refusal/outcome gates in §3.1) | **no** (lead's run) |
| `cold_all` recovery (same rules, memory generation +1) | yes | yes | **no** (lead's run) |

The honest one-line answer: the *recovery* half exists and is software-proven; the
*continuation* half cannot exist on today's compiled shared-slot carrier, because that
program is a single-epoch fixed launch sequence (§4.1) *and* the carrier pins its
original launch identities (§4.2). This task therefore delivers the second branch of
its own instruction: a typed refusal, an explicit `unavailable` status, and an
executable native reproduction — not continuation.

## 1. What already existed, and what was actually missing

Already existed and was reused, not re-implemented:

* `ScenarioRunner.reset_all` (`src/myfuzz/scenario/runner.py:1396`) is a real measured
  reset: every session `reset_local()` ends and relaunches its RTL process, increments
  `reset_epoch`, the barrier event carries memory generations and cancellations, and
  `command_epoch` advances.
* `NativeResetEvidence._after_barrier` (`src/myfuzz/scenario/native_reset_evidence.py:439`)
  already validates a per-target epoch transition and re-binds domain intervals after a
  global barrier. **No change was needed there**, and none was made.
* The proven terminal reset probe on the compiled shared-slot session
  (`scripts/run_shared_consumption_diagnostic.py:145`, artefacts
  `research/input-strategy-audit-20261027/runs/shared-consumption-20261029/reset-ram-v2`
  and `reset-pin-v1`) really resets and really invalidates the old providers:

  ```json
  "after": {"RAM": {"status": "unknown",
                    "reason": "shared_RAM_unavailable:shared_RAM_live_process_required",
                    "reset_epoch": 0},
            "PIN": {"status": "unknown", "reason": "shared_pin_process_identity_changed"}},
  "epochs_before": {"cpu": 0, "dma": 0, "peripheral": 0},
  "epochs_after":  {"cpu": 1, "dma": 1, "peripheral": 1}
  ```

  Its own report says it does **not** prove "reset 后重新安装 provider 并继续 slot
  execution" (`docs/reports/shared-consumption-acceptance-20261029.md:35`), and the
  completion audit lists the same gap (`docs/reports/universal-system-completion-audit-20261028.md:11`).

Missing, and what this change adds:

1. one **declared** place that says, before the barrier, *which* provider, *which*
   authority and *which* source sessions must be re-established;
2. the real **re-install** of those bindings stamped with the new epoch, plus a
   per-binding record of whether it really happened (and the refusing party's own
   reason when it did not);
3. the **lineage fence** that refuses old-epoch credit and refuses to call a repeated
   numeric token in a new epoch "lineage";
4. one **continuation attempt** through the declared carrier, so the carrier's own
   answer is measured instead of assumed.

## 2. Code implemented (files this task owns)

| File | Purpose |
|---|---|
| `src/myfuzz/scenario/native_reset_recovery.py` (new) | `declare_reset_recovery` / `ResetRecovery`: declaration, measured-barrier validation, epoch-scoped re-install, lineage fence, one continuation attempt, exportable document |
| `scripts/run_reset_recovery_native.py` (new) | one-command native runner: reuses the descriptor, cache, directed plan and reset probe of `scripts/run_shared_consumption_diagnostic.py`, adds the declared recovery and the continuation attempt |
| `tests/scenario/test_native_reset_recovery.py` (new) | 26 gates for the recovery itself |
| `tests/integration/test_reset_recovery_script.py` (new) | 27 gates for the runner's outcome rule, artifacts, CLI refusals and the real carrier-blocker codes |
| `docs/reports/reset-recovery-20261030.md` (this file) | the record |

No file outside that list was edited. In particular `src/myfuzz/runtime/flows/shared_slots.py`,
`src/myfuzz/integration/compiled_f6.py`, `src/myfuzz/scenario/event_provenance.py`,
`src/myfuzz/integration/{shared_slot_consumers,shared_f6_slots,shared_irq_firmware,compiled_f6_consumer}.py`
and `src/myfuzz/runtime/{compiler,binding,registry}.py` are untouched (the diffs they
would need are stated in §4.4 but not applied).

### 2.1 `native_reset_recovery`: the rules it enforces

`ResetRecovery` is declared **before** the barrier against the live runner and captures,
per declared source session, the reset epoch, the live process object, the execution
nonce, and (once) the runner `command_epoch` and every memory generation.

`observe()` — called once, after `reset_all` returns — refuses (typed) unless:

| Check | Refusal pointer | Code |
|---|---|---|
| exactly one measured `reset_barrier` since the declaration | `/barrier` | `generic-evidence-missing` (none) / `generic-binding-drift` (several) |
| the measured policy == the declared policy | `/barrier/policy` | `generic-binding-drift` |
| the barrier carries memory generations | `/barrier/memory_generations` | `generic-binding-drift` |
| every source `reset_epoch == declared+1`, one common epoch | `/sources/<name>/reset_epoch`, `/sources` | `generic-binding-drift` |
| every declared process was really relaunched (not the same object, still live) | `/sources/<name>/process` | `generic-binding-drift` |
| every declared execution nonce is fresh | `/sources/<name>/execution` | `generic-binding-drift` |
| `command_epoch == declared+1` | `/command_epoch` | `generic-binding-drift` |
| memory generations follow the declared policy (`warm_all`: unchanged, `cold_all`: +1) | `/memory_generations/<id>` | `generic-binding-drift` |

then re-installs, each bound to the new epoch:

* **sources** — an epoch-scoped binding row per session (`reset_epoch`, `execution`,
  `pid`, `binding_sha256`);
* **providers** — one `current_state()` read per declared provider; `reinstalled` only
  when the provider reports a live status *stamped with the new epoch*, otherwise
  `unavailable` with the provider's own `reason` (this is exactly how the recorded
  native probe reports `shared_pin_process_identity_changed` and
  `shared_RAM_unavailable:shared_RAM_live_process_required`);
* **authority** — one real epoch-scoped `issue(register=…, reset_epoch=new)` +
  `consume(token)` round trip. `GpioRegisterVersionAuthority` keeps its live state keyed
  by `(process, reset_epoch)` (`src/myfuzz/scenario/gpio_register_version.py:141`), so it
  **cannot** issue for the new epoch until a new actual command refreshed that state; the
  recovery records that exact refusal (`register-version-current-state-unavailable`) and
  re-installs the authority only when a **declared re-arm command** was declared in
  advance and executed in the new epoch. No retry loop: one declared re-arm, one retry.

`credit(component, epoch, token, identity=…)` is the lineage fence:

* before the barrier it returns `lineage: true` and records the epoch-qualified scope and
  identity;
* after the barrier an old-epoch credit is refused (`generic-binding-drift`,
  `/credit/epoch`), and an identity a pre-reset observation already used is refused
  (`/credit/identity`) — that is lineage, not a new observation;
* the **same numeric token in the new epoch is accepted as a new scope** with
  `lineage: false` and `token_reuse_across_epoch: true`, recorded under
  `lineage.token_reuse_across_epoch`. It is never joined to the old epoch, exactly the
  rule `IrqSerialCertificates` applies (`src/myfuzz/scenario/irq_serial_certificates.py`
  `_reset_floor` / `_epoch_fresh`).

A captured pre-reset authority token is the negative control: it must be refused, or be
consumable **only while it still carries its old epoch** (recorded as
`authority_token_stale_epoch`). The one thing refused outright is an old token silently
**re-stamped with the new epoch** (`generic-binding-drift`, `/authority/token`).

`continue_slot(record, flow=…)` asks the declared carrier **once**. Its refusal is a typed
refusal (`generic-semantic-unsupported`) plus the explicit `unavailable` status carrying
the carrier's own code; its success is `verified` only when the returned document passes
*and* the carried epoch equals the new epoch. There is no path that reports continuation
for a refused or non-passing carrier answer.

Every document carries `grants_storage`, `grants_version_dependency`, `grants_functional`
and `grants_reward` all `false`.

### 2.2 `scripts/run_reset_recovery_native.py`

Reuses (imports, does not copy): `load_descriptor`/`run_descriptor`, the
`DirectedConsumptionSelector` and its directed `reset-ram`/`reset-pin` plans, the real
`reset_all` probe (including its "old writer/consumption invalidated" checks and
`ResetProbeComplete`), and the same descriptor
`configs/scenarios/compiled-f1-f6-ibex-gpio-dma-shared/generic_scenario.json` and cache
`runs/config-driven-20261028/cache`.

Phase order inside one native invocation:

1. `run_descriptor` builds the compiled shared-slot runtime from the descriptor and
   begins it (one CPU + one DMA + one GPIO process pair, as in every shared-slot run);
2. at the **first** case the selector declares the recovery (the runner is `running`
   only after `begin()`), naming every persistent session as a source, the two installed
   consumption providers (`RAM`, `PIN`), the live `companion_authorities[pin.component]`
   and the runtime itself as the continuation carrier;
3. the directed plan runs to its last case; immediately before the barrier one real
   authority token is captured (the negative control) and the inherited probe performs
   `runner.reset_all(policy)`;
4. after the barrier the recovery observes it and re-installs (step 3 of §2.1);
5. exactly one continuation is attempted with the canonical eight-byte F6 record
   `0110c00008000000` (the same record the shared-slot tests and the consumption catalog
   use for this descriptor), and the carrier's own answer is recorded;
6. artifacts are written and the process exits with the outcome code of §5.

Artifacts under the given output directory: `recovery.json` (the re-install document),
`slot_continuation.json`, `result.json` (everything, incl. the recovered epoch, barrier,
providers, authority, lineage and the invalidation report of the probe), `summary.json`
(the graded summary, non-authority fields all false, terminal probe marker), and the
`original/` tree `run_shared_slot_descriptor` always writes (including its expected
`failure.json` whose error type is `ResetProbeComplete`, as in the recorded probes).

## 3. Software tests (exact commands, counts, exit codes)

All commands run from the repository root with `PYTHONPATH=src:.`. No native flag was used
anywhere, no Verilator build was started by any command below that reports `passed`.

### 3.1 The new capability

```
PYTHONPATH=src:. python3 -m pytest tests/scenario/test_native_reset_recovery.py \
  tests/integration/test_reset_recovery_script.py -q
# 53 passed in 0.42s          exit 0
```

Per file: `test_native_reset_recovery.py` **26 passed** ·
`test_reset_recovery_script.py` **27 passed**.

What the 26 recovery gates prove:

* **(a) re-install bound to the new epoch** — a real `ScenarioRunner` over a real
  `PersistentMemory`, a real `reset_all('warm_all')`, a real barrier event: the document
  reports `status=reinstalled`, `epoch={before:{…0}, after:1, advanced:true}`,
  `command_epoch 0→1`, every source at `reset_epoch=1` with a new pid/execution and a
  64-hex `binding_sha256`, the provider stamped `1`, the authority re-issued and consumed
  at `1` (with a declared re-arm), and the captured pre-reset token dead. A `cold_all`
  variant proves the `+1` memory generation rule.
* **(b) pre-reset lineage/credit cannot be reused** — an old-epoch credit after the
  barrier is refused (`generic-binding-drift`), a pre-reset identity in the new epoch is
  refused, and an authority that *re-stamps* an old token with the new epoch is refused.
* **(c) same token, new epoch ≠ lineage** — `credit(component,1,token=1)` after a
  pre-barrier `token=1` returns `lineage:false, token_reuse_across_epoch:true` and the
  document records the raw reuse while `pre_reset_tokens` keeps the old scope; a distinct
  new-epoch token is also `lineage:false`; an opaque token stays out of the document.
* **(d) the refusal path** — undeclared sources/authority/provider, a provider without
  `current_state()`, a carrier without `submit()`, continuation without a declared
  carrier, no measured barrier, two barriers, a wrong policy, and a warm barrier under a
  cold declaration are each refused with the exact code and JSON pointer; a carrier
  refusal becomes `generic-semantic-unsupported` **and** the explicit `unavailable`
  status with the carrier's code; a non-passing carrier document is never a continuation.

What the 27 runner gates prove: the outcome rule (declared blocker → `unavailable`,
undeclared carrier code → `mismatch`, verified continuation only with a reinstalled
binding and the new epoch), the summary's non-authority/terminal-probe fields, the CLI
refusals (existing output writes nothing, missing descriptor, unbounded rounds, required
`--native`), the declared blocker codes still being the real carrier codes **pinned
against the carrier sources**, the selector's declaration/`_recover_after_barrier`
end-to-end with the native processes replaced by declared doubles (artifacts written,
`status=unavailable`, all four layers), and a typed recovery refusal being written with
its own code.

### 3.2 The existing reset-related suites (unchanged, re-run)

```
# the ten-file suite the reset-lineage record itself cites
PYTHONPATH=src:. python3 -m pytest tests/integration/test_irq_reset_script.py \
  tests/integration/test_directed_irq_matrix.py \
  tests/integration/test_directed_irq_matrix_config.py \
  tests/integration/test_cv32e20_irq_smoke_script.py \
  tests/local_harness/test_timer_irq_smoke.py \
  tests/local_harness/test_wb_timer_irq_configuration.py \
  tests/scenario/test_irq_serial_certificates.py \
  tests/scenario/test_reset_policy.py tests/scenario/test_irq_delivery.py \
  tests/scenario/test_irq_delivery_group.py -q
# 175 passed, 1 skipped in 19.48s        exit 0
```
Identical to the count recorded in `docs/reports/irq-reset-lineage-20261030.md:160`
(175 passed, 1 skipped), so nothing regressed.

```
PYTHONPATH=src:. python3 -m pytest tests/scenario/test_native_reset_evidence.py -q
# 95 passed in 39.35s                   exit 0

PYTHONPATH=src:. python3 -m pytest tests/scenario/test_online_reset_replay.py \
  tests/scenario/test_reset_quiesce_lifecycle.py tests/scenario/test_gpio_reset_review.py \
  tests/scenario/test_register_reset_resume.py \
  tests/search/test_shared_consumption_diagnostic.py tests/search/test_shared_slot_ram.py \
  tests/search/test_shared_slot_pin_read.py -q
# 48 passed in 183.66s                  exit 0

PYTHONPATH=src:. python3 -m pytest tests/search/test_shared_consumption_diagnostic.py \
  tests/search/test_shared_slot_ram.py tests/search/test_shared_slot_pin_read.py \
  tests/integration/test_shared_f6_slots.py -q
# 36 passed in 85.76s                   exit 0
```
(the last two commands share the three `tests/search` files; the counts are per command,
not additive).

Two failures were observed that this task did **not** cause; see §6. They are stated here
so nobody attributes them to this change:

```
PYTHONPATH=src:. python3 -m pytest tests/integration/test_shared_slot_pin_provider.py -q
# 1 failed in 12.17s                    exit 1   (build admission, concurrent GPIO edit)

PYTHONPATH=src:. python3 -m pytest tests/scenario/test_register_reset_default_session.py \
  tests/scenario/test_register_reset_resume_terminal.py \
  tests/search/test_shared_consumption_diagnostic.py tests/scenario/test_online_reset_replay.py \
  tests/scenario/test_reset_quiesce_lifecycle.py tests/scenario/test_gpio_reset_review.py \
  tests/scenario/test_register_reset_resume.py tests/search/test_shared_slot_ram.py \
  tests/search/test_shared_slot_pin_read.py -q
# 20 failed, 57 passed in 550.45s       exit 1   (probe-digest drift, §6)
```

## 4. What blocks continuation (proof), and the exact diffs it needs

The refusal reproduction is honest: the runner's `status` is `unavailable`, the failing
code is the carrier's own, and no credit, version or reward is claimed. Three independent
layers block "continue slot execution in the new epoch" today.

### 4.1 The compiled program is a single-epoch fixed launch sequence

`src/myfuzz/integration/compiled_f6_firmware.py` builds the boot firmware and appends
`boot += [_jal(p['slot_base'] - …)]` (line 194): **boot always enters `slot_base`**. Each
slot island sits at `slot_base + i*256 + 128` and its `jal` goes to
`slot_base + (i+1)*256`, the last to `park_address` (lines 219–225). The slot a case may
execute is a *static* address, `slot_base + 256*slot_index`
(`src/myfuzz/integration/shared_f6_slots.py:375`, and `:201` for the typed mapping), and the ledger pins the session case
order (`reserve_case`, `:145`).

After `reset_local()` (`src/myfuzz/local_harness/session.py:780`) the CPU process is
relaunched and re-runs the same ROM, so it re-enters at `slot_base` — i.e. at slot 0,
which the pre-reset epoch already used. A continuation at `slot_index >= 1` therefore has
**no legal physical address** in the already-rendered program: the generated image for
that epoch does not contain a resume entry. This is not an identity-pin issue; it needs a
per-epoch rendered program.

### 4.2 The carrier pins its original launch identity (the codes the runner declares)

`CompiledF6Runtime._begin_once` captures nine launch pins
(`src/myfuzz/integration/compiled_f6.py:1785–1794`, incl.
`self._f6_original_cpu_reset_epoch`, `_f6_original_cpu_execution`,
`_f6_original_cpu_process`, `self._process_identities`). Every `submit` revalidates them
in `_verify_live_owner` (`:2122`), which calls
`_validated_build_process_identities` (`src/myfuzz/integration/compiled_process_audit.py:78`),
and that function admits **exactly one launch per session** (`len(launches) != 1`, `:83`).
`reset_local()` appends a second launch row
(`src/myfuzz/local_harness/session.py:586`), so the first refusal on a post-reset
`submit` is `compiled-F6-built-process-launch-missing`; the remaining identity refusals
(`-built-process-identity-changed`, `-built-process-identity-mismatch`,
`-built-receipt-identity-changed`, `-native-process-not-live`, `-runtime-not-live`) and
the slot ledger's one-shot CPU scope (`shared_f6_slots._state`:
`require(state['scope'] == scope, 'CPU-scope-drift')`, `:123`) follow in that order.
These eight codes are exactly the runner's `CARRIER_BLOCKERS`, and a test pins them
against the carrier sources so a future owner change cannot silently invalidate the
declaration.

### 4.3 The providers pin the original process too

`src/myfuzz/search/shared_slot_ram.py:74/76` refuses with
`shared_RAM_live_process_required` / `shared_RAM_process_changed`, and
`src/myfuzz/search/shared_slot_pin_read.py:103/105` with
`shared_pin_process_identity_changed` / `shared_pin_process_changed`, because both
installations captured the pre-reset processes (and the runtime's `_native_processes`).
Those are the two `reason` strings the recorded native probe already shows. A re-install
of these providers is only possible *after* the carrier re-binds the runtime's process
map (§4.2), so it inherits the same blocker.

### 4.4 The exact diffs needed (stated, deliberately **not** applied)

All four are in files another agent owns. They are listed so the owner can decide; none
of them is a change this task was allowed to make.

1. **`src/myfuzz/integration/compiled_f6.py`** — one new entry point, e.g.

   ```python
   def rebind_reset_epoch(self, *, reset_policy, barrier_event_id, expected_epoch):
       """Re-pin the one-epoch launch identity after ONE measured whole-scenario reset."""
       cpu, dma, runner = self.cpu, self.dma, self.runner
       barrier = runner._event_ref_by_id(barrier_event_id)
       if (self.finished or self._begin_state != 'begun'
               or barrier is None or barrier.get('kind') != 'reset_barrier'
               or barrier.get('policy') != reset_policy
               or cpu.reset_epoch != expected_epoch
               or dma.reset_epoch != expected_epoch
               or expected_epoch != self._f6_original_cpu_reset_epoch + 1
               or cpu._case_id != self._f6_original_cpu_case_id
               or cpu.process is self._f6_original_cpu_process
               or dma.process is self._f6_original_dma_process
               or cpu.process is None or cpu.process.poll() is not None
               or dma.process is None or dma.process.poll() is not None):
           raise ValueError('compiled-F6-reset-rebind-identity-mismatch')
       self._f6_original_cpu_process = cpu.process
       self._f6_original_dma_process = dma.process
       self._f6_original_cpu_process_id = cpu.process.pid
       self._f6_original_dma_process_id = dma.process.pid
       self._f6_original_cpu_execution = cpu._execution
       self._f6_original_dma_execution = dma._execution
       self._f6_original_cpu_reset_epoch = cpu.reset_epoch
       self._f6_original_dma_reset_epoch = dma.reset_epoch
       self._native_processes = {name: local.process
                                 for name, local in runner.sessions.items()}
       self._process_identities = self._validated_build_process_identities()
       self._f6_pending_fetch_sample = None
       self._f6_pending_fetch_sample_conflict = False
       self._bootstrap_to_first_slot(kind='resume')   # §4.1: needs a per-epoch entry
       return dict(reset_epoch=expected_epoch, barrier_event_id=barrier_event_id)
   ```

2. **`src/myfuzz/integration/compiled_process_audit.py`** — after a declared rebind the
   single-launch rule must accept the *current* launch, e.g. keep a
   `self._process_launch_index` pin and use `row = launches[self._process_launch_index]`
   instead of `launches[0]`/`len(launches) != 1` (`:83–93`). Without this the first
   refusal (`-built-process-launch-missing`) is unavoidable.

3. **`src/myfuzz/integration/shared_f6_slots.py`** — one owner-issued scope reset, only
   callable from the rebind above:
   ```python
   def rebind_slot_scope(runtime):
       state = _state(runtime)
       state['scope'] = None          # next mutate re-pins the new (epoch, process)
   ```
   (the ledger's rows, `session_case_index` and `_material` seals then continue
   unchanged).

4. **A per-epoch program/entry offset** in the preparation/program contract
   (`scenario/f6_execution_contract.py`, `integration/compiled_f6_firmware.py`,
   `runtime/preparation.py`) so that after epoch `n` the CPU enters slot `k` (the first
   unused one) instead of `slot_base`. This is the layer that makes continuation
   *possible* rather than merely un-refused; it changes the execution binding and
   therefore the evidence identity of every post-reset case, so it is a design decision
   for the owners, not a rebind.

`GpioRegisterVersionAuthority` needs **no** change: its `issue(register=…, reset_epoch=new)`
already works once a real command in the new epoch refreshed its state — the recovery
proves that path with a declared re-arm (software), and the real class cannot be
constructed without a native GPIO session.

## 5. The exact native command (the lead's run)

One command, no other flags required (defaults are the required descriptor and cache):

```bash
cd /home/qinkejiu/myfuzz
PYTHONPATH=src:. python3 scripts/run_reset_recovery_native.py \
  --native \
  --output research/input-strategy-audit-20261027/runs/reset-recovery-20261030/warm-ram-v1
```

The output directory must not exist (the script refuses otherwise and writes nothing).
Defaults: `--scenario reset-ram`, `--reset-policy warm_all`, `--rounds 1024`,
`--descriptor configs/scenarios/compiled-f1-f6-ibex-gpio-dma-shared/generic_scenario.json`,
`--cache runs/config-driven-20261028/cache`, `--expect unavailable`.

Variants the lead may want (each needs its own fresh output directory):

```bash
# the other directed plan, and the cold policy (the open cold-reset gap)
... --scenario reset-pin --output …/reset-recovery-20261030/warm-pin-v1
... --scenario reset-ram --reset-policy cold_all --output …/cold-ram-v1
# the enablement test: run this after the §4.4 diffs land
... --expect verified --output …/continuation-v1
```

**Exit codes.** `0` — the measured outcome equals `--expect`: with the default this means
`status=unavailable` with a code from `CARRIER_BLOCKERS`; with `--expect verified` it means
one more slot case really executed in the new epoch. `2` — everything else: an unexpected
carrier code, a non-passing carrier document, a typed recovery refusal
(`generic-evidence-missing` / `generic-binding-drift`), a configuration/output refusal, or
a native execution failure. `summary.json.status` is `unavailable` / `verified` /
`refused` / `mismatch` accordingly; **only `verified` is a pass**, and `unavailable` is an
explicit non-pass that records the blocker.

**Expected runtime and memory (estimate, not measured by me).** Two directed cases on a
cached build: the recorded 8-case shared-consumption run took 186.6 s of execution
(`docs/reports/shared-consumption-acceptance-20261029.md`) ≈ 23 s/case, so the 2-case plan
plus the reset/recovery is ≈ 60–120 s of execution; cached preparation adds ≈ 20–60 s.
Budget **≈ 2–4 minutes wall** and **≈ 2–4 GB peak RSS** (3 native RTL processes: CPU, DMA,
GPIO, plus the Python host) on the 7.5 GB host. If the PULP GPIO profile edited
concurrently (§6) invalidates the cache, the preparation rebuilds the GPIO harness first —
budget one extra build (several minutes, ≈ 1–2 GB of build jobs, ≤4 jobs) before the run.

**A pass reads:** `summary.status=unavailable`, `summary.result.layers` =
`{reset_barrier: true, no_old_epoch_credit: true, slot_continuation: "unavailable"}`, one
`reset_barrier` with the declared policy, `epochs_advanced=true`, every source at
`reset_epoch=old+1` with a fresh pid/execution, `providers[].reason` =
`shared_RAM_unavailable:shared_RAM_live_process_required` /
`shared_pin_process_identity_changed`, `authority.status=unavailable` with
`register-version-current-state-unavailable`, and `slot_continuation.code` one of the
eight declared blockers (expected first: `compiled-F6-built-process-launch-missing`).
`recovery.lineage.pre_reset_authority_token` being *refused* or *stale with its old epoch*
is the negative control that no old-epoch credit survived.

If the carrier instead refuses with a code **outside** `CARRIER_BLOCKERS` — the plausible
candidates are `compiled-F6-execution-binding-owner-*` / `-drift`, which
`_verify_live_owner` checks before the launch pins — the runner reports `status=mismatch`,
writes that exact code into `summary.json` and exits **2**. That is deliberate: an
unexpected refusal must not be silently filed as "the documented blocker". Confirm the
cause first, then either fix it or extend `CARRIER_BLOCKERS` in the same commit that
documents why the code is an identity refusal.

## 6. Pre-existing worktree failures observed (not caused by this change)

Both failures come from one concurrent, in-flight edit of the PULP GPIO profile; the two
touched files are outside this task's ownership and are not imported by the new code.

1. `src/myfuzz/local_harness/pulp_gpio_probe_contract.py` is modified in the worktree
   (`git status --porcelain` shows ` M`), its only change being
   `_PROFILE_SHA256 = 'a9056592…'` (was `'ebda4798…'`), while
   `src/myfuzz/scenario/register_reset_default_verifier.py` still pins the old probe bytes
   (`_PROBE_SHA='52c5a3eb…'`, actual digest `413cdbad…`). Every
   `derive_inten_reset_rule` therefore raises `reset-rule-current-probe-decode-drift`,
   which explains the 20 failures of `test_register_reset_default_session.py` (19) and
   `test_register_reset_resume_terminal.py` (1) in §3.2. The fix belongs to the owner of
   that pair (re-pin `_PROBE_SHA` or revert the profile change).
2. `tests/integration/test_shared_slot_pin_provider.py` (untracked, another agent's) fails
   with `LocalHarnessBuildError: build-admission-failed:runtime-physical-facts-mismatch`
   from `local_harness/build.py:649 → runtime_renderer._admit`
   (`elaborate_profile(plan.profile) != plan.facts`). This is the known
   direct-vs-supervised elaboration admission mismatch already recorded in
   `docs/reports/shared-irq-bit-offset-20261030.md:299` and
   `docs/reports/retirement-only-isr-return-20261030.md:265`; it affects such
   untracked/new tests, not the descriptor execution path the native runner uses (which
   stays inside `elaboration_mode_scope`).

Neither failure involves `native_reset_recovery.py`, `run_reset_recovery_native.py` or
their tests: the only repository references to the new module are its own three files.

## 7. Limitations of the claim

* The recovery is software-proven, not native-proven. Nothing here may be reported as a
  native pass; the lead's run is §5.
* The authority/provider re-install half is exercised against doubles that keep the real
  rules (`current_state()` epoch stamps, `(process, reset_epoch)`-keyed issuance,
  consume-clears-on-identity-change); a test additionally checks the real
  `GpioRegisterVersionAuthority.issue/consume` signatures and the real provider handle
  shapes. Only the native run can confirm the real objects' exact `reason` strings.
* One descriptor, one CPU/DMA/GPIO triple, one directed plan per run. Not a statement
  about other CPUs, targets or flows.
* Continuation is **unavailable**, not just unverified (§4). The runner reproduces that
  refusal; it does not attempt a workaround, and it has no fallback plan.
* A same numeric token reused in the new epoch is reported (raw reuse) as *not lineage*;
  the case does not claim anything about the token's value or origin.
* No storage version, ISR/MMIO fact, F5/F6 authority or reward is granted by any document
  this code writes.
