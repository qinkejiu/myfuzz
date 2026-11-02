# Post-reset slot continuation: per-epoch program entry, epoch-bound relaunch, native measurement

Date: 2026-10-30. This record covers three things and separates them on purpose:

1. **implemented** — a declared per-epoch program entry (firmware renderer), a
   relaunch acceptance bound to the measured reset epoch (compiled process audit),
   and the recovery/runner wiring that attempts the whole chain;
2. **software-tested** — 110 passed / 4 skipped in this task's own gates; 116 passed
   in the shared-slot/reset-evidence suites; 481 passed in one combined integration
   re-run whose 7 failures are another agent's concurrent edits, and the three
   F6-runtime ones pass on a stable tree (111 passed, §5);
3. **natively measured** — two real runs under `flock /tmp/myfuzz-native.lock`
   (warm and cold), authorised by the lead. Both refused with a **typed, measured**
   blocker. **No slot continuation was verified and this is not a pass.**

## 0. Status matrix (TL;DR)

| Capability | Implemented | Software-tested | Native-measured |
|---|---|---|---|
| Declared per-epoch program entry: same island layout, same slot payloads, boot `jal` re-targeted to the declared slot | yes (`src/myfuzz/integration/compiled_f6_firmware.py`) | yes, 29 gates | **yes** — epoch 1 rendered, `entry_address=70144` (`slot_base+256*2`), `image_changed=true`, manifest `6dd4188…→46cb2a2…` |
| Entry-offset rule as a declared policy (not a special case), with refusals | yes (`ENTRY_POLICY`, `declare_program_entry`, `render_epoch_program`) | yes | yes — the declared `policy`/`rule`/`slot` are in both native `result.json`s |
| Launch identity acceptance bound to the epoch, every refusal code kept | yes (`src/myfuzz/integration/compiled_process_audit.py`) | yes, 12 gates | **yes** — the post-reset relaunch was **accepted**: `relaunch.status=reinstalled`, `launch_index=1`, new pid + execution nonce for cpu/dma/peripheral |
| The first post-reset refusal moved past the launch pin | — | — | **yes**: `compiled-F6-built-process-launch-missing` → **`shared-F4-F6-CPU-scope-drift`** |
| Provider/authority re-install on the relaunched process | yes (recovery) | yes | **no** — the two providers still refuse with their *own* captured-process codes (`shared_RAM_unavailable:shared_RAM_process_changed`, `shared_pin_process_changed`); the authority needs a declared re-arm, which this runner does not declare |
| One slot execution completing with a passing result in the new epoch | **no** | proven only against a declared carrier double | **no** — refused `shared-F4-F6-CPU-scope-drift`; owner diff prepared (§4) |

The honest one-line answer: **the launch-identity half of the blocker is gone and
natively measured; the slot-ledger half is prepared as an exact diff for its owner;
the executable-image half is impossible without re-admitting the runtime path and is
stated as the remaining owner decision, not worked around.**

## 1. What was implemented (files this task owns)

| File | Change |
|---|---|
| `src/myfuzz/integration/compiled_f6_firmware.py` | declared per-epoch entry (`ENTRY_SCHEMA_VERSION`, `ENTRY_POLICY`, `declare_program_entry`, `_validated_entry`, `_entry_address`), `build_f6_firmware(contract, *, entry=None)`, `F6Firmware.entry` / `entry_document()`, `render_epoch_program()` |
| `src/myfuzz/integration/compiled_process_audit.py` | declared epoch-bound relaunch (`EPOCH_LAUNCH_SCHEMA`, `bind_reset_epoch_launch`, `_measured_reset_barrier`, `_accepted_launch`, `_validated_epoch_launch`), `_epoch_launch` initialised by `capture_build_construction` |
| `src/myfuzz/scenario/native_reset_recovery.py` | `program=` declaration / `declare_epoch_program()`, the `program` and `relaunch` re-install steps in `observe()`, both rows in every document, and the epoch entry named by a verified continuation |
| `scripts/run_reset_recovery_native.py` | declares the epoch program pre-barrier from the ledger's next slot, records `program`/`relaunch`/`program_declaration`, adds the `epoch_program_entry` + `relaunch_accepted` layers, requires the declared epoch entry for a `verified` outcome, declares the prepared patch's refusal code |
| `tests/integration/test_compiled_f6_epoch_entry.py` (new) | 29 gates |
| `tests/integration/test_compiled_epoch_launch_audit.py` (new) | 12 gates |
| `tests/integration/test_f6_reset_rebind_patch.py` (new) | 3 active + 4 skip-if-unapplied gates |
| `tests/scenario/test_reset_continuation_chain.py` (new) | 12 gates |
| `runs/reset-continuation-20261030/owner-reset-rebind.patch` + `README.md` | the prepared diff for the two owner files (§4) |
| `docs/reports/reset-continuation-20261030.md` (this file) | the record |

Nothing outside that list was edited: `compiled_f6.py`, `compiled_f6_consumer.py`,
`compiled_f4.py`, `runtime/flows/shared_slots.py`, `local_harness/*`,
`native_*_hops.py`, `shared_f6_slots.py`, `f6_execution_contract.py`,
`runtime/preparation.py` and `search/shared_slot_*.py` are untouched.

### 1.1 The entry rule, and why "resume at the declared next slot" is the correct semantics

The rule is one line and it is declared, not special-cased:

```
boot_jal_target = slot_base + slot_bytes*slot
```

* epoch 0 renders `slot = 0`, which is byte-identical to the pre-change image (same
  boot bytes, same `initial_segment_manifest`, same `manifest_sha256`, same
  `document()` — so every pinned first-epoch digest stays valid);
* epoch `n ≥ 1` renders the slot the caller declares, and the declared slot can never
  be 0 (`compiled-F6-firmware-entry-epoch-slot`), because slot 0's instruction window
  is already materialized with a pre-reset case payload and the session-case ledger is
  append-only: re-entering it is a **replay**, not continuation;
* `F6Firmware.entry_document()` states `policy`, `rule`, `reset_epoch`, `slot`,
  `slot_base`, `slot_bytes`, `entry_address` and `boot_address`, and `document()`
  gains exactly one key (`entry`) only when an entry was declared;
* `render_epoch_program(contract, reset_epoch=…, slot=…)` returns the rendering *and*
  its own re-derived `initial_image`/`initial_image_sha256` pin, and re-rendering the
  pinned contract reproduces the manifest — so the pin keeps refusing drift instead of
  refusing the epoch.

Rejected alternative, on the record: re-entering slot 0 after a `cold_all` reset would
in principle be addressable again (cold reset drops the materialized instruction bytes
and revives the reserved words), but the session-case ledger is append-only
(`reserve_case` requires `first_index == prior`), so the case would have to reuse slot
index 0 while the session already holds two cases — it is refused as
`shared-F4-F6-session-slot-order` and is not a continuation. The declared-next-slot
rule is therefore the only one that matches the measured session.

### 1.2 Launch acceptance bound to the epoch

`bind_reset_epoch_launch(runtime, *, reset_epoch, barrier_event_id, policy)`:

* authenticates the barrier **from the runner's own journal**
  (`_event_ref_by_id`: `kind == 'reset_barrier'`, `policy` equal, `event_id` equal);
* requires the runner and the sessions to be the same live owners
  (`_build_sessions` is exactly `runner.sessions`, object for object);
* requires **one launch per epoch**: `len(launches) == reset_epoch + 1`, the accepted
  row at index `reset_epoch`, its `execution_nonce` equal to the session's live
  execution and different from every earlier row's nonce (identity reuse is refused);
* requires every relaunched process to be live (`-native-process-not-live`);
* refuses a rebind that is not exactly `previous + 1`
  (`-built-process-identity-changed`);
* then re-pins the three documents the audit itself owns (`_native_processes`,
  `_process_identities`, `_epoch_launch`) and returns a detached document.

Still refused, with the **same codes as before**: an unbound relaunch
(`len(launches) != 1` → `-built-process-launch-missing`), a row that does not match the
receipt/process/execution (`-built-process-identity-mismatch`),
`-built-process-identity-changed`, `-built-receipt-identity-changed`,
`-native-process-not-live`, and the carrier's `-runtime-not-live`. There is no path in
which a launch row is accepted without a measured barrier.

## 2. The native gate: exact commands, outcomes, resources

Both runs were authorised by the lead (GO message), serialised under
`/tmp/myfuzz-native.lock`, and started only after the guard loop
`until ! pgrep -f "run_generic_scenario.py|bind_real_session.py|verilator|obj/harness"`
found no other native/build. No `.py` file under `src/myfuzz` was modified during
either run (`find src/myfuzz -name '*.py' -newer <marker>` empty), so the
source-closure digest that the F6 execution binding pins could not drift.

### 2.1 warm (`warm_all`) — the gate command

```bash
cd /home/qinkejiu/myfuzz
flock /tmp/myfuzz-native.lock -c 'PYTHONPATH=src:. python3 scripts/run_reset_recovery_native.py --native --expect verified \
  --output research/input-strategy-audit-20261027/runs/reset-continuation-20261030/warm-ram-v1'
```

* **exit code 2** (expected `verified`, measured `unavailable`), stdout:
  `{"code": "outcome-not-the-declared-expectation", "expected": "verified", "measured": "unavailable", ...}`
* **wall clock 74.05 s**, **peak RSS 469 816 kB (≈459 MiB)**, 81 s user CPU, 0 swaps.
* tree stable during the run: yes.

### 2.2 cold (`cold_all`)

```bash
flock /tmp/myfuzz-native.lock -c 'PYTHONPATH=src:. python3 scripts/run_reset_recovery_native.py --native --reset-policy cold_all --expect verified \
  --output research/input-strategy-audit-20261027/runs/reset-continuation-20261030/cold-ram-v1'
```

* **exit code 2**, same mismatch rule; **wall clock 68.83 s**, **peak RSS 472 604 kB**;
* tree stable during the run: yes.

### 2.3 What the two runs measured (verbatim values)

| Fact | warm | cold |
|---|---|---|
| `summary.status` / `result.status` | `mismatch` / `unavailable` | `mismatch` / `unavailable` |
| barrier `event_id` | 7576 | 7576 |
| barrier `policy` | `warm_all` | `cold_all` |
| barrier `memory_generations` | `{"shared_ram": 0}` | `{"shared_ram": 1}` |
| epochs before → after | `{cpu,dma,peripheral}=0` → `1` | same |
| `command_epoch` | 0 → 1 | 0 → 1 |
| sources re-installed | 3/3 at `reset_epoch=1`, new pid + execution, 64-hex `binding_sha256` | same |
| epoch program | `status=reinstalled`, `slot=2`, `entry_address=70144`, `image_changed=true`, manifest `6dd4188481772c28…` → `46cb2a2541284170…` | identical |
| relaunch | `status=reinstalled`, `launch_index=1`, barrier 7576, cpu pid 3198108 / nonce `bf3a9d58…`, dma pid 3198140 / nonce `d99394bb…`, peripheral pid 3198172 / nonce `1336dd72…` | same shape, cpu pid 3234519 / nonce `b6c27979…`, dma 3234557 / `9fda5bc4…`, peripheral 3234596 / `bcd69544…` |
| providers | `RAM unavailable shared_RAM_unavailable:shared_RAM_process_changed` (`provider_epoch=0`), `PIN unavailable shared_pin_process_changed` | identical |
| authority | `unavailable`, `reason=register-version-current-state-unavailable`, `rearm=undeclared`, `pre_reset_token_refused=true` | identical |
| lineage fence | `old_epoch_fenced=true`, pre-reset authority token refused | identical |
| **slot continuation** | **`unavailable`, `code=shared-F4-F6-CPU-scope-drift`**, `operation=submit:F6` | **same code** |
| typed refusal | `generic-semantic-unsupported` at `/slot_continuation`, `carrier_code=shared-F4-F6-CPU-scope-drift` | same |
| layers | `reset_barrier=true`, `recovery_reinstall=false`, `no_old_epoch_credit=true`, `epoch_program_entry=reinstalled`, `relaunch_accepted=reinstalled`, `slot_continuation=unavailable` | same |
| non-authority fields | `native_authority=false`, `grants_F5/F6/storage=false`, `reward_eligible=false`, terminal probe | same |

Artifacts: `result.json`, `recovery.json`, `slot_continuation.json`, `summary.json`,
`original/…` (including the expected `failure.json` whose error is `ResetProbeComplete`)
under each run directory, plus
`research/input-strategy-audit-20261027/runs/reset-continuation-20261030/native-gate.json`,
which collects both runs verbatim and states what moved and what still blocks.

### 2.4 What the measurement proves and what it does not

**Proves (measured, not assumed):**

* a real `reset_all` barrier on the persistent shared-slot session, epochs `0→1`,
  `command_epoch 0→1`, memory generation `+1` under `cold_all`;
* the post-reset relaunch **is accepted, bound to that barrier** — `launch_index=1`,
  new pid and execution nonce per session. The first post-reset refusal has therefore
  moved past `compiled-F6-built-process-launch-missing`, which is what the previous
  record declared as the blocker;
* a real per-epoch program **is rendered** for the declared next slot (2) with a
  different image and a re-derived pin, and the entry rule is stated in the document;
* the next blocker is now the **slot ledger's one-shot CPU scope**
  (`shared-F4-F6-CPU-scope-drift`), followed by the providers' own captured processes.

Note on the provider codes: the previous record (`reset-recovery-20261030.md` §1, §5)
predicted `shared_RAM_unavailable:shared_RAM_live_process_required` and
`shared_pin_process_identity_changed`. The measured codes are one step further on
(`…:shared_RAM_process_changed`, `shared_pin_process_changed`) because the runtime's
process map is now legitimately re-bound by the accepted relaunch, so the provider's
*live* check passes and the provider's own captured process is the refusing fact. Both
are the provider's own `current_state()` reason, recorded verbatim.

**Does not prove:**

* any slot execution: zero slot case ran in the new epoch;
* provider or authority re-install: both refuse, with their own codes;
* that applying the prepared owner patch is enough: it removes the scope and launch
  blockers and then refuses `compiled-F6-epoch-program-unbound` (§4.3).

## 3. Software tests (exact commands, counts, exit codes)

All commands run from the repository root with `PYTHONPATH=src:.`; none of them used
`--native` or started a build.

```
# this task's own gates
PYTHONPATH=src:. python3 -m pytest tests/integration/test_compiled_f6_epoch_entry.py \
  tests/integration/test_compiled_epoch_launch_audit.py \
  tests/integration/test_f6_reset_rebind_patch.py \
  tests/scenario/test_reset_continuation_chain.py -q
# 56 passed, 4 skipped in 0.57s            exit 0
#   (per file: 29 + 12 + 3(+4 skipped) + 12; the 4 skips are the
#    "owner patch not applied" gates of test_f6_reset_rebind_patch.py)

# the two updated gates from the previous record (26 + 27 → 54)
PYTHONPATH=src:. python3 -m pytest tests/scenario/test_native_reset_recovery.py \
  tests/integration/test_reset_recovery_script.py -q
# 54 passed in 0.58s                       exit 0
```

What the new gates prove:

* **entry rule** — the implicit first rendering is byte-identical to the declared
  `epoch 0 / slot 0` rendering (and `document()` gains no key); a later epoch's boot
  `jal` decodes to `slot_base + 256*slot` (decoded independently of the encoder) and
  the software RV32I model lands there; only the boot segment changes and every island,
  ISR byte and prefix stays identical; the island walk from that slot reaches the next
  slot and lands on the park fetch; a mismatched completion bit spins in place;
* **refusals** — epoch 0 with slot ≠ 0, a later epoch with slot 0, `slot == slot_count`,
  negative/bool/float slots, a slot count that disagrees with the contract, a drifted or
  extended entry document, a dict-subclass container;
* **epoch pin** — `render_epoch_program` re-derives the image pin, reproduces on
  re-render, refuses a hand-edited manifest and refuses a first-epoch pin carrying a
  later epoch's entry; the caller's contract is never mutated;
* **launch acceptance** — one launch is the only launch before a barrier; a relaunch
  cannot be bound without a measured barrier (missing id, wrong policy, `reset_epoch` 0
  or 2, a real event that is not the barrier); after a real `reset_all` the relaunch is
  admitted once with the new pid/nonce, and a third launch, a reused execution nonce, a
  repeated launch row, a changed receipt, a dead relaunched process, a foreign session
  map and a second barrier without its own binding are each refused with the original
  code;
* **the chain** — with a declared carrier double that refuses until the relaunch is
  bound, the full chain completes in software: `barrier → epoch+1 → entry at slot 2 →
  relaunch accepted → providers/authority re-installed → one passing slot document`,
  and `classify_outcome` returns `verified`; without the declared entry the same
  carrier answer is a `mismatch`; a next slot the epoch could not enter, a late
  declaration, a double declaration, a contract whose pin does not describe the
  program, and a relaunch the audit cannot authenticate are each refused/typed.

Re-run pre-existing suites (unchanged by this task):

```
PYTHONPATH=src:. python3 -m pytest tests/integration/test_shared_f6_slots.py \
  tests/integration/test_shared_f6_memory_slots.py \
  tests/search/test_shared_consumption_diagnostic.py \
  tests/scenario/test_native_reset_evidence.py -q
# 116 passed in 217.22s                   exit 0

PYTHONPATH=src:. python3 -m pytest tests/integration/test_compiled_f6_firmware.py \
  tests/integration/test_compiled_f6_epoch_entry.py tests/integration/test_compiled_f6_runtime.py \
  tests/integration/test_compiled_f6_build_join.py tests/integration/test_compiled_f4_build_join.py \
  tests/integration/test_compiled_f4_build_failure_audit.py tests/integration/test_compiled_f6_contract.py \
  tests/integration/test_compiled_f6_execution_binding.py tests/integration/test_compiled_f6_entry.py \
  tests/integration/test_verify_compiled_f6.py -q
# 7 failed, 481 passed in 1121.87s        exit 1   (7 failures = another agent's edits, §5)
```

## 4. The prepared owner diff

`runs/reset-continuation-20261030/owner-reset-rebind.patch` (two files, three hunks) and
`runs/reset-continuation-20261030/README.md` (per-hunk invariant + covering test).
`git apply --check` passes on the current tree (re-checked after the concurrent edit of
`compiled_f6.py`, which did not move these anchors); both patched files compile; and in a
**copy of the current tree** with the patch applied the four skip-if-unapplied gates
become active and the whole owned set passes:

```
git apply owner-reset-rebind.patch           # on a copy of src/
PYTHONPATH=<copy>/src:. python3 -m pytest tests/integration/test_f6_reset_rebind_patch.py \
  tests/integration/test_compiled_f6_epoch_entry.py \
  tests/integration/test_compiled_epoch_launch_audit.py \
  tests/scenario/test_reset_continuation_chain.py \
  tests/scenario/test_native_reset_recovery.py \
  tests/integration/test_reset_recovery_script.py -q
# 114 passed in 1.63s                        exit 0
```

It was **not** applied to this tree (the lead's instruction: another agent is still
editing `compiled_f6.py`).

| Hunk | File | What it does | Invariant | Covering test |
|---|---|---|---|---|
| 1 | `compiled_f6.py` | new `rebind_reset_epoch(reset_policy=…, barrier_event_id=…, expected_epoch=…, next_slot=…)` | one relaunch per measured barrier; `expected_epoch == old+1`; slot 0 refused; refuses `compiled-F6-epoch-program-unbound` instead of binding an image the admission did not admit; never rewrites `contract`/`program`/`execution_binding` | `test_f6_reset_rebind_patch.py::test_the_rebind_entry_point_declares_its_exact_arguments`, `…::test_the_rebind_refuses_a_slot_that_is_not_a_later_epoch_entry`, `test_compiled_epoch_launch_audit.py` (the binding it calls) |
| 2 | `compiled_f6.py` | `_bootstrap_to_first_slot(entry_address=None)` | the first epoch still waits at `slot_base`; a declared epoch waits at exactly the boot `jal` target | `test_f6_reset_rebind_patch.py::test_the_bootstrap_can_be_targeted_at_the_declared_entry`, `test_compiled_f6_epoch_entry.py` (decodes and executes the boot) |
| 3 | `shared_f6_slots.py` | new `rebind_slot_scope(runtime)` | ledger stays append-only; only `state['scope']` is released; only from `CompiledF6Runtime.rebind_reset_epoch` and only after a measured reset | `test_f6_reset_rebind_patch.py::test_the_one_shot_scope_release_is_refused_outside_the_declared_rebind`, `test_shared_f6_slots.py`/`test_shared_f6_memory_slots.py` (unchanged, 116 passed with suite 2) |

### 4.1 The blocker the patch deliberately leaves typed

The compiled contract pins its own image
(`f6_execution_contract.py` writes `initial_image`/`initial_image_sha256` from the
rendered firmware), the execution binding pins that contract
(`_program_document` requires equality, `compiled_build_join` re-derives the same
digest), and `runtime_path_admission` pins the contract digest. A later epoch's image
is therefore a different contract, and binding it means **re-admitting the runtime path
for the epoch contract** — a design decision with an evidence consequence (the
execution binding of every post-reset case changes). The patch refuses it explicitly as
`compiled-F6-epoch-program-unbound`, which is declared in the runner's
`CARRIER_BLOCKERS`, so `--expect unavailable` still classifies it as the documented
blocker and `--expect verified` still exits 2.

Also measured and recorded there: `ScenarioRunner.preload_image` refuses after the
start (`_status != 'created'`), `PersistentMemory.preload` refuses to overwrite, and
`PersistentMemory.cold_reset` re-applies only the *pre-reset* `_initial_images`, so the
relaunched CPU re-runs the pre-reset boot image byte for byte. Writing the boot word
through `PersistentMemory.write` would be the one way to change it without a re-preload
— and it must not be used: the CPU would execute an image the admitted pin does not
describe.

## 5. Failures observed that this task did not cause

* `tests/integration/test_compiled_f4_build_failure_audit.py` — 4 failed.
  `AttributeError: 'PinDriftReplay' object has no attribute '_mixed_flows'`
  (`compiled_f4.py:1601` reads `self._mixed_flows`, a field added at
  `compiled_f4.py:835`; the test fixtures do not set it). `compiled_f4.py` is owned by
  another agent and is being edited concurrently.
* `tests/integration/test_compiled_f6_runtime.py` — 3 failed with
  `compiled-F6-execution-binding-drift`. That check re-derives
  `executor_source_closure_sha256` over **every** `src/myfuzz/**/*.py`
  (`f6_execution_binding.py::_closure`), so any concurrent edit anywhere under `src`
  between binding construction and validation produces this refusal. Re-run on a
  stable tree: see §5.1.
* Known pre-existing failures listed in the task (`test_generic_wall_budget` 13,
  `test_registry` 3, `test_shared_f5_support_binding` 4, `register_reset_default_*` 20)
  were not run and not touched.

### 5.1 Re-run of the three `-binding-drift` tests on a stable tree

```
PYTHONPATH=src:. python3 -m pytest tests/integration/test_compiled_f6_runtime.py -q
# 111 passed in 660.59s                   exit 0
```

All three failures disappear when the same file is run with no concurrent edits, which
confirms the source-closure explanation: they are a property of running the suite while
another agent edits `src/`, not a regression of this task. The four
`test_compiled_f4_build_failure_audit.py` failures are the F4 owner's in-flight
`_mixed_flows` field and are outside this task's ownership.

## 6. Limitations

* Two runs, one descriptor, one CPU/DMA/GPIO triple, one directed plan per run
  (`reset-ram`), one measured reset each. Nothing here says anything about other CPUs,
  targets or flows.
* No slot execution happened after either reset. `verified` remains **unachieved**;
  the chain is software-proven only against a declared carrier double.
* The recovery/re-install half is native-measured only to the point of *refusal*: the
  providers and the authority refuse with their own codes, exactly as recorded.
* The prepared patch changes no evidence identity by itself (it refuses before binding
  a per-epoch image), but applying it and re-admitting the path **would** change the
  execution binding of every post-reset case — that is the owner decision.
* No storage version, ISR/MMIO fact, F5/F6 authority or reward is granted by any
  document this code writes.
