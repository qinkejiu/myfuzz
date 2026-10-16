# C M1: exact measured command clock scope

2026-10-17. Follow-up to cadaa75 and independent review b48c199. Root agreed integer runtime counter consistency is required, distinct from trusted private-journal memory. No new eligibility, source scope, history healing, reset grant, F4/host integration or native execution.

## Fix

Captured scope is now `(actual_process, execution_nonce, target_epoch, tick_base)`. Code-owned `validate_storage_scope` requires identity of the captured process and exact current nonce/epoch/tick-base, last measured state.sequence equal current sequence, and **last measured state.tick equal target.local_ticks**. `_actual_begin`, `issue`, and `consume` all invoke this same helper inside their permanent `_revoke` failure paths. Completion also checks the four-element captured scope. Initial measured state remains limited to no prior scope, sequence0, and tick==tick_base; missing history cannot heal a prior scope. No state is inferred zero.

The helper/code reference is included in the independent session-pinned issuer constant table. Caller replacement cannot turn a pure helper result into native build eligibility or a token. Existing real build/producer/frame/canonical source guards remain. Only the issuer module, session constant pin, new controls and owned reports/receipts changed.

## Pure evidence

- `test_scope_guard_rejects_counter_or_process_drift_without_native_fixture` covers integer tick, tick-base, sequence, actual process identity, execution and epoch drift. `test_scope_guard_initial_state_does_not_heal_missing_history` covers first-state vs unknown/retired history.
- Intended RED before helper implementation: **7failed**, `scope-red.log`, actual exit1 in compressed `scope-red-process.json.gz`.
- Focused GREEN: **7passed,47deselected**, `scope-green.log`, actual exit0. These are isolated scope calculations, not a fake native-positive fixture.
- `test_all_live_scope_guards_poison_on_failure_source_control` checks exact production AST: each shared scope guard is inside a try whose exception handler revokes. This closes source wiring/permanent-revocation review without monkeypatching native eligibility or manufacturing a live token positive.
- Final exact nine selectors are in `scope-final-process-receipt.json.gz`; command is `MYFUZZ_PURE_RECEIPT=.superpowers/apb-storage-version/scope-final-process-receipt.json python3 .superpowers/apb-storage-version/run_saved_facts_controls.py <those selectors>`.
- **253passed,50explicit skips,28.65s; actual pytest.main/controller exit0, PID505219.**9032 actual subprocess argv saved: executable basenames only git/mechanical-apb-peer.py/wire-worker.py. Saved ABI/tool identity remain explicit software fixtures; no native eligibility substitution. Skips are native opt-in gates and timer-only controls on GPIO parameter variants, never passed native evidence.
- Six current source/test/control hashes in `scope-fix-source-freeze.json`. Original cadaa75 `source-freeze.json`,245/50 receipts and old review remain intact as historical evidence. `git diff --check` clean.

Actual native token issue/consume and sampled reset/alias chains remain unexecuted. This is source/software closure of M1, awaiting independent re-review.
