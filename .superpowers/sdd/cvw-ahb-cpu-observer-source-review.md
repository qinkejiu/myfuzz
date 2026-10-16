# CVW/AHB CPU observer independent source review

2026-10-17. Initial frozen implementation `8dd8ead`, all eight source SHA256 values independently matched `docs/reports/evidence/cvw-ahb-implementation-20261017/freeze.json`. Reviewed observer, AHB session, generic verified-edge hook, renderer, strict contracts, three focused test files and audit/design/implementation report. No remote action, build, elaboration, model, native constructor or describe was invoked by this review. The existing focused integration controls construct a Python session only with saved-port/frontend fixtures and a no-tool guard; they do not start a native child.

## Initial software receipts

Independent command:

```sh
PYTHONPATH=src:. PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q tests/scenario/test_ahb_cpu_events.py tests/local_harness/test_ahb_cpu_observer.py tests/local_harness/test_ahb_cpu_contract.py
```

Actual process exit0; **51 passed in1.30s**. These are software observations only, not fresh frontend/build or native results.

## Medium M1 — control-only events bypass the global event threshold (pending fix)

`AhbCpuObserver._emit` increments the global record counter without checking `max_events`. The threshold is checked only inside `observe`. Therefore a sequence of scope begin/end with no observed edge emits reset events beyond `max_events` without terminal poison. Independent minimal pure control with max_events1/max_scopes256 performed three begin/end_scope pairs: records3, terminalfalse. This is bounded by the separate scope limit, but contradicts the declared global event stopping threshold and cannot be explained by one offending raw edge plus diagnostic slack.

Owner confirmed the gap and is implementing a separate RED→GREEN scope/reset control, terminal event-budget enforcement and a new source freeze. This report does not approve the old bytes for native scheduling before that review.

## Other source checks

- `observer_record_index` is monotonic across the whole observer lifetime. Address/write-data/completion refs name that namespace rather than mutable list offsets. Runner copies/imports these rows once; EventJournal may clear the original list in place without resetting the counter. The focused actual Runner+EventJournal control preserves old-address/new-completion raw refs across drain. Separate observer objects have separate state and explicit component/endpoint/scope.
- Old data completion occurs before independent new address acceptance on the same pre edge. Write payload/strobes come from the following pre phase and remain linked to address/data/completion raw refs. Actual 34-bit addresses, HRESP/read data, strobes0, raw control fields and error observations remain intact. Post is not an extra acceptance. The observer does not claim burst/lock/size execution or full two-cycle ERROR conformance.
- Edge/raw-byte/scope counters persist across scopes; poison/exhaustion refuses subsequent steps and reset before any command. Reset emits cancellation with the old scope before transport reset. Diagnostic raw is retained for malformed/overflow edges; trusted_projection=false and possible_effects distinguish unknown effects. The first measured boundary explicitly emits prefix_unknown, so startup transfer loss cannot masquerade as an initially empty complete pipeline.
- The generic hook is default no-op and called after actual receipt status/tick/control/pre-backend binding and sample capture, before backend service effects. The AHB wrapper catches ordinary Exception around command, validation, observer, service and output, clears stale receipt state, saves the current diagnostic, aborts and permanently poisons before retry. Non-AHB classes retain the no-op behavior.
- The renderer change is one AHB-only helper/call exporting13 copies of actual `_shape` ABI links. The AST comparison removes exactly those additions and verifies every remaining renderer node equals the pinned original. HREADYEXT is the bound response input; the unrelated ordinary HREADY output is not substituted.
- Strict AHB-only contract reconstruction checks generated artifact/build JSON with bool/int distinction, exact service/component/memory identity, boot constraint, role/tap/source-wire binding, observer version/default limits and trace metadata. It adds no generic source/retirement authority allowlist. Caller reports and observation rows remain documentary rather than authority.
- Historical raw has only three ordinary physical bits and is explicitly rejected for missing13-role taps. It is not upgraded to new native event coverage. The implementation documents its partial measured prefix and requires a later bounded startup capture plus separately authorized frozen generated native/Runner/fresh gate.

Current initial verdict: M1 pending; no other high/medium source blocker identified in this review. Native/source/retirement acceptance remains unavailable irrespective of the software receipt.

## Final reviewed fix — da4605f

Owner added a pure scope-only RED reproducing the control-event bypass and changed `_emit` to enforce the same global event threshold for nonterminal records. `begin_scope` refuses at the threshold before a new scope can start. The first terminal failure diagnostic has explicit one-record slack; subsequent poison calls do not add diagnostics. Old pending scope is retained in the terminal diagnostic when cancellation cannot be recorded. This resolves M1 without renewing counters or removing raw history.

New observer SHA256 `61367415fc82b9d6eefeb478fcf7cd0add0d4029e997d6cd326197fc3d49f0ed`; observer test SHA256 `8a2694aa45b649f1b951d9611ed359f75795442db752669c0ddea9a5e2805b83`. Other six source hashes remain unchanged from initial review; all eight independently match the updated freeze.

The same focused command was independently rerun after this fix: **52 passed in1.30s**, pytest reported no failures, command exit0. Source hash verification also returned0. No build, elaboration, model, remote or new native occurred.

Final source verdict: **no remaining high/medium blocker** in this reviewed software increment. This does not approve a complete initial CPU protocol prefix: prefix_unknown remains intentional, startup capture is still required, and no native/source/retirement authority or whole-system acceptance is granted.
