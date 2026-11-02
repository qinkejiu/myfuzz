# F6 WBDMAC dual-endpoint protocol checker

Date: 2026-10-25

## Result

Implemented a software-level WBDMAC protocol-checker path for the compiled F6 runtime. This does not close F6 acceptance: no complete real native original/fresh success or expected-error archive was generated and independently raw-audited in this slice. Freeze15 native-controls remains `4 passed / 5 failed, FAIL_PRESERVE`; no Freeze16 was created.

## Contract and implementation

- The generated `wishbone_dma` artifact declares two trace endpoints from the admitted profile and backend mapping: `dma.control` and `dma.memory`.
- WBDMAC has no `SEL` pin. The trace records an explicit no-SEL/full-word contract; memory master byte enable 15 is sourced from the admitted profile capability. No synthetic signal is introduced.
- Runner validates the artifact digest, source-verification identity, profile endpoint roles, clock/reset domains, signal direction/width, backend names, endpoint coverage, and byte-enable contract before installing the dual checker. The checker is installed before the session starts.
- `WishboneDmaProtocolChecker` maintains independent state per endpoint while consuming the same Runner PRE sample. Its report carries endpoint sample counts, raw sample IDs, findings, reset epochs, pending offer/outstanding state, and artifact/trace identity.
- `_assemble_f6_protocol_checker_case_report()` binds the checker delta to the case's admitted `_runner_event_start`, checks contiguous Runner event IDs, attaches each endpoint's complete PRE sample list, and joins every finding to exactly one Runner `protocol_violation` by endpoint, raw event ID, and code.
- The consumer rechecks the case/run/binding, artifact/profile/source/runtime/trace identities, cursor equality, sample IDs and reset epochs, violation rows, endpoint coverage, and pending state. Missing live reports on `CompiledF6Runtime` cannot use the synthetic fixture fallback. Impossible `report(since=...)` finding cursors are rejected.

## Review findings handled

Independent review found an unbound report event cursor and recommended guarding the production-runtime fallback and testing live report assembly. The consumer now requires exact equality with the attempt cursor. The synthetic report fixture calls the production report assembler and a real `WishboneDmaProtocolChecker`; positive and negative tests exercise the assembler-to-consumer path, violation joins, report suppression, and sample-ID tampering. The fallback regression invokes `capture_f6_case()` on a `CompiledF6Runtime` object with its Runner/report removed. A finding-cursor upper-bound check was added. Final read-only review found no Critical or Important findings; the suggested Minor test gap was closed with the consumer invocation.

## Verification

- Combined protocol checker, WBDMAC transport, F6 consumer, and F6 runtime orchestration command: **207 passed in 283.68s**.
- After strengthening the production-runtime fallback regression to invoke the actual consumer: **1 passed in 3.74s**.
- Focused report-scope/checker regression after the implementation changes: **13 passed in 8.04s**.
- `py_compile` on the five production modules and four relevant test modules: exit 0.
- Scoped `git diff --check` on the same source and test files: exit 0.

The reports and test journals in these software tests are synthetic fixtures; they are not native F6 evidence. The checker is wired into the production runtime path, but a complete real F6 session and saved archive remain unverified.

## Next acceptance work

1. Rebuild the four cross-component runtime-graph edge projections from declared artifacts and Runner facts.
2. Run original and fresh F6 success plus expected-ERR cases with the live Runner checker enabled.
3. Save complete raw archives and independently audit the checker reports, event joins, and semantic projections.
4. Only then rerun and assess a new frozen native gate.

The 6 CPU × 4 IP matrix, arbitrary same-protocol onboarding, P6/P7-E/P8, and overall system acceptance remain open.
