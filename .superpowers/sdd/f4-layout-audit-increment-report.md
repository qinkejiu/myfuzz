# Compiled F4 layout and replay audit increment

Scope: integrate reviewed code-owned candidate layout and export independently auditable fresh executions. No native build/simulation was launched for this increment. Prior native evidence remains frozen separately; this increment does not establish P7 or a complete D4 acceptance.

## Implementation

- Admission compiles the actual D3 path with `compile_candidate_layout`. Runtime recompiles and compares its issued immutable layout before decoding; all slices decode before writer declaration, pin events, or CPU execution. Values dispatch by source ID. Prefix and checker identity include schema, digest, slices and length. Unknown/seed/field semantics continue to refuse in the reviewed compiler.
- File input accepts bounded even hexadecimal strings and decodes every supplied record before native startup. The fixture remains eight bytes solely because its declared stream/pin widths are 32+32; independent additional/narrow pins use their own slices.
- Runtime retains actual Popen objects and startup role/component/PID/execution nonce/artifact identities. Post-close audit polls the retained child, records actual returncode and reaping, and refuses a successful prefix on nonzero/unreaped exits.
- Fresh runs must have component/role/artifact identity matching primary, distinct PID and nonce within the run and across primary and prior fresh runs. Complete actual prefix/events/audit are exported; exact comparison reports the first actual JSON path. Only the existing certificate prerequisite/postcondition process_scope fields are normalized.
- File output adds primary execution_audit.json, candidate_layout.json, and fresh-N/{prefix,events,execution_audit,comparison,artifact_hashes}.json. A fresh startup failure explicitly reports startup trace unavailable; later failures save actual events and close receipts. JSON remains evidence, never admission authority.

## Software receipts

Directory `.superpowers/f4-layout-audit-increment/` preserves logs and separately captured pytest exit codes.

RED: `PYTHONPATH=src python3 -m pytest -q tests/integration/test_compiled_f4_layout_replay_audit.py` => 10 failed, 16.66s, true exit 1 before implementation.

First GREEN: 8 passed/2 failed (test stub lacked consume; corrected stub, no production guard weakened).

Focused GREEN: same command => 11 passed, 16.86s, true exit 0 (green-audit.log/exit).

Broader command: `PYTHONPATH=src python3 -m pytest -q tests/integration/test_compiled_f4_layout_replay_audit.py tests/integration/test_compiled_execution_files.py tests/integration/test_compiled_f4.py`; result recorded below after completion.

No-error ABI contract remains a separate design, unimplemented here. No search throughput or whole-system completion claim.

Broader software result: **50 passed, 1 skipped in 143.85s**, true pytest exit **0**, `green.log`/`green.exit`. The skipped case is the explicitly opt-in native gate. The newest full replay audit test was also exercised separately in focused GREEN.

Independent source review found primary failure evidence omitted execution audit; addressed with independent evidence-save paths and a RED→GREEN regression (review-red.log/exit: 1 expected ImportError failure before helper implementation). Events-read failure must not suppress actual child returncode evidence. README now distinguishes prior frozen native result from the newer untested-native source.

Final implementation source SHA256 manifest: `.superpowers/f4-layout-audit-increment/source-files.sha256`. No candidate compiler changes, no runner/DMA changes, no native execution.

Final focused result after review fix: **12 passed in 16.27s**, true exit **0**, `review-green.log`/`review-green.exit`. `git diff --check` passed. Broader suite preceded the small primary-failure save helper; the focused regression verifies that exact helper and all layout/replay audit controls on final source.

Independent final source review: `.superpowers/sdd/f4-layout-audit-source-review.md`, no remaining high/medium blockers. Low notes concern fixed regex upper bound tracking the compiler constant and the existing stat/read window. Final source manifest verified OK. Source diff whitespace check passed; staged raw pytest failure logs intentionally preserve pytest's trailing whitespace, so whole-staged `diff --check` reports only those evidence log lines.
