# F6 runtime graph cross-component edge projector — 2026-10-25

## Scope

This software slice connects the admitted F6 runtime graph to live case capture
and the detached saved-prefix verifier. It reconstructs the declared four-edge
path from Runner events and separately derives the CPU configuration,
four-word DMA transfer, and IRQ/ISR component outcomes.

The four graph edges are:

1. RAM source words → DMA read words, bound to selected source commits,
   per-word DMA read snapshots, and the admitted read route.
2. DMA read words → DMA write words, bound to accepted read responses preceding
   the write acceptance sequence.
3. DMA write words → RAM destination words, bound to write acceptance,
   destination commit/version, response, and the admitted write route.
4. The admitted instruction source → online instruction prefixes, bound to
   source admission/service and actual instruction fetch evidence.

Edges 0–2 use edge-local issue scopes. A missing source snapshot affects edge 0
without downgrading the independent read-response/write-acceptance edge. The
four-read-before-four-write chronology checks are attributed to edge 1.

## Source and reference closure

`instruction_source` Runner events are now retained by the production F6
Observer projection. Live capture resolves the unique projected row through
the Runner and compares it byte-for-byte with the raw event. The original
`source_admission` event has no component-owned Observer row, so it remains in
the nested declared-edge projection and is reconstructed from the original or
fresh Runner archive by the saved verifier.

The cross expectation owns its own references: it retains the selected graph
edge references plus the instruction-source Observer reference. Component
evidence keeps separate references in its own expectation. The verifier
reprojects the four graph edges independently for original and fresh prefixes,
checks the cross outcome using failed-over-missing precedence, compares the
nested projection and four rows, and requires exact reference/evidence
inventory closure.

Edge 3 deliberately remains `missing`: the archive still has no original F6
instruction-acceptance receipt that proves the admitted prefix's per-byte
version chain. A service label or functional-fetch snapshot does not grant
that proof.

## Review and validation

- Independent review found and closed two edge-attribution defects: missing
  source snapshot had affected the causal edge, and raw chronology checks could
  inherit the previous destination edge's issue bucket.
- Independent review found and closed the instruction-source reference issues:
  an out-of-scope Observer index, the missing production Observer allowlist
  entry, and lack of live Observer-to-Runner byte comparison.
- Independent saved-verifier review found the original/fresh reprojection and
  exact root-reference closure consistent with the projector's reference
  shapes.
- The final code review found one Minor issue: cross-reference rows allowed
  extra keys even though their identity tuple was closed. The verifier now
  requires the exact `{component, event_id, kind}` row shape; follow-up review
  confirmed the finding is closed and reported no remaining issues.
- The combined consumer and assertion-evidence module completed **198 passed**
  in 294.11 seconds before the final Observer-link and exact-reference changes.
  It is a baseline result, not a post-change acceptance run.
- `py_compile` passed for `compiled_f6.py`, `compiled_f6_consumer.py`,
  `compiled_f6_saved_semantics.py`, and `verify_compiled_f6.py`. A direct
  whitespace check of those four files found no trailing whitespace or missing
  final newline. The workspace-wide `git diff --check` reports an unrelated
  pre-existing trailing blank line in `.superpowers/sdd/task-2-report.md`; that
  file was not changed in this slice.
- No native run, build, RFuzz, or remote operation was performed.

## Acceptance boundary

This is an offline software implementation candidate. No complete real F6
original/fresh success and expected-error archive has been independently
audited, and no Freeze16 gate has been issued. Freeze15 remains **FAIL_PRESERVE**
(native-controls attempt14: 4 passed, 5 failed). The six-CPU/four-IP joint
matrix, arbitrary same-protocol onboarding, P6 persistence/closed-loop gates,
P7-E, P8 5× performance target, and system acceptance remain open.

## Addendum — source-bound OBI receipt producer (2026-10-25)

Task9 now implements the source-bound `compiled_F6_instruction_fetch_completion.v1`
producer in the original generated CPU OBI path. Backend acceptance freezes a
candidate; the following native OBI PRE response sample issues the receipt.
The producer binds the accepted source/read objects and joins the source,
backend, native response, and Runner journal references. Same-edge new grants,
reset cancellation accounting, and read-only adapter invariants are covered by
software tests. The final receipt producer SHA-256 is
`fbcbe9721098b5717de0bd8f2759a1e212805eb0fc4077973da41271de86df51`.

This closes a prerequisite producer gap. Task10 has since connected the live
F6 consumer and detached original/fresh saved projector, but the latest frozen
live gate at saved SHA `53e1cf78…` is not green: saved-semantics passed 299
tests and the verifier passed 86, while the live positive/boundary group had 3
failures and 6 passes. A strictness follow-up at saved SHA `530f275f…` passed
saved-semantics (302), verifier (86), and saved-output (15) modules. It enforces
uniform per-byte versions and exact integer types, but independent review found
that the version sequence is still not anchored to an independent raw source
root, and bool mutation coverage omits several guarded producer fields. This
candidate has not rerun live. The live failures share an over-strict request-PRE TAP inventory check: the real
CPU journal sample contains 15 declared physical TAPs across its instruction
and data OBI traces, while the projector currently requires exactly the six
instruction-side names. The expected inventory must be reconstructed from the
source-bound generated artifact, then both live and saved gates rerun. Exact
commands, hashes, outputs, and all 15 observed names are recorded in
[`task-10-live-frozen-53e1cf78.md`](../../.superpowers/sdd/f6-edge3-live-20261025/task-10-live-frozen-53e1cf78.md).
Strictness evidence is in
[`task10-strictness-report.md`](../../.superpowers/sdd/f6-edge3-strictness-20261025/task10-strictness-report.md).

Task10 remains open. No native F6 first/fresh archive, independent raw audit,
or Freeze16 gate has been produced.

## Latest software gates — 2026-10-25

The sample/TAP and acceptance-anchor work is now integrated in the saved
projector. The source-bound CPU artifact supplies the exact union of
instruction/data OBI TAPs; the official helper rejects boolean widths even
after the artifact digest is recomputed. Each saved instruction receipt is
cross-checked against the F6 acceptance anchor published on its original
Runner `instruction_source` row, so a uniform rewrite of all receipt/read/
response versions no longer passes. The anchor/type changes received a
read-only review with no Critical/Important findings.

Live debugging found that Runner append IDs do not encode a total hardware
causal order between a serviced `memory_read` and that step's PRE sample. A
real generated step produced `memory_read event_id=42` before its PRE sample
at `event_id=52`, while both carried the same step identity. The projector now
checks their transaction, producer, scope and payload links, and separately
requires archived Runner IDs to remain strictly increasing in journal order;
gaps are allowed when rows are absent. Validated receipt evidence is retained
for an incomplete prefix, which reports `missing` with the 31 available
receipts.

Final-code software gates: Task9 full producer **57 passed / 536.09s** under
source closure `67221f53…0703d3`; saved-semantics **324 passed**, saved
verifier **87 passed**, saved outputs **15 passed**, and live edge-3 positive
plus boundary group **9 passed / 176 deselected**. Independent review of the
final chronology/partial-evidence source found no Critical/Important findings.
Exact final source/test/log SHA values are in the [final freeze
record](../../.superpowers/sdd/f6-source-anchor-20261025/final-freeze-20261025.md).
These are software gates and do not constitute a real native F6 original/fresh
success or expected-error archive. Freeze15 remains **4 passed / 5 failed,
FAIL_PRESERVE**; no native/build/RFuzz or remote execution was performed in
this slice.
