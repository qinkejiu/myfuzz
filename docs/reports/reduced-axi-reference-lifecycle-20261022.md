# Reduced AXI observer reference lifecycle: source fix and software regression

## Finding

`GeneratedReducedAxiCpuSession.runtime_events` aliases the
`ReducedAxiObserver.events` list. Runner imports the list into its
`EventJournal` and clears that same list in place. The observer can retain an
AR→R or AW/W→B correlation across that drain, so assigning the next raw
reference from `len(events) + 1` could reuse a reference number while a
pending derived event still points to an earlier raw record.

## Source change

`ReducedAxiObserver` now owns a monotonically increasing `_record_count` for
its lifetime. `_emit()` increments it for every emitted raw, derived, reset,
or violation record, and `observe()` assigns the next raw reference from that
counter. Scope changes and internal protocol-state clearing preserve the
counter. This matches the declared
`observer_stream_local_record_index` namespace and the full AXI observer's
record-count approach. Runner may still drain the public list in place.

Runner copies each observer record into its journal, leaves observer-local
references unchanged, and adds separate `event_id`, `producer_event_id`, and
`component` fields. Those ID namespaces differ; `raw_event_ref` is not a
Runner `event_id`, and the importer does not currently emit a crosswalk.

The change preserves the existing event schema and `observation_only`
authority. It does not authenticate a CPU transaction or claim that a CPU
consumed, decoded, or retired an instruction.

## Review and checks

- Independent source review found no issue in allocation order, scopes,
  resets, list draining, or consistency with full AXI references.
- `python3 -m py_compile src/myfuzz/scenario/reduced_axi_events.py`: exit 0.
- `git diff --check -- src/myfuzz/scenario/reduced_axi_events.py`: exit 0.
- The initial source slice used static checks only. The follow-up below adds
  software execution of the actual Runner/EventJournal importer.

## Software cross-drain regression

The focused suite now passes **38 tests**. Ten new cases use a real
`ScenarioRunner` and file-backed `EventJournal` with two-record chunks. Every
sample import clears the observer's aliased producer list; a repeated import
is inert. Synthetic read/write cases cover AR→drain→R, both separate AW/W
orders and same-edge AW/W before B, and reset cancellation followed by a
rejected orphan response in the new epoch. Interleaved journal events ensure
observer refs differ from journal IDs.

Six SHA-pinned saved native sample files are also reprocessed with per-sample
draining. The final aggregate observer stream equals an undrained replay,
and every retained raw/request/reset-pending reference resolves to an earlier
same-component, same-scope raw record. This test-only lookup is not a
production crosswalk or an independent protocol oracle.

An isolated child process replacing only the allocation expression with the
old `len(events) + 1` reproduces **10 expected failures**. It does not edit the
workspace source. Independent source review found no actionable findings;
its comparison-scope caveat is retained above.

Raw [negative-control log](evidence/reduced-axi-reference-lifecycle-20261022/software-attempt1/red.log),
[current-suite log](evidence/reduced-axi-reference-lifecycle-20261022/software-attempt1/green.log),
[verification receipt](evidence/reduced-axi-reference-lifecycle-20261022/software-attempt1/verification.json),
and [review](evidence/reduced-axi-reference-lifecycle-20261022/software-attempt1/independent-review.md)
are retained. Source hashes were captured after execution, not as a complete
pre-run source freeze. No native build, new native first/fresh run, or remote
operation was performed.

## Acceptance still required

The software gate above exercises the actual importer with synthetic and
archived receipts. A production crosswalk must still bind an
explicit observer stream/session identity to the actual journal `event_id`;
within that observer lifetime, raw refs must be globally unique and strictly
increasing across scopes. Each raw row's full scope must be checked as a
separate ownership fact, and derived/reset references must resolve to exactly
one earlier raw record in the same stream and request scope. Missing,
duplicate, forward, cross-epoch, or altered records must fail closed. Detecting
altered payloads also requires comparison to the original observer receipt,
fresh observer replay, or an authenticated digest; an ID crosswalk alone is
not sufficient. The observer's local references must remain intact. The gate
must cover scope/reset transitions and a new live native first/fresh
semantic-prefix replay. This software gate does not complete the CPU event
consumer. P6/P7/P8 and the overall six-CPU/four-IP goal remain open.
