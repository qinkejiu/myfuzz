# Reduced AXI receipt observer software increment

The approved first increment observes the code-owned `reduced_dual_single_beat.v1` shape at `GeneratedReducedAxiCpuSession.step_local` after the existing native pre-receipt checks and before RAM/MMIO service mutation. It accepts only the measured pre edge. It validates the exact pre/post ABI and keeps both unchanged in a long-lived `runtime_events` list. The existing ScenarioRunner importer drains that list with its normal stream offsets; a direct importer test checks no duplicate drain and subsequent reset import.

The observer keeps separate physical i/d contexts, read and write overlap, independent AW/W acceptance including W-before-AW, one pending read per face and one write context. It retains ID, LAST, RESP, size, byte lanes, raw references and scope. Response 0/2/3 completes the bus observation with the actual status; EXOKAY 1 is explicitly unsupported because the physical ABI exposes no exclusive request role. Missing LEN/BURST/LOCK/QOS roles remain `not_exposed`. No acceptance is inferred from post. Stalled VALID/payload must remain stable pre-to-post and through the following pre.

`begin_case` binds execution/case/component/reset scope. `reset_local` cancels pending observer identities immediately before clearing service state; the list remains the same object. A terminal protocol failure keeps its raw edge and violation, refuses further observations until a fresh scope, and supplies no source authority. Lifetime edge/raw-byte budgets remain in force across scopes; exhausting them permanently prevents reopening the observer. Scope count is also bounded. Identity includes schema, shape, sampling and budgets. The actual host import closure includes the observer, fields and session source files.

Every emitted record declares `authority=observation_only`, `runtime_accepted=false`, `semantic_accepted=false`. These records do not grant ISA retirement, instruction/data authority beyond the two declared physical faces, memory commit authority, generic protocol evidence certificates or coverage registration.

Validation command:

```sh
PYTHONPATH=src pytest -q tests/scenario/test_reduced_axi_events.py tests/local_harness/test_vexii_generated_cpu.py -k 'not test_real_generated'
```

Result: **38 passed, 2 deselected**. The two deselected tests would execute native generated CPU workloads and were not run. All six pinned existing native gzip artifacts were replayed in pure software after compressed SHA verification. The first/fresh entire event prefixes are identical after normalizing only `scope.execution_id`; raw samples and payloads remain untouched. Fault read substitution changes payload without a fabricated protocol violation. MMIO fault remains an incomplete data-read prefix.

| Saved sample | Edges | Records | i AR/R | d AW/W/B | d AR/R | Pending at end |
|---|---:|---:|---|---|---|---|
| first | 55 | 86 | 11/10 | 2/2/2 | 1/1 | i read |
| fresh | 55 | 86 | 11/10 | 2/2/2 | 1/1 | i read |
| fault | 55 | 86 | 11/10 | 2/2/2 | 1/1 | i read |
| mmio-first | 52 | 83 | 11/10 | 2/2/2 | 1/1 | i read |
| mmio-fresh | 52 | 83 | 11/10 | 2/2/2 | 1/1 | i read |
| mmio-fault | 40 | 59 | 7/7 | 1/1/1 | 1/0 | d read |

Controls cover native response ID/LAST mutations, response classes, post/next-pre payload stability, orphan responses, W-before-AW, independent faces, read/write overlap, ID reuse after same-edge completion, alignment/size/lanes, outstanding limits, missing/post-extra fields, reset cancellation, stream import and lifetime budget exhaustion. RED receipts show the initially missing observer, missing session stream, missing scope budget, and the reset-reopen budget bug before their fixes. Independent source review additionally found that a standalone session retry after observer failure could still advance the native transport before refusing the observation. A failing command-count control reproduced it; `step_local` now checks observer state before issuing any subsequent native command.

Durable evidence is in [the receipt](evidence/reduced-axi-observer-20261017/receipt.json) and [software log](evidence/reduced-axi-observer-20261017/software-green.log). File hashes and all RED logs are in the same directory.

This is software evidence against previously saved native receipts. No native/build/elaborate/remote job was run. It does not establish a new independently verified physical tap or a new native pass. CVA6 packed full AXI and burst observation remain a subsequent increment requiring the corresponding real saved journal and explicit contract; generic AXI evidence/coverage admission remains subsequent work.
