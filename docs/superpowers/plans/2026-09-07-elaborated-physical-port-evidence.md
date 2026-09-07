# Elaborated Physical Port Evidence Implementation Plan

> **For agentic workers:** Use subagent-driven-development with a fresh independent review. This continues the already approved source-evidence architecture and P1 handoff; no CPU-name dispatch or unsupported-semantics defaults are authorized.

**Goal:** Resolve parameter/package/packed-struct physical port facts using compiler evidence and preserve their source locations for later semantic annotation.

**Architecture:** Keep the existing fail-closed source parser unchanged while adding an explicit compiler-JSON evidence reader. Prefer the already installed Verilator JSON frontend over introducing an unverified new dependency or extending regex-based constant/type inference. The reader produces deterministic physical facts only. The later source-closure/annotation integration must prove actual elaboration parameters and type overrides before replacing any existing rejection.

**Tech Stack:** Python standard library, installed Verilator 5.051 JSON frontend, existing bounded command supervisor, unittest.

## Global Constraints

- Existing worktree only; preserve user task-2-report and third_party content.
- Single build/test worker, nice 15, JOBS=1, no waveform, 512/768 MiB sampled RSS policy and bounded command duration.
- Never infer interface function, temporal behavior, or CPU support from physical type names.
- Compiler references and temporary paths cannot enter stable identity; retain normalized source labels, exact line/column, widths, signedness and packed-member offsets.
- Unknown/ambiguous/missing type references and unsupported physical forms fail explicitly. No blackbox switches.
- Default type wrappers are evidence about default types only, not actual instantiated core overrides or CPU execution.

## Task 1: Deterministic Verilator physical evidence reader

Files: create `src/myfuzz/composition/source_elaboration.py` and `tests/composition/test_source_elaboration.py`.

Interface: `extract_physical_ports(tree, metadata, *, top_module, source_files)` returns a JSON-compatible document with schema_version `elaborated_ports.v1`, top_module and ports. `source_files` maps compiler absolute realpaths to caller-validated stable source labels. `ElaborationError(ValueError)` reports explicit failure.

Each port has name, direction, width, signed, source {file,line,column}, and members. Struct leaf members have path (list of member names), width, raw_lo, raw_hi, signed, and source. The first declared packed member occupies the most significant bits. A scalar/vector port has no struct members. Packed arrays of integral leaf types retain their combined width; do not invent unpacked or interface semantics.

Supported initial AST nodes: BASICDTYPE (explicit integral kinds only), REFDTYPE, PARAMTYPEDTYPE, packed STRUCTDTYPE, PACKARRAYDTYPE of supported integral/packed types. Reject unpacked structs/arrays, union, interface, unresolved references and non-integral kinds until explicitly implemented and tested. A missing range is scalar only for proven scalar logic/bit; builtin integer width must be proven or validated against its language type. Select exactly one matching MODULE, reject duplicate/missing modules and duplicate ports/type IDs. Parse compiler loc through metadata.files and enforce the caller source-file allowlist; do not expose built-in library objects as source-owned ports.

- [ ] Add RED tests: missing reader; real nested struct/package parameter example; signed 13-bit address; packed 2x4-bit member; renamed top/ports; unknown/ref-cycle, unpacked/union, bad range/location and missing source mapping rejection.
- [ ] Run `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 nice -n15 python3 -m unittest tests.composition.test_source_elaboration -v`; preserve the missing-reader RED log.
- [ ] Implement only this evidence reader. Use finite recursion/node/width bounds and avoid arbitrary evaluation of compiler strings.
- [ ] Run the same GREEN command and the existing source-crawler regression; record logs under `runs/p1_elaboration_probe_20260907/`.
- [ ] Independently review source location, alias cycles, signedness and nested MSB offsets before committing only these owned files.

## Evidence already gathered and next integration gate

`runs/p1_elaboration_probe_20260907/` retains a successful tiny typed-port JSON probe, plus a source-bound CVA6 default noc-type wrapper. The latter uses fixed config_pkg/build_config_pkg/selected config and AXI package objects, with extracted cva6.sv type declarations. Strict invocation exits on 14 upstream width warnings; exploratory -Wno-fatal retains warnings and permits JSON inspection. This does not authorize silent warning suppression in the later production elaboration supervisor.

Next P1 gate after Task 1: integrate explicit frontend selection, immutable source closure and elaboration settings into SourceLocator/SourceSnapshot/schema; test actual upstream config/type overrides and member semantic bindings through the existing annotation/composition pipeline. Full CVA6/BOOM module elaboration and real execution remain separate later gates. Do not mark P1 complete after the JSON reader alone.

## Task 2: Bounded compiler frontend over an explicit source closure

Files: extend `src/myfuzz/composition/source_elaboration.py`; create
`tests/composition/test_source_elaboration_runner.py`.

Interface: `run_verilator_elaboration(*, source_root, top_module, source_files,
include_roots=(), defines=(), parameters=(), output_dir) -> Mapping`. All source,
include and output paths are `Path`/relative strings rooted in one caller-owned
source root. Parameters are ordered `(name, decimal_integer)` pairs. This task
does not change SourceLocator or SourceCrawler yet.

- [x] RED: compile the existing nested package/module through this API and
  verify identical physical evidence; reject missing/duplicate files, symlinks,
  path escapes, unsafe define/parameter identifiers or values, duplicate
  parameters, existing/symlink output, missing tool, nonzero frontend status,
  timeout and malformed output. Verify diagnostics are retained with a 64 KiB
  limit and that a stalled frontend/descendant is reaped.
- [x] GREEN: construct a fixed Verilator JSON-only command from validated
  tokens only. No caller-provided arbitrary flags and no `shell=True`. Run one
  new process group at nice 15/JOBS=1, with 30-second duration and 512/768 MiB
  RSS supervision. Preserve command, tool version, source SHA256, return status,
  peak RSS and bounded diagnostics in a manifest even on failure. Parse output
  only after a completed zero exit and pass the explicit absolute-path to stable
  source-label mapping into `extract_physical_ports`.
- [x] Tests must inject a tiny fake frontend for timeout/error/diagnostic cases;
  only the positive integration test invokes installed Verilator and may skip
  when unavailable. Preserve RED/GREEN logs below
  `runs/p1_elaboration_probe_20260907/`.
- [x] Run reader, runner and source-crawler regressions, then independent review.
  Commit Task 2 separately. Do not suppress warnings or claim a CVA6 module is
  elaborated merely because the retained exploratory wrapper used
  `-Wno-fatal`.

## Task 3: Opt-in source-description and snapshot integration

After Task 2 review, add a typed, canonical elaboration block to
`interface_description.v1`, include it in source/composition identity, and let
SourceCrawler use the runner only when explicitly requested. Add member facts
to SourceSnapshot without converting them to scalar top-level ports. Existing
source-only behavior stays unchanged. Any frontend failure, stale source,
unsupported type or ambiguous member binding fails closed. Member semantic
annotation and renderer support require a later reviewed task before a packed
port can participate in composition.

Files: extend `schemas/interface_description.v1.schema.json`,
`src/myfuzz/contracts/validation.py`,
`src/myfuzz/composition/interface_description.py`,
`src/myfuzz/composition/source_crawler.py`, and their focused tests.

The optional source block is:

```json
{"elaboration":{"frontend":"verilator-json","defines":[{"name":"NAME","value":"VALUE"}],"parameters":[{"name":"WIDTH","value":"13"}]}}
```

`frontend` initially accepts only `verilator-json`. Define and parameter names
are identifiers; values use the Task 2 safe define and canonical decimal
subsets. Duplicate names fail. The loader stores immutable ordered pairs and
the serializer sorts them by name, so caller order cannot perturb identity.

- [x] RED: schema/loader tests prove typed parsing, duplicate/unsafe rejection,
  canonical serialization, and unchanged serialization when elaboration is
  absent. Crawler tests prove the runner is never called by default, is called
  with the resolved explicit closure when requested, and failures propagate.
- [x] Add immutable `ElaborationSettings`, `ElaboratedPortFact`, and
  `ElaboratedMemberFact` values. `SourceSnapshot` retains structured ports and
  nested member paths/offsets/source locations separately. A structured port
  must not enter `SourceSnapshot.ports`; therefore existing annotation and
  composition cannot bind it as a scalar. Memberless elaborated top ports may
  replace source-only top-port facts.
- [x] Run elaboration in a temporary caller-owned directory beneath the source
  root. Read its manifest before cleanup. Verify every manifest source against
  the bytes already pinned by the crawler (and Git blobs for Git revisions),
  then include the canonical elaboration block, stable source/tool hashes,
  tool version, and physical evidence in `SourceSnapshot.content_hash`. Do not
  hash absolute paths or temporary commands. Without elaboration, preserve the
  existing content hash exactly.
- [x] Collect safe include roots from explicit description and filelists for
  the runner. If a filelist carries define syntax that cannot be represented
  exactly by the typed block, reject opt-in elaboration explicitly rather than
  compiling different settings.
- [x] GREEN: run interface-contract, interface-description, source-crawler,
  elaboration-reader/runner, and generic composition regressions under the
  global low-resource policy. Preserve RED/GREEN logs, independently review
  identity stability and the structured-port non-composition boundary, then
  commit Task 3 separately.
