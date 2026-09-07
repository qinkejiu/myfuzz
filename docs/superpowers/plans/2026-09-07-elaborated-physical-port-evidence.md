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
