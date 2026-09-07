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

## Task 4: Explicit member semantic annotations with a composition gate

Add an optional `physical` selector to an input field:

```json
{"role":"address","physical":{"port":"noc_req_o","member_path":["aw","addr"]}}
```

Both members are required together. `port` and every path segment are HDL
identifiers; `member_path` is non-empty. A physical selector is mutually
exclusive with alias-based scalar selection. It is valid only for the
elaborated selected top module and must match exactly one compiler-proven leaf.

- [x] RED: reject missing/extra/unsafe selectors, absent elaboration, non-top
  endpoints, missing/ambiguous member paths, duplicate physical leaf mappings,
  and source/member location mismatches. Prove nested member selection uses the
  compiler width, signedness and raw offsets rather than declared semantics.
- [x] Extend `FieldHint` and `interface_description.v1` with a frozen typed
  physical selector. Emit member annotations with container port,
  `member_path`, `raw_lo`, `raw_hi`, `container_width`, member width/signedness,
  member source location, and evidence `explicit_member` plus
  `compiler_elaboration`.
- [x] Extend `interface_annotations.v1` validation and immutable capability
  normalization for these fields. Duplicate checks use `(port, member_path)`;
  scalar behavior and documents remain byte-compatible when selectors are
  absent. Protocol consistency may inspect member width/direction.
- [x] Add an explicit generic-composition rejection before any IR or RTL is
  published when a normalized field has a member path. This task does not
  render slices. Preserve RED/GREEN logs and independently review the gate so a
  member can never silently become a whole-port connection.

## Task 5: Packed-container renderer and complete-input policy

After Task 4 passes review, represent one physical signal per packed container
and use compiler-proven part selects for member bindings. Output members may be
consumed independently. An input container may be driven only when its full bit
range is covered by non-overlapping proven leaves; otherwise reject rather than
inventing values for unbound bits. Reject overlapping slices, inconsistent
container facts, mixed whole-port/member bindings, and multiple response
drivers. Carry container/member facts through canonical IR and render both the
source-only and component-connected tops. Compile generated RTL against a real
small packed-struct DUT before removing the Task 4 composition gate.

Completed and independently reviewed. The final connected acceptance follows
the real Verilator crawl, plan, canonical IR, freshness reconstruction,
publication and strict compile path. Runtime RFuzz projection of external
packed inputs remains a separate later boundary.

## Task 6: Real CVA6 module evidence without weakening strict defaults

Use the fixed upstream CVA6 revision
`2e1336dcff3d1a0b49fbe6282b97802f32ea32af` and its pinned cvfpu, hpdcache and
fpu_div_sqrt_mvp gitlinks. The official flattened `core/Flist.cva6` reaches the
actual `cva6` module and produces a 28 MiB Verilator tree. The measured tree has
2,650,008 JSON structure tokens and 1,361,725 traversed Python objects; the
frontend peaks below 218 MiB RSS. Strict Verilator exits only because the
upstream configuration emits 464 warnings. These measurements are retained
under `runs/p1_cva6_module_20260907/`.

### Task 6a: Reader scale and packed enum types

Files: extend `src/myfuzz/composition/source_elaboration.py` and
`tests/composition/test_source_elaboration.py`.

- [x] RED: cover a packed enum whose `ENUMDTYPE.refDTypep` resolves to an
  integral compiler-proven base type. Reject missing/unresolved enum bases,
  unsupported bases and reference cycles. Prove enum leaves retain the base
  width and signedness inside a packed structure.
- [x] Raise the JSON structure budget to 3,000,000 and traversal budget to
  1,500,000: both are bounded just above the measured fixed-revision artifact,
  while the existing 64 MiB file and 768 MiB process limits remain unchanged.
  Preserve focused over-limit tests.
- [x] Parse the retained real CVA6 JSON under the production limits and iterate
  on additional physical type forms only when the compiler artifact proves
  they occur at a top-level port. Do not generalize unsupported language forms
  speculatively. The measured next case is `rvfi_probes_o.csr.pmpcfg_q`, a
  packed array of packed structs. Recursively validate the complete element
  type, then expose the whole array as one aggregate member leaf with the
  compiler-proven combined width; do not invent index path syntax or expose
  unvalidated inner fields.
- [x] Run focused reader and runner regressions under nice 15/JOBS=1, retain a
  compact port/type diagnostic, obtain independent review, and commit this
  bounded reader change separately.

### Task 6b: Explicit recorded-warning frontend policy

Keep `verilator-json` strict by default. Add one schema-validated opt-in policy
that passes Verilator `-Wno-fatal` while continuing to retain its warning text.
The wrapper must stream-count every `%Warning-CLASS` line and write a bounded,
machine-readable summary containing total count, per-class counts, diagnostic
SHA256 and whether human-readable diagnostics were truncated. Validate the
summary before accepting physical evidence; any `%Error`, nonzero exit,
malformed summary or changed source closure still fails closed. Include the
policy and stable warning summary in elaboration identity.

Use focused fake-frontend tests for full-stream accounting beyond 64 KiB and a
real fixed-revision CVA6 run for acceptance. This gate establishes physical
port evidence only; warning acceptance does not imply RTL execution quality or
CPU support.

Completed and independently reviewed. The default remains fatal. The explicit
recorded mode accepted the actual fixed-revision CVA6 frontend with 464 fully
classified warnings, zero error records, a zero exit status and all 13 physical
ports. Raw diagnostic bytes and their hash remain in the run manifest; stable
snapshot identity contains only the policy and deterministic warning class
counts so source-root relocation cannot perturb identity.

### Task 7: Multi-repository source provenance for the official CVA6 closure

The official closure crosses pinned gitlinks, so parent-repository blob lookup
cannot authenticate all files. Introduce a typed source-repository map that
binds each relative subtree to an exact revision and verifies every file
against the owning repository. Resolve filelist variables only from explicit,
typed caller values; never inherit arbitrary host environment variables.
Then run SourceCrawler through the same actual CVA6 module evidence path and
include every repository revision in canonical source identity.

#### Task 7a: Typed gitlink repository ownership

Add optional source `repositories` entries with canonical shape
`{"path":"relative/subtree","revision":"git:<40 lowercase hex>"}`. The root
repository continues to use `source.revision`. Reject duplicate paths,
absolute/empty/dot/parent paths, symlink roots, non-Git checkouts and revisions
that do not equal checkout HEAD. Sort serialized entries by path.

For each nested repository, select its nearest declared ancestor repository and
prove the ancestor tree records the relative path as mode `160000`, type
`commit`, with the exact child revision. Files belong to the deepest declared
repository containing them; verify their bytes using `git cat-file blob` at
that repository revision. A file beneath an undeclared or mismatched gitlink
fails instead of falling back to filesystem bytes. Include the canonical
repository map in elaboration evidence and verify it again before physical
member annotation.

RED/GREEN tests create a root repository, a nested repository and a repository
nested inside that child. Cover successful deepest-owner reads, dirty tracked
files, missing pins, wrong revisions, forged non-gitlink directories,
duplicate/unsafe paths and path-independent identity. Commit this provenance
primitive separately after independent review.

Completed and independently reviewed. Empty repository maps preserve the
existing source and elaboration identities byte-for-byte. The actual CVA6
explicit 225-file list passes all four repository and blob ownership checks,
then stops at the separately planned non-top source-parser boundary.

#### Task 7b: Explicit filelist variables and actual SourceCrawler run

Add a typed mapping for filelist variables used by the official Flist. Variable
names are identifiers and values are safe paths rooted in one of the declared
repositories. Expand only `${NAME}` tokens from this mapping; reject `$NAME`,
host environment fallback, undefined variables, substitutions that form
options, recursive values and paths outside the source root. Canonicalize the
mapping into source/elaboration identity.

Run the official fixed-revision CVA6 closure through SourceCrawler with the
three nested repository pins and `recorded-nonfatal`. If source-only parsing
encounters unsupported types in non-top modules, it may defer those individual
port facts only while compiler elaboration is explicitly enabled; endpoints
requiring absent facts must still fail closed. Retain all 13 compiler-proven top
ports and the warning summary, and report exact source count, repository pins,
runtime and sampled RSS.

Completed and independently reviewed. The official Flist expands to 225 source
files and seven include roots without consulting the host environment. The full
SourceCrawler run verifies 317 closure files across four repositories, retains
207 modules and 865 supported source-only port facts, and adds all 13 actual
compiler-proven `cva6` top ports with the stable 464-warning class summary.

### Task 8: Protocol-neutral processor test boundary and runtime projection

Ibex, CVA6 and BOOM are test inputs for one generic RISC-V processor path; they
must not select generator behavior by CPU name.  Normalize only the execution
facts shared by processor tests: clock/reset, optional boot address and hart
ID, interrupt inputs, and one or more instruction/data memory-master endpoints.
Each memory endpoint keeps its declared bus protocol, but composition consumes
one protocol-neutral request/response backend contract.  Protocol adapters are
selected from declared endpoint protocol and capability evidence.

#### Task 8a: Generic processor boundary and real packed-member annotation

Define and validate the protocol-neutral processor boundary independently of
HDL port spellings and CPU identity.  It must require exactly one clock and one
reset, at least one declared memory-master endpoint, and explicit source-backed
field facts.  Boot address, hart ID, interrupts and debug request are optional
capabilities.  Split instruction/data masters and unified masters are both
valid.  Reject ambiguous duplicate control functions, target-oriented memory
endpoints, unknown protocols, and missing required protocol fields.

Use the fixed CVA6 source only as a regression sample.  Bind every member of
`noc_req_o` and `noc_resp_i` by compiler-proven path and offset.  AXI fields
needed for generic reads/writes retain their standard roles; cache, protection,
QoS, region, user and ATOP members remain explicit pass-through/unsupported
capabilities rather than becoming processor-specific behavior.  Prove complete
coverage of the packed response input and retain the exact source identity and
warning summary.  Add a renamed synthetic processor fixture to prove the path
does not dispatch on `ibex`, `cva6` or `boom`.

Completed and independently reviewed.  The real-source regression verifies
the fixed source identity, 464-warning summary, all 45 memory members, 16
explicit extension fields and complete 210-bit packed response input.  The
boundary builder contains no CPU-name dispatch and does not claim execution.

#### Task 8b: Generic memory backend adapters

Implement adapters from declared OBI, AXI4 and TileLink endpoint capabilities
to a common beat-oriented memory backend.  The first executable subset may
serialize requests, but it must preserve legal backpressure, response/error,
byte-enable and transaction identity needed by the accepted request.  Any
unsupported burst form, atomic operation, coherence message, ordering mode or
width conversion fails during composition or receives the protocol-defined
error response; it must never be silently dropped or rewritten.  Tests cover
renamed initiators, independent AXI AW/W arrival, response stalls, IDs, INCR
bursts used by ordinary instruction/data traffic, reset and timeout.

The first Task 8b substep is complete and independently reviewed:
`processor-memory-beat@1` now defines the common single-outstanding beat
request/response boundary with byte enables, independent backpressure and
error-qualified completion.  It is a distinct protocol identity, so the
existing `ready-valid-mmio@1` unique-loading and behavior remain compatible.

The AXI4 substep is also complete and independently reviewed.  Protocol and
field capabilities select a CPU-name-independent adapter that preserves
independent AW/W arrival, backpressure, IDs, byte enables and backend errors.
Unsupported bursts, locks and atomic requests complete with DECERR; rejected
write bursts drain their AWLEN-declared W transfers, and atomic requests return
the required number of R beats while R and B remain independently backpressured.
The fixed real CVA6 boundary resolves through this generic path.  At this
checkpoint, TileLink, timeout recovery and real processor execution acceptance
remained open.

The OBI substep is complete and independently reviewed.  Required read fields,
an optional paired write capability, optional byte enables and a required
observable error extension select read-only or read/write parameters without a
processor identity.  Grant is tied to backend request acceptance; one accepted
backend response produces one OBI response pulse.  At this checkpoint,
TileLink, timeout recovery and real processor execution acceptance remained
open.

The TL-UL substep is complete and independently reviewed.  Get, PutFullData
and PutPartialData serialize through the common backend with source/size,
byte-enable, error and backpressure preservation.  Unsupported operations use
protocol-shaped errors; oversized Get responses retain their D beat count and
multibeat data requests drain A before responding.  Empty PutPartialData is a
successful local no-op.  Task 8b now has executable AXI4, OBI and TL-UL paths;
timeout recovery and real processor execution acceptance remain open.

#### Task 8c: Packed RFuzz runtime projection and connected acceptance

Extend RFuzz runtime projection for external packed input containers using the
canonical IR member ranges.  Require complete non-overlapping input coverage,
stable bit ordering, and reconstruction equality between projected bits and
the rendered container.  Compile and simulate a connected generic processor
fixture before trying each real CPU source.  A real CPU integration gate also
requires boot code, observed instruction/data progress and completion through
the common backend; elaboration or wrapper compilation alone is insufficient.
