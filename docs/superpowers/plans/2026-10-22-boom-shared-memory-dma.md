# BOOM uncached shared-memory DMA Implementation Plan

> **For agentic workers:** Use subagent-driven-development for the disjoint
> owned-file tasks below, or executing-plans sequentially; review each boundary
> before integration. No implementation is performed by writing this plan.

**Goal:** Actual BOOM CPU source/configuration stores, four-word DMA and CPU
readback through shared host memory, with wrong-key and full fresh evidence.

**Architecture:** Keep native instruction/coherent backing in TlRam. Bind the
entire uncached0x4000 page to the existing native external A/D interface, then
dispatch declared data spans to shared MemoryService and control to queued
Wishbone DMA. Standard Runner owns all actual process edges.

**Tech Stack:** Python, pinned generated BoomTile, current C++ native driver,
TileLink accepted events, host MemoryService, Verilator and Wishbone DMA.

## Global constraints

- Follow `../specs/2026-10-22-boom-shared-memory-dma-design.md` exactly.
- Source4100/16,destination4200/16,result4300/24,DMA4400/16; code80000000,
  native reset trampoline10040. No shared host code region or data mirror.
- Native external_range=(4000,5000), separate from Router(4400,16).
- Actual lane masks0f/f0, size2, opcode0/1/4; no hidden width/opcode coercion.
- No profile/RTL/Runner edits or B probes/coherence claims in this slice.
- 4000 dma,cpu rounds; quiesce only after marker D and no partial A proof.
- One canonical heavy worker, unique attempts and exact executed input bytes.
- Preserve dirty tree; no staging, commits, cleanup or remote operations.
- Do not add/run test files under current authorization. Use static/inline
  software checks; native verification remains a distinct reviewed opt-in step.

## Task 1: bounded subpage firmware (independent owner A)

**Files:** create `src/myfuzz/scenario/boom_dma_example.py` only. Do not modify
the accepted shared builder or existing CPU wrappers for this first slice.

**Interface:** constants MAIN=80000000,BOOT_BYTES=512,SOURCE=4100,
DESTINATION=4200,RESULT=4300,DMA_BASE=4400,WORDS=(135,246,357,468), and
`boom_dma_images(*, start_key=0xfed) -> dict[int, bytes]` returning code only.
The factory separately initializes shared destination/result; no source image.

- [x] Encode positive low data addresses with LUI immediate `0x4` (which forms base `0x4000`) plus ADDI immediates `0x100`, `0x200`, `0x300`, or `0x400`. Code80000000 is loaded by native bootstrap, never generated
  through a sign-extended RV64 pointer in the data program.
- [x] Preserve exact-int12-bit start-key refusal. Emit four source SW and
  config source/dest/length/start offsets8/12/4/0. Insert actual FENCE after
  stores; relocate labels after expansion. Poll busy31, independently reject
  error30, compare actual destination/source and write unique status/marker.
- [x] Decode instruction/branch/lane addresses independently in an inline
  software check, including RV64 LW sign extension, stale key and error path.
  Check host image set contains code only and byte length512.
- [x] Independent review records exact valid/stale code hashes and unchanged
  accepted CVW/Vexii/CVA6 files. No native execution in this task.

## Task 2: exact shared external-memory service (owner B)

**Files:** create `src/myfuzz/local_harness/boom_shared_memory.py`; modify
`src/myfuzz/local_harness/boom_scenario_session.py`. Owner B exclusively owns
both until integration. No changes to boom_cpu_driver.cpp or TlRam.

**Interfaces:** an immutable `BoomSharedMemoryContract` with full external
page and exact source/destination/result ranges, plus
`BoomSharedMemoryService(memory: PersistentMemory, contract)` holding the
actual MemoryService. `GeneratedBoomScenarioSession` gains optional
`shared_memory_service=None`; default register-only API/identity stays exact.
New mode identity explicitly records contract/service schema and memory
identity. Native external_range is full page only in this opt-in mode.

- [x] Authenticate declared low-page layout against exact pinned source
  hashes/predicates and reject mismatching ranges/permissions/overlap before
  native startup. Do not synthesize PMP permission from the source audit.
- [x] Refactor accepted external-request validation once for common real
  opcode/param/size/mask/source/sequence/epoch checks. Dispatch data only to
  declared shared spans, control only to sole existing Router window and
  reject page holes before effects. Preserve old GPIO register-only dispatch.
- [x] On data Get/Put use actual complete native TransactionKey once, select
  four bytes from physical64-bit lanes, commit/snapshot MemoryService and
  preserve real physical fields plus service receipt. Offer correctly placed
  native D via respond_external with no clock. Retain active key until actual
  external D acceptance; do not clear it at commit/RESPOND.
- [x] Existing DMA control uses Router beat_bytes8 exactly once, avoiding
  double shifts. Preserve accepted/control/D key joins, asynchronous callback
  integrity and same-object memory binding. No host-register helper calls.
- [x] Before closing/reset, cancel queued callbacks and refuse stale epochs;
  preserve uncertain effects. Expose truthful zero/nonzero pending state and
  service records; do not claim generic memory_commit_authority for old mode.
- [x] Pure inline checks cover low/high lanes, four-byte snapshots, exact
  key/epoch refusal, holes, duplicate callbacks, pre-effect refusal, unchanged
  default identity and API. No subprocess construction required.
- [x] Independent review accepts native-source/D/service lifecycle and
  backwards compatibility before factory integration.

Task 2 is complete at the bounded static/lifecycle scope. Final adapter SHA-256
is `d92c56fc9bc18640f6174a462ef506f857a1d41efcedea2b9ceeb624a2a81915`, with
the shared service SHA-256 `65e50934ed97ed4727a087908ccf560134dedf0fa2940e160adf848d3f2e6a44`.
The second Important cancellation finding was independently cleared in
`.superpowers/sdd/task-2-final-review.md`. Inline lifecycle checks and syntax
checks passed; no test suite, build, or native execution was run. Task 4 native
acceptance remains open.

## Task 3: unstarted standard Runner factory (root owner)

**File:** create `src/myfuzz/scenario/boom_dma_runner.py`.

**Interface:** `make_boom_dma_runner(*, repo: Path, cpu_output: Path,
cache_dir: Path, start_key=0xfed) -> ScenarioRunner`. Explicit cpu_output is
an authenticated prebuilt BOOM persistent session; factory never builds.

- [x] Allocate exact three shared data regions with seed17 and bounded56-byte
  initialization capacity. Preload zero destination16/result24 only.
- [x] Construct existing GeneratedWishboneDmaScenarioSession(memory=same),
  Router DMA4400/16 and opt-in BOOM session with same shared service and Task1
  code. Register cpu,dma, empty ownership and no IRQ bindings.
- [x] Verify construction remains unstarted, every target is same registered
  object, CPU and DMA share storage, native external page differs correctly
  from Router's control window, and failure closes all constructed sessions.
- [x] Inspect queued target ticks/pending/cancellation through standard APIs.
  No manual router drain and no Runner CPU-name branch.
- [x] Independent fixture review checks exact PMA/layout/boot/lifecycle facts.

Task 3 is complete at unstarted fixture/static scope. The factory SHA-256 is
`f80c27ec6d66eb666df644f41acc5989190d40e065011ed10afaf9a7719adb62`; the
independent approval is `.superpowers/sdd/task-3-review.md`. Its inline
placeholder fixture and syntax verification passed. It did not build or start
BOOM; all native dataflow and replay claims remain for Task 4/5.

## Task 4: strict native evidence gate (owner C)

**File:** create `scripts/verify_boom_dma_ram.py`; review artifact owned by an
independent reader. This task depends on accepted Tasks1–3 interfaces.

**Interface:** environment opt-in `MYFUZZ_BOOM_DMA_RAM_REAL=1`, existing cache,
explicit prebuilt CPU output and unique evidence root. Reject optimized Python.
Follow existing CPU/DMA standalone verifier conventions without modifying them.

- [x] Freeze exact program/adapter/service/native driver/TlRam/profile/RTL/
  generator/source-lock inputs, binary and manifests. Record source/tool pin
  boundaries, worker receipt and lock. Preserve first/fresh native identities
  exactly before any runtime UUID normalization.
- [x] Step dma,cpu and record all actions/raw accepted events/service records.
  Independently account A multibeat state from opcode/size; on actual marker
  external D require no partial A and no simultaneous new A, then record
  quiesce no-edge action. Continue native D/E/C/DMA drains within4000rounds.
- [x] Assert design's four-source, four-config, four-master-read/write exact
  key/STB/ACK/response, writer/version and CPU consumed-D/result joins. Native
  cached code traffic must remain separate. Reject unsupported physical
  shapes rather than splitting them or changing accepted budgets.
- [x] Run stale-key branch with identical resource/code shape: no DMA accepted
  master/response/effect, actual first mismatch and failure markerFFFFFFFF.
  Preserve a separate hole-refusal result as abort-before-service/provider,
  not a synthetic TL error response or drained successful CPU transaction.
- [x] Fresh instances replay every saved action for each branch with distinct
  process/execution IDs. Require complete normalized retained-prefix equality,
  exact stable identities, all pending states zero and actual child exits0.
- [x] Unconditional nested-finally capture/cleanup preserves primary errors;
  terminal receipt records failed assertions and all failed attempts remain.
- [x] The prior exact verifier SHA-256
  `f4064cb130ea876eb4fe6228323e7bf6a42285b0cf62389a9715012f6d922379` had two
  independent static approvals (`.superpowers/sdd/task-4-final-independent-review.md`
  and `.superpowers/sdd/task-4-fix4-review-a.md`) and one nonblocking Minor
  about chained cleanup-cause diagnostics. A real positive run exposed a
  tuple/list representation defect; fix5 is frozen at SHA-256
  `bdb8bd3a7fa71ba8f8a70c05c2f256545da080f3e073914c980d6c9e0d3a9c36` with
  no assertion changes. Two independent reviews approved that exact hash
  (`.superpowers/sdd/task-4-fix5-review-a.md`,
  `.superpowers/sdd/task-4-fix5-review-b.md`); the same Minor remains. Root
  then authorized a new local canonical-lock native worker. Prior failure
  evidence remains intact. The subsequent native acceptance is recorded under
  Task 5 below.

## Task 5: native acceptance and scoped reporting (root)

- [x] Prepare/authenticate current native BOOM executable using existing
  build_boom_session under the canonical heavy lock; preserve build failures.
  Current artifact is `runs/boom-dma-ram-cpu-output-20261022-attempt1/`; the
  independent 22-check audit is `.superpowers/sdd/task-5-boom-cpu-artifact-audit.md`.
  Do not treat old archived executable availability as current acceptance.
- [x] Run the accepted opt-in gate with fix5 verifier SHA-256
  `bdb8bd3a7fa71ba8f8a70c05c2f256545da080f3e073914c980d6c9e0d3a9c36`.
  Attempt `docs/reports/evidence/boom-dma-ram-20261022-task5-attempt2/attempt-be77b5eef02548dbb28676a6ff4ce510/`
  has `verification.status=passed`, `matches=true`, complete positive and
  stale-key first/fresh pairs, zero pending and child exits 0. Independent
  saved-evidence and archive audits passed; see
  `docs/reports/boom-dma-ram-20261022.md`.
- [x] Have an independent reader reconstruct saved A/D, control/master,
  byte-writer/version, quiesce-boundary and complete fresh joins. Fix actual
  implementation defects in a new frozen attempt, retaining each failure.
- [x] Update CURRENT_PROGRESS, LOCAL_HARNESS_RUNTIME and a bounded report with
  actual measured outcome. Wider coherent/physical/F6/system gates stay open.

## Compatibility and stopping criteria

No change is accepted if existing register-only GPIO default external_range,
identity schema, opcode/mask rules or accepted firmware bytes change. Native
driver closure remains current and authenticated; any necessary native-driver
change returns to design review instead of being hidden in this plan.
Successful completion requires the full real positive/stale fresh evidence;
static checks alone complete only their specific tasks. A partial-A quiesce,
unexpected cached shared-data request, unsupported width or source drift is a
preserved failure, not grounds to enlarge the scope or relax comparisons.
