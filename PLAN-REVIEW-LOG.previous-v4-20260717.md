# Plan Review Log: 无损三层 bit-level 输入与自适应 AXI-Lite 探索

Act 1 (grill) complete - plan locked with the user. MAX_ROUNDS=5.

Reviewer model: `gpt-5.6-sol` from config, `codex-cli 0.144.1`.

## Round 1 - Codex

1. **Blocker: the campaign controller cannot control upstream kfuzz’s next testcase.** The server only receives already-mutated batches and returns coverage; kfuzz owns parent selection and mutation, so lane quotas, temperature, mutation provenance, and deterministic resume in `PLAN.md` cannot be implemented “outside” it through the existing protocol.
Fix: Explicitly choose either a controller-owned testcase producer replacing kfuzz, or a versioned kfuzz extension exposing parent selection, mutations, and per-test feedback.

2. **Blocker: RawBits v4 has no transport/framing design compatible with RFUZZ.** Current RFUZZ exposes one fixed-width record per cycle and discards alignment padding, while v4 introduces tagged, lane-specific payloads plus insertion/deletion mutations without specifying bounded lengths, tag placement, padding semantics, or checked decoding.
Fix: Define a fixed RFUZZ transport ABI with explicit length fields, maximum sizes, padding rules, tag protection, checked arithmetic, and malformed-input behavior before implementing v4.

3. **Blocker: “all legal AXI-Lite finite traces” conflicts with the existing fabric.** The current fabric serializes reads against writes and permits only one logical outstanding transaction, so the planned multi-pending handshakes cannot occur regardless of front-end expressiveness.
Fix: Either replace the fabric with a formally specified multi-outstanding implementation or narrow completeness to traces accepted by the generated single-outstanding fabric.

4. **Independent replay is under-specified.** `coverage_delta`, corpus acceptance, temperature transitions, and parent selection depend on the pre-test coverage union and controller state, neither of which is required in the bundle.
Fix: Include the pre-test coverage bitmap and complete canonical controller/corpus snapshot, or separate wire replay from decision replay and weaken the claim accordingly.

5. **Coverage exclusion is not implementable as written.** Merely freezing before drain excludes teardown, but reset/startup branches still become sticky hits in the same epoch.
Fix: Use distinct setup and measurement epochs, switch epochs only after reset/startup completes, and snapshot before drain begins.

6. **Runtime reclassification creates quota debt that may never converge.** A DUT that makes many literal traces response-incompatible can repeatedly move protocol tests into the adversarial bucket, producing unbounded compensation and DUT-dependent C/D input mixes.
Fix: Schedule quotas by declared lane, report observed classification separately, and cap or eliminate retroactive quota compensation.

7. **Reset fuzzing conflicts with testcase and lane boundaries.** Reset is declared fuzzable, yet lane selection is latched until reset and mode changes are allowed at reset boundaries, leaving mid-test reset semantics ambiguous.
Fix: Distinguish infrastructure testcase reset from fuzz-visible DUT reset and specify that only the former may change lane, epoch, or controller state.

8. **Resource-failure invalidation can censor unfavorable D results.** Discarding and rerunning any tuple where D exhausts memory hides a real cost of the adaptive corpus and can lead to indefinite retries.
Fix: Pre-register retry limits and classify variant-caused resource exhaustion as a reported feasibility failure, while invalidating only demonstrably external infrastructure failures.

9. **The wall-clock endpoint has no in-flight testcase rule.** A testcase crossing the deadline may be aborted, excluded after consuming time, or included after overshooting.
Fix: Pre-register an exact cutoff policy, record overshoot, and use the same dispatch/admission rule for every variant.

VERDICT: REVISE

### Claude's response

All nine findings were accepted. The plan now chooses a controller-owned v4 producer while preserving upstream kfuzz for A/v2/v3; defines a fixed checked v4 transport ABI; separates master-stimulus completeness from bounded fabric acceptance and adds a versioned decoupled fabric; splits wire replay from campaign-decision checkpoints; adds setup/measurement/teardown epochs; counts quotas by declared lane with no retroactive debt; distinguishes infrastructure reset from fuzz-visible DUT reset; treats variant-caused resource exhaustion as a non-rerunnable feasibility failure; and fixes the wall-clock endpoint to completion-before-deadline with censored in-flight work.

## Round 2 - Codex

All nine prior findings are addressed in the revised text. New material issues remain:

1. **The completeness claim still contradicts the transport bound.** The plan claims encoding for any finite-length trace, but v4 limits `record_count` to 65,535; splitting across testcases inserts infrastructure reset and cannot preserve one continuous trace.
Fix: Scope completeness to the manifest maximum, or define chained continuation chunks that preserve DUT and front-end state without testcase reset.

2. **Coverage epochs can wrap and resurrect historical hits.** The plan requires a fresh measurement epoch per testcase but gives no non-reuse rule; the existing ABI defaults to 16-bit epochs, which can wrap within a high-throughput 30-minute campaign.
Fix: Use a campaign-sized epoch width, reject impending wrap, and start a fresh target process before any epoch value is reused.

3. **The new multi-outstanding fabric lacks a precise ordering contract.** AXI-Lite has no transaction IDs, so independent AW/W queues require ordinal pairing, and responses from different targets need global per-channel acceptance ordering rather than merely target-local ordering.
Fix: Specify FIFO AW/W pairing, global read/write acceptance sequence numbers, bounded reorder buffers, and reset behavior, then verify them formally.

4. **Wire replay still omits runtime initial-state determinants.** Artifact digests do not capture simulator randomization seed, initialized memories/registers, environment-response state, invocation options, or tool/runtime version, yet the bundle promises identical wires and coverage.
Fix: Add a deterministic initialization contract and record every simulator seed, runtime option, initial memory image, and environment input needed for replay.

5. **Fixed A->B->C->D execution confounds variant with run order.** Thermal/load thresholds detect large disturbances but cannot remove systematic gradual drift, leaving D consistently measured under later machine conditions.
Fix: Counterbalance variant order across seeds with a preregistered Latin-square schedule, or explicitly downgrade the experiment to non-causal exploratory evidence.

6. **The B definition still references the discarded kfuzz producer.** B is described as “uniform RFUZZ raw bits,” while the revised architecture says v4 B/C/D use only the controller-owned producer; this leaves the actual uniform distribution and seed mapping ambiguous.
Fix: Define B as controller-generated uniform v4 `RAW_ESCAPE`, including the exact integer RNG domain and which payload/padding bits are sampled.

VERDICT: REVISE

### Claude's response

All six findings were accepted. The plan now represents an arbitrary finite logical testcase as reset-free continuation chunks; assigns non-reused 64-bit v4 coverage epochs with process rollover before wrap; defines FIFO AW/W pairing plus global read/write acceptance ordering and bounded reorder buffers; makes replay capture all deterministic initial-state inputs; explicitly classifies the user-locked fixed-order experiment as exploratory rather than causal; and defines B as controller-owned uniform sampling over RAW_ESCAPE used payload bits only.

## Round 3 - Codex

All six Round 2 findings are substantively addressed. The revised plan still has these material problems:

1. **Continuation validation is internally contradictory.** Earlier chunks could execute before a missing final chunk can be detected, while the format contract requires every format error to be rejected before the first DUT edge.
Fix: Buffer and validate the complete logical testcase before execution, or explicitly define streaming failures and preserve the resulting coverage/state as invalid-run artifacts.

2. **“Arbitrary finite” continuation is impossible with a fixed-size chunk-index field.** A fixed 64-byte header necessarily gives the chunk index a finite width, contradicting the unbounded completeness claim.
Fix: Specify the exact chunk-index width and scope completeness to its representable limit, or introduce a genuinely extensible index encoding.

3. **Profile precedence can override physical RTL facts.** The merge order places user/profile declarations above elaborated facts, conflicting with existing direction and width validation.
Fix: Make elaborated port existence, direction, and width immutable; apply declaration/profile precedence only to semantic classifications where structural facts do not decide the value.

4. **CPU semantic completeness still lacks a defined initial-state domain.** “All legal initial register/memory states” does not define CSR and privilege state, fixed registers such as `x0`, memory extent/default contents/permissions, device state, or which states the loader can actually realize.
Fix: Add a versioned CPU state-domain contract and require the encoder, loader, oracle, and completeness tests to use precisely that domain.

5. **AXI-Lite protection bits are promised but not carried by the specified implementation.** The completeness claim includes protection bits, while the fabric requirements and current profile omit `AWPROT`/`ARPROT`.
Fix: Define optional-signal discovery and carry present protection bits through layout, frontend, fabric, target model, monitor, replay, and round-trip tests.

6. **Experiment B cannot share an initial mutation corpus as claimed.** B generates independent uniform used-mask bits, but the fairness contract requires a common initial corpus across B/C/D.
Fix: State that corpus equality applies only to C/D and define B’s fairness through the shared seed mapping and legal layout domain.

VERDICT: REVISE

### Claude's response

All six findings were accepted. The plan now buffers and validates a complete logical testcase before any DUT edge; scopes completeness to a frozen manifest with a 32-bit chunk index and explicit aggregate limits; makes elaborated existence/direction/width immutable; adds a versioned `CpuStateDomain`; carries present `AWPROT`/`ARPROT` through every relevant layer; and limits byte-identical initial corpus equality to C/D while defining B's separate RNG domain.

## Round 4 - Codex

All six Round 3 findings are resolved: continuation input is now fully buffered and bounded, structural RTL facts are authoritative, `CpuStateDomain` is explicit, protection bits are end-to-end, and B no longer claims to share C/D’s corpus.

1. **The fabric’s global B/R response ordering can reject otherwise legal AXI-Lite behavior.** The wording could require read and write responses to follow one global acceptance sequence, allowing a delayed earlier B to block a later R.
Fix: Use per-channel ordering with independent response backpressure, or formally specify and prove the stronger global policy is deadlock-free and include that policy in the declared backend contract.

2. **Checkpoint atomicity does not cover the referenced corpus objects.** Making the checkpoint file atomic is insufficient when it references separately stored payloads and bitmaps; a crash can leave a committed checkpoint pointing at non-durable objects.
Fix: Use a durable two-phase/WAL commit for objects plus checkpoint, or commit a checkpoint only after every referenced object has been durably written and verified.

VERDICT: REVISE

### Claude's response

Both findings were accepted. The plan now gives B and R independent per-channel sequence spaces, reorder buffers, backpressure, and progress so neither can block the other; checkpoint persistence now durably publishes and verifies all referenced content-addressed objects before atomically committing the root, with full closure verification during recovery.

## Round 5 - Codex

Round 4 fixes are present and coherent:

- B/R now have independent sequence spaces, reorder buffers, READY/backpressure, and progress conditions, with explicit non-blocking guarantees.
- Checkpoint roots are committed only after referenced payloads, bitmaps, and controller objects are flushed, verified, and durably published.
- Completeness is explicitly bounded by the frozen manifest; the previous unbounded/global claims are removed.

I found no remaining material implementation blocker or internal contradiction. The remaining open items are appropriately scoped implementation details or explicitly declared risks, not gaps in the locked design.

VERDICT: APPROVED

### Claude's response

Approved without further revision. The plan is locked for user sign-off; implementation remains unauthorized until the user explicitly chooses to proceed.
