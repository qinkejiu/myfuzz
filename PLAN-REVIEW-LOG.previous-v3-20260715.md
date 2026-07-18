# Plan Review Log

## Round 1

### Codex critique

1. B and C lack a distinct behavioral contract. With the CPU as the only master, ROM-generated MMIO is already AXI-Lite legal; C cannot manufacture internal handshake safety without bypassing the CPU. Specify which fuzz-controlled external signals C constrains, or redefine the variants.
2. The plan contradicts preservation of historical A and RawBits v2 by placing a new A in v3 and permitting deletion of its fixed generator. Preserve the runnable v2 ABI/generator or make v3 a byte-preserving opaque wrapper.
3. Bit/cycle semantics are underspecified relative to RFUZZ ready/valid pacing: define whether state advances on DUT clocks or accepted records, raw-value stability during stalls, feedback sampling phase, timeout units and entropy accounting.
4. Address-width support conflicts with rejecting truncation. Define global-to-local base subtraction, preserved bits, alignment and alias rejection, plus the policy for 32/64-bit data endpoints.
5. TemporalConstraintIR is only a primitive list. Define composition/conflicts, evaluation order, typed feedback, reset/state, widths, deterministic choice consumption, bounded state, deadlock/timeout behavior and fail-closed synthesis validation.
6. Independent reset can strand in-flight AXI-Lite/APB requests. Add quiescence, isolation/error completion, reset synchronization, downstream bridge behavior and retention policy; epoch alone is insufficient.
7. An aggregated CPU IRQ cannot identify its source. Require pending/claim behavior, direct one-hot priority, or a profile-specific cause register, including simultaneous and level IRQ semantics.
8. Fairness language overclaims comparability for structurally different A and generated input banks. Preregister one stopping/checkpoint axis, RNG mapping, stall accounting and entropy definition; otherwise describe results without causal equivalence claims.
9. Freeze the actual Coverage ABI v2 inclusion/exclusion and sampling policy, not generic “branch instrumentation.” Separate functional holdout acceptance from coverage acceptance and require a nonzero denominator for coverage claims.
10. Name the exact first-delivery CPUs (the repository currently qualifies PicoRV32 and UltraEmbedded, not Ibex) and preserve a byte-level inventory of sources, manifests, licenses and reports.

VERDICT: REVISE

### Response

1. Defined C as constraining only fuzz-controlled external protocol boundaries. Internal AXI-Lite/APB remains CPU/fabric driven; a fully internal SoC may report B/C as deliberately degenerate, and malformed internal injection is forbidden.
2. Made the historical A generator, runner, v2 geometry, payload interpretation and replay bytes permanent. The optional v3 envelope is opaque and must round-trip bytes unchanged; legacy cleanup cannot remove baseline dependencies.
3. Added normative DUT-cycle versus RawBits-accept semantics, stable stalled vectors, NBA-settled feedback phase, timeout units, used-mask entropy accounting and replay indices.
4. Added SoCIR `AddressView` with base subtraction, local offset width, alignment and alias rejection. First delivery is explicitly 32-bit data only; other data widths fail capability matching until a semantic width adapter exists.
5. Added typed fixed-width values, dependency-DAG ordering, priority/conflict rules, bounded/reset state, fixed-slice weighted choice, finite wait timeout, cycle progress and fail-closed synthesizability rules.
6. Added outstanding tracking, request blocking, drain, deterministic SLVERR isolation, bridge clearing, synchronized deassertion and escalation to an execution reset when an independent reset cannot complete safely.
7. Made a pending/claim mapper mandatory, with deterministic priority, simultaneous-source retention, level-source re-pending and explicit complete behavior.
8. Fixed DUT cycles as both stopping and checkpoint axes, domain-separated variant RNG mappings, explicit stall accounting and accepted-used-bit entropy. Results are described as paired/descriptive, not equivalent stimuli or a controlled causal comparison.
9. Froze Coverage ABI v2 point kinds, process kinds, identity and NBA-settled sampling. Functional holdout qualification is separate; statistical coverage requires a frozen nonzero primary denominator.
10. Fixed the first CPU set to repository IDs `picorv32` and `ultra_riscv`; added SHA-256 inventory coverage for sources, filelists, manifests, ROM/wrappers, licenses, inputs, results and reports.

## Round 2

### Codex critique

1. B/C/D still receive variant-domain-separated payloads while claiming mode is their only difference. Require identical v3 bytes/layout per seed, and make mode immutable, out-of-band and excluded from entropy.
2. The comparability gate incorrectly rejects A because A necessarily has different SoC/layout digests. Use preregistered variant-specific tuples; require identical generated digests only within B/C/D and a common coverage catalog across all compared variants.
3. Strict alias rejection conflicts with reconstructing the historical 4 KiB GPIO window backed by a 5-bit local address. Add a deliberate legacy alias adapter or waive behavioral equivalence.
4. AXI-Lite operation timeout cannot simply log and continue because transactions cannot be cancelled. Require a synthetic terminal response or execution reset before continuation.
5. Reset isolation lacks outstanding/channel bounds and AW/W half-transaction rules, response ordering and late-response suppression.
6. A level IRQ without ack metadata can continuously re-pend and livelock the ISR. Define masking, bounded retry or escalation.
7. UltraEmbedded's existing AXI4 TCM loader appears to violate the AXI-Lite-only, one-master boundary unless it is explicitly defined as a private boot-time profile detail outside the generated graph.

VERDICT: REVISE

### Response

1. B/C/D now consume byte-identical v3 streams and layout for each seed. Mode was removed from ControlPlaneIR, set out-of-band before start, latched for the testcase and excluded from entropy; only A uses a distinct RNG domain.
2. The experiment gate now preregisters an A legacy tuple and one shared B/C/D generated tuple, while requiring one common coverage catalog/scope across all four.
3. Added an explicit manifest-selected `LegacyAddressAliasAdapter` for migration fixtures only. Generic AddressView still rejects aliases, and the adapter cannot count as a holdout generalization success.
4. Operation and scenario timeouts now share the reset unwind path: no continuation until a real/synthetic terminal response, otherwise execution reset.
5. Fixed the first backend to one read and one write outstanding per route with separate single AW/W slots; fencing accepts only a missing half, synthetic responses are unique and late responses are epoch-dropped.
6. Level IRQ without ack metadata now defaults to `mask_until_deassert`, records a diagnostic and cannot re-enter indefinitely; metadata may specify bounded retry.
7. Defined UltraEmbedded's AXI4 TCM loader as a reset-only, CPU-private opaque installation detail outside SoCIR, RFUZZ, coverage and system-master accounting.

## Round 3

### Codex critique

1. Requiring an identical B/C/D acceptance stream conflicts with mode-dependent latency and readiness. Require only identical ordered bytes and record each variant's acceptance trace, or add a mode-independent bounded ingestion queue.
2. Reset unwind allows one read and one write outstanding but specifies only one synthetic terminal response. Either serialize to one total transaction or define independent R/B completion and simultaneous tests.
3. TemporalConstraintIR still enumerates primitive names without authoritative operand schemas and transition semantics. Differential implementations can agree while both violate the intended behavior.

VERDICT: REVISE

### Response

1. Equality now applies to ordered v3 bytes/layout only. Each mode records its own acceptance cycles/count; the producer never skips a stalled record, and budget exhaustion records the consumed prefix and unconsumed-tail digest.
2. First delivery now serializes the entire system to one logical outstanding transaction. AW/W half buffering locks out reads; an accepted read locks out writes. Unwind generates exactly the matching synthetic R or B response, with phase-specific reset/timeout tests.
3. Added a normative primitive contract covering typed operands, exact edge/next-cycle behavior, activation while active, priority, reset, finite bounds and validation for all eleven primitives, plus an independently versioned schema digest and hand-authored golden vectors.

## Round 4

### Codex critique

1. Several primitive corner cases remain non-normative: WAIT_UNTIL lacks an activate operand; TIMEOUT active-drop behavior is absent; STABLE_UNTIL and FAULT_INJECT retrigger/simultaneous priorities are unclear; CHOICE_WEIGHT does not map all raw values exactly.
2. The fixed DUT-cycle boundary lacks a terminal lifecycle. A stalled record or outstanding CPU transaction can drain after the final edge and execute extra covered branches, as the current runner does. Define snapshot/freeze, bounded teardown, failure and replay semantics.

VERDICT: REVISE

### Response

1. Added explicit activate/release/retrigger priorities, timeout active-drop reset, fixed integer `floor(R*S/2^width)` weighted mapping, bounded fault behavior and a golden-vector requirement for every simultaneous/retrigger case.
2. Defined NBA-settled snapshot at final edge M, immediate frozen coverage, out-of-band abort at M+1, bounded unwind/global reset with coverage excluded, infrastructure-invalid teardown failure, and replay of snapshot/prefix/abort/teardown. Historical A keeps its native runner and gains only a measurement wrapper for new experiments.

## Round 5

### Codex critique

The only remaining blocking finding is that `RESET_SEQUENCE` lacks a complete executable state machine: idle/active timing, request behavior, retrigger policy, coincident feedback priority, timeout transitions and observable success/failure are undefined. Define it fully or as a canonical expansion into SEQUENCE/TIMEOUT. Also define a common fail-closed runtime result for dynamically illegal retriggers. Non-blocking: invalidation should remove the complete paired A/B/C/D seed tuple.

The reviewer found no other implementation-blocking conflict and confirmed the final-edge snapshot/frozen coverage/abort/teardown lifecycle is sufficient.

VERDICT: REVISE

### Response

Defined `RESET_SEQUENCE` as a canonical, backend-independent expansion with explicit IDLE/DRAIN/ISOLATE/RESET/DONE/FAILED states, outputs, counters, coincident-event priority, retrigger behavior, one-cycle success/failure and reset behavior. Dynamically illegal primitive events now set a sticky constraint runtime error, stop acceptance, run bounded teardown and invalidate the testcase. Any invalid variant removes the complete `(design, cpu, seed)` A/B/C/D tuple from paired statistics.

The configured five-round review cap was reached, so this post-round correction is recorded but was not submitted for a sixth verdict.
