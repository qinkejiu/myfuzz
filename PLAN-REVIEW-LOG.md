# Plan Review Log: compose-v5 无名称 SoC、bit 级约束与覆盖率对比

Act 1 (grill) complete - plan locked with the user. MAX_ROUNDS=5.

Current stage: `plan`. No implementation code may be changed before final user signoff.

## Round 1

Reviewer: OpenAI Codex `gpt-5.6-sol`, reasoning effort `medium`, read-only sandbox.

### Codex's critique

`VERDICT: REVISE`

1. Driver ownership is undefined. RAW/VALID/PERTURB appear able to second-drive internal CPU-to-IP wires, contradicting CPU-as-sole-master, and the right-inverse domain is therefore unclear. Define exactly one owner for every input/edge, explicit injection nodes, and scope completeness to fuzz-owned external injection points.
2. The existing frontend evidence is insufficient for the proposed inference. Coarse LHS/RHS dependencies do not provide sensitivity trees, reset polarity, guard/control predicates, slices, comparisons, or state transitions. Add a versioned frontend schema expansion and feasibility fixtures before contract work.
3. Bounded probing cannot prove a unique protocol intent. It may propose candidates, but formal generation needs independent evidence or annotations and must fail closed on ambiguity.
4. Excluding user port annotations appears to conflict with the route lock, which preserves annotations as authoritative. Resolve the compatibility boundary explicitly.
5. Bridge verification is circular if generated assertions merely restate inferred contracts. Primitive semantics must be independently specified, and the bridge must be checked against actual endpoint RTL transition relations.
6. B raw boot versus C persistent boot confounds the interpretation of C-B. Equalize it or explicitly make C-B a package comparison and add a diagnostic ablation.
7. Bounded startup probing cannot uniquely identify boot/fetch for shared, trap, or internally sourced fetch paths. Add a qualification proof and reject unresolved targets.
8. Address apertures may be sparse, aliased, privileged, or contain holes. Power-of-two rounding is unsound without equivalence; preserve exact predicates and route holes correctly.
9. The required real Ibex/RVX/CVA6 target sources/filelists do not appear available in the current tree. Slice 0 must elaborate the actual target manifests and stop if unavailable rather than substituting models.
10. Polling RSS every 10 seconds cannot prevent OOM. Enforce a hard process-tree limit using the effective cgroup memory limit, with a verified fallback only where cgroups are unavailable.
11. Behavioral probing is ordered before the runner/time-step ABI it depends on. Reorder implementation so the minimal common runner exists first.
12. “At least one complete record” conflicts with the 1 MiB cap if a record itself exceeds 1 MiB. Reject such layouts at build time.
13. Filelists and RTL are untrusted inputs. Specify root containment, symlink policy, argv-only tool invocation, environment scrubbing, read-only source access, isolated outputs, no network, and process limits.

### Planner's response

Accepted findings 1, 2, 5, 7-13 and revised the plan directly. For finding 3, bounded probing now only proposes candidates; formal v5 requires refinement/induction against actual endpoint RTL and fails closed if uniqueness cannot be proven. For finding 4, existing annotation support remains compatible and authoritative outside the new strict `compose-v5-auto` experiment; artifacts using annotations are excluded from that experiment. For finding 6, the user-locked B/C boot difference remains part of the fixed-constraint package, and a non-primary 5-minute `C-rawmem` diagnostic isolates its contribution without changing the four schemes.

The revision also scopes RAW completeness to fuzz-owned external injection points, gives every RTL input exactly one owner, forbids decoder second-driving CPU request wires, requires independent primitive proofs and endpoint miters, preserves exact sparse address predicates, adds a real-target eligibility gate, uses hard cgroup enforcement, reorders the first slices, rejects oversized records, and adds an explicit untrusted-source execution boundary.

## Round 2

Reviewer: same Codex thread `019f6fc5-793d-7432-8729-5c296bae2d15`, read-only sandbox.

### Codex's critique

`VERDICT: REVISE`

1. Contract uniqueness remains undefined. Refinement can prove a candidate but cannot prove uniqueness without a frozen hypothesis grammar, equivalence relation, and exhaustive ambiguity procedure.
2. Endpoint miters lack independent observable trace semantics, environment/fairness assumptions, reset correspondence, and non-vacuity checks. Specify assume-guarantee and trace-refinement obligations with mandatory covers.
3. RAW completeness excludes CPU request wires but still requires unmapped-address and illegal-request right-inverse coverage. Restrict those checks to fuzz-owned injection points that can actually control the signals.
4. The untrusted-source boundary still permits simulation-time `$system`, file IO, and native host access. Reject dangerous system tasks and require mount/user namespaces plus syscall filtering for generated executables.

### Planner's response

Accepted all four findings. The plan now freezes a finite versioned hypothesis grammar, equivalence/canonicalization rules and bounded exhaustive ambiguity checker; only a single surviving equivalence class with an actual-RTL proof is accepted. Endpoint proof now has independent observable events, assumptions, fairness, reset/stutter correspondence, bidirectional trace refinement, assumption witnesses and mandatory non-vacuity covers. RAW right-inverse tests now mention only manifest-listed fuzz-owned inputs. The source boundary now rejects host-effect system tasks/file IO and requires namespace isolation plus seccomp/syscall allowlisting for generated executables.

## Round 3

Reviewer: same Codex thread `019f6fc5-793d-7432-8729-5c296bae2d15`, read-only sandbox.

### Codex's critique

No remaining material correctness gaps in the reviewed Round 3 scope.

`VERDICT: APPROVED`

### Planner's response

Accepted. The plan is locked pending the user's final signoff; implementation has not started.
