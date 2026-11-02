# Host-overhead round 2: same-work A/B and where the remaining campaign time goes

2026-10-30. Scope: the shared eight-case runtime (`configs/scenarios/compiled-f1-f6-ibex-gpio-dma-shared`)
after this round's host-side changes. All numbers below come from real RTL runs of that
descriptor on this host; no estimated speedup is reported as measured.

Two source variants are compared:

* **baseline** — a byte copy of the tree taken before this round's source edits
  (`/tmp/myfuzz-baseline-0101`, `src`/`scripts`/`configs` copied, `third_party` hard-linked);
* **candidate** — the tree after this round (`/tmp/myfuzz-candidate-0149`, same copy rule).

Both variants are executed by `scripts/bench_shared_flow_ab.py` from the *same* working
directory, with the same descriptor, the same 13 GB content-addressed harness cache, the same
`--dut-eval` counters and the same eight records (`F3,F1,F4,F5,F2,F6,F5,F6`). Only the source
tree passed with `--base-root` differs.

## 1. What changed in the candidate

Lead (this session):

| file | change |
|---|---|
| `integration/compiled_f6.py` | `finish()`/`replay()` hand documents over instead of deep-copying them (`_finish_document` is the returned document; replay no longer copies `expected`, `actual_prefix`, `actual_events` or the envelope for its sink); the trace gate reuses the already-captured journal snapshot and the canonical journal/trace comparison is computed once; the prefix comparison is canonical **per top-level section** (`_documents_equal`); the replay compares complete normalized documents by digest first and only walks `_first_difference` on a real mismatch; `_drain_observer_view` reads the journal tail borrowed and the F6 case-boundary check validates/reads only the case tail |
| `runtime/flows/shared_slots.py` | `replay.json` is rendered once: the audit sink publishes it and the second write republishes those exact bytes; the 211 MB prefix render string is released before the replay |

Subagent (campaign-path copies, disjoint files):

| file | change |
|---|---|
| `scenario/event_provenance.py` | per-event `deepcopy(record)` replaced by a value-detaching `_copy_value` (same value domain, journal still keeps no caller object): 31.4 → 9.1 µs/event measured |
| `integration/shared_slot_consumers.py`, `integration/shared_f6_slots.py` | whole-journal `events_since(0)` → borrowed `_borrow_exact_events`, with the derived hop documents still detached before sealing |
| `integration/shared_irq_firmware.py` | one borrowed snapshot + one `{event_id: event}` index per F5 case; per-offset full scans become one pass (certificates unchanged) |
| `integration/compiled_f6_consumer.py` | docstring only: `remember()`'s JSON round-trip is measurably *faster* than `deepcopy` here and was kept |

## 2. Campaign-only A/B (no replay), interleaved with reversal

Order: `base-a`, `cand-a`, `cand-b`, `base-b`. Outputs:
`research/input-strategy-audit-20261027/runs/host-ab-20261030/timed/{base-a,cand-a,cand-b,base-b}/performance.json`.

| run | wall (s) | campaign `execution_seconds` | finish/export (s) | peak RSS (MB) |
|---|---:|---:|---:|---:|
| base-a | 241.00 | 166.87 | 47.62 | 1 952 |
| cand-a | **192.69** | **139.24** | **28.39** | 1 703 |
| cand-b | **198.06** | **143.16** | **29.15** | 1 703 |
| base-b | 222.93 | 154.28 | 43.41 | 1 942 |

| pair | wall ratio (cand/base) | campaign | finish/export | peak RSS |
|---|---:|---:|---:|---:|
| base-a → cand-a (`A B`) | 0.799 (−20.1 %) | −16.6 % | −40.4 % | −12.7 % |
| cand-b → base-b (`B A`, reversed) | 0.888 (−11.2 %) | −7.2 % | −32.8 % | −12.3 % |
| median of both repetitions | 231.96 → 195.37 s (−15.8 %) | 160.58 → 141.20 s (−12.1 %) | 45.52 → 28.77 s (−36.8 %) | 1 947 → 1 703 (−12.5 %) |

The first run (`base-a`) overlapped one 97 s software-only pytest from a background agent
(disclosed), which inflates the baseline; the **reversed, clean pair is the conservative result:
wall −11.2 %, campaign −7.2 %, finish/export −32.8 %, peak RSS −12.3 %**. Wall and process CPU
time move together (`host_cpu_seconds.self` 242.0 s vs 195.0 s in the first pair), so the gain is
work removed, not scheduling noise.

Per-case `submit` seconds (`cand-b` vs `base-b`), 8 cases:
`3.54,3.93,4.14,8.25,4.56,33.00,8.46,75.40` vs `4.05,4.33,5.40,9.06,5.78,34.95,9.16,79.71`.
Preparation/construct/begin are equal (≈5.0/5.7/3.9 s both sides), so the change is inside the
campaign and the export path, not in initialization.

## 3. Same-work proof (the A/B did not remove work)

All four runs executed exactly:

* 8 cases, flows `F1..F4 ×1, F5 ×2, F6 ×2`, 8 main / 9 session cases;
* **38 421 journal events** with identical per-kind counts;
* local ticks **CPU 977 / DMA 1010 / peripheral 1023**;
* native eval counts **CPU 3908 / DMA 4040 / peripheral 4092** (and eval seconds: CPU 8.4–8.8 ms,
  DMA 2.5–2.7 ms, peripheral 2.2–2.8 ms — the DUT work itself).

Cross-variant journal identity: after the runtime's own process-local normalization
(`_normalized_f6_prefix`), the only differing field in all 38 421 events × 4 runs is
`execution_binding_sha256` in 64 rows — the plan digest that pins the host source closure and is
*defined* to change when host code changes. Masking only that digest:
`sha256 = da01e4185790f2c0b7c05728eb6389e26d29f29a6acd1c8b676ef78ba3d63d64` in **all four**
runs (base-a, base-b, cand-a, cand-b). Whole-prefix documents differ only in the host-source
identity fields (`execution_binding_sha256`, `execution_binding.executor_source_closure_sha256`,
`trace_manifest_sha256`, `trace_genome_sha256`, `semantic_hash`), which is exactly why this is a
*source-version* A/B and not a same-binary switch: `plan_identity_sha256` changes by design.
Reproduction of the normalization/masking: see §6.

### 3.1 Change applied after the A/B (not in the numbers above)

The finish path read the session trace snapshot three times (comparison, source selection,
semantic hash) and each read of an `EventJournalSnapshot` detaches every row; at 38 421 events that
is three full journal-shaped copies at finish. After the A/B, the trace gate and the semantic hash
now iterate the snapshot's documented `_iter_borrowed()` and the trace document is no longer
materialised when the journal already is the trace material. Validation (not an A/B): a real
two-F6-case campaign with replay completed with `matches=true`, 14 921 events, ticks 385/424/408 and
eval counts 1540/1696/1632 — identical work to the recorded two-F6 reference — and the finish gate
that compares `trace.semantic_sha256` against `_trace_semantic_sha256(...)` passed, so the borrowed
hash is byte-identical to the detaching one. Its 7.4 s finish/export for two cases compares with
16.8–17.9 s recorded for the same two-case campaign before this round (different workload envelope:
that record excluded replay and predates the other changes here), so it is evidence, not an
isolated speedup claim. Output: `runs/host-ab-20261030/final-smoke/performance.json`.

## 4. Full eight cases **with** within-invocation replay
The candidate completed the full workload (campaign + finish/export + full fresh replay) in one
process:

| run | wall (s) | campaign (s) | finish/export (s) | replay (s) | peak RSS (MB) | replay |
|---|---:|---:|---:|---:|---:|---|
| `timed/cand-replay` | 415.66 | 140.69 | 29.15 | 214.18 | **3 077** | `matches=true`, scope `within_invocation` |

The same workload on the pre-change source exhausted this host's 7 GB in the previous session
(`docs/reports/journal-cache-campaign-ab-20261030.md` §1), so there is **no paired baseline replay
run**: this is a completion result plus one side's phase times, not a replay A/B. The replay half
re-executes the same eight cases in new processes (16 `submit` spans in the timing document) and
the fresh prefix matches the original after full normalization.

## 5. Where the remaining campaign time goes

From the same performance documents and the recorded profile
(`docs/reports/host-overhead-profile-20261030.md`):

1. **F6 case evidence dominates.** In `cand-b` the two F6 cases take 33.0 s and 75.4 s of a
   141.3 s campaign; the six other cases together take 33.3 s. The second F6 case alone costs
   75 s, and the same case at the *first* F6 position costs 33 s — the evidence path scales with
   the journal that precedes the case, which is the recorded profile's
   "47 % of the campaign is outside `runner_step`, concentrated in the two F6 cases". This round
   did **not** change that path: `compiled_f6_consumer.declared_edges` still does a whole-journal
   `read(0)` per F6 case (`≈1.8 s` at full size, and the fixtures that stub `runner` must be
   adapted before the borrowed reader can be used), and `capture_f6_case`/`_attempt_references`
   were deliberately left untouched. Making those case-scoped is the single largest next step.
2. **Wire/IPC host work is small; the roundtrip is not.** On a real recorded trace
   (`adapter-matrix-20261029/cv32-gpio-v1/original/local_commands.json`, 2 062 commands) the host
   stages of an already-received reply cost **0.292 s total** (hex 0.005, `json.loads` 0.055,
   `wire._payload` validation 0.164, sample `deepcopy` 0.067) — about **0.14 ms/command**. The
   same run recorded 13.2–13.8 s of `command_roundtrips`, so ≥95 % of a command's cost is the
   pipe roundtrip plus the driver's own per-command render/eval, not Python parsing. Batching IPC
   or relaxing the canonical-JSON guard therefore cannot recover that 13 s by itself; the
   optimizations that did pay off were the copy/scan ones above. Evidence:
   `runs/host-ab-20261030/wire-reply-cost.json` (`scripts/measure_wire_reply_cost.py`).
3. **Export is now render-bound, not copy-bound.** `finish/export` fell 45.5 → 28.8 s (median).
   What remains is the single pretty render of the 211 MB prefix (≈3.4 s at the recorded rate),
   the 398 MB replay render (≈6.5 s), the fresh runtime's own finish, and the normalized
   comparison (≈3 s + ≈3 s).
4. **DUT eval is still ~0.007 % of wall.** 13.4–13.5 ms of 195–242 s. Removing host work moves
   this share up only slowly: even with zero host overhead the eight-case DUT work is ~13 ms.
   The stated goal ("after initialization, most time is DUT progression") is not reachable by
   host micro-optimization of this execution model; it needs an execution model where the driver
   advances many ticks per host interaction (and evidence generation proportional to the case,
   not the session). This report does not claim progress on that goal beyond the measured
   −11 % wall.

## 6. Reproduction

```sh
# snapshots (baseline = pre-round copy, candidate = post-round copy)
# both: cp -a src scripts configs DEST/ ; cp -al third_party external_designs DEST/

REC='F3:55000000,F1:03200000,F4:0001000000,F5:0000000100000000,F2:08100040,F6:0110c00008000000,F5:0000000000000000,F6:0110c00008000000'
B=research/input-strategy-audit-20261027/runs/host-ab-20261030
for spec in "base-a:/tmp/myfuzz-baseline-0101:0" "cand-a:/tmp/myfuzz-candidate-0149:0" \
            "cand-b:/tmp/myfuzz-candidate-0149:0" "base-b:/tmp/myfuzz-baseline-0101:0"; do
  IFS=: read label root replay <<<"$spec"
  PYTHONPATH=src:. python3 scripts/bench_shared_flow_ab.py --output $PWD/$B/timed/$label \
    --cache $PWD/runs/config-driven-20261028/cache --base-root $root --records "$REC" --dut-eval
done
# full replay (candidate only; the pre-change source cannot hold this workload on this host)
PYTHONPATH=src:. python3 scripts/bench_shared_flow_ab.py --output $PWD/$B/timed/cand-replay \
  --cache $PWD/runs/config-driven-20261028/cache --base-root /tmp/myfuzz-candidate-0149 \
  --records "$REC" --dut-eval --replay
# wire-stage measurement
PYTHONPATH=src:. python3 scripts/measure_wire_reply_cost.py \
  --trace research/input-strategy-audit-20261027/runs/adapter-matrix-20261029/cv32-gpio-v1/original/local_commands.json \
  --output $B/wire-reply-cost.json
```

Cross-variant journal identity (`da01e418…` in all four runs) is recomputed with
`_normalized_f6_prefix({'actual_events': prefix['actual_events'], 'original_execution_audit':
prefix['original_execution_audit']})`, masking `execution_binding_sha256`, and hashing the
canonical JSON.

## 7. Not claimed

* No strategy, coverage or vulnerability conclusion.
* The reversed-pair −11.2 % is two repetitions on one host; `base-a` was contaminated by a
  concurrent software test, so the headline uses the clean reversed pair. Nothing here
  extrapolates to other workloads or to the 2-F6 subset (where the journal-cache A/B already
  showed a different −9.2 % wall).
* No replay A/B: the pre-change source could not complete the workload on this host, and the
  candidate's 3.08 GB peak is not an upper bound for other configurations.
* No claim that IPC batching was tried or would help; §5.2 measures only the host-side reply
  stages.
