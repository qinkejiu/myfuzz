# Host-side overhead profile of the steady-state per-case path

2026-10-30. Read-only analysis: no campaign, no RTL, no source edit. Every number below is
either (a) copied from an existing recorded artifact with its path, or (b) produced by a short
CPU-only Python measurement of a **pure host function on real artifacts** and then extrapolated
with the stated rate. Extrapolations are labelled `[rate-extrapolated]` and are **not** claimed
speedups: nothing here was re-run end-to-end.

Reference workload for all per-run arithmetic: the fixed eight-case shared A/B
`F3,F1,F4,F5,F2,F6,F5,F6` (`scripts/run_shared_all_flows.py:11`) as recorded in
`research/input-strategy-audit-20261027/runs/shared-performance-20261029/tail-v1/`.

---

## 1. Measured phase breakdown available today

### 1.1 Recorded runs

`…/shared-performance-20261029/{legacy-v1,snapshot-v1,tail-v1}/performance.json`

| metric (s) | legacy-v1 | snapshot-v1 | tail-v1 |
|---|---:|---:|---:|
| wall (`wall_seconds`) | 724.701 | 493.848 | 481.956 |
| campaign loop (`execution_seconds`, `campaign_loop_only`) | 248.372 | 155.593 | 149.976 |
| finish/export (`finish_export_seconds`) | 47.608 | 46.520 | 46.020 |
| within replay+export (`replay_seconds`) | 397.272 | 269.347 | 254.396 |
| `finish` (span) | 39.511 | 38.931 | 38.463 |
| `construct` | 14.778 | 6.029 | 14.974 |
| `preparation` | 3.961 | 4.158 | 3.961 |
| `begin` | 5.105 | 5.075 | 5.100 |

`comparison-v1.json` records `wall_ratio_candidate_over_baseline = 0.68145`, `equivalent: true`,
`first_prefix_difference: null`, identical normalized prefix SHA256
`ce6d4150…42f457`, and `"timing_scope": "same recorded work; inclusive spans overlap and must not be added"`.

**Work invariant actually measured in these runs** (`workload_identity` in
`src/myfuzz/integration/runtime_benchmark.py:104`): 8 main cases / 9 session cases,
CPU/DMA/GPIO ticks `977/1010/1023`, journal events `38421`, native eval counts
CPU `3908`, DMA `4040`, GPIO `4092` — identical on both sides of the A/B.

### 1.2 What `tail-v1` says about where the campaign loop goes

Aggregated from `tail-v1/performance.json` (`runtime_inclusive`, invocation `original`):

| span | sum (s) | count | mean |
|---|---:|---:|---:|
| `scheduler_batch` | 86.166 | 2791 | 30.9 ms |
| `runner_step` | 82.409 | 2918 | **28.2 ms** |
| `router_drain` | 1.025 | 23 | 44.6 ms |
| `observed_output_route` | 0.112 | 6020 | 19 µs |

`calls` → the eight `submit` spans sum to **147.616 s** (campaign `execution_seconds` 149.976 s),
split by case (`submit` is `CompiledF6Runtime.submit`, one per case):

| case | flow | submit (s) | nested `runner_step` (s) | steps | ms/step | outside step (s) | outside % |
|---:|---|---:|---:|---:|---:|---:|---:|
| 0 | F3 | 5.467 | 4.006 | 208 | 19.3 | 1.462 | 27 % |
| 1 | F1 | 5.848 | 4.116 | 208 | 19.8 | 1.732 | 30 % |
| 2 | F4 | 6.526 | 4.280 | 209 | 20.5 | 2.246 | 34 % |
| 3 | F5 | 11.768 | 9.605 | 466 | 20.6 | 2.164 | 18 % |
| 4 | F2 | 7.163 | 4.157 | 208 | 20.0 | 3.005 | 42 % |
| 5 | **F6** | 38.809 | 18.439 | 481 | **38.3** | **20.370** | 52 % |
| 6 | F5 | 12.441 | 9.748 | 466 | 20.9 | 2.692 | 22 % |
| 7 | **F6** | 59.594 | 24.284 | 481 | **50.5** | **35.309** | 59 % |
| Σ | | **147.616** | **78.635** | **2727** | | **68.981** | 47 % |

Two facts fall out of this table and drive the whole ranking:

1. **47 % of the campaign loop is outside `runner_step`** — that is per-case evidence/exit work
   (`capture_f6_case`, `_attempt_references`, `_freeze_f6_case`, protocol-checker report,
   online-session receipt), and it is concentrated in the two F6 cases (55.7 s of 69.0 s).
2. **The per-step cost grows with journal size only along the F6 chain**: cases 0–4 and 6 sit at
   19–21 ms/step regardless of their position, while F6 case 5 is 38.3 ms/step and F6 case 7
   (≈4.8 k more journal events) is 50.5 ms/step, i.e. **+12.2 ms per case-slot of journal growth**.

### 1.3 Command roundtrips (measured, nested inside `runner_step`)

`tail-v1/performance.json` → `command_roundtrips`, original invocation:

| command | count | sum (s) | mean | max |
|---|---:|---:|---:|---:|
| `STEP_GPIO` | 971 | 9.169 | 9.44 ms | 144.6 ms |
| `STEP_CPU` | 977 | 2.417 | 2.47 ms | 3.4 ms |
| `STEP_WB_DMA` | 1010 | 0.810 | 0.80 ms | 1.3 ms |
| `ACCESS_GPIO` | 13 | 0.212 | 16.3 ms | 109.7 ms |
| Σ | 2971 | **12.61** | | |

So of the 82.4 s `runner_step` total, **12.6 s (15 %) is the marshalled command roundtrip** and
**≈69.8 s (85 %) is Python-side per-step bookkeeping**. `STEP_GPIO` totals 9.17 s over 971 calls
while the whole RTL eval of the run is 0.0257 s: this command is the slowest wire operation and
its `max` (144 ms) is 15× its mean, so its distribution — not its median — dominates.

### 1.4 Export volume per run (byte-exact, from the artifact directory)

`tail-v1/workload/original/`:

| file | bytes |
|---|---:|
| `prefix.json` | 211 425 765 |
| `compiled_f6_prefix.json` | 211 425 765 (**identical content**) |
| `replay.json` | 397 873 205 |
| `shared_read_raw.json` | 56 716 |
| `shared_storage_raw.json` | 2 644 |
| `binding.json` | 372 584 |

Section sizes inside `prefix.json` (streamed line scan, 2.5 s):

| section | MB | `event_id` rows |
|---|---:|---:|
| `actual_events` (the whole Runner journal, `indent=2`) | **169.82** | 42 988 |
| `assertion_material` | 20.31 | 3 880 |
| `attempts` | 19.43 | 3 880 |
| `original_build` | 0.64 | 0 |
| `execution_binding` + rest | 0.6 | 12 |

`replay.json` = `actual_prefix` (211.4 MB) **+** `actual_events` (169.8 MB, the same journal a
second time) + `fresh_build`/`execution_audit`. The `actual_events` section alone is 5 588 681
lines for 38 421 events (≈145 lines per event, file total 6 537 015 lines) because the whole
document is rendered with `indent=2`.

**Write amplification today: 211.4×2 + 397.9×2 = 1 218.6 MB written per run for ≈605 MB of
distinct content.**

### 1.5 Which numbers are comparable

* Comparable, same-source A/B: `snapshot-v1` vs `legacy-v1` (identical `plan_identity_sha256`,
  identical normalized-prefix SHA256, identical eval counts). `tail-v1` changed host source
  (`plan_identity_sha256 10bc7e51…`) so **its wall must not be compared with the other two**
  (`docs/reports/shared-performance-public-entry-acceptance-20261029.md:44`).
* Comparable across runs: tick counts, event counts, per-command counts, `native_eval` counts/ns,
  and the byte sizes of exported documents.
* **Not** comparable / not additive: `execution`, `finish_export`, `replay`, `construct`, `begin`
  are enveloping spans (`timing_semantics: inclusive_not_additive`); `runner_step` and
  `scheduler_batch` overlap each other; command roundtrips are nested inside `runner_step`;
  `router_drain` is nested too. `wall − Σ(spans)` is not a measured quantity.
* `native_eval.runtime_eval_ns` covers `eval()` only — not process, IPC, parse, or host checks.
  Subtracting it from wall does **not** give "Python time" (the 20261029 report says the same).

---

## 2. Ranked host-side cost sites

Ranking rule: measured-or-rate-extrapolated seconds per eight-case run, discounted by semantics
risk. All timings below are for the `tail-v1` original invocation (campaign 150.0 s, finish
46.0 s, replay 254.4 s) and are **inclusive**, so they must not be summed with each other or with
the phase spans.

### 0. (Measurement gap, not yet a code site) ≈69.8 s of per-step Python inside `runner_step`

*Where*: `src/myfuzz/scenario/runner.py:1574` (`step`) → `1588` (`step_batch`) →
`3407` (`_execute_step`) → `1787` (`_step_once`) → `2529` (`_drain_tick_samples`) →
`2002` (`_route_observed_outputs`) → `2857` (`_append_external_events`).
*Evidence it exists*: 82.4 s of `runner_step` minus 12.6 s of measured command roundtrips.
*Evidence that part of it is a journal-cache pathology* (host-only measurement, real 3.6 KB
events, 38 421-event `EventJournal` from `src/myfuzz/scenario/event_journal.py:24`):

| access pattern per step | measured per step | over 2727 steps |
|---|---:|---:|
| tail slice only (`events_since(cursor)`, as `_drain_observer_view` does) | 1.83 ms | 5.0 s |
| tail slice **+ 3 lookups of old `event_id`s** | **75.96 ms** | **207 s** (measured pattern) |

`EventJournal._chunk` (`event_journal.py:56-64`) caches exactly **one** chunk and reloads it with
`pickle.load` on every miss; a single historical read (`EventJournal.__getitem__` →
`_chunk(divmod(index, 2048)[0])`) costs a full 2048-event unpickle. Measured: 27.8 ms per chunk
load, 0.53 s for the whole journal. Any code that touches an old `event_id` while the tail is
being drained alternates between two chunks and pays 2 loads per step.
*Historical readers that do exactly that*: `src/myfuzz/scenario/f6_instruction_fetch_receipt.py:694-699`
(`event(event_id)` → `runner._event_ref_by_id`, 7–8 times per F6 fetch completion, called from
`_drain_tick_samples` at `runner.py:2649`), `runner.py:2015` (`_event_ref_by_id` in
`_route_observed_outputs`), `runner.py:861`/`866`, `runner.py:2529-2650` drains.
*Proposal*: instrument before changing anything — (i) count `EventJournal` chunk reloads per step
(harness-level monkeypatch counter is not allowed by the read-only rule; add a product-level
counter or use `sys.monitoring` on `_chunk` in the benchmark script), (ii) add
`@timed_runtime_call` labels for `_step_once` sub-phases, `_drain_tick_samples`,
`_drain_observer_view`, `capture_f6_case`, `_attempt_references`, `_freeze_f6_case`. Only after
that attribution should the cache policy be changed (candidate: keep the tail chunk pinned plus a
bounded LRU, or route historical reads through an in-memory index of the current case).
*Semantics risk*: none for instrumentation; the eventual cache change is read-path only.
*Same-work invariant*: journal contents, `event_id` sequence, and every consumer's result must be
byte-identical; `EventJournalSnapshot.__eq__`/iteration order unchanged.
*How to verify no work was reduced*: recorded `event_count`, per-kind `Counter` of journal kinds,
and `semantic_hash` unchanged; add a counter asserting the number of events **appended** is equal
on both sides.

### 1. Whole-journal `deepcopy` on the per-case evidence path — ≈10–13 s per invocation

*Sites* (each returns `deepcopy(tuple(...))` from `runner.py:846`):

| site | what it copies | per case |
|---|---|---|
| `src/myfuzz/integration/shared_slot_consumers.py:87` `events_since(0)` | whole journal | once per F1/F2/F3/F5 submit (6 of 8 cases) |
| `src/myfuzz/integration/shared_f6_slots.py:289` `events_since(0)` | whole journal | once per F4 submit |
| `src/myfuzz/integration/compiled_f6_consumer.py:2037` (`declared_edges`) `read(0)` | whole journal | once per F6 case |
| `src/myfuzz/integration/compiled_f6.py:2333` (`_case_boundary_stop_ready`) `events_since(0)` | whole journal | once per advance **after** the pending-fetch latch opens |
| `src/myfuzz/integration/compiled_f6_consumer.py:644`, `:1947`, `src/myfuzz/scenario/session_runtime.py:2018` | journal slice from case start | once per F6 case / once per case (receipt) |
| `src/myfuzz/integration/shared_irq_firmware.py:131`, `:263` | whole journal, **borrowed** (`_borrow_exact_events`) | 2× per F5 case (no copy, but two full unpickle passes + `by_id` dict + full scans) |

*Why it is O(n) per case, i.e. O(cases × events) per run*: the journal grows monotonically
(≈4.8 k events per case); case *k* copies *k*/8 of the final journal. Measured copy cost:
`unpickle 0.53 s + deepcopy 2.05 s = 2.58 s` at 38 421 events (53.2 µs/event measured on 2857
real events). Summed over cases 0–7 → **≈5.6 s** for the flow consumers + **≈3.6 s** for the two
F6 `read(0)`s + ≈1 s of partial slices ≈ **10–13 s** `[rate-extrapolated]`, and the same again in
the fresh replay (the whole campaign re-executes) → **≈20–26 s per run**.
*Proposal*: give these read-only consumers the already existing borrowed reader
`ScenarioRunner._event_refs_since` (`runner.py:848-859`, pinned by
`compiled_f4._borrow_exact_events`, `src/myfuzz/integration/compiled_f4.py:38-43`) instead of the
detaching `events_since`. The consumers only read and never retain (they are the same functions
that already use `_borrow_exact_events` today), and `_saved_projection_inputs`/`remember` already
detach whatever they keep. Alternative with the same effect and lower risk surface: add one
**case-scoped pinned snapshot** per case (a `tuple` of borrowed refs) and pass it down, so a case
pays one unpickle pass instead of three.
*Semantics risk*: medium-low. Risk is limited to a consumer mutating or outliving the borrowed
record. Mitigation: keep the existing "no mutate, no retain, detach outputs" rule that
`_event_refs_since`'s docstring already states, and add an assertion in tests that no consumer
writes into a record (e.g. run the suite with a read-only mapping wrapper).
*Same-work invariant*: every consumer must see the same rows in the same order and produce the
same certificates/`semantic_hash`; `event_count` unchanged.
*Verification*: identical normalized-prefix SHA256, identical `event_kind_counts`, identical
`local_ticks`, identical `semantic_hash`, identical failure messages on the negative fixtures
(there are fixtures that assert the exact `RuntimeError`/`_Contradiction` strings — those strings
encode row fields, so they also prove the borrowed rows are the same objects' values).

### 2. `finish()` export chain: whole-document copies + journal re-serialization for trace checks — ≈8–11 s of the 38.5 s finish body

`tail-v1`: `finish` call = 38.463 s, `finish_export_seconds` = 46.020 s, so the four `_json`
writes in `shared_slots.py:132-135` account for ≈7.5 s (see item 4) and the body is ≈38.5 s.

| site | operation | measured/extrapolated |
|---|---|---|
| `compiled_f6.py:2815` `('events', lambda:list(self.runner.events_since(0)))` | full journal copy | 2.58 s |
| `compiled_f6.py:2998-2999` `deepcopy(exports['assertion_material'])` + `deepcopy(exports['events'])` | 20.3 MB + whole journal | 0.17 + 2.05 s |
| `compiled_f6.py:3010` `self._finish_document = deepcopy(result)` | whole 211 MB prefix | ≈2.3 s |
| `compiled_f6.py:3034` `return deepcopy(self._finish_document)` | whole 211 MB prefix | ≈2.3 s |
| `compiled_f6.py:648-717` `_f6_trace_failure`: `events_since(0)` at 680, `_canonical(list(trace.events)) != _canonical(list(event_snapshot))` at 691, `_trace_semantic_sha256(...)` at 701 | one full journal copy + **three** full journal serializations | 2.58 + 3×0.75 s |
| `compiled_f6.py:2813` `json.loads(self.session.encode_plan())` | plan re-parse | <0.05 s |

*Why O(n)*: every one of these is a whole-document transform whose output is only read
afterwards. `deepcopy` measured at 51 MB/s of compact size; compact canonical `json.dumps` at
143.6 MB/s; the journal is ≈65 MB compact.
*Proposal*: single-ownership handoff instead of four defensive copies:
(i) `_finish_once` stores `actual_events` **by reference** — the Runner journal is append-only and
frozen after `finalize()`, and no caller mutates it (all callers either serialize it or pass it to
pure readers); (ii) `_finish_document` owns the document and `finish()` returns it **without**
`deepcopy` once `self.finished`, or returns a shallow copy of the top level only; (iii)
`_f6_trace_failure` compares `trace.events` and the journal by structural equality (see item 6)
instead of serializing both, and reuses the `semantic_sha256` that `session.trace()` already
computed rather than recomputing it (it recomputes at 701 to prove the same value).
*Semantics risk*: medium. Aliasing is the only risk; the document is read-only after finish, but
that is currently an accident of discipline, not enforced. Mitigation: freeze the top-level dict
into a small read-only wrapper for tests, or add a `_deepcopy_guard` used by the test suite.
*Same-work invariant*: `prefix.json` bytes identical (same key order/sort, same values);
`semantic_hash`, `manifest_sha256`, `trace_genome_sha256` identical.
*Verification*: byte-compare regenerated `prefix.json`/`replay.json` against the recorded
`tail-v1` artifacts; assert `sha256` of both equals the artifact; assert `workload_identity()`
(tick/event/eval counts) is unchanged.

### 3. `replay()` whole-document copies — ≈10 s, plus one copy that is immediately discarded

`src/myfuzz/integration/compiled_f6.py:3039-3148`:

| line | operation | measured/extrapolated |
|---|---|---|
| 3041 | `expected = self.finish()` → `deepcopy(self._finish_document)` (`3034`) | ≈2.3 s |
| 3042 | `_canonical(prefix) != _canonical(expected)` → two 81 MB compact renders | ≈1.1 s + ≈160 MB transient strings |
| 3083 | `envelope['actual_prefix'] = deepcopy(actual)` | ≈2.3 s |
| 3084 | `envelope['actual_events'] = deepcopy(actual.get('actual_events') or [])` | 2.05 s |
| 3122 | `('actual_events', lambda:list(fresh.runner.events_since(0)))` **overwrites 3084** | 2.58 s |
| 3131-3132 | `deepcopy(fresh_shared_storage_raw/read_raw)` | <0.1 s |
| 3135 | `audit_sink(deepcopy(envelope))` | ≈3.0 s |

Line 3084 is pure waste: the value it installs is unconditionally replaced 38 lines later by
3122. Removing it is a one-line change with zero semantic effect.
*Proposal*: (i) delete 3084; (ii) share `actual` (already the freshly-built document) instead of
copying it at 3083; (iii) build the envelope's journal reference from `fresh.runner` once;
(iv) replace 3135's `deepcopy(envelope)` with an immutable-handoff contract identical to item 2.
*Semantics risk*: low for (i), medium for (ii)/(iv) as in item 2.
*Same-work invariant / verification*: as item 2; additionally `first_difference` and `matches`
must be produced by the same comparison, and `replay.json` must stay byte-identical.

### 4. The same document is rendered twice to two paths — ≈9.9 s `[rate-extrapolated]`

* `src/myfuzz/runtime/flows/shared_slots.py:132-133`: `_json(prefix, 'prefix.json')` and
  `_json(prefix, 'compiled_f6_prefix.json')` — the **same dict** rendered twice.
* `shared_slots.py:142` `audit_sink=lambda value: _json(value, out/'replay.json')` **and**
  `shared_slots.py:143` `_json(replay, out/'replay.json')` — `replay()` calls the sink once
  (`compiled_f6.py:3133-3137`) and the caller then writes the returned envelope again.

`_json` (`src/myfuzz/runtime/generic_campaign.py:213-218`) is
`json.dumps(value, indent=2, sort_keys=True, default=str) + '\n'` and `path.write_text(...)`.
Measured on a real 20.3 MB section of `prefix.json`: **61.6 MB/s** for `indent=2, sort_keys=True`
(vs 143.6 MB/s compact), ratio pretty/compact **2.60**. Therefore
`prefix.json` ≈ 3.43 s/render and `replay.json` ≈ 6.46 s/render → 2×3.43 + 2×6.46 = **19.8 s of
rendering per run, 9.9 s of it duplicate**. Cross-check: `finish_export 46.02 − finish 38.46 =
7.56 s` for two 211 MB renders + two tiny files (predicted 6.9 s) — the measured rate is
consistent with the artifact.

*Proposal*: render once, write twice —
`text = json.dumps(...); (out/'prefix.json').write_text(text); (out/'compiled_f6_prefix.json').write_text(text)`
(or `write_text` then `os.link`/`shutil.copyfile`) for both pairs. Keep `indent=2, sort_keys=True`
byte-for-byte; only the number of renders changes.
*Semantics risk*: **very low** — the two files must remain byte-identical (they already are:
211 425 765 bytes each), and no consumer distinguishes them.
*Same-work invariant*: `prefix.json` and `compiled_f6_prefix.json` SHA256 unchanged; `replay.json`
SHA256 unchanged; the command/export accounting at `shared_slots.py:179` still charges the work to
`finish_export_seconds`.
*Verification*: SHA256 of all three files must equal the recorded values before/after; and a
negative test that a deliberate divergence between the two documents is still detected (there is
validator code that reads `compiled_f6_prefix.json`).

### 5. `_normalized_f6_prefix` ×2 + `_first_difference` full walks — ≈4–6 s

`compiled_f6.py:3098-3099` calls `_normalized_f6_prefix(expected)` and
`_normalized_f6_prefix(actual)`; each runs `_project_process_local`
(`src/myfuzz/integration/compiled_f4.py:93-102`, a Python-level recursive rebuild measured at
**85 MB/s** compact) plus the execution-token/commit-id rewrite walk, then `_first_difference`
(`compiled_f6.py:157-185`) walks both trees in parallel until it finds a difference — and when
they are equal it walks **everything**, recursively, in Python.
*Proposal*: build each normalized tree once (they are needed for the diff only), and replace the
recursive diff with a canonical streaming comparison: iterate `canonical_json_chunks`-style
segments (already implemented in `src/myfuzz/scenario/event_journal.py:132`) over both trees and
stop at the first differing segment, materializing the `path` from the segment position. This
keeps the exact "first difference" semantics (it is the same lexical order as `_canonical`) and
avoids two extra 211 MB trees.
*Semantics risk*: medium — `first_difference`'s reported `path`/`expected`/`actual` structure is
consumed by acceptance reports; a streaming version must reproduce the same `$.a.b[3]` paths.
*Same-work invariant*: `matches` and `first_difference: null` for the recorded workload.
*Verification*: replay the saved `prefix.json` and `replay.json.actual_prefix` through both
implementations and assert identical `first_difference` on a set of mutated fixtures (mutate one
field at several depths, including list-length changes at 173-180).

### 6. `json.dumps` used as an equality oracle on whole documents — ≈4.4 s

| site | expression | cost |
|---|---|---|
| `compiled_f6.py:691` | `_canonical(list(trace.events)) != _canonical(list(event_snapshot))` | 2 × 0.75 s |
| `compiled_f6.py:2969-2970` | `_canonical(raw_trace_events) == _canonical(actual_events)` | 2 × 0.75 s |
| `compiled_f6.py:3042` | `_canonical(prefix) != _canonical(expected)` | 2 × 0.57 s |

(`_canonical` at `compiled_f6.py:41-43` = `json.dumps(sort_keys=True, separators=(',',':'))`;
compact measured at 143.6 MB/s; journal ≈65 MB compact, prefix ≈81 MB compact.)
*Proposal*: compare digests that are already computed for the same objects, or compare
structurally. Since all three sites compare documents that came from the same producer, `==`
is at least as strict for these shapes; the only divergences are tuple-vs-list and int-vs-float
normalization inside the JSON encoder.
*Semantics risk*: **medium-high** — that is exactly why this sits below the copy/duplication
items. Recommended compromise that is strictly semantics-preserving: keep one canonical render per
**top-level section** (`{k: _canonical(v)}` per section, compared section by section), which cuts
peak transient memory from 2 × 300 MB to 2 × a few MB and allows early exit at the first
differing section, without changing what "equal" means.
*Same-work invariant*: the three checks must still fail on the same mutations they fail on today.
*Verification*: property test `(a == b) == (_canonical(a) == _canonical(b))` over the saved
`prefix.json` plus targeted tuple/nan/float fixtures, before switching any site to `==`.

### 7. Per-event `deepcopy` at journal append — ≈1.5–2.0 s per invocation

`src/myfuzz/scenario/event_provenance.py:21-60`: `decorate()` starts with
`result = deepcopy(record)` for **every** appended event, called from
`src/myfuzz/scenario/runner.py:733-741` (`_decorate_provenance`) via `_EventLog.append`
(`runner.py:160-177`). 38 421 events per invocation; measured `deepcopy` 53.2 µs on a real 3.6 KB
event → 2.05 s.
*Proposal*: the decorator only adds/derives top-level keys (`provenance`, `edge_candidates`,
`resource`, …) and already selectively deep-copies the few nested values it rewrites (`:60`).
A shallow `dict(record)` plus copies of only the mutated sub-values preserves the documented
contract ("the supplied record is never modified").
*Semantics risk*: low-medium — the contract is about *not mutating the input*; it does not require
the output to be detached from all input sub-objects, but downstream code may rely on it by
accident.
*Same-work invariant*: every event's serialized bytes unchanged (this is directly checkable on the
recorded `actual_events`).
*Verification*: byte-identical `actual_events` in `prefix.json`; plus a test that mutating the
caller's record after append does not change the journal (run under `-X dev` with a
mutation-detecting wrapper).

### 8. `_saved_projection_inputs` and `remember()` JSON round-trips — ≈2–3 s

* `src/myfuzz/integration/compiled_f6_consumer.py:452-455`: `json.loads(_json(list(events)))` — a
  full journal compact render + parse per F6 case (≈0.75 s + ≈0.2 s, ×2 cases, ×2 invocations),
  plus `{key: json.loads(_json(row)) ...}` for every Observer row (1 656 rows in the whole
  prefix; measured 34.5 µs/row → ≈0.06 s per case).
* `:719` `remember()`: `json.loads(_json(row))` for **each** referenced journal row.
* `:2166` `return json.loads(_json(material))` — one full render+parse of the case material.
* `:2161` `sha256(_json(dict(scope, …, details=details, …)))` — 5 renders of the case detail
  document per case.
*Proposal*: keep the JSON value-domain conversion **only** where the value is written to disk;
for internal comparisons reuse one conversion per journal snapshot (compute
`events = json.loads(_json(...))` once per case and pass it down — it already is passed down for
`declared_edges`), and replace `remember()`'s per-row round-trip with `copy.deepcopy`.
*Semantics risk*: medium — the round-trip also normalizes tuples to lists; a `deepcopy` would leave
tuples in place and change `_json(row) == _json(expected)` comparisons downstream. So only the
`remember()` change is safe in isolation; the rest should keep the conversion but do it once.
*Same-work invariant*: identical `evidence_inventory` keys (they are `sha256` over canonical
JSON), identical `raw_evidence`.

### 9. `_jsonable` per observed row and per-step `events_since(cursor)` — <1 s, but wrong-shaped

* `src/myfuzz/integration/compiled_f6.py:1749-1757` `_jsonable` is a Python recursion with a
  `hasattr` check per node, applied in `_append_observer` (`:1759-1770`) to every observed row;
  `compiled_f6.py:1983-1987` calls it per CPU step for `request['transaction']` inside
  `_capture_f6_pending_fetch_sample`.
* `compiled_f6.py:1878-1905` `_drain_observer_view` calls `events_since(cursor)` once per
  component step and deep-copies the new tail (measured tail-slice path 1.83 ms/step — see item 0
  — of which the `deepcopy` of ~14 events is ≈0.74 ms).
* *Proposal*: `copy.deepcopy` where the input is already JSON-safe, and keep one conversion per
  row; when item 0's instrumentation lands, re-measure — the tail-drain design is already the
  "pinned tail" shape and should not be changed twice.
* *Semantics risk*: low. *Invariant*: same observer row count and bytes.

### 10. Wire-level reply validation (do **not** change first)

`src/myfuzz/local_harness/wire.py:130-186` `_payload` performs, per command, `bytes.fromhex` →
`json.loads(object_pairs_hook=_unique_object)` → `_valid_signal_json` recursion →
`json.dumps(sort_keys, separators)` and compares to the raw bytes (`noncanonical-driver-json`).
That is three full passes over every reply to prove the driver emitted canonical JSON. At 2 971
commands with small payloads this is ≈0.5–0.9 s per invocation `[rate-extrapolated, small payload
not isolated]`. It is a **semantic** guard (it rejects a driver that is not canonical), so it is
listed only to be measured, not changed; if item 0's instrumentation shows it is large, the
semantics-preserving direction is a single-pass scanner that verifies canonicality token by token
without materializing the re-render.
Also per command: `session.py:616-655` runs `_check_built_mode`, the native-reset owner guard, the
storage-authority probe, and a `time.monotonic()` pair; `session.py:734-757` writes a text line and
reads a line (line-buffered `bufsize=1` pipes).

### 11. Journal scans that are already borrowed but still O(n) per case — ≈1–2 s

`src/myfuzz/integration/shared_irq_firmware.py:248-330` `observe_irq_isr` →
`_borrow_exact_events` (`:263`) builds `by_id` over the whole journal and then
`collect_native_obi_beats` (`src/myfuzz/integration/native_obi_hops.py:21-49`) makes a full pass
per channel, and `verify_instruction_fetches` (`:58`) does `[e for e in events if …]` per
functional offset (7×). Per F5 case; 2 F5 cases × 2 invocations. The records are borrowed (good),
but each call still pays a full unpickle pass (0.53 s at final size) and full-array scans.
*Proposal*: pass the same borrowed snapshot down (one per case) and replace the per-offset scans
with a single indexed pass keyed by `(kind, component, address)`.
*Semantics risk*: low. *Invariant*: identical `certificates`, identical `irq_isr.status`.

---

## 3. Measurement plan for the later same-source A/B

**Mode discipline.** Same plan identity (`plan_identity_sha256`), same `RECORDS`, same
`rounds_per_case=1024`, same fetch-scan mode, same output layout. One variable changes per A/B.

**Counters to record, per invocation and per case.** These already exist; make them
first-class acceptance rows rather than report prose:

1. `native_eval.{original,fresh}.{cpu,dma,peripheral}`: `runtime_eval_count`,
   `runtime_eval_ns`, `startup_eval_count`, `startup_eval_ns` (from
   `…/native-eval/dut-timing-*.json`, `schema_version dut_eval_timing.v1`). These must be
   **equal on both sides** — they are the DUT work.
2. `trace_local_ticks` per component; `event_count`; per-`kind` `Counter` of journal events;
   `semantic_hash`. (`workload_identity`, `runtime_benchmark.py:104-120`.)
3. Per-command counts by operation (`STEP_CPU`, `STEP_GPIO`, `STEP_WB_DMA`, `ACCESS_*`) —
   from `command_roundtrips[].count`. Counts must be equal; only seconds may move.
4. Host CPU time by phase, not just wall: `time.process_time()` (this process) and
   `resource.getrusage(RUSAGE_SELF).ru_utime/ru_stime` at the same boundaries as
   `execution_seconds`, `finish_export_seconds`, `replay_seconds`, plus peak `ru_maxrss`.
   Wall alone cannot distinguish "host did less work" from "host waited less".
5. New spans required before any further optimization is claimed (currently **missing**, which is
   why item 0 is unattributed): `capture_f6_case`, each of its five expectation calls
   (`protocol`, `cross`, `configuration`, `words`, `irq_completion`), `_attempt_references`,
   `_freeze_f6_case`, `_assemble_f6_protocol_checker_case_report`, `_build_f6_assertion_material`,
   `session.trace`, `_f6_trace_failure`, `_normalized_f6_prefix`, `_first_difference`,
   `_step_once` (as 4 sub-labels: command, append, tick-drain, external-append),
   `_drain_observer_view`, and an `EventJournal` chunk-reload counter.
6. Bytes and renders: `len(prefix.json)`, `len(replay.json)`, SHA256 of each written document,
   and a render counter per document (should go 2→1 for the duplicated pairs).

**Separating init / cold-cache effects.**

* Report `preparation + construct + begin` as their own row and require them to be **equal** (they
  are 3.96 + 14.97 + 5.10 = 24.0 s in `tail-v1`; that is 5 % of wall and it is not the target of
  this work). If they move, the A/B is invalid.
* Warm the build/artifact cache **before** each measured repetition and record whether the cache
  was hit (`construct` seconds are the tell: 14.97 s warm vs 6.6 s for the fresh build in
  `tail-v1`, so the two are distinguishable).
* Interleave: `A B A B A B` (≥3 repetitions each), same host, same cwd, no concurrent jobs;
  report median and min, plus the per-case matrix from §1.2. Discard the first repetition of each
  mode. Never run all A's then all B's — the `legacy-v1`/`snapshot-v1` pair was sequential, which
  is exactly the weakness the 20261029 report itself flags.
* Report the measurement overhead: `RuntimeTimings.observe` installs `sys.monitoring` local events
  on 7 functions; measure wall with and without the observer for one mode and report both.

**What would falsify an improvement.**

1. Any decrease in `runtime_eval_count`, `local_ticks`, `event_count`, per-kind event counts, or
   per-command counts → invalid, regardless of wall.
2. Any change in normalized-prefix SHA256, `semantic_hash`, `first_difference` (must stay `null`),
   or a change in the owner/binding digests → invalid.
3. Wall improves while total host CPU time (`ru_utime+ru_stime`) does not → the gain is
   scheduling/ordering noise, not work removed.
4. The named phase does not improve but another phase grows by a similar amount (work moved rather
   than removed) → not an improvement; report net only.
5. Any file that must exist is smaller, missing a section, or fails its own validator
   (`_f6_export_failure`, `_f6_trace_failure`, `verify_compiled_f6_build_join`) → invalid.
6. A single run in either direction; require the median of ≥3 interleaved repetitions and require
   the direction to hold for the per-case F6 rows specifically (they carry 55.7 s of the 69.0 s of
   out-of-step cost).
7. Improvement that disappears when the fresh-replay half is excluded → the campaign-loop claim is
   false even if wall moved.

---

## 4. Things NOT to do

1. Do not reduce cases, rounds, `rounds_per_case`, ticks, or the number of advances. The recorded
   work is the acceptance criterion (`977/1010/1023` ticks, `38421` events, eval counts
   `3908/4040/4092`).
2. Do not stop recording events, tick samples, protocol-checker samples, or receipts "because they
   are big". The 169.8 MB `actual_events` **is** the evidence; its size is not an overhead item,
   only its repeated copying is.
3. Do not drop, truncate, sample, or deduplicate `actual_events`, `attempts`, `raw_evidence`,
   `raw_references`, or `evidence_inventory`.
4. Do not defer a required proof to a later phase, a background thread, or a post-run script and
   count the deferred time as saved. Moving cost out of `execution_seconds` into `replay_seconds`
   is not a gain.
5. Do not change the on-disk format (`indent=2`, `sort_keys=True`), key sets, or file names. The
   documents are identity-bound by SHA256 in manifests and by `_normalized_f6_prefix`; a reformat
   would invalidate every recorded hash and every prior A/B.
6. Do not weaken `noncanonical-driver-json`, the provenance/sha chains, the checker trace-set
   digest, or any `_require`/`_present` in the evidence consumers to save time.
7. Do not make `events_since` return borrowed records to *public* callers. The borrowed path exists
   (`_event_refs_since`) and is deliberately restricted; widening it without the "no mutate, no
   retain, detach outputs" discipline is a correctness regression waiting to happen.
8. Do not enable/disable `evidence`-metering or the resource budget as an optimization: for this
   workload `arm_evidence_meter` is **not** armed (it is only reached through
   `src/myfuzz/scenario/evidence.py:689,951`), so `_count_evidence_record`
   (`runner.py:924`) and `_count_final_state_growth` (`:967`) already return immediately. Note for
   the future: if a workload does arm it, `_evidence_final_state_size` (`:1110-1113`) rebuilds and
   re-serializes the whole final-state document **per event**, which is superlinear — but that is
   a different workload and must not be "fixed" by disabling the bound.
9. Do not claim a speedup from these estimates. Every second quoted above is a rate
   extrapolation from a host-only measurement of one document; the end-to-end A/B in §3 has not
   been run.
10. Do not touch `research/` or `runs/` artifacts, and do not re-run the campaigns to "confirm" a
    number in this report.

---

## Appendix A — measured host rates used for extrapolation

All measured in this session, CPython 3.12.3, 32 vCPU, on the real 20.31 MB
`assertion_material` section extracted from
`…/tail-v1/workload/original/prefix.json` (7.82 MB compact) and on 2 857 real
`actual_events` records (3 641 B pretty each).

| operation | rate | per-document implication |
|---|---:|---|
| `json.loads` (pretty JSON) | 370 MB/s | 211 MB prefix parse ≈0.57 s |
| `json.dumps(indent=2, sort_keys=True, default=str)` | **61.6 MB/s** | `prefix.json` ≈3.43 s; `replay.json` ≈6.46 s |
| `json.dumps(sort_keys=True, separators=(',',':'))` | **143.6 MB/s** | journal (65 MB compact) ≈0.75 s; prefix (81 MB) ≈0.57 s |
| pretty / compact byte ratio | 2.60 | 211.4 MB ↔ 81.3 MB |
| `copy.deepcopy` | **51 MB/s** compact | whole journal 2.05 s; whole prefix ≈2.3 s |
| `_project_process_local` (normalizer copy) | 85 MB/s compact | `_normalized_f6_prefix` ≈0.95 s/side |
| per event: `deepcopy` | 53.2 µs | 38 421 events → 2.05 s |
| per event: `json.loads(json.dumps(row))` | 34.5 µs | `remember()` per row |
| per event: compact render | 19.4 µs | journal ≈0.75 s |
| `EventJournal` 2 048-event chunk: `pickle.dumps` / `pickle.loads` | 23.5 ms / **27.8 ms** | whole journal load ≈0.53 s; **one cache miss = 27.8 ms** |
| `EventJournal` tail-only slice per step | **1.83 ms** | 2 727 steps → 5.0 s |
| `EventJournal` tail slice + 3 historical `event_id` lookups per step | **75.96 ms** | 2 727 steps → 207 s (the pathology to instrument) |

## Appendix B — read-only reproduction

```
# phase numbers, spans and command roundtrips
python3 -c "import json;d=json.load(open('research/input-strategy-audit-20261027/runs/shared-performance-20261029/tail-v1/performance.json'));print(d['wall_seconds'],d['summary']['execution_seconds'],d['summary']['finish_export_seconds'],d['summary']['replay_seconds'])"

# section sizes inside the 211 MB prefix (streaming, ~2.5 s)
# count bytes per top-level key and per "event_id"

# copy-multiplicity sites (all read-only)
grep -rn "events_since(0)" src/myfuzz/integration src/myfuzz/scenario
grep -rn "_json(prefix\|_json(replay\|'replay.json'" src/myfuzz/runtime/flows/shared_slots.py
```
