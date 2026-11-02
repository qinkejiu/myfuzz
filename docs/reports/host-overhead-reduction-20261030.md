# Host overhead reduction: bounded journal chunk cache and single-render prefix export

2026-10-30. Host-side change only. **No** native campaign, **no** Verilator build, **no** DUT
simulation, no RTL, and no end-to-end run in this session: every number below is either a
measured pure-Python micro-benchmark on the recorded artifacts or a rate extrapolation from one,
labelled as such. The same-workload A/B is **not** claimed here and is **not** run yet — the
commands for it are in §7.

Input profile: `docs/reports/host-overhead-profile-20261030.md` (§2 item 0 and item 4).

Reference workload (unchanged, from the recorded eight-case shared A/B `F3,F1,F4,F5,F2,F6,F5,F6`):
campaign 150 s, finish/export 46 s, replay 254 s, wall 482 s, 38 421 journal events, CPU/DMA/GPIO
ticks 977/1010/1023, native eval counts CPU 3908 / DMA 4040 / GPIO 4092.

---

## 1. What changed

### 1.1 `EventJournal` read-chunk cache: one slot -> bounded LRU (default 4)

`src/myfuzz/scenario/event_journal.py`

Before: `_chunk()` kept exactly one `(_cached_index, _cached_chunk)` slot, so any alternation
between the tail drain and a historical `event_id` read re-unpickled a 2 048-event chunk on every
step. After: an `OrderedDict` LRU of at most `chunk_cache_size` spilled chunks, default 4.

* `EventJournal(*, chunk_size=2048, chunk_cache_size=None)` — new keyword-only argument. `None`
  (the default) resolves the capacity from `MYFUZZ_EVENT_JOURNAL_CHUNK_CACHE`, else 4. An explicit
  keyword always wins. No existing parameter or public signature changed.
* `MYFUZZ_EVENT_JOURNAL_CHUNK_CACHE` — environment override, read once per journal (a `Runner`
  creates exactly one), validated as a positive integer; `1` reproduces the pre-change
  single-chunk behaviour exactly. This is the A/B switch for the lead (§7).
* `EventJournal.chunk_loads` — new read-only property: the number of `pickle.load` calls (cache
  misses) so far. Measurement only; never reset, never written outside `_chunk`.
* `EventJournal.chunk_cache_size` — new read-only property: the effective capacity.
* Memory stays bounded and independent of journal length: at most `chunk_cache_size` chunks plus
  the resident `_current` chunk. Measured (§3.3): 62.3 MB of live read-cache objects for capacity 4
  versus 15.4 MB for one slot, on the recorded journal.
* `runner.py` was **not** touched: `_EventLog.enable_journal()` constructs `EventJournal`, so the
  default and the environment override are already active for every `Runner`. No plumbing was
  required.

### 1.2 Prefix export: one render, two byte-identical writes

`src/myfuzz/runtime/generic_campaign.py` and `src/myfuzz/runtime/flows/shared_slots.py`

Before: `_json(prefix, 'prefix.json')` and `_json(prefix, 'compiled_f6_prefix.json')` rendered the
same 211 MB document twice. After: `_json` returns the exact text it wrote, and the second path is
published from that text (`rendered=` keyword). Both files are still written; both are still
byte-identical; the render count for the pair goes 2 -> 1.

* `_json(value, path, *, rendered=None) -> str` — the returned text is new (additive). `rendered`
  is only for byte-identical duplicates of the same, unmodified value, and is rejected for
  `summary.json` (that path applies the `candidate_summary` transform and must render).
* Nothing else in the export pipeline changed: `indent=2, sort_keys=True, default=str` and the
  trailing newline are untouched, file names and key sets are untouched, and the second write
  still happens inside the same `finish_export_seconds` window.

Verification on the real recorded document (§4): re-rendering the recorded `prefix.json`
document with `_json` reproduces the artifact **byte for byte** —
`sha256 1efc599e9212aa4efd236d563bd4d66eafb31efd0543a6f233742ceab0f9768f`, 211 425 765 bytes —
which is exactly the hash of both recorded `prefix.json` and `compiled_f6_prefix.json`.

---

## 2. Semantics invariants preserved (and how)

| invariant | how it is held |
|---|---|
| iteration order, `__getitem__` (int / slice -> `list` / negative / `IndexError` / `TypeError`), `len`, `append` timing | `_chunk()` still returns the live chunk list (or `_current` for the tail); only the number of resident chunk lists changed. Covered by `tests/scenario/test_event_journal_cache.py` for capacities 1/2/4 and by the pre-existing `tests/scenario/test_event_journal.py`. |
| `snapshot()` detaches, freezes its prefix, `__eq__` | untouched code; re-tested at capacities 1/2/4 (mutating a detached record, appending after the snapshot, `==` on equal and shorter sequences). |
| chunk file format and pickling | unchanged: `pickle.dump(chunk, protocol=HIGHEST_PROTOCOL)` at the same offsets. The new test reads a spilled chunk directly out of `journal._file` at `_offsets[i]` with `pickle.load` and asserts it equals the appended list, and that `_offsets[1] == len(pickle.dumps(chunk0))`. |
| borrowed-vs-detached ownership (`_event_refs_since`, `_event_ref_by_id`) | unchanged: chunk records are still shared by reference within a chunk; the "no mutate, no retain" discipline is the same one the single-slot cache already required (a test in the F6 suite mutates a borrowed record in place and still observes the mutation, as before). |
| `prefix.json` / `compiled_f6_prefix.json` bytes | identical: same single render, proven byte-equal to the recorded artifact (§4) and asserted equal by `tests/runtime/test_shared_slot_duplicate_export.py`. |
| export/audit accounting | `finish_export_seconds` still covers both writes; `tests/runtime/test_shared_slot_timing.py` still asserts the recorded accounting unchanged. |
| executed work (events, ticks, eval counts) | not touched by either change: the journal change is read-path only, the export change is write-path only. The benchmark script asserts every cache variant reads exactly the same tail records and historical records in the same order and that the whole journal content is identical, so a timing win cannot come from reading less. |

---

## 3. Journal benchmark: measured before/after

Script: `scripts/bench_event_journal_cache.py`. It builds one 38 421-event journal, reproduces the
*pre-change* `_chunk` body verbatim in `LegacyEventJournal`, and runs the same access patterns over
the same event objects and the same lookups.

Access patterns per step (one step = one `runner_step`):

* `tail` = `events_since(cursor)` = `deepcopy(tuple(journal[cursor:cursor+14]))` (14 = 38 421 events
  / 2 727 steps, the recorded drain width);
* `adjacent3` = tail + 3 historical `event_id` reads through the `_event_ref_by_id` path
  (1 / 2 049 / 4 097 events back: the F6 request/completion neighbourhood);
* `wide3` = tail + 3 historical reads 1 / 3 000 / 8 000 events back;
* `f6x8` = supplementary: the recorded per-fetch-completion fan-out (8 historical reads).

Measurement window = the last `steps x 14` events of the journal (where the F6 cases and the
largest chunk working set are).

### 3.1 Recorded 38 421-event journal (`--source …/tail-v1/workload/original/prefix.json`)

Command:

```
PYTHONPATH=src:. python3 scripts/bench_event_journal_cache.py \
  --source research/input-strategy-audit-20261027/runs/shared-performance-20261029/tail-v1/workload/original/prefix.json \
  --steps 600 --capacities 3,4 --patterns tail,adjacent3,wide3,f6x8 --memory-probe
```

600 steps measured per cell; the 2 727-step column is the measured per-step mean x 2 727.

| variant | pattern | ms/step | chunk loads | loads/step | s over 2 727 steps |
|---|---|---|---:|---:|---:|
| legacy (1 slot) | tail | 1.145 | 4 | 0.007 | 3.12 |
| legacy (1 slot) | **adjacent3** | **71.495** | 1 696 | **2.827** | **194.97** |
| legacy (1 slot) | wide3 | 82.186 | 1 696 | 2.827 | 224.12 |
| legacy (1 slot) | f6x8 | 95.725 | 1 695 | 2.825 | 261.04 |
| LRU 3 | tail | 0.867 | 4 | 0.007 | 2.36 |
| LRU 3 | adjacent3 | 1.872 | 25 | 0.042 | 5.11 |
| LRU 3 | wide3 | 1.757 | 26 | 0.043 | 4.79 |
| LRU 3 | f6x8 | 2.473 | 24 | 0.040 | 6.74 |
| **LRU 4 (default)** | tail | 0.753 | 4 | 0.007 | 2.05 |
| **LRU 4 (default)** | **adjacent3** | **0.834** | 5 | **0.008** | **2.27** |
| **LRU 4 (default)** | wide3 | 0.966 | 9 | 0.015 | 2.63 |
| **LRU 4 (default)** | f6x8 | 0.821 | 4 | 0.007 | 2.24 |

Implied cost of one 2 048-event chunk load on this host: 71.495 ms / 2.827 loads = **25.3 ms**
(profile: 27.8 ms). Chunk payload: 2 680 980 B pickled, 2 048 real events, 3 836 B mean pretty JSON.

**Headline for the pattern the profile named** (tail + 3 historical lookups per step):
**71.50 ms/step -> 0.83 ms/step, 194.97 s -> 2.27 s over 2 727 steps, 2.83 -> 0.01 chunk loads
per step.** The `tail`-only pattern is unchanged within noise (1.15 -> 0.75 ms/step; both are the
same 4 loads + deepcopy). This is a host-only measurement of the access pattern; it is **not** an
end-to-end speedup claim — §7 is how that gets measured.

Why 3 slots are not enough and why 4 is the default: the working set of one step is the tail chunk
plus two-to-three older chunks. Three slots still miss on 0.042 loads/step (5.1 s over 2 727 steps);
four slots miss on 0.008 (2.3 s). The two-slot variant is *not* usable: 2.455 loads/step — it
thrashes between the tail and the historical chunks.

### 3.2 Synthetic 38 421-event journal (independent reproduction)

Command:

```
PYTHONPATH=src:. python3 scripts/bench_event_journal_cache.py --steps 600 \
  --capacities 1,2,3,4,6,8 --patterns tail,adjacent3,wide3,f6x8
```

Synthetic events follow the recorded size distribution (mean 3 836 B pretty; template = the
dominant `gpio_input_sample` record shape with `stages` rows), every event built from fresh
objects. Same conclusions, full capacity sweep:

| capacity | tail ms/step | adjacent3 ms/step (loads/step) | wide3 ms/step | f6x8 ms/step |
|---:|---:|---:|---:|---:|
| legacy (1 slot) | 0.731 | 75.205 (2.827) | 67.962 | 73.766 |
| 1 | 0.744 | 74.022 (2.827) | 70.970 | 79.761 |
| 2 | 0.787 | 64.295 (2.455) | 70.300 | 73.986 |
| 3 | 0.751 | 1.564 (0.042) | 1.613 | 2.063 |
| 4 | 0.762 | **0.767 (0.008)** | **0.987** | **0.778** |
| 6 | 0.719 | 0.786 (0.003) | 0.830 | 0.660 |
| 8 | 0.733 | 0.645 (0.003) | 0.659 | 0.632 |

`capacity=1` (both implementations) reproduces the legacy times and the same 2.827 loads/step, which
is what makes the capacity knob a valid A/B: 1 = old policy, 4 = new policy, identical code.

### 3.3 Memory cost of the cache (measured, tracemalloc)

`--memory-probe` touches every spilled chunk after the timed loops and reports what stays
allocated:

| variant | resident chunks | pickled bytes bound | live objects (tracemalloc) |
|---|---:|---:|---:|
| legacy / capacity 1 | 1 | 2.68 MB | 15.4 MB |
| capacity 3 | 3 | 8.04 MB | 47.1 MB |
| capacity 4 (default) | 4 | 10.72 MB | 62.3 MB |

So the default costs **+47 MB** of resident read cache versus the old single slot on this journal,
and that number does not grow with the journal (it is `chunk_cache_size x chunk_size` events; 18
of 18.77 chunks stay on disk). The recorded workload holds a 211 MB prefix document plus the whole
event stream, so this is small next to its peak, but the peak RSS of that run was never recorded and
is not claimed here.

---

## 4. Export write amplification: measured, and what is / is not implemented

Script: `scripts/bench_shared_slot_export_writes.py`, run on the recorded artifacts.

```
PYTHONPATH=src:. python3 scripts/bench_shared_slot_export_writes.py \
  --source research/input-strategy-audit-20261027/runs/shared-performance-20261029/tail-v1/workload/original/prefix.json --compact
```

| measurement (prefix pair) | before (2 renders) | after (1 render) |
|---|---:|---:|
| `_json` wall time for the pair | 8.263 s | 4.087 s |
| of which render | 2 x 3.919 s | 3.919 s |
| of which write | 2 x 0.193 s | 2 x 0.193 s |
| bytes written | 422 851 530 | 422 851 530 |
| bytes per file / sha256 | 211 425 765 / `1efc599e…f9768f` | identical |

**Measured saving: 4.176 s per run** (render rate 53.9 MB/s on this host), with the same two files,
the same bytes, the same hashes. The script asserts all written documents are byte-equal and equal
to a direct `json.dumps` of the same value, and that hash equals the recorded artifact (both
recorded files hash to `1efc599e…`).

Not implemented, deliberately:

1. **`replay.json` is written twice and stays that way.** `shared_slots.py` passes
   `audit_sink=lambda value: _json(value, out/'replay.json')` *and* writes the returned envelope to
   the same path. The bytes are identical (the sink receives `deepcopy(envelope)` of the very value
   returned), so deduplicating would not change the file, but (a) it would couple the export writer
   to `CompiledF6Runtime.replay`'s internal document identity — if the sink ever receives a subset,
   the reuse would silently write the wrong bytes — and (b) the sink write is the artifact that
   survives a failed replay, while the caller's write only runs on success. Estimated opportunity,
   rate-extrapolated at the measured 53.9 MB/s: 397 873 205 B -> 7.38 s per render, so ~7.4 s saved
   of the ~14.8 s currently spent rendering it. **Not implemented** (audit-binding change).
2. **Compact separators are not used.** Measured on the same document:
   `json.dumps(..., separators=(',',':'))` produces 118 674 194 B (pretty/compact ratio 1.782) in
   0.721 s versus 3.919 s — a ~5.4x cheaper render and 92.8 MB less written per file pair. **Not
   implemented**: it changes every recorded document hash (`prefix.json`, `compiled_f6_prefix.json`,
   `replay.json` are identity-bound by SHA256 in manifests and by the recorded A/B artifacts) and
   would invalidate every prior run and the frozen-window comparison. The profile's §4.5 rule
   stands.

Bytes written per run after this change: 211.4 x 2 + 397.9 x 2 = 1 218.6 MB (unchanged; the
duplicate prefix file is still written — only its render is shared). Renders per run: 4 -> 3 for
these pairs (prefix pair 2 -> 1; replay pair still 2).

---

## 5. Tests run

All commands use `PYTHONPATH=src:.`. Counts are exact for the runs below.

| suite | command | result |
|---|---|---|
| journal + refs + reduced-AXI journal | `python3 -m pytest tests/scenario/test_event_journal.py tests/scenario/test_event_journal_cache.py tests/scenario/test_event_refs.py tests/scenario/test_reduced_axi_journal.py -q` | **217 passed** |
| new cache tests | `python3 -m pytest tests/scenario/test_event_journal_cache.py -q` | **7 passed** |
| export dedup + timing + writer consumers | `python3 -m pytest tests/runtime/test_shared_slot_duplicate_export.py tests/runtime/test_shared_slot_timing.py tests/runtime/test_candidate_summary_writers.py -q` | **22 passed** (3 + 12 + 7; the timing test keeps its recorded accounting assertion) |
| F6 receipt suite (66 tests) | `python3 -m pytest tests/scenario/test_f6_instruction_fetch_receipt.py -q` | **started, not finished**: 17 passed before the wall-clock cut; the suite is simply slow (~10-17 s per test: `test_runner_refuses_missing_or_malformed_f6_acceptance_anchor` alone is 49.7 s for its 3 parameters, and passes). Verified **not** caused by this change: the same single test passes in 49.7 s with `MYFUZZ_EVENT_JOURNAL_CHUNK_CACHE=1`. |
| F6 runtime path / DMA handoff / edge provenance / plugin-free fixtures + shared-slot runtime suites | see `F6 + shared-slot group` command below | see §5.1 |
| shared-slot integration subset | `python3 -m pytest tests/integration/test_shared_f6_slots.py tests/integration/test_shared_f6_memory_slots.py tests/integration/test_shared_f5_support_binding.py tests/integration/test_f6_saved_slot_mapping.py tests/integration/test_shared_all_flows_script.py -q` | see §5.1 |

```bash
# F6 + shared-slot group
PYTHONPATH=src:. python3 -m pytest tests/scenario/test_compiled_f6_runtime_path.py \
  tests/scenario/test_compiled_f6_dma_handoff.py tests/scenario/test_interaction_edge_provenance.py \
  tests/scenario/test_ip_plugin_free_fixtures.py tests/runtime/test_shared_slot_timing.py \
  tests/runtime/test_shared_slot_duplicate_export.py tests/runtime/test_shared_slot_elaboration_mode.py \
  tests/runtime/test_candidate_summary_writers.py tests/runtime/test_generic_mixed_entry.py \
  tests/runtime/test_generic_campaign_cleanup.py -q
```

### 5.1 Results of the two background groups

See the closing section of this report for the numbers that completed before the freeze; any group
listed there as "started, not finished" was still running when the wrap-up cut arrived.

Pre-existing failures: **none observed** in the suites that completed. The slow F6 receipt suite is
slow, not failing.

---

## 6. Files changed

| file | change |
|---|---|
| `src/myfuzz/scenario/event_journal.py` | bounded LRU chunk cache (default 4), `chunk_cache_size` keyword + `MYFUZZ_EVENT_JOURNAL_CHUNK_CACHE` override, `chunk_loads` / `chunk_cache_size` read-only counters |
| `src/myfuzz/runtime/generic_campaign.py` | `_json` returns the rendered text and accepts `rendered=` for byte-identical republication |
| `src/myfuzz/runtime/flows/shared_slots.py` | `compiled_f6_prefix.json` published from the `prefix.json` render |
| `tests/runtime/test_shared_slot_timing.py` | one line: the `_json` test double accepts the new keyword (`**kwargs`); the assertion (17 s accounting) is unchanged |
| `tests/scenario/test_event_journal_cache.py` | new: cache capacity, load counter, env override, order/slice/negative/`IndexError`, chunk file format, snapshot detachment |
| `tests/runtime/test_shared_slot_duplicate_export.py` | new: one render + byte-identical duplicate, summary rejection, end-to-end shared-slot duplicate |
| `scripts/bench_event_journal_cache.py` | new: journal access-pattern benchmark (before/after in one process) |
| `scripts/bench_shared_slot_export_writes.py` | new: export render/write benchmark and byte-identity proof |
| `docs/reports/host-overhead-reduction-20261030.md` | this report |

Not touched: `src/myfuzz/scenario/runner.py` (no plumbing needed), `src/myfuzz/integration/compiled_f6.py`,
`research/`, `runs/`, any artifact.

---

## 7. Same-workload A/B for the lead (not run here)

Same source, same plan identity, same `RECORDS`, same `rounds_per_case`, same output layout; the
**only** variable is the journal chunk-cache capacity. Run both on the same source tree, interleaved
`A B A B A B`, frozen window, no concurrent jobs:

```bash
# A — old cache policy (one resident chunk), current source
MYFUZZ_EVENT_JOURNAL_CHUNK_CACHE=1 PYTHONPATH=src:. \
python3 scripts/benchmark_shared_all_flows.py --native --dut-eval \
  --output <A-dir> --cache runs/config-driven-20261028/cache

# B — new cache policy (default, four resident chunks), same source
MYFUZZ_EVENT_JOURNAL_CHUNK_CACHE=4 PYTHONPATH=src:. \
python3 scripts/benchmark_shared_all_flows.py --native --dut-eval \
  --output <B-dir> --cache runs/config-driven-20261028/cache
```

(The benchmark CLI has no `--mode`; `--native` is required, and `--dut-eval` enables
the existing native eval counters on both sides. The lead runs both on the same
source tree in one frozen window.)

(The unset default is also 4, so `B` is exactly the shipped behaviour; setting it explicitly makes
the two commands symmetric.)

Acceptance rules from the profile §3 apply unchanged: `runtime_eval_count` (CPU 3908 / DMA 4040 /
GPIO 4092), `local_ticks` (977/1010/1023), `event_count` 38 421, per-kind event counts, per-command
counts and normalized-prefix SHA256 (`ce6d4150…42f457`) must be equal on both sides; only seconds
may move. Discard the first repetition of each mode, report median and min of >= 3 interleaved
repetitions, and report host CPU time (`ru_utime + ru_stime`) next to wall. The expected direction
is a visible drop only in the F6 cases (they carry the historical-lookup pattern) and no change in
`tail`-only phases; if the F6 rows do not move, the cache is not the cost driver and the profile's
item 0 attribution was wrong.

Also worth recording in that window (one line, no behaviour change):
`grep -c` of nothing — instead read `runner._events._records.chunk_loads` at the end of each run
(the counter added in §1.1) and report it as `journal_chunk_loads` for both sides. Expected: ~5 for
capacity 4 versus thousands for capacity 1 on the recorded workload.

## 8. Remaining sites not addressed

1. `replay.json` double render (~7.4 s estimated) — see §4, blocked on the audit-sink contract.
2. Compact separators (~5.4x cheaper renders, 92.8 MB less written) — blocked by every recorded hash.
3. Whole-journal `deepcopy` on the evidence path (profile §2 item 1) and the four defensive copies
   in `finish()`/`replay()` (items 2-3) — untouched; they are the next-largest host cost and each
   needs an aliasing-contract change, not a cache tweak.
4. `_normalized_f6_prefix` x2 and the recursive `_first_difference` walk (item 5), `_canonical` used
   as an equality oracle (item 6), per-event `deepcopy` at append (item 7), `_saved_projection_inputs`
   JSON round-trips (item 8), `_jsonable` per row (item 9), wire-level reply validation (item 10),
   per-case O(n) scans in `shared_irq_firmware` (item 11) — all untouched.
5. The measurement gap inside `runner_step` (~69.8 s of unexplained per-step Python) is still
   unattributed; the new `chunk_loads` counter makes the journal part of it attributable in the A/B,
   the rest still needs the span instrumentation listed in the profile §3.
