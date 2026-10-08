# P5 frozen 600-second chain and coverage audit (2026-10-07)

## Verdict and denominator

Audited `runs/current-dataflow-p5-snapshot-600s`, the isolated-source Ibex + two PULP GPIO persistent run. `report.json` gives 600.978866694 effective search seconds and 5,563/5,563 `complete` receipts: **9.257 completed cases/s**. Its full fresh replay matched according to the [P5 efficiency profile](current-dataflow-p5-efficiency-profile-20261006.md). Neither a completed case nor a `path_id` is a completed causal chain. **Strict complete real propagation chains/s is undetermined from this run, not zero and not the rate of `observed_path` labels.**

The four declared local coverage targets (`targets.json`, in byte order) are GPIO A `gpio_out` bit 0, GPIO B `irq` bit 0, Ibex accepted fetch at `0x1012c`, and Ibex `data_write` bit 0. The four bytes of each `coverage_hex` are per-case observed target flags, produced by `observed_targets(result.events, self.targets)` in `scenario_rfuzz.py`; they are not a cumulative graph coverage counter. First hits occurred at zero-based receipt indices 2, 1, 1, and 1 respectively. Thus the **distinct local target increment is 4/600.978866694 = 0.00665581 new target bits/s** over the entire effective search, with no further target novelty after receipt 3. The count is limited to these four coarse probes, not chain coverage or RTL edge coverage. There are 11,191 total per-case target hits (4,330, 1,598, 1,419, 3,844 by target), which are repeat observations, not 11,191 new coverage items. Receipts lack individual completion timestamps, so a wall-clock novelty curve cannot be reconstructed.

## Raw-event evidence and strict causal gap

`online_final_trace.meta.json` declares 2,236,544 events; streaming `online_events.jsonl` found IDs 1 through 2,236,544 without loading its 2.2 GiB body at once. The trace contains 8,348 `source_admission` events (5,563 fuzz sources and 2,785 fixed support), 5,563 `instruction_source`, 2,785 `source_injection`, 1,600 `source_start`/`pulse_start` pairs, 1,419 `cpu_irq_taken`, 5,367 `mmio_acceptance`/`mmio_delivery` pairs, and 5,676 `memory_write` events. These stage counts are useful activity bounds, but stages can come from different cases or persistent state and cannot be multiplied or minimized into a chain count.

The source admission, instruction source, and pin injection events carry known `origin_admission_ids`. In this trace **all** 1,600 `source_start`, 1,600 `pulse_start`, 1,419 `cpu_irq_taken`, 5,367 `mmio_acceptance`, 5,367 `mmio_delivery`, and 5,676 `memory_write` events have `origin_status="unknown"` and empty `origin_admission_ids`. Of 54,457 `memory_read` events, 18,967 have a known origin; that does not bridge the remaining transport and endpoint edges. The manifest's `provenance_configuration.edge_index` explicitly records `resource_versions_verified=false` and `runtime_causality_verified=false`. GPIO A and B identities have no `gpio_observation_contract`; the CPU identity has no `cpu_observation_schema_version`. In particular, the trace cannot prove which admitted pin change produced a GPIO B IRQ, or which admitted instruction produced a later MMIO transaction and final observation under persistent state.

`InteractionFeedback` proves certain local delivery and consumption edges. Its `observed_path:irq_sample_read_then_write`, `observed_path:irq_taken_read_then_write`, and `observed_path:write_bound_then_read` labels join selected local edges. The `irq_taken` variant proves architectural interrupt acceptance, but its path starts at the GPIO B IRQ rather than the admitted external pin; the write/bound/read variant has no accepted online CPU instruction source or final result store. `path_id` is only the selected candidate topology. The default `IbexPulpOnlineChecker` records concrete contradictions; its absence of violations does not assert a complete path. Its internal ISR checks retain state across cases and do not emit per-source completion certificates. Receipt `interaction_feature_deltas` are batched positive count changes (feedback interval 16, with deferred receipts), not distinct complete chains or a wall-time series. The 20 distinct feature names reported previously must not be substituted for complete chains.

This evidence supports **no certified numerator** for a strict end-to-end chain/s estimate. A reported numerical zero would assert that no real chain happened, which these records do not establish. The replay proves the recorded behavior is reproducible for the frozen source, not that the missing causal links are present.

## Minimal next collection and metric contract

Keep the same frozen program, two GPIOs, seed, 600-second effective budget, and full replay. Enable passive GPIO consumption and CPU retirement probes before the run; preserve their authenticated profile identities in the session manifest. Emit an incremental completion certificate for each source admission, with a unique chain ID, direction, source admission/action ID, ordered event IDs and values for every required hop, transaction/IRQ occurrence and memory version links, case indices of source and endpoint, and final checker outcome. The GPIO B path must connect admitted pin-8 injection to sampled/synchronized input, real GPIO IRQ, delivered and taken CPU IRQ, accepted ISR fetch, GPIO B PADIN MMIO acceptance/delivery, matched CPU response, ISR result store, GPIO A PADOUT MMIO acceptance/delivery, and settled real GPIO A output. The reverse path must connect the admitted CPU instruction fetch/retirement and its accepted GPIO A write to settled output, consumed A-to-B binding, B IRQ, CPU IRQ take, PADIN read/response, and result store. Reject a certificate when any source owner or version is unknown, an intervening write/IRQ supersedes the witness, values disagree, or the sequence crosses a reset. Allow endpoints in later cases but credit the original admission exactly once; separately count chains that complete within the same case.

Then report `certified_unique_chain_ids / effective_search_seconds` by direction and total, along with source-to-endpoint latency and replay match of the certificate stream. Report separate coverage rates for (a) first-seen local target IDs, (b) first-seen witnessed runtime edge IDs, and (c) first-seen complete chain signatures. Add per-case monotonic completion timestamps to compute novelty over time. The existing 600-second artifact requires no rerun to retain its valid 9.257 cases/s and four-target rate; a new instrumented run is required for the strict chain metric.

## Reproduction

Read-only calculations against the saved artifacts:

```bash
python3 - <<'PY'
import collections, json
from pathlib import Path
p = Path('runs/current-dataflow-p5-snapshot-600s')
seconds = json.loads((p/'report.json').read_text())['effective_search_seconds']
first, hits = {}, collections.Counter()
with (p/'receipts.jsonl').open() as f:
    for index, line in enumerate(f):
        flags = bytes.fromhex(json.loads(line)['coverage_hex'])
        assert len(flags) == 4 and all(flag in (0, 1) for flag in flags)
        for target, flag in enumerate(flags):
            if flag:
                hits[target] += 1
                first.setdefault(target, index)
print('first', first, 'hits', dict(hits), 'new_targets_per_s', len(first)/seconds)
PY
```

```bash
python3 - <<'PY'
import collections, json
from pathlib import Path
p = Path('runs/current-dataflow-p5-snapshot-600s/online_events.jsonl')
counts, origins = collections.Counter(), collections.Counter()
with p.open() as f:
    for line in f:
        event = json.loads(line)
        kind = event.get('kind')
        counts[kind] += 1
        if kind in {'source_admission', 'instruction_source', 'source_injection',
                    'source_start', 'pulse_start', 'cpu_irq_taken',
                    'mmio_acceptance', 'mmio_delivery', 'memory_read', 'memory_write'}:
            provenance = event.get('provenance', {})
            origins[(kind, provenance.get('origin_status'),
                     bool(provenance.get('origin_admission_ids')))] += 1
print('events', sum(counts.values()), 'kinds', dict(counts))
print('origins', dict(origins))
PY
```
