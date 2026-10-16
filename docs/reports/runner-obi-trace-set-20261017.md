# Runner dual-endpoint OBI events — 2026-10-17

## Implemented path

ScenarioRunner now admits the generated ip_protocol_trace_set.v1 declaration
when its existing raw CPU sample stream is explicitly enabled. The declaration
is checked against actual bound ABI wires by verify_cpu_obi_protocol_traces;
no component-name selection or inferred pin aliases are used. The existing
single-IP base_protocol_trace path remains separate and unchanged.

Each endpoint receives an independent normalizer/checker and bounded evidence
consumer/coverage consumer. The same original Runner local_tick_sample record,
component alias and raw event_id serve both endpoints. Raw outputs keep the
original backend, physical and protocol_taps groups. Protocol consumers now read
the explicitly declared sample_group; beat signals are never renamed or used
in place of CPU-side OBI taps. Projected events identify their declared endpoint
and reference original raw event IDs. Only local projected IDs get an
endpoint namespace to prevent concurrent event collisions; native OBI
transaction_key remains null with protocol_has_no_transaction_id. Existing
backend/single-IP local event ID bytes retain the old format.

protocol_trace_set_reports() exposes cursor-driven, idempotent boundary proofs
and base coverage from the complete Runner journal, including scheduler/reset
records. Each endpoint has max64 pending entries, max256 certificates,
max4096 event gap and saturating counters. State is independent: corruption of
one endpoint's projection cannot poison another endpoint's proof state. These
reports are boundary observations, not dataflow-edge certification or classified
campaign feedback. They are queried explicitly and are not automatically added
to authenticated scenario evidence bundles.

## Exact acceptance boundary

No new RTL was run. The offline SavedSampleSession only replays the100 original
pre/post samples committed by5e63035 in
`docs/reports/evidence/ibex-raw-obi-20261017/first.json.gz`. It computes no CPU or
IP response and exposes its finite saved receipts through Runner.begin_test,
step and the actual drain/projection/checker path. A renamed session alias
confirms the routing uses declared endpoint identity, not component names.

The historical artifact/build identity is preserved. Current regeneration has
identical SV/CPP and observation declarations, but source_verification changed
because sources.lock advanced; the test explicitly preserves the historical
source identity and does not claim that those receipts came from current HEAD.

Runner produces562 journal records:100 scheduler records,200 original raw
pre/post records and262 projections. There are52 certified responses:49
instruction and3 data. Data coverage reaches2 writes,1 read and3 successful
responses. The sampling cutoff retains2 instruction requests; no drained-prefix
claim is made. All local projected IDs are unique, each response refers to a
real raw record, and original raw snapshots compare byte-for-byte as decoded
JSON against the archive. Re-querying reports is idempotent.

A projected instruction response-value tamper produces projection_mismatch and
zero instruction certificates; all3 data certificates remain verified. Forged
trace metadata is refused before drain. Disabled raw streams preserve the
existing no-projection behavior. Existing singular APB/TL/Wishbone/AXI/AHB
projection, checker, evidence and coverage regressions are included.

Complete Runner journal, normal and tampered reports are committed as
deterministic gzip under `docs/reports/evidence/runner-obi-trace-set-20261017/`.
summary.json pins the original native archive, historical artifact/build,
new implementation source hashes and compressed/uncompressed evidence hashes.

## Remaining work

This closes Runner production of CPU-side OBI boundary events over declared
multi-endpoint taps. It does not claim a new real Ibex+GPIO run, current-build
fresh replay, CPU→IP register-effect joins, interrupt causality, online
mutation/search, classified feedback admission or authenticated scenario-prefix
replay. Those require their own current-source executable acceptance.

## Verification

```sh
PYTHONPATH=src python3 -m pytest -q \
 tests/scenario/test_runner_obi_trace_set.py \
 tests/scenario/test_ip_protocol_events*.py \
 tests/scenario/test_ip_protocol_checker*.py \
 tests/scenario/test_ip_protocol_evidence*.py \
 tests/scenario/test_ip_base_coverage*.py \
 tests/scenario/test_ip_protocol_obi.py \
 tests/scenario/test_native_apb_protocol_runner.py \
 tests/local_harness/test_obi_cpu_protocol_taps.py --tb=short
```

**243 passed,1 skipped,67 subtests passed in32.95s**. The skip is the explicitly
gated real RTL test; it was not enabled and no heavy-worker lock was needed.

A focused rerun after explicitly retaining the historical source-verification
object also passed: **4 passed in7.64s**.
