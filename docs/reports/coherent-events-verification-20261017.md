# Coherent event checks — 2026-10-17

Current software checks passed: **28 tests** for the new coherent consumer and
stream, and **168 tests plus 67 subtests** in the selected event/checker/evidence
regression. Both pytest processes exited 0. Logs and exact implementation/test
hashes are retained in [the evidence summary](evidence/coherent-events-20261017/summary.json).

The controls cover source namespaces, declared FIFO versus per-source response
ordering, noninterleaved multibeat D, grant sink lifetime, width/alignment/mask
checks, absent native fields, duplicate references, bounded storage, execution
and tick continuity, explicit reset cancellation and permanent error poisoning.
The first test invocation had two incorrect expected error-message patterns;
those expectations were corrected to the actual rejection reason. No production
behavior was changed for that result.

The current consumer also reads each of the three already committed native
BOOM journals (`fresh1`, `fresh2`, `fault_read`). Each has 279 accepted A/C/D/E
events, completes with no outstanding source or sink, and passes structural
checks. The fault journal intentionally still passes protocol structure: altered
data is not a protocol-order error. Runtime, semantic and source-authority flags
remain false for all three projections.

```bash
PYTHONPATH=src python3 -m pytest -q \
  tests/scenario/test_coherent_protocol_events.py \
  tests/scenario/test_coherent_event_stream.py
```

The saved native journals retain their earlier frozen build identities. This
report adds current software controls and offline projection evidence; it does
not establish a new RTL build, standard Runner execution, ISA retirement,
functional coverage, external probes or whole P6/P7/P8 acceptance.

Additional source-validation regression: **47 passed in 23.39 seconds**, exit 0,
for the existing discovery-scope, reuse-boundary and prepared-closure controls.
These verify that reusing AST discovery retains byte/probe/method drift checks.
This result does not establish native throughput or validate the pending DMA
performance change. The saved log and source hashes are in the same evidence
directory.
