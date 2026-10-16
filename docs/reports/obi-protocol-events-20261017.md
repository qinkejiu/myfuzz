# Generic OBI event/checker/evidence slice — 2026-10-17

## Actual scope

This is a **synthetic protocol gate**, not real CPU/IP dataflow acceptance. It
adds generic OBI projection/checking and base coverage without component-name
selection. Existing IpProtocolEvidenceConsumer recomputes and authenticates the
new projections through the existing generic path; it needs no implementation
change. The positive fixture deliberately uses a new component name.

The trace must explicitly declare max_outstanding=1. Required physical roles
are req/gnt/addr/rvalid/rdata, with either all or none of we/wdata/be, and optional
error. No IDs, response-ready, checksums or pipelined outstanding transactions
are admitted. No transaction ID is invented: certificates carry a null native
key and protocol_has_no_transaction_id. CACHE and software register semantics
are not inferred.

The normalizer emits request, accept, response, wait, timeout and reset cancel.
The checker enforces request control stability until grant, no withdrawal,
responses only after a prior grant, one outstanding transaction, declared widths
and bounded request/response latency. A previous response and next grant may
share one edge; a same-edge first grant cannot justify an orphan response.
Speculative grant without request accepts nothing. Read WDATA is irrelevant and
is not incorrectly required to remain stable. Timeout retains native pending
state; reset clears it, and an uncorrelated subsequent response is rejected.

## Saved real Ibex receipt inspection

The existing real DMA test's /tmp/myfuzz-dma-cpu-isolated-evidence/run-0.json and
run-1.json were inspected directly, not inferred from report prose. Both have128
CPU scheduler ticks. Their obi_cpu artifact marks processor.instruction and
processor.data as adapted, and exports **zero physical signals** for those two
endpoints. The saved backend has req_valid/req_ready/rsp_valid/rsp_ready and
payload signals from obi_processor_memory_adapter, not the original CPU OBI
req/gnt/rvalid wires. Mapping these beat signals back to OBI would lose the CPU
request while the adapter is busy and cannot authenticate the claimed boundary.
Neither real receipt was projected or certified as OBI.

The committed evidence JSON pins the exact complete real-receipt SHA256s,
records the inspected signal inventory, and includes the complete **synthetic**
journal, certificates and coverage:
[evidence/obi-synthetic-protocol-20261017.json](evidence/obi-synthetic-protocol-20261017.json).
The synthetic runtime-contract hash is deliberately a fixture value, not a real
build identity.

## Verification

```sh
PYTHONPATH=src python3 -m pytest -q \
 tests/scenario/test_ip_protocol_obi.py \
 tests/scenario/test_ip_protocol_events*.py \
 tests/scenario/test_ip_protocol_checker*.py \
 tests/scenario/test_ip_protocol_evidence*.py \
 tests/scenario/test_ip_base_coverage*.py --tb=short
```

**224 passed, 67 subtests passed in0.59s**. Includes delayed grant/response,
write/read certification (2 verified,0 pending), response rollover, read-only
shape, speculative grant, response error, reset/stale response, withdrawal,
changed address, orphan/same-edge response, overlapping grant, wait budgets,
unsupported widths/bounds/shapes, projected-value tamper, raw-grant tamper,
missing projection and reachable read/write/success coverage counters.

No RTL or remote heavy worker was run for this slice. No renderer, Runner,
generated_execution or DMA integration file was edited. Real OBI acceptance
requires passive CPU-side taps, an explicit multi-endpoint trace schema/Runner
path, fresh real RTL execution and authenticated consumption of those samples.
