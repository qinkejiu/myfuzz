# Independent full AXI observer source review — 2026-10-17

Read-only review; no tests/native/compiler/remote operation. Reviewed frozen
full_axi_events.py SHA25649ab18838e026a5537c6b0f187dfd909740c8b2fda79370a12889d6d66b5bb50
and cva6_axi4_session.py SHA2567bf5a5acb7784f4d2760392850e75fad11924dac3d7107b20cfcd2cd290a79b8,
field ABI, runtime renderer/source discovery, tests and
`docs/reports/CPU_FULL_AXI_OBSERVER_20261017.md`. Reported88passed is the owner's
software evidence, not rerun or independently established in this review.

## Findings

### M1 — exceptions after measured edge can escape without poison

cva6_axi4_session.py:316 catches only ValueError/RuntimeError. The native command
has already completed before `payload['samples'][0].get('pre',{}).get('backend')`
at352; a non-dict sample or pre=None raises AttributeError outside that catch.
Similarly target/service OSError/TypeError, or absent observations keys at the
final return after memory advancement, can bypass poison. The observer remains
active, so a later step can call _ready_inputs and native STEP again despite an
uncertain prior edge/target effect. This contradicts the documented poisoned
retry boundary. Validate nested receipt types and poison all effect-bearing
exception paths while preserving the original error. Add malformed sample/pre,
service OSError/TypeError/KeyError controls proving no subsequent ready/native
call. Delivered to owner before this report so fixes can proceed in parallel.

### M2 — observer protocol failures omit effect uncertainty

full_axi_events.py:109–114 marks _failed and emits full_axi_failure without
possible_effects. In session integration an actual edge has already occurred;
there may also be pre-command read/service effects. Outer poison returns early
when _failed at97, so the service's possible_effects=true diagnostic envelope is
never added to this protocol/shape/budget failure. The raw sample is retained,
but failure metadata does not convey the same uncertainty as service failure.
Set an explicit conservative effect marker and clear projection trust semantics
on this failure path; do not turn it into successful transfers or grant memory
or retirement authority. Delivered to owner; no source edit by reviewer.

### M3 — new stalled POST offer is not held through next PRE

At162–170 hold state is only created when PRE already has valid&&!ready.
A channel with PRE valid0, POST valid1/ready0 creates no hold. Next PRE may
withdraw VALID or change payload without any intervening accepted edge and is
accepted by this checker. This leaves a gap in the declared post-hold/next-pre
stability contract. POST must not project a transfer, but its new stalled offer
should be retained for continuity, or explicitly rejected as unsupported rather
than silently ignoring that stability evidence. Owner was asked to evaluate a
targeted control (e.g. AW POST new valid1/ready0, next PRE changed AWUSER or
valid0). This is a source-read control proposal, not an executed reproduction.

## Nonblocking boundary note

Raw byte budget is a stop threshold, not a strict retained-byte cap: observe
appends/deepcopies a raw sample before counting it at144–148, and poison retains
an entire offending diagnostic at95–107. Global counters cannot be reopened by
reset, which is correct. However a single oversized record can exceed max_bytes;
standalone observer has no independent per-receipt byte cap. Either name this
explicit bounded-overrun policy with the upstream packet cap in the contract,
or prebound/summarize oversize raw diagnostics. Do not describe max_raw_bytes
as a literal maximum retained allocation without that qualification.

## Source checks without additional findings

- Packed ABI is code-owned45 roles from cva6_axi4_fields:64-bit address/data/USER,
  ID4, actual LEN/BURST/LOCK/ATOP, one axi endpoint. Renderer _shape checks this
  against physical ABI. No instruction/data identity inferred from ID/address.
- Session compares exact pre role set, integer widths and injected inputs;
  observer checks exact pre/post backend shapes. Only pre valid&&ready projects
  acceptances; post acceptance is not invented.
- AW/W decoupling retains W-before-AW payload/LAST/raw tick without fabricated
  address. AW join computes per-beat address, encoded size/bytes/lane mask and
  raw refs. First-W ordering is retained across later batches. Bursts and IDs,
  R/B completion identity, LAST,4K/64-bit overflow, unsupported lock/ATOP and
  one-read/one-write budgets are explicit. Zero WSTRB is observation-supported;
  MMIO service may reject narrower operations. No memory commit authority.
- Stable runtime_events list and stream-local raw refs fit existing importer;
  scope reset records pending identities before state clear. Lifetime
  edge/bytes/scopes counters remain global across epochs. No native bins implied.
- Source discovery seeds cva6_axi4_session and recursively follows its static
  import of full_axi_events and that module's cva6_axi4_fields dependency. The
  source test checks these bytes; review did not run discovery or tests.
- Constructed software-model archive is labeled non-native and normalizes only
  scope.execution_id for its fresh-prefix comparison. It is not substituted
  for a saved generated native journal. Actual native bins remain unknown.

## Disposition

No high-severity finding. Resolve M1/M2 and close or explicitly constrain M3
before treating this source increment as complete. No runtime admission,
source/evidence certificate or full P6 completion follows from this review.
