# P7 I3/I4 and P8 S2/S3/S4 real-gate record (2026-10-18)

Commit lineage: production source at `07b207b`, plus the S4 complete-case and
normalizer fixes (`abcea20`, `9cbc323`). The final test-only commit `ade3fe6`
runs the same production source and adds the bounded S2 gate cases. All
numbers below are from the saved artifacts, not from a plan.

## P7 I3 — PULP timer generic APB storage F4

Evidence: `docs/reports/evidence/p7-i3-timer-f4-20261017/outputs/timer-ade3fe6/`

- `report.json`: `status=completed`, 3 cases, 3 certified, `runtime_admitted=true`.
- Three explicit records execute continuously in one runtime:
  - `0x55` commit `0 -> 85`
  - `0xaa` commit `85 -> 170`
  - `0x12345678` commit `170 -> 305419896`
- Every certificate has the three declared assertions passed and
  `source_id=peripheral.TIMER0_CTRL.value.mmio`, `path_id=F4:ram.image`.
- The probe is now evidence-bound:
  `probe.hierarchy_verified=true`, `probe.native_verified=true`, proof digest
  `a889c6eb...`, binding `fc2056da...`; the generated runtime/wrapper hashes
  match the Verilog probe evidence.
- `replays.json`/`fresh-1/comparison.json`: `matches=true`,
  `verification_scope=full`, `first_difference=null`, identical semantic hash;
  fresh PIDs/execution nonces differ and both native exits are 0.
- Boundary: this is the directed F4 candidate executor, not RFuzz coverage
  search; F2/F3/F5/F6 remain unsupported by this executor.

## P7 I4 — CV32E20 + PULP timer compiled RFuzz search

Evidence: `runs/p7-i4-real-ade3fe6/`

- `status=complete`, client return code 0, 4 RFuzz tests, 4 certified receipts.
- D1–D3: `executable=4/6`, one executable F4 target (`F4:ram.image`), source
  `peripheral.TIMER0_CTRL.value.mmio`; executor `compiled-f4-rfuzz`,
  `family_fallback=false`.
- `session/receipts.jsonl`: one row per admitted candidate, real path/source,
  non-zero coverage on the low-byte commit predicates.
- Capability report: `Coverage-guided searched=3`, `RTL operational=3`,
  `Bug confirmed=0`.
- `fresh-verification.json`: `matches=true`, `verification_scope=full`;
  receipt join `ok`.
- Boundary: the RFuzz wire record is 8 bytes and the timer candidate is 4
  bytes; the declared prefix is consumed and the remaining bytes are recorded
  as unreferenced transport lanes. The test executes at most 8 candidate
  records per RFuzz test and records the rest as lanes.

## P8 S2 — one boot, three directions, multi-word, accepted source

Evidence: `docs/reports/evidence/dma-s2-real-ade3fe6/`

- `1 passed in 465.88s`; three multi-word cases, one per direction:
  RX→RAM, RAM→RAM, RAM→TX.
- Every case has `fifo_origin=accepted_uart_fifo_entry`,
  `source_authority=accepted_uart_fifo_entry`,
  `proof_grade=accepted_uart_fifo_chain`; retention and read entry sets agree
  with every real FIFO pop.
- RX DMA reads carry `dma_master`/`dma-memory`; non-RX reads use `router`.
- `descriptor.json.gz` and `fresh.json.gz`: cases, plan commands, local ticks
  and identity documents equal; execution ids differ (new processes).
- The earlier six-case boot and its case-level evidence are retained under
  `docs/reports/evidence/dma-s2-real-20261018/`; the final-source gate uses
  three multi-word cases to stay inside the bounded native window.

## P8 S3 — real error ISR in the same boot

Evidence: `docs/reports/evidence/dma-s3-real-ade3fe6/`

- Two valid (RX→RAM, RAM→RAM) and two declared illegal cases; error status was
  measured, not pre-baked: `0x40000000` (bit30 `cfg_err=1`, busy=0).
- Invalid cases: `outcome=environment_error`, `completed=False`,
  `destination_committed=False`, real `environment_error_receipt`, no target
  delivery, no destination RAM commit, real CPU take and ISR counter.
- Valid cases remain `complete` with accepted FIFO authority.
- `descriptor.json.gz` vs `fresh.json.gz`: cases, plan, ticks and identities
  equal; execution ids differ. The retained `verification.json` is a root
  equality record; the raw files are the authoritative evidence.
- The pytest console summary is missing because the bounded run was terminated
  after the evidence was written; the saved case/fresh documents and the real
  status measurement are complete.

## P8 S4 — source authority and typed prefix replay

Evidence: `docs/reports/evidence/dma-prefix-s4-real-9cbc323/`

- `1 passed in 529.76s`.
- Two RX cases (one len=2) and two illegal cases in one boot.
- Every case carries accepted UART FIFO retention/consumption proofs; RX DMA
  pops carry the `dma_master` route; typed prefix replay compares every event,
  tick and case.
- The production S4 source is unchanged at `ade3fe6`; only S2 test cases were
  adjusted after this gate.

## Boundaries that are still open

- **P6** is still fixed-instance `fresh_genomes`; persistent single-harness
  sessions, per-edge `RuntimePathContract` and closed-loop four-hit acceptance remain open for those rows. Shared mechanisms exist; provider integration and actual acceptance are incomplete.
- **P7 I5** now has a bounded independent audit: N1–N8 negative groups passed
  (20 cases), and CVE2 + PULP timer produced two certified receipts with a full
  fresh match. The original DUT exit receipts are unavailable, so the result
  retains that evidence boundary; see [the I5 candidate record](p7-i5-candidate-20261018.md)
  and [independent audit](P7_I5_ATTEMPT2_INDEPENDENT_AUDIT_20261018.md).
- **P7-D4** now has protocol-neutral route consumption for PULP APB3, ZipCPU
  Wishbone, and Caliptra AHB-Lite, each with a bounded native positive, an
  in-window route refusal, and fresh replay evidence. D2/D3 F6 remains
  unsupported and emits no `DMA_MASTER_TRANSFER` edge; this does not establish
  a physical cross-protocol bridge or P7-E general onboarding. See the
  [Caliptra D4 report](p7-d4-caliptra-protocol-neutral-dma-route-consumption-20261021.md).
- **P8 S1c**'s earlier batching change measured a 1.3699× UART-tick reduction ratio; search wall time improved from 72.352s to 58.919s (about 1.228×), below the original 5× goal. A separate scalar-baseline run and partial saved-byte audit are now recorded in [the S1c measurement report](p8-s1c-scalar-measurement-attempt1-independent-20261018.md); they do not establish 5×. The longer multi-tick harness command remains future work.
- **P8 S2/S3** final-source gates use shorter bounded case sets (three
  multi-word all-direction; two valid + two invalid) than the earlier
  six-case boot; the earlier evidence is retained and the reduction is
  documented, not hidden.
- **CVW/Vexii/BOOM**: not fully adapted. [CVW now has a real directed D4 session](cvw-directed-session-20261018.md), while RFuzz online campaign remains open. [Vexii now has a fixed CPU/IP/IRQ chain](vexiiriscv-cpu-ip-irq-20261018.md), while online campaign and generic protocol authority remain open. BOOM has a generated profile and bounded directed CPU/IP runs; generic TileLink coherent events, B-probe, DMA, and P6 row acceptance remain open. See [the BOOM adaptation status](boom-adaptation-status-20261018.md).
- Independent acceptance audit is recorded separately; this document is an
  evidence index, not a substitute for it.
