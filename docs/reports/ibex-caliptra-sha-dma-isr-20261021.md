# Ibex → ZipCPU DMA → Caliptra SHA256 → Ibex ISR

Date: 2026-10-21

## Result

The local native gate passes for one bounded DMA word and an independent fresh
replay. Ibex configures the real ZipCPU `wbdmac` through OBI writes to source
`0x00022000`, destination `0x40002010`, length `1`, and keyed start. DMA reads
the declared RAM word `5` and writes the full word `5` to Caliptra SHA256
`CTRL@0x10`. The Caliptra input block for `abc` is separately loaded by host
AHB setup writes before the Runner schedule; the block bytes themselves are
not DMA-transferred.

The DMA completion IRQ is delivered to Ibex as the declared 16 CPU-tick pulse.
Ibex takes the interrupt and its ISR reads DMA status, polls SHA `STATUS`,
loads all eight digest words, and stores `mcause`, status, digest, and the
success marker to RAM at `0x24000..0x24028`. The positive result words are
`[0x8000000b, 0, 0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223,
0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad, 1]`. The stored digest is
`ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`, matching
SHA-256(`abc`).

The wrong-offset test uses the same real CPU-programmed path with destination
`0x40002014`. The native Wishbone request is observed, then the D4 route matcher
refuses it before provider dispatch. The provider/AHB counters remain at zero,
AHB ticks remain 111, there is no IRQ event, and all ISR result words including
the success marker remain zero. The refused transaction key fields are saved
under `rejected_transaction`; the serialized `typed_transaction_evidence`
contains the completed RAM read, while the in-process gate checks the rejected
key document. The Runner records a generic DMA
`harness_failure` with `status=uncertain_effect` for the rejected step and an
empty `uncertain_transactions` list; this is a host admission refusal, not an
AHB response or a claim of a DMA bus error.

## Verification

The scoped module gate after the heartbeat fix reports **17 passed, 2
skipped**; the skips are the explicitly opt-in native gates. The final native
positive/fresh attempt15 reports **1 passed in 98.59s** and wrong-offset
refusal attempt3 reports **1 passed in 46.15s**; both pytest commands returned
exit code 0. Both final runs are local and use an operation-local Verilator
cache. The earlier attempt14 fresh run had only the `after_host_setup` row in
its fresh heartbeat. The replay loop now emits the same round checkpoints and
marker polling as the first run; attempt15 has 19 checkpoints in each of the
first and fresh heartbeat streams (setup, each 10-round boundary, and terminal
round 175), and an independent read-only audit confirmed the fresh terminal
marker and 525 scheduled steps. Attempt14 is
retained as diagnostic history and is not the final positive evidence.

Final verification of the report/code slice returned exit 0 for `py_compile`,
scoped `git diff --check`, trailing-whitespace scan, and local-link checks for
the new report and slice references. The repository-wide report link scan
still finds five unrelated historical `../../runs/...` links in
`docs/reports/README.md`; this slice did not modify those entries.

Software command:

```sh
PYTHONPATH=src python3 -m pytest -q tests/integration/test_ibex_dma_caliptra_sha_real.py
```

Native positive plus fresh replay:

```sh
MYFUZZ_IBEX_CALIPTRA_SHA_DMA_REAL=1 \
MYFUZZ_IBEX_CALIPTRA_SHA_DMA_HEARTBEAT=1 \
MYFUZZ_IBEX_CALIPTRA_SHA_DMA_EVIDENCE=/home/qinkejiu/myfuzz/docs/reports/evidence/ibex-caliptra-sha-dma-isr-20261021/native-positive-20261021-attempt15 \
MYFUZZ_IBEX_CALIPTRA_SHA_DMA_CACHE=/home/qinkejiu/myfuzz/docs/reports/evidence/ibex-caliptra-sha-dma-isr-20261021/native-positive-20261021-attempt11/cache \
PYTHONPATH=src python3 -m pytest -q tests/integration/test_ibex_dma_caliptra_sha_real.py::test_real_ibex_dma_caliptra_sha_irq_isr_and_typed_fresh_replay
```

Observed result: `1 passed in 98.59s`, pytest exit code 0; a separately written
result record (not raw stdout) is archived in
[native-positive-attempt15-result.md](evidence/ibex-caliptra-sha-dma-isr-20261021/native-positive-attempt15-result.md).

Native wrong-offset refusal:

```sh
MYFUZZ_IBEX_CALIPTRA_SHA_DMA_REAL=1 \
MYFUZZ_IBEX_CALIPTRA_SHA_DMA_HEARTBEAT=1 \
MYFUZZ_IBEX_CALIPTRA_SHA_DMA_EVIDENCE=/home/qinkejiu/myfuzz/docs/reports/evidence/ibex-caliptra-sha-dma-isr-20261021/native-negative-20261021-attempt3 \
MYFUZZ_IBEX_CALIPTRA_SHA_DMA_CACHE=/home/qinkejiu/myfuzz/docs/reports/evidence/ibex-caliptra-sha-dma-isr-20261021/native-positive-20261021-attempt11/cache \
PYTHONPATH=src python3 -m pytest -q tests/integration/test_ibex_dma_caliptra_sha_real.py::test_real_ibex_dma_caliptra_sha_wrong_offset_refuses_before_ahb
```

Observed result: `1 passed in 46.15s`, pytest exit code 0; a separately written
result record (not raw stdout) is archived in
[native-negative-attempt3-result.md](evidence/ibex-caliptra-sha-dma-isr-20261021/native-negative-attempt3-result.md).

## Evidence and identities

- Positive/fresh run, joins, projections, comparison, compile inputs and
  complete heartbeat streams: [attempt15 evidence](evidence/ibex-caliptra-sha-dma-isr-20261021/native-positive-20261021-attempt15/).
- Positive gate result record: [native-positive-attempt15-result.md](evidence/ibex-caliptra-sha-dma-isr-20261021/native-positive-attempt15-result.md).
- Wrong-offset refusal receipt: [wrong-offset-refusal.json.gz](evidence/ibex-caliptra-sha-dma-isr-20261021/native-negative-20261021-attempt3/wrong-offset-refusal.json.gz).
- Negative gate result record: [native-negative-attempt3-result.md](evidence/ibex-caliptra-sha-dma-isr-20261021/native-negative-attempt3-result.md).

The positive and fresh runs each complete 175 rounds / 525 scheduled steps
(`dma`, `cpu`, `sha`). Each has one D4 bind and reuses the exact prepared path
object for that run. First and fresh have distinct CPU/DMA/SHA/Runner execution
IDs, distinct native process IDs, and distinct in-memory owners; all six native
process return codes are zero. Before event projection, raw artifact identity
documents compare equal. The typed semantic projections compare equal with
SHA-256 `44080f917808eec549e885c8a510e7960d3118ffcb99bcf525ff827a46401b84`.

The frozen profile/artifact identities are:

| Session | Component | Profile fingerprint | Source revision | Generated artifact digest |
|---|---|---|---|---|
| CPU | `ibex_rvfi_local` | `sha256:e42dd02e6c6188ad7cb837e6eb6cae50142320f55d0843143ee7429f1518a9e6` | `sha256:7fe2fcdbd5cccfafe0e774426c7417f1bf209c995918ac0ca0ea152d7d1a0cea` | `1345ca8f3f0a82e4ceeef9a7a8e193e5b7335eec9225ef9f0d7de6ddc13d92fc` |
| DMA | `zipcpu_wbdmac` | `sha256:f60f171e3c18c90140d03d1866cb9e4980f3ab1f277a2beaee17e8b757311b99` | `git:42606d2d6ef55df313772232977621b2d72f0159` | `05889d83bc7e93367bf1afa078439bde2718f4e88aba88bb114e11a41e01c654` |
| SHA | `caliptra_sha256` | `sha256:41ca23444147f3e181f6750202748cdc807559a07b4a55999d67fe12484e4447` | `git:49370266d12cb0c4a8f71b3a0ff7e54ba7d4866e` | `5f26b38151d3810ce50addcd050a8f676ca15a91d7378d1fd434ee6cdccb5410` |

The compile-input manifest binds three saved inputs: `wiring_contract.json`
SHA-256 `63674d15862739cc03027ce78eeda0c1aa6cbc42abcaba48bfa3510c1c14dcdf`,
Caliptra capability SHA-256
`0da6bd149fdc0640502c5b3ee59a1c40697be6a01e1c71b6252438cca6da21c4`, and DMA
capability SHA-256
`7a544ca5c37631034dad9c1338642ae388b129e7d0fef042fafe2316e855851a`. D3
compiled paths digest `7937bd3ac402d343d7ed0ff1ce2443a7e23b6e72c234b1a1ffd550f8ce9bf161`,
runtime-path digest `2a19c9313d6e9a6f6793738b9140169f720a8417c72bfc36eeeb60907785a3ae`,
and bound handoff digest `c1205e8c3538c077b0464e40f7c4a59716a3db9ad0578f53be85412152db0350`
are in `fresh-artifact-comparison.json.gz`.

The first run records the DMA IRQ source at DMA tick 66, a Runner-delivered CPU
pulse over ticks `[50,66)`, and the actual Ibex IRQ take at CPU tick 53. The
AHB provider receipt joins the DMA write key to `CTRL@0x10`, AHB write data `5`,
and request/response ticks 113/114. Independent read-only review verified the
attempt15 positive joins and replay. A separate read-only audit of final
attempt3 verifies the negative request and refusal deltas. Attempt3 is a
refusal-only run, not a fresh replay; its `rejected_transaction` records source
sequence 2 separately, while `typed_transaction_evidence.transactions`
contains the completed RAM read sequence 1. The compressed receipts preserve
the exact rows.

Heartbeat review found one remaining diagnostic boundary: `step_failure` is
written when a scheduled component step raises, but a failure in the separate
CPU marker-memory poll has no dedicated `step_failure` checkpoint. Attempt15
did not exercise that exceptional path; the regression directly covers a
missing terminal checkpoint, while setup/cadence corruption and marker-poll
failure do not yet have dedicated regression tests.

## Scope limits

This is one local fixed-instance, single-word path: Ibex configures ZipCPU DMA,
DMA starts Caliptra SHA by writing only `CTRL@0x10 = 5`, and Ibex observes the
completion IRQ and digest. The padded `abc` block is host-loaded through AHB
before the scheduled run. The CPU/DMA/Caliptra generated sessions are
independent, joined through transaction-level providers; the shared
`PersistentMemory` object does not establish physically shared SRAM, and this
does not establish a physical Wishbone-to-AHB bridge or a globally
cycle-accurate SoC.

Static D3 F6 remains `unsupported` with
`dma-route-live-topology-binding-required`; the live path is consumed through
one D4 bind only. Remote validation, generic F6, arbitrary AHB routes,
multiword SHA input DMA, P7-E, continuous fuzzing, and aggregate P6/P7/P8 and
six-CPU/four-IP acceptance remain open.
