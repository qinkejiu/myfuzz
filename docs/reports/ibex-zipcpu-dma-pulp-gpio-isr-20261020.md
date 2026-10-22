# Ibex → ZipCPU DMA → PULP GPIO → Ibex ISR

Date: 2026-10-20

## Result

The local native gate runs a bounded one-word transfer configured by real Ibex
OBI writes: ZipCPU `wbdmac` reads `0x5aa55aa5` from shared host
`PersistentMemory` at `0x00022000`, writes it to the PULP GPIO `PADOUT` register
at `0x4000100c`, and raises its native completion IRQ. The Runner's declared
16-tick pulse latch delivers that IRQ to Ibex. The ISR reads DMA status, PADOUT,
and the expected source word, compares the values, and stores the cause, status,
observed value, expected value, and success marker in RAM.

The recorded CPU retire receipts prove the three ISR loads at their declared
addresses and values. The native gate also joins the DMA read/write
`TransactionKey`s to this run's DMA execution and testcase, joins the PULP
target request/APB access/register effect/response by source key and access ID,
and requires the actual CPU external-IRQ take and ISR result stores.

## Fresh replay and refusal

The fresh run consumes the reference run's exact recorded component schedule
and uses new native execution identities and process IDs. The full semantic
event prefix matches after typed field-level normalization scoped to `cpu`,
`dma`, `gpio`, and `runner`; event values, local ticks, addresses, artifact
identities, payloads, and transaction sequence suffixes remain exact.

The negative case issues a real native Wishbone DMA write to `PADOUT+4`. Route
admission raises a `ValueError` after sampling the request and before provider
dispatch. The evidence has zero target-provider calls, zero PULP target/APB
accesses, unchanged `gpio_out`, no success marker, and clean native process
return codes. This is an environment-side refusal, not a DMA bus-error response.

## Verification details

- Software gate: **116 passed, 2 skipped in 0.43s**. The skips are the two
  opt-in native cases, which were run with the explicit gate below.
- Native gate: **2 passed in 80.84s**; pytest exit code 0. Reference and fresh
  each record 300 scheduler steps (100 fixed `dma`, `cpu`, `gpio` rounds),
  3,031 Runner events, and process return codes 0 for all three sessions. Fresh
  uses the exact reference schedule and distinct execution UUIDs and PIDs.
- Both successful results are `[0x8000000b, 0, 0x5aa55aa5, 0x5aa55aa5, 1]`.
  Typed replay comparison is equal with normalized semantic SHA-256
  `ace2acf88b33ffc565ca5d78d9c44d9364dcc26cf5c190c273619a93851f9b85`.
- The wrong-offset run records 163 component steps and one native write request
  to `0x40001010` (`mwb_adr=0x10000404`, `mwb_dat_w=0x5aa55aa5`). It ends with
  route state `expect_write`, provider calls 0, only GPIO tick-observation
  events, `gpio_out=0`, and all session processes returning 0.
- Runtime-path compilation records contract SHA-256
  `59cd7bd024ba78062c348955fbf70a7cee7b7074e45c3d7b4ee237b1aa1c4d22`, graph
  SHA-256 `2d6f11dde03b86e28ee3470097fc32d040075b77bf976ef47610785ab62ff49d`,
  and path ID `9ceeb5747bf5cc0d19f6ba196ecad8f1ce47adc4fb2ebf151532bf0f18c0493f`.
  Its proof scope remains `selected_declared_topology_only`, with
  `runtime_causality_verified=false` and `resource_versions_verified=false`;
  native receipts and their joins establish the measured transfer for this run.

Software command:

```sh
PYTHONPATH=src pytest -q tests/scenario/test_ibex_dma_pulp_gpio_example.py tests/scenario/test_ibex_dma_pulp_gpio_runner.py tests/scenario/test_replay_normalize.py tests/scenario/test_pulp_gpio_dma_paths.py tests/integration/test_ibex_dma_pulp_gpio_real.py
```

Native command:

```sh
MYFUZZ_IBEX_PULP_DMA_REAL=1 MYFUZZ_IBEX_PULP_DMA_CACHE=/tmp/myfuzz-ibex-pulp-cache-20261020 MYFUZZ_IBEX_PULP_DMA_EVIDENCE=/home/qinkejiu/myfuzz/docs/reports/evidence/ibex-zipcpu-dma-pulp-gpio-isr-20261020 PYTHONPATH=src pytest -q tests/integration/test_ibex_dma_pulp_gpio_real.py -s
```

## Evidence and commands

Raw compressed bundles, normalized comparison, run receipt, and a SHA-256
manifest are in [the evidence directory](evidence/ibex-zipcpu-dma-pulp-gpio-isr-20261020/).
The software regression and opt-in native gate results, exit codes, run counts,
process identities, and source hashes are recorded in
`run-receipt.json` and `sha256-manifest.json`.

## Scope limits

This is one local, fixed-instance, one-word transaction-level path. RAM is a
host `PersistentMemory` service and Wishbone-to-APB target delivery uses the
declared provider contract between independently generated sessions. It does
not prove a physical Wishbone-to-APB bridge, physically shared SRAM, arbitrary
DMA routes, multiword or continuous fuzzing, remote PULP execution, Caliptra
payload DMA, generic F6 support, six-CPU/four-IP completion, or aggregate P6,
P7, or P8 acceptance. Those gates remain open.
