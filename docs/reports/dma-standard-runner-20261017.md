# Real CPU/DMA execution in ScenarioRunner

The real generated Ibex and ZipCPU wbdmac now execute through ordinary `ScenarioRunner.step()` calls. CPU MMIO configuration is queued in DataflowRouter and serviced by the scheduler's DMA step. DMA uses the existing PersistentMemory/TransactionLedger service; its actual master requests, RAM read/write facts, every pre/post native sample, and physical IRQ enter the shared Runner journal. The declared IRQ delivery policy stretches the native pulse for 16 CPU-local ticks; actual CPU IRQ acceptance and ISR execution remain RTL observations.

`GeneratedWishboneDmaScenarioSession` preserves the direct driver's receipt API for control accesses and exposes the Runner mapping API for idle scheduler edges. It exports the single source-declared native IRQ, accounts for indirect register-access ticks, and retains samples from every control edge. Native ticks are preserved separately while public local ticks remain monotonic across a warm reset. This initial Runner interface accepts RAM master targets; it explicitly refuses IP master targets until their indirect scheduler budgets are integrated.

## Actual results

The final isolated real gate passed **1 test in 54.07s**. CPU writes four source words and actual DMA control registers. The DMA accepts four RAM reads and four RAM writes; CPU receives one native external IRQ and its real ISR stores mcause `0x8000000b`, destination words, and success `1`. The complete prefix contains 256 scheduler steps, 128 CPU ticks, 148 DMA ticks, and 1,682 journal events. All 148 DMA ticks have pre/post observations, including ticks advanced by CPU control transactions. The scheduler's initial DMA bound is one edge; when a queued CPU control access is ready it is 33 edges (one selected edge plus the declared 32-edge control bound).

A second fresh CPU/DMA process pair executes the exact same 256-component schedule with identical generated identities. Every journal event matches after replacing only the two declared native process UUIDs and the Runner UUID. The test also applies `warm_all`, then advances both components and verifies monotonic DMA sample ticks after process replacement. This is a complete directed prefix comparison, not the general authenticated-prefix evidence-bundle replay admission.

Final command under the local `.superpowers/heavy-worker.lock`, working directory `/home/qinkejiu/myfuzz/.superpowers/dma-runner-20261017/snapshot`:

```sh
MYFUZZ_DMA_RUNNER_REAL=1 \
MYFUZZ_DMA_RUNNER_CACHE=/home/qinkejiu/myfuzz/.superpowers/dma-runner-20261017/cache \
MYFUZZ_DMA_RUNNER_EVIDENCE=/home/qinkejiu/myfuzz/.superpowers/dma-runner-20261017/evidence \
PYTHONPATH=src python3 -m pytest -xq tests/integration/test_ibex_dma_runner_real.py
```

Focused software gate: `PYTHONPATH=src python3 -m pytest -q tests/local_harness/test_wishbone_dma_scenario_session.py tests/local_harness/test_wishbone_dma_error_recovery.py tests/local_harness/test_wishbone_dma_session.py` → **9 passed, 2 skipped in 3.31s**. Its regression caught a native sample tick missing the cumulative reset tick base before the fix. Independent spec/code-quality review found no Important/Critical findings; review is `.superpowers/sdd/runtime-integrations-review-20261017.md`.

The successful RTL run uses a frozen source tree and independent Git metadata. Five task files match the saved `task-source-files.sha256`. Full frozen Python source hashes and runtime build identities are retained. Parallel GPIO version-authority changes to other live source files are outside this run's source identity; the run does not certify the combined current tree. Two earlier setup/assertion failures are retained: source verification rejected a third-party symlink outside the snapshot; the initial test incorrectly expected a queued-control budget before any request was queued. Neither failure was fixed by relaxing runtime guards.

## Remaining P8 work

The standalone UART TX/RX FIFO proofs retain their own earlier source identities. They are not yet master targets in this new Runner interface. Multi-case DMA search, full source-version/FIFO provenance certification, generic authenticated-prefix replay admission, and multi-word FIFO behavior remain open. P8 remains unaccepted.

## Saved evidence

[Evidence directory](evidence/dma-runner-20261017) contains both complete compressed journals, exact schedules and generated identities, final gate output, earlier attempt logs and source hashes.

| File | SHA-256 |
| --- | --- |
| `fresh.json.gz` | `030e0cd9841e4348576b04bf574781267573fcf3f73e1318fc9e8d1fa81def70` |
| `frozen-host-sources.json.gz` | `05fe71f963a10d4437fec9215580df1e5ef32b2c7947cc98beb201b83fc4fa08` |
| `gate.log` | `d2c2ab2fbdbded911ec62667e57f0d10096071213d837640c99372fd37fe56e9` |
| `prefix-replay-passed.log` | `df2ee49fbbbbf30ae4c63d5fa4f574deb2b1a405986b79584c9d5e87e20d927c` |
| `runner.json.gz` | `e0d27825ee5db8ed0bf19fe8d3870ba15c61bdf83a84e8745026592297e87490` |
| `setup-symlink-refusal.log` | `e95c84645ac4721c31ba3c664b2809ef7367f6ab788a29a552350a031640af1f` |
| `single-run-passed.log` | `4aa92fcb4f6c5864e29656b77331d2167a1f1f17b49933c31e7454de9a501919` |
| `task-source-files.sha256` | `d68891842f6421d44ae02a6e58e31cf5d03e43691da9ee6623381ac0b414a7a7` |
| `test-initial-budget-failure.log` | `a7a85791c7c187cb8787baec94b8b4a29b5d28ec34f059fb414c0726de284aa9` |
