# Vexii CPU-programmed DMA RAM Implementation Plan

> Use subagent-driven-development for disjoint firmware, router and evidence
> implementation; independent review before native acceptance.

**Goal:** Real Vexii CPU-programmed four-word RAM DMA with full fresh and
wrong-key refusal, closing the missing CPU/DMA cell at its exact profile.

**Architecture:** Existing reduced-AXI CPU queued MMIO joins the existing
standard Runner through its same Router, and the existing Wishbone DMA shares
RAM. Parameterized RV32I image construction reuses the accepted CVW sequence.

**Tech Stack:** Python, generated RTL, Verilator, standard ScenarioRunner.

**Status (2026-10-22):** This bounded slice is accepted at native-attempt3:
actual worker exit0 in52.51s, positive/wrong-key each complete independent
fresh, eight DUT exits zero, independent saved-evidence audit PASS. Failed
attempt1(PMA layout) and attempt2(live tuple/list gate assertion) are retained.
No CPU RTL/profile or4000roundbound was changed. Wider system goal OPEN.
See [report and exact evidence](../../reports/vexii-dma-ram-20261022.md).

## Global constraints

- Follow ../specs/2026-10-22-vexii-dma-ram-design.md exact addresses and evidence.
- Preserve dirty shared tree; no commit/stage/reset/cleanup or remote operation.
- No CPU/IP name branch in generic protocol or Runner; no host source/config.
- Native runs one worker under canonical heavy lock, source freeze during run.
- No promotion to physical/coherent/IRQ/F6/general system acceptance.

## Task1: reusable firmware and Vexii layout

Own src/myfuzz/scenario/dma_ram_firmware.py, cvw_dma_example.py and
vexii_dma_example.py. Extract accepted instruction sequence into
`dma_ram_images(*,main,source,destination,result,dma_base,words,boot_bytes=512,start_key=0xfed)`.
Preserve cvw exports and exact output bytes. Vexii exports MAIN,BOOT_BYTES,
DMA_BASE,SOURCE,DESTINATION,RESULT,WORDS and `vexii_dma_images(*,start_key=0xfed)`.

- [x] Extract image construction preserving encoders and refusal.
- [x] Verify both CVW valid/wrongkey images against frozen executed bytes.
- [x] Independently review actual firmware encodings/addresses/branches.

## Task2: reduced-AXI Router discovery and fixture

Modify only vexii_axi_session.py for read-only router property returning
mmio_router; no identity/schema/queue-callback changes. Create
scenario/vexii_dma_runner.py with
`make_vexii_dma_runner(*,cache_dir,start_key=0xfed)` returning ScenarioRunner.
Use baseline GeneratedReducedAxiCpuSession and no IRQ fields/bindings. Factory
preloads only declaredimages, cleans every constructed session on later failure.

- [x] Expose same Router without CPU-name dispatch.
- [x] Build unstarted fixture and inspect registered targets/pending/tick bounds.
- [x] Verify queue/drain/reset invariants and partial construction cleanup.
- [x] Independent static review of adapter and fixture.

## Task3: actual native evidence gate

Create scripts/verify_vexii_dma_ram.py with explicit native optin and canonical
lock. Record full actions/samples, including CPU begin_quiesce after marker
if needed, no manual host queue drain;4000rounds bound. Enforce all six required
evidence groups, preserve failure bundles with unconditional cleanup, refuse
optimized Python, compare identities before UUID normalization.

- [x] Implement and review native gate against actual AXI/Wishbone schemas.
- [x] Run positive,wrongkey and full independent fresh of each in unique attempt.
- [x] Independently audit saved evidence and preserve all exact executed bytes.
- [x] Update progress/runtime/report/plan indexes; wider system goal stays OPEN.
