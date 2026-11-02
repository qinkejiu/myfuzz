# Ibex, ZipDMA and GPIO shared-flow prototype

This descriptor reuses the existing Ibex and GPIO requests, shared memory,
F1–F6 slots and host-side routing. ZipDMA is selected by its pinned source-backed
profile; its control and master Wishbone endpoints use the `dma-selected`
variant, and its completion IRQ is level-triggered and cleared by software.
The memory and devices remain independent models; this does not instantiate a SoC.

Static checks:

```bash
PYTHONPATH=src pytest -q tests/integration/test_ibex_zipdma_scenario.py
```

Once the common runtime and saved-evidence paths are ready, a single-worker
native integration attempt can be made with:

```bash
python3 scripts/run_shared_all_flows.py --native \
  --descriptor configs/scenarios/compiled-f1-f6-ibex-gpio-zipdma-shared/generic_scenario.json \
  --output runs/ibex-zipdma-gpio-shared \
  --cache runs/ibex-zipdma-gpio-shared-cache
```

The descriptor and static checks do not establish native F1–F6 execution or
fresh replay; these require a separate run and inspection of the evidence.
