# Shared CPU, RAM, DMA and GPIO execution

This configuration runs independent real Ibex RVFI, Wishbone DMA and causal GPIO
harnesses. The host models memory and data movement; it does not generate or
connect a SoC. CPU and IP requests reuse existing component adapters.

The declared paths are F1–F6. The fixed common IRQ entry dispatches to separate
DMA and GPIO handlers. Host OR delivery records each actual source; joint
activation does not grant a single-source IRQ completion certificate.

Integration acceptance (requires the native toolchain):

```bash
python3 scripts/run_shared_all_flows.py --native \
  --output research/input-strategy-audit-20261027/runs/shared-all-flows-20261028 \
  --cache runs/config-driven-20261028/cache
```

The eight online cases cover RAM write/read, GPIO configuration, high/low pin
stimuli, PADIN consumption and two DMA transfers. Each choice follows actual
completion. Both F5 cases must independently verify the full IRQ/ISR chain, and
the full prefix must match a fresh execution. A declared capability or successful
pin submission alone does not satisfy this acceptance.

Search catalog: `configs/search/shared-all-flows.json`. Status and actual run
evidence are tracked in `docs/reports/universal-system-completion-audit-20261028.md`;
this configuration's existence does not establish native acceptance.
