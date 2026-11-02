# Profile-driven shared DMA scenario

Provide one previously adapted CPU request and one previously adapted DMA
request plus its capability, as in `cv32e20-zipdma.json`. Generate a scenario:

```sh
python3 scripts/generate_shared_dma_scenario.py \
  --config configs/scenarios/shared-dma-profile-examples/cv32e20-zipdma.json \
  --output runs/cv32e20-zipdma-generated
python3 scripts/preflight_generic_scenario.py \
  --descriptor runs/cv32e20-zipdma-generated/generic_scenario.json
python3 scripts/run_shared_all_flows.py --native \
  --descriptor runs/cv32e20-zipdma-generated/generic_scenario.json \
  --output runs/cv32e20-zipdma-validation --cache runs/config-driven-20261028/cache
```

The generator selects DMA endpoints, Wishbone SEL variant and IRQ type from
the source-verified DMA provider, and derives the CPU boot address from its
source-backed boot contract. It reuses the existing shared F1–F6 runtime and
its fixed GPIO companion, memory layout and records. Currently it accepts the
registered OBI RV32 CPU and wbdmac/ZipDMA providers; a profile alone does not
add support for unregistered DMA behavior. It neither runs RTL nor proves
that the generated combination passes; run and inspect native results.
Preflight reports static support only; runtime admission is not checked.

An optional `target` selects a separate source-backed APB storage peripheral
for F2/F4, while the existing GPIO companion still supplies the F5 stimulus.
See `cv32e20-zipdma-timer.json`. The target request must identify its single
`apb_storage_observations` register; the generator derives its endpoint,
offset, and storage contract from that component instead of a CPU/IP pair.
Use the generated `acceptance_sequence.json` with `run_shared_slot_subset.py`
when testing that scenario: the canonical GPIO-specific F2/F4 bytes do not
represent the selected target's registers. This is currently limited to a
source-backed full-word storage register; it does not infer arbitrary IP state
or give the target an IRQ or DMA it does not declare.

`cv32e20-newid-irq-adapter-zipdma-i2c.json` selects an unregistered CPU
component ID whose profile embeds its source manifest and explicitly selects
the existing source-verified CV32E20 IRQ adapter. The CPU RTL is the same
CV32E20 design; this checks profile identity independence, not a new CPU
design. The adapter requires its pinned source, CPU semantics, physical ports
and real controller decision probes. Its profile declaration alone does not
prove execution. F5 uses the existing GPIO companion.

`cv32e40p-profile-embedded-zipdma-i2c.json` selects the real CV32E40P
limited-RVFI CPU through a timing-extended profile and reuses the embedded
DMA and target profiles. Its CPU ID remains the registered
`cv32e40p_rvfi_local` because the official observation wrapper and source
closure are pinned by the existing CPU adapter. The IRQ adapter observes
actual decision, ack/id and entry PC; no exact serial or unobserved retirement
fields are inferred. Native execution remains required for runtime evidence.
