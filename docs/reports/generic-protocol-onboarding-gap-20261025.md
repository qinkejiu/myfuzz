# Generic same-protocol onboarding gap audit — 2026-10-25

## Current boundary

`DmaMasterRouteAdmission` is protocol-neutral for matching an admitted read or
write route against a typed transaction key and beat policy. It does not execute
APB3, Wishbone, or AHB-Lite target transactions and does not own target effects.

The bounded D4 native consumers currently cover three fixed provider instances:

| Protocol | Fixed provider instance | Bounded target effect |
|---|---|---|
| APB3 | PULP GPIO `gpio.bus` | `PADOUT` at offset 12 |
| Wishbone | ZipCPU UART `uart.bus` | `TXREG` at offset 12 |
| AHB-Lite | Caliptra SHA `sha256.bus` | `CTRL` at offset 16 |

Each has bounded positive, wrong-offset refusal, and fresh evidence. They show
that these fixed providers use the shared route admission API; they do not prove
an arbitrary same-protocol target executor. OpenTitan TL-UL currently has a
topology-binding example, not native DMA target consumption. Reduced AXI remains
an observation-only journal consumer (`runtime_accepted=false`,
`semantic_accepted=false`).

## Why onboarding remains name-bound

`dma_intent_topology_binding.py` uses a closed set of exact session classes and
then branches on PULP GPIO, ZipCPU UART, or Caliptra AHB identity for target,
register, and template checks. Generic APB3 storage F4 similarly requires an
exact generic session with a source-registered contract. These are safe bounded
providers, but they are not arbitrary same-protocol inference or execution.

## Recommended next slice

Implement a versioned APB3 D4 storage-target adapter driven by an explicitly
verified source contract. The contract must provide register semantics,
offset/value policy, source closure, and observation receipt; execution must be
selected by protocol/template capability and verified contract, without
`component_id`, IP name, or exact provider-session branches.

Start with an already source-registered APB3 storage row, then bind a second
renamed APB3 target through the same adapter. The gate should include D2→D3→one
prepared-graph D4 binding; actual RAM read, APB setup/access/response/effect and
route joins; in-window wrong-offset refusal before provider effect; tampered
provider/source/template/window/response refusals; and native first plus a new
PID/nonce fresh full replay with independent raw/manifest audit. P7-E still
requires a genuinely new CPU and IP through the automatic source/profile to
multi-case feedback/checker path, with a similar-name negative control.

## Audit evidence

- Shared route matcher: `src/myfuzz/scenario/dma_route_admission.py`.
- Provider selection and identity branches:
  `src/myfuzz/scenario/dma_intent_topology_binding.py`.
- APB3 storage F4 source-registration boundary:
  `src/myfuzz/integration/compiled_storage_producer.py`.
- Existing bounded provider evidence: [protocol-neutral D4 report](p7-d4-protocol-neutral-dma-route-consumption-20261021.md),
  [Caliptra follow-up](p7-d4-caliptra-protocol-neutral-dma-route-consumption-20261021.md),
  [six-CPU/four-IP audit](dma-six-cpu-four-ip-status-20261022.md),
  and [Reduced AXI crosswalk](reduced-axi-journal-crosswalk-20261022.md).

This was a read-only audit. No source code, tests, native runs, builds, or remote
work were changed or executed for this report.
