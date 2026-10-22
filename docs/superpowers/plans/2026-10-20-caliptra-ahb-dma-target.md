# Caliptra AHB-Lite DMA target adapter implementation plan

Spec: [Caliptra AHB-Lite DMA target adapter](../specs/2026-10-20-caliptra-ahb-dma-target-design.md)

## Tasks

- [x] Add provider tests for identity, context, AHB phase joins, and
  uncertain terminal behavior.
- [x] Implement the keyed full-word CTRL provider on
  `GeneratedAhbLiteRegisterSession`.
- [x] Add a prepared/compiled runtime route from one RAM word through DMA to the
  Caliptra CTRL register, with immutable one-beat admission.
- [x] Add route topology and refusal tests, including exact shared-memory and
  endpoint-object identity.
- [x] Add an opt-in native positive/fresh gate and an unselected-target refusal
  case. Keep all evidence under the selected run/evidence directory.
- [x] Run the scoped regressions and native gate; record exact commands,
  outcomes, evidence paths and limitations.
- [x] Update `docs/CURRENT_PROGRESS.md`, `docs/reports/README.md`, and the DMA
  route implementation plan.

## Status

The local implementation and native positive/fresh/refusal gate are complete for
one transaction-level path. The native refusal artifact retains the exact
Wishbone pre-backend request, command/tick identity and typed transaction key;
the gate counts direct provider method invocations. Provider effect evidence is
named as AHB write-data-phase completion and does not independently prove SHA
start acceptance. The positive integration additionally checks STATUS and the
known `abc` digest. Remote validation, a physical Wishbone-to-AHB bridge,
CPU consumption/retirement, broader Caliptra DMA and overall four-series
coverage remain open. See [the local report](../../reports/caliptra-ahb-dma-target-20261020.md).
