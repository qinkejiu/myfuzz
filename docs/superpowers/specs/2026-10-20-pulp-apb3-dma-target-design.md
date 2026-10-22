# PULP APB3 DMA Target Provider

**Status:** Approved implementation slice, 2026-10-20. The user approved continuing with the previously recommended RAM → ZipCPU Wishbone DMA → PULP GPIO PADOUT route.

## Goal

Allow a declared ZipCPU `wbdmac` destination route to perform one real full-word write to PULP GPIO `PADOUT` through the existing generated APB3 session, while preserving the shared DMA route contract and transaction identity.

## Selected design

Add a small target-provider interface named `dma_master_target_access` to the DMA runtime. A provider receives the accepted DMA beat's exact `TransactionKey`, address, offset, operation, value, byte enable, and delivery context. It returns a closed `dma_master_target_access.v1` receipt that binds the same key and request to the observed target access, request/response witnesses, and a target-effect proof. The DMA session validates the common receipt shape and exact request/key joins without knowing APB3 or GPIO register semantics.

`GeneratedPulpGpioSession` implements this provider using its existing `routed_register_access` path. The first supported operation is a 32-bit write to PADOUT at offset `0x0c`. The provider requires one observed APB access, observed request and response transport witnesses, zero APB error, and a post-edge native `gpio_probe_out` value equal to the accepted DMA word. It rejects reads and other offsets in this first slice.

Add a small prepared route graph for a declared RAM image word → DMA RAM read → DMA target write → PULP PADOUT effect. It binds both DMA routes to the live DMA endpoint and the exact RAM/window identities already enforced by `RuntimePathContract`. Route compilation does not claim a transfer; only the joined native request, provider receipt, target effect, and native response establish runtime observation.

`MasterTargetWindow` continues to own the aperture, permission, offset, full-word byte enable, and accepted-value declaration. Validation of a `range` must be constant-time so a complete 32-bit word range can be represented without enumerating four billion values. Existing UART S4 behavior and serialized identities remain compatible.

## Rejected alternatives

- A PULP-specific conditional in `GeneratedWishboneDmaSession` would duplicate provider details in the generic DMA engine and make the next target family harder to add.
- Calling `write_register` directly would perform an APB action but discard the keyed request/response and observed target-effect proof required for a DMA transfer claim.

## Failure behavior and scope

- An undeclared address, unsupported operation/offset, partial byte enable, or unaccepted value is rejected before the PULP target callback. The DMA environment may return its existing real error response for a declared controlled negative case.
- A missing, mismatched, duplicated, or incomplete provider receipt raises an uncertainty/error path and cannot be counted as a successful transfer.
- APB `PSLVERR`, missing APB transport witnesses, or a PADOUT post-value mismatch cannot produce a successful route receipt.
- The callback executes at transaction level between independently clocked RTL sessions. This is not a synthesizable Wishbone-to-APB bridge or global cycle-accurate interconnect.
- This slice does not close P7 F6, P6, P7, P8, continuous DMA fuzzing, the other DMA IP providers, or all six CPU adaptations.

## Acceptance

1. Unit tests prove exact provider receipt/key/request validation, full-word and aperture rejection, PULP APB request/response/effect proof, and bounded accepted-value range validation.
2. Route compiler tests prove the RAM-read and PULP-write route rows bind to the exact live memory/window and reject missing, substituted, or mutated topology.
3. Existing UART DMA route tests retain their behavior.
4. A real generated DMA + PULP GPIO run writes the selected RAM word to PADOUT, records native Wishbone acceptance/response and measured APB request/access/response/effect, and an independent fresh run reproduces the typed result.
5. Reports distinguish `declared`, `topology_bound`, `runtime_observed`, and `replay_verified`; they do not claim a physical bridge or P7 F6 acceptance.
