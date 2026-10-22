# Caliptra SHA256 AHB-Lite DMA target adapter

**Status:** Implemented for the local single-word route; remote validation remains open.

## Scope

Add a provider-specific, versioned DMA target adapter for the pinned Caliptra
`sha256_ctrl` AHB-Lite session. The first path is one full-word RAM read followed
by one full-word DMA write of value `5` to the SHA256 `CTRL` register at byte
offset `0x10`. The `CTRL` register starts the hash operation after the existing
directed setup has loaded the padded `abc` block into `BLOCK0..BLOCK15`.

The target window is 4 KiB, write-only for this route, accepts only offset
`0x10`, value `5`, and byte enable `0xf`. The provider is selected by its pinned
AHB artifact and exact AHB-Lite observation contract. Its `target_effect` proves
completion of the CTRL write data phase; it does not prove that the SHA block
accepted a start while ready. No component-name dispatch is added.

## Runtime proof

For each DMA write, the provider requires the exact `TransactionKey` and closed
delivery context, then issues one `ACCESS_AHB_REG` command. It derives the
request witness from exactly one sampled AHB address acceptance and the response
and write-completion witnesses from that transfer's following data phase. The address
phase must match offset `0x10`, write direction and word size. The data phase
must be ready, error-free, and carry the exact value. The write-completion
witness includes the same access identity and request. The common DMA dispatcher
then checks the key and access identity across all provider witnesses. This bus
receipt alone does not prove Caliptra accepted the start while ready.

The integration gate also checks STATUS and the eight real digest registers
against `sha256(b"abc")`; those observed outputs prove that this integrated run
completed the hash, but they are not part of the single-beat provider receipt.
A request/evidence
mismatch after issuing the AHB command leaves the provider uncertain and
prevents it from issuing another routed access in the same target lifetime.

## Explicit limits

This slice does not add AHB reads, BLOCK-register DMA writes, full-block DMA
feeding, Caliptra IRQ, native HRESP errors, CPU retirement, physical bridge
timing, arbitrary AHB targets, or continuous fuzzing. The pinned target ties
HRESP low, so route errors must be refused before provider dispatch. Legacy
non-DMA AHB register use remains available.

## Acceptance

- Strict provider identity and malformed-context / unsupported-register refusal.
- Request, response and write-completion witnesses share one typed transaction and
  `access_id`; duplicate or missing AHB phases refuse.
- Route compilation binds the exact `MemoryService`, `PersistentMemory`, DMA
  endpoint, AHB target object, target window, permissions and provider identity.
- Admission accepts only the selected RAM word and CTRL write of value `5`.
- Real native positive plus unselected-destination refusal and fresh replay,
  retaining the refused native pre-backend payload, tick interval and typed DMA
  transaction for offline audit.
- Positive run starts SHA256 and matches the independent `abc` digest.
- Update the route plan, current progress and report index without claiming
  generic AHB or overall four-series completion.
