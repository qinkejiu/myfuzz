# ZipCPU UART TXREG DMA target adapter

**Status:** Implemented; bounded local gate and saved-evidence audit passed in
[the 2026-10-20 report](../../reports/zipcpu-uart-dma-target-20261020.md).

## Goal and route

Add one provider-specific DMA route from a single word in the existing host
`PersistentMemory` service through ZipCPU `wbdmac` to the pinned ZipCPU `wbuart`
Wishbone target. The one accepted destination is TXREG at byte offset `0x0c`;
the target window is 16 bytes, write-only for DMA, uses full-word byte enable
`0xf`, and accepts exactly the integer range `0..255`. The UART is initialized
to SETUP `25` before DMA starts so its real TX pin can be decoded at 8N1 with
25 clocks per bit.

The DMA source word and TXREG data must be identical. A successful provider
receipt joins the generated local Wishbone TXREG request, the native `wbuart`
ACK output sampled by the passive trace, and exactly one subsequently decoded
serial byte to the same DMA `TransactionKey` and provider `access_id`.

## Required identity and refusal behavior

The provider identity is `zipcpu_uart_dma_target_provider.v1` with API
`dma_master_target_access.v1` and implementation profile
`zipcpu_wbuart_txreg_wishbone_serial.v1`. It pins the generated artifact,
endpoint `uart.bus`, TXREG offset 12, accepted range `{kind: range, start: 0,
stop: 256, step: 1}`, byte enable 15, required startup write `[[0,25,15]]`,
25 clocks per bit, endpoint `uart.pins`/role `tx`, and the artifact-resolved
Wishbone `cyc`, `stb`, `we`, `adr`, `dat_w`, `sel`, `ack` passive trace map.
It must fail closed if the instance, artifact, pin map, startup setup, or
delivery context changes.

Reject values outside `0..255` before issuing `ACCESS_WB_UART`: upper TXREG
lanes can control break and UART-reset bits. Also reject any non-TXREG offset,
partial byte enable, invalid typed key, wrong testcase/window context, or
provider use before the UART is initialized. Once the native access command is
issued, missing/ambiguous request or ACK evidence, missing/duplicate serial
frames, byte mismatch, or any later evidence failure poisons the provider and
records an uncertain terminal. A possibly completed target side effect is not
replayed.

## Runtime route declaration

The graph contains one 32-bit `memory_image` RAM source, one DMA read edge, an
ordered read-to-write transfer, and one DMA write edge to the UART TXREG/serial
effect node. The compiled topology binds the exact DMA session, shared
`MemoryService`/`PersistentMemory`/ledger, RAM region, `MasterTargetWindow`,
registered UART session object and provider identity. An immutable one-beat
admission accepts only the selected source address, followed by the same byte
written to the selected TXREG address.

The route is a transaction-level dispatch between independent native sessions.
It does not model a physical Wishbone bridge or shared SoC clock.

## Acceptance

- Provider unit tests cover identity, exact context, Wishbone request/ACK joins,
  decoded TX byte, unsupported values/registers, and uncertain terminal/poison.
- Route tests cover source binding, exact live topology identities, one-beat
  admission and unselected destination refusal.
- An opt-in real gate runs DMA → real wbuart TXREG → real 8N1 output, checks the
  transferred byte, fresh execution replay, and host route admission refusal
  after observing a native DMA request to an unselected address. The refusal
  evidence retains raw Wishbone pre-backend values, command ticks, transaction
  key, direct provider-call count and no-output observation; it is not a DMA
  bus error-response test.
- Capability labels distinguish `declared`, `topology_bound`,
  `runtime_observed` and `replay_verified`; no CPU consumption/retirement,
  physical interconnect, generic UART read route or overall phase completion is
  inferred.
