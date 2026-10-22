# P7 D4 Caliptra SHA256 AHB-Lite Target Admission Design

Date: 2026-10-20

## Goal

Add one bounded Caliptra SHA256 AHB-Lite target to the existing P7 D4 topology binder. The only admitted target operation is a full-word write of value `5` to `CTRL` at byte offset `0x10` on the generated `sha256.bus` endpoint.

## Selected approach

Extend the existing closed target predicate in `dma_intent_topology_binding.py` for the exact generated `GeneratedAhbLiteRegisterSession`. Keep the admission specific to the existing Caliptra provider identity and its registered AHB-Lite template. The alternative of registering arbitrary AHB targets would overstate what the single Caliptra provider proves; a second Caliptra-only binder would duplicate the existing topology credential and prepared-path validation.

Before D4 binds, the target must match all of these facts:

- Generated artifact profile `caliptra_sha256`, request instance `sha`, runtime kind `ahb_lite_register_observe`, 4 KiB aperture, and adapted endpoint `sha256.bus` with protocol `ahb-lite@1`.
- Pinned trace identity `ip_protocol_trace.v1`, protocol `ahb-lite`, endpoint `sha256.bus`, and exactly these provider roles and widths: `haddr:32`, `hwdata:32`, `hsel:1`, `hwrite:1`, `hreadyin:1`, `htrans:2`, `hsize:3`, `hresp:1`, `hreadyout:1`, `hrdata:32`.
- Provider identity `caliptra_sha256_dma_target_provider.v1`, API `dma_master_target_access.v1`, implementation `caliptra_sha256_ctrl_ahb_write_completion.v1`, and artifact digest equal to the generated artifact digest.
- D2 selection `target.ahb-lite` v1 `full-word-single`, matching the exact endpoint policy stored in the generated artifact plan request. Recompute the registered contract and selection identity from that pinned request, endpoint, and profile; the current generated executor document does not duplicate this AHB policy under `protocol_templates`.
- A write-only `CTRL` register at offset `0x10`, width 32; route permission `write`, byte enable `15`, readable offsets empty, writable offsets `(0x10,)`, and accepted write value `5` only.

The binder must reject provider-method shadows before reading provider identity, resolve provider helpers through the class MRO, snapshot provider implementation and identity, and recheck them whenever the bound topology is validated. The checked call path includes the provider methods, artifact-stability check, command/readiness path, and AHB take helpers. It also pins stable configuration omitted from the provider identity: artifact/runtime kind, instance, access operation, `_window`, and the CTRL offset/start constants. Mutable event receipts are not part of this stable identity. The existing `PreparedRuntimePathContract.bind` continues to validate the live DMA `MasterTargetWindow` and typed route identity.

## Preparation and compile behavior

Add a pure `prepare_caliptra_sha256_dma_runtime_paths(...)` path that constructs the existing RAM-read / DMA-write / SHA CTRL typed graph without binding a runner or installing beat admission. Preserve `compile_caliptra_sha256_dma_runtime_paths(...)` as the compatibility API: it calls preparation, binds the same prepared object once, constructs and installs the existing one-beat admission, and returns the compiled result.

The P7 D2/D3 integration case must carry the route and binding rows unchanged through compilation and D4. The positive D4 bind uses the already-prepared graph object exactly once. F6 remains `unsupported`, and neither the D2/D3 dependency graph nor the runtime path contract gains a DMA transfer edge.

## Refusal and verification

Use one generated Caliptra artifact and the existing Caliptra typed route. Verify refusal before live bind for a non-exact session, instance-shadowed provider methods, wrong profile/runtime kind, wrong endpoint/protocol/adaptation, altered provider identity/trace, wrong AHB template, non-write/permission/offset/value/byte-enable policies, and a changed live target window. After a successful bind, verify that provider method or identity drift invalidates topology validation and that restoring the original identity restores validation.

The software gate reuses the existing D4 topology, route and replay readers. It does not rerun a native Caliptra build or gate. The separate native Caliptra report remains independent evidence for its bounded local transaction; this D4 credential only admits a topology and does not certify AHB execution, SHA completion/digest, a physical Wishbone-to-AHB bridge, CPU consumption/retirement, IRQ, generic AHB onboarding, F6 execution, or overall four-series / six-CPU acceptance.
