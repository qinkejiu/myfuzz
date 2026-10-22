# P7 D4 PULP GPIO APB3 Admission Design

Date: 2026-10-20

## Goal

Extend the D4 live DMA topology binder with one second, bounded peripheral target: the generated PULP GPIO APB3 PADOUT target. The binder may issue only its existing `topology_bound` software credential after validating actual generated artifacts, the D2/D3 route, the existing typed runtime path, and the live target window.

## Scope and architecture

The admission is closed over the exact `GeneratedPulpGpioSession` type and the generated `pulp_gpio_causal_local` artifact. It requires `kind == "apb_gpio"`, the pinned `pulp_gpio_observation_contract`, the exact `pulp_gpio_dma_target_provider.v1` / `dma_master_target_access.v1` / `pulp_gpio_padout_apb3.v1` identity, and the exact APB3 `gpio.bus` endpoint selected by the artifact.

The D2 target selection must be `target.apb3` version `1`, variant `full-word`. The route is limited to a write-only, full-word PADOUT transaction at offset 12 (`byte_enable == 15`); no other APB3 register or target is admitted. Existing `PreparedRuntimePathContract.bind` remains the authority that checks the exact typed route and `MasterTargetWindow` object against the live Runner. The binder does not construct a replacement graph or execute a provider.

The PULP path is carried as generated D2 route and binding rows through D3 and then joined to the existing PULP RAM-read / DMA-write / GPIO-effect typed graph. All route, endpoint, template, prepared-object, and runtime identity checks remain in force. P7-C F6 remains `unsupported`; this credential establishes neither a DMA transfer nor native execution.

## Refusal behavior

Reject subclasses and lookalikes, absent or altered provider identity, missing or altered observation contract, a non-PULP artifact, a non-APB3 or unadapted endpoint, a different D2 template, any operation/permission/offset/byte-enable shape outside full-word PADOUT, and a target window or route that differs from the existing typed contract. Refusal occurs before `PreparedRuntimePathContract.bind` when the static artifact/provider/template facts are invalid; live window identity is checked by the existing prepared binder.

## Verification boundary

The software gate must include a positive generated D2 -> D3 -> D4 case, same-object prepared graph binding, route and digest preservation, and negative mutations for provider, observation, target template, endpoint shape, register layout, and route window. It must assert F6 remains unsupported and that no DMA transfer edge is added by D2/D3 compilation. No native, remote, CPU DMA configuration, payload movement, IRQ/ISR, or fresh native replay claim is made by this slice.

## Guarded runtime route lookup extension

The bound credential may retain the existing `RuntimeEdgeIndex` privately and
expose `match_dma_master_route(...)` as a convenience lookup. Every lookup first
revalidates the live compiled topology, including the exact PULP producer seal
and provider identity. The index is validated against the existing compiled
document and receives the exact already-bound `PreparedRuntimePathContract`
object; it must not deserialize that declaration into a replacement graph or
route. Before reusing it, verify that the live graph, resolved paths, per-path
selection tuples, and source caches match the immutable prepared document.

A returned match proves only that the supplied beat identity fits one selected
route. The caller must still join the accepted native request, target effect,
and response under the same `TransactionKey` before claiming a runtime
transfer. It adds neither a DMA admission policy nor executable P7-C F6.
