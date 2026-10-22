# P7 D4 Protocol-Neutral DMA Route Consumption

Date: 2026-10-21

## Result

Added a shared `DmaMasterRouteAdmission` and used it for two live targets with different target protocols: PULP GPIO over APB3 and ZipCPU UART over Wishbone. The shared gate resolves each observed DMA read/write against the exact route selected by the D4-bound topology, validates every returned `DmaMasterRouteMatch` field, delegates protocol-specific sequencing/value checks to the existing beat policy, and records a route match only after policy acceptance. A response must use a transaction key with an earlier admitted route match.

The PULP public import `PulpGpioD4RouteAdmission` remains available as an alias to the shared implementation. PULP PADOUT and ZipCPU TXREG semantics remain in their existing beat policies and target providers. Existing compile helpers retain their immediate bind/install behavior.

The native ZipCPU fixture now uses a generated CPU artifact sharing the live RAM, a generated DMA artifact with endpoint-link evidence, and matching D2/D3/live RAM geometry. Each positive, refusal, and fresh execution prepares the same typed route graph, binds that exact prepared object once, and installs the shared D4 gate. The D2/D3 helper remains backward compatible with its original aperture and now accepts an explicit RAM base/size for the native fixture.

## Verification

The protocol-neutral unit, PULP/ZipCPU typed-path, target-policy refusal, and D2/D3/D4 binding gate passed **68 tests in 42.69 seconds**. The target-policy test verifies that a topology route match followed by a target-object identity refusal does not commit a route-match row or change beat-policy state.

The ZipCPU native gate passed **1 test in 63.42 seconds**. Its positive and fresh executions each show one D4 bind of the same prepared object, route matches for `(0,0)` RAM read and `(2,0)` UART write, a keyed RAM read and successful read/write responses, the UART Wishbone request/ACK/provider effect, and one decoded TX byte `0x41`. Fresh normalized reference and replay compare equal. The in-window `UART_BASE + 8` native write was refused after the RAM read because the selected D2/D3 route permits TXREG offset 12 only; the refusal evidence has only the read route match, zero provider receipts, unchanged UART ticks, and no serial byte.

After migrating PULP to the shared gate, its complete native file passed **2 tests in 76.86 seconds**: the PADOUT positive with independent fresh replay and the `PADOUT + 4` refusal before provider/APB activity. Both positive executions bind once to the same prepared graph and consume route edges `(0,0)` and `(2,0)`; normalized fresh comparison is equal.

Evidence directories:

- ZipCPU Wishbone: [`descriptor.json.gz`, `fresh.json.gz`, `comparison.json`, `native-refusal.json.gz`, `manifest.json`](evidence/p7-d4-zipcpu-native-route-consumption-20261021/)
- PULP APB3 shared-gate regression: [`reference.json.gz`, `fresh.json.gz`, `comparison.json`, `unselected-offset-refusal.json.gz`, `manifest.json`](evidence/p7-d4-pulp-generic-route-admission-20261021/)

Independent review found that the prior ZipCPU negative address was outside the target aperture. It was changed to the in-window `UART_BASE + 8` so the live target object is selected and the exact D4 route's offset constraint causes refusal. The final native gate passed with this stronger negative. The first PULP verification after extraction showed that refusal behavior was correct but the old test asserted a PULP-specific error string; the test now checks the shared route-match refusal, and the final complete native file passes.

## Scope

This is transaction-level process composition. It does not establish a physical Wishbone-to-APB bridge, CPU DMA programming/consumption/retirement, arbitrary Wishbone/APB3 target support, multiword DMA, or P7-E general onboarding. F6 remains `unsupported`, D2/D3 still emits no DMA transfer edge, and no P6/P7/P8 or six-CPU/four-IP completion is claimed.
