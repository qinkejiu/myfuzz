# BOOM → PULP GPIO directed diagnostic

Source implementation only; no builds, tests, source-authentication commands,
remote operations or simulation runs were performed.

Added scenario/boom_gpio_example.py with make_boom_gpio_chain and a bounded
diagnostic loop using standard DataflowRouter and TransactionLedger. The real
BOOM session intercepts accepted uncached TileLink A requests; the standard
router executes actual generated PULP GPIO and schedules the response back to
the CPU. The GPIO causal observation profile provides physical APB samples.
Native execution UUID, reset epoch and external request sequence key each
delivery. External D acceptance is correlated with original source/size/data.

Firmware writes decimal 53 to PADOUT at 0x400c, fences, reads that register,
and stores the CPU-observed value at 0x3000. A CPU BNE controls the success
marker at 0x3004. Neither result is preloaded. The result window uses a distinct
explicitly emitted legal uncached 0x3000 map entry rather than assuming that
0x6000 is legal. PADOUT is the high word of a 64-bit TileLink beat, with mask
0xf0; the router receives beat_bytes=8 and handles that lane translation.
All requests are checked before target effects: Get/Put only, param zero,
size two, exact PADOUT address, alignment, exact lane mask, and integer fields.
The diagnostic waits for native manager drain, both CPU result stores, both
external D acceptances and both observed GPIO APB accesses before reporting.

The reset stub was already in the native driver at commit 20259fc, written
explicitly at 0x10040/44/48. Its shift produces unsigned RV64 0x80000000;
firmware MMIO/result bases are positive low addresses. No broader boot-ROM
load API or unrestricted memory loading was introduced.

Addressed independent source-review findings in the session: retained selected
external D producer across stalls and C response enqueue, complete manifest
file set required, copied RTL and manager hashes cross-linked to independently
authenticated canonical inputs, duplicate RESPOND rejected in Python, strict
response token types, cancelled external token returned on reset, and native
alignment/mask checking. README explains raw 64-bit byte lanes.

Remaining limits: local executable hashes are integrity checks rather than
signed build provenance. This diagnostic and standalone session are not generic
ScenarioRunner admission or acceptance evidence. Interrupts/probes, denied D
injection and multiple external outstanding requests are unsupported. Runtime
verification, two fresh matching runs, negative controls and malformed-shape
checks remain pending explicit user authorization.

Final source-review cleanup: factory construction now closes an already
created CPU and ends the GPIO session if CPU/router construction fails.
External D raw receipts now include the actual driven param and sink fields,
plus beat zero for the supported single-beat response, matching the coherent
event consumer's required raw shape. No tests or builds were run.
