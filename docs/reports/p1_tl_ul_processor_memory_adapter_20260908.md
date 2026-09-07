# Generic TileLink-UL processor memory adapter

This Task 8b substep connects a `tl-ul@1` processor memory-master endpoint to
`processor-memory-beat@1`. Selection uses the protocol and validated fields;
there is no BOOM or other CPU-name dispatch.

The adapter serializes one request through distinct A acceptance, backend
request, backend response and D response phases. It maps Get, PutFullData and
PutPartialData, preserves source and size, holds requests/responses under
backpressure, and maps backend errors to denied plus corrupt for data-bearing
responses. Address alignment, size, param, corrupt and mask rules are checked.

Unsupported ArithmeticData and LogicalData requests receive AccessAckData
errors; unsupported request forms use their corresponding error response
shape. Oversized Get requests return the size-implied number of D error beats.
Oversized requests carrying A data are drained before their D error response.
A zero-mask PutPartialData is a legal local success no-op and never reaches the
backend.

Focused simulation covers Get, partial writes, source/size round-trip, backend
and D stalls, backend errors, unsupported opcode response shape, multi-beat Get
error completion, multi-beat A drain, empty partial writes and reset. All 325
composition tests and 74 protocol tests passed. Strict Verilator `-Wall` lint
passed. Independent review found the initial zero-mask gap; after correction it
reran nine focused tests and strict lint and reported PASS.
The final repository regression passed 1002 tests with one skip in 44.663
seconds.

Evidence is retained under `runs/p1_processor_backend_20260908/` in
`task8b-tlul-red.log`, `task8b-tlul-green.log`,
`task8b-tlul-composition.log`, and `task8b-tlul-protocol.log`.
The full-suite log is `task8b-tlul-full-regression.log`.

The adapter does not execute supported multi-beat payloads through the backend,
does not support coherence, and has no timeout recovery. Real processor
boot/progress acceptance remains later work.
