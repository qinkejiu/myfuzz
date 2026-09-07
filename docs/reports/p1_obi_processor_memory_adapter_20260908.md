# Generic OBI processor memory adapter

This Task 8b substep connects an `obi@1` processor memory-master endpoint to
the protocol-neutral `processor-memory-beat@1` backend. Selection and module
parameters come from declared protocol fields. No CPU name participates.

The adapter supports one outstanding transaction. OBI `gnt` occurs exactly
with backend request acceptance, and the initiator retains its normal OBI
obligation to hold request payload while grant is stalled. A backend response
is consumed only while an OBI request is outstanding and produces one-cycle
`rvalid`, data, and error outputs because this OBI profile has no response
backpressure.

Instruction-style read-only endpoints omit both `we` and `wdata`; the resolver
then selects `READ_ONLY=1`, forces backend writes low, and supplies full byte
enables. Read/write endpoints must declare `we` and `wdata` together. An
optional `be` output passes byte enables only when its width equals data width
divided by eight. The endpoint must expose an explicit error input so backend
failures are observable. Missing error, partial write-field declarations,
byte-enable on a read-only endpoint, wrong direction, and wrong width all fail
during composition.

Validation for this substep includes read/write stalls, request payloads,
grant timing, byte enables, response data/error, one-cycle response behavior,
read-only projection, reset with an outstanding transaction, and renamed
ports. All composition tests passed (323), all protocol tests passed (73), and
strict Verilator `-Wall` lint passed. Independent review reran 18 focused tests
and strict lint and reported PASS. The final repository regression passed 999
tests with one skip in 44.308 seconds.

Evidence logs are under `runs/p1_processor_backend_20260908/`:
`task8b-obi-red.log`, `task8b-obi-green.log`, `task8b-obi-composition.log`,
`task8b-obi-protocol.log`, and `task8b-obi-verilator-2.log`.
The full-suite log is `task8b-obi-full-regression.log`.

Timeout recovery, multiple outstanding requests, the TileLink processor
adapter, and real processor boot/progress acceptance remain later work.
