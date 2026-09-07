# Processor memory beat backend contract

Task 8b begins with a protocol-neutral transaction boundary shared by the OBI,
AXI4 and TileLink adapters.  `processor-memory-beat@1` defines one in-order request
and response at a time with explicit request/response backpressure, address,
read/write selection, write data, byte enables, read data and error completion.

The contract compiles for 32-bit and 64-bit data paths and independently sized
addresses. It declares partial writes, bounded stalls, `ack_or_err`
completion and single-outstanding in-order operation.  The existing
`ready-valid-mmio@1` document, unique-ID loading and behavior remain unchanged.

This commit establishes the common endpoint only.  It does not claim that an
OBI, AXI4 or TileLink processor has been connected to it.  Subsequent Task 8b
commits must implement each protocol adapter, define explicit policies for
sideband and unsupported transaction forms, simulate temporal behavior, and
connect selection to the canonical processor boundary without CPU-name
dispatch.

Retained tests:

- `runs/p1_processor_backend_20260908/task8b-backend-red.log`
- `runs/p1_processor_backend_20260908/task8b-backend-green-2.log`
- `runs/p1_processor_backend_20260908/task8b-backend-green-3.log`
- `runs/p1_processor_backend_20260908/task8b-backend-final-regression.log`

An initial same-ID v2 draft exposed an old unversioned-load compatibility
failure during the full suite.  Giving the backend its own protocol identity
restored the existing API.  The final full regression completed 989 tests in
45.597 seconds with one pre-existing skip and no failures.  Independent review
passed and directly verified the legacy unversioned loader still resolves v1.
