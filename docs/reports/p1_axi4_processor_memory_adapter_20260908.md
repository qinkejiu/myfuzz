# Generic AXI4 processor memory adapter

This Task 8b substep connects any processor memory-master endpoint declared as
`axi4@1` to the protocol-neutral `processor-memory-beat@1` backend. Adapter
selection uses the endpoint protocol and validated field capabilities only. The
implementation and resolver contain no Ibex, CVA6 or BOOM dispatch.

The executable subset serializes traffic to one outstanding backend request.
It accepts independent AW/W arrival, holds backend requests and AXI responses
under backpressure, preserves arbitrary AXI IDs, maps byte strobes, and converts
backend errors to SLVERR. Single-transfer FIXED or INCR requests at a supported
transfer size reach the backend. Unsupported bursts, locks and atomic operations
complete locally with DECERR instead of being dropped or rewritten.

Rejected write bursts consume every W transfer declared by AWLEN before BVALID.
AtomicLoad and AtomicSwap error responses return AWLEN+1 R transfers;
multi-transfer AtomicCompare returns half as many R transfers as W transfers.
R and B remain independently valid until accepted. These obligations follow
the Arm AXI atomic transaction structure and error-response rules:
https://documentation-service.arm.com/static/651c285c15583d1bff972f94

All 16 CVA6 sample sideband fields have explicit policy. Lock inputs reject a
nonzero value, ATOP receives a complete AXI error response, request metadata is
accepted and ignored, and response user fields are driven to zero. Fixed-width
fields, direction, and the shared user-width group fail closed during adapter
resolution.

Validation retained for this substep:

- focused resolver and RTL simulation: 5 tests passed;
- all composition tests: 320 passed;
- all protocol tests: 71 passed;
- full repository regression: 994 passed, one skipped, in 47.699 seconds;
- strict Verilator `-Wall` lint passed;
- the fixed real CVA6 source boundary selected the generic AXI adapter after
  compiler-backed annotation;
- independent P0 review passed after checking atomic response counts, R/B
  backpressure, AWLEN draining, extension validation, and CPU-name independence.

Evidence logs are under `runs/p1_processor_backend_20260908/`, including
`task8b-axi-real-cva6.log`, `task8b-axi-composition.log`,
`task8b-axi-protocol-regression-2.log`, `task8b-axi-verilator.log`, and
`task8b-axi-full-regression.log`.

This adapter does not execute supported multi-transfer bursts through the beat
backend and does not implement timeout recovery. OBI and TileLink processor
adapters and real processor boot/progress acceptance remain later work.
