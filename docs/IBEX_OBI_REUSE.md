# Generated OBI CPU reuse: CVE2 and Ibex

The `obi_cpu` runtime renderer, driver, and `GeneratedCve2Session` now run two
different pinned CPU RTL implementations. The Ibex case uses the same OBI
protocol path as CVE2; its profile supplies the physical pins, tied top-level
inputs, parameter values, and boot address.

| CPU RTL | Pin and top | Source admission | Local behavior exercised |
| --- | --- | --- | --- |
| CVE2 | `d079e8c8e6a08b330940ae123876ba0612bec18d`, `cve2_top` | Existing complete OBI profile and source lock | Instruction fetch and data store/load through persistent RAM |
| Ibex | `34b0705760ef3dfa00e99637432473d2be8f22f3`, `ibex_top` | 66 of 66 physical top ports classified; 43 explicit RTL files and 70 pinned elaboration-read files | Instruction fetch, store, load, full store, and byte store through persistent RAM; saved evidence replays from fresh RTL |

The Ibex profile disables RVFI and selects `PMPEnable=0`, `RV32E=0`,
`ICache=0`, and `SecureIbex=0`. The source closure contains the actual
Verilator read set for those selections. RAM configuration request ports are
tied to zero and their response ports remain observed. The source-lock replay
checks the pinned read set; the runtime test independently verifies generated
artifact facts, then builds and steps real RTL.

Ibex starts its first instruction request at `0x10080` with the configured
boot address `0x10000`, as `ibex_if_stage` appends its reset offset. The test
preloads nine RV32 instructions at that address. Accepted OBI data requests
write `42` to `0x20000`, read `42`, write `43`, then replace the low byte with
`44`. The observed byte enables are `15, 15, 1`; final persistent RAM reads
`44`. A budgeted 50-step scenario saves the generated Ibex and GPIO identities,
then replays the bundle with fresh RTL processes and compares the trace.

The demonstrated variants use aligned 32-bit RAM transactions and the
configured single outstanding transaction per OBI channel. The evidence does
not claim cache-enabled operation, RVFI, unaligned transactions, or MMIO
completion on Ibex.
