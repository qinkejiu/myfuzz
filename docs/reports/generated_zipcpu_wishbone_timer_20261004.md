# Generated ZipCPU Wishbone timer acceptance, 2026-10-04

## Pinned RTL and boundary

The source lock pins `third_party/soc-zipcpu` at `42606d2d6ef55df313772232977621b2d72f0159`, with `rtl/peripherals/ziptimer.v` as the complete `ziptimer` closure. The accepted elaboration is `BW=32`, `VW=31`, `RELOADABLE=1`. The current `verilator-json` frontend and source gate accept all 12 physical top ports with `selection=all`.

| Port group | Physical ports | Runtime treatment |
| --- | --- | --- |
| Clock and reset | `i_clk`, `i_reset` | Generated clock and synchronous active-high reset |
| Native enable | `i_ce` | Explicit constant 1, so hold behavior is outside this acceptance |
| Wishbone request | `i_wb_cyc`, `i_wb_stb`, `i_wb_we`, `i_wb_data[31:0]`, `i_wb_sel[3:0]` | Generated beat-to-Wishbone target adapter |
| Wishbone response | `o_wb_stall`, `o_wb_ack`, `o_wb_data[31:0]` | Adapter inputs and sampled physical output evidence |
| Native interrupt | `o_int` | Sampled as a one-clock `interrupt`/`irq` observation |

This target is addressless: there is no `i_wb_adr` pin. The adapter admits only the four-byte COUNT window at offset zero, using its typed `TARGET_ADDRESS_WIDTH=0`, `ADDRESS_UNITS=1`, `WINDOW_SIZE=4`, and `WB_FLAVOUR=2` configuration. The RTL updates the register on STB, returns a registered ACK, ignores CYC internally, ties STALL low, and has no ERR pin. The adapter drives a well-formed CYC/STB pair, rejects partial writes before the bus, and reports local errors for out-of-window requests. `i_wb_sel` exists physically but is ignored by the target RTL; no partial-write semantics are claimed.

## Generated operation and evidence

The renderer chooses the runtime from the typed Wishbone endpoint and capability facts, checks the exact eight bus roles and directions, the two non-bus port actions, and all 12 selected ports. `GeneratedZipTimerSession` has `artifact_kind='wishbone_timer'`, exposes one register read/write and a declared `load_count` scenario input, and retains the Verilator process across steps. It never installs an undeclared startup write. Each local tick records the native pulse; the session tracks a pending one-shot event until the pulse has been sampled.

With `MYFUZZ_SCENARIO_REAL=1`, the pinned RTL test compiled the generated driver, completed Wishbone reads and writes, rejected a partial write, observed exactly one native IRQ pulse, saved a budgeted scenario trace with a `load_count=5` source action, and matched a fresh replay of that evidence bundle. The manifest schema admits the exact generated session class and its base identity fields. The bounded test used 512 maximum scheduler cycles, 512 local cycles, and ten genome steps; the 512-cycle scheduler limit covers the conservative 38-cycle declared step bound.

## Accepted scope and limits

This acceptance covers a standalone generated target transaction and native interrupt pulse. `o_int` is not wired into a level-only interrupt controller because the source produces a one-cycle pulse; a CPU-facing IRQ latch or pulse-aware controller would need a separate declared composition. The timer has no address bits, error response, byte-lane masking, or pipelined requests. Reload mode and the `i_ce=0` hold path have not been exercised. A CPU-to-timer-to-RAM chain is not claimed by this evidence.
