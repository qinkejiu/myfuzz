# PULP SPI local contract pilot

## Delivered boundary and levels

The new `configs/peripherals/pulp_spi/local_component_profile.json` covers the original `apb_spi_master` full top, with `BUFFER_DEPTH=10`, `APB_ADDR_WIDTH=12`, all 25 ports, 32-bit data and four serial input/output lanes. Re-elaboration and the full port disposition ledger pass. Its actual bound MMIO fields select the existing `target.apb3@1/full-word` contract; no component-name dispatch was added.

| Level | This pilot |
|---|---|
| Catalog | Present: full-top source/profile and explicit APB/native serial facts |
| Contract and peer unit verification | Passed; `runtime_effective=false`, `dut_semantics_verified=false` |
| Generated local SPI runtime | Not implemented; no renderer/driver/build/session changes |
| RTL-operational generated SPI runtime | Not tested |
| Cross-component accepted generated SPI scenario | Not tested |

The existing **separate** `test_soc_pulp_spi_peer_timing` bench passed again for actual RXFIFO word `A5C396F0`, 32 real RX samples and native EOT at dividers 0 and 1. This uses the existing SystemVerilog peer, not the new Python helper or generated local SPI runtime. It is source timing calibration evidence only. No register-only run is counted as serial completion or Generated acceptance.

## Fixed source evidence

`verify_pulp_spi_source_contract` reuses `validate_document`, owners/allowed roots and `verify_record(replay=False)` from repository-local `scripts/verify_soc_sources.py`. Both lock records and the authenticated seven-file elaboration closure are verified; the union profile locator, canonical dataclass, parameters, capabilities and content pin are checked. The API requires a repository checkout and is not invoked by any artifact builder.

- Main selected two-file hash: `sha256:4e4179730dd875bc66396b973ddf98ecf6bedf5c13e241a4e4140bf002667929`.
- Five dependency-file hash: `sha256:90935e7e6ad612ce30f6f246abd05501e8276b3d51cbfe537d1d6dbd725c5e58`.
- Seven-file profile union pin: `sha256:c653811843b453f0689a8f6942934ff9d551734aa4bc4e197d8b9acbfb020230`.
- Lock hash: `e55b3ace8426ac4db78c1560c7caf2503de998237c20a7a87ae89046fab092a7`.
- SPI closure evidence hash: `c575700a1cc1c25a73a56b50545d4483f44f6e0cadaa535a7b847ac541b92a30`.

The union profile's `root=third_party` and seven regular files accurately represent the elaboration closure. The unchanged `pulp_spi` lock locator has `root=third_party/soc-pulp-apb-spi`, a git revision and only two selected files; dependency ownership is separate. Consequently `verify_local_source_lock` **rejects** this profile with `local-source-lock-source-mismatch:root`. The new API returns `artifact_source_gate_compatible=false`. It does not bypass or satisfy the independent artifact build gate. Closure-aware locator reconciliation remains a required gate before runtime build acceptance; the existing lock is unchanged.

| Fact | Pinned RTL evidence |
|---|---|
| APB3 PREADY=1, PSLVERR=0, no PSTRB; full-word only | `soc-pulp-apb-spi/spi_master_apb_if.sv:33`, `:79`, `:80`, `:110` |
| Decode `PADDR[5:2]`; 64-byte register alias across 4KB window | `spi_master_apb_if.sv:76` |
| TXFIFO 0x18 pushes all PWDATA, RXFIFO 0x20 pops PRDATA | `spi_master_apb_if.sv:215` |
| INTSTA 0x28 reads default zero and rearms threshold state; not readable IRQ status | `spi_master_apb_if.sv:82`, `:210` |
| `events_o[0]=s_int_tx|s_int_rx`, bit 1=s_eot; native pulses, no held-level conversion | `apb_spi_master.sv:116`, `:117`, GEN_INT_TX/GEN_INT_RX states |
| Single-line MOSI SDO0, MISO SDI1, MSB first; quad is distinct | `soc-pulp-axi-spi/spi_master_rx.sv:84`, `spi_master_tx.sv:42` |
| TX falls, RX rises, fixed mode 0; `spi_mode` is line width | `spi_master_controller.sv:115`, `:135`, `:11` |
| SPI divider period `2*(CLKDIV+1)` HCLK, idle low | `spi_master_clkgen.sv:40`, `:60` |
| Software reset only clears FIFOs; no controller reset | `spi_master_controller.sv:31`, `apb_spi_master.sv:300`, `:322` |

## Native peer contract

`PulpSpiMode0Peer` wraps the existing edge-driven `SpiPeer`. `drive_inputs()` supplies explicit zero sources for SDI0/2/3 and native peer MISO for SDI1. `observe(pins, local_tick, phase)` consumes actual pre/post snapshots; the fields are `spi_clk`, `spi_csn0..3`, `spi_mode`, `spi_sdo0`, `events_o`. Extra snapshot observations are allowed. Receipt positions must strictly increase; missing/invalid values, simultaneous selected SCK-high setup, multiple/wrong CS or actual quad clocking fail closed. `chip_select` explicitly chooses one of 0..3.

The actual controller may briefly present `spi_mode=2` with CS asserted and SCK idle low before standard mode becomes visible (existing timing bench notes this transient). The helper permits only that no-edge setup state, drives SDI1 zero during it, and presents the first bit once observed mode becomes 0. It refuses any clocked nonzero mode. Rising selected SCK captures actual MOSI and consumes a source bit; falling selected SCK updates MISO. Host time, idle HCLK count, command return and expected register contents do not shift the peer. Native event bits are independent real level-transition receipts with tick/phase, never a fabricated completion or IRQ.

Completed frames and source consumption persist until explicit testcase/reset policy. An incomplete byte is retried at its MSB on the next CS assertion. The helper models a byte stream over the complete selected interval: command/address/dummy bits must be explicitly represented in the peer source plan before data payload; it does not infer phases from expected register writes.

**Critical runtime gap:** Python cannot react inside a driver's already batched APB command. Consuming its samples after return cannot retroactively supply MISO. A runtime must exchange actual pin states and drive peer input between every internal HCLK, or implement the same independently checked peer inside that driver. Until this ownership/clock boundary exists, this helper is a contract/tool for future integration, not an executable SPI session.

## Implementation and acceptance order

1. Reconcile the union source locator with the authenticated multi-root closure at the artifact source gate. Preserve typed parameters, dependency owners and exact bytes; reject unpinned overrides. Rerun negative pin/file/parameter/profile-dataclass tests.
2. Reuse the APB3 **bus** contract selected from actual roles/widths. Keep no PSTRB, 32-bit full-word accesses, setup/access/idle phases, real PREADY/PSLVERR sampling, register read/pop effects and transaction identity. SPI pin/peer behavior needs its own contract and driver tick hooks; GPIO's environmental word/settling assumptions cannot be copied.
3. Define explicit peer source IDs and initial byte stream, single CS index and line-width mode. Bind all four SDI inputs with one driver per bit. Connect peer drive before **each** real HCLK and report every pre/post output and both events bits. Reset once per case or explicit reset, never per access/command.
4. Include the peer/contract implementation and selected source plan in generated v2 host/build identity before execution; preserve the legacy v1 source list. Run minimum real native pin/shift acceptance below. Keep a literal externally supplied payload separate from actual DUT observations. Retain all serial samples, APB receipts and IRQ transitions, including internal ticks during CPU MMIO.
5. Add CPU→SPI→CPU acceptance only after standalone SPI passes, then whole-case replay and mutation-difference evidence. A register roundtrip alone does not pass this gate.

| Real test | Minimum required evidence |
|---|---|
| Reset/idle | SCK low and all CS high; empty FIFOs; real pin reset observations; no invented EOT |
| TX 32-bit | CLKDIV=0 and 1; SPILEN=0x00200000; TXFIFO=0xA5C396F0; STATUS=0x102 (CS0 + write); capture exactly 32 real selected rising edges and MOSI literal A5C396F0; observe real EOT bit 1 |
| RX 32-bit | Explicit peer payload A5 C3 96 F0; SPILEN=0x00200000; STATUS=0x101 (CS0 + read); actual RXFIFO 0x20 equals A5C396F0; capture exactly 32 real samples and bit-1 pulse |
| Header/framing | SPICMD/SPIADR plus lengths in SPILEN; dummy count in SPIDUM; explicit source prefix for every header/dummy bit; prove data begins at the observed bit index, no cycle-only completion |
| Threshold IRQ | Set INTCFG bit 31 and TX/RX threshold fields; cause real FIFO threshold transition; retain bit-0 pre/post pulse; read 0x28 returns real zero and rearms; next transition produces a distinct actual event; keep EOT distinct |
| Full-word/alias | Reject partial BE before issuing APB; read/write 0x04 and 0x44 alias; undefined slot reads actual zero; do not claim fabric decode error from constant-zero PSLVERR |
| Repeated transactions | Two transfers within same reset epoch, distinct peer sources/frames and native EOT receipts; reset count unchanged; FIFO push/pop counted once |
| Retry/replay | Same transaction identity returns cached full receipt without an extra FIFO push/pop, tick, peer shift or event; whole-case replay from initial state reproduces all actual edges, words and pulses |
| Reset scope | STATUS software-reset bit flushes real FIFOs only; explicit hardware reset clears controller/clock and peer state; don't claim software reset aborts the FSM |
| CPU chain | Source CPU APB write starts transfer, real external peer supplies data, native events reach declared CPU bit(s), CPU then reads actual RXFIFO and commits result to memory; same program/input mutation must change trace and memory outcome |

## Commands and results

Initial missing-profile/module tests failed before implementation; additional real setup-transient test failed before the helper accepted that source-supported state. Dedicated tests plus old SPI peer/registry regression pass: **40 tests** (16 new); including existing source-lock regressions, **53 tests** pass.

For a checkout with populated pinned submodules:

```bash
PYTHONPATH=src python3 -m unittest tests.local_harness.test_pulp_spi_contract tests.scenario.test_pulp_spi_peer tests.scenario.test_spi_peer tests.local_harness.test_template_contracts -q
PYTHONPATH=src python3 -m unittest tests.integration.test_soc_pulp_spi_peer_timing -v
```

In the isolated worktree, source/profile tests used `MYFUZZ_PINNED_SOURCE_ROOT=/home/qinkejiu/myfuzz`; all implementation/profile/test bytes came from this worktree. Existing real RTL timing test reused the main checkout's unchanged bench and submodule bytes by setting that test module's `ROOT` to `/home/qinkejiu/myfuzz`; **1 real test passed**, 5.011 seconds. No core runtime integration was tested or claimed.

The complete scenario suite subsequently passed **356 tests**, 42.974 seconds. To make its existing generated GPIO identity tests use this worktree consistently, the GPIO dependency was populated as a detached worktree at its fixed revision `f82caeb7f7d89427f05e9af5ed31e0675efe0d83`. The legacy OpenTitan GPIO session's source-identity root alone remained the populated main checkout. Implementation, generated host identity and all scenario tests were evaluated from this isolated worktree. Earlier attempts with missing submodule bytes or mixed host-identity roots failed; those environment failures were resolved before this passing run.
