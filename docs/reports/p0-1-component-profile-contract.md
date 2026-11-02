# P0-1 component-profile contract: CPU, MMIO IP and DMA

Scope: the fields the unified in-process F1–F6 entry
(`scripts/run_inprocess_f1f6.py` + `scripts/inprocess_obi_apb_f1f4_spike.cpp`) and
the composition/routing layer (`src/myfuzz/composition/multi_target.py`, profile
loader `src/myfuzz/composition/component_profile.py`) actually consume. Nothing
here is a new schema: every field below is already declared by the checked-in
profiles and validated by the loader. The document exists so a new CPU or IP can
be added by *declaration* and so a missing field is reported by its own name
instead of surfacing as a build error.

The profile is data only. Device behaviour (how an interrupt is raised and
cleared, which register is its status, where the DMA control bits are) is a
separate `source_behavior` / `dma_behavior` declaration; firmware, addresses,
windows and IRQ wiring are the scenario's.

## 1. Common envelope (`component_profile.v1`)

| field | required | consumed by | refusal if wrong |
|---|---|---|---|
| `schema_version` = `component_profile.v1` | yes | loader | `unsupported-profile-schema:<v>` |
| `component_id` | yes (identifier) | source-lock dispatch, reporting | `invalid-component-id` |
| `kind` ∈ `cpu` / `peripheral` / `memory` | yes | loader | `unsupported-component-kind:<k>` |
| `source` | yes | elaboration, source lock | crawler/elaboration errors |
| `clocks` (≥1, one physical port + domain + Hz) | yes | host clock schedule | `profile-clock-required` |
| `resets` (≥1, port, domain, polarity, synchronous, release) | yes | reset sequence, host | `profile-reset-required` |
| `endpoints` (unique ids) | ≥1 | binding, protocol adapters | `duplicate-endpoint-id`, `invalid-endpoint-function`, `endpoint-protocol-required` |
| `capabilities` | yes for CPU/IP/DMA use | adapter selection, planner | `unsupported: …` at binding time |
| `address` | required iff `kind: peripheral` | window/register map, F5 checks | `peripheral-profile-requires-address`, `cpu-profile-must-not-declare-mmio-address` |
| `interrupts` | optional list | driver IRQ contract | `invalid-interrupt-polarity`, `unsupported-interrupt-trigger:<t>`, `interrupt-pulse-width-required` |
| `cpu` | required iff `kind: cpu` | CPU binding, boot, IRQ entry | `cpu-profile-requires-cpu-contract` |
| `port_actions` | one entry per unbound physical port/bit segment | generated SoC ties/observes | `duplicate-port-action`, missing disposition at generation |
| `evidence` | optional map | boot formula, timing mode, IRQ receipt, locks | see §5 |
| unknown keys | — | — | `unknown-profile-field:<key>` |

`source` carries `root`, `revision`, `top_module`, `top_port_selection`, `files`
(and `include_roots`), and `elaboration` (`frontend: verilator-json`, optional
`defines`, `parameters`, `warning_policy`). The source lock verifies those bytes;
a CPU profile whose contract is pinned (Ibex/CV32E40P/CV32E20/…) cannot be edited
without updating its pin, so a replacement CPU is a *new profile*, not an edit.

## 2. CPU profile

Required to be selected by this entry:

| fact | where | why |
|---|---|---|
| bus kind | `endpoints[].protocol` of the two OBI masters (`obi/1`) — or one `memory_master` for Wishbone `wishbone/classic`, AHB-Lite `ahb-lite/1`, AXI4 `axi4/1` | selects the CPU-side adapter and the host link (`CPU_BUSES`: `obi_cpu`, `wishbone_cpu`, `ahb_lite_cpu`, `cva6_packed_axi4_cpu`); anything else: `unsupported-cpu-kind:<kind>` |
| memory master roles | `endpoints[].fields[].role` + `aliases` | the OBI `req/gnt/addr/rvalid/rdata[/we/wdata/be/error]` backend port names |
| capabilities | `address_width`, `data_width`, `max_outstanding`, `byte_enable`, `error_response` | adapter width/extension policy |
| capabilities.verilator_timing_mode | optional `timing` | selects Verilator `--timing`, the timed driver and the host's timed phase scheduler (§5); `no_timing`/absent keeps the evaluate-only host |
| reset/boot | `cpu.reset_vector`, `cpu.boot_address_required`, `port_actions` for `boot_addr_i` | RAM base and bootstrap address; a CPU with an IF-stage formula needs `evidence.boot_fetch` (`source_file`, `source_sha256`, `base_mask`, `fixed_bits`) or a registered source strategy, else `CPU boot source strategy is not registered` |
| IRQ entry | `cpu.irq_entry_endpoint`, `irq_entry_role`, `irq_entry_polarity`, `irq_semantics` + the `interrupt_entry` endpoint | F5 delivery; an OBI CPU must declare an active-high machine-external 1-bit input, otherwise `unsupported-f5:…` / `unsupported: requires a one-bit CPU IRQ input` |
| ISA | `cpu.family`, `xlen`, `extensions` | F1 program gate (`f1_isa_from_profile`) |
| retirement face | the model must export `rvfi_valid`, `rvfi_insn`, `rvfi_pc_rdata` | F1; absent → `unsupported: F1 needs the CPU rvfi_* retirement probe` |
| retirement extras | `rvfi_order`, `rvfi_rd_addr`, `rvfi_rd_wdata` optional (`HAVE_RVFI_WRITEBACK`); `rvfi_trap` optional (`HAVE_RVFI_TRAP_PORT`) | a writeback pair gives `rvfi` event lines and last-writeback evidence; a missing `rvfi_trap` is reported as `traps unknown` / `trap_evidence unobservable`, never as zero |
| custom IRQ ABI | `evidence.custom_irq_abi` (`picorv32_custom0`) + scenario `cpu_irq_bit` | Wishbone CPUs reach F5 through their own handler vector (`handler_address`), not a CSR |
| timing overrides | `evidence.local_harness.{reset_assert_ticks, reset_release_ticks, max_wait_cycles}` | per-model timing without a second contract |

CPU `port_actions` must cover every physical input that the composition does not
bind (debug, DFT, integrity sidebands, unused IRQ lines) with `constant` + value,
and every unbound output with `observe`. A missing one is a generation error, not
a silent tie.

## 3. MMIO IP profile (`kind: peripheral`, one `mmio_slave` endpoint)

| fact | field | consumed by |
|---|---|---|
| protocol | `endpoints[] function: mmio_slave`, `protocol`: `apb/3`, `axi4-lite/1`, `wishbone/pipelined`, `tl-ul/1` | target request builder (`source_request_from_profile`, `scripts/run_inprocess_axi4lite.py`, `generic_target_request_from_profile`) and the host's target trait |
| protocol roles | `paddr/psel/penable/pwrite/pwdata/pready/prdata[/pslverr]` or that protocol's roles | generated bridge taps |
| window | `address.window_size`, `address.alignment` (both powers of two) | must match the scenario window exactly (`unsupported: the APB window does not match the target profile`) |
| register map | `address.registers[]`: `name`, `offset`, `width` (default 32), `access` ∈ `ro/rw/wo`, optional `side_effect`, `reset_value`, `writable_bits`, `clears_register` | F5 trigger/status/clear cross-checks (`irq_declaration`), register-kind labels, DMA control offsets |
| IRQ declaration | `interrupts[]`: `endpoint_id`, `role`, `polarity`, `clock_domain`, `trigger` (`level`/`pulse`/edge…), `hold`, `clear` | F5 protocol/IRQ checks; a pulse trigger requires `pulse_width_cycles` |
| capabilities | `address_width`, `data_width`, `read`, `write`, `byte_enable`, `partial_write`, `has_error`, `max_wait_cycles` | bridge selection and target response model |
| fixed pins | *scenario*, not profile: `fixed_inputs` + `tuning.fixed_inputs` for serial/pad inputs | the entry refuses a declared pin the generated target does not expose; a 32-bit `in/out/dir` pad group is a one-target feature (`unsupported-pins:multiple-targets`) |
| behaviour | separate `source_behavior` file | §4 |

Two inspection-only facts the entry reads from the generated target (not the
profile): the trace roles the bridge exposes, and the single interrupt-like output
that may be observed without being wired.

## 4. Behaviour declarations (not profile fields)

`source_behavior` (`inprocess_source_behavior.v1`), keys
`source_port`, `source_bit_offset`, `pulse_width_ticks`, `trigger_writes`,
`status_offsets`, `status_cause_bits`, `clear_writes` (v2 files may state several
links under `sources`). F5 exists only when the target declares the four facts it
needs: IRQ output, bit, writable trigger sequence, one readable status word; each
is re-checked against the profile's register map.

`dma_behavior` (`inprocess_dma_behavior.v1`): `block_words`, `busy_bit`,
`err_bit`, `status_kind`, optional `irq_pulse_ticks`. The executor cross-checks
it against the DMA profile and the generated edge contract.

## 5. DMA profile (`kind: peripheral`)

| fact | field | consumed by |
|---|---|---|
| control slave | endpoint `dma.control`, `mmio_slave`, `wishbone/pipelined` | host control port; wrong kind → `unsupported: requires a Wishbone DMA model` |
| master | endpoint `dma.memory`, `memory_master`, `wishbone/pipelined`, roles incl. `err` | DMA master route/beat |
| IRQ | endpoint `dma.interrupt`, `interrupt_source`, role `irq` | F6 completion IRQ delivery (level or declared pulse) |
| control registers | `address.registers[]` `CONTROL_STATUS(0)`, `SOURCE(4)`, `DESTINATION(8)`, `LENGTH(12)` with the declared `side_effect`s | control offsets, start/clear word, length encoding |
| control window | `address.window_size`, `alignment` | scenario `dma_window` must equal the declared size |
| master capabilities | `master_address_width`, `master_address_units`, `master_byte_enable`, `master_has_error`, `wishbone_flavour`, `address_units` | `myfuzz.composition.dma_transfer` plan (start word, length unit, lane masks, max outstanding) |
| IRQ facts | `interrupts[]` trigger/polarity/clear | F6 completion criterion |
| block/byte-enable | `dma_behavior.block_words`, per-device lane default | plan bounds; a plan the RTL cannot encode is refused by name |

## 6. What this increment added to the contract (no schema change)

1. **Timed models are accepted by the unified entry.** A profile that declares
   `capabilities.verilator_timing_mode: timing` (the pinned CV32E40P RVFI monitor
   needs real delayed edges) is built with `--timing`, and the host now advances
   the shared context by the model's declared half period on every clock phase,
   draining each model's `eventsPending()`/`nextTimeSlot()` in time order. The
   header states `CPU_TIMED_MODEL` and `TIMED_HALF_PERIOD_PS`, read from the
   artifacts' own `driver_timing` contracts; two timed models that disagree on the
   half period are refused (`unsupported: timed models declare different half
   periods`), and a timed model on the packed-AXI4 clock path is refused
   (`unsupported: timed model on the packed-axi4-clock-path`). The host link adds
   `verilated_timing.cpp` and `-fcoroutines` only when a timed artifact is
   present, so untimed links (and their cache keys) are unchanged.
2. **The retirement face's trap bit is optional and stated as such.** A model
   that exports `rvfi_trap` keeps the historical behaviour byte for byte
   (`HAVE_RVFI_TRAP_PORT 1`). A model that does not (the CV32E40P local top
   assigns valid/order/insn/pc only) yields `traps unknown` and
   `trap_evidence unobservable` in the case/summary lines, and the F1 record gate
   tolerates an unobservable `prog_traps` while still requiring the program's
   retirement count, address order and installed-word match.

## 7. Refusals this contract names (examples)

`unknown-profile-field:<key>`, `unsupported-component-kind:<kind>`,
`endpoint-protocol-required`, `invalid-address-window`,
`address-window-not-power-of-two`, `invalid-cpu-xlen`,
`cpu-master-endpoints-required`, `unsupported-cpu-kind:<kind>`,
`unsupported: F1 needs the CPU rvfi_* retirement probe`,
`unsupported: requires a one-bit CPU IRQ input`,
`unsupported-f5:target-protocol-not-run:<protocol>:<name>`,
`unsupported-f6:no-dma-model:<protocol>`,
`unsupported: the generated target does not expose every declared pin`,
`unsupported-pins:multiple-targets`, `unsupported-window-overlap:target[i]-ram`,
`unsupported-route-windows:overlap`,
`unsupported: timed models declare different half periods`.

## 8. What a profile still does not state

No profile proves that its RTL raises the interrupt its `interrupts` entry
describes, that a register's `side_effect` is implemented, or that a boot formula
matches silicon. Those are execution facts: the run reports them (or refuses the
flow by name), and a declared fact that a run contradicts is reported as a
mismatch, never repaired.
