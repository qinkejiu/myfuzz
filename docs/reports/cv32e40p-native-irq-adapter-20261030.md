# CV32E40P native IRQ adapter — real ack/id/entry-PC, no fabricated RVFI

2026-10-30 · scope: `cv32e40p_rvfi_local` local harness only · **no native RTL run was performed**

## What this adapter adds

The pinned `cv32e40p_rvfi_local_top` assigns only four official monitor fields
(`rvfi_valid`, `rvfi_order`, `rvfi_insn`, `rvfi_pc_rdata`). It never drives
`rvfi_intr`, `rvfi_pc_wdata`, `rvfi_trap`, `rvfi_mode`, `mem_*` or `halt`, so no
RVFI field can mint IRQ authority. What the core really exposes is the
controller's combinational IRQ decision plus its own `irq_ack_o` / `irq_id_o`
outputs and the IF stage's exception PC. Those are now installed as passive
probes and sampled on the **pre** edge — the only edge on which they name an
acceptance:

| observation | real RTL source | width |
| --- | --- | --- |
| `irq_masked_pre` | `core_i.cs_registers_i.mie_q[11]`, `mstatus_q.mie`, `controller_i.debug_mode_q` | 1 |
| `irq_taken_pre` | `controller_i.pc_set_o & csr_save_cause_o & (exc_pc_mux_o == cv32e40p_pkg::EXC_PC_IRQ) & (exc_cause_o == 5'd11)` | 1 |
| `irq_ack_pre` | `controller_i.irq_ack_o` | 1 |
| `irq_id_pre` | `controller_i.irq_id_o` | 5 |
| `irq_entry_pc` | `core_i.if_stage_i.exc_pc` | 32 |
| `irq_redirect_pre` | `controller_i.pc_set_o & (exc_pc_mux_o != EXC_PC_IRQ) & (!= EXC_PC_DBD) & (!= EXC_PC_DBE)` | 1 |
| `irq_redirect_cause` | `controller_i.exc_cause_o` | 5 |

The native line is `irq_i[11]` (`CSR_MEIX_BIT`, machine external); the profile's
other 31 bits stay constant 0 in `port_actions`. `irq_ack_o`/`irq_id_o` are also
already declared `observe` outputs of the profile.

A `cpu_external_irq_taken` event now additionally requires, on the same pre
edge, `irq_ack_pre == 1`, `irq_id_pre == 11` and a 4-byte-aligned
`irq_entry_pc`; the event carries those real values. A real non-IRQ exception
redirect emits a separate `cpu_native_exception_redirect` event with the real
`exc_cause_o` and tick. No IRQ serial token exists for this CPU, so no
`irq_serial_observation` document is emitted anywhere.

### Deliberately NOT observable (never fabricated, never zero-filled)

`rvfi_intr`, `rvfi_pc_wdata`, `rvfi_trap`, `rvfi_mode`, `rvfi_halt`, every
`rvfi_mem_*` field, `halt`, and any exact IRQ↔retirement serial token. The
retirement authority is `pc_insn_order_only` over exactly
`valid/order/insn/pc_rdata`; the retirement-entry join is PC/instruction/order
based, not token based. Debug/NMI/halt diversion is **unobservable** here: the
contract declares `retirement_diversion_fields=[]` and
`retirement_diversion_scope='unobservable'`, and
`native_irq_retirement_diverted()` answers `False` only because the scope is
declared unobservable — callers must record that unknown scope.

### Two source-derived design notes

1. `irq_redirect_pre` deliberately does not conjoin `csr_save_cause_o`. In this
   RTL the cause save happens in the flush cycle *before* the redirect
   (`cv32e40p_controller.sv`: `FLUSH_EX` sets `csr_save_cause_o`, `FLUSH_WB`
   sets `pc_set_o`), so requiring both would make the probe dead. The vector
   selector alone separates exception entry from IRQ (`EXC_PC_IRQ`) and debug
   (`EXC_PC_DBD`/`DBE`) entries; branch/jump/MRET leave `exc_pc_mux_o` at its
   `EXC_PC_IRQ` default.
2. `irq_redirect_cause` records the real combinational `exc_cause_o` at that
   redirect edge. It is simultaneously qualified for the two fault vectors
   (`EXC_CAUSE_INSTR_FAULT`, `EXC_CAUSE_LOAD/STORE_FAULT`); for
   illegal/ebreak/ecall the RTL saves the cause one cycle earlier, so the value
   read at the redirect edge is the controller's own default. It is a real
   observation, not a claim of the saved cause.

## Contract keys (`cv32e40p_irq_receipt_contract()`)

```
schema_version              'cv32e40p_native_irq_receipts.v1'
profile_id                  'cv32e40p_rvfi_local'
input_port / input_width    'irq_i' / 1
input_bit_offset            11              # documentary DUT line, not host delivery
sampling                    'pre_post_rising'
wire_schema_version         'local_driver.v1'
source                      {root:'external_designs/cv32e40p', revision:'git:6033d2b1…',
                             sha256:{rtl/…, rtl/include/…, bhv/…, bhv/include/…}}
decision_probes             {'irq_masked_pre', 'irq_taken_pre'}        (exactly 2)
decision_probes_all         {'irq_ack_pre','irq_id_pre','irq_entry_pc',
                             'irq_redirect_pre','irq_redirect_cause'}
decision_probe_widths       {irq_masked_pre:1, irq_taken_pre:1, irq_ack_pre:1,
                             irq_id_pre:5, irq_entry_pc:32, irq_redirect_pre:1,
                             irq_redirect_cause:5}
irq_ports                   {irq_i:{input,32,line_offset 11}, irq_ack_o:{output,1},
                             irq_id_o:{output,5}}
irq_authority_scope         'native_pre_edge_external_cause_decision_with_real_ack_id
                             _entry_pc_and_non_irq_exception_redirect_only'
decision_acceptance         {ack_probe:'irq_ack_pre', id_probe:'irq_id_pre',
                             source_id:11, id_width:5, entry_pc_probe:'irq_entry_pc'}
redirect_probes             {'taken':'irq_redirect_pre','cause':'irq_redirect_cause'}
notification_widths         {rvfi_valid:1, irq_ack_o:1, irq_id_o:5}
notification_semantics      irq_ack_o/irq_id_o are real pre-edge controller outputs;
                            rvfi_intr is not driven
retirement_authority        'pc_insn_order_only'
retirement_fields           ['valid','order','insn','pc_rdata']
unobserved_retirement_fields ['intr','pc_wdata','trap','halt','mode','mem_addr',
                             'mem_rdata','mem_wdata','mem_rmask','mem_wmask']
retirement_diversion_fields []
retirement_diversion_scope  'unobservable'
retirement_receipt          {schema 'cpu_retire.v2', phase 'post', rvfi_fields 4, …}
startup_reset_receipt       {schema 'cpu_native_startup.v1', source 'authenticated_startup_ready', …}
serial_observation          ABSENT (no exact serial token exists)
```

`validate_cv32e40p_irq_receipt_contract` is a strict canonical-JSON equality
check, so any edit (e.g. adding `rvfi_intr` to `notification_widths`, or a
`serial_observation` block) is refused. `native_irq_notification_observed()`
returns `False` for this contract by construction: a post-edge notification is
physically impossible, and returning `True` would be fabrication.

## Source pins (all real SHA256, verified by the contract)

| file | sha256 |
| --- | --- |
| `configs/cpus/cv32e40p_rvfi_local/cv32e40p_rvfi_local_top.sv` | `72e02345…e10a28` |
| `configs/cpus/cv32e40p_rvfi_local/component_profile.json` | `fc070f67…6c046c6806` |
| `configs/cpus/cv32e40p/component_profile.json` | `21d04c8a…73d0db3e45` |
| `external_designs/cv32e40p/bhv/cv32e40p_tb_wrapper.sv` | `591124e7…a8f6816b` |
| `external_designs/cv32e40p/bhv/cv32e40p_rvfi.sv` | `dba0bea3…20ef166d6` |
| `external_designs/cv32e40p/bhv/pipe_freeze_trace.sv` | `ebe391ca…9d9509f` |
| `external_designs/cv32e40p/bhv/insn_trace.sv` | `31b72b25…c5a330a39` |
| `external_designs/cv32e40p/bhv/include/cv32e40p_rvfi_pkg.sv` | `55ed3c9f…09ca7a675` |
| `external_designs/cv32e40p/bhv/include/cv32e40p_tracer_pkg.sv` | `44f2498d…1419ad212c` |
| `external_designs/cv32e40p/rtl/cv32e40p_core.sv` | `6a78a0d7…a70989224` |
| `external_designs/cv32e40p/rtl/cv32e40p_cs_registers.sv` | `e2cec8f3…d9bb0345` |
| `external_designs/cv32e40p/rtl/cv32e40p_controller.sv` | `858b1729…b0ed6d7b87` |
| `external_designs/cv32e40p/rtl/cv32e40p_int_controller.sv` | `24df51d9…5e7778af16f` |
| `external_designs/cv32e40p/rtl/cv32e40p_id_stage.sv` | `98b246d9…bbec83728e` |
| `external_designs/cv32e40p/rtl/cv32e40p_if_stage.sv` | `e2d1cc9b…f04597626` |
| `external_designs/cv32e40p/rtl/cv32e40p_top.sv` | `2467f6b3…f4223e5dc3` |
| `external_designs/cv32e40p/rtl/include/cv32e40p_pkg.sv` | `3fee39d2…6da6f6525805` |

The source revision is read from the pinned base profile and required to be
`git:6033d2b1be3295ec774d17ac4cf226faacfdeb08`. Verification also re-runs the
CV32E40P RVFI observation closure (`verify_cv32e40p_rvfi_source_contract`) and
elaborates the top (`elaborate_profile(mode='direct')`) to require the RVFI
output set still equals exactly those 4 fields, `irq_ack_o` output width 1,
`irq_id_o` output width 5 and `irq_i` input width 32.

`verify_cv32e40p_irq_source_contract` returns the **pinned RVFI closure document
unchanged** (the CV32E20 shape). That document is what the renderer stores as
`runtime_document['source_verification']` and what evidence hashes into
`cpu.source_verification_sha256`, so adding IRQ keys to it would break the
identity hash. The IRQ-only facts therefore live in the contract itself
(`irq_ports`, `irq_authority_scope`, `decision_probe_widths`,
`decision_acceptance`, `redirect_probes`) and in the module constant
`IRQ_AUTHORITY_SCOPE`; a test pins
`sha256(canonical(verify_cv32e40p_irq_source_contract(...))) ==
sha256(canonical(artifact.runtime_document['source_verification']))` for the
real rendered artifact.

## Files changed

- **new** `src/myfuzz/local_harness/cv32e40p_irq_receipt_contract.py` — pins,
  source/elaboration verification (returning the identity-hashed RVFI closure),
  strict contract, artifact verification, documentary passive sideband builder
  (`cv32e40p_irq_sideband()`, not installed by the renderer, never drives the
  DUT).
- `src/myfuzz/local_harness/native_irq_receipt_contract.py` — registers the
  third adapter; adds `native_irq_decision_probes`, `native_irq_acceptance`,
  `native_irq_redirect_probes`, `native_irq_serial_observable`,
  `native_irq_retirement_diversion_scope`; E40 notification is never observed;
  empty diversion fields answer `False` only for `unobservable` scope. Ibex and
  CV32E20 return values are byte-identical to before.
- `src/myfuzz/local_harness/runtime_renderer.py` — one new `obi_cpu` block for
  `cv32e40p_rvfi_local` that installs the seven contract probes as passive
  `assign probe_<name> = <expr>;` and exports them as `observe` outputs with the
  declared widths. The Ibex/CV32E20 blocks are untouched.
- `src/myfuzz/local_harness/cpu_session.py` — probe names/widths come from the
  contract instead of being hardcoded; a taken IRQ must be corroborated by the
  real ack/id/aligned entry PC; a real non-IRQ redirect emits
  `cpu_native_exception_redirect`; serial observation is emitted only for
  adapters that own a serial token. Host delivery is unchanged: the host-facing
  IRQ port stays the declared one-bit slice and its value is the port-local 0/1
  line.
- `src/myfuzz/local_harness/native_physical_observation.py` — the `obi_cpu` raw
  mapping now selects the IRQ input by declared endpoint/role with `width == 1`
  and **any** `bit_lo`, so a real one-bit DUT slice is accepted by a
  `raw_tick_stream` request. Offset-0 CPUs are unaffected.
- **new** `tests/local_harness/test_cv32e40p_irq_contract.py` (19 tests).
- `tests/local_harness/test_cv32e40p_rvfi_observation.py` — the pre-registration
  negative expectation is replaced by the registered contract identity, keeping
  the test's intent (RVFI alone grants no IRQ source).
- this report.

## Tests actually run (exact commands)

All commands were run from the repository root with `PYTHONPATH=src:.`, on a
quiescent tree (no other Python file was being edited during the run).

```
# required set from the task brief
python3 -m pytest tests/local_harness/test_cv32e40p_irq_contract.py \
  tests/local_harness/test_cpu_native_irq_receipt.py \
  tests/local_harness/test_cv32e20_irq_contract.py \
  tests/local_harness/test_ibex_irq_serial_sideband.py -q
→ 42 passed, 15 subtests passed in 148.03s

# requested combined bridge set (E40 observation + raw-tick mapping)
python3 -m pytest tests/local_harness/test_cv32e40p_irq_contract.py \
  tests/local_harness/test_cv32e40p_rvfi_observation.py \
  tests/local_harness/test_cpu_native_irq_receipt.py \
  tests/local_harness/test_cv32e20_irq_contract.py \
  tests/local_harness/test_native_physical_observation.py \
  tests/local_harness/test_cpu_physical_tick_stream.py \
  tests/local_harness/test_obi_cpu_protocol_taps.py -q
→ 93 passed, 1 skipped, 15 subtests passed in 212.95s
  (the skip is `test_obi_cpu_protocol_taps.py:119`, the pre-existing
   "explicit real Ibex RTL gate", unrelated to this adapter; the E40
   Verilator lint test does run here — verilator 5.051 is installed)

# renderer/session regression neighbours
python3 -m pytest tests/local_harness/test_runtime_renderer.py \
  tests/local_harness/test_cpu_session.py \
  tests/local_harness/test_cv32e20_native_irq_session.py \
  tests/local_harness/test_native_irq_profile_provider.py \
  tests/local_harness/test_cpu_native_retirement_receipt.py \
  tests/local_harness/test_driver_renderer.py -q
→ 53 passed, 1 skipped, 63 subtests passed in 80.61s
```

The E40 test file also contains a Verilator `--lint-only` test of the generated
runtime (skipped when verilator is absent). It elaborates the harness SV only —
no DUT is run. It was additionally validated by a negative control: corrupting
one probe's hierarchical signal name makes the same lint fail, proving the
probes are really elaborated.

## Remaining native work (for the lead; nothing here is a native pass)

- Build/run the E40 processor artifact through the frozen native window and
  confirm the seven probes appear in the driver pre/post `physical` snapshots.
- Drive `irq_i[11]` high for at least one tick after `mstatus.MIE` and
  `mie[11]` are set, and check the `cpu_external_irq_taken` event carries
  ack=1, id=11 and the mtvec-derived aligned entry PC.
- Confirm the first post-MRET / post-handler retirement joins by
  `pc_rdata`/`insn`/`rvfi_order` only; never expect `rvfi_intr`.
- Any F6 ISR flow on this CPU must fail closed on the missing `rvfi_intr`,
  serial token, trap/mode and debug/halt observations.
