# Attempt10 PicoRV32 CPU Consumer-Signal Inventory — 2026-10-19

## Result

The current Attempt10 build has no usable CPU-consumer or retirement witness. It preserves bus-transfer evidence only. Do not count `native_instruction_bus_completion.v1` as decode, retirement, architectural effect, semantic consumption, or P6 feedback.

## Pinned source and exposed outputs

- Upstream submodule HEAD: `ef203c2b0a3fb793280f5114941416c425c5b461`.
- Pinned `picorv32.v` SHA-256: `0836050971b3c6cdd28ac3b1e5719a67fb645161912bef1e472e63995ceb0622`.
- In [picorv32.v](../../third_party/picorv32_upstream_reference/picorv32.v), `ENABLE_TRACE` defaults to `0` (lines 78–83); `trace_valid` and `trace_data[35:0]` are output ports (157–159). Trace data is invalid when the option is disabled (1452–1455). When enabled, ordinary instruction trace is emitted from the fetch stage, and load/store address trace entries are also emitted; it is not a self-contained retirement record. Merely exposing it does not make it an accepted consumer witness.
- The [PicoRV32 profile](../../configs/cpus/picorv32/component_profile.json) assigns both outputs an `observe` disposition and notes that the default disables trace. The generated artifact bound them to wrapper/runtime output names, but recorded `defines=[]` and no `ENABLE_TRACE` override.
- The Runner stores physical outputs in raw tick samples. The frozen Attempt10 gate checker ([native_completion_gate_checks.py](../../scripts/verifier/native_completion_gate_checks.py)) checks native bus taps and `mem_instr`; it contains no `trace_valid` or `trace_data` validation. Thus the saved trace outputs are not independently interpreted or joined to the source-bound word.

## Stronger candidate and requirements

The same pinned RTL has an RVFI port set behind `ifdef RISCV_FORMAL`, including valid/order/instruction/PC/register observations. The current build's empty define set omits those ports and the wrapper does not export them. RVFI is a stronger candidate for a later consumer adapter, but it is not current evidence.

To evaluate RVFI, create a new source/build identity with the define enabled, enumerate every ABI port and wrapper disposition, capture raw pre/post evidence, bind reset and clock semantics, and add an independent checker that joins the exact delivered word and path to one unique CPU event. Do this only after the frozen Task5 real-process gate and independent audit required by the design. Keep the current consumer edge unsupported until that evidence exists.

The profile describes a 50 MHz core clock and synchronous active-low `resetn`. The existing trace pins cross the current runtime observation path, but the checker does not consume them; enabling a signal alone does not change this boundary.

## Scope and method

Read-only source/profile/generated-artifact inspection. No files were changed by the inventory, no source was imported or executed, no tests or model ran, and no remote path or `/usr/bin/**` file was accessed. The attempt's source manifest is remote-only; local identity was checked against its pinned upstream submodule and existing generated receipt, not against a locally reconstructed full 5,513-entry source manifest.
