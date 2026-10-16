# P7 D3 directed GPIOEN writer diagnostic

This bounded implementation projects the compiled F4 `cpu_mmio_stream` GPIOEN candidate into RV32I SW/LW code at a declared live CPU instruction slot. It uses the exact compiled address 0x40001004, values 0x55 and 0xaa, reads the register through the CPU and stores that readback at declared RAM address 0x30000. It checks loaded D2 profile fingerprints, immutable live router windows, native APB artifact verification, exact declaration regeneration, instruction slot bounds and RAM resource declaration before execution.

The observation checker joins CPU data acceptance to routed MMIO write/read deliveries and native APB pre-edge completion samples, then checks the CPU readback RAM store. These are directed diagnostics. They do not authenticate an `ip_register_version`, instruction retirement, compiled assertion/checker bindings, or a continuous search candidate admission. All declarations and observations retain `runtime_admitted=false`; full compiled runtime admission remains refused. F1/F2/F3 remain unsupported.

Explicit `observation_modes` maps every topology instance to a strict boolean. The writer selects CPU=false, gpio_a=true, gpio_b=true because CV32E40P has no supported native CPU physical alias. Unknown/missing instance names and nonboolean modes are rejected. Omitted maps preserve the existing all-instance `physical_observations` boolean behavior. Fresh replay retains the same factory and exact loaded objects.

## Verification

Focused software gate: `PYTHONPATH=src python3 -m pytest -xq tests/integration/test_generated_register_writer.py tests/integration/test_generated_factory_consumption.py`: **21 passed, 3 skipped in 63.69s**; `/tmp/myfuzz-writer-focused.log`.

The first local real run correctly refused `build-inputs-changed-during-build` while the shared live workspace changed; no success is attributed to that attempt. Its log is preserved as `/tmp/myfuzz-writer-real.log`.

A frozen independent copy `/tmp/myfuzz-writer-snapshot` preserves source working files and Git metadata. SHA256 manifest `/tmp/myfuzz-writer-snapshot-hashes.json` captures the host Python implementation and the gated tests. Subsequent real execution uses only this frozen tree and separate `/tmp/myfuzz-writer-frozen-cache`. No remote filesystem was changed by this task.


Frozen real gate: `MYFUZZ_GENERATED_RUNTIME_REAL=1 MYFUZZ_GENERATED_RUNTIME_CACHE=/tmp/myfuzz-writer-frozen-cache MYFUZZ_WRITER_EVIDENCE=/tmp/myfuzz-writer-evidence PYTHONPATH=src python3 -m pytest -xq tests/integration/test_generated_register_writer.py`, working directory `/tmp/myfuzz-writer-snapshot`: **8 passed in132.21s**; `/tmp/myfuzz-writer-frozen-real.log`.

Both values completed one real CV32E40P + dual PULP GPIO run and full fresh replay (`fresh_matches=true`, `fresh_scope=full`). Each full trace has3834 events. Candidate write CPU acceptance2959 joins delivery2977 and native APB sample3011. CPU read acceptance3136 joins delivery3154 and native APB sample3188. CPU stores the read value to RAM at event3355, data-channel transaction sequence9. The separate fixed bootstrap write255 is explicitly visible with `observed_case=null`; the directed values belong to the submitted instruction case. Event numbers are journal positions; native samples are drained after their delivery record and joined by the actual shared producer tick.

The real gate also rejects modified declaration addresses, deleted native APB samples and wrong candidate values, and confirms full D3 admission still refuses. Deterministic compressed traces, plans, summaries, success/failure logs and source hashes are retained under `docs/reports/evidence/p7-d3-directed-writer-20261017/`, with original and compressed SHA256 values in `index.json`.

No register-version or compiled checker authority is added. This closes the exact directed writer/readback diagnostic gap only; it does not complete D3 or P7.
