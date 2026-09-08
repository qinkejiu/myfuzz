# Task 13 report

## Status

Task 13 is **INCOMPLETE / BLOCKED**. Work stopped on user request. No compile or simulation process remains active.

- Ibex: generated split-OBI execution compiled and produced bounded activity/pass counters, but the evidence is **invalidated** because the boot bytes were loaded at RAM index zero instead of reset vector `0x80`. The log shows an illegal zero instruction at reset PC before the later pass.
- CVA6: compiler-backed packed AXI plan/write and real bounded execution completed, but execution is **not green**. Legal reads at `0x80`, `0x88`, and `0x90` returned zero, no instruction committed, and the run timed out at cycle 2000.
- BOOM: **BLOCKED**, unchanged. No BOOM generation was launched.

## Commits

- `31b0192` (`task13: add generic CPU execution evidence path`): generic infrastructure, parser/source-order fixes, focused tests, and curated Ibex/CVA6 evidence.
- The report itself is finalized in a separate report-only commit following the implementation commit.

## Base and preserved content

- Base/starting commit: `9b2b22091cc2b18863581526f77a31bf72932479`.
- Branch: `feature/ibex-protocol-longrun`.
- Pre-existing `.superpowers/sdd/task-2-report.md` modification was not edited or staged.
- Existing official source checkouts and untracked `third_party/rfuzz/upstream/ibex/sources.f` were reused without changing pins.

## Implemented generic infrastructure

- Generic RISC-V execution facts, Clang/LLD boot-image construction, bounded event verification, repository pin verification, run-manifest construction, and generic protocol blocker records.
- Generic 32-bit and 64-bit `processor-memory-beat@1` boot RAM components.
- Compiler physical-port filtering and packed-field evidence propagation.
- CPU-name-independent processor IR/source normalization and ordered source publication.
- Generic filelist variable expansion and safe full-line `//` preprocessing matching `SourceCrawler`.
- Generic filelist metadata now distinguishes ordered compilation units from the larger hash/source closure.
- Unified `memory_master` is handled by the same processor backend path as split and explicitly named processor-memory functions.
- One-bit `~reset` is accepted as active-low evidence only when consistent with a matching asynchronous reset edge.
- No BOOM-specific renderer, bridge, or protocol special case was added.

## Files changed or added

- `src/myfuzz/integration/riscv_execution.py`
- `src/myfuzz/integration/rtl/riscv_boot_memory.sv`
- `src/myfuzz/integration/__init__.py`
- `src/myfuzz/composition/source_elaboration.py`
- `src/myfuzz/composition/source_crawler.py`
- `src/myfuzz/composition/auto.py`
- `src/myfuzz/composition/protocol_composer.py`
- `configs/cpus/ibex/official_core_interface_description.json`
- `tests/integration/test_riscv_execution.py`
- `third_party/docs/task-13/ibex/manifest.json` and curated persistent run evidence
- `third_party/docs/task-13/cva6/manifest.json` and curated incomplete run evidence
- `.superpowers/sdd/task-13-report.md`

Uncommitted build-object directories and incidental raw harness logs may remain in the worktree; they are not required source changes and are not claimed as committed evidence.

## Focused test evidence

### Relevant Task 9-12 baseline

Command:

```text
timeout --signal=TERM 120s nice -n 15 env PYTHONPATH=src python3 -m pytest -q tests/composition/test_processor_execution.py tests/composition/test_processor_backend.py tests/protocols/test_processor_memory_arbiter_rtl.py tests/integration/test_processor_auto_wiring.py tests/integration/test_connected_processor_fixture.py
```

Result: exit 0, `21 passed, 20 subtests passed in 10.28s`.

This baseline preceded the final filelist changes. It was not rerun after the stop instruction.

### Generic execution API RED/GREEN

RED command:

```text
timeout --signal=TERM 30s nice -n 15 env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 python3 -m unittest tests.integration.test_riscv_execution -v
```

RED result: expected `ModuleNotFoundError` for the not-yet-created API.

GREEN command used the same invocation with a 60s bound. Result: 3 tests passed in 0.191s.

### Boot RAM RED/GREEN

- 32-bit RED: unknown/missing RAM module before implementation.
- 32-bit GREEN focused result: 1 test passed in 0.022s; repeated result 0.015s.
- 64-bit RED: unknown `riscv_boot_memory_64` module.
- 64-bit GREEN command:

```text
timeout --signal=TERM 60s nice -n 15 env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 python3 -m unittest tests.integration.test_riscv_execution.RiscvExecutionTests.test_64_bit_boot_memory_preserves_byte_lanes -v
```

Result: exit 0, 1 test passed in 0.016s.

These byte-lane tests did not cover loading the binary at a nonzero reset vector; that missing assertion caused the execution false positive.

### Generic filelist/CVA6 planning RED/GREEN

Initial RED after reaching CVA6 compiler evidence:

```text
timeout --signal=TERM 120s nice -n 15 env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 python3 -m unittest tests.integration.test_riscv_execution.RiscvExecutionTests.test_cva6_packed_axi_wiring_matches_compiler_evidence_and_warnings -v
```

Result: exit 1, `generic:source-list:invalid-filelist`; cause was a quote inside a full-line `//` comment reaching `shlex`.

After matching `SourceCrawler` comment preprocessing, subsequent REDs exposed:

- `generic:component:boot-memory:no-compatible-endpoint` because unified `memory_master` was omitted from planner classification.
- `memory-clock:processor.memory.unified` because `~rst_ni` was not recognized as the one-bit equivalent of `!rst_ni` despite `negedge rst_ni` source evidence.

Final focused GREEN command was identical to the command above.

Result: exit 0, 1 test passed in 19.772s. A later repeat after ordered compilation-unit selection also passed: exit 0, 1 test passed in 20.581s.

The test proves:

- source compiler evidence is accepted only with `warning_policy=recorded-nonfatal`;
- warning count is exactly 464;
- all 45 generated packed field connections use `noc_req_o` or `noc_resp_i`;
- every generated part-select text matches its compiler-derived `raw_hi/raw_lo`.

The official 464 warning messages were observed by the focused test but were not materialized as a persistent standalone warning-text artifact before the stop instruction. This remains an evidence completeness concern; the later binary compile log contains 445 warnings from a different compilation context and is not substituted for the official 464-warning set.

## Ibex evidence

### Pins and tools

- Ibex revision: `34b0705760ef3dfa00e99637432473d2be8f22f3`.
- Nested pins: none.
- Clang: `Ubuntu clang version 18.1.3 (1ubuntu1)`.
- Verilator: `Verilator 5.051 devel rev vUNKNOWN-built20260806-e413e67`.
- Icarus: `Icarus Verilog version 14.0 (devel) (f493076)`.

### Planning test

```text
timeout --signal=TERM 90s nice -n 15 env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 python3 -m unittest tests.integration.test_riscv_execution.RiscvExecutionTests.test_official_split_obi_processor_plans_generated_arbiter_backend -v
```

Result: exit 0, 1 test passed in 4.116s.

This proves the official split instruction/data OBI endpoints route through generated adapters, arbiter, backend, and 32-bit boot RAM without CPU-name selection.

### Persistent bounded execution

Outer command:

```text
timeout --signal=TERM 240s /usr/bin/time -v -o third_party/docs/task-13/ibex/process-metrics.txt nice -n 15 env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 python3 third_party/docs/task-13/ibex/persistent_test_launcher.py
```

Compile command captured in `subprocess-490.json`:

```text
nice -n15 verilator --binary --timing --top-module tb -Wno-fatal -Wno-PINMISSING -Wno-WIDTH -Wno-UNOPTFLAT -j 1 --Mdir obj_dir -f sources.f task13_tb.sv
```

Compile result: exit 0. Simulation command captured in `subprocess-491.json`; result exit 0.

Exact simulator output:

```text
30: Illegal instruction (hart 0) at PC 0x00000080: 0x00000000
EXEC reset=1 fetches=8 progress=8 completions=8 pass=1 cycles=61 exit=pass
```

Metrics and hashes:

- Maximum bounded-command RSS: 301460 KiB. This is GNU `time` command/descendant accounting, not a separately sampled aggregate process-group metric.
- Config: `sha256:db181ed864358817a51ede8dc8f43dca7892689ecccc5fcd45ed7a075174b3b2`.
- Composition JSON: `sha256:8f29d799a04916fd2f5e947a360b5265c8d4bffb71a9cdac7debb6884b997782`.
- Layout JSON: `sha256:afd63350a53eaee94430da01be30b92ac1583af11a47767fcdee876ec8fe9599`.
- Processor execution JSON: `sha256:bd51179f2b0e894609b5840218e7f078dc263b2ccdba350eb396cfb4a32903c3`.
- Generated top: `sha256:38f0cf739b35a9fbdaa9e3f9c39f98c5fb99be8b01d740bb9fd35098d43f30e2`.
- Source list: `sha256:53df3b5eb9ee799716c8f517b28db9e3912ac5bcb6d07294a3aeaea6ec2a6873`.
- Boot ELF: `sha256:2416ac77b858e03fa5df1c9cfffc0bbf7e4e0759fdc934e1512adec0bb1a3bc8`.
- Boot binary: `sha256:96a8e6a369f6f72c82b39af0ef863127690dad30c04ad2f6e2aba92fb3caa9ed`.
- Boot hex: `sha256:2beb94087fadd5889e83e0cd3d4810c2e8aa2ee18fa49c8e2010447c088b8836`.

Status: **INCOMPLETE / INVALIDATED**. `boot.hex` contains byte lines beginning at index zero while reset PC is `0x80`. The illegal-instruction line proves the core did not fetch the intended first boot instruction at reset. It then trapped to address zero, where the image existed, and eventually generated the pass store. The pass counter therefore does not satisfy Task 13a.

## CVA6 evidence

### Pins, nested pins, and policy

- CVA6 revision: `2e1336dcff3d1a0b49fbe6282b97802f32ea32af`.
- HPDCACHE: `f404e7ebbda8baa4af3729535f520a6b12a06d03`.
- CVFPU: `3eb6afeab2cb33f7d8689222955d0171aeb3a801`.
- FPU div/sqrt: `86e1f558b3c95e91577c41b2fc452c86b04e85ac`.
- SourceCrawler snapshot: `sha256:c5c43bf31209c575fd472111b074077b6a4bc4910c68501f13b66da5a04efe75`.
- Official compiler evidence: exactly 464 warnings, `recorded-nonfatal`; errors remain fatal.
- Packed boundary: `noc_req_o[469:0]`, `noc_resp_i[209:0]`, 45 compiler-proven generated part-selects.

### Plan/write

The first materialization attempt failed before write due to missing caller `base_dir`. The second strict-lint attempt exposed compilation of the full source closure and failed on duplicate mutually exclusive config packages/include-only files. Both failures were preserved.

After ordered filelist compilation units were separated from hash closure, strict plan/write completed and produced the generated top, source list, composition/layout/execution JSON, and RV64 boot ELF/binary/hex. The materialization process then exited only while serializing a nonexistent annotation key; generated plan/write artifacts remained complete.

### Bounded binary compile

```text
cd third_party/docs/task-13/cva6/run/composition
timeout --signal=TERM 180s ../../run_bounded.sh compile nice -n 15 env JOBS=1 verilator --binary --timing --top-module tb -Wno-fatal -Wno-PINMISSING -Wno-WIDTH -Wno-UNOPTFLAT -j 1 --Mdir obj_dir -f sources.f task13_tb.sv
```

Result: exit 0. Verilator reported 237 modules, 567.464 MB source input, 55.085s wall time in the first retained compile. Sampled peak aggregate process-session RSS: 835144 KiB. Final diagnostic compile also exited 0, wall time 58.932s, peak 835944 KiB.

The compile log retains all 445 warnings from this binary-build context. These are additional runtime-build warnings and are not the official 464-warning compiler-boundary set.

### Bounded real execution and precise blocker

```text
cd third_party/docs/task-13/cva6/run/composition
timeout --signal=TERM 30s ../../run_bounded.sh final-diagnostic-simulation nice -n 15 ./obj_dir/Vtb +riscv_boot_image=../boot/boot.hex
```

Result: exit 1 by the explicit 2000-cycle bound. Peak sampled process-session RSS: 6100 KiB.

Exact relevant evidence:

```text
AXI_AR cycle=268 addr=0000000000000080 len=0 size=3 burst=1
BACKEND_REQ cycle=270 write=0 addr=0000000000000080 ... be=ff
BACKEND_RSP cycle=272 data=0000000000000000 error=0
AXI_AR cycle=288 addr=0000000000000088 len=0 size=3 burst=1
BACKEND_RSP cycle=292 data=0000000000000000 error=0
AXI_AR cycle=308 addr=0000000000000090 len=0 size=3 burst=1
BACKEND_RSP cycle=312 data=0000000000000000 error=0
EXEC reset=1 fetches=5 progress=3 completions=5 pass=0 cycles=2000 exit=timeout
```

No commit event was observed. This rules out unsupported burst traffic: the reads are legal single-beat INCR transactions (`len=0`, `size=3`, `burst=1`) and all reach/complete through the generated backend. The precise blocker is generic boot-image placement: the RAM loads byte-only `boot.hex` at index zero while requests use absolute reset-vector addresses beginning at `0x80`, so all intended boot reads return zero.

Hashes:

- Config: `sha256:69c0005a719c204abe3fae628968049cf4c921cf1f9b548b98890344bb0cde34`.
- Composition JSON: `sha256:858a8125e141f74ff5fc2aa28d9396d1e7c1299045178c3b91955f8b9c70b3a2`.
- Layout JSON: `sha256:2e26be6176ea3af9e2a9f697ba6873276f391b9c8733e8af9f8039a0e14696f1`.
- Processor execution JSON: `sha256:6bde5a8b0f618ef6289414e0662c17c587d5905ae18a6f387dc34a7a58a4d234`.
- Generated top: `sha256:f105cd044ddd5e5848ecb768d64952bbca3808205b9fd16e68fd56f0ad25aacd`.
- Source list: `sha256:84c5f512f54e524a537112e80f68eee3fec84c139d286ce169887c550a4c9114`.
- Boot ELF: `sha256:ba26337898b8a8ff47e9a2944805da3849c2e9ab8cb13f1340719fc394acf17d`.
- Boot binary: `sha256:1e518028c66689599b2a7e4e42ff1c1327abec8e9ed29e8de5b177fea600ab07`.
- Boot hex: `sha256:00960f806a61adf03b84eafc39857f5af9faf0315045413f741711e7dbc375e8`.

Status: **INCOMPLETE**.

## BOOM status

No BOOM generation, toolchain installation, download, compile, or simulation was launched in this continuation.

- Pinned source revision: `58ef2720eae13be26b3008c02b5a74ce29c61c44`.
- Declared Chipyard revision: `4180463d52bc0a6b4c004530601ccdabebf0ab7d`.
- Generated BOOM RTL, elaborated parameter record, dependency closure, and filelist are absent.
- Chipyard checkout/generator toolchain is absent.
- The inspected BOOM boundary uses full coherent TileLink A/B/C/D/E; the available generic catalog supports TL-UL, not full coherent TileLink.
- Required generic work item: add a CPU-independent `tilelink@1` capability/schema, compiler boundary extraction, adapter/backend semantics including B/C/E coherence channels, and bounded protocol tests. No BOOM-specific bridge is acceptable.

Status: **BLOCKED**. Task 13 cannot be complete until actual BOOM execution evidence exists.

## Self-review and remaining work

- Good: parser comment handling now matches SourceCrawler; ordered compilation units and closure hashes are separated; CVA6 strict plan/write and all 45 packed slices are proven; no CPU-name branch or BOOM-specific logic was introduced.
- Blocking defect: generic boot image/RAM address layout does not place the linked binary at the nonzero reset vector. Both CPU execution claims must remain incomplete until fixed and rerun.
- Evidence gap: official CVA6 464 warning texts were not persisted, although exact count/policy were asserted by the passing focused test.
- Evidence metric gap: Ibex has GNU-time maximum RSS, not independently sampled aggregate process-group RSS.
- Regression gap: relevant Task 9-12 baseline passed before final parser/source-order changes but was not rerun after the explicit stop instruction.
- BOOM remains blocked as described above.
- Task 13 is not complete.
