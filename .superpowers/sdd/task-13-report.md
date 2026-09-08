# Task 13 report

## Status

Task 13 is **INCOMPLETE / BLOCKED** because BOOM has no actual execution evidence. The generic reset-vector fix and bounded evidence for Ibex and CVA6 are complete and accepted. No BOOM generation, download, installation, build, or simulation was launched in this continuation.

- Ibex: **GREEN / ACCEPTED**.
- CVA6: **GREEN / ACCEPTED**.
- BOOM: **BLOCKED / NOT RUN**.

## Commits and preservation

- Base: `9b2b22091cc2b18863581526f77a31bf72932479`.
- Existing Task 13 commits: `31b0192` and `bb831af`.
- Final reset-vector implementation/evidence commit: pending at report-write time.
- Pre-existing `.superpowers/sdd/task-2-report.md` modification was preserved and not staged.
- Official pinned source checkouts and unrelated untracked outputs were not modified, removed, repinned, downloaded, or staged.

## Implemented fixes

- Added explicit boot-image `load_base` and `reset_vector` metadata.
- Encoded the load address with a Verilog `$readmemh` address directive, so a binary linked at `0x80` is loaded at byte address `0x80`, not RAM index zero.
- Made 32-bit and 64-bit RAM reads/writes reject accesses that cannot fit fully within `BYTES`; byte loops are bounded without overflow-prone address addition.
- Hardened execution acceptance: first completed fetch must be at the reset vector and match linked boot bytes; pass is rejected if illegal/trap output precedes it; reset, progress, backend completion, and pass remain mandatory.
- Corrected generic processor classification exposed by Task 9-12 regressions: plain `memory_master` enters the processor path only when a generic `boot_control` fact establishes processor context. Processor-specific memory functions remain direct candidates. No CPU-name branch was added.

## Files changed or added in this continuation

- `src/myfuzz/composition/auto.py`
- `src/myfuzz/integration/riscv_execution.py`
- `src/myfuzz/integration/rtl/riscv_boot_memory.sv`
- `tests/integration/test_nonzero_boot_mapping.py`
- `tests/integration/test_riscv_execution.py`
- `third_party/docs/task-13/ibex-fixed/` curated source, boot, generated composition, logs, metrics, manifest, and manifest checksum
- `third_party/docs/task-13/cva6-fixed/` curated source, boot, generated composition, exact compiler warnings, logs, metrics, manifest, and manifest checksum
- `.superpowers/sdd/task-13-report.md`

## TDD and regression evidence

### Nonzero reset-vector RED/GREEN

Command:

```text
timeout --signal=TERM 60s nice -n 15 env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 python3 -m unittest tests.integration.test_nonzero_boot_mapping -v
```

RED: both RV32 and RV64 cases errored because `BootImage` had no `load_base`. GREEN: exit 0, 1 test passed in 0.414s. The test builds both images, requires the first hex record to be `@00000080`, and simulates both RAM widths to prove address zero is empty while address `0x80` returns the linked first word/qword.

### Focused Task 13 post-fix

```text
timeout --signal=TERM 180s nice -n 15 env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 python3 -m unittest tests.integration.test_nonzero_boot_mapping tests.integration.test_riscv_execution -v
```

Result: exit 0, 9 tests passed in 46.731s. This includes real Ibex execution, compiler-backed CVA6 part-select/warning evidence, both RAM widths, manifest encoding, pin verification, and explicit BOOM protocol-gap reporting.

### Task 9-12 scoped regressions

```text
timeout --signal=TERM 120s nice -n 15 env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 python3 -m pytest -q tests/composition/test_processor_execution.py tests/composition/test_processor_backend.py tests/protocols/test_processor_memory_arbiter_rtl.py tests/integration/test_processor_auto_wiring.py tests/integration/test_connected_processor_fixture.py
```

First post-fix result: 20 passed and 1 failed. The legacy MMIO test exposed that commit `31b0192` classified every plain `memory_master` as a processor and tried to resolve the OBI processor adapter inside the temporary source root. The existing test served as RED. A clock-only hypothesis was tested and rejected because ordinary RTL clock inference also sets the endpoint clock. The minimal generic fix requires `boot_control` context for plain `memory_master`.

Final result with the identical command: exit 0, `21 passed, 20 subtests passed in 11.46s`.

### Earlier filelist parser RED/GREEN retained from `31b0192`

```text
timeout --signal=TERM 120s nice -n 15 env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 python3 -m unittest tests.integration.test_riscv_execution.RiscvExecutionTests.test_cva6_packed_axi_wiring_matches_compiler_evidence_and_warnings -v
```

RED: `generic:source-list:invalid-filelist` from a quote inside a full-line `//` comment. GREEN after matching SourceCrawler's safe preprocessing: exit 0; subsequent focused runs passed in 19.772s and 20.581s. The test verifies all 45 generated packed part-selects against compiler-derived `raw_hi/raw_lo` evidence.

## Ibex accepted evidence

Pinned revision: `34b0705760ef3dfa00e99637432473d2be8f22f3`; no nested pins.

Bounded command:

```text
timeout --signal=TERM 240s third_party/docs/task-13/ibex-fixed/run_bounded.sh execution nice -n 15 env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 python3 third_party/docs/task-13/ibex-fixed/persistent_test_launcher.py > third_party/docs/task-13/ibex-fixed/test.log 2>&1
```

Result: exit 0. Compile subprocess 490 and simulation subprocess 491 both exited 0. Verilator compile wall time was 12.516s. Peak sampled process-group RSS was 439668 KiB.

Exact accepted simulator events:

```text
BOOT_FETCH addr=00000080 data=40000293
EXEC reset=1 fetches=5 progress=5 completions=5 pass=1 cycles=40 exit=pass
```

No illegal-instruction or trap record exists. The first fetch at reset vector `0x80` exactly matches the linked RV32 boot word. The earlier pass-after-trap evidence under `third_party/docs/task-13/ibex/` remains preserved but is superseded and explicitly invalid.

Hashes:

- Config: `db181ed864358817a51ede8dc8f43dca7892689ecccc5fcd45ed7a075174b3b2`.
- Composition: `1341c7429020afb4319b60e15d83390e4ac3b6dbbdb39fab8bf080b85c9045a0`.
- Layout: `afd63350a53eaee94430da01be30b92ac1583af11a47767fcdee876ec8fe9599`.
- Processor execution: `2ea506d2eaa255f4519a7290c61f0d9ffbc4f69ae91cf92bcd28036a002b2948`.
- Generated top: `38f0cf739b35a9fbdaa9e3f9c39f98c5fb99be8b01d740bb9fd35098d43f30e2`.
- Source list: `53df3b5eb9ee799716c8f517b28db9e3912ac5bcb6d07294a3aeaea6ec2a6873`.
- Boot ELF: `2416ac77b858e03fa5df1c9cfffc0bbf7e4e0759fdc934e1512adec0bb1a3bc8`.
- Boot binary: `96a8e6a369f6f72c82b39af0ef863127690dad30c04ad2f6e2aba92fb3caa9ed`.
- Addressed boot hex: `1d53d121b8ce1a32b5f7451c94da6d8f0a497480d402bc1fde50a45c0f65722d`.

Persistent manifest: `third_party/docs/task-13/ibex-fixed/manifest.json`; its checksum is in `manifest.sha256`.

## CVA6 accepted evidence

Pinned revision: `2e1336dcff3d1a0b49fbe6282b97802f32ea32af`. Required nested pins: HPDCACHE `f404e7ebbda8baa4af3729535f520a6b12a06d03`, CVFPU `3eb6afeab2cb33f7d8689222955d0171aeb3a801`, and FPU div/sqrt `86e1f558b3c95e91577c41b2fc452c86b04e85ac`.

Compiler evidence command:

```text
cd third_party/docs/task-13/cva6-fixed/run/composition
timeout --signal=TERM 90s ../../run_bounded.sh compiler-records nice -n 15 env JOBS=1 verilator --json-only -Wno-fatal --json-only-output compiler-ports.tree.json --json-only-meta-output compiler-ports.meta.json --top-module cva6 -f upstream-only.f > ../../compiler-records.log 2>&1
```

Result: exit 0; 231 modules; 549.312 MB sources; 3.778s wall; peak process-group RSS 212308 KiB. `compiler-records.log` contains exactly 464 `%Warning-*` records and zero `%Error` records. The complete standalone artifact hash is `0b9056b35329e323f7749c8ed0fb36410d90c2767b8aca825587a771f176e207`. Warning policy remains `recorded-nonfatal`; SourceCrawler rejects incomplete output or any compiler error. The focused test proves all 45 `noc_req_o`/`noc_resp_i` part-selects match compiler evidence.

Bounded compile and execution:

```text
cd third_party/docs/task-13/cva6-fixed/run/composition
timeout --signal=TERM 120s ../../run_bounded.sh compile nice -n 15 env JOBS=1 verilator --binary --timing --top-module tb -Wno-fatal -Wno-PINMISSING -Wno-WIDTH -Wno-UNOPTFLAT -j 1 --Mdir obj_dir -f sources.f task13_tb.sv > ../../compile.log 2>&1
timeout --signal=TERM 30s ../../run_bounded.sh simulation nice -n 15 ./obj_dir/Vtb +riscv_boot_image=../boot/boot.hex > ../../simulation.log 2>&1
```

Both commands exited 0. Compile: 237 modules, 567.466 MB sources, 63.167s Verilator wall, peak process-group RSS 836576 KiB. Simulation peak RSS: 5996 KiB.

Exact accepted event sequence:

```text
AXI_AR cycle=268 addr=0000000000000080 len=0 size=3 burst=1
BACKEND_RSP cycle=272 data=600dd33740000293 error=0
BOOT_FETCH addr=0000000000000080 data=600dd33740000293
COMMIT cycle=280 ack=01 pc0=0000000000000080
COMMIT cycle=290 ack=01 pc0=0000000000000084
COMMIT cycle=300 ack=01 pc0=0000000000000088
COMMIT cycle=311 ack=01 pc0=000000000000008c
BACKEND_REQ cycle=317 write=1 addr=0000000000000400 data=600dcafe600dcafe be=0f
EXEC reset=1 fetches=5 progress=3 completions=5 pass=1 cycles=318 exit=pass
```

No illegal-instruction or trap record exists. The first completed AXI fetch at `0x80` exactly matches the linked RV64 boot qword, and real commits precede the pass store. The earlier zero-fetch timeout under `third_party/docs/task-13/cva6/` remains preserved but is superseded.

Hashes:

- Config: `69c0005a719c204abe3fae628968049cf4c921cf1f9b548b98890344bb0cde34`.
- Composition: `858a8125e141f74ff5fc2aa28d9396d1e7c1299045178c3b91955f8b9c70b3a2`.
- Layout: `2e26be6176ea3af9e2a9f697ba6873276f391b9c8733e8af9f8039a0e14696f1`.
- Processor execution: `6bde5a8b0f618ef6289414e0662c17c587d5905ae18a6f387dc34a7a58a4d234`.
- Generated top: `f105cd044ddd5e5848ecb768d64952bbca3808205b9fd16e68fd56f0ad25aacd`.
- Source list: `84c5f512f54e524a537112e80f68eee3fec84c139d286ce169887c550a4c9114`.
- SourceCrawler snapshot: `c5c43bf31209c575fd472111b074077b6a4bc4910c68501f13b66da5a04efe75`.
- Boot ELF: `ba26337898b8a8ff47e9a2944805da3849c2e9ab8cb13f1340719fc394acf17d`.
- Boot binary: `1e518028c66689599b2a7e4e42ff1c1327abec8e9ed29e8de5b177fea600ab07`.
- Addressed boot hex: `cca768c2f71d00461ac0896897d15e213185d488136efe0f1fe0016325c144bf`.

Persistent manifest: `third_party/docs/task-13/cva6-fixed/manifest.json`; its checksum is in `manifest.sha256`.

## Tool versions

- Verilator: `Verilator 5.051 devel rev vUNKNOWN-built20260806-e413e67`.
- Clang: `Ubuntu clang version 18.1.3 (1ubuntu1)`.
- LLD: `Ubuntu LLD 18.1.3 (compatible with GNU linkers)`.
- Icarus: `Icarus Verilog version 14.0 (devel) (f493076)`.
- Python: `Python 3.12.3`.

## BOOM blocker

No BOOM work was performed in this continuation.

- BOOM source revision: `58ef2720eae13be26b3008c02b5a74ce29c61c44`.
- Declared Chipyard revision: `4180463d52bc0a6b4c004530601ccdabebf0ab7d`.
- Missing external generator/toolchain and generated RTL/parameters/source closure remain unavailable.
- The inspected real boundary is full coherent TileLink A/B/C/D/E, while the generic catalog supports TL-UL only.
- Required generic work item: add CPU-independent coherent `tilelink@1` capability/schema, compiler boundary extraction, B/C/E coherence semantics, adapter/backend support, and bounded protocol tests. No BOOM-specific bridge or renderer is acceptable.

Task 13 remains blocked until actual BOOM execution evidence exists.

## Self-review and concerns

- Ibex and CVA6 evidence is now valid against nonzero reset mapping, first-fetch byte matching, no-illegal/trap acceptance, real progress, backend completions, and bounded pass.
- CVA6's 464 compiler warnings are retained verbatim as a standalone hashed artifact; zero errors are recorded and error policy was not relaxed.
- The current manifests hash source lists and generated artifacts. CVA6 additionally carries the existing SourceCrawler snapshot hash.
- Binary-build warning counts are context-specific and are not substituted for the official 464-record compiler artifact.
- Uninitialized optional CVA6 submodules shown by `git submodule status` are outside the selected source closure; the three declared required nested pins are present and exact.
- Overall Task 13 is intentionally not claimed complete because BOOM is blocked.
