# Source-backed local runtime top evidence — 2026-10-04

Task 1 only, based on `48c07bf`. Artifacts have `status=top_only`, empty `cpp_text`, and `driver_status=not_generated`. Real lint and a bounded APB address-gate simulation establish structural/adaptor evidence; Generated, operational sessions, CPU execution and cross-component acceptance remain unproven.

## Admission and interface

`render_local_runtime(plan, structural, source_verification, *, base_dir: Path)` requires an explicit checkout. It checks current profile bytes against `profile_sha256`, reloads and compares the profile object, refreshes the source lock and requires exact receipt equality, checks parameter source snapshots, freshly elaborates and compares full PhysicalFacts, rebinds physical facts, reconstructs the authoritative disposition ledger and regenerates the supplied structural wrapper/ABI/build for exact equality. All original structural bytes remain unchanged. The runtime artifact is a frozen dataclass containing independent copies of supplied plan/documents.

Adapters are selected by endpoint functions, protocol version, resolved roles, directions and widths. There are no component-name conditions. Backend/physical export metadata records every runtime signal width; observations wider than 64 bits specify fixed-width lowercase hex encoding and digit count for the later serializer. No C++ serializer is implemented in Task 1.

## Verification

`PYTHONPATH=src:. python3 -m unittest discover -s tests/local_harness -v` passed 49 tests; 8 cover the new runtime renderer. Both real lint tests and the GPIO address-gate simulation ran, with no skips. `git diff --cached --check` passed.

Tool: Verilator 5.051 devel rev vUNKNOWN-built20260806-e413e67

JSON hashes use UTF-8, sorted keys, separators `,`/`:`, `ensure_ascii=False`, no trailing newline. Artifact digest hashes the runtime document before its `artifact_digest` field is inserted.

## cpu_0

- Profile: `configs/cpus/cv32e20/component_profile.json`
- Profile SHA-256: `18ef425486107690d2fb92bb80141cbfab4013b05768c8c2a5ee706fe223d7ec`
- Source revision: `git:d079e8c8e6a08b330940ae123876ba0612bec18d`
- Source content hash: `sha256:afe5ca029cc2ba2078bb7524475dc8061c32f88bcb91e197ae2861512c00b338`
- Source lock SHA-256: `e55b3ace8426ac4db78c1560c7caf2503de998237c20a7a87ae89046fab092a7`
- Structural wrapper SHA-256: `84db5687be8b3d6fbbc0509ba34e5176f4cbd4823df5da5a44b000a239d4b12d`
- Runtime SV SHA-256: `fe4ccc70c58e8b99f930ee7562b4fcd0ac7bbab712e12657ed38d2a0b518b159`
- Artifact digest: `8c55bde9c78389cd927af19df8c6d947a6a533a0580afafbb7887510e4f6b25a`
- Artifact document SHA-256: `68faade2f98a95ca5fd9d9c6f1909a5892d224396aa5571ec8d5875429f1e6a5`
- Physical ports: 70; structural ABI segments: 52; runtime physical exports: 37.
- Preserved parameters: `{"MHPMCounterNum": "10", "MHPMCounterWidth": "40", "RV32E": "0", "RV32M": "2", "XInterface": "0"}`
- Lint: exit 0; 94 recorded warnings (`COMBDLY=1, UNOPTFLAT=3, WIDTHEXPAND=45, WIDTHTRUNC=45`); no `%Error`.

Exact lint command, from the supplied checkout (`STRUCTURAL`/`RUNTIME` are generated file paths):

```sh
verilator --lint-only -Wno-fatal --top-module local_runtime_cpu_0 -Ithird_party/cv32e20_upstream_reference/rtl -Ithird_party/cv32e20_upstream_reference/vendor/lowrisc_ip/ip/prim/rtl -Ithird_party/cv32e20_upstream_reference/vendor/lowrisc_ip/dv/sv/dv_utils -DRVFI=1 third_party/cv32e20_upstream_reference/rtl/cve2_pkg.sv third_party/cv32e20_upstream_reference/rtl/cve2_tracer_pkg.sv third_party/cv32e20_upstream_reference/vendor/lowrisc_ip/ip/prim/rtl/prim_secded_pkg.sv third_party/cv32e20_upstream_reference/vendor/lowrisc_ip/ip/prim/rtl/prim_ram_1p_pkg.sv third_party/cv32e20_upstream_reference/rtl/cve2_alu.sv third_party/cv32e20_upstream_reference/rtl/cve2_compressed_decoder.sv third_party/cv32e20_upstream_reference/rtl/cve2_controller.sv third_party/cv32e20_upstream_reference/rtl/cve2_cs_registers.sv third_party/cv32e20_upstream_reference/rtl/cve2_csr.sv third_party/cv32e20_upstream_reference/rtl/cve2_counter.sv third_party/cv32e20_upstream_reference/rtl/cve2_decoder.sv third_party/cv32e20_upstream_reference/rtl/cve2_ex_block.sv third_party/cv32e20_upstream_reference/rtl/cve2_fetch_fifo.sv third_party/cv32e20_upstream_reference/rtl/cve2_id_stage.sv third_party/cv32e20_upstream_reference/rtl/cve2_if_stage.sv third_party/cv32e20_upstream_reference/rtl/cve2_load_store_unit.sv third_party/cv32e20_upstream_reference/rtl/cve2_multdiv_fast.sv third_party/cv32e20_upstream_reference/rtl/cve2_multdiv_slow.sv third_party/cv32e20_upstream_reference/rtl/cve2_prefetch_buffer.sv third_party/cv32e20_upstream_reference/rtl/cve2_pmp.sv third_party/cv32e20_upstream_reference/rtl/cve2_register_file_ff.sv third_party/cv32e20_upstream_reference/rtl/cve2_wb.sv third_party/cv32e20_upstream_reference/rtl/cve2_core.sv third_party/cv32e20_upstream_reference/rtl/cve2_top.sv third_party/cv32e20_upstream_reference/rtl/cve2_top_tracing.sv third_party/cv32e20_upstream_reference/rtl/cve2_tracer.sv third_party/cv32e20_upstream_reference/rtl/cve2_clock_gate.sv third_party/cv32e20_upstream_reference/rtl/cve2_branch_predict.sv src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv "$STRUCTURAL" "$RUNTIME"
```

Adapters:

- `src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv`: `70c73cb08affe154c60a24ace141fce5818c6852825f1c4cc9e6901ca8982172`

## gpio_a

- Profile: `configs/peripherals/pulp_gpio/component_profile.json`
- Profile SHA-256: `2268967fa909658fbc079fc41112a10bba88e7484909153cbc1a5a1b222a0b56`
- Source revision: `git:f82caeb7f7d89427f05e9af5ed31e0675efe0d83`
- Source content hash: `sha256:bde1f2c536e833582ab80faf74f8e56394aeb2af8cf6528a9452c34daa1da456`
- Source lock SHA-256: `e55b3ace8426ac4db78c1560c7caf2503de998237c20a7a87ae89046fab092a7`
- Structural wrapper SHA-256: `4dd42442937289662279e07d85717f2680ee66e27a3ed4e0b89eb68057819d22`
- Runtime SV SHA-256: `9c166d3f0be42a8445d060857f4d7be9978548bae8cad79894f75ca1add0f579`
- Artifact digest: `cba5c9e7ff886c5f1d1ee485b549fb88d8ca39bd3e755588dfb63d241ddb53cf`
- Artifact document SHA-256: `c2e0d2f8a452a025f86607cd3e7b92b7d28e20a64abc8bfe944682133828e234`
- Physical ports: 17; structural ABI segments: 14; runtime physical exports: 6.
- Preserved parameters: `{"APB_ADDR_WIDTH": "12", "NBIT_PADCFG": "4", "PAD_NUM": "32"}`
- Lint: exit 0; 1 recorded warnings (`CASEINCOMPLETE=1`); no `%Error`.

Exact lint command, from the supplied checkout (`STRUCTURAL`/`RUNTIME` are generated file paths):

```sh
verilator --lint-only -Wno-fatal --top-module local_runtime_gpio_a third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv src/myfuzz/protocols/rtl/beat_to_apb.sv "$STRUCTURAL" "$RUNTIME"
```

Adapters:

- `src/myfuzz/protocols/rtl/beat_to_apb.sv`: `35cc8c1765a42cdfbfdd1ec504492ab789559d7a3ceee95c9f3ed48b474b2d7c`

## APB address width correction and native RTL evidence

The PULP profile exposes 12-bit PADDR. Instantiating `beat_to_apb` with `ADDRESS_WIDTH=12` and `WINDOW_SIZE=4096` truncates its `WINDOW_LIMIT` to zero and violates the adapter's initialization check. The generated adapter therefore uses 32-bit local byte offsets and `WINDOW_BASE=0`, `WINDOW_SIZE=4096`; only its checked APB PADDR output is sliced to `[11:0]` at the structural boundary. No request is truncated before range checking.

The test compiles the actual generated runtime top, structural wrapper, original `apb_gpio` source and `beat_to_apb` using `verilator --binary --timing -j 1`, then executes the resulting binary with a 10-second deadline. For offset `0x1000`, the measured terminal response is valid/error and PSEL remains zero. For aligned offset `0xFFC`, PSEL asserts with APB address `0xFFC`, then the real APB completion produces valid/no-error. The test prints `ADDRESS_GATE_PASS`. No behavioral DUT replacement is present.

The existing adapter does not enforce address alignment, and native GPIO decodes `PADDR[6:2]`. Raw offset `0xFFF` can therefore reach APB and alias to the last word; this is a source behavior, not an admitted register API contract. The later `ACCESS_GPIO` host parser must reject offsets not divisible by four before an RTL edge. Task 1 preserves the shared adapter unchanged.

## Remaining gates

Review follow-up: OBI runtime rendering now records the profile's configured boot base without fixing it to `0x10000`; `expected_first_fetch` remains unknown until a source-backed first-fetch contract or real CPU observation is added. APB uses `min(request.max_wait_cycles, profile.max_wait_cycles)` and records the effective limit. Two regression cases failed before these changes and pass afterward. Runtime build admission still must reject mutation of nested artifact documents, even though the outer dataclass is frozen.

- Task 2 must implement the C++ wire driver, source-identity build/cache admission and persistent bounded transport. Empty C++ text here is intentional.
- `BoundedLineReader` defaults to 64 KiB while the planned wire payload permits 1 MiB before hex encoding; its reader limit/deadline must be set explicitly. A missing command deadline must not admit unbounded reads.
- `LocalCommandReplay` short ERROR replies must be wrapped in the versioned execution/sequence/tick envelope; lost receipts cannot authorize repeated uncertain effects.
- Later GPIO/CPU sessions must prove full-word/aligned accesses, native pulse receipts across command-internal clocks, actual CPU request handshakes and persistent state before operational claims.
