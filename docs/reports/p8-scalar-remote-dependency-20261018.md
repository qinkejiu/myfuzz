# P8 scalar measurement: remote source and tool dependencies

This report records the source/dependency inspection stage for scalar measurement `d7486c9` and the continuous RX factory. At that stage, no project imports, tests, frontend, build, model or remote operation were performed. Standard-library JSON/file/hash reads inspected declarative inputs. It remains a preparation checklist, not a proven transitive closure or a native/performance result. Task2 batching remains unimplemented pending measured attribution.

## Execution entry and exact instances

`scripts/measure_dma_uart_transport.py` SHA256 `91eb4652ce81aa2dbddc4da200f9b90f26dd2bebdd2d4ffd5bc98cf9d793f8ee` installs the existing command observer and calls `integration/dma_uart_rx_runtime.py:run_continuous_uart_rx()` once. Its factory is `scenario/ibex_dma_uart_rx_continuous.py:make_continuous_uart_rx_runner()`. `_artifact()` comes from `scenario/ibex_dma_example.py`; it plans, source-verifies and renders each actual generated artifact, with reset8/8 and max_wait16. Actual construction is:

| Instance | Profile | Runtime/session |
| --- | --- | --- |
| cpu | `configs/cpus/ibex_rvfi_local/component_profile.json` | GeneratedCve2Session, real RVFI/native IRQ receipts, deferred MMIO |
| uart | `configs/peripherals/opentitan_uart_fifo_local/component_profile.json` | GeneratedOpentitanUartSession, genome RX source, FIFO probes, `read_rx_after_source=false` |
| dma | `configs/peripherals/zipcpu_wbdmac/component_profile.json` | GeneratedWishboneDmaScenarioSession, UART RXDATA master target offset0x18 |

RAM is region0x10000..0x30000, seed17, max initialized0x20000; factory preloads encoded actual CPU firmware, destination and ISR/result cells. No RISC-V assembler/compiler, Rust fuzzer, Java/SBT/Mill or Chipyard is used by this scalar measurement entry. It is a directed continuous run, not RFuzz search. Complete `src` is needed for source-pin discovery and broad builder host-source hashing; trimming just direct Python imports changes identity.

## Source selection relative to the P7 snapshot

The reported P7 selection has Ibex/CVE2/CV32/PULP GPIO/timer. It **does not** supply two additional required source roots:

- `third_party/soc-opentitan` at official Git revision `fca045df919a26c47e71616b9dac917b1ea4fd07`.
- `third_party/soc-zipcpu` at official Git revision `42606d2d6ef55df313772232977621b2d72f0159`.

Existing `third_party/rfuzz/upstream/ibex` is required at official revision `34b0705760ef3dfa00e99637432473d2be8f22f3`, including both vendors under that root; do not replace it with `external_designs/cv32e40p` or the CVE2 reference. Full copied root `.git` plus independent component metadata is necessary for existing source-lock Git blob/track checks.

**Concrete local metadata blocker:** file reads show both added roots' `.git/config` currently set remote origin `promisor=true` and `partialclonefilter=blob:none`. Thus neither can be copied as-is through the reviewed strict preparer. Root must preserve original metadata, materialize separately audited independent Git stores with needed original objects, refuse lazy network acquisition, and freeze a new whole map after metadata overlay. Do not remove a promisor flag and assume missing objects exist. No such materialization was performed here. This is the same category of issue as the independently handled Ibex metadata, but it needs its own receipts.

The safest explicit source selection is the complete two added working trees, with original `.git` excluded only when independent metadata is deliberately overlaid; retain licenses/provenance/include files. Retain complete `src`, `scripts`, `configs`, root `.git`/`.gitmodules`, project documentation/agent instructions and any existing reviewed P7 configuration support. Do not mutate the already frozen P7 snapshot in place: derive a new independent P8 staging/copy and final map.

## Lock/profile/closure dependencies that cannot be omitted

Actual lock file `configs/soc/sources.lock.json` SHA256 is `4caf0ae616e99e3c7cac76a1b04daca41af9bcef0eee3b6b0923fb6bd7e2a29e`. The verifier dynamically loads actual `scripts/verify_soc_sources.py` from the imported project root; it reads component artifacts and uses Git to compare pinned blobs. A source-directory listing alone is insufficient. Root/configs deletion exclusions must preserve:

- `configs/cpus/ibex_rvfi_local/component_profile.json` (`aa73e0a5dd6052a50368eb8078199f3ec9f8f50e2de1ae27fc1ce04423e8d514`), recursively authenticated `configs/cpus/ibex_obi_local/component_profile.json` (`639508bbfd79ca0ab2fe5cbe412a67208df26333de8d06ce935c80e59c8771d3`), and `configs/cpus/ibex/official_core_interface_description.json`.
- `configs/peripherals/opentitan_uart_fifo_local/component_profile.json` (`e4204b40e2369635c956da51301cfeff3348ab6370515c55440c52a90f282d11`) and its authenticated original scalar `configs/peripherals/opentitan_uart_local/component_profile.json` (`759f864771b860c8d29b9005bf93ebb3b4381ec4472545de3c3e782b8697efce`). The FIFO variant does not bypass the original scalar contract.
- `configs/peripherals/zipcpu_wbdmac/component_profile.json` (`eabcac10f041131f3759ad194d1e6554fe07160d6f68633c65d52643b6e384bd`).
- `configs/soc/closures/ibex_obi_local.json`, `ibex_rvfi_local.json`, `opentitan_uart.json`, `opentitan_uart_fifo_local.json`, `zipcpu_wbdmac.json`. Their existing identity checks remain unchanged.
- Ibex `LICENSE`; OpenTitan `LICENSE`, `hw/ip/uart/data/uart.hjson` and `hw/ip/uart/uart.core`; ZipCPU **`doc/src/gpl-3.0.tex`**, not an invented top-level LICENSE substitute. Each ancillary artifact is byte/Git-bound by its actual lock record.

## RTL/macros/probes

The exact ordered RTL file list remains each profile's `source.files`; this report does not substitute a regenerated list. Ibex RVFI profile selects45 files and four recursive include roots; UART selects44 files and five recursive include roots; DMA selects one upstream `rtl/peripherals/wbdmac.v`.

Ibex include roots (relative to `third_party/rfuzz/upstream/ibex`): `vendor/lowrisc_ip/ip/prim/rtl`, `vendor/lowrisc_ip/ip/prim_generic/rtl`, `vendor/lowrisc_ip/dv/sv/dv_utils`, `vendor/pulp_common_cells/rtl`. Its RVFI profile explicitly defines `RVFI=1`; the recursively verified OBI profile has parameter settings PMPEnable0/RV32E0/ICache0/SecureIbex0. Preserve both rather than injecting those parameters into RVFI. Wrapper files are actual `src/myfuzz/composition/rtl/soc_ibex_rvfi_local.sv` and `ibex_irq_serial_sideband.sv`.

UART include roots (relative to `third_party/soc-opentitan`): `hw/ip/prim/rtl`, `hw/ip/prim_generic/rtl`, `hw/ip/tlul/rtl`, `hw/top_earlgrey/rtl`, `hw/top_earlgrey/rtl/autogen`. The scalar source contract hashes **all regular non-symlink files recursively under these roots**, including noncompiled files. Copying only44 listed RTL sources changes the union hash. Headers currently include `prim_assert_{dummy,standard,yosys}_macros.svh`, `prim_assert_sec_cm.svh`, `prim_fifo_assert.svh`, `prim_macros.svh`, `prim_secded_inc.svh`, `prim_util_get_scramble_params.svh`, `prim_util_memload.svh`; retain whole include roots rather than only these examples. The exact admitted wrapper is `src/myfuzz/composition/rtl/soc_opentitan_uart_local_target.sv`.

`local_harness/opentitan_uart_fifo_contract.py` owns `UART_FIFO_PROBES`, `_SOURCE_HASHES`, source contract and closure's passive probe manifest. It checks the pinned OpenTitan primitive/receiver/core/reg/TL-UL sources, actual FIFO/count/buffer/internal RX hierarchy and all real serial/interrupt/TL fields. `runtime_renderer.py` creates the passive probe exports from that contract. Retain this Python file and all exact UART profile source bytes; no handwritten stand-in hierarchy or omitted probe can reuse the old identity. No actual hierarchy resolution has been reverified by this report.

DMA uses profile elaboration parameters ADDRESS_WIDTH30/BUS_WIDTH32/SLV_WIDTH32/LGMEMLEN10. `wishbone_dma_template.py` and `rtl/wishbone_dma_edge.h` implement generated edge handling; they are project `src` inputs. Shared `rtl/local_driver_v1.h`, `scenario/rtl/local_command_replay.h`, protocol adapters and all profile-derived runtime code must retain the reviewed bytes. Existing scalar driver defaults, real UART waveform and source/IRQ consumers are unchanged.

## Tools/environment to freeze separately

`local_harness/build.py:_toolchain()` actually discovers `verilator`, `c++`, `make`, `ar` through PATH, resolves executable paths, executes each `--version`, hashes executable bytes, hashes sibling `verilator_bin`, invokes Verilator `-V` and recursively hashes its runtime `include` files. Build uses C++17, Verilator `--cc --exe --build -j1`, explicit CXX/LINK/AR, and existing300-second build timeout. `git` is also required by source verification and must have an independently reviewed executable/environment even though it is not one of those four compiler toolchain entries.

Freeze exact Python executable/stdlib and any selected external pythonlib files, PATH/wrapper bytes and their real backend paths, Verilator runtime/compiler dependencies, make/ar/git and loader/runtime dependencies needed in that environment. Python source here uses `hashlib.file_digest` and existing project features; use the previously supported Python3.12 environment rather than an unverified system replacement. The inspected direct paths are predominantly stdlib; this inspection does not certify the complete dynamically imported third-party Python closure. No `pip` installation or version command was run. Actual tool probes/imports are part of a separately authorized locked operation, not pure file preparation.

The user reports `/root/fanzehui/myfuzz/project` is local42a9ce9 plus later omitted documents. It cannot be treated as the source containing `d7486c9` or these current hashes without exact comparison/overlay. Inherited environment paths may still select `system-20261016`; source-first imports must point at the new P8 copy, while any deliberately reused external tool/runtime path is separately pinned. No remote path was inspected here.

## Minimal root operation checklist

1. Read new remote README and `agent.md`; select a new P8 staging/project/evidence/cache path under `/root/fanzehui`. Verify canonical outer heavy lock policy and no active native operation. Preserve P7/legacy/system snapshots.
2. Freeze a reviewed local source selection including the scalar script and added roots; resolve the two promisor metadata issues without implicit fetch/identity rewriting. Verify manifests, independent regular files/nlink1, source before/after and **new final whole map after all overlays**. Record profile/lock/closure/header/script hashes above plus actual full source map.
3. Transfer only frozen independent bytes to a new destination; byte-compare full source+Git/tool maps and source-first Python paths. Keep TMPDIR/cache/output outside frozen source. Precreate no misleading measured result. Tool preparation has its own receipt and authorization.
4. Root gives one exact GO for the scalar measurement process with explicit new output/cache and the canonical `--heavy-lock`; the script itself acquires that lock once nonblocking. Do not launch under another held copy of the same lock. Use `PYTHONDONTWRITEBYTECODE=1`, isolated Git global/system config and optional-lock disabling, reviewed external TMPDIR/PATH/PYTHONPATH. No Task2 opcode/driver/Runner changes.
5. Observe the same PID through startup/build/runtime/finalization. Timeout observation does not authorize restart/kill/rerun. Retain `operation.json`, `timing.json`, original compressed scalar document, stdout/stderr, actual process/child lifecycle, build manifests and full before/after source+tool maps. Failed first attempts remain immutable.
6. Independently check original result: complete four cases, no error/source drift/uncertain effects, actual process closure and saved actual PRE/POST samples/ticks. Count callback command calls separately from plan commands/events. Callback excludes the initial owner guard and includes later failed/prewire attempts; no fake wire byte/ACK count or isolated pipe-time claim.
7. Treat timing as cost attribution only: wall includes runtime setup/build/startup/finalization; import measured separately; build and steady state are not separated. Native-only CPU/effective RFuzz search/fresh are unavailable. Schedule ordinary full/failure fresh in a distinct reviewed operation before a correctness grant. Only after measured attribution and root design review consider UART batching.5× and P8 S1c remain open.

## 2026-10-18 实际准备进度补记

ZipCPU metadata attempt2已实际完成（父4100959 exit0，1198个Git子进程均exit0）。只读采集包保存在 `evidence/p8-zipcpu-metadata-attempt2-20261018/actual-remote.tar.gz`，218,999,928 bytes，SHA256 `9a91c2cf3366345527708a7038ba406ea696e427e3f74ea662423382ce2578b5`；大包保留本地与远端原件，不纳入Git。下载回执与独立审计结果分别维护；目前独立对象闭包审计尚未完成，不能只凭控制器exit0授予源码准备完成。首轮因真实tracked symlink拒绝的失败记录保留。

批量对象读取是新的未执行源码草稿，用于减少后续OpenTitan准备进程数量；旧实际控制保持原字节。该准备检查点之后已完成一次项目映射关联与标量运行，见 [S1c 实测报告](p8-s1c-scalar-measurement-attempt1-independent-20261018.md)。此处准备耗时不属于DMA吞吐证据，5×目标仍OPEN。
