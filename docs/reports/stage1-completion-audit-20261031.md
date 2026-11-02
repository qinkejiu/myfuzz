# 阶段一（F1–F4 profile 通用化）全量验收审计 — 2026-10-31

范围：只读审计当前工作树（HEAD `4186ff5` + 917 项未提交改动），只新建本文件；未改其他文件、未 `git reset/clean`、**未跑 RTL**。
支撑：静态代码/配置核对 + 重跑 6 个纯合成测试文件（`105 passed in 29.65s`，与 `extended-bus-adapters-20261031.md` 的 78+27 一致）+ 读取既有运行记录。
判定口径：只有可复核的运行记录才算通过；`observed`、`certified=0` 不升级为 verified。
状态快照：**2026-10-31 01:15**。审计期间存在并行改动（`src/myfuzz/local_harness/vexii_axi_mmio_session.py` 01:08、`src/myfuzz/scenario/target_bus_pins.py` 01:12、`cpu_axi4.py` 增 `SESSION_WRAPPERS`），本文按该快照判定；晚于此时间的改动未计入。

## 0. 状态说明（覆盖本文 01:15 快照判定）

本文是 **2026-10-31 01:15** 的只读审计快照。其后的进展使部分判定失效；**凡与本节冲突处，以本节和[阶段一验收矩阵](stage1-acceptance-matrix-20261031.md)为准**，其余章节保留当时措辞以维持审计可追溯性。

| 本文原判定 | 其后的真实事实 | 现口径 |
|---|---|---|
| 第 1 条“部分”：六组合中 3 个走冻结 request | 三份 SPI config（`spi-picorv32-wb-memory`、`spi-cvw-ahb-memory`、`spi-picorv32-axi-memory`）已改为 `cpu_profile`/`ip_profile`，实测生成 descriptor `flow_ids=[F1,F2,F3,F4]`、`executors` 全为 `compiled_mmio` | **已完成** |
| 第 3 条“部分”：AHB-Lite / AXI4-Lite CPU 无 F1–F4 | 远程镜像落地：`runs/remote-batch22-20261031b/spi-cvw-ahb-memory` 与 `.../spi-picorv32-axi-memory` 各 6 例 F3/F1/F4/F2/F4/F2 + fresh 匹配；本地 `runs/picorv32-axil-axi4lite-uart-20261030` 仍只有 F2/F4，故“AXI4-Lite CPU 只有 F2/F4”的说法只对本地该组合成立 | **已完成** |
| 第 5 条“部分”：fresh 仅远程 | `runs/remote-batch22-20261031b/` 16 组合镜像落地（除 `ahb-sha-target` 1 例外均 6 例，fresh 全 `true`）+ 本地 8 个证据目录 fresh 全匹配 | **已完成** |
| 第 6 条“部分”：报告索引未收录、`_local-*` 未清理 | 本轮收录矩阵与完成报告；`_local-*` 已改名为正式证据名，清理 149 项/681 MB（`runs/RENAMES-20261031.md`） | **部分**（仅剩仓库根目录散落文件与历史 campaign 缓存） |
| §2 VexiiRiscv“否（无运行目录）” | `runs/vexii-f1f4-20261031`：6 例 F1–F4 + fresh `true`（descriptor `configs/scenarios/compiled-f1-f4-axi4-apb-i2c-vexii/`；F3/F1 为 `submitted`，F4 joins=2、F2 joins=1）；F2/F4 另见 `runs/vexii-axi4-apb-i2c-20261031` | 已真实执行 **F1–F4** |
| §3 TL-UL“未通过 / 真实运行被阻断” | `runs/ibex-obi-tlul-gpio-20261031`：6 例 F2/F4 + fresh 通过；根因即本文 §3 已定位的“A 通道 10 个 pin 的 `source_id` 不在依赖图”，已由 `src/myfuzz/scenario/target_bus_pins.py` 入图 + `compiled_mmio` 忽略 pin 值修复 | 已真实通过 **F2/F4** |
| §2 关于 `extended-bus-adapters` §5 把 CVA6 写成“CVW / CVA6 的 RV32 配置 \| AHB-Lite \| 已适配” | 该表当前写作 `CVW（RV32 AHB-Lite 配置）`，不含 CVA6；CVA6 是 RV64/cv64a6（`configs/cpus/cva6/component_profile.json`），与 AHB-Lite 无关 | 已无该表述，无需再改 |
| §2 CVA6“否（无运行目录）/ §4.2 移出阶段一” | CVA6 现已 **F1–F4 6 例 + fresh 通过**（`runs/cva6-f1f4-20261031`，走通用 `compiled_mmio`，`campaign.json` bound adapters = `['apb3.mmio.v1','cva6.axi4.cpu.v1']`）；取指身份在 ARID/RID 上（`instruction_id_map {arid:0,rid:0,granule:8,rsize:3}`），此前 data-only 判定已更正 | **已完成（F1–F4，仅 pinned WT 配置）** |
| §2/§4.2 BOOM“本阶段不可行” | 通用执行器仍未准入，但 Phase A（harness 生成 + 真 RTL lint，exit 0 无 warning，`runs/boom-tl-harness-lint/`，`source_verification=null`）已完成，拒绝点前移为 `component-render-refused` ← 缺源锁；F2/F4 仍由 `directed_standard_runner_router` 各 6 例 + fresh 通过 | 通用准入未通过；Phase A 完成，剩余 Phase B 约 850–1120 行 |
| §3 远程证据只有 `remote-batch22-20261031b` | 同日 15:00 后新增冷缓存复验镜像 `runs/remote-stage1-20261031/`（`ibex-obi-apb-i2c`、`vexii-f1f4`、`vexii-f2f4`、`ibex-obi-tlul-gpio` 均 6+6、fresh 全 `true`）；`_ELABORATION_TIMEOUT_SECONDS` 由 30 调至 300 | 远程证据面扩大（资源预算调整，非放宽正确性检查） |

## 结论（先看这里）

- 按路线图自己的 6 条口径（**01:15 快照的判定**）：2 条已完成（第 2、4），4 条部分（第 1、3、5、6），没有一条被判定为完全未完成，也没有一条可以判定为“全量实现已完成”。后续改判为 **5 条已完成、1 条部分（第 6 条）**，见 §0 与[验收矩阵](stage1-acceptance-matrix-20261031.md)。
- 用户额外要求的六颗 CPU 里，只有 Ibex、CV32E40P、CVW 在通用 F1–F4 路径上真实跑过；其中**只有 Ibex 有本仓库内可复核的六例 + fresh 证据**（以上为 01:15 快照；此后 VexiiRiscv 也有，见 §0）。VexiiRiscv 的适配器在 01:08 才接入（快照时尚未跑；其后 F1–F4 6 例 + fresh 已通过，见 §0）；ZipAXI、CVA6、BOOM 仍未接入；后三者当前是具名拒绝而不是假成功。
- 主要问题不是代码路径断裂，而是三类“证据/措辞”缺口：六组合里 3 个走冻结 request 而非 profile 派生；AHB CPU 与 batch22 的证据只在远程；TL-UL 目标有 adapter 但真实运行被依赖图缺 pin 阻断。**三项都已在 2026-10-31 后续处理中解决（见 §0）**。
- 补齐 §4.1 五项（TL-UL 入图后真跑、Vexii 六例实跑、3 个 descriptor 回归 profile 入口、证据落地、文档纠错）后可把第 1/3/5/6 条转成已完成；CVA6、BOOM、ZipAXI 应明确移出阶段一。**§4.1 五项本轮已完成（Vexii 已 F1–F4 六例 + fresh，见 §0）**。

## 1. 验收 6 条逐条状态

| # | 验收项（`docs/universal-system-roadmap.md:47-52`） | 状态（01:15 快照 → 现） | 主要证据 |
|---|---|---|---|
| 1 | 选定 profile，无组合专用代码，自动生成并跑 F1–F4 | **部分 → 已完成（§0）** | `configs/scenarios/mmio-profile-examples/`、`runs/_local-*`、`src/myfuzz/integration/compiled_mmio.py` |
| 2 | 同一 IP 配 ≥2 种 CPU 总线；同一 CPU 配 ≥2 个同协议 IP | **已完成** | `runs/ibex-obi-apb-i2c-20261030`、`runs/picorv32-wb-apb-i2c-20261030`、`runs/picorv32-wb-apb-spi-20261030`（各 6 例；旧名见 `runs/RENAMES-20261031.md`） |
| 3 | OBI/WB/AHB-Lite/AXI4-Lite CPU 代表组合实跑 F1–F4 | **部分 → 已完成（§0）** | 本地 OBI/WB 有 F1–F4；AHB-Lite/AXI4-Lite 见 §2 与远程镜像 |
| 4 | 每种 IP 侧总线一次独立适配 + ≥1 真实 IP | **已完成（超出口径，文本过期）→ 已完成** | `runs/ibex-obi-apb-i2c-20261030`、`runs/picorv32-wb-wb-uart-20261030`、`runs/picorv32-axil-axi4lite-uart-20261030`、`runs/cvw-ahb-ahb-sha-20261031`、`runs/ibex-obi-tlul-gpio-20261031` |
| 5 | 代表性组合独立新进程 replay | **部分 → 已完成（§0）** | 本地 8 个证据目录 `fresh/replay_matches=true`；`runs/remote-batch22-20261031b/` 16 组合 fresh 全匹配 |
| 6 | 文档给最小字段/示例/范围/缺项/限制；临时产物已清理 | **部分（清理项遗留）** | `docs/profile-onboarding.md` 已更新；本轮收录矩阵/完成报告；`_local-*`、`.tmp-run-x` 已清理 |

**第 1 条当时为什么只是“部分”（历史判定，已被 §0 推翻）。** 路线图称“本批 6 个组合全部由 profile 生成”，快照时只有 3 个走 profile 派生分支（`cpu_profile`/`ip_profile`）：`i2c-ibex-obi-profile`、`i2c-picorv32-wb-profile`、`uart-picorv32-wb`；`spi-picorv32-wb-memory`、`spi-cvw-ahb-memory`、`spi-picorv32-axi-memory` 只用冻结的 `cpu_request`/`ip_request`（`scripts/profile_scenario_inputs.py:23-39` 强制 request 与 profile 二选一）。这些 request 内嵌 `profile_path`，所以组件仍是 profile 锚定的，但**生成器不是从 profile 声明推导场景**，验收措辞被放大。**本轮三份 config 已改为 `cpu_profile`/`ip_profile`，该判定不再成立。** 执行侧无 CPU×IP 分发：`compiled_mmio._target_adapter` 按目标 kind、`select_mmio_cpu` 按 CPU kind 选择（`compiled_mmio.py:27-53`、`mmio_cpu_adapter.py:84-96`）；但 `compiled_mmio.py:268-276` 仍保留 `protocol=='obi' and target_protocol=='apb'` 的旧别名分支（协议对，不是 CPU×IP 对）。

**第 3 条当时为什么只是“部分”（历史判定，已被 §0 推翻）。** 本地仓库只有 `runs/ibex-obi-apb-i2c-20261030`（Ibex OBI）、`runs/picorv32-wb-apb-i2c-20261030`/`runs/picorv32-wb-apb-spi-20261030`/`runs/picorv32-wb-wb-uart-20261030`（PicoRV32 Wishbone）带 F3/F1/F4/F2×2 六例与 fresh；CVW AHB-Lite 的 F1–F4 只在远程快照 `/root/fanzehui/myfuzz-profile-batch22-20261030`，本地仅有中间尝试 `runs/profile-spi-cvw-ahb-native-20261030/generated-original-archived/`，没有完成的 `original|fresh` 六例记录；AXI4-Lite CPU 在 `runs/picorv32-axil-axi4lite-uart-20261030` 只有 F4/F2×3（无 F1/F3 memory flows）。**本轮远程镜像落地后，AHB-Lite 与 AXI4-Lite CPU 均有 6 例全流 + fresh（`runs/remote-batch22-20261031b/spi-cvw-ahb-memory`、`.../spi-picorv32-axi-memory`），该判定不再成立；仅“本地无 prefix/events”这一限制仍有效。**

**第 5 条（现为已完成）。** 本地可复核：`runs/ibex-obi-apb-i2c-20261030`、`runs/picorv32-wb-apb-i2c-20261030`、`runs/picorv32-wb-apb-spi-20261030`、`runs/picorv32-wb-wb-uart-20261030`、`runs/picorv32-axil-axi4lite-uart-20261030`、`runs/ibex-obi-tlul-gpio-20261031`、`runs/vexii-axi4-apb-i2c-20261031` 各 `fresh/summary.json` 为 `replay_matches=true`（6 例）；`runs/cvw-ahb-ahb-sha-20261031` 1 例 F2 fresh 匹配。快照时六组合 + CV32E40P 的 fresh 仅远程；本轮已镜像到 `runs/remote-batch22-20261031b/`（16 组合，只有 `summary/replay/case_sequence`）。

## 2. 六颗 CPU 逐项

| CPU | 协议 | 适配器/会话 | 真实 F1–F4 | fresh | 缺口 |
|---|---|---|---|---|---|
| Ibex | OBI | `select_mmio_cpu('obi_cpu')`→`GeneratedCve2Session` | **是**（`runs/ibex-obi-apb-i2c-20261030` 6 例） | 是 | 退休/RAM 版本 unknown |
| CV32E40P | OBI | 同上（复用 OBI 适配器） | 仅远程 6 例（`runs/remote-batch22-20261031b/cv32e40p`） | 远程 `true` | 本仓库无逐事件记录 |
| CVW | AHB-Lite | `GeneratedAhbMemorySession`，unified channel，64 B 取指粒度 | 远程 6 例（`runs/remote-batch22-20261031b/spi-cvw-ahb-memory`）；另有旧定向门 `cvw-directed-session-20261018.md` | 远程 `true` | F1–F4 无本地 `prefix/events` |
| PicoRV32（补充行，非用户六颗） | Wishbone / AXI4-Lite | `GeneratedWishboneCpuSession` / `select_axi4lite_cpu_protocol` | **是**（WB 3 个 IP 各 6 例；AXI-Lite 本地仅 F2/F4，远程内存流组合有 F1–F4） | 是 | AXI-Lite 的 F1/F3 本地无 `prefix/events`（远程镜像 `runs/remote-batch22-20261031b/spi-picorv32-axi-memory` 有） |
| VexiiRiscv | AXI4（reduced 双通道） | 适配器已**承接**：`cpu_axi4.SESSION_WRAPPERS` → `GeneratedVexiiAxiMmioSession`（240 行，实测 `router=`/online slots/`waiting_instruction_address` 齐全，`AXI4_KIND_GAPS` 已移除该行）；内存流另由 `memory_commit_receipts`/`memory_readback_receipts`/`physical_tick_samples` 补齐（`tests/local_harness/test_vexii_memory_flows.py` 13 passed） | **F1–F4 已通过**（`runs/vexii-f1f4-20261031`，6 例 + fresh；F3/F1 为 `submitted`，F4 joins=2、F2 joins=1；快照时为“否”） | 是 | 无（F1/F3 不产生 join 证书属既有语义，见 `extended-bus-adapters-20261031.md` §5.2） |
| ZipAXI | AXI4（i/d 双全口） | 无每拍 AXI4 观测，`cpu_adapter` 拒绝 | 否 | 否 | 需新 observer（burst/WLAST/ID）+ router/slot/park |
| CVA6 | AXI4（64 位 packed） | `GeneratedCva6Axi4Session` 可复用 `BoundedFullAxiObserver` | 否 | 否 | 无取指/数据通道身份；64 位 beat vs 32 位寄存器；`mmio` vs `memory` 通道 |
| BOOM | TileLink coherent | 无 `compiled_mmio` 生命周期；`extension_plugins.py:24` 把 `boom_cpu` 映到**不存在的** `myfuzz.integration.cpu_tlul`，且真实 kind 是 `tilelink_coherent_cpu`，该映射永不命中 | 否 | 否 | RV64 F1 契约、C++ RAM 提交权威、通用 TL 准入 |

依据：`docs/reports/full-axi4-cpu-f1-f4-feasibility-20261031.md` §结论表、`src/myfuzz/integration/cpu_axi4.py:78-115`（`SESSION_CLASSES`/`SESSION_WRAPPERS`/`AXI4_KIND_GAPS`）、`docs/reports/extended-bus-adapters-20261031.md` §5。**关于 CVA6 与 AHB-Lite：** 快照曾记该 §5 把“CVA6”写进 CVW 的 AHB-Lite 行，此后该表已改写作 `CVW（RV32 AHB-Lite 配置）`，不含 CVA6；CVA6 是 RV64/cv64a6（`configs/cpus/cva6/component_profile.json`），与 AHB-Lite 无关，不应并作“CVW / CVA6 的 RV32 配置”。六颗 CPU 各自有历史 F6/DMA 有界运行（`dma-six-cpu-four-ip-status-20261022.md`），但那不是本阶段 F1–F4，不能并入口径。

## 3. IP 侧五条总线

| IP 总线 | 真实 IP / 寄存器 | 状态 | 证据 | F4 缺口 |
|---|---|---|---|---|
| APB3 | PULP I2C（`profile_only_idle_i2c`）、PULP SPI（`SPICMD`）、PULP Timer（`TIMER0_CTRL`） | **通过** F1–F4 | `runs/ibex-obi-apb-i2c-20261030`、`runs/picorv32-wb-apb-i2c-20261030`、`runs/picorv32-wb-apb-spi-20261030`、`runs/remote-batch22-20261031b/timer-target`/`wbtimer-target` | 无 |
| Wishbone | ZipCPU UART `SETUP`（mask `0x7fffffff`） | **通过** F1–F4 | `runs/picorv32-wb-wb-uart-20261030` | 无 |
| AXI4-Lite | ZipCPU AXI UART `SETUP` | **通过** F2/F4 | `runs/picorv32-axil-axi4lite-uart-20261030` 6 例 + fresh；远程 `runs/remote-batch22-20261031b/axil-uart-target` | 无（`BRESP/RRESP` 恒 OKAY，非 OKAY 只由合成单测覆盖） |
| AHB-Lite | Caliptra SHA `NAME0`（ro 常量 `0x61327368`） | **部分：仅 F2** | `runs/cvw-ahb-ahb-sha-20261031` 1 例 + fresh；远程 `ahb-sha-target` | **有**：profile 无 32 位 rw 寄存器，F4 的写后读回无法闭合 |
| TL-UL | OpenTitan GPIO `INTR_ENABLE`（rw） | **通过 F2/F4**（快照时为“未通过”） | `runs/ibex-obi-tlul-gpio-20261031` 6 例 + fresh；远程 `tlul-gpio-run`、`tlul-gpio-target`；阻断历史 `runs/_local-tlul-gpio/original/failure.json` | 无 F4 缺口；该组合只声明 F2/F4，无 F1/F3 记录 |

TL-UL 阻断根因已定位并**已修复**：与 `extended-bus-adapters-20261031.md:36` 的解释不同，不是“运行时只接受 0 个或 1 个 external pin”（`compiled_f4_runtime_path.py:156-166` 已按多个 pin 循环），而是 **A 通道 10 个 pin 的 `source_id` 不在依赖图里**。快照当时 `runs/_local-tlul-gpio/work/compiled_paths.json` 的 `runtime_dependency_graph.sources` 只有 4 条 `F*.program_image`，故 `pin_leaf is None` → `compiled-F4-runtime-path-unmapped-source`（该 `work/` 已在 2026-10-31 清理中删除，失败的 `runs/_local-tlul-gpio/original/failure.json` 保留）；`mmio_support` 仍报 supported，因为它只看 target/CPU 适配器、不跑 admission。修复方式：`src/myfuzz/scenario/target_bus_pins.py` 把 10 个已声明 pin 入图产生 `external_pin_paths`，同时 `compiled_mmio` 忽略 pin 值（A/D 通道仍由 target session 的 `beat_to_tlul` 驱动），**不是**“多 pin 无法映射”；修复后 6 例 F2/F4 + fresh 真实通过。

## 4. “全量实现”还差什么

### 4.1 阶段一必须（P0）

| 项 | 文件/模块 | 量级 | 完成判据 | 现状 |
|---|---|---|---|---|
| TL-UL 真实运行 | pin 入图模块已交付并接入 admission：`src/myfuzz/scenario/target_bus_pins.py`（217 行，`compiled_f4_runtime_path.py:14` 导入）；仍需编译/构建 + descriptor | 剩编译与运行 | GPIO 的 F2/F4 六例 + fresh；否则写“未支持” | **✓ 已完成**：`runs/ibex-obi-tlul-gpio-20261031` 6 例 + fresh |
| Vexii 真实运行 | wrapper 已交付（240 行，构造契约实测齐全）；descriptor `compiled-f2-f4-axi4-apb-i2c-vexii/` 已存在 | 剩构建与六例运行 | 六例 F1–F4 + fresh | **✓ 已完成**：`runs/vexii-f1f4-20261031` 6 例 F1–F4 + fresh（F2/F4 另见 `runs/vexii-axi4-apb-i2c-20261031`） |
| 3 个 combo 改回 profile 入口 | `configs/scenarios/mmio-profile-examples/spi-{picorv32-wb-memory,cvw-ahb-memory,picorv32-axi-memory}.json` | 各 ~6 行 | `generate_mmio_scenario.py` 走 `cpu_profile`/`ip_profile` 分支 | **✓ 已完成**：生成 descriptor `flow_ids=[F1,F2,F3,F4]`、executor 全 `compiled_mmio` |
| 证据落地 | `runs/<combo>/{original,fresh}/{summary,prefix,events,replay}.json` | 复制/归档 | 第 3、5 条在仓库内可复核 | **✓ 已完成**：本地 9 目录改名保留，远程 16 组合镜像 `runs/remote-batch22-20261031b/` |
| 文档纠错 | `universal-system-roadmap.md:47,50`、`profile-onboarding.md:39`、`extended-bus-adapters:36,43`、`reports/README.md`、`CATALOG.md` | ~10 行 + 3 条索引 | 措辞与代码/运行一致 | **✓ 本轮完成**：另新增验收矩阵与阶段一完成报告 |

### 4.2 可推迟 / 明确移出（P1）

| 项 | 判定 | 理由与量级 |
|---|---|---|
| Vexii（reduced AXI4） | **阶段一必须** | wrapper 与解析层均已交付（`tests/integration/test_cpu_axi4.py`）；**F1–F4 六例 + fresh 已通过**（`runs/vexii-f1f4-20261031`），内存流回执由 `tests/local_harness/test_vexii_memory_flows.py` 覆盖（13 passed） |
| TL-UL 目标 | **阶段一必须（条件式）** | 用户额外要求包含 TL-UL；adapter/单测已就绪，只差 pin 入图。**已入图并 6 例 F2/F4 + fresh 通过** |
| ZipAXI（全 AXI4 i/d） | **推迟到阶段一.5** | 无既有每拍观测，需新写 observer + session 改造，500–700 行 |
| CVA6 | **移出阶段一**（快照；现为 F1–F4 已通过，仅 pinned WT 配置，见 §0） | 快照时判为“单一 packed 口无取指身份”（需 profile 声明取指标志）；实际取指身份在 ARID/RID 上，其后已由 6 个 RTL 锚点现场声明并通过 F1–F4；`retirement`/内部版本仍 unknown |
| BOOM | **移出阶段一**（快照；现为 Phase A 完成、通用准入仍未通过，见 §0） | TileLink coherent 通用准入 + RV64 F1 + RAM 提交权威；原估 900–1500 行，晚近拆为 Phase B 约 850–1120 行（源锁 150–220 + host 播放器/适配器/注册 700–900）；F2/F4 仍只有 directed 基线 |
| AHB SHA 的 F4 | **移出** | 真实 IP 无 rw 寄存器；补 F4 需换 IP 或改 RTL 契约，不得伪造 |
| `compiled_mmio.py:268-276` 旧 OBI×APB 别名与 `native_mmio_hops` 双实现 | 推迟 | 协议对分支，功能正确；合并约 30 行 |

## 5. 文档与清理

- **覆盖情况**：验收 6 条在 `f1-f4-batch-20261030.md`（第 1/2/3/5 条）、`extended-bus-adapters-20261031.md`（第 4 条与 TL-UL/AHB/AXI-Lite 目标）、`profile-onboarding.md`（第 6 条）都有对应描述，但快照时**没有一份文档把六条列成矩阵**，且第 1/4 条文本已过期（见 §1、§3）。**本轮已新增 `stage1-acceptance-matrix-20261031.md`（六条矩阵）与 `stage1-completion-20261031.md`（阶段一完成报告）。**
- **索引缺失（已修）**：快照时 `docs/reports/README.md` 与 `docs/reports/CATALOG.md` 均未收录 `f1-f4-batch-20261030.md`、`extended-bus-adapters-20261031.md`、`full-axi4-cpu-f1-f4-feasibility-20261031.md`；本轮已补齐，并收录新增的矩阵与完成报告。
- **临时产物（已清）**：快照时 `runs/` 共 528 个目录，本阶段新增 `_local-*` 10 个（含 3 个 TL-UL 失败尝试的 `work/`）、`.tmp-run-x/`、`.myfuzz-elaboration-er0uhmyk|rtia1bt_/`、`runs/tmp_fbw2gv7/`、`runs/two-instances-k9w8ajyz/`；本轮清理 149 项/681 MB 并把 9 个证据目录改名为正式名（`runs/RENAMES-20261031.md`），这些临时目录现已不存在。根目录仍有 6 份散落报告（`descriptor-search-report.md` 等）与 `trace_hart_0.dasm` 未归位。
- **工作树**：审计开始 917 项 = 682 未跟踪 + 204 修改 + 32 删除（含 `docs/ALL_TEST_RESULTS_MASTER.md` 等）；01:15 前并行改动又新增 4 项（Vexii wrapper、TL-UL pin 模块与两个 descriptor 目录）。本审计不建议清理，但阶段一收尾前应确认删除项是刻意迁移而非丢失。
- 建议保留 `_local-tlul-*` 的 `failure.json` 作为阻断证据，其余 `cache/`、`work/` 可清；`_local-*` 目录建议改名为有日期与组合名的正式证据名。**本轮已照此执行**：`runs/_local-tlul-gpio`、`runs/_local-tlul-timer` 保留（仅 `failure.json`），其余 9 个目录改为 `runs/<CPU>-<CPU总线>-<IP总线>-<IP>-<日期>/`。

## 6. 不声称

- 本审计（01:15 快照）未运行 RTL/Verilator/native；全部 `passed` 均为合成测试。01:00 快照 `105 passed`（6 文件）；并行改动后重跑 `test_cpu_axi4.py + test_target_tlul.py` 为 `70 passed`，未重跑其余 4 个文件。§0 列出的后续真实运行不属于本审计的执行范围，其证据口径以[验收矩阵](stage1-acceptance-matrix-20261031.md)与各证据目录的 `summary.json`/`replay.json` 为准。
- 所有 `observed` 运行的 `feedback.certified=0`、`storage_reward=0`；退休、RAM 读取版本、跨例来源、IP 内部状态与副作用保持 unknown；DUT 断言未编译。
- 结论只覆盖 §1–§3 列出的实际运行；不推断任意 CPU/IP、地址或时序可自动支持。
