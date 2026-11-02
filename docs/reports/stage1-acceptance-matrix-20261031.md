# 阶段一验收矩阵：F1–F4 profile 通用化（2026-10-31）

范围：逐条对照[路线图](../universal-system-roadmap.md)第一阶段「验收」6 条（`docs/universal-system-roadmap.md:47-52`），给出状态、可复核的本地路径和剩余缺口。本文只改文档口径，不改源码/配置/测试，未跑 RTL。

口径与证据边界：

- 只有可复核的运行记录才算“已完成”。`status=observed`、`feedback.certified=0` 不升级为 verified；退休、RAM 读取版本、跨例来源、IP 内部状态/副作用一律 unknown；DUT 断言未编译（Verilator 无 `--assert`）。
- **本地证据**：`runs/<组合>-<日期>/{original,fresh}/` 内含 `summary.json`、`replay.json`、`prefix.json`、`events.json`、`case_sequence.requested.json`，可逐事件复核。
- **远程证据**：`runs/remote-batch22-20261031b/`（2026-10-31 早批）与 `runs/remote-stage1-20261031/`（同日 15:00 后重跑）是远程快照 `/root/fanzehui/myfuzz-profile-batch22-20261030` 的镜像，**只有** `summary.json`/`replay.json`/`case_sequence.requested.json`；`prefix.json`/`events.json` 仍在远程，故这类引用只支持“结果层面”复核。明细见 `../../runs/REMOTE-EVIDENCE-20261031.md`。
- 目录名均为 2026-10-31 改名后的正式名，旧名（`runs/_local-*`、`runs/_tlul-gpio-full`、`runs/vexii-i2c-20261031`）已不存在；映射见 `../../runs/RENAMES-20261031.md`。

## 1. 验收矩阵

| # | 验收项（roadmap 行号） | 状态 | 证据路径 | 还缺什么 |
|---|---|---|---|---|
| 1 | 选定支持的 CPU/IP profile，无组合专用代码，自动生成并运行 F1、F2、F3、F4（`:47`） | **已完成** | `configs/scenarios/mmio-profile-examples/`（6 主组合；另有 SPI/Timer 追加组合）；生成器 `scripts/generate_mmio_scenario.py`；本轮三个 SPI 组合改为 `cpu_profile`+`ip_profile` 派生，实测 descriptor `flow_ids=[F1,F2,F3,F4]`、`executors` 全为 `compiled_mmio`；运行证据见第 3 条，profile 派生复验 `runs/remote-batch22-20261031b/spiwb2-run`、`spiaxi2-run`、`spi_ahb2-run` | 旧场景仍保留按**协议对**（如 OBI×APB）的 executor 别名（`src/myfuzz/integration/compiled_mmio.py:268-276`），属协议对分支、不是 CPU×IP 分支；生成的 descriptor 落在 `runs/` 未入库；不外推任意 CPU/IP |
| 2 | 同一个 IP profile 配至少两种不同 CPU 总线；同一个 CPU profile 配至少两个同协议 IP（`:48`） | **已完成** | 同一 IP profile `configs/peripherals/profile_only_idle_i2c/component_profile.json` 同时被 `i2c-ibex-obi-profile.json`（Ibex OBI，`runs/ibex-obi-apb-i2c-20261030`）与 `i2c-picorv32-wb-profile.json`（PicoRV32 WB，`runs/picorv32-wb-apb-i2c-20261030`）引用，各 6 例 + fresh 匹配；同一 CPU profile `configs/cpus/picorv32_wb/component_profile.json` 配 APB I2C（`runs/picorv32-wb-apb-i2c-20261030`）、APB SPI（`runs/picorv32-wb-apb-spi-20261030`）、Wishbone UART（`runs/picorv32-wb-wb-uart-20261030`） | 只证明这 3 个 IP 组合；另提示同一 CPU 的第三个 APB IP（Timer）走 `timer-picorv32-wb-memory`，其配置仍是冻结 `cpu_request`/`ip_request`（远程 `wbtimer-target` 6 例通过），属第 1 条的 profile 派生面，不影响本条判据 |
| 3 | OBI、Wishbone、AHB-Lite、AXI4-Lite CPU 的首批代表组合均实际执行 F1–F4（`:49`） | **已完成** | 见 §2 逐协议表：OBI（本地）、Wishbone（本地）、AHB-Lite（远程镜像）、AXI4-Lite（远程镜像）均有 6 例 F3/F1/F4/F2/F4/F2 + fresh 匹配；另有 **AXI4 full 的 VexiiRiscv** 也完成 6 例 F1–F4 + fresh（`runs/vexii-f1f4-20261031`），超出本条要求的四条总线 | CVW 与 AXI4-Lite CPU 的 F1–F4 只有远程 `summary/replay`，本地无 `prefix/events`；退休、RAM 读取版本、跨例来源 unknown |
| 4 | 每种纳入本阶段的 IP 侧总线有一次独立适配和至少一个真实 IP 验证（`:50`） | **已完成** | 见 §3 逐总线表：APB3（PULP I2C/SPI/Timer）、Wishbone（ZipCPU UART）、AXI4-Lite（ZipCPU AXI UART）、AHB-Lite（Caliptra SHA）、TL-UL（OpenTitan GPIO）各有一次独立适配 + 真实 IP 运行 | AHB-Lite 只有 F2（该 IP 无 32 位 rw 寄存器，1 例）；TL-UL 只有 F2/F4（descriptor 仅声明 `flow_ids=['F2','F4']`）；IP 侧完整 AXI4 目标不存在 |
| 5 | 至少对代表性组合做一次独立新进程 replay（`:51`） | **已完成** | 本地 `compiled_mmio` 证据目录 11 个 fresh 全匹配（10 个 6 例，含 Vexii F1–F4 `runs/vexii-f1f4-20261031`、CVA6 F1–F4 `runs/cva6-f1f4-20261031`、CVA6 F2/F4 `runs/cva6-f2f4-20261031`；`runs/cvw-ahb-ahb-sha-20261031` 1 例）；BOOM 的 F2/F4（directed runner）各有 `fresh/compare.json` `matches=true`；远程镜像 16 组合 + `runs/remote-stage1-20261031/` 4 组合 fresh 全 `true`（除 `ahb-sha-target` 1 例外均 6 例），见 `../../runs/REMOTE-EVIDENCE-20261031.md` §3 | 重放复用同一构建缓存，不等于独立重编译；远程镜像无 `prefix/events`，逐事件比对须回远程快照；`runs/ibex-obi-tlul-gpio-f2f4-20261031` 是 2 例子集且无 fresh，不计入 |
| 6 | 文档给出 profile 最小字段、可运行示例、支持范围、常见缺项和限制；本批临时产物已清理（`:52`） | **部分** | [profile 接入说明](../profile-onboarding.md)（最小字段、示例命令、执行范围、unknown 边界）；本轮新增[本矩阵](stage1-acceptance-matrix-20261031.md)与[阶段一完成报告](stage1-completion-20261031.md)；清理与改名记录 `../../runs/RENAMES-20261031.md`（149 项、681 MB、9 个证据目录改名） | ① 仓库根目录仍有 6 份散落报告（`descriptor-search-report.md` 等）与 `trace_hart_0.dasm` 未归位；②`runs/_local-tlul-gpio`、`runs/_local-tlul-timer` 按审计要求保留为阻断证据（仅 `failure.json`）且名称未改；③`runs/` 清理后仍约 64.8 GB，主要是历史 campaign 缓存（如 `runs/config-driven-20261028` 约 23 GB），不属本批但未清理 |

状态汇总：**5 条已完成（第 1–5 条）、1 条部分（第 6 条，只差清理项）**。

## 1.1 六 CPU 的扩展进展（2026-10-31 同日后续）

| CPU | 执行器准入 | 已执行流 | 证据 | 说明 |
|---|---|---|---|---|
| Ibex / CVW / CV32E40P / PicoRV32 | `compiled_mmio` | F1–F4 | 见 §2 | 6+6，fresh 匹配 |
| VexiiRiscv | `compiled_mmio` | F1–F4 | `runs/vexii-f1f4-20261031` | 6+6；31.6 / 35.92 s；F3/F1 `submitted` |
| CVA6 | `compiled_mmio` | **F1–F4** | `runs/cva6-f1f4-20261031`；descriptor `configs/scenarios/compiled-f1-f4-axi4-apb-i2c-cva6/` | 6+6；117.09 / 106.63 s，fresh `matches=true`；`campaign.json` bound adapters = `['apb3.mmio.v1','cva6.axi4.cpu.v1']`；F3 `memory_store=observed`、F1 `memory_read=observed`，F4 joins=2 / hops=6、F2 joins=1 / hops=6（取指身份 = ARID/RID 声明，`instruction_id_map {arid:0,rid:0,granule:8,rsize:3}`） |
| BOOM | **未准入** `compiled_mmio`（Phase A 已完成） | F2/F4（`directed_standard_runner_router`，`compiled_mmio_admitted=false`） | `runs/boom-f2-20261031`、`runs/boom-f4-20261031`；拒绝证据 `runs/boom-refusal-20261031/refusal.json`；Phase A lint `runs/boom-tl-harness-lint/` | 各 6 例 + fresh `compare.json` 匹配；F2/F4 fresh `total_wall_seconds` 21.42 / 21.00 s（`wall_seconds` 21.83 / 21.48）；Phase A harness `verilator --lint-only` exit 0 无 warning，但 `source_verification=null`、拒绝点前移到 `component-render-refused`（`local-source-lock-missing-component:boom`） |
| ZipAXI | 未准入 | 无 | — | 需新写 AXI4 observer（burst/`WLAST`/ID）+ router/slot/park |

CVA6 的取指身份来自 AXI ID（此前“user/prot 钉 0 ⇒ 无法取指”的说法已更正：user/prot 确实钉 0，但身份在 ID 上）：`wt_axi_adapter.sv:116/159/597/638`（`arb_req={dcache…,icache…}`、`id_in=arb_idx`、`rid==0→I$`、`rid[0]→D$`）+ `cv64a6_imafdc_sv39_config_pkg.sv:32/:72`（AxiIdWidth=4、DcacheType=WT）⇒ `instruction_id_map {arid:0, rid:0, granule:8, rsize:3}`，由 `cva6_axi_mmio.py::cva6_instruction_identity()` 现场重读这 6 个锚点才声明，任一缺失退回 data-only refusal。hop 每例 6 granule / 12 拍 / 12 字，例：granule `0x10038` → `b700004093800000`，两字 `b7000040`/`93800000` 4/4 匹配，事件 `AR 2438 → memory_read 2663 → R 2696`。BOOM 的 Phase A 只做 harness 生成 + 真 RTL lint（`runs/boom-tl-harness-lint/`，`verilator --lint-only` exit 0 无 warning、518 modules / 36.9 MB / 20.88 s），artifact `source_verification=null`；拒绝点由 `protocol-shape-not-admitted` 前移到 `component-render-refused at /processor/request` ← `local-source-lock-missing-component:boom`，**仍未准入**。

## 2. 第 3 条逐协议证据

| CPU 侧总线 | CPU | 组合 / 证据 | 流序列 | 例数 | fresh |
|---|---|---|---|---|---:|
| OBI | Ibex | `runs/ibex-obi-apb-i2c-20261030` | F3/F1/F4/F2/F4/F2 | 6+6 | `true` |
| OBI | CV32E40P | `runs/remote-batch22-20261031b/cv32e40p` | F3/F1/F4/F2/F4/F2 | 6+6 | `true` |
| Wishbone | PicoRV32 | `runs/picorv32-wb-apb-i2c-20261030`、`runs/picorv32-wb-apb-spi-20261030`、`runs/picorv32-wb-wb-uart-20261030` | F3/F1/F4/F2/F4/F2 | 6+6 ×3 | `true` |
| AHB-Lite | CVW | `runs/remote-batch22-20261031b/spi-cvw-ahb-memory`（另有 `spi_ahb2-run` 同场景复跑） | F3/F1/F4/F2/F4/F2 | 6+6 | `true` |
| AXI4-Lite | PicoRV32 AXI | `runs/remote-batch22-20261031b/spi-picorv32-axi-memory`（另有 `spiaxi2-run` 同场景复跑） | F3/F1/F4/F2/F4/F2 | 6+6 | `true` |
| AXI4-Lite（本地补充） | PicoRV32 AXI | `runs/picorv32-axil-axi4lite-uart-20261030` | **仅 F4/F2×3** | 6+6 | `true` |
| AXI4 full（超出第 3 条的四条总线，补充证据） | VexiiRiscv | `runs/vexii-f1f4-20261031`（descriptor `configs/scenarios/compiled-f1-f4-axi4-apb-i2c-vexii/`） | F3/F1/F4/F2/F4/F2 | 6+6 | `true` |
| AXI4 full（补充：CVA6，走通用 `compiled_mmio`） | CVA6 | `runs/cva6-f1f4-20261031`（descriptor `configs/scenarios/compiled-f1-f4-axi4-apb-i2c-cva6/`；F2/F4 另见 `runs/cva6-f2f4-20261031`） | F3/F1/F4/F2/F4/F2 | 6+6 | `true` |
| TileLink coherent（补充：BOOM，非通用执行器） | BOOM | `runs/boom-f2-20261031`、`runs/boom-f4-20261031` | F2×6 与 F4×6 两次独立运行 | 6+6（每流） | `true`（`compare.json`） |

注意本地补充行：`runs/picorv32-axil-axi4lite-uart-20261030` 的 descriptor `configs/scenarios/compiled-f2-f4-axil-axiluart-picorv32/` 只声明 `flow_ids=['F2','F4']`，因此该目录**不能**作为 AXI4-Lite CPU 的 F1/F3 证据；AXI4-Lite CPU 的 F1/F3 由远程镜像 `spi-picorv32-axi-memory`（内存流组合）提供。

VexiiRiscv 行是同一条 `compiled_mmio` 执行器下的 AXI4 full 补充证据：F3/F1 的证书状态为 `submitted`（以提交记录 + 内存事件为证据，与 Ibex 基线 `runs/ibex-obi-apb-i2c-20261030` 完全相同），F4 joins=2、F2 joins=1；事件层 `instruction_source` 6、`memory_read` 61、`memory_write` 5、`mmio_delivery`/`mmio_acceptance` 各 6。

CVA6 与 BOOM 的行**不进入第 3 条判据**（该条只要求 OBI/WB/AHB-Lite/AXI4-Lite 四条总线）：CVA6 与 Vexii 一样走通用 `compiled_mmio`，但属 AXI4 full；BOOM 走 `directed_standard_runner_router`（`compiled_mmio_admitted=false`），不能与 `compiled_mmio` 组合并列。

## 3. 第 4 条逐总线证据

| IP 侧总线 | 真实 IP / 寄存器 | 已执行流 | 证据目录 | 例数 | fresh |
|---|---|---|---|---|---:|
| APB3 | PULP I2C `PRESCALER`（rw） | F1–F4 | `runs/ibex-obi-apb-i2c-20261030`、`runs/picorv32-wb-apb-i2c-20261030` | 6+6 ×2 | `true` |
| APB3 | PULP SPI `SPICMD`（rw） | F1–F4 | `runs/picorv32-wb-apb-spi-20261030`、`runs/remote-batch22-20261031b/spi-cvw-ahb-memory` | 6+6 ×2 | `true` |
| APB3 | PULP Timer `TIMER0_CTRL`（rw） | F1–F4 | `runs/remote-batch22-20261031b/timer-target`、`wbtimer-target` | 6+6 ×2 | `true` |
| Wishbone | ZipCPU UART `SETUP`（mask `0x7fffffff`，`full_word_reserved_zero`） | F1–F4 | `runs/picorv32-wb-wb-uart-20261030` | 6+6 | `true` |
| AXI4-Lite | ZipCPU AXI UART `SETUP`（rw） | F2/F4 | `runs/picorv32-axil-axi4lite-uart-20261030`、`runs/remote-batch22-20261031b/axil-uart-target` | 6+6 ×2 | `true` |
| AHB-Lite | Caliptra SHA256 `NAME0`（ro 常量 `0x61327368`） | **仅 F2** | `runs/cvw-ahb-ahb-sha-20261031`、`runs/remote-batch22-20261031b/ahb-sha-target` | **1+1** | `true` |
| TL-UL | OpenTitan GPIO `INTR_ENABLE`（rw，`0x40000000`，128 B） | F2/F4 | `runs/ibex-obi-tlul-gpio-20261031`、`runs/remote-batch22-20261031b/tlul-gpio-run`、`tlul-gpio-target` | 6+6 ×3 | `true` |

TL-UL 的 F4 候选 layout 为 **18 字节**（4 字节寄存器流 + A 通道 10 个已声明 pin 的 109 bit fuzzable 切片，共 141 bit），`compiled_mmio` 忽略 pin 值，A/D 通道由 target session 的 `write_register/read_register` 经 `beat_to_tlul` 内部驱动；pin 入图由 `src/myfuzz/scenario/target_bus_pins.py` 提供。根因不是“多 pin 无法映射”，而是这 10 个 pin 的 `source_id` 原先不在依赖图，详见[TL-UL 真实运行记录](tlul-f2f4-real-run-20261031.md)与[扩展总线适配](extended-bus-adapters-20261031.md) §4。

## 4. 与 01:15 审计快照的差异

`stage1-completion-audit-20261031.md` 的判定是 **2 条已完成（第 2、4 条）、4 条部分（第 1、3、5、6 条）**。本矩阵在其后的事实基础上改判：

| 审计快照的判定 | 改判依据 | 现状态 |
|---|---|---|
| 第 1 条“部分”：六组合中 3 个走冻结 request | 三份 SPI config 本轮改为 `cpu_profile`/`ip_profile`，实测生成 descriptor `flow_ids=[F1,F2,F3,F4]`、executor 均为 `compiled_mmio` | 已完成 |
| 第 3 条“部分”：AHB-Lite、AXI4-Lite CPU 无本地 F1–F4 | 远程镜像落地（`spi-cvw-ahb-memory`、`spi-picorv32-axi-memory` 均 6 例全流 + fresh）；此前的“AXI4-Lite CPU 只有 F2/F4”只对本地 `axil-axiluart` 组合成立 | 已完成 |
| 第 5 条“部分”：六组合 fresh 仅远程 | `runs/remote-batch22-20261031b/` 镜像落地（16 组合 fresh 全 `true`）+ 本地 11 目录 fresh 匹配（含 Vexii/CVA6 的 F1–F4） | 已完成 |
| 第 6 条“部分”：报告索引未收录、`_local-*` 未清理 | 本轮收录矩阵与完成报告；`_local-*` 已改名为正式证据名并清理 149 项/681 MB | 部分（仅剩清理项） |
| 第 4 条中 TL-UL“未通过” | TL-UL 目标 6 例 F2/F4 + fresh 真实通过 | 不影响第 4 条结论，改为“已通过” |
| §2 Vexii“无运行目录 / 否” | Vexii 现已 F1–F4 6 例 + fresh 通过（`runs/vexii-f1f4-20261031`；F2/F4 另见 `runs/vexii-axi4-apb-i2c-20261031`） | 已真实执行 F1–F4 |
| §4.2 CVA6“移出阶段一 / 本阶段不可行” | CVA6 现已 **F1–F4 6 例 + fresh 通过**（`runs/cva6-f1f4-20261031`，走通用 `compiled_mmio`）；此前 data-only 的判定基于“user/prot 钉 0”，实际取指身份在 ARID/RID 上、已由 6 个 RTL 锚点现场声明 | **已完成（F1–F4，仅 pinned WT 配置）** |
| §2/§4.2 BOOM“本阶段不可行” | 通用执行器仍未准入，但拒绝点已前移（`component-render-refused` ← 缺源锁）；Phase A harness 生成 + 真 RTL lint 完成（exit 0 无 warning，`source_verification=null`）；F2/F4 仍由 `directed_standard_runner_router` 各 6 例 + fresh 通过 | 通用准入未通过；Phase A 完成，剩余 Phase B 约 850–1120 行 |

## 5. 不声称

- 不声称 DUT 内部正确性、断言通过或覆盖率结论；Verilator 未编译 `--assert`。
- 不声称退休、RAM 读取版本、跨例来源、IP 内部状态/副作用；所有运行 `feedback.certified=0`、`storage_reward=0`。
- 不声称任意 CPU/IP 可自动支持；profile 只是接入前提，取指/复位/协议特性仍需真实声明与真实运行。
- 不声称 CVA6 的取指 hop 可外推：它只对当前 pinned WT 配置（ARID/RID 声明，`arid/rid=0`）成立；AMO 的 `ar.id[1]` 不作取指 hop；48 字节片段第 9–12 字无权威快照（`not-in-declared-window`）；`retirement`/内部存储版本/跨例来源仍 unknown。
- 不声称 BOOM 已准入：Phase A 只是生成 + lint（`source_verification=null`），`compiled_mmio_admitted=false`，F2/F4 是 `directed_standard_runner_router` 的有向运行。
- 不声称第 6 条的清理面已完成；遗留项见 §1 第 6 行。
