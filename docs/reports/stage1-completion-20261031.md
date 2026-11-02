# 阶段一（F1–F4 profile 通用化）完成报告（2026-10-31）

范围：CPU 和普通 MMIO IP 各自提供 profile，由框架按已支持协议自动装配并在同一会话执行 F1–F4，不为 CPU×IP 组合新增代码。本文只写可复核的真实运行结果；不判定 DUT 内部正确性（Verilator 未编译 `--assert`）。逐条验收状态见[阶段一验收矩阵](stage1-acceptance-matrix-20261031.md)。

## 结论

- 路线图 6 条验收：**5 条已完成（第 1–5 条）、1 条部分（第 6 条，只差清理项）**。
- 三个原先“冻结 request”的 SPI 组合已改为 profile 派生，**6 个主组合全部由 `cpu_profile`/`ip_profile` 推导场景**，执行器统一为 `compiled_mmio`。
- 六颗目标 CPU 中 **6 颗都有真实结果**：Ibex、CVW、CV32E40P、VexiiRiscv、**CVA6** 跑过 F1–F4（CVA6 走通用 `compiled_mmio`，取指身份由 ARID/RID 声明）；**BOOM 通用执行器仍未准入**，但 F2/F4 有 `directed_standard_runner_router` 各 6 例 + fresh 证据，且 Phase A（harness 生成 + 真 RTL lint）已完成。ZipAXI 仍移出。
- IP 侧五条总线（APB3、Wishbone、AXI4-Lite、AHB-Lite、TL-UL）各有一次独立适配 + 至少一个真实 IP 运行，全部 `fresh replay` 匹配。

## 1. 目标与范围

| 项 | 内容 |
|---|---|
| 数据流 | F1 取指/执行、F2 总线读 IP/RAM、F3 总线写 RAM、F4 MMIO 写外设 |
| 总线（CPU 侧） | OBI、Wishbone、AHB-Lite、AXI4-Lite（各一次适配）；另有 AXI4 full 原型：VexiiRiscv 受限双通道、CVA6 64 位 packed（均 F1–F4 已通过） |
| 总线（IP 侧） | APB3、Wishbone、AXI4-Lite、AHB-Lite、TL-UL（各一次适配） |
| 不在范围 | F5/F6、覆盖率工具对比、BOOM 的通用执行器准入（Phase B）、ZipAXI 的完整 AXI4 i/d、断言插入 |

## 2. 六颗目标 CPU 的真实结果

| CPU | CPU 侧总线 | 本阶段真实执行 | 证据（可复核） | 例数 | fresh |
|---|---|---|---|---:|---|
| Ibex | OBI | F1–F4 | `runs/ibex-obi-apb-i2c-20261030` | 6+6 | `true` |
| CVW（CORE-V Wally） | AHB-Lite | F1–F4 | `runs/remote-batch22-20261031b/spi-cvw-ahb-memory`（另有 `spi_ahb2-run`） | 6+6 | `true` |
| CV32E40P | OBI | F1–F4 | `runs/remote-batch22-20261031b/cv32e40p` | 6+6 | `true` |
| VexiiRiscv | AXI4（受限双通道 AXI 主端口） | F1–F4 | `runs/vexii-f1f4-20261031`（F1–F4；F2/F4 另见 `runs/vexii-axi4-apb-i2c-20261031`） | 6+6 | `true` |
| CVA6 | AXI4（64 位 packed） | F1–F4 | `runs/cva6-f1f4-20261031`（descriptor `configs/scenarios/compiled-f1-f4-axi4-apb-i2c-cva6/`；F2/F4 另见 `runs/cva6-f2f4-20261031`） | 6+6 | `true` |
| BOOM | TileLink coherent | **F2/F4（directed runner，非通用执行器）** | `runs/boom-f2-20261031`、`runs/boom-f4-20261031`；拒绝证据 `runs/boom-refusal-20261031/refusal.json`；Phase A harness lint `runs/boom-tl-harness-lint/` | 6+6（每流） | `true`（`compare.json`） |

补充（不属于六颗目标 CPU，但是本阶段 profile 示例的主 CPU）：PicoRV32 Wishbone 有 3 个 IP 的 F1–F4（`runs/picorv32-wb-apb-i2c-20261030`、`runs/picorv32-wb-apb-spi-20261030`、`runs/picorv32-wb-wb-uart-20261030`），PicoRV32 AXI4-Lite 的 F1–F4 见 `runs/remote-batch22-20261031b/spi-picorv32-axi-memory`，本地 `runs/picorv32-axil-axi4lite-uart-20261030` 只有 F2/F4。

CVW 与 AXI4-Lite CPU 的 F1–F4 证据是远程镜像（只有 `summary/replay/case_sequence`，`prefix/events` 仍在远程快照）；其余本地目录可逐事件复核。VexiiRiscv 的 **F1–F4 已在本机真实通过**（`runs/vexii-f1f4-20261031`，6 例 + fresh；F3/F1 为 `submitted`，F4 joins=2、F2 joins=1），见[扩展总线适配](extended-bus-adapters-20261031.md) §5.2。

CVA6 与 BOOM 的口径：

- **CVA6（`cva6_packed_axi4_cpu`）**：**F1–F4 已真实通过**，且确实走通用 `compiled_mmio`：`runs/cva6-f1f4-20261031` 6 例 original 117.09 s + 6 例 fresh 106.63 s、`replay_matches=true`、`first_difference=null`；descriptor `configs/scenarios/compiled-f1-f4-axi4-apb-i2c-cva6/`（`flow_ids=[F1,F2,F3,F4]`）；`original/campaign.json` 的 bound adapters 为 `['apb3.mmio.v1','cva6.axi4.cpu.v1']`。逐例：F3 `memory_store=observed`（5 条 `memory_write_commit`，`channel=memory`、width 4、be 15）、F1 `memory_read=observed`；F4 joins=2 / hops=6，F2 joins=1 / hops=6。本轮 6 例序列执行两对写读（0x55、0xaa），`read_value` 85/170、`result=read^0x5a5`；descriptor 另声明 0x1234 一对，未在本轮 6 例中执行。
- **取指身份 = ARID/RID 声明**（更正此前“user/prot 钉 0 ⇒ 无法取指”的说法：user/prot 确实钉 0，但身份在 AXI ID 上）：`wt_axi_adapter.sv:116/159/597/638`（`arb_req={dcache…,icache…}`、`id_in=arb_idx`、`rid==0→I$`、`rid[0]→D$`）+ `cv64a6_imafdc_sv39_config_pkg.sv:32/:72`（AxiIdWidth=4、DcacheType=WT）⇒ `instruction_id_map {arid:0, rid:0, granule:8, rsize:3}`；由 `cva6_axi_mmio.py::cva6_instruction_identity()` 现场重读这 6 个锚点才声明，任一缺失退回 data-only refusal（无默认打开）。hop 结构：每例 6 granule / 12 拍 / 12 字，每 hop 有 `granule_address`、`fetched_hex`（真实 8 字节）、`acceptance_event`/`response_event`/`memory_read_event`、`native_beats[]`、`instruction_words[2]`（`source_word_hex`/`fetched_word_hex`/4 字节 `bytes_match`/`authoritative_snapshot`）；例：granule `0x10038` 读到 `b700004093800000`，两字 `b7000040`、`93800000` 4/4 匹配，事件 `AR 2438 → memory_read 2663 → R 2696`。
- **CVA6 边界**：只对本 pinned WT 配置成立，不外推到所有 AXI/所有 CVA6；AMO 的 `ar.id[1]` 永不作取指 hop；`retirement`、DUT 内部存储版本、跨例来源仍 unknown；48 字节片段第 9–12 字无权威快照（`authoritative_snapshot: not-in-declared-window`）；composition SoC 面的 `src/myfuzz/runtime/adapters/cva6_axi4_cpu.py` 仍只发 refusal，未扩展。为跑通 RV64 做的小改（带注释）：`isa/constraints.py`、`scenario/memory.py`、`runtime/flows/memory.py`（F3 store 源宽度接受 64 位口，实测仍 4 字节存储）、`scenario/runner.py`；另修 `cpu_axi4._parse_adapter` 位置参数 bug（否则 vexii 行会被误开 F1/F3）。测试：`tests/integration/test_cva6_fetch_identity_hops.py` 8 passed，相关批 270 passed + 57 subtests。
- **BOOM（`tilelink_coherent_cpu`）**：通用 `compiled_mmio` 仍未打通。Phase A（harness 半）已完成：`src/myfuzz/protocols/rtl/tl_coherent_memory_adapter.sv`(468，A/B/C/D/E 从端 + 8 字节 backend beat，不支持者 `fault_o` 不伪装成功)、`template_contracts.py` +133/−5 增加 39-role `('tilelink-coherent','1')` 契约、`runtime_renderer.py` +120/−1、`driver_renderer.py` +45/−1（`STEP_TL_COHERENT`）、`local_harness/tilelink_coherent_fields.py`(93)、`tests/local_harness/test_tilelink_coherent_contract.py`(188, 9 passed)。真 RTL lint：`verilator --lint-only` **exit 0 无 warning**（518 modules / 36.9 MB / 20.88 s），产物 `runs/boom-tl-harness-lint/`；该 artifact `source_verification=null`（缺源锁），**不声称已准入**。拒绝点已前移：`protocol-shape-not-admitted` → `component-render-refused at /processor/request` ← `local-source-lock-missing-component:boom`（`local_harness/source_lock.py:164`）。剩余 Phase B：①`verify_soc_sources.py` 复用 stored 端口证据 + BOOM 进 `sources.lock.json`（约 150–220 行）；②host 播放器 + `cpu_tlul` 适配器 + `tilelink.cpu.v1` 注册（约 700–900 行）；之后才是 12 例真跑与 fresh。**F2/F4 仍只有 directed 基线，通用路径未通过。**

## 3. IP 侧五条总线的真实结果

| IP 侧总线 | 真实 IP / 寄存器 | 已执行流 | 证据 | 例数 | fresh |
|---|---|---|---|---|---:|
| APB3 | PULP I2C `PRESCALER`、PULP SPI `SPICMD`、PULP Timer `TIMER0_CTRL` | F1–F4 | `runs/ibex-obi-apb-i2c-20261030`、`runs/picorv32-wb-apb-spi-20261030`、`runs/remote-batch22-20261031b/timer-target` 与 `wbtimer-target` | 6+6 ×4 | `true` |
| Wishbone | ZipCPU UART `SETUP`（mask `0x7fffffff`、`full_word_reserved_zero`） | F1–F4 | `runs/picorv32-wb-wb-uart-20261030` | 6+6 | `true` |
| AXI4-Lite | ZipCPU AXI UART `SETUP`（rw） | F2/F4 | `runs/picorv32-axil-axi4lite-uart-20261030`、`runs/remote-batch22-20261031b/axil-uart-target` | 6+6 ×2 | `true` |
| AHB-Lite | Caliptra SHA256 `NAME0`（ro 常量 `0x61327368`） | **仅 F2**（无 32 位 rw 寄存器，F4 不存在） | `runs/cvw-ahb-ahb-sha-20261031`、`runs/remote-batch22-20261031b/ahb-sha-target` | **1+1** | `true` |
| TL-UL | OpenTitan GPIO `INTR_ENABLE`（rw） | F2/F4 | `runs/ibex-obi-tlul-gpio-20261031`、`runs/remote-batch22-20261031b/tlul-gpio-run`、`tlul-gpio-target` | 6+6 ×3 | `true` |

TL-UL 的 F4 候选 layout 为 **18 字节**（4 字节寄存器流 + A 通道 10 个已声明 pin 的 109 bit fuzzable 切片，共 141 bit），A/D 通道由 target session 内部 `beat_to_tlul` 驱动，`compiled_mmio` 忽略 pin 值。此前“TL-UL 真实运行被阻断”的根因是这 10 个 pin 的 `source_id` 不在依赖图；修复为 `src/myfuzz/scenario/target_bus_pins.py` 入图 + admission 生成 `external_pin_paths`，**不是**“多 pin 无法映射”。`runs/ibex-obi-tlul-gpio-f2f4-20261031` 是 2 例早期子集且无 fresh，引用完整结论时请用 `runs/ibex-obi-tlul-gpio-20261031`。

## 4. profile 派生与“无 CPU×IP 组合代码”的证据

1. **场景由 profile 推导**：主组合配置在 `configs/scenarios/mmio-profile-examples/`，入口 `scripts/generate_mmio_scenario.py`。本轮把 `spi-picorv32-wb-memory.json`、`spi-cvw-ahb-memory.json`、`spi-picorv32-axi-memory.json` 从冻结 `cpu_request`/`ip_request` 改为 `cpu_profile`/`ip_profile`，实测生成成功：descriptor `flow_ids=[F1,F2,F3,F4]`、`executors` 全为 `compiled_mmio`。至此 6 个主组合全部 profile 派生。
2. **同一 IP profile 配两种 CPU 总线**：`configs/peripherals/profile_only_idle_i2c/component_profile.json` 同时被 Ibex OBI 与 PicoRV32 WB 两份 config 引用，两者各跑 6 例 F1–F4。
3. **同一 CPU profile 配多个同协议 IP**：`configs/cpus/picorv32_wb/component_profile.json` 配 APB I2C、APB SPI、Wishbone UART 三个真实 IP。
4. **执行侧按协议/kind 选择，不按组合**：目标适配器按目标 artifact kind 选择（`compiled_mmio._target_adapter`、`extension_plugins.target_adapter`），CPU 适配器按 CPU kind 选择（`mmio_cpu_adapter.select_mmio_cpu`，第 70 行起）；`compiled_mmio.py:268-276` 只有 `obi`/`apb` **协议对**分支，不是 CPU×IP 分支。
5. **profile 派生与冻结 request 结果一致**：远程同快照复验 `spiwb2-run`、`spiaxi2-run`、`spi_ahb2-run` 各 6 例 + fresh 匹配，与早先冻结 request 的运行数字同量级（见[批量结果](f1-f4-batch-20261030.md) 第 10–12 项、`../../runs/REMOTE-EVIDENCE-20261031.md` §3）。

## 5. 性能数字（wall 时间，含进程启动/编译耗时）

本机（真实 RTL；`compiled_mmio` 用 `--execution-mode search`，BOOM 两行为 directed runner）：

| 证据目录 | 例数 | original (s) | fresh (s) |
|---|---:|---:|---:|
| `runs/ibex-obi-apb-i2c-20261030` | 6 | 43.60 | 45.95 |
| `runs/picorv32-wb-apb-i2c-20261030` | 6 | 27.65 | 27.26 |
| `runs/picorv32-wb-apb-spi-20261030` | 6 | 31.11 | 35.79 |
| `runs/picorv32-wb-wb-uart-20261030` | 6 | 30.15 | 26.76 |
| `runs/picorv32-axil-axi4lite-uart-20261030` | 6 | 29.49 | 30.29 |
| `runs/cvw-ahb-ahb-sha-20261031` | 1 | 30.32 | 30.29 |
| `runs/ibex-obi-tlul-gpio-20261031` | 6 | 48.51 | 48.58 |
| `runs/vexii-axi4-apb-i2c-20261031` | 6 | 33.65 | 36.98 |
| `runs/vexii-f1f4-20261031` | 6 | 31.60 | 35.92 |
| `runs/cva6-f2f4-20261031`（F2/F4） | 6 | 102.1 | 95.4 |
| `runs/cva6-f1f4-20261031`（F1–F4） | 6 | 117.09 | 106.63 |
| `runs/boom-f2-20261031`（directed，F2） | 6 | 30.78 | 21.83 |
| `runs/boom-f4-20261031`（directed，F4） | 6 | 28.25 | 21.48 |

BOOM 的 summary 另记 `total_wall_seconds`（F2 29.95 / 21.42 s、F4 26.60 / 21.00 s），与上表 `wall_seconds` 同一次运行的不同统计口径。

远程快照（`/root/fanzehui/myfuzz-profile-batch22-20261030`，16 个组合）：original 49.1–128.4 s、fresh 43.3–132.1 s；除 `ahb-sha-target` 1 例外均 6 例，fresh 全部匹配。逐组合数字见 `../../runs/REMOTE-EVIDENCE-20261031.md` §3；其中 CVW AHB-Lite 最慢（128.37 s / 132.11 s，64 字节取指粒度），AHB SHA 单例 65.05 s / 55.69 s。

同日 15:00 后远程复验（`runs/remote-stage1-20261031/`，同一快照、冷缓存）：`ibex-obi-apb-i2c` 6+6，85.61 / 78.60 s，fresh `true`；`vexii-f1f4` 6+6，67.32 / 86.77 s，`true`；`vexii-f2f4` 6+6，72.50 / 94.49 s，`true`；`ibex-obi-tlul-gpio` 6+6，102.9 / 92.9 s，`true`（15:10 后完成）。另：`src/myfuzz/composition/source_elaboration.py` 的 `_ELABORATION_TIMEOUT_SECONDS` 由 30 调至 300（远程冷缓存下 Ibex 首次 elaboration 实测 >30 s 被监督器误判 `crashed`；本机热缓存约 1.9 s）。这是资源预算调整，不放宽任何正确性检查。

说明：wall 包含构建/编译与进程启动；local 与 remote 是两次独立执行，不同机器、不同 Verilator 缓存状态，**不能**把两列直接当作优化前后 A/B。

## 6. 仍未完成 / 移出阶段一

| 项 | 判定 | 原因 / 现状 |
|---|---|---|
| BOOM | **通用执行器未准入（Phase A 已完成）** | Phase A（harness 生成 + 真 RTL lint）已完成：`runs/boom-tl-harness-lint/` 的 `verilator --lint-only` exit 0 无 warning（518 modules / 36.9 MB / 20.88 s），但 artifact `source_verification=null`。拒绝点前移为 `component-render-refused at /processor/request` ← `local-source-lock-missing-component:boom`（`local_harness/source_lock.py:164`）；F2/F4 仍只有 `directed_standard_runner_router` 的各 6 例 + fresh。剩余 Phase B 约 850–1120 行（`verify_soc_sources.py` 复用 stored 端口证据 + BOOM 进 `sources.lock.json` 约 150–220 行；host 播放器 + `cpu_tlul` 适配器 + `tilelink.cpu.v1` 注册约 700–900 行），之后才是 12 例真跑与 fresh |
| ZipAXI（AXI4 i/d 全双口） | **移出阶段一** | session 无每拍 AXI4 观测，需新写 AXI4 observer（burst/`WLAST`/ID）+ router/slot/park |
| AHB-Lite 的 F4 | **不存在** | Caliptra SHA 无 32 位 rw 寄存器（`CTRL`/`BLOCK*` 为 wo），现有 F4 需写后读回同一字；只声明 F2，不伪造 |
| TL-UL 的 F1/F3 | 不在该组合内 | descriptor 只声明 `flow_ids=['F2','F4']`；F1/F3 是 CPU–RAM 流，与该 IP 总线适配无关 |
| IP 侧完整 AXI4 目标 | 不存在 | 现有 IP 目标最高到 AXI4-Lite；ZipAXI 目标与突发语义未接入 |

## 7. 不声称

- DUT 断言未编译（Verilator 无 `--assert`），因此不声称任何 DUT 内部正确性。
- 退休、RAM 读取版本、跨例 writer/来源、IP 内部状态与寄存器副作用：全部 unknown；`observed` 不等于 verified。
- 所有运行 `feedback.certified=0`、`storage_reward=0`；本文数字不构成认证或覆盖率结论。
- 不声称任意 CPU/IP 可自动支持；不声称 profile 派生能消除新增组件所需的真实声明与验证。
- 不声称 CVA6 的取指身份可外推：hop 只在当前 pinned WT 配置（ARID/RID 声明）下成立，仅对已声明窗口内的字有权威快照；`retirement`/内部存储版本/跨例来源仍 unknown。
- 不声称 BOOM 已通过通用 `compiled_mmio`：Phase A 只完成 harness 生成与 lint（`source_verification=null`），`compiled_mmio_admitted=false`，F2/F4 是 directed runner 的有向运行。
- 不声称第 6 条验收的清理面已完成（遗留项见矩阵 §1 第 6 行）。

## 8. 入口

- [阶段一验收矩阵](stage1-acceptance-matrix-20261031.md)：6 条验收逐条状态、证据路径、还缺什么。
- [F1–F4 批量结果](f1-f4-batch-20261030.md)：远程 13 项运行（6 主组合 + CV32E40P/Timer 追加 + 3 个 profile 派生复验 + TL-UL）与本地交叉检查的逐例数字。
- [扩展总线适配](extended-bus-adapters-20261031.md)：TL-UL / AXI4-Lite / AHB-Lite 目标与 Vexii / CVA6 / BOOM 状态。
- [阶段一全量验收审计](stage1-completion-audit-20261031.md)：01:15 快照的独立审计（部分判定已被本报告取代）。
- [完整 AXI4 CPU 可行性](full-axi4-cpu-f1-f4-feasibility-20261031.md)：CVA6/BOOM/ZipAXI 分级。
- [profile 接入说明](../profile-onboarding.md)、[路线图](../universal-system-roadmap.md)。
- 证据目录改名与清理：`../../runs/RENAMES-20261031.md`；远程镜像说明：`../../runs/REMOTE-EVIDENCE-20261031.md`。
