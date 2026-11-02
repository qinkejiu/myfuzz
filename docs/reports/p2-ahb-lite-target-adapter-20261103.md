# P2-C：AHB-Lite 目标适配器（2026-11-03）

## 结论

统一入口（`scripts/run_inprocess_f1f6.py` + 宿主
`scripts/inprocess_obi_apb_f1f4_spike.cpp`）新增第五种目标协议 **AHB-Lite**：适配器从
profile 的 `mmio_slave` 端点（`["ahb-lite","1"]`）派生，不写 CPU×IP 组合分支；宿主按
目标的十个真实从端口角色采样 **address phase / data phase 两相**，完成判据是
`HSEL && HTRANS[1] && HREADYIN` 的地址相加上 `HREADYOUT` 完成的数据相。

真实跑通：同构 F2/F4 3/3；Caliptra `sha256_ctrl` **已知答案** 67 例（写 BLOCK+CTRL、
轮询 STATUS、读 DIGEST，摘要与 Python `hashlib` 逐字节一致）；APB3+AHB-Lite+TL-UL
三协议混合 9/9。F5 与 F6 都按名拒绝（前者该 profile 未授予 IRQ 契约，后者 DMA 路由准入
不在本代理区域）。既有四种协议（APB3/AXI4-Lite/Wishbone/TL-UL）的 case 行除 `seconds`
外逐字节不变。

证据：`runs/p2-ahb-target-20261103/README.md`（`run.sh`、`campaign.log`、
`case-lines.txt`、`verify_known_answer.py`、`code/` 副本）。本报告只陈述该包内真实运行。

## 精确 hunk 清单

行号以本次证据运行的代码为准：`scripts/run_inprocess_f1f6.py` md5
`4812a2623316bb2752800d1a280f9089`，`scripts/inprocess_obi_apb_f1f4_spike.cpp` md5
`9963468dc9b0ce10099527a3d7a8a665`（`code/MD5SUMS` 与之一致）。

### 入口 `scripts/run_inprocess_f1f6.py`

| 位置（函数/常量） | 行 | 行为 |
| --- | --- | --- |
| `TARGET_PROTOCOLS` | 197 | 新增 `'ahb_lite_register_observe': 'ahb-lite'`（删除原来“本增量不加两相采样”的拒绝注释块） |
| `TARGET_BRIDGES` | ~226 | `'ahb-lite': 'ahb_lite_mmio_target'` |
| `AHB_TARGET_KIND` | 234 | 常量保留，语义从“按名拒绝”改成“已准入的 kind”（删除 `AHB_TARGET_REFUSAL`） |
| `SUPPORTED_TARGET_PROTOCOLS` | 240 | 追加 `'ahb-lite'`（**末位**，既有 1/2/3/4 协议词的顺序与文本不变） |
| `PROFILE_PROTOCOLS` | 876 | `('ahb-lite','1'): 'ahb-lite'` |
| `TARGET_LABELS` | ~563 | `'ahb-lite': 'AHB-Lite'` |
| `AHB_TRACE_ROLES` / `PROTOCOL_TRACE_ROLES` | 591 / 596 | 十个真实角色 `hsel/htrans/haddr/hwrite/hsize/hwdata/hreadyin/hreadyout/hrdata/hresp` |
| `target_protocol()` | 896 | 删除 AHB 拒绝分支；kind 与 trace 不符仍是 `unsupported-target-trace:<kind>:<declared>` |
| `TARGET_TRANSFER_CRITERIA` | ~990 | `'ahb-lite': 'hsel_and_htrans_address_phase_then_hreadyout_data_phase'` |
| `TARGET_ERROR_RESPONSES` | ~1010 | `'ahb-lite': 'unknown: … tied-low err … has_error false …'`（不把 0 当干净总线） |
| `neutral_case_protocol()` | 1019 | 加入 `'ahb-lite'`（case 行使用中性字段拼写） |
| `AHB_TARGET_CASE_TRACE_KEYS` / `AHB_TARGET_CASE_OBSERVATION_KEYS` / `AHB_TARGET_CASE_COUNTER_KEYS` | 726 / 733 / 743 | 两相字段、F2/F4 观察键、`ahb_address_phases`/`ahb_data_phases`/`ahb_error` 计数键（**不改**既有的 `AHB_CASE_COUNTER_KEYS`，那是 AHB **CPU** 总线的） |
| `mixed_case_observation_keys()` / `mixed_case_counter_keys()` | 1048 / 1070 | 仅当声明含 `ahb-lite` 时追加 AHB 键 |
| `case_observation_keys()` / `case_counter_keys()` | 1095 / 1141 | `ahb-lite` 分派到上表；`bus == 'ahb'`（CPU 总线）分支保持原样 |
| `ahb_target_request_from_profile()` | 1211 | 新函数：从 profile 的 `ahb-lite/1` 端点钉 `target.ahb-lite/1/full-word-single` + 固定输入 |
| `run()` 目标建请求分派 | 8457 | `elif target_protocol_kind == 'ahb-lite':` 挂到新函数 |
| 头文件生成 `render_bindings` | 4753 / 4766 / ~4780 / 4822 / 4828 | `TARGET_PROTOCOL_AHB`、`TARGET_MIXED_HAS_AHB`、`TARGET_PROTOCOL_VERBOSE`（含 ahb-lite）、`TARGET_BUS_CHANNEL`=`ahb`、每目标 `TARGET_PROTOCOL_AHB_<n>` 与通道字 |
| 中性键发射条件 | 4858 | `mixed or protocol in (…, 'ahb-lite')`——AHB 构建打印 `target_*` 而不是 `apb_*` |
| `_generated_target_traits()` | 5381 | 每目标 `ahb` 常量 + 十个 `ahb_<role>()` 访问器（`elif row_protocol == 'ahb-lite'`） |

### 宿主 `scripts/inprocess_obi_apb_f1f4_spike.cpp`

| 位置 | 行 | 行为 |
| --- | --- | --- |
| 宏块 | 415 / 468 / 493 | `TARGET_PROTOCOL_AHB`（默认 0）、单协议和校验计入 AHB、`TARGET_MIXED_HAS_AHB`/`TARGET_HAS_AHB`、`TARGET_NEUTRAL_COUNTERS_AHB` 作为**最后一个**兜底组 |
| 回退 `IpTarget<0>` | 979 / 985 / 1094 | `ahb` 常量、协议词 `ahb-lite`、十个访问器（`#elif TARGET_PROTOCOL_AHB`） |
| `ip_is_ahb()` | 1307 | 按目标 trait 判协议（与 `ip_is_wishbone`/`ip_is_tlul` 同形） |
| `Observation` | 2098 | 两相字段、两相计数、`ahb_address_seen`（每例重置） |
| 采样块 | 6833 | `#if TARGET_HAS_AHB` + `if constexpr (IpTarget<index>::ahb)`；address phase 采 `haddr/hwrite/hsize/hreadyin`，data phase 采 `hwdata/hrdata/hreadyout/hresp` 并计完成 |
| F2 判据 | 8538 | `ahb_address_phases==1 && ahb_data_phases==1 && htrans==2 && hsize==2 && readyin && readyout && !hwrite` |
| F4 判据 | 8625 | 同上，`hwrite` 为真 |
| case 计数 | 9226 | `ahb_address_phases`/`ahb_data_phases` + `target_error unknown`（同构）或 `ahb_error unknown`（混合） |
| case 两相字段 | 9398 | 只对被路由的 AHB 目标打印十个采样字段，含 `ahb_hresp` |
| 批次总计 | 9886 / 10202 | `total_ahb_address_phases`/`total_ahb_data_phases` 与 summary 词 |
| `bus_error` 词 | 10530 / 10546 | 混合/同构两种 summary 的 `bus_error_ahb unknown` |

改动全部是“新常量/新函数/新分支 + 一处挂接”；没有重构既有函数，没有重排文件。

## 真实结果

证据包的 README 有逐字 case 行；这里只给结论与要点。

| 运行 | 例数 | 结果 | 要点 |
| --- | --- | --- | --- |
| `homogeneous-f2f4` | 3 | `observations_passed` | NAME0=0x61327368（profile 常量）；BLOCK0 写一次；STATUS=1；每例两相各 1、`htrans 2`、`hsize 2`、`target_error unknown` |
| `known-answer` | 67 | `observations_passed` | `abc`/`abd` 摘要与 hashlib 一致；STATUS `0 → 3`；BLOCK 读回 0（wo）；`verify_known_answer.py`：67 cases, 0 problems |
| `mixed-three-protocol` | 9 | `observations_passed` | 每例点名 `target_protocol`，未路由目标 0/0，summary `target_protocols apb3,ahb-lite,tl-ul`、每目标自己的桥 |
| `regression/mixed-pair` | 6 | `observations_passed` | 与 p1 基线除 `seconds` 外逐字节相同 |
| `regression/wb` | 5 | `observations_passed` | 同上 |
| `regression/tlul` | 6 | `observations_passed` | 同上 |
| `regression/mixed-pair-prehost` | 6 | `observations_passed` | A/B：case 行与生成头文件对当前宿主逐字节相同 |

墙钟：全部 10 次运行合计 82 s（含构建缓存；单次 2–14 s）。`campaign.log` 里每次运行
前后 digest 相同，说明整个窗口只有一个代码状态。

**已知答案为什么算证据**：BLOCK/CTRL 是软件 **只写** 寄存器、DIGEST 只读；写入的
512-bit block、一次 INIT|MODE 写、真实的 `READY→VALID` 状态迁移和读回的八个摘要字
与独立 `hashlib.sha256` 完全相同（且 `abd` 与 `abc` 不同）。总线握手成功本身不是结论，
摘要一致才是。

## 仍拒绝 / 仍未知

| 项 | 逐字 | 锚点 |
| --- | --- | --- |
| F5 | `unsupported-f5:target-irq-semantics:ahb-lite:source_port,source_bit_offset,trigger_writes,status_offsets` | 该 profile 声明“no IRQ trigger/capture contract”；`f5_declaration()` 在四事实缺失时给出 |
| F5（假定声明齐全） | `unsupported-f5:target-protocol-not-run:ahb-lite:<name>` | `F5_TARGET_PROTOCOLS` 不含 ahb-lite；本增量没有真实 F5 运行，不借用别的协议路径 |
| F6（无 DMA） | `unsupported-f6:no-dma-model:AHB-Lite` | 场景未声明 DMA 模型 |
| F6（DMA 路由） | `unsupported-dma-declaration:dma-route-target-protocol-unsupported:ahb-lite` | `src/myfuzz/composition/dma_transfer.py:99` `ROUTE_PROTOCOLS`（E2 区域） |
| HRESP 错误 | `unknown` | wrapper `sha256_ctrl.sv` 的 `.err(1'b0)`，profile `has_error: false` |
| 部分/非对齐访问 | 适配器回 `rsp_error`（无 case） | `ahb_lite_mmio_target.sv` 的 `req_addr_i[1:0]!=0 || req_be_i!=4'hf` 准入 |
| burst / 多 outstanding / AHB5 | 无适配器 | 模板只有 `full-word-single`、`max_outstanding 1` |
| AHB 多目标 fabric | 不存在 | 混合会话每个目标各用自己的桥；AHB 目标不共享总线 |

## 测试

- `tests/integration/test_p2_ahb_target.py`：**20 passed**（声明轴、请求模板、生成
  trait、case 键与判据词、F5/F6 具名拒绝、宿主两相采样与“无器件名分支”、适配器 RTL、
  两个真实场景声明、真实证据日志解析 + 已知答案复核）。
- `tests/integration/test_inprocess_target_protocols.py`：**21 passed**（把 AHB 从
  “按名拒绝”改为“准入 + trace 不符仍拒绝”）。
- `tests/integration/test_inprocess_mixed_protocols.py`：**22 passed**（2..5 子集；
  含 ahb-lite 的对/三/四/五协议混合）。
- 合计 **63 passed**。
- `tests/integration/test_inprocess_f1f6_entry.py`：**196 passed**（收尾时）。说明：期间
  有一段窗口该文件有 14 个 `KeyError: 'device_capabilities'` 失败
  （`run_inprocess_f1f6.py:5195` 的 DMA 头文件块），来自其他增量正在进行的 DMA 设备
  能力改动，与本增量的 AHB 代码路径无关；该键已由其所有者补齐，现在全绿。
- 编辑前已知失败基线（工作规约 §5：根 `README.md` 链接用例、`tests/composition/` 的
  pgid 用例）本代理未触碰、也不计入。

## 需要其他代理配合

1. **E2（DMA）**：在 `src/myfuzz/composition/dma_transfer.py` 的 `ROUTE_PROTOCOLS`
   （第 99 行）和入口 `DMA_ROUTE_PROTOCOLS`（`run_inprocess_f1f6.py` 第 ~277 行）各加
   `'ahb-lite'`。宿主侧不需要改：路由 beat 走 `IpTarget<I>::drive_request` /
   `response_valid`（cpp 第 ~5380–5420、~5523–5536），AHB 适配器的准入条件（全字、
   对齐、偏移 < 4096）与 F6 的 `full_word/15` beat 相符。之后可用本包的已知答案会话
   作为 F6 前置（BLOCK/CTRL 都是真实可写寄存器），或直接路由读 NAME0。
2. **D（IRQ）**：如果后续要做该器件的 F5，需要一份**新的**、真实声明 IRQ 触发/清除
   契约的 profile/RTL 事实；同一 RTL 的声明变体（`configs/peripherals/sha_declared_irq`）
   不能被当作新器件，本增量也不伪造触发序列。
3. **父代理**：`docs/reports/README.md` 的索引行由你统一插入（本代理按并发纪律未改）。
   建议新增 `## 2026-11-03`（P2 并行）分组后使用：

```markdown
| **P2 AHB-Lite 目标适配器**：统一入口新增第五种目标协议；profile 的 `mmio_slave` 端点派生 `target.ahb-lite/1` 模板与真实 `ahb_lite_mmio_target` 桥，宿主按十角色采 address/data 两相（`hsel/htrans/haddr/hwrite/hsize/hwdata/hreadyin/hreadyout/hrdata/hresp`）；同构 F2/F4 3/3、Caliptra SHA 已知答案 67/67（abc/abd 摘要与 hashlib 一致、STATUS READY→VALID、BLOCK 写后读 0）、APB3+AHB-Lite+TL-UL 混合 9/9（每例 `target_protocol`、非路由目标 0/0）；F5/F6 具名拒绝（无 IRQ 契约；DMA 路由准入未含 ahb-lite）；APB3/AXI4-Lite/Wishbone/TL-UL 既有 case 行除 `seconds` 外逐字节不变（含 pre-host A/B 与生成头文件 diff）；63 tests | [AHB 目标报告](p2-ahb-lite-target-adapter-20261103.md)、[证据](../../runs/p2-ahb-target-20261103/README.md) |
```
