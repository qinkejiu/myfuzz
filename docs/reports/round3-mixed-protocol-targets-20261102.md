# 混合协议多目标：同一个 CPU 在一个会话里访问 APB3 与 AXI4-Lite 两个真实目标（2026-11-02）

状态：**已接入统一单进程执行器，并在真实 RTL 上通过固定批次**。
证据目录：`runs/round3-mixed-targets/`（`README.md`、四份 `run.log`/`summary.json`、`run-all.sh`、`commands.log`、`code/`、`hunks.diff`）。

本增量只做一件事：**去掉 APB3 目标与 AXI4-Lite 目标同处一个会话时的具名拒绝**，把“目标协议”从一个构建级常量变成每个目标自己的声明，并让每个 case 行/摘要都写明被路由目标用的是哪一种协议。不涉及 Wishbone/TL-UL/AHB 目标，不改 DMA 语义，不改 F1、CVA6/AXI4 CPU、F5 link 生成（除 F5 的协议词）与 `src/myfuzz/local_harness/*`。

## 1. 声明：协议是每个目标自己的事实

新场景 `configs/scenarios/inprocess-obi-apb-axi4lite-mixed-timer-axiluart-f1f4.json`：

| index | name | profile | 协议（profile 自己的 mmio_slave 端口） | window | F5 |
|---|---|---|---|---|---|
| 0 | timer | `configs/peripherals/pulp_timer_irq` | `apb/3` → `apb3` → `apb3_mmio_bridge` | `0x40001000` + 4096 | 是（`configs/behaviors/pulp_timer_f5.json`） |
| 1 | axiluart | `configs/peripherals/zipcpu_axiluart` | `axi4-lite/1` → `axi4-lite` → `axi4_lite_mmio_bridge` | `0x40002000` + 16 | 否（不声明 F5 事实） |

CPU 为 Ibex RVFI OBI，RAM `0x10000..0x30000`，本场景**不声明 DMA**（因此 F6 以 `unsupported-f6:no-dma-model:APB3+AXI4-Lite` 具名拒绝，summary 里 `dma not_present`）。两个窗口互不重叠、也不与 RAM 重叠。

入口新增 `target_protocol_axis(protocols)`：一个协议 → 历史同构构建；`{apb3, axi4-lite}` → 混合构建；集合里出现其它协议（或空集）→ 仍然按名拒绝
`unsupported-targets:mixed-protocol:<集合>`。`render_bindings` 与 `main` 都只调用这一个判定，不再各自判断。

生成的 header 同时给出构建级与目标级事实（同构构建的历史宏一字不变）：

```
#define TARGET_PROTOCOLS_MIXED 1
#define TARGET_PROTOCOL_APB3 0            /* 混合构建里构建级协议是中性值 */
#define TARGET_PROTOCOL_AXI4LITE 0
#define TARGET_BRIDGE "mixed:apb3_mmio_bridge+axi4_lite_mmio_bridge"
#define TARGET_PROTOCOL_APB3_0 1
#define TARGET_PROTOCOL_AXI4LITE_0 0
#define TARGET_BRIDGE_0 "apb3_mmio_bridge"
#define TARGET_NAME_0 "APB"
#define TARGET_BUS_CHANNEL_0 "apb"
#define IP_PROTOCOL_0 "apb3"
#define TARGET_PROTOCOL_APB3_1 0
#define TARGET_PROTOCOL_AXI4LITE_1 1
#define TARGET_BRIDGE_1 "axi4_lite_mmio_bridge"
#define TARGET_NAME_1 "AXI4-Lite"
#define TARGET_BUS_CHANNEL_1 "axi"
#define IP_PROTOCOL_1 "axi4-lite"
#define KEY_TARGET_READS "target_reads"   /* 中性命名组 */
#define KEY_READ_FROM_TARGET "target"
```

每个目标还有一份生成的 `IpTarget<n>` trait，带
`static constexpr bool apb / axi4lite`、`apb_error_sampled`、`protocol`、`name`、
`bridge`、`bus_channel`、`fixed_input_count`，以及**只有该协议才有**的 trace 访问器
（target0 是 APB3 的 psel/penable/pready/pwrite/paddr/pwdata/prdata[/pslverr]，
target1 是 AXI4-Lite 五通道 19 个采样点）。`HAVE_APB_PSLVERR` 改为“任一目标的 trace 带 pslverr”，
每次采样再用该目标自己的 `apb_error_sampled` 做 `if constexpr` 守卫，避免“第一个目标没有 pslverr，第二个目标有”时编译失败或漏采样。

## 2. host：只有采样与完成判据分协议，引擎仍是同一套

`scripts/inprocess_obi_apb_f1f4_spike.cpp` 的改变集中在目标引擎：

- 新增 `ip_is_axi4lite/ip_bus_channel/ip_protocol_word/ip_bridge_of/ip_fixed_input_count`
  这些对 trait 的编译期折返；`#if TARGET_PROTOCOL_AXI4LITE` 的两个采样块改为
  `#if TARGET_PROTOCOL_AXI4LITE || TARGET_PROTOCOLS_MIXED`，块内用
  `if constexpr (IpTarget<index>::axi4lite)` 选边，因此混合构建里 APB3 目标只走 APB3 采样、
  AXI4-Lite 目标只走五通道采样。
- 完成判据按“完成请求的那个目标”的协议：APB3 仍是 `psel && penable && pready` 同一拍；
  AXI4-Lite 仍是 AW+W+B 恰好各一次（写）/ AR+R 恰好各一次（读），响应码非 OKAY 记为
  `axi_resp_non_okay` 并在该目标的通道上打印 `bus_error`。
- 通用请求/响应握手（`drive_request`/`request_ready`/`response_valid`）不变，`Mmio` 仍按窗口路由。
- F2/F3/F4 的通过判据改为读“被路由目标的协议”，并新增 `other_targets_quiet()`：
  除被路由目标外，其它目标必须保持 0 读 0 写（F5/F6 不适用：多 link 的 F5 一个 case 可能服务
  多个声明目标，routed F6 本来就写目标）。同构单目标构建里该项恒真，历史判据不变。
- case 行：混合构建打印中性计数（`target_reads/target_writes/target_transfers`、五个
  `axi_*`、`target_error`）、每目标计数（`target<n>_*`）、`target_index` 和新的
  `target_protocol <apb3|axi4-lite|none>`；同构构建的字段一字不变（见回归一节）。
- summary：混合构建增加 `target_protocols apb3,axi4-lite`、
  `target<n>_protocol`、`target<n>_bridge`、`target<n>_fixed_inputs`，两个错误通道分别写
  `bus_error_axi unknown` 与 `bus_error_apb observed|unknown`；同构构建不打印目标级协议词。

## 3. 入口：解析并核对新字段

- `windows['target_protocols']` 把“第 i 个窗口属于哪个协议”随地址视图一起传下去；
  `case_target_protocol()` 用它把某个 case 的 `target_index` 映射回协议；
  `_target_protocol_mismatch()` 把 case 行自己写的 `target_protocol` 与声明比对，
  不一致就让批次失败（`correspondence` 已经把它接进逐例检查，`correspondence: ...` 会出现在
  `summary.json` 的 `failure` 里）。
- `summary.json` 增加 `target_protocols`（每目标 name/protocol/bridge/kind/window/trace_roles）、
  `target_windows[*].protocol/bridge`，`target_protocol.kind` 在混合构建为 `mixed`，
  `transfer_criterion` 写成 `per_target: apb3=sel_enable_ready; axi4-lite=aw_w_b or ar_r`。
- F5 的词跟着“被选中的 F5 目标”走：`NEUTRAL_F5_KEYS` 让混合构建的 F5 文档读
  `target_read_offset/target_read_data/target_last_write_*`（host 在混合构建里印的就是这组中性名），
  一协议 APB3 构建仍读 `apb_*`。
- 两条具名拒绝：`f5_protocol_check()`（F5 只能是 APB3 目标，AXI4-Lite 声明了四个 F5 事实就
  `unsupported-f5:one-f5-target:apb3-only:<protocol>:<name>`）与
  `dma_route_protocol_check()`（DMA 路由到 AXI4-Lite 目标
  `unsupported-dma-route:apb3-target-only:<protocol>:<name>`，APB3 路由不变）。

## 4. 真实固定批次：6/6 `observations_passed`

```sh
PYTHONPATH=src:. python3 scripts/run_inprocess_f1f6.py \
  --config configs/scenarios/inprocess-obi-apb-axi4lite-mixed-timer-axiluart-f1f4.json \
  --cache runs/round3-mixed-cache --output runs/round3-mixed-targets/fixed \
  --records 'F2:40001000,F4:40001008:0fffffff,F5:00000001:00000000:ffffffff,F2:40002004,F4:4000200c:00005a5a,F3:00014004:0badf00d'
```

`{"status": "observations_passed", "cases": 6, "run_seconds": 0.00557, "total_seconds": 5.726}`，
`link_cache_hit true`（Ibex + PULP timer + ZipCPU axiluart 冷构建一次进 `runs/round3-mixed-cache`），
整条命令 7 s，host 侧 5.6 ms，六例分别 0.14/0.05/0.19/0.05/0.05/0.05 ms。

| 例 | flow/record | 被路由目标 | `target_protocol` | 选中目标读/写 | 另一目标读/写 | AW/W/B/AR/R |
|---|---|---|---|---|---|---|
| 0 | F2:40001000 | 0 timer | `apb3` | 1/0 | target1 0/0 | 0/0/0/0/0 |
| 1 | F4:40001008:0fffffff | 0 timer | `apb3` | 0/1 | target1 0/0 | 0/0/0/0/0 |
| 2 | F5:1:0:ffffffff | 0 timer | `apb3` | 1/3 | target1 0/0 | 0/0/0/0/0 |
| 3 | F2:40002004 | 1 axiluart | `axi4-lite` | 1/0 | target0 0/0 | 0/0/0/1/1 |
| 4 | F4:4000200c:00005a5a | 1 axiluart | `axi4-lite` | 0/1 | target0 0/0 | 1/1/1/0/0 |
| 5 | F3:00014004:0badf00d | 无（RAM） | `none` | 0/0 | 两者 0/0 | 0/0/0/0/0 |

批次合计：APB3 目标 2 读 + 4 写，AXI4-Lite 目标 1 读 + 1 写，
`axi_aw/w/b/ar/r` = 1/1/1/1/1，`target_wstrb_full 1`，`target_resp_okay 2`，
`target_resp_non_okay 0`，`target_errors 0`。

两侧的数据也互相吻合：`F2:40002004` 读到 UART 的 `FIFO_STATUS` 复位字 `0x403f4000`
（与单目标 AXI4-Lite 批次同值），CPU 把同一字写回 RAM（`echo_value` 相等）；
`F4:4000200c` 把 `0x00005a5a` 推进 `TXREG`，`target_wstrb 15`、`target_resp 0`（OKAY）。
timer 侧读到 `TIMER0_COUNT`（批次内 `0x00000000` → F5 内 `0x00000010`），F4 写到偏移 8 的
`TIMER0_CMP`。

## 5. F5 证据（混合构建里的 APB3 timer）

- `trigger_writes_declared 3`、`trigger_writes_observed 3`、`clear_writes 0`、
  `last_trigger_offset 0x00000000`、`last_trigger_data 0xffffffff`；
- `irq_edges 1`、`device_high_ticks 1`、`delivered_high_ticks 16`、`irq_takes 1`、
  `wait_timeout 0`：设备自己的 `irq_o` 脉冲被采样并送达 CPU；
- `target_read_offset 0x00000000`、`target_read_data 0x00000010`、
  `isr_read_addr 0x40001000`、`isr_read_value 0x00000010`、`isr_read_register_kind count`、
  `isr_result 0x00000010`、`isr_flag 1`：ISR 读的是声明的状态字并把它存回 RAM；
- `irq_level_final 0x00000000`、`level_stuck 0`；
- case 行 `target_protocol apb3`，summary `target0_f5 yes` / `target1_f5 no`。

F5 的协议词跟着被选中的 F5 目标（这里是 APB3 timer），不读构建级宏；
AXI4-Lite 目标声明 F5 事实会被具名拒绝，所以不存在“未测试的 F5 路径被当成通过”。

## 6. 回归（同一份代码、同一批次）

`runs/round3-mixed-targets/run-all.sh` + `commands.log`：四次运行前后共八次代码摘要完全一致
（`run_inprocess_f1f6.py` `d5b957ed…`、`inprocess_obi_apb_f1f4_spike.cpp` `d1d68447…`、
`multi_target.py` `c33a1d99…`），`code/` 就是这三个文件。

| 回归 | 命令要点 | 结果 |
|---|---|---|
| 同协议双 IP（APB3 timer + APB3 I2C） | `--config configs/scenarios/inprocess-obi-apb-two-ip-timer-i2c-f1f6.json --cache runs/stage2-stepD2-cache` | `observations_passed` 6/6，wall 7 s |
| 单 AXI4-Lite 目标（axiluart + ZipDMA） | `--config configs/scenarios/inprocess-obi-axi4lite-ibex-zipcpu-axiluart-zipdma-f1f6.json --cache runs/stage2-unified-axi4lite-20261101/cache` | F1/F2/F3/F4/F6 5/5，wall 7 s |
| 打包 AXI4 CPU（CVA6）F2/F3/F4 | `--config configs/scenarios/inprocess-cva6-axi4-timer-f2f4.json --cache runs/round1-cva6-cache` | 3/3，wall 17 s |

同协议双 IP 批次仍用历史 APB3 词（`apb_reads/apb_writes/apb_rdata/apb_offset/apb_pwdata/
apb_pready/apb_read_offset/apb_read_data/apb_last_write_*`），**不打印** `target_protocol`；
`apb_transfers 8`、`target0_reads_total 2`、`target0_writes_total 4`、`target1_reads_total 1`、
`target1_writes_total 1`、`target0_irq delivered`、`target1_irq observe_only`、
`bus_error_apb observed`。它和 `runs/round1-multi-ip/fixed/run.log` 的差别只有：其它增量后来加进共享 host 的
字段（`level_stuck`、DMA 形状词、每目标 delivered-tick 合计）以及它们改动固件带来的 tick 数；
生成 header 与 `runs/round1-multi-ip/fixed/spike_config.h` 相比只有新增宏，
`TARGET_PROTOCOL_APB3 1`、`TARGET_PROTOCOL_AXI4LITE 0`、`TARGET_BRIDGE "apb3_mmio_bridge"`、
`TARGET_NAME "APB"`、`TARGET_BUS_CHANNEL "apb"`、`HAVE_APB_PSLVERR 1` 全部一致。

单 AXI4-Lite 批次仍是历史 AXI 词（`target_reads/target_offset/target_rdata/target_wstrb 15/
target_resp 0/axi_aw/w/b/ar/r`），`target_transfers 2`、`target_resp_okay 2`、
`fixed_target_inputs 2`、F6 的 `dma_reads 4`/`dma_writes 4`/`dst0..3` 与 `runs/stage2-unified-axi4lite-20261101/f1f4f6-preloaded`
一致（F1 的字段随另一个增量的 trace 改动增加，不属于本次改动）。

CVA6 批次 `apb_offset 0x00000008`、`apb_pwdata 0x0fffffff`、`apb_pready 1`、`read_from ram`、
`cpu_axi_ar/r/aw/w/b 85/85/19/19/19`、`bus_error_axi unknown`。

## 7. 测试

```
PYTHONPATH=src:. python3 -m pytest tests/composition/test_multi_target.py \
  tests/composition/test_inprocess_behavior.py \
  tests/integration/test_inprocess_f1f6_entry.py -q          # 340 passed
PYTHONPATH=src:. python3 -m pytest tests/integration/test_inprocess_mixed_targets.py -q   # 23 passed
PYTHONPATH=src:. python3 -m pytest tests/integration/test_inprocess_axi4lite_entry.py \
  tests/integration/test_inprocess_f1f4_entry.py tests/integration/test_inprocess_ahb_entry.py \
  tests/integration/test_inprocess_wbcpu_entry.py tests/integration/test_inprocess_gpio_entry.py \
  tests/fuzz/test_entry_f1_program.py -q                     # 326 passed
```

新测试文件 `tests/integration/test_inprocess_mixed_targets.py` 覆盖：混合协议归一化
（`target_protocol_axis`、场景本身的两个协议/窗口不重叠）、per-target 宏与 trait
（`TARGET_PROTOCOL_*_<n>`、只有自己的 trace 访问器、per-target pslverr 采样）、
混合 case 行/摘要解析（真实 `run.log` 原文）、`target_protocol` 与声明的比对、
F5 文档的中性字段、两条具名拒绝，以及被保住的同构路径（APB3 键集、AXI4-Lite 键集、
单目标 case 没有 `target_protocol`）。

## 8. 仍然保有的拒绝与限制

- `unsupported-targets:mixed-protocol:<set>`：APB3/AXI4-Lite 之外的协议（或空集）按名拒绝，
  只有这两个适配器能被混合。
- `unsupported-f5:one-f5-target:apb3-only:<protocol>:<name>`：AXI4-Lite 目标声明 F5 事实即拒绝；
  本场景的 axiluart 不声明 F5 事实，所以 summary 写 `target1_f5 no`。
- `unsupported-dma-route:apb3-target-only:<protocol>:<name>`：DMA 路由到 AXI4-Lite 目标拒绝，
  APB3 路由不变；本场景无 DMA，F6 以 `unsupported-f6:no-dma-model:...` 拒绝。
- 混合构建的 case 行用中性词，因此与单协议 APB3 行不是逐字相同（`apb_reads` → `target_reads`）：
  一行要描述两种协议只能这样，且每例都显式写出 `target_protocol`；同构构建的行保持不变。
- CPU 只有一个外部中断输入、F5 ISR 只有一组 status/result 单元，因此一个 F5 case 只归属它选中的
  那一个 link。
- 一个 host tick 驱动所有模型；三个 profile 都声明 50 MHz，`assume_single_clock` 把这句写明。
- pin 模型仍是单目标特性（`unsupported-pins:multiple-targets`）。
- 不声称 RTL 覆盖率、证书或 replay；本文每个数字都来自 `runs/round3-mixed-targets/` 里的
  case/summary 行。

## 9. 变更文件

| 文件 | 内容 |
|---|---|
| `scripts/run_inprocess_f1f6.py` | `target_protocol_axis`、per-target 协议宏、按目标协议渲染 trait、中性/同构 case 词与 F5 中性键、`case_target_protocol`/`_target_protocol_mismatch`、`f5_protocol_check`/`dma_route_protocol_check`、`summary.json` 的 `target_protocols` 与限制文本 |
| `scripts/inprocess_obi_apb_f1f4_spike.cpp` | `TARGET_PROTOCOLS_MIXED`、trait 协议常量与折返、按目标协议的采样/完成/判据、`other_targets_quiet()`、`target_protocol` 与目标级 summary 词、双错误通道 |
| `configs/scenarios/inprocess-obi-apb-axi4lite-mixed-timer-axiluart-f1f4.json` | 新的混合场景 |
| `tests/integration/test_inprocess_mixed_targets.py` | 23 个纯 Python 新测试 |
| `runs/round3-mixed-targets/` | 证据包（四份运行、命令与代码摘要、`code/`、`hunks.diff`） |
| `runs/round3-mixed-cache/` | 冷构建缓存（Ibex + PULP timer + ZipCPU axiluart + 链接产物） |

`src/myfuzz/composition/multi_target.py` 未修改。
两个共享脚本在本 checkout 里是未跟踪文件，`hunks.diff` 是 before→after 的筛选视图
（只保留提到本次协议词的 hunk；同一文件里还有其它增量的改动，未在此列出）。
