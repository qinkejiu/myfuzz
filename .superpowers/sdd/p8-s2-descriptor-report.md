# P8 S2 实现报告：外部串行描述符固件 + 单 boot 三方向 + 多字 FIFO

- 增量：P8 S2（只做 S2；不做 S3 真实 error ISR、不做 S4 认证/typed normalizer/前缀 replay）
- 日期：2026-10-18
- 状态：源码 + 纯软件测试已提交。真实门已尝试两次并均失败：`8dd3e70`（FIFO push depth 采样语义，§7.4）、`90652e9`（CPU RDATA pop 只在 mmio_delivery 内嵌 `target_uart_access`，§7.5）。两次都已按真实 journal 修复并补负例锁字段；**修复后的真实门重新排队，尚未在冻结快照重跑**。P8 整体仍不通过。
- 证据目录：`docs/reports/evidence/dma-s2-20261018/`（仅软件证据，明确标注无 RTL 观测）

## 1. 结论摘要

1. 新增固定固件 `src/myfuzz/scenario/ibex_dma_uart_descriptor.py`：boot 写 RAM 源字、初始化 UART/CSR、装 ISR；每例由外部串行流给出 4 个描述符字节 + `len` 个 payload 字节，CPU 用真实 `lw RDATA` 取出并解码，真实 `sw` 写出 DMA SOURCE/DEST/LEN/CONTROL，真实 IRQ 进入真实 ISR，ISR 读真实 DMA status(0)/length(4) 并保存 `mcause/status/lenactual/payload/counter`，**不做期望值比较**。
2. 新增 `make_descriptor_runner`：同一组真实 Ibex / wbdmac / OpenTitan UART 进程，标准 `ScenarioRunner` + `DataflowRouter` + `MasterTargetWindow`（UART 同时声明 RDATA 可读、WDATA 可写与 TX 串行引脚）。RX→RAM、RAM→RAM、RAM→TX 三个方向可在**一次 boot** 内连续执行，TX 方向 drain 到真实串行 peer 捕获。
3. 新增 `src/myfuzz/integration/dma_uart_descriptor_runtime.py`：`DescriptorCase`（纯 pre-RTL 校验）、`DescriptorBoot`（单 boot 多例 + 逐例 command/event/tick 边界）、每例证书 `certify_descriptor_case`（真实 journal join）、`DescriptorResult`、`run_descriptor_cases`、`replay_descriptor_cases`（fresh 全前缀重放并逐例重认证）。
4. 纯软件：`47 passed`（新文件）+ focused 门 `67 passed, 4 skipped` + S1b 搜索回归 `30 passed`。真实门第一次尝试失败（见 §7.4），修复后重新排队，未在冻结快照重跑。
5. 诚实边界：每例 `fifo_origin='unknown'`、`source_authority='incomplete'`、`proof_grade='bounded_historical_chain'`；没有 admission/ownership/edge-index/UART consumption accepted；没有 invalid/error-ISR；TX 捕获来自真实 peer，journal 事件留 S4。

## 2. 变更文件

| 文件 | 类型 | 内容 |
| --- | --- | --- |
| `src/myfuzz/scenario/ibex_dma_uart_descriptor.py` | 新增 | 固定固件镜像、方向/控制字/窗口常量、`descriptor_program`、`ISR_PCS`、`make_descriptor_runner` |
| `src/myfuzz/integration/dma_uart_descriptor_runtime.py` | 新增 | 描述符解码/校验、boot 对象、每例真实证据 join、fresh 全前缀 replay |
| `tests/integration/test_dma_uart_descriptor.py` | 新增 | 纯软件：固件静态断言 + RV32I 模型 + 描述符解码/长度/窗口负例 + 合成 journal 正例/负例 + fake-runner boot 机制 |
| `tests/integration/test_dma_uart_descriptor_real.py` | 新增 | opt-in 真实门：一次 boot 六例（三方向，≥2 个多字）+ fresh 全前缀 replay；未运行 |
| `docs/reports/evidence/dma-s2-20261018/` | 新增 | 软件证据（manifest、固件/程序 JSON、pytest 日志、README） |
| `.superpowers/sdd/p8-s2-descriptor-report.md` | 新增 | 本报告 |

未修改 `third_party/`、RTL、`fifo_origin`、contracts、P6/P7 文件；没有改动 `agent.md`。

## 3. 两个关键设计发现（必须评审确认）

### 3.1 固定 `CONTROL=0x0fed0001` 与“多字 FIFO 真实读/写”冲突

设计稿 §5 S2 第 4 步写死 `CONTROL=0x0fed0001`。但 pinned `third_party/soc-zipcpu/rtl/peripherals/wbdmac.v` 的实际位定义是：

- `cfg_incs <= !s_data[29]`（bit29 = `inc_s_n`，源地址**不**自增）
- `cfg_incd <= !s_data[28]`（bit28 = `inc_d_n`，目的地址**不**自增）
- bits 27..16 = 启动 key `0xfed`；bits 9..0 = block length（本固件写 1）

固定 `0x0fed0001` 两端都自增，于是：

- `RX→RAM` 第 2 拍源地址 = `0x5000001c`（WDATA，写寄存器）→ 非法读 → 真实 environment error，得不到多字 FIFO 读；
- `RAM→TX` 第 2 拍目的地址 = `0x50000020`（未声明的 UART offset）→ 真实 environment error，得不到多字串行输出。

设计稿 §7.1 又明确要求“len>1 的真实 FIFO 读”，因此 S2 固件按方向写控制字（源码/测试/证据均记录）：

| 方向 | CONTROL | 位含义 |
| --- | --- | --- |
| `RX_TO_RAM` | `0x2fed0001` | bit29=1，源固定读 RDATA `0x50000018`，目的自增 |
| `RAM_TO_RAM` | `0x0fed0001` | 双端自增 |
| `RAM_TO_TX` | `0x1fed0001` | bit28=1，目的固定写 WDATA `0x5000001c`，源自增 |
| direction code 3（S3 hook） | `0x0fed0001` + 声明的非法 SOURCE/DEST | S2 pre-RTL 拒绝，永不上 RTL |

这是对设计稿固定值的**有意偏离**：没有它，S2 的多字 FIFO 读/写不可能成立。若评审坚持单一固定字，则多字只能退化为 RAM→RAM（不触及 UART FIFO），与 §7.1 冲突。

### 3.2 串行流协议必须是“4 描述符字节 + len payload 字节”，RAM/TX 方向由 CPU drain

若 RAM/TX 方向不带 payload 字节，则“`len <= 已入队 payload 数`”对这两个方向无意义；若带了却不消费，残留字节会被下一例当成描述符。因此声明：

- 所有方向的外部串行流统一为 `4 + len` 字节；
- `RX_TO_RAM`：4 个描述符字节由 CPU pop，`len` 个 payload 字节留给 DMA 从真实 FIFO pop；
- `RAM_TO_RAM` / `RAM_TO_TX`：CPU 先真实 pop 掉 `len` 个 payload 字节（drain），再把 `d3` 重复写入 `SOURCE_RAM+4*i`；drain 值也进入证书（真实 `uart_rdata_access.read_value`）；
- 每例 FIFO push 数 = pop 数 = `4 + len`，证书强制该守恒。

## 4. 固件（`ibex_dma_uart_descriptor.py`）

### 4.1 布局与陷阱入口

- `MAIN=0x10080`（Ibex reset fetch `{boot[31:8],8'h80}`），主程序 102 条 = 408 B，结束 `0x10218`；
- `MTVEC_BASE=0x10400`（256B 对齐），`ISR=0x1042c`（Ibex `EXC_PC_IRQ = {mtvec[31:8],1'b0,11,2'b00}`），ISR 16 条 = 64 B；
- 镜像：`MAIN/ISR/SOURCE_RAM(0x22000,16B)/DESTINATION(0x23000,16B)/RESULT(0x24000,24B)`；`descriptor_program_words()` 在 import 时做重叠/对齐/区间断言。

### 4.2 boot

1. `lui` 建立 x1=DMA_BASE、x2=UART_BASE、x4=DESTINATION、x5=RESULT；
2. `CTRL=0x80000003` 写 UART `0x10`（固定 fixture 的真实 UART 初始化字）；
3. 用真实 CPU store 写 `SOURCE_RAM..+12` 四个 boot 源字（设计稿“boot 写 RAM 源字”）；
4. `mtvec=0x10400`、`mie=0x800`（MEIE）、`mstatus=8`（MIE），与 S1 连续固件相同。

### 4.3 每例

1. 4 ×（轮询 UART STATUS `0x14` 的 RXEMPTY=bit5 → `lw RDATA 0x18`）得到 `d0..d3`；
2. 解码：`direction=d0&3`、`len=(d1&3)+1`、`dst_index=d2&3`、`payload=d3`；
3. 按方向算 SOURCE/DEST：
   - RX：SOURCE=`0x50000018`，DEST=`DEST+4*dst_index`；
   - RAM→RAM：SOURCE=`SOURCE_RAM`，DEST=`DEST+4*dst_index`；
   - RAM→TX：SOURCE=`SOURCE_RAM`，DEST=`0x5000001c`；
   - code 3：SOURCE=DEST=`0x50000020`（唯一声明的非法 offset，S3 hook）；
4. RAM 源方向：CPU 把 payload 真实 `sw` 到 `SOURCE_RAM+4*i`（i<len），随后真实 `lw RDATA` drain `len` 个 payload 字节；RX 方向不写 RAM 源字、不 drain；
5. 写真实 DMA `SOURCE(8)/DEST(12)/LEN(4)`，先 `lw` 快照 `COMPLETED`（`RESULT+16`）再写 `CONTROL(0)`，避免完成与快照竞争；
6. ISR 入口后真实读 DMA status(0)、length(4)、witness 指针（`RESULT+20`）与 witness 值，依次写 `RESULT+0/4/8/12` 和 `COMPLETED=RESULT+16`，32 次空转延迟保证 Runner 的 16 CPU-tick IRQ 脉冲在 MIE=0 期间过期，然后 `mret`；
7. 主循环比较 `COMPLETED` 变化后跳回 `case`，等待下一例描述符。

### 4.4 无期望值

固件镜像不含任何 payload/期望字节常量；`descriptor_uart_images()` 无参数、确定性；软件测试断言两次构建字节相等，且固件只引用固定地址与固定控制字。ISR 不比较期望值。

## 5. 运行时（`dma_uart_descriptor_runtime.py`）

### 5.1 单 boot 多例

`DescriptorBoot` 复用 S1 的 `ScenarioBatchRecorder`/`ScenarioBatchPlan`、`_poll_schedule`、`_capture`、`_case_boundaries`、`_source_pins`：

- `boot()`：`recorder.begin()`，只推进 `('dma','cpu')` 直到真实 UART CTRL 请求进入 router；
- 每例：
  1. 先提交**全部** `4+len` 个 `BatchSourceEvent`（action id `descriptor-{case}-{slot}`，唯一）；
  2. 只推进 `('uart',)` 直到全部 frame end 且 `register_access_conflict()` 为空（`max_source_ticks = 1024*(4+len)+1024`）；
  3. 推进 `_poll_schedule(runner)` 直到真实 CPU 在 `COMPLETED` 写入 `case_index`（单次、单调）；
  4. RAM→TX：继续只推进 `('uart',)` 直到真实 peer 捕获 `len` 字节（`320*len+320` 上界），才封存 case；
  5. 用真实 journal 切片做 `certify_descriptor_case`，再记录 `command_start/end`、`event_start/end`、`ticks_before/after`、`prefix_sha256`、`fifo_depth_after`。
- 结束后 `finish()` → `DescriptorResult`（schema `descriptor_dma_diagnostic.v1`），保存 plan/trace/cases/identities/execution_ids/budget/events/ticks/uncertain/source_pins。

### 5.2 拒绝不消费 RTL

`run_descriptor_cases` 在**构建 runner 之前**调用 `_validate_specs`；`DescriptorBoot.run_case` 在记录第一条命令之前调用 `case.validate(windows)`。测试 `test_boot_refuses_a_case_before_recording_any_command` 断言拒绝后 `commands/local_ticks/event_count` 完全不变。

### 5.3 pre-RTL 校验（全部纯函数）

- 方向 ∈ {RX_TO_RAM,RAM_TO_RAM,RAM_TO_TX}；code 3 与 `expect != complete` 一律拒绝（S3 才做）；
- `len ∈ 1..4`；`dst_index ∈ 0..3`；RAM 目的窗口要求 `dst_index+len <= 4`（`DEST+4*dst_index..` 不越出 16B 声明窗口）；
- 串行流长度必须恰为 `4+len`，且等于规范编码（高位置零、payload 重复），杜绝“同一 spec 两套解码”；
- `uart_rdata/uart_wdata/source_ram/destination_ram/declared_illegal` 均为声明半开窗口；每个真实 beat 地址必须在对应窗口内；
- 声明的非法目标只有 `0x50000020` 一个；complete 例不允许命中它；
- `ILLEGAL_TARGET` 必须在 `declared_illegal` 窗口内，否则拒绝；
- 每例 payload 字节已全部由 spec 入队（`len == len(source_bytes)-4`）；
- 16 例上限、identity 去重、`max_rounds_per_case ∈ 1..8192`。

## 6. 每例真实证据与多字 FIFO

`certify_descriptor_case` 只接受 real journal rows（`CaseWitnesses`），强制以下 join；任一缺失即 RuntimeError：

- **源**：每个 action id 恰好一个 `uart_frame_validation(waveform_matched=True)`，字节/顺序与 spec 完全一致；frame id 唯一；`source_injection` 计数与值一致；
- **FIFO**：每个串行字节恰好一次 `uart_tick_observation` post `wvalid&wready` push；push 的**真实深度按 pinned 采样语义从下一个 tick 样本读取**——push strobe 那个 tick 的 `post.probe_uart_fifo_depth` 仍是压入前占用（真实样本：push tick post depth=0/data=90，下一 tick post depth=1/head=90），证书要求“push tick 深度流恰为 0..n-1、下一 tick 的 depth = 本 tick 的 depth+1”、`push.post.probe_uart_fifo_data == byte`、相邻 push 的深度链连续；CPU pop 数 = 4（RX）或 4+len（RAM/TX），pop 来源同时接受**顶层 `uart_rdata_access`** 与**CPU `mmio_delivery.target_uart_access` 内嵌副本**，按真实 `access_id` 去重（真实 journal 的 4 次 RDATA 可能只有 3 个顶层事件，第 4 次只在 delivery 内嵌对象里），`fifo.pops[].source` 记录 top_level/nested；RX 的 DMA pop 数 = len；每个 pop 都有 `pre/post` 真实 depth/head/rvalid/rdata_re 探针，`post.depth = pre.depth-1`、`pre.head = byte`；总 push = 总 pop = 4+len；
- **CPU 真实配置**：DMA 的 `mmio_delivery` 写序列必须是 `(8,SOURCE),(12,DEST),(4,LEN),(0,CONTROL)`，值与 `descriptor_program` 完全一致；CONTROL key=`0xfed`；witness 指针 store 早于 CONTROL；RX 无 RAM 源写，RAM/TX 有 len 次真实 CPU store 且早于首个 DMA read；
- **DMA beats**：恰好 `2*len` 个 accepted beat，逐字 read→write；地址等于声明源/目的 beat 地址；read/write 的 transaction 身份同源、`source_sequence` 相邻且全程严格递增不重复（“不重复执行”）；RAM 源读的 response `rdata == payload`；RX 读的 target delivery 带真实 UART FIFO pop 证明；TX 写的 target delivery 地址 WDATA、值 payload；
- **RAM commit**：目的方向恰好 len 个 `memory_write(component='dma')`，值 payload、`version` 存在且严格递增、是 accepted write 的真实效果；TX 方向无目的 RAM commit；
- **IRQ/ISR**：恰好一个真实 DMA 完成脉冲（`mwb_ack=1,mwb_we=1,mwb_err=0` 且 physical 置位）→ `source_start` → `cpu_external_irq_taken` → `cpu_irq_taken`（`source_event_id` 相同、`cpu_tick` 相同、`source_tick=native_local_tick`）；ISR 的 `mcause=0x8000000b`、status、length、payload、counter 各恰好一次 store；status/length 有真实 MMIO delivery + `data_response`；`cpu_retire` 在 `ISR_PCS` 固定 PC 上验证 load/store 的地址/掩码/数据/寄存器（status x7、length x8、witness x9、counter x9）；
- **TX**：RAM→TX 的 peer 捕获必须逐字节等于 payload；非 TX 例捕获必须为空；
- **无 host 写**：`SOURCE_RAM/DESTINATION/RESULT` 区间内任何 store 的 component 必须是 `cpu` 或 `dma`。

证据中记录：`program`、`beats`（每字 read/write event id、地址、数据、transaction sequence、FIFO 探针）、`beat_count=2*len`、`ram_commits`（含 version）、`cpu_source_versions`、`fifo`（pushes/push_depths/pops/depth_after/max_depth）、`isr`（含 `status_nread`、`status_blocklen_sub_one`、`status_error`、`status_inc_s_n/inc_d_n` 与 `control_inc_s_n/inc_d_n`）、`irq`、`tx_captures`。**status/length 数值只记录不硬编码**；S2 断言 valid 例 `status_error==0`，并断言 status 的 bit29/28（`!cfg_incs/!cfg_incd` 的真实回读）等于 CPU 写出的 CONTROL 的 inc_s_n/inc_d_n——这是“多字固定端确实进入 wbdmac”的真实硬件回读，不是预期数据。

多字：六例门里 `RX_TO_RAM len=3` 的 DMA FIFO pop pre-depth 序列为 `3,2,1`（证书强制），`RAM_TO_RAM len=2/4` 的 commit version 严格递增，`RAM_TO_TX len=2` 的 peer 捕获为 `[payload,payload]`。

## 7. 测试

### 7.1 RED / GREEN

- RED：新模块不存在时 `tests/integration/test_dma_uart_descriptor.py` 无法 import（collection error），固件/解码/证书都无实现；先按此写测试。
- 实现过程中软件 fixture 实际抓住的问题：初始六例矩阵中 `RX_TO_RAM dst_index=2,len=3` 会使目的窗口越界（被 `descriptor_program`/`validate` 拒绝，证明窗口约束有效）；CSRRW funct3 必须为 2（`_csr` 实现）；合成 journal 的 `source_start` 必须携带 `source_event_id` 才能与 `cpu_irq_taken` 关联。控制字冲突来自直接阅读 `wbdmac.v`，不是模型发现的。
- GREEN：见 7.2。

### 7.2 纯软件命令与计数（已运行，证据在 evidence 目录）

```sh
cd /home/qinkejiu/myfuzz
PYTHONPATH=src python3 -m pytest -q tests/integration/test_dma_uart_descriptor.py
# 54 passed

PYTHONPATH=src python3 -m pytest -q \
  tests/scenario/test_ibex_dma_example.py \
  tests/local_harness/test_wishbone_dma_scenario_session.py \
  tests/local_harness/test_wishbone_dma_session.py \
  tests/local_harness/test_wishbone_dma_error_recovery.py \
  tests/integration/test_dma_uart_rx_runtime.py \
  tests/integration/test_dma_uart_rx_boot_contract.py \
  tests/integration/test_dma_uart_rx_cursor.py \
  tests/integration/test_dma_uart_rx_failure_document.py \
  tests/integration/test_dma_uart_rx_replay_state_edges.py \
  tests/integration/test_dma_uart_descriptor.py \
  tests/integration/test_dma_uart_descriptor_real.py
# 74 passed, 4 skipped

PYTHONPATH=src python3 -m pytest -q \
  tests/integration/test_dma_uart_rx_search.py \
  tests/scenario/test_dma_chain_feedback.py \
  tests/integration/test_dma_uart_rx_discovery_scope.py
# 30 passed
```

4 个 skip = 3 个既有 explicit-native 门 + 新的 queued descriptor 门。focused 列表并入 S1a/S1c 的 `test_dma_uart_rx_boot_object.py`、`test_dma_uart_rx_uart_schedule.py` 后为 `95 passed, 3 skipped`（数量只增不减）。

### 7.3 软件测试覆盖

- 固件布局/控制字/窗口/程序表；`MAIN+main<=MTVEC`、`ISR` 在 RAM 内；
- **RV32I 模型**（仅测试用解释器 + UART/DMA 行为模型，不是 RTL）：六组方向/多字参数各跑一次，断言 CPU 真实写出的 DMA 四寄存器、beats 地址/值、pop 序列、RAM 源字、TX 字节、ISR 五字；一次 boot 连跑三方向 + 多字四例，counter 单调；direction code 3 走声明非法目标（无 beat、status bit30、真实 IRQ/ISR）；`len` 未入队 payload 时模型在 DMA 空 pop 处失败（证明 pre-RTL 守卫的必要性）；
- 描述符解码掩码/长度/payload 相等/非法字段构造拒绝；窗口收窄、非法 offset 声明缺失、未知窗口、半开窗口语义；
- CPU pop 形状锁：默认 fixture 同时含顶层与内嵌副本（按 `access_id` 去重后仍为 4 个 CPU pop）；“只有第 4 次内嵌 `target_uart_access`”正例；两种副本都缺、内嵌缺 `access_id` 两个负例；
- push 深度字段锁：合成 journal 的 push tick 深度写 0..N-1（与真实 pinned 采样一致），证书要求整条 push tick 流恰为 0..n-1、下一 tick = +1 且链连续；负例覆盖“深度不递增”“push 数据字段不符”“push 后缺少 tick 样本”“跳号”“重复”“起点非空”“push 缺失”，防止退回把 push tick 深度当压入后深度或用 host 计数；
- plan↔spec 硬 join（值/action id/分量/端口/位宽）；
- 合成 journal 正例（三方向、len 1/2/3/4）与负例：缺 frame/pop/beat/RAM commit/source_start/cpu take/external take 必失败；篡改 counter/payload store/frame/pop 必失败；host 写被测地址必失败；TX 捕获不匹配必失败；DMA pop 不得被洗成 CPU pop；
- fake-runner boot 机制：一次 boot 两例的 plan 源字节/action id 完全一致、command/event/tick 边界链接、拒绝不消费、ISR 不完成时保留尝试边界与 prefix digest。

### 7.4 真实门第一次失败与修复（8dd3e70）

主会话在冻结快照 `8dd3e70` 上首次运行真实门，第一例 `RX_TO_RAM len=1` 在 4793 commands 后失败：

```
RuntimeError: UART RX FIFO push lacks a real depth
dma_uart_descriptor_runtime.py:571  push_depths=... event['post'].get('probe_uart_fifo_depth')
```

真实快照的第一例 5 个 push（对应 4 描述符 + 1 payload）在 push tick 的 `pre/post.probe_uart_fifo_depth` 都依次为 **0,1,2,3,4**（主会话 probe log：`PRE_DEPTH == POST_DEPTH`；event_id 3595/7062/10521/13988/17447，tick 851/1717/2581/3447/4311），即该 tick 记录的是**压入前占用**；旧实现断言 `>=1`，于是第一个 push（0）被误判为“缺 depth”。

**根因（真实 RTL 采样语义，不是字段缺失）**：pinned `uart_tick_observation` 在 push strobe 的那个 tick，`post.probe_uart_fifo_depth` 仍是被压入前的占用；写入的字节出现在 `post.probe_uart_fifo_data`（真实样本：`event_id=3587, local_tick=851, post{wvalid=1,wready=1,depth=0,data=90}`），深度 +1 出现在**下一个 tick 样本**（`event_id=3591, local_tick=852, post{depth=1,head=90,rvalid=1}`）。旧实现把 push tick 的 depth 当作压入后深度并断言 `>=1`，因此第一例失败（不是 host 计数、也不是没有 depth）。

**修复（不删断言、不伪造）**：`_push_depth_chain` 只读真实 journal：

1. push tick 必须 `post.wvalid==1 && wready==1`，且 `post.probe_uart_fifo_data == 声明 byte`；
2. push tick 的 `depth_before` 序列必须**恰好是 0..n-1**（n = 4+len；残留/跳号/重复/缺失都会失败），且 `depth_before[-1] + 1 == n`；
3. 取 journal 中紧随其后的真实 tick 样本（且其 `wvalid != 1`，即不是另一个 push），要求 `post.probe_uart_fifo_depth == depth_before + 1`，即真实压入后占用；
4. 相邻 push 的 `depth_before` 必须等于上一个 `depth_after`（深度链连续）；
5. 记录 `fifo.push_chain`（tick、byte、depth_before/after、head_after、下一 tick、event id）与 `push_depths`（=1..4+len）。

新增负例：push 后深度不递增、push 数据字段不符、push 后缺少 tick 样本、深度跳号、深度重复、case 起点 FIFO 非空（整体 0..n-1 被平移）、push 缺失都必须失败；正例的 push tick 深度写成 0..N-1（与真实 0,1,2,3,4 完全一致），若实现退回把 push tick 的深度当压入后深度会立即失败。这锁住了正确字段与语义，且证据仍全部来自真实 RTL 采样。

**说明**：S1b 的 `dma_chain_feedback` 把 `fifo_push_depth_*` 直接建在 push tick 的 `post.probe_uart_fifo_depth` 上，该桶在真实证据里恒为 0；它只是搜索 feature，不是 authority，S2 未改它（避免动 S1b 证据），留给 S4 typed feedback 统一修正。

### 7.5 真实门第二次失败与修复（90652e9）

第二次真实门（快照 `90652e9`，复用 cache）通过了 push-depth 检查，但第一例 `RX_TO_RAM len=1` 又失败：

```
RuntimeError: CPU must pop exactly the descriptor and drained payload bytes
```

**根因（真实 journal 形状）**：4 次 CPU UART RDATA 只有 3 个顶层 `uart_rdata_access`（tx7/9/11，event 18476/18621/18766）；第 4 次（tx13，`read_value=90`，`mmio_delivery` event 18849）只存在于 `mmio_delivery.target_uart_access` 内嵌对象（`kind='uart_rdata_access'`、`read_value=90`、`read_capture` 齐全、**无 event_id**）。`extract_case_witnesses` 只数顶层事件，于是得到 3 个 pop。

**修复（不降级、不用 host 计数）**：`_merge_cpu_pops` 同时读取两种真实形状：

1. 顶层 `uart_rdata_access`（`source_transaction.channel_id='data'`）；
2. CPU `mmio_delivery`（`device_id='uart'`、`offset=0x18`、`write=false`）里的 `target_uart_access`（`kind='uart_rdata_access'`）；
3. 按真实 `access_id` 去重，同一次访问只计一次；内嵌-only 的 pop 以承载它的 `mmio_delivery.event_id` 作为 journal 锚点并参与顺序排序；
4. 内嵌对象缺真实 `access_id` 时**忽略而不猜测**，计数会不足并在证书里明确报 top_level/nested 计数；
5. 计数断言不变：`4 + len`（RX 为 4，RAM/TX 为 4+len）；`fifo.pops[].source` 记录 `top_level`/`nested`。

**测试**：合成 fixture 现在对每个 CPU pop 同时写顶层与内嵌副本（默认路径正例断言 4 个 CPU pop 且 source 全为 top_level，证明按 access_id 去重而非按值/计数）；新增“只有第 4 次内嵌副本”的正例（source 为 top_level×3 + nested，pop 值仍完整）；新增“两种副本都缺”“内嵌缺 access_id”两个负例。`54 passed`。

**状态**：修复后真实门重新排队；两次失败记录都是失败证据，不是通过证据。

## 8. 真实 RTL 门（排队，未运行）

```sh
MYFUZZ_DMA_DESCRIPTOR_REAL=1 \
MYFUZZ_DMA_DESCRIPTOR_CACHE=<cache> \
MYFUZZ_DMA_DESCRIPTOR_EVIDENCE=<evidence> \
PYTHONPATH=src timeout 1800 python3 -m pytest -xq \
  tests/integration/test_dma_uart_descriptor_real.py
```

- 一次 boot 六例：RX len1 / RX len3 / RAM→RAM len1 / RAM→RAM len2 / RAM→TX len1 / RAM→TX len2；期望 `1 passed`；
- 每例真实 FIFO pop、`2*len` 个真实 DMA beat、len 个真实 RAM commit 版本（TX 除外）、真实 IRQ→ISR、TX peer 捕获、fresh 全前缀 replay 逐例相等；
- 保存 `descriptor.json.gz`、`fresh.json.gz`、`cases.json`、`multiword-readings.json`（首例 len>1 的真实 status/nread/blocklen）、`source_pins.json`、`manifest.json`；
- 内部 `ResourceBudget(max_wall_time_ms=600000)`，外层 `timeout 1800` 只作兜底，不替代内部预算；
- **首次尝试（8dd3e70）已失败并修复**（见 §7.4）；修复后必须在冻结快照重跑，且旧的失败不构成通过证据；
- **排队原因**：S1/P7 的真实门共用 build cache，当前 P7 I3 并行写源码；现在跑会改变/漂移尚未重基线的 build identity。等 root 冻结后由主会话串行执行。

## 9. 诚实边界与风险

1. **S3/S4 未做**：没有 invalid 例的真实 error status bit30 观测，没有 CPU error ISR，没有 admission/ownership/edge index/UART consumption accepted，`fifo_origin` 保持 `unknown`，`source_authority=incomplete`。P8 整体不通过。
2. **TX 捕获来源**：S2 用真实 UART peer 的串行捕获（`uart.peer.captured`），不是 journal 的 `uart_serial_tx_capture`；后者按设计留到 S4，且 fresh replay 通过逐例证据里的 `tx_captures` 比较。
3. **多字依赖控制字偏离**：见 §3.1；若评审否决，多字 FIFO 读无法成立，需要回到设计稿修订或另立增量。
4. **TX drain 上界**：`320*len+320`，比设计稿的 `320*len` 多一个空闲帧的相位余量；只用于宿主上界，不进入证据因果字段。
5. **全部源帧先入队**：每例先把 `4+len` 个 frame 全部排入再推进 CPU，依赖 pinned UART RX FIFO depth 64（单例最多 8 字节）；若后续把 `len` 上限提高或 FIFO 变浅，需改回逐字节交替。
6. **真实读值不预写**：ISR 的 status/length 只记录；`wbdmac cfg_len` 在传输中递减、status 由 idle/error/nread/blocklen 组成，必须由真实门建立基线（`multiword-readings.json`），S3 才能断言 error bit。
7. **`dst_index` 在 RAM→TX 无运行时作用**：仍解码/校验/记录，但不改变 WDATA 目的；这一点在报告中明确，避免“看起来被使用”。
8. **ISR PC 绑定**：证书按 `ISR_PCS` 固定 PC 校验 RVFI load/store；任何固件改动都必须同时更新 `ISR_PCS`、合成 fixture 和真实门。
9. **软件模型不是 RTL 证据**：RV32I 解释器只验证指令流/解码/寄存器配置；它不证明 Verilator 波形、FIFO 时序、wbdmac 握手或 IRQ 时序。
10. **未覆盖**：PLIC、物理总线仲裁、共享时钟、多主并发、CPU 程序字节变异（S5）。

## 10. 审计清单（真实门跑完后按此复核）

- [ ] 六例方向覆盖（每方向 ≥1）且 ≥2 个 `len>1`；`beat_count` 与 `2*len` 相符；
- [ ] 每例 FIFO push=pop=`4+len`；push 深度来自 push 后第一个真实 tick（+1 且链连续）；CPU pop 来自顶层+内嵌两种真实形状并按 `access_id` 去重；RX 的 DMA pop pre-depth 递减 `len..1`；
- [ ] 每例 CPU DMA 四寄存器写值与 `descriptor_program` 相等；CONTROL key=`0xfed`；
- [ ] 每例 `mcause=0x8000000b`、`status_error=0`、payload/counter 正确；`status/nread/blocklen/length` 原样记录；
- [ ] 每例 status bit29/28 与 CONTROL 的 inc_s_n/inc_d_n 一致（多字固定端回读）；
- [ ] IRQ edge tick = `source_start.source_tick`；take 与 start `source_event_id` 相等；external tick = take `cpu_tick`；
- [ ] RAM commit version 严格递增；TX 捕获逐字节等于 payload；非 TX 无捕获；
- [ ] 无 component ∉ {cpu,dma} 的受保护地址 store；
- [ ] fresh：新 native UUID、identity 文档相等、plan/events/ticks/每例证据相等；
- [ ] `fifo_origin='unknown'`、`source_authority='incomplete'` 未被改写；
- [ ] `source_pins` 426+ 文件前后相等（新模块已自动进入 pin 集合）。

## 11. 提交

- 增量提交信息以 `P8 S2:` 开头，只包含本增量新增的源/测试/报告/证据。
- P8 状态：**仍不通过**（S3/S4 未做；真实门排队）。
