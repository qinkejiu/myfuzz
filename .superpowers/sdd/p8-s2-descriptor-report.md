# P8 S2 实现报告：外部串行描述符固件 + 单 boot 三方向 + 多字 FIFO

- 增量：P8 S2（只做 S2；不做 S3 真实 error ISR、不做 S4 认证/typed normalizer/前缀 replay）
- 日期：2026-10-18
- 状态：源码 + 纯软件测试已提交。真实门已尝试六次并均失败：`8dd3e70`（FIFO push depth 采样语义，§7.4）、`90652e9`（CPU RDATA pop 只在 mmio_delivery 内嵌 `target_uart_access`，§7.5）、`457d411`（RAM commit 与 write beat 的真实顺序，§7.6）、`73eb811`（`source_start` 与 external take 的真实顺序，§7.7）、`c0b7ab8`（case 在 COMPLETED store retirement 之前被截断，§7.8）、`e5c4689`（迟到的顶层 `uart_rdata_access` 跨 case 重复计数，§7.9）。六次都已按真实 journal 修复并补负例锁字段；**修复后的真实门重新排队，尚未在冻结快照重跑**。P8 整体仍不通过。
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
- **FIFO**：每个串行字节恰好一次 `uart_tick_observation` post `wvalid&wready` push；push 的**真实深度按 pinned 采样语义从下一个 tick 样本读取**——push strobe 那个 tick 的 `post.probe_uart_fifo_depth` 仍是压入前占用（真实样本：push tick post depth=0/data=90，下一 tick post depth=1/head=90），证书要求“push tick 深度流恰为 0..n-1、下一 tick 的 depth = 本 tick 的 depth+1”、`push.post.probe_uart_fifo_data == byte`、相邻 push 的深度链连续；CPU pop 数 = 4（RX）或 4+len（RAM/TX），pop 来源同时接受**顶层 `uart_rdata_access`** 与**CPU `mmio_delivery.target_uart_access` 内嵌副本**，按真实 `access_id` 去重（真实 journal 的 4 次 RDATA 可能只有 3 个顶层事件，第 4 次只在 delivery 内嵌对象里），**且 boot 维护跨 case 的已计 `access_id` 集合**：上一 case 的 nested-only access 的迟到顶层事件落入下一 case slice 时不再重复计数；`fifo.pops[].source` 记录 top_level/nested；RX 的 DMA pop 数 = len；每个 pop 都有 `pre/post` 真实 depth/head/rvalid/rdata_re 探针，`post.depth = pre.depth-1`、`pre.head = byte`；总 push = 总 pop = 4+len；
- **CPU 真实配置**：DMA 的 `mmio_delivery` 写序列必须是 `(8,SOURCE),(12,DEST),(4,LEN),(0,CONTROL)`，值与 `descriptor_program` 完全一致；CONTROL key=`0xfed`；witness 指针 store 早于 CONTROL；RX 无 RAM 源写，RAM/TX 有 len 次真实 CPU store 且早于首个 DMA read；
- **DMA beats**：恰好 `2*len` 个 accepted beat，逐字 read→write；地址等于声明源/目的 beat 地址；read/write 的 transaction 身份同源、`source_sequence` 相邻且全程严格递增不重复（“不重复执行”）；RAM 源读的 response `rdata == payload`；RX 读的 target delivery 带真实 UART FIFO pop 证明；TX 写的 target delivery 地址 WDATA、值 payload；
- **RAM commit**：目的方向恰好 len 个 `memory_write(component='dma')`，值 payload、`version` 存在且严格递增；每个 commit 的真实区间是 `read_beat.event_id < commit.event_id < 下一个 read_beat.event_id`（真实 journal 为 read → commit → write edge；最后一字的区间由 IRQ 顺序闭合），不再错误要求 `write_beat < commit`；TX 方向无目的 RAM commit；
- **IRQ/ISR**：恰好一个真实 DMA 完成脉冲（`mwb_ack=1,mwb_we=1,mwb_err=0` 且 physical 置位）→ `source_start` → `cpu_external_irq_taken` → `cpu_irq_taken`，顺序为 `last_write < irq_edge < source_start < external < take`（真实 journal 里 source window 先于 CPU 对外部线的采样），且 `source_event_id` 相同、`take.cpu_tick == external.local_tick`、`source_tick == native_local_tick`；case slice 在正确 COMPLETED write 之后继续有界推进到 ISR counter store 的真实 retirement（并尽量覆盖 MRET 与返回主循环），否则 `_retire` 会缺 PC；ISR 的 `mcause=0x8000000b`、status、length、payload、counter 各恰好一次 store；status/length 有真实 MMIO delivery + `data_response`；`cpu_retire` 在 `ISR_PCS` 固定 PC 上验证 load/store 的地址/掩码/数据/寄存器（status x7、length x8、witness x9、counter x9）；
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
# 68 passed

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
# 88 passed, 4 skipped

PYTHONPATH=src python3 -m pytest -q \
  tests/integration/test_dma_uart_rx_search.py \
  tests/scenario/test_dma_chain_feedback.py \
  tests/integration/test_dma_uart_rx_discovery_scope.py
# 30 passed
```

4 个 skip = 3 个既有 explicit-native 门 + 新的 queued descriptor 门。focused 列表并入 S1a/S1c 的 `test_dma_uart_rx_boot_object.py`、`test_dma_uart_rx_uart_schedule.py` 后为 `109 passed, 3 skipped`（数量只增不减）。

### 7.3 软件测试覆盖

- 固件布局/控制字/窗口/程序表；`MAIN+main<=MTVEC`、`ISR` 在 RAM 内；
- **RV32I 模型**（仅测试用解释器 + UART/DMA 行为模型，不是 RTL）：六组方向/多字参数各跑一次，断言 CPU 真实写出的 DMA 四寄存器、beats 地址/值、pop 序列、RAM 源字、TX 字节、ISR 五字；一次 boot 连跑三方向 + 多字四例，counter 单调；direction code 3 走声明非法目标（无 beat、status bit30、真实 IRQ/ISR）；`len` 未入队 payload 时模型在 DMA 空 pop 处失败（证明 pre-RTL 守卫的必要性）；
- 描述符解码掩码/长度/payload 相等/非法字段构造拒绝；窗口收窄、非法 offset 声明缺失、未知窗口、半开窗口语义；
- CPU pop 形状锁：默认 fixture 同时含顶层与内嵌副本（按 `access_id` 去重后仍为 4 个 CPU pop）；“只有第 4 次内嵌 `target_uart_access`”正例；两种副本都缺、内嵌缺 `access_id` 两个负例；
- RAM commit 区间锁：真实 read→commit→write 形状（len=1/2）正例；commit 早于自己的 read、晚于下一 read、错误 value、重复 version 四个负例；
- IRQ take 顺序锁：真实 irq edge → source_start → external → take 正例；external 早于 start、take 早于 external、start tick 不匹配、take 身份不匹配四个负例；
- case 封存锁：fake boot 断言 COMPLETED 后继续到 store retire/MRET/主循环；COMPLETED 但缺 store retire、COMPLETED 值错误两个负例；
- 跨 case 去重锁：nested-only access 的迟到顶层事件/迟到 nested delivery 在下一 case 不得重复计数（无 settled 必失败，有 settled 仍为 4）；
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

### 7.6 真实门第三次失败与修复（457d411）

第三次真实门（快照 `457d411`，父提交含 P7 I3 `53a9b7b`）通过了 push-depth 与嵌套 CPU pop 两项修复，但第一例 `RX_TO_RAM len=1` 又失败：

```
RuntimeError: DMA RAM commit is not the accepted write beat effect
```

**真实 event 顺序**（主会话给出）：DMA read beat `dma_edge.event_id=19530` → DMA `memory_write` commit `event_id=19591, addr=143360, value=90, version=(0,7)` → DMA write beat `dma_edge.event_id=19592`。即一个字的真实 journal 是 **read → commit → write edge**；旧断言 `write_event_id < commit_event_id` 与真实顺序相反（S1 的注释也说明 memory service 可能先 commit 后 retirement/edge）。

**修复**：`certify_descriptor_case` 改为按每个 beat 的真实 read 区间校验：

- `read_event_id < commit_event_id`；
- 若存在下一个字：`commit_event_id < next_beat.read_event_id`；
- 最后一字的区间由后续 `last_write < irq_edge < external < source_start < take` 顺序闭合；
- **保留** address、value payload、version 存在且严格递增的断言；错误信息改为 `DMA RAM commit is not inside its accepted read beat interval`。

**测试**：合成 fixture 增加 `commit_before_write=True` 的真实形状（read → commit → write），正例覆盖 len=2 与 len=1；负例锁区间（commit 早于自己的 read、commit 晚于下一 read）并保留 value/version 断言（错误 value、重复 version 都必须失败）。`59 passed`。

**状态**：修复后真实门重新排队；三次失败记录都是失败证据，不是通过证据。

### 7.7 真实门第四次失败与修复（73eb811）

第四次真实门（快照 `73eb811`）通过了前三项修复，但第一例 `RX_TO_RAM len=1` 又失败：

```
RuntimeError: DMA completion/IRQ/CPU take order is incomplete
```

**真实 event 顺序**：`dma_edge` IRQ edge `event_id=19619, native_tick=196` → `source_start` `event_id=19622, source_tick=196` → `cpu_external_irq_taken` `event_id=19653, cpu_tick=182` → `cpu_irq_taken` `event_id=19655`。即 **source window 先打开，CPU 之后才采样外部中断**；旧断言写成 `irq_edge < external < start < take`，把 external 放在 start 之前，与真实 journal 相反。

**修复**：顺序断言改为 `last_write < irq_edge < source_start < external < take`；保留所有 join：`source_start.source_event_id == cpu_irq_taken.source_event_id`、`cpu_irq_taken.cpu_tick == cpu_external_irq_taken.local_tick`、`source_start.source_tick == irq_edge.native_local_tick`。

**测试**：合成 fixture 改为真实顺序（irq edge → source_start → external → take），正例显式断言这四个 event id 严格递增；负例锁 external 早于 start、take 早于 external、source_start tick 不匹配、take 身份不匹配。`64 passed`。

**状态**：修复后真实门重新排队；四次失败记录都是失败证据，不是通过证据。

### 7.8 真实门第五次失败与修复（c0b7ab8）

第五次真实门（快照 `c0b7ab8`）通过了前四项修复，但第一例失败：

```
RuntimeError: ISR PC 0x10464 lacks exactly one real retirement
```

**真实 journal**：`isr_counter_load=0x1045c` 有 retire eid 22912、`0x10460 addi` 有 retire eid 22928、`COMPLETED` `memory_write` eid 22934（value=1）已出现，但 `0x10464 sw` 的 `cpu_retire` 还没出现。`DescriptorBoot` 的 poll 循环一看到 COMPLETED write 就 break，导致 case slice 截断在 store retirement/MRET 之前，`_retire` 自然找不到 0x10464。

**修复**：`_execute_case` 在确认唯一且正确值的 COMPLETED write 之后不立即封存，继续有界推进（`COMPLETION_ROUNDS=64`）直到出现 `isr_counter_load+8` 的真实 store retirement；同时尽量捕获 `isr_counter_load+12`（MRET）与 `MAIN ≤ pc < ISR` 的返回主循环 retirement（看到即停，不强制）。保留失败语义：错误值/重复的 COMPLETED write 立即失败；64 轮内仍无 store retirement 则硬失败（`CPU ISR counter store retirement is missing after COMPLETED`）。模板 steps 相应增加每例 `3*COMPLETION_ROUNDS`。

**测试**：fake boot 在 COMPLETED 之后依次产生 store retire → MRET retire → 主循环 retire，正例断言 case slice 同时包含这三个 PC；负例覆盖“有 COMPLETED write 但没有 store retire”（有界后硬失败）与“COMPLETED 值错误”（立即失败）。`66 passed`。

**状态**：修复后真实门重新排队；五次失败记录都是失败证据，不是通过证据。

### 7.9 真实门第六次失败与修复（e5c4689）

第六次真实门（快照 `e5c4689`）通过了前五项修复，在一个后续 case（`command_count=11279, case_start=23086`）失败：

```
RuntimeError: CPU must pop exactly ... (4 pops; top_level=4, nested=1)
```

期望 4 个 CPU pop，实际 5 个。

**根因（跨 case 的迟到事件）**：前一 case 的第 4 次 access 只有 nested `target_uart_access`（当时按 `access_id` 计入，且该 nested 对象没有 event_id）；它的顶层 `uart_rdata_access` 迟到，落到**下一 case** 的 slice 里。per-case 的 `_merge_cpu_pops` 只在单个 slice 内按 `access_id` 去重，跨 case 未去重，于是同一 access 被算第二次。

**修复（boot 级跨 case 去重，计数断言不变）**：

1. `DescriptorBoot` 维护 `settled_access_ids`（本 boot 已计入的 CPU access id），replay 在同样的 case 顺序上维护同一集合；
2. `certify_descriptor_case` 接受 `settled_access_ids`，过滤已计的 CPU pop 和其迟到的内嵌 delivery，计数仍为 4 / 4+len；
3. 每个成功 case 的 `cpu_pop_access_ids` 加入集合；证据同时记录 `cpu_pop_access_ids`（本 case 计入）与 `settled_cpu_access_ids`（本 slice 被跨 case 过滤的迟到副本）；
4. 没有 real `access_id` 的 CPU pop 直接失败（不去猜），保证跨 case 去重有真实身份可依。

**测试**：上一 case 的 nested-only access + 下一 case 迟到的同 `access_id` 顶层事件——无 settled 时得到 5 并失败，有 settled 时仍为 4 且 `settled_cpu_access_ids` 记录迟到 id；另有迟到 nested delivery 变体。`68 passed`。

**状态**：修复后真实门重新排队；六次失败记录都是失败证据，不是通过证据。

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
- [ ] 每例 FIFO push=pop=`4+len`；push 深度来自 push 后第一个真实 tick（+1 且链连续）；CPU pop 来自顶层+内嵌两种真实形状并按 `access_id` 去重，且跨 case 的迟到副本按 boot 级 `settled_access_ids` 过滤；RX 的 DMA pop pre-depth 递减 `len..1`；
- [ ] 每例 CPU DMA 四寄存器写值与 `descriptor_program` 相等；CONTROL key=`0xfed`；
- [ ] 每例 `mcause=0x8000000b`、`status_error=0`、payload/counter 正确；`status/nread/blocklen/length` 原样记录；
- [ ] case slice 含 ISR counter store 的真实 retirement（并尽量含 MRET/返回主循环）；
- [ ] 每例 status bit29/28 与 CONTROL 的 inc_s_n/inc_d_n 一致（多字固定端回读）；
- [ ] 顺序 `last_write < irq edge < source_start < external < take`；IRQ edge tick = `source_start.source_tick`；take 与 start `source_event_id` 相等；external tick = take `cpu_tick`；
- [ ] RAM commit version 严格递增且落在 `read_beat < commit < next_beat.read` 区间（最后一字由 IRQ 顺序闭合）；TX 捕获逐字节等于 payload；非 TX 无捕获；
- [ ] 无 component ∉ {cpu,dma} 的受保护地址 store；
- [ ] fresh：新 native UUID、identity 文档相等、plan/events/ticks/每例证据相等；
- [ ] `fifo_origin='unknown'`、`source_authority='incomplete'` 未被改写；
- [ ] `source_pins` 426+ 文件前后相等（新模块已自动进入 pin 集合）。

## 11. 提交

- 增量提交信息以 `P8 S2:` 开头，只包含本增量新增的源/测试/报告/证据。
- P8 状态：**仍不通过**（S3/S4 未做；真实门排队）。
