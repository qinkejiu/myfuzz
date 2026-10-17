# P8 S3 实现报告：声明非法描述符 + 真实 CPU error ISR（成功/非法成对）

- 增量：P8 S3（只做 S3；不做 S4 来源认证、typed normalizer、逐语料前缀 replay）
- 日期：2026-10-18
- 状态：源码 + 纯软件测试已实现并提交。真实 RTL 门两次尝试均失败并已按真实 journal 修复：第一次（`537585f`）是跨 case 迟到的 CPU RDATA 副本被误判（§8.3）；第二次（`0eff9a7`）是前一个 valid RX 用例的 **DMA payload pop** 迟到副本，因为 boot 只结算了 `cpu_pop_access_ids`（§8.4）。第二次修复后真实门由主会话重新排队，尚未重跑。S3 首次真实 error status 读数仍待该门观测；代码保持 fail-closed，并把测量写入独立 artifact；P8 整体仍不通过。
- 基线：S2 HEAD `00dd54d`；本增量提交时工作树 HEAD 已推进到 `38c7453`（P7 I3），S3 只叠加自己的文件。

## 1. 结论摘要

1. **启用 S3 的声明非法描述符，不新增 host 侧“发明失败”**：`DescriptorCase.create('ILLEGAL', ...)` 生成方向码 3 的外部串行描述符；固定固件把唯一声明的 `ILLEGAL_TARGET=0x50000020` 同时写入 DMA SOURCE/DEST，CPU 真实写出四寄存器，真实 `wbdmac` 在第一个 master read 上收到 `i_mwb_err=1`，进入 IDLE、置 `cfg_err`、拉起原生 IRQ；CPU 真实 take，真实 ISR 读真实 status(0)/length(4)/witness 并保存 `mcause/status/length/payload/counter`。
2. **固件字节没有改动**：S2 固件的 `path_illegal` 分支、`ILLEGAL_TARGET` 和 `descriptor_program('ILLEGAL', ...)` 已经能在真实 RTL 上走通；S3 只把运行时从“pre-RTL 拒绝”改为“声明 + 真实证据认证”，因此 S2 的固件布局/镜像/ISR PC/控制字全部保持字节级不变，S2 成功例仍全绿。
3. **每例证据新增 error variant**：`outcome='environment_error'`、`completed=False`、`sealed=True`、`error_path='declared_illegal_master_target'`、`environment_error_receipt`（真实 receipt）、`environment_error`（收据/响应/IRQ/status/length/witness/counter 摘要）、`no_target_delivery=True`、`destination_committed=False`、`beats=[]`、`ram_commits=[]`、`fifo.dma_pops=0`。成功例新增 `outcome='complete'`、`sealed=True`，并统一记录 `status_bits`/`status_busy`/`status_layout`。
4. **分类诚实**：`dma_chain_feedback` 读取真实 journal 的顶层 `environment_error_receipt`（S1b 之前只看 `payload` 内的事件，真实 S3 形状不会被计数）、`accepted.target_rejection` 与 ISR status 的声明 error bit；error slice 的 `completed_chain` 恒为 `False`，即使同一 slice 混入 stray dataflow 也不会被当成成功链。
5. **纯软件**：新增 `tests/integration/test_dma_error_isr.py`（53 个用例，含 1 个“已测量 fixture 存在才断言”的可选用例，当前 skip）；focused 门实测 **162 passed, 6 skipped**；S1b 搜索回归 **32 passed**。
6. **真实门两次失败已修复、重新排队**：新增 `tests/integration/test_dma_error_isr_real.py`（一次 boot 3 valid + 3 invalid，fresh 全前缀 replay，写 `error-status-measured.json`）。第一次失败于跨 case 迟到的 CPU RDATA 副本；第二次失败于前一个 valid RX 用例的 DMA payload pop 迟到副本（boot 只结算 CPU pop id）。修复后未重跑。

## 2. 变更文件

| 文件 | 类型 | 内容 |
| --- | --- | --- |
| `src/myfuzz/scenario/ibex_dma_uart_descriptor.py` | 修改 | `DECLARED_DIRECTIONS`（三方向 + `ILLEGAL`）；`ILLEGAL` 只读声明程序；wbdmac status 位布局常量与纯函数 `dma_status_fields`；文档说明 S3 已启用 |
| `src/myfuzz/integration/dma_uart_descriptor_runtime.py` | 修改 | `ILLEGAL` case 构造/校验；真实 error 事件分组；`_certify_environment_error`；error 证据；成功例 `outcome/sealed/status_bits`；outcome 一致性检查 |
| `src/myfuzz/scenario/dma_chain_feedback.py` | 修改 | 真实顶层 error receipt；`env_error`/`no_target_effect` 单次计数；`status_error`/`status_bits`；error slice 不构成 completed chain |
| `tests/integration/test_dma_uart_descriptor.py` | 修改 | 仅更新 3 个被 S3 明确取代的 S2 断言（ILLEGAL 由“构造拒绝”改为“声明 error case”），其余 S2 测试原样保留 |
| `tests/integration/test_dma_uart_descriptor_real.py` | 修改 | manifest claim 由 `S3 not implemented` 改为指向独立 S3 门；测试逻辑不变 |
| `tests/integration/test_dma_error_isr.py` | 新增 | 固件非法路径（RV32I 模型）、真实形状合成 journal 正例、状态/收据/响应/IRQ/take/ISR 负例、feedback 分类、可选测量 fixture |
| `tests/integration/test_dma_error_isr_real.py` | 新增 | opt-in 真实门：一次 boot 3 valid + 3 invalid，测量 status，fresh 全前缀 replay |
| `tests/scenario/test_dma_chain_feedback.py` | 修改 | 新增真实顶层 receipt 与 status error bit 分类用例（原作用例不变） |
| `.superpowers/sdd/p8-s3-error-isr-report.md` | 新增 | 本报告 |

未修改 `agent.md`、`third_party/`、RTL、`fifo_origin`、contracts；未写 root-owned evidence 目录。

## 3. 真实 error 路径（源码与已保存真实证据）

### 3.1 固件/程序路径（未改固件字节）

`ILLEGAL` 方向码 3 的固定固件路径：

1. CPU 从真实 UART RX FIFO pop 4 个描述符字节，解码 `direction=3`、`len`、`dst_index`、`payload`；
2. 进入 `path_illegal`：`x15=x16=0x50000020`，把 `x4=DESTINATION` 写入 witness pointer，再真实 drain `len` 个 payload 字节（FIFO 收支守恒）；
3. 走公共 `configure`：真实 `sw` 写 `SOURCE=0x50000020`、`DEST=0x50000020`、`LEN=len`、`CONTROL=0x0fed0001`；
4. `wbdmac` 启动后第一个 master beat 是对 `0x50000020` 的 read；该 offset 在 UART window 内但不在声明的 `readable_offsets=(0x18,)`/`writable_offsets=(0x1c,)` 中，`GeneratedWishboneDmaSession` 走声明的 target rejection，不进任何 target 回调；
5. DMA session 返回 `mwb_err=1`（`ack=0`），`wbdmac` 进入 IDLE、`cfg_err<=1`，并在同一 error response 边沿拉起 `o_interrupt`（`wbdmac.v` 的 `o_interrupt` 对 `(dma_state != DMA_IDLE) && i_mwb_err` 置位）；
6. Runner 的声明 IRQ 通路（`Binding('dma','irq','cpu','irq',1)` + `irq_pulses=16`）把真实脉冲送到 CPU；CPU 真实 take；ISR 读真实 status/length 并写 `mcause/status/length/witness/counter`；main loop 观察 COMPLETED 递增后进入下一例。

### 3.2 已保存真实事件形状（不是本增量新造的）

`saved real evidence`：`docs/reports/evidence/dma-error-recovery-20261017/error-then-valid.json.gz`（真实 `wbdmac` 进程，`source=0x3000` 未映射）中的 error 序列与本次 UART target rejection 使用同一个 DMA session 形状：

- 第 1 个 `dma_edge`：`accepted={transaction,dma-memory, address, write:false, ...}`，顶层 `environment_error_receipt={error:1,target_effect:false,op:'master_environment_error',address,write:false,value,byte_enable:15,reason}`；
- 第 2 个 `dma_edge`：`response={transaction, rdata:0, error:1, delay:0}`，`payload.pre_backend.mwb_err=1`、`mwb_cyc=1`、`mwb_ack=0`、`mwb_we=0`，`payload.observations.physical` 为 1；
- 之后是真实 `source_start`/`cpu_external_irq_taken`/`cpu_irq_taken` 与 ISR stores/retirements。

本增量的 error 证据 join 逐项要求上述真实字段；合成 fixture 只用于纯软件负例，不作为 RTL 证据。

### 3.3 控制/状态位布局（来自 pinned `wbdmac.v`）

`third_party/soc-zipcpu/rtl/peripherals/wbdmac.v` 头部 30–60 行与 status 拼接（约 604–608 行）：

| bit | 名称 | S3 用途 |
| --- | --- | --- |
| 31 | busy (`dma_state != DMA_IDLE`) | ISR status 读时应为 0；error 证据断言 |
| 30 | `cfg_err` | **声明 error bit**；error 证据断言必须为 1 |
| 29/28 | `!cfg_incs`/`!cfg_incd`（写 CONTROL 的 inc_s_n/inc_d_n 回读） | 与 `CONTROL` 位逐位一致 |
| 26..16 | `nread` | 记录实际值，不预写 |
| 15..10 | trigger | 记录在原始 status 中 |
| 9..0 | `cfg_blocklen_sub_one` | 记录实际值，不预写 |

`dma_status_fields(value)` 只做上述**布局分解**，不添加期望值；evidence 同时保存原始 `status` 与 `status_bits`（所有置位 bit 的位置）。

## 4. 首次真实 error status 测量：明确未完成

**本增量没有运行真实 RTL 门，因此没有观测到 error 后的真实 status 字。**

- 代码**没有**写死 `0x40000000` 或任何完整 error status 值。纯测试使用合成 fixture 的 status 变量，并断言 evidence 原样回传该变量；另有一个“测量 fixture 存在才断言”的可选用例，当前因为尚无真实测量而 skip。
- error 认证只断言 RTL 源码声明的**位语义**：bit30=1、bit31=0、inc bits 与 CONTROL 一致；完整 32 位字原样记录到 `isr.status`、`isr.status_bits` 和 `error-status-measured.json`。
- 真实门 `test_dma_error_isr_real.py` 会把每个 invalid case 的 `status_raw/status_hex/status_bits/status_error/status_busy/status_nread/status_blocklen_sub_one/length_register` 写入 `<evidence>/error-status-measured.json`，并在同一进程内先观察后断言；fresh replay 要求同一 measured case 相等。
- **精确不确定性**：在真实门运行之前，无法知道 bit30 以外的实际置位集合、`nread`/`blocklen` 实际值，以及真实 status 是否与源码布局完全一致。若真实读数不满足 bit30=1/bit31=0/inc bits 一致，error case 会 fail-closed（不会降级为成功）。主会话跑完门后，应把 `error-status-measured.json` 的原始字段作为 S3 的正式测量基线，并把其中 exact word 复制到 `tests/integration/fixtures/dma_error_status_measured.json`（或设置 `MYFUZZ_DMA_ERROR_STATUS_FIXTURE`）以启用可选的精确 fixture 断言。
- 没有把“源码预期的 0x40000000”写进代码或报告当作已观测事实。

## 5. 每例 error 证据字段

invalid case 的 `certify_descriptor_case` 返回（成功例保留原有字段并新增 `outcome/sealed/status_bits/status_busy`）：

```
outcome="environment_error"
completed=false
sealed=true
error_path="declared_illegal_master_target"
environment_error_receipt={op,error:1,target_effect:false,address,write:false,
                           value,byte_enable:15,reason,transaction{stable fields}}
environment_error={request_event_id,response_event_id,receipt_event_id,
                   address,write:false,reason,target_effect:false,
                   data_beats:0,destination_commits:0,fifo_dma_pops:0,
                   no_target_delivery:true,destination_committed:false,
                   status,status_bits,status_error,status_busy,status_nread,
                   status_blocklen_sub_one,status_inc_s_n,status_inc_d_n,
                   length,mcause,counter,witness,witness_pointer}
no_target_delivery=true
destination_committed=false
beats=[]        beat_count=0
ram_commits=[]  cpu_source_versions=[]
cpu_pop_access_ids=[...]  settled_cpu_access_ids=[...]
settled_dma_rdata_access_ids=[...]   # 本 slice 过滤的迟到/内嵌 CPU RDATA 副本 id
fifo={pushes,push_depths,push_chain,pops(cpu only),dma_pops:0,depth_after,max_depth}
isr={mcause,status,status_bits,status_layout,status_nread,
     status_blocklen_sub_one,status_error,status_busy,
     status_inc_s_n,status_inc_d_n,control_inc_s_n,control_inc_d_n,
     payload:null,witness,counter,...event ids}
irq={edge_event_id,edge_tick,error:true,source_start_event_id,
     source_tick,cpu_take_event_id,external_event_id,external_tick}
tx_captures=[]  tx_capture_count=0
fifo_origin="unknown"  source_authority="incomplete"
proof_grade="bounded_historical_chain"
```

`environment_error_receipt.transaction` 不含 execution UUID（fresh replay 逐例 dict 比较必须稳定）；原始 receipt 仍在 `events` 里，由 `_normalize` 处理执行身份。

## 6. 认证的硬 join（任一缺失即失败）

- **源**：4+`len` 个真实 matched frame/injection，字节与 spec 完全一致；真实 FIFO push 链 0..n-1 且下一 tick +1。
- **CPU drain**：CPU RDATA pop 恰为 4 或 4+`len`（ILLEGAL 为 4+len），值等于描述符 + payload；每个 pop 的 access id 真实、跨 case 按 boot `settled_access_ids` 去重；所有 CPU pop 的 journal id **早于**非法 master request（证明 ERR 后无 FIFO pop）。
- **CPU 程序**：真实 DMA 四寄存器写恰好 `(8,0x50000020),(12,0x50000020),(4,len),(0,0x0fed0001)`；witness pointer 写入早于 CONTROL。
- **拒绝**：恰好一个 accepted master request，`write=false`、地址=声明非法 target、`target_rejection='declared_master_target_access'`、`target_delivery` 不存在；顶层 `environment_error_receipt` 恰一个且与 request 同 event id / 同 transaction，字段逐项为声明 rejection。
- **ERR 响应**：恰好一个 error response，transaction 与 request 相同、`error=1`、`rdata=0`、晚于 request；该 response event 就是唯一原生 error IRQ 边沿（physical IRQ=1，`pre_backend.mwb_err=1`、`mwb_ack=0`、`mwb_we=0`）。
- **无目标效果**：整个 case slice 无任何 `target_delivery`；无真正 DMA master RDATA access（不弹 FIFO）。boot 在每例认证后把该例**所有** FIFO pop 的 `access_id`（CPU + DMA，取自 `fifo.pops[].access_id` 与 `cpu_pop_access_ids`）并入 `settled_access_ids`；带真实 `access_id` 且已 settled 的 UART RDATA access 视为前 case 的迟到/内嵌 CPU 或 DMA 副本并过滤（记入 `settled_dma_rdata_access_ids`）；无 access id 或 id 不在 settled 的 RDATA access 仍是硬失败。`SOURCE_RAM/DESTINATION` 区间无任何 memory_write（无目的 RAM commit、无源字物化）。
- **IRQ/take**：唯一 `source_start` → `cpu_external_irq_taken` → `cpu_irq_taken`，三者与 error pulse 的 tick/`source_event_id` 互等；顺序 `response < start < external < take`。
- **ISR**：`mcause=0x8000000b`、status/length/witness/counter 各恰一次真实 CPU store，并有对应真实 `cpu_retire`；status/length 有真实 MMIO delivery + `data_response`；status 的 declared error bit=1、busy=0、inc bits 与 CONTROL 一致；length 等于程序中写出的 `len`（read-phase error 不递减 `cfg_len`）；witness 值原样读取并与 RVFI load/store 相等；counter 从 `case_index-1` 递增到 `case_index`。
- **无 TX**：invalid case 不得有串行 TX 捕获。
- **成功例反向保护**：`complete` case 若出现任何 receipt/rejection/error response，直接失败，不能被误认证为成功。

## 7. `dma_chain_feedback` 分类

- `env_error`：真实连接形状为顶层 `environment_error_receipt`；也接受 S1b 旧 `payload.error=1` 与 `accepted.target_rejection`，但同一 `dma_edge` 只计一次。
- `no_target_effect`：`accepted.target_rejection` 存在时计数；被拒绝的 accepted 不再计 `dma_master_read/write`。
- `status_error`/`status_bits`：从 ISR status store 的真实值按声明 bit30 分类；`isr_status_error` 是 `EXTRA_FEATURES` 诊断桶（不是 coverage 声明）。
- `target_error=True` 时 `completed_chain` 恒为 `False`，即使 slice 混入 stray DMA write/pop；`DMA_FEATURES` 冻结 tuple 未改。

## 8. 测试（已实际运行）

### 8.1 新增/修改测试

```sh
cd /home/qinkejiu/myfuzz
PYTHONPATH=src python3 -m pytest -q tests/integration/test_dma_error_isr.py
# 53 passed, 1 skipped
```

覆盖：ILLEGAL 固件路径（len 1..4，真实 program 四寄存器、无 beat、无目的写、FIFO 全 pop、ISR 结果）；真实形状合成 error journal 正例；status 原样回传（非规范 word）；成功/失败互斥；完整 case 不得带 receipt；缺失/篡改 receipt、response、error pulse、source_start、external、take、ISR stores/retirements、status bit、busy、inc bits、length 全部失败；目的 RAM commit、DMA FIFO pop、data beat、TX capture 全部失败；feedback 分类；可选测量 fixture（当前 skip）。

```sh
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
  tests/integration/test_dma_uart_descriptor_real.py \
  tests/integration/test_dma_uart_rx_boot_object.py \
  tests/integration/test_dma_uart_rx_uart_schedule.py \
  tests/integration/test_dma_error_isr.py \
  tests/integration/test_dma_error_isr_real.py
# 162 passed, 6 skipped in 5.03s
```

6 skip = 3 个既有 explicit-native 门 + S2 descriptor real 门 + S3 error-ISR real 门 + 可选测量 fixture（尚未有真实读数）。

```sh
PYTHONPATH=src python3 -m pytest -q \
  tests/integration/test_dma_uart_rx_search.py \
  tests/scenario/test_dma_chain_feedback.py \
  tests/integration/test_dma_uart_rx_discovery_scope.py
# 32 passed in 7.78s
```

S2 原有 descriptor 测试 **68 passed**（其中 3 个被 S3 明确取代的断言已更新，其余原样）；S1b 搜索回归从 30 增至 32（新增 2 个 feedback 用例）。

### 8.2 RED/GREEN 说明

- RED：S3 前 `DescriptorCase.create('ILLEGAL')` 与 `expect='environment_error'` 被构造拒绝；没有 error 证据/分类；先写上述测试，构造/认证均失败。
- GREEN：上述测试全绿；S2 成功例、S2 描述符 real 门（skip）、S1b 搜索回归保持通过。
- 软件 fixture 抓到的实现问题：真实 receipt 在 `dma_edge` 顶层（不是 `payload` 内）；error response 与 native IRQ 同一边沿；`i_mwb_err=1` 边沿的 `pre_backend.mwb_ack=0/mwb_we=0`；witness pointer 在非法路径指向 `DESTINATION`，witness 值必须从 ISR store 实际读取而不能预设。

### 8.3 第一次真实门失败与修复（`537585f`）

主会话在冻结快照 `537585f` 上首次运行 S3 门，失败信息：

```
RuntimeError: an illegal DMA request must not pop the UART RX FIFO
```

真实 slice 的 `dma_rdata_accesses` 只有 1 条：`event_id=23107`、`offset=24 (0x18 RDATA)`、`read_value=90`、`access_id=uart-access:uart:0:10`、`source_transaction=None`。它不是 DMA 对 `0x50000020` 的读，而是**前一个 valid RX 用例**第 4 次 CPU RDATA access 的迟到顶层副本；该 access 在上一 case 只有 nested `target_uart_access` 被计入，其迟到顶层事件落入下一 ILLEGAL slice。

根因：跨 case 的 `settled_access_ids` 只过滤了 `cpu_pops` / `uart_rdata_mmio`，没有过滤 `dma_rdata_accesses`；且该事件的 `source_transaction=None` 被分到“非 CPU pop”分支。

修复（不降级、不猜测）：

1. `_certify_environment_error` 只在事件带真实 `access_id` 且该 id 在 boot 的 `settled_access_ids` 中时，把该 UART RDATA access 视为前 case 的迟到副本并从 `dma_rdata_accesses` 过滤；
2. 无真实 `access_id` 的副本**不**过滤（继续 fail-closed），因为无法证明它已结算；
3. 真正 DMA master RDATA pop（`raw_offset=0x18`、带 access id 但不在 settled）仍然是硬失败；ILLEGAL 的拒绝请求本身不产生任何 RDATA pop；
4. evidence 新增 `settled_dma_rdata_access_ids`（本 slice 被过滤的迟到副本 id），与 `settled_cpu_access_ids` 语义一致；错误摘要仍记录 `fifo_dma_pops=0`。

新增纯测试（3 个）：late CPU RDATA access 在 settled 时通过、不在 settled 时失败；无 access id 的迟到副本在 settled 下仍失败；真实 DMA RDATA pop 即使存在无关 settled id 仍失败。`test_dma_error_isr.py` 从 48 增至 **51 passed, 1 skipped**。

### 8.4 第二次真实门失败与修复（`0eff9a7`）

主会话在修复后的快照 `0eff9a7` 上重跑 S3 门，仍失败：

```
RuntimeError: an illegal DMA request must not pop the UART RX FIFO
```

真实数据：case1 的 `cpu_pop_access_ids` 是 `3,5,7,9`，`settled=[]`；case2 ILLEGAL slice 里的迟到 RDATA 是 `event_id=23107`、`offset=0x18`、`read_value=90`、`access_id=uart-access:uart:0:10`、`source_transaction=None`。该 id 是 **case1 的 DMA payload pop**（不是 CPU 读）：case1 的 `fifo.pops` 里已有这个 DMA pop 的 access id，但 boot 只把 `cpu_pop_access_ids` 加入 settled，所以 §8.3 的过滤条件不成立。

修复（不降级、不猜测）：

1. 新增 `_settled_pop_access_ids(evidence)`：收集 `cpu_pop_access_ids` 与 `fifo.pops[].access_id`（CPU + DMA），只接受真实非空字符串 id；
2. `DescriptorBoot` 每例认证后用它更新 `settled_access_ids`，而不是只更新 `cpu_pop_access_ids`；
3. `_replay_descriptor_cases` 的逐例 settled 更新改为同一 helper，保证 fresh replay 的迟到副本过滤与原始一致；
4. `_certify_environment_error` 的 `dma_rdata_accesses` 过滤保持不变：只有真实 id 在 settled 中才过滤，无 id 或未 settled 仍硬失败；真正新的 DMA RDATA pop 仍失败。

新增纯测试（2 个）：`_settled_pop_access_ids` 必须同时收集 CPU 与 DMA pop id 且不猜测无 id 的 pop；fake boot 断言第一例后 `dma-access-1` 已进入 `settled_access_ids`，第二例 ILLEGAL 继承它。`test_dma_error_isr.py` 从 51 增至 **53 passed, 1 skipped**。

## 9. 真实 RTL 门（两次尝试失败已修复，重新排队）

```sh
MYFUZZ_DMA_ERROR_ISR_REAL=1 \
MYFUZZ_DMA_ERROR_ISR_CACHE=<cache> \
MYFUZZ_DMA_ERROR_ISR_EVIDENCE=<evidence> \
PYTHONPATH=src timeout 1800 python3 -m pytest -xq \
  tests/integration/test_dma_error_isr_real.py
```

- 一次 boot 六例：`RX_TO_RAM len1`、`ILLEGAL len1`、`RAM_TO_RAM len2`、`ILLEGAL len2`、`RAM_TO_TX len1`、`ILLEGAL len4`（3 valid + 3 invalid，交错）；
- 期望 `1 passed`；每例真实 FIFO push/pop、真实 IRQ/take、ISR；invalid 例必须有真实 receipt/ERR response/native error IRQ/CPU take、无 target delivery、无目的 RAM commit、无 DMA FIFO pop、status bit30=1（按实测 word）；valid 例全绿；
- 保存 `descriptor.json.gz`、`cases.json`、`manifest.json`、`error-status-measured.json`、`source_pins.json`，fresh replay 保存 `fresh.json.gz`；
- 内部 `ResourceBudget(max_wall_time_ms=900000)`；外层 `timeout 1800` 只作兜底；
- **第一次尝试（`537585f`）已失败并修复**：见 §8.3；**第二次尝试（`0eff9a7`）仍失败并已修复**：见 §8.4；修复后的真实门由主会话在冻结快照重跑，旧的失败不构成通过证据；
- **重新排队原因**：主会话需在冻结源码上串行建立真实 build identity；本增量不自行运行真实门。

## 10. 诚实边界与风险

1. **S3 的 error status 尚未实测**：见 §4。代码没有写死完整 status 值；真实门第一次运行的 `error-status-measured.json` 才是 S3 的正式测量。若该文件中的 bit30/busy/inc 与源码布局不符，门会 fail-closed，不能宣称通过。
2. **没有 PLIC / 共享时钟 / 物理总线仲裁**：error IRQ 仍是 `wbdmac` 原生 `o_interrupt` 经 Runner 声明 binding（16 CPU-tick 展宽）送入 CPU；这是 host 适配器，不是 PLIC RTL。
3. **S3 只覆盖一个声明非法 offset**：`0x50000020` 是 UART window 内未声明可读写 offset；没有覆盖越界崩溃、多 master 并发、错误后 DMA 内部残留等。
4. **length==programmed len 的断言**来自 `wbdmac.v` 的 `cfg_len` 只在写 ACK 递减；若真实读数不同，门会报告差异而不是放宽。
5. **`environment_error_receipt` 的每例证据是稳定摘要**：省略 execution UUID 以保证 fresh 逐例 dict 相等；原始 receipt 在 `events`，fresh 比较走 `_normalize`。S4 的 typed normalizer/认证前缀 replay 仍未做。
6. **`fifo_origin='unknown'`、`source_authority='incomplete'` 未改写**；S4 之前 error 例同样没有来源认证。
7. **S2 成功例仍全绿**，但 S2 的 6 例真实门没有在本增量重跑；S2 的失败/修复历史不变。
8. **未覆盖**：S4 认证、typed normalizer、逐语料前缀 replay、PLIC、共享时钟、物理仲裁、CPU 程序字节变异（S5）。

## 11. 提交

- 增量提交信息以 `P8 S3:` 开头，只包含本增量新增/修改的源、测试、报告；不包含 `agent.md`、`third_party/`、root-owned evidence。
- P8 状态：**仍不通过**（S4 未做；S3 真实门两次失败已修复、重新排队，error status 待实测）。
