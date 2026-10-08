# P4 计算结果到外设消费的通用证书

日期：2026-10-07。P4 此前只有[CPU `ADDI` 结果到 UART `SB` 的受限架构审计](current-dataflow-p4-computed-uart-store-audit-20261007.md)（顺序关联、无内部 token）。本报告交付一个**通用、有界、fail-closed** 的消费者，把"CPU 真实退休算出的值"与"目标设备真实消费的同一值"用**精确键**连接，并在四份真实 artifact 上给出实测。

## 交付

| 文件 | 作用 |
|---|---|
| `src/myfuzz/scenario/computed_value_certificates.py`（新增） | `ComputedValueCertificates`，输出 `computed_value_certificate.v1` |
| `tests/scenario/test_computed_value_certificates.py`（新增） | 31 项（27 合成 + 4 真实 trace 钉住） |
| `scripts/report_computed_value_certificates.py`（新增） | 只读复算 CLI |

### 判定条件

**起点**（真实 RVFI 退休）：`trap==0`、`valid==1`、`phase=='post'`、`rd != x0`、`rd_addr`/`rs1_addr` 与编码一致，且 **`rd_wdata` 必须等于用 `insn + rs1_rdata` 重算的值**；支持 `LUI/ADDI/XORI/ORI/ANDI/SLLI/SRLI/SRAI`，funct7 保留位一律拒绝。

**传播**：同一 **6 字段 `TransactionKey`**（`execution_id`/`source_epoch` 与退休一致）下的 `mmio_acceptance`/`mmio_delivery`/`gpio_target_receipt` 锚点与 `data_accept`/`data_response` 延伸；逐跳要求 byte-enable 相同、**被使能 lane 的字节**与锚定值相同（lane = `address & 3`）、address/offset 相同、`event_id` 严格递增且相邻跳 ≤ `max_event_gap`。

**终点**（同一身份的设备内部证据，四选一）：`gpio_register_commit`（逐位 `value` 与事务键全等，`observation_event_id` 必须指向已认证的 `gpio_apb_access`）；`gpio_apb_access`（`psel/penable/pwrite/pwdata/pready/pslverr/apb_addr` 探针全等）；`uart_tick_observation` 的 access 上下文；UART 串口字节（`serial_tx_count == base+1`、`serial_tx_last` 等于该 lane 字节，一条链只归因一次，不匹配则**永久**取消串口资格）。

**fail-closed**：值/lane/键/地址/顺序/伪造字段任一矛盾 → 丢链并计入 `rejections`（22 个键），丢链不产生证书；事件 id 非连续或回退、reset barrier → 取消全部候选（链永不跨 gap、永不跨 reset）。有界：`max_pending=64`、`max_event_gap=4096`、`max_value_history=256`、`max_consumption_witnesses=8`。

每张证书显式列出 `not_proof_of`：寄存器堆内部 token、跨指令数据依赖、该值确被后续指令使用、地址路由归属、设备内部 FIFO/序列化 token、取指/译码身份、逐位硬件锥。

## 真实 artifact 实测（只读流式，`semantic_sha256_verified` 全 True）

| run | 事件 | certified / incomplete / peak | 设备与终点 |
|---|---:|---|---|
| `runs/p3-lane-selectivity2-20261007-online` | 168,917 | **30 / 0 / 5** | gpio_a 27、gpio_b 3，全部 `gpio_register_commit` |
| `runs/p4-shift-fuzz-20261007-online` | 118,963 | **33 / 0 / 6** | gpio_a 30、gpio_b 3，全部 `gpio_register_commit` |
| `runs/current-dataflow-p4-uart-sb-real-online`（`uncertain_effect`） | 39,677 | **2 / 1 / 2** | uart，`uart_tick_observation_access` |
| `runs/current-dataflow-p4-sb-final-online-20261007` | 63,830 | **3 / 0 / 2** | uart，含 **1 条串口字节证书** |

**GPIO 代表链**：`cpu_retire 194`（`addi x2,x0,0x101`，pc 0x10084）→ `mmio_acceptance 267` → `data_accept 269` → `gpio_target_receipt 300` → `gpio_apb_access 304`（`pwdata=257`/`apb_addr=4` 等探针全等）→ `gpio_register_commit 306`（`gpioen` pre 0 → post `0x101`，`observation_event_id=304`）→ `mmio_delivery 313` → `data_response 332`。

**UART 串口字节代表链（独立复现既有审计，未复用其结论）**：`cpu_retire 25068`（`ADDI x2,x2,12` → `0x0c`，pc 69656）→ `mmio_acceptance 25121` → `data_accept 25122` → `uart_tick_observation_access 25132/25133/25141/25149`（off 28）→ `mmio_delivery 25150` → `data_response 25176` → **`uart_serial_observation 28002`**（`serial_tx_count 0→1`、`serial_tx_last=0x0c`、lane 0）。事件号与字节与既有审计文档一致。

**认证不了时的精确原因**：`p4-uart-sb-real-online` 唯一一次 WDATA 写（off 28、be=1、value `0xc8`、seq 15）出现在 event 39666/39667，紧随 event 39677 即 `harness_failure`，之后既无 delivery 也无串口观测 → 该链 `incomplete`，`missing_hops=["device_consumption"]`、`reason="expired_without_device_consumption"`（是运行被截断，不是字段缺失）。

## 限制

- 证书只证明**被使能 lane 上的值同一性**在"RVFI 计算退休"与"设备消费事件"之间成立；不证明寄存器堆内部 token、不证明跨指令依赖或该值确被后继 `SB` 用作 rs2、不证明地址路由归属。
- UART 串口字节终点是 trace 顺序 + 计数增量关联（无 FIFO 内部 token）；GPIO 以 register commit 行值为准。
- 未覆盖：多 beat 跨字（宽度 > 4B）store、压缩指令、向量/浮点、跨 testcase 的 CPU scope。
- 该消费者**尚未接入** `acceptance_metrics`（建议在同一次流式 pass 内并行喂第二个消费者，产出独立聚合块；不要经 `chain_producer=`，其工厂契约不兼容）。
- 全部结论来自既有保存 artifact 的只读复算；本轮未运行真实 RTL。
