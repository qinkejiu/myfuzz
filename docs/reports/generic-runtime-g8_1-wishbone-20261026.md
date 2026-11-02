# 通用运行框架 G8.1：Wishbone storage 行真实通过（WBUART SETUP）

本报告记录 G8.1 的最终真实证据与边界。**G8.1 = PASS（声明式接入范围）**：新增
Wishbone target/master 的 storage 行，真实 3 例持久 F4 campaign + 跨进程 fresh、
四态证据全部 certified、saved bundle pair 52 checks verified、8 类篡改全部拒绝。
范围仅限本文件"支持/不支持"两节列出的内容；不关闭 G8.2–G8.10，也不替代 P7-E。

## 结论表

| 项 | 结论 | 关键实际结果 |
|---|---|---|
| G8.1 | **PASS** | WBUART `SETUP` Wishbone 存储行真实 3 例（0x55→0x2a→0x12345678），original/fresh plan 字节一致（`74f7166e…`），PID 不相交，每例 8 条指令 hop + 2 条 data hop + 结果 RAM 写，四态证据 certified，replay matches；bundle pair 52 checks verified（`bfacec06…`/`82e44f92…`）；8/8 篡改类拒绝 |

## 接入对象（不是改名）

- Master：`configs/cpus/picorv32_wb`（PicoRV32 classic Wishbone，`cpu.wishbone/1/no-err-stall`，
  字节地址，无 ERR/STALL）。没有新增 ZipCPU master。
- Target：`configs/peripherals/zipcpu_uart_storage`（ZipCPU WBUART `SETUP`，
  `target.wishbone/1/word-addressed-registered-ack`；16 字节 word 窗口，`adr` 为
  word index，`ack` 寄存且 T+2，CYC 保持，`stall=0`，无 `err` 引脚）。
- Source row：`src/myfuzz/local_harness/wishbone_storage_source_contract.py` 的
  `zipcpu-wbuart.setup.storage.v1`（digest `3dc8b5e2…f088`）：`SETUP` @ word 0、
  width 32、reset `0x19`、write/read mask `0x7fffffff`（bit 31 永不存储、恒读 0）。
  UART RX/TX/FIFO/IRQ/serial 明确不声明。
- Probe：`wishbone_storage_probe.v1`，11 个端口（`storage_value`、`storage_reset`
  加九个总线角色），**prospective**（`hierarchy_verified=false`、
  `native_verified=false`），本行不声称层次/原生证明。

## 真实执行

源码闭包与运行环境：Python 3.12、Verilator 5.051；所有证据在
`runs/generic-runtime/G8/wishbone-F4-final/`。生命周期与 G6/G7 完全一致：
`create_preparation`（固定 generated 路径，本行只准备 F4）→ verify/select → 单计划 →
`WishboneF4Runtime(defer_begin=True)` → adapter 在 begin 前绑定 → 一次 begin → 3 case →
finish → 同进程 replay。

| 运行 | plan identity | PID（peripheral/processor） | 三例值 | 结果 |
|---|---|---|---|---|
| Wishbone original | `74f7166e…f3f7a2` | 2329999 / 2330057 | 0x55, 0x2a, 0x12345678 | 3/3 effective，四态 certified，replay matches，126.67s |
| Wishbone fresh | `74f7166e…f3f7a2` | 2331995 / 2332038 | 同上 | 3/3 effective，四态 certified，replay matches，114.98s |

- 两次 `execution_plan.json` 字节相同（20382 bytes），d2/d3 输入摘要一致。
- 每例 `prerequisite`/`postcondition` 构成持久链：`0x19→0x55→0x2a→0x12345678`，
  `write_count` 0→1→2→3，`field_version == write_count`，`command_sequence` 单调增加。
- 每例：8 条 instruction hop（0,4,…,28）、2 条 data hop（write seq n、read seq n+1）、
  结果 RAM 写 `0x2FFFC`（value 为该例写入值，`byte_enable=15`，version `[0, n]`），
  两条 declared edge（`persistent_state`、`mmio_route`）均 certified。
- 证据四态：`component_semantic_effect`、`cross_component_consumption`、
  `cross_component_source`、`physical_protocol_sample` 全部 `certified`；每例
  primary evidence 有 4 个 native refs（写 pre/post + 读 pre/ack）与 4 个 source refs
  （acceptance/delivery ×2）。
- 证书为 `compiled_F4_wishbone_chain.v1`，`runtime_admitted=true`，token 为单次消费
  opaque witness（`consumed=true`、`single_use=true`、`opaque=true`），
  `reset_waveform_observed=false`、`routed_context_authenticated=false`、
  `grants_reset_prerequisite=false`；证书中不含 `native_APB_event`/`native_obi`/
  `apb-storage:` 字样。

## 存档与验证

- `wishbone-F4-final/bundle-original`（id `bfacec06…f2494`）与
  `bundle-fresh`（id `82e44f92…45ea`，`fresh_of` 指向前者）。
- `scripts/verify_generic_runtime.py` 结果：
  `runs/generic-runtime/G8/verification/wishbone-pair.json`，`verdict=verified`、
  `checks=52`、`case_count=3`、两个 bundle id。
- 篡改：`runs/generic-runtime/G8/tamper/work/tamper-report.json`，
  `pristine_verdict=verified`，8 类全部拒绝（native-read-return、byte-version-value、
  counter-decrease、process-pid、source-archive-bytes、plan-bytes、evidence-status、
  fresh-pid-reuse）。
- Armed gate：`tests/integration/test_generic_storage_wishbone_native.py`（5 tests，
  需 `MYFUZZ_RUN_GENERIC_NATIVE=1`；未设置时 5 skipped，skip 不算通过）。
- 共享核心 freeze：`runs/generic-runtime/G8/G8.1-shared-core-freeze.json` 记录
  APB/OBI 会话/authority/consumer/writer、`compiled_f4.py`、`session.py`、
  `router.py`、`runner.py` 等 14 个文件的 sha256；armed gate 断言其未变。

## 本轮新增/修改的代码（按职责）

1. Wishbone source/probe/consumer/authority/adapter/renderer（G8.1a/1b 已落地，
   本轮接通）：`wishbone_storage_source_contract.py`、
   `wishbone_storage_probe_contract.py`、`wishbone_storage_probe_verification.py`、
   `generated_wishbone_storage_consumer.py`、`wishbone_storage_register_version.py`、
   `runtime/adapters/wishbone_storage.py`、`runtime/adapters/wishbone_cpu.py`。
2. Target 侧 routed storage：`GeneratedWishboneRegisterSession` 新增
   `routed_register_access`/`routed_delivery_failed`/producer hooks；
   `WishboneStorageRegisterVersionAuthority` 新增 `_actual_begin`/`_actual_command`，
   从真实 built receipt 绑定 build digest、全样本状态机（唯一 pre 请求、同 tick post、
   唯一 sustained ACK、CYC 保持、`stall=0`、`adr` word index、`sel=15`、probe 与
   backend 九角色交叉校验）、写入 journal 与单次消费 token。
3. 在线指令源：`GeneratedWishboneCpuSession` 增加 `declare_instruction_slots`/
   `accept_instructions`/`waiting_instruction_address`（与 OBI CPU 会话同构），
   并把 classic Wishbone 读事务的 `wb_dat_w` 规范为 0。
4. Producer/声明：新 `wishbone_register_writer.py`（`SETUP` 为 masked 行，
   `register_write_policy.v1`/`declared_masked_full_word_write`，只允许
   `value & ~value_mask == 0` 的 full-word 写）；`compiled_storage_producer.py`
   第三行 `generic_wishbone_storage_abi`。
5. Executor：新 `compiled_wishbone_f4.py`（`compiled_f4_wishbone`）：
   `admit_wishbone_f4`、`wishbone_cpu_traces`、`wishbone_native_beats`、
   `check_wishbone_f4_exact_hops`、`wishbone_normalized_semantic_sha256`、
   `WishboneF4Runtime`；`assess_compiled_f4_support` Wishbone 分支、
   `create_compiled_execution` dispatch、`WISHBONE_FLOW_EXECUTORS`。
6. 共享层最小修复（协议/单位/映射键驱动，非组件名分支）：
   - `runtime/compiler.py`：目标地址宽度按 endpoint 声明的 `address_units` 推导
     （word 单位时 `window_size / width_bytes` 的位宽，16B/4B→2 bits），字节单位不变；
   - `runtime/flows/storage.py`：native sample join 同时识别
     `native_APB_event/native_post_event` 与 `native_wishbone_event/native_ack_event`；
   - `generated_wishbone_storage_consumer.py`：`artifacts` 接受任意 `Mapping`
     （此前只接受 `dict`，`mappingproxy` 被误判为缺失 probe）。

## 支持 / 不支持（严格）

支持（已真实运行）：

- 单个 Wishbone classic target：32 位 full-word 读/写、`sel=15`、单 outstanding、
  寄存 ACK、CYC 保持到 ACK、`stall` 观测为 0、`adr` word index（由字节偏移换算）；
- 单个 PicoRV32 classic Wishbone master（字节地址，无 ERR/STALL）；
- `SETUP` 字的稳定存储值（UART 状态/IRQ 不声明）；
- 3 例持久写/读回 + 跨进程 fresh 复现 + 同进程 replay；
- 四态证据（语义效果、消费、来源、原生协议样本）与 saved bundle 验证。

不支持/拒绝：

- `sel != 15` 的运行时部分写（RTL 支持，但本行不声明）；
- burst、CTI/BTE、pipeline outstanding > 1；
- STALL 与 ERR/RTY 语义（无 `err` 引脚；`stall` 仅观测 0）；
- 地址无关（`address_width=0`）target 变体；
- ZipCPU Wishbone master（无 profile/lock）；
- `zipcpu_timer` 倒计时/IRQ、`wbdmac`、UART FIFO/RX/TX/serial/IRQ、
  `FIFO_STATUS`、`RXREG`、`TXREG`、`uart_setup` 的 UART 副作用；
- Wishbone F2 读行（`compiled_f2_consumer` 仍只接受 APB3）；
- 混合 F2+F4、F5/F6/DMA、native reset observation、Wishbone 层次/原生 probe 证明；
- G8.2–G8.10、P7-E。

## 已知偏差与说明

- **masked 写策略**：`SETUP` 的 write mask 是 `0x7fffffff`。`declare_writer` 对任何
  masked 写一律 `register-candidate-masked-merge-policy-undeclared` 拒绝；本行新增
  **按行限定**的 `declared_masked_full_word_write` 声明（不接受 merge/RMW，
  `value` 不得含保留位），未放宽原有拒绝。语料必须 ≤ `0x7fffffff`；
  `example_records.json` 中的 `aa000000` 属保留位值，必须在声明阶段被拒。
- **无 native reset observation**：Wishbone 行不接入封闭 reset producer registry；
  token 明确 `reset_waveform_observed=false`，不授予 reset prerequisite。
- **prospective probe**：11 端口 probe 只有文档级重推导，没有已登记的 Wishbone
  层次/原生证明；`hierarchy_verified=false`/`native_verified=false`。
- **在线指令源**位于 `wishbone_cpu_session.py`（而不是 executor 里的子类）：
  adapter 与 authority 都要求 exact class，因此把同构扩展放进会话本体。
- **campaign 只准备 F4**：本行没有 Wishbone F2，计划不得静默丢弃不支持的 flow，
  故 G8 driver 以 `flow_ids=('F4',)` 准备；F2 行仍为未支持。
- 本工作的 APB/OBI 共享文件未被重写（freeze 断言）；G6/G7 归档证据仍通过
  17 个 armed 检查。

## 开发过程中的非证据目录

`runs/generic-runtime/G8/wishbone-F4-attempt1/` 与 `wishbone-F4-attempt2/` 是本轮
开发中的尝试，**不是** G8.1 证据：attempt1 在 target admission
（`receipt-join-incomplete`）失败，attempt2 在 kernel native-join 修复前完成、其
四态证据仍为 `unsupported`。两次的 `.log` 均保留以显示真实过程；最终门只读
`wishbone-F4-final/`。

## 复现命令

```
PYTHONPATH=src:. PYTHONDONTWRITEBYTECODE=1 python3 \
  runs/generic-runtime/G8/run_wishbone_campaign.py --scenario wishbone-uart \
  --flow F4 --mode original --case runs/generic-runtime/G8/wishbone-F4-final
PYTHONPATH=src:. PYTHONDONTWRITEBYTECODE=1 python3 \
  runs/generic-runtime/G8/run_wishbone_campaign.py --scenario wishbone-uart \
  --flow F4 --mode fresh --case runs/generic-runtime/G8/wishbone-F4-final
PYTHONPATH=src:. PYTHONDONTWRITEBYTECODE=1 python3 \
  runs/generic-runtime/G8/emit_wishbone_bundle.py --case-root \
  runs/generic-runtime/G8/wishbone-F4-final --mode original --scenario wishbone-uart \
  --bundle-dir runs/generic-runtime/G8/wishbone-F4-final/bundle-original
PYTHONPATH=src:. python3 scripts/verify_generic_runtime.py \
  --bundle runs/generic-runtime/G8/wishbone-F4-final/bundle-original \
  --fresh-bundle runs/generic-runtime/G8/wishbone-F4-final/bundle-fresh \
  --output runs/generic-runtime/G8/verification/wishbone-pair.json
PYTHONPATH=src:. MYFUZZ_RUN_GENERIC_NATIVE=1 python3 -m pytest -q \
  tests/integration/test_generic_storage_wishbone_native.py
```

（fresh bundle 需以 `--fresh-of <original bundle id>` 生成，验证器要求 fresh 指向
original。）
