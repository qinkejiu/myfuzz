# 通用运行框架 G8.1c：Wishbone routed storage 与 producer row（仍未 PASS）

本报告记录 G8.1 在本轮真实完成的部分及其边界。**`G8.1: NOT_PASS`**：本轮没有
Wishbone F4/F2 executor、没有 3 例 persistent/fresh 计划与存档 bundle，也没有任何
G8.2–G8.10 或 P7-E 声明。所有数字来自本轮实际执行的命令；RTL 测试一律真实
Verilator 构建并通过真实进程运行，未使用 mock、未把 skip 记为通过。

## 任务状态

| 任务 | 结论 | 实际结果 |
|---|---|---|
| G8.1c 真实样本测量 | **完成（测量）** | 用真实 WBUART `SETUP` target 测出 `ACCESS_WB_REG` 每个 tick 的 pre/post `backend` + `storage_probes`，写入 0x55 读回 0x55；F4 consumer 期望的 pre/post/ACK 形状与真实 RTL 一致 |
| G8.1c target routed access | **完成（真实 RTL）** | `GeneratedWishboneRegisterSession` 新增 `routed_register_access`/`routed_delivery_failed`/producer hooks；真实 routed 写 0x55 + 读回 0x55，1 条 commit（before 0x19 / after 0x55）与单次 opaque token |
| G8.1c producer row | **完成（software）** | 新增 `generic_wishbone_storage_abi` row、`declare_wishbone_writer`、masked full-word write 声明策略；36 个新测试 |
| G8.1c F4 executor | **未完成** | `compiled_f4_wishbone` 仍不存在；`create_preparation` 能产出 executable Wishbone F4 path，但 support 报告仍无 executor，plan 编译在 `_flow_kernel` 处拒绝 |
| G8.1 | **NOT_PASS** | 缺 executor + 3 例 persistent/fresh + bundle |

## 真实测量：WBUART SETUP 的 Wishbone 逐 tick 形状

命令（退出码 0，47 行日志）：

```
PYTHONPATH=src:. PYTHONDONTWRITEBYTECODE=1 MYFUZZ_SCENARIO_REAL=1 \
  python3 runs/generic-runtime/G8/scratch-wb/probe_native_samples.py
```

一次 `ACCESS_WB_REG` 前进 5 个 tick，每次写/读都给出 `pre`+`post`。写 0x55 时：

```
tick1 pre : cyc=0 stb=0 adr=0 sel=0  ack=0 stall=0 dat_w=0    dat_r=0x19 value=0x19
tick1 post: cyc=1 stb=1 adr=0 sel=15 ack=0 stall=0 dat_w=0x55 dat_r=0x19 value=0x19
tick2 pre : cyc=1 stb=1 adr=0 sel=15 ack=0 stall=0 dat_w=0x55 dat_r=0x19 value=0x19
tick2 post: cyc=1 stb=0 adr=0 sel=15 ack=0 stall=0 dat_w=0x55 dat_r=0x19 value=0x55
tick3 pre : cyc=1 stb=0 adr=0 sel=15 ack=0 stall=0 dat_w=0x55            value=0x55
tick3 post: cyc=1 stb=0 adr=0 sel=15 ack=1 stall=0                        dat_r=0x55 value=0x55
tick4 pre : cyc=1 stb=0 adr=0 sel=15 ack=1 stall=0                        dat_r=0x55 value=0x55
tick4 post: cyc=0 stb=0 adr=0 sel=0  ack=0 stall=0                        dat_r=0x55 value=0x55
```

关键结论（设计依据，不是推断）：请求首次出现在 **post** 相位；`pre` 相位里唯一的
请求样本在下一 tick；`ack` 是寄存的，出现在请求后两 tick，且 CYC 一直保持；
`stall=0`、`storage_reset=0`；probe 值与同相位 `backend` trace 完全一致；reset 值
0x19 与 source contract 一致。详见
`runs/generic-runtime/G8/G8.1c-native-sample-shape.md` 与同名 `.log`。

## 新增实现（本轮）

### 1. target 侧真实 routed storage（`Subagent W1`，4 个文件）

- `src/myfuzz/local_harness/wishbone_register_session.py`：
  `routed_register_access_enabled`（必须是已启动的 storage row 且存在本 session 的
  exact authority）、`routed_register_access`（16-key pending context，无 `tick`；
  先做 subset 校验，再发真实 `ACCESS_WB_REG`，`_take` 后再由 authority 组装并校验
  17-key 完整 context）、`routed_delivery_failed`、`command()` producer hooks（在
  `super().command` 前 `_actual_begin`、后 `_actual_command`，任何异常即 revoke）、
  `end_case`/`reset_local` 撤销。
- `src/myfuzz/scenario/wishbone_storage_register_version.py`：
  `_bind_build_identity`（从 `built_executable_receipt_document()` 一次性绑定真实
  build digest/artifact digest/binary sha，之后只允许相等）、`_actual_begin`/
  `_actual_command`/`_complete_access`、纯函数
  `_analyse_wishbone_transfer`（全样本状态机）、`validate_pending_routed_context`、
  `wishbone_storage_authority`/`revoke_wishbone_storage_authority`、journal/state/
  limits。ACK 判定按真实波形：只在 `pre` 相位找唯一 sustained ACK，并要求恰好一次
  rise、一次 fall（`missing-ack`/`duplicate-ack`/`ack-release-missing` 分别拒绝）。
- 真实运行测得：write rdata 0、read rdata 0x55；pre 样本 index 1、tick 2、
  `value 0x19 → 0x55`；唯一 commit `{tick:2, raw_address:0, before:25, after:85,
  sample_index:1, phase:'pre', command_sequence:1}`；token 首次 consume 成功、
  第二次 `wishbone-storage-version-token-invalid`，随后 authority 永久 revoked；
  `build_identity_sha256 == receipt.build_digest`；`reset_waveform_observed=false`、
  `routed_context_authenticated=false`（不声明 reset/路由认证）。
- 新增 fail-closed 判定（本轮确认接受）：**routed 路径外被测量到的写**无法进入
  journal，因此 `issue()` 拒绝 `wishbone-storage-version-history-incomplete`，
  避免声称"完整写历史"。真实 row 没有这种写，行为不变。

### 2. producer row 与单一写策略（`Subagent W2`，3 个文件）

- 新 `src/myfuzz/integration/wishbone_register_writer.py`：
  `declare_wishbone_writer(...)`。全掩码行逐字委派 `declare_writer`，仅补
  `candidate.access.word_index`；被评审的 `SETUP` 是 **masked** 行
  （`write_mask=0x7fffffff`，bit 31 永不存储、恒读 0），`declare_writer` 会以
  `register-candidate-masked-merge-policy-undeclared` 拒绝所有 masked 写。因此新增
  **一个封闭、按行限定的声明策略** `register_write_policy.v1` /
  `declared_masked_full_word_write`：要求 full-word `sel=15`、
  `value & ~value_mask == 0`（不接受 merge/read-modify-write）、access mask 必须
  等于注册 contract 的 `write_mask`、寄存器名/offset/word index 必须匹配，并记录
  `not_claimed=['bits outside value_mask are not written','WBUART SETUP bit 31
  always reads 0']`。`generated_register_writer.py` 与
  `register_source_access.py` 字节未改，原有拒绝未被放宽。
- `src/myfuzz/integration/compiled_storage_producer.py`：新增
  `ROW_GENERIC_WISHBONE_STORAGE = 'generic_wishbone_storage_abi'`（第三行）、
  `_generic_wishbone_document`、`build_storage_producer` 分支（先要求
  `wishbone_storage_consumer_support(...)['complete'] is True`，再构造
  `GeneratedWishboneRegisterSession` + `WishboneStorageRegisterVersionAuthority`，
  不调用 reset/native 配置）、10 个新 pin 依赖。
- 选定行事实：`target=peripheral`、`kind=wishbone_register_observe`、endpoint
  `uart.bus`、`protocol=['wishbone','classic']`、template
  `target.wishbone/1/word-addressed-registered-ack`、register `SETUP` offset 0
  **word_index 0**、window 16 @ `0x60000000`、write/read mask `0x7fffffff`、source
  contract `zipcpu-wbuart.setup.storage.v1` digest `3dc8b5e2…f088`、probe digest
  `abdc03a3…6960`（hierarchy/native 均 false，无证据）、
  `live_token_scope=actual_initial_samples_required_not_claimed`、
  `grants_reset_prerequisite=false`、consumer
  `check_wishbone_storage_observation`、issuer
  `WishboneStorageRegisterVersionAuthority`。consumer support `complete=True`（四个
  receipt element 齐备），但 `runtime_admitted=false`。

## 本轮验证（全部真实执行）

| 命令 | 结果 |
|---|---|
| Wishbone 软件门（source/probe/version/native-authority/consumer/wishbone-producer/adapter/registry/admission，11 个文件） | **398 passed**（161.46s） |
| `test_wishbone_routed_storage_real.py` + `test_wishbone_storage_real.py`（真实 RTL） | **2 passed**（39.81s） |
| `test_wishbone_cpu_to_storage_real.py` + `..._persistent_real.py`（真实 RTL） | **2 passed**（54.90s） |
| `MYFUZZ_RUN_GENERIC_NATIVE=1` G6+G7 归档证据门 | **17 passed** |
| `test_compiled_f4_storage_producer.py` + `test_generated_wishbone_storage_consumer.py` + `test_admission.py` + `test_registry.py` | **244 passed** |
| `test_compiled_f4_spi_source_real.py`（APB SPI 软件门） | **23 passed**（修复后，见下） |

## 顺带修复的两个**既有**基线缺陷（非 G8 代码引起）

1. `tests/integration/test_compiled_f4_storage_producer.py` 的 2 个 fake runtime 缺少
   `_mixed_flows`，导致 `CompiledF4Runtime.finish()` 抛 `AttributeError`
   （`compiled_f4.py:1400`）。已在 fake 上补 `_mixed_flows=False`（测试侧对齐真实
   对象，不改生产代码）；该文件 124 passed。
2. `tests/integration/test_compiled_f4_spi_source_real.py:591` 断言
   `len(issue_calls)==1`，但混合 F2+F4 工作新增了第二个 `self.authority.issue(`
   调用点。已把断言改为**逐调用点**检查"经 authority 且 `register` 必须来自
   `self` 属性"，比原计数更强而不是放宽；该文件 23 passed。

两项都在 `runs/generic-runtime/G8/G8.1a-report.json` 之外的 APB/SPI 前置工作上，
不在本轮 G8.1 声明范围内，但会影响整仓软件门，故记录并修复。

## 明确未支持 / 未声明

- 无 `compiled_f4_wishbone` / `compiled_f2_wishbone` executor；`compiled_f2_consumer`
  仍只接受 `apb3_register_observe`，Wishbone F2 未支持。
- 无 3 例 persistent 计划、无 fresh 进程复现、无 saved bundle。
- 无 native reset observation（Wishbone 不接 `native_reset_producer_contract` 的封闭
  registry；token 明确 `reset_waveform_observed=false`、不授予 reset prerequisite）。
- 无 Wishbone hierarchy/native probe 证明（probe 仍是 prospective，
  `hierarchy_verified=false`/`native_verified=false`）。
- 不支持 `sel != 15`、burst、CTI/BTE、pipeline outstanding>1、STALL/ERR 语义、
  地址无关 target、ZipCPU Wishbone master（无 profile/lock）、UART
  FIFO/RX/TX/serial/IRQ、`FIFO_STATUS`、`REG` push/pop、AXI4-Lite。
- 写语料受限：`SETUP` bit 31 不可写，`example_records.json` 里的 `aa000000` 必须在
  declaration 阶段被拒；G8 campaign 语料需取 `0x7fffffff` 以内（下一步任务）。

## 下一步（PASS 所需）

1. `compiled_f4_wishbone` executor（`WishboneF4Runtime` + Wishbone exact-hop checker +
   `wishbone_normalized_semantic_sha256`）+ `assess_compiled_f4_support` Wishbone
   分支 + `create_compiled_execution` dispatch；已有设计合同
   `runs/generic-runtime/G8/G8.1d-F4-RUNTIME-CONTRACT.md`。
2. `configs/scenarios/` 新 G8 语料（值 ≤ `0x7fffffff`）+ G8 campaign driver 复用
   `runs/generic-runtime/G6/run_native_campaign.py` 的 lifecycle。
3. 真实 3 例 persistent + fresh（plan 字节一致、PID 不同、replay 匹配）+ saved
   bundle pair 与篡改类拒绝。
4. 只有在 1–3 全部成立后才可把 G8.1 标为 PASS，并把 `runtime_admitted=true` 的
   证据归档；在此之前 `G8.1: NOT_PASS`。
