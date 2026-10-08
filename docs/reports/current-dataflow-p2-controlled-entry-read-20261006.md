# P2 受控 UART IRQ 入口与实际退休 RDATA 读取

> **⚠ 复算可用性（2026-10-09 更新）**：本文引用的部分原始产物目录在 2026-10-09 的 `runs/` 清理中被删除，因此文中指向 `runs/` 的链接可能失效。**报告的结论、数字与边界仍然有效**（记录的是当时真实执行的结果），但"从原始产物复算"的能力已不存在。删除范围、已重建项与逐条断链清单见 [已删除的原始产物](DELETED_ARTIFACTS_20261009.md)。
日期：2026-10-06。CPU 原生观测 v2、受控 bootstrap 入口和 UART RDATA→实际退休 `lw` 关联已实现。**2048 容量版本的四例真实 RTL、独立审计、完整 fresh replay 和语义 fixture 已通过；首次 256 容量运行仍只作为容量不足的历史证据。** P2/P3 仍部分完成，P4～P8 未验收。最新状态见[当前进度](../CURRENT_PROGRESS.md)。

## 本轮实现范围

显式 Ibex RVFI＋UART FIFO 模式使用 `ibex_native_irq_receipts.v2`。CPU sample、taken、notification 和 `cpu_retire.v2` 共享同一真实 parsed driver receipt 的 nonce／sequence／tick pair；退休记录带精确 POST 引用和完整 44 字段 RVFI。成功 startup READY／物理 reset 事实认证 artifact、boot base、assert/release ticks 和进程/epoch；失败不生成成功事实，也不凭 host step 猜测退休来源。

Root 在执行前用受信 bootstrap builder 与认证 artifact 生成配置身份。两张实际镜像安装后，记录真实 event ID、memory generation/span，才构建安装 registry。外部事件或自签标签不能创建该 authority。受控入口关联完整固定 main／CSRRS 执行、实际输入/taken、派生 mtvec/cause11 和首个 `intr=1` 的机器模式退休；冻结指令响应必须属于实际 installed initial image。这是 `controlled_bootstrap_external_irq`，不授予 generic ISR 身份，也不是被动 CSR readback 证明。

退休读取 linker 独立重建 raw UART 与 CPU 模型，再核对 logged certificate；只接受实际编译 MMIO window 中 offset `0x18`、对齐、read／BE15 的单 beat RV32 `lw`。原始 UART entry/frame/admission、完整 TransactionKey、实际响应、RVFI memory/writeback 必须一致；普通 RAM／非 RDATA load 不占用 UART 待决预算。未知来源、冲突、容量丢失或未见证 epoch 变化保持 certainty barrier。

## 软件验证与审查

CPU 最终 v2 原生凭据专项 21 项通过（43.754 秒），旧默认形态保留；受控入口专项 42 项通过（独立最终记录 13.12 秒）；退休读取原专项整合 143 项／366 子检查通过（46.76 秒）。这些数目按各次源身份解释，不替代下面新容量真实门禁。最终新容量软件汇总由 Root 单独记录，不能沿用旧统计推定成功。

独立审查发现并修复 raw taken／derived certificate 顺序、reset kind-role 清除 certainty、UART reset 残留 orphan raw CPU cache、无关 RAM load 消耗待决预算等问题。严格 manifest 从实际 builder 和 typed bounds 重建配置；逻辑 graph source 经真实 RuntimeEdgeIndex 解析为 input owner。真实 fixture 重算 raw FIFO/native/entry/read 证明，不能仅采纳 accepted 标签；fresh 比较每条 canonical wire JSON 事件和 local tick，bool/int/float 差异不被掩盖。

## 首次 256 容量运行：保存失败边界

历史目录：[首次在线材料](../../runs/current-dataflow-p2-controlled-entry-read-20261006-online/)。在线四例 complete、client exit0；完整新进程 replay 的 **48,530** 个事件一致。fixture 5 项及 8 个删除子检查通过（239.99 秒），但其 scope-positive 检查不要求每帧都有退休 read，因此不能覆盖下面独立审计发现的缺口。

| 实际保存 scope | 接受数与原角色 |
|---|---|
| native external IRQ taken | 4；1 bootstrap／3 fuzz_source |
| controlled external IRQ entry | 4；1 bootstrap／3 fuzz_source |
| retired UART RDATA read | **3**；1 bootstrap／2 fuzz_source |
| native cause／FIFO 留存／FIFO read | 20／4／4 |

独立审计发现 **143** 条 `raw_cpu_certainty_barrier`。第 257 条同 epoch 取指响应（event44267、instr sequence257）触发旧默认 `CpuRetirementMatcher.max_pending=256` 的 `instruction_capacity_exceeded`；第 4 个真实 RDATA `lw` 存在，但保持未提升。该退休 event46592 在 tick1292／order300／PC`0x10230`，x3 与 mem_rdata 为128，data sequence16。不能因为值正确、完整 replay 相等或其他三条 read 成功，就删除此屏障或把第四条补成 accepted。

四个受控首入口的真实 PC 均为`0x1012c`，完整 POST RVFI／frozen image 证据有效；这不改变该 run 未达到 absence-of-incomplete／四条 read 完整门槛的结论。Trace SHA256：`84c9a12614d098eda21de0619b1e8eaa9e245497cdd3aecffc414cb341c23749`。后续 Runner/容量改动改变源身份，该目录不得被重新解释为修正后源码验收。

## 明确容量修正与新真实门禁

当前实现明确给 Runner 原退休 matcher 和重构 read linker 同一个 **2048** instruction-witness 预算，保留真实超限时 certainty loss；不是事后改变已丢失状态的 live 对象或静默清空 degraded。旧 raw prefix 的只读软件复算显示256会触发屏障，2048可保留329条取指证据并识别同一第四条 `lw`；这只证明预算足够该 prefix，不证明无限长会话或 instruction history GC。

冻结源码下的[新在线运行](../../runs/current-dataflow-p2-controlled-entry-read-20261006-capacity2048-frozen-online/)使用独立新 cache、`--cpu-retirement --uart-fifo --seconds 20 --max-tests 4 --seed 43`，命令为：

```sh
/usr/bin/python3 scripts/run_ibex_uart_online.py run --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz --cache-dir runs/current-dataflow-p2-controlled-entry-read-20261006-capacity2048-frozen-cache --output runs/current-dataflow-p2-controlled-entry-read-20261006-capacity2048-frozen-online --seconds 20 --max-tests 4 --seed 43 --run-id current-dataflow-p2-controlled-entry-read-20261006-capacity2048-frozen --cpu-retirement --uart-fifo
```

实际退出码 0，4/4 case `complete`，client 返回 0；online 有 48,315 条事件。独立[只读材料审计](../../.superpowers/sdd/current-dataflow-p2-controlled-entry-read-capacity2048-audit.json)退出码 0：`cpu_external_irq_taken`、`controlled_uart_external_irq_entry`、`cpu_retired_uart_rdata_read` 各 4 条 accepted，每类都是 1 条 bootstrap／3 条 fuzz_source；相关 incomplete、`instruction_capacity_exceeded` 和 raw certainty barrier 均为 0。四条实际 `lw` 的 data sequence 为 4／8／12／16，退休 order 为 81／151／226／300，读值为 90／126／127／128；四个受控入口的退休 PC 均为 `0x1012c`。审计时重验了保存的 artifact 哈希、当时磁盘 host/build source、路径与安装身份、原始 sample/take/binding、44 字段 POST 退休、冻结镜像取指和 UART 请求／响应引用；其 scope 是材料身份与原始引用一致性，不把 accepted 标签本身当作语义证明。其后工作区 Runner 再次变化，不能将本次保存证据说成当前源码重新通过。

另用新的 replay cache 执行以下完整 fresh replay，退出码 0，`matches=true`、`first_difference=null`：

```sh
/usr/bin/python3 scripts/run_ibex_uart_online.py replay --cache-dir runs/current-dataflow-p2-controlled-entry-read-20261006-capacity2048-frozen-replay-cache --plan runs/current-dataflow-p2-controlled-entry-read-20261006-capacity2048-frozen-online/online_plan.json --trace runs/current-dataflow-p2-controlled-entry-read-20261006-capacity2048-frozen-online/online_final_trace.json
```

独立 fixture 用 `MYFUZZ_UART_CONTROLLED_ENTRY_READ_REAL=1`、`MYFUZZ_UART_CONTROLLED_ENTRY_READ_RUN_DIR=<新在线目录>`、`MYFUZZ_UART_CONTROLLED_ENTRY_READ_CACHE_DIR=<新 replay cache>` 执行 `PYTHONPATH=src:. /usr/bin/python3 -m pytest -q tests/integration/test_uart_controlled_entry_read_real.py`，重建原始 FIFO／native／entry／read 模型，逐事件比较完整 wire 前缀与 local ticks，并运行删除见证和自签拒绝检查：**5 passed，8 subtests passed，228.75 秒，退出码 0**。审计脚本原先误把 UART 请求／响应 tick 观察当成 CPU `data_accept/data_response`；该失败复现后已改为验证实际 `uart_tick_observation` 的完整 transaction key 和请求／响应引用，再运行审计通过。

保存身份：plan SHA256 `dac70dd4a7889d9e509ae91513b26bcb37d223c915131969a1cc0a9c529eff89`；manifest `2ed310ec87d84557a35200f9af0b9fe7112cf34c6a0f6324b23cbdc34db79bf2`；run identity `0f865d04f5fbfef375d13835652a4e8f07e2746ae5301189e0f3b9d886c0c321`；trace `0ff041986b419c99f3d0dbc5e0be8808168ad651a32e0d764a8e50f238cdfa5e`。CPU/UART build digest 分别为 `247c15c9d150c8ceb9a784e285a50b80ef347ab2714852c3485c9202e50a6a80`／`44a201293ee061d946a4aa9fdc596140e33e0c2d4534b2edb5cf19cc19d0e`，runtime artifact 分别为 `9fa36802e854d1e5bf148643c6529bb8c7db6cdf6f1221202b73025a8449f09b`／`5034cc6d2628d1660c80a7cbfe41493e7ba6a8357d76a821379ddbcfdc4de2f1`；host source closure 有 394 份文件。

另一次[2048 容量在线运行](../../runs/current-dataflow-p2-controlled-entry-read-20261006-capacity2048-online/)也产生 4/4/4 accepted 且无容量屏障，但运行期间 `rv32i_sources.py` 被并行任务改动，保存值与现行值不同，独立审计和 fresh replay 均在 host source identity 检查退出码 1。该目录只保存为身份漂移失败边界，不作为通过证据。首次 256 容量失败与其完整 replay 同样保留原样。

## 后续 Runner 变更后的重验及再次源码漂移

P5 私有 event lookup 修改 Runner 后，冻结目录的 host source identity 与磁盘源码只在 `src/myfuzz/scenario/runner.py` 不同，不能用旧 trace 对该版本宣称 fresh replay。为此独立建立[新在线目录](../../runs/current-dataflow-p2-controlled-entry-read-20261006-current-p5lookup-online/)与 cache，仍用 `--cpu-retirement --uart-fifo --seconds 20 --max-tests 4 --seed 43`。实际 4/4 case complete，client exit 0，保存 48,315 事件。只读 `audit_uart_controlled_entry_read.py` 对当时磁盘源与保存 artifact 复核退出 0：taken、受控 entry、退休 RDATA read 各 4 accepted，均为 1 bootstrap／3 fuzz_source；相关 incomplete 与容量屏障为 0。无 RTL 编译的独立语义 fixture 为 7 passed、8 个删除／拒绝子检查通过，fresh 项单独排除（163.17 秒）。使用独立 replay cache 的 CLI 完整 fresh replay 在执行时返回 `matches=true`、`first_difference=null`。新 trace SHA256 为 `9c85a5a5f857c3c31db5d23b39fd1461ed2fb71f04767f71b89c66f8e30f08ff`。

随后单独执行 fixture 的完整 wire prefix 与 local tick 检查时，重建的 manifest identity 已不一致，测试失败。检查保存的 394 文件 host closure 与当时磁盘源码发现 `host_identity.py`、`runner.py`、`session_runtime.py` 哈希变化，并新增 `uart_operand_seed.py`。因此该目录只证明上述操作发生时的保存源码状态，**不作为后续当前源码的 P2 重验通过证据**；该次完整 fixture 未通过。源码冻结后另起的新门禁结果见下节。

## 源码冻结后的当前版本门禁

在生产源码冻结后，再从空目录建立[当前版本在线材料](../../runs/current-dataflow-p2-controlled-entry-read-20261006-finalfreeze-online/)和独立 cache，以相同 4-case、seed 43、2048 预算的真实 Ibex＋OpenTitan UART RTL 配置运行。在线 4/4 complete；保存 48,319 事件。独立只读材料审计退出码 0：native taken／受控 entry／退休 RDATA `lw` 各 4 accepted，均为 1 bootstrap／3 fuzz_source；相关 incomplete、容量和 certainty 屏障为 0。真实读取的 data sequence 仍为 4／8／12／16，退休 order 81／151／226／300，值为 90／126／127／128。

完整 `tests/integration/test_uart_controlled_entry_read_real.py` 以新 replay cache 运行，**8 passed、8 个删除／拒绝子检查通过，263.20 秒，退出码 0**；其中 fresh replay 的全部 48,319 条 canonical wire 事件和 local ticks 一致，`first_difference=null`。运行前后保存的 395 文件 host source closure 均与磁盘源码相等，审计还验证了 build/artifact、在线 identity、原始 UART/CPU 见证引用。plan SHA256 `dac70dd4a7889d9e509ae91513b26bcb37d223c915131969a1cc0a9c529eff89`；manifest `235c326d72872b5bc60d30650573a5d3daed5939bab320a8021da72fe894f048`；online identity 文件 `629fa2aa35efbfade4133ec30ec2018f845bf37e3ea083e51f3dc4ed5fca0673`；trace `4e78b0d5eb52929ddb24820d876c45f766799cd4b3fdf09ab89a487ecc84f37a`。CPU/UART build digest 为 `0f42c1daa3a3c3c671056c6316c7c3c7e27b08d10c8e8da5770b1e0beaddd5e6`／`ff4c103c9c9e25c870993f2cf10ac4fe11113c4b69f510b89e86cb65f7e84626`。此证据只授予固定受控 UART 子路径，通用 ISR、CPU 操作数、P2 整阶段与十分钟效率仍需独立门禁。

## 隔离源码快照门禁

另在授权的只读实现快照 `/home/qinkejiu/myfuzz_snapshot_p5_20261006` 中执行同一真实门禁，所有新输出仍存放原仓库的[快照在线目录](../../runs/current-dataflow-p2-controlled-entry-read-20261006-snapshotp5-online/)、`runs/current-dataflow-p2-controlled-entry-read-20261006-snapshotp5-cache` 与独立 `...snapshotp5-replay-cache`。快照基础 34 文件 host identity SHA256 为 `a81d037b3980a73e6b46289095710e54310256283764f29c5f02873fb2867bc1`；本次实际 harness host closure 有 396 文件，canonical identity SHA256 为 `6a318815ead724da410d93ca3b1ded96fbfcb766b62e5cbd0f5483c8522b43cb`。运行前后保存的 closure 均与**快照**磁盘源码一致；这项证据不把原工作区随后编辑的文件视为同一源码。

在线 4/4 complete，保存 48,323 事件。快照中的独立只读材料审计退出码 0：native taken、受控 entry、退休 RDATA `lw` 各 4 accepted，均为 1 bootstrap／3 fuzz_source，相关 incomplete／容量／certainty 屏障为 0；四条读取的 data sequence 为 4／8／12／16，退休 order 为 81／151／226／300，读值为 90／126／127／128。快照源码执行的完整 fixture **8 passed、8 个删除／拒绝子检查通过，264.02 秒，退出码 0**；全 48,323 条 canonical wire 事件及 local ticks 的 fresh replay 一致，`first_difference=null`。

快照材料 SHA256：plan `dac70dd4a7889d9e509ae91513b26bcb37d223c915131969a1cc0a9c529eff89`，manifest `53bcc18c5e54dafdb6a60fe4b02e778672ca9d163aa49a823a84a72e69732ea1`，online identity 文件 `28eafebf44ec637078b0f3bdf4d5115986d77b7413d1ffafbae63556801d7d3c`，trace `df36033f5c35076216a29474c8ddd0bbab5a24f7a0ccf3e2e18c0bb95085abb2`。CPU/UART build digest 为 `d85593165a018d22556ca3da605d6ec37c23a397299bd98f5f45510edd97cf85`／`0509f657c1cfd0a1461d05a64efa7f6fb05b365f6debae4f38f1176c69172b11`。该快照结果认证固定受控 UART 子路径，仍不授予 P2 整阶段、通用 ISR、操作数传播或 P5 效率通过。

Generic ISR、操作数／后续 Store 来源仍 unknown；受控 setup 不扩展为任意 CSR／handler；reset-free online 捕获不认证实际 reset 波形。P2整体、通用反馈搜索、十分钟效率、自动组件接入和 DMA 均不由本报告授予通过。

证据：[首次只读审计及容量定位](../../.superpowers/sdd/current-dataflow-p2-controlled-online-independent-audit.md)、[首次 online 日志](../../.superpowers/sdd/current-dataflow-p2-controlled-entry-read-real-online-gate.txt)、[首次 fixture／fresh 日志](../../.superpowers/sdd/current-dataflow-p2-controlled-entry-read-real-fixture-gate.txt)、[CPU v2 软件记录](../../.superpowers/sdd/current-dataflow-p2-cpu-native-retirement-receipt-report.md)、[入口独立审查](../../.superpowers/sdd/current-dataflow-p3-controlled-entry-independent-review.json)、[退休 read 审查](../../.superpowers/sdd/current-dataflow-p2-uart-retired-read-independent-review.md)、[Root 集成审查](../../.superpowers/sdd/current-dataflow-p2-controlled-root-integration-independent-review.md)。所有本轮工作未 stage/commit。
