# Ibex＋双 PULP GPIO 在线 RFuzz 运行记录

> **⚠ 复算可用性（2026-10-09 更新）**：本文引用的部分原始产物目录在 2026-10-09 的 `runs/` 清理中被删除，因此文中指向 `runs/` 的链接可能失效。**报告的结论、数字与边界仍然有效**（记录的是当时真实执行的结果），但"从原始产物复算"的能力已不存在。删除范围、已重建项与逐条断链清单见 [已删除的原始产物](DELETED_ARTIFACTS_20261009.md)。
日期：2026-10-06。此报告只覆盖当前固定 Ibex＋PULP GPIO A/B 实例；不是多协议通用框架的验收。

## 执行范围

三个真实 RTL 组件在各自生成的 harness 中启动一次。固定 Ibex 引导程序配置 GPIO B 中断与 GPIO A 输出后，CPU 从预约 RAM 区取在线指令；RFuzz 同时可以选择 GPIO B pin8 外部输入。GPIO A 的真实输出绑定 GPIO B 的低 8 位输入，GPIO B 的真实 IRQ 通过脉冲模型交付 CPU。每个 slot 在同一 Runner/RAM/事务状态上继续运行 32 轮局部调度，不重置 RTL；没有构造完整 SoC 总线或全局精确周期时序。

启动命令：

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_ibex_pulp_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir /tmp/myfuzz-online-cache-20261006 \
  --output runs/ibex-pulp-online-20261006-final4 \
  --seconds 15 --max-tests 120 --seed 20261006
```

实际处理 120 个 slot：CPU 在线指令源 16 个，GPIO B 外部输入源 104 个；状态均为 `complete`。有效搜索 8.038 秒，约 14.9 slot/秒；`--max-tests` 是硬上限，因此在达到 120 后结束，未用满 15 秒。累计真实局部 tick 为 CPU 3893、GPIO A 4137、GPIO B 4321。完整 trace 有 56,171 个事件。RFuzz 运输层的 `runs/s` 不等同于真实 RTL testcase 吞吐，此处采用主机 receipt 数除以有效搜索时间。

真实事件记录了 CPU 取在线指令、CPU MMIO 写 GPIO A PADOUT、GPIO A 输出到 GPIO B 输入的交付与消费、GPIO B IRQ 在 CPU 输入端采样，以及 CPU 读取 GPIO B 寄存器。GPIO A PADOUT 的 CPU MMIO 写有 5 种不同值。带数值及事务见证的交互反馈包含 52 条 `gpio_b→cpu→gpio_a` 有序路径和 52 条 `cpu→gpio_a→gpio_b→cpu` 有序读回路径；这两个计数是**观测路径**，并不证明指令级数据因果或 `irq_taken`。当前 harness 未暴露可关联的 `irq_taken_pre` 观测，因此 `closed_loops=0`，不能将路径计数写成已验收的完整闭环覆盖。CPU 指令与后续同地址/值 MMIO 的匹配、GPIO 输入采样与后续 IRQ 的匹配仅用于保守的搜索评分，均不冒充 RTL 内部因果证明。

## Fresh replay 与断言校准

将保存的 [`online_plan.json`](../../runs/ibex-pulp-online-20261006-final4/online_plan.json) 和 [`online_final_trace.json`](../../runs/ibex-pulp-online-20261006-final4/online_final_trace.json) 交给 `scripts/run_ibex_pulp_online.py replay`，新建三个 RTL harness 后得到 `matches=true`、`first_difference=null`。plan 文件 SHA-256 为 `b3c798488386fc8c01811b5b67343f0f272b70779576936a5c316447473ebdae`；trace 文件 SHA-256 为 `e19e4e67f08e9aebb3ef3e25898b16b55f2f95d318e14ae45bb6cc02e5e302ef`。replay 同时检查源码/配置 manifest、完整事件序列、状态和局部 tick。

另一次**受控断言校准**把“GPIO A PADOUT 不得写 1”故意设为错误属性；它在真实 RTL 写 1 时触发 `calibration_injected_property`。RFuzz 在 2 个完成例之后记录 1 个 `dut_violation` 并停止接纳后续 slot，保存的 trace 状态为 `finding`，fresh replay 匹配。校准文件在 [`runs/ibex-pulp-online-20261006-calibration2`](../../runs/ibex-pulp-online-20261006-calibration2)。这证明 finding/停止/完整前缀保存/重放链路可工作，**不表示发现真实 RTL bug**。默认真实检查器在 120 例中没有报告违反。

## 1000 例连续运行与容量边界

首次扩大预算时，本地 driver 的 64 MiB 命令重放缓存于第 347 例耗尽：346 例完成，随后返回 `resource_limit: replay_capacity`。该完整前缀 fresh replay 匹配；这是测试基础设施限制，不是 DUT bug。随后给本地命令协议加入累计 ACK：宿主完整接收并解析回执后，每 16 条确认一次；driver 回收旧回执并保留已退休序号下限，旧命令重试不会再次执行 RTL。同时减少在线会话的事件副本，并流式写出最终 trace。

在当前修订上重新运行 [`1000 例 plan`](../../runs/ibex-pulp-online-20261006-1k-ack/online_plan.json) 和 [`完整 trace`](../../runs/ibex-pulp-online-20261006-1k-ack/online_final_trace.json)：1000 例全部 `complete`，同一 CPU/双 GPIO 会话未重置；有效搜索 60.614 秒，约 16.50 例/秒。CPU 指令源 806 例，GPIO B 外部源 194 例。三个 harness 分别执行 CPU 32,053、GPIO A 34,033、GPIO B 33,433 个局部 tick；trace 含 370,070 个事件、文件约 228.9 MiB。交互摘要含 171 条 IRQ 采样→CPU 读→GPIO A 写的有序路径及 171 条 CPU 写→GPIO A→GPIO B→CPU 读的有序路径；`closed_loops=0`。fresh replay 得到 `matches=true`、`first_difference=null`。plan SHA-256 为 `63ebaf9a9ad587bc4147a62383aa02777cadc5842e3ff7d767b9021a0c76da9c`，trace SHA-256 为 `bfd3b23f7c511d33f870f2aa07eae906ff741ed6d898ca9c384a1f485442e460`。

1000 例证明命令缓存上限已突破，并验证了连续源选择、真实 RTL 执行和完整前缀重放。当时 Runner 仍在内存中保留全部事件；下面的长跑使用后续分段事件日志实现。

随后加入分段事件日志与 Ibex 控制器只读 `irq_taken_pre` 探针。同版本 [`1000 例 plan`](../../runs/ibex-pulp-online-20261006-1k-journal/online_plan.json)、[`JSONL 元数据`](../../runs/ibex-pulp-online-20261006-1k-journal/online_final_trace.meta.json) 和 [`事件日志`](../../runs/ibex-pulp-online-20261006-1k-journal/online_events.jsonl) 完成 1000/1000 例并 fresh replay 匹配：有效搜索 65.287 秒，约 15.32 例/秒；CPU 指令源 743 例、GPIO 外部源 257 例，370,778 条事件中有 170 条 `cpu_irq_taken`。JSONL 约 235.1 MiB。该探针观察真实 RTL 控制器时钟沿前的中断重定向决定，不能由 IRQ 输入高电平或向量取指替代。反馈另将 taken、读取消费与写入交付组成独立有序路径；`closed_loops` 仍专指 Bound Input 首尾回环，不等于所有跨组件路径的总数。

第一次尝试 600 秒搜索在约 2373 例时主动中止：尽管 Runner 已分段落盘，反馈器和检查器仍分别持有完整事件副本，内存持续增长。这次中止只有回执，没有可重放的终态 trace，**不计入十分钟验收**。随后检查器只保留事件哈希与结果；反馈器按需从磁盘事件日志读取，Runner 在在线 case 完整确认后退休 STEP 回执。冻结源码下再跑 1000 例，完整前缀 fresh replay 匹配，运行峰值 RSS 约 294 MiB。

## 600 秒长跑、重放及发现的环境边界

固定种子 `20261006`、预算 `--seconds 600 --max-tests 20000` 的真实 RFuzz 在线运行保存在 [`ibex-pulp-online-20261006-600s`](../../runs/ibex-pulp-online-20261006-600s)。三个 RTL harness 仅初始化一次，持续接纳 8232 例；有效搜索时间 647.902 秒，按全部回执计算约 12.70 例/秒。8231 例 `complete`，末例为 `environment_error`；没有默认检查器的 `dut_violation`。CPU 在线指令源选中 7944 次，GPIO B 外部 pin 源选中 257 次；末例在解码后发生错误，未计入上述已应用来源次数。完整 trace 为 2,749,640 个事件，JSONL 约 1.8 GiB；三个 harness 累计局部 tick 为 CPU 263,453、GPIO A 278,364、GPIO B 267,848。运行期间可用内存保持约 5 GiB；这些数字仅描述本次固定机器与配置。

增量交互反馈记录了 1096 次 CPU 控制器 `irq_taken` 观察、548 条 `irq_taken→CPU 读取 GPIO B→CPU 写 GPIO A` 有序路径，以及 547 条 `CPU 写 GPIO A→GPIO A 输出→GPIO B 输入→CPU 读回` 有序路径。它们是实际事件序列见证，不等同于每条指令的完整数据因果证明。`closed_loops` 仍按 Bound Input 首尾回环的单独定义计数。CPU/IP 双侧源都确实被选择，但同权重时的主机提示固定偏向索引 0，造成明显 CPU 倾斜；此问题在长跑后修复，旧运行统计不代表修复后的分布。

使用长跑前 30 条完全相同的原始 8-byte 记录和当时的 `online_weights` 做逐例冷启动对照，证据为 [`cold baseline`](../../runs/ibex-pulp-cold-baseline-20261006.json)。30/30 例均 `complete`，source/path 与原回执 30/30 兼容。每例新建 Ibex＋双 GPIO runtime 的总耗时 525.046 秒，平均 17.502 秒/例；其中初始化合计 522.554 秒，解码 0.008 秒，执行合计 1.598 秒，结束 0.886 秒。在线长跑按有效搜索时间为约 0.0787 秒/例，两者在本机观察到约 222 倍的平均每例墙钟差异。该比较只衡量重复初始化成本；冷启动会丢失历史 RAM、IRQ、覆盖和源选择状态，因此不能用于证明覆盖或 bug 发现能力的倍数提升。

末例的两条合法在线指令恰好填满 `0x11000..0x20000` 的可变区。CPU 随后从 `0x20000`、`0x20004` 首次物化的随机 RAM 字节取指，真实发出了未映射写请求；环境按 `uncertain_effect` 停止接纳后续输入。这是**指令流尾端保护缺失**，不是 DUT bug。完整 [`plan`](../../runs/ibex-pulp-online-20261006-600s/online_plan.json) 与 [`trace 元数据`](../../runs/ibex-pulp-online-20261006-600s/online_final_trace.meta.json) 在未修改的源码上由新建的三个 RTL 进程重放得到 `matches=true`、`first_difference=null`，包括相同的终态。plan SHA-256 为 `77bf25ad0eb37b838bba283f9bc01e4b1498a0f5384dcccb0bc5661dedd38b3b`，trace 元数据 SHA-256 为 `f975177510f0dae04c050db77fc34eb276afd829d711dd1ab9af11fd0488fe68`，事件 JSONL SHA-256 为 `c87328da710f314545de62489acb838790741d8e4855958f8fdf46bcbd4072d5`。随后 bootstrap 在可变区外增设 16 个固定自环指令，覆盖 Ibex 观察到的尾端投机取指；该改动改变场景身份，不能以新源码要求旧运行的 manifest replay 再次互认。 使用仅两条在线指令的真实 Ibex＋双 GPIO 边界场景验证：CPU 对尾端及下一预取地址均读取固定 `0x0000006f`，GPIO B 外部输入继续被接纳，完整前缀 fresh replay 匹配。

## 仍需验收

- 新增的固定尾端指令已通过真实 RTL 边界短跑与 fresh replay；来源平局修复仍需同版较长搜索验证实际 CPU/IP 选择分布。
- 为每个依赖路径建立能证明指令 retire 与 IP 内部状态转移的源到下游精确归因；当前只用严格观测关联指导搜索，不能将评分视为完整因果证明。
- 增量交互摘要和分段事件日志支持本次 600 秒运行；逐例冷启动成本对照已完成，仍需进一步控制大事件日志的落盘成本。
- OpenTitan UART 已接入真实双源 RFuzz 在线短跑并 fresh replay；UART 搜索速度仍需优化，其他协议实例还需扩展。

证据目录中的 `report.json`、`receipts.jsonl`、`decoder_manifest.json`、plan、trace、corpus 与 RFuzz client log 保留原始结果。源身份必须与保存时一致；修改相关代码后，旧 trace 按设计不应被新源码 replay 接受。
