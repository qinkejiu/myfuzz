# P2 Task4 来源、资源快照与逐边候选实施记录

日期：2026-10-06。**P2 仍部分完成。** 本轮已实现合法输入登记、跨例 writer 来源、实际字节 writer 类型、物理边候选及反馈见证元数据；在本报告原sourceclosure中，完整 CPU→IP→CPU / IP→CPU→IP 因果闭环尚需真实退休与UART frame/FIFO探针；更晚closure的退休/帧续作见文末。没有暂存或提交。

## 已实现与证明范围

- SourceAdmission 是 immutable、版本化输入记录，绑定 case/index、source/path/direction、action、角色与规范输入 SHA-256。Registry 拒绝同 action 不同内容；fuzz_source、fixed_support、bootstrap 分开。登记事件只表示授权尝试，不计 RTL 消费。
- RuntimeEdgeIndex 初始化核对 graph/contract/topology/路径和逐位 ownership，拒绝重算摘要的错类型或错源材料。追加日志的 Binding 候选匹配真实端点和位段；IRQ 使用实际 Binding 位段。MMIO 只匹配声明的 route_window，不能从逻辑名称推断寄存器语义。多路径候选保留歧义。
- Runner 在 append 和 append_unchecked 前深度分离原始记录及元数据，observed_case 与 origin_admission_ids 分开。case B 读取 case A 的指令时保留 A 的 writer、资源版本及 admission；先前 journal 记录不随 case 或调用方修改。畸形/空白 writer 引用留为未知，不遮蔽真实失败记录。
- PersistentMemory 的 ReadSnapshot 逐字节冻结真实 ByteCell.writer_kind；之后 Store、byte-enable 写或 Ledger retry 不改变旧快照。MemoryService 默认保留旧事件格式，仅来源模式加入 writer_kinds。RAM 只有 INSTRUCTION_SOURCE 且登记类型为 instruction 才可关联 action；Store/FIRST_READ/INITIAL_IMAGE 不凭同名字符串冒认输入来源。
- Session 新 plan schema 10/11 保存来源配置、完整登记前缀和每例 source_role；replay 在 factory 前重新构造规范输入、路径来源和登记表，拒绝材料/角色/配置/失败命令索引篡改。登记部分失败单列 provenance_admission 阶段。schema 4～9 保留原语义。
- 交互反馈在既有真实值、交易和消费检查通过后引用 producer/delivery/consumer 见证元数据；consumer 提供观察上下文与资源，不混入无关来源。显式 producer step 通过其事件 ID 点查，不扫描完整历史。候选和元数据引用不提升闭环或图因果计数。

## 失败测试与独立审查

各模块先观察 RED 再实现。独立审查实际发现并复现：嵌套 topology 的 bool/整数混淆及错 ownership、空白 writer 遮蔽失败、浅拷贝污染 journal 前缀、消费端来源污染、遗漏显式 producer step、失败命令索引越界。修复后逐项复审通过。

第一轮真实 GPIO/UART 完整前缀 replay 通过后，补充反例复现了 Store 的 TransactionKey 字符串与 instruction action ID 相同导致误归属。旧材料保留为 **preliminary**，不替代修复后门禁。修复加入真实 writer 类型快照，并通过混合 lane、覆盖后冻结快照、Ledger retry 与实际 Store/action 同名反例。writer-kind 独立审查 75 项、60 个子测试通过。

完整命令及 root 工具结果转录见[整合记录](../../.superpowers/sdd/current-dataflow-p2-task4-root-regression.txt)。最终 root 整合命令在上一轮 317 项焦点命令基础上，加入 tests.scenario.test_source_provenance、test_runtime_edge_index、test_runner_source_provenance、test_online_source_provenance、test_interaction_edge_provenance、test_memory_service、test_persistent_memory。退出0：**397 项 /26.011秒 /OK(skipped=5)**；跳过项不计 RTL 证据。实际运输检查如下，退出0，16项 /1.678秒 /OK：

```bash
MYFUZZ_SCENARIO_RFUZZ_LIVE=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_campaign_run_identity tests.integration.test_scenario_rfuzz_live_client -q
```

模块报告与复审记录保存在 `.superpowers/sdd/current-dataflow-p2-task4-*`；[来源实施计划](../superpowers/plans/2026-10-06-source-provenance-task4.md)列出接口及未完成门禁。

## 当前真实门禁

writer 类型修复后重新创建独立证据目录，不能改旧证据摘要。单 worker 顺序 record/replay，每次按固定 source/profile/build/toolchain 身份归档：

```bash
python3 scripts/run_ibex_pulp_online.py run --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz --cache-dir /tmp/myfuzz-online-cache-20261006 --output runs/current-dataflow-p2-provenance-20261006-pulp-writer-kinds --seconds 20 --max-tests 120 --seed 20261006 --run-id current-dataflow-p2-provenance-20261006-pulp-writer-kinds
python3 scripts/run_ibex_pulp_online.py replay --cache-dir /tmp/myfuzz-online-cache-20261006 --plan runs/current-dataflow-p2-provenance-20261006-pulp-writer-kinds/online_plan.json --trace runs/current-dataflow-p2-provenance-20261006-pulp-writer-kinds/online_final_trace.json
python3 scripts/run_ibex_uart_online.py run --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz --cache-dir /tmp/myfuzz-ibex-uart-online-cache --output runs/current-dataflow-p2-provenance-20261006-uart-writer-kinds --seconds 8 --max-tests 2 --seed 123 --run-id current-dataflow-p2-provenance-20261006-uart-writer-kinds
python3 scripts/run_ibex_uart_online.py replay --cache-dir /tmp/myfuzz-ibex-uart-online-cache --plan runs/current-dataflow-p2-provenance-20261006-uart-writer-kinds/online_plan.json --trace runs/current-dataflow-p2-provenance-20261006-uart-writer-kinds/online_final_trace.json
```

GPIO run/replay 均退出0，120例全部 complete，CPU16/IP104；224个登记包含120个主源与104个 fixed support。520个后例指令读快照保留先前 case 的来源。真实 STORE 读事件1711的四 lane 均为 STORE，来源列表为空；不能冒认为在线 instruction 源。UART run/replay 也均退出0、matches=true，CPU/RX各1例，4个登记为bootstrap1、fuzz_source2、fixed_support1；2个跨例指令快照保留原始来源。两组完整trace及所有artifact/run身份、registry/context、边候选、writer kind独立审计通过。

## 原bundle时的剩余范围（历史快照）

在上述writer-kinds原bundle中，所有 MMIO、任意本地输出、IRQ 的最初输入来源仍未知；逐边候选不证明源到这些输出的因果关系。官方固定 Ibex top 提供 RVFI，但该bundle使用的默认profile未启用，尚需重新认证端口/宏/闭包及退休 PC/order/insn/内存访问到真实交易的配对。不能用最后取指给后续 MMIO 贴来源。

在该原closure中，UART peer还缺独立frame/action身份、真实 FIFO push/pop、错误帧/overflow/clear 与 RDATA 交易关联；native IRQ sampled/taken 和 pulse policy 要分别建立真实见证。短跑不替代受控故障校准、10分钟效率搜索门禁、P3～P8 或 DMA。详细差距见[探针审计](../../.superpowers/sdd/current-dataflow-p2-task4-causal-probe-audit.md)。

修复后 GPIO 实际搜索11.975582秒、UART1.762370秒即达到例数预算，不是持续20/8秒或10分钟门禁。GPIO548个INSTRUCTION_SOURCE读快照具备已知来源，520个跨例；156条真实STORE读快照全部保持unknown。UART8个指令快照具备已知来源，2个跨例；没有STORE读或IRQ taken。known-origin事件总数含授权登记和支持指令，不当作有效链数。

最终 run identity：GPIO ff7c5fc5dcd88909c73acdae621b8ea4f1502a84512bc33448675d6bc7654e17；UART c6bd49737179f0848b858744f80119cc2c7ea45f9697cd98776fe3581fc22625。证据目录保存gate_commands.json、run/replay日志与退出码、独立provenance_gate_summary.json。旧 preliminary bundle 所有宣告artifact摘要未变。详细材料见[修复后真实门禁](../../.superpowers/sdd/current-dataflow-p2-task4-real-gate-writer-kinds.md)。该轮结束时没有未结束的RTL进程，整体目标保持进行中。

后续sourceclosure已增加真实RVFI退休和UART action/frame驱动观察，详见[退休/帧续作](current-dataflow-p2-retirement-frames-20261006.md)。本报告原bundle与397项验证保持其记录时的源码身份；新增见证不自动提升完整GPIO/FIFO/IRQ闭环等级。
