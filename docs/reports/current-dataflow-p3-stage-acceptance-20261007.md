# P3 阶段验收：目标动作、持续会话与跨例传播

日期：2026-10-07。本报告按主实施计划 P3 的验收条文逐条汇总证据。判定由两个冻结消费者给出：`src/myfuzz/scenario/p3_acceptance.py`（单 run 报告 `p3_acceptance_report.v1`）与 `src/myfuzz/scenario/p3_acceptance_suite.py`（跨 run 并集 `p3_acceptance_suite.v1`）。

## 验收门禁

```bash
cd /home/qinkejiu/myfuzz
PYTHONPATH=src python3 scripts/run_p3_acceptance_suite.py \
  --run primary=runs/p3-lane-selectivity2-20261007-online \
  --run cross_case=runs/p3-ip-cross-case-20261007-online \
  --run feedback=runs/current-dataflow-p5-chain-600s-20261007-online \
  --run controlled_fault=runs/current-dataflow-p5-fault-calibration-20261007-online@runs/current-dataflow-p5-fault-calibration-20261007-reproduce
```

**退出码 0**，`ready=true`：每个关键子项都至少被一个声明 run 证明。

| 验收子项 | 状态 | 由哪个 run 证明 | 关键实测 |
|---|---|---|---|
| `single_initialization`（单次初始化、≥3 例、无 harness 重建） | met | primary / cross_case / feedback / controlled_fault | 例序号连续单调、回执绑定同一 manifest 身份、无重建事件；p5 600 秒 run 368 例 |
| `store_then_load`（第 1 例 Store M[A]=X → 后例 Load 返回 X，含 byte-enable lane 选择性） | met | **primary**（`runs/p3-lane-selectivity2-20261007-online`） | 跨例精确匹配 **232** 个 lane 匹配、0 值冲突、0 同例匹配；**20** 次部分字节使能写、**9** 次未使能 lane 检查、**0** 次误采纳；首次未知读复用 met（24 个物化 lane、296 次复用、0 次重物化） |
| `cross_case_chains`（CPU→IP→CPU 与 IP→CPU→IP 跨例） | met | **cross_case**（`runs/p3-ip-cross-case-20261007-online`） | IP 方向 **3 条跨例链**（`case_gap` 全为 1），代表证书 `4dd1a703…` 源 case 2 → 端点 case 3，17 跳 `pin8_admission 3378 → … → isr_padin_retirement 4447`；CPU 方向另有 1 条跨例链 |
| `feedback_changes_next_input`（逐例反馈改变下一例输入） | met | primary / feedback | 600 秒 run：第 15 例产生增益后第 16 例由 `direct_source_byte` 改为 `feedback_weighted_legal_source` 并改变源 |
| `finding_stops_and_replays`（finding 停止接纳 + 前缀新进程复现） | met | **controlled_fault** + `compare_run` | 注入观测错误后真实会话停止并保存前缀；由 `minimal_replay.json` 在新进程复现同一 case 与同一 finding（注入校准，非自然缺陷） |
| `chunk_split_invariance`（chunk 切分不改变规范化输入/末态） | met | 四个 run | 该 run 自身声明的 genome 经真实 `ChunkAssembler` 在 5 种切分模式下重组后逐字节相同 |
| `execution_identity`（换 execution ID 不接受旧回执） | met | 四个 run | 真实 `ScenarioRunner.execute_step`：同 ID 返回缓存回执且 0 额外 harness 步；不同 ID 以 `stale_execution` 拒绝且 0 harness 步 |

支撑本轮补齐的两项能力（均显式 opt-in、默认关闭、默认身份逐字节不变）：

| enabler | 作用 | 相关 run |
|---|---|---|
| 结果槽读窗口 + `--memory-commit` + `--result-slot-byte-store` | 让"读结果槽的 `LW`"可生成、真实 `memory_write_commit` 可落盘、结果槽可做 `SB` 单 lane 写 | `runs/p3-ram-prereq-20261007-online`（RAM 版本先决条件绑定）、`runs/p3-lane-selectivity2-20261007-online`（lane 选择性） |
| `MYFUZZ_IP_CROSS_CASE`（源 case 只走 1 个声明 round） | 使外部源引发的 IRQ 结构上必须在**下一例**被 CPU 接受 | `runs/p3-ip-cross-case-20261007-online` |

## P3 验收条文的逐条对应

- 源动作契约：`source_action.v1`（`instruction` / `external_event`，`interrupt_flow` 仅作观察目标）已接入在线 executor，并在任何 RTL 命令之前查询先决条件（拒绝时 runner 事件数/tick/cases 零变化）。
- 会话与例分离：一次 `begin`、多例 `submit_case`，逐例独立 `case_id` 与增量反馈。
- RFuzz live 对齐：长会话、按 `(session_id, buffer_id, slot, raw_hash)` 幂等重传、逐 slot 回执。
- 失败停止与前缀重放：受控故障 run 上真实成立。
- 跨例传播：CPU→IP→CPU（6/5/1 条跨例链）与 IP→CPU→IP（3 条，本轮新增）均有真实证据。
- 反馈改选：600 秒 run 内实测发生。

## 明示边界

1. **没有任何单个 run 同时证明全部 7 项**（逐 run 覆盖最高 5/7）。`gate.exit_code=0` 的含义是"每个关键子项至少有一个证明 run"，**不是**单 run P3 通过；该事实写入报告 `limits.single_run_vs_cross_run_union`。
2. `finding_stops_and_replays` 由**注入故障校准**提供（受控观测副本），证明的是停止/保存/重放机制，不代表发现自然 RTL 缺陷。
3. `chunk_split_invariance.rtl_event_level` 为非关键项且恒为 `null`：真实 RTL 分块等价需要独立真实测试（`tests/integration/test_scenario_irq_chunk_batch_equivalence_real.py` + `MYFUZZ_SCENARIO_INVARIANCE` 类环境门禁），本轮未跑。
4. run 角色由调用方声明，suite 不校验其来源；报告 `proof_scope` 明确它是"跨 run 并集"。
5. `runs/p3-ip-cross-case-20261007-online` 曾出现 1 次 `unsupported_irq_overrun`（IP 跨例模式下待决 IRQ 与后续 IRQ 竞争）；该 run 的跨例链证据不受影响，但这说明该 opt-in 模式的稳定性仍未做长跑验收。
6. 所有结论绑定各自 run 身份与冻结消费者字节（报告内 `engine.*.sha256`）。
