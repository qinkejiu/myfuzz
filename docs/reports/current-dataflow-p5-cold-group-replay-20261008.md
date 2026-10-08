# P5 冷组逐例 fresh replay：15/15 可复现例通过，9 例因一个输入无效例级联拒绝

日期：2026-10-08。P5 的同预算配对要求"用固定输入/种子、同一源码和相同断言比较连续会话与逐 testcase 启动"，此前的[配对报告](current-dataflow-p5-paired-continuous-cold-start-20261007.md)把"冷启动逐例 replay 未跑"列为限制。本报告在**冻结源码**（无并发编辑）上重录一份同源 bundle，并对冷组每一例做逐例 fresh replay。

## 命令与产物

```bash
bash runs/current-dataflow-p5-final-20261007-logs/p5_paired_frozen_gate.sh
# 连续枝：16/24 例所需参数 --seconds 60 --max-tests 24 --seed 20261007 --cpu-retirement --native-irq-receipts --gpio-consumption
# 冷组： run_first_step_cold_start_run.py run --continuous-run-dir <连续枝> --max-cases 24
# 对照： bench_first_step_paired.py compare   逐例 replay：每例 replay_ibex_pulp_online_files
```

产物：连续枝 `runs/p5-paired-frozen-20261008-a-online`（24 例：**23 complete + 1 input_invalid**，32.461 有效秒）、冷组 `runs/p5-paired-frozen-20261008-a-cold-start`（24 例请求，**15 例发布/验证**）。

## 结果

| 项 | 结果 |
|---|---|
| 连续枝 fresh replay | `matches=true`（`first_difference=null`） |
| 冷组逐例 fresh replay | **15/15 `matches=true`**（每个发布例各起一个独立 RTL 进程） |
| 冷组未发布例 | 9 例（索引 15～23），全部因"前缀例 15 不可复现"被拒绝，**没有 plan 文件**，因此不存在可 replay 的对象 |
| 同预算配对对照 | `paired-efficiency-insufficient-data`：`continuous=24 cold=15`，对照器按设计**拒绝**逐例对齐（不手工补齐） |

## 为什么是 9 例级联：一个预 RTL 拒绝例

连续枝第 15 例（0 基）是 `input_invalid`：

- `candidate_disposition_reason = source_action_not_constructible`，错误为 `DynamicBindingUnbound: untrusted_source_provenance … memory 'ram' byte 0x0 has no provenance recorded by this binder`——该例在任何 RTL 命令之前就被 shipped 源动作门拒绝；
- 因此它的回执 `effective_genome_sha256 = null`（被拒候选没有 genome）；
- 冷组必须用同一 raw（`000000d00d0106b0`）在新进程里重放该例：新解码器**能**产出一个候选（`online-15-6dcf…` / genome `d284c01c…`），但它与保存的 `(case_id, genome=null)` 不相等 → `decode_reproduces_saved_case=false` → `ColdStartCaseError`；
- 冷组此后每一例都以"prefix case 15 is not reproducible"拒绝（第 16～23 例），所以 9 例失败是**一个**不可复现例的级联，而不是 9 个独立缺陷。

这是逐例冷启动方法学的真实边界：**连续 bundle 里存在"预 RTL 拒绝例"时，case-by-case 对齐在构造上不可能**——被拒例没有可比较的 genome，而新解码器无法复现"当时为什么被拒"（拒绝取决于当时的源动作/前置条件状态）。旧 24/24 全对齐 bundle（`runs/current-dataflow-p5-paired-20261007-*`）只是恰好没有这类例，且因解码空间漂移已不可重放。

## 结论与限制

**结论**：在冻结源码上，冷组**每一例能独立复现的 testcase 都通过了逐例 fresh RTL replay（15/15）**；连续枝本身也 replay 一致。尚未复现的 9 例有精确、可复核的原因（一个 `source_action_not_constructible` 例使前缀链不可复现），并且工具链全程 fail-closed：不发布 plan、不补贴用例、对照器拒绝数量不一致。

**限制**：

- 本报告不声称"连续 vs 冷启动"的有效例/s 或完整链/s 对照：该 bundle 无法逐例对齐，对照器因此拒绝出结论；此前的 1/16 墙钟对照基于另一个（已不可重放的）bundle。
- 15/15 的 replay 一致性只覆盖这 15 个可复现例，不含被拒例与后续级联例。
- "预 RTL 拒绝例破坏冷组对齐"是方法学结论，不是缺陷；若要得到全对齐 bundle，需要在采样时排除"含预 RTL 拒绝例"的连续运行，或让冷组把这类例标记为 `not_reproducible` 后**从该例之后继续**（后者需要新的声明与证据规则，本报告未实现）。
