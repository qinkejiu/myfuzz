# P4 候选选择与接纳原因：冻结源码真实短门禁

> **⚠ 复算可用性（2026-10-09 更新）**：本文引用的部分原始产物目录在 2026-10-09 的 `runs/` 清理中被删除，因此文中指向 `runs/` 的链接可能失效。**报告的结论、数字与边界仍然有效**（记录的是当时真实执行的结果），但"从原始产物复算"的能力已不存在。删除范围、已重建项与逐条断链清单见 [已删除的原始产物](DELETED_ARTIFACTS_20261009.md)。
日期：2026-10-07。在线决策和 RFuzz 回执增加三项诊断字段：`source_selection_reason` 区分合法直接源字节与在所选可执行路径内按反馈权重回退选源；`candidate_disposition` 和 `candidate_disposition_reason` 区分已提交、解码拒绝、提交前校验拒绝和提交调用失败或局部生效而结果不确定。这里的“已提交”指在线 case 已由 `submit_case` 返回且 decoder reservation 已提交，不等于源已被真实 RTL 消费或数据流闭环。

测试先暴露一个分类错误：代码在运行时路径校验前就标记 `submit_attempted`，使提交前的校验失败看起来可能有 RTL 副作用。现将标记移到校验后；提交调用一旦开始而未确认 commit，则保守记为 `uncertain/rtl_submit_failed_or_partial`。解码失败记 `rejected/decode_rejected`，提交前校验失败记 `rejected/pre_submit_validation_rejected`。定向测试覆盖上述三类及正常接纳、合法直接选源和非法直接字节的权重回退；`test_scenario_rfuzz_terminal_identity.py`、`test_scenario_online_credit.py`、`test_online_path_first_selection.py` 合计 **39 passed、2 subtests passed**。

## 源码身份与真实运行

独立源码快照 `/home/qinkejiu/myfuzz_snapshot_p4_disposition_20261007` 中 1,808 个 `src/`、`configs/`、`scripts/`、`schemas/`、`tests/` 文件见 [SHA-256 清单](../../runs/current-dataflow-p4-disposition-snapshot-20261007.sha256)，清单哈希 `6d455cb29f33e9c85f619cc17909c133430833191f445cf7dab912501ca85e45`；在线身份中的 36 个源码文件逐一匹配，运行与 replay 后清单 0 差异。在快照中执行：

```text
/usr/bin/python3 scripts/run_ibex_pulp_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p5-timing-20261007-cache \
  --output /home/qinkejiu/myfuzz/runs/current-dataflow-p4-disposition-20261007-online \
  --seconds 30 --max-tests 25 --seed 20261007 \
  --run-id current-dataflow-p4-disposition-20261007
```

退出码 0；25/25 例 `complete`，有效搜索 2.048 秒，完整 trace 10,390 事件。25 份[回执](../../runs/current-dataflow-p4-disposition-20261007-online/receipts.jsonl)的选择原因是 `direct_source_byte` 14 次、`feedback_weighted_legal_source` 11 次；全部为 `admitted/rtl_case_committed`。独立用回执原始字节、保存的 decoder manifest 源顺序及六项候选字段复算，25/25 项选择原因与候选 ID 均相符。这份正常运行没有真实拒绝或不确定例；这些分支仅有前述软件门禁。

同一快照用独立 cache 执行完整 fresh replay：

```text
/usr/bin/python3 scripts/run_ibex_pulp_online.py replay \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p4-disposition-20261007-replay-cache \
  --plan /home/qinkejiu/myfuzz/runs/current-dataflow-p4-disposition-20261007-online/online_plan.json \
  --trace /home/qinkejiu/myfuzz/runs/current-dataflow-p4-disposition-20261007-online/online_final_trace.json
```

退出码 0，`matches=true`、`first_difference=null`、`difference_context=null`。该门禁证明所列固定场景的选择／接纳诊断可审计，不证明操作子对目标覆盖有效、跨例反馈改变变异能量、CPU 计算到外设的完整来源或 P4 阶段验收。拒绝原因目前按流水阶段分类；更细的 ISA/profile 约束拒绝码及同预算独立驱动对照仍待补齐。
