# Stage 2 D1：三类依赖记录分离

日期：2026-10-11。D1 已完成。新增 `dependency_evidence.v1` 和 `dependency_evidence_ledger.v1` 分类 API／报告／JSON 保存与加载；下一工作包 D2。此项完成的是记录契约，不是运行因果证明或 DUT 授级。

`DependencyEvidence` 是不可变记录，包含 evidence type、relation、source/target、proof scope、证据引用、规则 ID/版本、逐组件局部 epoch、可选声明引用和有效性。declared 只允许 `declared_topology`，没有运行 epoch；candidate 只允许 `event_correlation`；verified 必须声明关系支持的证明范围、至少两个证据引用和局部 epoch。类型、epoch、引用、长度、关系/范围及有效性 fail closed；记录摘要按规范化 JSON 复算。

`DependencyEvidenceLedger` 将 declared/candidate/verified 分组保存和报告。运行记录可以引用匹配 relation/source/target 的既有声明，声明原记录保持存在。候选没有晋级方法，也不向 Runner、Router、Scheduler 或 `RuntimePathContract` 回写拓扑。`from_prepared_contract()` 只投影已选路径中有显式运行契约的边，不根据 EVENT_ORDER 补造因果边，不产生 candidate 或 verified。

存储和报告明确标记 `proof_scope=classified_records_only`、`record_counts`。加载一个 verified 格式记录只验证其文档及摘要，不认证其中引用的真实事件；D3 必须核对 journal 和规则后才能把运行证明用于反馈，D6 负责 active witness。这一边界避免把 schema 合法性当作 prerequisite。当前没有新增 prerequisite 授权 API，也没有 Stage 2 生产运行器消费此模块。

每类保存数量有显式上限（默认 4,096；最大配置 65,536），满容量拒绝追加，不静默删除证明历史。每记录最多 64 个证据引用及 64 个组件 epoch，字符串长度最多 1,024。重复记录幂等；保存重载、错误分组、计数/摘要篡改、未知键、候选自授证明范围和无效 epoch 均有负例。文档返回 detached 数据，不暴露内部容器。

验证：

```bash
PYTHONPATH=.:src python3 -m pytest -q tests/scenario/test_dependency_evidence.py --tb=short
```

首轮 23 passed；补充显式声明引用匹配、linked 保存重载和调用方强制改写记录后，D1 最终 27 passed。实现前确认新增测试因缺少 `dependency_evidence` 模块不能运行；实现后通过。

```bash
PYTHONPATH=.:src python3 -m pytest -q \
  tests/scenario/test_dependency_evidence.py \
  tests/scenario/test_dependency_edge_paths.py \
  tests/scenario/test_runtime_path_contract.py \
  tests/scenario/test_runtime_edge_index.py \
  tests/scenario/test_source_provenance.py \
  tests/scenario/test_runner_source_provenance.py \
  tests/scenario/test_ip_plugin_free_fixtures.py \
  tests/scenario/test_ip_plugin_import_boundary.py --tb=short
```

首轮 122 passed，151 subtests passed；加入 D2 及额外负例后，共同回归 190 passed，218 subtests passed，命令见 [D2 报告](stage2-d2-bounded-candidates-20261011.md)。`compileall`、`git diff --check` 通过。只读独立审查对 D1 文档分类范围未发现阻断问题；对 direct 源锁提出的两个问题在 C7 报告记录，按各自负例修复，不计入 D1 的运行依赖证明。

入口：[实现](../../src/myfuzz/scenario/dependency_evidence.py)、[测试](../../tests/scenario/test_dependency_evidence.py)、[主计划](../superpowers/plans/2026-10-09-stage2-declarative-cpu-ip-adaptation.md)。D2–D8、寄存器规则、真实新 IP 与 CPU/IP 组合仍待实施验收。
