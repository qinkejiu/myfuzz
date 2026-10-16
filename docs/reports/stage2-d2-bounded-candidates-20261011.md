# Stage 2 D2：有界候选相关性发现

日期：2026-10-11。D2 已完成。下一项 D3 为精确运行证据消费；D8 的默认关闭、每 case 能量限制及 replay identity 尚未接入生产调度。此报告不主张任何候选已获认证。

`DependencyCandidateConsumer` 从真实基础投影使用的 `ip_base_event.v1` 端口样本／变化事件发现值匹配及接收窗口关系。`CandidateSignal` 固定 component、instance、endpoint、role、物理端口、方向及精确位范围，`CandidateRelation` 固定建议关系；未知名称不触发特判。不同组件使用各自 epoch，窗口按 journal 位置计算，不假设不同本地时钟具有全局周期顺序。

候选覆盖上下文由 C6 `IpBaseCoverageConsumer` 按相同游标读取实际事件产生，只使用声明有限集合内首次出现的基础特征，并保存对应 journal 引用。调用方直接提供“新增覆盖”被拒绝。畸形协议 envelope、错误物理切片、非法值／假变化、超宽 epoch、bool 身份、缺失／重复／未来 raw 引用及旧 epoch 不能增加覆盖上下文。有效但协议非法的事实仍可能是探索上下文；候选不证明协议合法或一次数据传播。

pending 默认 1,024、窗口默认 256 journal 位置、详情默认 1,024、诊断计数默认饱和于 65,535；配置边界均校验。信号与关系各最多 1,024；每关系只有 value_match、receipt_window 和最多 64 个声明覆盖上下文特征。pending 容量淘汰、过期和 reset 清理可审计；session feature 去重集合不会随清理删除，旧 feature 不会重新产生 novelty。详情满容量只保留有界原记录及 record_limit 诊断，不改拓扑或输入。

候选记录使用 D1 的 `candidate`／`event_correlation` 类型，保存源／目标基础事件及覆盖 journal 引用、局部 epoch、规则版本和可选声明引用。快照标记 `exploration_suggestions_only`；没有授 prerequisite、晋级 verified、回写拓扑或驱动 DUT 输入的 API。合法 schema 或相同数据仍不等于真实关联证明。当前为独立消费者，D3/D8 尚未集成生产运行器。

定向检查先建立缺实现测试；审查提出的“非法事件推进 epoch”“任意覆盖标签”“畸形协议覆盖”“无变化 signal_change”“旧 epoch 覆盖上下文”等缺陷均先由负例复现，再修复。测试包括使用生产 `IpBaseEventNormalizer` 生成的原始事件及投影，确认无插件消费和 raw 不变。

```bash
PYTHONPATH=.:src python3 -m pytest -q \
  tests/scenario/test_dependency_candidates.py \
  tests/scenario/test_dependency_evidence.py --tb=short
```

67 passed（D1 27、D2 40）。复审已确认前述 finding 修复，没有剩余 D2 范围内的阻断问题；复审时最后一项生产 normalizer 集成测试尚未加入，复审测试结果为 66 passed。

兼容验证命令：

```bash
PYTHONPATH=.:src python3 -m pytest -q \
  tests/scenario/test_dependency_candidates.py \
  tests/scenario/test_dependency_evidence.py \
  tests/scenario/test_ip_base_coverage.py \
  tests/scenario/test_ip_plugin_free_fixtures.py \
  tests/scenario/test_ip_plugin_import_boundary.py \
  tests/scenario/test_runtime_path_contract.py \
  tests/scenario/test_runtime_edge_index.py \
  tests/scenario/test_source_provenance.py \
  tests/scenario/test_runner_source_provenance.py \
  tests/scenario/test_dependency_edge_paths.py --tb=short
```

最终 190 passed，218 subtests passed。`compileall` 与 `git diff --check` 通过。未运行 HMAC／四核交易、持续搜索或全量 replay，Stage 2 总目标仍未完成。

实现：[候选消费者](../../src/myfuzz/scenario/dependency_candidates.py)。测试：[D2](../../tests/scenario/test_dependency_candidates.py)、[D1](../../tests/scenario/test_dependency_evidence.py)。总计划：[D2–D8](../superpowers/plans/2026-10-09-stage2-declarative-cpu-ip-adaptation.md)。
