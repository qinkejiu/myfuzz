# D7 依赖负例的软件验收

D7 八类负例已按软件范围验收。生产 Runner、normalizer、protocol checker 和 evidence consumer 消费 raw 软件 fixture；完整控制链可认证，删失、顺序或身份变异不能授予缺失的证明范围。新增跨 APB3／TL-UL／Wishbone 的 13 项重传、消费顺序及晚到冲突检查；十二模块最终联合回归 333 passed（0.94 秒），只读复核独立五模块 171 passed（0.52 秒），无新增重要问题。git diff --check 通过。

本轮未修改生产逻辑、未运行新 RTL；此前真实 GPIO／RAM 验收各自保留原范围，不作为这些软件变异的实际 DUT 证据。D7 的软件负例覆盖可以勾选；D5／D6 的其他 active provider、D8 生产探索排序和后续 E–I 实际门禁仍未完成。

| 原要求 | 当前可复核的软件证据 | 结果与范围 |
|---|---|---|
| 仅事件相邻 | `test_dependency_candidates.py::test_time_order_and_coverage_context_never_grant_proof_or_change_topology`；真实基础 normalizer 的 fixture 入口 | 相邻、同值或覆盖相关只产生 candidate／event_correlation，不能认证或修改拓扑 |
| 值相同但事务不同 | `test_ip_protocol_evidence.py::test_same_value_response_for_other_request_cannot_complete_second_transaction`；GPIO 同值覆盖和 RAM 当前 cell 检查 | 旧 TL 请求引用不能完成第二笔事务；真实合法请求复用可产生独立证书，不用值相同替代请求身份 |
| 不同 epoch | `test_ip_binding_evidence.py` 的 epoch／intervening reset 变异；`test_irq_dependency_evidence.py` 的 epoch 变异；原生新 epoch 正例 | 旧资源不能满足新的消费身份，合法新 epoch 仍可建立新历史证书 |
| 消费先于接纳 | 新 `test_response_projection_before_accept_cannot_certify_consumer`（三协议）；`test_native_tl_response_before_request_acceptance_cannot_certify` | 保留完整请求和原始观察，仅把 response 投影放到 accept 前则零证书；实际 raw TL fixture 的 request／response 存在、accept 缺失时也零证书。accept-before-request 是另一个检查，不能替代本项 |
| 删除 delivery | `test_irq_dependency_evidence.py::test_missing_or_wrong_evidence_never_grants_later_scope` 的 delivery 分支 | 用连续 ID 的无关 annotation 替代真实交付，不依赖 journal 缺口来拒绝，不能授 CPU acceptance／retirement |
| 删除 sample | 同一参数化检查的 sample 分支；绑定消费者的精确 raw sample 引用检查 | 已发生交付的历史范围不代表 CPU 已接受，缺 sample 不能授后续范围 |
| 重传 | 新 `test_retransmitted_journal_cannot_count_a_second_protocol_certificate`，三协议乘两种重传 | 重复相同 ID 或给相同 physical ticks 新 journal ID，都保留原证书且 D1 verified=1，不制造第二次证明；新 ID 变体实际触发 non_increasing_tick |
| 同 ID 变内容 | 新 `test_late_same_id_changed_content_preserves_history_but_blocks_future_proof`（三协议），以及绑定／IRQ／GPIO／RAM 冲突检查 | 历史原文保留，完整性失败后不再续证；继续同一物理 tick 流的第二笔合法请求，clean control 有两证书，冲突 consumer 只有旧一条，reset 不恢复完整性 |

新增测试：[重传与消费顺序](../../tests/scenario/test_dependency_retransmission.py)。其 raw fixture 由生产 Runner 产生，原生 TL 表述仅指 raw 握手字段，不指实际 RTL DUT。

最终回归命令：

```bash
PYTHONPATH=.:src python3 -m pytest -q \
  tests/scenario/test_dependency_retransmission.py \
  tests/scenario/test_dependency_candidates.py \
  tests/scenario/test_dependency_evidence.py \
  tests/scenario/test_ip_binding_evidence.py \
  tests/scenario/test_ip_protocol_evidence.py \
  tests/scenario/test_gpio_register_evidence.py \
  tests/scenario/test_gpio_sync_evidence.py \
  tests/scenario/test_irq_dependency_evidence.py \
  tests/scenario/test_irq_boundary_evidence.py \
  tests/scenario/test_memory_dependency_evidence.py \
  tests/scenario/test_live_memory_prerequisites.py \
  tests/scenario/test_dependency_lifecycle.py --tb=short
```

D8 当前缺口已经从代码核对：`DependencyCandidateConsumer` 独立生成有界相关记录和 session feature 去重，但 `ScenarioRfuzzExecutor` 的生产权重仅有既有覆盖／interaction 基线及 opt-in closed-loop certificate energy；候选通道尚未接入。后续须实现默认关闭、合法目标限定、每 case 最多一个 novelty、至多 10% 新增能量、分类反馈，以及 replay identity 冻结；不能把现有 D2 发现或 D7 负例通过当作 D8 完成。
