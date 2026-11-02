# 执行流程与速度验证，2026-10-28

本轮将重复静态认证移至会话边界，拆分 develop/search/acceptance，并按实际新认证关系选择完整重放。既有 F1–F6 执行器保留。系统分别执行 CPU/IP RTL 并模拟数据流，不连接 SoC。

## 原生证据

目录：`research/input-strategy-audit-20261027/runs/workflow-20261028/`。

| 检查 | 结果 |
| --- | --- |
| timer-search + fresh | 搜索边界、严格 fresh 均 verified |
| timer-selected | 三 cases 发现真实 write-read 关系，触发 new-certified-relation 重放并通过 |
| memory-search original/fresh | F1/F3 搜索及严格 fresh 通过 |
| f5-search original/fresh | F5 搜索及严格 fresh 通过 |
| dma-search original/fresh | F6 搜索及严格 fresh 通过，无伪造 fresh artifacts |
| gpio-live-search | 首次失败：父子进程 elaboration 模式差异；保留失败证据 |
| gpio-live-search-v2 | 固定 direct 模式，三 cases 发现一条关系，独立 fresh 与父子静态边界均 verified |
| timer-search-v2 | 最新成功搜索，语义 hash 与旧基线相同 |

阶段一跨路径验证完成后，新增了失败复现和 GPIO 模式固定逻辑；v2 为这些变更后的成功路径复验。最后审阅对失败分支工厂初始化顺序的修复另由定向软件测试验证，未重新运行全部原生路径。

## 时间口径

同 Timer、seed 7、一个 F4、32 rounds、复用缓存的单样本：旧搜索阶段 22.2831 秒；本轮首次 2.5375 秒；v2 2.4774 秒，约降低 89%。选中输入与语义 hash 保持一致。v2 整条命令 39.5873 秒，其中结束边界认证 4.3750 秒。该结果不是多 seed 统计结论，也不等于纯 RTL 仿真耗时。

GPIO v2 三 cases 搜索首次关系在 5.6300 秒；独立自动重放 27.7856 秒；整条命令 66.2973 秒。剩余固定成本仍大，后续应优先减少会话初始化与边界认证成本、摊薄长会话开销，而不能只汇报热循环加速。

## 验证边界

搜索/比较软件测试 159 项通过（包含失败 worker GPIO 分派）；首次运行因缺少 PYTHONPATH 在收集阶段失败，使用 PYTHONPATH=src 后通过。此前静态校验和各执行器定向测试证据见实施计划。失败复现主要有 mock/纯软件验证，本轮没有可认证的真实 DUT bug 样本，不宣称已证明真实缺陷复现能力。

覆盖率没有因此自动变成在线可用。有限 catalog 路径的未知反馈仍为 unknown；没有完成任意 CPU×IP 穷举或正式多 seed 覆盖率优越性实验。

最终合并定向门：`PYTHONPATH=src python3 -m pytest -q tests/search tests/search_comparison tests/composition/test_elaboration_mode_scope.py tests/local_harness/test_execution_validation_scope.py`，**183 passed / 11.48s**。GPIO 失败工厂必须在静态与 elaboration scope 内构造的新增测试完成 RED→GREEN；独立审阅发现的该初始化顺序问题已修复。
