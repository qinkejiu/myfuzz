# 第二阶段 B2：IP 测试能力等级与缺口

更新日期：2026-10-10。范围：[第二阶段声明式 CPU／IP 适配计划](../superpowers/plans/2026-10-09-stage2-declarative-cpu-ip-adaptation.md)的 B2。B2 已实现并通过聚焦复审；M1 仍在执行，B3–B6、Stage 2 生产运行器接线和真实 DUT 门禁尚未完成。

新增 `ip_test_level_assessment.v1` 评估 API，分别输出 `declared_level`、`effective_level`、`verified_level`、独立的 `requested_minimum_level`／`minimum_level_met`、逐 endpoint／operation 支持矩阵及缺口。`require_minimum()` 在最低等级不满足时抛出启动前拒绝错误；实际 Stage 2 CPU/IP 生产命令目前还不存在，因此该 gate 尚无生产调用方。

等级来源保持分离：profile 与 B1 sidecar 只声明能力；profile 身份绑定的 runtime preflight 快照才能授予 effective；带非空证据引用的 verifier 快照才能授予 verified。L1 对必需协议端点要求 request／accept／response 均可用；矩阵保留其余端点和操作的局部支持。L2 从已校验字段语义派生 `register_read`／`register_write`，用 `Register.Field` scope 精确绑定权限和 mask；generic `read`／`write` 不会被重新解释成 L2。运行和验证快照都绑定 profile 与 sidecar fingerprint，并重新解析 frozen sidecar 原文以拒绝 typed 内容漂移。L3 保持不可用，直到版本化功能插件契约存在。

聚焦回归 `tests/composition/test_ip_test_levels.py tests/composition/test_test_capability.py`：**28 passed、2 subtests passed**；覆盖匿名 profile 的 L1、字段级 L2、局部缺口、最低等级拒绝、未知端点、协议缺口、部分验证、generic read/write 不得升级、profile／sidecar 身份绑定，以及 `dataclasses.replace` 不能把更改后的字段语义伪装成原指纹。`tests/protocols`：169 passed、249 subtests passed。组合模块 `compileall` 与 `git diff --check` 通过。文档链接检查扫描 586 个 Markdown、1,281 条链接，83 条为已有缺失产物引用；本次新增链接均有效。代码复审 Ready；复审期间发现并修复了 sidecar typed 字段可沿用缓存 fingerprint 的重要问题，新增负例并验证 fail closed。

完整组合诊断曾得到 1261 passed、7 skipped、1034 subtests、14 failures。14 项均落在未由 B2 改动的既有 Ibex 端口数、ZIPCPU `local_runtime_variant` adapter/evidence allowlist、legacy matrix digest 和 CPU adapter renderer unbound-input 问题；其中 adapter renderer 与 digest 在 B1 基线 HEAD 上已复现。该宽回归不是通过结果。最后的 sidecar 完整性收紧由上述受影响聚焦组复验，没有宣称完整组合套件全绿。

目前没有 Stage 2 CPU/IP runner 生成 runtime／verification snapshots，也没有 DUT 能力授级。B2 完成仅表示公共解析契约和拒绝逻辑已交付；不能把历史 Ibex smoke 或现有功能证据折算成 Stage 2 矩阵结果。

后续状态：B4 新增 `ip_test_capability.v2` feature contract 及 L3 观察映射门槛，并提供字段权限/mask/副作用约束的 L2 动作规划器；实现与限制见 [B4 报告](stage2-b4-level-semantics-20261010.md)。这不改变本报告所记录的 B2 时点状态，也没有接入生产 runner。
