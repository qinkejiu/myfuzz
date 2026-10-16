# 第二阶段 B4：L1–L3 等级语义

更新日期：2026-10-10。范围：[第二阶段声明式 CPU／IP 适配计划](../superpowers/plans/2026-10-09-stage2-declarative-cpu-ip-adaptation.md)的 B4。B4 完成；B5–B6、运行器接线及真实 DUT 门禁仍未完成。

L1 继续只要求合法的协议／端口和运行预检。匿名通用 IP 即使没有 register map 或功能 provider，也可按 B2 的请求／接纳／响应路径评为 L1；缺失功能语义不会被端口合法性错误替代。

L2 的 `plan_register_operation()` 将一个精确 `Register.Field` 访问解析成受 profile 与 sidecar 双重约束的动作计划。它验证字段读写权限、读取/写入 mask、写入值宽度与可写位，并给出寄存器偏移、总线 mask/value 和已声明副作用。带副作用的读写必须显式设置 `allow_side_effect=True`；规划器只返回数据，不执行总线事务。

L3 由新的 `ip_test_capability.v2` `feature_contract` 声明。provider id/version 为功能实现标识；每个有限词表中的功能操作必须列出非空观察映射 ID 和证据引用，且每个映射必须存在于同一 sidecar。任意脚本、callback 或未知操作仍会被拒绝。L3 必须完整包含 L2；runtime preflight 只有在支持所有必需观察映射及功能操作时才有效，verified L3 还要求协议、L2 与 L3 每项都带 verifier 证据。sidecar fingerprint 将 provider、操作和观察需求冻结在同一 profile 身份下。

并行回归结果：

- sidecar／L2 动作计划：**16 passed、2 subtests passed**。
- 等级评估／L3 映射 preflight：**18 passed**。
- profile 与 SoC composition 兼容组：**54 passed、13 subtests passed**。
- 端口 disposition、多角色与协议兼容组：**78 passed、19 subtests passed**。
- `compileall`、包级 API 导入和 `git diff --check` 通过。

当前没有 Stage 2 生产 runner 或 IP 功能 provider 消费这些 API；本报告证明的是描述契约、动作规划和分级逻辑，不能据此声明任意 IP 实际运行到 L2/L3，也不为 DUT 授级。
