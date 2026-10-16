# 第二阶段 B3：IP 接口预检

更新日期：2026-10-10。范围：[第二阶段声明式 CPU／IP 适配计划](../superpowers/plans/2026-10-09-stage2-declarative-cpu-ip-adaptation.md)的 B3。B3 完成；B4–B6 和后续 Stage 2 生产运行器／DUT 门禁仍未完成。

profile 绑定会把每个必需语义字段解析到真实 elaboration 端口，并核对方向、宽度及协议角色宽度；clock/reset 还必须是输入且为单 bit。端口 disposition ledger 要求所有物理端口的每个 bit 恰有一个 disposition，输入必须有唯一合法 driver，输出不能被 fuzz 或常量驱动；profile 映射与成员／切片边界由 elaboration 事实验证。协议只接受 protocol catalog 中实现且经 binding 核对的角色和宽度，不支持的 protocol id 或形态 fail closed。

request preflight 现在校验 MMIO aperture 不越过 64-bit 地址空间，并在 elaboration 前检查固定窗口的对齐、范围、aperture 和与 memory／其他固定窗口的重叠。自动分配在窗口放不进剩余 aperture 时拒绝，不会越界；`_allocate_windows()` 对直接构造的 request dataclass 也复核固定地址，避免绕过 loader。窗口是半开区间，因此结束点恰好等于 aperture 上界有效。

未知功能与非法接口分开报告：endpoint function 仍是封闭词表，未知 function 属于无效接口声明并拒绝；IP 没有功能插件或 register map 时，只要通用端点和物理映射合法，B2 能力评估仍允许 L1。该降级行为由匿名 profile 用例覆盖，避免把“功能语义未知”误判成端口非法。

并行聚焦回归结果：

- `test_soc_composition.py test_soc_port_dispositions.py test_multi_role_ports.py`：**75 passed、12 subtests passed**。
- `test_component_profile.py test_ip_test_levels.py test_test_capability.py`：**57 passed、13 subtests passed**。
- `test_endpoint_capabilities.py test_protocol_manifest.py`：**28 passed、9 subtests passed**。
- `compileall` 与 `git diff --check` 通过。

这些测试覆盖 scalar clock/reset、缺失／错向／错宽端口、固定与自动窗口对齐／范围／边界／重叠／溢出、直接 request 对象复核、任意输出映射、逐位输入 ownership、重复 driver、禁止输出 fuzz、协议方向／角色／宽度与未知协议拒绝。结果仅证明静态契约和生成前预检，不代表 Stage 2 生产 runner 已接入，也没有给任何 DUT 授级。
