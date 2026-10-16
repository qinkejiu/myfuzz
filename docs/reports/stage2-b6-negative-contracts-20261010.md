# Stage 2 B6：能力与接口拒绝负例

日期：2026-10-10。状态：B6 已完成，工作包 B 的接口和负例门槛已通过。测试覆盖能力只声明到有证据支持的等级、启动前拒绝不可满足的最低等级，以及接口和输入 ownership 的 fail-closed 行为。

## 负例边界

1. 没有 register map 或功能插件的匿名 profile 可以声明并预检为 L1；运行时出现 `completion` 等 operation 名，不会自动声明或启用 L3。
2. L2 缺少任一字段级读写操作、L3 缺少所需观察映射时，能力降到实际可执行等级，`require_minimum()` 拒绝高于该等级的请求。
3. 未注册协议即使报告了 request/accept/response 操作，也不能得到 effective L1；显式最低 L1 同样拒绝。
4. 真实 bound input 只接受精确 producer 交付；ownership 将其作为 IP→IP mutation source 查询时拒绝 `bound input cannot be mutated`。
5. 缺少物理端口／字段别名时，profile binding 报 `port-missing`；缺字段或协议不匹配的 runtime shape 不能通过 renderer admission。
6. 名为 `DONE` 的寄存器及 `DONE.ready` 字段，只有显式字段语义时可规划为 L2；即使 runtime 报告 `completion` 支持，也不能代替 L3 feature contract。

第 6 项新增到 `tests/composition/test_ip_test_levels.py`，单测通过。其余负例已由 B2–B4 的直接测试覆盖，没有为同一规则再建镜像测试。

## 验证

三个独立 pytest 子进程并行运行：

- `tests/composition/test_ip_test_levels.py tests/composition/test_test_capability.py`：**35 passed，2 subtests passed**。
- `tests/composition/test_component_profile.py tests/composition/test_multi_role_ports.py`：**66 passed，15 subtests passed**。
- `tests/local_harness/test_generated_register_factory.py tests/local_harness/test_tuning.py tests/local_harness/test_runtime_renderer.py`：**44 passed，92 subtests passed**。

命令使用 `PYTHONPATH=src:. pytest -q`。这些是契约、预检与 harness 入口测试；不表示新 HMAC RTL 或 Stage 2 CPU/IP 生产运行器已执行。
