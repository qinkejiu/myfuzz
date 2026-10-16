# Stage 2 C6：有界增量基础覆盖

日期：2026-10-10。C6 新增独立的 `IpBaseCoverageConsumer`，从不可变 raw/base event journal 按绝对游标增量消费，不依赖功能插件。覆盖类别只标记为 `base_coverage`，不把候选新颖性、依赖证明或功能覆盖混入基础反馈。

消费者的有限 feature vocabulary 由声明的 endpoint protocol、物理导出切片和 `CoverageTarget` 组成。APB3／Wishbone 记录 read/write，TL-UL 记录 opcode 0–7；事务事件、成功／错误响应、六档延迟、精确端口变化和声明的目标覆盖位均计数。feature 数量有界，计数饱和于配置上限（默认 65,535），pending 关联状态有界（默认 1,024）并为淘汰保留诊断。

端口变化只匹配完整声明身份：endpoint、role、direction、physical port、bit offset 与 width；C4 的 `ip_base_event.v1` 样本及变化投影现显式保留 `bit_lo`。目标覆盖按唯一的 physical port/runtime name 解析声明导出，读取已选 ABI 切片；整数和 `fixed_width_hex` 都按声明宽度校验。宽十六进制只接受精确位宽的裸 hex 字符串，歧义映射、畸形快照、超宽值和超出切片的 mask 均 fail closed。有效旧 direct-output 目标继续按其直接值谓词计数。

协议延迟关联要求唯一的正整数 raw request reference、接纳引用及响应引用，并且 reset epoch 一致；延迟从接纳 tick 算到响应 tick。APB3/Wishbone 不伪造原生 transaction ID。缺少有效关联的响应只增加 `latency_uncorrelated` 诊断。事务请求、接纳、timeout、cancel、reset 与迟到响应遵循 C3 事件引用和 epoch；raw 样本只有在 `event_id`、正整数 tick、`pre`/`post` phase 有效时才允许贡献目标覆盖。

`consume(events, start_cursor=...)` 跳过已消费的重叠前缀、返回保留绝对游标的输入事件引用，并拒绝未来游标缺口。`snapshot()` 返回 detached、JSON-ready 的 `ip_base_coverage.v1`，包含 `base_coverage` 类别、游标、计数、诊断及容量上限；不会暴露可变内部字典或其他反馈通道。

测试采用先失败后修复：修复前的精确切片、延迟起点、raw-envelope、物理 runtime target、宽 hex 和快照负例均复现失败，原始 RED 输出保存在 `/tmp/stage2-c6-*.log`。定向场景覆盖切片差异、错误引用、接纳前响应、reset/timeout/late、饱和和状态上限、增量游标、歧义 target、异常快照和 detached snapshot。

验证结果：

- C6 与 C4：`PYTHONPATH=.:src pytest -q tests/scenario/test_ip_base_coverage.py tests/scenario/test_ip_base_events.py`，31 passed，67 subtests passed。
- C3/C5 protocol/checker/journal/runner focused scenario regression：69 passed，4 subtests passed。
- 通用 artifact/factory/renderer 软件回归：28 passed，5 项真实 RTL 测试 skipped，4 项 lint/build/real-driver 测试 deselected，70 subtests passed。
- `compileall` 与 `git diff --check` 通过。
- 独立复审结论：Spec Compliance PASS、Code Quality PASS，无未解决 finding。

未运行真实 RTL、完整 `tests/scenario` 或 Verilator build/lint；消费者仍是 standalone L1 utility，尚未接入 Stage 2 生产 Runner，因此不代表任何 DUT 结果或矩阵授级。详情见[主计划 C6](../superpowers/plans/2026-10-09-stage2-declarative-cpu-ip-adaptation.md)、[实现](../../src/myfuzz/scenario/ip_base_coverage.py)、[覆盖测试](../../tests/scenario/test_ip_base_coverage.py)及[C4 投影](../../src/myfuzz/scenario/ip_base_events.py)。
