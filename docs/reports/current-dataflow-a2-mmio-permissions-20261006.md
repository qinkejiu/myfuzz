# A2 静态 MMIO 窗口权限与合法地址变异

日期：2026-10-06。范围：`rv32i_sources.py` 的受信窗口声明和生成前约束；不代表 A2 整体验收。

`MmioWindow` 现在可声明 `readable` / `writable`，默认均为真以兼容已有窗口。`mmio_access_fragment` 在已知地址上拒绝不被窗口允许的 `LW` 或 `SW/SB`；`mutate_mmio_access` 只从允许该操作、且存在完整对齐访问槽的窗口中选地址。无可用窗口时明确拒绝输入，不产出非法片段。

先新增四项失败测试，再修改实现，随后补充读权限与声明类型边界。验证命令：

```text
PYTHONPATH=src python3 -m pytest tests/scenario/test_rv32i_mmio_permissions.py tests/integration/test_scenario_online_credit.py -q
15 passed in 0.24s
```

此约束只作用于可静态确定的生成地址。已有 profile 未在本轮追加寄存器级读写声明；动态地址、真实 CPU 请求和 Router 接纳前权限仍需单独验证。CPU/IP 实际 RTL 流、初始 RAM 来源以及 A2 其余变异操作子尚未由本测试证明。

## 2026-10-07 写入宽度补充

`MmioWindow.write_widths` 可由受信窗口声明允许的 1 字节 `SB` 和／或 4 字节 `SW`，默认 `(1, 4)` 保持既有窗口行为。静态片段生成和熵驱动选址都排除不支持的写宽度，并分别报告权限不允许、宽度不支持、无完整对齐地址。测试先见到新宽度用例失败，再实现约束；当前主树执行 `PYTHONPATH=src:. pytest -q tests/scenario/test_rv32i_mmio_permissions.py tests/scenario/test_rv32i_sequence_edit.py tests/scenario/test_rv32i_xori_mutation.py`，**35 passed**。这是软件约束门禁；当前双 GPIO 在线 profile 仍只使用 `LW/SW`，不授予 `SB` 真实退休或 IP 字节写能力。
