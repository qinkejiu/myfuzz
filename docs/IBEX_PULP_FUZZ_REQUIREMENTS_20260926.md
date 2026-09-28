# Ibex + PULP GPIO/SPI fuzz 工作要求

更新日期：2026-09-26。本文记录本轮对话已确定的工作范围、验收口径和远端操作边界；具体 property ID 与实现步骤见文末计划。

## 目标与范围

- 使用仓库锁定的真实 Ibex、PULP APB GPIO 和 PULP APB SPI RTL 组成 SoC，并由官方 RFuzz 客户端产生输入。
- 手写有明确协议或独立参考依据的 CPU、OBI、APB、fabric、GPIO、SPI 检查器；断言失败要进入可保存、可回放的反馈与报告。预留的 50 个 property ID 不代表 50 条断言均已实现或评估。
- 保留两个互补的运行臂：`mmio_only` 由 RFuzz 驱动外设事务和引脚；`cpu_execute + cpu_only` 让真实 Ibex 取指、执行并输出 RVFI 退休证据。外设臂的结果不得称为 Ibex 指令覆盖。
- CPU 指令覆盖至少记录实际退休数量、RVFI 顺序及指令类别命中。要宣称指令语义正确，须接入独立 Spike 参考并处理每个 testcase 的状态重置；仅有 RVFI 退休或总线活动不足以支持该结论。无法独立评估的属性明确标为 `not_assessed`。
- 先完成短时 smoke，确认输入投影、真实 RTL 运行、反馈、corpus replay 和资源清理形成闭环，再按 [RVFI 与 RFuzz 长跑计划](superpowers/plans/2026-09-25-ibex-rvfi-rfuzz-campaign.md)执行至少 600 秒的正式 campaign。报告分别列出已评估属性、失败、未评估属性和发现的候选问题；故障注入校准不算自然发现的 IP bug。

## 运行和验收证据

- 使用仓库固定的 RFuzz 客户端、Verilator 5.020、源码闭包及其 provenance；保存构建、输入布局、约束、checker、工具与 boot image 身份。
- RFuzz 变异后的合法指令候选和外设输入要能够持续投影；一个可修复的候选槽控制字段错误不得中断整轮 campaign。直接投影的严格拒绝语义应继续保留，并在报告中记录 campaign 修复策略与计数。
- 每个运行臂分别记录有效执行时长、testcase/周期数、CPU 退休或 GPIO/SPI 事务、RTL 覆盖、checker eval/fail、首次失败证据、corpus、replay 和清理结果。
- 失败候选须复现并区分组合/适配器、输入、checker 与真实组件问题；只有独立隔离证据充分时才标记为确认的组件 bug。

## 远端执行边界

1. 本地项目目录为 `/home/qinkejiu/myfuzz`。先按本机 `~/.ssh/config` 执行 `ssh jumpserver`，再从跳转机执行 `ssh root@192.168.5.70`。跳转机仅用于连接，不修改其项目文件。
2. 目标机上的**所有文件操作**只限 `/root/fanzehui` 及其子目录；构建、测试、临时文件和测试结果也放在此目录内。不得清理、覆盖或改动目标机其他路径。
3. 用户已授权清空目标机 `/root/fanzehui` 中原有文件，再传输本次测试所需文件。执行清理前必须确认所在主机、目录真实路径和符号链接边界，避免删除目录外内容；清理范围仅为该目录内部。
4. 传输后在目标机核对源码、工具和配置身份，再启动短时测试。若跳转连接不可用，记录连接失败和未执行步骤；不得把本地 smoke 记作远端完成。

## 截至本次记录的状态

- 本地 `mmio_only` GPIO/SPI 定向 smoke 已运行，SPI 非零 MISO 到 RXFIFO 的检查有评估事件且未报告失败；这是外设臂证据。
- Ibex 短测已观察到 RVFI 退休；此前正式 RFuzz 指令短跑在 99 个 testcase 后因 `candidate-offer-not-full-word:data:0x0` 中断。会话中已写入 campaign 输入修复，但修复后的正式指令短跑尚无完成报告，也尚无 Spike 语义比较结论。
- 上次两跳 SSH 在准备清理和传输前超时；历史记录没有远端清理、传输或运行完成的证据。

## 依据

- [组合与协议检查器实施计划](superpowers/plans/2026-09-25-ibex-pulp-composition-and-protocol-monitors.md)
- [GPIO 检查器实施计划](superpowers/plans/2026-09-25-pulp-gpio-checker.md)
- [SPI 检查器实施计划](superpowers/plans/2026-09-25-pulp-spi-checker.md)
- [Ibex RVFI、Spike 与 RFuzz 长跑实施计划](superpowers/plans/2026-09-25-ibex-rvfi-rfuzz-campaign.md)
