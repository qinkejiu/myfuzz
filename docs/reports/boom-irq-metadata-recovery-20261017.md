# BOOM IRQ 构建的元数据恢复：实际结果

## 已完成什么

控制进程 **238790 实际退出0**。已在新目录独立复制源与原构建输出，并完成元数据最终化；原始构建目录未修改。保存的历史结果仍是 **Verilator build0、16 项实际 VPI descriptor 检查0、旧最终化阶段1**，没有把旧失败改成通过，也没有重新编译。

源修复支持实际生成的唯一 `VBoomTile__Syms__Slow.cpp` 布局，并与 make/对象依赖闭包关联。恢复工具只接受三个代码固定的历史归档，不导入任意可执行文件；实际 compiled inputs、工具路径/哈希/版本、原二进制、探针清单与历史退出记录均交叉核对。旧构建 Python 身份与新元数据 Python 身份分别保存。

恢复产物：`/root/fanzehui/boom-irq-metadata-recovery-20261017/{project-finalized,artifact-finalized}`。本次源快照固定 2,564 文件、316 个 host 依赖和独立 PULP Git 闭包；并非当前联合 HEAD 的干净检出或完整审查声明。恢复源修复 `3e9c07b`，独立审查 `2cdebba`，控制准备 `0ab3339`，实际运行收据 `9557281`。

## 独立复核

根代理读取完整保存数据，重新核对三份原始归档的代码固定 SHA、实际原二进制、历史退出、16 个探针条目、元数据清单及全部交叉引用。2,564 源文件的 before/after/copy 映射相同；原构建的 **84 文件** before/after 相同；工具前后相同；副本无共享源/构建 inode。另独立远端读取新旧二进制与新 manifest 的 SHA，确认如下值：

- 二进制：`6367b592b743f935cb2de04bc6dfc4ac54c9ec8cf5dce4eb6545b140971e6c90`
- 新 manifest：`ec4431b9aa2b75932d9a689d5e5bc1041f6bd25158919bd16e240a428bbd5737`

[原始状态、控制、清单及历史归档](evidence/boom-irq-metadata-recovery-20261017/evidence.tar.gz)、[逐文件 SHA](evidence/boom-irq-metadata-recovery-20261017/manifest.json)、[独立数据审计](evidence/boom-irq-metadata-recovery-20261017/independent-audit.json)。操作前一条只读预检因远端没有本地脚本文件退出2，阻止了操作启动；随后通过 stdin 执行冻结预检并通过，唯一恢复操作才启动。两份记录均保留。

## 未完成的实际门

本次操作只查询 Verilator 版本、复制、认证输入及最终化元数据。没有调用 CPU 构造器、模型、probe describe、IRQ 程序或原生门；`new_cpp_build=false`、`runtime_verified=false`、`source_authority=false` 保持明确。下一步仍需真实 GPIO 边沿→固定64 CPU tick MEIP→实际 trap/ISR 状态读清→RAM→qualified MRET→前台恢复，以及受控抑制和完整 fresh 前缀。它不构成 BOOM IRQ、P6/P7/P8 或全系统验收。
