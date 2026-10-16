# BOOM IRQ 运行入口 attempt1：原生会话启动前失败

## 实际终态

远程 `/root/fanzehui/boom-irq-runtime-gate-20261017` 的一次性入口实际执行。控制 Python265026、门 Python265033 均已终态 exit1，末端 stage=terminal；这是明确退出，不是观察超时。独立 canonical lock 非阻塞探测 exit0。未重启或覆写该次运行。

`first.json.gz` 原始错误为 `ValueError: binding producer does not match input ownership`。CPU/GPIO harness lifecycle、命令、物理采样、Router/Runner/source 事件全部为空，身份表为空；失败发生在工厂构造 `ScenarioRunner` 的输入归属校验。因此本次没有测量 IRQ、MEIP、trap、ISR 或 MRET，不应描述成 IRQ 语义失败，也不构成原生 IRQ 通过证据。外层摘要的“run did not complete”只是上述失败的汇总。

根因是工厂声明的 bound producer `gpio_irq` 与真实绑定要求 `gpio.irq` 不一致。后续修复必须保留本失败，并按新 factory SHA 准备独立来源/元数据；旧 artifact/source/历史运行不改写。

## 冻结和独立检查

门实现70fdbcb、复核869c70b；控制准备968088b、独立复核f9b8c2f。根代理运行前实际核对 ready SHA `5bde90ac4bc6ae3fe6ffb9bba549421073484b5b515f02d28bf7ee0d40bc7449`、所有控制 pins、源冻结389项、2566运行文件、2564受保护源与88受保护产物，并确认独立 inode 和空闲锁。

归档独立审计确认完整前后 map 相同，工具前后身份相同，实际 gate/worker exit1、一致的 child PID/argv、完整 incomplete 标记保留。原元数据 manifest `ec4431b9aa2b75932d9a689d5e5bc1041f6bd25158919bd16e240a428bbd5737` 未变。未宣称当前 HEAD 联合验收或 P6/P7/P8 通过。

- [完整失败证据](evidence/boom-irq-native-attempt1-20261017/evidence.tar.gz)，SHA256 `349026ceeb07f9fa74fc9c8daee707d7e978caf6f7e7ef84045d0e0adc471118`。
- [根代理独立保存数据审计](evidence/boom-irq-native-attempt1-20261017/independent-audit.json)。
