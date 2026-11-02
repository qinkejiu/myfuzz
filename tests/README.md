# 测试导航

| 目录 | 检查范围 |
|---|---|
| [scenario/](scenario/) | 场景状态、依赖、路由、事件、证书和 checker |
| [local_harness/](local_harness/) | 生成器、session、CPU/IP 协议与观测边界 |
| [integration/](integration/) | campaign、compiled F2/F4/F6、保存态验证及真实集成 |
| [composition/](composition/) | profile、源码与接口事实，以及历史 SoC 组合 |
| [fuzz/](fuzz/) | 闭环输入空间、变异、反馈、corpus、会话驱动、F1 短程序与统一入口的纯 Python 合同 |
| [protocols/](protocols/) | 协议和 RTL adapter |

先查看具体模块的环境开关、fixtures 和资源要求，再运行对应测试。软件测试、真实 RTL、native、RFuzz 和远程冻结 gate 的结论分别记录；一次局部通过不能推广为系统通过。

测试会读取 `runs/`、`.superpowers/sdd/`、`docs/reports/evidence/` 和第三方源码中的 fixtures，不能把这些目录统一作为缓存删除。验收任务与命令见[计划索引](../docs/superpowers/plans/README.md)。
