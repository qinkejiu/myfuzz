# 源码导航

统一命令入口是 [__main__.py](__main__.py)。当前执行链为：组件 profile → 独立 harness/session → 场景 Runner/Router/Scheduler → campaign/RFuzz → 证据保存和 replay。

| 目录 | 职责 |
|---|---|
| [local_harness/](local_harness/) | profile 验证、生成器、CPU/IP session、物理协议观测 |
| [scenario/](scenario/) | 输入、状态、依赖、路由、调度、checker、运行证据与 replay |
| [integration/](integration/) | 场景和 RFuzz 集成、compiled 数据流、保存态核验及历史集成入口 |
| [protocols/](protocols/) | 协议定义、模板、peer、monitor 和 RTL 适配 |
| [composition/](composition/) | 当前复用的 profile、源码与接口事实；同时保留历史 SoC 生成实现 |
| [frontend/](frontend/)、[harness/](harness/) | 前端分析、插桩及 harness 支持 |
| [components/](components/)、[contracts/](contracts/)、[dependency/](dependency/) | 组件、契约与依赖辅助模块 |
| [isa/](isa/) | 指令集支持 |
| [experiments/](experiments/)、[scripts/](scripts/) | 实验及既有 design-flow 工具 |

模块按运行职责的详细映射见[代码组织](../../docs/CODE_ORGANIZATION.md)。`composition/` 不是可整体移除的旧代码；变更模块位置前检查 import、CLI、配置 filelist、测试、冻结 source map 与 replay factory。
