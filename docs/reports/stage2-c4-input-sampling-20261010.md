# Stage 2 C4：物理输入采样与绑定交付

日期：2026-10-10。C4 在 C1 的 `ip_base_event.v1` 投影和 C3 的 raw tick 消费路径上补齐 profile 声明的物理输入观察，以及组件间显式绑定的交付记录。新生成的通用 APB3、TL-UL、Wishbone artifact 已在 `physical` 快照中逐项保存 `physical_exports`；C4 从该快照按 profile 的 `runtime_name` 读取输入和输出，不根据端口名称推断功能。

运行时快照中的 ABI 信号已经是所选物理切片。投影器因此保留快照值，不再按 `bit_lo` 二次移位；`bit_lo` 仅用于描述切片在原物理端口中的位置。每个有 endpoint/role 声明的 profile 输入／输出都产生 `port_sample`，同 reset epoch 内实测值变化时产生 `signal_change`；事件保留 raw `local_tick_sample` 引用、profile endpoint/role、物理端口、方向、tick、clock domain 与 reset epoch。原始样本不修改。无 endpoint/role 的私有探针仍只保留在 raw 记录中。

`ScenarioRunner` 对显式绑定保留原有 `dataflow_delivery`，并在源输出和目标输入都 opt in 基础事件、且目标字段声明了相同 producer 时生成 `binding_delivery`。事件记录源测量、绑定切片和值、完整目标输入值、源／目标 reset epoch 及 raw 来源。目标侧仅在同一 target reset epoch 中、实际 raw `pre` 样本与绑定交付值相等时生成 `input_sample`，并同时引用交付事件和目标 raw 样本；不匹配或跨 reset epoch 的值都不构成采样证明。

负例和集成覆盖包括：任意物理名称不参与功能推断；非零物理 bit offset 不会把已切片值再次移位；同 epoch 输入变化可观察而新 epoch 不继承变化历史；错误的实际输入值不生成 `input_sample`；正确 pre-edge 值产生一条与交付事件精确关联的 `input_sample`；post-edge 样本不会重复生成采样事件；目标 reset 后旧绑定候选失效；未 opt in 的旧 artifact 不生成新投影。

四个独立 pytest 子进程并行执行：

- 基础／协议事件、journal、Runner 连续性与来源回归：65 passed，86 subtests passed。
- 通用 APB3 artifact/factory：3 passed，2 个真实 RTL 测试按默认配置跳过。
- 通用 TL-UL artifact/factory：3 passed，2 个真实 RTL 测试按默认配置跳过。
- 通用 Wishbone artifact/factory 与 runtime renderer：17 passed，49 subtests passed，1 个真实 RTL 测试按默认配置跳过。

`compileall` 与 `git diff --check` 通过。文档链接扫描覆盖 593 个 Markdown 文件、1,321 个本地链接；新增 C4 链接全部解析成功。扫描器报告的 83 条断链是既有历史产物引用，另有 150 个 HTTPS 链接按规则跳过。

边界：结果验证 profile 声明、raw snapshot 投影和 ScenarioRunner 的交付／实际输入事件关联；它们不证明任何目标 DUT 的寄存器功能或内部语义。C4 不实现共用协议 Checker 与覆盖消费者，继续由 C5–C7 完成；Stage 2 CPU/IP 生产运行器和 DUT 级能力授级仍未完成。详细范围见[主计划 C4](../superpowers/plans/2026-10-09-stage2-declarative-cpu-ip-adaptation.md)、[C1–C2 报告](stage2-c1-base-events-20261010.md)与[C3 报告](stage2-c3-protocol-base-events-20261010.md)。

C6 兼容性补充：`bit_lo` 现作为显式字段出现在 `port_sample` 和 `signal_change`，使基础覆盖可按完整物理切片身份区分同一端口的不同 offset；对应回归见 [C6 报告](stage2-c6-base-coverage-20261010.md)。
