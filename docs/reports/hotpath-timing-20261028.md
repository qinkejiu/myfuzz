# 单例热路径精简与计时

Timer + Ibex，seed 7，1 个 F4，32 rounds。将 session artifact 反复检查改为与私有静态快照直接比较，避免每条命令为比较复制整份快照。变更仍会被即时发现，acceptance/fresh 保留结束复核。相关组合测试 198 passed。

无计时插桩缓存命中样本：搜索阶段 1.6821s、整条命令 11.0322s；先前单样本分别 2.2417s、11.2539s，语义 hash 相同。样本不足以确认统计收益，前后源码和缓存也有差别。

另用已有 observe_local_command_timings 观测整个调用：33 次 STEP_APB3_REG 共 0.5647s，33 次 STEP_CPU 共 0.0542s，2 次 ACCESS_APB3_REG 共 0.0333s；合计约 0.6521s。该计时涵盖命令实现和等待，包含启动及搜索期间命令，既不是纯 DUT eval 时间，也不能直接和搜索阶段相减。计时样本与测试并行，不能用于无负载性能对照。

尚缺 DUT 原生进程内部 eval/tick 的单独计时；要衡量 DUT 推进是否占主要时间，需在 native 驱动内测推进耗时，并分别测 Python 调度、进程收发和反馈。现有指标不能证明目标已经达到。

证据：research/input-strategy-audit-20261027/runs/hotpath-20261028/。测量脚本和按操作汇总位于 evidence/。

同源码 strict fresh 原生执行成功，within、cross 与 static boundary 均 verified。

## 原生 eval 直接计时

设置 `MYFUZZ_DUT_TIMING_DIR` 为现有目录，驱动正常退出时分别保存 CPU/IP 进程的 eval 次数及墙钟纳秒，stdout 协议不变；默认关闭。启动统计止于 READY，运行统计涵盖 READY 后全部命令，不等同单例精确边界。逐次调用 steady_clock 引入插桩开销，数值包括调度，非纯 CPU 时间。

真实 Timer 1 case、32 rounds：CPU 运行阶段 eval 132 次，共 244237ns；Timer 164 次，共 67512ns；二者合计 **0.311749ms**。该次搜索阶段 **1.5243s**、整条命令 **17.0906s**（新驱动构建、与软件测试并行）。eval 覆盖两进程 READY 后全部操作，包含单例之外操作，因此不能精确相除当作同窗口占比；但远小于搜索阶段表明宿主调度和证据处理是本样本的主要开销。严格 fresh 已通过，语义 hash 同前。

证据 `research/input-strategy-audit-20261027/runs/dut-timing-20261028/`，软件组合 **200 passed / 19.12s**。build identity 检查也复用私有快照比较；另有 34 项相关软件测试通过。

## 静态生产者检查复用

代码对象、类方法、操作表等静态身份检查移到 scope 首次执行；strict fresh/acceptance 退出重新检查。实例影子方法、实际 owner、状态、artifact 和进程等动态检查保持逐次执行。原生 Timer original 通过，搜索 1.5267 秒，命令 17.5979 秒；该运行与软件测试并行，不能作为隔离性能对照。软件组合 201 passed / 19.06s；新增用例覆盖 scope 复用、strict 退出漂移和实例影子即时拒绝。
strict fresh 已完成，within/cross/boundary 均 verified，语义 hash 保持一致。
