# 本地搜索流程精简，2026-10-28

用户要求减少防御性编程，以实现效率和维护成本为优先。

本轮采用明确假设：日常本地 search/develop original 期间代码、工具链和不可变构建缓存不会被修改。每个静态依赖首次使用时检查并在会话内复用，结束时不再全量复核。fresh、acceptance 和未显式指定模式的 Python scope 保留原完整检查。动态协议、输入、版本、消费关系及实际进程检查继续执行。

实现改动：execution_validation_scope 支持关闭结束复核；两个公共搜索入口传递执行策略；native/GPIO 普通搜索省去重复终态源码哈希；构建身份快照省去一层重复 deepcopy；descriptor 删除重复且丢弃返回值的策略检查。未再引入新的执行器或防御框架。

summary.static_validation_policy 明确为 entry-only 或 entry-and-exit。session_boundary=verified 表示对应策略已通过，entry-only 不声称检测运行期间源码变化。使用 entry-only 时应在修改代码前结束会话；需要完整复核时选择 acceptance/fresh。

软件验证：新增首次检查调用次数和四种执行策略用例，先失败后通过。定向搜索/比较/静态验证门 185 passed / 11.81s。

原生证据目录：research/input-strategy-audit-20261027/runs/trusted-search-20261028/timer/。相同 Timer/seed7/单 F4/32 rounds/复用缓存单样本：整条命令 39.5873 → 33.0293 秒，约减少 16.6%；热循环 2.4774 → 2.3847 秒，结束边界耗时 4.3750 → 0.0011 秒。差异不能全部归因于单一删除项，尚未做多 seed 统计。

严格 fresh 原生复核通过：within_invocation、cross_invocation、session_boundary 均 verified，策略为 entry-and-exit，整条命令 45.3224 秒。独立只读审阅未发现阻断问题；随后补齐失败 summary 的策略字段，并用定向测试验证，未改变执行逻辑。原生证据绑定的是该报告字段补齐前的源码版本。

最终合并定向测试：186 passed / 11.50s。

## 剩余瓶颈定位

最新源码单例 cProfile：/tmp/myfuzz-perf-20261028/timer.pstats，原始执行材料 /tmp/myfuzz-perf-20261028/timer/。profile 总时间约58.25秒，有明显采样插桩开销，不能与无 profiler 的33.03秒直接计算性能变化。

| 调用 | 次数 | profile累计时间 |
| --- | ---: | ---: |
| elaborate_profile | 22 | 20.02秒 |
| render_local_runtime | 16 | 20.62秒 |
| native._prepare | 1 | 18.76秒 |
| create_compiled_execution | 1 | 25.71秒 |
| source_crawler.read → subprocess.run | 3202 | 5.18秒 |
| _discover_host_sources | 1 | 5.44秒 |
| deepcopy | 8567顶层调用 | 7.14秒 |
| _toolchain | 4 | 0.41秒 |

累计时间互相嵌套，不能相加。22次展开涉及调用链，尚未逐参数区分相同与不同profile，不能直接声称可降至一次。deepcopy为全流程合计，不能全归为防御性校验。源码读取子进程实际为逐文件git cat-file blob核对。

建议顺序：先复用同输入的展开/渲染结果并传递prepared结果，消除多层重建；git采用批量cat-file或会话内共享已读取blob；随后让prepared配置产物可跨启动复用，避免二进制cache命中前仍跑完整生成链；热路径再减少大对象快照与对Python方法身份的逐命令反复检查。长会话复用是摊薄固定成本的有效方式，不能冒充单case执行时间下降。工具链和descriptor重复读取目前收益较低；优先级应服从最新profile。
