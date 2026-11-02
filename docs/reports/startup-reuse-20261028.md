# 启动准备结果复用，2026-10-28

本轮落实减少重复准备工作的第一步，复用现有 execution_validation 静态会话缓存。没有增加持久化缓存、后台服务或新执行器。

## 实现

- `component_profile.elaborate_profile` 按完整 profile 指纹、根目录、端口选择和有效 mode 复用 PhysicalFacts。不同参数不共用；缓存只活在当前执行 scope。严格结束复核重新执行原始展开函数。
- `source_crawler._pinned_source_reader` 按 Git 仓库、revision 和 tree path 复用已核对 blob。新读取器仍读取工作区文件并比较；严格结束复核重新认证。
- runtime renderer 仍有 endpoint collector 等副作用，本轮没有缓存完整渲染器或删除其逻辑。通过复用其内部展开结果降低开销，避免扩大改动。

## 验证

最终定向软件门：256 passed，47 subtests passed，1 deselected / 13.16s。覆盖新缓存的命中、参数/端口/根目录/模式隔离、源码修改、严格退出复核、嵌套 Git 仓库，以及搜索、比较和失败路径。排除的已有 real_elaboration 测试在实现代理初次宽泛运行时曾因 frontend startup-error 失败；它不计入通过证据。后续正式 RTL 运行由 root 执行。旧模式测试的 SimpleNamespace fixture 补齐 profile 指纹，没有添加生产 fallback。

Timer seed7、一个 F4、32 rounds，原生首轮 22.2269 秒，缓存复用后两次 15.3882/15.0939 秒，搜索区间 2.4465/2.4919 秒。之前同配置样本整条命令33.0293秒。所有输入语义 hash 保持 `077276a93ed2837fd5433fc3473268b42fa4a97a5556034acae01d0bdfcd21f2`。样本期间部分软件测试或 fresh 并行，非隔离、多seed性能实验；路径名 timer-warm-solo 也有软件测试重叠，不能由名字推断隔离。初次启动与重复运行分别记录，不将缓存预热收益全归因于代码删除。

Timer 严格 fresh 已实际通过：within_invocation、cross_invocation 和 session_boundary 均 verified，策略 entry-and-exit，整条命令31.9229秒。

## 调用次数

对同一例运行 cProfile 前后核对：

| 工作 | 修改前 | 修改后 |
| --- | ---: | ---: |
| 实际 direct RTL 展开 | 22 | 2 |
| 源码读取 git cat-file 子进程 | 3202 | 242 |
| runtime renderer 调用 | 16 | 16 |
| renderer 累计时间（带 profiler） | 20.62秒 | 5.24秒 |

profile 插桩时间只用于定位，不能当作无 profiler 性能；累计时间互相嵌套。减少展开次数为已观测结果，完整渲染器没有被宣称只运行一次。

原始材料：`research/input-strategy-audit-20261027/runs/startup-reuse-20261028/`，包含源码快照、测量 JSON、before/after pstats 与 counts.json。

剩余主要成本包括宿主 Python 依赖发现、重复 source-lock 验证、renderer/admission 构造与对象复制。跨启动复用 prepared 配置、持续会话摊薄初始化尚未在本轮实现。

GPIO 原生三例运行完成并发现一条关系，独立自动 fresh 的跨运行与父子静态边界均 verified；整条命令 50.3573 秒（包含自动 fresh 23.7231 秒）。该运行部分与 profiling 并行，作为功能验证，不作为隔离性能对照。

## 后续精简：源码锁和依赖发现

继续复用同一执行会话中的 source-lock 验证，以 profile、根目录和选项区分；严格退出复核仍重新执行。宿主依赖扫描对重复 import 前缀只探测一次。旧实现与新实现的项目扫描结果逐项相同（437 个源文件、4337 个探测项）；单次独立扫描测得约 2.48→1.99 秒，仅供定位。

软件门：搜索、比较、缓存和源码锁组合 219 passed + 18 subtests；host_source_discovery_scope 单独 7 passed。扩展测试另有 7 个 BOOM fixture 失败：fixture 使用 object.__new__ 跳过初始化，访问缺失的 _cleanup_terminal；这些失败与本次依赖扫描没有调用关联，不计入通过。Timer phase2 原生 original 和严格 fresh 均完成，fresh 的 within/cross/boundary 均 verified，实际 source/语义证据见 timer-phase2。首轮 original 18.5771秒，期间与测试并行，不作为隔离基准。

完成测试和 fresh 后，缓存命中的 phase2 单独运行用时 **11.2539 秒**；语义 hash 与前述相同。前一轮约 15.1–15.4 秒样本与其他任务重叠，因此只能作为参考，不能据此声称严格隔离的提速百分比。
