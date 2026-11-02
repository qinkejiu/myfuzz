# 第一轮原生验证提速

本轮只移动 `build.py::_prepare` 中的一次宿主源码读取：prepared cache 命中时由已有 validator 读取当前字节与 probe；未命中时仍在 verify/render 前建立 scope 基准，并保留准备末尾的读取。入口 dependency guard、逐字节检查、工具链、binary、manifest、materialized inputs 与权限检查均保留。未新增缓存子系统或启用 mtime 快路。

## 实测

同一 Timer + Ibex 配置、state、seed 7、一例 F4、32 rounds、无 seconds 截断；每次均包含完整内部重放。前后不带 profiler，顺序执行；源码在每次原生运行中冻结。

| 时间 | 修改前 original | 修改后 original | 此次降幅 |
| --- | ---: | ---: | ---: |
| 搜索/输入执行区间 | 26.1385 s | 22.2831 s | 14.75% |
| 总耗时，含准备及完整重放 | 105.0633 s | 98.6155 s | 6.14% |

修改后另跑独立 fresh：搜索 22.2311 s，总耗时 92.7541 s，严格跨调用验证通过。fresh 用于重放验证，不并入前后 original 降幅。

前后 `selected_cases.json` 完全一致，profile/catalog 一致，语义哈希均为 `077276a93ed2837fd5433fc3473268b42fa4a97a5556034acae01d0bdfcd21f2`。source 身份按代码变化正确改变；修改后 original/fresh 的 plan、语义和构建绑定一致，真实新进程 nonce 不复用，全部正常回收。复核也直接核对了 cache 中实际 binary 字节和本轮 build.py 输入快照。

这是一个配置和 seed 的单组测量，不代表所有负载的统计提速或固定预算覆盖率收益。源码变更可能触发重编译，旧汇总未单独记录 build/init，不能把总时间差全部归为构建收益。

## 定位与回归

首轮 cProfile 记录整个调用及内部重放：278 次 `_prepare`、556 次 host closure 读取，后者 inclusive 约 65.11 s；profile 总耗时约 190.42 s。profiler 自身有明显开销，该时间只用于定位，未用于计算提速。嵌套 inclusive spans 也未相加计算百分比。

TDD 先观察缓存命中两次读取的失败，再修至一次。独立审查发现直接删除读取会削弱冷 scope 的惰性基准，修订后保留冷路径前后检查；错误删除变体在冷 verify/render 中途漂移回归中失败。相关测试覆盖跨调用同尺寸且恢复 mtime 的内容变化、新 probe、accessor/context 漂移，以及冷 verify/render 中的内容、probe、root 变化。

Root 复核：**53 passed，3 subtests passed，0.52 s**；实现代理另有 host discovery 等相关检查通过。独立代码审查无 Critical/Important，三个修改文件的 `git diff --check` 通过。

原始证据位于 [speed-20261028](../../research/input-strategy-audit-20261027/runs/speed-20261028/)，最终数据见 [speed-result.json](../../research/input-strategy-audit-20261027/runs/speed-20261028/speed-result.json)。保留修改前后准确 build.py 字节和原始 pstats，不覆盖先前功能验收。下一步重点仍是重复工具链查询和构建缓存验证，先明确可复用的验证边界。
