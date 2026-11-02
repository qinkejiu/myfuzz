# 本轮性能与公共入口验收

2026-10-29。性能独立 raw 核验由 unified 完成；本报告复核轻量 performance/comparison/search-summary、selection 与 manifest，不重新运行 DUT。公共入口保存产物的独立核验记录见 [配套 JSON](shared-performance-public-entry-acceptance-20261029.json)。

## 固定工作量 A/B

证据：`research/input-strategy-audit-20261027/runs/shared-performance-20261029/{legacy-v1,snapshot-v1,comparison-v1.json}`。

| 度量（秒） | legacy | snapshot |
|---|---:|---:|
| 端到端 wall | 724.701 | 493.848 |
| original campaign loop | 248.372 | 155.593 |
| finish/export | 47.608 | 46.520 |
| 完整 within replay/export | 397.272 | 269.347 |

两侧均完成同一8个主 case / 9个实际 Session case，包含 F1–F6；CPU/DMA/GPIO local ticks 为977/1010/1023，journal events 38421。比较器确认完整规范化 prefix 相等（SHA256 `ce6d4150a33fc8acc0cdefe1a7a8d9ddc24ad16cd752a42a3e3a682e8642f457`）、native eval 次数相等、full fresh 成功，显式 legacy/snapshot 模式有效。

这一次 snapshot wall / legacy wall = 0.68145，观察到约31.85%较短 wall。它是单次固定输入 A/B，并非多次交错/随机顺序实验；构建与缓存热度、运行顺序及主机负载可能影响数值，不能外推一般速度提升或策略优越性。不同 inclusive spans 有嵌套，不可把各phase/runner/roundtrip相加。

原生 runtime eval 两侧 original+replay 合计各约0.026秒，eval次数 CPU3908、DMA4040、GPIO4092（每次执行）；host native command roundtrip 总计约26.97/26.06秒。native eval 计时只覆盖 eval，不覆盖整条native进程/IPC/解析/主机核验，不能拿 wall 减 eval 精确当Python独占时间。但数据明确不支持“数百秒主要由DUT eval主导”；大量成本仍在host执行/证据处理/检查，不能给DUT背书。

## 公共 state selector 入口

证据：`research/input-strategy-audit-20261027/runs/shared-search-20261029/state-v4/original/search-summary.json`。

- original handle76407 exit0；8例完成，公共 `live-shared-ram-pin` selector、实际live provider与同catalog执行正常。
- 实际选择 F1×2、F3×3、F4×1、F5×1、F6×1、F2×0。目录支持六flow不等于这次实际执行过所有六flow；本轮没有F2，不声称已观察公共策略的PIN消费。
- 一个RAM认证语义关系，实际同search-clock命中时刻26.830918秒；campaign108.524777秒，finish/export36.783778秒，within replay原模式未请求，coverage unavailable，IRQ/source/retirement不升级（IRQ消费unknown）。认证关系计数不是RTL覆盖。
- fresh handle79108已exit0，8例completed；within/cross/session均verified且matches=true，fresh_scope为strict-cross-invocation，metrics.fresh为verified。独立核selection、request、source manifest、prefix identity与语义key集合相等，manifest对summary/测量/execution身份文件的SHA绑定匹配。各组件original/fresh/within-replay的execution nonce三者独立、build/artifact/binary相同且均reaped/exit0；不同调用命名空间中PID数字可能复用，不能仅凭PID数字判断同一进程。
- fresh实际campaign106.666736秒、wall347.694611秒、workflow367.900497秒；fresh额外重放/核验不计入搜索campaign。original与fresh均只观察RAM关系1，F2仍0、coverage仍unavailable，不能提升为已观察PIN消费或RTL覆盖。

## 适配范围与剩余边界

现有支持矩阵记录 Ibex/CV32E40P/CV32E20 × Timer/SPI 六组合：均公共 OBI/APB F2/F4、各4例original/crossfresh、同版本关系与各自离线coverage。三个source families不可混成同一次性能/策略实验。CV32E40P+GPIO的独立F1–F4复用是另一范围，不授新CPU的IRQ/F5/F6支持。

RAM/PIN定向版本/归属/奖励去重与warm reset旧scope失效已有单独报告；不能把它们拼成当前公共state运行已选择F2/PIN关系。cold reset恢复、更多CPU的F5/F6仍不是本轮性能证据。本报告没有新增性能重复实验或扩大适配范围。

## tail 访问简化的集成回归

新增独立产物 `shared-performance-20261029/tail-v1`（native37667 exit0）：8主例，F1/F2/F3/F4各1、F5/F6各2，完整 fresh replay 匹配。独立对本次 original 与其 fresh 调用完整 `_normalized_f6_prefix`，整份内容相等；规范化 SHA256 为 `ab97f7d7467e6ead1ebd23716d7015b5fb696d30bc0c17a6e9d5eda1742cefe1`。两侧 raw native runtime eval 次数均为 CPU3908、DMA4040、GPIO4092，亦与各 PID 的实际 timing 文件一致。

两侧各两条 F5 IRQ/ISR 均 verified：raw native take 与 certified serial 引用相同事件，handler retirement/MRET、GPIO APB样本/MMIO delivery、结果 RAM事件逐项存在并匹配；high/low PADIN分别256/0，INTSTATUS读值均256。小核验明细附于配套 JSON。

本次 wall481.956177秒、campaign149.976447秒仅用于记录集成回归。host源已变，**不与前述旧源码 A/B 的 full-prefix hash 作直接等值比较，也不把481.956与493.848的差异解释为新增性能收益**。
