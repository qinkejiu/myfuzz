# 通用化增量，2026-10-28

将 F1/F3 作为统一 scenario 的独立 flow：输入由现有 memory lowerer 验证并规范化为 mixed 执行序列，复用原执行器；结果和 fresh 请求保留 F1/F3。新增 configs/search/memory-f1-ibex.json 和 memory-f3-ibex.json。未注册当前状态 provider 时反馈仍为 unknown。

新增最小逐 case CaseAdapter：读取状态、lower、submit、settle。StorageCaseAdapter 使用现有 live storage 实现，已接入 Timer/SPI 原 live 循环。接口本身不产生认证反馈；该阶段 GPIO/F5/F6 尚未接入；后续进展见下文。F1/F3 仍是执行前的有限记录选择，尚未实现全 F1–F6 公共在线循环。

软件门：tests/search 与 tests/search_comparison 170 passed / 8.71s。新增 F1/F3 preflight、执行路由、回放模拟和 storage adapter 调用顺序测试。

原生：F1、F3 独立场景各一例 original/fresh，均 exit0；Timer 一例 original/fresh exit0。Timer 三例 F4/F4/F2 发现一个认证写后读关系，触发实际选择性重放且通过。原始材料位于 research/input-strategy-audit-20261027/runs/generalize-20261028/。未声称其他 CPU/IP 组合、F5/F6 或全部功能已接入公共在线接口。

后续把 CaseAdapter 改为支持带显式 case_id/预算/重放上下文的原子 execute，并实际接入 GPIO 与 storage。GPIO 三例真实发现一条关系，独立 fresh verified；Timer 三例发现一条认证写读关系并选择性重放 verified。F5 在线选择在同一 runtime 中逐例 submit 后选择下一例；0.001 秒预算原生请求3例、实际执行1例，fresh 按实际1例前缀通过 within/cross/boundary。F5 仍没有版本消费 provider，反馈 unknown。

源码并发修改发生在最初 f5-online/gpio-adapter/timer-adapter-v2 的原生运行中，三者均失败，不计入通过。源码冻结后 f5-online-v2/gpio-adapter-v2/timer-adapter-v3 的运行通过；最终软件门 tests/search、tests/search_comparison、tests/runtime/test_generic_wall_budget.py 与 test_generic_f5_entry.py 为 227 passed / 9.76s。

F6 随后接入按需 selector：同一现有 DMA runtime 中，上一例真实提交后再选下一例；保留事务 scope、执行记录与 raw8 双射、finish 和 replay。预算截断只保存实际前缀，反馈仍为 unknown。软件相关门 252 passed / 9.63s；最终报告字段修正另有 101 passed / 3.53s。

最终源码 F6 原生 original 和 fresh 均 exit0：请求2例、极短预算实际执行1例；fresh 的 within/cross/session boundary verified。original 摘要 requested_case_count=2，fresh 实际重放1例，planned_case_count=2。见 `runs/generalize-20261028/f6-online-v2/`。更早 f6-online 的原生验证在报告字段修正前，按源码版本单独解释。该测试只证明一例部分前缀，新增 selector 的多例 DMA 逻辑切换尚需原生复验。

F1/F3/mixed 随后接入逐例选择：在现有同一持续 session 中，完整目录先做合法性预检；选择后提交真实输入，只有成功提交才 censored settle 并继续。预算在选择后提交前耗尽时恢复策略状态（含随机数），不把未执行决策写入实际前缀；fresh 按实际执行顺序恢复，保留请求容量和准备所需 flow。首次 online-* 原生运行与源码修改发生竞态，均失败，不算验证；冻结后 online2-* F1/F3 原生 original/fresh、mixed 截断 original/fresh 均通过。相关最终软件门 273 passed / 11.60s。

GPIO live 在最终源码再次运行：3例、完成1条真实关系，独立 fresh 和 session boundary verified；F5/F6 多例原生验证见 online2-gpio-f5 与 online2-dma-f6 的 original/fresh（其完整终态以目录实际 summary 为准）。统一逐例选择仍不意味着 F1–F6 都混合在同一个 session，也不意味着所有路径已有 live 状态/消费 provider。

最终 F6 两例 fresh 首次发现搜索层按候选目录数（1）而非执行次数（2）验证，错误拒绝底层已匹配结果；已增加“一个候选重复两例”的回归并修复。online2-dma-f6/fresh 为保留的失败诊断；最终版本以 online3-dma-f6 复测。修复后的搜索/比较/mixed/F5/F6 软件门 273 passed / 9.83s。
最终版本 `online3-dma-f6` 两次实际 submit 的 original 和 strict fresh 已通过，fresh 的 within/cross/session boundary 均 verified；因此验证了该两例顺序下的 F6 logical scope 与完整重放。该样本不代表任意 F6 输入或协议均已适配。
