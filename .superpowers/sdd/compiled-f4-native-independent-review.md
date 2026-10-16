# Compiled F4 Ibex native 证据独立复核 — be56973

只读审查冻结基点 `bdeee0b957a104b9e66abab52e219e15d0fee62e` 的 snapshot-attempt3 executor/file entry/launcher/Ibex config、commit be56973 报告及本地证据归档；独立解析 JSON/日志、核对摘要和事件关联，没有运行新测试、native、生成器或远端任务，未修改实现。

## 裁决

未发现推翻本次 **固定 RV32I writer、Ibex native OBI→APB→live GPIOEN** 三例实际执行结果的高/中严重性矛盾。已有证据支持三例连续 primary prefix 和两次受信 replay 函数返回 matches=true；fresh 原始日志持久化不足及 freshness 门控限制如下，不能称本轮独立逐事件重比了两套 fresh journal。

## 证据局限

1. **Fresh journal 未分别归档。** `attempt3/replays.json` 保存两次 matches、expected/actual semantic hashes 和耗时，但未保存 fresh.finish 的完整 plan/events/live witnesses。冻结 `CompiledF4Runtime.replay` 确实重建会话、逐 raw record 执行并比较完整 normalized plan（含 semantic hash），归一化只移除 prerequisite/postcondition.process_scope。然而本轮只能审查该实现与其实际返回记录，无法像 primary events 一样独立重算两次 fresh 的完整事件摘要与 certificate 内容。建议后续分别持久化 fresh plan/events/process scope。
2. **Fresh PID/nonce 未在 replay 中强制互异。** 每次通过 native constructor/begin 建新进程，现场记录第二 fresh PID 为 175538/175677，原 primary witness PID 163380；但 replay 源码移除 process_scope 前没有显式比较原/fresh PID/nonce，返回物也不保留这些 scope。此项是 fresh 绑定可审计性的剩余缺口，不足以据此断言本次实际复用了进程。
3. **退出码的范围。** `logs/remote-final/entry-attempt3.exit=0` 是 wrapper 捕获整个 Python 文件入口的真实返回值；归档未提供每个 primary/fresh native child 的独立 OS exit receipt。不能把它展开成“每个 native child exit0 都独立存证”。源码正常 finalize 及 runner failure checks、主入口成功记录存在。

上述为证据/门控限制；未发现 primary native 交易、版本和指令消费链的反例。软件 mock negatives 不等于 native 改响应/故障注入控制。

## 独立核对事实

归档大小 **1,940,936 bytes**，SHA-256：

`1af223cd2b2b8bff9750830a13d89d2a0f6d3aef1f910703206d47d2ec0aeb24`

与旁置 sha 文件相符。完整 source manifest 摘要为 `eb5d2bc471900de9143bfb31fbf8d7bd287f1afa962367861cd0138a542e3788`，记录 git head bdeee0b 和 **32,608 files**。归档 pre/post source verification 均 matches=true、零 mismatch。当前本地冻结 snapshot 中六个 selected source pins 全部重算匹配，prefix 中全部 Python source closure 也重算零 mismatch；本轮没有重扫全部 32,608 个源文件。归档 CPU/target driver.cpp 与 runtime.sv 摘要均匹配其 artifact；artifact digest 与 prefix 对应项相符。

真实 launcher 从 snapshot-attempt3 的 src/根目录加载入口、使用 canonical heavy-worker.lock，`entry_exit=$?` 后写 logs/entry-attempt3.exit。归档该值为 **0**；先前 attempt1/attempt2 的各自退出为 **2**，保留 report/.incomplete，未混作成功或 DUT failure。focused suite log 实为 **40 passed, 1 skipped in 127.66s**，其 exit 文件0；private snapshot regression 为 **1 passed, 8 deselected in 16.27s**，exit0。本轮未重跑。

primary events 含 **7,351** 条且 event_id 唯一。由原始 records 重算最终 ticks 为 processor=385、peripheral=412，再按冻结 session semantic payload 算得：

`568802e698c6fa86675b67e0cc8610af78b09d3c0253d54efd92b197dd09d7fa`

与 prefix/report/两次 replay 返回 hash 全部一致。

| case | raw 低字/候选 | 指令起点 | 指令 source event | GPIOEN 前→后 | native commit tick |
|---|---|---|---|---|---|
| 0 | 0x55 | 0x10080 | 37 | 0→85 | 16 |
| 1 | 0xaa | 0x100b0 | 2479 | 85→170 | 153 |
| 2 | 0x12345678 | 0x100e0 | 4924 | 170→305419896 | 290 |

三例 prerequisite/postcondition 都指向同一原始 target PID163380/nonce、epoch0、同一 artifact/source/observation合同，未每例重置。实际首次 instruction acceptance 为 event17、0x10080；未把 boot base0x10000替代实测首取指。每例八个 functional instruction hops 的 source event、memory_read rdata、版本组与 native acceptance/response references存在；四字节版本依次为 [0,1]、[0,3]、[0,5]，与对应 instruction_source 一致。尾部 NOP 未冒充功能指令或退休证据。

三例各有 SW/LW native data hops：第一例 native accept261/391→router delivery279/418→physical APB sample309/448→native response374/503；后续对应 hops亦指向原始记录。物理 APB pre sample 的 psel/penable/pready、pwrite/paddr/pwdata/prdata、error 及 GPIOEN probes保留于 outputs.backend/physical；commit context 地址0x40001004、offset4、be15、source_transaction和sample tick相符。native OBI data response返回实际候选值，readback RAM关联保留。不是仅检查 host 写入的 expected 数字。

文件入口成功耗时：generation39.368s、startup73.755s；三例68.490/67.812/68.921s；fresh234.422/237.128s；总795.370s。report 的 coverage_guided=false、general_instruction_search=false、full_D4_accepted=false保持诚实；不能凭 directed cases/sec授搜索性能等级。

## 不支持范围

只验证冻结 bdeee0b 的 compiled_f4_obi_apb、单目标 GPIOEN、固定48-byte RV32I writer和当前 Ibex physical error ABI。CV32E40P native no-error variant依然不支持。F1/F2/F3/F5/F6、通用 witness/assertion派发、seed、覆盖引导搜索、完整失败 prefix replay均未因本门通过而获得能力。

07f2da6/fd0f49a 的 candidate layout模块不在该冻结 native gate中，也尚未接生产 submit；不得拿此记录证明其独立 slices/空域修复被 RTL执行。该门不等于 P7-D/E、无适配同协议新CPU/IP、任意指令搜索、source/retirement authority或全路径验收。
