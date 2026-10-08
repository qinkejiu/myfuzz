# P3 长会话读发行重复与指令版本容量

> **⚠ 复算可用性（2026-10-09 更新）**：本文引用的部分原始产物目录在 2026-10-09 的 `runs/` 清理中被删除，因此文中指向 `runs/` 的链接可能失效。**报告的结论、数字与边界仍然有效**（记录的是当时真实执行的结果），但"从原始产物复算"的能力已不存在。删除范围、已重建项与逐条断链清单见 [已删除的原始产物](DELETED_ARTIFACTS_20261009.md)。
日期：2026-10-07。此分析使用先前被中断的 [82 例失败运行](../../runs/current-dataflow-p3-long-20261007-online/report.json)作只读诊断；其 `execution_status=failed`、`session_status=uncertain_effect`，不是验收证据。

## 失败前缀的精确计数与触发链

完整 JSONL 有 585,655 个事件。其中 `memory_read` 为 3,370 条：3,329 条 instr 读和 41 条 data 读，按六字段 TransactionKey 全部唯一；`memory_read_issuance` 为 49,572 条，但只有 **41 个不同完整 TransactionKey**，多记 49,531 次。`(epoch, sequence)` 两字段投影会把 instr/data 两通道混在一起，不能用于判定真实读是否重复。首次重复 issuance 在 event 331547，key `(source_epoch=0, channel_id=data, source_sequence=134)`；单 key 最多出现 6,197 次。49,572 是日志发行事件数，绝非 49,572 次真实 `MemoryService.read`。

首个确定屏障在 event 329444 的真实 `instr_response` 后：event 329445 是 `uart_store_memory_match` 的 `incomplete/raw_store_memory_certainty_barrier`，event 329449 是独立 CPU matcher 的 `incomplete/instruction_capacity_exceeded`。触发前已有 2,049 条 instr response，却只有 236 个不同的 `(address, rdata, frozen writer IDs/kinds/versions)`；旧 `CpuRetirementMatcher` 把相同冻结指令每次 fetch 都加入 2,048 槽队列，已退休后的重复版本也不回收。读回 join 退化后，其早退分支不消费已发行的 read authority token；runner 每步重新 `drain()` 未消费 token，遂重复记录 accepted issuance。这个屏障之后的 accepted issuance 只证明原有 callback 描述被重复展示，不能成为新的读回证书。

此前按低字节 `STORE` 类型过滤的试验已撤回：失败日志的 49,571/49,572 条 issuance 已标为 STORE，而且该计数受重复 drain 扭曲。保留完整读授权与退休身份，不按 writer 类型猜测来源。

## 修复与证据边界

`CpuRetirementMatcher` 现在按完整冻结签名保留一份代表性指令响应，并继续逐条检查 source sequence。地址或任一 writer ID、kind、version 不同仍占新槽；超过容量仍发 `instruction_capacity_exceeded` 并降级。旧的异版本容量负例继续通过。同一冻结版本的重复响应不制造新来源，代表性响应仍保留实际事务与快照；此证书原本也不主张某条退休指令与某次重复 fetch 的精确一对一关系。独立审查发现：仅保留代表项会把最近一次被合并事务的 exact duplicate 误判为冲突。新增最多 `max_pending` 个完整事务键及冻结签名的有界近期记录；窗口内 exact duplicate 保持原有拒绝但不降级，窗口外未知重复仍保守降级。

读回 join 在已退化时，仍核对并一次性 `resolve()` 实际 read token，然后拒绝形成 readback proof。独立审查又发现 authority 自身先因后续 callback 失败退化时，旧 `resolve()` 在弹出 token 前返回 `None`；现在它先弹出，再返回无证书的 `None`，使待结清 token 不会每步重复 drain，也绝不把退化恢复为 accepted 证书。在线 runner 的 EventJournal 归档后仅释放 CPU 原始事件和 MemoryService 原始事件列表，并将对应游标归零；普通列表模式保留原行为。router 的 acceptance/delivery 列表继续保留，因为其 `acceptance_order` 依赖列表长度。warm reset、不同 component 与 journal 跨 chunk 的游标回归均通过。

TDD 红测分别复现了相同冻结 fetch 溢出、退化后 read token 未消费、journal 下 CPU 列表不释放、误清 router 历史、合并后近期 exact duplicate 误降级，以及 authority 自身退化后旧 token 未结清。3,000 条具有真实 `instr_response` 字段形状、236 个冻结地址版本的回归保留 236 个代表项，未产生容量屏障，并能继续接受退休观察。把失败 trace 中首屏障之前的真实 CPU 事件流重新输入新 matcher，得到 236 个保留版本、零 `instruction_capacity_exceeded`；其中 1,757 条非内存指令匹配及 133 条内存指令匹配 accepted。此离线重算只检查 matcher 的局部行为，不转换失败运行的验收等级。

## 冻结源码短 RTL 门禁

快照 `/home/qinkejiu/myfuzz_snapshot_p3_efficiency_20261007` 的 `src/`、`configs/`、`scripts/`、`schemas/`、`tests/` 共 2,753 个文件见 [SHA-256 清单](../../runs/current-dataflow-p3-efficiency-snapshot-20261007.sha256)，清单哈希 `b0923d73a59a9bb7d1fd7a8c924cd6313050c0b44f99eb56a6cbc57a81e58d20`；运行与重放后复核零差异。

```bash
cd /home/qinkejiu/myfuzz_snapshot_p3_efficiency_20261007
PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_ibex_uart_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p3-efficiency-cache \
  --output /home/qinkejiu/myfuzz/runs/current-dataflow-p3-efficiency-4-online \
  --seconds 60 --max-tests 4 --seed 43 \
  --run-id current-dataflow-p3-efficiency-20261007 \
  --cpu-retirement --uart-fifo --memory-commit --memory-readback
```

[报告](../../runs/current-dataflow-p3-efficiency-4-online/report.json)显示 4/4 complete、37,643 事件、3 条 accepted Store 来源与 2 条 accepted host RAM 低字节读回证书、3 条 accepted read issuance；有效搜索 16.048 秒，证据终结 6.848 秒。独立 replay cache 对完整 plan 与 trace fresh RTL replay 返回 `matches=true`、`first_difference=null`、`difference_context=null`。短门禁验证当前修复未切断原有读回链；它没有达到旧第 82 例的容量点，也没有跨越 256 writer 历史容量。P3 长会话和完整阶段仍待验收。

审查修复后的短门禁使用另一冻结快照 `/home/qinkejiu/myfuzz_snapshot_p3_efficiency_review_20261007`；其 2,753 文件 [SHA-256 清单](../../runs/current-dataflow-p3-efficiency-review-snapshot-20261007.sha256) 哈希为 `bea0cd19f1a7a4f3b87cf02251cf6cf8cead8dbd48d3d636755fd5e128ca9c41`，包含上述近期 key 记录及 authority 退化 token 弃证修复。[运行报告](../../runs/current-dataflow-p3-efficiency-review-4-online/report.json)为 4/4 complete、37,643 事件、3 条 accepted Store 来源和 2 条 accepted 读回证书；独立完整 fresh RTL replay 返回 `matches=true`、`first_difference=null`。原短门禁仅证明审查前版本。

## 同快照 600 秒真实压力门禁

继续使用上述 review 快照，独立运行 `--seconds 600 --max-tests 100 --seed 43`。[报告](../../runs/current-dataflow-p3-efficiency-review-100-online/report.json)为 **76/76 complete**、有效搜索 602.289 秒、535,269 事件、终结 60.063 秒、进程最大 RSS 3,706,848 KB。流式审计完整 JSONL：3,470 条实际 `instr_response`，已跨越旧失败前缀在第 2,049 次 fetch 出现的容量条件；3,513 条 `memory_read`，43 条 `memory_read_issuance` 的完整事务键全唯一，43 条 accepted Store 来源、42 条 accepted readback，相关 `cpu_retirement_match`／Store／readback **零 incomplete**。这证明本次完整会话没有重现旧指令容量与重复 token 故障；它只有 76 例、43 个 writer，**未跨越 256 writer**。独立 replay cache 对全部 plan 与 JSONL trace 做新进程 fresh RTL replay，返回 `matches=true`、`first_difference=null`、`difference_context=null`；重放耗时 12 分 33 秒。后续 UART producer 列表释放不在这个快照内，其证据另见后续门禁。

## UART 生产者列表释放：独立快照与内存实测

审查发现 `GeneratedOpentitanUartSession.uart_events` 会为每次 tick 留一份完整深拷贝；即使 EventJournal 已归档，长会话仍在生产者列表保留它。新的逻辑仅在每个 component 的外部事件及同步消费全部成功后，将 journal 模式的 UART 原始列表与游标一并清空；异常时不清空，普通非 journal 模式不变。router 接受／交付历史继续保留其编号语义。异常后的旧游标已在写入 journal 时前进，本次改动不赋予失败的同步消费自动重试语义。

为隔离这个变化，从前述 600 秒 review 快照独立复制 `/home/qinkejiu/myfuzz_snapshot_p3_uart_release_20261007`，仅替换 `src/myfuzz/scenario/runner.py` 和 `tests/scenario/test_uart_ram_commit_runner.py`。2,753 个核心文件的 [SHA-256 清单](../../runs/current-dataflow-p3-uart-release-snapshot-20261007.sha256)哈希为 `55fba6cd26bb935e6393d1ddf1f13cc83d9d235750731cbf19e89c835bea0a92`，真实运行和 replay 后复核零差异；旧快照清单也再次通过。新测试放到旧快照执行时，跨组件 warm reset 与 UART 连续归档两项按预期失败；新快照相关套件 **87 passed、369 subtests passed**。

新快照按 `--seconds 60 --max-tests 4 --seed 43 --cpu-retirement --uart-fifo --memory-commit --memory-readback` 执行 [真实在线运行](../../runs/current-dataflow-p3-uart-release-4-online/report.json)：4/4 complete、37,643 事件，3 条 Store→host RAM 与 2 条后续读回证书 accepted，3 条 read issuance accepted；相关证书无 incomplete。另一独立 cache 对完整 [plan](../../runs/current-dataflow-p3-uart-release-4-online/online_plan.json) 和 [trace](../../runs/current-dataflow-p3-uart-release-4-online/online_final_trace.json)做新进程 fresh RTL replay，得到 `matches=true`、`first_difference=null`、`difference_context=null`。该短跑只检查数据流没有被清理切断，不证明长会话 RSS 降幅。

用同一个 [1000 条合成事件测量脚本](../../runs/current-dataflow-p3-uart-release-memory-probe.py)分别在旧／新快照执行，每条包含 24,006 字符 payload，EventJournal chunk size 为 8。两组均归档 1000 条；旧版 UART 生产者列表仍留 1000 条／24,006,000 payload 字符，`tracemalloc` 当前分配为 24,302,260 bytes；新版列表为 0，当前分配为 28,592 bytes（峰值 354,434 bytes）。这是隔离 Python 对象保留的受控对照，不等于真实 RTL 长跑的 RSS 差值。真正跨 256 writer 的长跑及新版清理在长跑中的 RSS 门禁仍未完成。
