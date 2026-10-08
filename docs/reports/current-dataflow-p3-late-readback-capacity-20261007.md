# P3 超 256 个真实 writer 后的退休 LW 读回门禁

> **⚠ 复算可用性（2026-10-09 更新）**：本文引用的部分原始产物目录在 2026-10-09 的 `runs/` 清理中被删除，因此文中指向 `runs/` 的链接可能失效。**报告的结论、数字与边界仍然有效**（记录的是当时真实执行的结果），但"从原始产物复算"的能力已不存在。删除范围、已重建项与逐条断链清单见 [已删除的原始产物](DELETED_ARTIFACTS_20261009.md)。
日期：2026-10-07。本门禁沿用定向容量脚本，在同一持续的真实 Ibex＋OpenTitan UART 会话中先提交 270 条合法 `sw x3, 0(x5)`，再向紧接的取指槽 `0x11438` 提交合法 `lw x6, 0(x5)`。脚本没有直接写入或读取 host RAM。固定 warmup 的 UART RDATA 为 `0x5a`；CPU 的 data 端口经 `MemoryService` 完成 RAM 读写。

## 冻结源码、命令与测试

最终运行使用独立快照 `/home/qinkejiu/myfuzz_snapshot_p3_late_readback_v2_20261007`，其 `src/`、`configs/`、`scripts/`、`schemas/`、`tests/`、`third_party/` 的 26,539 个文件列在 [SHA-256 清单](../../runs/p3-late-readback-v2-snapshot-20261007.sha256)；清单本身 SHA-256 为 `97409a40d0f90f1f87e3af0909fe901c9dab397abb508bedec73c6d5e59b6921`。真实运行及 replay 后在快照目录执行 `sha256sum -c --quiet`，退出码 0。

```bash
cd /home/qinkejiu/myfuzz_snapshot_p3_late_readback_v2_20261007
PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_p3_uart_writer_capacity.py run \
  --cache-dir /home/qinkejiu/myfuzz/runs/p3-late-readback-v2-cache-20261007 \
  --output /home/qinkejiu/myfuzz/runs/p3-late-readback-v2-270-20261007 \
  --stores 270 --chunk-size 54 --ticks 1000 --next-ticks 700 \
  --paired-ticks 400 --read-ticks 100
```

冻结快照中的脚本结果门禁先检查超过 256 个真实提交和不同 writer，再从刚保存的完整 trace 检查**最后一条** accepted Store 证书与 `memory_read`、一次性 `memory_read_issuance`、`data_response.snapshot`、RVFI `cpu_retire` 和 accepted 读回证书。测试先因缺少该读回审计函数而失败；完成后在冻结快照运行 `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pytest -q tests/integration/test_p3_uart_writer_capacity_gate.py tests/scenario/test_uart_readback_writer_history.py tests/scenario/test_uart_memory_readback.py tests/scenario/test_memory_read_authority.py`，结果 **18 passed**。下文的事后审查加严了这个脚本门禁；上述冻结快照及其 18 项结果**不包含**事后加严代码。

## 实际证据

[门禁结果](../../runs/p3-late-readback-v2-270-20261007/capacity_result.json)退出码 0，6 个 case 均保持 `running` 回执，终态 `complete`，29,401 个事件、CPU/UART local ticks 为 4,316/1,652，零 checker violation，readback join 未降级。实际 `memory_write_commit` 为 272 条，accepted UART→host RAM 低字节 Store 证书为 271 条且 writer 身份各异；尾部缓存仅 15 条。第 256、257、271 条证书分别位于事件索引 27,709、27,737、28,099，版本分别为 `[0,267]`、`[0,268]`、`[0,282]`。无 CPU/UART reset；相关 matcher 的 incomplete/unknown/ambiguous 均为 0。

最后 Store 的证书事件 ID 为 `28100`，writer 事务序号为 `277`，版本 `[0,282]`，Store 退休 order 为 `355`。随后真实 host `memory_read` 事件 ID `29192`、accepted read issuance `29201`、CPU data response `29205` 均引用该 writer 的精确事务身份与 lane 0 版本；response 的完整 snapshot 记录 RAM `ram`、generation `0`、offset `65536` 和值 `0x5a`。真实 Ibex RVFI 在事件 ID `29209`、order `356`、PC `0x11438` 退休指令 `0x0002a303`，`mem_rdata=rd_wdata=0x5a`。accepted [读回证书及完整压缩 trace](../../runs/p3-late-readback-v2-270-20261007/online_final_trace.meta.json)的事件 ID `29210`，把该退休 Load 的 fullkey、最后 Store 的 fullkey/commit ID/版本和 warmup UART 来源连在一起，认证范围为 `influenced_bits=[0,8]`。

在同一冻结快照、新进程及独立构建缓存下运行：

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_p3_uart_writer_capacity.py replay \
  --cache-dir /home/qinkejiu/myfuzz/runs/p3-late-readback-v2-replay-cache-20261007 \
  --output /home/qinkejiu/myfuzz/runs/p3-late-readback-v2-270-20261007
```

[完整 fresh replay](../../runs/p3-late-readback-v2-270-20261007/fresh_replay.json)退出码 0，`matches=true`、`first_difference=null`、`difference_context=null`，事件与 local ticks 均一致。第一次探查快照已有相同的物理读回及完整 replay，但当时运行时附加审计误判并退出 2，故不计作最终通过；最终脚本从保存的无损 trace 作审计，并在上面的新快照重新运行和 replay。

## 事后门禁审查与原 trace 重审

独立审查指出冻结快照脚本的附加审计仍可被数类不一致事件误导：同时改写 read/response/RVFI 值，倒置 Store/Load 退休 order，使用残缺 data fullkey 或无关的 snapshot transaction ID，替换最后 Store 的定向 case/PC 或固定 UART 来源，以及在 Store→Load 间插入其它 commit/reset。当前工作树的[脚本](../../scripts/run_p3_uart_writer_capacity.py)和[测试](../../tests/integration/test_p3_uart_writer_capacity_gate.py)已测试先行加严；5 类反例在旧门禁下均 RED。当前门禁还核对最后 Store 原始 RVFI 退休、精确 stream fullkey 与连续 data 序号、RAM 读值低字节与 writer 值、完整读字节、read issuance 和 response snapshot 的事务 ID、Load order 大于 Store order，以及中间无写入、提交、reset 或 flush。加严后当前工作树同组聚焦测试 **24 passed**，包含 10 项脚本门禁测试。

未重新运行 RTL，也未改写冻结快照或原 trace。用当前加严脚本的 `_late_readback_evidence` 只读重审原 [完整压缩 trace](../../runs/p3-late-readback-v2-270-20261007/online_final_trace.meta.json)，结果仍 `passed=true`，最后版本 `[0,282]`，Store order `355`，Load PC `0x11438`、order `356`，read/issuance/response/retirement/证书事件 ID 仍为 `29192/29201/29205/29209/29210`。归档 `online_events.zlib` 的 SHA-256 为 `987b21d070b3b5f3bc084ba8491b4097b2df367dab0bf3ede7e93c9c9d436634`，metadata 为 `1ed251517470d72791185d2ee35be82f63b84849219153e77eed55dc55023aa8`；冻结快照清单重新核对仍为 0 差异。原 `fresh_replay.json` 仍只证明冻结快照运行的完整 replay 一致；事后加严的结果是对同一归档事件的独立审计，不是一次新的 RTL 运行或新的 replay。

## 边界

本证据覆盖一个固定 UART 字节经受控 ISR 到重复 `sw`、建模 host RAM 低字节、超 256 writer 后再由真实 `lw` 退休读回的**受限路径**。在线指令沿用 `CPU_TO_IP` admission 身份，但实际 data 地址为 host RAM，不能把该路径标签解释成已认证的 CPU→UART 目标交付。高 24 位来源、RTL 内 RAM、一般 ISR 或任意操作子、随机 RFuzz 搜索吞吐和通用 P3 验收均未由此门禁证明。
