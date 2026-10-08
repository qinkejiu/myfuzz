# P3 定向真实 UART→host RAM writer 超 256 容量门禁

> **⚠ 复算可用性（2026-10-09 更新）**：本文引用的部分原始产物目录在 2026-10-09 的 `runs/` 清理中被删除，因此文中指向 `runs/` 的链接可能失效。**报告的结论、数字与边界仍然有效**（记录的是当时真实执行的结果），但"从原始产物复算"的能力已不存在。删除范围、已重建项与逐条断链清单见 [已删除的原始产物](DELETED_ARTIFACTS_20261009.md)。
日期：2026-10-07。此门禁只检验已实现的受限 UART 来源到 Ibex 退休 `sw`、真实 `MemoryService` 提交及 `UartMemoryReadbackJoin` writer 历史回收能否在一个持续会话中越过 256 个 writer。它不是随机 RFuzz 搜索、通用 CPU→RAM 路径或 P3 整阶段验收。

## 冻结源码与执行

使用独立快照 `/home/qinkejiu/myfuzz_snapshot_p3_capacity_20261007`。`src/`、`configs/`、`scripts/`、`schemas/`、`tests/`、`third_party/` 的 [SHA-256 清单](../../runs/p3-capacity-directed-snapshot-20261007.sha256)哈希为 `591338660cb49580b22ded7203ad278d8da441d485088cc80e69e4fc10fcee9f`；真实运行及 replay 后 `sha256sum -c` 退出码 0。构建缓存与 fresh replay 缓存分别在 `runs/p3-capacity-probe-cache/` 和 `runs/p3-capacity-directed-replay-cache/`。

新增 [定向门禁脚本](../../scripts/run_p3_uart_writer_capacity.py)从现有 `make_ibex_uart_online_runtime` 启动真实 Ibex＋OpenTitan UART。固定 warmup 的真实 UART RDATA 进入 x3；其后五个独立在线 case 各向未来预留取指槽提交 54 条合法 RV32I `sw x3, 0(x5)`，共 270 条。CPU 实际取指、退休并通过 data 请求/响应调用 `MemoryService.write`；脚本没有直接调用 host RAM 写接口。首例前 400 步同时推进 UART/CPU 以完成受控 ISR 的 MMIO，随后只推进 CPU。整个会话未出现 CPU 或 UART reset 事件。

```bash
cd /home/qinkejiu/myfuzz_snapshot_p3_capacity_20261007
PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_p3_uart_writer_capacity.py run \
  --cache-dir /home/qinkejiu/myfuzz/runs/p3-capacity-probe-cache \
  --output /home/qinkejiu/myfuzz/runs/p3-capacity-directed-270-20261007 \
  --stores 270 --chunk-size 54 --ticks 1000 --next-ticks 700 --paired-ticks 400
```

此前 3 条 `sw` 的步数探针先发现只推进 CPU 会停在 ISR 的 UART MMIO 读取；加入 UART/CPU paired 步后，3 条定向 `sw` 加 1 条 ISR `sw` 得到 4 条 accepted 证书，且该短探针的 fresh replay `matches=true`。正式运行使用上述已验证的调度。

## 实际结果与原始核对

[容量结果](../../runs/p3-capacity-directed-270-20261007/capacity_result.json)：五个 case 均 `running`，终态 `complete`，29,174 个事件，CPU/UART local ticks 为 4,216/1,652，零 checker violation，readback join 未降级。实际 `memory_write` 和 `memory_write_commit` 各 272 条，其中 271 条形成 accepted UART→host RAM 低字节 Store 证书：一条受控 ISR `sw` 加 270 条定向在线 `sw`。尾部 writer 缓存只有 15 条，说明旧同地址版本已按证据回收。

[独立事件审计](../../runs/p3-capacity-directed-270-20261007/capacity_audit.json)从完整压缩事件流复核：271 条 accepted 证书对应 271 个不同的 `(memory_id, generation, byte_offset, byte_version, writer_event_id)`；每条均指向事件流中真实的 `cpu_retire`、`data_accept`、`data_response`、`memory_write_commit`。第 256 条证书在事件索引 27709，版本 `[0,267]`；第 257 条在索引 27737，版本 `[0,268]`；最后一条在索引 28099，版本 `[0,282]`。相关 Store、readback、CPU retirement matcher 的 `incomplete` 计数均为 0。271 条证书的 UART 来源路径被认证，但 `store_memory_path_certified` 全为 false，符合本门禁只授予受限 host RAM 低字节来源的范围。

[完整计划](../../runs/p3-capacity-directed-270-20261007/online_plan.json)、[压缩 trace 元数据](../../runs/p3-capacity-directed-270-20261007/online_final_trace.meta.json)及 `online_events.zlib` 保存了全部输入、事件和 local ticks。独立 cache 的新进程 fresh RTL replay：

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_p3_uart_writer_capacity.py replay \
  --cache-dir /home/qinkejiu/myfuzz/runs/p3-capacity-directed-replay-cache \
  --output /home/qinkejiu/myfuzz/runs/p3-capacity-directed-270-20261007
```

[重放结果](../../runs/p3-capacity-directed-270-20261007/fresh_replay.json)为 `matches=true`、`first_difference=null`、`difference_context=null`、`actual_status=complete`，CPU/UART local ticks 同为 4,216/1,652。聚焦回收及读回软件测试命令 `PYTHONPATH=src pytest -q tests/scenario/test_uart_readback_writer_history.py tests/scenario/test_uart_memory_readback.py tests/scenario/test_memory_read_authority.py` 在主工作区返回 **14 passed**。

事后审查发现原定向脚本仅根据 case `running` 和 join 未降级决定退出码，因此未执行到 Store 的早期探针也会退出 0。现行脚本增加退出门禁：请求必须超过 256 个 Store、终态必须 `complete`，真实 `memory_write_commit` 和 accepted Store 证书均至少达到请求数，accepted 证书须有同样多的不同完整 writer 身份，尾部保留缓存不得超过 256 且须少于已认证身份数。[聚焦测试](../../tests/integration/test_p3_uart_writer_capacity_gate.py)先验证缺失门禁失败，再与上述三个回收／读回测试一起得到 **17 passed**。冻结快照及其哈希仍对应原运行脚本；事后修改只改变退出判断和结果计数字段，未重跑或改写原 trace。原运行的精确计数由独立 `capacity_audit.json` 与完整 fresh replay 支撑。

## 边界

这次只把同一个受控 UART 字节来源反复写入同一 host RAM 地址，验证超过 256 个真实 writer 后的有界历史与精确提交关联。定向 CPU 指令复用了现有 `CPU_TO_IP` 指令 admission path 身份；实际地址是 host RAM，所以不能把该 path 标签解释成已认证的 CPU→UART 目标交付。运行中没有在第 257 个 writer 之后再退休 `lw` 读回；读回正确性仍由已有短门禁与 300 版本软件回收测试证明，不能从本次 writer 容量门禁外推。通用跨例数据流、随机 RFuzz 吞吐和 P3 阶段验收继续待办。
