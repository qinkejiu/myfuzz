# P5 压缩 trace 写入的有界效率复核

> **⚠ 复算可用性（2026-10-09 更新）**：本文引用的部分原始产物目录在 2026-10-09 的 `runs/` 清理中被删除，因此文中指向 `runs/` 的链接可能失效。**报告的结论、数字与边界仍然有效**（记录的是当时真实执行的结果），但"从原始产物复算"的能力已不存在。删除范围、已重建项与逐条断链清单见 [已删除的原始产物](DELETED_ARTIFACTS_20261009.md)。
日期：2026-10-07。本报告针对 [P5 十分钟在线运行](current-dataflow-p5-runner-zlib-600s-20261007.md) 的 `trace_write=79.783s`，仅优化终态压缩写入时的事件读取。原运行的 600 秒搜索、2,355,748 事件 trace 和冻结源码证据均未修改，也未在当前源码下重跑完整搜索或 fresh RTL replay。

## 瓶颈与改动

原 `write_zlib_chunk_events` 遍历 `EventJournalSnapshot`，每个事件经公开 `__iter__` 深拷贝后再编码。压缩写入只读事件且发生在 `_finish_online_session()` 之后、同步终结流程中；其间无新的 session step 或 journal append。现在压缩写入器对这一内部 snapshot 使用固定前缀的私有借用迭代器，跳过每事件深拷贝。公开 snapshot 的索引与遍历仍返回独立拷贝。zlib 块大小、事件 JSON 编码、CRC、语义 SHA 和落盘格式均未改变。

先写的测试在旧实现上因 `deepcopy` 调用失败；实现后 7 项 `test_event_journal.py` 全部通过。测试包含 snapshot 后追加事件的固定前缀、公开读取的拷贝隔离、与普通事件列表写出的压缩字节一致，以及压缩读取器对截断、错误块计数、损坏块和错误语义 SHA 的拒绝。另加一个伪造负例：非规范 JSON 块即使把元数据 SHA 伪造成原始字节哈希，也必须被语义校验拒绝；它使曾尝试的原始字节哈希捷径暴露错误，该捷径已撤回。读取器继续对每个解码事件做规范化哈希。

## 同一事件集合的成对测量

`scripts/runs/benchmark_p5_trace_writer.py` 从原 139,902,175 字节压缩体中读取前 512 块，逐块核对原始长度、CRC 与事件数，构造 **131,072 个真实保存事件** 的同一个 `EventJournalSnapshot`。`iter(snapshot)` 强制走原深拷贝路径；直接传 `snapshot` 走新的借用路径。两者调用相同写入函数、256 事件/块、相同临时文件系统与 fsync；顺序为旧／新／新／旧／旧／新。每次把生成体逐字节与原保存 trace 的相同 512 块前缀比较，并比对写入时计算的事件语义摘要。测量命令：

```bash
cd /home/qinkejiu/myfuzz
PYTHONPATH=src:. /usr/bin/time -f 'total_wall_seconds=%e peak_kb=%M' \
  python3 scripts/runs/benchmark_p5_trace_writer.py
```

| 路径 | 三次写入耗时（秒） | 中位数 |
|---|---:|---:|
| 原深拷贝路径 | 3.880986、4.038232、4.051241 | 4.038232 |
| 借用前缀路径 | 1.941465、1.980555、1.972833 | 1.972833 |

在这组受控前缀上，中位写入耗时下降 **51.15%**。六次输出均逐字节等于原文件前缀（7,799,399 字节，SHA-256 `4ec93a86aae4f949d3a76a56ebf27b289ddb685850ed7abe1e181eb1215bf79c`）；再使用原 trace 元数据中的 `local_ticks` 和 `status` 完成规范语义 SHA，六次均为 `bd30aa0fc239cc58165ea56a1f22bd7c844f58eb5751b55e2199f68ca998f8a9`。整个基准含装载和六次写入共 19.37 秒，峰值 RSS 75,992 KB。

验证命令 `PYTHONPATH=src:. python3 -m pytest tests/scenario/test_event_journal.py tests/integration/test_p5_online_timing_gate.py tests/integration/test_p5_verified_replay.py tests/integration/test_p5_runtime_timing_receipts.py -q` 为 23 passed。原冻结运行的完整 trace/replay 结果仍是先前报告的证据；此次只证明相同已保存事件前缀的写入改进和字节/摘要一致，不能把 51.15% 直接套用到原 79.783 秒完整终结，也不能宣称 838.44 秒 fresh replay、搜索吞吐或故障发现质量变快。P5 整阶段仍未验收。

## 新写入器的真实 RTL 短回归

另从原 P5 长跑冻结快照创建 `/home/qinkejiu/myfuzz_snapshot_p5_writer_short_20261007`；2,766 项源码清单中只有 `src/myfuzz/scenario/event_journal.py` 的文件哈希变化。新[清单](../../runs/p5-writer-short-20261007/snapshot.sha256) SHA-256 为 `66684f6b4e4d093820c3cc075fccfc25250849176e5fe238d7414aa07c2067a8`。运行和 replay 后，新旧快照各自清单检查均退出 0。

```bash
cd /home/qinkejiu/myfuzz_snapshot_p5_writer_short_20261007
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 scripts/run_ibex_pulp_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir /home/qinkejiu/myfuzz/runs/p5-writer-short-20261007/cache \
  --output /home/qinkejiu/myfuzz/runs/p5-writer-short-20261007/online \
  --seconds 8 --max-tests 16 --seed 20261007 \
  --run-id p5-writer-short-20261007 --compressed-trace
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 scripts/run_ibex_pulp_online.py replay \
  --cache-dir /home/qinkejiu/myfuzz/runs/p5-writer-short-20261007/replay-cache \
  --plan /home/qinkejiu/myfuzz/runs/p5-writer-short-20261007/online/online_plan.json \
  --trace /home/qinkejiu/myfuzz/runs/p5-writer-short-20261007/online/online_final_trace.meta.json
```

两条命令均退出 0。[短跑产物](../../runs/p5-writer-short-20261007/online)为 16/16 `complete`、6,996 个压缩事件、语义 SHA-256 `695fa8ee588d3d8941024b2725569377f321b54c517a7ef1053031eb0b6303c4`，有效搜索 1.088 秒；独立 replay cache 的完整 fresh replay 为 `matches=true`、`first_difference=null`、`difference_context=null`。短跑 trace 写入 0.093 秒，运行整条命令壁钟 39.71 秒、replay 46.58 秒；没有同条件旧写入器短跑，因此这些时间不用于计算加速比。它证明改动后真实 RTL 压缩运行与重放仍一致，不能替代十分钟性能复测。
