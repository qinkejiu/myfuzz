# P5 可选分块压缩终态事件日志门禁

日期：2026-10-07。本轮在既有在线终态证据格式上增加显式 `--compressed-trace` 选项；默认 JSON/JSONL 规则和已有运行身份不变。压缩保存每条有序事件的完整 canonical JSON，不删去 tick、观测或失败事件。当前仅验证短时真实 RTL，不把短跑数值推广到十分钟终态效率。

## 格式与拒绝边界

新 `online_trace_zlib_chunks.v1` 元数据仍保存 `event_count`、完整 trace 的 `semantic_sha256`、plan 与 manifest 身份，事件文件为 `online_events.zlib`。文件以 `MFZ1` 开头，每块以四个 little-endian u32 标明压缩长度、原始长度、事件数和原始字节 CRC32；随后是独立 zlib 流。每块最多 8 MiB 原始字节和 4096 条事件，默认写入每 256 条分块。读取器启动时逐块检查边界、完整 zlib 结束、无流内尾字节、CRC、JSON 对象和计数，并重新计算**全部事件**的 canonical 语义 SHA；任何截断、尾字节、过大长度声明、数量不符或语义 SHA 不符在 fresh RTL 启动前拒绝。索引存每块文件偏移与事件起点，随机事件读取只解压所属块，避免整文件 gzip `seek` 重复从头解压。

`online_run_identity.json` 使用 `trace_format=zlib_chunks.v1`，同时绑定元数据和压缩文件的 SHA-256。旧 `json.v1`、`jsonl.v1` 仍由原路径读取。写压缩文件使用临时文件和原子替换；若写入失败，不生成 complete run identity。

## 测试与真实门禁

`PYTHONPATH=src python3 -m unittest tests.integration.test_scenario_campaign tests.integration.test_scenario_rfuzz_terminal_identity tests.integration.test_online_run_identity tests.scenario.test_event_journal tests.integration.test_scenario_rfuzz_jsonl_semantic_stream` 返回 **71 tests OK，3 skipped**。测试包含旧格式身份、压缩后完整语义 SHA 与 JSONL 相等、随机访问、损坏/截断/尾字节/过大块/计数拒绝、写入失败无完整身份、压缩 trace mock 在线 run 和 fresh replay。

真实门禁的冻结源码目录为 `/home/qinkejiu/myfuzz_snapshot_p5_zlib_chunks_20261007`，[SHA-256 清单](../../runs/current-dataflow-p5-zlib-chunks-snapshot-20261007.sha256)的哈希是 `871c3cd24b5ff09557fcb7ad50985ba95c287cf931a9d83d7993336ee01e420f`；运行后与重放后清单校验均零差异。命令：

```bash
cd /home/qinkejiu/myfuzz_snapshot_p5_zlib_chunks_20261007
python3 scripts/run_ibex_uart_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p5-zlib-chunks-cache \
  --output /home/qinkejiu/myfuzz/runs/current-dataflow-p5-zlib-chunks-4-online \
  --seconds 15 --max-tests 4 --seed 43 \
  --run-id current-dataflow-p5-zlib-chunks-20261007 \
  --cpu-retirement --uart-fifo --memory-commit --memory-readback --compressed-trace
```

[运行报告](../../runs/current-dataflow-p5-zlib-chunks-4-online/report.json)为 4/4 complete、37,643 条事件、有效搜索 16.381 秒。压缩文件 12,059,064 字节，块头原始字节合计 128,950,141 字节，**本次文件体积比为 10.693×**，共 148 块；`trace_write` 3.012 秒，进程峰值 RSS 509,228 KB。独立 replay cache、完整 plan 和压缩元数据的 fresh RTL replay 返回 `matches=true`、`first_difference=null`，回放进程峰值 RSS 417,152 KB。压缩读入先验证全部块和完整语义 SHA，再做运行身份检查及真实 RTL replay。

这些数字证明短门禁可重放和字节保存率；它们尚不能证明压缩让长时终结或 replay 更快。十分钟同源、同 seed、同预算且同断言条件的 JSONL 与压缩配对运行，及 256 writer 容量与 P5 完整传播链效率验收仍待完成。
