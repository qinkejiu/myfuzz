# UART Store 到 host RAM 低字节版本：冻结源码真实门禁

> **⚠ 复算可用性（2026-10-09 更新）**：本文引用的部分原始产物目录在 2026-10-09 的 `runs/` 清理中被删除，因此文中指向 `runs/` 的链接可能失效。**报告的结论、数字与边界仍然有效**（记录的是当时真实执行的结果），但"从原始产物复算"的能力已不存在。删除范围、已重建项与逐条断链清单见 [已删除的原始产物](DELETED_ARTIFACTS_20261009.md)。
日期：2026-10-07。此报告绑定 `/home/qinkejiu/myfuzz_snapshot_p3_store_20261007`，不自动证明之后的工作区修改。该快照使用 `UartStoreMemoryJoin` 和实际安装的 `MemoryCommitAuthority`，在服务回执 ack 前交付 live token；证书由原始 UART/CPU 事实、同一 Store 的 data request/response 和成功的 host RAM callback 连接。

## 源码与命令

快照的 1,798 个 `src/`、`configs/`、`scripts/`、`schemas/`、`tests/` 文件列在 [SHA-256 清单](../../runs/current-dataflow-p3-store-snapshot-20261007.sha256)，清单 SHA-256 为 `bc1aee230ad0abffc305cfde0511c718ae7165dc96974d82ad24bb34835df805`。运行及 replay 后重新核对：0 个文件不符。在线运行身份中的 34 个 source file 与该快照逐一核对：0 个不符；其中包括 `uart_store_memory.py`、`memory_commit_authority.py` 和 `uart_ram_commit_join.py`。

在该快照根目录执行：

```text
/usr/bin/python3 scripts/run_ibex_uart_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p3-store-20261007-cache \
  --output /home/qinkejiu/myfuzz/runs/current-dataflow-p3-store-20261007-online \
  --seconds 20 --max-tests 4 --seed 43 \
  --run-id current-dataflow-p3-store-20261007 \
  --cpu-retirement --uart-fifo --memory-commit
```

退出码 0；4/4 例 `complete`，client returncode 0，真实搜索 17.259 秒。保存 [在线材料](../../runs/current-dataflow-p3-store-20261007-online/)：27,031 条事件、4 条 `memory_write_commit`、2 条 `uart_operand_use` 和 2 条 `uart_store_memory_match` accepted；相关 incomplete/unknown 均为 0。两条证书分别将实际 UART 来源的 x3 版本 `[cpu,0,81,3]` 与 `[cpu,0,151,3]` 连接到 host RAM region 内偏移 65,536 的低字节 writer 版本 `[0,6]` 值 `0x5a`、`[0,11]` 值 `0x7f`。各自 `commit_id` 与保存的实际成功 callback 一致。证书明确 `influenced_bits=[0,8]`，其余写入 lane、RTL RAM、后续 RAM 读取、一般 ISR 来源仍未认证。

按原始 event ID 独立定位两组 Store：退休事件 22,199／24,689，data accept 22,162／24,656，data response 22,174／24,668，commit 22,161／24,655。两组 data fullkey 各自一致，CPU 退休测得地址 `0x20000`、mask 15、rs2 值 `0x5a`／`0x7f`，请求的地址、BE 与 wdata 同值；commit 的完整键对应 data 序号 5／9。此只读核对不替代 live callback 授权，授权由运行时安装对象和 fresh replay 提供。

新进程以独立 replay cache 执行：

```text
/usr/bin/python3 scripts/run_ibex_uart_online.py replay \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p3-store-20261007-replay-cache \
  --plan /home/qinkejiu/myfuzz/runs/current-dataflow-p3-store-20261007-online/online_plan.json \
  --trace /home/qinkejiu/myfuzz/runs/current-dataflow-p3-store-20261007-online/online_final_trace.json
```

退出码 0，`matches=true`，`first_difference=null`，`difference_context=null`；比较范围是完整事件与 local ticks。短运行的证据终结耗时为 5.633 秒，其中 session finish 2.460 秒、trace 写入 2.943 秒、identity 写入 0.191 秒；这是 UART 4 例、约 90 MB trace 的测量，不外推到 P5 十分钟 GPIO 性能门禁。

## 软件门禁与范围

主工作区对应的软件聚焦检查：`PYTHONPATH=src pytest -q tests/scenario/test_uart_store_memory.py tests/scenario/test_uart_ram_commit_runner.py tests/scenario/test_uart_ram_commit_join.py tests/scenario/test_memory_commit_authority.py tests/scenario/test_host_identity_uart_fifo.py tests/integration/test_ibex_uart_memory_commit_mode.py`，**75 passed**。其中 Runner 测试检查实际 callback 的 stage-before-ack、原始事件顺序、连续 drain 和伪造 detached 记录拒绝。真实短门禁只覆盖此固定 UART 场景内两次低字节来源；通用寄存器复制、任意 Store、跨例 RAM 读回、P2/P3 完整动作与路径契约仍待验收。

前一份独立快照 `/home/qinkejiu/myfuzz_snapshot_p3_20261007` 运行旧 `UartRamCommitJoin` 也得到 4/4、27,031 事件、2 条受限低字节证书及完整 fresh replay；其清单 SHA-256 为 `63eaca28a3e9076025734842d7abebe86db74035996fe7082cffa627b6a44e85`。旧 join 的迟到 commit 生命周期缺口见[迁移审查](../../.superpowers/sdd/current-dataflow-p3-store-join-migration-review.md)，因此本报告以新的 StoreMemoryJoin 快照为当前门禁，旧结果仅保留作版本对照。P3 整阶段保持部分完成。
