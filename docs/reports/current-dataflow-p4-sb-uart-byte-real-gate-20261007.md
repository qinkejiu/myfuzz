# P4 静态 UART WDATA 字节写：真实退休与目标输出短门禁

> **⚠ 复算可用性（2026-10-09 更新）**：本文引用的部分原始产物目录在 2026-10-09 的 `runs/` 清理中被删除，因此文中指向 `runs/` 的链接可能失效。**报告的结论、数字与边界仍然有效**（记录的是当时真实执行的结果），但"从原始产物复算"的能力已不存在。删除范围、已重建项与逐条断链清单见 [已删除的原始产物](DELETED_ARTIFACTS_20261009.md)。
日期：2026-10-07。范围为 Ibex RVFI + OpenTitan UART TL-UL 的 `WDATA` 低字节，受信地址 `0x4000001c`。UART RTL 的 `UART_WDATA_OFFSET=0x1c`，`UART_PERMIT[7]=4'b0001`，目标寄存器取 `reg_wdata[7:0]`。因此 opt-in `SB` 的静态窗口收窄为这一字节；普通 `SW` 仍使用原有 4 字节窗口。泛用选址对该 `SB` 窗口只能产生 `0x4000001c`。目标会话的 CPU 路由仅允许这个 offset 的 `be=1`，其他寄存器和其他字节 strobe 维持原有拒绝。

## 测试和首次失败

先增测试再修改：窗口测试以 `1 != 4` 失败；两项目标会话测试分别以 `unsupported UART register write` 和 `invalid routed UART register shape` 失败。修正后在最终冻结源码执行：

```text
PYTHONPATH=src:. pytest -q tests/local_harness/test_opentitan_uart_byte_write_gate.py tests/integration/test_ibex_uart_online_pilot.py tests/scenario/test_rv32i_mmio_permissions.py
23 passed in 0.18s
```

既有 `test_opentitan_uart_routed_identity.py` 在主工作树另得 `2 passed, 11 subtests passed`。首次冻结真实运行只有 2 例 complete、第 3 例 `rv32i:LUI+ADDI+LUI+SB` 为 `uncertain_effect`，错误精确为 `ValueError: invalid routed UART register shape`；该失败不算通过，保留在[首次日志](../../runs/current-dataflow-p4-sb-run-20261007.log)和[首次回执](../../runs/current-dataflow-p4-sb-online-20261007/receipts.jsonl)。

## 最终冻结身份和真实门禁

最终快照 `/home/qinkejiu/myfuzz_snapshot_p4_sb_20261007` 的 `src/`、`configs/`、`scripts/`、`schemas/`、`tests/` 共 1,850 个文件列于[SHA-256 清单](../../runs/current-dataflow-p4-sb-final-snapshot-20261007.sha256)，清单 SHA-256 为 `307decb5dc5a4c8d5bb9746a128fcac3a8df079af8058e01175f7c36ede73306`。在线身份中 37 个 `source_files` 与快照逐项一致；真实运行和 replay 后清单校验均退出 0。第三方 Ibex/UART RTL 随快照复制，实际组件源码身份还保存在在线 identity 和 source lock 中。

从该快照执行：

```text
/usr/bin/python3 scripts/run_ibex_uart_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p4-sb-final-cache-20261007 \
  --output /home/qinkejiu/myfuzz/runs/current-dataflow-p4-sb-final-online-20261007 \
  --seconds 30 --max-tests 40 --seed 20261007 \
  --run-id current-dataflow-p4-sb-final-20261007 \
  --cpu-retirement --uart-fifo --uart-wdata-byte-store
```

[运行日志](../../runs/current-dataflow-p4-sb-final-run-20261007.log)退出 0，9/9 例 complete，有效搜索 35.236 秒；[完整 trace](../../runs/current-dataflow-p4-sb-final-online-20261007/online_final_trace.json)有 63,830 事件，SHA-256 `d1b2ed9cae4e4f020a53e321277cc738752a2d6c1cf4814de194d8aa06090dab`。在线第 3 例回执的 `flow_id=F4`、源 `cpu.online_instruction`、操作子 `rv32i:LUI+ADDI+LUI+SB`、`candidate_disposition=admitted`，原始 record 为 `000000c30c0106b0`，action ID 为 `online-2-604caae5c07e4c776cb357d1:cpu.online_instruction`。

独立从原始事件复核：唯一 `SB` 的 Ibex RVFI 退休 `order=164`、PC `0x11020`、指令 `0x00208e23`、`mem_addr=0x4000001c`、`mem_wmask=1`、`mem_wdata=0x0c`；`cpu_retirement_match` 事件 25189 为 `accepted/matched_ordered_retired_transaction`，冻结取指响应事件 25098 的来源精确指向上述 action ID。匹配器记录的真实数据 beat 是 `address=0x4000001c, be=1, wdata=0x0c`，其事务 key 与目标 `mmio_delivery` 事件 25150 完全一致；投递 `offset=0x1c, byte_enable=1, write_value=0x0c`。随后 UART 实际串口观测 `serial_tx_count=1, serial_tx_last=0x0c`，首次见于事件 28002；全 trace 只有这一条 WDATA 写入。

同一快照、独立 cache 执行完整 fresh replay：

```text
/usr/bin/python3 scripts/run_ibex_uart_online.py replay \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p4-sb-final-replay-cache-20261007 \
  --plan /home/qinkejiu/myfuzz/runs/current-dataflow-p4-sb-final-online-20261007/online_plan.json \
  --trace /home/qinkejiu/myfuzz/runs/current-dataflow-p4-sb-final-online-20261007/online_final_trace.json
```

[重放日志](../../runs/current-dataflow-p4-sb-final-replay-20261007.log)退出 0，`matches=true`、`first_difference=null`、`difference_context=null`，比较完整前缀的事件和 local ticks。

## 边界

这是一条 opt-in、单地址、单 `SB` 候选的真实短门禁；串口字节输出提供目标 RTL 的外部可见结果，但没有给每个 TX FIFO 内部状态单独建立来源 token。它不证明其他 OpenTitan UART 寄存器、非 lane 0 字节、其他 IP 或多候选长期搜索，也不提升 P4 整阶段验收状态。原有 `rv32i_sources.py` 宽度/对齐筛选和 `mutation.py` 来源所有权机制沿用，未为本门禁扩大其授权范围。
