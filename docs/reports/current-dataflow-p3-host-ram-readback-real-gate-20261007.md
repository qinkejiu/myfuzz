# P3 UART 来源到后续 host RAM 低字节读回：真实短门禁

日期：2026-10-07。本门禁绑定独立源码快照 `/home/qinkejiu/myfuzz_snapshot_p3_readback_20261007`。该快照的 `src/`、`configs/`、`scripts/`、`schemas/`、`tests/` 共 1,804 个文件记录在 [SHA-256 清单](../../runs/current-dataflow-p3-readback-snapshot-20261007.sha256)，清单 SHA-256 为 `9d4b572fd40c691acf3ddc3af9d493a43cc948ea797a73a9e514c0d158c6a341`。运行后复核清单及在线身份中的 36 个源码文件，均为 0 个差异。

## 门禁与实际证据

在快照目录执行：

```text
/usr/bin/python3 scripts/run_ibex_uart_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p3-readback-20261007-cache \
  --output /home/qinkejiu/myfuzz/runs/current-dataflow-p3-readback-final-20261007-online \
  --seconds 20 --max-tests 4 --seed 43 \
  --run-id current-dataflow-p3-readback-final-20261007 \
  --cpu-retirement --uart-fifo --memory-commit --memory-readback
```

退出码 0，4/4 例 `complete`，真实搜索 15.826 秒。[最终 trace](../../runs/current-dataflow-p3-readback-final-20261007-online/online_final_trace.json)含 27,068 个事件、4 条 host `memory_write_commit`、2 条已接受的 `uart_store_memory_match`、2 条实际 host `memory_read_issuance`，以及 1 条 `uart_memory_readback` accepted；相关 incomplete/unknown 为 0。首次 ISR 读到初始镜像，不能构成 Store 读回。后一次 ISR 读取 `0x20000` 得到 `0x5a`，读发行的低字节 writer 版本为 `[0,6]`，与 warmup UART 来源经实际退休 Store、成功 host callback 的低字节 writer 证书一致。读回证书的 `source_case_id=uart-fixed-warmup`，`load_observed_case={case_id: online-2-6cc15f1f433a18955ac2a915, case_index: 3}`，证明这条**固定场景的跨逻辑例**读回。CPU 流的事务键仍以固定 stream testcase ID 命名，跨例关系由来源登记和 Runner 观察例上下文确定。

读回模式在实际 `MemoryService.read` 内取得快照和一次性私有 token，再由同一 data response 与认证退休 `lw` 连接；保存的 `memory_read_issuance` JSON 不能单独授权。受控 ISR 使用原有两个 NOP 槽位作 host RAM 读取，保持已验收 UART 状态读取、RDATA 读取和 `mret` 的固定 PC。受信 bootstrap 配置只接受两个精确构建镜像，replay 从已校验的 session manifest 选择读回模式。

隔离快照执行 `PYTHONPATH=src pytest -q tests/scenario/test_uart_memory_readback_integration.py tests/scenario/test_uart_memory_readback.py tests/scenario/test_memory_read_authority.py tests/scenario/test_uart_irq_controlled_entry.py tests/integration/test_ibex_uart_memory_commit_mode.py`，**62 passed**。测试覆盖实际服务发行顺序、私有 token、伪造事件拒绝、旧模式行为、受控镜像固定 PC、Store/Load 版本连接和迟到时序。

## 完整重放与范围

在同一快照内以独立 cache 执行：

```text
/usr/bin/python3 scripts/run_ibex_uart_online.py replay \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p3-readback-final-20261007-replay-cache \
  --plan /home/qinkejiu/myfuzz/runs/current-dataflow-p3-readback-final-20261007-online/online_plan.json \
  --trace /home/qinkejiu/myfuzz/runs/current-dataflow-p3-readback-final-20261007-online/online_final_trace.json
```

重放退出码 0，`matches=true`、`first_difference=null`、`difference_context=null`，覆盖完整事件和 local ticks。重放后再次核对快照清单，0 个文件不符。

本门禁只授予 OpenTitan UART RX 来源经受控 Ibex ISR、实际退休 `sw`、成功提交的**建模 host RAM 低字节**到下一次退休 `lw` 的受限来源连接。证书明确 `influenced_bits=[0,8]`；高 24 位、RTL 内 RAM、一般寄存器复制/ISR、任意操作子、通用跨例依赖及长会话容量仍未通过 P2/P3 整阶段验收。
