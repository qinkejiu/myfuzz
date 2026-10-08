# P3 readback writer 历史的有证据回收

日期：2026-10-07。`UartMemoryReadbackJoin` 的 `max_writer_versions=256` 原来只累积已认证的 UART→host RAM 低字节 writer；同一 RAM 字节连续改写超过 256 次会触发容量屏障。本次增加受限回收，仍不宣称真实 RTL 长跑完成。

## 可删条件

仅在 writer 容量将满时扫描历史。一个已认证的 writer 版本可删，须同时满足：

1. 实际安装 `MemoryReadAuthority` 所绑定的同一个 `MemoryService`/`PersistentMemory` 仍在位；当前 RAM 中该 `(memory_id, generation, byte_offset)` 的 cell 不再具有相同版本、writer ID、`STORE` 类型和值，或内存 generation 已变化。
2. `MemoryReadAuthority` 尚未交给 Runner 的 live 已发行 read 记录中，没有任何 lane0 精确引用该 writer 身份。
3. join 已收下、尚未由 CPU `lw` 退休消费的 read 记录中，也没有该精确引用。

因此，同值后写的不同版本不能代替旧版本；已发行 read 即使随后被覆盖，也保留旧 writer 直到退休。回收只删除不能再由本 join 出证的历史，不凭当前 RAM 值新建来源证明。安装对象丢失、待决 read 形状损坏或 distinct 当前/待决 writer 数超过容量时保守置 barrier，不静默驱逐。检查按需执行，正常每条事件无全表扫描。

## 软件门禁

新测试先因缺少 `_remember_writer` / `_reclaim_obsolete_writers` 而 RED。实现后运行：

```text
PYTHONPATH=src pytest -q tests/scenario/test_uart_readback_writer_history.py tests/scenario/test_uart_memory_readback.py tests/scenario/test_memory_read_authority.py
12 passed in 1.00s
```

测试用真实 `MemoryService.write` callback 周转同一地址 **300 个版本**，以已有完整软件证书为模板驱动历史缓存，确认容量不超过 256 且最新实际 cell 对应 writer 仍在。第二项在旧 read 已发行但尚未交付、以及已交付但 `lw` 未退休的两段窗口中覆盖同一字节：旧 writer 保留，退休 `lw` 仍精确读回旧版本，之后才可删除。第三项让三个不同地址的当前 writer 占用容量2，确认第三个不能借“回收”误删现存来源，join 显式降级。

模板周转测试测的是缓存安全与持续容量，不代表 300 次 UART 原始链或真实 RTL 已被认证。真正长会话仍需冻结源码的在线运行、全部 raw read/write/retirement 证据、源码/build 身份和 fresh replay。读发行必须走 opt-in 的 `MemoryReadAuthority`；未发行的 detached snapshot 不能获得 readback 证书，也不构成需要保留的证据。

## 新源码真实短回归

后续从 `/home/qinkejiu/myfuzz_snapshot_p4_xori_retire_20261007` 运行带 readback opt-in 的 Ibex＋OpenTitan UART：`--cpu-retirement --uart-fifo --memory-commit --memory-readback --seconds 20 --max-tests 4 --seed 43`，保存于 [在线材料](../../runs/current-dataflow-p3-readback-gc-20261007-online/)。运行退出码 0，4/4 complete、27,068 事件、4 条 host memory commit、2 条 Store 低字节证书、2 条真实 read 发行，以及 1 条 warmup UART 来源到第 3 例退休 `lw` 的读回证书 accepted。独立 cache 的完整 fresh replay 退出码 0，`matches=true`，事件与 local ticks 无差异。该快照的 [1,806 文件 SHA-256 清单](../../runs/current-dataflow-p4-xori-retire-snapshot-20261007.sha256)在运行及 replay 后均为 0 个差异。此短回归证明新回收代码没有破坏既有固定读回路径；只有 2 条 Store 证书，未实际触发 256 容量回收，不能当作真实长会话回收门禁。
