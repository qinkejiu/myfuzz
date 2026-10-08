# P3 在线长会话的整批超时缺口与逐 slot 截止修复

> **⚠ 复算可用性（2026-10-09 更新）**：本文引用的部分原始产物目录在 2026-10-09 的 `runs/` 清理中被删除，因此文中指向 `runs/` 的链接可能失效。**报告的结论、数字与边界仍然有效**（记录的是当时真实执行的结果），但"从原始产物复算"的能力已不存在。删除范围、已重建项与逐条断链清单见 [已删除的原始产物](DELETED_ARTIFACTS_20261009.md)。
日期：2026-10-07。为验证 UART readback 历史在长会话中越过 256 writer 容量，以旧冻结源码启动 `--seconds 180 --max-tests 800 --cpu-retirement --uart-fifo --memory-commit --memory-readback`。实际第 1 个 RFuzz buffer 含 seed，下一 buffer 持续接纳多个 slot；原截止检查仅在整个 `process_owned_pair()` 返回后执行。运行到 82 条 `complete` 回执时，有效搜索已达 652.118 秒，显著超过 180 秒。进程内存约 4 GB，因预算失控由主控发 SIGINT。保存了 585,655 事件、约 1.9 GB JSONL 和失败身份；[原运行报告](../../runs/current-dataflow-p3-long-20261007-online/report.json)明确为 `execution_status=failed`、`session_status=uncertain_effect`，不能当作长会话容量或 replay 验收。该次前缀包含 82 条完成回执，但没有成功终结的完整搜索门禁。

只读流式审计该失败 trace：82 条 `memory_write_commit`、3,370 条 `memory_read`（完整 TransactionKey 全部唯一）、49,572 条 `memory_read_issuance`（仅 41 个完整 TransactionKey）、25 条 accepted 和 1 条 incomplete 的 `uart_store_memory_match`、24 条 accepted `uart_memory_readback`。**49,572 条 issuance 并非 49,572 次实际 MemoryService.read**；其中 49,531 条是未消费的同一批 token 被重复 drain 后记录。它未达到 256 writer 周转门槛；这些计数不提升失败运行的验收等级。

进一步逐条检查同一失败 trace：49,572 条 read issuance 全在 RAM 地址 `0x20000`，只关联 41 个低字节 writer ID；49,571 条快照的低字节 writer kind 已经是 `STORE`，另 1 条是 `INITIAL_IMAGE`。其中 6,221 条引用了本次 25 张 accepted UART Store 证书的 writer ID。这些是重复日志的分布，不能据其推断真实读请求频率。按 `STORE` 类型过滤几乎没有收益；按当时已认证的 writer 过滤则可能漏掉随后才完成认证的同轮读取。曾在本地尝试前一种过滤，定向测试通过，但因这项原始 trace 审计否定收益，已完整撤回。尝试在独立副本运行真实 RTL 时，启动预检报 `git-content-mismatch:rtl/ibex_alu.sv`，没有执行 testcase，也不形成新门禁。后续[重复发行与指令版本容量分析](current-dataflow-p3-read-issuance-capacity-20261007.md)给出具体触发链和新短门禁。

根因不是 `max_tests` 计数，而是单个 buffer 内的 slot 循环不查看已开始的有效搜索时间。新增逐 slot 检查：第一条回执完成后计时，后续 slot 在接纳前若达到时长就返回中性覆盖、不再推进 RTL，并设置独立 `duration_budget` 停止原因。已提交 slot 不在中途抢断；因此一次进行中的真实 RTL testcase 可以使有效时间略超预算。重复收到跳过的同一 buffer/slot 只返回缓存的中性覆盖，不重复执行。

测试先以三 slot 的同一 buffer 复现失败（预期只执行第 1 条，旧实现实际执行 3 条）；修复后聚焦回归 `PYTHONPATH=src:. pytest -q tests/integration/test_scenario_rfuzz_terminal_identity.py tests/scenario/test_online_path_first_selection.py tests/scenario/test_online_real_flow_mapping.py tests/integration/test_scenario_online_credit.py` 为 **47 passed、2 subtests passed**。

## 冻结源码真实 RTL 截止门禁

新快照 `/home/qinkejiu/myfuzz_snapshot_p3_deadline_20261007` 的 2,751 个核心文件见 [SHA-256 清单](../../runs/current-dataflow-p3-deadline-snapshot-20261007.sha256)，清单哈希 `b5d623b84a7151b1561cf472c8b02c1abe6d337fb33bf425255db24925cb1063`；运行及重放后清单复核零差异。

```bash
cd /home/qinkejiu/myfuzz_snapshot_p3_deadline_20261007
PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_ibex_uart_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p3-deadline-cache \
  --output /home/qinkejiu/myfuzz/runs/current-dataflow-p3-deadline-online \
  --seconds 12 --max-tests 800 --seed 43 \
  --run-id current-dataflow-p3-deadline-20261007 \
  --cpu-retirement --uart-fifo --memory-commit --memory-readback
```

退出码 0，3/3 `complete`、36,669 事件；有效搜索 14.307 秒，终结 6.633 秒，`client_returncode=0`。同一输入传输可提供远多于 3 个 slot，但达到截止后没有继续产生接纳回执。以独立 replay cache 对保存的 `online_plan.json` 和 `online_final_trace.json` 完整 fresh replay，退出码 0，`matches=true`、`first_difference=null`、`difference_context=null`。

本门禁验证了时间预算在多 slot buffer 内生效及保存前缀可重放；它只有 3 例，**未验证** 256 writer 容量周转、长期 UART 来源连接或 P3 整阶段。原 82 例中断记录只用于定位截止缺口和终结开销，不转换为成功验收。
