# P4 在线指令片段插入与删除：软件门禁

日期：2026-10-07。`rv32i_sources.decode_instruction_fragment` 现允许 RFuzz 算术选项在**尚未提交的候选片段**内编辑两字基序列 `LUI rd; ADDI rd,rd,imm12`：熵字节 6 的高两位选择原序列、删除可选 `ADDI`，或在两字之间插入 `XORI rd,rd,imm12`。原有单字算术选择在高两位为零时保持原行为。三个候选最终长度分别为 8、4、12 字节，均通过已有 RV32I 字节校验；该操作不生成 MMIO 访问，因此不绕开既有目标窗口和权限校验。

在线解码器原有逻辑使用最终编码字节数校验未来保留区边界，提交成功后按该长度推进游标；最后只剩一字时，过长候选降为合法 NOP。`PersistentMemory.accept_instructions` 对整段保留字原子检查：目标第三字若已由较早的指令接纳并取指，或由真实 Store 决定，插入候选整段拒绝，内存状态摘要不变。因此这里的插入与删除不搬移、不改写已经确定的历史指令字节。

TDD 先新增 `tests/scenario/test_rv32i_sequence_edit.py`，四项原始检查在未实现时按预期失败（基序列仍只有一字、在线片段仍一字、边界未回退、占用的第三字未被触及）。实现后定向组合：

```text
PYTHONPATH=src:. /usr/bin/python3 -m pytest -q \
  tests/scenario/test_rv32i_sequence_edit.py \
  tests/scenario/test_rv32i_xori_mutation.py \
  tests/scenario/test_rv32i_mmio_permissions.py \
  tests/scenario/test_memory_service.py \
  tests/scenario/test_online_path_first_selection.py
49 passed, 3 subtests passed in 0.25s
```

这只证明软件语义、长度和原子拒绝。尚需由主任务在冻结源码后运行真实 Ibex＋双 GPIO 在线短门禁，并做完整 fresh replay，审计三字插入与一字删除都曾被在线 RFuzz 选择、实际取指和退休。当前不据此判定 P4 整阶段完成。
