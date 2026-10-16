# P7 candidate layout 修复独立复核 — fd0f49a

只读复核 `fd0f49a5e9f425ff5abc313aa60ea7f4ab0347eb` 的修复、测试源码及已有 RED/GREEN/receipt；本轮只运行文件 SHA-256 计算，没有重复测试或 pure-domain probes，没有 native/RTL/远端执行，也没有修改实现。

## 结论

上次中严重性 M1（空合法域未拒绝）与低项 total budget、JSON diagnostics 已在源码中修复；本轮未发现这些修复新增高/中严重性问题。此结论仅适用于纯候选布局模块，不授予生产 executor 接入或 P7 能力。

`_domain_nonempty` 检查的是 `minimum <= value <= maximum`、`value & ~mask == 0`、`value % alignment == 0` 的精确交集。零下界时 0 是合法见证；full 32-bit mask 使用首个 alignment 倍数；一般情况按 16+16 bits 拆分，低半按模余数分组排序，高半查互补余数并二分范围。每半最多 65,536 个 submask，避免 2^32 枚举。对通过前置 shape 检查的调用，alignment 为正、mask 在 32 bits 内，零/满 mask 快捷路径和高低半范围剪枝均成立。不存在以“范围内有倍数”代替 mask 交集的错误。

所有候选 slice 在 append 前执行该检查，空域以 `source-domain-empty` 和 `/sources/N` 拒绝，覆盖先前 `mask=1,range=[2,3]` 以及 `mask=3,range=[1,1],alignment=2` 的复现。

新增 `MAX_LAYOUT_SOURCES=64`（含 derived image）、`MAX_CANDIDATE_BITS=1024`，分别在 source 处理前和逐 slice 累计时拒绝。总 raw record 因而最多 128 bytes；最坏 source 数/交集检查次数有明确上限。digest payload 新增 schema 和两项预算，约束变更进入身份。最终 canonical JSON 将 TypeError/ValueError/RecursionError 转成 `CandidateLayoutError('declaration-json-invalid','/')`，修复上次列出的非法 JSON metadata 路径。

## 已有证据核对

当前四个文件 SHA 与 receipt 全部一致：

| 文件 | SHA-256 |
|---|---|
| compiled_candidate_layout.py | `bd5a794708cafbe9745c43a9ac35222b2a2a4e241d845cf7b0d20bdbed8fcb08` |
| test_compiled_candidate_layout.py | `00a4410a2e98507a3baeba27db0df6b04dc6a34e39c8a4450920750f89bbc60a` |
| red.log | `c6d77ae558181e1cafc23719f621a119294a126890a2a03a5f5ea09cf865bbe7` |
| green.log | `d8162e6fe2f44d753d855f02be927d544fb75461b4fb86422d68e5d2ec92f87c` |

日志实际记录 RED **9 failed, 16 passed in 16.40s**、GREEN **26 passed in 16.24s**；不是 25 个失败。receipt 的 exit codes 分别为 1/0，与日志一致。测试源码新增空域与 32-bit 非空边界、source/bit 预算边界、非法 JSON metadata、160 个固定随机小域与枚举参考的一致性、65536 submask 数量和快捷路径不枚举检查。GREEN 是已保存的实现者软件执行证据，本轮没有独立重跑；摘要一致证明当前文件与 receipt 记录对象相符，不是独立执行或签名证明。

## 剩余边界和阻断

没有剩余已确认的布局修复阻断。非零 physical bit_offset、更多稀疏 field mask 的回归仍可增强，但不据此推断当前代码错误。

生产 `CompiledF4Runtime.submit`/file entry 仍未消费新布局，typed D3真实性、runtime rule执行、physical ownership、writer arena权限/容量、seed decoder、通用 assertion/witness、覆盖反馈和失败 prefix绑定等仍由外层实现或保持拒绝。该模块本身明确不创建 live authority；不支持的 seed/register_field_constraints 仍拒绝。故这次软件修复通过审查不等于无适配新 CPU/IP、P7-D/E、coverage-guided search 或新增 native pass。
