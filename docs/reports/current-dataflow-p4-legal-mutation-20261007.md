# P4 合法 CPU 指令源变异：在线 XORI 子集

日期：2026-10-07

本文保留操作子软件实现时的范围；随后冻结源码的[真实 XORI 退休门禁](current-dataflow-p4-xori-retirement-real-gate-20261007.md)已补上 3 条精确取指来源与 RVFI 退休证据，P4 整阶段仍未验收。

## 范围与接入点

`OnlineCaseDecoder.decode()` 已经把所选 `instruction` 源的 payload 交给 `rv32i_sources.decode_instruction_fragment()`，然后把编码结果放进 `OnlineInstruction`。本次只扩充这条现有在线链的 RV32I 单字算术选择：原有 `ADDI` 选择中的寄存器字节高位为 1 时，生成 `XORI`；高位为 0 时仍生成 `ADDI`。寄存器号仍取该字节低 5 位，立即数仍按有符号 12 位解码。`Rv32iInstruction` 的构造、编码、`mutate_instruction` 和在线字节校验同时支持 XORI。MMIO 选择、窗口地址、读写权限和持久内存接纳逻辑未变。

这是一个有实际入口的 CPU 指令/操作数操作子。它不直接设置 CPU 计算结果，也不能绕过 `OnlineInstruction` 的地址预约与 `PersistentMemory` 的已取指、已物化及 Store 字节拒绝条件。

## 失败测试与边界

先增加 `tests/scenario/test_rv32i_xori_mutation.py`，执行 `PYTHONPATH=src pytest -q tests/scenario/test_rv32i_xori_mutation.py` 得到 3 失败、6 通过；失败来自原构造器拒绝 XORI。初版选择位曾取 payload 第 6 字节；真实在线 decoder 的输入上限是 8 字节且重复 5 字节 payload，使该位复制了偶数操作码选择字节。补入真实 `make_ibex_pulp_dual_source_online_decoder()` 的 8 字节入口测试后，得到 2 个预期失败，证明此版本在线不可达。选择位移至寄存器字节高位后，真实入口测试通过。

测试同时检查：XORI 的精确 RV32I 编码及在线校验、寄存器与立即数变异、ADDI 原分支、非法寄存器/rs2/立即数拒绝，以及不在首阶段子集内的 ORI 编码拒绝。在线测试遍历路径选择字节，找到声明的 CPU 源并核对其 `OnlineInstruction` 字节，因此不是只调用孤立的编码函数。

## 验证与限制

定向回归：`PYTHONPATH=src pytest -q tests/scenario/test_rv32i_xori_mutation.py tests/scenario/test_rv32i_mmio_permissions.py tests/scenario/test_online_path_first_selection.py tests/scenario/test_edge_aware_decoders.py tests/integration/test_scenario_online_credit.py`，44 项通过。另启动了 `tests/scenario` 全集；其执行耗时较长，在 122.94 秒时主动中断，已完成 373 项测试及 447 个 subtest，未见失败；这不构成全集通过的声明。

本次没有运行真实 RTL 门禁或 fresh replay，故只证明软件在线提案能生成并接受合法 XORI 字节，不声称 CPU 已退休该指令或传播到外设。当前候选身份尚无显式 operator 字段；在线 trace 只能从指令字节推导 XORI，不能满足 P4 对操作子采用/拒绝原因的完整记录要求。当前选择仅覆盖单字 XORI 与其操作数，不是指令插入/删除、协议字段 mask、全 ISA 或 P4 验收。对于 8 字节在线输入，只有选中 CPU `instruction` 源、算术 choice 为 2 且寄存器选择字节高位为 1，才会提议 XORI；源被路径权重选到 IP 环境输入时不会生成它。内存接纳失败仍由既有会话层拒绝。
