# BOOM IRQ 设计独立只读审查 — 1f406b9

复核设计 `.superpowers/sdd/boom-irq-next-design.md`、已物化 BoomTile/CSR RTL、PULP GPIO RTL、IrqPulseDelivery 和 Runner 相关接缝。只读源码，没有构造、测试、elaboration/build、native 或远端执行；不评估未运行软件为已测，也不把尚未实现视为设计缺陷。

## 实质问题

**中：MRET 观察合同需要精确资格，泛 system-return 不能独立证明 MRET。** 设计正确要求实际 system-return 加前景恢复 marker，但候选 probes 只列 CSR trap/state 和 ROB exception，未将 system-return 的具体 MRET 译码输入/资格纳入明确合同。真实 `CSRFile.insn_ret` 是 `system_insn & _T_246`，包含多种返回（SRET/MRET/DRET）；单独 insn_ret/io_eret 不能区分 MRET。应在新 probe 合同要求 `io_rw_cmd==3'h4` 且 `io_rw_addr==12'h302` 的实际合法 system 操作，或等价精确 qualified MRET decode，捕获前后 privilege/MIE/MPIE 与返回 PC，再结合已实际执行的 resumed RAM store。原始 32-bit MRET code/取指仅是候选来源，不自动等于指令已执行。此项可在当前 opt-in 实现的 probe/checker 合同内补齐，不需要放弃方案。

没有发现 MEIP接线、真实GPIO脉冲→64 tick交付 或 direct machine trap 的设计级阻断。

## 可行性核对

MEIP 真实链成立：BoomTile.auto_int_local_in_2_0→intXbar_auto_int_in_2_0→IntXbar_1.out3→core_io_interrupts_meip→BoomCore.io_interrupts_meip→csr_io_interrupts_meip→CSRFile.io_interrupts_meip→read_mip bit11。该结论来自逐段赋值/实例连接；不是名字猜测。设计对 BoomTile 输入的一个行号有轻微偏移（当前源码在303208而非303209），不影响角色结论。默认profile常量0和driver硬驱动0确实是当前禁用点；总端口未漏采。

PULP GPIO `interrupt = |(INTEN & GPIOEN & edge_detection)`，独立于 sticky r_status；r_status事件优先、读INTSTATUS清除。GPIOEN+4、INTEN+0x18、INTTYPE+0x1c、INTSTATUS+0x24及01 rising配置符合源码。不能把此pulse声明改成level保持型，也不能用host读status轮询生成假中断。设计对此区分正确。

`IrqPulseDelivery.observe_source` 在真实source上升沿发生时设 start=当前CPUtick+1、end=start+width，`input_at`在半开区间保持高。因此 width64是明确的CPU本地64步，不是64个GPIO步或全局cycle；源下降不会取消交付。占用窗口内第二上升沿标 unsupported_irq_overrun，不替换/延长原pulse；reset取消pending。Runner逐CPU步使用next-local-tick采样并在完成后调用sample_cpu，现有机制与设计所述相符。实现时应保留完整64个映射pin样本/过期边界，即使实际trap更早发生；不能因ISR预测提前结束pulse。64只是一项待验证固定参数，不提供BOOM最坏trap latency保证。

CSR pending通知与precise trap必须分层。真实 CSR io_interrupt 来自pending/mie/global MIE逻辑；ROB com_xcpt_valid/cause延迟一级进入CSR exception/cause，CSR trap时更新mepc/mcause/MIE及vector。每个probe需明确pre/post和RTL register延迟，不用同一tick粗略相等硬拼链。设计已明确不把通知当take。若将来复用 Runner `irq_taken_pre`，必须保证它的具体边沿对应实际precise interrupt exception；因为 IrqPulseDelivery只在交付pin为1时记录cpu_irq_taken，发生在交付窗口结束后的已锁存trap不能被硬改为同tick“接受”。首期使用独立observation-only ROB/CSR事件更稳妥。

固件策略可行：显式关MIE、写mie/mideleg/mtvec、真实CPU配置GPIO并清旧status；由CSR与真实ready store允许唯一pin边沿；ISR保存cause/mepc，清MEIE后读取status1/0，再MRET，不给mepc+4。清MEIE避免固定窗口在MRET恢复MIE后再次触发。同一0x4024 word处于64-bit拍高半，Get mask0xf0，既有external word合同可保留。RAM SD与外设LW宽度分开；0x8000xxxx地址需RV64零扩展。ISR/main所用寄存器和程序范围必须在实现中保持一致，但设计未规定具体寄存器分配不构成错误。

## 身份与回归要求

独立opt-in profile/schema/output和新模板/probe闭包是必要边界。只增加MEIP输入使用及被动可见性时，可保留原RTL bytes/source union与47端口捕获；profile/driver/generator/Python/probe config/build/executable identity必须更新。若导出新wrapper端口或改RTL，须更新source/top/物理捕获，不能继续声称原revision。Verilator public-read配置/生成成员/宽度/实例唯一性仍需实际build核对，当前设计没有伪造其已可访问。

新增IRQ endpoint后，canonical bus认证需按精确endpoint_id选择并完整验证39字段和独占MEIP驱动；旧单endpoint校验不可直接放宽。非法STEP_IRQ类型/宽度/epoch须在发命令或边沿前拒绝；bound ownership不可被随机源覆盖。旧GPIO和新persistent C/E结果只覆盖其冻结身份；共享认证/transport/driver改变后，需要在新共同源码身份下做相应源码回归、GPIO正负对照和C/E supplement。历史证据保留，不能覆盖后借其摘要授新IRQ binary通过。

## 验证与证据边界

设计列出的真实边沿、INTEN/GPIOEN gating、MEIE/globalMIE gating、environment suppression、改/抑制实际status响应、错vector/同步异常及overrun/reset控制，覆盖了主要因果替代。每个负例必须保留实际源、映射pin、trap/CSR/APB/RAM原始观测并核对“没有无关transport/checker失败”；不能仅用positive predicate=false记控制通过。

首轮可授范围仅是单事件、固定pulse delivery、实际MEI precise trap、ISR状态读/清除与MRET恢复的定向链。没有hardware-origin token，因此source edge→trap是受限单源历史相关，不是通用IRQ来源权威；无RVFI retirement、通用ISR/F5/fullP6或在线搜索授级。未native运行的当前variant必须继续标未验证。

结论：方案总体可实施；需把精确MRET资格写进probe/checker必需合同，并在后续授权build/运行中验证时序和身份。没有把本轮只读结论当native pass。
