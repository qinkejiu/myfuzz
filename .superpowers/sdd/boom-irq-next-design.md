# BOOM IRQ→trap→ISR：只读源码结论与下一分支设计

状态：设计待 root 审查。仅阅读本地已物化 RTL、profile、driver、固件与计划；未运行构造器、生成器、测试、elaboration、native 或远端命令，未占 heavy lock，未改实现。当前已通过的 GPIO/C/E 源码和原始证据保持冻结；本设计不授予 IRQ/F5/P6 通过。

## 1. 结论：中断入口真实存在，47 端口没有漏采

本文 `RTL` 指 `configs/cpus/boom/generated/chipyard.TestHarness.SmallBoomConfig.top.v`。

| 原始 BoomTile 输入 | 实际语义，由接线证明 | 证据位置 |
|---|---|---|
| auto_int_local_in_0_0 | debug | RTL:180494、305534 |
| auto_int_local_in_1_0 | machine software (msip) | RTL:180495、305536 |
| auto_int_local_in_1_1 | machine timer (mtip) | RTL:180496、305535 |
| **auto_int_local_in_2_0** | **machine external (meip)** | **RTL:180497、305537** |
| auto_int_local_in_3_0 | supervisor external (seip) | RTL:180498、305538 |

完整 MEIP 传递链：

1. RTL:303209 声明 BoomTile 的 `input auto_int_local_in_2_0`。
2. RTL:305384 接入 `intXbar_auto_int_in_2_0`。
3. `IntXbar_1` RTL:180482–180498，特别是180497，将该输入接至 out3。
4. RTL:305537 将 out3 接 `core_io_interrupts_meip`；304610 接入 BoomCore 实例。
5. RTL:285071 接 `csr_io_interrupts_meip`；284168 接 CSRFile 中断输入。

这是逐段 RTL 接线，不是由端口名字推测。物理捕获 `configs/cpus/boom/evidence/derived-20261017/physical_ports.json:1454` 同样记录 MEIP 输入及1位宽。47个端口=39个总线字段+clock/reset+5个中断输入+hartid。

当前禁用点是声明和驱动：`configs/cpus/boom/component_profile.json:299–303` 将 MEIP 作为 constant0 port_action，另外四路也均 constant0；没有 CPU irq_entry 声明。`src/myfuzz/local_harness/boom_cpu_driver.cpp:20–21` 硬驱动五路0。`boom_scenario_session.py:202–207` 拒绝任何 step 输入，实际调用 `native.step_local({})`。当前 GPIO 固件 `boom_gpio_example.py:39–54` 仅 SW/fence/LW/branch/result，不配置 trap CSRs。因此不能从已有 GPIO pass 推出 IRQ 可用。

## 2. CSR/精确 trap 的实际可行性

- `CSRFile` 声明在 RTL:278825，实例层次为 `BoomTile.core`（304603）及 `BoomCore.csr`（284161）。
- RTL:279255 将实际 meip 输入放入 read_mip bit11；279258 是 `pending_interrupts = read_mip & reg_mie`。
- RTL:279263 的 machine 中断受 privilege/global MIE 门控；280031 才是实际 CSR 中断通知输出，280032 给出 RV64 MSB=1 的 cause。只有使能 MEIP 且其它源为0时，候选 cause 是 `0x800000000000000b`。
- RTL:280094 将初始 privilege 置 machine(3)；280214 将 global MIE 置0；280606 将 mtvec 置0。不能依赖 mie 的模拟默认值，固件应显式写 mie。
- RTL:279428–279442 展示 CSR 地址 mask/decode；280565–280567 展示 mie 写路径。固件使用静态受信的 mstatus(0x300)、mie(0x304)、mtvec(0x305)、mepc(0x341)、mcause(0x342)，不开放任意 CSR fuzzer 输入。
- RTL:279375–279379 将 mtvec 作为32位地址零扩展；279601–279609 形成真实 trap vector；280029 输出 evec，285175 送入实际 IFU redirect 寄存器。
- **不能把 `csr_io_interrupt` 通知当作已 trap。** RTL:285204/285207 将 ROB 的 `com_xcpt_valid/cause` 延迟一级送 CSR；285078/285080 才接 CSR exception/cause。CSR 的机器 trap 状态更新见279631–279636、280587–280597。需记录 ROB trap 与 CSR trap/update 的各自实际边沿。
- RTL:279085–279096 与279667–279683 实现 system return、返回 PC/privilege/MIE 恢复。MRET 的证明应包含真实 CSR system-return 观察与返回后主程序的 RAM 标记，不能仅靠 ISR 中的成功常量。

以上证明硬件路径存在；尚未证明某个 IRQ 时序/固件在 native 中运行成功。

## 3. PULP GPIO 是脉冲源，不能伪装电平

真实 `third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv`：

- 125–133：同步输入变化与 INTTYPE 解码，01 为 rising。
- 138：INTEN 与 GPIOEN 同时门控真实事件。
- 141–143：`interrupt = s_rise_int`，**不是** r_status 的 OR。
- 151–162：r_status 累积事件；读 INTSTATUS(0x24)清除，且新事件优先。
- 寄存器定义：GPIOEN0x04、INTEN0x18、INTTYPE0x1c、INTSTATUS0x24。均由 CPU 真实 MMIO 写/读，主机不得代写寄存器或结果。

现有 causal profile 已明确这些语义与“不可接第一阶段 level-only controller”的限制（profile:276–290）。不改变它为假的 held-level 声明。`gpio_session.py:345` 的 irq 别名来自实际 interrupt，物理 pre/post tick 已由标准 Runner 采集，含 routed access 中的中间 tick。

## 4. 方案选择

1. **直接真实脉冲绑定**：最少机制；独立 GPIO/CPU 时钟调度可能只让 CPU 看到很短高电平，BOOM 的通知/ROB trap 延迟尚未实测。可做后续对照，不把失败解释成 IRQ 不存在。
2. **推荐：实际 GPIO 边沿→声明的有界 CPU pulse delivery→MEIP**：复用 `IrqPulseDelivery`，一条真实上升沿产生固定64个 CPU tick 的通知；宽度是明确受信交付规则，必须记录原始脉冲与映射脉冲、边界和源事件身份。重叠/overrun 拒绝，不续长、不轮询寄存器制造 IRQ、不按预测 ISR 调整宽度。64是首个待实测种子，不是已验证保证。
3. **把 r_status 重造为 held-level 或加入 PLIC**：会改变现有源语义/扩大硬件组合。当前最小设计不选，不能用 scheduler 假 IRQ 代替。

计划依据：当前实现计划 F5表(81)、Fuzzable/Bound约束(65)和P6(313–337)要求真实 IRQ→CPU handler、真实状态消费；允许声明脉冲交付规则，不允许由软件预测 ISR 或模拟 PLIC。首轮仅一真实 GPIO 事件/一 pending IRQ，不声称硬件来源 serial token 或多 IRQ 精确归因。

## 5. 最小实际执行链与固件

```text
CPU 配置 GPIO/CSR → 真实 boot-ready → 合法外部 pin0 0→1
  → GPIO 同步/真实 rising IRQ 与 status=1
  → 声明 pulse delivery → 实际 BoomTile MEIP pin
  → ROB interrupt exception → CSR trap/cause/vector
  → CPU 执行 ISR / 真实读取 GPIO INTSTATUS
  → 读响应经原 DataflowRouter/TileLink D 返回 CPU
  → CPU 保存 cause/mepc/status/clear-read 到原生 RAM
  → 实际 MRET → 主程序返回后标记
```

- 保留 reset ROM0x10040 stub；代码从0x80000000启动，ISR例如0x80000400(4字节对齐)。构造0x8000xxxx地址继续显式 RV64 zero extension，mtvec用 direct 模式。
- 初始清 MIE；显式写 mie/mideleg0、mtvec。CPU 写 GPIOEN bit0、INTEN bit0、INTTYPE01，其它位确定0；不用主机写。清理旧 status 只能由 CPU 的已记录读完成。
- 固件显式设置 mie.MEIE bit11 与 mstatus.MIE bit3；以实际 CSR 被动观察确认准备好，再允许外部 pin action。ready RAM marker 也由 CPU 实际 store，不能单靠预装常量触发。
- 主程序仅等待 handler RAM flag；不得自己轮询 INTSTATUS 并伪充 ISR。handler只保存已实际读的值；其 CSR/read/store 原始链必须保留。
- ISR 先读 mcause/mepc；清 mie.MEIE，避免固定通知窗口在 MRET 后造成重复 trap；真实 LW 0x4024读 status，应得1，再读应得0（无第二个外部边沿）。0x4024 位于64位拍的高32位，A.mask=0xf0，保留现有严格 lane/size 检查。
- 建议 native RAM：0x3010保存64位mcause、0x3018保存mepc、0x3020/24保存首次/清后status、0x3028保存handler_done、0x302c由返回后主程序保存resumed。RAM不预装期望结果。SD在原生RAM可用；外设仍只准完整32位word访问。
- MRET不应把中断 mepc加4；记录真实被中断前景PC和返回观察，主程序地址范围与 handler 范围不重叠。错误cause进入独立失败路径，不能把任意异常当外部IRQ。

## 6. 必要扩展与身份边界

推荐新 opt-in IRQ profile/artifact版本及独立输出目录，先不改冻结v1。实现分支需显式审查复用边界：

- profile/interface：新增 processor.interrupts / machine_external alias=auto_int_local_in_2_0、方向input宽1，删除该端口 constant action；其余四中断+hartid仍确定0。声明 cpu irq_entry 与 machine-external 语义；GPIO仍是原真实脉冲源，不改其RTL。
- generator：现有 `tilelink_coherent_cpu_session.generate` 写死配置、`endpoint, = endpoints`，仅准39条 bus字段。新版本须按 endpoint_id选总线，独立核对精确 MEIP端口和独占驱动；不能令双endpoint静默通过旧校验。只改profile/driver/观察配置时，四文件 RTL union revision 与原47物理端口捕获可保持不变，**profile/driver/build/executable/probe closure哈希必须更新**。
- native driver/session：新增有版本的 STEP_IRQ(1bit)，在低电平 eval 之前驱动该真实 input，逐边沿回执记录实际 pin值和前后观察。保留严格单测量边沿、A/C/D/E、D保持、源身份与timeout。非法类型/宽度在命令/边沿前拒绝。不能复用旧6f47... executable的 IRQ通过结论。
- 旧 native constructor硬钉 profile/生成器/模板hash。不要给旧artifact偷偷换字段或修改其manifest冒充旧成功；新IRQ构建需独立 schema/模板与源闭包。若提取共享认证/transport核心，必须承认其Python身份变更并重建/重验对应版本；冻结历史快照仍留存。
- **被动 trap probes 必须列入新构建闭包**：候选真实层次 `BoomTile.core.csr` 的 io_exception/io_cause/io_pc/io_evec、reg_mcause/reg_mepc/reg_mtvec/reg_mie/reg_mstatus_mie/reg_mstatus_prv，以及core的 ROB com_xcpt_valid/cause。优先专用 Verilator public-read 配置保存少量真实net，C++仅观察；该配置和生成符号/宽度/实例唯一性必须在新的 elaboration/build实测中核对。当前尚未验证具体public配置语法/生成C++成员名，不猜测可访问性、不给优化掉的信号补0。若必须新增RTL wrapper/export，source union/top/物理捕获均要重新钉定，不能沿用原revision。
- Runner adapter接受唯一 bound irq bit；factory用标准 Binding(gpio.irq→cpu.irq)、Ownership及声明 pulse policy，不加 BOOM 名字分支。每个被动观察必须对应真实 receipt/tick；notification、ROB precise exception、CSR trap commit、ISR读取和mret各自分开，不把CSR pending命名为take。
- `irq_taken_pre`等通用输出是否复用，应在review里确认实际take定义。建议先用专有 observation-only trap事件，避免把现有 Ibex native-IRQ authority/serial 合同借给BOOM。cause/RAM可构成受限单源架构证据；不等于来源权威、RVFI retirement或generic ISR验收。

## 7. 验证与负例（全部待实施/运行）

纯合同：variant移除精确MEIP常量且无双驱动；另四输入不受随机源控制；错alias/宽度/probe实例/哈希拒绝；双endpoint仍完整39bus映射；irq bool/越界/stale epoch在时钟前拒绝；pulse过期/overrun/reset身份及queued MMIO取消；lane0xf0与status offset验证先于target effect。

实际门（新的 heavy lock窗口）：

1. 两次新进程相同输入；记录完整每edge pin、原GPIO IRQ与status、映射交付、真实ROB/CSR trap/cause/vector、ISR source-keyed APB A/D及RAM stores、MRET/前景恢复。保持原始UUID/PID/退出码，只按明确声明scope比较完整fresh前缀。
2. 无外部边沿：GPIO无IRQ、CPU无对应trap/ISR/result；正常正例门必须拒绝。
3. GPIO INTEN=0 或 GPIOEN=0：外部pin变但实际IRQ不产生；不得自行补IRQ。
4. mie.MEIE=0 或 global MIE=0：实际源脉冲及 pin样本可存在，但不能凭通知宣称handler已运行；RAM完成门拒绝，masked观察来自真实CSR。
5. 在实际IRQ交付边做环境 suppression：GPIO真实IRQ/status保留，CPU输入为0；正例拒绝。这是明确环境控制，不是自然DUT bug。
6. 实际target首次status=1后，将真正读响应改交付0或抑制D；保留真实APB原回执，CPU分支/RAM应变化或等待，不能接受任意异常为因果控制通过。
7. 错mtvec/同步exception对照：即使发生trap，也必须因cause非MEI/ISR范围/结果不匹配而拒绝。
8. 一窗口二边沿产生overrun，应明确unsupported，而不是归给同一次ISR；reset中止pending脉冲/回调后不得把旧token交给新epoch。旧GPIO/C/E门在新实现身份下补必要回归，历史证据不被覆盖。

首轮通过仅登记“定向真实 GPIO IRQ→BOOM machine trap→ISR status→RAM→return”，仍保留P6双侧变异/交互反馈/持续会话、硬件来源token及全协议/通用接入缺口。

## 8. 待 root 决策

推荐批准：独立 IRQ variant/artifact + 标准64tick真实边沿映射 + 最少被动 ROB/CSR probes + 单事件定向固件。先核对 passive probe可访问性和新身份，再实现；直接短脉冲作为对照。当前不修改任何已通过实现，也不启动native。
