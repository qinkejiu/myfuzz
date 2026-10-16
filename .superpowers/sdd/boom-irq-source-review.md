# BOOM opt-in IRQ source 独立审查 — d326c5c

只读复核d326c5c、已审设计1f406b9、implementation report、新profile/generator/driver/session/adapter/factory/firmware及15项新测试源码。未运行测试、构造器、generator、elaboration/build、native或远端任务，未改实现。31passed/11.05s是实现者软件记录，不是本轮复测或ISR通过。

## 中项

**Builder的独立输出保护不完整。** `build_boom_irq_session`只检查output/session-artifact.json。原one-shot输出使用artifact.json，没有该marker；existing IRQ output则有irq-session-artifact.json，同样未被拒绝。随后generate_irq先调用baseline generate，在同目录覆盖driver.cpp、tl_ram.h、RTL与artifact.json，再替换IRQ driver/build产物。因此API可覆盖冻结one-shot或已有IRQ证据，和“独立目录、拒baseline artifacts”的报告承诺不符。建议要求新/空output（或明确拒绝所有既有artifact/证据markers）后再写文件。准备build.sh指定独立路径降低误用概率，但不修复builder本身。已同步owner/root。

## 源级符合项

MEIP profile是exact baseline delta：只移除auto_int_local_in_2_0常量动作，新增宽1input machine_external endpoint/cpu irq entry；39bus字段及其他四中断常量保持。generation先复用baseline四RTL/47端口认证，再验证精确MEIP物理role/width。driver只有此真实输入受STEP_IRQ驱动；初始0不是额外竞争驱动，其余中断仍固定0。strict int bit在Python命令前拒绝；C++也验证合法值/额外token。

精确MRET先前设计问题已修：observed_mret必须system_return=1、csr_cmd=4、csr_addr=0x302且类型为int；SRET0x102/DRET0x7b2不能通过。它是qualified CSR decode观察，不声称RVFI retirement；仍需实际MRET前后CSR和foreground resumed构成后续native门。没有复用Ibex take authority或把CSR通知当precise trap。

PROBES/VLT与generated specs为显式source-derived候选。C++通过vpi_handle_by_name查询真实handle，逐项验证vpiFullName/vpiSize；缺符号/错宽度立即异常，不补0。实际build随后执行--describe-probes，保存stdout/stderr/exit及inventory/Syms源码；session核对descriptor和artifact交叉链接、启动再次核对inventory。pre/post sample查询实际VPI vector，拒unknown bits。具体Verilator配置语法/符号可访问性尚未build确认，设计与报告对此诚实；不能因候选未确认就称native可用，也不以尚未build本身判源码错误。

辅助descriptor/header/VLT/profile/interface、implementation hashes和factory digest进入新闭包；copied RTL/manager与独立generated expected bytes交叉核对，完整required file set必需。新schema/driver与旧v1区分，执行binary hash仍只是本地integrity而非签名build provenance。共用baseline generator/manager/transport后续变化须重冻身份并做相应回归，旧GPIO/C/E证据不能授新IRQ artifact通过。

STEP先驱动MEIP、clock低eval/pre probes，再snapshot A/C/D/E、一次rising edge/post probes，然后推进manager。保留external selected D producer直到accept、strict alignment/mask、单pending external、response epoch/sequence/duplicate保护；adapter在target effect前只准full32word/param0/source3bits/window内请求，读INTSTATUS0x4024走高wordmask0xf0。reset新进程并reloadstaticimage，lifetime adapter ticks保留，coherent stream有显式reset barrier，stalecallback在execution/epoch/active identity检查前不能发D。结构checker poison会关闭transport并abort。

factory使用标准Binding(gpio.irq→cpu.irq)、固定IrqPulseDelivery64、source仅pin0及固定其余bits、CPUirq为bound。source下降不缩短pulse，重叠unsupported不延长，reset取消，CPU一步只clock本体；真实GPIO/APB tick路径由既有Runner采集，无组件名分支。输出irq_masked是专有观察而非irq_masked_pre authority；Runner通用accepted/taken没有伪装接入。

RV64 firmware的mtvec通过LUI+SLLI32/SRLI32零扩展到0x80000400，ISR位于第256word。显式清MIE/mie/mideleg，CPU真实写GPIOEN/INTEN/INTTYPE，清旧status、开MEIE/MIE后写ready。主循环等待RAMflag，不host轮询GPIO。ISR实际CSR读取cause/mepc、清MEIE、真实两次status read、保存结果、fence、MRET；main随后自己写resumed。RAM期望值未preload。done/resumed只是待检查的CPUstores，不是独立功能成功证据。

## 低项及后续必需证据

- firmware没有按错误mcause进入独立failure branch，而是统一保存cause后继续ISR。未来positive checker必须严格要求MEI=0x800000000000000b及正确ROB/CSR/vector/return，不能只看done/resumed；当前报告未声称已有该native gate。
- 现有probes含mepc、csr_pc/evec，但尚无独立retired foreground PC。后续门应明确用实际CSR return redirect/target和source-keyedforeground stores证明恢复，不把mepc值或取指单独当retirement。
- constructor认证/文件hash工作没有整体可抢占墙钟deadline；只有native READY/commands有bounded enclosing deadline，与baseline相同。未声称setup所有Python工作硬实时有界。

结论：除独立output保护中项外，opt-in MEIP/精确MRET/passiveVPI/standardpulse及事务生命周期源级实现与设计一致。actualsymbol/build、trap时序、真实ISR status1/clear0/MRET恢复、完整fresh前缀及负向因果控制仍未运行，不能授IRQ/F5/P6/nativepass。

## Output保护最终修复复核 — 5bb888f

Owner已提交 `5bb888f31e8655d23763b8d8e49d024ccf899161`。只读复核 `_require_empty_output`：resolve/获取锁前拒绝最终路径symlink、普通文件和任何非空目录；禁止heavy_lock位于output内部；拿锁后再次检查为空才generate。原one-shot、persistent、IRQ及未知内容目录均不会进入覆盖路径。前述中项已解决，无剩余确认的高/中阻断。

当前generation SHA：`6ccb1a107330d3ad4c9b54b89d46444eb301a74e9691d92df16c506f7f7ad89e`，工作树该文件无未提交变更。Owner报告新增9项filesystem合同测试与combined40passed/10.93s；本轮只读测试源码/结果说明，未重跑。该修复不构成build/probe/ISR/native通过，原待运行边界保持。
