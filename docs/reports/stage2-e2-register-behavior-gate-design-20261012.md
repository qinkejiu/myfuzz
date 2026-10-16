# E2 actual CPU 寄存器行为／reset 门禁设计

2026-10-12，只读设计，尚无本轮行为门禁通过声明。保留原完整 E1/E2 scope；combined generation＋fresh CLI 的性能问题独立跟踪，不以缩减寄存器矩阵代替语义验收。已有 ordinary receipt／association 只证明实际访问与边界关联，不授 verified／functional。

入口继续可信 ordinary assembly＋before-begin Session observer／register adapter；每 case 使用原 register request→实际 context 编译→adapter.submit，不能直接 BFM、saved bytes 或 host reset image。CPU LW 的 raw bus response 保持32位；CPU执行字段提取后用真实 SW 存 RAM。每次 read 核实际 source TransactionKey、router window、目标 epoch／command receipt、6 raw／3 base refs、CPU response callback private confirmation、同 case RAM store 与 authenticated commit。fresh trusted file CLI 从原请求重新编译，逐 case／完整 trace／terminal state 比较。

## 第一组可执行序列

GPIO A先隔离使用 scratch x1/x2/x3，INTEN保持0；result RAM不与固定 bootstrap、声明指令槽或 initial image 重叠。B可作为同 profile foreign alias 隔离对照，不能复用 A 的 receipt／RAM／epoch。

1. PADDIR写0xa5000000→读回；PADOUT写0x80000100→读回。比较真实CPU存RAM值与对应写请求，另核物理dir/out export。不要仅比较 host计算的write_new与actualCPU同一次SW。
2. PADOUTSET bits=0x01000200（显式allow_side_effect）→PADOUT读回；再重复SET同值→读回，要求 OR语义与幂等性。PADOUTCLR bits=0x80000100→PADOUT读回；重复CLR→读回，要求 AND~mask与幂等性。SET／CLR无读取权限，读请求须在目标命令前拒绝；不凭RTL默认地址PRDATA=0称合法alias read。
3. PADCFG_0 pin0=9 RMW→pin0读回；pin7=5 RMW→pin0及pin7读回；pin0=3 RMW→两字段读回。每个RMW保留真实read_old及write_new=(read_old&~bus_mask)|bus_value证据，后续独立LW验证持久值与未选字段保存。
4. INTTYPE_HIGH pin31=1 RMW→pin31读回；pin16=2 RMW→pin31／pin16读回；pin31=0→两字段读回。覆盖word lsb0／30与高pin位置，不因INTHIGH地址相近误绑LOW。
5. 拓展所有32个INTTYPE 2-bit字段及32个PADCFG 4-bit字段，按register分组复用已知pattern但每行至少实际read/write/reset/mask证据；GPIOEN、INTEN单独全word写读测试，控制外部pad输入使IRQ不被意外激活。

设计初始阶段 compiler 拒绝窄字段 register_read（现已完成下面的软件实现；Session 接线另行验证）；重复RMW的下一次read_old可补充持久性观察，但不能代替独立read权限／field result门禁。本轮 compiler 新功能使用现有RV32I：LW→SRLI(lsb)→ANDI(field_relative_mask≤0x7ff)→RAM SW；大mask用LUI／ADDI装入独立maskreg→AND，仍是实际CPU指令。fullword读保留旧16字节LUI/LW/LUI/SW；窄读字段lsb0免shift，2/4-bit字段20字节，非零lsb24字节；大mask分别28/32字节。不得用算术右移造成bit31符号扩展。

窄读前要求整个32位寄存器所有字段完整声明、readable、plain read-side-effect、完整field-relative read masks，覆盖恰好32位；任何其他字段read_clear或未知副作用都必须拒绝，不能因只选plain字段绕过总线LW副作用。写权限不决定read资格，但RO且read-mask完整可安全参与plain register。maskreg与base/data冲突拒绝，大小边界按实际fragment验证。

当前saved compiler document的result_storage闭集仍四字段，source长度由program_size和max_program_bytes约束；窄读结果约定为字段相对的零扩展u32，compiler 已在result_storage增加仅窄读存在的闭集 field_extraction metadata（lsb／width／read_mask／bus_width=32／representation=field_relative_zero_extended）以明确bus32→field结果。Session `_validate_register_manifest`需兼容该可选metadata并核lsb/width/mask与operation_plan；[capability preflight validator](../../src/myfuzz/scenario/register_program_capabilities.py) 当前固定 expected=36(RMW)/16(other)，必须改为根据可信当前编译结果／闭集field extraction规则核尺寸，不放宽任意长度。fresh verify helper仍从当前profile／sidecar／router／slots编译后exact compare，不从保存metadata恢复执行权限。

## Observable reset

采用已接纳case后的 `Session.reset('warm_all')` 或 `cold_all`，保存reset_operations位置。先写非零plain寄存器＋独立CPU读回，等待无pending ordinary访问，再执行真正local RESET并保留reset事件/receipt、target reset epoch、CPU epoch、memory generation。reset后经实际固定bootstrap重新到真实waiting instruction，重取adaptercontext与RAM权限，发新的read requests，核PADDIR/PADOUT/GPIOEN/INTEN、全部INTTYPE/PADCFG reset声明值。两个policy均复核：warm保持RAM和已materialized槽，不允许覆盖旧slot；cold清初始化内存资源，不能偷用旧initialimage或旧receipt。实际safe slot可重新取用的规则必须由installed gate／memory实际状态决定。bootstrap是否覆盖被测寄存器应从reset后实际APB trace核实，不能把bootstrap再次写入的值误称RTL reset值。

当前Runner reset_all会flush pending observation并terminalize，再reset本地组件和memory资源；Session记after_cases位置，fresh replay按相同位置reset。必须软件先证明多case reset后adapter动态context／sourceconfig pin不会误拒合法generation；若固定startup config包含会变的资源身份，则需分别保存稳定声明与每次实际context，不能以关闭guard绕过。reset失败、不完整访问、epoch不符一律保留terminal证据，不能授reset_verified。

## 完整14 registers／72 fields验收矩阵

8个word行（DIR/OUT/SET/CLR/GPIOEN/PADIN/INTEN/INTSTATUS）＋32 INTTYPE＋32 PADCFG，逐行记录declared、operation eligibility、actual请求／receipt／CPU result／reset evidence与unknown原因。RO write和WO read是命令前拒绝证据；value超fieldwidth、bool/int混淆、wrongwindow/alias、unaligned/slot不足同样拒绝。真实bus固定LW/SW32位、BE=15；软件fieldmask／word位置正确不等同硬件byte-enable masking。PULP该wrapper若无PSTRB，不能声称subword write被mask；要验证实际窄CPUstore权限需独立compiler/route接口与硬件语义支持。

PADIN需真实物理input stimulus与同步latency观察，不能host造input_sample。INTSTATUS读取是条件clear：pinnedRTL149–158若s_rise_int同时为1优先OR置位，只有无新事件才readclear；需要真实GPIOEN/INTEN/INTTYPE/pad刺激＋实际IRQ/status provider与时间控制，现compiler即allow_side_effect=True仍拒read_clears。未来专用明确opt-in readclear操作才能验证，不得放宽ordinary plain narrow read。PREADY=1、PSLVERR=0固定实现只验证实际constant行为，不捏造wait/error capability或M4。

最终等级需code-owned分操作verifier绑定实际artifact、source pins、scope、epoch／generation和证据，形成完整已验证矩阵；既有capability preflight declaredL2/effectiveL1/verifiedNone与访问association不可直接升L2。E1/E2保持未完成，性能拆分门禁不减少上述剩余行为要求。

## Compiler TDD 软件交付

仅修改 [register_program.py](../../src/myfuzz/scenario/register_program.py) 与新 [field-read tests](../../tests/scenario/test_register_program_field_read.py)，ISA／Session／adapter／sidecar未由本包修改。新18项先11失败、7通过（旧fullword guard拒窄读），随后四模块联合 `test_register_program_field_read.py`、`test_register_program.py`、`test_register_program_rmw.py`、`test_register_program_verification.py`：128 passed／1.05s／exit0。覆盖机器字独立解释器执行raw bus到RAM结果、bit31零扩展、2/4-bit高低字段、12/20-bit大mask路径、maskreg冲突、slot容量／RAM重叠、完整readable／mask／字段覆盖安全与原fullword布局兼容；没有CPU RTL结果或新verified证书。

生产 compiler 冻结SHA `ebb0b78da125b8990d87ef8bc0248c0074e3d2f3c70ddebc2252d4746e95e60e`；新测试SHA `15af24c752f9559ab0689f162f8ea7dc9e72e5e0b7471ab9779ac404e661395a`。sidecar loader 要求所有field side_effect与profile register一致，因此混合read-clear forged typed对象会在 typed-contract 边界更早拒绝；完整窄读 guard仍拒任何非plain／非readable／不完整read-mask或覆盖。caller allow_side_effect不授绕过权限。Session保存metadata／capability program长度约束由root独立TDD，本报告不提前授其通过。
