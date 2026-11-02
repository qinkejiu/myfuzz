# Compiled F6：CPU配置、四字DMA、原生IRQ与ISR的版本化执行合同

状态：2026-10-24用户已书面批准“批准，按规格继续实现（推荐）”；独立设计复审PASS。实施计划已完成并经独立规格/质量复核；Task 1合同/编译器软件组170 passed，3 subtests passed，独立复核中；Task 2稀疏固件73 passed且独立Spec/Quality PASS；Task 3 sealed DMA ERR软件组75 passed/2个明确native门skip，独立Spec/Quality PASS；Task 4 MRET凭据软件实现中。本规格原生门已于2026-10-25执行Freeze12 native-controls attempt11，但结果为4/9失败，独立raw audit为PASS_WITH_GATE_FAILURE；当前修复候选尚未冻结/复验。审批时完整规格SHA为d8b0d1666d548f7c70eff7416e559d5124412a252661b310a703d45cbcd172db。本轮独立Ibex源码复核为§6补充证据语义澄清：IRQ入口retirement serial连接take；MRET自身serial为0；实际返回PC从紧随MRET的有效退休来源推得，原始`pc_wdata`只保留为原始观察。该澄清只修正如何证明已批准的MRET/返回目标，不增加CPU/IP、DMA事务或搜索范围。2026-10-25又独立检查了当前固定Ibex M-mode的mip.MEIP[11]来源，确认其只读CSRRS读取真实irq_external_i；为满足固定16-tick脉冲expiry后再观察边界fetch的现有合同，mutable修复候选在ISR终止store/MRET前轮询MEIP拉低，不改Runner脉冲、通用OBI等待上限或在线指令白名单。该ISR字节和初始镜像manifest随之变化；此实现细节尚待代码复审和新冻结native重验。F2 freeze3十门、最终源码/证据复核及文档闭环均已独立接受，执行冻结已释放。保留共享分支和未提交前驱，不stage/commit/reset/clean。

## 1. 目标与依据

把已有固定实例的CPU-programmed DMA能力接入同次D2/D3驱动的独立compiled F6执行器，形成一次初始化、多例持续运行、逐例来源认证、真实断言、完整fresh和统一RFuzz入口的首个纵向交付。

总计划`2026-10-06-current-dataflow-fuzz-implementation-plan.md`的F6定义为CPU配置DMA→真实DMA master→RAM/IP→完成IRQ→CPU。第一切片保留IRQ/ISR终点：仅polling或最终RAM内容相同不算本规格的完整F6。P8的其他RAM/IP/FIFO方向、长期有效搜索及性能门仍各自开放。能力等级按`2026-10-04-generated-local-harness-five-protocol-design.md`及实际证据授予。

首个支持形态为RV32I、单在途OBI CPU＋源码固定的Wishbone DMA控制/主设备＋共享持久RAM，数据宽32、BE15、四字递增读写、真实机器外部IRQ及可认证的native IRQ-take/ISR证据。原始实测候选为Ibex RVFI profile与ZipCPU wbdmac；生产选择依据协议/template ABI/受信source contract/IRQ观察能力，不依据实例或组件名称。缺IRQ原生观察或DMA CSR语义来源的同协议形态须具名拒绝。

## 2. 路线比较与选择

方案A（推荐）：固定控制岛＋现有白名单在线前缀。boot时预装ISR与每槽固定branch/jump控制岛，在线仅接纳LUI/ADDI/SW/NOP前缀；每例候选只变异四个数据立即数。CPU真实写源RAM并配置DMA，固定ISR返回后经控制岛进入下一未填前缀。复用现有未填取指等待/恢复，不放宽通用RV32I可变指令白名单；新增的是F6配置/逐字搬运/IRQ消费及狭义ISR-return观察。

方案B：固定CPU循环读取顺序descriptor mailbox。每例使用新的未物化RAM槽，CPU读取候选再配置DMA；既有已读字节不能由host重新填写。该路线还需明确的首次数据物化/等待接纳合同及CPU mailbox消费来源证明，不能用host反复改写ready标记替代。它适合后续descriptor地址/长度变异，首个F6切片采用A，以控制新增语义范围。

不调用`make_ibex_dma_runner`或其他具名工厂来替代D2/D3装配；这些例子只提供已验证接口和firmware语义依据。

## 3. 候选、固定字段与所有权

每条RFuzz wire record仍为8 bytes，little-endian整数的bits[0:44]依次编码四个11-bit整数w0..w3；bits[44:64]为声明式常量0。四值必须两两不同，范围0..0x7ff。保留全部raw8、四值、规范program bytes及各自hash；高20位非零或重复值在任何case提交前拒绝，不裁剪/归一化为合法输入。默认合法seed由D3 seed声明产生，采用四个明确的不同值；全零record不伪装成合法seed。

F6一项test仅接收一条record；2..200条显式拒绝且不提交其中任何记录。公共wire parser的8-byte/200-record能力及F2/F4各自限制保持不变。一buffer的其他已完成slot按实际记录。相同slot/raw返回缓存；相同slot不同raw终止并拒绝。

V1只变异CPU片段中的四个ADDI数据立即数。DMA源/目的地址、长度4、block4、递增模式、BE15、start key0xfed、控制寄存器偏移0/4/8/12、IRQ接线与ISR均绑定。源RAM每例由CPU真实SW更新；host不替CPU写源数据，不直接写DMA寄存器，不随机化DMA响应/IRQ。指令只改未完成取指且尚未物化的显式程序槽。

旧D3的32-bit`dma_transfer_descriptor`静态source没有上述语义。新增marker下显式输出四个`cpu_instruction_operand` source及完整源映射，不把44个候选位静默塞进旧descriptor或F2/F4 source。每个source绑定CPU、image source、slot内指令偏移、寄存器、位宽及mask；DMA feature/route descriptor作为绑定语义保留。

## 4. 版本化合同与静态准入

保留`compiled_paths.v1`外层。新可执行形态使用独立`compiled_F6_cpu_dma_contract.v1`，闭合字段为：

`schema_version,flow_id,path_id,cpu,dma,instruction_source_id,candidate_layout,program_contract,memory,control,master_routes,irq,termination,expectation_ids`。

- `cpu`绑定实际D2 artifact、OBI instruction/data endpoint及native IRQ观察contract；不从协议名称推断IRQ-take能力。
- `dma`绑定实际transfer provider、双角色template版本、完整RTL/source/参数闭包与code-owned CSR语义provider。provider必须证明四个CSR偏移、key/count/length编码、递增位、32-bit主设备地址换算、BE和完成/错误IRQ语义；只声明FEATURE_TRANSFER不够。
- `candidate_layout`闭合规定wire8、四个11-bit source slice、reserved-zero mask、互异约束、seed和单record限制；重新编译/重建后逐字段比较。
- `program_contract`绑定规范白名单前缀、固定boot/ISR/控制岛的初始image hash、slot大小256／数量1..16／范围、在线前缀128B、per-case result布局和四个ADDI操作数位置。CSR、branch、jump及MRET仅在boot时预装的不可变控制代码中，不经过通用在线白名单，也不成为随机指令源。
- `memory`绑定CPU与DMA共享的同一个PersistentMemory对象；CPU.service与DMA.memory_service保留各自现有MemoryService/TransactionLedger，分别固定身份及生命周期。指令/源16B/目的16B/每例结果槽明确非重叠，resource id/权限来自同次wiring。读快照权威属于实际发行它的service，CPU/DMA事务按完整owner/execution/case/epoch/channel/sequence命名；跨服务仅通过同一RAM的generation/byte-version/writer身份及实际Runner事件join，不假设局部ledger event序号全局唯一。
- `control`绑定CPU→DMA控制端点和窗口；四个DMA寄存器顺序为source@8、destination@12、length@4、start@0。主设备transfer使用显式read/write route intent及artifact endpoint link；静态同一物理master到runtime读/写端点的alias须保留原有版本化凭据。
- `irq`绑定真实DMA输出、既有Runner固定16目标local-tick的`IrqPulseDelivery`、CPU入口、注册native take provider、固定ISR及新狭义`native_f6_isr_return.v1`观察。固定脉冲到期与CPU take是分别记录的事实；不把它写成take-cleared latch。
- `termination`固定为`native_dma_irq_then_cpu_isr_readback`，要求ISR读取DMA状态与全部四个目的字，并由真实CPU写per-case终止标记。

只有所有静态能力/源/权限/IRQ/route条件满足的marker形态才生成F6 executable图和source；其他F6继续unsupported并逐项点名。旧Caliptra单字post-live合同、旧图与旧保存schema保持其原有边界。

## 5. D4一次绑定与运行图

在`ScenarioSession.begin()`前，用同次D2 artifact对象、原始编译请求和完整D3文档重编译并准入，建立显式instruction binding、图/contract及静态DMA intent声明。构造CPU与DMA时传入同一个PersistentMemory，保留CPU构造器创建的service/ledger与DMA自己的service/ledger，不在构造后替换私有字段。随后调用已有live topology binder一次，核对artifact endpoint link、RAM对象身份、两个service的实际owner、read/write route及IRQ绑定。每笔DMA beat通过`DmaMasterRouteAdmission`重新验证topology；DMA发行ReadSnapshot及CPU写入/读回回执均使用各自原始service seal。

F6 的 `runtime_graph` 是数据来源/路由图，精确声明四条边：CPU 源 RAM words→DMA read words（`dma_master_route`）、DMA read words→DMA write words（`causal_order`）、DMA write words→目的 RAM words（`dma_master_route`）、instruction source→在线 instruction prefixes（`persistent_state`）。每条边必须由原始 Runner/Observer 事实逐边重建，不能由汇总状态或值相等代替。

CPU 配置写入与 DMA 控制接纳、IRQ 输入与 native take、ISR 状态/目的读取/结果写入/MRET/后继取指仍各自保留在独立 typed expectations 和事务身份中；它们不是上述四条 `runtime_graph` 边。配置与 IRQ/ISR 证据不会补足任一缺失的图边，反之亦然。若未来要把这些组件链提升为 runtime graph edge，须扩展并版本化图声明、路径选择与来源合同后再单独验收。

RAM→RAM策略只接受按声明顺序的四读四写、各16B范围、4-byte对齐/BE15、精确case/execution/epoch/key及对应源快照。route match只证明路由归属；effect与native response另行join。MemoryService的提交顺序仍为host事务顺序，不称物理总线仲裁。

不放宽`MasterTargetWindow`当前外设读边界；RAM路线直接复用持久内存接口。本规格不把UART readable offset或Caliptra CTRL规则改名为通用RAM能力。

## 6. 一次boot、多例CPU/IRQ流程

固定boot从声明复位向量真实取指，初始化受信ISR/CPU CSR并转入第一个未填在线前缀。每槽256B：前128B在case接纳时安装，后128B的控制岛在boot前预装；最多16槽，窗口与boot/ISR/park分离。前缀固定32条白名单指令：四个指针的LUI+ADDI、清x10并设x11=1、四组ADDI x3+SW源字、四笔DMA寄存器配置所需的LUI/ADDI/SW、NOP补齐。源值ADDI为零起算index10/12/14/16（byte40/48/56/64），仅其低11-bit立即数字段可变；其余字节逐字节重建核验，仍调用原在线指令白名单。

控制岛首先执行固定`BNE x10,x11,0`等待，再固定JAL到下一槽；最后一槽转入预装park。控制岛和ISR字节由初始镜像hash及PersistentMemory preload writer/version证明，绝不以“fixed”标签绕过在线validator。现有未填native fetch等待/恢复接口只负责下一前缀的等待；程序不允许host改PC或覆写已物化字节。

每例完整纯预检候选、程序槽、结果范围、case/事件/局部tick预算、DMA空闲及无未解决事务后才接纳。预算参数进入identity；不足不得先执行一个部分候选再拒绝。

规范case片段清本例CPU内部完成标志，设置source/destination/result指针，真实写四个候选源字，再按四个DMA寄存器顺序配置。DMA独立推进；所有accepted读写必须来自native PRE主设备输出。CPU等待固定ISR完成标志，不能由Scheduler设置成功标志。

IRQ使用现有Runner固定宽度脉冲策略：每个真实DMA输出事件按绑定/epoch/sequence进入16个CPU local-tick输入窗口，按实际起止tick到期，不因take提前清窗口。独立要求native take发生在当前transfer的有效交付范围并关联原生决定凭据；masked/过早/重复/stale IRQ原样保存，缺take/ISR则missing，不能续造脉冲。下一例前要求旧窗口到期、DMA源IRQ恢复inactive及无未结算该case事务。若以后需要take-cleared latch，另立版本；不借用具名例子的手工latch冒充既有Runner策略。

固定ISR保持x1(DMA)、x2(source)、x4(destination)、x5(result)、x11(完成比较值)，可clobber x3/x6..x9，并只把x10设为1(成功)或2(原生DMA错误)。成功ISR真实读status及四个目的字、写结果后，使用只读`CSRRS x6,mip,x0`轮询真实`mip.MEIP[11]`，直到固定IRQ输入窗口拉低，再写终止标记并执行MRET。错误ISR读status后也须先等真实MEIP拉低，再写错误终止标记并MRET，不走四字成功读回分支。轮询只在不可变预装控制代码中，既不扩展在线指令白名单，也不改Runner的16-tick固定脉冲。依据当前注册Ibex M-mode provider，`mip.irq_external`直接映射外部IRQ输入；若未来改成level-held来源或改动脉冲策略，必须重新验证窗口/循环上界，不能把未结束的轮询判为完成。x10=1使等待岛落入下一槽JAL；x10=2仍停在当前控制岛，记录实际返回边界后结束campaign，不接纳下一例。

终止store不是完整handoff：还须有绑定当前case的真实ISR-return证据，随后观察CPU到下一未填前缀的native fetch请求（末例为park）。新增code-owned`native_f6_isr_return.v1`只认证该固定ISR中的MRET及其真实返回后续PC，不把现有bus completion或IRQ-take凭据当成MRET退休，也不扩大为任意指令退休权威。其来源链为：实际native take的decision serial，随后固定ISR入口的首条`rvfi_valid && rvfi_intr`退休及相同非零retirement serial，再到固定success/error MRET及其后第一条有效退休。MRET本身的retirement serial按本sideband定义为0；0不提供来源权威，入口退休保存的非零serial负责将take连接到该ISR。拒绝重复/cross-case/缺观察。

固定Ibex源码只在trap handler首条指令设置`rvfi_intr`；`ibex_irq_serial_sideband`仅在`rvfi_valid && rvfi_intr`时输出retirement serial。因此，不能要求MRET样本自身带有与take相等的非零serial。MRET须满足真实native`rvfi_valid/order`、`insn=0x30200073`、ISR范围内`pc_rdata`、无trap；其`pc_wdata`原样记录但不解释为返回目标，因为被绑定的Ibex源码在`pc_set`时采样`branch_target_ex`，而`PC_ERET`实际选择`csr_mepc`。返回目标使用该MRET之后第一条有效退休的`pc_rdata`作为实际恢复PC：退休`order`须严格为MRET `order+1`，`rvfi_valid=1, rvfi_trap=0, rvfi_intr=0`，debug观察关闭、特权级有效、地址对齐且落在当前case的prefix/control-island范围。该后续指令必须有同一CPU/process/epoch/case下、无error的native instruction response，地址及指令字与退休观察吻合；F6执行绑定还须核对该字来自本例规范prefix或固定preload。其receipt/order/PC明确标作“由紧随MRET的source-verified退休推得的实际恢复PC”，不声称直接采样mepc。MRET、后续退休之间以及前序IRQ入口到MRET之间的native receipt必须连续，且不得出现新take、再次handler-entry、trap、debug diversion、reset或scope变化；invalid RVFI周期的陈旧insn/PC字段不参与判定。

MRET及其后续退休的闭合后，仍要单独观察CPU到下一未填前缀的native fetch请求（末例为park）；后续case只可由该请求的真实source-bound prefix填充并恢复，不能把已退休的固定控制岛指令当作下一未填前缀handoff。

native take的首个provider明确使用既有`verify_ibex_irq_receipt_artifact`及其源码/层次观察contract，保留其`ibex_rvfi_local`注册profile guard。F6装配只按注册provider contract选择，不增加F6的组件名称分支；逻辑实例改名保持profile/source identity。该边界不证明第二个OBI CPU的IRQ实现可接入。其他CPU须先有独立、source-verified兼容provider；不能仅删除profile guard或检查同名OBI端口。

程序槽接纳/等待使用现有显式instruction-source和native完成机制，控制岛走不可变初始镜像来源。若现有CPU interface不能保留真实下一fetch边界，必须使首个目标门失败并修正实现，不得靠猜测cycle或写已完成fetch字节绕过。实现计划首先验证源码支持的等待机制、固定ISR寄存器约定、原生MRET观察以及两个真实连续case。

## 7. 逐字来源与CPU消费

每个index0..3保留：候选source slice及实际功能取指；CPU source-SW acceptance/MemoryService writer/version；native DMA read acceptance/TransactionKey；MemoryService实际发行的ReadSnapshot及每字节writer/version；真实DMA write acceptance；目的RAM commit/BE/版本；native完成响应；ISR真实CPU LW response及随后result SW。值、地址、lane、epoch、case、producer和顺序必须一致。

CPU配置四笔写分别关联native OBI、Router delivery、DMA control native接纳/响应及该transfer起点。不能从host写寄存器记录推断CPU已配置。只比较源/目的最终值、没有native请求、缺来源版本、重复commit、错误IRQ或缺ISR都不得认证完整链。

原生IRQ/take与ISR只在受信观察contract声明的范围内授予。普通bus completion不升级为任意decode/退休证明；固定ISR若使用已有RVFI/IRQ serial凭据，按其原scope逐项核对，不借用其他实例的私有层次证据。

## 8. Typed断言、反馈与错误路径

新增独立`compiled_F6_execution_binding.v1`及F6 evidence validator；不伪装为F2 binding。每个实际admitted case有且仅有下列五个expectation的passed/failed/missing行：

`protocol_checker.receipt_violations`、`cross_component.declared_edge_hops`、`dma.cpu_configuration`、`dma.word_transfer_join`、`dma.irq_isr_completion`。

逐case独立inventory包含完整compiled/binding/path/run/case/expectation scope。pre-admission拒绝不制造case。观察矛盾failed、观察缺失missing；协议finding和期望结果分开。

RFuzz feedback仅来自上述真实case证据的显式代码投影；partial/failed case整个向量保守为零。字段/存储/IRQ/helper计数不能代替证据join。target定义和实际hit随报告保存，不因有client或passed typed行自动授予更高等级/搜索收益。

保留首个执行错误对象、原始notes及后续清理/导出诊断，停止后续case；已有CPU写、DMA读写和pending/uncertain事务完整保存，不声称回滚。finish只收尾一次，独立尝试partial trace/plan/typed inventory/build/process导出。

负例包括纯预检拒绝和明确新增的sealed controlled native-response fault seam；当前DMA session尚无合法RAM beat的此hook。该控制仅由冻结gate声明，采用稳定逻辑selector `(case_index,operation,word_index)`、一次性命中和`before_target_effect`时机，纳入binding/plan/identity；不接受任意callback、原进程execution_id或mutator隐藏位。fresh按同一selector选择其新native accepted beat，再分别保存/核对原始与fresh实际完整TransactionKey。

选中beat先通过真实native acceptance、route/admission检查，再记录带owner/key的error-response账本凭据，跳过MemoryService read/write callback，因此该beat不发行ReadSnapshot、不产生RAM commit，`target_effect=false`；已经发生的其他读/commit保留。环境按该凭据驱动ERR，真实DMA error/status/IRQ仍由RTL产生。正常策略没有此hook权限，不伪造DMA输出或对已发生的效果谎称未发生。

这是`expected_response_fault_pending`状态，不立即抛host异常：禁止新case，但继续有界推进当前DMA/CPU，让真实error IRQ、take、ISR status/error终止、MRET及回到当前控制岛的native取指边界进入trace。ISR错误分支不宣称四字读回成功；typed结果按正常成功expectation如实failed/missing，并保留实际错误完成观察，向量为零。超时/完整性/宿主异常仍立即终止并保留partial。最终失败前缀fresh必须独立再现selector→新key→ERR→实际部分effects→IRQ/ISR/返回边界，保存双方完整raw/计数/语义hash/first_difference；使用单独`failed_prefix_full`scope，不能用成功`full`或省略fresh代替。

## 9. 统一入口与fresh保存

本次交付包含显式`compiled-f6-rfuzz` registry、支持评估、独立decoder/executor、file入口和统一`auto_harness_test`调度；不把运输接入留成未交付的隐含后续。共享仅wire/shared-memory及已验证的小型build/process/字节pin原语，不继承F2/F4的路径/候选/反馈语义。

原始与fresh均消费同次声明身份，fresh重新构造CPU/DMA进程、boot、逐例配置/搬运/IRQ/ISR并比较完整归一化前缀；实际artifact/build/binary/observed executable/READY、PID/nonce、退出和reap均闭合。仅允许已声明的进程本地身份规范化，raw保留。

保存原始raw8 receipts、完整plan/events、F6 prefix、独立fresh events/audit/verification、build join、receipt/case/source join、typed results/inventory、final capability及各自首次字节hash。最终导出后重核同次材料和初始bytes；缺raw、格式漂移、跨scope和相干重hash替换均拒绝。独立保存审计器依赖冻结外部输入/输出ledger，不从JSON发行live authority。

## 10. 验收门与范围

先RED/GREEN及独立Spec/Quality；冻结完整production/tests/configs/wrappers/registered RTL/工具/控制输入及命令，任何实际运行保存外层监督child PID/PGID/exit/reap/timeout/RSS、来源与initial/final输出maps。

必须有：真实统一RFuzz正例和完整fresh；同一CPU/DMA进程连续至少两例且源数据不同；逻辑实例改名且保持物理ABI/source/template；错误reserved/source/layout/route/IRQ形态在副作用前拒绝；断开一个实际read snapshot/commit/IRQ/ISR观察的controlled负例保持failed/missing及零未证实反馈；声明的native ERR/IRQ/ISR失败前缀及独立fresh；受影响F2/F4同候选兼容门。所有门有完整raw和独立归档/证据审计，不把开发计数相加成一次验收。

报告分别列出generated/executed/certified/input-invalid/failed、真实候选及源字多样性、逐case成本、构建/缓存事实、有效case/s及链/s；缺时间材料则null并具名原因，不预测收益。只接受本次OBI/Wishbone四字RAM→RAM、IRQ/ISR与声明的形态。RAM→IP、IP FIFO→RAM、其他CPU协议、任意DMA CSR、PLIC/coherence/物理bus仲裁以及完整P6/P7-E/P8和六CPU×四IP总验收仍由各自门约束。

## 11. 当前源码依据

`scenario/compiled_paths.py::_evaluate_f6`和runtime图目前仍阻止静态F6；`generated_execution_admission.py`与统一registry仅有F2/F4。`compiled_f6_runtime_path.py`已有Caliptra单字post-live能力，固定dma/sha/CTRL16/value5，须保留。`dma_intent_topology_binding.py`、`dma_route_admission.py`、`wishbone_dma_session.py`及`memory_service.py`已具真实live route/native事务/内存发行机制。`ibex_dma_example.py`和`ibex_dma_runner.py`已证明四字真实CPU配置/IRQ/ISR接口，但具名装配不是新执行器。`dma_uart_descriptor_runtime.py::DescriptorBoot`证明一次boot多例的既有能力，其UART/FIFO专用来源不能借给RAM路径。

更细的只读API事实在`.superpowers/sdd/compiled-f6-preflight-20261024.md`。实现之前需要对本书面规格做一致性审阅，再形成任务计划；本草案本身不代表新增能力已经完成。
