# Stage 2 E1：PULP GPIO 寄存器源码核实

## 2026-10-12：14寄存器／72字段声明独立核实

真实sidecar已从首批4字段扩为14寄存器／72字段：保留原PADDIR／PADOUT／SET／CLR四字段，新增GPIOEN／PADIN／INTEN／INTSTATUS四个完整word、32个INTTYPE两位pin字段及32个PADCFG四位pin字段。下文“四字段”方案属于原始最小实现历史，当前声明范围以本节为准；声明扩展不授E1完成、全部规则可执行、L2 verified或M4功能能力。

独立检查实际 `PAD_NUM=32`／`NBIT_PADCFG=4`／`APB_ADDR_WIDTH=12` 的固定源码；RTL SHA仍为 `1e271914da4d25c87acd12121dde60a6ed955033870fd7a6730b2c9bafcbcaef`，profile SHA及fingerprint未变。当前sidecar SHA为 `f9b4837c6ca06b97a0ceb76f134ed7591538ab6d9c3e94c7839fc8ab63b7459b`。72项evidence_ref均绑定实际revision与该RTL SHA；独立逐字段提取源码PWDATA assignment，64个packed pin字段全部与实际slice一致，不凭字段名推断行为。

| 声明组 | 位置与mask核实 | 源码依据 |
| --- | --- | --- |
| GPIOEN／INTEN完整word | lsb0／width32，rw，read/write mask均0xffffffff，reset0 | GPIOEN写415–418／读670–678／reset218；INTEN写325–328／读590–598／reset217 |
| PADIN完整word | lsb0／width32，ro，read mask0xffffffff／write0，reset0 | 读550–558、reset190–192、管线184–203；第三采样级，不伪造host输入观察 |
| INTSTATUS完整word | lsb0／width32，ro，read mask0xffffffff／write0，reset0，read_clears | 149、151–158、650–658；事件累积先于读清除，只有无新s_rise_int才读清，不是无条件clear |
| INTTYPE_LOW pin0–15 | 每字段width2，word-relative lsb=2×pin，field-relative read/write mask3 | 写335–353／读610–618，reset214 |
| INTTYPE_HIGH pin16–31 | 每字段width2，word-relative lsb=2×(pin−16)，field-relative read/write mask3 | 写355–373／读620–628，pin31 lsb30；未误用全64位absolute offset |
| PADCFG_0～3 pin0–31 | 每字段width4，word-relative lsb=4×(pin mod8)，field-relative read/write mask15 | 写425–471／读690–728，reset213；pin31在PADCFG_3 lsb28 |

每个register字段覆盖完整32位且无重叠；planner仅在生成bus_mask／bus_value时把field-relative mask左移lsb。上半pin字段仍归属各自32bit寄存器，不混淆pin索引与word bit位置。新字段均reset0；旧SET／CLR继续省略独立reset值，因为它们没有独立存储。

root实现18项RED→GREEN及五模块108 passed／2subtests（0.97秒）；本次独立四模块软件验证 **92 passed／2subtests（0.78秒）**，包含新全字段、旧四字段／完整source refs、通用sidecar及compiler检查。未运行RTL、lint或build。现有compiler对普通窄字段仍拒绝无RMW编译；INTSTATUS即使显式allow_side_effect=True也拒绝unsupported-side-effect。没有新增read-clear oracle，`read_clears`仅是带本报告并发限定的声明标签，不授权无条件读后零断言。

两次旧E2实际门禁（`stage2-e2-gpio-cpu-register-20261011-r2`与`stage2-e2-gpio-program-verification-20261011`）均固定首批sidecar SHA `8ec362c3a2085d49f514111ac6c24193c0ace7da0db263ce8d06643d0eb36693`，与当前72字段数据不同。旧25项source pins及实际行为证明保留历史身份，不改写为新sidecar结果；本次软件通过不能替代新数据的实际门禁或生产能力证据。

## 2026-10-11原始只读源码核查（历史）

本次只读核查固定 PULP GPIO 源码与现有 profile，为后续真实 capability sidecar 提供声明依据。没有运行测试、elaboration、RTL、BFM或CPU程序；源码支撑不等同于真实行为验收，不授 E1/E2/M4 完成或 L3 功能能力。

## 冻结来源

| 对象 | 身份 |
| --- | --- |
| 仓库 HEAD／profile revision | `f82caeb7f7d89427f05e9af5ed31e0675efe0d83`；第三方仓库 `git status --short` 无输出 |
| `third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv` SHA256 | `1e271914da4d25c87acd12121dde60a6ed955033870fd7a6730b2c9bafcbcaef` |
| `configs/peripherals/pulp_gpio/component_profile.json` SHA256 | `2268967fa909658fbc079fc41112a10bba88e7484909153cbc1a5a1b222a0b56` |
| 审计参数 | `APB_ADDR_WIDTH=12`、`PAD_NUM=32`、`NBIT_PADCFG=4`，由 profile source.elaboration 声明；源码参数默认亦相同 |

源码链接：[APB GPIO](../../third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv)、[profile](../../configs/peripherals/pulp_gpio/component_profile.json)。下列源码行号均属于上述SHA。

## 总线、地址与优先级

源码11–24行定义profile的14个offset；121行只解码 `PADDR[6:2]`。因此硬件忽略低2位和高于6的位，128字节周期内存在地址别名；profile 4KB窗口是分配边界，不表示其中每个地址都是独立寄存器。后续CPU生成器应仅发声明的word-aligned精确offset，不能把硬件alias行为作为扩展合法输入的依据。

51–58行确认32位PWDATA／PRDATA且没有PSTRB。273–276行以 `PSEL && PENABLE && PWRITE` 进入唯一地址case，209–239行在HCLK上升沿提交；不存在byte-enable或部分word写入。783–784行固定 `PREADY=1`、`PSLVERR=0`；profile `has_error=true` 表示有错误信号角色，不意味着非法offset会返回错误。770–776行未实现／非读access输出零。所有存储及采样块均以active-low异步reset优先于正常更新。

PADDIR和PADOUT写是完整32位overwrite；SET是 `old_out | PWDATA`，CLR是 `old_out & ~PWDATA`。它们由互斥地址case选择，不能同一access同时触发，源码没有额外SET/CLR竞争优先级。输出存储不受GPIOEN或PADDIR门控：780–781行直接导出 `gpio_out=r_gpio_out`、`gpio_dir=r_gpio_dir`；这并不证明外部电气驱动或引脚回读。

## 14个寄存器逐项依据

所有下表可读／可写位mask均针对 `PAD_NUM=32`；一般RW／RO寄存器reset值为零，依据149行、190–192行及213–218行。`none`仅指该寄存器访问没有额外声明副作用，不表示更改配置不会影响采样或IRQ。

| 寄存器 / offset | profile访问与副作用 | 源码支持 | 声明与验收边界 |
| --- | --- | --- | --- |
| PADDIR / 0x00 | rw / none | 写277–280；读530–538；reset215；导出781 | 32位直接overwrite／readback，全mask。方向电气语义需独立真实观察 |
| GPIOEN / 0x04 | rw / none | 写415–418；读670–678；reset218；采样使能169–203 | 32位存储可靠；每四位任一enable使整组同步器推进，不能假设逐位独立采样门控 |
| PADIN / 0x08 | ro / none | 读550–558；写case无该地址；采样184–203 | 32位第三采样级 `r_gpio_in`，reset0。不是原始gpio_in，也不是导出的第二级gpio_in_sync；读不清IRQ status |
| PADOUT / 0x0c | rw / none | 写287–290；读570–578；reset216；导出780 | 32位overwrite／readback，全mask |
| PADOUTSET / 0x10 | wo / write_one_sets | 写297–302；读case无该地址，默认770–771 | 写1置PADOUT对应位，写0保留。无独立存储；不要声明独立readback/reset寄存器值 |
| PADOUTCLR / 0x14 | wo / write_one_clears | 写311–316；读case无该地址，默认770–771 | 写1清PADOUT对应位，写0保留。无独立存储；不要声明独立readback/reset寄存器值 |
| INTEN / 0x18 | rw / none | 写325–328；读590–598；reset217；IRQ门控138 | 32位存储支持；IRQ服务／原因认证不由此自动成立 |
| INTTYPE_LOW / 0x1c | rw / none | 写335–353；读610–618；reset214 | 16个2位字段，pin0–15。131–133行分别定义00下降、01上升、10双沿；11不会满足任何项，不授IRQ功能验收 |
| INTTYPE_HIGH / 0x20 | rw / none | 写355–373；读620–628；reset214 | 16个2位字段，pin16–31；不应把这个word误认为每pin一位 |
| INTSTATUS / 0x24 | ro / read_clears | reset145–149；更新151–158；读650–658 | 有条件read-clear：新IRQ事件累积优先，只有无 `s_rise_int` 才由读清零。单一read_clears标签不足以描述并发优先级，首个sidecar应暂不启用该操作 |
| PADCFG_0 / 0x28 | rw / none | 写425–435；读690–698；reset213；导出116–118 | 8个4位字段，pin0–7；存储及导出支持，不推断pad电气定义 |
| PADCFG_1 / 0x2c | rw / none | 写437–447；读700–708；reset213 | 8个4位字段，pin8–15；同上 |
| PADCFG_2 / 0x30 | rw / none | 写449–459；读710–718；reset213 | 8个4位字段，pin16–23；同上 |
| PADCFG_3 / 0x34 | rw / none | 写461–471；读720–728；reset213 | 8个4位字段，pin24–31；同上 |

INTSTATUS的具体优先级是源码可核实事实，并非未知的猜测：151–153行先OR新的cause，154–158行是其后的else-if读清；143行IRQ直接为 `s_rise_int`，不是status OR。尚未由本次核查验证的，是真实读采样时相、并发新事件与清除的完整端到端见证、CPU服务和功能oracle。因此不应把该粗粒度副作用直接用于无条件写后读／读后零断言。profile67–68行已有这项限定，无需捏造新的read-clear行为。

## 原首批最小sidecar可实施字段（历史）

优先声明四个完整word字段，避免无PSTRB情况下把field mask误当硬件写strobe。下表field名为建议的新声明名字；源码没有软件field名。这些名字只标识字段，不推断功能族。

| register.field | lsb / width | access | read_mask | write_mask | reset_value | side_effect | source_ref关键行 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| PADDIR.value | 0 / 32 | rw | 4294967295 | 4294967295 | 0 | none | 215, 277–280, 530–538, 781 |
| PADOUT.value | 0 / 32 | rw | 4294967295 | 4294967295 | 0 | none | 216, 287–290, 570–578, 780 |
| PADOUTSET.bits | 0 / 32 | wo | 0 | 4294967295 | 省略 | write_one_sets | 297–302；作用于216行reset的PADOUT存储 |
| PADOUTCLR.bits | 0 / 32 | wo | 0 | 4294967295 | 省略 | write_one_clears | 311–316；作用于216行reset的PADOUT存储 |

真实sidecar当前接受的引用键是 `evidence_ref`，没有 `source_ref`字段。可把明确source_ref编码放入evidence_ref字符串，例如：

```text
rtl:third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv@f82caeb7f7d89427f05e9af5ed31e0675efe0d83:277-280,530-538,215;sha256=1e271914da4d25c87acd12121dde60a6ed955033870fd7a6730b2c9bafcbcaef
```

分别替换行号即可引用PADOUT／SET／CLR；审计报告保留完整地址与reset上下文。解析器只校验evidence_ref为非空文本，不能把字符串本身当作自动认证来源，仍须绑定实际profile fingerprint与源码身份。

后续可按同一依据补GPIOEN完整word、PADIN只读word、INTEN完整word、各INTTYPE的16个2位字段及各PADCFG的8个4位字段。但普通配置寄存器窄字段写需明确CPU端RMW或完整word组装策略；`plan_register_operation()`只返回field bus_mask／shifted bus_value，不执行RMW。full-word直接SW该值会overwrite其他位，不能凭field mask承诺保留未选择位。SET／CLR由于write-one副作用可自然保留未选择位，但必须显式 `allow_side_effect=True`，不得给WO端口添加读取oracle。

当前最小字段方案支撑E1声明准备；E2还需将计划经真实CPU合法程序执行，复用 `rv32i_sources.mmio_write_fragment`／`mmio_access_fragment` 并精确处理32位bus访问。真实行为与负例／fresh replay门禁、可关闭功能插件及M4五族验收均不在本次只读审计范围。

## E1 首批数据声明与软件验证

新增 [真实 sidecar](../../configs/peripherals/pulp_gpio/test_capability.json) 固定精确profile fingerprint，APB基础操作、上述四个完整32位字段及dir/out真实输出port_sample映射；SET／CLR省略独立reset且拒绝read，所有驱动副作用要求明确授权。无input_sample、L3 feature contract或registry修改。新增16项先RED缺文件拒绝后GREEN；联合能力解析51 passed／2 subtests（0.25秒）。仅声明准备：effective默认L1，verified未授，真实CPU字段程序执行／reset／读写与L2行为门禁仍待E2。
