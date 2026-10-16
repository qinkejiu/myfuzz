# Ordinary PULP GPIO：alias、reset 与 permission 下一包设计

本报告只读核对当前生产代码与真实 RTL，不改变正在运行的门禁源码或 pins，不将声明规则当成已观察行为。上一包 verifier 的 READ/RW/RMW interval qualification 不等于完整 E1/E2 或 whole-component L2。

## 当前真实约束

真实 responder 为 `third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv`。低 32 位 PADOUT 地址为 0x0c，PADOUTSET 为 0x10，PADOUTCLR 为 0x14，PADDIR 为 0x00；RTL 通过 PADDR[6:2] 解码。PADOUTSET 对旧 PADOUT 与 PWDATA 作 OR，PADOUTCLR 作 AND NOT（297–316 行），普通 PADOUT 作全字覆盖（287–290 行）。当前 sidecar 的 SET/CLR 字段是 `bits`、32 位、wo、read_mask=0、write_mask=0xffffffff，副作用分别 `write_one_sets`/`write_one_clears`，引用实际源身份。PADOUT.value 则为普通 rw/none。alias READ 不是读回：PRDATA case 没有 SET/CLR 分支，default 为零。PADOUT READ 才返回 r_gpio_out（570–578 行）。不能用 alias READ 的零值验证 alias 写。

复用实际 collector sealed completed_accesses 的完整 chronology，包括未属于 selected request 的 bootstrap accesses；不按地址/值猜来源，不用 public journal 或 gpio_consumption/internal probe 授权。所有写仍要求实际 parsed command、真实 raw/base association、实际 CPU completed callback 与同一 target/endpoint/epoch/generation。当前 wrapper 声明真实 IP 无 PSTRB；partial bus-byte write 不应据 sidecar mask宣称支持，32 位写与显式 CPU RMW 保留原限制。

RTL reset 异步低有效：PADCFG、INTTYPE、PADDIR、PADOUT、INTEN、GPIOEN 均置零（209–220 行），status 置零（146–149 行）。PADIN 是输入同步状态，reset 后仍可随外部 pins/enable 更新；不能当作稳定 storage default。INTSTATUS 清除仅在没有 s_rise_int 的分支才发生（151–160 行），需真实 IRQ/引脚条件的独立规则，不能在此 alias/reset 包顺便承诺 read-clear。

当前真实 stream bootstrap 已主动覆盖 reset 值（按actual dual_source_wiring核对，修正本报告此前A/B基址写反）：gpio_b 基址0x40000000写 GPIOEN=0x101、INTEN=0x101、INTTYPE_LOW=0x10001；gpio_a 基址0x40001000写 PADDIR=0xff、GPIOEN=0xff、PADOUT=0。`make_pulp_dual_source_stream_bootstrap()` 的 fixed instructions在跳到online slots前执行。在线CPU读gpio_a PADDIR=0xff/PADOUT=0不能归因reset；gpio_a INTEN未由bootstrap或ISR写入，可作为完整reset来源与无affecting-write证明后的稳定候选，gpio_b PADDIR/PADOUT也未被bootstrap写入但仍须同样独立证据。A.gpio_out低8直接送B.gpio_in，不受DIR门控；B IRQ与CPU MEIE/MIE默认开启，任何输出观察需实际IRQ隔离条件。当前wholeScene warm/cold reset会重启CPU执行bootstrap；postboot被覆盖字段不能证明reset零值。未触字段也不能仅从epoch数值或数值等于声明授证。

权限方面，sidecar 的 ro/wo 是 compiler/source admission 的声明规则。实际 RTL PREADY 恒为1，PSLVERR 恒为0（783–784 行）；对未解码地址读取默认零、未解码写没有寄存器更新。不得声称硬件返回 permission error。PADIN 写或 alias READ 被 compiler 拒绝可认证为 host admission behavior，不能升级为 GPIO execution semantics。

## 最小 alias 实施契约

第一步只扩 code-owned verifier 规则，现有 Session/config/save/fresh channel 复用并增闭集规则字段，仍不接受 caller rule/provider。规则只适用精确实际 PULP native 32-pad profile/binding/sidecar/source fingerprints，target instance 不能跨 gpio_a/gpio_b。selected request 必须是 PADOUTSET.bits 或 PADOUTCLR.bits 的 register_write，explicit allow_side_effect=True，普通 fullword bus write。

给每个 selected alias 写寻找三段 sealed stream：同目标 PADOUT 的实际前读 R0、实际 alias 写 W、同目标 PADOUT 实际后读 R1。必须严格 ordinal/actual command 顺序 R0<W<R1、同 source execution/testcase/component/source epoch、同 target reset epoch、同 memory generation；使用全部 sealed accesses 检查区间，PADOUT/PADOUTSET/PADOUTCLR 的任何其它写都使该候选区间失效。没有 R0 不从 reset/default/先前 compiler value 推导旧值，没有 R1 不用当前 host RAM/port值补证。

SET 期望 `R1 == R0 | W`；CLR 期望 `R1 == R0 & (~W & 0xffffffff)`。同时检查完整 32 位结果，包括未触及位保持；不能仅核对 mask 中的 bits。R0/R1 必须为真实 CPU read callback响应与 APB response 相符。若 R1 是 selected register_read request，则既有 READ规则另外需要对应 later actual issued RAM result commit；R1 也可来自下一次 RMW 的前读，但只能作为 alias 写的 supporting observation，不能伪造独立 read request 资格。

证书绑定 exact requested alias field/op、relation_target PADOUT.value、before/write/after access IDs、source+target epochs、memory generation、actual request manifest 与规则源引用。proof_scope 继续 observed CPU register readback consistency；grants_storage/version_dependency/prerequisites/functional 全 False。snapshot 只增加获得 actual evidence 且 startup effective 的 exact alias register_write operation。未观察字段、read-clear、PADIN功能与 IRQ保持 gaps；不会以一个 alias positive 授 whole L2。

## Reset-default 的可执行前置工作

先明确原计划 reset-default 与当前 firmware 的观察窗口冲突。要授 observed reset_value，实际 CPU读必须处于 reset release 后、任何影响该寄存器的 bootstrap 写之前，并执行 LW→实际 RAM SW；对bootstrap已覆盖字段需 code-owned production mode 创造这个窗口；不能删除保存 template的 bootstrap bytes 或仅换 caller声明冒充既有固定selector。可另建固定 audited reset-read bootstrap selector，或实现 Session支持的 target-only reset barrier并证明 CPU原stream继续、actual target epoch更新且首次 target读前无写。二者属于更广reset字段的后续生产接线。最小首步可保留现bootstrap，只选择 gpio_a INTEN或gpio_b PADDIR/PADOUT等确实未被固定程序写入的字段，并新增真实reset来源seal与无先写证明；不能把现有 completed_accesses 的 epoch数值单独当作actualreset证据。

该后续 reset证书需实际 reset command/assert/deassert scope、target epoch transition、读观察区间与全部stream无先写证明，read→CPU response→私有issuedRAMcommit链，以及实际 environment/stimulus条件。首次只选稳定 rw配置寄存器（PADDIR/PADOUT/GPIOEN/INTEN/INTTYPE/PADCFG）与完整有效 pad位；PADIN与条件read-clear不纳入。warm memory保留与cold memorygeneration更新分别测试，旧epoch证书历史可保留但 current资格清空。

## TDD 与实际验收

软件 RED：SET/CLR无前读、无后读、alias READ冒充PADOUT、跨目标/epoch/generation、区间夹普通/alias写、只mask位正确但其余位错误、伪callback/publicrow、不匹配actual请求effect、source/sidecar关系漂移、snapshot错误alias或wholeoperation投影。保留真实三段positive、zero-mask/noop与重复SET/CLR幂等positive、RMW前读仅辅助而无独立read资格，以及 callbackfailure保留history/current清空。

建议真实 gate 最少依序请求 PADOUT READ、SET0、PADOUT READ、SET高位/低位、PADOUT READ、重复SET、PADOUT READ、CLR一组位、PADOUT READ、重复CLR、PADOUT READ。加入 ordinary PADOUT write间隔作为 negative区间，两个同profile实例交错避免跨实例；读结果都写独立实际RAMregion，原request/compiler/context/admission、sealed actual associations、RAM私有commit链均保存，freshCLI原请求完整重算所有wrapper/cert/snapshot。一次真实positive只能认证这组 exact rules，不能承诺所有72字段聚合等级。

生产 ownership 建议：verifier规则与purevalidator/tests一包；Session/schema/integration仅在证书新增闭集字段需要时单独接线；reset-only固定selector与观察barrier另包；permission admission tests独立保留，不添加虚假的硬件error verifier。正式实际门禁在所有源码软件冻结后运行，保留旧sourcepins/history，不改本轮 live gate。

## 成本报告 provenance 修正

优化测量进程62591复用了脚本输出路径，覆盖 `/tmp/myfuzz-register-verifier-guard-cost-20261012.json`；该路径现在是优化后的数据，不能当作原始 baseline JSON。优化文件另存 `/tmp/myfuzz-register-verifier-guard-cost-optimized-20261012.json`。原数据仅按进程89044此前真实工具输出恢复为 `/tmp/myfuzz-register-verifier-guard-cost-reported-baseline-20261012.json`，明确 provenance=reported-output reconstruction，未伪造原 cProfile。其 Runtime/Verifier/Runner mean分别64.9797/113.3269/231.6019ms；完整大槽配置126464bytes、2362000bytes，来自原实测输出而不是重新运行旧源码。


## 下一 alias 包的 schema 约定

下一 alias 声明使用 `ip_test_capability.v3`：v1 required根字段加 required register_aliases，feature_contract可选且present复用已有v2严格解析。现v2 mandatory feature_contract合同不改变。八字段关系行固定 source_register/source_field/destination_register/destination_field/endpoint_id/operation/bus_width/evidence_ref；operation仅set_bits/clear_bits，OR/AND_NOT只描述计算。v1/v2 aliases typed默认()，其source_document/fingerprint字节保持。完整72fields与尚未支持的gaps保留，不裁剪成wholeL2。具体软件私有来源链和下一纯规则/actualCPU-RAM测试设计见 [alias fixture设计](stage2-e2-alias-software-fixture-design-20261012.md)。本节是下一包设计，parser/verifier尚未实现，当前Task1仍33 RED/2兼容PASS。


2026-10-12只读补证：native postresetresume还有生产记录接线缺口。Session.advance_initial禁止已有case；runtime.prepare在真实CPU等待declaredonline缺word前不能执行。下一方案新closed18/19记录resume commands，默认16/17bytes不变；actualstartup/reset seal须独立source/binary/strictREADY私有来源证明，savedepoch不授权。失败halt/refuseexport，除非另有明确terminalcodec。细节见当前 [alias实施计划](../superpowers/plans/2026-10-12-stage2-declarative-register-alias-verification.md)。
