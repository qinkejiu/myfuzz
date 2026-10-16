# 窄字段64点之后的 word 字段门禁（只读提案）

当前14register／72field的8个word字段为PADDIR.value、PADOUT.value、PADOUTSET.bits、PADOUTCLR.bits、GPIOEN.value、PADIN.value、INTEN.value、INTSTATUS.value。全部32bit；PADIN只读，SET/CLR只写；INTSTATUS声明read_clears，实际RTL有条件清除，不可按普通无副作用READ偷送。本节不改生产、门禁或执行任何native，当前accepted仍36、chunk10 generation live。

| 字段 | 已有证据及源身份边界 | 后续具体缺口 |
|---|---|---|
| PADDIR/PADOUT | 旧runtime／verifier v5的真实CPU写读、physical端口及fresh/audit；Session source为历史冻结版本，不能借作当前f7da bundle通过 | 当前source闭包的完整普通WRITE→READ／物理端口关联复验；不能由postboot值授reset-default |
| SET/CLR | 旧alias四bracket与zero/fullmask包完整generation/fresh/audit；sidecarv3/verifier规则现仍存在，但旧Sessionsource不同 | 若要求当前统一source资格需新bundle重放完整before/write/after链；不得用alias效果推GPIO存储/version或wholeL2 |
| GPIOEN | bootstrap真实写入和可观察APB只是unselected transport证据，无当前selected普通写读审计包 | 新selected32bitWRITE→READ及actualRAM；enable对采样/时钟影响的语义需另有actualinput时序规则，不由读回自动授功能 |
| PADIN | bootstrap ISR可能读输入，未构成selected request／actualissuedRAM资格；无当前独立word门禁 | 显式RO READ至actualRAM，限定rawAPB→CPU→RAM；若要physical-input因果关系，必须实际输入／synchronizer采样时间依据与source-bound规则，不以host期望值或当前pad瞬时值代替 |
| INTEN | 当前f7da warm/cold包两selectedREAD与actualRAM完整generation/fresh/audit、history/current隔离；旧mask包B.INTEN WRITE0→READ0只属旧source | 当前非零普通WRITE→laterREAD行为；reset-resume不是reset-default certificate，observed0也无默认资格 |
| INTSTATUS | 当前compiler明确拒read_clears，即allow_side_effect=True也不能放行 | 条件read-clear源审计与显式compiler/admission/semantic rule，以及真实中断状态产生、READ、后READ；当前API不能完成此门禁，不准放宽成plainREAD |

可先做当前source普通word10原请求：B.INTEN WRITE0→READ(安全RAM)作为真实IRQ隔离，再A.PADDIR、PADOUT、GPIOEN、INTEN各WRITE→READ（8selectedcases）；其中非零值选择0x80000000以覆盖32位最高位，全部显式uint/fullword byte_enable15，无RMW、无sideeffect consent。结果位置逐case由actualRuntime检查安全RAM、所有slots/MMIO/initial/source-owned冲突；每pair完整APB／CPUcallback／privateissuedRAM链，current verifier ordinary_register_write_readback.v1与ordinary_register_read_result.v1，不以编译hash授证。B隔离只在actualCPU写读0后成立，持续记录实际CPU/A/B physicalIRQ、pending/policy与完整事件；如果脉冲未排空或新事务出现须保存解释，不host强制MIE／输入。

上述值不是唯一方案，DIR/OUT/GPIOEN改变真实端口和采样，必须核当前actuallink和同步影响。可以先分DIR/OUT与GPIOEN/INTEN两小包（每包真实B隔离2＋两pair4＝6cases），每次独立180秒generation/fresh和串行fullaudit，不为凑预算丢原case。之后单独selected PADIN READ门禁；受同步影响，应把READ观察scope与采样功能scope分开。

Permission验收当前已是actual prepare静态拒绝边界软件证据，非DUT返回错误：PADIN／INTSTATUS写、SET／CLR读、超field值、bool/负数、未知field/endpoint、未显式narrowRMW、readclearallowTrue、slot/result/router非法都应在真实command/ledger/journal/slot/issuedRAM无变更前拒绝。RTL PSLVERR固定0，不能要求硬件RO写或WO读报错以制造错误oracle。若原任务需探测无效硬件访问，应独立说明源语义与访问路径，不绕现adapter许可。

当前CPU编译仅LW/SW full32、APB byte_enable15；窄field的RMW/extraction不证明byte／halfword硬件访问。Reset-default未来必须actualreset/startup/source/build seal加无interveningwrites及CPU/APB/privateRAM读回，特别boot已覆盖DIR/OUT/GPIOEN/B.INTEN，不能把bootstrap重写结果当reset值。INTSTATUS条件清除还须排除s_rise_int同周期优先更新（RTL144–165），不能凭连续两次zero READ证明清除。原E1/E2完整permission／width／effects／reset／functional和Stage2目标均保留，不因64个窄字段单值通过提前关闭。

补充边界：B.INTEN0写读仅约束后续新中断条件，不能追溯抹去之前已pending/active pulse。真实pending状态与输入脉冲必须保留、排查并记录，无法据此强制quiet/MIE；高位EN/INTEN写读一致也不自动授功能资格。
