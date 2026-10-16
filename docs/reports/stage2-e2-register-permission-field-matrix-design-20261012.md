# E1／E2 剩余寄存器与权限矩阵（只读设计，未执行）

依据原Stage2计划 E1／E2 与 G4：需source核对地址／字段／权限／mask／reset／宽度，仅在真实行为与观察依据核对后启用副作用；访问由CPU程序产生，不能给未声明语义写后读oracle。最小稳定plain寄存器写读、reset与权限边界仍须真实证明；scoped alias 成功不能勾选整个阶段。

当前v3 sidecar为14寄存器／72字段：8个word字段 PADDIR、PADOUT、PADOUTSET、PADOUTCLR、GPIOEN、PADIN、INTEN、INTSTATUS；32个2bit INTTYPE字段及32个4bit PADCFG字段。当前真实证据覆盖DIR／OUT baseline，PADCFG_0 pin0／pin7，INTTYPE_HIGH pin16／pin31的CPU RMW与窄READ，以及source-bound SET／CLR alias和B.INTEN写读0隔离。它不证明剩余60个窄字段或GPIOEN／PADIN／INTTYPE_LOW／PADCFG_1–3完整行为。所有字段source声明测试不等于全部DUT行为已验证。

compiler只生成32bit LW／SW，APB完整word访问byte_enable15；窄field通过完整word RMW与SRLI／ANDI／AND extraction产生真实CPU结果。不能据此宣称byte／halfword硬件访问支持。PADIN为RO；SET／CLR为WO；INTSTATUS为条件read-clear且目前compiler拒绝，即allow_side_effect=True也不能绕过。RTL `apb_gpio.sv` 第784行将PSLVERR固定为0，不能编造RO写／WO读hardware错误。Runtime拒绝证据是声明权限／程序安全规则，不是DUT错误响应；若以后测试硬件无效访问，应另明确授权生产路径和source语义，不通过放宽当前adapter偷送请求。

首个有意义软件或native前置负例矩阵：PADIN／INTSTATUS写、SET／CLR读；bool／负值／>32bit值；INTTYPE>3／PADCFG>15；未知field／endpoint；未显式RMW的窄write；read-clear即使allowTrue；非法result／slot／route／alignment。对 actual-object prepare 每项记录命令sequence、ticks、ledger、journal、slot和issued RAM前后不变，证明拒绝在effect之前。禁止用空mock作为完整native证据，也不把此policy拒绝升为verified DUT permission。

实际字段矩阵可拆为每次4fields：每field不同合法值的RMW后独立READ至真实RAM，按实际old bus值核 `(old & ~busmask) | busvalue`，保留邻接bit并读取field extraction。每chunk8cases（4RMW／4READ）、12CPU MMIO／36APB／4RAM；固定bootstrap6关联后总18关联／54APB。16chunks才覆盖32INTTYPE＋32PADCFG全部64窄字段，不能把每bank代表field当整bank证明；需要追踪历史4field与当前源码pin差异。包含pin0／15／16／31与每PADCFG bank的高bit边界，每次gen与fresh分开singleworker／180秒预算，首chunk实测margin，不将128cases合并超预算。

另需GPIOEN／INTEN稳定plain约束写读、PADIN与actual物理采样关联READ（无主机reset／input oracle），以及实际RESET command后epoch／generation／sample边界和真实CPU重新读回。IRQ相关字段测试保持actual B.INTEN隔离策略并检查没有新的pending pulse；若实际reset重启IRQ使隔离失效，应重新以CPU显式配置并核实，不host强制信号。本方案没有实现、运行新worker或授予完整L2／functional／RFuzz能力，原完整权限／mask／width／effect与observable reset范围保持。
