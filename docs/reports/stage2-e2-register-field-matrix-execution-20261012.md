# E2 全窄字段执行 inventory（2026-10-12）

状态：16chunks全部generation／fresh／独立audit已PASS；current64 exact指定单valuepoints（32个2bit INTTYPE＋32个4bit PADCFG），非全值穷举。word DIR_OUT独立auditPASS（仅3instance-specific pairs）；EN_INTEN独立auditPASS（仅3instance-specific pairs）；PADIN完整auditPASS（APB_CPU_RAM consistency）；current aliaszero完整auditPASS（仅2source-bound zero brackets）；current fullmask完整auditPASS（仅2brackets）；partial SET完整auditPASS（仅2SET brackets）；CLR完整auditPASS（仅2CLR brackets）；当前f7da permission14软件已通过，原完整Stage2保持OPEN。

当前sidecar为 `ip_test_capability.v3`，SHA `0cefc52e9300d9c0630642fa70ce7cce021035b218dfb64eea01045a618efc1d`。初始inventory历史检查点（后来16chunk逐字段单valuepoint结果见下）：当时尚无这一轮每字段完整RMW／READ＋认证fresh矩阵证据；此前verifier v5 native audit通过14重编译／29985events／6READ＋7RMW current证书，脚本明确窄READ四字段PADCFG_0.pin0／pin7、INTTYPE_HIGH.pin16／pin31，末值分别3／13／2／3。这是历史冻结source证据，保留旧pins，不以当前loader成功重授历史级别。其余60字段没有同类已核DUT行为证据；新矩阵拟覆盖全部64，包括历史4字段在当前source下重跑。

证据：[历史v5审计](../../runs/stage2-e2-register-verifier-cli-20261012-v5/independent-audit.json)、[历史case脚本](../../runs/stage2-e2-register-verifier-cli-20261012-v5/check.py)。只读取上述小audit JSON和脚本文字；没有加载大型trace／运行worker。

| Register | Field | word lsb | width | 当前本轮证据 | 历史native范围 | 后续chunk |
|---|---|---:|---:|---|---|---:|
| INTTYPE_LOW | pin0 | 0 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 1 |
| INTTYPE_LOW | pin1 | 2 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 1 |
| INTTYPE_LOW | pin2 | 4 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 2 |
| INTTYPE_LOW | pin3 | 6 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 2 |
| INTTYPE_LOW | pin4 | 8 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 2 |
| INTTYPE_LOW | pin5 | 10 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 2 |
| INTTYPE_LOW | pin6 | 12 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 3 |
| INTTYPE_LOW | pin7 | 14 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 3 |
| INTTYPE_LOW | pin8 | 16 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 3 |
| INTTYPE_LOW | pin9 | 18 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 3 |
| INTTYPE_LOW | pin10 | 20 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 4 |
| INTTYPE_LOW | pin11 | 22 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 4 |
| INTTYPE_LOW | pin12 | 24 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 4 |
| INTTYPE_LOW | pin13 | 26 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 4 |
| INTTYPE_LOW | pin14 | 28 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 1 |
| INTTYPE_LOW | pin15 | 30 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 1 |
| INTTYPE_HIGH | pin16 | 0 | 2 | 当前valuepoint已审计PASS | v5实际RMW＋窄READ；历史pins | 5 |
| INTTYPE_HIGH | pin17 | 2 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 5 |
| INTTYPE_HIGH | pin18 | 4 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 6 |
| INTTYPE_HIGH | pin19 | 6 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 6 |
| INTTYPE_HIGH | pin20 | 8 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 6 |
| INTTYPE_HIGH | pin21 | 10 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 6 |
| INTTYPE_HIGH | pin22 | 12 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 7 |
| INTTYPE_HIGH | pin23 | 14 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 7 |
| INTTYPE_HIGH | pin24 | 16 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 7 |
| INTTYPE_HIGH | pin25 | 18 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 7 |
| INTTYPE_HIGH | pin26 | 20 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 8 |
| INTTYPE_HIGH | pin27 | 22 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 8 |
| INTTYPE_HIGH | pin28 | 24 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 8 |
| INTTYPE_HIGH | pin29 | 26 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 8 |
| INTTYPE_HIGH | pin30 | 28 | 2 | 当前valuepoint已审计PASS | 未有逐field核实 | 5 |
| INTTYPE_HIGH | pin31 | 30 | 2 | 当前valuepoint已审计PASS | v5实际RMW＋窄READ；历史pins | 5 |
| PADCFG_0 | pin0 | 0 | 4 | 当前valuepoint已审计PASS | v5实际RMW＋窄READ；历史pins | 9 |
| PADCFG_0 | pin1 | 4 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 9 |
| PADCFG_0 | pin2 | 8 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 10 |
| PADCFG_0 | pin3 | 12 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 10 |
| PADCFG_0 | pin4 | 16 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 10 |
| PADCFG_0 | pin5 | 20 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 10 |
| PADCFG_0 | pin6 | 24 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 9 |
| PADCFG_0 | pin7 | 28 | 4 | 当前valuepoint已审计PASS | v5实际RMW＋窄READ；历史pins | 9 |
| PADCFG_1 | pin8 | 0 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 11 |
| PADCFG_1 | pin9 | 4 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 11 |
| PADCFG_1 | pin10 | 8 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 12 |
| PADCFG_1 | pin11 | 12 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 12 |
| PADCFG_1 | pin12 | 16 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 12 |
| PADCFG_1 | pin13 | 20 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 12 |
| PADCFG_1 | pin14 | 24 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 11 |
| PADCFG_1 | pin15 | 28 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 11 |
| PADCFG_2 | pin16 | 0 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 13 |
| PADCFG_2 | pin17 | 4 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 13 |
| PADCFG_2 | pin18 | 8 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 14 |
| PADCFG_2 | pin19 | 12 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 14 |
| PADCFG_2 | pin20 | 16 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 14 |
| PADCFG_2 | pin21 | 20 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 14 |
| PADCFG_2 | pin22 | 24 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 13 |
| PADCFG_2 | pin23 | 28 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 13 |
| PADCFG_3 | pin24 | 0 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 15 |
| PADCFG_3 | pin25 | 4 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 15 |
| PADCFG_3 | pin26 | 8 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 16 |
| PADCFG_3 | pin27 | 12 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 16 |
| PADCFG_3 | pin28 | 16 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 16 |
| PADCFG_3 | pin29 | 20 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 16 |
| PADCFG_3 | pin30 | 24 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 15 |
| PADCFG_3 | pin31 | 28 | 4 | 当前valuepoint已审计PASS | 未有逐field核实 | 15 |

## 十六个独立chunk（仅执行计划）

每chunk4fields，每field实际CPU explicit RMW后READ至独立安全RAM，共8cases／12MMIO／36caseAPB／4RAM；固定bootstrap6关联加case12为18关联／54APB。每次generation和fresh独立singleworker／180秒、原RSS策略，先实测第一chunk余量，不合并128cases超过资源界限。当前firstchunk INTTYPE_LOW.pin0／pin1／pin14／pin15已由Root generation70951完成生成，fresh65778已通过，目录 `runs/stage2-e2-register-field-inttype-low-20261012-v1`，8cases／4fields尚待fresh与audit最终验收，不预填verified；own empty cache／不复制旧cache、singleworker／180秒，无并行native或重型audit，当前f7da／bfbb／verifier037源码冻结。其余15chunks仍为提议、未执行。

| Chunk | Register | exact fields | 状态 |
|---:|---|---|---|
| 1 | INTTYPE_LOW | pin0, pin1, pin14, pin15 | 当前valuepoint已审计PASS |
| 2 | INTTYPE_LOW | pin2, pin3, pin4, pin5 | 当前valuepoint已审计PASS |
| 3 | INTTYPE_LOW | pin6, pin7, pin8, pin9 | 当前valuepoint已审计PASS |
| 4 | INTTYPE_LOW | pin10, pin11, pin12, pin13 | 当前valuepoint已审计PASS |
| 5 | INTTYPE_HIGH | pin16, pin17, pin30, pin31 | 当前valuepoint已审计PASS |
| 6 | INTTYPE_HIGH | pin18, pin19, pin20, pin21 | 当前valuepoint已审计PASS |
| 7 | INTTYPE_HIGH | pin22, pin23, pin24, pin25 | 当前valuepoint已审计PASS |
| 8 | INTTYPE_HIGH | pin26, pin27, pin28, pin29 | 当前valuepoint已审计PASS |
| 9 | PADCFG_0 | pin0, pin1, pin6, pin7 | 当前valuepoint已审计PASS |
| 10 | PADCFG_0 | pin2, pin3, pin4, pin5 | 当前valuepoint已审计PASS |
| 11 | PADCFG_1 | pin8, pin9, pin14, pin15 | 当前valuepoint已审计PASS |
| 12 | PADCFG_1 | pin10, pin11, pin12, pin13 | 当前valuepoint已审计PASS |
| 13 | PADCFG_2 | pin16, pin17, pin22, pin23 | 当前valuepoint已审计PASS |
| 14 | PADCFG_2 | pin18, pin19, pin20, pin21 | 当前valuepoint已审计PASS |
| 15 | PADCFG_3 | pin24, pin25, pin30, pin31 | 当前valuepoint已审计PASS |
| 16 | PADCFG_3 | pin26, pin27, pin28, pin29 | 当前valuepoint已审计PASS |

每RMW以真实old bus核 `(old & ~busmask) | busvalue`，随后真实CPU field-relative READ／RAM确认目标field，并证明邻接bits不被破坏。所有字段都需exactscope／epoch／generation／CPU response／private RAM／source-ref绑定；同值／极值、错scope、intervening write等仍按各项真实规则检查，不由host假设reset。汇总必须保留每chunk当前源码／sidecar／artifact／binary pins和各请求tuple，不能把一次新版fingerprint与旧trace拼成权限。

## 额外word字段与原scope（单列OPEN）

PADDIR／PADOUT已有历史plain写读与部分实际证据；SET／CLR四非zero/fullmask括号及zero/fullmask门禁已各自审计，但不等于所有effect矩阵。GPIOEN稳定plain约束写读、INTEN非零及边界行为、PADIN真实物理输入对应READ、INTSTATUS条件read-clear仍OPEN：当前compiler拒read-clear，即allowTrue也不能绕过；不能称无条件清除。RO写／WO读／value width／narrow mask等14项实际对象软件拒绝已通过（22.92秒），属于前effect声明policy，不是RTL PSLVERR错误；RTL PSLVERR固定0。

访问仍只支持32bit LW／SW＋APB fullword15byte-enable；byte／halfwordnative边界与支持声明须单独说明，不虚构小访问。reset-resume native包审计证明重启后真实bootstrap／驻留程序执行与read consistency；它没有证明bootstrap重新配置之前瞬时PADDIR／OUT等RTL reset defaults。native observable reset defaults、完整权限／width／mask／effect矩阵和capability等级证据继续OPEN。16chunks即便全部通过也不代表完整E2、D5／D6／D8或E3–I完成，不授functional／RFuzz／BFM能力。


下一chunk2 INTTYPE_LOW.pin2／pin3／pin4／pin5由renderer准备独立 `runs/stage2-e2-register-field-inttype-low-pins2-5-20261012-v1`，当前未执行，不覆盖chunk1当前worker／旧证据。轻量检查chunk1已产生resource／summary／最终phase文件且282sourcepins当前一致；最终counter和fresh／audit状态由Root实际worker终态核实后更新，不能以文件出现提前宣称整chunk完成。


首chunk generation实际终态：133.03611893299967秒、peak2,046,107,648／limit3,134,181,376／available5,281,665,024／workers1／DUTFalse；8cases／18,218events／18关联／36selectedAPB／4RAM，4RMW＋4READ共8证书／gaps=[]。54allAPB待audit实际核对，fresh65778尚运行，不将4fields计为最终通过。semantic6150db278beb3f658d4108ea971904433e496843b9423b29879fc07b81e68bd6，identitydd2397a6db1a0790edd216108b60f8a22e434682ed07084e62333ba8aca5c1d4；chunk2仍prepared_not_executed。


首chunk fresh65778已exit0／PASS：117.5034022149921秒、peak1,849,569,280／limit3,116,818,432／available5,264,302,080／worker1／DUTFalse；18,218events／semantic6150db…bd6与完整ordinary／verifier／preflight一致。独立audit进行中，不计最终验收。exact已执行value points为INTTYPE_LOW.pin0=1、pin1=2、pin14=3、pin15=1，各一次合法CPU RMW＋READ；不是逐field 0..3穷举，不证明fullwidth或reset boundary完整。chunk2仍prepared未执行。


首chunk FULLaudit55320已终态PASS：8exact重编译／9产物／282pins／18关联／54总APB／12selectedMMIO／36selectedAPB／4RAM／18,218events／current及historical各8证书、IRQ2,766samples／0events、cache282／351／282 currentbinary与资源／fresh一致。current f7da／bfbb／verifier037下LOW.pin0=1／pin1=2／pin14=3／pin15=1四个合法valuepoint已验收，非逐字段全部值穷举；[独立报告](stage2-e2-inttype-low-first-field-independent-audit-20261012.md)。chunk2 LOW.pin2／3／4／5 generation86087已实际启动（own empty cache／singleworker180），尚未通过；不改其余字段或整bank授级。


下一chunk3 LOW.pin6=3／pin7=1／pin8=2／pin9=3目录 `runs/stage2-e2-register-field-inttype-low-pins6-9-20261012-v1` 由renderer准备，尚未执行。chunk2 generation86087轻量phase已到before_finish_export（110.457865秒），282current pins一致，尚未见resource／summary终态文件，不推断通过；firstchunk四valuepoints已审计PASS不变。


chunk2 generation86087已exit0／complete：132.4123047089961秒、peak2,046,140,416／limit3,134,119,936／available5,281,603,584／worker1／DUTFalse，8cases／18,227events／18关联／36selectedAPB／4RAM／8证书gaps=[]。exact valuepoints LOW.pin2=2／pin3=3／pin4=1／pin5=2；semanticfc2b38cd09d6259d221f9e949fcc74dd8e32baea57d200019033a1cb0e933502，identitye0146133dbc57db8ce2fd52faa8582b94cce3e64658d443e75ec72d3ef836b49。fresh72553正在独立180秒预算运行，audit待完成；这4valuepoints尚未最终验收。chunk3脚本已准备完整（check2cce78…3ff3f1），仍未执行。


chunk2 fresh72553已exit0／complete：117.86604998000257秒，peak1,850,150,912／limit3,119,108,096／available5,266,591,744／worker1／DUTFalse；完整18,227events／fc2b38…3502 semantic及全部wrappers相等。fullaudit正在执行、尚未最终验收；四valuepoints只完成gen＋fresh，chunk3仍prepared未执行。


chunk2 fullaudit16526已PASS：18,227events／18关联／54总APB／8exact重编译／9产物／282pins／4RMW＋4READ／12selectedMMIO／36selectedAPB／4RAM，fullIRQ／currentcache／fresh／resources相等；[独立报告](stage2-e2-inttype-low-pins2-5-independent-audit-20261012.md)。LOW2=2／3=3／4=1／5=2已验收，合并前chunk共8fields各一个合法valuepoint，不是allvalues。chunk3 LOW6=3／7=1／8=2／9=3 generation18307已实际启动，own empty cache／180秒／singleworker／无audit竞争，尚未通过；其余13chunks只是计划。


下一chunk4 LOW.pin10=1／pin11=2／pin12=3／pin13=1由renderer准备新pins10-13 v1目录，NOTEXECUTED。chunk3轻量phase已到before_authenticated_save117.2213秒，282pins当前一致且尚无resource／summary，仍运行不预授通过；accepted仍仅前2chunks8个单valuepoints，不升级全bank。


chunk3 generation18307已exit0／complete：132.3857018879935秒、peak2,046,533,632／limit3,117,260,800／available5,264,744,448／workers1／DUTFalse，actual8cases／18,227events／18关联／36selectedAPB／4RAM／8证书gaps=[]。仅LOW6=3／7=1／8=2／9=3各指定合法RMW＋READ；semantic1aef8e3bf66496602c69ea66ecab9e41a61306b00c5b3f66f345a83e1ef59186，identitydc199c25d57bb5709bb2f701cdcf35e49c76ccea092ae32906dedb9a49782e69。fresh64101独立180秒运行，audit待完成，尚未最终验收；chunk4准备完整但未执行。


chunk3 fresh64101已终态PASS：118.39475587400375秒、peak1,850,974,208／limit3,117,637,632／available5,265,121,280／workers1／DUTFalse，fullmatches18,227events／1aef8e…59186 semantic及全部state／preflight一致。audit正在执行，尚未计入accepted；accepted仍8points，nextchunk4仍prepared未执行。


chunk3 fullaudit55905已终态PASS，LOW6=3／7=1／8=2／9=3 exact合法RMW＋READ valuepoints已验收；[独立报告](stage2-e2-inttype-low-pins6-9-independent-audit-20261012.md)。前3chunks共12current field-valuepoints，不是每字段0..3穷举／整bank授级。chunk4 LOW10=1／11=2／12=3／13=1 generation12344实际运行，own empty cache／180秒singleworker、审计内存已释放，尚未通过；剩余12chunks仅提议。


下一chunk5 GPIO A INTTYPE_HIGH.pin16=1／pin17=2／pin30=3／pin31=2由renderer准备独立field-inttype-high v1目录，未执行。pin31=2将实际使用bus bit31，但仅一合法valuepoint，不能偷借旧high16／31历史pins证明当前chunk。当前accepted12个LOW指定points，chunk4phase已到atexit／summary写入但尚无resource，须Root实际handle终态后更新，不能由文件存在推断通过。


chunk4 generation12344终态exit0／complete：132.04403735398955秒、peak2,046,468,096／limit3,120,099,328／available5,267,582,976／worker1／DUTFalse，8cases／18,227events／18关联／36selectedAPB／4RAM／4RMW＋4READ共8证书gaps=[]；exactLOW10=1／11=2／12=3／13=1。semantic9037bcc96ff0c3cbdcb5abe475d3cb6819611c0c26b8a090453c5d0b2173205a，identitye826809ad27363c683eb47ef79fa06714532ee48d91351847cd64999f91428a7。fresh78630正在独立180秒预算运行、audit待完成，仍未最终验收。HIGH准备tuple/register明确INTTYPE_HIGH（check67e0…a8b43），未执行。


chunk4 fresh78630已exit0／complete：119.3633515190013秒、peak1,847,529,472／limit3,129,950,208／available5,277,433,856，完整fullmatch断言通过。独立audit刚启动、尚未验收，accepted仍12points，不提前记16；HIGH chunk5准备未执行，完整Stage2保持OPEN。


chunk4 fullaudit72392终态PASS，current LOW全部16字段各指定一次合法valuepoint已验收，不是各字段0..3穷举。HIGH chunk5 generation95236已实际启动、尚未通过，actualprofile PAD_NUM32／当前source与script SHA／AST／tuple preflight核对；新HIGH证据不能借历史pin16／31。chunk6 HIGH18／19／20／21 prepared NOTEXECUTED（check29231607528650ec7e4cdfee1b4bea8da20c11713b1b73c5d31d2bd81bacd87f）。原完整scope仍OPEN。


HIGH首组generation95236终态exit0／complete：132.3070836919942秒、available5,243,768,832／peak2,046,111,744／limit3,096,285,184／worker1／DUTFalse，8cases／18,218events／18关联；identity09fb6bc107ba6eb27d0dbca92e25f12f1169f8de0e18bf107a32fe435d6e9337，semantic245790b508f25245a9c0170049cc153789cf38505c087f85c90e5b3d4573b671。fresh59768实际运行、audit待完成，HIGH四points未最终验收；accepted仍16LOW。chunk7 HIGH22–25 prepared未执行，check17bb02e24fc5619ff0d872fe83ec14cbe5a11b8da24c5a153382ecb35cbb513b。


HIGH首组fresh59768终态exit0／complete：116.24226334200648秒、available5,239,918,592／peak1,848,770,560／limit3,092,434,944／worker1／DUTFalse，完整trace／count／semantic／ordinary／verifier／preflight一致。fullaudit正在执行，HIGH四points未accepted，accepted仍16LOW。


HIGH首组fullaudit45969已终态PASS（passed_separate_generation_and_fresh）：18,218events／8current＋8historical证书／identity与semantic及完整资源fresh一致。accepted current20 exact单取值points（16LOW＋4HIGH），不是每字段全值穷举。chunk6 HIGH18–21 generation50635实际运行、未通过，own empty cache／singleworker180／源码冻结；chunk8 HIGH26–29 prepared未执行（checkcd629e083eca91a6af04c84353de6bae41d7d80a9191a3dd0e50c42c65fbfd5f）。


chunk6 HIGH18–21 generation50635已exit0／complete：131.0059881999914秒、available5,244,407,808／peak2,046,242,816／limit3,096,924,160／worker1／DUTFalse，8cases／18,227events／18关联；identitybfefd001b7362b66f87e53d4836276cca1f33bc59f28b39ad1529a12d883ea5f，semantic98e9f7e2784f117be50ac610649e8c3c404b74b429c7322101ad2da51999e800。fresh69170实际运行，尚未验收、accepted仍20。chunk9 PADCFG_0.pin0／1／6／7 values1／5／10／15、width4／offset0x28 typed准备未执行（check2e867fd2e5c8711a43d6cd975960809a1b178b3bc2037b12e26e234d22ac5773）；旧pin0／7历史scope不能替代新运行。


chunk6 fresh69170终态exit0／complete：117.59755330599728秒、available5,260,267,520／peak1,849,614,336／limit3,112,783,872／worker1／DUTFalse，fulltrace／wrappers／count／semantic／preflight断言通过；audit待终态，accepted仍20。chunk10 PADCFG_0.pin2／3／4／5 values2／6／9／14准备未执行（checkaec6fc14944337001a3018ded94930b3dabbb9bd5827506ea91bd4ca452d525c）。


chunk6 fullaudit45184终态PASS，18,227events／8证书／exacttuple与完整generation／fresh资源一致，见[独立报告](stage2-e2-inttype-high-pins18-21-independent-audit-20261012.md)。accepted current24指定points（16LOW＋8HIGH），非全部值穷举。chunk7 HIGH22／23／24／25 values3／1／2／3 generation42268实际运行，own absent cache／singleworker180／无audit竞争，尚未通过。


chunk7 generation42268终态exit0／complete：131.44182803299918秒、available5,353,672,704／peak2,046,332,928／limit3,206,189,056／worker1／DUTFalse，8cases／18,227events／18关联；identity8591e10968220d42591ad0b9f067e02a7ad56f3c8060db48b06e40b2e07ee20c，semantic74a9b0f04f6fb3d555729d6304b74c0aa2baf046a23ed9bf1496d094efc36bf6。fresh75326实际运行，audit未完成、accepted仍24。chunk12 PADCFG_1.pin10–13 values2／6／9／14准备未执行（check2ac8b26161138880081ec2ae7817c4be869c8e0f8ca3d0c99d61eb07ee7e29dd）。


chunk7 fresh75326已exit0／complete：116.5613808670023秒、available5,327,286,272／peak1,849,888,768／limit3,179,802,624／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过；fullaudit待终态、accepted仍24。chunk13 PADCFG_2.pin16／17／22／23 values1／5／10／15 prepared未执行（check8df01c68341cd9d0509658b23a1bdc868b2b3a480bbeca4fceace6f28f3ab8d6）。


chunk7 fullaudit93696终态PASS，exacttuple／18,227events／8证书与完整fresh一致。accepted current28指定单points（16LOW＋12HIGH），非全值穷举。chunk8 HIGH26／27／28／29 values1／2／3／1 generation70283已实际启动，current source/script SHA／AST／tuple核对，own absent cache／singleworker180／无overlap，尚未通过。


chunk8 generation70283已exit0／complete：132.64775778599142秒、available5,336,645,632／peak2,046,345,216／limit3,189,161,984／worker1／DUTFalse，8cases／18,227events／18关联；identitycc235dcd53d9b5cc761c3ad4a6c45792b0abd22e7acb49e24a1e7f67a54fe803，semantic03475e3673e45aca55e8bfd11ab9193d3734ca2134f5f05fae54bc32db9a33d2。fresh31823实际运行、audit待完成，accepted仍28。chunk15 PADCFG_3.pin24／25／30／31 values1／5／10／15 prepared未执行（check6b6e2d1645b003dcf3b8cddc63c6529eca4d727064d9038b19aa1005dc5fc5a4）。


chunk8 fresh31823已exit0／complete：118.06382439300069秒、available5,314,101,248／peak1,851,424,768／limit3,166,617,600／worker1／DUTFalse，fulltrace／wrappers／semantic／count／preflight通过；audit待终态、accepted仍28。chunk16 PADCFG_3.pin26–29 values2／6／9／14 prepared未执行（check6b6aec3b15f8b3d6eb06a499794651ff892d87070a0b7252c744dc92786a16b2）。全部16chunks脚本准备不代表全部executed或accepted，矩阵保留逐组状态。


chunk8 fullaudit79481已终态PASS，exacttuple／18,227events／8证书及完整fresh一致。accepted current32指定points（16LOW＋16HIGH），每INTTYPE field只一个合法值，不是全值穷举／整bank能力授级。chunk9 PADCFG_0.pin0／1／6／7 values1／5／10／15 generation38477实际运行、尚未通过，offset0x28／current source-script SHA／AST／exacttuple核对，own absent cache／singleworker180／无overlap；旧PADCFG0.pin0／7历史证据仍独立。


## 16组当前准备文件轻量核对（不运行脚本）

全部16组preparation／current source字节与script SHA一致，四脚本AST可解析；check的register literal与enumerate exact field-value tuples同preparation，64个(reg,field,lsb,width)完整等于sidecar：32 INTTYPE＋32 PADCFG、无重复／漏项。accepted仍32points，chunk9generation已通过／fresh60729运行，未验收，10–16仅prepared，不以prepared metadata的未执行初值覆盖实际历史。核对产物仅 `/tmp/stage2-field-preparation-review.json`，没有读取trace／manifest或运行factory。

| Chunk | Register／field:value | actual prepared directory | check SHA256 | 当前状态 |
|---:|---|---|---|---|
| 1 | INTTYPE_LOW pin0=1, pin1=2, pin14=3, pin15=1 | runs/stage2-e2-register-field-inttype-low-20261012-v1 | `3157822aa993782e0139046b82a17f2b3edb86264306731379bb0500ea33096a` | 单valuepoint已审计PASS |
| 2 | INTTYPE_LOW pin2=2, pin3=3, pin4=1, pin5=2 | runs/stage2-e2-register-field-inttype-low-pins2-5-20261012-v1 | `6561a9ca2452d2359a7aa2aaa8e325a6f763f78b55c03f5c4a9e51d27e762821` | 单valuepoint已审计PASS |
| 3 | INTTYPE_LOW pin6=3, pin7=1, pin8=2, pin9=3 | runs/stage2-e2-register-field-inttype-low-pins6-9-20261012-v1 | `2cce78e0caa7cb0b28dcf35190d7456331a61c81954d91e3e51c9c00fe3ff3f1` | 单valuepoint已审计PASS |
| 4 | INTTYPE_LOW pin10=1, pin11=2, pin12=3, pin13=1 | runs/stage2-e2-register-field-inttype-low-pins10-13-20261012-v1 | `ffc36df87a6f29bd16760294a3f3ca810accbe70626997ee4284f140d6741568` | 单valuepoint已审计PASS |
| 5 | INTTYPE_HIGH pin16=1, pin17=2, pin30=3, pin31=2 | runs/stage2-e2-register-field-inttype-high-20261012-v1 | `67e0d32f3377b236df925ecbe8b823359794c5f9bd7435b17aece6fd054a8b43` | 单valuepoint已审计PASS |
| 6 | INTTYPE_HIGH pin18=2, pin19=3, pin20=1, pin21=2 | runs/stage2-e2-register-field-inttype-high-pins18-21-20261012-v1 | `29231607528650ec7e4cdfee1b4bea8da20c11713b1b73c5d31d2bd81bacd87f` | 单valuepoint已审计PASS |
| 7 | INTTYPE_HIGH pin22=3, pin23=1, pin24=2, pin25=3 | runs/stage2-e2-register-field-inttype-high-pins22-25-20261012-v1 | `17bb02e24fc5619ff0d872fe83ec14cbe5a11b8da24c5a153382ecb35cbb513b` | 单valuepoint已审计PASS |
| 8 | INTTYPE_HIGH pin26=1, pin27=2, pin28=3, pin29=1 | runs/stage2-e2-register-field-inttype-high-pins26-29-20261012-v1 | `cd629e083eca91a6af04c84353de6bae41d7d80a9191a3dd0e50c42c65fbfd5f` | 单valuepoint已审计PASS |
| 9 | PADCFG_0 pin0=1, pin1=5, pin6=10, pin7=15 | runs/stage2-e2-register-field-padcfg0-20261012-v1 | `2e867fd2e5c8711a43d6cd975960809a1b178b3bc2037b12e26e234d22ac5773` | generation通过／fresh运行；未验收 |
| 10 | PADCFG_0 pin2=2, pin3=6, pin4=9, pin5=14 | runs/stage2-e2-register-field-padcfg0-pins2-5-20261012-v1 | `aec6fc14944337001a3018ded94930b3dabbb9bd5827506ea91bd4ca452d525c` | prepared；未执行 |
| 11 | PADCFG_1 pin8=1, pin9=5, pin14=10, pin15=15 | runs/stage2-e2-register-field-padcfg1-20261012-v1 | `ed47521a41ad7a66ff1ce810e0996f632f79df9b7160e423f7d42238ad8c051d` | prepared；未执行 |
| 12 | PADCFG_1 pin10=2, pin11=6, pin12=9, pin13=14 | runs/stage2-e2-register-field-padcfg1-pins10-13-20261012-v1 | `2ac8b26161138880081ec2ae7817c4be869c8e0f8ca3d0c99d61eb07ee7e29dd` | prepared；未执行 |
| 13 | PADCFG_2 pin16=1, pin17=5, pin22=10, pin23=15 | runs/stage2-e2-register-field-padcfg2-20261012-v1 | `8df01c68341cd9d0509658b23a1bdc868b2b3a480bbeca4fceace6f28f3ab8d6` | prepared；未执行 |
| 14 | PADCFG_2 pin18=2, pin19=6, pin20=9, pin21=14 | runs/stage2-e2-register-field-padcfg2-pins18-21-20261012-v1 | `66b60895eadf6bf9f268c5b92cbcf32f90aa079361666701ded1bd900981dd39` | prepared；未执行 |
| 15 | PADCFG_3 pin24=1, pin25=5, pin30=10, pin31=15 | runs/stage2-e2-register-field-padcfg3-20261012-v1 | `6b6e2d1645b003dcf3b8cddc63c6529eca4d727064d9038b19aa1005dc5fc5a4` | prepared；未执行 |
| 16 | PADCFG_3 pin26=2, pin27=6, pin28=9, pin29=14 | runs/stage2-e2-register-field-padcfg3-pins26-29-20261012-v1 | `6b6aec3b15f8b3d6eb06a499794651ff892d87070a0b7252c744dc92786a16b2` | prepared；未执行 |


chunk9 generation38477已exit0／complete：132.42977688899555秒、available5,366,063,104／peak2,046,464,000／limit3,218,579,456／worker1／DUTFalse，8cases／18,222events／18关联；identity44258bd102bc2fe743413c5ee8f286d3274d79fe249f4f2901d4426f64ca6f4a，semantic46797d405211e4469177bbb8f12157dc7861614a0cb8409e76cd71ea0e71c61f。fresh60729运行、audit待完成，accepted仍32。当前64字段清单／16准备目录已核无漏重，9..16真实目录／values／check SHA列于上表；11与14过时未准备标记已改为prepared未执行。


chunk9 fresh60729已exit0／complete：119.73843699799909秒、available5,316,136,960／peak1,851,084,800／limit3,168,653,312／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。独立audit待终态，accepted仍32，不提前36；Root已复核清单exact64无漏重，nextchunk10当前SHA／AST／tuple／own absent cache preflight通过但尚未执行。


chunk9 fullaudit99824终态PASS，exactPADCFG_0.pin0／1／6／7 values1／5／10／15，18,222events／8证书与完整fresh一致；[独立报告](stage2-e2-padcfg0-first-field-independent-audit-20261012.md)。accepted current36单points（32INTTYPE＋4PADCFG），非穷举。chunk10 PADCFG_0.pin2–5 values2／6／9／14 generation48852实际运行，offset0x28／current source-script SHA／AST／tuple preflight／own absent cache／singleworker180，无overlap、未通过。准备清单核对表是当时准备快照，本段与主状态表为后续执行状态。


chunk10 generation48852终态exit0／complete：133.4572914129967秒、available5,361,512,448／peak2,046,603,264／limit3,214,028,800／worker1／DUTFalse，8cases／18,231events／18关联；identitye2af70dcba330380420cf32369c0253e879444430b2beecd16bebeddc48c5d83，semantic67494d72ff894fe4d626acec629d51c830fbeafb35b16dbbeb17d9f01c75f007。fresh60114实际运行、audit待完成，accepted仍36，不能计40或整PADCFG bank通过。


chunk10 fresh60114终态exit0／complete：118.20331636900664秒、available5,377,863,680／peak1,850,490,880／limit3,230,380,032／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。独立audit待终态、accepted仍36，不提前40。chunk11 PADCFG_1首组 current SHA／AST／tuple／offset0x2c／own absent cache preflight通过，仍未执行；remaining word gate设计只读审查不作为actual通过证据。


chunk10 fullaudit30129终态PASS，exactPADCFG_0.pin2–5 values2／6／9／14、18,231events／8证书与完整fresh一致。accepted current40指定单points（32INTTYPE＋8PADCFG0），非全值穷举。chunk11 PADCFG_1.pin8／9／14／15 values1／5／10／15 generation12336实际运行，offset0x2c／current source-script SHA／AST／tuple／own absent cache／singleworker180／无overlap，尚未通过；word设计审查无阻断仍未执行。


chunk11 generation12336终态exit0／complete：132.28506910100987秒、available5,405,487,104／peak2,046,394,368／limit3,258,003,456／worker1／DUTFalse，8cases／18,222events／18关联；identitybac307e0868f357f33424be2324860c613a4038ea4c9826c587d07b5368946a1，semantic83c1e86dff21dea624848f56050defc2240533f5d8aee5f9b86a929222edf20b。fresh25753实际运行，audit待完成，accepted仍40。reviewed wordDIR／OUT六request包仅准备，将在16matrixchunks之后另行运行，不预授native通过。


chunk11 fresh25753已exit0／complete：118.60419732998707秒、available5,349,089,280／peak1,850,675,200／limit3,201,605,632／worker1／DUTFalse，fulltrace／wrappers／count／semantic／preflight通过。fieldaudit待终态，accepted仍40；chunk12 current SHA／AST／tuple／offset0x2c／own absent cache preflight通过仍未执行。DIR_OUT word包checkd9937f10cde2802c2ba94be30a90068ecbfd57eb8bdf5b8f9a20a1babd6f7677仅准备，待16matrixchunks后另独立审查／执行。


chunk11 fullaudit57934终态PASS，exactPADCFG_1.pin8／9／14／15 values1／5／10／15、18,222events／8证书与完整fresh一致。accepted current44单valuepoints（32INTTYPE＋12PADCFG），非全值穷举。chunk12 PADCFG_1.pin10–13 values2／6／9／14 generation10967实际运行，offset0x2c／current source-script SHA／AST／tuple／own absent cache／singleworker180，无overlap、未通过；word仍未运行、独立审计仅准备。


chunk12 generation10967终态exit0／complete：133.12426655500894秒、available5,433,249,792／peak2,046,672,896／limit3,285,766,144／worker1／DUTFalse，8cases／18,231events／18关联；identityb150b59f8fab199cecf578b43e0fe59fc90e95421171d747e3cf1f386ad0e186，semanticef8046faf01aac1acae735a22a9b03e2b2109e0b5a0ecda55dcc35d3909c6d1f。fresh17134实际运行，audit待完成、accepted仍44。第二word GPIOEN_INTEN六case包仅准备，待16matrixchunks之后，未运行native。


chunk12 fresh17134终态exit0／complete：118.8060304679966秒、available5,397,753,856／peak1,850,212,352／limit3,250,270,208／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过；fieldaudit待终态、accepted仍44，不提前48。chunk13 offset0x30／current源脚本SHA／AST／tuple／own absent cache preflight通过仍未执行。GPIOEN_INTEN第二word包prepared check590d73840cd3aad76528bf3b7ce78e40a89c9eb7d5706a105f7afbdfb3d932f5，轻量review无阻断／独立audit准备，仍待16矩阵后执行。


chunk12 fullaudit8463终态PASS，exactPADCFG_1.pin10–13 values2／6／9／14、18,231events／8证书与完整fresh一致。accepted current48指定单points（32INTTYPE＋16PADCFG），非全值穷举。chunk13 PADCFG_2.pin16／17／22／23 values1／5／10／15 generation92288实际运行，offset0x30／current source-script SHA／AST／tuple／own absent cache／singleworker180，无overlap、未通过；两个word包仍prepared未执行。


chunk13 generation92288已exit0／complete：132.9991300420079秒、available5,449,052,160／peak2,046,648,320／limit3,301,568,512／worker1／DUTFalse，8cases／18,222events／18关联；identity6d3f9c74e46d4610efc2797a1a9be59a031551f492da5fc41fc6a40011e14eb5，semanticbd5c67e2b496e97f10d5a6332308ab2dff7d8fca480cae6b8402541b99ca5b4a。fresh97116实际运行，audit待完成，accepted仍48。PADIN word四request包prepared（check219240fa759d14f1d9aa2628d67b212ab3dcb431f1038120a1ba2e8c0cde9c8c），仅APB→CPU→RAM consistency scope，不授physical sampling／reset证明，待16matrix后执行。


chunk13 fresh97116终态exit0／complete：119.25131022800633秒、available5,386,960,896／peak1,850,802,176／limit3,239,477,248／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。fullaudit待终态，accepted仍48、不提前52；chunk14 offset0x30 current SHA／AST／tuple／own absent cache preflight通过未执行。PADIN word轻量review无阻断／独立audit已准备，仍未执行。


chunk13 fullaudit35340终态PASS，exactPADCFG_2.pin16／17／22／23 values1／5／10／15、18,222events／8证书及完整fresh一致；[独立报告](stage2-e2-padcfg2-first-field-independent-audit-20261012.md)。accepted current52单points（32INTTYPE＋20PADCFG），非全值穷举。chunk14 PADCFG_2.pin18–21 values2／6／9／14 generation43790实际运行，offset0x30／current source-script SHA／AST／tuple／own absent cache／singleworker180／无overlap、未通过；3word包仍prepared未执行。


chunk14 generation43790终态exit0／complete：132.3194965099974秒、available5,438,459,904／peak2,046,128,128／limit3,290,976,256／worker1／DUTFalse，8cases／18,231events／18关联；identity782eb140f92301ee6d8302e397ceb8a26d67e42535b364e67456c5955cd1189f，semantic6c56cc98cf053231d1523f369718f80b57a5975906addba32feb90e9264e42a3。fresh11311实际运行，audit待完成、accepted仍52。next reset-default路径只读设计，不执行或预授证明。


chunk14 fresh11311终态exit0／complete：118.92392746800033秒、available5,382,307,840／peak1,849,397,248／limit3,234,824,192／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。audit待终态，accepted仍52、不提前56；chunk15 offset0x34／current SHA／AST／tuple／own absent cache preflight通过，未执行。


chunk14 fullaudit60628终态PASS，exactPADCFG_2.pin18–21 values2／6／9／14、18,231events／8证书及完整fresh一致；[独立报告](stage2-e2-padcfg2-pins18-21-independent-audit-20261012.md)。accepted current56单points（32INTTYPE＋24PADCFG），非穷举。chunk15 PADCFG_3.pin24／25／30／31 values1／5／10／15 generation62291实际运行，offset0x34／current source-script SHA／AST／tuple／own absent cache／singleworker180，无overlap、未通过；reset-default设计只读、不实现／授grant。


chunk15 generation62291终态exit0／complete：134.15973644101177秒、available5,471,129,600／peak2,045,935,616／limit3,323,645,952／worker1／DUTFalse，8cases／18,222events／18关联；identity86f694f419c4e7855f2f5e49a1bc679c92e90f5172a1be8976cf6993134b0278，semantic8adb75b9750f113f6874da1b968014d35a3ca7219fc7ccb5133266f291111f99。fresh77906实际运行，audit待完成，accepted仍56。reset-default独立设计review已指出actualcommand全覆盖／unknown fail-closed／total field-affect／process boundary实施前缺口；仅文档修订，无实现或grant。


chunk15 fresh77906终态exit0／complete：120.05253920699761秒、available5,461,848,064／peak1,850,097,664／limit3,314,364,416／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。audit待终态，accepted仍56不提前60；chunk16 offset0x34 current SHA／AST／tuple／own absent cache preflight通过未执行。reset设计已reconciled仍只docs，无实现／grant，完整scope不变。


chunk15 fullaudit41628已终态PASS，exactPADCFG_3.pin24／25／30／31 values1／5／10／15、18,222events／8证书及完整fresh一致；[独立报告](stage2-e2-padcfg3-first-field-independent-audit-20261012.md)。accepted current60单points（32INTTYPE＋28PADCFG），非全值穷举。chunk16 PADCFG_3.pin26–29 values2／6／9／14 generation9338实际运行，offset0x34／current source-script SHA／AST／tuple／own absent cache／singleworker180，无overlap、未通过；64fieldpoints之后仍须word／permission／width／reset及完整原Stage2范围。


chunk16 generation9338终态exit0／complete：131.9667810839892秒、available5,477,412,864／peak2,046,443,520／limit3,329,929,216／worker1／DUTFalse，8cases／18,231events／18关联；identityc0615d235a2e7b14a539d270cc8f2ca9506635a144fb18e424212520e1e619db，semanticfd0950536f96ba523f6ae962831f26fcd765be468db10afd5cdaf9534c29e882。fresh6576实际运行、audit待完成，accepted仍60、不提前64；3word包prepared待矩阵后，原Stage2完整scope不变。


chunk16 fresh6576终态exit0／complete：118.51990141399438秒、available5,447,532,544／peak1,851,146,240／limit3,300,048,896／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。独立audit待终态，accepted仍60、不提前64。16chunk聚合仅准备读取小preparation／summary／audit／resource与wrapper资料，最后审计通过前不授64；各bundle current8证书不拼成global active128。


最终chunk16 fullaudit11089实际exit0、exactPADCFG_3.pin26–29 values2／6／9／14与18,231events／8current证书通过。16组轻量聚合已PASS，accepted current64指定单valuepoints＝32个2bit INTTYPE＋32个4bit PADCFG，无漏重；[聚合报告](stage2-e2-register-field-matrix-aggregate-20261012.md)／[JSON](stage2-e2-register-field-matrix-aggregate-20261012.json)。每bundle current8，不是global active128，不授全值／全E2。word DIR_OUT generation48145实际运行、未通过，原全scope仍OPEN。


word DIR_OUT generation48145终态exit0／complete：119.19223787200463秒、available5,482,065,920／peak1,715,609,600／limit3,334,582,272／worker1／DUTFalse，6cases／13,907events／12关联／18selectedAPB／3RAM；identity89c76c958c9fee3e91acd37ad9a34e18775d89968f71fab41b5edabe76023cd8，semantic67901c4321c154b0304d97a151905ec6d8da1c684bf6ac98a67ccb52b5150c33。fresh3571实际运行，word尚未accepted；已审计narrow64是独立单valuepointscope，不扩张成global或完整E2。


DIR_OUT word fresh3571终态exit0／complete：101.75905876699835秒、available5,479,596,032／peak1,575,030,784／limit3,332,112,384／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。新word fullaudit待终态、word尚未accepted；narrow64单值scope独立不变。


DIR_OUT word fullaudit42062终态PASS，13,907events／6证书、exact B.INTEN0与A.PADDIR／PADOUT 0x80000000三instance-specific fullword write/read pairs验收；[独立报告](stage2-e2-word-dir-out-independent-audit-20261012.md)。这不是functional／reset／fullL2，narrow64scope独立。EN_INTEN generation49060实际运行，6typedtuple／current source-script SHA／AST／own absent cache preflight一致／singleworker180／无overlap、未通过。PADIN准备未执行，reset-default设计未实现。


EN_INTEN word generation49060终态exit0／complete：116.19795339199482秒、available5,497,872,384／peak1,715,634,176／limit3,350,388,736／worker1／DUTFalse，6cases／13,905events／12关联／18selectedAPB／3RAM；identity932be8f1bf78ab518770c9014308eedf5927fcaf9b7f102d9509177866fc44ba，semantic2e87bdd4b083dd761b01db17f599d6e32c47b63d45e80b137ae8bccd82dcf160。fresh74249运行、EN_INTEN尚未accepted，DIR_OUT仅3pairs／narrow64分别独立。current-source alias zero-mask八case新包仅准备、PADIN之后执行，不借旧source证据。


EN_INTEN fresh74249终态exit0／complete：100.39961130799202秒、available5,492,273,152／peak1,573,228,544／limit3,344,789,504／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。fullaudit待终态、未accepted，DIR_OUT与narrow64scope独立。current alias zero-mask八request包prepared check86a6e87323acd90354f609748d397277118ae02d513f82fa277589637bb5bd97，待PADIN之后／独立review，未native执行。


EN_INTEN fullaudit99853终态PASS，13,905events／6证书／exact B.INTEN0、A.GPIOEN与A.INTEN 0x80000000三instance-specific fullword pairs验收。B.INTEN0与DIR_OUT重复，不多计unique；不授functional／reset／fullL2，narrow64scope独立。PADIN generation83748实际运行，current typed RO／exact4request builder／source-script SHA／AST／own absent cache preflight一致、singleworker180／无overlap，尚未通过。alias zero-mask仅prepared／review中，reset-default未实现。


PADIN generation83748终态exit0／complete：103.98888060198806秒、available5,509,058,560／peak1,414,696,960／limit3,361,574,912／worker1／DUTFalse，4cases／10,129events／10关联／12selectedAPB／3RAM；identity7391bd31ec5a149e4d04ae90b7ebe451a9dc59030b35d3807eeb7f7cc3360638，semantic77ac9f1d2ec93ae92b3e5a0a2c24db2b881bf4f4ba3ffdd878fcc50de0702baa。fresh88629实际运行、audit待完成，PADIN尚未accepted；仅APB→CPU→RAM consistency，不授sampling／reset。EN_INTEN3pairs与narrow64scope独立，aliaszero仍prepared。


PADIN fresh88629已exit0／complete：87.21911255799932秒、available5,506,846,720／peak1,302,310,912／limit3,359,363,072／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。fullaudit待終態、PADIN尚未accepted，不授sampling／reset；wordpairs与narrow64独立。current alias fullmask八case包仅准备，待PADIN＋aliaszero之后；aliaszero已prepared／review通过但尚未native执行。


PADIN fullaudit75237终态PASS，10,129events／4证书／exact B.INTEN0 pair与A／B.PADIN READs一致；[独立报告](stage2-e2-word-padin-independent-audit-20261012.md)。仅APB→CPU→RAM consistency，不授physical sampling／reset／fullL2，B.INTEN0重复不新增unique。current aliaszero generation52350实际运行，current typed v3 relation／8request builder／source-script SHA／AST／own absent cache preflight一致、singleworker180／无overlap，尚未通过。fullmask仅prepared未执行、reset-default只读，原全scope不变。


current aliaszero generation52350已exit0／complete：132.50322782000876秒、available5,517,291,520／peak2,044,710,912／limit3,369,807,872／worker1／DUTFalse，8cases／17,677events／14关联／24selectedAPB／5RAM；identity83a58d548a2d1bc4c63f91cee868174f635293c20ac1851a66e69385dc5a30b1，semanticb600b8ac43377f01ca5f36382ca819fb29c9261132b382096514b6827094c268。fresh75682实际运行、audit待完成，aliaszero尚未accepted；fullmaskprepared／轻量review通过未执行，PADINscoped与wordpairs／narrow64独立。


current aliaszero fresh75682终态exit0／complete：117.51322904099652秒、available5,533,614,080／peak1,847,062,528／limit3,386,130,432／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。audit待终态、zero尚未accepted，fullmask未执行；current partial／high／repeat alias下一步仅只读设计，不沿用旧source授权。


current aliaszero独立audit30129（本轮process ID）终态PASS，17,677events／8证书／exact8requests（zero SET／CLR brackets＋B.INTEN0 pair）一致；[独立报告](stage2-e2-alias-zero-current-independent-audit-20261012.md)。仅source-bound zero两个brackets验收，不授storage version／prerequisite／functional／reset／fullE2，word与narrow64scope独立。fullmask generation66978实际运行，actual builder FFFFFFFF SET／CLR／current typed v3／source-script SHA／AST／own absent cache preflight一致／singleworker180／无overlap，尚未通过。partial-repeat current-source只读设计待独立review、未准备执行。


current aliasfullmask generation66978终态exit0／complete：130.43963241600432秒、available5,511,983,104／peak2,043,985,920／limit3,364,499,456／worker1／DUTFalse，8cases／17,683events／14关联／24selectedAPB／5RAM；identityc8d271f66e0036be7ff8a3fbb6bf4bbcc7972a7f09c7fbbf296a5a215c3ab3a4，semanticc56019e222a6754327403e9cbc5d1e86b572a761ef65e9e39ba8b803c17baf14。fresh32283实际运行、audit待完成，fullmask尚未accepted。partial_repeat独立designreview已保存：现规则允许shared actual adjacent READ boundary，新gate独立before是实验要求而非生产缺陷；只修docs，无生产实现／native执行。


current fullmask fresh32283终态exit0／complete：115.31429795100121秒、available5,522,804,736／peak1,849,442,304／limit3,375,321,088／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。audit待终态、fullmask未accepted，currentzero两个brackets已验收。SET partial_repeat十request新worker仅prepare，reconciled shared actual READ与gate独立newbefore2要求，未native执行。


current fullmask fullaudit39840终态PASS，17,683events／8证书／exactSET／CLR FFFFFFFF与完整fresh一致；[独立报告](stage2-e2-alias-fullmask-current-independent-audit-20261012.md)。仅fullmask两个brackets验收，不授functional／reset／storage version／fullE2；zero两个brackets／word／narrow64scopes独立。SET partial_repeat十request包prepared check42b3ca3e2b477e44bfff3d62e13464aa0b52e5e842a7dd926c039b88027e05dc，Root SHA／AST／own absent cache preflight通过，轻量workerreview／audit准备中，NOTnative；当前所有native任务已终态。


SET partial_repeat十request包独立lightreview无阻断，auditprepared SHA a11961f77ff90279c6321f9b6b406f6c252e96810d491aa03d6f27e833673888；Root current source-script SHA／AST／exact10requests／own absent cache preflight通过后实际启动generation64745，新v1／singleworker180／无overlap，尚未通过。保留10cases（6READ／2plain／2alias）、10selectedMMIO／30selectedAPB／6RAM，expected16关联／48allAPB仅准备断言，不是actual PASS；high／repeat未预授，generic共享合法规则不改。


partial SET generation64745终态exit0／complete：151.32340373699844秒、available5,571,547,136／peak2,346,278,912／limit3,424,063,488／worker1／DUTFalse，10cases／21,451events／16关联／30selectedAPB／6RAM；identity1f8660e6c83892a7775057f15bce942636767d092bfef3e94f7b89da49d0e16b，semantica93b6d6e84fe731ce76cf420099c5f536ce83feaec37d828736793c2a75411ef。fresh51736实际运行、audit待完成，partial SET尚未accepted，全部10cases保留／预算未放宽。CLR partial_repeat十request包prepared checkf3e984369ecf049c7346a9dea32afe6103018bd0359713a5581eeccd43d9bc49，待SET全终态与独立review，未native执行。


partial SET fresh51736终态exit0／complete：133.26829966400692秒、available5,504,163,840／peak2,122,182,656／limit3,356,680,192／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。audit待终态、SET未accepted，全部10cases／原180秒预算保持。CLR prepared lightreview无阻断，auditprepared SHA b3c85ac1eed559552b1acf3036dea8f48397eb768eaaaa0c8f24b83eb93e5f3b，未执行／待SET audit终态。


partial SET finalaudit16667终态PASS，21,451events／10证书／exact seed55aa00ff→SET80000000及repeat与完整fresh一致；[独立报告](stage2-e2-alias-partial-set-current-independent-audit-20261012.md)。firstaudit69511 exit1为audit setup漏当前sidecar load导致NameError cap，仅补load不改事实或断言，失败历史保留／非DUT finding；finalaudit SHA a8a20738b217bee76b7bfe82c2ddefd5a7d7529189ce32a7d9d3b6d063127734。仅2SET brackets scope验收，不预授CLR／reset／functional／storageversion／fullE2。CLR generation60831实际运行，current source-script SHA／AST／10requests／own absent cache preflight／lightreview一致／singleworker180／无overlap／全部10cases保留，未通过。


partial CLR generation60831终态exit0／complete：143.68561087400303秒、available5,575,970,816／peak2,345,062,400／limit3,428,487,168／worker1／DUTFalse，10cases／21,451events／16关联／30selectedAPB／6RAM；identity4008d40c0d9e6d9e401be4089b3443f84ea5107cee50ee68281af708911c8aa9，semantic9dc75242896642072491e4b9ba8e8b3be831b13077cec4d88ffcc576322484a6。fresh48813实际运行、audit待完成，CLR尚未accepted，全部10cases／原180预算保持。SET两个brackets已验收，first setup failure真实script／stderr／receipt已保存、Root SHA核对，非DUT finding。


partial CLR fresh48813终态exit0／complete：139.66191233199788秒、available5,607,415,808／peak2,120,609,792／limit3,459,932,160／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。fullaudit待终态、CLR未accepted，全部10cases／原180秒预算保持。


partial CLR fullaudit28385终态PASS，21,451events／10证书／exact seed d5aa00ff及repeat／current auditor SHA一致；[独立报告](stage2-e2-alias-partial-clr-current-independent-audit-20261012.md)。仅2CLR brackets source-bound验收，不授arbitrary masks／reset／storageversion／functional／fullL2。所有native与audit均已终态后，currentf7da exact14 permission测试exec66607 exit0：14 passed／23.06秒（外层wall23.440831127998536），前后10份源码／fixture SHA完全相等；[receipt](../../runs/stage2-e2-current-register-permission-software-20261012/receipt.json)及真实stdout／stderr均保存。actual private对象software transport，无GeneratedSession Popen／DUT／RTL或PSLVERR资格，证明声明拒绝前effect不变；历史14PASS22.92秒不覆盖不改写。
