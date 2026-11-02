# 统一 F2 RFuzz 接入：实施与验收记录（2026-10-23）

状态（2026-10-24）：统一F2有界交付完成。最终冻结十门独立接受，Spec/source、Quality和软件/原生PASS；两份计划、运行边界、组件/代码职责、进度、索引及P7有界状态已同步，[最终文档闭环独立PASS](evidence/compiled-f2-rfuzz-entry-20261023/audits/final-documentation-closure.md)。历史候选与失败记录保留；下方过程状态属于对应历史截点。此前F2文件入口/F4八门与本次新增统一入口是不同候选，不合并测试总数。

## 第三冻结最终验收表

| 门／attempt | 实际结果 | 独立审计／状态 |
| --- | --- | --- |
| software4 | 498 passed／5精确native skip／22 subtests，exit0/reaped，931.92s | [PASS](evidence/compiled-f2-rfuzz-entry-20261023/audits/software-attempt4-freeze3-independent.md) |
| native-suite2 | 5 passed／0 skipped，exit0/reaped，1089.17s | [PASS](evidence/compiled-f2-rfuzz-entry-20261023/audits/native-suite-attempt2-independent.md) |
| F2 Ibex Timer3 | 1certified／3input_invalid，full631events，exit0/reaped，252.27s | [PASS](evidence/compiled-f2-rfuzz-entry-20261023/audits/f2-timer-attempt3-independent.md) |
| F2 CV32E20 Timer3 | 1certified／3input_invalid，full631events，exit0/reaped，240.11s | [PASS](evidence/compiled-f2-rfuzz-entry-20261023/audits/f2-cve2-timer-attempt3-independent.md) |
| F2 CV32E40P SPI3 | 1certified／3input_invalid，full4355events，exit0/reaped，298.01s，保存审计exit0/statusok | [PASS](evidence/compiled-f2-rfuzz-entry-20261023/audits/f2-spi-attempt3-independent.md) |
| F2 renamed Timer3 | 1certified／3input_invalid，full631events，exit0/reaped，311.60s，保存审计exit0/statusok | [PASS](evidence/compiled-f2-rfuzz-entry-20261023/audits/f2-renamed-timer-attempt3-independent.md) |
| refusal registration3 | actual/expected CLI1，reaped，38.99s | [PASS](evidence/compiled-f2-rfuzz-entry-20261023/audits/refusals-attempt3-freeze3-independent.md) |
| refusal shape3 | actual/expected CLI1，reaped，27.46s | [PASS](evidence/compiled-f2-rfuzz-entry-20261023/audits/refusals-attempt3-freeze3-independent.md) |
| F4 Timer2 | 2certified，full1306events，exit0/reaped，452.67s；两条八位反馈均0 | [PASS](evidence/compiled-f2-rfuzz-entry-20261023/audits/f4-timer-attempt2-independent.md) |
| F4 SPI2 | 2certified，full8950events，exit0/reaped，533.80s；两条八位反馈均0 | [PASS](evidence/compiled-f2-rfuzz-entry-20261023/audits/f4-spi-attempt2-independent.md) |

每行是一项独立运行；软件skip与原生五项控制分别计数，开发RED/GREEN不并入本表。所有已终态门的输入／来源／不可用链接／输出稳定，均无超时或capture error。监督器终态针对被监督child，不额外推断外层launcher的归档wait receipt。

## 最终归属、交付与边界

[最终冻结验收报告](evidence/compiled-f2-rfuzz-entry-20261023/audits/final-frozen-slice-acceptance.md)逐项核实十门命令、工具、终态、归档、输入/来源/不可用链接及输出，结合各自原始证据审计给出Spec/source、Quality及冻结软件/原生PASS。验收时全部21916项当前字节和origin与freeze3相等；13项不可用别名只保留缺失来源记录。source-map SHA为329f3e2f1cd4bddd5ad22bbaa0e5749c22f1a595eeb84f7b88a3def8393f4f7c，manifest SHA为438158a3295d6c244318a17b5a2a2427da948b2599a905e5aee63f8a0c87fe0a，冻结归档SHA为a4a4ef1aee5c6d1a071ce4f4b7ab7d2d86cdb2f95707ecb0b7cdcfc5b0cc3ec1。

交付为显式统一F2执行器、同次D2/D3消费、全test原子预检、真实反馈与两项typed期望、严格raw8/projected4/case关联、独立完整fresh、初始/最终字节保护、构建/原生进程身份和失败诊断。最终首异常与嵌套notes修复已在实际软件门覆盖，原有P2按最终hash关闭。原计划Task4–6与RFuzz补充Task1–6按实际证据同步。

执行冻结在所有门终态和最终独立接受后释放；本次计划勾选/链接/状态与参考文档修订属于之后的文档更新。归档中的旧计划字节、所有attempt、原始输出和历史审阅均不改写。本地RFuzz计划的文档新字节不冒充当时执行输入；生产、测试、配置、工具及gate/task字节保持验收版本，后续F6属于新候选。

F2地址域仍为1、正常PRDATA0、依赖RAM结果1445；六个反馈是观察，不是六条D3断言。F4两门虽各2certified，反馈均八零，不授覆盖或有用搜索收益。CV32E40P无native CPU error pin，保持None/未观测；APB PSLVERR0单独记录。能力仅限已登记RV32I OBI1/APB3稳定全字寄存器，不授退休、任意同协议接入、通用F6、P6/P7-E/P8或系统完成。

下一功能已获用户批准：[四字RAM→RAM＋真实IRQ/ISR F6规格](../superpowers/specs/2026-10-24-compiled-f6-cpu-programmed-ram-design.md)，正编写实施计划，尚未实现。文档全库链接预检exit1，旧失效引用单列于[检查范围说明](evidence/compiled-f2-rfuzz-entry-20261023/audits/doc-links-preflight-scope.md)，不声称全库链接通过。

## 实现范围

- 显式 `compiled-f2-rfuzz` 入口，按 F2 合同接入，不按 CPU/IP 名称选择执行器。
- 合法地址 little-endian 四字节加四字节未绑定后缀；每个 test 只接纳1–8记录，全部预检；9–200拒绝而不截断。
- 整例失败保留真实接纳 inventory，未接纳的提交失败不发明 case IDs。六项反馈来自逐例断言、实际三边与依赖 RAM store，不新增六条 D3 断言。
- 独立 raw8／projected4／case／typed assertion／原始与 fresh join。纯 JSON 不签发 native authority。
- 同次 seed、manifest、plan、原始 trace 与首次写出字节承诺绑定；fresh 原始材料分别导出、初始 byte pins 和最终校验保留。
- 实际 finalizer 的 F2 decoder／运行路径／指令绑定校验；F4 保留自己的严格校验。

## 开发证据

证据根：`.superpowers/sdd/compiled-f2-rfuzz-entry-20261023/`。以下为不同运行，不合并为完整验收数。

| 范围 | 已观察结果 | 边界 |
| --- | --- | --- |
| wire／decoder | 52 passed、20 subtests；另18项复跑 | 后续 decoder 材料字段另有专项 |
| executor 复审修复 | 22 passed | 软件 runtime spy，不是 RTL |
| feedback | 16 passed | source-backed synthetic exact-hop fixtures |
| receipt 顺序修复 | 18 passed | 保留 invalid slot 顺序，拒绝 coherent raw 替换 |
| F2 材料／实际 identity writer | 20 passed | 在 native begin 前停下的真实准备路径 |
| driver | 43 passed；projection 修复3 passed；principal 真实保存验证4变体通过 | 各次开发测试，未冻结 |
| saved-material auditor | 42 passed | source-backed synthetic 完整证据，不发 native authority |
| native controls | 收集5，默认跳过5 | 尚未启动原生运行 |

失败结果保留在对应 task 日志：包括并行源码变化的115/1、driver flow guard 的126/3、夹具父目录缺失的45/1，以及各项有意义的 RED。它们没有被追认为通过。

## 原始验收清单（当前终态以上方状态及后续记录为准）

1. 独立整合复审与所有 P1/P2 收口，冻结 supervisor／控制声明／源码／工具身份。
2. 同一冻结版本的软件门、真实客户端 Timer／CV32E20 Timer／SPI／改名实例 original+fresh。
3. 五项实际 runtime 控制、错误登记拒绝及相似名称错误形态负例；保持真实观察与受控注入区分。
4. 同版本 F4 Timer／SPI 兼容门，独立 saved-material 审计及原始运行证据复核。

F2 合法地址域仍为1，当前读响应仍是 reset-zero；成功交换／重复候选不证明有用搜索收益。通用 F6、多字 DMA、全面同协议接入、P6/P7-E/P8 和系统总目标仍开放。

## 冻结前复审追加修复

- Task5 最终 summary 曾遗漏在其后写出的 capability-report 初始 SHA；已保留原始 pin map 并在 finish 刷新公开摘要。RED1失败，四项入口变体复跑通过；不是重新散列磁盘来建立基线。
- Task6 原生测试误用 manifest 属性、replay 导出可能覆盖 primary；已以五项默认软件控制复现并修复，原生尚未运行。
- 监督器第三方符号链接的物化与来源记录、审计器反馈向量检查／导入源码归属／拒绝分支，以及相似名称错误形态 fixture 正在按独立复审补齐。复审未收口前不启动冻结门。

## 最终候选 freeze-attempt1

输入21257项，source-map SHA256 `7a35d75ac6945bf0a1bc9234a0693470ed2e8694cb1fc4fd854523fc4022ece1`，归档 SHA256 `374ea2948fb2eda121991930fecf309426763c7788f5642b90dd29e1f44074da`。所有已识别 P1/P2 修复完成并独立复审通过。source/scripts/tests/configs/gates/既有task证据停止修改。

监督 `software-attempt1` 与 `f2-timer-attempt1` 已启动；初始工作为归档同份输入，进程终态／原生结果尚待读取。余下门不会并行启动第二个重型原生 worker。审核报告另存 audits/，不向封闭的 attempt output ledger 追加文件。

首个 Timer 实际客户端阶段：`session/report.json` 保存 tests4、client_returncode0、certified1／input_invalid3；实际 receipt 反馈为 `010101010101`／三个 `000000000000`。这是阶段结果，fresh 和监督终态尚未完成。软件门仍运行。冻结归档已获独立只读审计 PASS，报告在 evidence/compiled-f2-rfuzz-entry-20261023/audits/freeze-attempt1.md。

### f2-timer-attempt1 终态

监督 actual／expected exit0、reaped、未超时，248.157544s，21257项输入及来源／输出前后一致。actual client returncode0、4 receipts（1 certified／3 input_invalid），fresh full631events、first_difference=null，build join complete，receipt join case_count1／rows4／rejected3，`.incomplete`已移除。独立保存材料脚本以绝对 output 路径运行 exit0／statusok：66输出pin，1case4receipts，不签发nativeauthority。原始证据独立复审待收口；整个切片仍待其他门。

保存审计初次使用相对 output 路径，因内部绝对／相对路径归属计算而 refused exit2；同目录绝对路径重新调用通过，期间未修改源码或减少校验。失败输出与通过输出均保留在 audits/；审计 CLI 的路径用法限制待后续非冻结窗口修复。该工具参数问题不改写运行门的实际终态。

### CV32E20 Timer 与软件门后续

CVE2 Timer attempt1：exit0／reaped、230.752378s、21257输入／来源／输出不变，full631-event fresh，4receipts（1certified／3input_invalid），绝对路径保存审计通过66pins。原始证据复审待收口；SPI attempt1已串行启动。

软件 attempt1：实际 pytest exit0／reaped、436 passed／9 skipped／22 subtests，787.65s；监督791.295374s、skip_policy_ok=false／监督自身exit1。五项 native skip 符合要求，但四项 Rust smoke 默认跳过未在允许策略内，所以本门不接受。源码和跳过策略保持冻结不变，以显式继承 `MYFUZZ_SCENARIO_RFUZZ_LIVE=1` 启动 software-attempt2，仍由wrapper强制native opt-in0；请求环境另存 audits/，待核对实际child环境和终态。

### SPI attempt1 与独立证据复审

SPI attempt1：actual／expected0、reaped、274.945256s、同21257输入／来源／输出不变；客户端4条（1certified／3input_invalid），full4355-event fresh匹配、buildjoincomplete、绝对路径脚本审计statusok／66pins。CPU无error pin，未因此授予错误响应观测。原始证据复审中。

Ibex Timer 和 CV32E20 Timer 的原始证据独立复审均 PASS，各核实两份631-event原始流、七条功能取指、真实读／XOR／RAM依赖、两条typed断言、当前寄存器版本、构建／进程身份及初始字节pin。CV32E20有实际error角色，与SPI无error形态区分记录。

改名 Timer attempt1 已启动；软件 attempt2 仍运行，已从实际子进程/proc只读取并记录三个批准环境键：Rust live opt-in1、native F2 opt-in0、PYTHONPATHsrc:.，未读取或输出其余环境值。

## 第一冻结后的阻断与修改窗口

- 改名 Timer attempt1：实际exit1／reaped7.434474s，原因component-endpoint-undeclared：夹具误将物理端点processor.data改为core_probe.data。仅修正该字段，保留logicalinstance/RAMowner等改名；真实D2/D3准备RED1→GREEN1，构造sentinel未触发。
- registration／shape attempt1：实际CLI各产生准确exit1拒绝摘要；监督器最终源快照时遇到另一个前端创建／删除的`.myfuzz-elaboration-*`临时输出，异常退出且缺完整terminal，不能接受为监督通过。
- software attempt2为释放修改窗口受控SIGINT：实际pytest2／reaped530.982974s、323passed部分结果、21257输入与来源未变，非通过。没有继续任何运行中门后修改其源输入。
- 第一候选三个真实门（Ibex Timer、CV32E20 Timer、CV32E40P SPI）均有脚本及原始证据独立PASS，归档保持不变；新候选验收不会把旧失败／中断追认为通过。
- 修复工作：仅排除由现有frontend明确拥有的scratch目录并保留普通／隐藏／符号链接输入；最终采集失败仍应保存实际child退出与reaped、失败原因及终态；software模式显式开启Rustsmoke且仍只允许native5跳过。审计相对路径归一化RED2→GREEN53；四项实际Rustclient smoke另跑4passed。生产F2 runtime未因此修改，验收工具／控制输入将形成新冻结。

## 新冻结准备的修复结果

改名夹具 scoped 独立复审 PASS。监督器按已有frontend的源目录拥有关系，在遍历前剪掉临时目录；普通／隐藏／显式声明的prefix目录与符号文件链接保留，缺失普通输入失败封闭。最终采集各阶段独立保存错误并保留实际child退出/reaped；software显式Rust opt-in1/native0，仅接受准确五个native节点跳过。

来源范围补齐external_designs静态顶层与生成器两个RTL源根；工作区当前全部521个已声明且存在的原生源文件均进入输入，13个不可用别名单独记录target/path/null内容/状态，无任何nativeauthority。sourceRoot/includeRoot不会递归扩大到任意cwd/cache/freeze。故障／来源专项28passed2.71s，另bounded组合33passed／5精确native跳过。审计器相对路径及available/unavailable before-after校验完整55passed48.72s；四项实际Rust smoke另4passed1.67s。最终源复审待收口，尚未建立新冻结。

## freeze-attempt2 已建立

最终独立源复审 PASS，外部静态源和两个生成器源根缺口均关闭。冻结21867项可用文件、13项独立不可用链接元数据；source-map SHA256 `b5aad3763feb7f25d2f60423dc9b4084c81741d825cab16aea06196cfe0125db`，归档 SHA256 `bba0b56dea88fa3d95cfcab4d6cc6a9e499df180d0ef91660ce0a5222e6feec5`。

已启动 software-attempt3（显式Rustlive1/native0、仅允许准确五项native跳过）与native-suite-attempt1（准确五项真实控制、单重型worker）。本轮优先检查双记录连续运行／原子拒绝／suffix／missing-store控制，再执行其余客户端与兼容门。终态尚待，不记为通过。

第二冻结阶段观察：two-legal-records 控制已保存原始2条certified记录与fresh-replay-0 matches=true／first_difference=null／scopefull／fresh_records2，控制terminal已保存；主native-suite与software3仍运行，尚不授予整套通过。后续atomic invalid-second控制已开始。

## freeze-attempt2 首批四门终态

`software-attempt3` 的冻结监督回执已终态：pytest exit0、473 passed／5 skipped／22 subtests passed，测试自身821.36s，监督843.914725s；PID1893859 已回收、未超时、峰值RSS261672KiB。五项 skip 恰为 opt-in 原生控制，Rust client smoke 在本轮实际执行。21867项输入字节、来源链接、13项不可用链接及预存输出前后一致，capture_errors为空；本轮 invocation archive SHA256 为 `ae79a80b24e6d5557b07d149994fbbc67539292ca1bc18a8c54bcdb54fc536f7`。独立终态／归档人工复审 PASS，已接受为当前冻结的软件门；审计明确区分保存的受监督子进程回执和仅由控制器观察到、没有单独仓库PID回执的外层run_gate exit0。

`native-suite-attempt1` 也已终态：pytest exit0、5 passed／0 skipped，测试自身1007.55s，监督1030.294715s；PID1893860 已回收、未超时、峰值RSS588440KiB，同一21867项冻结闭包与输出映射保持不变，archive SHA256 同为 `ae79a80b24e6d5557b07d149994fbbc67539292ca1bc18a8c54bcdb54fc536f7`。五项是定向真实 runtime 控制而不是 RFuzz 搜索门：同一原始进程连续执行两个合法记录并分别 fresh；错误第二地址的原始／独立 fresh 原子零副作用；9记录完整保留且不裁剪；不同suffix4具有不同raw身份但相同投影／程序／观察；以及明确标注为复制观察视图注入的missing-store控制，不能归因于自然RTL故障。独立原始证据复审正在核对各流、进程、typed结果和初始／最终hash。

两项第二冻结拒绝门均获得完整监督终态。registration attempt2：实际／预期CLI exit1，PID2009065已回收，35.589278s，`component-render-refused`／`harness_set`，constructor未调用；shape attempt2：实际／预期CLI exit1，PID2009099已回收，25.899068s，`duplicate-port-binding`／`declaration_review`，constructor未调用。两者21867项输入／来源／不可用链接／输出不变、capture_errors为空，保存材料审计脚本均exit0／statusok；共同 invocation archive SHA256 为 `bc1e406cd6ad632d2a664fcc1cd05f782ff889d9fecff87cdbf3273dbb75a85e`。独立人工复审 PASS，核实精确pointer/detail、同源guard、冻结归档及无DUT session材料；接受为当前冻结的两个精确拒绝门。审计见 `evidence/compiled-f2-rfuzz-entry-20261023/audits/software3-refusals-freeze2-independent.md`。

当前单一重型worker运行 `f2-renamed-timer-attempt2`；它使用同一freeze-attempt2且写入新目录。后续串行队列为三个F2真实客户端正例和两个F4兼容门，每个正例均另做保存脚本与独立原始证据审计。源码／测试／配置／模板／third_party／gates／task证据继续冻结。通用F6、P6、P7-E、P8和系统目标仍开放。

### 改名 Timer attempt2 接受

改名真实客户端门 actual／expected exit0、PID2053515 reaped、未超时，监督258.240209s／RSS300840KiB；21867项冻结字节／来源／不可用链接／输出保持不变，归档 SHA256 `d69c66c632a63309920c748a8f624d61082fb71fc6787ffdc020cc48560b11b0`。保存审计 statusok、66pins、1case／4receipts；原始证据独立复审 PASS。

实际逻辑实例为 `core_probe`／`target_probe`，物理 ABI 保持 `processor.data`／`processor.instruction`／`processor.interrupts` 与 `timer.bus`。客户端4条receipt为1certified／3input_invalid；认证向量六项命中，拒绝向量全零。original／fresh各631events、完整前缀字节一致、两条typed expectation通过，四个DUT进程PID／nonce不同且均exit0／reaped，build／binary／READY关联完整。实际链为取指、CPU读、APB offset4、返回0、XOR1445、RAM store1445。该门只证明一个已登记合同的名称无关调度，不继承原实例私有层次证明，也不证明有用搜索多样性或系统完成。独立报告：`evidence/compiled-f2-rfuzz-entry-20261023/audits/f2-renamed-timer-attempt2-independent.md`。

当前单一重型worker已转入 `f2-timer-attempt2`，统一exec session36943，子进程PID2066457；保持同一freeze-attempt2。后续仍为CV32E20 Timer、SPI与两项F4兼容门。

### native-suite attempt1 与 Ibex Timer attempt2 接受

五项定向真实runtime控制的独立原始证据复审 PASS：监督5 passed／0 skipped，21867项冻结闭包及121项外部输出不变；97项初始control pin、19项生成输入pin、16个原生进程回执全部核实。双合法记录及suffix控制各有original／fresh 1262 events和完整前缀；invalid-second与9记录拒绝为零attempt／零反馈且原始raw完整；controlled missing-store保存真实RAM event149/value1445，但复制观察视图明确标记 `natural_RTL_failure=false`，保留failed／missing typed结果、零反馈、primary及清理。该套为定向控制，不是RFuzz搜索多样性。审计：`evidence/compiled-f2-rfuzz-entry-20261023/audits/native-suite-attempt1-independent.md`。

Ibex Timer `f2-timer-attempt2` actual／expected exit0、PID2066457 reaped、未超时，监督245.374803s／RSS299240KiB；21867项输入／来源／不可用链接／输出不变，archive SHA256 `d3c09d1ca82f5ef861bb0be895f133d8998b7e6092fed98cc67ecbd91e267f55`。保存审计statusok／66pins／1case／4receipts，独立raw审计PASS。实际1certified／3input_invalid、认证六反馈全命中／拒绝全零；original/fresh各631events且完整前缀一致，读Timer offset4返回0，经XORI 0x5a5写RAM1445；两条typed断言通过，四个DUT进程不同且exit0／reaped，build／binary／READY关联完整。候选域1且客户端新增输入0，不声明有用搜索收益、retirement或系统完成。审计：`evidence/compiled-f2-rfuzz-entry-20261023/audits/f2-timer-attempt2-independent.md`。

当前单重型worker已转入 `f2-cve2-timer-attempt2`，统一exec session40965；后续为F2 SPI与两项F4兼容门。

### CV32E20 Timer attempt2 监督终态

`f2-cve2-timer-attempt2` actual／expected exit0、PID2079702 reaped、未超时，监督245.677353s／RSS274396KiB；21867项输入／来源／不可用链接／输出不变，archive SHA256 `554a77ed58d15622a50373879bdd77293455fb188229e276a92a15619e1def7d`。保存审计statusok／66pins／1case／4receipts；full fresh、两条typed结果及完整run summary存在。独立raw审计 PASS：original/fresh各631events，取指／读／APB／返回／XORI0x5a5／RAM store链闭合；CV32E20的native error角色实际存在，功能取指、读回和store响应的raw error tap均观测为0，不能与SPI的无pin形态混同；四个DUT进程不同且exit0／reaped，build／binary／READY及冻结字节全部核实。审计：`evidence/compiled-f2-rfuzz-entry-20261023/audits/f2-cve2-timer-attempt2-independent.md`。

当前单重型worker已转入 `f2-spi-attempt2`，统一exec session69624，子进程PID2091940；后续为两项F4兼容门。

### F2 SPI attempt2 接受；F4 Timer 兼容终态

F2 SPI attempt2 actual／expected exit0、PID2091940 reaped、未超时，286.324322s／RSS305668KiB；21867项输入／来源／不可用链接／输出不变，归档 SHA256 `d1529345295b5ce57598a2e410c67900effb2bf99a825996767658fb5b0507d2`。保存审计statusok／66pins／1case／4receipts，独立raw审计PASS，original/fresh各4355events、full前缀匹配。SPICMD offset8的accepted APB PRE399观测PRDATA0／PSLVERR0，CPU return493随后驱动XOR1445及RAM write722；POST416 deselected时的PRDATA1没有冒充accepted response。CPU无error pin，native error=None／不可观测。两条typed断言、四个不同PID／nonce的exit0/reaped及build／binary／READY关联完整。审计见 `evidence/compiled-f2-rfuzz-entry-20261023/audits/f2-spi-attempt2-independent.md`。

F4 Timer兼容attempt1 actual／expected exit0、PID2101786 reaped、未超时，417.008849s／RSS307056KiB；同一21867项闭包不变，归档 SHA256 `87683a7c92f0e5198ba6a3187067e9732fc9790659f3329d939b0c6c92c8c1c3`。实际client2tests／2certified，run complete、receipt join ok、build join complete、full fresh匹配，实际fresh raw1306events。独立raw审计正核对F4自己的写入／commit／readback／RAM链和运行内保存校验，尚待其接受结论。

最后一项F4 SPI兼容attempt1已启动，统一exec session7048，子进程PID2121853。最终源码复审另由新代理进行，正在核对submit失败后的原始异常传播；全部实现输入继续冻结，待真实终态和审查结论。

### F4 Timer 独立接受；最终源码P2保持开放

F4 Timer的独立raw审计PASS：两例实际写入0与0x24000000，各自取指／APB commit／读回／依赖RAM链在original/fresh两份1306-event流独立核实；完整前缀与build／binary／READY匹配，四个DUT进程不同且exit0／reaped。64项外部输出及21867项冻结闭包核实。两条反馈向量实际全零，client内部“80 tests”不替代执行器实际完成的两条exchange。审计见 `evidence/compiled-f2-rfuzz-entry-20261023/audits/f4-timer-attempt1-independent.md`。

最终新代理源码复审发现Important/P2：`execute_batch`捕获submit／certificate／feedback异常后没有保留原异常对象；`_finish_online_session`随后传播`runtime.finish`新建的failed-attempt错误，wrapper把后者当作primary，原始异常上的导出诊断note也丢失。根用既有source-backed软件夹具、一次真实`CompiledF2Runtime._finish`调用已复现：原始RuntimeError带FileNotFound导出note，最终surfaced为不同ValueError且notes为空。初次复现仅夹具output parent设置错误，修正临时父目录后完成实际复现；详见 `audits/submit-primary-reproduction.md`。现有成功门和各自独立raw审计保持原记录，但本候选整片验收不关闭；F4 SPI终态后按合并审查结论修复并验证新候选。

### 第二冻结十门审计收口；P2修复窗口已打开

F4 SPI兼容attempt1 actual／expected exit0、PID2121853 reaped、未超时，495.697298s／RSS360104KiB；21867项输入／来源／不可用链接／输出不变，归档 SHA256 `4e5908c5acd10f5a9b76435857658b303a3285fe4f9e0a5cdf91a6488a02460f`。独立raw审计PASS，original/fresh各8950events、两例F4写入／commit／读回／RAM链及完整前缀匹配，四个不同DUT进程exit0／reaped、build／binary／READY核实。两例反馈实际全零；CPU native error仍None／不可观测，accepted APB PSLVERR0单独实测。审计：`evidence/compiled-f2-rfuzz-entry-20261023/audits/f4-spi-attempt1-independent.md`。

第二冻结十门均已终态并各自独立审计PASS，但整片源码复审仍为Spec／Quality changes required，唯一P2原始错误传播未修。最后一次修改前的全量current bytes／origin／alias／executable核对已完成；现在限定编辑executor/shared live finalizer及关联软件测试，开发证据只写新`task7-primary-error-fix`。保持首个执行错误优先，其次先发生的transport错误，再其次finish／export错误，后续错误作notes；必须保持部分导出、tuple、一次finish和零未证实反馈。修复、独立复审及新冻结验证完成前，不把旧门标为新源码已执行。

### P2首轮软件RED／GREEN

新增connected模块首个RED为17 failed／18.46s；补齐executor状态与部分plan捕获控制后的完整修复前RED为26 failed／14 passed／37.62s。两次为独立开发运行，各自原始输出保留。生产仅改F2 executor与shared live终态块：execution-only首异常字段，finish局部primary，plan／trace分别尝试、成功标志门控完整identity，最终按execution→先发生transport→首个finish/export选择异常，其余错误作notes。生产wrapper与direct runtime未改。

聚焦GREEN终态exit0、40 passed／36.62s（`task7-primary-error-fix/green-attempt1.log`），包含真实executor→真实outer live finalizer→既有wrapper失败导出循环，确认同一异常对象与双层后续诊断保留；context-none、transport-first／finish-first、部分导出与重复finish tuple均覆盖。扩大六模块软件回归正在运行，独立源码复审及新冻结／原生验证尚待。

### P2次级notes补充

扩大六模块回归实际exit0、134 passed／2 subtests／102.57s。独立复审接受主异常身份／顺序、零反馈、真实case inventory、分别导出、mandatory-write flags及repeat tuple，但发现同一P2中的次级notes转移边界：先发生的transport R成为primary时，finish F上已有partial-export P诊断不能仅通过repr(F)保留。复审报告 `audits/task7-primary-error-rereview.md`为changesrequired。

新子目录`task7-primary-error-fix/notes-promotion/`单独保存第一修复源码baseline、完整diff和新RED/GREEN，父目录13个已审证据文件hash保持不变。RED为6 failed／18 deselected／17.77s，另去重控制1 failed／24 deselected／17.45s；随后executor／新控制／既有shared terminal软件组合exit0、74 passed／2 subtests／37.22s。生产差异仅四行，记录次级异常时复制其既有notes，覆盖owned-context／context-none、多层diagnostic和同对象去重；未改错误优先顺序、字段归属、接口或导出阶段。独立复审正在核对，新冻结及原生验收仍未执行。

两项development constructor guard3均工具exit0／真实CLI exit1、constructor_called=false、cache为空且861／862项源码前后一致；这些凭据对应第一修复源码，最终notes修复稳定后必须另生成guard4再冻结，不能沿用为最终候选的同源码证明。

### 最终修复源复审PASS与第三冻结

notes补充独立Spec／Quality PASS、无剩余发现，报告 `audits/task7-primary-error-notes-rereview.md`。最终executor SHA `51493cc1e500a81f7383c9bca274c801189b8bba37c29ff61c9311ab53c813e5`，shared live SHA `62dfdfee2bc0969ea60520fad91dbfddf6f30fd446c82ac036337b6ca8605217`；新增测试SHA `56927597bc261d4b40d0ad3faddd51debd24ec53de9605191c6d6c190049f09e`。旧P2报告保持其原始changesrequired结论，最终补充报告按这些新hash关闭该源码问题。

guard4两项均工具exit0／真实CLI exit1、constructor_called=false／cache为空，wrong-registration 861项、shape862项源码before=after=current；最终proof声明已指向guard4。用保存审计器的材料检查函数核对声明／guard／来源一致性也通过，scope为development preparation，不代替后续无sentinel的冻结CLI门。最终准备回执在`task7-negative-controls/final-guards-verification.json`；此前guard3及其旧源码身份保持原记录。

全部source／script／test／config／template／third_party／external_designs／gate／task证据及本RFuzz计划重新只读。`freeze-attempt3`准备已工具exit0：21916项可用字节及origin、13项不可用链接，source-map SHA256 `329f3e2f1cd4bddd5ad22bbaa0e5749c22f1a595eeb84f7b88a3def8393f4f7c`，manifest SHA256 `438158a3295d6c244318a17b5a2a2427da948b2599a905e5aee63f8a0c87fe0a`，archive SHA256 `a4a4ef1aee5c6d1a071ce4f4b7ab7d2d86cdb2f95707ecb0b7cdcfc5b0cc3ec1`。独立全量冻结审计进行中，尚未执行第三候选验收门。计划新attempt为software4／native-suite2／四项F2 positive3／两项refusal3／两项F4 compatibility2；原生串行，软件可与一个重型worker并行。

独立freeze3预启动审计PASS：全部21916项current字节／origin、13项不可用链接、七项工具、tar成员／payload、521个现有声明原生文件、28模块选择、准确native5节点及Rustlive1/native0均核实，最终源hash与guard4凭据／声明吻合，首轮13个任务证据文件仍不变。报告 `audits/freeze-attempt3.md`。完整software4与真实native-suite2已启动，统一exec分别88403／34749；没有终态前不记为通过。该新候选后续门保持同一闭包，不复用freeze2输出目录。

### 第三冻结拒绝门接受

registration attempt3 actual／expected CLI1、PID2198436 reaped、未超时，38.992962s／RSS94480KiB；shape attempt3 actual／expected CLI1、PID2198397 reaped、未超时，27.456796s／RSS94876KiB。两门21916项输入／origin／13项不可用链接／output map不变，capture_errors为空，invocation archive SHA各为 `aebbcb0753086d56d2f43e201b6ffac96a1b8298f9ff9d3e45b095709ab585d1`。分别精确拒绝harness_set/component-render-refused及declaration_review/duplicate-port-binding，guard4 source子集关联最终freeze3，未构造DUT。

保存审计均exit0／statusok、6／5pins，独立完整归档／来源／refusal／preconstruction证据复审PASS，报告 `audits/refusals-attempt3-freeze3-independent.md`。这些结论只接受第三冻结两个拒绝门。software4与native-suite2仍在运行；01:15:30本地观察软件stdout71%+，native前三个passed标记且保存双合法、invalid-second原始/独立fresh及nine-record控制终态，整套终态尚待。

### 第三冻结软件门接受；native suite2监督终态

software4 actual／expected exit0、PID2188553 reaped、未超时，监督931.923899s／RSS260788KiB；pytest498 passed／5精确native skip／22 subtests／908.57s。独立审计PASS，核实28模块、四项Rust smoke及25项primary-error测试实际执行，JUnit503个唯一testcase与22subtests分开计数，三项输出pin及所有21916项字节/origin/13aliases/七工具/完整tar匹配；报告 `audits/software-attempt4-freeze3-independent.md`。

native-suite2 actual／expected exit0、PID2188554 reaped、未超时，监督1089.165983s／RSS593212KiB；pytest5 passed／0 skipped／1064.85s。21916项输入/来源/不可用链接/输出不变、capture_errors为空。软件与native各自invocation archive SHA为 `39fba58738f39b88d103c3bc4891ffb59b63630f3e78da124c728580a7e4f95a`，两命令分别留有独立进程回执，不能把相同归档压缩hash误当作同一运行。native raw独立审计已启动，尚不以监督exit0代替其接受结论。

当前单重型worker转入`f2-timer-attempt3`，统一exec session57722；后续为CVE2 Timer3／SPI3／renamed3／F4 Timer2／F4 SPI2。全部继续消费同一freeze3，源码/测试/gate/task证据保持只读。

### native suite2接受与F2 Timer3监督终态

native-suite2独立raw审计PASS：自己的全部21916项current输入/origin/13aliases/七工具/完整tar，以及121个输出、97个初始control pin、19个生成pin吻合；两个正例original/fresh各1262events、原子拒绝/suffix/controlled observer故障均独立重建，16个不同PID/nonce全部exit0／reaped。报告 `audits/native-suite-attempt2-independent.md`；仅接受五项定向控制。

F2 Timer3 actual／expected exit0、PID2348231 reaped、未超时，252.268261s／RSS298924KiB；21916项闭包与输出不变、capture_errors为空，invocation archive SHA `9e3f92bca1ad2725cbf4b186ec55040c29c308909f11dfdd5ffbb0de1ce84934`。实际客户端4tests／4feedback exchanges、1certified／3input_invalid，full fresh matches/null difference；保存审计exit0/statusok／66pins／21916sources／1case4receipts，独立raw审计已启动。

单重型worker已转入`f2-cve2-timer-attempt3`，统一exec session50978；后续仍为SPI3／renamed3／F4 Timer2／F4 SPI2。

### F2 Timer3接受与CVE2 Timer3监督终态

Timer3独立完整raw审计PASS，报告`audits/f2-timer-attempt3-independent.md`：自己的21916项字节/origin、13aliases、七工具、完整tar、66output pin及27初始pin均匹配；原始/fresh各631events，真实read67→APB78/81→return97→依赖store148/RAM149/response166、七条功能取指/字节版本、两条typed断言及四个独立原生进程exit0/reaped核实。完整规范化journal hash均为`daa482794aa288044315871471d27133039ec59da989b4902748cdcdd01c5ead`。仅接受该注册单地址有界路径。

CVE2 Timer3 actual/expected exit0、PID2360749 reaped、未超时，240.107086s/RSS294000KiB；21916项输入/来源/不可用链接/输出不变，capture_errors为空，invocation archive SHA`5742b436c91d4b965a7f4cf32dd993893612db9e4eceeb1af2c2316d77bae980`。保存审计工具exit0，独立raw审计中。当前单重型worker为SPI3统一exec47697，后续改名3/F4 Timer2/F4 SPI2；尚无整片最终接受。
