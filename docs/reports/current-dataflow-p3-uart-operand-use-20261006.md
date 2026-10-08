# 受限 UART 寄存器版本 → SW rs2 消费

> **⚠ 复算可用性（2026-10-09 更新）**：本文引用的部分原始产物目录在 2026-10-09 的 `runs/` 清理中被删除，因此文中指向 `runs/` 的链接可能失效。**报告的结论、数字与边界仍然有效**（记录的是当时真实执行的结果），但"从原始产物复算"的能力已不存在。删除范围、已重建项与逐条断链清单见 [已删除的原始产物](DELETED_ARTIFACTS_20261009.md)。
日期：2026-10-06。P3 的受限子阶段，P2/P3 整体仍部分完成。新模块及接线的软件检查、新actual online及raw重构fixture已通过；**完整fresh fixture也已通过**。旧seed记录中的四条SW仅为历史候选；本次结果按含use模块的新冻结源码身份解释。

## 设计与证明范围

`UartOperandUseTracker` 独立重建真实UART LW seed，并在每条SW的raw退休记录输入前捕获rs2的准确旧寄存器版本。它要求实际Registry、Ownership、RuntimeIndex、完整原始read/load见证和RVFI v2 POST receipt，不采纳调用者自签的accepted seed/use标签。Runner先交付raw事实，再交付用于独立重算比较的派生记录；三个source identity列表纳入新模块。

首版只授予 `uart_seed_register_operand_read`：某个普通退休SW确实以rs2读取了此前UART seed所对应的具体寄存器版本。严格核对解码的rs1/rs2、S立即数、测量地址、mem_wmask15、mem_rmask0和mem_wdata，以及非trap、非capability、非RF抑制。源版本相同且值一致缺一不可；equal byte、最近seed或固定ISR指令位置不能补来源。

同值unknown覆盖也创建新的寄存器版本，后续SW不能继承旧seed。迟到seed只完成已冻结的旧版本消费候选，不改当前寄存器或既有输出。ordinary testcase不reset；跨case保留最初action/admission/path。证书仍只授予UART影响低8位，高24位来源unknown。

本模块**不证明RAM交付/字节writer版本、whole-word store来源、后续RAM load、通用寄存器复制或generic ISR来源**。SW的4字节mask不等于4字节都受UART影响。需要RAM sink时，必须另行join真实唯一提交和MemoryService字节版本；不能以SW退休代替RAM最终落地。

## 已通过的软件门禁

独立组合命令：`PYTHONPATH=src pytest -q tests/scenario/test_uart_operand_use.py tests/scenario/test_uart_operand_use_runner.py tests/scenario/test_uart_operand_seed.py`。最终冻结源fresh独立结果：**81 passed，7.28s，exit0**（38项use＋2项Runner＋41项seed）。此前中途快照为80项、7.00s，不计作最终源码门禁。Runner定向测试单独为2 passed、0.05s。

最终冻结模块 SHA256：`bab6308b0813324093de089429146a7491ca83b2f787ae2c299aad4d0d57f954`。owner软件use＋seed为79项、7.21s且compile exit0；独立复验另含2项Runner。重复相同已知bad scope不会额外升级为全局屏障，正确actual CPU reset仍可恢复该scope。检查覆盖原始证据缺失与自签标签、同值覆盖、迟到proof、严格POST/字段、malformed容器、duplicate、flush/reset和pending容量。独立复现1000个malformed未知CPU scope，在max_components1/max_pending_uses1下保持bad tombstones0、pending0、native0，并置global certainty barrier；单CPU reset不能修复未定位的全局缺失。已知scope的真实pending溢出保持有界，只有正确CPU域且epoch推进的实际reset恢复对应新scope。

预算有限：pending uses256、内嵌seed pending256、components16、instruction witnesses2048。长期distinct fetch历史问题没有由此解决；该范围不宣称任意长度会话通过。

软件证据：[Runner及最终容量独立审查](../../.superpowers/sdd/current-dataflow-p3-uart-operand-use-runner-review.md)、[模块独立审查](../../.superpowers/sdd/current-dataflow-p3-uart-operand-use-independent-review.md)。这些测试使用模拟actual-shaped receipt，不代替真实RTL。

## 旧原始记录中的四个SW候选

来自此前已保存的[seed finalfreeze-online](../../runs/current-dataflow-p2-controlled-entry-read-20261006-finalfreeze-online/)，详见[下一消费边原始设计审查](../../.superpowers/sdd/current-dataflow-p3-uart-operand-next-hop-design.md)。此前记录包含seed模块，不包含本次use模块的新source identity；只能用于确定真实候选形状。

| UART LW seed order | 后续SW order / CPU tick / raw event ID | 实际rs2值 |
| --- | --- | --- |
| 81 | 83 / 654 / 22196 | x3 / 90 |
| 151 | 153 / 802 / 24682 | x3 / 126 |
| 226 | 228 / 976 / 34856 | x3 / 127 |
| 300 | 302 / 1296 / 46478 | x3 / 128 |

四条候选在PC0x10238，SW编码0x0032a023；rs1=x5、值0x20000，rs2=x3，测量mem_addr0x20000、mask15、mem_wdata等于x3 word。它们不是ADDI零立即数复制，也不能从数值一致直接宣称RAM来源闭合。

## 新冻结源 actual online 与 raw fixture

新保存目录：[freeze-online](../../runs/current-dataflow-p3-uart-operand-use-20261006-freeze-online/)，独立构建缓存`runs/current-dataflow-p3-uart-operand-use-20261006-freeze-cache/`。在线4/4 complete、client exit0，保存**48,323事件**。FIFO retention/read、retired UART LW read、register seed及SW rs2 use各4条accepted；native cause20、taken4、controlled entry4。相关UART proof的incomplete/rejected/capacity/certainty barrier均0。

新trace的use输出IDs为22197／24684／34859／46482，对应raw SW退休IDs22196／24683／34858／46481、order83／153／228／302，精确引用x3的旧版本order81／151／226／300。不能复制旧记录的event IDs来关联新trace。

[冻结身份独立审计](../../.superpowers/sdd/current-dataflow-p3-uart-operand-use-freeze-identity-audit.md)确认401项repository source paths和36项online source文件与当前源码一致、0 mismatch；CPU/UART保存build identity与cache一致，实际binary SHA与cache manifest一致。Runner和3个新增identity列表绑定本次use源。

- online run identity digest：`47aa981c0aba54520dc42aecbe9c1f0c67c1600adc83cc58186b155f4a5aa30d`。
- trace semantic SHA256：`235fc6fbf471a087ec007f6597817a0031ff6d7cf44bb877e7a832523b8bd83e`；trace文件SHA256：`3f4cc6b47a0626a6dd46d88bf235485d48a320bde8e04174c6c269deb4d06b49`。
- CPU/UART build digests：`7c9e4e18f1cda153f8d6f2f8793311ea80df3329626c3675e5454eac767b627a`／`259d6d68dab394b4e23576e616e312c727058774897fb2e635e3c5d8c56bfe2c`。

本次`tests/integration/test_uart_operand_use_real.py`的raw fixture结果：**3 passed、2 subtests，30.34s，exit0**。它重构原始seed/use语义并执行凭据变动负例；更改SW凭据导致全CPU certainty barrier是预期failclosed行为，不能要求仍有旧seed accepted。[实际原始证据审计](../../.superpowers/sdd/current-dataflow-p3-uart-operand-use-real-audit.md)与身份审计分别保留，身份相同不是语义证明的替代。

## 本次完整fresh通过与范围

冻结源完整fixture实际结果：**8 passed、8 subtests，257.41s，exit0**。fresh CPU/UART会话的全部**48,323条canonical wire事件与local ticks一致**。该次门禁与前述raw use fixture **3 passed、2 subtests、30.34s**分开计数：完整fixture检验既有FIFO/native/entry/read链及whole-trace replay，use语义由原始独立重构fixture与审计验证。详见[本次受控路径门禁归档](current-dataflow-p2-controlled-entry-read-20261006.md)和[实际use原始审计](../../.superpowers/sdd/current-dataflow-p3-uart-operand-use-real-audit.md)。

该结果绑定本报告列出的新freeze-online/source/build身份。旧seed阶段的250.72s或独立263.20s fixture不是本次257.41s门禁，不能混用其时间和源码范围。后续RAM交付/字节writer、wholeword来源、copy与genericISR仍unknown；P2/P3整个阶段、无限长会话及搜索策略/反馈门禁未由此完成。
