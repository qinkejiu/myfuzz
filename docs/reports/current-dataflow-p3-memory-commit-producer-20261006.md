# MemoryService 冻结提交凭据生产者

日期：2026-10-06；最终复验更新：2026-10-07。本阶段完成host modeled RAM的成功write commit receipt生产者与软件验证，span identity类型负例已修复，P2/P3整体仍部分完成。**没有新增RTL/fresh门禁，也没有实现UART Store→RAM来源join。**

## 接口与提交边界

`MemoryService.write`在任何effect前检查完整六字段TransactionKey的严格类型。真实`TransactionLedger.execute_once` callback调用`PersistentMemory.write`成功后，冻结实际memory span、generation、payload摘要、enabled STORE cells和byte versions，形成`WriteReceipt.commit_document()`。查询返回独立JSON副本，不读取当前RAM、不物化disabled字节、不用后来的同值Store替代旧版本。

保留旧三字段构造、asdict、repr/equality ABI及原`memory_write`事件形状；内部冻结bytes不是新增wire字段。手动构造的旧receipt没有测量commit document。complete receipt构建后才记录成功事件；原始ledger对完整key与payload幂等，duplicate返回同一个旧receipt，不执行callback、不新增版本或effect。

实际返回version及每个STORE cell version均要求严格tuple2、uint64整数，绑定实际generation和per-memory commit sequence；bool/float即使数值相等也不能认证。BE0必须version=None、enabled cells为空、performed_effect=False，不发生byte effect。真实effect之后的callback失败或矛盾outcome保持ledger uncertain，无成功event，重试不能重复effect。warm/cold reset不修改历史receipt，新cold generation与旧版本区分。

## 最终软件证据与冻结身份

最终冻结源码：`src/myfuzz/scenario/memory_service.py`，SHA256 **`d2e1b1d3bcc8af6d26502ebf94b3ac45d9d64e499c84ef42c0888f48148d7998`**。

| 软件检查 | 结果 | 验证范围 |
| --- | --- | --- |
| Root较宽整合门禁 | 134 passed、26 subtests，1.38s | 新producer与既有memory/ledger、MEM-04故障检测边界兼容 |
| 独立type-review＋contract＋legacy memory/ledger | 86 passed、11 subtests，0.14s | 原11RED转绿、producer contract、14项独立typed version/span矩阵及新增错误span负例、旧ABI和幂等行为 |

10项类型矩阵分别修改实际returned version和STORE cell version，覆盖(False,1)、(0,True)、(0.0,1)、(0,1.0)、(False,1.0)。这些post-effect错误必须RuntimeError、uncertain、无success event且禁止第二次effect。额外独立探针确认BE0在read被禁止时仍无读取/物化，以及receipt构建失败后的准确uncertain语义。

既有MEM-04注入的endian/mask_shift错误现在会被新producer在较早的RuntimeError边界检出，早于原下游AssertionError。Root只调整该测试以接受两种有效检测边界；先前118项在be3f中途源通过，不是放宽effect一致性。

后续独立审查新增4项span identity RED：BE15的byte_offset=False／0.0，以及BE0的generation=False／0.0曾利用Python等价比较形成成功凭据。最终d2e1修复要求memory_id严格非空字符串、generation/offset严格uint64整数，并独立对照实际`_resolve`的region/offset和当前memory.generation；BE0也执行检查。四项原始RED及其他错误span负例全部转绿。返回version、cells与span检查失败均在成功event前留下uncertain，retry无第二次effect。

旧be3f及118／70项只作为中途软件证据保留，不代表最终验收。最终门禁为上述d2e1的134项整合与86项独立fresh软件；旧三参数构造、asdict三字段ABI独立再次确认。

证据：[生产者软件报告](../../.superpowers/sdd/current-dataflow-p3-uart-store-commit-software-report.md)、[独立RED→最终GREEN审查](../../.superpowers/sdd/current-dataflow-p3-memory-commit-red-contract-review.md)。软件模拟callback不能作为真实RTL RAM证据。

## 来源授权与后续限制

commit_id/payload SHA只是内容摘要，**不是来源授权**。receipt是数据容器；未来consumer必须绑定实际安装的MemoryService callback/ledger receipt、原始CPU请求与响应/退休，以及精确UART operand-use链，不能仅信自签document、accepted标签或摘要相等。

这里的RAM是host `PersistentMemory`模型，不能称为RTL RAM、物理bus时序或真实RAM芯片写入。生产者可确认完整BE15 word提交，但UART低8位来源仍需独立join；不能把四条written cells都标为UART影响。后续RAM byte writer来源、再读消费、generic ISR、whole-word污点及长期distinct instruction GC均未由本报告验证。

接下来需设计受限SW→host RAM commit join、安装可信receipt引用并更新source identity；另起冻结源实际online、raw重构负例与完整fresh门禁。本报告不授予任何尚未运行的新真实门禁通过。
