# DMA state_dependency replay 修复独立审查

范围：冻结 WIP `dma_uart_rx_runtime.py::_normalize`、新测试源码、真实 state_dependency producer/schema、原始 native first-difference 与已有软件/离线摘要日志。没有运行测试、native、远端或修改实现；本轮只读及计算文件摘要。

## 结论

未发现本次最小新增归一化的高/中严重性问题。真实差异确为 root journal 的 state_dependency.source 内DMA执行nonce：其余TransactionKey后缀相同，原/新34794 events、ticks及complete status一致。新增scope足以处理该记录，并保留suffix、byte/version/data。此为replay身份比较修复，不是新native gate通过，也不抹去attempt4 exit1。

## Producer 与 scope 核对

`StateDependencyTracker._transaction` 用 `str(TransactionKey(**record['transaction']))` 创建读写依赖身份；RAW/PERSIST/WAW/WAR的source/target以同类repr进入StateEdge。Runner将asdict(StateEdge)的kind改为edge_kind，并加入event_id、producer_event_id、kind='state_dependency'。新增要求的完整字段集合与该producer真实结构相符，INVALIDATE边界中非TransactionKey target仍保持原文。

新event_record资格只赋给传入journal最外层list/tuple的记录；递归dict/list不会继承资格。因此nested payload即使具有完整state_dependency字典也不处理其source/target；仅含kind/source而缺edge字段也不处理；直接传单个dict不作为journal边。source/target中的值只有匹配TransactionKey前缀、已声明32hex execution token且有完整闭合字符串时才替换token，未知nonce不变，后缀逐字保留。没有替换raw序列化文本，也不归一化任意source字符串。

## 软件与离线记录

当前源SHA：`cbc59d31e20f6f9e151ff18473ea5874cec93973a93f2b0bb25937b081b7e816`。

新测试SHA：`ec183260041d5818299652ae8a2ad534a2628a7896268f9dcbcd1840036f808d`。

已保存RED记录1failed3passed/0.26s，失败为fresh state edge equality；GREEN5passed1skipped/0.29s。本轮未重跑，不能将skip计为native通过。新测试覆盖known source nonce相等、source sequence/target/offset/version差异保留、nested与不完整记录不改、未知nonce不改。

读取时saved-prefix-audit.log已经存在结果：原/新34794条的offline normalized comparison无差异、ticks/uncertainty/status一致，双方normalized digest为 `d1c1b2f7672d2a3d8c95b7a79c645d6a5e75577dc03a154cac0061073bef5919`，scope明确not new native gate。本轮只核对该记录的内容，未自行重读两份全量原始数据重算，也未执行其审计脚本。日志normalizer SHA是摘出的函数文件摘要，不能与整模块SHA直接互换。

## 低项和边界

- 当前“结构完整”指必需keys存在，没有逐项验证edge_kind枚举、整数字段/版本类型；repr regex对后缀仍为任意文本，未调用仓库已有精确TransactionKey parser。鉴于这里输入是受信producer journal而非authority入口，且后缀仍参与逐字比较，不构成本次已确认误授；若扩展到不受信bundle，应显式验证类型/枚举/六字段canonical key，不能称纯key集合检查为完整schema认证。
- 新测试未直接覆盖“source和target都含known fresh nonce时两边相等”的target正例，也未逐一删除每个必需edge字段；目前代码路径对二者相同，可补纯软件边界加强证明。
- 既有execution/execution_id及writer/uncertainty字段仍按任意嵌套字段名归一化。它们不是本次新增scope，不能用本次state edge修复声称整个_normalize已实现任意payload保真。例如payload.execution_id等于已声明nonce时仍会被既有分支改写。后续若承诺严格结构路径，需要单独收窄、回归及重验。

本次修复只涉及已声明process nonce的比较policy，不改变UART/FIFO/DMA/RAM/CPU实际字节、版本、IRQ/ISR证据，不增加FIFO-origin authority。应冻结新host身份并完成原gate的授权重跑后再报告native/replay最终结论；当前只可报告源码修复及已有raw离线一致性。
