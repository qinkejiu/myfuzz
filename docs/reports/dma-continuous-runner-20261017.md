# UART RX DMA：单次启动四例与 fresh 重放

## 已实测的冻结范围

实际 attempt6 的 native pytest 为 **1 passed / 277.19 秒，exit 0**；前置软件门为 **65 passed / 70.42 秒，exit 0**。worker 退出码亦为 0。实现包含 `9eeff26` 的连续调度、`9125484` 的类型限定执行身份归一及 `1951a4a` 的失败文档 JSON 类型修复；独立远端副本的 426 个 Python 源文件预检保留在归档内。此证据不等于当前联合 HEAD 重新验证。

精确门禁为 `tests/integration/test_dma_uart_rx_runtime.py::test_continuous_native_uart_dma_prefix_and_failure`。一次 CPU 启动连续处理 `0x5a, 0, 0xa5, 0xa5`，逐例核对实际 FIFO 读取、DMA RAM 写入、CPU 读取版本、IRQ/状态/RVFI 和完成计数。测试将完整结果经过 JSON 往返，再启动 fresh 执行重放全部命令并比较完整归一事件前缀。另以原有 `max_source_ticks=1` 产生真实受控失败，并将失败结果 JSON 往返后 fresh 重放；严格比较原失败诊断和预算。

资源预算保持 300 秒；外层进程超时 900 秒没有替代内部预算。保存的四份结果分别为 `positive`、`fresh`、`failure`、`failure-fresh`。原生测试和 worker 的终态由退出文件确认；本报告不推定未单独保存的每个原生子进程退出码。

## 原始记录

- [完整 attempt6 归档](evidence/dma-continuous-20261017/attempt6-complete.tar)
- [归档与逐文件 SHA256](evidence/dma-continuous-20261017/attempt6-complete.manifest.json)

归档包含 worker、源码预检、修复收据、完整日志、退出状态以及四份 gzip 原始 JSON。[独立保存数据复核](evidence/dma-continuous-20261017/attempt6-independent-audit.json)逐份读取本次四个原始结果，使用冻结实现的类型限定归一器重新计算完整事件摘要。positive/fresh 各 **34,794** 条事件、4,774 条命令，CPU/DMA/UART ticks 为 **1314/1394/4790**；全事件摘要均为 `d1c1b2f7672d2a3d8c95b7a79c645d6a5e75577dc03a154cac0061073bef5919`。failure/failure-fresh 各 **200** 条事件、18 条命令、ticks **16/16/5**，全事件摘要均为 `b342064365dce6b9aee2464cea83225da98f047a20094268fe4653467f2a59de`。两对的 cases、失败诊断、预算、状态、源 pin 摘要及归一 uncertain 状态均相等，原/fresh 的实际执行身份集合互不相交。四份结果的完整 source_pins 映射还逐项等于归档内 426 文件预检映射。该审计仅操作保存数据，没有启动模型。

受控失败的 `trace.status=complete` 表示已记录的命令前缀执行完毕；失败仍由 `phase=source` 与真实错误诊断表明，不能据此前缀状态把失败用例描述为业务成功。

## 保留的失败历史

attempt4 原执行完成四例，fresh 因类型明确的 state-dependency 事务引用含新执行 nonce 而失败；修复只归一已发放身份的明确引用，不删除事件或放宽业务值。attempt5 已运行所有阶段，最后严格比较失败诊断时发现 Python tuple 与 JSON list 不同；`1951a4a` 将真实失败构造器输出固定为 JSON list，保留原测试断言。两次失败均保留各自原始归档，不改记为通过。

## 能力边界

等级为 **bounded_historical_chain**。FIFO 来源仍明确为 `unknown`；这是限定程序与输入的真实链、全前缀重放及负例结果，不授予一般来源权威、任意 CPU/IP 通用接入、覆盖驱动持续搜索或 P6/P7/P8 全部验收。六 CPU、四系列 IP 和联合 HEAD 验证仍有未完成工作。
