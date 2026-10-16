# BOOM primary GPIO native 证据独立复核

复核对象：commit `8a3fed344fbf9d77f2b5fe2fb12eee23596c0e5e` 的源代码、回归测试、native verification report，以及 `configs/cpus/boom/evidence/persistent-runtime-20261017/evidence.tar.gz`。已阅读 `agent.md`。本轮只解析本地既有证据、读取代码并计算文件摘要；未运行测试、编译、native simulator、源码认证构造过程或远端任务，未修改实现。

## 问题（按严重性）

**低：scope normalizer 对嵌套保留字段名的匹配仍宽于“任意 payload 不变”的文字承诺。** `boom_gpio_verification.py:scoped_prefix` 对顶层记录 scope 和 local_event_id 有结构限制，但 transaction/reset 分支只要求倒数第二级名称为 `source_transaction` 或 `native_acknowledgement`。因此类似 `payload.source_transaction.execution_id` 的任意嵌套字符串若等于声明 nonce，也会被替换；目前测试只覆盖 `payload.execution_id`。建议限定实际允许的交易/复位路径，或将文档承诺收窄到保留结构字段的明确定义。没有发现该边缘情况导致本次真实 fresh prefixes 出现被遮蔽的功能差异；原始未归一化数据完整保留。此项不否定当前 primary GPIO native 证据。

未发现推翻本次已保存 GPIO positive/control 结果的高或中严重性问题。

## 独立核对结果

本地重新计算归档大小为 **3,046,302 bytes**，SHA-256 为：

`be65978ca43a7f4ee5bae761a936094976207d3c695c9ffd9c37e52bc8faf586`

内部 manifest 列出 41 个证据文件；归档共有 42 个成员，额外成员为 manifest 本身。逐一计算全部 41 个文件的大小及 SHA-256，**零不符**。已有 `state/build.exit`、`state/gate.exit`、`state/one-shot.exit`、`state/focused-tests.exit` 内容均为 0。未把 launcher 最终状态描述为不存在的独立 verify.exit。

通过独立实现同一已声明 scope 规则，重新解析并比较 fresh1/fresh2 完整 events：两者均为 **20,597 records**，归一化后逐项相等，摘要均为：

`62891182387db436fbc07210c7a6e9a4615d60725d0015861cf6f9afb2da1141`

CPU/GPIO/runner/stream 声明 scope 在两次运行间均不同。两次都是 CPU 1,200 ticks、GPIO 1,208 ticks；CPU/GPIO OS PID 分别为 156014/156142 和 156700/156828，四个已记录进程退出码均为 0。两次实际 GPIO APB 写值、输出和读值为 53，native RAM 最终为 `(1 << 32) | 53`，manager drained 为 1。完整 accepted raw channel 计数均为 A=6、D=20，无 C/E。

源码 positive checker 同时检查原始 A/D、queued/completed source key、native execution identity、物理 APB access ID、router delivery/target receipt、CPU result stores、最终 RAM 和 coherent closed/drain。实际记录保留这些关联数据，不是仅保存一个 pass 布尔。六个关键 gate/session/driver/firmware/factory 源文件的当前本地摘要与归档 snapshot pins 相同。

changed_read 记录实际 GPIO read=53，offered D 高 32 位=52；CPU 最终 RAM 为 `(0xffffffff << 32) | 52`，说明读值替换传播到实际 CPU readback 和失败分支。missing_read 同样保留实际 GPIO read=53，但 offered response 为 null；CPU result RAM 保持 0、drained=0、coherent pending_sources=1。两项均无 recorded transport exception，coherent structural_error=false，CPU/GPIO native exits 均为 0；它们是刻意施加的环境响应控制，不能记为 DUT bug。

归档 source pre/post 检查报告均为 2,366 files、零 mismatches。native session artifact/build log 和原始退出文件存在。归档没有完整 native binary/RTL 副本，因此本轮能确认的是 artifact 中保留的 closure 摘要、snapshot pins 与记录的一致性，不能离线重新执行或独立重编译证明该 binary 的来源。已读 launcher 明确区分新 persistent build 与旧 one-shot prior executable；prior binary provenance 文件存在，未混作新 persistent C/E 证据。

测试源码覆盖 manifest omission、重新标记哈希的 RTL/manager 篡改、duplicate/stale callback、非法 register shape 和 scope payload preservation，以及 scoped host discovery。归档实际 focused log 为 **15 passed in 1.07s**。报告另列本地后续 16-test 结果；本轮未重跑或将其伪装为归档 native 结果。

## 结论与边界

已有归档支持当前 **persistent BOOM → standard ScenarioRunner/DataflowRouter → actual PULP GPIO → CPU readback/branch → native RAM** 的 primary native gate，两次完整 fresh prefix 相等，改读值与缺响应控制具有所记录的因果效果。此判断来自既有 native 证据的独立解析，不是本轮新执行通过。

本 GPIO firmware 只覆盖 A/D；**新 persistent C/E cached-RAM 路径尚未由本归档证明**。旧 one-shot 的 C/E 和 read-corruption gate 保留独立 prior-build provenance。该证据也不证明任意 firmware/调度、warm RAM retention、IRQs/probes、ISA retirement、独立 memory commit/source authority、generic runtime admission 或完整 P6。
