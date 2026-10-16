# Stage 2 D4：能力契约与派生事件衔接

日期：2026-10-11。本文补充 [D4 版本／内部消费报告](stage2-d4-register-progress-20261011.md)。范围为生产 Python 消费者、真实源锁校验及软件观察 fixture；没有新增 DUT 运行或 fresh RTL replay。

## 与既有能力接口衔接

`EdgeProvenanceConsumer.bind_semantic_capabilities()` 将明确的 component alias 和语义 operation ID 绑定到现有 profile／sidecar 的 endpoint、operation 与 field scope；必须在任何 ingest 前，仅一次绑定该 alias。先通过既有 `assess_ip_test_level()` 核对 profile、sidecar 和 runtime preflight 身份，以及目标操作确实 declared／effective。没有另建等级规则。

profile、sidecar、完整 typed runtime preflight、显式绑定和缺口进入语义配置摘要，改变预检协议／映射也会改变身份。绑定失败不会发布半成品。snapshot 复用 `VerifiedCapabilitySnapshot`，引用 D1 中实际已认证的证据 ID。没有实测证书、当前状态 incomplete／unknown 或 journal 完整性失败时不提供对应能力 claim；reset 后历史证书继续保留，当前 claim 不复用旧资源。snapshot 不是 prerequisite witness。

可选 GPIO L2 规则复用固定 PULP profile 和实际源锁校验，核对原生布局、32-bit bank、声明字段 slice 和完整 access mask。具体证书另外核对实际 decoded offset 和操作语义。PADOUTSET／PADOUTCLR 的版本可以证明随后读 PADOUT，却不能证明直接写 PADOUT 的地址。证书现在保留原始写／读 offset、access ID、操作及 pre／post 值，不能靠目标寄存器标签替代实际访问身份。

内部 sync0→sync1 消费仍只授内部 scope。即使 sidecar 声明 completion，且 runtime 可执行，内部证书也不授该操作；绑定报告保留 `evidence-scope-does-not-cover-declared-operation`。未知 provider 同样不提供功能 claim。语义操作单独通过不会补齐尚未认证的 L1 操作，也不会自动授完整 L2／L3 或实际 CPU/IP 矩阵等级。

## 统一派生事件

`semantic_derived_events()` 从经过原生验证的台账和证书返回脱离的 `ip_register_event.v1`／`ip_function_event.v1` 投影。记录包含规则及版本、operation ID、epoch、证明 scope、历史有效性、D1 evidence ID、原始 journal 引用、runtime／配置身份和实际资源 payload。规范化摘要给出稳定 derived ID，重复查询不制造新的事实。

此处的原生 GPIO 观察路径没有 C1 的公共 base 投影，因此 `base_event_refs=[]`，同时明确记录 `native-observation-has-no-ip-base-projection`，不虚构公共事件引用。任意同值／伪造 base 注释不会填充该引用。投影不回写 raw／base journal，不把内部 consumption 改称 completion。后续 E3 生产插件输出和新观察路径必须保留其真实 base 引用；本次不宣称已完成该生产门禁。

## 验证与审查

初始能力／派生接口 **13 failed**，原因为接口缺失；实现后通过。runtime preflight 元数据漏入身份先被 RED 复现（不同协议集合得相同摘要），补入完整 typed snapshot 后通过。只读 reviewer 发现 SET／CLR 可过授 direct-write 的 P1；两个负例先失败，再按实际访问语义过滤。直接写正例和 SET 后读取正例均通过，修复没有撤销已有读取范围。

当前能力 **15 项**、派生事件 **4 项**，加统一接口 19、内部消费 13、L2 版本 29，共 **80 项**；与已有 B2 等级预检合计 **99 passed（0.98 秒）**。最终只读复核 78 passed（最后两个补充前），未发现其他具体范围过授路径。

```bash
PYTHONPATH=.:src python3 -m pytest -q tests/scenario/test_ip_semantic_capabilities.py tests/scenario/test_ip_derived_events.py tests/scenario/test_ip_semantic_evidence.py tests/scenario/test_gpio_sync_evidence.py tests/scenario/test_gpio_register_evidence.py tests/composition/test_ip_test_levels.py --tb=short
```

## D4 要求核对

| 要求 | 证据与边界 |
|---|---|
| L2／L3 额外版本／消费证明 | L2 逐位实际 writer→read，L3 已观察 sync0 版本→后续启用的 sync1 消费；都进入 D1 历史台账并统一 ingest |
| 无功能证据保持 incomplete／unknown | 未知 provider、缺 source、坏 probe／epoch、窗口过期及 journal 冲突负例；不授对应 capability claim |
| 协议接纳不等于内部成功 | 仅 accept／假注释无语义证书；内部消费不授 completion／外部 sample／IRQ／CPU 退休，D3 scope 保持独立 |

扩大兼容回归 **515 passed、218 subtests passed（100.64 秒）**，包括上述 D4 组、D1–D3、旧逐边与冻结 trace 复算、C3/C5、基础覆盖、runtime／source provenance、无插件边界及 B2。该组在最后两个补充测试前收集；新增 SET 后读取和冲突后不授 capability claim 在最新 99 项组独立通过。`git diff --check` 通过。没有新增 RTL 运行。

D4 按本表的软件范围完成，下一项 D5 RAM／IRQ 精确证明范围。D6 witness 生命周期、E3 生产派生事件、各功能族和真实 CPU/IP／HMAC 门禁均未由本报告授验收；整个 Stage 2 仍未完成。
