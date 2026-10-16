# Stage 2 D4：寄存器版本证据实施进度

日期：2026-10-11。本文记录 D4 首步及统一语义／原生消费增量；D4 现已按软件范围完成，最终能力与派生事件衔接、验收边界见 [D4 衔接报告](stage2-d4-capability-events-20261011.md)。没有新增 DUT 构建、运行或 fresh RTL replay。

## 实现范围

`GpioRegisterEvidenceConsumer` 根据显式 component、register、bit slice 和已有 runtime contract 身份，复用 `GpioConsumptionTracker` 从实际 `gpio_apb_access`／`gpio_tick_observation` 重算版本。derived 注释与协议接纳不授证。

只有后续真实读取的每个选定位资源与原始写入资源完全一致，且写者仍在保留窗口内，才生成 `persistent_state`／`register_version` 证书并写入 D1 台账。证书引用原始写／读 journal ID、观察配置和 runtime 摘要，保留完整事务与各自 testcase。相同数值覆盖写创建新版本；set／clear 未触及位保留原写者。64-bit 寄存器切片须位于单个实际 32-bit 读取 bank。

declared 记录登记显式观察关系，不改写外部 DependencyGraph。寄存器证书全部为 historical，仅描述写入→读取版本关联，不授 CPU 退休、动作来源、内部功能完成或 prerequisite。L2 适配器的 `functional_status` 始终 unknown；reset 后历史证书继续保留，但当前 `register_status` 回到 unknown。

## 完整性与容量

全局 journal ID 必须连续；保留窗口内相同重复为无效操作，冲突、过期重复或缺行永久停止本消费者新授证，reset 不修复 journal 缺口。local tick 连续，上一 post 与下一 pre 的所有原生寄存器相符。生产 ACCESS→同周期 tick 配对仅在快照和 command scope 全部一致时接受。

缺少 ACCESS 的原生写入阻断认证，即使 ready=0 或值未变；完成但无 ACCESS 的读取也阻断。完整 source transaction 不得重复用于另一 access。坏契约、响应冲突、未知 epoch、不确定目标访问和容量损失均保持 incomplete，注释不能恢复。

默认证书 4096、journal 窗口 4096、每 epoch access 256；配置为非 bool 正整数，最多 65536。access 容量耗尽停止本 epoch 认证；advanced reset 才清除资源范围屏障。只保留声明探针及必要身份，事务／scope 有类型和长度边界，任意注释不进入 native tracker／边沿缓存。report 为脱离副本。

## 验证与审查

初始 22 项因消费者缺失失败，实现后通过。继续经 RED→GREEN 修复：删除同值覆盖 ACCESS 而保留 tick、重复完整事务身份、大型注释进入长期缓存。只读 reviewer 发现 ready=0 native write 变体，也经 RED→GREEN 修复；最终 adapter／GPIO versions／D1 复核 90 passed，未发现其他具体错误授证路径。

首步生产 Runner＋EventJournal 软件 fixture：跨 case 原始写／读 ID 精确匹配；去掉 derived 注释后证书不变。L2 adapter **29 passed**；首步联合回归 **254 passed（1.09 秒）**，包括 GPIO routed receipt／reset／source alias、D1、D3 协议／binding 和 C7 新解释器禁止功能消费者导入。软件回执不是新 RTL 运行。

```bash
PYTHONPATH=.:src python3 -m pytest -q tests/scenario/test_gpio_register_evidence.py --tb=short
PYTHONPATH=.:src python3 -m pytest -q tests/scenario/test_gpio_register_evidence.py tests/scenario/test_gpio_consumption_versions.py tests/scenario/test_gpio_routed_consumption.py tests/scenario/test_gpio_runner_receipt_review.py tests/scenario/test_gpio_reset_review.py tests/scenario/test_gpio_source_alias_review.py tests/scenario/test_dependency_evidence.py tests/scenario/test_ip_protocol_evidence.py tests/scenario/test_ip_binding_evidence.py tests/scenario/test_ip_plugin_free_fixtures.py tests/scenario/test_ip_plugin_import_boundary.py --tb=short
```

## 统一接入与内部消费增量

`EdgeProvenanceConsumer.configure_semantic_events()` 在任何 ingest 前仅配置一次，统一 ingest 将同一原始 journal 交给可选语义消费者；`semantic_evidence_report()` 逐操作独立报告证据。配置仅有 level、版本化 provider ID 和有界数据参数；代码维护的 catalog 延迟加载明确选中的 provider，不按组件名字猜测功能，不执行配置中的模块路径／脚本／callback。未知或缺失 provider 保持 unknown，坏 journal 保持 incomplete。配置与预算进入规范化身份摘要。

L2 的 `register_version` 和 L3 的 `functional_consumption` 分别计数，都是历史观察次数，不能解释成完整链收益或实际 IP 已授级。provider 与请求 scope 不匹配时拒绝；参数树深度、成员数、字符串和字节总量均有界。默认最多 16 个操作，每操作证书 256、access 256，journal 窗口 4096；操作数硬上限 128，其他预算上限 65536。基础／旧报告 shape 不变，无 provider 时不导入功能消费者。

`gpio_sync_consumption.v1` 复用同一原生认证和 tracker，只认证实际启用的 sync1 边沿消费了先前已观察 sync0 的精确逐位版本。必须具有原始 producer／consumer journal ID、同 epoch、后续 tick、完整 native dependency 引用及未过期版本。基线版本、相同数值、保持不动的 stage、缺 source、坏 post、假 derived 注释均不授证。scope 严格为 `sync0_to_sync1_version_consumption`／`internal_stage_consumption_only`，不声称外部动作来源、IRQ、CPU 接受或整体功能成功。

初始统一接口 19 项及同步级 11 项因功能缺失失败，实现后通过。补充历史成功但当前版本过期的 RED→GREEN，以及生产 Runner／EventJournal 跨 case 原始 source／consumer 引用检查；删除 derived sample 注释证书不变。当前统一接口 **19 passed**、内部消费 **13 passed**，与 L2 共 **61 项**。只读增量复核 59 passed（补充前），未发现具体错误授证路径。

扩大兼容回归 **478 passed、218 subtests passed（100.42 秒）**，包含 D3 两类认证、旧逐边／冻结 trace 复算、C3/C5、基础覆盖、D1/D2、runtime／source provenance 及无插件路径。该组在最后新增同步级生产跨例 fixture 前收集，包含内部消费 12 项；该新增项在最新 61 项定向组独立通过（0.57 秒）。`git diff --check` 通过。没有新增 RTL 运行。

```bash
PYTHONPATH=.:src python3 -m pytest -q tests/scenario/test_ip_semantic_evidence.py tests/scenario/test_gpio_sync_evidence.py tests/scenario/test_gpio_register_evidence.py --tb=short
```

## 后续工作

D4 的逐操作能力契约、`VerifiedCapabilitySnapshot` 和统一派生事件接口已完成软件衔接，最终 80 项 D4 定向检查及 515 项兼容回归见衔接报告。下一项 D5；生产调度／E3 插件 journal 输出、D6 active witness 与真实 CPU/IP／HMAC 门禁仍待执行，不授实际 IP 等级或 prerequisite。
