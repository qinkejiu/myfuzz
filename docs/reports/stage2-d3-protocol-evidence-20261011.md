# Stage 2 D3：精确协议事务证据

日期：2026-10-11。本文记录 D3 的协议部分；显式绑定部分见 [D3 绑定进度报告](stage2-d3-binding-progress-20261011.md)。验收范围为生产 Python 消费者与软件回执 fixture，没有新增 DUT 构建／运行或 fresh RTL replay。

## 实现与证明范围

既有 `EdgeProvenanceConsumer` 新增启动前、仅一次的 `configure_protocol_events()` 和独立 `protocol_evidence_report()`。同一 ingest journal 同时进入逐边／来源消费者和协议证据消费者；未配置协议证据时保留原有报告行为。协议证书不创建外部 runtime topology 边，不把 EVENT_ORDER 推断成动作导致功能输出。

`IpProtocolEvidenceConsumer` 复用 C3 的 `IpProtocolEventNormalizer` 和 C5 的 `IpProtocolChecker`，只根据受信声明的实际 pre-edge passive taps 重建事务。raw 必须显式声明 `ip_raw_observation.v1` 并携带实际 session reset epoch；旧 artifact 的未版本化 raw 不升级。

每个协议证书必须同时拥有通过逐字段比较的 request、accept、response 基础事件，并保留三者各自实际 raw 引用。`related_request_event_refs` 必须解析到该次原始请求；没有接纳、缺投影、错误请求引用、重排、错 epoch、重传、超时／取消或 Checker 违规均不能形成证书。Checker 从 raw 独立运行，删除 journal 中的 finding 注释不能绕过它。原生错误响应仍可证明协议边界完成，但 `outcome=error`，不宣称功能成功。

TL-UL 保留 endpoint／epoch／原生 source 事务键，并以原始 request raw ID 区分同一 source 的后续重用。不同 source 的响应可乱序，必须回到各自原始请求。APB3／Wishbone 的事务键保持 null，显式保留 `protocol_has_no_transaction_id`；顺序关联只证明其受信协议子集内的实际接纳／响应。

## 分类、来源与有界性

证书通过 D1 `DependencyEvidenceLedger` 分类为 `verified`、`protocol_transaction`、`protocol_accept_response`，引用冻结的 declared 协议边界记录、观察配置 SHA256 和已有 runtime contract SHA256。declared 记录只登记受信接口事务关系，不授运行认证，也不回写 DependencyGraph。保存／重载仍能验证分类、摘要和 declaration 引用。

所有完成事务记录明确标记 `validity=historical`，不用于 prerequisite。request／response case 从各自实际 raw 的来源元数据读取；source admission、原始 action／case 仍可经 raw journal 精确引用复核。事务证书不授予 action→输出因果、寄存器副作用、内部功能完成、RAM writer、IRQ 接受或 CPU 退休。

默认 pending 1024、journal gap 4096、证书 4096、诊断计数上限 65535；配置参数为正整数、有上限且拒绝 bool。配置最多 1024 个组件，信号最多 64 个、名称最多 1024 字符、宽度与等待预算至多 65536。每组件的原生 normalizer／Checker outstanding 状态也受 pending 限额约束；溢出清空并禁用该 epoch 的授证。配置冻结，report 返回脱离副本。

expected 只保留声明 taps、必要 header 和经校验的 case，避免保留任意 raw 详情。case 仅允许明确的 `case_id`／`case_index` 映射，字符串最多 1024 字符，索引为 null 或非 bool 的非负 64-bit 整数。错误元数据拒绝进入 pending／证书。

reset／epoch 变化移除旧 pending；证据过期或淘汰不补造请求。缺行或冲突重复 ID 使 journal 完整性失败并停止新授证；相同内容的重复不会改写记录。既有已完成证书的失效与 active witness 恢复属于 D6，本次不宣称完成。

## 验证

初组 TDD 正例在旧消费者上为零证书：9 failed、11 passed；实现后 20 passed。后续加入台账、边界、case 详情、生命周期和乱序响应检查，当前协议 59 项、绑定 38 项，联合 **97 passed**。负例修改普通脱离列表中的实际 journal 行，不依赖 EventJournalSnapshot 的迭代副本。

生产 Runner／normalizers／source provenance 的既有三协议跨 case fixture 新增证书断言：原始 request／response raw 引用、起始／消费 case、历史 scope 均精确一致。EVENT_ORDER 没有被升级为 topology 边；新解释器禁止功能消费者导入的 fixture 检查仍通过。

只读 reviewer 发现的 provenance 类型崩溃和无界 case 详情均经 RED → GREEN 修复；最终复核协议／绑定联合 92 passed（当时协议 54 项），未发现其他具体错误授证或越界路径。随后补齐三协议 stall、TL 乱序响应及重复 source 5 项，联合 97 passed。

兼容回归 **378 passed、218 subtests passed（123.13 秒）**，包括既有逐边证据、冻结真实 trace 复算、C3/C5、基础覆盖、D1/D2、runtime edge、source provenance、禁止功能消费者导入及三协议 raw schema 检查。该组包含补齐前的协议 54 项；新增 5 项在上述 97 项联合组独立通过。`git diff --check` 通过。D3 按上述软件范围完成；完整 Stage 2 CPU/IP／HMAC 矩阵、fresh RTL replay 及 D6 未完成。

复核命令：

```bash
PYTHONPATH=.:src python3 -m pytest -q tests/scenario/test_ip_protocol_evidence.py tests/scenario/test_ip_binding_evidence.py --tb=short
PYTHONPATH=.:src python3 -m pytest -q tests/scenario/test_ip_plugin_free_fixtures.py tests/scenario/test_ip_plugin_import_boundary.py --tb=short
```
