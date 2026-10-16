# Stage 2 D3：通用绑定运行证据进度

日期：2026-10-11。本文记录 D3 的绑定部分。后续协议部分已完成软件验收，详见 [D3 精确协议证据报告](stage2-d3-protocol-evidence-20261011.md)；D3 按两份报告的软件范围完成，真实 DUT 门禁及 D6 仍待后续。

现有 `EdgeProvenanceConsumer` 新增启动前、仅一次的 `configure_base_events()` 接口，冻结受信组件的基础事件配置。它仍使用既有 runtime edge 声明、端点、来源提示、journal 引用和证书接口，不从观测创建 topology 边，不依赖 GPIO/UART 功能消费者。未配置该接口的旧消费者不自动升级基础事件。

`IpBindingEvidenceVerifier` 使用既有 `IpBaseEventNormalizer` 根据可信配置和真实 raw receipts 重建 `binding_delivery` 与 `input_sample`，逐字段比较投影。必须解析独立、按顺序记录的 source raw → raw dataflow delivery → base binding delivery → target raw pre sample → input projection；原始交付本身须指向声明边、匹配精确端点／位段，并引用实际 source raw。源端实测位段、交付值、目标交付位段和实际输入必须一致。物理 ABI 切片已经由 harness 选择，不重复移位 `bit_lo`。

目标投影必须携带精确的 base delivery 引用和 target raw 引用，源投影也须引用同一个实际 driver。实际 source／target 各有自己的局部 clock、tick 和 reset epoch，不比较不同组件的局部 tick 大小。跨 case 只改变观察归属，不切断同一连续会话中的显式交付。证书新增 raw input 与 base delivery 引用及 `binding_delivery_sample` scope；不授予源动作导致输出、寄存器副作用、功能消费、CPU IRQ 接受或退休的证明。

新生成的 v2 通用 APB3／TL-UL／Wishbone runtime document 声明 `raw_observation_schema_version=ip_raw_observation.v1`，纳入现有 artifact digest。Runner 仅在 artifact 显式声明时将当前 session 的实际 reset epoch 和观察版本冻结到新的原始 sample envelope；旧 artifact 不增加这些字段，已有 raw 输出内容不改写。缺失版本／epoch 的旧证据不能获得本次新认证。

新认证在 raw receipt 与投影之间出现 reset、不同 epoch、目标后续交付（包括同值交付）或证据过期时保持未认证。保留 journal 记录使用深复制，调用方不能在分批 ingest 后修改已经观察的嵌套输出。缺行、畸形记录或冲突重复 ID 使本消费者会话不再授予新的基础 binding 证书；相同内容的重复 ID 仍由原策略计为 rejection，不改变已有证据。这是保守完整性拒绝，不代表 D6 的恢复或已生成证书失效逻辑已经实现。

## 测试与复核

- TDD 初始完整／逐条／跨 case 正例均为 `incomplete`，证明现有消费者尚无该能力；实现后通过。
- 绑定定向测试：38 passed，覆盖错误值／端点／位段／epoch／引用、post 采样、缺 raw epoch、跨 case、前后 reset、覆盖交付、过期、配置冻结、调用方篡改、重复 ID 冲突和缺行。
- 实际生产 Runner／normalizer／source provenance 的跨 case 软件 fixture 按逐条 ingest 认证完整绑定链，并核对 source raw、base delivery、target raw 三个精确引用。session 是软件回执 fixture，不是 DUT 运行。
- 新 runtime artifact schema 声明测试先失败后通过；新旧 raw envelope 兼容测试先失败后通过。
- 只读 reviewer 发现的一致伪造目标值、畸形端点崩溃、receipt 后 reset、浅复制篡改、重复 ID 冲突均有 RED → GREEN 复现。最终只读复核 38 passed，未发现 binding 增量的其他具体误认证路径。

兼容回归：296 passed、218 subtests passed（99.89 秒），包含既有逐边来源、冻结真实 trace 复算、runtime edge、来源归属、D1/D2、基础覆盖及禁止功能消费者导入检查。此前更小的逐边／C7／schema 组合为 112 passed；后续 schema 声明检查扩展到 APB3／TL-UL／Wishbone 三类，独立 3 passed。未启动新的 DUT 构建／运行；冻结 trace 的复算不等于 fresh DUT replay。`git diff --check` 通过。

本报告不证明 Stage 2 真实 DUT、fresh replay、四核／HMAC 矩阵、协议事务认证或 D6 完成。

## 下一步

继续 D4–D8，包括额外功能版本／消费证据、持久状态、历史／active witness 与探索预算。协议 request → accept → response 已由后续 D3 协议报告验证，不把本报告早期未完成状态当作当前待办。

复核命令：

```bash
PYTHONPATH=.:src python3 -m pytest -q tests/scenario/test_ip_binding_evidence.py
PYTHONPATH=.:src python3 -m pytest -q tests/local_harness/test_ip_raw_observation_contract.py
```

296 项兼容组包括上述绑定测试、`test_edge_provenance.py`、`test_edge_provenance_binding_consumer.py`、`test_dependency_candidates.py`、`test_dependency_evidence.py`、`test_ip_base_coverage.py`、`test_ip_plugin_free_fixtures.py`、`test_ip_plugin_import_boundary.py`、`test_runtime_path_contract.py`、`test_runtime_edge_index.py`、`test_source_provenance.py`、`test_runner_source_provenance.py`、`test_dependency_edge_paths.py` 以及扩展前单项 raw schema 声明测试。全部以 `PYTHONPATH=.:src python3 -m pytest -q … --tb=short` 执行。三类 schema 扩展后另行执行上面的独立检查；最后绑定／C7／三协议 schema 组合 64 passed（5.74 秒）。
