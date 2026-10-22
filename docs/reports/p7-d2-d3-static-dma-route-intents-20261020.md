# P7-B/P7-C 静态 DMA route intent v2：软件链与拒绝边界

日期：2026-10-20

## 本次完成

P7-B 现在接受闭合的 `harness_compose.v2` DMA route intent，生成
`harness_set.v2` 与 `wiring_contract.v2`。route intent 是协议无关的静态声明；
另一个一对一 binding 段保存发起端/目标端模板选择、profile endpoint 摘要，或
persistent-memory owner/resource 摘要。D2 在创建输出目录前检查实例、端点、
模板、窗口、权限、寄存器 offset、byte enable、目标资源和 aperture。无路由的
v1 产物路径保留原序列化，旧输出有固定 SHA 回归。

P7-C 严格读取 `wiring_contract.v2` 和 `path_wiring.v2`，复算 route wrapper、
profile endpoint 与 memory resource 摘要，并将静态 routes/bindings 放入编译 wiring
identity。它要求 route initiator 是已声明 master，且与该组件 `transfer` feature
operation 指向完全相同的 endpoint；同为 master 的另一个 endpoint 也会拒绝。
request supplement 合并不覆盖 route 声明或摘要。

route intent 不填入 live endpoint/target identity，不生成 `DMA_MASTER_TRANSFER`
runtime edge。F6 对无 route 的 mover 保持 `dma-master-route-undeclared`；静态 route
通过校验时仍以 `dma-route-live-topology-binding-required` 为由 `unsupported`。

## 端到端与下游读取

新增的 D2→D3 集成用例调用真实 harness-set generator，使用 Ibex、ZipCPU `wbdmac`
和 PULP GPIO profiles。测试为 ZipCPU 提供一个**测试专用** transfer feature sidecar，
目的是覆盖声明编译正例；它不是仓库中已认证的 ZipCPU sidecar，也不建立真实 DMA
能力结论。生成的 peripheral route 在 D3 合并一个 memory supplement 后，route digest
及 static binding digest 保持一致；F6 仍 unsupported，compiled runtime contract 不含
`DMA_MASTER_TRANSFER` edge。

生成产物 admission、capability report 与 auto-harness fixed-input reader 目前都是
v1-only 下游入口；遇到 `harness_set.v2`/`wiring_contract.v2` route intent 时现在给出
route-specific refusal，不会把它当作已理解的数据继续处理。compiled execution 文件
准备入口经 artifact admission 使用同一拒绝门。

## 验证

- `PYTHONPATH=src python3 -m pytest -q tests/scenario/test_dma_route_intent.py`：22 passed，227 subtests passed。
- `PYTHONPATH=src pytest -q tests/local_harness/test_harness_set.py`：29 passed（135.64s）。含 v1 固定 wiring digest 与 v2 positive/negative。
- `PYTHONPATH=src python3 -m pytest -q tests/scenario/test_compiled_paths.py`：49 passed，3 subtests passed（36.53s）。
- `PYTHONPATH=src python3 -m pytest -q tests/integration/test_p7b_p7c_dma_route_intent.py`：1 passed（12.75s）。
- `PYTHONPATH=src python3 -m pytest -q tests/integration/test_p7b_to_p7c_chain.py`：7 passed（73.30s），覆盖既有 v1 链。
- `PYTHONPATH=src pytest -q tests/integration/test_route_intent_reader_boundaries.py tests/integration/test_generated_artifact_admission.py tests/scenario/test_capability_report.py`：44 passed。
- `PYTHONPATH=src pytest -q tests/integration/test_auto_harness_test.py`：33 passed。
- Task 2 scoped `git diff --check` 通过；本轮 scoped `git diff --check` exit 0，新增文件 trailing-whitespace scan 为空，相关 source/test `compileall` exit 0。

## 未完成与范围边界

这是静态声明与软件读写链，不是 RTL/native DMA 运行。没有生成 live
`MasterTargetWindow`，没有 Runner/session topology binding、CPU DMA 配置、完成 IRQ/ISR
或 CPU 消费证明；没有授予 F6 执行或 P7-D/P7-E。P6、整体 P7/P8、六颗 CPU 与四个 IP
系列的总体验收状态不变。后续需实现 live binder，并以真实路由事务、错误负例和 fresh
replay 证明 runtime edge，方可移除 F6 当前拒绝。
