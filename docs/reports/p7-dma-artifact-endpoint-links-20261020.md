# P7-D4-A DMA artifact endpoint links

日期：2026-10-20

## 已完成

新增 opt-in `render_dma_linked_runtime(...)`，只接受已注册的
`wishbone-dma-single-master.v1` issuer。凭据采集发生在 renderer 已解析的实际 master
到 `mwb` backend 赋值处，逐字段记录 endpoint、protocol side、模板选择和完整物理
role 映射（direction、width、physical port/member path/raw range/port width/backend
port）。凭据在普通 driver 生成之后绑定最终 runtime artifact、SystemVerilog 与 C++
摘要；不把 endpoint link 字段塞入历史 `LocalRuntimeArtifact.runtime_document`。

新凭据使用闭合的 `dma_artifact_endpoint_links.v1` 和
`dma_linked_runtime_artifact.v1`。旧 artifact 的 endpoint ID 或 `adapted_endpoint_ids`
不能单独签发凭据；导出前会以实际 artifact 重算最终 artifact/text/template/ABI/backend
与 role 映射。普通未启用 link collector 的 renderer 路径仍产出与该调用自身相同的
runtime document 和生成文本。

## 验证

- TDD 初始 RED 由实现者记录：新模块/API 缺失，测试收集失败；后续 malformed-artifact
  case 也先以预期异常失败，再经修复通过。
- 定向软件门：`PYTHONPATH=src python3 -m pytest -q tests/local_harness/test_dma_artifact_endpoint_links.py`，**26 passed in 2.41s**（本轮独立重跑）。
- 独立 task review：Approved；没有 Critical 或 Important 项。
- scoped `git diff --check` exit 0，新建 Python 文件 trailing-whitespace 检查为空。

## 边界和后续

这是生成 artifact 的端点/角色链接，不是 live Runner topology binding。没有创建 DMA runtime
graph、CPU 配置、route alias、DMA beat/effect/IRQ 证据，也没有执行 native/build/replay。
D4-B 仍待实现：静态 `route_id`、typed runtime edge、explicit runtime alias 和本凭据之间的
一对一拓扑绑定及保存/replay 凭据。历史 `read_master`/`write_master` 不会被自动映射；
P7-C F6 仍 `unsupported`，P6/P7/P8 与六 CPU／四 IP 总目标仍开放。

实现规格和分步计划：[D4 设计](../superpowers/specs/2026-10-20-p7-dma-intent-topology-binding-design.md)、[计划](../superpowers/plans/2026-10-20-p7-dma-intent-topology-binding.md)。


## Subsequent status update

On 2026-10-20, D4-B Task 2 added a detached static route-to-typed-edge
declaration layer, and Task 3 added live software topology binding plus a
mutation guard. See the [Task 2 report](p7-dma-intent-declaration-20261020.md)
and [Task 3 report](p7-dma-intent-topology-binding-20261020.md). Versioned
save/replay Tasks 4–5 remain open. This update does not change the scope of
the D4-A artifact-only credential described above.
