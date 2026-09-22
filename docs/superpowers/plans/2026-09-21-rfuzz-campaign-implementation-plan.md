# Profile SoC 官方 RFuzz campaign 实现计划

基于 `docs/superpowers/specs/2026-09-21-soc-rfuzz-campaign-integration-design.md`，把已经存在的 profile SoC 组合路径接入官方 RFuzz client。当前工作树已有其他 SoC 变更，实施时只修改本计划涉及的接入边界并保留已有编辑。

## 全局约束

- 生产 RFuzz 路径必须使用官方 `kfuzz`、现有 FIFO/共享内存 protocol-2 和 persistent RTL simulator。
- Verilator 必须来自 `myfuzz.rfuzz_compat.resolve_rfuzz_verilator`，并通过 `validate_rfuzz_verilator_version` 验证 `Verilator 5.020`；不得把 PATH 中其他版本作为无条件 fallback。
- 缺少官方 client、bundled Verilator、真实 RTL 编译闭包、有效 receipt、非空 corpus 或清理证据时运行失败，不得降级为 seeded-corpus 后报告 RFuzz 成功。
- 工具路径、版本、哈希和环境必须进入 artifact provenance、cache key、campaign report 和 replay identity。
- 首期只运行一个官方 RFuzz arm；三臂比较只能重放同一份官方 raw corpus，不能把三次独立 fuzz 运行写成同输入对照。
- BFM `isolated/contention`、跨域中断和独立 peer oracle 不在本次接入范围。

## 任务

1. 增加 RFuzz 工具链 resolver 和 campaign 配置归一化：支持 `rfuzz` 子对象、客户端环境变量、bundled Verilator、版本/路径冲突拒绝和可审计身份。
2. 修改 profile builder：固定使用 resolver 返回的 Verilator 和环境，加入 provenance/cache/tool identity，拒绝旧 PATH 工具。
3. 将工具链记录传入官方 campaign/live runner，补齐单臂 profile campaign 的失败分类、清理和报告字段。
4. 增加官方 corpus 的三 projector 严格重放入口，使用同一 executable/layout/source/tool identity 并拒绝漂移。
5. 增加缺依赖、身份漂移、profile 单臂和 corpus replay 契约测试；在依赖可用时运行真实 opt-in 回归，依赖缺失时保留明确失败证据。
6. 汇总 capability matrix、acceptance report 和 remaining implementation 文档，准确反映 seeded-corpus 与官方 RFuzz 状态。

## 验收

- 快速契约测试覆盖 resolver、配置冲突、builder tool/env/provenance/cache、campaign failure/cleanup 和 same-corpus arm identity。
- `MYFUZZ_SOC_REAL=1` 且官方依赖存在时，profile composition 真实通过 `kfuzz -> FIFO/shared memory -> Verilator`，生成非空 corpus、receipt、coverage 和 replay manifest。
- 官方依赖不存在时，测试报告具体的 `rfuzz-client-unavailable`、`rfuzz-verilator-unavailable` 或版本不匹配，而不是 skip 成功。
