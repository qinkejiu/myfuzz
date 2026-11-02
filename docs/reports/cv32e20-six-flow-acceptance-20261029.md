# CV32E20 六 flow 原生验收，2026-10-29

CV32E20 主 profile（RV32I、32 GPR）在同一公共 shared-slot runtime、CPU/RAM/session 中完成八例：`F3 → F1 → F4 → F5高 → F2 → F6 → F5低 → F6`。original 与同次调用启动新进程的 full fresh 均完整完成，八例全部 `passed`，replay 为 `completed=true / matches=true / verification_scope=full`，build join 为 `complete`。

原始材料：[cv32e20-v2/original](../../research/input-strategy-audit-20261027/runs/shared-all-flows-20261029/cv32e20-v2/original/)。逐项独立核验及输入文件 SHA-256 保存在[验收 JSON](cv32e20-six-flow-acceptance-20261029.json)。未修改原始 prefix、replay 或 summary。v1 的 facade 缺少 `artifacts` 失败材料原样保留，不计入通过。

| 实际证据 | original / fresh 核验结果 |
| --- | --- |
| F5 高 / 低 | 各 `irq_isr=verified`，每例一条完整证书；原生 serial 分别 1、3，实际返回 PC 分别 70404、71172 |
| F6 两例 | 每例四字 `[1,2,3,4]`；五项义务全部通过，证据引用均解析到对应 inventory；CPU 配置、四字源版本/目的 commit、原生 IRQ、ISR 返回及实际后继证据完整 |
| CPU IRQ take | 两次 F5 与两次 F6 的 take key 顺序为 1、2、3、4；未将 `rvfi_intr` 单独当作外部 IRQ 来源 |
| 原始记录 | 两边均 38,384 events；local ticks 均为 CPU 977、DMA 1010、GPIO 1023 |
| 进程隔离 | original CPU/DMA/GPIO PID 为 3604237/3604269/3604301；fresh 为 3604519/3604551/3604583；六个 PID 与 execution nonce 独立，三组件均 reap 且 exit 0，相应 artifact/build/binary SHA 相同 |

对两份完整 prefix 独立应用公共 `_normalized_f6_prefix` 并以排序键、紧凑 JSON 计算 SHA-256，结果完全相同：`a38f6087097601eaedb1126ec5de0a8659c90a223d7bb2c2c97b13151c28b85d`。该投影保留原始数据、版本、来源与证明内容，并归一进程身份及由其派生的引用。

存储的 `prefix.semantic_hash` 字段本身不同：original 为 `b81640886a707b4fefaa37f2646bfb89adff206191500accf41c804202ac5fe1`，fresh 为 `bb1fd561f555a3cf76c30d940941181d2b3deaea4dc9604d731f94f7973bd22d`。独立用 `_trace_semantic_sha256(trace_status, actual_events, trace_local_ticks)` 重算，两边各自都精确匹配其存储值。该函数直接散列未归一的 raw trace；第一处 raw 差异是 `actual_events[45].f6_obi_scope[0]` 中不同的真实 CPU execution nonce，故不是 prefix 后补字段或计算时点漂移。因此本报告依据完整 normalized prefix 比较与 full replay，不声称该字段字面相等，也不将其直接用作跨进程 selector identity。

只读核对公共 `descriptor_search._prefix_identity`：F6/shared-slots 分支已先认证 raw trace hash，再使用完整 normalized prefix SHA 与 plan/genome/manifest/compiled 身份，未直接将上述 raw hash 当作跨进程 identity。本报告没有另外执行 shared state CLI 或 cross-CLI 验收。

运行时间原样记录：campaign execution **142.639827 s**，finish/export **45.875084 s**，within-invocation replay/export **267.923115 s**，入口至 scope/preparation 关闭总 wall **492.300172 s**。这些阶段口径不同，本次没有同源性能 A/B，不据此作提速或 DUT 时间主导结论。

本次证明的是上述 CV32E20 主 profile 与现有 DMA、causal GPIO 的公共执行与证据链复用，包括全部 F1–F6。fresh 是 **within-invocation 的独立新进程 full replay**，不是另一次 CLI 调用的 cross-CLI 验收；不外推到未注册 CPU、RV32E variant 或其他 IRQ IP。

## 后续公共 state CLI 与独立 fresh 验收

公共搜索配置为 `configs/search/shared-all-flows-cv32e20.json`，复用原七动作 catalog 与 goal，只更换 descriptor；使用同一 CPU-independent selector/provider。本节另行独立核对 [original search summary](../../research/input-strategy-audit-20261027/runs/shared-search-20261029/cv32e20-state-v1/original/search-summary.json)、[fresh search summary](../../research/input-strategy-audit-20261027/runs/shared-search-20261029/cv32e20-state-v1/fresh/search-summary.json) 和保存产物，结果与逐文件 SHA 见 [公共 CLI 独立验收 JSON](cv32e20-state-cli-acceptance-20261029.json)。未改写任何 raw summary。

请求为 `state / seed=7 / cases=8 / mixed / rounds=1024 / seconds=null`。实际八次在线决策为 `F3 → F4 → F3 → F1 → F1 → F5高 → F6 → F3`；原/fresh 的完整 selection（含 decisions、transitions、settlements、replayed costs）及 request 精确相等。原/fresh 均完成 8 例，没有 budget truncation。此次自然序列没有选中 F2，也没有 F5低；不把 directed 八例中的这些覆盖移入本次搜索声明。

独立重算 raw trace semantic hash、online-plan/genome hash 与完整 normalized prefix identity，均精确匹配各自 search manifest；两次 CLI 的 normalized prefix SHA 相同：`97349095d59e4e3803242c61549d942cca83a474f616f7acbc584607d887b876`。两份包含 839 项的 source manifest 相等，复核时逐文件 SHA 仍全部匹配。summary、execution-identities、shared-measurements 的文件 SHA 均匹配 manifest，三组件每次执行的实际 binary/manifest 文件 SHA 也逐一匹配保存身份。

original CLI 有 3 个组件进程；fresh CLI 有本次执行与 within replay 共 6 个组件进程。九个 PID、execution nonce 均独立，全部 reaped、exit 0。original 的 within/cross 为 `not-requested`；fresh 的公共 **search-summary** 中 within/cross/session-boundary 均为 `verified / matches=true`。其底层 `summary.json` 的 cross pending 原样保留，不混淆两层输出。

两边均只有 1 条 certified RAM write→read 关系，IRQ consumption、source origin、retirement 仍 unknown，coverage 为 unavailable。F5 被选择并不等同于获得 PIN→PADIN read credit，本次没有 F2；也没有离线 coverage 原生重放证据。original campaign/wall 为 87.571585s / 146.407227s，fresh 为 87.301715s / 297.213100s，fresh wall 包含其额外 within replay，不作为性能 A/B。
