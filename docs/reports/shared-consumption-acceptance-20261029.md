# 共享 RAM / PIN 消费反馈与延迟归属验收

2026-10-29，独立读取已完成的真实 native 产物，未重新运行 DUT、修改证明门或 runner。核验记录为 [shared-consumption-acceptance-20261029.json](shared-consumption-acceptance-20261029.json)：绑定28份实际产物的 SHA256，并记录四套独立执行身份、关系、奖励与 reset 检查结果。全部离线断言通过；保存文件核验本身不产生 live authority。

证据根目录：`research/input-strategy-audit-20261027/runs/shared-consumption-20261029/`。入口均为 `scripts/run_shared_consumption_diagnostic.py`，复用原 shared-slot executor 与实际 `SharedSlotSelector`、同一 Policy/catalog/clock、已安装 RAM/PIN provider。动作选择使用明确标记的 scripted entropy，原 Policy 仍创建和结算每项 decision；这是定向正确性诊断，不是 uniform/state 策略效果比较。

## ③ 真实版本消费反馈

| 证据 | 实际序列 / 当前版本 | 原生结果 |
|---|---|---|
| `ram-v3/{original,fresh}` | F3:55 → F1 → F3:aa → F3:55 → F1 → F3:55 → F1 | 各7例、full replay；三次 F1 均有 native OBI read 与4条同版本 byte certificate，分别归属 F3 slot 0/3/5 |
| `pin-v1/{original,fresh}` | GPIOEN配置 → high → F2 → high → F2 → low → F2 → F2 | 各8例、full replay；F2 分别归属 F5 slot 1/3/5/5，包含同值新 admission 与 low 的实际读取 |

RAM 原生观察区分 `memory_write` 与真实 issuer `memory_write_commit`，通过同 producer/full transaction、resource、四字节版本/值/使能、原生 acceptance/response 区间精确关联。整数 `write_event_id` 与交易文本 `writer_event_id` 保持各自语义。三次值为55的当前字节版本实际不同，不能从值相等复用旧 writer。

PIN 由真实 F5 source admission、原生 pin 样本/PADIN 读、APB/CPU OBI 与 dependent RAM store 关联，不能用 GPIOEN token 冒充 PADIN 版本。两次 high 的 resource/admission identity 不同，第二次读归属第二个 writer。当前消费 frontier 只接受与 live writer resource/epoch/value 精确匹配的已认证关系；历史语义完成集合仅供去重。

RAM 反馈窗口为显式有界的 `min(65536, 8192*slot_count)`，本次8-slot配置为65536；超界仍 unknown，不承诺保留任意长会话或16个最重 slot 的全部历史。该关系仅证明 host RAM 当前版本经真实 DUT OBI 消费，retirement 与 source-instruction-to-store 因果仍 unknown。PIN IRQ 消费也仍 unknown。

## ④ 延迟归属、覆盖失效与奖励守恒

- RAM 首次55关系只有一个语义 key，writer / reader 各奖励1，总2；后两次同语义读取虽认证通过，新增奖励均为0。
- 未被读取的 aa writer（slot 2）被下一次写覆盖，结算为 censored、reward=null，无 relation 奖励。后两次55读取分别精确分配给 slot 3、5，不给旧 writer。
- PIN high / low 各一个语义 key，各分配 writer / reader 总奖励2，合计4。重复 high 和末次重复 low 读取不产生新增语义奖励。GPIOEN 配置动作不获得 PIN 消费关系奖励。
- RAM/PIN 两类 credit 共享 Policy，但按实际 family 互斥路由；F4/F6 没有这些已证关系时不获其消费奖励。terminal credit 无残留 pending。

两组的跨调用 `selection.json` 与 `diagnostic-prefix-identity.json` 均实际相等；fresh 重新构造原生会话和 provider，重新查询当前版本及关系。CPU/DMA/GPIO 在 original、其 replay、fresh、其 replay 四套执行中的 PID 和 execution nonce 各自全部不同，audit 均 closed/reaped/returncode=0；同一组件的 binary/build/artifact 身份一致。完整身份见核验 JSON，未把相同输入文件当成独立执行证明。

原 `fresh/summary.json` 的 `verification.cross_invocation` 仍显示 pending：该诊断脚本在 `run()` 尾部完成 selection/prefix 比较，未回写旧 summary。这里依据实际保存的比较结果与独立身份另作验收，不修改历史产物或把 pending 显示为它原已 verified。策略回放成本与实际 campaign 时间分开；本报告不作性能提升结论。

## 真实 reset 终端负控

`reset-ram-v2` 与 `reset-pin-v2` 均先取得实际消费关系与奖励，再执行 `warm_all`。两个 probe 各有一个实际 `reset_barrier`，CPU/DMA/GPIO epoch 均0→1。旧 RAM installation 因 process scope 变化拒绝，旧 PIN installation 因 process identity 变化拒绝；after 均 unknown、writer_attributed=false，RAM/PIN relations 均为空。

这是明确 `normal_campaign_completion=false` 的终端 probe：保存的 `failure.json` 类型为预期 `ResetProbeComplete`，不是普通 campaign 成功摘要。它证明真实 reset 后旧 provider/归属失效；不证明 reset 后重新安装 provider 并继续 slot execution，也不证明尚未运行的 cold_all 场景。

## 本轮 checklist

- [x] ③ 已在上述真实原生作用域验证 RAM F3→F1、PIN F5→PADIN/F2 当前版本消费；原/fresh facts 独立重算。
- [x] ④ 已验证最新 writer case 归属、RAM 覆盖 censor、同值新 writer、语义奖励去重与守恒、warm reset 旧 scope 失效。
- [ ] 本报告不关闭其它目标项；全6随机搜索效果、其它新 CPU 的 F5/F6、cold reset 后恢复执行、IRQ/source/retirement 因果与性能另行验收。
