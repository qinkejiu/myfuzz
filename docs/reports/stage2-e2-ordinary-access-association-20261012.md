# E2 ordinary APB Runner association — 2026-10-12

当前状态：本轮 Runner association 软件包已实现并独立复核，最终生产及测试 SHA 核对一致。原 Stage2 全计划继续执行，E1/E2 尚未完成。

本增量在第一包目标命令 receipt 与 Router 交接基础上增加显式、默认关闭的 `ScenarioRunner.install_ordinary_apb_access_evidence(max_records=...)`。安装须在 begin 前，目标须已配置普通 receipt；身份文档仅启用时包含配置，已有默认布局保持。新增 snapshot API 返回分离副本，保存文件或调用者引用不能注册可信证据。

Collector 从实际 CPU service、ledger、router、window、memory 对象及目标实例建立绑定。源 reset epoch、目标 reset epoch 与 memory generation 分别保存；原生 APB base event 的 transaction key 仍为 null，关联由真实队列、目标命令与 journal 引用建立。新增 association 保存 target receipt、acceptance、delivery、raw/base 独立引用，scope 仅为实际命令和协议边界关联，`grants_verified/storage/functional` 均为 false。

目标 strict wire parser 成功解析的原始 phase 内容具有私有 digest；可变样本队列及公开 event tag 不能替换原内容。Router 私有 confirmation 只在排队 callback 成功返回后产生；同步返回及失败 callback 无确认，公开 bool 或 delivery 副本修改不能创造确认。容量和配置校验在目标 STEP 与访问命令前运行；失败及 reset 显式记录缺口，历史保留，不静默淘汰。

## 当前检查与待修复项

- Root Router 私有 confirmation 五项与已有 router 回归合计 33 passed（8.90 秒）；容量负例先 RED 再修复。
- Renderer collector/helper 候选联合 46 passed（28.67 秒），包括原样本 private digest、实际 acceptance 内容、projector 配置及重复 preflight 上下文校验。
- Runner 与五个既有相关模块合计 43 passed（27.92 秒）；新增十项覆盖实际 journal 引用、默认布局、容量及 warm/cold 软件 reset。真实 callback 内部失败单项通过（9.27 秒）。
- 独立 callback confirmation 三项通过（5.22 秒），sample digest 生命周期三项通过（5.50 秒）。Root 组合 identity/acceptance 两项通过（9.27 秒）。
- Root 新来源负例 1 failed（9.45 秒）：把真实 CPU `_serve` 的 queued callback 换成 no-op，CPU `_pending_data` 仍为 None，却出现 `cpu_delivery_confirmed`。修复已增加实际 completed closure、完整源 key/request、实际响应 tuple 与读写计数检查。Root 组合三项及 collector/前包边界联合 34 passed（28.32 秒）；独立六项伪 enqueue／callback／closure 替换负例已转 GREEN（5.55 秒）。合法排队等待允许 acceptance tick 小于当前 tick，重复检查固定原请求内容。独立检查随后发现 decoded queue 的 byte enable／data32／offset 可被改动而预检仍放行，三项 RED（5.37 秒），已补纯重算与 method pin；missing delivery 降级另有独立 RED→GREEN。最终生产 SHA 下独立完整 boundary 16 项通过，复核无剩余重要生产缺口。首轮 root 联合回归因此主动中断：127 passed、1 项未消费前响应的软件夹具失败（92.72 秒，exit2），不能计最终通过；夹具只补模拟消费，生产来源约束保留。最终联合回归须在此修复后重跑。

以上均使用实际生成的 artifact、真实 Python CPU/service/router 对象和 strict parsed 软件 transport。未执行本增量 RTL。当前源 SHA 已不同于之前实际 CLI gate，历史 gate 只证明其冻结版本；最终回归结果及本增量 SHA 见下文。软件 transport 使用实际 artifact 与前端 elaboration，未启动 DUT 仿真或新的实际 CLI gate。

## 后续执行

完成上述交付来源修复和联合验证后，继续生产 Session/assembly opt-in 身份、源码闭包与 fresh 原请求重建。CLI 目前尚无本通道启用选项。随后实现 code-owned 分操作 verifier：full READ 实际 CPU/APB 响应一致，WRITE/RMW 必须有之后的真实 CPU readback；实际 reset、新 epoch 读值、权限、mask、width 与已支持副作用仍为原 E2 必需工作。SET/CLR alias effect 与 read-clear 条件分别处理，部分观察不能授 aggregate L2。

前包及设计入口：[目标 receipt 首包](stage2-e2-ordinary-access-receipts-20261012.md)、[Runner 设计](stage2-e2-ordinary-access-runner-design-20261012.md)、[完整 next steps](stage2-e2-register-replay-next-steps-20261012.md)。

## 本增量生产候选 SHA-256

下列源码在最终联合回归启动前固定，终态后再次核对无漂移。旧报告与历史实际 gate 的 SHA 保持原值。

- `src/myfuzz/local_harness/ordinary_apb_access_receipts.py`: `14641232586227568f3388f2cc88b0a5ac19ae96b92c048fe36d7174c46e4692`
- `src/myfuzz/local_harness/gpio_session.py`: `7bb99987f96ac70d15a4d2dbc3f73792117d11d9872c23f1c1724ed72ecb9300`
- `src/myfuzz/scenario/router.py`: `d32f54b41608da1b14eb33b548512d66efca9a4727744cd27c87a39cbe3fedef`
- `src/myfuzz/scenario/runner.py`: `d9e363f604f2b5a68cb83022b9a419ceec815e031bca94bc87bb5e1b939a95ec`
- `src/myfuzz/scenario/ordinary_apb_access_evidence.py`: `e56766d4c021dbeb22e62950d385e4f4f85a4a2d9e06e8a66c54543916e7f49c`

最终生产候选下 renderer 联合 44 passed／1 软件夹具失败（47.38 秒），reviewer 联合 42 passed／同一夹具失败（25.02 秒）；都不计整组通过。Root 第二次 broad 在发现夹具尚未落盘时提前中断（32 passed，18.68 秒，exit2），等待夹具修复冻结后单次完整重跑。

Runner 最终软件夹具模块 10 passed（20.70 秒），SHA `488c84b78f3614657a40e2c95043595b1de04a103d23f88c56d54b3f3fe3cafd`。连续访问明确模拟已消费上一响应；capacity 负例直接触达 STEP 前 preflight，精确匹配容量错误，不以 acceptance journal 上界或旧 pending 响应拒绝代替容量检查。真实 completed 内部 TypeError 覆盖保持。

## 最终验证结果

Root 十五模块联合运行 handle56669：**211 passed／34 subtests passed／1 failed（175.25 秒，exit1）**。唯一失败是测试收集时加载的旧 Runner capacity fixture：acceptance journal capacity 先包装成 invalid-association，未触达待验证的 STEP 前容量错误。不能把该命令记录为整组通过。

最终 Runner fixture 改为消费上一响应后直接调用实际 `_step_once`，精确验证 STEP 前的 `ordinary-evidence-capacity` 且目标 command sequence 不增加。Root handle12692 在同一生产 SHA 下重新验证最终 Runner 模块：**10 passed（20.53 秒，exit0）**；其测试 SHA 与子代理冻结值完全一致。十五模块的其余十四模块 **202 项及 34 子测试通过**，配合最终 Runner 十项，最终覆盖 **212 个不重复测试及 34 子测试**。独立最终 boundary 十六项和 renderer owned 十七项另行通过，属于上述范围，不重复计数。

联合范围包括 ordinary target/helper、Router、前包独立拒绝与 CPU handoff、私有 callback confirmation、collector／新独立边界／root integration／Runner、既有 GPIO session、native APB Runner、continuity、register runtime／capabilities 与可信 register replay。新通道原始身份、空回调、同代码不同闭包、伪 enqueue、解码字段漂移、缺 raw/base/delivery、sample digest、实例／epoch／generation、配置漂移、容量及默认布局都有软件覆盖。

根回归结束后五项生产 SHA 与最终 Runner fixture SHA 再次核对一致；未提交、更改分支或运行新实际 DUT 门禁。文档链接检查 624 files／1686 links，83 条既有历史失效链接，Stage2 新增链接失效为零；不把全仓链接检查 exit1 写成通过。

下一交付仍是生产 Session/assembly opt-in 身份与源码闭包、fresh 原请求重建，随后实际 CPU readback/reset 与分操作 verifier。本包不替代 E1/E2 完整验收。
