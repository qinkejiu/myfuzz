# Ordinary GPIO access receipts：Runner／Session可信接线设计

日期：2026-10-12。只读设计笔记；未修改生产代码、未执行RTL。此方案补充ordinary target访问证据，不放宽既有causal GPIO provider，不直接授L2或functional。

## 现有事实与缺口

CPU真实接受beat时生成 `TransactionKey('local-execution', case_id, source_component, reset_epoch, channel, source_sequence)`：[cpu_session.py](../../src/myfuzz/local_harness/cpu_session.py)（第151行）。`DataflowRouter.enqueue` 用实际ledger去重并保存acceptance；`drain_one` 在 `complete_accepted` 中调用实际window.target，完成CPU response callback后记录delivery：[router.py](../../src/myfuzz/scenario/router.py)（第130行）、[router.py](../../src/myfuzz/scenario/router.py)（第155行）。因此source key、实际window、目标对象及地址变换已经有可信活对象路径。

关键缺口在 [router.py](../../src/myfuzz/scenario/router.py)（第111行） `_access` 的ordinary分支：只调用 `write_register/read_register`，返回空access元数据；`target_access_id`、command scope及逐次receipt仅causal `routed_register_access_enabled` 分支提供。该flag要求 `gpio_observation_contract`，不能为了ordinary寄存器矩阵把旧causal合约扩大。普通GPIO [write/read](../../src/myfuzz/local_harness/gpio_session.py)（第377行） 仍执行真实 `ACCESS_GPIO`，[取receipt](../../src/myfuzz/local_harness/gpio_session.py)（第285行）保存真实pre/post样本，但样本队列没有ordinary命令身份。

Runner [drain_one顺序](../../src/myfuzz/scenario/runner.py)（第1529行） 是实际target命令后同步ticks、追加外部events、再drain raw samples；[raw投影](../../src/myfuzz/scenario/runner.py)（第1868行）分配全局journal event_id并生成base协议事件。raw的producer_event_id指向触发CPU step，不能唯一识别该step内的某次目标命令。[外部流](../../src/myfuzz/scenario/runner.py)（第1951行）会为MMIO acceptance／delivery分配journal ID，但delivery本身没有ordinary receipt关联。APB [normalizer](../../src/myfuzz/scenario/ip_protocol_events.py)（第81行）保留 `transaction_key=None`、`identity_gap=protocol_has_no_transaction_id`，并用raw event refs连接request／accept／response；不能往APB native identity填CPU key。

## 最小完整接线

1. 新独立、默认关闭的ordinary-access开关及receipt能力；只对通过native ABI validator的实际ordinary GPIO target安装。factory保持gpio_consumption=False，保留native physical observation和实际memory commit。不要复用 `routed_register_access_enabled` 或新增虚假gpio_observation_contract。
2. Router `_access` 在旧causal分支之外增加显式ordinary接口，如 `ordinary_register_access(key, *, address, offset, write, value, be, delivery_context)`。传递实际TransactionKey及window身份，target验证完整context与自己的实例/epoch；仅执行既有ACCESS_GPIO一次。ordinary接口返回真实rdata和receipt引用，不能由主机模型生成rdata或APB样本。
3. 目标在命令发出前分配单调access序号并绑定当前reset epoch、预期driver command sequence；成功receipt验证actualsequence、operation、ticks与backend identity。独立记录 `ordinary_target_access_receipt.v1`：access_id、source_transaction、target_instance、target_reset_epoch、command_sequence、实际window/base/size/address/offset、write/value/be、receipt_status、rdata/error、sample tick范围、artifact/ABI/backend identity pin。失败记录uncertain或transport_failed，绝不生成successful访问。key重复只能返回同一缓存结果，不能再执行RTL。
4. `_take` 对本次真实receipt的每个样本附加受控ordinary receipt引用；只在opt-in下附加，不能给普通step或reset样本误打标。Runner `_drain_tick_samples` 在分配raw ID后登记 `access_id → raw IDs`；base events仍保留原APB字段，其raw refs用于登记协议IDs。不要修改normalizer的native transaction identity。最终由Runner闭集join生成独立 `ordinary_register_access_evidence.v1`，包含acceptance ID、delivery ID、receipt ID、raw IDs和APB request/accept/response IDs。
5. Join必须验证实际同一target/epoch/command、一个receipt、一组完整APB边界、地址/方向/数据对应，以及read response实际值与router CPU delivery一致。两个目标地址和值相同也不能互换；同CPU step的两次访问不能按近邻event或相同offset猜测。出现重复边界、跨命令refs、reset、protocol violation、response callback失败时只记录incomplete/uncertain，不发成功证据。成功target receipt与成功CPU delivery是不同事实。

推荐使用独立code-owned collector模块维护join，不把认证逻辑散入generic EventJournal。Runner负责可信append与live绑定；collector只消费可信journal refs并用existing `event_by_id`／ID-order守卫复核。容量必须显式上界、不得截断后继续声称完整。

## Session、保存与fresh重放

新增明确before-begin配置hook；旧默认manifest／schema16／17／runtime config／assembly不加字段。opt-in assembly选择固定local实现，不接受saved module/path。启动manifest加入actual target绑定、完整collector配置及独立source closure；Session plan保存请求与终态证据，不恢复receipt序号、事件IDs或savedbytes为运行权限。

Source closure仅opt-in补新collector/receipt模块；实际修改的router、GPIO session、Runner、ledger、driver parser、native validator、ip protocol modules、Session／integration等已有路径仍由当前固定closure认证。新identity必须覆盖保存的receipt state和terminal证据artifact；不能写未经runidentity认证的extra文件。默认38／capability40闭包保持各自明确范围，新增receipt通道需另行定义闭包，不宣称仍为40。

Fresh replay在可信factory创建、declare slots及adapter安装后、begin前配置collector；重新取得actualartifact/window/ledger/driver context并执行原requests。逐case重编译manifest、实际receipt、join结果与完整trace比较，终态collector state exact比较。schema17保留自然failure前缀与actualuncertain，不把saved失败记录变成fresh failure注入，也不要求导出时重做实际admission。capability startup评估仍固定pin；access receipts只有将来code-owned分操作verifier成功且绑定证书时才可能成为verified证据。

## 软件fixture与实际门禁证据

复用 `tests/scenario/test_register_program_replay.py` 的actual generated artifact＋software command stubs，`test_register_program_capability_replay.py` 的before-begin安装/fresh failure模式，及现有router ledger／ip protocol normalizer／Runner journal测试。首先RED证明ordinary路径缺receipt与raw唯一关联，再测试：A/B同值同offset；同step多access；RMW read/write各有独立key；read→RAM真实commit引用；duplicate key不重执行；错误sequence/backend/source key/offset/be；APB缺失/重复/错误response；跨epoch与reset；target执行成功但CPU callback失败；lost receipt与容量满；saved join重签hash仍fresh不相等；source drift在命令前拒。default-off布局与旧causal正负例必须同时保持。

实际门禁应在全源冻结后单worker执行：每次RMW两个CPU MMIO delivery对应两个独立target receipts；full-word READ一个receipt，read→RAM commit单列。保存原始命令receipt、raw/base refs和fresh完整比较证据，独立审查逐引用重算。该门禁证明访问链，不能替代reset／权限／mask／width／副作用行为oracle、完整72字段verified矩阵或L2 minimum。

## 有界索引与finalize插入点

不扫描全部journal。collector维护三份有界索引：`access_id → pending receipt + bounded raw/base ID lists`、`(target, reset_epoch, command_sequence) → access_id`、`source TransactionKey → acceptance/delivery IDs`。每次新增receipt／acceptance／delivery/raw/base事件时由Runner同步通知一次；协议事件通过其raw refs查询本次有界 `raw_id → access_id` 索引。raw仅该receipt span内索引，finalize后移除pending及raw反向索引，保留有界terminal records用于snapshot；拒绝capacity overflow，禁止静默淘汰未完成join。

真实driver receipt已有execution、sequence、tick_before、tick_after及new_ticks；target记录actual span，而非估算ACCESS耗时。execution随机nonce仅作为当前活对象receipt认证因素，保存／fresh比较使用可信parser提供的稳定process scope，不能把savednonce装回driver。索引键采用目标实例＋reset epoch＋实际sequence；execution/generation另作为活对象绑定，避免同实例重启重复命令序号。

精确finalize位置是Runner `_step_once` 中 `router.drain_one(component)` 的finally：sync ticks → causal drain → `_append_external_events(source_component,event_id)` → `_drain_tick_samples(event_id)` **之后**。此时acceptance/delivery及全部该命令raw/base IDs已分配；在当前router结果/exception状态明确后封口。finally必须保留目标命令已发生但delivery未成功的uncertain证据，不能因异常把receipt提升为成功。协议checker finding也在该drain同步索引，用同span判定未完成。selected ID可借 `event_by_id`逐项复核，但这是有界引用读，不是全journal搜索。

## 第一包后续接线（2026-10-12代码核实）

**已实现，软件范围：**ordinary GPIO helper的before-begin配置、actual native ABI／artifact检查、真实driver receipt与APB边界检查、private registry exact-once与sample命令tag；Router独立ordinary branch及closed receipt validator＋live registry核对、callback后发布、深拷贝、失败terminal与原CPU异常保留。queued delivery仅成功callback有 `source_delivery_confirmed=True`，sync `transact` 为False；default／旧causal无此新增字段。Router＋legacy软件28 passed（9.09秒），含actual native artifact/session及严格wire parser软件transport；这不是RTL门禁。

**尚未实现：**Runner raw/base全局IDs的有界join与finalize、Session／trusted assembly opt-in保存与fresh重建、ordinary通道明确source closure、真实门禁与code-owned operation verifier／能力证书。当前target receipt `proof_scope=actual_target_command_observation_only`，全部grants=False；不能凭Router delivery授verified。

精确闭包核实：[integration固定名单](../../src/myfuzz/integration/ibex_pulp_register_replay.py) `_sources(assembly=None)` 的默认38／capability40已经包含 `src/myfuzz/scenario/ip_protocol_events.py`、`src/myfuzz/scenario/ip_protocol_checker.py`、`src/myfuzz/scenario/ip_base_events.py`、router／runner／ledger／gpio_session／native_physical_observation。helper实际lazy调用的 `IpProtocolEventNormalizer`／`IpProtocolChecker`无需再补这两条。**现固定名单缺** `src/myfuzz/local_harness/ordinary_apb_access_receipts.py`；未来新Runner collector模块尚未命名，须作为第二条新增路径按最终名字加入，仅ordinary opt-in扩展。Session的register_program_source_files已有三个ip协议路径、router与native validator，但未列local gpio_session与新ordinary helper；建议ordinary独立source字段明确包括新helper、新collector及实际GPIO session，避免混改旧register字段。

以上“缺”指显式selector／opt-in名单，不能误称整个运行身份没认证这些源码。[build.py](../../src/myfuzz/local_harness/build.py) `_host_sources` 从GPIO／session等固定roots用AST递归发现包括函数内lazy imports；当前新增helper因此也进入新的actual build输入闭包，wire.py／local session.py已在该闭包。Runner `host_source_identity` 合并generated build inputs并逐SHA认证。新增AST dependency会改变当前build身份，不能复用旧门禁binary pins；显式ordinary closure仍应独立声明和验证。

[GPIO identity](../../src/myfuzz/local_harness/gpio_session.py)目前仅在旧causal模式追加gpio观察合约；ordinary开启后与关闭时的identity_document结构相同，未表达receipt开关／max_records。helper `_static` pin runtime／plan／binding／profile／SV／driver，未把max_records列入configuration。下一包需actual配置document/guard覆盖开启状态、目标alias与endpoint、receipt容量、reset策略、proof_scope／false grants，以及collector pending／terminal容量；保存配置为比较身份，不能据此装任意实现。容量变更必须命令前拒，不能只在终态snapshot发现。

最小hook顺序：固定可信assembly选择actual factory → Session构造与declare slots → 固定alias目标before-begin配置ordinary receipts（当前native且非causal）→ 配置Runner collector并绑定actual router/windows/targets/ledger → 安装RegisterProgramRuntime → 若有capability opt-in，在ordinary配置和identity已固定后configure capability → Session.begin在第一条driver命令前重核全部static config/source pins及fresh startup报告。新配置必须进入Session startup manifest；plan保存同配置及terminal evidence。fresh installer按同顺序从当前活对象重建，在begin前比saved配置和报告，saved target receipts／IDs／process scope从不恢复权限。schema16／17仍可用optional closed channel，默认字段集合不变。若选择在Generated GPIO identity增加conditional ordinary字段，会改变adapter.configuration的actual artifact/session identity内容，必须先配置目标再构造adapter，不能构造后悄悄切换。

2026-10-12 后续说明：前段关于首包identity/max_records缺口的检查已被首包最终修复替代，见[首包实现报告](stage2-e2-ordinary-access-receipts-20261012.md)。本包Runnerassociation实际实施还加入私有callback confirmation与parsed sample phase digest；公开delivery bool、ledger complete或sampletag均不足以认证。容量检查必须在有待交付访问的目标STEP与ACCESS命令之前，不能只在已执行STEP后检查。
