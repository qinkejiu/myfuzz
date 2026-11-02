# 通用运行框架：DS 分阶段实现计划

> 使用配套设计的固定接口，在当前工作树逐任务实现。先完成 G0–G6 这个 APB storage 纵向子项目；后续 G7–G10 按能力增量扩展。每任务通过自己的门后继续，不把未来模块提前建成空壳。

**Goal:** 新增同协议、已验证语义组件时，通过profile/源合同接入统一持久执行路径，不在共享运行时增加组件名称分支。

**Architecture:** 保留现有source/native权威、Runner/Router/Memory和flow证据消费者；新增受信能力选择、同次执行计划、协议provider接口及生命周期编排。旧路径维持兼容，generic显式入口无fallback。

**Tech Stack:** Python 3.12、现有dataclass/typed contracts、pytest、现有Verilator/native sessions、RFuzz、EventJournal。

**规范依据：** [框架设计](../specs/2026-10-26-generic-runtime-framework-design.md)。DS开始前同时阅读[交接规则](../../handover/DS_GENERIC_RUNTIME_TASK.md)。下列新文件尚不存在；命令为实现后必须执行的检查，不能用缺文件skip替代。

## 全局约束

- 不改变现有TransactionKey字段、F2/F4/F6 wire格式、source action白名单或native token发行/消费规则。
- 不关闭旧checker，不伪造sample/token/reset/retirement，不把宿主policy refusal当RTL错误。
- 不以component_id、profile名、实例名、IP系列名或exact session class选择通用执行行为。source-specific verifier可以认证精确源码，适配器内部保留实际ABI/issuer身份校验。
- 所有generic运行要求同次D2/D3/prepared graph绑定；fallback具名工厂、每例重建harness、跨例清空RAM均不得记为通过。
- 保留dirty源码、untracked F2/F6实现、旧attempt、第三方pin、未合并native工作树。不得git reset/clean/stage-all或把旧gate结果赋给新源码。
- 每任务只修改该任务允许文件；确需扩展范围时先在task report说明引用和原因，再作必要最小修改。不是等待泛泛确认的理由。
- 完成定义是实际命令、exit、输入/hash、raw证据和对应断言，不是“代码已写”或mock数量。

## G0：冻结实现输入，记录真实基线

**读取：** 当前工作树、`agent.md`、本规范、`docs/CURRENT_PROGRESS.md`、本设计接缝表中的现有模块。

**输出：** `runs/generic-runtime/G0/`，其中保存branch/worktree/status、tracked二进制patch、untracked候选列表、源码hash、tool版本、命令与退出码、baseline失败分类。

1. 运行以下命令并保存输出，保护当前dirty状态。不要以checkout HEAD的另一工作树替代尚未提交实现。

```bash
git status --short
git branch -avv
git worktree list --porcelain
git diff --binary HEAD
git ls-files --others --exclude-standard
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m pytest -q tests/test_current_cli.py tests/integration/test_compiled_f2_read_response.py tests/integration/test_compiled_f4_build_join.py
python3 scripts/check_doc_links.py --json-out runs/generic-runtime/G0/doc-links.json
```

2. 用专用Python审计脚本对本任务依赖的 `src/ scripts/ tests/ configs/ schemas/` 常规文件保存SHA-256；排除缓存、evidence和symlink后，额外明确包含计划实际读取的fixtures/control文件。第三方source和工具按既有source metadata/gate工具封存，不把`.git`目录递归打包。
3. 记录当前缺失的历史static-campaign `instrumented/sources.f`及原有文档断链；相关基线失败不假装通过，也不在此任务删除测试来修复。

**门：** 依赖可定位、原始工作树可恢复、每个失败有错误栈和分类。若某G1–G6真实依赖缺失，先补真实fixture/source闭包或拒绝该分支；不能把关键验收改成skip。

## G1：数据合同与严格解析

**创建：** `src/myfuzz/runtime/__init__.py`、`contracts.py`、`adapters/contracts.py`、`semantics/contracts.py`、`evidence/contracts.py`；所需子目录仅增加最小`__init__.py`。

**测试：** `tests/runtime/test_contracts.py`、`test_evidence_contracts.py`。

**接口：** 实现设计§4的四个dataclass和GenericRuntimeRefused；补齐设计规定的TargetRequest、ProviderProgress、EffectEvidence和EvidenceRef的闭合字段与严格序列化。PreparedTargetOperation/BoundExecutionPlan/PreparationContext是provider或准备器私有发行的live句柄，禁止JSON恢复；只允许单独导出无执行效力的documentary快照。增加“手工重建字段或JSON round-trip不能获得accepted live operation”的负例。

步骤：

1. 先测试bool/int混淆、重复JSON key、NaN/Infinity、额外字段、缺端点、列表重复、超宽值和外部可变容器修改。
2. dataclass构造与JSON解析都执行闭合形状检查；输出文档为detached副本。不能只在CLI一层验证。
3. 必须包含这个独立于实现细节的性质检查：同一输入生成同一canonical bytes；事后改输入的嵌套dict不能改变已封存对象。

```python
def test_frozen_plan_is_detached_from_callers():
    from hashlib import sha256
    from myfuzz.runtime.contracts import GenericExecutionPlan
    import json
    raw = {
        "schema_version": "generic_execution_plan.v1",
        "components": [], "selections": [], "paths": [], "sources": [],
        "constraints": [], "seeds": [], "assertions": [], "memory": {},
        "scheduling": {}, "termination": {}, "evidence_obligations": [],
        "input_digests": {"d2": "1" * 64, "d3": "2" * 64},
    }
    frozen = json.dumps(raw, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    plan = GenericExecutionPlan("generic_execution_plan.v1", frozen, sha256(frozen).hexdigest())
    raw["input_digests"]["d2"] = "3" * 64
    assert json.loads(plan.document_bytes)["input_digests"]["d2"] == "1" * 64
```

此例是完整顶层形状的空静态声明，只验证documentary封存，不能bind或运行；G4必须拒绝无paths/seeds/真实组件的空计划。完整plan语义与绑定另在G4检查。

**门：**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m pytest -q tests/runtime/test_contracts.py tests/runtime/test_evidence_contracts.py
```

所有新测试通过，受影响旧schema round-trip不变。报告明确“软件合同完成，无真实执行”。

## G2：受信组件认证与唯一能力选择

**创建：** `runtime/preparation.py`、`admission.py`、`registry.py`、`semantics/storage.py`、`tests/runtime/test_admission.py`、`test_registry.py`。

**复用：** `local_harness/plan.py`、`runtime_artifact.py`、`template_contracts.py`、`apb_storage_source_contract.py`、source lock与profile binding。

**允许最小修改：** `src/myfuzz/integration/compiled_execution_files.py`，只抽取共享准备阶段并保留原single-flow wrapper；涉及该修改时必须运行原execution-files和source-admission回归。

**输入/输出：** `LocalRuntimeArtifact + PreparationContext → verify_component → VerifiedComponent`；`VerifiedComponent + CapabilityRequirement + PreparationContext → select_adapter → AdapterSelection`。注册项由代码常量固定，不从JSON导入factory/class/module。

步骤：

1. 固定实现ID `apb3.storage.v1` 和 `obi.cpu.v1`；版本与实现source摘要进入selection。一个adapter覆盖多个合格storage source合同，不能每个IP登记一个同义adapter。
2. create_preparation私有持有实际artifacts映射与compiled_inputs，输入为显式compose/capability/supplement；verify_component从该context拥有的LocalRuntimeArtifact读取plan/runtime_document/生成文件和显式observation `{contract_id, register}`，再认证pin/文件/profile/模板/语义。不能仅收LocalHarnessPlan就捏造artifact摘要。先复用timer/SPI登记；新source留G7。
3. 对compiled_execution_files做最小内部阶段抽取，复用其source/supplement/ownership/fixed-input/physical-map校验；一次生成D2、一次D3编译，再对同一对象做所需flow静态评估。旧单flow API保持兼容，不能重复调用两次生成器。
4. 精确实施设计§4.4匹配规则，endpoint显式选定；0匹配和多匹配分别拒绝。
5. 测试实例改名后adapter_id/version相同、身份摘要随配置改变；相似名错误协议拒绝；同协议W1C/FIFO语义不可当storage；caller提供factory/import-string或测试provider拒绝。
6. 负例分别篡改source、模板、寄存器alias、位宽、evidence义务和原生producer声明。静态selection不能被当成native grant。

**门：**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m pytest -q tests/runtime/test_admission.py tests/runtime/test_registry.py tests/integration/test_compiled_f2_execution_files.py tests/integration/test_generated_artifact_admission.py
```

输出匹配表、拒绝pointer和source reader调用证据；不能只证明一个fake实现返回了预期字符串。

## G3：实际APB storage provider与OBI适配边界

**创建：** `runtime/adapters/apb3_storage.py`、`obi_cpu.py`、`runtime/binding.py`中仅适配绑定部分、`tests/runtime/test_apb3_provider.py`、`test_provider_lifecycle.py`。

**复用：** `GeneratedApb3RegisterSession`、`ApbStorageRegisterVersionAuthority`、原生APB观察/token消费者、OBI CPU接口、既有ledger和route matcher。

**禁止修改：** native issuer权限、CPU instruction whitelist、既有模板时序；任何需修复的真实缺陷分开记录和测试。

步骤：

1. 实现bind/assert_current/prepare/advance/complete；prepare无RTL side effect，advance调用既有驱动而非在Python模拟寄存器。
2. `PreparedTargetOperation`固定key/payload/route/semantic/adapter绑定，重复key同payload幂等，不同payload拒绝；reset/close后不可继续推进。
3. 软件用明确mock session/raw fixture检查APB setup→access→wait→response状态、背压和错误收尾。fake结果始终标为software，不发行native证书。
4. 真实token由原issuer消费；适配器不能通过解析JSON伪造token。method/ABI/binary/artifact漂移均使绑定失效。
5. 地址测试包括真实alias、非alias wrong-offset、BE不支持及地址单位混淆；policy refusal发生在target调用前。若原生ERR无真实支持，返回unsupported而非伪造ERR。

**门：**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m pytest -q tests/runtime/test_apb3_provider.py tests/runtime/test_provider_lifecycle.py tests/scenario/test_dma_route_admission.py
```

此旧测试模块已在设计时核对存在；若DS工作树版本不同导致路径缺失，应先核对基线，不能创建空同名测试或跳过该回归。

## G4：同次D2/D3执行计划与显式准备入口

**创建：** `runtime/compiler.py`、补齐`binding.py`、`scripts/run_generic_runtime.py`、`tests/runtime/test_plan_compiler.py`、`test_plan_binding.py`、`test_generic_cli.py`。

**接口：** 设计§4.2的compile/bind签名固定，均显式接收PreparationContext；其对象成员规则按§4.3实现。计划v1顶层字段固定为 `schema_version, components, selections, paths, sources, constraints, seeds, assertions, memory, scheduling, termination, evidence_obligations, input_digests`；`identity_sha256`在封存对象上计算，不放回自身hash循环。

步骤：

1. compiler消费同一个PreparationContext拥有的artifact映射/compiled_inputs，使用它登记的VerifiedComponent/selection对象。先编译static plan，再创建共享内存、target/provider sessions和Router，将实际memory/router传入CPU session后创建runner，最后从该context唯一物化typed图并编译/登记PreparedRuntimePathContract；不能要求纯静态compiler先得到依赖真实runner的prepared graph。begin和effect前binding.assert_current。
2. 检查选定路径每条edge都有provider或明确unsupported。memory必须引用实际共享PersistentMemory，不能反序列化出第二份“相同内容”的RAM来代替。
3. 新入口参数固定为 `--compose PATH --ip-capability PATH --supplement PATH --flow F2|F4 --mode prepare|run --output PATH`。capability与flow可重复；base_dir为项目根，输出目录必须新建。prepare从本次生成的wiring构造request，不另收可能过时的`--path-request`。supplement继续采用现有 `compiled_execution_file_supplement.v1`，显式包含request_supplements/ownership/physical_port_map。G4只实现prepare，run明确拒绝；G5再启用run，并要求`--cases PATH --cache-dir PATH`。
4. 重复F2/F4必须进入同一个create_preparation：一次D2生成、一次request/ownership构建、一次compile_paths，同一artifact map/inputs的两种flow选择。原single-flow prepare API的tuple输出只能在内部兼容封装，不接受caller拼接两个tuple或按hash相等声称同次。
5. prepare保存 `execution_plan.json`、`inputs.json`、`capabilities.json`、`refusals.json`和实际D2/D3摘要；无native成功字段。
6. 软件测试把另一次D2/D3对象、值相等但不同context的selection/plan、旧prepared graph、source_id错接、篡改plan JSON、删减必需assertion/obligation、声明更多证据能力逐项拒绝。

**门：**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m pytest -q tests/runtime/test_plan_compiler.py tests/runtime/test_plan_binding.py tests/runtime/test_generic_cli.py
PYTHONPATH=src:. python3 scripts/run_generic_runtime.py --help
```

两个现有受信APB source合同都能从真实prepare链生成同一类型计划；bad请求无process启动。旧F2/F4入口行为保持不变。

实现后执行这两条完整命令（配置文件均已在设计时核对存在）：

```bash
PYTHONPATH=src:. python3 scripts/run_generic_runtime.py \
  --compose configs/scenarios/compiled-f4-obi-apb-timer/compose.json \
  --ip-capability configs/scenarios/compiled-f4-obi-apb-timer/test_capability.json \
  --supplement configs/scenarios/compiled-f4-obi-apb-timer/execution_supplement.json \
  --flow F2 --flow F4 --mode prepare \
  --output runs/generic-runtime/G4/timer-attempt1

PYTHONPATH=src:. python3 scripts/run_generic_runtime.py \
  --compose configs/scenarios/compiled-f4-obi-apb-spi-cv32e40p/compose.json \
  --ip-capability configs/scenarios/compiled-f4-obi-apb-spi-cv32e40p/test_capability.json \
  --supplement configs/scenarios/compiled-f4-obi-apb-spi-cv32e40p/f2_execution_supplement.json \
  --flow F2 --flow F4 --mode prepare \
  --output runs/generic-runtime/G4/spi-attempt1
```

已有supplement不因名称含F2/F4改变解释：以上两份都显式声明空request_supplements/ownership/physical_port_map；由同一次artifact生成器补充实际fixed ownership并逐项核验。后续不同source需要的非空声明必须显式提供，不能隐藏在工厂或自动扫描邻接文件。

## G5：持久执行与首个flow kernel

**创建：** `runtime/engine.py`、`campaign.py`、`flows/storage.py`、`tests/runtime/test_persistent_engine.py`、`test_storage_kernel.py`、`test_generic_feedback.py`。

**输入/输出：** `BoundExecutionPlan → PersistentCampaignRuntime`；提交旧typed source/OnlineCase，输出真实case receipt、edge claims、feedback及持久状态。流程重用ScenarioSession/Runner，不增加第二套step循环。

步骤：

1. 实现CREATED/PREPARED/RUNNING/QUIESCING/CLOSED/FAULTED状态；finish/abort保留原始process、pending和uncertain记录。run模式增加必需的 `--cases PATH --cache-dir PATH`，读取设计§5.2的generic_case_sequence.v1；RFuzz模式另需明确client、budget和旧flow wire layout，不自行猜选。
2. storage kernel按设计§5.2固定prepare/lower/capture/feedback接口，复用F2 read-response消费与F4 write/readback证据合同，接入同一组已绑定CPU/IP session。允许最小修改 `integration/compiled_f2.py`、`compiled_f4.py`，把context/构造与case逻辑分开，并保留旧类的兼容wrapper及测试；不得在新kernel里各建一套harness。
3. 先做directed三个case：写一个非零值；后例真实读取该版本并写入CPU结果RAM；再写不同合法值并读回。每项path/source/seed/assertion都由计划声明。缺少相应F2/F4证据能力时停止，不用host读取替代CPU读。
4. 再接固定flow/layout的RFuzz合法字段变异：F2/F4各自保留旧8-byte解释，不从其中偷取bits做generic flow selector；首版混合flow只跑directed序列。只改变未绑定source和未物化程序槽，至少两个不同合法值；逐例反馈来自真实checker/edge/coverage，不由期望值填充。
5. 预算/超时/route拒绝/中途断连均保存已发生effect；禁止每例reset、重新初始化RAM、丢pending或重试可能已写出的事务。

**门：**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m pytest -q tests/runtime/test_persistent_engine.py tests/runtime/test_storage_kernel.py tests/runtime/test_generic_feedback.py tests/test_current_cli.py
```

软件测试明确检查build/start/begin初始化次数为1，所有case复用同一runner/memory对象。真实持久证明留G6；mock调用次数不能代替真实PID/raw证据。

## G6：首切片真实门、独立saved验证与兼容回归

**创建：** `runtime/evidence/saved.py`、`scripts/verify_generic_runtime.py`、`tests/integration/test_generic_storage_native.py`、`tests/runtime/test_saved_generic_evidence.py`、`configs/scenarios/generic-storage-contracts/`下的显式选择/种子配置。

**参考既有输入：** `configs/scenarios/compiled-f4-obi-apb-timer/`、`compiled-f4-obi-apb-spi-cv32e40p/`的source/profile合同；它们仅提供输入事实，generic执行不得回退这些实例的具名runner。

步骤：

1. 两个登记source合同各运行三case persistent正例、一个改名实例正例、一个真实非alias错偏移的effect前拒绝。用同一adapter/kernel版本，PID/nonce/READY/raw采样证明持久性。
2. 每个正例和有已接纳前缀的拒绝例均用新process重放完整prefix；原生错误/uncertain各按实际合同另记录。不能只重放最后一个case。
3. saved verifier从原始APB/OBI/issuer/source-version和Runner refs重构路径，不读取live的certified布尔值直接通过。分别篡改read-return值、byte-version、raw引用、native nonce、source契约、计划和counter，必须失败。
4. 真实运行显式开关为 `MYFUZZ_RUN_GENERIC_NATIVE=1`；native未运行时保留skip理由，G6不得完成。软件运行该模块的skip结果也不得当作G6通过。
5. 受控finding和正常对照分开，保留所有失败attempt；fresh normalization仅允许设计列出的身份字段。原生CPU→IP和IP→CPU消费链必须各有实际证据。

**软件命令：**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m pytest -q tests/runtime tests/integration/test_generic_storage_native.py tests/integration/test_compiled_f2_read_response.py tests/integration/test_compiled_f4_build_join.py
```

**原生命令：**

```bash
MYFUZZ_RUN_GENERIC_NATIVE=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m pytest -q tests/integration/test_generic_storage_native.py
PYTHONPATH=src:. python3 scripts/verify_generic_runtime.py --help
```

verify脚本实现 `--bundle PATH --fresh-bundle PATH --output PATH`；缺任何归档输入拒绝，不从mutable工作树补齐。真实gate必须记录source/tool/command/pre/post closure、原/fresh进程与退出状态、全部case/transaction/edge数量、结果比较scope和独立原始审计。

**退出：** 两个登记source使用同一generic core/adapter、3case持久和新fresh成立；无legacy fallback；兼容回归无新增失败；独立源码/原始证据审计通过。这里只关闭首切片。

## G7：真正新增同协议source

**只允许新增：** 新组件profile/interface/source合同、source-verifier登记与fixtures、矩阵配置；不得为该组件修改 `runtime/engine.py`、`compiler.py`、registry匹配算法、APB3 adapter或storage kernel。

要求一个实际不同RTL source的受支持APB storage target；仅改名不算新source。新增source认证可增加受信source事实校验，不得把实例名称变成factory分派；超出storage语义则拒绝，并作为新语义任务另做。

门：新source、改名实例、相似名错误语义/模板负例、实际三case持久和完整fresh，均通过G6相同证据规则。保存前后共享core/adapter源码SHA以证明没有为它追加分支。若必须修改匹配算法或adapter才能过，本次不得称“仅声明接入”。

## G8：协议、CPU ABI与事件能力逐项迁移

依赖G6/G7。每个子项单独任务与提交边界：

- G8.1：Wishbone target/master和地址单位/ACK/STALL/ERR子集，先迁移现有ZipCPU实例。
- G8.2：AHB-Lite target、HTRANS/ready/response子集，先迁移Caliptra并保留源合同。
- G8.3：AXI4-Lite、full AXI4与reduced观察形态分开；不把observation-only升级为semantic-consumed。
- G8.4：TL-UL target、native/Wishbone CPU、BOOM uncached TileLink A/D，按已证明子集分别接入；coherent C/E/B另列能力。
- G8.5：CPU ISA/启动/IRQ ABI分层：RV32/RV64编码、machine trap、Pico自定义ABI、可观察take/retirement等逐一认证，不能只靠ISA同名通用化。
- G8.6：FIFO、W1C/W1S、timer、command类effect与IRQ事件扩充。每种语义各有source事实、原生issuer/观察、实际正/负/fresh；不借storage adapter假设副作用。

每个子项均输出严格supported/unsupported列表，复用G6框架跑正/拒绝/持久/fresh及受控finding。不存在无测试的“协议已支持”注册项。对应旧类型分支只有在能力实际迁移、引用为零且兼容检查通过后才删除。

## G9：F6 kernel与现有失败门闭合

依赖所需CPU/DMA/IRQ能力已认证。先按既有 [F6规格](../specs/2026-10-24-compiled-f6-cpu-programmed-ram-design.md) 与 [source-closure计划](2026-10-25-f6-frozen-source-closure.md)处理当前真实失败，保留Freeze15/attempt15/16和各次结果，不能以新框架抹掉失败。

迁移步骤：CPU实际写源RAM/配置DMA → 真实master读/写与byte-version → RAM/IP实际effect → DMA IRQ → native take/ISR/readback/返回 → 完整fresh。候选wire/白名单/ISR边界保持既有批准规格。RAM→RAM、RAM→IP、FIFO→RAM方向分别验收；各flow使用同一共享内存及既有事务ledger。observer/source-owner没有证据时保持missing/unsupported。

门：通过原规格正例、expected-error、边界控制、持久多例与RFuzz gate，独立saved/raw审计；新generic选择路径不调用具名DMA runner，且没有降低既有source/issuer/transaction检查。

## G10：系统矩阵、P7-E与性能门

由DS先生成逐profile/协议/语义/path矩阵，不按“六乘四”填一个笼统绿表。每个cell分别记录catalog/generated/RTL/cross-component/searched、持久模式、CPU/IP source、IRQ/retirement scope、finding、fresh、effective throughput和原因。

- P6：各原计划协议行真实持久多例、双侧源、逐边来源、交互反馈/闭环和prefix，不能用每例新harness的旧18格结果代替。
- P7-E：真正新CPU和新IP，仅源码/profile/允许微调完成同次D2/D3→D4→多例搜索/断言/fresh，并有相似名负例。G7的APB-only结果不单独关闭P7-E。
- P8：按同硬件/输入/观察/checker/完整日志/replay义务配对；5×未达到就保持OPEN并给瓶颈，不通过减少验证范围造提升。
- 总验收：每项原计划要求都指向实际当前冻结输入的证据，所有关键skip/unknown/pending明确；不得把软件测试总数或代码量换算完成率。

## 每任务交付格式

`task-report.json`固定字段：`task_id, baseline_sha256, allowed_paths, changed_paths, commands, test_results, native_runs, source_digests, evidence_paths, unresolved, verdict`。每条command记录 `argv,cwd,environment_allowlist,exit_code,stdout,stderr`；不记录密钥/完整环境。verdict仅 `PASS / FAIL / BLOCKED_DEPENDENCY`；未执行关键门不得PASS。

DS每轮说明具体改动、为何必要、实际测试、局限和下一个可执行task。不要复制数百行历史进度到首页；报告按task保存，源码和原始证据保持可关联。
